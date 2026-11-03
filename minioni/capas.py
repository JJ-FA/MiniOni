"""Cifrado por capas (la "cebolla").

Requisito R2 (OWASP ASVS 5.0 V11.3.3 y V11.3.4):
- Cada capa usa ChaCha20-Poly1305 (cifrado autenticado). Si alguien cambia
  un solo bit, la verificación falla y se lanza CeldaManipulada.
- Cada salto tiene una clave por dirección (ida y vuelta) y un contador por
  dirección que forma el nonce. El contador nunca se transmite ni se repite;
  un contador desfasado (celda repetida, borrada o reordenada) también
  hace fallar la verificación.

Formato de una capa:   longitud (2) | texto_cifrado (longitud)
El texto cifrado ocupa 16 bytes más que su contenido (etiqueta Poly1305).
Después de la última capa se rellena con bytes aleatorios hasta 507, para
que todas las celdas midan lo mismo.

Reglas del circuito:
- Solo el ÚLTIMO salto del circuito interpreta o genera mensajes RELAY.
- Ida: el cliente envuelve N capas; cada relay quita una y reenvía.
- Vuelta: el último salto sella el mensaje; cada relay anterior agrega
  su capa; el cliente quita las N capas.
"""

from __future__ import annotations

import os
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .constantes import (
    SOBRECOSTO_CAPA,
    TAM_CARGA,
    TAM_CLAVE_SIMETRICA,
    TAM_ETIQUETA,
    TAM_PREFIJO_LONGITUD,
    TAM_RELAY_PLANO,
)
from .errores import CeldaInvalida, CeldaManipulada

_MAX_CONTADOR = 2**64 - 1
IDA = "ida"
VUELTA = "vuelta"


class CapaSalto:
    """Estado criptográfico de UN salto del circuito (vive solo en memoria)."""

    def __init__(self, clave_ida: bytes, clave_vuelta: bytes) -> None:
        if len(clave_ida) != TAM_CLAVE_SIMETRICA or len(clave_vuelta) != TAM_CLAVE_SIMETRICA:
            raise ValueError("las claves deben ser de 256 bits")
        if clave_ida == clave_vuelta:
            raise ValueError("ida y vuelta deben usar claves distintas")
        self._aead = {IDA: ChaCha20Poly1305(clave_ida), VUELTA: ChaCha20Poly1305(clave_vuelta)}
        self._contador = {IDA: 0, VUELTA: 0}

    def _nonce(self, direccion: str) -> bytes:
        n = self._contador[direccion]
        if n >= _MAX_CONTADOR:
            # Agotar el contador obligaría a repetir un nonce: se cierra el circuito.
            raise CeldaManipulada("contador agotado")
        self._contador[direccion] = n + 1
        return b"\x00\x00\x00\x00" + struct.pack(">Q", n)

    def sellar(self, contenido: bytes, direccion: str) -> bytes:
        """Devuelve longitud(2) | cifrado."""
        cifrado = self._aead[direccion].encrypt(self._nonce(direccion), contenido, None)
        return struct.pack(">H", len(cifrado)) + cifrado

    def abrir(self, carga: bytes, direccion: str) -> bytes:
        """Lee la capa al inicio de `carga` (puede traer relleno detrás) y la descifra."""
        if len(carga) < TAM_PREFIJO_LONGITUD:
            raise CeldaInvalida("capa truncada")
        (largo,) = struct.unpack(">H", carga[:TAM_PREFIJO_LONGITUD])
        if largo <= TAM_ETIQUETA or TAM_PREFIJO_LONGITUD + largo > len(carga):
            raise CeldaInvalida("longitud de capa inválida")
        cifrado = carga[TAM_PREFIJO_LONGITUD:TAM_PREFIJO_LONGITUD + largo]
        try:
            return self._aead[direccion].decrypt(self._nonce(direccion), cifrado, None)
        except InvalidTag:
            raise CeldaManipulada("verificación Poly1305 fallida") from None


def rellenar(datos: bytes) -> bytes:
    """Completa hasta 507 bytes con aleatorio (el relleno no debe ser predecible)."""
    if len(datos) > TAM_CARGA:
        raise CeldaInvalida("carga demasiado grande")
    return datos + os.urandom(TAM_CARGA - len(datos))


def _medida_capa(carga: bytes) -> int:
    """Bytes que ocupa la capa al inicio de `carga` (prefijo + cifrado)."""
    if len(carga) < TAM_PREFIJO_LONGITUD:
        raise CeldaInvalida("capa truncada")
    (largo,) = struct.unpack(">H", carga[:TAM_PREFIJO_LONGITUD])
    total = TAM_PREFIJO_LONGITUD + largo
    if largo <= TAM_ETIQUETA or total > len(carga):
        raise CeldaInvalida("longitud de capa inválida")
    return total


# --- Lado cliente ---------------------------------------------------------------

def cliente_envolver(capas: list[CapaSalto], relay_plano: bytes) -> bytes:
    """Envuelve el mensaje en una capa por salto, de la más interna (último salto) a la externa."""
    if len(relay_plano) != TAM_RELAY_PLANO:
        raise CeldaInvalida("mensaje relay de tamaño incorrecto")
    if not capas:
        raise ValueError("el circuito no tiene saltos")
    datos = relay_plano
    for capa in reversed(capas):
        datos = capa.sellar(datos, IDA)
    return rellenar(datos)


def cliente_pelar(capas: list[CapaSalto], carga: bytes) -> bytes:
    """Quita las capas de vuelta en orden (entrada, intermedio, salida)."""
    if len(carga) != TAM_CARGA:
        raise CeldaInvalida("carga de tamaño incorrecto")
    datos = carga
    for capa in capas:
        datos = capa.abrir(datos, VUELTA)
    if len(datos) != TAM_RELAY_PLANO:
        raise CeldaInvalida("mensaje relay de tamaño incorrecto")
    return datos


# --- Lado relay -----------------------------------------------------------------

def relay_pelar(capa: CapaSalto, carga: bytes) -> bytes:
    """Quita la capa de este salto (ida). Devuelve el contenido SIN relleno.

    Si el relay tiene siguiente salto, reenvía `rellenar(resultado)`.
    Si es el último salto, el resultado es el texto plano RELAY (453 bytes).
    """
    if len(carga) != TAM_CARGA:
        raise CeldaInvalida("carga de tamaño incorrecto")
    return capa.abrir(carga, IDA)


def relay_originar(capa: CapaSalto, relay_plano: bytes) -> bytes:
    """El último salto sella un mensaje de vuelta hacia el cliente."""
    if len(relay_plano) != TAM_RELAY_PLANO:
        raise CeldaInvalida("mensaje relay de tamaño incorrecto")
    return rellenar(capa.sellar(relay_plano, VUELTA))


def relay_agregar_capa(capa: CapaSalto, carga: bytes) -> bytes:
    """Un salto intermedio agrega su capa a una celda que viene de vuelta."""
    if len(carga) != TAM_CARGA:
        raise CeldaInvalida("carga de tamaño incorrecto")
    util = carga[:_medida_capa(carga)]
    if len(util) + SOBRECOSTO_CAPA > TAM_CARGA:
        raise CeldaInvalida("demasiadas capas")
    return rellenar(capa.sellar(util, VUELTA))
