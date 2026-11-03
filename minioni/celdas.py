"""Formato de celdas y validación positiva de todo lo que llega por la red.

Requisito R1 (OWASP ASVS 5.0 V2.2.1): solo se acepta lo que coincide con
una estructura esperada. Cualquier otra cosa lanza CeldaInvalida o
DestinoNoPermitido y quien llama cierra la conexión.

Celda de enlace (512 bytes):
    circ_id (4, uint32 big-endian, != 0) | comando (1) | carga (507)

Texto plano RELAY (453 bytes, viaja dentro de las capas de cifrado):
    comando_relay (1) | stream_id (2) | longitud (2) | datos | ceros

Cargas de enlace con tamaño fijo (CREATE, CREATED, DESTROY): el contenido
útil va al inicio y el resto DEBE ser ceros.
"""

from __future__ import annotations

import ipaddress
import re
import struct
from dataclasses import dataclass
from enum import IntEnum

from .constantes import (
    MAX_DATOS_RELAY,
    MAX_LONGITUD_DOMINIO,
    TAM_CABECERA_RELAY,
    TAM_CARGA,
    TAM_CELDA,
    TAM_CLAVE_PUBLICA,
    TAM_RELAY_PLANO,
)
from .errores import CeldaInvalida, DestinoNoPermitido


class Comando(IntEnum):
    """Comandos de enlace (los ve cada relay)."""
    CREATE = 1     # cliente -> relay de entrada: inicia el handshake
    CREATED = 2    # relay -> cliente: respuesta del handshake
    RELAY = 3      # celda cifrada por capas
    DESTROY = 4    # cerrar el circuito


class ComandoRelay(IntEnum):
    """Comandos dentro de una celda RELAY (solo los ve el último salto)."""
    BEGIN = 1       # abrir conexión TCP al destino (solo nodo de salida)
    DATA = 2
    END = 3
    CONNECTED = 4
    EXTEND = 5      # pedir al último salto que extienda el circuito
    EXTENDED = 6
    ECO = 7         # diagnóstico: el último salto responde con los mismos datos


class MotivoDestroy(IntEnum):
    """Motivo genérico de un DESTROY (1 byte). Nunca lleva detalles."""
    PROTOCOLO = 1   # error de protocolo
    TIEMPO = 2      # tiempo agotado
    CLIENTE = 3     # cerrado por el cliente
    RECURSO = 4     # recurso no disponible


class MotivoEnd(IntEnum):
    """Motivo genérico de un END enviado por la salida (1 byte). Sin datos = cierre normal."""
    NO_PERMITIDO = 1   # destino, puerto o stream no permitido
    INALCANZABLE = 2   # no se pudo resolver o conectar
    TIEMPO = 3         # tiempo agotado


@dataclass(frozen=True)
class Celda:
    circ_id: int
    comando: Comando
    carga: bytes

    def codificar(self) -> bytes:
        if not 1 <= self.circ_id <= 0xFFFFFFFF:
            raise CeldaInvalida("circ_id fuera de rango")
        if len(self.carga) > TAM_CARGA:
            raise CeldaInvalida("carga demasiado grande")
        carga = self.carga.ljust(TAM_CARGA, b"\x00")
        return struct.pack(">IB", self.circ_id, int(self.comando)) + carga


def decodificar_celda(datos: bytes) -> Celda:
    """Valida y decodifica exactamente 512 bytes."""
    if not isinstance(datos, (bytes, bytearray)) or len(datos) != TAM_CELDA:
        raise CeldaInvalida("tamaño de celda incorrecto")
    circ_id, comando = struct.unpack(">IB", datos[:5])
    if circ_id == 0:
        raise CeldaInvalida("circ_id 0 reservado")
    try:
        cmd = Comando(comando)
    except ValueError:
        raise CeldaInvalida("comando desconocido") from None
    return Celda(circ_id, cmd, bytes(datos[5:]))


# --- Cargas de enlace de tamaño fijo -----------------------------------------

def decodificar_carga_fija(carga: bytes, tam: int) -> bytes:
    """Devuelve los primeros `tam` bytes; el resto de la carga debe ser ceros."""
    if len(carga) != TAM_CARGA:
        raise CeldaInvalida("carga de tamaño incorrecto")
    if any(carga[tam:]):
        raise CeldaInvalida("bytes sobrantes en la carga")
    return bytes(carga[:tam])


def codificar_destroy(motivo: int) -> bytes:
    try:
        return bytes([MotivoDestroy(motivo)])
    except ValueError:
        raise CeldaInvalida("motivo de DESTROY desconocido") from None


def decodificar_destroy(carga: bytes) -> MotivoDestroy:
    try:
        return MotivoDestroy(decodificar_carga_fija(carga, 1)[0])
    except ValueError:
        raise CeldaInvalida("motivo de DESTROY desconocido") from None


# --- Texto plano RELAY ------------------------------------------------------

@dataclass(frozen=True)
class MensajeRelay:
    comando: ComandoRelay
    stream_id: int
    datos: bytes


def codificar_relay(msg: MensajeRelay) -> bytes:
    if not 0 <= msg.stream_id <= 0xFFFF:
        raise CeldaInvalida("stream_id fuera de rango")
    if len(msg.datos) > MAX_DATOS_RELAY:
        raise CeldaInvalida("datos demasiado grandes")
    cab = struct.pack(">BHH", int(msg.comando), msg.stream_id, len(msg.datos))
    return (cab + msg.datos).ljust(TAM_RELAY_PLANO, b"\x00")


def decodificar_relay(plano: bytes) -> MensajeRelay:
    if len(plano) != TAM_RELAY_PLANO:
        raise CeldaInvalida("tamaño de relay incorrecto")
    comando, stream_id, longitud = struct.unpack(">BHH", plano[:TAM_CABECERA_RELAY])
    try:
        cmd = ComandoRelay(comando)
    except ValueError:
        raise CeldaInvalida("comando relay desconocido") from None
    if longitud > MAX_DATOS_RELAY:
        raise CeldaInvalida("longitud relay inválida")
    fin = TAM_CABECERA_RELAY + longitud
    if any(plano[fin:]):
        raise CeldaInvalida("relleno no nulo")
    return MensajeRelay(cmd, stream_id, bytes(plano[TAM_CABECERA_RELAY:fin]))


def codificar_end(motivo: int | None = None) -> bytes:
    if motivo is None:
        return b""
    try:
        return bytes([MotivoEnd(motivo)])
    except ValueError:
        raise CeldaInvalida("motivo de END desconocido") from None


def decodificar_end(datos: bytes) -> MotivoEnd | None:
    """Datos de END: vacío (cierre normal) o exactamente 1 byte de motivo conocido."""
    if len(datos) == 0:
        return None
    if len(datos) != 1:
        raise CeldaInvalida("END con datos sobrantes")
    try:
        return MotivoEnd(datos[0])
    except ValueError:
        raise CeldaInvalida("motivo de END desconocido") from None


# --- Destinos (BEGIN) y extensiones (EXTEND) ---------------------------------

# Se usa con fullmatch: con match, el "$" de Python acepta un salto de línea al final
# ("ejemplo.com\n" pasaba). Hallazgo de la Clase 3.
_ETIQUETA_DNS = re.compile(r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)")


def validar_host(host: str) -> str:
    """Acepta una IP literal o un nombre DNS bien formado. Devuelve el host normalizado."""
    if not isinstance(host, str) or not host or len(host) > MAX_LONGITUD_DOMINIO:
        raise DestinoNoPermitido("host vacío o demasiado largo")
    if not host.isascii():
        raise DestinoNoPermitido("host no ASCII")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    nombre = host[:-1] if host.endswith(".") else host
    etiquetas = nombre.split(".")
    if not all(_ETIQUETA_DNS.fullmatch(e) for e in etiquetas):
        raise DestinoNoPermitido("nombre de host mal formado")
    if etiquetas[-1].isdigit():
        raise DestinoNoPermitido("dominio de nivel superior numérico")
    return nombre.lower()


def validar_puerto(puerto: int) -> int:
    if isinstance(puerto, bool) or not isinstance(puerto, int) or not 1 <= puerto <= 65535:
        raise DestinoNoPermitido("puerto fuera de rango")
    return puerto


def codificar_destino(host: str, puerto: int) -> bytes:
    """Formato: largo_host (1) | host ASCII | puerto (2)."""
    h = validar_host(host).encode("ascii")
    return struct.pack(">B", len(h)) + h + struct.pack(">H", validar_puerto(puerto))


def decodificar_destino(datos: bytes) -> tuple[tuple[str, int], int]:
    """Devuelve ((host, puerto), bytes_consumidos)."""
    if len(datos) < 1:
        raise DestinoNoPermitido("destino vacío")
    largo = datos[0]
    if largo == 0 or len(datos) < 1 + largo + 2:
        raise DestinoNoPermitido("destino truncado")
    try:
        host = datos[1:1 + largo].decode("ascii")
    except UnicodeDecodeError:
        raise DestinoNoPermitido("host no ASCII") from None
    (puerto,) = struct.unpack(">H", datos[1 + largo:3 + largo])
    return (validar_host(host), validar_puerto(puerto)), 3 + largo


def decodificar_begin(datos: bytes) -> tuple[str, int]:
    (host, puerto), usados = decodificar_destino(datos)
    if usados != len(datos):
        raise DestinoNoPermitido("bytes sobrantes en BEGIN")
    return host, puerto


def codificar_extend(host: str, puerto: int, clave_relay: bytes, clave_cliente: bytes) -> bytes:
    """EXTEND: destino | clave cebolla del siguiente relay (32) | X efímera del cliente (32)."""
    if len(clave_relay) != TAM_CLAVE_PUBLICA or len(clave_cliente) != TAM_CLAVE_PUBLICA:
        raise CeldaInvalida("clave de tamaño incorrecto")
    return codificar_destino(host, puerto) + clave_relay + clave_cliente


def decodificar_extend(datos: bytes) -> tuple[str, int, bytes, bytes]:
    (host, puerto), usados = decodificar_destino(datos)
    resto = datos[usados:]
    if len(resto) != 2 * TAM_CLAVE_PUBLICA:
        raise CeldaInvalida("EXTEND con tamaño incorrecto")
    return host, puerto, resto[:TAM_CLAVE_PUBLICA], resto[TAM_CLAVE_PUBLICA:]
