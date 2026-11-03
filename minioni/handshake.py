"""Intercambio de claves entre el cliente y cada relay (inspirado en ntor de Tor).

Requisito R3 (OWASP ASVS 5.0 V11.6.1 / V11.6.2) y R5 (NIST SSDF PW.4.1):
se usan X25519, HKDF-SHA256 y HMAC-SHA256 de la librería `cryptography`.
No se inventa ningún algoritmo, solo se combinan primitivas estándar.

Notación:
    B, b  clave cebolla del relay (pública en el directorio firmado / privada en disco)
    X, x  clave efímera del cliente para este salto
    Y, y  clave efímera del relay para este salto

1. Cliente -> relay (CREATE o EXTEND):  B | X
2. Relay calcula  s = X25519(y, X) | X25519(b, X) | B | X | Y | "MiniOni-v1"
   y deriva con HKDF 96 bytes: clave_auth | clave_ida | clave_vuelta.
   Relay -> cliente (CREATED o EXTENDED):  Y | HMAC(clave_auth, B | X | Y | "relay")
3. El cliente calcula lo mismo con X25519(x, Y) y X25519(x, B) y verifica el HMAC.

Por qué así:
- X25519(b, X) solo lo puede calcular quien tiene la clave privada del relay
  publicada en el directorio: un relay falso no puede producir el HMAC (anti-suplantación).
- X25519(y, X) usa dos claves efímeras: si después roban `b`, el tráfico
  grabado sigue protegido (secreto hacia adelante).
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .capas import CapaSalto
from .constantes import PROTOCOLO_ID, TAM_CLAVE_PUBLICA
from .errores import HandshakeFallido

TAM_SOLICITUD = 2 * TAM_CLAVE_PUBLICA     # B | X
TAM_RESPUESTA = TAM_CLAVE_PUBLICA + 32    # Y | HMAC


def _x25519(privada: X25519PrivateKey, publica_bytes: bytes) -> bytes:
    try:
        compartido = privada.exchange(X25519PublicKey.from_public_bytes(publica_bytes))
    except ValueError:
        # Punto de orden bajo o clave mal formada: resultado todo ceros.
        raise HandshakeFallido("clave pública no válida") from None
    if compartido == bytes(32):
        raise HandshakeFallido("secreto compartido nulo")
    return compartido


def _derivar(entrada: bytes) -> tuple[bytes, bytes, bytes]:
    material = HKDF(
        algorithm=hashes.SHA256(),
        length=96,
        salt=PROTOCOLO_ID,
        info=PROTOCOLO_ID + b" claves de salto",
    ).derive(entrada)
    return material[:32], material[32:64], material[64:]


def _mac(clave_auth: bytes, B: bytes, X: bytes, Y: bytes) -> hmac.HMAC:
    h = hmac.HMAC(clave_auth, hashes.SHA256())
    h.update(B + X + Y + PROTOCOLO_ID + b" relay")
    return h


@dataclass
class HandshakeCliente:
    """Estado del cliente mientras espera la respuesta de un relay."""
    clave_relay: bytes
    _x: X25519PrivateKey

    @classmethod
    def iniciar(cls, clave_relay: bytes) -> tuple["HandshakeCliente", bytes]:
        if len(clave_relay) != TAM_CLAVE_PUBLICA:
            raise HandshakeFallido("clave del relay de tamaño incorrecto")
        x = X25519PrivateKey.generate()
        X = x.public_key().public_bytes_raw()
        return cls(clave_relay, x), clave_relay + X

    def finalizar(self, respuesta: bytes) -> CapaSalto:
        if self._x is None:
            raise HandshakeFallido("handshake ya finalizado")
        if len(respuesta) != TAM_RESPUESTA:
            raise HandshakeFallido("respuesta de tamaño incorrecto")
        Y, etiqueta = respuesta[:TAM_CLAVE_PUBLICA], respuesta[TAM_CLAVE_PUBLICA:]
        B = self.clave_relay
        X = self._x.public_key().public_bytes_raw()
        entrada = _x25519(self._x, Y) + _x25519(self._x, B) + B + X + Y + PROTOCOLO_ID
        auth, ida, vuelta = _derivar(entrada)
        try:
            _mac(auth, B, X, Y).verify(etiqueta)   # comparación en tiempo constante
        except InvalidSignature:
            raise HandshakeFallido("el relay no demostró tener su clave") from None
        self._x = None   # la clave efímera ya no se necesita
        return CapaSalto(ida, vuelta)


def relay_responder(clave_cebolla: X25519PrivateKey, solicitud: bytes) -> tuple[CapaSalto, bytes]:
    """Lado relay: procesa B | X y devuelve (capa, Y | HMAC)."""
    if len(solicitud) != TAM_SOLICITUD:
        raise HandshakeFallido("solicitud de tamaño incorrecto")
    B, X = solicitud[:TAM_CLAVE_PUBLICA], solicitud[TAM_CLAVE_PUBLICA:]
    propia = clave_cebolla.public_key().public_bytes_raw()
    if B != propia:
        raise HandshakeFallido("la solicitud no es para este relay")
    y = X25519PrivateKey.generate()
    Y = y.public_key().public_bytes_raw()
    entrada = _x25519(y, X) + _x25519(clave_cebolla, X) + B + X + Y + PROTOCOLO_ID
    auth, ida, vuelta = _derivar(entrada)
    etiqueta = _mac(auth, B, X, Y).finalize()
    return CapaSalto(ida, vuelta), Y + etiqueta
