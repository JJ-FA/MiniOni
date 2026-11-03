"""Parser SOCKS5 (RFC 1928), solo lo necesario: sin autenticación y CONNECT.

Validación positiva (OWASP ASVS 5.0 V2.2.1): se acepta exactamente

    Saludo:     05 | NMETHODS (1-255) | métodos (debe incluir 00)
    Solicitud:  05 | CMD=01 | RSV=00 | ATYP | dirección | puerto (1-65535)
                ATYP 01 = IPv4 (4 bytes), 03 = dominio (largo 1-255 + nombre
                que pase `validar_host`), 04 = IPv6 (16 bytes)

y cualquier otra cosa termina en una respuesta genérica y el cierre de la
conexión. Las respuestas nunca dan detalles: solo 05 00 (éxito), 05 01
(fallo general), 05 02 (no permitido), 05 07 (comando no soportado) y
05 08 (tipo de dirección no soportado).

DNS remoto obligatorio: este módulo nunca resuelve nombres. El dominio
viaja tal cual en BEGIN y lo resuelve el nodo de salida.

Las funciones puras (`procesar_saludo`, `validar_cabecera_solicitud`,
`decodificar_solicitud`) se prueban y se fuzzean sin red; `negociar` las usa
sobre un StreamReader.
"""

from __future__ import annotations

import asyncio
import ipaddress
import struct

from .celdas import validar_host, validar_puerto
from .constantes import TIMEOUT_SOCKS_S
from .errores import DestinoNoPermitido, SocksInvalido

VERSION = 0x05
SIN_AUTENTICACION = 0x00
CMD_CONNECT = 0x01
ATYP_IPV4 = 0x01
ATYP_DOMINIO = 0x03
ATYP_IPV6 = 0x04

EXITO = 0x00
FALLO_GENERAL = 0x01
NO_PERMITIDO = 0x02
COMANDO_NO_SOPORTADO = 0x07
DIRECCION_NO_SOPORTADA = 0x08

SALUDO_ACEPTADO = bytes([VERSION, SIN_AUTENTICACION])
SALUDO_RECHAZADO = bytes([VERSION, 0xFF])


def respuesta(codigo: int) -> bytes:
    """Respuesta a la solicitud: 05 | código | 00 | 01 | 0.0.0.0 | 0 (nunca la dirección real)."""
    return bytes([VERSION, codigo, 0x00, ATYP_IPV4]) + bytes(6)


RESPUESTAS_VALIDAS = frozenset({SALUDO_ACEPTADO, SALUDO_RECHAZADO} | {
    respuesta(c) for c in (EXITO, FALLO_GENERAL, NO_PERMITIDO, COMANDO_NO_SOPORTADO, DIRECCION_NO_SOPORTADA)
})


# --- funciones puras ------------------------------------------------------------

def validar_cabecera_saludo(cabecera: bytes) -> int:
    """Primeros 2 bytes del saludo. Devuelve NMETHODS."""
    if len(cabecera) != 2 or cabecera[0] != VERSION:
        raise SocksInvalido("no es SOCKS5")
    if cabecera[1] == 0:
        raise SocksInvalido("sin métodos", SALUDO_RECHAZADO)
    return cabecera[1]


def procesar_saludo(datos: bytes) -> bytes:
    """Saludo completo -> respuesta 05 00. Si no ofrece 'sin autenticación' -> 05 FF y cierre."""
    n = validar_cabecera_saludo(bytes(datos[:2]))
    if len(datos) != 2 + n:
        raise SocksInvalido("saludo de tamaño incorrecto")
    if SIN_AUTENTICACION not in datos[2:]:
        raise SocksInvalido("sin método aceptable", SALUDO_RECHAZADO)
    return SALUDO_ACEPTADO


def validar_cabecera_solicitud(cabecera: bytes) -> int:
    """VER CMD RSV ATYP. Devuelve ATYP."""
    if len(cabecera) != 4 or cabecera[0] != VERSION:
        raise SocksInvalido("no es SOCKS5")
    if cabecera[1] != CMD_CONNECT:
        raise SocksInvalido("comando no soportado", respuesta(COMANDO_NO_SOPORTADO))
    if cabecera[2] != 0x00:
        raise SocksInvalido("byte reservado no nulo", respuesta(FALLO_GENERAL))
    if cabecera[3] not in (ATYP_IPV4, ATYP_DOMINIO, ATYP_IPV6):
        raise SocksInvalido("tipo de dirección no soportado", respuesta(DIRECCION_NO_SOPORTADA))
    return cabecera[3]


def decodificar_solicitud(datos: bytes) -> tuple[str, int]:
    """Solicitud completa -> (host, puerto). El host no se resuelve nunca."""
    atyp = validar_cabecera_solicitud(bytes(datos[:4]))
    resto = bytes(datos[4:])
    if atyp == ATYP_IPV4:
        largo_dir = 4
    elif atyp == ATYP_IPV6:
        largo_dir = 16
    else:
        if not resto or resto[0] == 0:
            raise SocksInvalido("dominio vacío", respuesta(FALLO_GENERAL))
        largo_dir = 1 + resto[0]
    if len(resto) != largo_dir + 2:
        raise SocksInvalido("solicitud de tamaño incorrecto", respuesta(FALLO_GENERAL))
    direccion, (puerto,) = resto[:largo_dir], struct.unpack(">H", resto[largo_dir:])
    try:
        if atyp == ATYP_IPV4:
            host = str(ipaddress.IPv4Address(direccion))
        elif atyp == ATYP_IPV6:
            host = str(ipaddress.IPv6Address(direccion))
        else:
            try:
                host = direccion[1:].decode("ascii")
            except UnicodeDecodeError:
                raise DestinoNoPermitido("dominio no ASCII") from None
        return validar_host(host), validar_puerto(puerto)
    except DestinoNoPermitido:
        raise SocksInvalido("destino no válido", respuesta(NO_PERMITIDO)) from None


# --- negociación sobre la red -----------------------------------------------------

async def _negociar(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> tuple[str, int]:
    cabecera = await reader.readexactly(2)
    n = validar_cabecera_saludo(cabecera)
    writer.write(procesar_saludo(cabecera + await reader.readexactly(n)))
    await writer.drain()

    cabecera = await reader.readexactly(4)
    atyp = validar_cabecera_solicitud(cabecera)
    if atyp == ATYP_IPV4:
        resto = await reader.readexactly(4 + 2)
    elif atyp == ATYP_IPV6:
        resto = await reader.readexactly(16 + 2)
    else:
        largo = await reader.readexactly(1)
        resto = largo + await reader.readexactly(largo[0] + 2)
    return decodificar_solicitud(cabecera + resto)


async def negociar(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                   timeout: float = TIMEOUT_SOCKS_S) -> tuple[str, int]:
    """Saludo + solicitud en `timeout` segundos. Devuelve (host, puerto) o lanza SocksInvalido.

    Si el error tiene una respuesta genérica, se envía antes de lanzar; quien
    llama cierra la conexión.
    """
    try:
        return await asyncio.wait_for(_negociar(reader, writer), timeout)
    except SocksInvalido as e:
        if e.respuesta is not None:
            try:
                writer.write(e.respuesta)
                await asyncio.wait_for(writer.drain(), 2)
            except (ConnectionError, OSError, RuntimeError, asyncio.TimeoutError):
                pass
        raise
    except asyncio.TimeoutError:
        raise SocksInvalido("tiempo agotado") from None
    except (asyncio.IncompleteReadError, ConnectionError, OSError, RuntimeError):
        raise SocksInvalido("conexión cerrada") from None
