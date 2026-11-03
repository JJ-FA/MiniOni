"""Transporte entre nodos: TLS 1.3 con pinning de certificado y celdas de 512 bytes.

Requisitos (OWASP ASVS 5.0):
- V12.1.1: solo TLS 1.3 (mínimo y máximo), en servidor y en cliente.
- V12.3.4: se confía solo en el certificado autofirmado cuya huella SHA-256
  aparece en el directorio firmado (pinning). No se usan autoridades de
  certificación ni nombres de host.
- V2.2.1: del enlace solo se leen bloques exactos de 512 bytes que pasan por
  `decodificar_celda`; cualquier otra cosa cierra el enlace.

Un relay NO autentica a quien se le conecta: clientes y relays entran igual
(ver docs/LIMITES.md). La autenticación del relay ante el cliente la dan el
pinning TLS y, por encima, el handshake cebolla.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import secrets
import ssl
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .celdas import Celda, decodificar_celda
from .constantes import TAM_CELDA, TIMEOUT_ENVIO_S, TIMEOUT_HANDSHAKE_S
from .errores import CertificadoVencido, EnlaceCerrado, TLSInvalido


def _solo_tls13(ctx: ssl.SSLContext) -> ssl.SSLContext:
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    return ctx


def huella_certificado(ruta_crt: Path) -> str:
    """SHA-256 (hex) del DER del certificado PEM, igual que `huella_tls` del directorio."""
    der = ssl.PEM_cert_to_DER_cert(Path(ruta_crt).read_text(encoding="ascii"))
    return hashlib.sha256(der).hexdigest()


def contexto_servidor(ruta_crt: Path, der_clave: bytes) -> ssl.SSLContext:
    """Contexto TLS 1.3 del relay a partir de la clave TLS ya descifrada (DER PKCS#8).

    `load_cert_chain` solo acepta archivos, y la clave en disco está en el
    contenedor scrypt. Se escribe un PEM temporal cifrado con una contraseña
    aleatoria de 256 bits de un solo uso y se borra enseguida: con esa
    contraseña, la debilidad del PBKDF2 del PEM no importa
    (docs/INVENTARIO_CRIPTOGRAFICO.md).
    """
    clave = serialization.load_der_private_key(der_clave, password=None)
    contrasena = secrets.token_urlsafe(32)
    pem = clave.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(contrasena.encode("ascii")),
    )
    ctx = _solo_tls13(ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER))
    fd, ruta = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(pem)
        ctx.load_cert_chain(str(ruta_crt), ruta, password=contrasena)
    finally:
        try:
            os.unlink(ruta)
        except OSError:
            pass
    return ctx


def contexto_cliente() -> ssl.SSLContext:
    """Contexto TLS 1.3 para conectarse a un relay (lo usan el cliente y los relays al extender).

    No se valida la cadena ni el nombre porque el certificado es autofirmado:
    la confianza viene de `verificar_huella`, que se llama justo después del
    handshake y antes de enviar cualquier celda.
    """
    ctx = _solo_tls13(ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT))
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE   # la confianza la da el pinning (verificar_huella)
    return ctx


def verificar_vigencia(der: bytes, ahora: datetime | None = None) -> None:
    """Rechaza un certificado vencido o que todavía no es válido.

    Con pinning, OpenSSL no revisa la cadena ni las fechas: sin esta comprobación un
    certificado vencido seguía funcionando y sus 90 días de vigencia no servían de
    nada (hallazgo de la Clase 3; ASVS 5.0 V11.1.1 y V12.3.4).
    """
    try:
        cert = x509.load_der_x509_certificate(der)
    except ValueError:
        raise TLSInvalido("certificado ilegible") from None
    ahora = ahora or datetime.now(timezone.utc)
    if not cert.not_valid_before_utc <= ahora <= cert.not_valid_after_utc:
        raise CertificadoVencido("certificado fuera de vigencia")


def verificar_huella(writer: asyncio.StreamWriter, huella_esperada: str) -> None:
    objeto = writer.get_extra_info("ssl_object")
    der = objeto.getpeercert(binary_form=True) if objeto is not None else None
    if der is None or not hmac.compare_digest(hashlib.sha256(der).hexdigest(), huella_esperada):
        writer.close()
        raise TLSInvalido("huella TLS no coincide")
    try:
        verificar_vigencia(der)
    except (TLSInvalido, CertificadoVencido):
        writer.close()
        raise


class Enlace:
    """Conexión TLS con otro nodo, por la que viajan celdas de 512 bytes.

    Un único escritor por enlace (asyncio.Lock): dos tareas nunca mezclan los
    bytes de sus celdas, y las celdas salen en el orden en que se pidieron.
    """

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 saliente: bool = False, timeout_envio: float = TIMEOUT_ENVIO_S) -> None:
        self._reader = reader
        self._writer = writer
        self._lock = asyncio.Lock()
        self._timeout_envio = timeout_envio
        self.saliente = saliente          # True si este nodo abrió la conexión
        self.cerrado = False
        self.ultima_actividad = time.monotonic()

    async def leer_celda(self) -> Celda:
        """Lee exactamente 512 bytes y los valida. Lanza EnlaceCerrado o CeldaInvalida."""
        try:
            datos = await self._reader.readexactly(TAM_CELDA)
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            self.cerrar()
            raise EnlaceCerrado("enlace cerrado") from None
        self.ultima_actividad = time.monotonic()
        return decodificar_celda(datos)

    async def enviar(self, celda: Celda) -> None:
        datos = celda.codificar()
        async with self._lock:
            if self.cerrado:
                raise EnlaceCerrado("enlace cerrado")
            try:
                self._writer.write(datos)
                await asyncio.wait_for(self._writer.drain(), self._timeout_envio)
            except (ConnectionError, OSError, asyncio.TimeoutError, RuntimeError):
                self.cerrar()
                raise EnlaceCerrado("no se pudo enviar") from None
        self.ultima_actividad = time.monotonic()

    def puerto_local(self) -> int | None:
        """Solo para pruebas (comprobar que no aparece en la consola)."""
        nombre = self._writer.get_extra_info("sockname")
        return nombre[1] if nombre else None

    def cerrar(self) -> None:
        """Idempotente."""
        if self.cerrado:
            return
        self.cerrado = True
        try:
            self._writer.close()
        except (OSError, RuntimeError):
            pass

    def abortar(self) -> None:
        """Corta la conexión sin despedirse (simula la caída de un nodo)."""
        self.cerrado = True
        try:
            self._writer.transport.abort()
        except (OSError, RuntimeError, AttributeError):
            pass

    async def esperar_cierre(self, timeout: float = 2.0) -> None:
        try:
            await asyncio.wait_for(self._writer.wait_closed(), timeout)
        except (ConnectionError, OSError, asyncio.TimeoutError, ssl.SSLError):
            pass


async def conectar(relay, ctx: ssl.SSLContext | None = None,
                   timeout: float = TIMEOUT_HANDSHAKE_S) -> Enlace:
    """Abre un enlace TLS 1.3 hacia `relay` (entrada del directorio) y verifica su huella.

    Lanza TLSInvalido si el handshake TLS falla o la huella no coincide, y
    EnlaceCerrado si el relay no responde. No se envía nada antes del pinning.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(relay.host, relay.puerto, ssl=ctx or contexto_cliente(),
                                    ssl_handshake_timeout=timeout),
            timeout,
        )
    except ssl.SSLError:
        raise TLSInvalido("handshake TLS fallido") from None
    except (OSError, asyncio.TimeoutError):
        raise EnlaceCerrado("relay inalcanzable") from None
    verificar_huella(writer, relay.huella_tls)
    return Enlace(reader, writer, saliente=True)


def dias_restantes(der: bytes, ahora: datetime | None = None) -> int:
    """Días completos que le quedan al certificado (negativo si ya venció).

    Lo usan el relay al arrancar (evento CERTIFICADO_POR_VENCER) y
    `minioni_admin.py revisar-certificados` (Clase 3, T6; ASVS 5.0 V11.1.1).
    Va al final del archivo para no mover las líneas citadas en la documentación.
    """
    try:
        cert = x509.load_der_x509_certificate(der)
    except ValueError:
        raise TLSInvalido("certificado ilegible") from None
    return (cert.not_valid_after_utc - (ahora or datetime.now(timezone.utc))).days
