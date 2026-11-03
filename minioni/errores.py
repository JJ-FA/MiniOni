"""Excepciones de MiniOni.

Cada excepción trae un `mensaje_publico` genérico. Es lo único que puede
llegar al usuario o a la consola (ASVS V16.5.1). El detalle técnico se
queda en la excepción para las pruebas y nunca se imprime con la traza.
"""

from __future__ import annotations


class MiniOniError(Exception):
    mensaje_publico = "error interno"


class CeldaInvalida(MiniOniError):
    """La celda no cumple el formato esperado (ASVS V2.2.1)."""
    mensaje_publico = "celda rechazada"


class CeldaManipulada(MiniOniError):
    """La verificación Poly1305 falló: alguien alteró la celda (ASVS V11.3.3)."""
    mensaje_publico = "celda rechazada"


class HandshakeFallido(MiniOniError):
    """El intercambio de claves con un relay no pudo completarse."""
    mensaje_publico = "no se pudo construir el circuito"


class DirectorioInvalido(MiniOniError):
    """Firma, formato o vigencia del directorio no válidos."""
    mensaje_publico = "directorio de nodos no válido"


class ClaveInvalida(MiniOniError):
    """Contraseña incorrecta o archivo de clave dañado."""
    mensaje_publico = "no se pudo abrir la clave"


class DestinoNoPermitido(MiniOniError):
    """El destino pedido no es válido o la política de salida lo bloquea."""
    mensaje_publico = "destino no permitido"


class TLSInvalido(MiniOniError):
    """El handshake TLS 1.3 falló o la huella del certificado no es la del directorio."""
    mensaje_publico = "no se pudo construir el circuito"


class EnlaceCerrado(MiniOniError):
    """La conexión TLS con el otro nodo se cerró o no se pudo abrir."""
    mensaje_publico = "conexión cerrada"


class SocksInvalido(MiniOniError):
    """La negociación SOCKS5 no cumple el formato aceptado (ASVS V2.2.1).

    `respuesta` son los bytes que se envían al navegador antes de cerrar
    (siempre una respuesta genérica de RFC 1928), o None si no se responde.
    """
    mensaje_publico = "solicitud SOCKS5 rechazada"

    def __init__(self, detalle: str = "solicitud SOCKS5 inválida", respuesta: bytes | None = None) -> None:
        super().__init__(detalle)
        self.respuesta = respuesta


class ConfiguracionInvalida(MiniOniError):
    """Un archivo u opción de configuración local no cumple el formato estricto."""
    mensaje_publico = "configuración no válida"


class CarpetaClavesInvalida(ConfiguracionInvalida):
    """MINIONI_CLAVES no es una carpeta local absoluta. El mensaje nunca repite la ruta."""

    def __init__(self, motivo: str) -> None:
        super().__init__(f"MINIONI_CLAVES no válida: {motivo}")
        self.mensaje_publico = f"MINIONI_CLAVES no válida: {motivo}"


class PruebaFallida(MiniOniError):
    """Una prueba del panel (eco o página) no se completó. El mensaje es genérico y fijo."""

    def __init__(self, mensaje_publico: str) -> None:
        super().__init__(mensaje_publico)
        self.mensaje_publico = mensaje_publico


class CircuitoCerrado(MiniOniError):
    """El circuito se destruyó (llegó un DESTROY o falló un salto)."""
    mensaje_publico = "el circuito se cerró"

    def __init__(self, detalle: str = "circuito cerrado", motivo: int | None = None) -> None:
        super().__init__(detalle)
        self.motivo = motivo


class CertificadoVencido(MiniOniError):
    """El certificado TLS de un relay está vencido o todavía no es válido."""
    mensaje_publico = "certificado TLS vencido o aún no válido"
