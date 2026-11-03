"""Política del nodo de salida (amenaza STRIDE E: escalada hacia la LAN interna).

El nodo de salida nunca debe abrir conexiones hacia la red interna, el
propio equipo o direcciones especiales. Si lo hiciera, cualquier usuario
de MiniOni podría alcanzar paneles de administración o servicios internos
saltándose la segmentación de la red (OWASP ASVS 5.0 V2.2.1).

La verificación se hace sobre la IP ya RESUELTA (después del DNS), no sobre
el nombre: así un dominio que apunte a 127.0.0.1 también queda bloqueado.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path

from .errores import ConfiguracionInvalida, DestinoNoPermitido

PUERTOS_PERMITIDOS = frozenset({80, 443})
_CAMPOS_POLITICA = {"puertos", "excepciones_redes"}
_TAM_MAX_POLITICA = 16 * 1024
_MAX_PUERTOS = 64
_MAX_EXCEPCIONES = 32


@dataclass(frozen=True)
class PoliticaSalida:
    """Puertos permitidos y redes internas permitidas de forma explícita (cada una en docs/LIMITES.md)."""
    puertos: frozenset[int] = PUERTOS_PERMITIDOS
    excepciones: tuple[str, ...] = field(default=())


def _sin_duplicados(pares):
    obj = {}
    for k, v in pares:
        if k in obj:
            raise ConfiguracionInvalida("clave JSON duplicada")
        obj[k] = v
    return obj


def validar_politica(datos) -> PoliticaSalida:
    """Validación positiva: claves exactas, puertos 1-65535 sin repetir, redes con ip_network estricto."""
    if not isinstance(datos, dict) or set(datos) != _CAMPOS_POLITICA:
        raise ConfiguracionInvalida("campos de la política inesperados")
    puertos, redes = datos["puertos"], datos["excepciones_redes"]
    if not isinstance(puertos, list) or not 1 <= len(puertos) <= _MAX_PUERTOS:
        raise ConfiguracionInvalida("lista de puertos inválida")
    if any(isinstance(p, bool) or not isinstance(p, int) or not 1 <= p <= 65535 for p in puertos):
        raise ConfiguracionInvalida("puerto inválido")
    if len(set(puertos)) != len(puertos):
        raise ConfiguracionInvalida("puertos repetidos")
    if not isinstance(redes, list) or len(redes) > _MAX_EXCEPCIONES:
        raise ConfiguracionInvalida("lista de excepciones inválida")
    normalizadas = []
    for red in redes:
        if not isinstance(red, str) or not red.isascii():
            raise ConfiguracionInvalida("red inválida")
        try:
            normalizadas.append(str(ipaddress.ip_network(red, strict=True)))
        except ValueError:
            raise ConfiguracionInvalida("red inválida") from None
    return PoliticaSalida(frozenset(puertos), tuple(normalizadas))


def cargar_politica(ruta: Path) -> PoliticaSalida:
    """Lee config/politica_salida.json. Si no existe, se usan los valores por defecto (80 y 443)."""
    ruta = Path(ruta)
    if not ruta.exists():
        return PoliticaSalida()
    try:
        contenido = ruta.read_bytes()
        if len(contenido) > _TAM_MAX_POLITICA:
            raise ConfiguracionInvalida("archivo de política demasiado grande")
        datos = json.loads(contenido.decode("utf-8"), object_pairs_hook=_sin_duplicados)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise ConfiguracionInvalida("política de salida ilegible") from None
    return validar_politica(datos)


def verificar_ip_destino(ip: str, excepciones: tuple = ()) -> None:
    """Lanza DestinoNoPermitido si la IP no es pública.

    `excepciones` es una lista explícita de redes permitidas (por ejemplo, el
    servidor web del laboratorio en 10.10.9.0/24). Debe documentarse cada una.
    """
    try:
        direccion = ipaddress.ip_address(ip)
    except ValueError:
        raise DestinoNoPermitido("IP inválida") from None
    # IPv4 dentro de IPv6 (::ffff:10.0.0.1) se evalúa como IPv4.
    if isinstance(direccion, ipaddress.IPv6Address) and direccion.ipv4_mapped:
        direccion = direccion.ipv4_mapped
    if any(direccion in ipaddress.ip_network(red) for red in excepciones):
        return
    if not direccion.is_global or direccion.is_multicast:
        # is_global es False para RFC 1918, loopback, link-local, CGNAT,
        # documentación, reservadas y no especificadas.
        raise DestinoNoPermitido("destino interno o reservado")


def verificar_puerto_destino(puerto: int, permitidos: frozenset[int] = PUERTOS_PERMITIDOS) -> None:
    if puerto not in permitidos:
        raise DestinoNoPermitido("puerto no permitido por la política de salida")
