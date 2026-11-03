"""Directorio de nodos firmado con Ed25519.

Requisito R3 (OWASP ASVS 5.0 V11.6.1) y amenazas STRIDE S y R:
- El cliente solo usa relays que aparecen en un directorio firmado por la
  autoridad. La clave pública de la autoridad se distribuye aparte (config/).
- La versión y las fechas van DENTRO del contenido firmado: cada publicación
  queda atribuida a la autoridad y no se puede reutilizar una versión vieja
  (anti-rollback con `version_minima`).

Archivo firmado:
    {"directorio": {...}, "firma": "<base64 de 64 bytes>"}

Directorio:
    {
      "version": 1,
      "publicado": "2026-10-22T00:00:00Z",
      "valido_hasta": "2026-10-29T00:00:00Z",
      "relays": [
        {"apodo": "entrada1", "host": "10.10.1.10", "puerto": 9001,
         "clave_cebolla": "<base64 X25519>", "huella_tls": "<sha256 hex>",
         "salida": false},
        ...
      ]
    }
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .celdas import validar_host, validar_puerto
from .constantes import (
    MAX_RELAYS,
    MIN_RELAYS,
    PROTOCOLO_ID,
    TAM_CLAVE_PUBLICA,
    TAM_FIRMA,
    TAM_MAX_DIRECTORIO,
)
from .errores import DestinoNoPermitido, DirectorioInvalido

_SEPARADOR_DOMINIO = PROTOCOLO_ID + b" directorio\n"
_APODO = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
_HUELLA = re.compile(r"^[0-9a-f]{64}$")
_FECHA = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_CAMPOS_DIR = {"version", "publicado", "valido_hasta", "relays"}
_CAMPOS_RELAY = {"apodo", "host", "puerto", "clave_cebolla", "huella_tls", "salida"}


@dataclass(frozen=True)
class Relay:
    apodo: str
    host: str
    puerto: int
    clave_cebolla: bytes
    huella_tls: str
    salida: bool


@dataclass(frozen=True)
class Directorio:
    version: int
    publicado: datetime
    valido_hasta: datetime
    relays: tuple[Relay, ...]

    def buscar(self, host: str, puerto: int) -> Relay | None:
        for r in self.relays:
            if r.host == host and r.puerto == puerto:
                return r
        return None


# --- utilidades ---------------------------------------------------------------

def _sin_duplicados(pares):
    """Rechaza JSON con claves repetidas (dos parsers podrían leerlo distinto)."""
    obj = {}
    for k, v in pares:
        if k in obj:
            raise DirectorioInvalido("clave JSON duplicada")
        obj[k] = v
    return obj


def bytes_canonicos(directorio: dict) -> bytes:
    """Representación única que se firma: JSON ordenado y compacto."""
    cuerpo = json.dumps(directorio, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return _SEPARADOR_DOMINIO + cuerpo.encode("ascii")


def _b64_exacto(texto, largo: int, campo: str) -> bytes:
    if not isinstance(texto, str):
        raise DirectorioInvalido(f"{campo}: no es texto")
    try:
        datos = base64.b64decode(texto, validate=True)
    except (binascii.Error, ValueError):
        raise DirectorioInvalido(f"{campo}: base64 inválido") from None
    if len(datos) != largo:
        raise DirectorioInvalido(f"{campo}: tamaño incorrecto")
    return datos


def _fecha(texto, campo: str) -> datetime:
    if not isinstance(texto, str) or not _FECHA.fullmatch(texto):
        raise DirectorioInvalido(f"{campo}: formato de fecha inválido")
    try:
        return datetime.strptime(texto, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise DirectorioInvalido(f"{campo}: fecha inexistente") from None


def formato_fecha(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --- validación del contenido (ASVS V2.2.1) ------------------------------------

def _validar_relay(r) -> Relay:
    if not isinstance(r, dict) or set(r) != _CAMPOS_RELAY:
        raise DirectorioInvalido("relay con campos inesperados")
    if not isinstance(r["apodo"], str) or not _APODO.fullmatch(r["apodo"]):
        raise DirectorioInvalido("apodo inválido")
    try:
        host = validar_host(r["host"])
        puerto = validar_puerto(r["puerto"])
    except DestinoNoPermitido:
        raise DirectorioInvalido("dirección de relay inválida") from None
    if not isinstance(r["huella_tls"], str) or not _HUELLA.fullmatch(r["huella_tls"]):
        raise DirectorioInvalido("huella TLS inválida")
    if not isinstance(r["salida"], bool):
        raise DirectorioInvalido("campo salida inválido")
    clave = _b64_exacto(r["clave_cebolla"], TAM_CLAVE_PUBLICA, "clave_cebolla")
    return Relay(r["apodo"], host, puerto, clave, r["huella_tls"], r["salida"])


def validar_estructura(d) -> Directorio:
    if not isinstance(d, dict) or set(d) != _CAMPOS_DIR:
        raise DirectorioInvalido("campos del directorio inesperados")
    v = d["version"]
    if isinstance(v, bool) or not isinstance(v, int) or not 1 <= v <= 2**31:
        raise DirectorioInvalido("versión inválida")
    publicado = _fecha(d["publicado"], "publicado")
    valido_hasta = _fecha(d["valido_hasta"], "valido_hasta")
    if valido_hasta <= publicado:
        raise DirectorioInvalido("vigencia inválida")
    lista = d["relays"]
    if not isinstance(lista, list) or not MIN_RELAYS <= len(lista) <= MAX_RELAYS:
        raise DirectorioInvalido("cantidad de relays fuera de rango")
    relays = tuple(_validar_relay(r) for r in lista)
    if len({r.apodo for r in relays}) != len(relays):
        raise DirectorioInvalido("apodos repetidos")
    if len({r.clave_cebolla for r in relays}) != len(relays):
        raise DirectorioInvalido("claves repetidas")
    if len({(r.host, r.puerto) for r in relays}) != len(relays):
        raise DirectorioInvalido("direcciones repetidas")
    if not any(r.salida for r in relays):
        raise DirectorioInvalido("no hay nodos de salida")
    return Directorio(v, publicado, valido_hasta, relays)


# --- firma y verificación -------------------------------------------------------

def firmar(directorio: dict, clave_autoridad: Ed25519PrivateKey) -> bytes:
    """Valida y firma. Devuelve el archivo firmado listo para guardar."""
    validar_estructura(directorio)
    firma = clave_autoridad.sign(bytes_canonicos(directorio))
    salida = {"directorio": directorio, "firma": base64.b64encode(firma).decode("ascii")}
    return json.dumps(salida, indent=2, ensure_ascii=True, sort_keys=True).encode("ascii") + b"\n"


def verificar(
    contenido: bytes,
    clave_autoridad: bytes,
    ahora: datetime | None = None,
    version_minima: int = 1,
) -> Directorio:
    """Verifica firma, formato y vigencia. Ante cualquier fallo: DirectorioInvalido (fail-closed)."""
    if not isinstance(contenido, (bytes, bytearray)) or len(contenido) > TAM_MAX_DIRECTORIO:
        raise DirectorioInvalido("archivo demasiado grande")
    try:
        externo = json.loads(contenido.decode("utf-8"), object_pairs_hook=_sin_duplicados)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise DirectorioInvalido("JSON mal formado") from None
    if not isinstance(externo, dict) or set(externo) != {"directorio", "firma"}:
        raise DirectorioInvalido("estructura externa inesperada")
    firma = _b64_exacto(externo["firma"], TAM_FIRMA, "firma")

    # 1. Primero la firma: no se confía en nada del contenido antes de verificarla.
    try:
        Ed25519PublicKey.from_public_bytes(clave_autoridad).verify(
            firma, bytes_canonicos(externo["directorio"])
        )
    except (InvalidSignature, ValueError, TypeError):
        raise DirectorioInvalido("firma inválida") from None

    # 2. Luego la estructura y la vigencia.
    directorio = validar_estructura(externo["directorio"])
    ahora = ahora or datetime.now(timezone.utc)
    if not directorio.publicado <= ahora < directorio.valido_hasta:
        raise DirectorioInvalido("directorio fuera de vigencia")
    if directorio.version < version_minima:
        raise DirectorioInvalido("versión anterior a la aceptada")
    return directorio
