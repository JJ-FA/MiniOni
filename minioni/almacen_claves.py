"""Almacenamiento de claves privadas en disco (cifrado en reposo).

Requisito no funcional "Cifrado en reposo" (OWASP ASVS 5.0 V11.4.4 y V11.1.1):
- La clave privada se cifra con ChaCha20-Poly1305 usando una clave derivada
  de una contraseña con scrypt (N=2^17, r=8, p=1, parámetros recomendados por OWASP).
- El archivo se crea con permisos 600 y nunca sobrescribe uno existente.
- La contraseña se pide con getpass, nunca como argumento de línea de comandos
  (quedaría en el historial de la terminal).

Nota Windows: os.chmod solo controla "solo lectura" en Windows. Ahí la
protección real es la carpeta del usuario; queda documentado en docs/LIMITES.md.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .errores import CarpetaClavesInvalida, ClaveInvalida

FORMATO = "minioni-clave-v1"
# tipo -> (tamaño mínimo, tamaño máximo) de la clave privada en bytes
TIPOS = {
    "x25519": (32, 32),        # clave cebolla del relay
    "ed25519": (32, 32),       # clave de la autoridad del directorio
    "p256-pkcs8": (100, 200),  # clave del certificado TLS (ECDSA P-256, DER PKCS#8)
}
N_SCRYPT = 2**17
N_SCRYPT_PRUEBAS = 2**14
N_SCRYPT_MINIMO = N_SCRYPT_PRUEBAS   # nombre usado por las pruebas: valor rápido para generar claves
# Mínimo que se ACEPTA al guardar o cargar. En uso normal es el recomendado por OWASP
# (2^17). Antes era 2^14 para que las pruebas corrieran rápido, y eso dejaba aceptar
# en producción claves 8 veces más fáciles de atacar (hallazgo de la Clase 3).
# Solo tests/conftest.py lo baja.
minimo_aceptado = N_SCRYPT
R_SCRYPT = 8
P_SCRYPT = 1
TAM_MAX_ARCHIVO = 4096


def _derivar(contrasena: str, sal: bytes, n: int) -> bytes:
    return Scrypt(salt=sal, length=32, n=n, r=R_SCRYPT, p=P_SCRYPT).derive(contrasena.encode("utf-8"))


def _aad(tipo: str) -> bytes:
    # Asocia el cifrado al formato y al tipo: no se puede cambiar el tipo sin romper la etiqueta.
    return f"{FORMATO}|{tipo}".encode("ascii")


def guardar_privada(ruta: Path, privada: bytes, tipo: str, contrasena: str, n: int = N_SCRYPT) -> None:
    if tipo not in TIPOS or not TIPOS[tipo][0] <= len(privada) <= TIPOS[tipo][1]:
        raise ValueError("tipo o tamaño de clave no soportado")
    motivo = motivo_contrasena_debil(contrasena)
    if motivo:
        raise ValueError(f"la contraseña {motivo}")
    if n < minimo_aceptado:
        raise ValueError("parámetro scrypt demasiado débil")
    sal, nonce = os.urandom(16), os.urandom(12)
    cifrado = ChaCha20Poly1305(_derivar(contrasena, sal, n)).encrypt(nonce, privada, _aad(tipo))
    doc = {
        "formato": FORMATO,
        "tipo": tipo,
        "kdf": {"nombre": "scrypt", "n": n, "r": R_SCRYPT, "p": P_SCRYPT},
        "sal": base64.b64encode(sal).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "cifrado": base64.b64encode(cifrado).decode(),
    }
    ruta = Path(ruta)
    ruta.parent.mkdir(parents=True, exist_ok=True)
    # O_EXCL: falla si ya existe; 0o600: solo el dueño puede leer y escribir.
    fd = os.open(ruta, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")


def cargar_privada(ruta: Path, contrasena: str, tipo_esperado: str) -> bytes:
    try:
        crudo = Path(ruta).read_bytes()
        if len(crudo) > TAM_MAX_ARCHIVO:
            raise ClaveInvalida("archivo demasiado grande")
        doc = json.loads(crudo.decode("ascii"))
        if doc["formato"] != FORMATO or doc["tipo"] != tipo_esperado:
            raise ClaveInvalida("formato o tipo inesperado")
        kdf = doc["kdf"]
        n = kdf["n"]
        if (kdf["nombre"] != "scrypt" or not isinstance(n, int) or n < minimo_aceptado
                or n > 2**20 or n & (n - 1) or kdf["r"] != R_SCRYPT or kdf["p"] != P_SCRYPT):
            raise ClaveInvalida("parámetros KDF no aceptados")
        sal = base64.b64decode(doc["sal"], validate=True)
        nonce = base64.b64decode(doc["nonce"], validate=True)
        cifrado = base64.b64decode(doc["cifrado"], validate=True)
        if len(sal) != 16 or len(nonce) != 12:
            raise ClaveInvalida("sal o nonce de tamaño incorrecto")
        privada = ChaCha20Poly1305(_derivar(contrasena, sal, n)).decrypt(nonce, cifrado, _aad(tipo_esperado))
    except ClaveInvalida:
        raise
    except (OSError, ValueError, KeyError, TypeError, InvalidTag, binascii.Error):
        # Mismo error para "contraseña incorrecta" y "archivo dañado": no da pistas.
        raise ClaveInvalida("no se pudo abrir la clave") from None
    minimo, maximo = TIPOS.get(tipo_esperado, (1, 0))
    if not minimo <= len(privada) <= maximo:
        raise ClaveInvalida("clave de tamaño incorrecto")
    return privada


def guardar_publica(ruta: Path, publica: bytes) -> None:
    Path(ruta).parent.mkdir(parents=True, exist_ok=True)
    Path(ruta).write_text(base64.b64encode(publica).decode("ascii") + "\n", encoding="ascii")


def cargar_publica(ruta: Path) -> bytes:
    try:
        texto = Path(ruta).read_text(encoding="ascii").strip()
        datos = base64.b64decode(texto, validate=True)
    except (OSError, ValueError, binascii.Error):
        raise ClaveInvalida("clave pública ilegible") from None
    if len(datos) != 32:
        raise ClaveInvalida("clave pública de tamaño incorrecto")
    return datos


# Carpetas que se copian solas a la nube. Una clave privada ahí sale del equipo,
# aunque vaya cifrada (NIST SSDF PS.1: proteger los secretos del proyecto).
_SERVICIOS_NUBE = re.compile(r"onedrive|dropbox|google ?drive|icloud ?drive|mega(sync)?$", re.IGNORECASE)
_VARIABLES_ONEDRIVE = ("OneDrive", "OneDriveConsumer", "OneDriveCommercial")


def carpeta_sincronizada(ruta: Path) -> str | None:
    """Devuelve el nombre del servicio si `ruta` está dentro de una carpeta que se sube a la nube."""
    ruta = Path(ruta).resolve()
    for variable in _VARIABLES_ONEDRIVE:
        raiz = os.environ.get(variable)
        if raiz:
            try:
                ruta.relative_to(Path(raiz).resolve())
                return "OneDrive"
            except ValueError:
                pass
    for parte in ruta.parts:
        coincidencia = _SERVICIOS_NUBE.search(parte)
        if coincidencia:
            return parte
    return None


# --- dónde viven las claves privadas (Clase 3, fallo 9) ----------------------------

VARIABLE_CLAVES = "MINIONI_CLAVES"
CARPETA_PREDETERMINADA = Path("claves")


def carpeta_claves() -> Path:
    """Carpeta de las claves privadas: MINIONI_CLAVES si está definida, si no 'claves'.

    La variable permite sacar las claves de una carpeta que se sube a la nube
    (OneDrive en los equipos del grupo). Se valida en positivo y se falla cerrado:
    ruta absoluta, que no sea un archivo y que no esté sincronizada. Los errores
    nunca repiten la ruta (ASVS 5.0 V16.5.1).
    """
    valor = os.environ.get(VARIABLE_CLAVES, "").strip()
    if not valor:
        return CARPETA_PREDETERMINADA
    ruta = Path(valor)
    if not ruta.is_absolute():
        raise CarpetaClavesInvalida("debe ser una ruta absoluta, por ejemplo C:\\MiniOniClaves")
    ruta = ruta.resolve()
    if ruta.exists() and not ruta.is_dir():
        raise CarpetaClavesInvalida("la ruta existe pero no es una carpeta")
    if carpeta_sincronizada(ruta):
        raise CarpetaClavesInvalida("está dentro de una carpeta que se sube a la nube")
    return ruta


# --- calidad de la contraseña que protege las claves (ASVS 5.0 V6.2.4) -----------

MIN_LARGO_CONTRASENA = 12
_COMUNES = {
    "123456789012", "1234567890123", "12345678901234", "123456789123", "098765432109",
    "qwertyuiopas", "qwertyuiop12", "qwerty123456", "qwertyqwerty", "asdfghjklñzx",
    "password1234", "passwordpassword", "password123!", "iloveyou1234", "administrator",
    "administrador", "contraseña123", "contrasena123", "abcdefghijkl", "abc123abc123",
    "123123123123", "aaaaaaaaaaaa", "000000000000", "111111111111", "minionimini1",
}
_PALABRAS_BASE = ("password", "contraseña", "contrasena", "qwerty", "admin", "minioni",
                  "welcome", "bienvenido", "letmein", "iloveyou", "clave", "secreto")
_FILAS_TECLADO = ("1234567890qwertyuiop", "qwertyuiopasdfghjklñ", "asdfghjklñzxcvbnm", "1234567890",
                  "qwertyuiop", "asdfghjklñ", "asdfghjkl", "zxcvbnm")


def motivo_contrasena_debil(contrasena: str) -> str | None:
    """Devuelve por qué la contraseña es débil, o None si es aceptable.

    Solo largo no basta: "aaaaaaaaaaaa" o "123456789012" cumplen 12 caracteres y caen
    en segundos con un diccionario (hallazgo de la Clase 3). Lista local, sin internet.
    """
    if len(contrasena) < MIN_LARGO_CONTRASENA:
        return f"debe tener al menos {MIN_LARGO_CONTRASENA} caracteres"
    baja = contrasena.lower()
    if baja in _COMUNES:
        return "es una contraseña muy común"
    if len(set(baja)) < 5:
        return "tiene muy pocos caracteres distintos"
    sin_cola = baja.rstrip("0123456789!@#$%&*.-_ ")
    if sin_cola in _PALABRAS_BASE or not sin_cola:
        return "es una palabra común seguida de números o símbolos"
    for fila in _FILAS_TECLADO:
        doble = fila * 3
        if baja in doble or baja in doble[::-1]:
            return "es una secuencia del teclado"
    return None
