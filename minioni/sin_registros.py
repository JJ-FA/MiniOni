"""Verificación de "sin registros": demuestra que una búsqueda por MiniOni no deja rastro.

Método (búsqueda testigo):
1. Se inventa una palabra al azar que no existe en ningún otro sitio (el
   testigo) y se busca a través del proxy SOCKS5 y el circuito de 3 saltos.
2. Mientras dura la búsqueda:
   - `VigiaEscrituras` usa los audit hooks de Python (PEP 578) para anotar
     CADA intento de este proceso de abrir un archivo para escribir, crear,
     renombrar o borrar archivos. Relays, proxy y panel corren en este mismo
     proceso, así que nada de MiniOni puede escribir sin que se vea.
   - `EspejoConsola` copia todo lo que se imprime en stdout y stderr.
3. Al terminar, `buscar_en_archivos` recorre las carpetas del proyecto y la
   carpeta temporal buscando el testigo y el dominio en los archivos
   modificados desde el inicio.

Aprobado = 0 escrituras, 0 apariciones en consola y 0 archivos con el testigo.

Privacidad: el vigía anota solo la ruta local y el tipo de operación, nunca
contenido. Nada de esto se guarda en disco: el informe vive en memoria.
Límites (docs/LIMITES.md): solo ve lo que hace Python; lo que haga Windows
por su cuenta (caché DNS del sistema, archivo de paginación) queda fuera.
"""

from __future__ import annotations

import os
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path

# Eventos de auditoría que modifican el disco (además de "open" en modo escritura).
EVENTOS_DISCO = {"os.rename", "os.remove", "os.mkdir", "os.rmdir", "os.truncate",
                 "os.link", "os.symlink", "shutil.copyfile", "shutil.move", "sqlite3.connect"}
FLAGS_ESCRITURA = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC
MAX_BYTES_ARCHIVO = 20 * 1024 * 1024

_lock = threading.Lock()
_vigias: list[VigiaEscrituras] = []
_instalado = False


def _es_escritura(evento: str, args: tuple) -> bool:
    if evento in EVENTOS_DISCO:
        return True
    if evento != "open" or len(args) < 3:
        return False
    _, modo, flags = args[:3]
    if isinstance(modo, str):
        return any(c in modo for c in "wax+")
    return isinstance(flags, int) and bool(flags & FLAGS_ESCRITURA)


def _ruta(args: tuple) -> str:
    primero = args[0] if args else ""
    if isinstance(primero, (str, bytes, os.PathLike)):
        return os.fsdecode(primero)
    return "(descriptor)"


def _gancho(evento: str, args: tuple) -> None:
    # Se llama en TODOS los hilos y por cada evento: lo más barato posible.
    if not _vigias or not _es_escritura(evento, args):
        return
    ruta = _ruta(args)
    # Python compila módulos importados por primera vez (.pyc). No es un
    # registro de actividad: es caché de código, no contiene datos del usuario.
    if ruta.endswith(".pyc"):
        return
    with _lock:
        for vigia in _vigias:
            vigia.escrituras.append((evento, ruta))


class VigiaEscrituras:
    """`with VigiaEscrituras() as v:` → al salir, `v.escrituras` = [(evento, ruta)]."""

    def __init__(self) -> None:
        self.escrituras: list[tuple[str, str]] = []

    def __enter__(self) -> VigiaEscrituras:
        global _instalado
        with _lock:
            if not _instalado:
                # Un audit hook no se puede quitar; se instala una vez y queda
                # inactivo (retorna enseguida) mientras no haya vigías.
                sys.addaudithook(_gancho)
                _instalado = True
            _vigias.append(self)
        return self

    def __exit__(self, *exc) -> None:
        with _lock:
            _vigias.remove(self)


class _Copia:
    def __init__(self, original, destino: list[str]) -> None:
        self._original = original
        self._destino = destino

    def write(self, texto: str) -> int:
        self._destino.append(texto)
        return self._original.write(texto) if self._original is not None else len(texto)

    def flush(self) -> None:
        if self._original is not None:
            self._original.flush()

    def __getattr__(self, nombre):
        return getattr(self._original, nombre)


class EspejoConsola:
    """Copia lo que se imprime en stdout y stderr mientras está activo (sigue saliendo por pantalla)."""

    def __init__(self) -> None:
        self._partes: list[str] = []

    @property
    def texto(self) -> str:
        return "".join(self._partes)

    def __enter__(self) -> EspejoConsola:
        self._antes = (sys.stdout, sys.stderr)
        sys.stdout = _Copia(sys.stdout, self._partes)
        sys.stderr = _Copia(sys.stderr, self._partes)
        return self

    def __exit__(self, *exc) -> None:
        sys.stdout, sys.stderr = self._antes


def buscar_en_archivos(carpetas, testigos, desde: float) -> tuple[list[Path], int]:
    """Archivos modificados desde `desde` que contienen alguno de los `testigos`.

    Devuelve (archivos con testigo, cantidad de archivos revisados). Solo lee.
    """
    agujas = [t.encode("utf-8") for t in testigos if t] + [t.encode("utf-16-le") for t in testigos if t]
    encontrados, revisados, vistos = [], 0, set()
    for carpeta in carpetas:
        for raiz, _, archivos in os.walk(carpeta, onerror=lambda _: None):
            for nombre in archivos:
                ruta = Path(raiz, nombre)
                try:
                    st = ruta.stat()
                    clave = (st.st_dev, st.st_ino, str(ruta))
                    if clave in vistos or st.st_mtime < desde - 1 or st.st_size > MAX_BYTES_ARCHIVO:
                        continue
                    vistos.add(clave)
                    datos = ruta.read_bytes()
                except OSError:
                    continue
                revisados += 1
                if any(a in datos for a in agujas):
                    encontrados.append(ruta)
    return encontrados, revisados


@dataclass
class InformeRegistros:
    testigo: str
    dominio: str
    busqueda: str                      # "HTTP 200 · 3 saltos" o el motivo del fallo
    busqueda_ok: bool
    escrituras: list[tuple[str, str]] = field(default_factory=list)
    en_consola: bool = False
    archivos: list[Path] = field(default_factory=list)
    revisados: int = 0
    duracion_s: float = 0.0
    contenedores: bool | None = None   # solo en modo Docker: Docker confirma cero registros

    @property
    def aprobado(self) -> bool:
        return (not self.escrituras and not self.en_consola and not self.archivos
                and self.contenedores is not False)
