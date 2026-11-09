"""Revisión de secretos del proyecto (NIST SSDF PS.1 y PW.7).

Uso (con el entorno activo, desde la carpeta MiniOni):
    python revisar_secretos.py

Hace siete comprobaciones:
  1. detect-secrets sobre los archivos que irían al repositorio (respeta .gitignore):
     no debe haber contraseñas, tokens ni claves escritos en el código o la configuración.
  2. .gitignore protege las claves privadas (claves/ y *.key).
  3. Toda clave privada de la carpeta de claves está cifrada (contenedor scrypt de
     MiniOni); ningún PEM de clave privada sin cifrar en todo el proyecto. La carpeta
     es 'claves' o la de la variable MINIONI_CLAVES (almacen_claves.carpeta_claves);
     si la variable no es válida, este paso falla.
  4. Aviso (no falla): si la carpeta de claves está dentro de una carpeta que se sube a la nube.
  5. Aviso: si el hook hooks/pre-commit está disponible para revisar cada commit nuevo.
  6. Secretos en el historial de Git: revisa las líneas AGREGADAS en todos los commits
     (git log --all -p). Un secreto que se commiteó y luego se borró sigue en el
     historial; también se reporta cualquier archivo que .gitignore excluye (por
     ejemplo un .key) y que igual se commiteó. Sin repositorio o sin git, solo avisa.
  7. Si hay Dockerfile (semana 4): .dockerignore excluye claves/, *.key y config/, para
     que ninguna clave entre a la imagen (una clave copiada queda en sus capas).

Nunca imprime el secreto encontrado: solo archivo, línea (o commit) y tipo.
Termina con código 0 si 1-3, 6 y 7 pasan, 1 si no.
"""

from __future__ import annotations

import fnmatch
import json
import re
import shutil
import subprocess  # nosec B404 - solo se ejecuta git con una lista fija de argumentos, sin shell
import sys
import tempfile
from pathlib import Path

from minioni import almacen_claves as ak
from minioni.almacen_claves import FORMATO, carpeta_sincronizada
from minioni.consola import texto_seguro
from minioni.errores import CarpetaClavesInvalida

RAIZ = Path.cwd()
SIEMPRE_FUERA = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", ".hypothesis"}
BINARIOS = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".pyc", ".docx", ".zip"}
# Las marcas se arman por partes: escritas completas, el propio escáner las
# reportaría como claves privadas (falso positivo encontrado al probarlo).
_INICIO = "-----BEGIN "
PEM_SIN_CIFRAR = tuple(_INICIO + tipo + "PRIVATE KEY-----" for tipo in ("", "EC ", "RSA ", "OPENSSH "))


def patrones_gitignore() -> list[str]:
    archivo = RAIZ / ".gitignore"
    if not archivo.exists():
        return []
    lineas = archivo.read_text(encoding="utf-8").splitlines()
    return [l.strip() for l in lineas if l.strip() and not l.strip().startswith("#")]


def ignorado(relativo: Path, patrones: list[str]) -> bool:
    texto = relativo.as_posix()
    for patron in patrones:
        if patron.endswith("/"):
            carpeta = patron.rstrip("/")
            if texto == carpeta or texto.startswith(carpeta + "/") or carpeta in relativo.parts[:-1]:
                return True
        elif fnmatch.fnmatch(texto, patron) or fnmatch.fnmatch(relativo.name, patron):
            return True
    return False


def archivos(incluir_ignorados: bool) -> list[Path]:
    patrones = patrones_gitignore()
    salida = []
    for ruta in RAIZ.rglob("*"):
        relativo = ruta.relative_to(RAIZ)
        if not ruta.is_file() or SIEMPRE_FUERA & set(relativo.parts):
            continue
        if ruta.suffix.lower() in BINARIOS:
            continue
        if not incluir_ignorados and ignorado(relativo, patrones):
            continue
        salida.append(ruta)
    return sorted(salida)


def comprobar_detect_secrets() -> bool:
    try:
        from detect_secrets import SecretsCollection
        from detect_secrets.settings import default_settings
    except ImportError:
        print("  FALTA detect-secrets: pip install -r requirements-dev.txt")
        return False
    lista = archivos(incluir_ignorados=False)
    coleccion = SecretsCollection()
    with default_settings():
        for ruta in lista:
            coleccion.scan_file(str(ruta))
    hallazgos = [(Path(nombre).relative_to(RAIZ).as_posix() if Path(nombre).is_absolute() else nombre,
                  secreto.line_number, secreto.type) for nombre, secreto in coleccion]
    print(f"  Archivos revisados (los que irían al repositorio): {len(lista)}")
    for nombre, linea, tipo in sorted(hallazgos):
        print(f"  POSIBLE SECRETO: {texto_seguro(nombre, 200)}:{linea} ({tipo})")
    print(f"  Hallazgos: {len(hallazgos)}")
    return not hallazgos


def comprobar_gitignore() -> bool:
    patrones = patrones_gitignore()
    faltan = [p for p in ("claves/", "*.key") if p not in patrones]
    for p in faltan:
        print(f"  FALTA en .gitignore: {p}")
    if not faltan:
        print("  .gitignore excluye claves/ y *.key")
    return not faltan


PATRONES_DOCKERIGNORE = ("claves/", "**/*.key", "config/")


def comprobar_dockerignore() -> bool:
    """Lo que se copia al construir la imagen de Docker nunca debe incluir claves."""
    if not (RAIZ / "Dockerfile").exists():
        print("  No hay Dockerfile: nada que revisar")
        return True
    archivo = RAIZ / ".dockerignore"
    lineas = archivo.read_text(encoding="utf-8").splitlines() if archivo.exists() else []
    patrones = {l.strip() for l in lineas if l.strip() and not l.strip().startswith("#")}
    faltan = [p for p in PATRONES_DOCKERIGNORE if p not in patrones]
    for p in faltan:
        print(f"  FALTA en .dockerignore: {p}")
    if not faltan:
        print("  .dockerignore excluye claves/, *.key y config/: ninguna clave entra a la imagen")
    return not faltan


def carpeta_de_claves() -> Path:
    """La carpeta de claves que usan los programas, vista desde RAIZ."""
    carpeta = ak.carpeta_claves()
    return carpeta if carpeta.is_absolute() else RAIZ / carpeta


def _nombre(ruta: Path, carpeta: Path) -> str:
    try:
        return ruta.relative_to(RAIZ).as_posix()
    except ValueError:
        return f"{ak.VARIABLE_CLAVES}/{ruta.relative_to(carpeta).as_posix()}"


def comprobar_claves_cifradas() -> bool:
    try:
        carpeta = carpeta_de_claves()
    except CarpetaClavesInvalida as e:
        print(f"  {e.mensaje_publico}")
        return False
    ok = True
    claves = sorted(carpeta.rglob("*.key")) if carpeta.exists() else []
    for ruta in claves:
        try:
            doc = json.loads(ruta.read_text(encoding="ascii"))
            cifrada = doc.get("formato") == FORMATO and "cifrado" in doc and doc.get("kdf", {}).get("nombre") == "scrypt"
        except (ValueError, UnicodeDecodeError, AttributeError):
            cifrada = False
        if not cifrada:
            print(f"  CLAVE SIN EL CONTENEDOR CIFRADO: {texto_seguro(_nombre(ruta, carpeta), 200)}")
            ok = False
    for ruta in archivos(incluir_ignorados=True):
        try:
            texto = ruta.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if any(marca in texto for marca in PEM_SIN_CIFRAR):
            print(f"  CLAVE PRIVADA PEM SIN CIFRAR: {ruta.relative_to(RAIZ).as_posix()}")
            ok = False
    if ok:
        print(f"  {len(claves)} claves privadas, todas cifradas con scrypt + ChaCha20-Poly1305; ningún PEM sin cifrar")
    return ok


def avisar_nube() -> None:
    try:
        carpeta = carpeta_de_claves()
    except CarpetaClavesInvalida:
        print("  (sin revisar: MINIONI_CLAVES no es válida, ver el paso 3)")
        return
    nombre = "MINIONI_CLAVES" if carpeta.is_absolute() and ak.carpeta_claves().is_absolute() else "'claves'"
    servicio = carpeta_sincronizada(carpeta)
    if servicio:
        print(f"  AVISO: la carpeta de claves ({nombre}) está dentro de '{texto_seguro(servicio, 40)}' "
              "y se sube a la nube.\n"
              "  Van cifradas, pero lo ideal es tenerlas fuera: define MINIONI_CLAVES con una carpeta local\n"
              "  y regenera las claves (ver COMANDOS.txt, 'Claves fuera de OneDrive').")
    else:
        print(f"  La carpeta de claves ({nombre}) no está en una carpeta sincronizada con la nube")


def avisar_historial() -> None:
    """El hook revisa cada commit nuevo; los anteriores los revisa el paso 6."""
    if not (RAIZ / ".git").exists():
        print("  Aún no hay repositorio Git. Al crearlo, activa el hook: git config core.hooksPath hooks")
    elif not (RAIZ / "hooks" / "pre-commit").exists():
        print("  AVISO: falta hooks/pre-commit; un secreto commiteado quedaría en el historial.")
    else:
        print("  Usa el hook (git config core.hooksPath hooks) para revisar antes de cada commit;\n"
              "  los commits que ya existen los revisa el paso 6.")


# --- 6. historial de Git (Clase 3, T3; cierra el fallo 10) -------------------------

_COMMIT = re.compile(rb"commit ([0-9a-f]{40,64})(?: .*)?")
_BINARIO = re.compile(rb"Binary files .* and b/(.+) differ")


def lineas_agregadas(log: bytes) -> dict[tuple[str, str], list[str]]:
    """Agrupa por (commit, archivo) las líneas que cada commit AGREGÓ.

    Lee la salida de `git log -p --unified=0`. Solo se miran las líneas que empiezan
    con '+' dentro de un fragmento (después de '@@'), así una línea agregada que
    empieza con '++' no se confunde con el encabezado '+++ b/archivo'. Un archivo
    binario aparece con lista vacía: igual cuenta para la regla de .gitignore.
    """
    grupos: dict[tuple[str, str], list[str]] = {}
    commit = archivo = None
    en_fragmento = False
    for linea in log.split(b"\n"):
        coincidencia = _COMMIT.fullmatch(linea)
        if coincidencia:
            commit, archivo, en_fragmento = coincidencia.group(1).decode("ascii"), None, False
        elif linea.startswith(b"diff --git "):
            archivo, en_fragmento = None, False
        elif not en_fragmento and linea.startswith(b"+++ "):
            ruta = linea[4:]
            archivo = ruta[2:].decode("utf-8", "replace") if ruta.startswith(b"b/") else None
            if commit and archivo:
                grupos.setdefault((commit, archivo), [])
        elif not en_fragmento and _BINARIO.fullmatch(linea):
            archivo = _BINARIO.fullmatch(linea).group(1).decode("utf-8", "replace")
            if commit:
                grupos.setdefault((commit, archivo), [])
        elif linea.startswith(b"@@"):
            en_fragmento = True
        elif en_fragmento and linea.startswith(b"+") and commit and archivo:
            grupos[(commit, archivo)].append(linea[1:].decode("utf-8", "replace").rstrip("\r"))
    return grupos


def git(*argumentos: str, carpeta: Path) -> subprocess.CompletedProcess:
    """Ejecuta git sin shell. Los argumentos son siempre fijos, escritos en el código.

    Lo usan el paso 6 y las pruebas (que arman repositorios temporales sin tener
    que importar subprocess, porque en tests/ no se acepta ningún `nosec`).
    """
    return subprocess.run(["git", *argumentos], capture_output=True, shell=False, cwd=carpeta, check=False)  # nosec B603 B607 - argumentos fijos del código, sin shell; git se busca en el PATH a propósito (cada equipo lo instala en otra ruta)


def comprobar_historial() -> bool:
    if not (RAIZ / ".git").exists() or shutil.which("git") is None:
        print("  Sin repositorio Git (o sin git instalado): no hay historial que revisar.")
        return True
    try:
        from detect_secrets import SecretsCollection
        from detect_secrets.settings import default_settings
    except ImportError:
        print("  FALTA detect-secrets: pip install -r requirements-dev.txt")
        return False
    r = git("log", "--all", "-p", "--no-color", "--unified=0", "--no-ext-diff", carpeta=RAIZ)
    if r.returncode != 0:
        # Repositorio recién creado sin commits: git log falla y no hay nada que revisar.
        sin_commits = b"does not have any commits" in r.stderr or not r.stdout
        print("  El repositorio aún no tiene commits." if sin_commits else "  No se pudo leer el historial de Git.")
        return sin_commits
    grupos = lineas_agregadas(r.stdout)
    patrones = patrones_gitignore()
    hallazgos = set()
    for commit, archivo in grupos:
        if ignorado(Path(archivo), patrones):
            hallazgos.add((commit, archivo, "archivo que .gitignore excluye"))
    with tempfile.TemporaryDirectory(prefix="minioni-historial-") as temporal:
        origen = {}
        coleccion = SecretsCollection()
        for i, ((commit, archivo), lineas) in enumerate(grupos.items()):
            if not lineas or Path(archivo).suffix.lower() in BINARIOS:
                continue
            copia = Path(temporal) / f"{i}{Path(archivo).suffix}"
            copia.write_text("\n".join(lineas) + "\n", encoding="utf-8")
            origen[str(copia)] = (commit, archivo)
        with default_settings():
            for copia in origen:
                coleccion.scan_file(copia)
        for nombre, secreto in coleccion:
            hallazgos.add((*origen[nombre], secreto.type))
    print(f"  Commits revisados: {len({c for c, _ in grupos})}; archivos con cambios: {len(grupos)}")
    for commit, archivo, tipo in sorted(hallazgos, key=lambda h: (h[1], h[0], h[2])):
        print(f"  EN EL HISTORIAL: commit {commit[:10]} {texto_seguro(archivo, 200)} ({tipo})")
    if hallazgos:
        print("  Rota ese secreto; borrarlo del código no lo saca del historial (ver docs/ROTACION_CLAVES.md).")
    print(f"  Hallazgos: {len(hallazgos)}")
    return not hallazgos


def main() -> int:
    pasos = [("1. Secretos en archivos versionables (detect-secrets)", comprobar_detect_secrets),
             ("2. .gitignore protege las claves", comprobar_gitignore),
             ("3. Claves privadas cifradas en disco", comprobar_claves_cifradas)]
    resultados = []
    for titulo, funcion in pasos:
        print(titulo)
        resultados.append(funcion())
    print("4. Sincronización con la nube")
    avisar_nube()
    print("5. Hook de Git antes de cada commit")
    avisar_historial()
    print("6. Secretos en el historial de Git")
    resultados.append(comprobar_historial())
    print("7. Imagen de Docker sin claves (.dockerignore)")
    resultados.append(comprobar_dockerignore())
    todo = all(resultados)
    print("\nRevisión de secretos: " + ("sin secretos expuestos." if todo else "HAY PROBLEMAS (ver arriba)."))
    return 0 if todo else 1


if __name__ == "__main__":
    sys.exit(main())
