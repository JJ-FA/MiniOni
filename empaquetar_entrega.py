"""Arma el paquete de la entrega final y comprueba que no lleve secretos (semana 5, S5-T7).

Uso (con el entorno activo, desde la carpeta del proyecto y con la etiqueta ya creada):
    python empaquetar_entrega.py
    python empaquetar_entrega.py --etiqueta v1.0

El código sale de `git archive`, así que solo entra lo versionado en esa etiqueta. El
resto se toma de una carpeta local que no va a Git:
    entrega/informe/      el PDF del informe y los informes de clase
    entrega/evidencia/    capturas de pantalla (PNG) y salidas/ (probar.txt, pytest.txt, ...)
    capturas_wireshark/   los .pcap de `laboratorio_docker.py capturar`

Si encuentra algo prohibido borra el zip y termina con código 1 (fallo cerrado).
"""

from __future__ import annotations

import argparse
import io
import os
import re
import shutil
import subprocess  # nosec B404 - solo se ejecutan git, docker y este mismo Python, sin shell
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

from minioni import consola
from revisar_secretos import PEM_SIN_CIFRAR

RAIZ = Path(__file__).resolve().parent
CARPETA_ENTREGA = RAIZ / "entrega"
CARPETA_CAPTURAS = RAIZ / "capturas_wireshark"
_ETIQUETA = re.compile(r"v[0-9]{1,3}(\.[0-9]{1,3}){1,2}")

CARPETAS_PROHIBIDAS = {"claves", ".venv", "venv", ".git", "__pycache__", ".pytest_cache", ".hypothesis"}
ARCHIVOS_PROHIBIDOS = {"directorio.docker.json", "directorio.firmado.json", "directorio.atacado.json",
                       "ultima_version", "errores.txt"}
EXTENSIONES_PROHIBIDAS = {".key", ".pem"}
EXTENSIONES_SIN_TEXTO = {".png", ".jpg", ".jpeg", ".pdf", ".pcap", ".pcapng", ".zip", ".docx"}

LEEME = """MiniOni, paquete de entrega {etiqueta}
Equipo Onion. Python {python}. Docker {docker}.

codigo/      el proyecto (git archive {etiqueta}, sin claves, .venv ni historial)
informe/     informe final e informes de clase
evidencia/   capturas de pantalla, tráfico .pcap y salidas de las pruebas

Cómo levantarlo (Windows, con Docker Desktop abierto y desde la carpeta codigo):
1. python -m venv .venv  y luego  .\\.venv\\Scripts\\Activate.ps1
2. pip install -r requirements.txt -r requirements-dev.txt
3. Definir MINIONI_CLAVES con una carpeta local fuera de la nube, y ejecutar
   python minioni_admin.py preparar-laboratorio --relays config/relays.local.json
4. python laboratorio_docker.py preparar
5. python panel.py, elegir Docker, escribir la contraseña e iniciar la red.

El detalle está en codigo/README.md.
"""


class ErrorEntrega(Exception):
    """Error con un mensaje fijo para la persona que empaqueta."""


def _ejecutar(comando: list[str], carpeta: Path, entorno: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(comando, capture_output=True, cwd=carpeta, env=entorno, check=False, timeout=600)  # nosec B603 - lista de argumentos fijos, sin shell


def problemas_de_nombre(nombre: str) -> list[str]:
    """Motivos por los que una ruta del paquete no se puede entregar."""
    ruta = PurePosixPath(nombre)
    if ruta.is_absolute() or ".." in ruta.parts or "\\" in nombre:
        return [f"ruta insegura: {consola.texto_seguro(nombre, 200)}"]
    motivos = []
    if CARPETAS_PROHIBIDAS & set(ruta.parts):
        motivos.append(f"carpeta prohibida: {consola.texto_seguro(nombre, 200)}")
    if ruta.suffix.lower() in EXTENSIONES_PROHIBIDAS:
        motivos.append(f"archivo de clave: {consola.texto_seguro(nombre, 200)}")
    if ruta.name in ARCHIVOS_PROHIBIDOS or ruta.name.startswith("ultima_version."):
        motivos.append(f"archivo que no se entrega: {consola.texto_seguro(nombre, 200)}")
    if ruta.name == "pytest.txt" and ruta.parts[:2] != ("evidencia", "salidas"):   # fuera de la evidencia es diagnóstico
        motivos.append(f"archivo de diagnóstico: {consola.texto_seguro(nombre, 200)}")
    return motivos


def verificar_paquete(ruta_zip: Path) -> list[str]:
    """Revisa nombres y contenido del zip. Devuelve la lista de problemas (vacía si está bien)."""
    problemas = []
    with zipfile.ZipFile(ruta_zip) as paquete:
        for info in paquete.infolist():
            problemas += problemas_de_nombre(info.filename)
            if info.is_dir() or PurePosixPath(info.filename).suffix.lower() in EXTENSIONES_SIN_TEXTO:
                continue
            texto = paquete.read(info).decode("utf-8", errors="ignore")
            if any(marca in texto for marca in PEM_SIN_CIFRAR):
                problemas.append(f"clave privada sin cifrar: {consola.texto_seguro(info.filename, 200)}")
    return problemas


def extraer_zip(ruta_zip: Path, destino: Path) -> None:
    """Extrae archivo por archivo; una ruta que saldría de `destino` detiene la extracción."""
    with zipfile.ZipFile(ruta_zip) as paquete:
        for info in paquete.infolist():
            ruta = PurePosixPath(info.filename)
            if ruta.is_absolute() or ".." in ruta.parts or "\\" in info.filename or ":" in info.filename:
                raise ErrorEntrega("el paquete contiene una ruta insegura")
            if info.is_dir():
                continue
            final = destino.joinpath(*ruta.parts)
            final.parent.mkdir(parents=True, exist_ok=True)
            final.write_bytes(paquete.read(info))


def _revisar_secretos_del_codigo(descomprimido: Path) -> bool:
    """revisar_secretos.py sobre el contenido real del zip, no sobre la carpeta de trabajo."""
    codigo = descomprimido / "codigo"
    entorno = {k: v for k, v in os.environ.items() if k != "MINIONI_CLAVES"}   # no revisar las claves reales
    entorno.update(PYTHONIOENCODING="utf-8", PYTHONDONTWRITEBYTECODE="1")
    return _ejecutar([sys.executable, str(codigo / "revisar_secretos.py")], codigo, entorno).returncode == 0


def _version_docker() -> str:
    if shutil.which("docker") is None:
        return "no disponible"
    r = _ejecutar(["docker", "version", "--format", "{{.Server.Version}}"], RAIZ)
    return r.stdout.decode("ascii", "ignore").strip() or "no disponible" if r.returncode == 0 else "no disponible"


def _armar_carpeta(destino: Path, etiqueta: str) -> None:
    r = _ejecutar(["git", "archive", "--format=tar", "--prefix=codigo/", etiqueta], RAIZ)
    if r.returncode != 0:
        raise ErrorEntrega(f"no existe la etiqueta {etiqueta}. Créenla con el equipo presente: "
                           f'git tag -a {etiqueta} -m "Entrega final MiniOni"')
    with tarfile.open(fileobj=io.BytesIO(r.stdout)) as tar:
        tar.extractall(destino, filter="data")
    (destino / "informe").mkdir()
    (destino / "evidencia" / "wireshark").mkdir(parents=True)
    for origen, final in ((CARPETA_ENTREGA / "informe", destino / "informe"),
                          (CARPETA_ENTREGA / "evidencia", destino / "evidencia")):
        if origen.is_dir():
            shutil.copytree(origen, final, dirs_exist_ok=True)
    if CARPETA_CAPTURAS.is_dir():
        for captura in CARPETA_CAPTURAS.glob("*.pcap"):
            shutil.copy2(captura, destino / "evidencia" / "wireshark")
    version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    (destino / "LEEME.txt").write_text(LEEME.format(etiqueta=etiqueta, python=version, docker=_version_docker()),
                                       encoding="utf-8", newline="\r\n")


def empaquetar(etiqueta: str, ruta_zip: Path) -> list[str]:
    """Crea el zip y lo verifica. Si hay problemas lo borra y los devuelve."""
    with tempfile.TemporaryDirectory(prefix="minioni-entrega-") as temporal:
        carpeta = Path(temporal) / "paquete"
        carpeta.mkdir()
        _armar_carpeta(carpeta, etiqueta)
        with zipfile.ZipFile(ruta_zip, "w", zipfile.ZIP_DEFLATED) as paquete:
            for archivo in sorted(p for p in carpeta.rglob("*") if p.is_file()):
                paquete.write(archivo, archivo.relative_to(carpeta).as_posix())
        problemas = verificar_paquete(ruta_zip)
        if not problemas:
            descomprimido = Path(temporal) / "revision"
            extraer_zip(ruta_zip, descomprimido)
            if not _revisar_secretos_del_codigo(descomprimido):
                problemas.append("revisar_secretos.py encontró un problema en el contenido del paquete")
    if problemas:
        ruta_zip.unlink(missing_ok=True)
    return problemas


def _argumento_etiqueta(texto: str) -> str:
    if not _ETIQUETA.fullmatch(texto):
        raise argparse.ArgumentTypeError("usa una etiqueta como v1.0")
    return texto


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="empaquetar_entrega", description="Paquete de la entrega final de MiniOni")
    p.add_argument("--etiqueta", type=_argumento_etiqueta, default="v1.0")
    args = p.parse_args(argv)
    ruta_zip = RAIZ / f"MiniOni_entrega_{args.etiqueta}.zip"
    try:
        problemas = empaquetar(args.etiqueta, ruta_zip)
    except ErrorEntrega as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile, subprocess.SubprocessError):
        ruta_zip.unlink(missing_ok=True)
        print("Error: no se pudo armar el paquete.", file=sys.stderr)
        return 1
    if problemas:
        print("Paquete rechazado y borrado:", file=sys.stderr)
        for problema in problemas:
            print(f"  {problema}", file=sys.stderr)
        return 1
    print(f"Paquete listo y verificado: {ruta_zip.name}")
    return 0


if __name__ == "__main__":
    consola.instalar_manejador_global("entrega")
    sys.exit(main())
