"""T2 y T3 de la Clase 3: SAST sobre las pruebas y secretos en el historial de Git.

T2: las pruebas también se analizan con Bandit y en tests/ no se acepta ningún
    `nosec` (NIST SSDF PW.7.2).
T3: revisar_secretos.py revisa las líneas agregadas en todos los commits; un
    secreto borrado después sigue en el historial y se debe rotar (cierra el
    fallo 10; NIST SSDF PS.1.1, ASVS 5.0 V13.3.1).
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

import revision_completa
import revisar_secretos

RAIZ = Path(__file__).resolve().parent.parent
TOKEN = "sk_" + "live_" + "0123456789" * 3        # falso, armado en ejecución (regla 20)
HAY_GIT = shutil.which("git") is not None


# --- T2 · Bandit sobre las pruebas ----------------------------------------------

def test_revision_completa_analiza_las_pruebas_con_bandit():
    pasos = dict(revision_completa.PASOS)
    comando = pasos["Análisis estático de las pruebas (Bandit)"]
    assert comando[1:] == ["-m", "bandit", "-q", "-r", "tests", "-s", "B101,B104,B105"]


def test_ninguna_prueba_silencia_a_bandit():
    marca = re.compile(r"#\s*" + "no" + "sec", re.IGNORECASE)     # armada por partes para no marcarse sola
    con_marca = [f"{ruta.name}:{n}" for ruta in sorted((RAIZ / "tests").rglob("*.py"))
                 for n, linea in enumerate(ruta.read_text(encoding="utf-8").splitlines(), 1)
                 if marca.search(linea)]
    assert con_marca == []


# --- T3 · lectura de `git log -p` -----------------------------------------------

HASH_A = "a" * 40
HASH_B = "b" * 40
LOG = (
    f"commit {HASH_A}\nAuthor: x\n\n    mensaje\n\n"
    "diff --git a/config.py b/config.py\nnew file mode 100644\n--- /dev/null\n+++ b/config.py\n"
    "@@ -0,0 +1,2 @@\n+linea uno\n+++ empieza con mas\n"
    f"commit {HASH_B}\n\n"
    "diff --git a/config.py b/config.py\n--- a/config.py\n+++ /dev/null\n@@ -1,2 +0,0 @@\n-linea uno\n"
    "diff --git a/logo.png b/logo.png\nnew file mode 100644\nBinary files /dev/null and b/logo.png differ\n"
).encode()


def test_lee_solo_las_lineas_agregadas_por_commit_y_archivo():
    grupos = revisar_secretos.lineas_agregadas(LOG)
    assert grupos[(HASH_A, "config.py")] == ["linea uno", "++ empieza con mas"]
    assert (HASH_B, "config.py") not in grupos          # un archivo borrado no agrega nada
    assert grupos[(HASH_B, "logo.png")] == []           # binario: cuenta para .gitignore


@given(st.binary(max_size=2000))
def test_fuzz_el_lector_del_historial_nunca_falla(datos):
    for (commit, archivo), lineas in revisar_secretos.lineas_agregadas(datos).items():
        assert re.fullmatch(r"[0-9a-f]{40,64}", commit) and isinstance(archivo, str)
        assert all(isinstance(linea, str) for linea in lineas)


# --- T3 · repositorios temporales ----------------------------------------------

def _git(repo: Path, *argumentos: str) -> str:
    r = revisar_secretos.git("-c", "user.name=Prueba", "-c", "user.email=prueba@ejemplo.invalid",
                             "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false", *argumentos, carpeta=repo)
    assert r.returncode == 0, r.stderr.decode("utf-8", "replace")
    return r.stdout.decode("utf-8", "replace").strip()


@pytest.fixture
def repo(tmp_path, monkeypatch):
    if not HAY_GIT:
        pytest.skip("git no está instalado")
    pytest.importorskip("detect_secrets")
    carpeta = tmp_path / "repo"
    carpeta.mkdir()
    _git(carpeta, "init", "-q")
    (carpeta / ".gitignore").write_text("claves/\n*.key\n", encoding="utf-8")
    (carpeta / "programa.py").write_text("print('hola')\n", encoding="utf-8")
    _git(carpeta, "add", ".")
    _git(carpeta, "commit", "-q", "-m", "inicio")
    monkeypatch.setattr(revisar_secretos, "RAIZ", carpeta)
    return carpeta


def test_sin_repositorio_solo_avisa(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(revisar_secretos, "RAIZ", tmp_path)
    assert revisar_secretos.comprobar_historial() is True
    assert "Sin repositorio Git" in capsys.readouterr().out


def test_historial_limpio_no_tiene_hallazgos(repo, capsys):
    assert revisar_secretos.comprobar_historial() is True
    assert "Hallazgos: 0" in capsys.readouterr().out


def test_secreto_borrado_sigue_en_el_historial(repo, capsys):
    (repo / "ajustes.py").write_text(f'TOKEN = "{TOKEN}"\n', encoding="utf-8")
    _git(repo, "add", "ajustes.py")
    _git(repo, "commit", "-q", "-m", "agrega ajustes")
    con_secreto = _git(repo, "rev-parse", "HEAD")
    (repo / "ajustes.py").write_text("TOKEN = None\n", encoding="utf-8")
    _git(repo, "commit", "-q", "-am", "quita el token")
    assert revisar_secretos.comprobar_historial() is False
    salida = capsys.readouterr().out
    assert f"commit {con_secreto[:10]} ajustes.py" in salida
    assert "borrarlo del código no lo saca del historial" in salida
    assert TOKEN not in salida and "0123456789" not in salida      # nunca el secreto


def test_un_key_commiteado_se_reporta(repo, capsys):
    (repo / "claves" / "salida1").mkdir(parents=True)
    (repo / "claves" / "salida1" / "cebolla.key").write_text('{"formato": "minioni-clave-v1"}\n', encoding="ascii")
    _git(repo, "add", "-f", "claves/salida1/cebolla.key")         # -f: alguien saltó el .gitignore
    _git(repo, "commit", "-q", "-m", "por error")
    assert revisar_secretos.comprobar_historial() is False
    assert "claves/salida1/cebolla.key (archivo que .gitignore excluye)" in capsys.readouterr().out


def test_el_paso_6_hace_fallar_la_revision(repo, capsys):
    (repo / "ajustes.py").write_text(f'TOKEN = "{TOKEN}"\n', encoding="utf-8")
    _git(repo, "add", "ajustes.py")
    _git(repo, "commit", "-q", "-m", "agrega ajustes")
    (repo / "ajustes.py").unlink()
    _git(repo, "commit", "-q", "-am", "borra ajustes")
    assert revisar_secretos.main() == 1                 # los archivos actuales están limpios; el historial no
    salida = capsys.readouterr().out
    assert "1. Secretos en archivos versionables" in salida and "6. Secretos en el historial de Git" in salida
    assert TOKEN not in salida
