"""Pruebas de la semana 5: análisis de capturas, comando capturar, demo y paquete de entrega.

Nunca usan Docker real: las llamadas al cliente de Docker se simulan.
"""

from __future__ import annotations

import argparse
import re
import struct
import zipfile
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import empaquetar_entrega as entrega
import laboratorio_docker as lab
import revisar_secretos
from minioni import analisis_pcap as pcap
from minioni.errores import ConfiguracionInvalida

RAIZ = Path(__file__).resolve().parent.parent


def _paquete_tcp(datos: bytes, origen: int = 40000, destino: int = 9002) -> bytes:
    tcp = struct.pack(">HHIIBBHHH", origen, destino, 1, 1, 5 << 4, 0x18, 1024, 0, 0) + datos
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, bytes(4), bytes(4))
    return ip + tcp


def _pcap(paquetes: list[bytes], enlace: int = 113, magia: bytes = b"\xd4\xc3\xb2\xa1") -> bytes:
    salto = {113: 16, 276: 20, 1: 14, 101: 0}[enlace]
    orden = "<" if magia[0] == 0xd4 else ">"
    salida = magia + struct.pack(orden + "HHiIII", 2, 4, 0, 0, 65535, enlace)
    for paquete in paquetes:
        registro = bytes(salto) + paquete
        salida += struct.pack(orden + "IIII", 0, 0, len(registro), len(registro)) + registro
    return salida


# --- análisis de la captura ------------------------------------------------------------

@pytest.mark.parametrize("enlace", [113, 276, 1, 101])
def test_resumen_cuenta_paquetes_puertos_y_tls(enlace):
    registro = b"\x17\x03\x03" + bytes(530)
    r = pcap.resumir(_pcap([_paquete_tcp(registro), _paquete_tcp(registro), _paquete_tcp(b"")], enlace))
    assert r.paquetes == 3 and r.registros_tls == 2 and 9002 in r.puertos
    assert r.tamanos.most_common(1) == [(533, 2)] and not r.texto_en_claro


def test_resumen_detecta_texto_en_claro():
    r = pcap.resumir(_pcap([_paquete_tcp(b"GET / HTTP/1.0\r\nHost: web\r\n\r\n", destino=80)]))
    assert r.marcas == {b"GET /", b"Host: web"} and r.texto_en_claro


def test_palabras_sueltas_en_texto_cifrado_no_cuentan_como_fuga():
    assert not pcap.resumir(_pcap([_paquete_tcp(b"\x91web\x07GET\x00")])).texto_en_claro


def test_orden_de_bytes_contrario():
    assert pcap.resumir(_pcap([_paquete_tcp(b"x")], magia=b"\xa1\xb2\xc3\xd4")).paquetes == 1


def test_captura_cortada_al_final_se_acepta():
    completa = _pcap([_paquete_tcp(b"primero"), _paquete_tcp(b"segundo")])
    assert pcap.resumir(completa[:-3]).paquetes == 1


@pytest.mark.parametrize("contenido", [b"", b"hola", bytes(24), b"\xd4\xc3\xb2\xa1" + bytes(4)])
def test_captura_invalida_se_rechaza(contenido):
    with pytest.raises(ConfiguracionInvalida):
        pcap.resumir(contenido)


def test_tipo_de_enlace_desconocido_se_rechaza():
    with pytest.raises(ConfiguracionInvalida):
        pcap.resumir(b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 9999))


def test_archivo_ausente_da_error_generico(tmp_path):
    with pytest.raises(ConfiguracionInvalida):
        pcap.resumir_archivo(tmp_path / "no.pcap")


@settings(max_examples=300, deadline=None)
@given(st.binary(max_size=2048))
def test_fuzz_bytes_al_azar(contenido):
    try:
        pcap.resumir(contenido)
    except ConfiguracionInvalida:
        pass


@settings(max_examples=300, deadline=None)
@given(st.lists(st.binary(max_size=128), max_size=8), st.sampled_from([113, 276, 1, 101]))
def test_fuzz_paquetes_mal_formados(paquetes, enlace):
    assert pcap.resumir(_pcap(paquetes, enlace)).paquetes == len(paquetes)


# --- comando capturar ------------------------------------------------------------------

class _Resultado:
    def __init__(self, returncode=0, stdout=b""):
        self.returncode, self.stdout = returncode, stdout


@pytest.fixture
def captura_simulada(monkeypatch, tmp_path):
    llamadas = {"docker": [], "trafico": 0, "datos": b"\x91cifrado"}

    def ejecutar(argumentos, capturar=True, timeout=600):
        llamadas["docker"].append(argumentos)
        if argumentos[0] == "run":
            tramo = next(a for a in argumentos if a.startswith("/captura/")).removeprefix("/captura/")
            (tmp_path / tramo).write_bytes(_pcap([_paquete_tcp(llamadas["datos"])]))
        return _Resultado()

    def sonda(red, modo, archivos=None):
        llamadas["trafico"] += 1
        return {}

    monkeypatch.setattr(lab, "CARPETA_CAPTURAS", tmp_path)
    monkeypatch.setattr(lab, "_comprobar_docker", lambda: None)
    monkeypatch.setattr(lab, "_verificar_directorio_docker", lambda: None)
    monkeypatch.setattr(lab, "_ejecutar", ejecutar)
    monkeypatch.setattr(lab, "_sonda", sonda)
    monkeypatch.setattr(lab, "_eco_desde_el_equipo", lambda: True)
    monkeypatch.setattr(lab.time, "sleep", lambda _s: None)
    return llamadas


def _corrida(llamadas) -> list[str]:
    return next(a for a in llamadas["docker"] if a[0] == "run")


def test_captura_con_privilegios_minimos_y_sin_registros(captura_simulada):
    assert lab.capturar("entrada-medio", 10) is True
    run = _corrida(captura_simulada)
    assert "container:minioni-medio1" in run and "--read-only" in run
    assert run[run.index("--cap-drop") + 1] == "ALL"
    assert [run[i + 1] for i, a in enumerate(run) if a == "--cap-add"] == ["NET_RAW", "NET_ADMIN"]
    assert run[run.index("--log-driver") + 1] == "none" and "--privileged" not in run
    assert run[-2:] == ["port", "9002"] and captura_simulada["trafico"] == 1


def test_captura_de_un_tramo_interno_falla_si_hay_texto_en_claro(captura_simulada):
    captura_simulada["datos"] = b"GET / HTTP/1.0\r\n"
    assert lab.capturar("medio-salida", 10) is False


def test_captura_salida_web_exige_ver_la_peticion(captura_simulada):
    assert lab.capturar("salida-web", 10) is False
    captura_simulada["datos"] = b"GET / HTTP/1.0\r\nHost: web\r\n\r\n"
    assert lab.capturar("salida-web", 10) is True


def test_captura_vacia_no_se_da_por_buena(captura_simulada, monkeypatch, tmp_path):
    def ejecutar(argumentos, capturar=True, timeout=600):
        if argumentos[0] == "run":
            (tmp_path / "medio-salida.pcap").write_bytes(_pcap([]))
        return _Resultado()
    monkeypatch.setattr(lab, "_ejecutar", ejecutar)
    assert lab.capturar("medio-salida", 10) is False


def test_si_docker_no_lanza_la_captura_hay_error_fijo(captura_simulada, monkeypatch):
    monkeypatch.setattr(lab, "_ejecutar", lambda a, **k: _Resultado(1 if a[0] == "run" else 0))
    with pytest.raises(lab.ErrorLaboratorio, match="inicia el laboratorio"):
        lab.capturar("entrada-medio", 10)


@pytest.mark.parametrize("tramo,segundos", [("otro", 10), ("entrada-medio", 4), ("entrada-medio", 121)])
def test_captura_rechaza_valores_fuera_de_rango(captura_simulada, tramo, segundos):
    with pytest.raises(lab.ErrorLaboratorio):
        lab.capturar(tramo, segundos)
    assert captura_simulada["docker"] == []


@pytest.mark.parametrize("texto", ["0", "4", "121", "-5", "10.5", "abc", "", "١٠"])
def test_argumento_segundos_fuera_de_rango(texto):
    with pytest.raises(argparse.ArgumentTypeError):
        lab._argumento_segundos(texto)


@pytest.mark.parametrize("texto,valor", [("5", 5), ("120", 120)])
def test_argumento_segundos_valido(texto, valor):
    assert lab._argumento_segundos(texto) == valor


def test_los_puertos_de_los_tramos_coinciden_con_el_directorio():
    relays = __import__("json").loads((RAIZ / "config" / "relays.json").read_text(encoding="utf-8"))
    puertos = {r["apodo"]: r["puerto"] for r in relays}
    assert lab.TRAMOS["entrada-medio"] == ("medio1", puertos["medio1"])
    assert lab.TRAMOS["medio-salida"] == ("salida1", puertos["salida1"])
    assert lab.TRAMOS["salida-web"] == ("web", 80)


@pytest.mark.parametrize("archivo", [".gitignore", ".dockerignore"])
def test_las_capturas_no_van_a_git_ni_a_la_imagen(archivo):
    assert "capturas_wireshark/" in (RAIZ / archivo).read_text(encoding="utf-8").splitlines()


def test_imagen_de_captura_usa_el_mismo_digest():
    captura = (RAIZ / "docker" / "Dockerfile.captura").read_text(encoding="utf-8")
    principal = (RAIZ / "Dockerfile").read_text(encoding="utf-8")
    patron = r"^ARG BASE=(python:3\.14-slim@sha256:[0-9a-f]{64})$"
    assert re.search(patron, captura, re.M).group(1) == re.search(patron, principal, re.M).group(1)


# --- comando demo ----------------------------------------------------------------------

@pytest.mark.parametrize("resultado", [True, False])
def test_demo_muestra_estado_prueba_y_comandos(monkeypatch, capsys, resultado):
    orden = []
    monkeypatch.setattr(lab, "estado", lambda: orden.append("estado"))
    monkeypatch.setattr(lab, "probar", lambda: orden.append("probar") or resultado)
    assert lab.demo() is resultado
    salida = capsys.readouterr().out
    assert orden == ["estado", "probar"]
    assert "docker pause minioni-medio1" in salida and "simular-ataque" in salida


# --- paquete de entrega ----------------------------------------------------------------

def _zip(tmp_path, archivos: dict[str, bytes]) -> Path:
    ruta = tmp_path / "paquete.zip"
    with zipfile.ZipFile(ruta, "w") as paquete:
        for nombre, contenido in archivos.items():
            paquete.writestr(nombre, contenido)
    return ruta


def test_paquete_limpio_se_acepta(tmp_path):
    ruta = _zip(tmp_path, {"codigo/README.md": b"hola", "codigo/.gitignore": b"claves/\n",
                           "codigo/minioni/almacen_claves.py": b"x = 1", "evidencia/wireshark/a.pcap": b"\x00"})
    assert entrega.verificar_paquete(ruta) == []


@pytest.mark.parametrize("nombre", [
    "codigo/claves/entrada1/cebolla.pub", "codigo/.venv/pyvenv.cfg", "codigo/.git/config",
    "codigo/otra/tls.key", "codigo/config/directorio.docker.json", "codigo/config/ultima_version",
    "codigo/config/ultima_version.docker", "codigo/errores.txt", "codigo/pytest.txt", "../fuera.txt", "/absoluta.txt",
])
def test_paquete_con_algo_prohibido_se_rechaza(tmp_path, nombre):
    assert entrega.verificar_paquete(_zip(tmp_path, {nombre: b"x"}))


def test_la_salida_de_pytest_solo_vale_como_evidencia(tmp_path):
    assert entrega.verificar_paquete(_zip(tmp_path, {"evidencia/salidas/pytest.txt": b"ok"})) == []


def test_barra_invertida_en_una_ruta_se_rechaza():
    assert entrega.problemas_de_nombre("a\\b.txt")


def test_extraer_zip_copia_los_archivos_en_su_carpeta(tmp_path):
    destino = tmp_path / "salida"
    entrega.extraer_zip(_zip(tmp_path, {"codigo/minioni/a.py": b"x = 1", "LEEME.txt": b"hola"}), destino)
    assert (destino / "codigo" / "minioni" / "a.py").read_bytes() == b"x = 1"
    assert (destino / "LEEME.txt").read_bytes() == b"hola"


@pytest.mark.parametrize("nombre", ["../fuera.txt", "a/../../fuera.txt", "/absoluta.txt", "C:/fuera.txt"])
def test_extraer_zip_no_sale_de_la_carpeta_destino(tmp_path, nombre):
    destino = tmp_path / "salida"
    with pytest.raises(entrega.ErrorEntrega):
        entrega.extraer_zip(_zip(tmp_path, {nombre: b"x"}), destino)
    assert not (tmp_path / "fuera.txt").exists()
    assert not destino.exists()


def test_paquete_con_clave_pem_sin_cifrar_se_rechaza(tmp_path):
    marca = revisar_secretos.PEM_SIN_CIFRAR[0].encode("ascii")
    assert entrega.verificar_paquete(_zip(tmp_path, {"codigo/notas.txt": marca}))


def _repositorio(tmp_path, monkeypatch, con_etiqueta=True) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "README.md").write_text("MiniOni\n", encoding="utf-8")
    for argumentos in (("init", "-q"), ("add", "-A"),
                       ("-c", "user.name=prueba", "-c", "user.email=prueba@ejemplo.test", "commit", "-q", "-m", "x")):
        assert revisar_secretos.git(*argumentos, carpeta=repo).returncode == 0
    if con_etiqueta:
        assert revisar_secretos.git("tag", "v1.0", carpeta=repo).returncode == 0
    monkeypatch.setattr(entrega, "RAIZ", repo)
    monkeypatch.setattr(entrega, "CARPETA_ENTREGA", repo / "entrega")
    monkeypatch.setattr(entrega, "CARPETA_CAPTURAS", repo / "capturas_wireshark")
    monkeypatch.setattr(entrega, "_revisar_secretos_del_codigo", lambda _d: True)
    return repo


def test_empaquetar_de_punta_a_punta(tmp_path, monkeypatch):
    repo = _repositorio(tmp_path, monkeypatch)
    (repo / "entrega" / "informe").mkdir(parents=True)
    (repo / "entrega" / "informe" / "informe.pdf").write_bytes(b"%PDF")
    (repo / "capturas_wireshark").mkdir()
    (repo / "capturas_wireshark" / "entrada-medio.pcap").write_bytes(b"\x00")
    ruta = tmp_path / "salida.zip"
    assert entrega.empaquetar("v1.0", ruta) == []
    nombres = zipfile.ZipFile(ruta).namelist()
    assert {"codigo/README.md", "informe/informe.pdf", "evidencia/wireshark/entrada-medio.pcap",
            "LEEME.txt"} <= set(nombres)


def test_sin_etiqueta_no_se_empaqueta(tmp_path, monkeypatch):
    _repositorio(tmp_path, monkeypatch, con_etiqueta=False)
    ruta = tmp_path / "salida.zip"
    with pytest.raises(entrega.ErrorEntrega, match="con el equipo"):
        entrega.empaquetar("v1.0", ruta)
    assert not ruta.exists()


def test_si_la_revision_de_secretos_falla_se_borra_el_zip(tmp_path, monkeypatch):
    _repositorio(tmp_path, monkeypatch)
    monkeypatch.setattr(entrega, "_revisar_secretos_del_codigo", lambda _d: False)
    ruta = tmp_path / "salida.zip"
    assert entrega.empaquetar("v1.0", ruta) and not ruta.exists()


def test_evidencia_con_una_clave_rechaza_el_paquete(tmp_path, monkeypatch):
    repo = _repositorio(tmp_path, monkeypatch)
    (repo / "entrega" / "evidencia").mkdir(parents=True)
    (repo / "entrega" / "evidencia" / "cebolla.key").write_bytes(b"x")
    ruta = tmp_path / "salida.zip"
    assert entrega.empaquetar("v1.0", ruta) and not ruta.exists()


@pytest.mark.parametrize("texto", ["1.0", "v1", "v1.0;x", "", "v1.0\n"])
def test_etiqueta_invalida_se_rechaza(texto):
    with pytest.raises(argparse.ArgumentTypeError):
        entrega._argumento_etiqueta(texto)


# --- STRIDE final ----------------------------------------------------------------------

def test_stride_cubre_las_seis_categorias_y_cita_pruebas_que_existen():
    texto = (RAIZ / "docs" / "STRIDE.md").read_text(encoding="utf-8")
    for letra in "STRIDE":
        assert re.search(rf"^## {letra} · ", texto, re.M)
    citadas = set(re.findall(r"`(test_[a-z0-9_]+)`", texto))
    definidas = set()
    for archivo in (RAIZ / "tests").glob("test_*.py"):
        definidas |= set(re.findall(r"^(?:async )?def (test_[a-z0-9_]+)", archivo.read_text(encoding="utf-8"), re.M))
    assert citadas and citadas <= definidas, sorted(citadas - definidas)
