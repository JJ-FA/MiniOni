"""Pruebas de la verificación «sin registros» (búsqueda testigo).

Dos lados:
- El detector funciona: si algo escribe en disco, imprime o deja el testigo
  en un archivo, la verificación lo detecta (pruebas negativas, incluida una
  versión de MiniOni con fugas simulada).
- MiniOni real aprueba: una búsqueda por el circuito de 3 saltos no escribe
  en disco, no imprime el testigo ni el dominio y no deja archivos con ellos.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import pytest
from test_panel import correr, preparar
from test_red import PASS, laboratorio  # noqa: F401  (fixture compartida)
from test_salida_proxy import ServidorPrueba

from minioni import consola
from minioni.errores import PruebaFallida
from minioni.sin_registros import EspejoConsola, InformeRegistros, VigiaEscrituras, buscar_en_archivos

# --- el detector detecta -------------------------------------------------------------


def test_el_vigia_ve_escrituras_y_no_lecturas(tmp_path):
    existente = tmp_path / "existente.txt"
    existente.write_text("hola", encoding="utf-8")
    with VigiaEscrituras() as v:
        existente.read_text(encoding="utf-8")                      # lectura: no cuenta
        (tmp_path / "registro.log").write_text("x", encoding="utf-8")
        with open(tmp_path / "otro.log", "ab"):
            pass
        os.close(os.open(tmp_path / "bajo_nivel.log", os.O_WRONLY | os.O_CREAT))
        os.replace(tmp_path / "otro.log", tmp_path / "renombrado.log")
        os.remove(tmp_path / "renombrado.log")
    nombres = [os.path.basename(r) for _, r in v.escrituras]
    assert "existente.txt" not in nombres
    assert {"registro.log", "otro.log", "bajo_nivel.log"} <= set(nombres)
    assert {e for e, _ in v.escrituras} >= {"open", "os.rename", "os.remove"}


def test_el_vigia_solo_cuenta_mientras_esta_activo(tmp_path):
    with VigiaEscrituras() as v:
        pass
    (tmp_path / "despues.log").write_text("x", encoding="utf-8")
    assert v.escrituras == []


def test_el_espejo_copia_stdout_y_stderr_de_otros_hilos(capsys):
    import threading
    with EspejoConsola() as e:
        print("en stdout")
        hilo = threading.Thread(target=lambda: consola.evento("proxy", "CIRCUITO_CREADO", 1))
        hilo.start()
        hilo.join()
    assert "en stdout" in e.texto and "circuito creado" in e.texto
    assert sys.stdout is not None and "Copia" not in type(sys.stdout).__name__


def test_buscar_en_archivos_encuentra_utf8_y_utf16_y_omite_los_viejos(tmp_path):
    inicio = time.time()
    (tmp_path / "a.txt").write_text("busqué minionitestigo1 ayer", encoding="utf-8")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.log").write_bytes("minionitestigo1".encode("utf-16-le"))
    (tmp_path / "limpio.txt").write_text("nada que ver", encoding="utf-8")
    viejo = tmp_path / "viejo.txt"
    viejo.write_text("minionitestigo1", encoding="utf-8")
    os.utime(viejo, (inicio - 3600, inicio - 3600))
    encontrados, revisados = buscar_en_archivos([tmp_path], ["minionitestigo1"], inicio)
    assert sorted(p.name for p in encontrados) == ["a.txt", "b.log"]
    assert revisados == 3


def test_el_informe_solo_aprueba_si_no_hay_nada():
    base = dict(testigo="t", dominio="d", busqueda="HTTP 200", busqueda_ok=True)
    assert InformeRegistros(**base).aprobado
    assert not InformeRegistros(**base, escrituras=[("open", "x.log")]).aprobado
    assert not InformeRegistros(**base, en_consola=True).aprobado
    assert not InformeRegistros(**base, archivos=[Path("historial.log")]).aprobado


# --- de punta a punta con la red real ----------------------------------------------


@pytest.fixture
def red(tmp_path, laboratorio):
    """Controlador con la red levantada y un «buscador» HTTP local permitido por la política."""
    async def servir():
        srv = ServidorPrueba(b"<html>resultados</html>")
        await srv.__aenter__()
        return srv

    control = preparar(tmp_path, laboratorio)
    try:
        srv = correr(control, servir())
        (control.config / "politica_salida.json").write_text(
            json.dumps({"puertos": [80, 443, srv.puerto], "excepciones_redes": ["127.0.0.0/8"]}),
            encoding="utf-8")
        correr(control, control.iniciar(PASS))
        yield control, f"http://127.0.0.1:{srv.puerto}/buscar?q=", srv
    finally:
        control.cerrar()


def test_una_busqueda_por_minioni_no_deja_registros(red, tmp_path):
    control, buscador, srv = red
    inf = correr(control, control.verificar_sin_registros(buscador, [tmp_path, control.config]))
    assert inf.busqueda_ok and inf.busqueda.startswith("HTTP 200")
    assert srv.conexiones == 1                       # la búsqueda sí llegó, por el circuito
    assert inf.escrituras == []
    assert not inf.en_consola and inf.archivos == []
    assert inf.aprobado
    assert inf.testigo.startswith("minioni") and len(inf.testigo) == 19


def test_cada_verificacion_usa_un_testigo_distinto(red, tmp_path):
    control, buscador, _ = red
    a = correr(control, control.verificar_sin_registros(buscador, [tmp_path]))
    b = correr(control, control.verificar_sin_registros(buscador, [tmp_path]))
    assert a.testigo != b.testigo


def test_un_minioni_con_fugas_es_detectado(red, tmp_path, monkeypatch):
    """Simula un programa que SÍ registra la búsqueda: la verificación debe reprobar."""
    control, buscador, _ = red
    original = control.probar_url

    async def con_fugas(url):
        (tmp_path / "historial.log").write_text(url, encoding="utf-8")   # guarda la búsqueda
        print("buscando", url, file=sys.stderr)                         # y la imprime
        return await original(url)

    monkeypatch.setattr(control, "probar_url", con_fugas)
    inf = correr(control, control.verificar_sin_registros(buscador, [tmp_path]))
    assert not inf.aprobado
    assert any(r.endswith("historial.log") for _, r in inf.escrituras)
    assert inf.en_consola
    assert [p.name for p in inf.archivos] == ["historial.log"]


def test_sin_red_no_hay_verificacion(tmp_path, laboratorio):
    control = preparar(tmp_path, laboratorio)
    try:
        with pytest.raises(PruebaFallida):
            correr(control, control.verificar_sin_registros())
    finally:
        control.cerrar()


def test_si_el_circuito_cae_la_busqueda_falla_cerrada_y_tampoco_hay_registros(red, tmp_path):
    control, buscador, srv = red
    correr(control, control.alternar("medio1"))
    inf = correr(control, control.verificar_sin_registros(buscador, [tmp_path]))
    assert not inf.busqueda_ok and "fallo cerrado" in inf.busqueda
    assert srv.conexiones == 0
    assert inf.aprobado
