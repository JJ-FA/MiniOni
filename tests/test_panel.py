"""Pruebas del panel gráfico: el controlador de red (sin ventana) y la ventana en sí.

El controlador se prueba de punta a punta con las claves del laboratorio de
test_red: arranque, eco por 3 saltos, apagar y encender un relay (fallo
cerrado), página por el proxy SOCKS5 y apagado. La ventana solo se construye
y se cierra; si no hay pantalla (CI sin escritorio) esa prueba se salta.
"""

from __future__ import annotations

import asyncio
import gc
import json

import pytest
from test_red import APODOS, PASS, _puerto_libre, laboratorio  # noqa: F401  (fixture compartida)
from test_salida_proxy import ServidorPrueba

from minioni import admin, consola
from minioni import almacen_claves as ak
from minioni import directorio as dirmod
from minioni.control_red import ControladorRed
from minioni.errores import ClaveInvalida, ConfiguracionInvalida, PruebaFallida
from minioni.relay import ConfigRelay

CONFIG = ConfigRelay(timeout_handshake=3, inactividad_max=30, vida_max=60, intervalo_limpieza=0.2)


def preparar(tmp_path, laboratorio, host="127.0.0.1", puerto_web=8080) -> ControladorRed:
    claves, autoridad = laboratorio
    config = tmp_path / "config"
    config.mkdir()
    lista = [{"apodo": a, "host": host, "puerto": _puerto_libre(), "salida": a == "salida1"} for a in APODOS]
    firmado = dirmod.firmar(admin.armar_directorio(lista, claves, 1, 7), autoridad)
    (config / "directorio.firmado.json").write_bytes(firmado)
    ak.guardar_publica(config / "autoridad.pub", autoridad.public_key().public_bytes_raw())
    # Excepción explícita SOLO para la prueba: el servidor local de prueba.
    (config / "politica_salida.json").write_text(
        json.dumps({"puertos": [80, 443, puerto_web], "excepciones_redes": ["127.0.0.0/8"]}), encoding="utf-8")
    return ControladorRed(config, claves, puerto_proxy=0, config_relay=CONFIG)


def correr(control: ControladorRed, coro, timeout: float = 60):
    return control.ejecutar(coro).result(timeout)


def test_consola_avisa_a_los_suscriptores_y_se_dan_de_baja(capsys):
    vistos = []
    baja = consola.suscribir(lambda *a: vistos.append(a))
    consola.evento("proxy", "ARRANQUE")
    consola.evento("proxy", "codigo-inventado", cantidad="x")
    baja()
    consola.evento("proxy", "ARRANQUE")
    assert vistos == [("proxy", "ARRANQUE", None), ("proxy", "ERROR_INTERNO", None)]


def test_un_suscriptor_que_falla_no_rompe_la_consola(capsys):
    def roto(*_):
        raise RuntimeError("falla")
    baja = consola.suscribir(roto)
    try:
        consola.evento("proxy", "ARRANQUE")
    finally:
        baja()


def test_ciclo_completo_del_controlador(tmp_path, laboratorio):
    async def servir():
        srv = ServidorPrueba()
        await srv.__aenter__()
        return srv

    control = None
    try:
        # El servidor HTTP de prueba vive en el bucle del controlador; su puerto va a la política.
        control = preparar(tmp_path, laboratorio, puerto_web=0)
        srv = correr(control, servir())
        politica = control.config / "politica_salida.json"
        politica.write_text(json.dumps({"puertos": [80, 443, srv.puerto],
                                        "excepciones_redes": ["127.0.0.0/8"]}), encoding="utf-8")

        assert control.revisar_directorio()["estado"] == "local"
        assert correr(control, control.iniciar(PASS)) == 3
        s = control.instantanea
        assert s["en_marcha"] and all(s["nodos"].values()) and s["puerto_proxy"] > 0

        ms, saltos = correr(control, control.probar_circuito())
        assert saltos == 3 and ms >= 0

        assert correr(control, control.alternar("medio1")) is False
        with pytest.raises(PruebaFallida):
            correr(control, control.probar_circuito())
        with pytest.raises(PruebaFallida, match="fallo cerrado"):
            correr(control, control.probar_url(f"http://127.0.0.1:{srv.puerto}/"))
        assert srv.conexiones == 0   # sin circuito, nada llega al destino
        assert correr(control, control.alternar("medio1")) is True
        assert correr(control, control.probar_circuito())[1] == 3

        codigo, total, _ = correr(control, control.probar_url(f"http://127.0.0.1:{srv.puerto}/"))
        assert codigo == 200 and total > 0 and srv.conexiones == 1

        with pytest.raises(PruebaFallida, match="política"):
            correr(control, control.probar_url("http://127.0.0.1:1/"))
        with pytest.raises(PruebaFallida, match="no válida"):
            correr(control, control.probar_url("ftp://ejemplo"))

        with pytest.raises(ConfiguracionInvalida):
            control.publicar_directorio_local(PASS)   # con la red en marcha no se publica

        correr(control, control.detener())
        assert not control.instantanea["en_marcha"] and control.instantanea["nodos"] == {}
        assert any(c == "ARRANQUE" for _, _, c, _ in control.eventos_nuevos())
    finally:
        if control is not None:
            control.cerrar()


def test_contrasena_incorrecta_no_deja_nada_en_marcha(tmp_path, laboratorio):
    control = preparar(tmp_path, laboratorio)
    try:
        with pytest.raises(ClaveInvalida):
            correr(control, control.iniciar("otra contraseña"))
        assert not control.instantanea["en_marcha"] and control.nodos == {}
        with pytest.raises(PruebaFallida):
            correr(control, control.probar_circuito())
    finally:
        control.cerrar()


def test_directorio_de_docker_se_rechaza(tmp_path, laboratorio):
    control = preparar(tmp_path, laboratorio, host="172.28.0.11")
    try:
        assert control.revisar_directorio()["estado"] == "remoto"
        with pytest.raises(ConfiguracionInvalida):
            correr(control, control.iniciar(PASS))
        assert not control.instantanea["en_marcha"]
    finally:
        control.cerrar()


def test_directorio_ausente_es_invalido(tmp_path, laboratorio):
    control = ControladorRed(tmp_path / "config", laboratorio[0], puerto_proxy=0)
    try:
        r = control.revisar_directorio()
        assert r["estado"] == "invalido" and r["relays"] == []
    finally:
        control.cerrar()


def test_la_ventana_se_construye_y_se_cierra(tmp_path, laboratorio):
    tk = pytest.importorskip("tkinter")
    import panel
    try:
        raiz = tk.Tk()
    except tk.TclError:
        pytest.skip("sin pantalla")
    raiz.withdraw()
    control = preparar(tmp_path, laboratorio)
    panel.elegir_fuentes()
    p = panel.Panel(raiz, control)
    raiz.update()
    assert set(p._tarjetas) == {*APODOS, "Proxy"}
    assert "verificado" in p.info["text"]
    assert panel.mensaje_error(ClaveInvalida("x")).startswith("Contraseña")
    assert panel.mensaje_error(OSError()).startswith("Un puerto")
    assert panel.mensaje_error(ValueError("detalle interno")) == "Error interno."
    p.cerrar()
    # Tcl aborta el proceso si un objeto de Tk se libera desde otro hilo (el de la red
    # de otra prueba). Se liberan aquí, en el hilo principal.
    del p, raiz
    gc.collect()
