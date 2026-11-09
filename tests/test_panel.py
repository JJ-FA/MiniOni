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
import time

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


# --- modo Docker (semana 4) con un orquestador simulado: nunca se usa Docker real -----

class OrquestadorFalso:
    class ErrorLaboratorio(Exception):
        pass

    ERRORES_DOCKER = (OSError,)

    def __init__(self):
        self.llamadas = []
        self.contrasenas = []
        self.error = None
        self.sin_registros = True

    def iniciar_con_contrasena(self, contrasena, internet=False, avisar=lambda _t: None):
        self.contrasenas.append(contrasena)
        self.llamadas.append(("iniciar", internet))
        if contrasena != PASS:
            raise ClaveInvalida("x")
        if self.error is not None:
            raise self.error
        avisar("[2/4] Construyendo la imagen")

    def preparar(self, contrasena):
        self.contrasenas.append(contrasena)
        self.llamadas.append(("preparar",))

    def detener(self):
        self.llamadas.append(("detener",))

    def pausar(self, apodo):
        self.llamadas.append(("pausar", apodo))

    def reanudar(self, apodo):
        self.llamadas.append(("reanudar", apodo))

    def matriz_segmentacion(self):
        return [{"red": "red_cliente", "alcanza": {"entrada1": True, "web": False}, "ok": True},
                {"red": "red_destinos", "alcanza": None, "ok": False}]

    def contenedores_sin_registros(self):
        return self.sin_registros


def preparar_docker(tmp_path, laboratorio, modo="docker"):
    claves, autoridad = laboratorio
    config = tmp_path / "config"
    config.mkdir()
    lista = [{"apodo": a, "host": f"10.10.{i + 1}.10", "puerto": 9001, "salida": a == "salida1"}
             for i, a in enumerate(APODOS)]
    (config / "directorio.docker.json").write_bytes(dirmod.firmar(admin.armar_directorio(lista, claves, 3, 7), autoridad))
    ak.guardar_publica(config / "autoridad.pub", autoridad.public_key().public_bytes_raw())
    orq = OrquestadorFalso()
    control = ControladorRed(config, claves, puerto_proxy=0, config_relay=CONFIG, orquestador=orq)
    if modo == "docker":
        control.cambiar_modo("docker")
    return control, orq


def test_docker_ciclo_completo_con_orquestador_simulado(tmp_path, laboratorio):
    control, orq = preparar_docker(tmp_path, laboratorio)
    try:
        assert control.revisar_directorio() == {
            "estado": "docker", "version": 3, "relays": [(a, a == "salida1") for a in APODOS]}
        assert correr(control, control.iniciar(PASS, internet=True)) == 3
        s = control.instantanea
        assert s["en_marcha"] and all(s["nodos"].values()) and s["salidas"]["salida1"] is True
        assert orq.llamadas == [("iniciar", True)] and orq.contrasenas == [PASS]
        # El proxy entra por el puerto publicado y no hay relays locales.
        assert control.proxy.gestor._entrada_via == ("127.0.0.1", 9001) and control.nodos == {}
        assert PASS not in [v for v in vars(control).values() if isinstance(v, str)]   # no se guarda
        with pytest.raises(ConfiguracionInvalida):
            control.cambiar_modo("local")

        assert correr(control, control.alternar("medio1")) is False
        assert correr(control, control.alternar("medio1")) is True
        assert orq.llamadas[-2:] == [("pausar", "medio1"), ("reanudar", "medio1")]
        with pytest.raises(ConfiguracionInvalida):
            correr(control, control.alternar("otro"))

        assert correr(control, control.probar_segmentacion())[0]["red"] == "red_cliente"
        correr(control, control.detener())
        assert not control.instantanea["en_marcha"] and orq.llamadas[-1] == ("detener",)
        with pytest.raises(PruebaFallida):
            correr(control, control.probar_segmentacion())
    finally:
        control.cerrar()


def test_docker_contrasena_incorrecta_no_deja_nada_en_marcha(tmp_path, laboratorio):
    control, orq = preparar_docker(tmp_path, laboratorio)
    try:
        with pytest.raises(ClaveInvalida):
            correr(control, control.iniciar("otra contraseña"))
        assert not control.instantanea["en_marcha"] and control.proxy is None
    finally:
        control.cerrar()
    assert ("detener",) not in orq.llamadas      # no había nada que apagar


@pytest.mark.parametrize("error,mensaje", [
    (OrquestadorFalso.ErrorLaboratorio("Docker no responde."), "Docker no responde"),
    (OSError("detalle interno 10.10.1.10"), "no se pudo comunicar con Docker"),
])
def test_docker_los_errores_son_genericos(tmp_path, laboratorio, error, mensaje):
    control, orq = preparar_docker(tmp_path, laboratorio)
    orq.error = error
    try:
        with pytest.raises(PruebaFallida) as e:
            correr(control, control.iniciar(PASS))
        assert e.value.mensaje_publico == mensaje and "10.10" not in e.value.mensaje_publico
        assert not control.instantanea["en_marcha"]
    finally:
        control.cerrar()


def test_docker_si_el_proxy_no_arranca_se_apaga_el_laboratorio(tmp_path, laboratorio, monkeypatch):
    control, orq = preparar_docker(tmp_path, laboratorio)

    async def falla(_self):
        raise OSError("puerto ocupado")
    monkeypatch.setattr("minioni.control_red.ServidorProxy.iniciar", falla)
    try:
        with pytest.raises(OSError):
            correr(control, control.iniciar(PASS))
        assert orq.llamadas[-1] == ("detener",) and control.proxy is None
    finally:
        control.cerrar()


def test_docker_el_eco_usa_la_entrada_publicada(tmp_path, laboratorio, monkeypatch):
    control, _ = preparar_docker(tmp_path, laboratorio)
    vistos = []

    class Circuito:
        def __init__(self, **kw):
            vistos.append(kw)
            raise PruebaFallida("detenido aquí")

    monkeypatch.setattr("minioni.control_red.CircuitoCliente", Circuito)
    try:
        correr(control, control.iniciar(PASS))
        with pytest.raises(PruebaFallida):
            correr(control, control.probar_circuito())
        assert vistos == [{"entrada_via": ("127.0.0.1", 9001)}]
    finally:
        control.cerrar()


def test_docker_verificacion_sin_registros(tmp_path, laboratorio):
    control, orq = preparar_docker(tmp_path, laboratorio)
    pedidas = []

    async def pagina(url):
        pedidas.append(url)
        (tmp_path / "ajeno.txt").write_text("web", encoding="utf-8")   # «web» no es un rastro
        return 200, 10, 1.0

    control.probar_url = pagina
    try:
        correr(control, control.iniciar(PASS))
        inf = correr(control, control.verificar_sin_registros(carpetas=[tmp_path]))
        assert pedidas[0].startswith("http://web/?q=minioni") and inf.dominio == "web"
        assert inf.contenedores is True and not inf.archivos
        orq.sin_registros = False
        assert not correr(control, control.verificar_sin_registros(carpetas=[tmp_path])).aprobado
    finally:
        control.cerrar()


def test_docker_con_internet_usa_el_buscador_real(tmp_path, laboratorio):
    control, _ = preparar_docker(tmp_path, laboratorio)
    pedidas = []

    async def pagina(url):
        pedidas.append(url)
        return 200, 10, 1.0

    control.probar_url = pagina
    try:
        correr(control, control.iniciar(PASS, internet=True))
        correr(control, control.verificar_sin_registros(carpetas=[tmp_path]))
        assert pedidas[0].startswith("https://html.duckduckgo.com/")
    finally:
        control.cerrar()


def test_docker_firmar_directorio_con_la_red_detenida(tmp_path, laboratorio):
    control, orq = preparar_docker(tmp_path, laboratorio)
    try:
        assert control.publicar_directorio_docker(PASS) == 3 and orq.contrasenas == [PASS]
        correr(control, control.iniciar(PASS))
        with pytest.raises(ConfiguracionInvalida):
            control.publicar_directorio_docker(PASS)
    finally:
        control.cerrar()


def test_el_modo_local_no_toca_al_orquestador(tmp_path, laboratorio):
    control, orq = preparar_docker(tmp_path, laboratorio, modo="local")
    try:
        assert control.modo == "local" and control.revisar_directorio()["estado"] == "invalido"
        with pytest.raises(ConfiguracionInvalida):
            control.cambiar_modo("otro")
        assert orq.llamadas == []
    finally:
        control.cerrar()


def test_sin_orquestador_no_hay_modo_docker(tmp_path, laboratorio):
    control = ControladorRed(tmp_path / "config", laboratorio[0], puerto_proxy=0)
    try:
        assert not control.docker_disponible
        with pytest.raises(ConfiguracionInvalida):
            control.cambiar_modo("docker")
        with pytest.raises(ConfiguracionInvalida):
            control.publicar_directorio_docker(PASS)
    finally:
        control.cerrar()


def _esperar(raiz, condicion, timeout=20):
    limite = time.monotonic() + timeout
    while not condicion():
        assert time.monotonic() < limite, "la ventana no terminó a tiempo"
        raiz.update()
        time.sleep(0.02)


def test_ventana_en_modo_docker(tmp_path, laboratorio):
    tk = pytest.importorskip("tkinter")
    import panel
    try:
        raiz = tk.Tk()
    except tk.TclError:
        pytest.skip("sin pantalla")
    raiz.withdraw()
    control, orq = preparar_docker(tmp_path, laboratorio, modo="local")
    panel.elegir_fuentes()
    p = panel.Panel(raiz, control)
    raiz.update()
    assert p.url.get() == "https://example.com" and p.b_segmentacion.b["state"] == "disabled"

    p.modo.set("docker")
    p.cambiar_modo()
    raiz.update()
    assert control.modo == "docker" and p.url.get() == "http://web/"
    assert p.b_publicar.b["text"] == "Firmar directorio Docker" and p.c_internet["state"] == "normal"
    assert "Docker v3" in p.info["text"]

    p.clave.insert(0, PASS)
    p.internet.set(True)
    p.iniciar_o_detener()
    assert p.clave.get() == ""
    _esperar(raiz, lambda: control.instantanea["en_marcha"] and not p._ocupado)
    assert orq.llamadas == [("iniciar", True)] and orq.contrasenas == [PASS]
    assert p.radios["local"]["state"] == "disabled" and p.c_internet["state"] == "disabled"
    assert "en Docker" in p.info["text"]

    p.probar_segmentacion()
    _esperar(raiz, lambda: "red_cliente" in p.log.get("1.0", "end") and not p._ocupado)
    assert "FALLO (la sonda" in p.log.get("1.0", "end")
    assert "NO es la esperada" in p.resultado["text"]

    p.iniciar_o_detener()
    _esperar(raiz, lambda: not control.instantanea["en_marcha"] and not p._ocupado)
    assert orq.llamadas[-1] == ("detener",)

    p.modo.set("local")
    p.cambiar_modo()
    assert p.url.get() == "https://example.com" and p.internet.get() is False
    assert not p.c_internet.winfo_manager()      # en modo local la casilla no se muestra
    p.cerrar()
    del p, raiz
    gc.collect()


def test_ventana_sin_orquestador_desactiva_docker(tmp_path, laboratorio):
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
    assert p.radios["docker"]["state"] == "disabled" and p.modo.get() == "local"
    assert panel.texto_matriz([{"red": "r", "alcanza": {"a": True}, "ok": True}]).splitlines()[1].endswith("OK")
    p.cerrar()
    del p, raiz
    gc.collect()
