"""Pruebas de la semana 4: laboratorio Docker con redes segmentadas (ISO/IEC 27033).

No necesitan Docker: prueban las piezas nuevas del código (primer salto por el puerto
publicado, marca de entrada en el directorio, contraseña por la entrada estándar,
nombre del directorio de Docker) y revisan que docker-compose.yml, Dockerfile y
.dockerignore mantengan las decisiones de seguridad. La prueba con Docker real es
`python laboratorio_docker.py probar`.
"""

import argparse
import asyncio
import io
import json
import re
import socket
import threading
import http.client
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import ejecutar_relay
import laboratorio_docker
import revisar_secretos
from minioni import admin
from minioni import almacen_claves as ak
from minioni import directorio as dirmod
from minioni.celdas import ComandoRelay, MensajeRelay
from minioni.circuito import CircuitoCliente, elegir_ruta
from minioni.errores import ClaveInvalida, DirectorioInvalido, TLSInvalido
from minioni.proxy import argumento_entrada_via, ruta_ultima_version
from minioni.relay import ConfigRelay, cargar_relay

RAIZ = Path(__file__).resolve().parent.parent
PASS = "contraseña de laboratorio"
APODOS = ("entrada1", "medio1", "salida1")


def _puerto_libre() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def laboratorio(tmp_path_factory):
    claves = tmp_path_factory.mktemp("semana4") / "claves"
    for apodo in APODOS:
        admin.generar_relay(apodo, PASS, claves, ak.N_SCRYPT_MINIMO)
    return claves, Ed25519PrivateKey.generate()


def _lista(con_entrada: bool = True) -> list[dict]:
    lista = []
    for apodo in APODOS:
        r = {"apodo": apodo, "host": "127.0.0.1", "puerto": _puerto_libre(), "salida": apodo == "salida1"}
        if con_entrada:
            r["entrada"] = apodo == "entrada1"
        lista.append(r)
    return lista


def _firmar(laboratorio, lista, alterar=None) -> dirmod.Directorio:
    claves, autoridad = laboratorio
    doc = admin.armar_directorio(lista, claves, 1, 7)
    if alterar is not None:
        alterar(doc)
    firmado = dirmod.firmar(doc, autoridad)
    return dirmod.verificar(firmado, autoridad.public_key().public_bytes_raw())


class Reenviador:
    """Hace de puerto publicado por Docker: reenvía TCP de un puerto local a otro."""

    def __init__(self, destino: int) -> None:
        self.destino = destino
        self.conexiones = 0
        self.puerto = 0
        self._servidor = None

    async def _atender(self, lector, escritor) -> None:
        self.conexiones += 1
        l2, e2 = await asyncio.open_connection("127.0.0.1", self.destino)

        async def copiar(origen, destino):
            try:
                while datos := await origen.read(4096):
                    destino.write(datos)
                    await destino.drain()
            except (ConnectionError, OSError):
                pass
            finally:
                destino.close()

        await asyncio.gather(copiar(lector, e2), copiar(l2, escritor))

    async def __aenter__(self):
        self._servidor = await asyncio.start_server(self._atender, "127.0.0.1", 0)
        self.puerto = self._servidor.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *exc):
        self._servidor.close()


async def _con_relays(laboratorio, d, escenario):
    claves, _ = laboratorio
    cfg = ConfigRelay(timeout_handshake=3, inactividad_max=30, vida_max=60, intervalo_limpieza=0.2)
    nodos = [cargar_relay(a, d, claves, PASS, cfg) for a in APODOS]
    for n in nodos:
        await n.iniciar()
    try:
        return await escenario()
    finally:
        for n in nodos:
            await n.detener()


# --- primer salto por el puerto publicado (--entrada-via) -------------------------------

def test_entrada_via_construye_el_circuito_por_el_puerto_publicado(laboratorio):
    d = _firmar(laboratorio, _lista())
    entrada = next(r for r in d.relays if r.apodo == "entrada1")

    async def escenario():
        async with Reenviador(entrada.puerto) as publicado:
            c = CircuitoCliente(timeout=3, entrada_via=("127.0.0.1", publicado.puerto))
            await c.construir(d, elegir_ruta(d))
            await c.enviar(MensajeRelay(ComandoRelay.ECO, 0, b"por docker"))
            respuesta = await asyncio.wait_for(c.recibir(), 5)
            await c.cerrar()
            return respuesta.datos, publicado.conexiones

    datos, conexiones = asyncio.run(_con_relays(laboratorio, d, escenario))
    assert datos == b"por docker"
    assert conexiones == 1   # el primer salto pasó por el puerto publicado


def test_entrada_via_hacia_otro_relay_se_rechaza_por_la_huella(laboratorio):
    """--entrada-via cambia la dirección, nunca la identidad: el pinning sigue mandando."""
    d = _firmar(laboratorio, _lista())
    medio = next(r for r in d.relays if r.apodo == "medio1")

    async def escenario():
        c = CircuitoCliente(timeout=3, entrada_via=("127.0.0.1", medio.puerto))
        with pytest.raises(TLSInvalido):
            await c.construir(d, elegir_ruta(d))

    asyncio.run(_con_relays(laboratorio, d, escenario))


@pytest.mark.parametrize("texto", ["127.0.0.1:9001", "127.0.0.2:65535"])
def test_entrada_via_acepta_solo_loopback(texto):
    host, puerto = argumento_entrada_via(texto)
    assert host.startswith("127.") and 1 <= puerto <= 65535


@pytest.mark.parametrize("texto", ["10.10.1.10:9001", "192.168.1.5:9001", "localhost:9001",
                                   "127.0.0.1:0", "127.0.0.1:70000", "127.0.0.1", ":9001",
                                   "127.0.0.1:9001\n", "127.0.0.1:9001 ", "[::1]:9001", "999.0.0.1:9001"])
def test_entrada_via_rechaza_todo_lo_demas(texto):
    with pytest.raises(argparse.ArgumentTypeError):
        argumento_entrada_via(texto)


def test_cada_directorio_tiene_su_propio_anti_rollback(tmp_path):
    assert ruta_ultima_version(tmp_path, Path("config/directorio.firmado.json")) == tmp_path / "ultima_version"
    assert ruta_ultima_version(tmp_path, Path("config/directorio.docker.json")) == tmp_path / "ultima_version.docker"
    assert ruta_ultima_version(tmp_path, Path("otro.json")) == tmp_path / "ultima_version"
    assert ruta_ultima_version(tmp_path, Path("directorio.../x.json")) == tmp_path / "ultima_version"


# --- marca de entrada en el directorio (como Guard en Tor) -----------------------------

def test_con_marca_de_entrada_la_ruta_respeta_la_segmentacion(laboratorio):
    d = _firmar(laboratorio, _lista())
    for _ in range(200):
        assert [r.apodo for r in elegir_ruta(d)] == ["entrada1", "medio1", "salida1"]


def test_directorio_sin_marca_de_entrada_sigue_siendo_valido(laboratorio):
    d = _firmar(laboratorio, _lista(), alterar=lambda doc: [r.pop("entrada") for r in doc["relays"]])
    assert not any(r.entrada for r in d.relays)
    assert len(elegir_ruta(d)) == 3


@pytest.mark.parametrize("valor", [1, "true", None])
def test_marca_de_entrada_debe_ser_booleana(laboratorio, valor):
    def alterar(doc):
        doc["relays"][0]["entrada"] = valor
    with pytest.raises(DirectorioInvalido):
        _firmar(laboratorio, _lista(), alterar)


def test_un_relay_no_puede_ser_entrada_y_salida(laboratorio):
    """Vería a la vez la IP del cliente y el destino: se rechaza el directorio."""
    def alterar(doc):
        doc["relays"][2]["entrada"] = True
    with pytest.raises(DirectorioInvalido):
        _firmar(laboratorio, _lista(), alterar)


def test_relays_json_de_docker_marca_solo_la_entrada():
    lista = json.loads((RAIZ / "config" / "relays.json").read_text(encoding="utf-8"))
    assert [r["apodo"] for r in lista if r.get("entrada")] == ["entrada1"]
    assert {r["apodo"]: r["host"] for r in lista} == {
        "entrada1": "10.10.1.10", "medio1": "10.10.2.10", "salida1": "10.10.3.10"}


# --- contraseña por la entrada estándar y nombre del directorio -------------------------

@pytest.mark.parametrize("entrada,esperado", [("mi red cebolla 2026\n", "mi red cebolla 2026"),
                                              ("sin fin de linea", "sin fin de linea"),
                                              ("con windows\r\n", "con windows")])
def test_contrasena_por_entrada(monkeypatch, entrada, esperado):
    monkeypatch.setattr("sys.stdin", io.StringIO(entrada))
    assert ejecutar_relay.leer_contrasena_por_entrada() == esperado


@pytest.mark.parametrize("entrada", ["", "\n", "x" * 2000 + "\n"])
def test_contrasena_por_entrada_vacia_o_enorme_se_rechaza(monkeypatch, entrada):
    monkeypatch.setattr("sys.stdin", io.StringIO(entrada))
    with pytest.raises(ClaveInvalida):
        ejecutar_relay.leer_contrasena_por_entrada()


@pytest.mark.parametrize("nombre", ["../directorio.docker.json", "config/directorio.docker.json",
                                    "directorio.atacado.json", "directorio.Docker.json", "otro.json",
                                    "directorio.docker.json\n", "C:\\directorio.docker.json"])
def test_salida_del_directorio_solo_dentro_de_config(tmp_path, nombre):
    with pytest.raises(SystemExit):
        admin.destino_directorio(tmp_path, nombre)


def test_salida_del_directorio_docker(tmp_path):
    assert admin.destino_directorio(tmp_path, "directorio.docker.json") == tmp_path / "directorio.docker.json"
    assert admin.destino_directorio(tmp_path, None) == tmp_path / "directorio.firmado.json"


# --- docker-compose.yml, Dockerfile y .dockerignore -------------------------------------

COMPOSE = (RAIZ / "docker-compose.yml").read_text(encoding="utf-8")
DOCKERFILE = (RAIZ / "Dockerfile").read_text(encoding="utf-8")


def _bloque_red(nombre: str) -> str:
    inicio = COMPOSE.index(f"\n  {nombre}:\n", COMPOSE.index("\nnetworks:"))
    fin = re.search(r"\n  \w+:\n|\Z", COMPOSE[inicio + 1:])
    return COMPOSE[inicio: inicio + 1 + fin.start()]


def test_docker_no_guarda_registros_y_contenedores_endurecidos():
    ancla = COMPOSE[COMPOSE.index("x-endurecido"):COMPOSE.index("x-relay")]
    for linea in ("read_only: true", 'user: "10001:10001"', "cap_drop: [ALL]",
                  "no-new-privileges:true", "driver: none"):
        assert linea in ancla, linea
    servicios = COMPOSE[COMPOSE.index("\nservices:"):COMPOSE.index("\nnetworks:")]
    assert servicios.count("<<: *relay") == 3 and servicios.count("<<: *endurecido") == 2
    for prohibido in ("privileged:", "network_mode", "cap_add", "/var/run/docker.sock", "CONTRASENA", "PASSWORD"):
        assert prohibido not in COMPOSE, prohibido


def _bloque_servicio(nombre: str) -> str:
    fin_servicios = COMPOSE.index("\nnetworks:")
    inicio = COMPOSE.index(f"\n  {nombre}:\n", COMPOSE.index("\nservices:"))
    siguiente = re.search(r"\n  \w+:\n", COMPOSE[inicio + 1:fin_servicios])
    return COMPOSE[inicio: inicio + 1 + siguiente.start()] if siguiente else COMPOSE[inicio:fin_servicios]


def test_solo_la_puerta_de_la_entrada_se_publica_y_solo_en_127_0_0_1():
    publicados = re.findall(r'^\s+- "([^"]+:\d+:\d+)"', COMPOSE, re.M)
    assert publicados == ["127.0.0.1:9001:9001"]
    assert '"127.0.0.1:9001:9001"' in _bloque_servicio("puerta")
    assert "ports:" not in _bloque_servicio("entrada1")


def test_la_puerta_es_la_unica_en_la_red_con_salida_y_no_tiene_claves():
    assert COMPOSE.count("red_publica: {ipv4_address") == 1
    puerta = _bloque_servicio("puerta")
    assert "red_publica: {ipv4_address: 10.10.7.10}" in puerta
    assert "<<: *endurecido" in puerta
    assert "volumes:" not in puerta and "claves" not in puerta
    assert "docker/puerta.py" in DOCKERFILE
    assert "puerta" in laboratorio_docker.CONTENEDORES      # estado y «sin registros» también la revisan
    assert "puerta" not in laboratorio_docker.RELAYS


def test_redes_segmentadas_sin_salida_a_internet():
    for red in ("red_cliente", "red_entrada_medio", "red_medio_salida", "red_destinos"):
        assert "internal: true" in _bloque_red(red)
    assert 'enable_ip_masquerade: "false"' in _bloque_red("red_publica")
    assert "10.10.7.0/24" in _bloque_red("red_publica")
    esperadas = {"red_cliente": "10.10.1.0/24", "red_entrada_medio": "10.10.2.0/24",
                 "red_medio_salida": "10.10.3.0/24", "red_destinos": "10.10.9.0/24"}
    for red, subred in esperadas.items():
        assert subred in _bloque_red(red)
    assert set(laboratorio_docker.REDES_ESPERADAS) == set(esperadas)
    assert all(len(v) == 1 for v in laboratorio_docker.REDES_ESPERADAS.values())


def test_cada_relay_recibe_solo_sus_claves_y_en_solo_lectura():
    montajes = re.findall(r"MINIONI_CARPETA_CLAVES[^}]*\}/(\w+):/app/claves/(\w+):ro", COMPOSE)
    assert sorted(montajes) == sorted((a, a) for a in APODOS)
    assert "autoridad" not in re.sub(r"autoridad\.pub", "", COMPOSE)


def test_imagen_sin_claves_y_sin_root():
    assert re.search(r"^USER 10001:10001$", DOCKERFILE, re.M)
    assert not re.search(r"^COPY \. ", DOCKERFILE, re.M)          # lista blanca, nunca todo el proyecto
    assert "claves" not in re.sub(r"MINIONI_CLAVES=/app/claves", "", DOCKERFILE.split("FROM", 1)[1])
    patrones = (RAIZ / ".dockerignore").read_text(encoding="utf-8").splitlines()
    for p in revisar_secretos.PATRONES_DOCKERIGNORE:
        assert p in patrones


def test_revision_de_secretos_exige_dockerignore(tmp_path, monkeypatch):
    (tmp_path / "Dockerfile").write_text("FROM python\n", encoding="utf-8")
    monkeypatch.setattr(revisar_secretos, "RAIZ", tmp_path)
    assert not revisar_secretos.comprobar_dockerignore()
    (tmp_path / ".dockerignore").write_text("claves/\n**/*.key\nconfig/\n", encoding="utf-8")
    assert revisar_secretos.comprobar_dockerignore()


def test_sondas_endurecidas_y_entorno_sin_secretos(monkeypatch, tmp_path):
    for opcion in ("--read-only", "--cap-drop", "no-new-privileges:true", "10001:10001", "none"):
        assert opcion in laboratorio_docker.ENDURECIDO
    monkeypatch.setenv("MINIONI_CLAVES", str(tmp_path))
    entorno = laboratorio_docker._entorno()
    assert entorno["MINIONI_CARPETA_CLAVES"] == tmp_path.resolve().as_posix()
    assert not any("CONTRASENA" in k.upper() or "PASSWORD" in k.upper() for k in entorno
                   if k not in __import__("os").environ)


# --- puerta de la entrada -------------------------------------------------------------------

def _modulo_puerta():
    import importlib.util
    spec = importlib.util.spec_from_file_location("puerta", RAIZ / "docker" / "puerta.py")
    puerta = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(puerta)
    return puerta


def test_la_puerta_apunta_solo_a_la_entrada():
    puerta = _modulo_puerta()
    relays = json.loads((RAIZ / "config" / "relays.json").read_text(encoding="utf-8"))
    entrada = next(r for r in relays if r["apodo"] == "entrada1")
    assert puerta.DESTINO == (entrada["host"], entrada["puerto"])


async def _con_servicios(puerta, destino_activo: bool, prueba):
    async def eco(lector, escritor):
        while datos := await lector.read(1024):
            escritor.write(datos)
            await escritor.drain()
        escritor.close()

    destino = await asyncio.start_server(eco, "127.0.0.1", 0)
    puerto_destino = destino.sockets[0].getsockname()[1]
    if not destino_activo:
        destino.close()
        await destino.wait_closed()
    puerta.destino = ("127.0.0.1", puerto_destino)
    frente = await asyncio.start_server(puerta.atender, "127.0.0.1", 0)
    try:
        return await prueba(frente.sockets[0].getsockname()[1])
    finally:
        frente.close()
        if destino_activo:
            destino.close()


def test_la_puerta_reenvia_en_ambos_sentidos_sin_imprimir_nada(capsys):
    modulo = _modulo_puerta()

    async def prueba(puerto):
        lector, escritor = await asyncio.open_connection("127.0.0.1", puerto)
        escritor.write(b"hola por la puerta")
        await escritor.drain()
        recibido = await asyncio.wait_for(lector.readexactly(18), 5)
        escritor.close()
        return recibido

    assert asyncio.run(_con_servicios(modulo.Puerta(), True, prueba)) == b"hola por la puerta"
    salida = capsys.readouterr()
    assert salida.out == "" and salida.err == ""


def test_sin_entrada_la_puerta_corta_la_conexion():
    modulo = _modulo_puerta()

    async def prueba(puerto):
        lector, escritor = await asyncio.open_connection("127.0.0.1", puerto)
        datos = await asyncio.wait_for(lector.read(10), 5)
        escritor.close()
        return datos

    assert asyncio.run(_con_servicios(modulo.Puerta(), False, prueba)) == b""


def test_la_puerta_limita_las_conexiones():
    modulo = _modulo_puerta()
    puerta = modulo.Puerta(max_conexiones=0)

    async def prueba(puerto):
        lector, escritor = await asyncio.open_connection("127.0.0.1", puerto)
        datos = await asyncio.wait_for(lector.read(10), 5)
        escritor.close()
        return datos

    assert asyncio.run(_con_servicios(puerta, True, prueba)) == b"" and puerta.activas == 0


@pytest.mark.parametrize("valor", ["web", "", "10.10.7", "10.10.7.10:9001"])
def test_la_puerta_exige_una_ip_para_escuchar(valor, capsys):
    assert _modulo_puerta().main(["--escuchar", valor]) == 1


# --- servidor web del laboratorio -----------------------------------------------------------

def test_servidor_web_no_registra_nada_y_muestra_quien_llega(capsys):
    import importlib.util
    spec = importlib.util.spec_from_file_location("servidor_web", RAIZ / "docker" / "servidor_web.py")
    web = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(web)
    servidor = web.ThreadingHTTPServer(("127.0.0.1", 0), web.Manejador)
    hilo = threading.Thread(target=servidor.serve_forever, daemon=True)
    hilo.start()
    try:
        def pedir(ruta: str) -> tuple[int, str]:
            conexion = http.client.HTTPConnection("127.0.0.1", servidor.server_address[1], timeout=5)
            conexion.request("GET", ruta)
            respuesta = conexion.getresponse()
            cuerpo = respuesta.read().decode("utf-8", "replace")
            conexion.close()
            return respuesta.status, cuerpo

        estado, pagina = pedir("/")
        assert estado == 200 and "ve la conexión desde: <b>127.0.0.1</b>" in pagina
        assert pedir("/" + "x" * 300)[0] == 414
    finally:
        servidor.shutdown()
        servidor.server_close()
    salida = capsys.readouterr()
    assert "127.0.0.1" not in salida.out + salida.err   # http.server normalmente imprime cada visita


# --- S4-T3: imagen base fijada por digest (SSDF PW.4.1) -------------------------------

_IMAGEN_FIJADA = r"python:3\.14-slim@sha256:[0-9a-f]{64}"


def test_imagen_base_fijada_por_digest_y_coincide_en_ambos_archivos():
    dockerfile = re.search(r"^ARG BASE=(.+)$", DOCKERFILE, re.M).group(1).strip()
    compose = re.search(r"MINIONI_IMAGEN_BASE:-([^}]+)\}", COMPOSE).group(1).strip()
    assert re.fullmatch(_IMAGEN_FIJADA, dockerfile)
    assert compose == dockerfile


# --- S4-T4: funciones del laboratorio que usa el panel --------------------------------

class _Resultado:
    def __init__(self, returncode=0, stdout=b""):
        self.returncode, self.stdout = returncode, stdout


@pytest.fixture
def laboratorio_simulado(monkeypatch, tmp_path):
    """Sin Docker real: registra las llamadas a compose y entrega siempre con éxito."""
    llamadas = {"compose": [], "entregas": []}

    def compose(*args, capturar=True, timeout=600, internet=False):
        llamadas["compose"].append((args, capturar, internet))
        return _Resultado()

    def entregar(contenedor, contrasena, espera=60):
        llamadas["entregas"].append((contenedor, contrasena))
        return True

    class Directorio:
        version = 7

    monkeypatch.setattr(laboratorio_docker, "_comprobar_docker", lambda: None)
    monkeypatch.setattr(laboratorio_docker, "_claves_relays", lambda _c: None)
    monkeypatch.setattr(laboratorio_docker, "_verificar_directorio_docker", lambda: Directorio())
    monkeypatch.setattr(laboratorio_docker.ak, "carpeta_claves", lambda: tmp_path)
    monkeypatch.setattr(laboratorio_docker.ak, "cargar_privada", lambda *a: object())
    monkeypatch.setattr(laboratorio_docker, "_compose", compose)
    monkeypatch.setattr(laboratorio_docker, "entregar_contrasena", entregar)
    return llamadas


def test_iniciar_con_contrasena_la_entrega_a_cada_relay(laboratorio_simulado):
    avisos = []
    laboratorio_docker.iniciar_con_contrasena("secreto-de-prueba", internet=True, avisar=avisos.append)
    assert [c for c, _ in laboratorio_simulado["entregas"]] == [
        f"minioni-{a}" for a in laboratorio_docker.RELAYS]
    assert {p for _, p in laboratorio_simulado["entregas"]} == {"secreto-de-prueba"}
    # Nunca va en los argumentos de docker compose ni en los avisos (regla 26).
    assert "secreto-de-prueba" not in repr(laboratorio_simulado["compose"]) + repr(avisos)
    subidas = [c for c in laboratorio_simulado["compose"] if c[0][0] == "up"]
    assert subidas == [(("up", "-d"), True, True)]
    construcciones = [c for c in laboratorio_simulado["compose"] if c[0][0] == "build"]
    assert construcciones == [(("build",), True, False)]   # el panel no vuelca la salida de Docker


def test_contrasena_incorrecta_no_crea_ningun_contenedor(laboratorio_simulado, monkeypatch):
    def rechaza(*_a):
        raise ClaveInvalida("x")
    monkeypatch.setattr(laboratorio_docker.ak, "cargar_privada", rechaza)
    with pytest.raises(ClaveInvalida):
        laboratorio_docker.iniciar_con_contrasena("mala")
    assert laboratorio_simulado["compose"] == [] and laboratorio_simulado["entregas"] == []


@pytest.mark.parametrize("fallo", [False, OSError("tubería rota")])
def test_si_un_relay_no_arranca_se_apaga_todo(laboratorio_simulado, monkeypatch, fallo):
    def entregar(contenedor, contrasena, espera=60):
        if fallo:
            raise fallo
        return False
    monkeypatch.setattr(laboratorio_docker, "entregar_contrasena", entregar)
    with pytest.raises(laboratorio_docker.ErrorLaboratorio):
        laboratorio_docker.iniciar_con_contrasena("clave")
    assert laboratorio_simulado["compose"][-1][0] == ("down",)


def test_matriz_de_segmentacion(monkeypatch):
    def sonda(red, modo, archivos=None):
        if red == "red_destinos":
            return {"error": "x"}
        if red == "red_medio_salida":
            return {"alcanza": {"salida1": True, "web": True}}    # alcanza de más
        return {"alcanza": {next(iter(laboratorio_docker.REDES_ESPERADAS[red])): True}}
    monkeypatch.setattr(laboratorio_docker, "_sonda", sonda)
    filas = {f["red"]: f for f in laboratorio_docker.matriz_segmentacion()}
    assert filas["red_cliente"]["ok"] and filas["red_cliente"]["alcanza"]["entrada1"] is True
    assert filas["red_cliente"]["alcanza"]["internet"] is False
    assert not filas["red_medio_salida"]["ok"]
    assert filas["red_destinos"] == {"red": "red_destinos", "alcanza": None, "ok": False}
    assert laboratorio_docker.probar_segmentacion() is False


def test_pausar_solo_relays_conocidos(monkeypatch):
    comandos = []
    monkeypatch.setattr(laboratorio_docker, "_ejecutar", lambda a, **k: comandos.append(a) or _Resultado())
    laboratorio_docker.pausar("medio1")
    laboratorio_docker.reanudar("medio1")
    assert comandos == [["pause", "minioni-medio1"], ["unpause", "minioni-medio1"]]
    for apodo in ("web", "otro", "minioni-medio1; x"):
        with pytest.raises(laboratorio_docker.ErrorLaboratorio):
            laboratorio_docker.pausar(apodo)
    assert len(comandos) == 2
    monkeypatch.setattr(laboratorio_docker, "_ejecutar", lambda a, **k: _Resultado(1))
    with pytest.raises(laboratorio_docker.ErrorLaboratorio):
        laboratorio_docker.pausar("medio1")


@pytest.mark.parametrize("tipo,solo_lectura,codigo,esperado", [
    ("none", True, 0, True), ("json-file", True, 0, False), ("none", False, 0, False), ("none", True, 1, False)])
def test_contenedores_sin_registros(monkeypatch, tipo, solo_lectura, codigo, esperado):
    salida = json.dumps([{"HostConfig": {"LogConfig": {"Type": tipo}, "ReadonlyRootfs": solo_lectura}}]).encode()
    monkeypatch.setattr(laboratorio_docker, "_ejecutar", lambda a, **k: _Resultado(codigo, salida))
    assert laboratorio_docker.contenedores_sin_registros() is esperado
