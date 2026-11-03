"""Pruebas de la semana 3: nodo de salida, proxy SOCKS5 y fallo cerrado.

Todo corre en 127.0.0.1 dentro del mismo proceso: 3 relays reales con TLS
1.3, el proxy SOCKS5 y un servidor HTTP de prueba. Para alcanzar ese servidor
local, la política de salida de la prueba agrega de forma EXPLÍCITA la
excepción 127.0.0.0/8 y el puerto del servidor; la configuración real
(config/politica_salida.json) no la tiene.

Normas: ASVS V2.2.1 (validación de BEGIN y SOCKS5), V16.5.3 (fallo cerrado),
V16.2.5 (consola sin destinos), STRIDE E (política de salida).
"""

import asyncio
import ipaddress
import os
import socket
import struct

import pytest
from test_red import PASS, Red, eco, esperar, laboratorio  # noqa: F401  (fixture compartida)

import cliente_proxy
from minioni import admin, socks5
from minioni import almacen_claves as ak
from minioni import directorio as dirmod
from minioni.celdas import ComandoRelay, MensajeRelay, MotivoEnd, codificar_destino, decodificar_end
from minioni.circuito import CircuitoCliente
from minioni.errores import CircuitoCerrado, ConfiguracionInvalida, DirectorioInvalido
from minioni.politica_salida import PoliticaSalida
from minioni.proxy import GestorCircuitos, ServidorProxy, cargar_directorio, leer_ultima_version
from minioni.relay import cargar_relay

# --- infraestructura de las pruebas -----------------------------------------------


def _info(ip: str, puerto: int):
    familia = socket.AF_INET6 if ":" in ip else socket.AF_INET
    return (familia, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, puerto))


def resolver_falso(tabla: dict):
    """Resolver del nodo de salida para las pruebas: nombre -> lista de IP (sin DNS real)."""
    async def resolver(host, puerto):
        if host in tabla:
            return [_info(ip, puerto) for ip in tabla[host]]
        try:
            ipaddress.ip_address(host)
        except ValueError:
            raise socket.gaierror("nombre desconocido") from None
        return [_info(host, puerto)]
    return resolver


class RedSalida(Red):
    """Red de 3 relays donde salida1 aplica la política y el resolver indicados."""

    def __init__(self, laboratorio, politica=None, tabla_dns=None, **config):
        super().__init__(laboratorio, **config)
        salida = self.nodos["salida1"]
        salida.politica = politica or PoliticaSalida()
        salida._resolver = resolver_falso(tabla_dns or {})

    @property
    def salida(self):
        return self.nodos["salida1"]


def politica_local(*puertos) -> PoliticaSalida:
    """Excepción explícita SOLO para la prueba: 127.0.0.0/8 y el puerto del servidor de prueba."""
    return PoliticaSalida(frozenset({80, 443, *puertos}), ("127.0.0.0/8",))


class ServidorPrueba:
    """Servidor HTTP mínimo en 127.0.0.1. modo: 'http', 'infinito' (envía sin parar) o 'mantener'."""

    def __init__(self, cuerpo: bytes = b"hola desde el servidor de prueba", modo: str = "http"):
        self.cuerpo = cuerpo
        self.modo = modo
        self.conexiones = 0
        self.abiertas = 0
        self.cortada = asyncio.Event()

    async def __aenter__(self):
        self._srv = await asyncio.start_server(self._atender, "127.0.0.1", 0)
        self.puerto = self._srv.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *exc):
        self._srv.close()

    async def _atender(self, reader, writer):
        self.conexiones += 1
        self.abiertas += 1
        try:
            if self.modo == "mantener":
                await reader.read()
                return
            await reader.readuntil(b"\r\n\r\n")
            if self.modo == "http":
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n"
                             % len(self.cuerpo) + self.cuerpo)
                await writer.drain()
                return
            writer.write(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
            bloque = os.urandom(64 * 1024)
            while True:
                writer.write(bloque)
                await writer.drain()
        except (ConnectionError, OSError, asyncio.IncompleteReadError):
            self.cortada.set()
        finally:
            self.abiertas -= 1
            writer.close()


async def socks_conectar(puerto_proxy: int, host: str, puerto: int, abrir=None):
    """Cliente SOCKS5 de prueba (como curl --socks5-hostname). Devuelve (reader, writer, código)."""
    abrir = abrir or asyncio.open_connection
    r, w = await abrir("127.0.0.1", puerto_proxy)
    w.write(b"\x05\x01\x00")
    assert await asyncio.wait_for(r.readexactly(2), 5) == b"\x05\x00"
    try:
        direccion = b"\x01" + ipaddress.IPv4Address(host).packed
    except ValueError:
        direccion = b"\x03" + bytes([len(host)]) + host.encode("ascii")
    w.write(b"\x05\x01\x00" + direccion + struct.pack(">H", puerto))
    respuesta = await asyncio.wait_for(r.readexactly(10), 30)
    assert respuesta in socks5.RESPUESTAS_VALIDAS
    return r, w, respuesta[1]


async def http_get(puerto_proxy: int, host: str, puerto: int, abrir=None) -> bytes:
    r, w, codigo = await socks_conectar(puerto_proxy, host, puerto, abrir)
    assert codigo == socks5.EXITO
    w.write(f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
    datos = await asyncio.wait_for(r.read(), 30)
    while True:
        mas = await asyncio.wait_for(r.read(), 30)
        if not mas:
            break
        datos += mas
    w.close()
    return datos


class Proxy:
    def __init__(self, directorio, **kw):
        self.servidor = ServidorProxy(directorio, puerto=0, gestor=GestorCircuitos(directorio, timeout=3, **kw))

    async def __aenter__(self):
        await self.servidor.iniciar()
        return self.servidor

    async def __aexit__(self, *exc):
        await self.servidor.detener()


async def recibir_stream(c: CircuitoCliente, sid: int) -> MensajeRelay:
    while True:
        msg = await asyncio.wait_for(c.recibir(), 10)
        if msg.stream_id == sid:
            return msg


# 3.5-1 ---------------------------------------------------------------------------

def test_proxy_circuito_salida_y_servidor_http_local(laboratorio):
    async def escenario():
        async with ServidorPrueba() as srv, RedSalida(laboratorio, politica_local(srv.puerto)) as red, \
                Proxy(red.d) as proxy:
            respuesta = await http_get(proxy.puerto, "127.0.0.1", srv.puerto)
            assert respuesta.startswith(b"HTTP/1.1 200 OK")
            assert respuesta.endswith(srv.cuerpo)
            await esperar(lambda: red.salida.streams_activos == 0)
    asyncio.run(escenario())


# 3.5-2 ---------------------------------------------------------------------------

def test_sin_la_excepcion_responde_05_02_y_el_servidor_no_recibe_nada(laboratorio):
    async def escenario():
        async with ServidorPrueba() as srv:
            sin_excepcion = PoliticaSalida(frozenset({80, 443, srv.puerto}), ())
            async with RedSalida(laboratorio, sin_excepcion) as red, Proxy(red.d) as proxy:
                _, w, codigo = await socks_conectar(proxy.puerto, "127.0.0.1", srv.puerto)
                w.close()
                assert codigo == socks5.NO_PERMITIDO
                assert srv.conexiones == 0
    asyncio.run(escenario())


# 3.5-3 y 3.5-4 --------------------------------------------------------------------

@pytest.mark.parametrize("host, puerto", [
    ("interno.prueba", 443),       # el dominio resuelve a 127.0.0.1
    ("lan.prueba", 443),           # el dominio resuelve a 192.168.1.20
    ("publico.prueba", 8080),      # IP pública, pero puerto fuera de 80/443
    ("publico.prueba", 22),
])
def test_begin_bloqueado_recibe_end_1(laboratorio, host, puerto):
    dns = {"interno.prueba": ["127.0.0.1"], "lan.prueba": ["192.168.1.20"], "publico.prueba": ["93.184.216.34"]}

    async def escenario():
        async with RedSalida(laboratorio, tabla_dns=dns) as red:
            c = await red.circuito()
            await c.enviar(MensajeRelay(ComandoRelay.BEGIN, 7, codificar_destino(host, puerto)))
            msg = await recibir_stream(c, 7)
            assert msg.comando == ComandoRelay.END
            assert decodificar_end(msg.datos) == MotivoEnd.NO_PERMITIDO
            assert await eco(c, b"sigue vivo") == b"sigue vivo"   # el circuito sigue sirviendo
            await c.cerrar()
    asyncio.run(escenario())


def test_se_conecta_a_la_ip_exacta_que_paso_la_politica(laboratorio):
    """Anti DNS-rebinding: una sola resolución; se usa la primera IP permitida y no se vuelve a resolver."""
    async def escenario():
        async with ServidorPrueba(modo="mantener") as srv:
            dns = {"mixto.prueba": ["10.1.2.3", "127.0.0.1"]}   # la primera está bloqueada
            async with RedSalida(laboratorio, politica_local(srv.puerto), dns) as red:
                usadas = []
                original = red.salida._abrir_destino

                async def espia(ip, puerto):
                    usadas.append(ip)
                    return await original(ip, puerto)

                red.salida._abrir_destino = espia
                c = await red.circuito()
                await c.enviar(MensajeRelay(ComandoRelay.BEGIN, 1, codificar_destino("mixto.prueba", srv.puerto)))
                assert (await recibir_stream(c, 1)).comando == ComandoRelay.CONNECTED
                assert usadas == ["127.0.0.1"]
                await c.cerrar()
    asyncio.run(escenario())


def test_relay_que_no_es_de_salida_destruye_el_circuito_ante_begin(laboratorio):
    async def escenario():
        async with RedSalida(laboratorio) as red:
            c = await red.circuito(saltos=2)            # termina en medio1 (salida=False)
            await c.enviar(MensajeRelay(ComandoRelay.BEGIN, 1, codificar_destino("example.com", 443)))
            with pytest.raises(CircuitoCerrado) as e:
                await asyncio.wait_for(c.recibir(), 5)
            assert e.value.motivo == 1
    asyncio.run(escenario())


def test_data_para_un_stream_desconocido_recibe_end_1(laboratorio):
    async def escenario():
        async with RedSalida(laboratorio) as red:
            c = await red.circuito()
            await c.enviar(MensajeRelay(ComandoRelay.DATA, 99, b"hola"))
            msg = await recibir_stream(c, 99)
            assert msg.comando == ComandoRelay.END and decodificar_end(msg.datos) == MotivoEnd.NO_PERMITIDO
            await c.cerrar()
    asyncio.run(escenario())


# 3.5-5 ---------------------------------------------------------------------------

def test_todos_los_relays_caidos_responde_05_01_sin_conexiones_directas(laboratorio, monkeypatch):
    async def escenario():
        red = RedSalida(laboratorio)                    # relays creados pero NUNCA iniciados
        relays = {(r.host, r.puerto) for r in red.d.relays}
        original = asyncio.open_connection
        directas = []

        async def espia(host=None, port=None, *a, **kw):
            if (host, port) not in relays:
                directas.append((host, port))
            return await original(host, port, *a, **kw)

        monkeypatch.setattr(asyncio, "open_connection", espia)
        async with Proxy(red.d) as proxy:
            for destino in (("example.com", 443), ("93.184.216.34", 80)):
                r, w, codigo = await socks_conectar(proxy.puerto, *destino, abrir=original)
                assert codigo == socks5.FALLO_GENERAL
                assert await asyncio.wait_for(r.read(), 5) == b""     # y se cierra
                w.close()
        assert directas == []
    asyncio.run(escenario())


# 3.5-6 (y consola sin destinos) ----------------------------------------------------

def test_el_proxy_nunca_resuelve_nombres_y_la_consola_no_los_muestra(laboratorio, monkeypatch, capfd):
    llamadas = []

    async def escenario():
        async with ServidorPrueba() as srv:
            dns = {"servidor-secreto.prueba": ["127.0.0.1"]}
            async with RedSalida(laboratorio, politica_local(srv.puerto), dns) as red, Proxy(red.d) as proxy:
                def prohibido(*a, **kw):
                    llamadas.append(a[:1])
                    raise OSError("getaddrinfo prohibido en el proxy")

                async def prohibido_async(self, *a, **kw):
                    return prohibido(*a, **kw)

                monkeypatch.setattr(socket, "getaddrinfo", prohibido)
                monkeypatch.setattr(asyncio.BaseEventLoop, "getaddrinfo", prohibido_async)
                respuesta = await http_get(proxy.puerto, "servidor-secreto.prueba", srv.puerto)
                assert respuesta.endswith(srv.cuerpo)
                return [proxy.puerto, srv.puerto] + red.puertos

    puertos = asyncio.run(escenario())
    assert llamadas == []
    salida = "".join(capfd.readouterr())
    assert "circuito creado" in salida
    assert "servidor-secreto" not in salida and "127.0.0.1" not in salida
    for p in puertos:
        assert str(p) not in salida


# 3.5-7 ---------------------------------------------------------------------------

def test_33_streams_en_un_circuito_el_33_recibe_end_1(laboratorio):
    async def escenario():
        async with ServidorPrueba(modo="mantener") as srv, \
                RedSalida(laboratorio, politica_local(srv.puerto)) as red:
            c = await red.circuito()
            destino = codificar_destino("127.0.0.1", srv.puerto)
            for sid in range(1, 33):
                await c.enviar(MensajeRelay(ComandoRelay.BEGIN, sid, destino))
            conectados = set()
            while len(conectados) < 32:
                msg = await asyncio.wait_for(c.recibir(), 10)
                assert msg.comando == ComandoRelay.CONNECTED
                conectados.add(msg.stream_id)
            await c.enviar(MensajeRelay(ComandoRelay.BEGIN, 33, destino))
            msg = await recibir_stream(c, 33)
            assert msg.comando == ComandoRelay.END and decodificar_end(msg.datos) == MotivoEnd.NO_PERMITIDO
            assert red.salida.streams_activos == 32
            await c.cerrar()
            await esperar(lambda: red.salida.streams_activos == 0 and srv.abiertas == 0)
    asyncio.run(escenario())


# 3.5-8 ---------------------------------------------------------------------------

def test_respuesta_de_1_mb_llega_integra_y_en_orden(laboratorio):
    async def escenario():
        async with ServidorPrueba(cuerpo=os.urandom(1024 * 1024)) as srv, \
                RedSalida(laboratorio, politica_local(srv.puerto)) as red, Proxy(red.d) as proxy:
            respuesta = await http_get(proxy.puerto, "127.0.0.1", srv.puerto)
            cabecera, _, cuerpo = respuesta.partition(b"\r\n\r\n")
            assert cabecera.startswith(b"HTTP/1.1 200 OK")
            assert cuerpo == srv.cuerpo
    asyncio.run(escenario())


# 3.5-9 ---------------------------------------------------------------------------

def test_el_cliente_cierra_a_mitad_de_la_descarga(laboratorio):
    async def escenario():
        async with ServidorPrueba(modo="infinito") as srv, \
                RedSalida(laboratorio, politica_local(srv.puerto)) as red, Proxy(red.d) as proxy:
            r, w, codigo = await socks_conectar(proxy.puerto, "127.0.0.1", srv.puerto)
            assert codigo == socks5.EXITO
            w.write(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            recibido = 0
            while recibido < 200_000:
                recibido += len(await asyncio.wait_for(r.read(65536), 10))
            w.close()
            await asyncio.wait_for(srv.cortada.wait(), 10)   # la salida cerró el socket del destino
            await esperar(lambda: red.salida.streams_activos == 0 and srv.abiertas == 0, 10)
    asyncio.run(escenario())


# 3.5-10 --------------------------------------------------------------------------

@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.1.10", "localhost"])
def test_el_proxy_no_escucha_fuera_de_127_0_0_1(laboratorio, host):
    d = Red(laboratorio).d
    with pytest.raises(ConfiguracionInvalida):
        ServidorProxy(d, host=host)
    assert cliente_proxy.main(["--escuchar", host]) == 1


# 3.5-11 --------------------------------------------------------------------------

def _publicar(laboratorio, carpeta, version: int):
    claves, autoridad = laboratorio
    lista = [{"apodo": a, "host": "127.0.0.1", "puerto": 9001 + i, "salida": a == "salida1"}
             for i, a in enumerate(("entrada1", "medio1", "salida1"))]
    firmado = dirmod.firmar(admin.armar_directorio(lista, claves, version, 7), autoridad)
    ruta = carpeta / f"directorio.v{version}.json"
    ruta.write_bytes(firmado)
    return ruta


def test_anti_rollback_rechaza_un_directorio_mas_viejo(laboratorio, tmp_path):
    _, autoridad = laboratorio
    pub = tmp_path / "autoridad.pub"
    ak.guardar_publica(pub, autoridad.public_key().public_bytes_raw())
    ultima = tmp_path / "ultima_version"
    v3, v2 = _publicar(laboratorio, tmp_path, 3), _publicar(laboratorio, tmp_path, 2)

    assert cargar_directorio(v3, pub, ultima).version == 3
    assert leer_ultima_version(ultima) == 3
    with pytest.raises(DirectorioInvalido):
        cargar_directorio(v2, pub, ultima)          # rollback: el proxy no arranca
    assert leer_ultima_version(ultima) == 3          # y el número no baja
    assert cargar_directorio(v3, pub, ultima).version == 3

    ultima.write_text("tres\n", encoding="ascii")
    with pytest.raises(ConfiguracionInvalida):
        cargar_directorio(v3, pub, ultima)           # archivo manipulado: falla cerrado


# Aceptación de la semana 3: detener y reiniciar el relay intermedio -----------------

def test_sin_relay_intermedio_la_navegacion_falla_y_al_reiniciarlo_vuelve(laboratorio):
    async def escenario():
        async with ServidorPrueba() as srv, \
                RedSalida(laboratorio, politica_local(srv.puerto)) as red, Proxy(red.d) as proxy:
            assert (await http_get(proxy.puerto, "127.0.0.1", srv.puerto)).endswith(srv.cuerpo)
            await red.nodos["medio1"].detener(limpio=False)
            _, w, codigo = await socks_conectar(proxy.puerto, "127.0.0.1", srv.puerto)
            w.close()
            assert codigo == socks5.FALLO_GENERAL
            conexiones = srv.conexiones
            nuevo = cargar_relay("medio1", red.d, red.claves, PASS, red.nodos["medio1"].config)
            red.nodos["medio1"] = nuevo
            await nuevo.iniciar()
            assert (await http_get(proxy.puerto, "127.0.0.1", srv.puerto)).endswith(srv.cuerpo)
            assert srv.conexiones == conexiones + 1
    asyncio.run(escenario())
