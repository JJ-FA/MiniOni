"""Fuzzing con Hypothesis: "toda entrada es hostil".

R1 · OWASP ASVS 5.0 V2.2.1 y NIST SSDF PW.8.2 (pruebas del código ejecutable).

Cada prueba le lanza cientos de entradas generadas al azar a un parser y
comprueba UNA propiedad: el parser acepta la entrada o la rechaza con su
excepción controlada. Cualquier otra excepción (IndexError, KeyError,
UnicodeError, struct.error, ...) sería un fallo no previsto que un atacante
podría usar para tumbar un nodo, y hace fallar la prueba.

Además se comprueban propiedades de ida y vuelta: lo que se codifica se
decodifica igual.
"""

import asyncio
import json
import os
import struct
import time
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from hypothesis import given
from hypothesis import strategies as st

from minioni import almacen_claves, capas, celdas, directorio, handshake, politica_salida, socks5
from minioni.celdas import Celda, Comando, ComandoRelay, MensajeRelay
from minioni.constantes import MAX_DATOS_RELAY, TAM_CARGA, TAM_CELDA, TAM_RELAY_PLANO
from minioni.errores import (
    CeldaInvalida,
    CeldaManipulada,
    ClaveInvalida,
    ConfiguracionInvalida,
    DestinoNoPermitido,
    DirectorioInvalido,
    EnlaceCerrado,
    HandshakeFallido,
    SocksInvalido,
)
from minioni.relay import ConfigRelay, NodoRelay

# Claves fijas para todo el módulo (generarlas en cada caso sería lento).
CLAVE_RELAY = X25519PrivateKey.generate()
AUTORIDAD = Ed25519PrivateKey.generate()
PUB_AUTORIDAD = AUTORIDAD.public_key().public_bytes_raw()

# Valores JSON arbitrarios: null, booleanos, números, texto, listas y objetos anidados.
json_arbitrario = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | st.text(max_size=20),
    lambda hijos: st.lists(hijos, max_size=5) | st.dictionaries(st.text(max_size=12), hijos, max_size=6),
    max_leaves=30,
)


def una_capa():
    est, sol = handshake.HandshakeCliente.iniciar(CLAVE_RELAY.public_key().public_bytes_raw())
    capa_relay, resp = handshake.relay_responder(CLAVE_RELAY, sol)
    return est.finalizar(resp), capa_relay


# --- celdas ---------------------------------------------------------------------

@given(st.binary(max_size=1024))
def test_fuzz_celda_bytes_cualquiera(datos):
    try:
        c = celdas.decodificar_celda(datos)
    except CeldaInvalida:
        return
    assert len(datos) == TAM_CELDA and c.circ_id != 0


@given(st.binary(min_size=TAM_CELDA, max_size=TAM_CELDA))
def test_fuzz_celda_tamano_correcto(datos):
    try:
        c = celdas.decodificar_celda(datos)
    except CeldaInvalida:
        return
    assert c.codificar() == datos   # aceptar implica poder reconstruirla igual


@given(st.integers(1, 2**32 - 1), st.sampled_from(Comando), st.binary(max_size=TAM_CARGA))
def test_ida_y_vuelta_celda(circ_id, comando, carga):
    c = celdas.decodificar_celda(Celda(circ_id, comando, carga).codificar())
    assert (c.circ_id, c.comando) == (circ_id, comando)
    assert c.carga[:len(carga)] == carga


@given(st.binary(min_size=TAM_RELAY_PLANO, max_size=TAM_RELAY_PLANO))
def test_fuzz_relay_plano(datos):
    try:
        celdas.decodificar_relay(datos)
    except CeldaInvalida:
        pass


@given(st.sampled_from(ComandoRelay), st.integers(0, 0xFFFF), st.binary(max_size=MAX_DATOS_RELAY))
def test_ida_y_vuelta_relay(comando, stream_id, datos):
    m = MensajeRelay(comando, stream_id, datos)
    assert celdas.decodificar_relay(celdas.codificar_relay(m)) == m


# --- destinos ---------------------------------------------------------------------

@given(st.text(max_size=300))
def test_fuzz_validar_host(texto):
    try:
        host = celdas.validar_host(texto)
    except DestinoNoPermitido:
        return
    assert host.isascii() and len(host) <= 255
    assert not any(c in host for c in "\r\n\x00 /\\@")


@given(st.binary(max_size=400))
def test_fuzz_begin(datos):
    try:
        celdas.decodificar_begin(datos)
    except DestinoNoPermitido:
        pass


@given(st.binary(max_size=400))
def test_fuzz_extend(datos):
    try:
        celdas.decodificar_extend(datos)
    except (DestinoNoPermitido, CeldaInvalida):
        pass


@given(st.text(max_size=60))
def test_fuzz_politica_salida(texto):
    try:
        politica_salida.verificar_ip_destino(texto)
    except DestinoNoPermitido:
        pass


@given(st.ip_addresses())
def test_politica_salida_nunca_permite_redes_internas(ip):
    try:
        politica_salida.verificar_ip_destino(str(ip))
    except DestinoNoPermitido:
        return
    assert ip.is_global and not ip.is_private and not ip.is_loopback


# --- capas y handshake ----------------------------------------------------------

@given(st.binary(min_size=TAM_CARGA, max_size=TAM_CARGA))
def test_fuzz_relay_pelar(carga):
    """Una celda inventada nunca pasa la verificación Poly1305."""
    _, capa_relay = una_capa()
    try:
        capas.relay_pelar(capa_relay, carga)
    except (CeldaInvalida, CeldaManipulada):
        return
    raise AssertionError("se aceptó una celda que no fue cifrada con la clave del salto")


@given(st.binary(min_size=TAM_CARGA, max_size=TAM_CARGA))
def test_fuzz_relay_agregar_capa(carga):
    _, capa_relay = una_capa()
    try:
        assert len(capas.relay_agregar_capa(capa_relay, carga)) == TAM_CARGA
    except CeldaInvalida:
        pass


@given(st.binary(min_size=TAM_CARGA, max_size=TAM_CARGA))
def test_fuzz_cliente_pelar(carga):
    capa_cliente, _ = una_capa()
    try:
        capas.cliente_pelar([capa_cliente], carga)
    except (CeldaInvalida, CeldaManipulada):
        return
    raise AssertionError("el cliente aceptó una respuesta falsificada")


@given(st.binary(max_size=200))
def test_fuzz_handshake_relay(solicitud):
    try:
        handshake.relay_responder(CLAVE_RELAY, solicitud)
    except HandshakeFallido:
        pass


@given(st.binary(max_size=200))
def test_fuzz_handshake_cliente(respuesta):
    est, _ = handshake.HandshakeCliente.iniciar(CLAVE_RELAY.public_key().public_bytes_raw())
    try:
        est.finalizar(respuesta)
    except HandshakeFallido:
        return
    raise AssertionError("el cliente aceptó una respuesta de handshake inventada")


# --- directorio ---------------------------------------------------------------

@given(st.binary(max_size=2048))
def test_fuzz_directorio_bytes(datos):
    try:
        directorio.verificar(datos, PUB_AUTORIDAD)
    except DirectorioInvalido:
        return
    raise AssertionError("se aceptó un directorio sin firma válida")


@given(json_arbitrario)
def test_fuzz_directorio_json(valor):
    """JSON bien formado pero con estructura arbitraria."""
    contenido = json.dumps({"directorio": valor, "firma": "A" * 88}).encode()
    try:
        directorio.verificar(contenido, PUB_AUTORIDAD)
    except DirectorioInvalido:
        return
    raise AssertionError("se aceptó un directorio con firma inventada")


@given(json_arbitrario)
def test_fuzz_estructura_directorio(valor):
    """Aunque la firma fuera válida, una estructura arbitraria debe rechazarse limpiamente."""
    try:
        directorio.validar_estructura(valor)
    except DirectorioInvalido:
        pass


# --- almacén de claves --------------------------------------------------------

@given(json_arbitrario)
def test_fuzz_archivo_de_clave(tmp_path_factory, valor):
    ruta = tmp_path_factory.mktemp("k") / "clave.key"
    ruta.write_text(json.dumps(valor), encoding="ascii")
    try:
        almacen_claves.cargar_privada(ruta, "contraseña cualquiera", "x25519")
    except ClaveInvalida:
        return
    raise AssertionError("se abrió un archivo de clave inventado")


@given(st.binary(max_size=600))
def test_fuzz_archivo_de_clave_binario(tmp_path_factory, datos):
    ruta = tmp_path_factory.mktemp("k") / "clave.key"
    ruta.write_bytes(datos)
    try:
        almacen_claves.cargar_privada(ruta, "contraseña cualquiera", "x25519")
    except ClaveInvalida:
        return
    raise AssertionError("se abrió un archivo de clave inventado")


def test_fuzz_mutacion_de_celda_valida():
    """Mutación dirigida: se toma una celda VÁLIDA y se altera cada byte, uno por uno."""
    plano = celdas.codificar_relay(MensajeRelay(ComandoRelay.DATA, 1, os.urandom(100)))
    capa_cliente, _ = una_capa()
    original = capas.cliente_envolver([capa_cliente], plano)
    util = 2 + int.from_bytes(original[:2], "big")   # solo los bytes cubiertos por la capa
    for i in range(util):
        # Circuito nuevo en cada intento: el contador del nonce empieza en cero.
        cliente_nuevo, relay_nuevo = una_capa()
        celda = bytearray(capas.cliente_envolver([cliente_nuevo], plano))
        celda[i] ^= 0xFF
        try:
            capas.relay_pelar(relay_nuevo, bytes(celda))
        except (CeldaInvalida, CeldaManipulada):
            continue
        raise AssertionError(f"la alteración del byte {i} no se detectó")


# --- semana 2: cargas de enlace -------------------------------------------------

@given(st.binary(max_size=TAM_CARGA + 10), st.integers(0, TAM_CARGA))
def test_fuzz_carga_fija(carga, tam):
    try:
        util = celdas.decodificar_carga_fija(carga, tam)
    except CeldaInvalida:
        return
    assert len(carga) == TAM_CARGA and not any(carga[tam:]) and util == carga[:tam]


@given(st.binary(max_size=TAM_CARGA + 10))
def test_fuzz_destroy(carga):
    try:
        motivo = celdas.decodificar_destroy(carga)
    except CeldaInvalida:
        return
    assert 1 <= motivo <= 4 and celdas.codificar_destroy(motivo).ljust(TAM_CARGA, b"\x00") == carga


# --- semana 2: máquina de estados del relay (sin red) ----------------------------

CLAVE_OTRO = X25519PrivateKey.generate()


def _directorio_fuzz(salida_yo: bool = False) -> directorio.Directorio:
    ahora = datetime.now(timezone.utc)

    def entrada(apodo, puerto, clave, salida):
        return directorio.Relay(apodo, "127.0.0.1", puerto, clave.public_key().public_bytes_raw(), "0" * 64, salida)

    return directorio.Directorio(1, ahora, ahora + timedelta(days=1), (
        entrada("yo", 9001, CLAVE_RELAY, salida_yo),
        entrada("otro", 9002, CLAVE_OTRO, False),
        entrada("salida", 9003, X25519PrivateKey.generate(), True),
    ))


class EnlaceFalso:
    """Mismo contrato que transporte.Enlace, sin red."""

    def __init__(self, saliente=False):
        self.saliente = saliente
        self.cerrado = False
        self.enviadas = []
        self.ultima_actividad = 0.0

    async def enviar(self, celda):
        if self.cerrado:
            raise EnlaceCerrado("cerrado")
        celda.codificar()
        self.enviadas.append(celda)

    async def leer_celda(self):
        await asyncio.Event().wait()

    def cerrar(self):
        self.cerrado = True

    def abortar(self):
        self.cerrado = True


# "relay", "extend" y "destroy" eligen uno de los circuitos vivos por su índice
# (o un circ_id cualquiera si no hay): así se llega a los estados profundos.
operacion_relay = st.one_of(
    st.tuples(st.just("create"), st.integers(0, 2), st.integers(1, 3)),
    st.tuples(st.just("relay"), st.integers(0, 7),
              st.sampled_from([int(c) for c in ComandoRelay]) | st.integers(0, 255),
              st.integers(0, 3), st.binary(max_size=80)),
    st.tuples(st.just("extend"), st.integers(0, 7), st.booleans(), st.booleans(), st.integers(0, 600)),
    st.tuples(st.just("saliente"), st.integers(0, 3), st.sampled_from(Comando), st.integers(0, 600),
              st.binary(max_size=TAM_CARGA - 2)),
    st.tuples(st.just("crudo"), st.integers(0, 2), st.binary(min_size=TAM_CELDA, max_size=TAM_CELDA)),
    st.tuples(st.just("destroy"), st.integers(0, 7), st.integers(0, 255)),
    st.tuples(st.just("limpiar"), st.floats(0, 1000)),
    # Semana 3: BEGIN con destinos bien formados (permitidos, internos, inalcanzables, otros puertos).
    st.tuples(st.just("begin"), st.integers(0, 7), st.integers(0, 3),
              st.sampled_from(["example.com", "interno.prueba", "caido.prueba"]), st.sampled_from([80, 443, 22])),
)


@given(st.lists(operacion_relay, max_size=25))
def test_fuzz_maquina_de_estados_del_relay(operaciones):
    """Secuencias de celdas válidas e inválidas: solo MiniOniError, nunca ERROR_INTERNO, tablas coherentes."""
    asyncio.run(_ejecutar_operaciones(operaciones))


@given(st.lists(operacion_relay, max_size=25))
def test_fuzz_maquina_de_estados_del_nodo_de_salida(operaciones):
    """Lo mismo con el relay como nodo de salida: streams que conectan, se bloquean, fallan o quedan abiertos."""
    asyncio.run(_ejecutar_operaciones(operaciones, salida=True))


class EscritorDestinoFalso:
    def __init__(self):
        self.cerrado = False

    def write(self, datos):
        if self.cerrado:
            raise ConnectionResetError("cerrado")

    async def drain(self):
        pass

    def close(self):
        self.cerrado = True


async def _resolver_fuzz(host, puerto):
    if host == "caido.prueba":
        raise OSError("sin respuesta")
    ip = "10.0.0.1" if host == "interno.prueba" else "93.184.216.34"
    return [(2, 1, 6, "", (ip, puerto))]


async def _abrir_fuzz(ip, puerto):
    lector = asyncio.StreamReader()
    lector.feed_data(b"respuesta del destino")
    if puerto == 80:
        lector.feed_eof()      # el destino cierra; en 443 el stream queda abierto
    return lector, EscritorDestinoFalso()


async def _ejecutar_operaciones(operaciones, salida=False):
    salientes = []

    async def conectar(destino):
        e = EnlaceFalso(saliente=True)
        salientes.append(e)
        return e

    nodo = NodoRelay("yo", _directorio_fuzz(salida), CLAVE_RELAY, None, ConfigRelay(timeout_handshake=1), conectar,
                     resolver=_resolver_fuzz, abrir_destino=_abrir_fuzz)
    eventos = []
    nodo._evento = lambda codigo, cantidad=None: eventos.append(codigo)
    entrantes = [EnlaceFalso() for _ in range(3)]
    capas_cliente = {}
    B_yo = CLAVE_RELAY.public_key().public_bytes_raw()
    B_otro = CLAVE_OTRO.public_key().public_bytes_raw()

    async def entregar(enlace, celda):
        celda = celdas.decodificar_celda(celda.codificar())   # como llega del cable: carga de 507 bytes
        try:
            await nodo.procesar_celda(enlace, celda)
        except CeldaInvalida:
            await nodo.cerrar_enlace(enlace)   # lo mismo que hace el bucle de lectura

    def elegir(k):
        vivos = sorted(capas_cliente)
        return vivos[k % len(vivos)] if vivos else (k % 3, k + 1)

    def envolver(i, cid, plano):
        capa = capas_cliente.get((i, cid))
        return capas.cliente_envolver([capa], plano) if capa else os.urandom(TAM_CARGA)

    for op in operaciones:
        for i, e in enumerate(entrantes):
            if e.cerrado:
                entrantes[i] = EnlaceFalso()
                capas_cliente = {k: v for k, v in capas_cliente.items() if k[0] != i}
        tipo = op[0]
        if tipo == "create":
            _, i, cid = op
            est, sol = handshake.HandshakeCliente.iniciar(B_yo)
            e = entrantes[i]
            antes = len(e.enviadas)
            await entregar(e, Celda(cid, Comando.CREATE, sol))
            if len(e.enviadas) > antes and e.enviadas[-1].comando == Comando.CREATED:
                capas_cliente[(i, cid)] = est.finalizar(e.enviadas[-1].carga[:64])
        elif tipo == "relay":
            _, k, cmd, stream, datos = op
            i, cid = elegir(k)
            plano = (struct.pack(">BHH", cmd, stream, len(datos)) + datos).ljust(TAM_RELAY_PLANO, b"\x00")
            await entregar(entrantes[i], Celda(cid, Comando.RELAY, envolver(i, cid, plano)))
        elif tipo == "extend":
            _, k, valido, responder, largo_vuelta = op
            i, cid = elegir(k)
            datos = celdas.codificar_extend("127.0.0.1", 9002, B_otro if valido else os.urandom(32), os.urandom(32))
            plano = celdas.codificar_relay(MensajeRelay(ComandoRelay.EXTEND, 0, datos))
            await entregar(entrantes[i], Celda(cid, Comando.RELAY, envolver(i, cid, plano)))
            for _ in range(3):
                await asyncio.sleep(0)
            creates = [c for e in salientes for c in e.enviadas if c.comando == Comando.CREATE]
            if responder and creates and not salientes[-1].cerrado:
                _, resp = handshake.relay_responder(CLAVE_OTRO, creates[-1].carga[:64])
                await entregar(salientes[-1], Celda(creates[-1].circ_id, Comando.CREATED, resp))
                vuelta = struct.pack(">H", largo_vuelta) + os.urandom(TAM_CARGA - 2)
                if not salientes[-1].cerrado:
                    await entregar(salientes[-1], Celda(creates[-1].circ_id, Comando.RELAY, vuelta))
        elif tipo == "saliente" and salientes:
            _, i, cmd, largo, carga = op
            e = salientes[i % len(salientes)]
            carga = struct.pack(">H", largo) + carga   # longitud de capa a veces plausible
            creates = [c for c in e.enviadas if c.comando == Comando.CREATE]
            cid = creates[-1].circ_id if creates else 1
            if cmd == Comando.CREATED and creates:
                _, carga = handshake.relay_responder(CLAVE_OTRO, creates[-1].carga[:64])
            if not e.cerrado:
                await entregar(e, Celda(cid, cmd, carga))
        elif tipo == "crudo":
            _, i, datos = op
            try:
                celda = celdas.decodificar_celda(datos)
            except CeldaInvalida:
                await nodo.cerrar_enlace(entrantes[i])
            else:
                await entregar(entrantes[i], celda)
        elif tipo == "destroy":
            _, k, motivo = op
            i, cid = elegir(k)
            await entregar(entrantes[i], Celda(cid, Comando.DESTROY, bytes([motivo])))
        elif tipo == "limpiar":
            await nodo.limpiar_una_vez(time.monotonic() + op[1])
        elif tipo == "begin":
            _, k, stream, host, puerto = op
            i, cid = elegir(k)
            msg = MensajeRelay(ComandoRelay.BEGIN, stream, celdas.codificar_destino(host, puerto))
            await entregar(entrantes[i], Celda(cid, Comando.RELAY, envolver(i, cid, celdas.codificar_relay(msg))))
            for _ in range(5):
                await asyncio.sleep(0)   # deja correr la tarea del stream
        for estado in nodo._circuitos:
            assert nodo._tabla[estado.anterior] is estado
            assert estado.siguiente is None or nodo._tabla[estado.siguiente] is estado
            assert all(1 <= sid <= 0xFFFF for sid in estado.streams)
            assert salida or not estado.streams
    await nodo.detener()
    assert nodo.tablas_vacias() and nodo.streams_activos == 0
    assert "ERROR_INTERNO" not in eventos


# --- semana 3: SOCKS5, END y política de salida -----------------------------------

class _EscritorSocks:
    def __init__(self):
        self.escrito = []

    def write(self, datos):
        self.escrito.append(bytes(datos))

    async def drain(self):
        pass


@given(st.binary(max_size=300))
def test_fuzz_socks5_saludo(datos):
    try:
        assert socks5.procesar_saludo(datos) == socks5.SALUDO_ACEPTADO
    except SocksInvalido as e:
        assert e.respuesta in (None, socks5.SALUDO_RECHAZADO)


@given(st.binary(max_size=300))
def test_fuzz_socks5_solicitud(datos):
    try:
        host, puerto = socks5.decodificar_solicitud(datos)
    except SocksInvalido as e:
        assert e.respuesta is None or e.respuesta in socks5.RESPUESTAS_VALIDAS
        return
    assert celdas.validar_host(host) == host and 1 <= puerto <= 65535


solicitud_socks = st.builds(
    lambda cmd, rsv, atyp, cuerpo, puerto: bytes([5, cmd, rsv, atyp]) + cuerpo + struct.pack(">H", puerto),
    st.sampled_from([1, 1, 1, 2, 3, 0, 255]), st.sampled_from([0, 0, 0, 1]),
    st.sampled_from([1, 3, 3, 4, 0, 5]),
    st.one_of(st.binary(min_size=4, max_size=4), st.binary(min_size=16, max_size=16),
              st.builds(lambda n: bytes([len(n)]) + n.encode("ascii"),
                        st.from_regex(r"[a-z0-9.-]{0,40}", fullmatch=True)),
              st.binary(max_size=40)),
    st.integers(0, 65535),
)


@given(st.one_of(st.binary(max_size=400),
                 st.builds(lambda m, s: bytes([5, len(m)]) + m + s, st.binary(min_size=1, max_size=5),
                           solicitud_socks)))
def test_fuzz_socks5_negociacion(datos):
    """Cualquier entrada termina en (host, puerto) o SocksInvalido, y solo se escriben respuestas válidas."""
    async def correr():
        reader = asyncio.StreamReader()
        reader.feed_data(datos)
        reader.feed_eof()
        w = _EscritorSocks()
        try:
            host, puerto = await socks5.negociar(reader, w, timeout=2)
            assert celdas.validar_host(host) == host and 1 <= puerto <= 65535
        except SocksInvalido:
            pass
        assert all(r in socks5.RESPUESTAS_VALIDAS for r in w.escrito)
    asyncio.run(correr())


@given(st.binary(max_size=5))
def test_fuzz_end(datos):
    try:
        motivo = celdas.decodificar_end(datos)
    except CeldaInvalida:
        return
    assert celdas.codificar_end(motivo) == datos


@given(st.one_of(json_arbitrario,
                 st.fixed_dictionaries({"puertos": st.lists(st.integers(-5, 70000) | st.booleans(), max_size=5),
                                        "excepciones_redes": st.lists(st.text(max_size=20), max_size=3)})))
def test_fuzz_politica_salida(datos):
    try:
        p = politica_salida.validar_politica(datos)
    except ConfiguracionInvalida:
        return
    assert p.puertos and all(1 <= x <= 65535 for x in p.puertos)
