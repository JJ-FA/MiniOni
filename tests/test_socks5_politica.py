"""Parser SOCKS5, motivos de END y política de salida configurable (semana 3), sin red.

Normas: ASVS V2.2.1 (validación positiva), V16.5.1 (respuestas genéricas).
"""

import asyncio
import json

import pytest

from minioni import socks5
from minioni.celdas import MotivoEnd, codificar_end, decodificar_end
from minioni.errores import CeldaInvalida, ConfiguracionInvalida, SocksInvalido
from minioni.politica_salida import PUERTOS_PERMITIDOS, cargar_politica, validar_politica


class EscritorFalso:
    def __init__(self):
        self.escrito = b""

    def write(self, datos):
        self.escrito += datos

    async def drain(self):
        pass


def negociar(datos: bytes):
    async def correr():
        reader = asyncio.StreamReader()
        reader.feed_data(datos)
        reader.feed_eof()
        w = EscritorFalso()
        try:
            return await socks5.negociar(reader, w, timeout=2), w.escrito
        except SocksInvalido as e:
            return e, w.escrito
    return asyncio.run(correr())


SALUDO = b"\x05\x01\x00"


@pytest.mark.parametrize("solicitud, esperado", [
    (b"\x05\x01\x00\x03\x0bexample.com\x01\xbb", ("example.com", 443)),
    (b"\x05\x01\x00\x03\x0bEXAMPLE.com\x00\x50", ("example.com", 80)),
    (b"\x05\x01\x00\x01\x5d\xb8\xd8\x22\x01\xbb", ("93.184.216.34", 443)),
    (b"\x05\x01\x00\x04" + bytes(15) + b"\x01\x00\x50", ("::1", 80)),
])
def test_solicitudes_validas(solicitud, esperado):
    resultado, escrito = negociar(SALUDO + solicitud)
    assert resultado == esperado
    assert escrito == b"\x05\x00"     # solo la respuesta del saludo: el éxito lo decide el circuito


def test_saludo_sin_metodo_00_responde_05_ff():
    e, escrito = negociar(b"\x05\x02\x01\x02")
    assert isinstance(e, SocksInvalido) and escrito == b"\x05\xff"


@pytest.mark.parametrize("solicitud, codigo", [
    (b"\x05\x02\x00\x01\x01\x02\x03\x04\x00\x50", socks5.COMANDO_NO_SOPORTADO),   # BIND
    (b"\x05\x03\x00\x01\x01\x02\x03\x04\x00\x50", socks5.COMANDO_NO_SOPORTADO),   # UDP ASSOCIATE
    (b"\x05\x01\x00\x05\x01\x02\x03\x04\x00\x50", socks5.DIRECCION_NO_SOPORTADA),
    (b"\x05\x01\x00\x03\x00\x00\x50", socks5.FALLO_GENERAL),                      # dominio vacío
    (b"\x05\x01\x01\x01\x01\x02\x03\x04\x00\x50", socks5.FALLO_GENERAL),          # RSV != 0
    (b"\x05\x01\x00\x03\x05ex_mp\x00\x50", socks5.NO_PERMITIDO),                  # nombre mal formado
    (b"\x05\x01\x00\x03\x05ex\xffmp\x00\x50", socks5.NO_PERMITIDO),               # no ASCII
    (b"\x05\x01\x00\x01\x01\x02\x03\x04\x00\x00", socks5.NO_PERMITIDO),           # puerto 0
])
def test_solicitudes_rechazadas_con_respuesta_generica(solicitud, codigo):
    e, escrito = negociar(SALUDO + solicitud)
    assert isinstance(e, SocksInvalido)
    assert escrito == b"\x05\x00" + socks5.respuesta(codigo)


@pytest.mark.parametrize("datos", [
    b"",                       # nada
    b"\x04\x01\x00\x50",       # SOCKS4
    b"\x05\x00",               # sin métodos
    b"\x05\x03\x00",           # métodos truncados
    SALUDO + b"\x05\x01\x00\x01\x01\x02",          # solicitud truncada
    SALUDO + b"\x04\x01\x00\x01\x01\x02\x03\x04\x00\x50",   # versión distinta en la solicitud
])
def test_entradas_mal_formadas_cierran_sin_detalles(datos):
    e, escrito = negociar(datos)
    assert isinstance(e, SocksInvalido)
    assert escrito in (b"", b"\x05\x00", b"\x05\xff")


def test_negociacion_lenta_se_corta_por_tiempo():
    async def correr():
        reader = asyncio.StreamReader()
        reader.feed_data(b"\x05")      # y nunca más nada
        with pytest.raises(SocksInvalido):
            await socks5.negociar(reader, EscritorFalso(), timeout=0.2)
    asyncio.run(correr())


def test_respuesta_nunca_lleva_la_direccion():
    for codigo in (0, 1, 2, 7, 8):
        assert socks5.respuesta(codigo) == bytes([5, codigo, 0, 1, 0, 0, 0, 0, 0, 0])


# --- END ----------------------------------------------------------------------------

def test_end_ida_y_vuelta():
    assert decodificar_end(codificar_end()) is None
    for m in MotivoEnd:
        assert decodificar_end(codificar_end(m)) == m
    for malo in (b"\x00", b"\x04", b"\x01\x00"):
        with pytest.raises(CeldaInvalida):
            decodificar_end(malo)


# --- política de salida configurable ------------------------------------------------

def test_politica_por_defecto_si_no_hay_archivo(tmp_path):
    p = cargar_politica(tmp_path / "no_existe.json")
    assert p.puertos == PUERTOS_PERMITIDOS and p.excepciones == ()


def test_politica_valida(tmp_path):
    ruta = tmp_path / "p.json"
    ruta.write_text(json.dumps({"puertos": [80, 443, 8443], "excepciones_redes": ["10.10.9.0/24"]}))
    p = cargar_politica(ruta)
    assert p.puertos == {80, 443, 8443} and p.excepciones == ("10.10.9.0/24",)


@pytest.mark.parametrize("datos", [
    {"puertos": [80]},                                               # falta una clave
    {"puertos": [80], "excepciones_redes": [], "extra": 1},          # clave de más
    {"puertos": [], "excepciones_redes": []},                        # sin puertos
    {"puertos": [0], "excepciones_redes": []},
    {"puertos": [65536], "excepciones_redes": []},
    {"puertos": [True], "excepciones_redes": []},
    {"puertos": ["80"], "excepciones_redes": []},
    {"puertos": [80, 80], "excepciones_redes": []},
    {"puertos": [80], "excepciones_redes": ["10.10.9.1/24"]},       # host bits: strict
    {"puertos": [80], "excepciones_redes": ["no es una red"]},
    {"puertos": [80], "excepciones_redes": "10.0.0.0/8"},
    [80, 443],
])
def test_politica_invalida_se_rechaza(datos):
    with pytest.raises(ConfiguracionInvalida):
        validar_politica(datos)


def test_politica_con_json_roto_o_claves_duplicadas(tmp_path):
    ruta = tmp_path / "p.json"
    for contenido in ('{"puertos": [80', '{"puertos": [80], "puertos": [22], "excepciones_redes": []}'):
        ruta.write_text(contenido)
        with pytest.raises(ConfiguracionInvalida):
            cargar_politica(ruta)


def test_politica_del_repositorio_es_la_restrictiva():
    p = cargar_politica("config/politica_salida.json")
    assert p.puertos == {80, 443} and p.excepciones == ()
