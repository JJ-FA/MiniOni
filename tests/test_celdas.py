"""R1 · ASVS V2.2.1: validación positiva de todo lo que llega por la red."""

import pytest

from minioni import celdas
from minioni.celdas import Celda, Comando, ComandoRelay, MensajeRelay
from minioni.constantes import MAX_DATOS_RELAY, TAM_CELDA, TAM_RELAY_PLANO
from minioni.errores import CeldaInvalida, DestinoNoPermitido


def test_celda_ida_y_vuelta():
    c = Celda(7, Comando.RELAY, b"abc")
    datos = c.codificar()
    assert len(datos) == TAM_CELDA
    d = celdas.decodificar_celda(datos)
    assert d.circ_id == 7 and d.comando == Comando.RELAY and d.carga.startswith(b"abc")


@pytest.mark.parametrize("largo", [0, 1, 511, 513, 4096])
def test_rechaza_tamano_distinto_de_512(largo):
    with pytest.raises(CeldaInvalida):
        celdas.decodificar_celda(b"\x00" * largo)


def test_rechaza_circ_id_cero():
    with pytest.raises(CeldaInvalida):
        celdas.decodificar_celda(b"\x00\x00\x00\x00\x03" + b"\x00" * 507)


def test_rechaza_comando_desconocido():
    with pytest.raises(CeldaInvalida):
        celdas.decodificar_celda(b"\x00\x00\x00\x01\x63" + b"\x00" * 507)


def test_relay_ida_y_vuelta():
    m = MensajeRelay(ComandoRelay.DATA, 3, b"hola")
    plano = celdas.codificar_relay(m)
    assert len(plano) == TAM_RELAY_PLANO
    assert celdas.decodificar_relay(plano) == m


def test_relay_rechaza_datos_grandes():
    with pytest.raises(CeldaInvalida):
        celdas.codificar_relay(MensajeRelay(ComandoRelay.DATA, 1, b"x" * (MAX_DATOS_RELAY + 1)))


def test_relay_rechaza_longitud_falsa():
    plano = bytearray(celdas.codificar_relay(MensajeRelay(ComandoRelay.DATA, 1, b"")))
    plano[3:5] = (MAX_DATOS_RELAY + 1).to_bytes(2, "big")
    with pytest.raises(CeldaInvalida):
        celdas.decodificar_relay(bytes(plano))


def test_relay_rechaza_relleno_no_nulo():
    plano = bytearray(celdas.codificar_relay(MensajeRelay(ComandoRelay.DATA, 1, b"a")))
    plano[-1] = 1
    with pytest.raises(CeldaInvalida):
        celdas.decodificar_relay(bytes(plano))


@pytest.mark.parametrize("host", ["ejemplo.com", "a.b-c.co", "10.0.0.1", "2001:db8::1", "EJEMPLO.com."])
def test_hosts_validos(host):
    celdas.validar_host(host)


@pytest.mark.parametrize("host", ["", "-malo.com", "malo-.com", "a..b", "a" * 256, "ej emplo.com",
                                  "ejemplo.com\r\n", "ñandú.com", "ejemplo.123", "x" * 64 + ".com"])
def test_hosts_invalidos(host):
    with pytest.raises(DestinoNoPermitido):
        celdas.validar_host(host)


@pytest.mark.parametrize("puerto", [0, -1, 65536, True, "80", 1.5])
def test_puertos_invalidos(puerto):
    with pytest.raises(DestinoNoPermitido):
        celdas.validar_puerto(puerto)


def test_begin_ida_y_vuelta():
    assert celdas.decodificar_begin(celdas.codificar_destino("ejemplo.com", 443)) == ("ejemplo.com", 443)


def test_begin_rechaza_bytes_sobrantes():
    with pytest.raises(DestinoNoPermitido):
        celdas.decodificar_begin(celdas.codificar_destino("ejemplo.com", 443) + b"x")


def test_begin_rechaza_truncado():
    with pytest.raises(DestinoNoPermitido):
        celdas.decodificar_begin(b"\x10ejemplo")


def test_extend_ida_y_vuelta():
    B, X = b"\x01" * 32, b"\x02" * 32
    datos = celdas.codificar_extend("10.10.1.11", 9002, B, X)
    assert celdas.decodificar_extend(datos) == ("10.10.1.11", 9002, B, X)


def test_extend_rechaza_claves_cortas():
    datos = celdas.codificar_destino("10.10.1.11", 9002) + b"\x01" * 40
    with pytest.raises(CeldaInvalida):
        celdas.decodificar_extend(datos)
