"""R2 · ASVS V11.3.3 / V11.3.4 y R3 · ASVS V11.6.1 / V11.6.2."""

import os

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from minioni import capas, celdas, handshake
from minioni.celdas import ComandoRelay, MensajeRelay
from minioni.constantes import TAM_CARGA, TAM_RELAY_PLANO
from minioni.errores import CeldaInvalida, CeldaManipulada, HandshakeFallido


def circuito(n=3):
    cli, rel = [], []
    for _ in range(n):
        k = X25519PrivateKey.generate()
        est, sol = handshake.HandshakeCliente.iniciar(k.public_key().public_bytes_raw())
        capa_r, resp = handshake.relay_responder(k, sol)
        cli.append(est.finalizar(resp))
        rel.append(capa_r)
    return cli, rel


def ida(cli, rel, plano):
    carga = capas.cliente_envolver(cli, plano)
    for i, capa in enumerate(rel):
        interior = capas.relay_pelar(capa, carga)
        carga = capas.rellenar(interior) if i < len(rel) - 1 else interior
    return carga


def vuelta(cli, rel, plano):
    carga = capas.relay_originar(rel[-1], plano)
    for capa in reversed(rel[:-1]):
        carga = capas.relay_agregar_capa(capa, carga)
    return capas.cliente_pelar(cli, carga)


def plano(texto=b"hola"):
    return celdas.codificar_relay(MensajeRelay(ComandoRelay.DATA, 1, texto))


# --- handshake -----------------------------------------------------------------

def test_handshake_produce_claves_iguales():
    cli, rel = circuito(1)
    assert vuelta(cli, rel, plano()) == plano()


def test_relay_falso_no_puede_completar_handshake():
    """STRIDE S: un relay sin la clave privada publicada no genera un HMAC válido."""
    legitimo, impostor = X25519PrivateKey.generate(), X25519PrivateKey.generate()
    B = legitimo.public_key().public_bytes_raw()
    est, sol = handshake.HandshakeCliente.iniciar(B)
    # El impostor ignora el B pedido y responde con su propia clave.
    sol_impostor = impostor.public_key().public_bytes_raw() + sol[32:]
    _, resp = handshake.relay_responder(impostor, sol_impostor)
    with pytest.raises(HandshakeFallido):
        est.finalizar(resp)


def test_relay_rechaza_solicitud_para_otro():
    a, b = X25519PrivateKey.generate(), X25519PrivateKey.generate()
    _, sol = handshake.HandshakeCliente.iniciar(a.public_key().public_bytes_raw())
    with pytest.raises(HandshakeFallido):
        handshake.relay_responder(b, sol)


def test_respuesta_alterada_se_rechaza():
    k = X25519PrivateKey.generate()
    est, sol = handshake.HandshakeCliente.iniciar(k.public_key().public_bytes_raw())
    _, resp = handshake.relay_responder(k, sol)
    with pytest.raises(HandshakeFallido):
        est.finalizar(resp[:-1] + bytes([resp[-1] ^ 1]))


def test_clave_publica_nula_se_rechaza():
    k = X25519PrivateKey.generate()
    sol = k.public_key().public_bytes_raw() + bytes(32)   # X = punto de orden bajo
    with pytest.raises(HandshakeFallido):
        handshake.relay_responder(k, sol)


def test_handshake_no_se_reutiliza():
    k = X25519PrivateKey.generate()
    est, sol = handshake.HandshakeCliente.iniciar(k.public_key().public_bytes_raw())
    _, resp = handshake.relay_responder(k, sol)
    est.finalizar(resp)
    with pytest.raises(HandshakeFallido):
        est.finalizar(resp)


def test_cada_circuito_usa_claves_distintas():
    """Secreto hacia adelante: mismo relay, handshakes distintos -> claves distintas."""
    k = X25519PrivateKey.generate()
    B = k.public_key().public_bytes_raw()
    cargas = []
    for _ in range(2):
        est, sol = handshake.HandshakeCliente.iniciar(B)
        _, resp = handshake.relay_responder(k, sol)
        cargas.append(capas.cliente_envolver([est.finalizar(resp)], plano())[:100])
    assert cargas[0] != cargas[1]


# --- capas ----------------------------------------------------------------------

@pytest.mark.parametrize("n", [1, 2, 3])
def test_ida_y_vuelta_por_n_saltos(n):
    cli, rel = circuito(n)
    assert ida(cli, rel, plano()) == plano()
    assert vuelta(cli, rel, plano(b"respuesta")) == plano(b"respuesta")


def test_todas_las_celdas_miden_lo_mismo():
    cli, _ = circuito()
    assert {len(capas.cliente_envolver(cli, plano(b"x" * k))) for k in (0, 10, 448)} == {TAM_CARGA}


def test_relay_intermedio_no_ve_el_texto_plano():
    cli, rel = circuito()
    secreto = b"ejemplo.com"
    carga = capas.cliente_envolver(cli, plano(secreto))
    assert secreto not in carga
    interior = capas.relay_pelar(rel[0], carga)
    assert secreto not in interior
    interior = capas.relay_pelar(rel[1], capas.rellenar(interior))
    assert secreto not in interior


@pytest.mark.parametrize("posicion", [0, 1, 2, 100, 300])
def test_bit_alterado_se_detecta(posicion):
    """STRIDE T: ataque de etiquetado."""
    cli, rel = circuito()
    carga = bytearray(capas.cliente_envolver(cli, plano()))
    carga[posicion] ^= 0x01
    with pytest.raises((CeldaManipulada, CeldaInvalida)):
        ida(cli, rel, bytes(carga))


def test_celda_repetida_se_detecta():
    """El nonce es un contador implícito: reenviar una celda vieja falla."""
    cli, rel = circuito(1)
    carga = capas.cliente_envolver(cli, plano())
    capas.relay_pelar(rel[0], carga)
    with pytest.raises(CeldaManipulada):
        capas.relay_pelar(rel[0], carga)


def test_celdas_reordenadas_se_detectan():
    cli, rel = circuito(1)
    c1 = capas.cliente_envolver(cli, plano(b"1"))
    c2 = capas.cliente_envolver(cli, plano(b"2"))
    with pytest.raises(CeldaManipulada):
        capas.relay_pelar(rel[0], c2)
    del c1


def test_mismo_mensaje_produce_cifrados_distintos():
    cli, _ = circuito(1)
    assert capas.cliente_envolver(cli, plano()) != capas.cliente_envolver(cli, plano())


def test_longitud_de_capa_absurda_se_rechaza():
    _, rel = circuito(1)
    for largo in (b"\x00\x00", b"\x00\x10", b"\xff\xff"):
        with pytest.raises(CeldaInvalida):
            capas.relay_pelar(rel[0], largo + os.urandom(TAM_CARGA - 2))


def test_cliente_rechaza_plano_de_tamano_incorrecto():
    cli, _ = circuito()
    with pytest.raises(CeldaInvalida):
        capas.cliente_envolver(cli, b"x" * (TAM_RELAY_PLANO - 1))


def test_claves_iguales_en_ambas_direcciones_se_rechazan():
    with pytest.raises(ValueError):
        capas.CapaSalto(b"\x01" * 32, b"\x01" * 32)
