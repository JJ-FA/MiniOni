"""Flujo completo de administración: autoridad, relays y directorio firmado."""

import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from minioni import admin
from minioni import almacen_claves as ak
from minioni import directorio as dirmod

N = ak.N_SCRYPT_MINIMO
PASS = "contraseña de laboratorio"
RELAYS = [
    {"apodo": "entrada1", "host": "10.10.1.10", "puerto": 9001, "salida": False},
    {"apodo": "medio1", "host": "10.10.2.10", "puerto": 9002, "salida": False},
    {"apodo": "salida1", "host": "10.10.3.10", "puerto": 9003, "salida": True},
]


@pytest.fixture
def entorno(tmp_path):
    claves, config = tmp_path / "claves", tmp_path / "config"
    config.mkdir()
    (config / "relays.json").write_text(json.dumps(RELAYS), encoding="utf-8")
    admin.generar_autoridad(PASS, claves, config, N)
    for r in RELAYS:
        admin.generar_relay(r["apodo"], PASS, claves, N)
    return claves, config


def test_flujo_completo(entorno):
    claves, config = entorno
    ruta = admin.publicar_directorio(PASS, claves, config, version=1, dias=7)
    d = dirmod.verificar(ruta.read_bytes(), ak.cargar_publica(config / "autoridad.pub"))
    assert [r.apodo for r in d.relays] == ["entrada1", "medio1", "salida1"]


def test_clave_tls_cifrada_con_scrypt_y_coincide_con_certificado(entorno):
    claves, _ = entorno
    contenido = (claves / "entrada1" / "tls.key").read_text(encoding="ascii")
    assert "scrypt" in contenido and "BEGIN" not in contenido   # no es PEM con PBKDF2 débil
    der = ak.cargar_privada(claves / "entrada1" / "tls.key", PASS, "p256-pkcs8")
    privada = serialization.load_der_private_key(der, password=None)
    cert = x509.load_pem_x509_certificate((claves / "entrada1" / "tls.crt").read_bytes())
    assert privada.public_key() == cert.public_key()


def test_contrasena_incorrecta_no_publica(entorno):
    claves, config = entorno
    with pytest.raises(Exception):
        admin.publicar_directorio("otra contraseña larga", claves, config, version=1, dias=7)
    assert not (config / "directorio.firmado.json").exists()


def test_no_sobrescribe_relay_existente(entorno):
    claves, _ = entorno
    with pytest.raises(SystemExit):
        admin.generar_relay("entrada1", PASS, claves, N)


@pytest.mark.parametrize("apodo", ["", "con espacio", "../salir", "a" * 33])
def test_apodo_invalido(tmp_path, apodo):
    with pytest.raises(SystemExit):
        admin.generar_relay(apodo, PASS, tmp_path, N)


def test_simular_ataque_no_toca_el_original_y_la_copia_se_rechaza(entorno, monkeypatch):
    claves, config = entorno
    original = admin.publicar_directorio(PASS, claves, config, version=1, dias=7)
    antes = original.read_bytes()
    apodo, p1, p2, copia = admin.simular_ataque(config)
    assert (apodo, p1, p2) == ("entrada1", 9001, 9005)
    assert original.read_bytes() == antes
    pub = ak.cargar_publica(config / "autoridad.pub")
    dirmod.verificar(original.read_bytes(), pub)
    with pytest.raises(dirmod.DirectorioInvalido):
        dirmod.verificar(copia.read_bytes(), pub)


def _config_con_relays(tmp_path):
    claves, config = tmp_path / "claves", tmp_path / "config"
    config.mkdir()
    (config / "relays.json").write_text(json.dumps(RELAYS), encoding="utf-8")
    return claves, config


def test_preparar_laboratorio_en_un_paso(tmp_path):
    claves, config = _config_con_relays(tmp_path)
    ruta = admin.preparar_laboratorio(PASS, claves, config, reiniciar=False, n=N)
    d = dirmod.verificar(ruta.read_bytes(), ak.cargar_publica(config / "autoridad.pub"))
    assert len(d.relays) == 3


def test_preparar_laboratorio_no_borra_sin_reiniciar(tmp_path):
    claves, config = _config_con_relays(tmp_path)
    admin.preparar_laboratorio(PASS, claves, config, reiniciar=False, n=N)
    antes = (config / "autoridad.pub").read_bytes()
    with pytest.raises(SystemExit):
        admin.preparar_laboratorio(PASS, claves, config, reiniciar=False, n=N)
    assert (config / "autoridad.pub").read_bytes() == antes


def test_preparar_laboratorio_reiniciar_crea_autoridad_nueva(tmp_path):
    claves, config = _config_con_relays(tmp_path)
    admin.preparar_laboratorio(PASS, claves, config, reiniciar=False, n=N)
    antes = (config / "autoridad.pub").read_bytes()
    ruta = admin.preparar_laboratorio("otra contraseña larga", claves, config, reiniciar=True, n=N)
    assert (config / "autoridad.pub").read_bytes() != antes
    assert (config / "relays.json").exists()
    dirmod.verificar(ruta.read_bytes(), ak.cargar_publica(config / "autoridad.pub"))
