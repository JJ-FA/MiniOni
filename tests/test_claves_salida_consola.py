"""Cifrado en reposo (ASVS V11.4.4), política de salida (STRIDE E) y consola sin datos sensibles (V16.2.5)."""

import io
import json
import os

import pytest

from minioni import almacen_claves as ak
from minioni import consola, politica_salida
from minioni.errores import ClaveInvalida, DestinoNoPermitido

N_PRUEBA = ak.N_SCRYPT_MINIMO   # más rápido en pruebas
CLAVE = os.urandom(32)
PASS = "una contraseña larga"


def test_clave_ida_y_vuelta(tmp_path):
    ak.guardar_privada(tmp_path / "k.key", CLAVE, "x25519", PASS, N_PRUEBA)
    assert ak.cargar_privada(tmp_path / "k.key", PASS, "x25519") == CLAVE


def test_clave_no_queda_en_claro(tmp_path):
    ak.guardar_privada(tmp_path / "k.key", CLAVE, "x25519", PASS, N_PRUEBA)
    contenido = (tmp_path / "k.key").read_bytes()
    assert CLAVE not in contenido and CLAVE.hex().encode() not in contenido


@pytest.mark.skipif(os.name == "nt", reason="Windows no usa permisos POSIX")
def test_permisos_600(tmp_path):
    ak.guardar_privada(tmp_path / "k.key", CLAVE, "x25519", PASS, N_PRUEBA)
    assert (tmp_path / "k.key").stat().st_mode & 0o777 == 0o600


def test_no_sobrescribe(tmp_path):
    ak.guardar_privada(tmp_path / "k.key", CLAVE, "x25519", PASS, N_PRUEBA)
    with pytest.raises(FileExistsError):
        ak.guardar_privada(tmp_path / "k.key", CLAVE, "x25519", PASS, N_PRUEBA)


def test_contrasena_incorrecta(tmp_path):
    ak.guardar_privada(tmp_path / "k.key", CLAVE, "x25519", PASS, N_PRUEBA)
    with pytest.raises(ClaveInvalida):
        ak.cargar_privada(tmp_path / "k.key", "otra contraseña", "x25519")


def test_tipo_cambiado_se_detecta(tmp_path):
    ak.guardar_privada(tmp_path / "k.key", CLAVE, "x25519", PASS, N_PRUEBA)
    with pytest.raises(ClaveInvalida):
        ak.cargar_privada(tmp_path / "k.key", PASS, "ed25519")


def test_kdf_debilitada_se_rechaza(tmp_path):
    ak.guardar_privada(tmp_path / "k.key", CLAVE, "x25519", PASS, N_PRUEBA)
    doc = json.loads((tmp_path / "k.key").read_text())
    doc["kdf"]["n"] = 2
    (tmp_path / "k.key").write_text(json.dumps(doc))
    with pytest.raises(ClaveInvalida):
        ak.cargar_privada(tmp_path / "k.key", PASS, "x25519")


def test_contrasena_corta_se_rechaza(tmp_path):
    with pytest.raises(ValueError):
        ak.guardar_privada(tmp_path / "k.key", CLAVE, "x25519", "corta", N_PRUEBA)


# --- política de salida ------------------------------------------------------------

@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.5", "172.16.3.4", "192.168.1.1", "169.254.169.254",
                                "0.0.0.0", "100.64.0.1", "224.0.0.1", "::1", "fe80::1", "fc00::1",
                                "::ffff:192.168.1.1", "255.255.255.255", "no-es-ip"])
def test_destinos_internos_bloqueados(ip):
    with pytest.raises(DestinoNoPermitido):
        politica_salida.verificar_ip_destino(ip)


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
def test_destinos_publicos_permitidos(ip):
    politica_salida.verificar_ip_destino(ip)


def test_excepcion_explicita_de_laboratorio():
    politica_salida.verificar_ip_destino("10.10.9.20", excepciones=("10.10.9.0/24",))
    with pytest.raises(DestinoNoPermitido):
        politica_salida.verificar_ip_destino("10.10.8.20", excepciones=("10.10.9.0/24",))


def test_puertos_de_salida():
    politica_salida.verificar_puerto_destino(443)
    with pytest.raises(DestinoNoPermitido):
        politica_salida.verificar_puerto_destino(22)


# --- consola ---------------------------------------------------------------------------

def test_consola_solo_imprime_catalogo():
    buf = io.StringIO()
    linea = consola.evento("relay-entrada", "CIRCUITO_CREADO", 3, salida=buf)
    assert linea.endswith("[relay-entrada] circuito creado (3)")
    assert linea[:20].endswith("Z")


def test_consola_no_acepta_texto_libre():
    buf = io.StringIO()
    linea = consola.evento("relay\n192.168.1.5", "visitó ejemplo.com desde 10.0.0.7", salida=buf)
    assert "192.168" not in linea and "ejemplo.com" not in linea and "10.0.0.7" not in linea
    assert "\n" not in linea
