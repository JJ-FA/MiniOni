"""T6 de la Clase 3: rotación del certificado TLS de un relay.

- transporte.dias_restantes con fechas fijas.
- El relay avisa CERTIFICADO_POR_VENCER al arrancar con 15 días o menos (no con 16).
- renovar-certificado cambia la huella TLS pero no la clave cebolla, y con una
  contraseña equivocada no toca ningún archivo.
- Un relay renovado con el directorio viejo se rechaza (fallo cerrado); con el
  directorio nuevo funciona. Ver docs/ROTACION_CLAVES.md (ASVS 5.0 V11.1.1, V12.3.4).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

from minioni import admin
from minioni import almacen_claves as ak
from minioni import consola, transporte
from minioni import directorio as dirmod
from minioni.errores import ClaveInvalida
from minioni.relay import DIAS_AVISO_CERTIFICADO, cargar_relay, verificar_identidad

PASS = "frase larga de prueba para rotar"
N = ak.N_SCRYPT_PRUEBAS
APODOS = ("entrada1", "medio1", "salida1")


def _der_que_vence(fin: datetime) -> bytes:
    clave = ec.generate_private_key(ec.SECP256R1())
    nombre = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "prueba")])
    cert = (x509.CertificateBuilder().subject_name(nombre).issuer_name(nombre).public_key(clave.public_key())
            .serial_number(1).not_valid_before(fin - timedelta(days=90)).not_valid_after(fin)
            .sign(clave, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER)


FIN = datetime(2026, 12, 31, 12, 0, tzinfo=timezone.utc)


@pytest.mark.parametrize("ahora, esperado", [
    (FIN - timedelta(days=30), 30),
    (FIN - timedelta(days=15, hours=1), 15),       # días completos: 15 y una hora -> 15
    (FIN - timedelta(hours=1), 0),
    (FIN + timedelta(days=2), -2),                 # vencido: negativo
])
def test_dias_restantes_con_fechas_fijas(ahora, esperado):
    assert transporte.dias_restantes(_der_que_vence(FIN), ahora) == esperado


def test_dias_restantes_rechaza_basura():
    with pytest.raises(Exception) as e:
        transporte.dias_restantes(b"no es un certificado")
    assert e.value.mensaje_publico


@pytest.fixture
def lab(tmp_path):
    claves = tmp_path / "claves"
    for apodo in APODOS:
        admin.generar_relay(apodo, PASS, claves, N)
    autoridad = Ed25519PrivateKey.generate()

    def directorio(version: int):
        lista = [{"apodo": a, "host": "127.0.0.1", "puerto": 9101 + i, "salida": a == "salida1"}
                 for i, a in enumerate(APODOS)]
        firmado = dirmod.firmar(admin.armar_directorio(lista, claves, version, 7), autoridad)
        return dirmod.verificar(firmado, autoridad.public_key().public_bytes_raw())
    return claves, directorio


def _eventos(nodo, dias):
    vistos = []
    baja = consola.suscribir(lambda componente, codigo, cantidad: vistos.append((codigo, cantidad)))
    try:
        nodo.dias_certificado = dias
        nodo.avisar_certificado()
    finally:
        baja()
    return vistos


def test_el_aviso_sale_con_15_dias_y_no_con_16(lab, capsys):
    claves, directorio = lab
    nodo = cargar_relay("medio1", directorio(1), claves, PASS)
    assert nodo.dias_certificado == 89                     # recién creado: 90 días menos unos minutos
    assert DIAS_AVISO_CERTIFICADO == 15
    assert _eventos(nodo, 16) == []
    assert _eventos(nodo, 15) == [("CERTIFICADO_POR_VENCER", 15)]
    assert "certificado TLS próximo a vencer (15)" in capsys.readouterr().err
    assert nodo.reiniciado().dias_certificado == 15        # al volver a encender lo sigue sabiendo


def test_renovar_cambia_la_huella_pero_no_la_clave_cebolla(lab):
    claves, _ = lab
    carpeta = claves / "salida1"
    cebolla_antes = (carpeta / "cebolla.key").read_bytes(), (carpeta / "cebolla.pub").read_bytes()
    huella_antes = admin.huella_certificado(carpeta / "tls.crt")
    huella = admin.renovar_certificado("salida1", PASS, claves, N)
    assert huella != huella_antes and huella == admin.huella_certificado(carpeta / "tls.crt")
    assert ((carpeta / "cebolla.key").read_bytes(), (carpeta / "cebolla.pub").read_bytes()) == cebolla_antes
    assert sorted(p.name for p in carpeta.iterdir()) == ["cebolla.key", "cebolla.pub", "tls.crt", "tls.key"]
    assert ak.cargar_privada(carpeta / "tls.key", PASS, "p256-pkcs8")     # la nueva sigue cifrada con scrypt


def test_contrasena_equivocada_no_toca_ningun_archivo(lab):
    claves, _ = lab
    carpeta = claves / "salida1"
    antes = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in carpeta.iterdir()}
    with pytest.raises(ClaveInvalida):
        admin.renovar_certificado("salida1", "otra frase larga equivocada", claves, N)
    assert {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in carpeta.iterdir()} == antes


def test_relay_renovado_con_directorio_viejo_se_rechaza_y_con_el_nuevo_funciona(lab):
    claves, directorio = lab
    viejo = directorio(1)
    admin.renovar_certificado("entrada1", PASS, claves, N)
    with pytest.raises(ClaveInvalida, match="certificado TLS no coincide"):
        verificar_identidad("entrada1", viejo, claves)       # fallo cerrado: no arranca
    nuevo = directorio(2)
    nodo = cargar_relay("entrada1", nuevo, claves, PASS)
    assert nodo.apodo == "entrada1" and nodo.propio.huella_tls == admin.huella_certificado(claves / "entrada1" / "tls.crt")


def test_renovar_desde_la_linea_de_comandos(lab, tmp_path, monkeypatch, capsys):
    claves, _ = lab
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(admin, "_pedir_contrasena", lambda confirmar: PASS)
    monkeypatch.setattr(admin.renovar_certificado, "__defaults__", (N,))
    assert admin.main(["renovar-certificado", "--apodo", "medio1"]) == 0
    salida = capsys.readouterr().out
    assert "Huella nueva" in salida and "publicar-directorio --version 1" in salida and PASS not in salida


def test_revisar_certificados_y_falla_si_alguno_vencio(lab, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert admin.main(["revisar-certificados"]) == 0
    assert capsys.readouterr().out.count("vence en 89 días") == 3
    monkeypatch.setattr(transporte, "dias_restantes", lambda der, ahora=None: -3)
    assert admin.main(["revisar-certificados"]) == 1
    salida = capsys.readouterr()
    assert "VENCIDO hace 3 días" in salida.out and "renovar-certificado" in salida.err


def test_la_version_siguiente_supera_a_la_vista_y_a_la_publicada(tmp_path):
    config = tmp_path / "config"
    config.mkdir()
    assert admin._version_siguiente(config) == 1
    (config / "ultima_version").write_text("2\n", encoding="ascii")
    assert admin._version_siguiente(config) == 3
    (config / "directorio.firmado.json").write_text('{"directorio": {"version": 5}}', encoding="utf-8")
    assert admin._version_siguiente(config) == 6
