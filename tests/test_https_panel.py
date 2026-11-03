"""HTTPS en las pruebas del panel («Abrir por MiniOni» y «Verificar sin registros»).

Un servidor TLS local con certificados de una autoridad de PRUEBA (que ni
OpenSSL ni Windows conocen) se alcanza por el circuito de 3 saltos:
- Sin la autoridad en el almacén, el sitio se rechaza con un mensaje claro y
  el servidor no recibe ni un byte de la petición (fallo cerrado), también
  cuando la verificación pasa a Windows por falta de la raíz local.
- Si Windows aprueba la cadena (simulado), la página llega por TLS.
"""

from __future__ import annotations

import asyncio
import datetime
import ipaddress
import json
import ssl
import sys

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from test_panel import correr, preparar
from test_red import PASS, laboratorio  # noqa: F401  (fixture compartida)

from minioni import confianza_windows
from minioni.errores import PruebaFallida


def _certificado(nombre, clave_publica, emisor, clave_emisor, ca: bool):
    ahora = datetime.datetime.now(datetime.timezone.utc)
    b = (x509.CertificateBuilder()
         .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, nombre)]))
         .issuer_name(emisor).public_key(clave_publica).serial_number(x509.random_serial_number())
         .not_valid_before(ahora - datetime.timedelta(minutes=5))
         .not_valid_after(ahora + datetime.timedelta(days=1))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if not ca:
        b = b.add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                            critical=False)
    return b.sign(clave_emisor, hashes.SHA256())


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    """Autoridad de prueba + certificado de 127.0.0.1 firmado por ella. Solo en memoria y en tmp."""
    d = tmp_path_factory.mktemp("pki")
    clave_ca = ec.generate_private_key(ec.SECP256R1())
    nombre_ca = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Autoridad de prueba MiniOni")])
    ca = _certificado("Autoridad de prueba MiniOni", clave_ca.public_key(), nombre_ca, clave_ca, True)
    clave = ec.generate_private_key(ec.SECP256R1())
    hoja = _certificado("127.0.0.1", clave.public_key(), nombre_ca, clave_ca, False)
    (d / "hoja.pem").write_bytes(hoja.public_bytes(serialization.Encoding.PEM))
    (d / "clave.pem").write_bytes(clave.private_bytes(serialization.Encoding.PEM,
                                                      serialization.PrivateFormat.PKCS8,
                                                      serialization.NoEncryption()))
    return d


class ServidorTLS:
    """HTTPS mínimo en 127.0.0.1 que envía SOLO su certificado (sin la autoridad)."""

    def __init__(self, pki):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(pki / "hoja.pem", pki / "clave.pem")
        self.peticiones = 0

    async def iniciar(self):
        self._srv = await asyncio.start_server(self._atender, "127.0.0.1", 0, ssl=self.ctx)
        self.puerto = self._srv.sockets[0].getsockname()[1]
        return self

    async def _atender(self, reader, writer):
        try:
            await reader.readuntil(b"\r\n\r\n")
            self.peticiones += 1
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\ncifrado")
            await writer.drain()
        except (ConnectionError, OSError, asyncio.IncompleteReadError, ssl.SSLError):
            pass
        finally:
            writer.close()


@pytest.fixture
def red_tls(tmp_path, laboratorio, pki):
    control = preparar(tmp_path, laboratorio)
    try:
        srv = correr(control, ServidorTLS(pki).iniciar())
        (control.config / "politica_salida.json").write_text(
            json.dumps({"puertos": [80, 443, srv.puerto], "excepciones_redes": ["127.0.0.0/8"]}),
            encoding="utf-8")
        correr(control, control.iniciar(PASS))
        yield control, srv
    finally:
        control.cerrar()


def test_sitio_con_autoridad_desconocida_se_rechaza_sin_enviar_la_peticion(red_tls):
    control, srv = red_tls
    with pytest.raises(PruebaFallida, match="no es de confianza"):
        correr(control, control.probar_url(f"https://127.0.0.1:{srv.puerto}/"))
    assert srv.peticiones == 0


def test_si_windows_aprueba_la_cadena_la_pagina_llega_por_tls(red_tls, monkeypatch):
    control, srv = red_tls
    vistos = []

    def aprobar(cadena, host):
        vistos.append((len(cadena), host))
        return True

    monkeypatch.setattr(confianza_windows, "disponible", lambda: True)
    monkeypatch.setattr(confianza_windows, "verificar_cadena", aprobar)
    codigo, total, _ = correr(control, control.probar_url(f"https://127.0.0.1:{srv.puerto}/"))
    assert codigo == 200 and total > 0 and srv.peticiones == 1
    assert vistos == [(1, "127.0.0.1")]   # Windows recibió la cadena del sitio y su nombre


def test_si_windows_rechaza_la_cadena_no_se_envia_nada(red_tls, monkeypatch):
    control, srv = red_tls
    monkeypatch.setattr(confianza_windows, "disponible", lambda: True)
    monkeypatch.setattr(confianza_windows, "verificar_cadena", lambda cadena, host: False)
    with pytest.raises(PruebaFallida, match="no es de confianza"):
        correr(control, control.probar_url(f"https://127.0.0.1:{srv.puerto}/"))
    assert srv.peticiones == 0


@pytest.mark.skipif(sys.platform != "win32", reason="verificador de Windows")
def test_el_verificador_de_windows_rechaza_una_autoridad_desconocida(pki):
    hoja = x509.load_pem_x509_certificate((pki / "hoja.pem").read_bytes())
    assert not confianza_windows.verificar_cadena([hoja.public_bytes(serialization.Encoding.DER)], "127.0.0.1")


@pytest.mark.parametrize("cadena, host", [([], "a.com"), ([b"basura"], "a.com"), ([b"x"] * 11, "a.com"),
                                          ([b"x" * 70000], "a.com"), ([b"x"], ""), (["texto"], "a.com")])
def test_el_verificador_rechaza_entradas_invalidas(cadena, host):
    assert confianza_windows.verificar_cadena(cadena, host) is False
