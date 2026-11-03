"""R3 · ASVS V11.6.1: directorio firmado; STRIDE S y R."""

import base64
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from minioni import directorio as d
from minioni.errores import DirectorioInvalido

AHORA = datetime(2026, 10, 22, 12, 0, 0, tzinfo=timezone.utc)


def relay(apodo, puerto, salida=False):
    return {
        "apodo": apodo, "host": "10.10.1.10", "puerto": puerto, "salida": salida,
        "clave_cebolla": base64.b64encode(apodo.encode().ljust(32, b"_")).decode(),
        "huella_tls": "ab" * 32,
    }


def base(version=1):
    return {
        "version": version,
        "publicado": d.formato_fecha(AHORA - timedelta(hours=1)),
        "valido_hasta": d.formato_fecha(AHORA + timedelta(days=7)),
        "relays": [relay("entrada1", 9001), relay("medio1", 9002), relay("salida1", 9003, True)],
    }


@pytest.fixture
def autoridad():
    k = Ed25519PrivateKey.generate()
    return k, k.public_key().public_bytes_raw()


def test_directorio_valido(autoridad):
    k, pub = autoridad
    dirx = d.verificar(d.firmar(base(), k), pub, AHORA)
    assert [r.apodo for r in dirx.relays] == ["entrada1", "medio1", "salida1"]
    assert dirx.buscar("10.10.1.10", 9003).salida


def test_relay_insertado_despues_de_firmar_se_detecta(autoridad):
    """STRIDE S: el atacante agrega su propio nodo al archivo."""
    k, pub = autoridad
    doc = json.loads(d.firmar(base(), k))
    doc["directorio"]["relays"].append(relay("malo", 9666, True))
    with pytest.raises(DirectorioInvalido):
        d.verificar(json.dumps(doc).encode(), pub, AHORA)


def test_cambio_de_puerto_se_detecta(autoridad):
    k, pub = autoridad
    doc = json.loads(d.firmar(base(), k))
    doc["directorio"]["relays"][0]["puerto"] = 9999
    with pytest.raises(DirectorioInvalido):
        d.verificar(json.dumps(doc).encode(), pub, AHORA)


def test_firma_de_otra_autoridad_se_rechaza(autoridad):
    _, pub = autoridad
    otro = Ed25519PrivateKey.generate()
    with pytest.raises(DirectorioInvalido):
        d.verificar(d.firmar(base(), otro), pub, AHORA)


def test_directorio_vencido_se_rechaza(autoridad):
    k, pub = autoridad
    with pytest.raises(DirectorioInvalido):
        d.verificar(d.firmar(base(), k), pub, AHORA + timedelta(days=8))


def test_version_vieja_se_rechaza(autoridad):
    """Anti-rollback: no se acepta una versión anterior a la ya vista."""
    k, pub = autoridad
    with pytest.raises(DirectorioInvalido):
        d.verificar(d.firmar(base(version=3), k), pub, AHORA, version_minima=4)


def test_claves_json_duplicadas_se_rechazan(autoridad):
    k, pub = autoridad
    texto = d.firmar(base(), k).decode()
    texto = texto.replace('"firma":', '"firma": "AAAA", "firma":', 1)
    with pytest.raises(DirectorioInvalido):
        d.verificar(texto.encode(), pub, AHORA)


@pytest.mark.parametrize("cambio", [
    lambda x: x.update(extra=1),
    lambda x: x.update(version=0),
    lambda x: x.update(version=True),
    lambda x: x.update(publicado="ayer"),
    lambda x: x.update(relays=x["relays"][:2]),
    lambda x: x["relays"][1].update(apodo="entrada1"),
    lambda x: x["relays"][1].update(puerto=9001),
    lambda x: x["relays"][2].update(salida=False),
    lambda x: x["relays"][0].update(host="mal host"),
    lambda x: x["relays"][0].update(huella_tls="xyz"),
    lambda x: x["relays"][0].update(clave_cebolla="corta=="),
    lambda x: x["relays"][0].update(salida="si"),
    lambda x: x["relays"][0].update(sobra=1),
])
def test_estructuras_invalidas_no_se_pueden_firmar(autoridad, cambio):
    k, _ = autoridad
    doc = base()
    cambio(doc)
    with pytest.raises(DirectorioInvalido):
        d.firmar(doc, k)


@pytest.mark.parametrize("contenido", [b"", b"no json", b"[]", b'{"directorio":{}}', b"\xff\xfe",
                                       b"[" * 100000],
                         # Nombres cortos: sin ellos pytest usa el contenido completo como nombre de
                         # la prueba y en Windows supera el límite de 32767 caracteres de una variable de entorno.
                         ids=["vacio", "texto", "lista", "incompleto", "binario", "anidado_profundo"])
def test_archivos_basura_se_rechazan(autoridad, contenido):
    _, pub = autoridad
    with pytest.raises(DirectorioInvalido):
        d.verificar(contenido, pub, AHORA)
