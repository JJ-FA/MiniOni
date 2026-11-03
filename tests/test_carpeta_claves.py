"""T1 · Carpeta de claves configurable (MINIONI_CLAVES), fuera de la nube.

Cierra el fallo 9 de la Clase 3: las claves privadas, aunque cifradas, se
subían a OneDrive. Con MINIONI_CLAVES todos los programas usan otra carpeta;
una ruta relativa, un archivo o una carpeta sincronizada se rechazan sin
mostrar la ruta (ASVS 5.0 V13.3.1, V11.1.1; NIST SSDF PS.1.1).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from minioni import admin
from minioni import almacen_claves as ak
from minioni import directorio as dirmod
from minioni.errores import CarpetaClavesInvalida
from minioni.relay import verificar_identidad

PASS = "frase larga de prueba para las claves"


@pytest.fixture
def sin_nube(tmp_path, monkeypatch):
    """Una OneDrive simulada en una carpeta temporal; nada real del equipo."""
    nube = tmp_path / "nube"
    nube.mkdir()
    for variable in ("OneDrive", "OneDriveConsumer", "OneDriveCommercial"):
        monkeypatch.delenv(variable, raising=False)
    monkeypatch.setenv("OneDrive", str(nube))
    return nube


def test_sin_la_variable_se_usa_la_carpeta_de_siempre(monkeypatch):
    monkeypatch.delenv("MINIONI_CLAVES", raising=False)
    assert ak.carpeta_claves() == Path("claves")


def test_la_variable_vacia_equivale_a_no_definirla(monkeypatch):
    monkeypatch.setenv("MINIONI_CLAVES", "")
    assert ak.carpeta_claves() == Path("claves")


def test_una_carpeta_local_absoluta_se_acepta(tmp_path, sin_nube, monkeypatch):
    destino = tmp_path / "MiniOniClaves"
    monkeypatch.setenv("MINIONI_CLAVES", str(destino))
    assert ak.carpeta_claves() == destino.resolve()      # aún no existe: se creará al generar


@pytest.mark.parametrize("valor", ["claves_locales", "./claves", "..\\claves"])
def test_una_ruta_relativa_se_rechaza(valor, monkeypatch):
    monkeypatch.setenv("MINIONI_CLAVES", valor)
    with pytest.raises(CarpetaClavesInvalida, match="absoluta") as e:
        ak.carpeta_claves()
    assert valor not in e.value.mensaje_publico


def test_un_archivo_se_rechaza(tmp_path, sin_nube, monkeypatch):
    archivo = tmp_path / "no_soy_carpeta.txt"
    archivo.write_text("x", encoding="utf-8")
    monkeypatch.setenv("MINIONI_CLAVES", str(archivo))
    with pytest.raises(CarpetaClavesInvalida, match="no es una carpeta") as e:
        ak.carpeta_claves()
    assert str(tmp_path) not in e.value.mensaje_publico     # nunca la ruta completa


def test_una_carpeta_dentro_de_onedrive_se_rechaza(sin_nube, monkeypatch):
    monkeypatch.setenv("MINIONI_CLAVES", str(sin_nube / "claves"))
    with pytest.raises(CarpetaClavesInvalida, match="nube") as e:
        ak.carpeta_claves()
    assert str(sin_nube) not in e.value.mensaje_publico


def test_generar_relay_desde_la_linea_de_comandos_usa_la_variable(tmp_path, sin_nube, monkeypatch):
    destino = tmp_path / "MiniOniClaves"
    monkeypatch.setenv("MINIONI_CLAVES", str(destino))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(admin, "_pedir_contrasena", lambda confirmar: PASS)
    monkeypatch.setattr(ak, "N_SCRYPT", ak.N_SCRYPT_PRUEBAS)
    monkeypatch.setattr(admin.generar_relay, "__defaults__", (ak.N_SCRYPT_PRUEBAS,))
    assert admin.main(["generar-relay", "--apodo", "entrada1"]) == 0
    assert (destino / "entrada1" / "cebolla.key").exists()
    assert not (tmp_path / "claves").exists()               # nada en la carpeta de siempre


def test_verificar_identidad_con_la_carpeta_de_la_variable(tmp_path, sin_nube, monkeypatch):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    destino = tmp_path / "MiniOniClaves"
    monkeypatch.setenv("MINIONI_CLAVES", str(destino))
    claves = ak.carpeta_claves()
    lista = []
    for i, apodo in enumerate(("entrada1", "medio1", "salida1")):    # el directorio exige 3 relays
        admin.generar_relay(apodo, PASS, claves, ak.N_SCRYPT_PRUEBAS)
        lista.append({"apodo": apodo, "host": "127.0.0.1", "puerto": 9001 + i, "salida": apodo == "salida1"})
    autoridad = Ed25519PrivateKey.generate()
    d = dirmod.verificar(dirmod.firmar(admin.armar_directorio(lista, claves, 1, 7), autoridad),
                         autoridad.public_key().public_bytes_raw())
    assert verificar_identidad("entrada1", d, claves).apodo == "entrada1"


def test_donde_estan_las_claves_informa_sin_secretos(tmp_path, sin_nube, monkeypatch, capsys):
    destino = tmp_path / "MiniOniClaves"
    monkeypatch.setenv("MINIONI_CLAVES", str(destino))
    admin.generar_relay("medio1", PASS, ak.carpeta_claves(), ak.N_SCRYPT_PRUEBAS)
    assert admin.main(["donde-estan-las-claves"]) == 0
    salida = capsys.readouterr().out
    assert "MINIONI_CLAVES" in salida and "1 relay" in salida and "no está en una carpeta" in salida
    assert PASS not in salida and "cifrado" not in salida


def test_donde_estan_las_claves_con_la_carpeta_de_siempre_en_onedrive(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("MINIONI_CLAVES", raising=False)
    nube = tmp_path / "OneDrive" / "MiniOni"
    nube.mkdir(parents=True)
    monkeypatch.chdir(nube)
    assert admin.main(["donde-estan-las-claves"]) == 0
    salida = capsys.readouterr().out
    assert "predeterminada" in salida and "OneDrive" in salida and "0 relays" in salida


def test_donde_estan_las_claves_con_una_variable_invalida(monkeypatch, capsys):
    monkeypatch.setenv("MINIONI_CLAVES", "relativa")
    assert admin.main(["donde-estan-las-claves"]) == 1
    assert "absoluta" in capsys.readouterr().err


def test_revisar_secretos_mira_la_carpeta_de_la_variable(tmp_path, sin_nube, monkeypatch, capsys):
    pytest.importorskip("detect_secrets")
    import revisar_secretos
    proyecto = tmp_path / "proyecto"
    proyecto.mkdir()
    (proyecto / ".gitignore").write_text("claves/\n*.key\n", encoding="utf-8")
    monkeypatch.setattr(revisar_secretos, "RAIZ", proyecto)
    destino = tmp_path / "MiniOniClaves"
    monkeypatch.setenv("MINIONI_CLAVES", str(destino))
    (destino / "salida1").mkdir(parents=True)
    (destino / "salida1" / "olvidada.key").write_text('{"formato": "otro"}', encoding="ascii")
    assert revisar_secretos.main() == 1          # la clave sin cifrar está en la carpeta de la variable
    salida = capsys.readouterr().out
    assert "olvidada.key" in salida and "no está en una carpeta sincronizada" in salida


def test_revisar_secretos_avisa_si_la_variable_es_invalida(tmp_path, sin_nube, monkeypatch, capsys):
    pytest.importorskip("detect_secrets")
    import revisar_secretos
    (tmp_path / ".gitignore").write_text("claves/\n*.key\n", encoding="utf-8")
    monkeypatch.setattr(revisar_secretos, "RAIZ", tmp_path)
    monkeypatch.setenv("MINIONI_CLAVES", str(sin_nube / "claves"))
    assert revisar_secretos.main() == 1
    assert "MINIONI_CLAVES no válida" in capsys.readouterr().out
