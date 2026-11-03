"""Clase 3 · Codificación segura: pruebas de los cuatro controles fundamentales.

1. Validación de entradas en la línea de comandos (ASVS 5.0 V2.2.1).
2. Errores sin trazas: manejador de último recurso del proceso y del panel (V16.5.1, V16.5.4).
3. Cifrado: regla automática contra algoritmos y configuraciones débiles (V11.3.2, V11.4.1, V12.1.1).
4. Secretos: detección de secretos y claves sin cifrar, carpetas en la nube (NIST SSDF PS.1).
"""

import argparse
import json
import re
import sys
import threading
from pathlib import Path

import pytest

import cliente_proxy
from minioni import almacen_claves as ak
from minioni import consola
from minioni.proxy import argumento_puerto

RAIZ = Path(__file__).resolve().parent.parent
CODIGO = sorted([*RAIZ.glob("*.py"), *(RAIZ / "minioni").glob("*.py")])


# --- 1. Validación ---------------------------------------------------------------

@pytest.mark.parametrize("texto", ["0", "-1", "65536", "70000", "abc", "", "9050.5", "0x2352"])
def test_puerto_invalido_en_linea_de_comandos(texto):
    with pytest.raises(argparse.ArgumentTypeError):
        argumento_puerto(texto)


@pytest.mark.parametrize("texto,valor", [("1", 1), ("9050", 9050), ("65535", 65535)])
def test_puerto_valido_en_linea_de_comandos(texto, valor):
    assert argumento_puerto(texto) == valor


def test_cliente_proxy_rechaza_puerto_0_antes_de_arrancar(capsys):
    """Antes se aceptaba y el proxy escuchaba en un puerto al azar."""
    with pytest.raises(SystemExit) as salida:
        cliente_proxy.main(["--puerto", "0"])
    assert salida.value.code == 2
    assert "65535" in capsys.readouterr().err


# --- 2. Errores y logging --------------------------------------------------------

@pytest.fixture
def ganchos_originales():
    antes = (sys.excepthook, threading.excepthook)
    yield
    sys.excepthook, threading.excepthook = antes


def test_excepcion_no_prevista_no_muestra_traza(capsys, ganchos_originales):
    consola.instalar_manejador_global("relay")
    try:
        raise ValueError(r"detalle interno C:\Users\x\minioni\relay.py 10.0.0.7")
    except ValueError:
        sys.excepthook(*sys.exc_info())
    err = capsys.readouterr().err
    assert "[relay] error interno" in err
    for fuga in ("Traceback", "relay.py", "10.0.0.7", "ValueError", "detalle"):
        assert fuga not in err


def test_excepcion_en_un_hilo_no_muestra_traza(capsys, ganchos_originales):
    consola.instalar_manejador_global("proxy")

    def falla():
        raise RuntimeError("secreto del hilo")
    hilo = threading.Thread(target=falla)
    hilo.start()
    hilo.join()
    err = capsys.readouterr().err
    assert "[proxy] error interno" in err and "secreto" not in err and "Traceback" not in err


def test_ctrl_c_cierra_en_silencio(capsys, ganchos_originales):
    consola.instalar_manejador_global("relay")
    sys.excepthook(KeyboardInterrupt, KeyboardInterrupt(), None)
    assert capsys.readouterr().err == ""


def test_error_en_un_boton_del_panel_es_generico(capsys):
    """Tk imprimiría 'Exception in Tkinter callback' con la traza completa."""
    panel = pytest.importorskip("panel", reason="tkinter no está instalado")
    mostrado = {}

    class Etiqueta:
        def configure(self, **kw):
            mostrado.update(kw)

    class PanelFalso:
        info = Etiqueta()

        def _ocupar(self, si, texto=""):
            mostrado["ocupado"] = si

    panel.Panel.error_inesperado(PanelFalso(), ZeroDivisionError, ZeroDivisionError("x/0 en panel.py"), None)
    err = capsys.readouterr().err
    assert mostrado["text"] == "Error interno." and mostrado["ocupado"] is False
    assert "[panel] error interno" in err and "panel.py" not in err and "Traceback" not in err


# --- 3. Cifrado: regla automática sobre el código ------------------------------------

PROHIBIDOS = {
    r"\bhashlib\.(md5|sha1)\b|\bmd5\(|\bsha1\(": "hash débil (MD5/SHA-1)",
    r"verify\s*=\s*False": "verificación de certificados desactivada",
    r"_create_unverified_context": "contexto TLS sin verificación",
    r"PROTOCOL_(SSLv2|SSLv3|TLSv1(_1)?)\b|TLSVersion\.(SSLv3|TLSv1|TLSv1_1)\b": "versión de TLS obsoleta",
    r"^\s*(import random|from random import)": "aleatorio no criptográfico",
    r"\bpickle\b|\beval\(|\bexec\(": "deserialización o ejecución dinámica",
    r"shell\s*=\s*True": "subproceso con shell",
    r"\bDES\b|\bARC4\b|\bBlowfish\b|modes\.ECB": "cifrado obsoleto",
}


def _lineas_de_codigo():
    for archivo in CODIGO:
        for n, linea in enumerate(archivo.read_text(encoding="utf-8").splitlines(), 1):
            if not linea.lstrip().startswith("#"):
                yield archivo, n, linea


def test_sin_algoritmos_ni_configuraciones_debiles():
    encontrados = [f"{a.name}:{n} {motivo}" for a, n, linea in _lineas_de_codigo()
                   for patron, motivo in PROHIBIDOS.items() if re.search(patron, linea)]
    assert encontrados == []


def test_cert_none_solo_donde_hay_verificacion_propia_documentada():
    """CERT_NONE equivale a verify=False salvo que el código verifique después por su cuenta.

    Solo se permite en los dos lugares auditados: el pinning de relays (transporte.py) y la
    verificación con Windows del panel (control_red.py), cada uno con su justificación.
    """
    usos = [(a.name, linea) for a, _, linea in _lineas_de_codigo() if "CERT_NONE" in linea]
    assert sorted(nombre for nombre, _ in usos) == ["control_red.py", "transporte.py"]
    assert all("#" in linea for _, linea in usos), "cada uso debe llevar su justificación"


# Caracteres de control de dirección Unicode (ataque "Trojan Source", CVE-2021-42574):
# hacen que el código se lea distinto de como se ejecuta. Se construyen con chr() para
# que esta misma prueba no los contenga.
_BIDI = {chr(c) for c in (0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A))}


def test_ningun_archivo_contiene_caracteres_bidi_ocultos():
    """Incluye tests/: Bandit los excluye y por eso no vio uno real (hallazgo de la Clase 3)."""
    archivos = [*CODIGO, *sorted((RAIZ / "tests").glob("*.py"))]
    encontrados = [f"{a.relative_to(RAIZ).as_posix()}:{n}" for a in archivos
                   for n, linea in enumerate(a.read_text(encoding="utf-8").splitlines(), 1)
                   if _BIDI & set(linea)]
    assert encontrados == []


def test_tls_entre_nodos_es_solo_1_3():
    texto = (RAIZ / "minioni" / "transporte.py").read_text(encoding="utf-8")
    assert "minimum_version = ssl.TLSVersion.TLSv1_3" in texto
    assert "maximum_version = ssl.TLSVersion.TLSv1_3" in texto


def test_claves_en_disco_usan_kdf_lenta():
    assert ak.N_SCRYPT >= 2**17 and ak.R_SCRYPT == 8 and ak.P_SCRYPT == 1


# --- 4. Secretos -----------------------------------------------------------------------

@pytest.mark.parametrize("ruta", [r"C:\Users\Ana\OneDrive\Desktop\MiniOni\claves",
                                  "/home/ana/Dropbox/MiniOni/claves",
                                  "/Users/ana/Google Drive/MiniOni/claves"])
def test_detecta_carpetas_que_suben_a_la_nube(ruta, monkeypatch):
    for v in ("OneDrive", "OneDriveConsumer", "OneDriveCommercial"):
        monkeypatch.delenv(v, raising=False)
    assert ak.carpeta_sincronizada(Path(ruta)) is not None


def test_carpeta_local_no_se_marca(tmp_path, monkeypatch):
    for v in ("OneDrive", "OneDriveConsumer", "OneDriveCommercial"):
        monkeypatch.delenv(v, raising=False)
    assert ak.carpeta_sincronizada(tmp_path / "claves") is None


def test_variable_de_entorno_de_onedrive(tmp_path, monkeypatch):
    monkeypatch.setenv("OneDrive", str(tmp_path))
    assert ak.carpeta_sincronizada(tmp_path / "proyecto" / "claves") == "OneDrive"


@pytest.fixture
def proyecto_falso(tmp_path, monkeypatch):
    import revisar_secretos
    monkeypatch.setattr(revisar_secretos, "RAIZ", tmp_path)
    (tmp_path / ".gitignore").write_text("claves/\n*.key\n", encoding="utf-8")
    (tmp_path / "programa.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "claves").mkdir()
    return revisar_secretos, tmp_path


def test_revision_de_secretos_limpia(proyecto_falso):
    pytest.importorskip("detect_secrets")
    rs, raiz = proyecto_falso
    ak.guardar_privada(raiz / "claves" / "a.key", bytes(32), "x25519", "contraseña de prueba", ak.N_SCRYPT_MINIMO)
    assert rs.main() == 0


def test_revision_de_secretos_detecta_token_en_el_codigo(proyecto_falso, capsys):
    pytest.importorskip("detect_secrets")
    rs, raiz = proyecto_falso
    # El token falso se arma por partes: escrito completo, el escáner marcaría esta prueba.
    falso = "sk_" + "live_" + "0123456789" * 3
    (raiz / "config.py").write_text(f'API_KEY = "{falso}"\n', encoding="utf-8")
    assert rs.main() == 1
    salida = capsys.readouterr().out
    assert "config.py:1" in salida and "sk_live" not in salida   # nunca imprime el secreto


def test_revision_de_secretos_detecta_clave_sin_cifrar(proyecto_falso, capsys):
    pytest.importorskip("detect_secrets")
    rs, raiz = proyecto_falso
    (raiz / "claves" / "olvidada.key").write_text(json.dumps({"formato": "otro"}), encoding="ascii")
    assert rs.main() == 1
    assert "olvidada.key" in capsys.readouterr().out


def test_revision_de_secretos_exige_gitignore(proyecto_falso, capsys):
    pytest.importorskip("detect_secrets")
    rs, raiz = proyecto_falso
    (raiz / ".gitignore").write_text("__pycache__/\n", encoding="utf-8")
    assert rs.main() == 1
    assert "FALTA en .gitignore: claves/" in capsys.readouterr().out


# --- Hallazgos adicionales de la Clase 3 ---------------------------------------------

import datetime as _dt

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import ejecutar_relay
from minioni import admin, celdas, transporte
from minioni.errores import CertificadoVencido, ClaveInvalida, DestinoNoPermitido


@pytest.mark.parametrize("host", ["ejemplo.com\n", "127.0.0.1\n", "a\n.com", "ejemplo.com\r\n"])
def test_salto_de_linea_al_final_ya_no_pasa_la_validacion(host):
    """Con re.match, el "$" de Python aceptaba un \\n final: "ejemplo.com\\n" era válido."""
    with pytest.raises(DestinoNoPermitido):
        celdas.validar_host(host)


def test_apodo_con_salto_de_linea_se_rechaza_al_generar(tmp_path):
    with pytest.raises(SystemExit):
        admin.generar_relay("entrada1\n", "contraseña de laboratorio", tmp_path, ak.N_SCRYPT_PRUEBAS)


def test_apodo_con_secuencias_de_escape_no_llega_a_la_consola(capsys):
    """Antes: 'Error: las claves de 'x<ESC>[2J<salto>FALSO: relay comprometido'..."""
    assert ejecutar_relay.main(["--apodo", "x\x1b[2J\nFALSO: relay comprometido"]) == 1
    err = capsys.readouterr().err
    assert "\x1b" not in err and "FALSO" not in err and "apodo inválido" in err


def test_texto_seguro_neutraliza_controles():
    assert consola.texto_seguro("a\x1b[2J\nb\u202ec") == "a?[2J?b?c"
    assert len(consola.texto_seguro("x" * 500)) == 80


def _certificado(dias_antes: int, dias_despues: int) -> bytes:
    clave = ec.generate_private_key(ec.SECP256R1())
    nombre = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "prueba")])
    ahora = _dt.datetime.now(_dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(nombre).issuer_name(nombre)
            .public_key(clave.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(ahora + _dt.timedelta(days=dias_antes))
            .not_valid_after(ahora + _dt.timedelta(days=dias_despues))
            .sign(clave, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER)


def test_certificado_vigente_se_acepta():
    transporte.verificar_vigencia(_certificado(-1, 89))


@pytest.mark.parametrize("antes,despues", [(-100, -10), (5, 95)])
def test_certificado_vencido_o_futuro_se_rechaza(antes, despues):
    """Con pinning (CERT_NONE) OpenSSL no mira fechas: antes un certificado vencido seguía sirviendo."""
    with pytest.raises(CertificadoVencido):
        transporte.verificar_vigencia(_certificado(antes, despues))


def test_en_uso_normal_no_se_acepta_scrypt_debil(tmp_path, monkeypatch):
    ak.guardar_privada(tmp_path / "k.key", bytes(32), "x25519", "contraseña de laboratorio", ak.N_SCRYPT_PRUEBAS)
    monkeypatch.setattr(ak, "minimo_aceptado", ak.N_SCRYPT)   # el valor real del programa
    with pytest.raises(ClaveInvalida):
        ak.cargar_privada(tmp_path / "k.key", "contraseña de laboratorio", "x25519")
    with pytest.raises(ValueError):
        ak.guardar_privada(tmp_path / "otra.key", bytes(32), "x25519", "contraseña de laboratorio",
                           ak.N_SCRYPT_PRUEBAS)


@pytest.mark.parametrize("contrasena", ["aaaaaaaaaaaa", "123456789012", "contraseña2026", "Password1234!",
                                        "qwertyuiopas", "zxcvbnmzxcvb", "1234567890qw", "abababababab"])
def test_contrasenas_debiles_se_rechazan(contrasena, tmp_path):
    assert ak.motivo_contrasena_debil(contrasena) is not None
    with pytest.raises(ValueError):
        ak.guardar_privada(tmp_path / "k.key", bytes(32), "x25519", contrasena, ak.N_SCRYPT_PRUEBAS)


@pytest.mark.parametrize("contrasena", ["mi red cebolla 2026", "Tres tigres comen trigo", "contraseña de laboratorio"])
def test_frases_largas_se_aceptan(contrasena):
    assert ak.motivo_contrasena_debil(contrasena) is None


def test_salidas_de_diagnostico_no_van_al_repositorio_y_hay_hook():
    gitignore = (RAIZ / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert "errores.txt" in gitignore and "pytest.txt" in gitignore
    hook = (RAIZ / "hooks" / "pre-commit").read_text(encoding="utf-8")
    assert "revisar_secretos.py" in hook and "exit 1" in hook
