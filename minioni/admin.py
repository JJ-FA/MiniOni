"""Herramienta de administración de MiniOni.

Uso (desde la carpeta del proyecto):
    python minioni_admin.py generar-autoridad
    python minioni_admin.py generar-relay --apodo entrada1
    python minioni_admin.py publicar-directorio --version 1 --dias 7
    python minioni_admin.py verificar-directorio
    python minioni_admin.py donde-estan-las-claves
    python minioni_admin.py revisar-certificados
    python minioni_admin.py renovar-certificado --apodo salida1    (ver docs/ROTACION_CLAVES.md)

Las claves privadas van en 'claves' o, si está definida, en la carpeta de la
variable MINIONI_CLAVES (ruta absoluta, fuera de OneDrive). Ver almacen_claves.carpeta_claves.

`preparar-laboratorio` y `publicar-directorio` aceptan `--relays RUTA`
(por defecto config/relays.json, con las IP de Docker). Para correr los 3
relays en el mismo computador: --relays config/relays.local.json

Las contraseñas se piden con getpass (no se ven al escribir y no quedan en
el historial de la terminal).
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import re
import shutil
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.x509.oid import NameOID

from . import almacen_claves as ak
from . import consola
from . import directorio as dirmod
from .errores import ClaveInvalida, MiniOniError

CARPETA_CONFIG = Path("config")
_APODO = re.compile(r"^[A-Za-z0-9_-]{1,32}$")


MIN_CONTRASENA = 12


def _pedir_contrasena(confirmar: bool) -> str:
    c = getpass.getpass(f"Contraseña (mínimo {MIN_CONTRASENA} caracteres): ")
    if confirmar:
        if len(c) < MIN_CONTRASENA:
            raise SystemExit(f"Error: la contraseña debe tener al menos {MIN_CONTRASENA} caracteres "
                             f"(escribiste {len(c)}). No se creó nada.")
        motivo = ak.motivo_contrasena_debil(c)
        if motivo:
            raise SystemExit(f"Error: la contraseña {motivo}. Usa una frase fácil de recordar, "
                             "por ejemplo cuatro palabras. No se creó nada.")
        if getpass.getpass("Repite la contraseña: ") != c:
            raise SystemExit("Error: las contraseñas no coinciden. No se creó nada.")
    return c


# --- autoridad del directorio ---------------------------------------------------

def generar_autoridad(contrasena: str, claves: Path, config: Path, n: int = ak.N_SCRYPT) -> bytes:
    if (claves / "autoridad" / "autoridad.key").exists():
        raise SystemExit(
            "Error: ya existe una autoridad (claves/autoridad/autoridad.key) y no se sobrescribe.\n"
            "Si quieres empezar de cero, borra la carpeta 'claves' y el archivo 'config/autoridad.pub'."
        )
    privada = Ed25519PrivateKey.generate()
    ak.guardar_privada(claves / "autoridad" / "autoridad.key", privada.private_bytes_raw(),
                       "ed25519", contrasena, n)
    publica = privada.public_key().public_bytes_raw()
    ak.guardar_publica(config / "autoridad.pub", publica)
    return publica


# --- relays ------------------------------------------------------------------------

DIAS_CERTIFICADO = 90


def _certificado_tls(apodo: str, contrasena: str, carpeta: Path, n: int = ak.N_SCRYPT,
                     nombre_clave: str = "tls.key", nombre_crt: str = "tls.crt") -> str:
    """Certificado autofirmado ECDSA P-256. Devuelve su huella SHA-256 (hex).

    La clave privada NO se guarda como PEM cifrado de OpenSSL: ese formato usa
    PBKDF2 con solo 2048 iteraciones, muy por debajo de lo recomendado. Se guarda
    en el mismo contenedor scrypt que las demás claves (ver almacen_claves.py).
    """
    clave = ec.generate_private_key(ec.SECP256R1())
    nombre = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"minioni-{apodo}")])
    ahora = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(nombre)
        .issuer_name(nombre)
        .public_key(clave.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(ahora - timedelta(minutes=5))
        .not_valid_after(ahora + timedelta(days=DIAS_CERTIFICADO))
        .sign(clave, hashes.SHA256())
    )
    der_clave = clave.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    ak.guardar_privada(carpeta / nombre_clave, der_clave, "p256-pkcs8", contrasena, n)
    der = cert.public_bytes(serialization.Encoding.DER)
    (carpeta / nombre_crt).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return hashlib.sha256(der).hexdigest()


def huella_certificado(ruta_crt: Path) -> str:
    cert = x509.load_pem_x509_certificate(Path(ruta_crt).read_bytes())
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def generar_relay(apodo: str, contrasena: str, claves: Path, n: int = ak.N_SCRYPT) -> str:
    if not _APODO.fullmatch(apodo):
        raise SystemExit("Apodo inválido: usa letras, números, - o _ (máx. 32).")
    motivo = ak.motivo_contrasena_debil(contrasena)
    if motivo:
        raise SystemExit(f"Error: la contraseña {motivo}.")
    carpeta = claves / apodo
    if carpeta.exists() and any(carpeta.iterdir()):
        raise SystemExit(f"Error: ya existen claves para '{apodo}' y no se sobrescriben.")
    carpeta.mkdir(parents=True, exist_ok=True)   # una carpeta vacía de un intento fallido se reutiliza
    try:
        cebolla = X25519PrivateKey.generate()
        ak.guardar_privada(carpeta / "cebolla.key", cebolla.private_bytes_raw(), "x25519", contrasena, n)
        ak.guardar_publica(carpeta / "cebolla.pub", cebolla.public_key().public_bytes_raw())
        return _certificado_tls(apodo, contrasena, carpeta, n)
    except BaseException:
        # Si algo falla a mitad de camino no se deja un relay a medias.
        shutil.rmtree(carpeta, ignore_errors=True)
        raise


# --- rotación del certificado TLS (Clase 3, T6; docs/ROTACION_CLAVES.md) ----------

_TEMPORALES = (".tls.nuevo.key", ".tls.nuevo.crt")


def renovar_certificado(apodo: str, contrasena: str, claves: Path, n: int = ak.N_SCRYPT) -> str:
    """Nueva clave y certificado TLS (90 días) para un relay. Devuelve la huella nueva.

    - Antes de tocar nada, la contraseña debe abrir el tls.key actual: con una
      contraseña equivocada no cambia ningún archivo.
    - Lo nuevo se escribe en temporales de la misma carpeta y se reemplaza con
      os.replace (atómico dentro de un mismo disco).
    - La clave cebolla NO cambia: solo cambia la huella TLS, que va en el directorio.
    """
    if not _APODO.fullmatch(apodo):
        raise SystemExit("Apodo inválido: usa letras, números, - o _ (máx. 32).")
    carpeta = claves / apodo
    if not (carpeta / "tls.key").exists() or not (carpeta / "tls.crt").exists():
        raise SystemExit(f"Error: no hay certificado TLS para '{apodo}' en la carpeta de claves.")
    ak.cargar_privada(carpeta / "tls.key", contrasena, "p256-pkcs8")     # ClaveInvalida si no es la contraseña
    for nombre in _TEMPORALES:
        (carpeta / nombre).unlink(missing_ok=True)   # restos de un intento anterior interrumpido
    try:
        huella = _certificado_tls(apodo, contrasena, carpeta, n, *_TEMPORALES)
        os.replace(carpeta / _TEMPORALES[0], carpeta / "tls.key")
        os.replace(carpeta / _TEMPORALES[1], carpeta / "tls.crt")
    except BaseException:
        for nombre in _TEMPORALES:
            (carpeta / nombre).unlink(missing_ok=True)
        raise
    return huella


def revisar_certificados(claves: Path) -> list[tuple[str, int]]:
    """(apodo, días restantes) de cada relay con tls.crt en la carpeta de claves."""
    from .relay import dias_certificado
    if not claves.is_dir():
        return []
    return [(c.name, dias_certificado(c.name, claves)) for c in sorted(claves.iterdir())
            if c.is_dir() and _APODO.fullmatch(c.name) and (c / "tls.crt").exists()]


# --- directorio -----------------------------------------------------------------

def armar_directorio(lista_relays: list, claves: Path, version: int, dias: int) -> dict:
    if not 1 <= dias <= 30:
        raise SystemExit("La vigencia debe estar entre 1 y 30 días.")
    ahora = datetime.now(timezone.utc).replace(microsecond=0)
    relays = []
    for r in lista_relays:
        apodo = r.get("apodo", "") if isinstance(r, dict) else ""
        if not _APODO.fullmatch(apodo):
            raise SystemExit("relays.json contiene un apodo inválido.")
        carpeta = claves / apodo
        if not (carpeta / "cebolla.pub").exists() or not (carpeta / "tls.crt").exists():
            raise SystemExit(f"Error: falta generar el relay '{apodo}' "
                             f"(python minioni_admin.py generar-relay --apodo {apodo}).")
        relays.append({
            "apodo": apodo,
            "host": r.get("host"),
            "puerto": r.get("puerto"),
            "salida": r.get("salida"),
            "clave_cebolla": (carpeta / "cebolla.pub").read_text(encoding="ascii").strip(),
            "huella_tls": huella_certificado(carpeta / "tls.crt"),
        })
    return {
        "version": version,
        "publicado": dirmod.formato_fecha(ahora),
        "valido_hasta": dirmod.formato_fecha(ahora + timedelta(days=dias)),
        "relays": relays,
    }


def publicar_directorio(contrasena: str, claves: Path, config: Path, version: int, dias: int,
                        relays: Path | None = None) -> Path:
    if not (claves / "autoridad" / "autoridad.key").exists():
        raise SystemExit("Error: primero crea la autoridad (python minioni_admin.py generar-autoridad).")
    lista = json.loads(Path(relays or config / "relays.json").read_text(encoding="utf-8"))
    directorio = armar_directorio(lista, claves, version, dias)
    privada = ak.cargar_privada(claves / "autoridad" / "autoridad.key", contrasena, "ed25519")
    firmado = dirmod.firmar(directorio, Ed25519PrivateKey.from_private_bytes(privada))
    destino = config / "directorio.firmado.json"
    destino.write_bytes(firmado)
    return destino


# --- todo en un paso (laboratorio) -------------------------------------------

ARCHIVOS_GENERADOS = ("autoridad.pub", "directorio.firmado.json", "directorio.atacado.json")


def preparar_laboratorio(contrasena: str, claves: Path, config: Path, reiniciar: bool,
                         n: int = ak.N_SCRYPT, relays: Path | None = None) -> Path:
    """Crea autoridad, relays de `relays` (config/relays.json) y el directorio firmado con UNA contraseña.

    Con `reiniciar` borra antes solo lo que este mismo comando genera (claves/ y los
    archivos de config/ listados en ARCHIVOS_GENERADOS); los relays*.json nunca se tocan.
    """
    lista = json.loads(Path(relays or config / "relays.json").read_text(encoding="utf-8"))
    hay_claves = claves.exists() and any(claves.iterdir())
    if hay_claves and not reiniciar:
        raise SystemExit("Error: ya existen claves en 'claves'. Para borrarlas y crear todo de nuevo usa:\n"
                         "  python minioni_admin.py preparar-laboratorio --reiniciar")
    if reiniciar:
        shutil.rmtree(claves, ignore_errors=True)
        for nombre in ARCHIVOS_GENERADOS:
            (config / nombre).unlink(missing_ok=True)
        print("[1/4] Claves y directorio anteriores borrados")
    else:
        print("[1/4] No había claves anteriores")
    generar_autoridad(contrasena, claves, config, n)
    print("[2/4] Autoridad creada")
    for r in lista:
        generar_relay(r.get("apodo", "") if isinstance(r, dict) else "", contrasena, claves, n)
    print(f"[3/4] {len(lista)} relays creados")
    ruta = publicar_directorio(contrasena, claves, config, version=_version_siguiente(config), dias=7,
                               relays=relays)
    print(f"[4/4] Directorio firmado en {ruta.as_posix()}\n")
    servicio = ak.carpeta_sincronizada(claves)
    if servicio:
        print(f"Aviso: 'claves' está dentro de '{servicio}' y se sube a la nube. Van cifradas con scrypt,\n"
              "pero lo ideal es tenerlas en una carpeta local (ver: python minioni_admin.py "
              "donde-estan-las-claves).\n")
    return ruta


def _version_siguiente(config: Path) -> int:
    """Versión para un directorio nuevo: por encima de la más alta conocida en este equipo.

    Si se regeneran las claves con un directorio versión 1, el cliente que ya vio la 2
    lo rechazaría por anti-rollback (y hace bien). Se mira la última vista por el
    cliente (config/ultima_version) y la del directorio publicado; sin ninguna, 1.
    """
    from .proxy import leer_ultima_version
    vistas = [0]
    if (config / "ultima_version").exists():
        vistas.append(leer_ultima_version(config / "ultima_version"))
    try:
        version = json.loads((config / "directorio.firmado.json").read_text(encoding="utf-8"))["directorio"]["version"]
        if isinstance(version, int) and not isinstance(version, bool) and 1 <= version <= 2**31:
            vistas.append(version)
    except (OSError, ValueError, KeyError, TypeError):
        pass
    return max(vistas) + 1


# --- dónde están las claves (Clase 3, T1) -------------------------------------

def informe_claves(claves: Path) -> list[str]:
    """Líneas para `donde-estan-las-claves`: origen, nube y cuántos relays tienen claves."""
    if claves == ak.CARPETA_PREDETERMINADA:
        lineas = ["Carpeta de claves: la predeterminada ('claves' dentro del proyecto).",
                  f"  Para usar otra, define {ak.VARIABLE_CLAVES} (ver COMANDOS.txt)."]
    else:
        lineas = [f"Carpeta de claves: definida con {ak.VARIABLE_CLAVES}: {consola.texto_seguro(claves, 120)}"]
    servicio = ak.carpeta_sincronizada(claves)
    if servicio:
        lineas.append(f"Sincronización: está dentro de '{consola.texto_seguro(servicio, 40)}' y se sube a la nube.")
    else:
        lineas.append("Sincronización: no está en una carpeta sincronizada con la nube.")
    relays = []
    if claves.is_dir():
        relays = sorted(c.name for c in claves.iterdir()
                        if c.is_dir() and c.name != "autoridad" and (c / "cebolla.key").exists())
    lineas.append(f"Relays con claves: {len(relays)} relay{'' if len(relays) == 1 else 's'}"
                  + (f" ({', '.join(consola.texto_seguro(r, 32) for r in relays)})" if relays else ""))
    autoridad = (claves / "autoridad" / "autoridad.key").exists()
    lineas.append("Autoridad del directorio: " + ("presente" if autoridad else "no creada"))
    return lineas


# --- simulación de ataque (para demostraciones) -------------------------------

def simular_ataque(config: Path) -> tuple[str, int, int, Path]:
    """Copia el directorio firmado, cambia el puerto del primer relay y guarda la copia.

    El archivo original NUNCA se modifica: la copia va a config/directorio.atacado.json.
    Simula a alguien que intenta desviar el tráfico hacia su propio relay sin tener la
    clave de la autoridad (amenaza STRIDE S).
    """
    original = config / "directorio.firmado.json"
    doc = json.loads(original.read_text(encoding="utf-8"))
    relay = doc["directorio"]["relays"][0]
    antes = relay["puerto"]
    relay["puerto"] = antes + 4 if antes + 4 <= 65535 else antes - 4
    copia = config / "directorio.atacado.json"
    copia.write_text(json.dumps(doc, indent=2, ensure_ascii=True, sort_keys=True) + "\n", encoding="ascii")
    return relay["apodo"], antes, relay["puerto"], copia


def _verificar_e_imprimir(ruta_dir: Path, ruta_pub: Path) -> None:
    if not ruta_dir.exists():
        raise SystemExit(f"Error: no existe {consola.texto_seguro(ruta_dir.as_posix())}; "
                         "ejecuta primero publicar-directorio.")
    if ruta_dir.stat().st_size == 0:
        raise SystemExit(f"Error: {consola.texto_seguro(ruta_dir.as_posix())} está vacío; "
                         "vuelve a ejecutar publicar-directorio.")
    try:
        d = dirmod.verificar(ruta_dir.read_bytes(), ak.cargar_publica(ruta_pub))
    except MiniOniError:
        # Pista para el administrador (nunca para un cliente): si la autoridad es más
        # nueva que el directorio, lo más probable es que se regeneraron las claves
        # sin volver a publicar.
        if ruta_dir.name == "directorio.firmado.json" and ruta_pub.stat().st_mtime > ruta_dir.stat().st_mtime:
            print("Aviso: la autoridad (config/autoridad.pub) es más nueva que el directorio.\n"
                  "Si regeneraste las claves, vuelve a ejecutar publicar-directorio.", file=sys.stderr)
        raise
    print(f"Directorio válido: versión {d.version}, {len(d.relays)} relays, "
          f"vigente hasta {dirmod.formato_fecha(d.valido_hasta)}")
    for r in d.relays:
        print(f"  - {r.apodo:<12} puerto {r.puerto:<6} {'salida' if r.salida else 'relay'}")


# --- interfaz de línea de comandos -------------------------------------------

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="minioni_admin", description="Administración de MiniOni")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("generar-autoridad", help="crea la clave Ed25519 que firma el directorio")
    g = sub.add_parser("generar-relay", help="crea la clave cebolla y el certificado TLS de un relay")
    g.add_argument("--apodo", required=True)
    pub = sub.add_parser("publicar-directorio", help="arma y firma config/directorio.firmado.json")
    pub.add_argument("--version", type=int, required=True)
    pub.add_argument("--dias", type=int, default=7)
    pub.add_argument("--relays", default=str(CARPETA_CONFIG / "relays.json"),
                     help="lista de relays (por defecto config/relays.json; local: config/relays.local.json)")
    ver = sub.add_parser("verificar-directorio", help="comprueba firma, formato y vigencia")
    ver.add_argument("--archivo", default=str(CARPETA_CONFIG / "directorio.firmado.json"),
                     help="directorio a verificar (por defecto config/directorio.firmado.json)")
    lab = sub.add_parser("preparar-laboratorio",
                         help="crea autoridad, relays y directorio firmado en un solo paso (una contraseña)")
    lab.add_argument("--reiniciar", action="store_true",
                     help="borra antes las claves y el directorio generados")
    lab.add_argument("--relays", default=str(CARPETA_CONFIG / "relays.json"),
                     help="lista de relays (por defecto config/relays.json; local: config/relays.local.json)")
    sub.add_parser("simular-ataque",
                   help="crea una copia alterada del directorio (config/directorio.atacado.json) y la verifica")
    ren = sub.add_parser("renovar-certificado",
                         help="nueva clave y certificado TLS (90 días) para un relay; la clave cebolla no cambia")
    ren.add_argument("--apodo", required=True)
    sub.add_parser("revisar-certificados", help="días que le quedan al certificado TLS de cada relay")
    sub.add_parser("donde-estan-las-claves",
                   help="dice qué carpeta de claves se usa (MINIONI_CLAVES o la predeterminada) y si está en la nube")
    args = p.parse_args(argv)

    ruta_pub = CARPETA_CONFIG / "autoridad.pub"
    try:
        claves = ak.carpeta_claves()
        if args.cmd == "donde-estan-las-claves":
            print("\n".join(informe_claves(claves)))
        elif args.cmd == "generar-autoridad":
            generar_autoridad(_pedir_contrasena(True), claves, CARPETA_CONFIG)
            print("Autoridad creada. Pública: config/autoridad.pub  Privada: <carpeta de claves>/autoridad/")
        elif args.cmd == "generar-relay":
            huella = generar_relay(args.apodo, _pedir_contrasena(True), claves)
            print(f"Relay '{args.apodo}' creado. Huella TLS: {huella}")
        elif args.cmd == "publicar-directorio":
            for intento in range(1, 4):
                try:
                    ruta = publicar_directorio(_pedir_contrasena(False), claves, CARPETA_CONFIG,
                                               args.version, args.dias, Path(args.relays))
                    break
                except ClaveInvalida:
                    # Herramienta local del administrador: decir "contraseña incorrecta" no da
                    # ventaja a nadie remoto; el límite de 3 intentos evita bucles infinitos.
                    print(f"Contraseña incorrecta para la clave de la autoridad "
                          f"(intento {intento} de 3).", file=sys.stderr)
            else:
                raise SystemExit("Error: 3 intentos fallidos. Si olvidaste la contraseña, crea todo de "
                                 "nuevo con:\n  python minioni_admin.py preparar-laboratorio --reiniciar")
            print(f"Directorio firmado en {ruta.as_posix()}")
        elif args.cmd == "preparar-laboratorio":
            preparar_laboratorio(_pedir_contrasena(True), claves, CARPETA_CONFIG, args.reiniciar,
                                 relays=Path(args.relays))
            _verificar_e_imprimir(CARPETA_CONFIG / "directorio.firmado.json", ruta_pub)
            print("\nLaboratorio listo. Guarda la contraseña: la necesitarás para volver a publicar.")
        elif args.cmd == "renovar-certificado":
            huella = renovar_certificado(args.apodo, _pedir_contrasena(False), claves)
            print(f"Certificado TLS de '{args.apodo}' renovado ({DIAS_CERTIFICADO} días). Huella nueva: {huella}\n"
                  "La clave cebolla no cambió. Siguiente paso: publica el directorio con la versión siguiente\n"
                  f"  python minioni_admin.py publicar-directorio --version {_version_siguiente(CARPETA_CONFIG)}\n"
                  "Hasta entonces los clientes rechazan este relay (la huella no coincide con el directorio).")
        elif args.cmd == "revisar-certificados":
            lista = revisar_certificados(claves)
            if not lista:
                print("No hay certificados TLS en la carpeta de claves.")
            for apodo, dias in lista:
                estado = (f"VENCIDO hace {-dias} días" if dias < 0 else
                          f"vence en {dias} días" + ("  <- renuévalo pronto" if dias <= 15 else ""))
                print(f"  - {apodo:<12} {estado}")
            if any(dias < 0 for _, dias in lista):
                print("Hay certificados vencidos: python minioni_admin.py renovar-certificado --apodo APODO",
                      file=sys.stderr)
                return 1
        elif args.cmd == "verificar-directorio":
            _verificar_e_imprimir(Path(args.archivo), ruta_pub)
        elif args.cmd == "simular-ataque":
            print("1) Directorio original:")
            _verificar_e_imprimir(CARPETA_CONFIG / "directorio.firmado.json", ruta_pub)
            apodo, antes, despues, copia = simular_ataque(CARPETA_CONFIG)
            print(f"\n2) El atacante copia el directorio y cambia el puerto de '{apodo}': "
                  f"{antes} -> {despues}\n   (copia guardada en {copia.as_posix()}; el original no se toca)")
            print("\n3) Verificación de la copia alterada:")
            try:
                dirmod.verificar(copia.read_bytes(), ak.cargar_publica(ruta_pub))
            except MiniOniError as e:
                print(f"   RECHAZADO: {e.mensaje_publico}. La firma Ed25519 ya no coincide.")
            else:
                print("   ALERTA: la copia alterada fue aceptada. Esto no debería ocurrir.")
                return 1
    except MiniOniError as e:
        # Solo el mensaje genérico; nunca la traza (ASVS V16.5.1).
        print(f"Error: {e.mensaje_publico}", file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, IndexError, json.JSONDecodeError):
        print("Error: no se pudo completar la operación (revisa archivos y parámetros)", file=sys.stderr)
        return 1
    return 0
