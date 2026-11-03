"""Arranca un relay de MiniOni.

Uso (desde la carpeta del proyecto, una ventana de PowerShell por relay):
    python ejecutar_relay.py --apodo entrada1
    python ejecutar_relay.py --apodo medio1
    python ejecutar_relay.py --apodo salida1

1. Verifica el directorio con config/autoridad.pub (si falla, termina con código 1).
2. Comprueba que cebolla.pub y la huella de tls.crt coinciden con el directorio.
3. Pide la contraseña UNA vez y descifra cebolla.key y tls.key.
4. Escucha en el host:puerto que dice el directorio (TLS 1.3).
   Si es nodo de salida, aplica config/politica_salida.json (puertos y
   excepciones de red; si no existe, solo 80 y 443 hacia IP públicas).
5. Ctrl+C: apagado limpio (destruye los circuitos).

La consola solo muestra eventos del catálogo de minioni/consola.py: nunca
IP, puertos de clientes, destinos ni contenido (ASVS V16.2.5).
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import ipaddress
import re
import sys
from pathlib import Path

from minioni import almacen_claves as ak
from minioni import consola
from minioni import directorio as dirmod
from minioni.errores import CertificadoVencido, ClaveInvalida, MiniOniError
from minioni.politica_salida import cargar_politica
from minioni.relay import cargar_relay, verificar_identidad

APODO_VALIDO = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
CARPETA_CONFIG = Path("config")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="ejecutar_relay", description="Relay de MiniOni")
    p.add_argument("--apodo", required=True)
    p.add_argument("--directorio", default=str(CARPETA_CONFIG / "directorio.firmado.json"))
    p.add_argument("--escuchar", default=None,
                   help="IP local donde escuchar (solo para Docker, semana 4); por defecto la del directorio")
    p.add_argument("--politica", default=str(CARPETA_CONFIG / "politica_salida.json"),
                   help="política del nodo de salida (por defecto config/politica_salida.json)")
    args = p.parse_args(argv)

    # Lista blanca, la misma del directorio (ASVS 5.0 V2.2.1). Antes el apodo se repetía
    # tal cual en el mensaje de error: un apodo con ESC o saltos de línea podía borrar la
    # pantalla o fabricar líneas falsas en la consola.
    if not APODO_VALIDO.fullmatch(args.apodo):
        print("Error: apodo inválido (letras, números, - o _; máximo 32).", file=sys.stderr)
        return 1

    try:
        d = dirmod.verificar(Path(args.directorio).read_bytes(), ak.cargar_publica(CARPETA_CONFIG / "autoridad.pub"))
    except (MiniOniError, OSError):
        consola.evento("relay", "DIRECTORIO_INVALIDO")
        return 1
    consola.evento("relay", "DIRECTORIO_OK")

    if args.escuchar is not None:
        try:
            args.escuchar = str(ipaddress.ip_address(args.escuchar))
        except ValueError:
            print("Error: --escuchar debe ser una dirección IP.", file=sys.stderr)
            return 1

    try:
        politica = cargar_politica(Path(args.politica))
    except MiniOniError as e:
        print(f"Error: {e.mensaje_publico} ({consola.texto_seguro(args.politica)}).", file=sys.stderr)
        return 1

    try:
        claves = ak.carpeta_claves()
    except MiniOniError as e:
        print(f"Error: {e.mensaje_publico}", file=sys.stderr)
        return 1

    try:
        verificar_identidad(args.apodo, d, claves)
    except CertificadoVencido as e:
        print(f"Error: {e.mensaje_publico}. Regenera las claves "
              "(python minioni_admin.py preparar-laboratorio --reiniciar).", file=sys.stderr)
        return 1
    except (MiniOniError, OSError):
        # Consola local del administrador: no da información a nadie remoto.
        print(f"Error: las claves de '{args.apodo}' no coinciden con el directorio o el relay no está en él.\n"
              "Vuelve a publicar el directorio (python minioni_admin.py publicar-directorio ...).",
              file=sys.stderr)
        return 1

    try:
        nodo = cargar_relay(args.apodo, d, claves, getpass.getpass("Contraseña de las claves: "),
                            politica=politica)
    except ClaveInvalida as e:
        print(f"Error: {e.mensaje_publico}", file=sys.stderr)
        return 1

    try:
        asyncio.run(nodo.servir(args.escuchar))
    except KeyboardInterrupt:
        return 0
    except OSError:
        print("Error: no se pudo escuchar en el puerto del directorio (¿ya hay otro proceso usándolo?).",
              file=sys.stderr)
        return 1
    except MiniOniError as e:
        print(f"Error: {e.mensaje_publico}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    consola.instalar_manejador_global("relay")
    sys.exit(main())
