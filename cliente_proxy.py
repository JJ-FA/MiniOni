"""Arranca el proxy SOCKS5 de MiniOni para el navegador.

Uso (con los 3 relays corriendo):
    python cliente_proxy.py                 # escucha en 127.0.0.1:9050
    python cliente_proxy.py --puerto 9150

Con el laboratorio Docker (semana 4, ver docs/SEMANA4_DOCKER.md):
    python cliente_proxy.py --directorio config/directorio.docker.json --entrada-via 127.0.0.1:9001

Luego configurar Firefox según docs/NAVEGADOR.md, o probar con:
    curl.exe --socks5-hostname 127.0.0.1:9050 https://example.com

1. Verifica el directorio con config/autoridad.pub y anti-rollback
   (config/ultima_version guarda solo el número de versión más alto visto;
   el directorio de Docker usa config/ultima_version.docker).
2. Escucha SOLO en 127.0.0.1 (otra dirección se rechaza).
3. Cada conexión del navegador viaja por un circuito de 3 saltos. Si no hay
   circuito, la conexión falla: nunca se sale directo (fallo cerrado).
4. Ctrl+C: apagado limpio.

La consola solo muestra eventos genéricos: nunca dominios, IP ni puertos.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from minioni import consola
from minioni.constantes import HOST_PROXY, PUERTO_PROXY
from minioni.errores import ConfiguracionInvalida, MiniOniError
from minioni.proxy import (GestorCircuitos, ServidorProxy, argumento_entrada_via, argumento_puerto,
                           cargar_directorio, ruta_ultima_version)

CARPETA_CONFIG = Path("config")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="cliente_proxy", description="Proxy SOCKS5 de MiniOni")
    p.add_argument("--puerto", type=argumento_puerto, default=PUERTO_PROXY)
    p.add_argument("--escuchar", default=HOST_PROXY, help="solo se acepta 127.0.0.1")
    p.add_argument("--directorio", default=str(CARPETA_CONFIG / "directorio.firmado.json"))
    p.add_argument("--entrada-via", type=argumento_entrada_via, default=None,
                   help="127.0.0.1:PUERTO: llega al relay de entrada por el puerto que publica Docker")
    args = p.parse_args(argv)

    # Se rechaza antes de tocar el directorio (ServidorProxy lo vuelve a comprobar).
    if args.escuchar != HOST_PROXY:
        print("Error: el proxy solo puede escuchar en 127.0.0.1.", file=sys.stderr)
        return 1

    try:
        d = cargar_directorio(Path(args.directorio), CARPETA_CONFIG / "autoridad.pub",
                              ruta_ultima_version(CARPETA_CONFIG, Path(args.directorio)))
    except (MiniOniError, OSError):
        consola.evento("proxy", "DIRECTORIO_INVALIDO")
        return 1
    consola.evento("proxy", "DIRECTORIO_OK")

    try:
        servidor = ServidorProxy(d, args.escuchar, args.puerto,
                                 gestor=GestorCircuitos(d, entrada_via=args.entrada_via))
    except ConfiguracionInvalida as e:
        print(f"Error: {e.mensaje_publico}", file=sys.stderr)
        return 1

    try:
        asyncio.run(servidor.servir())
    except KeyboardInterrupt:
        return 0
    except OSError:
        print("Error: no se pudo escuchar en el puerto del proxy (¿ya hay otro proceso usándolo?).",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    consola.instalar_manejador_global("proxy")
    sys.exit(main())
