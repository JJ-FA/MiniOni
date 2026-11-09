"""Puerta de la entrada del laboratorio (semana 4): reenvía TCP hacia entrada1, sin más.

Docker no publica puertos de una red `internal: true`, y en Docker Desktop una red
que no es interna sale a Internet aunque tenga el NAT desactivado. Por eso entrada1
vive solo en redes internas y este contenedor es el único en una red con salida.

Solo copia bytes entre el puerto publicado y entrada1. No tiene claves ni descifra
nada: lo que pasa por aquí ya va en TLS 1.3 con la huella que el cliente comprueba
contra el directorio. Su destino es fijo y no se puede elegir desde afuera.

Sin registros: nunca mira ni imprime la dirección de quien se conecta (ASVS 5.0 V16.2.5).
Si entrada1 no responde, se corta la conexión (ASVS 5.0 V16.5.3).
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import sys

DESTINO = ("10.10.1.10", 9001)
PUERTO = 9001
MAX_CONEXIONES = 128
TIMEOUT_CONEXION_S = 10
TAM_BLOQUE = 65536


async def _copiar(lector: asyncio.StreamReader, escritor: asyncio.StreamWriter) -> None:
    try:
        while datos := await lector.read(TAM_BLOQUE):
            escritor.write(datos)
            await escritor.drain()
    except OSError:
        pass


class Puerta:
    def __init__(self, destino: tuple[str, int] = DESTINO, max_conexiones: int = MAX_CONEXIONES) -> None:
        self.destino = destino
        self.max_conexiones = max_conexiones
        self.activas = 0

    async def atender(self, lector: asyncio.StreamReader, escritor: asyncio.StreamWriter) -> None:
        if self.activas >= self.max_conexiones:
            escritor.close()
            return
        self.activas += 1
        salida = None
        try:
            try:
                lector_destino, salida = await asyncio.wait_for(
                    asyncio.open_connection(*self.destino), TIMEOUT_CONEXION_S)
            except OSError:   # incluye TimeoutError: sin entrada1 no hay conexión
                return
            tareas = [asyncio.create_task(_copiar(lector, salida)),
                      asyncio.create_task(_copiar(lector_destino, escritor))]
            await asyncio.wait(tareas, return_when=asyncio.FIRST_COMPLETED)
            for tarea in tareas:
                tarea.cancel()
            await asyncio.gather(*tareas, return_exceptions=True)
        finally:
            self.activas -= 1
            escritor.close()
            if salida is not None:
                salida.close()


async def servir(ip: str) -> None:
    servidor = await asyncio.start_server(Puerta().atender, ip, PUERTO)
    print("puerta de la entrada iniciada", flush=True)
    async with servidor:
        await servidor.serve_forever()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="puerta", description="Puerta de la entrada del laboratorio MiniOni")
    p.add_argument("--escuchar", required=True, help="IP del contenedor en red_publica")
    args = p.parse_args(argv)
    try:
        ip = str(ipaddress.ip_address(args.escuchar))
    except ValueError:
        print("Error: --escuchar debe ser una dirección IP.", file=sys.stderr)
        return 1
    try:
        asyncio.run(servir(ip))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    from minioni import consola   # en la imagen, PYTHONPATH=/app

    consola.instalar_manejador_global("puerta")
    sys.exit(main())
