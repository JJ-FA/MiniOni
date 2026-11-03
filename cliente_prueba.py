"""Cliente de prueba de la semana 2: construye un circuito real de 3 saltos y envía un ECO.

Uso (con los 3 relays corriendo):
    python cliente_prueba.py
    python cliente_prueba.py --mensaje "otro texto"

Muestra apodos (es el equipo del propio usuario), nunca IP ni puertos. Si
algo falla, muestra solo el mensaje genérico y termina con código 1.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
from pathlib import Path

from minioni import almacen_claves as ak
from minioni import consola
from minioni import directorio as dirmod
from minioni.celdas import ComandoRelay, MensajeRelay
from minioni.circuito import CircuitoCliente, elegir_ruta
from minioni.constantes import MAX_DATOS_RELAY
from minioni.errores import MiniOniError

CARPETA_CONFIG = Path("config")


def _progreso(i: int, relay, listo: bool) -> None:
    if not listo:
        texto = f"Circuito hasta {relay.apodo}" if i == 1 else f"Extendido a {relay.apodo}"
        print(f"[{i}/3] {(texto + ' ...').ljust(30)} ", end="", flush=True)
    else:
        print("OK", flush=True)


async def _probar(d: dirmod.Directorio, mensaje: str) -> int:
    datos = mensaje.encode("utf-8")
    circuito = CircuitoCliente()
    try:
        await circuito.construir(d, elegir_ruta(d), _progreso)
        inicio = time.perf_counter()
        await circuito.enviar(MensajeRelay(ComandoRelay.ECO, 0, datos))
        print(f'Eco enviado: "{consola.texto_seguro(mensaje)}" ({len(datos)} bytes)')
        respuesta = await circuito.recibir()
        ms = (time.perf_counter() - inicio) * 1000
        if respuesta.comando != ComandoRelay.ECO or respuesta.datos != datos:
            print("Error: el eco no coincide con lo enviado", file=sys.stderr)
            return 1
        print(f'Eco recibido: "{consola.texto_seguro(respuesta.datos.decode("utf-8", "replace"))}" · ida y vuelta {ms:.0f} ms')
    finally:
        await circuito.cerrar()
    print("Circuito cerrado.")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="cliente_prueba", description="Eco por un circuito de 3 saltos")
    p.add_argument("--directorio", default=str(CARPETA_CONFIG / "directorio.firmado.json"))
    p.add_argument("--mensaje", default="hola MiniOni")
    args = p.parse_args(argv)
    if not args.mensaje or len(args.mensaje.encode("utf-8")) > MAX_DATOS_RELAY:
        print(f"Error: el mensaje debe tener entre 1 y {MAX_DATOS_RELAY} bytes.", file=sys.stderr)
        return 1
    try:
        d = dirmod.verificar(Path(args.directorio).read_bytes(), ak.cargar_publica(CARPETA_CONFIG / "autoridad.pub"))
    except (MiniOniError, OSError):
        print("Error: directorio de nodos no válido", file=sys.stderr)
        return 1
    print(f"Directorio verificado: versión {d.version}, {len(d.relays)} relays")
    try:
        return asyncio.run(_probar(d, args.mensaje))
    except MiniOniError as e:
        print(f"FALLO\nError: {e.mensaje_publico}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 1


if __name__ == "__main__":
    consola.instalar_manejador_global("cliente")
    sys.exit(main())
