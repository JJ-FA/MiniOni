"""Sonda del laboratorio Docker (semana 4). La lanza laboratorio_docker.py probar.

Dos modos, y los dos imprimen UNA línea JSON con el resultado (sin IP de usuarios: las
únicas direcciones son las fijas del laboratorio):

  alcance        Se conecta a una red y prueba a qué servicios del laboratorio llega
                 (conexión TCP con tiempo límite). Demuestra la segmentación: desde
                 cada red solo debe verse el servicio que le corresponde (ISO/IEC 27033).

  punta-a-punta  Desde red_cliente: eco por un circuito de 3 saltos, una página de la web
                 del laboratorio a través del proxy SOCKS5 de MiniOni (127.0.0.1 dentro de
                 la sonda), y dos destinos que la política de salida debe bloquear.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import socket
import sys
from pathlib import Path

OBJETIVOS = {
    "entrada1": ("10.10.1.10", 9001),
    "medio1": ("10.10.2.10", 9002),
    "salida1": ("10.10.3.10", 9003),
    "web": ("10.10.9.20", 80),
    "internet": ("1.1.1.1", 443),
}
IP_SALIDA_EN_DESTINOS = "10.10.9.11"
_IP_VISTA = re.compile(rb"ve la conexi\xc3\xb3n desde: <b>([0-9.]{7,15})</b>")


def alcance(timeout: float = 2.0) -> dict:
    resultado = {}
    for nombre, (ip, puerto) in OBJETIVOS.items():
        try:
            with socket.create_connection((ip, puerto), timeout=timeout):
                resultado[nombre] = True
        except OSError:
            resultado[nombre] = False
    return {"modo": "alcance", "alcanza": resultado}


def _socks5(puerto_proxy: int, host: str, puerto: int, peticion: bytes, timeout: float = 20.0) -> tuple[int, bytes]:
    """Cliente SOCKS5 mínimo (RFC 1928, CONNECT por nombre). Devuelve (código, respuesta)."""
    with socket.create_connection(("127.0.0.1", puerto_proxy), timeout=timeout) as s:
        s.sendall(b"\x05\x01\x00")
        if s.recv(2) != b"\x05\x00":
            return 255, b""
        nombre = host.encode("ascii")
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(nombre)]) + nombre + puerto.to_bytes(2, "big"))
        cabecera = s.recv(4)
        if len(cabecera) < 4:
            return 255, b""
        codigo = cabecera[1]
        resto = {1: 6, 4: 18}.get(cabecera[3], 0)
        if resto:
            s.recv(resto)
        if codigo != 0:
            return codigo, b""
        s.sendall(peticion)
        datos = b""
        while len(datos) < 65536:
            parte = s.recv(4096)
            if not parte:
                break
            datos += parte
        return 0, datos


async def _eco(d) -> bool:
    from minioni.celdas import ComandoRelay, MensajeRelay
    from minioni.circuito import CircuitoCliente, elegir_ruta

    circuito = CircuitoCliente()
    try:
        await circuito.construir(d, elegir_ruta(d))
        await circuito.enviar(MensajeRelay(ComandoRelay.ECO, 0, b"hola desde la sonda"))
        respuesta = await circuito.recibir()
        return respuesta.comando == ComandoRelay.ECO and respuesta.datos == b"hola desde la sonda"
    finally:
        await circuito.cerrar()


async def _por_proxy(d) -> dict:
    from minioni.proxy import ServidorProxy

    servidor = ServidorProxy(d, "127.0.0.1", 0)
    await servidor.iniciar()
    try:
        peticion = b"GET / HTTP/1.0\r\nHost: web\r\n\r\n"
        codigo, pagina = await asyncio.to_thread(_socks5, servidor.puerto, "web", 80, peticion)
        vista = _IP_VISTA.search(pagina)
        codigo_puerto, _ = await asyncio.to_thread(_socks5, servidor.puerto, "web", 22, b"")
        codigo_interno, _ = await asyncio.to_thread(_socks5, servidor.puerto, "10.10.2.10", 9002, b"")
    finally:
        await servidor.detener()
    return {
        "pagina": codigo == 0 and pagina.startswith(b"HTTP/1.0 200"),
        "ip_que_ve_el_destino": vista.group(1).decode() if vista else None,
        "puerto_22_bloqueado": codigo_puerto != 0,
        "relay_interno_bloqueado": codigo_interno != 0,
    }


def punta_a_punta() -> dict:
    from minioni import almacen_claves as ak
    from minioni import directorio as dirmod

    d = dirmod.verificar(Path("config/directorio.docker.json").read_bytes(),
                         ak.cargar_publica(Path("config/autoridad.pub")))
    resultado = {"modo": "punta-a-punta", "eco": asyncio.run(_eco(d))}
    resultado.update(asyncio.run(_por_proxy(d)))
    resultado["destino_no_ve_al_cliente"] = resultado["ip_que_ve_el_destino"] == IP_SALIDA_EN_DESTINOS
    return resultado


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="sonda")
    p.add_argument("modo", choices=["alcance", "punta-a-punta"])
    args = p.parse_args(argv)
    try:
        resultado = alcance() if args.modo == "alcance" else punta_a_punta()
    except Exception:  # la sonda informa en JSON; nunca muestra trazas
        print(json.dumps({"modo": args.modo, "error": "fallo de la sonda"}))
        return 1
    print(json.dumps(resultado))
    if args.modo == "punta-a-punta":
        ok = all(resultado[k] for k in ("eco", "pagina", "destino_no_ve_al_cliente",
                                         "puerto_22_bloqueado", "relay_interno_bloqueado"))
        return 0 if ok else 1
    return 0


if __name__ == "__main__":
    from minioni import consola   # en la imagen, PYTHONPATH=/app

    consola.instalar_manejador_global("sonda")
    sys.exit(main())
