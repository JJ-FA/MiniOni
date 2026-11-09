"""Servidor web del laboratorio (semana 4): el «destino» al que se navega por MiniOni.

Vive en red_destinos (10.10.9.0/24), a la que solo llega el relay de salida. Responde
una página fija que muestra la IP desde la que le llegó la petición: debe ser la del
relay de salida (10.10.9.11), nunca la del equipo del usuario. Así se demuestra que
el destino no ve al cliente.

Sin registros: http.server imprime cada petición con la IP del visitante; aquí
log_message no hace nada y la IP solo se devuelve en la respuesta, a quien la pidió
(ASVS 5.0 V16.2.5).
"""

from __future__ import annotations

import argparse
import ipaddress
import sys
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PAGINA = """<!doctype html>
<html lang="es"><head><meta charset="utf-8"><title>MiniOni · web del laboratorio</title></head>
<body style="font-family:sans-serif;max-width:40em;margin:3em auto">
<h1>Llegaste por MiniOni</h1>
<p>Esta página está en la red <b>10.10.9.0/24</b> del laboratorio, a la que solo llega el relay de salida.</p>
<p>El servidor ve la conexión desde: <b>{ip}</b></p>
<p>Si es <b>10.10.9.11</b> (el relay de salida), el destino no conoce tu equipo.</p>
</body></html>
"""
MAX_RUTA = 256


class Manejador(BaseHTTPRequestHandler):
    server_version = "web-laboratorio"
    sys_version = ""
    timeout = 10

    def do_GET(self) -> None:  # noqa: N802 (nombre que exige http.server)
        if len(self.path) > MAX_RUTA:
            self.send_error(414)
            return
        cuerpo = PAGINA.format(ip=escape(self.client_address[0])).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(cuerpo)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(cuerpo)

    def log_message(self, formato, *argumentos) -> None:
        """No se registra nada: ni IP, ni rutas, ni horas."""


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="servidor_web", description="Web del laboratorio MiniOni")
    p.add_argument("--escuchar", required=True, help="IP del contenedor en red_destinos")
    p.add_argument("--puerto", type=int, default=80)
    args = p.parse_args(argv)
    try:
        ip = str(ipaddress.ip_address(args.escuchar))
    except ValueError:
        print("Error: --escuchar debe ser una dirección IP.", file=sys.stderr)
        return 1
    servidor = ThreadingHTTPServer((ip, args.puerto), Manejador)
    servidor.daemon_threads = True
    print("web del laboratorio iniciada", flush=True)
    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        servidor.server_close()
    return 0


if __name__ == "__main__":
    from minioni import consola   # en la imagen, PYTHONPATH=/app

    consola.instalar_manejador_global("web")
    sys.exit(main())
