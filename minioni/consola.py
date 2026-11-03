"""Mensajes de consola sin datos sensibles.

Decisión de diseño (OWASP ASVS 5.0 V16.2.5 y V16.4.1):
- No hay archivos de log. Nada se escribe en disco.
- Solo se pueden imprimir eventos de un catálogo cerrado. La función no
  acepta texto libre, así que es imposible imprimir por error una IP, un
  destino o el contenido de una celda.
- El único dato variable permitido es un número entero (por ejemplo, la
  cantidad de circuitos activos).
- La hora va en UTC (ASVS V16.2.2).
"""

from __future__ import annotations

import contextlib
import re
import sys
import threading
from datetime import datetime, timezone

EVENTOS = {
    "ARRANQUE": "nodo iniciado",
    "APAGADO": "nodo detenido",
    "DIRECTORIO_OK": "directorio verificado",
    "DIRECTORIO_INVALIDO": "directorio rechazado",
    "CIRCUITO_CREADO": "circuito creado",
    "CIRCUITO_FALLIDO": "no se pudo construir el circuito",
    "CIRCUITO_CERRADO": "circuito cerrado",
    "CELDA_RECHAZADA": "celda rechazada",
    "RELAY_CAIDO": "relay no disponible",
    "LIMITE_ALCANZADO": "conexión rechazada por límite",
    "DESTINO_BLOQUEADO": "destino bloqueado por la política de salida",
    "CERTIFICADO_POR_VENCER": "certificado TLS próximo a vencer",
    "ERROR_INTERNO": "error interno",
}

_COMPONENTE = re.compile(r"^[a-z0-9-]{1,24}$")

# Funciones que reciben cada evento (el panel gráfico). Reciben lo MISMO que
# se imprime: componente, código del catálogo y cantidad; nunca texto libre.
_oyentes: list = []


def suscribir(funcion):
    """Registra `funcion(componente, codigo, cantidad)`. Devuelve una función para darse de baja."""
    _oyentes.append(funcion)

    def baja() -> None:
        with contextlib.suppress(ValueError):
            _oyentes.remove(funcion)
    return baja


def evento(componente: str, codigo: str, cantidad: int | None = None, salida=None) -> str:
    if not _COMPONENTE.fullmatch(componente):
        componente = "desconocido"
    if codigo not in EVENTOS:
        codigo = "ERROR_INTERNO"
    if not isinstance(cantidad, int) or isinstance(cantidad, bool):
        cantidad = None
    texto = EVENTOS[codigo]
    hora = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    linea = f"{hora} [{componente}] {texto}"
    if cantidad is not None:
        linea += f" ({cantidad})"
    print(linea, file=salida or sys.stderr, flush=True)
    for oyente in list(_oyentes):
        # Un oyente con fallos nunca debe tumbar al relay ni al proxy.
        with contextlib.suppress(Exception):
            oyente(componente, codigo, cantidad)
    return linea


# Caracteres de control C0/C1 (saltos de línea, ESC de las secuencias ANSI) y
# controles de dirección Unicode (pueden invertir el texto que se ve).
_CONTROL = re.compile("[\x00-\x1f\x7f-\x9f\u200e\u200f\u202a-\u202e\u2066-\u2069]")


def texto_seguro(texto, maximo: int = 80) -> str:
    """Neutraliza texto que viene de fuera antes de mostrarlo (ASVS 5.0 V16.4.1).

    Para los pocos mensajes del administrador que repiten algo escrito por el usuario
    (un apodo, una ruta) o recibido por la red (el eco de prueba): cada carácter de
    control se reemplaza por '?', así nadie puede borrar la pantalla ni fabricar
    líneas falsas que parezcan eventos del sistema.
    """
    limpio = _CONTROL.sub("?", str(texto))
    return limpio if len(limpio) <= maximo else limpio[:maximo - 1] + "…"


def instalar_manejador_global(componente: str) -> None:
    """Manejador de último recurso del proceso (ASVS V16.5.4 y V16.5.1).

    Sin esto, una excepción no prevista hace que Python imprima la traza completa:
    rutas de archivos, nombres de funciones y, a veces, valores internos. Con esto
    solo se emite ERROR_INTERNO del catálogo y el proceso termina con código 1.
    Ctrl+C sigue cerrando en silencio.
    """
    def gancho(tipo, valor, traza) -> None:
        if tipo is not None and issubclass(tipo, KeyboardInterrupt):
            return
        evento(componente, "ERROR_INTERNO")

    def gancho_hilos(args) -> None:
        if args.exc_type is not None and issubclass(args.exc_type, SystemExit):
            return
        evento(componente, "ERROR_INTERNO")

    sys.excepthook = gancho
    threading.excepthook = gancho_hilos
