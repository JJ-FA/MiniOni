"""Resumen de una captura .pcap sin necesitar Wireshark (semana 5, S5-T1).

Cuenta paquetes, puertos y registros TLS, y busca texto en claro de la petición de
prueba en los datos TCP. Los archivos los genera `laboratorio_docker.py capturar`,
pero igual se validan: un archivo mal formado termina en un error genérico.

Se buscan «GET /» y «Host: web», y no las palabras sueltas «GET» o «web»: una cadena
de 3 bytes aparece por azar en cientos de kilobytes de texto cifrado, y la prueba
fallaría sin que hubiera ninguna fuga.
"""

from __future__ import annotations

import struct
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from .errores import ConfiguracionInvalida

MAX_BYTES_PCAP = 200 * 1024 * 1024
MAX_BYTES_PAQUETE = 262144
MARCAS_TEXTO_CLARO = (b"GET /", b"Host: web")

_ORDEN_POR_MAGIA = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
                    b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}
# Bytes de la cabecera de enlace según el tipo: NULL, Ethernet, IP crudo, SLL y SLL2.
_CABECERA_ENLACE = {0: 4, 1: 14, 101: 0, 113: 16, 276: 20}
_CABECERA_GLOBAL = 24
_CABECERA_PAQUETE = 16
_PROTOCOLO_TCP = 6


@dataclass
class ResumenCaptura:
    paquetes: int = 0
    puertos: set[int] = field(default_factory=set)
    registros_tls: int = 0
    tamanos: Counter = field(default_factory=Counter)
    marcas: set[bytes] = field(default_factory=set)

    @property
    def texto_en_claro(self) -> bool:
        return bool(self.marcas)


def _contar_paquete(paquete: bytes, salto: int, resumen: ResumenCaptura) -> None:
    ip = paquete[salto:]
    if len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] != _PROTOCOLO_TCP:
        return
    largo_ip = (ip[0] & 0x0F) * 4
    tcp = ip[largo_ip:int.from_bytes(ip[2:4], "big") or len(ip)]
    if largo_ip < 20 or len(tcp) < 20:
        return
    resumen.puertos.update((int.from_bytes(tcp[:2], "big"), int.from_bytes(tcp[2:4], "big")))
    datos = tcp[(tcp[12] >> 4) * 4:]
    if not datos:
        return
    resumen.tamanos[len(datos)] += 1
    if datos[:3] == b"\x17\x03\x03":   # registro de datos TLS 1.3
        resumen.registros_tls += 1
    resumen.marcas.update(m for m in MARCAS_TEXTO_CLARO if m in datos)


def resumir(contenido: bytes) -> ResumenCaptura:
    """Resume una captura. Un final cortado se acepta: así queda si la captura se interrumpe."""
    orden = _ORDEN_POR_MAGIA.get(contenido[:4])
    if orden is None or len(contenido) < _CABECERA_GLOBAL:
        raise ConfiguracionInvalida("captura no válida")
    salto = _CABECERA_ENLACE.get(struct.unpack_from(orden + "I", contenido, 20)[0] & 0xFFFF)
    if salto is None:
        raise ConfiguracionInvalida("tipo de captura no soportado")
    resumen = ResumenCaptura()
    posicion = _CABECERA_GLOBAL
    while posicion + _CABECERA_PAQUETE <= len(contenido):
        incluido = struct.unpack_from(orden + "I", contenido, posicion + 8)[0]
        posicion += _CABECERA_PAQUETE
        if incluido > MAX_BYTES_PAQUETE or posicion + incluido > len(contenido):
            break
        resumen.paquetes += 1
        _contar_paquete(contenido[posicion:posicion + incluido], salto, resumen)
        posicion += incluido
    return resumen


def resumir_archivo(ruta: Path) -> ResumenCaptura:
    try:
        if Path(ruta).stat().st_size > MAX_BYTES_PCAP:
            raise ConfiguracionInvalida("captura demasiado grande")
        return resumir(Path(ruta).read_bytes())
    except OSError:
        raise ConfiguracionInvalida("no se pudo leer la captura") from None
