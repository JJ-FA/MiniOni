"""Proxy SOCKS5 local de MiniOni: cada conexión del navegador viaja como un stream por un circuito.

Fallo cerrado (ASVS V16.5.3): este módulo NO tiene ningún camino de código
que abra una conexión al destino. Las únicas conexiones salientes son las
de `CircuitoCliente` hacia el relay de entrada del directorio (con pinning
TLS). Si no hay circuito, el navegador recibe 05 01 y la navegación falla.

DNS remoto obligatorio: el proxy nunca resuelve nombres (ver socks5.py).

Escucha solo en 127.0.0.1: un proxy abierto a la red sería un relé abierto
y más superficie de ataque.

Consola (ASVS V16.2.5): solo ARRANQUE, DIRECTORIO_OK, CIRCUITO_CREADO(n),
CIRCUITO_FALLIDO, CIRCUITO_CERRADO(n), APAGADO y, como último recurso,
ERROR_INTERNO. Nunca dominios, IP ni puertos.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import os
import re
import secrets
import tempfile
import time
from pathlib import Path

from . import almacen_claves as ak
from . import consola
from . import directorio as dirmod
from . import socks5
from .celdas import (
    ComandoRelay,
    MensajeRelay,
    MotivoEnd,
    codificar_destino,
    codificar_end,
    decodificar_end,
    validar_puerto,
)
from .circuito import CircuitoCliente, elegir_ruta
from .constantes import (
    HOST_PROXY,
    MAX_CONEXIONES_SOCKS,
    MAX_DATOS_RELAY,
    MAX_INTENTOS_CIRCUITO,
    MAX_STREAMS_POR_CIRCUITO,
    PUERTO_PROXY,
    TAM_COLA_DATOS,
    TIMEOUT_CONNECTED_S,
    TIMEOUT_HANDSHAKE_S,
    TIMEOUT_SOCKS_S,
    VIDA_MAX_CIRCUITO_S,
)
from .errores import (
    CeldaInvalida,
    CircuitoCerrado,
    ConfiguracionInvalida,
    DestinoNoPermitido,
    DirectorioInvalido,
    MiniOniError,
    SocksInvalido,
)

COMPONENTE = "proxy"
_VERSION_GUARDADA = re.compile(rb"[0-9]{1,10}\r?\n?")


# --- anti-rollback del directorio ----------------------------------------------

def leer_ultima_version(ruta: Path) -> int:
    """Versión más alta del directorio vista hasta ahora (1 si nunca se guardó)."""
    ruta = Path(ruta)
    if not ruta.exists():
        return 1
    try:
        contenido = ruta.read_bytes()
    except OSError:
        raise ConfiguracionInvalida("no se pudo leer ultima_version") from None
    if not _VERSION_GUARDADA.fullmatch(contenido):
        raise ConfiguracionInvalida("ultima_version con formato inválido")
    version = int(contenido.strip())
    if not 1 <= version <= 2**31:
        raise ConfiguracionInvalida("ultima_version fuera de rango")
    return version


def guardar_ultima_version(ruta: Path, version: int) -> None:
    """Escritura atómica: archivo temporal en la misma carpeta y os.replace."""
    ruta = Path(ruta)
    fd, temporal = tempfile.mkstemp(dir=ruta.parent, prefix=".ultima_version.")
    try:
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write(f"{version}\n")
        os.replace(temporal, ruta)
    except OSError:
        try:
            os.unlink(temporal)
        except OSError:
            pass
        raise ConfiguracionInvalida("no se pudo guardar ultima_version") from None


def cargar_directorio(ruta_directorio: Path, ruta_autoridad: Path, ruta_ultima: Path) -> dirmod.Directorio:
    """Verifica el directorio con anti-rollback: nunca acepta una versión menor a la ya vista.

    En `ruta_ultima` solo se guarda el número de versión (no es un dato del usuario).
    """
    minima = leer_ultima_version(ruta_ultima)
    try:
        contenido = Path(ruta_directorio).read_bytes()
    except OSError:
        raise DirectorioInvalido("no se pudo leer el directorio") from None
    d = dirmod.verificar(contenido, ak.cargar_publica(Path(ruta_autoridad)), version_minima=minima)
    if d.version > minima:
        guardar_ultima_version(ruta_ultima, d.version)
    return d


# --- circuito compartido por varios streams -------------------------------------------

class CircuitoProxy:
    """Un CircuitoCliente con varios streams y una tarea que reparte lo que llega."""

    def __init__(self, circuito: CircuitoCliente, gestor: GestorCircuitos) -> None:
        self.circuito = circuito
        self.creado = time.monotonic()
        self.caido = False
        self.retirado = False
        self._gestor = gestor
        self._colas: dict[int, asyncio.Queue] = {}
        self._lector: asyncio.Task | None = None

    @property
    def streams(self) -> int:
        return len(self._colas)

    def iniciar(self) -> None:
        self._lector = asyncio.get_running_loop().create_task(self._despachar())

    def abrir_stream(self) -> tuple[int, asyncio.Queue]:
        if self.caido or self.retirado:
            raise CircuitoCerrado("circuito no disponible")
        if len(self._colas) >= MAX_STREAMS_POR_CIRCUITO:
            raise CircuitoCerrado("circuito lleno")
        while True:
            sid = secrets.randbelow(0xFFFF) + 1     # 1..65535, el 0 está reservado
            if sid not in self._colas:
                break
        cola: asyncio.Queue = asyncio.Queue(maxsize=TAM_COLA_DATOS)
        self._colas[sid] = cola
        return sid, cola

    def soltar_stream(self, sid: int) -> None:
        cola = self._colas.pop(sid, None)
        if cola is not None:
            _vaciar(cola)   # libera al repartidor si estaba esperando espacio en esta cola
        self._gestor.revisar(self)

    async def enviar(self, mensaje: MensajeRelay) -> None:
        await self.circuito.enviar(mensaje)

    async def _despachar(self) -> None:
        try:
            while True:
                msg = await self.circuito.recibir()
                if msg.comando not in (ComandoRelay.CONNECTED, ComandoRelay.DATA, ComandoRelay.END):
                    raise CeldaInvalida("mensaje inesperado en el proxy")
                cola = self._colas.get(msg.stream_id)
                if cola is not None:
                    await cola.put(msg)   # cola llena = presión hacia atrás sobre el circuito
                # Un stream ya cerrado por el proxy puede recibir DATA/END en vuelo: se ignora.
        except asyncio.CancelledError:
            raise
        except Exception:
            self.caer()   # circuito destruido o mensaje inválido: fallo cerrado
        finally:
            self.caer()   # también si se cancela (idempotente)

    def caer(self) -> None:
        """El circuito ya no sirve: se avisa a todos sus streams (None) para que cierren."""
        if self.caido:
            return
        self.caido = True
        for cola in self._colas.values():
            _vaciar(cola)
            cola.put_nowait(None)
        self._gestor.revisar(self)

    async def cerrar(self) -> None:
        self.caido = True
        if self._lector is not None and self._lector is not asyncio.current_task():
            self._lector.cancel()
        await self.circuito.cerrar()


def _vaciar(cola: asyncio.Queue) -> None:
    while True:
        try:
            cola.get_nowait()
        except asyncio.QueueEmpty:
            return


class GestorCircuitos:
    """Un circuito activo para los streams nuevos; rotación, reintentos y cierre de los viejos."""

    def __init__(self, directorio: dirmod.Directorio, timeout: float = TIMEOUT_HANDSHAKE_S,
                 vida_max: float = VIDA_MAX_CIRCUITO_S, max_intentos: int = MAX_INTENTOS_CIRCUITO,
                 construir=None, entrada_via: tuple[str, int] | None = None) -> None:
        self.directorio = directorio
        self._entrada_via = entrada_via
        self._timeout = timeout
        self._vida_max = vida_max
        self._max_intentos = max_intentos
        self._construir = construir or self._construir_real
        self._activo: CircuitoProxy | None = None
        self._circuitos: set[CircuitoProxy] = set()
        self._lock = asyncio.Lock()
        self._tareas: set[asyncio.Task] = set()

    @property
    def circuitos(self) -> int:
        return len(self._circuitos)

    async def _construir_real(self) -> CircuitoCliente:
        c = CircuitoCliente(self._timeout, entrada_via=self._entrada_via)
        await c.construir(self.directorio, elegir_ruta(self.directorio))
        return c

    async def obtener(self) -> CircuitoProxy:
        """Circuito para un stream nuevo. Hasta `max_intentos` construcciones seguidas; luego falla."""
        async with self._lock:
            activo = self._activo
            if activo is not None and (activo.caido
                                       or time.monotonic() - activo.creado >= self._vida_max
                                       or activo.streams >= MAX_STREAMS_POR_CIRCUITO):
                self._retirar(activo)
                activo = None
            if activo is None:
                activo = await self._nuevo()
            return activo

    async def _nuevo(self) -> CircuitoProxy:
        for _ in range(self._max_intentos):
            try:
                circuito = await self._construir()
            except MiniOniError:
                consola.evento(COMPONENTE, "CIRCUITO_FALLIDO")
                continue
            cp = CircuitoProxy(circuito, self)
            self._circuitos.add(cp)
            self._activo = cp
            cp.iniciar()
            consola.evento(COMPONENTE, "CIRCUITO_CREADO", len(self._circuitos))
            return cp
        raise CircuitoCerrado("no se pudo construir un circuito")

    def _retirar(self, cp: CircuitoProxy) -> None:
        cp.retirado = True
        if self._activo is cp:
            self._activo = None
        self.revisar(cp)

    def revisar(self, cp: CircuitoProxy) -> None:
        """Cierra un circuito caído o retirado cuando ya no le quedan streams."""
        if cp.caido and self._activo is cp:
            self._activo = None
        if cp not in self._circuitos or not (cp.caido or cp.retirado) or cp.streams:
            return
        self._circuitos.discard(cp)
        t = asyncio.get_running_loop().create_task(cp.cerrar())
        self._tareas.add(t)
        t.add_done_callback(self._tareas.discard)
        consola.evento(COMPONENTE, "CIRCUITO_CERRADO", len(self._circuitos))

    async def cerrar_todo(self) -> None:
        for cp in list(self._circuitos):
            await cp.cerrar()
        self._circuitos.clear()
        self._activo = None
        if self._tareas:
            await asyncio.gather(*self._tareas, return_exceptions=True)


# --- servidor SOCKS5 ----------------------------------------------------------------

def _codigo_socks(msg: MensajeRelay | None) -> int:
    """CONNECTED -> 05 00; END(1) -> 05 02; END(2), END(3), tiempo agotado o circuito caído -> 05 01."""
    if msg is None:
        return socks5.FALLO_GENERAL
    if msg.comando == ComandoRelay.CONNECTED and not msg.datos:
        return socks5.EXITO
    if msg.comando == ComandoRelay.END:
        try:
            motivo = decodificar_end(msg.datos)
        except CeldaInvalida:
            return socks5.FALLO_GENERAL
        if motivo == MotivoEnd.NO_PERMITIDO:
            return socks5.NO_PERMITIDO
    return socks5.FALLO_GENERAL


class ServidorProxy:
    def __init__(self, directorio: dirmod.Directorio, host: str = HOST_PROXY, puerto: int = PUERTO_PROXY,
                 gestor: GestorCircuitos | None = None, timeout_socks: float = TIMEOUT_SOCKS_S,
                 timeout_connected: float = TIMEOUT_CONNECTED_S,
                 max_conexiones: int = MAX_CONEXIONES_SOCKS) -> None:
        if host != HOST_PROXY:
            raise ConfiguracionInvalida("el proxy solo escucha en 127.0.0.1")
        try:
            # 0 solo para pruebas: el sistema elige un puerto libre.
            puerto = puerto if puerto == 0 else validar_puerto(puerto)
        except DestinoNoPermitido:
            raise ConfiguracionInvalida("puerto inválido") from None
        self.host = host
        self.puerto = puerto
        self.gestor = gestor or GestorCircuitos(directorio)
        self._timeout_socks = timeout_socks
        self._timeout_connected = timeout_connected
        self._max_conexiones = max_conexiones
        self._conexiones: set[asyncio.Task] = set()
        self._servidor: asyncio.AbstractServer | None = None
        self._detenido = False

    @property
    def conexiones_activas(self) -> int:
        return len(self._conexiones)

    def _manejador_excepciones(self, loop, contexto) -> None:
        # Reemplaza al manejador por defecto, que imprimiría trazas y direcciones.
        consola.evento(COMPONENTE, "ERROR_INTERNO")

    async def iniciar(self) -> None:
        asyncio.get_running_loop().set_exception_handler(self._manejador_excepciones)
        self._servidor = await asyncio.start_server(self._al_conectar, self.host, self.puerto)
        self.puerto = self._servidor.sockets[0].getsockname()[1]
        consola.evento(COMPONENTE, "ARRANQUE")

    async def servir(self) -> None:
        """Atiende hasta que se cancele (Ctrl+C). Siempre termina con un apagado limpio."""
        await self.iniciar()
        try:
            await asyncio.Event().wait()
        finally:
            await self.detener()

    async def detener(self) -> None:
        if self._detenido:
            return
        self._detenido = True
        if self._servidor is not None:
            self._servidor.close()
        tareas = [t for t in self._conexiones if t is not asyncio.current_task()]
        for t in tareas:
            t.cancel()
        await asyncio.gather(*tareas, return_exceptions=True)
        await self.gestor.cerrar_todo()
        if self._servidor is not None:
            try:
                await asyncio.wait_for(self._servidor.wait_closed(), 2)
            except asyncio.TimeoutError:
                pass
            self._servidor = None
        consola.evento(COMPONENTE, "APAGADO")

    async def _al_conectar(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if len(self._conexiones) >= self._max_conexiones:
            writer.transport.abort()
            return
        tarea = asyncio.current_task()
        self._conexiones.add(tarea)
        try:
            await self._atender(reader, writer)
        except asyncio.CancelledError:
            raise
        except Exception:
            consola.evento(COMPONENTE, "ERROR_INTERNO")
        finally:
            self._conexiones.discard(tarea)
            try:
                writer.close()
            except (OSError, RuntimeError):
                pass

    @staticmethod
    async def _responder(writer: asyncio.StreamWriter, codigo: int) -> None:
        try:
            writer.write(socks5.respuesta(codigo))
            await asyncio.wait_for(writer.drain(), 5)
        except (ConnectionError, OSError, RuntimeError, asyncio.TimeoutError):
            pass

    async def _atender(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            host, puerto = await socks5.negociar(reader, writer, self._timeout_socks)
            destino = codificar_destino(host, puerto)
        except SocksInvalido:
            return
        except DestinoNoPermitido:
            await self._responder(writer, socks5.NO_PERMITIDO)
            return
        try:
            cp = await self.gestor.obtener()
            sid, cola = cp.abrir_stream()
        except MiniOniError:
            await self._responder(writer, socks5.FALLO_GENERAL)
            return

        fin_remoto = False
        try:
            try:
                await cp.enviar(MensajeRelay(ComandoRelay.BEGIN, sid, destino))
                msg = await asyncio.wait_for(cola.get(), self._timeout_connected)
            except (MiniOniError, asyncio.TimeoutError):
                msg = None
            # Sin respuesta a tiempo se envía END igual: la salida cierra el socket si llega a conectar.
            fin_remoto = msg is not None and msg.comando == ComandoRelay.END
            codigo = _codigo_socks(msg)
            await self._responder(writer, codigo)
            if codigo != socks5.EXITO:
                return
            fin_remoto = await self._copiar(reader, writer, cp, sid, cola)
        finally:
            if not fin_remoto and not cp.caido:
                try:
                    await cp.enviar(MensajeRelay(ComandoRelay.END, sid, codificar_end()))
                except MiniOniError:
                    pass
            cp.soltar_stream(sid)

    @staticmethod
    async def _copiar(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                      cp: CircuitoProxy, sid: int, cola: asyncio.Queue) -> bool:
        """Copia en ambos sentidos hasta que un lado cierre. Devuelve True si cerró la salida."""

        async def subir() -> None:
            while True:
                datos = await reader.read(MAX_DATOS_RELAY)
                if not datos:
                    return
                await cp.enviar(MensajeRelay(ComandoRelay.DATA, sid, datos))

        async def bajar() -> bool:
            while True:
                msg = await cola.get()
                if msg is None or msg.comando != ComandoRelay.DATA:
                    return True   # END de la salida, circuito caído o mensaje inesperado
                writer.write(msg.datos)
                await writer.drain()

        loop = asyncio.get_running_loop()
        t_subir, t_bajar = loop.create_task(subir()), loop.create_task(bajar())
        try:
            hechas, pendientes = await asyncio.wait({t_subir, t_bajar}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for t in (t_subir, t_bajar):
                t.cancel()
            resultados = await asyncio.gather(t_subir, t_bajar, return_exceptions=True)
        return t_bajar in hechas and resultados[1] is True


def argumento_puerto(texto: str) -> int:
    """Tipo de argparse para --puerto: entero de 1 a 65535 (ASVS V2.2.1).

    El 0 (puerto al azar) solo existe para las pruebas internas de ServidorProxy;
    en la línea de comandos se rechaza, porque el usuario no sabría a qué puerto
    apuntar el navegador (la consola nunca muestra puertos).
    """
    try:
        return validar_puerto(int(texto, 10))
    except (ValueError, DestinoNoPermitido):
        raise argparse.ArgumentTypeError("debe ser un número entre 1 y 65535") from None


_ENTRADA_VIA = re.compile(r"([0-9.]{7,15}):([0-9]{1,5})")


def argumento_entrada_via(texto: str) -> tuple[str, int]:
    """Tipo de argparse para --entrada-via: '127.0.0.1:PUERTO' (semana 4, Docker).

    Solo se acepta una IP de loopback (127.x.x.x): la opción existe para llegar al
    relay de entrada que Docker publica en el propio equipo, no para desviar el
    tráfico a otra máquina. Aun así, la identidad del relay la sigue garantizando
    el pinning de la huella del directorio (ASVS 5.0 V2.2.1, V12.3.4).
    """
    coincidencia = _ENTRADA_VIA.fullmatch(texto)
    error = argparse.ArgumentTypeError("debe ser 127.0.0.1:PUERTO (el puerto que publica Docker)")
    if coincidencia is None:
        raise error
    try:
        ip = ipaddress.IPv4Address(coincidencia.group(1))
        puerto = validar_puerto(int(coincidencia.group(2), 10))
    except (ValueError, DestinoNoPermitido):
        raise error from None
    if not ip.is_loopback:
        raise error
    return str(ip), puerto


_NOMBRE_DIRECTORIO = re.compile(r"directorio\.([a-z0-9_-]{1,32})\.json")


def ruta_ultima_version(carpeta_config: Path, ruta_directorio: Path) -> Path:
    """Archivo anti-rollback que corresponde a un directorio.

    Cada directorio lleva su propio contador: el local (directorio.firmado.json →
    ultima_version) y el de Docker (directorio.docker.json → ultima_version.docker)
    se publican por separado, y con un contador común el que tuviera la versión más
    baja quedaría rechazado como si fuera un ataque de rollback.
    """
    nombre = Path(ruta_directorio).name
    coincidencia = _NOMBRE_DIRECTORIO.fullmatch(nombre)
    if coincidencia is None or coincidencia.group(1) == "firmado":
        return Path(carpeta_config) / "ultima_version"
    return Path(carpeta_config) / f"ultima_version.{coincidencia.group(1)}"
