"""Relay de MiniOni: servidor asyncio con TLS 1.3 que quita o agrega una capa por celda.

Regla del protocolo: solo el ÚLTIMO salto de un circuito interpreta o genera
mensajes RELAY. Un relay con siguiente salto quita su capa y reenvía sin
mirar el contenido.

`circ_id` es local a cada enlace TLS: el relay guarda la correspondencia
(enlace_anterior, circ_id_anterior) <-> (enlace_siguiente, circ_id_siguiente).

Fallo cerrado (ASVS V16.5.3): ante cualquier error se destruye el circuito
(DESTROY con un motivo genérico) o se cierra el enlace completo. Límites
anti-saturación (ASVS V2.4.1): conexiones por IP, circuitos por enlace y
totales, tiempos máximos y limpieza periódica. La consola solo recibe
eventos del catálogo de `consola.py` (ASVS V16.2.5).

Nodo de salida (semana 3): solo un relay con `salida=True` en el directorio
acepta BEGIN/DATA/END. Cada stream es una conexión TCP al destino; el nombre
se resuelve UNA vez y se conecta a la IP exacta que pasó la política de
salida (anti DNS-rebinding). Todo lo que vuelve hacia el cliente por un
circuito pasa por una sola cola en orden; si se llena, se deja de leer de
los destinos (presión hacia atrás).
"""

from __future__ import annotations

import asyncio
import hmac
import re
import secrets
import socket
import ssl
import time
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from . import almacen_claves as ak
from . import consola, transporte
from .capas import CapaSalto, relay_agregar_capa, relay_originar, relay_pelar, rellenar
from .celdas import (
    Celda,
    Comando,
    ComandoRelay,
    MensajeRelay,
    MotivoDestroy,
    MotivoEnd,
    codificar_destroy,
    codificar_end,
    codificar_relay,
    decodificar_begin,
    decodificar_carga_fija,
    decodificar_destroy,
    decodificar_end,
    decodificar_extend,
    decodificar_relay,
)
from .constantes import (
    INACTIVIDAD_MAX_CIRCUITO_S,
    INTERVALO_LIMPIEZA_S,
    MAX_CELDAS_DESCONOCIDAS,
    MAX_CIRCUITOS_POR_CONEXION,
    MAX_CIRCUITOS_TOTALES,
    MAX_COLA_CIRCUITO,
    MAX_CONEXIONES_POR_IP,
    MAX_DATOS_RELAY,
    MAX_STREAMS_POR_CIRCUITO,
    TAM_COLA_DATOS,
    TIMEOUT_DESTINO_S,
    TIMEOUT_ENVIO_S,
    TIMEOUT_HANDSHAKE_S,
    VIDA_MAX_CIRCUITO_S,
)
from .directorio import Directorio, Relay
from .errores import (
    CeldaInvalida,
    ClaveInvalida,
    DestinoNoPermitido,
    DirectorioInvalido,
    EnlaceCerrado,
    MiniOniError,
)
from .handshake import TAM_RESPUESTA, TAM_SOLICITUD, relay_responder
from .politica_salida import PoliticaSalida, verificar_ip_destino, verificar_puerto_destino
from .transporte import Enlace

_COMPONENTE = re.compile(r"^[a-z0-9-]{1,24}$")


@dataclass
class ConfigRelay:
    """Límites y tiempos del relay. Las pruebas inyectan valores cortos."""
    timeout_handshake: float = TIMEOUT_HANDSHAKE_S
    inactividad_max: float = INACTIVIDAD_MAX_CIRCUITO_S
    vida_max: float = VIDA_MAX_CIRCUITO_S
    max_conexiones_por_ip: int = MAX_CONEXIONES_POR_IP
    max_circuitos_por_conexion: int = MAX_CIRCUITOS_POR_CONEXION
    max_circuitos_totales: int = MAX_CIRCUITOS_TOTALES
    intervalo_limpieza: float = INTERVALO_LIMPIEZA_S
    timeout_destino: float = TIMEOUT_DESTINO_S
    max_streams_por_circuito: int = MAX_STREAMS_POR_CIRCUITO
    tam_cola_datos: int = TAM_COLA_DATOS
    max_cola_circuito: int = MAX_COLA_CIRCUITO


@dataclass(eq=False)
class HandshakePendiente:
    """Extensión en curso: se envió (o se va a enviar) CREATE al siguiente relay."""
    destino: Relay
    solicitud: bytes                       # B | X
    futuro: asyncio.Future
    enlace: Enlace | None = None
    circ_id: int | None = None
    tarea: asyncio.Task | None = None


@dataclass(eq=False)
class StreamSalida:
    """Una conexión TCP del navegador, abierta por el nodo de salida hacia el destino."""
    stream_id: int
    escritor: asyncio.StreamWriter | None = None
    tarea: asyncio.Task | None = None
    cerrado: bool = False


@dataclass(eq=False)
class EstadoCircuito:
    capa: CapaSalto | None
    anterior: tuple[Enlace, int]           # (enlace, circ_id)
    siguiente: tuple[Enlace, int] | None
    creado: float                          # time.monotonic()
    ultima_actividad: float
    extension_pendiente: HandshakePendiente | None = None
    cerrado: bool = field(default=False)
    # Solo en el nodo de salida:
    streams: dict[int, StreamSalida] = field(default_factory=dict)
    cola: asyncio.Queue | None = None      # mensajes de vuelta en orden (CONNECTED, DATA, END)
    espacio: asyncio.Event | None = None   # puesto cuando la cola baja del límite
    emisor: asyncio.Task | None = None


async def _resolver_sistema(host: str, puerto: int) -> list:
    return await asyncio.get_running_loop().getaddrinfo(
        host, puerto, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)


async def _abrir_tcp(ip: str, puerto: int):
    return await asyncio.open_connection(ip, puerto)


def _destroy(circ_id: int, motivo: int) -> Celda:
    return Celda(circ_id, Comando.DESTROY, codificar_destroy(motivo))


def _end(stream_id: int, motivo: int | None = None) -> MensajeRelay:
    return MensajeRelay(ComandoRelay.END, stream_id, codificar_end(motivo))


def _cerrar_escritor(escritor: asyncio.StreamWriter) -> None:
    try:
        escritor.close()
    except (OSError, RuntimeError):
        pass


# Con 15 días o menos el relay avisa al arrancar (el certificado dura 90): da tiempo
# a renovar y publicar el directorio siguiente antes de que los clientes lo rechacen.
DIAS_AVISO_CERTIFICADO = 15


class NodoRelay:
    def __init__(self, apodo: str, directorio: Directorio, clave_cebolla: X25519PrivateKey,
                 ctx_servidor: ssl.SSLContext | None, config: ConfigRelay | None = None,
                 conectar=None, politica: PoliticaSalida | None = None,
                 resolver=None, abrir_destino=None) -> None:
        propio = next((r for r in directorio.relays if r.apodo == apodo), None)
        if propio is None:
            raise DirectorioInvalido("el relay no está en el directorio")
        self.apodo = apodo
        self.propio = propio
        self.directorio = directorio
        self.config = config or ConfigRelay()
        self._clave = clave_cebolla
        self._ctx = ctx_servidor
        self._ctx_cliente = transporte.contexto_cliente()
        self._conectar = conectar or self._conectar_tls
        self.politica = politica or PoliticaSalida()
        self._resolver = resolver or _resolver_sistema
        self._abrir_destino = abrir_destino or _abrir_tcp
        nombre = f"relay-{apodo}"
        self._componente = nombre if _COMPONENTE.fullmatch(nombre) else "relay"

        self._tabla: dict[tuple[Enlace, int], EstadoCircuito] = {}
        self._circuitos: set[EstadoCircuito] = set()
        self._ids_por_enlace: dict[Enlace, set[int]] = {}
        self._desconocidas: dict[Enlace, int] = {}
        self._enlaces: set[Enlace] = set()
        self._pool: dict[str, Enlace] = {}
        self._locks_pool: dict[str, asyncio.Lock] = {}
        # IP -> conexiones abiertas. Solo en memoria y solo mientras dura la
        # conexión, para aplicar el límite; nunca se imprime ni se guarda.
        self._conexiones_ip: dict[str, int] = {}
        self._tareas: set[asyncio.Task] = set()
        self._servidor: asyncio.AbstractServer | None = None
        self._limpieza: asyncio.Task | None = None
        self._detenido = False
        self.dias_certificado: int | None = None    # lo fija cargar_relay; None = no se conoce

    # --- consultas (también las usan las pruebas) ------------------------------

    @property
    def circuitos_activos(self) -> int:
        return len(self._circuitos)

    @property
    def streams_activos(self) -> int:
        return sum(len(e.streams) for e in self._circuitos)

    def reiniciado(self) -> NodoRelay:
        """Un relay nuevo con las mismas claves ya descifradas (para volver a encenderlo sin contraseña)."""
        nodo = NodoRelay(self.apodo, self.directorio, self._clave, self._ctx, self.config,
                         politica=self.politica, resolver=self._resolver, abrir_destino=self._abrir_destino)
        nodo.dias_certificado = self.dias_certificado
        return nodo

    def tablas_vacias(self) -> bool:
        return not self._circuitos and not self._tabla and not any(self._ids_por_enlace.values())

    def _evento(self, codigo: str, cantidad: int | None = None) -> None:
        consola.evento(self._componente, codigo, cantidad)

    def _tarea(self, coro) -> asyncio.Task:
        t = asyncio.get_running_loop().create_task(coro)
        self._tareas.add(t)
        t.add_done_callback(self._fin_tarea)
        return t

    def _fin_tarea(self, t: asyncio.Task) -> None:
        self._tareas.discard(t)
        if not t.cancelled() and t.exception() is not None:
            self._evento("ERROR_INTERNO")

    def _manejador_excepciones(self, loop, contexto) -> None:
        # Reemplaza al manejador por defecto, que imprimiría trazas y direcciones.
        self._evento("ERROR_INTERNO")

    # --- arranque y apagado ------------------------------------------------------

    async def iniciar(self, host: str | None = None) -> None:
        asyncio.get_running_loop().set_exception_handler(self._manejador_excepciones)
        self._servidor = await asyncio.start_server(
            self._al_conectar, host or self.propio.host, self.propio.puerto,
            ssl=self._ctx, ssl_handshake_timeout=self.config.timeout_handshake,
        )
        self._limpieza = self._tarea(self._limpiar())
        self._evento("ARRANQUE")
        self.avisar_certificado()

    def avisar_certificado(self) -> None:
        """CERTIFICADO_POR_VENCER si quedan DIAS_AVISO_CERTIFICADO días o menos (solo el número)."""
        if self.dias_certificado is not None and self.dias_certificado <= DIAS_AVISO_CERTIFICADO:
            self._evento("CERTIFICADO_POR_VENCER", self.dias_certificado)

    async def servir(self, host: str | None = None) -> None:
        """Atiende hasta que se cancele (Ctrl+C). Siempre termina con un apagado limpio."""
        await self.iniciar(host)
        try:
            await asyncio.Event().wait()
        finally:
            await self.detener()

    async def detener(self, limpio: bool = True) -> None:
        """Apagado: destruye los circuitos (DESTROY 4) y cierra todo.

        Con `limpio=False` corta las conexiones sin avisar (simula una caída).
        Idempotente.
        """
        if self._detenido:
            return
        self._detenido = True
        if self._servidor is not None:
            self._servidor.close()
        if self._limpieza is not None:
            self._limpieza.cancel()
        if limpio:
            for estado in list(self._circuitos):
                await self._destruir(estado, MotivoDestroy.RECURSO)
        for enlace in list(self._enlaces):
            if limpio:
                enlace.cerrar()
            else:
                enlace.abortar()
        tareas = [t for t in self._tareas if t is not asyncio.current_task()]
        for t in tareas:
            t.cancel()
        await asyncio.gather(*tareas, return_exceptions=True)
        for estado in list(self._circuitos):
            await self._destruir(estado, MotivoDestroy.RECURSO)
        if self._servidor is not None:
            try:
                await asyncio.wait_for(self._servidor.wait_closed(), 2)
            except asyncio.TimeoutError:
                pass
            self._servidor = None
        self._evento("APAGADO")

    # --- conexiones ----------------------------------------------------------------

    async def _al_conectar(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        pareja = writer.get_extra_info("peername")
        ip = str(pareja[0]) if pareja else "?"
        if self._conexiones_ip.get(ip, 0) >= self.config.max_conexiones_por_ip:
            self._evento("LIMITE_ALCANZADO")
            writer.transport.abort()
            return
        self._conexiones_ip[ip] = self._conexiones_ip.get(ip, 0) + 1
        enlace = Enlace(reader, writer, saliente=False)
        try:
            await self._atender(enlace, primera_con_timeout=True)
        finally:
            restantes = self._conexiones_ip.get(ip, 1) - 1
            if restantes > 0:
                self._conexiones_ip[ip] = restantes
            else:
                self._conexiones_ip.pop(ip, None)

    async def _atender(self, enlace: Enlace, primera_con_timeout: bool) -> None:
        """Bucle de lectura de un enlace. Tiene manejador de último recurso."""
        self._enlaces.add(enlace)
        self._ids_por_enlace.setdefault(enlace, set())
        try:
            if primera_con_timeout:
                celda = await asyncio.wait_for(enlace.leer_celda(), self.config.timeout_handshake)
                await self.procesar_celda(enlace, celda)
            while not enlace.cerrado:
                await self.procesar_celda(enlace, await enlace.leer_celda())
        except MiniOniError as e:
            if not isinstance(e, EnlaceCerrado):
                self._evento("CELDA_RECHAZADA")
        except (asyncio.TimeoutError, OSError):
            pass
        except Exception:
            self._evento("ERROR_INTERNO")
        finally:
            await self.cerrar_enlace(enlace)

    async def _conectar_tls(self, destino: Relay) -> Enlace:
        return await transporte.conectar(destino, self._ctx_cliente, self.config.timeout_handshake)

    async def _enlace_hacia(self, destino: Relay) -> Enlace:
        """Pool de enlaces salientes: uno por relay de destino, con pinning."""
        lock = self._locks_pool.setdefault(destino.apodo, asyncio.Lock())
        async with lock:
            enlace = self._pool.get(destino.apodo)
            if enlace is not None and not enlace.cerrado:
                return enlace
            try:
                enlace = await self._conectar(destino)
            except MiniOniError:
                self._evento("RELAY_CAIDO")
                raise
            enlace.saliente = True
            self._pool[destino.apodo] = enlace
            self._enlaces.add(enlace)
            self._ids_por_enlace.setdefault(enlace, set())
            self._tarea(self._atender(enlace, primera_con_timeout=False))
            return enlace

    async def cerrar_enlace(self, enlace: Enlace) -> None:
        """Cierra el enlace y destruye todos sus circuitos, avisando al otro lado."""
        enlace.cerrar()
        self._enlaces.discard(enlace)
        self._desconocidas.pop(enlace, None)
        for apodo, e in list(self._pool.items()):
            if e is enlace:
                del self._pool[apodo]
        for cid in list(self._ids_por_enlace.pop(enlace, ())):
            estado = self._tabla.get((enlace, cid))
            if estado is not None:
                await self._destruir(estado, MotivoDestroy.RECURSO, origen=(enlace, cid))

    def _nuevo_circ_id(self, enlace: Enlace) -> int:
        usados = self._ids_por_enlace.setdefault(enlace, set())
        while True:
            cid = secrets.randbelow(2**32 - 1) + 1
            if cid not in usados:
                return cid

    def _registrar(self, lado: tuple[Enlace, int], estado: EstadoCircuito) -> None:
        self._tabla[lado] = estado
        self._ids_por_enlace.setdefault(lado[0], set()).add(lado[1])

    def _olvidar(self, lado: tuple[Enlace, int]) -> None:
        self._tabla.pop(lado, None)
        ids = self._ids_por_enlace.get(lado[0])
        if ids is not None:
            ids.discard(lado[1])

    async def _enviar_silencioso(self, enlace: Enlace, celda: Celda) -> None:
        if enlace.cerrado:
            return
        try:
            await enlace.enviar(celda)
        except MiniOniError:
            pass

    # --- máquina de estados ------------------------------------------------------

    async def procesar_celda(self, enlace: Enlace, celda: Celda) -> None:
        """Procesa una celda ya decodificada que llegó por `enlace`.

        Lanza CeldaInvalida solo ante violaciones del enlace completo (quien
        llama debe cerrarlo). Los errores dentro de un circuito destruyen ese
        circuito y no salen de aquí.
        """
        lado = (enlace, celda.circ_id)
        estado = self._tabla.get(lado)

        if celda.comando == Comando.CREATE:
            if enlace.saliente:
                raise CeldaInvalida("CREATE en un enlace saliente")
            if estado is not None or celda.circ_id in self._ids_por_enlace.get(enlace, ()):
                raise CeldaInvalida("circ_id repetido en el enlace")
            self._desconocidas[enlace] = 0
            await self._crear(enlace, celda)
            return

        if estado is None:
            n = self._desconocidas.get(enlace, 0) + 1
            self._desconocidas[enlace] = n
            if n > MAX_CELDAS_DESCONOCIDAS:
                raise CeldaInvalida("demasiadas celdas para circuitos desconocidos")
            return
        self._desconocidas[enlace] = 0
        estado.ultima_actividad = time.monotonic()

        try:
            if celda.comando == Comando.DESTROY:
                try:
                    motivo = decodificar_destroy(celda.carga)
                except CeldaInvalida:
                    motivo = MotivoDestroy.PROTOCOLO
                await self._destruir(estado, motivo, origen=lado)
            elif celda.comando == Comando.RELAY and lado == estado.anterior:
                await self._relay_ida(estado, celda.carga)
            elif celda.comando == Comando.RELAY and lado == estado.siguiente:
                await self._relay_vuelta(estado, celda.carga)
            elif celda.comando == Comando.CREATED and self._es_pendiente(estado, lado):
                await self._extendido(estado, celda.carga)
            else:
                raise CeldaInvalida("celda inesperada para el estado del circuito")
        except EnlaceCerrado:
            await self._destruir(estado, MotivoDestroy.RECURSO)
        except MiniOniError:
            # CeldaInvalida, CeldaManipulada, DestinoNoPermitido, HandshakeFallido...
            self._evento("CELDA_RECHAZADA")
            await self._destruir(estado, MotivoDestroy.PROTOCOLO)

    @staticmethod
    def _es_pendiente(estado: EstadoCircuito, lado: tuple[Enlace, int]) -> bool:
        p = estado.extension_pendiente
        return p is not None and p.enlace is lado[0] and p.circ_id == lado[1]

    async def _crear(self, enlace: Enlace, celda: Celda) -> None:
        cid = celda.circ_id
        en_enlace = sum(1 for e in self._circuitos if e.anterior[0] is enlace)
        if (en_enlace >= self.config.max_circuitos_por_conexion
                or len(self._circuitos) >= self.config.max_circuitos_totales):
            self._evento("LIMITE_ALCANZADO")
            await enlace.enviar(_destroy(cid, MotivoDestroy.RECURSO))
            return
        try:
            solicitud = decodificar_carga_fija(celda.carga, TAM_SOLICITUD)
            capa, respuesta = relay_responder(self._clave, solicitud)
        except MiniOniError:
            self._evento("CELDA_RECHAZADA")
            await enlace.enviar(_destroy(cid, MotivoDestroy.PROTOCOLO))
            return
        ahora = time.monotonic()
        estado = EstadoCircuito(capa, (enlace, cid), None, ahora, ahora)
        self._circuitos.add(estado)
        self._registrar((enlace, cid), estado)
        await enlace.enviar(Celda(cid, Comando.CREATED, respuesta))
        self._evento("CIRCUITO_CREADO", len(self._circuitos))

    async def _relay_ida(self, estado: EstadoCircuito, carga: bytes) -> None:
        interior = relay_pelar(estado.capa, carga)
        if estado.siguiente is not None:
            enlace, cid = estado.siguiente
            await enlace.enviar(Celda(cid, Comando.RELAY, rellenar(interior)))
            return
        await self._interpretar(estado, decodificar_relay(interior))

    async def _relay_vuelta(self, estado: EstadoCircuito, carga: bytes) -> None:
        enlace, cid = estado.anterior
        await enlace.enviar(Celda(cid, Comando.RELAY, relay_agregar_capa(estado.capa, carga)))

    async def _responder(self, estado: EstadoCircuito, msg: MensajeRelay) -> None:
        """El último salto origina un mensaje de vuelta hacia el cliente."""
        enlace, cid = estado.anterior
        await enlace.enviar(Celda(cid, Comando.RELAY, relay_originar(estado.capa, codificar_relay(msg))))

    async def _interpretar(self, estado: EstadoCircuito, msg: MensajeRelay) -> None:
        if msg.comando == ComandoRelay.EXTEND:
            self._iniciar_extension(estado, msg.datos)
        elif msg.comando == ComandoRelay.ECO:
            # Mismos datos (máx. 448 bytes): sin amplificación.
            await self._responder(estado, MensajeRelay(ComandoRelay.ECO, msg.stream_id, msg.datos))
        elif msg.comando in (ComandoRelay.BEGIN, ComandoRelay.DATA, ComandoRelay.END):
            if not self.propio.salida:
                raise CeldaInvalida("solo el nodo de salida acepta streams")
            await self._mensaje_stream(estado, msg)
        else:
            raise CeldaInvalida("comando relay no admitido")

    # --- streams del nodo de salida ----------------------------------------------

    async def _mensaje_stream(self, estado: EstadoCircuito, msg: MensajeRelay) -> None:
        sid = msg.stream_id
        if sid == 0:
            raise CeldaInvalida("stream_id 0 reservado")
        stream = estado.streams.get(sid)
        if msg.comando == ComandoRelay.BEGIN:
            if stream is not None:
                raise CeldaInvalida("stream_id repetido en el circuito")
            try:
                host, puerto = decodificar_begin(msg.datos)
                verificar_puerto_destino(puerto, self.politica.puertos)
            except DestinoNoPermitido:
                self._evento("DESTINO_BLOQUEADO")
                await self._encolar(estado, _end(sid, MotivoEnd.NO_PERMITIDO))
                return
            if len(estado.streams) >= self.config.max_streams_por_circuito:
                self._evento("LIMITE_ALCANZADO")
                await self._encolar(estado, _end(sid, MotivoEnd.NO_PERMITIDO))
                return
            stream = StreamSalida(sid)
            estado.streams[sid] = stream
            stream.tarea = self._tarea(self._abrir_stream(estado, stream, host, puerto))
        elif msg.comando == ComandoRelay.DATA:
            if stream is None or stream.escritor is None:
                # Stream desconocido (o todavía sin CONNECTED): no se acepta.
                if stream is not None:
                    self._cerrar_stream(estado, stream)
                await self._encolar(estado, _end(sid, MotivoEnd.NO_PERMITIDO))
                return
            try:
                stream.escritor.write(msg.datos)
                await asyncio.wait_for(stream.escritor.drain(), TIMEOUT_ENVIO_S)
            except (ConnectionError, OSError, RuntimeError, asyncio.TimeoutError):
                await self._terminar_stream(estado, stream, MotivoEnd.INALCANZABLE)
        else:
            decodificar_end(msg.datos)   # validación positiva del motivo
            if stream is not None:
                self._cerrar_stream(estado, stream)

    async def _resolver_permitida(self, host: str, puerto: int) -> str:
        """Resuelve una sola vez y devuelve la primera IP que pasa la política de salida."""
        for info in await self._resolver(host, puerto):
            ip = str(info[4][0])
            try:
                verificar_ip_destino(ip, self.politica.excepciones)
            except DestinoNoPermitido:
                continue
            return ip
        raise DestinoNoPermitido("ninguna IP permitida")

    async def _abrir_stream(self, estado: EstadoCircuito, stream: StreamSalida, host: str, puerto: int) -> None:
        """Tarea de un stream: conecta al destino y copia lo que llega hacia el cliente."""
        escritor = None
        try:
            motivo = None
            try:
                ip = await asyncio.wait_for(self._resolver_permitida(host, puerto), self.config.timeout_destino)
                lector, escritor = await asyncio.wait_for(self._abrir_destino(ip, puerto),
                                                          self.config.timeout_destino)
            except DestinoNoPermitido:
                self._evento("DESTINO_BLOQUEADO")
                motivo = MotivoEnd.NO_PERMITIDO
            except asyncio.TimeoutError:
                motivo = MotivoEnd.TIEMPO
            except (OSError, UnicodeError, ValueError):
                motivo = MotivoEnd.INALCANZABLE
            if motivo is not None:
                await self._terminar_stream(estado, stream, motivo)
                return
            if stream.cerrado:
                return
            stream.escritor = escritor
            await self._encolar(estado, MensajeRelay(ComandoRelay.CONNECTED, stream.stream_id, b""))
            try:
                while not stream.cerrado:
                    await self._esperar_espacio(estado)
                    datos = await lector.read(MAX_DATOS_RELAY)
                    if not datos or stream.cerrado:
                        break
                    await self._encolar(estado, MensajeRelay(ComandoRelay.DATA, stream.stream_id, datos))
            except (ConnectionError, OSError):
                motivo = MotivoEnd.INALCANZABLE
            await self._terminar_stream(estado, stream, motivo)
        except asyncio.CancelledError:
            raise
        except Exception:
            self._evento("ERROR_INTERNO")
            self._cerrar_stream(estado, stream)
        finally:
            if escritor is not None:
                _cerrar_escritor(escritor)

    async def _esperar_espacio(self, estado: EstadoCircuito) -> None:
        """Presión hacia atrás: no se lee del destino mientras la cola del circuito esté llena."""
        while (estado.cola is not None and not estado.cerrado
               and estado.cola.qsize() >= self.config.tam_cola_datos):
            estado.espacio.clear()
            await estado.espacio.wait()

    def _cerrar_stream(self, estado: EstadoCircuito, stream: StreamSalida) -> None:
        """Cierra el socket del destino y olvida el stream, sin avisar al cliente."""
        if stream.cerrado:
            return
        stream.cerrado = True
        if estado.streams.get(stream.stream_id) is stream:
            del estado.streams[stream.stream_id]
        if stream.escritor is not None:
            _cerrar_escritor(stream.escritor)
            stream.escritor = None
        if stream.tarea is not None and stream.tarea is not asyncio.current_task():
            stream.tarea.cancel()

    async def _terminar_stream(self, estado: EstadoCircuito, stream: StreamSalida,
                               motivo: int | None) -> None:
        """Cierra el stream y avisa al cliente con END (motivo genérico o cierre normal)."""
        if stream.cerrado:
            return
        self._cerrar_stream(estado, stream)
        await self._encolar(estado, _end(stream.stream_id, motivo))

    async def _encolar(self, estado: EstadoCircuito, msg: MensajeRelay) -> None:
        """Pone un mensaje de vuelta en la cola del circuito (un único emisor lo sella en orden)."""
        if estado.cerrado:
            return
        if estado.cola is None:
            estado.cola = asyncio.Queue()
            estado.espacio = asyncio.Event()
            estado.espacio.set()
            estado.emisor = self._tarea(self._emitir(estado))
        if estado.cola.qsize() >= self.config.max_cola_circuito:
            # El cliente no lee lo que pide: se corta el circuito (ASVS V2.4.1).
            self._evento("LIMITE_ALCANZADO")
            await self._destruir(estado, MotivoDestroy.RECURSO)
            return
        estado.cola.put_nowait(msg)

    async def _emitir(self, estado: EstadoCircuito) -> None:
        cola = estado.cola
        try:
            while not estado.cerrado:
                msg = await cola.get()
                if cola.qsize() < self.config.tam_cola_datos:
                    estado.espacio.set()
                if estado.cerrado:
                    return
                await self._responder(estado, msg)
                estado.ultima_actividad = time.monotonic()
        except asyncio.CancelledError:
            raise
        except Exception:
            # Enlace hacia atrás caído u otro error: fallo cerrado.
            await self._destruir(estado, MotivoDestroy.RECURSO)

    # --- extensión del circuito ------------------------------------------------

    def _iniciar_extension(self, estado: EstadoCircuito, datos: bytes) -> None:
        if estado.siguiente is not None or estado.extension_pendiente is not None:
            raise CeldaInvalida("el circuito ya se extendió")
        host, puerto, B, X = decodificar_extend(datos)
        destino = self.directorio.buscar(host, puerto)
        # Solo hacia relays del directorio, con su clave publicada y nunca hacia sí mismo:
        # EXTEND no puede usarse como conexión arbitraria (ASVS V11.6.1).
        if (destino is None or destino.apodo == self.apodo
                or not hmac.compare_digest(B, destino.clave_cebolla)):
            raise CeldaInvalida("EXTEND no permitido")
        pendiente = HandshakePendiente(destino, B + X, asyncio.get_running_loop().create_future())
        estado.extension_pendiente = pendiente
        pendiente.tarea = self._tarea(self._extender(estado, pendiente))

    async def _extender(self, estado: EstadoCircuito, pendiente: HandshakePendiente) -> None:
        try:
            await asyncio.wait_for(self._enviar_create(estado, pendiente), self.config.timeout_handshake)
        except asyncio.CancelledError:
            raise
        except Exception:
            # Relay inalcanzable, huella TLS distinta o sin CREATED a tiempo.
            await self._destruir(estado, MotivoDestroy.RECURSO)

    async def _enviar_create(self, estado: EstadoCircuito, pendiente: HandshakePendiente) -> None:
        enlace = await self._enlace_hacia(pendiente.destino)
        if estado.cerrado:
            return
        cid = self._nuevo_circ_id(enlace)
        pendiente.enlace, pendiente.circ_id = enlace, cid
        self._registrar((enlace, cid), estado)
        await enlace.enviar(Celda(cid, Comando.CREATE, pendiente.solicitud))
        await pendiente.futuro

    async def _extendido(self, estado: EstadoCircuito, carga: bytes) -> None:
        respuesta = decodificar_carga_fija(carga, TAM_RESPUESTA)
        pendiente = estado.extension_pendiente
        estado.siguiente = (pendiente.enlace, pendiente.circ_id)
        estado.extension_pendiente = None
        if not pendiente.futuro.done():
            pendiente.futuro.set_result(None)
        await self._responder(estado, MensajeRelay(ComandoRelay.EXTENDED, 0, respuesta))

    # --- destrucción y limpieza -------------------------------------------------

    async def _destruir(self, estado: EstadoCircuito, motivo: int,
                        origen: tuple[Enlace, int] | None = None) -> None:
        """Quita el circuito de todas las tablas y avisa a los lados que no lo pidieron."""
        if estado.cerrado:
            return
        estado.cerrado = True
        self._circuitos.discard(estado)
        pendiente = estado.extension_pendiente
        lados = [estado.anterior, estado.siguiente]
        if pendiente is not None:
            if pendiente.enlace is not None:
                lados.append((pendiente.enlace, pendiente.circ_id))
            if pendiente.tarea is not None and pendiente.tarea is not asyncio.current_task():
                pendiente.tarea.cancel()
            if not pendiente.futuro.done():
                pendiente.futuro.cancel()
        for lado in lados:
            if lado is not None:
                self._olvidar(lado)
        for stream in list(estado.streams.values()):
            self._cerrar_stream(estado, stream)
        if estado.emisor is not None and estado.emisor is not asyncio.current_task():
            estado.emisor.cancel()
        if estado.espacio is not None:
            estado.espacio.set()
        estado.cola = None
        # Las claves de salto solo viven en memoria: se sueltan las referencias.
        estado.capa = None
        estado.extension_pendiente = None
        for lado in lados:
            if lado is not None and lado != origen:
                await self._enviar_silencioso(lado[0], _destroy(lado[1], motivo))
        self._evento("CIRCUITO_CERRADO", len(self._circuitos))

    async def limpiar_una_vez(self, ahora: float | None = None) -> None:
        ahora = time.monotonic() if ahora is None else ahora
        cfg = self.config
        for estado in list(self._circuitos):
            if (ahora - estado.ultima_actividad > cfg.inactividad_max
                    or ahora - estado.creado > cfg.vida_max):
                await self._destruir(estado, MotivoDestroy.TIEMPO)
        for enlace in list(self._enlaces):
            if not self._ids_por_enlace.get(enlace) and ahora - enlace.ultima_actividad > cfg.inactividad_max:
                enlace.cerrar()   # su bucle de lectura termina y lo saca de las tablas

    async def _limpiar(self) -> None:
        while True:
            await asyncio.sleep(self.config.intervalo_limpieza)
            try:
                await self.limpiar_una_vez()
            except Exception:
                self._evento("ERROR_INTERNO")


# --- carga desde disco ---------------------------------------------------------

def verificar_identidad(apodo: str, directorio: Directorio, carpeta_claves: Path) -> Relay:
    """Comprueba, sin contraseña, que cebolla.pub y tls.crt coinciden con el directorio."""
    propio = next((r for r in directorio.relays if r.apodo == apodo), None)
    if propio is None:
        raise DirectorioInvalido("el relay no está en el directorio")
    carpeta = Path(carpeta_claves) / apodo
    try:
        huella = transporte.huella_certificado(carpeta / "tls.crt")
    except (OSError, ValueError):
        raise ClaveInvalida("certificado TLS ilegible") from None
    if ak.cargar_publica(carpeta / "cebolla.pub") != propio.clave_cebolla:
        raise ClaveInvalida("la clave cebolla no coincide con el directorio")
    if not hmac.compare_digest(huella, propio.huella_tls):
        raise ClaveInvalida("el certificado TLS no coincide con el directorio")
    try:
        der = ssl.PEM_cert_to_DER_cert((carpeta / "tls.crt").read_text(encoding="ascii"))
    except (OSError, ValueError):
        raise ClaveInvalida("certificado TLS ilegible") from None
    transporte.verificar_vigencia(der)   # un relay no arranca con su certificado vencido
    return propio


def dias_certificado(apodo: str, carpeta_claves: Path) -> int:
    """Días que le quedan al tls.crt del relay (ver transporte.dias_restantes)."""
    try:
        der = ssl.PEM_cert_to_DER_cert((Path(carpeta_claves) / apodo / "tls.crt").read_text(encoding="ascii"))
    except (OSError, ValueError):
        raise ClaveInvalida("certificado TLS ilegible") from None
    return transporte.dias_restantes(der)


def cargar_relay(apodo: str, directorio: Directorio, carpeta_claves: Path, contrasena: str,
                 config: ConfigRelay | None = None, politica: PoliticaSalida | None = None) -> NodoRelay:
    """Descifra cebolla.key y tls.key con la misma contraseña y arma el relay."""
    propio = verificar_identidad(apodo, directorio, carpeta_claves)
    carpeta = Path(carpeta_claves) / apodo
    clave = X25519PrivateKey.from_private_bytes(ak.cargar_privada(carpeta / "cebolla.key", contrasena, "x25519"))
    if clave.public_key().public_bytes_raw() != propio.clave_cebolla:
        raise ClaveInvalida("la clave cebolla no coincide con el directorio")
    der_tls = ak.cargar_privada(carpeta / "tls.key", contrasena, "p256-pkcs8")
    try:
        ctx = transporte.contexto_servidor(carpeta / "tls.crt", der_tls)
    except (ssl.SSLError, ValueError, OSError):
        raise ClaveInvalida("la clave TLS no corresponde al certificado") from None
    nodo = NodoRelay(apodo, directorio, clave, ctx, config, politica=politica)
    nodo.dias_certificado = dias_certificado(apodo, carpeta_claves)
    return nodo
