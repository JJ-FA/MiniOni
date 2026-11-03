"""Cliente de circuitos: elige la ruta y construye un circuito de 3 saltos.

Fallo cerrado (ASVS V16.5.3): cualquier error al construir o usar el
circuito lo cierra todo y lanza una subclase de MiniOniError. Nunca hay
plan B fuera del circuito: este módulo no abre conexiones a destinos, solo
al relay de entrada del directorio, con pinning TLS.
"""

from __future__ import annotations

import asyncio
import secrets
import ssl

from . import transporte
from .capas import CapaSalto, cliente_envolver, cliente_pelar
from .celdas import (
    Celda,
    Comando,
    ComandoRelay,
    MensajeRelay,
    MotivoDestroy,
    codificar_destroy,
    codificar_extend,
    codificar_relay,
    decodificar_carga_fija,
    decodificar_destroy,
    decodificar_relay,
)
from .constantes import MAX_SALTOS, TAM_CLAVE_PUBLICA, TIMEOUT_HANDSHAKE_S
from .directorio import Directorio, Relay
from .errores import CeldaInvalida, CircuitoCerrado, HandshakeFallido, MiniOniError
from .handshake import TAM_RESPUESTA, HandshakeCliente
from .transporte import Enlace


def elegir_ruta(directorio: Directorio) -> list[Relay]:
    """3 relays distintos al azar (CSPRNG); el último es de salida y, si se puede, los otros no."""
    azar = secrets.SystemRandom()
    ultimo = azar.choice([r for r in directorio.relays if r.salida])
    resto = [r for r in directorio.relays if r is not ultimo]
    no_salida = [r for r in resto if not r.salida]
    if len(no_salida) >= MAX_SALTOS - 1:
        primeros = azar.sample(no_salida, MAX_SALTOS - 1)
    else:
        otros = [r for r in resto if r.salida]
        primeros = no_salida + azar.sample(otros, MAX_SALTOS - 1 - len(no_salida))
        azar.shuffle(primeros)
    return primeros + [ultimo]


class CircuitoCliente:
    def __init__(self, timeout: float = TIMEOUT_HANDSHAKE_S, ctx: ssl.SSLContext | None = None) -> None:
        self._timeout = timeout
        self._ctx = ctx
        self._capas: list[CapaSalto] = []
        self.enlace: Enlace | None = None
        self.circ_id: int | None = None
        self.ruta: list[Relay] = []
        self.cerrado = False
        self.motivo_cierre: int | None = None
        self._destruido_remoto = False

    @property
    def saltos(self) -> int:
        return len(self._capas)

    async def construir(self, directorio: Directorio, ruta: list[Relay], al_avanzar=None) -> None:
        """CREATE al primer relay y EXTEND a los siguientes. Máximo len(ruta) × timeout en total.

        `al_avanzar(i, relay, listo)` se llama antes (listo=False) y después
        (listo=True) de cada salto; sirve para mostrar el progreso.
        """
        if (not 1 <= len(ruta) <= MAX_SALTOS or len({r.apodo for r in ruta}) != len(ruta)
                or any(r not in directorio.relays for r in ruta)):
            raise HandshakeFallido("ruta inválida")
        try:
            await asyncio.wait_for(self._construir(ruta, al_avanzar), len(ruta) * self._timeout)
        except MiniOniError:
            await self.cerrar()
            raise
        except (asyncio.TimeoutError, OSError):
            await self.cerrar()
            raise HandshakeFallido("tiempo agotado al construir el circuito") from None
        except BaseException:
            await self.cerrar()
            raise
        self.ruta = list(ruta)

    async def _construir(self, ruta: list[Relay], al_avanzar) -> None:
        avisar = al_avanzar or (lambda i, relay, listo: None)
        avisar(1, ruta[0], False)
        self.enlace = await transporte.conectar(ruta[0], self._ctx, self._timeout)
        self.circ_id = secrets.randbelow(2**32 - 1) + 1
        estado, solicitud = HandshakeCliente.iniciar(ruta[0].clave_cebolla)
        await self.enlace.enviar(Celda(self.circ_id, Comando.CREATE, solicitud))
        celda = await self._leer_propia()
        if celda.comando != Comando.CREATED:
            raise CeldaInvalida("se esperaba CREATED")
        self._capas.append(estado.finalizar(decodificar_carga_fija(celda.carga, TAM_RESPUESTA)))
        avisar(1, ruta[0], True)
        for i, relay in enumerate(ruta[1:], start=2):
            avisar(i, relay, False)
            estado, solicitud = HandshakeCliente.iniciar(relay.clave_cebolla)
            datos = codificar_extend(relay.host, relay.puerto, solicitud[:TAM_CLAVE_PUBLICA],
                                     solicitud[TAM_CLAVE_PUBLICA:])
            await self.enviar(MensajeRelay(ComandoRelay.EXTEND, 0, datos))
            msg = await self.recibir()
            if msg.comando != ComandoRelay.EXTENDED or msg.stream_id != 0:
                raise HandshakeFallido("se esperaba EXTENDED")
            self._capas.append(estado.finalizar(msg.datos))
            avisar(i, relay, True)

    async def _leer_propia(self) -> Celda:
        """Lee la siguiente celda del enlace; un DESTROY se convierte en CircuitoCerrado."""
        celda = await self.enlace.leer_celda()
        if celda.circ_id != self.circ_id:
            raise CeldaInvalida("celda de otro circuito")
        if celda.comando == Comando.DESTROY:
            try:
                motivo = int(decodificar_destroy(celda.carga))
            except CeldaInvalida:
                motivo = int(MotivoDestroy.PROTOCOLO)
            self.motivo_cierre = motivo
            self._destruido_remoto = True
            raise CircuitoCerrado("el relay destruyó el circuito", motivo)
        return celda

    async def enviar(self, mensaje: MensajeRelay) -> None:
        if self.cerrado or self.enlace is None or not self._capas:
            raise CircuitoCerrado("circuito no disponible")
        try:
            carga = cliente_envolver(self._capas, codificar_relay(mensaje))
            await self.enlace.enviar(Celda(self.circ_id, Comando.RELAY, carga))
        except MiniOniError:
            await self.cerrar()
            raise

    async def recibir(self) -> MensajeRelay:
        if self.cerrado or self.enlace is None:
            raise CircuitoCerrado("circuito no disponible")
        try:
            celda = await self._leer_propia()
            if celda.comando != Comando.RELAY:
                raise CeldaInvalida("se esperaba RELAY")
            return decodificar_relay(cliente_pelar(self._capas, celda.carga))
        except MiniOniError:
            await self.cerrar()
            raise

    async def cerrar(self) -> None:
        """Envía DESTROY(3) si el circuito sigue vivo y cierra el enlace. Idempotente."""
        if self.cerrado:
            return
        self.cerrado = True
        enlace = self.enlace
        if enlace is not None and not enlace.cerrado and self.circ_id and not self._destruido_remoto:
            try:
                await asyncio.wait_for(
                    enlace.enviar(Celda(self.circ_id, Comando.DESTROY, codificar_destroy(MotivoDestroy.CLIENTE))),
                    2,
                )
            except (MiniOniError, asyncio.TimeoutError):
                pass
        if enlace is not None:
            enlace.cerrar()
        self._capas.clear()
