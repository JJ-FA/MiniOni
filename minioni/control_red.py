"""Control de la red completa (3 relays + proxy) desde una sola ventana. Lo usa `panel.py`.

No depende de tkinter: corre su propio bucle asyncio en un hilo aparte y
la ventana solo le pide acciones (`ejecutar`) y lee `instantanea`. Así se
prueba con pytest sin abrir ventanas.

Mismas reglas que el resto de MiniOni:
- Los eventos llegan por `consola.suscribir`: código del catálogo y una
  cantidad, nunca IP, dominios ni puertos (ASVS V16.2.5).
- La contraseña se usa una vez para descifrar las claves y no se guarda; un
  relay apagado se vuelve a encender con las claves que ya están en memoria.
- Las pruebas (eco y página) solo se conectan al relay de entrada o al
  proxy en 127.0.0.1: nunca hay conexión directa al destino (ASVS V16.5.3).

Modo Docker (semana 4): los relays viven en contenedores que maneja el
`orquestador` que recibe el constructor (`laboratorio_docker` en el panel, uno
simulado en las pruebas). Aquí corre solo el proxy, y la contraseña solo pasa
como argumento hasta la entrada estándar de cada relay.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import contextlib
import ipaddress
import queue
import secrets
import ssl
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

from . import admin, confianza_windows, consola, sin_registros, socks5
from . import almacen_claves as ak
from . import directorio as dirmod
from .celdas import ComandoRelay, MensajeRelay, validar_host
from .circuito import CircuitoCliente, elegir_ruta
from .constantes import HOST_PROXY, MAX_DATOS_RELAY, PUERTO_PROXY
from .errores import (
    ConfiguracionInvalida,
    DestinoNoPermitido,
    MiniOniError,
    PruebaFallida,
)
from .politica_salida import cargar_politica
from .proxy import GestorCircuitos, ServidorProxy, cargar_directorio, leer_ultima_version, ruta_ultima_version
from .relay import ConfigRelay, NodoRelay, cargar_relay, verificar_identidad

MAX_BYTES_PRUEBA = 5 * 1024 * 1024
# Buscador para la verificación «sin registros» (versión HTML, sin JavaScript).
BUSCADOR_PRUEBA = "https://html.duckduckgo.com/html/?q="
# Sin Internet, la búsqueda testigo va a la web del laboratorio (red_destinos).
BUSCADOR_DOCKER = "http://web/?q="
TIMEOUT_PRUEBA_S = 30
DIRECTORIO_DOCKER = "directorio.docker.json"
ENTRADA_DOCKER = ("127.0.0.1", 9001)   # el único puerto que Docker publica en este equipo
ESPERA_CIERRE_DOCKER_S = 120


def _es_ip(texto: str) -> bool:
    try:
        ipaddress.ip_address(texto)
    except ValueError:
        return False
    return True


def _motivo_certificado(codigo: int) -> str:
    """Mensaje corto por motivo de rechazo del certificado (códigos de OpenSSL)."""
    if codigo == 10:
        return "el certificado del sitio está vencido"
    if codigo == 62:
        return "el certificado es de otro sitio"
    if codigo in (18, 19):
        return "el sitio usa un certificado autofirmado"
    return "el certificado del sitio no es de confianza"


def es_local(d: dirmod.Directorio) -> bool:
    """True si todos los relays del directorio están en este computador (127.0.0.1)."""
    return all(r.host == "127.0.0.1" for r in d.relays)


class ControladorRed:
    def __init__(self, carpeta_config: Path = Path("config"), carpeta_claves: Path = Path("claves"),
                 puerto_proxy: int = PUERTO_PROXY, config_relay: ConfigRelay | None = None,
                 orquestador=None) -> None:
        self.config = Path(carpeta_config)
        self.claves = Path(carpeta_claves)
        self._puerto_proxy = puerto_proxy
        self._config_relay = config_relay
        self._orq = orquestador
        self.modo = "local"
        self.con_internet = False
        self.aviso = ""                    # progreso del arranque en Docker (solo textos fijos)
        self._entrada_via: tuple[str, int] | None = None   # solo con el laboratorio Docker en marcha
        self._salidas: dict[str, bool] = {}
        self.directorio: dirmod.Directorio | None = None
        self.nodos: dict[str, NodoRelay] = {}
        self._activos: dict[str, bool] = {}
        self.proxy: ServidorProxy | None = None
        self._bloqueados = 0
        self._eventos: queue.Queue = queue.Queue()
        self._baja = consola.suscribir(self._al_evento)
        self.instantanea = self._calcular()
        self._loop = asyncio.new_event_loop()
        self._hilo = threading.Thread(target=self._correr, name="minioni-red", daemon=True)
        self._hilo.start()

    # --- hilo de la red ----------------------------------------------------------

    def _correr(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.create_task(self._refrescar())
        self._loop.run_forever()
        # Cancela lo que quede (refresco, conexiones a medio cerrar) antes de cerrar el bucle,
        # así no aparecen avisos de tareas destruidas en el registro.
        pendientes = asyncio.all_tasks(self._loop)
        for tarea in pendientes:
            tarea.cancel()
        self._loop.run_until_complete(asyncio.gather(*pendientes, return_exceptions=True))
        self._loop.close()

    async def _refrescar(self) -> None:
        while True:
            self.instantanea = self._calcular()
            await asyncio.sleep(0.25)

    def ejecutar(self, coro) -> concurrent.futures.Future:
        """Corre una corrutina en el hilo de la red. Devuelve un Future (no bloquea)."""
        return asyncio.run_coroutine_threadsafe(coro, self._loop)

    def _al_evento(self, componente: str, codigo: str, cantidad: int | None) -> None:
        if codigo == "DESTINO_BLOQUEADO":
            self._bloqueados += 1
        self._eventos.put((time.time(), componente, codigo, cantidad))

    def eventos_nuevos(self) -> list[tuple]:
        """(hora, componente, código, cantidad) desde la última llamada."""
        nuevos = []
        while True:
            try:
                nuevos.append(self._eventos.get_nowait())
            except queue.Empty:
                return nuevos

    def _calcular(self) -> dict:
        proxy = self.proxy
        return {
            "en_marcha": proxy is not None,
            "nodos": dict(self._activos),
            "salidas": {**self._salidas, **{a: n.propio.salida for a, n in self.nodos.items()}},
            "proxy": proxy is not None,
            "puerto_proxy": proxy.puerto if proxy else self._puerto_proxy,
            "circuitos": proxy.gestor.circuitos if proxy else 0,
            "conexiones": proxy.conexiones_activas if proxy else 0,
            "bloqueados": self._bloqueados,
        }

    # --- modo Docker -----------------------------------------------------------------

    @property
    def docker_disponible(self) -> bool:
        return self._orq is not None

    def cambiar_modo(self, modo: str) -> None:
        """Elige 'local' o 'docker'. Solo con la red detenida."""
        if modo not in ("local", "docker") or (modo == "docker" and self._orq is None):
            raise ConfiguracionInvalida("modo no disponible")
        if self.proxy is not None:
            raise ConfiguracionInvalida("detén la red antes de cambiar de modo")
        self.modo = modo

    def _llamar(self, funcion, *args, **kw):
        """Llama al orquestador convirtiendo cualquier fallo en un error genérico de MiniOni."""
        try:
            return funcion(*args, **kw)
        except self._orq.ErrorLaboratorio as e:   # sus mensajes son fijos, nunca salida de Docker
            raise PruebaFallida(str(e).rstrip(".")) from None
        except self._orq.ERRORES_DOCKER:
            raise PruebaFallida("no se pudo comunicar con Docker") from None
        except SystemExit:
            raise ConfiguracionInvalida("faltan claves o config/relays.json") from None

    def _avisar(self, texto: str) -> None:
        self.aviso = texto.strip()

    def publicar_directorio_docker(self, contrasena: str) -> int:
        """Firma config/directorio.docker.json (no toca el local). Devuelve la versión."""
        if self._orq is None:
            raise ConfiguracionInvalida("modo no disponible")
        if self.proxy is not None:
            raise ConfiguracionInvalida("detén la red antes de publicar")
        self._llamar(self._orq.preparar, contrasena)
        return self.revisar_directorio()["version"]

    # --- directorio ------------------------------------------------------------------

    def _revisar_directorio_docker(self) -> dict:
        ruta = self.config / DIRECTORIO_DOCKER
        try:
            minima = leer_ultima_version(ruta_ultima_version(self.config, ruta))
            d = dirmod.verificar(ruta.read_bytes(), ak.cargar_publica(self.config / "autoridad.pub"),
                                 version_minima=minima)
        except (MiniOniError, OSError, ValueError):
            return {"estado": "invalido", "version": None, "relays": []}
        return {"estado": "docker", "version": d.version, "relays": [(r.apodo, r.salida) for r in d.relays]}

    def revisar_directorio(self) -> dict:
        """Sin modificar nada. {'estado': 'local' | 'remoto' | 'docker' | 'invalido', 'version', 'relays': [(apodo, salida)]}."""
        if self.modo == "docker":
            return self._revisar_directorio_docker()
        try:
            minima = leer_ultima_version(self.config / "ultima_version")
            d = dirmod.verificar((self.config / "directorio.firmado.json").read_bytes(),
                                 ak.cargar_publica(self.config / "autoridad.pub"), version_minima=minima)
        except (MiniOniError, OSError, ValueError):
            return {"estado": "invalido", "version": None, "relays": []}
        return {"estado": "local" if es_local(d) else "remoto", "version": d.version,
                "relays": [(r.apodo, r.salida) for r in d.relays]}

    def publicar_directorio_local(self, contrasena: str) -> int:
        """Firma un directorio nuevo con config/relays.local.json (versión siguiente). Devuelve la versión."""
        if self.proxy is not None:
            raise ConfiguracionInvalida("detén la red antes de publicar")
        version = leer_ultima_version(self.config / "ultima_version")
        # Si el directorio actual está vencido o no existe, se publica uno nuevo igual.
        with contextlib.suppress(MiniOniError, OSError, ValueError):
            actual = dirmod.verificar((self.config / "directorio.firmado.json").read_bytes(),
                                      ak.cargar_publica(self.config / "autoridad.pub"))
            version = max(version, actual.version)
        try:
            admin.publicar_directorio(contrasena, self.claves, self.config, version + 1, 7,
                                      relays=self.config / "relays.local.json")
        except SystemExit:
            raise ConfiguracionInvalida("faltan claves o relays.local.json") from None
        except (OSError, ValueError):
            raise ConfiguracionInvalida("no se pudo publicar el directorio") from None
        return version + 1

    # --- arranque y apagado ---------------------------------------------------------

    async def _iniciar_docker(self, contrasena: str, internet: bool) -> int:
        """Levanta el laboratorio con el orquestador y, en este equipo, solo el proxy."""
        ruta = self.config / DIRECTORIO_DOCKER
        d = cargar_directorio(ruta, self.config / "autoridad.pub", ruta_ultima_version(self.config, ruta))
        try:
            await asyncio.to_thread(self._llamar, self._orq.iniciar_con_contrasena, contrasena,
                                    internet=internet, avisar=self._avisar)
        finally:
            self.aviso = ""
        try:
            proxy = ServidorProxy(d, puerto=self._puerto_proxy, gestor=GestorCircuitos(d, entrada_via=ENTRADA_DOCKER))
            await proxy.iniciar()
        except BaseException:   # fallo cerrado: sin proxy no queda el laboratorio a medias
            with contextlib.suppress(MiniOniError):
                await asyncio.to_thread(self._llamar, self._orq.detener)
            raise
        self.proxy, self.directorio, self._entrada_via, self.con_internet = proxy, d, ENTRADA_DOCKER, internet
        self._activos = {r.apodo: True for r in d.relays}
        self._salidas = {r.apodo: r.salida for r in d.relays}
        for relay in d.relays:
            consola.evento(f"relay-{relay.apodo}", "ARRANQUE")
        self.instantanea = self._calcular()
        return len(d.relays)

    async def iniciar(self, contrasena: str, internet: bool = False) -> int:
        """Verifica el directorio, descifra las claves y levanta todos los relays y el proxy.

        `internet` solo cuenta en modo Docker: conecta a Internet únicamente el relay de salida.
        """
        if self.proxy is not None:
            return len(self._activos)
        if self.modo == "docker":
            return await self._iniciar_docker(contrasena, internet)
        d = cargar_directorio(self.config / "directorio.firmado.json", self.config / "autoridad.pub",
                              self.config / "ultima_version")
        if not es_local(d):
            raise ConfiguracionInvalida("el directorio no es local")
        politica = cargar_politica(self.config / "politica_salida.json")
        nodos = {}
        for relay in d.relays:
            verificar_identidad(relay.apodo, d, self.claves)
            # scrypt es lento: en otro hilo, para que el bucle siga respondiendo.
            nodos[relay.apodo] = await asyncio.to_thread(
                cargar_relay, relay.apodo, d, self.claves, contrasena, self._config_relay, politica)
        iniciados = []
        try:
            for apodo, nodo in nodos.items():
                await nodo.iniciar()
                iniciados.append(nodo)
                self._activos[apodo] = True
            self.nodos = nodos
            self.directorio = d
            proxy = ServidorProxy(d, puerto=self._puerto_proxy)
            await proxy.iniciar()
            self.proxy = proxy
        except BaseException:
            for nodo in iniciados:
                await nodo.detener()
            self.nodos, self._activos, self.proxy = {}, {}, None
            raise
        self.instantanea = self._calcular()
        return len(nodos)

    async def detener(self) -> None:
        if self.proxy is not None:
            await self.proxy.detener()
            self.proxy = None
        if self._entrada_via is not None:
            self._entrada_via, self.directorio, self.con_internet = None, None, False
            self._activos, self._salidas = {}, {}
            try:
                await asyncio.to_thread(self._llamar, self._orq.detener)
            finally:
                self.instantanea = self._calcular()
            return
        for apodo, nodo in self.nodos.items():
            if self._activos.get(apodo):
                await nodo.detener()
        self.nodos, self._activos = {}, {}
        self.instantanea = self._calcular()

    async def alternar(self, apodo: str) -> bool:
        """Apaga o enciende un relay (demostración de fallo cerrado). Devuelve el nuevo estado."""
        if self._entrada_via is not None:
            if apodo not in self._activos:
                raise ConfiguracionInvalida("relay desconocido")
            encendido = self._activos[apodo]
            await asyncio.to_thread(self._llamar, self._orq.pausar if encendido else self._orq.reanudar, apodo)
            self._activos[apodo] = not encendido
            self.instantanea = self._calcular()
            return not encendido
        nodo = self.nodos.get(apodo)
        if nodo is None:
            raise ConfiguracionInvalida("relay desconocido")
        if self._activos.get(apodo):
            await nodo.detener()
            self._activos[apodo] = False
        else:
            nuevo = nodo.reiniciado()
            await nuevo.iniciar()
            self.nodos[apodo] = nuevo
            self._activos[apodo] = True
        self.instantanea = self._calcular()
        return self._activos[apodo]

    # --- pruebas ---------------------------------------------------------------------

    async def probar_circuito(self, mensaje: bytes = b"hola MiniOni") -> tuple[float, int]:
        """ECO por un circuito nuevo de 3 saltos. Devuelve (milisegundos, saltos)."""
        if self.directorio is None:
            raise PruebaFallida("primero inicia la red")
        circuito = CircuitoCliente(entrada_via=self._entrada_via)
        try:
            await circuito.construir(self.directorio, elegir_ruta(self.directorio))
            inicio = time.perf_counter()
            await circuito.enviar(MensajeRelay(ComandoRelay.ECO, 0, mensaje))
            respuesta = await asyncio.wait_for(circuito.recibir(), TIMEOUT_PRUEBA_S)
            ms = (time.perf_counter() - inicio) * 1000
            if respuesta.comando != ComandoRelay.ECO or respuesta.datos != mensaje:
                raise PruebaFallida("el eco no coincide")
            return ms, circuito.saltos
        except asyncio.TimeoutError:
            raise PruebaFallida("sin respuesta del circuito") from None
        except PruebaFallida:
            raise
        except MiniOniError:
            raise PruebaFallida("no se pudo construir el circuito") from None
        finally:
            await circuito.cerrar()

    async def probar_url(self, url: str) -> tuple[int, int, float]:
        """Pide `url` a través del proxy SOCKS5 (DNS remoto). Devuelve (código HTTP, bytes, ms)."""
        if self.proxy is None:
            raise PruebaFallida("primero inicia la red")
        partes = urlsplit(url.strip())
        try:
            if partes.scheme not in ("http", "https") or not partes.hostname:
                raise ValueError
            host = validar_host(partes.hostname)
            puerto = partes.port or (443 if partes.scheme == "https" else 80)
        except (ValueError, DestinoNoPermitido):
            raise PruebaFallida("dirección no válida (usa http:// o https://)") from None
        inicio = time.perf_counter()
        try:
            try:
                return await asyncio.wait_for(self._pedir(partes, host, puerto, inicio), TIMEOUT_PRUEBA_S)
            except ssl.SSLCertVerificationError as e:
                # Raíz que Windows aún no descargó: se le pide la verificación al propio Windows.
                if e.verify_code != confianza_windows.CODIGO_SIN_EMISOR_LOCAL or not confianza_windows.disponible():
                    raise
                return await asyncio.wait_for(self._pedir(partes, host, puerto, inicio, verifica_windows=True),
                                              TIMEOUT_PRUEBA_S)
        except asyncio.TimeoutError:
            raise PruebaFallida("tiempo agotado") from None
        except ssl.SSLCertVerificationError as e:
            raise PruebaFallida(_motivo_certificado(e.verify_code)) from None
        except ssl.SSLError:
            raise PruebaFallida("la conexión cifrada con el sitio falló") from None
        except (OSError, asyncio.IncompleteReadError, ValueError, IndexError):
            raise PruebaFallida("la conexión se cerró") from None

    async def probar_segmentacion(self) -> list[dict]:
        """Matriz de a qué llega un equipo conectado a cada red (ISO/IEC 27033)."""
        if self._entrada_via is None:
            raise PruebaFallida("primero inicia la red en modo Docker")
        return await asyncio.to_thread(self._llamar, self._orq.matriz_segmentacion)

    async def _contenedores_sin_registros(self) -> bool | None:
        """None en modo local. Si no se puede confirmar, cuenta como no confirmado (fallo cerrado)."""
        if self._entrada_via is None:
            return None
        try:
            return await asyncio.to_thread(self._llamar, self._orq.contenedores_sin_registros)
        except MiniOniError:
            return False

    async def verificar_sin_registros(self, buscador: str | None = None,
                                      carpetas: list[Path] | None = None) -> sin_registros.InformeRegistros:
        """Búsqueda testigo por MiniOni vigilando disco y consola (ver `sin_registros.py`)."""
        if self.proxy is None:
            raise PruebaFallida("primero inicia la red")
        if buscador is None:
            buscador = BUSCADOR_DOCKER if self._entrada_via is not None and not self.con_internet else BUSCADOR_PRUEBA
        testigo = "minioni" + secrets.token_hex(6)   # palabra inventada, única en el mundo
        url = buscador + testigo
        dominio = urlsplit(url).hostname or ""
        # Se rastrean el testigo y el nombre del buscador. Una IP literal no es un nombre
        # buscado y las de 127.0.0.1 están (legítimamente) en el directorio de relays. Un
        # nombre sin punto («web») tampoco sirve de rastro: aparecería en cualquier archivo.
        rastros = [testigo] if _es_ip(dominio) or "." not in dominio else [testigo, dominio]
        if carpetas is None:
            carpetas = [self.config, self.claves, Path.cwd(), Path(tempfile.gettempdir())]
        inicio = time.time()
        with sin_registros.VigiaEscrituras() as vigia, sin_registros.EspejoConsola() as espejo:
            try:
                codigo, total, _ = await self.probar_url(url)
                busqueda, ok = f"HTTP {codigo} · {total:,} bytes por 3 saltos".replace(",", "."), True
            except PruebaFallida as e:
                busqueda, ok = e.mensaje_publico, False
            # Deja que circuitos y streams terminen de cerrarse dentro de la ventana vigilada.
            await asyncio.sleep(1.5)
        archivos, revisados = await asyncio.to_thread(
            sin_registros.buscar_en_archivos, carpetas, rastros, inicio)
        en_consola = any(r and r in espejo.texto for r in rastros)
        contenedores = await self._contenedores_sin_registros()
        return sin_registros.InformeRegistros(testigo, dominio, busqueda, ok, list(vigia.escrituras),
                                              en_consola, archivos, revisados, time.time() - inicio, contenedores)

    async def _pedir(self, partes, host: str, puerto: int, inicio: float,
                     verifica_windows: bool = False) -> tuple[int, int, float]:
        # Única conexión: al proxy local. El destino lo alcanza el circuito.
        lector, escritor = await asyncio.open_connection(HOST_PROXY, self.proxy.puerto)
        try:
            escritor.write(socks5.SALUDO_ACEPTADO[:1] + b"\x01\x00")
            await escritor.drain()
            if await lector.readexactly(2) != socks5.SALUDO_ACEPTADO:
                raise PruebaFallida("el proxy rechazó la conexión")
            nombre = host.encode("ascii")
            escritor.write(b"\x05\x01\x00\x03" + bytes([len(nombre)]) + nombre + puerto.to_bytes(2, "big"))
            await escritor.drain()
            codigo = (await lector.readexactly(10))[1]
            if codigo == socks5.NO_PERMITIDO:
                raise PruebaFallida("destino bloqueado por la política de salida")
            if codigo != socks5.EXITO:
                raise PruebaFallida("sin circuito o destino inalcanzable (fallo cerrado)")
            if partes.scheme == "https":
                if not verifica_windows:
                    await escritor.start_tls(ssl.create_default_context(), server_hostname=host)
                else:
                    # La verificación la hace Windows justo después del handshake y ANTES de
                    # enviar un solo byte al sitio: si rechaza, se corta sin pedir nada.
                    contexto = ssl.create_default_context()
                    contexto.check_hostname = False
                    contexto.verify_mode = ssl.CERT_NONE  # nosec B501 - verificado por Windows abajo
                    await escritor.start_tls(contexto, server_hostname=host)
                    cadena = escritor.get_extra_info("ssl_object").get_unverified_chain() or []
                    if not await asyncio.to_thread(confianza_windows.verificar_cadena, list(cadena), host):
                        raise PruebaFallida("el certificado del sitio no es de confianza")
            ruta = (partes.path or "/") + (f"?{partes.query}" if partes.query else "")
            escritor.write(f"GET {ruta} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: MiniOni-panel\r\n"
                           "Connection: close\r\n\r\n".encode("ascii", "ignore"))
            await escritor.drain()
            primera = await lector.readline()
            estado = int(primera.split()[1])
            total = len(primera)
            while total < MAX_BYTES_PRUEBA:
                bloque = await lector.read(16 * MAX_DATOS_RELAY)
                if not bloque:
                    break
                total += len(bloque)
            return estado, total, (time.perf_counter() - inicio) * 1000
        finally:
            escritor.close()

    # --- cierre --------------------------------------------------------------------

    def cerrar(self, timeout: float = 10) -> None:
        """Apaga la red y el hilo. Se llama al cerrar la ventana."""
        if self._entrada_via is not None:   # docker compose down tarda más que apagar relays locales
            timeout = max(timeout, ESPERA_CIERRE_DOCKER_S)
        with contextlib.suppress(concurrent.futures.TimeoutError, MiniOniError, OSError):
            self.ejecutar(self.detener()).result(timeout)
        self._baja()
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._hilo.join(timeout)
