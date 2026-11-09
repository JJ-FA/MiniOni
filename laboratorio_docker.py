"""Laboratorio MiniOni en Docker con redes segmentadas (semana 4, ISO/IEC 27033).

Uso (PowerShell, con el entorno activo, Docker Desktop abierto y desde la carpeta del proyecto):
    python laboratorio_docker.py preparar     # firma config/directorio.docker.json (IP 10.10.x)
    python laboratorio_docker.py iniciar      # construye la imagen, levanta redes y relays, pide la contraseña
    python laboratorio_docker.py iniciar --con-internet   # igual, y el relay de salida llega a Internet
    python laboratorio_docker.py probar       # segmentación + eco + página por el proxy
    python laboratorio_docker.py estado       # contenedores y su endurecimiento
    python laboratorio_docker.py eventos entrada1   # eventos en vivo de un relay (Ctrl+C para salir)
    python laboratorio_docker.py detener      # apaga todo y borra las redes

Después de `iniciar`, el navegador usa el proxy de siempre, apuntando a la entrada que
Docker publica en 127.0.0.1:9001:
    python cliente_proxy.py --directorio config/directorio.docker.json --entrada-via 127.0.0.1:9001

Contraseña: se pide UNA vez con getpass, se comprueba aquí descifrando una clave y se
escribe en la entrada estándar de cada relay (docker attach). Nunca va en argumentos,
variables de entorno, archivos ni en la imagen (NIST SSDF PS.1.1).

Registros: los contenedores usan el controlador de registro "none" de Docker, que no
guarda la consola en disco. `eventos` muestra la consola en vivo sin guardarla.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import queue
import shutil
import subprocess  # nosec B404 - solo se ejecuta el cliente de Docker con listas fijas, sin shell
import sys
import threading
import time
from pathlib import Path

from minioni import almacen_claves as ak
from minioni import consola
from minioni import directorio as dirmod
from minioni.errores import ClaveInvalida, MiniOniError

RAIZ = Path(__file__).resolve().parent
CONFIG = RAIZ / "config"
DIRECTORIO_DOCKER = "directorio.docker.json"
ULTIMA_DOCKER = "ultima_version.docker"
PROYECTO = "minioni"
IMAGEN = "minioni:semana4"
RELAYS = ("entrada1", "medio1", "salida1")
CONTENEDORES = {apodo: f"minioni-{apodo}" for apodo in (*RELAYS, "web", "puerta")}
ESPERA_ARRANQUE_S = 60

# Segmentación esperada (ISO/IEC 27033): desde cada red solo se alcanza UN servicio.
REDES_ESPERADAS = {
    "red_cliente": {"entrada1"},
    "red_entrada_medio": {"medio1"},
    "red_medio_salida": {"salida1"},
    "red_destinos": {"web"},
}
OBJETIVOS = ("entrada1", "medio1", "salida1", "web", "internet")

# Las mismas restricciones de docker-compose.yml para los contenedores de la sonda.
ENDURECIDO = ["--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
              "--user", "10001:10001", "--log-driver", "none", "--pids-limit", "64",
              "--memory", "256m",
              # /tmp en memoria y privado (ver docker-compose.yml); no es un directorio del equipo.
              "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=1m,uid=10001,gid=10001,mode=0700"]  # nosec B108


class ErrorLaboratorio(Exception):
    """Error con un mensaje fijo para el usuario (nunca salida cruda de Docker)."""


# Lo que puede fallar al hablar con Docker. El panel lo convierte en un mensaje genérico.
ERRORES_DOCKER = (OSError, ValueError, subprocess.SubprocessError)


def _imprimir(texto: str) -> None:
    print(texto, flush=True)


def _sin_aviso(_texto: str) -> None:
    pass


# --- Docker ----------------------------------------------------------------------

def _docker() -> str:
    ruta = shutil.which("docker")
    if ruta is None:
        raise ErrorLaboratorio("no se encontró Docker. Instala y abre Docker Desktop (ver docs/SEMANA4_DOCKER.md).")
    return ruta


def _entorno() -> dict:
    """Entorno para docker compose: solo la ruta de la carpeta de claves (no es un secreto)."""
    claves = ak.carpeta_claves()
    if not claves.is_absolute():
        claves = RAIZ / claves
    entorno = dict(os.environ)
    entorno["MINIONI_CARPETA_CLAVES"] = claves.resolve().as_posix()
    return entorno


def _ejecutar(argumentos: list[str], capturar: bool = True, timeout: float = 600) -> subprocess.CompletedProcess:
    return subprocess.run([_docker(), *argumentos], cwd=RAIZ, env=_entorno(),  # nosec B603 - lista fija, sin shell
                          capture_output=capturar, timeout=timeout)


def _compose(*argumentos: str, capturar: bool = True, timeout: float = 600,
             internet: bool = False) -> subprocess.CompletedProcess:
    archivos = ["-f", str(RAIZ / "docker-compose.yml")]
    if internet:
        archivos += ["-f", str(RAIZ / "docker-compose.internet.yml")]
    return _ejecutar(["compose", "-p", PROYECTO, *archivos, *argumentos], capturar, timeout)


def _comprobar_docker() -> None:
    r = _ejecutar(["info", "--format", "{{.ServerVersion}}"], timeout=30)
    if r.returncode != 0:
        raise ErrorLaboratorio("Docker no responde. Abre Docker Desktop y espera a que diga «Engine running».")


# --- directorio de Docker ---------------------------------------------------------

def _verificar_directorio_docker() -> dirmod.Directorio:
    try:
        return dirmod.verificar((CONFIG / DIRECTORIO_DOCKER).read_bytes(),
                                ak.cargar_publica(CONFIG / "autoridad.pub"))
    except (MiniOniError, OSError):
        raise ErrorLaboratorio("falta config/directorio.docker.json o no es válido (¿venció?). "
                               "Ejecuta: python laboratorio_docker.py preparar") from None


def _claves_relays(claves: Path) -> None:
    for apodo in RELAYS:
        carpeta = claves / apodo
        if not all((carpeta / n).exists() for n in ("cebolla.key", "cebolla.pub", "tls.key", "tls.crt")):
            raise ErrorLaboratorio(f"faltan las claves de {apodo}. Ejecuta primero: "
                                   "python minioni_admin.py preparar-laboratorio")


def preparar(contrasena: str | None = None, dias: int = 7) -> Path:
    """Firma config/directorio.docker.json con las IP de Docker (config/relays.json).

    El directorio local (directorio.firmado.json) no se toca, y cada uno tiene su
    propio contador anti-rollback.
    """
    from minioni import admin

    claves = ak.carpeta_claves()
    _claves_relays(claves)
    version = admin._version_siguiente(CONFIG, DIRECTORIO_DOCKER, ULTIMA_DOCKER)
    for intento in range(1, 4):
        clave = contrasena if contrasena is not None else getpass.getpass("Contraseña de las claves: ")
        try:
            return admin.publicar_directorio(clave, claves, CONFIG, version, dias,
                                             CONFIG / "relays.json", DIRECTORIO_DOCKER)
        except ClaveInvalida:
            if contrasena is not None:
                raise
            print(f"Contraseña incorrecta (intento {intento} de 3).", file=sys.stderr)
    raise ErrorLaboratorio("3 intentos fallidos.")


# --- iniciar -------------------------------------------------------------------------

def _pedir_y_comprobar_contrasena(claves: Path) -> str:
    """La contraseña se comprueba aquí (descifrando una clave) antes de entregarla."""
    for intento in range(1, 4):
        contrasena = getpass.getpass("Contraseña de las claves: ")
        try:
            ak.cargar_privada(claves / "entrada1" / "cebolla.key", contrasena, "x25519")
            return contrasena
        except ClaveInvalida:
            print(f"Contraseña incorrecta (intento {intento} de 3).", file=sys.stderr)
    raise ErrorLaboratorio("3 intentos fallidos; no se arrancó ningún relay.")


def _lector(flujo, cola: queue.Queue) -> None:
    for linea in iter(flujo.readline, b""):
        cola.put(linea)
    cola.put(None)


def entregar_contrasena(contenedor: str, contrasena: str, espera: float = ESPERA_ARRANQUE_S) -> bool:
    """Escribe la contraseña en la entrada estándar del relay y espera «nodo iniciado».

    `docker attach` conecta con la consola del contenedor sin guardarla; al terminar se
    corta la conexión y el relay sigue funcionando. Devuelve False si el relay terminó
    o no arrancó a tiempo.
    """
    proceso = subprocess.Popen([_docker(), "attach", "--sig-proxy=false", contenedor],  # nosec B603 - lista fija
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               cwd=RAIZ)
    cola: queue.Queue = queue.Queue()
    threading.Thread(target=_lector, args=(proceso.stdout, cola), daemon=True).start()
    try:
        time.sleep(0.5)   # que el attach quede conectado antes de escribir
        proceso.stdin.write(contrasena.encode("utf-8") + b"\n")
        proceso.stdin.flush()
        limite = time.monotonic() + espera
        while time.monotonic() < limite:
            try:
                linea = cola.get(timeout=0.5)
            except queue.Empty:
                continue
            if linea is None:
                return False   # el relay terminó (contraseña o claves que no coinciden)
            if consola.EVENTOS["ARRANQUE"].encode("utf-8") in linea:
                return True
        return False
    finally:
        proceso.kill()
        proceso.wait(timeout=10)


def _levantar(contrasena: str, internet: bool, avisar, capturar: bool) -> None:
    """Construye la imagen, crea redes y contenedores y entrega la contraseña a cada relay.

    `avisar` recibe solo textos fijos de progreso. Si un relay no arranca se apaga todo
    (fallo cerrado): nunca queda un laboratorio a medias.
    """
    avisar("[2/4] Construyendo la imagen (la primera vez descarga python:3.14-slim) ...")
    if _compose("build", capturar=capturar).returncode != 0:
        raise ErrorLaboratorio("no se pudo construir la imagen (revisa la conexión a Internet de Docker).")
    _compose("down", "--remove-orphans", timeout=120, internet=True)
    if _compose("up", "-d", internet=internet).returncode != 0:
        raise ErrorLaboratorio("no se pudieron crear las redes o los contenedores. Si dice que la subred ya "
                               "existe, ejecuta: python laboratorio_docker.py detener")
    avisar("[3/4] Redes y contenedores creados; entregando la contraseña a los relays")
    for apodo in RELAYS:
        try:
            arranco = entregar_contrasena(CONTENEDORES[apodo], contrasena)
        except (OSError, subprocess.SubprocessError):
            arranco = False
        avisar(f"      {apodo:<9} ... {'OK' if arranco else 'FALLO'}")
        if not arranco:
            _compose("down", timeout=120, internet=True)
            raise ErrorLaboratorio(f"{apodo} no arrancó (¿las claves coinciden con el directorio? "
                                   "Prueba: python laboratorio_docker.py preparar). Se apagó todo.")


def iniciar_con_contrasena(contrasena: str, internet: bool = False, avisar=_sin_aviso) -> None:
    """Lo mismo que `iniciar`, para el panel: la contraseña ya la escribió la persona.

    Solo viaja como argumento hasta la entrada estándar de cada relay. Se comprueba
    descifrando una clave ANTES de crear nada: si es incorrecta, sale ClaveInvalida
    y no se arranca ningún contenedor.
    """
    _comprobar_docker()
    claves = ak.carpeta_claves()
    _claves_relays(claves)
    d = _verificar_directorio_docker()
    avisar(f"[1/4] Directorio de Docker verificado (versión {d.version})")
    ak.cargar_privada(claves / "entrada1" / "cebolla.key", contrasena, "x25519")
    _levantar(contrasena, internet, avisar, capturar=True)


def iniciar(internet: bool = False) -> None:
    _comprobar_docker()
    claves = ak.carpeta_claves()
    _claves_relays(claves)
    d = _verificar_directorio_docker()
    print(f"[1/4] Directorio de Docker verificado (versión {d.version})")
    contrasena = _pedir_y_comprobar_contrasena(claves)
    try:
        _levantar(contrasena, internet, _imprimir, capturar=False)
    finally:
        del contrasena
    modo = ("con Internet solo para el relay de salida" if internet
            else "cerrado: solo la web del laboratorio, sin Internet")
    print(f"[4/4] Laboratorio en marcha ({modo}).\n\n"
          "Siguiente paso, en otra ventana de PowerShell:\n"
          "  python cliente_proxy.py --directorio config/directorio.docker.json --entrada-via 127.0.0.1:9001\n"
          "y en Firefox (proxy 127.0.0.1:9050) abre: http://web/\n"
          "Para comprobar la segmentación: python laboratorio_docker.py probar")


# --- probar ----------------------------------------------------------------------------

def _sonda(red: str, modo: str, archivos: dict[str, Path] | None = None) -> dict:
    """Contenedor desechable y endurecido conectado SOLO a `red`; devuelve el JSON de la sonda."""
    argumentos = ["run", "--rm", "--network", f"{PROYECTO}_{red}", *ENDURECIDO]
    for destino, origen in (archivos or {}).items():
        argumentos += ["--mount", f"type=bind,source={origen.resolve()},target={destino},readonly"]
    r = _ejecutar([*argumentos, IMAGEN, "python", "docker/sonda.py", modo], timeout=180)
    try:
        return json.loads(r.stdout.decode("utf-8").strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"error": "la sonda no respondió"}


def matriz_segmentacion() -> list[dict]:
    """Una fila por red: {'red', 'alcanza': {objetivo: bool} o None, 'ok'}."""
    filas = []
    for red, esperado in REDES_ESPERADAS.items():
        alcanza = _sonda(red, "alcance").get("alcanza")
        if not isinstance(alcanza, dict):
            filas.append({"red": red, "alcanza": None, "ok": False})
            continue
        celdas = {o: bool(alcanza.get(o)) for o in OBJETIVOS}
        filas.append({"red": red, "alcanza": celdas, "ok": {o for o in OBJETIVOS if celdas[o]} == esperado})
    return filas


def probar_segmentacion() -> bool:
    print("Segmentación (ISO/IEC 27033): a qué llega un equipo conectado a cada red")
    print(f"  {'red':<19}" + "".join(f"{o:<10}" for o in OBJETIVOS) + "resultado")
    filas = matriz_segmentacion()
    for fila in filas:
        if fila["alcanza"] is None:
            print(f"  {fila['red']:<19}FALLO (la sonda no pudo conectarse a la red)")
            continue
        celdas = "".join(f"{('sí' if fila['alcanza'][o] else 'no'):<10}" for o in OBJETIVOS)
        print(f"  {fila['red']:<19}{celdas}{'OK' if fila['ok'] else 'FALLO'}")
    return all(fila["ok"] for fila in filas)


def probar_punta_a_punta() -> bool:
    print("\nDe punta a punta, desde la red del cliente (sonda con el proxy de MiniOni):")
    r = _sonda("red_cliente", "punta-a-punta", {
        "/app/config/autoridad.pub": CONFIG / "autoridad.pub",
        f"/app/config/{DIRECTORIO_DOCKER}": CONFIG / DIRECTORIO_DOCKER,
    })
    filas = [("Eco por 3 saltos", r.get("eco")),
             ("Página de http://web/ por el proxy SOCKS5", r.get("pagina")),
             (f"El destino ve al relay de salida ({r.get('ip_que_ve_el_destino')}), no al cliente",
              r.get("destino_no_ve_al_cliente")),
             ("Puerto 22 bloqueado por la política de salida", r.get("puerto_22_bloqueado")),
             ("Relay interno 10.10.2.10 bloqueado como destino", r.get("relay_interno_bloqueado"))]
    for texto, ok in filas:
        print(f"  [{'OK   ' if ok else 'FALLO'}] {texto}")
    return all(ok for _, ok in filas)


def _eco_desde_el_equipo(timeout: float = 5) -> bool:
    """Eco por 3 saltos desde este equipo, por la entrada que Docker publica en 127.0.0.1:9001."""
    import asyncio

    from minioni.celdas import ComandoRelay, MensajeRelay
    from minioni.circuito import CircuitoCliente, elegir_ruta

    async def eco(d) -> bool:
        c = CircuitoCliente(timeout=timeout, entrada_via=("127.0.0.1", 9001))
        try:
            await c.construir(d, elegir_ruta(d))
            await c.enviar(MensajeRelay(ComandoRelay.ECO, 0, b"hola desde el equipo"))
            m = await asyncio.wait_for(c.recibir(), timeout)
            return m.comando == ComandoRelay.ECO and m.datos == b"hola desde el equipo"
        finally:
            await c.cerrar()

    try:
        return asyncio.run(eco(_verificar_directorio_docker()))
    except (MiniOniError, TimeoutError):
        return False


def probar_desde_el_equipo() -> bool:
    print("\nDesde este equipo (entrada publicada en 127.0.0.1:9001):")
    ok = _eco_desde_el_equipo()
    print(f"  [{'OK   ' if ok else 'FALLO'}] Eco por 3 saltos usando la entrada publicada")
    return ok


def probar_fallo_cerrado() -> bool:
    """Con el relay intermedio en pausa no hay circuito, y nada sale por otro camino (ASVS V16.5.3)."""
    print("\nFallo cerrado (se pausa medio1 unos segundos):")
    if _ejecutar(["pause", CONTENEDORES["medio1"]], timeout=30).returncode != 0:
        print("  [FALLO] No se pudo pausar medio1")
        return False
    try:
        sin_circuito = not _eco_desde_el_equipo(timeout=3)
    finally:
        _ejecutar(["unpause", CONTENEDORES["medio1"]], timeout=30)
    print(f"  [{'OK   ' if sin_circuito else 'FALLO'}] Con medio1 en pausa la conexión falla (no hay ruta alternativa)")
    recupera = _eco_desde_el_equipo()
    print(f"  [{'OK   ' if recupera else 'FALLO'}] Al reanudar medio1 los circuitos vuelven a funcionar")
    return sin_circuito and recupera


def probar() -> bool:
    _comprobar_docker()
    _verificar_directorio_docker()
    resultados = [probar_segmentacion(), probar_punta_a_punta(), probar_desde_el_equipo(), probar_fallo_cerrado()]
    print("\n" + ("Todo correcto." if all(resultados) else "Hay pruebas con FALLO (ver arriba)."))
    return all(resultados)


# --- estado, eventos, detener -----------------------------------------------------------

def estado() -> None:
    """Estado y endurecimiento de cada contenedor, leído de Docker (evidencia para el informe)."""
    _comprobar_docker()
    print(f"  {'contenedor':<18}{'estado':<11}{'usuario':<13}{'solo lect.':<12}{'capacidades':<13}registros")
    for nombre in CONTENEDORES.values():
        r = _ejecutar(["inspect", nombre], timeout=30)
        if r.returncode != 0:
            print(f"  {nombre:<18}no existe")
            continue
        info = json.loads(r.stdout.decode("utf-8"))[0]
        host = info.get("HostConfig", {})
        quitadas = host.get("CapDrop") or []
        print(f"  {nombre:<18}{info['State']['Status']:<11}{info['Config'].get('User') or 'root':<13}"
              f"{('sí' if host.get('ReadonlyRootfs') else 'NO'):<12}"
              f"{('ninguna' if 'ALL' in quitadas else 'algunas'):<13}"
              f"{host.get('LogConfig', {}).get('Type', '?')}")


def contenedores_sin_registros() -> bool:
    """True solo si Docker confirma, en todos, registros apagados y disco de solo lectura."""
    for nombre in CONTENEDORES.values():
        r = _ejecutar(["inspect", nombre], timeout=30)
        if r.returncode != 0:
            return False
        host = json.loads(r.stdout.decode("utf-8"))[0].get("HostConfig", {})
        if host.get("LogConfig", {}).get("Type") != "none" or not host.get("ReadonlyRootfs"):
            return False
    return True


def _pausa(comando: str, apodo: str) -> None:
    if apodo not in RELAYS:
        raise ErrorLaboratorio("relay desconocido.")
    if _ejecutar([comando, CONTENEDORES[apodo]], timeout=30).returncode != 0:
        raise ErrorLaboratorio(f"no se pudo cambiar el estado de {apodo}.")


def pausar(apodo: str) -> None:
    """Congela un relay (demostración de fallo cerrado desde el panel)."""
    _pausa("pause", apodo)


def reanudar(apodo: str) -> None:
    _pausa("unpause", apodo)


def eventos(apodo: str) -> None:
    if apodo not in CONTENEDORES:
        raise ErrorLaboratorio("apodo desconocido: usa entrada1, medio1, salida1, web o puerta.")
    print("Eventos en vivo (no se guardan en ningún archivo). Ctrl+C para salir.", flush=True)
    try:
        _ejecutar(["attach", "--no-stdin", "--sig-proxy=false", CONTENEDORES[apodo]],
                  capturar=False, timeout=24 * 3600)
    except KeyboardInterrupt:
        pass


def detener() -> None:
    _comprobar_docker()
    _compose("down", "--remove-orphans", timeout=180, internet=True)
    print("Laboratorio detenido: contenedores y redes eliminados (no quedan registros que borrar).")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="laboratorio_docker", description="Laboratorio MiniOni en Docker")
    sub = p.add_subparsers(dest="cmd", required=True)
    pre = sub.add_parser("preparar", help="firma config/directorio.docker.json")
    pre.add_argument("--dias", type=int, default=7)
    ini = sub.add_parser("iniciar", help="construye y arranca el laboratorio")
    ini.add_argument("--con-internet", action="store_true",
                     help="conecta SOLO el relay de salida a Internet (docker-compose.internet.yml)")
    sub.add_parser("probar", help="segmentación y prueba de punta a punta")
    sub.add_parser("estado", help="contenedores y su endurecimiento")
    ev = sub.add_parser("eventos", help="eventos en vivo de un contenedor")
    ev.add_argument("apodo")
    sub.add_parser("detener", help="apaga y elimina contenedores y redes")
    args = p.parse_args(argv)
    os.chdir(RAIZ)   # claves/ y config/ se resuelven siempre desde la carpeta del proyecto
    try:
        if args.cmd == "preparar":
            ruta = preparar(dias=args.dias)
            d = _verificar_directorio_docker()
            print(f"Directorio de Docker firmado: config/{ruta.name} (versión {d.version}, "
                  f"{len(d.relays)} relays en 10.10.x). El directorio local no cambió.")
        elif args.cmd == "iniciar":
            iniciar(args.con_internet)
        elif args.cmd == "probar":
            return 0 if probar() else 1
        elif args.cmd == "estado":
            estado()
        elif args.cmd == "eventos":
            eventos(args.apodo)
        elif args.cmd == "detener":
            detener()
    except ErrorLaboratorio as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except MiniOniError as e:
        print(f"Error: {e.mensaje_publico}", file=sys.stderr)
        return 1
    except (OSError, subprocess.SubprocessError):
        print("Error: no se pudo comunicar con Docker.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    consola.instalar_manejador_global("laboratorio")
    sys.exit(main())
