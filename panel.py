"""Panel gráfico de MiniOni: levanta y controla la red completa desde una sola ventana.

Uso (desde la carpeta del proyecto):
    python panel.py
    python panel.py --puerto 9150          # otro puerto para el proxy SOCKS5

Hace lo mismo que las 4 ventanas de PowerShell (3 relays + proxy), con
botones para las demostraciones: probar el circuito, abrir una página por
MiniOni, apagar y encender cada relay (fallo cerrado) y publicar el
directorio local. Solo biblioteca estándar (tkinter): ninguna dependencia nueva.

Privacidad (ASVS V16.2.5): el registro de eventos muestra exactamente los
eventos genéricos de la consola, nunca IP, dominios ni puertos de clientes.
La contraseña se usa una vez para descifrar las claves y se borra del campo.

Con el selector Local / Docker, la misma ventana maneja el laboratorio de la
semana 4: los relays corren en contenedores con redes segmentadas y la
contraseña se escribe en la entrada estándar de cada relay.
"""

from __future__ import annotations

import argparse
import queue
import sys
import time
import tkinter as tk
import tkinter.font as tkfont
import webbrowser
from pathlib import Path

import laboratorio_docker
from minioni import almacen_claves as ak
from minioni import consola
from minioni.constantes import HOST_PROXY, PUERTO_PROXY
from minioni.control_red import ControladorRed
from minioni.proxy import argumento_puerto
from minioni.errores import ClaveInvalida, ConfiguracionInvalida, DirectorioInvalido, MiniOniError

# --- estilo: vinotinto con negro --------------------------------------------------
VINO = "#A30000"
VINO_HOVER = "#C10000"
VINO_CLARO = "#E86A6A"     # texto vinotinto legible sobre negro
VINO_OSCURO = "#2A0505"
NEGRO = "#0A0A0C"
TARJETA = "#141417"
TARJETA_HOVER = "#1E1E23"
LINEA = "#2A2A30"
TEXTO = "#EDEDEF"
TEXTO2 = "#9A9AA2"
VERDE = "#5DBB63"
ALERTA = "#FF4D4D"

ANCHO = 980
URL_LOCAL = "https://example.com"
URL_DOCKER = "http://web/"
CARPETA_PROYECTO = Path(__file__).resolve().parent
EVENTOS_ALERTA = {"CIRCUITO_FALLIDO", "CERTIFICADO_POR_VENCER", "DESTINO_BLOQUEADO", "RELAY_CAIDO", "CELDA_RECHAZADA",
                  "LIMITE_ALCANZADO", "ERROR_INTERNO", "DIRECTORIO_INVALIDO"}

F = {}   # fuentes, se eligen al arrancar según lo instalado


def elegir_fuentes() -> None:
    disponibles = set(tkfont.families())
    sans = next((f for f in ("Segoe UI", "Segoe UI Variable Text", "Arial") if f in disponibles), "TkDefaultFont")
    titulo = next((f for f in ("Segoe UI Variable Display", "Segoe UI", "Arial") if f in disponibles), sans)
    mono = next((f for f in ("Cascadia Mono", "Consolas", "Courier New") if f in disponibles), "TkFixedFont")
    F.update(texto=(sans, 10), chico=(sans, 9), negrita=(sans, 12, "bold"), numero=(titulo, 24, "bold"),
             titulo=(titulo, 26, "bold"), mono=(mono, 10), seccion=(mono, 9, "bold"), mono_chico=(mono, 8))


def mezclar(c1: str, c2: str, t: float) -> str:
    a = [int(c1[i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(c2[i:i + 2], 16) for i in (1, 3, 5)]
    return "#" + "".join(f"{round(x + (y - x) * t):02x}" for x, y in zip(a, b))


def degradado(canvas: tk.Canvas, x0: int, y0: int, x1: int, y1: int, colores: list[str]) -> None:
    """Degradado horizontal entre varios colores (líneas verticales de 1 px)."""
    tramos = len(colores) - 1
    for x in range(x0, x1):
        t = (x - x0) / max(1, x1 - x0 - 1) * tramos
        i = min(int(t), tramos - 1)
        canvas.create_line(x, y0, x, y1, fill=mezclar(colores[i], colores[i + 1], t - i))


def franja_peligro(canvas: tk.Canvas, ancho: int, alto: int) -> None:
    canvas.create_rectangle(0, 0, ancho, alto, fill=NEGRO, width=0)
    for x in range(-alto, ancho + alto, 26):
        canvas.create_polygon(x, alto, x + alto, 0, x + alto + 12, 0, x + 12, alto, fill=VINO, width=0)


def tarjeta(padre, **kw) -> tk.Frame:
    return tk.Frame(padre, bg=TARJETA, highlightthickness=1, highlightbackground=LINEA, **kw)


def seccion(padre, texto: str) -> tk.Label:
    return tk.Label(padre, text=f"// {texto}", font=F["seccion"], fg=VINO_CLARO, bg=padre["bg"])


def texto_matriz(filas: list[dict]) -> str:
    """Matriz de segmentación en columnas, para mostrarla con fuente monoespaciada."""
    objetivos = next((list(f["alcanza"]) for f in filas if f["alcanza"]), [])
    lineas = [f"{'red':<19}" + "".join(f"{o:<10}" for o in objetivos) + "resultado"]
    for f in filas:
        if f["alcanza"] is None:
            lineas.append(f"{f['red']:<19}FALLO (la sonda no pudo conectarse a la red)")
            continue
        celdas = "".join(f"{'sí' if f['alcanza'][o] else 'no':<10}" for o in objetivos)
        lineas.append(f"{f['red']:<19}{celdas}{'OK' if f['ok'] else 'FALLO'}")
    return "\n".join(lineas)


class Boton(tk.Frame):
    """Botón plano con borde de 1 px y efecto al pasar el ratón."""

    def __init__(self, padre, texto: str, comando, principal: bool = False, chico: bool = False) -> None:
        self.principal = principal
        super().__init__(padre, bg=VINO if principal else LINEA, padx=1, pady=1)
        self._fondo = VINO if principal else TARJETA
        self._hover = VINO_HOVER if principal else TARJETA_HOVER
        self.b = tk.Button(self, text=texto, command=comando, cursor="hand2", relief="flat", bd=0,
                           font=F["chico"] if chico else F["texto"], padx=10 if chico else 14,
                           pady=3 if chico else 6, bg=self._fondo, fg="#FFFFFF" if principal else TEXTO,
                           activebackground=self._hover, activeforeground="#FFFFFF",
                           disabledforeground="#55555C", highlightthickness=0)
        self.b.pack()
        self.b.bind("<Enter>", lambda _: self.b["state"] == "normal" and self.b.configure(bg=self._hover))
        self.b.bind("<Leave>", lambda _: self.b.configure(bg=self._fondo))
        self.configure(highlightthickness=0)

    def texto(self, texto: str) -> None:
        self.b.configure(text=texto)

    def activo(self, si: bool) -> None:
        self.b.configure(state="normal" if si else "disabled")


class Panel:
    def __init__(self, raiz: tk.Tk, control: ControladorRed) -> None:
        self.raiz = raiz
        self.control = control
        self._resultados: queue.Queue = queue.Queue()
        self._ocupado = False
        self._tarjetas: dict[str, dict] = {}
        self._apodos: list[tuple[str, bool]] = []

        raiz.title("MiniOni · panel de control")
        raiz.configure(bg=NEGRO)
        raiz.resizable(False, False)
        raiz.protocol("WM_DELETE_WINDOW", self.cerrar)

        self._cabecera()
        cuerpo = tk.Frame(raiz, bg=NEGRO, padx=22, pady=6)
        cuerpo.pack(fill="both", expand=True)
        self._arranque(cuerpo)
        seccion(cuerpo, "NODOS").pack(anchor="w", pady=(10, 5))
        self.fila_nodos = tk.Frame(cuerpo, bg=NEGRO)
        self.fila_nodos.pack(fill="x")
        self._metricas(cuerpo)
        self._pruebas(cuerpo)
        self._eventos(cuerpo)
        pie = tk.Canvas(raiz, width=ANCHO, height=5, bg=NEGRO, highlightthickness=0)
        pie.pack(fill="x")
        degradado(pie, 0, 0, ANCHO, 5, [NEGRO, VINO, NEGRO])

        self.revisar_directorio()
        self._evento_local("panel", "listo · introduce la contraseña y pulsa Iniciar red")
        self.raiz.after(200, self._sondear)

    # --- construcción ---------------------------------------------------------------

    def _cabecera(self) -> None:
        c = tk.Canvas(self.raiz, width=ANCHO, height=100, bg=NEGRO, highlightthickness=0)
        c.pack(fill="x")
        franja_peligro(c, ANCHO, 10)
        degradado(c, 0, 10, ANCHO, 100, [NEGRO, NEGRO, "#3A0000", VINO])
        for r, w, color in ((26, 3, VINO), (18, 2, VINO_CLARO), (10, 2, VINO), (3, 3, VINO_CLARO)):
            c.create_oval(52 - r, 56 - r, 52 + r, 56 + r, outline=color, width=w)
        c.create_text(94, 46, text="MiniOni", anchor="w", font=F["titulo"], fill=TEXTO)
        c.create_text(96, 76, text="RED CEBOLLA DE LABORATORIO  ·  EQUIPO ONION", anchor="w",
                      font=F["mono_chico"], fill=TEXTO2)
        self._pildora_fondo = c.create_rectangle(ANCHO - 330, 34, ANCHO - 22, 68, fill=NEGRO,
                                                 outline=TEXTO2, width=1)
        self._pildora = c.create_text(ANCHO - 176, 51, text="●  RED DETENIDA", font=F["seccion"], fill=TEXTO2)
        self._canvas_cab = c
        self._selector_modo(c)

    def _arranque(self, cuerpo) -> None:
        seccion(cuerpo, "ARRANQUE").pack(anchor="w", pady=(10, 6))
        t = tarjeta(cuerpo, padx=14, pady=12)
        t.pack(fill="x")
        fila = tk.Frame(t, bg=TARJETA)
        fila.pack(fill="x")
        tk.Label(fila, text="Contraseña de las claves", font=F["texto"], fg=TEXTO, bg=TARJETA).pack(side="left")
        self.clave = tk.Entry(fila, show="•", font=F["texto"], bg=NEGRO, fg=TEXTO, insertbackground=TEXTO,
                              relief="flat", highlightthickness=1, highlightbackground=LINEA,
                              highlightcolor=VINO, width=28)
        self.clave.pack(side="left", padx=12, ipady=6)
        self.clave.bind("<Return>", lambda _: self.iniciar_o_detener())
        self.b_publicar = Boton(fila, "Publicar directorio local", self.publicar)
        self.b_publicar.pack(side="right")
        self.b_iniciar = Boton(fila, "▶  Iniciar red", self.iniciar_o_detener, principal=True)
        self.b_iniciar.pack(side="right", padx=8)
        linea = tk.Frame(t, bg=TARJETA)
        linea.pack(fill="x", pady=(8, 0))
        self.info = tk.Label(linea, text="", font=F["chico"], fg=TEXTO2, bg=TARJETA, anchor="w", justify="left")
        self.info.pack(side="left", fill="x", expand=True)
        # Solo se muestra en modo Docker (cambiar_modo).
        self.c_internet = tk.Checkbutton(linea, text="Internet solo para el relay de salida", variable=self.internet,
                                         bg=TARJETA, fg=TEXTO, selectcolor=NEGRO, font=F["chico"],
                                         activebackground=TARJETA, activeforeground=TEXTO,
                                         disabledforeground="#55555C", highlightthickness=0, state="disabled")

    def _selector_modo(self, c: tk.Canvas) -> None:
        """Local / Docker en la cabecera: así la ventana no crece y sigue cabiendo en 1080 px."""
        c.create_text(640, 34, text="DÓNDE CORRE LA RED", anchor="e", font=F["mono_chico"], fill=TEXTO2)
        fila = tk.Frame(c, bg=NEGRO)
        c.create_window(640, 60, window=fila, anchor="e")
        # Las variables se guardan en self y se atan a esta raíz: Tk las libera con la ventana.
        self.modo = tk.StringVar(master=self.raiz, value="local")
        self.internet = tk.BooleanVar(master=self.raiz, value=False)
        self.radios = {}
        for valor, texto in (("local", "Local"), ("docker", "Docker")):
            r = tk.Radiobutton(fila, text=texto, value=valor, variable=self.modo, command=self.cambiar_modo,
                               indicatoron=False, selectcolor=VINO, bg=TARJETA, fg=TEXTO, font=F["chico"],
                               activebackground=TARJETA_HOVER, activeforeground="#FFFFFF", cursor="hand2",
                               disabledforeground="#55555C", relief="flat", bd=1, padx=14, pady=3)
            r.pack(side="left", padx=(4, 0))
            self.radios[valor] = r
        if not self.control.docker_disponible:
            self.radios["docker"].configure(state="disabled")

    def _estado_selector(self) -> None:
        libre = not self._ocupado and not self.control.instantanea["en_marcha"]
        docker = self.modo.get() == "docker"
        self.radios["local"].configure(state="normal" if libre else "disabled")
        self.radios["docker"].configure(state="normal" if libre and self.control.docker_disponible else "disabled")
        self.c_internet.configure(state="normal" if libre and docker else "disabled")
        self.b_segmentacion.activo(docker and not self._ocupado)

    def cambiar_modo(self) -> None:
        if self._ocupado:
            self.modo.set(self.control.modo)
            return
        try:
            self.control.cambiar_modo(self.modo.get())
        except ConfiguracionInvalida as e:
            self.modo.set(self.control.modo)
            self.info.configure(text=mensaje_error(e), fg=ALERTA)
            return
        docker = self.control.modo == "docker"
        if docker:
            self.c_internet.pack(side="right")
        else:
            self.internet.set(False)
            self.c_internet.pack_forget()
        # Con la casilla al lado, un mensaje largo usa dos líneas en vez de cortarse.
        self.info.configure(wraplength=ANCHO - 340 if docker else 0)
        self.b_publicar.texto("Firmar directorio Docker" if docker else "Publicar directorio local")
        if self.url.get().strip() in (URL_LOCAL, URL_DOCKER):
            self.url.delete(0, "end")
            self.url.insert(0, URL_DOCKER if docker else URL_LOCAL)
        self._estado_selector()
        self.revisar_directorio()

    def _construir_nodos(self, relays: list[tuple[str, bool]]) -> None:
        if relays == self._apodos and self._tarjetas:
            return
        for hijo in self.fila_nodos.winfo_children():
            hijo.destroy()
        self._tarjetas.clear()
        self._apodos = list(relays)
        elementos = [(a, "Nodo de salida" if s else ("Relay de entrada" if i == 0 else "Relay intermedio"))
                     for i, (a, s) in enumerate(relays)]
        elementos.append(("Proxy", f"SOCKS5 · {HOST_PROXY}:{self.control.instantanea['puerto_proxy']}"))
        for i, (nombre, desc) in enumerate(elementos):
            t = tarjeta(self.fila_nodos, padx=14, pady=10)
            t.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 10, 0))
            self.fila_nodos.columnconfigure(i, weight=1, uniform="nodos")
            arriba = tk.Frame(t, bg=TARJETA)
            arriba.pack(fill="x")
            tk.Label(arriba, text=nombre, font=F["negrita"], fg=TEXTO, bg=TARJETA).pack(side="left")
            punto = tk.Canvas(arriba, width=12, height=12, bg=TARJETA, highlightthickness=0)
            ovalo = punto.create_oval(1, 1, 11, 11, fill="#44444A", outline="")
            punto.pack(side="right")
            tk.Label(t, text=desc, font=F["chico"], fg=TEXTO2, bg=TARJETA).pack(anchor="w", pady=(3, 8))
            abajo = tk.Frame(t, bg=TARJETA)
            abajo.pack(fill="x")
            estado = tk.Label(abajo, text="Detenido", font=F["texto"], fg=TEXTO2, bg=TARJETA)
            estado.pack(side="left")
            boton = None
            if nombre != "Proxy":
                boton = Boton(abajo, "Apagar", lambda a=nombre: self.alternar(a), chico=True)
                boton.pack(side="right")
                boton.activo(False)
            self._tarjetas[nombre] = dict(marco=t, punto=punto, ovalo=ovalo, estado=estado, boton=boton)

    def _metricas(self, cuerpo) -> None:
        seccion(cuerpo, "MÉTRICAS").pack(anchor="w", pady=(10, 5))
        fila = tk.Frame(cuerpo, bg=NEGRO)
        fila.pack(fill="x")
        self.metricas = {}
        for i, (clave, nombre) in enumerate((("circuitos", "Circuitos activos"),
                                             ("conexiones", "Conexiones del navegador"),
                                             ("bloqueados", "Destinos bloqueados"))):
            t = tarjeta(fila, padx=14, pady=10)
            t.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 10, 0))
            fila.columnconfigure(i, weight=1, uniform="met")
            tk.Label(t, text=nombre, font=F["chico"], fg=TEXTO2, bg=TARJETA).pack(anchor="w")
            v = tk.Label(t, text="0", font=F["numero"], fg=VINO_CLARO if i == 0 else TEXTO, bg=TARJETA)
            v.pack(anchor="w")
            self.metricas[clave] = v

    def _pruebas(self, cuerpo) -> None:
        seccion(cuerpo, "PRUEBAS Y DEMOSTRACIONES").pack(anchor="w", pady=(10, 5))
        t = tarjeta(cuerpo, padx=14, pady=12)
        t.pack(fill="x")
        fila = tk.Frame(t, bg=TARJETA)
        fila.pack(fill="x")
        self.b_eco = Boton(fila, "⇄  Probar circuito", self.probar_circuito)
        self.b_eco.pack(side="left")
        self.url = tk.Entry(fila, font=F["texto"], bg=NEGRO, fg=TEXTO, insertbackground=TEXTO, relief="flat",
                            highlightthickness=1, highlightbackground=LINEA, highlightcolor=VINO, width=30)
        self.url.insert(0, URL_LOCAL)
        self.url.pack(side="left", padx=(12, 8), ipady=6)
        self.url.bind("<Return>", lambda _: self.probar_url())
        self.b_url = Boton(fila, "↗  Abrir por MiniOni", self.probar_url)
        self.b_url.pack(side="left")
        fila2 = tk.Frame(t, bg=TARJETA)
        fila2.pack(fill="x", pady=(8, 0))
        self.b_verificar = Boton(fila2, "◈  Verificar sin registros", self.verificar_registros, principal=True)
        self.b_verificar.pack(side="left")
        Boton(fila2, "≡  Guía de Firefox", self.guia_firefox).pack(side="left", padx=8)
        Boton(fila2, "⧉  Copiar comando curl", self.copiar_curl).pack(side="left")
        self.b_segmentacion = Boton(fila2, "▦  Probar segmentación", self.probar_segmentacion)
        self.b_segmentacion.pack(side="left", padx=8)
        self.b_segmentacion.activo(False)
        self.resultado = tk.Label(t, text="Inicia la red para probar el circuito.", font=F["chico"],
                                  fg=TEXTO2, bg=TARJETA, anchor="w", justify="left", wraplength=ANCHO - 90)
        self.resultado.pack(fill="x", pady=(10, 0))

    def _eventos(self, cuerpo) -> None:
        cab = tk.Frame(cuerpo, bg=NEGRO)
        cab.pack(fill="x", pady=(10, 5))
        seccion(cab, "EVENTOS").pack(side="left")
        tk.Label(cab, text="sin IP, dominios ni puertos", font=F["mono_chico"], fg=TEXTO2,
                 bg=NEGRO).pack(side="right")
        t = tarjeta(cuerpo, padx=2, pady=2)
        t.pack(fill="both", expand=True, pady=(0, 14))
        self.log = tk.Text(t, height=5, bg=NEGRO, fg=TEXTO2, font=F["mono"], relief="flat",
                           highlightthickness=0, padx=12, pady=8, state="disabled", wrap="none")
        self.log.tag_configure("comp", foreground=VINO_CLARO)
        self.log.tag_configure("alerta", foreground=ALERTA)
        self.log.pack(fill="both", expand=True)

    # --- acciones --------------------------------------------------------------------

    def _accion(self, coro, al_ok, al_error=None) -> None:
        """Corre `coro` en el hilo de la red; el resultado vuelve a la ventana en `_sondear`."""
        futuro = self.control.ejecutar(coro)
        futuro.add_done_callback(lambda f: self._resultados.put((f, al_ok, al_error)))

    def _ocupar(self, si: bool, texto: str = "") -> None:
        self._ocupado = si
        for b in (self.b_iniciar, self.b_publicar, self.b_eco, self.b_url, self.b_verificar):
            b.activo(not si)
        self._estado_selector()
        if texto:
            self.info.configure(text=texto, fg=TEXTO2)

    def error_inesperado(self, *_detalles) -> None:
        """Reemplaza a Tk.report_callback_exception, que imprimiría la traza completa.

        Un fallo no previsto en un botón solo emite ERROR_INTERNO del catálogo y muestra
        un mensaje genérico; la ventana sigue funcionando (ASVS V16.5.1 y V16.5.4).
        """
        consola.evento("panel", "ERROR_INTERNO")
        self._ocupar(False)
        self.info.configure(text="Error interno.", fg=ALERTA)

    def iniciar_o_detener(self) -> None:
        if self._ocupado:
            return
        if self.control.instantanea["en_marcha"]:
            self._ocupar(True, "Deteniendo la red…")
            self._accion(self.control.detener(), lambda _: self._detenida(), self._error_arranque)
            return
        contrasena = self.clave.get()
        self.clave.delete(0, "end")
        if not contrasena:
            self.info.configure(text="Escribe la contraseña de las claves.", fg=ALERTA)
            return
        if self.control.modo == "docker":
            self._ocupar(True, consola.texto_fase(1))
            self._accion(self.control.iniciar(contrasena, internet=self.internet.get()),
                         self._iniciada, self._error_arranque)
            return
        self._ocupar(True, consola.texto_fase(1))
        self._accion(self.control.iniciar(contrasena), self._iniciada, self._error_arranque)

    def _iniciada(self, n: int) -> None:
        self._ocupar(False)
        self.b_iniciar.texto("■  Detener red")
        self.b_publicar.activo(False)
        d = self.control.directorio
        self.info.configure(text=f"Red en marcha: {n} relays y el proxy SOCKS5 en {HOST_PROXY}:"
                                 f"{self.control.instantanea['puerto_proxy']}  ·  directorio v{d.version}"
                                 + ("  ·  en Docker" if self.control.modo == "docker" else ""),
                            fg=VERDE)
        self.resultado.configure(text="Listo. Prueba el circuito o abre una página por MiniOni.", fg=TEXTO2)

    def _detenida(self) -> None:
        self._ocupar(False)
        self.b_iniciar.texto("▶  Iniciar red")
        self.revisar_directorio()

    def _error_arranque(self, e: BaseException) -> None:
        self._ocupar(False)
        self.b_iniciar.texto("■  Detener red" if self.control.instantanea["en_marcha"] else "▶  Iniciar red")
        self.info.configure(text=mensaje_error(e), fg=ALERTA)

    def publicar(self) -> None:
        if self._ocupado:
            return
        contrasena = self.clave.get()
        if not contrasena:
            self.info.configure(text="Escribe la contraseña de la autoridad para firmar el directorio.", fg=ALERTA)
            return
        self.clave.delete(0, "end")
        docker = self.control.modo == "docker"
        nombre = "de Docker" if docker else "local"
        self._ocupar(True, "Firmando un directorio nuevo con los relays en "
                           + ("las redes de Docker…" if docker else "127.0.0.1…"))
        firmar = self.control.publicar_directorio_docker if docker else self.control.publicar_directorio_local

        async def tarea():
            import asyncio
            return await asyncio.to_thread(firmar, contrasena)

        def ok(version):
            self._ocupar(False)
            self.revisar_directorio()
            self.info.configure(text=f"Directorio {nombre} v{version} publicado. Ya puedes iniciar la red.",
                                fg=VERDE)
            self._evento_local("panel", f"directorio {nombre} v{version} publicado")
        self._accion(tarea(), ok, self._error_arranque)

    def alternar(self, apodo: str) -> None:
        if self._ocupado or not self.control.instantanea["en_marcha"]:
            return
        self._accion(self.control.alternar(apodo), lambda on: self._alternado(apodo, on),
                     lambda e: self.resultado.configure(text=mensaje_error(e), fg=ALERTA))

    def _alternado(self, apodo: str, on: bool) -> None:
        if on:
            self.resultado.configure(text=f"{apodo} encendido: el siguiente circuito vuelve a funcionar.",
                                     fg=TEXTO2)
        else:
            self.resultado.configure(text=f"{apodo} apagado. Fallo cerrado: sin circuito la navegación se "
                                          "bloquea; MiniOni nunca sale directo.", fg=VINO_CLARO)

    def probar_circuito(self) -> None:
        self.resultado.configure(text="Construyendo un circuito de 3 saltos y enviando un eco…", fg=TEXTO2)
        self._accion(self.control.probar_circuito(),
                     lambda r: self.resultado.configure(
                         text=f'Eco "hola MiniOni" recibido · {r[1]} saltos · ida y vuelta {r[0]:.0f} ms',
                         fg=VERDE),
                     lambda e: self.resultado.configure(text=f"Fallo: {mensaje_error(e)}", fg=ALERTA))

    def probar_url(self) -> None:
        self.resultado.configure(text="Pidiendo la página a través del circuito (DNS remoto)…", fg=TEXTO2)
        self._accion(self.control.probar_url(self.url.get()),
                     lambda r: self.resultado.configure(
                         text=f"Respuesta HTTP {r[0]} · {r[1]:,} bytes · {r[2]:.0f} ms · por 3 saltos".replace(",", "."),
                         fg=VERDE),
                     lambda e: self.resultado.configure(text=f"Fallo: {mensaje_error(e)}", fg=ALERTA))

    def verificar_registros(self) -> None:
        if self._ocupado:
            return
        if not self.control.instantanea["en_marcha"]:
            self.resultado.configure(text="Primero inicia la red.", fg=ALERTA)
            return
        self._ocupar(True)
        self.resultado.configure(text="Buscando una palabra testigo por MiniOni mientras se vigilan el disco y "
                                      "la consola…", fg=TEXTO2)
        self._accion(self.control.verificar_sin_registros(), self._informe,
                     lambda e: (self._ocupar(False),
                                self.resultado.configure(text=f"Fallo: {mensaje_error(e)}", fg=ALERTA)))

    def probar_segmentacion(self) -> None:
        if self._ocupado:
            return
        if not self.control.instantanea["en_marcha"]:
            self.resultado.configure(text="Primero inicia la red en modo Docker.", fg=ALERTA)
            return
        self._ocupar(True)
        self.resultado.configure(text="Conectando un contenedor de prueba a cada red…", fg=TEXTO2)
        self._accion(self.control.probar_segmentacion(), self._matriz,
                     lambda e: (self._ocupar(False),
                                self.resultado.configure(text=f"Fallo: {mensaje_error(e)}", fg=ALERTA)))

    def _matriz(self, filas: list[dict]) -> None:
        self._ocupar(False)
        ok = all(f["ok"] for f in filas)
        self.resultado.configure(text=("Segmentación correcta: desde cada red solo se alcanza un servicio."
                                       if ok else "La segmentación NO es la esperada."),
                                 fg=VERDE if ok else ALERTA)
        self._evento_local("panel", "segmentación: " + ("correcta" if ok else "FALLIDA"), alerta=not ok)
        self._bloque_en_eventos(texto_matriz(filas))

    def _informe(self, inf) -> None:
        self._ocupar(False)
        registro = self.log.get("1.0", "end")
        # Un nombre sin punto («web», en el laboratorio) aparece en cualquier texto: no sirve de rastro.
        en_panel = inf.testigo in registro or ("." in inf.dominio and not inf.dominio[0].isdigit()
                                                     and inf.dominio in registro)
        aprobado = inf.aprobado and not en_panel
        escrituras = str(len(inf.escrituras))
        if inf.escrituras:
            escrituras += " (" + ", ".join(Path(r).name for _, r in inf.escrituras[:3]) + ")"
        archivos = (f"{inf.revisados}, ninguno con el testigo" if not inf.archivos
                    else f"{inf.revisados}, {len(inf.archivos)} CON el testigo")
        lineas = [
            ("✔  SIN REGISTROS" if aprobado else "✖  SE ENCONTRÓ UN REGISTRO")
            + f"  ·  búsqueda testigo «{inf.testigo}» en {inf.dominio}: {inf.busqueda}",
            f"Escrituras en disco: {escrituras}  ·  apariciones en consola y panel: "
            f"{int(inf.en_consola) + int(en_panel)}  ·  archivos modificados durante la búsqueda: {archivos}",
            "La búsqueda no llegó al buscador (¿sin internet?): repite la prueba con conexión."
            if not inf.busqueda_ok else
            f"Compruébalo tú: busca «{inf.testigo}» con findstr en cualquier carpeta; no aparecerá.",
        ]
        if inf.contenedores is not None:
            lineas.insert(2, "Contenedores: Docker confirma registros apagados y disco de solo lectura."
                             if inf.contenedores else "Contenedores: Docker NO confirmó que estén sin registros.")
        self.resultado.configure(text="\n".join(lineas), fg=VERDE if aprobado else ALERTA)
        self._evento_local("panel", "verificación sin registros: " + ("aprobada" if aprobado else "FALLIDA"),
                           alerta=not aprobado)

    def guia_firefox(self) -> None:
        webbrowser.open((CARPETA_PROYECTO / "docs" / "NAVEGADOR.md").as_uri())

    def copiar_curl(self) -> None:
        puerto = self.control.instantanea["puerto_proxy"]
        self.raiz.clipboard_clear()
        self.raiz.clipboard_append(f"curl.exe --socks5-hostname {HOST_PROXY}:{puerto} {self.url.get().strip()}")
        self.resultado.configure(text="Comando curl copiado. Pégalo en PowerShell.", fg=TEXTO2)

    def revisar_directorio(self) -> None:
        r = self.control.revisar_directorio()
        self._construir_nodos(r["relays"] or [("entrada1", False), ("medio1", False), ("salida1", True)])
        if r["estado"] == "docker":
            self.info.configure(text=f"Directorio de Docker v{r['version']} verificado: cada relay en su red.",
                                fg=TEXTO2)
        elif self.control.modo == "docker":
            self.info.configure(text="Directorio de Docker ausente, vencido o no válido. Escribe la contraseña "
                                     "y pulsa «Firmar directorio Docker».", fg=VINO_CLARO)
        elif r["estado"] == "local":
            self.info.configure(text=f"Directorio v{r['version']} verificado: relays en 127.0.0.1.", fg=TEXTO2)
        elif r["estado"] == "remoto":
            self.info.configure(text=f"El directorio v{r['version']} es el de Docker (semana 4). Escribe la "
                                     "contraseña y pulsa «Publicar directorio local».", fg=VINO_CLARO)
        else:
            self.info.configure(text="Directorio ausente, vencido o no válido. Escribe la contraseña y pulsa "
                                     "«Publicar directorio local».", fg=VINO_CLARO)

    # --- refresco --------------------------------------------------------------------

    def _evento_local(self, componente: str, texto: str, alerta: bool = False) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", time.strftime("%H:%M:%S") + "  ")
        self.log.insert("end", componente.ljust(10), "comp")
        self.log.insert("end", f" {texto}\n", "alerta" if alerta else ())
        if int(self.log.index("end-1c").split(".")[0]) > 500:
            self.log.delete("1.0", "100.0")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _bloque_en_eventos(self, texto: str) -> None:
        """Texto en columnas dentro del cuadro de eventos, visible desde su primera línea."""
        self.log.configure(state="normal")
        inicio = self.log.index("end-1c")
        self.log.insert("end", texto + "\n")
        self.log.yview(inicio)
        self.log.configure(state="disabled")

    def _sondear(self) -> None:
        try:
            while True:
                futuro, al_ok, al_error = self._resultados.get_nowait()
                excepcion = futuro.exception() if not futuro.cancelled() else MiniOniError("cancelado")
                if excepcion is None:
                    al_ok(futuro.result())
                elif al_error is not None:
                    al_error(excepcion)
        except queue.Empty:
            pass
        if self._ocupado and self.control.aviso:
            self.info.configure(text=self.control.aviso, fg=TEXTO2)
        for _, componente, codigo, cantidad in self.control.eventos_nuevos():
            texto = consola.EVENTOS.get(codigo, consola.EVENTOS["ERROR_INTERNO"])
            if cantidad is not None:
                texto += f" ({cantidad})"
            self._evento_local(componente.removeprefix("relay-"), texto, codigo in EVENTOS_ALERTA)
        self._pintar(self.control.instantanea)
        self.raiz.after(200, self._sondear)

    def _pintar(self, s: dict) -> None:
        if s["en_marcha"] and set(s["nodos"]) != {a for a, _ in self._apodos}:
            self._construir_nodos([(a, s["salidas"][a]) for a in s["nodos"]])
        for nombre, t in self._tarjetas.items():
            if nombre == "Proxy":
                on, texto = s["proxy"], "Escuchando" if s["proxy"] else "Detenido"
            else:
                on = s["nodos"].get(nombre, False)
                texto = "En línea" if on else ("Apagado" if s["en_marcha"] else "Detenido")
                t["boton"].activo(s["en_marcha"] and not self._ocupado)
                t["boton"].texto("Encender" if s["en_marcha"] and not on else "Apagar")
            caido = s["en_marcha"] and not on
            t["punto"].itemconfigure(t["ovalo"], fill=VERDE if on else (ALERTA if caido else "#44444A"))
            t["estado"].configure(text=texto, fg=VERDE if on else (ALERTA if caido else TEXTO2))
            t["marco"].configure(highlightbackground=ALERTA if caido else (VINO if nombre == "Proxy" and on
                                                                          else LINEA))
        for clave, etiqueta in self.metricas.items():
            etiqueta.configure(text=str(s[clave]))
        c = self._canvas_cab
        if not s["en_marcha"]:
            c.itemconfigure(self._pildora, text="●  RED DETENIDA", fill=TEXTO2)
            c.itemconfigure(self._pildora_fondo, outline=TEXTO2, fill=NEGRO)
        elif all(s["nodos"].values()):
            c.itemconfigure(self._pildora, text="●  RED ACTIVA · PROTEGIDA", fill="#FFFFFF")
            c.itemconfigure(self._pildora_fondo, outline=VINO_CLARO, fill=VINO_OSCURO)
        else:
            c.itemconfigure(self._pildora, text="▲  SIN CIRCUITO · BLOQUEADO", fill=ALERTA)
            c.itemconfigure(self._pildora_fondo, outline=ALERTA, fill=NEGRO)

    def cerrar(self) -> None:
        if self._ocupado and self.control.modo == "docker":   # no dejar contenedores a medio crear
            self.info.configure(text="Espera a que termine la operación de Docker para cerrar.", fg=ALERTA)
            return
        self.info.configure(text="Cerrando la red…", fg=TEXTO2)
        self.raiz.update_idletasks()
        self.control.cerrar()
        self.raiz.destroy()


def mensaje_error(e: BaseException) -> str:
    """Mensajes cortos y genéricos para la ventana. Nunca trazas ni detalles internos."""
    if isinstance(e, ClaveInvalida):
        return "Contraseña incorrecta o clave dañada."
    if isinstance(e, DirectorioInvalido):
        return "Directorio no válido, vencido o más viejo que el último visto. Publica uno local."
    if isinstance(e, ConfiguracionInvalida) and "no es local" in str(e):
        return "El directorio es el de Docker (semana 4). Pulsa «Publicar directorio local»."
    if isinstance(e, MiniOniError):
        return e.mensaje_publico[:1].upper() + e.mensaje_publico[1:] + "."
    if isinstance(e, OSError):
        return "Un puerto está ocupado: ¿hay relays o un proxy abiertos en otra ventana?"
    return "Error interno."


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="panel", description="Panel gráfico de MiniOni")
    p.add_argument("--puerto", type=argumento_puerto, default=PUERTO_PROXY, help="puerto del proxy SOCKS5 (127.0.0.1)")
    p.add_argument("--carpeta", default=None,
                   help="carpeta con config/ y claves/ (por defecto la actual y, para las claves, MINIONI_CLAVES si existe)")
    args = p.parse_args(argv)
    if args.carpeta is not None:
        config, claves = Path(args.carpeta) / "config", Path(args.carpeta) / "claves"
    else:
        try:
            config, claves = Path("config"), ak.carpeta_claves()
        except MiniOniError as e:
            print(f"Error: {e.mensaje_publico}", file=sys.stderr)
            return 1
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)   # texto nítido en pantallas con escala
    except (AttributeError, OSError):
        pass
    # Con --carpeta las claves no son las que monta Docker: el modo Docker queda desactivado.
    control = ControladorRed(config, claves, args.puerto, orquestador=None if args.carpeta else laboratorio_docker)
    raiz = tk.Tk()
    elegir_fuentes()
    panel = Panel(raiz, control)
    raiz.report_callback_exception = panel.error_inesperado
    try:
        raiz.mainloop()
    except KeyboardInterrupt:
        control.cerrar()
    return 0


if __name__ == "__main__":
    consola.instalar_manejador_global("panel")
    sys.exit(main())
