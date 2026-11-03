# MiniOni

Red de enrutamiento cebolla (*onion routing*) para una LAN de laboratorio,
escrita en Python. Impide que el administrador o un observador de la red
sepa a qué destinos se conecta cada usuario.

> MiniOni **no es un navegador**: se usa Firefox o LibreWolf configurado
> para salir por el proxy SOCKS5 de MiniOni. Ver [docs/LIMITES.md](docs/LIMITES.md).

**Equipo Onion** · Proyecto de Seguridad en Redes · 5 semanas

## Instalación (Windows)

Requiere Python 3.10 o superior.

```powershell
cd MiniOni
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements-dev.txt
```

En Linux/macOS: `python3 -m venv .venv` y `source .venv/bin/activate`.

## Probar lo que hay hasta ahora (semanas 1 a 3)

```powershell
python -m pytest                # pruebas automáticas (fuzzing, 3 relays reales con TLS 1.3, proxy SOCKS5)
python demo_capas.py            # una celda atravesando los 3 saltos, en memoria
```

## Panel gráfico (la forma más fácil)

```powershell
python panel.py
```

Una sola ventana, en vinotinto y negro, que hace lo mismo que las 4 ventanas
de PowerShell de abajo: escribe la contraseña de las claves y pulsa
**▶ Iniciar red** (levanta los 3 relays y el proxy SOCKS5 en `127.0.0.1:9050`).
Desde ahí:

- **⇄ Probar circuito**: eco por un circuito real de 3 saltos, con el tiempo.
- **↗ Abrir por MiniOni**: pide una dirección `http://` o `https://` a través
  del proxy (DNS remoto) y muestra el código HTTP y los bytes recibidos.
- **Apagar / Encender** en cada relay: demostración de fallo cerrado (sin
  circuito la navegación se bloquea; nunca sale directo).
- **Publicar directorio local**: firma un directorio nuevo con los relays en
  `127.0.0.1` (necesario si `config/` tiene el de Docker).
- **◈ Verificar sin registros**: busca una palabra testigo inventada por
  MiniOni mientras vigila cada escritura en disco y todo lo que se imprime;
  después busca el testigo en los archivos. Detalle y pruebas manuales en
  [docs/SIN_REGISTROS.md](docs/SIN_REGISTROS.md).
- **≡ Guía de Firefox** y **⧉ Copiar comando curl**.
- Métricas (circuitos, conexiones del navegador, destinos bloqueados) y un
  registro con los mismos eventos genéricos de la consola: sin IP, dominios
  ni puertos. La contraseña no se guarda: se borra del campo al usarla.

Capturas en [docs/capturas](docs/capturas). Opciones: `--puerto 9150` para
otro puerto del proxy y `--carpeta RUTA` para otra carpeta con `config/` y `claves/`.

## Levantar la red y navegar en un solo computador (semanas 2 y 3)

Lo mismo que el panel, pero a mano, con una ventana por proceso.

Orden de arranque: **3 relays → proxy → navegador**.

Una sola vez, publicar un directorio con los relays en `127.0.0.1:9001-9003`
(usa siempre un número de versión mayor que el anterior):

```powershell
python minioni_admin.py publicar-directorio --version 2 --relays config/relays.local.json
```

Luego, **una ventana de PowerShell por relay** (cada uno pide la contraseña):

```powershell
python ejecutar_relay.py --apodo entrada1
python ejecutar_relay.py --apodo medio1
python ejecutar_relay.py --apodo salida1
```

En una cuarta ventana, comprobar el circuito y arrancar el proxy SOCKS5:

```powershell
python cliente_prueba.py        # circuito real de 3 saltos + eco
python cliente_proxy.py         # proxy SOCKS5 en 127.0.0.1:9050 (déjalo corriendo)
```

Y en una quinta ventana (o en Firefox, ver [docs/NAVEGADOR.md](docs/NAVEGADOR.md)):

```powershell
curl.exe --socks5-hostname 127.0.0.1:9050 https://example.com
```

Ctrl+C apaga cada proceso de forma limpia. Los relays y el proxy solo
muestran eventos genéricos: nunca IP, puertos de clientes, dominios ni
contenido. Si se detiene un relay, la navegación **falla** (no sale directo).

La política del nodo de salida está en `config/politica_salida.json`
(por defecto solo puertos 80 y 443 hacia IP públicas).

## Revisión de seguridad del código

| Comando | Qué revisa | Norma |
|---|---|---|
| `bandit -c pyproject.toml -r .` | Análisis estático: patrones de código inseguro | NIST SSDF PW.7.2 |
| `python -m pytest tests/test_fuzzing.py --hypothesis-profile=intenso` | Fuzzing: ~100 000 entradas aleatorias a los parsers (tarda unos minutos) | NIST SSDF PW.8.2 · ASVS V2.2.1 |
| `pip-audit -r requirements.txt` | Vulnerabilidades conocidas en las dependencias | NIST SSDF PW.4.1 |
| `python -m bandit -q -r tests -s B101,B104,B105` | Análisis estático de las pruebas (motivos de las 3 reglas omitidas en `docs/CLASE3_CODIFICACION_SEGURA.md`) | NIST SSDF PW.7.2 |
| `python revisar_secretos.py` | Secretos en el código (detect-secrets), claves sin cifrar, `.gitignore`, carpeta en la nube y **secretos en el historial de Git** | NIST SSDF PS.1 |
| `python minioni_admin.py revisar-certificados` | Días que le quedan al certificado TLS de cada relay (código 1 si alguno venció) | ASVS 5.0 V11.1.1 |

## Crear las claves y el directorio firmado

```powershell
python minioni_admin.py preparar-laboratorio     # todo en un paso, una contraseña (--relays para otra lista)
python revision_completa.py                      # todas las comprobaciones con resumen
python minioni_admin.py simular-ataque           # demostración: directorio alterado = rechazado
```

Paso por paso: `generar-autoridad`, `generar-relay --apodo <nombre>` (×3),
`publicar-directorio --version 1 --dias 7` y `verificar-directorio`.

Las contraseñas se piden de forma oculta (mínimo 12 caracteres). Las claves
privadas quedan cifradas en `claves/`, carpeta que **nunca** se sube al
repositorio.

**Claves fuera de OneDrive.** Si el proyecto está en una carpeta que se sube a la
nube, define una carpeta local para las claves y regenéralas (las que pasaron por
la nube se consideran expuestas):

```powershell
mkdir C:\MiniOniClaves
setx MINIONI_CLAVES C:\MiniOniClaves            # abre una ventana NUEVA de PowerShell después
python minioni_admin.py donde-estan-las-claves   # debe decir MINIONI_CLAVES y "no está en una carpeta sincronizada"
python minioni_admin.py preparar-laboratorio
python revisar_secretos.py
```

Luego el equipo borra la carpeta `claves` vieja del proyecto y vacía la papelera
de OneDrive. Rotación de certificados y claves: [docs/ROTACION_CLAVES.md](docs/ROTACION_CLAVES.md). Las direcciones de los relays se editan en `config/relays.json`
(Docker, semana 4) o `config/relays.local.json` (los 3 en este computador).

## Documentación

| Documento | Contenido |
|---|---|
| [docs/ARQUITECTURA.md](docs/ARQUITECTURA.md) | Componentes, diagramas, límites de confianza, decisiones |
| [docs/PROTOCOLO.md](docs/PROTOCOLO.md) | Formato de celdas, capas, handshake y directorio |
| [docs/INVENTARIO_CRIPTOGRAFICO.md](docs/INVENTARIO_CRIPTOGRAFICO.md) | Cada clave y algoritmo: dónde vive, qué protege, cuánto dura; plan poscuántico |
| [docs/LIMITES.md](docs/LIMITES.md) | Qué NO protege MiniOni |
| [docs/NAVEGADOR.md](docs/NAVEGADOR.md) | Configurar Firefox y curl con el proxy; demostración de fallo cerrado |
| [docs/SIN_REGISTROS.md](docs/SIN_REGISTROS.md) | Cómo demostrar que las búsquedas no quedan registradas |
| [docs/ROTACION_CLAVES.md](docs/ROTACION_CLAVES.md) | Cuándo y cómo rotar el certificado TLS, la clave cebolla y la autoridad |
| [docs/capturas](docs/capturas) | Capturas del panel gráfico (`panel.py`) |
| [docs/CLASE3_FALLOS_Y_CORRECCIONES.md](docs/CLASE3_FALLOS_Y_CORRECCIONES.md) | Los 11 fallos de la Clase 3: control, causa y corrección |
| [docs/CLASE3_CODIFICACION_SEGURA.md](docs/CLASE3_CODIFICACION_SEGURA.md) | Investigación de los 4 controles (Clase 3): hallazgos, SAST, secretos |
| [docs/TRASPASO_CLASE3_CLAUDE_CODE.md](docs/TRASPASO_CLASE3_CLAUDE_CODE.md) | Traspaso para Claude Code: reglas nuevas, estado y tareas T1-T7 antes de la Clase 4 |
| [docs/TRAZABILIDAD.md](docs/TRAZABILIDAD.md) | Requisito → norma → código → prueba |

## Plan

| Semana | Entregable | Estado |
|---|---|---|
| 1 | Ficha, requisitos, arquitectura; núcleo criptográfico, directorio firmado, pruebas | ✅ |
| 2 | Relays en red (asyncio + TLS 1.3), límites anti-DoS | ✅ |
| 3 | Nodo de salida, proxy SOCKS5, fail-closed, conexión del navegador | ✅ |
| 4 | Entorno Docker con redes segmentadas | ⏳ |
| 5 | Pruebas con Wireshark, documentación final e informe | ⏳ |

## Normas

OWASP ASVS 5.0 (V2, V11, V12, V16) · NIST SP 800-218 SSDF (PW.1.1, PW.4.1, PW.7.2, PW.8.2) ·
ISO/IEC 27033 (segmentación y límites de confianza).
