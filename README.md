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

**La primera vez, en este orden:** crea las claves ([Crear las claves y el directorio
firmado](#crear-las-claves-y-el-directorio-firmado), con `MINIONI_CLAVES` fuera de la
nube), ejecuta las pruebas y después abre el panel. Si clonaste el repositorio, activa
también el hook de revisión de secretos con `git config core.hooksPath hooks`.

## Probar el proyecto

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

- **Local / Docker** (en la cabecera): con Docker, la misma ventana firma el
  directorio, levanta el laboratorio con redes segmentadas, pausa relays y muestra
  la matriz con **▦ Probar segmentación**. Requiere Docker Desktop abierto.

Capturas en [docs/capturas](docs/capturas). Opciones: `--puerto 9150` para
otro puerto del proxy y `--carpeta RUTA` para otra carpeta con `config/` y `claves/`
(con esta opción el modo Docker queda desactivado).

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

## Laboratorio Docker con redes segmentadas (semana 4)

Cada relay en su contenedor y cada salto en su propia red (ISO/IEC 27033): desde cada
red solo se alcanza el siguiente nodo, nadie tiene Internet salvo (opcionalmente) el
relay de salida, y Docker no guarda registros. El puerto publicado llega a una puerta
sin claves que solo reenvía hacia el relay de entrada. Requiere Docker Desktop.
Detalle, diagrama y resultados: [docs/SEMANA4_DOCKER.md](docs/SEMANA4_DOCKER.md).

```powershell
python laboratorio_docker.py preparar      # firma config/directorio.docker.json (IP 10.10.x)
python laboratorio_docker.py iniciar       # imagen + 4 redes + 3 relays + web del laboratorio
python laboratorio_docker.py probar        # segmentación, punta a punta y fallo cerrado
python cliente_proxy.py --directorio config/directorio.docker.json --entrada-via 127.0.0.1:9001
# Firefox con proxy 127.0.0.1:9050 -> http://web/   (muestra 10.10.9.11: el destino no ve tu equipo)
python laboratorio_docker.py detener
```

## Captura de tráfico y paquete de entrega (semana 5)

```powershell
python laboratorio_docker.py capturar --tramo entrada-medio --segundos 20   # también medio-salida y salida-web
python laboratorio_docker.py demo          # estado, pruebas y comandos para presentar
python empaquetar_entrega.py               # MiniOni_entrega_v1.0.zip, verificado sin claves (requiere la etiqueta v1.0)
```

Qué mirar en cada captura: [docs/WIRESHARK.md](docs/WIRESHARK.md). El paquete toma el
informe y la evidencia de la carpeta local `entrega/` (`informe/` y `evidencia/`), que
no va a Git.

## Demostración en 15 minutos

La noche anterior: Docker Desktop abierto, directorio publicado con
`laboratorio_docker.py preparar`, certificados vigentes, Firefox con el proxy en un
perfil aparte y las capturas ya abiertas en Wireshark.

| Min. | Qué se muestra | Comando o acción | Qué decir |
|---|---|---|---|
| 0-2 | Idea y arquitectura | Diagrama de [SEMANA4_DOCKER.md](docs/SEMANA4_DOCKER.md) | Tres saltos y redes separadas: nadie ve a la vez quién navega y adónde |
| 2-4 | Cebolla | `python demo_capas.py` | Cada relay quita solo su capa (ChaCha20-Poly1305) |
| 4-8 | Laboratorio y segmentación | `python laboratorio_docker.py iniciar` y luego `demo` | Sin root, solo lectura, sin capacidades ni registros; desde cada red solo se alcanza el siguiente nodo (ISO/IEC 27033) |
| 8-10 | Navegación | `python cliente_proxy.py --directorio config/directorio.docker.json --entrada-via 127.0.0.1:9001` y Firefox → `http://web/` | El destino ve 10.10.9.11, no el equipo del cliente. Prueba la separación de funciones: todos los nodos están en este equipo, así que la IP pública no se oculta |
| 10-12 | Wireshark | Capturas entrada → medio y salida → web | Dentro de la red solo hay TLS 1.3 de tamaño fijo; solo la salida ve HTTP |
| 12-13 | Fallo cerrado | `docker pause minioni-medio1`, Firefox falla, `docker unpause minioni-medio1` | Si algo cae, no se sale directo |
| 13-14 | Ataque al directorio | `python minioni_admin.py simular-ataque` | La firma Ed25519 detecta el cambio |
| 14-15 | Sin registros | `docker logs minioni-salida1`; panel → «Verificar sin registros» | No queda nada que pueda delatar al usuario |

**Plan B:** si Docker falla en vivo, usa el modo local (`panel.py`) y muestra las salidas
guardadas de `probar` y los `.pcap` ya hechos.

## Revisión de seguridad del código

| Comando | Qué revisa | Norma |
|---|---|---|
| `bandit -c pyproject.toml -r .` | Análisis estático: patrones de código inseguro | NIST SSDF PW.7.2 |
| `python -m pytest tests/test_fuzzing.py --hypothesis-profile=intenso` | Fuzzing: ~100 000 entradas aleatorias a los parsers (tarda unos minutos) | NIST SSDF PW.8.2 · ASVS V2.2.1 |
| `pip-audit -r requirements.txt` | Vulnerabilidades conocidas en las dependencias | NIST SSDF PW.4.1 |
| `python -m bandit -q -r tests -s B101,B104,B105` | Análisis estático de las pruebas (motivos de las 3 reglas omitidas en `docs/CLASE3_CODIFICACION_SEGURA.md`) | NIST SSDF PW.7.2 |
| `python revisar_secretos.py` | Secretos en el código (detect-secrets), claves sin cifrar, `.gitignore`, carpeta en la nube, **secretos en el historial de Git** y `.dockerignore` (ninguna clave en la imagen) | NIST SSDF PS.1 |
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
| [docs/DOCUMENTACION_COMPLETA.md](docs/DOCUMENTACION_COMPLETA.md) | **Empieza aquí:** qué es, cómo funciona, estado, qué falta y uso paso a paso |
| [docs/ARQUITECTURA.md](docs/ARQUITECTURA.md) | Componentes, diagramas, límites de confianza, decisiones |
| [docs/PROTOCOLO.md](docs/PROTOCOLO.md) | Formato de celdas, capas, handshake y directorio |
| [docs/INVENTARIO_CRIPTOGRAFICO.md](docs/INVENTARIO_CRIPTOGRAFICO.md) | Cada clave y algoritmo: dónde vive, qué protege, cuánto dura; plan poscuántico |
| [docs/LIMITES.md](docs/LIMITES.md) | Qué NO protege MiniOni |
| [docs/NAVEGADOR.md](docs/NAVEGADOR.md) | Configurar Firefox y curl con el proxy; demostración de fallo cerrado |
| [docs/SIN_REGISTROS.md](docs/SIN_REGISTROS.md) | Cómo demostrar que las búsquedas no quedan registradas |
| [docs/ROTACION_CLAVES.md](docs/ROTACION_CLAVES.md) | Cuándo y cómo rotar el certificado TLS, la clave cebolla y la autoridad |
| [docs/capturas](docs/capturas) | Capturas del panel gráfico (`panel.py`) |
| [docs/CLASE3_FALLOS_Y_CORRECCIONES.md](docs/CLASE3_FALLOS_Y_CORRECCIONES.md) | Los 11 fallos de la Clase 3: control, causa y corrección |
| [docs/CLASE3_NVD.md](docs/CLASE3_NVD.md) | CVE del NVD que tocan a MiniOni, por control (03-11-2026) |
| [docs/CLASE3_CODIFICACION_SEGURA.md](docs/CLASE3_CODIFICACION_SEGURA.md) | Investigación de los 4 controles (Clase 3): hallazgos, SAST, secretos |
| [docs/SEMANA4_DOCKER.md](docs/SEMANA4_DOCKER.md) | Semana 4: redes segmentadas en Docker, endurecimiento, pruebas y evidencia |
| [docs/WIRESHARK.md](docs/WIRESHARK.md) | Semana 5: cómo capturar cada tramo y qué se debe ver |
| [docs/STRIDE.md](docs/STRIDE.md) | Modelo de amenazas final: control, archivo y prueba de cada amenaza |
| [docs/historial](docs/historial) | Planes y traspasos ya cerrados (documentos de trabajo) |
| [docs/PLAN_ENTREGA_SEMANA5.md](docs/PLAN_ENTREGA_SEMANA5.md) | Entrega final: qué debe tener la aplicación, Wireshark, informe, demostración y paquete |
| [docs/TRAZABILIDAD.md](docs/TRAZABILIDAD.md) | Requisito → norma → código → prueba |

## Plan

| Semana | Entregable | Estado |
|---|---|---|
| 1 | Ficha, requisitos, arquitectura; núcleo criptográfico, directorio firmado, pruebas | ✅ |
| 2 | Relays en red (asyncio + TLS 1.3), límites anti-DoS | ✅ |
| 3 | Nodo de salida, proxy SOCKS5, fail-closed, conexión del navegador | ✅ |
| 4 | Entorno Docker con redes segmentadas, contenedores endurecidos, pruebas de segmentación | ✅ |
| 5 | Pruebas con Wireshark, documentación final e informe | ✅ Terminada (etiqueta `v1.0`, 10-11-2026) |

## Normas

OWASP ASVS 5.0 (V2, V11, V12, V16) · NIST SP 800-218 SSDF (PW.1.1, PW.4.1, PW.7.2, PW.8.2) ·
ISO/IEC 27033 (segmentación y límites de confianza).
