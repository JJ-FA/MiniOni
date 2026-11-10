---
title: "MiniOni – Documentación completa del proyecto"
subtitle: "Qué es, cómo funciona, en qué estado está, qué falta y cómo usarlo paso a paso"
date: "10 de noviembre de 2026 · Equipo Onion (Juan José Figueroa Ayala, Juan David Ramos Rangel)"
---

# 1. Estado del proyecto en una página

**Revisión hecha el 10-11-2026** sobre los archivos de la carpeta del proyecto.

| Semana | Entregable | Estado |
|---|---|---|
| 1 | Idea, requisitos, STRIDE, núcleo criptográfico, directorio firmado | Terminada |
| 2 | Relays en red con TLS 1.3 y límites contra abuso | Terminada |
| 3 | Nodo de salida, proxy SOCKS5, navegador, panel gráfico, "sin registros" | Terminada |
| Clase 3 | Codificación segura: 4 controles, 11 fallos corregidos, SAST y secretos | Terminada |
| 4 | Laboratorio Docker con redes segmentadas, verificado en Windows el 09-11-2026 | Terminada |
| 5 | Captura con Wireshark, demostración, paquete y borrador del informe | Terminada en el código (etiqueta `v1.0`); falta lo de la sección 6 |

**Números de hoy** (medidos en Windows el 10-11-2026):

- 496 pruebas aprobadas y 1 omitida, 0 fallos.
- Bandit: 0 hallazgos en 6 023 líneas del programa y 0 en las pruebas.
- 19 módulos en `minioni/` y 18 archivos de pruebas.

**Lo que falta** está en la sección 6: las tareas que el plan reserva al equipo y dos
pendientes menores de orden.

# 2. Qué es MiniOni

MiniOni es una red de **enrutamiento cebolla** (*onion routing*) de laboratorio,
inspirada en Tor y escrita en Python. Sirve para que nadie en el camino pueda saber a
la vez **quién** navega y **adónde**.

- El navegador (Firefox) se conecta a un **proxy SOCKS5** local, en `127.0.0.1:9050`.
- El proxy arma un **circuito de 3 relays**: entrada, intermedio y salida.
- El tráfico viaja con **3 capas de cifrado**. Cada relay quita solo la suya.
- La entrada conoce al usuario pero no el destino. La salida conoce el destino pero no
  al usuario. El intermedio no conoce a ninguno.
- **No se guarda ningún registro** de lo que se navega: ni IP, ni dominios, ni contenido.

MiniOni **no es un navegador** ni un reemplazo de Tor. Es un proyecto académico para
una red local o un laboratorio Docker (ver sección 9).

# 3. Cómo funciona

## 3.1 Recorrido de una página

```
Firefox ──SOCKS5──> proxy (tu equipo, 127.0.0.1:9050)
                       │  3 capas de cifrado, celdas de 512 bytes, TLS 1.3
                       ▼
                   entrada1 ──> medio1 ──> salida1 ──> sitio web
                   quita capa 1  quita capa 2  quita capa 3 y se conecta al destino
```

1. El proxy lee el **directorio firmado** (la lista de relays) y verifica la firma.
2. Elige la ruta y hace un **intercambio de claves** con cada relay, uno por uno.
3. Firefox pide una página. El proxy la parte en **celdas de 512 bytes**, todas del
   mismo tamaño, y las cifra tres veces.
4. Cada relay quita una capa y pasa la celda al siguiente por **TLS 1.3**.
5. La salida resuelve el nombre del sitio (DNS remoto), revisa la **política de
   salida** y se conecta. La respuesta vuelve por el mismo camino.
6. Si cualquier paso falla, el circuito se destruye y la conexión se corta. **Nunca**
   se sale directo a Internet (fallo cerrado).

## 3.2 Componentes

| Componente | Archivo | Qué hace |
|---|---|---|
| Celdas | `minioni/celdas.py` | Formato fijo de 512 bytes y validación de todo lo que entra |
| Capas | `minioni/capas.py` | Cifrado y descifrado por capa (ChaCha20-Poly1305) |
| Handshake | `minioni/handshake.py` | Intercambio de claves con cada relay (X25519, tipo ntor) |
| Directorio | `minioni/directorio.py` | Lista de relays firmada con Ed25519, con vigencia y versión |
| Almacén de claves | `minioni/almacen_claves.py` | Claves privadas cifradas en disco (scrypt + ChaCha20-Poly1305) |
| Transporte | `minioni/transporte.py` | TLS 1.3 entre nodos, verificación de huella y de vencimiento |
| Relay | `minioni/relay.py` | Nodo de la red: entrada, intermedio o salida |
| Política de salida | `minioni/politica_salida.py` | Qué destinos puede abrir la salida (puertos 80 y 443, IP públicas) |
| Circuito | `minioni/circuito.py` | Lado cliente: arma el circuito de 3 saltos |
| SOCKS5 y proxy | `minioni/socks5.py`, `minioni/proxy.py` | Puerta de entrada para el navegador |
| Consola | `minioni/consola.py` | Único canal de mensajes: lista cerrada de eventos, sin datos sensibles |
| Errores | `minioni/errores.py` | Errores con mensaje público genérico |
| Administración | `minioni/admin.py` | Crear claves, firmar el directorio, rotar certificados |
| Control de red | `minioni/control_red.py` | Motor del panel: arranca y detiene relays y proxy (local o Docker) |
| Sin registros | `minioni/sin_registros.py` | Verifica que nada se escribe en disco al navegar |
| Confianza Windows | `minioni/confianza_windows.py` | Certificados raíz de Windows para "Abrir por MiniOni" del panel |
| Análisis de capturas | `minioni/analisis_pcap.py` | Resume un `.pcap` sin Wireshark (semana 5) |

## 3.3 Criptografía usada

| Para qué | Algoritmo | Detalle |
|---|---|---|
| Cifrar cada capa | ChaCha20-Poly1305 | Cifrado autenticado; el contador de mensajes impide repetir o reordenar |
| Acordar claves con cada relay | X25519 + HKDF-SHA256 | Claves nuevas en cada circuito (secreto hacia adelante) |
| Firmar el directorio | Ed25519 | Con número de versión para impedir volver a uno viejo (anti-rollback) |
| Proteger el canal entre nodos | TLS 1.3 | Solo 1.3; se comprueba la huella del certificado contra el directorio |
| Guardar claves privadas | scrypt (N = 2¹⁷) + ChaCha20-Poly1305 | Protegidas con contraseña de al menos 12 caracteres, no común |

No se inventó ningún algoritmo: todo viene de la librería `cryptography`. Detalle en
`docs/INVENTARIO_CRIPTOGRAFICO.md` y `docs/PROTOCOLO.md`.

## 3.4 Laboratorio Docker (semana 4)

Cada relay corre en su propio contenedor y **cada salto tiene su propia red**:

| Red | Subred | Quién está | Internet |
|---|---|---|---|
| `red_publica` | 10.10.7.0/24 | puerta (reenviador sin claves) | Solo la puerta |
| `red_cliente` | 10.10.1.0/24 | puerta, entrada1 | No |
| `red_entrada_medio` | 10.10.2.0/24 | entrada1, medio1 | No |
| `red_medio_salida` | 10.10.3.0/24 | medio1, salida1 | No |
| `red_destinos` | 10.10.9.0/24 | salida1, web del laboratorio | No |
| `red_internet` (opcional) | 10.10.8.0/24 | salida1 | Sí, solo la salida |

- Desde cada red solo se alcanza el siguiente nodo; nadie puede saltarse un relay.
- Tu equipo llega a la red por un único puerto, `127.0.0.1:9001`, que apunta a la
  **puerta**: un contenedor sin claves que solo reenvía hacia entrada1.
- Los contenedores corren sin root, con disco de solo lectura, sin privilegios y con
  los **registros de Docker apagados**.
- La web del laboratorio (`http://web/`) muestra desde qué IP le llega la conexión:
  siempre `10.10.9.11`, el relay de salida, nunca tu equipo.

Detalle, diagrama y resultados en `docs/SEMANA4_DOCKER.md`.

# 4. Seguridad y normas

## 4.1 Requisitos del proyecto

| Req. | Qué exige | Cómo se cumple | Norma |
|---|---|---|---|
| R1 | Validar toda entrada | Listas blancas en todos los parsers; unas 105 000 entradas aleatorias de fuzzing | OWASP ASVS 5.0 V2.2.1 |
| R2 | Cifrado autenticado | ChaCha20-Poly1305 por capa y TLS 1.3 entre nodos | ASVS 5.0 V11.3, V12 |
| R3 | Firmas e intercambio de claves | Directorio Ed25519 y handshake X25519 | ASVS 5.0 V11.6 |
| R4 | Fallo seguro y errores genéricos | Fallo cerrado; mensajes sin detalles internos | ASVS 5.0 V16.5 |
| R5 | Amenazas y componentes seguros | STRIDE, versiones fijas, `pip-audit`, imagen fijada por digest | NIST SSDF PW.1.1, PW.4.1 |
| Red | Segmentación | Una red por salto en Docker | ISO/IEC 27033 |
| Privacidad | No registrar nada | Consola de lista cerrada, cero archivos, Docker sin registros | ASVS 5.0 V16.2.5 |

La tabla completa (requisito → norma → código → prueba) está en `docs/TRAZABILIDAD.md`.

## 4.2 Controles de la Clase 3

| Control | Qué hay |
|---|---|
| Validación | Listas blancas con `fullmatch`, puertos 1–65535, apodos limitados |
| Errores y logging | Mensajes genéricos, manejador de último recurso, texto externo neutralizado |
| Cifrado | TLS 1.3, vencimiento de certificados, scrypt fuerte, contraseñas no comunes |
| SAST y secretos | Bandit en programa y pruebas, `revisar_secretos.py`, hook de Git |

Se encontraron y corrigieron 11 fallos (`docs/CLASE3_FALLOS_Y_CORRECCIONES.md`).

## 4.3 Herramientas de revisión

| Comando | Qué revisa |
|---|---|
| `python -m pytest` | Todas las pruebas automáticas |
| `bandit -c pyproject.toml -r .` | Código inseguro en el programa |
| `python -m bandit -q -r tests -s B101,B104,B105` | Código inseguro en las pruebas |
| `python revisar_secretos.py` | Secretos en archivos, historial de Git, claves sin cifrar, imagen de Docker |
| `pip-audit -r requirements.txt` | Vulnerabilidades conocidas en las dependencias |
| `python revision_completa.py` | Todo lo anterior con un resumen (`--con-docker`, `--con-internet`) |

# 5. Estructura de la carpeta

```
MiniOni/
├── minioni/                  Código de la red (sección 3.2)
├── panel.py                  Panel gráfico: la forma más fácil de usarlo
├── minioni_admin.py          Claves, directorio, certificados
├── ejecutar_relay.py         Arranca un relay
├── cliente_proxy.py          Proxy SOCKS5 para el navegador
├── cliente_prueba.py         Prueba de eco por un circuito
├── demo_capas.py             Demostración de las capas, sin red
├── laboratorio_docker.py     Laboratorio Docker: preparar, iniciar, probar, estado, eventos, capturar, demo, detener
├── empaquetar_entrega.py     Arma el paquete final y comprueba que no lleve secretos
├── Dockerfile, docker-compose.yml, docker-compose.internet.yml, .dockerignore
├── docker/                   puerta.py, servidor_web.py, sonda.py, Dockerfile.captura
├── revisar_secretos.py       Revisión de secretos
├── revision_completa.py      Todas las comprobaciones
├── hooks/pre-commit          Revisa secretos antes de cada commit
├── config/                   Listas de relays, políticas de salida, directorios firmados
├── tests/                    18 archivos de pruebas
├── docs/                     Documentación (sección 10)
├── COMANDOS.txt              Todos los comandos explicados
└── README.md                 Resumen y arranque rápido
```

Las **claves privadas** no deben estar en esta carpeta, porque se sincroniza con
OneDrive. Van en la carpeta local que indica la variable `MINIONI_CLAVES`.

# 6. Qué falta por desarrollar

## 6.1 Lo que el plan reserva al equipo

El código, las capturas, el STRIDE final, el borrador del informe y la etiqueta `v1.0`
ya están hechos.
Falta lo que debe hacer una persona (`docs/PLAN_ENTREGA_SEMANA5.md`):

| Tarea | Qué falta | Importancia |
|---|---|---|
| S5-T2 | Que alguien del grupo instale el proyecto siguiendo solo el README, incluidas las claves y Firefox | Alta |
| S5-T5 | Escribir las conclusiones, agregar los pantallazos y exportar el informe a PDF | Alta |
| S5-T6 | Ensayar la demostración con el cronómetro | Media |
| S5-T7 | Generar el paquete con `empaquetar_entrega.py` después de la etiqueta | Alta |
| S5-T8 | Revisión cruzada del paquete por alguien que no lo hizo | Media |

## 6.2 Pendientes menores

1. **Carpeta `claves` vieja dentro del proyecto.** Las claves actuales ya están en
   `MINIONI_CLAVES`. Falta borrar esa carpeta y vaciar la papelera de OneDrive.
2. **`errores.txt` en la raíz.** Es una salida de diagnóstico de octubre. Git la
   ignora, y el paquete tampoco la incluye, pero conviene borrarla.

## 6.3 Fuera del alcance (trabajo futuro para el informe)

Más relays por posición, control de flujo de extremo a extremo, autenticación entre
relays, servicios ocultos y criptografía poscuántica.

# 7. Cómo usarlo paso a paso

Todos los comandos son para **PowerShell en Windows**.

## 7.1 Instalación (una sola vez)

1. Instalar **Python 3.10 o superior** (el equipo usa 3.14).
2. Abrir PowerShell en la carpeta del proyecto y crear el entorno:

```powershell
cd C:\Users\Harpe\OneDrive\Desktop\MiniOni
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
```

3. Para el laboratorio Docker, instalar **Docker Desktop** con WSL 2, abrirlo y
   esperar a que diga *Engine running*.

**Cada vez que abras PowerShell** hay que entrar a la carpeta y activar el entorno:

```powershell
cd C:\Users\Harpe\OneDrive\Desktop\MiniOni
.\.venv\Scripts\Activate.ps1
```

## 7.2 Crear las claves (una sola vez)

1. Definir una carpeta de claves **fuera de OneDrive**:

```powershell
mkdir C:\MiniOniClaves
setx MINIONI_CLAVES C:\MiniOniClaves
```

2. Cerrar PowerShell, abrir una ventana nueva y activar el entorno.
3. Comprobar la carpeta y crear todo en un paso:

```powershell
python minioni_admin.py donde-estan-las-claves
python minioni_admin.py preparar-laboratorio --relays config\relays.local.json
```

Pide una contraseña de **12 caracteres o más** que no sea común. Esa contraseña se usa
después para arrancar los relays. No se guarda en ningún lado: si se olvida, hay que
crear las claves de nuevo.

4. Comprobar que todo quedó bien:

```powershell
python -m pytest
python revisar_secretos.py
```

## 7.3 Forma más fácil: el panel gráfico

```powershell
python panel.py
```

1. Elegir el modo en la cabecera: **Local** (todo en tu equipo) o **Docker** (redes
   segmentadas; Docker Desktop debe estar abierto).
2. Firmar el directorio del modo elegido: **Publicar directorio local** o **Firmar
   directorio Docker**. Hace falta la primera vez, al cambiar de modo y cada 7 días.
3. Escribir la contraseña y pulsar **Iniciar red**. En Docker la primera vez tarda
   varios minutos y solo muestra "Fase N de 4".
4. Probar:
   - **Probar circuito**: eco por los 3 saltos.
   - **Abrir por MiniOni**: pide una página por la red.
   - **Apagar / Encender** un relay: demuestra el fallo cerrado.
   - **Probar segmentación** (solo Docker): muestra la matriz de redes.
   - **Verificar sin registros**: comprueba que nada se escribe en disco.
5. Configurar Firefox (sección 7.6) y navegar.
6. Cerrar la ventana para apagar todo.

## 7.4 Modo local a mano (sin panel)

Orden: **directorio → 3 relays → proxy → navegador**.

1. Firmar el directorio local. El número de versión debe ser mayor que el anterior:

```powershell
python minioni_admin.py publicar-directorio --version 3 --relays config/relays.local.json
```

2. Abrir **tres ventanas** de PowerShell, una por relay. Cada una pide la contraseña:

```powershell
python ejecutar_relay.py --apodo entrada1
python ejecutar_relay.py --apodo medio1
python ejecutar_relay.py --apodo salida1
```

3. En una cuarta ventana, probar el circuito y dejar el proxy corriendo:

```powershell
python cliente_prueba.py
python cliente_proxy.py
```

4. En una quinta ventana o en Firefox:

```powershell
curl.exe --socks5-hostname 127.0.0.1:9050 https://example.com
```

5. Para apagar, **Ctrl+C** en cada ventana.

## 7.5 Laboratorio Docker a mano

Con Docker Desktop abierto:

```powershell
python laboratorio_docker.py preparar      # firma el directorio de Docker (cada 7 días)
python laboratorio_docker.py iniciar       # pide la contraseña una vez
python laboratorio_docker.py probar        # debe terminar en "Todo correcto"
python laboratorio_docker.py estado        # seguridad de cada contenedor
```

En otra ventana, el proxy apuntando a Docker:

```powershell
python cliente_proxy.py --directorio config/directorio.docker.json --entrada-via 127.0.0.1:9001
```

Luego Firefox en `http://web/`, o:

```powershell
curl.exe --socks5-hostname 127.0.0.1:9050 http://web/
```

La página debe decir que la conexión llega desde **10.10.9.11**.

- Para navegar sitios reales: `python laboratorio_docker.py iniciar --con-internet`.
  Solo el relay de salida recibe Internet.
- Para ver la consola de un relay sin guardarla: `python laboratorio_docker.py eventos salida1`.
- Para apagar: `python laboratorio_docker.py detener`.

## 7.6 Configurar Firefox

1. **Ajustes → General → Configuración de red → Configuración…**
2. Elegir **Configuración manual del proxy**.
3. **Host SOCKS:** `127.0.0.1`, **Puerto:** `9050`, marcar **SOCKS v5**. Dejar vacíos
   los campos HTTP y HTTPS.
4. Marcar **Usar proxy DNS cuando se use SOCKS v5**. Sin esta casilla, `http://web/`
   da "Servidor no encontrado".
5. En `about:config`, poner `media.peerconnection.enabled` en `false`.

Conviene usar un **perfil aparte** de Firefox para el laboratorio. Para volver a
navegar normal: Configuración de red → **Sin proxy**. Detalle en `docs/NAVEGADOR.md`.

## 7.7 Demostraciones

| Qué demostrar | Cómo | Qué debe pasar |
|---|---|---|
| Tráfico ilegible entre nodos | `python laboratorio_docker.py capturar --tramo entrada-medio` y `docs/WIRESHARK.md` | Solo TLS 1.3, sin texto en claro |
| Capas de cifrado | `python demo_capas.py` | Cada salto quita una capa |
| Directorio alterado | `python minioni_admin.py simular-ataque` | Se rechaza por la firma |
| Fallo cerrado | Apagar medio1 (panel, Ctrl+C o `docker pause minioni-medio1`) y recargar | La página falla; no sale directo |
| Política de salida | `curl.exe --socks5-hostname 127.0.0.1:9050 http://web:22/` | Bloqueado |
| Segmentación | `python laboratorio_docker.py probar` | Matriz con un solo "sí" por red |
| Destino no ve al usuario | `http://web/` en Firefox | Muestra 10.10.9.11 |
| Sin registros | Botón del panel; `docker logs minioni-salida1` | Nada escrito; Docker dice que no hay registros |

## 7.8 Mantenimiento

| Tarea | Comando | Cuándo |
|---|---|---|
| Renovar el directorio | `publicar-directorio` o `laboratorio_docker.py preparar` | Cada 7 días |
| Ver vencimiento de certificados | `python minioni_admin.py revisar-certificados` | Antes de cada demostración |
| Renovar un certificado | `python minioni_admin.py renovar-certificado --apodo X` y publicar de nuevo | Cada 90 días |
| Revisión completa | `python revision_completa.py` | Antes de cada entrega y de cada commit importante |
| Actualizar la imagen de Docker | `docs/SEMANA4_DOCKER.md`, sección 4.3 | Cuando haya un parche de seguridad |

`COMANDOS.txt` explica cada comando con más detalle.

# 8. Problemas frecuentes

| Qué sale | Causa | Solución |
|---|---|---|
| "Contraseña incorrecta" | No es la contraseña con que se crearon las claves | Hay 3 intentos. Si se olvidó, `preparar-laboratorio --reiniciar` crea todo de nuevo |
| El directorio no es válido o venció | Pasaron 7 días o se cambió de modo | Firmarlo de nuevo (sección 7.4 o 7.5) |
| Directorio firmado por una autoridad más nueva | Las claves se regeneraron | Publicar el directorio otra vez |
| Versión del directorio rechazada | El número no es mayor que el último visto | Usar un `--version` más alto |
| "certificado TLS vencido" | Pasaron 90 días | `renovar-certificado` y publicar de nuevo |
| `curl: (97)` o Firefox rechaza el proxy | No hay circuito: falta un relay o el proxy | Revisar que los 3 relays y el proxy estén corriendo |
| Firefox: "Servidor no encontrado" en `http://web/` | Falta el proxy DNS | Marcar "Usar proxy DNS cuando se use SOCKS v5" |
| "Docker no responde" | Docker Desktop cerrado | Abrirlo y esperar *Engine running* |
| No se crean las redes (la subred ya existe) | Quedó un laboratorio anterior o tu red usa 10.10.x | `laboratorio_docker.py detener`; si sigue, cambiar las subredes (`docs/historial/TRASPASO_SEMANA4_CLAUDE_CODE.md`) |
| Un sitio real no abre en Docker | El laboratorio está en modo cerrado | Usar `iniciar --con-internet` |
| Aviso de OneDrive en `revisar_secretos.py` | Las claves están en una carpeta sincronizada | Sección 7.2 |

# 9. Límites: qué NO protege MiniOni

- Es un **laboratorio**: con 3 relays en un mismo equipo no hay anonimato real.
- No oculta la huella del navegador, las cookies ni lo que escribas en un sitio.
- La **salida ve el contenido** si el sitio no usa HTTPS.
- Quien observe la entrada y la salida a la vez puede correlacionar por tiempos.
- Los relays no se autentican entre sí; cualquiera en la red puede conectarse a uno.

La lista completa y las decisiones tomadas están en `docs/LIMITES.md`.

# 10. Índice de la documentación

| Documento | Para qué sirve |
|---|---|
| `README.md` | Resumen y arranque rápido |
| `COMANDOS.txt` | Todos los comandos, explicados |
| `docs/ARQUITECTURA.md` | Componentes, diagramas y decisiones de diseño |
| `docs/PROTOCOLO.md` | Formato de celdas, capas, handshake y directorio |
| `docs/INVENTARIO_CRIPTOGRAFICO.md` | Cada clave y algoritmo |
| `docs/LIMITES.md` | Qué no protege y por qué |
| `docs/TRAZABILIDAD.md` | Requisito → norma → código → prueba |
| `docs/NAVEGADOR.md` | Firefox y curl con el proxy |
| `docs/SIN_REGISTROS.md` | Cómo demostrar que no se registra nada |
| `docs/ROTACION_CLAVES.md` | Rotar certificados y claves |
| `docs/SEMANA4_DOCKER.md` | Laboratorio Docker: diseño, uso, resultados y evidencia |
| `docs/WIRESHARK.md` | Cómo capturar cada tramo y qué se debe ver |
| `docs/STRIDE.md` | Modelo de amenazas final |
| `docs/CLASE3_CODIFICACION_SEGURA.md` | Respuestas del OVA de la Clase 3 |
| `docs/CLASE3_FALLOS_Y_CORRECCIONES.md` | Los 11 fallos y sus correcciones |
| `docs/CLASE3_NVD.md` | Vulnerabilidades públicas que tocan al proyecto |
| `docs/PLAN_ENTREGA_SEMANA5.md` | Qué falta para la entrega final |
| `docs/historial/TRASPASO_CLASE3_CLAUDE_CODE.md`, `docs/historial/TRASPASO_SEMANA4_CLAUDE_CODE.md`, `docs/historial/PLAN_SEMANAS_2_3.md` | Documentos de trabajo para Claude Code (reglas 1 a 32) |
| `MiniOni - Fundamentos técnicos.pdf` | Explicación de los conceptos base |
