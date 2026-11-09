---
title: "MiniOni – Traspaso de la semana 4 para Claude Code"
subtitle: "Laboratorio Docker con redes segmentadas: qué se cambió, qué reglas nuevas rigen el código y qué falta hacer"
date: "8 de noviembre de 2026 · Equipo Onion"
---

# 0. Cómo usar este documento

Este documento explica todo lo que se hizo en la **semana 4** de MiniOni (laboratorio
Docker con redes segmentadas, ISO/IEC 27033) y lo que todavía falta para cerrarla. Está
escrito para que un asistente de programación (Claude Code) continúe sin repetir trabajo
ni deshacer decisiones de seguridad.

Las decisiones ya están tomadas. Si algo no está especificado, se elige la opción **más
restrictiva** y se documenta. Las tareas de la sección 6 se hacen **en orden**, y cada
una tiene criterios de aceptación.

Documentos relacionados, que se leen en este orden:

1. `docs/TRASPASO_CLASE3_CLAUDE_CODE.md`: reglas 1 a 22 (siguen vigentes).
2. `docs/SEMANA4_DOCKER.md`: diseño, diagrama, resultados y evidencia de la semana 4.
3. `docs/PLAN_ENTREGA_SEMANA5.md`: lo que la aplicación debe tener el día de la entrega.

## 0.1 Antes de escribir código

```powershell
cd C:\Users\Harpe\OneDrive\Desktop\MiniOni
.\.venv\Scripts\Activate.ps1
python -m pytest                      # referencia: 387 passed, 3 skipped (Linux, 08-11-2026)
python revision_completa.py           # debe terminar en "Todo correcto"
docker version                        # Docker Desktop instalado y abierto ("Engine running")
```

Si `docker version` falla, la tarea S4-T1 empieza por instalar Docker Desktop (sección
4.1 de `docs/SEMANA4_DOCKER.md`).

**Nunca** ejecutar `preparar-laboratorio --reiniciar` ni borrar la carpeta de claves sin
que el equipo lo pida. Las contraseñas las escribe siempre la persona.

# 1. Qué se construyó en la semana 4

Antes, los tres relays corrían en el mismo computador, en `127.0.0.1`, y cualquiera
podía hablar con cualquiera. Ahora cada relay vive en su propio contenedor y **cada
salto del circuito tiene su propia red**:

| Red | Subred | Nodos | Tipo |
|---|---|---|---|
| `red_publica` | 10.10.7.0/24 | puerta (10.10.7.10) | Puente sin NAT de salida; publica solo `127.0.0.1:9001` (agregada el 09-11-2026, ver regla 28) |
| `red_cliente` | 10.10.1.0/24 | puerta (.11), entrada1 (10.10.1.10) | `internal: true` |
| `red_entrada_medio` | 10.10.2.0/24 | entrada1 (.11), medio1 (10.10.2.10) | `internal: true` |
| `red_medio_salida` | 10.10.3.0/24 | medio1 (.11), salida1 (10.10.3.10) | `internal: true` |
| `red_destinos` | 10.10.9.0/24 | salida1 (.11), web (10.10.9.20) | `internal: true` |
| `red_internet` (opcional) | 10.10.8.0/24 | salida1 | Solo con `--con-internet` |

Cada relay escucha **solo** en la IP que dice el directorio, así que desde cada red se
alcanza un único servicio. El navegador y el proxy siguen en Windows: el proxy llega a
la entrada por el puerto que Docker publica en `127.0.0.1:9001`.

**Resultado verificado (08-11-2026, Docker 29.9):** `python laboratorio_docker.py
probar` dio *Todo correcto*:

- La matriz de segmentación coincide con lo esperado.
- El eco y la página `http://web/` llegan por el proxy.
- El destino ve `10.10.9.11` (el relay de salida), no al cliente.
- La política de salida bloquea el puerto 22 y los relays internos.
- Hay fallo cerrado al pausar medio1.
- `docker logs` responde que no hay registros.

# 2. Cambios aplicados

## 2.1 Archivos nuevos

| Archivo | Qué es |
|---|---|
| `Dockerfile` | Una imagen para todo (relays, web y sonda). `ARG BASE=python:3.14-slim`, `COPY` con lista blanca, `USER 10001:10001`, `PYTHONPATH=/app`, `MINIONI_CLAVES=/app/claves`. |
| `.dockerignore` | Excluye `claves/`, `**/*.key`, `config/`, `.git/`, `.venv/`, `tests/`, `docs/` y más. |
| `docker-compose.yml` | 4 redes, 3 relays y la web. Ancla `x-endurecido`: solo lectura, usuario 10001, `cap_drop: [ALL]`, `no-new-privileges`, límites de PID, memoria y CPU, **`logging: driver: none`** y `/tmp` en `tmpfs` privado. Ancla `x-relay`: agrega `stdin_open: true`. |
| `docker-compose.internet.yml` | Opcional: conecta **solo** salida1 a `red_internet`. |
| `config/politica_salida.docker.json` | Puertos 80 y 443 más la excepción documentada `10.10.9.0/24` (la web del laboratorio). |
| `docker/servidor_web.py` | Web de destino: página fija que muestra la IP que ve; `log_message` no hace nada. |
| `docker/sonda.py` | Contenedor desechable con dos modos: `alcance` (matriz de segmentación) y `punta-a-punta` (eco, página por el proxy, política de salida). Imprime una línea JSON. |
| `laboratorio_docker.py` | Orquestador con los comandos `preparar`, `iniciar [--con-internet]`, `probar`, `estado`, `eventos APODO` y `detener`. |
| `tests/test_semana4_docker.py` | 45 pruebas que no necesitan Docker (código nuevo y reglas estáticas de compose, Dockerfile y .dockerignore). |
| `docs/SEMANA4_DOCKER.md` | Diseño, endurecimiento, uso, resultados y evidencia. |

## 2.2 Archivos modificados

| Archivo | Cambio | Por qué |
|---|---|---|
| `minioni/transporte.py` | `conectar(relay, ctx, timeout, direccion=None)` | Conectar el primer salto a otra dirección (el puerto publicado). La huella TLS del directorio se verifica igual. |
| `minioni/circuito.py` | `CircuitoCliente(..., entrada_via=None)`; `elegir_ruta` respeta la marca `entrada` | Con la red segmentada, la ruta debe ser entrada → medio → salida. |
| `minioni/directorio.py` | Campo opcional `"entrada"` (booleano) en cada relay; `Relay.entrada = False`; entrada y salida a la vez se rechaza | Equivale a la marca *Guard* de Tor. Los directorios anteriores siguen siendo válidos. |
| `minioni/proxy.py` | `argumento_entrada_via` (solo `127.x.x.x:puerto`); `ruta_ultima_version`; `GestorCircuitos(entrada_via=)` | Opción `--entrada-via` y un contador anti-rollback separado para cada directorio. |
| `minioni/admin.py` | `publicar-directorio --salida directorio.<algo>.json` (`destino_directorio`, lista blanca y validación antes de pedir la contraseña); campo `entrada` en `armar_directorio`; `_version_siguiente(config, directorio, ultima)` | El directorio de Docker convive con el local. |
| `ejecutar_relay.py` | `--contrasena-por-entrada` → `leer_contrasena_por_entrada()` (una línea, máximo 1024 caracteres) | En un contenedor no hay teclado. |
| `cliente_proxy.py`, `cliente_prueba.py` | `--entrada-via 127.0.0.1:PUERTO`; anti-rollback por directorio | Usar los relays de Docker desde Windows. |
| `config/relays.json` | Campo `"entrada": true` solo en entrada1 | Ruta fija con la red segmentada. |
| `revisar_secretos.py` | Paso 7: `.dockerignore` debe excluir `claves/`, `**/*.key` y `config/` | Una clave copiada a una imagen queda en sus capas. |
| `revision_completa.py` | Opción `--con-docker` (agrega `laboratorio_docker.py probar`) | Revisión completa con el laboratorio. |
| `.gitignore` | `config/ultima_version.*` y `config/directorio.docker.json` | Archivos generados. |
| `README.md`, `COMANDOS.txt` (CRLF), `docs/TRAZABILIDAD.md`, `docs/LIMITES.md`, `docs/PROTOCOLO.md`, `docs/ARQUITECTURA.md` | Sección de Docker, 8 filas de trazabilidad, decisiones y límites, campo `entrada`, decisiones de diseño | Documentación al día. |

## 2.3 Problemas encontrados al probar y cómo se resolvieron

1. **El cliente empezaba a veces por medio1.** `elegir_ruta` mezclaba al azar los dos
   relays que no son de salida, pero con redes segmentadas el cliente solo llega a la
   entrada. Se resolvió con la marca `entrada` en el directorio.
2. **El relay no arrancaba con el disco en solo lectura** ("no se pudo abrir la clave").
   `transporte.contexto_servidor` escribe por un instante la clave TLS, cifrada con una
   contraseña aleatoria de un solo uso, porque `ssl.load_cert_chain` solo acepta
   archivos. Se resolvió con `/tmp` en `tmpfs`
   (`rw,noexec,nosuid,nodev,size=1m,uid=10001,gid=10001,mode=0700`): está en memoria,
   es privado y nunca toca un disco.
3. **La sonda no encontraba el paquete `minioni`** al correr `docker/sonda.py` como
   script. Se resolvió con `ENV PYTHONPATH=/app` en el Dockerfile.

# 3. Reglas nuevas de la semana 4

Se suman a las reglas 1 a 22 de `docs/TRASPASO_CLASE3_CLAUDE_CODE.md`.

| # | Regla | Vigilada por |
|---|---|---|
| 23 | **Todo contenedor usa `logging: driver: none`** (y `--log-driver none` en los `docker run` de la sonda). Para ver la consola se usa `laboratorio_docker.py eventos`, que no guarda nada. | `test_docker_no_guarda_registros_y_contenedores_endurecidos` |
| 24 | **Ninguna clave ni la carpeta `config/` entran a la imagen.** `COPY` siempre con lista blanca (nunca `COPY . .`) y `.dockerignore` completo. | `test_imagen_sin_claves_y_sin_root`, `revisar_secretos.py` paso 7 |
| 25 | **Cada relay monta solo `<claves>/<su apodo>` en `:ro`.** Nunca la carpeta completa ni la clave de la autoridad. | `test_cada_relay_recibe_solo_sus_claves_y_en_solo_lectura` |
| 26 | **La contraseña nunca va en `environment`, `command`, argumentos, archivos ni secretos de Docker.** Solo `getpass` en el equipo → entrada estándar del relay (`docker attach`). | `test_docker_no_guarda_registros...` (busca CONTRASENA y PASSWORD), `test_sondas_endurecidas_y_entorno_sin_secretos` |
| 27 | **Contenedores endurecidos:** `read_only`, usuario 10001, `cap_drop: [ALL]`, `no-new-privileges` y límites. Prohibidos `privileged:`, `network_mode`, `cap_add` y montar `/var/run/docker.sock`. | mismas pruebas |
| 28 | **Solo se publica la puerta de la entrada, y solo en `127.0.0.1`.** Las redes de relays y destinos son `internal: true`; solo la puerta, sin claves, está en `red_publica`. Cambio aprobado el 09-11-2026: en Docker Desktop una red sin NAT de salida igual llegaba a Internet. | `test_solo_la_puerta_de_la_entrada_se_publica...`, `test_la_puerta_es_la_unica_en_la_red_con_salida...`, `test_redes_segmentadas_sin_salida_a_internet` |
| 29 | **Si se cambia la topología**, se actualizan juntos `docker-compose.yml`, `config/relays.json`, `REDES_ESPERADAS` y `OBJETIVOS` (en `laboratorio_docker.py` y `docker/sonda.py`) y la tabla de `docs/SEMANA4_DOCKER.md`. | `test_redes_segmentadas...`, `python laboratorio_docker.py probar` |
| 30 | **`--entrada-via` solo acepta loopback**, y nunca reemplaza la verificación de la huella. | `test_entrada_via_rechaza_todo_lo_demas`, `test_entrada_via_hacia_otro_relay_se_rechaza_por_la_huella` |
| 31 | **Un relay no puede ser entrada y salida a la vez** (vería la IP del cliente y el destino). | `test_un_relay_no_puede_ser_entrada_y_salida` |
| 32 | **`/tmp` del contenedor solo como `tmpfs` privado y sin ejecución.** No agregar otros montajes con escritura. | revisión manual de `docker-compose.yml` |

# 4. Cómo funciona `laboratorio_docker.py` (para modificarlo sin romperlo)

- **`preparar`:** firma `config/directorio.docker.json` a partir de `config/relays.json`
  con `admin.publicar_directorio(..., salida="directorio.docker.json")`. La versión sale
  de `ultima_version.docker` y del directorio existente, más 1. Vigencia de 7 días.
- **`iniciar`:**
  1. Verifica el directorio y pide la contraseña (3 intentos), comprobándola al
     descifrar `entrada1/cebolla.key`.
  2. Ejecuta `docker compose build`, `down` y `up -d`.
  3. Para cada relay abre `docker attach --sig-proxy=false`, escribe la contraseña y
     espera la línea con el texto del evento `ARRANQUE` ("nodo iniciado"), con un
     máximo de 60 s. Luego cierra el attach; el relay sigue funcionando.
  4. Si un relay falla, ejecuta `compose down` y muestra un mensaje fijo.
- **Variables de compose:** `MINIONI_CARPETA_CLAVES` (la carpeta de claves en formato
  `C:/...`, la define el orquestador; **no es un secreto**) y `MINIONI_IMAGEN_BASE`
  (solo para pruebas sin Docker Hub; por defecto `python:3.14-slim`).
- **`probar`:** lanza sondas endurecidas con `docker run --rm --network minioni_<red>`,
  más el eco desde el equipo por `127.0.0.1:9001` y la prueba de fallo cerrado
  (`docker pause` / `unpause` de medio1).
- **Llamadas a Docker:** todas usan `subprocess` con listas fijas, sin shell y con la
  ruta completa de `shutil.which("docker")`; los `# nosec` llevan su motivo. Los
  errores muestran mensajes fijos, nunca la salida cruda de Docker.

# 5. Estado de verificación

| Comprobación | Linux (entorno de prueba) | Windows (equipo del grupo) |
|---|---|---|
| `python -m pytest` | 387 passed, 3 skipped | **Pendiente** (S4-T1) |
| Bandit del programa y de las pruebas | 0 hallazgos | **Pendiente** |
| `revisar_secretos.py` | Sin secretos; paso 7 OK | **Pendiente** |
| `laboratorio_docker.py iniciar` y `probar` | Todo correcto | **Pendiente** (S4-T1) |
| Firefox → `http://web/` | Probado con `curl --socks5-hostname` | **Pendiente** |
| `iniciar --con-internet` | Red conectada; sin DNS externo en el entorno de prueba | **Pendiente** (S4-T2) |

**Nota:** en Linux la imagen de prueba se construyó con una base local
(`MINIONI_IMAGEN_BASE`), porque el entorno no tenía acceso a Docker Hub. En Windows se
usa la oficial `python:3.14-slim`, así que la primera construcción real es la de S4-T1.

# 6. Tareas pendientes de la semana 4

## S4-T1 · Verificar el laboratorio en Windows (con el equipo presente)

1. Instalar Docker Desktop (backend WSL 2) si falta; abrirlo y esperar *Engine running*.
2. Confirmar que `MINIONI_CLAVES` apunta fuera de OneDrive
   (`python minioni_admin.py donde-estan-las-claves`).
3. Ejecutar `python laboratorio_docker.py preparar`, `iniciar`, `probar` y `estado`.
4. Ejecutar el proxy con `--entrada-via 127.0.0.1:9001`, abrir Firefox en `http://web/`
   y probar `curl.exe --socks5-hostname 127.0.0.1:9050 http://web/`.
5. Ejecutar `docker logs minioni-salida1`: debe decir que no hay registros.

**Riesgos conocidos en Windows y qué hacer:**

- **No se crean las redes ("Pool overlaps").** La red de la universidad o de la casa
  usa `10.10.x`. Cambiar las subredes en `docker-compose.yml`, `config/relays.json`,
  `docker/sonda.py` (`OBJETIVOS`, `IP_SALIDA_EN_DESTINOS`) y
  `config/politica_salida.docker.json`, y volver a `preparar` (regla 29).
- **Falla el montaje de las claves.** Revisar que `MINIONI_CARPETA_CLAVES` quedó como
  `C:/MiniOniClaves` y que Docker Desktop comparte esa unidad (con WSL 2 viene
  activado).
- **`entregar_contrasena` no recibe "nodo iniciado".** Probar a mano con
  `docker attach --sig-proxy=false minioni-entrada1`, escribir la contraseña y salir
  con Ctrl+C. Si en Windows el attach se comporta distinto, ajustar la espera inicial
  (0,5 s) antes de escribir. **No** cambiar a variables de entorno (regla 26).
- **Error de `sysctls`** en la web. Como alternativa, escuchar en el puerto 8080 y
  agregar 8080 a `politica_salida.docker.json`. Documentarlo.

**Criterio de aceptación:** `probar` da *Todo correcto* en Windows; Firefox muestra la
página con `10.10.9.11`. Registrar la fecha y el resultado en `docs/SEMANA4_DOCKER.md`
(sección 5) y en `docs/TRAZABILIDAD.md`.

## S4-T2 · Verificar el modo con Internet

`python laboratorio_docker.py iniciar --con-internet`, el proxy y luego
`curl.exe --socks5-hostname 127.0.0.1:9050 https://example.com`. Además, `probar` debe
seguir dando *Todo correcto*: las demás redes siguen sin Internet. Si falla el DNS del
relay de salida, revisar la configuración DNS de Docker Desktop. **No** dar Internet a
otros nodos.

**Criterio:** la página de example.com carga por MiniOni; la matriz de segmentación no
cambia.

## S4-T3 · Fijar la imagen base por su digest

```powershell
docker pull python:3.14-slim
docker image inspect python:3.14-slim --format "{{index .RepoDigests 0}}"
```

Usar ese valor como predeterminado: `ARG BASE=python:3.14-slim@sha256:<digest>` en el
`Dockerfile` y en la variable de `docker-compose.yml`. Agregar una prueba que exija
`@sha256:` en el `ARG BASE` y documentar en `docs/ROTACION_CLAVES.md` o en
`SEMANA4_DOCKER.md` cómo actualizarlo (volver a hacer pull, cambiar el digest, correr
`probar`).

**Norma:** NIST SSDF PW.4.1 (componentes verificados).

## S4-T4 · Modo Docker en el panel gráfico (opcional, mejora la demostración)

Agregar en `panel.py` y `control_red.py` un selector **Local / Docker**. En modo Docker:

- **Iniciar red:** usa la contraseña del campo del panel y llama a las mismas funciones
  de `laboratorio_docker.py` (sin volver a pedirla). Nunca guarda la contraseña ni la
  pasa por variables.
- **Proxy:** se arranca con `directorio.docker.json` y `entrada_via=("127.0.0.1", 9001)`.
- **Probar segmentación:** muestra la matriz de `probar_segmentacion()` en la ventana.
- **"Verificar sin registros"** sigue funcionando para el proxy local.

**Criterio:** pruebas en `tests/test_panel.py` con el orquestador simulado (sin Docker
real), y el panel en modo Local sin cambios de comportamiento.

## S4-T5 · Commit de la semana 4 (con el equipo)

```powershell
python revision_completa.py --con-docker   # con el laboratorio iniciado
git status                                  # no deben aparecer claves, directorio.docker.json ni ultima_version.*
git add -A
git commit -m "Semana 4: laboratorio Docker con redes segmentadas"
```

El hook de secretos corre solo. No subir a un remoto sin que el equipo lo pida.

# 7. Criterios de aceptación de la semana 4

- [ ] `probar` da *Todo correcto* en Windows (S4-T1).
- [ ] Firefox navega a `http://web/` por los relays de Docker y ve `10.10.9.11`.
- [ ] `docker logs` de cualquier contenedor dice que no hay registros.
- [ ] El modo `--con-internet` navega a un sitio real sin cambiar la matriz (S4-T2).
- [ ] Imagen base fijada por digest (S4-T3).
- [ ] Todas las pruebas, Bandit y `revisar_secretos.py` en verde en Windows.
- [ ] Commit hecho con el hook activo (S4-T5).
- [ ] Ninguna regla de 1 a 32 rota.

# 8. Fuera del alcance de la semana 4

La captura con Wireshark, el informe final, el guion de la demostración y el paquete de
entrega están en `docs/PLAN_ENTREGA_SEMANA5.md`.
