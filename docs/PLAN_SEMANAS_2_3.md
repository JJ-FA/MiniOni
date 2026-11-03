---
title: "MiniOni – Especificación de desarrollo, semanas 2 y 3"
subtitle: "Relays en red con TLS 1.3, cliente de circuitos, nodo de salida y proxy SOCKS5"
date: "27 de octubre de 2026 · Equipo Onion"
---

# 0. Cómo usar este documento

Este documento es la especificación para programar las semanas 2 y 3 de MiniOni.
Está escrito para que un asistente de programación (Claude Code) lo siga paso a
paso sin tener que adivinar decisiones de diseño. Las decisiones ya están
tomadas aquí; si algo no está especificado, se elige la opción **más
restrictiva** y se documenta.

**Resultado esperado al final de la semana 3:** Firefox configurado con el proxy
`127.0.0.1:9050` navega por un circuito de 3 relays que corren en el mismo
computador, con TLS 1.3 entre nodos, cifrado por capas, sin registros de
conexiones y fallando de forma cerrada.

## 0.1 Antes de escribir código

1. Leer `README.md`, `docs/ARQUITECTURA.md`, `docs/PROTOCOLO.md`,
   `docs/LIMITES.md`, `docs/TRAZABILIDAD.md` y `docs/INVENTARIO_CRIPTOGRAFICO.md`.
2. Leer todo `minioni/` (≈1 000 líneas). La API existente se resume en la sección 1.
3. Ejecutar `python -m pytest` y confirmar que todo pasa **antes** de cambiar nada
   (148 passed y 1 skipped en Windows; 149 passed en Linux).

## 0.2 Reglas obligatorias (aplican a todo el código nuevo)

| # | Regla | Norma |
|---|---|---|
| 1 | **Ninguna dependencia nueva de ejecución.** Solo biblioteca estándar + `cryptography`. Herramientas de desarrollo nuevas solo con justificación. | NIST SSDF PW.4.1 |
| 2 | **Cero registros de conexiones.** Nunca imprimir ni guardar IP, puertos de clientes, dominios ni contenido. La consola solo se usa con `consola.evento(componente, codigo, cantidad)`; si hace falta un evento nuevo, se agrega al catálogo `EVENTOS`. | ASVS V16.2.5 |
| 3 | **Validación positiva** de todo lo que llega por la red: tamaño exacto, valores dentro de una lista permitida, nada sobrante. Lo que no cumple se rechaza y la conexión se cierra. | ASVS V2.2.1 |
| 4 | **Fallo cerrado.** Ante cualquier error se destruye el circuito o se cierra la conexión. El cliente **nunca** se conecta directo al destino. | ASVS V16.5.3 |
| 5 | **Errores genéricos.** Toda excepción propia hereda de `MiniOniError` y tiene `mensaje_publico`. Nunca se muestran trazas. Cada tarea asyncio de larga vida tiene un manejador de último recurso que emite `ERROR_INTERNO` y sigue funcionando. | ASVS V16.5.1, V16.5.4 |
| 6 | **No reinventar criptografía.** Solo se usan las funciones de `capas.py`, `handshake.py` y `directorio.py`, más el módulo `ssl`. | ASVS V11.2.1 |
| 7 | **Compatibilidad con Windows** (el equipo usa Windows 11 + PowerShell + Python 3.14). No usar `loop.add_signal_handler` (no existe en Windows): el apagado es con `KeyboardInterrupt`. Rutas con `pathlib`. | — |
| 8 | **Todo cambio lleva pruebas.** Cada parser nuevo lleva prueba de fuzzing con Hypothesis. `bandit -c pyproject.toml -r .` debe seguir en 0 hallazgos (un `# nosec` solo con justificación escrita en la misma línea). | SSDF PW.7.2, PW.8.2 |
| 9 | **Sin dependencias de prueba nuevas.** No usar `pytest-asyncio`: las pruebas async se escriben como funciones normales que llaman `asyncio.run(...)`. | SSDF PW.4.1 |
| 10 | **Idioma:** identificadores, mensajes y documentación en español, igual que el código existente. | — |
| 11 | **Documentación al día:** al terminar cada bloque se actualizan `docs/PROTOCOLO.md`, `docs/TRAZABILIDAD.md`, `docs/LIMITES.md`, `README.md` y `COMANDOS.txt` (este último con fin de línea CRLF). | — |
| 12 | Los cambios al formato del protocolo se reflejan en `docs/PROTOCOLO.md` y en las pruebas en el mismo cambio. | — |

# 1. Lo que ya existe (semana 1)

| Módulo | API relevante |
|---|---|
| `constantes.py` | `TAM_CELDA=512`, `TAM_CARGA=507`, `TAM_RELAY_PLANO=453`, `MAX_DATOS_RELAY=448`, `TIMEOUT_HANDSHAKE_S=10`, `INACTIVIDAD_MAX_CIRCUITO_S=60`, `VIDA_MAX_CIRCUITO_S=600`, `MAX_CONEXIONES_POR_IP=8`, `MAX_CIRCUITOS_POR_CONEXION=16` |
| `celdas.py` | `Comando` (CREATE, CREATED, RELAY, DESTROY), `ComandoRelay` (BEGIN, DATA, END, CONNECTED, EXTEND, EXTENDED), `Celda(circ_id, comando, carga).codificar()`, `decodificar_celda`, `MensajeRelay`, `codificar_relay`/`decodificar_relay`, `codificar_destino`, `decodificar_begin`, `codificar_extend`/`decodificar_extend`, `validar_host`, `validar_puerto` |
| `capas.py` | `CapaSalto`, `cliente_envolver(capas, plano)`, `cliente_pelar(capas, carga)`, `relay_pelar(capa, carga)`, `relay_originar(capa, plano)`, `relay_agregar_capa(capa, carga)`, `rellenar(datos)` |
| `handshake.py` | `HandshakeCliente.iniciar(B) -> (estado, B|X)`, `estado.finalizar(Y|HMAC) -> CapaSalto`, `relay_responder(clave_cebolla, B|X) -> (CapaSalto, Y|HMAC)` |
| `directorio.py` | `verificar(bytes, pub_autoridad, ahora=None, version_minima=1) -> Directorio`; `Directorio.relays` (tupla de `Relay(apodo, host, puerto, clave_cebolla, huella_tls, salida)`), `Directorio.buscar(host, puerto)` |
| `almacen_claves.py` | `cargar_privada(ruta, contraseña, tipo)` con tipos `x25519`, `ed25519`, `p256-pkcs8`; `cargar_publica(ruta)` |
| `politica_salida.py` | `verificar_ip_destino(ip, excepciones=())`, `verificar_puerto_destino(puerto, permitidos)` |
| `consola.py` | `evento(componente, codigo, cantidad=None)` con catálogo cerrado `EVENTOS` |
| `errores.py` | `MiniOniError` y subclases `CeldaInvalida`, `CeldaManipulada`, `HandshakeFallido`, `DirectorioInvalido`, `ClaveInvalida`, `DestinoNoPermitido` |
| `admin.py` | `preparar_laboratorio`, `publicar_directorio`, `simular_ataque`, `huella_certificado`; CLI en `minioni_admin.py` |

Archivos por relay en `claves/<apodo>/`: `cebolla.key` (X25519, contenedor scrypt),
`cebolla.pub`, `tls.key` (ECDSA P-256 en DER PKCS#8 dentro del contenedor scrypt) y
`tls.crt` (PEM autofirmado; su SHA-256 del DER está en el directorio como `huella_tls`).

**Regla del protocolo que no cambia:** solo el **último salto** de un circuito
interpreta o genera mensajes RELAY. Un relay que tiene siguiente salto siempre
quita su capa y reenvía, sin mirar el contenido.

# 2. Semana 2 – Relays en red

**Objetivo:** tres relays corriendo como procesos independientes en
`127.0.0.1:9001-9003`, conectados por TLS 1.3, y un cliente de prueba que
construye un circuito real de 3 saltos y recibe un eco.

## 2.1 Configuración local (Windows, sin Docker)

* Crear `config/relays.local.json` con `entrada1 127.0.0.1:9001`,
  `medio1 127.0.0.1:9002` y `salida1 127.0.0.1:9003 (salida=true)`.
  `config/relays.json` se queda con las IP de Docker para la semana 4.
* Agregar `--relays RUTA` (por defecto `config/relays.json`) a
  `preparar-laboratorio` y `publicar-directorio`.
* `validar_host` ya acepta `127.0.0.1`. El directorio puede contener loopback:
  la política de salida aplica a **destinos**, no a relays.

## 2.2 Cambios al protocolo

1. **Nuevo `ComandoRelay.ECO = 7`.** Solo lo interpreta el último salto, que
   responde con `ECO` y los mismos datos (máx. 448 bytes, sin amplificación).
   Sirve para diagnóstico y pruebas.
2. **`circ_id` es local a cada enlace TLS** (como en Tor). Quien abre el circuito
   en un enlace elige un `circ_id` aleatorio con `secrets.randbelow(2**32 - 1) + 1`,
   distinto de los que ya usa en ese enlace. Cada relay mantiene la
   correspondencia (enlace_anterior, circ_id_anterior) ↔ (enlace_siguiente,
   circ_id_siguiente).
3. **Carga de DESTROY:** 1 byte de motivo genérico (`1` = error de protocolo,
   `2` = tiempo agotado, `3` = cerrado por el cliente, `4` = recurso no
   disponible) + ceros. Nunca lleva detalles.
4. Documentar los tres puntos en `docs/PROTOCOLO.md`.

## 2.3 Transporte: `minioni/transporte.py`

**TLS 1.3 únicamente** (ASVS V12.1.1):

```python
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ctx.maximum_version = ssl.TLSVersion.TLSv1_3
```

**Contexto de servidor (relay).** La clave TLS está en el contenedor scrypt y
  `ssl.load_cert_chain` solo acepta archivos. Procedimiento: descifrar el DER con
  `cargar_privada(..., "p256-pkcs8")`; serializarlo como PEM PKCS#8 cifrado con una
  contraseña de un solo uso (`secrets.token_urlsafe(32)`); escribirlo en un archivo
  temporal creado con `tempfile.mkstemp()`; llamar
  `load_cert_chain(tls.crt, temporal, password=...)` y borrar el temporal en un
  `finally`. La contraseña aleatoria de 256 bits hace irrelevante la debilidad del
  PBKDF2 de ese PEM. Documentarlo en el inventario criptográfico.

**Contexto de cliente** (lo usan el cliente y un relay al extender):
`check_hostname = False`, `verify_mode = ssl.CERT_NONE` y, **justo después del
handshake**, verificar la huella con *pinning*:

```python
der = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
if der is None or not hmac.compare_digest(hashlib.sha256(der).hexdigest(), relay.huella_tls):
    writer.close()
    raise TLSInvalido("huella TLS no coincide")
```

Agregar `TLSInvalido(MiniOniError)` con `mensaje_publico = "no se pudo construir el circuito"`.
Norma: ASVS V12.3.4 (confiar solo en certificados autofirmados específicos).

**Clase `Enlace`** (envuelve `StreamReader` y `StreamWriter`):

* `async leer_celda()`: `await reader.readexactly(512)` y luego `decodificar_celda`;
  `IncompleteReadError` significa enlace cerrado.
* `async enviar(celda)`: un **único escritor** por enlace, con `asyncio.Lock` o
  una cola acotada de 64 celdas, para que dos tareas no mezclen bytes;
  `await writer.drain()`.
* `cerrar()`: idempotente.
* Tiempo máximo del handshake TLS + primera celda: `TIMEOUT_HANDSHAKE_S`
  (usar `asyncio.wait_for`).
* Un relay **no autentica** a quien se le conecta (clientes y relays entran
  igual). Anotarlo en `docs/LIMITES.md`.

## 2.4 Relay: `minioni/relay.py` y `ejecutar_relay.py`

**Arranque:**
`python ejecutar_relay.py --apodo entrada1 [--directorio config/directorio.firmado.json]`

1. Verificar el directorio con `config/autoridad.pub`. Si falla, se emite
   `DIRECTORIO_INVALIDO` y el programa termina con código 1.
2. Buscar la entrada propia por apodo y comprobar que `cebolla.pub` y la huella de
   `tls.crt` coincidan con el directorio; si no coinciden, termina.
3. Pedir la contraseña **una vez** con `getpass` y descifrar `cebolla.key` y `tls.key`.
4. Escuchar en el host:puerto del directorio (`asyncio.start_server` con `ssl=`).
   Opción `--escuchar HOST` solo para Docker (semana 4).
5. Emitir `ARRANQUE`. Ctrl+C hace un apagado limpio: destruye los circuitos y
   emite `APAGADO`.

**Configuración inyectable para pruebas:** `@dataclass ConfigRelay` con
`timeout_handshake`, `inactividad_max`, `vida_max`, `max_conexiones_por_ip`,
`max_circuitos_por_conexion`, `max_circuitos_totales` (nuevo, 256) e
`intervalo_limpieza` (5 s). Los valores por defecto salen de `constantes.py`.

**Estado de un circuito:**

```python
@dataclass
class EstadoCircuito:
    capa: CapaSalto
    anterior: tuple[Enlace, int]            # (enlace, circ_id)
    siguiente: tuple[Enlace, int] | None
    creado: float                           # time.monotonic()
    ultima_actividad: float
    extension_pendiente: HandshakePendiente | None
```

**Tabla de comportamiento por celda recibida:**

| Celda | Viene de | Acción |
|---|---|---|
| CREATE | anterior | Si el `circ_id` ya existe en ese enlace → cerrar el enlace (violación). Si se superan los límites de circuitos → DESTROY(4). Si no, `relay_responder` → CREATED(Y\|HMAC); registrar el circuito; emitir `CIRCUITO_CREADO(n)`. `HandshakeFallido` → DESTROY(1). |
| RELAY | anterior | `inner = relay_pelar(capa, carga)`. Si hay siguiente → reenviar `RELAY(rellenar(inner))` por el siguiente. Si no hay siguiente → `decodificar_relay(inner)` e interpretarlo (ver abajo). |
| RELAY | siguiente | `relay_agregar_capa(capa, carga)` → reenviar al anterior. |
| CREATED | siguiente | Solo válido si hay `extension_pendiente`: responder EXTENDED(Y\|HMAC) al anterior con `relay_originar`. Si no hay extensión pendiente → DESTROY(1). |
| DESTROY | cualquiera | Destruir el circuito, propagar DESTROY al otro lado, emitir `CIRCUITO_CERRADO(n)`. |

**Mensajes interpretados por el último salto (semana 2):**

* **EXTEND:** `host, puerto, B, X = decodificar_extend(datos)`. El destino **debe**
  estar en el directorio (`directorio.buscar`) y `B` debe ser igual a su
  `clave_cebolla`; si no, DESTROY(1) hacia atrás. No se extiende hacia uno mismo
  ni dos veces en el mismo circuito. Se abre o reutiliza un enlace TLS hacia ese
  relay (un *pool* por apodo, con pinning) y se envía CREATE(B|X) con un `circ_id`
  nuevo. Si no llega CREATED dentro de `timeout_handshake` → DESTROY(4) hacia
  atrás.
* **ECO:** responder ECO con los mismos datos mediante `relay_originar`.
* Cualquier otro comando en la semana 2 → DESTROY(1).

**Errores:**

* `CeldaInvalida` al decodificar una celda de enlace → **cerrar todo el enlace**
  (y destruir sus circuitos), emitir `CELDA_RECHAZADA`.
* `CeldaManipulada` o `CeldaInvalida` dentro de un circuito → destruir **ese**
  circuito (DESTROY(1) en ambas direcciones).
* Celda para un `circ_id` desconocido → ignorarla. Más de 8 celdas desconocidas
  seguidas en un enlace → cerrar el enlace.
* Si se cae un enlace, se destruyen todos sus circuitos y se propaga DESTROY por
  el otro lado.

**Límites anti-saturación (ASVS V2.4.1):**

* Conexiones simultáneas por IP de origen > `max_conexiones_por_ip` → cerrar al
  aceptar y emitir `LIMITE_ALCANZADO` (sin la IP).
* Circuitos por enlace > `max_circuitos_por_conexion` o totales >
  `max_circuitos_totales` → DESTROY(4).
* Tarea de limpieza cada `intervalo_limpieza`: destruir circuitos con inactividad
  > `inactividad_max` o edad > `vida_max` con DESTROY(2).
* Al destruir: quitar el circuito de todas las tablas y soltar las referencias a
  `CapaSalto` (las claves solo viven en memoria).

## 2.5 Cliente de circuitos: `minioni/circuito.py`

* `elegir_ruta(directorio) -> list[Relay]`: 3 relays distintos con
  `secrets.SystemRandom`; el último con `salida=True` y, si es posible, los dos
  primeros con `salida=False`.
* `class CircuitoCliente` (async):
  * `construir(directorio, ruta)`: abrir el enlace TLS con pinning al primer relay;
    CREATE/CREATED; luego EXTEND/EXTENDED al segundo y al tercero (usando
    `HandshakeCliente`). Tiempo máximo total: 3 × `TIMEOUT_HANDSHAKE_S`.
  * `enviar(mensaje: MensajeRelay)` → `cliente_envolver`.
  * `recibir() -> MensajeRelay` → `cliente_pelar`. Si llega un DESTROY → `CircuitoCerrado`.
  * `cerrar()`: envía DESTROY(3) y cierra el enlace; idempotente.
  * Cualquier error durante `construir` → cerrar todo y lanzar una subclase de
    `MiniOniError`. **Nunca** hay plan B fuera del circuito.
* Agregar `CircuitoCerrado(MiniOniError)`.

## 2.6 Cliente de prueba: `cliente_prueba.py`

```text
> python cliente_prueba.py
Directorio verificado: versión 1, 3 relays
[1/3] Circuito hasta entrada1 ... OK
[2/3] Extendido a medio1 ...       OK
[3/3] Extendido a salida1 ...      OK
Eco enviado: "hola MiniOni" (12 bytes)
Eco recibido: "hola MiniOni" · ida y vuelta 4 ms
Circuito cerrado.
```

Imprimir apodos está permitido: es el equipo del propio usuario. Nunca imprimir
IP ni puertos. Si falla, mostrar el `mensaje_publico` y terminar con código 1.

## 2.7 Pruebas de la semana 2: `tests/test_red.py`

Fixture común: generar claves con `n=N_SCRYPT_MINIMO` en `tmp_path`, obtener 3
puertos libres en `127.0.0.1` (abrir un socket en el puerto 0, leer el puerto y
cerrarlo), publicar un directorio con esos puertos y levantar los 3 relays **en
el mismo proceso** con un `ConfigRelay` de tiempos cortos.

| # | Prueba | Resultado esperado |
|---|---|---|
| 1 | Circuito de 3 saltos + ECO | El eco vuelve idéntico |
| 2 | 20 circuitos seguidos y luego cerrados | Las tablas de los 3 relays quedan vacías |
| 3 | Huella TLS distinta en el directorio | `TLSInvalido`; no se envía ninguna celda |
| 4 | Cliente que fuerza TLS 1.2 | Handshake rechazado |
| 5 | EXTEND hacia un host:puerto que no está en el directorio | El cliente recibe DESTROY |
| 6 | EXTEND con una `B` que no corresponde al relay | DESTROY |
| 7 | Celda con un bit alterado enviada directo al relay de entrada | DESTROY del circuito; el relay sigue atendiendo |
| 8 | 512 bytes aleatorios tras el handshake TLS | Enlace cerrado; un circuito nuevo después funciona |
| 9 | `max_conexiones_por_ip + 1` conexiones | La última se cierra sin respuesta |
| 10 | Inactividad (`inactividad_max = 1 s`) | El circuito se destruye y el cliente recibe DESTROY(2) |
| 11 | Se detiene el relay intermedio a mitad de camino | Entrada y salida destruyen el circuito; el cliente recibe DESTROY |
| 12 | Celdas que llegan de a pocos bytes | Se reensamblan bien (`readexactly`) |
| 13 | Ninguna salida de consola contiene "127.0.0.1" ni puertos | Se captura `stderr` y se comprueba |

Además: fuzzing (Hypothesis, perfil normal) de la máquina de estados del relay,
alimentándola con secuencias aleatorias de celdas válidas e inválidas sin red.
Nunca debe lanzar algo distinto de `MiniOniError`.

## 2.8 Criterios de aceptación de la semana 2

- [ ] Tres ventanas de PowerShell con `ejecutar_relay.py` (entrada1, medio1, salida1) y `cliente_prueba.py` mostrando el eco.
- [ ] `python -m pytest` en verde; `bandit` en 0; `revision_completa.py` incluye las pruebas de red y termina en "Todo correcto".
- [ ] Ninguna salida de los relays contiene IP, puertos de clientes ni contenido.
- [ ] Documentación actualizada: PROTOCOLO (ECO, `circ_id` por enlace, motivos de DESTROY), ARQUITECTURA (transporte y relay), LIMITES (no se autentica al que se conecta), TRAZABILIDAD (filas de TLS y anti-DoS en ✅), COMANDOS.txt (cómo levantar los relays).
- [ ] Opcional: captura de Wireshark (Npcap con *loopback*) donde solo se ve TLS 1.3 entre los puertos 9001-9003.

# 3. Semana 3 – Nodo de salida, proxy SOCKS5 y navegador

**Objetivo:** Firefox navega a través de MiniOni; todo el DNS se resuelve en el
nodo de salida; si el circuito falla, la navegación falla en lugar de salir directo.

## 3.1 Streams en el nodo de salida

Un circuito transporta varios *streams* (una conexión TCP del navegador = un
stream). El cliente elige `stream_id` entre 1 y 65535, sin repetir en el
circuito; el 0 está reservado.

| Mensaje recibido por la salida | Acción |
|---|---|
| BEGIN(host, puerto) | Validar con `decodificar_begin`; el puerto debe estar en la lista permitida (80, 443). Resolver **una sola vez** con `loop.getaddrinfo`; tomar la **primera IP que pase** `verificar_ip_destino(ip, excepciones)`; conectar **a esa IP exacta** (anti DNS-rebinding) con `asyncio.wait_for(open_connection(...), 10)`. Éxito → CONNECTED (datos vacíos). Fallo → END con un byte de motivo genérico: `1` no permitido, `2` inalcanzable, `3` tiempo agotado. Emitir `DESTINO_BLOQUEADO` cuando aplique, sin el destino. |
| DATA(stream, datos) | Escribir en el socket del destino (`drain`). Stream desconocido → END(1). |
| END(stream) | Cerrar el socket del destino y olvidar el stream. |
| *(datos desde el destino)* | Leer en bloques de hasta 448 bytes → DATA hacia atrás. EOF → END. |

* Máximo 32 streams por circuito (nueva constante `MAX_STREAMS_POR_CIRCUITO`);
  si se supera → END(1).
* Al destruir el circuito se cierran todos sus streams.
* **Solo la salida** acepta BEGIN; un relay que no es de salida responde
  DESTROY(1). Se determina con `salida=True` en su entrada del directorio.
* Configuración de la política en `config/politica_salida.json`:
  `{"puertos": [80, 443], "excepciones_redes": []}`. La validación es estricta
  (claves exactas, puertos válidos, redes con `ipaddress.ip_network`). Si el
  archivo no existe, se usan los valores por defecto. Cada excepción se documenta
  en `docs/LIMITES.md`.
* Control de flujo simple: los mensajes DATA salientes por circuito pasan por una
  cola acotada (p. ej. 128 celdas); si se llena, se deja de leer del destino
  hasta que se vacíe (presión hacia atrás).

## 3.2 Parser SOCKS5: `minioni/socks5.py` (RFC 1928, solo lo necesario)

Funciones puras y probables **sin red**, más una corrutina que las usa sobre un
`StreamReader`.

| Paso | Formato que se acepta | Respuesta |
|---|---|---|
| Saludo | `05`, `NMETHODS` (1–255), métodos. Debe incluir `00` (sin autenticación) | `05 00`; si no incluye `00` → `05 FF` y cerrar |
| Solicitud | `05`, `CMD=01` (CONNECT), `RSV=00`, `ATYP` 01 (IPv4) / 03 (dominio, largo 1–255, `validar_host`) / 04 (IPv6), puerto 1–65535 | — |
| Comando distinto de CONNECT | — | `05 07` y cerrar |
| ATYP desconocido | — | `05 08` y cerrar |
| Éxito | — | `05 00 00 01 00000000 0000` |
| Fallo de MiniOni | — | Solo `05 01` (fallo general) o `05 02` (no permitido). Nunca detalles. |

* Tiempo máximo del saludo y la solicitud: 10 s.
* **DNS remoto obligatorio:** el proxy **nunca** resuelve nombres. El dominio
  viaja tal cual en BEGIN y lo resuelve la salida. Prueba: monkeypatch de
  `getaddrinfo` en el proceso del cliente que falle si se llama.
* Fuzzing con Hypothesis de saludo y solicitud: cualquier entrada termina en
  respuesta válida o `MiniOniError`.

## 3.3 Proxy: `minioni/proxy.py` y `cliente_proxy.py`

`python cliente_proxy.py [--puerto 9050]`

* Escucha **solo** en `127.0.0.1`. Si se pide otra dirección, se rechaza
  (amenaza de relé abierto, superficie de ataque).
* Al arrancar: verificar el directorio y aplicar **anti-rollback**, guardando en
  `config/ultima_version` solo el número de versión más alto visto (no es un dato
  del usuario) y pasándolo como `version_minima`. Emitir `DIRECTORIO_OK`.
* **Gestor de circuitos:**
  * Un circuito activo para los streams nuevos; se construye al primer uso o por
    adelantado.
  * Rotación: a los `VIDA_MAX_CIRCUITO_S` (10 min) los streams nuevos van a un
    circuito nuevo; el viejo se cierra cuando terminan sus streams.
  * Si el circuito falla, los streams afectados se cierran y el siguiente pedido
    construye otro circuito. Máximo 3 intentos de construcción seguidos; luego la
    respuesta es `05 01`.
  * **Fallo cerrado:** no existe ningún camino de código que abra una conexión al
    destino fuera del circuito. Prueba: monkeypatch de `asyncio.open_connection` en
    el proceso del proxy que registre cualquier conexión que no vaya a un relay del
    directorio; la lista debe quedar vacía incluso con todos los relays caídos.
* Por cada conexión SOCKS: parsear → BEGIN por el circuito → esperar CONNECTED
  (máx. 15 s) → responder `05 00` → copiar datos en ambos sentidos (bloques de
  448 bytes como DATA) → END al cerrar cualquiera de los lados.
* Correspondencia de respuestas: CONNECTED → `05 00`; END(1) → `05 02`;
  END(2), END(3), tiempo agotado o circuito caído → `05 01`.
* Consola: solo `ARRANQUE`, `DIRECTORIO_OK`, `CIRCUITO_CREADO(n)`,
  `CIRCUITO_FALLIDO`, `CIRCUITO_CERRADO(n)` y `APAGADO`. Nunca dominios.

## 3.4 Navegador y demostración

Crear la guía `docs/NAVEGADOR.md`:

1. Firefox → Ajustes → Configuración de red → Configuración manual del proxy →
   Host SOCKS `127.0.0.1`, puerto `9050`, **SOCKS v5**, y marcar
   **"Usar proxy DNS cuando se use SOCKS v5"**.
2. En `about:config`: `network.proxy.socks_remote_dns = true` y
   `media.peerconnection.enabled = false` (WebRTC puede filtrar la IP real).
3. Prueba rápida sin navegador, con el curl que trae Windows:
   `curl.exe --socks5-hostname 127.0.0.1:9050 https://example.com`

Actualizar `docs/LIMITES.md` con: DNS remoto obligatorio, WebRTC, el
fingerprinting y el hecho de que en un solo computador no hay anonimato real (es
una demostración del mecanismo).

## 3.5 Pruebas de la semana 3

| # | Prueba | Resultado esperado |
|---|---|---|
| 1 | Proxy → circuito → salida → servidor HTTP local de prueba (con excepción explícita `127.0.0.0/8` y el puerto del servidor solo en la configuración de la prueba) | Llega la respuesta HTTP completa |
| 2 | La misma petición sin la excepción | SOCKS `05 02`; el servidor de prueba no recibe nada |
| 3 | BEGIN hacia un dominio que resuelve a 127.0.0.1 o 192.168.x.x (getaddrinfo simulado) | Bloqueado (END 1) |
| 4 | BEGIN a un puerto distinto de 80/443 | END(1) |
| 5 | Todos los relays caídos | SOCKS `05 01`; ninguna conexión directa (monkeypatch) |
| 6 | El proxy nunca llama `getaddrinfo` | Comprobado con monkeypatch |
| 7 | 33 streams en un circuito | El 33 recibe END(1) |
| 8 | Respuesta grande (1 MB) desde el servidor de prueba | Llega íntegra y en orden |
| 9 | El cliente cierra a mitad de una descarga | La salida cierra el socket del destino; no quedan streams abiertos |
| 10 | Bind del proxy en 0.0.0.0 | Rechazado |
| 11 | Anti-rollback: directorio con versión menor a `ultima_version` | El proxy no arranca |
| 12 | Fuzzing SOCKS5 | Solo respuestas válidas o `MiniOniError` |

## 3.6 Criterios de aceptación de la semana 3

- [ ] Con los 3 relays y `cliente_proxy.py` corriendo, `curl.exe --socks5-hostname 127.0.0.1:9050 https://example.com` devuelve la página.
- [ ] Firefox configurado según `docs/NAVEGADOR.md` abre sitios HTTPS a través de MiniOni.
- [ ] Al detener el relay intermedio, la navegación **falla** (no sale directo); al reiniciarlo, vuelve a funcionar.
- [ ] `python -m pytest` en verde, `bandit` en 0, `pip-audit` en 0 y `revision_completa.py` en "Todo correcto".
- [ ] TRAZABILIDAD: R4 (fallo cerrado) pasa a ✅ con la prueba 5; la política de salida queda conectada (prueba 3).
- [ ] COMANDOS.txt y README con el orden de arranque: 3 relays → proxy → navegador.

# 4. Orden de trabajo sugerido

1. `transporte.py` (TLS + `Enlace`) con sus pruebas 3, 4 y 12.
2. `relay.py`: CREATE/CREATED/DESTROY y la máquina de estados con fuzzing.
3. EXTEND, *pool* de enlaces y `circuito.py`; pruebas 1, 2, 5 y 6.
4. Límites y limpieza; pruebas 7 a 11 y 13.
5. `ejecutar_relay.py`, `cliente_prueba.py`, `relays.local.json` y `--relays`. **Cierre de la semana 2.**
6. Streams en la salida + `politica_salida.json`; pruebas 3.5-1 a 3.5-4 y 3.5-7 a 3.5-9.
7. `socks5.py` con fuzzing; `proxy.py` + `cliente_proxy.py`; pruebas restantes.
8. `docs/NAVEGADOR.md`, prueba manual con curl y Firefox. **Cierre de la semana 3.**

Después de cada paso: `python -m pytest` y `bandit -c pyproject.toml -r .`.
Antes de dar un paso por terminado: `python revision_completa.py`.

# 5. Mapa de normas de este trabajo

| Control | Dónde se cumple |
|---|---|
| ASVS V2.2.1 – validación positiva | `transporte.leer_celda`, tabla de celdas del relay, `socks5.py`, BEGIN en la salida |
| ASVS V2.4.1 – anti-automatización / DoS | Límites por IP, por enlace y totales; timeouts; colas acotadas |
| ASVS V11.3.3 / V11.3.4 – cifrado autenticado y nonces | Sin cambios: `capas.py` en cada salto |
| ASVS V11.6.1 / V11.6.2 – firmas e intercambio de claves | EXTEND solo hacia relays del directorio, `B` verificada |
| ASVS V12.1.1 – solo TLS 1.3 | `transporte.py` |
| ASVS V12.3.4 – confiar solo en certificados específicos | Pinning de `huella_tls` |
| ASVS V16.2.5 – sin datos sensibles en registros | `consola.evento` y prueba 2.7-13 |
| ASVS V16.5.1 / V16.5.3 / V16.5.4 – errores genéricos, fallo cerrado, manejador de último recurso | Motivos genéricos en DESTROY/END/SOCKS, gestor de circuitos, manejadores de tareas |
| NIST SSDF PW.4.1 – componentes seguros | Sin dependencias nuevas |
| NIST SSDF PW.7.2 / PW.8.2 – análisis y pruebas | Bandit, `test_red.py`, fuzzing de SOCKS5 y del relay |
| ISO/IEC 27033 – segmentación | Preparado para Docker (semana 4): `--escuchar` y `relays.json` con subredes 10.10.x |

# 6. Fuera del alcance de estas dos semanas

Docker y redes segmentadas (semana 4); captura con Wireshark para el informe
(semana 5); servicios `.onion`; selección de relays por ancho de banda; tráfico de
cobertura; autenticación mutua entre relays; criptografía poscuántica (está el
plan en `docs/INVENTARIO_CRIPTOGRAFICO.md`).
