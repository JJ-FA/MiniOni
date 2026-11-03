# Protocolo MiniOni v1

Todos los enteros van en *big-endian*. Todo lo que no cumpla exactamente
este formato se rechaza y la conexión se cierra (OWASP ASVS 5.0 V2.2.1).

## 1. Celda de enlace (512 bytes)

| Campo | Bytes | Validación |
|---|---|---|
| `circ_id` | 4 | uint32, distinto de 0 |
| `comando` | 1 | CREATE=1, CREATED=2, RELAY=3, DESTROY=4 |
| `carga` | 507 | según el comando |

- **CREATE**: `B (32) | X (32)` + ceros.
- **CREATED**: `Y (32) | HMAC (32)` + ceros.
- **RELAY**: carga cifrada por capas (sección 3).
- **DESTROY**: `motivo (1)` + ceros. Cierra el circuito en todos los saltos.

En CREATE, CREATED y DESTROY el resto de la carga **debe** ser ceros; si no,
la celda se rechaza (validación positiva, `decodificar_carga_fija`).

### 1.1 `circ_id` local a cada enlace

Como en Tor, el `circ_id` solo tiene sentido dentro de **un** enlace TLS.
Quien abre el circuito en un enlace (el cliente hacia la entrada, o un relay
al extender) elige un valor aleatorio con `secrets.randbelow(2**32 - 1) + 1`,
distinto de los que ya usa en ese enlace. Cada relay guarda la
correspondencia `(enlace_anterior, circ_id_anterior) ↔ (enlace_siguiente,
circ_id_siguiente)`. Así el `circ_id` de un salto no sirve para seguir el
circuito en el siguiente.

Solo se aceptan CREATE en enlaces que **otro** abrió hacia este relay. Un
CREATE con un `circ_id` que ya existe en ese enlace es una violación y se
cierra el enlace completo.

### 1.2 Motivos de DESTROY

| Valor | Motivo genérico |
|---|---|
| 1 | Error de protocolo (celda mal formada, manipulada, EXTEND no permitido, comando no admitido) |
| 2 | Tiempo agotado (inactividad o vida máxima del circuito) |
| 3 | Cerrado por el cliente |
| 4 | Recurso no disponible (límite alcanzado, relay siguiente caído o sin respuesta) |

Nunca lleva detalles (ASVS V16.5.1). Un relay que recibe un DESTROY lo
propaga al otro lado del circuito con el mismo motivo.

## 2. Mensaje RELAY en texto plano (453 bytes)

| Campo | Bytes | Validación |
|---|---|---|
| `comando_relay` | 1 | BEGIN=1, DATA=2, END=3, CONNECTED=4, EXTEND=5, EXTENDED=6, ECO=7 |
| `stream_id` | 2 | 0–65535 |
| `longitud` | 2 | ≤ 448 |
| `datos` | `longitud` | según el comando |
| relleno | resto | debe ser todo ceros |

- **BEGIN**: `largo_host (1) | host ASCII | puerto (2)`. El host es una IP o
  un nombre DNS válido (≤ 255, etiquetas de 1–63 caracteres alfanuméricos o `-`).
- **EXTEND**: `largo_host | host | puerto | B (32) | X (32)`. El relay solo
  extiende hacia relays que aparezcan en el directorio firmado (evita usar
  EXTEND como conexión arbitraria).
- **EXTENDED**: `Y (32) | HMAC (32)`.
- **ECO** (diagnóstico): datos cualesquiera, máximo 448 bytes. Solo lo
  interpreta el último salto, que responde ECO con **los mismos datos**
  (sin amplificación).
- **CONNECTED**: datos vacíos.
- **DATA**: 1–448 bytes del flujo TCP.
- **END**: vacío (cierre normal) o **exactamente 1 byte** de motivo genérico
  (tabla 2.3). Cualquier otra cosa es un error de protocolo → DESTROY(1).

### 2.1 Qué hace el último salto (semana 2)

| Mensaje | Acción |
|---|---|
| EXTEND | El destino debe estar en el directorio (`buscar(host, puerto)`), `B` debe ser su `clave_cebolla`, no puede ser el propio relay y el circuito no puede estar ya extendido. Se abre o reutiliza un enlace TLS hacia ese relay (uno por apodo, con *pinning*) y se envía CREATE con un `circ_id` nuevo. Sin CREATED en `TIMEOUT_HANDSHAKE_S` → DESTROY(4). |
| ECO | Responde ECO con los mismos datos. |
| BEGIN / DATA / END | Solo si el relay tiene `salida=True` en el directorio (sección 2.2); si no, DESTROY(1). |
| Cualquier otro | DESTROY(1). |

Un relay que tiene siguiente salto **nunca** mira el contenido: quita su capa
y reenvía.

### 2.2 Streams en el nodo de salida (semana 3)

Un circuito transporta varios *streams*; cada conexión TCP del navegador es
uno. El cliente elige `stream_id` entre 1 y 65535 sin repetirlo en el
circuito; el 0 está reservado (un BEGIN/DATA/END con `stream_id` 0 o un BEGIN
con un `stream_id` en uso es error de protocolo → DESTROY(1)).

| Mensaje recibido por la salida | Acción |
|---|---|
| BEGIN(host, puerto) | `decodificar_begin`; el puerto debe estar en la política (por defecto 80 y 443). Se resuelve **una sola vez** con `getaddrinfo`, se toma la primera IP que pase `verificar_ip_destino(ip, excepciones)` y se conecta a **esa IP exacta** (anti DNS-rebinding), máx. 10 s para resolver y 10 s para conectar. Éxito → CONNECTED. Fallo → END(motivo) y, si la política lo bloqueó, el evento `DESTINO_BLOQUEADO` (sin el destino). |
| DATA(stream, datos) | Se escriben en el socket del destino (`drain`). Stream desconocido o todavía sin CONNECTED → END(1). |
| END(stream) | Se cierra el socket del destino y se olvida el stream. Stream desconocido: se ignora. |
| (datos del destino) | Bloques de hasta 448 bytes → DATA hacia atrás. EOF → END vacío. Error de lectura → END(2). |

- Máximo **32 streams por circuito** (`MAX_STREAMS_POR_CIRCUITO`); el 33.º recibe END(1).
- Todo lo que vuelve hacia el cliente (CONNECTED, DATA, END) pasa por **una
  sola cola por circuito**, que un único emisor sella en orden. Si tiene 128
  mensajes, la salida deja de leer de los destinos hasta que baje
  (presión hacia atrás). Si llega a 512 (el cliente no lee), DESTROY(4).
- Al destruir el circuito se cierran todos sus streams.

Política (`config/politica_salida.json`, validación estricta; si no existe,
valores por defecto):

```json
{"puertos": [80, 443], "excepciones_redes": []}
```

### 2.3 Motivos de END

| Valor | Motivo genérico | Respuesta SOCKS5 en el proxy |
|---|---|---|
| (vacío) | Cierre normal | — (o 05 01 si aún no había CONNECTED) |
| 1 | No permitido (puerto, destino interno, límite de streams, stream desconocido) | 05 02 |
| 2 | Inalcanzable (no resuelve, conexión rechazada, error de lectura) | 05 01 |
| 3 | Tiempo agotado | 05 01 |

## 3. Capas de cifrado

Cada salto tiene dos claves de 256 bits (ida y vuelta) y un contador por
dirección. Nonce de 96 bits = `00000000 | contador (8 bytes)`.

Una capa es: `longitud (2) | ChaCha20-Poly1305(contenido)`. Cada capa suma
18 bytes (2 de longitud + 16 de etiqueta). Con 3 saltos:
453 + 3 × 18 = 507 bytes, exactamente la carga de una celda.

Tras quitar o agregar una capa, el resto de la celda se rellena con bytes
aleatorios hasta 507.

| Dirección | Quién | Operación |
|---|---|---|
| Ida | Cliente | Sella con salida → intermedio → entrada |
| Ida | Cada relay | Abre su capa; si tiene siguiente salto, reenvía |
| Vuelta | Último salto | Sella el mensaje |
| Vuelta | Relays anteriores | Agregan su capa |
| Vuelta | Cliente | Abre entrada → intermedio → salida |

Si la etiqueta Poly1305 no verifica (bit alterado, celda repetida, borrada
o reordenada), el circuito se destruye.

## 4. Handshake (por salto)

```
Cliente:  x ← aleatorio;  envía  B | X
Relay:    y ← aleatorio
          s = X25519(y,X) | X25519(b,X) | B | X | Y | "MiniOni-v1"
          auth | k_ida | k_vuelta = HKDF-SHA256(s, sal="MiniOni-v1", 96 bytes)
          responde  Y | HMAC-SHA256(auth, B | X | Y | "MiniOni-v1 relay")
Cliente:  calcula s con X25519(x,Y) y X25519(x,B), verifica el HMAC
          en tiempo constante. Si falla: no hay circuito.
```

## 5. Transporte entre nodos (TLS 1.3)

- **Solo TLS 1.3** en servidor y cliente (`minimum_version` = `maximum_version`
  = TLS 1.3; ASVS V12.1.1). Un cliente con TLS 1.2 no completa el handshake.
- **Pinning:** el certificado de cada relay es autofirmado. Quien se conecta
  no valida cadena ni nombre; justo después del handshake compara en tiempo
  constante el SHA-256 del DER recibido con `huella_tls` del directorio
  firmado. Si no coincide, cierra **antes de enviar ninguna celda**
  (`TLSInvalido`; ASVS V12.3.4).
- Del enlace solo se leen bloques de exactamente 512 bytes
  (`readexactly(512)`); una celda que no decodifica cierra el enlace completo.
- Un relay no autentica a quien se le conecta (ver `docs/LIMITES.md`).

### 5.1 Errores y límites del relay

| Situación | Reacción |
|---|---|
| Celda de enlace que no decodifica | Cerrar el enlace y destruir sus circuitos |
| Celda manipulada o inválida dentro de un circuito | DESTROY(1) en ambas direcciones |
| `circ_id` desconocido | Se ignora; más de 8 seguidas en un enlace → cerrar el enlace |
| Se cae un enlace | Se destruyen sus circuitos y se propaga DESTROY(4) |
| Más de 8 conexiones simultáneas desde una IP | Se cierra al aceptar |
| Más de 16 circuitos en un enlace o 256 en el relay | DESTROY(4) |
| Circuito inactivo 60 s o con más de 10 min | DESTROY(2) |
| Handshake TLS + primera celda en más de 10 s | Se cierra la conexión |

## 6. Directorio firmado

Ver el formato completo en `minioni/directorio.py`. Se firma
`"MiniOni-v1 directorio\n" + JSON canónico` (claves ordenadas, sin
espacios). El cliente verifica en este orden: tamaño ≤ 64 KB → JSON sin
claves duplicadas → **firma** → estructura → vigencia → versión mínima.

## 7. Proxy SOCKS5 local (RFC 1928, subconjunto)

El proxy escucha **solo** en `127.0.0.1` (por defecto puerto 9050) y acepta:

| Paso | Formato aceptado | Respuesta |
|---|---|---|
| Saludo | `05 | NMETHODS (1–255) | métodos`, debe incluir `00` | `05 00`; si no incluye `00` → `05 FF` y cierre |
| Solicitud | `05 | CMD=01 | RSV=00 | ATYP | dirección | puerto (1–65535)`; ATYP `01` IPv4, `03` dominio (largo 1–255, `validar_host`), `04` IPv6 | — |
| CMD distinto de CONNECT | — | `05 07` y cierre |
| ATYP desconocido | — | `05 08` y cierre |
| Dominio mal formado o puerto 0 | — | `05 02` y cierre |
| Éxito (llegó CONNECTED) | — | `05 00 00 01 00000000 0000` |
| Fallo de MiniOni | — | Solo `05 01` (general) o `05 02` (no permitido). Nunca detalles. |

Todas las respuestas a la solicitud miden 10 bytes y llevan la dirección
`0.0.0.0:0`. Saludo + solicitud: máximo 10 s. Espera de CONNECTED: máximo 15 s.

**DNS remoto obligatorio:** el proxy nunca resuelve nombres; el dominio viaja
tal cual en BEGIN y lo resuelve el nodo de salida.

Gestor de circuitos: un circuito activo para los streams nuevos (se
construye al primer uso). A los 10 minutos, o con 32 streams abiertos, los
streams nuevos van a un circuito nuevo y el viejo se cierra cuando terminan
sus streams. Si un circuito cae, sus streams se cierran. Máximo 3 intentos de
construcción seguidos; luego `05 01`. **No existe ningún camino que conecte
directo al destino.**

Anti-rollback: el proxy guarda en `config/ultima_version` solo el número de
versión más alto del directorio que ha visto, y rechaza arrancar con un
directorio de versión menor.
