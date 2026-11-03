# Inventario criptográfico de MiniOni

Responde a OWASP ASVS 5.0 **V11.1.2** (inventario de claves, algoritmos y
certificados, dónde se pueden usar y qué protegen), **V11.1.1** (ciclo de
vida de las claves), **V11.2.3** (mínimo 128 bits de seguridad) y
**V11.1.4** (plan de migración poscuántica).

Toda la criptografía viene de la librería `cryptography` 50.0.2
(NIST SSDF PW.4.1). MiniOni no implementa ningún algoritmo propio.

## 1. Algoritmos

| Uso | Algoritmo | Seguridad | Módulo |
|---|---|---|---|
| Firma del directorio | Ed25519 | ~128 bits | `directorio.py` |
| Intercambio de claves por salto | X25519 (efímera-efímera + efímera-estática) | ~128 bits | `handshake.py` |
| Derivación de claves de salto | HKDF-SHA256 | 256 bits | `handshake.py` |
| Autenticación del relay en el handshake | HMAC-SHA256, verificación en tiempo constante | 256 bits | `handshake.py` |
| Cifrado de cada capa | ChaCha20-Poly1305 (AEAD) | 256 bits | `capas.py` |
| Cifrado de claves en disco | scrypt (N=2¹⁷, r=8, p=1) + ChaCha20-Poly1305 | según la contraseña | `almacen_claves.py` |
| Certificado TLS de cada relay | ECDSA P-256 con SHA-256 | ~128 bits | `admin.py` |
| Huella del certificado | SHA-256, comparación en tiempo constante (pinning) | 128 bits contra colisiones | `admin.py`, `directorio.py`, `transporte.py` |
| Túnel entre nodos | TLS 1.3 únicamente (suites por defecto de OpenSSL: AES-GCM / ChaCha20-Poly1305 con ECDHE) | ≥ 128 bits | `transporte.py` |
| Números aleatorios | `os.urandom` (CSPRNG del sistema operativo) | — | todos |

Todos cumplen el mínimo de 128 bits de ASVS V11.2.3. No se usan MD5, SHA-1,
RSA, modo ECB ni rellenos PKCS#1 v1.5 (V11.3.1, V11.4.1).

## 2. Claves

| Clave | Tipo | Dónde vive | Quién la usa | Qué protege | Duración | Si se compromete |
|---|---|---|---|---|---|---|
| **Privada de la autoridad** | Ed25519 | `claves/autoridad/autoridad.key`, cifrada con scrypt; idealmente en un equipo fuera de línea | Solo el administrador, al publicar | La integridad del directorio | Hasta que se rote manualmente | Un atacante puede publicar un directorio con relays falsos → se genera una autoridad nueva y se redistribuye `autoridad.pub` |
| Pública de la autoridad | Ed25519 | `config/autoridad.pub` | Clientes y relays | — | Igual que la privada | — |
| **Clave cebolla del relay** | X25519 estática | `claves/<apodo>/cebolla.key`, cifrada con scrypt | Solo ese relay | Demuestra que el relay es el publicado en el directorio | Recomendado: rotarla con cada certificado (90 días) | Alguien puede suplantar ese relay en circuitos **nuevos**; el tráfico pasado sigue protegido por las claves efímeras → se saca del directorio |
| Pública cebolla | X25519 | En el directorio firmado | Clientes | — | Igual | — |
| **Clave TLS del relay** | ECDSA P-256 | `claves/<apodo>/tls.key`, DER PKCS#8 dentro del contenedor scrypt | Solo ese relay | El túnel TLS 1.3 entre nodos | 90 días (vigencia del certificado) | Igual que la cebolla → nuevo certificado y nueva huella en el directorio |
| Certificado TLS | X.509 autofirmado | `claves/<apodo>/tls.crt`; su huella va en el directorio | Relays vecinos | — | 90 días | — |
| **Efímeras del handshake** (x, y) | X25519 | Solo memoria | Cliente y relay, una vez | Secreto hacia adelante | Un solo handshake | Ninguna consecuencia futura: se descartan al terminar |
| **Claves de salto** (ida, vuelta, auth) | 3 × 256 bits, derivadas con HKDF | Solo memoria | Cliente y un relay | Las celdas de un circuito en un salto | Máximo 10 min (o 60 s inactivo); el relay destruye el circuito y suelta las claves (semana 2) | Se expone solo ese circuito y solo ese salto |
| Clave de archivo | 256 bits derivados con scrypt | Solo memoria, mientras se abre el archivo | `almacen_claves.py` | Una clave privada en disco | Instantes | — |

Reglas que cumplen todas las claves (ASVS V11.1.1):
- Ninguna clave privada se comparte: cada relay tiene las suyas.
- Ninguna clave está escrita en el código ni se sube al repositorio
  (`claves/` está en `.gitignore`).
- Cada clave se usa para un solo propósito: la cebolla solo para el
  handshake, la TLS solo para TLS, la autoridad solo para firmar el directorio.
- Ida y vuelta usan claves distintas, así que un nonce nunca se repite entre direcciones.

## 3. Valores de un solo uso

| Valor | Cómo se genera | Garantía |
|---|---|---|
| Nonce de cada capa | Contador de 64 bits por salto y dirección, nunca se transmite | No se repite (V11.3.4); detecta celdas repetidas o reordenadas |
| Nonce del archivo de clave | 12 bytes de `os.urandom` | Clave de archivo distinta en cada guardado (sal nueva) |
| Sal de scrypt | 16 bytes de `os.urandom` | Evita tablas precalculadas |
| Relleno de celdas | `os.urandom` | No predecible: no revela el tamaño real |
| `circ_id` y `stream_id` | `secrets.randbelow` (CSPRNG), sin repetir en el enlace / circuito | No son secretos, pero no permiten adivinar ni enlazar circuitos o conexiones |
| Elección de la ruta | `secrets.SystemRandom` | Un observador no puede predecir qué relays usará el próximo circuito |

La semana 3 (nodo de salida y proxy SOCKS5) **no agrega algoritmos ni
claves**: los streams viajan dentro de las mismas capas ChaCha20-Poly1305 y el
tramo navegador → proxy es SOCKS5 en claro por `127.0.0.1` (ver LIMITES).

## 4. Decisión corregida durante el inventario

Al revisar el formato de la clave TLS se encontró que el PEM cifrado
estándar de OpenSSL (`BestAvailableEncryption`) usa **PBKDF2 con solo 2 048
iteraciones**, muy por debajo de las 600 000 que recomienda OWASP para
PBKDF2-HMAC-SHA256. La librería no permite cambiar ese valor en PKCS#8.
**Corrección:** la clave TLS ahora se guarda en el mismo contenedor scrypt
que las demás claves. Lo comprueba
`tests/test_admin.py::test_clave_tls_cifrada_con_scrypt_y_coincide_con_certificado`.

## 4.1 Clave TLS en memoria al arrancar el relay (semana 2)

El módulo `ssl` de Python solo carga la clave desde un archivo. Para no
guardar nunca la clave TLS en un formato débil, `transporte.contexto_servidor`:

1. descifra el DER desde el contenedor scrypt (`cargar_privada(..., "p256-pkcs8")`);
2. lo serializa como PEM PKCS#8 cifrado con una contraseña **aleatoria de
   256 bits y de un solo uso** (`secrets.token_urlsafe(32)`);
3. lo escribe en un archivo temporal (`tempfile.mkstemp`), llama a
   `load_cert_chain` y **borra el archivo en un `finally`**.

El PEM temporal usa PBKDF2 débil, pero con una contraseña aleatoria de 256
bits que nunca sale de la memoria esa debilidad no importa: no hay
diccionario posible. El archivo existe solo unos milisegundos.

## 5. Plan de migración poscuántica (ASVS V11.1.4)

Un computador cuántico suficientemente grande rompería X25519, Ed25519 y
ECDSA P-256. ChaCha20 con claves de 256 bits y SHA-256 siguen siendo seguros.

| Hoy | Reemplazo previsto | Disponible en `cryptography` 50 |
|---|---|---|
| X25519 en el handshake | Híbrido X25519 + ML-KEM-768 (FIPS 203): se concatenan ambos secretos antes de HKDF | Sí (`mlkem`) |
| Ed25519 en el directorio | ML-DSA-65 (FIPS 204), o firma doble Ed25519 + ML-DSA durante la transición | Sí (`mldsa`) |
| ECDSA P-256 en TLS | Depende del soporte TLS poscuántico de OpenSSL/Python | Fuera del alcance |

La prioridad es el **handshake**, porque un atacante podría grabar hoy el
tráfico y descifrarlo en el futuro ("guardar ahora, descifrar después").
Para que el cambio no obligue a rehacer el protocolo, el identificador
`MiniOni-v1` ya forma parte de todas las derivaciones de claves y de la
firma del directorio: una versión `MiniOni-v2` con el handshake híbrido no
podría confundirse con la v1. Este plan queda fuera de las 5 semanas del
proyecto.
