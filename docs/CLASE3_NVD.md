# Vulnerabilidades conocidas (NVD) y los 4 controles de la Clase 3

Consulta del 03-11-2026 a la base de datos del NIST (National Vulnerability
Database, <https://nvd.nist.gov/vuln/search>) por medio de su API oficial
(`services.nvd.nist.gov/rest/json/cves/2.0`), que consulta los mismos registros que
la página de búsqueda. Norma: NIST SSDF PW.4.1 y RV.1.1 (vigilar vulnerabilidades
de los componentes); OWASP ASVS 5.0 V15.2.1.

## Qué se buscó

Lo que MiniOni usa de verdad, con sus versiones en el equipo del grupo:

| Componente | Versión | Dónde lo usa MiniOni |
|---|---|---|
| Python (CPython) | 3.14.6 | Todo; `ssl` para TLS 1.3 entre nodos, `ipaddress` para la política de salida |
| OpenSSL del módulo `ssl` de Python | 3.5.7 | TLS 1.3 entre nodos y pruebas HTTPS del panel |
| `cryptography` | 50.0.2 (con OpenSSL 4.0.3) | X25519, Ed25519, ChaCha20-Poly1305, scrypt, certificados |
| detect-secrets, Bandit, pip-audit | 1.5.0, 1.9.4, 2.10.1 | Revisiones de seguridad |

Búsquedas: `cryptography`, `CPython`, módulo `ssl`, OpenSSL (marzo a noviembre de
2026), `X25519`, `ChaCha20-Poly1305`, `scrypt`, `SOCKS5`, `tkinter`, las tres
herramientas y CVE-2021-42574.

**Resultado:** un CVE aplica a la versión instalada (CVE-2026-75803, sin camino
explotable en MiniOni); los demás están corregidos en nuestras versiones o son de
otros productos, y sirven como evidencia de que los controles cubren fallos reales.
pip-audit coincide: sin vulnerabilidades en `requirements.txt` ni en
`requirements-dev.txt`.

## 1. Validación de entradas

| CVE | Qué es | Relación con MiniOni |
|---|---|---|
| CVE-2024-4032 (7.5) | `ipaddress` de Python clasificaba mal algunas direcciones como públicas o privadas (`is_private`, `is_global`). | La política de salida bloquea redes internas con `is_global` (`minioni/politica_salida.py:98`). Corregido en Python 3.12.4: **no afecta** (3.14.6), pero muestra que el bloqueo depende de mantener Python actualizado. |
| CVE-2023-38545 (9.8, curl), CVE-2026-56123 (9.2, socat) | Desbordamientos al procesar el nombre de dominio en SOCKS5. | Otros productos. Es el tipo de fallo que evitan la validación por lista blanca de `socks5.py` y su fuzzing (`test_fuzzing.py::test_fuzz_socks5_*`). |

## 2. Errores y logging

| CVE | Qué es | Relación con MiniOni |
|---|---|---|
| CVE-2026-69247 (8.2, CWE-209) | `cryptography` < 50.0.0 respondía distinto según el tipo de error al descifrar PKCS#7, y eso daba un oráculo de Bleichenbacher. | **No afecta** (50.0.2 y no usamos PKCS#7). Es el mismo principio de nuestro control: `cargar_privada` da el mismo error para "contraseña incorrecta" y "archivo dañado", y los DESTROY/END llevan motivos genéricos. |
| CVE-2026-2297 (5.7) | Los ganchos de auditoría de Python (PEP 578) no se activan al leer archivos `.pyc`. | "Verificar sin registros" (`minioni/sin_registros.py`) vigila **escrituras**, no lecturas: el resultado no cambia. Se anotó en `docs/LIMITES.md` que los ganchos de auditoría no son una barrera de seguridad. |

## 3. Cifrado

| CVE | Qué es | Relación con MiniOni |
|---|---|---|
| **CVE-2026-75803 (9.1)** | OpenSSL 3.0–3.0.21, 3.4.0–3.4.6, 3.5.0–3.5.7, 3.6.0–3.6.3 y 4.0.0–4.0.1: `EVP_Cipher()` acepta una etiqueta ChaCha20-Poly1305 falsa si el texto cifrado está vacío. | **Versión en el rango:** el `ssl` de Python 3.14.6 trae OpenSSL 3.5.7 (TLS 1.3 entre nodos). Sin camino explotable: cada registro TLS 1.3 lleva al menos el byte de tipo de contenido, nunca va vacío. Las capas de la cebolla y las claves en disco usan `cryptography` con OpenSSL 4.0.3 (corregido); se comprobó que una etiqueta falsa con texto vacío se rechaza con `InvalidTag`. **Acción:** actualizar Python cuando haya una 3.14.x con OpenSSL ≥ 3.5.8. |
| CVE-2026-26007 (8.2), CVE-2026-39892 (6.9), CVE-2026-69248 (6.9) | `cryptography` < 46.0.5 (sin validar el subgrupo de claves EC), < 46.0.7 (desbordamiento con buffers no contiguos), 45–48 (restricciones de nombre). | **No afectan** (50.0.2). |
| CVE-2026-17508 (5.3), CVE-2026-81721 (8.7) | Otras librerías derivaban claves con el costo de scrypt/PBKDF2 tomado del archivo, sin límite (denegación de servicio). | **No afecta:** `almacen_claves.cargar_privada` acepta n entre el mínimo y 2^20, con r y p fijos (`minioni/almacen_claves.py:95`). |
| CVE-2026-115557 (9.4) | El módulo `ssl` de Python agrega una lista de certificados comprometidos que se rechazan siempre. | Solo toca las pruebas HTTPS del panel (`control_red._pedir`), no la red cebolla, que usa pinning. El NVD aún no lista versiones: revisarlo al actualizar Python. |
| CVE-2026-10512 (wolfSSL), CVE-2026-65630 (jose, Erlang) | Fallos en implementaciones propias de X25519. | Otros productos. MiniOni no implementa criptografía propia (regla 6). |

## 4. SAST y secretos

| CVE | Qué es | Relación con MiniOni |
|---|---|---|
| CVE-2021-42574 (8.3) | Trojan Source: caracteres Unicode de dirección hacen que el código se vea distinto de lo que ejecuta. | Es el **fallo 11** que encontramos. Desde la tarea T2, Bandit (B613) lo revisa también en `tests/` en cada `revision_completa.py`. |
| CVE-2026-9323 (9.2, CWE-338) | Un programa usaba `random` para identificadores de sesión. | Exactamente lo que detectan Bandit (B311) y la regla `test_sin_algoritmos_ni_configuraciones_debiles`. |
| CVE-2026-120202 (7.1) | Un escáner de seguridad se saltaba subcarpetas y `.pyc`. | El mismo tipo de punto ciego que tuvo Bandit al excluir `tests/` (fallo 11). |
| CVE-2026-81690 (8.7) | Un escáner usaba `rglob()`, que no entra en carpetas enlazadas (*symlinks*). | **Brecha menor propia:** `revisar_secretos.py` también usa `rglob`, así que una carpeta enlazada dentro de la carpeta de claves no se revisaría. Git no sigue enlaces, así que lo que va al repositorio sí se revisa completo. Anotado en `docs/LIMITES.md`. |

detect-secrets, Bandit y pip-audit no tienen CVE registrados.

## Descartados

Los CVE de OpenSSL de 2026 sobre QUIC, CMS, CMP, OCSP, DTLS, SM2, CRL y AES-CFB:
MiniOni no usa esas funciones. Los CVE de SOCKS5 en clientes HTTP de Node, Erlang o
Python (undici, hackney, httpx2): MiniOni no usa esas librerías.

## Cómo repetir la consulta

```powershell
pip-audit -r requirements.txt          # dependencias de Python (usa la base de OSV/PyPI)
python -c "import ssl; print(ssl.OPENSSL_VERSION)"
```

Y buscar en <https://nvd.nist.gov/vuln/search> la versión de OpenSSL que imprima
el segundo comando, `cryptography` y `CPython`. pip-audit no revisa el OpenSSL que
trae Python: por eso esta consulta manual complementa a la automática.
