---
title: "MiniOni – Traspaso de la Clase 3 para Claude Code"
subtitle: "Qué se hizo en Codificación segura, qué reglas nuevas rigen el código y qué falta desarrollar antes de la Clase 4"
date: "3 de noviembre de 2026 · Equipo Onion"
---

> **Documento de trabajo ya cerrado.** Se conserva como historial del proyecto y puede no reflejar el estado actual. Lo vigente está en `README.md` y `docs/TRAZABILIDAD.md`.

# 0. Cómo usar este documento

Este documento reúne todo lo trabajado en el OVA de la **Clase 3 (Codificación
segura)**: la investigación de los cuatro controles, los 11 fallos encontrados y cómo
se corrigieron, las respuestas que se entregaron en el OVA y las tareas que quedaron
pendientes. Está escrito para que un asistente de programación (Claude Code) continúe
el proyecto sin repetir trabajo ni romper lo que ya se corrigió.

Las decisiones de diseño ya están tomadas aquí. Si algo no está especificado, se
elige la opción **más restrictiva** y se documenta. Las tareas de la sección 5 se
hacen **en el orden indicado**; cada una tiene criterios de aceptación.

**Resultado esperado al terminar:** las tareas T1 a T7 hechas, `python
revision_completa.py` en verde, Bandit (incluidas las pruebas) sin hallazgos reales,
`revisar_secretos.py` sin secretos y la documentación actualizada. Con eso el proyecto
queda listo para la semana 4 (Docker y redes segmentadas), que **no** se empieza aquí.

## 0.1 Antes de escribir código

1. Leer, en este orden: `README.md`, `docs/ARQUITECTURA.md`, `docs/PROTOCOLO.md`,
   `docs/LIMITES.md`, `docs/TRAZABILIDAD.md`, `docs/INVENTARIO_CRIPTOGRAFICO.md`,
   `docs/SIN_REGISTROS.md`, `docs/CLASE3_CODIFICACION_SEGURA.md` y
   `docs/CLASE3_FALLOS_Y_CORRECCIONES.md`.
2. Leer `minioni/` completo y `tests/test_codificacion_segura.py`, que contiene las
   reglas automáticas de la Clase 3.
3. Activar el entorno y comprobar que todo pasa **antes** de cambiar nada:

```powershell
cd C:\Users\Harpe\OneDrive\Desktop\MiniOni
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
python -m pytest
python revision_completa.py
```

   Estado de referencia (03-11-2026, Linux): **306 passed, 3 skipped**. En Windows
   cambia un poco el número de pruebas omitidas (las del panel sí corren porque hay
   tkinter), pero no debe haber ningún *failed*.

## 0.2 Entorno del equipo

- Windows 11, PowerShell, Python 3.14 con `.venv` en la raíz del proyecto.
- El proyecto está en `C:\Users\Harpe\OneDrive\Desktop\MiniOni`, **dentro de OneDrive**
  (ver la tarea T1).
- Todavía **no hay repositorio Git** (tarea T4).
- Dependencias de ejecución: solo `cryptography`. Desarrollo: pytest, Hypothesis,
  Bandit 1.9.4, pip-audit 2.10.1 y detect-secrets 1.5.0.
- **No ejecutar** `minioni_admin.py preparar-laboratorio --reiniciar` ni borrar
  `claves/` sin que el equipo lo pida: destruye las claves del laboratorio. Las
  contraseñas las escribe siempre la persona (`getpass`); nunca se piden por argumento,
  variable de entorno ni archivo.

# 1. Reglas obligatorias

## 1.1 Reglas que ya existían (semanas 1 a 3)

| # | Regla | Norma |
|---|---|---|
| 1 | **Ninguna dependencia nueva de ejecución.** Solo biblioteca estándar + `cryptography`. Herramientas de desarrollo nuevas solo con justificación escrita. | NIST SSDF PW.4.1 |
| 2 | **Cero registros de conexiones.** Nunca imprimir ni guardar IP, puertos de clientes, dominios ni contenido. La consola solo se usa con `consola.evento(componente, codigo, cantidad)`; un evento nuevo se agrega al catálogo `EVENTOS`. Nada se escribe en disco durante la navegación (lo vigila `sin_registros.py`). | ASVS 5.0 V16.2.5 |
| 3 | **Validación positiva** de todo lo que entra: tamaño exacto, valores de una lista permitida, nada sobrante. Lo demás se rechaza y la conexión se cierra. | ASVS 5.0 V2.2.1 |
| 4 | **Fallo cerrado.** Ante un error se destruye el circuito o se cierra la conexión; el cliente nunca se conecta directo al destino. | ASVS 5.0 V16.5.3 |
| 5 | **Errores genéricos.** Toda excepción propia hereda de `MiniOniError` y tiene `mensaje_publico`. Nunca se muestran trazas. | ASVS 5.0 V16.5.1 |
| 6 | **No reinventar criptografía.** Solo `capas.py`, `handshake.py`, `directorio.py`, `almacen_claves.py`, `transporte.py` y el módulo `ssl`. | ASVS 5.0 V11.2.1 |
| 7 | **Compatibilidad con Windows:** nada de `loop.add_signal_handler`; apagado con `KeyboardInterrupt`; rutas con `pathlib`. | — |
| 8 | **Todo cambio lleva pruebas.** Cada parser nuevo, con fuzzing de Hypothesis. `bandit -c pyproject.toml -r .` en 0 hallazgos; un `# nosec` solo con el motivo en la misma línea. | SSDF PW.7.2, PW.8.2 |
| 9 | **Sin `pytest-asyncio`.** Las pruebas async llaman `asyncio.run(...)`. | SSDF PW.4.1 |
| 10 | **Idioma:** identificadores, mensajes y documentación en español. | — |
| 11 | **Documentación al día:** `docs/TRAZABILIDAD.md`, `docs/LIMITES.md`, `README.md` y `COMANDOS.txt` (este último con fin de línea **CRLF**). | — |

## 1.2 Reglas nuevas de la Clase 3

Estas reglas salen de los fallos encontrados. Varias ya están vigiladas por pruebas en
`tests/test_codificacion_segura.py`, que fallan si se rompen.

| # | Regla | Por qué (fallo) | Vigilada por |
|---|---|---|---|
| 12 | Validar con **`fullmatch`**, nunca con `re.match`/`re.search` y `$`. En Python, `$` acepta un `\n` final. | Fallo 2 | `test_salto_de_linea_al_final_ya_no_pasa_la_validacion` |
| 13 | **Ningún texto externo llega a la consola sin pasar por `consola.texto_seguro`** (rutas, apodos, ecos de la red, nombres de archivo). Mejor aún: no repetir la entrada y dar un mensaje fijo. | Fallo 4 | `test_texto_seguro_neutraliza_controles` |
| 14 | **Todo programa nuevo con `if __name__ == "__main__":`** llama `consola.instalar_manejador_global("<componente>")` antes de cualquier otra cosa. Las ventanas Tk asignan `report_callback_exception`. | Fallo 3 | `test_excepcion_no_prevista_no_muestra_traza` |
| 15 | **Argumentos numéricos de la línea de comandos con tipo validado** (por ejemplo `type=argumento_puerto`), nunca `type=int` a secas. | Fallo 1 | `test_puerto_invalido_en_linea_de_comandos` |
| 16 | **Prohibido:** MD5, SHA-1, `verify=False`, `_create_unverified_context`, TLS anterior a 1.3 entre nodos, el módulo `random` para algo de seguridad, `pickle`, `eval`/`exec`, `shell=True`, DES, RC4, Blowfish y ECB. `ssl.CERT_NONE` **solo** en `transporte.py` y `control_red.py`; ni siquiera en comentarios de otros archivos. | Fallo 5 | `test_sin_algoritmos_ni_configuraciones_debiles`, `test_cert_none_solo_donde_hay_verificacion_propia_documentada` |
| 17 | **Toda conexión TLS nueva entre nodos** usa `transporte.verificar_huella`, que ya llama `verificar_vigencia`. Un relay no arranca con su certificado vencido. | Fallo 6 | `test_certificado_vencido_o_futuro_se_rechaza` |
| 18 | **No bajar `almacen_claves.minimo_aceptado`** fuera de `tests/conftest.py`. Las claves nuevas siempre usan `N_SCRYPT` (2¹⁷). | Fallo 7 | `test_en_uso_normal_no_se_acepta_scrypt_debil` |
| 19 | **Toda contraseña nueva de claves** pasa por `motivo_contrasena_debil`. | Fallo 8 | `test_contrasenas_debiles_se_rechazan` |
| 20 | **Cero secretos en archivos versionables.** Un token falso para una prueba se arma en tiempo de ejecución (`"sk_" + "live_" + ...`). Las contraseñas de prueba solo viven en `tests/`. `python revisar_secretos.py` debe terminar con código 0. | Fallo 9 | `test_revision_de_secretos_limpia` |
| 21 | **Nunca escribir caracteres Unicode de control de dirección** (U+202A–U+202E, U+2066–U+2069, U+200E, U+200F) en el código: usar siempre la secuencia de escape (`"\u202e"`). Cuidado al generar código: es fácil que el editor o la herramienta convierta el escape en el carácter real. | Fallo 11 | `test_ningun_archivo_contiene_caracteres_bidi_ocultos` |
| 22 | **El SAST cubre también las pruebas.** Además del Bandit normal, `bandit -r tests -s B101,B104,B105` no debe mostrar hallazgos (tarea T2). | Fallo 11 | `revision_completa.py` |

# 2. Estado del proyecto después de la Clase 3

## 2.1 Los cuatro controles

| Control (OVA) | Cómo está implementado | Norma |
|---|---|---|
| Validación de entradas | Listas blancas en los 9 parsers (celdas, SOCKS5, política de salida, directorio, línea de comandos), con `fullmatch` y fuzzing de Hypothesis (≈105 000 entradas). | ASVS 5.0 V2.2.1 (4.0 V5) |
| Errores y logging | `mensaje_publico` en cada error; manejador de último recurso en proceso, hilos, bucle asyncio y Tk; consola de catálogo cerrado en UTC; `texto_seguro` para el texto externo; **ningún registro en disco** (decisión de privacidad). | ASVS 5.0 V16 (4.0 V7) |
| Cifrado | TLS 1.3 entre nodos con *pinning* de huella y verificación de vigencia; X25519 + HKDF; ChaCha20-Poly1305 por capa; directorio firmado con Ed25519 y anti-rollback; claves en disco con scrypt N=2¹⁷ + ChaCha20-Poly1305; contraseñas no comunes. | ASVS 5.0 V11, V12 (4.0 V6, V9) |
| SAST y secretos | Bandit 1.9.4 en 0; reglas propias para lo que Bandit no ve; `revisar_secretos.py` (detect-secrets + `.gitignore` + claves cifradas + aviso de nube); `hooks/pre-commit`. | SSDF PW.7, PS.1; ASVS 5.0 V13.3 |

## 2.2 Archivos creados o modificados en la Clase 3

| Archivo | Qué cambió |
|---|---|
| `minioni/consola.py` | `texto_seguro(texto, maximo=80)` (línea 78) e `instalar_manejador_global(componente)` (línea 90); `_COMPONENTE.fullmatch`. |
| `minioni/proxy.py` | `argumento_puerto` (≈463); `_VERSION_GUARDADA.fullmatch`. |
| `minioni/transporte.py` | `verificar_vigencia` (92), llamada desde `verificar_huella` (108). TLS 1.3 en las líneas 38-39; `CERT_NONE` en la 88 con su comentario. |
| `minioni/relay.py` | `verificar_identidad` comprueba la vigencia del certificado propio (777). |
| `minioni/errores.py` | Nuevo `CertificadoVencido`. |
| `minioni/almacen_claves.py` | `minimo_aceptado` (43), `carpeta_sincronizada` (137), `motivo_contrasena_debil` (171). |
| `minioni/celdas.py`, `directorio.py`, `admin.py` | `fullmatch` en todos los validadores; `admin.py` revisa contraseñas débiles, aplica `texto_seguro` a `--archivo` y avisa de OneDrive. |
| `ejecutar_relay.py`, `cliente_proxy.py`, `cliente_prueba.py`, `minioni_admin.py`, `panel.py` | Manejador global; apodo con lista blanca; `argumento_puerto`; `Panel.error_inesperado`. |
| `revisar_secretos.py` (nuevo) | 5 comprobaciones; nunca imprime el secreto; código 1 si hay problemas. |
| `hooks/pre-commit` (nuevo) | Ejecuta `revisar_secretos.py` y cancela el commit si falla. |
| `tests/test_codificacion_segura.py` (nuevo) | 29 funciones de prueba (≈53 casos con parámetros) con las reglas de la sección 1.2. |
| `tests/conftest.py` | Fixture que baja `minimo_aceptado` a 2¹⁴ solo durante las pruebas. |
| `.gitignore`, `requirements-dev.txt`, `revision_completa.py`, `COMANDOS.txt`, `README.md` | `errores.txt`/`pytest.txt` excluidos; detect-secrets; paso de secretos; sección "Revisión de secretos". |
| `docs/CLASE3_CODIFICACION_SEGURA.md`, `docs/CLASE3_FALLOS_Y_CORRECCIONES.md` (+ PDF), `docs/TRAZABILIDAD.md` | Investigación del OVA, detalle de los 11 fallos y 10 filas nuevas de trazabilidad. |

## 2.3 Verificación final de la Clase 3 (03-11-2026)

- `python -m pytest`: 306 passed, 3 skipped (Linux, sin tkinter).
- `bandit -c pyproject.toml -r .`: 0 hallazgos en 4 332 líneas; 2 suprimidos con
  motivo (`revision_completa.py:9` B404 y `:32` B603).
- `bandit -r . -x ./.venv` (incluye pruebas, 6 592 líneas): 220 B101, 3 B105 y 2 B104,
  todos falsos positivos de código de pruebas; 0 B613 después de la corrección.
- `python revisar_secretos.py`: 62 archivos versionables, 0 secretos; 22 cadenas de alta
  entropía esperadas en archivos ignorados (8 en las claves cifradas de `claves/`, 14 en
  datos públicos de `config/`); aviso de OneDrive.
- `python revision_completa.py`: "Todo correcto".

# 3. Los 11 fallos de la Clase 3 (resumen)

El detalle completo (qué pasaba, qué lo provocaba, cómo se resolvió, prueba y norma)
está en `docs/CLASE3_FALLOS_Y_CORRECCIONES.md`. **Ninguno debe reaparecer.**

| # | Control | Causa | Corrección | Estado |
|---|---|---|---|---|
| 1 | Validación | `--puerto` con `type=int` aceptaba 0 (puerto al azar). | `argumento_puerto` (1–65535) en `cliente_proxy.py` y `panel.py`. | Corregido |
| 2 | Validación | `re.match` con `$` aceptaba un `\n` final en host, apodo, huella, fechas y versión. | `fullmatch` en los 10 usos. | Corregido |
| 3 | Errores y logging | Sin manejador de último recurso en proceso, hilos ni Tk: se veían trazas. | `instalar_manejador_global` en 5 programas + `Panel.error_inesperado`. | Corregido |
| 4 | Errores y logging | `print` directos repetían el apodo/rutas/eco con secuencias ANSI: inyección en la consola. | Lista blanca del apodo + `texto_seguro`. | Corregido |
| 5 | Cifrado | Nada impedía agregar criptografía débil; Bandit no marcó `CERT_NONE` (falso negativo). | Regla automática de algoritmos prohibidos y de `CERT_NONE`. | Corregido |
| 6 | Cifrado | Con *pinning*, OpenSSL no revisaba fechas: un certificado vencido seguía funcionando. | `verificar_vigencia` en cliente y al arrancar el relay. | Corregido |
| 7 | Cifrado | El mínimo de scrypt al cargar era 2¹⁴ (el de las pruebas). | `minimo_aceptado` = 2¹⁷; solo `conftest.py` lo baja. | Corregido |
| 8 | Cifrado | La contraseña de las claves solo exigía 12 caracteres. | `motivo_contrasena_debil` (comunes, repetidas, palabra + números, teclado). | Corregido |
| 9 | SAST y secretos | Sin escáner de secretos; las claves (cifradas) se sincronizan con OneDrive. | `revisar_secretos.py`; aviso de nube. **OneDrive solo mitigado.** | Mitigado → **T1** |
| 10 | SAST y secretos | La revisión no ve el historial de Git; `errores.txt` no estaba excluido. | `hooks/pre-commit`; `.gitignore`. **El historial aún no se revisa.** | Corregido → **T3** |
| 11 | SAST y secretos | Carácter U+202E real en una prueba (Trojan Source); Bandit excluye `tests/`. | Escape `\u202e` + regla sobre todos los `.py`. | Corregido → **T2** |

Falsos positivos ya resueltos (no repetir): `revisar_secretos.py` arma las marcas PEM
por partes para no detectarse a sí mismo; el token de la prueba se arma en tiempo de
ejecución; una línea de `docs/CLASE3_CODIFICACION_SEGURA.md` lleva
`<!-- pragma: allowlist secret -->`.

# 4. Lo que se entregó en el OVA de la Clase 3

El OVA tiene tres partes de investigación y una de evidencia. El texto completo está en
`docs/CLASE3_CODIFICACION_SEGURA.md`; aquí va el resumen para tener el contexto.

**Investigación 01 · Hallazgos de controles (8 filas).** Se dejaron los fallos 1, 2, 3,
4, 6, 7, 8 y 9 más los controles correctos; los fallos 5 y 10 se movieron a la
Investigación 02. Cada fila cita archivo y línea y la norma en ASVS 4.0 (la que usa el
OVA) con su equivalente en ASVS 5.0: V5 → V2, V6 → V11, V7 → V16, V9 → V12.

**Investigación 02 · SAST y secretos.**

- Herramienta: Bandit (Python), complementada con detect-secrets y reglas propias.
- Hallazgos: 0 en el código del programa (+2 suprimidos con motivo); 225 al ampliar a
  las pruebas, de los que solo 1 era real (B613, fallo 11).
- Interpretación: B404/B603, B105, B104 y B101 son falsos positivos; `CERT_NONE` fue un
  falso negativo cubierto con una regla propia. Conclusión: el SAST no es una bala de plata.
- Revisión de secretos: se eligió la opción «Sí, no encontramos secretos» (62 archivos, 0 secretos; escáner probado
  plantando 3 secretos; OneDrive, Git y `errores.txt` como puntos de atención).

**Investigación 03 · Conclusiones.** Los cuatro controles estaban implementados; la
investigación encontró 11 huecos y corrigió 10. **Compromisos para antes de la Clase 4**
(son las tareas de la sección 5):

1. Sacar las claves de OneDrive y regenerarlas (T1).
2. Crear el repositorio Git y activar el hook de secretos (T4).
3. Ejecutar `pip-audit` con internet (T5).
4. Documentar la rotación de claves y certificados (T6); los certificados actuales
   vencen hacia el **25 de enero de 2027**.
5. Mantener `python revision_completa.py` en verde antes de cada entrega (T2, T7).

**Evidencia (fotos que sube el equipo).** 1) `celdas.py` 187-215; 2) `python
cliente_proxy.py --puerto 0`; 3) `python ejecutar_relay.py --apodo "x;rm"`; 4)
`consola.py` 78-110; 5) `transporte.py` 38-39 y 92-120; 6) `bandit -c pyproject.toml -r
.`; 7) `python revisar_secretos.py`; 8) `python -m pytest tests/test_codificacion_segura.py
-v`. **Si una tarea mueve esas funciones de línea, actualizar las líneas citadas en
`docs/CLASE3_CODIFICACION_SEGURA.md`.**

# 5. Tareas para Claude Code

## T1 · Carpeta de claves configurable, fuera de OneDrive (cierra el fallo 9)

**Problema real encontrado al preparar este traspaso:** solo `panel.py` acepta otra
carpeta (`--carpeta`, que mueve `config/` y `claves/` juntas). `minioni_admin.py`,
`ejecutar_relay.py` y `revisar_secretos.py` usan siempre `Path("claves")` relativo a la
carpeta actual, así que hoy **no hay forma práctica** de tener las claves fuera de
OneDrive usando todos los programas.

**Qué hacer:**

1. Nueva función `almacen_claves.carpeta_claves() -> Path`: devuelve la ruta de la
   variable de entorno `MINIONI_CLAVES` si está definida; si no, `Path("claves")`.
   Validación: la ruta se resuelve (`resolve()`), debe ser absoluta, no puede estar
   dentro de una carpeta sincronizada (`carpeta_sincronizada`) **salvo** que sea la
   predeterminada (para no romper el uso actual), y si existe debe ser una carpeta.
   Si no cumple, error genérico y salida con código 1, sin mostrar la ruta completa
   (`texto_seguro`).
2. Usarla en `minioni/admin.py`, `ejecutar_relay.py`, `panel.py` (cuando no se pase
   `--carpeta`), `control_red.py` si corresponde y `revisar_secretos.py` (el paso 3 revisa
   esa carpeta; el aviso de nube también).
3. Nuevo comando `python minioni_admin.py donde-estan-las-claves`: dice si se usa la
   carpeta predeterminada o `MINIONI_CLAVES`, si está en una carpeta sincronizada y
   cuántos relays tienen claves. No muestra contraseñas ni contenido de claves.
4. Documentar en `COMANDOS.txt` y en `README.md` el procedimiento (PowerShell):

```powershell
mkdir C:\MiniOniClaves
setx MINIONI_CLAVES C:\MiniOniClaves      # cerrar y abrir PowerShell después
python minioni_admin.py preparar-laboratorio   # crea claves NUEVAS en C:\MiniOniClaves
python revisar_secretos.py                     # ya no debe salir el aviso de OneDrive
```

   Después el equipo borra la carpeta `claves/` vieja **y vacía la papelera de reciclaje
   de OneDrive**: OneDrive guarda copias de lo borrado y su historial de versiones. Por
   eso se **regeneran** las claves en lugar de moverlas: las que pasaron por la nube se
   consideran expuestas, aunque estén cifradas.
5. Actualizar `docs/LIMITES.md` (decisión documentada) y la fila de secretos de
   `docs/TRAZABILIDAD.md`.

**Pruebas:** `MINIONI_CLAVES` con una carpeta temporal se respeta en `generar_relay`,
`verificar_identidad` y `revisar_secretos`; una ruta relativa, un archivo o una carpeta
dentro de OneDrive (simulada con la variable `OneDrive` apuntando a un temporal) se
rechazan; sin la variable todo funciona como antes.

**Norma:** ASVS 5.0 V13.3.1 y V11.1.1; NIST SSDF PS.1.1.

## T2 · SAST también sobre las pruebas (cierra la lección del fallo 11)

1. En `revision_completa.py`, nuevo paso **"Análisis estático de las pruebas (Bandit)"**:
   `[PY, "-m", "bandit", "-q", "-r", "tests", "-s", "B101,B104,B105"]`.
   - B101: pytest funciona con `assert`.
   - B104: `0.0.0.0` aparece en pruebas que comprueban que se **rechaza**.
   - B105: contraseñas de laboratorio que solo existen en las pruebas.
   - Escribir esas tres justificaciones como comentario junto al paso y en
     `docs/CLASE3_CODIFICACION_SEGURA.md`.
2. No se acepta ningún `# nosec` dentro de `tests/`. Agregar una prueba que lo compruebe.
3. Agregar el comando a `COMANDOS.txt`.

**Criterio:** el paso sale OK hoy y falla si se planta un U+202E real en un archivo de
`tests/` (comprobarlo en una copia temporal y descartar la copia).

**Norma:** NIST SSDF PW.7.2.

## T3 · Revisión del historial de Git (cierra el fallo 10)

1. En `revisar_secretos.py`, nuevo paso **"6. Secretos en el historial de Git"**, que solo
   corre si existe `.git` y el comando `git` está disponible. Si no, imprime el aviso
   actual y no falla.
2. Implementación: `subprocess.run(["git", "log", "--all", "-p", "--no-color",
   "--unified=0", "--no-ext-diff"], capture_output=True, shell=False)`, con `# nosec
   B603 B607` y su motivo (comando fijo, sin shell, sin datos del usuario). Tomar solo las
   líneas **agregadas** (`+` y no `+++`), agrupadas por commit y archivo. Escribirlas en un
   directorio temporal (`tempfile.TemporaryDirectory`) con la misma extensión que el
   archivo original y analizarlas con `SecretsCollection`, como en el paso 1.
3. Ignorar lo que esté bajo rutas de `.gitignore` (por si alguna vez se commiteó algo
   antes de ignorarlo, **eso sí se reporta**: un `.key` en el historial es un hallazgo).
4. Salida: hash corto del commit, archivo y tipo de secreto. **Nunca el secreto.**
   Si hay hallazgos, código 1 y la indicación: "rota ese secreto; borrarlo del código no
   lo saca del historial".
5. El hook `hooks/pre-commit` no cambia (revisa lo actual antes de cada commit).

**Pruebas** (se omiten con `pytest.skip` si no hay `git`): repositorio temporal con un
commit limpio → 0 hallazgos; un commit que agrega el token falso (armado en tiempo de
ejecución) y otro que lo borra → se detecta con el hash del primer commit; un `.key`
commiteado → hallazgo; la salida nunca contiene el token.

**Norma:** NIST SSDF PS.1.1; ASVS 5.0 V13.3.1.

## T4 · Crear el repositorio Git (con el equipo presente)

Solo después de T1 a T3 y **con la confirmación del equipo**:

```powershell
git init
git config core.hooksPath hooks
python revisar_secretos.py        # debe terminar sin problemas
git add .
git status                        # comprobar que NO aparecen claves/, *.key ni errores.txt
git commit -m "MiniOni: estado al cierre de la Clase 3"
```

Si `git status` muestra cualquier archivo de claves, **detenerse** y corregir
`.gitignore` antes del commit. Registrar en `docs/TRAZABILIDAD.md` la fecha y que el hook
quedó activo. No subir a ningún remoto sin que el equipo lo pida.

## T5 · Auditoría de dependencias con internet

`python revision_completa.py --con-internet` (ya ejecuta `pip-audit -r
requirements.txt`). Si aparece una vulnerabilidad en `cryptography`, actualizar la
versión fijada en `requirements.txt`, volver a correr todo y anotarlo. Registrar el
resultado y la fecha en `docs/TRAZABILIDAD.md`. También se puede auditar
`requirements-dev.txt` como información, sin que bloquee.

**Norma:** NIST SSDF PW.4.4; ASVS 5.0 V15.2.1.

## T6 · Rotación de certificados y claves (compromiso 4 del OVA)

Los certificados TLS duran 90 días (`admin.py:99`) y los actuales vencen hacia el
25-01-2027. Hoy la única forma de renovarlos es `preparar-laboratorio --reiniciar`, que
borra **todo**.

1. **Aviso anticipado:** nuevo evento del catálogo `CERTIFICADO_POR_VENCER`
   ("certificado TLS próximo a vencer"), emitido por el relay al arrancar si faltan 15
   días o menos, con `cantidad` = días restantes. Implementarlo con una función
   `transporte.dias_restantes(der, ahora=None) -> int`.
2. **Comando `python minioni_admin.py renovar-certificado --apodo X`:** pide la
   contraseña, comprueba que descifra la `tls.key` actual, genera clave y certificado TLS
   nuevos (90 días) y los guarda solo después de generarlos bien (escribir a un archivo
   temporal en la misma carpeta y `os.replace`). La clave cebolla no cambia. Al
   terminar indica el siguiente paso: publicar el directorio con la versión siguiente.
3. **Comando `python minioni_admin.py revisar-certificados`:** lista por apodo los días
   restantes de cada certificado (el apodo no es un dato sensible). Sale con código 1 si
   alguno está vencido.
4. **Nuevo `docs/ROTACION_CLAVES.md`:** cuándo rotar (vencimiento, sospecha de
   exposición, claves que pasaron por la nube), los pasos de cada caso (certificado TLS,
   clave cebolla de un relay, clave de la autoridad), cómo se publica el directorio con
   la versión siguiente (el anti-rollback exige subirla) y qué ve un cliente con el
   directorio viejo (fallo cerrado por huella distinta).

**Pruebas:** `dias_restantes` con fechas fijas; el evento se emite a los 15 días y no a
los 16; `renovar-certificado` cambia la huella y la clave cebolla no; con contraseña
incorrecta no toca ningún archivo; el relay con el certificado renovado y el directorio
viejo se rechaza; con el directorio nuevo funciona.

**Norma:** ASVS 5.0 V13.3.4 y V11.1.1; ASVS 5.0 V12.3.4.

## T7 · Documentación y cierre

1. Actualizar `docs/TRAZABILIDAD.md` (una fila por tarea, con prueba y fecha),
   `docs/LIMITES.md`, `README.md` y `COMANDOS.txt` (**CRLF**).
2. Si cambian líneas citadas en el OVA, actualizar `docs/CLASE3_CODIFICACION_SEGURA.md`.
3. En `docs/CLASE3_FALLOS_Y_CORRECCIONES.md`, marcar el fallo 9 como **resuelto** cuando
   el equipo haya regenerado las claves fuera de OneDrive, y el fallo 10 como resuelto
   con T3. Regenerar su PDF si se tiene la herramienta; si no, dejarlo indicado.
4. Ejecutar y dejar en verde: `python -m pytest`, `python revision_completa.py`,
   `bandit -c pyproject.toml -r .` y `python revisar_secretos.py`.

# 6. Criterios de aceptación

- [ ] Todas las pruebas pasan en Windows; las 306 anteriores siguen pasando.
- [ ] Con `MINIONI_CLAVES` apuntando fuera de OneDrive, todos los programas usan esa
      carpeta y `revisar_secretos.py` ya no muestra el aviso de nube.
- [ ] `revision_completa.py` incluye el Bandit de pruebas y sale "Todo correcto".
- [ ] `revisar_secretos.py` revisa el historial cuando hay `.git` y detecta un secreto
      commiteado y luego borrado, sin mostrarlo.
- [ ] Existe el repositorio con el hook activo y ningún archivo de claves en él (T4).
- [ ] `pip-audit` ejecutado y registrado.
- [ ] `renovar-certificado`, `revisar-certificados` y el evento `CERTIFICADO_POR_VENCER`
      funcionan; `docs/ROTACION_CLAVES.md` existe.
- [ ] Ninguna regla de la sección 1 se rompió: sin registros en disco, sin trazas, sin
      texto externo sin `texto_seguro`, sin dependencias de ejecución nuevas.

# 7. Mapa de normas de este trabajo

| Norma | Dónde se cumple |
|---|---|
| OWASP ASVS 5.0 V2.2.1-2 (4.0 V5) | Listas blancas y `fullmatch`; argumentos de línea de comandos validados (T1: `MINIONI_CLAVES`). |
| OWASP ASVS 5.0 V11, V12 (4.0 V6, V9) | TLS 1.3 + pinning + vigencia; scrypt 2¹⁷; regla de criptografía débil; rotación (T6). |
| OWASP ASVS 5.0 V13.3.1, V13.3.4 | Secretos fuera del repositorio y de la nube (T1, T3, T4); rotación documentada (T6). |
| OWASP ASVS 5.0 V16 (4.0 V7) | Consola de catálogo cerrado, `texto_seguro`, manejador global; evento nuevo de vencimiento (T6). |
| NIST SP 800-218 SSDF PS.1.1 | `revisar_secretos.py`, historial (T3), hook (T4). |
| NIST SSDF PW.4.4 | `pip-audit` (T5). |
| NIST SSDF PW.7.2 | Bandit en código y pruebas (T2); reglas propias. |
| NIST SSDF PW.8.2 | Pruebas de cada tarea. |
| ISO/IEC 27033 | Protección del canal entre nodos (TLS 1.3); la segmentación en redes llega en la semana 4. |

# 8. Fuera del alcance de este traspaso

- **Semana 4 – Docker y redes segmentadas (ISO/IEC 27033).** Ya está preparado:
  `config/relays.json` con subredes `10.10.1.x`, `10.10.2.x` y `10.10.3.x`,
  `ejecutar_relay.py --escuchar` y el panel rechaza el directorio de Docker. Se diseña
  cuando el equipo comparta el OVA de la Clase 4.
- Captura con Wireshark para el informe (semana 5), servicios `.onion`, tráfico de
  cobertura, autenticación mutua entre relays y criptografía poscuántica (plan en
  `docs/INVENTARIO_CRIPTOGRAFICO.md`).
- Subir el repositorio a un remoto (GitHub u otro) sin la decisión del equipo.
