---
title: "MiniOni – Fallos encontrados en los controles y cómo se corrigieron"
subtitle: "Clase 3 · Codificación segura · Validación, errores y logging, cifrado, SAST y secretos"
date: "3 de noviembre de 2026 · Equipo Onion"
---

# Resumen

La investigación de la Clase 3 revisó el código real de MiniOni contra los cuatro
controles del OVA y encontró **11 fallos**: 2 de validación, 2 de errores y
logging, 4 de cifrado y 3 de SAST y secretos. Diez quedaron corregidos en el
código y uno quedó mitigado con un aviso (las claves en OneDrive), porque moverlas
es una decisión del equipo. Cada corrección tiene una prueba automática en
`tests/test_codificacion_segura.py` que falla si el error vuelve a aparecer.

| Control | Fallos | Corregidos | Mitigados |
|---|---|---|---|
| Validación de entradas | 2 | 2 | 0 |
| Errores y logging | 2 | 2 | 0 |
| Cifrado | 4 | 4 | 0 |
| SAST y secretos | 3 | 2 | 1 |
| **Total** | **11** | **10** | **1** |

Verificación final (03-11-2026): 306 pruebas automáticas en verde, Bandit con 0
hallazgos y `revisar_secretos.py` sin secretos expuestos.

**Actualización del 03-11-2026 (tareas T1 a T7):** el fallo 10 queda **resuelto**
con la revisión del historial de Git. El fallo 9 sigue **mitigado** hasta que el
equipo regenere las claves fuera de OneDrive: el código ya lo permite
(`MINIONI_CLAVES`), pero el paso lo hace cada persona en su equipo. Verificación:
344 pruebas en verde (1 omitida, solo para Linux), Bandit con 0 hallazgos en el
programa y en las pruebas, `revisar_secretos.py` sin secretos y `pip-audit` sin
vulnerabilidades.

# 1. Validación de entradas

## Fallo 1 · El proxy aceptaba el puerto 0

| | |
|---|---|
| **Qué pasaba** | `python cliente_proxy.py --puerto 0` se aceptaba y el proxy quedaba escuchando en un puerto elegido al azar por el sistema. El usuario no podía saber a qué puerto apuntar Firefox, porque la consola nunca muestra puertos. |
| **Qué lo provocaba** | El argumento `--puerto` de `cliente_proxy.py` y `panel.py` se leía con `type=int`, que acepta cualquier entero. La validación de rango (1–65535) solo estaba dentro de `ServidorProxy`, que deja pasar el 0 a propósito para las pruebas internas. |
| **Cómo se resolvió** | Nueva función `argumento_puerto` en `minioni/proxy.py`, usada como tipo del argumento en los dos programas: solo acepta enteros de 1 a 65535 y rechaza el valor antes de arrancar, con un mensaje claro. |
| **Prueba** | `test_puerto_invalido_en_linea_de_comandos`, `test_cliente_proxy_rechaza_puerto_0_antes_de_arrancar` |
| **Norma** | OWASP ASVS 5.0 V2.2.1 y V2.2.2 (4.0 V5.1.3) |

## Fallo 2 · Los validadores aceptaban un salto de línea al final

| | |
|---|---|
| **Qué pasaba** | `validar_host("ejemplo.com\n")` y `validar_host("a\n.com")` se aceptaban como nombres válidos. Lo mismo ocurría con el apodo de un relay (`"entrada1\n"`), la huella TLS, las fechas del directorio y la versión guardada del anti-rollback. Un nombre con salto de línea podía colarse en la petición BEGIN o en la cabecera `Host:` que arma el panel. |
| **Qué lo provocaba** | Las expresiones regulares se aplicaban con `re.match` y terminaban en `$`. En Python, `$` también coincide **justo antes de un salto de línea final**, así que `^[A-Za-z0-9-]+$` acepta `"abc\n"`. El fuzzing no lo encontró porque generar exactamente ese caso es poco probable. |
| **Cómo se resolvió** | Los 10 usos se cambiaron a `fullmatch`, que exige que todo el texto coincida: `celdas.py` (etiquetas DNS), `directorio.py` (apodo, huella y fecha), `admin.py` (apodo), `consola.py` y `relay.py` (componente), `proxy.py` (versión guardada) y `ejecutar_relay.py` (apodo). |
| **Prueba** | `test_salto_de_linea_al_final_ya_no_pasa_la_validacion`, `test_apodo_con_salto_de_linea_se_rechaza_al_generar` |
| **Norma** | OWASP ASVS 5.0 V2.2.1 (4.0 V5.1.3) |

# 2. Errores y logging

## Fallo 3 · Las excepciones no previstas mostraban la traza completa

| | |
|---|---|
| **Qué pasaba** | Si ocurría un error no previsto fuera del bucle de red, o en un botón del panel, Python imprimía la traza completa: rutas de archivos, nombres de funciones y a veces valores internos. En el panel salía como "Exception in Tkinter callback". |
| **Qué lo provocaba** | Los relays y el proxy ya tenían un manejador para el bucle asyncio, pero el **proceso** no tenía manejador de último recurso: se usaban `sys.excepthook`, `threading.excepthook` y `Tk.report_callback_exception` por defecto, que imprimen todo. |
| **Cómo se resolvió** | Nueva función `consola.instalar_manejador_global(componente)`, que reemplaza los manejadores del proceso y de los hilos para emitir solo "error interno" del catálogo; Ctrl+C sigue cerrando en silencio. Se instala en los 5 programas (`ejecutar_relay.py`, `cliente_proxy.py`, `cliente_prueba.py`, `minioni_admin.py`, `panel.py`), y el panel tiene además `Panel.error_inesperado`, que muestra "Error interno." y deja la ventana funcionando. |
| **Prueba** | `test_excepcion_no_prevista_no_muestra_traza`, `test_excepcion_en_un_hilo_no_muestra_traza`, `test_ctrl_c_cierra_en_silencio`, `test_error_en_un_boton_del_panel_es_generico` |
| **Norma** | OWASP ASVS 5.0 V16.5.4 y V16.5.1 (4.0 V7.4.1) |

## Fallo 4 · Inyección en la consola con texto escrito por el usuario

| | |
|---|---|
| **Qué pasaba** | `ejecutar_relay.py --apodo` repetía el apodo tal cual en su mensaje de error. Con un apodo que contenía `ESC[2J` (borrar pantalla) y un salto de línea, la consola mostraba una línea falsa: `FALSO: relay comprometido`. Lo mismo podía pasar con las rutas de `--politica` y `--archivo`, y con el eco que devuelve la red en `cliente_prueba.py`. |
| **Qué lo provocaba** | La consola de eventos usa un catálogo cerrado y es segura, pero esos mensajes eran `print(f"...")` directos que **saltaban el catálogo** y mostraban texto externo sin neutralizar los caracteres de control. |
| **Cómo se resolvió** | El apodo se valida con lista blanca antes de usarlo (`[A-Za-z0-9_-]{1,32}`, con `fullmatch`). Nueva función `consola.texto_seguro`, que reemplaza por `?` los caracteres de control (incluidas las secuencias ANSI y los controles de dirección Unicode) y recorta el largo; se aplica a las rutas, al eco y a los nombres de archivo de `revisar_secretos.py`. |
| **Prueba** | `test_apodo_con_secuencias_de_escape_no_llega_a_la_consola`, `test_texto_seguro_neutraliza_controles` |
| **Norma** | OWASP ASVS 5.0 V16.4.1 (codificar para evitar inyección en registros) y V2.2.1 |

# 3. Cifrado

## Fallo 5 · Nada impedía introducir criptografía débil en el futuro

| | |
|---|---|
| **Qué pasaba** | El código no usaba MD5, SHA-1, ECB ni `verify=False`, pero ninguna comprobación automática lo garantizaba. Además, **Bandit no marcó** `ssl.CERT_NONE` en `transporte.py`: es seguro porque la confianza viene del *pinning* de la huella, pero el SAST no lo distinguió (falso negativo). |
| **Qué lo provocaba** | La seguridad del cifrado dependía solo de la revisión manual, y el SAST tiene puntos ciegos. |
| **Cómo se resolvió** | Regla automática en las pruebas: falla si aparece MD5/SHA-1, `verify=False`, `_create_unverified_context`, TLS anterior a 1.2, el módulo `random`, `pickle`, `eval`, `shell=True` o cifrados obsoletos (DES, RC4, Blowfish, ECB). `CERT_NONE` solo se permite en los dos lugares auditados (`transporte.py` y `control_red.py`), cada uno con su justificación. Al probarla, la regla detectó un comentario nuevo que mencionaba `CERT_NONE`, señal de que funciona. |
| **Prueba** | `test_sin_algoritmos_ni_configuraciones_debiles`, `test_cert_none_solo_donde_hay_verificacion_propia_documentada`, `test_tls_entre_nodos_es_solo_1_3` |
| **Norma** | OWASP ASVS 5.0 V11.3.2, V11.4.1, V12.1.1 (4.0 V6.2.2, V9.1.3); NIST SSDF PW.7 |

## Fallo 6 · El vencimiento de los certificados TLS no se comprobaba

| | |
|---|---|
| **Qué pasaba** | Los certificados de los relays se generan con 90 días de vigencia, pero un certificado vencido seguía funcionando: la vigencia era decorativa. |
| **Qué lo provocaba** | Como la confianza viene del *pinning* de la huella, el contexto TLS no valida la cadena, y por lo tanto OpenSSL **tampoco revisa las fechas**. Nadie más las revisaba. |
| **Cómo se resolvió** | Nueva función `transporte.verificar_vigencia`: el cliente rechaza un certificado vencido o todavía no válido justo después de comprobar la huella, y el relay se niega a arrancar con su propio certificado vencido, indicando cómo regenerarlo. Nuevo error `CertificadoVencido`. |
| **Prueba** | `test_certificado_vigente_se_acepta`, `test_certificado_vencido_o_futuro_se_rechaza` |
| **Norma** | OWASP ASVS 5.0 V12.3.4 y V11.1.1 (ciclo de vida de las claves) |

## Fallo 7 · Se aceptaban claves guardadas con scrypt más débil

| | |
|---|---|
| **Qué pasaba** | Las claves se generan con scrypt N=2¹⁷ (recomendación de OWASP), pero al cargarlas se aceptaba desde N=2¹⁴. Un archivo de clave creado con 2¹⁴ es unas 8 veces más rápido de atacar por fuerza bruta y se habría aceptado sin aviso. |
| **Qué lo provocaba** | El mínimo se había bajado a 2¹⁴ para que las pruebas automáticas corrieran rápido, y ese mismo valor quedó como mínimo del programa. |
| **Cómo se resolvió** | El mínimo aceptado (`almacen_claves.minimo_aceptado`) es ahora 2¹⁷ en uso normal. Solo `tests/conftest.py` lo baja a 2¹⁴ mientras corren las pruebas. |
| **Prueba** | `test_en_uso_normal_no_se_acepta_scrypt_debil`, `test_claves_en_disco_usan_kdf_lenta` |
| **Norma** | OWASP ASVS 5.0 V11.4.4 (4.0 V6.2); OWASP Password Storage Cheat Sheet |

## Fallo 8 · La contraseña de las claves solo exigía largo

| | |
|---|---|
| **Qué pasaba** | Se aceptaban `aaaaaaaaaaaa`, `123456789012` o `contraseña2026`. Si alguien roba los archivos de `claves`, esa contraseña es lo único que protege las claves privadas, y un diccionario las prueba en segundos. |
| **Qué lo provocaba** | La única regla era "mínimo 12 caracteres". |
| **Cómo se resolvió** | Nueva función `almacen_claves.motivo_contrasena_debil`, aplicada al crear claves (en `admin.py` y en `guardar_privada`). Rechaza contraseñas comunes, con menos de 5 caracteres distintos, palabras comunes seguidas de números o símbolos (`Password1234!`) y secuencias del teclado. Usa una lista local, sin internet. Las frases largas como "mi red cebolla 2026" se aceptan. |
| **Prueba** | `test_contrasenas_debiles_se_rechazan`, `test_frases_largas_se_aceptan` |
| **Norma** | OWASP ASVS 5.0 V6.2.4 (comprobar contra contraseñas comunes) |

# 4. SAST y secretos

## Fallo 9 · No había revisión de secretos y las claves se suben a OneDrive

| | |
|---|---|
| **Qué pasaba** | El proyecto no tenía ninguna revisión automática de secretos: una clave API, una contraseña o una clave privada sin cifrar podían terminar en el repositorio sin que nadie lo notara. Además, la carpeta del proyecto está en **OneDrive**, así que las claves privadas (cifradas) se sincronizan con la nube de Microsoft. |
| **Qué lo provocaba** | El análisis de seguridad solo cubría código peligroso (Bandit), no secretos; y nada advertía sobre la ubicación de la carpeta `claves`. |
| **Cómo se resolvió** | Nuevo `revisar_secretos.py`: ejecuta detect-secrets sobre los archivos que irían al repositorio (respetando `.gitignore`), comprueba que `.gitignore` excluya `claves/` y `*.key`, que toda clave privada esté en el contenedor cifrado y que no haya ninguna clave PEM sin cifrar. Nunca muestra el secreto, solo archivo, línea y tipo. Se agregó a `revision_completa.py` y a `requirements-dev.txt`. Se probó plantando una clave API, una contraseña y una clave sin cifrar en una copia: detectó las tres. **OneDrive queda mitigado, no resuelto:** la revisión y `preparar-laboratorio` avisan, y el equipo debe mover `claves` a una carpeta local (`panel.py --carpeta RUTA`). **Actualización 03-11-2026 (T1):** nueva variable `MINIONI_CLAVES` (`almacen_claves.carpeta_claves`), que usan la herramienta de administración, los relays, el panel y la revisión de secretos; rechaza rutas relativas, archivos y carpetas sincronizadas sin mostrar la ruta; `python minioni_admin.py donde-estan-las-claves` muestra dónde están. **Estado: mitigado, pendiente de que el equipo regenere las claves fuera de OneDrive** (pasos en `COMANDOS.txt`); se marcará resuelto cuando lo haga. |
| **Prueba** | `test_revision_de_secretos_limpia`, `…detecta_token_en_el_codigo`, `…detecta_clave_sin_cifrar`, `…exige_gitignore`, `test_detecta_carpetas_que_suben_a_la_nube`; `tests/test_carpeta_claves.py` |
| **Norma** | NIST SSDF PS.1.1; OWASP ASVS 5.0 V13.3.1 |

## Fallo 10 · Secretos en el historial de Git y archivos de diagnóstico sueltos

| | |
|---|---|
| **Qué pasaba** | `revisar_secretos.py` revisa los archivos actuales: un secreto que llegue a un commit y luego se borre seguiría en el historial de Git, y la revisión no lo vería. Además, `errores.txt` (una salida de diagnóstico con la lista de paquetes del equipo) estaba en la raíz y no estaba excluido del repositorio. |
| **Qué lo provocaba** | La revisión solo corría a mano, no antes de cada commit; y `.gitignore` no contemplaba las salidas de diagnóstico guardadas con `> errores.txt`. |
| **Cómo se resolvió** | Nuevo hook `hooks/pre-commit`, que ejecuta `revisar_secretos.py` y **cancela el commit** si encuentra algo, para que nada entre al historial; se activa con `git config core.hooksPath hooks` al crear el repositorio, y la revisión lo recuerda. `errores.txt` y `pytest.txt` se agregaron a `.gitignore`. **Resuelto el 03-11-2026 (T3):** `revisar_secretos.py` tiene un paso 6 que revisa con detect-secrets las líneas agregadas en todos los commits (`git log --all -p`) y reporta cualquier archivo que `.gitignore` excluye pero se commiteó (un `.key`); muestra commit, archivo y tipo, nunca el secreto, y pide rotarlo. El repositorio se creó con el hook activo (T4). |
| **Prueba** | `test_salidas_de_diagnostico_no_van_al_repositorio_y_hay_hook`; `tests/test_revisiones_clase3.py` |
| **Norma** | NIST SSDF PS.1.1 y PW.7 |

## Fallo 11 · Un carácter Unicode oculto en el código que Bandit no vio

| | |
|---|---|
| **Qué pasaba** | `tests/test_codificacion_segura.py:256` contenía un carácter Unicode de inversión de texto (U+202E) real, no su secuencia de escape `\u202e`. Esos caracteres hacen que el código se vea en pantalla distinto de lo que ejecuta (ataque "Trojan Source", CVE-2021-42574). Se coló al escribir la prueba de `texto_seguro`. |
| **Qué lo provocaba** | Bandit sí detecta este ataque (regla B613), pero `pyproject.toml` excluye `tests/` del análisis, para no llenar el reporte con los `assert` de pytest. Ese punto ciego dejaba sin revisar 2 260 líneas. Se encontró al **ampliar** el SAST a las pruebas para la investigación. |
| **Cómo se resolvió** | Se reemplazó el carácter por su secuencia de escape. Nueva regla `test_ningun_archivo_contiene_caracteres_bidi_ocultos`, que revisa **todos** los `.py`, incluidas las pruebas; se comprobó que falla si se planta el carácter en `capas.py`. Bandit ampliado a las pruebas ya no reporta ningún hallazgo real. Desde el 03-11-2026 (T2) ese análisis de las pruebas es un paso fijo de `revision_completa.py`. |
| **Prueba** | `test_ningun_archivo_contiene_caracteres_bidi_ocultos` |
| **Norma** | NIST SSDF PW.7.2 (revisar el código para encontrar vulnerabilidades) |

# Falsos positivos encontrados al probar (no son fallos del proyecto)

Al probar las herramientas aparecieron tres falsos positivos, que se documentan
porque muestran cómo se interpretó cada hallazgo, como pide el OVA:

1. `revisar_secretos.py` se detectaba a sí mismo, porque contiene las marcas que
   busca (el encabezado de una clave privada en formato PEM). Se resolvió armando esas marcas por partes.
2. La prueba del escáner contenía un token de API falso escrito completo, que el
   escáner marcó como real. Se resolvió generándolo en tiempo de ejecución.
3. detect-secrets marcó una línea de la documentación de la Clase 3. Se revisó y se
   marcó con el comentario estándar `pragma: allowlist secret`.

Bandit reporta 2 hallazgos suprimidos (B404 y B603, uso de `subprocess` en
`revision_completa.py`). Son falsos positivos según los criterios del OVA: la lista
de comandos es fija, no viene de un usuario y no usa shell. Están justificados en la
misma línea con `# nosec`. Desde el 03-11-2026 son 5: se suman B404, B603 y B607 en
`revisar_secretos.py`, que ejecuta `git log` para revisar el historial (lista fija de
argumentos, sin shell; `git` se busca en el `PATH` porque cada equipo lo instala en
otra ruta).

# Pendiente para la Clase 4

1. Regenerar las claves fuera de OneDrive con `MINIONI_CLAVES` (fallo 9; pasos en
   `COMANDOS.txt`, sección "Claves fuera de OneDrive"), borrar la carpeta `claves`
   vieja y vaciar la papelera de OneDrive.
2. ~~Crear el repositorio Git y activar el hook~~ (hecho el 03-11-2026).
3. ~~Ejecutar `pip-audit -r requirements.txt` con internet~~ (hecho el 03-11-2026:
   sin vulnerabilidades).
4. Revisar los certificados con `python minioni_admin.py revisar-certificados` y
   renovarlos con `renovar-certificado` antes de que venzan (ver
   `docs/ROTACION_CLAVES.md`).

El PDF `docs/MiniOni - Fallos y correcciones Clase 3.pdf` corresponde a la versión
anterior a esta actualización: en este equipo no hay una herramienta para
regenerarlo (pandoc), así que la versión vigente es este archivo.
