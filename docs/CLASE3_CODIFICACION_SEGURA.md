# Clase 3 · Codificación segura: investigación de controles

Investigación hecha sobre el código real de MiniOni el 03-11-2026. Las líneas
citadas corresponden a esa versión. Se usa la numeración de **OWASP ASVS 5.0**;
entre paréntesis va el equivalente de ASVS 4.0, que es el que cita el OVA
(V5 → 5.0 V2, V6 → 5.0 V11, V7 → 5.0 V16, V9 → 5.0 V12).

Resultado: los cuatro controles estaban implementados, y la investigación
encontró **11 fallos reales** (2 de validación, 2 de errores y logging, 4 de
cifrado y 3 de SAST y secretos). Diez se corrigieron y uno quedó mitigado, todos con
pruebas en `tests/test_codificacion_segura.py`. El detalle de cada fallo (qué
pasaba, qué lo provocaba y cómo se resolvió) está en
[CLASE3_FALLOS_Y_CORRECCIONES.md](CLASE3_FALLOS_Y_CORRECCIONES.md).

## Investigación 01 · Hallazgos de controles en el código

| # | Control | Norma / requisito | Archivo / línea | Hallazgo de la investigación |
|---|---|---|---|---|
| 1 | Validación de entradas de red (lista blanca) | ASVS 5.0 V2.2.1 (4.0 V5.1.3) | `minioni/celdas.py:86` `decodificar_celda`, `:185` `validar_host`, `:204` `validar_puerto`; `minioni/socks5.py:144` `negociar`; `minioni/politica_salida.py:44` `validar_politica` | **Correcto.** Validación positiva en los 9 parsers: tamaño exacto, valores de una lista permitida y nada sobrante; lo demás se rechaza y se cierra la conexión. Fuzzing con ≈105 000 entradas aleatorias y 5 000 secuencias de la máquina de estados del relay, sin fallos inesperados. |
| 2 | Validación en el punto de entrada (línea de comandos) | ASVS 5.0 V2.2.1, V2.2.2 (4.0 V5.1.3) | `cliente_proxy.py:37` y `panel.py:527` → `minioni/proxy.py:463` `argumento_puerto` | **Fallo encontrado y corregido.** `python cliente_proxy.py --puerto 0` se aceptaba y el proxy escuchaba en un puerto al azar que el usuario no podía conocer (la consola nunca muestra puertos). Ahora el argumento solo acepta enteros de 1 a 65535 y se rechaza antes de arrancar. |
| 3 | Mensajes de error genéricos | ASVS 5.0 V16.5.1 (4.0 V7.4.1) | `minioni/errores.py:11` (`mensaje_publico` en cada error), `panel.py:510` `mensaje_error`, `minioni/relay.py:235` y `minioni/proxy.py:330` (manejador del bucle asyncio) | **Correcto.** El usuario solo ve frases como "conexión cerrada" o "directorio de nodos no válido"; DESTROY, END y SOCKS5 usan códigos genéricos. |
| 4 | Manejador de último recurso | ASVS 5.0 V16.5.4 | `minioni/consola.py:73` `instalar_manejador_global` (usado en `ejecutar_relay.py:101`, `cliente_proxy.py:73`, `cliente_prueba.py:82`, `minioni_admin.py:9`, `panel.py:549`); `panel.py:288` `error_inesperado` (`:540`) | **Fallo encontrado y corregido.** Una excepción no prevista fuera del bucle asyncio, o en un botón del panel (Tk), imprimía la traza completa con rutas y valores internos. Ahora solo se emite "error interno" del catálogo, también en hilos, y Ctrl+C cierra en silencio. |
| 5 | Logging sin datos sensibles | ASVS 5.0 V16.2.5, V16.4.1 (4.0 V7.1.1) | `minioni/consola.py:21` catálogo `EVENTOS`, `:53` `evento`; `minioni/sin_registros.py` | **Correcto, con una diferencia justificada.** La teoría del OVA manda el detalle a un log interno; MiniOni no tiene log interno a propósito, porque un registro de conexiones desharía el anonimato. La consola solo acepta códigos de un catálogo cerrado (imposible imprimir IP, dominios o contraseñas) y el botón "Verificar sin registros" lo demuestra vigilando cada escritura en disco. |
| 6 | Cifrado en tránsito | ASVS 5.0 V12.1.1, V12.3.4 (4.0 V9.1.3, V9.2.1) | `minioni/transporte.py:36-37` (solo TLS 1.3), `:86` `CERT_NONE`, `:90` `verificar_huella` (llamada en `:185`) | **Correcto, con un punto de atención.** `CERT_NONE` equivale a `verify=False` si no hay nada más; aquí la confianza la da el *pinning* de la huella del directorio firmado, que se verifica antes de enviar la primera celda. Bandit **no** marcó esta línea (falso negativo), así que se agregó una regla automática que solo permite `CERT_NONE` en los dos lugares auditados. |
| 7 | Algoritmos y cifrado en reposo | ASVS 5.0 V11.3.3, V11.4.1, V11.4.4 (4.0 V6.2.1, V6.2.2) | `minioni/capas.py:46` (ChaCha20-Poly1305), `minioni/handshake.py:101` (X25519 + HKDF), `minioni/almacen_claves.py:36` (scrypt N=2¹⁷) | **Correcto.** Sin MD5, SHA-1, ECB, `random` ni `verify=False` en todo el código. Las claves privadas se guardan con scrypt (función lenta recomendada por OWASP, equivalente a Argon2/bcrypt/PBKDF2 del OVA). Nueva prueba `test_sin_algoritmos_ni_configuraciones_debiles` que falla si alguien los agrega. |
| 8 | Secretos fuera del código y del repositorio | NIST SSDF PS.1.1; ASVS 5.0 V13.3.1 | `.gitignore:2` (`claves/`, `*.key`); `revisar_secretos.py`; `minioni/almacen_claves.py:130` `carpeta_sincronizada`; `minioni/admin.py:49` (`getpass`) | **Faltaba un escáner y había una exposición.** No había revisión automática de secretos: se agregó `revisar_secretos.py` (detect-secrets + claves cifradas + `.gitignore`). Además, el proyecto está en **OneDrive**, así que las claves privadas (cifradas) se suben a la nube: ahora se avisa y se recomienda moverlas a una carpeta local. | <!-- pragma: allowlist secret -->

## Investigación 02 · Análisis estático y secretos

**Herramienta SAST usada:** Bandit (Python), versión 1.9.4. Como complemento:
detect-secrets 1.5.0 para secretos y reglas propias en
`tests/test_codificacion_segura.py` para lo que Bandit no ve.

**Total de hallazgos:**
- Código del programa (configuración del proyecto, 4 332 líneas): **0**, más 2
  suprimidos con `# nosec` justificado.
- Análisis ampliado a las pruebas (6 592 líneas): **225** (219 B101, 3 B105, 2 B104
  y 1 B613). Solo **1 era real** (B613) y se corrigió; los otros 224 son falsos
  positivos esperables en código de pruebas.

**Hallazgos relevantes y cómo los interpretamos** (criterios del OVA: ¿el dato viene
de un usuario?, ¿hay validación en el camino?, ¿el *sink* lo interpreta?):

1. **B613 · Trojan Source · `tests/test_codificacion_segura.py:256` · REAL.** La
   prueba de `texto_seguro` contenía un carácter Unicode de inversión de texto
   (U+202E) real, en vez de su secuencia de escape. Esos caracteres hacen que el
   código se vea distinto de lo que ejecuta (CVE-2021-42574). Se coló al escribir la
   prueba y Bandit no lo vio porque `pyproject.toml` excluye `tests/`. Se encontró
   ampliando el análisis. **Corrección:** se reemplazó por `\u202e`, y la nueva prueba
   `test_ningun_archivo_contiene_caracteres_bidi_ocultos` revisa todos los archivos,
   incluidas las pruebas (se comprobó que falla si se planta el carácter en `capas.py`).
2. **B404 y B603 · `subprocess` · `revision_completa.py:9` y `:32` · falso positivo.**
   Severidad baja, confianza alta. Los comandos son una lista fija del propio
   proyecto, no vienen de un usuario y no pasan por una shell (`shell=False`): el
   *sink* no interpreta nada. Están suprimidos con `# nosec` y el motivo en la línea.
3. **B105 · contraseña escrita en el código · `tests/test_admin.py:14`,
   `tests/test_claves_salida_consola.py:15`, `tests/test_red.py:38` · falso positivo.**
   Son contraseñas de laboratorio que solo cifran claves temporales dentro de las
   pruebas. Las claves reales usan una contraseña pedida con `getpass` que nunca se
   escribe en ningún archivo.
4. **B104 · escuchar en todas las interfaces (`0.0.0.0`) ·
   `tests/test_claves_salida_consola.py:70`, `tests/test_salida_proxy.py:372` · falso
   positivo.** Ahí `0.0.0.0` aparece justamente para comprobar que se **rechaza**: el
   proxy no escucha fuera de `127.0.0.1` y la política de salida bloquea esa dirección.
5. **B101 · `assert` · 219 en `tests/` · esperado.** pytest funciona con `assert`;
   por eso la carpeta se excluye del análisis normal.
6. **Falso negativo · `ssl.CERT_NONE` en `minioni/transporte.py:88`.** Bandit no lo
   marcó. La revisión manual confirmó que es seguro, porque la confianza la da la
   verificación de la huella del certificado antes de enviar la primera celda. Como
   el SAST no lo distingue, se agregó una regla propia que solo permite `CERT_NONE` en
   los dos lugares revisados y falla si aparece MD5, SHA-1, `verify=False`, TLS viejo,
   `random`, `pickle` o ECB.

**Desde el 03-11-2026 (tarea T2) las pruebas también pasan por Bandit** en cada
`revision_completa.py`, con `bandit -q -r tests -s B101,B104,B105`. Solo se omiten
esas tres reglas, por los motivos de los puntos 3 a 5: **B101**, pytest verifica con
`assert`; **B104**, `0.0.0.0` aparece en pruebas que comprueban que se rechaza;
**B105**, contraseñas de laboratorio que solo existen dentro de las pruebas. En
`tests/` no se acepta ninguna marca `nosec` (lo comprueba una prueba). Se verificó
que el paso falla (B613) si se planta un U+202E real en una copia temporal de
`tests/`; la copia se borró después. Con la revisión del historial de Git (T3), el
programa pasa de 2 a 5 hallazgos suprimidos con motivo: se suman B404, B603 y B607 en
`revisar_secretos.py` (ejecuta `git log` con argumentos fijos y sin shell).

**Conclusión:** el SAST no es una bala de plata. El único hallazgo real apareció al
**ampliar** el alcance, y la debilidad más delicada (`CERT_NONE`) la vio la revisión
manual y no la herramienta. Por eso se combinan Bandit, reglas propias y revisión manual.

**¿Revisaron que no haya secretos en el repositorio?** Sí, no encontramos secretos.

**Detalle de la revisión de secretos:**
`python revisar_secretos.py` revisó con detect-secrets los 62 archivos que irían al
repositorio (respetando `.gitignore`): **0 secretos**. En los archivos excluidos
encontró 22 cadenas de alta entropía, todas esperadas: 8 en las 7 claves privadas de
`claves/`, que están **cifradas** con scrypt + ChaCha20-Poly1305 y excluidas por
`.gitignore`, y 14 en `config/` (claves públicas, huellas y firmas del directorio, que
son datos públicos). No hay ninguna clave privada PEM sin cifrar. Las contraseñas se
piden con `getpass` y nunca se escriben en código, archivos ni consola.

Para comprobar que el escáner funciona, se plantó en una copia del proyecto una clave
API falsa, una contraseña y una clave privada sin cifrar: detectó las tres, mostrando
solo archivo, línea y tipo, nunca el secreto.

Puntos de atención:
- La carpeta del proyecto está en **OneDrive**, así que `claves/` se sincroniza con la
  nube. Van cifradas, pero se moverán a una carpeta local; mientras tanto, la revisión
  y `preparar-laboratorio` lo advierten.
- Todavía no hay repositorio Git. La revisión ve los archivos actuales, no el
  historial: un secreto que llegue a un commit quedaría ahí aunque se borre después.
  Por eso se creó `hooks/pre-commit`, que ejecuta la revisión y **cancela el commit**
  si encuentra algo; se activa con `git config core.hooksPath hooks`.
- `errores.txt`, una salida de diagnóstico con la lista de paquetes del equipo,
  estaba en la raíz y no estaba excluida: se agregó a `.gitignore`, junto con
  `pytest.txt`.
- Al probar aparecieron tres falsos positivos propios: el escáner detectaba sus
  propias marcas de búsqueda, la prueba contenía un token falso completo y una línea
  de esta documentación. Las dos primeras se resolvieron armando esas cadenas por
  partes; la tercera se marcó con el comentario estándar `pragma: allowlist secret`.

## Investigación 03 · Conclusiones

**¿Qué controles encontraron implementados y cuáles faltan?**
Los cuatro estaban implementados desde las clases anteriores: validación positiva
con fuzzing, errores genéricos y consola sin datos sensibles, cifrado estándar
(TLS 1.3 con pinning, ChaCha20-Poly1305, scrypt) y Bandit en 0. La investigación
encontró 11 huecos y corrigió 10 con pruebas: validación (puerto 0 en la línea de
comandos; validadores que aceptaban un salto de línea final), errores y logging
(trazas visibles sin manejador de último recurso; inyección en la consola con el
apodo), cifrado (sin regla contra algoritmos débiles; vencimiento de certificados sin
comprobar; scrypt débil aceptado al cargar; contraseñas comunes aceptadas) y SAST y secretos
(sin escáner de secretos; historial de Git y archivos de diagnóstico sin proteger; un
carácter Unicode oculto en una prueba que Bandit no vio por excluir `tests/`).
Queda mitigada, pero no resuelta, la exposición de las claves cifradas en OneDrive.

**¿Qué corregirán antes de la Clase 4?**
1. Mover la carpeta `claves/` fuera de OneDrive y regenerar las claves, porque ya pasaron
   por la nube (detalle en `docs/TRASPASO_CLASE3_CLAUDE_CODE.md`, tarea T1).
2. Crear el repositorio Git y activar el hook de secretos (`git config core.hooksPath
   hooks`), para que `revisar_secretos.py` se ejecute antes de cada commit.
3. Ejecutar `pip-audit` con internet para revisar vulnerabilidades conocidas en las
   dependencias (SSDF PW.4).
4. Documentar la rotación de claves y certificados (ASVS 5.0 V13.3.4): los certificados
   TLS vencen hacia el 25 de enero de 2027.
5. Mantener en verde `python revision_completa.py` (pruebas, Bandit y secretos) como
   condición antes de cada entrega.

**Fuentes consultadas:** OWASP ASVS 4.0.3 (V5, V6, V7, V9); OWASP ASVS 5.0 (V2, V11,
V12, V13.3, V16) para la equivalencia con la versión actual; NIST SP 800-218 SSDF (PS.1,
PW.4, PW.7, PW.9); ISO/IEC 27033 (protección de las comunicaciones entre nodos);
documentación oficial de Bandit (incluida la regla B613), detect-secrets, pytest,
Hypothesis y la librería `cryptography`; OWASP Cheat Sheets de Logging, Error Handling,
Password Storage y Secrets Management; CVE-2021-42574 (Trojan Source).

## Evidencia sugerida (fotos)

| # | Qué capturar | Comando o archivo |
|---|---|---|
| 1 | Validación con lista blanca | `minioni/celdas.py` líneas 187-215 (`validar_host`, `validar_puerto`) |
| 2 | Fallo corregido: puerto 0 rechazado | `python cliente_proxy.py --puerto 0` |
| 3 | Inyección en consola bloqueada | `python ejecutar_relay.py --apodo "x;rm"` → "apodo inválido" |
| 4 | Manejador de último recurso y `texto_seguro` | `minioni/consola.py` líneas 79-111 |
| 5 | TLS 1.3, huella y vigencia | `minioni/transporte.py` líneas 38-39 y 92-120 |
| 6 | Reporte SAST | `bandit -c pyproject.toml -r .` |
| 7 | Revisión de secretos | `python revisar_secretos.py` (muestra el aviso de OneDrive) |
| 8 | Pruebas de los 4 controles | `python -m pytest tests/test_codificacion_segura.py -v` |
| opcional | Todo en verde | `python revision_completa.py` (resumen final) |
