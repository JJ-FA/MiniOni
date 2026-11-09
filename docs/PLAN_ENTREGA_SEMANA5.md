---
title: "MiniOni – Plan de entrega final (semana 5)"
subtitle: "Qué debe tener la aplicación, cómo se demuestra y qué se entrega"
date: "8 de noviembre de 2026 · Equipo Onion"
---

# 0. Para qué sirve este documento

La semana 5 es la entrega del proyecto. Este documento define **cómo tiene que estar
MiniOni ese día**:

- qué debe hacer la aplicación;
- con qué evidencia se demuestra cada cosa;
- qué falta construir (la captura con Wireshark);
- cómo se arma el informe final y la presentación;
- qué contiene el paquete que se entrega.

Sirve como lista de verificación para el equipo y como especificación para Claude Code
(tareas S5-T1 a S5-T8). Las reglas 1 a 32 de los traspasos anteriores siguen vigentes
(`docs/TRASPASO_CLASE3_CLAUDE_CODE.md` y `docs/TRASPASO_SEMANA4_CLAUDE_CODE.md`).

**En una frase:** el día de la entrega, una persona que no conoce el proyecto debe
poder ver en 15 minutos que Firefox navega por un circuito de 3 relays en redes
separadas, que nadie en el camino ve a la vez quién navega y adónde, que el tráfico
entre nodos es ilegible en Wireshark, que si algo falla no se sale directo y que no
queda ningún registro.

# 1. Qué es MiniOni (para la portada del informe)

MiniOni es una red de enrutamiento cebolla (*onion routing*) de laboratorio, inspirada
en Tor y escrita en Python:

- El navegador se conecta a un proxy SOCKS5 local.
- El tráfico viaja cifrado en 3 capas por tres relays (entrada, intermedio y salida).
- Cada relay quita una capa y solo conoce a sus vecinos: la entrada conoce al usuario
  pero no el destino, y la salida conoce el destino pero no al usuario.
- Los relays se publican en un directorio firmado con Ed25519.
- Entre nodos todo va por TLS 1.3 con verificación de la huella.
- El sistema no guarda ningún registro de lo que se navega.

**Alcance:** laboratorio académico en una red local o en Docker. **No** es un
reemplazo de Tor ni está pensado para Internet pública (`docs/LIMITES.md`).

# 2. Qué debe tener la aplicación el día de la entrega

## 2.1 Funcionalidad obligatoria

| # | Función | Cómo se demuestra | Estado al 08-11-2026 |
|---|---|---|---|
| F1 | Circuito de 3 saltos con cifrado por capas | `python demo_capas.py`; `python cliente_prueba.py` (eco) | ✅ |
| F2 | Navegación con Firefox por el proxy SOCKS5 `127.0.0.1:9050` | Firefox → página por MiniOni (`docs/NAVEGADOR.md`) | ✅ local · ⏳ Docker en Windows |
| F3 | Directorio firmado y rechazo de un directorio alterado | `python minioni_admin.py simular-ataque` | ✅ |
| F4 | Fallo cerrado: sin circuito no hay navegación | Apagar o pausar un relay → Firefox falla, nunca sale directo | ✅ |
| F5 | Política de salida (solo 80 y 443 hacia IP públicas) | Puerto 22 o IP interna bloqueados (`probar`) | ✅ |
| F6 | Sin registros, demostrable | Botón "Verificar sin registros" del panel; `docker logs` vacío | ✅ |
| F7 | Laboratorio Docker con redes segmentadas | `python laboratorio_docker.py probar` → matriz y *Todo correcto* | ✅ Linux · ⏳ Windows (S4-T1) |
| F8 | El destino no ve al usuario | `http://web/` muestra 10.10.9.11 | ✅ |
| F9 | Tráfico entre nodos ilegible en Wireshark | Captura entrada → medio: solo TLS 1.3, sin dominios ni contenido | ⏳ **S5-T1** |
| F10 | Panel gráfico para la demostración | `python panel.py` | ✅ local · opcional Docker (S4-T4) |

## 2.2 Requisitos de seguridad del proyecto (Clase 1) y su evidencia final

| Req. | Qué exige | Evidencia que debe estar en el informe | Norma |
|---|---|---|---|
| R1 | Validación positiva de toda entrada | Fuzzing (≈105 000 entradas), `fullmatch`, pruebas de los parsers | ASVS 5.0 V2.2.1 · SSDF PW.8.2 |
| R2 | Cifrado autenticado por capa y en tránsito | ChaCha20-Poly1305 por capa, TLS 1.3, captura de Wireshark (S5-T1) | ASVS 5.0 V11.3.3, V12.1.1 |
| R3 | Firmas e intercambio de claves | Directorio Ed25519 con anti-rollback, handshake X25519 tipo ntor, `simular-ataque` | ASVS 5.0 V11.6.1, V11.6.2 |
| R4 | Fallo seguro y errores genéricos | Fallo cerrado (`probar`), mensajes genéricos, manejador de último recurso | ASVS 5.0 V16.5.1, V16.5.3, V16.5.4 |
| R5 | Modelado de amenazas y componentes seguros | STRIDE actualizado (S5-T4), `pip-audit`, versiones fijas, imagen por digest | SSDF PW.1.1, PW.4.1 |
| Seg. | Segmentación de red | Matriz de alcance de `probar` y `docker network inspect` | ISO/IEC 27033 |
| Priv. | Sin registros | "Verificar sin registros", `logging: none`, consola de catálogo cerrado | ASVS 5.0 V16.2.5 |

## 2.3 Calidad que debe cumplir el código entregado

- [ ] `python -m pytest`: 0 fallos **en Windows** (anotar el número exacto).
- [ ] `bandit -c pyproject.toml -r .` y `bandit -r tests -s B101,B104,B105`: 0 hallazgos.
- [ ] `python revisar_secretos.py`: "sin secretos expuestos" y sin aviso de OneDrive.
- [ ] `pip-audit -r requirements.txt`: sin vulnerabilidades (con fecha).
- [ ] `python revision_completa.py --con-docker --con-internet`: *Todo correcto*.
- [ ] Certificados vigentes el día de la entrega (`revisar-certificados`; hoy vencen
      hacia el 25-01-2027).
- [ ] Directorios (local y Docker) publicados **el día anterior** (valen 7 días).
- [ ] Ningún archivo de diagnóstico suelto (`errores.txt`, `pytest.txt`) en el paquete.

# 3. Lo que falta construir: tareas S5 para Claude Code

Se hacen en orden. Cada una lleva pruebas y documentación.

## S5-T1 · Captura de tráfico con Wireshark (evidencia de F9 y R2)

**Objetivo:** demostrar con capturas reales qué ve un observador en cada tramo.

| Tramo | Dónde se captura | Qué se debe ver | Qué NO se debe ver |
|---|---|---|---|
| Navegador → proxy | Windows, interfaz *Adapter for loopback traffic capture* (Npcap), puerto 9050 | SOCKS5 con el nombre `web` en claro | — (es local; está documentado en LIMITES #5) |
| Equipo → entrada | Loopback, puerto 9001 | TLS 1.3, registros de tamaño fijo | El nombre `web`, rutas, HTML |
| Entrada → medio | `red_entrada_medio` (contenedor de captura en la red de medio1) | TLS 1.3 entre 10.10.2.11 y 10.10.2.10 | Destino, contenido, la IP del cliente |
| Medio → salida | `red_medio_salida` | TLS 1.3 entre 10.10.3.11 y 10.10.3.10 | Ídem |
| Salida → web | `red_destinos` | HTTP en claro: `GET /` desde 10.10.9.11 | La IP del cliente (demuestra LIMITES #3: la salida ve el contenido si no hay HTTPS) |

**Qué construir:**

1. **`docker/Dockerfile.captura`:** `FROM` la misma base fijada por digest, con
   `tcpdump` instalado. Solo se usa durante la captura y no forma parte del laboratorio.
2. **`laboratorio_docker.py capturar --tramo {entrada-medio|medio-salida|salida-web} --segundos N`:**
   - Lanza `docker run --rm --network container:minioni-<nodo> --cap-drop ALL
     --cap-add NET_RAW --cap-add NET_ADMIN --read-only --log-driver none` con
     `tcpdump -i any -w /captura/<tramo>.pcap` durante N segundos, como máximo 120.
   - La carpeta `/captura` se monta desde `capturas_wireshark/` en el proyecto, que
     queda en `.gitignore`.
   - Mientras captura, genera tráfico de prueba propio (eco y `GET http://web/`), para
     que la captura solo contenga tráfico del laboratorio.
   - Al terminar imprime la ruta del `.pcap` y un resumen calculado con Python sobre el
     pcap (sin Wireshark): cantidad de paquetes, puertos y si aparece el texto `web`
     o `GET` en los datos.
3. **`docs/WIRESHARK.md`:** cómo abrir cada captura, qué filtros usar y qué capturas de
   pantalla tomar:
   - `tls`, `tcp.port == 9002`, `http`.
   - *Estadísticas → Longitudes de paquete*: los tamaños de los registros TLS se
     repiten, porque las celdas miden 512 bytes.
   - *Seguir flujo TCP*: solo texto cifrado.
   - *Editar → Buscar paquete → "web"*: sin resultados en los tramos internos.

**Reglas:** las capturas son evidencia, **no registros del sistema**. Solo se hacen a
pedido, solo con tráfico de prueba propio, no van a Git y se borran después de
entregar. La herramienta de captura es el único contenedor con `NET_RAW`; documentarlo
en `LIMITES.md` como excepción y en la trazabilidad.

**Pruebas:**

- El análisis del pcap con un archivo pcap pequeño de ejemplo generado en la prueba,
  sin Docker.
- `--segundos` fuera de rango se rechaza.
- `capturas_wireshark/` está en `.gitignore` y en `.dockerignore`.

**Criterio:** en los tramos entrada → medio y medio → salida, el resumen dice que no
aparecen `web` ni `GET`; en salida → web sí aparecen.

**Normas:** ASVS 5.0 V12.1.1 (TLS 1.3), ISO/IEC 27033, R2.

## S5-T2 · Prueba de "instalación desde cero" (reproducibilidad)

En una carpeta nueva, fuera de OneDrive, seguir **solo** el README:

1. `git clone` (o descomprimir el paquete de entrega).
2. Crear el `.venv` y ejecutar `pip install -r requirements.txt -r requirements-dev.txt`.
3. `preparar-laboratorio` con `MINIONI_CLAVES` en otra carpeta.
4. Pruebas, laboratorio local, laboratorio Docker y Firefox.

Corregir en el README cada paso que falte o confunda.

**Criterio:** alguien del grupo que no programó la parte la levanta sin ayuda.

## S5-T3 · Limpieza final del repositorio

- `git status` limpio; ningún archivo generado ni de diagnóstico versionado.
- Revisar que `docs/` no tenga documentos contradictorios. Los planes viejos
  (`PLAN_SEMANAS_2_3.md` y los traspasos) se mueven a `docs/historial/` con una línea
  que explique que son documentos de trabajo.
- `README.md`: tabla del plan con las 5 semanas en ✅, sección "Demostración en 15
  minutos" (sección 5 de este documento) y enlaces vigentes.
- Etiqueta final: `git tag -a v1.0 -m "Entrega final MiniOni"`, con el equipo presente.

## S5-T4 · STRIDE y trazabilidad finales

- Actualizar el modelo STRIDE de la Clase 1 con lo que cambió:
  - **S:** directorio firmado y pinning.
  - **T:** AEAD por capa.
  - **R:** firma de la autoridad.
  - **I:** sin registros, segmentación, DNS remoto.
  - **D:** límites anti-DoS y límites de los contenedores.
  - **E:** política de salida, contenedores sin privilegios, marca de entrada.
  - Para cada amenaza: el control, el archivo y la prueba.
- `docs/TRAZABILIDAD.md`: todo en ✅ con fecha, más una columna o nota "verificado en
  Windows el DD-MM-2026".

## S5-T5 · Informe final (documento de entrega)

Ver la sección 4. Claude Code puede generar el **borrador** a partir de los documentos
de `docs/`, pero las conclusiones y la reflexión del equipo las escribe el equipo.

## S5-T6 · Guion y ensayo de la demostración

Ver la sección 5. Agregar `python laboratorio_docker.py demo`, que hace en orden
`estado`, `probar` y muestra los comandos siguientes en pantalla, para que la
presentación no dependa de recordarlos.

## S5-T7 · Paquete de entrega

Ver la sección 6. Script `empaquetar_entrega.py`:

- Usa `git archive v1.0` para empaquetar.
- Agrega los PDF del informe y las capturas `.pcap` seleccionadas.
- Verifica que dentro del zip **no** haya `claves/`, `.key`, `.venv/`, `.git/` ni
  `directorio.docker.json`, y que `revisar_secretos.py` pase sobre el contenido
  descomprimido.

Prueba automática de esa verificación.

## S5-T8 · Revisión cruzada

Un agente o una persona que no hizo el trabajo revisa el paquete final contra la lista
de la sección 7 antes de entregarlo, para que el trabajo no se califique a sí mismo.

# 4. Estructura del informe final

El curso pide un informe por clase y, al final, un documento integrado. Estructura
sugerida (25 a 40 páginas más anexos):

1. **Portada:** MiniOni, Equipo Onion (Juan José Figueroa Ayala, Juan David Ramos
   Rangel), curso, fecha.
2. **Resumen** (media página): qué es, qué se logró y los resultados clave (la matriz
   de segmentación, *Todo correcto*, cero registros).
3. **Problema y motivación:** privacidad al navegar; por qué el modelo cebolla (idea de
   la Clase 1).
4. **Requisitos:** los 5 normativos (R1 a R5) y los de seguridad, con su norma.
5. **Modelo de amenazas STRIDE** (versión final, S5-T4).
6. **Arquitectura:** componentes, diagrama, protocolo (celdas de 512 bytes, capas,
   handshake, directorio) y decisiones de diseño (`ARQUITECTURA.md`, `PROTOCOLO.md`).
7. **Implementación por semanas:**
   - Semana 1: núcleo criptográfico y directorio.
   - Semana 2: relays con TLS 1.3.
   - Semana 3: salida, SOCKS5, navegador y panel.
   - Semana 4: Docker y segmentación.
   - Semana 5: Wireshark y cierre.
8. **Codificación segura (Clase 3):** los 4 controles, los 11 fallos encontrados y
   corregidos, SAST y secretos (`CLASE3_*.md`).
9. **Pruebas y resultados:**
   - Número de pruebas y fuzzing.
   - Bandit, `revisar_secretos` y `pip-audit`.
   - Matriz de segmentación.
   - Fallo cerrado.
   - Capturas de Wireshark con explicación.
   - "Verificar sin registros".
10. **Cumplimiento normativo:** tabla de trazabilidad resumida (ISO/IEC 27033, NIST
    SP 800-218 SSDF, OWASP ASVS).
11. **Límites conocidos** (`LIMITES.md`): qué NO protege MiniOni. Es parte de la
    seguridad, no una debilidad.
12. **Conclusiones y trabajo futuro:** escritas por el equipo. Trabajo futuro: más
    relays, control de flujo tipo SENDME, criptografía poscuántica, servicios
    `.onion`.
13. **Anexos:** comandos (`COMANDOS.txt`), capturas de pantalla, enlace o hash del
    paquete de entrega.

**Formato:** documento con las capturas de pantalla integradas. Cada afirmación de
seguridad lleva su evidencia (captura o salida de comando) y su norma. Se exporta a PDF
para la entrega.

# 5. Guion de la demostración (15 minutos)

Preparar la noche anterior: Docker Desktop abierto, `preparar` ejecutado, certificados
vigentes, Firefox con el proxy configurado en un perfil aparte y Wireshark con las
capturas ya abiertas por si falla la red.

| Min. | Qué se muestra | Comando o acción | Qué decir |
|---|---|---|---|
| 0-2 | Idea y arquitectura | Diagrama de `SEMANA4_DOCKER.md` | Tres saltos y redes separadas: nadie ve quién navega y adónde a la vez |
| 2-4 | Cebolla | `python demo_capas.py` | Cada relay quita solo su capa (ChaCha20-Poly1305) |
| 4-6 | Laboratorio | `python laboratorio_docker.py iniciar` y `estado` | Sin root, solo lectura, sin capacidades, registros "none" |
| 6-8 | Segmentación | `python laboratorio_docker.py probar` | Desde cada red solo se alcanza el siguiente nodo (ISO/IEC 27033) |
| 8-10 | Navegación | Proxy con `--entrada-via` y Firefox → `http://web/` | El destino ve 10.10.9.11, no mi equipo |
| 10-12 | Wireshark | Captura entrada → medio frente a salida → web | Dentro de la red solo hay TLS 1.3 de tamaño fijo; solo la salida ve HTTP |
| 12-13 | Fallo cerrado | `docker pause minioni-medio1` → Firefox falla → `unpause` | Si algo cae, no se sale directo |
| 13-14 | Ataque al directorio | `python minioni_admin.py simular-ataque` | La firma Ed25519 detecta el cambio |
| 14-15 | Sin registros | `docker logs minioni-salida1`; panel → "Verificar sin registros" | No queda nada que pueda delatar al usuario |

**Plan B:** si Docker falla en vivo, usar el modo local (`panel.py`) y mostrar las
salidas guardadas de `probar` y las capturas `.pcap` ya hechas.

# 6. Paquete de entrega

```
MiniOni_entrega_v1.0.zip
├── codigo/                      git archive v1.0 (sin claves, .venv ni .git)
├── informe/
│   ├── MiniOni - Informe final.pdf
│   └── informes de clase (Clase 1, 2, 3, ...) exportados de los OVA
├── evidencia/
│   ├── capturas de pantalla (PNG) numeradas como en el informe
│   ├── wireshark/*.pcap         solo tráfico de prueba del laboratorio
│   └── salidas/                 probar.txt, estado.txt, pytest.txt, bandit.txt, pip-audit.txt
└── LEEME.txt                    cómo levantarlo en 5 pasos y versión de Python y Docker usadas
```

**Nunca** dentro del paquete: `claves/` ni ningún `.key`, contraseñas,
`directorio.docker.json` (se genera con `preparar`), `.venv/` ni historial de Git. El
script de S5-T7 lo verifica.

# 7. Lista de verificación del día de la entrega

**Una semana antes**

- [ ] Semana 4 cerrada (criterios de `TRASPASO_SEMANA4_CLAUDE_CODE.md`).
- [ ] S5-T1 a S5-T4 hechas.
- [ ] Borrador del informe completo; el equipo escribe las conclusiones.

**Dos días antes**

- [ ] Prueba desde cero (S5-T2) superada.
- [ ] Ensayo completo de la demostración, cronometrado.
- [ ] `git tag v1.0` y paquete generado (S5-T7); revisión cruzada (S5-T8).

**El día anterior**

- [ ] `python minioni_admin.py revisar-certificados`: ninguno vence en los próximos 15 días.
- [ ] Publicar los directorios: local (`publicar-directorio`) y Docker (`laboratorio_docker.py preparar`).
- [ ] `python revision_completa.py --con-docker --con-internet`: *Todo correcto*. Guardar la salida en `evidencia/salidas/`.
- [ ] Imagen de Docker ya descargada y construida (sin depender de la red del salón).

**El día de la entrega**

- [ ] Docker Desktop abierto, `iniciar` hecho antes de presentar.
- [ ] Firefox con un perfil solo para la demostración (proxy 127.0.0.1:9050, sin historial).
- [ ] Al terminar: `laboratorio_docker.py detener`; borrar las capturas `.pcap` que no se entregan.

# 8. Normas que debe citar la entrega

| Norma | Dónde se cumple en MiniOni |
|---|---|
| **ISO/IEC 27033** (seguridad de redes) | Segmentación en 4 redes, un servicio alcanzable por red, TLS 1.3 entre nodos, solo la entrada publicada en loopback |
| **NIST SP 800-218 SSDF** | PW.1.1 (STRIDE), PW.4.1 (versiones fijas, imagen por digest, `pip-audit`), PW.7.2 (Bandit en código y pruebas), PW.8.2 (pruebas y fuzzing), PS.1.1 (secretos fuera del código, del historial y de la imagen) |
| **OWASP ASVS 5.0** | V2 (validación), V11 (criptografía), V12 (comunicaciones seguras), V13.3 (secretos), V16 (errores y registros), con la equivalencia a ASVS 4.0 que usan los OVA (V5, V6, V9, V7) |
