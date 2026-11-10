# Límites conocidos de MiniOni

> Una herramienta madura declara qué NO protege. Los límites conocidos son
> parte de la seguridad, no una debilidad.

## Lo que MiniOni NO protege

1. **No es un navegador.** Se usa Firefox o LibreWolf configurado con el
   proxy. MiniOni no protege contra la huella digital del navegador
   (fingerprinting), cookies, ni contra lo que el usuario escriba en un sitio.
2. **Adversario global.** Quien observe a la vez la entrada y la salida
   puede correlacionar tiempos y volúmenes. MiniOni no agrega tráfico de
   cobertura ni retrasos.
3. **Nodo de salida.** Ve el destino y, si el sitio no usa HTTPS, también el
   contenido. Solo se permiten los puertos 80 y 443.
4. **Posición del salto.** La longitud de cada capa revela si un relay es
   entrada, intermedio o salida. Igual que en Tor, se considera aceptable:
   la posición no identifica al usuario.
5. **Tramo navegador → proxy.** Va sin cifrar por `127.0.0.1`. Nunca sale del
   equipo, pero un programa malicioso en ese mismo equipo podría leerlo.
6. **Pocos relays.** Con 3 nodos en laboratorio, todos los circuitos usan
   los mismos relays. El anonimato real exige muchos operadores independientes.
7. **No es compatible con Tor** ni ofrece servicios ocultos (`.onion`).
   No está pensado para Internet pública ni para producción.

## Decisiones de privacidad documentadas

- **Sin logs persistentes.** No se registran IP, destinos ni contenido.
  Solo se imprimen en consola eventos de un catálogo cerrado
  (`minioni/consola.py`). Se acepta perder trazabilidad forense a cambio de
  no crear un registro que desanonimice a los usuarios (ASVS V16, V16.2.5).
- **Claves en memoria.** Python no permite borrar con garantía la memoria de
  las claves de circuito; se descartan las referencias al cerrar, pero
  pueden quedar copias hasta que el recolector de basura las libere.

- **Panel gráfico.** El registro de la ventana muestra solo los eventos del
  catálogo de `consola.py` (vía `consola.suscribir`), en memoria y hasta 500
  líneas; no se guarda en disco. La contraseña se borra del campo en cuanto
  se usa y no se guarda; como cualquier cadena de Python puede quedar en
  memoria hasta que el recolector la libere. «Abrir por MiniOni» descarga
  como máximo 5 MB y no muestra el contenido, solo el código HTTP y el tamaño.

- **Alcance de «Verificar sin registros».** El audit hook ve todo lo que
  hace Python en el proceso de MiniOni (relays, proxy y panel), pero no lo
  que Windows hace por su cuenta: la caché DNS del sistema guarda el dominio
  (no la búsqueda) que resolvió el nodo de salida, y el archivo de
  paginación queda fuera de control. Se ignoran las escrituras de `.pyc`
  (caché de código de Python, sin datos del usuario). El testigo se muestra
  en pantalla para comprobarlo con `findstr`, pero no se guarda.

- **Certificados en las pruebas del panel.** Si OpenSSL no encuentra la raíz
  en el almacén de Windows, se usa el verificador de Windows, que puede
  descargar la raíz desde la lista oficial de Microsoft (lo mismo que pasa al
  abrir el sitio en Edge). No se comprueba revocación (CRL/OCSP), igual que
  en la verificación por defecto de Python. Cualquier otro rechazo
  (vencido, autofirmado, nombre distinto) se respeta y la prueba falla.

## Decisiones de la red (semana 2)

- **Un relay no autentica a quien se le conecta.** Clientes y relays entran
  igual por el mismo puerto TLS. Es necesario para no identificar al
  cliente, pero significa que cualquiera que alcance el puerto puede abrir
  circuitos. Lo contienen los límites: 8 conexiones simultáneas por IP, 16
  circuitos por enlace, 256 circuitos por relay y los tiempos máximos.
- **El límite por enlace también aplica entre relays.** Todos los circuitos
  que pasan de un relay a otro comparten un único enlace TLS, así que entre
  cada par de relays caben a lo sumo 16 circuitos simultáneos. Para un
  laboratorio basta (el proxy usa un circuito activo a la vez).
- **IP de origen en memoria.** Para aplicar el límite por IP, el relay
  cuenta las conexiones abiertas de cada IP. El dato vive solo en memoria y
  solo mientras la conexión está abierta; nunca se imprime ni se guarda.
- **TLS sin CA.** La confianza en el certificado de cada relay viene solo del
  directorio firmado (pinning de la huella). Si la autoridad publica una
  huella equivocada, el relay es inalcanzable (falla cerrado).

## Decisiones del nodo de salida y del proxy (semana 3)

- **DNS remoto obligatorio.** El proxy nunca resuelve nombres: el dominio
  viaja dentro del circuito y lo resuelve el nodo de salida. Por eso en
  Firefox hay que marcar "Usar proxy DNS cuando se use SOCKS v5"
  (`network.proxy.socks_remote_dns = true`); si no, el navegador consultaría
  el DNS local y el administrador de la red vería los dominios visitados.
  Ver [NAVEGADOR.md](NAVEGADOR.md).
- **WebRTC.** Puede abrir conexiones UDP fuera del proxy y revelar la IP real.
  MiniOni solo transporta TCP por SOCKS5 CONNECT; hay que desactivar WebRTC
  (`media.peerconnection.enabled = false`).
- **Huella del navegador (fingerprinting).** Fuentes, resolución, zona
  horaria, cookies y extensiones identifican al navegador aunque la IP
  cambie. MiniOni no lo protege; un navegador endurecido (LibreWolf, o el
  modo de resistencia al fingerprinting de Firefox) lo reduce.
- **Un solo computador no da anonimato real.** Con los 3 relays y el
  navegador en el mismo equipo, quien vea ese equipo ve todo. Es una
  demostración del mecanismo (capas, TLS, fallo cerrado), no anonimato.
- **Solo TCP y solo CONNECT.** No hay UDP (UDP ASSOCIATE) ni BIND: `05 07`.
  QUIC/HTTP3 no funciona; el navegador vuelve a HTTP/2 sobre TCP.
- **Política de salida.** Por defecto solo los puertos 80 y 443 hacia IP
  públicas (`config/politica_salida.json`, sin excepciones). Cada excepción
  que se agregue debe documentarse aquí. Las pruebas automáticas usan una
  excepción `127.0.0.0/8` y un puerto aleatorio **solo en la configuración de
  la prueba**, para alcanzar un servidor HTTP local; el archivo del
  repositorio no la tiene.
- **Sin control de flujo de extremo a extremo.** La salida deja de leer del
  destino cuando su cola por circuito llega a 128 celdas, pero no hay ventanas
  tipo SENDME como en Tor. Una subida muy grande de un destino lento puede
  frenar el enlace hasta 30 s; después se cierra ese stream.
- **Circuitos de vida limitada.** Los relays destruyen un circuito a los 60 s
  sin tráfico o a los 10 min de vida. Las conexiones abiertas en ese circuito
  se cortan (el navegador reintenta); el proxy construye otro en el siguiente
  pedido.
- **`config/ultima_version`.** Guarda solo el número de versión más alto del
  directorio visto por el proxy (anti-rollback); no es un dato del usuario.
  Si se borra, el proxy acepta de nuevo cualquier versión vigente.

## Decisiones del laboratorio Docker (semana 4)

- **La puerta sí puede llegar a Internet en Docker Desktop.** Docker no publica
  puertos de una red `internal: true`, y allí una red no interna sale a Internet aunque
  tenga el NAT desactivado. Por eso `docker/puerta.py` es el único contenedor en una
  red con salida (`red_publica`). No tiene claves, su destino es fijo y solo ve tráfico
  TLS cifrado. Los relays y la web siguen solo en redes internas, y la prueba de
  segmentación no conecta una sonda a `red_publica`, porque su resultado depende de
  la plataforma.
- **`--entrada-via` solo cambia la dirección del primer salto.** La identidad la
  sigue dando la huella TLS del directorio; además solo se acepta `127.x.x.x`.
- **La ruta ya no se elige al azar entre entrada y medio** cuando el directorio marca
  la entrada (como *Guard* en Tor): con 3 relays la ruta es siempre la misma. Con más
  relays por posición vuelve a haber elección al azar dentro de cada posición.
- **`/tmp` en memoria.** El relay escribe ahí la clave TLS un instante, cifrada con
  una contraseña aleatoria de un solo uso, porque `ssl` solo carga claves desde un
  archivo. Es un `tmpfs` privado (modo 0700, sin ejecución) que nunca toca un disco.
- **La contraseña viaja por `docker attach`.** Pasa por el cliente de Docker de tu
  equipo hacia la entrada estándar del relay; no se guarda en archivos, variables ni
  en la imagen. Quien controle Docker en tu equipo ya controla los contenedores, así
  que no es un permiso nuevo.
- **Sin registros, también para depurar.** Con `logging: none` no existe
  `docker logs`; para ver la consola se usa `laboratorio_docker.py eventos APODO`, que
  la muestra en vivo sin guardarla.
- **Subredes 10.10.x.** Si la red de tu universidad o tu casa usa esas mismas
  subredes, hay que cambiarlas en `docker-compose.yml` y `config/relays.json` (y
  volver a `preparar`).
- **En Linux** las claves deben poder leerse con el usuario 10001 del contenedor
  (en Windows con Docker Desktop no hace falta).
- **El digest de la imagen no se actualiza solo.** Fijarlo evita cambios sin aviso,
  pero los parches de `python:3.14-slim` solo llegan si alguien repite el procedimiento
  de `SEMANA4_DOCKER.md` 4.3.
- **El arranque solo muestra fases generales.** La terminal y el panel indican
  «Fase N de 4» y descartan la salida de Docker, para no exponer comandos ni nombres
  internos. La primera construcción puede tardar varios minutos en la misma fase.

## Captura de tráfico (semana 5)

- **Única excepción al endurecimiento.** `laboratorio_docker.py capturar` lanza el único
  contenedor con `NET_RAW` y `NET_ADMIN`, unido a la red de un nodo con
  `--network container:`. Sin esos permisos no se puede capturar. Corre como root dentro
  del contenedor, con el resto de capacidades eliminadas, disco de solo lectura, sin
  registros y durante 120 s como máximo. No forma parte del laboratorio: solo existe
  mientras dura la captura.
- **Las capturas contienen tráfico real del tramo.** Por eso solo se hacen a pedido y
  con tráfico de prueba, no van a Git y se borran después de entregar. Si durante una
  captura de `salida-web` alguien navegara, quedaría guardado.
- **`capturas_wireshark/` queda dentro del proyecto**, como pide el plan. Si el proyecto
  está en OneDrive, esos archivos se copian a la nube: solo contienen tráfico de prueba.
- **La versión de `tcpdump` no está fijada.** La imagen base sí va por digest, pero
  `apt` instala la versión vigente al construir. Es una herramienta de evidencia y no
  participa en el laboratorio.
- **El resumen automático busca frases, no palabras sueltas.** Una búsqueda de 3 bytes
  daría falsos positivos en texto cifrado (`docs/WIRESHARK.md`, sección 4).

## Limitaciones del entorno

- **OpenSSL que trae Python.** El TLS 1.3 entre nodos usa el OpenSSL incluido en
  Python (3.5.7 con Python 3.14.6), que pip-audit no revisa. CVE-2026-75803 lo
  alcanza sin camino explotable en MiniOni (ver `docs/CLASE3_NVD.md`); se corrige
  actualizando Python.
- **Verificación sin registros.** Los ganchos de auditoría de Python (PEP 578) no
  son una barrera de seguridad: CVE-2026-2297 muestra eventos que no se emiten (la
  lectura de `.pyc`). La verificación vigila escrituras, que sí se emiten, y además
  busca el testigo en los archivos.
- **Enlaces simbólicos.** `revisar_secretos.py` recorre las carpetas con `rglob`, que
  no entra en carpetas enlazadas: una clave dentro de una carpeta enlazada de la
  carpeta de claves no se revisaría (mismo tipo de fallo que CVE-2026-81690). No
  afecta a lo que va al repositorio, porque Git tampoco sigue enlaces.

- **Permisos en Windows.** `chmod 600` solo se aplica completo en Linux/macOS
  (o dentro de Docker). En Windows la protección de la carpeta de claves depende
  de los permisos de la carpeta del usuario.
- **Dónde viven las claves.** Por defecto en `claves/`, dentro del proyecto. Si el
  proyecto está en OneDrive (como en los equipos del grupo), las claves cifradas se
  copian a la nube. Con la variable `MINIONI_CLAVES` (ruta absoluta y local) todos
  los programas usan otra carpeta; una ruta relativa, un archivo o una carpeta
  sincronizada se rechazan. MiniOni no puede borrar las copias que ya subieron:
  por eso las claves que pasaron por la nube se **regeneran**, no se mueven, y el
  equipo vacía la papelera de OneDrive (ver `COMANDOS.txt` y `docs/ROTACION_CLAVES.md`).
  `panel.py --carpeta RUTA` sigue usando `RUTA/claves` sin mirar la variable.
- **Historial de Git.** `revisar_secretos.py` (paso 6) encuentra un secreto que
  ya está en un commit, pero no lo borra: reescribir el historial no alcanza si
  alguien ya lo clonó. La única respuesta segura es rotar ese secreto. El paso
  necesita `git` en el `PATH` (se busca ahí a propósito, cada equipo lo instala en
  otra ruta); sin git o sin repositorio solo avisa.
- **Certificados de 90 días.** La renovación es manual (`renovar-certificado`). El
  relay avisa al arrancar cuando quedan 15 días o menos, pero si nadie lo renueva
  el relay deja de arrancar al vencer y los clientes lo rechazan (fallo cerrado).
  Tras renovar hay que publicar el directorio con la versión siguiente.
- **Distribución de la clave de la autoridad.** `config/autoridad.pub` debe
  llegar a los clientes por un canal confiable. Si un atacante la reemplaza,
  puede firmar su propio directorio.
- **Modo laboratorio.** La política de salida permite excepciones explícitas
  (por ejemplo, el servidor web del laboratorio). Cada excepción debe
  documentarse aquí.
