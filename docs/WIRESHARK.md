# Captura de tráfico con Wireshark (semana 5)

Evidencia de que un observador de la red no puede leer lo que viaja entre los nodos
(F9 y R2 del plan de entrega). Normas: ASVS 5.0 V12.1.1, ISO/IEC 27033.

## 1. Reglas

- Las capturas son **evidencia, no registros del sistema**: solo se hacen a pedido y
  solo con tráfico de prueba propio.
- No van a Git (`capturas_wireshark/` está en `.gitignore` y `.dockerignore`) y se
  borran después de entregar.
- No captures mientras navegas por sitios reales: una captura de la salida guardaría
  esa navegación.
- La herramienta de captura es el único contenedor con `NET_RAW` y `NET_ADMIN`
  (excepción explicada en [LIMITES.md](LIMITES.md)).

## 2. Hacer las capturas

Con el laboratorio iniciado (`python laboratorio_docker.py iniciar`):

```powershell
python laboratorio_docker.py capturar --tramo entrada-medio --segundos 20
python laboratorio_docker.py capturar --tramo medio-salida --segundos 20
python laboratorio_docker.py capturar --tramo salida-web --segundos 20
```

La primera vez descarga `tcpdump` y necesita conexión a Internet. Cada comando genera
su propio tráfico de prueba (eco y `GET http://web/`), guarda
`capturas_wireshark/<tramo>.pcap` e imprime un resumen calculado sin Wireshark. Termina
con código 1 si el resultado no es el esperado.

## 3. Qué se debe ver en cada tramo

| Tramo | Dónde se captura | Qué se debe ver | Qué NO se debe ver |
|---|---|---|---|
| Navegador → proxy | Wireshark en Windows, interfaz *Adapter for loopback traffic capture*, filtro `tcp.port == 9050` | SOCKS5 con el nombre `web` en claro | Es local (LIMITES #5) |
| Equipo → entrada | La misma interfaz, filtro `tcp.port == 9001` | TLS 1.3, registros de tamaño fijo | `web`, rutas, HTML |
| Entrada → medio | `capturas_wireshark/entrada-medio.pcap` | TLS 1.3 entre 10.10.2.11 y 10.10.2.10 | Destino, contenido, IP del cliente |
| Medio → salida | `capturas_wireshark/medio-salida.pcap` | TLS 1.3 entre 10.10.3.11 y 10.10.3.10 | Ídem |
| Salida → web | `capturas_wireshark/salida-web.pcap` | HTTP en claro: `GET /` desde 10.10.9.11 | La IP del cliente. Muestra LIMITES #3: la salida ve el contenido si no hay HTTPS |

Los dos primeros tramos pasan por la interfaz de loopback de Windows, así que se
capturan a mano en Wireshark mientras navegas por `http://web/`.

## 4. Resultado medido en Windows (10-11-2026)

| Tramo | Paquetes | Registros TLS | Tamaño más repetido | «GET /» o «Host: web» | Criterio |
|---|---|---|---|---|---|
| entrada-medio | 38 | 23 | 534 bytes (22 veces) | no aparece | Cumple |
| medio-salida | 30 | 23 | 534 bytes (23 veces) | no aparece | Cumple |
| salida-web | 12 | 0 | sin tamaño fijo | aparece | Cumple |

Los 534 bytes son una celda dentro de un registro TLS 1.3: 512 de la celda, 1 del tipo
de contenido interno, 16 de la etiqueta de autenticación y 5 de la cabecera del registro.

**Por qué se buscan frases completas.** El plan pedía buscar `web` o `GET`. Una cadena
de 3 bytes puede aparecer por azar en texto cifrado, así que el resumen automático
busca `GET /` y `Host: web`. La búsqueda de `web` del punto 5 sí se hace a mano; un
resultado suelto dentro de datos cifrados se explica por ese azar.

## 5. Revisar cada captura en Wireshark

Abre el archivo con doble clic o con *Archivo → Abrir*.

| Qué hacer | En qué captura | Qué debe mostrar | Pantallazo para el informe |
|---|---|---|---|
| Filtro `tls` | entrada-medio | Solo *Application Data* de TLS 1.3 tras el saludo | Sí |
| Filtro `tcp.port == 9002` (o `9003`) | entrada-medio, medio-salida | Solo las IP de ese tramo | No |
| Filtro `http` | salida-web | La petición `GET /` y su respuesta | Sí |
| *Estadísticas → Longitudes de paquete* | entrada-medio | Un grupo dominante de tamaño fijo, por las celdas de 512 bytes | Sí |
| Clic derecho → *Seguir → Flujo TCP* | entrada-medio y salida-web | Bytes ilegibles en el primero; la página en claro en el segundo | Sí, los dos |
| *Editar → Buscar paquete*, tipo *Cadena*, `web` | entrada-medio y medio-salida | Sin resultados en los datos | Sí |

Guarda los pantallazos en `entrega/evidencia/` con el número de figura del informe.

## 6. Plan B

Si la red del salón o Docker fallan en vivo, abre los `.pcap` ya hechos: Wireshark no
necesita el laboratorio encendido.
