# Navegar a través de MiniOni

> Requisitos: los 3 relays corriendo y `python cliente_proxy.py` en otra
> ventana (orden de arranque en el [README](../README.md)). El proxy escucha
> solo en `127.0.0.1:9050`.

## 1. Prueba rápida sin navegador (curl de Windows)

```powershell
curl.exe --socks5-hostname 127.0.0.1:9050 https://example.com
```

Debe mostrar el HTML de la página. Usa **`--socks5-hostname`** (no
`--socks5`): así el nombre viaja dentro del circuito y lo resuelve el nodo de
salida. Con `--socks5` a secas, curl resolvería el nombre en tu equipo.

Si sale `curl: (97) ... (1)`, no hay circuito (¿los 3 relays están
corriendo? ¿hay internet en el nodo de salida?). Si sale `(2)`, el destino no
está permitido por la política de salida (solo puertos 80 y 443 hacia IP
públicas).

## 2. Firefox

1. **Ajustes → General → Configuración de red → Configuración…**
2. Elegir **Configuración manual del proxy**.
3. **Host SOCKS:** `127.0.0.1` · **Puerto:** `9050` · marcar **SOCKS v5**.
   Dejar vacíos los campos de proxy HTTP/HTTPS.
4. Marcar **"Usar proxy DNS cuando se use SOCKS v5"**.
5. Aceptar.

Luego, en la barra de direcciones, `about:config` (aceptar el aviso) y fijar:

| Preferencia | Valor | Por qué |
|---|---|---|
| `network.proxy.socks_remote_dns` | `true` | Todo el DNS se resuelve en el nodo de salida, nunca en tu equipo |
| `media.peerconnection.enabled` | `false` | WebRTC puede abrir conexiones UDP fuera del proxy y revelar tu IP real |

Recomendado para la demostración: usar un **perfil aparte** de Firefox
(`firefox.exe -P`) o LibreWolf, para no mezclar cookies ni sesiones
personales con el laboratorio.

## 3. Comprobar que funciona

- Abrir un sitio HTTPS (por ejemplo `https://example.com`). En las ventanas
  de los relays aparece `circuito creado`; en la del proxy, `circuito creado (1)`.
- Ninguna ventana muestra el dominio, la IP ni los puertos: es intencional.

## 4. Demostración de fallo cerrado

1. Con Firefox navegando, detener **medio1** con Ctrl+C.
2. Recargar la página: **falla** (Firefox muestra "El servidor proxy está
   rechazando las conexiones" o similar). MiniOni no sale directo a internet
   cuando el circuito no existe.
3. Volver a arrancar `python ejecutar_relay.py --apodo medio1` y recargar:
   vuelve a funcionar con un circuito nuevo.

## 5. Volver a la navegación normal

Ajustes → Configuración de red → **Sin proxy** (o "Usar la configuración del
proxy del sistema"). Las preferencias de `about:config` pueden quedarse.

## Límites

MiniOni no protege contra la huella del navegador, las cookies ni lo que
escribas en un sitio. En un solo computador no hay anonimato real: es una
demostración del mecanismo. Ver [LIMITES.md](LIMITES.md).
