# Rotación de claves y certificados

Cómo y cuándo cambiar cada clave de MiniOni sin dejar la red en un estado
inseguro (Clase 3, tarea T6 · OWASP ASVS 5.0 V11.1.1 y V12.3.4 · NIST SSDF PS.1.1).

Regla general: **una clave que pudo quedar expuesta no se mueve, se regenera**.
Copiar el archivo a otro lugar no borra las copias que ya existen (en la nube,
en la papelera o en el historial de Git).

## Cuándo rotar

| Situación | Qué se rota | Urgencia |
|---|---|---|
| El certificado TLS de un relay vence en 15 días o menos (el relay muestra `certificado TLS próximo a vencer (N)` al arrancar; `revisar-certificados` lo lista) | Certificado TLS de ese relay | Antes de que venza: vencido, el relay no arranca y los clientes lo rechazan |
| Sospecha de que alguien copió la carpeta de claves o vio la contraseña | Todas las claves de esa carpeta | Inmediata |
| Las claves pasaron por la nube (por ejemplo, la carpeta `claves` dentro de OneDrive) | Todas: se regeneran en una carpeta local con `MINIONI_CLAVES` | Antes de la entrega (fallo 9 de la Clase 3) |
| Un secreto llegó a un commit (`revisar_secretos.py`, paso 6) | Ese secreto. Borrarlo del código no lo saca del historial | Inmediata |
| Se olvidó la contraseña de las claves | Todas (no se pueden abrir) | Cuando haga falta |

## 1. Certificado TLS de un relay

El certificado dura 90 días. Renovarlo **no cambia la clave cebolla**; solo
cambia la huella TLS, que está en el directorio firmado.

```powershell
python minioni_admin.py revisar-certificados              # días que le quedan a cada relay
python minioni_admin.py renovar-certificado --apodo salida1
python minioni_admin.py publicar-directorio --version N   # N lo indica el comando anterior
```

`renovar-certificado`:

1. Pide la contraseña y comprueba que abre el `tls.key` actual. Con una contraseña
   equivocada termina con error y **no toca ningún archivo**.
2. Genera una clave ECDSA P-256 nueva y un certificado autofirmado de 90 días, y los
   escribe primero en archivos temporales de la misma carpeta (`.tls.nuevo.key`,
   `.tls.nuevo.crt`).
3. Los pone en su lugar con `os.replace`, que es atómico dentro del mismo disco. La
   clave nueva queda cifrada con scrypt + ChaCha20-Poly1305 como las demás.
4. Muestra la huella nueva y el comando para publicar el directorio siguiente.

Hasta que se publique el directorio nuevo, el relay renovado **no arranca** (su
huella no coincide con la del directorio) y ningún cliente lo acepta: es el fallo
cerrado esperado.

## 2. Clave cebolla de un relay

La clave cebolla (X25519) identifica al relay en el handshake. Para cambiarla se
regenera el relay completo (clave cebolla y certificado):

```powershell
Remove-Item -Recurse "$env:MINIONI_CLAVES\medio1"     # o claves\medio1 si no usas la variable
python minioni_admin.py generar-relay --apodo medio1
python minioni_admin.py publicar-directorio --version N
```

`generar-relay` nunca sobrescribe claves existentes; por eso primero se borra la
carpeta de ese relay (y solo la de ese relay).

## 3. Clave de la autoridad del directorio

La autoridad firma el directorio; su clave pública (`config/autoridad.pub`) es la
raíz de confianza de todos los clientes. Cambiarla equivale a crear una red nueva:

```powershell
python minioni_admin.py preparar-laboratorio --reiniciar
```

Esto borra las claves y el directorio generados y crea todo de nuevo con una sola
contraseña. Después hay que **entregar el nuevo `config/autoridad.pub` a cada
cliente por un canal confiable** (ver `docs/LIMITES.md`). Solo se hace si la clave
de la autoridad pudo quedar expuesta o si el equipo lo decide; nunca de forma
automática.

## Publicar con la versión siguiente (anti-rollback)

Cada cliente guarda en `config/ultima_version` la versión más alta del directorio
que ya vio y **rechaza cualquier versión menor** (STRIDE T: un atacante no puede
reponer un directorio viejo con la huella antigua). Por eso, después de rotar
cualquier clave, el directorio se publica con una versión **mayor** que la última:

- `renovar-certificado` muestra el número que corresponde.
- `preparar-laboratorio` ya usa la siguiente a la que vio este equipo (antes
  publicaba siempre la 1, que un cliente que había visto la 2 rechazaba).

## Qué ve un cliente con el directorio viejo

| Situación | Resultado |
|---|---|
| Directorio viejo + relay con certificado renovado | La huella TLS no coincide: el cliente corta antes de enviar la primera celda (`transporte.verificar_huella`). El circuito falla y el proxy responde `05 01`; nunca sale directo. |
| Directorio nuevo publicado | El cliente lo acepta (versión mayor) y vuelve a construir circuitos. |
| Alguien repone el directorio viejo | Rechazado por anti-rollback (versión menor que `ultima_version`). |
| Relay sin renovar con certificado vencido | El relay no arranca (`verificar_identidad`), y un cliente que llegara a conectarse lo rechaza (`verificar_vigencia`). |

## Pruebas

`tests/test_rotacion.py`: `dias_restantes` con fechas fijas; el aviso sale con 15
días y no con 16; renovar cambia la huella y no la clave cebolla; una contraseña
equivocada no toca ningún archivo; un relay renovado con el directorio viejo se
rechaza y con el nuevo funciona; `revisar-certificados` termina con código 1 si hay
alguno vencido.
