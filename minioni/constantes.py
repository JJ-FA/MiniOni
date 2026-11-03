"""Constantes del protocolo MiniOni v1.

Todos los tamaños son fijos: un observador de la red ve siempre celdas
de 512 bytes, sin importar lo que transporten.
"""

PROTOCOLO_ID = b"MiniOni-v1"

# --- Celdas de enlace -------------------------------------------------------
TAM_CELDA = 512          # bytes en el cable, siempre
TAM_CIRC_ID = 4          # identificador de circuito (uint32, 0 reservado)
TAM_COMANDO = 1
TAM_CARGA = TAM_CELDA - TAM_CIRC_ID - TAM_COMANDO   # 507 bytes

# --- Capas de cifrado ---------------------------------------------------------
TAM_PREFIJO_LONGITUD = 2   # uint16 con la longitud del texto cifrado
TAM_ETIQUETA = 16          # etiqueta Poly1305
SOBRECOSTO_CAPA = TAM_PREFIJO_LONGITUD + TAM_ETIQUETA   # 18 bytes por capa
MAX_SALTOS = 3

# Texto plano de una celda RELAY: siempre el mismo tamaño, sin importar
# en qué salto termine. 507 - 3*18 = 453 bytes.
TAM_RELAY_PLANO = TAM_CARGA - MAX_SALTOS * SOBRECOSTO_CAPA
TAM_CABECERA_RELAY = 5     # comando(1) + stream_id(2) + longitud(2)
MAX_DATOS_RELAY = TAM_RELAY_PLANO - TAM_CABECERA_RELAY   # 448 bytes útiles

# --- Claves --------------------------------------------------------------------
TAM_CLAVE_PUBLICA = 32     # X25519 y Ed25519
TAM_CLAVE_SIMETRICA = 32   # ChaCha20-Poly1305 (256 bits)
TAM_FIRMA = 64             # Ed25519

# --- Límites operativos (ASVS V2.4.1) -------------------------------------
VIDA_MAX_CIRCUITO_S = 600         # 10 minutos
INACTIVIDAD_MAX_CIRCUITO_S = 60
TIMEOUT_HANDSHAKE_S = 10
MAX_CONEXIONES_POR_IP = 8
MAX_CIRCUITOS_POR_CONEXION = 16
MAX_CIRCUITOS_TOTALES = 256       # por relay
INTERVALO_LIMPIEZA_S = 5          # cada cuánto se revisan circuitos vencidos
MAX_CELDAS_DESCONOCIDAS = 8       # seguidas, para un circ_id desconocido, antes de cerrar el enlace
TIMEOUT_ENVIO_S = 30              # un par que no lee en este tiempo se desconecta

# --- Streams y nodo de salida (semana 3) -------------------------------------
MAX_STREAMS_POR_CIRCUITO = 32
TIMEOUT_DESTINO_S = 10            # resolver + conectar al destino desde la salida
TAM_COLA_DATOS = 128              # DATA en cola por circuito antes de dejar de leer del destino
MAX_COLA_CIRCUITO = 4 * TAM_COLA_DATOS   # tope duro: si se supera, se destruye el circuito

# --- Proxy SOCKS5 (semana 3) -----------------------------------------------------
HOST_PROXY = "127.0.0.1"          # único host permitido para escuchar
PUERTO_PROXY = 9050
TIMEOUT_SOCKS_S = 10              # saludo + solicitud SOCKS5
TIMEOUT_CONNECTED_S = 15          # espera de CONNECTED desde la salida
MAX_INTENTOS_CIRCUITO = 3         # construcciones seguidas antes de responder 05 01
MAX_CONEXIONES_SOCKS = 256        # conexiones simultáneas del navegador al proxy

# --- Directorio ---------------------------------------------------------------
TAM_MAX_DIRECTORIO = 64 * 1024    # bytes
MIN_RELAYS = 3
MAX_RELAYS = 64

# --- Validación de destinos -------------------------------------------------
MAX_LONGITUD_DOMINIO = 255
