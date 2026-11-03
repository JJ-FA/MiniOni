"""Demostración de la semana 1: una celda atraviesa el circuito de 3 saltos.

Todo ocurre en memoria (todavía no hay red; eso es la semana 2). Sirve para
ver, paso a paso, qué conoce cada relay y comprobar que una celda alterada
se detecta.

    python demo_capas.py
"""

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from minioni import capas, celdas, handshake
from minioni.celdas import ComandoRelay, MensajeRelay
from minioni.errores import CeldaManipulada


def corto(b: bytes) -> str:
    return b[:12].hex() + "…"


def main() -> None:
    nombres = ["entrada", "intermedio", "salida"]
    claves_relay = [X25519PrivateKey.generate() for _ in nombres]

    # 1. Handshake con cada salto. En la red real el 2.º y el 3.º viajan
    #    dentro de celdas EXTEND a través de los saltos anteriores.
    capas_cliente, capas_relay = [], []
    for nombre, clave in zip(nombres, claves_relay):
        B = clave.public_key().public_bytes_raw()
        estado, solicitud = handshake.HandshakeCliente.iniciar(B)
        capa_r, respuesta = handshake.relay_responder(clave, solicitud)
        capas_cliente.append(estado.finalizar(respuesta))
        capas_relay.append(capa_r)
        print(f"[handshake] clave de 256 bits acordada con el relay de {nombre}")

    # 2. El cliente pide al nodo de salida conectarse a ejemplo.com:443.
    begin = MensajeRelay(ComandoRelay.BEGIN, 1, celdas.codificar_destino("ejemplo.com", 443))
    carga = capas.cliente_envolver(capas_cliente, celdas.codificar_relay(begin))
    print(f"\n[cliente]  envía 507 bytes cifrados en 3 capas: {corto(carga)}")

    # 3. Cada relay quita SOLO su capa.
    for i, nombre in enumerate(nombres):
        interior = capas.relay_pelar(capas_relay[i], carga)
        if i < 2:
            carga = capas.rellenar(interior)
            print(f"[{nombre:<10}] quita su capa; sigue cifrado, no ve el destino: {corto(carga)}")
        else:
            msg = celdas.decodificar_relay(interior)
            host, puerto = celdas.decodificar_begin(msg.datos)
            print(f"[{nombre:<10}] quita la última capa: {msg.comando.name} {host}:{puerto}"
                  " (no sabe quién lo pidió)")

    # 4. Respuesta de vuelta: el nodo de salida sella, los demás agregan su capa.
    respuesta = MensajeRelay(ComandoRelay.CONNECTED, 1, b"")
    carga = capas.relay_originar(capas_relay[2], celdas.codificar_relay(respuesta))
    carga = capas.relay_agregar_capa(capas_relay[1], carga)
    carga = capas.relay_agregar_capa(capas_relay[0], carga)
    msg = celdas.decodificar_relay(capas.cliente_pelar(capas_cliente, carga))
    print(f"\n[cliente]  recibe de vuelta: {msg.comando.name} en stream {msg.stream_id}")

    # 5. Manipulación: un atacante cambia un bit de una celda en tránsito.
    data = MensajeRelay(ComandoRelay.DATA, 1, b"GET / HTTP/1.1")
    carga = bytearray(capas.cliente_envolver(capas_cliente, celdas.codificar_relay(data)))
    carga[40] ^= 0x01
    try:
        capas.relay_pelar(capas_relay[0], bytes(carga))
    except CeldaManipulada as e:
        print(f"\n[entrada]  bit alterado detectado por Poly1305 -> {e.mensaje_publico}; se cierra el circuito")


if __name__ == "__main__":
    main()
