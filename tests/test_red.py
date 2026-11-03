"""Pruebas de red de la semana 2: 3 relays reales con TLS 1.3 en 127.0.0.1.

Los 3 relays corren en el mismo proceso, en puertos libres elegidos al azar,
con un ConfigRelay de tiempos cortos. Sin pytest-asyncio: cada prueba llama
asyncio.run(...).

Normas: ASVS V12.1.1 (solo TLS 1.3), V12.3.4 (pinning), V2.4.1 (límites
anti-DoS), V16.5.3 (fallo cerrado), V16.2.5 (consola sin direcciones).
"""

import asyncio
import os
import socket
import ssl

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from minioni import admin, transporte
from minioni import almacen_claves as ak
from minioni import directorio as dirmod
from minioni.capas import cliente_envolver
from minioni.celdas import (
    Celda,
    Comando,
    ComandoRelay,
    MensajeRelay,
    codificar_extend,
    codificar_relay,
    decodificar_carga_fija,
)
from minioni.circuito import CircuitoCliente
from minioni.constantes import TAM_CELDA
from minioni.errores import CircuitoCerrado, EnlaceCerrado, TLSInvalido
from minioni.handshake import TAM_RESPUESTA, HandshakeCliente
from minioni.relay import ConfigRelay, cargar_relay

PASS = "contraseña de laboratorio"
APODOS = ("entrada1", "medio1", "salida1")
CONFIG_CORTA = dict(timeout_handshake=3, inactividad_max=30, vida_max=60, intervalo_limpieza=0.2)


@pytest.fixture(scope="module")
def laboratorio(tmp_path_factory):
    """Claves de los 3 relays (se generan una vez por módulo) y una autoridad."""
    claves = tmp_path_factory.mktemp("red") / "claves"
    for apodo in APODOS:
        admin.generar_relay(apodo, PASS, claves, ak.N_SCRYPT_MINIMO)
    return claves, Ed25519PrivateKey.generate()


def _puerto_libre() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Red:
    """3 relays en 127.0.0.1 con un directorio firmado que apunta a puertos libres."""

    def __init__(self, laboratorio, **config):
        self.claves, self._autoridad = laboratorio
        self.lista = [{"apodo": a, "host": "127.0.0.1", "puerto": _puerto_libre(), "salida": a == "salida1"}
                      for a in APODOS]
        self.d = self.directorio()
        cfg = ConfigRelay(**{**CONFIG_CORTA, **config})
        self.nodos = {a: cargar_relay(a, self.d, self.claves, PASS, cfg) for a in APODOS}

    def directorio(self, alterar=None) -> dirmod.Directorio:
        doc = admin.armar_directorio(self.lista, self.claves, 1, 7)
        if alterar is not None:
            alterar(doc)
        firmado = dirmod.firmar(doc, self._autoridad)
        return dirmod.verificar(firmado, self._autoridad.public_key().public_bytes_raw())

    @property
    def puertos(self) -> list[int]:
        return [r["puerto"] for r in self.lista]

    def relay(self, apodo: str, d=None):
        return next(r for r in (d or self.d).relays if r.apodo == apodo)

    def ruta(self, d=None):
        return [self.relay(a, d) for a in APODOS]

    async def circuito(self, saltos: int = 3) -> CircuitoCliente:
        c = CircuitoCliente(timeout=3)
        await c.construir(self.d, self.ruta()[:saltos])
        return c

    async def __aenter__(self):
        for nodo in self.nodos.values():
            await nodo.iniciar()
        return self

    async def __aexit__(self, *exc):
        for nodo in self.nodos.values():
            await nodo.detener()


async def esperar(condicion, timeout: float = 5.0) -> None:
    fin = asyncio.get_running_loop().time() + timeout
    while not condicion():
        if asyncio.get_running_loop().time() > fin:
            raise AssertionError("la condición no se cumplió a tiempo")
        await asyncio.sleep(0.02)


async def eco(c: CircuitoCliente, datos: bytes) -> bytes:
    await c.enviar(MensajeRelay(ComandoRelay.ECO, 0, datos))
    msg = await asyncio.wait_for(c.recibir(), 5)
    assert msg.comando == ComandoRelay.ECO
    return msg.datos


def _todas_vacias(red: Red) -> bool:
    return all(n.tablas_vacias() for n in red.nodos.values())


# 1 --------------------------------------------------------------------------------

def test_circuito_de_3_saltos_y_eco(laboratorio):
    async def escenario():
        async with Red(laboratorio) as red:
            c = await red.circuito()
            assert c.saltos == 3
            assert await eco(c, b"hola MiniOni") == b"hola MiniOni"
            datos = os.urandom(448)   # máximo por celda
            assert await eco(c, datos) == datos
            await c.cerrar()
    asyncio.run(escenario())


# 2 --------------------------------------------------------------------------------

def test_20_circuitos_seguidos_y_cerrados_dejan_tablas_vacias(laboratorio):
    async def escenario():
        async with Red(laboratorio) as red:
            for i in range(20):
                c = await red.circuito()
                assert await eco(c, f"circuito {i}".encode()) == f"circuito {i}".encode()
                await c.cerrar()
                await esperar(lambda: not red.nodos["entrada1"]._conexiones_ip)
            await esperar(lambda: _todas_vacias(red))
    asyncio.run(escenario())


def test_limite_de_circuitos_por_enlace_responde_destroy_4(laboratorio):
    # Entre entrada y medio hay UN enlace del pool: ahí se nota el límite por enlace.
    async def escenario():
        async with Red(laboratorio, max_circuitos_por_conexion=2) as red:
            vivos = [await red.circuito(), await red.circuito()]
            with pytest.raises(CircuitoCerrado) as e:
                await red.circuito()
            assert e.value.motivo == 4
            for c in vivos:
                assert await eco(c, b"siguen") == b"siguen"
                await c.cerrar()
            await esperar(lambda: _todas_vacias(red))
    asyncio.run(escenario())


# 3 --------------------------------------------------------------------------------

def test_huella_tls_distinta_rechaza_sin_enviar_celdas(laboratorio, monkeypatch):
    async def escenario():
        async with Red(laboratorio) as red:
            def alterar(doc):
                doc["relays"][0]["huella_tls"] = "0" * 64
            d_malo = red.directorio(alterar)
            enviadas = []
            original = transporte.Enlace.enviar

            async def espia(self, celda):
                enviadas.append(celda)
                await original(self, celda)

            monkeypatch.setattr(transporte.Enlace, "enviar", espia)
            c = CircuitoCliente(timeout=3)
            with pytest.raises(TLSInvalido):
                await c.construir(d_malo, red.ruta(d_malo))
            assert enviadas == []
            assert red.nodos["entrada1"].circuitos_activos == 0
    asyncio.run(escenario())


# 4 --------------------------------------------------------------------------------

def test_cliente_con_tls_1_2_es_rechazado(laboratorio):
    async def escenario():
        async with Red(laboratorio) as red:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
            with pytest.raises((TLSInvalido, EnlaceCerrado)):
                enlace = await transporte.conectar(red.relay("entrada1"), ctx, 3)
                await enlace.leer_celda()
            # Control: con TLS 1.3 el mismo relay sí atiende.
            c = await red.circuito()
            assert await eco(c, b"ok") == b"ok"
            await c.cerrar()
    asyncio.run(escenario())


# 5 y 6 ----------------------------------------------------------------------------

def test_extend_fuera_del_directorio_recibe_destroy(laboratorio):
    async def escenario():
        async with Red(laboratorio) as red:
            c = await red.circuito(saltos=1)
            datos = codificar_extend("127.0.0.1", _puerto_libre(), red.relay("medio1").clave_cebolla,
                                     os.urandom(32))
            await c.enviar(MensajeRelay(ComandoRelay.EXTEND, 0, datos))
            with pytest.raises(CircuitoCerrado) as e:
                await asyncio.wait_for(c.recibir(), 5)
            assert e.value.motivo == 1
            await esperar(lambda: _todas_vacias(red))
    asyncio.run(escenario())


def test_extend_con_clave_que_no_corresponde_recibe_destroy(laboratorio):
    async def escenario():
        async with Red(laboratorio) as red:
            c = await red.circuito(saltos=1)
            medio = red.relay("medio1")
            datos = codificar_extend(medio.host, medio.puerto, red.relay("salida1").clave_cebolla, os.urandom(32))
            await c.enviar(MensajeRelay(ComandoRelay.EXTEND, 0, datos))
            with pytest.raises(CircuitoCerrado) as e:
                await asyncio.wait_for(c.recibir(), 5)
            assert e.value.motivo == 1
            assert red.nodos["medio1"].circuitos_activos == 0
    asyncio.run(escenario())


# 7 --------------------------------------------------------------------------------

def test_bit_alterado_destruye_el_circuito_y_el_relay_sigue(laboratorio):
    async def escenario():
        async with Red(laboratorio) as red:
            c = await red.circuito()
            carga = bytearray(cliente_envolver(c._capas, codificar_relay(MensajeRelay(ComandoRelay.ECO, 0, b"x"))))
            carga[40] ^= 0x01
            await c.enlace.enviar(Celda(c.circ_id, Comando.RELAY, bytes(carga)))
            with pytest.raises(CircuitoCerrado) as e:
                await asyncio.wait_for(c.recibir(), 5)
            assert e.value.motivo == 1
            await esperar(lambda: _todas_vacias(red))
            nuevo = await red.circuito()
            assert await eco(nuevo, b"sigo vivo") == b"sigo vivo"
            await nuevo.cerrar()
    asyncio.run(escenario())


# 8 --------------------------------------------------------------------------------

def test_bytes_aleatorios_cierran_el_enlace_y_luego_todo_funciona(laboratorio):
    async def escenario():
        async with Red(laboratorio) as red:
            enlace = await transporte.conectar(red.relay("entrada1"), timeout=3)
            basura = bytearray(os.urandom(TAM_CELDA))
            basura[4] = 0xFF                      # comando inexistente: nunca decodifica
            enlace._writer.write(bytes(basura))
            with pytest.raises(EnlaceCerrado):
                await asyncio.wait_for(enlace.leer_celda(), 5)
            c = await red.circuito()
            assert await eco(c, b"de nuevo") == b"de nuevo"
            await c.cerrar()
    asyncio.run(escenario())


# 9 --------------------------------------------------------------------------------

async def _crear_en_enlace(relay) -> transporte.Enlace:
    enlace = await transporte.conectar(relay, timeout=3)
    estado, solicitud = HandshakeCliente.iniciar(relay.clave_cebolla)
    await enlace.enviar(Celda(1, Comando.CREATE, solicitud))
    celda = await asyncio.wait_for(enlace.leer_celda(), 5)
    assert celda.comando == Comando.CREATED
    estado.finalizar(decodificar_carga_fija(celda.carga, TAM_RESPUESTA))
    return enlace


def test_conexiones_por_ip_sobre_el_limite_se_cierran(laboratorio):
    async def escenario():
        async with Red(laboratorio, max_conexiones_por_ip=3) as red:
            entrada = red.relay("entrada1")
            abiertos = [await _crear_en_enlace(entrada) for _ in range(3)]
            with pytest.raises((EnlaceCerrado, TLSInvalido)):
                extra = await transporte.conectar(entrada, timeout=3)
                estado, solicitud = HandshakeCliente.iniciar(entrada.clave_cebolla)
                await extra.enviar(Celda(1, Comando.CREATE, solicitud))
                await asyncio.wait_for(extra.leer_celda(), 5)
            assert red.nodos["entrada1"].circuitos_activos == 3
            for e in abiertos:
                e.cerrar()
            await esperar(lambda: red.nodos["entrada1"].circuitos_activos == 0)
            await esperar(lambda: not red.nodos["entrada1"]._conexiones_ip)
            c = await red.circuito()
            assert await eco(c, b"libre") == b"libre"
            await c.cerrar()
    asyncio.run(escenario())


# 10 -------------------------------------------------------------------------------

def test_inactividad_destruye_el_circuito_con_motivo_2(laboratorio):
    async def escenario():
        async with Red(laboratorio, inactividad_max=1) as red:
            c = await red.circuito()
            with pytest.raises(CircuitoCerrado) as e:
                await asyncio.wait_for(c.recibir(), 5)
            assert e.value.motivo == 2
            await esperar(lambda: _todas_vacias(red))
    asyncio.run(escenario())


# 11 -------------------------------------------------------------------------------

def test_caida_del_relay_intermedio_destruye_el_circuito(laboratorio):
    async def escenario():
        async with Red(laboratorio) as red:
            c = await red.circuito()
            await red.nodos["medio1"].detener(limpio=False)
            with pytest.raises(CircuitoCerrado):
                await asyncio.wait_for(c.recibir(), 5)
            await esperar(lambda: red.nodos["entrada1"].tablas_vacias() and red.nodos["salida1"].tablas_vacias())
            # Sin el intermedio no hay circuito posible, y el cliente no tiene plan B.
            with pytest.raises((CircuitoCerrado, EnlaceCerrado)):
                await red.circuito()
    asyncio.run(escenario())


# 12 -------------------------------------------------------------------------------

def test_celdas_que_llegan_de_a_pocos_bytes_se_reensamblan(laboratorio):
    async def escenario():
        async with Red(laboratorio) as red:
            entrada = red.relay("entrada1")
            enlace = await transporte.conectar(entrada, timeout=3)
            estado, solicitud = HandshakeCliente.iniciar(entrada.clave_cebolla)
            datos = Celda(77, Comando.CREATE, solicitud).codificar()
            for i in range(0, len(datos), 7):
                enlace._writer.write(datos[i:i + 7])
                await enlace._writer.drain()
                await asyncio.sleep(0.002)
            celda = await asyncio.wait_for(enlace.leer_celda(), 5)
            assert celda.circ_id == 77 and celda.comando == Comando.CREATED
            estado.finalizar(decodificar_carga_fija(celda.carga, TAM_RESPUESTA))
            enlace.cerrar()
    asyncio.run(escenario())


# 13 -------------------------------------------------------------------------------

def test_la_consola_no_muestra_direcciones_ni_puertos(laboratorio, capfd):
    async def escenario():
        async with Red(laboratorio) as red:
            c = await red.circuito()
            puertos_cliente = [c.enlace.puerto_local()]
            await eco(c, b"privado")
            await c.cerrar()
            malo = await red.circuito(saltos=1)          # provoca CELDA_RECHAZADA y DESTROY
            puertos_cliente.append(malo.enlace.puerto_local())
            await malo.enviar(MensajeRelay(ComandoRelay.BEGIN, 1, b"\x0bexample.com\x01\xbb"))
            with pytest.raises(CircuitoCerrado):
                await asyncio.wait_for(malo.recibir(), 5)
            return red.puertos + puertos_cliente
    puertos = asyncio.run(escenario())
    salida = "".join(capfd.readouterr())
    assert "nodo iniciado" in salida and "celda rechazada" in salida
    assert "127.0.0.1" not in salida and "privado" not in salida and "example" not in salida
    for p in puertos:
        assert str(p) not in salida
