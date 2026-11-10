# Modelo de amenazas STRIDE (versión final)

Actualiza el modelo de la Clase 1 con lo construido en las 5 semanas (NIST SSDF
PW.1.1, R5). Cada amenaza indica el control, el archivo y la prueba. Lo que queda sin
cubrir está en la última columna y en [LIMITES.md](LIMITES.md).

**Activos que se protegen:** la relación entre quién navega y adónde, el contenido en
tránsito, las claves privadas y la integridad de la lista de relays.

## S · Suplantación

| Amenaza | Control | Archivo | Prueba | Riesgo que queda |
|---|---|---|---|---|
| Un atacante publica una lista de relays falsa | Directorio firmado con Ed25519 | `minioni/directorio.py` | `test_firma_de_otra_autoridad_se_rechaza`, `test_relay_insertado_despues_de_firmar_se_detecta`, `test_simular_ataque_no_toca_el_original_y_la_copia_se_rechaza` | `config/autoridad.pub` debe llegar por un canal confiable |
| Un equipo se hace pasar por un relay en la red | Pinning de la huella TLS tomada del directorio | `minioni/transporte.py` | `test_huella_tls_distinta_rechaza_sin_enviar_celdas`, `test_entrada_via_hacia_otro_relay_se_rechaza_por_la_huella` | Ninguno conocido en el laboratorio |
| Un relay falso completa el intercambio de claves | Handshake X25519 ligado a la clave publicada | `minioni/handshake.py` | `test_relay_falso_no_puede_completar_handshake`, `test_respuesta_alterada_se_rechaza` | Ninguno conocido en el laboratorio |

## T · Manipulación

| Amenaza | Control | Archivo | Prueba | Riesgo que queda |
|---|---|---|---|---|
| Alterar una celda en el camino | ChaCha20-Poly1305 por capa | `minioni/capas.py`, `minioni/relay.py` | `test_bit_alterado_se_detecta`, `test_bit_alterado_destruye_el_circuito_y_el_relay_sigue` | Ninguno conocido |
| Repetir o reordenar celdas | Contador de mensajes por capa | `minioni/capas.py` | `test_celda_repetida_se_detecta`, `test_celdas_reordenadas_se_detectan` | Ninguno conocido |
| Reponer un directorio viejo con una clave ya rotada | Anti-rollback por directorio | `minioni/proxy.py`, `minioni/directorio.py` | `test_anti_rollback_rechaza_un_directorio_mas_viejo`, `test_cada_directorio_tiene_su_propio_anti_rollback` | Si se borra `config/ultima_version`, vuelve a aceptarse cualquier versión vigente |

## R · Repudio

| Amenaza | Control | Archivo | Prueba | Riesgo que queda |
|---|---|---|---|---|
| Negar quién publicó la lista de relays | Firma de la autoridad, con versión y vigencia | `minioni/directorio.py`, `minioni/admin.py` | `test_firma_de_otra_autoridad_se_rechaza` | Una sola autoridad |
| Negar la navegación de un usuario | **Aceptado por diseño:** no se registra nada, porque un registro desanonimizaría al usuario | `minioni/consola.py` | `test_consola_no_acepta_texto_libre` | Se pierde la trazabilidad forense (ASVS V16.2.5) |

## I · Divulgación de información

| Amenaza | Control | Archivo | Prueba | Riesgo que queda |
|---|---|---|---|---|
| Un observador lee el tráfico entre nodos | TLS 1.3 y capas; celdas de tamaño fijo | `minioni/transporte.py`, `minioni/celdas.py` | `test_cliente_con_tls_1_2_es_rechazado`; capturas reales en [WIRESHARK.md](WIRESHARK.md) | Correlación de tiempos (LIMITES #2) |
| Los registros delatan al usuario | Consola de catálogo cerrado; Docker sin registros | `minioni/consola.py`, `minioni/sin_registros.py`, `docker-compose.yml` | `test_la_consola_no_muestra_direcciones_ni_puertos`, `test_un_minioni_con_fugas_es_detectado`, `test_contenedores_sin_registros` | Lo que Windows guarda por su cuenta (LIMITES) |
| El DNS local revela los destinos | El proxy nunca resuelve nombres | `minioni/socks5.py`, `minioni/proxy.py` | `test_el_proxy_nunca_resuelve_nombres_y_la_consola_no_los_muestra` | Requiere la casilla de DNS remoto en Firefox |
| Un nodo comprometido alcanza a otros | Una red por salto | `docker-compose.yml` | `test_redes_segmentadas_sin_salida_a_internet`; matriz de `laboratorio_docker.py probar` | Todos los nodos están en un mismo equipo (LIMITES) |
| El destino ve al usuario | Solo la salida se conecta al destino | `minioni/relay.py`, `docker/servidor_web.py` | `test_servidor_web_no_registra_nada_y_muestra_quien_llega`; `probar` | En este laboratorio la IP pública del equipo no se oculta: todos los relays están en él |
| Se filtran las claves | Cifrado en reposo; nada en la imagen; contraseña por entrada estándar | `minioni/almacen_claves.py`, `Dockerfile`, `.dockerignore` | `test_imagen_sin_claves_y_sin_root`, `test_cada_relay_recibe_solo_sus_claves_y_en_solo_lectura`, `test_contrasena_por_entrada` | Copias de claves en memoria (LIMITES) |

## D · Denegación de servicio

| Amenaza | Control | Archivo | Prueba | Riesgo que queda |
|---|---|---|---|---|
| Agotar conexiones o circuitos | Límites por IP, enlace y relay; tiempos máximos | `minioni/relay.py` | `test_conexiones_por_ip_sobre_el_limite_se_cierran`, `test_limite_de_circuitos_por_enlace_responde_destroy_4`, `test_inactividad_destruye_el_circuito_con_motivo_2` | Sin control de flujo de extremo a extremo (LIMITES) |
| Abrir streams sin límite | 32 streams por circuito y cola acotada | `minioni/relay.py`, `minioni/proxy.py` | `test_33_streams_en_un_circuito_el_33_recibe_end_1` | Ídem |
| Un contenedor consume la máquina | Límites de PID, memoria y CPU | `docker-compose.yml` | `test_docker_no_guarda_registros_y_contenedores_endurecidos` | Ninguno conocido en el laboratorio |

## E · Elevación de privilegios

| Amenaza | Control | Archivo | Prueba | Riesgo que queda |
|---|---|---|---|---|
| Usar la salida para llegar a la red interna | Política de salida: 80 y 443 hacia IP públicas, conexión a la IP verificada | `minioni/politica_salida.py`, `minioni/relay.py` | `test_destinos_internos_bloqueados`, `test_begin_bloqueado_recibe_end_1`, `test_se_conecta_a_la_ip_exacta_que_paso_la_politica` | Cada excepción de laboratorio se documenta en LIMITES |
| Extender un circuito hacia un nodo no publicado | EXTEND solo hacia relays del directorio | `minioni/relay.py` | `test_extend_fuera_del_directorio_recibe_destroy`, `test_extend_con_clave_que_no_corresponde_recibe_destroy` | Ninguno conocido |
| Un fallo en el relay da control del equipo | Usuario 10001, solo lectura, sin capacidades, `no-new-privileges` | `Dockerfile`, `docker-compose.yml` | `test_docker_no_guarda_registros_y_contenedores_endurecidos` | La captura es la única excepción, a pedido y por 120 s como máximo (LIMITES) |
| Un mismo relay actúa como entrada y salida | Marca de entrada en el directorio | `minioni/directorio.py`, `minioni/circuito.py` | `test_un_relay_no_puede_ser_entrada_y_salida`, `test_con_marca_de_entrada_la_ruta_respeta_la_segmentacion` | Con 3 relays la ruta es siempre la misma (LIMITES #6) |
