# Imagen de MiniOni para el laboratorio con redes segmentadas (semana 4).
# La misma imagen sirve para los 3 relays, el servidor web del laboratorio y la sonda.
#
# Se construye con:  python laboratorio_docker.py iniciar   (o docker compose build)
#
# Decisiones de seguridad:
# - Solo se copian los archivos necesarios (lista blanca); .dockerignore excluye
#   además claves/, config/, .git/ y .venv/: ninguna clave entra a la imagen (SSDF PS.1.1).
# - Las claves y el directorio se montan al arrancar, en solo lectura, y cada relay
#   recibe solo SU carpeta de claves (docker-compose.yml).
# - Usuario sin privilegios (10001); docker-compose.yml agrega sistema de archivos de
#   solo lectura, sin capacidades y sin registros de Docker.
# - Dependencias con versión fija (requirements.txt, SSDF PW.4.1).

# Imagen base fijada por su digest (SSDF PW.4.1): si alguien cambia la etiqueta en el
# registro, la construcción falla en vez de usar otra imagen. Para actualizarla, ver
# docs/SEMANA4_DOCKER.md, sección 4.3.
ARG BASE=python:3.14-slim@sha256:9aaa474097d094040649f2162a627c0049b408f52138d980916788d80f04802f
FROM ${BASE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8 \
    MINIONI_CLAVES=/app/claves \
    PYTHONPATH=/app

WORKDIR /app

COPY requirements.txt ./
RUN python -m pip install --no-cache-dir --disable-pip-version-check --root-user-action=ignore -r requirements.txt

COPY minioni/ ./minioni/
COPY ejecutar_relay.py cliente_prueba.py ./
COPY docker/servidor_web.py docker/sonda.py docker/puerta.py ./docker/

# Usuario numérico sin privilegios: no hace falta crearlo para ejecutar Python.
USER 10001:10001

CMD ["python", "-c", "print('Usa docker-compose.yml: cada servicio define su comando.')"]
