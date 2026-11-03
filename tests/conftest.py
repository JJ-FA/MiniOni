"""Configuración de Hypothesis (fuzzing).

Perfiles:
    normal   300 casos por prueba (por defecto)
    intenso  5000 casos por prueba:   python -m pytest --hypothesis-profile=intenso
"""

import pytest
from hypothesis import HealthCheck, settings

from minioni import almacen_claves

settings.register_profile(
    "normal", max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow]
)
settings.register_profile(
    "intenso", max_examples=5000, deadline=None, suppress_health_check=[HealthCheck.too_slow]
)
settings.load_profile("normal")


@pytest.fixture(autouse=True, scope="session")
def _scrypt_rapido_en_pruebas():
    """Las pruebas generan claves con N=2^14 para ir rápido; el programa exige 2^17."""
    anterior = almacen_claves.minimo_aceptado
    almacen_claves.minimo_aceptado = almacen_claves.N_SCRYPT_PRUEBAS
    yield
    almacen_claves.minimo_aceptado = anterior


@pytest.fixture(autouse=True)
def _sin_minioni_claves(monkeypatch):
    """Las pruebas nunca deben tocar la carpeta real de claves del equipo (MINIONI_CLAVES)."""
    monkeypatch.delenv(almacen_claves.VARIABLE_CLAVES, raising=False)
