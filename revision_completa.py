"""Ejecuta todas las comprobaciones de MiniOni de una sola vez y muestra un resumen.

Uso (con el entorno activo y después de preparar-laboratorio):
    python revision_completa.py
    python revision_completa.py --con-internet     # agrega pip-audit (necesita internet)
    python revision_completa.py --con-docker       # agrega la prueba del laboratorio Docker (debe estar iniciado)
"""

import os
import subprocess  # nosec B404 - solo se ejecutan comandos fijos de este proyecto, sin shell
import sys

PY = sys.executable
PASOS = [
    ("Pruebas automáticas (pytest + fuzzing)",
     [PY, "-m", "pytest", "-q", "-p", "no:cacheprovider",
      "--ignore=tests/test_red.py", "--ignore=tests/test_salida_proxy.py"]),
    ("Pruebas de red (3 relays con TLS 1.3 en 127.0.0.1)",
     [PY, "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/test_red.py"]),
    ("Pruebas de salida y proxy SOCKS5 (fallo cerrado, DNS remoto)",
     [PY, "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/test_salida_proxy.py"]),
    ("Análisis estático de seguridad (Bandit)", [PY, "-m", "bandit", "-q", "-c", "pyproject.toml", "-r", "."]),
    # Las pruebas también son código que se ejecuta y se versiona (Clase 3, T2). Se omiten
    # solo tres reglas, cada una con motivo (docs/CLASE3_CODIFICACION_SEGURA.md):
    #   B101  pytest compara con `assert`; es su forma normal de verificar.
    #   B104  "0.0.0.0" aparece en pruebas que comprueban que se RECHAZA.
    #   B105  contraseñas de laboratorio que solo existen dentro de las pruebas.
    # En tests/ no se acepta ninguna marca para silenciar a Bandit (lo comprueba
    # tests/test_revisiones_clase3.py).
    ("Análisis estático de las pruebas (Bandit)",
     [PY, "-m", "bandit", "-q", "-r", "tests", "-s", "B101,B104,B105"]),
    ("Revisión de secretos (detect-secrets + claves cifradas)", [PY, "revisar_secretos.py"]),
    ("Demostración de la cebolla", [PY, "demo_capas.py"]),
    ("Verificación del directorio firmado", [PY, "minioni_admin.py", "verificar-directorio"]),
    ("Simulación de ataque al directorio", [PY, "minioni_admin.py", "simular-ataque"]),
]


def ejecutar(nombre: str, comando: list[str]) -> bool:
    print(f"\n=== {nombre} ===", flush=True)
    entorno = dict(os.environ, PYTHONIOENCODING="utf-8")
    r = subprocess.run(comando, capture_output=True, env=entorno)  # nosec B603 - lista fija, sin shell
    salida = (r.stdout + r.stderr).decode("utf-8", errors="replace").strip()
    lineas = salida.splitlines()
    for linea in (lineas if len(lineas) <= 25 else ["..."] + lineas[-25:]):
        print("  " + linea)
    ok = r.returncode == 0
    print(f"  -> {'OK' if ok else 'FALLO'}")
    return ok


def main() -> int:
    pasos = list(PASOS)
    if "--con-internet" in sys.argv:
        pasos.append(("Vulnerabilidades en dependencias (pip-audit)",
                      [PY, "-m", "pip_audit", "-r", "requirements.txt"]))
    if "--con-docker" in sys.argv:
        pasos.append(("Laboratorio Docker: segmentación, punta a punta y fallo cerrado",
                      [PY, "laboratorio_docker.py", "probar"]))
    if not os.path.exists(os.path.join("config", "directorio.firmado.json")):
        print("Falta el directorio firmado. Ejecuta primero:\n"
              "  python minioni_admin.py preparar-laboratorio")
        return 1
    resultados = [(nombre, ejecutar(nombre, cmd)) for nombre, cmd in pasos]
    print("\n================ RESUMEN ================")
    for nombre, ok in resultados:
        print(f"  [{'OK   ' if ok else 'FALLO'}] {nombre}")
    todos = all(ok for _, ok in resultados)
    print("\nTodo correcto." if todos else "\nHay pasos con FALLO: revisa su salida arriba.")
    return 0 if todos else 1


if __name__ == "__main__":
    sys.exit(main())
