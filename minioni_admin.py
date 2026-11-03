"""Punto de entrada de la herramienta de administración. Ver minioni/admin.py."""

import sys

from minioni import consola
from minioni.admin import main

if __name__ == "__main__":
    consola.instalar_manejador_global("admin")
    sys.exit(main())
