"""Verificación de certificados TLS con el verificador de Windows (solo para las pruebas del panel).

Problema: Windows no trae todas las raíces de confianza instaladas; descarga
cada una la primera vez que un programa suyo (Edge, por ejemplo) la
necesita. Python lee ese almacén, pero no puede pedir la descarga, así que
rechaza sitios válidos cuya raíz todavía no se descargó ("unable to get local
issuer certificate"). Ejemplo real: example.com, con raíz SSL.com 2022.

Solución: en ese caso concreto, la cadena que envió el sitio se verifica con
CertGetCertificateChain + CertVerifyCertificateChainPolicy (política SSL,
con el nombre del sitio), el mismo verificador que usa Edge. No es
criptografía propia: verifica el sistema operativo. Si Windows rechaza, la
prueba falla sin haber enviado nada al sitio (fallo cerrado).

Solo biblioteca estándar (ctypes). En otros sistemas `disponible()` es False.
"""

from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes

CODIGO_SIN_EMISOR_LOCAL = 20          # X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY (OpenSSL)
_CODIFICACION = 0x00000001 | 0x00010000   # X509_ASN_ENCODING | PKCS_7_ASN_ENCODING
_ALMACEN_MEMORIA = 2                  # CERT_STORE_PROV_MEMORY
_AGREGAR_SI_NO_EXISTE = 2             # CERT_STORE_ADD_USE_EXISTING
_POLITICA_SSL = 4                     # CERT_CHAIN_POLICY_SSL
_AUTENTICAR_SERVIDOR = 2              # AUTHTYPE_SERVER
_OID_AUTENTICACION_SERVIDOR = b"1.3.6.1.5.5.7.3.1"   # szOID_PKIX_KP_SERVER_AUTH
MAX_CERTIFICADOS = 10
MAX_BYTES_CERTIFICADO = 64 * 1024


class _UsoMejorado(ctypes.Structure):          # CERT_ENHKEY_USAGE
    _fields_ = [("cUsageIdentifier", wintypes.DWORD),
                ("rgpszUsageIdentifier", ctypes.POINTER(ctypes.c_char_p))]


class _UsoPedido(ctypes.Structure):            # CERT_USAGE_MATCH
    _fields_ = [("dwType", wintypes.DWORD), ("Usage", _UsoMejorado)]


class _ParametrosCadena(ctypes.Structure):     # CERT_CHAIN_PARA
    _fields_ = [("cbSize", wintypes.DWORD), ("RequestedUsage", _UsoPedido)]


class _ExtraSSL(ctypes.Structure):             # SSL_EXTRA_CERT_CHAIN_POLICY_PARA
    _fields_ = [("cbSize", wintypes.DWORD), ("dwAuthType", wintypes.DWORD),
                ("fdwChecks", wintypes.DWORD), ("pwszServerName", wintypes.LPWSTR)]


class _ParametrosPolitica(ctypes.Structure):   # CERT_CHAIN_POLICY_PARA
    _fields_ = [("cbSize", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                ("pvExtraPolicyPara", ctypes.c_void_p)]


class _EstadoPolitica(ctypes.Structure):       # CERT_CHAIN_POLICY_STATUS
    _fields_ = [("cbSize", wintypes.DWORD), ("dwError", wintypes.DWORD),
                ("lChainIndex", wintypes.LONG), ("lElementIndex", wintypes.LONG),
                ("pvExtraPolicyStatus", ctypes.c_void_p)]


def disponible() -> bool:
    return sys.platform == "win32"


def _crypt32():
    c = ctypes.WinDLL("crypt32", use_last_error=True)
    c.CertCreateCertificateContext.restype = ctypes.c_void_p
    c.CertCreateCertificateContext.argtypes = [wintypes.DWORD, ctypes.c_char_p, wintypes.DWORD]
    c.CertOpenStore.restype = ctypes.c_void_p
    c.CertOpenStore.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p]
    c.CertAddEncodedCertificateToStore.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.c_char_p,
                                                   wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
    c.CertGetCertificateChain.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                          ctypes.POINTER(_ParametrosCadena), wintypes.DWORD, ctypes.c_void_p,
                                          ctypes.POINTER(ctypes.c_void_p)]
    c.CertVerifyCertificateChainPolicy.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                                   ctypes.POINTER(_ParametrosPolitica),
                                                   ctypes.POINTER(_EstadoPolitica)]
    c.CertFreeCertificateChain.argtypes = [ctypes.c_void_p]
    c.CertFreeCertificateContext.argtypes = [ctypes.c_void_p]
    c.CertCloseStore.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    return c


def verificar_cadena(cadena: list[bytes], host: str) -> bool:
    """True solo si Windows acepta la cadena para `host` como servidor TLS. Ante cualquier duda, False.

    `cadena` = certificados DER tal como los envió el sitio (el primero es el del sitio).
    Es bloqueante (Windows puede descargar una raíz): llamarla con asyncio.to_thread.
    """
    if not disponible() or not cadena or len(cadena) > MAX_CERTIFICADOS or not host:
        return False
    if any(not isinstance(c, bytes) or not 0 < len(c) <= MAX_BYTES_CERTIFICADO for c in cadena):
        return False
    c = _crypt32()
    hoja = almacen = contexto_cadena = None
    try:
        hoja = c.CertCreateCertificateContext(_CODIFICACION, cadena[0], len(cadena[0]))
        almacen = c.CertOpenStore(_ALMACEN_MEMORIA, 0, None, 0, None)
        if not hoja or not almacen:
            return False
        for intermedio in cadena[1:]:
            c.CertAddEncodedCertificateToStore(almacen, _CODIFICACION, intermedio, len(intermedio),
                                               _AGREGAR_SI_NO_EXISTE, None)
        usos = (ctypes.c_char_p * 1)(_OID_AUTENTICACION_SERVIDOR)
        parametros = _ParametrosCadena(ctypes.sizeof(_ParametrosCadena),
                                       _UsoPedido(0, _UsoMejorado(1, usos)))
        salida = ctypes.c_void_p()
        if not c.CertGetCertificateChain(None, hoja, None, almacen, ctypes.byref(parametros), 0, None,
                                         ctypes.byref(salida)) or not salida:
            return False
        contexto_cadena = salida
        extra = _ExtraSSL(ctypes.sizeof(_ExtraSSL), _AUTENTICAR_SERVIDOR, 0, host)
        politica = _ParametrosPolitica(ctypes.sizeof(_ParametrosPolitica), 0,
                                       ctypes.cast(ctypes.pointer(extra), ctypes.c_void_p))
        estado = _EstadoPolitica(ctypes.sizeof(_EstadoPolitica), 0, 0, 0, None)
        if not c.CertVerifyCertificateChainPolicy(_POLITICA_SSL, contexto_cadena, ctypes.byref(politica),
                                                  ctypes.byref(estado)):
            return False
        return estado.dwError == 0
    except (OSError, ValueError, TypeError):
        return False
    finally:
        if contexto_cadena:
            c.CertFreeCertificateChain(contexto_cadena)
        if hoja:
            c.CertFreeCertificateContext(hoja)
        if almacen:
            c.CertCloseStore(almacen, 0)
