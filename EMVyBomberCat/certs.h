// PLACEHOLDER — ejecuta generate_cert.py para generar certs reales:
//   pip install cryptography
//   python3 generate_cert.py
//
// Este archivo es sobrescrito por generate_cert.py.
// NO subir certs.h a control de versiones (agregar a .gitignore).
#pragma once

// Certificado autofirmado EC P-256 para 192.168.4.1
// (reemplazar con salida de generate_cert.py)
static const char SERVER_CERT_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "REEMPLAZAR_CON_SALIDA_DE_generate_cert.py\n"
    "-----END CERTIFICATE-----\n";

static const char SERVER_KEY_PEM[] =
    "-----BEGIN EC PRIVATE KEY-----\n"
    "REEMPLAZAR_CON_SALIDA_DE_generate_cert.py\n"
    "-----END EC PRIVATE KEY-----\n";
