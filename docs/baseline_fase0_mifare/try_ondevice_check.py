#!/usr/bin/env python3
# Electronic Cats — Distributed as-is; no warranty is given.
#
# Fase 1 — prueba manual del comando `mifare check` ON-DEVICE.
#
# El CLI (`bombercat tags mifare check`) todavía conduce el barrido comando a
# comando desde el host (Fase 4 aún no conecta el comando on-device). Este
# script reutiliza el MISMO contexto de sesión que usa check.py para abrir el
# enlace, esperar el tap de la tarjeta y enviar UNA sola línea `mifare check`
# al firmware, imprimiendo la salida consolidada tal cual (serial_log_format.md).
#
# Uso (con el BomberCat conectado y el firmware de esta rama flasheado):
#     python3 try_ondevice_check.py            # 16 sectores, dict embebido
#     python3 try_ondevice_check.py --sectors 8
#     python3 try_ondevice_check.py --keys FFFFFFFFFFFF,A0A1A2A3A4A5,D3F7D3F7D3F7
#
# GOTCHA (Sesión 3): abrir el puerto resetea el RP2040 (DTR) y, si la tarjeta
# está sobre el lector al arrancar, la lectura falla. INICIA con la tarjeta
# retirada y acércala cuando el script te lo pida.

import sys
import time

# El paquete `modules` está enraizado en bombercat-tools/.
_TOOLS = "/home/darcko/Documentos/ElectronicCats/BomberCat/bombercat-tools"
sys.path.insert(0, _TOOLS)

from modules.tags.mifare.session import _mifare_session, _wait_for_mifare_card  # noqa: E402

READ_TIMEOUT = 60.0  # holgado: cada clave errónea hace un re-select (reset de chip)
TAP_TIMEOUT = 30.0


def _sector_num(key: str) -> int:
    # "mifare_check_s7" -> 7 ; la línea de stat va al final.
    if key.startswith("mifare_check_s") and key[len("mifare_check_s"):].isdigit():
        return int(key[len("mifare_check_s"):])
    return 10_000


def main() -> int:
    args = sys.argv[1:]  # se pasan tal cual al firmware tras "mifare check"
    line = "mifare check" + ((" " + " ".join(args)) if args else "")

    with _mifare_session(None, None) as (target, link):
        print(f"[on-device check] enlace @ {target}")
        print(">>> ACERCA la tarjeta al lector AHORA "
              f"(esperando hasta {TAP_TIMEOUT:g}s)...")
        if not _wait_for_mifare_card(link, TAP_TIMEOUT):
            print("!! No se detectó ninguna tarjeta (sesión no abierta).")
            return 1

        t0 = time.monotonic()
        r = link.command(line, read_timeout=READ_TIMEOUT)
        dt = time.monotonic() - t0

        print(f"\n--- salida on-device (`{line}`) ---")
        for key in sorted(r.data, key=_sector_num):
            print(f":{key} {r.data[key]}")
        stat = r.data.get("mifare_check_stat", "")
        print(("+OK" if r.ok else f"-ERR {r.message}"))
        print(f"--- {dt:.1f}s ---")

        # Pin de regresión (card_1k): 32/32 con attempts <= 66.
        ok = r.ok and "recovered=32/32" in stat
        attempts = None
        for tok in stat.split():
            if tok.startswith("attempts="):
                attempts = int(tok.split("=", 1)[1])
        if attempts is not None:
            ok = ok and attempts <= 66
            print(f"[pin card_1k] recovered=32/32 & attempts<=66 -> "
                  f"{'PASS' if ok else 'REVISAR'} (attempts={attempts})")
        return 0 if r.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
