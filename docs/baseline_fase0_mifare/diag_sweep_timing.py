#!/usr/bin/env python3

# Electronic Cats
# diag_sweep_timing.py — ¿por qué el barrido on-device es más lento que el
# barrido del host?
#
# Contexto (Plan de Implementación Firmware MIFARE, Fase 4, Sesión 11): los
# dos modos emiten EXACTAMENTE el mismo número de autenticaciones contra la
# tarjeta (79 en la card_1k del usuario) y el mismo número de re-selects, pero
# el on-device tarda más (17,2 s vs 7,5 s medidos). El código de ambos caminos
# es el mismo (`sweepAuth` vs `handleMifareAuth` -> `mifareBeginAuth` +
# `mifareAuthenticate` + `mifareReselect`), así que la diferencia tiene que
# estar DENTRO del firmware.
#
# Este script mide, sobre el hardware real:
#
#   1. el coste por comando del CAMINO HOST: N × `mifare auth` (1 auth + 1
#      re-select + un round-trip USB por comando);
#   2. el coste por iteración del CAMINO ON-DEVICE: `mifare check` con una
#      clave que falla, en varios tamaños, para sacar la pendiente;
#   3. el desglose que da el propio firmware en `:mifare_check_stat`
#      (auth_ms / reselect_ms / trailer_ms): el tiempo DENTRO de la
#      autenticación y dentro del re-select, medido en la placa;
#   4. el barrido del valor de `--settle` (el reposo entre re-select y la
#      siguiente autenticación), que es lo que el camino host recibe gratis de
#      su round-trip USB.
#
# Uso (con la tarjeta EN el lector):
#
#   python3 diag_sweep_timing.py [--port /dev/ttyACM0] [--key AABBCCDDEEFF]
#
# La clave por defecto es una que NO abre ningún sector de la card_1k del
# usuario (A0A1A2A3A4A5 / D3F7D3F7D3F7 / FFFFFFFFFFFF), así que todas las
# autenticaciones fallan: así se mide el coste por intento fallido, que es
# donde está la diferencia.

from __future__ import annotations

import argparse
import re
import sys
import time
from typing import Dict, List, Optional, Tuple

try:
    import serial
except ImportError:  # pragma: no cover
    sys.exit("pyserial is required: pip install pyserial")

# Una clave que falla en todos los sectores de la tarjeta de referencia.
DEFAULT_WRONG_KEY = "AABBCCDDEEFF"

_PROBE_RE = re.compile(r"^:mifare\s")
_STAT_RE = re.compile(r"^:mifare_check_stat\s+(.*)$")
_SECTOR_RE = re.compile(r"^:mifare_check_s(\d+)\s")


class Board:
    """El enlace con la placa: líneas de texto, con cronómetro."""

    def __init__(self, port: str, baud: int = 115200, timeout: float = 2.0):
        self.ser = serial.Serial(port, baud, timeout=timeout)
        time.sleep(0.3)
        self.ser.reset_input_buffer()

    def close(self) -> None:
        self.ser.close()

    def send(self, line: str) -> None:
        self.ser.write((line + "\n").encode("ascii", "replace"))
        self.ser.flush()

    def read_line(self, deadline: float) -> Optional[str]:
        """La próxima línea no vacía, o None si se agota el plazo."""
        while time.monotonic() < deadline:
            raw = self.ser.readline()
            if not raw:
                continue
            text = raw.decode("ascii", "replace").strip()
            if text:
                return text
        return None

    def command(self, line: str, wait: float = 300.0) -> Tuple[float, List[str], bool]:
        """Envía una orden y espera a su terminador (+OK / -ERR).

        Devuelve (segundos, líneas, ok). Las líneas de datos (`:clave valor`)
        se devuelven tal cual: el llamador las parsea.
        """
        t0 = time.monotonic()
        self.send(line)
        out: List[str] = []
        ok = False
        while time.monotonic() - t0 < wait:
            text = self.read_line(t0 + wait)
            if text is None:
                break
            out.append(text)
            if text.startswith("+OK"):
                ok = True
                break
            if text.startswith("-ERR"):
                ok = False
                break
        return time.monotonic() - t0, out, ok

    def wait_for_session(self, timeout: float = 60.0) -> bool:
        """Espera a que la placa tenga una sesión con tarjeta (el auto-probe
        emite su señal `:mifare ...` cuando la tarjeta ya está seleccionada)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            text = self.read_line(deadline)
            if text is None:
                return False
            if _PROBE_RE.match(text):
                return True
        return False


def parse_stat(lines: List[str]) -> Dict[str, str]:
    """`:mifare_check_stat attempts=… naive=… trailer=… auth_ms=…` -> dict."""
    stat: Dict[str, str] = {}
    for line in lines:
        m = _STAT_RE.match(line)
        if not m:
            continue
        for token in m.group(1).split():
            name, _, raw = token.partition("=")
            if name:
                stat[name] = raw
    return stat


def parse_timing(lines: List[str]) -> Dict[str, str]:
    """`:mifare_timing attempts=… auth_ms=… reselect_ms=… reset_ms=…` -> dict."""
    stat: Dict[str, str] = {}
    for line in lines:
        if not line.startswith(":mifare_timing "):
            continue
        for token in line[len(":mifare_timing ") :].split():
            name, _, raw = token.partition("=")
            if name:
                stat[name] = raw
    return stat


def board_timing(board: Board) -> Dict[str, str]:
    """Los contadores de la placa (los mismos que el stat del barrido)."""
    _, lines, _ = board.command("mifare timing", wait=10.0)
    return parse_timing(lines)


def reset_timing(board: Board) -> None:
    board.command("mifare timing reset", wait=10.0)


def count_sectors(lines: List[str]) -> int:
    return sum(1 for line in lines if _SECTOR_RE.match(line))


def host_path_cost(board: Board, block: int, key: str, n: int) -> float:
    """El coste del CAMINO HOST: n autenticaciones fallidas, una por round-trip
    USB. Devuelve el tiempo total en segundos."""
    total = 0.0
    for _ in range(n):
        dt, _, _ = board.command(f"mifare auth {block} A {key}", wait=30.0)
        total += dt
    return total


def device_path(board: Board, sectors: int, key: str, settle: Optional[int]) -> Tuple[float, Dict[str, str], int]:
    """El coste del CAMINO ON-DEVICE: `mifare check` con una clave que falla en
    todos los slots. Devuelve (segundos, stat, nº de sectores resueltos)."""
    cmd = f"mifare check --sectors {sectors} --keys {key}"
    if settle is not None:
        cmd += f" --settle {settle}"
    dt, lines, _ = board.command(cmd, wait=600.0)
    return dt, parse_stat(lines), count_sectors(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", default="/dev/ttyACM0")
    ap.add_argument("--key", default=DEFAULT_WRONG_KEY,
                    help="clave que falla en todos los sectores (por defecto "
                         f"{DEFAULT_WRONG_KEY})")
    ap.add_argument("--host-iterations", type=int, default=16,
                    help="autenticaciones del camino host a medir (16)")
    ap.add_argument("--skip-host", action="store_true")
    args = ap.parse_args()

    board = Board(args.port)
    try:
        print(f"Puerto {args.port}")
        dt, lines, ok = board.command("info", wait=10.0)
        state = ""
        for line in lines:
            if line.startswith(":state "):
                state = line.split(" ", 1)[1].strip()
        print(f"  estado: {state or '?'}  (ping/info en {dt*1000:.0f} ms)")

        if state != "tag-detected":
            print("\nNo hay sesión con tarjeta. Pon la tarjeta en el lector"
                  " (el Firmware la detecta y barre sola); esperando 60 s...")
            if not board.wait_for_session(60.0):
                print("No se detectó ninguna tarjeta. Abortando.")
                return 1
            print("  sesión abierta.")

        print(f"\nClave de prueba: {args.key} (falla en todos los slots)\n")

        # ── 1. el camino host ────────────────────────────────────────────────
        if not args.skip_host:
            print("CAMINO HOST — 16 × `mifare auth` (1 auth + 1 re-select + USB)")
            reset_timing(board)
            t_host = host_path_cost(board, 0, args.key, args.host_iterations)
            stat = board_timing(board)
            per = t_host / args.host_iterations
            print(f"  total {t_host:.2f} s  →  {per*1000:.0f} ms por intento"
                  "  (auth + re-select + USB)")
            print(f"  en la placa: {stat}")
            n = int(stat.get("attempts", 0)) or 1
            print(f"  por intento: auth {int(stat.get('auth_ms',0))/n:.0f} ms + "
                  f"re-select {int(stat.get('reselect_ms',0))/n:.0f} ms "
                  f"(reset {int(stat.get('reset_ms',0))/n:.0f} ms + "
                  f"detect {int(stat.get('detect_ms',0))/n:.0f} ms)")

        # ── 2. el camino on-device, con el desglose del firmware ─────────────
        print("\nCAMINO ON-DEVICE — `mifare check --keys <clave que falla>`")
        print(f"  {'sectores':>8} {'tiempo':>9} {'auths':>6} {'auth_ms':>9} "
              f"{'resel_ms':>9} {'reset_ms':>9} {'detect_ms':>10} {'ms/auth':>9}")
        for sectors in (1, 4, 8, 16):
            dt, stat, _ = device_path(board, sectors, args.key, None)
            attempts = int(stat.get("attempts", 0))
            per_auth = int(stat.get("auth_ms", 0)) / attempts if attempts else 0
            print(f"  {sectors:>8} {dt:>8.2f}s {attempts:>6} "
                  f"{stat.get('auth_ms','?'):>9} {stat.get('reselect_ms','?'):>9} "
                  f"{stat.get('reset_ms','?'):>9} {stat.get('detect_ms','?'):>10} "
                  f"{per_auth:>8.0f}ms")

        # ── 3. el barrido del settle ────────────────────────────────────────
        print("\nSETTLE — el reposo entre re-select y la siguiente auth")
        print(f"  {'settle':>8} {'tiempo':>9} {'auths':>6} {'auth_ms':>9} "
              f"{'resel_ms':>9} {'detect_ms':>10}")
        for settle in (0, 5, 10, 20, 40, 80, 160):
            dt, stat, _ = device_path(board, 16, args.key, settle)
            print(f"  {settle:>7}ms {dt:>8.2f}s {stat.get('attempts','?'):>6} "
                  f"{stat.get('auth_ms','?'):>9} {stat.get('reselect_ms','?'):>9} "
                  f"{stat.get('detect_ms','?'):>10}")

        print("\nSi `auth_ms/auth` es mucho mayor en on-device que el coste por"
              "\nintento del camino host, la autenticación es la que espera a"
              "\nla tarjeta (y el settle es la palanca). Si `reselect_ms/resel`"
              "\nes el que domina, el re-select (re-arm completo del lector)"
              "\nes el cuello de botella.")
        return 0
    finally:
        board.close()


if __name__ == "__main__":
    raise SystemExit(main())
