#!/usr/bin/env bash
# Fase 0 · Tarea 0.2 — captura la línea base host de `mifare check` sobre la
# card_1k de referencia. Corre DOS veces y compara para probar reproducibilidad.
#
# Requiere: BomberCat conectada por USB con firmware MifareClassic, y la card_1k
# de referencia sobre el lector. Uso:  ./capture_baseline.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BOMBERCAT="${BOMBERCAT:-bombercat}"   # alias del CLI; o export BOMBERCAT=/ruta/bombercat.py
SECTORS="${SECTORS:-16}"              # 16 = 1K
TAP_TIMEOUT="${TAP_TIMEOUT:-30}"      # ventana para acercar la tarjeta tras iniciar

# QUIRK DE HARDWARE (confirmado en Fase 0): si la tarjeta ya está sobre el lector
# cuando arranca el proceso, la lectura falla (0/32). Hay que INICIAR con la
# tarjeta RETIRADA y ACERCARLA una vez que aparece el prompt de espera. Por eso
# cada corrida pide retirar la tarjeta y usa --timeout amplio.
run() {  # $1 = fichero de salida
  read -rp "→ Retira la tarjeta del lector y pulsa Enter para iniciar (acércala cuando arranque)... " _
  echo "  tags mifare check --json --timeout $TAP_TIMEOUT --sectors $SECTORS --key-type both  >  $1"
  # El CLI imprime un banner ASCII en stdout junto al JSON; --json emite un
  # único objeto en la última línea. Extraemos solo esa línea JSON.
  "$BOMBERCAT" tags mifare check --json --timeout "$TAP_TIMEOUT" \
    --sectors "$SECTORS" --key-type both \
    2>/dev/null | grep -E '^\{.*"sectors"' | tail -1 > "$1"
  if ! jq -e . "$1" >/dev/null 2>&1; then
    echo "✗ No se obtuvo JSON válido (¿tarjeta no acercada a tiempo, o timeout?)."
    return 1
  fi
}

echo "== Corrida 1 =="
run "$HERE/baseline.json"
echo "== Corrida 2 (reproducibilidad) =="
run "$HERE/baseline_run2.json"

echo
echo "== Comparación de claves recuperadas (deben coincidir) =="
# Compara solo el mapa sector→claves, ignorando stats de timing.
jq -S '.sectors' "$HERE/baseline.json"      > "$HERE/.b1.sectors.json"
jq -S '.sectors' "$HERE/baseline_run2.json" > "$HERE/.b2.sectors.json"
if diff -q "$HERE/.b1.sectors.json" "$HERE/.b2.sectors.json" >/dev/null; then
  echo "✓ Reproducible: ambas corridas dan el mismo conjunto de claves."
else
  echo "✗ DIVERGEN — revisar (tarjeta movida, ruido RF, o clave no determinista):"
  diff "$HERE/.b1.sectors.json" "$HERE/.b2.sectors.json" || true
fi
rm -f "$HERE/.b1.sectors.json" "$HERE/.b2.sectors.json"

echo
echo "== Pins de regresión (baseline.json) =="
jq '{recovered, total, stats}' "$HERE/baseline.json"
echo "Guardar baseline.json en git como referencia de las Fases 1 y 5."
