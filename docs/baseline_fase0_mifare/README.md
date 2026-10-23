# Línea base — Fase 0 (plan MIFARE on-device)

> Fase 0 de [`Plan de Implementacion Firmware MIFARE.md`](../../../Plan%20de%20Implementacion%20Firmware%20MIFARE.md).
> Capturada el 2026-09-25. Firmware: `MifareClassic/`, rama `feature/mifare` @ `6dcb617`.
> Placa: BomberCat (RP2040 + PN7150), FQBN `electroniccats:mbed_rp2040:bombercat`.
> Toolchain: `arduino-cli 1.5.1`, core `electroniccats:mbed_rp2040 2.0.0`.

**No confundir con `docs/baseline_fase0/`**, que es la línea base del proyecto
`EMVyBomberCat` (otro plan). Esta carpeta es exclusiva del plan MIFARE.

---

## Estado de las tareas de Fase 0

| Tarea | Descripción | Estado |
|-------|-------------|--------|
| 0.1 | Leer `MifareClassic.ino` y primitivas | ✅ hecho (esta sesión) |
| 0.2 | Generar `baseline.json` con `check.py` sobre `card_1k` | ✅ hecho (2026-09-25) — 32/32, reproducible. Ver [baseline](#02--baseline-de-referencia-capturada) |
| 0.3 | Medir presupuesto de flash en QSPI | ✅ hecho — ver [presupuesto de flash](#03--presupuesto-de-flash-medido) |
| 0.4 | Confirmar API de `ConfigStore` (para Fase 3) | ✅ hecho — ver [ConfigStore](#04--api-de-configstore-confirmada) |
| 0.5 | Preparar 2–3 tarjetas de prueba | 🟡 parcial — `card_1k` (NDEF) y `card_hole` disponibles; falta `card_custom`. Ver [banco de tarjetas](#05--banco-de-tarjetas) |
| 0.6 | Definir formato de log serial ASCII-only | ✅ hecho — ver [`serial_log_format.md`](serial_log_format.md) |

Las dos tareas pendientes (0.2 y 0.5) necesitan la BomberCat física con tarjetas
en el lector; están totalmente preparadas para que se ejecuten en una pasada.

---

## 0.1 — Lectura del firmware (mapa)

`MifareClassic.ino` (603 líneas) + `MifareCommands.{h,cpp}` + `MifareClassic.h`.

**Modelo de sesión (no tocar en Fases 1–3 — restricción transversal #4):**
- `loop()` no bloquea: `control.poll()` cada iteración; `awaitingRemoval` y
  `mifareSessionOpen` son máquinas de estado con `return` temprano.
- La retirada de tarjeta se sondea (`pollCardRemoval`, cada 500 ms, timeout 200 ms),
  **nunca** con el `waitForTagRemoval()` bloqueante del vendor.
- Cualquier bucle de barrido on-device (Fase 1) debe respetar este patrón:
  ceder control en cada iteración, sin `delay()` largos ni waits bloqueantes.

**Primitivas reutilizables (base de Fases 1–2), en `MifareCommands.h`:**
- `mifareAuthenticate(nfc, block, keyType, key)` — auth Crypto1 real por I²C.
  Un **fallo deja la tarjeta HALTed y deseleccionada**.
- `mifareReselect(nfc, timeoutMs=500)` — re-selecciona tras fallo; `false` = tarjeta
  fuera del campo (no "clave mala"). **Obligatorio** entre intentos de clave.
- `mifareReadBlock` / `mifareWriteBlock` / `mifareReadSector` (este último devuelve
  `authOk` para distinguir "clave mala" de "auth ok pero access bits deniegan lectura").

**Sesión Crypto1 caliente (`mifareCardAuthed`):** un auth exitoso **no** re-selecciona,
para que `auth` + `read`/`write` posteriores compartan sesión. Pero **antes del
siguiente auth** hay que re-seleccionar (`mifareBeginAuth()`), o el PN7150 deja que
un auth nuevo "cabalgue" la sesión abierta → falso positivo Key B == Key A. El barrido
on-device debe replicar esta coreografía por cada clave probada.

**Selector de clave (gotcha ya resuelto en `MifareClassic.h`):** el PN7150 usa su
`MFC_Authenticate_REQ` propietario (`0x40`), **no** los códigos PN532 `0x60/0x61`.
Key A = `0x10`, Key B = `0x90` (bit b7). `0x11` autentica silenciosamente como Key A.

**Auto-prueba actual (caso degenerado que la Fase 2 amplía):** `probeMifareBlock()`
solo prueba **bloque 4**, **solo Key A**, con **3 claves** (`MIFARE_PROBE_KEYS`:
`FFFFFFFFFFFF`, `000000000000`, `A0A1A2A3A4A5`).

**`emitKnownKeys()` (`mifare keys`):** hoy solo **lista** las 3 claves embebidas con
claves indexadas `:mifare_key0/1/2`. El key-store persistente de la Fase 3
(`add/remove`) está marcado como *no implementado* en el propio comentario del código.

---

## 0.2 — Baseline de referencia (capturada)

Capturada el 2026-09-25 con la ruta `bombercat tags mifare check` (el comando vive
bajo el grupo `tags`, no en la raíz). El CLI emite JSON con `--json`: sectores
`key_a`/`key_b`, `recovered`, `total` y `stats {attempts, naive_attempts,
auths_saved, saved_pct, interrupted}`. Ese es el contrato que la Fase 1 debe igualar
sin regresión.

**Resultado (`baseline.json`, = `baseline_run1.json` = `baseline_run2.json`):**

| Métrica | Valor |
|---|---|
| Recuperadas | **32/32** (16 sectores × A y B) |
| `stats.attempts` (real) | **66** |
| `stats.naive_attempts` | 79 264 (16 × 2 × 2477) |
| `auths_saved` | 79 198 (**99.9 %** vs. naive, por reuso known-first + early-cut) |
| Reproducibilidad | ✅ dos corridas → mismo conjunto de claves y mismo nº de auths |

**Perfil de la tarjeta de referencia (`card_1k`, NDEF/NFC Forum formateada):**

| Sector(es) | Key A | Key B |
|---|---|---|
| 0 | `A0A1A2A3A4A5` (clave MAD) | `FFFFFFFFFFFF` |
| 1–2 | `D3F7D3F7D3F7` (clave NFC Forum) | `FFFFFFFFFFFF` |
| 3–15 | `FFFFFFFFFFFF` | `FFFFFFFFFFFF` |

**Pins de regresión para Fases 1 y 5:**
- On-device `mifare check` debe recuperar **exactamente estas 32 claves** sobre esta
  tarjeta (criterio de aceptación global #1).
- `attempts` on-device **≤ 66** — idealmente igual (criterio global #2: no aumentar auths).
  El plan citaba "~2514" como orden de magnitud genérico; en esta tarjeta el real es 66
  gracias al reuso, porque casi todas las claves son `FFFFFFFFFFFF`.

> **Quirk de hardware (importante para todas las capturas y para la Fase 4 standalone):**
> si la tarjeta ya está sobre el lector cuando arranca el proceso, la lectura falla
> (se observó 0/32 con barrido naive completo). Hay que **iniciar con la tarjeta
> retirada y acercarla cuando aparece el prompt "tap a Mifare Classic card"**.
> `capture_baseline.sh` codifica esto (`--timeout 30` + aviso de retirar la tarjeta
> antes de cada corrida). Abrir el puerto serie resetea el RP2040 (DTR): no sondear
> con serie crudo entre corridas, porque tira la sesión de la tarjeta.

**Re-ejecutar:**

```bash
./capture_baseline.sh            # 2 corridas + verificación de reproducibilidad
# o manualmente, con la tarjeta fuera al iniciar:
bombercat tags mifare check --json --timeout 30 --sectors 16 --key-type both
```

> Toda auth es una Crypto1 real sobre I²C RP2040↔PN7150. Mover el barrido on-device
> **no reduce** el nº de auths; solo elimina el round-trip USB-serial + parseo del host.

---

## 0.3 — Presupuesto de flash medido

Comando: `arduino-cli compile --fqbn electroniccats:mbed_rp2040:bombercat --library core MifareClassic`
(log completo: [`compile_mifare_fase0.log`](compile_mifare_fase0.log)).

| Métrica | Uso | % | Límite | Libre |
|---|---|---|---|---|
| Flash (programa) | 104 676 B | 4 % | 2 097 152 B (2 MB QSPI) | **1 992 476 B (~1.90 MB)** |
| RAM (globales) | 44 936 B | 17 % | 262 144 B | 217 208 B |

**Conclusión:** el presupuesto de flash **no es un riesgo**. El diccionario embebido
compacto (2477 claves × 6 B = **14 862 B**, ~0.7 % del binario) cabe con margen enorme;
incluso el `.keys` completo cabría. El riesgo #1 del plan ("diccionario excede QSPI")
queda **descartado con cifras**. La restricción real sigue siendo no volcar ficheros
`.dic` completos como archivos, sino embeber la tabla compacta en flash de programa.

---

## 0.4 — API de `ConfigStore` confirmada

`core/src/ConfigStore.{h,cpp}`. Es un **wrapper de propósito fijo** sobre mbed
`TDBStore` montado en un `FlashIAPBlockDevice` (región QSPI reservada vía
`FlashIAPLimits.h`).

- API pública tipada a `RelayConfig`: `begin()`, `load(RelayConfig&)`,
  `save(const RelayConfig&)`, `clear()`, `defaults()`.
- Internamente guarda **una sola clave** TDBStore: `"relaycfg"` (POD de tamaño fijo).
- `TDBStore` por debajo **es** un key-value store completo con wear-leveling:
  `set(key, buf, size, flags)`, `get`, `get_info`, `remove` — por clave arbitraria.

**Implicaciones para la Fase 3 (key-store `mifare keys`):**
1. **Reutilizar la misma instancia** de `FlashIAPBlockDevice`/`TDBStore`. Montar un
   segundo `FlashIAPBlockDevice` sobre la misma región colisiona. → Extender
   `ConfigStore` con una segunda clave (p.ej. `"mifarekeys"`) y accesores tipados
   (`loadMifareKeys/saveMifareKeys`), **no** crear un store nuevo.
2. `set()` reescribe el registro completo → cada guardado es una escritura flash.
   Confirma la necesidad de la Tarea 3.7 (batch, escribir solo al cambiar).
3. Guardar un blob POD de tamaño fijo (array de claves de 6 B + contador) encaja con el
   patrón `RelayConfig` ya probado (get/set con verificación de `actual == sizeof`).
4. **`MifareClassic.ino` hoy no instancia `ConfigStore` ni lo incluye.** La Fase 3 debe
   añadir el `#include <ConfigStore.h>` y un `ConfigStore` global + `begin()` en `setup()`.

---

## 0.5 — Banco de tarjetas

| Rol | Estado | Contenido | Para qué |
|-----|--------|-----------|----------|
| `card_1k` | ✅ disponible | tarjeta NDEF: claves de diccionario (`A0A1A2A3A4A5`, `D3F7D3F7D3F7`, `FFFFFFFFFFFF`) — ver perfil en 0.2 | baseline 0.2 y regresión 5.1 |
| `card_hole` | ✅ disponible | tarjeta personalizada: **0/32** claves de diccionario (todos los sectores son huecos) — `baseline_card-personalizada.json` | reporte honesto de huecos (restricción #6) |
| `card_custom` | ⏳ pendiente | ≥1 sector con clave custom **conocida** (no de diccionario) | verifica que el key-store de Fase 3 alimenta el barrido |

La `card_hole` cae por sí sola de la tarjeta que se probó primero: su barrido completo
recupera 0/32 (`attempts == naive_attempts == 79264`), justo el caso de "sector hueco"
que el reporte honesto debe declarar sin darlo por resuelto.

**Pendiente:** una `card_custom` con al menos un sector reprogramado con una clave
conocida fuera del diccionario, para probar en Fase 3 que añadirla al key-store
(`mifare keys add`) hace que el barrido la recupere sin recompilar.

Registrar UID de cada tarjeta junto a su JSON para trazabilidad (no capturado aún;
se puede leer con `bombercat tags mifare sector 0 A <keyA>` una vez abierta).

---

## 0.6 — Formato de log serial ASCII-only

Definido en [`serial_log_format.md`](serial_log_format.md). Resumen: toda salida del
barrido on-device usa marcadores existentes (`:clave valor`, `+OK`/`-ERR`), hex ASCII
en mayúsculas, `-` para huecos, y **claves indexadas por sector** (`:mifare_check_s0`, …)
para no colisionar en el dict del `DeviceLink` del host — mismo patrón que
`:mifare_key0/1/2`. Nunca emitir bytes no-ASCII (gotcha del log serial).

---

## Decisiones pendientes (heredadas del plan, a cerrar antes de Fase 3)

- Política de fusión diccionario embebido ⊕ key-store: known-first vs custom-first
  (Tarea 3.5).
- ¿`mifare check` persiste automáticamente las claves recuperadas? (Tarea 3.6) —
  confirmar comportamiento deseado con el usuario.
