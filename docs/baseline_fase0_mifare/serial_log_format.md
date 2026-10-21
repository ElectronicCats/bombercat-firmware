# Formato de log serial ASCII-only — barrido `mifare check` on-device (Fase 1)

> Tarea 0.6. Define la salida serial del comando on-device para que la Fase 1
> la implemente y la Fase 4 (host) la parsee sin ambigüedad.

## Reglas duras

1. **Solo ASCII imprimible.** Nada de bytes crudos ni UTF-8 en el log serial
   (gotcha conocido: bytes no-ASCII rompen el parseo del host y los visores serie).
   Los datos binarios (claves, bloques) van en **hex mayúsculas**.
2. **Convención de marcadores existente** (la que ya usa `BomberCatControl` y el resto
   del sketch): líneas de datos `:<clave> <valor>`, terminadores `+OK [texto]` /
   `-ERR <texto>`. El comando emite su propio terminador.
3. **Claves indexadas, no repetidas.** El `DeviceLink.command()` del host colapsa
   líneas `:clave valor` que compartan la misma clave en un dict (quedaría solo la
   última). Igual que `emitKnownKeys()` usa `:mifare_key0/1/2`, el barrido usa una
   clave por sector: `:mifare_check_s0`, `:mifare_check_s1`, …
4. **Huecos explícitos.** Clave no recuperada → `-` (guión), nunca vacío ni ceros
   (restricción transversal #6: huecos honestos).

## Formato propuesto

Una línea de datos por sector, más una línea de estadística, más terminador:

```
:mifare_check_s0 <keyA_hex12|-> <keyB_hex12|->
:mifare_check_s1 <keyA_hex12|-> <keyB_hex12|->
...
:mifare_check_sN <keyA_hex12|-> <keyB_hex12|->
:mifare_check_stat attempts=<n> naive=<n> recovered=<r>/<total>
+OK
```

Ejemplo (sector 0 abierto en A y B por defecto; sector 3 hueco en B):

```
:mifare_check_s0 FFFFFFFFFFFF FFFFFFFFFFFF
:mifare_check_s3 A0A1A2A3A4A5 -
:mifare_check_stat attempts=2514 naive=79264 recovered=29/32
+OK
```

Errores (tarjeta retirada a mitad, timeout, fallo I²C) → terminador `-ERR`:

```
-ERR card removed, tap a card again
```

## Correspondencia con el host (`baseline.json`, Fase 4)

| Campo serial | Campo JSON de `check.py` |
|---|---|
| `:mifare_check_sN <A> <B>` | `sectors[N].key_a` / `key_b` (`-` ⇢ `null`) |
| `attempts=` | `stats.attempts` (pin de regresión: **no debe superar** baseline) |
| `naive=` | `stats.naive_attempts` |
| `recovered=r/total` | `recovered` / `total` |

El `attempts=` on-device debe ser **≤** el `stats.attempts` del `baseline.json`
del host (criterio de aceptación global #2: no aumentar el nº de auths).

### consumption por el host (Fase 4, tarea 4.1 — implementado)

`bombercat tags mifare check --mode device` consume **este** formato: envía una
sola línea `mifare check --sectors N [--keys k1,k2,…]` y parsea la respuesta
consolidada (`modules/tags/mifare/device_sweep.py` en `bombercat-tools`).

- El **contador de auths pasa a ser el del firmware**: en modo device el pin
  `attempts ≤ 66` se lee de `:mifare_check_stat attempts=…`, no del recuento de
  líneas `mifare auth` que hace el host. Es el mismo número de autenticaciones
  reales contra la tarjeta, contado por quien las emite.
- El `recovered=r/total` del firmware cuenta **slots (sector, tipo de clave)**,
  igual que el `recovered` del host (2 slots por sector).
- Un token que no sea una clave de 12 hex se trata como **hueco**, nunca como
  una clave adivinada.
- Si el firmware no conoce el comando (`-ERR unknown mifare subcommand`) o
  contesta sin datos de barrido, el host cae al barrido comando-a-comando
  (fallback) en modo `auto`, y falla con un error claro en modo `device`.
- La auto-prueba de la Fase 2 emite las mismas líneas `:mifare_check_sN` pero
  **sin** línea de stat: es un barrido distinto (diccionario embebido, sin
  `--keys`), no la respuesta del comando `mifare check`.

### lectura de trailer (Fase 4, tarea 4.4 — implementado)

Tras el barrido, el firmware hace **una pasada más**: por cada sector que el
diccionario abrió con Key A pero **no** con Key B, lee el *trailer* con esa Key A
y se lleva el Key B que la tarjeta devuelva en claro. No es un ataque
Crypto-1 (el PN7150 nunca expone nonces/paridad): es una **lectura** del
trailer, y solo la dan las tarjetas cuyos access bits dejan el Key B legible
con Key A (configuración de transporte).

Es exactamente la misma pasada que hace el host (`check.py`'s
`_trailer_read_pass`), con las mismas reglas — el Key B solo se acepta cuando
los access bits dicen "key A" (no "key A or B"), y un Key B de ceros se
declara **no recuperado** en vez de darse por bueno. La lógica de access bits
está replicada en el firmware (`MifareAccessBits`, un port de `access_bits.py`)
y la paridad se **verifica** con un test nativo
(`bombercat-tools/tests/test_mifare_parity.py`), no se afirma en un comentario.

La línea de stat gana un campo:

```
:mifare_check_stat attempts=66 naive=1024 recovered=32/32 trailer=0
```

- `trailer=` es el número de lecturas de trailer que hizo el barrido. Su
  presencia le dice al host que **el dispositivo ya hizo la pasada**: el host
  no la repite (serían un round-trip USB por sector para nada). Un firmware
  viejo no tiene ese campo → el host hace su propia pasada, como siempre.

Cuando la pasada recupera un Key B, el firmware **reemite** la línea del sector
con la Key B ya rellena (el host se queda con la última línea por sector):

```
:mifare_check_s0 A0A1A2A3A4A5 AABBCCDDEEFF
```

### línea de stat del barrido (Fase 4, Sesión 11)

```
:mifare_check_stat attempts=79 naive=1024 recovered=32/32 trailer=0 cached=0
                 auth_ms=1229 reselect_ms=6177 reset_ms=5085 detect_ms=1092 trailer_ms=0
```

- `attempts=` / `naive=` / `recovered=` — como hasta ahora (el pin de no
  regresión es `attempts ≤ 66` en la `card_1k`).
- `trailer=` — lecturas de trailer que hizo el barrido (ver arriba).
- `cached=0|1` — `1` cuando la respuesta viene del **barrido en caché**: el
  firmware ya había barrido esa tarjeta (la auto-prueba de detección lo hace
  con el mismo diccionario) y **no repite el trabajo**. El host lo dice en
  pantalla; con `cached=1` **no se ha emitido ninguna autenticación nueva**.
- `auth_ms` / `reselect_ms` / `reset_ms` / `detect_ms` / `trailer_ms` — el
  reparto del reloj de pared, **medido en la placa**:
  - `auth_ms`: tiempo dentro de la autenticación Crypto-1 (≈16 ms);
  - `reselect_ms`: tiempo dentro del re-select que sigue a una clave
    equivocada (≈78 ms), repartido en
  - `reset_ms`: el re-arm completo del lector (≈65 ms) y
  - `detect_ms`: la espera a que la tarjeta vuelva a ser detectada (≈14 ms).

  Con estas cifras se puede comparar el barrido del host con el on-device
  **sin cronómetro**: los dos emiten el mismo número de autenticaciones, así
  que la diferencia se atribuye al reparto, no a una impresión.

### `mifare timing [reset]` (Fase 4, Sesión 11)

Contadores acumulados del board, para medir sin cronómetro:

```
:mifare_timing attempts=79 reselects=78 auth_ms=1231 reselect_ms=6177
                reset_ms=5085 detect_ms=1092 trailer_ms=0
                det_calls=80 det_ok=80 det_timeout=0 det_ntf=0
```

- `det_calls` / `det_ok` / `det_timeout` / `det_ntf` — diagnóstico de la
  detección: cuántas esperas, cuántas encontraron la tarjeta, cuántas
  expiraron y cuántas notificaciones ajenas se drenaron. Sirven para
  distinguir "la tarjeta se fue" de "se perdió la notificación".

### el dump on-device (Fase 4, tarea 4.4 — implementado)

```
:mifare_dump_s0 <hex128|-> <A|B|-> [motivo]
:mifare_dump_s1 - - nokey
:mifare_dump_stat read=1 failed=1 total=2
:mifare_card0 <hex32> uid=<hex8> sak=<hex2> atqa=<hex4> bcc=<hex2> bcc_ok=<0|1>
+OK
```

- Una línea por sector: los 4 bloques en hex (128 chars) o `-` si el sector
  es un hueco, la clave que lo abrió (`A`/`B`) y — cuando no se pudo leer — el
  motivo (`nokey`, `readfail`, `removed`). **Los huecos se declaran, nunca se
  rellenan con ceros.**
- El firmware **sustituye las claves recuperadas en el trailer** (la tarjeta
  nunca devuelve la Key A, y a menudo tampoco la Key B), igual que hace el
  dump del host (`display.py`'s `_substitute_trailer_keys`): los dos dumps
  llevan los mismos bytes.
- `:mifare_card0` lleva el bloque 0 **crudo** más su disección. El host lo
  re-parsea con su propio `block0.py` — la misma lógica que el firmware
  aplicó (`MifareBlock0`, un port de `block0.py`, con paridad verificada por
  test nativo) — así que ambos lados llegan al mismo veredicto. El firmware
  además contrasta el UID del bloque 0 con el UID de anticolisión y avisa si
  difieren (tarjeta clonada/magic).
- El dump usa las claves que el **último barrido** recuperó (el firmware las
  guarda en RAM), así que la tarjeta se lee **una vez**: no hay segundo
  barrido ni un round-trip por sector.

### modo standalone (Fase 4, tarea 4.4 — implementado)

`mifare standalone [on|off]` (flag persistido con el key-store):

```
+OK standalone on
```

Con el modo standalone **encendido**, al detectar una tarjeta el firmware hace
la cadena completa por su cuenta — **detectar → barrido → dump → emitir →
almacenar** — sin PC conectado:

1. la auto-prueba barre los sectores (como siempre);
2. la pasada de trailer recupera las Key B que se pueden leer;
3. el firmware cede el control (`control.poll()`) **entre pasos**, nunca
   dentro de uno: un comando que llegue a mitad de dump tocaría la sesión de
   tarjeta que el dump está usando, así que `mifare ...` se rechaza con
   `-ERR busy - the card workflow is running` mientras la cadena corre;
4. se emite el dump (`mifare_dump_sN` + `mifare_dump_stat` + `mifare_card0`);
5. se guardan las claves propias confirmadas (si `mifare keys autostore on`).

El comando `mifare check --dump` hace la cadena (barrido + dump) en **un solo
comando**, para el host que sí está conectado; `mifare dump` a secas usa las
claves del último barrido.


## Notas de implementación (Fase 1)

- Emitir cada línea `:mifare_check_sN` **en cuanto el sector se resuelve** (streaming),
  no acumular en RAM los 16–40 sectores: el host puede ir parseando y hay feedback
  visible en barridos largos.
- `control.poll()` debe seguir corriendo durante el barrido (restricción #4): la
  emisión serial no bloquea, pero el bucle de auth sí debe ceder control por iteración.
- El contador `attempts=` cuenta auths reales (Tarea 1.8), para verificar contra baseline.

---

## Key-store persistente (Fase 3)

> Formato de `mifare keys ...` — el almacén de claves propias en QSPI. Mismas reglas
> duras (ASCII, marcadores `:`/`+`/`-`, claves indexadas, huecos explícitos).

### Listado — `mifare keys` (o `mifare keys list`)

```
:mifare_key0 default_ff FFFFFFFFFFFF
:mifare_key1 default_00 000000000000
:mifare_key2 default_a0a1a2 A0A1A2A3A4A5
:mifare_key3 custom 112233445566
:mifare_key4 custom A1B2C3D4E5F6
+OK
```

- **Un único índice correlativo**: `:mifare_key0..2` son las claves compiladas en el
  firmware; `:mifare_key3..` son las guardadas en QSPI, en el orden en que se añadieron.
- El host las lee con un bucle `while f"mifare_key{i}" in data` (ver
  `bombercat-tools/modules/tags/mifare/cli.py`), así que **las claves guardadas
  aparecen en la tabla del host sin ningún cambio en el host**.
- Con el almacén vacío la salida es exactamente la de antes (3 líneas): sin
  regresión para el host actual.
- No hace falta tarjeta: el key-store es una ajustes del dispositivo.

### Mutaciones

| Comando | Salida | Notas |
|---|---|---|
| `mifare keys add <key_hex12>` | `+OK added 112233445566` | 12 hex chars. Rechaza duplicados y claves ya presentes en el diccionario embebido (`-ERR key is already in the built-in dictionary`). |
| `mifare keys remove <key_hex12>` | `+OK removed 112233445566` | Por valor. |
| `mifare keys remove <index>` | `+OK removed 112233445566` | Por índice **del listado**: `0..2` son las claves compiladas (no se pueden borrar → `-ERR built-in default keys cannot be removed`), `3+` son las guardadas. |
| `mifare keys clear` | `+OK key store cleared` | Borra todas las claves guardadas (las compiladas no se tocan). |
| `mifare keys autostore [on\|off]` | `+OK autostore on` | Persiste automáticamente las claves **propias** que un barrido confirme. El flag persiste con el almacén. |

Un argumento de 12 caracteres se interpreta SIEMPRE como clave hex; cualquier otro
argumento numérico se interpreta como índice del listado.

### Errores

```
-ERR key is already in the built-in dictionary
-ERR key is already stored
-ERR key store is full
-ERR key is not in the key store
-ERR built-in default keys cannot be removed
-ERR index out of range
-ERR could not persist the key store (flash write failed)
```

### Política de fusión con el diccionario (Tarea 3.5)

**Custom-first.** Las claves guardadas se prueban **antes** del diccionario embebido
de 32 claves: una clave que el usuario añadió porque abrió una tarjeta en el campo
es una apuesta mucho mejor que un valor por defecto genérico. Las claves que el
barrido va confirmando se anexan después, conservando el reuso *known-first*.

Con el almacén **vacío** el barrido es bit a bit el de la Fase 1, así que el pin
`attempts <= 66` (card_1k) se mantiene.

### Persistencia y desgaste (Tarea 3.7)

- Un único registro TDBStore (`"mifarekeys"`) sobre la **misma** instancia de
  `ConfigStore` (montar un segundo `FlashIAPBlockDevice` sobre la misma región
  colisionaría).
- El registro es un POD de tamaño fijo (195 B) con un byte de versión: un registro
  de otra versión se rechaza y el almacén arranca vacío, en vez de leerse mal.
- `add`/`remove`/`clear` reescriben el registro completo → **una escritura de flash
  por comando**, y **ninguna** si el comando no cambia nada (p. ej. `autostore on`
  cuando ya estaba `on`).
- El primer arranque tras flashear formatea el TDBStore: puede tardar unos cientos
  de ms. Conviene hacerlo con el lector en reposo.
- `autostore` (Tarea 3.6) escribe **como máximo una vez por barrido**, y solo si
  confirmó alguna clave nueva **fuera** del diccionario (las del diccionario no se
  guardan: ya están cubiertas).
