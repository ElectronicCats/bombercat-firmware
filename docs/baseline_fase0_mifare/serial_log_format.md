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
