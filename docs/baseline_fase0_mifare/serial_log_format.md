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
                 aborted=0
                 auth_ms=1229 reselect_ms=6177 reset_ms=5085 detect_ms=1092 trailer_ms=0
```

- `attempts=` / `naive=` / `recovered=` — como hasta ahora (el pin de no
  regresión es `attempts ≤ 66` en la `card_1k`).
- `naive=` — la proyección HONESTA del barrido completo: cada slot
  (sector × {A,B}) probando el diccionario entero, sin reutilización ni corte
  temprano. Se declara por adelantado (`sectores × 2 × claves`), no se acumula
  slot a slot, para que un barrido interrumpido siga reportando el coste del
  barrido que debía hacer.
- `aborted=0|1` — `1` cuando el barrido se interrumpió antes de cubrir todos
  los sectores (la tarjeta se fue del campo, o los re-selects se rindieron).
  Las líneas por sector son entonces un resultado **parcial**: los sectores que
  el barrido no alcanzó son desconocidos porque el barrido se detuvo, no
  porque las claves no existan. Un firmware viejo no tiene este campo → el
  host no puede distinguirlo y trata el resultado como completo.
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
:mifare_timing attempts=79 reselects=78 reselect_fails=1 auth_ms=1231
                reselect_ms=6177 reset_ms=5085 detect_ms=1092 trailer_ms=0
                det_calls=80 det_ok=79 det_timeout=1 det_ntf=0
                det_disc=0 det_sel=0 det_deact=0 det_err=0 rst_fail=0
```

- `det_calls` / `det_ok` / `det_timeout` / `det_ntf` — diagnóstico de la
  detección: cuántas esperas, cuántas encontraron la tarjeta, cuántas
  expiraron y cuántas notificaciones ajenas se drenaron. Sirven para
  distinguir "la tarjeta se fue" de "se perdió la notificación".
- `det_disc` / `det_sel` — `RF_DISCOVER_NTF` (0x61 0x03): el chip **encontró**
  la tarjeta pero espera a que el host la **seleccione**. `det_sel` cuenta los
  `RF_DISCOVER_SELECT_CMD` enviados como respuesta. Antes de esto, esa
  notificación se descartaba: la activación (0x61 0x05) no llegaba nunca y la
  espera expiraba como si la tarjeta se hubiera ido.
- `det_deact` — `RF_DEACTIVATE_NTF` (0x61 0x06): la tarjeta se fue.
- `det_err` — respuesta de error del chip (0x41): rechazó una orden.
- `rst_fail` — el **re-arm del lector** falló por I²C. Un re-arm fallido NO es
  "la tarjeta se fue".
- `reselect_fails` — de los re-selects del barrido, cuántos **no** recuperaron
  la tarjeta. Con `det_*` y `rst_fail` dan la causa exacta de un barrido
  interrumpido.

### el re-select y el settle del barrido on-device (corregido)

El barrido on-device hace un re-select **después de cada clave equivocada**
(la autenticación fallida deja la tarjeta en HALT). Dos parámetros deciden si
ese re-select funciona:

- **la ventana de detección** (2000 ms, `MIFARE_CHECK_RESELECT_MS`): la
  tarjeta está en HALT y el PN7150 tiene que despertarla y volver a activarla,
  que tarda más que una re-detección en caliente. Antes el barrido usaba el
  valor por defecto de `waitForTag()` (**500 ms**) —justo el camino que hace
  un re-select tras cada clave fallida era el que menos tiempo le daba a la
  tarjeta— mientras que `mifareReselect()` sí tenía los 2000 ms.
- **el settle** (25 ms, `MIFARE_CHECK_SETTLE_MS`, ajustable en caliente con
  `mifare check --settle <ms>`): el reposo entre el re-select y la siguiente
  autenticación. El camino del host lo recibe gratis en su round-trip USB
  (10-30 ms); el barrido on-device tiene que pedirlo explícitamente. Con 5 ms
  el chip todavía no está listo y la clave CORRECTA se lee como fallo.

Un re-select fallido **no** significa que la tarjeta se fue: el chip puede
perder el despertar de la tarjeta, o el re-init por I²C puede toser, con la
tarjeta ahí mismo. Por eso el re-select se reintenta (3 veces) antes de
creer que la tarjeta se fue — el barrido no puede ser más estricto que la
sonda de retirada (`MIFARE_REMOVAL_MISSES_TO_CONFIRM`), o un solo fallo
tira la tarjeta entera.

Sin estas tres correcciones, una tarjeta que por el camino del host da 15/16
sectores por el camino on-device salía como "1/16 sectores con claves
conocidas": el barrido se rendía a mitad y el host recibía el resultado
parcial como si fuera la tarjeta entera.

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

### el disparador de campo (Fase 4, tarea 4.3 — implementado)

El botón de usuario de la placa (BOM v1.3): **SW2**, rotulado *GPIO*, sobre
RP2040 **GPIO17 = Arduino D5**, activo a LOW contra GND — el mismo botón que
usa el sketch MagSpoof (`MagStripe::classic()` → `pinButton = 5`). El otro
botón, **SW1** (*RESET*), es el pin RUN del RP2040: reinicia la placa, así que
**no** puede ser un disparador. El LED de la placa (LED1) está en GPIO27 =
D15 = `LED_BUILTIN`.

Dos gestos:

- **pulsación corta** → *one-shot*: la cadena corre para la tarjeta que está
  en el campo (el dump usa las claves del barrido ya hecho: **ninguna
  autenticación extra**). Sin tarjeta en el campo, **arma** el one-shot y la
  siguiente detección lo dispara.
- **pulsación larga** (≥ 1200 ms) → alterna el **flag persistente** de modo
  standalone (queda en la flash del key-store; `mifare standalone on|off` es
  exactamente el mismo flag).

El LED dice qué pasó: **1 parpadeo** = pulsación corta aceptada, **2** = modo
standalone armado, **3** = desarmado (o acción fallida). El LED de la placa
también lo usa el `identify` del host: los dos comparten **un** planificador
(`MifareLedBlink`), así que nunca pelean por el pin.

Líneas del log serial:

```
:mifare_trigger short
:mifare_trigger armed
:mifare_trigger run
:mifare_trigger standalone on
:mifare_trigger standalone off
:mifare_trigger ignored busy
:mifare_trigger error flash-write-failed
:mifare_trigger error card-removed
```

Y el estado del disparador, con `mifare trigger` (no necesita tarjeta):

```
:mifare_trigger pin=5 long_ms=1200 armed=0 standalone=0 presses=0 long_presses=0
+OK
```

- `armed=1` → hay un one-shot armado (pulso corto sin tarjeta en el campo).
- `standalone=1` → el modo persistente está encendido.
- `presses` / `long_presses` → los contadores del botón.

El disparador se consulta **en cada iteración de `loop()`**, antes de
cualquier `return` temprano: funciona en todos los estados (escaneando, con
sesión abierta, esperando una retirada, barriendo) y **no bloquea**. Pero el
barrido **bloquea** `loop()` (segundos o minutos según la tarjeta): una
pulsación durante el barrido solo se ve cuando el barrido termina.


### los resultados que guarda la placa (Fase 4, tarea 4.6 — implementado)

En modo standalone nadie está escuchando el puerto serie, así que el resultado
se perdería. El firmware guarda los **últimos 8 resultados en su propia flash**
(la QSPI, a través de la API genérica de blobs del `ConfigStore` — el mismo
TDBStore que usa el key-store): **una escritura por tarjeta**, y el resultado
más antiguo es el que se sobrescribe.

El registro guarda el volcado **con sus huecos y su motivo** (`nokey`,
`readfail`, `removed`): un sector que nunca se abrió se declara, nunca se da
por seguro (restricción transversal #6).

`mifare results` (no necesita tarjeta) lista lo guardado:

```
:mifare_result0 seq=12 ts=34567 uid=AABBCCDD sectors=16 read=15 failed=1
:mifare_result1 seq=11 ts=20100 uid=11223344 sectors=16 read=16 failed=0
:mifare_results_stat slots=8 used=2 seq=12
+OK
```

- `seq=` — contador monótono: cuál es el más reciente.
- `ts=` — el reloj de la placa: **milisegundos desde el arranque** (la placa
  no tiene reloj de tiempo real). El host lo muestra como "uptime".
- `uid=` — el UID que la placa leyó (hex).
- `sectors=` / `read=` / `failed=` — los sectores de la tarjeta, los que se
  leyeron y los que no.

`mifare results show <n>` (0 = el más reciente) devuelve un resultado guardado
**en el mismo formato que un volcado en vivo**, para que el host lo parseé con
el código que ya tiene:

```
:mifare_result0 seq=12 ts=34567 uid=AABBCCDD sectors=16 read=15 failed=1
:mifare_dump_s0 <hex128> A
:mifare_dump_s1 - - nokey
:mifare_dump_stat read=1 failed=1 total=2
:mifare_card0 <hex32> uid=<hex8> sak=<hex2> atqa=<hex4> bcc=<hex2> bcc_ok=<0|1>
+OK
```

`mifare results clear` borra todos los resultados guardados.

Y la cadena standalone deja rastro de lo que guardó:

```
:mifare_result_saved seq=12 slot=3 read=15 failed=1
```

o, si la flash falla (el resultado ya salió por serie, así que la lectura no se
pierde — solo la copia que se recogería luego):

```
:mifare_result_saved error flash-write-failed
```

**Sobre el desgaste (medido contra el TDBStore de mbed):** el almacén
**añade** cada escritura al final de la misma área y reescribe el área
**entera** cuando se llena. Así que el anillo **no multiplica por ocho la vida
del flash** — multiplica por ocho el **historial**. El número de borrados es
el que era (un borrado de área por cada ~450 resultados guardados, muy por
debajo de los 100 000 ciclos de borrado del flash), y el valor real del anillo
es que el operador conserva las últimas N tarjetas, no que la flash dure más.

---

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
