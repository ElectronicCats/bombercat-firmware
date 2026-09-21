# EMVyBomberCat — firmware "navaja suiza" para pruebas de tarjetas

Firmware unificado para BomberCat (Electronic Cats, RP2040 + NINA WiFi + PN7150 NFC)
que combina, en una sola imagen, lo del lector EMV propio con capacidades oficiales,
todo manejable por **serie** desde EMVyController.

## Modos (por comando serie, @115200)

| Comando serie              | Modo   | Qué hace                                              |
|----------------------------|--------|------------------------------------------------------|
| `ping` / `info` / `identify` | control | Descubrimiento (Discovery Contract) → `+OK bombercat` / `:fw_name…+OK` / `+OK`+LED |
| `SCAN <centavos>`          | EMV    | Flujo EMV contactless → `JSON_START/…/JSON_END`      |
| `WAIT [ms]`                | APDU   | Espera tarjeta ISO-DEP (`READY:` / `ERR:NOCARD`)     |
| `APDU:<hex>` / `RELEASE`   | APDU   | Passthrough de APDU (`RESP:<hex+SW>`)                |
| `TAG` / `TAGS`             | TAGS   | Lee un tag NFC → `TAG:<proto> TECH:<t> UID:<hex>`    |
| `MAG:<track1>\|<track2>`   | MAG    | Emula un swipe de banda magnética (magspoof) → `OK`  |
| `EMU:<hex>`                | NDEF   | Emula un tag NFC Type 4 (NDEF); observable y cancelable |
| `CARDSCAN`                 | EMV    | Lee una tarjeta EMV por NFC y la guarda en **RAM** del firmware |
| `EMUEMV[:aid\|pan\|exp\|t2\|RAM]` | EMV | Emula tarjeta EMV: sin args=Visa prueba; `:hex…`=captura del host; `:RAM`=la escaneada con CARDSCAN |
| `STOP`                     | EMU    | Detiene la emulación en curso (NDEF o EMV) → `EMU:DONE` |
| `REBOOT` / `RESET`         | —      | Reinicia el MCU (`NVIC_SystemReset`); el USB se re-enumera |

**Emulación NDEF observable** (`EMU:<hex>`): el firmware bombea el card-emulation loop él mismo
(`cardModeReceive`/`cardModeSend` + `T4T_NDEF_EMU_Next`), así que reporta por serie **cada APDU del
lector** — qué app/fichero selecciona (`EMU:RX SELECT-APP/-CC/-NDEF`) y qué offset lee
(`EMU:RX READ off=<n> len=<n>`), la respuesta (`EMU:TX <hex>`) y `EMU:MSG-SENT` al entregar el mensaje.
No bloquea: arranca (`EMU:START`) y sigue hasta `STOP`/`RELEASE`, otro `EMU:`, `REBOOT`, o el auto-stop
de seguridad (180 s) → `EMU:DONE sent=<k> reason=<...>`.

**Emulación de tarjeta EMV** (`EMUEMV`): en vez de un tag NDEF, responde al flujo EMV contactless de un
**terminal de pago** (`SELECT PPSE → FCI`, `SELECT AID → FCI con PDOL`, `GPO → AIP+AFL`, `READ RECORD`,
`GENERATE AC`) con datos canned, para que el terminal **avance y revele su configuración**. Reporta
`EMU:RX SELECT-PPSE`, `EMU:RX SELECT-AID <hex> (ESQUEMA)`, y sobre todo el **PDOL del GPO decodificado**
(`  PDOL TTQ(9F66)=… Monto(9F02)=… Pais(9F1A)=… Divisa(5F2A)=… UN(9F37)=…`) y el CDOL1 del GENERATE AC.
**No** genera un criptograma válido (sin la clave del emisor): el objetivo es **extraer el perfil del
terminal** (qué pide y con qué parámetros), no aprobar un pago. Con `EMUEMV:<aid>|<pan>|<exp>|<track2>`
(hex; vacío = default) presenta los datos de una **captura real** en vez de la Visa de prueba; el firmware
confirma `EMU:CARD aid=.. pan=.. exp=.. t2=..`. `emvy bombercat emv-emulate [--card cap.json]` o la Fuente
"EMV · tarjeta de pago" (con selector de captura) en la pestaña Fuzzing.

**Escanear → RAM → reemular (on-device)**: `CARDSCAN` lee una tarjeta por NFC y la guarda en la RAM del
firmware (`EMU:SCANNED aid=.. pan=..`); luego `EMUEMV:RAM` la presenta al terminal — todo en la placa, sin
PC ni archivos, hasta reiniciar. `emvy bombercat cardscan` + `emvy bombercat emv-emulate --ram`, o en la
pestaña Fuzzing los botones **Escanear→RAM (BomberCat)** / **Escanear→memoria** y las fuentes EMV
"(tarjeta en RAM del BomberCat)" / "(tarjeta escaneada en memoria de la app)".

También levanta el **AP WiFi `EMVyBomberCat`** (clave `bombercat`, `http://192.168.4.1`) con el
panel web del lector EMV (branding "parte de EMVy Controller"; `/scan`, `/test`, `/log`).

Desde EMVy — interacción **directa** con el firmware (mismo `Transceiver` que cualquier lector):
- `emvy bombercat dump [--raw] [--save nombre]` — volcado completo de la tarjeta
- `emvy bombercat write record|binary|data|append ...` — **escribe** en la tarjeta
- `emvy bombercat analyze` — capacidades/CVM/ODA (AIP, cert. del emisor…)
- `emvy bombercat read` / `-r bombercat discover|apdu|info …` (EMV JSON + passthrough genérico)
- `emvy bombercat cmd TAG` (lee un tag) · `emvy bombercat cmd "MAG:%B4111...^X^...?|;4111...=...?"`
  (emite banda)
- `emvy fuzz ndef emit <plantilla>` (emula un tag NDEF; imprime la actividad del lector APDU-a-APDU)
- `emvy bombercat reboot` (reinicia la placa; reconecta el lector después)

Todos aceptan `--port /dev/ttyACMx` para fijar el puerto si hay más de un dispositivo serie.

## Discovery Contract (plano de control conforme)

Este firmware implementa el **BomberCatControl Discovery Contract v1.0**
(`docs/BomberCatControl-Discovery-Contract.md`, normativo) en su **plano de control**,
para que cualquier host conforme —el CLI de `bombercat-tools`, la GUI y la TUI de EMVy—
lo descubra e identifique de forma **idéntica**:

| Estímulo (host→device) | Respuesta (device→host)                    | Cláusula |
|------------------------|--------------------------------------------|----------|
| `ping` (o `PING`/`Ping`) | `+OK bombercat`  (sin data lines)        | §5, C-6/C-7 |
| `info`                 | `:fw_name emvybombercat` · `:fw <v>` · `:role emv-multitool` · `+OK` | §6.1, C-8 |
| `identify`             | `+OK` inmediato + parpadeo de LED asíncrono (~2 s) | §6.2, C-9 |
| `<verbo desconocido>`  | `-ERR unknown command <verb>`              | §6.3.3, C-11 |

- El verbo es **case-insensitive** (el dispatcher compara en mayúsculas), así que
  `ping`/`PING`/`Ping` producen la misma respuesta (§5.1) — esto reconcilia el `PING`
  (mayúsculas) del reader de EMVy con el `ping` (minúsculas) del CLI del vendor.
- El parpadeo de `identify` **no bloquea** el plano de control: la respuesta `+OK` sale
  al instante y el LED se bombea desde `loop()` (`identifyPump`, §6.2.1).

**Desviación conocida (transitoria).** Los verbos **operativos** (`WAIT`/`APDU:`→`RESP:`,
`SCAN`→`JSON_*`, `EMU:`/`EMUEMV`→`EMU:*`, `MAG:`/`RELEASE`/`STOP`→`OK`) conservan el
**dialecto histórico** en vez del framing `+OK`/`-ERR` del contrato (§2.7/§3), por
retrocompatibilidad con `emvy/readers/bombercat.py`, que aún habla ese dialecto. Migrarlos
al framing del contrato es **Fase 2** y depende de que el host se actualice primero (PR en
curso). El descubrimiento (ping/info/identify/verbo-desconocido) —lo que hace que la placa
aparezca con ✓ en `device list`— ya es conforme.

## Estructura (sketch multi-archivo — Arduino concatena los .ino)

- `EMVyBomberCat.ino` — base: lector EMV + passthrough + servidor web + dispatcher serie.
- `modes_tags.ino`    — modo TAGS (reusa el objeto `nfc` PN7150).
- `modes_mag.ino`     — modo MAG (magspoof, pines A=6/B=7).

## Compilar y flashear

### Requisitos (wiki: "First Steps with Arduino")
1. Arduino IDE.
2. Board Manager URL: `https://electroniccats.github.io/Arduino_Boards_Index/package_electroniccats_index.json`
3. Instalar **"Electronic Cats Mbed OS RP2040 Boards"**.
4. Librerías: **Electroniccats_PN7150**, **WiFiNINA**, **ArduinoJson**.

### Opción A — Arduino IDE
Abre `EMVyBomberCat.ino`, selecciona la placa BomberCat, y sube (Upload).

### Opción B — script del repo (flujo oficial)
Como con cualquier otro firmware de este monorepo, la imagen oficial se compila y flashea
como `.uf2` (BOOTSEL) con el script en la raíz del repo:
```sh
../flash_bombercat.sh -f EMVyBomberCat        # compila y sube
../flash_bombercat.sh -f EMVyBomberCat -c     # solo compila (no sube)
```

### Opción C — TUI de EMVy (compilación local del usuario)
Pestaña **BomberCat** → elige el sketch → **Compilar** / **Compilar y subir (picotool)**. Este
flujo sube por **picotool** (`bombercat.upload.tool=picotool`; reset a 1200-bps + carga directa
del `.elf`/`.bin` vía `arduino-cli upload`) en vez de `.uf2`, y es el que usa quien compila su
propio firmware localmente desde la TUI de EMVyController — no es el flujo de las imágenes
oficiales del repo (esas van por `.uf2`/BOOTSEL, ver Opción B).

**Permisos USB (Linux) para picotool**: picotool/`arduino-cli upload` necesitan acceso crudo al
dispositivo RP2040 en modo BOOTSEL (`idVendor=2e8a`). Sin una regla `udev`, falla con *"No
accessible RP2040 devices... try sudo or check your permissions"* aunque el touch-reset a
1200-bps sí funcione. Arréglalo una vez:
```sh
echo 'SUBSYSTEM=="usb", ATTRS{idVendor}=="2e8a", MODE="0666"' | sudo tee /etc/udev/rules.d/99-pico.rules
sudo udevadm control --reload-rules && sudo udevadm trigger
```
**Alternativa sin permisos**: convierte el `.elf` a `.uf2` con la herramienta del paquete de la placa
y cópialo a la unidad `RPI-RP2` montada (funciona siempre, sin udev ni sudo — es lo que hace
`flash_bombercat.sh` de la Opción B):
```sh
ELF2UF2=$(find ~/.arduino15 -iname elf2uf2 | head -1)
"$ELF2UF2" build/EMVyBomberCat.ino.elf build/EMVyBomberCat.ino.uf2
cp build/EMVyBomberCat.ino.uf2 /run/media/$USER/RPI-RP2/   # placa en BOOTSEL (doble-tap RESET)
```

### Flasheo rápido de imágenes OFICIALES (sin compilar)
Para intercambiar al firmware oficial (NFCGate/magspoof/DetectTags…):
```sh
emvy bombercat fw list
emvy bombercat fw flash NFCGate
```
(La BomberCat debe entrar en modo bootloader — doble-tap RESET si no entra sola.)

> Uso autorizado (pentest/lab con tarjetas propias). NFC/magspoof requieren el
> hardware del BomberCat (PN7150 + bobina); en otros RP2040 sólo corre el
> andamiaje WiFi/serie.
