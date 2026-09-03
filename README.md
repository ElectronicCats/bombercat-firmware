# BomberCat Firmware

Arduino firmware collection for the [BomberCat](https://github.com/ElectronicCats/BomberCat)
— an RP2040-based security research board with an onboard PN7150 NFC front-end and an
ESP32/NINA WiFi co-processor.

---

## Repository layout

```
bombercat-firmware/
├── core/                   # BomberCatCore — shared Arduino library (NFCGate relay stack)
├── NFCGate/                # ★ Main relay firmware (NFCGate-compatible, both READER + CARD roles)
├── DetectTags/               # NFC tag reader / UID dumper
├── DetectReaders/            # NFC reader detector / fingerprinter (security sensor)
├── magspoof/               # Magnetic-stripe emulator (single card, button-triggered)
├── MagspoofCVSAttack/      # MagSpoof variant that replays a CSV track dataset
├── MagSpoofMqtt/           # Networked MagSpoof — receives tracks via MQTT over WiFi
├── WiFiWebServer/          # All-in-one web UI: NFC read/clone + MagSpoof from a browser
├── client_Relay_NFC/       # Legacy MQTT relay — CARD/HCE side (superseded by NFCGate)
├── host_Relay_NFC/         # Legacy MQTT relay — READER side  (superseded by NFCGate)
├── ESP32SerialPassthroughFlash/ # Utility: transparent RP2040 → ESP32 serial bridge for flashing
├── docs/                   # Design documents (latency analysis, communication redesign)
├── descriptions.json       # Machine-readable firmware descriptions (used by CI release assets)
├── flash_bombercat.sh      # Interactive flash helper (sets up toolchain, compiles, uploads)
├── VERSION                 # Firmware version string
└── .github/workflows/      # CI: build-firmware.yml + pre-commit.yml
```

---

## Firmwares

### NFCGate *(primary — relay)*

Role-selectable [NFCGate](https://github.com/nfcgate/nfcgate)-compatible relay endpoint.
Built on `BomberCatCore`; both **READER** and **CARD/HCE** roles are fully implemented and
validated end-to-end on real hardware:

- **Path A** — two BomberCats through a live `nfcgate-server`: full EMV transaction relayed
  end-to-end (2026-08-17).
- **Path B** — against the NFCGate Android app, both B1 (BomberCat reader + phone HCE) and B2
  (BomberCat card + phone reader) (2026-08-19).
- **Per-transaction latency** brought down to **~4.5 s** (see
  [`docs/LATENCIA_OPTIMIZACION.md`](docs/LATENCIA_OPTIMIZACION.md)).
- **APDU capture** — `:apdu` tap + `bombercat capture` write a Wireshark-openable `.pcapng`.

See [`NFCGate/README.md`](NFCGate/README.md) for build, configuration, and usage details.

### DetectTags

Lightweight NFC diagnostic firmware. Polls the PN7150 RF field continuously and prints the
technology and UID of any detected tag (ISO 14443-A/B, ISO 15693, FeliCa, …) over USB serial.
No relay or emulation logic.

### DetectReaders

Security-sensor counterpart to DetectTags. The PN7150 runs in card-emulation (listen) mode
presenting an emulated contactless card; when an external reader or terminal enters the field
and activates it, the firmware reports the reader's polling technology, protocol and interface
over USB serial, exchanges APDUs during a bounded dwell window, and fingerprints the first
command (PPSE → EMV payment terminal; known AIDs → Visa/Mastercard/Amex/NDEF readers). Each
detection is emitted as a structured `:reader` serial event — same marker conventions as
DetectTags' `:tag`, ready for `bombercat-tools` — alongside human-readable text. The board
answers the standard `ping`/`info`/`identify` control REPL and re-arms automatically after
every session.

### magspoof

Basic magnetic-stripe emulator. Drives the on-board H-bridge coil to reproduce the
electromagnetic field of a real card; a standard magstripe reader picks up the emulated tracks
wirelessly. Track data is compiled in; a button press triggers playback.

### MagspoofCVSAttack

MagSpoof variant that replays a sequence of tracks loaded from a `data.csv` dataset. Suitable
for research demonstrations (e.g. gift-card/PIN-space brute-force style attacks) where many
candidate values are emitted in turn.

### MagSpoofMqtt

Networked MagSpoof. Connects to WiFi via the onboard ESP32/NINA module, subscribes to an MQTT
broker, and emulates the received track data through the MagSpoof coil. Enables remote /
automated triggering. Requires WiFi and broker credentials in `arduino_secrets.h`.

### WiFiWebServer

All-in-one firmware. Turns the BomberCat into a self-hosted WiFi access point serving an
HTML/JS/CSS web interface directly from the RP2040. Lets the user read NFC tags, clone a
card's ID, and trigger MagSpoof emulation from a browser — no serial console needed.

### client\_Relay\_NFC / host\_Relay\_NFC *(legacy)*

Original MQTT-based NFC relay endpoints (CARD/HCE side and READER side respectively).
**Superseded by `NFCGate`**, which unifies both roles on the `BomberCatCore` library over TCP
and adds a proper CLI. Kept for historical reference.

### ESP32SerialPassthroughFlash

Maintenance utility. Bridges RP2040 USB serial → ESP32 UART so you can send AT commands,
inspect bootloader output, or flash new firmware onto the ESP32 (e.g. with Espressif's Flash
Download Tool) through the RP2040.

---

## Host tool

The `bombercat` CLI drives the NFCGate relay firmware over USB serial — WiFi / relay config,
start/stop, status, APDU capture, and device management for multiple boards. It lives in its
own repository:

**<https://github.com/ElectronicCats/bombercat-tools>**

The wire protocols it consumes (binary framing, opcodes, the SerialControl text-shell grammar)
are defined and owned by this firmware repo.

---

## CI

Every push and pull request triggers **build-firmware** (`.github/workflows/build-firmware.yml`):
each sketch is compiled with `arduino-cli` against `electroniccats:mbed_rp2040:bombercat` and
converted to `.uf2`. On a published release, the `.uf2` files and `descriptions.json` are
attached as release assets.

Pre-commit hooks (`clang-format`, `check-yaml`, `trailing-whitespace`, conventional commits)
are configured in `.pre-commit-config.yaml`.

---

## Hardware repository

Board design (KiCad, BOM, mechanical files):

**<https://github.com/ElectronicCats/BomberCat>**

---

## Disclaimer
>[!IMPORTANT]
>BomberCat is a wireless penetration testing tool intended **solely for use in authorized security audits, where such usage is permitted by applicable laws and regulations**. Before utilizing this tool, it is crucial to ensure compliance with all relevant legal requirements and obtain appropriate permissions from the relevant authorities.
>
>The board **does not provide** any means or authorization to utilize credit cards or engage in any financial transactions that are not legally authorized. **Electronic Cats holds no responsibility for any unauthorized use of the tool or any resulting damages**.

---

## How to contribute <img src="https://electroniccats.com/wp-content/uploads/2018/01/fav.png" height="35"><img src="https://raw.githubusercontent.com/gist/ManulMax/2d20af60d709805c55fd784ca7cba4b9/raw/bcfeac7604f674ace63623106eb8bb8471d844a6/github.gif" height="30">

Contributions are welcome!

Please read the [**Contribution Manual**](https://github.com/ElectronicCats/electroniccats-cla/blob/main/electroniccats-contribution-manual.md)
which will show you how to contribute your changes to the project.

✨ Thanks to all our [contributors](https://github.com/ElectronicCats/bombercat-firmware/graphs/contributors)! ✨

See [**Electronic Cats CLA**](https://github.com/ElectronicCats/electroniccats-cla/blob/main/electroniccats-cla.md)
for more information.

See the [**community code of conduct**](https://github.com/ElectronicCats/electroniccats-cla/blob/main/electroniccats-community-code-of-conduct.md)
for a vision of the community we want to build and what we expect from it.

---

## License

This project is licensed under the terms in the [`LICENSE`](LICENSE) file.
