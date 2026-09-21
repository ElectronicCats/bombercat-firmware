# BomberCatCore

Reusable Arduino library that is the foundation for the NFCGate relay firmware
(see [`../../docs/NFCGATE_PLAN.md`](../../docs/NFCGATE_PLAN.md)). It is a **local library**:
`#include <BomberCatCore.h>` from any sketch in this repo, or include a single
module header directly.

Target: **Arduino Mbed OS RP2040** core (`mbed_rp2040`). The persistence layer
uses mbed `TDBStore` / `FlashIAPBlockDevice`, which are only available there.

## Modules (Fases 2-4)

| Header | Class / API | Responsibility |
|---|---|---|
| `Log.h` | `Log`, `LOG_ERROR/WARN/INFO/DEBUG` | Level-gated logging over a `Stream`. Replaces the scattered `if (debug) …` blocks. Levels are `LogLevel::None/Error/Warn/Info/Debug` (PascalCase: the PN7150 lib `#define ERROR`, so an all-caps enum member would be mangled by the preprocessor). |
| `HexUtils.h` | `HexUtils::toString`, `HexUtils::print` | Hex dump formatting (factored from `getHexRepresentation` / `printData`). |
| `NfcController.h` | `NfcController` | Wrapper over `Electroniccats_PN7150`: `beginReaderMode()`, `beginEmulationMode()`, `reset()`, `waitForTag()`, `readerTransceive()`, `cardReceive()` / `cardSend()`. Setup failures **return false** instead of hanging. |
| `ConfigStore.h` | `ConfigStore`, `RelayConfig`, `RelayRole` | Persistent WiFi + NFCGate relay config (SSID/pass, server host/port, session byte, role) on `TDBStore`. |
| `NfcGateCodec.h` | `NfcGateCodec::makeNfcData/encodeFrame/decodeServerData`; aliases `NfcData`, `ServerData`, `NfcSource`, `NfcType`, `NfcOpcode` | **Arduino-free** codec for the NFCGate wire format: builds/parses the length-prefixed `ServerData{NFCData}` frames. No sockets — pure bytes, so it is host-testable (see below). Short aliases tame the very long generated nanopb names. |
| `NfcGateLink.h` | `NfcGateLink` | TCP transport to `nfcgate-server` over an Arduino `Client&` (WiFiNINA `WiFiClient` on device). `connect()`, `send()`, `sendControl()` (SYN/ACK/FIN), non-blocking `poll()` / `receive()`. Owns the asymmetric framing (`[4B len BE][1B session][payload]` c→s); delegates protobuf to `NfcGateCodec`. WiFi *association* stays in the sketch. |
| `RelayEngine.h` | `RelayEngine` | Glue over `NfcController` + `NfcGateLink`: `begin()` (NFC bring-up + connect + `OP_SYN` session join), non-blocking `loop()`, `stop()` (`OP_FIN`). Owns the SYN/ACK handshake and the **READER**-role relay loop (command in → card transceive → response out). CARD role is a stub (Fase 5). No WiFiNINA dependency — WiFi stays in the sketch. |
| `FlashIAPLimits.h` | `mbed::getFlashIAPLimits()` | Computes the usable flash region past the sketch (vendored from the relay sketches). |
| `MagStripe.h` | `MagStripe`, `MagStripe::classic()` / `forwardOnly()` | MagSpoof F2F magnetic-stripe emulation engine (blink/playBit/playTrack/storeRevTrack), factored from the identical copies in `WiFiWebServer/magspoof.ino`, `MagSpoofMqtt`, `MagspoofCVSAttack` (classic waveform) and `magspoof/magspoof.ino` (forward-only). Pins/timing + the two differing knobs (leading-zero count, reverse pass) come from `Config`; each sketch keeps only its own trigger/UX glue. |
| `TagReader.h` | `TagReader::hexCompact`, `protocolName`, `emitTagEvent` | PN7150 tag helpers, factored from the byte-identical `getHexCompact`/`getProtocolName`/`emitTagEvent` in `DetectTags`, `DetectReaders` and `MifareClassic`. Pure formatting/mapping over the PROT_* constants and the bombercat-tools `:tag` wire format; complements `HexUtils` (which stays the human-readable "0x.." dump). |
| `proto/…` | `NFCData`, `ServerData` | NFCGate wire messages, generated with nanopb in Fase 1. See [`proto/UPSTREAM.md`](proto/UPSTREAM.md). |
| `pb*.{h,c}` | nanopb runtime | Vendored nanopb 0.4.9.1 runtime (`pb.h`, `pb_common`, `pb_encode`, `pb_decode`), zlib-licensed — see `NANOPB_LICENSE.txt`. Kept flat in `src/` so the generated `proto/*.pb.h` resolve `#include <pb.h>` via the library's include path. |

Coming in later phases: CARD-role relay (Fase 5), `SerialControl`.

## Contract: every new firmware MUST mount BomberCatControl

**Binding rule, not a suggestion.** Any new sketch added to this repo (root
folder + `<name>/<name>.ino`) MUST instantiate `BomberCatControl` (see
[`src/BomberCatControl.h`](src/BomberCatControl.h)) and wire up all four of the
following before the sketch is considered done:

| # | Component | What it is |
|---|---|---|
| 1 | `ping` | Built into `BomberCatControl`; answers `+OK bombercat`. No sketch code required beyond instantiating the class. |
| 2 | `info` | Built in; answers `:fw <version>` / `:fw_name <name>` / `:state <state>` / `+OK`. The sketch supplies `fwVersion`/`fwName` to the constructor and, optionally, a `state()` callback. |
| 3 | `identify` | Built in (LED blink on `LED_BUILTIN`) unless the sketch overrides it with an `identify()` callback for a device-specific cue. |
| 4 | `hook command` | The `Callbacks::command(verb, args)` callback. Any verb the base REPL does not recognize (`ping`/`info`/`identify`) is forwarded here. This is where a firmware's own protocol lives (`:tag`, `:mifare`, `run`/`stop`, or an entirely custom dispatcher). |

This is **not optional infrastructure** — `bombercat-tools` (the host CLI) and
the release flasher (`flash_bombercat.sh`) use the `ping`/`info`/`identify`
triad over USB serial to auto-detect, catalogue, and disambiguate BomberCat
boards. A firmware that skips `BomberCatControl` is invisible to that
tooling: it will not be auto-detected, `fw list`/`fw flash` will not
recognize it, and a user with two boards plugged in has no way to `identify`
which is which. There is no case where a firmware talks to
`bombercat-tools` correctly without this REPL — the four components above
are the entire discovery contract.

### Reference case: EMVy's `PING`/`ping` reconciliation

`EMVyBomberCat` (see
[`../../docs/INTEGRACION_EMVYBOMBERCAT.md`](../../docs/INTEGRACION_EMVYBOMBERCAT.md))
is the concrete case that motivated writing this rule down. Its upstream
protocol already used `PING → PONG` for its own APDU-passthrough handshake —
a **different, uppercase, colliding verb** that `bombercat-tools` does not
understand and that shadows the lowercase `ping → +OK bombercat` the CLI
actually probes for. Left as-is, the board would never be auto-detected as a
BomberCat.

The required fix — and the pattern every new firmware must replicate — is:

1. Mount `BomberCatControl` for the standard triad (`ping`/`info`/`identify`),
   exactly as any other firmware does.
2. Move the firmware-specific protocol (EMVy's `SCAN`/`APDU:`/`EMU:`/…) behind
   the `Callbacks::command` hook instead of a bespoke serial dispatcher that
   competes for the same verbs.
3. Resolve the verb collision at the source, not by working around it:
   `PING`/`PONG` is renamed/aliased in `emvyctl` so it no longer collides with
   the CLI's `ping`. `BomberCatControl` owns the lowercase verb space;
   anything a device-specific protocol needs that overlaps it must yield.

The result is identical in shape to `MifareClassic/MifareClassic.ino`, which
already does this correctly for its own extra `mifare ...` verbs: it wires
`Callbacks::command = bomberCatCommand` and lets everything that is not
`ping`/`info`/`identify` fall through to its own handler. Any firmware
carrying a device-specific serial protocol — EMVy's included — follows this
same shape, never a parallel, competing REPL.

### How to mount BomberCatControl in a new firmware

```cpp
#include <BomberCatControl.h>

BomberCatControl control(Serial, FW_VERSION, FW_NAME); // 1: fwVersion/fwName -> `info`

bool myCommand(const char *verb, char *args) {
  // 4: handle this sketch's own verbs here; emit your OWN +OK/-ERR.
  // Return false for anything you don't recognize either.
  return false;
}

const char *myState() { return "idle"; } // 2: optional, feeds `info`'s :state

void setup() {
  Serial.begin(115200);
  BomberCatControl::Callbacks cb;
  cb.state = myState;       // optional — omit to report "idle"
  cb.command = myCommand;   // required for any firmware with its own verbs
  control.setCallbacks(cb);
  control.begin();          // announces "+OK bombercat ready"
}

void loop() {
  control.poll(); // must run every iteration — never call anything blocking
                   // without also calling poll() first, or the host handshake stalls
}
```

Non-negotiable details:

- `control.poll()` must be called on **every** `loop()` iteration, including
  while the sketch is otherwise busy (waiting for a card, running a
  non-blocking state machine, etc.). A blocking `delay()`/`while(1)` between
  polls stalls `ping`/`info`/`identify` and looks, to the host CLI, like a
  disconnected board.
- Register the firmware's slug in `bombercat-tools`' firmware catalog so the
  name reported by `info`/used in `descriptions.json` matches what the CLI
  expects (see EMVy's pending `emvybombercat` slug registration in the
  integration doc above).
- Do not invent a second `ping`/`info`/`identify` in the sketch's own
  dispatcher. If a device-specific protocol already defines one of these
  verbs (as EMVy's `PING` did), it is the one that must change.

## Dependencies

- **Electronic Cats PN7150** (`Electroniccats_PN7150`) — install via Library
  Manager.
- **nanopb runtime** — **vendored** in `src/` (`pb*.{h,c}`), so no Library
  Manager entry is needed. (nanopb is *not* published to the Arduino Library
  Manager; it is only referenced there as a dependency name, which cannot be
  resolved — hence vendoring.) Every `.c`/`.cpp` under `src/` is compiled when
  the library is used, so this is required even before `NfcGateLink` exists.
- mbed `TDBStore` / `FlashIAPBlockDevice` — provided by the `mbed_rp2040` core.

## Building / verifying

There is no separate build step for the library. To smoke-test that it compiles,
open **File ▸ Examples ▸ BomberCatCore ▸ CoreSelfTest** (after making
`firmware/core` visible to the IDE, e.g. symlink it into your
`Arduino/libraries/`), select the **Electronic Cats BomberCat** board, and
compile (the ✓ button — no upload needed). Or with `arduino-cli`:

```sh
arduino-cli compile -b electroniccats:mbed_rp2040:bombercat \
  --library firmware/core \
  firmware/core/examples/CoreSelfTest
```

`CoreSelfTest` exercises every public symbol (including a `NfcGateCodec`
round-trip and `NfcGateLink` over a `WiFiClient`); it is a compile check, not a
functional relay. Fase 2 was verified building clean against
`electroniccats:mbed_rp2040` 2.0.0 + `Electronic Cats PN7150` 3.1.1 (~112 KB
flash / 45 KB RAM); re-run the command above after the Fase 3 additions.

### Host test for the wire format (no board, no RF)

`NfcGateLink`'s wire format is validated off-device by compiling the **actual**
`NfcGateCodec.cpp` + vendored nanopb with a host compiler and running a
reader↔card loopback against a local `nfcgate-server`:

```sh
tools/testserver/run.sh                       # terminal 1: server on :5566
tools/testserver/codec_hosttest/build_and_run.sh   # terminal 2: g++ + loopback
```

A green `CODEC HOST TEST PASSED` proves the bytes the RP2040 will emit are
accepted and relayed by the real server (and that server frames decode back to
the original APDUs). RF/PN7150 are not involved — this is the Fase 3 / §6 "mock"
verification. See [`../../tools/testserver/codec_hosttest/`](../../tools/testserver/codec_hosttest/).

## Notes on fidelity to the legacy sketches

`NfcController` mirrors the exact call sequences of `host_Relay_NFC` /
`client_Relay_NFC` with two deliberate differences, so host/client can migrate
onto it later:

1. NCI bring-up failures return `false` (the sketches did `while (1);`).
2. `readerTransceive()` sends then waits for **one** response frame with a
   timeout; it does not reproduce the legacy double-`cardModeReceive()` in
   `seekTrack2()`. Use `raw()` if you need a byte-for-byte legacy sequence.
