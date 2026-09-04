/**
 * BomberCat MifareClassic - Mifare Classic card reader.
 *
 * Polls the onboard PN7150 in reader mode; whenever a Mifare Classic card
 * enters the field, reports its UID over USB serial as a structured ":tag"
 * event (same wire format as DetectTags), then probes MIFARE_PROBE_BLOCK
 * with each of the built-in default keys and reports the outcome as a
 * ":mifare" event (Decision 3, MIFARE_CLASSIC_PLAN.md - a distinct event
 * type from ":tag" so TagParser stays UID-only). The "mifare ..." REPL
 * commands for on-demand auth/read/write of an arbitrary block (Phase 3) are
 * not wired in yet - see MIFARE_CLASSIC_PLAN.md.
 *
 * Distributed as-is; no warranty is given.
 */

#include <BomberCatControl.h>
#include <HexUtils.h>
#include <NfcController.h>

#include "MifareClassic.h"
#include "MifareCommands.h"

NfcController nfc;

// BomberCat serial-control REPL (ping/info/identify) so bombercat-tools can
// discover and identify this board over USB serial. Slug must match the id
// registered in bombercat-tools/modules/core/firmwares.py.
BomberCatControl control(Serial, BOMBERCAT_FW_VERSION, BOMBERCAT_FW_NAME);

static bool tagSessionActive = false; // drives control.state()

// Block probed automatically on every Mifare Classic detection, matching
// ElectronicCats-PN7150's MifareClassic_read_block.ino example default.
static const uint8_t MIFARE_PROBE_BLOCK = 4;
static const uint8_t *const MIFARE_PROBE_KEYS[] = {
    MIFARE_DEFAULT_KEY_FFFFFF, MIFARE_DEFAULT_KEY_000000,
    MIFARE_DEFAULT_KEY_A0A1A2A3A4A5};
static const uint8_t MIFARE_PROBE_KEY_COUNT = 3;

// Function prototypes
String getHexCompact(const byte *data, const uint32_t numBytes);
const char *getProtocolName(unsigned char protocol);
void emitTagEvent(uint32_t tsMs, const char *tech, const char *protocol,
                  const String &uidHex);
void emitMifareEvent(uint32_t tsMs, const String &uidHex, uint8_t blockNum,
                     const uint8_t *data, uint8_t dataLen, const char *status);
void probeMifareBlock(uint32_t tsMs, const String &uidHex);
void handleTagDetected();
const char *controlState();

void setup() {
  Serial.begin(115200);
  while (!Serial)
    ;
  Serial.println("Mifare Classic reader with PN7150/60");

  Serial.println("Initializing...");
  if (!nfc.beginReaderMode()) {
    Serial.println("Error while setting up reader mode, check connections!");
    while (1)
      ;
  }
  Serial.println("Waiting for a Mifare Classic card...");

  BomberCatControl::Callbacks cb;
  cb.state = controlState;
  control.setCallbacks(cb);
  control.begin(); // announce readiness to the host CLI
}

void loop() {
  control.poll(); // service host CLI commands (ping/info/identify)

  if (nfc.waitForTag()) {
    handleTagDetected();
  }
}

// One tag session: classify the card, emit the ":tag" event for Mifare
// Classic cards, wait for removal and re-arm discovery.
void handleTagDetected() {
  tagSessionActive = true;
  const uint32_t tsMs = millis();
  const unsigned char protocol = nfc.raw().remoteDevice.getProtocol();
  const char *protocolName = getProtocolName(protocol);

  if (protocol == nfc.raw().protocol.MIFARE) {
    Serial.println(" - Found MIFARE card");
    String uidHex = getHexCompact(nfc.raw().remoteDevice.getNFCID(),
                                  nfc.raw().remoteDevice.getNFCIDLen());
    Serial.print("\tUID = ");
    Serial.println(uidHex);
    emitTagEvent(tsMs, "NFC-A", protocolName, uidHex);
    probeMifareBlock(tsMs, uidHex);
  } else {
    Serial.print(" - Found a card, but it is not Mifare Classic (protocol=");
    Serial.print(protocolName);
    Serial.println(")");
  }

  if (nfc.raw().remoteDevice.hasMoreTags()) {
    Serial.println("Multiple cards are detected!");
    nfc.raw().activateNextTagDiscovery();
  }

  Serial.println("Remove the card...");
  // Blocking, same known limitation as DetectTags.ino's waitForTagRemoval()
  // call: the PN7150 library has no callback/return point to poll() the
  // control REPL from here. See DetectTags.ino's FW-3 comment.
  nfc.raw().waitForTagRemoval();
  Serial.println("Card removed!");

  Serial.println("Restarting discovery...");
  // NfcController::reset() unconditionally re-runs connectNCI +
  // configureSettings + configMode + startDiscovery (unlike the PN7150
  // library's own reset(), which skips configureSettings() once a protocol
  // is latched - see DetectTags.ino's FW-3 comment for the full trace).
  nfc.reset();
  Serial.println("Waiting for a Mifare Classic card...");
  tagSessionActive = false;
}

// Compact uppercase hex with no "0x"/separators, e.g. "041A2B3C" - the
// :tag wire format's uid_hex field (see modules/tags/parser.py
// TagParser._hex_compact in bombercat-tools).
String getHexCompact(const byte *data, const uint32_t numBytes) {
  if (numBytes == 0 || data == NULL) {
    return "-";
  }
  char tmp[3];
  String hex;
  for (uint32_t i = 0; i < numBytes; i++) {
    sprintf(tmp, "%02X", data[i] & 0xFF);
    hex += tmp;
  }
  return hex;
}

const char *getProtocolName(unsigned char protocol) {
  const Protocol &proto = nfc.raw().protocol;
  switch (protocol) {
  case proto.T1T:
    return "T1T";
  case proto.T2T:
    return "T2T";
  case proto.T3T:
    return "T3T";
  case proto.ISODEP:
    return "ISODEP";
  case proto.NFCDEP:
    return "NFCDEP";
  case proto.ISO15693:
    return "ISO15693";
  case proto.MIFARE:
    return "MIFARE";
  default:
    return "UNKNOWN";
  }
}

// Structured event consumed by bombercat-tools' TagParser (same conventions
// as DetectTags.ino's emitTagEvent).
void emitTagEvent(uint32_t tsMs, const char *tech, const char *protocol,
                  const String &uidHex) {
  Serial.print(":tag ");
  Serial.print(tsMs);
  Serial.print(' ');
  Serial.print(tech);
  Serial.print(' ');
  Serial.print(protocol);
  Serial.print(' ');
  Serial.println(uidHex);
}

// Control-plane state reported by `info`.
const char *controlState() {
  return tagSessionActive ? "tag-detected" : "scanning";
}

// Structured event for a block probe/read attempt, consumed by a future
// bombercat-tools MifareParser. Kept separate from ":tag" (Decision 3) so
// TagParser's UID-only format is untouched. dataHex is "-" when the block
// wasn't read (e.g. auth failure).
void emitMifareEvent(uint32_t tsMs, const String &uidHex, uint8_t blockNum,
                     const uint8_t *data, uint8_t dataLen, const char *status) {
  Serial.print(":mifare ");
  Serial.print(tsMs);
  Serial.print(' ');
  Serial.print(uidHex);
  Serial.print(' ');
  Serial.print(blockNum);
  Serial.print(' ');
  Serial.print(dataLen > 0 ? getHexCompact(data, dataLen) : "-");
  Serial.print(' ');
  Serial.println(status);
}

// Try each built-in default key (as Key A) against MIFARE_PROBE_BLOCK and
// emit the outcome. Read-only - never attempts a write automatically.
void probeMifareBlock(uint32_t tsMs, const String &uidHex) {
  uint8_t data[MIFARE_BLOCK_SIZE];
  uint8_t dataLen = 0;
  for (uint8_t i = 0; i < MIFARE_PROBE_KEY_COUNT; i++) {
    if (mifareAuthenticate(nfc, MIFARE_PROBE_BLOCK, MIFARE_KEY_A,
                           MIFARE_PROBE_KEYS[i]) &&
        mifareReadBlock(nfc, MIFARE_PROBE_BLOCK, data, &dataLen)) {
      emitMifareEvent(tsMs, uidHex, MIFARE_PROBE_BLOCK, data, dataLen, "ok");
      return;
    }
  }
  emitMifareEvent(tsMs, uidHex, MIFARE_PROBE_BLOCK, nullptr, 0, "auth_fail");
}
