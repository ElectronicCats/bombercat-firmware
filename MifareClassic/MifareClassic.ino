/**
 * BomberCat MifareClassic - Mifare Classic card reader (Phase 1 skeleton).
 *
 * Polls the onboard PN7150 in reader mode; whenever a Mifare Classic card
 * enters the field, reports its UID over USB serial as a structured ":tag"
 * event (same wire format as DetectTags). Authentication and block
 * read/write (Phase 2) and the "mifare ..." REPL commands (Phase 3) are not
 * wired in yet - see MIFARE_CLASSIC_PLAN.md.
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

// Function prototypes
String getHexCompact(const byte *data, const uint32_t numBytes);
const char *getProtocolName(unsigned char protocol);
void emitTagEvent(uint32_t tsMs, const char *tech, const char *protocol,
                  const String &uidHex);
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
