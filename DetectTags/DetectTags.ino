/**
 * Example detect tags and show their unique ID
 * Authors:
 *        Salvador Mendoza - @Netxing - salmg.net
 *        For Electronic Cats - electroniccats.com
 *
 * Updated by Francisco Torres - Electronic Cats - electroniccats.com
 *
 *  March 2020
 *
 * This code is beerware; if you see me (or any other collaborator
 * member) at the local, and you've found our code helpful,
 * please buy us a round!
 * Distributed as-is; no warranty is given.
 */

#include "Electroniccats_PN7150.h"
#include <BomberCatControl.h>
#include <HexUtils.h>

#define BOMBERCAT_FW_VERSION "1.2.0.0"

#define PN7150_IRQ (11)
#define PN7150_VEN (13)
#define PN7150_ADDR (0x28)

Electroniccats_PN7150
    nfc(PN7150_IRQ, PN7150_VEN, PN7150_ADDR,
        PN7150); // creates a global NFC device interface object, attached to
                 // pins 11 (IRQ) and 13 (VEN) and using the default I2C address
                 // 0x28,specify PN7150 or PN7160 in constructor

// BomberCat serial-control REPL (ping/info/identify) so bombercat-tools can
// discover and identify this board over USB serial.
BomberCatControl control(Serial, BOMBERCAT_FW_VERSION, "detecttags");

// Function prototypes
String getHexCompact(const byte *data, const uint32_t numBytes);
const char *getProtocolName(unsigned char protocol);
void emitTagEvent(uint32_t tsMs, const char *tech, const char *protocol,
                  const String &uidHex, const String &extra = "");
void displayCardInfo();

void setup() {
  Serial.begin(115200);
  while (!Serial)
    ;
  Serial.println("Detect NFC tags with PN7150/60");

  Serial.println("Initializing...");
  if (nfc.connectNCI()) { // Wake up the board
    Serial.println("Error while setting up the mode, check connections!");
    while (1)
      ;
  }

  if (nfc.configureSettings()) {
    Serial.println("The Configure Settings is failed!");
    while (1)
      ;
  }

  // Read/Write mode as default
  if (nfc.configMode()) { // Set up the configuration mode
    Serial.println("The Configure Mode is failed!!");
    while (1)
      ;
  }
  nfc.startDiscovery(); // NCI Discovery mode
  Serial.println("Waiting for an Card ...");

  control.begin(); // announce readiness to the host CLI
}

void loop() {
  control.poll(); // service host CLI commands (ping/info/identify)

  if (nfc.isTagDetected()) {
    displayCardInfo();

    // It can detect multiple cards at the same time if they use the same
    // protocol
    if (nfc.remoteDevice.hasMoreTags()) {
      nfc.activateNextTagDiscovery();
      Serial.println("Multiple cards are detected!");
    }

    Serial.println("Remove the Card");
    // Blocking: PN7150 library's presenceCheck() loop has no callback/return
    // point to poll() the control REPL from, so the CLI is unresponsive here
    // until the tag is physically removed. Fixing this needs a change in the
    // Electronic_Cats_PN7150 library itself (deferred, see
    // IMPLEMENTATION_PLAN_ImproveDetectTags.md Phase 6 / FW-3).
    nfc.waitForTagRemoval();
    Serial.println("Card removed!");

    Serial.println("Restarting...");
    // Electroniccats_PN7150::reset() only re-runs configureSettings() (RF /
    // tag-detector chip config) while remoteDevice.getProtocol() is still
    // UNDETERMINED - i.e. only before the very first tag is ever detected -
    // so after the first tag every later nfc.reset() alone left the PN7150's
    // tag detector never reconfigured and no further tag was ever detected
    // again. Calling nfc.configureSettings() ourselves works around it, but
    // ONLY when placed after stopDiscovery() (matching reset()'s own
    // internal order) - calling it before stopDiscovery() (i.e. before
    // reset(), which was the first attempt at this fix) silently had no
    // effect, confirmed on hardware. See IMPLEMENTATION_PLAN_
    // ImproveDetectTags.md Phase 6 / FW-3 for the full trace-based
    // diagnosis.
    nfc.stopDiscovery();
    nfc.configureSettings();
    nfc.configMode();
    nfc.startDiscovery();
    Serial.println("Waiting for a Card...");
    delay(500);
  }
}

// Compact uppercase hex with no "0x"/separators, e.g. "041A2B3C" - the
// :tag wire format's uid_hex field (see modules/tags/parser.py
// TagParser._hex_compact in bombercat-tools). "-" means no UID available.
String getHexCompact(const byte *data, const uint32_t numBytes) {
  if (numBytes == 0) {
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
  switch (protocol) {
  case nfc.protocol.T1T:
    return "T1T";
  case nfc.protocol.T2T:
    return "T2T";
  case nfc.protocol.T3T:
    return "T3T";
  case nfc.protocol.ISODEP:
    return "ISODEP";
  case nfc.protocol.NFCDEP:
    return "NFCDEP";
  case nfc.protocol.ISO15693:
    return "ISO15693";
  case nfc.protocol.MIFARE:
    return "MIFARE";
  default:
    return "UNKNOWN";
  }
}

// Structured event consumed by bombercat-tools' TagParser: once it sees one
// ":tag" line it stops parsing the legacy prose below permanently, so this
// is emitted alongside (not instead of) the existing Serial prints. `extra`
// is optional trailing "k=v" pairs (space-separated), e.g. "attrib=1122".
void emitTagEvent(uint32_t tsMs, const char *tech, const char *protocol,
                  const String &uidHex, const String &extra) {
  Serial.print(":tag ");
  Serial.print(tsMs);
  Serial.print(' ');
  Serial.print(tech);
  Serial.print(' ');
  Serial.print(protocol);
  Serial.print(' ');
  Serial.print(uidHex);
  if (extra.length() > 0) {
    Serial.print(' ');
    Serial.print(extra);
  }
  Serial.println();
}

void displayCardInfo() { // Funtion in charge to show the card/s in te field
  char tmp[16];

  while (true) {
    const char *protocolName = getProtocolName(nfc.remoteDevice.getProtocol());

    switch (nfc.remoteDevice.getProtocol()) { // Indetify card protocol
    case nfc.protocol.T1T:
    case nfc.protocol.T2T:
    case nfc.protocol.T3T:
    case nfc.protocol.ISODEP:
      Serial.print(" - POLL MODE: Remote activated tag type: ");
      Serial.println(nfc.remoteDevice.getProtocol());
      break;
    case nfc.protocol.ISO15693:
      Serial.println(" - POLL MODE: Remote ISO15693 card activated");
      break;
    case nfc.protocol.MIFARE:
      Serial.println(" - POLL MODE: Remote MIFARE card activated");
      break;
    default:
      Serial.println(" - POLL MODE: Undetermined target");
      return;
    }

    switch (nfc.remoteDevice.getModeTech()) { // Indetify card technology
    case (nfc.tech.PASSIVE_NFCA):
      Serial.println("\tTechnology: NFC-A");
      Serial.print("\tSENS RES = ");
      Serial.println(HexUtils::toString(nfc.remoteDevice.getSensRes(),
                                        nfc.remoteDevice.getSensResLen()));

      Serial.print("\tNFC ID = ");
      Serial.println(HexUtils::toString(nfc.remoteDevice.getNFCID(),
                                        nfc.remoteDevice.getNFCIDLen()));

      Serial.print("\tSEL RES = ");
      Serial.println(HexUtils::toString(nfc.remoteDevice.getSelRes(),
                                        nfc.remoteDevice.getSelResLen()));

      emitTagEvent(millis(), "NFC-A", protocolName,
                   getHexCompact(nfc.remoteDevice.getNFCID(),
                                 nfc.remoteDevice.getNFCIDLen()));
      break;

    case (nfc.tech.PASSIVE_NFCB): {
      Serial.println("\tTechnology: NFC-B");
      const unsigned char *sensRes = nfc.remoteDevice.getSensRes();
      unsigned char sensResLen = nfc.remoteDevice.getSensResLen();
      Serial.print("\tSENS RES = ");
      Serial.println(HexUtils::toString(sensRes, sensResLen));

      const unsigned char *attribRes = nfc.remoteDevice.getAttribRes();
      unsigned char attribResLen = nfc.remoteDevice.getAttribResLen();
      Serial.println("\tAttrib RES = ");
      Serial.println(HexUtils::toString(attribRes, attribResLen));

      // SENSB_RES (ISO14443-3B ATQB): byte 0 = 0x50, bytes 1-4 = PUPI
      // (NFCID0) - the closest thing Type B has to a UID. Confirmed against
      // Electroniccats_PN7150::RemoteDevice::setInfo() (RemoteDevice.cpp),
      // which copies the raw ATQB frame into SensRes untouched.
      String pupiHex = "-";
      if (sensResLen >= 5) {
        Serial.print("\tPUPI = ");
        Serial.println(HexUtils::toString(&sensRes[1], 4));
        pupiHex = getHexCompact(&sensRes[1], 4);
      }

      String extra = "attrib=" + getHexCompact(attribRes, attribResLen);
      emitTagEvent(millis(), "NFC-B", protocolName, pupiHex, extra);
      break;
    }

    case (nfc.tech.PASSIVE_NFCF): {
      Serial.println("\tTechnology: NFC-F");
      const unsigned char *sensRes = nfc.remoteDevice.getSensRes();
      unsigned char sensResLen = nfc.remoteDevice.getSensResLen();
      Serial.print("\tSENS RES = ");
      Serial.println(HexUtils::toString(sensRes, sensResLen));

      bool is212 = (nfc.remoteDevice.getBitRate() == 1);
      Serial.print("\tBitrate = ");
      Serial.println(is212 ? "212" : "424");

      // SENSF_RES (JIS X6319-4): byte 0 = response code, bytes 1-8 = NFCID2
      // (IDm) - FeliCa's UID equivalent. Same setInfo() source as above.
      String idmHex = "-";
      if (sensResLen >= 9) {
        Serial.print("\tIDm = ");
        Serial.println(HexUtils::toString(&sensRes[1], 8));
        idmHex = getHexCompact(&sensRes[1], 8);
      }

      String extra = is212 ? "bitrate=212" : "bitrate=424";
      emitTagEvent(millis(), "NFC-F", protocolName, idmHex, extra);
      break;
    }

    case (nfc.tech.PASSIVE_NFCV):
      Serial.println("\tTechnology: NFC-V");
      Serial.print("\tID = ");
      Serial.println(HexUtils::toString(nfc.remoteDevice.getID(),
                                        sizeof(nfc.remoteDevice.getID())));

      Serial.print("\tAFI = ");
      Serial.println(nfc.remoteDevice.getAFI());

      Serial.print("\tDSF ID = ");
      Serial.println(nfc.remoteDevice.getDSFID(), HEX);

      // ID is a fixed 8-byte field (RemoteDevice.h); getID() has no length
      // getter, unlike the other technologies.
      emitTagEvent(millis(), "NFC-V", protocolName,
                   getHexCompact(nfc.remoteDevice.getID(), 8));
      break;

    default:
      break;
    }

    // It can detect multiple cards at the same time if they are the same
    // technology
    if (nfc.remoteDevice.hasMoreTags()) {
      Serial.println("Multiple cards are detected!");
      if (!nfc.activateNextTagDiscovery()) {
        break; // Can't activate next tag
      }
    } else {
      break;
    }
  }
}
