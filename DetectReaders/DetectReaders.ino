/**
 * Example detect NFC readers / terminals (security sensor mode)
 * Authors:
 *        Salvador Mendoza - @Netxing - salmg.net
 *        For Electronic Cats - electroniccats.com
 *
 * Updated by Francisco Torres - Electronic Cats - electroniccats.com
 *
 *  August 2026
 *
 * This code is beerware; if you see me (or any other collaborator
 * member) at the local, and you've found our code helpful,
 * please buy us a round!
 * Distributed as-is; no warranty is given.
 *
 * The PN7150 runs in card-emulation (LISTEN) mode presenting an emulated
 * contactless card. Any reader/terminal entering the field activates it,
 * which is reported both as human-readable text and as one structured
 * ":reader" serial event consumed by bombercat-tools (same leading-marker
 * convention as DetectTags' ":tag" events):
 *
 *   :reader <ts_ms> <tech> <protocol> [intf=<name>] [apdu=<hex|->]
 *           [label=<slug>] [n=<count>]
 *
 * Beyond the RF-layer classification (technology, protocol, interface), the
 * first APDU the reader sends is captured and fingerprinted (see
 * classifyFirstApdu()): a PPSE SELECT identifies an EMV payment terminal,
 * well-known AIDs identify payment apps / NDEF readers.
 */

#include "Electroniccats_PN7150.h"
#include <BomberCatControl.h>

#define BOMBERCAT_FW_VERSION "1.2.0.0"

#define PN7150_IRQ (11)
#define PN7150_VEN (13)
#define PN7150_ADDR (0x28)

// Ceiling on each isTagDetected() wait: keeps control.poll() serviced at
// least every ~DETECT_POLL_MS while listening (DetectTags' REPL instead goes
// unanswered during its blocking waitForTagRemoval(); here the whole session
// stays responsive because the APDU dwell polls control.poll() itself).
#define DETECT_POLL_MS (50)
// Post-activation window to exchange APDUs with the detected reader before
// tearing the session down and re-arming discovery.
#define DWELL_WINDOW_MS (3000)
// Max reader commands captured per session (the first one drives the label).
#define MAX_APDUS (8)
// Practical cap for one captured command frame (SELECT PPSE is ~30 B).
#define APDU_MAX (128)

Electroniccats_PN7150
    nfc(PN7150_IRQ, PN7150_VEN, PN7150_ADDR,
        PN7150); // creates a global NFC device interface object, attached to
                 // pins 11 (IRQ) and 13 (VEN) and using the default I2C address
                 // 0x28, specify PN7150 or PN7160 in constructor

// BomberCat serial-control REPL (ping/info/identify) so bombercat-tools can
// discover and identify this board over USB serial. Slug must match the id
// registered later in bombercat-tools/modules/core/firmwares.py.
BomberCatControl control(Serial, BOMBERCAT_FW_VERSION, "detectreaders");

static bool readerSessionActive = false; // drives control.state()

// Function prototypes
String getHexCompact(const byte *data, const uint32_t numBytes);
const char *getProtocolName(unsigned char protocol);
const char *getListenTechName(unsigned char modeTech);
const char *getInterfaceName(unsigned char interface);
void emitReaderEvent(uint32_t tsMs, const char *tech, const char *protocol,
                     const String &extra);
bool receiveApduBounded(byte *payload, uint8_t &payloadLen,
                        uint32_t deadlineMs);
bool containsBytes(const byte *haystack, uint32_t haystackLen,
                   const uint8_t *needle, uint32_t needleLen);
const char *classifyFirstApdu(const byte *apdu, uint32_t len, String &aidHex);
void handleReaderDetected();
void reArmEmulation();
const char *controlState();

void setup() {
  Serial.begin(115200);
  while (!Serial)
    ;
  Serial.println("Detect NFC readers with PN7150/60 (emulation mode)");

  Serial.println("Initializing...");
  // Bring-up order mirrors NfcController::beginEmulationMode()
  // (core/src/NfcController.cpp), which replicates the known-good legacy
  // sequence client_Relay_NFC.ino:1407 (`setEmulationMode()` then a trailing
  // full re-arm). connectNCI() is what pulses VEN and starts Wire, so it must
  // come first.
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

  if (nfc.configMode()) {
    Serial.println("The Configure Mode is failed!!");
    while (1)
      ;
  }
  nfc.startDiscovery();

  // Switch the discovery role to EMULATION (arms the listen/CARD side).
  if (!nfc.setEmulationMode()) {
    Serial.println("The Emulation Mode setup failed!");
    while (1)
      ;
  }

  // Re-arm discovery cleanly in the now-selected EMULATION mode. Mirrors the
  // trailing reset() of beginEmulationMode(): without it the chip is left
  // armed only by setEmulationMode()'s internal reset(), which skips
  // configureSettings() once a protocol is latched, leaving the RF front-end
  // not cleanly in listen mode (no terminal can activate the emulated card).
  if (nfc.stopDiscovery()) {
    Serial.println("The Stop Discovery is failed!");
    while (1)
      ;
  }
  if (nfc.configureSettings()) {
    Serial.println("The Configure Settings is failed!");
    while (1)
      ;
  }
  if (nfc.configMode()) {
    Serial.println("The Configure Mode is failed!!");
    while (1)
      ;
  }
  nfc.startDiscovery();

  Serial.println("Waiting for a Reader ...");

  BomberCatControl::Callbacks cb;
  cb.state = controlState;
  control.setCallbacks(cb);
  control.begin(); // announce readiness to the host CLI
}

void loop() {
  control.poll(); // service host CLI commands (ping/info/identify)

  if (!readerSessionActive && nfc.isTagDetected(DETECT_POLL_MS)) {
    // In EMULATION mode an RF_INTF_ACTIVATED_NTF means a READER activated our
    // emulated card. remoteDevice then carries the listen-side classification:
    // getModeTech() has the MODE_LISTEN bit (0x80) set plus the polled
    // technology, getProtocol()/getInterface() tell ISODEP (payment terminals,
    // wallets) from NFCDEP (P2P initiators). NOTE: the metadata getters
    // (getSensRes/getNFCID/...) return NULL in listen mode -
    // RemoteDevice::setInfo() switches on the raw modeTech byte and only
    // parses POLL activations - so classification relies on
    // protocol/interface/APDU only (IMPLEMENTATION_PLAN_DetectReaders.md T3).
    handleReaderDetected();
  }
}

// One reader session: classify the RF activation, capture/fingerprint the
// first APDU(s) inside a bounded dwell window, emit the ":reader" event and
// re-arm emulation discovery for the next reader.
void handleReaderDetected() {
  readerSessionActive = true;
  const uint32_t tsMs = millis();
  const unsigned char modeTech = nfc.remoteDevice.getModeTech();
  const unsigned char protocol = nfc.remoteDevice.getProtocol();
  const unsigned char intf = nfc.remoteDevice.getInterface();
  const char *techName = getListenTechName(modeTech);
  const char *protocolName = getProtocolName(protocol);
  const char *interfaceName = getInterfaceName(intf);

  // Human-readable prose alongside the structured event: any line not
  // starting with ':' '+' '-' is ignored by the CLI (log noise).
  Serial.println(" - LISTEN MODE: Remote reader activated emulated card");
  Serial.print("\tTechnology: ");
  Serial.println(techName);
  Serial.print("\tProtocol: ");
  Serial.println(protocolName);
  Serial.print("\tInterface: ");
  Serial.println(interfaceName);

  // --- Dwell window: capture up to MAX_APDUS reader commands ---------------
  // Uses receiveApduBounded() (IRQ-gated polling of the public readData()
  // primitive) instead of the library's cardModeReceive(), whose internal
  // getMessage(2000) would freeze control.poll() for up to 2 s per command
  // (IMPLEMENTATION_PLAN_DetectReaders.md T4). Every captured command gets a
  // bare STATUS OK back so ordinary readers keep the transaction alive.
  static unsigned char STATUSOK[] = {0x90, 0x00};
  byte firstApdu[APDU_MAX];
  uint32_t firstApduLen = 0;
  uint8_t apduCount = 0;

  const uint32_t deadline = millis() + DWELL_WINDOW_MS;
  while (apduCount < MAX_APDUS) {
    int32_t remain = (int32_t)(deadline - millis());
    if (remain <= 0) {
      break;
    }

    byte payload[APDU_MAX];
    uint8_t payloadLen = 0;
    if (!receiveApduBounded(payload, payloadLen, deadline)) {
      break; // field dropped (RF_DEACTIVATE_NTF) or window elapsed
    }

    apduCount++;
    Serial.print("\tAPDU[" + String(apduCount) + "/" + String(MAX_APDUS) +
                 "] = ");
    Serial.println(getHexCompact(payload, payloadLen));

    if (apduCount == 1) { // the first command drives the fingerprint
      memcpy(firstApdu, payload, payloadLen);
      firstApduLen = payloadLen;
    }

    // cardModeSend() is a plain writeData() (no blocking); its return value
    // is an UNINITIALIZED variable in the library - ignored here exactly as
    // the library's own ProcessCardMode() ignores the write status.
    nfc.cardModeSend((unsigned char *)STATUSOK, sizeof(STATUSOK));
  }

  // --- Fingerprint + structured event --------------------------------------
  String aidHex;
  const char *label = (firstApduLen > 0)
                          ? classifyFirstApdu(firstApdu, firstApduLen, aidHex)
                          : "unknown";

  String extra = "intf=" + String(interfaceName);
  extra += " apdu=" + (firstApduLen > 0 ? getHexCompact(firstApdu, firstApduLen)
                                        : String("-"));
  if (aidHex.length() > 0) {
    extra += " aid=" + aidHex;
  }
  extra += " label=" + String(label);
  extra += " n=" + String(apduCount);

  emitReaderEvent(tsMs, techName, protocolName, extra);

  // Let the reader's closing frames (credits / RF_DEACTIVATE_NTF) drain
  // before touching discovery state; a reader still holding the field when
  // the window expired deactivates against the re-arm below.
  {
    const uint32_t drainUntil = millis() + 100;
    byte sink[APDU_MAX];
    while ((int32_t)(millis() - drainUntil) < 0) {
      control.poll();
      if (nfc.hasMessage()) {
        nfc.readData(sink); // discard
      }
    }
  }

  reArmEmulation();
  Serial.println("Waiting for a Reader ...");
  readerSessionActive = false;
}

// Re-arm card-emulation discovery after a reader session.
//
// FW-3-style traceability (mirrors DetectTags.ino's post-tag restart and
// NfcController::cardReArm): the library's reset() only runs
// configureSettings() while remoteDevice.getProtocol() is still UNDETERMINED,
// i.e. only before the very first activation - so calling reset() alone left
// the front-end unreconfigured. We therefore run the explicit sequence
// ourselves, in reset()'s own internal order (stopDiscovery BEFORE
// configureSettings; the opposite order silently had no effect on hardware,
// see DetectTags.ino's FW-3 comment).
//
// KNOWN HARDWARE CAVEAT: NfcController::cardReArm found that even the explicit
// light sequence was INSUFFICIENT to restore a detectable ISO-DEP listen
// target after the first activation ("worked exactly once, dormant
// afterwards") and had to escalate to a FULL bring-up (connectNCI() +
// configureSettings() + configMode() + startDiscovery(), setEmulationMode(),
// final arm). If repeated detections fail here on hardware, replace this
// body with that full sequence - it is isolated in this function precisely to
// make that escalation a one-function change.
void reArmEmulation() {
  bool failed = false;

  if (nfc.stopDiscovery()) {
    Serial.println("Re-arm: stopDiscovery failed");
    failed = true;
  }
  if (nfc.configureSettings()) {
    Serial.println("Re-arm: configureSettings failed");
    failed = true;
  }
  if (nfc.configMode()) {
    Serial.println("Re-arm: configMode failed");
    failed = true;
  }
  nfc.startDiscovery();

  if (failed) {
    Serial.println("Re-arm completed with errors - monitor next detections");
  } else {
    Serial.println("Re-armed. Emulation discovery running.");
  }
}

// Pull ONE reader command (NCI DATA packet) with a wall-clock deadline,
// without the library cardModeReceive()'s blocking getMessage(2000) and its
// useless writeData(Ans,255) garbage write (H2/Fase C pattern from
// NfcController::receiveNoGarbage). Non-DATA frames are skipped: credits
// notifications (0x60 0x06) and similar are ignored, an RF_DEACTIVATE_NTF
// (0x61 0x06) means the reader left the field -> returns false immediately.
// control.poll() is called every spin so ping/info/identify stay live during
// the whole dwell window. Fragmented (>255 B) reader commands are out of
// scope for a detector: only the first fragment would be captured (never
// observed for SELECT-class commands).
bool receiveApduBounded(byte *payload, uint8_t &payloadLen,
                        uint32_t deadlineMs) {
  uint8_t buf[MAX_NCI_FRAME_SIZE];

  while ((int32_t)(millis() - deadlineMs) < 0) {
    control.poll(); // keep the host CLI responsive mid-session

    if (!nfc.hasMessage()) {
      continue; // IRQ low: nothing pending, keep polling until deadline
    }
    uint32_t n = nfc.readData(buf);
    if (n < 3) {
      continue; // header not fully read; treat as noise
    }
    if (buf[0] == 0x00 && buf[1] == 0x00) { // DATA packet = reader command
      uint8_t len = buf[2];
      if (len > APDU_MAX) {
        len = APDU_MAX; // truncate pathological frames
      }
      memcpy(payload, &buf[3], len);
      payloadLen = len;
      return true;
    }
    if (buf[0] == 0x61 && buf[1] == 0x06) {
      return false; // RF_DEACTIVATE_NTF: reader gone, end session early
    }
    // Any other notification (credits, etc.): drop and keep waiting.
  }
  return false; // deadline elapsed
}

// Compact uppercase hex with no "0x"/separators, e.g. "00A404000E..." - the
// :reader wire format's apdu/aid fields (same conventions as DetectTags'
// getHexCompact for :tag uid_hex). "-" means no data available.
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

// Listen-side technology: getModeTech() is (MODE_LISTEN | techBits) in
// emulation mode; strip the mode bit and map the remaining technology nibble
// (values from Tech.h).
const char *getListenTechName(unsigned char modeTech) {
  switch (modeTech & 0x7F) {
  case nfc.tech.PASSIVE_NFCA: // 0
    return "NFC-A";
  case nfc.tech.PASSIVE_NFCB: // 1
    return "NFC-B";
  case nfc.tech.PASSIVE_NFCF: // 2
    return "NFC-F";
  case nfc.tech.ACTIVE_NFCA: // 3
    return "NFC-A";
  case nfc.tech.ACTIVE_NFCF: // 5
    return "NFC-F";
  case nfc.tech.PASSIVE_15693: // 6
    return "NFC-V";
  default:
    return "UNKNOWN";
  }
}

const char *getInterfaceName(unsigned char interface) {
  switch (interface) {
  case nfc.interface.FRAME:
    return "FRAME";
  case nfc.interface.ISODEP:
    return "ISODEP";
  case nfc.interface.NFCDEP:
    return "NFCDEP";
  case nfc.interface.TAGCMD:
    return "TAGCMD";
  case nfc.interface.UNDETERMINED:
  default:
    return "UNDETERMINED";
  }
}

// Structured event consumed by bombercat-tools (future ReadersParser, a twin
// of tags/parser.py TagParser._TAG_EVENT). Same conventions as :tag:
// compact uppercase hex, "-" for unavailable values, trailing "k=v" extras
// space-separated.
void emitReaderEvent(uint32_t tsMs, const char *tech, const char *protocol,
                     const String &extra) {
  Serial.print(":reader ");
  Serial.print(tsMs);
  Serial.print(' ');
  Serial.print(tech);
  Serial.print(' ');
  Serial.print(protocol);
  if (extra.length() > 0) {
    Serial.print(' ');
    Serial.print(extra);
  }
  Serial.println();
}

bool containsBytes(const byte *haystack, uint32_t haystackLen,
                   const uint8_t *needle, uint32_t needleLen) {
  if (needleLen == 0 || haystackLen < needleLen) {
    return false;
  }
  for (uint32_t i = 0; i + needleLen <= haystackLen; i++) {
    if (memcmp(&haystack[i], needle, needleLen) == 0) {
      return true;
    }
  }
  return false;
}

// Fingerprint the reader by its FIRST command (IMPLEMENTATION_PLAN_
// DetectReaders.md §6). Payment terminals open with a PPSE SELECT whose DF
// name ("2PAY.SYS.DDF01" / "1PAY.SYS.DDF01") travels in clear inside the
// C-APDU; wallet/payment apps select well-known AIDs; NDEF-capable readers
// select the NDEF T4T AID. Anything else falls back to "unknown" (with the
// selected AID surfaced as an extra when the command is a SELECT).
const char *classifyFirstApdu(const byte *apdu, uint32_t len, String &aidHex) {
  struct Pattern {
    const uint8_t *bytes;
    uint32_t len;
    const char *label;
  };

  static const uint8_t PPSE_2PAY[] = {'2', 'P', 'A', 'Y', '.', 'S', 'Y',
                                      'S', '.', 'D', 'D', 'F', '0', '1'};
  static const uint8_t PPSE_1PAY[] = {'1', 'P', 'A', 'Y', '.', 'S', 'Y',
                                      'S', '.', 'D', 'D', 'F', '0', '1'};
  static const uint8_t AID_VISA[] = {0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10};
  static const uint8_t AID_MASTERCARD[] = {0xA0, 0x00, 0x00, 0x00,
                                           0x04, 0x10, 0x10};
  static const uint8_t RID_AMEX[] = {0xA0, 0x00, 0x00, 0x00, 0x00, 0x25};
  static const uint8_t AID_NDEF[] = {0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01};

  static const Pattern PATTERNS[] = {
      {PPSE_2PAY, sizeof(PPSE_2PAY), "emv-payment"},
      {PPSE_1PAY, sizeof(PPSE_1PAY), "emv-payment"},
      {AID_VISA, sizeof(AID_VISA), "visa"},
      {AID_MASTERCARD, sizeof(AID_MASTERCARD), "mastercard"},
      {RID_AMEX, sizeof(RID_AMEX), "amex"},
      {AID_NDEF, sizeof(AID_NDEF), "ndef"},
  };
  static const size_t PATTERN_COUNT = sizeof(PATTERNS) / sizeof(PATTERNS[0]);

  aidHex = "";
  if (len >= 2 && apdu[0] == 0x00 && apdu[1] == 0xA4) {
    // SELECT by DF name: CLA INS P1 P2 Lc AID... -> surface the AID even when
    // the label ends up "unknown".
    uint8_t lc = apdu[4];
    uint32_t avail = len - 5;
    uint32_t n = (lc < avail) ? lc : avail;
    if (n > 16) {
      n = 16; // AIDs are <= 16 bytes
    }
    if (n > 0) {
      aidHex = getHexCompact(&apdu[5], n);
    }
  }

  for (size_t i = 0; i < PATTERN_COUNT; i++) {
    if (containsBytes(apdu, len, PATTERNS[i].bytes, PATTERNS[i].len)) {
      return PATTERNS[i].label;
    }
  }
  return "unknown";
}

// Control-plane state reported by `info`: "listening" while armed, and
// "reader-detected" for the whole activation/dwell/re-arm session.
const char *controlState() {
  return readerSessionActive ? "reader-detected" : "listening";
}
