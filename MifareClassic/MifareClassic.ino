/**
 * BomberCat MifareClassic - Mifare Classic card reader.
 *
 * Polls the onboard PN7150 in reader mode; whenever a Mifare Classic card
 * enters the field, reports its UID over USB serial as a structured ":tag"
 * event (same wire format as DetectTags), then probes MIFARE_PROBE_BLOCK
 * with each of the built-in default keys and reports the outcome as a
 * ":mifare" event (Decision 3, MIFARE_CLASSIC_PLAN.md - a distinct event
 * type from ":tag" so TagParser stays UID-only).
 *
 * The card then stays selected in an interactive "mifare session" (instead
 * of immediately blocking on removal) so the host CLI can issue
 * "mifare auth/read/write/sector" REPL commands against it across multiple
 * exchanges - Decision 5's non-blocking card-session requirement, without a
 * new presence-check primitive: the PN7150 keeps a card selected across
 * readerTransceive() calls on its own (proven by the ported
 * MifareClassic_write_block.ino example's auth-then-read-then-write
 * sequence), so the session only needs to keep control.poll() running and
 * auto-close on REPL inactivity (MIFARE_SESSION_IDLE_MS) since there is no
 * cheap non-blocking "is the card still there" check in this library -
 * removal is still only detected via the existing blocking
 * waitForTagRemoval() (see DetectTags.ino's FW-3 comment), now deferred to
 * session close instead of running immediately on every detection.
 *
 * Distributed as-is; no warranty is given.
 */

#include <ctype.h>
#include <string.h>

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

// Interactive "mifare ..." REPL session over an already-selected Mifare
// card. Closes (blocking wait-for-removal + re-arm discovery) after this
// long without a "mifare ..." command, so a forgotten card doesn't wedge the
// reader forever.
static bool mifareSessionOpen = false;
static uint32_t mifareSessionDeadline = 0; // millis() deadline
static const uint32_t MIFARE_SESSION_IDLE_MS = 10000;

// Function prototypes
String getHexCompact(const byte *data, const uint32_t numBytes);
const char *getProtocolName(unsigned char protocol);
void emitTagEvent(uint32_t tsMs, const char *tech, const char *protocol,
                  const String &uidHex);
void emitMifareEvent(uint32_t tsMs, const String &uidHex, uint8_t blockNum,
                     const uint8_t *data, uint8_t dataLen, const char *status);
void probeMifareBlock(uint32_t tsMs, const String &uidHex);
void handleTagDetected();
void openMifareSession();
void closeCardSession();
const char *controlState();
bool bomberCatCommand(const char *verb, char *args);
void handleMifareCommand(char *args);
void handleMifareAuth(char *args);
void handleMifareRead(char *args);
void handleMifareWrite(char *args);
void handleMifareSector(char *args);
void emitKnownKeys();

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
  cb.command = bomberCatCommand;
  control.setCallbacks(cb);
  control.begin(); // announce readiness to the host CLI
}

void loop() {
  control.poll(); // service host CLI commands (ping/info/identify/mifare)

  if (mifareSessionOpen) {
    if ((int32_t)(millis() - mifareSessionDeadline) >= 0) {
      Serial.println("Mifare session idle timeout.");
      closeCardSession();
    }
    return; // card stays selected; don't re-arm discovery mid-session
  }

  if (nfc.waitForTag()) {
    handleTagDetected();
  }
}

// One tag session: classify the card, emit the ":tag"/":mifare" events for
// Mifare Classic cards, then either hand off to the interactive REPL session
// (Mifare) or wait for removal and re-arm discovery right away (non-Mifare).
void handleTagDetected() {
  tagSessionActive = true;
  const uint32_t tsMs = millis();
  const unsigned char protocol = nfc.raw().remoteDevice.getProtocol();
  const char *protocolName = getProtocolName(protocol);
  const bool isMifare = protocol == nfc.raw().protocol.MIFARE;

  if (isMifare) {
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

  if (isMifare) {
    openMifareSession();
    return;
  }
  closeCardSession();
}

// Arm the interactive REPL session over the currently-selected card.
void openMifareSession() {
  mifareSessionOpen = true;
  mifareSessionDeadline = millis() + MIFARE_SESSION_IDLE_MS;
  Serial.println("Card selected - use 'mifare auth/read/write/sector' "
                 "commands (see MIFARE_CLASSIC_PLAN.md Sec.5).");
}

// End a card session: wait for physical removal and re-arm discovery.
// Blocking, same known limitation as before (see DetectTags.ino's FW-3
// comment) - now only reached once per session instead of once per
// detection.
void closeCardSession() {
  Serial.println("Remove the card...");
  nfc.raw().waitForTagRemoval();
  Serial.println("Card removed!");

  Serial.println("Restarting discovery...");
  // NfcController::reset() unconditionally re-runs connectNCI +
  // configureSettings + configMode + startDiscovery (unlike the PN7150
  // library's own reset(), which skips configureSettings() once a protocol
  // is latched - see DetectTags.ino's FW-3 comment for the full trace).
  nfc.reset();
  Serial.println("Waiting for a Mifare Classic card...");
  mifareSessionOpen = false;
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

// --- REPL command extensions (Phase 3) --------------------------------------
//
// BomberCatControl::Callbacks::command receives the first whitespace-
// separated token as `verb` and the rest of the line, untouched, as `args`;
// the sketch owns parsing beyond that and must emit its own +OK/-ERR
// terminator (see BomberCatControl.h). All "mifare ..." replies below follow
// the same leading-marker wire convention BomberCatControl itself uses
// (":key value" data lines, "+OK [text]" / "-ERR text" terminators) since
// that logic is private to BomberCatControl and not reusable here.

// Splits the next whitespace-separated token off *cursor, advancing it past
// the token (and its trailing separator). Returns nullptr, leaving *cursor
// at the trailing '\0', once no tokens remain.
static char *nextArg(char **cursor) {
  char *p = *cursor;
  while (*p == ' ')
    p++;
  if (*p == '\0') {
    *cursor = p;
    return nullptr;
  }
  char *start = p;
  while (*p && *p != ' ')
    p++;
  if (*p) {
    *p++ = '\0';
  }
  *cursor = p;
  return start;
}

static int hexNibble(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  return -1;
}

// Parses exactly `expectedBytes` * 2 hex chars from `hex` into `out`. Rejects
// any other length or a non-hex character.
static bool parseHexBytes(const char *hex, uint8_t *out,
                          uint8_t expectedBytes) {
  if (hex == nullptr || strlen(hex) != (size_t)expectedBytes * 2) {
    return false;
  }
  for (uint8_t i = 0; i < expectedBytes; i++) {
    int hi = hexNibble(hex[i * 2]);
    int lo = hexNibble(hex[i * 2 + 1]);
    if (hi < 0 || lo < 0) {
      return false;
    }
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return true;
}

// "A"/"a" -> MIFARE_KEY_A, "B"/"b" -> MIFARE_KEY_B.
static bool parseKeyType(const char *tok, uint8_t *keyType) {
  if (tok == nullptr || tok[0] == '\0' || tok[1] != '\0') {
    return false;
  }
  char c = toupper(tok[0]);
  if (c == 'A') {
    *keyType = MIFARE_KEY_A;
    return true;
  }
  if (c == 'B') {
    *keyType = MIFARE_KEY_B;
    return true;
  }
  return false;
}

static void replyOk() { Serial.println("+OK"); }

static void replyOk(const String &msg) {
  Serial.print("+OK ");
  Serial.println(msg);
}

static void replyErr(const char *msg) {
  Serial.print("-ERR ");
  Serial.println(msg);
}

static void replyKv(const char *key, const String &value) {
  Serial.print(':');
  Serial.print(key);
  Serial.print(' ');
  Serial.println(value);
}

// `mifare auth <block> <A|B> <key_hex12>` -> +OK / -ERR
void handleMifareAuth(char *args) {
  char *blockTok = nextArg(&args);
  char *keyTypeTok = nextArg(&args);
  char *keyHexTok = nextArg(&args);
  uint8_t keyType;
  uint8_t key[6];
  if (blockTok == nullptr || !parseKeyType(keyTypeTok, &keyType) ||
      !parseHexBytes(keyHexTok, key, 6)) {
    replyErr("usage: mifare auth <block> <A|B> <key_hex12>");
    return;
  }

  uint8_t blockNum = (uint8_t)atoi(blockTok);
  if (mifareAuthenticate(nfc, blockNum, keyType, key)) {
    replyOk();
  } else {
    replyErr("authentication failed");
  }
}

// `mifare read <block>` -> :mifare_data <block> <hex> +OK / -ERR
void handleMifareRead(char *args) {
  char *blockTok = nextArg(&args);
  if (blockTok == nullptr) {
    replyErr("usage: mifare read <block>");
    return;
  }

  uint8_t blockNum = (uint8_t)atoi(blockTok);
  uint8_t data[MIFARE_BLOCK_SIZE];
  uint8_t dataLen = 0;
  if (!mifareReadBlock(nfc, blockNum, data, &dataLen)) {
    replyErr("read failed (not authenticated, or card gone)");
    return;
  }
  replyKv("mifare_data", String(blockNum) + " " + getHexCompact(data, dataLen));
  replyOk();
}

// `mifare write <block> <data_hex32>` -> +OK / -ERR
void handleMifareWrite(char *args) {
  char *blockTok = nextArg(&args);
  char *dataTok = nextArg(&args);
  uint8_t data[MIFARE_BLOCK_SIZE];
  if (blockTok == nullptr || !parseHexBytes(dataTok, data, MIFARE_BLOCK_SIZE)) {
    replyErr("usage: mifare write <block> <data_hex32> (32 hex chars)");
    return;
  }

  uint8_t blockNum = (uint8_t)atoi(blockTok);
  if (mifareWriteBlock(nfc, blockNum, data, MIFARE_BLOCK_SIZE)) {
    replyOk();
  } else {
    replyErr("write failed (not authenticated, or card gone)");
  }
}

// `mifare sector <sector> <A|B> <key_hex12>` -> :mifare_sector <hex64> +OK /
// -ERR. Self-contained (authenticates internally), unlike read/write which
// reuse a prior `mifare auth`.
void handleMifareSector(char *args) {
  char *sectorTok = nextArg(&args);
  char *keyTypeTok = nextArg(&args);
  char *keyHexTok = nextArg(&args);
  uint8_t keyType;
  uint8_t key[6];
  if (sectorTok == nullptr || !parseKeyType(keyTypeTok, &keyType) ||
      !parseHexBytes(keyHexTok, key, 6)) {
    replyErr("usage: mifare sector <sector> <A|B> <key_hex12>");
    return;
  }

  uint8_t sectorNum = (uint8_t)atoi(sectorTok);
  uint8_t sectorData[MIFARE_BLOCKS_PER_SECTOR * MIFARE_BLOCK_SIZE];
  if (!mifareReadSector(nfc, sectorNum, keyType, key, sectorData)) {
    replyErr("sector read failed");
    return;
  }
  replyKv("mifare_sector", getHexCompact(sectorData, sizeof(sectorData)));
  replyOk();
}

// `mifare keys` -> :mifare_key <name> <hex> (one per built-in default key)
// +OK. Listing only - Decision 4's persisted custom-key store (`mifare keys
// add/remove`, backed by ConfigStore) is not implemented yet.
void emitKnownKeys() {
  replyKv("mifare_key",
          String("default_ff ") + getHexCompact(MIFARE_DEFAULT_KEY_FFFFFF, 6));
  replyKv("mifare_key",
          String("default_00 ") + getHexCompact(MIFARE_DEFAULT_KEY_000000, 6));
  replyKv("mifare_key", String("default_a0a1a2 ") +
                            getHexCompact(MIFARE_DEFAULT_KEY_A0A1A2A3A4A5, 6));
  replyOk();
}

// `mifare <auth|read|write|sector|keys> ...` dispatch. `keys` needs no card;
// the rest require an open session (Decision 5) - see the file header.
void handleMifareCommand(char *args) {
  char *sub = nextArg(&args);
  if (sub == nullptr) {
    replyErr("usage: mifare <auth|read|write|sector|keys> ...");
    return;
  }

  if (strcmp(sub, "keys") == 0) {
    emitKnownKeys();
    return;
  }

  if (!mifareSessionOpen) {
    replyErr("no card selected, tap a Mifare Classic card first");
    return;
  }
  // Any REPL activity keeps the session alive (sliding idle timeout).
  mifareSessionDeadline = millis() + MIFARE_SESSION_IDLE_MS;

  if (strcmp(sub, "auth") == 0) {
    handleMifareAuth(args);
  } else if (strcmp(sub, "read") == 0) {
    handleMifareRead(args);
  } else if (strcmp(sub, "write") == 0) {
    handleMifareWrite(args);
  } else if (strcmp(sub, "sector") == 0) {
    handleMifareSector(args);
  } else {
    replyErr("unknown mifare subcommand");
  }
}

// BomberCatControl::Callbacks::command hook: claims the "mifare" verb only.
bool bomberCatCommand(const char *verb, char *args) {
  if (strcmp(verb, "mifare") != 0) {
    return false;
  }
  handleMifareCommand(args);
  return true;
}
