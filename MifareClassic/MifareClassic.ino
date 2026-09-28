/**
 * BomberCat MifareClassic - Mifare Classic card reader.
 *
 * Polls the onboard PN7150 in reader mode; whenever a Mifare Classic card
 * enters the field, reports its UID over USB serial as a structured ":tag"
 * event (same wire format as DetectTags), then runs the complete on-detection
 * auto-probe (Fase 2, Plan de Implementación Firmware MIFARE): the full Fase 1
 * dictionary sweep - Key A AND Key B across every default-card sector's header
 * - streaming each sector's recovered keys as ":mifare_check_sN" lines, and
 * finally a single ":mifare" block event (Decision 3, MIFARE_CLASSIC_PLAN.md -
 * a distinct event type from ":tag" so TagParser stays UID-only) that doubles
 * as the host's session-open signal.
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
 * removal is still only detected via reselect probes (see DetectTags.ino's
 * FW-3 comment), now deferred to session close instead of running
 * immediately on every detection.
 *
 * Removal itself is polled, not blocking-waited: the vendor library's
 * waitForTagRemoval() spins internally (delay(500) + deactivate/reselect)
 * until the card is gone and never returns control in between, which froze
 * control.poll() - and therefore the host's handshake - for as long as a
 * forgotten card sat on the reader (see beginCardRemovalWait()).
 *
 * Distributed as-is; no warranty is given.
 */

#include <ctype.h>
#include <string.h>

#include <BomberCatControl.h>
#include <HexUtils.h>
#include <NfcController.h>
#include <TagReader.h>

#include "MifareClassic.h"
#include "MifareCommands.h"

NfcController nfc;

// BomberCat serial-control REPL (ping/info/identify) so bombercat-tools can
// discover and identify this board over USB serial. Slug must match the id
// registered in bombercat-tools/modules/core/firmwares.py.
BomberCatControl control(Serial, BOMBERCAT_FW_VERSION, BOMBERCAT_FW_NAME);

static bool tagSessionActive = false; // drives control.state()

// Block read back on every Mifare Classic detection for the legacy ":mifare"
// session-open signal event (see probeMifareBlock()), matching
// ElectronicCats-PN7150's MifareClassic_read_block.ino example default. Fase 2
// retired the old 3-key MIFARE_PROBE_KEYS table: the auto-probe now sweeps the
// shared MIFARE_CHECK_DICT below over every sector, so keeping a second,
// smaller key table would only duplicate the dictionary (restriction #3,
// Tarea 2.4).
static const uint8_t MIFARE_PROBE_BLOCK = 4;

// Compact embedded default-key dictionary for the on-device `mifare check`
// dictionary sweep (Plan de Implementación Firmware MIFARE, Fase 1). Ordered
// *known-first*, mirroring the FRONT of the host's bundled dictionary
// (bombercat-tools/.../data/mifare_default_keys.keys) so the per-slot early cut
// resolves the same keys in the same order the host does: the card_1k
// regression pin (attempts <= 66, 32/32 recovered — baseline_fase0_mifare/
// baseline.json) relies on FFFF/A0A1/D3F7 sitting at indices 0/1/2. 32 keys x 6
// bytes = 192 B in flash — restriction #3 (compact embedded dictionary, never a
// full .dic dump). Grow the reachable key set through the persistent key-store
// (`mifare keys`, Fase 3), not by expanding this table without measuring flash.
static const uint8_t MIFARE_CHECK_DICT[][6] = {
    {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, // FFFFFFFFFFFF
    {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5}, // A0A1A2A3A4A5 (MAD)
    {0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7}, // D3F7D3F7D3F7 (NFC Forum)
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // 000000000000
    {0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5}, // B0B1B2B3B4B5
    {0x4D, 0x3A, 0x99, 0xC3, 0x51, 0xDD}, // 4D3A99C351DD
    {0x1A, 0x98, 0x2C, 0x7E, 0x45, 0x9A}, // 1A982C7E459A
    {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}, // AABBCCDDEEFF
    {0x71, 0x4C, 0x5C, 0x88, 0x6E, 0x97}, // 714C5C886E97
    {0x58, 0x7E, 0xE5, 0xF9, 0x35, 0x0F}, // 587EE5F9350F
    {0xA0, 0x47, 0x8C, 0xC3, 0x90, 0x91}, // A0478CC39091
    {0x53, 0x3C, 0xB6, 0xC7, 0x23, 0xF6}, // 533CB6C723F6
    {0x8F, 0xD0, 0xA4, 0xF2, 0x56, 0xE9}, // 8FD0A4F256E9
    {0xA6, 0x45, 0x98, 0xA7, 0x74, 0x78}, // A64598A77478
    {0x26, 0x94, 0x0B, 0x21, 0xFF, 0x5D}, // 26940B21FF5D
    {0xFC, 0x00, 0x01, 0x87, 0x78, 0xF7}, // FC00018778F7
    {0x00, 0x00, 0x0F, 0xFE, 0x24, 0x88}, // 00000FFE2488
    {0x5C, 0x59, 0x8C, 0x9C, 0x58, 0xB5}, // 5C598C9C58B5
    {0xE4, 0xD2, 0x77, 0x0A, 0x89, 0xBE}, // E4D2770A89BE
    {0x43, 0x4F, 0x4D, 0x4D, 0x4F, 0x41}, // 434F4D4D4F41
    {0x43, 0x4F, 0x4D, 0x4D, 0x4F, 0x42}, // 434F4D4D4F42
    {0x47, 0x52, 0x4F, 0x55, 0x50, 0x41}, // 47524F555041
    {0x47, 0x52, 0x4F, 0x55, 0x50, 0x42}, // 47524F555042
    {0x50, 0x52, 0x49, 0x56, 0x41, 0x41}, // 505249564141
    {0x50, 0x52, 0x49, 0x56, 0x41, 0x42}, // 505249564142
    {0x02, 0x97, 0x92, 0x7C, 0x0F, 0x77}, // 0297927C0F77
    {0xEE, 0x00, 0x42, 0xF8, 0x88, 0x40}, // EE0042F88840
    {0x72, 0x2B, 0xFC, 0xC5, 0x37, 0x5F}, // 722BFCC5375F
    {0xF1, 0xD8, 0x3F, 0x96, 0x43, 0x14}, // F1D83F964314
    {0x54, 0x72, 0x61, 0x76, 0x65, 0x6C}, // 54726176656C
    {0x77, 0x69, 0x74, 0x68, 0x75, 0x73}, // 776974687573
    {0x4A, 0xF9, 0xD7, 0xAD, 0xEB, 0xE4}, // 4AF9D7ADEBE4
};
static const uint8_t MIFARE_CHECK_DICT_COUNT =
    sizeof(MIFARE_CHECK_DICT) / sizeof(MIFARE_CHECK_DICT[0]);

// `mifare check` sweep bounds. Sectors default to a 1K card; the max matches
// the host's `sector * 4` first-block mapping (1K = 16, 2K = 32 sectors — 4K's
// 16-block sectors 32-39 are out of scope, same as the host CLI). The reuse
// store and the --keys override are capped so both stay in bounded RAM.
static const uint8_t MIFARE_CHECK_DEFAULT_SECTORS = 16;
static const uint8_t MIFARE_CHECK_MAX_SECTORS = 32;
static const uint8_t MIFARE_CHECK_MAX_KEYS = 64;  // --keys override cap
static const uint8_t MIFARE_CHECK_KNOWN_MAX = 64; // confirmed-key reuse cap

// Settle pause after a re-select inside the on-device sweep, before the next
// authentication. The host-driven sweep never needs this: one `mifare auth`
// per USB round-trip gives the PN7150 tens of ms of rest between attempts. The
// on-device loop fires auth -> reselect -> auth back-to-back, and right after a
// reset()+waitForTag() the chip is occasionally not ready for an immediate
// auth, so the CORRECT key reads back as a failure once (observed on hardware:
// a single sector's Key B dropped as a false hole ~1 run in N). This restores
// that rest on the sweep path only (not in mifareReselect(), so the host path
// keeps its speed). It does NOT count as an authentication, so the baseline
// pin (attempts <= 66 on card_1k) is unaffected.
static const uint8_t MIFARE_CHECK_SETTLE_MS = 5;

// Per-slot sweep outcome (declared here, above the Arduino auto-generated
// prototypes, so the functions returning it name a known type).
enum SweepSlotResult { SLOT_FOUND, SLOT_NOT_FOUND, SLOT_CARD_REMOVED };

// Whole-card sweep outcome, returned by the shared runCardSweep() (Fase 2).
enum SweepResult { SWEEP_DONE, SWEEP_CARD_REMOVED };

// Per-sector result sink for runCardSweep(): called once as each sector
// resolves, so each caller (`mifare check` and the on-detection auto-probe)
// emits its own wire format from one shared sweep. `ctx` threads caller state
// without a global. keyA/keyB are valid only when haveA/haveB are true.
typedef void (*SweepSectorSink)(uint8_t sector, bool haveA, const uint8_t *keyA,
                                bool haveB, const uint8_t *keyB, void *ctx);

// Interactive "mifare ..." REPL session over an already-selected Mifare
// card. Closes (blocking wait-for-removal + re-arm discovery) after this
// long without a "mifare ..." command, so a forgotten card doesn't wedge the
// reader forever.
static bool mifareSessionOpen = false;
static uint32_t mifareSessionDeadline = 0; // millis() deadline
static const uint32_t MIFARE_SESSION_IDLE_MS = 10000;

// True while the selected card holds an open Crypto1 session from a prior
// SUCCESSFUL authentication (auto-probe, `mifare auth`, or `mifare sector`).
// A successful auth is deliberately NOT followed by a re-select so `mifare
// auth` + a later `mifare read`/`write` can share the session across separate
// host commands. But that warm session must be torn down before the NEXT
// authentication, or the PN7150 lets a fresh auth to the same sector ride it:
// e.g. after Key A = A0A1A2A3A4A5 opens a sector, `mifare auth <blk> B
// A0A1A2A3A4A5` succeeds against the still-open Key A session even though the
// real Key B differs, so `mifare check`'s known-keys-first sweep reports
// Key B == Key A. mifareBeginAuth() re-selects when this flag is set so every
// authentication starts from a clean, independent SELECT.
static bool mifareCardAuthed = false;

// Non-blocking removal wait (replaces a direct waitForTagRemoval() call -
// see the file header). While true, loop() probes for the card at
// MIFARE_REMOVAL_PROBE_INTERVAL_MS instead of re-arming discovery, but keeps
// calling control.poll() every iteration so the host handshake never stalls.
static bool awaitingRemoval = false;
static uint32_t nextRemovalProbeAt = 0;
static const uint32_t MIFARE_REMOVAL_PROBE_INTERVAL_MS = 500; // vendor cadence
static const uint16_t MIFARE_REMOVAL_PROBE_TIMEOUT_MS =
    200; // bounded reselect wait

// Function prototypes.
// hexCompact()/protocolName()/TagReader::emitTagEvent(Serial, ) now come from
// BomberCatCore's TagReader (shared with DetectTags / DetectReaders).
void emitMifareEvent(uint32_t tsMs, const String &uidHex, uint8_t blockNum,
                     const uint8_t *data, uint8_t dataLen, const char *status);
void probeMifareBlock(uint32_t tsMs, const String &uidHex);
void handleTagDetected();
void openMifareSession();
void beginCardRemovalWait();
void pollCardRemoval();
const char *controlState();
bool bomberCatCommand(const char *verb, char *args);
void handleMifareCommand(char *args);
bool mifareBeginAuth();
void handleMifareAuth(char *args);
void handleMifareRead(char *args);
void handleMifareWrite(char *args);
void handleMifareSector(char *args);
void handleMifareCheck(char *args);
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

  if (awaitingRemoval) {
    if ((int32_t)(millis() - nextRemovalProbeAt) >= 0) {
      pollCardRemoval();
    }
    return; // still waiting for the card to leave the field
  }

  if (mifareSessionOpen) {
    if ((int32_t)(millis() - mifareSessionDeadline) >= 0) {
      Serial.println("Mifare session idle timeout.");
      beginCardRemovalWait();
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
  const char *protocolName = TagReader::protocolName(protocol);
  const bool isMifare = protocol == nfc.raw().protocol.MIFARE;

  if (isMifare) {
    Serial.println(" - Found MIFARE card");
    String uidHex = TagReader::hexCompact(nfc.raw().remoteDevice.getNFCID(),
                                          nfc.raw().remoteDevice.getNFCIDLen());
    Serial.print("\tUID = ");
    Serial.println(uidHex);
    TagReader::emitTagEvent(Serial, tsMs, "NFC-A", protocolName, uidHex);
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
  beginCardRemovalWait();
}

// Arm the interactive REPL session over the currently-selected card.
void openMifareSession() {
  mifareSessionOpen = true;
  mifareSessionDeadline = millis() + MIFARE_SESSION_IDLE_MS;
  Serial.println("Card selected - use 'mifare auth/read/write/sector' "
                 "commands.");
}

// Start ending a card session: arm the non-blocking removal poll (see the
// file header and pollCardRemoval()) instead of calling the vendor library's
// blocking waitForTagRemoval(), which never returned control to loop() -
// and therefore never let control.poll() run - for as long as the card sat
// on the reader.
void beginCardRemovalWait() {
  Serial.println("Remove the card...");
  awaitingRemoval = true;
  nextRemovalProbeAt = millis();
  mifareSessionOpen = false; // no REPL commands while waiting for removal
}

// One bounded removal probe, called from loop() at
// MIFARE_REMOVAL_PROBE_INTERVAL_MS - never blocks longer than
// MIFARE_REMOVAL_PROBE_TIMEOUT_MS, so control.poll() keeps running between
// probes. Reuses the same reset()+waitForTag() reselect mifareReselect()
// already relies on (NfcController::reset() unconditionally re-runs
// connectNCI + configureSettings + configMode + startDiscovery, unlike the
// PN7150 library's own reset() - see DetectTags.ino's FW-3 comment for the
// full trace). If the reselect still finds a card, it's the same one still
// sitting there - keep waiting. Once it doesn't, the card is gone and
// discovery is already freshly re-armed from that last reset().
void pollCardRemoval() {
  nextRemovalProbeAt = millis() + MIFARE_REMOVAL_PROBE_INTERVAL_MS;
  if (nfc.reset() && nfc.waitForTag(MIFARE_REMOVAL_PROBE_TIMEOUT_MS)) {
    return; // still present - try again next interval
  }
  Serial.println("Card removed!");
  Serial.println("Waiting for a Mifare Classic card...");
  awaitingRemoval = false;
  tagSessionActive = false;
  mifareCardAuthed = false; // next card starts from a clean, un-authed session
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
  Serial.print(dataLen > 0 ? TagReader::hexCompact(data, dataLen) : "-");
  Serial.print(' ');
  Serial.println(status);
}

// probeMifareBlock() — the complete Fase 2 on-detection auto-probe — is defined
// with the `mifare check` sweep machinery it reuses (search "Fase 2 auto-probe"
// below), so it sits after runCardSweep()/emitCheckSector() instead of forcing
// forward declarations for them here.

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

// Force the next authentication to run from a clean SELECT. If the card still
// holds an open Crypto1 session from a prior successful auth, re-select it so
// this authentication is evaluated independently instead of riding the warm
// session (the Key B == Key A duplication described at mifareCardAuthed). A
// no-op when nothing is authenticated, so it costs a re-select only right
// after a success, not on every probed key.
// Returns false when the reselect proves the card has left the field (the
// session is then ended and discovery re-armed), so a card removed while the
// interactive session was still open is caught immediately instead of after a
// full ~4 s dead transceive in mifareAuthenticate(). True when the card is
// still present, or when there was nothing to reselect.
bool mifareBeginAuth() {
  if (mifareCardAuthed) {
    mifareCardAuthed = false;
    if (!mifareReselect(nfc)) {
      beginCardRemovalWait(); // card left the field while the session was open
      return false;
    }
  }
  return true;
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
  // independent auth: never ride a prior success's session. Bails out early if
  // the card is already gone (session ended inside mifareBeginAuth()).
  if (!mifareBeginAuth()) {
    replyErr("card removed, tap a card again");
    return;
  }
  if (mifareAuthenticate(nfc, blockNum, keyType, key)) {
    mifareCardAuthed = true; // session now open; tear down before the next auth
    replyOk();
  } else {
    mifareCardAuthed = false;
    // A wrong key HALTs the card. Re-select it before answering so the host's
    // NEXT dictionary attempt starts clean — without this, one wrong key (e.g.
    // FFFFFFFFFFFF on a sector keyed A0A1A2A3A4A5) dooms the whole sweep and
    // `mifare check` reports every key as failing. mifareReselect() returns
    // false only when no card is in the field, which distinguishes a real
    // wrong-key from a removed card: end the session and re-arm in that case so
    // the host's next command correctly gets "no card selected" instead of a
    // misleading auth failure. See CLI_IMPROVEMENTS_MifareCheck.md §4.
    if (!mifareReselect(nfc)) {
      beginCardRemovalWait();
      replyErr("card removed, tap a card again");
      return;
    }
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
  replyKv("mifare_data",
          String(blockNum) + " " + TagReader::hexCompact(data, dataLen));
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
  bool authOk = false;
  // independent auth: never ride a prior success's session. Bails out early if
  // the card is already gone (session ended inside mifareBeginAuth()).
  if (!mifareBeginAuth()) {
    replyErr("card removed, tap a card again");
    return;
  }
  if (!mifareReadSector(nfc, sectorNum, keyType, key, sectorData, &authOk)) {
    mifareCardAuthed = false;
    // A failed auth inside mifareReadSector HALTed the card; re-select so the
    // next self-contained command starts clean (same gotcha handleMifareAuth
    // guards against). mifareReselect() returning false means the card is gone,
    // not a wrong key: end the session and re-arm instead of reporting a
    // misleading auth failure.
    if (!mifareReselect(nfc)) {
      beginCardRemovalWait();
      replyErr("card removed, tap a card again");
      return;
    }
    if (authOk) {
      // Key was right (auth succeeded) but a block read NAKed — the
      // sector's access bits don't permit reading with this key type, not
      // a wrong-key problem. Distinguish it from "authentication failed" so
      // callers (and users) don't waste time re-checking the key.
      replyErr("sector read failed: key authenticated but a block read was "
               "denied (access bits)");
    } else {
      replyErr("authentication failed");
    }
    return;
  }
  mifareCardAuthed = true; // sector auth left an open session; tear down next
  replyKv("mifare_sector",
          TagReader::hexCompact(sectorData, sizeof(sectorData)));
  replyOk();
}

// `mifare keys` -> :mifare_key0/1/2 <name> <hex> (one per built-in default
// key) +OK. Indexed like `magcard list`'s ':cardN' lines - the host's
// DeviceLink.command() collects ':key value' replies into a dict keyed by
// name, so three lines sharing one ":mifare_key" key would collapse to the
// last one instead of listing all three. Listing only - Decision 4's
// persisted custom-key store (`mifare keys add/remove`, backed by
// ConfigStore) is not implemented yet.
void emitKnownKeys() {
  replyKv("mifare_key0",
          String("default_ff ") +
              TagReader::hexCompact(MIFARE_DEFAULT_KEY_FFFFFF, 6));
  replyKv("mifare_key1",
          String("default_00 ") +
              TagReader::hexCompact(MIFARE_DEFAULT_KEY_000000, 6));
  replyKv("mifare_key2",
          String("default_a0a1a2 ") +
              TagReader::hexCompact(MIFARE_DEFAULT_KEY_A0A1A2A3A4A5, 6));
  replyOk();
}

// --- `mifare check` on-device dictionary sweep (Fase 1) --------------------
//
// Repatriates into the device the sector x key x {A,B} sweep the host CLI used
// to drive one `mifare auth` USB round-trip at a time (check.py). Same result,
// same authentication count against the card (restriction #2: no extra RF
// traffic — only the USB-serial + host-parse layer is removed); it just runs
// the loop locally and streams the consolidated result. Stays strictly within
// the PN7150 ceiling: only standard authentication with known keys, never any
// key deduction (restriction #1).

static bool keyEquals(const uint8_t *a, const uint8_t *b) {
  return memcmp(a, b, 6) == 0;
}

static bool keyInSet(const uint8_t set[][6], uint8_t count,
                     const uint8_t *key) {
  for (uint8_t i = 0; i < count; i++) {
    if (keyEquals(set[i], key)) {
      return true;
    }
  }
  return false;
}

// Record a just-confirmed key for known-first reuse on later slots (the reuse
// that collapses card_1k's sweep to 66 attempts: a key that already opened one
// sector is the likeliest to open the next). De-duplicated; a no-op once the
// bounded store is full — the sweep stays correct, it just loses some reuse.
static void addKnownKey(uint8_t set[][6], uint8_t *count, const uint8_t *key) {
  if (*count >= MIFARE_CHECK_KNOWN_MAX || keyInSet(set, *count, key)) {
    return;
  }
  memcpy(set[*count], key, 6);
  (*count)++;
}

// One sweep authentication with the same clean-session choreography the host's
// `mifare auth` uses. Before the attempt, tear down any warm Crypto1 session
// left by a prior success (or the auto-probe) via a re-select, so this auth is
// evaluated independently instead of riding the open session — the Key B ==
// Key A false hit documented at mifareCardAuthed / mifareBeginAuth(). After a
// wrong key (which HALTs the card) re-select so the next attempt starts clean.
// Sets *removed = true and returns false when a re-select proves the card left
// the field. Returns true on a real successful auth (card left warm).
static bool sweepAuth(uint8_t block, uint8_t keyType, const uint8_t *key,
                      uint32_t *attempts, bool *removed) {
  *removed = false;
  if (mifareCardAuthed) {
    mifareCardAuthed = false;
    if (!mifareReselect(nfc)) {
      *removed = true;
      return false;
    }
    delay(MIFARE_CHECK_SETTLE_MS); // let the PN7150 settle before the auth
  }
  (*attempts)++;
  if (mifareAuthenticate(nfc, block, keyType, key)) {
    mifareCardAuthed = true; // leave warm; next sweepAuth tears it down
    return true;
  }
  if (mifareReselect(nfc)) { // recover the HALTed card before the next key
    delay(MIFARE_CHECK_SETTLE_MS); // same rest the USB-paced host path gets
  } else {
    *removed = true;
  }
  return false;
}

// Try to open one (sector, key type) slot: confirmed keys first (reuse), then
// the dictionary skipping any key already tried as a confirmed one (the host's
// dedup(known + dict), first-occurrence-wins order), with an early cut on the
// first hit. On success copies the winning key into outKey.
static SweepSlotResult sweepSlot(uint8_t block, uint8_t keyType,
                                 const uint8_t known[][6], uint8_t knownCount,
                                 const uint8_t dict[][6], uint8_t dictCount,
                                 uint32_t *attempts, uint8_t outKey[6]) {
  for (uint8_t i = 0; i < knownCount; i++) {
    bool removed;
    if (sweepAuth(block, keyType, known[i], attempts, &removed)) {
      memcpy(outKey, known[i], 6);
      return SLOT_FOUND;
    }
    if (removed) {
      return SLOT_CARD_REMOVED;
    }
  }
  for (uint8_t i = 0; i < dictCount; i++) {
    if (keyInSet(known, knownCount, dict[i])) {
      continue; // already tried as a confirmed key
    }
    bool removed;
    if (sweepAuth(block, keyType, dict[i], attempts, &removed)) {
      memcpy(outKey, dict[i], 6);
      return SLOT_FOUND;
    }
    if (removed) {
      return SLOT_CARD_REMOVED;
    }
  }
  return SLOT_NOT_FOUND;
}

// Emit one streamed per-sector result line (serial_log_format.md): the two
// recovered keys as uppercase hex, or "-" for a hole (restriction #6: holes
// are reported explicitly, never as zeros or blanks). Streamed as each sector
// resolves — not accumulated in RAM — so the host parses incrementally and a
// long sweep shows progress.
static void emitCheckSector(uint8_t sector, bool haveA, const uint8_t *keyA,
                            bool haveB, const uint8_t *keyB) {
  Serial.print(":mifare_check_s");
  Serial.print(sector);
  Serial.print(' ');
  Serial.print(haveA ? TagReader::hexCompact(keyA, 6) : String("-"));
  Serial.print(' ');
  Serial.println(haveB ? TagReader::hexCompact(keyB, 6) : String("-"));
  Serial.flush(); // push the line over USB now; also services the USB stack
}

// Shared sector x {A,B} dictionary sweep, factored out of `mifare check` so the
// Fase 2 on-detection auto-probe runs the exact same logic instead of the old
// degenerate block-4 / Key-A / 3-key probe (Tarea 2.4: reuse, don't duplicate).
// Sweeps `sectors` sectors, each Key A then Key B, over `dict`, delivering
// every sector's recovered keys to `sink(..., ctx)` as it resolves. `known`/
// `knownCount` is the caller-owned confirmed-key reuse store the sweep appends
// to; it doubles as the Fase 3 key-store seed hook (Tarea 2.5) — pre-fill it
// with persisted keys before the call, or pass count 0 for a cold sweep. Counts
// real auths into *attempts (the baseline regression pin) and the no-reuse pool
// into *naive; counts recovered slots into *recovered. Returns
// SWEEP_CARD_REMOVED — without arming removal itself, so each caller reports it
// its own way — when a re-select proves the card left the field mid-sweep;
// sectors already resolved were already streamed through `sink`.
static SweepResult runCardSweep(uint8_t sectors, const uint8_t dict[][6],
                                uint8_t dictCount, uint8_t known[][6],
                                uint8_t *knownCount, SweepSectorSink sink,
                                void *ctx, uint32_t *attempts, uint32_t *naive,
                                uint8_t *recovered) {
  for (uint8_t s = 0; s < sectors; s++) {
    const uint8_t block = s * MIFARE_BLOCKS_PER_SECTOR;
    uint8_t keyA[6], keyB[6];
    bool haveA = false, haveB = false;

    for (uint8_t ktIdx = 0; ktIdx < 2; ktIdx++) {
      const uint8_t keyType = (ktIdx == 0) ? MIFARE_KEY_A : MIFARE_KEY_B;
      *naive += dictCount; // this slot's naive pool = the dictionary
      uint8_t found[6];
      SweepSlotResult res = sweepSlot(block, keyType, known, *knownCount, dict,
                                      dictCount, attempts, found);
      if (res == SLOT_CARD_REMOVED) {
        return SWEEP_CARD_REMOVED;
      }
      if (res == SLOT_FOUND) {
        (*recovered)++;
        addKnownKey(known, knownCount, found);
        if (ktIdx == 0) {
          memcpy(keyA, found, 6);
          haveA = true;
        } else {
          memcpy(keyB, found, 6);
          haveB = true;
        }
      }
    }
    sink(s, haveA, keyA, haveB, keyB, ctx);
  }
  return SWEEP_DONE;
}

// `mifare check` per-sector sink: stream the recovered keys in the documented
// :mifare_check_sN format (serial_log_format.md). No ctx needed.
static void checkSectorSink(uint8_t sector, bool haveA, const uint8_t *keyA,
                            bool haveB, const uint8_t *keyB, void *ctx) {
  (void)ctx;
  emitCheckSector(sector, haveA, keyA, haveB, keyB);
}

// --- Fase 2 auto-probe -------------------------------------------------------

// Auto-probe sink context: remembers the recovered Key A of the sector holding
// MIFARE_PROBE_BLOCK, so the auto-probe can still emit the legacy block-4
// ":mifare" data event as the host's session-open signal.
struct AutoProbeCtx {
  uint8_t probeSector; // sector containing MIFARE_PROBE_BLOCK
  bool haveKeyA;
  uint8_t keyA[6];
};

// On-detection auto-probe sink: stream each sector's recovered keys exactly
// like `mifare check` (one wire format for both, parsed by the host in Fase 4)
// and capture the probe sector's Key A for the legacy signal event.
static void autoProbeSectorSink(uint8_t sector, bool haveA, const uint8_t *keyA,
                                bool haveB, const uint8_t *keyB, void *ctx) {
  emitCheckSector(sector, haveA, keyA, haveB, keyB);
  AutoProbeCtx *c = (AutoProbeCtx *)ctx;
  if (sector == c->probeSector && haveA) {
    c->haveKeyA = true;
    memcpy(c->keyA, keyA, 6);
  }
}

// Fase 2 — complete on-detection auto-probe. Where the original probe tried
// only 3 keys as Key A against a single block, this runs the full Fase 1 sweep:
// Key A AND Key B across every default-card sector's header, over the embedded
// default-key dictionary (Tareas 2.1/2.2/2.3), reusing runCardSweep so there is
// one sweep implementation, not two (Tarea 2.4). Each sector's recovered keys
// stream as :mifare_check_sN lines; then a single legacy ":mifare" block event
// is emitted LAST as the session-open signal the host blocks on (session.py's
// _wait_for_mifare_card matches "^:mifare\\s"). Emitting the per-sector lines
// first and the signal line last lets the host drain the unsolicited sweep
// output while it waits and start REPL commands on a clean stream. A card with
// default keys still yields the exact block-4 data event the degenerate probe
// did (no regression); a fully unknown card yields auth_fail. Read-only — never
// writes automatically.
void probeMifareBlock(uint32_t tsMs, const String &uidHex) {
  // Confirmed-key reuse store. Fase 3 hook (Tarea 2.5): seed this from the
  // persistent key-store before the sweep so custom keys feed the auto-probe.
  uint8_t known[MIFARE_CHECK_KNOWN_MAX][6];
  uint8_t knownCount = 0;
  uint32_t attempts = 0, naive = 0;
  uint8_t recovered = 0;

  AutoProbeCtx ctx;
  ctx.probeSector = MIFARE_PROBE_BLOCK / MIFARE_BLOCKS_PER_SECTOR;
  ctx.haveKeyA = false;

  if (runCardSweep(MIFARE_CHECK_DEFAULT_SECTORS, MIFARE_CHECK_DICT,
                   MIFARE_CHECK_DICT_COUNT, known, &knownCount,
                   autoProbeSectorSink, &ctx, &attempts, &naive,
                   &recovered) == SWEEP_CARD_REMOVED) {
    // Card lifted mid-probe: emit the signal so the host stops waiting, then
    // let handleTagDetected() open the session — its idle/removal poll notices
    // the absent card and re-arms discovery.
    emitMifareEvent(tsMs, uidHex, MIFARE_PROBE_BLOCK, nullptr, 0, "auth_fail");
    return;
  }

  // Legacy session-open signal: re-read MIFARE_PROBE_BLOCK with the Key A the
  // sweep recovered for its sector, so a default-keyed card still produces the
  // exact block-4 data event the degenerate probe did. The sweep left a warm
  // Crypto1 session on the LAST swept sector, so tear it down first (a
  // re-select) to keep this authentication independent — the same
  // mifareCardAuthed choreography every other auth path uses.
  if (ctx.haveKeyA) {
    if (mifareCardAuthed) {
      mifareCardAuthed = false;
      if (!mifareReselect(nfc)) {
        emitMifareEvent(tsMs, uidHex, MIFARE_PROBE_BLOCK, nullptr, 0,
                        "auth_fail");
        return; // card gone; the removal poll re-arms discovery
      }
    }
    uint8_t data[MIFARE_BLOCK_SIZE];
    uint8_t dataLen = 0;
    if (mifareAuthenticate(nfc, MIFARE_PROBE_BLOCK, MIFARE_KEY_A, ctx.keyA) &&
        mifareReadBlock(nfc, MIFARE_PROBE_BLOCK, data, &dataLen)) {
      mifareCardAuthed = true; // leave warm; session's first auth tears it down
      emitMifareEvent(tsMs, uidHex, MIFARE_PROBE_BLOCK, data, dataLen, "ok");
      return;
    }
    // Unexpected: the sweep found Key A but this re-auth/read failed. Recover a
    // cleanly selected card and fall through to auth_fail.
    mifareCardAuthed = false;
    mifareReselect(nfc);
  }
  emitMifareEvent(tsMs, uidHex, MIFARE_PROBE_BLOCK, nullptr, 0, "auth_fail");
}

// `mifare check [--sectors <n>] [--keys <hex,...>]`
//   -> :mifare_check_sN <keyA|-> <keyB|-> (one per sector, streamed)
//      :mifare_check_stat attempts=<n> naive=<n> recovered=<r>/<total>
//      +OK   (or -ERR if the card leaves the field mid-sweep)
//
// --sectors: sectors to sweep (default 16 = 1K; max 32).
// --keys:    comma-separated 12-hex keys that REPLACE the embedded dictionary
//            for this run (mirrors the host `--keys`), e.g.
//            `mifare check --keys FFFFFFFFFFFF,A0A1A2A3A4A5`.
void handleMifareCheck(char *args) {
  uint8_t sectors = MIFARE_CHECK_DEFAULT_SECTORS;
  const uint8_t (*dict)[6] = MIFARE_CHECK_DICT;
  uint8_t dictCount = MIFARE_CHECK_DICT_COUNT;
  // --keys override lives in a bounded static buffer so a long list never eats
  // the stack; single-threaded REPL, so no re-entrancy concern.
  static uint8_t overrideKeys[MIFARE_CHECK_MAX_KEYS][6];

  char *tok;
  while ((tok = nextArg(&args)) != nullptr) {
    if (strcmp(tok, "--sectors") == 0) {
      char *v = nextArg(&args);
      int n = (v != nullptr) ? atoi(v) : 0;
      if (n < 1 || n > MIFARE_CHECK_MAX_SECTORS) {
        replyErr("usage: mifare check [--sectors <1..32>] [--keys <hex,...>]");
        return;
      }
      sectors = (uint8_t)n;
    } else if (strcmp(tok, "--keys") == 0) {
      char *list = nextArg(&args);
      uint8_t n = 0;
      for (char *p = list;
           p != nullptr && *p != '\0' && n < MIFARE_CHECK_MAX_KEYS;) {
        char *comma = strchr(p, ',');
        if (comma != nullptr) {
          *comma = '\0';
        }
        if (!parseHexBytes(p, overrideKeys[n], 6)) {
          replyErr("--keys: each entry must be 12 hex chars, comma-separated");
          return;
        }
        n++;
        p = (comma != nullptr) ? comma + 1 : nullptr;
      }
      if (n == 0) {
        replyErr("--keys: no keys parsed");
        return;
      }
      dict = overrideKeys;
      dictCount = n;
    } else {
      replyErr("usage: mifare check [--sectors <1..32>] [--keys <hex,...>]");
      return;
    }
  }

  // Confirmed-key reuse store, ordered by first confirmation (known-first).
  // Fase 3 hook (Tarea 2.5): seed this from the persistent key-store here.
  uint8_t known[MIFARE_CHECK_KNOWN_MAX][6];
  uint8_t knownCount = 0;

  uint32_t attempts = 0; // real auths issued (Tarea 1.8: pin against baseline)
  uint32_t naive = 0;    // auths a no-reuse, no-early-cut sweep would cost
  uint8_t recovered = 0;
  const uint16_t total = (uint16_t)sectors * 2;

  if (runCardSweep(sectors, dict, dictCount, known, &knownCount,
                   checkSectorSink, nullptr, &attempts, &naive,
                   &recovered) == SWEEP_CARD_REMOVED) {
    // Card left the field mid-sweep: end the session and re-arm discovery
    // (Tarea 1.7) so the host's next command gets a clean "no card" instead of
    // a hung session. Sectors already resolved were streamed.
    beginCardRemovalWait();
    replyErr("card removed mid-sweep, tap a card again");
    return;
  }

  Serial.print(":mifare_check_stat attempts=");
  Serial.print(attempts);
  Serial.print(" naive=");
  Serial.print(naive);
  Serial.print(" recovered=");
  Serial.print(recovered);
  Serial.print('/');
  Serial.println(total);
  // A long sweep may have overrun the idle window while loop() was blocked;
  // give a follow-up REPL command the full window again.
  mifareSessionDeadline = millis() + MIFARE_SESSION_IDLE_MS;
  replyOk();
}

// `mifare <auth|read|write|sector|keys|check> ...` dispatch. `keys` needs no
// card; the rest require an open session (Decision 5) - see the file header.
void handleMifareCommand(char *args) {
  char *sub = nextArg(&args);
  if (sub == nullptr) {
    replyErr("usage: mifare <auth|read|write|sector|keys|check> ...");
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
  } else if (strcmp(sub, "check") == 0) {
    handleMifareCheck(args);
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
