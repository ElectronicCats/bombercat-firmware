/**
 * BomberCat MifareClassic - Mifare Classic card reader.
 *
 * Polls the onboard PN7150 in reader mode; whenever a Mifare Classic card
 * enters the field, reports its UID over USB serial as a structured ":tag"
 * event (same wire format as DetectTags), then runs the complete on-detection
 * auto-probe: the full
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
 * A PERSISTENT key-store holds the user-curated Mifare keys that are
 * not part of the embedded dictionary live in QSPI (through ConfigStore's
 * TDBStore), so they survive a reset and feed the dictionary sweep - both
 * `mifare check` and the on-detection auto-probe - without recompiling the
 * firmware. `mifare keys add/remove/list/clear` manage it, and
 * `mifare keys autostore on` makes a sweep persist the custom keys it
 * confirms. The stored keys are tried BEFORE the embedded dictionary
 * (custom-first fusion); with an empty store the sweep is
 * bit-identical to the baseline.
 *
 * The FIELD TRIGGER: the board's user button (SW2,
 * "GPIO" in the BOM, on RP2040 GPIO17 = Arduino D5) starts the standalone
 * workflow with no PC attached. A short press runs the chain for the card in
 * the field (or arms it for the next card); a long press toggles the
 * persistent standalone flag. The board's LED says what happened.
 *
 * Distributed as-is; no warranty is given.
 */

#include <ctype.h>
#include <string.h>

#include <BomberCatControl.h>
#include <ConfigStore.h>
#include <HexUtils.h>
#include <MifareAccessBits.h>
#include <MifareBlock0.h>
#include <MifareCommands.h>
#include <MifareCommon.h>
#include <MifareDumpFormat.h>
#include <MifareKeyStore.h>
#include <MifareResultStore.h>
#include <MifareStandaloneTrigger.h>
#include <NfcController.h>
#include <TagReader.h>

#include "MifareClassic.h"

NfcController nfc;

// BomberCat serial-control REPL (ping/info/identify) so bombercat-tools can
// discover and identify this board over USB serial. Slug must match the id
// registered in bombercat-tools/modules/core/firmwares.py.
BomberCatControl control(Serial, BOMBERCAT_FW_VERSION, BOMBERCAT_FW_NAME);

static bool tagSessionActive = false; // drives control.state()

// Persistent key-store: user-curated Mifare Classic keys kept in
// QSPI through ConfigStore's TDBStore, so they survive a reset and feed the
// dictionary sweep (both `mifare check` and the on-detection auto-probe)
// without recompiling the firmware. Only custom keys live here - the 32-key
// embedded dictionary (MIFARE_CHECK_DICT) is compiled in and needs no
// persistence.
ConfigStore config;
MifareKeyStore mifareKeys;

// The results of the standalone runs.
//
// The standalone workflow reads a card with NO PC attached: the dump goes out
// over the serial port, where nobody is listening when the board is in the
// field. The ring below keeps the last MIFARE_RESULT_SLOTS results in the
// board's own flash, so the operator collects them later, over USB, and gets
// the very same canonical dump - with its holes - that the connected
// workflow produces.
//
// The store is fed through ConfigStore's blob API (the SAME TDBStore
// instance the key-store uses - mounting a second FlashIAPBlockDevice over
// the same region would collide), so a stored result costs ONE flash write
// per card and survives a reset.
static MifareResultStore mifareResults;
// The buffer the standalone chain fills with the result it just read. It is
// the caller's own buffer (not the store's) so that scanning the ring and
// building a result never fight over the same bytes.
static MifareResultRecord mifareResultBuild;
// True when the flash is usable: without it there is nowhere to keep the
// results, and the firmware says so instead of failing silently.
static bool mifareResultsReady = false;

// Block read back on every Mifare Classic detection for the legacy ":mifare"
// session-open signal event (see probeMifareBlock()), matching
// ElectronicCats-PN7150's MifareClassic_read_block.ino example default. The
// auto-probe retired the old 3-key MIFARE_PROBE_KEYS table: the auto-probe now
// sweeps the shared MIFARE_CHECK_DICT below over every sector, so keeping a
// second, smaller key table would only duplicate the dictionary (restriction
// #3).
static const uint8_t MIFARE_PROBE_BLOCK = 4;

// Compact embedded default-key dictionary for the on-device `mifare check`
// dictionary sweep (Plan de Implementación Firmware MIFARE). Ordered
// *known-first*, mirroring the FRONT of the host's bundled dictionary
// (bombercat-tools/.../data/mifare_default_keys.keys) so the per-slot early cut
// resolves the same keys in the same order the host does: the card_1k
// regression pin (attempts <= 66, 32/32 recovered — baseline_fase0_mifare/
// baseline.json) relies on FFFF/A0A1/D3F7 sitting at indices 0/1/2. 32 keys x 6
// bytes = 192 B in flash — restriction #3 (compact embedded dictionary, never a
// full .dic dump). Grow the reachable key set through the persistent key-store
// (`mifare keys`), not by expanding this table without measuring flash.
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
//
// The confirmed-key pool (MIFARE_CHECK_KNOWN_MAX) holds THREE kinds of key:
// the persisted key-store (up to MIFARE_KEYSTORE_MAX = 32), the keys confirmed
// during the current sweep (up to 2 per sector, so 32 for a 1K card), and
// their slack. 96 leaves room for all of them at once; with an empty key-store
// the pool holds exactly the same keys as the baseline, so the
// `attempts <= 66` pin is unaffected.
static const uint8_t MIFARE_CHECK_DEFAULT_SECTORS = 16;
static const uint8_t MIFARE_CHECK_MAX_SECTORS = 32;
static const uint8_t MIFARE_CHECK_MAX_KEYS = 64;  // --keys override cap
static const uint8_t MIFARE_CHECK_KNOWN_MAX = 96; // confirmed-key pool cap

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
//
// The value is the host path's EFFECTIVE rest, measured: the USB round-trip
// between two `mifare auth` commands is 10-30 ms (the host parses the reply
// and writes the next command). 5 ms was below what the chip actually needs,
// so the on-device sweep kept hitting the race the comment above describes -
// and on a card whose sectors are NOT opened by the first keys of the
// dictionary it did not stay a single false hole: every spurious failure HALTs
// the card again, so the chip never settles, the re-selects get slower and
// the sweep eventually gives up mid-card (the card is then reported as
// "1/16 sectors known" although the very same card yields 15/16 through the
// host path). 25 ms matches what the host path gets for free; the cost is
// 25 ms per attempt, i.e. ~2 s on a 79-attempt sweep.
static const uint8_t MIFARE_CHECK_SETTLE_MS = 25;

// How long the sweep's re-select waits for the card to come back.
//
// The sweep re-selects after EVERY failed authentication, and a failed
// authentication HALTs the card: the PN7150 has to wake it up and activate it
// again, which takes longer than a warm re-detection. mifareReselect() was
// given a 2000 ms window for exactly that reason - but
// the sweep did NOT go through it: timedReselect() called
// nfc.waitForTag() with its DEFAULT 500 ms window, so the sweep - the ONE
// path that re-selects after every wrong key - was the one that gave the card
// the least time to come back. A card that needs a little longer than 500 ms
// was declared "gone", and the sweep threw the whole card away.
static const uint16_t MIFARE_CHECK_RESELECT_MS = 2000;

// How many times the sweep re-tries the re-select before it believes the card
// really left the field.
//
// ONE failed re-select is NOT proof: the chip can miss the wake-up, or the
// I2C re-init (nfc.reset() pulses VEN and re-inits the chip) can hiccup,
// while the card is right there on the reader. The removal probe already
// needs several consecutive misses to believe the card is gone
// (MIFARE_REMOVAL_MISSES_TO_CONFIRM); the sweep must not be STRICTER than
// the removal probe, or a single hiccup costs the whole card.
static const uint8_t MIFARE_CHECK_RESELECT_TRIES = 3;

// Runtime override of the settle pause (`mifare check --settle <ms>`), so the
// value can be tuned ON THE HARDWARE without reflashing - the settle is the
// knob that decides how much rest the PN7150 gets between a re-select and the
// next authentication, and that rest is what the host-driven sweep gets for
// free from its USB round-trip.
static uint16_t mifareCheckSettleMs = MIFARE_CHECK_SETTLE_MS;

// Where the sweep's wall-clock time goes. The host-driven
// sweep and the on-device sweep issue the SAME number of authentications and
// re-selects, so the time split is what tells them apart: `authMs` is the
// time inside the Crypto-1 authentication and `reselectMs` the time inside the
// re-select (a full reader re-arm + re-detection). Reported in the
// :mifare_check_stat line, so the numbers come from the board and not from a
// stopwatch on the host.
//
// The re-select is split in two, because they have different fixes:
//   resetMs  — the reader re-arm itself (NCI re-init over I²C);
//   detectMs — waiting for the card to be detected and selected again.
static uint32_t mifareSweepAuthMs = 0;
static uint32_t mifareSweepReselectMs = 0;
static uint32_t mifareSweepResetMs = 0;
static uint32_t mifareSweepDetectMs = 0;
static uint32_t mifareSweepTrailerMs = 0;
static uint32_t mifareSweepAttempts = 0;
static uint32_t mifareSweepReselects = 0;
// How many re-selects did NOT get the card back. Together with the core's
// det_* counters it says whether the card left the field or the re-select
// simply failed to recover it (the difference between "the user took the
// card away" and "the chip hiccupped").
static uint32_t mifareSweepReselectFails = 0;

// Outcome of one trailer read. Declared here, with the
// other types, because the Arduino auto-generated prototypes come before the
// section that defines it and would otherwise name an unknown type.
enum TrailerReadResult {
  TRAILER_OK,          // Key B came back
  TRAILER_FAILED,      // protected by the access bits, or the read failed
  TRAILER_CARD_REMOVED // the card left the field
};

// Per-slot sweep outcome (declared here, above the Arduino auto-generated
// prototypes, so the functions returning it name a known type).
enum SweepSlotResult { SLOT_FOUND, SLOT_NOT_FOUND, SLOT_CARD_REMOVED };

// Whole-card sweep outcome, returned by the shared runCardSweep().
enum SweepResult { SWEEP_DONE, SWEEP_CARD_REMOVED };

// Per-sector result sink for runCardSweep(): called once as each sector
// resolves, so each caller (`mifare check` and the on-detection auto-probe)
// emits its own wire format from one shared sweep. `ctx` threads caller state
// without a global. keyA/keyB are valid only when haveA/haveB are true.
typedef void (*SweepSectorSink)(uint8_t sector, bool haveA, const uint8_t *keyA,
                                bool haveB, const uint8_t *keyB, void *ctx);

// Auto-probe sink context: remembers the recovered Key A of the sector holding
// MIFARE_PROBE_BLOCK, so the auto-probe can still emit the legacy block-4
// ":mifare" data event as the host's session-open signal. Declared here, with
// the other types, because the Arduino auto-generated prototypes come before
// the auto-probe section and would otherwise name an unknown type.
struct AutoProbeCtx {
  uint8_t probeSector; // sector containing MIFARE_PROBE_BLOCK
  bool haveKeyA;
  uint8_t keyA[6];
};

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
// The window the removal probe gives the card to be found again. It has to
// outlast the re-detection the reselect costs on this hardware (~80 ms
// measured, but it is a full reader re-arm plus the card waking up from its
// HALT state, so it can take longer — and a window that expires too early
// makes the firmware believe the card left when it is right there).
static const uint16_t MIFARE_REMOVAL_PROBE_TIMEOUT_MS = 1500;
// How many consecutive failed probes it takes to believe the card left.
//
// ONE failed probe is NOT proof: the re-arm can fail for reasons that have
// nothing to do with the card (a stale notification still queued in the
// PN7150, an I2C hiccup, a reset that did not settle). Believing it made the
// firmware re-arm discovery, re-detect the SAME card, and run the whole
// on-detection auto-probe AGAIN — a loop that left the board busy ~40 % of the
// time and burned 7.5 s of RF work per cycle.
static const uint8_t MIFARE_REMOVAL_MISSES_TO_CONFIRM = 3;
static uint8_t mifareRemovalMisses = 0;

// True while a dictionary sweep is running (the auto-probe on detection, or
// an explicit `mifare check`). The sweep blocks loop(), so the control REPL
// is silent for its whole duration (11 s measured on a 1K card, minutes on a
// card whose sectors nothing opens). `info` reports this so the host can tell
// "the board is working on it" from "the board is gone" instead of guessing —
// and, above all, so it never mistakes a busy board for a different firmware.
static bool mifareSweepActive = false;

// Keys recovered by the last sweep, cached in RAM.
//
// The dump step needs the keys the sweep found, and the standalone workflow
// runs "detect -> sweep -> dump" without a PC in between: caching them is
// what lets `mifare dump` (and the automatic dump) reuse the sweep's work
// instead of sweeping the card a second time.
//
// Index 0 = Key A, index 1 = Key B. `mifareSweepHave[sector]` is a bitmask:
// bit 0 = Key A recovered, bit 1 = Key B recovered.
static uint8_t mifareSweepKeys[MIFARE_CHECK_MAX_SECTORS][2][6];
static uint8_t mifareSweepHave[MIFARE_CHECK_MAX_SECTORS];
static uint8_t mifareSweepSectors = 0;
static bool mifareSweepValid = false;

// The counters of the sweep whose results are cached above, so a later
// `mifare check` can answer from the cache with the SAME numbers the sweep
// reported (the device must not sweep the same card twice
// — the on-detection auto-probe already did the full sweep, and repeating it
// costs exactly the same authentications for exactly the same result).
static uint32_t mifareSweepCacheAttempts = 0;
static uint32_t mifareSweepCacheNaive = 0;
static uint8_t mifareSweepCacheRecovered = 0;
static uint8_t mifareSweepCacheTrailer = 0;
// True when the cached sweep was interrupted (the card left the field, or the
// re-selects gave up) before it covered every sector. The host has to say so:
// the cached per-sector lines are then a PARTIAL result, and reporting them
// as the whole card is what made an interrupted sweep look like a card whose
// keys are unknown.
static bool mifareSweepCacheAborted = false;
// The wall-clock split OF THAT SWEEP, cached with it: the global counters keep
// accumulating whatever else the board did afterwards (a host-driven sweep
// adds its own authentications to them), so a cached answer has to report the
// numbers of the sweep it is reusing, not the sum of everything.
static uint32_t mifareSweepCacheAuthMs = 0;
static uint32_t mifareSweepCacheReselectMs = 0;
static uint32_t mifareSweepCacheResetMs = 0;
static uint32_t mifareSweepCacheDetectMs = 0;
static uint32_t mifareSweepCacheTrailerMs = 0;

// True while the firmware is running the standalone chain (detect -> sweep ->
// dump -> emit) on its own. The chain cedes control to the control REPL
// between its steps, so a command could arrive mid-chain; the chain refuses
// it instead of letting it touch the card session (re-entrancy).
static bool mifareChainActive = false;

// The field trigger: the board's user button (SW2 ->
// RP2040 GPIO17 = Arduino D5) and the board's LED (LED1 -> GPIO27 = D15 =
// LED_BUILTIN).
//
// Two gestures: a SHORT press runs the standalone chain for the card in the
// field (or arms it for the next card); a LONG press toggles the persistent
// standalone flag. The logic lives in MifareStandaloneTrigger (pure, no
// Arduino, so it can be tested natively); the sketch owns the pins.
static MifareStandaloneTrigger mifareTrigger;
static MifareLedBlink mifareLed;

// UID the anti-collision loop reported for the card in the field. Kept so the
// dump step can cross-check it against the UID stored in block 0 - they differ
// on a clone/magic card, and that difference is worth saying out loud.
static String mifareCardUid;

// UID of the last card that was swept. When the SAME card comes back (the
// removal probe can miss it, or the user taps it again), its keys are already
// known: re-running the auto-probe would cost the same authentications for
// the same result.
static String mifareLastCardUid;

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
static bool sweepReselect(NfcController &nfc);
void handleMifareAuth(char *args);
void handleMifareRead(char *args);
void handleMifareWrite(char *args);
void handleMifareSector(char *args);
void handleMifareCheck(char *args);
void handleMifareDump(char *args);
void handleMifareKeys(char *args);
void handleMifareStandalone(char *args);
void handleMifareResults(char *args);
void handleMifareTrigger(char *args);
void handleMifareTiming(char *args);
void emitKnownKeys();
// The trailer-read pass and the sector dump, used by both
// the auto-probe and `mifare check` (declared here because the Arduino
// auto-generated prototypes come before the section that defines them).
static uint8_t trailerReadPass(uint8_t sectors, SweepSectorSink sink, void *ctx,
                               uint32_t *trailerAuths, uint8_t *recovered,
                               bool *removed);
static void runStandaloneChain();
static bool storeStandaloneResult(MifareResultRecord &record, uint8_t read,
                                  uint8_t failed);
static void emitStoredResult(const MifareResultRecord &record);
static void pollStandaloneTrigger();
static void onTriggerShort();
static void onTriggerLong();
static void mifareLedApply(uint32_t nowMs);
static void mifareIdentifyLed();
static bool runFieldSweepNow();
static TrailerReadResult
recoverKeyBViaTrailer(uint8_t sector, const uint8_t *keyA, uint8_t outKeyB[6]);

// The ring's flash: ConfigStore's generic blob API (added for the
// key-store), so both live in the same TDBStore without colliding.
//
// They live HERE, and not with the globals above, because the Arduino
// builder inserts the auto-generated prototypes right before the FIRST
// function of the sketch: a function defined above the type declarations
// would push those prototypes in front of the enums this file declares
// (SweepResult, AutoProbeCtx…), and the sketch would not compile.
static bool mifareResultBlobRead(const char *key, void *buf, size_t size) {
  return config.loadBlob(key, buf, size);
}
static bool mifareResultBlobWrite(const char *key, const void *buf,
                                  size_t size) {
  return config.saveBlob(key, buf, size);
}
static bool mifareResultBlobClear(const char *key) {
  return config.clearBlob(key);
}

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

  // Persistent key-store. A failure here is NOT fatal: the firmware
  // keeps working with the embedded dictionary alone, it just cannot persist
  // custom keys across resets - say so instead of failing silently.
  mifareKeyStoreInit(mifareKeys);
  if (config.begin()) {
    if (mifareKeyStoreLoad(config, mifareKeys)) {
      Serial.print("Mifare key-store: ");
      Serial.print(mifareKeys.count);
      Serial.println(" custom key(s) loaded.");
    } else {
      Serial.println("Mifare key-store: empty.");
    }
    // The standalone result ring lives in the same
    // TDBStore, through the same blob API. The ring is NOT scanned here: the
    // scan reads eight records, and nothing needs it until a result is
    // stored or asked for.
    MifareResultBlob blob;
    blob.read = mifareResultBlobRead;
    blob.write = mifareResultBlobWrite;
    blob.clear = mifareResultBlobClear;
    mifareResults.setBlob(blob);
    mifareResultsReady = true;
  } else {
    Serial.println("Mifare key-store unavailable (flash init failed); custom "
                   "keys will not persist.");
    Serial.println("Standalone results unavailable (flash init failed); the "
                   "board will not keep the dumps it reads.");
  }

  BomberCatControl::Callbacks cb;
  cb.state = controlState;
  cb.command = bomberCatCommand;
  // The sketch owns the board's LED: the button's
  // feedback and the host's `identify` blink share ONE scheduler, so the two
  // can never fight over the pin.
  cb.identify = mifareIdentifyLed;
  control.setCallbacks(cb);
  control.begin(); // announce readiness to the host CLI

  // The field trigger: the board's user button (SW2,
  // "GPIO" in the BOM) is on RP2040 GPIO17 = Arduino D5, active LOW to GND.
  // (The other board button, SW1, is the RP2040's RUN/reset: pressing it
  // reboots the board, so it cannot be a trigger.)
  pinMode(MIFARE_TRIGGER_PIN, INPUT_PULLUP);
  mifareTrigger.begin(millis());
  mifareLed.begin();
  pinMode(LED_BUILTIN, OUTPUT);
  digitalWrite(LED_BUILTIN, LOW);
}

void loop() {
  control.poll(); // service host CLI commands (ping/info/identify/mifare)

  // The field trigger: polled on EVERY iteration, before
  // any of the early returns below, so the button works in every state
  // (scanning, session open, waiting for a removal). It never blocks.
  pollStandaloneTrigger();

  if (awaitingRemoval) {
    if ((int32_t)(millis() - nextRemovalProbeAt) >= 0) {
      pollCardRemoval();
    }
    return; // still waiting for the card to leave the field
  }

  if (mifareSessionOpen) {
    if ((int32_t)(millis() - mifareSessionDeadline) >= 0) {
      // The session has been idle for a while. Before giving it up, check
      // whether the card is STILL THERE: if it is, the session is perfectly
      // usable and it simply keeps running. A forgotten card must not make the
      // board unusable — the user can still read and write it, and lifting it
      // releases the reader for the next card.
      //
      // Closing the session anyway (the old behaviour) left the board
      // answering "no card selected" to every command while the card was
      // right there, until the user lifted it: the host's sweep then failed
      // every single authentication.
      if (mifareCardStillPresent()) {
        mifareSessionDeadline = millis() + MIFARE_SESSION_IDLE_MS;
        mifareCardAuthed = false; // the re-arm dropped the Crypto1 session
      } else {
        Serial.println("Mifare session idle timeout.");
        beginCardRemovalWait();
      }
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
    // Remembered so the dump step can cross-check it against the UID stored
    // in block 0 - they differ on a clone/magic card.
    mifareCardUid = uidHex;

    // The SAME card is back (it never really left, or the user tapped it
    // again): its keys are already known, so the auto-probe must NOT run
    // again - the same sweep would cost the same authentications for the same
    // result. Re-open the session and say so.
    if (uidHex == mifareLastCardUid && mifareSweepValid) {
      Serial.println(" - Same card again: reusing the keys already recovered");
      mifareLastCardUid = uidHex;
      AutoProbeCtx cached;
      cached.probeSector = MIFARE_PROBE_BLOCK / MIFARE_BLOCKS_PER_SECTOR;
      cached.haveKeyA = false;
      bool haveA, haveB;
      const uint8_t *keyA, *keyB;
      sweepCacheGet(cached.probeSector, &haveA, &keyA, &haveB, &keyB);
      if (haveA) {
        cached.haveKeyA = true;
        memcpy(cached.keyA, keyA, 6);
      }
      emitMifareSessionSignal(tsMs, uidHex, cached);
      // Same rule as the first detection: the standalone mode, or the
      // field trigger's one-shot, runs the chain for this card.
      const bool oneShot = mifareTrigger.takeOneShot();
      if ((mifareKeys.flags & MIFARE_KEYSTORE_FLAG_STANDALONE) || oneShot) {
        if (oneShot) {
          Serial.println(":mifare_trigger run");
        }
        runStandaloneChain();
      }
      openMifareSession();
      return;
    }
    mifareLastCardUid = uidHex;

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

// Is the card still in the field? A bounded probe: re-arm the reader and wait
// for the card to be found again. Unlike the removal probe, a failed
// detection here concludes NOTHING: it only means "not found right now", so
// the caller decides what to do about it.
static bool mifareCardStillPresent() {
  if (!nfc.reset()) {
    return false;
  }
  return nfc.waitForTag(MIFARE_REMOVAL_PROBE_TIMEOUT_MS);
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
  const bool present =
      nfc.reset() && nfc.waitForTag(MIFARE_REMOVAL_PROBE_TIMEOUT_MS);
  if (present) {
    mifareRemovalMisses = 0; // the card is still there
    return;                  // still present - try again next interval
  }
  // One failed probe is not proof that the card left (see
  // MIFARE_REMOVAL_MISSES_TO_CONFIRM): only several consecutive misses are.
  if (++mifareRemovalMisses < MIFARE_REMOVAL_MISSES_TO_CONFIRM) {
    return;
  }
  mifareRemovalMisses = 0;
  Serial.println("Card removed!");
  Serial.println("Waiting for a Mifare Classic card...");
  awaitingRemoval = false;
  tagSessionActive = false;
  mifareCardUid = "";       // the next card has its own UID
  mifareLastCardUid = "";   // ... and it is not the one that just left
  sweepCacheInvalidate();   // the cached keys belong to the card that left
  mifareCardAuthed = false; // next card starts from a clean, un-authed session
}

// Control-plane state reported by `info`.
//
// The host reads this to tell apart the states that need DIFFERENT advice
// from the user:
//   "scanning"          — no card; tap one.
//   "tag-detected"      — a session is open; REPL commands work.
//   "sweeping"          — a dictionary sweep is running; the REPL is busy
//                         until it finishes (wait, do not re-flash).
//   "awaiting-removal"  — the board is waiting for the card to LEAVE the
//                         field before it re-arms discovery. Tapping does
//                         nothing here: the card must go away for a moment.
const char *controlState() {
  if (mifareSweepActive) {
    return "sweeping";
  }
  if (awaitingRemoval) {
    return "awaiting-removal";
  }
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

// probeMifareBlock() — the complete on-detection auto-probe — is defined
// with the `mifare check` sweep machinery it reuses (search "on-detection
// auto-probe" below), so it sits after runCardSweep()/emitCheckSector() instead
// of forcing forward declarations for them here.

// --- REPL command extensions ------------------------------------------------
//
// BomberCatControl::Callbacks::command receives the first whitespace-
// separated token as `verb` and the rest of the line, untouched, as `args`;
// the sketch owns parsing beyond that and must emit its own +OK/-ERR
// terminator (see BomberCatControl.h). All "mifare ..." replies below follow
// the same leading-marker wire convention the core uses; the formatting
// itself now comes from BomberCatControl's public reply helpers (ok/err/kv)
// so there is a single wire-format implementation in `core`. The local shims
// only bind the shared `control` instance to this sketch's String-based call
// sites.

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

// Parses exactly `expectedBytes` * 2 hex chars from `hex` into `out`. Rejects
// any other length or a non-hex character. (Strict on purpose: HexUtils::
// decode() is lenient and would silently accept spaces or skip bad input,
// which would truncate keys/blocks on the wire.)
static bool parseHexBytes(const char *hex, uint8_t *out,
                          uint8_t expectedBytes) {
  if (hex == nullptr || strlen(hex) != (size_t)expectedBytes * 2) {
    return false;
  }
  for (uint8_t i = 0; i < expectedBytes; i++) {
    int hi = HexUtils::nibble(hex[i * 2]);
    int lo = HexUtils::nibble(hex[i * 2 + 1]);
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

// Thin delegations to the shared `control` instance (BomberCatControl): the
// +OK/-ERR/":key value" formatting is authored once in core and the String
// overloads below keep this sketch's ~90 call sites untouched.
static void replyOk() { control.ok(); }

static void replyOk(const String &msg) { control.ok(msg.c_str()); }

static void replyErr(const char *msg) { control.err(msg); }

static void replyKv(const char *key, const String &value) {
  control.kv(key, value.c_str());
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
    if (!timedReselect(nfc)) {
      beginCardRemovalWait(); // card left the field while the session was open
      return false;
    }
  }
  return true;
}

// The re-select, with the wall-clock split.
//
// Same choreography as mifareReselect() — a full reader re-arm (the only
// re-selection proven on this hardware, see MifareCommands.cpp) followed by
// the wait for the card to be detected again — but MEASURED, because it is
// the dominant cost of a dictionary sweep (a wrong key HALTs the card, and
// every wrong key costs one re-select).
//
// The two halves are timed apart because they have different fixes: the
// re-arm is I²C/NCI work the firmware does, while the detection wait is the
// card waking up from its HALT state and the reader finding it again.
static bool timedReselect(NfcController &nfc) {
  mifareSweepReselects++;
  const uint32_t t0 = millis();
  const bool armed = nfc.reset();
  const uint32_t t1 = millis();
  mifareSweepResetMs += t1 - t0;
  if (!armed) {
    mifareSweepReselectMs += millis() - t0;
    mifareSweepReselectFails++;
    return false;
  }
  // The SAME window mifareReselect() uses (2000 ms): the card was HALTed by
  // the failed authentication, so waking it up takes longer than a warm
  // re-detection. waitForTag()'s default (500 ms) is what this call used
  // before, and it was the wrong window for the wrong path - see
  // MIFARE_CHECK_RESELECT_MS.
  const bool detected = nfc.waitForTag(MIFARE_CHECK_RESELECT_MS);
  mifareSweepDetectMs += millis() - t1;
  mifareSweepReselectMs += millis() - t0;
  if (!detected) {
    mifareSweepReselectFails++;
  }
  return detected;
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
  // Timed like the on-device sweep: the host-driven sweep
  // and the on-device one must be comparable with the SAME counters, or the
  // difference between them stays a guess.
  const uint32_t t0 = millis();
  const bool authOk = mifareAuthenticate(nfc, blockNum, keyType, key);
  mifareSweepAuthMs += millis() - t0;
  mifareSweepAttempts++;
  if (authOk) {
    mifareCardAuthed = true; // session now open; tear down before the next auth
    replyOk();
  } else {
    mifareCardAuthed = false;
    // A wrong key HALTs the card. Re-select it before answering so the host's
    // NEXT dictionary attempt starts clean — without this, one wrong key (e.g.
    // FFFFFFFFFFFF on a sector keyed A0A1A2A3A4A5) dooms the whole sweep and
    // `mifare check` reports every key as failing. sweepReselect() returns
    // false only when several consecutive re-selects prove the card is gone,
    // which distinguishes a real wrong-key from a removed card: end the
    // session and re-arm in that case so the host's next command correctly
    // gets "no card selected" instead of a misleading auth failure. See
    // CLI_IMPROVEMENTS_MifareCheck.md §4.
    if (!sweepReselect(nfc)) {
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
// last one instead of listing all three.
//
// The persisted key-store (mifareKeys) is listed right after the
// built-ins, continuing the SAME index sequence (:mifare_key3, :mifare_key4,
// ...). The host reads the list with a "while mifare_key{i} in data" loop, so
// the stored keys show up there with no host change at all.
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

  // Stored (custom) keys, in the order they were added.
  for (uint8_t i = 0; i < mifareKeys.count; i++) {
    char key[16];
    snprintf(key, sizeof(key), "mifare_key%u", (unsigned)(3 + i));
    replyKv(key,
            String("custom ") + TagReader::hexCompact(mifareKeys.keys[i], 6));
  }
  replyOk();
}

// --- `mifare check` on-device dictionary sweep --------------------
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

// Fusion policy: seed the sweep's confirmed-key pool with
// the persisted key-store, so a user-curated key is tried BEFORE the embedded
// dictionary - a key the user added because it opened a card in the field is a
// far better bet than a generic default. The keys the sweep confirms during
// the run are appended after them, so the known-first reuse still works.
//
// With an empty key-store this seeds nothing and the sweep is bit-identical
// to the baseline (`attempts` <= 66 on card_1k stays true).
static uint8_t seedKnownFromStore(uint8_t known[][6], uint8_t maxCount) {
  uint8_t n = 0;
  for (uint8_t i = 0; i < mifareKeys.count && n < maxCount; i++) {
    memcpy(known[n], mifareKeys.keys[i], 6);
    n++;
  }
  return n;
}

// Persist the keys a sweep confirmed that are NOT
// part of the dictionary it swept - i.e. genuinely custom keys - so the next
// card/session finds them without another sweep. Opt-in through
// `mifare keys autostore on` (the flag is persisted with the store, so it
// survives a reset).
//
// Wear: the whole record is rewritten, so this performs AT MOST one flash
// write per sweep, and only when there is something new to save. Keys that
// came from a dictionary are skipped - the embedded one always covers them,
// and storing them would fill the store with noise.
static void autostoreRecoveredKeys(const uint8_t dict[][6], uint8_t dictCount,
                                   const uint8_t known[][6],
                                   uint8_t knownCount) {
  if ((mifareKeys.flags & MIFARE_KEYSTORE_FLAG_AUTOSTORE) == 0) {
    return;
  }
  bool changed = false;
  for (uint8_t i = 0; i < knownCount; i++) {
    if (keyInSet(MIFARE_CHECK_DICT, MIFARE_CHECK_DICT_COUNT, known[i]) ||
        keyInSet(dict, dictCount, known[i])) {
      continue; // already covered by a dictionary
    }
    if (mifareKeyStoreIndexOf(mifareKeys, known[i]) >= 0) {
      continue; // already stored
    }
    if (!mifareKeyStoreAdd(mifareKeys, known[i])) {
      break; // store full - keep what we got
    }
    changed = true;
  }
  if (changed) {
    mifareKeyStoreSave(config, mifareKeys);
  }
}

// The sweep's re-select, with retries.
//
// A single failed re-select does NOT mean the card left the field: the chip
// can miss the card's wake-up, or the I2C re-init can hiccup, while the card
// is right there on the reader. The removal probe already needs several
// consecutive misses before it believes the card is gone
// (MIFARE_REMOVAL_MISSES_TO_CONFIRM) - the sweep must not be stricter, or a
// single hiccup throws away every sector the sweep has not reached yet.
//
// This is what turned a card that yields 15/16 sectors through the host path
// into a "1/16 sectors known" card through the device path: the sweep gave
// up on the first hiccup and the host was then told the partial result as if
// it were the whole card.
static bool sweepReselect(NfcController &nfc) {
  for (uint8_t i = 0; i < MIFARE_CHECK_RESELECT_TRIES; i++) {
    if (timedReselect(nfc)) {
      return true;
    }
  }
  return false;
}

// One sweep authentication with the same clean-session choreography the host's
// `mifare auth` uses. Before the attempt, tear down any warm Crypto1 session
// left by a prior success (or the auto-probe) via a re-select, so this auth is
// evaluated independently instead of riding the open session — the Key B ==
// Key A false hit documented at mifareCardAuthed / mifareBeginAuth(). After a
// wrong key (which HALTs the card) re-select so the next attempt starts clean.
// Sets *removed = true and returns false when the re-selects prove the card
// left the field. Returns true on a real successful auth (card left warm).
static bool sweepAuth(uint8_t block, uint8_t keyType, const uint8_t *key,
                      uint32_t *attempts, bool *removed) {
  *removed = false;
  if (mifareCardAuthed) {
    mifareCardAuthed = false;
    if (!sweepReselect(nfc)) {
      *removed = true;
      return false;
    }
    delay(mifareCheckSettleMs); // let the PN7150 settle before the auth
  }
  (*attempts)++;
  const uint32_t t0 = millis();
  const bool ok = mifareAuthenticate(nfc, block, keyType, key);
  mifareSweepAuthMs += millis() - t0;
  mifareSweepAttempts++;
  if (ok) {
    mifareCardAuthed = true; // leave warm; next sweepAuth tears it down
    return true;
  }
  if (sweepReselect(nfc)) {     // recover the HALTed card before the next key
    delay(mifareCheckSettleMs); // same rest the USB-paced host path gets
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

// --- sweep result cache ----------------------------------
//
// The sweep's recovered keys are kept in RAM so the dump step can reuse them
// without sweeping the card a second time. `mifare dump` (and the automatic
// standalone dump) read the card with these keys; the host's `mifare dump`
// gets the same result in ONE round-trip instead of one per sector.

static void sweepCacheReset(uint8_t sectors) {
  memset(mifareSweepHave, 0, sizeof(mifareSweepHave));
  mifareSweepSectors = sectors;
  mifareSweepValid = true; // there IS sweep data for the card in the field
}

// Store one sector's recovered keys (either half may be absent).
static void sweepCacheStore(uint8_t sector, bool haveA, const uint8_t *keyA,
                            bool haveB, const uint8_t *keyB) {
  if (sector >= MIFARE_CHECK_MAX_SECTORS) {
    return;
  }
  uint8_t mask = 0;
  if (haveA) {
    memcpy(mifareSweepKeys[sector][0], keyA, 6);
    mask |= 0x01;
  }
  if (haveB) {
    memcpy(mifareSweepKeys[sector][1], keyB, 6);
    mask |= 0x02;
  }
  mifareSweepHave[sector] = mask;
}

// The cached keys of one sector: `haveA`/`haveB` say which half is real.
static void sweepCacheGet(uint8_t sector, bool *haveA, const uint8_t **keyA,
                          bool *haveB, const uint8_t **keyB) {
  if (sector >= MIFARE_CHECK_MAX_SECTORS) {
    *haveA = false;
    *haveB = false;
    *keyA = nullptr;
    *keyB = nullptr;
    return;
  }
  const uint8_t mask = mifareSweepHave[sector];
  *haveA = (mask & 0x01) != 0;
  *haveB = (mask & 0x02) != 0;
  *keyA = mifareSweepKeys[sector][0];
  *keyB = mifareSweepKeys[sector][1];
}

// Drop the cached sweep. Called when the card leaves the field (the next
// card is a different one) and when the key-store changes (the dictionary the
// sweep used is no longer the one the store would use now).
static void sweepCacheInvalidate() {
  mifareSweepValid = false;
  mifareSweepSectors = 0;
  mifareSweepCacheAborted = false;
  memset(mifareSweepHave, 0, sizeof(mifareSweepHave));
}

// Shared sector x {A,B} dictionary sweep, factored out of `mifare check` so the
// on-detection auto-probe runs the exact same logic instead of the old
// degenerate block-4 / Key-A / 3-key probe (reuse, don't duplicate).
// Sweeps `sectors` sectors, each Key A then Key B, over `dict`, delivering
// every sector's recovered keys to `sink(..., ctx)` as it resolves. `known`/
// `knownCount` is the caller-owned confirmed-key reuse store the sweep appends
// to; it doubles as the key-store seed hook — pre-fill it
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
  mifareSweepActive = true; // `info` says "sweeping" while this runs
  sweepCacheReset(sectors); // the dump step reads the keys from here
  mifareSweepAuthMs = 0;    // the wall-clock split of this sweep
  mifareSweepReselectMs = 0;
  mifareSweepResetMs = 0;
  mifareSweepDetectMs = 0;
  mifareSweepTrailerMs = 0;
  mifareSweepAttempts = 0;
  mifareSweepReselects = 0;
  // The naive baseline is the PROJECTION of the whole sweep - every slot
  // trying the whole dictionary, with no reuse shortcut and no early cut -
  // and it is declared UP FRONT, not accumulated slot by slot. A sweep that
  // gives up half-way still reports the honest cost of the sweep it was
  // supposed to run, and the "auths saved" ratio stays meaningful instead of
  // comparing a truncated attempt count with a full projection.
  *naive = (uint32_t)sectors * 2 * dictCount;
  for (uint8_t s = 0; s < sectors; s++) {
    const uint8_t block = s * MIFARE_BLOCKS_PER_SECTOR;
    uint8_t keyA[6], keyB[6];
    bool haveA = false, haveB = false;

    for (uint8_t ktIdx = 0; ktIdx < 2; ktIdx++) {
      const uint8_t keyType = (ktIdx == 0) ? MIFARE_KEY_A : MIFARE_KEY_B;
      uint8_t found[6];
      SweepSlotResult res = sweepSlot(block, keyType, known, *knownCount, dict,
                                      dictCount, attempts, found);
      if (res == SLOT_CARD_REMOVED) {
        mifareSweepActive = false;
        // Publish what the sweep got before it gave up. The cached counters
        // are what a later `mifare check` answers with, and leaving them
        // stale (from an earlier sweep, or at zero) made the host report the
        // partial result of an interrupted sweep as if it were the whole card.
        mifareSweepCacheAttempts = *attempts;
        mifareSweepCacheNaive = *naive;
        mifareSweepCacheRecovered = *recovered;
        mifareSweepCacheTrailer = 0; // the trailer pass never ran
        mifareSweepCacheAborted = true;
        // The wall-clock split of the aborted sweep travels with it: it is
        // what tells "the card left" from "the re-select gave up" (see
        // det_timeout / det_ok in `mifare timing`).
        mifareSweepCacheAuthMs = mifareSweepAuthMs;
        mifareSweepCacheReselectMs = mifareSweepReselectMs;
        mifareSweepCacheResetMs = mifareSweepResetMs;
        mifareSweepCacheDetectMs = mifareSweepDetectMs;
        mifareSweepCacheTrailerMs = mifareSweepTrailerMs;
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
    sweepCacheStore(s, haveA, keyA, haveB, keyB);
  }
  mifareSweepActive = false;
  mifareSweepCacheAborted = false;
  // The counters of THIS sweep go with the cached keys, so a later
  // `mifare check` can answer from the cache with the same numbers.
  mifareSweepCacheAttempts = *attempts;
  mifareSweepCacheNaive = *naive;
  return SWEEP_DONE;
}

// `mifare check` per-sector sink: stream the recovered keys in the documented
// :mifare_check_sN format (serial_log_format.md). No ctx needed.
static void checkSectorSink(uint8_t sector, bool haveA, const uint8_t *keyA,
                            bool haveB, const uint8_t *keyB, void *ctx) {
  (void)ctx;
  emitCheckSector(sector, haveA, keyA, haveB, keyB);
}

// --- on-detection auto-probe
// -------------------------------------------------------

// (AutoProbeCtx is declared with the other types near the top of the file,
// because the Arduino auto-generated prototypes come before this section.)

// On-detection auto-probe sink: stream each sector's recovered keys exactly
// like `mifare check` (one wire format for both, parsed by the host)
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

// Legacy session-open signal: re-read MIFARE_PROBE_BLOCK with the Key A the
// sweep recovered for its sector, so a default-keyed card still produces the
// exact block-4 data event the degenerate probe did. The sweep left a warm
// Crypto1 session on the LAST swept sector, so tear it down first (a
// re-select) to keep this authentication independent — the same
// mifareCardAuthed choreography every other auth path uses.
//
// Split out of probeMifareBlock() so the signal is emitted BEFORE the
// optional key-store flash write: that write can block the CPU for a few
// hundred ms, and the host is waiting for this exact line.
static void emitMifareSessionSignal(uint32_t tsMs, const String &uidHex,
                                    const AutoProbeCtx &ctx) {
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

// Complete on-detection auto-probe. Where the original probe tried
// only 3 keys as Key A against a single block, this runs the full sweep:
// Key A AND Key B across every default-card sector's header, over the embedded
// default-key dictionary, reusing runCardSweep so there is
// one sweep implementation, not two. Each sector's recovered keys
// stream as :mifare_check_sN lines; then a single legacy ":mifare" block event
// is emitted LAST as the session-open signal the host blocks on (session.py's
// _wait_for_mifare_card matches "^:mifare\\s"). Emitting the per-sector lines
// first and the signal line last lets the host drain the unsolicited sweep
// output while it waits and start REPL commands on a clean stream. A card with
// default keys still yields the exact block-4 data event the degenerate probe
// did (no regression); a fully unknown card yields auth_fail. Read-only — never
// writes automatically.
void probeMifareBlock(uint32_t tsMs, const String &uidHex) {
  // Confirmed-key reuse store, seeded with the persisted key-store so the
  // custom keys the user added are tried first.
  uint8_t known[MIFARE_CHECK_KNOWN_MAX][6];
  uint8_t knownCount = seedKnownFromStore(known, MIFARE_CHECK_KNOWN_MAX);
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

  // Second pass: read Key B off the card's trailer for the sectors the
  // dictionary opened with Key A only - the same pass the host runs
  // (check.py's _trailer_read_pass), so both sides recover the same keys.
  uint32_t trailerAuths = 0;
  bool cardRemoved = false;
  trailerReadPass(MIFARE_CHECK_DEFAULT_SECTORS, autoProbeSectorSink, &ctx,
                  &trailerAuths, &recovered, &cardRemoved);
  if (cardRemoved) {
    emitMifareEvent(tsMs, uidHex, MIFARE_PROBE_BLOCK, nullptr, 0, "auth_fail");
    return;
  }

  // The session-open signal goes out FIRST: the host is blocked waiting for
  // it, and the (optional) key-store flash write below can take a few
  // hundred ms with the CPU busy.
  emitMifareSessionSignal(tsMs, uidHex, ctx);

  // Standalone mode: with no PC attached, the firmware
  // finishes the job by itself - dump the sectors the sweep cracked and emit
  // them over serial. The flag persists with the key-store.
  //
  // The field trigger arms a ONE-SHOT for the next
  // detection: the operator pressed the button with no card in the field, and
  // this card is the one they meant. The one-shot is consumed here, so it
  // fires exactly once.
  const bool oneShot = mifareTrigger.takeOneShot();
  if ((mifareKeys.flags & MIFARE_KEYSTORE_FLAG_STANDALONE) || oneShot) {
    if (oneShot) {
      Serial.println(":mifare_trigger run");
    }
    runStandaloneChain();
  }

  // Persist any custom key the sweep just confirmed (opt-in; at most one
  // flash write per sweep). After the signal on purpose: the write must not
  // delay - nor disturb - the session the host is about to use.
  autostoreRecoveredKeys(MIFARE_CHECK_DICT, MIFARE_CHECK_DICT_COUNT, known,
                         knownCount);
}

// --- trailer-read Key B, sector dump, standalone ---------
//
// The workflow the host drives today, command by command, moves into the
// firmware: sweep -> read the sectors it cracked -> emit. The two pieces of
// "decryption" logic the host used to own are ported here, so both sides
// reach the SAME verdict on the same card:
//
//   * the access-bits decode (MifareAccessBits, a port of the host's
//     access_bits.py) - it decides whether Key B can be read back;
//   * the trailer read that recovers Key B without any Crypto-1 attack
//     (the twin of check.py's _recover_key_b_via_trailer).
//
// The parity is checked by a native test that compiles these modules and
// compares them with the Python ones (bombercat-tools/tests/
// test_mifare_parity.py) - not just asserted in a comment.

// Outcome of one trailer read.
//
// (TrailerReadResult is declared with the other types near the top of the
// file, because the Arduino auto-generated prototypes come before this
// section and would otherwise name an unknown type.)

// Recover Key B straight off the card's trailer, using the Key A we already
// have.
//
// This is NOT the Crypto-1 nested attack: that needs raw nonce/parity capture
// the PN7150 never surfaces (it runs Crypto-1 in-chip and only reports auth
// pass/fail). The trailer is simply READ with Key A, and only cards whose
// access bits leave Key B *readable with Key A* (the transport/default
// configs) give it back in cleartext. Key A itself never reads back under any
// access condition, so only Key B is recoverable this way.
//
// The rules are the host's, rule for rule (check.py's
// _recover_key_b_via_trailer): Key B is only accepted when the trailer's
// access bits say "Key A" - not "Key A or B" - and an all-zero Key B is
// refused as "not recovered" instead of being reported as a key.
static TrailerReadResult
recoverKeyBViaTrailer(uint8_t sector, const uint8_t *keyA, uint8_t outKeyB[6]) {
  uint8_t data[MIFARE_BLOCKS_PER_SECTOR * MIFARE_BLOCK_SIZE];
  bool authOk = false;
  // Independent auth: tear down any warm Crypto-1 session first, exactly
  // like every other authentication path (see mifareCardAuthed).
  if (!mifareBeginAuth()) {
    return TRAILER_CARD_REMOVED;
  }
  if (!mifareReadSector(nfc, sector, MIFARE_KEY_A, keyA, data, &authOk)) {
    mifareCardAuthed = false;
    // A failed read may have HALTed the card: re-select so the next step
    // starts clean. sweepReselect() returning false means the card is gone,
    // not that the key was wrong.
    if (!sweepReselect(nfc)) {
      beginCardRemovalWait();
      return TRAILER_CARD_REMOVED;
    }
    return TRAILER_FAILED;
  }
  mifareCardAuthed = true; // warm session; the next auth tears it down

  // Trailer layout: key A (0-5) | access conditions + GPB (6-9) | key B
  // (10-15).
  const uint8_t *trailer =
      data + (MIFARE_BLOCKS_PER_SECTOR - 1) * MIFARE_BLOCK_SIZE;
  MifareAccessBits access;
  mifareParseAccessBits(trailer + 6, access);
  if (access.trailer.keyBRead != MIFARE_PERM_KEY_A) {
    return TRAILER_FAILED; // Key B is protected by the access bits
  }
  memcpy(outKeyB, trailer + 10, 6);
  bool allZero = true;
  for (uint8_t i = 0; i < 6; i++) {
    if (outKeyB[i] != 0) {
      allZero = false;
      break;
    }
  }
  if (allZero) {
    return TRAILER_FAILED; // the card returned zeros for Key B
  }
  return TRAILER_OK;
}

// Second pass of a sweep: every sector the dictionary opened with Key A but
// NOT with Key B gets one more try - read the trailer with the Key A we have
// and take Key B off it.
//
// The host does exactly this (check.py's _trailer_read_pass), so both sides
// recover the same keys from the same card. It runs AFTER the whole sweep,
// exactly like the host, so a Key B recovered this way does NOT enter the
// sweep's known-key pool: the number of authentications stays comparable
// between the host-driven and the on-device sweep.
//
// `sink` re-emits the sector's line with the Key B filled in. The host keeps
// the LAST line per sector, so the updated key wins.
static uint8_t trailerReadPass(uint8_t sectors, SweepSectorSink sink, void *ctx,
                               uint32_t *trailerAuths, uint8_t *recovered,
                               bool *removed) {
  uint8_t found = 0;
  *removed = false;
  for (uint8_t s = 0; s < sectors; s++) {
    bool haveA, haveB;
    const uint8_t *keyA, *keyB;
    sweepCacheGet(s, &haveA, &keyA, &haveB, &keyB);
    if (!haveA || haveB) {
      continue; // nothing to read the trailer with, or Key B is already known
    }
    (*trailerAuths)++;
    uint8_t keyBRead[6];
    const uint32_t t0 = millis();
    TrailerReadResult res = recoverKeyBViaTrailer(s, keyA, keyBRead);
    mifareSweepTrailerMs += millis() - t0;
    if (res == TRAILER_CARD_REMOVED) {
      *removed = true;
      return found;
    }
    if (res != TRAILER_OK) {
      continue; // protected by the access bits, or the read failed
    }
    sweepCacheStore(s, true, keyA, true, keyBRead);
    (*recovered)++;
    found++;
    if (sink != nullptr) {
      sink(s, true, keyA, true, keyBRead, ctx);
    }
  }
  // The cached sweep's counters follow the pass (the recovered keys it added
  // are part of the result).
  mifareSweepCacheRecovered = *recovered;
  mifareSweepCacheTrailer =
      (uint8_t)(*trailerAuths > 255 ? 255 : *trailerAuths);
  mifareSweepCacheAuthMs = mifareSweepAuthMs;
  mifareSweepCacheReselectMs = mifareSweepReselectMs;
  mifareSweepCacheResetMs = mifareSweepResetMs;
  mifareSweepCacheDetectMs = mifareSweepDetectMs;
  mifareSweepCacheTrailerMs = mifareSweepTrailerMs;
  return found;
}

// Emit one dumped sector: the 4 blocks as 128 hex chars (or "-" for a hole)
// and the key type that opened it ("A"/"B", "-" for a hole). A sector that
// could not be read carries the reason as a third token ("nokey", "readfail",
// "removed") - the host turns it into the `failed_sectors` entry.
//
// The line itself is built by MifareDumpFormat (the library's canonical dump
// format), so this firmware emits the same bytes MifareDumpFormat's own
// builder produces for the same card.
static void emitDumpSector(uint8_t sector, const uint8_t *data, char keyType,
                           const char *reason) {
  char line[8 + 2 * MIFARE_SECTOR_BYTES + 32];
  if (MifareDumpFormat::formatSector(line, sizeof(line), sector, data, keyType,
                                     reason) == 0) {
    Serial.println("-ERR dump line too long");
    return;
  }
  Serial.println(line);
  Serial.flush(); // push the line over USB now; also services the USB stack
}

// The closing stat line of a dump ("read=<n> failed=<n> total=<n>"). Built by
// MifareDumpFormat, so it emits the same bytes MifareDumpFormat's own builder
// produces for the same counters.
static void emitDumpStat(uint8_t read, uint8_t failed, uint8_t total) {
  char line[64];
  if (MifareDumpFormat::formatStat(line, sizeof(line), read, failed, total) ==
      0) {
    Serial.println("-ERR dump stat too long");
    return;
  }
  Serial.println(line);
  Serial.flush();
}

// The block 0 the card returned, dissected with the SAME rules as the host's
// block0.py (the firmware's MifareBlock0 is a port of it). Emitted raw AND
// dissected: a host that has block0.py re-parses the raw bytes and gets the
// identical verdict, and one that doesn't can still read the fields.
//
// The UID stored in block 0 is cross-checked against the anti-collision UID:
// they differ on a clone/magic card, and that difference is worth saying out
// loud instead of hiding it in a hex dump.
static void emitCard0(const uint8_t *sector0) {
  MifareBlock0 b0;
  mifareParseBlock0(sector0, b0);
  emitCard0Raw(sector0);

  const String uidHex = TagReader::hexCompact(b0.uid, 4);
  if (mifareCardUid.length() > 0 && mifareCardUid != uidHex) {
    Serial.println("WARNING: the UID in block 0 differs from the tag UID "
                   "(clone/magic card?)");
  }
}

// The raw `:mifare_card0` line: the block the card returned, dissected with
// the SAME rules as the host's block0.py (the firmware's MifareBlock0 is a
// port of it). Emitted raw AND dissected: a host that has block0.py re-parses
// the raw bytes and gets the identical verdict, and one that doesn't can
// still read the fields.
//
// Split from emitCard0() because the cross-check against the anti-collision
// UID only makes sense for a card that is IN the field right now: a stored
// result is replayed later, when a DIFFERENT card may be
// on the reader - and the warning would then be a lie.
static void emitCard0Raw(const uint8_t *sector0) {
  MifareBlock0 b0;
  mifareParseBlock0(sector0, b0);
  Serial.print(":mifare_card0 ");
  Serial.print(TagReader::hexCompact(sector0, MIFARE_BLOCK_SIZE));
  Serial.print(" uid=");
  Serial.print(TagReader::hexCompact(b0.uid, 4));
  Serial.print(" sak=");
  Serial.print(TagReader::hexCompact(&b0.sak, 1));
  Serial.print(" atqa=");
  Serial.print(TagReader::hexCompact(b0.atqa, 2));
  Serial.print(" bcc=");
  Serial.print(TagReader::hexCompact(&b0.bcc, 1));
  Serial.print(" bcc_ok=");
  Serial.println(b0.bccValid ? 1 : 0);
  Serial.flush();
}

// Read every sector the sweep cracked and emit it.
//
// The keys come from the sweep cache, so the card is read ONCE: no second
// sweep, no per-sector host round-trip. A sector with no recovered key is an
// honest hole ("nokey"), never a guess.
//
// `collect` is where the same result is kept for the flash: when it is not
// null, every sector's outcome - INCLUDING the reason
// of a hole - is copied into it, so the stored result says exactly what the
// serial dump said.
static SweepResult runSectorDump(uint8_t sectors, uint8_t *read,
                                 uint8_t *failed, MifareResultRecord *collect) {
  for (uint8_t s = 0; s < sectors; s++) {
    bool haveA, haveB;
    const uint8_t *keyA, *keyB;
    sweepCacheGet(s, &haveA, &keyA, &haveB, &keyB);
    if (!haveA && !haveB) {
      emitDumpSector(s, nullptr, '-', "nokey");
      if (collect != nullptr) {
        mifareResultSetSector(*collect, s, MIFARE_RESULT_NOKEY, '-', nullptr);
      }
      (*failed)++;
      continue;
    }
    const bool useA = haveA;
    const uint8_t keyType = useA ? MIFARE_KEY_A : MIFARE_KEY_B;
    const uint8_t *key = useA ? keyA : keyB;

    // Independent auth: never ride a warm session from a previous sector.
    if (!mifareBeginAuth()) {
      emitDumpSector(s, nullptr, '-', "removed");
      if (collect != nullptr) {
        mifareResultSetSector(*collect, s, MIFARE_RESULT_REMOVED, '-', nullptr);
      }
      (*failed)++;
      return SWEEP_CARD_REMOVED;
    }
    uint8_t data[MIFARE_BLOCKS_PER_SECTOR * MIFARE_BLOCK_SIZE];
    bool authOk = false;
    if (!mifareReadSector(nfc, s, keyType, key, data, &authOk)) {
      mifareCardAuthed = false;
      if (!mifareReselect(nfc)) {
        beginCardRemovalWait();
        emitDumpSector(s, nullptr, '-', "removed");
        if (collect != nullptr) {
          mifareResultSetSector(*collect, s, MIFARE_RESULT_REMOVED, '-',
                                nullptr);
        }
        (*failed)++;
        return SWEEP_CARD_REMOVED;
      }
      emitDumpSector(s, nullptr, '-', "readfail");
      if (collect != nullptr) {
        mifareResultSetSector(*collect, s, MIFARE_RESULT_READFAIL, '-',
                              nullptr);
      }
      (*failed)++;
      continue;
    }
    mifareCardAuthed = true; // warm session; the next auth tears it down

    // Substitute the recovered keys into the trailer: a card never reads Key
    // A back (and often not Key B either), so the raw bytes would show zeros
    // where the real keys are. Same substitution the host's dump does
    // (display.py's _substitute_trailer_keys), so both dumps are identical.
    uint8_t *trailer =
        data + (MIFARE_BLOCKS_PER_SECTOR - 1) * MIFARE_BLOCK_SIZE;
    if (haveA) {
      memcpy(trailer, keyA, 6);
    }
    if (haveB) {
      memcpy(trailer + 10, keyB, 6);
    }
    emitDumpSector(s, data, useA ? 'A' : 'B', nullptr);
    if (collect != nullptr) {
      // AFTER the substitution: the stored bytes are the very bytes the
      // serial dump emitted.
      mifareResultSetSector(*collect, s, MIFARE_RESULT_READ, useA ? 'A' : 'B',
                            data);
    }
    (*read)++;
    if (s == 0) {
      emitCard0(data);
    }
  }
  return SWEEP_DONE;
}

// The standalone workflow: with no PC attached, the
// firmware finishes the job by itself - dump the sectors the sweep cracked
// and emit everything over serial.
//
// Control is ceded BETWEEN the steps (control.poll()), never inside one: a
// command arriving mid-dump would touch the very card session the dump is
// using, so `mifare ...` is refused while the chain runs (see
// bomberCatCommand).
static void runStandaloneChain() {
  mifareChainActive = true;
  control.poll(); // cede control between the steps

  // The result the board keeps for the operator: the very
  // dump it is emitting, holes included, stored in its own flash so it can
  // be collected later, over USB, when nobody was listening to the serial
  // port.
  mifareResultInit(mifareResultBuild);
  mifareResultBuild.sectors = mifareSweepSectors;
  mifareResultBuild.tsMs = millis();
  strncpy(mifareResultBuild.uid, mifareCardUid.c_str(),
          sizeof(mifareResultBuild.uid) - 1);
  mifareResultBuild.uid[sizeof(mifareResultBuild.uid) - 1] = '\0';

  uint8_t read = 0, failed = 0;
  SweepResult res =
      runSectorDump(mifareSweepSectors, &read, &failed, &mifareResultBuild);
  mifareChainActive = false;
  if (res == SWEEP_CARD_REMOVED) {
    // The card left the field in the middle of the dump. The sectors that
    // were never reached are holes with the "removed" reason - the card was
    // GONE, not unopenable - and the partial result is still a result: it
    // is emitted and kept, with its counters saying exactly what happened.
    for (uint8_t s = 0; s < mifareResultBuild.sectors; s++) {
      if (mifareResultBuild.status[s] == MIFARE_RESULT_MISSING) {
        mifareResultSetSector(mifareResultBuild, s, MIFARE_RESULT_REMOVED, '-',
                              nullptr);
        failed++;
      }
    }
    beginCardRemovalWait();
  }
  emitDumpStat(read, failed, mifareSweepSectors);

  // Keep the result in the flash (ONE write per card, never per key).
  storeStandaloneResult(mifareResultBuild, read, failed);
}

// Store the result of a standalone run in the flash ring.
//
// ONE write per card: the record goes into the slot that holds the OLDEST
// result (or the first free one), so the ring always keeps the newest
// results. The erases are the store's own business (mbed's TDBStore rewrites
// its whole area when it fills up - about every 450 results stored, orders of
// magnitude below the flash's 100k erase cycles); this store only ever
// APPENDS one record per card.
//
// A failed write is NOT fatal: the result was already emitted over the
// serial port, so the run is not lost - only the copy that would have been
// collected later is. The failure is said out loud instead of passing
// unnoticed.
static bool storeStandaloneResult(MifareResultRecord &record, uint8_t read,
                                  uint8_t failed) {
  if (!mifareResultsReady) {
    Serial.println(":mifare_result_saved error flash-unavailable");
    Serial.flush();
    return false;
  }
  record.read = read;
  record.failed = failed;
  if (!mifareResults.store(record)) {
    Serial.println(":mifare_result_saved error flash-write-failed");
    Serial.flush();
    return false;
  }
  Serial.print(":mifare_result_saved seq=");
  Serial.print(record.seq);
  Serial.print(" slot=");
  Serial.print(record.slot);
  Serial.print(" read=");
  Serial.print(read);
  Serial.print(" failed=");
  Serial.println(failed);
  Serial.flush();
  return true;
}

// Emit a stored result in the very same wire format a live dump uses:
// `:mifare_dump_sN <hex128|-> <A|B|-> [reason]` per sector, the counters and
// the dissected block 0. The host parses it with the code it already has, so
// a result collected later is indistinguishable from one read with the PC
// attached - including its holes, which are declared, never filled.
static void emitStoredResult(const MifareResultRecord &record) {
  for (uint8_t s = 0; s < record.sectors && s < MIFARE_RESULT_MAX_SECTORS;
       s++) {
    const uint8_t status = record.status[s];
    if (status == MIFARE_RESULT_READ) {
      // formatSector() maps the stored byte ('A'/'B'/other) to the wire token
      // itself, so the raw byte is all this needs to carry.
      emitDumpSector(s, record.data[s], (char)record.keyType[s], nullptr);
      continue;
    }
    const char *reason = mifareResultReason(status);
    if (reason[0] == '\0') {
      reason = "nokey"; // a sector the card does not have: an honest hole
    }
    emitDumpSector(s, nullptr, '-', reason);
  }
  emitDumpStat(record.read, record.failed, record.sectors);
  // The block 0 the card returned, dissected with the firmware's own
  // MifareBlock0 (the twin of the host's block0.py). NOT emitCard0(): the
  // cross-check against the anti-collision UID is about the card that is in
  // the field NOW, and this result may be replayed hours later.
  if (record.sectors > 0 && record.status[0] == MIFARE_RESULT_READ) {
    emitCard0Raw(record.data[0]);
  }
}

// `mifare dump [--sectors <n>]` -> :mifare_dump_sN <hex128|-> <A|B|-> per
// sector, :mifare_dump_stat read=<n> failed=<n> total=<n>, +OK.
//
// Reads the card with the keys the last sweep recovered (the cache), so the
// card is read ONCE: no second sweep, no per-sector host round-trip. Needs a
// sweep first - `mifare check` (or the on-detection auto-probe) fills it.
void handleMifareDump(char *args) {
  uint8_t sectors =
      mifareSweepValid ? mifareSweepSectors : MIFARE_CHECK_DEFAULT_SECTORS;
  char *tok;
  while ((tok = nextArg(&args)) != nullptr) {
    if (strcmp(tok, "--sectors") == 0) {
      char *v = nextArg(&args);
      int n = (v != nullptr) ? atoi(v) : 0;
      if (n < 1 || n > MIFARE_CHECK_MAX_SECTORS) {
        replyErr("usage: mifare dump [--sectors <1..32>]");
        return;
      }
      sectors = (uint8_t)n;
    } else {
      replyErr("usage: mifare dump [--sectors <1..32>]");
      return;
    }
  }
  if (!mifareSweepValid) {
    replyErr("no sweep results yet - run 'mifare check' first");
    return;
  }
  // Never read past what the sweep covered: those sectors have no keys.
  if (sectors > mifareSweepSectors) {
    sectors = mifareSweepSectors;
  }

  uint8_t read = 0, failed = 0;
  // Not stored in the flash: this dump is driven by a host that is RIGHT
  // THERE and receives it over the serial port. Only the standalone run
  // (no PC attached) keeps a copy for later.
  if (runSectorDump(sectors, &read, &failed, nullptr) == SWEEP_CARD_REMOVED) {
    beginCardRemovalWait();
    replyErr("card removed mid-dump, tap a card again");
    return;
  }
  emitDumpStat(read, failed, sectors);
  // A dump may have overrun the idle window while loop() was blocked; give a
  // follow-up REPL command the full window again.
  mifareSessionDeadline = millis() + MIFARE_SESSION_IDLE_MS;
  replyOk();
}

// `mifare standalone [on|off]` -> +OK standalone on|off
//
// Standalone mode: with no PC attached, the firmware runs
// the whole field workflow by itself when a card is detected - sweep, dump the
// sectors it cracked, emit everything over serial, and store the custom keys
// it confirmed. The flag persists with the key-store, so it survives a reset.
void handleMifareStandalone(char *args) {
  char *mode = nextArg(&args);
  uint8_t flags = mifareKeys.flags;
  if (mode == nullptr) {
    replyOk(String("standalone ") +
            ((flags & MIFARE_KEYSTORE_FLAG_STANDALONE) ? "on" : "off"));
    return;
  }
  if (strcmp(mode, "on") == 0) {
    flags |= MIFARE_KEYSTORE_FLAG_STANDALONE;
  } else if (strcmp(mode, "off") == 0) {
    flags &= (uint8_t)~MIFARE_KEYSTORE_FLAG_STANDALONE;
  } else {
    replyErr("usage: mifare standalone [on|off]");
    return;
  }
  if (flags == mifareKeys.flags) {
    // Nothing changed: do NOT rewrite the flash record (wear).
    replyOk(String("standalone ") +
            ((flags & MIFARE_KEYSTORE_FLAG_STANDALONE) ? "on" : "off"));
    return;
  }
  MifareKeyStore backup = mifareKeys;
  mifareKeys.flags = flags;
  if (!mifareKeyStoreSave(config, mifareKeys)) {
    mifareKeys = backup; // keep RAM and flash in sync
    replyErr("could not persist the setting (flash write failed)");
    return;
  }
  replyOk(String("standalone ") +
          ((flags & MIFARE_KEYSTORE_FLAG_STANDALONE) ? "on" : "off"));
}

// --- the results the board kept on its own ---------------
//
// `mifare results`            -> list the results the board stored, newest
//                                first (one line per result).
// `mifare results show <n>`   -> re-emit result n (0 = the newest) in the very
//                                same wire format a live dump uses, so the
//                                host parses it with the code it already has.
// `mifare results clear`      -> erase every stored result.
//
// None of these need a card: the results live in the board's own flash.
//
// The stored result keeps the HOLES with their reason ("nokey", "readfail",
// "removed"), so a result collected hours later says exactly what the card
// gave and what it did not - the honest-gap rule of the plan (transversal
// restriction #6), which is the whole point of task 4.6.

void handleMifareResults(char *args) {
  char *sub = nextArg(&args);
  if (sub == nullptr || strcmp(sub, "list") == 0) {
    if (!mifareResultsReady) {
      replyErr("the results store is unavailable (flash init failed)");
      return;
    }
    const uint8_t count = mifareResults.scan();
    MifareResultMeta meta[MIFARE_RESULT_SLOTS];
    const uint8_t n = mifareResults.list(meta, MIFARE_RESULT_SLOTS);
    for (uint8_t i = 0; i < n; i++) {
      Serial.print(":mifare_result");
      Serial.print(i);
      Serial.print(" seq=");
      Serial.print(meta[i].seq);
      Serial.print(" ts=");
      Serial.print(meta[i].tsMs);
      Serial.print(" uid=");
      Serial.print(meta[i].uid);
      Serial.print(" sectors=");
      Serial.print(meta[i].sectors);
      Serial.print(" read=");
      Serial.print(meta[i].read);
      Serial.print(" failed=");
      Serial.println(meta[i].failed);
    }
    Serial.print(":mifare_results_stat slots=");
    Serial.print(MIFARE_RESULT_SLOTS);
    Serial.print(" used=");
    Serial.print(count);
    Serial.print(" seq=");
    Serial.println(count > 0 ? meta[0].seq : 0);
    Serial.flush();
    replyOk();
    return;
  }

  if (strcmp(sub, "show") == 0) {
    char *idxTok = nextArg(&args);
    int index = 0;
    if (idxTok != nullptr) {
      index = atoi(idxTok);
      if (index < 0 || index >= MIFARE_RESULT_SLOTS) {
        replyErr("usage: mifare results show [0..7]");
        return;
      }
    }
    if (!mifareResultsReady) {
      replyErr("the results store is unavailable (flash init failed)");
      return;
    }
    mifareResults.scan();
    const MifareResultRecord *record = mifareResults.load((uint8_t)index);
    if (record == nullptr) {
      replyErr("no such stored result");
      return;
    }
    // The result's own metadata, in the same shape the listing uses.
    Serial.print(":mifare_result");
    Serial.print(index);
    Serial.print(" seq=");
    Serial.print(record->seq);
    Serial.print(" ts=");
    Serial.print(record->tsMs);
    Serial.print(" uid=");
    Serial.print(record->uid);
    Serial.print(" sectors=");
    Serial.print(record->sectors);
    Serial.print(" read=");
    Serial.print(record->read);
    Serial.print(" failed=");
    Serial.println(record->failed);
    Serial.flush();
    // ... and the dump itself, in the live dump's format.
    emitStoredResult(*record);
    replyOk();
    return;
  }

  if (strcmp(sub, "clear") == 0) {
    if (!mifareResultsReady) {
      replyErr("the results store is unavailable (flash init failed)");
      return;
    }
    if (!mifareResults.clear()) {
      replyErr("could not erase the stored results (flash write failed)");
      return;
    }
    replyOk("results cleared");
    return;
  }

  replyErr("usage: mifare results [list|show <0..7>|clear]");
}

// --- the field trigger -----------------------------------
//
// The standalone workflow needs a GESTURE to start it in the field, with no PC
// attached. The BomberCat board has two push buttons (BOM v1.3):
//
//   SW1 "RESET" -> the RP2040's RUN pin: pressing it reboots the board, so it
//                  cannot be a trigger (the reboot would kill the sweep in
//                  progress and wipe the key-store's RAM copy).
//   SW2 "GPIO"  -> RP2040 GPIO17 = Arduino D5, active LOW to GND. This is the
//                  board's user button, and the very same one the MagSpoof
//                  sketch triggers with (MagStripe::classic() ->
//                  pinButton = 5). The board's LED1 is on GPIO27 = D15 =
//                  LED_BUILTIN.
//
// The trigger speaks two gestures:
//
//   SHORT press -> ONE-SHOT. The chain runs for the card in the field (the
//                  auto-probe already swept it, so the dump reuses those keys:
//                  no extra authentications, no second sweep). With no card in
//                  the field it ARMS the one-shot, and the next detection runs
//                  the chain.
//
//   LONG press  -> TOGGLE the persistent standalone flag: armed mode, the
//                  chain runs on every detection. The flag is persisted with
//                  the key-store, so it survives a reset.
//
// The LED says what happened, because in the field the serial console may not
// be the thing the operator is looking at:
//
//   1 blink  -> a short press was taken (the chain runs / is armed)
//   2 blinks -> the long press ARMED the standalone mode
//   3 blinks -> the long press DISARMED it (or an action failed)
//
// Everything here is non-blocking: the button is polled on every loop()
// iteration, and the LED is driven by the same scheduler the host's
// `identify` uses, so the two never fight over the pin.

// Drive the board's LED from the pattern scheduler. The pin is only written
// when the state actually changes: a USB CDC write is not free, and the
// trigger polls this on every loop().
static void mifareLedApply(uint32_t nowMs) {
  static bool lastLit = false;
  static bool initialised = false;
  const bool lit = mifareLed.update(nowMs);
  if (!initialised || lit != lastLit) {
    digitalWrite(LED_BUILTIN, lit ? HIGH : LOW);
    lastLit = lit;
    initialised = true;
  }
}

// The host's `identify` command: a steady blink for two seconds, so the user
// can tell which board is which on the desk.
static void mifareIdentifyLed() {
  mifareLed.blinkUntil(millis() + 2000, 150, 150);
}

// Sweep the card that is in the field right now and recover the Key B's that
// can be read back - the very same two passes the on-detection auto-probe
// runs (the full sweep + the trailer pass), reused through runCardSweep()
// so there stays ONE sweep implementation.
//
// Used by the field trigger when the card in the field has no sweep results
// yet (the host drove its own sweep, so the firmware's cache is empty). The
// per-sector results are streamed in the usual `:mifare_check_sN` format, so
// the field operator sees the keys on the serial console too.
//
// Returns false when the card left the field.
static bool runFieldSweepNow() {
  uint8_t known[MIFARE_CHECK_KNOWN_MAX][6];
  uint8_t knownCount = seedKnownFromStore(known, MIFARE_CHECK_KNOWN_MAX);
  uint32_t attempts = 0, naive = 0;
  uint8_t recovered = 0;

  AutoProbeCtx ctx;
  ctx.probeSector = MIFARE_PROBE_BLOCK / MIFARE_BLOCKS_PER_SECTOR;
  ctx.haveKeyA = false;

  if (runCardSweep(MIFARE_CHECK_DEFAULT_SECTORS, MIFARE_CHECK_DICT,
                   MIFARE_CHECK_DICT_COUNT, known, &knownCount,
                   autoProbeSectorSink, &ctx, &attempts, &naive,
                   &recovered) == SWEEP_CARD_REMOVED) {
    return false;
  }

  uint32_t trailerAuths = 0;
  bool cardRemoved = false;
  trailerReadPass(MIFARE_CHECK_DEFAULT_SECTORS, autoProbeSectorSink, &ctx,
                  &trailerAuths, &recovered, &cardRemoved);
  return !cardRemoved;
}

// A SHORT press: run the chain for the card in the field, or arm it for the
// next card.
static void onTriggerShort() {
  Serial.println(":mifare_trigger short");
  if (mifareChainActive) {
    // The chain is already using the card: a second one would fight it for
    // the same session.
    Serial.println(":mifare_trigger ignored busy");
    mifareLed.blinkTimes(3, 60, 60);
    return;
  }

  if (mifareSessionOpen) {
    // A card is in the field. The auto-probe already swept it, so the chain
    // reuses those keys: no second sweep, no extra authentications.
    if (!mifareSweepValid) {
      // No sweep results for THIS card (the host drove its own sweep): run
      // ours so the dump has keys to read with.
      Serial.println(":mifare_trigger sweep");
      if (!runFieldSweepNow()) {
        Serial.println(":mifare_trigger error card-removed");
        mifareLed.blinkTimes(3, 60, 60);
        return;
      }
    }
    Serial.println(":mifare_trigger run");
    mifareLed.blinkTimes(1, 100, 100);
    runStandaloneChain();
    return;
  }

  // No card in the field: arm the one-shot. The next detection runs the
  // chain (the auto-probe sweeps, then the dump reads what it cracked).
  mifareTrigger.armOneShot();
  Serial.println(":mifare_trigger armed");
  mifareLed.blinkTimes(1, 100, 100);
}

// A LONG press: toggle the persistent standalone flag (armed mode).
static void onTriggerLong() {
  Serial.println(":mifare_trigger long");
  const bool turnOn = !(mifareKeys.flags & MIFARE_KEYSTORE_FLAG_STANDALONE);
  uint8_t flags = mifareKeys.flags;
  if (turnOn) {
    flags |= MIFARE_KEYSTORE_FLAG_STANDALONE;
  } else {
    flags &= (uint8_t)~MIFARE_KEYSTORE_FLAG_STANDALONE;
  }
  if (flags == mifareKeys.flags) {
    // Nothing changed: do NOT rewrite the flash record (wear).
    Serial.println(":mifare_trigger standalone unchanged");
    mifareLed.blinkTimes(1, 100, 100);
    return;
  }
  MifareKeyStore backup = mifareKeys;
  mifareKeys.flags = flags;
  if (!mifareKeyStoreSave(config, mifareKeys)) {
    mifareKeys = backup; // keep RAM and flash in sync
    Serial.println(":mifare_trigger error flash-write-failed");
    mifareLed.blinkTimes(3, 60, 60);
    return;
  }
  Serial.print(":mifare_trigger standalone ");
  Serial.println(turnOn ? "on" : "off");
  // 2 blinks = armed, 3 = disarmed. Distinct from the short press' single
  // blink, so the two gestures are told apart at a glance.
  mifareLed.blinkTimes(turnOn ? 2 : 3, 100, 100);
}

// Poll the trigger. Called from EVERY loop() iteration (before the early
// returns), so the button answers in every state: scanning, session open,
// waiting for a removal, sweeping. It never blocks.
static void pollStandaloneTrigger() {
  const uint32_t now = millis();
  const bool pressed = (digitalRead(MIFARE_TRIGGER_PIN) == LOW); // active LOW
  const int event = mifareTrigger.poll(pressed, now);
  if (event == MIFARE_TRIGGER_SHORT) {
    onTriggerShort();
  } else if (event == MIFARE_TRIGGER_LONG) {
    onTriggerLong();
  }
  // The LED is advanced AFTER the gesture is handled, so a pattern requested
  // by the handler lights up on this very iteration.
  mifareLedApply(now);
}

// `mifare trigger` -> :mifare_trigger pin=5 long_ms=1200 armed=0 standalone=0
//                      presses=0 long_presses=0
//
// Read-only: it reports what the board's field trigger is doing, so the host
// can tell "the operator armed a one-shot" from "the standalone mode is on"
// without guessing. The flag itself is set with `mifare standalone on|off`
// (or with a long press on the board's button).
void handleMifareTrigger(char *args) {
  if (nextArg(&args) != nullptr) {
    replyErr("usage: mifare trigger");
    return;
  }
  Serial.print(":mifare_trigger pin=");
  Serial.print(MIFARE_TRIGGER_PIN);
  Serial.print(" long_ms=");
  Serial.print(MIFARE_TRIGGER_LONG_MS);
  Serial.print(" armed=");
  Serial.print(mifareTrigger.oneShotPending() ? 1 : 0);
  Serial.print(" standalone=");
  Serial.print((mifareKeys.flags & MIFARE_KEYSTORE_FLAG_STANDALONE) ? 1 : 0);
  Serial.print(" presses=");
  Serial.print(mifareTrigger.presses());
  Serial.print(" long_presses=");
  Serial.println(mifareTrigger.longPresses());
  replyOk();
}

// Emit the cached sweep's per-sector results (the keys the last sweep
// recovered) in the same `:mifare_check_sN` format a fresh sweep streams.
static void emitCachedSectors(uint8_t sectors) {
  for (uint8_t s = 0; s < sectors; s++) {
    bool haveA, haveB;
    const uint8_t *keyA, *keyB;
    sweepCacheGet(s, &haveA, &keyA, &haveB, &keyB);
    emitCheckSector(s, haveA, keyA, haveB, keyB);
  }
}

// `mifare check [--sectors <n>] [--keys <hex,...>] [--dump] [--fresh]
//   -> :mifare_check_sN <keyA|-> <keyB|-> (one per sector, streamed)
//      :mifare_check_stat attempts=<n> naive=<n> recovered=<r>/<total>
//         trailer=<n> [cached=<0|1>] [auth_ms=… reselect_ms=… …]
//      +OK   (or -ERR if the card leaves the field mid-sweep)
//
// --sectors: sectors to sweep (default 16 = 1K; max 32).
// --keys:    comma-separated 12-hex keys that REPLACE the embedded dictionary
//            for this run (mirrors the host `--keys`), e.g.
//            `mifare check --keys FFFFFFFFFFFF,A0A1A2A3A4A5`.
// --dump:    chain the dump right after the sweep, in the SAME command: the
//            sectors the sweep cracked are read and emitted before the reply
//            (the standalone workflow in one round-trip).
// --settle:  ms of rest between a re-select and the next authentication
//            (default MIFARE_CHECK_SETTLE_MS = 25). The host-driven sweep gets
//            this rest for free from its USB round-trip; the on-device sweep
//            has to ask for it explicitly. Tunable at runtime so it can be
//            measured on the hardware without reflashing.
// --fresh:   sweep the card again even if the last sweep's results are still
//            cached. By DEFAULT the command answers from the cache: the
//            on-detection auto-probe already swept this card with the very
//            same dictionary, and sweeping it again would cost exactly the
//            same authentications for exactly the same result (the device must
//            not do the same work twice).
void handleMifareCheck(char *args) {
  uint8_t sectors = MIFARE_CHECK_DEFAULT_SECTORS;
  const uint8_t (*dict)[6] = MIFARE_CHECK_DICT;
  uint8_t dictCount = MIFARE_CHECK_DICT_COUNT;
  bool wantDump = false;
  bool wantFresh = false;
  bool haveKeyOverride = false;
  // --keys override lives in a bounded static buffer so a long list never eats
  // the stack; single-threaded REPL, so no re-entrancy concern.
  static uint8_t overrideKeys[MIFARE_CHECK_MAX_KEYS][6];

  char *tok;
  while ((tok = nextArg(&args)) != nullptr) {
    if (strcmp(tok, "--sectors") == 0) {
      char *v = nextArg(&args);
      int n = (v != nullptr) ? atoi(v) : 0;
      if (n < 1 || n > MIFARE_CHECK_MAX_SECTORS) {
        replyErr("usage: mifare check [--sectors <1..32>] [--keys <hex,...>] "
                 "[--dump]");
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
      haveKeyOverride = true;
    } else if (strcmp(tok, "--dump") == 0) {
      wantDump = true;
    } else if (strcmp(tok, "--fresh") == 0) {
      wantFresh = true;
    } else if (strcmp(tok, "--settle") == 0) {
      char *v = nextArg(&args);
      int n = (v != nullptr) ? atoi(v) : -1;
      if (n < 0 || n > 1000) {
        replyErr("usage: mifare check --settle <0..1000> (ms)");
        return;
      }
      mifareCheckSettleMs = (uint16_t)n;
    } else {
      replyErr("usage: mifare check [--sectors <1..32>] [--keys <hex,...>] "
               "[--dump] [--fresh] [--settle <ms>]");
      return;
    }
  }

  // Confirmed-key reuse store, ordered by first confirmation (known-first),
  // seeded with the persisted key-store so the custom
  // keys are tried before the dictionary.
  uint8_t known[MIFARE_CHECK_KNOWN_MAX][6];
  uint8_t knownCount = seedKnownFromStore(known, MIFARE_CHECK_KNOWN_MAX);

  uint32_t attempts = 0; // real auths issued (pinned against the baseline)
  uint32_t naive = 0;    // auths a no-reuse, no-early-cut sweep would cost
  uint8_t recovered = 0;
  const uint16_t total = (uint16_t)sectors * 2;

  // Answer from the cache when the last sweep already covered this card with
  // the very same dictionary (the on-detection auto-probe does a full sweep
  // with the embedded dictionary + the key-store, which is exactly what this
  // command would do). Sweeping the same card again would cost exactly the
  // same authentications for exactly the same result — the device must not do
  // the same work twice. `--fresh` forces the re-sweep;
  // an explicit `--keys` always sweeps (a different dictionary).
  if (!wantFresh && !haveKeyOverride && mifareSweepValid &&
      mifareSweepSectors >= sectors) {
    emitCachedSectors(sectors);
    Serial.print(":mifare_check_stat attempts=");
    Serial.print(mifareSweepCacheAttempts);
    Serial.print(" naive=");
    Serial.print(mifareSweepCacheNaive);
    Serial.print(" recovered=");
    Serial.print(mifareSweepCacheRecovered);
    Serial.print('/');
    Serial.print(total);
    Serial.print(" trailer=");
    Serial.print(mifareSweepCacheTrailer);
    Serial.print(" cached=1");
    // 1 when the cached sweep was interrupted before it covered every
    // sector: the per-sector lines above are then a PARTIAL result.
    Serial.print(" aborted=");
    Serial.print(mifareSweepCacheAborted ? 1 : 0);
    Serial.print(" auth_ms=");
    Serial.print(mifareSweepCacheAuthMs);
    Serial.print(" reselect_ms=");
    Serial.print(mifareSweepCacheReselectMs);
    Serial.print(" reset_ms=");
    Serial.print(mifareSweepCacheResetMs);
    Serial.print(" detect_ms=");
    Serial.print(mifareSweepCacheDetectMs);
    Serial.print(" trailer_ms=");
    Serial.println(mifareSweepCacheTrailerMs);
    mifareSessionDeadline = millis() + MIFARE_SESSION_IDLE_MS;
    replyOk();

    if (wantDump) {
      uint8_t read = 0, failed = 0;
      // Host-driven: the result goes to the host over the serial port, so
      // there is nothing to keep in the flash (only the standalone run does).
      if (runSectorDump(sectors, &read, &failed, nullptr) ==
          SWEEP_CARD_REMOVED) {
        beginCardRemovalWait();
        replyErr("card removed mid-dump, tap a card again");
        return;
      }
      emitDumpStat(read, failed, sectors);
    }
    return;
  }

  if (runCardSweep(sectors, dict, dictCount, known, &knownCount,
                   checkSectorSink, nullptr, &attempts, &naive,
                   &recovered) == SWEEP_CARD_REMOVED) {
    // Card left the field mid-sweep: end the session and re-arm discovery
    // so the host's next command gets a clean "no card" instead of
    // a hung session. Sectors already resolved were streamed.
    beginCardRemovalWait();
    replyErr("card removed mid-sweep, tap a card again");
    return;
  }

  // Second pass: for every sector the dictionary opened with Key A but not
  // with Key B, read the trailer with that Key A and take Key B off it. Same
  // pass the host runs (check.py's _trailer_read_pass), so both sides recover
  // the same keys from the same card.
  uint32_t trailerAuths = 0; // counted apart: `attempts` stays comparable
  bool cardRemoved = false;
  trailerReadPass(sectors, checkSectorSink, nullptr, &trailerAuths, &recovered,
                  &cardRemoved);
  if (cardRemoved) {
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
  Serial.print(total);
  // How many trailer reads this sweep issued. The host uses it to know the
  // DEVICE already recovered the Key B it could read back - so it does not
  // repeat the pass over USB (an older firmware has no such field, and then
  // the host does it itself).
  Serial.print(" trailer=");
  Serial.print(trailerAuths);
  Serial.print(" cached=0");
  // A sweep that reaches this point covered every sector.
  Serial.print(" aborted=0");
  // Where the wall-clock went, measured on the board: the time inside the
  // Crypto-1 authentication, inside the re-select (full reader re-arm +
  // re-detection) and inside the trailer pass. The host-driven sweep issues
  // the same number of authentications and re-selects, so these numbers are
  // what tell the two paths apart.
  Serial.print(" auth_ms=");
  Serial.print(mifareSweepAuthMs);
  Serial.print(" reselect_ms=");
  Serial.print(mifareSweepReselectMs);
  Serial.print(" reset_ms=");
  Serial.print(mifareSweepResetMs);
  Serial.print(" detect_ms=");
  Serial.print(mifareSweepDetectMs);
  Serial.print(" trailer_ms=");
  Serial.println(mifareSweepTrailerMs);

  // Optional: chain the dump right here, in the same command - the sectors the
  // sweep cracked are read and emitted before the reply, so the whole workflow
  // is ONE round-trip.
  if (wantDump) {
    uint8_t read = 0, failed = 0;
    // Host-driven: the result goes to the host over the serial port, so
    // there is nothing to keep in the flash (only the standalone run does).
    if (runSectorDump(sectors, &read, &failed, nullptr) == SWEEP_CARD_REMOVED) {
      beginCardRemovalWait();
      replyErr("card removed mid-dump, tap a card again");
      return;
    }
    emitDumpStat(read, failed, sectors);
  }

  // A long sweep may have overrun the idle window while loop() was blocked;
  // give a follow-up REPL command the full window again.
  mifareSessionDeadline = millis() + MIFARE_SESSION_IDLE_MS;
  replyOk();

  // Persist any custom key this sweep just confirmed (opt-in; at most one
  // flash write per sweep). The keys that came from a dictionary are skipped -
  // they are already covered. AFTER the reply on purpose: the write can take
  // a few hundred ms and must not delay the host's answer, nor disturb the
  // card session the host is about to use.
  autostoreRecoveredKeys(dict, dictCount, known, knownCount);
}

// --- `mifare keys ...` persistent key-store ------------------------
//
// `mifare keys`                     -> list the built-in + stored keys
// `mifare keys list`                -> same
// `mifare keys add <key_hex12>`     -> persist a custom key (survives a reset)
// `mifare keys remove <key_hex12|index>` -> drop a stored key
// `mifare keys clear`               -> drop every stored key
// `mifare keys autostore on|off`    -> auto-persist the custom keys a sweep
//                                       confirms
//
// Wire format (docs/baseline_fase0_mifare/serial_log_format.md): the listing
// keeps ONE index sequence - :mifare_key0..2 are the compiled-in defaults,
// :mifare_key3.. are the stored ones - so the host's "while mifare_key{i} in
// data" loop lists every key with no change on the host side.
//
// Needs no card: the key-store is a device-side setting, like `mifare keys`
// itself.

// True when `tok` is a non-empty decimal number; writes it to *index.
static bool parseDecimalIndex(const char *tok, int *index) {
  if (tok == nullptr || tok[0] == '\0') {
    return false;
  }
  for (const char *p = tok; *p != '\0'; p++) {
    if (!isdigit((unsigned char)*p)) {
      return false;
    }
  }
  *index = atoi(tok);
  return true;
}

// `mifare keys ...` dispatch. See the section header for the sub-commands.
void handleMifareKeys(char *args) {
  char *sub = nextArg(&args);
  if (sub == nullptr || strcmp(sub, "list") == 0) {
    emitKnownKeys();
    return;
  }

  if (strcmp(sub, "add") == 0) {
    char *keyHex = nextArg(&args);
    uint8_t key[6];
    if (keyHex == nullptr || !parseHexBytes(keyHex, key, 6)) {
      replyErr("usage: mifare keys add <key_hex12>");
      return;
    }
    if (keyInSet(MIFARE_CHECK_DICT, MIFARE_CHECK_DICT_COUNT, key)) {
      replyErr("key is already in the built-in dictionary");
      return;
    }
    if (mifareKeyStoreIndexOf(mifareKeys, key) >= 0) {
      replyErr("key is already stored");
      return;
    }
    MifareKeyStore backup = mifareKeys;
    if (!mifareKeyStoreAdd(mifareKeys, key)) {
      replyErr("key store is full");
      return;
    }
    if (!mifareKeyStoreSave(config, mifareKeys)) {
      mifareKeys = backup; // keep RAM and flash in sync
      replyErr("could not persist the key store (flash write failed)");
      return;
    }
    replyOk(String("added ") + TagReader::hexCompact(key, 6));
    // The dictionary just changed: the cached sweep used the old one.
    sweepCacheInvalidate();
    return;
  }

  if (strcmp(sub, "remove") == 0) {
    char *target = nextArg(&args);
    if (target == nullptr) {
      replyErr("usage: mifare keys remove <key_hex12|index>");
      return;
    }
    int index;
    if (strlen(target) == 12) {
      uint8_t key[6];
      if (!parseHexBytes(target, key, 6)) {
        replyErr("usage: mifare keys remove <key_hex12|index>");
        return;
      }
      index = mifareKeyStoreIndexOf(mifareKeys, key);
      if (index < 0) {
        replyErr("key is not in the key store");
        return;
      }
    } else if (parseDecimalIndex(target, &index)) {
      // Index into the listing printed by `mifare keys`: 0..2 are the
      // compiled-in defaults (not removable), 3+ are the stored keys.
      if (index < 3) {
        replyErr("built-in default keys cannot be removed");
        return;
      }
      index -= 3;
      if (index >= mifareKeys.count) {
        replyErr("index out of range");
        return;
      }
    } else {
      replyErr("usage: mifare keys remove <key_hex12|index>");
      return;
    }
    uint8_t removed[6];
    memcpy(removed, mifareKeys.keys[index], 6);
    MifareKeyStore backup = mifareKeys;
    mifareKeyStoreRemoveAt(mifareKeys, (uint8_t)index);
    if (!mifareKeyStoreSave(config, mifareKeys)) {
      mifareKeys = backup; // keep RAM and flash in sync
      replyErr("could not persist the key store (flash write failed)");
      return;
    }
    replyOk(String("removed ") + TagReader::hexCompact(removed, 6));
    // The dictionary just changed: the cached sweep used the old one.
    sweepCacheInvalidate();
    return;
  }

  if (strcmp(sub, "clear") == 0) {
    if (mifareKeys.count == 0) {
      replyOk("key store is already empty");
      return;
    }
    MifareKeyStore backup = mifareKeys;
    mifareKeyStoreClearKeys(mifareKeys);
    if (!mifareKeyStoreSave(config, mifareKeys)) {
      mifareKeys = backup; // keep RAM and flash in sync
      replyErr("could not persist the key store (flash write failed)");
      return;
    }
    replyOk("key store cleared");
    // The dictionary just changed: the cached sweep used the old one.
    sweepCacheInvalidate();
    return;
  }

  if (strcmp(sub, "autostore") == 0) {
    char *mode = nextArg(&args);
    if (mode == nullptr) {
      replyOk(
          String("autostore ") +
          ((mifareKeys.flags & MIFARE_KEYSTORE_FLAG_AUTOSTORE) ? "on" : "off"));
      return;
    }
    uint8_t flags = mifareKeys.flags;
    if (strcmp(mode, "on") == 0) {
      flags |= MIFARE_KEYSTORE_FLAG_AUTOSTORE;
    } else if (strcmp(mode, "off") == 0) {
      flags &= (uint8_t)~MIFARE_KEYSTORE_FLAG_AUTOSTORE;
    } else {
      replyErr("usage: mifare keys autostore [on|off]");
      return;
    }
    if (flags == mifareKeys.flags) {
      // Nothing changed: do NOT rewrite the flash record (wear).
      replyOk(String("autostore ") +
              ((flags & MIFARE_KEYSTORE_FLAG_AUTOSTORE) ? "on" : "off"));
      return;
    }
    MifareKeyStore backup = mifareKeys;
    mifareKeys.flags = flags;
    if (!mifareKeyStoreSave(config, mifareKeys)) {
      mifareKeys = backup; // keep RAM and flash in sync
      replyErr("could not persist the key store (flash write failed)");
      return;
    }
    replyOk(String("autostore ") +
            ((flags & MIFARE_KEYSTORE_FLAG_AUTOSTORE) ? "on" : "off"));
    return;
  }

  replyErr("usage: mifare keys [list|add <key_hex12>|remove <key_hex12|index>"
           "|clear|autostore [on|off]]");
}

// `mifare timing [reset]` -> :mifare_timing attempts=… reselects=… auth_ms=…
// reselect_ms=… reset_ms=… detect_ms=… trailer_ms=… +OK
//
// The wall-clock split of everything the board did with the card since the
// last reset. The host-driven sweep and the on-device one
// are measured with the SAME counters, so their difference can be attributed
// instead of guessed: `auth_ms` is the time inside the Crypto-1
// authentication, `reselect_ms` the time inside the re-select that follows a
// wrong key, and that re-select is split into `reset_ms` (the reader re-arm)
// and `detect_ms` (waiting for the card to be found again).
//
// `mifare timing reset` zeroes the counters, so a measurement can start from
// a clean slate. Needs no card.
void handleMifareTiming(char *args) {
  char *sub = nextArg(&args);
  if (sub != nullptr && strcmp(sub, "reset") == 0) {
    mifareSweepAuthMs = 0;
    mifareSweepReselectMs = 0;
    mifareSweepResetMs = 0;
    mifareSweepDetectMs = 0;
    mifareSweepTrailerMs = 0;
    mifareSweepAttempts = 0;
    mifareSweepReselects = 0;
    mifareSweepReselectFails = 0;
    // The core's detection counters too: a measurement starts from a clean
    // slate, and the det_* counters are half of the measurement.
    nfc.waitTagCalls = 0;
    nfc.waitTagOk = 0;
    nfc.waitTagTimeout = 0;
    nfc.waitTagNotifications = 0;
    nfc.waitTagDiscovery = 0;
    nfc.waitTagSelects = 0;
    nfc.waitTagDeactivate = 0;
    nfc.waitTagErrors = 0;
    nfc.resetFailures = 0;
    replyOk("counters reset");
    return;
  }
  Serial.print(":mifare_timing attempts=");
  Serial.print(mifareSweepAttempts);
  Serial.print(" reselects=");
  Serial.print(mifareSweepReselects);
  Serial.print(" reselect_fails=");
  Serial.print(mifareSweepReselectFails);
  Serial.print(" auth_ms=");
  Serial.print(mifareSweepAuthMs);
  Serial.print(" reselect_ms=");
  Serial.print(mifareSweepReselectMs);
  Serial.print(" reset_ms=");
  Serial.print(mifareSweepResetMs);
  Serial.print(" detect_ms=");
  Serial.print(mifareSweepDetectMs);
  Serial.print(" trailer_ms=");
  Serial.print(mifareSweepTrailerMs);
  // The detection diagnostics of the core: how many waits, how many found the
  // card, how many expired and how many unrelated notifications were drained
  // on the way. They tell a "the card left" from a "the notification was
  // missed" apart, on the hardware.
  Serial.print(" det_calls=");
  Serial.print(nfc.waitTagCalls);
  Serial.print(" det_ok=");
  Serial.print(nfc.waitTagOk);
  Serial.print(" det_timeout=");
  Serial.print(nfc.waitTagTimeout);
  Serial.print(" det_ntf=");
  Serial.print(nfc.waitTagNotifications);
  // What the chip actually said when a detection failed: a discovery
  // notification the host had to answer (det_disc/det_sel), the card
  // leaving (det_deact), a CORE error (det_err) or the reader re-arm
  // failing on I²C (rst_fail). Those four separate "the card left" from
  // "the re-select did not get the card back".
  Serial.print(" det_disc=");
  Serial.print(nfc.waitTagDiscovery);
  Serial.print(" det_sel=");
  Serial.print(nfc.waitTagSelects);
  Serial.print(" det_deact=");
  Serial.print(nfc.waitTagDeactivate);
  Serial.print(" det_err=");
  Serial.print(nfc.waitTagErrors);
  Serial.print(" rst_fail=");
  Serial.println(nfc.resetFailures);
  replyOk();
}

// `mifare <auth|read|write|sector|keys|check|dump|standalone|results|trigger|
// timing> ...` dispatch. `keys`, `standalone`, `results`, `trigger` and
// `timing` need no card; the rest require an open session (Decision 5) -
// see the file header.
void handleMifareCommand(char *args) {
  char *sub = nextArg(&args);
  if (sub == nullptr) {
    replyErr("usage: mifare <auth|read|write|sector|keys|check|dump|standalone"
             "|results|trigger|timing> ...");
    return;
  }

  if (strcmp(sub, "keys") == 0) {
    handleMifareKeys(args);
    return;
  }

  if (strcmp(sub, "standalone") == 0) {
    handleMifareStandalone(args);
    return;
  }

  if (strcmp(sub, "results") == 0) {
    handleMifareResults(args);
    return;
  }

  if (strcmp(sub, "trigger") == 0) {
    handleMifareTrigger(args);
    return;
  }

  if (strcmp(sub, "timing") == 0) {
    handleMifareTiming(args);
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
  } else if (strcmp(sub, "dump") == 0) {
    handleMifareDump(args);
  } else {
    replyErr("unknown mifare subcommand");
  }
}

// BomberCatControl::Callbacks::command hook: claims the "mifare" verb only.
bool bomberCatCommand(const char *verb, char *args) {
  if (strcmp(verb, "mifare") != 0) {
    return false;
  }
  if (mifareChainActive) {
    // The standalone chain is using the card right now. Refuse instead of
    // letting the command touch the very session the chain is in.
    replyErr("busy - the card workflow is running");
    return true;
  }
  handleMifareCommand(args);
  return true;
}
