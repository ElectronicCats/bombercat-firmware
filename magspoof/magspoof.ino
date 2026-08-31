/************************************************************
  MagSpoof version for Bomber Cat
  by Salvador Mendoza (salmg.net)
  Electronic Cats (https://electroniccats.com/)

  This example demonstrates how to use Bomber Cat by Electronic Cats
  https://github.com/ElectronicCats/BomberCat

  Development environment specifics:
  IDE: Arduino 1.8.9
  Hardware Platform:
  Bomber Cat
  - RP2040

  Electronic Cats invests time and resources providing this open source code,
  please support Electronic Cats and open-source hardware by purchasing
  products from Electronic Cats!

  This code is beerware; if you see me (or any other Electronic Cats
  member) at the local, and you've found our code helpful,
  please buy us a round!
  Distributed as-is; no warranty is given.
*/

#include <BomberCatControl.h>

#include "CardDatabase.h"
#include "NfcController.h"

// 1.2.3.0: two-track cards now play TRACK 2 by default (playActiveCard/button
// alt mode). One coil can't drive a reader's parallel heads at once, so a real
// combined dual-track read is impossible; every attempt to emit both left the
// reader latching track 1 (often twice) and dropping track 2. Track 2 carries
// the financial PAN/expiry most readers consume, so emitting it alone gives the
// clean isolated swipe that reads reliably. `magplay 1` / `magbtn 1` still
// force track 1. Bumped so `bombercat info` confirms which image is actually
// flashed.
//
// 1.2.2.0: attempted to emit BOTH tracks per swipe — reverted in 1.2.3.0
// because the reader could not capture two tracks from a single coil (it
// re-read track 1 and missed track 2).
//
// 1.2.1.0: MSR read fixes — forward-only single pass (no reverse/there-and-back
// double read), 60-bit leading clock preamble so the reader locks before the
// start sentinel, and button-release debounce (one press = one swipe). Bumped
// from 1.2.0.0 so `bombercat info` confirms which image is actually flashed.
//
// 1.2.0.0: adds the persistent multi-card store and the `magcard` verb
// (IMPLEMENTATION_PLAN_MagSpoof_Flash.md, Phase 3). Older images answer
// `magcard` with "-ERR unknown command", which is how bombercat-tools tells a
// pre-flash firmware apart and prompts a reflash.
#define BOMBERCAT_FW_VERSION "1.2.3.0"

#define L1 (LED_BUILTIN) // LED1
#define PIN_A (6)        // MagSpoof-1
#define PIN_B (7)        // MagSpoofZF
#define NPIN (5)         // Button
#define CLOCK_US                                                               \
  (500) // 500us clock, it simulates the speed of the magnetic card swiping
// Leading clock-zero bits emitted before the start sentinel. Real cards carry a
// long run of zeros here so the reader's clock-recovery PLL locks before the
// first data character; too few and the reader mis-frames the sentinel (it came
// out as '+' on some MSRs). 60 gives ample preamble at CLOCK_US bit timing.
#define LEADING_ZEROS (60)
#define TRACKS (2)
// Longest track magset accepts: fits tracks[128] (+ null).
#define TRACK_MAX_CHARS (126)
#define DEBUGCAT
// How long nfcread waits for a card to enter the field before giving up
// (IMPLEMENTATION_PLAN_NFC_VISA_MAGSPOOF.md Phase 4.4). Longer than
// NfcController::waitForTag()'s 500ms default: this is a manual CLI command,
// so the user needs time to physically place the card after issuing it.
// Defined here (rather than alongside Phase 4's other NFC code) because
// handleCommand() -- which uses it -- is defined earlier in the file, and
// #define is resolved in file order, unlike Arduino's auto-prototyped
// function declarations.
#define NFC_READ_WAIT_TAG_MS (8000)

char tracks[2][128]; // 2 tracks, 128 chars each (max)

const int sublen[] = {32, 48, 48};

const int bitlen[] = {7, 5, 5};

int dir;

// Which track the physical NPIN button reproduces: 0 alternates 1 <-> 2 (the
// historical behaviour), 1 or 2 pin it to that single track. Set over the REPL
// with `magbtn`/`magcard`; mirrors the active card's persisted button mode
// (CardDatabase), reloaded from flash on boot.
unsigned int buttonTrack = 0;

// Persistent multi-card store (IMPLEMENTATION_PLAN_MagSpoof_Flash.md, Phase 3).
// The global tracks[][]/buttonTrack above are the live playback copy of the
// *active* card; loadActiveIntoRam() refreshes them whenever the active card or
// its data changes, so magplay/magget/magbtn and the physical button keep
// working unchanged while now operating on the selected card.
CardDatabase cardDb;

// PN7150 NFC controller (IMPLEMENTATION_PLAN_NFC_VISA_MAGSPOOF.md Phase 1).
// Default-constructed: BomberCat's PN7150 wiring (IRQ=11, VEN=13, I2C
// addr=0x28) is baked into NfcController.h's defaults, same as NFCGate.ino.
NfcController nfc;

// SEL_RES override buffer (IMPLEMENTATION_PLAN_NFC_VISA_MAGSPOOF.md Phase 2),
// ported verbatim from hunterCatNFC_AllOne.ino:61-65. This is the raw
// CORE_SET_CONFIG_CMD payload nfc.raw().configureSettings() sends to the
// PN7150; passing uidlen==0 makes the library ignore this buffer entirely and
// fall back to its own built-in default (Electroniccats_PN7150::
// configureSettings()'s `if (uidlen == 0) uidlen = 8;` branch), so
// setSelResChip() always rebuilds a full override rather than only touching
// uidcf[8].
uint8_t uidcf[20] = {
    0x20, 0x02, 0x05, 0x01, // CORE_SET_CONFIG_CMD
    0x00, 0x02, 0x00, 0x01  // TOTAL_DURATION
};
uint8_t uidlen = 0;

// Placeholder NFCID1 used by setSelResChip(). hunterCatNFC fills this slot
// with a real card's scanned UID (detectcard(), line 418) when cloning a tag;
// VISA MSD emulation doesn't clone a UID, and Track 2 (not the NFC-A UID)
// carries the card identity through the APDU exchange, so any fixed 4-byte
// value works here. 4 bytes = single-size NFCID1 (avoid the 0x88
// cascade-tag prefix byte).
static const uint8_t SEL_RES_DUMMY_UID[4] = {0xDE, 0xAD, 0xBE, 0xEF};

// Default card seeded on first boot / factory reset (plan section 10).
static const char DEFAULT_CARD_NAME[] = "DEFAULT";
static const char DEFAULT_TRACK1[] =
    "%B123456781234567^LASTNAME/FIRST^YYMMSSSDDDDDDDDDDDDDDDDDDDDDDDDD?";
static const char DEFAULT_TRACK2[] = ";123456781234567=112220100000000000000?";

// Wire/report name of the current button mode, shared by `magbtn` and
// `magget` so both always spell it the same way.
static const char *buttonModeName() {
  if (buttonTrack == 1)
    return "1";
  if (buttonTrack == 2)
    return "2";
  return "alt";
}

// Copy the active card's tracks and button mode from the CardDatabase cache
// into the live playback state (tracks[][], buttonTrack). Call after anything
// that changes the active card or its data so playTrack()/magget always see
// the current card.
static void loadActiveIntoRam() {
  const CardEntry *c = cardDb.getActive();
  if (c != nullptr) {
    strncpy(tracks[0], c->track1, sizeof(tracks[0]) - 1);
    tracks[0][sizeof(tracks[0]) - 1] = '\0';
    strncpy(tracks[1], c->track2, sizeof(tracks[1]) - 1);
    tracks[1][sizeof(tracks[1]) - 1] = '\0';
  } else {
    tracks[0][0] = '\0';
    tracks[1][0] = '\0';
  }
  buttonTrack = cardDb.buttonTrack();
}

void blink(int pin, int msdelay, int times) {
  for (int i = 0; i < times; i++) {
    digitalWrite(pin, HIGH);
    delay(msdelay);
    digitalWrite(pin, LOW);
    delay(msdelay);
  }
}

// send a single bit out
void playBit(int sendBit) {
  dir ^= 1;
  digitalWrite(PIN_A, dir);
  digitalWrite(PIN_B, !dir);
  delayMicroseconds(CLOCK_US);

  if (sendBit) {
    dir ^= 1;
    digitalWrite(PIN_A, dir);
    digitalWrite(PIN_B, !dir);
  }
  delayMicroseconds(CLOCK_US);
}

// Emit one track forward: leading clock zeros, the track's F2F characters and
// the LRC byte. `idx` is the 0-based track index. Leaves the field running (no
// trailing zeros / no pins-low) so the caller decides when to drop the field
// via endSwipe().
static void emitTrackForward(int idx) {
  int tmp, crc, lrc = 0;

  // First put out a bunch of leading zeros so the reader locks its clock.
  for (int i = 0; i < LEADING_ZEROS; i++)
    playBit(0);

  for (int i = 0; tracks[idx][i] != '\0'; i++) {
    crc = 1;
    tmp = tracks[idx][i] - sublen[idx];

    for (int j = 0; j < bitlen[idx] - 1; j++) {
      crc ^= tmp & 1;
      lrc ^= (tmp & 1) << j;
      playBit(tmp & 1);
      tmp >>= 1;
    }
    playBit(crc);
  }

  // finish calculating and send last "byte" (LRC)
  tmp = lrc;
  crc = 1;
  for (int j = 0; j < bitlen[idx] - 1; j++) {
    crc ^= tmp & 1;
    playBit(tmp & 1);
    tmp >>= 1;
  }
  playBit(crc);
}

// Close the emulated swipe: trailing zeros, then drop the H-bridge.
static void endSwipe() {
  for (int i = 0; i < 5 * 5; i++)
    playBit(0);

  digitalWrite(PIN_A, LOW);
  digitalWrite(PIN_B, LOW);
}

// Emit a single track as one clean forward swipe: the track forward, then the
// field is dropped. Forward-only (no reverse/there-and-back pass): a magnetic
// stripe reader (MSR) decodes in both directions, so appending a reverse pass
// makes it read the data twice, once corrupted at the sentinel. `track` is 1|2.
void playTrack(int track) {
  dir = 0;
  track--; // index 0
  emitTrackForward(track);
  endSwipe();
}

// Whether the live copy of track `t` (1 or 2) currently holds data.
static bool trackPresent(int t) { return tracks[t - 1][0] != '\0'; }

// Play the active card, preferring track 2 whenever it is present. A single
// MagSpoof coil cannot drive a reader's parallel track heads at once, so a
// two-track card can't be reproduced as a real card's combined dual-track line:
// every attempt to emit both (chained into one field, or as two isolated
// swipes) left the reader latching track 1 — sometimes twice — and dropping
// track 2 entirely. On a financial card track 2 carries the PAN/expiry/service
// code that most readers actually consume, so emitting track 2 ALONE gives it
// the clean isolated swipe the reader reads reliably (the same path the
// single-track track-2 cards already use). A track-1-only card still plays its
// track 1. Explicit `magplay 1` / `magbtn 1` override this to force track 1.
// Returns the track number played, or 0 if the card is empty.
static int playActiveCard() {
  if (trackPresent(2)) {
    playTrack(2);
    return 2;
  }
  if (trackPresent(1)) {
    playTrack(1);
    return 1;
  }
  return 0;
}

void magspoof() {
  if (digitalRead(NPIN) == 0) {
    Serial.println("Activating MagSpoof...");
    int track;
    if (buttonTrack == 1 && trackPresent(1)) {
      // Pinned to track 1: force track 1 (playActiveCard would prefer track 2).
      playTrack(1);
      track = 1;
    } else if (buttonTrack == 2 && trackPresent(2)) {
      // Pinned to track 2: play track 2 forward.
      playTrack(2);
      track = 2;
    } else {
      // buttonTrack 0 (alt): play the active card, which prefers track 2.
      track = playActiveCard();
    }
    if (track != 0)
      emitMagEvent(millis(), track);
    blink(L1, 150, 3);
    // Wait for the button to be released before allowing another swipe. The old
    // fixed delay(400) let a held button auto-repeat, which a reader captured
    // as a duplicate swipe; requiring a release makes one press = one swipe.
    while (digitalRead(NPIN) == 0)
      ;
    delay(50); // debounce the release
  }
}

// Structured event consumed by bombercat-tools, same conventions as :tag/
// :reader: ":mag <ts_ms> <track>", one per reproduction regardless of origin
// (command or physical button). The timestamp is taken once playback returns,
// so it marks the end of the swipe, not its start (playTrack() blocks for
// ~0.6-1.5 s).
void emitMagEvent(uint32_t tsMs, int track) {
  Serial.print(":mag ");
  Serial.print(tsMs);
  Serial.print(' ');
  Serial.println(track);
}

// The core REPL only skips the spaces *before* the args, so a trailing space
// or tab would survive inside the payload and break magset's "ends with '?'"
// check or magplay's exact match.
static void rstripArgs(char *s) {
  size_t n = strlen(s);
  while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t'))
    s[--n] = '\0';
}

// Shared ISO-track validation for `magset` and `magcard set`: returns nullptr
// when `data` is a valid track for `track` (1 or 2), else a short error slug
// for a "-ERR <slug>" reply. Enforces the sentinels, length, and the F2F
// charset (playTrack() keeps only bitlen-1 bits after subtracting sublen, so a
// character outside the range would be silently mangled on the wire).
static const char *validateTrack(int track, const char *data) {
  size_t len = strlen(data);
  if (len > TRACK_MAX_CHARS)
    return "track too long";
  char expectedStart = (track == 1) ? '%' : ';';
  if (len < 3 || data[0] != expectedStart || data[len - 1] != '?')
    return "bad track";
  unsigned char lo = (track == 1) ? 0x20 : 0x30;
  unsigned char hi = (track == 1) ? 0x5F : 0x3F;
  for (size_t i = 0; i < len; i++) {
    unsigned char c = (unsigned char)data[i];
    if (c < lo || c > hi)
      return "bad char";
  }
  return nullptr;
}

// Grab the next space-delimited token from *pp: NUL-terminate it in place,
// advance *pp past it and any following spaces, and return it (an empty string
// once the args are exhausted). Used by the `magcard` subcommand parser; a
// track's own data, which may contain spaces, is taken verbatim as the tail
// after the fixed leading tokens rather than through this splitter.
static char *nextToken(char **pp) {
  char *s = *pp;
  while (*s == ' ')
    s++;
  char *start = s;
  while (*s != '\0' && *s != ' ')
    s++;
  if (*s == ' ') {
    *s++ = '\0';
    while (*s == ' ')
      s++;
  }
  *pp = s;
  return start;
}

// Persist the active card's tracks to flash after a `magset` mutated the live
// RAM copy, so the change survives a reboot. Failures are swallowed: RAM stays
// the source of truth for playback, matching the historical RAM-only behaviour
// if flash is unavailable.
static void persistActiveTracks() {
  if (!cardDb.ready())
    return;
  const CardEntry *c = cardDb.getActive();
  if (c == nullptr)
    return;
  // activeName() points into the cache entry that update() will overwrite; copy
  // the key out first so it stays valid through the call.
  char name[CARD_NAME_MAX + 1];
  strncpy(name, c->name, sizeof(name) - 1);
  name[sizeof(name) - 1] = '\0';
  cardDb.update(name, tracks[0], tracks[1]);
}

// Serial-control command hook for magplay/magset/magget
// (IMPLEMENTATION_PLAN_MagSpoof.md sec 4). Emits its own +OK/-ERR terminator
// and returns true when it handled the verb; returning false lets the core
// REPL answer "-ERR unknown command" instead.
static bool handleCommand(const char *verb, char *args) {
  rstripArgs(args);

  if (strcmp(verb, "magplay") == 0) {
    int track;
    if (*args == '\0') {
      // Bare `magplay` plays the active card, auto-selecting the track(s) it
      // actually carries — the host CLI's `play` uses this so a 1-track
      // membership card and a 2-track card both "just play".
      track = playActiveCard();
      if (track == 0) {
        Serial.println("-ERR empty card");
        return true;
      }
    } else if (strcmp(args, "1") == 0 || strcmp(args, "2") == 0) {
      // Explicit single-track play (raw-serial / power use). Refuse a track the
      // active card doesn't have rather than emit an empty swipe.
      track = args[0] - '0';
      if (!trackPresent(track)) {
        Serial.println("-ERR empty track");
        return true;
      }
      playTrack(track);
    } else {
      Serial.println("-ERR bad track");
      return true;
    }
    emitMagEvent(millis(), track);
    Serial.print("+OK played ");
    Serial.println(track);
    blink(L1, 150, 3); // after the terminator: 900 ms the host need not wait
    return true;
  }

  if (strcmp(verb, "magset") == 0) {
    if ((args[0] != '1' && args[0] != '2') || args[1] != ' ') {
      Serial.println("-ERR bad track");
      return true;
    }
    int track = args[0] - '0';
    char *data = args + 2;
    const char *verr = validateTrack(track, data);
    if (verr != nullptr) {
      Serial.print("-ERR ");
      Serial.println(verr);
      return true;
    }
    size_t len = strlen(data);
    strcpy(tracks[track - 1], data);
    // magset now edits the active card; write the change through to flash.
    persistActiveTracks();
    Serial.print("+OK track ");
    Serial.print(track);
    Serial.print(" set (");
    Serial.print(len);
    Serial.println(" chars)");
    return true;
  }

  if (strcmp(verb, "magget") == 0) {
    Serial.print(":t1 ");
    Serial.println(tracks[0]);
    Serial.print(":t2 ");
    Serial.println(tracks[1]);
    Serial.print(":btn ");
    Serial.println(buttonModeName());
    Serial.print(":name ");
    Serial.println(cardDb.ready() ? cardDb.activeName() : "");
    Serial.println("+OK");
    return true;
  }

  // magbtn [1|2|alt] — report, or pin, the track the physical button plays.
  // Both forms answer with the resulting mode, so the host has one code path.
  if (strcmp(verb, "magbtn") == 0) {
    if (*args != '\0') {
      if (strcmp(args, "1") == 0) {
        buttonTrack = 1;
      } else if (strcmp(args, "2") == 0) {
        buttonTrack = 2;
      } else if (strcmp(args, "alt") == 0) {
        buttonTrack = 0;
      } else {
        Serial.println("-ERR bad mode");
        return true;
      }
      // Persist the mode with the store so it survives a reboot (RAM-only
      // before Phase 3); no-op if the card store failed to initialise.
      if (cardDb.ready())
        cardDb.setButtonTrack((uint8_t)buttonTrack);
    }
    Serial.print(":btn ");
    Serial.println(buttonModeName());
    Serial.println("+OK");
    return true;
  }

  // magcard <sub> ... — persistent multi-card store management (plan section
  // 3). Subcommands: list | info | get [name] | add <name> | del <name> |
  // select <name> | set <name> <1|2> <data>. One track per `set` line keeps the
  // longest command within the REPL's LINE_MAX input buffer; the host CLI
  // composes an add-with-tracks out of `add` + two `set`s.
  if (strcmp(verb, "magcard") == 0) {
    if (!cardDb.ready()) {
      Serial.println("-ERR not ready");
      return true;
    }
    char *p = args;
    char *sub = nextToken(&p);

    if (strcmp(sub, "list") == 0) {
      Serial.print(":count ");
      Serial.println(cardDb.count());
      Serial.print(":active ");
      Serial.println(cardDb.activeName());
      // One ':cardN' line per card, tab-delimited: the name carries no spaces
      // or control chars and neither track charset includes a tab, so the host
      // can split on '\t' unambiguously even when a track contains spaces.
      for (uint8_t i = 0; i < cardDb.count(); i++) {
        const CardEntry *c = cardDb.get(i);
        Serial.print(":card");
        Serial.print(i);
        Serial.print(' ');
        Serial.print(c->name);
        Serial.print('\t');
        Serial.print(c->track1);
        Serial.print('\t');
        Serial.println(c->track2);
      }
      Serial.print("+OK ");
      Serial.print(cardDb.count());
      Serial.println(" cards");
      return true;
    }

    if (strcmp(sub, "info") == 0) {
      Serial.print(":count ");
      Serial.println(cardDb.count());
      Serial.print(":capacity ");
      Serial.println(CardDatabase::capacity());
      Serial.print(":active ");
      Serial.println(cardDb.activeName());
      Serial.print(":btn ");
      Serial.println(buttonModeName());
      Serial.println("+OK");
      return true;
    }

    if (strcmp(sub, "get") == 0) {
      char *name = nextToken(&p);
      const CardEntry *c;
      if (*name == '\0') {
        c = cardDb.getActive();
      } else {
        int idx = cardDb.find(name);
        c = (idx >= 0) ? cardDb.get((uint8_t)idx) : nullptr;
      }
      if (c == nullptr) {
        Serial.println("-ERR not found");
        return true;
      }
      Serial.print(":name ");
      Serial.println(c->name);
      Serial.print(":t1 ");
      Serial.println(c->track1);
      Serial.print(":t2 ");
      Serial.println(c->track2);
      Serial.print(":active ");
      Serial.println(strcmp(c->name, cardDb.activeName()) == 0 ? "1" : "0");
      Serial.println("+OK");
      return true;
    }

    if (strcmp(sub, "add") == 0) {
      char *name = nextToken(&p);
      DbStatus st = cardDb.add(name, "", "");
      if (st != DbStatus::Ok) {
        Serial.print("-ERR ");
        Serial.println(dbStatusName(st));
        return true;
      }
      Serial.print("+OK added ");
      Serial.println(name);
      return true;
    }

    if (strcmp(sub, "del") == 0) {
      char *name = nextToken(&p);
      // Whether this deletes the active card decides if the live RAM copy must
      // be reloaded (the active index shifts inside remove()).
      bool wasActive =
          (*name != '\0' && strcmp(name, cardDb.activeName()) == 0);
      DbStatus st = cardDb.remove(name);
      if (st != DbStatus::Ok) {
        Serial.print("-ERR ");
        Serial.println(dbStatusName(st));
        return true;
      }
      if (wasActive)
        loadActiveIntoRam();
      Serial.print("+OK deleted ");
      Serial.println(name);
      return true;
    }

    if (strcmp(sub, "select") == 0) {
      char *name = nextToken(&p);
      DbStatus st = cardDb.select(name);
      if (st != DbStatus::Ok) {
        Serial.print("-ERR ");
        Serial.println(dbStatusName(st));
        return true;
      }
      loadActiveIntoRam();
      Serial.print(":active ");
      Serial.println(cardDb.activeName());
      Serial.println("+OK");
      return true;
    }

    if (strcmp(sub, "set") == 0) {
      char *name = nextToken(&p);
      char *tk = nextToken(&p);
      char *data = p; // rest of line verbatim (a track may contain spaces)
      rstripArgs(data);
      if (*name == '\0' || (tk[0] != '1' && tk[0] != '2') || tk[1] != '\0') {
        Serial.println("-ERR bad track");
        return true;
      }
      int track = tk[0] - '0';
      const char *verr = validateTrack(track, data);
      if (verr != nullptr) {
        Serial.print("-ERR ");
        Serial.println(verr);
        return true;
      }
      const char *t1 = (track == 1) ? data : nullptr;
      const char *t2 = (track == 2) ? data : nullptr;
      DbStatus st = cardDb.update(name, t1, t2);
      if (st != DbStatus::Ok) {
        Serial.print("-ERR ");
        Serial.println(dbStatusName(st));
        return true;
      }
      // If we just edited the active card, refresh the live playback copy.
      if (strcmp(name, cardDb.activeName()) == 0)
        loadActiveIntoRam();
      Serial.print("+OK track ");
      Serial.print(track);
      Serial.print(" set on ");
      Serial.println(name);
      return true;
    }

    Serial.println("-ERR bad subcommand");
    return true;
  }

  // nfcselres <chip|nochip> -- manual SEL_RES override
  // (IMPLEMENTATION_PLAN_NFC_VISA_MAGSPOOF.md Phase 2.4). Pushes the
  // chip/no-chip bit immediately; a later mode switch (resetNfc(), e.g. via
  // nfcread/nfcvisa in later phases) resets it back to that mode's default.
  if (strcmp(verb, "nfcselres") == 0) {
    bool hasChip;
    if (strcmp(args, "chip") == 0) {
      hasChip = true;
    } else if (strcmp(args, "nochip") == 0) {
      hasChip = false;
    } else {
      Serial.println("-ERR bad mode");
      return true;
    }
    if (!setSelResChip(hasChip)) {
      Serial.println("-ERR nfc config failed");
      return true;
    }
    Serial.print("+OK selres ");
    Serial.println(hasChip ? "chip" : "nochip");
    return true;
  }

  // nfcvisa -- start a VISA MSD contactless emulation session against a
  // terminal (IMPLEMENTATION_PLAN_NFC_VISA_MAGSPOOF.md Phase 3.4). Blocks the
  // REPL for the duration of the exchange (bounded by VISA_MSD_TIMEOUT_MS).
  if (strcmp(verb, "nfcvisa") == 0) {
    if (!emulateVisaMSD()) {
      Serial.println("-ERR nfcvisa failed");
      return true;
    }
    Serial.println("+OK nfcvisa done");
    return true;
  }

  // nfcread -- read a physical EMV/Visa card's Track 2 over NFC and store it
  // as the active card's Track 2 (IMPLEMENTATION_PLAN_NFC_VISA_MAGSPOOF.md
  // Phase 4.4). Switches the PN7150 into reader mode, waits up to
  // NFC_READ_WAIT_TAG_MS for a card to enter the field, then runs the
  // PPSE/AID/GPO/READ RECORD sequence once. NFC-sourced cards aren't
  // flagged as such in CardDatabase yet (that's Phase 5); this stores the
  // extracted Track 2 the same way `magcard set`/`magset` would.
  if (strcmp(verb, "nfcread") == 0) {
    if (!cardDb.ready()) {
      Serial.println("-ERR not ready");
      return true;
    }
    if (!resetNfc(false)) {
      Serial.println("-ERR nfc reader mode failed");
      return true;
    }
    if (!nfc.waitForTag(NFC_READ_WAIT_TAG_MS)) {
      Serial.println("-ERR no card detected");
      return true;
    }
    uint8_t packed[19];
    uint8_t packedLen = readVisaTrack2(packed, sizeof(packed));
    if (packedLen == 0) {
      Serial.println("-ERR track 2 not found");
      return true;
    }
    char track2[TRACK_MAX_CHARS + 2];
    if (!unpackTrack2Equivalent(packed, packedLen, track2, sizeof(track2))) {
      Serial.println("-ERR track 2 decode failed");
      return true;
    }
    const char *verr = validateTrack(2, track2);
    if (verr != nullptr) {
      Serial.print("-ERR ");
      Serial.println(verr);
      return true;
    }
    char name[CARD_NAME_MAX + 1];
    strncpy(name, cardDb.activeName(), sizeof(name) - 1);
    name[sizeof(name) - 1] = '\0';
    DbStatus st = cardDb.update(name, nullptr, track2);
    if (st != DbStatus::Ok) {
      Serial.print("-ERR ");
      Serial.println(dbStatusName(st));
      return true;
    }
    loadActiveIntoRam();
    Serial.print(":t2 ");
    Serial.println(track2);
    Serial.println("+OK nfcread stored");
    return true;
  }

  return false;
}

// Toggle the PN7150's emulated SEL_RES "supports ISO-DEP/chip" bit (byte 8 of
// uidcf, bit 0x20) and push it to the chip. hasChip=true -> 0x33 (EMV/
// contactless); false -> 0x13 (MSD fallback). Ported from hunterCatNFC_AllOne
// .ino:411-418 (detectcard()), minus the real-UID capture -- see
// SEL_RES_DUMMY_UID above.
//
// Must be called AFTER beginReaderMode()/beginEmulationMode() (or a plain
// reset()), never before: both call the library's no-arg configureSettings()
// internally, which would overwrite this override with the chip's built-in
// default. A mid-emulation cardReArm() (Phase 3+) re-runs that same bring-up,
// so any caller relying on cardReArm() must re-apply setSelResChip()
// afterward.
bool setSelResChip(bool hasChip) {
  uidcf[2] = 7 + sizeof(SEL_RES_DUMMY_UID);
  uidcf[3] = 0x02;
  uidcf[8] = hasChip ? 0x33 : 0x13;
  uidcf[9] = sizeof(SEL_RES_DUMMY_UID);
  memcpy(&uidcf[10], SEL_RES_DUMMY_UID, sizeof(SEL_RES_DUMMY_UID));
  uidlen = sizeof(SEL_RES_DUMMY_UID);
  return nfc.raw().configureSettings(uidcf, uidlen);
}

// Switch the PN7150 into reader (false) or card-emulation (true) mode, re-run
// its NCI bring-up, and auto-apply that mode's SEL_RES default: chip mode for
// reader (advertise ISO-DEP support so a full EMV card can be read), no-chip
// for MSD emulation (the POS falls back to magstripe instead of attempting
// EMV crypto the emulation can't satisfy). Wraps NfcController's two mode
// entry points behind one call so later phases (VISA MSD emulation, Track 2
// extraction) can flip modes without duplicating the choice at each call
// site; `nfcselres` (Phase 2.4) can still override the result afterward.
bool resetNfc(bool emulation) {
  bool ok = emulation ? nfc.beginEmulationMode() : nfc.beginReaderMode();
  if (!ok)
    return false;
  return setSelResChip(!emulation);
}

// --- VISA MSD emulation (IMPLEMENTATION_PLAN_NFC_VISA_MAGSPOOF.md Phase 3)
// ---------------------------------------------------------------------

// Canned APDU responses for a VISA MSD contactless flow, ported verbatim from
// hunterCatNFC_AllOne.ino:73-79 (Phase 3.1): PPSE SELECT, VISA AID SELECT and
// GPO (processing) answers, plus the terminator response the original's
// 6-step loop replays for its trailing two steps. `last`/`statusapdu` from
// the source aren't kept as separate globals -- their bytes (the 0x70/0x57
// record header and the 0x90 0x00 status word) are inlined into
// buildVisaTrack2Record() below, which computes the record length instead of
// assuming HunterCat's fixed 19-byte token.
uint8_t ppsea[] = {0x6F, 0x23, 0x84, 0x0E, 0x32, 0x50, 0x41, 0x59, 0x2E, 0x53,
                   0x59, 0x53, 0x2E, 0x44, 0x44, 0x46, 0x30, 0x31, 0xA5, 0x11,
                   0xBF, 0x0C, 0x0E, 0x61, 0x0C, 0x4F, 0x07, 0xA0, 0x00, 0x00,
                   0x00, 0x03, 0x10, 0x10, 0x87, 0x01, 0x01, 0x90, 0x00};
uint8_t visaa[] = {0x6F, 0x1E, 0x84, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x03,
                   0x10, 0x10, 0xA5, 0x13, 0x50, 0x0B, 0x56, 0x49, 0x53,
                   0x41, 0x20, 0x43, 0x52, 0x45, 0x44, 0x49, 0x54, 0x9F,
                   0x38, 0x03, 0x9F, 0x66, 0x02, 0x90, 0x00};
uint8_t processinga[] = {0x80, 0x06, 0x00, 0x80, 0x08,
                         0x01, 0x01, 0x00, 0x90, 0x00};
uint8_t finished[] = {0x6f, 0x00};

// Longest READ RECORD response buildVisaTrack2Record() can produce: the 4
// -byte "70 LL 57 LL" header + tag 0x57's EMV-standard 19-byte cap (a packed
// PAN + separator + expiry + service code + discretionary data never exceeds
// 19 bytes per EMV Book 3) + the 2-byte trailing status word.
#define VISA_TRACK2_RECORD_MAX (4 + 19 + 2)

// Hardcoded fallback Track 2 Equivalent Data (EMV tag 0x57), used when the
// active card has no Track 2. Ported verbatim from hunterCatNFC_AllOne
// .ino:69 (`token`) -- an example 4412345605781234 PAN, already packed as
// BCD nibbles.
static const uint8_t DEFAULT_VISA_TOKEN[19] = {
    0x44, 0x12, 0x34, 0x56, 0x05, 0x78, 0x12, 0x34, 0xd1, 0x71,
    0x12, 0x01, 0x00, 0x00, 0x03, 0x00, 0x00, 0x99, 0x1f};

// Pack an ISO/ABA Track 2 string (";PAN=expiry+service+discretionary?", the
// format CardDatabase stores) into EMV tag 0x57's BCD-nibble encoding: each
// digit becomes one nibble, '=' becomes 0xD, high nibble first, and an odd
// nibble count is padded with a trailing 0xF nibble -- the standard EMV
// Track 2 Equivalent Data packing. Returns the packed byte count, or 0 if
// `track2` doesn't start with ';', is empty, or is too long to fit tag
// 0x57's 19-byte cap.
static uint8_t packTrack2Equivalent(const char *track2, uint8_t *out,
                                    uint8_t outCap) {
  if (track2[0] != ';')
    return 0;
  uint8_t nibbles[2 * 19];
  uint8_t n = 0;
  for (const char *p = track2 + 1; *p != '\0' && *p != '?'; p++) {
    uint8_t v;
    if (*p >= '0' && *p <= '9')
      v = *p - '0';
    else if (*p == '=')
      v = 0xD;
    else
      continue; // skip anything unexpected rather than corrupt the encoding
    if (n >= sizeof(nibbles))
      return 0; // too long for tag 0x57's 19-byte cap
    nibbles[n++] = v;
  }
  if (n == 0)
    return 0;
  if (n & 1)
    nibbles[n++] = 0xF; // pad the last nibble to a whole byte
  uint8_t len = n / 2;
  if (len > outCap)
    return 0;
  for (uint8_t i = 0; i < len; i++)
    out[i] = (nibbles[2 * i] << 4) | nibbles[2 * i + 1];
  return len;
}

// Build the READ RECORD response for the VISA MSD flow's step 4: the 0x70
// record template wrapping tag 0x57 (Track 2 Equivalent Data), followed by
// the 0x90 0x00 status word -- what hunterCatNFC_AllOne.ino:367-369 built as
// the fixed-size `card` array, here sized to the actual Track 2 length.
// Track 2 source (clarifying question 3): the active CardDatabase card's
// Track 2 (tracks[1], kept in sync by loadActiveIntoRam()) if present,
// otherwise DEFAULT_VISA_TOKEN. Returns the total record length, or 0 if it
// wouldn't fit `out`/`outCap`.
static uint8_t buildVisaTrack2Record(uint8_t *out, uint8_t outCap) {
  uint8_t payload[19];
  uint8_t payloadLen = 0;
  if (trackPresent(2))
    payloadLen = packTrack2Equivalent(tracks[1], payload, sizeof(payload));
  if (payloadLen == 0) {
    memcpy(payload, DEFAULT_VISA_TOKEN, sizeof(DEFAULT_VISA_TOKEN));
    payloadLen = sizeof(DEFAULT_VISA_TOKEN);
  }
  uint8_t total = 4 + payloadLen + 2;
  if (total > outCap)
    return 0;
  out[0] = 0x70;
  out[1] = 2 + payloadLen;
  out[2] = 0x57;
  out[3] = payloadLen;
  memcpy(&out[4], payload, payloadLen);
  out[4 + payloadLen] = 0x90;
  out[4 + payloadLen + 1] = 0x00;
  return total;
}

// Overall wall-clock budget for one nfcvisa run: long enough to cover a slow
// tap-and-hold across all 6 steps, short enough that a command that never
// gets a terminal doesn't hang the REPL indefinitely.
#define VISA_MSD_TIMEOUT_MS (15000)

// Run one VISA MSD emulation session against a terminal (Phase 3.2), porting
// hunterCatNFC_AllOne.ino:364-390 (visamsd()) onto NfcController's
// cardReceive()/cardSend(). The original blindly replies to each of the 6
// incoming commands in a fixed order (PPSE, VISA AID, GPO, READ RECORD, then
// two terminator replies) without inspecting their content; that assumption
// is kept here. Puts the PN7150 into emulation mode first (auto-applies
// SEL_RES nochip via resetNfc(), so the terminal falls back to magstripe
// instead of attempting EMV crypto this emulation can't satisfy).
bool emulateVisaMSD() {
  if (!resetNfc(true)) {
    Serial.println("NFC: emulation mode failed");
    return false;
  }

  uint8_t card[VISA_TRACK2_RECORD_MAX];
  uint8_t cardLen = buildVisaTrack2Record(card, sizeof(card));
  if (cardLen == 0) {
    Serial.println("nfcvisa: track 2 too long to encode");
    return false;
  }

  uint8_t *apdus2[] = {ppsea, visaa, processinga, card, finished, finished};
  uint8_t apdusLen2[] = {sizeof(ppsea), sizeof(visaa),    sizeof(processinga),
                         cardLen,       sizeof(finished), sizeof(finished)};

  uint8_t cmdBuf[255];
  uint8_t cmdLen;
  const unsigned long start = millis();
  for (uint8_t i = 0; i < 6;) {
    if (millis() - start >= VISA_MSD_TIMEOUT_MS) {
      Serial.println("nfcvisa: timeout waiting for terminal");
      return false;
    }
    if (!nfc.cardReceive(cmdBuf, &cmdLen)) {
      // No command arrived within cardReceive's own window: either no
      // terminal has tapped yet, or one left mid-transaction. Re-arm
      // listening and keep waiting for the overall deadline. cardReArm()
      // re-runs the plain emulation bring-up (NfcController.cpp), which
      // reverts the SEL_RES override, so it must be re-applied here.
      if (nfc.cardReArm())
        setSelResChip(false);
      continue;
    }
    nfc.cardSend(apdus2[i], apdusLen2[i]);
    i++;
  }
  Serial.println("nfcvisa: MSD emulation complete");
  return true;
}

// --- Track 2 extraction from a real card
// (IMPLEMENTATION_PLAN_NFC_VISA_MAGSPOOF.md Phase 4) ---------------------

// Reader-mode APDU commands for the Visa flow, ported verbatim from
// hunterCatNFC_AllOne.ino:239-242 (seekTrack2()): PPSE SELECT, VISA AID
// SELECT, GPO with no PDOL (the fallback when the card's AID SELECT response
// carries no tag 0x9F38), and READ RECORD for SFI=1 record 1 (the slot Visa
// MSD/EMV cards carry Track 2 Equivalent Data in).
static uint8_t READ_PPSE[] = {0x00, 0xA4, 0x04, 0x00, 0x0E, 0x32, 0x50,
                              0x41, 0x59, 0x2E, 0x53, 0x59, 0x53, 0x2E,
                              0x44, 0x44, 0x46, 0x30, 0x31, 0x00};
static uint8_t READ_VISA_AID[] = {0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00,
                                  0x00, 0x00, 0x03, 0x10, 0x10, 0x00};
static uint8_t READ_GPO_DEFAULT[] = {0x80, 0xA8, 0x00, 0x00,
                                     0x02, 0x83, 0x00, 0x00};
static uint8_t READ_RECORD_SFI1[] = {0x00, 0xB2, 0x01, 0x0C, 0x00};

// GPO command built from the card's declared PDOL by treatPDOL(); kept as a
// global buffer (like hunterCatNFC_AllOne.ino's `ppdol`) since its length is
// dynamic, set by treatPDOL()'s return value rather than sizeof().
static uint8_t ppdol[255] = {0x80, 0xA8, 0x00, 0x00, 0x02, 0x83, 0x00};

// Build a GPO command satisfying the card's PDOL (tag 0x9F38's payload, laid
// out in `apdu` as apdu[0]=length, apdu[1..length]=the PDOL tag/length list)
// by substituting placeholder values for each recognised terminal data
// element. Ported verbatim from hunterCatNFC_AllOne.ino:146-215 (Task 4.2);
// as the source's own comment notes, this only follows the PDOL *format* --
// the substituted values aren't a real EMV challenge, so a terminal
// verifying them cryptographically would reject the card. That's fine here:
// Track 2 Equivalent Data (tag 0x57) doesn't depend on GPO's response being
// genuine, only on the card accepting a well-formed GPO.
static uint8_t treatPDOL(uint8_t *apdu) {
  uint8_t plen = 7;
  for (uint8_t i = 1; i <= apdu[0]; i++) {
    if (apdu[i] == 0x9F && apdu[i + 1] == 0x66) {
      ppdol[plen] = 0xF6;
      ppdol[plen + 1] = 0x20;
      ppdol[plen + 2] = 0xC0;
      ppdol[plen + 3] = 0x00;
      plen += 4;
      i += 2;
    } else if (apdu[i] == 0x9F && apdu[i + 1] == 0x1A) {
      ppdol[plen] = 0x9F;
      ppdol[plen + 1] = 0x1A;
      plen += 2;
      i += 2;
    } else if (apdu[i] == 0x5F && apdu[i + 1] == 0x2A) {
      ppdol[plen] = 0x5F;
      ppdol[plen + 1] = 0x2A;
      plen += 2;
      i += 2;
    } else if (apdu[i] == 0x9A) {
      ppdol[plen] = 0x9A;
      ppdol[plen + 1] = 0x9A;
      ppdol[plen + 2] = 0x9A;
      plen += 3;
      i += 1;
    } else if (apdu[i] == 0x95) {
      ppdol[plen] = 0x95;
      ppdol[plen + 1] = 0x95;
      ppdol[plen + 2] = 0x95;
      ppdol[plen + 3] = 0x95;
      ppdol[plen + 4] = 0x95;
      plen += 5;
      i += 1;
    } else if (apdu[i] == 0x9C) {
      ppdol[plen] = 0x9C;
      plen += 1;
      i += 1;
    } else if (apdu[i] == 0x9F && apdu[i + 1] == 0x37) {
      ppdol[plen] = 0x9F;
      ppdol[plen + 1] = 0x37;
      ppdol[plen + 2] = 0x9F;
      ppdol[plen + 3] = 0x37;
      plen += 4;
      i += 2;
    } else {
      uint8_t u = apdu[i + 2];
      while (u > 0) {
        ppdol[plen] = 0;
        plen += 1;
        u--;
      }
      i += 2;
    }
  }
  ppdol[4] = (plen + 2) - 7; // length of PDOL + 2
  ppdol[6] = plen - 7;       // real length
  plen++;                    // +1 for the trailing 0
  ppdol[plen] = 0x00;
  return plen;
}

// Read a physical EMV/Visa card's Track 2 Equivalent Data (tag 0x57) over
// NFC-A/ISO-DEP: PPSE SELECT -> VISA AID SELECT -> GPO (PDOL-aware) -> READ
// RECORD SFI=1. Ported from hunterCatNFC_AllOne.ino:234-293 (seekTrack2()),
// dropping its serial debug prints and its infinite 4-command retry loop (a
// single attempt here; the caller decides whether to retry). Assumes a tag
// is already in the field (call nfc.waitForTag() first) and the PN7150 is
// in reader mode. Returns the packed length (same BCD-nibble format
// buildVisaTrack2Record() emits, Phase 3) written to `out`, or 0 on any
// transceive failure, a malformed/truncated PDOL, or a missing tag 0x57.
static uint8_t readVisaTrack2(uint8_t *out, uint8_t outCap) {
  uint8_t resp[255], respLen;

  if (!nfc.readerTransceive(READ_PPSE, sizeof(READ_PPSE), resp, &respLen))
    return 0;

  if (!nfc.readerTransceive(READ_VISA_AID, sizeof(READ_VISA_AID), resp,
                            &respLen))
    return 0;

  uint8_t *gpoCmd = READ_GPO_DEFAULT;
  uint8_t gpoLen = sizeof(READ_GPO_DEFAULT);
  for (uint8_t u = 0; u + 2 < respLen; u++) {
    if (resp[u] == 0x9F && resp[u + 1] == 0x38) {
      uint8_t pdolLen = resp[u + 2];
      // Bail out (keep the no-PDOL default GPO) rather than trust a
      // malformed/truncated PDOL length: without this check a card claiming
      // a PDOL longer than what's actually in `resp` would make the copy
      // loop below read past the end of the 255-byte `resp` buffer.
      if (pdolLen >= 50 || u + 2 + pdolLen >= respLen)
        break;
      uint8_t pdol[50];
      for (uint8_t e = 0; e <= pdolLen; e++)
        pdol[e] = resp[u + e + 2];
      gpoLen = treatPDOL(pdol);
      gpoCmd = ppdol;
      break;
    }
  }

  if (!nfc.readerTransceive(gpoCmd, gpoLen, resp, &respLen))
    return 0;

  if (!nfc.readerTransceive(READ_RECORD_SFI1, sizeof(READ_RECORD_SFI1), resp,
                            &respLen))
    return 0;

  for (uint8_t u = 0; u + 1 < respLen; u++) {
    uint8_t tagLen = resp[u + 1];
    if (resp[u] == 0x57 && u + 2 + tagLen <= respLen) {
      if (tagLen > outCap)
        return 0;
      memcpy(out, &resp[u + 2], tagLen);
      return tagLen;
    }
  }
  return 0;
}

// Inverse of packTrack2Equivalent() (Phase 3): unpack EMV tag 0x57's BCD
// nibbles back into an ISO/ABA Track 2 string (";PAN=discretionary?", the
// format CardDatabase stores), so an NFC-extracted card can be replayed over
// the MagSpoof coil like any other stored card. 0xD unpacks to the '='
// PAN/discretionary-data separator; a trailing 0xF pad nibble (added by
// packTrack2Equivalent() for an odd digit count) ends the string early.
// Writes into `out` (capacity `outCap`) and returns false if the data
// contains an invalid nibble or doesn't fit.
static bool unpackTrack2Equivalent(const uint8_t *data, uint8_t len, char *out,
                                   size_t outCap) {
  if (outCap < 3) // ';' + at least one digit + '?' + NUL
    return false;
  size_t o = 0;
  out[o++] = ';';
  bool done = false;
  for (uint8_t i = 0; i < len && !done; i++) {
    uint8_t nibbles[2] = {(uint8_t)(data[i] >> 4), (uint8_t)(data[i] & 0x0F)};
    for (uint8_t half = 0; half < 2 && !done; half++) {
      uint8_t nib = nibbles[half];
      if (nib == 0xF) {
        done = true;
        break;
      }
      char c;
      if (nib == 0xD)
        c = '=';
      else if (nib <= 9)
        c = (char)('0' + nib);
      else
        return false;     // invalid nibble
      if (o + 3 > outCap) // this char + '?' + NUL must still fit
        return false;
      out[o++] = c;
    }
  }
  out[o++] = '?';
  out[o] = '\0';
  return true;
}

// BomberCat serial-control REPL (ping/info/identify) for bombercat-tools.
BomberCatControl control(Serial, BOMBERCAT_FW_VERSION, "magspoof");

void setup() {
  pinMode(PIN_A, OUTPUT);
  pinMode(PIN_B, OUTPUT);
  pinMode(L1, OUTPUT);
  pinMode(NPIN, INPUT_PULLUP);

  Serial.begin(115200);
  while (!Serial)
    ;

  // blink to show we started up
  blink(L1, 200, 2);

  // Bring up the persistent card store and load the active card into the live
  // playback state. On first boot this seeds the single DEFAULT card (plan
  // section 10 migration); if flash init fails, fall back to the RAM defaults
  // so playback still works.
  if (cardDb.begin(DEFAULT_CARD_NAME, DEFAULT_TRACK1, DEFAULT_TRACK2)) {
    loadActiveIntoRam();
    Serial.print("Active card: ");
    Serial.println(cardDb.activeName());
  } else {
    Serial.println("Card store init failed — using RAM defaults");
    strcpy(tracks[0], DEFAULT_TRACK1);
    strcpy(tracks[1], DEFAULT_TRACK2);
  }
  Serial.print("Track 1: ");
  Serial.println(tracks[0]);
  Serial.print("Track 2: ");
  Serial.println(tracks[1]);

  // Bring up the PN7150 in reader mode by default. Failure is reported but
  // non-fatal: MagSpoof playback works over the coil regardless of NFC state,
  // and later phases add CLI commands (nfcselres/nfcvisa/nfcread) that can
  // retry via resetNfc().
  if (resetNfc(false)) {
    Serial.println("NFC ready (reader mode)");
  } else {
    Serial.println("NFC init failed");
  }

  Serial.println("Press the MagSpoof button");

  BomberCatControl::Callbacks cb;
  cb.command = handleCommand;
  control.setCallbacks(cb);
  control.begin(); // announce readiness to the host CLI
}
void loop() {
  control.poll(); // service host CLI commands (ping/info/identify)
  magspoof();
}
