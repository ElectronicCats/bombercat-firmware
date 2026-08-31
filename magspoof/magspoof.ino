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
