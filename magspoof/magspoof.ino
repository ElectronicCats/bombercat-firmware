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

// 1.2.0.0: adds the persistent multi-card store and the `magcard` verb
// (IMPLEMENTATION_PLAN_MagSpoof_Flash.md, Phase 3). Older images answer
// `magcard` with "-ERR unknown command", which is how bombercat-tools tells a
// pre-flash firmware apart and prompts a reflash.
#define BOMBERCAT_FW_VERSION "1.2.0.0"

#define L1 (LED_BUILTIN) // LED1
#define PIN_A (6)        // MagSpoof-1
#define PIN_B (7)        // MagSpoofZF
#define NPIN (5)         // Button
#define CLOCK_US                                                               \
  (500) // 500us clock, it simulates the speed of the magnetic card swiping
#define BETWEEN_ZERO (53) // 53 zeros between track1 & 2
#define TRACKS (2)
// Longest track magset accepts: fits tracks[128] (+ null) and revTrack[128]
// (+ LRC byte + null), which is what storeRevTrack() needs.
#define TRACK_MAX_CHARS (126)
#define DEBUGCAT

char tracks[2][128]; // 2 tracks, 128 chars each (max)

// Track 2 re-encoded for reverse playback: one byte per character, plus the
// LRC byte and the null terminator, so storeRevTrack() writes strlen + 2 bytes.
// Sized like tracks[] so any track magset accepts fits; the previous
// revTrack[41] left exactly zero margin over the 39-char default track.
char revTrack[128];

const int sublen[] = {32, 48, 48};

const int bitlen[] = {7, 5, 5};

unsigned int curTrack = 0;
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
// into the live playback state (tracks[][], buttonTrack) and re-encode the
// reverse track. Call after anything that changes the active card or its data
// so playTrack()/magget always see the current card.
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
  storeRevTrack(2);
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

// when reversing
void reverseTrack(int track) {
  int i = 0;
  track--; // index 0
  dir = 0;

  while (revTrack[i++] != '\0')
    ;
  i--;
  while (i--)
    for (int j = bitlen[track] - 1; j >= 0; j--)
      playBit((revTrack[i] >> j) & 1);
}

// plays out a full track, calculating CRCs and LRC
void playTrack(int track) {
  int tmp, crc, lrc = 0;
  dir = 0;
  track--; // index 0
  // enable H-bridge and LED
  // digitalWrite(ENABLE_PIN, HIGH);

  // First put out a bunch of leading zeros.
  for (int i = 0; i < 25; i++)
    playBit(0);

  for (int i = 0; tracks[track][i] != '\0'; i++) {
    crc = 1;
    tmp = tracks[track][i] - sublen[track];

    for (int j = 0; j < bitlen[track] - 1; j++) {
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
  for (int j = 0; j < bitlen[track] - 1; j++) {
    crc ^= tmp & 1;
    playBit(tmp & 1);
    tmp >>= 1;
  }
  playBit(crc);

  // if track 1, play 2nd track in reverse (like swiping back?)
  if (track == 0) {
    // if track 1, also play track 2 in reverse
    // zeros in between
    for (int i = 0; i < BETWEEN_ZERO; i++)
      playBit(0);

    // send second track in reverse
    reverseTrack(2);
  }

  // finish with 0's
  for (int i = 0; i < 5 * 5; i++)
    playBit(0);

  digitalWrite(PIN_A, LOW);
  digitalWrite(PIN_B, LOW);
}

// stores track for reverse usage later
void storeRevTrack(int track) {
  int i, tmp, crc, lrc = 0;
  track--; // index 0
  dir = 0;
  // Parity goes on the character's top bit, which is track-dependent: bit 4
  // for track 2's 5-bit characters, bit 6 for track 1's 7-bit ones.
  const int parityBit = bitlen[track] - 1;

  for (i = 0; tracks[track][i] != '\0'; i++) {
    crc = 1;
    tmp = tracks[track][i] - sublen[track];

    for (int j = 0; j < bitlen[track] - 1; j++) {
      crc ^= tmp & 1;
      lrc ^= (tmp & 1) << j;
      tmp & 1 ? (revTrack[i] |= 1 << j) : (revTrack[i] &= ~(1 << j));
      tmp >>= 1;
    }
    crc ? (revTrack[i] |= 1 << parityBit) : (revTrack[i] &= ~(1 << parityBit));
  }

  // finish calculating and send last "byte" (LRC)
  tmp = lrc;
  crc = 1;
  for (int j = 0; j < bitlen[track] - 1; j++) {
    crc ^= tmp & 1;
    tmp & 1 ? (revTrack[i] |= 1 << j) : (revTrack[i] &= ~(1 << j));
    tmp >>= 1;
  }
  crc ? (revTrack[i] |= 1 << parityBit) : (revTrack[i] &= ~(1 << parityBit));

  i++;
  revTrack[i] = '\0';
}

void magspoof() {
  if (digitalRead(NPIN) == 0) {
    Serial.println("Activating MagSpoof...");
    int track = (buttonTrack != 0) ? (int)buttonTrack : 1 + (curTrack++ % 2);
    playTrack(track);
    emitMagEvent(millis(), track);
    blink(L1, 150, 3);
    delay(400);
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
      track = 1 + (curTrack++ % 2);
    } else if (strcmp(args, "1") == 0) {
      track = 1;
    } else if (strcmp(args, "2") == 0) {
      track = 2;
    } else {
      Serial.println("-ERR bad track");
      return true;
    }
    playTrack(track);
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
    // Playing track 1 replays track 2 in reverse, so a new track 2 has to be
    // re-encoded here or playTrack(1) would keep emitting the previous one.
    if (track == 2) {
      storeRevTrack(2);
    }
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

  return false;
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
    storeRevTrack(2);
  }
  Serial.print("Track 1: ");
  Serial.println(tracks[0]);
  Serial.print("Track 2: ");
  Serial.println(tracks[1]);

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
