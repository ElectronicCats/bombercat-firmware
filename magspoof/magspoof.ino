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

#define BOMBERCAT_FW_VERSION "1.1.1.0"

#define L1 (LED_BUILTIN) // LED1
#define PIN_A (6)        // MagSpoof-1
#define PIN_B (7)        // MagSpoofZF
#define NPIN (5)         // Button
#define CLOCK_US                                                               \
  (500) // 500us clock, it simulates the speed of the magnetic card swiping
#define BETWEEN_ZERO (53) // 53 zeros between track1 & 2
#define TRACKS (2)
#define DEBUGCAT

char tracks[2][128]; // 2 tracks, 128 chars each (max)

char revTrack[41]; // 40 chars + null

const int sublen[] = {32, 48, 48};

const int bitlen[] = {7, 5, 5};

unsigned int curTrack = 0;
int dir;

void setupTracks() {
  String track1 =
      "%B123456781234567^LASTNAME/FIRST^YYMMSSSDDDDDDDDDDDDDDDDDDDDDDDDD?";
  String track2 = ";123456781234567=112220100000000000000?";

  // Copy the tracks into the char arrays using strcpy
  strcpy(tracks[0], track1.c_str());
  strcpy(tracks[1], track2.c_str());

  Serial.println("Default tracks:");
  Serial.print("Track 1: ");
  Serial.println(tracks[0]);
  Serial.print("Track 2: ");
  Serial.println(tracks[1]);

  // Keep revTrack in sync so playTrack(1)'s reverseTrack(2) has valid data
  // instead of replaying whatever was in the (zero-initialized) buffer.
  storeRevTrack(2);
}

void updateTracks(String track1, String track2) {
  strcpy(tracks[0], track1.c_str());
  strcpy(tracks[1], track2.c_str());

  Serial.println("Updated tracks:");
  Serial.print("Track 1: ");
  Serial.println(tracks[0]);
  Serial.print("Track 2: ");
  Serial.println(tracks[1]);

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

  for (i = 0; tracks[track][i] != '\0'; i++) {
    crc = 1;
    tmp = tracks[track][i] - sublen[track];

    for (int j = 0; j < bitlen[track] - 1; j++) {
      crc ^= tmp & 1;
      lrc ^= (tmp & 1) << j;
      tmp & 1 ? (revTrack[i] |= 1 << j) : (revTrack[i] &= ~(1 << j));
      tmp >>= 1;
    }
    crc ? (revTrack[i] |= 1 << 4) : (revTrack[i] &= ~(1 << 4));
  }

  // finish calculating and send last "byte" (LRC)
  tmp = lrc;
  crc = 1;
  for (int j = 0; j < bitlen[track] - 1; j++) {
    crc ^= tmp & 1;
    tmp & 1 ? (revTrack[i] |= 1 << j) : (revTrack[i] &= ~(1 << j));
    tmp >>= 1;
  }
  crc ? (revTrack[i] |= 1 << 4) : (revTrack[i] &= ~(1 << 4));

  i++;
  revTrack[i] = '\0';
}

void magspoof() {
  if (digitalRead(NPIN) == 0) {
    Serial.println("Activating MagSpoof...");
    int track = 1 + (curTrack++ % 2);
    playTrack(track);
    emitMagEvent(millis(), track);
    blink(L1, 150, 3);
    delay(400);
  }
}

// Structured event consumed by bombercat-tools, same conventions as :tag/
// :reader: ":mag <ts_ms> <track>", one per reproduction regardless of origin
// (command or physical button).
void emitMagEvent(uint32_t tsMs, int track) {
  Serial.print(":mag ");
  Serial.print(tsMs);
  Serial.print(' ');
  Serial.println(track);
}

// Serial-control command hook for magplay/magset/magget
// (IMPLEMENTATION_PLAN_MagSpoof.md sec 4). Emits its own +OK/-ERR terminator
// and returns true when it handled the verb; returning false lets the core
// REPL answer "-ERR unknown command" instead.
static bool handleCommand(const char *verb, char *args) {
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
    blink(L1, 150, 3);
    Serial.print("+OK played ");
    Serial.println(track);
    return true;
  }

  if (strcmp(verb, "magset") == 0) {
    if ((args[0] != '1' && args[0] != '2') || args[1] != ' ') {
      Serial.println("-ERR bad track");
      return true;
    }
    int track = args[0] - '0';
    char *data = args + 2;
    size_t len = strlen(data);
    if (len > 126) {
      Serial.println("-ERR track too long");
      return true;
    }
    char expectedStart = (track == 1) ? '%' : ';';
    if (len < 3 || data[0] != expectedStart || data[len - 1] != '?') {
      Serial.println("-ERR bad track");
      return true;
    }
    strcpy(tracks[track - 1], data);
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
    Serial.println("+OK");
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
  setupTracks();

  String track1 =
      "%B4784556940589010^HOGAN/PAUL      ^08043210000000725000000?";
  String track2 = ";4784556940589010=08043210000072500000?";
  // Uncomment to modify tracks
  // updateTracks(track1, track2);

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
