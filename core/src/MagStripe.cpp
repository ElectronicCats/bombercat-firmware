/**
 * BomberCatCore - MagStripe implementation
 *
 * F2F engine lifted verbatim from the legacy MagSpoof sketches; the only change
 * is that the pin/timing constants and the two waveform knobs now come from
 * Config instead of per-sketch #defines. See MagStripe.h.
 *
 * Distributed as-is; no warranty is given.
 */
#include "MagStripe.h"

namespace {
// ISO/IEC 7811-2 (track 1) / 7813 (track 2) linear ASCII offsets and F2F bit
// widths. Index 0 = track 1 (6-bit: 5 data + parity), index 1/2 = track 2/3
// (5-bit: 4 data + parity). A third entry is kept so reverseTrack(2) can index
// [track-1] == [1] exactly as the legacy code did.
const int kSublen[] = {32, 48, 48};
const int kBitlen[] = {7, 5, 5};
} // namespace

MagStripe::Config MagStripe::classic() {
  Config c;
  c.pinA = 6;
  c.pinB = 7;
  c.pinLed = LED_BUILTIN;
  c.pinButton = 5;
  c.clockUs = 500;
  c.leadingZeros = 25;
  c.betweenZero = 53;
  c.reversePass = true;
  return c;
}

MagStripe::Config MagStripe::forwardOnly() {
  Config c = classic();
  c.leadingZeros = 60;
  c.reversePass = false;
  return c;
}

void MagStripe::begin() {
  pinMode(cfg_.pinA, OUTPUT);
  pinMode(cfg_.pinB, OUTPUT);
  pinMode(cfg_.pinLed, OUTPUT);
  pinMode(cfg_.pinButton, INPUT_PULLUP);
}

void MagStripe::blink(int msdelay, int times) {
  for (int i = 0; i < times; i++) {
    digitalWrite(cfg_.pinLed, HIGH);
    delay(msdelay);
    digitalWrite(cfg_.pinLed, LOW);
    delay(msdelay);
  }
}

bool MagStripe::buttonPressed() const {
  return digitalRead(cfg_.pinButton) == 0;
}

// send a single bit out
void MagStripe::playBit(int sendBit) {
  dir_ ^= 1;
  digitalWrite(cfg_.pinA, dir_);
  digitalWrite(cfg_.pinB, !dir_);
  delayMicroseconds(cfg_.clockUs);

  if (sendBit) {
    dir_ ^= 1;
    digitalWrite(cfg_.pinA, dir_);
    digitalWrite(cfg_.pinB, !dir_);
  }
  delayMicroseconds(cfg_.clockUs);
}

// when reversing
void MagStripe::reverseTrack(int track) {
  int i = 0;
  track--; // index 0
  dir_ = 0;

  while (revTrack_[i++] != '\0')
    ;
  i--;
  while (i--)
    for (int j = kBitlen[track] - 1; j >= 0; j--)
      playBit((revTrack_[i] >> j) & 1);
}

// plays out a full track, calculating CRCs and LRC
void MagStripe::playTrack(int track, const char tracks[2][128]) {
  int tmp, crc, lrc = 0;
  dir_ = 0;
  track--; // index 0

  // First put out a bunch of leading zeros so the reader locks its clock.
  for (int i = 0; i < cfg_.leadingZeros; i++)
    playBit(0);

  for (int i = 0; tracks[track][i] != '\0'; i++) {
    crc = 1;
    tmp = tracks[track][i] - kSublen[track];

    for (int j = 0; j < kBitlen[track] - 1; j++) {
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
  for (int j = 0; j < kBitlen[track] - 1; j++) {
    crc ^= tmp & 1;
    playBit(tmp & 1);
    tmp >>= 1;
  }
  playBit(crc);

  // Classic waveform only: if track 1, also play track 2 in reverse (like
  // swiping back). Forward-only configs skip this entirely.
  if (cfg_.reversePass && track == 0) {
    // zeros in between
    for (int i = 0; i < cfg_.betweenZero; i++)
      playBit(0);

    // send second track in reverse
    reverseTrack(2);
  }

  // finish with 0's
  for (int i = 0; i < 5 * 5; i++)
    playBit(0);

  digitalWrite(cfg_.pinA, LOW);
  digitalWrite(cfg_.pinB, LOW);
}

// stores track for reverse usage later
void MagStripe::storeRevTrack(int track, const char tracks[2][128]) {
  int i, tmp, crc, lrc = 0;
  track--; // index 0
  dir_ = 0;

  for (i = 0; tracks[track][i] != '\0'; i++) {
    crc = 1;
    tmp = tracks[track][i] - kSublen[track];

    for (int j = 0; j < kBitlen[track] - 1; j++) {
      crc ^= tmp & 1;
      lrc ^= (tmp & 1) << j;
      tmp & 1 ? (revTrack_[i] |= 1 << j) : (revTrack_[i] &= ~(1 << j));
      tmp >>= 1;
    }
    crc ? (revTrack_[i] |= 1 << 4) : (revTrack_[i] &= ~(1 << 4));
  }

  // finish calculating and send last "byte" (LRC)
  tmp = lrc;
  crc = 1;
  for (int j = 0; j < kBitlen[track] - 1; j++) {
    crc ^= tmp & 1;
    tmp & 1 ? (revTrack_[i] |= 1 << j) : (revTrack_[i] &= ~(1 << j));
    tmp >>= 1;
  }
  crc ? (revTrack_[i] |= 1 << 4) : (revTrack_[i] &= ~(1 << 4));

  i++;
  revTrack_[i] = '\0';
}
