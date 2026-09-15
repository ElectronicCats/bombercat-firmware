/**
 * BomberCatCore - MagStripe
 *
 * Reusable magnetic-stripe (MagSpoof) F2F emulation engine, factored out of the
 * bit-banging code that was duplicated across the MagSpoof sketches:
 *   - WiFiWebServer/magspoof.ino, MagSpoofMqtt, MagspoofCVSAttack  (classic)
 *   - magspoof/magspoof.ino (forward-only)
 *
 * Those sketches carried byte-identical copies of blink()/playBit()/
 * reverseTrack()/playTrack()/storeRevTrack(); only the pin/timing #defines and
 * two knobs (leading-zero count and whether track 1 replays track 2 in reverse)
 * differed. This class owns the F2F engine and exposes those knobs through
 * Config, so each sketch keeps ONLY its own trigger/UX glue (button handling,
 * track loading, event reporting) and calls into the shared engine.
 *
 * Character encoding is ISO/IEC 7811-2 (track 1, 6-bit) / 7813 (track 2,
 * 5-bit); it is a straight linear offset from ASCII (c - sublen[track]) with
 * odd-parity added per character and an LRC byte appended, exactly as the
 * legacy sketches did.
 *
 * Usage from a sketch:
 *
 *   #include <MagStripe.h>
 *   char tracks[2][128];                     // your track store (unchanged)
 *   MagStripe stripe(MagStripe::classic());  // or MagStripe::forwardOnly()
 *
 *   void setup()  { stripe.begin(); }        // pinMode for A/B/LED/button
 *   void loop()   {
 *     if (stripe.buttonPressed()) stripe.playTrack(1, tracks);
 *   }
 *
 * Distributed as-is; no warranty is given.
 */
#ifndef BOMBERCAT_CORE_MAGSTRIPE_H
#define BOMBERCAT_CORE_MAGSTRIPE_H

#include <Arduino.h>

class MagStripe {
public:
  // Wiring + timing + waveform knobs. The two knobs that actually differed
  // between the sketches are `leadingZeros` and `reversePass`; everything else
  // was identical (BomberCat's PIN_A=6 / PIN_B=7 H-bridge, NPIN=5 button,
  // LED_BUILTIN, 500us bit clock).
  struct Config {
    uint8_t pinA;      // H-bridge phase A (PIN_A)
    uint8_t pinB;      // H-bridge phase B (PIN_B)
    uint8_t pinLed;    // activity LED (L1)
    uint8_t pinButton; // trigger button (NPIN), read active-low
    uint16_t clockUs;  // half-bit period in microseconds (CLOCK_US)
    uint16_t
        leadingZeros;     // clock-lock preamble zeros before the start sentinel
    uint16_t betweenZero; // zeros inserted between track 1 and the reverse pass
    bool reversePass;     // classic: playing track 1 also replays track 2 in
                          // reverse; forward-only: never (single clean swipe)
  };

  // Classic BomberCat MagSpoof waveform (WiFiWebServer / MagSpoofMqtt /
  // MagspoofCVSAttack): 25 leading zeros and the track-1 -> track-2-reverse
  // "there and back" pass. Byte-for-byte the legacy behaviour.
  static Config classic();

  // Forward-only waveform (magspoof/magspoof.ino): 60 leading zeros for a
  // longer PLL lock and NO reverse pass, so an MSR decodes the data once, not
  // twice-with-a-corrupted-sentinel. Same character encoding as classic.
  static Config forwardOnly();

  explicit MagStripe(const Config &cfg) : cfg_(cfg) {}

  // Configure the H-bridge / LED as OUTPUT and the button as INPUT_PULLUP.
  // Does NOT touch Serial. Call from setup().
  void begin();

  // Blink the activity LED `times` times with `msdelay` on/off periods.
  void blink(int msdelay, int times);

  // True while the trigger button is held (active-low, matches the legacy
  // `digitalRead(NPIN) == 0`).
  bool buttonPressed() const;

  // Emit one track as a swipe. `track` is 1 or 2. `tracks` is the caller's
  // 2-track store (tracks[0], tracks[1]) so the classic reverse pass can reach
  // track 2 while playing track 1. Blocks for the duration of the swipe
  // (~0.6-1.5 s) and drops the field when done.
  void playTrack(int track, const char tracks[2][128]);

  // Populate the internal reverse-playback buffer from `track` (1 or 2) so a
  // later classic reverse pass reproduces it. Preserved for parity with the
  // legacy API; the historical sketches defined it but never called it, so the
  // reverse pass replayed an empty buffer (a no-op). Only meaningful when
  // Config::reversePass is true.
  void storeRevTrack(int track, const char tracks[2][128]);

private:
  void playBit(int sendBit);
  void reverseTrack(int track);

  Config cfg_;
  int dir_ = 0;
  char revTrack_[41] = {0};
};

#endif // BOMBERCAT_CORE_MAGSTRIPE_H
