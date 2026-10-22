/**
 * BomberCatCore - the standalone field trigger (Fase 4, tarea 4.3).
 *
 * The standalone workflow (Fase 4, tarea 4.4) already runs on its own when
 * the persistent `mifare standalone on` flag is set. What was missing is the
 * GESTURE that starts it in the field, with no PC attached: the board sits
 * there, the operator walks up with a card, and something has to say "now do
 * the job".
 *
 * The BomberCat board has exactly two push buttons (BOM v1.3):
 *
 *   SW1 "RESET" -> the RP2040's RUN pin. Pressing it REBOOTS the board, so
 *                  it cannot be a trigger (a reboot would wipe the sweep in
 *                  progress).
 *   SW2 "GPIO"  -> RP2040 GPIO17 = Arduino D5, active LOW to GND. This is
 *                  the board's user button, and the very same one the MagSpoof
 *                  sketch uses as its trigger (MagStripe::classic() ->
 *                  pinButton = 5). The board's LED1 is on GPIO27 = D15 =
 *                  LED_BUILTIN.
 *
 * So the trigger is SW2, and it speaks two gestures:
 *
 *   short press  -> ONE-SHOT: run the chain for the card in the field (dump
 *                   the sectors the sweep cracked and emit them). With no
 *                   card in the field it ARMS the one-shot, and the next
 *                   detection runs it.
 *   long press   -> TOGGLE the persistent standalone flag (armed mode: the
 *                   chain runs on every detection). The flag lives in the
 *                   key-store, so it survives a reset.
 *
 * This module holds ONLY the logic - the debounce, the short/long
 * classification, the one-shot latch and the LED blink pattern - with no
 * Arduino dependency at all, so it can be compiled natively and checked
 * against a model (bombercat-tools/tests/test_mifare_trigger.py). The sketch
 * owns the pins: it reads the button, writes the LED, and decides what a
 * gesture means.
 *
 * Distributed as-is; no warranty is given.
 */
#ifndef BOMBERCAT_CORE_MIFARESTANDALONETRIGGER_H
#define BOMBERCAT_CORE_MIFARESTANDALONETRIGGER_H

#include <stdint.h>

// What a button gesture produced.
enum MifareTriggerEvent {
  MIFARE_TRIGGER_NONE = 0,  // nothing (still bouncing, or just idle)
  MIFARE_TRIGGER_SHORT = 1, // a short press: the one-shot
  MIFARE_TRIGGER_LONG = 2,  // a long press: the persistent flag
};

// The board's trigger button (SW2 -> RP2040 GPIO17 = Arduino D5) and the
// board's LED (LED1 -> GPIO27 = Arduino D15 = LED_BUILTIN). The Arduino pin
// numbering is the one the rest of the repo already uses (MagStripe's
// pinButton = 5 is this very button).
static const uint8_t MIFARE_TRIGGER_PIN = 5;

// How long a press has to be held to count as a LONG press. Long enough not
// to fire by accident while operating the board, short enough not to feel
// like a chore in the field.
static const uint32_t MIFARE_TRIGGER_LONG_MS = 1200;

// How long the button level must be stable before it is believed. The button
// is a cheap SMD tactile switch: it bounces for a few ms.
static const uint32_t MIFARE_TRIGGER_DEBOUNCE_MS = 25;

// The button gesture recogniser.
//
// Feed it the raw button level and the clock; it answers with the gesture
// (at most one per call). It is deliberately free of Arduino so the logic can
// be tested natively.
class MifareStandaloneTrigger {
public:
  // Reset the state machine. `nowMs` seeds the debounce clock.
  void begin(uint32_t nowMs);

  void setDebounceMs(uint32_t ms) { _debounceMs = ms; }
  void setLongPressMs(uint32_t ms) { _longPressMs = ms; }

  uint32_t longPressMs() const { return _longPressMs; }
  uint32_t debounceMs() const { return _debounceMs; }

  // Feed the button level (true = pressed) and the current time. Returns the
  // gesture, if any.
  int poll(bool pressed, uint32_t nowMs);

  // The one-shot latch: armed by a short press with no card in the field,
  // consumed by the next detection that runs the chain.
  void armOneShot();
  bool oneShotPending() const { return _oneShot; }
  // Read AND clear the latch.
  bool takeOneShot();

  // How many presses (short and long) the button has seen.
  uint32_t presses() const { return _presses; }
  uint32_t longPresses() const { return _longPresses; }

private:
  bool _raw = false;    // the last level sampled
  bool _stable = false; // the level the debouncer believes
  uint32_t _rawChangedMs = 0;
  uint32_t _pressStartMs = 0;
  bool _longFired = false; // the long press already reported
  bool _oneShot = false;
  uint32_t _presses = 0;
  uint32_t _longPresses = 0;
  uint32_t _debounceMs = MIFARE_TRIGGER_DEBOUNCE_MS;
  uint32_t _longPressMs = MIFARE_TRIGGER_LONG_MS;
};

// The LED feedback pattern.
//
// One tiny scheduler drives the board's only LED, so the two things that
// light it (the host's `identify` command and the button's feedback) can
// never fight over the pin. Like the trigger, it is pure logic: the sketch
// applies the state it returns.
class MifareLedBlink {
public:
  void begin();

  // Blink until `untilMs` (the host's identify: a steady blink so the user
  // can tell which board is which).
  void blinkUntil(uint32_t untilMs, uint16_t onMs, uint16_t offMs);
  // Blink `count` times (the button's feedback).
  void blinkTimes(uint8_t count, uint16_t onMs, uint16_t offMs);

  // Advance the pattern and return the LED state (true = lit).
  bool update(uint32_t nowMs);
  bool active() const { return _active; }

private:
  bool _active = false;
  bool _lit = false;
  uint32_t _untilMs = 0; // the steady blink runs until here
  uint16_t _onMs = 150;
  uint16_t _offMs = 150;
  uint32_t _nextToggleMs = 0;
  uint8_t _remaining = 0; // blinks left in the counted pattern
  bool _counted = false;  // the counted pattern is the active one
};

#endif // BOMBERCAT_CORE_MIFARESTANDALONETRIGGER_H
