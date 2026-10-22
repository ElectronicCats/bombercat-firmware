/**
 * BomberCat MifareClassic - the standalone field trigger (Fase 4, tarea 4.3).
 *
 * Implementation of the debounce / short-long classification / one-shot latch
 * and of the LED pattern scheduler. See MifareStandaloneTrigger.h.
 *
 * Distributed as-is; no warranty is given.
 */

#include "MifareStandaloneTrigger.h"

void MifareStandaloneTrigger::begin(uint32_t nowMs) {
  _raw = false;
  _stable = false;
  _rawChangedMs = nowMs;
  _pressStartMs = 0;
  _longFired = false;
  _oneShot = false;
  _presses = 0;
  _longPresses = 0;
}

int MifareStandaloneTrigger::poll(bool pressed, uint32_t nowMs) {
  // 1. Remember the raw level and when it changed.
  if (pressed != _raw) {
    _raw = pressed;
    _rawChangedMs = nowMs;
  }

  // 2. Believe a change only once it has been stable for the debounce window.
  //    A bouncing switch would otherwise look like a press and a release.
  if (_raw != _stable) {
    if ((uint32_t)(nowMs - _rawChangedMs) < _debounceMs) {
      return MIFARE_TRIGGER_NONE; // still bouncing
    }
    _stable = _raw;
    if (_stable) {
      // The press starts now: this is the reference for the long-press
      // threshold, and the only thing the debounce window shifts.
      _pressStartMs = nowMs;
      _longFired = false;
      _presses++;
    } else {
      // Released. A press that never reached the long threshold was a short
      // one; a long press already reported itself while it was held.
      if (!_longFired) {
        return MIFARE_TRIGGER_SHORT;
      }
      return MIFARE_TRIGGER_NONE;
    }
  }

  // 3. Held long enough: that is the long press, reported ONCE (the finger
  //    is still down).
  if (_stable && !_longFired &&
      (uint32_t)(nowMs - _pressStartMs) >= _longPressMs) {
    _longFired = true;
    _longPresses++;
    return MIFARE_TRIGGER_LONG;
  }

  return MIFARE_TRIGGER_NONE;
}

void MifareStandaloneTrigger::armOneShot() { _oneShot = true; }

bool MifareStandaloneTrigger::takeOneShot() {
  if (!_oneShot) {
    return false;
  }
  _oneShot = false;
  return true;
}

void MifareLedBlink::begin() {
  _active = false;
  _lit = false;
  _untilMs = 0;
  _nextToggleMs = 0;
  _remaining = 0;
  _counted = false;
}

void MifareLedBlink::blinkUntil(uint32_t untilMs, uint16_t onMs,
                                uint16_t offMs) {
  _untilMs = untilMs;
  _onMs = onMs;
  _offMs = offMs;
  _nextToggleMs = 0; // toggle on the next update()
  _remaining = 0;
  _counted = false;
  _active = true;
  _lit = false;
}

void MifareLedBlink::blinkTimes(uint8_t count, uint16_t onMs, uint16_t offMs) {
  if (count == 0) {
    return;
  }
  _untilMs = 0;
  _onMs = onMs;
  _offMs = offMs;
  _nextToggleMs = 0; // light up on the next update()
  _remaining = count;
  _counted = true;
  _active = true;
  _lit = false;
}

bool MifareLedBlink::update(uint32_t nowMs) {
  if (!_active) {
    return false;
  }

  if (!_counted) {
    // The steady blink: light/dark until the deadline.
    if ((int32_t)(nowMs - _untilMs) >= 0) {
      _active = false;
      _lit = false;
      return false;
    }
    if ((int32_t)(nowMs - _nextToggleMs) >= 0) {
      _lit = !_lit;
      _nextToggleMs = nowMs + (_lit ? _onMs : _offMs);
    }
    return _lit;
  }

  // The counted pattern: `count` blinks of on/off, then the LED goes dark.
  if (_remaining == 0) {
    _active = false;
    _lit = false;
    return false;
  }
  if ((int32_t)(nowMs - _nextToggleMs) >= 0) {
    if (_lit) {
      // The lit half just ended: one blink done.
      _remaining--;
      _lit = false;
      _nextToggleMs = nowMs + _offMs;
    } else {
      _lit = true;
      _nextToggleMs = nowMs + _onMs;
    }
  }
  return _lit;
}
