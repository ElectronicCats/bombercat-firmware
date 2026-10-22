/**
 * BomberCatCore - GpioUtils
 *
 * Tiny GPIO helpers shared by the sketches. `blink()` is the generic
 * "flash a pin N times" status-LED helper, lifted out of the byte-identical
 * copies in host_Relay_NFC and client_Relay_NFC. It is the free-function
 * counterpart to MagStripe::blink (which owns the MagSpoof LED pin) and
 * MifareStandaloneTrigger's blink* methods (which drive a timed state machine):
 * this one just takes the pin, so any sketch can flash an arbitrary LED.
 *
 * Header-only: the body is three lines and Arduino-dependent, so there is
 * nothing to compile separately.
 *
 * Distributed as-is; no warranty is given.
 */
#ifndef BOMBERCAT_CORE_GPIO_UTILS_H
#define BOMBERCAT_CORE_GPIO_UTILS_H

#include <Arduino.h>

namespace Gpio {

// Blink `pin` `times` times, `msdelay` ms on and `msdelay` ms off. Blocking.
inline void blink(int pin, int msdelay, int times) {
  for (int i = 0; i < times; i++) {
    digitalWrite(pin, HIGH);
    delay(msdelay);
    digitalWrite(pin, LOW);
    delay(msdelay);
  }
}

} // namespace Gpio

#endif // BOMBERCAT_CORE_GPIO_UTILS_H
