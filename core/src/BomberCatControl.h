/**
 * BomberCatCore - BomberCatControl
 *
 * A lightweight, standalone control REPL over a Stream (USB-serial) for the
 * "simple" BomberCat firmwares (DetectTags, magspoof, WiFiWebServer, ...) that
 * do NOT use the relay stack. It implements only the minimal subset of the
 * BomberCat serial protocol the host CLI (bombercat-tools) needs to discover
 * and identify a board:
 *
 *   ping      -> +OK bombercat            (auto-detection / handshake)
 *   info      -> :fw :firmware :state +OK (bombercat device info)
 *   identify  -> +OK  (+ LED blink)       (bombercat identify)
 *   <other>   -> -ERR unknown command
 *
 * Unlike core/src/SerialControl.h this class has NO dependency on ConfigStore /
 * RelayEngine / NfcGateLink, so any sketch can add it without pulling in the
 * relay stack. NFCGate keeps using the full SerialControl; this is the small
 * sibling for everything else.
 *
 * Wire protocol (same leading-marker convention as SerialControl): a datum is
 * ":<key> <value>", a command terminates with "+OK [text]" or "-ERR <text>",
 * and any line NOT starting with ':' '+' or '-' is log noise the CLI ignores —
 * which is why adding this REPL does not disturb a firmware's existing serial
 * output.
 *
 * Distributed as-is; no warranty is given.
 */
#ifndef BOMBERCAT_CORE_BOMBERCATCONTROL_H
#define BOMBERCAT_CORE_BOMBERCATCONTROL_H

#include <Arduino.h>

class BomberCatControl {
public:
  // Optional hooks the sketch provides. Both may be null.
  struct Callbacks {
    // Start a short visual identification (LED blink) so the user can match a
    // CLI device ID to a board on the desk. If null, BomberCatControl blinks
    // LED_BUILTIN itself. Must return promptly; the blink is driven from
    // poll().
    void (*identify)() = nullptr;
    // Control-plane state name reported by `info` ("idle"|"running"|...). If
    // null, `info` reports "idle".
    const char *(*state)() = nullptr;
  };

  // `io` must outlive the control object (typically a global in the sketch).
  // `fwVersion` and `fwName` are reported by `info` (e.g. "1.0.0",
  // "DetectTags").
  BomberCatControl(Stream &io, const char *fwVersion, const char *fwName);

  void setCallbacks(const Callbacks &cb) { _cb = cb; }

  // Announce readiness so the CLI can sync (prints "+OK bombercat ready").
  void begin();

  // Read available bytes, dispatch each complete line and advance an armed
  // identify blink. Call once per loop(); never blocks.
  void poll();

private:
  void dispatch(char *line);
  void ok();
  void ok(const char *msg);
  void err(const char *msg);
  void kv(const char *key, const char *value);

  // Built-in identify blink (used when no identify callback is supplied).
  void startIdentify();
  void driveIdentify();

  Stream &_io;
  const char *_fw;
  const char *_name;
  Callbacks _cb;

  static const size_t LINE_MAX = 64;
  char _buf[LINE_MAX];
  size_t _len = 0;
  bool _overflow = false;

  uint32_t _identifyUntil = 0; // 0 = not identifying
  uint32_t _identifyNext = 0;  // next LED toggle (millis)
  bool _identifyLedOn = false;
};

#endif // BOMBERCAT_CORE_BOMBERCATCONTROL_H
