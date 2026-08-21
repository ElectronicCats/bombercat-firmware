/**
 * BomberCatCore - BomberCatControl implementation.
 *
 * Distributed as-is; no warranty is given.
 */
#include "BomberCatControl.h"

#include <string.h>

static const uint32_t IDENTIFY_DURATION_MS = 2000;
static const uint32_t IDENTIFY_PERIOD_MS = 150;

BomberCatControl::BomberCatControl(Stream &io, const char *fwVersion,
                                   const char *fwName)
    : _io(io), _fw(fwVersion), _name(fwName) {}

void BomberCatControl::begin() {
  _len = 0;
  _overflow = false;
  ok("bombercat ready");
}

void BomberCatControl::poll() {
  while (_io.available() > 0) {
    char c = (char)_io.read();
    if (c == '\n' || c == '\r') {
      if (_overflow) {
        err("line too long");
        _overflow = false;
        _len = 0;
        continue;
      }
      if (_len == 0) {
        continue; // ignore empty lines / bare CR-LF
      }
      _buf[_len] = '\0';
      dispatch(_buf);
      _len = 0;
      continue;
    }
    if (_overflow) {
      continue; // still swallowing an over-long line
    }
    if (_len >= LINE_MAX - 1) {
      _overflow = true; // wait for the newline, then error out
      continue;
    }
    _buf[_len++] = c;
  }
  driveIdentify(); // advance an armed blink (no-op when idle / using callback)
}

// --- Response helpers ------------------------------------------------------

void BomberCatControl::ok() { _io.println("+OK"); }

void BomberCatControl::ok(const char *msg) {
  _io.print("+OK ");
  _io.println(msg);
}

void BomberCatControl::err(const char *msg) {
  _io.print("-ERR ");
  _io.println(msg);
}

void BomberCatControl::kv(const char *key, const char *value) {
  _io.print(':');
  _io.print(key);
  _io.print(' ');
  _io.println(value);
}

// --- Dispatch --------------------------------------------------------------

// Split the leading verb off `line`; returns a pointer to the remaining args
// (leading spaces skipped). Mutates `line` in place (null-terminates the verb).
static char *splitVerb(char *line) {
  char *p = line;
  while (*p && *p != ' ')
    p++;
  if (*p == '\0')
    return p;
  *p++ = '\0';
  while (*p == ' ')
    p++;
  return p;
}

void BomberCatControl::dispatch(char *line) {
  while (*line == ' ')
    line++;
  char *verb = line;
  (void)splitVerb(line); // this REPL takes no arguments; verb is enough

  if (strcmp(verb, "ping") == 0) {
    ok("bombercat");
  } else if (strcmp(verb, "info") == 0) {
    kv("fw", _fw);
    kv("firmware", _name);
    kv("state", _cb.state != nullptr ? _cb.state() : "idle");
    ok();
  } else if (strcmp(verb, "identify") == 0) {
    if (_cb.identify != nullptr) {
      _cb.identify();
    } else {
      startIdentify();
    }
    ok();
  } else {
    err("unknown command");
  }
}

// --- Built-in identify blink (LED_BUILTIN) ---------------------------------

void BomberCatControl::startIdentify() {
  pinMode(LED_BUILTIN, OUTPUT);
  _identifyUntil = millis() + IDENTIFY_DURATION_MS;
  if (_identifyUntil == 0)
    _identifyUntil = 1;     // 0 is the "idle" sentinel
  _identifyNext = millis(); // toggle on the next poll()
}

void BomberCatControl::driveIdentify() {
  if (_identifyUntil == 0)
    return; // not identifying, or using a sketch-provided callback
  if ((int32_t)(millis() - _identifyUntil) >= 0) {
    _identifyUntil = 0;
    _identifyLedOn = false;
    digitalWrite(LED_BUILTIN, LOW);
    return;
  }
  if ((int32_t)(millis() - _identifyNext) >= 0) {
    _identifyLedOn = !_identifyLedOn;
    digitalWrite(LED_BUILTIN, _identifyLedOn ? HIGH : LOW);
    _identifyNext = millis() + IDENTIFY_PERIOD_MS;
  }
}
