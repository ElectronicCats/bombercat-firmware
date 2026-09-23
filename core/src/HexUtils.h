/**
 * BomberCatCore - HexUtils
 *
 * Hex formatting helpers, factored out of the duplicated getHexRepresentation()
 * / printData() found in host_Relay_NFC and client_Relay_NFC. Pure formatting,
 * no side effects on the NFC/WiFi state.
 *
 * Distributed as-is; no warranty is given.
 */
#ifndef BOMBERCAT_CORE_HEXUTILS_H
#define BOMBERCAT_CORE_HEXUTILS_H

#include <Arduino.h>

namespace HexUtils {

// Returns a space-separated hex dump such as "0x00 0x1a 0xff".
// Returns the literal "null" when len == 0, matching the legacy
// getHexRepresentation() behaviour the relay sketches relied on.
String toString(const uint8_t *data, size_t len);

// Streams the same representation as toString() without allocating a String.
// Prefer this on the hot path to keep RAM pressure low on the RP2040.
void print(Print &out, const uint8_t *data, size_t len);

// Decodes a hex string (upper/lowercase, spaces ignored) into `out`. Stops at
// the first invalid nibble, an unpaired trailing nibble, or once `maxLen`
// bytes have been written. Returns the number of bytes decoded.
size_t decode(const char *hex, uint8_t *out, size_t maxLen);

// Compact uppercase hex with no "0x"/separators, e.g. "1A2B3C". Writes
// len*2 hex digits plus a terminating '\0' into `out`, which the caller must
// size accordingly (at least len*2 + 1 bytes).
void toCompact(const uint8_t *data, size_t len, char *out);

} // namespace HexUtils

#endif // BOMBERCAT_CORE_HEXUTILS_H
