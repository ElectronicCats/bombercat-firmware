/**
 * BomberCatCore - MifareDumpFormat
 *
 * The canonical BomberCat Mifare dump wire format: the `:mifare_dump_sN …`
 * sector lines and the closing `:mifare_dump_stat …` line.
 *
 * It is ONE format with two carriers: the MifareClassic firmware prints it
 * over USB serial and the MifareMqtt firmware publishes it over MQTT. Both
 * used to spell the grammar out on their own (the serial side in
 * emitDumpSector()/emitStoredResult(), the MQTT side in MifareMqttPayload),
 * which meant the host parser had to trust two copies of the same rule. The
 * format lives here now, so both carriers emit the same bytes by
 * construction.
 *
 * The module is PURE (no Arduino.h, no radio, no flash, draws no current), so
 * it compiles in the native test harness exactly like MifareResultStore.
 *
 * Distributed as-is; no warranty is given.
 */
#ifndef BOMBERCAT_CORE_MIFAREDUMPFORMAT_H
#define BOMBERCAT_CORE_MIFAREDUMPFORMAT_H

#include <stddef.h>
#include <stdint.h>

#include "MifareCommon.h"

// One sector's outcome, flattened from a MifareResultRecord by the caller.
struct MifareDumpSector {
  const uint8_t *data; // the 64 sector bytes, or nullptr for a hole
  char keyType;        // 'A' | 'B' | '-' (the key that read it)
  const char *reason;  // "" when read, else "nokey"|"readfail"|"removed"
};

namespace MifareDumpFormat {

// The wire token for the key that opened a sector: 'A'/'B' pass through,
// anything else is the honest "-".
const char *keyTypeToken(char keyType);

// One sector line, WITHOUT the trailing newline:
//
//   ":mifare_dump_s<N> <hex128|-> <A|B|-> [reason]"
//
// `data` == nullptr renders the hole marker "-"; `reason` == nullptr (or "")
// omits the third token. The hex is uppercase and separator-less.
//
// Returns the number of chars written (excluding the NUL). Returns 0 with
// out[0] = '\0' when the line would not fit in `cap` - a truncated dump is
// never published.
size_t formatSector(char *out, size_t cap, uint8_t sector, const uint8_t *data,
                    char keyType, const char *reason);

// The closing stat line, WITHOUT the trailing newline:
//
//   ":mifare_dump_stat read=<n> failed=<n> total=<n>"
//
// Returns the number of chars written (excluding the NUL), 0 on overflow.
size_t formatStat(char *out, size_t cap, uint8_t read, uint8_t failed,
                  uint8_t total);

// The whole payload: one sector line per sector, then the stat line, each
// terminated with '\n'. NUL-terminated.
//
// Returns the number of chars written (excluding the NUL). Returns 0 with
// out[0] = '\0' if the payload would not fit in `cap`.
size_t buildPayload(const MifareDumpSector *sectors, uint8_t count,
                    uint8_t read, uint8_t failed, char *out, size_t cap);

} // namespace MifareDumpFormat

#endif // BOMBERCAT_CORE_MIFAREDUMPFORMAT_H
