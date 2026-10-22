/**
 * BomberCatCore - MifareDumpFormat (implementation)
 *
 * Pure (no Arduino.h): see MifareDumpFormat.h.
 *
 * A self-check lives at the bottom, guarded by MIFARE_DUMP_FORMAT_SELFTEST,
 * so the format can be verified natively (g++) without the Arduino toolchain:
 *   g++ -DMIFARE_DUMP_FORMAT_SELFTEST -I. MifareDumpFormat.cpp -o t && ./t
 *
 * Distributed as-is; no warranty is given.
 */
#include "MifareDumpFormat.h"

#include <stdio.h>

namespace {

// Append `src` at out[*pos], NUL-terminating, without ever writing past `cap`.
// Returns false (and leaves a '\0' at the start) on overflow, so the caller
// aborts the whole payload: a truncated dump is never published.
bool appendStr(char *out, size_t cap, size_t *pos, const char *src) {
  while (*src) {
    if (*pos + 1 >= cap) { // +1 keeps room for the terminating NUL
      out[0] = '\0';
      return false;
    }
    out[(*pos)++] = *src++;
  }
  out[*pos] = '\0';
  return true;
}

// Append one byte as two uppercase hex digits (as HexUtils::toCompact does,
// but without the Arduino dependency this module keeps itself free of).
bool appendHexByte(char *out, size_t cap, size_t *pos, uint8_t b) {
  static const char kHex[] = "0123456789ABCDEF";
  if (*pos + 2 >= cap) {
    out[0] = '\0';
    return false;
  }
  out[(*pos)++] = kHex[(b >> 4) & 0x0F];
  out[(*pos)++] = kHex[b & 0x0F];
  out[*pos] = '\0';
  return true;
}

} // namespace

namespace MifareDumpFormat {

const char *keyTypeToken(char keyType) {
  if (keyType == 'A') {
    return "A";
  }
  if (keyType == 'B') {
    return "B";
  }
  return "-";
}

size_t formatSector(char *out, size_t cap, uint8_t sector, const uint8_t *data,
                    char keyType, const char *reason) {
  if (out == nullptr || cap == 0) {
    return 0;
  }
  out[0] = '\0';
  size_t pos = 0;

  char head[32];
  snprintf(head, sizeof(head), ":mifare_dump_s%u ", (unsigned)sector);
  if (!appendStr(out, cap, &pos, head)) {
    return 0;
  }

  if (data != nullptr) {
    for (uint8_t i = 0; i < MIFARE_SECTOR_BYTES; i++) {
      if (!appendHexByte(out, cap, &pos, data[i])) {
        return 0;
      }
    }
  } else if (!appendStr(out, cap, &pos, "-")) {
    return 0;
  }

  if (!appendStr(out, cap, &pos, " ") ||
      !appendStr(out, cap, &pos, keyTypeToken(keyType))) {
    return 0;
  }
  if (reason != nullptr && reason[0] != '\0') {
    if (!appendStr(out, cap, &pos, " ") || !appendStr(out, cap, &pos, reason)) {
      return 0;
    }
  }
  return pos;
}

size_t formatStat(char *out, size_t cap, uint8_t read, uint8_t failed,
                  uint8_t total) {
  if (out == nullptr || cap == 0) {
    return 0;
  }
  out[0] = '\0';
  size_t pos = 0;

  char stat[64]; // the stat line reaches 48 chars + NUL at read/failed=255
  snprintf(stat, sizeof(stat), ":mifare_dump_stat read=%u failed=%u total=%u",
           (unsigned)read, (unsigned)failed, (unsigned)total);
  if (!appendStr(out, cap, &pos, stat)) {
    return 0;
  }
  return pos;
}

size_t buildPayload(const MifareDumpSector *sectors, uint8_t count,
                    uint8_t read, uint8_t failed, char *out, size_t cap) {
  if (out == nullptr || cap == 0) {
    return 0;
  }
  out[0] = '\0';
  size_t pos = 0;

  for (uint8_t s = 0; s < count; s++) {
    const MifareDumpSector &sec = sectors[s];

    char line[8 + 2 * MIFARE_SECTOR_BYTES + 32];
    if (formatSector(line, sizeof(line), s, sec.data, sec.keyType,
                     sec.reason) == 0) {
      out[0] = '\0';
      return 0;
    }
    if (!appendStr(out, cap, &pos, line) || !appendStr(out, cap, &pos, "\n")) {
      return 0;
    }
  }

  char stat[64];
  if (formatStat(stat, sizeof(stat), read, failed, count) == 0) {
    out[0] = '\0';
    return 0;
  }
  if (!appendStr(out, cap, &pos, stat) || !appendStr(out, cap, &pos, "\n")) {
    return 0;
  }
  return pos;
}

} // namespace MifareDumpFormat

#ifdef MIFARE_DUMP_FORMAT_SELFTEST
#include <cassert>
#include <cstring>

int main() {
  // Two sectors read (A, B) and one hole (nokey): the three shapes the wire
  // format has. The expected bytes are written out literally - if the format
  // drifts, this fails.
  uint8_t s0[MIFARE_SECTOR_BYTES];
  uint8_t s1[MIFARE_SECTOR_BYTES];
  for (int i = 0; i < MIFARE_SECTOR_BYTES; i++) {
    s0[i] = 0x00;
    s1[i] = (uint8_t)(0xA0 + (i & 0x0F));
  }

  MifareDumpSector sectors[3];
  sectors[0] = {s0, 'A', ""};
  sectors[1] = {s1, 'B', ""};
  sectors[2] = {nullptr, '-', "nokey"};

  char out[1024];
  size_t n = MifareDumpFormat::buildPayload(sectors, 3, 2, 1, out, sizeof(out));
  assert(n == strlen(out));

  // s0: 64 zero bytes -> 128 '0'; s1: A0..AF repeated; s2: a hole.
  const char *expected =
      ":mifare_dump_s0 "
      "00000000000000000000000000000000000000000000000000000000000000000000"
      "000000000000000000000000000000000000000000000000000000000000 A\n"
      ":mifare_dump_s1 "
      "A0A1A2A3A4A5A6A7A8A9AAABACADAEAFA0A1A2A3A4A5A6A7A8A9AAABACADAEAFA0A1A2"
      "A3A4A5A6A7A8A9AAABACADAEAFA0A1A2A3A4A5A6A7A8A9AAABACADAEAF B\n"
      ":mifare_dump_s2 - - nokey\n"
      ":mifare_dump_stat read=2 failed=1 total=3\n";
  assert(strcmp(out, expected) == 0);

  // The per-line formatters carry the same bytes the payload does.
  char line[256];
  size_t ln = MifareDumpFormat::formatSector(line, sizeof(line), 2, nullptr,
                                             '-', "nokey");
  assert(ln == strlen(line));
  assert(strcmp(line, ":mifare_dump_s2 - - nokey") == 0);

  size_t sn = MifareDumpFormat::formatStat(line, sizeof(line), 2, 1, 3);
  assert(sn == strlen(line));
  assert(strcmp(line, ":mifare_dump_stat read=2 failed=1 total=3") == 0);

  // Overflow is refused, not truncated.
  char small[8];
  assert(MifareDumpFormat::buildPayload(sectors, 3, 2, 1, small,
                                        sizeof(small)) == 0);
  assert(small[0] == '\0');

  printf("MifareDumpFormat self-check OK (%zu bytes)\n", n);
  return 0;
}
#endif // MIFARE_DUMP_FORMAT_SELFTEST
