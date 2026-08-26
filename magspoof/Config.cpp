/**
 * MagSpoof Flash Storage - Config (CRC-32)
 *
 * Bitwise IEEE 802.3 CRC-32 (poly 0xEDB88320). No lookup table: the records are
 * small (~290 B) and written rarely, so the ~256-byte table is not worth the
 * RAM/flash on the RP2040.
 *
 * Distributed as-is; no warranty is given.
 */
#include "Config.h"

uint32_t magCrc32(const void *data, size_t len) {
  const uint8_t *p = static_cast<const uint8_t *>(data);
  uint32_t crc = 0xFFFFFFFFu;
  for (size_t i = 0; i < len; i++) {
    crc ^= p[i];
    for (int b = 0; b < 8; b++)
      crc = (crc >> 1) ^ (0xEDB88320u & (~(crc & 1) + 1));
  }
  return ~crc;
}
