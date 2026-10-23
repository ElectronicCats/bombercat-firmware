/**
 * BomberCat MifareClassic - MIFARE Classic access bits (C1/C2/C3).
 *
 * Port of bombercat-tools/modules/tags/mifare/access_bits.py (NXP MF1S50yyX
 * datasheet, "Access bits" / access conditions for data blocks and sector
 * trailers). Kept byte-for-byte equivalent to the Python: same tables, same
 * bit layout, same inverse check.
 *
 * Distributed as-is; no warranty is given.
 */
#include "MifareAccessBits.h"

namespace {

// (C1, C2, C3) -> permissions, data blocks (NXP MF1S50yyX, Table 7).
struct PermTriplet {
  uint8_t c1, c2, c3;
  MifareAccessPerm read, write, increment, decrement;
};

const PermTriplet kDataBlockTable[8] = {
    {0, 0, 0, MIFARE_PERM_KEY_AB, MIFARE_PERM_KEY_AB, MIFARE_PERM_KEY_AB,
     MIFARE_PERM_KEY_AB},
    {0, 1, 0, MIFARE_PERM_KEY_AB, MIFARE_PERM_NEVER, MIFARE_PERM_NEVER,
     MIFARE_PERM_NEVER},
    {1, 0, 0, MIFARE_PERM_KEY_AB, MIFARE_PERM_KEY_B, MIFARE_PERM_NEVER,
     MIFARE_PERM_NEVER},
    {1, 1, 0, MIFARE_PERM_KEY_AB, MIFARE_PERM_KEY_B, MIFARE_PERM_KEY_B,
     MIFARE_PERM_KEY_AB},
    {0, 0, 1, MIFARE_PERM_KEY_AB, MIFARE_PERM_NEVER, MIFARE_PERM_NEVER,
     MIFARE_PERM_KEY_AB},
    {0, 1, 1, MIFARE_PERM_KEY_B, MIFARE_PERM_KEY_B, MIFARE_PERM_NEVER,
     MIFARE_PERM_NEVER},
    {1, 0, 1, MIFARE_PERM_KEY_B, MIFARE_PERM_NEVER, MIFARE_PERM_NEVER,
     MIFARE_PERM_NEVER},
    {1, 1, 1, MIFARE_PERM_NEVER, MIFARE_PERM_NEVER, MIFARE_PERM_NEVER,
     MIFARE_PERM_NEVER},
};

// (C1, C2, C3) -> permissions, sector trailer (NXP MF1S50yyX, Table 8).
struct TrailerPermTriplet {
  uint8_t c1, c2, c3;
  MifareAccessPerm keyAWrite, acRead, acWrite, keyBRead, keyBWrite;
};

const TrailerPermTriplet kTrailerTable[8] = {
    {0, 0, 0, MIFARE_PERM_KEY_A, MIFARE_PERM_KEY_A, MIFARE_PERM_NEVER,
     MIFARE_PERM_KEY_A, MIFARE_PERM_KEY_A},
    {0, 1, 0, MIFARE_PERM_NEVER, MIFARE_PERM_KEY_A, MIFARE_PERM_NEVER,
     MIFARE_PERM_KEY_A, MIFARE_PERM_NEVER},
    {1, 0, 0, MIFARE_PERM_KEY_B, MIFARE_PERM_KEY_AB, MIFARE_PERM_NEVER,
     MIFARE_PERM_NEVER, MIFARE_PERM_KEY_B},
    {1, 1, 0, MIFARE_PERM_NEVER, MIFARE_PERM_KEY_AB, MIFARE_PERM_NEVER,
     MIFARE_PERM_NEVER, MIFARE_PERM_NEVER},
    {0, 0, 1, MIFARE_PERM_KEY_A, MIFARE_PERM_KEY_A, MIFARE_PERM_KEY_A,
     MIFARE_PERM_KEY_A, MIFARE_PERM_KEY_A},
    {0, 1, 1, MIFARE_PERM_KEY_B, MIFARE_PERM_KEY_AB, MIFARE_PERM_KEY_B,
     MIFARE_PERM_NEVER, MIFARE_PERM_KEY_B},
    {1, 0, 1, MIFARE_PERM_NEVER, MIFARE_PERM_KEY_AB, MIFARE_PERM_KEY_B,
     MIFARE_PERM_NEVER, MIFARE_PERM_NEVER},
    {1, 1, 1, MIFARE_PERM_NEVER, MIFARE_PERM_KEY_AB, MIFARE_PERM_NEVER,
     MIFARE_PERM_NEVER, MIFARE_PERM_NEVER},
};

uint8_t bit(uint8_t byte, uint8_t n) { return (byte >> n) & 1; }

} // namespace

void mifareParseAccessBits(const uint8_t *ac, MifareAccessBits &out) {
  const uint8_t b6 = ac[0];
  const uint8_t b7 = ac[1];
  const uint8_t b8 = ac[2];

  uint8_t c1[4], c2[4], c3[4];
  uint8_t c1Inv[4], c2Inv[4], c3Inv[4];
  for (uint8_t n = 0; n < 4; n++) {
    c1[n] = bit(b7, 4 + n);
    c2[n] = bit(b8, n);
    c3[n] = bit(b8, 4 + n);
    c1Inv[n] = bit(b6, n);
    c2Inv[n] = bit(b6, 4 + n);
    c3Inv[n] = bit(b7, n);
  }

  bool valid = true;
  for (uint8_t n = 0; n < 4; n++) {
    if (c1[n] == c1Inv[n] || c2[n] == c2Inv[n] || c3[n] == c3Inv[n]) {
      valid = false;
    }
  }
  out.valid = valid;

  for (uint8_t n = 0; n < 3; n++) {
    for (uint8_t i = 0; i < 8; i++) {
      const PermTriplet &t = kDataBlockTable[i];
      if (t.c1 == c1[n] && t.c2 == c2[n] && t.c3 == c3[n]) {
        out.blocks[n].read = t.read;
        out.blocks[n].write = t.write;
        out.blocks[n].increment = t.increment;
        out.blocks[n].decrement = t.decrement;
        break;
      }
    }
  }

  for (uint8_t i = 0; i < 8; i++) {
    const TrailerPermTriplet &t = kTrailerTable[i];
    if (t.c1 == c1[3] && t.c2 == c2[3] && t.c3 == c3[3]) {
      out.trailer.keyAWrite = t.keyAWrite;
      out.trailer.acRead = t.acRead;
      out.trailer.acWrite = t.acWrite;
      out.trailer.keyBRead = t.keyBRead;
      out.trailer.keyBWrite = t.keyBWrite;
      break;
    }
  }
}

bool mifarePermAllows(MifareAccessPerm perm, bool keyA) {
  switch (perm) {
  case MIFARE_PERM_KEY_A:
    return keyA;
  case MIFARE_PERM_KEY_B:
    return !keyA;
  case MIFARE_PERM_KEY_AB:
    return true;
  case MIFARE_PERM_NEVER:
  default:
    return false;
  }
}
