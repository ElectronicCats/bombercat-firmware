/**
 * BomberCat MifareClassic - MIFARE Classic block 0 dissection.
 *
 * Port of bombercat-tools/modules/tags/mifare/block0.py. Same layout, same
 * names, same check byte rule.
 *
 * Distributed as-is; no warranty is given.
 */
#include "MifareBlock0.h"

namespace {

struct SakName {
  uint8_t sak;
  const char *name;
};

// The SAK values the host's block0.py knows about. 0x88 is non-NXP silicon
// (Infineon SLE66R35 and friends) that sets the proprietary b8 bit on top of
// the standard Classic 1K SAK: 0x88 & 0x7F == 0x08.
const SakName kSakNames[] = {
    {0x08, "MIFARE Classic 1K"},  {0x18, "MIFARE Classic 4K"},
    {0x09, "MIFARE Mini"},        {0x28, "SmartMX Classic 1K"},
    {0x38, "SmartMX Classic 4K"}, {0x88, "MIFARE Classic 1K (Infineon)"},
};

} // namespace

void mifareParseBlock0(const uint8_t block[16], MifareBlock0 &out) {
  out.uid[0] = block[0];
  out.uid[1] = block[1];
  out.uid[2] = block[2];
  out.uid[3] = block[3];
  out.bcc = block[4];
  out.bccValid = (block[0] ^ block[1] ^ block[2] ^ block[3]) == block[4];
  out.sak = block[5];
  out.atqa[0] = block[6];
  out.atqa[1] = block[7];
  for (uint8_t i = 0; i < 8; i++) {
    out.manufacturer[i] = block[8 + i];
  }
}

const char *mifareSakName(uint8_t sak) {
  for (uint8_t i = 0; i < sizeof(kSakNames) / sizeof(kSakNames[0]); i++) {
    if (kSakNames[i].sak == sak) {
      return kSakNames[i].name;
    }
  }
  return "unknown/non-standard";
}

const char *mifareAtqaName(const uint8_t atqa[2]) {
  // The host's block0.py keys the table by the ATQA's hex string, in the byte
  // order it was read ("0400" = Classic 1K, "0200" = Classic 4K).
  if (atqa[0] == 0x04 && atqa[1] == 0x00) {
    return "MIFARE Classic 1K";
  }
  if (atqa[0] == 0x02 && atqa[1] == 0x00) {
    return "MIFARE Classic 4K";
  }
  return "unknown";
}

bool mifareSakIsClassic(uint8_t sak) {
  // The "MIFARE Classic" bit of the SAK is b3 (0x08); the proprietary b8 bit
  // of non-NXP silicon must not change the verdict.
  return (sak & 0x08) != 0;
}
