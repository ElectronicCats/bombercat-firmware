/**
 * BomberCat MifareClassic - shared constants.
 *
 * Distributed as-is; no warranty is given.
 */
#ifndef MIFARECLASSIC_H
#define MIFARECLASSIC_H

#include <Arduino.h>

#define BOMBERCAT_FW_VERSION "1.2.0.0"
#define BOMBERCAT_FW_NAME "mifareclassic"

// Mifare Classic key types, as used by the PN7150's raw reader-mode
// authenticate command (see MifareCommands.h). This is the PN7150's own
// proprietary "0x40" authenticate opcode, NOT the PN532-style MIFARE_Authent
// (0x60/0x61) codes the plan originally assumed - the working values (0x10 =
// Key A, 0x11 = Key B) come from ElectronicCats-PN7150's own
// MifareClassic_read_block/_write_block examples
// (`{0x40, block/4, 0x10, key[6]}`), the only verified-on-hardware reference
// for this chip.
static const uint8_t MIFARE_KEY_A = 0x10;
static const uint8_t MIFARE_KEY_B = 0x11;

// Common/default Mifare Classic keys (6 bytes each).
static const uint8_t MIFARE_DEFAULT_KEY_FFFFFF[6] = {0xFF, 0xFF, 0xFF,
                                                     0xFF, 0xFF, 0xFF};
static const uint8_t MIFARE_DEFAULT_KEY_000000[6] = {0x00, 0x00, 0x00,
                                                     0x00, 0x00, 0x00};
static const uint8_t MIFARE_DEFAULT_KEY_A0A1A2A3A4A5[6] = {0xA0, 0xA1, 0xA2,
                                                           0xA3, 0xA4, 0xA5};

// Mifare Classic 1K/4K layout: 4 blocks per sector, 16 bytes per block.
static const uint8_t MIFARE_BLOCKS_PER_SECTOR = 4;
static const uint8_t MIFARE_BLOCK_SIZE = 16;

#endif // MIFARECLASSIC_H
