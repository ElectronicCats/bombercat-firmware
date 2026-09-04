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
// authenticate command (see MifareCommands.h).
static const uint8_t MIFARE_KEY_A = 0x60;
static const uint8_t MIFARE_KEY_B = 0x61;

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
