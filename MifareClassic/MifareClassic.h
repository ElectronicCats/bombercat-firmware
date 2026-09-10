/**
 * BomberCat MifareClassic - shared constants.
 *
 * Distributed as-is; no warranty is given.
 */
#ifndef MIFARECLASSIC_H
#define MIFARECLASSIC_H

#include <Arduino.h>

#define BOMBERCAT_FW_VERSION "1.1.0.0"
#define BOMBERCAT_FW_NAME "mifareclassic"

// Mifare Classic key types, as used by the PN7150's raw reader-mode
// authenticate command (see MifareCommands.h). This is the PN7150's own
// proprietary "0x40" MFC_Authenticate_REQ, NOT the PN532-style MIFARE_Authent
// (0x60/0x61) codes the plan originally assumed. Per NXP UM10936 (PN7150 User
// Manual) Table 38 "MFC_Authenticate_REQ parameters", the single-byte Key
// Selector is a bitmask, not a plain enum:
//   b7    = Key A ('0') or Key B ('1')
//   b6-b5 = RFU (must be 0)
//   b4    = 0 => use a pre-loaded key (index in b3-b0), 1 => use the 6-byte
//           embedded key (param 3, which this codebase always sends)
//   b3-b0 = pre-loaded key index (0-15); ignored when b4=1
// With b4=1 (embedded key) and b7 as the A/B selector: Key A = 0b0001_0000 =
// 0x10, Key B = 0b1001_0000 = 0x90.
//
// ElectronicCats-PN7150's own MifareClassic_read_block/_write_block examples
// (`{0x40, block/4, 0x10, key[6]}`) only ever demonstrate Key A - they were
// (wrongly) read as implying 0x11 for Key B, by analogy with 0x10+1. 0x11 sets
// b0 (part of the pre-loaded-key-index field, irrelevant when b4=1) but never
// sets b7, so it silently authenticates as Key A regardless of the key bytes
// sent - confirmed on hardware via a temporary `mifare rawauth` diagnostic
// (removed now that this is corrected): every `mifare check` sector reported
// Key B == Key A because "Key B" was never actually being requested.
static const uint8_t MIFARE_KEY_A = 0x10;
static const uint8_t MIFARE_KEY_B = 0x90;

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
