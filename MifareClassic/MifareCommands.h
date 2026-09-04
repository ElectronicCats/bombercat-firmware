/**
 * BomberCat MifareClassic - Mifare Classic block operations.
 *
 * Auth/read/write/sector primitives built on top of
 * NfcController::readerTransceive(), using the PN7150's raw reader-mode
 * command bytes ported from ElectronicCats-PN7150's
 * MifareClassic_read_block/_write_block examples (see MIFARE_CLASSIC_PLAN.md
 * Phase 2). Callers are responsible for the card session already being
 * selected (a tag detected via NfcController::waitForTag()).
 *
 * Distributed as-is; no warranty is given.
 */
#ifndef MIFARECOMMANDS_H
#define MIFARECOMMANDS_H

#include <Arduino.h>
#include <NfcController.h>

// Authenticate `blockNum`'s sector with `key` (6 bytes) as Key A/B
// (MIFARE_KEY_A / MIFARE_KEY_B from MifareClassic.h). Must be called before
// mifareReadBlock/mifareWriteBlock on any block in that sector.
bool mifareAuthenticate(NfcController &nfc, uint8_t blockNum, uint8_t keyType,
                        const uint8_t *key);

// Read one 16-byte block into `buffer` (`bufferLen` set to the bytes
// written). Requires a prior successful mifareAuthenticate() on the same
// sector.
bool mifareReadBlock(NfcController &nfc, uint8_t blockNum, uint8_t *buffer,
                     uint8_t *bufferLen);

// Write exactly MIFARE_BLOCK_SIZE (16) bytes to one block - the raw MIFARE
// WRITE command has no partial-block form. Requires a prior successful
// mifareAuthenticate() on the same sector. Returns false if dataLen != 16.
bool mifareWriteBlock(NfcController &nfc, uint8_t blockNum, const uint8_t *data,
                      uint8_t dataLen);

// Authenticate and read all MIFARE_BLOCKS_PER_SECTOR (4) blocks of
// `sectorNum` into `outData` (caller-provided buffer of at least
// MIFARE_BLOCKS_PER_SECTOR * MIFARE_BLOCK_SIZE = 64 bytes).
bool mifareReadSector(NfcController &nfc, uint8_t sectorNum, uint8_t keyType,
                      const uint8_t *key, uint8_t *outData);

#endif // MIFARECOMMANDS_H
