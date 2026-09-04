/**
 * BomberCat MifareClassic - Mifare Classic block operations.
 *
 * Declarations for the auth/read/write primitives built on top of
 * NfcController::readerTransceive(). Phase 1 ships these as stubs (always
 * returning false) so the firmware skeleton compiles and the REPL command
 * dispatch (Phase 3) has real call sites to wire up; the actual raw-command
 * logic lands in Phase 2 (see MIFARE_CLASSIC_PLAN.md).
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

// Write `dataLen` bytes (<=16) to one block. Requires a prior successful
// mifareAuthenticate() on the same sector.
bool mifareWriteBlock(NfcController &nfc, uint8_t blockNum, const uint8_t *data,
                      uint8_t dataLen);

#endif // MIFARECOMMANDS_H
