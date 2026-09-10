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
//
// A FAILED authentication (wrong key) leaves the MIFARE card HALTed and
// deselected, so the very next command also fails until the card is
// re-selected. Callers that try more than one key in a row (the auto-probe,
// and the host-driven `mifare check` dictionary sweep) MUST call
// mifareReselect() after a failure before the next attempt, or only the first
// key is ever really tested. See mifareReselect() and
// CLI_IMPROVEMENTS_MifareCheck.md §4.
bool mifareAuthenticate(NfcController &nfc, uint8_t blockNum, uint8_t keyType,
                        const uint8_t *key);

// Recover the reader link after a FAILED mifareAuthenticate(): re-select the
// still-present (but HALTed) card so the next attempt starts from a clean,
// selected state. Returns true if a card was re-selected within `timeoutMs`,
// false if none is in the field any more. See the .cpp for the hardware note
// on why this uses the full reader re-arm.
bool mifareReselect(NfcController &nfc, uint16_t timeoutMs = 500);

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
//
// If `authOk` is non-null, it is always set before returning: true once
// mifareAuthenticate() succeeds, even if a later block read then fails. That
// lets the caller tell "wrong key" (authOk left false) apart from "key was
// fine, but a block read was denied" (authOk true, return false) — the
// latter means the sector's access bits don't allow reading with this key
// type, not that the key itself is wrong.
bool mifareReadSector(NfcController &nfc, uint8_t sectorNum, uint8_t keyType,
                      const uint8_t *key, uint8_t *outData,
                      bool *authOk = nullptr);

#endif // MIFARECOMMANDS_H
