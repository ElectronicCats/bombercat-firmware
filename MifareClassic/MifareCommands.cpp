/**
 * BomberCat MifareClassic - Mifare Classic block operations.
 *
 * Phase 1 stubs; ported from ElectronicCats-PN7150's MifareClassic_read_block
 * example in Phase 2.
 *
 * Distributed as-is; no warranty is given.
 */
#include "MifareCommands.h"

bool mifareAuthenticate(NfcController &nfc, uint8_t blockNum, uint8_t keyType,
                        const uint8_t *key) {
  (void)nfc;
  (void)blockNum;
  (void)keyType;
  (void)key;
  return false; // Phase 2
}

bool mifareReadBlock(NfcController &nfc, uint8_t blockNum, uint8_t *buffer,
                     uint8_t *bufferLen) {
  (void)nfc;
  (void)blockNum;
  (void)buffer;
  (void)bufferLen;
  return false; // Phase 2
}

bool mifareWriteBlock(NfcController &nfc, uint8_t blockNum, const uint8_t *data,
                      uint8_t dataLen) {
  (void)nfc;
  (void)blockNum;
  (void)data;
  (void)dataLen;
  return false; // Phase 2
}
