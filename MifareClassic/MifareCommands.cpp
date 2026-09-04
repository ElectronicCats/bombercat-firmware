/**
 * BomberCat MifareClassic - Mifare Classic block operations.
 *
 * Raw NCI command bytes ported from ElectronicCats-PN7150's
 * MifareClassic_read_block/_write_block examples, replayed over
 * NfcController::readerTransceive() (send + double-receive) instead of the
 * library's own readerTagCmd() so these compose with BomberCatControl's
 * poll() loop like every other reader-mode call in this codebase.
 *
 * Distributed as-is; no warranty is given.
 */
#include "MifareCommands.h"

#include "MifareClassic.h"

// PN7150 reader-mode raw command opcodes (see the ElectronicCats-PN7150
// examples this was ported from - not documented in API.md).
static const uint8_t MIFARE_CMD_AUTH = 0x40;
static const uint8_t MIFARE_CMD_TAG_RELAY = 0x10; // prefixes READ/WRITE below
static const uint8_t MIFARE_CMD_READ = 0x30;
static const uint8_t MIFARE_CMD_WRITE = 0xA0;
static const uint8_t MIFARE_STATUS_OK = 0x00;

bool mifareAuthenticate(NfcController &nfc, uint8_t blockNum, uint8_t keyType,
                        const uint8_t *key) {
  uint8_t cmd[9] = {MIFARE_CMD_AUTH,
                    static_cast<uint8_t>(blockNum / MIFARE_BLOCKS_PER_SECTOR),
                    keyType};
  memcpy(&cmd[3], key, 6);

  uint8_t resp[MAX_NCI_FRAME_SIZE];
  uint8_t respLen = 0;
  if (!nfc.readerTransceive(cmd, sizeof(cmd), resp, &respLen)) {
    return false;
  }
  return respLen > 0 && resp[respLen - 1] == MIFARE_STATUS_OK;
}

bool mifareReadBlock(NfcController &nfc, uint8_t blockNum, uint8_t *buffer,
                     uint8_t *bufferLen) {
  uint8_t cmd[3] = {MIFARE_CMD_TAG_RELAY, MIFARE_CMD_READ, blockNum};

  uint8_t resp[MAX_NCI_FRAME_SIZE];
  uint8_t respLen = 0;
  if (!nfc.readerTransceive(cmd, sizeof(cmd), resp, &respLen)) {
    return false;
  }
  // Response layout: resp[0] echo byte, resp[1..len-2] block data,
  // resp[len-1] status (0x00 = OK).
  if (respLen < 2 || resp[respLen - 1] != MIFARE_STATUS_OK) {
    return false;
  }

  uint8_t dataLen = respLen - 2;
  if (dataLen > MIFARE_BLOCK_SIZE) {
    dataLen = MIFARE_BLOCK_SIZE;
  }
  memcpy(buffer, &resp[1], dataLen);
  *bufferLen = dataLen;
  return true;
}

bool mifareWriteBlock(NfcController &nfc, uint8_t blockNum, const uint8_t *data,
                      uint8_t dataLen) {
  if (dataLen != MIFARE_BLOCK_SIZE) {
    return false;
  }

  // PN7160 acks a raw tag-relay write with 0x14; PN7150 acks with 0x00.
  const uint8_t writeAck =
      nfc.raw().getChipModel() == PN7160 ? 0x14 : MIFARE_STATUS_OK;

  uint8_t resp[MAX_NCI_FRAME_SIZE];
  uint8_t respLen = 0;

  uint8_t cmdHeader[3] = {MIFARE_CMD_TAG_RELAY, MIFARE_CMD_WRITE, blockNum};
  if (!nfc.readerTransceive(cmdHeader, sizeof(cmdHeader), resp, &respLen) ||
      respLen == 0 || resp[respLen - 1] != writeAck) {
    return false;
  }

  uint8_t cmdData[1 + MIFARE_BLOCK_SIZE];
  cmdData[0] = MIFARE_CMD_TAG_RELAY;
  memcpy(&cmdData[1], data, MIFARE_BLOCK_SIZE);
  respLen = 0;
  if (!nfc.readerTransceive(cmdData, sizeof(cmdData), resp, &respLen) ||
      respLen == 0 || resp[respLen - 1] != writeAck) {
    return false;
  }
  return true;
}

bool mifareReadSector(NfcController &nfc, uint8_t sectorNum, uint8_t keyType,
                      const uint8_t *key, uint8_t *outData) {
  const uint8_t firstBlock = sectorNum * MIFARE_BLOCKS_PER_SECTOR;
  if (!mifareAuthenticate(nfc, firstBlock, keyType, key)) {
    return false;
  }
  for (uint8_t i = 0; i < MIFARE_BLOCKS_PER_SECTOR; i++) {
    uint8_t blockLen = 0;
    if (!mifareReadBlock(nfc, firstBlock + i, outData + (i * MIFARE_BLOCK_SIZE),
                         &blockLen)) {
      return false;
    }
  }
  return true;
}
