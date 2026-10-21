#include "MifareResultStore.h"

#include <stdio.h>
#include <string.h>

const char *mifareResultReason(uint8_t status) {
  switch (status) {
  case MIFARE_RESULT_NOKEY:
    return "nokey";
  case MIFARE_RESULT_READFAIL:
    return "readfail";
  case MIFARE_RESULT_REMOVED:
    return "removed";
  default:
    return "";
  }
}

void mifareResultSlotKey(uint8_t slot, char *out, size_t outSize) {
  if (out == nullptr || outSize == 0) {
    return;
  }
  // "mifares0".."mifares7": the same "mifare" prefix the key-store uses, so
  // the records of this device are easy to spot in the store.
  snprintf(out, outSize, "mifares%u", (unsigned)slot);
}

void mifareResultInit(MifareResultRecord &record) {
  memset(&record, 0, sizeof(record));
  record.version = MIFARE_RESULT_VERSION;
}

void mifareResultSetSector(MifareResultRecord &record, uint8_t sector,
                           uint8_t status, char keyType, const uint8_t *data) {
  if (sector >= MIFARE_RESULT_MAX_SECTORS) {
    return;
  }
  record.status[sector] = status;
  record.keyType[sector] = (uint8_t)keyType;
  if (data != nullptr && status == MIFARE_RESULT_READ) {
    memcpy(record.data[sector], data, MIFARE_RESULT_SECTOR_BYTES);
  } else {
    memset(record.data[sector], 0, MIFARE_RESULT_SECTOR_BYTES);
  }
}

MifareResultStore::MifareResultStore() : _count(0), _nextSlot(0), _nextSeq(1) {
  _blob.read = nullptr;
  _blob.write = nullptr;
  _blob.clear = nullptr;
  memset(_meta, 0, sizeof(_meta));
  memset(&_scratch, 0, sizeof(_scratch));
}

void MifareResultStore::indexRecord(uint8_t slot,
                                    const MifareResultRecord &record) {
  // Replace the metadata of that slot, or append it when the slot is new.
  for (uint8_t i = 0; i < _count; i++) {
    if (_meta[i].slot == slot) {
      _meta[i].seq = record.seq;
      _meta[i].sectors = record.sectors;
      _meta[i].read = record.read;
      _meta[i].failed = record.failed;
      _meta[i].tsMs = record.tsMs;
      memcpy(_meta[i].uid, record.uid, sizeof(_meta[i].uid));
      return;
    }
  }
  if (_count >= MIFARE_RESULT_SLOTS) {
    return; // the ring is full: the caller overwrites the oldest slot
  }
  MifareResultMeta &m = _meta[_count];
  m.seq = record.seq;
  m.slot = slot;
  m.sectors = record.sectors;
  m.read = record.read;
  m.failed = record.failed;
  m.tsMs = record.tsMs;
  memcpy(m.uid, record.uid, sizeof(m.uid));
  _count++;
}

void MifareResultStore::sortNewestFirst() {
  // Insertion sort over eight entries: newest (highest seq) first.
  for (uint8_t i = 1; i < _count; i++) {
    const MifareResultMeta key = _meta[i];
    int8_t j = (int8_t)i - 1;
    while (j >= 0 && _meta[j].seq < key.seq) {
      _meta[j + 1] = _meta[j];
      j--;
    }
    _meta[j + 1] = key;
  }
}

void MifareResultStore::recomputeNext() {
  sortNewestFirst();

  // The next sequence number is one past the highest one stored.
  _nextSeq = 1;
  for (uint8_t i = 0; i < _count; i++) {
    if (_meta[i].seq >= _nextSeq) {
      _nextSeq = _meta[i].seq + 1;
    }
  }

  // The next slot is a free one; when the ring is full it is the slot that
  // holds the OLDEST result, so the newest ones are always kept.
  bool used[MIFARE_RESULT_SLOTS] = {false};
  for (uint8_t i = 0; i < _count; i++) {
    if (_meta[i].slot < MIFARE_RESULT_SLOTS) {
      used[_meta[i].slot] = true;
    }
  }
  for (uint8_t slot = 0; slot < MIFARE_RESULT_SLOTS; slot++) {
    if (!used[slot]) {
      _nextSlot = slot;
      return;
    }
  }
  _nextSlot = (_count > 0) ? _meta[_count - 1].slot : 0;
}

uint8_t MifareResultStore::scan() {
  _count = 0;
  _nextSlot = 0;
  _nextSeq = 1;
  if (_blob.read == nullptr) {
    return 0;
  }

  for (uint8_t slot = 0; slot < MIFARE_RESULT_SLOTS; slot++) {
    char key[MIFARE_RESULT_KEY_MAX];
    mifareResultSlotKey(slot, key, sizeof(key));
    if (!_blob.read(key, &_scratch, sizeof(_scratch))) {
      continue; // empty slot (or a flash error: treat it as empty)
    }
    if (_scratch.version != MIFARE_RESULT_VERSION) {
      continue; // a record of another layout: not ours to read
    }
    if (_scratch.sectors > MIFARE_RESULT_MAX_SECTORS) {
      continue; // a corrupted record: not ours to read either
    }
    indexRecord(slot, _scratch);
  }

  recomputeNext();
  return _count;
}

uint8_t MifareResultStore::list(MifareResultMeta *out, uint8_t max) const {
  if (out == nullptr) {
    return 0;
  }
  uint8_t n = 0;
  for (uint8_t i = 0; i < _count && n < max; i++) {
    out[n++] = _meta[i];
  }
  return n;
}

bool MifareResultStore::store(MifareResultRecord &record) {
  if (_blob.write == nullptr) {
    return false;
  }
  record.version = MIFARE_RESULT_VERSION;
  record.slot = _nextSlot;
  record.seq = _nextSeq;

  char key[MIFARE_RESULT_KEY_MAX];
  mifareResultSlotKey(_nextSlot, key, sizeof(key));
  if (!_blob.write(key, &record, sizeof(record))) {
    return false; // the flash write failed: the ring is left as it was
  }

  indexRecord(_nextSlot, record);
  recomputeNext();
  return true;
}

const MifareResultRecord *MifareResultStore::load(uint8_t index) {
  if (_blob.read == nullptr || index >= _count) {
    return nullptr;
  }
  const uint8_t slot = _meta[index].slot;
  char key[MIFARE_RESULT_KEY_MAX];
  mifareResultSlotKey(slot, key, sizeof(key));
  if (!_blob.read(key, &_scratch, sizeof(_scratch))) {
    return nullptr;
  }
  if (_scratch.version != MIFARE_RESULT_VERSION) {
    return nullptr;
  }
  return &_scratch;
}

bool MifareResultStore::clear() {
  if (_blob.clear == nullptr) {
    return false;
  }
  bool ok = true;
  for (uint8_t slot = 0; slot < MIFARE_RESULT_SLOTS; slot++) {
    char key[MIFARE_RESULT_KEY_MAX];
    mifareResultSlotKey(slot, key, sizeof(key));
    if (!_blob.clear(key)) {
      ok = false;
    }
  }
  _count = 0;
  _nextSlot = 0;
  _nextSeq = 1;
  return ok;
}
