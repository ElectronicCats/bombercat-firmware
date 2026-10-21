/**
 * BomberCat MifareClassic - the standalone result store (Fase 4, tarea 4.6).
 *
 * The standalone workflow (Fase 4, tarea 4.4) reads a card with no PC
 * attached and emits the result over the serial port - where nobody is
 * listening when the board is in the field. This module keeps those results
 * in the board's own flash, so the operator collects them LATER, over USB,
 * and turns them into the very same canonical dump (and the very same honest
 * gap report) the connected workflow produces.
 *
 * WHY FLASH AND NOT THE RADIO: the on-board ESP32 coprocessor can reach a
 * broker (MagSpoofMqtt already does it over WiFiNINA), but a standalone run
 * would then depend on a network that may not be there, on credentials the
 * MifareClassic firmware does not hold, and on a power budget that has NOT
 * been measured (the F1 fuse is 0.5 A and task 4.5 is still open). The flash
 * path needs none of that, and it closes the gap the plan cares about: the
 * result - with its holes - is retrievable later, offline, and can be run
 * through the very same `mifare analyze` engine.
 *
 * Storage: a RING of slots on the SAME ConfigStore instance the sketch
 * already owns ("mifares0".."mifares7"), each slot a fixed-size POD record
 * written verbatim as a blob. Every stored result is ONE flash write, and
 * the OLDEST result is the one that gets overwritten.
 *
 * A note on wear, because the intuition is wrong here: mbed's TDBStore
 * appends every write to the same area and rewrites the WHOLE area when it
 * fills up. So the ring does NOT multiply the flash's life by eight - it
 * multiplies the HISTORY by eight. The number of erases stays what it is
 * (one area erase per ~450 stored results, orders of magnitude below the
 * flash's 100k erase cycles), and the ring's real value is that the operator
 * still has the last N cards, not that the flash lasts longer.
 *
 * Dependency-free on purpose (no Arduino.h): the parity harness compiles
 * this module outside the Arduino toolchain, and the flash is reached
 * through the callbacks below (ConfigStore's blob calls in the firmware, a
 * map in the native test).
 *
 * Distributed as-is; no warranty is given.
 */
#ifndef MIFARERESULTSTORE_H
#define MIFARERESULTSTORE_H

#include <stddef.h>
#include <stdint.h>

// Layout version of the persisted record. It is bumped whenever the layout
// changes, so a record written by another layout is REJECTED (the slot reads
// as empty) instead of being misread.
static const uint8_t MIFARE_RESULT_VERSION = 1;

// The card sizes this firmware sweeps: 16 sectors (1K) up to 32 (2K).
static const uint8_t MIFARE_RESULT_MAX_SECTORS = 32;

// A sector is 4 blocks of 16 bytes.
static const uint8_t MIFARE_RESULT_SECTOR_BYTES = 64;

// How many results the ring keeps. When it is full, the oldest result is
// the one that gets overwritten.
static const uint8_t MIFARE_RESULT_SLOTS = 8;

// The TDBStore key of a slot ("mifares0".."mifares7"), plus room for the
// terminating NUL.
static const uint8_t MIFARE_RESULT_KEY_MAX = 16;

// The outcome of one sector, as stored. The holes are stored WITH their
// reason: a sector that was never opened is never reported as read (the
// plan's honest-gap rule, transversal restriction #6).
enum MifareResultStatus {
  MIFARE_RESULT_MISSING = 0,  // not part of this card
  MIFARE_RESULT_READ = 1,     // read
  MIFARE_RESULT_NOKEY = 2,    // no key recovered -> hole
  MIFARE_RESULT_READFAIL = 3, // the key was there, the read failed
  MIFARE_RESULT_REMOVED = 4,  // the card left the field mid-dump
};

// The persisted record: POD, fixed size, written to flash verbatim. The
// recovered keys are already substituted into the trailer bytes (the card
// never reads Key A back), so the stored bytes are the very bytes the
// serial dump emitted.
struct MifareResultRecord {
  uint8_t version; // MIFARE_RESULT_VERSION
  uint8_t slot;    // the ring slot this record occupies
  uint8_t sectors; // how many sectors the card has (16 for a 1K card)
  uint8_t flags;   // reserved
  uint32_t seq;    // monotonic counter: which result this is
  uint32_t tsMs;   // when the dump was taken (millis since boot)
  uint8_t read;    // sectors read
  uint8_t failed;  // sectors failed (holes included)
  // The card's UID in hex, NUL-terminated. 16 chars + NUL: a 7-byte UID is
  // 14 hex chars, and a truncated UID would be a WRONG one.
  char uid[17];
  uint8_t status[MIFARE_RESULT_MAX_SECTORS];
  uint8_t keyType[MIFARE_RESULT_MAX_SECTORS]; // 'A' | 'B' | '-'
  uint8_t data[MIFARE_RESULT_MAX_SECTORS][MIFARE_RESULT_SECTOR_BYTES];
};

// The metadata of one stored result: what the listing shows without having
// to read the whole record.
struct MifareResultMeta {
  uint32_t seq;
  uint8_t slot;
  uint8_t sectors;
  uint8_t read;
  uint8_t failed;
  uint32_t tsMs;
  char uid[17];
};

// The blob store the ring lives in. The callbacks ARE the flash: in the
// firmware they are ConfigStore's loadBlob/saveBlob/clearBlob; in the native
// test they are a map.
struct MifareResultBlob {
  bool (*read)(const char *key, void *buf, size_t size);
  bool (*write)(const char *key, const void *buf, size_t size);
  bool (*clear)(const char *key);
};

// The reason token a hole carries on the wire ("nokey", "readfail",
// "removed"), or "" for a sector that was read.
const char *mifareResultReason(uint8_t status);

// The TDBStore key of a slot.
void mifareResultSlotKey(uint8_t slot, char *out, size_t outSize);

// Reset a record: a valid, empty result (no sectors, no data). The padding
// bytes are zeroed too, so nothing of the RAM ends up in the flash.
void mifareResultInit(MifareResultRecord &record);

// Record one sector's outcome. `data` is the sector's 64 bytes (already
// with the recovered keys substituted into the trailer); it is ignored for
// a hole.
void mifareResultSetSector(MifareResultRecord &record, uint8_t sector,
                           uint8_t status, char keyType, const uint8_t *data);

// The ring of stored results.
//
// The store keeps the metadata of the ring in RAM (a few hundred bytes) and
// owns ONE record-sized buffer, used to read the slots. The caller keeps the
// record it builds in its own buffer, so building a result and scanning the
// ring never fight over the same bytes.
class MifareResultStore {
public:
  MifareResultStore();

  // The flash the ring lives in.
  void setBlob(const MifareResultBlob &blob) { _blob = blob; }
  bool hasBlob() const { return _blob.read != nullptr; }

  // Read every slot and index what is there, newest first. Cheap enough to
  // do on demand: the ring is eight records.
  uint8_t scan();

  // The indexed results, newest first. Returns how many were written.
  uint8_t list(MifareResultMeta *out, uint8_t max) const;

  // How many results the ring holds.
  uint8_t count() const { return _count; }

  // Store a result: ONE flash write, into the slot that holds the OLDEST
  // result (or the first free one). `record.seq` and `record.slot` are set
  // by this call. False when the write failed.
  bool store(MifareResultRecord &record);

  // The result at listing index `index` (0 = the newest), or nullptr when
  // there is no such result. The record lives in the store's own buffer
  // until the next call.
  const MifareResultRecord *load(uint8_t index);

  // Erase every slot. False when a slot could not be erased.
  bool clear();

  // The slot the next `store` will write to, and the sequence number it
  // will carry (both for the log and for the tests).
  uint8_t nextSlot() const { return _nextSlot; }
  uint32_t nextSeq() const { return _nextSeq; }

private:
  void indexRecord(uint8_t slot, const MifareResultRecord &record);
  void sortNewestFirst();
  void recomputeNext();

  MifareResultBlob _blob;
  MifareResultMeta _meta[MIFARE_RESULT_SLOTS];
  uint8_t _count;
  uint8_t _nextSlot;
  uint32_t _nextSeq;
  MifareResultRecord _scratch;
};

#endif // MIFARERESULTSTORE_H
