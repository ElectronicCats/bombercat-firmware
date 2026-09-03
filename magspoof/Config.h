/**
 * MagSpoof Flash Storage - Config
 *
 * Constants and the two flash-resident POD records for the persistent
 * multi-card MagSpoof store (IMPLEMENTATION_PLAN_MagSpoof_Flash.md, Phase 1).
 *
 * NOTE on approach: the plan's sections 2/9 assumed the arduino-pico core with
 * raw `flash_*` SDK calls and hard-coded sector addresses. This firmware builds
 * against the *mbed_rp2040* core, where the project already persists data with
 * mbed TDBStore over a FlashIAP block device (see core/src/ConfigStore.cpp).
 * TDBStore provides storage-level CRC, wear-leveling and compaction for free,
 * so FlashStorage is layered on it instead of managing sectors by hand. The
 * FLASH_*_ADDR / FLASH_SECTOR_SIZE constants from the plan are intentionally
 * dropped as they have no meaning under TDBStore.
 *
 * The per-record `crc32` fields below are still kept: a cheap, independent
 * integrity check so a truncated/garbled record is detected on read even if the
 * storage layer handed it back.
 *
 * Distributed as-is; no warranty is given.
 */
#ifndef MAGSPOOF_CONFIG_H
#define MAGSPOOF_CONFIG_H

#include <Arduino.h>
#include <stddef.h> // offsetof

// --- Tunables (plan section 9, flash-address macros omitted, see header) ---
#define MAX_CARDS 50
#define CARD_NAME_MAX 31    // usable chars; +1 for the NUL terminator
#define TRACK_MAX_CHARS 126 // matches magset's limit in magspoof.ino
// v3 (IMPLEMENTATION_PLAN_NFC_VISA_MAGSPOOF.md Phase 5) adds nfcEnabled/
// selResMode to CardEntry. FlashStorage::readCard() migrates v2 records
// forward in place on first read (clarifying question 5), so this bump does
// not require a factory reset -- see CardDatabase::begin().
#define CONFIG_VERSION 3

// A single stored card. POD so it can be written to TDBStore as a raw blob.
// name/track1/track2/nfcEnabled/selResMode are contiguous at the top of the
// struct and are the only bytes covered by crc32 (see cardCrc32); keep them
// first and do not reorder.
struct CardEntry {
  char name[CARD_NAME_MAX + 1];     // NUL-terminated identifier ("BBVA", ...)
  char track1[TRACK_MAX_CHARS + 2]; // '%'...'?' + NUL  (128 bytes)
  char track2[TRACK_MAX_CHARS + 2]; // ';'...'?' + NUL  (128 bytes)
  // Per-card SEL_RES preference (IMPLEMENTATION_PLAN_NFC_VISA_MAGSPOOF.md
  // Phase 5). nfcEnabled=false means "no explicit preference": NFC mode
  // switches (resetNfc() in magspoof.ino) fall back to their own default
  // (chip for reader mode, no-chip for MSD emulation) instead of reading
  // selResMode. selResMode is only meaningful when nfcEnabled is true:
  // 0 = no-chip/MSD (SEL_RES 0x13), 1 = chip/EMV (SEL_RES 0x33).
  bool nfcEnabled;
  uint8_t selResMode;
  uint32_t crc32; // integrity over the fields above
  bool valid;     // false = tombstone / unused slot
};

// Store-wide metadata, persisted in its own key. Mirrors the RAM cache the
// later phases build (active card, button mode, card count).
struct ConfigData {
  uint32_t version;    // CONFIG_VERSION; a mismatch triggers a fresh default
  uint8_t count;       // number of valid cards currently stored
  uint8_t activeIndex; // currently selected card slot
  uint8_t buttonTrack; // persisted physical-button mode: 0=alt, 1, 2
  uint8_t reserved;    // padding / future use, keep zeroed
  uint32_t crc32;      // integrity over the fields above
};

// IEEE 802.3 CRC-32 (poly 0xEDB88320) over an arbitrary buffer.
uint32_t magCrc32(const void *data, size_t len);

// Integrity field for each record: computed over every byte that precedes the
// crc32 member, so callers must zero-initialise the struct before filling it
// (trailing bytes past a string's NUL must be deterministic).
inline uint32_t cardCrc32(const CardEntry &c) {
  return magCrc32(&c, offsetof(CardEntry, crc32));
}
inline uint32_t configCrc32(const ConfigData &c) {
  return magCrc32(&c, offsetof(ConfigData, crc32));
}

#endif // MAGSPOOF_CONFIG_H
