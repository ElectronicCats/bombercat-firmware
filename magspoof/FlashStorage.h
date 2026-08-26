/**
 * MagSpoof Flash Storage - FlashStorage
 *
 * Persistence layer for the multi-card MagSpoof store
 * (IMPLEMENTATION_PLAN_MagSpoof_Flash.md, Phase 1). It is a thin wrapper over
 * mbed TDBStore on a FlashIAP block device, the same mechanism ConfigStore uses
 * in core/src. TDBStore already gives us wear-leveling (log-structured writes),
 * storage-level CRC and compaction, so this class only maps the plan's
 * config/card operations onto TDBStore keys and adds a per-record CRC check.
 *
 * Keys:  "mag_cfg"          -> ConfigData
 *        "mag_c00".."mag_c49" -> CardEntry for each slot
 *
 * mbed_rp2040 core only (TDBStore / FlashIAPBlockDevice).
 *
 * Distributed as-is; no warranty is given.
 */
#ifndef MAGSPOOF_FLASHSTORAGE_H
#define MAGSPOOF_FLASHSTORAGE_H

#include <Arduino.h>

#include "Config.h"

// Forward declarations so this header does not drag the mbed flash stack into
// every translation unit that only needs the FlashStorage type.
class FlashIAPBlockDevice;
namespace mbed {
class TDBStore;
} // namespace mbed

class FlashStorage {
public:
  FlashStorage() = default;
  ~FlashStorage();

  // Initialise FlashIAP + TDBStore. Returns true on success. Idempotent: extra
  // calls are no-ops returning true.
  bool begin();

  // --- Config record ---------------------------------------------------------
  // Load the store-wide config. On a missing/corrupt/old-version record, fills
  // `out` with defaultConfig() and returns false so callers always have a
  // usable value.
  bool readConfig(ConfigData &out);
  // Persist config. Stamps version + crc32 from a copy, so the caller need not
  // fill those in.
  bool writeConfig(const ConfigData &cfg);

  // --- Card records ----------------------------------------------------------
  // Read slot `index`. Returns false if absent, the wrong size, the crc32 does
  // not match, or the entry is a tombstone (valid == false).
  bool readCard(uint8_t index, CardEntry &out);
  // Write slot `index`. Stamps crc32 and valid=true from a copy.
  bool writeCard(uint8_t index, const CardEntry &card);
  // Remove slot `index`. Returns true if it was deleted or already absent.
  bool eraseCard(uint8_t index);

  // Number of slots [0, MAX_CARDS) that currently hold a valid card. Scans the
  // store, so it is authoritative rather than trusting ConfigData::count.
  uint8_t getCardCount();

  // Erase every MagSpoof key (config + all card slots). Factory-reset helper
  // for later phases. Returns true if the store ended up empty.
  bool wipe();

  // Zero cards, active index 0, alternating button mode, current version.
  static ConfigData defaultConfig();

private:
  // Fill `keyOut` (>= 8 bytes) with the TDBStore key for a card slot.
  static void cardKey(uint8_t index, char *keyOut);

  bool _ready = false;
  FlashIAPBlockDevice *_bd = nullptr;
  mbed::TDBStore *_store = nullptr;
};

#endif // MAGSPOOF_FLASHSTORAGE_H
