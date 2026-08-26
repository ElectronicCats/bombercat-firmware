/**
 * MagSpoof Flash Storage - FlashStorage (implementation)
 *
 * TDBStore-backed persistence, mirroring core/src/ConfigStore.cpp. See
 * FlashStorage.h for the rationale (mbed_rp2040, not raw flash_*).
 *
 * Distributed as-is; no warranty is given.
 */
#include "FlashStorage.h"

#include <stdio.h> // snprintf

#include <FlashIAPBlockDevice.h>
#include <TDBStore.h>

#include <FlashIAPLimits.h> // from BomberCatCore (core/src)

using namespace mbed;

namespace {
// TDBStore key holding the ConfigData blob.
const char kConfigKey[] = "mag_cfg";
} // namespace

FlashStorage::~FlashStorage() {
  if (_store != nullptr) {
    _store->deinit();
    delete _store;
    _store = nullptr;
  }
  if (_bd != nullptr) {
    _bd->deinit();
    delete _bd;
    _bd = nullptr;
  }
}

void FlashStorage::cardKey(uint8_t index, char *keyOut) {
  // "mag_cNN" -> 7 chars + NUL. index is always < MAX_CARDS (< 100).
  snprintf(keyOut, 8, "mag_c%02u", (unsigned)index);
}

bool FlashStorage::begin() {
  if (_ready)
    return true;

  auto limits = getFlashIAPLimits();
  if (limits.available_size == 0)
    return false;

  _bd = new FlashIAPBlockDevice(limits.start_address, limits.available_size);
  if (_bd == nullptr)
    return false;
  _bd->init();

  _store = new TDBStore(_bd);
  if (_store == nullptr)
    return false;
  if (_store->init() != MBED_SUCCESS)
    return false;

  _ready = true;
  return true;
}

ConfigData FlashStorage::defaultConfig() {
  ConfigData cfg{}; // zero-initialised
  cfg.version = CONFIG_VERSION;
  cfg.count = 0;
  cfg.activeIndex = 0;
  cfg.buttonTrack = 0; // alternating, matches the RAM default in magspoof.ino
  cfg.reserved = 0;
  cfg.crc32 = configCrc32(cfg);
  return cfg;
}

bool FlashStorage::readConfig(ConfigData &out) {
  out = defaultConfig();
  if (!_ready)
    return false;

  ConfigData tmp{};
  size_t actual = 0;
  int rc = _store->get(kConfigKey, &tmp, sizeof(tmp), &actual);
  if (rc != MBED_SUCCESS || actual != sizeof(tmp))
    return false; // missing or a different (older) layout
  if (tmp.version != CONFIG_VERSION)
    return false; // migration is a later concern; keep defaults for now
  if (tmp.crc32 != configCrc32(tmp))
    return false; // corrupt record

  out = tmp;
  return true;
}

bool FlashStorage::writeConfig(const ConfigData &cfg) {
  if (!_ready)
    return false;
  ConfigData rec = cfg;
  rec.version = CONFIG_VERSION;
  rec.crc32 = configCrc32(rec);
  return _store->set(kConfigKey, &rec, sizeof(rec), 0) == MBED_SUCCESS;
}

bool FlashStorage::readCard(uint8_t index, CardEntry &out) {
  if (!_ready || index >= MAX_CARDS)
    return false;

  char key[8];
  cardKey(index, key);

  CardEntry tmp{};
  size_t actual = 0;
  int rc = _store->get(key, &tmp, sizeof(tmp), &actual);
  if (rc != MBED_SUCCESS || actual != sizeof(tmp))
    return false; // absent or wrong layout
  if (!tmp.valid)
    return false; // tombstone
  if (tmp.crc32 != cardCrc32(tmp))
    return false; // corrupt

  out = tmp;
  return true;
}

bool FlashStorage::writeCard(uint8_t index, const CardEntry &card) {
  if (!_ready || index >= MAX_CARDS)
    return false;

  char key[8];
  cardKey(index, key);

  CardEntry rec = card;
  rec.valid = true;
  rec.crc32 = cardCrc32(rec);
  return _store->set(key, &rec, sizeof(rec), 0) == MBED_SUCCESS;
}

bool FlashStorage::eraseCard(uint8_t index) {
  if (!_ready || index >= MAX_CARDS)
    return false;

  char key[8];
  cardKey(index, key);

  int rc = _store->remove(key);
  return rc == MBED_SUCCESS || rc == MBED_ERROR_ITEM_NOT_FOUND;
}

uint8_t FlashStorage::getCardCount() {
  if (!_ready)
    return 0;

  uint8_t n = 0;
  CardEntry tmp;
  for (uint8_t i = 0; i < MAX_CARDS; i++) {
    if (readCard(i, tmp))
      n++;
  }
  return n;
}

bool FlashStorage::wipe() {
  if (!_ready)
    return false;

  bool ok = true;
  int rc = _store->remove(kConfigKey);
  ok &= (rc == MBED_SUCCESS || rc == MBED_ERROR_ITEM_NOT_FOUND);
  for (uint8_t i = 0; i < MAX_CARDS; i++)
    ok &= eraseCard(i);
  return ok;
}
