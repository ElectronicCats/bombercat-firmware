#include "ConfigStore.h"

#include <FlashIAPBlockDevice.h>
#include <TDBStore.h>

#include "FlashIAPLimits.h"

using namespace mbed;

namespace {
// TDBStore key holding the RelayConfig blob.
const char kRelayKey[] = "relaycfg";
} // namespace

ConfigStore::~ConfigStore() {
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

bool ConfigStore::begin() {
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

RelayConfig ConfigStore::defaults() {
  RelayConfig cfg{}; // zero-initialised: empty strings
  cfg.port = NFCGATE_DEFAULT_PORT;
  cfg.session = 1;
  cfg.setRole(RelayRole::READER);
  return cfg;
}

bool ConfigStore::load(RelayConfig &out) {
  out = defaults();
  if (!_ready)
    return false;

  TDBStore::info_t info;
  if (_store->get_info(kRelayKey, &info) != MBED_SUCCESS)
    return false;

  RelayConfig tmp{};
  size_t actual = 0;
  int rc = _store->get(kRelayKey, &tmp, sizeof(tmp), &actual);
  if (rc != MBED_SUCCESS || actual != sizeof(tmp)) {
    // Missing or a record of a different (older) layout: fall back to defaults.
    return false;
  }

  out = tmp;
  return true;
}

bool ConfigStore::save(const RelayConfig &cfg) {
  if (!_ready)
    return false;
  return _store->set(kRelayKey, &cfg, sizeof(cfg), 0) == MBED_SUCCESS;
}

bool ConfigStore::clear() {
  if (!_ready)
    return false;
  int rc = _store->remove(kRelayKey);
  return rc == MBED_SUCCESS || rc == MBED_ERROR_ITEM_NOT_FOUND;
}

bool ConfigStore::loadBlob(const char *key, void *buf, size_t size) {
  if (!_ready || key == nullptr || buf == nullptr || size == 0)
    return false;

  size_t actual = 0;
  int rc = _store->get(key, buf, size, &actual);
  if (rc != MBED_SUCCESS || actual != size) {
    // Missing, or a record written with a different layout: the caller
    // falls back to its own defaults instead of reading garbage.
    return false;
  }
  return true;
}

bool ConfigStore::saveBlob(const char *key, const void *buf, size_t size) {
  if (!_ready || key == nullptr || buf == nullptr || size == 0)
    return false;
  return _store->set(key, buf, size, 0) == MBED_SUCCESS;
}

bool ConfigStore::hasBlob(const char *key) {
  if (!_ready || key == nullptr)
    return false;
  TDBStore::info_t info;
  return _store->get_info(key, &info) == MBED_SUCCESS;
}

bool ConfigStore::clearBlob(const char *key) {
  if (!_ready || key == nullptr)
    return false;
  int rc = _store->remove(key);
  return rc == MBED_SUCCESS || rc == MBED_ERROR_ITEM_NOT_FOUND;
}
