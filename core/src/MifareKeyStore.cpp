#include "MifareKeyStore.h"

#include <string.h>

namespace {
// TDBStore key holding the Mifare key-store blob.
const char kMifareKeysKey[] = "mifarekeys";
} // namespace

void mifareKeyStoreInit(MifareKeyStore &store) {
  store.version = MIFARE_KEYSTORE_VERSION;
  store.count = 0;
  store.flags = 0;
  memset(store.keys, 0, sizeof(store.keys));
}

int mifareKeyStoreIndexOf(const MifareKeyStore &store, const uint8_t *key) {
  if (key == nullptr)
    return -1;
  for (uint8_t i = 0; i < store.count && i < MIFARE_KEYSTORE_MAX; i++) {
    if (memcmp(store.keys[i], key, 6) == 0)
      return (int)i;
  }
  return -1;
}

bool mifareKeyStoreAdd(MifareKeyStore &store, const uint8_t *key) {
  if (key == nullptr || store.count >= MIFARE_KEYSTORE_MAX)
    return false;
  if (mifareKeyStoreIndexOf(store, key) >= 0)
    return false; // already stored
  memcpy(store.keys[store.count], key, 6);
  store.count++;
  return true;
}

bool mifareKeyStoreRemoveAt(MifareKeyStore &store, uint8_t index) {
  if (index >= store.count)
    return false;
  // Keep the remaining keys in order: shift the tail one slot down.
  for (uint8_t i = index; i + 1 < store.count; i++) {
    memcpy(store.keys[i], store.keys[i + 1], 6);
  }
  store.count--;
  memset(store.keys[store.count], 0, 6);
  return true;
}

void mifareKeyStoreClearKeys(MifareKeyStore &store) {
  store.count = 0;
  memset(store.keys, 0, sizeof(store.keys));
}

bool mifareKeyStoreLoad(ConfigStore &config, MifareKeyStore &out) {
  mifareKeyStoreInit(out);
  if (!config.loadBlob(kMifareKeysKey, &out, sizeof(out))) {
    // A failed read may have written part of a differently-sized record
    // into `out`; start from a clean, empty store.
    mifareKeyStoreInit(out);
    return false;
  }
  if (out.version != MIFARE_KEYSTORE_VERSION ||
      out.count > MIFARE_KEYSTORE_MAX) {
    // A record from another layout (or a corrupted count): start clean
    // instead of handing the sweep keys it cannot trust.
    mifareKeyStoreInit(out);
    return false;
  }
  return true;
}

bool mifareKeyStoreSave(ConfigStore &config, const MifareKeyStore &store) {
  return config.saveBlob(kMifareKeysKey, &store, sizeof(store));
}
