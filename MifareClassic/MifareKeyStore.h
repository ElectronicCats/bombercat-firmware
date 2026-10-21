/**
 * BomberCat MifareClassic - persistent Mifare Classic key-store.
 *
 * Fase 3 of the "Plan de Implementacion Firmware MIFARE": a small, bounded
 * store of user-curated Mifare Classic keys kept in QSPI, so keys that are
 * NOT in the embedded default dictionary survive a reset and feed the
 * on-device dictionary sweep (`mifare check` and the on-detection auto-probe)
 * without recompiling the firmware.
 *
 * Storage: one TDBStore record ("mifarekeys") on the SAME ConfigStore
 * instance the sketch already owns. Mounting a second FlashIAPBlockDevice
 * over the same flash region would collide, so the sketch reuses this
 * wrapper (see core/src/ConfigStore.h - "Generic key/value blobs").
 *
 * The record is a fixed-size POD, written as a raw byte blob. `version` is
 * bumped whenever the layout changes, so an old record is rejected (and the
 * store falls back to empty) instead of being misread.
 *
 * Distributed as-is; no warranty is given.
 */
#ifndef MIFAREKEYSTORE_H
#define MIFAREKEYSTORE_H

#include <Arduino.h>
#include <ConfigStore.h>

// Maximum number of persisted keys. 32 entries = 192 B of key data, which
// comfortably fits the sweep's confirmed-key reuse pool (the store and the
// per-sweep reuse share one pool, see MIFARE_CHECK_KNOWN_MAX in
// MifareClassic.ino) and costs a single, tiny flash record.
static const uint8_t MIFARE_KEYSTORE_MAX = 32;

// Layout version of the persisted record.
static const uint8_t MIFARE_KEYSTORE_VERSION = 1;

// Persisted flags.
static const uint8_t MIFARE_KEYSTORE_FLAG_AUTOSTORE = 0x01; // auto-persist
                                                            // recovered custom
                                                            // keys
// Standalone mode: on detection the firmware runs the whole field workflow by
// itself - sweep, dump the cracked sectors, emit everything over serial - with
// no PC attached (Fase 4, tarea 4.4). The flag lives in the same record
// because that record is the device's persisted MIFARE settings.
static const uint8_t MIFARE_KEYSTORE_FLAG_STANDALONE = 0x02;

// The persisted record. POD, fixed size: it is written to flash verbatim.
struct MifareKeyStore {
  uint8_t version;                      // layout version
  uint8_t count;                        // keys in use (<= MAX)
  uint8_t flags;                        // MIFARE_KEYSTORE_FLAG_*
  uint8_t keys[MIFARE_KEYSTORE_MAX][6]; // the keys themselves
};

// Reset `store` to an empty, valid record (no keys, no flags).
void mifareKeyStoreInit(MifareKeyStore &store);

// Index of `key` in `store`, or -1 when it is not stored.
int mifareKeyStoreIndexOf(const MifareKeyStore &store, const uint8_t *key);

// Append `key` to `store`. Returns false when the store is full or the key
// is already stored (the caller reports the difference).
bool mifareKeyStoreAdd(MifareKeyStore &store, const uint8_t *key);

// Drop the key at `index` (the remaining keys keep their relative order).
// Returns false when `index` is out of range.
bool mifareKeyStoreRemoveAt(MifareKeyStore &store, uint8_t index);

// Drop every stored key, keeping the flags.
void mifareKeyStoreClearKeys(MifareKeyStore &store);

// Load the persisted store into `out`. On failure (no record, wrong layout
// version, flash error) `out` is reset to an empty store and false is
// returned.
bool mifareKeyStoreLoad(ConfigStore &config, MifareKeyStore &out);

// Persist `store`. Returns true on success.
bool mifareKeyStoreSave(ConfigStore &config, const MifareKeyStore &store);

#endif // MIFAREKEYSTORE_H
