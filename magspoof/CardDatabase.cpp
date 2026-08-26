/**
 * MagSpoof Flash Storage - CardDatabase (implementation)
 *
 * See CardDatabase.h for the design (compact write-through cache mirroring
 * flash).
 *
 * Distributed as-is; no warranty is given.
 */
#include "CardDatabase.h"

#include <string.h>

const char *dbStatusName(DbStatus s) {
  switch (s) {
  case DbStatus::Ok:
    return "ok";
  case DbStatus::ErrFull:
    return "full";
  case DbStatus::ErrNotFound:
    return "not found";
  case DbStatus::ErrExists:
    return "exists";
  case DbStatus::ErrBadName:
    return "bad name";
  case DbStatus::ErrTooLong:
    return "track too long";
  case DbStatus::ErrFlash:
    return "flash error";
  case DbStatus::ErrNotReady:
    return "not ready";
  }
  return "error";
}

// A name must be non-empty, fit the buffer, and carry no space/control chars so
// the CLI's space-separated parser (Phase 3) can round-trip it.
bool CardDatabase::validName(const char *name) {
  if (name == nullptr)
    return false;
  size_t n = strlen(name);
  if (n == 0 || n > CARD_NAME_MAX)
    return false;
  for (size_t i = 0; i < n; i++) {
    unsigned char c = (unsigned char)name[i];
    if (c <= ' ' || c == 0x7F)
      return false;
  }
  return true;
}

bool CardDatabase::begin(const char *defName, const char *defTrack1,
                         const char *defTrack2) {
  if (_ready)
    return true;
  if (!_flash.begin())
    return false;

  ConfigData cfg;
  bool haveCfg = _flash.readConfig(cfg);

  // Compact-load: skip unreadable/tombstoned slots so a corrupt entry just
  // drops out (plan section 6.1) instead of leaving a hole in the cache.
  _count = 0;
  bool hadHole = false;
  for (uint8_t i = 0; i < MAX_CARDS && _count < MAX_CARDS; i++) {
    if (_flash.readCard(i, _cards[_count])) {
      if (i != _count)
        hadHole = true; // a lower slot was empty/corrupt
      _count++;
    }
  }

  _ready = true;

  // First boot (or a wiped/empty store): seed the default card.
  if (!haveCfg || _count == 0)
    return factoryReset(defName, defTrack1, defTrack2);

  _activeIndex = (cfg.activeIndex < _count) ? cfg.activeIndex : 0;
  _buttonTrack = (cfg.buttonTrack <= 2) ? cfg.buttonTrack : 0;

  // Re-persist if we compacted around a hole or the stored count drifted, so
  // flash matches the cache before any mutation relies on the mirror.
  if (hadHole || cfg.count != _count || cfg.activeIndex != _activeIndex) {
    for (uint8_t i = 0; i < _count; i++)
      _flash.writeCard(i, _cards[i]);
    for (uint8_t i = _count; i < MAX_CARDS; i++)
      _flash.eraseCard(i);
    persistConfig();
  }
  return true;
}

int CardDatabase::find(const char *name) const {
  if (name == nullptr)
    return -1;
  for (uint8_t i = 0; i < _count; i++) {
    if (strncmp(_cards[i].name, name, CARD_NAME_MAX + 1) == 0)
      return i;
  }
  return -1;
}

const CardEntry *CardDatabase::get(uint8_t index) const {
  return (index < _count) ? &_cards[index] : nullptr;
}

const CardEntry *CardDatabase::getActive() const {
  return (_count > 0) ? &_cards[_activeIndex] : nullptr;
}

const char *CardDatabase::activeName() const {
  const CardEntry *c = getActive();
  return c ? c->name : "";
}

bool CardDatabase::persistConfig() {
  ConfigData cfg{};
  cfg.version = CONFIG_VERSION;
  cfg.count = _count;
  cfg.activeIndex = _activeIndex;
  cfg.buttonTrack = _buttonTrack;
  return _flash.writeConfig(cfg);
}

DbStatus CardDatabase::add(const char *name, const char *track1,
                           const char *track2) {
  if (!_ready)
    return DbStatus::ErrNotReady;
  if (!validName(name))
    return DbStatus::ErrBadName;
  if (find(name) >= 0)
    return DbStatus::ErrExists;
  if (full())
    return DbStatus::ErrFull;
  if ((track1 && strlen(track1) > TRACK_MAX_CHARS) ||
      (track2 && strlen(track2) > TRACK_MAX_CHARS))
    return DbStatus::ErrTooLong;

  CardEntry &c = _cards[_count];
  memset(&c, 0, sizeof(c));
  strncpy(c.name, name, CARD_NAME_MAX);
  if (track1)
    strncpy(c.track1, track1, TRACK_MAX_CHARS);
  if (track2)
    strncpy(c.track2, track2, TRACK_MAX_CHARS);

  if (!_flash.writeCard(_count, c))
    return DbStatus::ErrFlash;
  _count++;
  if (!persistConfig())
    return DbStatus::ErrFlash;
  return DbStatus::Ok;
}

DbStatus CardDatabase::update(const char *name, const char *track1,
                              const char *track2) {
  if (!_ready)
    return DbStatus::ErrNotReady;
  int idx = find(name);
  if (idx < 0)
    return DbStatus::ErrNotFound;
  if ((track1 && strlen(track1) > TRACK_MAX_CHARS) ||
      (track2 && strlen(track2) > TRACK_MAX_CHARS))
    return DbStatus::ErrTooLong;

  CardEntry &c = _cards[idx];
  if (track1) {
    memset(c.track1, 0, sizeof(c.track1));
    strncpy(c.track1, track1, TRACK_MAX_CHARS);
  }
  if (track2) {
    memset(c.track2, 0, sizeof(c.track2));
    strncpy(c.track2, track2, TRACK_MAX_CHARS);
  }
  if (!_flash.writeCard(idx, c))
    return DbStatus::ErrFlash;
  return DbStatus::Ok;
}

DbStatus CardDatabase::remove(const char *name) {
  if (!_ready)
    return DbStatus::ErrNotReady;
  int idx = find(name);
  if (idx < 0)
    return DbStatus::ErrNotFound;

  // Shift the cache down to keep it compact (this is the compaction step).
  for (uint8_t i = (uint8_t)idx; i + 1 < _count; i++)
    _cards[i] = _cards[i + 1];
  uint8_t oldTail = _count - 1;
  _count--;

  // Fix up the active index for the shift/removal.
  if ((uint8_t)idx < _activeIndex)
    _activeIndex--;
  if (_count == 0)
    _activeIndex = 0;
  else if (_activeIndex >= _count)
    _activeIndex = _count - 1;

  // Rewrite the moved slots and erase the freed tail so flash mirrors the
  // cache.
  for (uint8_t i = (uint8_t)idx; i < _count; i++) {
    if (!_flash.writeCard(i, _cards[i]))
      return DbStatus::ErrFlash;
  }
  _flash.eraseCard(oldTail);

  if (!persistConfig())
    return DbStatus::ErrFlash;
  return DbStatus::Ok;
}

DbStatus CardDatabase::select(const char *name) {
  if (!_ready)
    return DbStatus::ErrNotReady;
  int idx = find(name);
  if (idx < 0)
    return DbStatus::ErrNotFound;
  _activeIndex = (uint8_t)idx;
  if (!persistConfig())
    return DbStatus::ErrFlash;
  return DbStatus::Ok;
}

DbStatus CardDatabase::setButtonTrack(uint8_t mode) {
  if (!_ready)
    return DbStatus::ErrNotReady;
  if (mode > 2)
    return DbStatus::ErrBadName; // reused: caller validates the token first
  _buttonTrack = mode;
  if (!persistConfig())
    return DbStatus::ErrFlash;
  return DbStatus::Ok;
}

bool CardDatabase::factoryReset(const char *defName, const char *defTrack1,
                                const char *defTrack2) {
  if (!_flash.begin())
    return false;
  _flash.wipe();

  _count = 0;
  _activeIndex = 0;
  _buttonTrack = 0;
  _ready = true;

  CardEntry &c = _cards[0];
  memset(&c, 0, sizeof(c));
  strncpy(c.name, defName ? defName : "DEFAULT", CARD_NAME_MAX);
  if (defTrack1)
    strncpy(c.track1, defTrack1, TRACK_MAX_CHARS);
  if (defTrack2)
    strncpy(c.track2, defTrack2, TRACK_MAX_CHARS);

  if (!_flash.writeCard(0, c))
    return false;
  _count = 1;
  return persistConfig();
}
