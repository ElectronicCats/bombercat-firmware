/**
 * MagSpoof Flash Storage - CardDatabase
 *
 * Multi-card database with an in-RAM cache backed by FlashStorage
 * (IMPLEMENTATION_PLAN_MagSpoof_Flash.md, Phase 2). It owns the runtime cache
 * from plan section 1.3 (embedded as members rather than a nested struct) and
 * implements name-based CRUD, boot loading, compaction and persistence of the
 * active-card index + button mode.
 *
 * Invariant: the cache is always *compact* — slots [0, count) hold valid cards
 * and flash slot i mirrors _cards[i]; slots >= count are erased. Every mutation
 * writes through to flash immediately (power-loss safe) and keeps the mirror,
 * so deletion is its own compaction: later cards shift down and the freed tail
 * slot is erased.
 *
 * Track *content* validation (leading '%'/';', trailing '?', F2F charset) is
 * intentionally left to the CLI layer (Phase 3); this class validates the name
 * and enforces capacity/buffer limits only.
 *
 * Distributed as-is; no warranty is given.
 */
#ifndef MAGSPOOF_CARDDATABASE_H
#define MAGSPOOF_CARDDATABASE_H

#include <Arduino.h>

#include "Config.h"
#include "FlashStorage.h"

// Result of a database operation. name() gives a stable lowercase slug suitable
// for a "-ERR <slug>" CLI reply.
enum class DbStatus : uint8_t {
  Ok = 0,
  ErrFull,     // no free slot (count == MAX_CARDS)
  ErrNotFound, // no card with that name
  ErrExists,   // a card with that name already exists
  ErrBadName,  // empty, too long, or contains space/control chars
  ErrTooLong,  // a track exceeds TRACK_MAX_CHARS
  ErrFlash,    // underlying flash write failed
  ErrNotReady, // begin() has not succeeded
};

const char *dbStatusName(DbStatus s);

class CardDatabase {
public:
  CardDatabase() = default;

  // Initialise flash and load the cache. On first boot (no saved config or an
  // empty store) seeds a single card from the supplied defaults and makes it
  // active — the section 10 migration path. Returns true on success.
  bool begin(const char *defName, const char *defTrack1, const char *defTrack2);

  bool ready() const { return _ready; }

  // --- Queries ---
  uint8_t count() const { return _count; }
  static constexpr uint8_t capacity() { return MAX_CARDS; }
  bool full() const { return _count >= MAX_CARDS; }

  // Cache index of `name`, or -1 if absent.
  int find(const char *name) const;
  // Card at cache index [0, count), or nullptr if out of range.
  const CardEntry *get(uint8_t index) const;

  uint8_t activeIndex() const { return _activeIndex; }
  const CardEntry *getActive() const;
  const char *activeName() const;

  uint8_t buttonTrack() const { return _buttonTrack; }

  // --- Mutations (all write through to flash) ---
  DbStatus add(const char *name, const char *track1, const char *track2);
  // Update tracks of an existing card; pass nullptr to leave a track unchanged.
  DbStatus update(const char *name, const char *track1, const char *track2);
  DbStatus remove(const char *name);
  DbStatus select(const char *name); // set + persist the active card

  // Persisted physical-button mode: 0 = alternate, 1 or 2 = pinned track.
  DbStatus setButtonTrack(uint8_t mode);

  // Set an existing card's SEL_RES preference (Phase 5): nfcEnabled=true,
  // selResMode = hasChip ? 1 : 0. Consulted by resetNfc()/emulateVisaMSD()
  // in magspoof.ino whenever this card is active.
  DbStatus setNfcMode(const char *name, bool hasChip);

  // Erase everything and reseed the single default card. Used by the factory
  // reset (section 6.3) and first-boot migration.
  bool factoryReset(const char *defName, const char *defTrack1,
                    const char *defTrack2);

private:
  static bool validName(const char *name);
  bool persistConfig();

  FlashStorage _flash;
  CardEntry _cards[MAX_CARDS];
  uint8_t _count = 0;
  uint8_t _activeIndex = 0;
  uint8_t _buttonTrack = 0;
  bool _ready = false;
};

#endif // MAGSPOOF_CARDDATABASE_H
