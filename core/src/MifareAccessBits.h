/**
 * BomberCatCore - MIFARE Classic access bits (C1/C2/C3).
 *
 * On-device twin of bombercat-tools/modules/tags/mifare/access_bits.py
 * (Plan de Implementacion Firmware MIFARE, Fase 4 / tarea 4.4): the SAME
 * decode of a sector trailer's 3 access-condition bytes, so the firmware and
 * the host CLI reach the same verdict on the same trailer - in particular on
 * the one that decides the key-recovery shortcut ("is Key B readable with Key
 * A?").
 *
 * The two implementations are kept honest by a parity test that compiles this
 * module natively (g++) and compares it against the Python one over a vector
 * set - see bombercat-tools/tests/test_mifare_parity.py.
 *
 * Dependency-free on purpose (no Arduino.h): the module is plain C++ so the
 * parity harness can build it outside the Arduino toolchain.
 *
 * Distributed as-is; no warranty is given.
 */
#ifndef BOMBERCAT_CORE_MIFAREACCESSBITS_H
#define BOMBERCAT_CORE_MIFAREACCESSBITS_H

#include <cstdint>

// Who grants an access condition. Same four values the host's access_bits.py
// uses ("never" / "key A" / "key B" / "key A or B").
enum MifareAccessPerm {
  MIFARE_PERM_NEVER = 0,
  MIFARE_PERM_KEY_A = 1,
  MIFARE_PERM_KEY_B = 2,
  MIFARE_PERM_KEY_AB = 3,
};

// Access conditions of one of the sector's three data blocks.
struct MifareBlockAccess {
  MifareAccessPerm read;
  MifareAccessPerm write;
  MifareAccessPerm increment;
  MifareAccessPerm decrement; // decrement/transfer/restore share one condition
};

// Access conditions of the sector trailer itself. There is deliberately no
// "key A read": a card NEVER reads Key A back under any access condition.
struct MifareTrailerAccess {
  MifareAccessPerm keyAWrite;
  MifareAccessPerm acRead;
  MifareAccessPerm acWrite;
  MifareAccessPerm keyBRead;
  MifareAccessPerm keyBWrite;
};

// A decoded trailer.
struct MifareAccessBits {
  bool valid; // false when the bits and their stored inverses disagree
  MifareBlockAccess blocks[3];
  MifareTrailerAccess trailer;
};

// Decode the 3 access-condition bytes of a sector trailer (bytes 6..8 of the
// 16-byte trailer: key A | access+GPB | key B).
//
// `ac` points at those 3 bytes (b6, b7, b8). Always fills `out`; the caller
// checks `out.valid` before trusting it - a trailer whose inverse check fails
// is reported, not silently accepted.
void mifareParseAccessBits(const uint8_t *ac, MifareAccessBits &out);

// True when `perm` grants the operation to the given key type. `keyA` selects
// Key A (true) or Key B (false).
bool mifarePermAllows(MifareAccessPerm perm, bool keyA);

#endif // BOMBERCAT_CORE_MIFAREACCESSBITS_H
