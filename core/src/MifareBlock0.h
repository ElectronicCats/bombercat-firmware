/**
 * BomberCatCore - MIFARE Classic block 0 dissection.
 *
 * On-device twin of bombercat-tools/modules/tags/mifare/block0.py (Plan de
 * Implementacion Firmware MIFARE, Fase 4 / tarea 4.4). Only the fixed layout
 * of a 4-byte-UID card applies: UID(4) BCC(1) SAK(1) ATQA(2) manufacturer
 * data(8). A 7-byte-UID card lays block 0 out differently - the host's
 * parser simply declines to dissect those (returns None), and so does this
 * one, by reporting the card's SAK as a non-Classic value.
 *
 * Why the firmware needs it: the block 0 the card returns is the authoritative
 * UID (the anti-collision UID can differ on a clone/magic card), and the
 * firmware cross-checks the two before emitting the dump.
 *
 * Dependency-free on purpose (no Arduino.h): the parity harness compiles
 * this module outside the Arduino toolchain.
 *
 * Distributed as-is; no warranty is given.
 */
#ifndef BOMBERCAT_CORE_MIFAREBLOCK0_H
#define BOMBERCAT_CORE_MIFAREBLOCK0_H

#include <cstdint>

// The dissected block 0.
struct MifareBlock0 {
  uint8_t uid[4];
  uint8_t bcc;     // the card's check byte
  bool bccValid;   // bcc == XOR of the UID bytes
  uint8_t sak;     // select acknowledge
  uint8_t atqa[2]; // as read (byte order preserved)
  uint8_t manufacturer[8];
};

// Dissect one 16-byte block 0. Always fills `out`; `out.bccValid` reports
// whether the card's check byte matches the UID.
void mifareParseBlock0(const uint8_t block[16], MifareBlock0 &out);

// Human name of a SAK ("MIFARE Classic 1K", ...). Never null: an unknown SAK
// is "unknown/non-standard", exactly as the host's block0.py reports it.
const char *mifareSakName(uint8_t sak);

// Human name of an ATQA pair ("MIFARE Classic 1K", ...). Never null: an
// unknown ATQA is "unknown".
const char *mifareAtqaName(const uint8_t atqa[2]);

// True when the SAK says "this is a MIFARE Classic card" (the bit the host's
// TagParser uses to classify a tag).
bool mifareSakIsClassic(uint8_t sak);

#endif // BOMBERCAT_CORE_MIFAREBLOCK0_H
