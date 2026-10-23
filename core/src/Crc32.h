/**
 * BomberCatCore - Crc32
 *
 * IEEE 802.3 CRC-32 (polynomial 0xEDB88320, reflected) over an arbitrary
 * buffer - the same checksum the MagSpoof card store has always written into
 * its records, lifted out of the sketch so any persisted POD record in the
 * library can carry one.
 *
 * Dependency-free on purpose (no Arduino.h): the record layouts that use it
 * are plain C++ and the checksum is computed by the host tooling too.
 *
 * Distributed as-is; no warranty is given.
 */
#ifndef BOMBERCAT_CORE_CRC32_H
#define BOMBERCAT_CORE_CRC32_H

#include <stddef.h>
#include <stdint.h>

namespace Crc32 {

// CRC-32 (IEEE 802.3) over `len` bytes. No table: the records this checks
// are small (a few hundred bytes at most) and the flash wear, not the CPU,
// is the scarce resource here.
uint32_t compute(const void *data, size_t len);

} // namespace Crc32

#endif // BOMBERCAT_CORE_CRC32_H
