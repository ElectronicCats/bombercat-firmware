/**
 * BomberCatCore - TagReader
 *
 * Small helpers factored out of the PN7150 tag-reading sketches that carried
 * byte-identical copies of them:
 *   - getHexCompact()  : DetectTags, DetectReaders, MifareClassic
 *   - getProtocolName() : DetectTags, DetectReaders, MifareClassic
 *   - emitTagEvent()   : DetectTags, MifareClassic
 *
 * These are pure formatting / mapping helpers over the PN7150 protocol
 * constants and the bombercat-tools ":tag" wire format. They hold no state and
 * do not touch the RF stack, so every reader sketch can share them while
 * keeping its own display / control-plane logic.
 *
 * `HexUtils` (space-separated "0x.." dump, "null" when empty) stays the tool
 * for human-readable prints; `TagReader::hexCompact` is the separator-less
 * uppercase form the ":tag"/":reader"/":mifare" wire formats use ("-" when
 * empty).
 *
 * Distributed as-is; no warranty is given.
 */
#ifndef BOMBERCAT_CORE_TAGREADER_H
#define BOMBERCAT_CORE_TAGREADER_H

#include <Arduino.h>

namespace TagReader {

// Compact uppercase hex with no "0x"/separators, e.g. "041A2B3C" - the wire
// format's uid_hex/apdu field (see bombercat-tools TagParser._hex_compact).
// Returns "-" when there is nothing to show (len == 0 or data == NULL).
String hexCompact(const uint8_t *data, uint32_t numBytes);

// Human name for a PN7150 protocol value (nfc.remoteDevice.getProtocol()),
// e.g. "T1T", "ISODEP", "MIFARE", or "UNKNOWN". Uses the library's PROT_*
// constants, so no PN7150 instance is needed.
const char *protocolName(unsigned char protocol);

// Emit a structured ":tag" event on `out`, matching the format bombercat-tools'
// TagParser consumes: ":tag <ts_ms> <tech> <protocol> <uid_hex> [extra]".
// `extra` is optional trailing space-separated "k=v" pairs (e.g.
// "attrib=1122").
void emitTagEvent(Print &out, uint32_t tsMs, const char *tech,
                  const char *protocol, const String &uidHex,
                  const String &extra = "");

} // namespace TagReader

#endif // BOMBERCAT_CORE_TAGREADER_H
