/**
 * BomberCatCore - TagReader implementation
 *
 * See TagReader.h. Bodies are lifted verbatim from the reader sketches; the
 * protocol switch uses the library's PROT_* macros (Protocol.h) instead of a
 * per-instance `nfc.protocol.*`, so the helper needs no PN7150 object.
 *
 * Distributed as-is; no warranty is given.
 */
#include "TagReader.h"

#include "Electroniccats_PN7150.h" // PROT_* protocol constants
#include "HexUtils.h"

namespace TagReader {

String hexCompact(const uint8_t *data, uint32_t numBytes) {
  if (numBytes == 0 || data == NULL) {
    return "-";
  }
  // Same encoding as HexUtils::toCompact(); converted in fixed-size chunks so
  // a long APDU payload never needs a len*2+1 scratch buffer on the RP2040.
  const uint32_t kChunk = 16;
  char tmp[kChunk * 2 + 1];
  String hex;
  hex.reserve(numBytes * 2);
  for (uint32_t i = 0; i < numBytes; i += kChunk) {
    uint32_t n = numBytes - i < kChunk ? numBytes - i : kChunk;
    HexUtils::toCompact(data + i, n, tmp);
    hex += tmp;
  }
  return hex;
}

const char *protocolName(unsigned char protocol) {
  switch (protocol) {
  case PROT_T1T:
    return "T1T";
  case PROT_T2T:
    return "T2T";
  case PROT_T3T:
    return "T3T";
  case PROT_ISODEP:
    return "ISODEP";
  case PROT_NFCDEP:
    return "NFCDEP";
  case PROT_ISO15693:
    return "ISO15693";
  case PROT_MIFARE:
    return "MIFARE";
  default:
    return "UNKNOWN";
  }
}

void emitTagEvent(Print &out, uint32_t tsMs, const char *tech,
                  const char *protocol, const String &uidHex,
                  const String &extra) {
  out.print(":tag ");
  out.print(tsMs);
  out.print(' ');
  out.print(tech);
  out.print(' ');
  out.print(protocol);
  out.print(' ');
  out.print(uidHex);
  if (extra.length() > 0) {
    out.print(' ');
    out.print(extra);
  }
  out.println();
}

} // namespace TagReader
