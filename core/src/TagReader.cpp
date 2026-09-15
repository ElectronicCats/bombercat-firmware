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

namespace TagReader {

String hexCompact(const uint8_t *data, uint32_t numBytes) {
  if (numBytes == 0 || data == NULL) {
    return "-";
  }
  char tmp[3];
  String hex;
  for (uint32_t i = 0; i < numBytes; i++) {
    sprintf(tmp, "%02X", data[i] & 0xFF);
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
