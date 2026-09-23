#include "HexUtils.h"

namespace HexUtils {

static void printByte(Print &out, uint8_t b, bool leadingSpace) {
  if (leadingSpace)
    out.print(' ');
  out.print("0x");
  if (b <= 0x0F)
    out.print('0');
  out.print(b, HEX);
}

String toString(const uint8_t *data, size_t len) {
  if (len == 0)
    return String("null");

  String hex;
  hex.reserve(len * 5); // "0xNN " per byte
  for (size_t i = 0; i < len; i++) {
    if (i != 0)
      hex += ' ';
    hex += "0x";
    if (data[i] <= 0x0F)
      hex += '0';
    hex += String(data[i], HEX);
  }
  return hex;
}

void print(Print &out, const uint8_t *data, size_t len) {
  if (len == 0) {
    out.print("null");
    return;
  }
  for (size_t i = 0; i < len; i++) {
    printByte(out, data[i], i != 0);
  }
}

namespace {
int hexNibble(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  return -1;
}
} // namespace

size_t decode(const char *hex, uint8_t *out, size_t maxLen) {
  size_t n = 0;
  while (hex[0]) {
    if (hex[0] == ' ') {
      hex++;
      continue;
    }
    if (!hex[1])
      break;
    int hi = hexNibble(hex[0]), lo = hexNibble(hex[1]);
    if (hi < 0 || lo < 0)
      break;
    if (n >= maxLen)
      break;
    out[n++] = (uint8_t)((hi << 4) | lo);
    hex += 2;
  }
  return n;
}

void toCompact(const uint8_t *data, size_t len, char *out) {
  static const char kHexDigits[] = "0123456789ABCDEF";
  for (size_t i = 0; i < len; i++) {
    out[i * 2] = kHexDigits[(data[i] >> 4) & 0x0F];
    out[i * 2 + 1] = kHexDigits[data[i] & 0x0F];
  }
  out[len * 2] = '\0';
}

} // namespace HexUtils
