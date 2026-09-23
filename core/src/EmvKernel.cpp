#include "EmvKernel.h"
#include <string.h>

namespace EmvKernel {

TerminalProfile TerminalProfile::mexicoOnlinePos() {
  // Mirrors EMVyBomberCat's original constants (Mexico, attended online POS).
  // TTQ byte1 0x26: Online-req|CVM-not-req, bit5=0 so the issuer does not
  // reject for "CVM required but not performed".
  TerminalProfile tp = {
      {0x04, 0x84},       // country
      {0x04, 0x84},       // currency
      0x22,               // type
      {0, 0, 0, 0, 0},    // tvr
      0x00,               // txnType
      {0x26, 0, 0, 0},    // ttq
      {0x1F, 0x00, 0x02}, // cvmResults
      "260612",           // txnDate (YYMMDD)
  };
  return tp;
}

uint8_t *tlvFind(uint8_t *buf, int bufLen, uint16_t tag, int *outLen) {
  int i = 0;
  while (i < bufLen - 1) {
    uint16_t t;
    int tagBytes;
    if ((buf[i] & 0x1F) == 0x1F) {
      if (i + 1 >= bufLen)
        break;
      t = ((uint16_t)buf[i] << 8) | buf[i + 1];
      tagBytes = 2;
    } else {
      t = buf[i];
      tagBytes = 1;
    }
    bool constr = (buf[i] & 0x20) != 0;
    i += tagBytes;
    if (i >= bufLen)
      break;
    int vlen;
    if (buf[i] & 0x80) {
      int nb = buf[i] & 0x7F;
      if (nb > 2 || i + nb >= bufLen)
        break;
      vlen = 0;
      for (int j = 0; j < nb; j++)
        vlen = (vlen << 8) | buf[i + 1 + j];
      i += 1 + nb;
    } else {
      vlen = buf[i++];
    }
    if (i + vlen > bufLen)
      break;
    if (t == tag) {
      if (outLen)
        *outLen = vlen;
      return buf + i;
    }
    if (constr) {
      int cl = 0;
      uint8_t *f = tlvFind(buf + i, vlen, tag, &cl);
      if (f) {
        if (outLen)
          *outLen = cl;
        return f;
      }
    }
    i += vlen;
  }
  return NULL;
}

void encodeAmount(uint64_t cents, uint8_t *out6) {
  // EMV tag 9F02 "Amount, Authorised" es formato n12: 6 bytes en BCD
  // empaquetado (dos dígitos decimales por byte), NO binario. Ej.: 500 →
  // 00 00 00 00 05 00.
  //
  // Antes esto codificaba en binario (500 → 00 00 00 00 01 F4). Visa qVSDC
  // nunca lo delata porque su criptograma llega directo en la respuesta al GPO
  // y la tarjeta no corre gestión de riesgo sobre el monto; pero Mastercard
  // M/Chip sí interpreta 9F02 como BCD durante su Card Risk Management en el
  // GENERATE AC — un monto en binario contiene nibbles inválidos (A–F).
  //
  // Ésta fue la causa raíz confirmada en hardware (2026-09-22) del SW=6985 que
  // hacía fallar `bombercat emvy read` con Mastercard mientras Visa funcionaba:
  // con el monto en BCD la tarjeta acepta el GENERATE AC y devuelve
  // ARQC/ATC/IAD reales. Detalle completo en
  // bombercat-firmware/docs/MASTERCARD_READ_FIX_EMVYBOMBERCAT.md.
  for (int i = 5; i >= 0; i--) {
    uint8_t lo = (uint8_t)(cents % 10);
    cents /= 10;
    uint8_t hi = (uint8_t)(cents % 10);
    cents /= 10;
    out6[i] = (uint8_t)((hi << 4) | lo);
  }
}

void buildDolData(uint8_t *dol, int dolLen, uint8_t *out, uint8_t &outLen,
                  uint64_t amountCents, const TerminalProfile &tp,
                  const uint8_t un[4], bool isVisa) {
  outLen = 0;
  uint8_t amtBytes[6];
  encodeAmount(amountCents, amtBytes);
  int i = 0;
  while (i < dolLen && outLen < 62) {
    uint16_t tag;
    int tb;
    if ((dol[i] & 0x1F) == 0x1F) {
      tag = ((uint16_t)dol[i] << 8) | dol[i + 1];
      tb = 2;
    } else {
      tag = dol[i];
      tb = 1;
    }
    i += tb;
    uint8_t len = dol[i++];
    switch (tag) {
    case 0x9F02:
      memcpy(out + outLen, amtBytes, 6);
      outLen += 6;
      break;
    case 0x9F03:
      for (int j = 0; j < len; j++)
        out[outLen++] = 0;
      break;
    case 0x9F1A:
      out[outLen++] = tp.country[0];
      out[outLen++] = tp.country[1];
      break;
    case 0x95:
      for (int j = 0; j < 5; j++)
        out[outLen++] = tp.tvr[j];
      break;
    case 0x5F2A:
      out[outLen++] = tp.currency[0];
      out[outLen++] = tp.currency[1];
      break;
    case 0x9A:
      out[outLen++] =
          (uint8_t)(((tp.txnDate[0] - '0') << 4) | (tp.txnDate[1] - '0'));
      out[outLen++] =
          (uint8_t)(((tp.txnDate[2] - '0') << 4) | (tp.txnDate[3] - '0'));
      out[outLen++] =
          (uint8_t)(((tp.txnDate[4] - '0') << 4) | (tp.txnDate[5] - '0'));
      break;
    case 0x9C:
      out[outLen++] = tp.txnType;
      break;
    case 0x9F37:
      memcpy(out + outLen, un, 4);
      outLen += 4;
      break;
    case 0x9F34:
      memcpy(out + outLen, tp.cvmResults, 3);
      outLen += 3;
      break;
    case 0x9F35:
      out[outLen++] = tp.type;
      break;
    case 0x9F66: {
      if (isVisa)
        memcpy(out + outLen, tp.ttq, 4);
      else
        memset(out + outLen, 0, 4);
      outLen += 4;
      break;
    }
    default:
      for (int j = 0; j < len; j++)
        out[outLen++] = 0;
      break;
    }
  }
}

} // namespace EmvKernel
