#pragma once
#include <stdint.h>

// EmvKernel — pure, transport-independent EMV L2 contactless codec.
//
// Factored (Fase 6, task #1) from EMVyBomberCat's inline EMV reader kernel.
// This module owns only the *pure* pieces: BER-TLV search, the 6-byte amount
// encoding, and the DOL (PDOL/CDOL) builder driven by a terminal profile. There
// is NO dependency on the PN7150, `Wire`, `Serial` or any Arduino global here,
// so the codec is reusable and host-testable.
//
// Deliberately NOT in this module (they belong to the transport layer and stay
// in the sketch): `apduExchange` / NCI fragment reassembly (they drive the
// PN7150 over `Wire` and log to `Serial`), and the thin `selectPPSE` /
// `selectAID` / `getProcessingOptions` / `readRecord` / `generateAC` wrappers
// that combine "build command bytes" with "transceive". Those wrappers keep
// building their own APDU bytes inline and now delegate the DOL/TLV/amount work
// to this kernel. A future NfcController-based EMV transport helper could
// absorb the exchange side; that is left for the later core split (Fase 6, task
// #2).
namespace EmvKernel {

// Terminal / transaction parameters used to fill a DOL (PDOL in GPO, CDOL1 in
// GENERATE AC). Holds exactly the values EMVy hardcoded as file-scope
// constants; `mexicoOnlinePos()` returns that canonical set so the sketch has a
// single source of truth (it also reads `ttq`/`cvmResults`/`txnDate` back for
// its web JSON).
struct TerminalProfile {
  uint8_t country[2];    // tag 9F1A
  uint8_t currency[2];   // tag 5F2A
  uint8_t type;          // tag 9F35 (terminal type)
  uint8_t tvr[5];        // tag 95  (terminal verification results)
  uint8_t txnType;       // tag 9C  (transaction type)
  uint8_t ttq[4];        // tag 9F66 (TTQ, emitted only for Visa)
  uint8_t cvmResults[3]; // tag 9F34
  char txnDate[7];       // tag 9A, "YYMMDD" + NUL

  // Mexico attended-online POS defaults (the values EMVy shipped with).
  static TerminalProfile mexicoOnlinePos();
};

// Recursive BER-TLV search over `buf` (constructed templates are descended
// into). Returns a pointer into `buf` at the value of the first match, writing
// its length to `*outLen`, or NULL if not found. Signature kept byte-for-byte
// compatible with EMVy's original `tlvFind` so call sites need only
// namespacing.
uint8_t *tlvFind(uint8_t *buf, int bufLen, uint16_t tag, int *outLen);

// Big-endian 6-byte encoding of an amount in cents (EMV tag 9F02 format).
void encodeAmount(uint64_t cents, uint8_t *out6);

// Build DOL response data (`out`/`outLen`) for the DOL descriptor `dol`,
// filling each requested tag from `tp`, the per-transaction unpredictable
// number `un` (tag 9F37) and `isVisa` (gates whether tag 9F66/TTQ is
// populated). Unknown tags are zero-filled to their requested length. Caps
// output at 62 bytes, as the original did.
void buildDolData(uint8_t *dol, int dolLen, uint8_t *out, uint8_t &outLen,
                  uint64_t amountCents, const TerminalProfile &tp,
                  const uint8_t un[4], bool isVisa);

} // namespace EmvKernel
