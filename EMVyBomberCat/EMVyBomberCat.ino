/**
 * EMVyBomberCat — firmware "navaja suiza" de EMVy Controller
 * ============================================================
 * Board : BomberCat (Electronic Cats) — RP2040 mbed + NINA-W102
 * NFC   : PN7150 (I2C, 0x28) vía `core/src/NfcController` (Fase 5) — único
 *         punto de acceso al chip; `nfc.raw()` alcanza las primitivas que
 *         NfcController no re-expone (remoteDevice/protocol/readerTagCmd/…).
 *
 * Pines FIJOS — NO modificar:
 *   IRQ=11  VEN=13  ADDR=0x28
 *
 * Acceso: AP "EMVyBomberCat" clave "bombercat"
 *         http://192.168.4.1
 *
 * Panel web (este dispositivo) cubre:
 *   Hardware · Escaneo NFC · Identificación de tarjeta
 *   Protocolo EMV · Transacciones · Sondas de seguridad
 *
 * Plano de control — BomberCatControl Discovery Contract v1.0
 * (docs/BomberCatControl-Discovery-Contract.md): ping/info/identify los sirve
 * `core/src/BomberCatControl` (mismo REPL que MifareClassic/DetectTags/…) para
 * que cualquier host (CLI del vendor, GUI/TUI de EMVy) descubra e identifique
 * la placa de forma idéntica:
 *   ping     (case-insensitive) -> `+OK bombercat`   (§5, handshake)
 *   info     -> `:fw_name emvybombercat` `:fw <v>` `:state <idle|scanning|
 *               emulating|hw-error>` `+OK` (§6.1)
 *   identify -> `+OK` inmediato + parpadeo LED asíncrono (§6.2)
 *   <verbo desconocido> -> `-ERR unknown command <verb>` (§6.3.3)
 * Los verbos OPERATIVOS de abajo (WAIT/APDU:/EMU:/…) los atiende el hook
 * `emvyCommand()` y conservan el dialecto histórico por retrocompatibilidad
 * con `emvy/readers/bombercat.py` hasta que el host migre al framing +OK/-ERR
 * (ver README §"Discovery Contract").
 *
 * Por serie (@115200) expone el mismo dispositivo a **EMVy Controller**
 * (`emvyctl.py`/`emvy`): passthrough de APDU (PING/WAIT/APDU:/RELEASE),
 * lectura EMV (SCAN), tags NFC (TAG), banda magnética (MAG:) y emulación de
 * tag NDEF (EMU:<hex> — se hace pasar por un tag NFC Type 4 para fuzzear
 * lectores; observable APDU-a-APDU y cancelable con STOP). REBOOT reinicia el
 * MCU (para salir de un estado atascado sin desconectar). Una vez conectado
 * desde la pestaña Lectores, EMVy puede leer,
 * escribir (Escritura) y hacer el dump completo de la tarjeta igual que con
 * cualquier otro lector. Ver `firmware/EMVyBomberCat/README.md`.
 *
 * Créditos
 * --------
 * Firmware EMVy contribuido originalmente por
 * [Glitchboi-sudo](https://github.com/Glitchboi-sudo) en
 * https://github.com/ElectronicCats/bombercat-firmware/pull/4. A partir de esa
 * contribución se adaptó para seguir el mismo core y los mismos patrones
 * arquitectónicos que ya usan los demás firmwares de este repositorio
 * (`core/src/NfcController` como único punto de acceso al PN7150,
 * `core/src/BomberCatControl` para el REPL ping/info/identify del Discovery
 * Contract, y `core/src/EmvKernel` para la lógica EMV compartida) en vez de
 * reimplementar esas piezas de forma aislada.
 */

#include "emv_emu.h" // struct DolItem (ver nota en el header sobre por qué)
#include <ArduinoJson.h>
#include <BomberCatControl.h>
#include <Electroniccats_PN7150.h>
#include <EmvKernel.h>
#include <HexUtils.h>
#include <MagStripe.h>
#include <NfcController.h>
#include <TagReader.h>
#include <WiFiNINA.h>
#include <Wire.h>
#include <stdarg.h>

// ---------------------------------------------------------------------------
// WiFi AP
// ---------------------------------------------------------------------------
#define AP_SSID "EMVyBomberCat"
#define AP_PASS "bombercat"
#define BOMBERCAT_FW_VERSION "1.1.0.1"
WiFiServer server(80);

// ---------------------------------------------------------------------------
// Hardware BomberCat — NO modificar
// ---------------------------------------------------------------------------
#define PN7150_IRQ (11)
#define PN7150_VEN (13)
#define PN7150_ADDR (0x28)
// Único punto de acceso al PN7150 (Fase 5): NfcController evita la doble ruta
// al chip que existía al enlazar `core` sin adoptarlo. Las primitivas que no
// re-expone (remoteDevice/protocol/readerTagCmd/cardModeSend/Receive/…) se
// alcanzan vía nfc.raw() — mismo objeto físico, sin reescribir el kernel EMV.
NfcController nfc(PN7150_IRQ, PN7150_VEN, PN7150_ADDR, PN7150);

// BomberCat serial-control REPL (ping/info/identify) — plano de descubrimiento
// canónico consumido por bombercat-tools/emvyctl. Slug debe coincidir con el
// registrado en bombercat-tools/firmwares.py y con descriptions.json.
BomberCatControl control(Serial, BOMBERCAT_FW_VERSION, "emvybombercat");

// true tras un WAIT/APDU exitoso; false tras RELEASE o un fallo de
// transmisión. Ver nota en el handler de WAIT sobre por qué APDU: no puede
// re-consultar nfc.raw().isTagDetected() directamente.
static bool gPassthroughActive = false;

// Estado del plano de control (reportado por `info`/:state): true mientras se
// espera una tarjeta/tag (WAIT/SCAN/CARDSCAN/TAG). "emulating" se deriva de
// gEmuActive (ver más abajo); controlState() combina ambas señales.
static bool gScanningCard = false;

// Fase 5: fallos de bring-up (NFC/WiFi) ya no cuelgan el firmware en
// `while(true)` — quedan registrados aquí y controlState() los reporta como
// "hw-error" para que el host siga viendo la placa (ping sigue respondiendo).
static bool gNfcFault = false;
static bool gWifiFault = false;

// Emulación NDEF (comando EMU:): el BomberCat se hace pasar por un tag NFC
// Forum Type 4 sirviendo un mensaje NDEF arbitrario (posiblemente malformado,
// para fuzzing de lectores). En vez del enfoque opaco isReaderDetected()/
// sendMessage() (que hace un bloqueo de ~30 s y no deja ver nada), bombeamos el
// bucle de card-emulation nosotros mismos desde loop() con las primitivas
// públicas cardModeReceive()/cardModeSend() + la máquina de estados T4T de la
// librería (T4T_NDEF_EMU_Next). Así (1) reportamos por serie CADA APDU que
// manda el lector —qué app/fichero selecciona y qué offset/longitud lee— y
// (2) la emulación es cancelable en cualquier momento (STOP) sin apagar la
// placa.
NdefMessage emuMessage;
static volatile bool gEmuSent = false;
static void emuSentCallback() { gEmuSent = true; }
static bool gEmuActive = false; // true mientras emulamos un tag NDEF
static uint8_t
    gEmuBuf[2048]; // mensaje NDEF servido (persiste: T4T guarda el puntero)
static int gEmuLen = 0;
static unsigned long gEmuStart =
    0; // millis() de inicio (para el auto-stop de seguridad)
static int gEmuSentCount = 0; // nº de mensajes NDEF entregados a un lector
static const unsigned long EMU_MAX_MS =
    180000UL; // ventana de seguridad: auto-stop
// Modo de emulación: 0 = tag NDEF (T4T), 1 = tarjeta EMV (perfilar terminal).
// En modo EMV el firmware responde PPSE→FCI→SELECT AID→GPO→READ RECORD→GEN AC
// con datos canned para que un TERMINAL de pago avance y revele su config
// (PDOL: TTQ/monto/país/divisa/UN…, y CDOL1 en el GENERATE AC). Sin cripto
// real.
static int gEmuMode = 0; // struct DolItem vive en emv_emu.h

// ---------------------------------------------------------------------------
// Parámetros de terminal (México, attended online POS)
// ---------------------------------------------------------------------------
// Perfil de terminal (país/divisa/tipo/TVR/TTQ/CVM/fecha) — fuente única en
// core/src/EmvKernel (TerminalProfile). Antes eran 8 constantes sueltas aquí
// (TERM_COUNTRY/CURRENCY/TYPE/TVR, TXN_TYPE, TERM_TTQ, CVM_RESULTS, TXN_DATE);
// el kernel EMV (buildDolData) y buildWebJson las leen ahora vía este objeto.
// Valores idénticos a los originales: México, POS atendido online.
static const EmvKernel::TerminalProfile TERM =
    EmvKernel::TerminalProfile::mexicoOnlinePos();

// ---------------------------------------------------------------------------
// Tabla de AIDs conocidas — selección prioritaria
// ---------------------------------------------------------------------------
struct AidEntry {
  const uint8_t *bytes;
  uint8_t len;
  const char *name;
};
static const uint8_t AID_VISA[] = {0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10};
static const uint8_t AID_VISA_DEB[] = {0xA0, 0x00, 0x00, 0x00,
                                       0x03, 0x20, 0x10};
static const uint8_t AID_MC[] = {0xA0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10};
static const uint8_t AID_MC_DEB[] = {0xA0, 0x00, 0x00, 0x00, 0x04, 0x30, 0x60};
static const uint8_t AID_AMEX[] = {0xA0, 0x00, 0x00, 0x00,
                                   0x25, 0x01, 0x04, 0x02};
static const uint8_t AID_JCB[] = {0xA0, 0x00, 0x00, 0x00, 0x65, 0x10, 0x10};
static const uint8_t AID_UNIONPAY[] = {0xA0, 0x00, 0x00, 0x03,
                                       0x33, 0x01, 0x01, 0x01};
static const AidEntry AIDS[] = {
    {AID_VISA, 7, "VISA"},         {AID_VISA_DEB, 7, "VISA_DEBIT"},
    {AID_MC, 7, "MASTERCARD"},     {AID_MC_DEB, 7, "MAESTRO"},
    {AID_AMEX, 8, "AMEX"},         {AID_JCB, 7, "JCB"},
    {AID_UNIONPAY, 8, "UNIONPAY"},
};
static const int NUM_AIDS = (int)(sizeof(AIDS) / sizeof(AIDS[0]));

// Tabla extendida para id_aids (todos los conocidos)
struct FullAid {
  const uint8_t *b;
  uint8_t l;
  const char *n;
};
static const uint8_t FA_VISAELEC[] = {0xA0, 0x00, 0x00, 0x00, 0x03, 0x20, 0x20};
static const uint8_t FA_VISAPLUS[] = {0xA0, 0x00, 0x00, 0x00, 0x03, 0x80, 0x10};
static const uint8_t FA_MAESTRO2[] = {0xA0, 0x00, 0x00, 0x00, 0x05, 0x00, 0x01};
static const uint8_t FA_DISCOVER[] = {0xA0, 0x00, 0x00, 0x01, 0x52, 0x30, 0x10};
static const uint8_t FA_INTERLINK[] = {0xA0, 0x00, 0x00, 0x00,
                                       0x03, 0x30, 0x10};
static const uint8_t FA_LINK[] = {0xA0, 0x00, 0x00, 0x00, 0x29, 0x10, 0x10};
static const uint8_t FA_EFTPOS[] = {0xA0, 0x00, 0x00, 0x03, 0x84, 0x00, 0x00};
static const FullAid ALL_AIDS[] = {
    {AID_VISA, 7, "VISA Credit"},
    {AID_VISA_DEB, 7, "VISA Debit"},
    {FA_VISAELEC, 7, "VISA Electron"},
    {FA_VISAPLUS, 7, "VISA Plus"},
    {AID_MC, 7, "Mastercard"},
    {AID_MC_DEB, 7, "Mastercard Debit"},
    {FA_MAESTRO2, 7, "Maestro"},
    {AID_AMEX, 8, "American Express"},
    {FA_DISCOVER, 7, "Discover"},
    {AID_JCB, 7, "JCB"},
    {AID_UNIONPAY, 8, "UnionPay"},
    {FA_INTERLINK, 7, "Interlink"},
    {FA_LINK, 7, "LINK"},
    {FA_EFTPOS, 7, "EFTPOS"},
};
static const int NUM_ALL_AIDS = (int)(sizeof(ALL_AIDS) / sizeof(ALL_AIDS[0]));

// ---------------------------------------------------------------------------
// Estado de tarjeta
// ---------------------------------------------------------------------------
struct EmvCard {
  char pan[22];
  char expiry[5];
  char track2[82];
  char label[18];
  uint8_t aip[2];
  uint8_t arqc[8];
  uint8_t atc[2];
  uint8_t iad[32];
  uint8_t iadLen;
  uint8_t un[4];
  uint8_t cdol1[64];
  uint8_t cdol1Len;
  char aidName[20];
  char aidHex[36];
  bool valid;
};
static EmvCard card;
static char webResult[1200] = "";
static uint64_t gTestAmt = 0;

// ---------------------------------------------------------------------------
// Ring buffer de log — persiste líneas para /log aunque vengan de serial
// ---------------------------------------------------------------------------
#define LOG_LINES 20
#define LOG_WIDTH 96
static char logRing[LOG_LINES][LOG_WIDTH];
static uint16_t logHead = 0; // próxima posición a escribir (monotónico)

static void logPush(const char *m) {
  uint16_t idx = logHead % LOG_LINES;
  strncpy(logRing[idx], m, LOG_WIDTH - 1);
  logRing[idx][LOG_WIDTH - 1] = '\0';
  logHead++;
}

// ---------------------------------------------------------------------------
// Streaming console — gSC apunta al cliente activo durante handleTest
// ---------------------------------------------------------------------------
static WiFiClient *gSC = nullptr;

static void slog(const char *m) {
  Serial.println(m);
  logPush(m);
  if (!gSC)
    return;
  char b[130];
  snprintf(b, sizeof(b), "{\"t\":\"log\",\"m\":\"%s\"}\n", m);
  gSC->print(b);
}
#define SLOGF(...)                                                             \
  do {                                                                         \
    char _s[90];                                                               \
    snprintf(_s, 90, __VA_ARGS__);                                             \
    slog(_s);                                                                  \
  } while (0)

static void sResult(const String &id, bool pass, const char *detail,
                    unsigned long ms) {
  if (!gSC)
    return;
  char d2[180];
  int j = 0;
  for (int i = 0; detail[i] && j < 178; i++)
    d2[j++] = (detail[i] == '"') ? '\'' : detail[i];
  d2[j] = '\0';
  char b[320];
  snprintf(
      b, sizeof(b),
      "{\"t\":\"r\",\"id\":\"%s\",\"pass\":%s,\"detail\":\"%s\",\"ms\":%lu}\n",
      id.c_str(), pass ? "true" : "false", d2, ms);
  gSC->print(b);
}

// ---------------------------------------------------------------------------
// TRNG — registro ROSC RP2040
// ---------------------------------------------------------------------------
static uint32_t hwRand32() {
  volatile uint32_t *rng = (volatile uint32_t *)0x4006001C;
  uint32_t r = 0;
  for (int i = 0; i < 32; i++)
    r = (r << 1) | (*rng & 1u);
  return r;
}

// ---------------------------------------------------------------------------
// Helpers EMV
// ---------------------------------------------------------------------------
// Hex encode/decode ahora viven en core/src/HexUtils (HexUtils::toCompact /
// HexUtils::decode) — antes reimplementados aquí como hexEncode()/hexDecode().

// encodeAmount / tlvFind ahora viven en core/src/EmvKernel (EmvKernel::
// encodeAmount / EmvKernel::tlvFind) — antes definidos aquí. buildDolData
// también se movió al kernel (ver más abajo, GET PROCESSING OPTIONS).

// Capacidad compartida de los buffers de respuesta EMV (resp/fci/gpo/rr/gen).
// READ RECORD con Le=00 puede devolver legítimamente hasta 256 bytes de datos
// + 2 de SW = 258 (caso real visto con el certificado de clave pública del
// emisor de Mastercard, SFI grande) — 8 bits (máx. 255) se quedan cortos,
// por eso las longitudes de este flujo son uint16_t y los buffers usan este
// tope en vez de 256.
static const uint16_t EMV_RESP_CAP = 264;

static void drainNciFragments(uint8_t *resp, uint16_t &respLen) {
  for (int frag = 0; frag < 16 && respLen < EMV_RESP_CAP; frag++) {
    delay(10);
    if (!nfc.raw().hasMessage())
      break;
    uint8_t hdr[3];
    Wire.requestFrom((uint8_t)PN7150_ADDR, (uint8_t)3);
    if (Wire.available() < 3)
      break;
    hdr[0] = Wire.read();
    hdr[1] = Wire.read();
    hdr[2] = Wire.read();
    uint8_t fl = hdr[2];
    if (fl == 0 || fl > 252)
      break;
    Wire.requestFrom((uint8_t)PN7150_ADDR, fl);
    uint8_t got = 0;
    while (Wire.available() && got < fl) {
      if (respLen < EMV_RESP_CAP)
        resp[respLen++] = Wire.read();
      else
        Wire.read();
      got++;
    }
    if ((hdr[0] & 0x10) == 0)
      break;
  }
}

static bool apduExchange(uint8_t *cmd, uint8_t cmdLen, uint8_t *resp,
                         uint16_t &respLen, const char *label) {
  for (int attempt = 0; attempt < 1; attempt++) {
    if (attempt == 0) {
      SLOGF("→ %s", label);
    } else {
      SLOGF("→ %s (retry %d)", label, attempt);
      delay(80);
    }
    delay(20);
    // readerTagCmd() de la librería PN7150 exige un puntero a uint8_t para
    // el tamaño (un único fragmento NCI nunca pasa de 255 bytes), así que
    // recibimos ahí en un temporal de 8 bits y lo ampliamos a respLen
    // (uint16_t) antes de drenar el resto de la cadena.
    uint8_t firstFragLen = 0;
    bool err = nfc.raw().readerTagCmd(cmd, cmdLen, resp, &firstFragLen);
    respLen = firstFragLen;
    // readerTagCmd() marca "err" tanto en un timeout real como cuando el
    // PRIMER fragmento de una respuesta encadenada (NCI PBF=1) no trae el
    // header 00 00 que espera — y en ambos casos ya copió en resp/respLen
    // lo que tenía en rxBuffer. El segundo caso es habitual en Mastercard
    // M/Chip: registros grandes (p. ej. el certificado de clave pública
    // del emisor, SFI=6) no entran en un solo fragmento NCI, algo que Visa
    // qVSDC no sufre porque manda el criptograma directo en el GPO (sin
    // READ RECORD). Por eso drenamos el resto de la cadena SIEMPRE, haya
    // marcado error o no, y decidimos éxito/fallo por el SW final real en
    // vez de confiar en el flag de readerTagCmd(). Si no se drena aquí, el
    // FIFO I2C queda con bytes pendientes y desincroniza el comando
    // siguiente (por eso fallaban también las lecturas y el GENERATE AC
    // posteriores, no solo este registro).
    drainNciFragments(resp, respLen);
    if (respLen < 2) {
      if (err) {
        size_t showLen = (respLen < 8) ? respLen : 8;
        char hx[24];
        HexUtils::toCompact(resp, showLen, hx);
        char eb[90];
        snprintf(eb, sizeof(eb), "# APDU ERR: %s (len=%u data=%s)", label,
                 (unsigned)respLen, hx);
        Serial.println(eb);
        break;
      }
      Serial.println("# APDU short resp");
      continue;
    }
    uint8_t sw1 = resp[respLen - 2], sw2 = resp[respLen - 1];
    if (err && sw1 != 0x90 && sw1 != 0x61) {
      // No era una cadena recuperable: error real (timeout, tarjeta
      // retirada, notificación NCI inesperada, etc.)
      size_t showLen = (respLen < 8) ? respLen : 8;
      char hx[24];
      HexUtils::toCompact(resp, showLen, hx);
      char eb[90];
      snprintf(eb, sizeof(eb), "# APDU ERR: %s (len=%u data=%s)", label,
               (unsigned)respLen, hx);
      Serial.println(eb);
      break;
    }
    // SW=61xx: tarjeta tiene más datos — emitir GET RESPONSE
    if (sw1 == 0x61 && sw2 > 0) {
      uint8_t gr[] = {0x00, 0xC0, 0x00, 0x00, sw2};
      uint8_t grResp[EMV_RESP_CAP];
      uint8_t grFragLen = 0;
      delay(20);
      if (!nfc.raw().readerTagCmd(gr, sizeof(gr), grResp, &grFragLen)) {
        uint16_t grLen = grFragLen;
        drainNciFragments(grResp, grLen);
        if (grLen >= 2) {
          uint16_t origData = respLen - 2;
          uint16_t newData = grLen - 2;
          if ((uint32_t)origData + newData + 2 <= EMV_RESP_CAP) {
            memcpy(resp + origData, grResp, grLen);
            respLen = origData + grLen;
            sw1 = resp[respLen - 2];
            sw2 = resp[respLen - 1];
          }
        }
      }
    }
    if (sw1 == 0x90)
      return true;
    {
      char _b[80];
      snprintf(_b, sizeof(_b), "# SW=%02X%02X en %s", sw1, sw2, label);
      Serial.println(_b);
    }
    if (sw1 == 0x6A || sw1 == 0x69)
      break; // error no recuperable, no reintentar
  }
  return false;
}

// buildDolData se movió a core/src/EmvKernel (EmvKernel::buildDolData). El
// perfil de terminal (TERM), el UN de la tarjeta (card.un) y el flag isVisa se
// pasan ahora como argumentos; ver los call sites en GET PROCESSING OPTIONS y
// GENERATE AC.

// ---------------------------------------------------------------------------
// EMV steps
// ---------------------------------------------------------------------------
static bool selectPPSE(uint8_t *resp, uint16_t &len) {
  uint8_t cmd[] = {0x00, 0xA4, 0x04, 0x00, 0x0E, '2', 'P', 'A', 'Y', '.',
                   'S',  'Y',  'S',  '.',  'D',  'D', 'F', '0', '1', 0x00};
  return apduExchange(cmd, sizeof(cmd), resp, len, "SELECT PPSE");
}

static bool selectAID(const uint8_t *aid, uint8_t aidLen, uint8_t *resp,
                      uint16_t &len) {
  uint8_t cmd[32];
  cmd[0] = 0x00;
  cmd[1] = 0xA4;
  cmd[2] = 0x04;
  cmd[3] = 0x00;
  cmd[4] = aidLen;
  memcpy(cmd + 5, aid, aidLen);
  cmd[5 + aidLen] = 0x00;
  return apduExchange(cmd, 6 + aidLen, resp, len, "SELECT AID");
}

static bool getProcessingOptions(uint8_t *fci, uint16_t fciLen, uint8_t *resp,
                                 uint16_t &len, uint64_t amountCents) {
  uint8_t dolData[64];
  uint8_t dolLen = 0;
  int pdolLen = 0;
  uint8_t *pdol = EmvKernel::tlvFind(fci, fciLen - 2, 0x9F38, &pdolLen);
  if (pdol && pdolLen > 0) {
    bool isVisa = (strncmp(card.aidHex, "A00000000310", 12) == 0);
    EmvKernel::buildDolData(pdol, pdolLen, dolData, dolLen, amountCents, TERM,
                            card.un, isVisa);
  }
  uint8_t cmd[72];
  cmd[0] = 0x80;
  cmd[1] = 0xA8;
  cmd[2] = 0x00;
  cmd[3] = 0x00;
  cmd[4] = dolLen + 2;
  cmd[5] = 0x83;
  cmd[6] = dolLen;
  memcpy(cmd + 7, dolData, dolLen);
  cmd[7 + dolLen] = 0x00;
  return apduExchange(cmd, 8 + dolLen, resp, len, "GET PROCESSING OPTIONS");
}

static bool readRecord(uint8_t sfi, uint8_t rec, uint8_t *resp, uint16_t &len) {
  uint8_t cmd[] = {0x00, 0xB2, rec, (uint8_t)((sfi << 3) | 0x04), 0x00};
  char lbl[32];
  sprintf(lbl, "RR sfi=%d r=%d", sfi, rec);
  return apduExchange(cmd, sizeof(cmd), resp, len, lbl);
}

static bool generateAC(uint64_t amountCents, uint8_t *resp, uint16_t &len,
                       uint8_t p1 = 0x80) {
  uint8_t cd[64];
  uint8_t cdLen = 0;
  if (card.cdol1Len > 0) {
    bool isVisa = (strncmp(card.aidHex, "A00000000310", 12) == 0);
    EmvKernel::buildDolData(card.cdol1, card.cdol1Len, cd, cdLen, amountCents,
                            TERM, card.un, isVisa);
  } else {
    uint8_t amtB[6];
    EmvKernel::encodeAmount(amountCents, amtB);
    memcpy(cd + cdLen, amtB, 6);
    cdLen += 6;
    for (int j = 0; j < 6; j++)
      cd[cdLen++] = 0;
    cd[cdLen++] = TERM.country[0];
    cd[cdLen++] = TERM.country[1];
    for (int j = 0; j < 5; j++)
      cd[cdLen++] = TERM.tvr[j];
    cd[cdLen++] = TERM.currency[0];
    cd[cdLen++] = TERM.currency[1];
    cd[cdLen++] =
        (uint8_t)(((TERM.txnDate[0] - '0') << 4) | (TERM.txnDate[1] - '0'));
    cd[cdLen++] =
        (uint8_t)(((TERM.txnDate[2] - '0') << 4) | (TERM.txnDate[3] - '0'));
    cd[cdLen++] =
        (uint8_t)(((TERM.txnDate[4] - '0') << 4) | (TERM.txnDate[5] - '0'));
    cd[cdLen++] = TERM.txnType;
    memcpy(cd + cdLen, card.un, 4);
    cdLen += 4;
    cd[cdLen++] = TERM.type;
  }
  uint8_t cmd[72];
  cmd[0] = 0x80;
  cmd[1] = 0xAE;
  cmd[2] = p1;
  cmd[3] = 0x00;
  cmd[4] = cdLen;
  memcpy(cmd + 5, cd, cdLen);
  cmd[5 + cdLen] = 0x00;
  // Diagnóstico: el log original solo mostraba "# SW=6985 en GENERATE AC" sin
  // el comando que la tarjeta rechazó, lo que forzaba a adivinar. Emitimos el
  // P1/Lc y el CDOL1 descriptor + datos ensamblados para que un SW≠9000 sea
  // diagnosticable en una sola corrida (qué tag/longitud/valor no cuadra). Solo
  // se dispara en la ruta no-qVSDC (Mastercard), nunca en Visa.
  //
  // Fue justo esto lo que confirmó la causa del 6985 en hardware (2026-09-22):
  // la línea "# CDOL1 data=…" mostró el monto arrancando en 000000000500 (BCD
  // correcto) — antes iba en binario (…01F4). Con el monto en BCD (ver
  // EmvKernel::encodeAmount) la Mastercard de prueba dejó de declinar y
  // devolvió ARQC/ATC/IAD reales. Se deja el log activo como herramienta de
  // diagnóstico.
  {
    char dhex[2 * sizeof(card.cdol1) + 1];
    char cdhex[2 * 64 + 1];
    HexUtils::toCompact(card.cdol1, card.cdol1Len, dhex);
    HexUtils::toCompact(cd, cdLen, cdhex);
    char hdr[64];
    snprintf(hdr, sizeof(hdr), "# GEN AC P1=%02X Lc=%u", p1, (unsigned)cdLen);
    Serial.println(hdr);
    Serial.print("#   CDOL1 desc=");
    Serial.println(dhex);
    Serial.print("#   CDOL1 data=");
    Serial.println(cdhex);
  }
  return apduExchange(cmd, 6 + cdLen, resp, len, "GENERATE AC");
}

static bool parseGenerateAC(uint8_t *resp, uint16_t respLen) {
  uint8_t *data = resp;
  int dLen = (respLen > 2) ? respLen - 2 : 0;
  if (dLen < 3)
    return false;
  if (data[0] == 0x77) {
    int tLen = 0;
    uint8_t *inner = EmvKernel::tlvFind(data, dLen, 0x77, &tLen);
    if (!inner)
      return false;
    int al = 0, atl = 0, il = 0;
    uint8_t *ap = EmvKernel::tlvFind(inner, tLen, 0x9F26, &al);
    uint8_t *atp = EmvKernel::tlvFind(inner, tLen, 0x9F36, &atl);
    uint8_t *ip = EmvKernel::tlvFind(inner, tLen, 0x9F10, &il);
    if (!ap || al < 8)
      return false;
    memcpy(card.arqc, ap, 8);
    if (atp && atl >= 2)
      memcpy(card.atc, atp, 2);
    if (ip) {
      card.iadLen = (uint8_t)min(il, (int)sizeof(card.iad));
      memcpy(card.iad, ip, card.iadLen);
    }
    return true;
  }
  if (data[0] == 0x80) {
    // Template 80: tag(1) + len(1-3) + CID(1) + ATC(2) + AC(8) [+ IAD]
    int off = 1;
    if (off >= dLen)
      return false;
    int vlen;
    if (data[off] & 0x80) {
      int nb = data[off] & 0x7F;
      off++;
      if (off + nb > dLen || nb > 2)
        return false;
      vlen = 0;
      for (int j = 0; j < nb; j++)
        vlen = (vlen << 8) | data[off++];
    } else {
      vlen = data[off++];
    }
    if (off + vlen > dLen || vlen < 11)
      return false; // min: CID(1)+ATC(2)+AC(8)
    off++;          // skip CID
    card.atc[0] = data[off++];
    card.atc[1] = data[off++];
    memcpy(card.arqc, data + off, 8);
    off += 8;
    int rem = dLen - off;
    if (rem > 0) {
      card.iadLen = (uint8_t)min(rem, (int)sizeof(card.iad));
      memcpy(card.iad, data + off, card.iadLen);
    }
    return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Flujo EMV completo — un intento
// ---------------------------------------------------------------------------
static bool runEmvFlowOnce(uint64_t amountCents) {
  memset(&card, 0, sizeof(card));
  uint32_t un = hwRand32();
  card.un[0] = (un >> 24) & 0xFF;
  card.un[1] = (un >> 16) & 0xFF;
  card.un[2] = (un >> 8) & 0xFF;
  card.un[3] = un & 0xFF;

  uint8_t resp[EMV_RESP_CAP];
  uint16_t respLen = 0;
  if (!selectPPSE(resp, respLen))
    return false;

  uint8_t ppseAid[16];
  uint8_t ppseAidLen = 0;
  {
    int al = 0;
    uint8_t *ap = EmvKernel::tlvFind(resp, respLen - 2, 0x4F, &al);
    if (ap && al >= 5 && al <= 16) {
      ppseAidLen = (uint8_t)al;
      memcpy(ppseAid, ap, al);
    }
  }

  uint8_t fci[EMV_RESP_CAP];
  uint16_t fciLen = 0;
  bool aidOk = false;
  if (ppseAidLen > 0 && selectAID(ppseAid, ppseAidLen, fci, fciLen)) {
    HexUtils::toCompact(ppseAid, ppseAidLen, card.aidHex);
    strncpy(card.aidName, "DISC", sizeof(card.aidName) - 1);
    aidOk = true;
  }
  for (int a = 0; a < NUM_AIDS && !aidOk; a++) {
    if (selectAID(AIDS[a].bytes, AIDS[a].len, fci, fciLen)) {
      strncpy(card.aidName, AIDS[a].name, sizeof(card.aidName) - 1);
      HexUtils::toCompact(AIDS[a].bytes, AIDS[a].len, card.aidHex);
      aidOk = true;
    }
  }
  if (!aidOk)
    return false;

  uint8_t gpo[EMV_RESP_CAP];
  uint16_t gpoLen = 0;
  if (!getProcessingOptions(fci, fciLen, gpo, gpoLen, amountCents))
    return false;

  int aipL = 0, aflL = 0;
  uint8_t *aipP = EmvKernel::tlvFind(gpo, gpoLen - 2, 0x82, &aipL);
  uint8_t *aflP = EmvKernel::tlvFind(gpo, gpoLen - 2, 0x94, &aflL);
  if (!aipP && gpoLen >= 6 && gpo[0] == 0x80) {
    aipP = gpo + 2;
    aipL = 2;
    aflP = gpo + 4;
    aflL = gpoLen - 6;
  }
  if (aipP && aipL >= 2)
    memcpy(card.aip, aipP, 2);

  bool qvsdc = false, gotPAN = false, gotCDOL = false;
  auto extractFromBuf = [&](uint8_t *gd, int gdl) {
    if (gdl <= 0)
      return;
    int t57l = 0;
    uint8_t *t57 = EmvKernel::tlvFind(gd, gdl, 0x57, &t57l);
    if (t57 && t57l > 0) {
      HexUtils::toCompact(t57, t57l, card.track2);
      char *sep = strchr(card.track2, 'D');
      if (sep) {
        int pl = sep - card.track2;
        if (pl < (int)sizeof(card.pan)) {
          memcpy(card.pan, card.track2, pl);
          card.pan[pl] = '\0';
          strncpy(card.expiry, sep + 1, 4);
          card.expiry[4] = '\0';
          gotPAN = true;
        }
      }
    }
    if (!gotPAN) {
      int ppl = 0;
      uint8_t *pp = EmvKernel::tlvFind(gd, gdl, 0x5A, &ppl);
      if (pp) {
        HexUtils::toCompact(pp, ppl, card.pan);
        int l = strlen(card.pan);
        while (l > 0 && card.pan[l - 1] == 'F')
          card.pan[--l] = '\0';
        gotPAN = true;
      }
    }
    if (card.expiry[0] == '\0') {
      int el = 0;
      uint8_t *ep = EmvKernel::tlvFind(gd, gdl, 0x5F24, &el);
      if (ep && el >= 3) {
        char t[8];
        HexUtils::toCompact(ep, 3, t);
        strncpy(card.expiry, t, 4);
        card.expiry[4] = '\0';
      }
    }
    if (card.label[0] == '\0') {
      int ll = 0;
      uint8_t *lp = EmvKernel::tlvFind(gd, gdl, 0x50, &ll);
      if (lp && ll > 0) {
        int n = min(ll, (int)sizeof(card.label) - 1);
        memcpy(card.label, lp, n);
        card.label[n] = '\0';
      }
    }
    if (!gotCDOL) {
      int cl = 0;
      uint8_t *cp = EmvKernel::tlvFind(gd, gdl, 0x8C, &cl);
      if (cp && cl > 0) {
        card.cdol1Len = (uint8_t)min(cl, (int)sizeof(card.cdol1));
        memcpy(card.cdol1, cp, card.cdol1Len);
        gotCDOL = true;
      }
    }
    int al = 0;
    uint8_t *ap = EmvKernel::tlvFind(gd, gdl, 0x9F26, &al);
    if (ap && al >= 8) {
      memcpy(card.arqc, ap, 8);
      int atcl = 0;
      uint8_t *atcp = EmvKernel::tlvFind(gd, gdl, 0x9F36, &atcl);
      if (atcp && atcl >= 2)
        memcpy(card.atc, atcp, 2);
      int iadl = 0;
      uint8_t *iadp = EmvKernel::tlvFind(gd, gdl, 0x9F10, &iadl);
      if (iadp) {
        card.iadLen = (uint8_t)min(iadl, (int)sizeof(card.iad));
        memcpy(card.iad, iadp, card.iadLen);
      }
      qvsdc = true;
    }
  };
  extractFromBuf(gpo, gpoLen - 2);

  if (!qvsdc && aflP && aflL >= 4) {
    for (int i = 0; i + 3 < aflL; i += 4) {
      uint8_t sfi = (aflP[i] >> 3), from = aflP[i + 1], to = aflP[i + 2];
      for (uint8_t r = from; r <= to; r++) {
        uint8_t rr[EMV_RESP_CAP];
        uint16_t rl = 0;
        if (!readRecord(sfi, r, rr, rl) || rl < 2)
          continue;
        extractFromBuf(rr, rl - 2);
      }
    }
  }
  if (!gotPAN)
    return false;

  if (!qvsdc) {
    // Ruta no-qVSDC (Mastercard M/Chip y demás apps que NO exponen el
    // criptograma en el GPO): el GENERATE AC aporta ARQC/ATC/IAD. Pero los
    // datos identificatorios de la tarjeta (PAN/expiry/track2/AID) YA se
    // extrajeron de los READ RECORD (extractFromBuf, arriba), así que el
    // GENERATE AC es enriquecimiento, no un requisito para "leer" la tarjeta.
    //
    // Visa nunca llega aquí: su criptograma viene gratis en la respuesta al
    // GPO (qvsdc=true) y este bloque se salta por completo. Mastercard, en
    // cambio, puede declinar el GENERATE AC en su gestión de riesgo (p. ej.
    // SW=6985, "conditions of use not satisfied"), lo cual antes hacía fallar
    // TODA la lectura pese a tener ya PAN/track2. Ahora el GENERATE AC es
    // best-effort: si la tarjeta responde, guardamos el criptograma; si lo
    // declina, reportamos la tarjeta igual (el SW real ya quedó logueado por
    // apduExchange y el APDU por generateAC, para diagnóstico posterior).
    //
    // Nota (probado en HW 2026-09-22): la causa real del 6985 resultó ser el
    // monto en binario, ya corregido a BCD (EmvKernel::encodeAmount), así que
    // la Mastercard de prueba ahora SÍ acepta el GENERATE AC y este best-effort
    // no llega a activarse en el flujo feliz. Se conserva como red de
    // seguridad: otra tarjeta/monto podría declinarlo por otra condición y la
    // lectura de PAN/track2 no debe caerse por eso.
    uint8_t gen[EMV_RESP_CAP];
    uint16_t genLen = 0;
    if (generateAC(amountCents, gen, genLen))
      parseGenerateAC(gen, genLen);
    else
      Serial.println("# GENERATE AC declinado por la tarjeta; se reporta "
                     "PAN/track2 sin criptograma (ARQC/ATC/IAD)");
  }
  card.valid = true;
  return true;
}

// Wrapper con hasta 3 intentos: re-init NFC y re-detección entre intentos
static bool runEmvFlow(uint64_t amountCents) {
  for (int attempt = 0; attempt < 3; attempt++) {
    if (attempt > 0) {
      SLOGF("# Reintento EMV %d/3...", attempt + 1);
      nfc.raw().waitForTagRemoval();
      nfc.raw().stopDiscovery();
      nfc.raw().startDiscovery();
      // Esperar re-detección de la tarjeta (máx 6s)
      unsigned long tw = millis();
      bool found = false;
      while (millis() - tw < 6000) {
        if (nfc.raw().isTagDetected() &&
            nfc.raw().remoteDevice.getProtocol() == nfc.raw().protocol.ISODEP) {
          found = true;
          break;
        }
        delay(50);
      }
      if (!found) {
        SLOGF("# Tarjeta perdida en reintento %d", attempt + 1);
        return false;
      }
    }
    if (runEmvFlowOnce(amountCents))
      return true;
    SLOGF("# Flujo EMV fallo (intento %d/3)", attempt + 1);
    delay(100);
  }
  return false;
}

// ---------------------------------------------------------------------------
// Helpers NFC card management
// ---------------------------------------------------------------------------
static bool pollCard(unsigned long timeoutMs = 20000) {
  unsigned long t = millis();
  int lastSec = -1;
  while (millis() - t < timeoutMs) {
    if (nfc.raw().isTagDetected() &&
        nfc.raw().remoteDevice.getProtocol() == nfc.raw().protocol.ISODEP)
      return true;
    int sec = (int)((millis() - t) / 1000);
    if (sec != lastSec) {
      lastSec = sec;
      SLOGF("Esperando tarjeta... %ds/%ds", sec, (int)(timeoutMs / 1000));
    }
    control.poll(); // atiende ping/info/identify durante la espera
    delay(100);
  }
  return false;
}

static void releaseCard() {
  nfc.raw().waitForTagRemoval();
  nfc.raw().stopDiscovery();
  nfc.raw().startDiscovery();
}

// ---------------------------------------------------------------------------
// buildWebJson para /scan
// ---------------------------------------------------------------------------
static void buildWebJson(uint64_t amountCents) {
  JsonDocument doc;
  char buf[70];
  doc["ok"] = true;
  doc["pan"] = card.pan;
  doc["expiry"] = card.expiry;
  doc["label"] = card.label;
  doc["track2"] = card.track2;
  doc["aid"] = card.aidHex;
  doc["aidName"] = card.aidName;
  HexUtils::toCompact(card.arqc, 8, buf);
  doc["arqc"] = buf;
  HexUtils::toCompact(card.atc, 2, buf);
  doc["atc"] = buf;
  HexUtils::toCompact(card.aip, 2, buf);
  doc["aip"] = buf;
  HexUtils::toCompact(card.un, 4, buf);
  doc["un"] = buf;
  HexUtils::toCompact(card.iad, card.iadLen, buf);
  doc["iad"] = buf;
  HexUtils::toCompact(card.cdol1, card.cdol1Len, buf);
  doc["cdol1"] = buf;
  HexUtils::toCompact(TERM.ttq, 4, buf);
  doc["ttq"] = buf;
  HexUtils::toCompact(TERM.cvmResults, 3, buf);
  doc["cvmResults"] = buf;
  doc["amount_cents"] = (uint32_t)amountCents;
  doc["txn_date"] =
      TERM.txnDate; // YYMMDD (tag 9A del CDOL) — misma fuente que EmvKernel
  serializeJson(doc, webResult, sizeof(webResult));
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// HTML — Banking Test Suite UI (button-first dashboard)
// ---------------------------------------------------------------------------
static const char PAGE_HTML[] =
    "<!DOCTYPE html><html lang='es'><head>"
    "<meta charset='UTF-8'><meta name='viewport' "
    "content='width=device-width,initial-scale=1,maximum-scale=1'>"
    "<meta name='theme-color' content='#07090f'>"
    "<meta name='description' content='EMVyBomberCat — firmware companero de "
    "EMVy Controller'>"
    "<link rel='icon' href=\"data:image/svg+xml,%3Csvg "
    "xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Crect "
    "width='24' height='24' rx='5' fill='%2307090f'/%3E%3Cpath d='M12 4 L20 18 "
    "L4 18 Z' fill='none' stroke='%2300e676' stroke-width='2'/%3E%3C/svg%3E\">"
    "<title>EMVyBomberCat &middot; EMVy Controller</title>"
    "<style>"
    "*{box-sizing:border-box;margin:0;padding:0}"
    ":root{"
    "--bg:#07090f;--s1:#0d1117;--s2:#161b22;--s3:#1c2128;"
    "--green:#00e676;--gd:#00e67622;--red:#ff5252;--rd:#ff525222;"
    "--yellow:#ffc107;--yd:#ffc10722;--blue:#40c4ff;--bd:#40c4ff22;"
    "--purple:#ce93d8;--orange:#ff7043;"
    "--text:#c9d1d9;--dim:#484f58;--border:#30363d;--r:8px;"
    "--f:'Courier New',monospace}"
    "body{background:var(--bg);color:var(--text);font-family:var(--f);"
    "height:100dvh;display:flex;flex-direction:column;overflow:hidden}"
    "header{flex-shrink:0;display:flex;align-items:center;gap:10px;padding:"
    "10px 14px;"
    "border-bottom:1px solid var(--border);background:var(--s1)}"
    ".brand{display:flex;align-items:center;gap:8px;flex:1;min-width:0}"
    ".brand-mark{width:26px;height:26px;border-radius:6px;background:var(--gd);"
    "border:1px solid "
    "var(--green);color:var(--green);display:flex;align-items:center;"
    "justify-content:center;font-weight:700;font-size:.8rem;flex-shrink:0}"
    "h1{font-size:.9rem;letter-spacing:2px;color:var(--green);white-space:"
    "nowrap;"
    "overflow:hidden;text-overflow:ellipsis}"
    "h1 small{color:var(--dim);font-size:.6rem;letter-spacing:1px}"
    ".chip{padding:2px 8px;border-radius:20px;font-size:.58rem;border:1px "
    "solid}"
    ".chip-g{color:var(--green);border-color:var(--green);background:var(--gd)}"
    ".chip-b{color:var(--blue);border-color:var(--blue);background:var(--bd)}"
    ".chip-p{color:var(--purple);border-color:var(--purple);background:#"
    "ce93d822}"
    "footer{flex-shrink:0;padding:6px 14px;text-align:center;font-size:.62rem;"
    "color:var(--dim);border-top:1px solid var(--border);background:var(--s1)}"
    "footer b{color:var(--green)}"
    "#sbar{flex-shrink:0;display:flex;align-items:center;gap:8px;padding:7px "
    "14px;"
    "background:var(--s1);border-bottom:1px solid "
    "var(--border);font-size:.78rem}"
    ".dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}"
    "@keyframes blink{0%,100%{opacity:1}50%{opacity:.15}}"
    ".blink{animation:blink .8s ease-in-out infinite}"
    ".main{flex:1;overflow-y:auto;padding:12px;display:flex;flex-direction:"
    "column;gap:10px;"
    "-webkit-overflow-scrolling:touch}"
    "/* Mobile-first: single column */"
    ".grid{display:grid;grid-template-columns:1fr;gap:10px}"
    "#toprow{display:flex;flex-direction:column;gap:10px}"
    ".card{background:var(--s1);border:1px solid "
    "var(--border);border-radius:var(--r);padding:14px}"
    ".card-h{font-size:.6rem;letter-spacing:2px;text-transform:uppercase;"
    "margin-bottom:10px;display:flex;align-items:center;gap:6px}"
    ".cdot{width:7px;height:7px;border-radius:50%;flex-shrink:0}"
    ".scan-card{background:var(--s1);border:1px solid "
    "var(--green);border-radius:var(--r);padding:14px}"
    ".btns{display:flex;flex-wrap:wrap;gap:7px}"
    "/* Larger touch targets for mobile */"
    ".tbtn{display:inline-flex;align-items:center;justify-content:center;"
    "padding:9px 14px;border:1px solid var(--border);border-radius:6px;"
    "font-family:var(--f);font-size:.82rem;cursor:pointer;background:var(--s2);"
    "color:var(--text);"
    "transition:all .15s;white-space:nowrap;min-height:40px;"
    "-webkit-tap-highlight-color:transparent;user-select:none}"
    ".tbtn:hover:not([disabled]){border-color:var(--blue);color:var(--blue)}"
    ".tbtn:active:not([disabled]){filter:brightness(1.25)}"
    ".tbtn[disabled]{opacity:.45;cursor:not-allowed}"
    ".tbtn.run{border-color:var(--yellow);background:var(--yd);color:var(--"
    "yellow);"
    "animation:blink .8s infinite}"
    ".tbtn.ok{border-color:var(--green);background:var(--gd);color:var(--green)"
    "}"
    ".tbtn.fail{border-color:var(--red);background:var(--rd);color:var(--red)}"
    ".inp{background:var(--s3);border:1px solid "
    "var(--border);color:var(--text);"
    "font-family:var(--f);font-size:.82rem;padding:7px 10px;"
    "border-radius:6px;min-height:38px;-webkit-appearance:none}"
    ".inp:focus{outline:none;border-color:var(--blue)}"
    ".row{display:flex;align-items:center;gap:8px;flex-wrap:wrap}"
    ".btn{display:inline-flex;align-items:center;gap:5px;padding:9px 14px;"
    "border:1px "
    "solid;border-radius:var(--r);font-family:var(--f);font-size:.82rem;"
    "cursor:pointer;transition:all .15s;min-height:40px;"
    "-webkit-tap-highlight-color:transparent;user-select:none}"
    ".btn-g{background:var(--green);color:#000;border-color:var(--green);font-"
    "weight:700}"
    ".btn-g:hover{filter:brightness(1.1)}"
    ".btn-g:disabled{background:var(--s3);color:var(--dim);border-color:var(--"
    "border);cursor:not-allowed}"
    ".btn-r{background:var(--rd);color:var(--red);border-color:var(--red)}"
    ".btn-r:hover{background:var(--red);color:#fff}"
    ".btn-d{background:var(--s2);color:var(--text);border-color:var(--border)}"
    ".btn-d:hover{border-color:var(--blue);color:var(--blue)}"
    ".scan-res{margin-top:12px;padding-top:10px;border-top:1px solid "
    "var(--border)}"
    ".tbl{width:100%;border-collapse:collapse;font-size:.78rem}"
    ".tbl "
    "th{color:var(--dim);font-size:.6rem;letter-spacing:1px;text-align:left;"
    "padding:5px 8px;border-bottom:1px solid var(--border)}"
    ".tbl td{padding:5px 8px;border-bottom:1px solid "
    "var(--border);word-break:break-all}"
    ".tbl td:first-child{color:var(--dim);white-space:nowrap;width:72px}"
    ".tbl tr:last-child td{border-bottom:none}"
    ".tbl tr:hover td{background:var(--s2)}"
    ".raw{background:var(--s2);padding:8px;border-radius:4px;font-size:.65rem;"
    "overflow:auto;max-height:130px;border:1px solid var(--border);"
    "color:var(--green);white-space:pre;margin-top:7px}"
    ".sep{height:1px;background:var(--border);margin:10px 0}"
    ".console-wrap{flex-shrink:0;border-top:2px solid var(--border)}"
    ".console-hdr{display:flex;align-items:center;padding:5px 10px;"
    "border-bottom:1px solid var(--border);background:var(--s1);gap:6px}"
    ".console-hdr "
    ".ctitle{flex:1;font-size:.58rem;letter-spacing:2px;color:var(--dim)}"
    "#console{height:130px;overflow-y:auto;padding:5px 12px;font-size:.72rem;"
    "background:var(--bg);-webkit-overflow-scrolling:touch}"
    ".cl-ok{color:var(--green)}.cl-err{color:var(--red)}"
    ".cl-info{color:var(--blue)}.cl-warn{color:var(--yellow)}.cl-dim{color:var("
    "--dim)}"
    "/* Tablet 600px: 2 columns */"
    "@media(min-width:600px){"
    ".grid{grid-template-columns:repeat(2,1fr)}"
    "#toprow{flex-direction:row}"
    "#toprow>.scan-card{flex:1.4;min-width:0}"
    "#toprow>.card{flex:1;min-width:0}}"
    "/* Desktop 960px: auto-fill */"
    "@media(min-width:960px){"
    ".grid{grid-template-columns:repeat(auto-fill,minmax(240px,1fr))}"
    "#console{height:155px}}"
    "</style></head><body>"
    "<header>"
    "<div class='brand'>"
    "<div class='brand-mark'>&#9651;</div>"
    "<h1>EMVyBomberCat <small>parte de EMVy Controller &middot; "
    "v" BOMBERCAT_FW_VERSION "</small></h1>"
    "</div>"
    "<span class='chip chip-p'>EMVy</span>"
    "<span class='chip chip-g'>HTTP</span>"
    "<span class='chip chip-b'>PN7150</span>"
    "</header>"
    "<div id='sbar'>"
    "<div class='dot' id='dot' style='background:var(--dim)'></div>"
    "<span id='stxt'>Listo.</span>"
    "</div>"
    "<div class='main'>"

    /* ----- Top row: Scan card + Hardware card ----- */
    "<div id='toprow'>"

    /* Scan card */
    "<div class='scan-card'>"
    "<div class='card-h'><div class='cdot' "
    "style='background:var(--green)'></div>"
    "<span style='color:var(--green)'>LEER TARJETA</span></div>"
    "<div class='row'>"
    "<span style='font-size:.75rem;color:var(--dim)'>Monto:</span>"
    "<input id='scanAmt' class='inp' type='number' value='5.00' min='0' "
    "step='0.01' style='width:100px'>"
    "<span style='font-size:.72rem;color:var(--dim)'>MXN</span>"
    "<button class='btn btn-g' id='btnScan' onclick='doScan()'>&#9654; "
    "Leer</button>"
    "<button class='btn btn-r' id='btnCS' style='display:none' "
    "onclick='cancelScan()'>&#9632; Cancelar</button>"
    "</div>"
    "<div id='rpanel' class='scan-res' style='display:none'>"
    "<table class='tbl'><thead><tr><th>Campo</th><th>Valor</th></tr></thead>"
    "<tbody id='rtbody'></tbody></table>"
    "<div class='row' style='margin-top:8px'>"
    "<button class='btn btn-d' style='font-size:.65rem;padding:5px "
    "10px;min-height:32px' onclick='dlJSON()'>&#8595; JSON</button>"
    "<button class='btn btn-d' style='font-size:.65rem;padding:5px "
    "10px;min-height:32px' onclick='toggleRaw()'>{ } Raw</button>"
    "</div>"
    "<div id='rawj' class='raw' style='display:none'></div>"
    "</div></div>"

    /* Hardware card */
    "<div class='card'>"
    "<div class='card-h'><div class='cdot' "
    "style='background:var(--blue)'></div>"
    "<span style='color:var(--blue)'>HARDWARE</span></div>"
    "<div class='btns'>"
    "<button class='tbtn' data-id='hw_nfc' onclick='runFromBtn(this)'>NFC "
    "Init</button>"
    "<button class='tbtn' data-id='hw_wifi' onclick='runFromBtn(this)'>WiFi "
    "AP</button>"
    "<button class='tbtn' data-id='hw_mem' onclick='runFromBtn(this)'>RAM "
    "Check</button>"
    "</div></div></div>" /* end toprow */

    /* ----- 2×2 / 4-col grid: NFC / ID / EMV / Security ----- */
    "<div class='grid'>"

    /* NFC Scan */
    "<div class='card'>"
    "<div class='card-h'><div class='cdot' "
    "style='background:var(--yellow)'></div>"
    "<span style='color:var(--yellow)'>ESCANEO NFC</span></div>"
    "<div class='btns'>"
    "<button class='tbtn' data-id='nfc_any' "
    "onclick='runFromBtn(this)'>Cualquier tag</button>"
    "<button class='tbtn' data-id='nfc_iso' onclick='runFromBtn(this)'>ISO-DEP "
    "/ EMV</button>"
    "</div></div>"

    /* Identificacion */
    "<div class='card'>"
    "<div class='card-h'><div class='cdot' "
    "style='background:var(--purple)'></div>"
    "<span style='color:var(--purple)'>IDENTIFICACI&#211;N</span></div>"
    "<div class='btns'>"
    "<button class='tbtn' data-id='id_ppse' "
    "onclick='runFromBtn(this)'>PPSE&#8594;AIDs</button>"
    "<button class='tbtn' data-id='id_aids' onclick='runFromBtn(this)'>14 "
    "AIDs</button>"
    "<button class='tbtn' data-id='id_pan' "
    "onclick='runFromBtn(this)'>PAN/Expiry</button>"
    "<button class='tbtn' data-id='id_dump' onclick='runFromBtn(this)'>Dump "
    "SFI</button>"
    "</div></div>"

    /* EMV Protocol */
    "<div class='card'>"
    "<div class='card-h'><div class='cdot' "
    "style='background:var(--green)'></div>"
    "<span style='color:var(--green)'>PROTOCOLO EMV</span></div>"
    "<div class='btns'>"
    "<button class='tbtn' data-id='emv_ppse' onclick='runFromBtn(this)'>SELECT "
    "PPSE</button>"
    "<button class='tbtn' data-id='emv_aid' onclick='runFromBtn(this)'>SELECT "
    "AID</button>"
    "<button class='tbtn' data-id='emv_gpo' onclick='runFromBtn(this)'>GET "
    "GPO</button>"
    "<button class='tbtn' data-id='emv_rr' onclick='runFromBtn(this)'>READ "
    "RECORD</button>"
    "<button class='tbtn' data-id='emv_ac' onclick='runFromBtn(this)'>GENERATE "
    "AC</button>"
    "</div></div>"

    /* Security Probes */
    "<div class='card'>"
    "<div class='card-h'><div class='cdot' style='background:var(--red)'></div>"
    "<span style='color:var(--red)'>SONDAS SEGURIDAD</span></div>"
    "<div class='btns'>"
    "<button class='tbtn' data-id='probe_atc' onclick='runFromBtn(this)'>Leer "
    "ATC</button>"
    "<button class='tbtn' data-id='probe_cvm' onclick='runFromBtn(this)'>CVM "
    "List</button>"
    "<button class='tbtn' data-id='probe_caps' "
    "onclick='runFromBtn(this)'>SDA/DDA/CDA</button>"
    "<button class='tbtn' data-id='probe_lim' "
    "onclick='runFromBtn(this)'>L&#237;mites CL</button>"
    "<button class='tbtn' data-id='probe_off' onclick='runFromBtn(this)'>AAC "
    "Offline</button>"
    "</div></div>"
    "</div>" /* end grid */

    /* ----- Transactions card (full width) ----- */
    "<div class='card'>"
    "<div class='card-h'><div class='cdot' "
    "style='background:var(--orange)'></div>"
    "<span style='color:var(--orange)'>TRANSACCIONES</span></div>"
    "<div class='btns'>"
    "<button class='tbtn' data-id='txn_zero' "
    "onclick='runFromBtn(this)'>$0.00</button>"
    "<button class='tbtn' data-id='txn_5' onclick='runFromBtn(this)'>$5.00 "
    "MXN</button>"
    "<button class='tbtn' data-id='txn_500' onclick='runFromBtn(this)'>$500 "
    "MXN</button>"
    "<button class='tbtn' data-id='txn_1k' onclick='runFromBtn(this)'>$1,000 "
    "MXN</button>"
    "<button class='tbtn' data-id='txn_5k' onclick='runFromBtn(this)'>$5,000 "
    "MXN</button>"
    "<button class='tbtn' data-id='txn_3x' onclick='runFromBtn(this)'>3&#215; "
    "ATC</button>"
    "</div>"
    "<div class='sep'></div>"
    "<div class='row'>"
    "<span style='font-size:.75rem;color:var(--dim)'>Personalizado:</span>"
    "<input id='custAmt' class='inp' type='number' value='100.00' min='0' "
    "step='0.01' style='width:110px'>"
    "<span style='font-size:.72rem;color:var(--dim)'>MXN</span>"
    "<button class='tbtn' id='btn_txn_custom' onclick='runCustomTxn()'>&#9654; "
    "Cobrar</button>"
    "</div></div>"

    /* ----- Herramientas EMVy (navaja suiza NFC / NDEF / banda) full width
       ----- */
    "<div class='card'>"
    "<div class='card-h'><div class='cdot' "
    "style='background:var(--purple)'></div>"
    "<span style='color:var(--purple)'>HERRAMIENTAS EMVy</span></div>"
    "<div class='btns'>"
    "<button class='tbtn' onclick='emvyTag()'>Leer UID (TAG)</button>"
    "<button class='tbtn' onclick='emvyNfcInfo()'>Diagn&#243;stico NFC</button>"
    "</div>"
    "<div class='sep'></div>"
    "<div class='row'>"
    "<span style='font-size:.72rem;color:var(--dim)'>Emular NDEF (hex):</span>"
    "<input id='emuHex' class='inp' style='flex:1;min-width:180px' "
    "placeholder='D101...' "
    "value='D101125504656D76792E746573742F6465662D636F6E'>"
    "<button class='tbtn' onclick='emvyEmu()'>Emular tag NFC</button>"
    "</div>"
    "<div class='row'>"
    "<span style='font-size:.72rem;color:var(--dim)'>Magspoof:</span>"
    "<input id='magT1' class='inp' style='flex:1;min-width:120px' "
    "placeholder='track1 (%B..?)'>"
    "<input id='magT2' class='inp' style='flex:1;min-width:120px' "
    "placeholder='track2 (;..?)'>"
    "<button class='tbtn' onclick='emvyMag()'>Enviar banda</button>"
    "</div></div>"

    "</div>" /* end main */

    /* ----- Console ----- */
    "<div class='console-wrap'>"
    "<div class='console-hdr'>"
    "<span class='ctitle'>&#9654; CONSOLA</span>"
    "<button class='btn btn-d' id='btnTogCons' "
    "style='font-size:.62rem;padding:4px 9px;min-height:28px' "
    "onclick='toggleConsole()'>&#9660;</button>"
    "<button class='btn btn-d' style='font-size:.62rem;padding:4px "
    "9px;min-height:28px' onclick='clearLog()'>&#10006;</button>"
    "</div>"
    "<div id='console'></div>"
    "</div>"

    /* ----- Footer: credito EMVy ----- */
    "<footer>EMVyBomberCat v" BOMBERCAT_FW_VERSION
    " &middot; parte de <b>EMVy Controller</b> "
    "&middot; passthrough APDU activo (serie @115200)</footer>"

    "<script>"
    "var running=false,scan=false,scanCtrl=null,lastCard=null,consOpen=true;"
    "function sleep(ms){return new Promise(function(r){setTimeout(r,ms);})}"
    "function setSt(msg,type){"
    "var "
    "d=document.getElementById('dot'),s=document.getElementById('stxt'),b="
    "document.getElementById('sbar');"
    "b.style.borderLeft=type?'3px solid var(--'+type+')':'';"
    "d.className='dot'+(type==='yellow'?' blink':'');"
    "d.style.background=type==='green'?'var(--green)':type==='red'?'var(--red)'"
    ":type==='yellow'?'var(--yellow)':'var(--dim)';"
    "s.textContent=msg;}"
    "function clog(msg,type){"
    "var el=document.getElementById('console');"
    "var d=document.createElement('div');"
    "d.className='cl-'+(type||'dim');"
    "d.textContent='> '+msg;"
    "el.appendChild(d);"
    "if(el.children.length>400)el.removeChild(el.children[0]);"
    "el.scrollTop=el.scrollHeight;"
    "if(!consOpen)toggleConsole();}"
    "function clearLog(){document.getElementById('console').innerHTML='';}"
    "function toggleConsole(){"
    "consOpen=!consOpen;"
    "var el=document.getElementById('console');"
    "var btn=document.getElementById('btnTogCons');"
    "var ctitle=document.querySelector('.ctitle');"
    "el.style.display=consOpen?'':'none';"
    "btn.innerHTML=consOpen?'&#9660;':'&#9654;';"
    "ctitle.textContent=consOpen?'&#9660; CONSOLA':'&#9654; CONSOLA';}"
    "async function runT(id,extra){"
    "if(running)return;"
    "running=true;"
    "var btn=document.querySelector('[data-id=\"'+id+'\"]');"
    "if(!btn)btn=document.getElementById('btn_'+id);"
    "if(btn){btn.className='tbtn run';btn.setAttribute('disabled','');}"
    "setSt('Ejecutando: '+id,'yellow');"
    "clog('--- '+id+' ---','dim');"
    "try{"
    "var resp=await fetch('/test?id='+id+(extra||''));"
    "var rdr=resp.body.getReader();"
    "var dec=new TextDecoder(),buf='',d=null,done2=false;"
    "while(!done2){"
    "var ck=await rdr.read();done2=ck.done;"
    "if(ck.value)buf+=dec.decode(ck.value,{stream:!done2});"
    "var lines=buf.split('\\n');buf=lines.pop();"
    "for(var li=0;li<lines.length;li++){"
    "var ln=lines[li].trim();if(!ln)continue;"
    "try{"
    "var msg=JSON.parse(ln);"
    "if(msg.t==='log'){"
    "var isW=msg.m.indexOf('Esperando')===0;"
    "if(isW)setSt(msg.m,'yellow');"
    "clog(msg.m,isW?'dim':'info');"
    "}else if(msg.t==='r'){d=msg;}"
    "}catch(pe){}}"
    "}"
    "if(!d)d={pass:false,detail:'Sin respuesta del stream',ms:0};"
    "if(btn){btn.className='tbtn "
    "'+(d.pass?'ok':'fail');btn.removeAttribute('disabled');}"
    "setSt((d.pass?'OK ✓: ':'FAIL ✗: ')+id+(d.ms?' "
    "('+d.ms+'ms)':''),d.pass?'green':'red');"
    "clog((d.pass?'PASS':'FAIL')+': '+id+(d.detail?' — '+d.detail:'')+(d.ms?' "
    "['+d.ms+'ms]':''),d.pass?'ok':'err');"
    "}catch(e){"
    "if(btn){btn.className='tbtn fail';btn.removeAttribute('disabled');}"
    "clog('ERROR: '+id+' — '+(e.message||e),'err');"
    "setSt('Error en: '+id,'red');"
    "}"
    "running=false;}"
    "function runFromBtn(b){runT(b.dataset.id);}"
    "function runCustomTxn(){"
    "if(running)return;"
    "var v=parseFloat(document.getElementById('custAmt').value)||0;"
    "var cents=Math.round(v*100);if(cents<0)cents=0;"
    "clog('Monto personalizado: $'+v.toFixed(2)+' MXN ('+cents+' cts)','info');"
    "runT('txn_custom','&amt='+cents);}"
    /* --- Herramientas EMVy: llaman a los endpoints /tag /nfcinfo /emu /mag ---
     */
    "async function emvyGet(url,label){"
    "clog(label+'...','info');setSt(label,'yellow');"
    "try{var r=await fetch(url);var j=await r.json();"
    "clog(label+': '+JSON.stringify(j),j.ok?'ok':'err');"
    "setSt(j.ok?(label+' OK'):(label+' fallo'),j.ok?'green':'red');return j;}"
    "catch(e){clog(label+' ERROR: "
    "'+(e.message||e),'err');setSt('Error','red');}}"
    "function emvyTag(){emvyGet('/tag','Leer UID');}"
    "function emvyNfcInfo(){emvyGet('/nfcinfo','Diagn\\u00f3stico NFC');}"
    "function emvyEmu(){var "
    "h=(document.getElementById('emuHex').value||'').replace(/\\s/g,'');"
    "emvyGet('/emu?hex='+encodeURIComponent(h),'Emular NDEF (20s)');}"
    "function emvyMag(){var t1=document.getElementById('magT1').value||'';"
    "var t2=document.getElementById('magT2').value||'';"
    "emvyGet('/"
    "mag?t1='+encodeURIComponent(t1)+'&t2='+encodeURIComponent(t2),'Magspoof');"
    "}"
    "async function doScan(){"
    "if(running||scan)return;"
    "scan=true;running=true;"
    "var "
    "amt=Math.round((parseFloat(document.getElementById('scanAmt').value)||5)*"
    "100);"
    "if(amt<0)amt=0;"
    "var sb=document.getElementById('btnScan');"
    "var cs=document.getElementById('btnCS');"
    "if(sb)sb.disabled=true;"
    "if(cs)cs.style.display='inline-flex';"
    "document.getElementById('rpanel').style.display='none';"
    "setSt('Acercando tarjeta... $'+(amt/100).toFixed(2)+' MXN','yellow');"
    "clog('Lectura iniciada — monto: $'+(amt/100).toFixed(2)+' MXN','info');"
    "scanCtrl=new AbortController();"
    "try{"
    "var r=await fetch('/scan?amt='+amt,{signal:scanCtrl.signal});"
    "var d=await r.json();"
    "if(d.ok){lastCard=d;showCard(d);setSt('Tarjeta leída.','green');clog('OK "
    "— PAN: '+d.pan+' | '+d.aidName,'ok');}"
    "else{setSt('Error: '+(d.error||'fallo EMV'),'red');clog('Error: "
    "'+(d.error||'fallo EMV'),'err');}"
    "}catch(e){if(scan){setSt('Error: '+(e.message||e),'red');clog('Error de "
    "red: '+(e.message||e),'err');}}"
    "scan=false;running=false;"
    "if(sb)sb.disabled=false;"
    "if(cs)cs.style.display='none';}"
    "function cancelScan(){"
    "scan=false;running=false;"
    "if(scanCtrl)scanCtrl.abort();"
    "setSt('Cancelado.','');"
    "var "
    "sb=document.getElementById('btnScan'),cs=document.getElementById('btnCS');"
    "if(sb)sb.disabled=false;if(cs)cs.style.display='none';}"
    "function showCard(d){"
    "var exp='20'+d.expiry.substring(0,2)+'/'+d.expiry.substring(2,4);"
    "var rows=[['Red',d.aidName+(d.aid?' ('+d.aid+')':'')],"
    "['Label',d.label||'—'],['PAN',d.pan],['Expiry',exp],"
    "['ARQC',d.arqc],['ATC',d.atc],['AIP',d.aip],['IAD',d.iad],"
    "['UN',d.un],['Monto',d.amount_cents+' cts MXN']];"
    "var tb=document.getElementById('rtbody');tb.innerHTML='';"
    "rows.forEach(function(row){"
    "var tr=document.createElement('tr');"
    "row.forEach(function(v){var "
    "td=document.createElement('td');td.textContent=v;tr.appendChild(td);});"
    "tb.appendChild(tr);});"
    "document.getElementById('rawj').textContent=JSON.stringify(d,null,2);"
    "document.getElementById('rpanel').style.display='block';}"
    "function dlJSON(){"
    "if(!lastCard)return;"
    "var b=new "
    "Blob([JSON.stringify(lastCard,null,2)],{type:'application/json'});"
    "var u=URL.createObjectURL(b),a=document.createElement('a');"
    "a.href=u;a.download='card_'+lastCard.pan+'_'+lastCard.expiry+'.json';"
    "document.body.appendChild(a);a.click();document.body.removeChild(a);URL."
    "revokeObjectURL(u);}"
    "function toggleRaw(){"
    "var e=document.getElementById('rawj');"
    "e.style.display=e.style.display==='none'?'block':'none';}"
    // Polling de /log para mostrar actividad serial en la consola web
    "var logCursor=0;"
    "async function pollLog(){"
    "try{"
    "var r=await fetch('/log?from='+logCursor);"
    "var d=await r.json();"
    "if(d.head>logCursor){"
    "d.lines.forEach(function(l){clog(l,'info');});"
    "logCursor=d.head;"
    "}}"
    "catch(e){}"
    "setTimeout(pollLog,500);}"
    "pollLog();"
    "</script></body></html>";

// ---------------------------------------------------------------------------
// NFC reset
// ---------------------------------------------------------------------------
// NfcController::reset() reproduce connectNCI+configureSettings+configMode+
// startDiscovery en ese orden (igual que el bring-up legacy), pero devuelve
// false en vez de colgar en while(true) — el fallo queda en gNfcFault, que
// controlState() reporta como "hw-error" sin dejar la placa muda.
static void resetNFC() {
  gNfcFault = !nfc.reset();
  if (gNfcFault) {
    Serial.println("# ERROR NFC bring-up (connectNCI/configureSettings/"
                   "configMode) — chip no responde; usa NFCINFO para "
                   "reintentar");
  }
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------
static void sendHeaders(WiFiClient &client, const char *ct) {
  client.println("HTTP/1.1 200 OK");
  client.print("Content-Type: ");
  client.println(ct);
  client.println("Connection: close");
  client.println();
}
static void sendJson(WiFiClient &client, const char *json) {
  sendHeaders(client, "application/json");
  client.print(json);
}
static void streamBody(WiFiClient &client, const char *buf, size_t len) {
  const size_t CHUNK = 512;
  size_t sent = 0;
  while (sent < len) {
    size_t n = (len - sent < CHUNK) ? (len - sent) : CHUNK;
    client.write((const uint8_t *)buf + sent, n);
    sent += n;
  }
}

// Nibble hex único para el %XX de qparam() — no confundir con
// HexUtils::decode (cadena completa), que resuelve un problema distinto
// (payloads EMV) y vive en core/ desde la Fase 4.
static int _hexNib(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  return -1;
}

// Extrae y decodifica (%XX, +) un parámetro de query de la línea de request.
static String qparam(const String &req, const char *key) {
  String pat = String(key) + "=";
  int i = req.indexOf(pat);
  if (i < 0)
    return String("");
  i += pat.length();
  int e1 = req.indexOf(' ', i);
  int e2 = req.indexOf('&', i);
  int end = (e2 >= 0 && (e1 < 0 || e2 < e1)) ? e2 : e1;
  if (end < 0)
    end = req.length();
  String raw = req.substring(i, end), out;
  out.reserve(raw.length());
  for (int j = 0; j < (int)raw.length(); j++) {
    char c = raw[j];
    if (c == '+')
      out += ' ';
    else if (c == '%' && j + 2 < (int)raw.length()) {
      int hi = _hexNib(raw[j + 1]), lo = _hexNib(raw[j + 2]);
      if (hi >= 0 && lo >= 0) {
        out += (char)((hi << 4) | lo);
        j += 2;
      } else
        out += c;
    } else
      out += c;
  }
  return out;
}

// ---------------------------------------------------------------------------
// handleTest — 25 test cases
// ---------------------------------------------------------------------------
static void handleTest(WiFiClient &client, const String &id) {
  gSC = &client;
  client.println("HTTP/1.1 200 OK");
  client.println("Content-Type: application/x-ndjson");
  client.println("Connection: close");
  client.println();
  unsigned long t0 = millis();
  bool pass = false;
  char detail[180] = "";

  // =========================================================
  // HARDWARE — no card
  // =========================================================
  if (id == "hw_nfc") {
    SLOGF("Verificando PN7150 via NCI (IRQ=%d VEN=%d)...", PN7150_IRQ,
          PN7150_VEN);
    pass = (nfc.raw().connectNCI() == 0);
    if (pass) {
      nfc.raw().configureSettings();
      nfc.raw().configMode();
      nfc.raw().startDiscovery();
      SLOGF("NCI OK — I2C 0x%02X", PN7150_ADDR);
      snprintf(detail, sizeof(detail),
               "PN7150 NCI OK | IRQ=%d VEN=%d I2C=0x%02X", PN7150_IRQ,
               PN7150_VEN, PN7150_ADDR);
    } else {
      SLOGF("connectNCI fallo");
      strcpy(detail, "connectNCI fallo — verificar SDA/SCL/IRQ/VEN");
    }

  } else if (id == "hw_wifi") {
    SLOGF("Verificando estado AP WiFi...");
    pass = (WiFi.status() == WL_AP_LISTENING || WiFi.status() == WL_CONNECTED);
    IPAddress ip = WiFi.localIP();
    SLOGF("AP: %s | IP: %d.%d.%d.%d", AP_SSID, ip[0], ip[1], ip[2], ip[3]);
    SLOGF("FW NINA: %s", WiFi.firmwareVersion());
    snprintf(detail, sizeof(detail), "AP: %s | IP: %d.%d.%d.%d | FW: %s",
             AP_SSID, ip[0], ip[1], ip[2], ip[3], WiFi.firmwareVersion());

  } else if (id == "hw_mem") {
    SLOGF("Probando asignacion de memoria dinámica...");
    void *p64 = malloc(65536);
    void *p128 = malloc(131072);
    bool ok64 = (p64 != nullptr), ok128 = (p128 != nullptr);
    if (p64)
      free(p64);
    if (p128)
      free(p128);
    pass = ok64;
    SLOGF("64KB: %s | 128KB: %s", ok64 ? "OK" : "FAIL", ok128 ? "OK" : "FAIL");
    snprintf(detail, sizeof(detail),
             "64KB alloc: %s | 128KB alloc: %s | RP2040 SRAM total: 264KB",
             ok64 ? "OK" : "FAIL", ok128 ? "OK" : "FAIL");

    // =========================================================
    // NFC SCAN — any tag
    // =========================================================
  } else if (id == "nfc_any") {
    unsigned long tw = millis();
    bool found = false;
    while (millis() - tw < 15000) {
      if (nfc.raw().isTagDetected()) {
        found = true;
        break;
      }
      control.poll(); // atiende ping/info/identify durante la espera
      delay(100);
    }
    if (!found) {
      sResult(id, false, "Timeout: sin tag en 15s", millis() - t0);
      return;
    }
    pass = true;
    int p = nfc.raw().remoteDevice.getProtocol();
    const char *proto = "desconocido";
    if (p == nfc.raw().protocol.ISODEP)
      proto = "ISO-DEP (EMV contactless)";
    else if (p == nfc.raw().protocol.ISO15693)
      proto = "ISO 15693 (vicinity)";
    else if (p == nfc.raw().protocol.MIFARE)
      proto = "MIFARE";
    else if (p == nfc.raw().protocol.T3T)
      proto = "T3T / FeliCa";
    snprintf(detail, sizeof(detail), "Tag detectado: %s (proto=0x%02X)", proto,
             p);
    SLOGF("Protocolo: %s", proto);
    nfc.raw().waitForTagRemoval();
    nfc.raw().stopDiscovery();
    nfc.raw().startDiscovery();

  } else if (id == "nfc_iso") {
    unsigned long tw = millis();
    bool found = false, isISO = false;
    while (millis() - tw < 15000) {
      if (nfc.raw().isTagDetected()) {
        found = true;
        isISO =
            (nfc.raw().remoteDevice.getProtocol() == nfc.raw().protocol.ISODEP);
        break;
      }
      control.poll(); // atiende ping/info/identify durante la espera
      delay(100);
    }
    if (!found) {
      sResult(id, false, "Timeout: sin tag", millis() - t0);
      return;
    }
    pass = isISO;
    if (isISO)
      strcpy(detail, "ISO-DEP OK — tarjeta EMV lista para APDU");
    else
      snprintf(detail, sizeof(detail),
               "Tag no es ISO-DEP (proto=%d) — no es tarjeta de pago",
               nfc.raw().remoteDevice.getProtocol());
    nfc.raw().waitForTagRemoval();
    nfc.raw().stopDiscovery();
    nfc.raw().startDiscovery();

    // =========================================================
    // CARD IDENTIFICATION
    // =========================================================
  } else if (id == "id_ppse") {
    if (!pollCard()) {
      sResult(id, false, "Timeout tarjeta", millis() - t0);
      return;
    }
    SLOGF("Tarjeta ISO-DEP detectada");
    uint8_t resp[EMV_RESP_CAP];
    uint16_t rLen = 0;
    pass = selectPPSE(resp, rLen);
    if (pass) {
      SLOGF("SELECT PPSE OK");
      // Scan linealmente para todos los tag 4F
      char aidStr[140] = "";
      int aidCount = 0;
      for (int i = 0; i < (int)rLen - 3; i++) {
        if (resp[i] == 0x4F && resp[i + 1] >= 5 && resp[i + 1] <= 16) {
          uint8_t al = resp[i + 1];
          if (i + 2 + al <= (int)rLen) {
            char h[34];
            HexUtils::toCompact(resp + i + 2, al, h);
            if (strlen(aidStr) + strlen(h) + 4 < sizeof(aidStr)) {
              if (aidCount > 0)
                strcat(aidStr, " | ");
              strcat(aidStr, h);
              aidCount++;
            }
            // buscar label 50 cercano
            if (i + 2 + al + 2 < (int)rLen && resp[i + 2 + al] == 0x50) {
              uint8_t ll = resp[i + 2 + al + 1];
              char lbl[20] = "";
              if (ll > 0 && ll < 19 && i + 2 + al + 2 + ll <= (int)rLen) {
                memcpy(lbl, resp + i + 2 + al + 2, ll);
                lbl[ll] = '\0';
                SLOGF("AID %s = %s", h, lbl);
              } else
                SLOGF("AID %s", h);
            } else
              SLOGF("AID %s", h);
            i += 1 + al;
          }
        }
      }
      if (aidCount == 0)
        strcpy(aidStr, "(sin AID en respuesta)");
      snprintf(detail, sizeof(detail), "AIDs encontradas (%d): %s", aidCount,
               aidStr);
    } else
      strcpy(detail, "SELECT PPSE fallo");
    releaseCard();

  } else if (id == "id_aids") {
    if (!pollCard()) {
      sResult(id, false, "Timeout tarjeta", millis() - t0);
      return;
    }
    SLOGF("Tarjeta ISO-DEP detectada");
    // Intentar primero PPSE para referencia
    uint8_t ppseresp[EMV_RESP_CAP];
    uint16_t ppseLen = 0;
    selectPPSE(ppseresp, ppseLen);
    // Probar cada AID
    char found[140] = "";
    int ok = 0, total = NUM_ALL_AIDS;
    for (int a = 0; a < total; a++) {
      uint8_t fci[EMV_RESP_CAP];
      uint16_t fciLen = 0;
      if (selectAID(ALL_AIDS[a].b, ALL_AIDS[a].l, fci, fciLen)) {
        ok++;
        if (strlen(found) + strlen(ALL_AIDS[a].n) + 3 < sizeof(found)) {
          if (ok > 1)
            strcat(found, ", ");
          strcat(found, ALL_AIDS[a].n);
        }
        SLOGF("OK: %s", ALL_AIDS[a].n);
      } else {
        SLOGF("NO: %s", ALL_AIDS[a].n);
      }
      delay(30);
    }
    pass = (ok > 0);
    snprintf(detail, sizeof(detail), "%d/%d AIDs OK: %s", ok, total,
             ok > 0 ? found : "ninguna");
    releaseCard();

  } else if (id == "id_pan") {
    if (!pollCard()) {
      sResult(id, false, "Timeout tarjeta", millis() - t0);
      return;
    }
    SLOGF("Tarjeta ISO-DEP detectada");
    memset(&card, 0, sizeof(card));
    uint32_t un = hwRand32();
    card.un[0] = (un >> 24) & 0xFF;
    card.un[1] = (un >> 16) & 0xFF;
    card.un[2] = (un >> 8) & 0xFF;
    card.un[3] = un & 0xFF;
    // PPSE → AID → GPO → Records
    uint8_t resp[EMV_RESP_CAP];
    uint16_t rLen = 0;
    selectPPSE(resp, rLen);
    rLen = 0;
    uint8_t fci[EMV_RESP_CAP];
    uint16_t fciLen = 0;
    bool aidOk = false;
    for (int a = 0; a < NUM_AIDS && !aidOk; a++) {
      if (selectAID(AIDS[a].bytes, AIDS[a].len, fci, fciLen)) {
        strncpy(card.aidName, AIDS[a].name, sizeof(card.aidName) - 1);
        HexUtils::toCompact(AIDS[a].bytes, AIDS[a].len, card.aidHex);
        aidOk = true;
        SLOGF("AID: %s", AIDS[a].name);
      }
    }
    if (!aidOk) {
      sResult(id, false, "Sin AID compatible", millis() - t0);
      return;
    }
    uint8_t gpo[EMV_RESP_CAP];
    uint16_t gpoLen = 0;
    getProcessingOptions(fci, fciLen, gpo, gpoLen, 500);
    // Buscar PAN en GPO y en records
    auto tryExtractPAN = [&](uint8_t *buf, int blen) {
      int l = 0;
      uint8_t *p57 = EmvKernel::tlvFind(buf, blen, 0x57, &l);
      if (p57 && l > 0) {
        HexUtils::toCompact(p57, l, card.track2);
        char *sep = strchr(card.track2, 'D');
        if (sep) {
          int pl = sep - card.track2;
          memcpy(card.pan, card.track2, pl);
          card.pan[pl] = '\0';
          strncpy(card.expiry, sep + 1, 4);
          card.expiry[4] = '\0';
        }
      }
      if (!card.pan[0]) {
        int l2 = 0;
        uint8_t *p5A = EmvKernel::tlvFind(buf, blen, 0x5A, &l2);
        if (p5A && l2 > 0) {
          HexUtils::toCompact(p5A, l2, card.pan);
          int n = strlen(card.pan);
          while (n > 0 && card.pan[n - 1] == 'F')
            card.pan[--n] = '\0';
        }
      }
      if (!card.expiry[0]) {
        int el = 0;
        uint8_t *ep = EmvKernel::tlvFind(buf, blen, 0x5F24, &el);
        if (ep && el >= 3) {
          char tmp[8];
          HexUtils::toCompact(ep, 3, tmp);
          strncpy(card.expiry, tmp, 4);
          card.expiry[4] = '\0';
        }
      }
      if (!card.label[0]) {
        int ll = 0;
        uint8_t *lp = EmvKernel::tlvFind(buf, blen, 0x50, &ll);
        if (lp && ll > 0) {
          int n = min(ll, (int)sizeof(card.label) - 1);
          memcpy(card.label, lp, n);
          card.label[n] = '\0';
        }
      }
    };
    tryExtractPAN(gpo, (gpoLen > 2) ? gpoLen - 2 : 0);
    int aflL = 0;
    uint8_t *aflP = EmvKernel::tlvFind(gpo, gpoLen - 2, 0x94, &aflL);
    if (!aflP && gpoLen >= 6 && gpo[0] == 0x80) {
      aflP = gpo + 4;
      aflL = gpoLen - 6;
    }
    if (aflP && aflL >= 4) {
      for (int i = 0; i + 3 < aflL; i += 4) {
        uint8_t sfi = (aflP[i] >> 3), from = aflP[i + 1], to = aflP[i + 2];
        for (uint8_t r = from; r <= to; r++) {
          uint8_t rr[EMV_RESP_CAP];
          uint16_t rl = 0;
          if (readRecord(sfi, r, rr, rl) && rl > 2)
            tryExtractPAN(rr, rl - 2);
        }
      }
    }
    pass = (card.pan[0] != '\0');
    if (pass) {
      char exp[6] = "";
      if (card.expiry[0])
        snprintf(exp, sizeof(exp), "20%.2s/%.2s", card.expiry, card.expiry + 2);
      snprintf(detail, sizeof(detail), "PAN: %s | Exp: %s | Label: %s | %s",
               card.pan, exp, card.label[0] ? card.label : "—", card.aidName);
      SLOGF("PAN: %s", card.pan);
      SLOGF("Expiry: %s", exp);
      if (card.label[0])
        SLOGF("Label: %s", card.label);
    } else
      strcpy(detail, "PAN no encontrado en ninguna fuente");
    releaseCard();

  } else if (id == "id_dump") {
    if (!pollCard()) {
      sResult(id, false, "Timeout tarjeta", millis() - t0);
      return;
    }
    SLOGF("Tarjeta ISO-DEP detectada");
    uint8_t resp[EMV_RESP_CAP];
    uint16_t rLen = 0;
    selectPPSE(resp, rLen);
    rLen = 0;
    uint8_t fci[EMV_RESP_CAP];
    uint16_t fciLen = 0;
    for (int a = 0; a < NUM_AIDS && !fciLen; a++)
      selectAID(AIDS[a].bytes, AIDS[a].len, fci, fciLen);
    uint8_t gpo[EMV_RESP_CAP];
    uint16_t gpoLen = 0;
    if (fciLen)
      getProcessingOptions(fci, fciLen, gpo, gpoLen, 100);
    int found = 0;
    for (int sfi = 1; sfi <= 10 && found < 16; sfi++) {
      for (int rec = 1; rec <= 8 && found < 16; rec++) {
        uint8_t rr[EMV_RESP_CAP];
        uint16_t rl = 0;
        if (readRecord((uint8_t)sfi, (uint8_t)rec, rr, rl) && rl > 2) {
          found++;
          char h[20];
          snprintf(h, sizeof(h), "SFI%d/R%d:%dB", sfi, rec, rl - 2);
          SLOGF("%s", h);
        }
      }
    }
    pass = (found > 0);
    snprintf(detail, sizeof(detail),
             "%d registros leibles encontrados (SFI 1-10, REC 1-8)", found);
    releaseCard();

    // =========================================================
    // EMV PROTOCOL (individual steps)
    // =========================================================
  } else if (id == "emv_ppse") {
    if (!pollCard()) {
      sResult(id, false, "Timeout tarjeta", millis() - t0);
      return;
    }
    SLOGF("Tarjeta ISO-DEP detectada");
    uint8_t resp[EMV_RESP_CAP];
    uint16_t rLen = 0;
    pass = selectPPSE(resp, rLen);
    if (pass) {
      int al = 0;
      uint8_t *ap = EmvKernel::tlvFind(resp, rLen - 2, 0x4F, &al);
      if (ap) {
        char h[34];
        HexUtils::toCompact(ap, al, h);
        snprintf(detail, sizeof(detail), "AID en PPSE: %s", h);
        SLOGF("AID: %s", h);
      } else
        strcpy(detail, "PPSE OK (sin tag 4F en respuesta)");
      SLOGF("SW: %02X%02X", resp[rLen - 2], resp[rLen - 1]);
    } else
      strcpy(detail, "SELECT PPSE fallo (tarjeta no responde)");
    releaseCard();

  } else if (id == "emv_aid") {
    if (!pollCard()) {
      sResult(id, false, "Timeout tarjeta", millis() - t0);
      return;
    }
    SLOGF("Tarjeta ISO-DEP detectada");
    uint8_t resp[EMV_RESP_CAP];
    uint16_t rLen = 0;
    selectPPSE(resp, rLen);
    rLen = 0;
    uint8_t fci[EMV_RESP_CAP];
    uint16_t fciLen = 0;
    bool aidOk = false;
    for (int a = 0; a < NUM_AIDS && !aidOk; a++) {
      if (selectAID(AIDS[a].bytes, AIDS[a].len, fci, fciLen)) {
        char h[34];
        HexUtils::toCompact(AIDS[a].bytes, AIDS[a].len, h);
        snprintf(detail, sizeof(detail), "%s seleccionada (%s)", AIDS[a].name,
                 h);
        SLOGF("AID: %s = %s", AIDS[a].name, h);
        // Check PDOL
        int pdolL = 0;
        uint8_t *pdol = EmvKernel::tlvFind(fci, fciLen - 2, 0x9F38, &pdolL);
        if (pdol)
          SLOGF("PDOL presente: %d bytes", pdolL);
        else
          SLOGF("Sin PDOL");
        aidOk = true;
        pass = true;
      }
    }
    if (!aidOk)
      strcpy(detail, "Ninguna AID compatible");
    releaseCard();

  } else if (id == "emv_gpo") {
    if (!pollCard()) {
      sResult(id, false, "Timeout tarjeta", millis() - t0);
      return;
    }
    SLOGF("Tarjeta ISO-DEP detectada");
    uint8_t resp[EMV_RESP_CAP];
    uint16_t rLen = 0;
    selectPPSE(resp, rLen);
    rLen = 0;
    uint8_t fci[EMV_RESP_CAP];
    uint16_t fciLen = 0;
    for (int a = 0; a < NUM_AIDS && !fciLen; a++) {
      if (selectAID(AIDS[a].bytes, AIDS[a].len, fci, fciLen)) {
        SLOGF("AID: %s", AIDS[a].name);
        break;
      }
    }
    if (!fciLen) {
      sResult(id, false, "Sin AID", millis() - t0);
      return;
    }
    uint8_t gpo[EMV_RESP_CAP];
    uint16_t gpoLen = 0;
    pass = getProcessingOptions(fci, fciLen, gpo, gpoLen, 500);
    if (pass) {
      int aipL = 0;
      uint8_t *aipP = EmvKernel::tlvFind(gpo, gpoLen - 2, 0x82, &aipL);
      int aflL = 0;
      uint8_t *aflP = EmvKernel::tlvFind(gpo, gpoLen - 2, 0x94, &aflL);
      if (!aipP && gpoLen >= 6 && gpo[0] == 0x80) {
        aipP = gpo + 2;
        aipL = 2;
        aflP = gpo + 4;
        aflL = gpoLen - 6;
      }
      char aipH[6] = "";
      if (aipP)
        HexUtils::toCompact(aipP, 2, aipH);
      int recCount = 0;
      if (aflP && aflL >= 4)
        for (int i = 0; i + 3 < aflL; i += 4)
          recCount += (aflP[i + 2] - aflP[i + 1] + 1);
      snprintf(detail, sizeof(detail), "GPO OK | AIP: %s | AFL: %d registros",
               aipH[0] ? aipH : "N/A", recCount);
      SLOGF("AIP: %s", aipH);
      SLOGF("AFL entries: %d", aflL / 4);
    } else
      strcpy(detail, "GPO fallo");
    releaseCard();

  } else if (id == "emv_rr") {
    if (!pollCard()) {
      sResult(id, false, "Timeout tarjeta", millis() - t0);
      return;
    }
    SLOGF("Tarjeta ISO-DEP detectada");
    uint8_t resp[EMV_RESP_CAP];
    uint16_t rLen = 0;
    selectPPSE(resp, rLen);
    rLen = 0;
    uint8_t fci[EMV_RESP_CAP];
    uint16_t fciLen = 0;
    for (int a = 0; a < NUM_AIDS && !fciLen; a++)
      selectAID(AIDS[a].bytes, AIDS[a].len, fci, fciLen);
    if (!fciLen) {
      sResult(id, false, "Sin AID", millis() - t0);
      return;
    }
    uint8_t gpo[EMV_RESP_CAP];
    uint16_t gpoLen = 0;
    getProcessingOptions(fci, fciLen, gpo, gpoLen, 100);
    int aflL = 0;
    uint8_t *aflP = EmvKernel::tlvFind(gpo, gpoLen - 2, 0x94, &aflL);
    if (!aflP && gpoLen >= 6 && gpo[0] == 0x80) {
      aflP = gpo + 4;
      aflL = gpoLen - 6;
    }
    if (!aflP || aflL < 4) {
      sResult(id, false, "AFL no disponible", millis() - t0);
      return;
    }
    uint8_t sfi = (aflP[0] >> 3), rec = aflP[1];
    uint8_t rr[EMV_RESP_CAP];
    uint16_t rl = 0;
    pass = readRecord(sfi, rec, rr, rl);
    if (pass) {
      int t57l = 0;
      uint8_t *t57 = EmvKernel::tlvFind(rr, rl - 2, 0x57, &t57l);
      int ppl = 0;
      uint8_t *pp = EmvKernel::tlvFind(rr, rl - 2, 0x5A, &ppl);
      bool hasPAN = (t57 || pp);
      snprintf(detail, sizeof(detail), "SFI=%d REC=%d OK | %d bytes | PAN: %s",
               sfi, rec, rl - 2, hasPAN ? "SI" : "no visible");
      SLOGF("Record %d bytes leidos", rl - 2);
      if (hasPAN)
        SLOGF("Track2/PAN encontrado");
    } else
      snprintf(detail, sizeof(detail), "READ RECORD SFI=%d REC=%d fallo", sfi,
               rec);
    releaseCard();

  } else if (id == "emv_ac") {
    if (!pollCard()) {
      sResult(id, false, "Timeout tarjeta", millis() - t0);
      return;
    }
    SLOGF("Tarjeta ISO-DEP detectada");
    memset(&card, 0, sizeof(card));
    uint32_t un = hwRand32();
    card.un[0] = (un >> 24) & 0xFF;
    card.un[1] = (un >> 16) & 0xFF;
    card.un[2] = (un >> 8) & 0xFF;
    card.un[3] = un & 0xFF;
    SLOGF("Ejecutando flujo EMV completo...");
    pass = runEmvFlow(500);
    if (pass) {
      char arqcH[18], atcH[6], aipH[6], iadH[66];
      HexUtils::toCompact(card.arqc, 8, arqcH);
      HexUtils::toCompact(card.atc, 2, atcH);
      HexUtils::toCompact(card.aip, 2, aipH);
      HexUtils::toCompact(card.iad, card.iadLen, iadH);
      snprintf(detail, sizeof(detail), "ARQC: %s | ATC: %s | %s", arqcH, atcH,
               card.aidName);
      SLOGF("ARQC: %s", arqcH);
      SLOGF("ATC:  %s", atcH);
      SLOGF("AIP:  %s", aipH);
      SLOGF("IAD:  %s", iadH);
      SLOGF("UN:   %02X%02X%02X%02X", card.un[0], card.un[1], card.un[2],
            card.un[3]);
    } else
      strcpy(detail, "Flujo EMV fallo — ver Serial");
    releaseCard();

    // =========================================================
    // TRANSACTIONS
    // =========================================================
  } else if (id == "txn_zero") {
    if (!pollCard()) {
      sResult(id, false, "Timeout tarjeta", millis() - t0);
      return;
    }
    memset(&card, 0, sizeof(card));
    uint32_t un = hwRand32();
    card.un[0] = (un >> 24) & 0xFF;
    card.un[1] = (un >> 16) & 0xFF;
    card.un[2] = (un >> 8) & 0xFF;
    card.un[3] = un & 0xFF;
    SLOGF("Ejecutando flujo EMV completo...");
    pass = runEmvFlow(0);
    if (pass) {
      char h[18];
      HexUtils::toCompact(card.arqc, 8, h);
      snprintf(detail, sizeof(detail), "ARQC: %s | PAN: %s | %s", h, card.pan,
               card.aidName);
    } else
      strcpy(detail, "Fallo con monto $0.00");
    releaseCard();

  } else if (id == "txn_5" || id == "txn_500" || id == "txn_1k" ||
             id == "txn_5k") {
    if (!pollCard()) {
      sResult(id, false, "Timeout tarjeta", millis() - t0);
      return;
    }
    uint64_t amt = id == "txn_5"     ? 500
                   : id == "txn_500" ? 50000
                   : id == "txn_1k"  ? 100000
                                     : 500000;
    const char *amtStr = id == "txn_5"     ? "$5.00"
                         : id == "txn_500" ? "$500.00"
                         : id == "txn_1k"  ? "$1,000.00"
                                           : "$5,000.00";
    memset(&card, 0, sizeof(card));
    uint32_t un = hwRand32();
    card.un[0] = (un >> 24) & 0xFF;
    card.un[1] = (un >> 16) & 0xFF;
    card.un[2] = (un >> 8) & 0xFF;
    card.un[3] = un & 0xFF;
    SLOGF("Ejecutando flujo EMV completo...");
    pass = runEmvFlow(amt);
    if (pass) {
      char h[18], atcH[6];
      HexUtils::toCompact(card.arqc, 8, h);
      HexUtils::toCompact(card.atc, 2, atcH);
      snprintf(detail, sizeof(detail),
               "%s OK | PAN: %s | ARQC: %s | ATC: %s | %s", amtStr, card.pan, h,
               atcH, card.aidName);
      SLOGF("Monto: %s", amtStr);
      SLOGF("ARQC: %s", h);
      SLOGF("ATC: %s", atcH);
    } else
      snprintf(detail, sizeof(detail), "%s: flujo EMV fallo", amtStr);
    releaseCard();

  } else if (id == "txn_3x") {
    if (!pollCard(25000)) {
      sResult(id, false, "Timeout tarjeta", millis() - t0);
      return;
    }
    SLOGF("Tarjeta ISO-DEP detectada (25s)");
    uint16_t atcVal[3] = {0, 0, 0};
    char arqcStr[3][18];
    bool txOk[3] = {false, false, false};
    for (int i = 0; i < 3; i++) {
      if (i > 0) {
        // Reiniciar descubrimiento y esperar re-deteccion
        nfc.raw().waitForTagRemoval();
        nfc.raw().stopDiscovery();
        nfc.raw().startDiscovery();
        unsigned long tw = millis();
        bool ref = false;
        while (millis() - tw < 8000) {
          if (nfc.raw().isTagDetected() &&
              nfc.raw().remoteDevice.getProtocol() ==
                  nfc.raw().protocol.ISODEP) {
            ref = true;
            break;
          }
          control.poll(); // atiende ping/info/identify durante la espera
          delay(100);
        }
        if (!ref) {
          SLOGF("Txn %d: tarjeta no re-detectada", i + 1);
          break;
        }
      }
      memset(&card, 0, sizeof(card));
      uint32_t un = hwRand32();
      card.un[0] = (un >> 24) & 0xFF;
      card.un[1] = (un >> 16) & 0xFF;
      card.un[2] = (un >> 8) & 0xFF;
      card.un[3] = un & 0xFF;
      txOk[i] = runEmvFlow(500);
      if (txOk[i]) {
        atcVal[i] = (card.atc[0] << 8) | card.atc[1];
        HexUtils::toCompact(card.arqc, 8, arqcStr[i]);
        SLOGF("Txn%d ARQC: %s ATC: %04X", i + 1, arqcStr[i], atcVal[i]);
      } else {
        SLOGF("Txn%d: FAIL", i + 1);
      }
    }
    bool allOk = (txOk[0] && txOk[1] && txOk[2]);
    bool atcInc =
        (allOk && atcVal[1] == atcVal[0] + 1 && atcVal[2] == atcVal[1] + 1);
    pass = allOk;
    if (allOk)
      snprintf(detail, sizeof(detail),
               "3 txns OK | ATC: %04X→%04X→%04X | Incremento: %s", atcVal[0],
               atcVal[1], atcVal[2], atcInc ? "NORMAL" : "ANORMAL(!)");
    else
      snprintf(detail, sizeof(detail), "Txn1:%s Txn2:%s Txn3:%s",
               txOk[0] ? "OK" : "FAIL", txOk[1] ? "OK" : "FAIL",
               txOk[2] ? "OK" : "FAIL");
    releaseCard();

    // =========================================================
    // SECURITY PROBES
    // =========================================================
  } else if (id == "probe_atc") {
    if (!pollCard()) {
      sResult(id, false, "Timeout tarjeta", millis() - t0);
      return;
    }
    uint8_t resp[EMV_RESP_CAP];
    uint16_t rLen = 0;
    selectPPSE(resp, rLen);
    rLen = 0;
    uint8_t fci[EMV_RESP_CAP];
    uint16_t fciLen = 0;
    for (int a = 0; a < NUM_AIDS && !fciLen; a++)
      selectAID(AIDS[a].bytes, AIDS[a].len, fci, fciLen);
    if (!fciLen) {
      sResult(id, false, "Sin AID", millis() - t0);
      return;
    }
    uint8_t gpo[EMV_RESP_CAP];
    uint16_t gpoLen = 0;
    getProcessingOptions(fci, fciLen, gpo, gpoLen, 100);
    // ATC puede venir en GPO (template 80) o en records
    int atcL = 0;
    uint8_t *atcP = EmvKernel::tlvFind(gpo, gpoLen - 2, 0x9F36, &atcL);
    if (!atcP) {
      int aflL = 0;
      uint8_t *aflP = EmvKernel::tlvFind(gpo, gpoLen - 2, 0x94, &aflL);
      if (!aflP && gpoLen >= 6 && gpo[0] == 0x80) {
        aflP = gpo + 4;
        aflL = gpoLen - 6;
      }
      if (aflP && aflL >= 4) {
        uint8_t sfi = (aflP[0] >> 3), rec = aflP[1];
        uint8_t rr[EMV_RESP_CAP];
        uint16_t rl = 0;
        if (readRecord(sfi, rec, rr, rl))
          atcP = EmvKernel::tlvFind(rr, rl - 2, 0x9F36, &atcL);
      }
    }
    pass = (atcP && atcL >= 2);
    if (pass) {
      uint16_t atcVal = (atcP[0] << 8) | atcP[1];
      snprintf(detail, sizeof(detail),
               "ATC: 0x%04X (%u transacciones realizadas)", atcVal, atcVal);
      SLOGF("ATC decimal: %u", atcVal);
    } else
      strcpy(detail, "ATC (9F36) no encontrado");
    releaseCard();

  } else if (id == "probe_cvm") {
    if (!pollCard()) {
      sResult(id, false, "Timeout tarjeta", millis() - t0);
      return;
    }
    uint8_t resp[EMV_RESP_CAP];
    uint16_t rLen = 0;
    selectPPSE(resp, rLen);
    rLen = 0;
    uint8_t fci[EMV_RESP_CAP];
    uint16_t fciLen = 0;
    for (int a = 0; a < NUM_AIDS && !fciLen; a++)
      selectAID(AIDS[a].bytes, AIDS[a].len, fci, fciLen);
    if (!fciLen) {
      sResult(id, false, "Sin AID", millis() - t0);
      return;
    }
    uint8_t gpo[EMV_RESP_CAP];
    uint16_t gpoLen = 0;
    getProcessingOptions(fci, fciLen, gpo, gpoLen, 100);
    // CVM List está en records
    int aflL = 0;
    uint8_t *aflP = EmvKernel::tlvFind(gpo, gpoLen - 2, 0x94, &aflL);
    if (!aflP && gpoLen >= 6 && gpo[0] == 0x80) {
      aflP = gpo + 4;
      aflL = gpoLen - 6;
    }
    int cvmL = 0;
    uint8_t *cvmP = NULL;
    if (aflP && aflL >= 4) {
      for (int i = 0; i + 3 < aflL && !cvmP; i += 4) {
        uint8_t sfi = (aflP[i] >> 3), from = aflP[i + 1], to = aflP[i + 2];
        for (uint8_t r = from; r <= to && !cvmP; r++) {
          uint8_t rr[EMV_RESP_CAP];
          uint16_t rl = 0;
          if (readRecord(sfi, r, rr, rl)) {
            cvmP = EmvKernel::tlvFind(rr, rl - 2, 0x8E, &cvmL);
          }
        }
      }
    }
    pass = (cvmP && cvmL >= 8);
    if (pass) {
      const char *cvmCodes[] = {
          "Fallo", "PIN offline", "PIN online", "N/A",  "N/A", "N/A", "N/A",
          "N/A",   "N/A",         "N/A",        "N/A",  "N/A", "N/A", "N/A",
          "N/A",   "N/A",         "N/A",        "N/A",  "N/A", "N/A", "N/A",
          "N/A",   "N/A",         "N/A",        "N/A",  "N/A", "N/A", "N/A",
          "N/A",   "N/A",         "Sign",       "NoCVM"};
      char cvmStr[120] = "";
      for (int i = 8; i + 1 < cvmL; i += 2) {
        uint8_t code = cvmP[i] & 0x3F;
        const char *name = (code == 0x00)   ? "Fallo"
                           : (code == 0x01) ? "PIN-offline"
                           : (code == 0x02) ? "PIN-online"
                           : (code == 0x1E) ? "Firma"
                           : (code == 0x1F) ? "NoCVM"
                                            : "otro";
        if (strlen(cvmStr) + strlen(name) + 3 < sizeof(cvmStr)) {
          if (i > 8)
            strcat(cvmStr, ", ");
          strcat(cvmStr, name);
        }
        SLOGF("CVM: %s (cond=0x%02X)", name, cvmP[i + 1]);
      }
      snprintf(detail, sizeof(detail), "CVM List: %s",
               cvmStr[0] ? cvmStr : "sin metodos");
    } else
      strcpy(detail, "CVM List (8E) no encontrada en registros");
    releaseCard();

  } else if (id == "probe_caps") {
    if (!pollCard()) {
      sResult(id, false, "Timeout tarjeta", millis() - t0);
      return;
    }
    uint8_t resp[EMV_RESP_CAP];
    uint16_t rLen = 0;
    selectPPSE(resp, rLen);
    rLen = 0;
    uint8_t fci[EMV_RESP_CAP];
    uint16_t fciLen = 0;
    for (int a = 0; a < NUM_AIDS && !fciLen; a++)
      selectAID(AIDS[a].bytes, AIDS[a].len, fci, fciLen);
    if (!fciLen) {
      sResult(id, false, "Sin AID", millis() - t0);
      return;
    }
    uint8_t gpo[EMV_RESP_CAP];
    uint16_t gpoLen = 0;
    getProcessingOptions(fci, fciLen, gpo, gpoLen, 100);
    int aipL = 0;
    uint8_t *aipP = EmvKernel::tlvFind(gpo, gpoLen - 2, 0x82, &aipL);
    if (!aipP && gpoLen >= 6 && gpo[0] == 0x80) {
      aipP = gpo + 2;
      aipL = 2;
    }
    pass = (aipP && aipL >= 2);
    if (pass) {
      uint8_t b1 = aipP[0];
      bool sda = (b1 >> 6) & 1, dda = (b1 >> 5) & 1, cv = (b1 >> 4) & 1,
           trm = (b1 >> 3) & 1, ia = (b1 >> 2) & 1, cda = (b1 >> 0) & 1;
      char h[6];
      HexUtils::toCompact(aipP, 2, h);
      snprintf(detail, sizeof(detail),
               "AIP: %s | SDA:%s DDA:%s CDA:%s CV:%s IA:%s TRM:%s", h,
               sda ? "SI" : "no", dda ? "SI" : "no", cda ? "SI" : "no",
               cv ? "SI" : "no", ia ? "SI" : "no", trm ? "SI" : "no");
      SLOGF("SDA (firma estatica): %s", sda ? "SOPORTADA" : "no");
      SLOGF("DDA (firma dinamica): %s", dda ? "SOPORTADA" : "no");
      SLOGF("CDA (DDA+AC):         %s", cda ? "SOPORTADA" : "no");
      SLOGF("Verificacion titular: %s", cv ? "SI" : "no");
      SLOGF("Auth emisor:          %s", ia ? "SI" : "no");
    } else
      strcpy(detail, "AIP (82) no disponible");
    releaseCard();

  } else if (id == "probe_lim") {
    if (!pollCard()) {
      sResult(id, false, "Timeout tarjeta", millis() - t0);
      return;
    }
    uint8_t resp[EMV_RESP_CAP];
    uint16_t rLen = 0;
    selectPPSE(resp, rLen);
    rLen = 0;
    uint8_t fci[EMV_RESP_CAP];
    uint16_t fciLen = 0;
    for (int a = 0; a < NUM_AIDS && !fciLen; a++)
      selectAID(AIDS[a].bytes, AIDS[a].len, fci, fciLen);
    if (!fciLen) {
      sResult(id, false, "Sin AID", millis() - t0);
      return;
    }
    uint8_t gpo[EMV_RESP_CAP];
    uint16_t gpoLen = 0;
    getProcessingOptions(fci, fciLen, gpo, gpoLen, 100);
    // Buscar 9F6D (VISA CL limit), 9F6B (CTQ VISA), 9F66 (VISA TTQ en PDOL)
    char found[160] = "";
    auto checkTag = [&](uint8_t *buf, int blen, uint16_t tag,
                        const char *name) {
      int l = 0;
      uint8_t *p = EmvKernel::tlvFind(buf, blen, tag, &l);
      if (p && l > 0) {
        char h[32];
        HexUtils::toCompact(p, min(l, 12), h);
        char tmp[60];
        snprintf(tmp, sizeof(tmp), "%s: %s  ", name, h);
        if (strlen(found) + strlen(tmp) < sizeof(found))
          strcat(found, tmp);
        SLOGF("Tag 0x%04X (%s): %s", tag, name, h);
        return true;
      }
      return false;
    };
    bool got = false;
    got |= checkTag(gpo, gpoLen - 2, 0x9F6D, "CL Limit");
    got |= checkTag(gpo, gpoLen - 2, 0x9F6B, "CTQ");
    got |= checkTag(gpo, gpoLen - 2, 0x9F66, "TTQ");
    // Also check in FCI
    got |= checkTag(fci, fciLen - 2, 0x9F6D, "CL Limit(FCI)");
    // Check PDOL for 9F66
    int pdolL = 0;
    uint8_t *pdol = EmvKernel::tlvFind(fci, fciLen - 2, 0x9F38, &pdolL);
    if (pdol && pdolL > 0) {
      char h[50];
      HexUtils::toCompact(pdol, min(pdolL, 20), h);
      SLOGF("PDOL: %s", h);
    }
    pass = got;
    if (got)
      snprintf(detail, sizeof(detail), "Tags de limite: %s", found);
    else
      strcpy(detail, "Sin tags de limite contactless (9F6D/9F6B/9F66) — normal "
                     "en tarjetas MX");
    releaseCard();

  } else if (id == "probe_off") {
    if (!pollCard()) {
      sResult(id, false, "Timeout tarjeta", millis() - t0);
      return;
    }
    // Setup full EMV but request AAC instead of ARQC
    memset(&card, 0, sizeof(card));
    uint32_t un = hwRand32();
    card.un[0] = (un >> 24) & 0xFF;
    card.un[1] = (un >> 16) & 0xFF;
    card.un[2] = (un >> 8) & 0xFF;
    card.un[3] = un & 0xFF;
    uint8_t resp[EMV_RESP_CAP];
    uint16_t rLen = 0;
    selectPPSE(resp, rLen);
    rLen = 0;
    uint8_t fci[EMV_RESP_CAP];
    uint16_t fciLen = 0;
    bool aidOk = false;
    for (int a = 0; a < NUM_AIDS && !aidOk; a++) {
      if (selectAID(AIDS[a].bytes, AIDS[a].len, fci, fciLen)) {
        strncpy(card.aidName, AIDS[a].name, sizeof(card.aidName) - 1);
        HexUtils::toCompact(AIDS[a].bytes, AIDS[a].len, card.aidHex);
        aidOk = true;
      }
    }
    if (!aidOk) {
      sResult(id, false, "Sin AID", millis() - t0);
      return;
    }
    uint8_t gpo[EMV_RESP_CAP];
    uint16_t gpoLen = 0;
    getProcessingOptions(fci, fciLen, gpo, gpoLen, 500);
    // Read records for CDOL
    int aflL = 0;
    uint8_t *aflP = EmvKernel::tlvFind(gpo, gpoLen - 2, 0x94, &aflL);
    if (!aflP && gpoLen >= 6 && gpo[0] == 0x80) {
      aflP = gpo + 4;
      aflL = gpoLen - 6;
    }
    if (aflP && aflL >= 4) {
      for (int i = 0; i + 3 < aflL; i += 4) {
        uint8_t sfi = (aflP[i] >> 3), from = aflP[i + 1], to = aflP[i + 2];
        for (uint8_t r = from; r <= to; r++) {
          uint8_t rr[EMV_RESP_CAP];
          uint16_t rl = 0;
          if (!readRecord(sfi, r, rr, rl))
            continue;
          if (!card.cdol1Len) {
            int cl = 0;
            uint8_t *cp = EmvKernel::tlvFind(rr, rl - 2, 0x8C, &cl);
            if (cp && cl > 0) {
              card.cdol1Len = (uint8_t)min(cl, (int)sizeof(card.cdol1));
              memcpy(card.cdol1, cp, card.cdol1Len);
            }
          }
        }
      }
    }
    // Send GENERATE AC with P1=0x00 (request AAC = offline decline)
    uint8_t gen[EMV_RESP_CAP];
    uint16_t genLen = 0;
    bool acOk = generateAC(500, gen, genLen, 0x00); // 0x00 = AAC
    if (acOk && genLen >= 3) {
      // Check tag 9F27 (Cryptogram Information Data)
      int cidL = 0;
      uint8_t *cidP = EmvKernel::tlvFind(gen, genLen - 2, 0x9F27, &cidL);
      // Also check raw template 80
      uint8_t cidByte = 0;
      if (cidP && cidL >= 1) {
        cidByte = cidP[0];
      } else if (gen[0] == 0x80 && genLen >= 5) {
        cidByte = gen[2];
      } // CID in byte offset 2 of 80 template
      uint8_t cid = (cidByte >> 6) & 0x03;
      const char *cidStr = (cid == 0)   ? "AAC (offline decline)"
                           : (cid == 1) ? "TC (offline approve)"
                           : (cid == 2) ? "ARQC (fuerza online)"
                                        : "RFU";
      snprintf(detail, sizeof(detail),
               "Respuesta a AAC request: %s (CID=0x%02X) | %s", cidStr, cidByte,
               card.aidName);
      SLOGF("CID byte: 0x%02X", cidByte);
      SLOGF("Tipo: %s", cidStr);
      pass = true; // El test pasa si obtenemos respuesta (informativo)
    } else {
      strcpy(detail, "GENERATE AC (AAC) no respondio — SW de error");
      pass = false;
    }
    releaseCard();

    // =========================================================
    // CUSTOM TRANSACTION — amount from gTestAmt (centavos)
    // =========================================================
  } else if (id == "txn_custom") {
    if (!pollCard()) {
      sResult(id, false, "Timeout tarjeta", millis() - t0);
      return;
    }
    SLOGF("Tarjeta ISO-DEP detectada");
    memset(&card, 0, sizeof(card));
    uint32_t un = hwRand32();
    card.un[0] = (un >> 24) & 0xFF;
    card.un[1] = (un >> 16) & 0xFF;
    card.un[2] = (un >> 8) & 0xFF;
    card.un[3] = un & 0xFF;
    SLOGF("Monto: $%lu.%02lu MXN (%lu cts)", (unsigned long)(gTestAmt / 100),
          (unsigned long)(gTestAmt % 100), (unsigned long)gTestAmt);
    SLOGF("Ejecutando flujo EMV completo...");
    pass = runEmvFlow(gTestAmt);
    if (pass) {
      char h[18], atcH[6];
      HexUtils::toCompact(card.arqc, 8, h);
      HexUtils::toCompact(card.atc, 2, atcH);
      snprintf(detail, sizeof(detail),
               "$%lu.%02lu MXN | PAN: %s | ARQC: %s | ATC: %s | %s",
               (unsigned long)(gTestAmt / 100), (unsigned long)(gTestAmt % 100),
               card.pan, h, atcH, card.aidName);
      SLOGF("ARQC: %s | ATC: %s", h, atcH);
    } else {
      snprintf(detail, sizeof(detail), "Flujo EMV fallo (monto %lu cts)",
               (unsigned long)gTestAmt);
    }
    releaseCard();

  } else {
    sResult(id, false, "Test desconocido", 0);
    return;
  }

  sResult(id, pass, detail, millis() - t0);
  gSC = nullptr;
}

// ---------------------------------------------------------------------------
// handleClient
// ---------------------------------------------------------------------------
// Modos adicionales (definidos en modes_tags.ino / modes_mag.ino) — declarados
// aquí porque los endpoints web /tag y /mag los usan.
void emvyTagsRead();
void emvyMagPlay(const char *track1, const char *track2);

static void handleClient(WiFiClient &client) {
  String reqLine = "";
  unsigned long dl = millis() + 3000;
  while (client.connected() && millis() < dl) {
    if (client.available()) {
      char c = client.read();
      if (c == '\n')
        break;
      if (c != '\r')
        reqLine += c;
    }
  }
  String buf = "";
  while (client.connected() && millis() < dl) {
    if (client.available()) {
      char c = client.read();
      buf += c;
      if (buf.endsWith("\r\n\r\n"))
        break;
    }
  }

  if (reqLine.startsWith("GET /scan")) {
    // Parse optional amt= (centavos), default $5.00 = 500 cts
    uint64_t scanAmt = 500;
    {
      int ai = reqLine.indexOf("amt=");
      if (ai >= 0) {
        int e1 = reqLine.indexOf(' ', ai);
        int e2 = reqLine.indexOf('&', ai + 4);
        if (e2 >= 0 && e2 < e1)
          e1 = e2;
        scanAmt = (uint64_t)reqLine.substring(ai + 4, e1).toInt();
      }
    }
    SLOGF("Scan: monto %lu centavos", (unsigned long)scanAmt);
    Serial.println("# Esperando tarjeta ISO-DEP...");
    bool tagFound = false;
    unsigned long tw = millis();
    while (millis() - tw < 15000) {
      if (nfc.raw().isTagDetected() &&
          nfc.raw().remoteDevice.getProtocol() == nfc.raw().protocol.ISODEP) {
        tagFound = true;
        break;
      }
      delay(100);
    }
    if (!tagFound) {
      sendJson(client,
               "{\"ok\":false,\"error\":\"Timeout: sin tarjeta en 15s\"}");
    } else {
      if (runEmvFlow(scanAmt)) {
        buildWebJson(scanAmt);
        sendJson(client, webResult);
        // Salida serial para modo --port del PoC
        Serial.println("JSON_START");
        Serial.println(webResult);
        Serial.println("JSON_END");
      } else {
        sendJson(client, "{\"ok\":false,\"error\":\"Flujo EMV fallo\"}");
      }
      nfc.raw().waitForTagRemoval();
      nfc.raw().stopDiscovery();
      nfc.raw().startDiscovery();
      Serial.println("# Listo.");
    }

  } else if (reqLine.startsWith("GET /test")) {
    // Parse id= (stop at & or space)
    int qi = reqLine.indexOf("id=");
    String tid = "";
    if (qi >= 0) {
      int e1 = reqLine.indexOf(' ', qi);
      int e2 = reqLine.indexOf('&', qi + 3);
      if (e2 >= 0 && e2 < e1)
        e1 = e2;
      tid = reqLine.substring(qi + 3, e1);
    }
    // Parse optional amt= (centavos)
    gTestAmt = 0;
    {
      int ai = reqLine.indexOf("amt=");
      if (ai >= 0) {
        int e1 = reqLine.indexOf(' ', ai);
        int e2 = reqLine.indexOf('&', ai + 4);
        if (e2 >= 0 && e2 < e1)
          e1 = e2;
        gTestAmt = (uint64_t)reqLine.substring(ai + 4, e1).toInt();
      }
    }
    handleTest(client, tid);

  } else if (reqLine.startsWith("GET /log")) {
    // GET /log?from=N  — devuelve líneas del ring buffer desde el índice N
    uint16_t from = 0;
    {
      int fi = reqLine.indexOf("from=");
      if (fi >= 0) {
        int e1 = reqLine.indexOf(' ', fi);
        int e2 = reqLine.indexOf('&', fi + 5);
        if (e2 >= 0 && e2 < e1)
          e1 = e2;
        from = (uint16_t)reqLine.substring(fi + 5, e1).toInt();
      }
    }
    // Clamp: nunca retroceder más de LOG_LINES líneas
    if (logHead > from + LOG_LINES)
      from = logHead - LOG_LINES;
    client.println("HTTP/1.1 200 OK");
    client.println("Content-Type: application/json");
    client.println("Connection: close");
    client.println();
    client.print("{\"head\":");
    client.print(logHead);
    client.print(",\"lines\":[");
    bool first = true;
    for (uint16_t i = from; i < logHead; i++) {
      uint16_t idx = i % LOG_LINES;
      if (!first)
        client.print(",");
      first = false;
      client.print("\"");
      // Escapar caracteres JSON básicos
      for (int c = 0; logRing[idx][c]; c++) {
        char ch = logRing[idx][c];
        if (ch == '"')
          client.print("\\\"");
        else if (ch == '\\')
          client.print("\\\\");
        else
          client.print(ch);
      }
      client.print("\"");
    }
    client.print("]}");

    // -------------------------------------------------------------------------
    // Endpoints web de las capacidades "navaja suiza" (equivalentes a los
    // comandos serie): lector NFC de UID, diagnóstico, emulación NDEF y
    // magspoof. Así todo lo del firmware es accesible también desde el panel
    // web.
    // -------------------------------------------------------------------------
  } else if (reqLine.startsWith("GET /tag")) { // lee UID de cualquier tag
    unsigned long t = millis();
    bool found = false;
    while (millis() - t < 8000) {
      if (nfc.raw().isTagDetected()) {
        found = true;
        break;
      }
      delay(50);
    }
    if (!found) {
      sendJson(client, "{\"ok\":false,\"error\":\"sin tag en 8s\"}");
    } else {
      const byte *uid = nfc.raw().remoteDevice.getNFCID();
      unsigned int n = nfc.raw().remoteDevice.getNFCIDLen();
      char uidhex[48];
      HexUtils::toCompact(uid, (int)n, uidhex);
      char b[128];
      snprintf(b, sizeof(b),
               "{\"ok\":true,\"proto\":%d,\"tech\":%d,\"uid\":\"%s\"}",
               nfc.raw().remoteDevice.getProtocol(),
               nfc.raw().remoteDevice.getModeTech(), uidhex);
      sendJson(client, b);
      nfc.raw().reset();
    }

  } else if (reqLine.startsWith("GET /nfcinfo")) { // diagnóstico: chip vivo?
    uint8_t err = nfc.raw().connectNCI();
    if (err) {
      sendJson(client, "{\"ok\":false,\"error\":\"connectNCI\"}");
    } else {
      char b[80];
      snprintf(b, sizeof(b), "{\"ok\":true,\"fwver\":%d}",
               nfc.raw().getFirmwareVersion());
      nfc.raw().configureSettings();
      nfc.raw().configMode();
      nfc.raw().startDiscovery();
      sendJson(client, b);
    }

  } else if (reqLine.startsWith("GET /emu")) { // emula tag NDEF (hex)
    String hx = qparam(reqLine, "hex");
    gEmuLen = HexUtils::decode(hx.c_str(), gEmuBuf, sizeof(gEmuBuf));
    if (gEmuLen < 0)
      gEmuLen = 0;
    // Arranca la emulación persistente (la bombea loop()) y responde enseguida;
    // el progreso APDU-a-APDU se ve por serie. Se detiene con STOP/REBOOT.
    if (emuStart(0)) {
      char b[80];
      snprintf(b, sizeof(b), "{\"ok\":true,\"started\":true,\"len\":%d}",
               gEmuLen);
      sendJson(client, b);
    } else {
      sendJson(client, "{\"ok\":false,\"error\":\"emu mode\"}");
    }

  } else if (reqLine.startsWith("GET /mag")) { // magspoof (banda)
    String t1 = qparam(reqLine, "t1"), t2 = qparam(reqLine, "t2");
    emvyMagPlay(t1.c_str(), t2.c_str());
    sendJson(client, "{\"ok\":true}");

  } else if (reqLine.startsWith("GET / ") || reqLine.startsWith("GET /index")) {
    sendHeaders(client, "text/html");
    streamBody(client, PAGE_HTML, sizeof(PAGE_HTML) - 1);

  } else {
    client.println("HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n");
  }
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------
// --- EMVyBomberCat: modos adicionales (en modes_tags.ino / modes_mag.ino) ---
void emvyTagsRead();
void emvyMagInit();
void emvyMagPlay(const char *track1, const char *track2);

// BomberCatControl::Callbacks hooks (ver EMVyBomberCat.ino más abajo para la
// implementación): controlState() reporta el estado del plano de control para
// `info`; emvyCommand() atiende los verbos operativos que el REPL base no
// reconoce (identify/ping/info los sirve BomberCatControl directamente — el
// parpadeo de IDENTIFY también lo maneja core, mismo timing que antes).
const char *controlState();
bool emvyCommand(const char *verb, char *args);

void setup() {
  Serial.begin(115200);
  delay(800);
#ifdef LED_BUILTIN
  pinMode(LED_BUILTIN, OUTPUT);
  digitalWrite(LED_BUILTIN, LOW);
#endif

  // Fase 5: el plano de control se levanta ANTES del bring-up de WiFi/NFC,
  // para que un fallo de cualquiera de los dos deje la placa reportando
  // "hw-error" en vez de muda — antes un fallo de WiFi colgaba el setup()
  // en while(true) sin llegar nunca a control.begin(), y ni siquiera `ping`
  // respondía. Cambio observable: "+OK bombercat ready" ahora se emite antes
  // que las líneas "# AP:"/"# ERROR:" (no afecta al contrato de
  // descubrimiento, que no depende de este orden).
  BomberCatControl::Callbacks cb;
  cb.state = controlState;
  cb.command = emvyCommand;
  control.setCallbacks(cb);
  control.begin(); // anuncia listo al host CLI (+OK bombercat ready)

  gWifiFault = (WiFi.status() == WL_NO_MODULE);
  if (gWifiFault) {
    Serial.println("# ERROR: WiFi no encontrado");
  } else {
    gWifiFault = (WiFi.beginAP(AP_SSID, AP_PASS) != WL_AP_LISTENING);
    if (gWifiFault) {
      Serial.println("# ERROR: AP fallo");
    } else {
      server.begin();
      IPAddress ip = WiFi.localIP();
      char _b[80];
      snprintf(_b, sizeof(_b), "# AP: %s | http://%d.%d.%d.%d", AP_SSID, ip[0],
               ip[1], ip[2], ip[3]);
      Serial.println(_b);
    }
  }

  resetNFC(); // ya no cuelga: gNfcFault queda registrado si el chip no responde
  emvyMagInit();
  Serial.println("# EMVyBomberCat listo — navaja suiza: EMV/APDU/TAGS/MAG");
  Serial.println("# Acerca la tarjeta contactless...");
}

// Estado del plano de control (reportado por `info`/:state): "emulating"
// mientras hay una emulación NDEF/EMV en curso (gEmuActive), "scanning"
// mientras se espera una tarjeta/tag (WAIT/SCAN/CARDSCAN/TAG), "hw-error"
// (Fase 5) si el bring-up de NFC o WiFi falló — la placa sigue respondiendo
// ping/info aunque el hardware no esté listo —, "idle" en cualquier otro
// momento.
const char *controlState() {
  if (gEmuActive)
    return "emulating";
  if (gScanningCard)
    return "scanning";
  if (gNfcFault || gWifiFault)
    return "hw-error";
  return "idle";
}

// ---------------------------------------------------------------------------
// Emulación NDEF observable (comando EMU:) — ver la nota de gEmuActive arriba.
// APDUs de un lector Type 4 (los que clasificamos para el log):
//   SELECT NDEF-app  00 A4 04 00 07 D2760000850101 00
//   SELECT CC file   00 A4 00 0C 02 E1 03
//   SELECT NDEF file 00 A4 00 0C 02 E1 04
//   READ BINARY      00 B0 <offHi> <offLo> <len>   ← "qué sector/offset lee"
//   UPDATE BINARY    00 D6 <offHi> <offLo> <len>
// ---------------------------------------------------------------------------
static const uint8_t EMU_SEL_APP[] = {0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2,
                                      0x76, 0x00, 0x00, 0x85, 0x01, 0x01};
static const uint8_t EMU_SEL_CC[] = {0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x03};
static const uint8_t EMU_SEL_NDEF[] = {0x00, 0xA4, 0x00, 0x0C,
                                       0x02, 0xE1, 0x04};

// Reporta por serie qué está pidiendo el lector (consola en vivo de EMVy).
static void emuOnReaderApdu(const uint8_t *cmd, uint8_t n) {
  char hx[520];
  HexUtils::toCompact(cmd, n > 256 ? 256 : n, hx);
  if (n >= (uint8_t)sizeof(EMU_SEL_APP) &&
      !memcmp(cmd, EMU_SEL_APP, sizeof(EMU_SEL_APP))) {
    Serial.print("EMU:RX SELECT-APP D2760000850101 ");
    Serial.println(hx);
  } else if (n == (uint8_t)sizeof(EMU_SEL_CC) &&
             !memcmp(cmd, EMU_SEL_CC, sizeof(EMU_SEL_CC))) {
    Serial.print("EMU:RX SELECT-CC E103 ");
    Serial.println(hx);
  } else if (n == (uint8_t)sizeof(EMU_SEL_NDEF) &&
             !memcmp(cmd, EMU_SEL_NDEF, sizeof(EMU_SEL_NDEF))) {
    Serial.print("EMU:RX SELECT-NDEF E104 ");
    Serial.println(hx);
  } else if (n >= 5 && cmd[0] == 0x00 && cmd[1] == 0xB0) {
    unsigned int off = ((unsigned int)cmd[2] << 8) | cmd[3];
    Serial.print("EMU:RX READ off=");
    Serial.print(off);
    Serial.print(" len=");
    Serial.print(cmd[4]);
    Serial.print(" ");
    Serial.println(hx);
  } else if (n >= 5 && cmd[0] == 0x00 && cmd[1] == 0xD6) {
    unsigned int off = ((unsigned int)cmd[2] << 8) | cmd[3];
    Serial.print("EMU:RX WRITE off=");
    Serial.print(off);
    Serial.print(" len=");
    Serial.print(cmd[4]);
    Serial.print(" ");
    Serial.println(hx);
  } else if (n >= 2 && cmd[0] == 0x00 && cmd[1] == 0xA4) {
    Serial.print("EMU:RX SELECT ");
    Serial.println(hx);
  } else {
    Serial.print("EMU:RX APDU ");
    Serial.println(hx);
  }
}

// ===========================================================================
// Emulación de TARJETA EMV (modo gEmuMode==1) — perfilar/fuzzear terminales.
// El firmware responde a los APDUs de un terminal de pago con datos "canned"
// suficientes para que AVANCE en el flujo y revele su configuración:
//   SELECT PPSE (2PAY.SYS.DDF01) -> FCI con un AID (directorio)
//   SELECT AID (cualquiera)      -> FCI con un PDOL (pide datos del terminal)
//   GPO (80 A8)                  -> se troza el PDOL recibido (TTQ/monto/país/
//                                   divisa/fecha/UN/tipo…) y se responde
//                                   AIP+AFL
//   READ RECORD (00 B2)          -> registro con track2/PAN/CDOL1/CVM
//   GENERATE AC (80 AE)          -> se troza el CDOL1 recibido y se responde un
//                                   criptograma DUMMY (sin cripto real del
//                                   emisor)
// No es una tarjeta funcional (no genera ARQC válido) — el objetivo es EXTRAER
// el perfil del terminal (qué pide, con qué parámetros), no aprobar un pago.
// (struct DolItem se define arriba, junto a gEmuMode.)
// ===========================================================================

// PDOL que anunciamos en el FCI del AID (9F38) + tabla para trocear el GPO.
static const uint8_t EMV_PDOL_BYTES[] = {
    0x9F, 0x66, 0x04, 0x9F, 0x02, 0x06, 0x9F, 0x03, 0x06,
    0x9F, 0x1A, 0x02, 0x95, 0x05, 0x5F, 0x2A, 0x02, 0x9A,
    0x03, 0x9C, 0x01, 0x9F, 0x37, 0x04, 0x9F, 0x35, 0x01};
static const DolItem EMV_PDOL[] = {
    {0x9F66, 4, "TTQ"},      {0x9F02, 6, "Monto"}, {0x9F03, 6, "MontoOtro"},
    {0x9F1A, 2, "Pais"},     {0x95, 5, "TVR"},     {0x5F2A, 2, "Divisa"},
    {0x9A, 3, "Fecha"},      {0x9C, 1, "TipoTxn"}, {0x9F37, 4, "UN"},
    {0x9F35, 1, "TipoTerm"},
};
static const int EMV_NUM_PDOL = (int)(sizeof(EMV_PDOL) / sizeof(EMV_PDOL[0]));

// CDOL1 que ponemos en el registro (tag 8C) + tabla para trocear el GENERATE
// AC.
static const uint8_t EMV_CDOL1_BYTES[] = {
    0x9F, 0x02, 0x06, 0x9F, 0x03, 0x06, 0x9F, 0x1A, 0x02,
    0x95, 0x05, 0x5F, 0x2A, 0x02, 0x9A, 0x03, 0x9C, 0x01,
    0x9F, 0x37, 0x04, 0x9F, 0x35, 0x01, 0x9F, 0x34, 0x03};
static const DolItem EMV_CDOL1[] = {
    {0x9F02, 6, "Monto"},    {0x9F03, 6, "MontoOtro"},
    {0x9F1A, 2, "Pais"},     {0x95, 5, "TVR"},
    {0x5F2A, 2, "Divisa"},   {0x9A, 3, "Fecha"},
    {0x9C, 1, "TipoTxn"},    {0x9F37, 4, "UN"},
    {0x9F35, 1, "TipoTerm"}, {0x9F34, 3, "CVMResults"},
};
static const int EMV_NUM_CDOL1 =
    (int)(sizeof(EMV_CDOL1) / sizeof(EMV_CDOL1[0]));

static const uint8_t PPSE_NAME[] = {0x32, 0x50, 0x41, 0x59, 0x2E, 0x53, 0x59,
                                    0x53, 0x2E, 0x44, 0x44, 0x46, 0x30, 0x31};

// -- Datos de tarjeta para el modo EMV --------------------------------------
// Por defecto una Visa de prueba; el backend puede inyectar los datos REALES de
// una captura con `EMUEMV:<aid>|<pan>|<exp>|<track2>` (todo hex; campos vacíos
// = usa el default). Se anuncia el AID en el PPSE y se sirven PAN/expiry/track2
// en el registro, para presentar al terminal la tarjeta capturada.
static const uint8_t DEF_AID[] = {0xA0, 0x00, 0x00, 0x00,
                                  0x03, 0x10, 0x10}; // Visa
static const uint8_t DEF_PAN[] = {0x47, 0x61, 0x73, 0x90,
                                  0x01, 0x01, 0x01, 0x19};
static const uint8_t DEF_EXP[] = {0x25, 0x12, 0x31}; // YYMMDD
static const uint8_t DEF_T2[] = {0x47, 0x61, 0x73, 0x90, 0x01, 0x01, 0x01,
                                 0x19, 0xD2, 0x51, 0x22, 0x01, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x0F};
static bool gCardCustom = false;
static uint8_t gCardAid[16];
static uint8_t gCardAidLen = 0;
static uint8_t gCardPan[12];
static uint8_t gCardPanLen = 0;
static uint8_t gCardExp[3];
static uint8_t gCardExpLen = 0;
static uint8_t gCardT2[40];
static uint8_t gCardT2Len = 0;

// Punteros/longitudes efectivos (captura o default) por campo.
static const uint8_t *cardAid(uint8_t *l) {
  if (gCardCustom && gCardAidLen) {
    *l = gCardAidLen;
    return gCardAid;
  }
  *l = (uint8_t)sizeof(DEF_AID);
  return DEF_AID;
}
static const uint8_t *cardPan(uint8_t *l) {
  if (gCardCustom && gCardPanLen) {
    *l = gCardPanLen;
    return gCardPan;
  }
  *l = (uint8_t)sizeof(DEF_PAN);
  return DEF_PAN;
}
static const uint8_t *cardExp(uint8_t *l) {
  if (gCardCustom && gCardExpLen) {
    *l = gCardExpLen;
    return gCardExp;
  }
  *l = (uint8_t)sizeof(DEF_EXP);
  return DEF_EXP;
}
static const uint8_t *cardT2(uint8_t *l) {
  if (gCardCustom && gCardT2Len) {
    *l = gCardT2Len;
    return gCardT2;
  }
  *l = (uint8_t)sizeof(DEF_T2);
  return DEF_T2;
}

// FCI del PPSE: anuncia el AID de la tarjeta (capturada o Visa por defecto).
static int emvBuildPpseFci(uint8_t *out) {
  uint8_t aidlen;
  const uint8_t *aid = cardAid(&aidlen);
  uint8_t dir[32];
  int d = 0; // 4F <aid> 87 01 01
  dir[d++] = 0x4F;
  dir[d++] = aidlen;
  memcpy(&dir[d], aid, aidlen);
  d += aidlen;
  dir[d++] = 0x87;
  dir[d++] = 0x01;
  dir[d++] = 0x01;
  uint8_t bf[48];
  int b = 0; // BF0C{ 61{ dir } }
  bf[b++] = 0xBF;
  bf[b++] = 0x0C;
  bf[b++] = (uint8_t)(d + 2);
  bf[b++] = 0x61;
  bf[b++] = (uint8_t)d;
  memcpy(&bf[b], dir, d);
  b += d;
  uint8_t inner[80];
  int i = 0; // 84<name> A5{ BF0C }
  inner[i++] = 0x84;
  inner[i++] = (uint8_t)sizeof(PPSE_NAME);
  memcpy(&inner[i], PPSE_NAME, sizeof(PPSE_NAME));
  i += (int)sizeof(PPSE_NAME);
  inner[i++] = 0xA5;
  inner[i++] = (uint8_t)b;
  memcpy(&inner[i], bf, b);
  i += b;
  int o = 0;
  out[o++] = 0x6F;
  out[o++] = (uint8_t)i;
  memcpy(&out[o], inner, i);
  o += i;
  return o;
}

// Nombre de esquema por RID (para el log del SELECT-AID).
static const char *emvSchemeName(const uint8_t *aid, uint8_t len) {
  if (len < 5)
    return "?";
  if (!memcmp(aid, "\xA0\x00\x00\x00\x03", 5))
    return "VISA";
  if (!memcmp(aid, "\xA0\x00\x00\x00\x04", 5))
    return "MASTERCARD";
  if (!memcmp(aid, "\xA0\x00\x00\x00\x25", 5))
    return "AMEX";
  if (!memcmp(aid, "\xA0\x00\x00\x00\x65", 5))
    return "JCB";
  if (!memcmp(aid, "\xA0\x00\x00\x03\x33", 5))
    return "UNIONPAY";
  if (!memcmp(aid, "\xA0\x00\x00\x01\x52", 5))
    return "DISCOVER";
  return "?";
}

// Construye el FCI de respuesta a SELECT AID: 6F{ 84<aid> A5{ 50"CARD"
// 9F38<pdol> } }
static int emvBuildAidFci(const uint8_t *aid, uint8_t aidlen, uint8_t *out) {
  if (aidlen > 16)
    aidlen = 16;
  uint8_t a5[64];
  int a = 0;
  a5[a++] = 0x50;
  a5[a++] = 0x04;
  a5[a++] = 'C';
  a5[a++] = 'A';
  a5[a++] = 'R';
  a5[a++] = 'D';
  a5[a++] = 0x9F;
  a5[a++] = 0x38;
  a5[a++] = (uint8_t)sizeof(EMV_PDOL_BYTES);
  memcpy(&a5[a], EMV_PDOL_BYTES, sizeof(EMV_PDOL_BYTES));
  a += (int)sizeof(EMV_PDOL_BYTES);
  uint8_t inner[128];
  int i = 0;
  inner[i++] = 0x84;
  inner[i++] = aidlen;
  memcpy(&inner[i], aid, aidlen);
  i += aidlen;
  inner[i++] = 0xA5;
  inner[i++] = (uint8_t)a;
  memcpy(&inner[i], a5, a);
  i += a;
  int o = 0;
  out[o++] = 0x6F;
  out[o++] = (uint8_t)i;
  memcpy(&out[o], inner, i);
  o += i;
  return o;
}

// Construye un registro EMV (template 70) con track2/PAN/expiry (de la captura
// o default) + CDOL1/CDOL2/CVM canned. La longitud del 70 usa forma larga (81
// XX) si el contenido supera 127 bytes (track2 largo).
static int emvBuildRecord(uint8_t *out) {
  uint8_t t2l, panl, expl;
  const uint8_t *t2 = cardT2(&t2l), *pan = cardPan(&panl),
                *exp = cardExp(&expl);
  uint8_t b[220];
  int i = 0;
  b[i++] = 0x57;
  b[i++] = t2l;
  memcpy(&b[i], t2, t2l);
  i += t2l;
  b[i++] = 0x5A;
  b[i++] = panl;
  memcpy(&b[i], pan, panl);
  i += panl;
  b[i++] = 0x5F;
  b[i++] = 0x24;
  b[i++] = expl;
  memcpy(&b[i], exp, expl);
  i += expl;
  b[i++] = 0x5F;
  b[i++] = 0x34;
  b[i++] = 0x01;
  b[i++] = 0x00; // PAN seq
  b[i++] = 0x8C;
  b[i++] = (uint8_t)sizeof(EMV_CDOL1_BYTES);
  memcpy(&b[i], EMV_CDOL1_BYTES, sizeof(EMV_CDOL1_BYTES));
  i += (int)sizeof(EMV_CDOL1_BYTES);
  static const uint8_t cdol2[] = {0x91, 0x0A, 0x8A, 0x02, 0x95,
                                  0x05, 0x9F, 0x37, 0x04};
  b[i++] = 0x8D;
  b[i++] = (uint8_t)sizeof(cdol2);
  memcpy(&b[i], cdol2, sizeof(cdol2));
  i += (int)sizeof(cdol2);
  static const uint8_t cvm[] = {0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x1F, 0x00};
  b[i++] = 0x8E;
  b[i++] = (uint8_t)sizeof(cvm);
  memcpy(&b[i], cvm, sizeof(cvm));
  i += (int)sizeof(cvm);
  int o = 0;
  out[o++] = 0x70;
  if (i <= 127) {
    out[o++] = (uint8_t)i;
  } else {
    out[o++] = 0x81;
    out[o++] = (uint8_t)i;
  }
  memcpy(&out[o], b, i);
  o += i;
  return o;
}

// Construye la respuesta del GPO estilo **qVSDC** (Visa contactless): template
// 77 con el criptograma DENTRO (AIP/AFL + ATC/AC/CID/IAD/CTQ + track2). Sin
// esto (solo AIP+AFL en un 80) el kernel Visa 3 trata la transacción como
// incompleta y re-arma el campo en bucle. CID=0x80 (ARQC) → el terminal pide
// autorización online. El AC es DUMMY (no hay clave del emisor): no aprueba el
// pago, pero el terminal deja de reintentar y avanza a su decisión
// (online/declina).
static uint16_t gEmuAtc = 0; // ATC de la tarjeta emulada; incrementa por GPO
static int emvBuildGpoResp(uint8_t *out) {
  uint8_t t2l;
  const uint8_t *t2 = cardT2(&t2l);
  static const uint8_t AC8[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33};
  static const uint8_t IAD7[] = {0x06, 0x01, 0x12, 0x03,
                                 0xA0, 0x60, 0x00}; // IAD estilo Visa
  gEmuAtc++;
  uint8_t b[200];
  int i = 0;
  // Estructura calcada de una respuesta qVSDC real (Visa contactless), SIN AFL:
  // todo va dentro del 77 (fast-path), así el terminal no hace READ RECORD y no
  // rechaza-reinicia. AIP=2000, CTQ=2840, FFI=20700000 como una tarjeta real.
  // AIP = 1800: CVM soportado (b5) + gestión de riesgo (b4), SIN SDA/DDA/CDA.
  // Anunciar DDA/CDA (p.ej. 2000/1980) hace que el kernel Visa espere la firma
  // 9F4B (fDDA) dentro del GPO; como no podemos firmarla, la trataba como
  // "tarjeta ilegible" y abortaba. Sin auth offline el terminal salta la ODA y
  // va directo a online con el ARQC (lo que su TTQ ya pide).
  b[i++] = 0x82;
  b[i++] = 0x02;
  b[i++] = 0x18;
  b[i++] = 0x00; // AIP = 1800
  // AFL SFI1 rec1: hace que el terminal ADEMÁS lea el registro (READ RECORD) →
  // más traza en la consola (útil para perfilar). El criptograma ya va aquí en
  // el 77, así que el terminal no depende del registro para el cripto.
  b[i++] = 0x94;
  b[i++] = 0x04;
  b[i++] = 0x08;
  b[i++] = 0x01;
  b[i++] = 0x01;
  b[i++] = 0x00;
  b[i++] = 0x57;
  b[i++] = t2l;
  memcpy(&b[i], t2, t2l);
  i += t2l; // Track2 equiv
  b[i++] = 0x5F;
  b[i++] = 0x34;
  b[i++] = 0x01;
  b[i++] = 0x01; // PAN seq = 01
  b[i++] = 0x9F;
  b[i++] = 0x10;
  b[i++] = 0x07;
  memcpy(&b[i], IAD7, 7);
  i += 7; // IAD
  b[i++] = 0x9F;
  b[i++] = 0x26;
  b[i++] = 0x08;
  memcpy(&b[i], AC8, 8);
  i += 8; // AC (dummy)
  b[i++] = 0x9F;
  b[i++] = 0x27;
  b[i++] = 0x01;
  b[i++] = 0x80; // CID = ARQC
  b[i++] = 0x9F;
  b[i++] = 0x36;
  b[i++] = 0x02; // ATC (incrementa)
  b[i++] = (uint8_t)(gEmuAtc >> 8);
  b[i++] = (uint8_t)(gEmuAtc & 0xFF);
  b[i++] = 0x9F;
  b[i++] = 0x6C;
  b[i++] = 0x02;
  b[i++] = 0x28;
  b[i++] = 0x40; // CTQ = 2840
  b[i++] = 0x9F;
  b[i++] = 0x6E;
  b[i++] = 0x04;
  b[i++] = 0x20;
  b[i++] = 0x70;
  b[i++] = 0x00;
  b[i++] = 0x00; // FFI
  int o = 0;
  out[o++] = 0x77;
  if (i <= 127) {
    out[o++] = (uint8_t)i;
  } else {
    out[o++] = 0x81;
    out[o++] = (uint8_t)i;
  }
  memcpy(&out[o], b, i);
  o += i;
  return o;
}

// Parsea `EMUEMV:<aid>|<pan>|<exp>|<track2>` (hex; campos vacíos = default) e
// inyecta los datos de la captura en la tarjeta emulada. Reporta lo cargado.
static void emvParseCard(const String &p) {
  gCardAidLen = gCardPanLen = gCardExpLen = gCardT2Len = 0;
  int from = 0;
  for (int f = 0; f < 4; f++) {
    int bar = p.indexOf('|', from);
    String tok = (bar < 0) ? p.substring(from) : p.substring(from, bar);
    tok.trim();
    if (tok.length()) {
      if (f == 0)
        gCardAidLen =
            (uint8_t)HexUtils::decode(tok.c_str(), gCardAid, sizeof(gCardAid));
      else if (f == 1)
        gCardPanLen =
            (uint8_t)HexUtils::decode(tok.c_str(), gCardPan, sizeof(gCardPan));
      else if (f == 2)
        gCardExpLen =
            (uint8_t)HexUtils::decode(tok.c_str(), gCardExp, sizeof(gCardExp));
      else if (f == 3)
        gCardT2Len =
            (uint8_t)HexUtils::decode(tok.c_str(), gCardT2, sizeof(gCardT2));
    }
    if (bar < 0)
      break;
    from = bar + 1;
  }
  gCardCustom = (gCardAidLen || gCardPanLen || gCardT2Len || gCardExpLen);
  Serial.print("EMU:CARD aid=");
  Serial.print(gCardAidLen);
  Serial.print(" pan=");
  Serial.print(gCardPanLen);
  Serial.print(" exp=");
  Serial.print(gCardExpLen);
  Serial.print(" t2=");
  Serial.println(gCardT2Len);
}

// Copia la tarjeta recién leída (struct `card`: strings
// pan/track2/aidHex/expiry) a los buffers de emulación gCard* (RAM). Es lo que
// permite el flujo on-device "escanear → RAM → reemular": tras CARDSCAN queda
// cargada y EMUEMV:RAM la sirve.
static bool storeScannedCard() {
  gCardAidLen = gCardPanLen = gCardExpLen = gCardT2Len = 0;
  if (card.aidHex[0])
    gCardAidLen =
        (uint8_t)HexUtils::decode(card.aidHex, gCardAid, sizeof(gCardAid));
  if (card.track2[0])
    gCardT2Len =
        (uint8_t)HexUtils::decode(card.track2, gCardT2, sizeof(gCardT2));
  if (card.pan[0]) { // dígitos → BCD (pad 'F' si impar)
    char tmp[26];
    strncpy(tmp, card.pan, sizeof(tmp) - 2);
    tmp[sizeof(tmp) - 2] = '\0';
    int l = (int)strlen(tmp);
    if (l % 2) {
      tmp[l] = 'F';
      tmp[l + 1] = '\0';
    }
    gCardPanLen = (uint8_t)HexUtils::decode(tmp, gCardPan, sizeof(gCardPan));
  }
  if (card.expiry[0]) { // YYMM → YYMMDD
    char e[8] = "";
    strncpy(e, card.expiry, 4);
    e[4] = '\0';
    if (strlen(e) == 4)
      strcat(e, "31");
    gCardExpLen = (uint8_t)HexUtils::decode(e, gCardExp, sizeof(gCardExp));
  }
  gCardCustom = (gCardAidLen || gCardPanLen || gCardT2Len);
  return gCardCustom;
}

// Loguea cada campo de un DOL recibido (GPO/GENERATE AC) troceado por la tabla.
static void emvLogDol(const char *which, const DolItem *dol, int n,
                      const uint8_t *data, int datalen) {
  int off = 0;
  for (int k = 0; k < n && off < datalen; k++) {
    int L = dol[k].len;
    if (off + L > datalen)
      L = datalen - off;
    char hx[64];
    HexUtils::toCompact(&data[off], L > 28 ? 28 : L, hx);
    char t[8];
    if (dol[k].tag > 0xFF)
      snprintf(t, sizeof(t), "%04X", dol[k].tag);
    else
      snprintf(t, sizeof(t), "%02X", dol[k].tag);
    Serial.print("  ");
    Serial.print(which);
    Serial.print(" ");
    Serial.print(dol[k].name);
    Serial.print("(");
    Serial.print(t);
    Serial.print(")=");
    Serial.println(hx);
    off += dol[k].len;
  }
}

static void emvSetSw(uint8_t *rsp, unsigned short *len, uint8_t sw1,
                     uint8_t sw2) {
  rsp[0] = sw1;
  rsp[1] = sw2;
  *len = 2;
}
static void emvAppendSw(uint8_t *rsp, unsigned short *len, uint8_t sw1,
                        uint8_t sw2) {
  rsp[*len] = sw1;
  rsp[(*len) + 1] = sw2;
  *len += 2;
}

// Calcula la respuesta a un APDU del terminal en modo EMV. **PURA** (sin
// Serial): el logging va aparte (emvLogCmd) y se hace DESPUÉS de responder,
// para no meter latencia de serie en mitad de la transacción (qVSDC es sensible
// al FWT).
static void emvCardRespond(const uint8_t *cmd, uint8_t n, uint8_t *rsp,
                           unsigned short *rspLen) {
  uint8_t cla = cmd[0], ins = cmd[1];
  uint8_t p1 = (n > 2 ? cmd[2] : 0);
  if (ins == 0xA4 && p1 == 0x04) { // SELECT by name
    uint8_t lc = (n > 4 ? cmd[4] : 0);
    const uint8_t *d = &cmd[5];
    if (lc == (uint8_t)sizeof(PPSE_NAME) &&
        !memcmp(d, PPSE_NAME, sizeof(PPSE_NAME)))
      *rspLen =
          (unsigned short)emvBuildPpseFci(rsp); // anuncia el AID de la tarjeta
    else
      *rspLen = (unsigned short)emvBuildAidFci(d, lc, rsp);
    emvAppendSw(rsp, rspLen, 0x90, 0x00);
    return;
  }
  if (cla == 0x80 && ins == 0xA8) { // GET PROCESSING OPTIONS
    *rspLen =
        (unsigned short)emvBuildGpoResp(rsp); // qVSDC: criptograma en el 77
    emvAppendSw(rsp, rspLen, 0x90, 0x00);
    return;
  }
  if (ins == 0xB2) { // READ RECORD
    *rspLen = (unsigned short)emvBuildRecord(rsp);
    emvAppendSw(rsp, rspLen, 0x90, 0x00);
    return;
  }
  if (cla == 0x80 && ins == 0xAE) { // GENERATE AC
    static const uint8_t AC[] = {
        0x77, 0x1E, 0x9F, 0x27, 0x01, 0x80, 0x9F, 0x36, 0x02, 0x00, 0x01,
        0x9F, 0x26, 0x08, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33,
        0x9F, 0x10, 0x07, 0x06, 0x01, 0x0A, 0x03, 0xA0, 0x00, 0x00};
    memcpy(rsp, AC, sizeof(AC));
    *rspLen = sizeof(AC);
    emvAppendSw(rsp, rspLen, 0x90, 0x00);
    return;
  }
  if (cla == 0x80 && ins == 0xCA) {
    emvSetSw(rsp, rspLen, 0x6A, 0x88);
    return;
  } // GET DATA
  emvSetSw(rsp, rspLen, 0x6D, 0x00); // INS no soportado
}

// Reporta por serie el APDU del terminal (decodificado). Se llama DESPUÉS de
// haberle respondido, para no retrasar la respuesta (ver nota en
// emvCardRespond).
static void emvLogCmd(const uint8_t *cmd, uint8_t n) {
  char hx[600];
  HexUtils::toCompact(cmd, n > 256 ? 256 : n, hx);
  uint8_t cla = cmd[0], ins = cmd[1];
  uint8_t p1 = (n > 2 ? cmd[2] : 0), p2 = (n > 3 ? cmd[3] : 0);
  if (ins == 0xA4 && p1 == 0x04) {
    uint8_t lc = (n > 4 ? cmd[4] : 0);
    const uint8_t *d = &cmd[5];
    if (lc == (uint8_t)sizeof(PPSE_NAME) &&
        !memcmp(d, PPSE_NAME, sizeof(PPSE_NAME))) {
      Serial.print("EMU:RX SELECT-PPSE 2PAY.SYS.DDF01 ");
      Serial.println(hx);
    } else {
      char aidhx[40];
      HexUtils::toCompact(d, lc > 16 ? 16 : lc, aidhx);
      Serial.print("EMU:RX SELECT-AID ");
      Serial.print(aidhx);
      Serial.print(" (");
      Serial.print(emvSchemeName(d, lc));
      Serial.print(") ");
      Serial.println(hx);
    }
  } else if (cla == 0x80 && ins == 0xA8) {
    Serial.print("EMU:RX GPO ");
    Serial.println(hx);
    uint8_t lc = (n > 4 ? cmd[4] : 0);
    const uint8_t *d = &cmd[5];
    if (lc >= 2 && d[0] == 0x83)
      emvLogDol("PDOL", EMV_PDOL, EMV_NUM_PDOL, &d[2], d[1]);
  } else if (ins == 0xB2) {
    Serial.print("EMU:RX READ-RECORD rec=");
    Serial.print(p1);
    Serial.print(" sfi=");
    Serial.print(p2 >> 3);
    Serial.print(" ");
    Serial.println(hx);
  } else if (cla == 0x80 && ins == 0xAE) {
    const char *t = ((p1 & 0xC0) == 0x40)   ? "TC"
                    : ((p1 & 0xC0) == 0x80) ? "ARQC"
                                            : "AAC";
    Serial.print("EMU:RX GENERATE-AC pide=");
    Serial.print(t);
    Serial.print(" ");
    Serial.println(hx);
    uint8_t lc = (n > 4 ? cmd[4] : 0);
    emvLogDol("CDOL1", EMV_CDOL1, EMV_NUM_CDOL1, &cmd[5], lc);
  } else if (cla == 0x80 && ins == 0xCA) {
    Serial.print("EMU:RX GET-DATA ");
    Serial.println(hx);
  } else {
    Serial.print("EMU:RX APDU ");
    Serial.println(hx);
  }
}

// Detiene la emulación y devuelve el chip a modo lector (PING/WAIT/APDU/TAG
// vuelven a operar). Idempotente. `reason` se reporta para trazabilidad.
static void emuStop(const char *reason) {
  if (!gEmuActive)
    return;
  gEmuActive = false;
  nfc.raw().setReaderWriterMode();
  nfc.raw().startDiscovery();
  gPassthroughActive = false;
  Serial.print("EMU:DONE sent=");
  Serial.print(gEmuSentCount);
  Serial.print(" reason=");
  Serial.println(reason);
}

// Arranca la emulación. No bloquea: el servicio real ocurre en emuPump() desde
// loop(). mode=0 = tag NDEF (sirve gEmuBuf vía T4T; setContent() presenta los
// bytes crudos —para un hex sin addRecord, updateHeaderFlags() es no-op— ideal
// para fuzzing malformado). mode=1 = tarjeta EMV (responde a un terminal de
// pago).
static bool emuStart(int mode) {
  if (gEmuActive)
    emuStop("restart");
  gEmuMode = mode;
  if (mode == 0) {
    emuMessage.setContent((const char *)gEmuBuf, (unsigned short)gEmuLen);
    nfc.raw().setSendMsgCallback(emuSentCallback);
  }
  gEmuSent = false;
  gEmuSentCount = 0;
  // setEmulationMode() (setMode+reset NCI) puede fallar la 1ª vez al venir de
  // un passthrough/dump intensivo (chip a media sesión de lector). Reintentar
  // tras re-inicializar el NCI lo recupera — igual que resetNFC() al arrancar.
  bool ok = nfc.raw().setEmulationMode();
  for (int a = 0; !ok && a < 3; a++) {
    nfc.raw().connectNCI();
    nfc.raw().configureSettings();
    nfc.raw().configMode();
    delay(40);
    ok = nfc.raw().setEmulationMode();
  }
  if (!ok) {
    Serial.println("ERR:EMU_MODE");
    nfc.raw().setReaderWriterMode();
    nfc.raw().startDiscovery();
    return false;
  }
  gEmuActive = true;
  gEmuStart = millis();
  if (mode == 1)
    Serial.println("EMU:START mode=emv");
  else {
    Serial.print("EMU:START len=");
    Serial.println(gEmuLen);
  }
  return true;
}

// Atiende UN APDU del lector por iteración de loop() (si lo hay), lo responde
// según el modo (T4T NDEF o tarjeta EMV) y reporta comando/respuesta.
// cardModeSend() añade su propia cabecera NCI de 3 bytes → pasamos la resp
// cruda.
static void emuPump() {
  uint8_t cmd[256];
  uint8_t cmdSize = 0;
  if (nfc.raw().cardModeReceive(cmd, &cmdSize) == 0 && cmdSize >= 2) {
    uint8_t rsp[256];
    unsigned short rspSize = 0;
    if (gEmuMode == 1)
      emvCardRespond(cmd, cmdSize, rsp, &rspSize); // PURO: solo calcula
    else
      T4T_NDEF_EMU_Next(cmd, (unsigned short)cmdSize, rsp, &rspSize);
    if (rspSize > sizeof(rsp))
      rspSize = sizeof(rsp);
    // RESPONDER PRIMERO (mínima espera para el terminal; qVSDC es sensible al
    // FWT), y loguear DESPUÉS — el log por serie de un APDU tarda ~ms.
    nfc.raw().cardModeSend(rsp, (uint8_t)rspSize);
    if (gEmuMode == 1)
      emvLogCmd(cmd, cmdSize);
    else
      emuOnReaderApdu(cmd, cmdSize);
    char hx[520];
    HexUtils::toCompact(rsp, rspSize > 256 ? 256 : rspSize, hx);
    Serial.print("EMU:TX ");
    Serial.println(hx);
    if (gEmuSent) {
      gEmuSent = false;
      gEmuSentCount++;
      Serial.print("EMU:MSG-SENT n=");
      Serial.println(gEmuSentCount);
    }
  }
  if (millis() - gEmuStart > EMU_MAX_MS)
    emuStop("timeout");
}

// ---------------------------------------------------------------------------
// BomberCatControl::Callbacks::command hook — ping/info/identify ya los sirve
// BomberCatControl (core), case-insensitive; este hook solo atiende el
// dialecto operativo histórico (WAIT/APDU:/EMU:/EMUEMV/MAG:/TAG/CARDSCAN/
// REBOOT/STOP/RELEASE/NFCINFO/SCAN), sin cambios de comportamiento respecto a
// la versión previa. `verb`/`args` llegan ya separados por el primer espacio
// (BomberCatControl.h); se reconstruyen en una sola línea para reutilizar el
// parseo original basado en offsets fijos (p.ej. c.substring(4) para "MAG:")
// y para no partir payloads con espacios embebidos (p.ej. un track1 con un
// espacio en el nombre del titular). Un verbo no reconocido retorna false: el
// propio BomberCatControl emite "-ERR unknown command <verb>" (§6.3.3/C-11).
// ---------------------------------------------------------------------------
bool emvyCommand(const char *verb, char *args) {
  String c(verb);
  if (args != nullptr && args[0] != '\0') {
    c += ' ';
    c += args;
  }
  c.trim();
  if (c.length() == 0)
    return false;
  String up = c;
  up.toUpperCase();

  // REBOOT / RESET — reinicio completo del MCU (RP2040). Útil desde la GUI/TUI
  // para salir de un estado atascado (p.ej. emulación colgada) sin desconectar
  // físicamente la placa. El USB CDC se re-enumera: el host debe reconectar.
  if (up == "REBOOT" || up == "RESET") {
    Serial.println("# REBOOT");
    Serial.flush();
    delay(80);
    NVIC_SystemReset(); // no retorna
    return true;
  }

  // STOP — detiene la emulación NDEF en curso (si la hay) en cualquier momento.
  if (up == "STOP") {
    if (gEmuActive)
      emuStop("stop");
    else
      Serial.println("OK");
    return true;
  }

  // Si estamos emulando y llega un comando que necesita el modo lector, detener
  // la emulación primero (deja el chip en modo lector antes de atenderlo).
  if (gEmuActive && (up.startsWith("WAIT") || up.startsWith("APDU:") ||
                     up.startsWith("SCAN") || up == "TAG" || up == "TAGS" ||
                     up == "NFCINFO" || up.startsWith("MAG:"))) {
    emuStop("preempt");
  }

  // NFCINFO — diagnóstico: reconecta al PN7150, reporta su versión de firmware
  // (confirma que la comunicación I2C con el chip funciona) y re-arma el
  // discovery del lector. Útil cuando no se detectan tarjetas: si devuelve una
  // versión, el chip está vivo y el problema es RF (tarjeta/antena/colocación).
  if (up == "NFCINFO") {
    uint8_t err = nfc.raw().connectNCI();
    if (err) {
      Serial.println("NFCINFO: ERR connectNCI (chip no responde)");
      return true;
    }
    char b[48];
    snprintf(b, sizeof(b), "NFCINFO: fwver=%d (chip vivo)",
             nfc.raw().getFirmwareVersion());
    Serial.println(b);
    nfc.raw().configureSettings();
    nfc.raw().configMode();
    nfc.raw().startDiscovery();
    Serial.println("NFCINFO: discovery re-armado");
    return true;
  }

  // -------------------------------------------------------------------------
  // Navaja suiza (EMVyBomberCat):
  //   TAG / TAGS              -> lee un tag y emite TAG:<proto> UID:<hex>
  //   MAG:<track1>|<track2>   -> emula un swipe de banda (magspoof); OK
  // -------------------------------------------------------------------------
  if (up == "TAG" || up == "TAGS") {
    gScanningCard = true;
    emvyTagsRead();
    gScanningCard = false;
    return true;
  }

  if (up.startsWith("MAG:")) {
    String rest = c.substring(4);
    int bar = rest.indexOf('|');
    String t1 = (bar >= 0) ? rest.substring(0, bar) : rest;
    String t2 = (bar >= 0) ? rest.substring(bar + 1) : String("");
    emvyMagPlay(t1.c_str(), t2.c_str());
    Serial.println("OK");
    return true;
  }

  if (up.startsWith("WAIT")) {
    unsigned long ms = 30000;
    int sp = up.indexOf(' ');
    if (sp >= 0)
      ms = (unsigned long)c.substring(sp + 1).toInt();
    // Rearma el discovery NCI (igual que TAG/SCAN) y luego encuestra: tras
    // cualquier detección previa (TAG/APDU) el aviso NCI de una tarjeta que
    // sigue físicamente presente ya se consumió y no vuelve a llegar hasta
    // reiniciar el discovery loop. Un solo reset() al entrar no basta: el
    // ciclo de poll/anticolisión del PN7150 puede tardar varios segundos en
    // volver a generar el aviso, así que se re-arma periódicamente dentro de
    // toda la ventana de espera en vez de una sola vez al principio (evita
    // la carrera de "reset justo antes de la única lectura corta").
    // No usa waitForTagRemoval() (a diferencia de RELEASE): aquí SÍ queremos
    // detectar de inmediato una tarjeta que ya esté puesta.
    gScanningCard = true;
    nfc.raw().reset();
    unsigned long lastRearm = millis();
    bool found = false;
    unsigned long tw = millis();
    while (millis() - tw < ms) {
      // Sin atender clientes WiFi aquí (a diferencia de otros comandos): un
      // handleClient() sirviendo el dashboard puede tardar cientos de ms y
      // hacer que se pierda la ventana de la notificación NCI de activación.
      if (nfc.raw().isTagDetected() &&
          nfc.raw().remoteDevice.getProtocol() == nfc.raw().protocol.ISODEP) {
        found = true;
        break;
      }
      if (millis() - lastRearm > 2500) {
        nfc.raw().reset();
        lastRearm = millis();
      }
      control.poll(); // atiende ping/info/identify durante la espera
      delay(40);
    }
    gScanningCard = false;
    // isTagDetected() es de FLANCO (avisa una vez por notificación NCI), no
    // de nivel: si aquí volviéramos a llamarlo desde APDU: casi siempre daría
    // false aunque la tarjeta siga presente, porque el aviso ya se consumió.
    // Por eso se recuerda el resultado en gPassthroughActive en vez de
    // re-consultar al hardware en cada APDU (mismo patrón que ya usa
    // runEmvFlowOnce, que jamás vuelve a llamar isTagDetected() entre APDUs).
    gPassthroughActive = found;
    Serial.println(found ? "READY:" : "ERR:NOCARD");
    return true;
  }

  if (up.startsWith("APDU:")) {
    String hx = c.substring(5);
    hx.trim();
    uint8_t apdu[264];
    int alen = HexUtils::decode(hx.c_str(), apdu, sizeof(apdu));
    if (alen < 4) {
      Serial.println("ERR:BADAPDU");
      return true;
    }
    if (!gPassthroughActive) {
      Serial.println("ERR:NOCARD");
      return true;
    }
    uint8_t resp[264];
    uint8_t rlenFrag = 0;
    if (nfc.raw().readerTagCmd(apdu, (uint8_t)alen, resp, &rlenFrag)) {
      gPassthroughActive =
          false; // fallo de transmisión: se asume tarjeta retirada
      Serial.println("ERR:TXFAIL");
      return true;
    }
    uint16_t rlen = rlenFrag;
    drainNciFragments(resp, rlen);
    char out[600];
    HexUtils::toCompact(resp, rlen, out);
    Serial.print("RESP:");
    Serial.println(out);
    return true;
  }

  if (up == "RELEASE") {
    if (gEmuActive) {
      emuStop("release");
      return true;
    }
    gPassthroughActive = false;
    nfc.raw().waitForTagRemoval();
    nfc.raw().stopDiscovery();
    nfc.raw().startDiscovery();
    Serial.println("OK");
    return true;
  }

  // -------------------------------------------------------------------------
  // EMU:<hex> — emula un tag NFC Type 4 sirviendo <hex> como mensaje NDEF.
  // NO bloquea: arranca la emulación y vuelve enseguida; loop() la bombea con
  // emuPump(), que reporta cada APDU del lector (EMU:RX .../EMU:TX .../
  // EMU:MSG-SENT). Se detiene con STOP/RELEASE en cualquier momento, con
  // REBOOT, al mandar otro EMU: (reinicia) o por el auto-stop de seguridad
  // (EMU_MAX_MS). Reporta EMU:START al arrancar y EMU:DONE al terminar. Sirve
  // para fuzzear cómo un lector/POS/telefono NFC parsea un NDEF fuera de norma.
  // -------------------------------------------------------------------------
  // CARDSCAN — lee una tarjeta EMV por NFC y la guarda en RAM (gCard*) para
  // reemularla luego con EMUEMV:RAM. Flujo on-device "escanear → RAM → emular"
  // sin PC ni archivos. Reporta EMU:SCANNED aid/pan/exp o ERR:NOCARD/SCANFAIL.
  if (up == "CARDSCAN" || up.startsWith("CARDSCAN ")) {
    if (gEmuActive)
      emuStop("preempt");
    Serial.println("# CARDSCAN: acerca la tarjeta contactless a leer...");
    gScanningCard = true;
    bool found = pollCard(20000);
    gScanningCard = false;
    if (!found) {
      Serial.println("ERR:NOCARD");
      releaseCard();
      return true;
    }
    memset(&card, 0, sizeof(card));
    if (!runEmvFlow(50)) {
      Serial.println("ERR:SCANFAIL");
      releaseCard();
      return true;
    }
    storeScannedCard();
    // Reporta los campos COMPLETOS (incluido el track2 hex) para que el editor
    // del host pueda cargar un escaneo de RAM y editarlo.
    Serial.print("EMU:SCANNED aid=");
    Serial.print(card.aidHex);
    Serial.print(" pan=");
    Serial.print(card.pan);
    Serial.print(" exp=");
    Serial.print(card.expiry);
    Serial.print(" t2=");
    Serial.println(card.track2);
    releaseCard();
    return true;
  }

  // EMUEMV[:<aid>|<pan>|<exp>|<track2>|RAM] — emula una TARJETA EMV para
  // perfilar/ fuzzear un terminal de pago (responde PPSE/SELECT/GPO/READ
  // RECORD/GEN AC y reporta lo que pide). Sin parámetros usa una Visa de
  // prueba; con `:<hex...>` inyecta los datos REALES de una captura (host); con
  // `:RAM` reemula la tarjeta guardada en RAM por CARDSCAN. Se para igual que
  // la NDEF. Debe ir ANTES de "EMU:".
  if (up.startsWith("EMUEMV")) {
    int colon = c.indexOf(':');
    if (colon >= 0) {
      String rest = c.substring(colon + 1);
      rest.trim();
      String ru = rest;
      ru.toUpperCase();
      if (ru == "RAM") {
        if (!gCardCustom)
          Serial.println(
              "# EMUEMV:RAM sin tarjeta en RAM — usando tarjeta de prueba");
        // usa gCard* tal cual (de CARDSCAN o un EMUEMV: previo); no la toca
      } else {
        emvParseCard(rest);
      }
    } else {
      gCardCustom = false; // EMUEMV a secas = tarjeta de prueba canned
    }
    emuStart(1);
    return true;
  }

  if (up.startsWith("EMU:")) {
    String hx = c.substring(4);
    hx.trim();
    gEmuLen = HexUtils::decode(hx.c_str(), gEmuBuf, sizeof(gEmuBuf));
    if (gEmuLen < 0)
      gEmuLen = 0; // mensaje vacío es válido (tag vacío)
    emuStart(0);
    return true;
  }

  // -------------------------------------------------------------------------
  // SCAN <centavos>: flujo EMV completo -> JSON_START/END (comportamiento
  // previo)
  // -------------------------------------------------------------------------
  if (!up.startsWith("SCAN")) {
    return false; // verbo no reconocido -> BomberCatControl emite -ERR
  }

  int sp = up.indexOf(' ');
  uint64_t amt = (sp >= 0) ? (uint64_t)c.substring(sp + 1).toInt() : 500;

  SLOGF("# CMD serial: SCAN %lu centavos", (unsigned long)amt);
  Serial.println("# Esperando tarjeta ISO-DEP...");

  gScanningCard = true;
  bool tagFound = false;
  unsigned long tw = millis();
  while (millis() - tw < 30000) {
    if (nfc.raw().isTagDetected() &&
        nfc.raw().remoteDevice.getProtocol() == nfc.raw().protocol.ISODEP) {
      tagFound = true;
      break;
    }
    // Atender el plano de control (ping/info/identify) y WiFi para que el
    // USB CDC no pierda conexión ni el host vea la placa colgada.
    control.poll();
    WiFiClient wc = server.available();
    if (wc) {
      handleClient(wc);
      wc.stop();
    }
    delay(50);
  }
  gScanningCard = false;
  if (!tagFound) {
    Serial.println("# ERROR: Timeout — sin tarjeta en 30s");
    return true;
  }
  if (runEmvFlow(amt)) {
    buildWebJson(amt);
    Serial.println("JSON_START");
    Serial.println(webResult);
    Serial.println("JSON_END");
    nfc.raw().waitForTagRemoval();
    nfc.raw().stopDiscovery();
    nfc.raw().startDiscovery();
    Serial.println("# Listo.");
  } else {
    Serial.println("# ERROR: Flujo EMV fallo — ver log");
    nfc.raw().waitForTagRemoval();
    nfc.raw().stopDiscovery();
    nfc.raw().startDiscovery();
  }
  return true;
}

// ---------------------------------------------------------------------------
// Loop
// ---------------------------------------------------------------------------
void loop() {
  control.poll(); // servicio del plano de control (ping/info/identify/…)

  WiFiClient client = server.available();
  if (client) {
    handleClient(client);
    client.stop();
  }

  // Emulación NDEF observable: se bombea aquí para que sea cancelable (STOP/
  // REBOOT se leen entre pumps) y no un bloqueo de 30 s.
  if (gEmuActive)
    emuPump();
}
