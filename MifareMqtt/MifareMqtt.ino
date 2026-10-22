/************************************************************
  BomberCat MifareMqtt - WiFi/MQTT uplink Core (Fase 4, tarea 4.7)

  A standalone Core that publishes the Mifare Classic dumps the MifareClassic
  firmware persisted in the board's flash (the §4.6 result ring) over MQTT, in
  the VERY SAME wire format a live dump uses - so the host rebuilds the
  canonical dump with the parser it already has and `mifare analyze` gives the
  same honest report, holes and all, without a USB cable.

  WHY A SEPARATE CORE (not radio inside MifareClassic): the on-board ESP32 is a
  NINA coprocessor over SPI1, driven from the RP2040 with WiFiNINA (no ESP32
  image to build); MagSpoofMqtt/NFCGate already prove WiFiNINA + PubSubClient on
  this board. This Core reuses the §4.6 result store verbatim (a symlink, not a
  copy) and the shared BomberCatCore library, and never re-cracks a card: the
  operator cracks with the MifareClassic firmware (which fills the ring), then
  flashes this Core to uplink. The crack engine is not duplicated.

  POWER NOTE (§4.7, task 4.5 override): the current budget (F1 fuse, 0.5 A) is
  still UNMEASURED. WiFi association and TX are the biggest current spikes on
  this board; this Core activates the radio before 4.5 is closed, which the
  plan flags as a brownout risk with no safety net. Measure 4.5 before relying
  on this in a long standalone session.

  SECURITY NOTE (§4.7): MQTT here is in the CLEAR (port 1883). The recovered
  keys and card blocks travel the network UNENCRYPTED. Use a trusted WiFi.

  Distributed as-is; no warranty is given.
*/
#include "arduino_secrets.h"

#include <BomberCatControl.h>
#include <ConfigStore.h>
#include <MifareDumpFormat.h>
#include <MifareResultStore.h>
#include <MqttUplink.h>

#define BOMBERCAT_FW_VERSION "1.0.0.0"
#define BOMBERCAT_FW_NAME "mifaremqtt"

// ── Persisted credentials (§4.7: a Mifare-own POD record, like the key-store
// and the result store, NOT the NFCGate RelayConfig). Stored as a ConfigStore
// blob under this key; absent/empty -> the arduino_secrets.h fallback. ────────
static const char *MIFARE_MQTT_CFG_KEY = "mifamqtt";
static const uint8_t MIFARE_MQTT_CFG_VERSION = 1;

struct MifareMqttConfig {
  uint8_t version; // MIFARE_MQTT_CFG_VERSION; a different layout is rejected
  uint8_t pad[3];
  char ssid[64];
  char pass[64];
  char server[64];
  char topic[64];
  uint16_t port;
};

static MifareMqttConfig cfg;

static void cfgDefaults(MifareMqttConfig &c) {
  memset(&c, 0, sizeof(c));
  c.version = MIFARE_MQTT_CFG_VERSION;
  strncpy(c.ssid, MIFARE_MQTT_SSID, sizeof(c.ssid) - 1);
  strncpy(c.pass, MIFARE_MQTT_PASS, sizeof(c.pass) - 1);
  strncpy(c.server, MIFARE_MQTT_SERVER, sizeof(c.server) - 1);
  strncpy(c.topic, MIFARE_MQTT_TOPIC, sizeof(c.topic) - 1);
  c.port = MIFARE_MQTT_PORT;
}

// ── Globals ───────────────────────────────────────────────────────────────
static ConfigStore config;
static MifareResultStore mifareResults;
static bool mifareResultsReady = false;

// Shared WiFi/MQTT transport (BomberCatCore). Non-blocking; serviced from
// loop(). The ":mifare_mqtt_wifi up ip=" datum is emitted by the uplink via
// this tag, byte-for-byte as before.
static MqttUplink uplink(&Serial, "mifare_mqtt", "bombercat");

// The published payload. 32 sectors * (16 + 128 + 4) chars + the stat line
// fits comfortably; sized once, published from here.
static char payload[5120];

// ── Result ring flash: the SAME ConfigStore blob API MifareClassic uses, so
// this Core reads the very records that firmware wrote. ──────────────────────
static bool blobRead(const char *key, void *buf, size_t size) {
  return config.loadBlob(key, buf, size);
}
static bool blobWrite(const char *key, const void *buf, size_t size) {
  return config.saveBlob(key, buf, size);
}
static bool blobClear(const char *key) { return config.clearBlob(key); }

// ── REPL plumbing ───────────────────────────────────────────────────────────
BomberCatControl control(Serial, BOMBERCAT_FW_VERSION, BOMBERCAT_FW_NAME);

// Reply formatting delegates to BomberCatControl (public helpers) so the
// +OK/-ERR wire format lives only in core. See MifareClassic.ino for the
// same pattern.
static void replyOk() { control.ok(); }
static void replyErr(const char *msg) { control.err(msg); }

static const char *controlState() {
  if (!uplink.wifiUp()) {
    return "wifi-down";
  }
  return uplink.connected() ? "online" : "mqtt-down";
}

// Publish one stored record: flatten it into the primitive per-sector view the
// pure payload builder wants (§4.7 greenlit module), build the canonical lines,
// and push them over MQTT. Returns false (and says why) on any failure.
static bool publishRecord(const MifareResultRecord &rec) {
  if (!uplink.connected()) {
    replyErr("mqtt not connected");
    return false;
  }
  MifareDumpSector sectors[MIFARE_RESULT_MAX_SECTORS];
  uint8_t count = rec.sectors;
  if (count > MIFARE_RESULT_MAX_SECTORS) {
    count = MIFARE_RESULT_MAX_SECTORS;
  }
  for (uint8_t s = 0; s < count; s++) {
    if (rec.status[s] == MIFARE_RESULT_READ) {
      sectors[s].data = rec.data[s];
      sectors[s].keyType = (char)rec.keyType[s];
      sectors[s].reason = "";
    } else {
      sectors[s].data = nullptr;
      sectors[s].keyType = '-';
      const char *reason = mifareResultReason(rec.status[s]);
      sectors[s].reason = reason[0] ? reason : "nokey"; // honest hole
    }
  }

  size_t n = MifareDumpFormat::buildPayload(
      sectors, count, rec.read, rec.failed, payload, sizeof(payload));
  if (n == 0) {
    replyErr("payload build failed (too large?)");
    return false;
  }
  if (!uplink.publish(cfg.topic, (const uint8_t *)payload, n,
                      /*retained=*/false)) {
    replyErr("mqtt publish failed (buffer size?)");
    return false;
  }
  Serial.print(":mifare_mqtt_published seq=");
  Serial.print(rec.seq);
  Serial.print(" bytes=");
  Serial.println((unsigned)n);
  return true;
}

// `mifare mqtt publish <n>` (one stored result, index 0 = newest) or
// `mifare mqtt publish all`.
static void handlePublish(char *args) {
  if (!mifareResultsReady) {
    replyErr("flash unavailable");
    return;
  }
  uint8_t have = mifareResults.scan();
  if (have == 0) {
    replyErr("no stored results");
    return;
  }
  const char *tok = strtok(args, " \t");
  if (tok != nullptr && strcmp(tok, "all") == 0) {
    uint8_t ok = 0;
    for (uint8_t i = 0; i < have; i++) {
      const MifareResultRecord *rec = mifareResults.load(i);
      if (rec != nullptr && publishRecord(*rec)) {
        ok++;
      }
      uplink.poll(millis()); // service the link between publishes
    }
    if (ok == have) {
      replyOk();
    } else {
      replyErr("some results failed to publish");
    }
    return;
  }

  uint8_t index = 0; // default: the newest
  if (tok != nullptr) {
    index = (uint8_t)atoi(tok);
  }
  const MifareResultRecord *rec = mifareResults.load(index);
  if (rec == nullptr) {
    replyErr("no such result");
    return;
  }
  if (publishRecord(*rec)) {
    replyOk();
  }
}

// `mifare mqtt config key=value ...` -> persist; `... config show` -> print.
static void handleConfig(char *args) {
  char *first = strtok(args, " \t");
  if (first != nullptr && strcmp(first, "show") == 0) {
    Serial.print(":mifare_mqtt_cfg ssid=");
    Serial.print(cfg.ssid);
    Serial.print(" server=");
    Serial.print(cfg.server);
    Serial.print(" port=");
    Serial.print(cfg.port);
    Serial.print(" topic=");
    Serial.println(cfg.topic);
    replyOk();
    return;
  }

  // Parse key=value tokens (first token already pulled above).
  bool changed = false;
  for (char *tok = first; tok != nullptr; tok = strtok(nullptr, " \t")) {
    char *eq = strchr(tok, '=');
    if (eq == nullptr) {
      continue;
    }
    *eq = '\0';
    const char *key = tok;
    const char *val = eq + 1;
    if (strcmp(key, "ssid") == 0) {
      strncpy(cfg.ssid, val, sizeof(cfg.ssid) - 1);
      cfg.ssid[sizeof(cfg.ssid) - 1] = '\0';
      changed = true;
    } else if (strcmp(key, "pass") == 0) {
      strncpy(cfg.pass, val, sizeof(cfg.pass) - 1);
      cfg.pass[sizeof(cfg.pass) - 1] = '\0';
      changed = true;
    } else if (strcmp(key, "server") == 0) {
      strncpy(cfg.server, val, sizeof(cfg.server) - 1);
      cfg.server[sizeof(cfg.server) - 1] = '\0';
      changed = true;
    } else if (strcmp(key, "topic") == 0) {
      strncpy(cfg.topic, val, sizeof(cfg.topic) - 1);
      cfg.topic[sizeof(cfg.topic) - 1] = '\0';
      changed = true;
    } else if (strcmp(key, "port") == 0) {
      cfg.port = (uint16_t)atoi(val);
      changed = true;
    }
  }
  if (!changed) {
    replyErr("usage: mifare mqtt config [show|ssid=.. pass=.. server=.. "
             "port=.. topic=..]");
    return;
  }
  cfg.version = MIFARE_MQTT_CFG_VERSION;
  if (!config.saveBlob(MIFARE_MQTT_CFG_KEY, &cfg, sizeof(cfg))) {
    replyErr("flash write failed");
    return;
  }
  uplink.configure(cfg.ssid, cfg.pass, cfg.server, cfg.port); // re-associate
  replyOk();
}

static void handleStatus() {
  Serial.print(":mifare_mqtt_status wifi=");
  Serial.print(uplink.wifiUp()           ? "up"
               : uplink.wifiConnecting() ? "connecting"
                                         : "down");
  Serial.print(" mqtt=");
  Serial.print(uplink.connected() ? "connected" : "disconnected");
  Serial.print(" results=");
  Serial.println(mifareResultsReady ? mifareResults.scan() : 0);
  replyOk();
}

// Verb dispatch. Only "mifare mqtt ..." is ours; everything else is unknown.
static bool bomberCatCommand(const char *verb, char *args) {
  if (strcmp(verb, "mifare") != 0) {
    return false;
  }
  const char *sub = strtok(args, " \t");
  if (sub == nullptr || strcmp(sub, "mqtt") != 0) {
    replyErr("unknown mifare subcommand (only 'mqtt' here)");
    return true;
  }
  char *rest = strtok(nullptr, ""); // the remainder of the line
  const char *action = rest ? strtok(rest, " \t") : nullptr;
  char *actionArgs = rest ? strtok(nullptr, "") : nullptr;
  if (action == nullptr) {
    replyErr("usage: mifare mqtt <publish|config|status>");
  } else if (strcmp(action, "publish") == 0) {
    handlePublish(actionArgs ? actionArgs : (char *)"");
  } else if (strcmp(action, "config") == 0) {
    handleConfig(actionArgs ? actionArgs : (char *)"");
  } else if (strcmp(action, "status") == 0) {
    handleStatus();
  } else {
    replyErr("unknown mqtt action");
  }
  return true;
}

void setup() {
  Serial.begin(115200);
  while (!Serial)
    ;
  Serial.println("BomberCat MifareMqtt uplink (Fase 4, tarea 4.7)");

  cfgDefaults(cfg);
  if (config.begin()) {
    MifareMqttConfig stored;
    if (config.loadBlob(MIFARE_MQTT_CFG_KEY, &stored, sizeof(stored)) &&
        stored.version == MIFARE_MQTT_CFG_VERSION) {
      cfg = stored; // persisted credentials override the compile-time ones
    }
    MifareResultBlob blob;
    blob.read = blobRead;
    blob.write = blobWrite;
    blob.clear = blobClear;
    mifareResults.setBlob(blob);
    mifareResultsReady = true;
  } else {
    Serial.println("flash init failed: no stored results, no persisted config");
  }

  // PubSubClient's default buffer is 256 B - far too small for a 1K/4K dump.
  // Size it for the whole payload so publish() never silently refuses, then
  // arm the (non-blocking) link with the resolved credentials.
  uplink.setBufferSize(sizeof(payload) + 128);
  uplink.configure(cfg.ssid, cfg.pass, cfg.server, cfg.port);
  uplink.begin();

  BomberCatControl::Callbacks cb;
  cb.state = controlState;
  cb.command = bomberCatCommand;
  control.setCallbacks(cb);
  control.begin();
}

void loop() {
  control.poll(); // host CLI (ping/info/identify/mifare mqtt ...)
  uplink.poll(millis());
}
