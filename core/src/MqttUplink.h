/**
 * BomberCatCore - MqttUplink
 *
 * The WiFi + MQTT transport shared by the MQTT firmwares (MifareMqtt,
 * MagSpoofMqtt, and future ones). It owns a WiFiNINA WiFiClient and a
 * PubSubClient and drives the whole connection lifecycle - associate, connect,
 * reconnect, re-associate on drop - as a NON-BLOCKING state machine serviced
 * from loop(), so the sketch's REPL (BomberCatControl) keeps responding while
 * the link comes up. (This is MifareMqtt's state machine, lifted verbatim; it
 * replaces MagSpoofMqtt's older busy-wait setup_wifi()/reconnect().)
 *
 * Firmware-specific logic stays in the sketch: this class carries no payload
 * format and subscribes to nothing on its own. A sketch wires its behaviour
 * through onMessage() (subscription delivery) and onConnect() (fired after each
 * MQTT (re)connect - the place to subscribe and/or announce).
 *
 * Distributed as-is; no warranty is given.
 */
#ifndef BOMBERCAT_CORE_MQTTUPLINK_H
#define BOMBERCAT_CORE_MQTTUPLINK_H

#include <Arduino.h>
#include <PubSubClient.h>
#include <WiFiNINA.h>

class MqttUplink {
public:
  // PubSubClient's subscription callback signature.
  typedef void (*MessageCallback)(char *topic, uint8_t *payload,
                                  unsigned int length);
  // Fired once after each successful MQTT (re)connect.
  typedef void (*ConnectCallback)();

  // `log`/`tag` drive optional diagnostics: on each WiFi association the uplink
  // prints ":<tag>_wifi up ip=<addr>" over `log` (the BomberCat datum
  // convention, see BomberCatControl.h). Pass log=nullptr for silence.
  // `clientId` prefixes the random-suffixed MQTT client id ("<clientId>-A1B2").
  MqttUplink(Stream *log = nullptr, const char *tag = "mqtt",
             const char *clientId = "bombercat");

  // (Re)arm association with these credentials. Safe to call again at runtime
  // (e.g. after a config change): it drops the current link and reconnects.
  void configure(const char *ssid, const char *pass, const char *server,
                 uint16_t port);

  // Raise PubSubClient's buffer (default 256 B) for large payloads. Call before
  // begin(), or publish() will silently refuse anything bigger.
  void setBufferSize(uint16_t bytes);

  void onMessage(MessageCallback cb); // subscription delivery
  void onConnect(ConnectCallback cb); // after each MQTT (re)connect

  void begin(); // arm the state machine; touches no hardware
  void
  poll(uint32_t now); // service WiFi + MQTT, non-blocking; call every loop()

  bool publish(const char *topic, const uint8_t *payload, size_t len,
               bool retained = false);
  bool publish(const char *topic, const char *payload); // C-string convenience
  bool subscribe(const char *topic);

  bool wifiUp() const { return _wifi == WIFI_UP; }
  bool wifiConnecting() const { return _wifi == WIFI_CONNECTING; }
  bool connected() { return _mqtt.connected(); } // MQTT link up?

private:
  enum WifiState { WIFI_IDLE, WIFI_CONNECTING, WIFI_UP };

  void serviceWifi(uint32_t now);
  void serviceMqtt(uint32_t now);

  Stream *_log;
  const char *_tag;
  const char *_clientId;

  WiFiClient _net;
  PubSubClient _mqtt;
  ConnectCallback _onConnect = nullptr;

  // Credentials live here so a runtime reconfigure survives re-association.
  char _ssid[64] = {0};
  char _pass[64] = {0};
  char _server[64] = {0};
  uint16_t _port = 1883;

  WifiState _wifi = WIFI_IDLE;
  uint32_t _wifiDeadline = 0;
  uint32_t _wifiRetryAt = 0;
  uint32_t _mqttRetryAt = 0;

  static const uint32_t WIFI_CONNECT_TIMEOUT_MS = 20000;
  static const uint32_t WIFI_RETRY_MS = 5000;
  static const uint32_t MQTT_RETRY_MS = 5000;
};

#endif // BOMBERCAT_CORE_MQTTUPLINK_H
