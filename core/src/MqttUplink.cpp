/**
 * BomberCatCore - MqttUplink (see MqttUplink.h).
 *
 * The WiFi/MQTT state machine is the same non-blocking connect/poll loop the
 * MQTT sketches shared before it was unified here; only the firmware-specific
 * log prefix is parameterised (`_tag`). It cannot be exercised in the native
 * g++ harness - it is pure radio glue (WiFiNINA + PubSubClient), with no
 * decodable logic of its own - so its check is the arduino-cli build of the
 * sketches that use it.
 *
 * Distributed as-is; no warranty is given.
 */
#include "MqttUplink.h"

MqttUplink::MqttUplink(Stream *log, const char *tag, const char *clientId)
    : _log(log), _tag(tag), _clientId(clientId), _mqtt(_net) {}

void MqttUplink::configure(const char *ssid, const char *pass,
                           const char *server, uint16_t port) {
  strncpy(_ssid, ssid ? ssid : "", sizeof(_ssid) - 1);
  _ssid[sizeof(_ssid) - 1] = '\0';
  strncpy(_pass, pass ? pass : "", sizeof(_pass) - 1);
  _pass[sizeof(_pass) - 1] = '\0';
  strncpy(_server, server ? server : "", sizeof(_server) - 1);
  _server[sizeof(_server) - 1] = '\0';
  _port = port;

  _mqtt.setServer(_server, _port);
  _wifi = WIFI_IDLE; // re-associate with the new credentials
  _wifiRetryAt = 0;
}

void MqttUplink::setBufferSize(uint16_t bytes) { _mqtt.setBufferSize(bytes); }

void MqttUplink::onMessage(MessageCallback cb) { _mqtt.setCallback(cb); }
void MqttUplink::onConnect(ConnectCallback cb) { _onConnect = cb; }

void MqttUplink::begin() { /* nothing to init; poll() drives everything */ }

void MqttUplink::poll(uint32_t now) {
  serviceWifi(now);
  serviceMqtt(now);
}

bool MqttUplink::publish(const char *topic, const uint8_t *payload, size_t len,
                         bool retained) {
  return _mqtt.publish(topic, payload, len, retained);
}

bool MqttUplink::publish(const char *topic, const char *payload) {
  return _mqtt.publish(topic, payload);
}

bool MqttUplink::subscribe(const char *topic) { return _mqtt.subscribe(topic); }

// ── WiFi state machine: begin(), then poll WiFi.status() against a deadline,
// re-arming after a lull so a dropped link reconnects - never blocks the REPL.
void MqttUplink::serviceWifi(uint32_t now) {
  switch (_wifi) {
  case WIFI_IDLE:
    if (_ssid[0] == '\0') {
      return; // nothing to connect to until configured
    }
    if (now < _wifiRetryAt) {
      return;
    }
    if (WiFi.status() == WL_NO_MODULE) {
      if (_log) {
        _log->println("WiFi module not found");
      }
      _wifiRetryAt = now + WIFI_RETRY_MS;
      return;
    }
    WiFi.begin(_ssid, _pass);
    _wifi = WIFI_CONNECTING;
    _wifiDeadline = now + WIFI_CONNECT_TIMEOUT_MS;
    break;
  case WIFI_CONNECTING:
    if (WiFi.status() == WL_CONNECTED) {
      if (_log) {
        _log->print(":");
        _log->print(_tag);
        _log->print("_wifi up ip=");
        _log->println(WiFi.localIP());
      }
      _wifi = WIFI_UP;
    } else if (now >= _wifiDeadline) {
      WiFi.disconnect();
      _wifi = WIFI_IDLE;
      _wifiRetryAt = now + WIFI_RETRY_MS;
    }
    break;
  case WIFI_UP:
    if (WiFi.status() != WL_CONNECTED) {
      _wifi = WIFI_IDLE; // link dropped; re-associate
      _wifiRetryAt = now + WIFI_RETRY_MS;
    }
    break;
  }
}

void MqttUplink::serviceMqtt(uint32_t now) {
  if (_wifi != WIFI_UP) {
    return;
  }
  if (_mqtt.connected()) {
    _mqtt.loop();
    return;
  }
  if (now < _mqttRetryAt) {
    return;
  }
  // PubSubClient.connect() blocks only briefly (one socket handshake); the
  // retry gate keeps a dead broker from busy-looping it.
  char clientId[40];
  snprintf(clientId, sizeof(clientId), "%s-%04X", _clientId,
           (unsigned)random(0xFFFF));
  if (_mqtt.connect(clientId)) {
    if (_onConnect) {
      _onConnect(); // the sketch subscribes / announces here
    }
  } else {
    _mqttRetryAt = now + MQTT_RETRY_MS;
  }
}
