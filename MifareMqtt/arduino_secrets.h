// Compile-time fallback credentials for the MifareMqtt uplink Core.
//
// These are used only when no persisted MifareMqttConfig record is found in
// the board's flash (set one at runtime with `mifare mqtt config ssid=... `).
// Leave ssid empty to require runtime configuration.
//
// WARNING (§4.7): this Core publishes over MQTT in the CLEAR (port 1883), so
// the recovered keys and card blocks travel the network UNENCRYPTED. Use a
// trusted WiFi, or accept it explicitly.

// WiFi access
#define MIFARE_MQTT_SSID ""
#define MIFARE_MQTT_PASS ""

// MQTT broker
#define MIFARE_MQTT_SERVER "test.mosquitto.org"
#define MIFARE_MQTT_PORT 1883
#define MIFARE_MQTT_TOPIC "bombercat/mifare/dump"
