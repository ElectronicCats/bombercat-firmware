/**
 * BomberCatCore - WiFiConnect
 *
 * Blocking WPA/WPA2 association for the relay sketches, factored from the
 * near-identical WiFi bring-up block that lived inside host_Relay_NFC's and
 * client_Relay_NFC's setup_wifi(). Only the radio bring-up is shared here:
 * credential parsing (SerialCommand), the stats-store load/save and the
 * sketch's OK/ERROR serial protocol stay in each sketch, because those parts
 * genuinely differ between the two.
 *
 * Unlike MqttUplink's non-blocking WiFi state machine, this mirrors the
 * sketches' original synchronous "try a few times then give up" loop, so the
 * observable behavior of setup_wifi() is unchanged.
 *
 * Distributed as-is; no warranty is given.
 */
#ifndef BOMBERCAT_CORE_WIFI_CONNECT_H
#define BOMBERCAT_CORE_WIFI_CONNECT_H

#include <Arduino.h>
#include <WiFiNINA.h>

namespace WiFiConnect {

// Associate with `ssid`/`pass`, retrying WiFi.begin() up to `maxAttempts`
// times, and return the final wl_status_t.
//
// Deliberately does NOT halt and prints no protocol tokens: if the radio is
// absent it returns WL_NO_MODULE and the caller decides what to do (the
// sketches halt), and OK/ERROR belong to each sketch's serial protocol. If a
// `debug` Stream is given, it mirrors the chatter the sketches printed before.
uint8_t associate(const char *ssid, const char *pass, uint8_t maxAttempts = 3,
                  Stream *debug = nullptr);

} // namespace WiFiConnect

#endif // BOMBERCAT_CORE_WIFI_CONNECT_H
