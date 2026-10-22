/**
 * BomberCatCore - WiFiConnect implementation
 *
 * Distributed as-is; no warranty is given.
 */
#include "WiFiConnect.h"

namespace WiFiConnect {

uint8_t associate(const char *ssid, const char *pass, uint8_t maxAttempts,
                  Stream *debug) {
  // check for the WiFi module:
  if (WiFi.status() == WL_NO_MODULE) {
    if (debug)
      debug->println("Communication with WiFi module failed!");
    return WL_NO_MODULE;
  }

  String fv = WiFi.firmwareVersion();
  if (fv < WIFI_FIRMWARE_LATEST_VERSION && debug)
    debug->println("Please upgrade the firmware");

  // attempt to connect to WPA/WPA2 network (change for open/WEP):
  uint8_t status = WiFi.status();
  for (uint8_t cont = 0; status != WL_CONNECTED && cont < maxAttempts; ++cont) {
    if (debug) {
      debug->print("Attempting to connect to SSID: ");
      debug->println(ssid);
    }
    status = WiFi.begin(ssid, pass);
  }

  if (debug && status == WL_CONNECTED) {
    debug->println("");
    debug->println("WiFi connected");
    debug->println("IP address: ");
    debug->println(WiFi.localIP());
  }
  return status;
}

} // namespace WiFiConnect
