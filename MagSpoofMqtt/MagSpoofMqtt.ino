/************************************************************
  Example for send Magstripe with MagSpoof via MQTT version for BomberCat
  by Jaz, Electronic Cats (https://electroniccats.com/)
  by Salvador Mendoza (salmg.net)
  by Andres Sabas
  Date: 17/05/2022

  This example demonstrates how to use BomberCat by Electronic Cats
  https://github.com/ElectronicCats/BomberCat

  Development environment specifics:
  IDE: Arduino 1.8.19
  Hardware Platform:
  BomberCat
  - RP2040

  Thanks Wallee for support this project open source https://en.wallee.com/

  Electronic Cats invests time and resources providing this open source code,
  please support Electronic Cats and open-source hardware by purchasing
  products from Electronic Cats!

  This code is beerware; if you see me (or any other Electronic Cats
  member) at the local, and you've found our code helpful,
  please buy us a round!
  Distributed as-is; no warranty is given.
*/
#include "arduino_secrets.h"
#include <ArduinoJson.h>
#include <BomberCatControl.h>
#include <MagStripe.h>
#include <MqttUplink.h>

#define BOMBERCAT_FW_VERSION "1.1.1.0"
// Update these with values suitable for your network.

const char *ssid = ssidName;
const char *password = passWIFI;
const char *mqtt_server = mqttServ;

#define L1 (LED_BUILTIN) // LED1 indicates activity

#define PIN_A (6) // MagSpoof-1
#define PIN_B (7) // MagSpoof

#define NPIN (5) // Button
#define CLOCK_US (500)

#define BETWEEN_ZERO (53) // 53 zeros between track1 & 2

#define TRACKS (2)
#define DEBUGCAT

unsigned long myTime1;
unsigned long myTime2;
unsigned long result;

// Live track store filled from MQTT payloads; the F2F engine now lives in
// BomberCatCore's MagStripe (classic waveform).
char tracks[2][128];

unsigned int curTrack = 0;

MagStripe stripe(MagStripe::classic());

// Shared WiFi/MQTT transport (BomberCatCore); non-blocking, serviced from
// loop(). Replaces the old busy-wait setup_wifi()/reconnect().
MqttUplink uplink(&Serial, "magspoof_mqtt", "ESPClient");

unsigned long lastMsg = 0;
#define MSG_BUFFER_SIZE (50)
char msg[MSG_BUFFER_SIZE];
int value = 0;

void magspoof();

void callback(char *topic, byte *payload, unsigned int length) {

  // Converts the payload into a character array and adds the termination
  // character
  char message[length + 1];
  strncpy(message, (char *)payload, length);
  message[length] = '\0';

  // Searching for these specific characters in the payload
  char *questionMark = strchr(message, '?'); // End Sentinel of Track 1
  char *semicolon = strchr(message, ';');    // Start Sentinel of Track 2

  /*Verify that the payload contains:
    '%': Start Sentinel of Track 1
    '?': End sentinel of Track 1
    And confirms the position of the End Sentinel of Track 1 and Start Sentinel
    of Track 2*/
  if (message[0] != '%' || message[length - 1] != '?' || questionMark == NULL ||
      semicolon == NULL || questionMark >= semicolon) {
    Serial.println("Invalid message received in the Mag topic. Ignoring...");
    return;
  }

  // Track 1: from '%' to the first '?' (Start and End Sentinels, respectively)
  int track1Length = questionMark - message + 1;
  strncpy(tracks[0], message, track1Length);
  tracks[0][track1Length] = '\0';

  // Track 2: from ';' to the second '?' (Start and End Sentinels, respectively)
  int track2Start = semicolon - message;
  int track2End = length - track2Start;
  strncpy(tracks[1], message + track2Start, track2End);
  tracks[1][track2End] = '\0';

  // Show the tracks in the Serial Monitor
  Serial.println();
  Serial.println("Track 1:");
  Serial.println(tracks[0]);
  Serial.println("Track 2:");
  Serial.println(tracks[1]);

  magspoof();
}

// Fired after each MQTT (re)connect: announce presence and (re)subscribe to the
// "Mag" topic, exactly as the old reconnect() loop did.
void onMqttConnect() {
  uplink.publish("Mag", "hello i'm here");
  uplink.subscribe("Mag");
}

// BomberCat serial-control REPL (ping/info/identify) for bombercat-tools.
BomberCatControl control(Serial, BOMBERCAT_FW_VERSION, "magspoofmqtt");

void setup() {
  stripe.begin();      // H-bridge / LED / button pin setup
  pinMode(13, OUTPUT); // Initialize the BUILTIN_LED pin as an output

  // Serial must come up before the uplink, which logs over Serial.
  Serial.begin(115200);
  while (!Serial)
    ;

  uplink.onMessage(callback);
  uplink.onConnect(onMqttConnect);
  uplink.configure(ssid, password, mqtt_server, 1883);
  uplink.begin();

  // blink to show we started up
  stripe.blink(200, 2);
  Serial.println("Ready MQTT MagSpoof");

  control.begin(); // announce readiness to the host CLI
}

void magspoof() {
  Serial.println("Activating MagSpoof...");
  stripe.playTrack(1 + (curTrack++ % 2), tracks);
  stripe.blink(150, 3);
  delay(400);
}

void loop() {
  control.poll(); // service host CLI commands (ping/info/identify)
  uplink.poll(millis());
}
