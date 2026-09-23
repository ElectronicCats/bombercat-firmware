/************************************************************
  MagSpoof Attack for Bomber Cat
  by Andres Sabas, Electronic Cats (https://electroniccats.com/)
  by Salvador Mendoza (salmg.net)
  Electronic Cats (https://electroniccats.com/)
  Date: 12/09/2022

  This example demonstrates how to use Bomber Cat by Electronic Cats
  https://github.com/ElectronicCats/BomberCat

  Development environment specifics:
  IDE: Arduino 1.8.19
  Hardware Platform:
  Bomber Cat
  - RP2040

  Electronic Cats invests time and resources providing this open source code,
  please support Electronic Cats and open-source hardware by purchasing
  products from Electronic Cats!

  This code is beerware; if you see me (or any other Electronic Cats
  member) at the local, and you've found our code helpful,
  please buy us a round!
  Distributed as-is; no warranty is given.
*/
#include "FlashIAPBlockDevice.h"
#include "PluggableUSBMSD.h"

#include <BomberCatControl.h>
#include <MagStripe.h>

#define BOMBERCAT_FW_VERSION "1.1.1.0"

#define DEBUG
#define L1 (LED_BUILTIN) // LED1

#define PIN_A (6) // MagSpoof-1
#define PIN_B (7) // MagSpoof

#define NPIN (5) // Button

#define CLOCK_US (500)

#define BETWEEN_ZERO (53) // 53 zeros between track1 & 2

#define TRACKS (2)

// Live track store filled from the CSV; the F2F engine now lives in
// BomberCatCore's MagStripe (classic waveform).
char tracks[2][128];

unsigned int curTrack = 0;

MagStripe stripe(MagStripe::classic());

static FlashIAPBlockDevice bd(XIP_BASE + 0x100000, 0x100000);

USBMSD MassStorage(&bd);

FILE *f = nullptr;

char buf[255]{0};

const char *fname = "/fs/data.csv";

void USBMSD::begin() {
  int err = getFileSystem().mount(&bd);
  if (err) {
    err = getFileSystem().reformat(&bd);
  }
}

mbed::FATFileSystem &USBMSD::getFileSystem() {
  static mbed::FATFileSystem fs("fs");
  return fs;
}

void readContents() {
  f = fopen(fname, "r");
  if (f != nullptr) {
    while (std::fgets(buf, sizeof buf, f) != nullptr)
      Serial.print(buf);
    fclose(f);
    Serial.println("File found");
  } else {
    Serial.println("File not found");
  }
}

void magspoof() {
  Serial.println("Activating MagSpoof...");
  stripe.playTrack(1 + (curTrack++ % 2), tracks);
  stripe.blink(150, 3);
  delay(400);
}

// BomberCat serial-control REPL (ping/info/identify) for bombercat-tools.
BomberCatControl control(Serial, BOMBERCAT_FW_VERSION, "magspoofcvsattack");

void setup() {
  Serial.begin(115200);
  MassStorage.begin();
  stripe.begin(); // H-bridge / LED / button pin setup

#ifdef DEBUG
  while (!Serial) {
    ; // wait for serial port to connect. Needed for native USB port only
  }
#endif
  Serial.println("BomberCat, yes Sir!");
  Serial.println("MagSpoof Attack!!");

  f = fopen(fname, "r");
  if (f != nullptr) {
    while (std::fgets(buf, 255, f) != nullptr) {
      Serial.print("Buf: ");
      Serial.write(buf);
      Serial.println();
      int i, j;
      j = 0;
      for (i = 0; i < 255; i++) {
        if (buf[i] == '?' && j == 0) {
          tracks[0][i] = buf[i];
          j = i;
          tracks[0][i + 1] = NULL;
        }
        if (j == 0) {
          tracks[0][i] = buf[i];
        } else {
          tracks[1][i - j] = buf[i + 1];
          if (buf[i + 1] == '?') {
            tracks[1][i - j + 1] = NULL;
            break;
          }
        }
      }
      Serial.print("Track 0: ");
      Serial.write(tracks[0]);
      Serial.println();
      Serial.print("Track 1: ");
      Serial.write(tracks[1]);
      Serial.println();
      magspoof();
    }
  }
  fclose(f);
  Serial.println("MagSpoof Attack End!!");

  control.begin(); // announce readiness to the host CLI
}

void loop() {
  control.poll(); // service host CLI commands (ping/info/identify)
}
