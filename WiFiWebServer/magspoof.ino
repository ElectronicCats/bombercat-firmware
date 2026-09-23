/************************************************************
  MagSpoof version for Bomber Cat
  by Salvador Mendoza (salmg.net)
  Electronic Cats (https://electroniccats.com/)

  This example demonstrates how to use Bomber Cat by Electronic Cats
  https://github.com/ElectronicCats/BomberCat

  Development environment specifics:
  IDE: Arduino 1.8.9
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

// The F2F magnetic-stripe engine (blink / playBit / reverseTrack / playTrack /
// storeRevTrack) now lives in BomberCatCore's MagStripe, shared with the other
// MagSpoof sketches. `stripe` and the track store are declared in Magspoof.h;
// only this sketch's trigger glue (button + web `runMagspoof` flag) stays here.

void magspoof() {
  if (stripe.buttonPressed() || runMagspoof) {
    runMagspoof = false;
    debug.println("Activating MagSpoof...");
    debug.print("Track 1: ");
    debug.println(tracks[0]);
    debug.print("Track 2: ");
    debug.println(tracks[1]);

    stripe.playTrack(1 + (curTrack++ % 2), tracks);
    stripe.blink(150, 3);
    delay(400);
  }
}

void setupMagspoof() {
  stripe.begin(); // H-bridge / LED / button pin setup

  Serial.begin(115200);

  // blink to show we started up
  stripe.blink(200, 2);
  debug.println("Press the MagSpoof button");
}
