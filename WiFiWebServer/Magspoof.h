#include <MagStripe.h>

#define NPIN                                                                   \
  (5) // Button. Kept here because WiFiWebServer.ino's ezButton is
      // constructed with it; the H-bridge / LED / clock config now
      // lives in MagStripe (see `stripe` below).
#define DEBUGCAT

bool runMagspoof = false;
char tracks[2][128];
unsigned int curTrack = 0;

// Classic MagSpoof F2F engine, shared via BomberCatCore. Defaults to BomberCat
// wiring (PIN_A=6, PIN_B=7, NPIN=5, LED_BUILTIN, 500us clock, track-1 ->
// track-2-reverse pass) - byte-identical to the previous inline engine.
MagStripe stripe(MagStripe::classic());
