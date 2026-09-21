// EMVyBomberCat — modo MAG: emulación de banda magnética (magspoof).
// Portado del ejemplo oficial magspoof de Electronic Cats, pero disparado por
// serie (`MAG:<track1>|<track2>`) en vez de por el botón físico.
// El motor F2F (antes _magPlay/_magStoreRev/_magReverse/_magBit) ahora vive en
// core/src/MagStripe; este archivo solo aporta el glue de trigger por serie.
// Pines del BomberCat: PIN_A=6, PIN_B=7 (bobina H-bridge) —
// MagStripe::classic().

static MagStripe _magStripe(MagStripe::classic());
static char _magTracks[2][128];

void emvyMagInit() { _magStripe.begin(); }

// Emite un swipe. `track1`/`track2` pueden venir con o sin centinelas (%..?
// ;..?).
void emvyMagPlay(const char *track1, const char *track2) {
  _magTracks[0][0] = '\0';
  _magTracks[1][0] = '\0';
  if (track1 && track1[0]) {
    strncpy(_magTracks[0], track1, 127);
    _magTracks[0][127] = '\0';
  }
  if (track2 && track2[0]) {
    strncpy(_magTracks[1], track2, 127);
    _magTracks[1][127] = '\0';
  }
  if (_magTracks[0][0]) {
    if (_magTracks[1][0])
      _magStripe.storeRevTrack(2, _magTracks); // necesario para el reverse
    _magStripe.playTrack(1, _magTracks);
  } else if (_magTracks[1][0]) {
    _magStripe.playTrack(2, _magTracks);
  }
}
