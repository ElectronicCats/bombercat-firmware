// EMVyBomberCat — modo MAG: emulación de banda magnética (magspoof).
// Portado del ejemplo oficial magspoof de Electronic Cats, pero disparado por
// serie (`MAG:<track1>|<track2>`) en vez de por el botón físico.
// Pines del BomberCat: PIN_A=6, PIN_B=7 (bobina H-bridge).

#define EMVY_MAG_PIN_A      6
#define EMVY_MAG_PIN_B      7
#define EMVY_MAG_CLOCK_US   500   // ~velocidad de swipe
#define EMVY_MAG_BETWEEN    53    // ceros entre track1 y track2

static char _magTracks[2][128];
static char _magRev[41];
static const int _magSublen[] = {32, 48, 48};
static const int _magBitlen[] = {7, 5, 5};
static int _magDir;

void emvyMagInit() {
  pinMode(EMVY_MAG_PIN_A, OUTPUT);
  pinMode(EMVY_MAG_PIN_B, OUTPUT);
  digitalWrite(EMVY_MAG_PIN_A, LOW);
  digitalWrite(EMVY_MAG_PIN_B, LOW);
}

static void _magBit(int sendBit) {
  _magDir ^= 1;
  digitalWrite(EMVY_MAG_PIN_A, _magDir);
  digitalWrite(EMVY_MAG_PIN_B, !_magDir);
  delayMicroseconds(EMVY_MAG_CLOCK_US);
  if (sendBit) {
    _magDir ^= 1;
    digitalWrite(EMVY_MAG_PIN_A, _magDir);
    digitalWrite(EMVY_MAG_PIN_B, !_magDir);
  }
  delayMicroseconds(EMVY_MAG_CLOCK_US);
}

static void _magStoreRev(int track) {
  int i, tmp, crc, lrc = 0;
  track--;
  _magDir = 0;
  for (i = 0; _magTracks[track][i] != '\0'; i++) {
    crc = 1;
    tmp = _magTracks[track][i] - _magSublen[track];
    for (int j = 0; j < _magBitlen[track] - 1; j++) {
      crc ^= tmp & 1;
      lrc ^= (tmp & 1) << j;
      (tmp & 1) ? (_magRev[i] |= 1 << j) : (_magRev[i] &= ~(1 << j));
      tmp >>= 1;
    }
    crc ? (_magRev[i] |= 1 << 4) : (_magRev[i] &= ~(1 << 4));
  }
  tmp = lrc; crc = 1;
  for (int j = 0; j < _magBitlen[track] - 1; j++) {
    crc ^= tmp & 1;
    (tmp & 1) ? (_magRev[i] |= 1 << j) : (_magRev[i] &= ~(1 << j));
    tmp >>= 1;
  }
  crc ? (_magRev[i] |= 1 << 4) : (_magRev[i] &= ~(1 << 4));
  i++;
  _magRev[i] = '\0';
}

static void _magReverse(int track) {
  int i = 0;
  track--;
  _magDir = 0;
  while (_magRev[i++] != '\0')
    ;
  i--;
  while (i--)
    for (int j = _magBitlen[track] - 1; j >= 0; j--)
      _magBit((_magRev[i] >> j) & 1);
}

static void _magPlay(int track) {
  int tmp, crc, lrc = 0;
  _magDir = 0;
  track--;
  for (int i = 0; i < 25; i++) _magBit(0);          // ceros iniciales
  for (int i = 0; _magTracks[track][i] != '\0'; i++) {
    crc = 1;
    tmp = _magTracks[track][i] - _magSublen[track];
    for (int j = 0; j < _magBitlen[track] - 1; j++) {
      crc ^= tmp & 1;
      lrc ^= (tmp & 1) << j;
      _magBit(tmp & 1);
      tmp >>= 1;
    }
    _magBit(crc);
  }
  tmp = lrc; crc = 1;                                 // LRC
  for (int j = 0; j < _magBitlen[track] - 1; j++) {
    crc ^= tmp & 1;
    _magBit(tmp & 1);
    tmp >>= 1;
  }
  _magBit(crc);
  if (track == 0) {                                   // track1 -> track2 en reversa
    for (int i = 0; i < EMVY_MAG_BETWEEN; i++) _magBit(0);
    _magReverse(2);
  }
  for (int i = 0; i < 25; i++) _magBit(0);            // ceros finales
  digitalWrite(EMVY_MAG_PIN_A, LOW);
  digitalWrite(EMVY_MAG_PIN_B, LOW);
}

// Emite un swipe. `track1`/`track2` pueden venir con o sin centinelas (%..? ;..?).
void emvyMagPlay(const char *track1, const char *track2) {
  _magTracks[0][0] = '\0';
  _magTracks[1][0] = '\0';
  if (track1 && track1[0]) { strncpy(_magTracks[0], track1, 127); _magTracks[0][127] = '\0'; }
  if (track2 && track2[0]) { strncpy(_magTracks[1], track2, 127); _magTracks[1][127] = '\0'; }
  if (_magTracks[0][0]) {
    if (_magTracks[1][0]) _magStoreRev(2);           // necesario para el reverse
    _magPlay(1);
  } else if (_magTracks[1][0]) {
    _magPlay(2);
  }
}
