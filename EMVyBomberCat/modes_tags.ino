// EMVyBomberCat — modo TAGS: lee un tag NFC y emite su UID.
// Reutiliza el objeto global `nfc` (Electroniccats_PN7150) del sketch principal.
// Basado en el ejemplo oficial DetectTags de Electronic Cats.

void emvyTagsRead() {
  unsigned long t = millis();
  bool found = false;
  while (millis() - t < 8000) {          // espera hasta 8 s por un tag
    if (nfc.isTagDetected()) { found = true; break; }
    delay(50);
  }
  if (!found) { Serial.println("ERR:NOTAG"); return; }

  const byte *uid = nfc.remoteDevice.getNFCID();
  unsigned int n = nfc.remoteDevice.getNFCIDLen();
  Serial.print("TAG:");
  Serial.print(nfc.remoteDevice.getProtocol());   // protocolo (ISODEP/T2T/…)
  Serial.print(" TECH:");
  Serial.print(nfc.remoteDevice.getModeTech());
  Serial.print(" UID:");
  for (unsigned int i = 0; i < n; i++) {
    if (uid[i] < 0x10) Serial.print('0');
    Serial.print(uid[i], HEX);            // Arduino imprime HEX en mayúsculas
  }
  Serial.println();

  nfc.reset();                            // reanuda discovery para el siguiente
}
