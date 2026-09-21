// EMVyBomberCat — modo TAGS: lee un tag NFC y emite su UID.
// Reutiliza el objeto global `nfc` (NfcController, Fase 5) del sketch
// principal; las primitivas que NfcController no re-expone (remoteDevice,
// isTagDetected, reset "ligero" de la librería) se alcanzan vía nfc.raw().
// Basado en el ejemplo oficial DetectTags de Electronic Cats.

void emvyTagsRead() {
  unsigned long t = millis();
  bool found = false;
  while (millis() - t < 8000) { // espera hasta 8 s por un tag
    if (nfc.raw().isTagDetected()) {
      found = true;
      break;
    }
    delay(50);
  }
  if (!found) {
    Serial.println("ERR:NOTAG");
    return;
  }

  const byte *uid = nfc.raw().remoteDevice.getNFCID();
  unsigned int n = nfc.raw().remoteDevice.getNFCIDLen();
  Serial.print("TAG:");
  Serial.print(
      nfc.raw().remoteDevice.getProtocol()); // protocolo (ISODEP/T2T/…)
  Serial.print(" TECH:");
  Serial.print(nfc.raw().remoteDevice.getModeTech());
  Serial.print(" UID:");
  // Formato TAG:/TECH:/UID: mantenido por retrocompatibilidad con emvyctl
  // (ver PLAN_IMPLEMENTACION_EMVYBOMBERCAT.md, Fase 4 #6); el hex ahora se
  // deriva de core/src/TagReader en vez de un loop propio. hexCompact()
  // devuelve "-" para n==0, que aquí se omite para no cambiar el wire format
  // (antes imprimía nada tras "UID:" si no había UID).
  if (n > 0) {
    Serial.print(TagReader::hexCompact(uid, n));
  }
  Serial.println();

  // nfc.raw().reset() (Electroniccats_PN7150::reset(), no
  // NfcController::reset()): es el "reanude discovery" ligero de la
  // librería, distinto del bring-up completo — ver nota de Fase 5 en
  // EMVyBomberCat.ino sobre por qué no se confunden.
  nfc.raw().reset();
}
