#pragma once
#include <stdint.h>

// Item de un DOL (PDOL/CDOL) usado por la emulación de tarjeta EMV.
// Vive en un header (no en el .ino) a propósito: Arduino autogenera los
// prototipos de las funciones del sketch y los inserta ARRIBA, antes de
// cualquier `struct` definido dentro del .ino — así que un parámetro
// `const DolItem*` en una función daría "does not name a type". Al declararlo
// en un header incluido, el tipo ya es visible cuando aparecen esos prototipos.
struct DolItem {
  uint16_t tag;
  uint8_t len;
  const char *name;
};
