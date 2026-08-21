> ⚠️ **OBSOLETO / LEGACY.** Sketch Relay NFC (rol READER (lector)) sobre MQTT.
> Reemplazado por [`../../NFCGate/NFCGate.ino`](../../NFCGate/NFCGate.ino), que
> unifica ambos roles en un solo sketch basado en `core/` y es el Relay por
> defecto. Conservado solo por su histórico. Ver [`../README.md`](../README.md).

# Changes required Arduino Serial Command

For this example to work properly, you must make changes to the library [Arduino Serial Command](https://github.com/kroimon/Arduino-SerialCommand)

Change in SerialCommand.h
```
// Size of the input buffer in bytes (maximum length of one command plus arguments)
#define SERIALCOMMAND_BUFFER 32
```
to
```
// Size of the input buffer in bytes (maximum length of one command plus arguments)
#define SERIALCOMMAND_BUFFER 255
```
Change in SerialCommand.cpp
```
strcpy(delim, " "); // strtok_r needs a null-terminated string
```
to
```
strcpy(delim, "-"); // strtok_r needs a null-terminated string
```
