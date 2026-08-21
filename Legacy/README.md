# Legacy

Sketches conservados solo por su valor histórico. **No usar en nuevos
despliegues** — han sido reemplazados por implementaciones basadas en `core/`.

## Relay NFC (obsoleto)

| Sketch | Rol antiguo | Reemplazado por |
|---|---|---|
| `client_Relay_NFC/` | Relay lado **READER** (lector) sobre MQTT | [`NFCGate/NFCGate.ino`](../NFCGate/NFCGate.ino) |
| `host_Relay_NFC/`   | Relay lado **CARD/HCE** (tarjeta) sobre MQTT | [`NFCGate/NFCGate.ino`](../NFCGate/NFCGate.ino) |

### Motivo del movimiento

Ambos sketches eran los dos roles del Relay implementados por separado, cada uno
reimplementando a mano el PN7150, el almacenamiento en flash (TDBStore /
FlashIAP) y el control por `SerialCommand`. Todo eso ahora vive en la librería
`core/` (`NfcController`, `NfcGateLink`, `RelayEngine`, `ConfigStore`,
`SerialControl`), y **`NFCGate/NFCGate.ino` los unifica en un único sketch
seleccionable por rol** (`RELAY_ROLE`, roles READER y CARD/HCE). Desde ahora
`NFCGate.ino` es el código por defecto para Relay; su transporte es el
`nfcgate-server` por TCP en lugar de MQTT.

Se movieron con `git mv` para mantener el histórico en lugar de borrarlos.
