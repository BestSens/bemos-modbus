# BeMoS Modbus
## Einleitung
Dieser Dienst stellt einen Wrapper für Teile der BeMoS-API über Modbus TCP auf Port `502` im Netzwerk bereit. Da Modbus keinerlei Authentifizierung beherrscht, muss auf Netzwerkbasis sichergestellt werden, dass nur berechtigte Geräte Zugriff auf diesen Port am entsprechenden BeMoS-Controller haben. Aufgrund dieses Sicherheitsproblems ist der Modbus Wrapper nicht standardmäßig bei allen BeMoS Controllern aktiviert, sondern muss gesondert gestartet werden.

## Datentypen
Die Daten werden *Big-Endian* geordnet übertragen. Registerübergreifende Daten werden als *word swap* gesendet und Fließkommazahlen nach dem *IEEE 754*-Standard erzeugt. Die Adressierung ist 1-basierend.

Beispiel: `[ a b c d ] = [ c d ][ a b ]`

## Input-Register
Adressbereich 30001-39999

| Start-Adresse | Datentyp      | Messwert           | Einheit |
| ------------- | ------------- | ------------------ | ------- |
| 0x01          | uint32        | Unix-Zeitstempel   | s       |
| 0x03          | float32       | Käfigdrehzahl      | RPM     |
| 0x05          | float32       | Wellendrehzahl     | RPM     |
| 0x07          | float32       | Temperatur         | °C      |
| 0x09          | float32       | Störlevel          | -       |
| 0x0B          | float32       | Mittlere Laufzeit  | ns      |
| 0x0D          | float32       | Mittlere Amplitude | V       |
| 0x0F          | float32       | RMS Laufzeit       | ns      |
| 0x11          | float32       | RMS Amplitude      | V       |
| 0x13          | float32       | Temperatur X1      | °C      |
| 0x15          | float32       | Temperatur X2      | °C      |
| 0x17          | float32       | Druckwinkel        | °       |

## Holding-Register
Adressbereich 40001-49999

| Start-Adresse | Datentyp      | Messwert               | Einheit |
| ------------- | ------------- | ---------------------- | ------- |
| 0x01          | uint16        | Externe Wellendrehzahl | RPM     |
