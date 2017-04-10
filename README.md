# BeMoS Modbus
## Einleitung
Dieser Dienst stellt einen Wrapper für Teile der BeMoS-API über Modbus TCP auf Port `502` im Netzwerk bereit. Da Modbus keinerlei Authentifizierung beherrscht, muss auf Netzwerkbasis sichergestellt werden, dass nur berechtigte Geräte Zugriff auf diesen Port am entsprechenden BeMoS-Controller haben. Aufgrund dieses Sicherheitsproblems ist der Modbus Wrapper nicht standardmäßig bei allen BeMoS Controllern aktiviert, sondern muss gesondert gestartet werden.

## Datentypen
Die Daten werden im *Big-Endian* formatiert übertragen. Registerübergreifende Daten werden als *word swap* gesendet. Fließkommazahlen werden nach dem *IEEE 754* Standard erzeugt.

Beispiel: `[ a b c d ] = [ c d ][ a b ]`

## Input-Register
| Start-Adresse | Datentyp      | Messwert           | Einheit |
| ------------- | ------------- | ------------------ | ------- |
| 0x00          | uint32        | Unix-Zeitstempel   | s       |
| 0x02          | float32       | Käfigdrehzahl      | RPM     |
| 0x04          | float32       | Wellendrehzahl     | RPM     |
| 0x06          | float32       | Temperatur         | °C      |
| 0x08          | float32       | Störlevel          | -       |
| 0x0A          | float32       | Mittlere Laufzeit  | ns      |
| 0x0C          | float32       | Mittlere Amplitude | V       |
| 0x0E          | float32       | RMS Laufzeit       | ns      |
| 0x10          | float32       | RMS Amplitude      | V       |
| 0x12          | float32       | Temperatur X1      | °C      |
| 0x14          | float32       | Temperatur X2      | °C      |
| 0x16          | float32       | Druckwinkel        | °       |

## Holding-Register
| Start-Adresse | Datentyp      | Messwert               | Einheit |
| ------------- | ------------- | ---------------------- | ------- |
| 0x00          | uint16        | Externe Wellendrehzahl | RPM     |
