# BeMoS Modbus
## Einleitung
Dieser Dienst stellt einen Wrapper für Teile der BeMoS-API über Modbus TCP auf Port `502` im Netzwerk bereit. Da Modbus keinerlei Authentifizierung beherrscht, muss auf Netzwerkbasis sichergestellt werden, dass nur berechtigte Geräte Zugriff auf diesen Port am entsprechenden BeMoS-Controller haben. Aufgrund dieses Sicherheitsproblems ist der Modbus Wrapper nicht standardmäßig bei allen BeMoS Controllern aktiviert, sondern muss gesondert gestartet werden.

## Datentypen
* Daten werden **Big-Endian** geordnet übertragen
* Registerübergreifende Daten werden als **word swap** gesendet, jeweils mit der/den darauffolgenden Adresse(n) (siehe Lücken)
* Fließkommazahlen werden nach dem **IEEE 754**-Standard erzeugt
* die Adressierung ist **1-basierend**
* Input- und Holding-Register zeigen auf den gleichen Speicherbereich

Beispiel: `[ a b c d ] = [ c d ][ a b ]`

## Register
Adressbereich 30001-30099
Adressbereich 40001-40099

| Start-Adresse | Datentyp      | Messwert           | Einheit |
| ------------: | :-----------: | ------------------ | ------- |
| 0001          | uint32        | Unix-Zeitstempel   | s       |
| 0003          | float32       | Käfigdrehzahl      | RPM     |
| 0005          | float32       | Wellendrehzahl     | RPM     |
| 0007          | float32       | Temperatur         | °C      |
| 0009          | float32       | Störlevel          | -       |
| 0011          | float32       | Mittlere Laufzeit  | ns      |
| 0013          | float32       | Mittlere Amplitude | V       |
| 0015          | float32       | RMS Laufzeit       | ns      |
| 0017          | float32       | RMS Amplitude      | V       |
| 0019          | float32       | Temperatur X1      | °C      |
| 0021          | float32       | Temperatur X2      | °C      |
| 0023          | float32       | Druckwinkel        | °       |
| 0025          | float32       | Axialschub         | N       |
| 0027          | float32       | Effektivwert       | mm/s    |

## External Data
Über den Registerbreich 40100-40120 können externe Daten in das System eingespielt werden. Diese sind im Scripteditor oder den Benutzerdefinierten Variablen als `external_data["..."]` verfügbar.

| Start-Adresse | Datentyp      | Messwert               | Einheit |
| ------------: | :-----------: | ---------------------- | ------- |
| 0100          | uint16        | ext_0					 | -       |
| 0101          | uint16        | ext_1					 | -       |
| 0102          | uint16        | ext_2					 | -       |
| 0103          | uint16        | ext_3					 | -       |
| 0104          | uint16        | ext_4					 | -       |
| 0105          | uint16        | ext_5					 | -       |
| 0106          | uint16        | ext_6					 | -       |
| 0107          | uint16        | ext_7					 | -       |
| 0108          | uint16        | ext_8					 | -       |
| 0109          | uint16        | ext_9					 | -       |
| 0110          | uint16        | ext_10				 | -       |
| 0111          | uint16        | ext_11				 | -       |
| 0112          | uint16        | ext_12				 | -       |
| 0113          | uint16        | ext_13				 | -       |
| 0114          | uint16        | ext_14				 | -       |
| 0115          | uint16        | ext_15				 | -       |
| 0116          | uint16        | ext_16				 | -       |
| 0117          | uint16        | ext_17				 | -       |
| 0118          | uint16        | ext_18				 | -       |
| 0119          | uint16        | ext_19				 | -       |

## Fehlerwerte
Nicht gesetzte Register werden mit 0xFFFF initialisiert. Im Fehlerfall wird 0x8000 ausgegeben.