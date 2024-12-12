# BeMoS Modbus
## Einleitung
Dieser Dienst stellt einen Wrapper für Teile der BeMoS-API über Modbus TCP auf Port `502` im Netzwerk bereit. Da Modbus TCP keinerlei Authentifizierung beherrscht, muss auf Netzwerkbasis sichergestellt werden, dass nur berechtigte Geräte Zugriff auf diesen Port am entsprechenden BeMoS-Controller haben. Aufgrund dieses Sicherheitsproblems ist der Modbus TCP Server nicht standardmäßig bei allen BeMoS Controllern aktiviert, sondern muss gesondert unter `Dienste` im Webclient gestartet werden.

Die Standardkonfiguration umfasst Register für Wälzlager- und Dichtungsanalyse, je nach Einstellung sind nicht alle Kenngrößen verfügbar. Nicht verfügbare Kenngrößen werden als Fehlerhaft ausgegeben.

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

| Start-Adresse | Datentyp      | Messwert                      | Einheit |
| ------------: | :-----------: | ----------------------------- | ------- |
| 0001          | int32         | Unix-Zeitstempel              | s       |
| 0003          | uint16        | Pumpenzustand                 | -       |
| 0004          | uint16        | Dichtungszustand              | -       |
| 0005          | float32       | Temperatur                    | °C      |
| 0007          | float32       | Wellendrehzahl                | rpm     |
| 0009          | float32       | Kurtosis                      | -       |
| 0011          | float32       | Reciprocal variation          | -       |
| 0013          | float32       | delta Kurtosis                | -       |
| 0015          | float32       | delta Reciprocal variation    | -       |
| 0017          | float32       | Mittelwert CoE                | ns      |
| 0019          | float32       | Standardabweichung CoE        | ns      |
| 0021          | float32       | Käfigdrehzahl                 | rpm     |
| 0023          | float32       | Druckwinkel                   | °       |
| 0025          | float32       | Temperatur X1                 | °C      |
| 0027          | float32       | Temperatur X2                 | °C      |
| 0029          | float32       | Mittelwert Integral 1         | Vns     |
| 0031          | float32       | Standardabweichung Integral 1 | Vns     |
| 0033          | float32       | Mittelwert Integral 2         | Vns     |
| 0035          | float32       | Standardabweichung Integral 2 | Vns     |

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

## Fehlerwerte
Nicht gesetzte Register werden mit 0xFFFF initialisiert. Im Fehlerfall wird 0x8000 ausgegeben (0x7FC00000 (NaN) bei Floatwerten).