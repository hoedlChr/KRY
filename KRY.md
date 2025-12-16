# Warum ist Kryptographie so wichtig?
* Datenschutz
* Integrität
* Authtentifizierung
  * Verifiziert die Auth. von Systemen und Benutzern
* Sicherheit im Internet
* Sicherheit in der IT
* Kryptowährung
  * Sichert Transaktion in digitalen Währung
# Einsatzgebiete Kryptographie
* Datenschutz im Internet
* E-Mail-Sicherheit
* Passwortschutz
* Online-Banking
* Identitätsnachweis
* Smartphone-Sicherheit
  * Verschlüsselung von Daten
* Kryptowährung
* Cloud-Sicherheit
* IoT-Geräte
* Regierungs- und Militäranwendungen
* VPN
* SSH
* BitLocker
* S/MIME-Zertifikate
* Persönlichers Zertifikat für eMails
* Code Signing
  * Authentizität und Integrität von Programmcode
# CIA Triad + Zusatzziele - Beschreiben
* Confidentiality (Vertraulichkeit)
  * Daten werden nur von den vorgesehenen Personen gelesen
* Integrity (Integrität)
  * Daten können nicht verändert werden
* Availability (Verfügbarkeit)
  * Jederzeit und ohne unnötige Unterbrechungen oder Einschränkungen verfügbar
+ Authenticity (Authentizität)
  + Identität der Teilnehmer muss verifiziert werden
+ Non-repudiation (Verbindlichkeit / Nichtabstreitbarkeit)
  + Aktionen sollen nachvollziehbar und überprüfbar sein
# Wichtige Begriffe kennen und beschreiben können
* Information Security (Informationssicherheit)
  * Gesamtkonzept und Praktiken zum Schutz vor unbefugtem Informations Zugriff, Verlust oder Diebstahl
* Confidentiality (Vertraulichkeit)
  * Information nur vpn autorisierten Personen gelesen
* Eavesdropping (Abhören)
  * unautorisierte Abhören
* Integrity (Integrität)
  * Sicherstellung das Information nicht während der Übertragung oder Speicherung unbemerkt verändert wird
* Modification (Veränderung)
  * unautorisierte Änderung von Daten
* Availability (Verfügbarkeit)
  * Systeme zuverlässig und ohne Unterbrechung verfügbar sind
* (Service) Interruption (Dienstunterbrechung)
  * Gezielte Störung oder Unterbrechung
* Authenticity (Authentizität)
  * Person/System ist tatsächlich die Person/System
* Identity (Identität)
  * Die DIentifikation und Überprüfung einer Person/System
* Fraud/Spoofing (Betrug/Täuschung)
  * Täuschung oder Imitation
* (Public/Private) Channel (öffentlicher/Privater Kanal)
  * Kommunikationswege sind entweder für dritte sichtbar (bearbeitbar) oder nur für Sender und Empfänger
* Encryption (Verschlüsselung)
  * Information in unverständliche Form umgewandelt
* Key (Schlüssel)
  * Für Ver- und Entschlüsselung
* Kerchhoffs Principle (Kerckhoffs-Prinzip)
  * Verschlüsselungsalgorithmus muss öffentlich sein (Sicherheit liegt im Schlüssel)
* Key Distribution
  * geheimer Schlüssel sicher an Kommunikationspartner
* Zero Knowledge
  * Verfahren das eine Person eine Info weiß, ohne diese Preis zu geben 
* (Authentication) Non-Repudiation (Nicht-Abstreitbarkeit)
  * User kann Aktion nicht leungnen
* Anonymity (Anonymität)
  * Online oder in Kommunikation Anonym zu bleiben
* Unlinkability (Nicht-Verknüpfbarkeit)
  * Transaktionen und Aktivitäten nicht miteinander in Verbindung gebracht werden
* Full Privacy (Vollständige Privatsphäre)
  * Umfassender Schutz der Privatsphäre
# Was bedeutet Vertraulichkeit? Durch welche Verfahren kann Vertraulichkeit sichergestellt werden?
* Daten können nur von den vorgesehenen Empfängern gelesen werden
* Verschlüsselung, Zugriffkontrolle, Authentifizierung, Datensicherheit, klare Richtlinien
# Kann es vollständige Vertraulichkeit (= Null Informationsgewinn) geben?
* in der Theorie schon, jemand kann beweisen das er etwas beweis ohne es preis zugeben
* aber in der Praxis ist das nciht möglich
# Was ist Integrität? Kann es Integrität ohne Vertraulichkeit geben?
* Daten nicht unbemerkt verändert werden können
* öffentlich lesbar aber vor Manipulation geschützt
# Was ist Unterschied zwischen Authentizität und Verbindlichkeit? Welche Verfahren stellen Authentizität sicher, aber nicht Verbindlichkeit- Welche Verfahren stellen beides sicher?
* Authentizität: Bestätigung, dass eine Perso wirklich die ist für die sie sich gibt
* Verbindlichkeit: Aktionenn sollen nachvollziehbar sein
# Was sind die Eigenschaften symmetrischer Verschlüsselung im Allgemeinen?
* Ohne Schlüssel kann Mallory die Nachricht nicht entschlüsseln
* ein Schlüssel der ent- und verschlüsselt
# Was besagt das Prinzip von Kerckhoffs?
* Ein Kryptosystem muss auf die Sicherheit des Key s vertrauen und nicht auf die vom Algorythmus
# Was sind die Eigenschaften monoalphabetischer Substitution
* Zeichen durch andere Zeichen ersetzen
* Code of Mary Stuart, Cäsar-Chiffre, rot13,...
* Verschlüsselungsverfahren, bei dem jeder Buchstabe oder jedes Zeichen durch ein anderes Zeichen nach Vorgabe eines einzigen Alphabets ersetzt wird.
# Warum ist sie heute nicht ausreichend
* seit Erfindung der Häufigkeitsanalyse keine Sicherheit mehr
* Sprachmuster bleiben erhalten
# Wieso ist der Schlüsselraum bzw. Suchraum eines kryptographischen Verfahrens so wichtig?
* ist der schlüsselraum zu klein kann man es einfach ausprobieren
* man soll den gesamten schlüsselraum ausnutzen
# Welche Rolle spielt Zufall in kryptographischen Verfahren- In welchen Schritten ist Zufallsicherheitsrelevant?
* Schlüssel soll möglichst zufällig sein
* OTP zufalls ist zwingend
# Was ist die Kryptoanalyse- Welche Methoden (Angriffe) werden verwendet?
* Brute Force
  * Wiederholte Versuche, Schlüssel zu erraten
  * Angreifer kennt den Algo
* Ciphertext Only
  * Angreifer hat nur den Chiffre Text
  * Schwierigste
* Known Plaintext
  * Algorithmus, Chiffretext und Klartext
  * Mallory kennt den Klartext und versucht für das Entschlüsseln weitere Nachrichten den Schlüssel zu erfahren
* Chosen Plaintext
  * Mallory will den Schlüssel herausfinden und hat dabei die Möglichkeit, den Klartext selber zu wählen
* Lineare Kryptoanalyse
  * Verhalten von Blockchiffre zu analysieren
* Differenzielle Kryptoanalyse
  * Berechnet Unterschied zwischen Klartext und Chiffretext
* Side Channel Attacks
  * betrachtet die Physikalischen Eigenschaften: Klang, Stromverbrauch, Temp...
* Fault Analysis
  * versucht das Kryptosystem in einen Fehlerzustand zu zwingen
# Was ist ein Klartextangriff?
* Der Angreifer kennt eine bekannte Nachricht (Klartext) und den zugehörigen Geheimtext und versucht, den Schlüssel zu finden 
# KERCKHOFFS‘ PRINCIPLE
* Ein Kryptosystem muss auf die Sicherheit des Key s vertrauen und nicht auf die vom Algorythmus
# Kryptographische Schlüssel (KEY MANAGEMENT BEST PRACTICES, SCHLÜSSELVERTEILUNG)
* geheime Zeichenfolgen/Zahlen - zum Daten ver und entschlüsseln
* **Key Management Best Practices**
* Bewahren Sie die geheimen Schlüssel immer sicher auf
* Schlüssel muss Zufällig sein
* Schlüssel muss (wenn nicht mehr benötigt) vernichtet werden
* schlüssel und daten auf zwei systemen speichern
* Schlüssel halbieren und zwei Personen geben (wenn es sehr wichtig ist)
* **Schlüsselverteilung**
* Offline Verteilung - physisch zwischen den Parteien ausgetauscht
* Verschlüsselung mti öffentlichem Schlüssel
* Diffie Helmman Schlüsselaustausch (geheimen schlüssel ableiten ohne übertragen)
# Vor- und Nachteile der Symmetrischen Kryptographie
* **Vorteile**
* Effizienz
* Geringer Overhead
* Enfache Schlüsselverwaltung
* Sichere bei richtiger Umsetzung
* Vielseitig
* **Nachteile**
* Schlüsselverteilung
* Keine "Non-Repudiation" - Man kann nicht sagen von wem die Nachricht kommt
* Nicht skalierbar
* Häufige Schlüsselneugenerierung - wenn teilnehmer die Gruppe verlassen
# Was ist das Ziel der homophonen Verschlüsselung? Warum ist sie heute nicht mehr ausreichend sicher?
* Buchstaben die häufig vorkommen werden durch verschiedene Zeichen ersetzt
* zuordnung unveränderlich, weist ein muster auf
# Was ist polyalphabetische Substitution- Warum bietet sie eine höhere Sicherheit als monoalphabetische Substitution?
* Buchstaben durch andere ersetzen, wobei verschiedene Alphabete verwendet werden
+ Vignere-Chiffre
  + Text und Schlüssel
| Text | Schlüssel |  | Verschlüsselt |
| alles ist eine folge von bits | alice | alice ali ceal iceal ice alic |awtgw idb gmnp nqpgp dqr btbu|
  + Schlüssellänge finden, einzelne Alphabete finden
  + Autokorrelation testen
  + Häufigkeitsanalyse
* Vernam-Chiffre
  * schlüssel muss (mind) Länge des Textes haben
  * schlüssel nur einmal verwendet
  * muss zufällig sein
  * Nachteil: schlüssel austausch und generierung
+ One-Time Pad
# Wieso ist bei polyalphabetischer Substitution das Verhältnis Geheimtextlänge zu Schlüssellänge sicherheitsrelevant?
* je größer der schlüsssel ist desto weniger oft wiederholt er sich
# Warum ist der One-Time-Pad (OTP / Vernam-Chiffre) nachweislich sicher- Was sind die Vor-/Nachteile des Verfahrens?
* Beweisbar unknackbar
  * Muss mindestens text länge sein
  * darf nur 1x verwendet werden
  * muss zufällig sein
* **Nachteil**
  * Schlüsselaustausch
  * Schlüsselgenerierung
  * Daher kaum in der Praxis eingesetzt
# Worauf muss bei OTP besonders geachtet werden- Warum?
* Schlüssel nur einmal Benutzen
* Schlüssel muss gleich lang wie text sein
# Was ist die Basisidee von Rotormaschinen?
* Aus einem kurzen schlüssel einen sich verändernden schlüsselstrom erzeugen
* sich drehende Rotoren ergeben bei jedem Zeichen ein neues Alphabet
# Mit welcher Art von moderner Chiffre (Strom, Block mit bestimmten Modi) können Rotormaschinen am ehesten verglichen werden?
* Vernam Chiffre
# Welche kryptographischen Eigenschaften weisen Rotormaschinen auf?
* Frequenz analyse nicht mehr zielführend (weil Alphabet ständig wechselt)
* Bekannter klartext ist nur bedingt hilfreich
# Was ist die Transposition? Welche Eigenschaften zeichnen sie aus? Welche Angriffe gibt es auf die Transposition?
* Position der Zeichen Ändern, aber zeichen bleiben gleich
* Frequenzanalyse ist nutzlos
* wenn teile bekannt ist es relativ einfach
# Welche Verfahren gibt es für die Transposition?
* Skytale
* Gartenzaun
* Fleißner Schablone
* Spalten Transposition
# Wie ist das Grundkonzept der asymmetrischen Verschlüsselung? 
* Private und Public Key
* Sender verschlüsselt mit dem public key vom enmpfänger und empfänger entschlüsselt mit private key
# Welche Bedingungen muss der Schlüssel für eine sichere One-Time Pad Verschlüsselung erfüllen?
* gleich lang wie der nachrichten text
* nur einmal verwendet
* zufällig sein
* geheim und sicher verteilen
# Welche Schwachstellen weist eine Verschlüsselung mit der Enigma auf?
* Umkehrwalzen
* Klartexte bekannt
* Bedienfehler
* Sehr großer, aber endlicher Schlüsselraum mit 77bit, welcher heute knackbar ist
# Was ist die Grundidee des Vigenere Chiffre und wie kann dieser geknackt werden?
* Schlüssellänge finden, Alphabet finden
* Zählen der Häufigkeit des x buchstaben
# Welche typischen Rollen und Name kennen Sie in er Kryptographie
* Alice: want to exchange a message
+ Bob: wants to exchange a message
- Eave: listen to the message (cannot modify)
* Mallory malicous attacker: man in the middle attack, modify message
+ Trudy: Intruder
# Wie lauten die zwei Grundfunktionen eines Verschlüsselungsprozesses?
* Ver und Entschlüsseln
# Welcher Buchstabe ist der häufigste in der Deutschen Sprache?
- e

# Was ist Diffusion? Warum ist sie wichtig? Welche kryptographischen Eigenschaften besitzt sie?
* Kleine Änderungen führen zu großen unvorhersebare Änderung
* Verfahren robust gegen Analysen (statischtische muster im klartext ausnutzen)
* Verteilung der information - änderungen sollen sich breit im chiffre text auswirken
# Welche Angriffe werden durch gute Diffusion verhindert?
* Statistische Angriffe
# Welche Diffusionseigenschaften haben klassische (z.B. Vigenere) und moderne (z.B. DES/AES) Verfahren?
* Vignere: arbeiten auf zeichen ebene
* des/AES: lineare Umverteilung/Mischung in Runden erreicht
# Was ist der Avalanche-Effekt? Warum soll dieser möglichst ausgeprägt sein?
* Bei einer Eingabe ein möglichst andere ausgabe, gute Diffusion
# Wieso findet bei modernen Verfahren die Kryptographie in Runden statt?
# Wieso ist die Hill-Chiffre nach heutigen Maßstäben nicht ausreichend sicher? Worauf beruht ihre Schwäche?
* Lineare Transformation
* Anfällig für angriffe, wenn die schlüsselmatric nicht invertierbar ist
* Nicht sicher gegen morderne kryptanalytische Techniken
# Was ist Konfusion?
* Verschleiert die Beziehung zwischen Klartext, Schlüssel und geheimtext -> ideal nicht linear 
# Welche wesentliche Eigenschaft muss ein Verfahren haben, um gute Konfusion zu erzielen?
* nicht lineare operationen
# Wie wird diese Eigenschaft in der Praxis umgesetzt?
* Substitutionsoperationen (zb AES SubBytes als nichtlineare Byte-Substitution per S Box)
# Welche Eigenschaften hat DES?
* Blockchiffre 64 bit Blöcke, 16 runden
* Schlüssel: 64 bit, aber nur 56bit genutzt
* Intern: feistel-Netzwerk entschlüsseln mit gleichem verfahren
# Was ist differentielle Kryptoanalyse?
* Verwendet ausgewählten Klartext und versucht dann, die Unterschiede zwischen Chiffretexten zu berechnen, um den Schlüssel zu erhalten
# Worauf beruht die Sicherheit von DES? Warum ist DES heute nicht mehr ausreichend sicher?
* S Box substitution ist zentral, zustätzlich ist DES gegen differentielle kryptoanalyse entworfen. 
* Kurze Schlüssel länge
# Welche DES-Varianten gibt es?
+ Export DES mit effektiv 48 bit Schlüssel
* Mehrfach Verschlüsselungen
# Warum gilt 3DES als noch ausreichend sicher, wenn DES selbst unsicher ist?
* DES dreimal, wegen MITM ist die effektive sicherheit aber 112 Bit statt 168 Bit
# Welche Eigenschaften hat AES?
Symmetrische Blockchiffre, Block größe 128Bit, Standard seit 2001 (NIST)
Schlüsselgrößen: 128/192/256 Bit sehr effizient in Software & Hardware, weltweit als sicher anerkannt
# Worauf beruht die Sicherheit von AES?
Rundenstruktur udn dem Zusammenspiel aus nichtlinearer substitution (S-Box), Permutattion/linearer Durchmischung (Diffusion) und Rundenschlüssel
SubBytes trägt explizit dazu bei, gegen lineare und differentielle Kryptoanalyse zu schützen
# Wie lauten die einzelnen Schritte einer AES-Runde und wie funktionieren sie?
1. SubBytes
  * Nichtlineare Byte Substitution über eine S Box
2. ShiftRows
  * Zeilenweises Verschieben der 4x4 Byte Matrix
3. Mix Columns
  * Spaltenweise Durchmischung
4. AddRoundKey
  * XOR der Datenmatrix mit dem Rundenschlüssel
# Welche Eigenschaften haben die einzelnen Schritte im AES und warum sind sie notwendig?
# Welcher Schritt wird bei AES in der letzten Runde ausgelassen?
MixColums
# Welches Ziel hat der Shiftrow Schritt des AES?
Bytes Verteilun und verschieben für die diffusion (Permute)
# Von wem wurden die Grundprinzipien der Kryptografie (Konfusion & Diffusion) definiert?
Claude Shannon in seinem Werk „A Mathematical Theory of Communication“
# Welche 3 Elemente müssen in einer Runde im Rundenprinzip vorhanden sein?
* ncihtlineares zur Konfusion
* Lineares zur Diffusion
* rundenschlüssel

# Was ist ein Hash? Welche Eigenschaften besitzt er? Für welchen Zweck werden Hashverfahren eingesetzt?
* Ausgabewert feste Länge
* Einwegfunktion
* Kollisionsresistenz
* Effizient
* **Anwendung**
* Integritätsprüfung
* Digitale Signaturen
* Passwortspeicherung
* Datenbanken
* MAC / HMAC
* Blockchain - Technologie
# Was ist eine Kompressionsfunktion?
* ist die funktion die aus einem zulangen eingabe die ausgabe kürzt
* zentraler baustein
# Welche Auswirkung hat die blockweise Verarbeitung der Daten beim Hashen?
* beliebig lange Nachrichten zu Hashen
* **Positive Effekte**
* Skalierbarkeit
* Effiziente Verarbeitung großer Datenmengen
* **Negative Effekte / Risiken**
* Length-Extension-Angriffe bei bestimmten Hashkonstruktionen
* Angreifer können unter Umständen den Hash einer verlängerten Nachricht berechnen
# Was ist eine Kollision? Warum sollten Kollisionen vermieden werden?
* wenn zwei unterschiedliche Nachrichten den gleihcen Hashwert haben
* Integrität kann nicht garantiert werden
* Angreifer können manipulierte Nachrichten als legitim ausgeben
* Digitale Signatiren werden angreifbar
* Vertrauen in das Hashverfahren geht verloren
# Was ist der Unterschied zwischen schwacher und starker Kollisionsresistenz?
* **Schwacher**
* wenn es sehr schwer eine zweite Nachricht mit dem selben Hashwert
* **Starker**
* es ist extrem schwer irgendein Paar zufinden
# Was ist das Geburtstagsparadoxon?
* bei n bit braucht man 2^(n/2) versuche für ein doppeltes
# Was sind die wesentlichen Bausteine von MD5?
* Merkle Damgard Konstruktion
* Blcokgröße 512Bit
* 16 Wörter pro Block
* 64 Runden
* rundenfunktion F
* Verwendung von Konstanten Ki
* Wiederholte Nutzung von Nachrichtenwörtern MI
* Ausgangslänge 128Bit
* linearen und nichtlinearen Bitoperationen
MD5 darf nicht mehr verwendet werden
# Welche SHA versionen sind sicher?
* **SICHER**
* SHA-256
* SHA-384
* SHA-512
* SHA-3
* **UNSICHER**
* MD5
* SHA-1
# Hashfunktion vs. Kryptografische Hashfunktion
* Hashfunktion
  * Datenstruktur
  * Daten effizient speichern
  * keine Einwegfunktion
* Kryptografische Hashfunktion
  * Sicherheit
  * Einwegfunktion
  * hoher Kollisionsresistenz
  * Manipulation und Rückrechnung nicht möglich
# Arten von Kollisionen
* Zufällige Kollision
* Gezielte Kollision
* Praktische Kollision (berechenbar)
# Merkle Damgard Konstruktion
* Verfahren zum Aufbau von Hashfunktionen
* Nachricht in Blöche Zerlegt
* komprimiert
* anfällig für length Extension angriffe
# Angriffe auf Hashfuktionen
* Brute Force Angriffe - ausprobieren
* Geburstagsangriffe - Ausnutzen des Geburtstagsparadox
* Kollisionsangriffe - zwei nachrichten mit einem Hash
* Längenerweiterungsangriff - Hash wird verlängert ohne die Nachricht zu ändern
* Vorabberechnungsangriff - Vorab berechnete Hash Tabellen zur schnellen Rückrechnung
* Wörterbuchangriff - Hashes typischer Eingaben werden verglichen
* Rainbow Table Angriff - Speicheroptimierter VOrabbrechnungsangriff mit Hashketten
* Side Channel Angriff - Nutzung von Laufzeit oder Energieinformationne zur Iformationsgewinnung
* Quantenangriff - Quatencomputer halbieren die effektiv die Hash Sicherheit
# Was ist ein MAC? Wodurch unterscheidet er sich von einem Hash?
* Message Authentication Code - Hashverfahren mit geheimen Schlüssel
- Hash - Integrität
- MAC - Integrität und Authentizität
# Wieso wird die Authentizität sichergestellt? Wieso aber nicht die Verbindlichkeit?
* Authentizität: nur schlüssel inhaber
* Verbindlichkeit: beide haben den gleichenschlüssel
# Was ist ein HMAC? Welche Eigenschaften hat er?
* Kryptographische Hashfunktion
* geheimenschlüssel
* zwei hash-durchläufe
# Warum könnte beim HMAC ohne zweite Stufe der Angreifer den MAC für eine verlängerte Nachricht erzeugen, ohne den Schlüssel zu kennen?
Ohne zweite hash stufe wäre das verfahren anfällig
aus bekannten hashwert einen gültigen hash für eien verlängerte nachricht berechnen

# Kapitel 05 - Secure Password Storage:

# Was unterscheidet Block- und Stromchiffren?
**Block Chiffren**
Verschlüsseln Daten in festen Blöcken mit dem selben Schlüssel
**Strom chiffren**
Schlüsselstrom: pseudozufälligen schlüsselstrom und verknüpfen diesen im laufend mit dem klartext
# Welche Vor- und Nachteile gibt es im Allgemeinen? Wo werden bevorzugt welche Varianten eingesetzt?
* Blockchiffren
  * Vorteile
  * Nachteile
* Stromchiffren
  * Vorteile
  * Nachteile

# Wie funktioniert eine Stromchiffre? Worauf beruht die Sicherheit einer Stromchiffre?
# Welche Rolle spielt Zufall bei Stromchiffren? Welche Rolle hat der Pseudozufallsgenerator?
# Was muss beim praktischen Einsatz von Stromchiffren beachtet werden?
# Nennen Sie einige Stromchiffren und deren Sicherheit.
# Warum stellen Stromchiffren die Integrität der Daten nicht sicher?
# Was muss erfüllt sein, damit Stromchiffren gegen Klartextangriffe sicher sind?
# Wie sieht Diffusion und Konfusion im Zusammenhang mit Stromchiffren aus? Wie, wenn man diese Begriffe auf den PRNG anwendet?
# Was sind Blockchiffren? Welche wesentlichen Eigenschaften haben sie?
# Was kann über die Eigenschaften einzelner Blöcke gesagt werden?
# Welche Eigenschaften hat der ECB Modus?
# Welche Integrität bietet ECB? Welche Vertraulichkeit?
# Welche Eigenschaften hat der CBC-Modus?
# Was ist Padding?
# Was ist der Initialisierungsvektor? Warum wird dieser unverschlüsselt übertragen? Welche Vorteile ergeben sich durch den IV?
# Wieso bietet der CBC-Modus keinen Schutz gegen das Verkürzen der Daten (am Anfang bzw. Ende)? Was w#re ein einfacher Mechanismus verkürzte Daten zu erkennen (ohne Hash/MAC)?
# Welche Eigenschaften hat der CFB-Modus? Wofür wird dieser bevorzugt eingesetzt?
# Inwiefern sind OFB/CTR-Modi mit einer Stromchiffre vergleichbar?
# Worauf beruht die Sicherheit von OFB/CTR? Was sollte unter allen Umständen vermieden werden?
# Welchen Vorteil bietet der CTR Modus gegenüber CFB/OFB?
# Wofür werden Modi verwendet
# AES GCM 

# Kapitel Asymmetrische Verfahren:
# siehe alle Folien Inhalte

# Kerberos: Einsatzbereiche
# Kerberos: Funktionsweise / Beschreibung des Protokolls
# Kerberos: Vor- und Nachteile / Schwachstellen

# Was ist ein SSL/TLS Handshake?
# Wofür wird dieser Verwendet?
# Wie funktioniert ein SSL/TLS Handshake?
# Welche SSL / TLS Versionen sind sicher?
# SSL RSA vs. DHE WARUM WIE
# Welche CIA Ziele werden erfüllt
# Praxisanwendung
# Man in The Middle
# Heartbleed 
# Forward Secrecy
# Cipher beschreiben und erklären können
