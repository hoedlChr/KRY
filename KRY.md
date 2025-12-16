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
# Was ist Integrität? Kann es Integrität ohne Vertraulichkeit geben?
# Was ist Unterschied zwischen Authentizität und Verbindlichkeit? Welche Verfahren stellen Authentizität sicher, aber nicht Verbindlichkeit- Welche Verfahren stellen beides sicher?
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
# Wieso ist der Schlüsselraum bzw. Suchraum eines kryptographischen Verfahrens so wichtig?
# Welche Rolle spielt Zufall in kryptographischen Verfahren- In welchen Schritten ist Zufallsicherheitsrelevant?
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
* Schlüssel halbieren und zwei Personen geben (wenn es sehr wichtig ist)
* **Schlüsselverteilung**
* Offline Verteilung - physisch zwischen den Parteien ausgetauscht
* Verschlüsselung mti öffentlichem Schlüssel
* Diffie Helmman Schlüsselaustausch
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
# Warum ist der One-Time-Pad (OTP / Vernam-Chiffre) nachweislich sicher- Was sind die Vor-/Nachteile des Verfahrens?
# Worauf muss bei OTP besonders geachtet werden- Warum?
# Was ist die Basisidee von Rotormaschinen?
# Mit welcher Art von moderner Chiffre (Strom, Block mit bestimmten Modi) können Rotormaschinen am ehesten verglichen werden?
# Welche kryptographischen Eigenschaften weisen Rotormaschinen auf?
# Was ist die Transposition? Welche Eigenschaften zeichnen sie aus? Welche Angriffe gibt es auf die Transposition?
# Welche Verfahren gibt es für die Transposition?
# Wie ist das Grundkonzept der asymmetrischen Verschlüsselung? 
# Welche Bedingungen muss der Schlüssel für eine sichere One-Time Pad Verschlüsselung erfüllen?
# Welche Schwachstellen weist eine Verschlüsselung mit der Enigma auf?
# Was ist die Grundidee des Vigenere Chiffre und wie kann dieser geknackt werden?
# Welche typischen Rollen und Name kennen Sie in er Kryptographie
* Alice: want to exchange a message
+ Bob: wants to exchange a message
- Eave: listen to the message (cannot modify)
* Mallory malicous attacker: man in the middle attack, modify message
+ Trudy: Intruder
# Wie lauten die zwei Grundfunktionen eines Verschlüsselungsprozesses?
# Welcher Buchstabe ist der häufigste in der Deutschen Sprache?
- e

# Was ist Diffusion? Warum ist sie wichtig? Welche kryptographischen Eigenschaften besitzt sie?
# Welche Angriffe werden durch gute Diffusion verhindert?
# Welche Diffusionseigenschaften haben klassische (z.B. Vigenere) und moderne (z.B. DES/AES) Verfahren?
# Was ist der Avalanche-Effekt? Warum soll dieser möglichst ausgeprägt sein?
# Wieso findet bei modernen Verfahren die Kryptographie in Runden statt?
# Wieso ist die Hill-Chiffre nach heutigen Maßstäben nicht ausreichend sicher? Worauf beruht ihre Schwäche?
# Was ist Konfusion?
# Welche wesentliche Eigenschaft muss ein Verfahren haben, um gute Konfusion zu erzielen?
# Wie wird diese Eigenschaft in der Praxis umgesetzt?
# Welche Eigenschaften hat DES?
# Was ist differentielle Kryptoanalyse?
# Worauf beruht die Sicherheit von DES? Warum ist DES heute nicht mehr ausreichend sicher?
# Welche DES-Varianten gibt es?
# Warum gilt 3DES als noch ausreichend sicher, wenn DES selbst unsicher ist?
# Welche Eigenschaften hat AES?
# Worauf beruht die Sicherheit von AES?
# Wie lauten die einzelnen Schritte einer AES-Runde und wie funktionieren sie?
# Welche Eigenschaften haben die einzelnen Schritte im AES und warum sind sie notwendig?
# Welcher Schritt wird bei AES in der letzten Runde ausgelassen?
# Welches Ziel hat der Shiftrow Schritt des AE?
# Von wem wurden die Grundprinzipien der Kryptografie (Konfusion & Diffusion) definiert?
# Welche 3 Elemente müssen in einer Runde im Rundenprinzip vorhanden sein?

# Was ist ein Hash? Welche Eigenschaften besitzt er? Für welchen Zweck werden Hashverfahren eingesetzt?
# Was ist eine Kompressionsfunktion?
# Welche Auswirkung hat die blockweise Verarbeitung der Daten beim Hashen?
# Was ist eine Kollision? Warum sollten Kollisionen vermieden werden?
# Was ist der Unterschied zwischen schwacher und starker Kollisionsresistenz?
# Was ist das Geburtstagsparadoxon?
# Was sind die wesentlichen Bausteine von MD5?
# Welche SHA versionen sind sicher?
# Hashfunktion vs. Kryptografische Hashfunktion
# Arten von Kollisionen
# Merkle Damgard Konstruktion
# Angriffe auf Hashfuktionen
# Was ist ein MAC? Wodurch unterscheidet er sich von einem Hash?
# Wieso wird die Authentizität sichergestellt? Wieso aber nicht die Verbindlichkeit?
# Was ist ein HMAC? Welche Eigenschaften hat er?
# Warum könnte beim HMAC ohne zweite Stufe der Angreifer den MAC für eine verlängerte Nachricht erzeugen, ohne den Schlüssel zu kennen?

# Kapitel 05 - Secure Password Storage:

# Was unterscheidet Block- und Stromchiffren?
# Welche Vor- und Nachteile gibt es im Allgemeinen? Wo werden bevorzugt welche Varianten eingesetzt?
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
