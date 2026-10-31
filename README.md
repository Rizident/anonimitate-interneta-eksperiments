# Anonimitāte internetā — eksperiments

Projekta darba "Anonimitāte internetā" (RTU, 2026) eksperimenta kods un dati.

Eksperimentā lokāli (127.0.0.1) nosūtīju DNS pieprasījumus četros veidos
(DNS/UDP, HTTP, DoH, DoH ar padding) un ar Wireshark pārbaudīju, ko redz novērotājs.
Detalizēts apraksts ir darba 3.3. nodaļā.

Faili:
- lab.py — eksperimenta kods
- analyze.py — uztvēruma analīze
- lab.pcapng — Wireshark uztvērums
- lab_out/, results/ — <īsi, kas tur ir>

Vide: macOS 15.6, Wireshark 4.6.9, Python <versija>, OpenSSL <versija>

Palaišana:
python3 lab.py
python3 analyze.py

TLS atslēgu žurnālu (keys.log) nepublicēju.
