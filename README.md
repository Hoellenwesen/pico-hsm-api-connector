# HSM API Gateway

Netzwerk-API-Gateway, das Kryptooperationen des Pico-HSM (USB-angebunden,
PKCS#11) für mehrere interne Netzwerk-Clients bereitstellt — mit
Client-Authentifizierung per mTLS und Autorisierung pro Client, granular
bis auf einzelne Key-Labels.

Ergänzt das bestehende `pico-hsm`-Projekt. Seit der Konsolidierung
(siehe [`MIGRATION.md`](MIGRATION.md)) ist dies der **einzige**
PKCS#11-Konsument im gesamten Projekt — sowohl entfernte Netzwerk-Clients
als auch lokale Produkte (z. B. pqvault) sprechen über mTLS mit diesem
Gateway, auch wenn sie auf demselben Host laufen. Der bisherige separate
`pico-hsm-daemon` (Python, Unix-Socket) ist damit abgelöst und wird nicht
mehr benötigt.

---

## Bewusst nicht enthalten

Dieser Dienst stellt **ausschließlich** die fünf Kryptooperationen
`sign`, `verify`, `encrypt`, `decrypt`, `derive` bereit — jeweils
eingeschränkt auf einzelne Key-Labels pro Client. Explizit **nicht**
erreichbar über diese API, auch nicht indirekt:

- Objekt-Management (Key-Erzeugung/-Löschung, `find_objects` ohne
  Label-Filter)
- PIN-/PUK-/SO-PIN-Verwaltung
- Firmware-Update (bleibt physischer BOOTSEL-Pfad, `scripts/verify_and_flash.py`)
- Backup/Restore der HSM-Schlüssel (bleibt `scripts/backup-*.sh`)

Das ist keine reine Konvention, sondern strukturell erzwungen: `src/hsm.rs`
implementiert schlicht keine Funktionen dafür, und `src/protocol.rs` kennt
keine entsprechenden Request-Varianten.

## Architektur

```
Client (mTLS-Zertifikat) ──TLS──▶ src/server.rs
                                     │  1. CN aus Client-Zertifikat extrahieren
                                     │  2. gegen config/clients.yaml autorisieren
                                     │     (Default-Deny, pro Operation + Key-Label)
                                     │  3. bei Erfolg: src/hsm.rs aufrufen
                                     │  4. Ergebnis + Audit-Eintrag (Hash-Chain)
                                     ▼
                              src/hsm.rs ──PKCS#11──▶ Pico HSM (USB)
```

Wire-Format: newline-delimited JSON über mTLS (kein gRPC), damit jedes
Produkt, das TLS + JSON kann, ohne generiertes SDK andocken kann.
Beispiel-Request:

```json
{"op": "sign", "key_label": "app-b-signing-key", "mechanism": "ecdsa_sha256", "data_b64": "..."}
```

Bei AES-Operationen (`encrypt`, `decrypt`, `derive_and_encrypt`, `derive_and_decrypt`)
generiert das Gateway den IV pro `encrypt`/`derive_and_encrypt`-Aufruf frisch
und liefert ihn in der Antwort (`iv_b64`) zurück — der Aufrufer muss ihn
für den passenden `decrypt`/`derive_and_decrypt`-Aufruf mitschicken. Bei
`derive_and_encrypt`/`derive_and_decrypt` ist zusätzlich `peer_public_key_b64`
Pflicht (Public Key der Gegenseite für `ECDH1_DERIVE` — ohne ihn lässt sich
kein Shared Secret berechnen):

```json
{"op": "derive_and_encrypt", "key_label": "app-c-derive-key", "derive_mechanism": "ecdh1_derive", "target_mechanism": "aes_cbc_pad", "peer_public_key_b64": "<Public Key der Gegenseite>", "data_b64": "..."}
```

## Setup

```bash
# Server-Zertifikat + Client-CA vorbereiten (eigene interne CA empfohlen,
# nicht öffentliches TLS — das ist ein internes Homelab-Gateway)
export GATEWAY_LISTEN_ADDR="0.0.0.0:8443"
export GATEWAY_SERVER_CERT=/etc/hsm-gateway/server.pem
export GATEWAY_SERVER_KEY=/etc/hsm-gateway/server-key.pem
export GATEWAY_CLIENT_CA=/etc/hsm-gateway/client-ca.pem
export GATEWAY_CLIENTS_CONFIG=/etc/hsm-gateway/clients.yaml
# WICHTIG: libsc-hsm-pkcs11.so, NICHT opensc-pkcs11.so — OpenSCs
# sc-hsm-Treiber unterstuetzt laut pico-hsm/doc/aes.md kein AES fuer
# das Pico HSM. encrypt/decrypt/derive_and_encrypt/derive_and_decrypt
# (alle nutzen AES-CBC) wuerden mit opensc-pkcs11.so fehlschlagen; sign/
# verify/RSA-Operationen funktionieren mit beiden Modulen. Siehe
# "Offene Punkte", Punkt 6, zur noch ausstehenden Hardware-Verifikation.
export GATEWAY_PKCS11_MODULE=/usr/lib/libsc-hsm-pkcs11.so
export GATEWAY_HSM_PIN="<aus Vaultwarden zur Laufzeit injizieren>"
export GATEWAY_AUDIT_LOG=/var/log/hsm-api-gateway/audit.jsonl
# Zertifikats-Lebensdauer-Policy (docs/11-Ergänzung, Punkt 4) — optional,
# Defaults: max. 90 Tage Gültigkeit, Warnung ab 14 Tagen vor Ablauf
export GATEWAY_MAX_CLIENT_CERT_VALIDITY_DAYS=90
export GATEWAY_CERT_EXPIRY_WARN_DAYS=14

cargo run --release
```

`config/clients.yaml` nach dem Muster in `config/clients.example.yaml`
befüllen — siehe Kommentare dort zum Default-Deny-Prinzip.

**Für den Betrieb mit echter Pico-HSM-Hardware und den kompletten
Zertifikats-Rotations-Ablauf (Client-Zertifikate, Server-Zertifikat,
Notfall-Sperrung, CA-Kompromittierung):
[`docs/16-real-hardware-and-cert-rotation.md`](docs/16-real-hardware-and-cert-rotation.md).**

**Migriert ihr von `pico-hsm-daemon` (bisheriger lokaler Python-Daemon)
auf dieses Gateway:** vollständige Anleitung inkl. Funktionsvergleich,
Wrap/Unwrap-Ersatz und Schritt-für-Schritt-Vorgehen in
[`MIGRATION.md`](MIGRATION.md). Ein lauffähiges Client-Beispiel für lokale
Produkte liegt in [`examples/local_client_example.py`](examples/local_client_example.py).

## Client-Zertifikats-Policy (kurzlebige Zertifikate statt Revocation)

Statt CRL/OCSP-Checking (mehr Betriebsaufwand fürs Homelab) erzwingt das
Gateway kurze Zertifikatslaufzeiten direkt am Verbindungsaufbau:

- **Harte Ablehnung**, wenn ein präsentiertes Client-Zertifikat länger
  gültig ist als `GATEWAY_MAX_CLIENT_CERT_VALIDITY_DAYS` (Default: 90
  Tage) — fängt eine falsch konfigurierte CA ab, nicht nur ein
  einzelnes falsch ausgestelltes Zertifikat.
- **Proaktive Warnung** (Log + Audit-Eintrag `cert_expiring_soon`), wenn
  ein Client sich mit einem bald ablaufenden Zertifikat meldet
  (`GATEWAY_CERT_EXPIRY_WARN_DAYS`, Default: 14 Tage) — Rotation fällt
  damit auf, bevor der Client eines Tages hart mit TLS-Handshake-Fehler
  ausfällt.
- Reine Ablauf-/Noch-nicht-gültig-Prüfung übernimmt weiterhin `rustls`
  selbst beim Handshake (`WebPkiClientVerifier`) — das hier ist eine
  zusätzliche Policy-Ebene, kein Ersatz dafür.
- **Bewusst kein Revocation-Checking:** Ein kompromittiertes, aber noch
  gültiges Zertifikat lässt sich aktuell nur durch Entfernen aus
  `clients.yaml` sperren, nicht durch aktiven Widerruf. Für ein Homelab
  mit wenigen Clients und kurzen Rotationszyklen ist das eine bewusste
  Abwägung, kein Versehen — bei Bedarf (mehr Clients, höheres
  Bedrohungsniveau) CRL/OCSP später nachrüsten.

## Kompilieren & Testen (lokal, ohne echtes HSM)

### 1. Voraussetzungen installieren

```bash
# Aktuelles Rust — NICHT das Distro-Paket verwenden (siehe Abschnitt
# "Warum hier nicht kompiliert" unten, MSRV-Problem)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustc --version   # sollte 1.85+ sein

# PKCS#11-Software-Token für lokale Tests OHNE Pico-Hardware.
# SoftHSM2 emuliert ein PKCS#11-Token komplett in Software — genau das
# Interface, das euer echter Pico HSM auch bereitstellt, nur ohne USB.
sudo apt install -y softhsm2 opensc

# OpenSSL für lokale Test-CA/-Zertifikate
sudo apt install -y openssl
```

### 2. Bauen und Unit-Tests laufen lassen

```bash
cd hsm-api-gateway
cargo build            # Debug-Build, schnell, für Entwicklung
cargo build --release  # Release-Build, für den späteren Produktivbetrieb

cargo test              # Unit-Tests (Autorisierungslogik in config.rs:
                         # allows_configured_combination, denies_wrong_key_label,
                         # denies_wrong_operation, denies_unknown_client,
                         # rejects_empty_key_labels_at_load_time)
```

Diese Tests brauchen kein HSM — sie prüfen nur die Autorisierungstabelle
(`AuthzTable`) rein logisch.

### 3. SoftHSM2 als Pico-HSM-Ersatz für lokale End-to-End-Tests einrichten

```bash
mkdir -p ~/softhsm2-tokens
cat > ~/softhsm2.conf << 'EOF'
directories.tokendir = /home/YOUR_USER/softhsm2-tokens
objectstore.backend = file
EOF
export SOFTHSM2_CONF=~/softhsm2.conf

# Token initialisieren (SO-PIN/PIN frei wählbar, nur für den lokalen Test)
softhsm2-util --init-token --slot 0 --label "test-token" \
    --so-pin 12345678 --pin 648219

# Beispiel-AES-Key für encrypt/decrypt-Tests anlegen (Label muss zu
# eurer clients.yaml passen, siehe config/clients.example.yaml)
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --login --pin 648219 \
    --keygen --key-type AES:32 --label "shared-encryption-key"

# EC-Key für sign/verify-Tests
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --login --pin 648219 \
    --keypairgen --key-type EC:secp256r1 --label "app-b-signing-key"
```

Für den Gateway-Start dann `GATEWAY_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so`
statt `opensc-pkcs11.so` setzen — der restliche Code (Autorisierung,
mTLS, Audit-Log) ist identisch zum späteren Betrieb mit dem echten Pico.
Erst wenn das durchgängig funktioniert, gegen `opensc-pkcs11.so` mit
angeschlossenem Board wechseln.

### 4. Test-CA + Server-/Client-Zertifikate lokal erzeugen

```bash
mkdir -p certs && cd certs

# Interne Test-CA (nicht die Produktiv-CA — nur zum lokalen Ausprobieren)
openssl req -x509 -newkey rsa:4096 -days 3650 -nodes \
    -keyout ca-key.pem -out ca.pem -subj "/CN=hsm-gateway-test-ca"

# Server-Zertifikat
openssl req -newkey rsa:4096 -nodes -keyout server-key.pem \
    -out server.csr -subj "/CN=hsm-gateway.internal.test"
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem \
    -CAcreateserial -days 825 -out server.pem

# Ein Client-Zertifikat, CN muss exakt zu config/clients.yaml passen
# (z. B. "app-a.internal.example" aus clients.example.yaml).
# -days bewusst kurz halten, um GATEWAY_MAX_CLIENT_CERT_VALIDITY_DAYS
# gleich mitzutesten (Default 90 Tage — 30 Tage hier besteht die Policy-Prüfung).
openssl req -newkey rsa:4096 -nodes -keyout client-a-key.pem \
    -out client-a.csr -subj "/CN=app-a.internal.example"
openssl x509 -req -in client-a.csr -CA ca.pem -CAkey ca-key.pem \
    -CAcreateserial -days 30 -out client-a.pem
```

Test der Policy-Ablehnung: ein zweites Client-Zertifikat mit `-days 200`
ausstellen und gegen den laufenden Gateway verbinden — sollte mit
`cert_policy_violation` abgelehnt werden (siehe `enforce_cert_policy` in
`src/server.rs`).

### 5. Gateway starten und mit einem einfachen Client testen

```bash
# Terminal 1: Gateway starten
export GATEWAY_LISTEN_ADDR="127.0.0.1:8443"
export GATEWAY_SERVER_CERT=certs/server.pem
export GATEWAY_SERVER_KEY=certs/server-key.pem
export GATEWAY_CLIENT_CA=certs/ca.pem
export GATEWAY_CLIENTS_CONFIG=config/clients.example.yaml
export GATEWAY_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so
export GATEWAY_HSM_PIN=648219
export GATEWAY_AUDIT_LOG=/tmp/hsm-gateway-audit.jsonl
RUST_LOG=debug cargo run --release
```

```bash
# Terminal 2: mit openssl s_client testen (mTLS-Handshake + manuelle Anfrage)
echo '{"op":"encrypt","key_label":"shared-encryption-key","mechanism":"aes_cbc_pad","data_b64":"aGVsbG8="}' | \
openssl s_client -connect 127.0.0.1:8443 \
    -cert certs/client-a.pem -key certs/client-a-key.pem -CAfile certs/ca.pem \
    -quiet
```

Erwartete Antwort: eine Zeile JSON mit `"status":"ok"`, `result_b64` und
zusätzlich `iv_b64` (der pro Aufruf frisch generierte AES-CBC-IV, siehe
"Wire-Format" oben — für den passenden `decrypt`-Aufruf muss dieser
`iv_b64`-Wert mitgeschickt werden, sonst lässt sich der Ciphertext nicht
entschlüsseln).
Danach `/tmp/hsm-gateway-audit.jsonl` ansehen — dort sollte ein
`authorized`-Eintrag für `app-a.internal.example` stehen.

Ein Aufruf mit einem Key-Label, das laut `clients.example.yaml` für
diesen Client *nicht* freigegeben ist (z. B. `app-b-signing-key`), sollte
stattdessen `"status":"denied"` liefern und im Audit-Log als `denied`
auftauchen — guter erster Test für die Autorisierungslogik end-to-end.

### 6. Audit-Chain-Integrität prüfen

Es gibt noch kein CLI-Tool dafür (analog zu
`verify_audit_chain()` in `scripts/verify_and_flash.py`) — `AuditLog::verify_chain()`
in `src/audit.rs` ist aktuell nur intern beim Gateway-Start eingebunden.
Für einen manuellen Check reicht ein kleines Testprogramm oder ein
zusätzliches `cargo test`, das die Datei einliest — noch nicht als
eigenständiges Binary umgesetzt (siehe "Offene Punkte", Wazuh-Anbindung).

## Offene Punkte vor Produktivbetrieb

Diese Liste ist bewusst genauso ehrlich gehalten wie
`docs/15-real-hardware-validation-checklist.md` im Hauptprojekt — nichts
hiervon wurde gegen echte Hardware getestet, dafür gibt es in dieser
Sandbox weder ein PKCS#11-Modul noch ein angeschlossenes Board:

1. ~~`derive`-Semantik ist noch ein Platzhalter~~ **Gelöst:** Es gibt
   kein eigenständiges "gib mir den abgeleiteten Key zurück" mehr,
   sondern nur noch atomare `derive_and_encrypt`/`derive_and_decrypt` —
   Ableitung und Verwendung passieren in derselben PKCS#11-Session, der
   abgeleitete Key ist `Token(false)` (session-lokal) und verlässt das
   HSM nie. Analog zum bestehenden `hsm_backend.py::wrap_key()`-Muster.
2. **Mechanismus-Freigabeliste in `server.rs`** (`parse_mechanism`,
   `build_aes_cbc_pad`, `build_ecdh1_derive`) ist nur ein Startpunkt
   (RSA-PKCS, ECDSA-SHA256, AES-CBC-Pad, ECDH1) — an die tatsächlich von
   euren angebundenen Produkten benötigten Mechanismen anpassen.
3. ~~Noch nicht gegen echtes HSM getestet, Kompilierung nicht möglich~~
   **Teilweise gelöst:** `cargo check`/`cargo test` laufen inzwischen
   erfolgreich (Rust 1.85+ vorausgesetzt, s. u.) — dabei kamen drei
   reale Bugs zutage, die vorher nie kompiliert wurden und jetzt
   behoben sind: fehlendes `tokio`-Feature `io-util` (Cargo.toml),
   `u64`/`Ulong`-Typfehler in `hsm.rs::default_derived_aes_template`,
   sowie in `server.rs::parse_mechanism` zwei Stellen, die mit
   `Default::default()` arbeiteten, obwohl die zugehörigen
   `cryptoki`-Parametertypen (`Ecdh1DeriveParams`) gar kein `Default`
   implementieren bzw. (`AesCbcPad`-IV) fachlich falsch gewesen wären
   (fixer Null-IV). Was weiterhin fehlt: ein **Testlauf gegen echte
   oder simulierte (SoftHSM2) Hardware** — die PKCS#11-Aufrufe in
   `hsm.rs`/`server.rs` kompilieren jetzt korrekt gegen die
   `cryptoki`-0.7-API, wurden aber noch nie tatsächlich ausgeführt.
4. **`docs/11-threat-model.md` ergänzen** — dieser Dienst ist ein neues
   Angriffsziel (Netzwerkdienst statt nur lokaler Host), sollte als
   eigener Eintrag ins Threat Model, bevor er produktiv geht.
5. **Wazuh-Anbindung** — `AuditLog::verify_chain()` ist als periodischer
   Check gedacht, genau wie beim bestehenden `verify_and_flash.py`-Audit-
   Log; noch nicht an eure Wazuh-Instanz angebunden.
6. **SoftHSM2 ≠ Pico HSM.** SoftHSM2 eignet sich gut, um Autorisierung,
   mTLS und das Wire-Protokoll durchgängig zu testen, deckt aber nicht
   zwingend exakt dieselbe Mechanismus-Unterstützung ab wie die
   `pico-hsm`-Firmware (insbesondere `ECDH1_DERIVE`-Parameter/Verhalten
   können abweichen). Ein erfolgreicher SoftHSM2-Testlauf ersetzt nicht
   den Testlauf gegen das echte Board — nur den ersten, schnelleren
7. **AES braucht `libsc-hsm-pkcs11.so`, nicht `opensc-pkcs11.so`.**
   Laut `pico-hsm/doc/aes.md` unterstützt OpenSCs sc-hsm-Treiber kein
   AES für das Pico HSM — nur das `sc-hsm-embedded`-Modul
   (`libsc-hsm-pkcs11.so`) tut das. Da `encrypt`/`decrypt` und beide
   `derive_and_*`-Operationen AES-CBC nutzen, betrifft das den
   Großteil der API. Setup/docs/16 sind entsprechend auf
   `libsc-hsm-pkcs11.so` umgestellt, aber **noch nicht gegen echte
   Hardware verifiziert**, ob dieses Modul auch RSA/ECDSA/ECDH
   vollständig abdeckt (Doku-Hinweise deuten stark darauf hin, siehe
   `pico-hsm/doc/sign-verify.md` und `usage.md`) — vor Produktivbetrieb
   den kompletten Mechanismus-Satz einmal ausschließlich gegen
   `libsc-hsm-pkcs11.so` durchtesten.
   Iterationszyklus davor.

## Kompilier-Status

`cargo check` und `cargo test` laufen erfolgreich durch (verifiziert mit
Rust 1.97). Frühere Sandbox-Versuche scheiterten an Rust 1.75
(Ubuntu-Distro-Paket) — aktuelle crates.io-Versionen mehrerer
Abhängigkeiten (u. a. transitiv über `chrono`, `indexmap`, `aws-lc-sys`)
verlangen Rust 1.85+. Auf eurem Dev-Host: aktuelles Rust per `rustup`
installieren (nicht das Distro-Paket).

Ein erfolgreicher `cargo check` bedeutet **nicht**, dass die
PKCS#11-Aufrufe tatsächlich funktionieren — das wurde noch nie gegen
echte oder simulierte (SoftHSM2) Hardware ausgeführt, siehe "Offene
Punkte", Punkt 3.
