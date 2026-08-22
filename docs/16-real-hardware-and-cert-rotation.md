# HSM API Gateway: Betrieb mit echtem Pico HSM + Zertifikats-Rotation

Ergänzt `README.md` (dort steht der SoftHSM2-Testpfad ohne Hardware).
Dieses Dokument beschreibt den Wechsel auf das echte Board und den
laufenden Betrieb der mTLS-Zertifikate — im gleichen Stil wie
`docs/12-secrets-overview.md` im Hauptprojekt (Tabelle: was, wo, wer,
Rotation).

---

## 1. Voraussetzungen (Board bereits provisioniert)

Setzt voraus, dass euer Pico HSM bereits nach `docs/01-setup.md` und
`docs/02-firmware-update-security.md` im Hauptprojekt provisioniert ist:
PIN/PUK/SO-PIN gesetzt, Secure Boot aktiv, `pico-hsm-tool`/`opensc`
installiert, `pcscd` läuft. Das Gateway nutzt exakt dieselbe
PKCS#11-Schnittstelle wie `pqvault`s `hsm_backend.py` — kein separates
Provisioning nötig, nur ein zusätzlicher, eingeschränkter Zugriffspfad
auf dasselbe Board.

```bash
# Board eingesteckt? Sollte als Smartcard-Reader erscheinen:
pcsc_scan
```

## 2. Vom SoftHSM2-Testpfad auf echte Hardware wechseln

Gegenüber dem SoftHSM2-Testlauf (README.md, Abschnitt "Kompilieren &
Testen") ändert sich nur eine Variable:

```bash
# Statt:
# export GATEWAY_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so

# Jetzt:
# WICHTIG: libsc-hsm-pkcs11.so, NICHT opensc-pkcs11.so — siehe README.md,
# "Offene Punkte" Punkt 7 (OpenSCs sc-hsm-Treiber unterstuetzt kein AES
# fuer das Pico HSM, betrifft encrypt/decrypt/derive_and_*).
export GATEWAY_PKCS11_MODULE=/usr/lib/libsc-hsm-pkcs11.so
export GATEWAY_HSM_PIN="<eure echte User-PIN, aus Vaultwarden>"
```

Die auf dem HSM benötigten Keys (`shared-encryption-key`,
`app-b-signing-key` o. ä., je nach eurer `clients.yaml`) müsst ihr — falls
noch nicht vorhanden — genauso mit `pkcs11-tool` gegen das echte Board
anlegen, wie es README.md für SoftHSM2 zeigt, nur mit
`--module /usr/lib/libsc-hsm-pkcs11.so`. Nutzt dafür
sinnvollerweise **eigene** Key-Labels, getrennt von `pqvault-wrap-key` —
nicht denselben Key doppelt für pqvault und das Gateway verwenden, sonst
verwischt die Trennung, die das ganze Berechtigungsmodell erst sinnvoll
macht.

**Empfehlung:** Erst den kompletten End-to-End-Testlauf aus README.md
Abschnitt 5 einmal gegen SoftHSM2 grün bekommen, danach identisch gegen
das Board wiederholen. Wenn dort etwas abweicht, wisst ihr sofort: Es
liegt an der `pico-hsm`-Firmware selbst (z. B. Mechanismus-Unterstützung),
nicht an Gateway-Logik — siehe README.md, Punkt 6 der offenen Punkte.

## 3. Produktivbetrieb starten

```bash
export GATEWAY_LISTEN_ADDR="0.0.0.0:8443"
export GATEWAY_SERVER_CERT=/etc/hsm-gateway/server.pem
export GATEWAY_SERVER_KEY=/etc/hsm-gateway/server-key.pem
export GATEWAY_CLIENT_CA=/etc/hsm-gateway/client-ca.pem
export GATEWAY_CLIENTS_CONFIG=/etc/hsm-gateway/clients.yaml
export GATEWAY_PKCS11_MODULE=/usr/lib/libsc-hsm-pkcs11.so
export GATEWAY_HSM_PIN="<aus Vaultwarden>"
export GATEWAY_AUDIT_LOG=/var/log/hsm-api-gateway/audit.jsonl
export GATEWAY_MAX_CLIENT_CERT_VALIDITY_DAYS=90
export GATEWAY_CERT_EXPIRY_WARN_DAYS=14

cargo run --release
```

Als systemd-Unit betreiben (Beispiel, an euer Setup anpassen):

```ini
[Unit]
Description=HSM API Gateway
After=network.target

[Service]
EnvironmentFile=/etc/hsm-gateway/gateway.env
ExecStart=/opt/hsm-api-gateway/target/release/hsm-api-gateway
Restart=on-failure
# PIN steht in gateway.env — Datei entsprechend restriktiv schützen
# (chmod 600, root:root oder dedizierter Service-User)

[Install]
WantedBy=multi-user.target
```

---

## 4. Zertifikats-Übersicht (analog zu docs/12-secrets-overview.md)

| Zertifikat/Key | Schützt | Wo gespeichert | Rotation |
|---|---|---|---|
| **Client-CA** (`ca.pem` + `ca-key.pem`) | Vertrauensanker: legitimiert alle Client-Zertifikate | CA-Key offline/getrennt vom Gateway-Host aufbewahren, nur `ca.pem` (öffentlich) liegt als `GATEWAY_CLIENT_CA` auf dem Gateway | Nur bei Kompromittierungsverdacht — Rotation invalidiert **alle** Client-Zertifikate gleichzeitig, größter Einzel-Rotationsfall |
| **Gateway-Server-Zertifikat** (`server.pem`/`server-key.pem`) | Authentizität des Gateways gegenüber Clients | Gateway-Host, `GATEWAY_SERVER_CERT`/`_KEY` | Vor Ablauf (eigene Laufzeit, z. B. 1 Jahr üblich für Server-Zertifikate), erfordert Gateway-Neustart (siehe Abschnitt 6) |
| **Client-Zertifikate** (eins pro angebundenem Produkt) | Identität + Autorisierungs-Anker (CN → `clients.yaml`) | Beim jeweiligen Client-Produkt, nicht auf dem Gateway | Alle `GATEWAY_MAX_CLIENT_CERT_VALIDITY_DAYS` Tage (Default 90), kein Gateway-Neustart nötig |
| **`clients.yaml`** | Wer darf was — kein Zertifikat selbst, aber untrennbar mit der CN-Bindung verknüpft | Gateway-Host, `GATEWAY_CLIENTS_CONFIG` | Bei jeder Änderung der Client-Landschaft (neuer Client, Rechte-Änderung, Sperrung) |

---

## 5. Client-Zertifikat rotieren (Regelfall, alle ~90 Tage)

Kein Gateway-Neustart nötig — das Gateway prüft bei jeder neuen
Verbindung frisch gegen die Client-CA und `clients.yaml`, es merkt sich
keine einzelnen Client-Zertifikate zwischen Verbindungen.

**Ablauf:**

1. **Frühzeitig erkennen:** Sobald ein Client sich mit weniger als
   `GATEWAY_CERT_EXPIRY_WARN_DAYS` Tagen Restlaufzeit meldet, loggt das
   Gateway eine Warnung und schreibt einen `cert_expiring_soon`-Eintrag
   ins Audit-Log (`src/server.rs::enforce_cert_policy`). Praktischer
   Weg, das nicht zu verpassen:

   ```bash
   grep '"status":"cert_expiring_soon"' /var/log/hsm-api-gateway/audit.jsonl \
       | tail -20
   ```

   Empfehlung, analog zu eurem bestehenden Wazuh-Muster
   (`docs/02-firmware-update-security.md`): diese Logzeile als
   Wazuh-Alert einrichten, dann bekommt ihr eine aktive Benachrichtigung
   statt manuell nachzusehen.

2. **Neues Zertifikat ausstellen**, gleicher CN wie das alte (der CN ist
   der Autorisierungs-Schlüssel in `clients.yaml` — er darf sich bei
   einer reinen Rotation nicht ändern, sonst braucht es zusätzlich einen
   `clients.yaml`-Eintrag-Wechsel):

   ```bash
   openssl req -newkey rsa:4096 -nodes -keyout app-a-key-new.pem \
       -out app-a-new.csr -subj "/CN=app-a.internal.example"
   openssl x509 -req -in app-a-new.csr -CA ca.pem -CAkey ca-key.pem \
       -CAcreateserial -days 90 -out app-a-new.pem
   ```

3. **Neues Zertifikat + Key an das Client-Produkt ausrollen** (Weg hängt
   vom jeweiligen Produkt ab — Secret-Store, Config-Deployment, o. ä.).

4. **Altes Zertifikat läuft aus / wird ersetzt** — kein aktiver
   Widerruf nötig für den Regelfall, da es ohnehin abläuft. Sobald der
   Client auf das neue Zertifikat umgestellt hat, kann das alte
   Schlüsselmaterial beim Client-Produkt gelöscht werden.

5. **Verifizieren:** nächste Verbindung des Clients im Audit-Log prüfen
   — sollte keine `cert_expiring_soon`-Warnung mehr auslösen.

**Bewusst kein automatisierter Rotations-Mechanismus in dieser Version**
— das Gateway erkennt und warnt, rotiert aber nicht selbst (kein
ACME-artiges Protokoll für Client-Zertifikate). Für eine größere Anzahl
Clients wäre das ein sinnvoller Ausbauschritt (siehe README.md, Punkt 5
der offenen Punkte — passt thematisch zur ohnehin geplanten
Wazuh-Anbindung).

## 6. Server-Zertifikat rotieren (seltener, betrifft alle Clients gleichzeitig)

Anders als beim Client-Zertifikat lädt das Gateway `GATEWAY_SERVER_CERT`/
`GATEWAY_SERVER_KEY` aktuell nur einmal beim Start (`src/main.rs`) — es
gibt **kein** Hot-Reload. Rotation bedeutet also kurzer Neustart:

```bash
# Neues Server-Zertifikat ausstellen (gleicher CN wie bisher, z. B.
# hsm-gateway.internal.test)
openssl req -newkey rsa:4096 -nodes -keyout server-key-new.pem \
    -out server-new.csr -subj "/CN=hsm-gateway.internal.test"
openssl x509 -req -in server-new.csr -CA ca.pem -CAkey ca-key.pem \
    -CAcreateserial -days 825 -out server-new.pem

# Alte Dateien ersetzen, dann Dienst neu starten
sudo cp server-new.pem /etc/hsm-gateway/server.pem
sudo cp server-key-new.pem /etc/hsm-gateway/server-key.pem
sudo systemctl restart hsm-api-gateway
```

Kurzer Verbindungsabbruch für alle aktiven Clients während des
Neustarts ist hier normal — bei Bedarf in einem Wartungsfenster planen.
Ein echtes Zero-Downtime-Reload (SIGHUP-Handler, der die TLS-Config neu
lädt) ist noch nicht implementiert — sinnvoller nächster Ausbauschritt,
falls der Neustart operativ stört.

## 7. Notfall: Client-Zertifikat kompromittiert

Da es keinen aktiven Widerruf (CRL/OCSP) gibt (bewusste Entscheidung,
siehe README.md und `docs/11-addendum-hsm-gateway.md`), ist der einzige
Sperrmechanismus:

```bash
# Eintrag für den betroffenen CN aus clients.yaml entfernen
vim /etc/hsm-gateway/clients.yaml

# Config wird aktuell nur beim Start geladen -> Neustart nötig
sudo systemctl restart hsm-api-gateway
```

Nach dem Neustart wird das kompromittierte Zertifikat zwar von der CA
weiterhin als gültig anerkannt (TLS-Handshake gelingt), die
Autorisierungsprüfung (`AuthzTable::is_authorized`) lehnt aber jede
Operation ab, weil der CN keinen Eintrag mehr hat — funktional
gleichwertig zu einem Widerruf, nur ohne CRL/OCSP-Infrastruktur.
Danach: neues Zertifikat für den Client mit neuem, separatem CN
ausstellen (nicht denselben CN wiederverwenden, falls das alte
Zertifikat evtl. noch im Umlauf ist) und in `clients.yaml` neu
eintragen.

## 8. Client-CA selbst kompromittiert (worst case)

Größter Rotationsfall — betrifft alle Clients gleichzeitig, analog zum
Firmware-Key-Kompromittierungsfall im Hauptprojekt
(`docs/12-secrets-overview.md`, "neuer Trust-Anker, alle Boards
betroffen"):

1. Neue Client-CA erzeugen
2. **Alle** Client-Zertifikate neu ausstellen (alte CN-Zuordnungen aus
   `clients.yaml` bleiben gültig, nur das Signatur-Vertrauen wechselt)
3. `GATEWAY_CLIENT_CA` auf dem Gateway austauschen, Neustart
4. Jedes Client-Produkt auf sein neues Zertifikat umstellen — bis dahin
   sind alte Zertifikate (alte CA) am Gateway nicht mehr gültig, das
   ist der gewünschte Bruch

Kein automatisierter Ablauf dafür vorgesehen — bei diesem Schadensbild
ist ein manuell koordinierter, geplanter Wechsel ohnehin richtig,
keine Automatisierung, die im Ernstfall selbst wieder Angriffsfläche
wäre.
