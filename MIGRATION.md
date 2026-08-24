# Migration: pico-hsm-daemon (Python) → hsm-api-gateway (Rust)

Dieses Dokument beschreibt die Konsolidierung der beiden bisher parallel
existierenden Schnittstellen zum Pico HSM auf **eine** Schnittstelle:
dieses Gateway. Der bisherige lokale `pico-hsm-daemon` (Unix-Socket,
Python) wird **außer Betrieb genommen**.

## Warum

Beide Schnittstellen sprachen unabhängig voneinander PKCS#11 mit
demselben physischen HSM — zwei Prozesse mit eigenen, unkoordinierten
Sessions auf denselben Slot. Eine einzige Schnittstelle vermeidet dieses
Risiko und reduziert die Angriffsfläche/Wartungslast auf einen Dienst.

## Was sich ändert

| | bisher (`pico-hsm-daemon`) | neu (`hsm-api-gateway`) |
|---|---|---|
| Transport | Unix-Domain-Socket, lokal | mTLS über TCP, auch für lokale Clients (z. B. `127.0.0.1:8443`) |
| Auth | Token pro Client, Hash in `clients.yaml` | Client-Zertifikat (mTLS), CN in `clients.yaml` |
| Operationen | Sign, Verify, Encrypt, Decrypt, WrapKey, UnwrapKey, GenerateKeyPair, FindObjects | Sign, Verify, Encrypt, Decrypt, DeriveAndEncrypt, DeriveAndDecrypt |
| Autorisierung Derive | — | `derive_and_encrypt` und `derive_and_decrypt` sind getrennte Permissions, jeweils mit eigener Peer-Key-Allowlist |

## Bewusster Funktionsverlust

Das Gateway implementiert **absichtlich kein Objekt-Management** (siehe
README.md, "Bewusst nicht enthalten") — das war schon vor dieser
Konsolidierung eine explizite Sicherheitsgrenze, keine Lücke, die diese
Migration nachträglich einreißt. Konkret entfallen gegenüber dem
Python-Daemon:

- **`GenerateKeyPair`** — Schlüssel künftig weiterhin manuell am Host
  erzeugen: `pkcs11-tool --module ... --login --pin ... --keypairgen ...`
  (wie in `README.md` des Hauptprojekts, Schritt 6, beschrieben)
- **`WrapKey` / `UnwrapKey`** — für den Fall "symmetrischen Key mit einem
  hardwaregebundenen Key schützen" gibt es im Gateway das funktional
  ähnliche, aber bewusst enger gefasste Paar `DeriveAndEncrypt` /
  `DeriveAndDecrypt` (Ableitung + Ver-/Entschlüsselung atomar in einer
  Session, der abgeleitete Key verlässt das HSM nie). Prüfen, ob euer
  bisheriger Wrap/Unwrap-Anwendungsfall sich darauf abbilden lässt —
  siehe Abschnitt unten.
- **`FindObjects`** — kein Objekt-Listing über die Netzwerk-API. Falls
  ein Produkt zur Laufzeit wissen muss, welche Key-Labels existieren:
  diese Information gehört ins jeweilige Produkt selbst (z. B. als feste
  Konfiguration), nicht in eine Laufzeit-Abfrage ans HSM.

Falls eines dieser fehlenden Features für ein Produkt zwingend nötig ist:
das ist ein bewusster Erweiterungspunkt für später (siehe README.md,
"Offene Punkte"), keine Sackgasse — aber kein automatischer Teil dieser
Konsolidierung.

## Wrap/Unwrap → DeriveAndEncrypt/DeriveAndDecrypt abbilden

Bisher (`pico-hsm-daemon`, bzw. das ursprüngliche `hsm_backend.py`):

```python
wrapped = client.wrap_key(key_label="pqvault-wrap-key", plaintext_key=aes_key)
```

Intern lief das ohnehin schon über "Key ableiten (ECDH1_DERIVE), dann
damit wrappen" — funktional identisch zu `DeriveAndEncrypt` mit
`derive_mechanism=ecdh1_derive`. Neu, über das Gateway:

```json
{"op": "derive_and_encrypt", "key_label": "pqvault-wrap-key", "derive_mechanism": "ecdh1_derive", "target_mechanism": "aes_cbc_pad", "peer_public_key_b64": "<Public Key der Gegenseite>", "data_b64": "<AES-Key base64>"}
```

Die Antwort enthält neben `result_b64` auch `iv_b64` und
`integrity_b64` — beide müssen zusammen mit dem Ciphertext gespeichert
und beim Entwrappen mitgegeben werden. Gegenüber dem alten
`wrap_key()`, das nur einen Blob zurückgab, ist das ein
Datenmodell-Unterschied: Wer bisher nur den Wrapped-Key persistiert hat,
braucht jetzt zwei zusätzliche Felder im Speicherformat.

`peer_public_key_b64` ist Pflicht — `ECDH1_DERIVE` berechnet das Shared
Secret aus dem privaten Key im HSM und dem Public Key der Gegenseite,
ohne ihn lässt sich kein Shared Secret berechnen (siehe README.md,
Abschnitt "Wire-Format"). Die Antwort enthält zusätzlich `iv_b64` (der
frisch generierte AES-CBC-IV) — für `derive_and_decrypt` muss dieser
Wert mitgeschickt werden.

**Wichtig gegenüber dem alten `wrap_key()`:** Der Peer-Public-Key ist
kein frei wählbarer Parameter. Er muss vorab in `clients.yaml` unter
`peer_public_keys` freigegeben sein, sonst antwortet das Gateway mit
`"status":"denied"`. Hintergrund und Erzeugung des Werts:
README.md, Abschnitt "Peer-Public-Key-Allowlist". Plant das bei der
Migration mit ein — ein Produkt, das den Peer-Key bisher zur Laufzeit
selbst bestimmt hat, braucht hier einen Config-Eintrag pro verwendetem
Peer-Key.

Ein vollständiges, lauffähiges Python-Beispiel liegt in
`examples/local_client_example.py`.

## Lokale Clients: mTLS statt Unix-Socket

Produkte, die bisher lokal über den Unix-Socket mit dem Python-Daemon
sprachen, verbinden sich jetzt genau wie entfernte Clients — per mTLS,
nur eben gegen `127.0.0.1` (oder `localhost`) statt eine entfernte
Adresse:

```bash
export GATEWAY_LISTEN_ADDR="127.0.0.1:8443"   # oder 0.0.0.0, falls auch
                                                # entfernte Clients bedient werden
```

**Jeder lokale Client braucht ein eigenes Client-Zertifikat**, genau wie
entfernte Clients (siehe README.md, Abschnitt 4, zur Zertifikatserzeugung
mit eurer internen CA). Es gibt keine Sonderbehandlung für "lokal" auf
Protokollebene — bewusst so, damit Autorisierung und Audit-Log für alle
Clients einheitlich funktionieren, unabhängig davon, ob sie auf demselben
Host oder im Netzwerk laufen.

## Schritt-für-Schritt-Migration

1. **Gateway produktiv aufsetzen** (falls noch nicht geschehen): siehe
   README.md, Abschnitt "Setup".
2. **Für jedes Produkt, das bisher den Python-Daemon nutzte:** ein
   Client-Zertifikat ausstellen (CN = eindeutiger Produktname), Eintrag
   in `clients.yaml` mit den benötigten `(operation, key_label)`-Paaren
   anlegen (Least Privilege, wie bisher bei den Daemon-Tokens).
3. **Produktcode umstellen:** Unix-Socket-Client (`pico_hsm_client.py`)
   durch mTLS-Client ersetzen — siehe
   `examples/local_client_example.py` als Vorlage.
4. **Parallelbetrieb testen:** Gateway und Python-Daemon können
   übergangsweise gleichzeitig laufen, **aber nicht dauerhaft** — beide
   öffnen unabhängige PKCS#11-Sessions auf denselben Slot, das birgt
   genau das Locking-Risiko, das die Konsolidierung eigentlich auflösen
   soll. Migration pro Produkt zügig abschließen, dann Daemon stoppen.
5. **Python-Daemon deaktivieren:**
   ```bash
   sudo systemctl disable --now pico-hsm-daemon
   ```
   Das `pico-hsm-daemon`-Repository/Paket kann danach archiviert werden
   (siehe dortige `DEPRECATED.md`).
6. **`docs/11-threat-model.md`** aktualisieren — der Python-Daemon fällt
   als eigenständige Komponente weg, das Gateway wird zum alleinigen
   Zugriffspunkt (lokal wie remote). Bereits vorbereitet in
   `docs/11-addendum-hsm-gateway.md`, dort den Hinweis ergänzen, dass
   jetzt auch lokale Clients darüber laufen.

## Bekannte Einschränkung nach der Migration

Jede PKCS#11-Operation im Gateway öffnet aktuell eine **eigene, neue
Session** (`HsmClient::open_session()` in `src/hsm.rs`) statt eine
persistente Session wiederzuverwenden. Bei deutlich höherer Last durch
mehr (jetzt auch lokale) Clients kann das ein Performance-Faktor werden
(Login-Overhead pro Request). Funktional ist das unproblematisch, aber
falls die Request-Rate nach der Konsolidierung spürbar steigt, lohnt sich
ein Blick auf Session-Pooling als spätere Optimierung — nicht Teil dieser
Migration, hier nur als Beobachtungspunkt festgehalten.
