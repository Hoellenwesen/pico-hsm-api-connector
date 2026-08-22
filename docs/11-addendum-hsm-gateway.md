# Ergänzung zu docs/11-threat-model.md: HSM API Gateway

Zum Einfügen in die bestehende Struktur von `docs/11-threat-model.md`,
nach Einführung des `hsm-api-gateway`-Diensts (siehe eigenes README dort).
Ändert nichts an den bestehenden Profilen A–D, ergänzt sie.

---

## Ergänzung: Schutzgüter

Zur bestehenden Tabelle hinzufügen:

| Gut | Wo | Kritikalität |
|---|---|---|
| Client-CA (mTLS-Vertrauensanker des Gateways) | `GATEWAY_CLIENT_CA`, Dateisystem des Gateway-Hosts | Hoch — jeder, der ein von dieser CA signiertes Zertifikat besitzt, gilt dem Gateway als legitimer, per `clients.yaml` autorisierter Client |
| Gateway-Server-Key (`GATEWAY_SERVER_KEY`) | Dateisystem des Gateway-Hosts | Mittel-Hoch — Kompromiss erlaubt Impersonation des Gateways gegenüber Clients (MITM), nicht aber direkten HSM-Zugriff |
| `clients.yaml` (Autorisierungstabelle) | `GATEWAY_CLIENTS_CONFIG` | Hoch — definiert, welcher Client welche Operation auf welchem Key-Label darf; Manipulation = Rechteausweitung ohne neues Zertifikat |
| HSM-PIN im Gateway-Prozessspeicher | Laufzeit-Speicher des Gateway-Prozesses (aus Vaultwarden injiziert, wie `PQVAULT_HSM_PIN`) | Hoch — identisch kritisch wie bei pqvault selbst, nur jetzt zusätzlich im Gateway-Prozess vorhanden |

---

## Ergänzung: Angreiferprofil E — Netzwerk-Angreifer im internen LAN

Jemand mit Zugriff auf euer internes Netz (kompromittiertes IoT-Gerät,
kompromittierter anderer Homelab-Dienst, böswilliger Gast im WLAN), aber
**ohne** Zugriff auf den Host, auf dem das Gateway selbst läuft, und
**ohne** physischen Zugriff aufs HSM. Bisher deckte Profil A nur den
Host ab, auf dem `pqvault`/`verify_and_flash.py` läuft — das Gateway
öffnet dieselbe Angriffsklasse jetzt zusätzlich für jeden Punkt im
internen Netz, nicht nur für den einen Host.

**Wirksame Maßnahmen:**
- mTLS ist Pflicht, kein Fallback auf unauthentifizierte Verbindungen
  (`src/main.rs`: `WebPkiClientVerifier`, kein optionaler Client-Auth) —
  ein Angreifer ohne gültiges Client-Zertifikat kommt nicht einmal bis
  zum TLS-Handshake durch.
- Default-Deny-Autorisierung pro (Client-CN, Operation, Key-Label) —
  selbst ein gestohlenes, aber falsch zugeordnetes Zertifikat (z. B. das
  von App A) kann keine Operationen anfordern, die nicht explizit für
  genau diesen CN freigegeben sind.
- Verwaltungsoperationen (Objekt-Management, PIN-Reset, Firmware,
  Backup) sind im Gateway-Protokoll strukturell nicht vorhanden — ein
  kompromittiertes Client-Zertifikat kann bestenfalls die ihm erlaubten
  Krypto-Operationen missbrauchen, nie die Verwaltungsebene erreichen.
- Hash-Chain-Audit-Log protokolliert jede Anfrage inkl. abgelehnter —
  Missbrauch eines gültigen Zertifikats ist nachträglich erkennbar.

**Bewusste Lücke:** Wie bei Profil A gibt es aktuell keine
Rate-Limitierung pro Client — ein kompromittiertes, aber korrekt
autorisiertes Client-Zertifikat (z. B. App A mit `encrypt`-Recht) kann
beliebig viele `encrypt`-Anfragen stellen, solange das Zertifikat gültig
ist. Gleiche offene Punkt-Kategorie wie in `docs/10-feature-roadmap.md`,
"Nutzungs-Metriken" — jetzt zusätzlich relevant für mehrere Clients statt
nur den einen pqvault-Host.

**Neue Lücke gegenüber Profil A:** Ein kompromittierter *anderer*
interner Host mit gestohlenem, gültigem Client-Zertifikat kann Anfragen
stellen, ohne dass ihr das am Gateway-Host selbst bemerkt (anders als
bei Profil A, wo der Host mit dem HSM identisch ist). Zertifikats-
Widerruf (CRL/OCSP) ist im aktuellen Entwurf nicht vorgesehen — bei
Verdacht auf ein kompromittiertes Client-Zertifikat bleibt aktuell nur:
Eintrag aus `clients.yaml` entfernen und Gateway neu starten/Config neu
laden. Kein automatisierter Sperrmechanismus.

---

## Ergänzung: Maßnahmen-zu-Bedrohung-Matrix

| Maßnahme | Wirkt gegen | Wirkt NICHT gegen |
|---|---|---|
| mTLS-Pflicht ohne Fallback (hsm-api-gateway) | Unauthentifizierten Netzwerkzugriff (E) | Missbrauch eines gültigen, aber gestohlenen Client-Zertifikats innerhalb seiner erlaubten Rechte |
| Default-Deny + Key-Scoping pro Client (hsm-api-gateway) | Rechteausweitung über die eigene Zertifikats-Identität hinaus (E) | Missbrauch innerhalb der eigenen erlaubten Rechte |
| Strukturell fehlende Verwaltungs-Endpunkte (hsm-api-gateway) | Erreichen der HSM-Verwaltungsebene über das Netz (E) | — |
| Hash-Chain-Audit-Log (hsm-api-gateway) | Nachträgliche Erkennung von Missbrauch (E) | Verhindert Missbrauch nicht in Echtzeit |

---

## Ergänzung: Offene Punkte

Zur bestehenden Liste hinzufügen:

4. ~~Zertifikats-Widerruf für das Gateway einrichten~~ **Umgesetzt:**
   Statt CRL/OCSP erzwingt das Gateway kurze Zertifikatslaufzeiten direkt
   am Verbindungsaufbau (`src/server.rs::enforce_cert_policy`):
   - Verbindungen mit Client-Zertifikaten, deren Gesamtgültigkeit
     `GATEWAY_MAX_CLIENT_CERT_VALIDITY_DAYS` (Default 90 Tage)
     überschreitet, werden hart abgelehnt und als
     `cert_policy_violation` auditiert.
   - Client-Zertifikate mit weniger als `GATEWAY_CERT_EXPIRY_WARN_DAYS`
     (Default 14 Tage) Restlaufzeit lösen eine Warnung aus
     (`cert_expiring_soon`, Log + Audit), noch bevor sie hart ablaufen.
   - Bewusst weiterhin **kein** aktives Widerrufen bereits gültiger,
     aber kompromittierter Zertifikate (kein CRL/OCSP) — bei Verdacht
     bleibt der Weg über `clients.yaml` + Neustart. Für die aktuelle
     Homelab-Größenordnung (wenige Clients, 90-Tage-Rotation) eine
     bewusste Abwägung; bei mehr Clients oder höherem Bedrohungsniveau
     nachrüsten.
5. Rate-Limitierung pro Client-CN am Gateway (verwandt mit dem
   bestehenden Punkt 3 zu Profil A, jetzt aber pro Client statt nur
   global)
6. Gateway selbst ins `docs/07-physical-security.md`-Modell einordnen,
   falls es auf demselben Host wie das USB-HSM läuft (dann greift
   physische Absicherung des Hosts automatisch mit) — falls auf einem
   separaten Host: eigene Absicherung dieses Hosts nötig
7. **Konsolidierung abgeschlossen (siehe `MIGRATION.md`):** Der bisher
   separate `pico-hsm-daemon` (Python, lokaler Unix-Socket) ist
   abgelöst — das Gateway ist jetzt der einzige PKCS#11-Konsument im
   gesamten Projekt. Das ändert Profil A (Remote-Angreifer auf den Host):
   dessen Angriffsfläche war zuvor "Host + lokaler Daemon", jetzt
   "Host + lokaler mTLS-Client des Gateways" — ein kompromittierter
   Host mit gültigem lokalem Client-Zertifikat kann weiterhin beliebig
   viele autorisierte Operationen anfordern (unverändert gegenüber
   vorher, siehe "Bewusste Lücke" bei Profil A), aber jetzt einheitlich
   über dasselbe Auth-/Audit-Modell wie entfernte Clients statt über
   ein separates Token-System. Vorteil: nur noch eine Autorisierungs-
   und Audit-Implementierung zu pflegen und zu prüfen, statt zwei
   parallele mit potenziell unterschiedlichem Reifegrad.
