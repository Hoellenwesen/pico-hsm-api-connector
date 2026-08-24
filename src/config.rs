use base64::Engine;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

/// Die von diesem Gateway unterstützten Kryptooperationen.
///
/// Bewusst eine geschlossene, kleine Liste: keine generische
/// PKCS#11-Passthrough-Operation, kein Objekt-Management (create/
/// destroy/find-all), kein PIN-Reset, kein Firmware-Bezug. Wer eine
/// dieser Operationen braucht, muss weiterhin den physischen
/// BOOTSEL-/opensc-Pfad direkt am Host nutzen (siehe README.md).
/// Die Namen entsprechen exakt den `op`-Werten im Wire-Format
/// (`protocol.rs`), damit `clients.yaml` und Request 1:1 lesbar
/// zusammenpassen.
///
/// `DeriveAndEncrypt` und `DeriveAndDecrypt` sind bewusst **getrennte**
/// Operationen: Wrappen und Entwrappen sind zueinander inverse
/// Faehigkeiten. Ein Client, der Schluesselmaterial nur einpacken soll,
/// darf daraus nicht automatisch das Recht bekommen, vorhandenes
/// Material wieder auszupacken (Least Privilege). Als Nebeneffekt
/// unterscheidet auch das Audit-Log beide Faelle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Sign,
    Verify,
    Encrypt,
    Decrypt,
    DeriveAndEncrypt,
    DeriveAndDecrypt,
}

impl Operation {
    /// Braucht diese Operation einen Peer-Public-Key (ECDH1_DERIVE)?
    pub fn uses_peer_public_key(self) -> bool {
        matches!(self, Operation::DeriveAndEncrypt | Operation::DeriveAndDecrypt)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PermissionEntry {
    pub operation: Operation,
    pub key_labels: Vec<String>,
    /// Nur für `derive_and_encrypt`/`derive_and_decrypt`: Base64-kodierte
    /// Public Keys der Gegenseite, die für ECDH1_DERIVE verwendet werden
    /// dürfen.
    ///
    /// SICHERHEITSKRITISCH: Ohne diese Allowlist könnte ein Client den
    /// Peer-Public-Key frei wählen. Da ECDH symmetrisch ist
    /// (`d_hsm · Q_client == d_client · Q_hsm`), könnte er den
    /// abgeleiteten AES-Key dann selbst nachrechnen — die Hardware-
    /// Bindung des Wrapping-Keys wäre wertlos. Zusätzlich verhindert
    /// die Allowlist Invalid-Curve-Angriffe, mit denen sich über viele
    /// Anfragen der private Schlüssel aus dem HSM rekonstruieren lässt
    /// (NIST SP 800-56A Rev. 3, §5.6.2.3.2). Deshalb: nur explizit
    /// hinterlegte, vom Betreiber geprüfte Peer-Keys sind zulässig.
    #[serde(default)]
    pub peer_public_keys: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClientEntry {
    /// Muss exakt dem CN (Common Name) des mTLS-Client-Zertifikats entsprechen.
    pub cn: String,
    /// Nur Dokumentation für Menschen, die `clients.yaml` lesen — wird
    /// im Code bewusst nicht ausgewertet.
    #[serde(default)]
    #[allow(dead_code)]
    pub description: String,
    pub permissions: Vec<PermissionEntry>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RawConfig {
    pub clients: Vec<ClientEntry>,
}

/// Was ein Client für eine bestimmte Operation darf.
#[derive(Debug, Clone, Default)]
struct PermissionRule {
    key_labels: Vec<String>,
    /// Bereits dekodierte Peer-Public-Keys (nur bei den Derive-
    /// Operationen befüllt, dort dann garantiert nicht leer — siehe
    /// `decode_peer_public_keys`).
    peer_public_keys: Vec<Vec<u8>>,
}

/// Aufbereitete, schnell abfragbare Autorisierungstabelle.
/// (cn, operation) -> erlaubte key_labels (+ Peer-Keys bei derive)
#[derive(Debug, Clone, Default)]
pub struct AuthzTable {
    table: HashMap<(String, Operation), PermissionRule>,
}

impl AuthzTable {
    pub fn from_raw(raw: RawConfig) -> anyhow::Result<Self> {
        let mut table = HashMap::new();
        for client in raw.clients {
            if client.permissions.is_empty() {
                anyhow::bail!(
                    "Client '{}' hat keine Permissions definiert — \
                     entweder Eintrag entfernen oder mindestens eine \
                     Operation zulassen. Ein leerer Eintrag wäre \
                     mehrdeutig (alles erlaubt vs. nichts erlaubt).",
                    client.cn
                );
            }
            for perm in client.permissions {
                if perm.key_labels.is_empty() {
                    anyhow::bail!(
                        "Client '{}', Operation '{:?}': key_labels ist leer. \
                         Explizit mindestens ein Label angeben — kein \
                         impliziter Wildcard-Zugriff auf alle Keys.",
                        client.cn,
                        perm.operation
                    );
                }
                let peer_public_keys =
                    decode_peer_public_keys(&client.cn, perm.operation, &perm.peer_public_keys)?;

                table.insert(
                    (client.cn.clone(), perm.operation),
                    PermissionRule {
                        key_labels: perm.key_labels,
                        peer_public_keys,
                    },
                );
            }
        }
        Ok(Self { table })
    }

    pub fn load_from_file(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Config {:?} nicht lesbar: {e}", path))?;
        let raw: RawConfig = serde_yaml::from_str(&content)?;
        Self::from_raw(raw)
    }

    /// Kernprüfung: darf `cn` die Operation `op` auf `key_label` ausführen?
    /// Default-Deny — jeder nicht explizit erlaubte Fall wird abgelehnt.
    pub fn is_authorized(&self, cn: &str, op: Operation, key_label: &str) -> bool {
        self.table
            .get(&(cn.to_string(), op))
            .map(|rule| rule.key_labels.iter().any(|l| l == key_label))
            .unwrap_or(false)
    }

    /// Zweite Autorisierungsstufe für ECDH1_DERIVE: Ist genau dieser
    /// Peer-Public-Key für `cn` freigegeben? Default-Deny, gleiches
    /// Prinzip wie `is_authorized`.
    ///
    /// Kein konstantzeitiger Vergleich nötig — Public Keys sind
    /// per Definition öffentlich, hier wird kein Geheimnis verglichen.
    pub fn is_peer_key_authorized(&self, cn: &str, op: Operation, peer_key: &[u8]) -> bool {
        self.table
            .get(&(cn.to_string(), op))
            .map(|rule| rule.peer_public_keys.iter().any(|k| k == peer_key))
            .unwrap_or(false)
    }
}

impl AuthzTable {
    /// Taucht dieses Key-Label in irgendeiner Client-Permission auf?
    ///
    /// Dient dem Startup-Check in `main.rs`: Der Integritaetsschluessel
    /// (Encrypt-then-Sign) ist gateway-intern. Duerfte ein Client ihn
    /// ueber die regulaere `sign`-Operation benutzen, koennte er
    /// beliebige Integritaets-Signaturen selbst erzeugen und damit
    /// manipulierte Ciphertexts als echt ausgeben — der Schutz waere
    /// wertlos.
    pub fn mentions_key_label(&self, label: &str) -> bool {
        self.table
            .values()
            .any(|rule| rule.key_labels.iter().any(|l| l == label))
    }
}

/// Validiert und dekodiert die `peer_public_keys` eines Permission-
/// Eintrags. `derive` verlangt zwingend mindestens einen Eintrag; alle
/// anderen Operationen dürfen keinen haben (sonst entstünde der
/// Eindruck, dort würde etwas eingeschränkt, was gar nicht geprüft wird).
fn decode_peer_public_keys(
    cn: &str,
    operation: Operation,
    raw_keys: &[String],
) -> anyhow::Result<Vec<Vec<u8>>> {
    if !operation.uses_peer_public_key() {
        if !raw_keys.is_empty() {
            anyhow::bail!(
                "Client '{cn}', Operation '{operation:?}': peer_public_keys ist \
                 nur für derive_and_encrypt/derive_and_decrypt zulässig. Bei \
                 allen anderen Operationen wird kein Peer-Key verwendet — der \
                 Eintrag hier waere wirkungslos und damit irrefuehrend."
            );
        }
        return Ok(Vec::new());
    }

    if raw_keys.is_empty() {
        anyhow::bail!(
            "Client '{cn}', Operation '{operation:?}': peer_public_keys ist leer. \
             Fuer ECDH1_DERIVE muessen die zulaessigen Public Keys der \
             Gegenseite explizit hinterlegt werden — ein frei waehlbarer \
             Peer-Key erlaubt es dem Client, den abgeleiteten Key selbst \
             nachzurechnen (die Hardware-Bindung waere wertlos) und oeffnet \
             Invalid-Curve-Angriffe auf den privaten Schluessel im HSM."
        );
    }

    let b64 = base64::engine::general_purpose::STANDARD;
    let mut decoded = Vec::with_capacity(raw_keys.len());
    for (i, key) in raw_keys.iter().enumerate() {
        let bytes = b64.decode(key).map_err(|e| {
            anyhow::anyhow!(
                "Client '{cn}', Operation '{operation:?}': peer_public_keys[{i}] ist \
                 kein gueltiges Base64: {e}"
            )
        })?;
        if bytes.is_empty() {
            anyhow::bail!(
                "Client '{cn}', Operation '{operation:?}': peer_public_keys[{i}] \
                 dekodiert zu 0 Bytes."
            );
        }
        decoded.push(bytes);
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> RawConfig {
        serde_yaml::from_str(
            r#"
clients:
  - cn: "app-a"
    permissions:
      - operation: encrypt
        key_labels: ["k1"]
      - operation: decrypt
        key_labels: ["k1"]
"#,
        )
        .unwrap()
    }

    #[test]
    fn allows_configured_combination() {
        let table = AuthzTable::from_raw(sample()).unwrap();
        assert!(table.is_authorized("app-a", Operation::Encrypt, "k1"));
    }

    #[test]
    fn denies_wrong_key_label() {
        let table = AuthzTable::from_raw(sample()).unwrap();
        assert!(!table.is_authorized("app-a", Operation::Encrypt, "some-other-key"));
    }

    #[test]
    fn denies_wrong_operation() {
        let table = AuthzTable::from_raw(sample()).unwrap();
        assert!(!table.is_authorized("app-a", Operation::Sign, "k1"));
    }

    #[test]
    fn denies_unknown_client() {
        let table = AuthzTable::from_raw(sample()).unwrap();
        assert!(!table.is_authorized("unknown-client", Operation::Encrypt, "k1"));
    }

    #[test]
    fn rejects_empty_key_labels_at_load_time() {
        let raw: RawConfig = serde_yaml::from_str(
            r#"
clients:
  - cn: "app-a"
    permissions:
      - operation: encrypt
        key_labels: []
"#,
        )
        .unwrap();
        assert!(AuthzTable::from_raw(raw).is_err());
    }

    // -- Peer-Public-Key-Allowlist fuer ECDH1_DERIVE --
    // Ohne diese Allowlist koennte ein Client den abgeleiteten Key selbst
    // nachrechnen und ueber Invalid-Curve-Anfragen den privaten Schluessel
    // aus dem HSM extrahieren.

    /// "peer-key-1" / "peer-key-2" als Base64, damit die Tests lesbar
    /// bleiben — der Code interessiert sich nur fuer die Bytes.
    fn derive_sample() -> RawConfig {
        serde_yaml::from_str(
            r#"
clients:
  - cn: "app-c"
    permissions:
      - operation: derive_and_encrypt
        key_labels: ["dk"]
        peer_public_keys: ["cGVlci1rZXktMQ==", "cGVlci1rZXktMg=="]
"#,
        )
        .unwrap()
    }

    #[test]
    fn allows_configured_peer_key() {
        let table = AuthzTable::from_raw(derive_sample()).unwrap();
        assert!(table.is_peer_key_authorized("app-c", Operation::DeriveAndEncrypt, b"peer-key-1"));
        assert!(table.is_peer_key_authorized("app-c", Operation::DeriveAndEncrypt, b"peer-key-2"));
    }

    /// Kernabwehr: ein selbst erzeugter Peer-Key (der Angriff aus dem
    /// Security-Review) wird abgelehnt.
    #[test]
    fn denies_attacker_supplied_peer_key() {
        let table = AuthzTable::from_raw(derive_sample()).unwrap();
        assert!(!table.is_peer_key_authorized(
            "app-c",
            Operation::DeriveAndEncrypt,
            b"attacker-generated-key"
        ));
    }

    #[test]
    fn denies_peer_key_for_unknown_client() {
        let table = AuthzTable::from_raw(derive_sample()).unwrap();
        assert!(!table.is_peer_key_authorized("unknown", Operation::DeriveAndEncrypt, b"peer-key-1"));
    }

    /// Least Privilege: Wrap-Recht darf kein Unwrap-Recht implizieren.
    #[test]
    fn derive_encrypt_does_not_grant_derive_decrypt() {
        let table = AuthzTable::from_raw(derive_sample()).unwrap();
        assert!(table.is_authorized("app-c", Operation::DeriveAndEncrypt, "dk"));
        assert!(!table.is_authorized("app-c", Operation::DeriveAndDecrypt, "dk"));
        assert!(!table.is_peer_key_authorized("app-c", Operation::DeriveAndDecrypt, b"peer-key-1"));
    }

    #[test]
    fn rejects_derive_without_peer_public_keys() {
        let raw: RawConfig = serde_yaml::from_str(
            r#"
clients:
  - cn: "app-c"
    permissions:
      - operation: derive_and_decrypt
        key_labels: ["dk"]
"#,
        )
        .unwrap();
        assert!(AuthzTable::from_raw(raw).is_err());
    }

    #[test]
    fn rejects_peer_public_keys_on_non_derive_operation() {
        let raw: RawConfig = serde_yaml::from_str(
            r#"
clients:
  - cn: "app-a"
    permissions:
      - operation: encrypt
        key_labels: ["k1"]
        peer_public_keys: ["cGVlci1rZXktMQ=="]
"#,
        )
        .unwrap();
        assert!(AuthzTable::from_raw(raw).is_err());
    }

    // -- Guard fuer den Integritaetsschluessel (Encrypt-then-Sign) --

    #[test]
    fn detects_integrity_key_granted_to_a_client() {
        let table = AuthzTable::from_raw(sample()).unwrap();
        assert!(table.mentions_key_label("k1"));
        assert!(!table.mentions_key_label("gateway-integrity-key"));
    }

    /// Die Beispiel-Config darf den in README/docs empfohlenen
    /// Integritaetsschluessel keinem Client freigeben — sonst koennte er
    /// eigene Integritaets-Signaturen erzeugen.
    #[test]
    fn example_config_does_not_grant_integrity_key() {
        let path = Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/config/clients.example.yaml"
        ));
        let table = AuthzTable::load_from_file(path).unwrap();
        assert!(!table.mentions_key_label("gateway-integrity-key"));
    }

    /// Die mitgelieferte Beispiel-Config muss ladbar bleiben — README.md
    /// Abschnitt 5 startet den Quickstart direkt damit. Faengt ab, dass
    /// neue Validierungsregeln die Beispieldatei unbrauchbar machen.
    #[test]
    fn shipped_example_config_loads() {
        let path = Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/config/clients.example.yaml"
        ));
        AuthzTable::load_from_file(path).expect("config/clients.example.yaml muss ladbar sein");
    }

    #[test]
    fn rejects_malformed_base64_peer_key() {
        let raw: RawConfig = serde_yaml::from_str(
            r#"
clients:
  - cn: "app-c"
    permissions:
      - operation: derive_and_encrypt
        key_labels: ["dk"]
        peer_public_keys: ["nicht!gueltiges!base64"]
"#,
        )
        .unwrap();
        assert!(AuthzTable::from_raw(raw).is_err());
    }
}
