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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Sign,
    Verify,
    Encrypt,
    Decrypt,
    Derive,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PermissionEntry {
    pub operation: Operation,
    pub key_labels: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClientEntry {
    /// Muss exakt dem CN (Common Name) des mTLS-Client-Zertifikats entsprechen.
    pub cn: String,
    #[serde(default)]
    pub description: String,
    pub permissions: Vec<PermissionEntry>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RawConfig {
    pub clients: Vec<ClientEntry>,
}

/// Aufbereitete, schnell abfragbare Autorisierungstabelle.
/// (cn, operation) -> erlaubte key_labels
#[derive(Debug, Clone, Default)]
pub struct AuthzTable {
    table: HashMap<(String, Operation), Vec<String>>,
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
                table.insert((client.cn.clone(), perm.operation), perm.key_labels);
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
            .map(|labels| labels.iter().any(|l| l == key_label))
            .unwrap_or(false)
    }
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
}
