//! Client authorization table: default-deny on `(operation, key_label)`,
//! keyed by mTLS client-certificate CN.
//!
//! Load-time validation (hard start errors, no silent wildcards):
//! - every permission needs at least one non-empty `key_labels` entry
//! - `derive_and_*` entries REQUIRE a non-empty `peer_public_keys` allowlist
//!   (every value must be valid base64); missing list = start error
//! - `peer_public_keys` on any non-derive operation = start error
//!   (it would be silently ineffective and therefore misleading)
//! - the gateway integrity key label must not appear anywhere —
//!   a client with that label could forge integrity signatures
//! - duplicate CNs are rejected

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

/// The six operations this gateway exposes. Nothing else may be added
/// without also adding an `hsm.rs` implementation, a `protocol.rs`
/// variant, and an authz path — that friction is intentional.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Sign,
    Verify,
    Encrypt,
    Decrypt,
    DeriveAndEncrypt,
    DeriveAndDecrypt,
}

#[derive(Debug, Deserialize)]
struct FileConfig {
    #[serde(default)]
    clients: Vec<ClientEntry>,
}

#[derive(Debug, Deserialize)]
struct ClientEntry {
    cn: String,
    #[allow(dead_code)]
    description: Option<String>,
    #[serde(default)]
    permissions: Vec<PermissionEntry>,
}

#[derive(Debug, Deserialize)]
struct PermissionEntry {
    operation: Operation,
    #[serde(default)]
    key_labels: Vec<String>,
    #[serde(default)]
    peer_public_keys: Option<Vec<String>>,
}

/// In-memory authorization table built once at startup.
#[derive(Debug, Default)]
pub struct AuthzTable {
    /// (cn, operation, key_label) grants.
    grants: HashSet<(String, Operation, String)>,
    /// (cn, operation, key_label) -> allowed peer keys (derive ops only).
    peer_keys: HashMap<(String, Operation, String), HashSet<String>>,
}

impl AuthzTable {
    /// Load + validate `clients.yaml`. `integrity_key_label` is the dedicated
    /// ECDSA integrity key — it must not be granted to any client.
    pub fn load(path: &Path, integrity_key_label: &str) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read clients config {path:?}"))?;
        Self::from_str(&text, integrity_key_label)
            .with_context(|| format!("invalid clients config {path:?}"))
    }

    fn from_str(text: &str, integrity_key_label: &str) -> Result<Self> {
        let cfg: FileConfig = serde_yaml::from_str(text).context("YAML parse error")?;
        let mut table = AuthzTable::default();
        let mut seen_cn: HashSet<String> = HashSet::new();

        for client in &cfg.clients {
            let cn = client.cn.trim();
            if cn.is_empty() {
                bail!("client entry with empty cn");
            }
            if !seen_cn.insert(cn.to_string()) {
                bail!("duplicate client cn {cn:?}");
            }
            for perm in &client.permissions {
                table.add_permission(cn, perm, integrity_key_label)?;
            }
        }
        Ok(table)
    }

    fn add_permission(
        &mut self,
        cn: &str,
        perm: &PermissionEntry,
        integrity_key_label: &str,
    ) -> Result<()> {
        let op = perm.operation;
        let is_derive = matches!(
            op,
            Operation::DeriveAndEncrypt | Operation::DeriveAndDecrypt
        );

        if perm.key_labels.is_empty() {
            bail!("{cn} {op:?}: key_labels must not be empty");
        }
        let mut labels: HashSet<String> = HashSet::new();
        for label in &perm.key_labels {
            let label = label.trim();
            if label.is_empty() {
                bail!("{cn} {op:?}: key_labels contains an empty label");
            }
            if label == integrity_key_label {
                bail!("{cn} {op:?}: key label {label:?} is the gateway integrity key and must never be granted to clients");
            }
            if !labels.insert(label.to_string()) {
                bail!("{cn} {op:?}: duplicate key label {label:?}");
            }
        }

        match (&perm.peer_public_keys, is_derive) {
            (None, false) => {}
            (Some(_), true) => {}
            (Some(_), false) => {
                bail!("{cn} {op:?}: peer_public_keys is only allowed on derive operations")
            }
            (None, true) => {
                bail!("{cn} {op:?}: peer_public_keys allowlist is mandatory for derive operations (no wildcard)")
            }
        }

        if is_derive {
            let raw = perm.peer_public_keys.as_ref().expect("checked above");
            if raw.is_empty() {
                bail!("{cn} {op:?}: peer_public_keys must not be empty");
            }
            let mut vetted: HashSet<String> = HashSet::new();
            for key in raw {
                let key = key.trim();
                if key.is_empty() {
                    bail!("{cn} {op:?}: peer_public_keys contains an empty entry");
                }
                if B64.decode(key).is_err() {
                    bail!("{cn} {op:?}: peer_public_keys contains an entry that is not valid base64");
                }
                if !vetted.insert(key.to_string()) {
                    bail!("{cn} {op:?}: duplicate peer public key entry");
                }
            }
            for label in &labels {
                let grant = (cn.to_string(), op, label.clone());
                self.grants.insert(grant.clone());
                self.peer_keys.insert(grant, vetted.clone());
            }
        } else {
            for label in &labels {
                self.grants
                    .insert((cn.to_string(), op, label.clone()));
            }
        }
        Ok(())
    }

    /// Default-deny: unknown clients / operations / labels return false.
    pub fn is_authorized(&self, cn: &str, op: Operation, key_label: &str) -> bool {
        self.grants
            .contains(&(cn.to_string(), op, key_label.to_string()))
    }

    /// Peer-key check for derive ops. Returns false for unknown
    /// combinations AND for non-derive ops (which never have an allowlist).
    pub fn is_peer_key_authorized(
        &self,
        cn: &str,
        op: Operation,
        key_label: &str,
        peer_key_b64: &str,
    ) -> bool {
        self.peer_keys
            .get(&(cn.to_string(), op, key_label.to_string()))
            .is_some_and(|set| set.contains(peer_key_b64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INTEGRITY: &str = "gateway-integrity-key";

    fn table(yaml: &str) -> Result<AuthzTable> {
        AuthzTable::from_str(yaml, INTEGRITY)
    }

    #[test]
    fn allows_configured_combination() {
        let t = table(
            r#"
clients:
  - cn: "app-a"
    permissions:
      - operation: encrypt
        key_labels: ["k1"]
"#,
        )
        .unwrap();
        assert!(t.is_authorized("app-a", Operation::Encrypt, "k1"));
    }

    #[test]
    fn denies_wrong_key_label() {
        let t = table(
            r#"
clients:
  - cn: "app-a"
    permissions:
      - operation: encrypt
        key_labels: ["k1"]
"#,
        )
        .unwrap();
        assert!(!t.is_authorized("app-a", Operation::Encrypt, "other"));
    }

    #[test]
    fn denies_wrong_operation() {
        let t = table(
            r#"
clients:
  - cn: "app-a"
    permissions:
      - operation: encrypt
        key_labels: ["k1"]
"#,
        )
        .unwrap();
        assert!(!t.is_authorized("app-a", Operation::Decrypt, "k1"));
    }

    #[test]
    fn denies_unknown_client() {
        let t = table(
            r#"
clients:
  - cn: "app-a"
    permissions:
      - operation: sign
        key_labels: ["k1"]
"#,
        )
        .unwrap();
        assert!(!t.is_authorized("nobody", Operation::Sign, "k1"));
    }

    #[test]
    fn rejects_empty_key_labels_at_load_time() {
        let res = table(
            r#"
clients:
  - cn: "app-a"
    permissions:
      - operation: sign
        key_labels: []
"#,
        );
        assert!(res.is_err());
    }

    #[test]
    fn rejects_derive_without_allowlist() {
        let res = table(
            r#"
clients:
  - cn: "app-c"
    permissions:
      - operation: derive_and_encrypt
        key_labels: ["dk"]
"#,
        );
        assert!(res.is_err());
    }

    #[test]
    fn rejects_allowlist_on_non_derive() {
        let res = table(
            r#"
clients:
  - cn: "app-a"
    permissions:
      - operation: encrypt
        key_labels: ["k1"]
        peer_public_keys: ["cA=="]
"#,
        );
        assert!(res.is_err());
    }

    #[test]
    fn rejects_integrity_label() {
        let res = table(
            r#"
clients:
  - cn: "app-a"
    permissions:
      - operation: sign
        key_labels: ["gateway-integrity-key"]
"#,
        );
        assert!(res.is_err());
    }

    #[test]
    fn rejects_non_base64_peer_key() {
        let res = table(
            r#"
clients:
  - cn: "app-c"
    permissions:
      - operation: derive_and_encrypt
        key_labels: ["dk"]
        peer_public_keys: ["!!!not-base64!!!"]
"#,
        );
        assert!(res.is_err());
    }

    #[test]
    fn peer_key_allowlist_enforced() {
        let t = table(
            r#"
clients:
  - cn: "app-c"
    permissions:
      - operation: derive_and_encrypt
        key_labels: ["dk"]
        peer_public_keys: ["cA=="]
"#,
        )
        .unwrap();
        assert!(t.is_authorized("app-c", Operation::DeriveAndEncrypt, "dk"));
        assert!(t.is_peer_key_authorized("app-c", Operation::DeriveAndEncrypt, "dk", "cA=="));
        assert!(!t.is_peer_key_authorized("app-c", Operation::DeriveAndEncrypt, "dk", "other=="));
    }

    #[test]
    fn loads_example_template() {
        let t = AuthzTable::load(
            std::path::Path::new("config/clients.example.yaml"),
            INTEGRITY,
        )
        .unwrap();
        assert!(t.is_authorized("app-a.internal.example", Operation::Encrypt, "shared-encryption-key"));
        assert!(!t.is_authorized("app-a.internal.example", Operation::Sign, "shared-encryption-key"));
    }
}
