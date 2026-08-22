use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::Mutex;

/// Manipulations-*erkennende* (nicht -sichere) Hash-Chain, wie im
/// bestehenden `verify_and_flash.py`-Audit-Log dokumentiert (docs/03,
/// docs/12 "Bekannte Grenzen"). Für echten Löschschutz zusätzlich per
/// Syslog an Wazuh weiterreichen — hier bewusst dasselbe Muster wie im
/// Python-Teil des Projekts übernommen, damit beide Audit-Logs gleich
/// ausgewertet werden können.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuditEntry {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub client_cn: String,
    pub operation: String,
    pub key_label: String,
    pub status: String, // "authorized" | "denied" | "hsm_error"
    pub detail: Option<String>,
    pub prev_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_hash: Option<String>,
}

pub struct AuditLog {
    path: PathBuf,
    lock: Mutex<()>,
}

impl AuditLog {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            lock: Mutex::new(()),
        }
    }

    fn last_hash(&self) -> anyhow::Result<String> {
        if !self.path.exists() {
            return Ok("0".repeat(64));
        }
        let file = std::fs::File::open(&self.path)?;
        let reader = BufReader::new(file);
        let mut last: Option<String> = None;
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let entry: AuditEntry = serde_json::from_str(&line)?;
            last = entry.entry_hash;
        }
        Ok(last.unwrap_or_else(|| "0".repeat(64)))
    }

    /// Schreibt einen Eintrag. Nie fehlschlagen lassen, ohne dass der
    /// Aufrufer es merkt — ein Audit-Log, das still versagt, ist
    /// schlimmer als keins. Der Aufrufer (siehe server.rs) behandelt
    /// einen Fehler hier als Grund, die angefragte Operation
    /// abzulehnen, statt sie unprotokolliert durchzuwinken.
    pub fn append(
        &self,
        client_cn: &str,
        operation: &str,
        key_label: &str,
        status: &str,
        detail: Option<String>,
    ) -> anyhow::Result<()> {
        let _guard = self.lock.lock().unwrap();
        let prev_hash = self.last_hash()?;

        let mut entry = AuditEntry {
            timestamp: chrono::Utc::now(),
            client_cn: client_cn.to_string(),
            operation: operation.to_string(),
            key_label: key_label.to_string(),
            status: status.to_string(),
            detail,
            prev_hash,
            entry_hash: None,
        };

        // Hash über alle Felder außer entry_hash selbst, exakt wie im
        // Python-Pendant (sort_keys + kompaktes JSON für Determinismus).
        let payload = serde_json::to_string(&SerializeForHash::from(&entry))?;
        let hash = format!("{:x}", Sha256::digest(payload.as_bytes()));
        entry.entry_hash = Some(hash);

        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(file, "{}", serde_json::to_string(&entry)?)?;
        Ok(())
    }

    /// Verifiziert die komplette Kette — als periodischer Wazuh-Check
    /// gedacht, analog zu `verify_audit_chain()` in verify_and_flash.py.
    pub fn verify_chain(&self) -> anyhow::Result<bool> {
        if !self.path.exists() {
            return Ok(true);
        }
        let file = std::fs::File::open(&self.path)?;
        let reader = BufReader::new(file);
        let mut expected_prev = "0".repeat(64);

        for (i, line) in reader.lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let mut entry: AuditEntry = serde_json::from_str(&line)?;
            let stored_hash = entry.entry_hash.take().ok_or_else(|| {
                anyhow::anyhow!("Zeile {}: kein entry_hash vorhanden", i + 1)
            })?;
            if entry.prev_hash != expected_prev {
                tracing::error!("Audit-Kette gebrochen bei Zeile {}", i + 1);
                return Ok(false);
            }
            let payload = serde_json::to_string(&SerializeForHash::from(&entry))?;
            let recomputed = format!("{:x}", Sha256::digest(payload.as_bytes()));
            if recomputed != stored_hash {
                tracing::error!("Audit-Eintrag {} wurde nachträglich verändert", i + 1);
                return Ok(false);
            }
            expected_prev = stored_hash;
        }
        Ok(true)
    }
}

/// Hilfstyp, um exakt die Felder zu hashen, die auch beim Verify
/// wieder rekonstruiert werden (ohne entry_hash).
#[derive(Serialize)]
struct SerializeForHash<'a> {
    timestamp: &'a chrono::DateTime<chrono::Utc>,
    client_cn: &'a str,
    operation: &'a str,
    key_label: &'a str,
    status: &'a str,
    detail: &'a Option<String>,
    prev_hash: &'a str,
}

impl<'a> From<&'a AuditEntry> for SerializeForHash<'a> {
    fn from(e: &'a AuditEntry) -> Self {
        Self {
            timestamp: &e.timestamp,
            client_cn: &e.client_cn,
            operation: &e.operation,
            key_label: &e.key_label,
            status: &e.status,
            detail: &e.detail,
            prev_hash: &e.prev_hash,
        }
    }
}
