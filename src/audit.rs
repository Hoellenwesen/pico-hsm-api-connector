//! Hash-chained audit log (JSONL, append-only).
//!
//! Fail-closed: if an entry cannot be written (permissions, full disk,
//! read-only mount), the caller must reject the request and perform NO
//! HSM operation. Every fallible method returns `Result` for exactly
//! this reason.
//!
//! Two-phase protocol per request:
//! 1. `intent` — written BEFORE touching the HSM
//! 2. `authorized` / `denied` / `error` — written AFTER the outcome is known
//! A lone `intent` without a closing entry means the operation was
//! interrupted and its outcome is UNKNOWN (by design, not a bug).

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Outcome of a single audit entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Intent,
    Authorized,
    Denied,
    Error,
    CertExpiringSoon,
}

/// One audit entry. `hash_b64` chains to the previous entry:
/// `SHA256(prev_hash || canonical_json_without_hashes)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub ts: String,
    pub cn: String,
    pub operation: String,
    pub key_label: String,
    pub outcome: Outcome,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
    pub prev_hash_b64: String,
    pub hash_b64: String,
}

const GENESIS: &str = "GENESIS";

fn entry_hash(prev_hash_b64: &str, ts: &str, cn: &str, op: &str, label: &str, outcome: Outcome, detail: &str) -> String {
    let outcome_str = serde_json::to_string(&outcome).unwrap_or_default();
    // Length-prefixed canonical encoding so field boundaries cannot shift.
    let mut h = Sha256::new();
    for part in [prev_hash_b64, ts, cn, op, label, &outcome_str, detail] {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part.as_bytes());
    }
    B64.encode(h.finalize())
}

/// Append-only audit log. Interior mutability via `Mutex` so handlers can
/// share it; the lock is held only for the duration of one append+flush.
pub struct AuditLog {
    path: PathBuf,
    file: Mutex<std::fs::File>,
    last_hash_b64: Mutex<String>,
}

impl AuditLog {
    /// Open (or create) the log. Verifies the existing chain first —
    /// a tampered log refuses to open rather than silently extending.
    pub fn open(path: &Path) -> Result<Self> {
        let last = verify_chain(path).with_context(|| format!("audit chain broken in {path:?}"))?;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("cannot open audit log {path:?}"))?;
        Ok(Self {
            path: path.to_path_buf(),
            file: Mutex::new(file),
            last_hash_b64: Mutex::new(last),
        })
    }

    /// Append one entry and flush (fail-closed on any I/O error).
    pub fn append(
        &self,
        cn: &str,
        operation: &str,
        key_label: &str,
        outcome: Outcome,
        detail: &str,
    ) -> Result<()> {
        let ts = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let prev = self.last_hash_b64.lock().expect("audit mutex poisoned").clone();
        let hash = entry_hash(&prev, &ts, cn, operation, key_label, outcome, detail);
        let entry = Entry {
            ts,
            cn: cn.to_string(),
            operation: operation.to_string(),
            key_label: key_label.to_string(),
            outcome,
            detail: detail.to_string(),
            prev_hash_b64: prev,
            hash_b64: hash.clone(),
        };
        let mut line = serde_json::to_string(&entry).context("audit serialize error")?;
        line.push('\n');
        {
            let mut file = self.file.lock().expect("audit mutex poisoned");
            file.write_all(line.as_bytes())
                .with_context(|| format!("cannot write audit log {:?}", self.path))?;
            file.flush()
                .with_context(|| format!("cannot flush audit log {:?}", self.path))?;
        }
        *self.last_hash_b64.lock().expect("audit mutex poisoned") = hash;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Verify the whole chain. Returns the last hash (`GENESIS` for a
/// missing/empty log). Errors on any gap, reorder, or tampering.
pub fn verify_chain(path: &Path) -> Result<String> {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(GENESIS.to_string()),
        Err(e) => bail!("cannot open audit log {path:?}: {e}"),
    };
    let mut expected_prev = GENESIS.to_string();
    let mut count: u64 = 0;
    for (idx, line) in BufReader::new(file).lines().enumerate() {
        let line = line.with_context(|| format!("cannot read audit log {path:?} line {idx}"))?;
        if line.trim().is_empty() {
            continue;
        }
        let entry: Entry = serde_json::from_str(&line)
            .with_context(|| format!("audit log {path:?} line {idx}: invalid JSON"))?;
        if entry.prev_hash_b64 != expected_prev {
            bail!("audit log {path:?} line {idx}: chain gap (prev hash mismatch)");
        }
        let recomputed = entry_hash(
            &entry.prev_hash_b64,
            &entry.ts,
            &entry.cn,
            &entry.operation,
            &entry.key_label,
            entry.outcome,
            &entry.detail,
        );
        if recomputed != entry.hash_b64 {
            bail!("audit log {path:?} line {idx}: entry hash mismatch (tampered?)");
        }
        expected_prev = entry.hash_b64.clone();
        count += 1;
    }
    let _ = count;
    Ok(expected_prev)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn tmp_path(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("pico-hsm-audit-test-{name}-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn roundtrip_intent_then_authorized() {
        let path = tmp_path("roundtrip");
        let log = AuditLog::open(&path).unwrap();
        log.append("cn-a", "sign", "k1", Outcome::Intent, "").unwrap();
        log.append("cn-a", "sign", "k1", Outcome::Authorized, "").unwrap();
        drop(log);
        let last = verify_chain(&path).unwrap();
        assert_ne!(last, GENESIS);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn detects_tampering() {
        let path = tmp_path("tamper");
        let log = AuditLog::open(&path).unwrap();
        log.append("cn-a", "encrypt", "k1", Outcome::Intent, "").unwrap();
        drop(log);
        // Flip a byte in the stored line.
        let mut text = std::fs::read_to_string(&path).unwrap();
        text = text.replace("cn-a", "cn-b");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(text.as_bytes()).unwrap();
        assert!(verify_chain(&path).is_err());
        // And re-opening must refuse as well.
        assert!(AuditLog::open(&path).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn detects_gap_after_truncation() {
        let path = tmp_path("gap");
        let log = AuditLog::open(&path).unwrap();
        log.append("cn-a", "sign", "k1", Outcome::Intent, "").unwrap();
        log.append("cn-a", "sign", "k1", Outcome::Authorized, "").unwrap();
        drop(log);
        // Keep only the second line -> prev hash points at nothing.
        let text = std::fs::read_to_string(&path).unwrap();
        let mut lines = text.lines();
        let _first = lines.next().unwrap();
        let second = lines.next().unwrap().to_string();
        std::fs::write(&path, format!("{second}\n")).unwrap();
        assert!(verify_chain(&path).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_file_is_empty_chain() {
        let path = tmp_path("missing");
        assert_eq!(verify_chain(&path).unwrap(), GENESIS);
    }

    #[test]
    fn open_unwritable_path_fails() {
        // Opening a directory as the log file must fail (fail-closed).
        let dir = std::env::temp_dir();
        assert!(AuditLog::open(&dir).is_err());
    }
}
