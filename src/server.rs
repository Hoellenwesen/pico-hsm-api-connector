//! mTLS server: per-request pipeline
//! client-cert CN extract → cert policy → `config.rs` authz → `audit.rs`
//! intent → `hsm.rs` call → audit result.
//!
//! Plus: short-lived-cert policy and Encrypt-then-Sign integrity for AES-CBC.

use crate::audit::{AuditLog, Outcome};
use crate::config::{AuthzTable, Operation};
use crate::hsm::HsmClient;
use crate::protocol::{Request, Response};
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio_rustls::server::TlsStream;
use tracing::{info, warn};
use x509_parser::prelude::*;

/// Domain separator for the integrity payload (Encrypt-then-Sign).
const INTEGRITY_DOMAIN: &[u8] = b"pico-hsm-api-connector/integrity-v1";

/// MVP mechanism allowlist. RSA and the rest are a deferred extension.
const MECH_ECDSA_SHA256: &str = "ecdsa_sha256";
const MECH_AES_CBC_PAD: &str = "aes_cbc_pad";
const MECH_ECDH1_DERIVE: &str = "ecdh1_derive";

pub struct Gateway {
    authz: Arc<AuthzTable>,
    hsm: Arc<HsmClient>,
    audit: Arc<AuditLog>,
    integrity_label: String,
    max_cert_validity_days: i64,
    cert_expiry_warn_days: i64,
}

impl Gateway {
    pub fn new(
        authz: AuthzTable,
        hsm: HsmClient,
        audit: AuditLog,
        integrity_label: String,
        max_cert_validity_days: i64,
        cert_expiry_warn_days: i64,
    ) -> Self {
        Self {
            authz: Arc::new(authz),
            hsm: Arc::new(hsm),
            audit: Arc::new(audit),
            integrity_label,
            max_cert_validity_days,
            cert_expiry_warn_days,
        }
    }

    /// Serve one mTLS connection: enforce the cert policy once, then
    /// process NDJSON lines until EOF or a fatal transport error.
    /// A malformed line yields an `error` response — the connection stays open.
    pub async fn handle_connection(
        self: Arc<Self>,
        stream: TlsStream<tokio::net::TcpStream>,
    ) -> Result<()> {
        let cert = peer_leaf_cert(&stream)?;
        let cn = cert_cn(&cert)?;
        let (validity_days, days_left) = cert_policy_numbers(&cert)?;

        if validity_days > self.max_cert_validity_days {
            warn!(
                cn = %cn,
                validity_days,
                max = self.max_cert_validity_days,
                "rejecting connection: cert_policy_violation"
            );
            // Best-effort audit; the connection is rejected regardless.
            let _ = self.audit.append(
                &cn,
                "connect",
                "",
                Outcome::Denied,
                "cert_policy_violation: validity exceeds maximum",
            );
            anyhow::bail!("cert_policy_violation");
        }
        if days_left <= self.cert_expiry_warn_days {
            warn!(cn = %cn, days_left, "client certificate expiring soon");
            let _ = self.audit.append(
                &cn,
                "connect",
                "",
                Outcome::CertExpiringSoon,
                &format!("expires in {days_left}d"),
            );
        }
        info!(cn = %cn, "client connected");

        let (reader, mut writer) = tokio::io::split(stream);
        let mut lines = BufReader::new(reader).lines();
        while let Some(line) = lines.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }
            let response = self.process_line(&cn, &line).await;
            let mut out = serde_json::to_string(&response).unwrap_or_else(|_| {
                r#"{"status":"error","message":"response serialization failed"}"#.to_string()
            });
            out.push('\n');
            if writer.write_all(out.as_bytes()).await.is_err() {
                break;
            }
        }
        info!(cn = %cn, "client disconnected");
        Ok(())
    }

    async fn process_line(&self, cn: &str, line: &str) -> Response {
        let req: Request = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(e) => return err(format!("invalid request: {e}")),
        };
        let op = req.operation();
        let label = req.key_label().to_string();
        let op_name = op_name(op);

        // 1. Authorization (default-deny, before any PKCS#11 session).
        if !self.authz.is_authorized(cn, op, &label) {
            let reason = format!("denied: {cn} may not run {op_name} on {label:?}");
            let _ = self.audit.append(cn, op_name, &label, Outcome::Denied, &reason);
            return denied(reason);
        }

        // 2. Peer-key allowlist for derive ops.
        let peer_key: Option<Vec<u8>> = match req.peer_public_key_b64() {
            None => None,
            Some(b64) => match B64.decode(b64) {
                Ok(bytes) => {
                    if !self.authz.is_peer_key_authorized(cn, op, &label, b64) {
                        let fp = hex_sha256(&bytes);
                        let reason = format!("denied: peer key {fp} not allowlisted for {label:?}");
                        let _ = self.audit.append(cn, op_name, &label, Outcome::Denied, &reason);
                        return denied(reason);
                    }
                    Some(bytes)
                }
                Err(_) => {
                    let reason = "invalid peer_public_key_b64".to_string();
                    let _ = self.audit.append(cn, op_name, &label, Outcome::Denied, &reason);
                    return denied(reason);
                }
            },
        };

        // 3. Intent (fail-closed: unwritable log rejects the request).
        if let Err(e) = self.audit.append(cn, op_name, &label, Outcome::Intent, "") {
            return err(format!("audit log unavailable, request rejected: {e:#}"));
        }

        // 4. Execute (blocking HSM calls on a blocking thread).
        let result = self.execute(&req, peer_key.as_deref()).await;

        // 5. Closing audit entry.
        match &result {
            Response::Ok { .. } => {
                let _ = self.audit.append(cn, op_name, &label, Outcome::Authorized, "");
            }
            Response::Denied { reason } => {
                let _ = self.audit.append(cn, op_name, &label, Outcome::Denied, reason);
            }
            Response::Error { message } => {
                let _ = self.audit.append(cn, op_name, &label, Outcome::Error, message);
            }
        }
        result
    }

    async fn execute(&self, req: &Request, peer_key: Option<&[u8]>) -> Response {
        match req {
            Request::Sign { key_label, mechanism, data_b64 } => {
                if mechanism != MECH_ECDSA_SHA256 {
                    return err(format!("unsupported sign mechanism {mechanism:?} (MVP: {MECH_ECDSA_SHA256})"));
                }
                let data = match b64(data_b64) {
                    Ok(d) => d,
                    Err(e) => return e,
                };
                let hsm = Arc::clone(&self.hsm);
                let label = key_label.clone();
                match tokio::task::spawn_blocking(move || hsm.sign_ecdsa_sha256(&label, &data)).await {
                    Ok(Ok(sig)) => ok_result(B64.encode(sig), None),
                    Ok(Err(e)) => err(format!("sign failed: {e:#}")),
                    Err(e) => err(format!("sign task failed: {e}")),
                }
            }
            Request::Verify { key_label, mechanism, data_b64, signature_b64 } => {
                if mechanism != MECH_ECDSA_SHA256 {
                    return err(format!("unsupported verify mechanism {mechanism:?} (MVP: {MECH_ECDSA_SHA256})"));
                }
                let (data, sig) = match (b64(data_b64), b64(signature_b64)) {
                    (Ok(d), Ok(s)) => (d, s),
                    _ => return err("invalid data_b64/signature_b64".to_string()),
                };
                let hsm = Arc::clone(&self.hsm);
                let label = key_label.clone();
                match tokio::task::spawn_blocking(move || hsm.verify_ecdsa_sha256(&label, &data, &sig)).await {
                    Ok(Ok(valid)) => Response::Ok { result_b64: None, verified: Some(valid), iv_b64: None, integrity_b64: None },
                    Ok(Err(e)) => err(format!("verify failed: {e:#}")),
                    Err(e) => err(format!("verify task failed: {e}")),
                }
            }
            Request::Encrypt { key_label, mechanism, data_b64 } => {
                if mechanism != MECH_AES_CBC_PAD {
                    return err(format!("unsupported encrypt mechanism {mechanism:?} (MVP: {MECH_AES_CBC_PAD})"));
                }
                let data = match b64(data_b64) {
                    Ok(d) => d,
                    Err(e) => return e,
                };
                let hsm = Arc::clone(&self.hsm);
                let label = key_label.clone();
                let ct_iv = tokio::task::spawn_blocking(move || hsm.encrypt_aes_cbc_pad(&label, &data)).await;
                match ct_iv {
                    Ok(Ok((iv, ct))) => self.seal_response(key_label, &iv, &ct),
                    Ok(Err(e)) => err(format!("encrypt failed: {e:#}")),
                    Err(e) => err(format!("encrypt task failed: {e}")),
                }
            }
            Request::Decrypt { key_label, mechanism, .. } => {
                if mechanism != MECH_AES_CBC_PAD {
                    return err(format!("unsupported decrypt mechanism {mechanism:?} (MVP: {MECH_AES_CBC_PAD})"));
                }
                let Some((iv_b64, integrity_b64, data_b64)) = req.integrity_input() else {
                    return err("decrypt request missing integrity fields".to_string());
                };
                let (ct, iv, integ) = match (b64(data_b64), b64(iv_b64), b64(integrity_b64)) {
                    (Ok(a), Ok(b), Ok(c)) => (a, b, c),
                    _ => return err("invalid data_b64/iv_b64/integrity_b64".to_string()),
                };
                // Integrity BEFORE decrypt (no padding oracle).
                if !self.check_integrity(key_label, &iv, &ct, &integ) {
                    return denied("integrity check failed, ciphertext rejected".to_string());
                }
                let hsm = Arc::clone(&self.hsm);
                let label = key_label.clone();
                match tokio::task::spawn_blocking(move || hsm.decrypt_aes_cbc_pad(&label, &ct, &iv)).await {
                    Ok(Ok(pt)) => ok_result(B64.encode(pt), None),
                    Ok(Err(e)) => err(format!("decrypt failed: {e:#}")),
                    Err(e) => err(format!("decrypt task failed: {e}")),
                }
            }
            Request::DeriveAndEncrypt { key_label, derive_mechanism, target_mechanism, data_b64, .. } => {
                if derive_mechanism != MECH_ECDH1_DERIVE || target_mechanism != MECH_AES_CBC_PAD {
                    return err(format!("unsupported derive pair {derive_mechanism:?}+{target_mechanism:?} (MVP: {MECH_ECDH1_DERIVE}+{MECH_AES_CBC_PAD})"));
                }
                let data = match b64(data_b64) {
                    Ok(d) => d,
                    Err(e) => return e,
                };
                let peer = peer_key.unwrap_or_default().to_vec();
                let hsm = Arc::clone(&self.hsm);
                let label = key_label.clone();
                match tokio::task::spawn_blocking(move || hsm.derive_and_encrypt(&label, &peer, &data)).await {
                    Ok(Ok((iv, ct))) => self.seal_response(key_label, &iv, &ct),
                    Ok(Err(e)) => err(format!("derive_and_encrypt failed: {e:#}")),
                    Err(e) => err(format!("derive task failed: {e}")),
                }
            }
            Request::DeriveAndDecrypt { key_label, derive_mechanism, target_mechanism, .. } => {
                if derive_mechanism != MECH_ECDH1_DERIVE || target_mechanism != MECH_AES_CBC_PAD {
                    return err(format!("unsupported derive pair {derive_mechanism:?}+{target_mechanism:?} (MVP: {MECH_ECDH1_DERIVE}+{MECH_AES_CBC_PAD})"));
                }
                let Some((iv_b64, integrity_b64, data_b64)) = req.integrity_input() else {
                    return err("derive_and_decrypt request missing integrity fields".to_string());
                };
                let (ct, iv, integ) = match (b64(data_b64), b64(iv_b64), b64(integrity_b64)) {
                    (Ok(a), Ok(b), Ok(c)) => (a, b, c),
                    _ => return err("invalid data_b64/iv_b64/integrity_b64".to_string()),
                };
                if !self.check_integrity(key_label, &iv, &ct, &integ) {
                    return denied("integrity check failed, ciphertext rejected".to_string());
                }
                let peer = peer_key.unwrap_or_default().to_vec();
                let hsm = Arc::clone(&self.hsm);
                let label = key_label.clone();
                match tokio::task::spawn_blocking(move || hsm.derive_and_decrypt(&label, &peer, &ct, &iv)).await {
                    Ok(Ok(pt)) => ok_result(B64.encode(pt), None),
                    Ok(Err(e)) => err(format!("derive_and_decrypt failed: {e:#}")),
                    Err(e) => err(format!("derive task failed: {e}")),
                }
            }
        }
    }

    /// Attach `iv_b64` + Encrypt-then-Sign `integrity_b64` to an encrypt result.
    /// A signing failure is a hard error (fail-closed, no unauthenticated ciphertext out).
    fn seal_response(&self, key_label: &str, iv: &[u8], ct: &[u8]) -> Response {
        let payload = integrity_payload(key_label, iv, ct);
        match self.hsm.sign_ecdsa_sha256(&self.integrity_label, &payload) {
            Ok(sig) => Response::Ok {
                result_b64: Some(B64.encode(ct)),
                verified: None,
                iv_b64: Some(B64.encode(iv)),
                integrity_b64: Some(B64.encode(sig)),
            },
            Err(e) => err(format!("integrity signing failed: {e:#}")),
        }
    }

    /// Recompute the payload and verify the ECDSA signature.
    /// Any error (including an invalid signature) means "reject".
    fn check_integrity(&self, key_label: &str, iv: &[u8], ct: &[u8], sig: &[u8]) -> bool {
        let payload = integrity_payload(key_label, iv, ct);
        self.hsm
            .verify_ecdsa_sha256(&self.integrity_label, &payload, sig)
            .unwrap_or(false)
    }
}

/// Canonical integrity payload: domain separator + key label + IV +
/// ciphertext, each length-prefixed so field boundaries cannot shift.
/// The bound key label prevents cross-key replay of a ciphertext.
pub fn integrity_payload(key_label: &str, iv: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        INTEGRITY_DOMAIN.len() + key_label.len() + iv.len() + ciphertext.len() + 32,
    );
    for part in [INTEGRITY_DOMAIN, key_label.as_bytes(), iv, ciphertext] {
        out.extend_from_slice(&(part.len() as u64).to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

fn ok_result(result_b64: String, _unused: Option<()>) -> Response {
    Response::Ok {
        result_b64: Some(result_b64),
        verified: None,
        iv_b64: None,
        integrity_b64: None,
    }
}

fn denied(reason: String) -> Response {
    Response::Denied { reason }
}

fn err(message: String) -> Response {
    Response::Error { message }
}

fn b64(s: &str) -> Result<Vec<u8>, Response> {
    B64.decode(s).map_err(|_| err("invalid base64 input".to_string()))
}

fn op_name(op: Operation) -> &'static str {
    match op {
        Operation::Sign => "sign",
        Operation::Verify => "verify",
        Operation::Encrypt => "encrypt",
        Operation::Decrypt => "decrypt",
        Operation::DeriveAndEncrypt => "derive_and_encrypt",
        Operation::DeriveAndDecrypt => "derive_and_decrypt",
    }
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn peer_leaf_cert(stream: &TlsStream<tokio::net::TcpStream>) -> Result<X509Certificate<'_>> {
    let certs = stream
        .get_ref()
        .1
        .peer_certificates()
        .ok_or_else(|| anyhow!("no client certificate presented"))?;
    let leaf = certs
        .first()
        .ok_or_else(|| anyhow!("empty client certificate chain"))?;
    let (_, cert) =
        X509Certificate::from_der(leaf.as_ref()).context("cannot parse client certificate")?;
    Ok(cert)
}

fn cert_cn(cert: &X509Certificate<'_>) -> Result<String> {
    let cn_attr = cert
        .subject()
        .iter_common_name()
        .next()
        .ok_or_else(|| anyhow!("client certificate has no CN"))?;
    let cn = std::str::from_utf8(cn_attr.as_slice())
        .context("client certificate CN is not UTF-8")?
        .to_string();
    if cn.trim().is_empty() {
        anyhow::bail!("client certificate CN is empty");
    }
    Ok(cn)
}

/// Returns `(total_validity_days, days_until_expiry)`.
fn cert_policy_numbers(cert: &X509Certificate<'_>) -> Result<(i64, i64)> {
    let validity = cert.validity();
    let not_before = DateTime::<Utc>::from_timestamp(validity.not_before.timestamp(), 0)
        .ok_or_else(|| anyhow!("client certificate not_before out of range"))?;
    let not_after = DateTime::<Utc>::from_timestamp(validity.not_after.timestamp(), 0)
        .ok_or_else(|| anyhow!("client certificate not_after out of range"))?;
    let validity_days = (not_after - not_before).num_days();
    let days_left = (not_after - Utc::now()).num_days();
    Ok((validity_days, days_left))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integrity_payload_binds_label_iv_and_ct() {
        let a = integrity_payload("k1", b"0123456789abcdef", b"ciphertext");
        let b = integrity_payload("k2", b"0123456789abcdef", b"ciphertext");
        let c = integrity_payload("k1", b"0123456789abcdef", b"other");
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert!(a.windows(INTEGRITY_DOMAIN.len()).any(|w| w == INTEGRITY_DOMAIN));
    }
}
