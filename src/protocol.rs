//! Wire format: newline-delimited JSON over mTLS.
//! No gRPC/Protobuf, so any product speaking TLS + JSON can connect
//! without a generated client stub.
//!
//! Exactly six operations exist. There are deliberately no variants for
//! object management, PIN/PUK handling, firmware update, or backup/restore.

use crate::config::Operation;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Sign {
        key_label: String,
        mechanism: String,
        data_b64: String,
    },
    Verify {
        key_label: String,
        mechanism: String,
        data_b64: String,
        signature_b64: String,
    },
    Encrypt {
        key_label: String,
        mechanism: String,
        data_b64: String,
    },
    /// `iv_b64` / `integrity_b64` come from the matching `encrypt` response.
    /// AES-CBC needs the exact IV used at encrypt time, and the integrity
    /// signature is verified *before* decrypting (AES-CBC alone gives no
    /// integrity; without this check the decrypt path would be a padding oracle).
    Decrypt {
        key_label: String,
        mechanism: String,
        data_b64: String,
        iv_b64: String,
        integrity_b64: String,
    },
    /// Derive a key from `key_label` and encrypt `data_b64` with it,
    /// atomically in one HSM session. There is intentionally no standalone
    /// "give me the derived key" operation — the derived key never leaves
    /// the HSM.
    ///
    /// `peer_public_key_b64`: counterparty public key for ECDH derive.
    /// Same bytes as passed to `pkcs11-tool --derive -i <file>`.
    DeriveAndEncrypt {
        key_label: String,
        derive_mechanism: String,
        target_mechanism: String,
        peer_public_key_b64: String,
        data_b64: String,
    },
    /// `iv_b64` / `integrity_b64` come from the matching
    /// `derive_and_encrypt` response (see `Decrypt`).
    DeriveAndDecrypt {
        key_label: String,
        derive_mechanism: String,
        target_mechanism: String,
        peer_public_key_b64: String,
        iv_b64: String,
        integrity_b64: String,
        data_b64: String,
    },
}

impl Request {
    pub fn operation(&self) -> Operation {
        match self {
            Request::Sign { .. } => Operation::Sign,
            Request::Verify { .. } => Operation::Verify,
            Request::Encrypt { .. } => Operation::Encrypt,
            Request::Decrypt { .. } => Operation::Decrypt,
            Request::DeriveAndEncrypt { .. } => Operation::DeriveAndEncrypt,
            Request::DeriveAndDecrypt { .. } => Operation::DeriveAndDecrypt,
        }
    }

    /// `Some` only for the derive variants. The value is subject to its own
    /// authorization level (`AuthzTable::is_peer_key_authorized`).
    pub fn peer_public_key_b64(&self) -> Option<&str> {
        match self {
            Request::DeriveAndEncrypt {
                peer_public_key_b64,
                ..
            }
            | Request::DeriveAndDecrypt {
                peer_public_key_b64,
                ..
            } => Some(peer_public_key_b64),
            _ => None,
        }
    }

    /// The integrity-check inputs `(iv_b64, integrity_b64, data_b64)` —
    /// `Some` only for the decrypt variants. Checked in `server.rs` before
    /// the HSM ever decrypts.
    pub fn integrity_input(&self) -> Option<(&str, &str, &str)> {
        match self {
            Request::Decrypt {
                iv_b64,
                integrity_b64,
                data_b64,
                ..
            }
            | Request::DeriveAndDecrypt {
                iv_b64,
                integrity_b64,
                data_b64,
                ..
            } => Some((iv_b64, integrity_b64, data_b64)),
            _ => None,
        }
    }

    pub fn key_label(&self) -> &str {
        match self {
            Request::Sign { key_label, .. }
            | Request::Verify { key_label, .. }
            | Request::Encrypt { key_label, .. }
            | Request::Decrypt { key_label, .. }
            | Request::DeriveAndEncrypt { key_label, .. }
            | Request::DeriveAndDecrypt { key_label, .. } => key_label,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Response {
    /// `iv_b64` / `integrity_b64` are set only on `encrypt` /
    /// `derive_and_encrypt` with AES-CBC: the caller must store them with
    /// the ciphertext and send them back for the matching decrypt call —
    /// without them the ciphertext cannot be decrypted.
    Ok {
        result_b64: Option<String>,
        verified: Option<bool>,
        iv_b64: Option<String>,
        integrity_b64: Option<String>,
    },
    Denied { reason: String },
    Error { message: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_six_ops() {
        let cases = [
            (r#"{"op":"sign","key_label":"k","mechanism":"ecdsa_sha256","data_b64":"eA=="}"#, Operation::Sign),
            (r#"{"op":"verify","key_label":"k","mechanism":"ecdsa_sha256","data_b64":"eA==","signature_b64":"cw=="}"#, Operation::Verify),
            (r#"{"op":"encrypt","key_label":"k","mechanism":"aes_cbc_pad","data_b64":"eA=="}"#, Operation::Encrypt),
            (r#"{"op":"decrypt","key_label":"k","mechanism":"aes_cbc_pad","data_b64":"eA==","iv_b64":"aQ==","integrity_b64":"cw=="}"#, Operation::Decrypt),
            (r#"{"op":"derive_and_encrypt","key_label":"k","derive_mechanism":"ecdh1_derive","target_mechanism":"aes_cbc_pad","peer_public_key_b64":"cA==","data_b64":"eA=="}"#, Operation::DeriveAndEncrypt),
            (r#"{"op":"derive_and_decrypt","key_label":"k","derive_mechanism":"ecdh1_derive","target_mechanism":"aes_cbc_pad","peer_public_key_b64":"cA==","iv_b64":"aQ==","integrity_b64":"cw==","data_b64":"eA=="}"#, Operation::DeriveAndDecrypt),
        ];
        for (json, expected) in cases {
            let req: Request = serde_json::from_str(json).unwrap();
            assert_eq!(req.operation(), expected);
        }
    }

    #[test]
    fn rejects_unknown_op() {
        let res: Result<Request, _> =
            serde_json::from_str(r#"{"op":"generate_key","key_label":"k"}"#);
        assert!(res.is_err());
    }

    #[test]
    fn peer_key_only_on_derive() {
        let sign: Request =
            serde_json::from_str(r#"{"op":"sign","key_label":"k","mechanism":"m","data_b64":"eA=="}"#)
                .unwrap();
        assert_eq!(sign.peer_public_key_b64(), None);
        let derive: Request = serde_json::from_str(
            r#"{"op":"derive_and_encrypt","key_label":"k","derive_mechanism":"d","target_mechanism":"t","peer_public_key_b64":"cA==","data_b64":"eA=="}"#,
        )
        .unwrap();
        assert_eq!(derive.peer_public_key_b64(), Some("cA=="));
    }
}
