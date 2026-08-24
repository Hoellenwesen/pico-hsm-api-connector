//! Bewusst simples Wire-Format: newline-delimited JSON über mTLS.
//! Kein gRPC/Protobuf, damit jedes Produkt, das TLS + JSON kann (also
//! praktisch jede Sprache/Plattform), ohne generiertes Client-Stub
//! andocken kann — passend zur Anforderung "universell nutzbare API,
//! die von anderen Software-Produkten angebunden werden kann".

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
    /// `iv_b64`: der IV, der bei der zugehörigen `encrypt`-Antwort in
    /// `iv_b64` zurückgegeben wurde (AES-CBC-Pad braucht für Decrypt
    /// exakt den IV, der beim Encrypt verwendet wurde — der Server
    /// generiert ihn pro Encrypt-Aufruf frisch und gibt ihn deshalb mit
    /// zurück, statt ihn implizit/fest anzunehmen).
    /// `integrity_b64`: die Signatur aus der zugehörigen
    /// `encrypt`-Antwort. Wird **vor** dem Entschlüsseln geprüft — AES-CBC
    /// allein bietet keinen Integritätsschutz, ohne diese Prüfung wäre
    /// jeder Ciphertext unbemerkt manipulierbar (und der Decrypt-Pfad ein
    /// Padding-Orakel).
    Decrypt {
        key_label: String,
        mechanism: String,
        data_b64: String,
        iv_b64: String,
        integrity_b64: String,
    },
    /// Leitet aus `key_label` einen Key ab und verschlüsselt `data_b64`
    /// damit, atomar in einer HSM-Session (siehe hsm.rs für die
    /// Begründung, warum es kein eigenständiges "gib mir den
    /// abgeleiteten Key" mehr gibt).
    ///
    /// `peer_public_key_b64`: der Public Key der Gegenseite für
    /// ECDH1_DERIVE — ohne ihn lässt sich kein Shared Secret berechnen
    /// (siehe pico-hsm/doc/asymmetric-ciphering.md, Abschnitt
    /// ECDH-DERIVE). Format: dieselben Bytes, die auch an
    /// `pkcs11-tool --derive -i <public_key_datei>` übergeben würden.
    DeriveAndEncrypt {
        key_label: String,
        derive_mechanism: String,
        target_mechanism: String,
        peer_public_key_b64: String,
        data_b64: String,
    },
    /// `iv_b64` und `integrity_b64`: aus der zugehörigen
    /// `derive_and_encrypt`-Antwort (siehe `Decrypt`).
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

    /// `Some` nur bei den Derive-Varianten. Der Wert unterliegt einer
    /// eigenen Autorisierungsstufe (`AuthzTable::is_peer_key_authorized`),
    /// siehe die Begründung an `PermissionEntry::peer_public_keys`.
    pub fn peer_public_key_b64(&self) -> Option<&str> {
        match self {
            Request::DeriveAndEncrypt { peer_public_key_b64, .. }
            | Request::DeriveAndDecrypt { peer_public_key_b64, .. } => Some(peer_public_key_b64),
            _ => None,
        }
    }

    /// Die Eingaben der Integritätsprüfung `(iv_b64, integrity_b64,
    /// data_b64)` — `Some` nur bei den Decrypt-Varianten. Wird in
    /// `server.rs::process_line` geprüft, bevor das HSM überhaupt
    /// entschlüsselt.
    pub fn integrity_input(&self) -> Option<(&str, &str, &str)> {
        match self {
            Request::Decrypt { iv_b64, integrity_b64, data_b64, .. }
            | Request::DeriveAndDecrypt { iv_b64, integrity_b64, data_b64, .. } => {
                Some((iv_b64, integrity_b64, data_b64))
            }
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
    /// `iv_b64`: nur bei `encrypt`/`derive_and_encrypt` mit AES-CBC-Pad
    /// gesetzt — der frisch generierte IV dieser einen Operation, muss
    /// vom Aufrufer für den passenden `decrypt`/`derive_and_decrypt`-
    /// Aufruf aufbewahrt und mitgeschickt werden.
    ///
    /// `integrity_b64`: ebenfalls nur bei den Encrypt-Varianten — die
    /// Signatur über Key-Label, IV und Ciphertext (Encrypt-then-Sign).
    /// Zusammen mit `iv_b64` aufbewahren; ohne sie lässt sich der
    /// Ciphertext später nicht mehr entschlüsseln.
    Ok {
        result_b64: Option<String>,
        verified: Option<bool>,
        iv_b64: Option<String>,
        integrity_b64: Option<String>,
    },
    Denied { reason: String },
    Error { message: String },
}
