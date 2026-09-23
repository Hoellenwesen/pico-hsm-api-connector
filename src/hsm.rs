//! Narrow PKCS#11 layer.
//!
//! Deliberately exposes ONLY sign/verify/encrypt/decrypt/derive. There is
//! no function for object creation/deletion, PIN changes, SO operations,
//! or firmware access — not because `cryptoki` could not do it, but so an
//! accidental management-feature addition stands out (new method + new
//! call site in `server.rs` + new `Operation` in `config.rs`).
//!
//! MVP mechanism scope: ECDSA-SHA256, AES-CBC-PAD, ECDH1_DERIVE→AES.
//! RSA variants are a deferred extension (see plan).
//!
//! NOTE: compiled against the `cryptoki` 0.12 API; hardware execution
//! (especially `CKD_SHA256_KDF` in `sc-hsm-embedded`) is still unverified —
//! see the USB smoke test in the plan.

use anyhow::{anyhow, Context, Result};
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as Pkcs11Error, RvError};
use cryptoki::mechanism::{elliptic_curve::Ecdh1DeriveParams, elliptic_curve::EcKdf, Mechanism};
use cryptoki::object::{Attribute, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use std::path::Path;
use zeroize::Zeroizing;

/// Domain separation for the ECDH KDF (`shared_data` / OtherInfo).
/// Non-empty on purpose: `EcKdf::sha256()` requires `shared_data`, and an
/// empty slice would produce a non-NULL pointer with length 0 (PKCS#11-widric).
/// A fixed context string is also good KDF hygiene.
pub const KDF_SHARED_DATA: &[u8] = b"pico-hsm-api-connector/kdf-v1";

/// Length in bytes of the AES key derived via ECDH (AES-256).
pub const DERIVED_AES_LEN: u32 = 32;

pub struct HsmClient {
    pkcs11: Pkcs11,
    slot: Slot,
    pin: Zeroizing<String>,
}

impl HsmClient {
    /// `module_path`: PKCS#11 module, e.g. `/usr/lib/libsc-hsm-pkcs11.so`
    /// in production (NOT `opensc-pkcs11.so` — its sc-hsm driver has no AES),
    /// or SoftHSM2 for local E2E tests.
    pub fn connect(module_path: &Path, pin: String) -> Result<Self> {
        let pkcs11 = Pkcs11::new(module_path)
            .with_context(|| format!("cannot load PKCS#11 module {module_path:?}"))?;
        pkcs11
            .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .context("PKCS#11 C_Initialize failed")?;

        let slots = pkcs11.get_slots_with_token()?;
        let slot = *slots
            .first()
            .ok_or_else(|| anyhow!("no HSM token found — is the Pico plugged in?"))?;

        Ok(Self {
            pkcs11,
            slot,
            pin: Zeroizing::new(pin),
        })
    }

    fn open_session(&self) -> Result<Session> {
        let session = self.pkcs11.open_rw_session(self.slot)?;
        let pin = AuthPin::new(self.pin.as_str().into());
        session.login(UserType::User, Some(&pin))?;
        Ok(session)
    }

    /// Find exactly ONE object with the given label AND object class.
    /// Ambiguity (0 or >1 hits) is an error — never guess which key was meant.
    ///
    /// The class filter is mandatory: `pkcs11-tool --keypairgen --label "X"`
    /// creates a private AND a public key object with the same label
    /// (see pico-hsm/doc/usage.md). Without the filter the search returns
    /// two hits and aborts — sign/verify/derive would be unusable against
    /// real keypairs. It also guarantees an operation never lands on a
    /// wrong-typed object by accident.
    fn find_key_by_label(
        &self,
        session: &Session,
        label: &str,
        class: ObjectClass,
    ) -> Result<ObjectHandle> {
        let template = vec![
            Attribute::Class(class),
            Attribute::Label(label.as_bytes().to_vec()),
        ];
        let mut found = session.find_objects(&template)?;
        match (found.len(), found.pop()) {
            (1, Some(handle)) => Ok(handle),
            (0, _) => bail_key(label, "not found"),
            _ => bail_key(label, "ambiguous (multiple objects with this label+class)"),
        }
    }

    fn private_key(&self, session: &Session, label: &str) -> Result<ObjectHandle> {
        self.find_key_by_label(session, label, ObjectClass::PRIVATE_KEY)
    }

    fn public_key(&self, session: &Session, label: &str) -> Result<ObjectHandle> {
        self.find_key_by_label(session, label, ObjectClass::PUBLIC_KEY)
    }

    fn secret_key(&self, session: &Session, label: &str) -> Result<ObjectHandle> {
        self.find_key_by_label(session, label, ObjectClass::SECRET_KEY)
    }

    /// Raw ECDSA-SHA256 sign. Returns the signature bytes.
    pub fn sign_ecdsa_sha256(&self, label: &str, data: &[u8]) -> Result<Vec<u8>> {
        let session = self.open_session()?;
        let key = self.private_key(&session, label)?;
        let sig = session
            .sign(&Mechanism::EcdsaSha256, key, data)
            .with_context(|| format!("HSM sign failed for {label:?}"))?;
        Ok(sig)
    }

    /// Returns `Ok(true)` / `Ok(false)` for valid / invalid signatures.
    /// Only a signature-mismatch maps to `false`; every other PKCS#11
    /// error (token removed, mechanism unsupported, …) is a hard error.
    pub fn verify_ecdsa_sha256(
        &self,
        label: &str,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        let session = self.open_session()?;
        let key = self.public_key(&session, label)?;
        match session.verify(&Mechanism::EcdsaSha256, key, data, signature) {
            Ok(()) => Ok(true),
            Err(Pkcs11Error::Pkcs11(RvError::SignatureInvalid, _)) => Ok(false),
            Err(e) => Err(e).with_context(|| format!("HSM verify failed for {label:?}")),
        }
    }

    /// Encrypt with AES-CBC-PAD. The IV is freshly drawn from the HSM RNG
    /// per call and returned alongside the ciphertext.
    pub fn encrypt_aes_cbc_pad(
        &self,
        label: &str,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let session = self.open_session()?;
        let key = self.secret_key(&session, label)?;
        let iv = self.random_iv(&session)?;
        let ct = session
            .encrypt(&Mechanism::AesCbcPad(iv), key, plaintext)
            .with_context(|| format!("HSM encrypt failed for {label:?}"))?;
        Ok((iv.to_vec(), ct))
    }

    pub fn decrypt_aes_cbc_pad(
        &self,
        label: &str,
        ciphertext: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>> {
        let iv: [u8; 16] = iv
            .try_into()
            .map_err(|_| anyhow!("decrypt: iv must be 16 bytes"))?;
        let session = self.open_session()?;
        let key = self.secret_key(&session, label)?;
        let pt = session
            .decrypt(&Mechanism::AesCbcPad(iv), key, ciphertext)
            .with_context(|| format!("HSM decrypt failed for {label:?}"))?;
        Ok(pt)
    }

    /// Atomically derive (ECDH1 + SHA-256 KDF) and encrypt. Derivation and
    /// use happen in the same session; the derived key is session-local
    /// (`Token(false)`) and never leaves the HSM.
    pub fn derive_and_encrypt(
        &self,
        label: &str,
        peer_public_key: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let session = self.open_session()?;
        let base = self.private_key(&session, label)?;
        let derived = self.derive_aes_key(&session, base, peer_public_key, label)?;
        let iv = self.random_iv(&session)?;
        let ct = session
            .encrypt(&Mechanism::AesCbcPad(iv), derived, plaintext)
            .with_context(|| format!("HSM derive_and_encrypt failed for {label:?}"))?;
        Ok((iv.to_vec(), ct))
    }

    pub fn derive_and_decrypt(
        &self,
        label: &str,
        peer_public_key: &[u8],
        ciphertext: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>> {
        let iv: [u8; 16] = iv
            .try_into()
            .map_err(|_| anyhow!("derive_and_decrypt: iv must be 16 bytes"))?;
        let session = self.open_session()?;
        let base = self.private_key(&session, label)?;
        let derived = self.derive_aes_key(&session, base, peer_public_key, label)?;
        let pt = session
            .decrypt(&Mechanism::AesCbcPad(iv), derived, ciphertext)
            .with_context(|| format!("HSM derive_and_decrypt failed for {label:?}"))?;
        Ok(pt)
    }

    /// Derive a session-local AES-256 key via ECDH1 + SHA-256 KDF.
    /// Whether `sc-hsm-embedded` actually honors `CKD_SHA256_KDF` is
    /// UNVERIFIED against real hardware (pre-wipe finding) — the USB
    /// smoke test must cover this before production use.
    fn derive_aes_key(
        &self,
        session: &Session,
        base_key: ObjectHandle,
        peer_public_key: &[u8],
        label: &str,
    ) -> Result<ObjectHandle> {
        let params = Ecdh1DeriveParams::new(EcKdf::sha256(KDF_SHARED_DATA), peer_public_key);
        let mechanism = Mechanism::Ecdh1Derive(params);
        let template = vec![
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::ValueLen(DERIVED_AES_LEN.into()),
            Attribute::Token(false),
            Attribute::Sensitive(true),
            Attribute::Encrypt(true),
            Attribute::Decrypt(true),
        ];
        session
            .derive_key(&mechanism, base_key, &template)
            .with_context(|| format!("HSM ECDH derive failed for {label:?}"))
    }

    fn random_iv(&self, session: &Session) -> Result<[u8; 16]> {
        let bytes = session
            .generate_random_vec(16)
            .context("HSM RNG failed")?;
        bytes
            .try_into()
            .map_err(|_| anyhow!("HSM RNG returned wrong length"))
    }
}

fn bail_key<T>(label: &str, why: &str) -> Result<T> {
    Err(anyhow!("key {label:?}: {why}"))
}
