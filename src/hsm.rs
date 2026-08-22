//! Absichtlich schmale Schicht über PKCS#11.
//!
//! WICHTIG: Diese Datei stellt bewusst NUR sign/verify/encrypt/decrypt/
//! derive bereit. Es gibt hier keine Funktion für Objekt-Erzeugung,
//! Objekt-Löschung, PIN-Änderung, SO-Operationen oder Firmware-Bezug —
//! nicht weil das PKCS#11-Crate das nicht könnte, sondern weil dieser
//! Compiler-Baustein so aufgebaut ist, dass eine versehentliche
//! Erweiterung um Verwaltungsfunktionen auffallen muss (neue Methode,
//! neuer Call-Site in server.rs, neuer Config-Eintrag in Operation enum).
//!
//! HINWEIS ZUR VALIDIERUNG: Dieser Code kompiliert gegen die
//! `cryptoki`-Crate-API, wurde aber in dieser Sandbox NICHT gegen ein
//! echtes (oder simuliertes) HSM getestet — hier ist kein PKCS#11-Modul
//! und keine Hardware verfügbar (vgl. docs/15, "Bekannte Grenzen" in
//! README.md). Vor Produktivbetrieb: gegen echtes Board mit
//! opensc-pkcs11.so verifizieren, analog zum bestehenden
//! `hsm_backend.py`-Selbsttest.

use anyhow::{anyhow, Context, Result};
use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use std::path::Path;
use zeroize::Zeroizing;

pub struct HsmClient {
    pkcs11: Pkcs11,
    slot: Slot,
    pin: Zeroizing<String>,
}

impl HsmClient {
    /// `module_path`: Pfad zum PKCS#11-Modul, z. B.
    /// /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so (wie in README.md,
    /// Schritt 7 pqvault-Integration).
    pub fn connect(module_path: &Path, pin: String) -> Result<Self> {
        let pkcs11 = Pkcs11::new(module_path)
            .with_context(|| format!("PKCS#11-Modul {:?} nicht ladbar", module_path))?;
        pkcs11.initialize(CInitializeArgs::OsThreads)?;

        let slots = pkcs11.get_slots_with_token()?;
        let slot = *slots
            .first()
            .ok_or_else(|| anyhow!("Kein HSM-Token gefunden — ist der Pico eingesteckt?"))?;

        Ok(Self {
            pkcs11,
            slot,
            pin: Zeroizing::new(pin),
        })
    }

    fn open_session(&self) -> Result<Session> {
        let session = self.pkcs11.open_rw_session(self.slot)?;
        session.login(UserType::User, Some(&AuthPin::new(self.pin.to_string())))?;
        Ok(session)
    }

    /// Findet genau EIN Objekt mit dem gegebenen Label. Mehrdeutigkeit
    /// (0 oder >1 Treffer) ist ein Fehler — wir wollen nie erraten,
    /// welcher Key gemeint war.
    fn find_key_by_label(&self, session: &Session, label: &str) -> Result<ObjectHandle> {
        let template = vec![Attribute::Label(label.as_bytes().to_vec())];
        let handles = session.find_objects(&template)?;
        match handles.len() {
            0 => Err(anyhow!("Kein Key mit Label '{label}' gefunden")),
            1 => Ok(handles[0]),
            n => Err(anyhow!(
                "Mehrdeutig: {n} Keys mit Label '{label}' gefunden — Konfiguration \
                 auf dem HSM prüfen, Labels müssen eindeutig sein"
            )),
        }
    }

    pub fn sign(&self, key_label: &str, mechanism: &Mechanism, data: &[u8]) -> Result<Vec<u8>> {
        let session = self.open_session()?;
        let key = self.find_key_by_label(&session, key_label)?;
        Ok(session.sign(mechanism, key, data)?)
    }

    pub fn verify(
        &self,
        key_label: &str,
        mechanism: &Mechanism,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        let session = self.open_session()?;
        let key = self.find_key_by_label(&session, key_label)?;
        Ok(session.verify(mechanism, key, data, signature).is_ok())
    }

    pub fn encrypt(&self, key_label: &str, mechanism: &Mechanism, data: &[u8]) -> Result<Vec<u8>> {
        let session = self.open_session()?;
        let key = self.find_key_by_label(&session, key_label)?;
        Ok(session.encrypt(mechanism, key, data)?)
    }

    pub fn decrypt(&self, key_label: &str, mechanism: &Mechanism, data: &[u8]) -> Result<Vec<u8>> {
        let session = self.open_session()?;
        let key = self.find_key_by_label(&session, key_label)?;
        Ok(session.decrypt(mechanism, key, data)?)
    }

    /// Standard-Template für einen abgeleiteten AES-Session-Key:
    /// `Token(false)` ist der entscheidende Punkt — das Objekt ist rein
    /// session-lokal, das HSM verwirft es automatisch, sobald die
    /// Session geschlossen wird. Es landet nie im persistenten
    /// Objekt-Store und kann nie über eine zweite Anfrage erneut
    /// referenziert werden — es existiert schlicht nur für die
    /// Dauer dieses einen Funktionsaufrufs.
    fn default_derived_aes_template(key_len_bytes: usize) -> Vec<Attribute> {
        vec![
            Attribute::Class(cryptoki::object::ObjectClass::SECRET_KEY),
            Attribute::KeyType(cryptoki::object::KeyType::AES),
            Attribute::ValueLen((key_len_bytes as u32).into()),
            Attribute::Token(false),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Encrypt(true),
            Attribute::Decrypt(true),
        ]
    }

    /// Leitet einen Key aus `base_key_label` ab (z. B. ECDH1_DERIVE, wie
    /// im bestehenden pqvault-`hsm_backend.py::wrap_key()`) und
    /// verschlüsselt `plaintext` damit — alles innerhalb EINER Session.
    /// Der abgeleitete Key verlässt das HSM zu keinem Zeitpunkt und
    /// existiert nach Rückgabe dieser Funktion nicht mehr.
    pub fn derive_and_encrypt(
        &self,
        base_key_label: &str,
        derive_mechanism: &Mechanism,
        encrypt_mechanism: &Mechanism,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let session = self.open_session()?;
        let base_key = self.find_key_by_label(&session, base_key_label)?;
        let derived = session.derive_key(
            derive_mechanism,
            base_key,
            &Self::default_derived_aes_template(32),
        )?;
        Ok(session.encrypt(encrypt_mechanism, derived, plaintext)?)
        // `session` fällt hier aus Scope -> HSM verwirft den
        // Session-Key automatisch (Token(false)).
    }

    /// Gegenstück zu `derive_and_encrypt`: leitet denselben Key erneut
    /// ab (deterministisch bei ECDH1_DERIVE mit denselben Parametern)
    /// und entschlüsselt damit, wieder alles in einer Session.
    pub fn derive_and_decrypt(
        &self,
        base_key_label: &str,
        derive_mechanism: &Mechanism,
        decrypt_mechanism: &Mechanism,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let session = self.open_session()?;
        let base_key = self.find_key_by_label(&session, base_key_label)?;
        let derived = session.derive_key(
            derive_mechanism,
            base_key,
            &Self::default_derived_aes_template(32),
        )?;
        Ok(session.decrypt(decrypt_mechanism, derived, ciphertext)?)
    }
}
