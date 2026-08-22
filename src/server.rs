use crate::audit::AuditLog;
use crate::config::AuthzTable;
use crate::hsm::HsmClient;
use crate::protocol::{Request, Response};
use anyhow::{anyhow, Result};
use base64::Engine;
use cryptoki::mechanism::elliptic_curve::{Ecdh1DeriveParams, EcKdf};
use cryptoki::mechanism::Mechanism;
use rand::RngCore;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use x509_parser::prelude::*;

pub struct CertPolicy {
    /// Maximale erlaubte Gesamt-Gültigkeitsdauer eines Client-Zertifikats.
    /// Erzwingt "kurzlebige Zertifikate mit Zwangs-Rotation" als Policy —
    /// ein versehentlich mit z. B. 10 Jahren Gültigkeit ausgestelltes
    /// Zertifikat wird hier abgelehnt, statt sich auf die CA-Ausstellung
    /// allein zu verlassen (docs/11-Ergänzung, Punkt 4).
    pub max_validity: chrono::Duration,
    /// Ab wie viel Restlaufzeit vor Ablauf gewarnt wird (Audit + Log),
    /// damit eine Rotation nicht erst beim harten Handshake-Fehlschlag
    /// auffällt.
    pub warn_before_expiry: chrono::Duration,
}

pub struct AppState {
    pub authz: AuthzTable,
    pub hsm: HsmClient,
    pub audit: AuditLog,
    pub cert_policy: CertPolicy,
}

struct ClientIdentity {
    cn: String,
    not_before: chrono::DateTime<chrono::Utc>,
    not_after: chrono::DateTime<chrono::Utc>,
}

/// Extrahiert CN und Gültigkeitszeitraum aus dem (bereits per mTLS als
/// vertrauenswürdig validierten) Client-Zertifikat. Die reine
/// Ablauf-/Noch-nicht-gültig-Prüfung übernimmt bereits rustls beim
/// Handshake (WebPkiClientVerifier, main.rs) — hier kommt zusätzlich
/// eine eigene Policy dazu, die über reine Gültigkeit hinausgeht
/// (siehe `enforce_cert_policy`).
fn extract_identity(cert_der: &[u8]) -> Result<ClientIdentity> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| anyhow!("Client-Zertifikat nicht parsebar: {e}"))?;
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("Client-Zertifikat hat keinen CN"))?;

    let validity = cert.validity();
    let not_before = chrono::DateTime::from_timestamp(validity.not_before.timestamp(), 0)
        .ok_or_else(|| anyhow!("Zertifikat hat ungültiges not_before"))?;
    let not_after = chrono::DateTime::from_timestamp(validity.not_after.timestamp(), 0)
        .ok_or_else(|| anyhow!("Zertifikat hat ungültiges not_after"))?;

    Ok(ClientIdentity { cn, not_before, not_after })
}

/// Ergebnis der Policy-Prüfung — bewusst kein simples bool, damit der
/// Aufrufer zwischen "hart ablehnen" und "durchlassen, aber warnen"
/// unterscheiden kann.
enum PolicyOutcome {
    Ok,
    OkButExpiringSoon { days_remaining: i64 },
    Rejected { reason: String },
}

fn enforce_cert_policy(identity: &ClientIdentity, policy: &CertPolicy) -> PolicyOutcome {
    let total_validity = identity.not_after - identity.not_before;
    if total_validity > policy.max_validity {
        return PolicyOutcome::Rejected {
            reason: format!(
                "Zertifikat für '{}' ist {} Tage gültig, erlaubt sind maximal {} Tage \
                 (GATEWAY_MAX_CLIENT_CERT_VALIDITY_DAYS) — CA-Konfiguration prüfen, \
                 kurzlebige Zertifikate sind hier bewusste Policy, nicht nur Empfehlung",
                identity.cn,
                total_validity.num_days(),
                policy.max_validity.num_days()
            ),
        };
    }

    let remaining = identity.not_after - chrono::Utc::now();
    if remaining < policy.warn_before_expiry {
        return PolicyOutcome::OkButExpiringSoon {
            days_remaining: remaining.num_days().max(0),
        };
    }

    PolicyOutcome::Ok
}

/// Mechanismen ohne Laufzeitparameter — bewusst nur eine kleine,
/// freigegebene Liste, kein generisches "beliebigen Mechanismus-String
/// an PKCS#11 durchreichen".
///
/// `ecdsa_sha256` mappt auf den kombinierten Hash-und-Sign-Mechanismus
/// `CKM_ECDSA_SHA256` (nicht auf `CKM_ECDSA`/`Mechanism::Ecdsa`, das
/// erwartet bereits gehashte Daten exakt in Kurvenlänge und würde bei
/// beliebig langen Nutzdaten fehlschlagen — siehe
/// pico-hsm/doc/sign-verify.md, "SHA256-ECDSA" vs. "ECDSA").
fn parse_mechanism(name: &str) -> Result<Mechanism<'_>> {
    match name {
        "sha256_rsa_pkcs" => Ok(Mechanism::Sha256RsaPkcs),
        "ecdsa_sha256" => Ok(Mechanism::EcdsaSha256),
        other => Err(anyhow!(
            "Mechanismus '{other}' nicht in der Freigabeliste (oder \
             braucht Laufzeitparameter — siehe build_aes_cbc_pad/build_ecdh1_derive)"
        )),
    }
}

/// AES-CBC mit PKCS#7-Padding — braucht pro Aufruf einen frischen IV
/// (siehe `generate_iv`), deshalb getrennt von `parse_mechanism`: ein
/// `Default`-IV (alles Nullen) wäre für jede Verschlüsselung identisch
/// und würde die semantische Sicherheit von CBC brechen.
fn build_aes_cbc_pad(name: &str, iv: [u8; 16]) -> Result<Mechanism<'_>> {
    match name {
        "aes_cbc_pad" => Ok(Mechanism::AesCbcPad(iv)),
        other => Err(anyhow!("Mechanismus '{other}' nicht in der AES-Freigabeliste")),
    }
}

/// ECDH1_DERIVE braucht zwingend den Public Key der Gegenseite als
/// Laufzeitparameter (`Ecdh1DeriveParams` hat kein `Default` — ein
/// vorheriges `Default::default()` hier hätte gar nicht kompiliert).
/// `EcKdf::null()`: keine zusätzliche KDF, das rohe Shared Secret wird
/// direkt verwendet, wie im pico-hsm-Referenzbeispiel
/// (asymmetric-ciphering.md, ECDH-DERIVE — dort werden die rohen
/// abgeleiteten Bytes direkt verglichen, ohne KDF-Nachbearbeitung).
fn build_ecdh1_derive<'a>(name: &str, peer_public_key: &'a [u8]) -> Result<Mechanism<'a>> {
    match name {
        "ecdh1_derive" => Ok(Mechanism::Ecdh1Derive(Ecdh1DeriveParams::new(
            EcKdf::null(),
            peer_public_key,
        ))),
        other => Err(anyhow!("Mechanismus '{other}' nicht in der Derive-Freigabeliste")),
    }
}

/// IV-Generierung bewusst host-seitig über OS-CSPRNG statt über die
/// HSM-eigene TRNG: ein AES-CBC-IV muss nur unvorhersehbar/eindeutig
/// sein, nicht geheim — dafür ist kein zusätzlicher PKCS#11-Roundtrip
/// zum HSM nötig.
fn generate_iv() -> [u8; 16] {
    let mut iv = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut iv);
    iv
}

async fn handle_connection(
    stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    state: Arc<AppState>,
) -> Result<()> {
    let (_, session) = stream.get_ref();
    let identity = match session.peer_certificates() {
        Some(certs) if !certs.is_empty() => extract_identity(certs[0].as_ref())?,
        _ => return Err(anyhow!("Keine Client-Zertifikate präsentiert — mTLS sollte das bereits verhindert haben")),
    };

    // "-" als key_label: Connection-Level-Ereignisse betreffen noch
    // keinen konkreten Key, das Audit-Schema (audit.rs) verlangt aber
    // ein Feld — bewusst statt Schema-Änderung, um die Hash-Chain nicht
    // rückwirkend zu verkomplizieren.
    match enforce_cert_policy(&identity, &state.cert_policy) {
        PolicyOutcome::Rejected { reason } => {
            tracing::warn!("Verbindung von '{}' abgelehnt: {reason}", identity.cn);
            let _ = state.audit.append(
                &identity.cn,
                "connection",
                "-",
                "cert_policy_violation",
                Some(reason.clone()),
            );
            return Err(anyhow!(reason));
        }
        PolicyOutcome::OkButExpiringSoon { days_remaining } => {
            tracing::warn!(
                "Client-Zertifikat für '{}' läuft in {days_remaining} Tagen ab — Rotation einplanen",
                identity.cn
            );
            let _ = state.audit.append(
                &identity.cn,
                "connection",
                "-",
                "cert_expiring_soon",
                Some(format!("{days_remaining} Tage bis Ablauf")),
            );
        }
        PolicyOutcome::Ok => {}
    }

    let cn = identity.cn;
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut lines = BufReader::new(read_half).lines();

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let response = process_line(&line, &cn, &state);
        let out = serde_json::to_string(&response)?;
        write_half.write_all(out.as_bytes()).await?;
        write_half.write_all(b"\n").await?;
    }
    Ok(())
}

fn process_line(line: &str, cn: &str, state: &AppState) -> Response {
    let req: Request = match serde_json::from_str(line) {
        Ok(r) => r,
        Err(e) => return Response::Error { message: format!("Ungültige Anfrage: {e}") },
    };

    let op = req.operation();
    let key_label = req.key_label().to_string();

    if !state.authz.is_authorized(cn, op, &key_label) {
        let _ = state.audit.append(cn, &format!("{op:?}"), &key_label, "denied", None);
        return Response::Denied {
            reason: format!("Client '{cn}' nicht autorisiert für {op:?} auf '{key_label}'"),
        };
    }

    let result = execute(&req, &key_label, state);

    let (status, detail) = match &result {
        Ok(_) => ("authorized", None),
        Err(e) => ("hsm_error", Some(e.to_string())),
    };
    let _ = state.audit.append(cn, &format!("{op:?}"), &key_label, status, detail);

    match result {
        Ok(resp) => resp,
        Err(e) => Response::Error { message: e.to_string() },
    }
}

/// Dekodiert `iv_b64` und prüft die AES-Blockgröße (16 Bytes) — ein
/// falsch langer IV wäre sonst erst ein kryptischer PKCS#11-Fehler
/// statt einer klaren Fehlermeldung an den Client.
fn decode_iv(iv_b64: &str, b64: &base64::engine::GeneralPurpose) -> Result<[u8; 16]> {
    let bytes = b64.decode(iv_b64)?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("iv_b64 muss genau 16 Bytes dekodieren (AES-Blockgroesse)"))
}

fn execute(req: &Request, key_label: &str, state: &AppState) -> Result<Response> {
    let b64 = base64::engine::general_purpose::STANDARD;
    match req {
        Request::Sign { mechanism, data_b64, .. } => {
            let mech = parse_mechanism(mechanism)?;
            let data = b64.decode(data_b64)?;
            let sig = state.hsm.sign(key_label, &mech, &data)?;
            Ok(Response::Ok { result_b64: Some(b64.encode(sig)), verified: None, iv_b64: None })
        }
        Request::Verify { mechanism, data_b64, signature_b64, .. } => {
            let mech = parse_mechanism(mechanism)?;
            let data = b64.decode(data_b64)?;
            let sig = b64.decode(signature_b64)?;
            let ok = state.hsm.verify(key_label, &mech, &data, &sig)?;
            Ok(Response::Ok { result_b64: None, verified: Some(ok), iv_b64: None })
        }
        Request::Encrypt { mechanism, data_b64, .. } => {
            let iv = generate_iv();
            let mech = build_aes_cbc_pad(mechanism, iv)?;
            let data = b64.decode(data_b64)?;
            let ct = state.hsm.encrypt(key_label, &mech, &data)?;
            Ok(Response::Ok {
                result_b64: Some(b64.encode(ct)),
                verified: None,
                iv_b64: Some(b64.encode(iv)),
            })
        }
        Request::Decrypt { mechanism, data_b64, iv_b64, .. } => {
            let iv = decode_iv(iv_b64, &b64)?;
            let mech = build_aes_cbc_pad(mechanism, iv)?;
            let data = b64.decode(data_b64)?;
            let pt = state.hsm.decrypt(key_label, &mech, &data)?;
            Ok(Response::Ok { result_b64: Some(b64.encode(pt)), verified: None, iv_b64: None })
        }
        Request::DeriveAndEncrypt {
            derive_mechanism,
            target_mechanism,
            peer_public_key_b64,
            data_b64,
            ..
        } => {
            let peer_key = b64.decode(peer_public_key_b64)?;
            let derive_mech = build_ecdh1_derive(derive_mechanism, &peer_key)?;
            let iv = generate_iv();
            let target_mech = build_aes_cbc_pad(target_mechanism, iv)?;
            let data = b64.decode(data_b64)?;
            let ct = state
                .hsm
                .derive_and_encrypt(key_label, &derive_mech, &target_mech, &data)?;
            Ok(Response::Ok {
                result_b64: Some(b64.encode(ct)),
                verified: None,
                iv_b64: Some(b64.encode(iv)),
            })
        }
        Request::DeriveAndDecrypt {
            derive_mechanism,
            target_mechanism,
            peer_public_key_b64,
            iv_b64,
            data_b64,
            ..
        } => {
            let peer_key = b64.decode(peer_public_key_b64)?;
            let derive_mech = build_ecdh1_derive(derive_mechanism, &peer_key)?;
            let iv = decode_iv(iv_b64, &b64)?;
            let target_mech = build_aes_cbc_pad(target_mechanism, iv)?;
            let data = b64.decode(data_b64)?;
            let pt = state
                .hsm
                .derive_and_decrypt(key_label, &derive_mech, &target_mech, &data)?;
            Ok(Response::Ok { result_b64: Some(b64.encode(pt)), verified: None, iv_b64: None })
        }
    }
}

pub async fn run(addr: &str, acceptor: TlsAcceptor, state: Arc<AppState>) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("HSM-API-Gateway lauscht auf {addr}");
    loop {
        let (tcp_stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let state = state.clone();
        tokio::spawn(async move {
            match acceptor.accept(tcp_stream).await {
                Ok(tls_stream) => {
                    if let Err(e) = handle_connection(tls_stream, state).await {
                        tracing::warn!("Verbindung von {peer} beendet mit Fehler: {e}");
                    }
                }
                Err(e) => tracing::warn!("TLS-Handshake mit {peer} fehlgeschlagen: {e}"),
            }
        });
    }
}
