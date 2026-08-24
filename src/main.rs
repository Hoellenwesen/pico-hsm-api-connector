mod audit;
mod config;
mod hsm;
mod protocol;
mod server;

use anyhow::{Context, Result};
use audit::AuditLog;
use config::AuthzTable;
use hsm::HsmClient;
use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

fn load_certs(path: &Path) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let f = std::fs::File::open(path).with_context(|| format!("{path:?} nicht lesbar"))?;
    let mut reader = std::io::BufReader::new(f);
    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn load_private_key(path: &Path) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let f = std::fs::File::open(path).with_context(|| format!("{path:?} nicht lesbar"))?;
    let mut reader = std::io::BufReader::new(f);
    rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| anyhow::anyhow!("Kein Private Key in {path:?} gefunden"))
}

/// Struktur der Umgebungsvariablen -- bewusst keine PIN oder Secrets in
/// einer Config-Datei im Repo, gleiches Prinzip wie PQVAULT_HSM_PIN im
/// bestehenden Projekt (README.md, Secrets-Uebersicht docs/12).
struct EnvConfig {
    listen_addr: String,
    server_cert: PathBuf,
    server_key: PathBuf,
    client_ca: PathBuf,
    clients_config: PathBuf,
    pkcs11_module: PathBuf,
    hsm_pin: String,
    audit_log: PathBuf,
    integrity_key_label: String,
    max_client_cert_validity_days: i64,
    cert_expiry_warn_days: i64,
}

fn parse_days_env(name: &str, default: i64) -> Result<i64> {
    match std::env::var(name) {
        Ok(v) => v
            .parse::<i64>()
            .with_context(|| format!("{name} muss eine Ganzzahl (Tage) sein, war '{v}'")),
        Err(_) => Ok(default),
    }
}

fn load_env() -> Result<EnvConfig> {
    let var = |name: &str| -> Result<String> {
        std::env::var(name).with_context(|| format!("Umgebungsvariable {name} nicht gesetzt"))
    };
    Ok(EnvConfig {
        listen_addr: std::env::var("GATEWAY_LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8443".into()),
        server_cert: var("GATEWAY_SERVER_CERT")?.into(),
        server_key: var("GATEWAY_SERVER_KEY")?.into(),
        client_ca: var("GATEWAY_CLIENT_CA")?.into(),
        clients_config: var("GATEWAY_CLIENTS_CONFIG")?.into(),
        pkcs11_module: var("GATEWAY_PKCS11_MODULE")?.into(),
        hsm_pin: var("GATEWAY_HSM_PIN")?,
        // Bewusst Pflicht ohne Default: AES-CBC hat keinen
        // Integritaetsschutz, ohne Encrypt-then-Sign waeren alle
        // Ciphertexts unbemerkt manipulierbar. Ein optionaler Schalter
        // waere ein Fail-Open-Pfad, den niemand bemerkt.
        integrity_key_label: var("GATEWAY_INTEGRITY_KEY_LABEL")?,
        audit_log: std::env::var("GATEWAY_AUDIT_LOG")
            .unwrap_or_else(|_| "/var/log/hsm-api-gateway/audit.jsonl".into())
            .into(),
        // Policy statt reiner Empfehlung: erzwingt kurzlebige
        // Client-Zertifikate (docs/11-Ergänzung, Punkt 4). Default 90
        // Tage max. Gültigkeit, Warnung ab 14 Tagen vor Ablauf — beides
        // bewusst konfigurierbar, falls eure interne CA andere
        // Rotationszyklen fährt.
        max_client_cert_validity_days: parse_days_env(
            "GATEWAY_MAX_CLIENT_CERT_VALIDITY_DAYS",
            90,
        )?,
        cert_expiry_warn_days: parse_days_env("GATEWAY_CERT_EXPIRY_WARN_DAYS", 14)?,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let env = load_env()?;

    let mut client_ca_store = RootCertStore::empty();
    for cert in load_certs(&env.client_ca)? {
        client_ca_store.add(cert)?;
    }
    let client_verifier = WebPkiClientVerifier::builder(Arc::new(client_ca_store))
        .build()
        .context("Client-Verifier konnte nicht gebaut werden")?;

    let server_certs = load_certs(&env.server_cert)?;
    let server_key = load_private_key(&env.server_key)?;

    let tls_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(server_certs, server_key)
        .context("TLS-Server-Config ungueltig")?;

    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let authz = AuthzTable::load_from_file(&env.clients_config)?;
    tracing::info!("Autorisierungs-Config geladen aus {:?}", env.clients_config);

    // Der Integritaetsschluessel ist gateway-intern. Waere er einem
    // Client freigegeben, koennte dieser ueber die regulaere
    // `sign`-Operation beliebige Integritaets-Signaturen erzeugen und
    // damit manipulierte Ciphertexts als echt ausgeben.
    if authz.mentions_key_label(&env.integrity_key_label) {
        anyhow::bail!(
            "GATEWAY_INTEGRITY_KEY_LABEL ('{}') ist in {:?} einem Client \
             freigegeben. Dieser Schluessel ist ausschliesslich fuer die \
             Integritaets-Signaturen des Gateways bestimmt — ein Client mit \
             Zugriff darauf koennte manipulierte Ciphertexts selbst signieren. \
             Entweder den Client-Eintrag entfernen oder einen eigenen, \
             separaten Key fuer die Integritaetssicherung anlegen.",
            env.integrity_key_label,
            env.clients_config
        );
    }

    let hsm = HsmClient::connect(&env.pkcs11_module, env.hsm_pin)?;
    tracing::info!("PKCS#11-Verbindung zum HSM hergestellt");

    let audit = AuditLog::new(env.audit_log.clone());
    if !audit.verify_chain()? {
        anyhow::bail!(
            "Audit-Log {:?} ist bereits inkonsistent (Kette gebrochen) -- \
             manuell pruefen, bevor der Dienst startet",
            env.audit_log
        );
    }

    let state = Arc::new(server::AppState {
        authz,
        hsm,
        audit,
        cert_policy: server::CertPolicy {
            max_validity: chrono::Duration::days(env.max_client_cert_validity_days),
            warn_before_expiry: chrono::Duration::days(env.cert_expiry_warn_days),
        },
        integrity_key_label: env.integrity_key_label,
    });

    server::run(&env.listen_addr, acceptor, state).await
}
