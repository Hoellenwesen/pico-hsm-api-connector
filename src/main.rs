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
use server::Gateway;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::info;

/// Environment wiring. Secrets have NO defaults — every variable below
/// must be set, otherwise the gateway refuses to start.
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

fn required_var(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("environment variable {name} is not set"))
}

fn days_var(name: &str, default: i64) -> Result<i64> {
    match std::env::var(name) {
        Ok(v) => v
            .parse::<i64>()
            .with_context(|| format!("{name} must be an integer (days), was {v:?}")),
        Err(_) => Ok(default),
    }
}

fn load_env() -> Result<EnvConfig> {
    Ok(EnvConfig {
        listen_addr: required_var("GATEWAY_LISTEN_ADDR")?,
        server_cert: PathBuf::from(required_var("GATEWAY_SERVER_CERT")?),
        server_key: PathBuf::from(required_var("GATEWAY_SERVER_KEY")?),
        client_ca: PathBuf::from(required_var("GATEWAY_CLIENT_CA")?),
        clients_config: PathBuf::from(required_var("GATEWAY_CLIENTS_CONFIG")?),
        pkcs11_module: PathBuf::from(required_var("GATEWAY_PKCS11_MODULE")?),
        hsm_pin: required_var("GATEWAY_HSM_PIN")?,
        audit_log: PathBuf::from(required_var("GATEWAY_AUDIT_LOG")?),
        integrity_key_label: required_var("GATEWAY_INTEGRITY_KEY_LABEL")?,
        max_client_cert_validity_days: days_var("GATEWAY_MAX_CLIENT_CERT_VALIDITY_DAYS", 90)?,
        cert_expiry_warn_days: days_var("GATEWAY_CERT_EXPIRY_WARN_DAYS", 14)?,
    })
}

fn load_certs(path: &Path) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let f = std::fs::File::open(path).with_context(|| format!("{path:?} unreadable"))?;
    let mut reader = std::io::BufReader::new(f);
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut reader).collect::<Result<_, std::io::Error>>()?;
    if certs.is_empty() {
        anyhow::bail!("no valid certificates found in {path:?}");
    }
    Ok(certs)
}

fn load_private_key(path: &Path) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let f = std::fs::File::open(path).with_context(|| format!("{path:?} unreadable"))?;
    let mut reader = std::io::BufReader::new(f);
    rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {path:?}"))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let env = load_env()?;

    // 1. Authz table (validates peer-key allowlists + integrity-label exclusion).
    let authz = AuthzTable::load(&env.clients_config, &env.integrity_key_label)?;
    info!("loaded clients config from {:?}", env.clients_config);

    // 2. Audit log (verifies the hash chain; refuses tampered logs).
    let audit = AuditLog::open(&env.audit_log)?;
    info!("opened audit log at {:?}", audit.path());

    // 3. HSM (fails here — not on first request — if the Pico is missing).
    let hsm = HsmClient::connect(&env.pkcs11_module, env.hsm_pin)?;
    info!("connected to HSM via {:?}", env.pkcs11_module);

    let gateway = Arc::new(Gateway::new(
        authz,
        hsm,
        audit,
        env.integrity_key_label,
        env.max_client_cert_validity_days,
        env.cert_expiry_warn_days,
    ));

    // 4. mTLS: server cert + mandatory client-cert verification against our CA.
    let server_certs = load_certs(&env.server_cert)?;
    let server_key = load_private_key(&env.server_key)?;
    let mut client_roots = RootCertStore::empty();
    for cert in load_certs(&env.client_ca)? {
        client_roots.add(cert)?;
    }
    let client_auth = WebPkiClientVerifier::builder(client_roots.into()).build()?;
    let tls_config = Arc::new(
        rustls::ServerConfig::builder()
            .with_client_cert_verifier(client_auth)
            .with_single_cert(server_certs, server_key)?,
    );
    let acceptor = TlsAcceptor::from(tls_config);

    let listener = TcpListener::bind(&env.listen_addr).await?;
    info!("listening on {}", env.listen_addr);

    loop {
        let (tcp, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let gateway = Arc::clone(&gateway);
        tokio::spawn(async move {
            match acceptor.accept(tcp).await {
                Ok(tls) => {
                    if let Err(e) = gateway.handle_connection(tls).await {
                        tracing::warn!(%peer, "connection failed: {e:#}");
                    }
                }
                Err(e) => tracing::warn!(%peer, "TLS handshake failed: {e}"),
            }
        });
    }
}
