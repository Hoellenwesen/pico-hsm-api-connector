//! Minimal example client for pico-hsm-api-connector.
//!
//! Mirrors `examples/local_client_example.py`: sign/verify + encrypt/decrypt
//! roundtrips plus a tamper probe and a denied probe.
//!
//! Usage:
//!   cargo run -- <host> <port> <client-cert> <client-key> <ca-cert>
//!                [sign-key] [enc-key]

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio_rustls::TlsConnector;

fn b64(data: &[u8]) -> String {
    B64.encode(data)
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let f = std::fs::File::open(path).with_context(|| format!("{path} unreadable"))?;
    let mut r = std::io::BufReader::new(f);
    let v: Vec<_> = rustls_pemfile::certs(&mut r).collect::<Result<_, std::io::Error>>()?;
    if v.is_empty() {
        bail!("no certificates in {path}");
    }
    Ok(v)
}

fn load_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let f = std::fs::File::open(path).with_context(|| format!("{path} unreadable"))?;
    let mut r = std::io::BufReader::new(f);
    rustls_pemfile::private_key(&mut r)?.ok_or_else(|| anyhow::anyhow!("no key in {path}"))
}

struct Client {
    reader: tokio::io::Lines<
        BufReader<tokio::io::ReadHalf<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>>,
    >,
    writer: tokio::io::WriteHalf<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
}

impl Client {
    async fn connect(
        host: &str,
        port: u16,
        cert_pem: &str,
        key_pem: &str,
        ca_pem: &str,
    ) -> Result<Self> {
        let mut roots = rustls::RootCertStore::empty();
        for cert in load_certs(ca_pem)? {
            roots.add(cert)?;
        }
        let certs = load_certs(cert_pem)?;
        let key = load_key(key_pem)?;
        let cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(certs, key)?;
        let connector = TlsConnector::from(Arc::new(cfg));
        let tcp = tokio::net::TcpStream::connect((host, port)).await?;
        let domain: rustls::pki_types::ServerName<'static> =
            host.to_owned().try_into().context("invalid DNS name")?;
        let tls = connector.connect(domain, tcp).await.context("TLS handshake failed (cert? CA? expiry?)")?;
        let (rh, wh) = tokio::io::split(tls);
        Ok(Self {
            reader: BufReader::new(rh).lines(),
            writer: wh,
        })
    }

    async fn request(&mut self, v: Value) -> Result<Value> {
        let mut line = serde_json::to_string(&v)?;
        line.push('\n');
        self.writer.write_all(line.as_bytes()).await?;
        let answer = self
            .reader
            .next_line()
            .await?
            .ok_or_else(|| anyhow::anyhow!("connection closed by gateway"))?;
        Ok(serde_json::from_str(&answer)?)
    }

    fn status(resp: &Value) -> &str {
        resp.get("status").and_then(|s| s.as_str()).unwrap_or("?")
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 6 {
        eprintln!(
            "usage: {} <host> <port> <client-cert> <client-key> <ca-cert> [sign-key] [enc-key]",
            args[0]
        );
        std::process::exit(2);
    }
    let (host, port) = (args[1].as_str(), args[2].parse::<u16>()?);
    let sign_key = args.get(6).cloned().unwrap_or_else(|| "app-b-signing-key".into());
    let enc_key = args.get(7).cloned().unwrap_or_else(|| "shared-encryption-key".into());

    let mut c = Client::connect(host, port, &args[3], &args[4], &args[5]).await?;

    // sign/verify
    let data = b64(b"hello pico-hsm");
    let sign = c
        .request(json!({"op":"sign","key_label":sign_key,"mechanism":"ecdsa_sha256","data_b64":data}))
        .await?;
    println!("sign: {sign}");
    assert_eq!(Client::status(&sign), "ok");
    let sig = sign["result_b64"].as_str().unwrap_or_default().to_string();
    let verify = c
        .request(json!({"op":"verify","key_label":sign_key,"mechanism":"ecdsa_sha256","data_b64":data,"signature_b64":sig}))
        .await?;
    println!("verify: {verify}");
    assert_eq!(Client::status(&verify), "ok");
    assert_eq!(verify["verified"], true);

    // encrypt/decrypt
    let enc = c
        .request(json!({"op":"encrypt","key_label":enc_key,"mechanism":"aes_cbc_pad","data_b64":b64(b"secret message")}))
        .await?;
    println!("encrypt: <ciphertext + iv + integrity>");
    assert_eq!(Client::status(&enc), "ok");
    let dec = c
        .request(json!({"op":"decrypt","key_label":enc_key,"mechanism":"aes_cbc_pad","data_b64":enc["result_b64"].clone(),"iv_b64":enc["iv_b64"].clone(),"integrity_b64":enc["integrity_b64"].clone()}))
        .await?;
    println!("decrypt: {dec}");
    assert_eq!(Client::status(&dec), "ok");
    assert_eq!(B64.decode(dec["result_b64"].as_str().unwrap_or_default())?, b"secret message");

    // tamper probe: must NOT be ok
    let mut raw = B64.decode(enc["result_b64"].as_str().unwrap_or_default())?;
    raw[0] ^= 0x01;
    let tampered = c
        .request(json!({"op":"decrypt","key_label":enc_key,"mechanism":"aes_cbc_pad","data_b64":b64(&raw),"iv_b64":enc["iv_b64"].clone(),"integrity_b64":enc["integrity_b64"].clone()}))
        .await?;
    println!("tampered decrypt (must not be ok): {}", Client::status(&tampered));
    assert_ne!(Client::status(&tampered), "ok");

    // denied probe
    let denied = c
        .request(json!({"op":"sign","key_label":"key-this-client-must-not-use","mechanism":"ecdsa_sha256","data_b64":b64(b"nope")}))
        .await?;
    println!("denied probe: {denied}");
    assert_eq!(Client::status(&denied), "denied");

    println!("All demos passed.");
    Ok(())
}
