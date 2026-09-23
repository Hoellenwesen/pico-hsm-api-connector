# pico-hsm-api-connector

Network API gateway exposing crypto operations of the Pico-HSM (USB-attached,
PKCS#11) to internal network clients — with per-client mTLS authentication and
authorization down to individual key labels.

This gateway is the **only** PKCS#11 consumer in the setup: remote network
clients as well as local products (e.g. pqvault) talk to it over mTLS, even
when running on the same host (`127.0.0.1:8443`). There is no Unix-socket
special case.

Firmware project: https://github.com/Hoellenwesen/pico-hsm

## Deliberately out of scope

This service exposes **only** the crypto operations
`sign`, `verify`, `encrypt`, `decrypt`, `derive_and_encrypt`, `derive_and_decrypt` —
each restricted to individual key labels per client. Explicitly **not**
reachable through this API, not even indirectly:

- Object management (key generation/deletion, unfiltered `find_objects`)
- PIN/PUK/SO-PIN management
- Firmware update (stays a physical BOOTSEL flow)
- Backup/restore of HSM keys

This is structural, not conventional: `src/hsm.rs` simply implements no
functions for those, and `src/protocol.rs` knows no such request variants.

## Architecture

```
Client (mTLS cert) ──TLS──▶ src/server.rs
                              │  1. extract CN from client cert
                              │  2. authorize against config/clients.yaml
                              │     (default-deny, per operation + key label)
                              │  3. audit `intent`, call src/hsm.rs
                              │  4. Encrypt-then-Sign seal, audit result
                              ▼
                         src/hsm.rs ──PKCS#11──▶ Pico HSM (USB)
```

- Southbound: USB via PKCS#11 module (`GATEWAY_PKCS11_MODULE`). Production:
  `libsc-hsm-pkcs11.so` — NOT `opensc-pkcs11.so`, whose sc-hsm driver has no
  AES support (encrypt/decrypt/derive would fail; sign/verify work with either).
- Northbound: TCP + mTLS + newline-delimited JSON (no gRPC), so any product
  speaking TLS + JSON can connect without a generated SDK.

Example request:

```json
{"op": "sign", "key_label": "app-b-signing-key", "mechanism": "ecdsa_sha256", "data_b64": "..."}
```

AES operations (`encrypt`, `decrypt`, `derive_and_encrypt`, `derive_and_decrypt`)
return two extra fields next to `result_b64` that the caller must store with the
ciphertext and send back for decryption:

- `iv_b64` — freshly generated AES-CBC IV per encryption
- `integrity_b64` — Encrypt-then-Sign signature over key label, IV and ciphertext

Without both values a ciphertext cannot be decrypted. For
`derive_and_encrypt`/`derive_and_decrypt`, `peer_public_key_b64` is additionally
required (counterparty public key for ECDH derive) and must be allowlisted in
`clients.yaml` (see below).

## Setup

```bash
export GATEWAY_LISTEN_ADDR="0.0.0.0:8443"
export GATEWAY_SERVER_CERT=/etc/hsm-gateway/server.pem
export GATEWAY_SERVER_KEY=/etc/hsm-gateway/server-key.pem
export GATEWAY_CLIENT_CA=/etc/hsm-gateway/client-ca.pem
export GATEWAY_CLIENTS_CONFIG=/etc/hsm-gateway/clients.yaml
export GATEWAY_PKCS11_MODULE=/usr/lib/libsc-hsm-pkcs11.so
export GATEWAY_HSM_PIN="<inject at runtime, never commit>"
export GATEWAY_AUDIT_LOG=/var/log/hsm-api-gateway/audit.jsonl
# Dedicated ECDSA key for integrity signatures (Encrypt-then-Sign).
# Mandatory, no default — must NOT be granted to any client (startup check).
export GATEWAY_INTEGRITY_KEY_LABEL=gateway-integrity-key
# Optional: cert lifetime policy (defaults: 90 days max, warn 14 days out)
export GATEWAY_MAX_CLIENT_CERT_VALIDITY_DAYS=90
export GATEWAY_CERT_EXPIRY_WARN_DAYS=14

cargo run --release
```

Fill `config/clients.yaml` following `config/clients.example.yaml`
(default-deny; the real file is gitignored, only the template is tracked).

## Integrity protection (Encrypt-then-Sign)

AES-CBC provides **no** integrity: anyone holding a stored ciphertext could
flip bits (CBC malleability) without decryption noticing. The gateway therefore
signs key label, IV and ciphertext with a dedicated ECDSA key in the HSM on
every encryption, and verifies that signature **before** decrypting. Side
effect: the decrypt path is no padding oracle, since tampered data never
reaches the PKCS#11 unpadding.

Create the key (its own key, none of the application keys):

```bash
pkcs11-tool --module /usr/lib/libsc-hsm-pkcs11.so --login --pin <PIN> \
    --keypairgen --key-type EC:secp256r1 --label "gateway-integrity-key"
```

**This key must never appear in `clients.yaml`.** A client granted `sign` on it
could forge integrity signatures for manipulated ciphertexts. The gateway
refuses to start if the label is found in the authorization config.

The signed payload (`server.rs::integrity_payload`) is a canonical
length-prefixed encoding (domain separator, key label, IV, ciphertext). The
bound key label prevents cross-key replay of a ciphertext.

## Peer-public-key allowlist (mandatory for `derive_*`)

```yaml
- operation: derive_and_encrypt   # or derive_and_decrypt
  key_labels: ["app-c-derive-key"]
  peer_public_keys:
    - "<base64 of counterparty public key>"
```

Wrapping and unwrapping are **separate** operations: a client that should only
wrap key material gets `derive_and_encrypt` without the counterpart. Both need
their own `peer_public_keys`.

Produce a value (same bytes `pkcs11-tool --derive -i <file>` expects):

```bash
openssl ec -in peer.pem -pubout -outform DER | base64 -w0
```

Why mandatory, not optional hardening: ECDH is symmetric
(`d_hsm · Q_client == d_client · Q_hsm`). A freely chosen peer key would let a
client recompute the derived AES key offline with its own private key
(worthless hardware binding) and reconstruct the HSM private key via
invalid-curve queries (NIST SP 800-56A Rev. 3, §5.6.2.3.2).

Enforced twice: at config load (derive entry without allowlist = hard start
error; allowlist on other ops = start error) and per request (unlisted peer
key → `"status":"denied"` + audit entry with the SHA-256 fingerprint).
Curve membership itself is NOT checked — only operator-vetted keys belong in
the list.

## Client certificate policy (short-lived certs instead of revocation)

- **Hard reject** when a client cert is valid longer than
  `GATEWAY_MAX_CLIENT_CERT_VALIDITY_DAYS` (default 90).
- **Proactive warning** (log + `cert_expiring_soon` audit entry) when a cert
  expires within `GATEWAY_CERT_EXPIRY_WARN_DAYS` (default 14).
- Plain expiry is still enforced by `rustls` at handshake; this is an
  additional policy layer, not a replacement.
- **No revocation checking:** a compromised but valid cert is blocked by
  removing its CN from `clients.yaml`. Conscious trade-off for few clients
  with short rotation cycles.

## Build & test (no real HSM needed)

Requires current Rust via `rustup` (≥1.85; distro Rust 1.75 fails on
`chrono`/`indexmap`/`aws-lc-sys`):

```bash
cargo check
cargo test    # authz table, audit chain, protocol parsing — pure logic, no HSM
cargo build --release
RUST_LOG=debug cargo run --release
```

Local E2E without hardware uses SoftHSM2 (`softhsm2`, `opensc`, `openssl`
packages; typically WSL/Linux) with
`GATEWAY_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so`, `openssl`-generated
test CA/certs (client CN must match `clients.yaml`; `-days 30` passes the
policy, `-days 200` must be rejected with `cert_policy_violation`), then:

```bash
python3 examples/local_client_example.py \
    --host 127.0.0.1 --port 8443 \
    --client-cert certs/client-a.pem --client-key certs/client-a-key.pem \
    --ca-cert certs/ca.pem
```

The audit log is **fail-closed**: if an entry cannot be written, the request
is rejected without any HSM operation. Each request logs two entries — `intent`
before the HSM call, `authorized`/`denied`/`error` after; a lone `intent`
means the outcome is unknown.

## Open items before production

1. **Hardware coverage is partial (verified 2026-09-23, Pico-HSM FW 6.6, OpenSC driver):**
   slot/token detection, PIN login, `sign → ok`, `verify → verified:true`,
   `denied` path, cert-policy reject — all green against real hardware.
   Still missing: the full mechanism matrix exclusively via
   `libsc-hsm-pkcs11.so` (OpenSC's sc-hsm driver has no AES, so
   encrypt/decrypt/derive could not be exercised yet).
2. **KDF verification**: `EcKdf::sha256()` requires `shared_data` (a fixed
   domain string is used); whether `sc-hsm-embedded` honors `CKD_SHA256_KDF`
   is unverified — cover in the smoke test before production.
3. **Mechanism scope**: MVP is ECDSA-SHA256 + AES-CBC-PAD + ECDH1_DERIVE.
   RSA-PKCS/PSS (firmware supports RSA 1024–4096) is a deferred extension in
   `server.rs` + `hsm.rs`.
4. SoftHSM2 covers authz/mTLS/protocol but NOT the exact firmware mechanism
   behavior — a green SoftHSM run does not replace the real-board run.
5. **No per-client rate limiting**: a compromised but correctly authorized
   client certificate can issue unlimited operations. Conscious gap carried
   over from the pre-wipe threat-model addendum — revisit if the client
   count or threat level grows.

## Threat model (summary)

New network service = new attack surface vs. a local-only daemon. Mitigations
by design: mTLS with short-lived certs, default-deny authz to key labels,
mandatory peer-key allowlists, Encrypt-then-Sign on all AES ciphertexts,
fail-closed hash-chained audit, structural exclusion of all management
operations, PIN via runtime-injected env (zeroized in memory).

## Further documentation

- `docs/16-real-hardware-and-cert-rotation.md` — real board + certificate rotation runbook.
- `docs/17-linux-service.md` — Linux install + systemd service (`contrib/pico-hsm-api-connector.service`).
- `docs/18-client-integration.md` — onboarding + wire protocol + example clients
  (`examples/`: Python, Rust, Go, Node.js, Bash).
