# Client integration guide

How a tool talks to `pico-hsm-api-connector`: onboarding (certificate,
authorization, keys), the wire protocol with all six operations, minimal
example clients in Python, Rust, Go, Node.js and Bash, and an error table.

> Start here for the big picture: `README.md` (architecture, scope).
> For gateway operation on Linux (incl. systemd): `docs/17-linux-service.md`.
> For hardware + certificate rotation: `docs/16-real-hardware-and-cert-rotation.md`.

## 1. Onboarding a new client

Three things must exist before the first request succeeds. All three are
operator tasks — none of them happens through the gateway API.

### 1.1 Client certificate (mTLS identity)

The gateway identifies a client **solely by the CN** of its mTLS client
certificate. Issue one certificate per tool/host:

```bash
openssl req -newkey rsa:2048 -nodes -keyout tool-key.pem \
    -out tool.csr -subj "/CN=my-tool.internal.example"
openssl x509 -req -in tool.csr -CA ca.pem -CAkey ca-key.pem \
    -CAcreateserial -days 30 -out tool.pem
rm tool.csr
```

Rules:

- The CN must **exactly** match the `cn:` entry in `clients.yaml`.
- Keep `-days` well under `GATEWAY_MAX_CLIENT_CERT_VALIDITY_DAYS`
  (default 90) — longer-lived certs are rejected with
  `cert_policy_violation`, no exceptions.
- One certificate per client. Sharing a cert between tools destroys the
  per-client authorization boundary.

### 1.2 Authorization entry (`clients.yaml`)

The gateway operator adds which `(operation, key_label)` pairs the new CN
may use (default-deny — anything not listed is rejected before any HSM
contact). Template: `config/clients.example.yaml`. Changes require a
**gateway restart** (config is loaded once at startup).

```yaml
clients:
  - cn: "my-tool.internal.example"
    description: "Signs releases with its own key"
    permissions:
      - operation: sign
        key_labels: ["my-tool-signing-key"]
      - operation: verify
        key_labels: ["my-tool-signing-key"]
```

For `derive_and_encrypt` / `derive_and_decrypt`, each entry additionally
needs a `peer_public_keys` allowlist (base64, operator-vetted, mandatory —
missing list = gateway refuses to start). See `README.md`.

### 1.3 Keys on the HSM

Keys are created manually on the host — key management is deliberately not
part of the gateway API:

```bash
# Signing key (EC P-256):
pkcs11-tool --module <pkcs11-module> --login --pin <PIN> \
    --keypairgen --key-type EC:secp256r1 --label "my-tool-signing-key"

# Encryption key (AES-256):
pkcs11-tool --module <pkcs11-module> --login --pin <PIN> \
    --keygen --key-type AES:32 --label "shared-encryption-key"
```

Label discipline: labels are the authorization unit. One label per
purpose, never reuse a label across tools. (`pkcs11-tool --keypairgen`
creates a private AND a public object under the same label — the gateway
selects by object class internally, so this is expected, not a conflict.)

## 2. Wire protocol

- Transport: **TCP + mTLS** (client cert + key, gateway CA). Default port
  in examples: `8443`. Local tools connect to `127.0.0.1:8443` — no
  Unix-socket special case.
- Framing: **newline-delimited JSON**. One request line in, one response
  line out. The connection stays open for multiple requests.
- Binary data is **base64** in `*_b64` fields.
- Mechanism strings (MVP): `ecdsa_sha256`, `aes_cbc_pad`, `ecdh1_derive`.
  Anything else is rejected with `{"status":"error"}`.

### 2.1 Sign / verify

```json
{"op": "sign", "key_label": "my-tool-signing-key", "mechanism": "ecdsa_sha256", "data_b64": "aGVsbG8="}
{"status": "ok", "result_b64": "<signature>", "verified": null, "iv_b64": null, "integrity_b64": null}
```

```json
{"op": "verify", "key_label": "my-tool-signing-key", "mechanism": "ecdsa_sha256", "data_b64": "aGVsbG8=", "signature_b64": "<signature>"}
{"status": "ok", "result_b64": null, "verified": true, "iv_b64": null, "integrity_b64": null}
```

### 2.2 Encrypt / decrypt

```json
{"op": "encrypt", "key_label": "shared-encryption-key", "mechanism": "aes_cbc_pad", "data_b64": "c2VjcmV0"}
{"status": "ok", "result_b64": "<ciphertext>", "verified": null, "iv_b64": "<iv>", "integrity_b64": "<sig>"}
```

**Store `iv_b64` and `integrity_b64` together with the ciphertext.**
Decryption is impossible without them, and the integrity signature is
verified *before* decrypting (tampered input never reaches unpadding):

```json
{"op": "decrypt", "key_label": "shared-encryption-key", "mechanism": "aes_cbc_pad", "data_b64": "<ciphertext>", "iv_b64": "<iv>", "integrity_b64": "<sig>"}
{"status": "ok", "result_b64": "c2VjcmV0", "verified": null, "iv_b64": null, "integrity_b64": null}
```

### 2.3 Derive + encrypt / decrypt

Atomic derive (ECDH1 + SHA-256 KDF) and use in one HSM session. The derived
key never leaves the HSM — there is intentionally no operation that returns
it. `peer_public_key_b64` is mandatory and must be allowlisted (1.2):

```json
{"op": "derive_and_encrypt", "key_label": "app-c-derive-key", "derive_mechanism": "ecdh1_derive", "target_mechanism": "aes_cbc_pad", "peer_public_key_b64": "<peer-key>", "data_b64": "c2VjcmV0"}
{"status": "ok", "result_b64": "<ciphertext>", "verified": null, "iv_b64": "<iv>", "integrity_b64": "<sig>"}
```

```json
{"op": "derive_and_decrypt", "key_label": "app-c-derive-key", "derive_mechanism": "ecdh1_derive", "target_mechanism": "aes_cbc_pad", "peer_public_key_b64": "<peer-key>", "iv_b64": "<iv>", "integrity_b64": "<sig>", "data_b64": "<ciphertext>"}
{"status": "ok", "result_b64": "c2VjcmV0", "verified": null, "iv_b64": null, "integrity_b64": null}
```

Produce the peer-key value (same bytes `pkcs11-tool --derive` expects):

```bash
openssl ec -in peer.pem -pubout -outform DER | base64 -w0
```

## 3. Error handling

| Symptom | Meaning | Client action |
|---|---|---|
| `{"status":"denied","reason":"..."}` | Authorization failed (unknown CN, wrong label/op, unlisted peer key, integrity mismatch). Audited server-side. | Fix config or input; do NOT retry blindly — repeated denies indicate a config bug or an attack. |
| `{"status":"error","message":"..."}` | HSM/policy failure (bad PIN at login, unsupported mechanism, bad base64, audit log unwritable, `cert_policy_violation` on connect). | Depends on message; `cert_policy_violation` = re-issue a shorter-lived cert. |
| TLS handshake failure | No/expired/wrong-CA client cert, or server unreachable. | Check cert + CA + expiry + `GATEWAY_CLIENTS_CONFIG` CN match. |
| Connection dropped mid-session | Gateway restarted (config change, update). Protocol is stateless per line. | Reconnect and retry the unanswered request. |
| Lone request, no answer, connection open | Server is still working (HSM ops on slow hardware take seconds — RSA-4096 keygen-adjacent ops excluded by design, but ECDH/AES on token HW is not instant). | Wait; apply a generous timeout (≥30 s), then reconnect. |

Rules of thumb: `denied` is always final for that input. `error` may be
transient (HSM busy) except `cert_policy_violation` and `invalid base64`,
which are final. Never cache `verified:true` across different data.

## 4. Example clients

Minimal roundtrip clients (sign/verify + encrypt/decrypt + tamper and
denied probes — mirroring each other):

| Language | File | Notes |
|---|---|---|
| Python | `examples/local_client_example.py` | Full demo incl. ECDH notes; run with `python`/`python3` |
| Rust | `examples/client_rust/` (mini-crate) | `tokio-rustls` + `serde_json`; `cargo run -- <host> <port> ...` |
| Go | `examples/client_go/main.go` | stdlib only (`crypto/tls`); `go run .` |
| Node.js | `examples/client_node.mjs` | stdlib only (`node:tls`); `node client_node.mjs` |
| Bash | `examples/client_bash.sh` | `openssl s_client` recipes; `jq` optional, falls back to `python3` |

All examples assume the §1 onboarding is done (matching CN in
`clients.yaml`, keys on the token) and default to `127.0.0.1:8443`.
They are syntax/compile-checked in CI-less fashion (`cargo check`,
`go vet`, `node --check`, `bash -n`); live runs happen against the
gateway (see README.md E2E section).
