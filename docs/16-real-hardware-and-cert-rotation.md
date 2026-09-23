# Real hardware + certificate rotation runbook

Complements `README.md` (which covers the SoftHSM2 path without hardware).
This document covers the switch to the real board and the day-to-day
operation of the mTLS certificates.

> Verified 2026-09-23 against a real Pico-HSM (token `Pico-HSM`, FW 6.6):
> slot/token detection, PIN login, `sign → ok`, `verify → verified:true`,
> `denied` path, and cert-policy reject all pass on native Windows via
> `opensc-pkcs11.dll`. AES operations could not be exercised there
> (OpenSC sc-hsm driver has no AES) — they require `libsc-hsm-pkcs11.so`
> (Linux/WSL, see §1).

## 1. Switching from SoftHSM2 to real hardware

Compared to the SoftHSM2 test run, only one variable changes:

```bash
# Instead of:
# export GATEWAY_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so  (Linux)
#   or a SoftHSM2 DLL path (Windows)

# Now (Linux):
export GATEWAY_PKCS11_MODULE=/usr/lib/libsc-hsm-pkcs11.so
export GATEWAY_HSM_PIN="<real user PIN, runtime-injected>"
```

**IMPORTANT: `libsc-hsm-pkcs11.so`, NOT `opensc-pkcs11.so`.** OpenSC's sc-hsm
driver supports no AES for the Pico HSM — `encrypt`/`decrypt` and both
`derive_and_*` operations (all AES-CBC based) fail with it; `sign`/`verify`
work with either module. The full mechanism matrix must be run exclusively
against `libsc-hsm-pkcs11.so` before production.

The gateway additionally needs its **integrity key** for Encrypt-then-Sign
(see README.md) — its own EC keypair, never granted to any client:

```bash
pkcs11-tool --module /usr/lib/libsc-hsm-pkcs11.so --login --pin <PIN> \
    --keypairgen --key-type EC:secp256r1 --label "gateway-integrity-key"
```

**Rotation warning:** replacing this key orphans **all previously encrypted
data** — their integrity signatures no longer verify, so nothing can be
decrypted anymore. The integrity key belongs in the same protection class
as the application keys (firmware backup flow), NOT in routine certificate
rotation. Plan integrity-key rotation as a data-migration event
(decrypt everything with the old key, rotate, re-encrypt), never as a
silent swap.

Application keys (`shared-encryption-key`, `app-b-signing-key`, …) are
created the same way, manually on the host — key creation is deliberately
not part of the gateway API.

## 2. Secrets overview

| Secret | Where | Rotation |
|---|---|---|
| `GATEWAY_HSM_PIN` | Runtime-injected env, never on disk/in repo (zeroized in process memory) | Firmware PIN change (`pkcs11-tool --change-pin`); gateway restart picks it up |
| `GATEWAY_SERVER_KEY` | Gateway host filesystem, readable only by the service account | §4 |
| Client keys | Each client's own host, never on the gateway | §3 (client side) |
| Client CA key | **Offline** — ideally not on the gateway host at all | §6 (emergency only) |
| `clients.yaml` | `GATEWAY_CLIENTS_CONFIG` path, gateway host | Edit + **gateway restart** (config is loaded once at startup, not watched) |
| Audit log | `GATEWAY_AUDIT_LOG` path | Append-only; see §7 |

## 3. Client certificate rotation (routine)

Client certs are short-lived by policy (default: max 90 days validity,
warning at 14 days before expiry — the gateway logs `cert_expiring_soon`
so rotation is noticed *before* the hard TLS failure).

```bash
# 1. Issue (CN must match clients.yaml):
openssl req -newkey rsa:2048 -nodes -keyout client-key.pem \
    -out client.csr -subj "/CN=app-a.internal.example"
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca-key.pem \
    -CAcreateserial -days 30 -out client.pem
rm client.csr

# 2. Deploy key+cert to the client host, restart/reload the client.

# 3. Verify: one request through the gateway; a denied/ok answer both
#    prove the handshake works (only TLS errors mean cert trouble).
```

Keep `-days` well under `GATEWAY_MAX_CLIENT_CERT_VALIDITY_DAYS` — a cert
valid longer than the maximum is rejected with `cert_policy_violation`
(this catches a misconfigured CA, not just a single bad cert). A second
cert with `-days 200` against the default 90-day policy is the standard
negative test.

## 4. Server certificate rotation

```bash
openssl req -newkey rsa:2048 -nodes -keyout server-key.pem \
    -out server.csr -subj "/CN=<gateway-host>"
# 2. Write the SAN extension to a file (portable, no shell substitution):
printf 'subjectAltName=IP:127.0.0.1,DNS:localhost\n' > server.ext
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem \
    -CAcreateserial -days 825 -out server.pem -extfile server.ext
```

Replace `GATEWAY_SERVER_CERT`/`GATEWAY_SERVER_KEY` and restart the gateway.
Clients pinning the CA (not the leaf) need no change. Coordinate a
maintenance window: in-flight requests are dropped by the restart (the
protocol is stateless per line, so clients can simply retry).

## 5. Emergency: blocking a compromised client

No CRL/OCSP exists by design. To block a compromised but still-valid
client certificate:

1. Remove its CN entry from `clients.yaml`.
2. Restart the gateway (config is load-once).
3. Confirm in the audit log: new requests from that CN must show
   `denied` (and any prior abuse is traceable via the hash chain).
4. Rotate the replacement cert per §3 when ready.

Response time beats elegance here — steps 1–2 take under a minute.

## 6. Emergency: CA compromise

1. Generate a new CA offline.
2. Re-issue server cert (§4) + all client certs (§3).
3. Replace `GATEWAY_CLIENT_CA`, server cert/key, restart the gateway.
4. Old certs become invalid at once (trust anchor swapped) — every client
   must hold its new cert before the swap, so prepare first, switch fast.

## 7. Audit log rotation

The log is append-only and hash-chained; `verify_chain()` runs at every
gateway start. To rotate:

1. Stop the gateway (or accept that the tail entry may be mid-write —
   a lone `intent` means "unknown outcome" by design).
2. Move the file aside (keep it — it is the tamper-evidence record).
3. Start the gateway; a fresh chain begins at `GENESIS`.

Never edit a log file in place — any modification breaks the chain and
the gateway will refuse to open it.
