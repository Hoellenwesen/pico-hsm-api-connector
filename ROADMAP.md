# Roadmap — pico-hsm-api-connector

Single progress document: status legend below, milestones with what/why,
dependencies, and rough effort. Details live in the referenced docs —
nothing is tracked in parallel anywhere else. Flip milestones to ✅ when done.

Legend: ✅ done · ▶ next · ○ planned · ⏸ parked

## M1 — MVP against real hardware ✅ (2026-09-23, Pico-HSM FW 6.6, OpenSC driver)

- USB slot/token detection, PIN login, `HsmClient::connect` green.
- `sign → ok` with real HSM signature; `verify → verified:true` roundtrip.
- `denied` path without HSM contact (audited); 200-day cert rejected
  (`cert_policy_violation`, audited); two-phase audit (`intent → authorized/denied/error`).
- `cargo check` warning-free, `cargo test` 20/20, `cargo build --release` green.
- Greenfield rebuild complete: `protocol.rs`, `config.rs`, `audit.rs`,
  `hsm.rs` (cryptoki 0.12), `server.rs`, `main.rs`, English docs
  (README, `docs/16`, `docs/17`, `docs/18`), example clients
  (Python, Rust, Go, Node.js, Bash — live run: Python only so far).

## M2 — Complete hardware coverage ▶ (priority 1)

1. **Integrity key on the token** (`--keypairgen EC:secp256r1`, label
   `gateway-integrity-key`; never granted to clients). *Why: blocks every
   encrypt E2E until it exists. Effort: minutes.*
2. **AES matrix exclusively via `libsc-hsm-pkcs11.so`** (Linux/WSL — OpenSC's
   sc-hsm driver has no AES, so encrypt/decrypt/derive are unexercised).
   *Depends on: Linux environment + integrity key. Effort: ~0.5 day incl. setup.*
3. **`CKD_SHA256_KDF` verification** — whether `sc-hsm-embedded` honors the
   KDF (`EcKdf::sha256()` with fixed domain `shared_data`) or silently
   returns raw secrets. *Why: determines NIST-SP-800-56A posture before
   production. Depends on: (2). Effort: hours.*
4. **ECDH derive smoke** with `hw-dkek1` (token reports `derive` usage):
   `derive_and_encrypt → derive_and_decrypt` roundtrip. *Depends on: (2), (3).*
5. **SoftHSM2 E2E path** run end-to-end for the first time (authz/mTLS/protocol
   without hardware). *Depends on: Linux environment. Effort: hours.*

## M3 — Client E2E matrix ○

- Live runs of the Rust, Go, Node.js and Bash example clients against the
  gateway (currently only compile/syntax-checked; Python already ran against
  hardware). Check off per language. *Depends on: running gateway (M2 env).
  Effort: ~0.5 day incl. fixes.*
- SoftHSM2 covers authz/mTLS/protocol but NOT exact firmware mechanism
  behavior — a green SoftHSM run never replaces the real-board run.

## M4 — Linux service deployment ○

- Deploy per `docs/17-linux-service.md`; verify `udev` `ATTRS` matches
  (`lsusb -v`) and test `DeviceAllow` hardening against the board.
  *Depends on: M2 environment. Effort: ~0.5 day.*
- Dry-run one client rotation + one server rotation per `docs/16`.
  *Effort: hours.*

## M5 — Hardening / extensions ○

- **RSA-PKCS/PSS mechanisms** (firmware supports RSA 1024–4096): extend
  mechanism allowlist in `server.rs` + methods in `hsm.rs`. *Effort: ~1 day
  incl. hardware roundtrips.*
- **Per-client rate limiting** (known conscious gap): a compromised but
  correctly authorized client cert can issue unlimited operations. Revisit
  when client count or threat level grows.
- **Threat model**: full document only once a `docs/11` exists in the
  firmware project; until then the README summary stands.

## ⏸ Parked

- **AES negative proof via OpenSC** (expected: HSM-level `error`, not
  `denied` — proves requests pass authz/audit/session and fail in the
  driver). Recipe ready: create AES test key on token, add
  encrypt/decrypt for it to `clients.yaml`, restart gateway, send one
  `encrypt` line via `s_client`. Deliberately deferred, no information lost.
