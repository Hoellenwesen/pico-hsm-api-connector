# Running the gateway on Linux (incl. systemd service)

How to install, run, and operate `pico-hsm-api-connector` on a Linux host
with the Pico-HSM attached via USB. Distro-neutral: package names below
use Debian/Ubuntu as an example (`apt`); on other distros install the
equivalent packages (`pcscd` + CCID driver, `opensc`, `openssl`).

> Client side (how tools talk to the gateway): `docs/18-client-integration.md`.
> Hardware + certificate rotation runbook: `docs/16-real-hardware-and-cert-rotation.md`.

## 1. Prerequisites

- **Rust via `rustup`** (≥1.85). Do NOT use the distro Rust (1.75 fails on
  `chrono`/`indexmap`/`aws-lc-sys`):
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  source "$HOME/.cargo/env"
  rustc --version
  ```
- **Smartcard access to the board**: `pcscd` + CCID driver so the Pico
  appears as a smartcard reader (`opensc-tool --list-readers` must show it,
  card present). Example (Debian/Ubuntu):
  ```bash
  sudo apt install -y pcscd libccid opensc openssl
  opensc-tool --list-readers
  ```
- **PKCS#11 module**: production `libsc-hsm-pkcs11.so` — NOT
  `opensc-pkcs11.so`, whose sc-hsm driver has no AES (encrypt/decrypt and
  both `derive_and_*` operations fail with it; sign/verify work with either).
- **Certificates**: server cert + key, client CA (see `docs/16`, §3–§4 for
  issuance). The service account needs read access to all of them.

## 2. Build and install layout

```bash
cargo build --release
sudo install -m 0755 target/release/pico-hsm-api-connector /usr/local/bin/
```

Suggested layout (adapt paths to your distro conventions):

| Path | Content | Permissions |
|---|---|---|
| `/usr/local/bin/pico-hsm-api-connector` | binary | `0755 root:root` |
| `/etc/hsm-gateway/env` | all `GATEWAY_*` vars incl. `GATEWAY_HSM_PIN` | `0640 root:hsm-gateway` |
| `/etc/hsm-gateway/server.pem`, `server-key.pem` | server cert + key | `0640 root:hsm-gateway` |
| `/etc/hsm-gateway/client-ca.pem` | client CA | `0640 root:hsm-gateway` |
| `/etc/hsm-gateway/clients.yaml` | authorization table (from `config/clients.example.yaml`) | `0640 root:hsm-gateway` |
| `/var/log/hsm-gateway/audit.jsonl` | hash-chained audit log | writable by service user |

`/etc/hsm-gateway/env` (all nine required, no defaults for secrets):

```bash
GATEWAY_LISTEN_ADDR="0.0.0.0:8443"
GATEWAY_SERVER_CERT=/etc/hsm-gateway/server.pem
GATEWAY_SERVER_KEY=/etc/hsm-gateway/server-key.pem
GATEWAY_CLIENT_CA=/etc/hsm-gateway/client-ca.pem
GATEWAY_CLIENTS_CONFIG=/etc/hsm-gateway/clients.yaml
GATEWAY_PKCS11_MODULE=/usr/lib/libsc-hsm-pkcs11.so
GATEWAY_HSM_PIN="<inject securely, never commit>"
GATEWAY_AUDIT_LOG=/var/log/hsm-gateway/audit.jsonl
GATEWAY_INTEGRITY_KEY_LABEL=gateway-integrity-key
# Optional (defaults 90 / 14):
# GATEWAY_MAX_CLIENT_CERT_VALIDITY_DAYS=90
# GATEWAY_CERT_EXPIRY_WARN_DAYS=14
# RUST_LOG=info
```

## 3. Service user and USB access

Do NOT run the gateway as root. Create a dedicated system user:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin hsm-gateway
```

Trade-off documented deliberately: a `DynamicUser=` unit looks tidier but
its shifting UID/GID complicates USB device ACLs and audit-log persistence
across restarts — a static system user plus a `udev` rule is the predictable
choice. Grant USB access with a device rule (verify VID/PID against your
board with `lsusb`; Pico VID is `2e8a`):

```
# /etc/udev/rules.d/99-pico-hsm.rules
SUBSYSTEM=="usb", ATTRS{idVendor}=="2e8a", GROUP="hsm-gateway", MODE="0660"
```

```bash
sudo udevadm control --reload-rules && sudo udevadm trigger
```

> The exact `ATTRS` match (interface, product) is marked for verification
> against real hardware on Linux — adjust after `lsusb -v` on your board.

## 4. systemd unit

A ready unit ships at `contrib/pico-hsm-api-connector.service`:

```bash
sudo install -m 0644 contrib/pico-hsm-api-connector.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now pico-hsm-api-connector
sudo systemctl status pico-hsm-api-connector
journalctl -u pico-hsm-api-connector -f   # logs (RUST_LOG tunable via env file)
```

The unit sets `Restart=always`, `NoNewPrivileges`, `ProtectSystem=strict`,
`PrivateTmp`, and keeps `/var/log/hsm-gateway` writable. USB access comes
from the §3 `udev` rule, not from a broad device policy — tighten
`DeviceAllow=` further only after testing against your board.

## 5. Operating notes

- **Config changes need a restart**: `clients.yaml` is loaded once at
  startup (`sudo systemctl restart pico-hsm-api-connector`). In-flight
  requests are dropped; the protocol is stateless per line, so clients
  simply reconnect and retry the unanswered request.
- **Updates**: replace the binary, `restart`. Same drop-and-retry semantics.
- **Health check**: one `verify` (or any authorized no-op-shaped call) over
  mTLS — `ok`/`denied` both prove the stack is up; only TLS errors or
  timeouts mean trouble. See `examples/client_bash.sh` for a dependency-free
  probe.
- **Audit log**: append-only, hash-chained, verified at every start; rotate
  per `docs/16`, §7.
- **Backup**: `clients.yaml`, env file (secrets vault!), audit logs. Keys
  stay in the HSM (firmware backup flow) — never exportable by design.
