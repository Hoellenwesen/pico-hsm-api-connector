#!/usr/bin/env bash
# Minimal s_client recipes for pico-hsm-api-connector (no SDK needed).
#
# Usage:
#   ./client_bash.sh <host> <port> <client-cert> <client-key> <ca-cert> [sign-key] [enc-key]
#
# Sends one request per line over a single mTLS session and checks the
# answers. Requires: openssl, python3 (for JSON checks; plain grep fallback
# if you strip the check() calls). Exits non-zero on the first failure.
set -euo pipefail

HOST_="${1:?usage: $0 <host> <port> <client-cert> <client-key> <ca-cert> [sign-key] [enc-key]}"
PORT_="${2:?usage: $0 <host> <port> <client-cert> <client-key> <ca-cert> [sign-key] [enc-key]}"
CERT_="${3:?usage: $0 <host> <port> <client-cert> <client-key> <ca-cert> [sign-key] [enc-key]}"
KEY_="${4:?usage: $0 <host> <port> <client-cert> <client-key> <ca-cert> [sign-key] [enc-key]}"
CA_="${5:?usage: $0 <host> <port> <client-cert> <client-key> <ca-cert> [sign-key] [enc-key]}"
SIGN_KEY="${6:-app-b-signing-key}"
ENC_KEY="${7:-shared-encryption-key}"

B64() { printf '%s' "$1" | openssl base64 -A; }

# check <response-line> <want-status> <label>
check() {
  local status
  status="$(printf '%s' "$1" | python3 -c 'import json,sys; print(json.load(sys.stdin)["status"])')"
  if [ "$status" != "$2" ]; then
    echo "FAIL [$3]: want status $2, got: $1" >&2
    exit 1
  fi
  echo "ok [$3]"
}

coproc GW { openssl s_client -connect "${HOST_}:${PORT_}" -cert "$CERT_" -key "$KEY_" -CAfile "$CA_" -quiet 2>/dev/null; }
trap 'kill "$GW_PID" 2>/dev/null' EXIT

ask() { printf '%s\n' "$1" >&"${GW[1]}"; IFS= read -r -u "${GW[0]}" RESP; printf '%s' "$RESP"; }

DATA="$(B64 'hello pico-hsm')"

# sign/verify
SIG_RESP="$(ask "{\"op\":\"sign\",\"key_label\":\"$SIGN_KEY\",\"mechanism\":\"ecdsa_sha256\",\"data_b64\":\"$DATA\"}")"
check "$SIG_RESP" ok "sign"
SIG="$(printf '%s' "$SIG_RESP" | python3 -c 'import json,sys; print(json.load(sys.stdin)["result_b64"])')"
VERIFY_RESP="$(ask "{\"op\":\"verify\",\"key_label\":\"$SIGN_KEY\",\"mechanism\":\"ecdsa_sha256\",\"data_b64\":\"$DATA\",\"signature_b64\":\"$SIG\"}")"
check "$VERIFY_RESP" ok "verify"

# encrypt/decrypt
ENC_RESP="$(ask "{\"op\":\"encrypt\",\"key_label\":\"$ENC_KEY\",\"mechanism\":\"aes_cbc_pad\",\"data_b64\":\"$(B64 'secret message')\"}")"
check "$ENC_RESP" ok "encrypt"
CT="$(printf '%s' "$ENC_RESP" | python3 -c 'import json,sys; print(json.load(sys.stdin)["result_b64"])')"
IV="$(printf '%s' "$ENC_RESP" | python3 -c 'import json,sys; print(json.load(sys.stdin)["iv_b64"])')"
INT="$(printf '%s' "$ENC_RESP" | python3 -c 'import json,sys; print(json.load(sys.stdin)["integrity_b64"])')"
DEC_RESP="$(ask "{\"op\":\"decrypt\",\"key_label\":\"$ENC_KEY\",\"mechanism\":\"aes_cbc_pad\",\"data_b64\":\"$CT\",\"iv_b64\":\"$IV\",\"integrity_b64\":\"$INT\"}")"
check "$DEC_RESP" ok "decrypt"

# denied probe (must be denied, never ok)
DENIED_RESP="$(ask '{"op":"sign","key_label":"key-this-client-must-not-use","mechanism":"ecdsa_sha256","data_b64":"bm9wZQ=="}')"
check "$DENIED_RESP" denied "denied probe"

echo "All bash probes passed."
