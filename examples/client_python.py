"""
Example client for pico-hsm-api-connector — including local products that
previously used a Unix-socket daemon.

The connection uses mTLS even when gateway and client run on the same host;
there is no "local" special case on the protocol level.

Prerequisites:
- Own client certificate + key (see README.md; the cert CN must match an
  entry in clients.yaml with the required (operation, key_label) pairs)
- Gateway running and listening (locally e.g. on 127.0.0.1:8443)

Usage:
    python3 examples/local_client_example.py \
        --host 127.0.0.1 --port 8443 \
        --client-cert certs/client-a.pem --client-key certs/client-a-key.pem \
        --ca-cert certs/ca.pem
"""

from __future__ import annotations

import argparse
import base64
import json
import socket
import ssl


class GatewayError(Exception):
    pass


class GatewayClient:
    def __init__(self, host: str, port: int, client_cert: str, client_key: str, ca_cert: str):
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_cert)
        ctx.load_cert_chain(certfile=client_cert, keyfile=client_key)
        ctx.check_hostname = False
        raw = socket.create_connection((host, port))
        self._sock = ctx.wrap_socket(raw, server_hostname=host)
        self._file = self._sock.makefile("r")

    def request(self, payload: dict) -> dict:
        line = json.dumps(payload) + "\n"
        self._sock.sendall(line.encode())
        answer = self._file.readline()
        if not answer:
            raise GatewayError("connection closed by gateway")
        return json.loads(answer)

    def close(self) -> None:
        try:
            self._file.close()
        finally:
            self._sock.close()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def demo_sign_verify(client: GatewayClient, key_label: str) -> None:
    print(f"--- sign/verify with {key_label!r} ---")
    data = b64(b"hello pico-hsm")
    sig_resp = client.request({
        "op": "sign",
        "key_label": key_label,
        "mechanism": "ecdsa_sha256",
        "data_b64": data,
    })
    print("sign:", sig_resp)
    assert sig_resp.get("status") == "ok", sig_resp

    verify_resp = client.request({
        "op": "verify",
        "key_label": key_label,
        "mechanism": "ecdsa_sha256",
        "data_b64": data,
        "signature_b64": sig_resp["result_b64"],
    })
    print("verify:", verify_resp)
    assert verify_resp.get("status") == "ok" and verify_resp.get("verified") is True


def demo_encrypt_decrypt(client: GatewayClient, key_label: str) -> None:
    print(f"--- encrypt/decrypt with {key_label!r} ---")
    enc = client.request({
        "op": "encrypt",
        "key_label": key_label,
        "mechanism": "aes_cbc_pad",
        "data_b64": b64(b"secret message"),
    })
    print("encrypt:", {k: (v[:16] + "..." if isinstance(v, str) and len(v) > 20 else v)
                       for k, v in enc.items()})
    assert enc.get("status") == "ok", enc
    # iv_b64 + integrity_b64 must be stored with the ciphertext and sent back.
    dec = client.request({
        "op": "decrypt",
        "key_label": key_label,
        "mechanism": "aes_cbc_pad",
        "data_b64": enc["result_b64"],
        "iv_b64": enc["iv_b64"],
        "integrity_b64": enc["integrity_b64"],
    })
    print("decrypt:", dec)
    assert dec.get("status") == "ok", dec
    assert base64.b64decode(dec["result_b64"]) == b"secret message"

    # Tamper probe: flip a ciphertext byte -> integrity check must refuse
    # BEFORE any decrypt happens (no padding oracle).
    raw = bytearray(base64.b64decode(enc["result_b64"]))
    raw[0] ^= 0x01
    tampered = client.request({
        "op": "decrypt",
        "key_label": key_label,
        "mechanism": "aes_cbc_pad",
        "data_b64": b64(bytes(raw)),
        "iv_b64": enc["iv_b64"],
        "integrity_b64": enc["integrity_b64"],
    })
    print("tampered decrypt (must NOT be ok):", tampered)
    assert tampered.get("status") != "ok", tampered


def demo_denied(client: GatewayClient) -> None:
    print("--- authorization probe (must be denied) ---")
    resp = client.request({
        "op": "sign",
        "key_label": "key-this-client-must-not-use",
        "mechanism": "ecdsa_sha256",
        "data_b64": b64(b"nope"),
    })
    print("denied probe:", resp)
    assert resp.get("status") == "denied", resp


def main() -> None:
    ap = argparse.ArgumentParser(description="Example client for pico-hsm-api-connector")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--client-cert", required=True)
    ap.add_argument("--client-key", required=True)
    ap.add_argument("--ca-cert", required=True)
    ap.add_argument("--sign-key", default="app-b-signing-key")
    ap.add_argument("--enc-key", default="shared-encryption-key")
    args = ap.parse_args()

    client = GatewayClient(args.host, args.port, args.client_cert, args.client_key, args.ca_cert)
    try:
        demo_sign_verify(client, args.sign_key)
        demo_encrypt_decrypt(client, args.enc_key)
        demo_denied(client)
        print("All demos passed.")
    finally:
        client.close()


if __name__ == "__main__":
    main()
