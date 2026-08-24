"""
Beispiel-Client für das hsm-api-gateway — auch für lokale Produkte, die
bisher den pico-hsm-daemon (Unix-Socket) genutzt haben (siehe
MIGRATION.md).

Verbindung läuft über mTLS, auch wenn Gateway und Client auf demselben
Host laufen — keine Sonderbehandlung für "lokal" auf Protokollebene.

Voraussetzungen:
- Eigenes Client-Zertifikat + Key (siehe README.md, Abschnitt 4, oder
  eure interne CA für den Produktivbetrieb)
- Eintrag in clients.yaml mit den benötigten (operation, key_label)-Paaren
- Gateway läuft und lauscht (lokal z.B. auf 127.0.0.1:8443)

Ausführen:
    python3 examples/local_client_example.py \
        --host 127.0.0.1 --port 8443 \
        --client-cert certs/client-a.pem --client-key certs/client-a-key.pem \
        --ca-cert certs/ca.pem
"""

from __future__ import annotations

import argparse
import base64
import json
import ssl
import socket


class GatewayError(Exception):
    pass


class GatewayClient:
    def __init__(
        self,
        host: str,
        port: int,
        client_cert: str,
        client_key: str,
        ca_cert: str,
        timeout_seconds: float = 30.0,
    ):
        self.host = host
        self.port = port
        self.timeout_seconds = timeout_seconds

        self._ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self._ssl_context.load_verify_locations(cafile=ca_cert)
        self._ssl_context.load_cert_chain(certfile=client_cert, keyfile=client_key)
        # Server-Zertifikat muss zum verbundenen Hostnamen passen — bei
        # reinem IP-Verbindungsaufbau ggf. server_hostname explizit setzen
        # (siehe check_hostname/CN im Server-Zertifikat).

    def _call(self, request: dict) -> dict:
        with socket.create_connection(
            (self.host, self.port), timeout=self.timeout_seconds
        ) as sock:
            with self._ssl_context.wrap_socket(
                sock, server_hostname=self.host
            ) as tls_sock:
                tls_sock.sendall((json.dumps(request) + "\n").encode("utf-8"))

                buffer = b""
                while not buffer.endswith(b"\n"):
                    chunk = tls_sock.recv(4096)
                    if not chunk:
                        raise GatewayError("Verbindung vom Gateway geschlossen")
                    buffer += chunk

        response = json.loads(buffer.decode("utf-8"))
        status = response.get("status")
        if status == "denied":
            raise GatewayError(f"Autorisierung verweigert: {response.get('reason')}")
        if status == "error":
            raise GatewayError(f"Fehler: {response.get('message')}")
        return response

    @staticmethod
    def _b64(data: bytes) -> str:
        return base64.b64encode(data).decode("ascii")

    @staticmethod
    def _unb64(value: str) -> bytes:
        return base64.b64decode(value)

    # -- Öffentliche High-Level-Methoden, decken die 5 Gateway-Operationen ab --

    def sign(self, key_label: str, data: bytes, mechanism: str = "ecdsa_sha256") -> bytes:
        resp = self._call(
            {
                "op": "sign",
                "key_label": key_label,
                "mechanism": mechanism,
                "data_b64": self._b64(data),
            }
        )
        return self._unb64(resp["result_b64"])

    def verify(
        self, key_label: str, data: bytes, signature: bytes, mechanism: str = "ecdsa_sha256"
    ) -> bool:
        resp = self._call(
            {
                "op": "verify",
                "key_label": key_label,
                "mechanism": mechanism,
                "data_b64": self._b64(data),
                "signature_b64": self._b64(signature),
            }
        )
        return bool(resp["verified"])

    def encrypt(
        self, key_label: str, data: bytes, mechanism: str = "aes_cbc_pad"
    ) -> tuple[bytes, bytes, bytes]:
        """Gibt (ciphertext, iv, integrity) zurueck.

        Der IV wird vom Gateway pro Aufruf frisch generiert (kein
        fester/Null-IV mehr). `integrity` ist die Encrypt-then-Sign-
        Signatur ueber Key-Label, IV und Ciphertext.

        ALLE DREI Werte zusammen aufbewahren — ohne iv und integrity
        laesst sich der Ciphertext nicht mehr entschluesseln."""
        resp = self._call(
            {
                "op": "encrypt",
                "key_label": key_label,
                "mechanism": mechanism,
                "data_b64": self._b64(data),
            }
        )
        return (
            self._unb64(resp["result_b64"]),
            self._unb64(resp["iv_b64"]),
            self._unb64(resp["integrity_b64"]),
        )

    def decrypt(
        self,
        key_label: str,
        data: bytes,
        iv: bytes,
        integrity: bytes,
        mechanism: str = "aes_cbc_pad",
    ) -> bytes:
        """`iv` und `integrity` muessen aus dem passenden
        encrypt()-Aufruf stammen. Das Gateway prueft die Signatur, bevor
        es ueberhaupt entschluesselt — bei Manipulation kommt
        "status":"denied" zurueck und es wird nichts entschluesselt."""
        resp = self._call(
            {
                "op": "decrypt",
                "key_label": key_label,
                "mechanism": mechanism,
                "data_b64": self._b64(data),
                "iv_b64": self._b64(iv),
                "integrity_b64": self._b64(integrity),
            }
        )
        return self._unb64(resp["result_b64"])

    def derive_and_encrypt(
        self,
        key_label: str,
        plaintext: bytes,
        peer_public_key: bytes,
        derive_mechanism: str = "ecdh1_derive",
        target_mechanism: str = "aes_cbc_pad",
    ) -> tuple[bytes, bytes, bytes]:
        """Ersatz für das bisherige WrapKey des Python-Daemons — Ableitung
        und Verschlüsselung passieren atomar in einer HSM-Session, siehe
        MIGRATION.md.

        `peer_public_key` ist der Public Key der Gegenseite für
        ECDH1_DERIVE. Pflicht — und er muss in clients.yaml unter
        peer_public_keys freigegeben sein, sonst kommt "denied" zurueck.

        Gibt (ciphertext, iv, integrity) zurück, analog zu encrypt()."""
        resp = self._call(
            {
                "op": "derive_and_encrypt",
                "key_label": key_label,
                "derive_mechanism": derive_mechanism,
                "target_mechanism": target_mechanism,
                "peer_public_key_b64": self._b64(peer_public_key),
                "data_b64": self._b64(plaintext),
            }
        )
        return (
            self._unb64(resp["result_b64"]),
            self._unb64(resp["iv_b64"]),
            self._unb64(resp["integrity_b64"]),
        )

    def derive_and_decrypt(
        self,
        key_label: str,
        ciphertext: bytes,
        peer_public_key: bytes,
        iv: bytes,
        integrity: bytes,
        derive_mechanism: str = "ecdh1_derive",
        target_mechanism: str = "aes_cbc_pad",
    ) -> bytes:
        """Ersatz für das bisherige UnwrapKey des Python-Daemons. `iv` und
        `integrity` muessen aus der passenden derive_and_encrypt()-Antwort
        stammen.

        Hinweis: derive_and_encrypt und derive_and_decrypt sind getrennte
        Permissions — ein Client, der nur wrappen soll, bekommt fuer
        diesen Aufruf bewusst "denied"."""
        resp = self._call(
            {
                "op": "derive_and_decrypt",
                "key_label": key_label,
                "derive_mechanism": derive_mechanism,
                "target_mechanism": target_mechanism,
                "peer_public_key_b64": self._b64(peer_public_key),
                "iv_b64": self._b64(iv),
                "integrity_b64": self._b64(integrity),
                "data_b64": self._b64(ciphertext),
            }
        )
        return self._unb64(resp["result_b64"])


def main():
    parser = argparse.ArgumentParser(description="Beispiel-Client für hsm-api-gateway")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--client-cert", required=True)
    parser.add_argument("--client-key", required=True)
    parser.add_argument("--ca-cert", required=True)
    parser.add_argument(
        "--key-label",
        default="shared-encryption-key",
        help="Muss zu einem Eintrag in clients.yaml für dieses Client-Zertifikat passen",
    )
    args = parser.parse_args()

    client = GatewayClient(
        host=args.host,
        port=args.port,
        client_cert=args.client_cert,
        client_key=args.client_key,
        ca_cert=args.ca_cert,
    )

    payload = b"Beispiel-Nutzdaten"
    ciphertext, iv, integrity = client.encrypt(key_label=args.key_label, data=payload)
    print(f"Verschlüsselt, {len(ciphertext)} Bytes, IV: {iv.hex()}")

    plaintext = client.decrypt(
        key_label=args.key_label, data=ciphertext, iv=iv, integrity=integrity
    )
    assert plaintext == payload, "Encrypt/Decrypt-Roundtrip fehlgeschlagen!"
    print("✓ Encrypt/Decrypt-Roundtrip erfolgreich")

    # Gegenprobe: ein manipulierter Ciphertext muss abgelehnt werden,
    # bevor ueberhaupt entschluesselt wird.
    tampered = bytearray(ciphertext)
    tampered[0] ^= 0x01
    try:
        client.decrypt(
            key_label=args.key_label,
            data=bytes(tampered),
            iv=iv,
            integrity=integrity,
        )
    except GatewayError:
        print("✓ Manipulierter Ciphertext wurde abgelehnt")
    else:
        raise SystemExit("FEHLER: manipulierter Ciphertext wurde akzeptiert!")


if __name__ == "__main__":
    main()
