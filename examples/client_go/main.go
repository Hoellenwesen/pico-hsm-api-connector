// Minimal example client for pico-hsm-api-connector (stdlib only).
//
// Mirrors examples/local_client_example.py: sign/verify + encrypt/decrypt
// roundtrips plus a tamper probe and a denied probe.
//
// Usage:
//
//	go run . <host> <port> <client-cert> <client-key> <ca-cert> [sign-key] [enc-key]
package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
)

type Client struct {
	conn *tls.Conn
	r    *bufio.Reader
}

func Connect(host, port, certFile, keyFile, caFile string) (*Client, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load client cert: %w", err)
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("invalid CA cert")
	}
	conn, err := tls.Dial("tcp", net.JoinHostPort(host, port), &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      roots,
		ServerName:   host,
	})
	if err != nil {
		return nil, fmt.Errorf("TLS handshake (cert? CA? expiry?): %w", err)
	}
	return &Client{conn: conn, r: bufio.NewReader(conn)}, nil
}

func (c *Client) Request(payload map[string]any) (map[string]any, error) {
	line, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	line = append(line, '\n')
	if _, err := c.conn.Write(line); err != nil {
		return nil, err
	}
	answer, err := c.r.ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("connection closed by gateway: %w", err)
	}
	var resp map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(answer), &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func must(resp map[string]any, err error, want string) map[string]any {
	if err != nil {
		fmt.Fprintln(os.Stderr, "request failed:", err)
		os.Exit(1)
	}
	if resp["status"] != want {
		fmt.Fprintf(os.Stderr, "want status %q, got: %v\n", want, resp)
		os.Exit(1)
	}
	return resp
}

func main() {
	if len(os.Args) < 6 {
		fmt.Fprintln(os.Stderr, "usage: client <host> <port> <client-cert> <client-key> <ca-cert> [sign-key] [enc-key]")
		os.Exit(2)
	}
	signKey, encKey := "app-b-signing-key", "shared-encryption-key"
	if len(os.Args) > 6 {
		signKey = os.Args[6]
	}
	if len(os.Args) > 7 {
		encKey = os.Args[7]
	}
	c, err := Connect(os.Args[1], os.Args[2], os.Args[3], os.Args[4], os.Args[5])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer c.conn.Close()

	data := b64([]byte("hello pico-hsm"))
	sign, err := c.Request(map[string]any{"op": "sign", "key_label": signKey, "mechanism": "ecdsa_sha256", "data_b64": data})
	must(sign, err, "ok")
	fmt.Println("sign: ok")
	verify, err := c.Request(map[string]any{"op": "verify", "key_label": signKey, "mechanism": "ecdsa_sha256", "data_b64": data, "signature_b64": sign["result_b64"]})
	must(verify, err, "ok")
	if verify["verified"] != true {
		fmt.Fprintln(os.Stderr, "verify: expected verified=true, got:", verify)
		os.Exit(1)
	}
	fmt.Println("verify: verified=true")

	enc, err := c.Request(map[string]any{"op": "encrypt", "key_label": encKey, "mechanism": "aes_cbc_pad", "data_b64": b64([]byte("secret message"))})
	must(enc, err, "ok")
	fmt.Println("encrypt: ok (+iv +integrity)")
	dec, err := c.Request(map[string]any{"op": "decrypt", "key_label": encKey, "mechanism": "aes_cbc_pad", "data_b64": enc["result_b64"], "iv_b64": enc["iv_b64"], "integrity_b64": enc["integrity_b64"]})
	must(dec, err, "ok")
	pt, _ := base64.StdEncoding.DecodeString(dec["result_b64"].(string))
	if string(pt) != "secret message" {
		fmt.Fprintln(os.Stderr, "decrypt: plaintext mismatch")
		os.Exit(1)
	}
	fmt.Println("decrypt: ok")

	raw, _ := base64.StdEncoding.DecodeString(enc["result_b64"].(string))
	raw[0] ^= 0x01
	tampered, err := c.Request(map[string]any{"op": "decrypt", "key_label": encKey, "mechanism": "aes_cbc_pad", "data_b64": b64(raw), "iv_b64": enc["iv_b64"], "integrity_b64": enc["integrity_b64"]})
	if err != nil {
		fmt.Fprintln(os.Stderr, "tamper probe failed:", err)
		os.Exit(1)
	}
	if tampered["status"] == "ok" {
		fmt.Fprintln(os.Stderr, "tamper probe: ciphertext accepted, MUST NOT happen")
		os.Exit(1)
	}
	fmt.Println("tampered decrypt refused, as expected")

	denied, err := c.Request(map[string]any{"op": "sign", "key_label": "key-this-client-must-not-use", "mechanism": "ecdsa_sha256", "data_b64": b64([]byte("nope"))})
	must(denied, err, "denied")
	fmt.Println("denied probe: ok")
	fmt.Println("All demos passed.")
}
