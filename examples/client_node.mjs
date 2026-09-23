// Minimal example client for pico-hsm-api-connector (stdlib only).
//
// Mirrors examples/local_client_example.py: sign/verify + encrypt/decrypt
// roundtrips plus a tamper probe and a denied probe.
//
// Usage:
//   node client_node.mjs <host> <port> <client-cert> <client-key> <ca-cert> [sign-key] [enc-key]

import tls from 'node:tls';
import readline from 'node:readline';
import fs from 'node:fs';

const [host, port, certFile, keyFile, caFile] = process.argv.slice(2, 7);
const signKey = process.argv[7] ?? 'app-b-signing-key';
const encKey = process.argv[8] ?? 'shared-encryption-key';
if (!host || !port) {
  console.error('usage: node client_node.mjs <host> <port> <client-cert> <client-key> <ca-cert> [sign-key] [enc-key]');
  process.exit(2);
}

const socket = tls.connect({
  host,
  port: Number(port),
  cert: fs.readFileSync(certFile),
  key: fs.readFileSync(keyFile),
  ca: fs.readFileSync(caFile),
  // Hostname check against the test cert: disabled here like in the
  // Python example (production: use proper SANs + checkServerIdentity).
  checkServerIdentity: () => undefined,
});
await new Promise((resolve, reject) => {
  socket.once('secureConnect', resolve);
  socket.once('error', reject);
});

const rl = readline.createInterface({ input: socket, crlfDelay: Infinity });
const pending = [];
rl.on('line', (line) => {
  if (!line.trim()) return;
  const next = pending.shift();
  if (next) next(JSON.parse(line));
});

function request(payload) {
  return new Promise((resolve) => {
    pending.push(resolve);
    socket.write(JSON.stringify(payload) + '\n');
  });
}
const b64 = (s) => Buffer.from(s).toString('base64');
function expect(resp, want, label) {
  if (resp.status !== want) {
    console.error(`${label}: want status ${want}, got:`, resp);
    process.exit(1);
  }
}

// sign/verify
const data = b64('hello pico-hsm');
const sign = await request({ op: 'sign', key_label: signKey, mechanism: 'ecdsa_sha256', data_b64: data });
expect(sign, 'ok', 'sign');
console.log('sign: ok');
const verify = await request({ op: 'verify', key_label: signKey, mechanism: 'ecdsa_sha256', data_b64: data, signature_b64: sign.result_b64 });
expect(verify, 'ok', 'verify');
if (verify.verified !== true) { console.error('verify: expected verified=true'); process.exit(1); }
console.log('verify: verified=true');

// encrypt/decrypt
const enc = await request({ op: 'encrypt', key_label: encKey, mechanism: 'aes_cbc_pad', data_b64: b64('secret message') });
expect(enc, 'ok', 'encrypt');
console.log('encrypt: ok (+iv +integrity)');
const dec = await request({ op: 'decrypt', key_label: encKey, mechanism: 'aes_cbc_pad', data_b64: enc.result_b64, iv_b64: enc.iv_b64, integrity_b64: enc.integrity_b64 });
expect(dec, 'ok', 'decrypt');
if (Buffer.from(dec.result_b64, 'base64').toString() !== 'secret message') { console.error('decrypt: plaintext mismatch'); process.exit(1); }
console.log('decrypt: ok');

// tamper probe: must NOT be ok
const raw = Buffer.from(enc.result_b64, 'base64');
raw[0] ^= 0x01;
const tampered = await request({ op: 'decrypt', key_label: encKey, mechanism: 'aes_cbc_pad', data_b64: raw.toString('base64'), iv_b64: enc.iv_b64, integrity_b64: enc.integrity_b64 });
if (tampered.status === 'ok') { console.error('tamper probe: ciphertext accepted, MUST NOT happen'); process.exit(1); }
console.log('tampered decrypt refused, as expected');

// denied probe
const denied = await request({ op: 'sign', key_label: 'key-this-client-must-not-use', mechanism: 'ecdsa_sha256', data_b64: b64('nope') });
expect(denied, 'denied', 'denied probe');
console.log('denied probe: ok');

console.log('All demos passed.');
socket.end();
rl.close();
