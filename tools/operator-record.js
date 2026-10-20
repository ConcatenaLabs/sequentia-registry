#!/usr/bin/env node
'use strict';
// Writes an Arca operator's record for the registry, unsigned, from the
// operator's own GET /v1/info: what operators.js checks it against.
//
//   node tools/operator-record.js --info http://127.0.0.1:3535 --api https://example.org/arca \
//     --contact-name "Example" --contact-domain example.org [--contact-email ops@example.org] \
//     [--contact-url https://example.org] [--issued-at <unix seconds>] > record.json
//
// --info is where this machine reaches the server (often its loopback
// address); --api is the public base URL wallets are given, and the registry
// reads the operator's info there. The operator then signs the record with its
// key, on the machine that holds it, and posts what that prints:
//
//   arca-signer --key-file <key> --genesis <genesis> --sign-operator-record record.json > signed.json
//   curl -s -X POST -H 'content-type: application/json' --data @signed.json https://<registry>/operators
const http = require('http');
const https = require('https');
const { recordFromInfo, canonical } = require('../operators');

function args(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 2) {
    const k = argv[i];
    if (!k.startsWith('--') || argv[i + 1] === undefined) throw new Error(`${k}: expected --name value`);
    out[k.slice(2)] = argv[i + 1];
  }
  for (const k of ['info', 'api', 'contact-name', 'contact-domain']) if (!out[k]) throw new Error(`--${k} is required`);
  return out;
}

function get(u) {
  return new Promise((resolve, reject) => {
    const url = new URL(u);
    (url.protocol === 'https:' ? https : http).get(url, res => {
      let d = '';
      res.on('data', c => { d += c; });
      res.on('end', () => (res.statusCode === 200 ? resolve(d) : reject(new Error(`${u}: HTTP ${res.statusCode}`))));
    }).on('error', reject).setTimeout(10000, function () { this.destroy(new Error(`${u}: timeout`)); });
  });
}

(async () => {
  const a = args(process.argv.slice(2));
  const info = JSON.parse(await get(`${a.info.replace(/\/+$/, '')}/v1/info`));
  const contact = { name: a['contact-name'], domain: a['contact-domain'].toLowerCase() };
  if (a['contact-email']) contact.email = a['contact-email'];
  if (a['contact-url']) contact.url = a['contact-url'];
  const record = recordFromInfo(info, {
    api: a.api.replace(/\/+$/, ''), contact, issued_at: a['issued-at'] ? Number(a['issued-at']) : Math.floor(Date.now() / 1000),
  });
  canonical(record);
  process.stdout.write(JSON.stringify(record, null, 2) + '\n');
})().catch(e => { console.error(`operator-record: ${e.message}`); process.exit(1); });
