'use strict';
// Arca operator records and the leaf template list, end to end: a registry on
// a temporary store, a stand-in operator answering GET /v1/info, and records
// signed here (BIP340, as the operator's signer signs them).
//
//   node --test test/
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { spawn, execFile } = require('node:child_process');
const { schnorrVerify, taggedHash, mul, G, N, bytes32, int } = require('../contracts');
const ops = require('../operators');
const templates = require('../templates');

const ROOT = path.join(__dirname, '..');
const ADMIN = 'test-admin-token';
const GENESIS = '3ce8ab6c8f9836c0cebca304f3cbed3e824e6c53f4cacd2822f6f8441eed1a3e';
const X = '750627c5778222a49fc785933f4636964f010092b460b9bd16bf8c424e14366f';
const Y = '7fb7b8b9c62e1333ff1d39293fa23c8793ac1718467cf7227766408bea1baf00';

function sign (seckey, msg) {
  const d0 = BigInt('0x' + seckey);
  const Pt = mul(d0, G);
  const d = Pt[1] % 2n === 0n ? d0 : N - d0;
  const px = bytes32(Pt[0]);
  const t = bytes32(d ^ int(taggedHash('BIP0340/aux', Buffer.alloc(32))));
  const k0 = int(taggedHash('BIP0340/nonce', Buffer.concat([t, px, msg]))) % N;
  const R = mul(k0, G);
  const k = R[1] % 2n === 0n ? k0 : N - k0;
  const e = int(taggedHash('BIP0340/challenge', Buffer.concat([bytes32(R[0]), px, msg]))) % N;
  return { pub: px.toString('hex'), sig: Buffer.concat([bytes32(R[0]), bytes32((k + e * d) % N)]).toString('hex') };
}
const SECRET = crypto.createHash('sha256').update('registry test operator').digest('hex');
const KEY = sign(SECRET, Buffer.alloc(32)).pub;
const signed = record => ({ record, signature: sign(SECRET, ops.recordDigest(record)).sig });

function freePort () {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.once('error', reject);
    s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); });
  });
}

// What an operator's GET /v1/info says, in the shape arcad answers.
function info () {
  const fees = { refresh_ppm: 0, refresh_base: '0', offboard_ppm: 0, offboard_base: '0', lightning_ppm: 0, lightning_base: '0' };
  return {
    operator: KEY, genesis_hash: GENESIS,
    assets: [
      { asset: Y, min_leaf: '1000', fees: { ...fees, refresh_base: '400', refresh_base_value: '1000' },
        rate: { source: 'file', rate: '250000000', time: 1, age_seconds: 4, max_age_seconds: 600, stale: false } },
      { asset: X, min_leaf: '1000', fees },
    ],
    exit_delay_units: { min: 1, max: 338 }, depth_limit: 32, finality: { certification: 'required', anchor_depth: 2 },
    templates: { version: 1, list: ['vtxo-1', 'board-1', 'htlc-1'] },
    fees: {}, participations: {}, boards: { lifetime_seconds: 2419200, exit_deadline_seconds: 259200, refresh_until_seconds: 259200 },
    keepers: { keys: [], required: 0 }, max_request_bytes: 65536, lightning: {},
  };
}

// A stand-in operator whose info the test changes, and which can stop
// answering.
async function fakeOperator (t) {
  const op = { info: info(), down: false };
  const server = http.createServer((req, res) => {
    if (op.down || req.url !== '/v1/info') { res.writeHead(op.down ? 503 : 404); return res.end('{}'); }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(op.info));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  op.url = `http://127.0.0.1:${server.address().port}`;
  return op;
}

async function start (t, env = {}) {
  const db = fs.mkdtempSync(path.join(os.tmpdir(), 'registry-operators-'));
  t.after(() => fs.rmSync(db, { recursive: true, force: true }));
  const port = await freePort();
  const child = spawn(process.execPath, [path.join(ROOT, 'server.js')], {
    env: {
      PATH: process.env.PATH, PORT: String(port), DB_DIR: db, SEED_FILE: path.join(db, 'no-seed.json'), REQUIRE_DOMAIN_PROOF: '0',
      ADMIN_TOKEN: ADMIN, SEQ_ELECTRS_URL: 'http://127.0.0.1:9', REQUIRE_COMPILE: '0', OPERATORS_LOCAL: '1', OPERATOR_CHECK_MS: '0', ...env,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  t.after(() => child.kill());
  let log = '';
  child.stderr.on('data', d => { log += d; });
  await new Promise((resolve, reject) => {
    child.stdout.on('data', d => { if (String(d).includes(`on :${port}`)) resolve(); });
    child.once('exit', code => reject(new Error(`the registry exited ${code}: ${log}`)));
  });
  const url = `http://127.0.0.1:${port}`;
  const call = async (method, p, body, admin) => {
    const r = await fetch(url + p, {
      method, headers: { 'content-type': 'application/json', ...(admin ? { authorization: `Bearer ${ADMIN}` } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { status: r.status, body: await r.json() };
  };
  return { url, db, get: p => call('GET', p), post: (p, b, admin) => call('POST', p, b, admin) };
}

const contact = { name: 'Test operator', domain: 'example.org' };

test('a record signed by the Arca signer verifies here, over the bytes both sides write', () => {
  // Signed by `arca-signer --sign-operator-record` with the test vector key S;
  // arca's covenant::operator_record tests hold the same digest.
  const b = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', 'arca', 'operator-record.signed.json'), 'utf8'));
  const d = ops.recordDigest(b.record);
  assert.equal(d.toString('hex'), '6f1188f5ef76f91831bbffe2910fd0b5cb38b0f889d91c2f8d7be2deda9c58dc');
  assert.ok(schnorrVerify(Buffer.from(b.record.operator, 'hex'), d, Buffer.from(b.signature, 'hex')));
  assert.equal(ops.canonical({ b: [1, true, 'x"\\/'], a: { d: 0, c: false } }), '{"a":{"c":false,"d":0},"b":[1,true,"x\\"\\\\/"]}');
  for (const bad of [{ a: null }, { a: 1.5 }, { a: -1 }, { a: 2 ** 53 }, { a: 'é' }, { a: '\n' }]) assert.throws(() => ops.canonical(bad));
});

test('the record from info keeps the operator\'s settings, not today\'s conversions', () => {
  const r = ops.recordFromInfo(info(), { api: 'https://example.org/arca', contact, issued_at: 5 });
  assert.deepEqual(r.assets.map(a => a.asset), [X, Y].sort());
  const y = r.assets.find(a => a.asset === Y);
  assert.deepEqual(y.rate, { source: 'file', max_age_seconds: 600 });
  assert.equal(y.fees.refresh_base_value, '1000');
  assert.equal(y.fees.refresh_base, undefined, 'the atoms a value comes to at today\'s rate are not recorded');
  // A rate that moves, and the atoms it converts a value to, are no difference.
  const moved = info();
  moved.assets[0].rate.rate = '300000000';
  moved.assets[0].fees.refresh_base = '333';
  assert.deepEqual(ops.differences(r, moved), []);
});

test('a record is listed only when signed by its key and true to the operator\'s info', async t => {
  const op = await fakeOperator(t);
  const s = await start(t);
  const record = ops.recordFromInfo(op.info, { api: op.url, contact, issued_at: Math.floor(Date.now() / 1000) });

  let r = await s.post('/operators', { ...signed(record), signature: signed({ ...record, issued_at: 1 }).signature });
  assert.equal(r.status, 403);
  assert.match(r.body.error, /not the operator key's over the record/);

  const edited = { ...record, exit_delay_units: { min: 1, max: 400 } };
  r = await s.post('/operators', signed(edited));
  assert.equal(r.status, 400);
  assert.match(r.body.error, /does not say what the operator's info says: exit_delay_units/);

  op.down = true;
  r = await s.post('/operators', signed(record));
  assert.equal(r.status, 502);
  assert.match(r.body.error, /could not be read/);
  op.down = false;

  r = await s.post('/operators', { ...signed(record), extra: 1 });
  assert.equal(r.status, 400);
  r = await s.post('/operators', signed({ ...record, api: 'ftp://example.org' }));
  assert.equal(r.status, 400);
  assert.match(r.body.error, /record.api/);

  r = await s.post('/operators', signed(record));
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.status, 'ok');
  assert.deepEqual(r.body.live.rates[Y], { rate: '250000000', age_seconds: 4, stale: false });
  assert.deepEqual(r.body.live.unknown_templates, []);
  r = await s.get('/operators');
  assert.deepEqual(r.body.map(e => e.key), [KEY]);
  r = await s.get(`/operators/${KEY}`);
  assert.ok(schnorrVerify(Buffer.from(KEY, 'hex'), ops.recordDigest(r.body.record), Buffer.from(r.body.signature, 'hex')));

  // An older record never replaces a newer; a newer one does.
  r = await s.post('/operators', signed({ ...record, issued_at: record.issued_at - 1 }));
  assert.equal(r.status, 409);
  assert.match(r.body.error, /lists a newer record/);
  r = await s.post('/operators', signed({ ...record, contact: { ...contact, name: 'Renamed' } }));
  assert.equal(r.status, 409);
  assert.match(r.body.error, /already has another record issued at/);
  r = await s.post('/operators', signed({ ...record, issued_at: record.issued_at + 1, contact: { ...contact, name: 'Renamed' } }));
  assert.equal(r.status, 200);
  assert.equal(r.body.record.contact.name, 'Renamed');
  // Another domain cannot take the key's listing over.
  r = await s.post('/operators', signed({ ...record, issued_at: record.issued_at + 2, contact: { name: 'x', domain: 'thief.example' } }));
  assert.equal(r.status, 409);
  assert.match(r.body.error, /is listed by example.org/);
});

test('an operator that repays swept coins says so in its record, and a record cannot claim it for an operator that does not', async t => {
  const op = await fakeOperator(t);
  const s = await start(t);
  op.info.swept = { policy: 'repaid', late_fee: 'refresh' };
  const record = ops.recordFromInfo(op.info, { api: op.url, contact, issued_at: Math.floor(Date.now() / 1000) });
  assert.deepEqual(record.expiry.swept, { policy: 'repaid', late_fee: 'refresh' });
  assert.equal((await s.post('/operators', signed(record))).status, 200);
  // An info that states no such policy differs from the record.
  delete op.info.swept;
  const e = (await s.post(`/admin/operators/${KEY}/check`, {}, true)).body;
  assert.equal(e.status, 'mismatched');
  assert.deepEqual(e.differences.map(d => d.field), ['expiry']);
  // A policy the registry does not know is refused.
  const odd = ops.recordFromInfo({ ...info(), swept: { policy: 'kept', late_fee: 'refresh' } },
    { api: op.url, contact, issued_at: Math.floor(Date.now() / 1000) + 1 });
  const r = await s.post('/operators', signed(odd));
  assert.equal(r.status, 400);
  assert.match(JSON.stringify(r.body), /record.expiry.swept.policy: repaid/);
});

test('a listed record is marked mismatched, stale and ok again as its operator changes', async t => {
  const op = await fakeOperator(t);
  const s = await start(t, { OPERATOR_STALE_AFTER_MS: '300' });
  const record = ops.recordFromInfo(op.info, { api: op.url, contact, issued_at: Math.floor(Date.now() / 1000) });
  assert.equal((await s.post('/operators', signed(record))).status, 200);
  const check = async () => (await s.post(`/admin/operators/${KEY}/check`, {}, true)).body;
  assert.equal((await s.post(`/admin/operators/${KEY}/check`, {})).status, 403, 'a check on demand is the registry operator\'s');

  op.info.assets[1].fees.refresh_ppm = 2500;
  op.info.keepers = { keys: [KEY], required: 1 };
  let e = await check();
  assert.equal(e.status, 'mismatched');
  assert.deepEqual(e.differences.map(d => d.field).sort(), [`assets.${X}`, 'keepers']);
  op.info = info();
  op.info.assets.pop();
  e = await check();
  assert.deepEqual(e.differences, [{ field: `assets.${X}`, record: record.assets[0], info: 'not served' }]);

  op.info = info();
  e = await check();
  assert.equal(e.status, 'ok');
  op.down = true;
  e = await check();
  assert.equal(e.status, 'ok', 'one missed answer is not yet stale');
  assert.match(e.last_error, /HTTP 503/);
  await new Promise(resolve => setTimeout(resolve, 400));
  e = await check();
  assert.equal(e.status, 'stale');
  op.down = false;
  e = await check();
  assert.equal(e.status, 'ok');
  assert.equal(e.last_error, undefined);
});

test('the scheduled check runs by itself', async t => {
  const op = await fakeOperator(t);
  const s = await start(t, { OPERATOR_CHECK_MS: '200' });
  const record = ops.recordFromInfo(op.info, { api: op.url, contact, issued_at: Math.floor(Date.now() / 1000) });
  assert.equal((await s.post('/operators', signed(record))).status, 200);
  op.info.exit_delay_units = { min: 2, max: 338 };
  await new Promise(resolve => setTimeout(resolve, 700));
  const e = (await s.get(`/operators/${KEY}`)).body;
  assert.equal(e.status, 'mismatched');
  assert.equal(e.differences[0].field, 'exit_delay_units');
});

test('a public registry reads an operator through the SSRF guard and takes https only', async t => {
  const op = await fakeOperator(t);
  const s = await start(t, { OPERATORS_LOCAL: '0' });
  const record = ops.recordFromInfo(op.info, { api: op.url, contact, issued_at: Math.floor(Date.now() / 1000) });
  let r = await s.post('/operators', signed(record));
  assert.equal(r.status, 400);
  assert.match(r.body.error, /an https URL/);
  r = await s.post('/operators', signed({ ...record, api: op.url.replace('http:', 'https:') }));
  assert.equal(r.status, 502);
  assert.match(r.body.error, /non-public address/);
});

test('the template list is rebuilt from the pinned Arca vectors, and a tampered copy is refused', async t => {
  const list = templates.load();
  assert.deepEqual(list.templates.map(x => x.name), ['vtxo-1', 'board-1', 'htlc-1']);
  const leaf = list.templates[0].vectors[0];
  assert.equal(leaf.script_hash, crypto.createHash('sha256').update(Buffer.from(leaf.script_pubkey, 'hex')).digest('hex'));
  assert.deepEqual(list.templates[2].vectors.map(v => v.vector), ['htlc', 'htlc_receive']);
  const s = await start(t);
  assert.deepEqual((await s.get('/templates')).body, list);

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'registry-templates-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const pin = JSON.parse(fs.readFileSync(path.join(ROOT, 'arca', 'PIN.json'), 'utf8'));
  const v = JSON.parse(fs.readFileSync(path.join(ROOT, 'arca', 'vectors.json'), 'utf8'));
  fs.writeFileSync(path.join(dir, 'PIN.json'), JSON.stringify(pin));
  fs.writeFileSync(path.join(dir, 'vectors.json'), JSON.stringify(v));
  assert.throws(() => templates.load(dir), /hashes to .*not the pinned/);
  // Resealed with the copy's own hash: each rebuild check still holds the
  // vectors to their scripts.
  const cases = [
    [o => { o.leaf.leaves.exit.script = o.leaf.leaves.exit.script.replace('fe0040', 'fe0041'); }, /leaf.exit: the script hashes to/],
    [o => { o.board.script_pubkey = '5120' + '00'.repeat(32); }, /board: the leaves build the script/],
    [o => { o.htlc.leaves.claim.control_block = o.htlc.leaves.claim.control_block.slice(0, -2) + '00'; }, /htlc.claim: reaches root|merkle|root/],
    [o => { o.leaf.merkle_root = '00'.repeat(32); }, /leaf: the leaves reach root/],
  ];
  for (const [edit, why] of cases) {
    const copy = JSON.parse(JSON.stringify(v));
    edit(copy.outputs);
    const text = JSON.stringify(copy);
    fs.writeFileSync(path.join(dir, 'vectors.json'), text);
    fs.writeFileSync(path.join(dir, 'PIN.json'), JSON.stringify({ ...pin, sha256: crypto.createHash('sha256').update(text).digest('hex') }));
    assert.throws(() => templates.load(dir), why);
  }
});

test('the record tool writes the record the registry checks', async t => {
  const op = await fakeOperator(t);
  const out = await new Promise((resolve, reject) => execFile(process.execPath, [path.join(ROOT, 'tools', 'operator-record.js'), '--info', op.url,
    '--api', 'https://example.org/arca/', '--contact-name', 'Test operator', '--contact-domain', 'Example.org', '--issued-at', '7'],
  (err, stdout, stderr) => (err ? reject(new Error(stderr)) : resolve(stdout))));
  const r = JSON.parse(out);
  assert.deepEqual(r, ops.recordFromInfo(op.info, { api: 'https://example.org/arca', contact, issued_at: 7 }));
  assert.deepEqual(Object.keys(r).sort(), ops.FIELDS);
});
