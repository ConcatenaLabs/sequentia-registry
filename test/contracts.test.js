'use strict';
// The contracts collection and oracle key records, end to end: a registry on a
// temporary store, with a stand-in for electrs that answers the two calls an
// instance needs.
//
//   node --test test/
//   SEQC=/path/to/seqc node --test test/     # also runs the pinned compiler
//
// Without SEQC the compiler check is off (REQUIRE_COMPILE=0), and the tests that
// need it are skipped.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { pathToFileURL } = require('node:url');
const { schnorrVerify, taggedHash, mul, G, N, bytes32, int, ORACLE_RECORD_TAG, PIN } = require('../contracts');

const ROOT = path.join(__dirname, '..');
const FIX = path.join(__dirname, 'fixtures', 'sequentia-contracts');
const SEQC = process.env.SEQC || '';
const ADMIN = 'test-admin-token';
const TESTNET_GENESIS = 'ddd11d54c87a2bd94400fd31ce05d8e1110bb4b78e7103f738342086fc4ea92e';
const read = p => fs.readFileSync(path.join(FIX, p), 'utf8');
let reader;
test.before(async () => { reader = await import(pathToFileURL(path.join(ROOT, 'contracts', 'sequentia-address.mjs')).href); });

function freePort () {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.once('error', reject);
    s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); });
  });
}

// electrs, as far as an instance needs it: the genesis hash, and whether a
// script has been paid.
async function fakeElectrs (t, genesis, funded) {
  const server = http.createServer((req, res) => {
    let body = null;
    if (req.url === '/block-height/0') body = genesis;
    const m = req.url.match(/^\/scripthash\/([0-9a-f]{64})$/);
    if (m) body = JSON.stringify({ chain_stats: { funded_txo_count: funded.has(m[1]) ? 1 : 0 }, mempool_stats: { funded_txo_count: 0 } });
    res.writeHead(body === null ? 404 : 200);
    res.end(body === null ? 'not found' : body);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  return `http://127.0.0.1:${server.address().port}`;
}

async function start (t, env = {}) {
  const db = fs.mkdtempSync(path.join(os.tmpdir(), 'registry-test-'));
  t.after(() => fs.rmSync(db, { recursive: true, force: true }));
  const port = await freePort();
  const base = Object.fromEntries(Object.entries(process.env).filter(([k]) =>
    !['PORT', 'DB_DIR', 'SEED_FILE', 'SEQ_ELECTRS_URL', 'REQUIRE_DOMAIN_PROOF', 'ADMIN_TOKEN', 'SEQC', 'REQUIRE_COMPILE', 'CONTRACTS_CHAIN'].includes(k)));
  const child = spawn(process.execPath, [path.join(ROOT, 'server.js')], {
    env: {
      ...base, PORT: String(port), DB_DIR: db, SEED_FILE: path.join(db, 'no-seed.json'), REQUIRE_DOMAIN_PROOF: '0',
      ADMIN_TOKEN: ADMIN, SEQ_ELECTRS_URL: 'http://127.0.0.1:9', ...(SEQC ? { SEQC } : { REQUIRE_COMPILE: '0' }), ...env,
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
  return { url, get: p => call('GET', p), post: (p, b, admin) => call('POST', p, b, admin) };
}

// A template's submission from a directory of the fixtures.
function submission (dir, publisher = { domain: 'sequentiatestnet.com', name: 'The registry operator' }) {
  const descriptor = read(`${dir}/descriptor.json`);
  const d = JSON.parse(descriptor);
  const sources = {};
  const walk = n => {
    if (n.branch) n.branch.forEach(walk);
    else if (n.simplicity) sources[n.simplicity.source] = read(`${dir}/${n.simplicity.source}`);
  };
  if (d.template.tree) walk(d.template.tree);
  else sources[d.template.program.source] = read(`${dir}/${d.template.program.source}`);
  return { descriptor, sources, vectors: read(`${dir}/vectors.json`), publisher };
}

// A submission with its template changed, resealed and its vectors derived again.
function edited (dir, edit, publisher) {
  const sub = submission(dir, publisher);
  const d = JSON.parse(sub.descriptor);
  edit(d.template, sub);
  d.template_hash = reader.templateHash(d.template);
  const v = JSON.parse(sub.vectors);
  v.template_hash = d.template_hash;
  if (d.descriptor === 1) v.cmr = d.template.program.cmr;
  v.addresses = v.addresses.map(c => ({ name: c.name, params: c.params, ...(d.descriptor === 2 ? { slots: c.slots } : {}),
    ...reader.derive(d, c.params, c.slots || {}) }));
  return { ...sub, descriptor: JSON.stringify(d, null, 2), vectors: JSON.stringify(v, null, 2) };
}

test('the reader is the pinned one', () => {
  const got = crypto.createHash('sha256').update(fs.readFileSync(path.join(ROOT, 'contracts', 'sequentia-address.mjs'))).digest('hex');
  assert.equal(got, PIN.reader.sha256);
  assert.deepEqual(PIN.compiler, { name: 'simplicityhl', version: '0.7.2' });
});

// The refusals every reader must make (sequentia-contracts
// mirrors/fixtures/refusals.json), each made by the registry for its reason.
function applyEdit (doc, op) {
  let target = doc;
  for (const k of op.at.slice(0, -1)) target = target[k];
  const last = op.at[op.at.length - 1];
  if ('set' in op) Object.defineProperty(target, last, { value: op.set, enumerable: true, writable: true, configurable: true });
  else if ('delete' in op) { if (Array.isArray(target)) target.splice(last, 1); else delete target[last]; }
  else if ('append' in op) target[last].push(op.append);
  else if ('suffix' in op) target[last] += op.suffix;
  else throw new Error(`unknown edit ${JSON.stringify(op)}`);
}
function refusalText (c) {
  let text = read(`${c.base}/descriptor.json`);
  if (c.text) {
    for (const [from, to] of c.text) { assert.ok(text.includes(from), `${c.name}: ${from}`); text = text.replace(from, to); }
    return text;
  }
  const d = JSON.parse(text);
  for (const op of c.edit) applyEdit(d, op);
  if (c.reseal !== false) d.template_hash = reader.templateHash(d.template);
  return JSON.stringify(d, null, 2);
}

test('every refusal in refusals.json is made, for its reason', async t => {
  const s = await start(t);
  const { cases } = JSON.parse(read('mirrors/fixtures/refusals.json'));
  assert.equal(cases.length, 76);
  let refused = 0, accepted = 0;
  for (const c of cases) {
    const sub = { ...submission(c.base), descriptor: refusalText(c) };
    if (c.derive) {
      // The descriptor is read; deriving these values must fail, so a vector
      // that names them is refused.
      const d = JSON.parse(sub.descriptor);
      sub.vectors = JSON.stringify({ vectors: d.descriptor, template_hash: d.template_hash,
        addresses: [{ name: c.name, params: c.derive.params, slots: c.derive.slots }] });
    }
    let r;
    try { r = await s.post('/admin/contracts', sub, true); } catch (e) { throw new Error(`${c.name}: ${e.message} (${JSON.stringify(sub).length} bytes)`); }
    if (c.accept) {
      assert.equal(r.status, 200, `${c.name}: ${JSON.stringify(r.body)}`);
      accepted++;
      continue;
    }
    assert.equal(r.status, 400, `${c.name}: ${JSON.stringify(r.body)}`);
    assert.match(r.body.error, c.derive ? /^vectors refused: / : /^descriptor refused: /, c.name);
    assert.ok(r.body.error.includes(c.expect), `${c.name}: ${r.body.error}`);
    refused++;
  }
  assert.deepEqual([refused, accepted], [75, 1]);
  // Nothing refused was stored.
  const list = (await s.get('/contracts')).body;
  assert.equal(list.length, 1);
  assert.equal(list[0].name, 'sequentia/one-key');
});

test('the faucet drip and one_key templates are accepted', async t => {
  const s = await start(t);
  const fixtures = { 'templates/faucet_drip': 'sequentia/faucet-drip', 'templates/one_key': 'sequentia/one-key' };
  for (const [dir, name] of Object.entries(fixtures)) {
    const sub = submission(dir);
    const r = await s.post('/admin/contracts', { ...sub, audits: [
      { by: 'An auditor', url: 'https://example.com/audit.pdf', summary: 'Read against the specification.' }] }, true);
    assert.equal(r.status, 200, `${dir}: ${JSON.stringify(r.body)}`);
    const d = JSON.parse(sub.descriptor);
    assert.equal(r.body.template_hash, d.template_hash);
    assert.equal(r.body.name, name);
    assert.equal(r.body.verified_by, 'operator');
    assert.equal(r.body.verified_compile, !!SEQC);
    assert.equal(r.body.verified, !!SEQC);
    if (SEQC) assert.match(r.body.compile_check, /^ok: descriptor version \d, \d+ address vectors/);
    // Everything needed to check it again is served, byte for byte.
    const full = (await s.get(`/contracts/${d.template_hash}`)).body;
    assert.equal(full.descriptor, sub.descriptor);
    assert.deepEqual(full.sources, sub.sources);
    assert.equal(full.vectors, sub.vectors);
    assert.equal(full.audits[0].by, 'An auditor');
  }
  const drip = (await s.get('/contracts/12986f202fbfb850f7699c5d5188f261f276de6c7038142f0a28bbb672b5af34')).body;
  assert.deepEqual(drip.leaves.map(l => [l.leaf, l.kind, l.paths]),
    [['drip', 'simplicity', ['drip']], ['params', 'data', []], ['recover', 'tapscript', ['recover']]]);
  assert.equal(drip.leaves[0].cmr, '5251ec00d9799dbcdb31da4534f25ef9960321f195e2e24ef7125c46f24b972a');
  assert.equal(drip.leaves[0].max_cost_wu, 432);
  const index = (await s.get('/contracts/index.minimal.json')).body;
  if (SEQC) {
    assert.deepEqual(index.leaves['5251ec00d9799dbcdb31da4534f25ef9960321f195e2e24ef7125c46f24b972a'],
      [['12986f202fbfb850f7699c5d5188f261f276de6c7038142f0a28bbb672b5af34', 'sequentia/faucet-drip', 1, 'drip', 'drip']]);
    assert.equal(Object.keys(index.leaves).length, 2);
  } else {
    assert.deepEqual(index, { leaves: {}, scripts: {} }, 'an entry the compiler did not check is not indexed');
  }
});

test('a template is checked beyond its descriptor', async t => {
  const s = await start(t);
  const refused = async (sub, re, status = 400) => {
    const r = await s.post('/admin/contracts', sub, true);
    assert.equal(r.status, status, JSON.stringify(r.body));
    assert.match(r.body.error, re);
  };
  const drip = () => submission('templates/faucet_drip');
  // The source as compiled, and only the leaves' sources.
  let sub = drip();
  sub.sources['faucet_drip.simf'] = sub.sources['faucet_drip.simf'].replace('fn main', 'fn  main');
  await refused(sub, /^leaf drip: faucet_drip\.simf hashes to [0-9a-f]{64}, not the source_sha256 f6b1bc9c/);
  sub = drip(); delete sub.sources['faucet_drip.simf'];
  await refused(sub, /faucet_drip\.simf is missing/);
  sub = drip(); sub.sources['other.simf'] = 'fn main() {}';
  await refused(sub, /other\.simf is no leaf's source/);
  // The source as written, with its includes, is not the source compiled.
  const unexpanded = submission('templates/faucet_drip');
  unexpanded.sources['faucet_drip.simf'] = unexpanded.sources['faucet_drip.simf'].replace(/\n/, '\n// include output_reader\n');
  await refused(unexpanded, /hashes to/);
  // The pinned compiler.
  await refused(edited('templates/faucet_drip', tp => { tp.tree.branch[0].branch[0].simplicity.compiler.version = '0.7.3'; }),
    /^leaf drip: compiler simplicityhl 0\.7\.3 is not the pinned simplicityhl 0\.7\.2$/);
  // Sequentia's budget.
  await refused(edited('templates/faucet_drip', tp => { tp.budget.per_witness_byte = 5; }), /budget/);
  // The vectors, field by field.
  sub = drip();
  let v = JSON.parse(sub.vectors);
  v.addresses[3].output_key_parity ^= 1;
  sub.vectors = JSON.stringify(v);
  await refused(sub, /^vectors refused: address 3 \(.*\): output_key_parity is not what the descriptor derives$/);
  sub = drip(); v = JSON.parse(sub.vectors); v.addresses[0].address['sequentia-testnet'] = v.addresses[1].address['sequentia-testnet'];
  sub.vectors = JSON.stringify(v);
  await refused(sub, /address is not what the descriptor derives/);
  sub = drip(); sub.vectors = read('templates/one_key_exit/vectors.json');
  await refused(sub, /^vectors refused: template_hash is not the descriptor's$/);
  sub = drip(); v = JSON.parse(sub.vectors); v.addresses = []; sub.vectors = JSON.stringify(v);
  await refused(sub, /^vectors refused: no addresses$/);
  sub = drip(); sub.vectors = sub.vectors.replace('"vectors": 2', '"vectors": 2.0');
  await refused(sub, /^vectors refused: .*2\^53/);
  // The body and its fields.
  await refused({ ...drip(), descriptor: JSON.parse(drip().descriptor) }, /descriptor: the descriptor file's text/);
  await refused({ ...drip(), publisher: { domain: 'not a domain' } }, /publisher\.domain/);
  await refused({ ...drip(), extra: 1 }, /unknown field extra/);
  await refused({ ...drip(), audits: [{ by: 'x', url: 'http://example.com/a', summary: 'y' }] }, /https URL/);
  // Nothing was stored.
  assert.deepEqual((await s.get('/contracts')).body, []);
});

test('the pinned compiler refuses a root its source does not give', { skip: !SEQC && 'set SEQC' }, async t => {
  // Every check the reader can make passes: the root is changed, the template
  // resealed and the vectors derived again. Only compiling the source shows
  // that it does not give that root.
  const forged = edited('templates/one_key', tp => { tp.program.cmr = '00'.repeat(31) + '01'; });
  const s = await start(t);
  const r = await s.post('/admin/contracts', forged, true);
  assert.equal(r.status, 400, JSON.stringify(r.body));
  assert.match(r.body.error, /^the pinned compiler refused the template: /);
  assert.match(r.body.error, /cmr|commitment|root/i);
  // With the compiler check off, the same template is stored but not verified,
  // and the explorer's index leaves it out.
  const off = await start(t, { REQUIRE_COMPILE: '0' });
  const stored = await off.post('/admin/contracts', forged, true);
  assert.equal(stored.status, 200);
  assert.equal(stored.body.verified, false);
  assert.deepEqual((await off.get('/contracts/index.minimal.json')).body, { leaves: {}, scripts: {} });
});

test('writes are authenticated', async t => {
  const s = await start(t);
  // The operator's namespace, and the operator's path.
  let r = await s.post('/contracts', submission('templates/one_key'));
  assert.equal(r.status, 403);
  assert.match(r.body.error, /sequentia\/ namespace is published by the registry operator only/);
  r = await s.post('/admin/contracts', submission('templates/one_key'));
  assert.equal(r.status, 403);
  r = await fetch(`${s.url}/admin/contracts`, { method: 'POST', headers: { authorization: 'Bearer wrong' }, body: '{}' });
  assert.equal(r.status, 403);
  // Another namespace is open to its first publisher, with the domain proof
  // (off in these tests, as REQUIRE_DOMAIN_PROOF=0 turns it off for assets).
  const mine = { domain: 'example.com', name: 'Example' };
  const ours = edited('templates/one_key', tp => { tp.name = 'example/one-key'; }, mine);
  r = await s.post('/contracts', ours);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.publisher.domain, 'example.com');
  // The same template, or another in the namespace, from another domain.
  r = await s.post('/contracts', { ...ours, publisher: { domain: 'example.org' } });
  assert.equal(r.status, 409);
  assert.match(r.body.error, /already published by example\.com/);
  r = await s.post('/contracts', edited('templates/one_key_exit', tp => { tp.name = 'example/exit'; }, { domain: 'example.org' }));
  assert.equal(r.status, 409);
  assert.match(r.body.error, /example\/ namespace belongs to example\.com/);
  // One template per name and version.
  r = await s.post('/contracts', edited('templates/one_key', tp => { tp.name = 'example/one-key'; tp.summary += ' Again.'; }, mine));
  assert.equal(r.status, 409);
  assert.match(r.body.error, /example\/one-key version 1 is already template/);
  // The publisher refreshes its own entry, with audit notes.
  r = await s.post('/contracts', { ...ours, audits: [{ by: 'Auditor', url: 'https://example.com/r', summary: 'Clean.' }] });
  assert.equal(r.status, 200);
  assert.equal(r.body.audits.length, 1);
  r = await fetch(`${s.url}/contracts`, { method: 'POST', body: 'not json' });
  assert.equal(r.status, 400);
});

test('an instance is registered once the chain has paid it', async t => {
  const v = JSON.parse(read('templates/faucet_drip/vectors.json')).addresses[0];
  const scripthash = crypto.createHash('sha256').update(Buffer.from(v.script_pubkey, 'hex')).digest('hex');
  const electrs = await fakeElectrs(t, TESTNET_GENESIS, new Set([scripthash]));
  const s = await start(t, { SEQ_ELECTRS_URL: electrs });
  const hash = '12986f202fbfb850f7699c5d5188f261f276de6c7038142f0a28bbb672b5af34';
  let r = await s.post(`/contracts/${hash}/instances`, { params: v.params, genesis: TESTNET_GENESIS });
  assert.equal(r.status, 404, 'no template yet');
  assert.equal((await s.post('/admin/contracts', submission('templates/faucet_drip'), true)).status, 200);
  r = await s.post(`/contracts/${hash}/instances`, { params: v.params, genesis: TESTNET_GENESIS });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.script_pubkey, v.script_pubkey);
  assert.equal(r.body.address, v.address['sequentia-testnet']);
  assert.equal((await s.get(`/contracts/instances/${v.script_pubkey}`)).body.name, 'sequentia/faucet-drip');
  assert.equal((await s.get(`/contracts/${hash}/instances`)).body.length, 1);
  if (SEQC) {
    assert.deepEqual((await s.get('/contracts/index.minimal.json')).body.scripts,
      { [v.script_pubkey]: [hash, 'sequentia/faucet-drip', 1] });
  }
  // An instance no output pays, another chain's, and values the template refuses.
  const other = JSON.parse(read('templates/faucet_drip/vectors.json')).addresses[1];
  r = await s.post(`/contracts/${hash}/instances`, { params: other.params, genesis: TESTNET_GENESIS });
  assert.equal(r.status, 400);
  assert.match(r.body.error, /^no output pays tb1p/);
  r = await s.post(`/contracts/${hash}/instances`, { params: v.params, genesis: '00'.repeat(32) });
  assert.equal(r.status, 400);
  assert.match(r.body.error, /is not this chain's/);
  r = await s.post(`/contracts/${hash}/instances`, { params: { ...v.params, RECOVERY_DELAY: '80000001' }, genesis: TESTNET_GENESIS });
  assert.equal(r.status, 400);
  assert.match(r.body.error, /^instance refused: .*sequence/);
});

// BIP340 signing, for the tests only: deterministic, auxiliary randomness zero.
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

test('BIP340 verification matches the BIP\'s vectors', () => {
  // Vectors 0 and 1 of bip-0340/test-vectors.csv, and 5 and 6, which must fail.
  const v0 = sign('0000000000000000000000000000000000000000000000000000000000000003', Buffer.alloc(32));
  assert.equal(v0.pub, 'f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9');
  assert.equal(v0.sig, 'e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0');
  const ok = (pub, msg, sig) => schnorrVerify(Buffer.from(pub, 'hex'), Buffer.from(msg, 'hex'), Buffer.from(sig, 'hex'));
  assert.ok(ok(v0.pub, '00'.repeat(32), v0.sig));
  assert.ok(ok('dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659', '243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89',
    '6896bd60eeae296db48a229ff71dfe071bde413e6d43f917dc8dcf8c78de33418906d11ac976abccb20b091292bff4ea897efcb639ea871cfa95f6de339e4b0a'));
  assert.ok(!ok('eefdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34', '243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89',
    '6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e17776969e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b'), 'a key not on the curve');
  assert.ok(!ok('dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659', '243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89',
    'fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a14602975563cc27944640ac607cd107ae10923d9ef7a73c643e166be5ebeafa34b1ac553e2'), 'R has an odd y');
});

test('an oracle key record is signed by its key', async t => {
  const s = await start(t);
  const seckey = crypto.randomBytes(32).toString('hex');
  const key = sign(seckey, Buffer.alloc(32)).pub;
  const record = {
    version: 1, key,
    feeds: [{ id: 'BTC/USD', description: 'Bitcoin in US dollars', decimals: 8 }, { id: 'XAU/USD', description: 'Gold, one troy ounce, in US dollars', decimals: 8 }],
    operator: { name: 'Example oracle', domain: 'oracle.example.com' },
    endpoints: ['https://oracle.example.com/attestations'],
    attestation_tag: 'example/price-attestation/v1',
    bond: 'none',
  };
  const signed = r => sign(seckey, taggedHash(ORACLE_RECORD_TAG, Buffer.from(reader.canonicalJson(r), 'utf8'))).sig;
  let r = await s.post('/oracles', { record, signature: signed(record) });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.key, key);
  assert.equal(r.body.verified_key, true);
  assert.equal((await s.get(`/oracles/${key}`)).body.record.feeds[1].id, 'XAU/USD');
  assert.equal((await s.get('/oracles')).body.length, 1);
  // A signature by another key, over another record, or a record changed after signing.
  const other = sign(crypto.randomBytes(32).toString('hex'), taggedHash(ORACLE_RECORD_TAG, Buffer.from(reader.canonicalJson(record), 'utf8'))).sig;
  r = await s.post('/oracles', { record, signature: other });
  assert.equal(r.status, 403);
  assert.match(r.body.error, /not the key's over the record/);
  r = await s.post('/oracles', { record: { ...record, endpoints: ['https://evil.example.net/'] }, signature: signed(record) });
  assert.equal(r.status, 403);
  // The same key, now claimed by another operator.
  const moved = { ...record, operator: { name: 'Someone else', domain: 'example.org' } };
  r = await s.post('/oracles', { record: moved, signature: signed(moved) });
  assert.equal(r.status, 409);
  // A revocation, signed by the key.
  const revoked = { ...record, revoked: true };
  r = await s.post('/oracles', { record: revoked, signature: signed(revoked) });
  assert.equal(r.status, 200);
  assert.equal(r.body.revoked, true);
  // Records the registry refuses before it checks a signature.
  for (const [bad, re] of [
    [{ ...record, key: '00'.repeat(32) }, /not the x coordinate/],
    [{ ...record, feeds: [] }, /1 to 50 feeds/],
    [{ ...record, feeds: [record.feeds[0], record.feeds[0]] }, /BTC\/USD twice/],
    [{ ...record, endpoints: ['http://oracle.example.com/'] }, /https URL/],
    [{ ...record, price_server: 'https://x' }, /unknown field price_server/],
    [{ ...record, version: 2 }, /record\.version/],
  ]) {
    r = await s.post('/oracles', { record: bad, signature: signed(bad) });
    assert.equal(r.status, 400, JSON.stringify(bad));
    assert.match(r.body.error, re);
  }
  // The operator's path still needs the key's signature.
  r = await s.post('/admin/oracles', { record: moved, signature: other }, true);
  assert.equal(r.status, 403);
  r = await s.post('/admin/oracles', { record: moved, signature: signed(moved) }, true);
  assert.equal(r.status, 200);
  assert.equal(r.body.verified_by, 'operator');
});

test('the assets still work beside the contracts', async t => {
  const s = await start(t);
  assert.equal((await s.get('/health')).body.ok, true);
  assert.deepEqual((await s.get('/')).body, []);
  assert.equal((await s.get('/' + 'ab'.repeat(32))).status, 404);
});
