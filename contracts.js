'use strict';
/*
 * The registry's contracts collection and oracle key records.
 *
 * A contract template is identified by its hash, and everything the registry
 * says about it can be checked again by anyone from what it serves: the
 * descriptor exactly as submitted, each program's source as compiled, and the
 * golden vectors. A template is accepted only when
 *
 *   1. the descriptor is read by the JavaScript reader of sequentia-contracts
 *      (contracts/sequentia-address.mjs, pinned in contracts/PIN.json), which
 *      refuses every file the specification refuses;
 *   2. every Simplicity leaf names the pinned compiler, and its source hashes
 *      to the leaf's source_sha256;
 *   3. the reader reproduces every golden vector, field for field;
 *   4. the pinned compiler, through `seqc descriptor check`, compiles each
 *      source to the leaf's commitment root, witness list and cost bound, and
 *      the lints pass (skipped only with REQUIRE_COMPILE=0, which leaves the
 *      entry unverified);
 *   5. the publisher's domain serves the proof line for the template hash
 *      (skipped for the operator's own templates, written with ADMIN_TOKEN).
 *
 * An instance (a template's parameters on this chain) is accepted from anyone,
 * because it is checked completely: the reader derives its script, and the
 * chain must have paid that script. The explorer labels a spend from the
 * index these make.
 *
 * An oracle key record says which price feeds a BIP340 key signs, who runs it
 * and where its attestations are published. It is signed by the key itself, so
 * no one can file a record for a key they do not hold, and the operator's
 * domain serves the proof line for the key.
 */
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFile } = require('child_process');
const { pathToFileURL } = require('url');

const HEX64 = /^[0-9a-f]{64}$/;
const HEX128 = /^[0-9a-f]{128}$/;
const SPK_RE = /^[0-9a-f]{2,20000}$/;
const PIN = JSON.parse(fs.readFileSync(path.join(__dirname, 'contracts', 'PIN.json'), 'utf8'));
// Namespaces only the operator publishes in, with ADMIN_TOKEN.
const RESERVED_NAMESPACES = new Set(['sequentia']);
const ORACLE_RECORD_TAG = 'sequentia-registry/oracle-key/v1';

let reader = null;
const readerReady = import(pathToFileURL(path.join(__dirname, 'contracts', 'sequentia-address.mjs')).href)
  .then(m => { reader = m; });

function init(deps) {
  const {
    DB_DIR, ELECTRS, REQUIRE_DOMAIN_PROOF, DOMAIN_RE, fetchUrl, verifyProofLine, httpErr, canonicalize,
  } = deps;
  const REQUIRE_COMPILE = (process.env.REQUIRE_COMPILE || '1') !== '0';
  const SEQC = process.env.SEQC || 'seqc';
  const CHAIN = process.env.CONTRACTS_CHAIN || 'sequentia-testnet';

  const dirs = {
    contracts: path.join(DB_DIR, 'contracts'),
    instances: path.join(DB_DIR, 'contract-instances'),
    oracles: path.join(DB_DIR, 'oracles'),
  };
  for (const d of Object.values(dirs)) fs.mkdirSync(d, { recursive: true });
  const file = (kind, id) => path.join(dirs[kind], `${id}.json`);
  const read = (kind, id) => { try { return JSON.parse(fs.readFileSync(file(kind, id), 'utf8')); } catch (e) { return null; } };
  const write = (kind, id, v) => {
    const tmp = file(kind, id) + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(v, null, 2));
    fs.renameSync(tmp, file(kind, id));
  };
  const all = (kind, re) => fs.readdirSync(dirs[kind])
    .filter(f => f.endsWith('.json')).map(f => f.slice(0, -5)).filter(id => re.test(id))
    .map(id => read(kind, id)).filter(Boolean);
  const sha256 = s => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
  const bad = why => httpErr(400, why);

  // ---------- templates ----------

  function strField(v, at, max) {
    if (typeof v !== 'string' || v.length < 1 || v.length > max || !/^[\x20-\x7e]*$/.test(v))
      throw bad(`${at}: printable text of 1 to ${max} characters`);
  }
  function httpsUrl(v, at) {
    strField(v, at, 300);
    let u;
    try { u = new URL(v); } catch (e) { throw bad(`${at}: not a URL`); }
    if (u.protocol !== 'https:') throw bad(`${at}: an https URL`);
  }
  function checkPublisher(p) {
    if (!p || typeof p !== 'object' || Array.isArray(p)) throw bad('publisher: { domain, name? }');
    for (const k of Object.keys(p)) if (k !== 'domain' && k !== 'name') throw bad(`publisher: unknown field ${k}`);
    if (typeof p.domain !== 'string' || !DOMAIN_RE.test(p.domain)) throw bad('publisher.domain: a DNS domain');
    if (p.name !== undefined) strField(p.name, 'publisher.name', 100);
    return { domain: p.domain.toLowerCase(), ...(p.name !== undefined ? { name: p.name } : {}) };
  }
  function checkAudits(a) {
    if (a === undefined) return [];
    if (!Array.isArray(a) || a.length > 20) throw bad('audits: an array of at most 20 notes');
    return a.map((n, i) => {
      if (!n || typeof n !== 'object' || Array.isArray(n)) throw bad(`audits[${i}]: an object`);
      for (const k of Object.keys(n)) if (!['by', 'url', 'summary', 'report_sha256'].includes(k)) throw bad(`audits[${i}]: unknown field ${k}`);
      strField(n.by, `audits[${i}].by`, 100);
      httpsUrl(n.url, `audits[${i}].url`);
      strField(n.summary, `audits[${i}].summary`, 500);
      if (n.report_sha256 !== undefined && !HEX64.test(n.report_sha256)) throw bad(`audits[${i}].report_sha256: 64 lowercase hex`);
      return { by: n.by, url: n.url, summary: n.summary, ...(n.report_sha256 ? { report_sha256: n.report_sha256 } : {}) };
    });
  }

  // The leaves of the reader's model, in tree order.
  function leaves(node) {
    return node.kind === 'branch' ? [...leaves(node.a), ...leaves(node.b)] : [node];
  }

  // Reads and checks everything but the compiler and the domain. Returns the
  // parts the entry is built from.
  function readTemplate(sub) {
    if (!sub || typeof sub !== 'object') throw bad('body: { descriptor, sources, vectors, publisher, audits? }');
    for (const k of Object.keys(sub)) if (!['descriptor', 'sources', 'vectors', 'publisher', 'audits'].includes(k)) throw bad(`unknown field ${k}`);
    // The descriptor travels as the file's text: parsing it into the request's
    // JSON would already have dropped a repeated field or rounded a number,
    // which the reader must see to refuse.
    if (typeof sub.descriptor !== 'string') throw bad('descriptor: the descriptor file\'s text');
    let d;
    try { d = reader.parseDescriptor(sub.descriptor); } catch (e) { throw bad(`descriptor refused: ${e.message}`); }
    const m = reader.model(d);
    const t = d.template;
    for (const [k, v] of Object.entries(PIN.budget)) {
      if (m.budget[k] !== v) throw bad(`descriptor refused: the budget is not Sequentia's (${k} ${m.budget[k]}, not ${v})`);
    }

    // Each Simplicity leaf: the pinned compiler, and its source as compiled.
    if (!sub.sources || typeof sub.sources !== 'object' || Array.isArray(sub.sources)) throw bad('sources: { "<name>.simf": "<text>" }');
    const simplicity = leaves(m.tree).filter(l => l.kind === 'simplicity');
    const wanted = new Set(simplicity.map(l => l.body.source));
    for (const name of Object.keys(sub.sources)) if (!wanted.has(name)) throw bad(`sources: ${name} is no leaf's source`);
    for (const l of simplicity) {
      const { compiler, source, source_sha256: want } = l.body;
      if (compiler.name !== PIN.compiler.name || compiler.version !== PIN.compiler.version)
        throw bad(`leaf ${l.name}: compiler ${compiler.name} ${compiler.version} is not the pinned ${PIN.compiler.name} ${PIN.compiler.version}`);
      const text = sub.sources[source];
      if (typeof text !== 'string') throw bad(`sources: ${source} is missing; give it with its includes resolved, as \`seqc expand\` prints it`);
      const got = sha256(text);
      if (got !== want) throw bad(`leaf ${l.name}: ${source} hashes to ${got}, not the source_sha256 ${want}`);
    }

    // The golden vectors, each reproduced in full.
    if (typeof sub.vectors !== 'string') throw bad('vectors: the vectors file\'s text');
    let v;
    try { v = reader.parseJson(sub.vectors); } catch (e) { throw bad(`vectors refused: ${e.message}`); }
    if (!v || v.vectors !== d.descriptor) throw bad(`vectors refused: version ${v && v.vectors} is not the descriptor's ${d.descriptor}`);
    if (v.template_hash !== d.template_hash) throw bad('vectors refused: template_hash is not the descriptor\'s');
    if (d.descriptor === 1 && v.cmr !== t.program.cmr) throw bad('vectors refused: cmr is not the program\'s');
    if (!Array.isArray(v.addresses) || v.addresses.length === 0) throw bad('vectors refused: no addresses');
    const expectKeys = d.descriptor === 1 ? ['vectors', 'template_hash', 'cmr', 'addresses'] : ['vectors', 'template_hash', 'addresses'];
    for (const k of Object.keys(v)) if (!expectKeys.includes(k)) throw bad(`vectors refused: unknown field ${k}`);
    v.addresses.forEach((c, i) => {
      const at = `vectors refused: address ${i} (${c && c.name})`;
      if (!c || typeof c.name !== 'string') throw bad(`${at}: no name`);
      let got;
      try { got = reader.derive(d, c.params, c.slots || {}); } catch (e) { throw bad(`${at}: ${e.message}`); }
      const extra = Object.keys(c).filter(k => !(k in got) && !['name', 'params', 'slots'].includes(k));
      if (extra.length) throw bad(`${at}: unknown field ${extra[0]}`);
      for (const k of Object.keys(got)) {
        if (canonicalize(got[k]) !== canonicalize(c[k])) throw bad(`${at}: ${k} is not what the descriptor derives`);
      }
    });

    const publisher = checkPublisher(sub.publisher);
    const audits = checkAudits(sub.audits);
    const name = t.name;
    const ns = name.includes('/') ? name.slice(0, name.indexOf('/')) : '';
    if (!ns || !name.slice(ns.length + 1)) throw bad(`name ${name} is not namespace/name`);
    return { d, m, publisher, audits, ns };
  }

  // The pinned compiler, run over the submission in a fresh directory: the
  // sources, roots, witness lists, cost bounds and lints, and the vectors again.
  // One at a time, so a burst of submissions cannot run many compilers at once.
  let compileQueue = Promise.resolve();
  function compileCheck(sub, d) {
    const job = compileQueue.then(() => new Promise((resolve, reject) => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'registry-template-'));
      const done = (err, out) => { fs.rmSync(dir, { recursive: true, force: true }); err ? reject(err) : resolve(out); };
      try {
        fs.writeFileSync(path.join(dir, 'descriptor.json'), sub.descriptor);
        fs.writeFileSync(path.join(dir, 'vectors.json'), sub.vectors);
        // Names the reader already checked: [A-Za-z0-9_-]+.simf, so no path leaves dir.
        for (const [n, text] of Object.entries(sub.sources)) fs.writeFileSync(path.join(dir, n), text);
      } catch (e) { return done(e); }
      execFile(SEQC, ['descriptor', 'check', dir], { cwd: dir, timeout: 120000, maxBuffer: 1 << 20 }, (err, stdout, stderr) => {
        const said = String(stdout || '').trim().replace(dir + ': ', '').split('\n').pop();
        if (err && err.code === 'ENOENT') return done(httpErr(503, `the compiler check is required and ${SEQC} cannot be run`));
        if (err) return done(bad(`the pinned compiler refused the template: ${said || String(stderr || err.message).trim()}`));
        done(null, said);
      });
    }));
    compileQueue = job.catch(() => {});
    return job;
  }

  function contractProofLine(domain, hash) {
    return `Authorize linking the domain name ${domain} to the Sequentia contract template ${hash}`;
  }

  async function registerTemplate(sub, opts = {}) {
    await readerReady;
    const { d, m, publisher, audits, ns } = readTemplate(sub);
    const hash = d.template_hash;
    const t = d.template;

    if (RESERVED_NAMESPACES.has(ns) && !opts.operator)
      throw httpErr(403, `the ${ns}/ namespace is published by the registry operator only`);
    const existing = read('contracts', hash);
    if (existing && existing.publisher.domain !== publisher.domain && !opts.operator)
      throw httpErr(409, `template ${hash} is already published by ${existing.publisher.domain}`);
    for (const e of all('contracts', HEX64)) {
      if (e.template_hash === hash) continue;
      if (e.name === t.name && e.version === t.version)
        throw httpErr(409, `${t.name} version ${t.version} is already template ${e.template_hash}`);
      const theirs = e.name.slice(0, e.name.indexOf('/'));
      if (theirs === ns && e.publisher.domain !== publisher.domain && !opts.operator)
        throw httpErr(409, `the ${ns}/ namespace belongs to ${e.publisher.domain}`);
    }

    let compile = null;
    if (REQUIRE_COMPILE) compile = await compileCheck(sub, d);

    let proof_url = null, verified_domain = false;
    if (REQUIRE_DOMAIN_PROOF && !opts.operator) {
      proof_url = await verifyProofLine(publisher.domain, `sequentia-contract-proof-${hash}`, contractProofLine(publisher.domain, hash));
      verified_domain = true;
    }

    const paths = m.paths;
    const entry = {
      template_hash: hash,
      name: t.name,
      version: t.version,
      summary: t.summary,
      descriptor_version: d.descriptor,
      compiler: PIN.compiler,
      leaves: leaves(m.tree).map(l => ({
        leaf: l.name,
        kind: l.kind,
        ...(l.kind === 'simplicity' ? {
          cmr: l.body.cmr, source: l.body.source, source_sha256: l.body.source_sha256,
          ...(d.descriptor === 2 ? { max_cost_wu: l.body.max_cost_wu } : {}),
        } : {}),
        paths: paths.filter(p => p.leaf === l.name).map(p => p.name),
      })),
      paths: paths.map(p => ({ name: p.name, who: p.who, effect: p.effect, ...(p.leaf ? { leaf: p.leaf } : {}) })),
      publisher,
      audits,
      verified_descriptor: true,
      verified_sources: true,
      verified_vectors: true,
      verified_compile: !!compile,
      compile_check: compile,
      verified_domain,
      verified_by: opts.operator ? 'operator' : (verified_domain ? 'domain' : null),
      verified: !!compile && (verified_domain || !!opts.operator || !REQUIRE_DOMAIN_PROOF),
      proof_url,
      registered_at: existing ? existing.registered_at : new Date().toISOString(),
      updated_at: new Date().toISOString(),
      descriptor: sub.descriptor,
      sources: sub.sources,
      vectors: sub.vectors,
    };
    write('contracts', hash, entry);
    return entry;
  }

  // ---------- instances ----------

  async function electrsJson(p) {
    const r = await fetchUrl(`${ELECTRS}${p}`, 8000, { trusted: true });
    if (r.status !== 200) throw httpErr(502, `electrs ${p}: HTTP ${r.status}`);
    return r.body;
  }

  async function registerInstance(hash, inst) {
    await readerReady;
    if (!HEX64.test(hash)) throw bad('template hash: 64 lowercase hex');
    const tpl = read('contracts', hash);
    if (!tpl) throw httpErr(404, `no template ${hash}`);
    if (!inst || typeof inst !== 'object') throw bad('body: { params, slots?, genesis }');
    for (const k of Object.keys(inst)) if (!['params', 'slots', 'genesis'].includes(k)) throw bad(`unknown field ${k}`);
    if (!HEX64.test(inst.genesis || '')) throw bad('genesis: 64 lowercase hex');
    const d = reader.parseDescriptor(tpl.descriptor);
    const chain = d.chains.find(c => c.name === CHAIN);
    if (!chain) throw bad(`the template is not addressed on ${CHAIN}`);
    const genesis = String(await electrsJson('/block-height/0')).trim();
    if (inst.genesis !== genesis) throw bad(`genesis ${inst.genesis} is not this chain's (${genesis})`);
    if (chain.genesis !== null && chain.genesis !== genesis) throw bad(`the template's ${CHAIN} is another chain (${chain.genesis})`);
    let x;
    try { x = reader.derive(d, inst.params, inst.slots || {}); } catch (e) { throw bad(`instance refused: ${e.message}`); }
    // Only an output the chain has paid is registered, so the index holds
    // contracts in use and nothing anyone can make up for free.
    const scripthash = crypto.createHash('sha256').update(Buffer.from(x.script_pubkey, 'hex')).digest('hex');
    let stats;
    try { stats = JSON.parse(await electrsJson(`/scripthash/${scripthash}`)); } catch (e) { throw httpErr(502, `electrs: ${e.message}`); }
    const funded = (stats.chain_stats ? stats.chain_stats.funded_txo_count : 0) + (stats.mempool_stats ? stats.mempool_stats.funded_txo_count : 0);
    if (!funded) throw bad(`no output pays ${x.address[CHAIN]} on this chain`);
    const entry = {
      script_pubkey: x.script_pubkey,
      address: x.address[CHAIN],
      template_hash: hash,
      name: tpl.name,
      version: tpl.version,
      params: inst.params,
      slots: inst.slots || {},
      genesis,
      registered_at: (read('instances', x.script_pubkey) || {}).registered_at || new Date().toISOString(),
    };
    write('instances', x.script_pubkey, entry);
    return entry;
  }

  // What the explorer reads: each verified template's Simplicity leaves by
  // commitment root, and each registered instance by its script. One root can
  // sit in several templates, so a root maps to a list.
  function minimalIndex() {
    const out = { leaves: {}, scripts: {} };
    const verified = new Map();
    for (const e of all('contracts', HEX64)) {
      if (!e.verified) continue;
      verified.set(e.template_hash, e);
      for (const l of e.leaves) {
        if (l.kind !== 'simplicity') continue;
        (out.leaves[l.cmr] = out.leaves[l.cmr] || []).push([e.template_hash, e.name, e.version, l.leaf, l.paths[0] || null]);
      }
    }
    for (const i of all('instances', SPK_RE)) {
      const e = verified.get(i.template_hash);
      if (e) out.scripts[i.script_pubkey] = [e.template_hash, e.name, e.version];
    }
    return out;
  }

  const summary = e => {
    const { descriptor, sources, vectors, ...rest } = e;
    return rest;
  };

  // ---------- oracle keys ----------

  function checkOracleRecord(r) {
    const fields = ['version', 'key', 'feeds', 'operator', 'endpoints', 'attestation_tag', 'bond', 'revoked'];
    if (!r || typeof r !== 'object' || Array.isArray(r)) throw bad('record: an object');
    for (const k of Object.keys(r)) if (!fields.includes(k)) throw bad(`record: unknown field ${k}`);
    if (r.version !== 1) throw bad('record.version: 1');
    if (!HEX64.test(r.key || '')) throw bad('record.key: a 32-byte x-only key, lowercase hex');
    if (!liftX(BigInt('0x' + r.key))) throw bad('record.key: not the x coordinate of a curve point');
    if (!Array.isArray(r.feeds) || r.feeds.length < 1 || r.feeds.length > 50) throw bad('record.feeds: 1 to 50 feeds');
    const ids = new Set();
    r.feeds.forEach((f, i) => {
      if (!f || typeof f !== 'object' || Array.isArray(f)) throw bad(`record.feeds[${i}]: an object`);
      for (const k of Object.keys(f)) if (!['id', 'description', 'decimals'].includes(k)) throw bad(`record.feeds[${i}]: unknown field ${k}`);
      strField(f.id, `record.feeds[${i}].id`, 64);
      if (ids.has(f.id)) throw bad(`record.feeds: ${f.id} twice`);
      ids.add(f.id);
      strField(f.description, `record.feeds[${i}].description`, 200);
      if (!Number.isInteger(f.decimals) || f.decimals < 0 || f.decimals > 18) throw bad(`record.feeds[${i}].decimals: an integer 0 to 18`);
    });
    const op = r.operator;
    if (!op || typeof op !== 'object' || Array.isArray(op)) throw bad('record.operator: { name, domain }');
    for (const k of Object.keys(op)) if (k !== 'name' && k !== 'domain') throw bad(`record.operator: unknown field ${k}`);
    strField(op.name, 'record.operator.name', 100);
    if (typeof op.domain !== 'string' || !DOMAIN_RE.test(op.domain) || op.domain !== op.domain.toLowerCase()) throw bad('record.operator.domain: a lowercase DNS domain');
    if (!Array.isArray(r.endpoints) || r.endpoints.length < 1 || r.endpoints.length > 5) throw bad('record.endpoints: 1 to 5 https URLs where every attestation is published');
    r.endpoints.forEach((u, i) => httpsUrl(u, `record.endpoints[${i}]`));
    strField(r.attestation_tag, 'record.attestation_tag', 64);
    if (r.bond !== undefined) strField(r.bond, 'record.bond', 300);
    if (r.revoked !== undefined && typeof r.revoked !== 'boolean') throw bad('record.revoked: a boolean');
  }

  // What the key signs: a BIP340 tagged hash of the record's canonical JSON.
  const oracleRecordHash = r => taggedHash(ORACLE_RECORD_TAG, Buffer.from(canonicalize(r), 'utf8'));

  function oracleProofLine(domain, key) {
    return `Authorize linking the domain name ${domain} to the Sequentia oracle key ${key}`;
  }

  async function registerOracle(body, opts = {}) {
    if (!body || typeof body !== 'object') throw bad('body: { record, signature }');
    for (const k of Object.keys(body)) if (k !== 'record' && k !== 'signature') throw bad(`unknown field ${k}`);
    const r = body.record;
    checkOracleRecord(r);
    if (!HEX128.test(body.signature || '')) throw bad('signature: 64 bytes, lowercase hex');
    if (!schnorrVerify(Buffer.from(r.key, 'hex'), oracleRecordHash(r), Buffer.from(body.signature, 'hex')))
      throw httpErr(403, `the signature is not the key's over the record (BIP340, tag ${ORACLE_RECORD_TAG})`);
    const existing = read('oracles', r.key);
    if (existing && existing.record.operator.domain !== r.operator.domain && !opts.operator)
      throw httpErr(409, `oracle key ${r.key} is already operated by ${existing.record.operator.domain}`);
    let proof_url = null, verified_domain = false;
    if (REQUIRE_DOMAIN_PROOF && !opts.operator) {
      proof_url = await verifyProofLine(r.operator.domain, `sequentia-oracle-proof-${r.key}`, oracleProofLine(r.operator.domain, r.key));
      verified_domain = true;
    }
    const entry = {
      key: r.key,
      record: r,
      signature: body.signature,
      record_hash: oracleRecordHash(r).toString('hex'),
      verified_key: true,
      verified_domain,
      verified_by: opts.operator ? 'operator' : (verified_domain ? 'domain' : null),
      verified: verified_domain || !!opts.operator || !REQUIRE_DOMAIN_PROOF,
      proof_url,
      revoked: !!r.revoked,
      registered_at: existing ? existing.registered_at : new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
    write('oracles', r.key, entry);
    return entry;
  }

  // ---------- routes ----------

  // Returns true when it answered the request.
  async function route(req, p, send, readJson, isAdmin) {
    if (req.method === 'GET') {
      if (p === '/contracts') return send(200, all('contracts', HEX64).map(summary)), true;
      if (p === '/contracts/index.minimal.json') return send(200, minimalIndex()), true;
      let m = p.match(/^\/contracts\/([0-9a-f]{64})$/);
      if (m) { const e = read('contracts', m[1]); return send(e ? 200 : 404, e || { error: 'not found' }), true; }
      m = p.match(/^\/contracts\/([0-9a-f]{64})\/instances$/);
      if (m) return send(200, all('instances', SPK_RE).filter(i => i.template_hash === m[1])), true;
      m = p.match(/^\/contracts\/instances\/([0-9a-f]+)$/);
      if (m) { const e = read('instances', m[1]); return send(e ? 200 : 404, e || { error: 'not found' }), true; }
      if (p === '/oracles') return send(200, all('oracles', HEX64)), true;
      m = p.match(/^\/oracles\/([0-9a-f]{64})$/);
      if (m) { const e = read('oracles', m[1]); return send(e ? 200 : 404, e || { error: 'not found' }), true; }
      return false;
    }
    if (req.method !== 'POST') return false;
    if (p === '/contracts') {
      const e = await registerTemplate(await readJson(), {});
      console.log(`[registry] contract ${e.template_hash} (${e.name} v${e.version}) by ${e.publisher.domain} verified=${e.verified}`);
      return send(200, summary(e)), true;
    }
    if (p === '/admin/contracts') {
      if (!isAdmin()) return send(403, { error: 'forbidden' }), true;
      const e = await registerTemplate(await readJson(), { operator: true });
      console.log(`[registry] contract ${e.template_hash} (${e.name} v${e.version}) by the operator verified=${e.verified}`);
      return send(200, summary(e)), true;
    }
    const m = p.match(/^\/contracts\/([0-9a-f]{64})\/instances$/);
    if (m) {
      const e = await registerInstance(m[1], await readJson());
      console.log(`[registry] instance ${e.address} of ${e.name}`);
      return send(200, e), true;
    }
    if (p === '/oracles' || p === '/admin/oracles') {
      const operator = p === '/admin/oracles';
      if (operator && !isAdmin()) return send(403, { error: 'forbidden' }), true;
      const e = await registerOracle(await readJson(), { operator });
      console.log(`[registry] oracle key ${e.key} (${e.record.operator.domain}) verified=${e.verified}`);
      return send(200, e), true;
    }
    return false;
  }

  return { route, registerTemplate, registerInstance, registerOracle, minimalIndex, readerReady };
}

// ---------- BIP340 ----------
// Verification only, with BigInt arithmetic: the registry checks that an oracle
// key signed its own record. Nothing here holds a secret, so constant time does
// not matter.
const P = 2n ** 256n - 2n ** 32n - 977n;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const G = [0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n];
const mod = (a, m = P) => ((a % m) + m) % m;
function pow(b, e, m = P) { let r = 1n; b = mod(b, m); while (e > 0n) { if (e & 1n) r = r * b % m; b = b * b % m; e >>= 1n; } return r; }
function add(a, b) {
  if (a === null) return b;
  if (b === null) return a;
  if (a[0] === b[0] && a[1] !== b[1]) return null;
  const l = a[0] === b[0] ? mod(3n * a[0] * a[0] * pow(2n * a[1], P - 2n)) : mod((b[1] - a[1]) * pow(b[0] - a[0], P - 2n));
  const x = mod(l * l - a[0] - b[0]);
  return [x, mod(l * (a[0] - x) - a[1])];
}
function mul(k, pt) { let r = null; while (k > 0n) { if (k & 1n) r = add(r, pt); pt = add(pt, pt); k >>= 1n; } return r; }
function liftX(x) {
  if (x >= P) return null;
  const c = mod(x ** 3n + 7n);
  const y = pow(c, (P + 1n) / 4n);
  if (mod(y * y) !== c) return null;
  return [x, y % 2n === 0n ? y : P - y];
}
const int = b => BigInt('0x' + (Buffer.from(b).toString('hex') || '0'));
const bytes32 = n => Buffer.from(n.toString(16).padStart(64, '0'), 'hex');
function taggedHash(tag, msg) {
  const t = crypto.createHash('sha256').update(tag, 'utf8').digest();
  return crypto.createHash('sha256').update(Buffer.concat([t, t, msg])).digest();
}
function schnorrVerify(pub, msg, sig) {
  if (pub.length !== 32 || msg.length !== 32 || sig.length !== 64) return false;
  const p = liftX(int(pub));
  const r = int(sig.subarray(0, 32));
  const s = int(sig.subarray(32));
  if (!p || r >= P || s >= N) return false;
  const e = mod(int(taggedHash('BIP0340/challenge', Buffer.concat([sig.subarray(0, 32), pub, msg]))), N);
  const R = add(mul(s, G), mul(N - e, p));
  return R !== null && R[1] % 2n === 0n && R[0] === r;
}

module.exports = { init, schnorrVerify, taggedHash, liftX, mul, G, N, bytes32, int, ORACLE_RECORD_TAG, PIN };
