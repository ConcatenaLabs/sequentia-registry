'use strict';
/*
 * Arca operator records.
 *
 * An Arca operator lists itself here so that wallets can find it: a record of
 * its operator key, the chain's genesis, its API's address, the assets it
 * serves with their rate sources and fee schedules, its keepers, its exit
 * delays and expiry, the leaf templates it co-signs, and a contact, signed by
 * the operator key. The record says what the operator's own GET /v1/info
 * says, in the operator's own settings: a part it sets as a value in the
 * reference unit is recorded as that value, not as the atoms it comes to at
 * today's rate, and a rate is recorded by its source and how long it is
 * good for, not by the price it read last, so a record stays true while
 * prices move.
 *
 * The key signs a BIP340 tagged hash, tag sequentia-registry/arca-operator/v1,
 * of the record's canonical JSON (keys sorted, no white space, printable ASCII
 * strings, whole numbers up to 2^53 - 1, no null): the same bytes Arca's
 * arca_covenant::operator_record writes, so the operator's signer
 * (`arca-signer --sign-operator-record`) and every wallet agree on them.
 *
 * A record is listed only when its signature verifies and the operator's live
 * info says what it says; then it is checked again on a schedule. A record
 * whose operator answers with something else is marked `mismatched`, with each
 * difference; one whose operator has not answered for longer than
 * OPERATOR_STALE_AFTER_MS is marked `stale`; one that matches again is `ok`
 * again. A key's newer record replaces its older one; an older one is refused,
 * so a record cannot be played back over the one that replaced it.
 */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { schnorrVerify, taggedHash, liftX } = require('./contracts');

const TAG = 'sequentia-registry/arca-operator/v1';
const HEX64 = /^[0-9a-f]{64}$/;
const HEX128 = /^[0-9a-f]{128}$/;
const DEC = /^(0|[1-9][0-9]{0,17})$/;
const FIELDS = ['api', 'arca_operator', 'assets', 'contact', 'exit_delay_units', 'expiry', 'genesis_hash', 'issued_at', 'keepers', 'operator', 'templates'];
const RATE_SOURCES = ['node', 'file', 'command'];
const FEE_PARTS = ['refresh', 'offboard', 'lightning'];

// The canonical form: the bytes the operator key signs.
function canonical(v, at = 'record') {
  if (v === null || v === undefined) throw new Error(`${at}: null`);
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (typeof v === 'number') {
    if (!Number.isSafeInteger(v) || v < 0) throw new Error(`${at}: ${v} is not a whole number from 0 to 2^53 - 1`);
    return String(v);
  }
  const str = s => {
    if (!/^[\x20-\x7e]*$/.test(s)) throw new Error(`${at}: text other than printable ASCII`);
    return '"' + s.replace(/[\\"]/g, c => '\\' + c) + '"';
  };
  if (typeof v === 'string') return str(v);
  if (Array.isArray(v)) return '[' + v.map((e, i) => canonical(e, `${at}[${i}]`)).join(',') + ']';
  if (typeof v === 'object') {
    // Sorted by their bytes: keys are printable ASCII, where that is the
    // order of their UTF-16 code units too.
    return '{' + Object.keys(v).sort().map(k => str(k) + ':' + canonical(v[k], `${at}.${k}`)).join(',') + '}';
  }
  throw new Error(`${at}: not JSON`);
}

const recordDigest = r => taggedHash(TAG, Buffer.from(canonical(r), 'utf8'));

// The record a running operator's info implies, given what info does not
// carry: its public address, its contact and when the record is made.
function recordFromInfo(info, { api, contact, issued_at }) {
  const assets = (info.assets || []).map(a => {
    const out = { asset: a.asset };
    if (a.min_leaf_value !== undefined) out.min_leaf_value = a.min_leaf_value;
    else if (a.min_leaf !== undefined) out.min_leaf = a.min_leaf;
    if (a.rate) out.rate = { source: a.rate.source, max_age_seconds: a.rate.max_age_seconds };
    if (a.fees) {
      const f = {};
      for (const p of FEE_PARTS) {
        f[`${p}_ppm`] = a.fees[`${p}_ppm`];
        if (a.fees[`${p}_base_value`] !== undefined) f[`${p}_base_value`] = a.fees[`${p}_base_value`];
        else f[`${p}_base`] = a.fees[`${p}_base`];
      }
      out.fees = f;
    }
    return out;
  }).sort((x, y) => (x.asset < y.asset ? -1 : x.asset > y.asset ? 1 : 0));
  return {
    arca_operator: 1,
    operator: info.operator,
    genesis_hash: info.genesis_hash,
    api,
    assets,
    keepers: { keys: [...((info.keepers && info.keepers.keys) || [])].sort(), required: (info.keepers && info.keepers.required) || 0 },
    exit_delay_units: { min: info.exit_delay_units.min, max: info.exit_delay_units.max },
    expiry: { batch_lifetime_seconds: info.boards.lifetime_seconds, exit_deadline_seconds: info.boards.exit_deadline_seconds },
    templates: { version: info.templates.version, list: [...info.templates.list] },
    contact,
    issued_at,
  };
}

// Where a record and what the operator's info implies differ, field by
// field: [{field, record, info}].
function differences(record, info) {
  let live;
  try { live = recordFromInfo(info, { api: record.api, contact: record.contact, issued_at: record.issued_at }); } catch (e) {
    return [{ field: 'info', record: 'an operator info', info: `unreadable: ${e.message}` }];
  }
  const out = [];
  const same = (a, b) => { try { return canonical(a) === canonical(b); } catch (e) { return false; } };
  for (const f of ['operator', 'genesis_hash', 'keepers', 'exit_delay_units', 'expiry', 'templates']) {
    if (!same(record[f], live[f])) out.push({ field: f, record: record[f], info: live[f] === undefined ? null : live[f] });
  }
  const mine = new Map(record.assets.map(a => [a.asset, a]));
  const theirs = new Map(live.assets.map(a => [a.asset, a]));
  for (const [id, a] of mine) {
    if (!theirs.has(id)) out.push({ field: `assets.${id}`, record: a, info: 'not served' });
    else if (!same(a, theirs.get(id))) out.push({ field: `assets.${id}`, record: a, info: theirs.get(id) });
  }
  for (const [id, a] of theirs) if (!mine.has(id)) out.push({ field: `assets.${id}`, record: 'not listed', info: a });
  return out;
}

function init(deps) {
  const { DB_DIR, REQUIRE_DOMAIN_PROOF, DOMAIN_RE, fetchUrl, verifyProofLine, httpErr, templateNames } = deps;
  // Operators on this machine (a local chain): plain http and private
  // addresses are taken for an operator's API. Never on a public registry.
  const LOCAL = process.env.OPERATORS_LOCAL === '1';
  const CHECK_MS = Number(process.env.OPERATOR_CHECK_MS || 600000);
  const STALE_AFTER_MS = Number(process.env.OPERATOR_STALE_AFTER_MS || 3600000);
  const FETCH_MS = Number(process.env.OPERATOR_FETCH_TIMEOUT || 8000);
  const dir = path.join(DB_DIR, 'operators');
  fs.mkdirSync(dir, { recursive: true });
  const file = k => path.join(dir, `${k}.json`);
  const read = k => { try { return JSON.parse(fs.readFileSync(file(k), 'utf8')); } catch (e) { return null; } };
  const write = (k, v) => { const t = file(k) + '.tmp'; fs.writeFileSync(t, JSON.stringify(v, null, 2)); fs.renameSync(t, file(k)); };
  const all = () => fs.readdirSync(dir).filter(f => /^[0-9a-f]{64}\.json$/.test(f)).map(f => read(f.slice(0, -5))).filter(Boolean);
  const bad = why => httpErr(400, why);

  function only(o, at, fields, required = fields) {
    if (!o || typeof o !== 'object' || Array.isArray(o)) throw bad(`${at}: an object`);
    for (const k of Object.keys(o)) if (!fields.includes(k)) throw bad(`${at}: unknown field ${k}`);
    for (const k of required) if (o[k] === undefined) throw bad(`${at}.${k} is missing`);
  }
  const int = (v, at) => { if (!Number.isSafeInteger(v) || v < 0) throw bad(`${at}: a whole number`); };
  const dec = (v, at) => { if (typeof v !== 'string' || !DEC.test(v)) throw bad(`${at}: a decimal string of atoms`); };
  const text = (v, at, max) => { if (typeof v !== 'string' || v.length < 1 || v.length > max || !/^[\x20-\x7e]*$/.test(v)) throw bad(`${at}: printable text of 1 to ${max} characters`); };

  function checkRecord(r) {
    only(r, 'record', FIELDS);
    if (r.arca_operator !== 1) throw bad('record.arca_operator: 1');
    if (!HEX64.test(r.operator || '') || !liftX(BigInt('0x' + r.operator))) throw bad('record.operator: the x-only operator key, 64 lowercase hex');
    if (!HEX64.test(r.genesis_hash || '')) throw bad('record.genesis_hash: 64 lowercase hex, display order');
    text(r.api, 'record.api', 300);
    let u;
    try { u = new URL(r.api); } catch (e) { throw bad('record.api: not a URL'); }
    if (u.protocol !== 'https:' && !(LOCAL && u.protocol === 'http:')) throw bad('record.api: an https URL, the base wallets are given (`arca create --server`)');
    if (r.api.endsWith('/') || u.search || u.hash) throw bad('record.api: a base URL, without a trailing slash, query or fragment');
    if (!Array.isArray(r.assets) || r.assets.length < 1 || r.assets.length > 50) throw bad('record.assets: 1 to 50 assets');
    const seen = new Set();
    r.assets.forEach((a, i) => {
      const at = `record.assets[${i}]`;
      only(a, at, ['asset', 'min_leaf', 'min_leaf_value', 'rate', 'fees'], ['asset']);
      if (!HEX64.test(a.asset)) throw bad(`${at}.asset: an asset id, 64 lowercase hex`);
      if (seen.has(a.asset)) throw bad(`record.assets: ${a.asset} twice`);
      seen.add(a.asset);
      if (a.min_leaf !== undefined && a.min_leaf_value !== undefined) throw bad(`${at}: min_leaf or min_leaf_value, not both`);
      if (a.min_leaf !== undefined) dec(a.min_leaf, `${at}.min_leaf`);
      if (a.min_leaf_value !== undefined) dec(a.min_leaf_value, `${at}.min_leaf_value`);
      if (a.rate !== undefined) {
        only(a.rate, `${at}.rate`, ['source', 'max_age_seconds']);
        if (!RATE_SOURCES.includes(a.rate.source)) throw bad(`${at}.rate.source: ${RATE_SOURCES.join(', ')}`);
        int(a.rate.max_age_seconds, `${at}.rate.max_age_seconds`);
      }
      if (a.fees !== undefined) {
        const fields = FEE_PARTS.flatMap(p => [`${p}_ppm`, `${p}_base`, `${p}_base_value`]);
        only(a.fees, `${at}.fees`, fields, FEE_PARTS.map(p => `${p}_ppm`));
        for (const p of FEE_PARTS) {
          int(a.fees[`${p}_ppm`], `${at}.fees.${p}_ppm`);
          const b = a.fees[`${p}_base`], v = a.fees[`${p}_base_value`];
          if ((b === undefined) === (v === undefined)) throw bad(`${at}.fees: ${p}_base or ${p}_base_value, one of them`);
          dec(b === undefined ? v : b, `${at}.fees.${p}_base${b === undefined ? '_value' : ''}`);
        }
      }
    });
    for (let i = 1; i < r.assets.length; i++) if (r.assets[i - 1].asset > r.assets[i].asset) throw bad('record.assets: in the order of their ids');
    only(r.keepers, 'record.keepers', ['keys', 'required']);
    if (!Array.isArray(r.keepers.keys) || r.keepers.keys.length > 16 || !r.keepers.keys.every(k => HEX64.test(k))) throw bad('record.keepers.keys: up to 16 keys, 64 lowercase hex');
    if (r.keepers.keys.some((k, i) => i > 0 && r.keepers.keys[i - 1] >= k)) throw bad('record.keepers.keys: sorted, each once');
    int(r.keepers.required, 'record.keepers.required');
    if (r.keepers.keys.length ? !(r.keepers.required >= 1 && r.keepers.required <= r.keepers.keys.length) : r.keepers.required !== 0)
      throw bad('record.keepers.required: 0 with no keeper, otherwise from 1 to the number of keepers');
    only(r.exit_delay_units, 'record.exit_delay_units', ['min', 'max']);
    int(r.exit_delay_units.min, 'record.exit_delay_units.min'); int(r.exit_delay_units.max, 'record.exit_delay_units.max');
    if (r.exit_delay_units.min > r.exit_delay_units.max) throw bad('record.exit_delay_units: min above max');
    only(r.expiry, 'record.expiry', ['batch_lifetime_seconds', 'exit_deadline_seconds']);
    int(r.expiry.batch_lifetime_seconds, 'record.expiry.batch_lifetime_seconds'); int(r.expiry.exit_deadline_seconds, 'record.expiry.exit_deadline_seconds');
    only(r.templates, 'record.templates', ['version', 'list']);
    int(r.templates.version, 'record.templates.version');
    if (!Array.isArray(r.templates.list) || r.templates.list.length < 1 || r.templates.list.length > 32) throw bad('record.templates.list: 1 to 32 template names');
    r.templates.list.forEach((t, i) => { if (typeof t !== 'string' || !/^[a-z0-9]+-[1-9][0-9]*$/.test(t)) throw bad(`record.templates.list[${i}]: a name as vtxo-1`); });
    only(r.contact, 'record.contact', ['name', 'domain', 'email', 'url'], ['name', 'domain']);
    text(r.contact.name, 'record.contact.name', 100);
    if (typeof r.contact.domain !== 'string' || !DOMAIN_RE.test(r.contact.domain) || r.contact.domain !== r.contact.domain.toLowerCase()) throw bad('record.contact.domain: a lowercase DNS domain');
    if (r.contact.email !== undefined && (typeof r.contact.email !== 'string' || !/^[^\s@]{1,64}@[^\s@]{1,253}$/.test(r.contact.email))) throw bad('record.contact.email: an address');
    if (r.contact.url !== undefined) { text(r.contact.url, 'record.contact.url', 300); if (!/^https:\/\//.test(r.contact.url)) throw bad('record.contact.url: an https URL'); }
    int(r.issued_at, 'record.issued_at');
    if (r.issued_at > Math.floor(Date.now() / 1000) + 600) throw bad('record.issued_at: more than ten minutes ahead of the registry\'s clock');
    try { canonical(r); } catch (e) { throw bad(`record: ${e.message}`); }
  }

  // The operator's live info, read through the SSRF guard unless the
  // registry is told its operators are on this machine.
  async function liveInfo(api) {
    const r = await fetchUrl(`${api}/v1/info`, FETCH_MS, { trusted: LOCAL });
    if (r.status !== 200) throw new Error(`GET ${api}/v1/info answered HTTP ${r.status}`);
    try { return JSON.parse(r.body); } catch (e) { throw new Error(`GET ${api}/v1/info: not JSON`); }
  }

  // What the registry shows beside a record from the operator's info: the
  // rates the operator reads now, and the templates it names that the
  // registry's list does not hold.
  function liveView(record, info) {
    const rates = {};
    for (const a of info.assets || []) if (a.rate) rates[a.asset] = { rate: a.rate.rate || null, age_seconds: a.rate.age_seconds === undefined ? null : a.rate.age_seconds, stale: !!a.rate.stale };
    const known = new Set(templateNames());
    return { rates, unknown_templates: record.templates.list.filter(t => !known.has(t)) };
  }

  function proofLine(domain, key) {
    return `Authorize linking the domain name ${domain} to the Arca operator key ${key}`;
  }

  async function register(body, opts = {}) {
    if (!body || typeof body !== 'object') throw bad('body: { record, signature }');
    for (const k of Object.keys(body)) if (k !== 'record' && k !== 'signature') throw bad(`unknown field ${k}`);
    const r = body.record;
    checkRecord(r);
    if (!HEX128.test(body.signature || '')) throw bad('signature: 64 bytes, lowercase hex');
    if (!schnorrVerify(Buffer.from(r.operator, 'hex'), recordDigest(r), Buffer.from(body.signature, 'hex')))
      throw httpErr(403, `the signature is not the operator key's over the record (BIP340, tag ${TAG})`);
    const existing = read(r.operator);
    if (existing) {
      if (r.issued_at < existing.record.issued_at) throw httpErr(409, `the registry lists a newer record of operator ${r.operator} (issued at ${existing.record.issued_at}); an older one never replaces it`);
      if (r.issued_at === existing.record.issued_at && canonical(r) !== canonical(existing.record)) throw httpErr(409, `operator ${r.operator} already has another record issued at ${r.issued_at}`);
      if (existing.record.contact.domain !== r.contact.domain && !opts.operator) throw httpErr(409, `operator key ${r.operator} is listed by ${existing.record.contact.domain}`);
    }
    let info;
    try { info = await liveInfo(r.api); } catch (e) { throw httpErr(502, `the operator's info could not be read, so the record cannot be checked: ${e.message}`); }
    const diffs = differences(r, info);
    if (diffs.length) throw httpErr(400, `the record does not say what the operator's info says: ${diffs.map(d => d.field).join(', ')}: ${JSON.stringify(diffs)}`);
    let proof_url = null, verified_domain = false;
    if (REQUIRE_DOMAIN_PROOF && !opts.operator) {
      proof_url = await verifyProofLine(r.contact.domain, `sequentia-operator-proof-${r.operator}`, proofLine(r.contact.domain, r.operator));
      verified_domain = true;
    }
    const now = new Date().toISOString();
    const entry = {
      key: r.operator,
      record: r,
      signature: body.signature,
      record_hash: recordDigest(r).toString('hex'),
      status: 'ok',
      checked_at: now,
      last_ok_at: now,
      differences: [],
      live: liveView(r, info),
      verified_signature: true,
      verified_domain,
      verified_by: opts.operator ? 'operator' : (verified_domain ? 'domain' : null),
      proof_url,
      registered_at: existing ? existing.registered_at : now,
      updated_at: now,
    };
    write(r.operator, entry);
    return entry;
  }

  // One check of a listed record against its operator's info.
  async function check(key, now = Date.now()) {
    const e = read(key);
    if (!e) return null;
    let info;
    try { info = await liveInfo(e.record.api); } catch (err) {
      e.last_error = err.message;
      e.checked_at = new Date(now).toISOString();
      if (now - Date.parse(e.last_ok_at) > STALE_AFTER_MS) e.status = 'stale';
      write(key, e);
      return e;
    }
    delete e.last_error;
    e.differences = differences(e.record, info);
    e.status = e.differences.length ? 'mismatched' : 'ok';
    e.checked_at = new Date(now).toISOString();
    if (!e.differences.length) e.last_ok_at = e.checked_at;
    e.live = liveView(e.record, info);
    write(key, e);
    return e;
  }

  let running = false;
  async function checkAll() {
    if (running) return;
    running = true;
    try {
      for (const e of all()) {
        const was = e.status;
        const now = await check(e.key);
        if (now && now.status !== was) console.log(`[registry] operator ${e.key}: ${was} -> ${now.status}${now.last_error ? ` (${now.last_error})` : ''}`);
      }
    } finally { running = false; }
  }
  if (CHECK_MS > 0) setInterval(() => { checkAll().catch(err => console.error(`[registry] operator checks: ${err.message}`)); }, CHECK_MS).unref();

  async function route(req, p, send, readJson, isAdmin) {
    if (req.method === 'GET') {
      if (p === '/operators') return send(200, all()), true;
      const m = p.match(/^\/operators\/([0-9a-f]{64})$/);
      if (m) { const e = read(m[1]); return send(e ? 200 : 404, e || { error: 'not found' }), true; }
      return false;
    }
    if (req.method !== 'POST') return false;
    if (p === '/operators' || p === '/admin/operators') {
      const operator = p === '/admin/operators';
      if (operator && !isAdmin()) return send(403, { error: 'forbidden' }), true;
      const e = await register(await readJson(), { operator });
      console.log(`[registry] operator ${e.key} (${e.record.contact.domain}) at ${e.record.api}, issued ${e.record.issued_at}`);
      return send(200, e), true;
    }
    // A check now, for the registry's operator: it costs a fetch of the
    // operator's info, so it is not open to anyone.
    const m = p.match(/^\/admin\/operators\/([0-9a-f]{64})\/check$/);
    if (m) {
      if (!isAdmin()) return send(403, { error: 'forbidden' }), true;
      const e = await check(m[1]);
      return send(e ? 200 : 404, e || { error: 'not found' }), true;
    }
    return false;
  }

  return { route, register, check, checkAll };
}

module.exports = { init, canonical, recordDigest, recordFromInfo, differences, TAG, FIELDS };
