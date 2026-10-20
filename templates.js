'use strict';
/*
 * The Arca leaf template list: every leaf template an Arca operator may
 * co-sign, with the script hashes of its golden vectors, beside the contract
 * collection.
 *
 * A leaf template is a family of tapscript outputs, one per set of keys and
 * delays, so what identifies it is its golden vector: the output the template
 * builds from fixed test parameters, which every implementation must
 * reproduce byte for byte. The vectors are those of the arca repository
 * (regtest/vectors/arca.json), copied unchanged into arca/vectors.json at the
 * commit arca/PIN.json names, with the file's SHA-256; arca/PIN.json also
 * names which vectors belong to which template. Never edit the copy: move
 * the pin.
 *
 * At start the registry checks the copy against the pin's hash and rebuilds
 * each vector's output from its leaves: each leaf's hash from its script
 * (TapLeaf/elements, leaf version 0xc4), the root from the leaf's control
 * block (TapBranch/elements), the output key from the internal key tweaked
 * by the root (TapTweak/elements), and the script from the key. Every leaf
 * of a vector must reach the same root, and the script must be the vector's.
 * A copy that fails any check stops the registry: it never serves a list it
 * has not rebuilt.
 */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { taggedHash, liftX, mul, add, G, N, P, bytes32, int } = require('./contracts');

const DIR = path.join(__dirname, 'arca');

function compactSize(n) {
  if (n < 0xfd) return Buffer.from([n]);
  if (n <= 0xffff) { const b = Buffer.alloc(3); b[0] = 0xfd; b.writeUInt16LE(n, 1); return b; }
  const b = Buffer.alloc(5); b[0] = 0xfe; b.writeUInt32LE(n, 1); return b;
}

// The output key and its parity: lift_x(internal) + t·G.
function tweak(internal, root) {
  const p = liftX(int(internal));
  if (!p) throw new Error('the internal key is not on the curve');
  const t = int(taggedHash('TapTweak/elements', Buffer.concat([internal, root])));
  if (t >= N) throw new Error('the tweak is out of range');
  const q = add(p, mul(t, G));
  return { key: bytes32(q[0]), parity: Number(q[1] % 2n) };
}

// Rebuilds a vector's output from its leaves; returns what the list shows.
function rebuild(name, v) {
  const internal = Buffer.from(v.internal_key, 'hex');
  let root = null;
  const leaves = [];
  for (const [leaf, l] of Object.entries(v.leaves)) {
    const script = Buffer.from(l.script, 'hex');
    const cb = Buffer.from(l.control_block, 'hex');
    const version = cb[0] & 0xfe;
    if (version !== 0xc4 || l.leaf_version !== 'c4') throw new Error(`${name}.${leaf}: leaf version ${cb[0].toString(16)}, not c4`);
    if ((cb.length - 33) % 32 !== 0) throw new Error(`${name}.${leaf}: a control block of ${cb.length} bytes`);
    if (!cb.subarray(1, 33).equals(internal)) throw new Error(`${name}.${leaf}: the control block's internal key is not the vector's`);
    let h = taggedHash('TapLeaf/elements', Buffer.concat([Buffer.from([version]), compactSize(script.length), script]));
    if (h.toString('hex') !== l.leaf_hash) throw new Error(`${name}.${leaf}: the script hashes to ${h.toString('hex')}, not the leaf hash ${l.leaf_hash}`);
    for (let i = 33; i < cb.length; i += 32) {
      const s = cb.subarray(i, i + 32);
      h = taggedHash('TapBranch/elements', Buffer.compare(h, s) <= 0 ? Buffer.concat([h, s]) : Buffer.concat([s, h]));
    }
    if (root && !root.equals(h)) throw new Error(`${name}.${leaf}: reaches root ${h.toString('hex')}, another leaf ${root.toString('hex')}`);
    root = h;
    const q = tweak(internal, h);
    if (q.parity !== (cb[0] & 1)) throw new Error(`${name}.${leaf}: the control block's parity is not the output key's`);
    leaves.push({ leaf, leaf_hash: l.leaf_hash, bytes: script.length });
  }
  if (!root) throw new Error(`${name}: no leaves`);
  if (root.toString('hex') !== v.merkle_root) throw new Error(`${name}: the leaves reach root ${root.toString('hex')}, not ${v.merkle_root}`);
  const { key } = tweak(internal, root);
  const spk = '5120' + key.toString('hex');
  if (key.toString('hex') !== v.output_key || spk !== v.script_pubkey) throw new Error(`${name}: the leaves build the script ${spk}, not ${v.script_pubkey}`);
  return {
    vector: name,
    description: v.template,
    script_pubkey: spk,
    script_hash: crypto.createHash('sha256').update(Buffer.from(spk, 'hex')).digest('hex'),
    merkle_root: v.merkle_root,
    leaves,
  };
}

function load(dir = DIR) {
  const pin = JSON.parse(fs.readFileSync(path.join(dir, 'PIN.json'), 'utf8'));
  const raw = fs.readFileSync(path.join(dir, 'vectors.json'));
  const got = crypto.createHash('sha256').update(raw).digest('hex');
  if (got !== pin.sha256) throw new Error(`arca/vectors.json hashes to ${got}, not the pinned ${pin.sha256}`);
  const vectors = JSON.parse(raw.toString('utf8'));
  const templates = pin.templates.map(t => ({
    name: t.name,
    use: t.use,
    vectors: t.vectors.map(n => {
      const v = vectors.outputs[n];
      if (!v) throw new Error(`${t.name}: the pinned file has no vector ${n}`);
      return rebuild(n, v);
    }),
  }));
  return {
    version: pin.list_version,
    source: { repository: pin.repository, commit: pin.commit, file: pin.file, sha256: pin.sha256 },
    templates,
  };
}

module.exports = { load, rebuild, compactSize };
