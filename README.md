# Sequentia Asset Registry

The asset-metadata service for the Sequentia network. On-chain, a Sequentia asset
is only a 64-hex asset id plus a `contract_hash` commitment; this registry maps
that id to verified, human-readable metadata (name, ticker, precision, issuer
domain), the Sequentia equivalent of the Blockstream Liquid Asset Registry.
Every Sequentia surface (the node, the node GUI, the block explorer, the web
wallet) fetches asset labels from here, so there is a single source of truth
instead of hand-maintained lists.

Beside the assets it keeps more collections: **contract templates**
(Simplicity and tapscript contracts, each verified on write against its
descriptor, sources, golden vectors and pinned compiler, with the instances the
chain has paid), **oracle keys** (the price feeds a BIP340 key signs and where
its attestations are published), **Arca operators** (each operator's signed
record, checked against its live `info`, which wallets read to find an
operator) and the **Arca leaf templates** (every leaf template an operator
co-signs, with the script hashes of its golden vectors). See the sections of
those names below.

The service is `server.js` with the collections in `contracts.js`,
`operators.js` and `templates.js`, and has zero npm dependencies:

```
node server.js
```

> **Testnet software.** Everything here serves the public Sequentia testnet
> (parent chain: Bitcoin testnet4). No mainnet is running yet.

## Where this fits in the Sequentia ecosystem

| Repo | One-liner |
|---|---|
| [`Sequentia`](https://github.com/ConcatenaLabs/Sequentia) | The Sequentia node (`sequentiad`, a fork of Elements 23.3.3): consensus, anchoring, proof of stake, open fee market, plus the canonical protocol documentation in `doc/sequentia/`. |
| [`sequentia-electrs`](https://github.com/ConcatenaLabs/sequentia-electrs) | The electrs fork: Rust indexer + Esplora REST API for Sequentia and its Bitcoin testnet4 parent chain. The registry uses it for on-chain verification. |
| [`sequentia-explorer`](https://github.com/ConcatenaLabs/sequentia-explorer) | Sequentia block explorer frontend (esplora fork); the indexer lives in sequentia-electrs. Its public server also proxies this registry. |
| [`SWK`](https://github.com/ConcatenaLabs/SWK) | Sequentia Wallet Kit: a fork of Blockstream LWK, a Rust wallet library, CLI, and WASM bindings for building Sequentia (and Bitcoin testnet4) wallets. |
| [`sequentia-web-wallet`](https://github.com/ConcatenaLabs/sequentia-web-wallet) | Proof-of-concept browser wallet built on SWK, live at https://sequentiatestnet.com/wallet. Reads its asset labels from this registry. |
| [`openamp`](https://github.com/ConcatenaLabs/openamp) | OpenAMP: open-source restricted-asset issuance/transfer-approval service (an AMP2 equivalent) with opt-in confidentiality; zero consensus changes. Restricted assets carry an `openamp` block in their registry contract. |

Umbrella protocol documentation:
[`Sequentia/doc/sequentia/`](https://github.com/ConcatenaLabs/Sequentia/tree/master/doc/sequentia).

## Live instance

A public instance serves the public testnet at:

```
https://sequentiatestnet.com/registry/
```

(The explorer's public server proxies the `/registry` path to the registry
process; see `serve-public.js` in
[sequentia-explorer](https://github.com/ConcatenaLabs/sequentia-explorer).)

Quick check:

```
curl -s https://sequentiatestnet.com/registry/health
curl -s https://sequentiatestnet.com/registry/index.minimal.json
```

The full verification pipeline -- on-chain contract binding, asset-id
re-derivation, domain proof, ticker uniqueness -- is enforced for every new
registration. It stops at the consumer's door: the node fetches the index over
plain HTTP with no signature, so labels are advisory rather than a guarantee
(see "Trust model" below).

## Trust model

Anyone can submit metadata for an asset via `POST /`, but it is only stored as
**verified** if all of the following pass:

1. **Contract binding (on-chain).** An asset's metadata is a *contract* JSON.
   Its `contract_hash = SHA256(canonical-JSON(contract))` must equal the
   `contract_hash` committed on-chain in the asset's initial issuance input
   (reissuances are rejected). The registry looks the asset up via electrs
   (`SEQ_ELECTRS_URL`) and compares. Since the asset id is derived from the
   contract hash, nobody can register false metadata for an asset they did not
   issue.
2. **Asset-id re-derivation.** As a defense in depth, the registry re-derives
   the asset id itself from the issuance prevout and the on-chain
   `contract_hash` (Elements' fast-merkle / SHA256-midstate derivation,
   reimplemented in `server.js`; references: `src/issuance.cpp` and
   `src/primitives/txwitness.cpp` in the node repo) and requires it to equal
   the submitted asset id. A forged electrs reply cannot decouple the two.
3. **Domain proof.** The issuer must publish, at
   `https://<entity.domain>/.well-known/sequentia-asset-proof-<asset_id>`,
   a body that is exactly the line:

   ```
   Authorize linking the domain name <entity.domain> to the Sequentia asset <asset_id>
   ```

   The registry fetches this over HTTPS with an SSRF guard (the domain must
   resolve to a public address). The exact-match on the whole body is what
   prevents smuggling the line inside user-generated HTML on a domain the
   issuer does not control. The declared content type may be `text/plain`,
   `application/octet-stream`, or absent — what extensionless files typically
   get — but a response declaring itself anything else (HTML, say) is refused.

Tickers are additionally unique first-come, case-insensitive: a registration
whose ticker is already held by a different asset is rejected with HTTP 409,
and a small set of legacy demo tickers is reserved for the seeded entries
(`RESERVED_TICKERS` in `server.js`).

Entries record the outcome as `verified_chain`, `verified_domain`, and the
combined `verified` flag. Seeded legacy entries (see below) are stored with
`verified: false, legacy: true`.

**Consumer caveat.** The registry's labels are advisory display metadata, not a
cryptographic guarantee to the consumer. In particular the Sequentia node
fetches the index over plain HTTP with no TLS and no signature (the
`-assetregistryurl` help text in the node says the same), so labels must never
be treated as authoritative for value decisions.

## Contract format

```json
{
  "name": "USD Stablecoin",
  "ticker": "USDX",
  "precision": 8,
  "entity": { "domain": "example.com" },
  "issuer_pubkey": "02abc...",
  "version": 0
}
```

Validation rules (from `validateContract` in `server.js`):

| Field | Rule |
|---|---|
| `name` | string, 1..255 chars |
| `ticker` | 1..12 chars of `A-Za-z0-9.-` (mixed case allowed, e.g. `tSEQ`) |
| `precision` | integer 0..8 |
| `entity.domain` | valid DNS domain |
| `entity.issuer` | optional string (the issuing entity's name); no other `entity` fields allowed |
| `issuer_pubkey` | 33-byte compressed pubkey hex, or 32-byte x-only hex (BIP340, used by OpenAMP enclave keys); an all-zeros X coordinate is rejected |
| `version` | must be `0` |
| `openamp` | optional, see below |
| `operator` | optional `{ "name", "registration" }`, both strings (the registrar or transfer agent operating a policy server) |
| `supervision` | optional `{ "operational_key", "recovery_key", "feature_bits" }`: the two keys as 32-byte x-only hex, `feature_bits` an integer 0..65535. A supervised (issuer-freezable) asset may restate its on-chain supervision descriptor here; registration cross-checks it against the issuance's declaration and rejects a contract that misstates it or claims supervision the chain does not declare. See `doc/sequentia/supervised-assets.md` in the node repo. |
| `terms_hash` | optional 64-hex commitment to the offering terms (top level, for supervised issuances that carry no `openamp` block) |

Any other top-level key is rejected so the canonical hash is well-defined.

**Canonical hashing.** Issuers must replicate this exactly so the on-chain
`contract_hash` matches: serialize the contract as JSON with object keys sorted
lexicographically and no insignificant whitespace, then SHA256 the UTF-8 bytes.

### Optional `openamp` block (restricted assets)

OpenAMP restricted assets embed their policy binding in the contract, so the
on-chain `contract_hash` commits to it:

```json
"openamp": {
  "version": 1,
  "type": "restricted",
  "policy_pubkey": "<32-byte x-only hex (FROST group key)>",
  "clawback": true,
  "confidential": false,
  "policy_endpoints": ["https://sequentiatestnet.com/openamp/"]
}
```

Rules: `version` integer >= 1; `type` is `"restricted"` or `"tracked"`;
`policy_pubkey` is 32-byte x-only hex; `clawback` boolean; optional
`burn_allowed` and `confidential` booleans; optional `policy_endpoints` array
of https URLs; optional `terms_hash`. See
[`openamp/spec/contract-v1.md`](https://github.com/ConcatenaLabs/openamp/blob/main/spec/contract-v1.md)
for the full semantics. The seeded BONDX demo asset is an example.

## API

Base URL: `https://sequentiatestnet.com/registry` (public testnet instance) or
`http://localhost:3005` (local run). All responses are JSON with
`Access-Control-Allow-Origin: *` and `Cache-Control: public, max-age=30`.
Errors are `{ "error": "<message>" }` with an appropriate 4xx/5xx status.

| Method | Path | Description |
|---|---|---|
| GET | `/` | All registered entries (array) |
| GET | `/<asset_id>` | One entry (404 if unknown) |
| GET | `/index.json` | `{ asset_id: entry }` |
| GET | `/index.minimal.json` | `{ asset_id: [domain, ticker, name, precision, verified, supervised] }`, the format consumers use |
| GET | `/health` | `{ ok, count, electrs }` |
| POST | `/` | Submit `{ asset_id, contract }`: runs all verifications, then registers |
| POST | `/succeed` | Submit `{ asset_id, contract, signature }`: hand the asset's display identity to a successor (see "Succession") |
| POST | `/admin/seed` | (bearer `ADMIN_TOKEN`) add a pre-approved entry, skipping chain and domain checks |

`index.minimal.json` entry example (live):

```json
"8d1dbf45af45dd18eac10215efb86386695b9c4122ce6f4c18e03fea155e86c7": [
  "sequentiatestnet.com", "BONDX", "OpenAMP Demo Bond", 8, 0, 0
]
```

The 5th element is the `verified` flag (1/0). The 6th is `supervised` (1/0):
1 when the issuer can freeze holders of the asset by consensus rule; absent or
0 means not supervised. It rides in the minimal index because that is the file
every wallet loads at startup, and a holder has to be told before accepting
the asset. Consumers that only read elements 0..3 (the old Liquid
`assets.minimal.json` shape) are unaffected.

A full entry (`GET /<asset_id>`) looks like:

```json
{
  "asset_id": "<64-hex>",
  "contract": { "...": "the contract JSON" },
  "contract_hash": "<64-hex>",
  "issuance_txid": "<64-hex or null for seeded entries>",
  "verified": true,
  "verified_chain": true,
  "verified_domain": true,
  "legacy": false,
  "proof_url": "https://<domain>/.well-known/sequentia-asset-proof-<asset_id>",
  "supervision": { "supervised": false }
}
```

`supervision` is read from the chain at registration: `{ "supervised": true,
"version", "operational_key", "recovery_key", "pause_allowed" }` for a
supervised asset, `{ "supervised": false }` otherwise, `null` for a seeded
legacy entry. An entry that has been handed to a successor additionally
carries `origin_contract` (the contract as issued) and `successions[]` (see
"Succession").

Request bodies are capped at 256 KB (1 MB for the contract and oracle routes);
a larger one is answered with 413. POST failure statuses: 400 (validation,
chain mismatch, domain-proof failure), 403 (bad/missing admin token, or a
succession signature that does not verify), 404 (succession of an unknown
asset), 409 (ticker already claimed or reserved).

## Registering an asset, step by step

1. **Write the contract JSON** (see "Contract format").

2. **Compute the contract hash** with the same canonicalization the registry
   uses:

   ```
   node -e '
   function c14n(v){if(Array.isArray(v))return"["+v.map(c14n).join(",")+"]";
   if(v&&typeof v==="object")return"{"+Object.keys(v).sort().map(k=>JSON.stringify(k)+":"+c14n(v[k])).join(",")+"}";
   return JSON.stringify(v)}
   const contract={name:"Example Asset",ticker:"EXA",precision:8,entity:{domain:"example.com"},issuer_pubkey:"02...",version:0};
   console.log(require("crypto").createHash("sha256").update(c14n(contract),"utf8").digest("hex"));'
   ```

3. **Issue the asset with that hash committed on-chain**: pass the 64-hex value
   as the `contract_hash` argument of the node's `issueasset` (4th argument) or
   `rawissueasset` RPC. The contract hash affects the asset id, so it must be
   set at issuance; it cannot be added later, and reissuances do not count.

4. **Publish the domain proof** at
   `https://<entity.domain>/.well-known/sequentia-asset-proof-<asset_id>`,
   served raw (plain text; no declared content type is fine), containing
   exactly:

   ```
   Authorize linking the domain name <entity.domain> to the Sequentia asset <asset_id>
   ```

5. **Submit the registration**:

   ```
   curl -X POST https://sequentiatestnet.com/registry/ \
     -H 'Content-Type: application/json' \
     -d '{"asset_id":"<64-hex>","contract":{"name":"Example Asset","ticker":"EXA","precision":8,"entity":{"domain":"example.com"},"issuer_pubkey":"02...","version":0}}'
   ```

   The response is the stored entry; check that `verified` is `true`.
   Re-submitting the same asset (a refresh) is allowed and keeps its ticker.

## Succession (`POST /succeed`)

An asset's chain-committed contract is immutable: its hash is part of the
asset id, so the name and ticker an asset was issued under can never be
rewritten on chain. A bridged asset that its stablecoin issuer later adopts
still needs to keep every balance and integration while becoming the issuer's
own, so the registry lets the *display* identity (name, ticker, domain,
issuer key) be handed to a successor while the original contract and its hash
stay exactly as issued.

`POST /succeed` takes `{ asset_id, contract, signature }` and requires both
factors, which is what makes it unsquattable:

1. `signature` is a DER ECDSA signature by the **current** contract's
   `issuer_pubkey` (which must be a 33-byte compressed key) over the UTF-8
   message `sequentia-asset-succession:v1:<asset_id>:<contract_hash of the
   new contract>`, hashed with SHA-256;
2. the **successor's** `entity.domain` serves the usual `.well-known` proof
   for the asset (skipped only when `REQUIRE_DOMAIN_PROOF=0`).

The new contract passes the normal validation, must keep the asset's
`precision` (it is committed on chain and consumers convert amounts with it),
and its ticker must be free. On success the entry's `contract` is replaced,
`origin_contract` keeps the contract as issued, and a record `{ at, from, to,
message, signature }` is appended to `successions[]`.

`tools/sign-succession.js <asset_id> <new-contract.json> <privkey>` produces
the signature (the key as 64-hex or WIF; on a shared machine pass it via
`SUCCESSION_PRIVKEY` in the environment instead of the command line).

## Contract templates

A contract template is a [contract descriptor](https://github.com/ConcatenaLabs/sequentia-contracts/blob/main/docs/descriptor.md)
(version 1 or 2), identified by its template hash. The registry keeps, for each,
the descriptor exactly as submitted, every Simplicity program's source as
compiled, the golden vectors, the pinned compiler, the commitment root of each
Simplicity leaf, and the publisher's audit notes. Everything it serves can be
checked again from what it serves.

A template is stored only when all of these hold:

1. **The descriptor reads.** `contracts/sequentia-address.mjs`, the JavaScript
   reader of `sequentia-contracts`, pinned in `contracts/PIN.json`, refuses every
   file the specification refuses: each case of the reader corpus
   (`mirrors/fixtures/refusals.json`) is refused by this registry, for its
   reason, in its tests. The descriptor is submitted as the file's text, because
   parsing it into the request would already drop a repeated field or round a
   number the reader must see.
2. **The sources are the ones compiled.** Each Simplicity leaf names the pinned
   compiler (`simplicityhl`, the version in `PIN.json`), and its source, with its
   helper includes resolved as `seqc expand` prints it, hashes to the leaf's
   `source_sha256`.
3. **The vectors are reproduced.** The reader derives every golden vector's
   leaves, root, tweak, output key, parity, script and addresses, field for field.
4. **The compiler agrees.** `seqc descriptor check`, the pinned compiler of
   `sequentia-contracts`, compiles each source to the leaf's commitment root,
   witness list and cost bound, and runs the lints. With `REQUIRE_COMPILE=0`
   (testing only) this is skipped and the entry is stored unverified.
5. **The publisher is who it says.** The publisher's domain serves, at
   `https://<domain>/.well-known/sequentia-contract-proof-<template_hash>`, exactly
   the line

   ```
   Authorize linking the domain name <domain> to the Sequentia contract template <template_hash>
   ```

   The operator publishes with `ADMIN_TOKEN` instead, and is the only publisher in
   the `sequentia/` namespace. Any other namespace belongs to the first domain to
   publish in it, and a name and version name one template only.

Audit notes are the publisher's: each is who audited, a link to the report, an
optional SHA-256 of it, and a summary, shown as the publisher states them.

```
curl -X POST https://sequentiatestnet.com/registry/contracts \
  -H 'Content-Type: application/json' \
  -d '{"descriptor": "<descriptor.json, as text>",
       "sources": {"<name>.simf": "<seqc expand <name>.simf>"},
       "vectors": "<vectors.json, as text>",
       "publisher": {"domain": "example.com", "name": "Example"},
       "audits": [{"by": "An auditor", "url": "https://example.com/audit.pdf", "summary": "..."}]}'
```

An **instance** is a template's parameters on this chain. Anyone may register
one, because it is checked completely: the reader derives its script, its
genesis hash must be this chain's (read from electrs), the template must list
the chain named by `CONTRACTS_CHAIN`, and electrs must show an output paying the
script. `POST /contracts/<template_hash>/instances` takes `{ params, slots,
genesis }`, the instance file a contract's tool writes.

The explorer reads `GET /contracts/index.minimal.json`:

```json
{
  "leaves":  { "<commitment root>": [["<template_hash>", "sequentia/faucet-drip", 1, "drip", "drip"]] },
  "scripts": { "<scriptPubKey>":    ["<template_hash>", "sequentia/faucet-drip", 1] }
}
```

`leaves` maps the commitment root of each verified template's Simplicity leaves
to the template, the leaf and the path that spends it. A template keeps its
parameters in a data leaf, so a root is one constant per template and a spend
reveals it. One root can sit in several templates, so each maps to a list.
`scripts` maps each registered instance's output script to its template.

## Oracle keys

An oracle key record says which price feeds a BIP340 key signs, who runs the
signer, where every attestation is published and, in version 2, the beacon
asset its contracts pin and the bond it stands behind its prices with:

```json
{
  "version": 2,
  "key": "<32-byte x-only key>",
  "feeds": [{ "id": "GOLD/USDX", "description": "Gold in USDX", "decimals": 5 }],
  "operator": { "name": "Example oracle", "domain": "oracle.example.com" },
  "endpoints": ["https://oracle.example.com/v2/log/raw"],
  "attestation_tag": "Sequentia/oracle/price",
  "beacon_asset": "<the beacon asset, as the node prints it>",
  "bond": {
    "template": "<sequentia/oracle-bond's template hash>",
    "asset": "<the asset the bond is held in, as the node prints it>",
    "notice": "<NOTICE: a BIP68 time-based sequence, 8 hex digits>",
    "notice_seconds": 2592000,
    "bonded": "<the bond's script while bonded>",
    "noticed": "<its script once notice is given>",
    "log": "<optional: the https URL of the oracle's bond log>"
  },
  "revoked": false
}
```

The bond is sequentia-contracts' `templates/oracle_bond`, pinned in
`contracts/oracle_bond/` (`contracts/PIN.json`), and the only bond template
the registry reads. It derives `bonded` and `noticed` again from the key, the
asset and the notice, and refuses a record whose scripts are not those, a
notice in blocks (such a bond could never be withdrawn), or a
`notice_seconds` that is not the notice. Anyone counting the coins at those
two scripts on a node sees what the key has bonded; a conflict between two of
its attestations slashes them. A version 1 record has no `beacon_asset`, and
its `bond`, when present, is a line of text.

`POST /oracles` takes `{ record, signature }`. The signature is the key's, BIP340,
over the tagged hash (tag `sequentia-registry/oracle-key/v1`) of the record's
canonical JSON, so no one can file a record for a key they do not hold, nor
change a record after its key signed it. sequentia-oracle's signer signs a
version 2 record with `--sign-registry-record`, only for its own key and its
own bond as its bond log declares it; `test/fixtures/sequentia-oracle/` is a
record that signer signed, which the tests post. The operator's domain serves, at
`https://<domain>/.well-known/sequentia-oracle-proof-<key>`, exactly
`Authorize linking the domain name <domain> to the Sequentia oracle key <key>`.
A key's record is replaced by a newer one it signs, from the same domain; a
record with `revoked: true` stays listed as revoked. The registry operator files
records with `ADMIN_TOKEN` and no domain proof, never without the key's signature.

| Method | Path | Description |
|---|---|---|
| GET | `/contracts` | Every template, without its descriptor, sources and vectors |
| GET | `/contracts/<template_hash>` | One template, with the descriptor, sources and vectors as submitted |
| GET | `/contracts/index.minimal.json` | Verified templates' Simplicity roots, and registered instances' scripts |
| GET | `/contracts/<template_hash>/instances` | A template's registered instances |
| GET | `/contracts/instances/<scriptPubKey>` | One instance |
| POST | `/contracts` | Publish a template: every check above, with the domain proof |
| POST | `/admin/contracts` | (bearer `ADMIN_TOKEN`) the same checks, published by the operator |
| POST | `/contracts/<template_hash>/instances` | Register an instance the chain has paid |
| GET | `/oracles`, `/oracles/<key>` | Oracle key records |
| POST | `/oracles` | File a record: the key's signature and the domain proof |
| POST | `/admin/oracles` | (bearer `ADMIN_TOKEN`) the key's signature, filed by the operator |

## Arca operators

An Arca operator lists itself here so that wallets can find it. Its record
says what its own `GET /v1/info` says, in the operator's own settings, signed
by its operator key:

```json
{
  "arca_operator": 1,
  "operator": "<the operator key S, 32-byte x-only, hex>",
  "genesis_hash": "<the chain's genesis hash, display order>",
  "api": "https://example.org/arca",
  "assets": [{
    "asset": "<asset id>",
    "min_leaf": "1000",
    "rate": { "source": "node", "max_age_seconds": 600 },
    "fees": { "refresh_ppm": 5000, "refresh_base": "200", "offboard_ppm": 1000, "offboard_base_value": "100",
              "lightning_ppm": 0, "lightning_base": "0" }
  }],
  "keepers": { "keys": [], "required": 0 },
  "exit_delay_units": { "min": 253, "max": 338 },
  "expiry": { "batch_lifetime_seconds": 2419200, "exit_deadline_seconds": 259200 },
  "templates": { "version": 1, "list": ["vtxo-1", "board-1", "htlc-1"] },
  "contact": { "name": "Example", "domain": "example.org", "email": "ops@example.org" },
  "issued_at": 1800000000
}
```

- `api` is the base URL wallets are given (`arca create --server`); the
  registry reads the operator's info at `<api>/v1/info`.
- `assets` are in the order of their ids. A smallest leaf or a fixed fee part
  the operator sets as a value in the reference unit is recorded as that value
  (`min_leaf_value`, `*_base_value`), and otherwise in atoms; a rate is recorded
  by its source and how long it is good for. The atoms a value comes to and the
  rate itself move with prices, so they are not part of the record: the
  registry shows each asset's rate as the operator reads it now beside the
  record (`live.rates`).
- `keepers.keys` are sorted; `expiry` is a batch's lifetime and its exit
  deadline (`info.boards`); `templates` is `info.templates`, and the registry
  names any it does not list among the Arca leaf templates
  (`live.unknown_templates`).
- `issued_at` is when the record was made, unix seconds.

`POST /operators` takes `{ record, signature }`. The signature is the operator
key's, BIP340, over the tagged hash (tag `sequentia-registry/arca-operator/v1`)
of the record's canonical JSON: keys sorted, no white space, strings of
printable ASCII, whole numbers from 0 to 2^53 - 1, no `null`. Those are the
bytes Arca's `arca_covenant::operator_record` writes, so the operator's signer
signs them (`arca-signer --sign-operator-record`) and wallets check them
(`arca operators`, `arca join --from-registry`) without trusting the registry.

A record is listed only when its signature verifies and the operator's info,
read when it is posted, says what it says; otherwise it is refused with each
difference. A key's newer record (a later `issued_at`) replaces its older one;
an older one, or another record with the same `issued_at`, is refused, so a
record cannot be played back over the one that replaced it. With
`REQUIRE_DOMAIN_PROOF`, the contact's domain serves, at
`https://<domain>/.well-known/sequentia-operator-proof-<key>`, exactly
`Authorize linking the domain name <domain> to the Arca operator key <key>`,
and another domain cannot take a listed key over. The registry operator files
records with `ADMIN_TOKEN` and no domain proof, never without the key's
signature.

Each listed record is checked against its operator's info again every
`OPERATOR_CHECK_MS`, and its entry says how it stands: `status` is `ok` while
the info says what the record says; `mismatched`, with `differences` (each
`{ field, record, info }`), once it says something else, so an operator that
changes what it serves, charges or names signs a new record; and `stale` once
the operator has not answered for `OPERATOR_STALE_AFTER_MS`, with the error in
`last_error`. A record that matches again is `ok` again.

The record is written from the operator's own info by
`tools/operator-record.js`, then signed on the machine that holds the key:

```
node tools/operator-record.js --info http://127.0.0.1:3535 --api https://example.org/arca \
  --contact-name "Example" --contact-domain example.org > record.json
arca-signer --key-file <key file> --genesis <genesis hash> --sign-operator-record record.json > signed.json
curl -s -X POST -H 'content-type: application/json' --data @signed.json https://<registry>/operators
```

An operator's API is read through the SSRF guard and must be `https://`;
`OPERATORS_LOCAL=1` takes plain `http://` and private addresses, for a
registry and operators on one machine, as on a local chain.

## Arca leaf templates

`GET /templates` lists every leaf template an Arca operator co-signs
(`vtxo-1`, `board-1`, `htlc-1`, …) with the list's version, and for each its
golden vectors: the output the template builds from fixed test parameters,
which every implementation reproduces byte for byte. Each vector shows its
`script_pubkey`, its `script_hash` (SHA-256 of the script, as electrs keys
scripts), the taproot root and each leaf's hash and size.

The vectors are those of the
[arca](https://github.com/ConcatenaLabs/arca) repository
(`regtest/vectors/arca.json`), copied unchanged into `arca/vectors.json` at the
commit `arca/PIN.json` names, with the file's SHA-256 and which vectors belong
to which template. At start the registry checks the copy's hash and rebuilds
every vector's output from its leaves (each leaf's hash from its script,
`TapLeaf/elements` at leaf version `0xc4`; the root from its control block,
`TapBranch/elements`; the output key from the internal key tweaked by the
root, `TapTweak/elements`); a copy that fails any check stops the registry.
To move the pin, copy the file from the new commit and update `arca/PIN.json`.

| Method | Path | Description |
|---|---|---|
| GET | `/operators`, `/operators/<key>` | Arca operator records, each with its signature, `status`, `checked_at`, `differences` and `live` |
| POST | `/operators` | File a record: the key's signature, the operator's info and the domain proof |
| POST | `/admin/operators` | (bearer `ADMIN_TOKEN`) the key's signature and the operator's info, filed by the registry operator |
| POST | `/admin/operators/<key>/check` | (bearer `ADMIN_TOKEN`) check a record against its operator's info now |
| GET | `/templates` | The Arca leaf template list |

## Consumers

- **Sequentia node**: start `sequentiad` with `-assetregistryurl=<index url>`;
  the node fetches the minimal index shortly after startup and then every
  `-assetregistrypoll` seconds (default 300) and merges the tickers of
  **verified** entries into its asset directory (RPC output and the GUI).
  Unverified/legacy entries are skipped by the node. On the public testnet the
  node defaults this to the live registry index. Operator `-assetdir` entries
  always take precedence. See `src/assetregistry.{h,cpp}` in the
  [Sequentia](https://github.com/ConcatenaLabs/Sequentia) repo.
- **Block explorer**: the explorer's public server proxies `/registry` to this
  service, and the `sequentia-testnet` flavor defaults its asset map
  (`ASSET_MAP_URL`) to `/registry/index.minimal.json` and its contract map
  (`CONTRACT_MAP_URL`) to `/registry/contracts/index.minimal.json`, which names
  the template a Simplicity spend runs.
- **Web wallet**: fetches `/registry/index.minimal.json` (override with
  `window.SEQ_REGISTRY_URL`).
- **Arca wallets**: `arca operators` lists `/operators`, checking every
  signature, and `arca join --from-registry <key>` joins one (the `arca`
  library's `bark::arca::registry`).
- **OpenAMP wallets**: discover restricted assets here, then verify the
  asset-to-policy binding against the policy server listed in the contract's
  `openamp.policy_endpoints`.

## Seeded testnet assets

The public testnet's demo assets -- the Sequence token (tSEQ), USDX, EURX,
GOLD, SILVR, OILX and SBTC -- were issued with
`contract_hash = 0`, so they can **never** pass cryptographic chain+domain
verification. They are seeded from `seed/legacy-assets.json` on first run
(`legacy: true`) so their labels resolve, alongside the BONDX OpenAMP demo asset
(which does earn verification the normal way). SBTC is pegged bitcoin: 1:1
BTC held in the
[sbtc-bridge](https://github.com/ConcatenaLabs/sbtc-bridge)
reserve, an ordinary unprivileged reissuable asset, not Elements' consensus
peg; native Bitcoin remains a distinct asset in every wallet. Seeding never
overwrites an existing entry's contract and still enforces ticker uniqueness.

### Operator override (`operator_verified`)

A seed entry may set `"operator_verified": true`. The registry **operator** then
vouches for that entry by fiat: `loadSeed` sets the consumer-facing `verified: 1`
and records `verified_by: "operator"`, while `verified_chain` and
`verified_domain` stay `false` so the audit trail never claims a cryptographic
proof that does not exist. This is reconciled idempotently on every restart (a
`git pull` that toggles the flag takes effect on the next boot), and it only ever
touches `legacy` entries that are not chain-verified, so a properly registered
asset can never be silently overridden.

**This is a testnet convenience only.** On a public or mainnet network, `verified`
must be earned through `POST /` (on-chain contract match + `.well-known` domain
proof); an operator override is a deliberate trust shortcut appropriate only when
the operator issued the demo assets themselves and no real contract exists to
verify against. The testnet demo assets above use it because they predate
the contract scheme; every asset issued with a real `contract_hash` should verify
cryptographically instead.

## Running locally

Requirements: Node.js (no npm install needed; the server uses only Node
built-ins).

```
git clone https://github.com/ConcatenaLabs/sequentia-registry.git
cd sequentia-registry
node server.js
```

On first run the server seeds the testnet assets and listens on port 3005.
Smoke-test it:

```
curl -s http://localhost:3005/health
curl -s http://localhost:3005/index.minimal.json
```

Chain verification needs a reachable Sequentia electrs instance
(`SEQ_ELECTRS_URL`, default `http://127.0.0.1:3003`, treated as trusted and
exempt from the SSRF guard). For local development without a domain, set
`REQUIRE_DOMAIN_PROOF=0` to skip the domain-proof check (testing only; the
chain check still runs). To bypass both checks for a hand-approved entry, set
`ADMIN_TOKEN` and use `POST /admin/seed` with `Authorization: Bearer <token>`.

### Config (env)

| Var | Default | Meaning |
|---|---|---|
| `PORT` | `3005` | listen port |
| `DB_DIR` | `./db` | per-asset JSON store |
| `SEED_FILE` | `./seed/legacy-assets.json` | pre-approved assets loaded on first run |
| `SEQ_ELECTRS_URL` | `http://127.0.0.1:3003` | esplora-API base for on-chain lookups |
| `REQUIRE_DOMAIN_PROOF` | `1` | require the `.well-known` proof (`0` to skip, testing only) |
| `PROOF_FETCH_TIMEOUT` | `8000` | ms timeout for the domain-proof fetch |
| `ADMIN_TOKEN` | (unset) | enables `POST /admin/seed`, `/admin/contracts` and `/admin/oracles` |
| `SEQC` | `seqc` | the pinned compiler's `seqc` binary, from `sequentia-contracts` at the commit in `contracts/PIN.json` |
| `REQUIRE_COMPILE` | `1` | compile every template with `SEQC` before storing it (`0` stores it unverified, testing only) |
| `CONTRACTS_CHAIN` | `sequentia-testnet` | the chain name, in a descriptor's `chains`, that instances are registered on |
| `OPERATOR_CHECK_MS` | `600000` | how often every Arca operator record is checked against its operator's info (`0`: never) |
| `OPERATOR_STALE_AFTER_MS` | `3600000` | how long an operator may not answer before its record is `stale` |
| `OPERATOR_FETCH_TIMEOUT` | `8000` | ms timeout for reading an operator's info |
| `OPERATORS_LOCAL` | (unset) | `1` takes `http://` and private addresses for an operator's API (one machine only, testing) |

`seqc` is built from `sequentia-contracts`, at the commit `contracts/PIN.json`
names:

```
git clone https://github.com/ConcatenaLabs/sequentia-contracts && cd sequentia-contracts
git checkout <commit from contracts/PIN.json>
cargo build --release --locked --bin seqc -p sequentia-contracts   # target/release/seqc
```

### Storage format

The store is a flat directory of JSON files, one per asset:
`<DB_DIR>/<asset_id>.json`, each containing the full entry shown under "API".
Templates, instances and oracle keys sit beside them in
`<DB_DIR>/contracts/<template_hash>.json`,
`<DB_DIR>/contract-instances/<scriptPubKey>.json` and
`<DB_DIR>/oracles/<key>.json`, with Arca operator records in
`<DB_DIR>/operators/<key>.json`.
There is no database server; back up or migrate the registry by copying the
directory.

## For contributors

Repo layout:

- `server.js`: the entire service (HTTP API, canonical-JSON hashing, asset-id
  derivation, electrs lookups, domain-proof fetch with SSRF guard, flat-file
  store, seeding, succession).
- `contracts.js`: the contract templates, their instances and oracle keys, with
  BIP340 verification.
- `contracts/`: the pinned JavaScript reader of `sequentia-contracts`
  (`sequentia-address.mjs`, copied unchanged) and `PIN.json`, which names its
  commit and hash, the pinned compiler and Sequentia's budget. To move the pin,
  copy the reader from the new commit and update `PIN.json` and the fixtures.
- `test/contracts.test.js`, with `test/fixtures/sequentia-contracts/`: the
  reader corpus and the templates it reads, copied from that commit.
- `operators.js`: Arca operator records, their canonical form, their checks
  against an operator's info and the schedule that repeats them.
- `templates.js` and `arca/`: the Arca leaf template list, rebuilt from the
  golden vectors copied unchanged from the arca repository
  (`arca/vectors.json`) at the commit `arca/PIN.json` names.
- `test/operators.test.js`, with `test/fixtures/arca/`: operator records
  against a stand-in operator, and a record signed by `arca-signer`.
- `tools/operator-record.js`: writes an operator's unsigned record from its info.
- `seed/legacy-assets.json`: pre-approved entries loaded on first run.
- `tools/sign-succession.js`: signs a succession with the current issuer key.
- `tools/succession-smoke.js`: self-contained end-to-end test of succession
  (starts a registry on a temporary DB with domain proofs off, seeds an entry,
  exercises the hand-off and its refusals).
- `db/`: the live registry state, ignored by version control; never force-add it.

The tests:

```
node --test test/*.test.js                              # contracts, oracle keys, Arca operators and templates
SEQC=/path/to/seqc node --test test/*.test.js           # and the pinned compiler's check
node tools/succession-smoke.js                          # succession
```

Without `SEQC` the compiler's tests are skipped. Verify asset changes with the
smoke commands above (and, for verification-path changes, against a local
electrs). Open PRs against the `main` branch.
