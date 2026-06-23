# v2 Storage: RFC6962 vs static-ct-api — differences & optimizations

How the two CT log APIs map into the v2 on-disk record (`RawLogEntry` / `RawLogEntryBatch`,
binary `.binpb`), why their per-entry sizes differ, and where we can shrink them. Measured
2026-06-17 on the two test mirrors (argon2027h1 = rfc6962, tuscolo2027h1 = static).

> Status: **O1 + O2 + O3 + O4 implemented** — both protocols emit one minimal record
> (`leaf_input` + `chain_fingerprints` + precert fields), RFC6962 chains are deduped into a
> shared issuer store, and partition files are optionally gzip-compressed. O5 (archival tile
> format) remains a proposal.

## What each protocol used to store (pre-optimization baseline)

This was the original divergence that motivated the optimizations below. The same `RawLogEntry`
was populated differently per source:

| field | RFC6962 (get-entries) | static-ct-api (tiles / sunlight) |
|---|---|---|
| `leaf_input` | verbatim `MerkleTreeLeaf` (TLS), contains leaf cert | reconstructed `MerkleTreeLeaf`, contains leaf cert |
| `extra_data` | **full issuer chain DER, verbatim** | empty |
| `certificate` | empty | **leaf cert DER (same cert as in `leaf_input`)** |
| `precertificate` | empty | precert chain entry (precerts only) |
| `issuer_key_hash` | empty | precert only |
| `chain_fingerprints` | empty | **SHA-256 of each chain cert (32 B each)** |

So a leaf cert was the common payload, but the two diverged sharply on **(a) how the chain is
stored** and **(b) whether the leaf cert is duplicated**.

**After O1+O2+O3** (current): both protocols emit `leaf_input` + `chain_fingerprints`
(+ `precertificate`/`issuer_key_hash` for precerts); `extra_data` and `certificate` are
`reserved`. RFC6962 chain certs live in `<output_root>/issuers/<hex>.der`; static resolves
fingerprints from the log's `issuer/<hash>` endpoint.

## Measured per-entry size

| | RFC6962 (argon) | static (tuscolo2027h1) |
|---|---|---|
| baseline (binary) | ~4.3–4.9 KB/entry | ~3.1 KB/entry |
| **after opts** | **~1.86 KB/entry (O1, ~2.6×)** | **~1.6 KB/entry (O2, ~halved)** |
| dominant remaining cost | `leaf_input` (~1 KB, kept by design) | `leaf_input` (~1.4 KB) |
| chain bytes/entry | fingerprints ~32–96 B (+ one-time issuer store) | fingerprints ~64–96 B |

(Baseline RFC6962 breakdown from a decoded sample: `leaf_input` ~1.03 KB + `extra_data` ~3.88 KB
≈ 4.9 KB raw. Post-O1 measured on argon [0,5000): ~1.86 KB/entry leaf records + a one-time issuer
store of 1,478 unique certs whose per-entry cost → ~0 at full-log scale.)

## The two structural differences

### 1. Cert-chain storage — the big asymmetry
- **RFC6962** stores the **entire issuer chain as DER, verbatim** in `extra_data` (~3.9 KB,
  ~79% of the record). This is **highly redundant**: a handful of intermediate/root CA certs
  are repeated in nearly every one of millions of entries that share an issuer.
- **static-ct-api** stores only **chain fingerprints** (32 B per chain cert). The actual chain
  certs are not in the per-entry record (they're fetchable once from the log's `issuer/<hash>`
  endpoint). This is why static is ~1.8 KB/entry leaner on the chain alone.

Net: the static API already does the space-smart thing; the RFC6962 path is carrying ~3.9 KB of
mostly-duplicate chain bytes per entry.

### 2. Static duplicates the leaf cert
The static record sets **both** `leaf_input` (a reconstructed `MerkleTreeLeaf`, which embeds the
leaf cert) **and** `certificate` (the same leaf cert DER). That's ~1.4 KB stored twice per entry —
roughly half of static's ~3.1 KB. (`sunlight.LogEntry.Certificate` is exactly the
`TimestampedEntry.signed_entry` / `PreCert.tbs_certificate` that `MerkleTreeLeaf()` already
embeds, so it is fully derivable from `leaf_input`.)

## Optimizations (ranked)

### O1 — RFC6962: store chain as fingerprints + a shared issuer store (biggest win) — ✅ IMPLEMENTED
Mirror what static already does: keep `chain_fingerprints` in the leaf record and write each
unique chain cert once into a shared, deduplicated issuer store (keyed by SHA-256). Parse the
chain out of `extra_data`, dedupe, drop the verbatim copy.
- **Impact:** ~3.9 KB → ~0.1 KB chain per entry ⇒ RFC6962 records drop from ~5 KB to ~1–1.5 KB
  (**~3–4×**). The issuer store is tiny (a few thousand CA certs total vs millions of copies).
- **Cost:** no longer self-contained (need the issuer store to reconstruct full chains);
  added write-path step (parse + dedupe chains); breaks the "verbatim raw leaf" simplicity.
- **Done:** `RawLogEntry.extra_data` (field 6) is now `reserved`. `rawEntryFromRFC6962` parses
  the chain via ctgo `RawLogEntryFromLeaf`, records each cert's SHA-256 in `chain_fingerprints`,
  and returns the certs; `issuerStore` (`internal/ctv2/issuer_store.go`) writes each unique cert
  once to `<output_root>/issuers/<hex>.der` via the new `Writer.PutIfAbsent` (content-addressed,
  idempotent → safe for concurrent fan-out jobs sharing one log's root). The full submitted
  precertificate (the only part of extra_data not in `leaf_input`) is preserved in `precertificate`.
- **Measured** (Argon2026h1 [0,5000)): leaf records **~4.9 KB → ~1.86 KB/entry (~2.6×)**; the
  remaining bytes are mostly `leaf_input` (the verbatim leaf, ~1 KB, kept by design). The issuer
  store held 1,478 unique certs deduped from ~10k chain instances even in this 5k sample (~6.8×),
  and its per-entry cost → ~0 at full-log scale (distinct CA certs plateau in the low thousands).

### O2 — static: drop the redundant `certificate` field (cheap, immediate) — ✅ IMPLEMENTED
Keep `leaf_input` (the canonical raw Merkle leaf, consistent with RFC6962 and needed for Merkle
verification), drop `certificate` (derivable by parsing `leaf_input`). Keep `precertificate` for
precerts.
- **Impact:** ~−1.4 KB/entry ⇒ static ~3.1 KB → **~1.6 KB (~halved)**.
- **Cost:** downstream tools must parse `leaf_input` to get the cert instead of reading a
  ready field (trivial; they'll parse leaves anyway).
- **Done:** `RawLogEntry.certificate` (field 7) is now `reserved` in `ingestion.proto`;
  `rawEntryFromStatic` no longer populates it. The leaf cert lives only in `leaf_input`.

### O3 — unify both protocols onto one minimal record — ✅ IMPLEMENTED
End state of O1+O2: every record = `leaf_input` + `chain_fingerprints` (+ precert fields) +
a shared fingerprint-keyed issuer store. RFC6962 and static records become byte-identical in
shape and both minimal (~1–1.6 KB/entry). Cleanest long-term; biggest aggregate savings.
- **Done:** with O1+O2 in, both `rawEntryFromRFC6962` and `rawEntryFromStatic` emit the same
  fields (`leaf_input`, `chain_fingerprints`, and for precerts `precertificate` + `issuer_key_hash`).
  Fingerprints use the same SHA-256-of-DER on both paths, so the fingerprint semantics are uniform.
- **Issuer-store unification — automatic.** RFC6962 writes chain certs to the local store during
  ingestion (the log has no issuer endpoint); static records carry only fingerprints (certs live at
  the log's `issuer/<hash>` endpoint). `GetLogEntries` now **always resolves static issuers inline,
  best-effort**: as entries stream in it fetches each referenced-but-missing chain cert from
  `<monitoring_url>/issuer/<hex>`, verifies `sha256(DER) == fingerprint`, and writes it to the same
  `<output_root>/issuers/<hex>.der` store. Deduped across batches, skips certs already on disk (a
  cheap no-op on re-runs), and never fails the ingest if the endpoint is flaky/absent (counted +
  logged; the standalone pass backfills). So a plain static fetch already yields the unified,
  offline-validatable layout. (Verified live on LE Sycamore: 512 entries → 45 issuers stored inline,
  0 failures, invariant holds.)
- **`ResolveIssuers` RPC / `-mode resolve-issuers`** remains as a standalone backfill/retry pass:
  it scans an existing output_root and resolves any still-missing issuers (e.g. for data ingested
  before this was automatic, or after transient endpoint failures). Idempotent/rerunnable.

### O4 — compression (orthogonal multiplier) — ✅ IMPLEMENTED (gzip)
gzip the partition `.binpb` files. Stacks on top of O1/O2/O3 (dedup already removed the bulk of
the redundancy; compression trims what's left of the per-leaf DER).
- **Done:** request field `compression` (enum `Compression`, default NONE); `gzipWriter`
  (`writer.go`) decorates the `Writer`, gzip-compressing payloads and appending `.gz`. Wired in
  `service.go` for the **partition writer only**; `CheckCoverage` parses `<range>.binpb[.gz]`.
  CLI: `-compress gzip`.
- **Issuer store is deliberately NOT compressed:** small DER certs barely shrink (measured ~1.0×),
  and keeping them raw preserves the content-address invariant `sha256(<hex>.der) == fingerprint`
  and keeps certs directly readable.
- **Measured** (Argon [0,5000), gzip DefaultCompression): partition files **9.29 MB → 4.20 MB
  (~2.21×)**; issuer store unchanged at ~1.85 MB raw. Verified CheckCoverage works against the
  compressed tree and the issuer content-address invariant holds.
- zstd would compress better/faster but needs a non-stdlib dep; gzip (stdlib) was chosen to avoid
  it. Could revisit if the ratio matters more than the dependency.

### O5 — static: archival tile format
Instead of re-serializing into `RawLogEntry`, store raw static-ct-api tiles (the geomys
`ct-archive` zip format; `sunlight` can already read `archive+file://`). More faithful and
re-readable by sunlight, potentially more compact. A different storage strategy for static only.

## Tradeoffs to decide

- **Self-contained vs deduplicated.** RFC6962 files are no longer independently parseable: a leaf's
  full chain must be reconstructed from `chain_fingerprints` + the issuer store. **Decided:**
  deduplicated (the chain question below was answered "keep fingerprints + store").
- **Do downstreams even need the chain?** Subject/SAN extraction needs only the leaf cert
  (in `leaf_input`). **Resolved:** keep `chain_fingerprints` (+ the issuer store for RFC6962) so
  chain/issuance re-validation stays possible, without paying the ~3.9 KB/entry inline cost.
- **Verification.** A monitor that re-verifies inclusion/issuance needs the leaf (`leaf_input`)
  and, for chain validation, the issuer certs — satisfied by O1's shared store.

## Suggested order
1. **O2** (drop static `certificate`) — ✅ done.
2. Chain question — ✅ resolved: keep fingerprints + issuer store.
3. **O1** (RFC6962 → fingerprints + issuer store), converging on **O3** — ✅ done.
4. **O4** (gzip partition files) — ✅ done. O5 (archival tile format) still open.
