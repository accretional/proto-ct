# v2 Storage: RFC6962 vs static-ct-api — differences & optimizations

How the two CT log APIs map into the v2 on-disk record (`RawLogEntry` / `RawLogEntryBatch`,
binary `.binpb`), why their per-entry sizes differ, and where we can shrink them. Measured
2026-06-17 on the two test mirrors (argon2027h1 = rfc6962, tuscolo2027h1 = static).

> Status: **proposal for review.** Nothing here is implemented yet.

## What each protocol actually stores

The same `RawLogEntry` message is populated differently per source:

| field | RFC6962 (get-entries) | static-ct-api (tiles / sunlight) |
|---|---|---|
| `leaf_input` | verbatim `MerkleTreeLeaf` (TLS), contains leaf cert | reconstructed `MerkleTreeLeaf`, contains leaf cert |
| `extra_data` | **full issuer chain DER, verbatim** | empty |
| `certificate` | empty | **leaf cert DER (same cert as in `leaf_input`)** |
| `precertificate` | empty | precert chain entry (precerts only) |
| `issuer_key_hash` | empty | precert only |
| `chain_fingerprints` | empty | **SHA-256 of each chain cert (32 B each)** |

So a leaf cert is the common payload, but the two diverge sharply on **(a) how the chain is
stored** and **(b) whether the leaf cert is duplicated**.

## Measured per-entry size

| | RFC6962 (argon2027h1) | static (tuscolo2027h1) |
|---|---|---|
| on disk (binary) | **~4.3–4.9 KB/entry** | **~3.1 KB/entry** |
| dominant cost | `extra_data` = full chain (~3.9 KB, ~79%) | leaf cert stored **twice** (~1.4 KB ×2) |
| chain bytes | full DER, ~3.9 KB | fingerprints only, ~64–96 B |

(RFC6962 breakdown from a decoded sample: `leaf_input` ~1.03 KB + `extra_data` ~3.88 KB ≈ 4.9 KB
raw; binary proto adds negligible framing.)

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

### O1 — RFC6962: store chain as fingerprints + a shared issuer store (biggest win)
Mirror what static already does: keep `chain_fingerprints` in the leaf record and write each
unique chain cert once into a shared, deduplicated issuer store (keyed by SHA-256). Parse the
chain out of `extra_data`, dedupe, drop the verbatim copy.
- **Impact:** ~3.9 KB → ~0.1 KB chain per entry ⇒ RFC6962 records drop from ~5 KB to ~1–1.5 KB
  (**~3–4×**). The issuer store is tiny (a few thousand CA certs total vs millions of copies).
- **Cost:** no longer self-contained (need the issuer store to reconstruct full chains);
  added write-path step (parse + dedupe chains); breaks the "verbatim raw leaf" simplicity.

### O2 — static: drop the redundant `certificate` field (cheap, immediate)
Keep `leaf_input` (the canonical raw Merkle leaf, consistent with RFC6962 and needed for Merkle
verification), drop `certificate` (derivable by parsing `leaf_input`). Keep `precertificate` for
precerts.
- **Impact:** ~−1.4 KB/entry ⇒ static ~3.1 KB → **~1.6 KB (~halved)**.
- **Cost:** downstream tools must parse `leaf_input` to get the cert instead of reading a
  ready field (trivial; they'll parse leaves anyway).

### O3 — unify both protocols onto one minimal record
End state of O1+O2: every record = `leaf_input` + `chain_fingerprints` (+ precert fields) +
a shared fingerprint-keyed issuer store. RFC6962 and static records become byte-identical in
shape and both minimal (~1–1.6 KB/entry). Cleanest long-term; biggest aggregate savings.

### O4 — compression (orthogonal multiplier)
zstd/gzip the `.binpb` files (or just the chain bytes). RFC6962 chains compress extremely well
(repeated CA certs), so even without dedup, compression could give ~2–3×. Stacks with O1/O2, but
dedup is structurally better than compressing redundant copies.

### O5 — static: archival tile format
Instead of re-serializing into `RawLogEntry`, store raw static-ct-api tiles (the geomys
`ct-archive` zip format; `sunlight` can already read `archive+file://`). More faithful and
re-readable by sunlight, potentially more compact. A different storage strategy for static only.

## Tradeoffs to decide

- **Self-contained vs deduplicated.** Today RFC6962 files are independently parseable (full chain
  inline). O1/O3 make records small but require the issuer store to reconstruct chains.
- **Do downstreams even need the chain?** Subject/SAN extraction needs only the leaf cert
  (in `leaf_input`). If chains aren't needed downstream, we could drop them (or fingerprints too)
  entirely — a bigger win than any of the above. This is the open question from earlier
  ("not sure if later use cases need the chain, full or fingerprints").
- **Verification.** A monitor that re-verifies inclusion/issuance needs the leaf (`leaf_input`)
  and, for chain validation, the issuer certs — satisfied by O1's shared store.

## Suggested order
1. **O2** (drop static `certificate`) — trivial, ~halves static, no downside. Do first.
2. Decide the chain question (needed downstream? full vs fingerprints vs none).
3. If chains stay: **O1** (RFC6962 → fingerprints + issuer store), converging on **O3**.
4. **O4** compression as an independent layer whenever.
