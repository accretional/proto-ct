# v2 on-disk storage format

How the v2 archiver stores a CT log on disk. It writes the log's **raw Merkle leaves**, partitioned
by time and index, with deduplicated issuer and accepted-root certificates alongside. The layout is
the same regardless of source protocol (RFC 6962 `get-entries` and static-ct-api tiles both produce
identical output).

## Directory layout

One directory tree per log; the caller owns the top-level prefix (conventionally the log's hex id):

```
<output_root>/                      # a single log
├── <YYYY-MM-DD>/                   # leaf-timestamp day, UTC  (or <YYYY-MM-DD>/<HH> at hourly granularity)
│   └── <first>-<last>.binpb[.gz]   # one partition file per contiguous same-day index run
├── issuers/
│   └── <sha256-hex>.der            # each unique issuer-chain certificate, stored once
└── roots/
    └── <sha256-hex>.der            # the log's accepted roots (trust anchors)
```

The log's identity (id, URL, protocol) is also recorded inside every partition file (`LogMeta`), so
a tree is self-describing.

## Partition files

- **Format:** a binary protobuf `RawLogEntryBatch` (deterministic marshal). Extension `.binpb`, or
  `.binpb.gz` when gzip compression is enabled.
- **Filename `<first>-<last>`:** the inclusive index range the file covers, encoded in **base-36**
  (`0-9a-z`, single-case so it is collision-free on case-insensitive filesystems). Filenames are
  hints for range lookup; the authoritative index of each entry is the `index` field inside it.
- **Partitioning:** by leaf timestamp (UTC day, or day+hour) **and** index. A fetched range that
  straddles midnight is split into one file per contiguous same-day run, so every file holds a
  disjoint, contiguous index range. Re-fetching the same `(log, range, granularity)` is
  deterministic — byte-identical files.

## The record — `RawLogEntry`

Every entry is one `RawLogEntry`. Both protocols emit the same minimal shape:

| field | type | meaning |
|---|---|---|
| `index` | int64 | position of the entry in the log |
| `timestamp_ms` | int64 | leaf timestamp (epoch ms); drives time partitioning |
| `entry_type` | enum | `X509` or `PRECERT` |
| `source` | enum | `RFC6962`, `STATIC_CT_API`, or `STATIC_CT_API_NO_CHECKPOINT` |
| `leaf_input` | bytes | TLS-encoded `MerkleTreeLeaf` — the canonical raw leaf. Embeds the leaf cert (X509) or the `TBSCertificate` (precert), plus the timestamp. Verbatim for RFC 6962; reconstructed for static. |
| `chain_fingerprints` | repeated bytes | SHA-256 of each issuer-chain cert, ordered leaf's-issuer-first → toward-root. The certs themselves live in `issuers/`. |
| `precertificate` | bytes | **precerts only:** the full submitted precertificate (not recoverable from `leaf_input`). |
| `issuer_key_hash` | bytes | **precerts only:** the precert's issuing-CA key hash. |

Fields 6 (`extra_data`) and 7 (`certificate`) are `reserved` — they were dropped (see *Rationale*).
The leaf certificate is **not** stored separately; it is parsed out of `leaf_input`.

## Issuer store — `issuers/`

Content-addressed: a chain cert's DER is stored at `issuers/<hex>.der` where `<hex>` is its
SHA-256 — i.e. `sha256(file) == filename == the fingerprint in chain_fingerprints`. Each unique CA
certificate is stored exactly once (a handful of CA certs back millions of leaves), regardless of
how many entries reference it. Populated automatically during ingest:

- **RFC 6962** carries the chain inline on the wire — it is parsed out and written directly.
- **static-ct-api** carries only fingerprints — the certs are fetched from the log's
  `issuer/<hash>` endpoint, verified against the fingerprint, and written.

To reconstruct a leaf's chain: for each `fp` in `chain_fingerprints`, read `issuers/<hex(fp)>.der`.

## Roots store — `roots/`

The log's **accepted roots** (its `get-roots` set) — the trust anchors a chain must terminate at.
Same content-addressing as the issuer store (`roots/<hex>.der`, `sha256(file) == hex`). Mirrored
automatically, once per log.

## Reading the data back

- **Leaf certificate:** parse `leaf_input` as a `MerkleTreeLeaf` (X509 → `TimestampedEntry.X509Entry`);
  for precerts use the `precertificate` field.
- **Full chain:** `leaf` + `issuers/<hex>.der` for each `chain_fingerprints` entry.
- **Validate:** verify the signature path `leaf → chain → a cert in roots/`. The built-in
  `VerifyEntry` RPC / `ctv2 -mode verify` does this offline.
- **Not stored** (needs a live fetch): Merkle *inclusion* proofs (no STH or tree tiles are kept) and
  the issued certificate's SCT.

## Rationale (why this shape)

- **Raw leaf kept verbatim** (`leaf_input`): canonical, independently re-verifiable, and identical
  across both protocols.
- **Chain as fingerprints + a shared issuer store:** ~3–4× smaller records — the same CA certs are
  deduplicated from millions of inline copies down to a few thousand files — and both protocols
  converge on one record shape.
- **Content-addressing the issuer/root certs:** free deduplication, tamper-evidence
  (`sha256(file) == name`), and safe concurrent writes from fanned-out jobs sharing one log's tree.
- **gzip on partitions only** (~2.2×); the issuer/root stores stay raw to preserve the
  content-address invariant and keep certs directly readable.

Measured sizes: leaf records ≈ 1.6–1.9 KB/entry; the issuer and root stores are a fixed, small set
per log, so their per-entry cost approaches zero at scale.
