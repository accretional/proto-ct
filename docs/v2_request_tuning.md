# v2 Request Tuning Recommendations

Per-provider fetch tuning for the v2 raw-leaf archiver (`internal/ctv2`, `cmd/ctv2`).
Concurrency is **not** baked into the code — it is caller-specified per request
(`fetch_concurrency`, `page_size`) because the right values differ sharply by log operator.
This doc consolidates the measurements taken 2026-06-16 and gives concrete recommendations.

> Measurements are coarse (fixed-30s cold probes, 1–2 trials, entries counted via the
> `CheckCoverage` RPC) except where noted as a controlled same-range test. They are good for
> ranking and order-of-magnitude tuning, not exact knees. See **Caveats** at the end.

---

## TL;DR — per-operator settings

| Operator | Protocol | Concurrency | page_size | Observed best | Notes |
|---|---|---|---|---|---|
| **Let's Encrypt** | static (sycamore) | **64** | n/a (tiles) | ~20,700 e/s | plateaus at 64; fastest overall |
| **Sectigo** | rfc6962 (mammoth) | **128+** | 256-aligned | ~17,000 e/s | still scaling past 128; top rfc6962 |
| **Geomys** | static (skylight) | **96–128** | n/a (tiles) | ~16,600 e/s | climbing, diminishing returns |
| **Google** | rfc6962 (argon) | **32** | (cap 32) | ~4,000 cold / ~5,800 warm | hard knee at 32 |
| **IPng** | static (halloumi) | **32** | n/a (tiles) | ~3,800 e/s | plateaus at 32 |
| **Cloudflare** | rfc6962 (nimbus) | ~32–64 (re-test) | 256 | ~1,300 e/s | throttled in testing; needs clean re-test |
| **DigiCert** | rfc6962 (wyvern) | 8–16 | **256-aligned** | ~200→~310 e/s | request-rate-limited; alignment ~doubles it |
| **TrustAsia** | rfc6962 → **tiles** | 32 | (cap 32) | ~220 → **~1,300** e/s | get-entries hard-capped; use the experimental **tile interface** (~6×) — see [TrustAsia tiles](#trustasia-experimental-tile-interface-the-6-workaround) |

**Universal rule:** keep `page_size` a multiple of **256** and start ranges on 256-aligned
indices (see [256 alignment](#the-256-alignment-effect)). 256 is also the static-ct-api tile size,
so it is safe everywhere.

---

## The two knobs

- **`fetch_concurrency`** — number of in-flight fetches.
  - rfc6962: parallel `get-entries` workers (`scanner.Fetcher.ParallelFetch`).
  - static-ct-api: `sunlight` `ConcurrencyLimit` (parallel tile fetches).
- **`page_size`** — how many entries a single request asks for.
  - rfc6962: `get-entries` range width per call (`scanner.Fetcher.BatchSize`, default 256).
  - static-ct-api: not meaningful — entries come in fixed 256-entry tiles.

`target_qps` exists but was not the limiting factor in any test; leave at 0 (unlimited) and let
concurrency + provider rate-limits govern.

---

## Per-request return caps (verified directly)

Measured by issuing a single `GetRawEntries` for 16,384 entries and counting the response:

| Operator | Cap / call | Boundary-aligned only? |
|---|---|---|
| Google | **32** | no (flat) |
| TrustAsia | **32** | no (flat) |
| Cloudflare | **256** | no — 256 from any offset |
| DigiCert | **256** | **yes** — only when start ≡ 0 (mod 256) |
| Sectigo | **256** | **yes** |
| Let's Encrypt (static) | 256 (tile) | n/a |

Note: the widely-cited "Cloudflare ~1024" is **wrong** for nimbus2026 — it returns 256.
Let's Encrypt's rfc6962 `oak` log was unreachable during testing (DNS/timeout); LE is served via
the static `sycamore` logs.

### The 256-alignment effect

DigiCert and Sectigo **truncate each `get-entries` response at the next 256-entry boundary**: a
request starting at offset `o` returns only `256 − (o mod 256)` entries. Verified:

| start offset | `o mod 256` | entries returned |
|---|---|---|
| 100000 | 160 | 96 |
| 1000000 | 64 | 192 |
| 256000 / 1024000 (aligned) | 0 | 256 |

Implication for the fetcher: `scanner.Fetcher` steps by `BatchSize` from `StartIndex`, so if
`StartIndex` is not 256-aligned, **every** request in the run is misaligned → ~2 requests per 256
entries. The chunked mirror driver uses 1,000,000-entry chunks (1e6 mod 256 = 64), so DigiCert /
Sectigo ranges are currently misaligned — roughly **halving** DigiCert throughput (it is
request-rate-limited) and doubling Sectigo's request count.

**Recommendation / TODO:** align ranges to 256 — make the chunk size and `page_size` multiples of
256 so `StartIndex` lands on a boundary (e.g. chunk size 1,048,576). No effect on
Google/Cloudflare/TrustAsia; up to ~2× for DigiCert; pure efficiency + politeness for Sectigo.

---

## Concurrency findings

### Controlled test (Google Argon, rfc6962)
Same index range held constant, CDN cache warmed, 3 rotated rounds, SSD output (isolates the
concurrency variable):

| concurrency | 8 | 16 | 32 | 48 | 64 |
|---|---|---|---|---|---|
| entries/s (warm) | 2,419 | 4,134 | **5,815** | 5,721 | 5,699 |

Clean knee at **32**; flat beyond. Concurrency 16 is ~40% below plateau. Cold throughput is lower
and noisier (~4,000 at 32) but the knee holds.

### Per-operator cold sweep (entries/s)
| Operator | 8 | 32 | 64 | 96 | 128 |
|---|---|---|---|---|---|
| Let's Encrypt | 5,962 | 14,490 | 20,041 | 20,547 | 20,717 |
| Geomys | 3,402 | 8,093 | 13,638 | 15,556 | 16,624 |
| Sectigo | 972 | 4,429 | 9,588 | 11,998 | 17,098 |
| Google | 1,230 | 3,922 | ~1–2k* | — | — |
| IPng | 2,976 | 3,829 | 3,402 | — | — |
| Cloudflare | ~900* | 0* | ~1,300* | — | — |
| DigiCert | 154 | 287 | 200 | — | — |
| TrustAsia | 173 | 215 | 235 | — | — |

`*` = obvious throttling/noise (see Caveats). Static/CDN providers scale cleanly to high
concurrency; the rate-limited rfc6962 logs (DigiCert, TrustAsia) are flat regardless.

---

## Batch-size findings (slow rfc6962 logs, concurrency 16)

| Operator | 256 | 1000 | 4000 | 16000 |
|---|---|---|---|---|
| DigiCert | 200 | 271 | **310** | 305 |
| TrustAsia | 211 | 228 | 223 | 223 |

DigiCert improves ~1.5× with larger batches (it is request-rate-limited — fewer, larger requests
get more through), plateauing ~4000. TrustAsia is flat (entries-rate-capped; batch size
irrelevant). Note this interacts with alignment: a larger `page_size` that is a multiple of 256,
combined with a 256-aligned start, is the ideal for DigiCert.

---

## TrustAsia: experimental tile interface (the ~6× workaround)

TrustAsia's get-entries is hard-capped (32 entries/request → ~220 e/s, untunable), but they layer
an experimental **static-ct-api tile front-end on the same RFC6962 logs** — `/tile/data/<N>`
(256 entries/request) + `/issuer/<hash>` — on `ct2026-a.trustasia.com/log2026a` and
`ct2026-b.trustasia.com/log2026b` (ct-policy thread `LNvmpQUsKF8`). That's ~8× the entries/request
of get-entries.

It serves tiles + issuers but **no signed checkpoint** (`/checkpoint` 404s), so the normal
sunlight static path (which authenticates against a checkpoint) can't use it. v2's **tile fetcher**
(`LOG_PROTOCOL_STATIC_CT_API_NO_CHECKPOINT`, CLI `-protocol tiles`) handles this: it reads
`/tile/data` directly and takes the tree size from the log's RFC6962 `get-sth` instead of a
checkpoint.

    ctv2 -mode fetch -url https://ct2026-a.trustasia.com/log2026a -protocol tiles \
      -start <256-aligned> -end <256-aligned> -concurrency 32

**Measured:** ~**1,301 entries/s** @ conc 32 vs ~220 e/s get-entries — **~6×**. Records come out
static-style (leaf + chain *fingerprints*, ~2.6 KB/entry) so they're also smaller than
get-entries' full-chain records.

Caveats: **unauthenticated** (no checkpoint / inclusion proof — fine for a raw archiver, but note
it); **no partial tiles**, so the frontier stops at the last full 256-tile; experimental endpoint
(~3% transient tile errors observed → the fetcher retries). No public key needed.

When a TrustAsia log has a *real* static log in the loglist with a working checkpoint (e.g.
`luoshu2027`), prefer the authenticated `static` path there; use `tiles` for the RFC6962-only
shards (`log2026a/b`) where only the checkpoint-less tile front-end exists.

This pattern generalizes: **any RFC6962 log that exposes static tiles but no checkpoint** can be
mirrored far faster via `-protocol tiles` than via its get-entries endpoint.

---

## Bandwidth & entry size

- This host sustained **~20–26 MB/s** (Google rfc6962 ~23 MB/s, Sectigo ~26 MB/s, LE static
  ~18 MB/s). Bandwidth was never the binding constraint at observed concurrencies.
- **rfc6962 ~5 KB/entry** stored (binary `.binpb`; `extra_data` carries the full issuer chain,
  ~79% of bytes) vs **static ~1 KB/entry** (chain stored as 32-byte fingerprints, not full DER).
  Compare **entries/s** across protocols, not MB/s.
- Full-history mirror sizes scale accordingly (e.g. Argon2027h1, 30.4M entries ≈ 150 GB binary).

---

## Practical guidance

- **Fast first:** the static providers (Let's Encrypt, Geomys, IPng) and Sectigo are where
  throughput lives; target them for bulk work.
- **Slow / long-pole:** DigiCert (~310 e/s tuned) gates any full mirror (1.2B ≈ 45 days); prefer
  recent/targeted ranges over full history. TrustAsia *was* in this bucket via get-entries (~220
  e/s) but its experimental **tile interface gives ~1,300 e/s (~6×)** — see the TrustAsia section;
  use `-protocol tiles` for its RFC6962 shards.
- **Always** align ranges + `page_size` to 256.
- **Distributed fan-out:** since per-provider ceilings differ by ~100×, schedule per provider —
  one slow provider should not hold up the fast ones.

---

## Caveats

- Probes are coarse: fixed-30s cold windows, 1–2 trials, distinct cold offsets. The first
  per-operator sweep used single trials; the refinement used two. Exact knees would need more
  trials / same-range control per provider.
- **Google and Cloudflare showed intermittent zero-throughput probes under sustained testing =
  our-IP throttling.** Their numbers here are conservative; a clean re-test after a cooldown is
  warranted, especially for Cloudflare.
- The first cross-provider sweep confounded index-range with concurrency for some points; treat
  single-trial outliers (the `*` cells) as noise.
- Numbers are point-in-time (2026-06-16) and vary with provider load and our network.
