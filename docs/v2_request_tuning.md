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
| **Cloudflare** | rfc6962 (nimbus) | 16 + **`-qps 8`** | 256 | **~2,077 e/s** (stable) | **self-throttle to < 10 req/s** or get a 1-min block; see [Cloudflare](#cloudflare-self-throttle-under-the-rate-limit) |
| **DigiCert** | rfc6962 (wyvern) | 16+ | **256-aligned** | ~370 → **~1,825** e/s | **disable HTTP keep-alive** (~5×) + 256-align; see [DigiCert keep-alive](#digicert-disable-http-keep-alive-the-5-fix) |
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

## DigiCert: disable HTTP keep-alive (the ~5× fix)

DigiCert runs **N Nginx servers per shard, each limited to ~1 req/s**, behind a load balancer
(ct-policy thread `lTqtb4WHsqo`). A **persistent (keep-alive) connection pins to one server**, so
connection reuse caps you at ~1 req/s and triggers 429s — which is why our default client (Go
keep-alive + connection pooling) only managed ~370 e/s. Closing the connection after each request
lets the load balancer **re-roll each request across all servers**; combined with concurrency,
requests spread over the whole pool.

Use `-no-keepalive` (sets `Transport.DisableKeepAlives`, rfc6962 path):

    ctv2 -mode fetch -url https://wyvern.ct.digicert.com/2026h1/ -protocol rfc6962 \
      -start <256-aligned> -end <256-aligned> -concurrency 16 -page-size 256 -no-keepalive

**Measured (conc 16, 256-aligned, 30 s):** keep-alive **371 e/s** → `-no-keepalive` **1,825 e/s**
(**~4.9×**). Best combined with 256-alignment (DigiCert returns a full 256 only on aligned starts)
and concurrency ≥ the server count to cover the pool.

Trade-off: a TLS handshake per request, so it's **off by default** — only worth it for logs that
throttle persistent connections (DigiCert today; possibly others that 429 under keep-alive).

---

## Cloudflare: self-throttle under the rate limit

Cloudflare (nimbus) enforces **100 requests per 10 s per IP (= 10 req/s), with a 1-minute IP block
when exceeded** (per a Cloudflare rep on ct-policy, Apr 2024). Their 2024 note assumed a **1024**
get-entries batch (→ ~36M entries/hr), but nimbus now returns only **256/request** (verified), so
today's per-IP ceiling is **10 req/s × 256 ≈ 2,560 e/s** — the 1024→256 downgrade quartered it.

Naively bursting (high concurrency, no rate limit) repeatedly trips the 10 req/s line and earns the
1-min block, which is why earlier runs were erratic (~1,000 e/s with frequent zeros). The fix is
**client-side `target_qps`** to stay safely under 10 req/s. Measured (conc 16, page 256, 30 s):

| `-qps` | req/s | result |
|---|---|---|
| 4 | 4 | ~985 e/s, stable |
| **8** | 8 | **~2,077 e/s, stable (no failures)** |
| 10 | 10 | erratic (1,278 / 0) — at the limit, jitter trips the block |
| 12–16 | >10 | collapses to ~300 e/s — **1-min block** |

Use `-qps 8` (≈2× the uncapped result, fully stable):

    ctv2 -mode fetch -log-id <nimbus> -concurrency 16 -qps 8 -page-size 256 …

`qps 10` is *at* the policy line and unstable (the limiter's burst + timing jitter tip over
100/10 s); keep margin. No keep-alive trick or tile interface helps here (Cloudflare is rfc6962-only
and resets via HTTP/2 RST_STREAM). General lesson: **for an IP-rate-limited log, a client-side qps
cap just under the limit beats high concurrency** — concurrency above the cap only causes blocks.

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
- **Previously-slow providers, now tunable:** DigiCert ~370 → **~1,825 e/s** with `-no-keepalive`
  (+256-align); TrustAsia ~220 → **~1,300 e/s** via `-protocol tiles`; Cloudflare ~1,000 erratic →
  **~2,077 e/s stable** with `-qps 8`. None is a hard long-pole anymore — see their sections.
  (Full 1–2 B mirrors are still large, but no longer rate-gated.)
- **Always** align ranges + `page_size` to 256; **`-no-keepalive` for DigiCert**; **`-qps 8` for
  Cloudflare** (and a client qps cap for any IP-rate-limited log).
- **Distributed fan-out:** since per-provider ceilings differ by ~100×, schedule per provider —
  one slow provider should not hold up the fast ones.

---

## Caveats

- Probes are coarse: fixed-30s cold windows, 1–2 trials, distinct cold offsets. The first
  per-operator sweep used single trials; the refinement used two. Exact knees would need more
  trials / same-range control per provider.
- **Google's** early zero-throughput probes under sustained testing were partly our-IP throttling;
  its ~32 knee is from the controlled same-range test and is solid.
- **Cloudflare was re-tested after a cooldown (2026-06):** still rate-limited (100 req/10 s/IP +
  1-min block, not transient) — resolved by self-throttling to `-qps 8` (see the Cloudflare
  section). The erratic numbers in the concurrency-sweep table above are pre-`qps`-cap and
  superseded by that section.
- The first cross-provider sweep confounded index-range with concurrency for some points; treat
  single-trial outliers (the `*` cells) as noise.
- Numbers are point-in-time (2026-06-16) and vary with provider load and our network.
