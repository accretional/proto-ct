Allow a target QPS to the monitoring endpoint to be configured, parallelize/throttle CT API clients during ingestion so that they stay below but close to (eg target ~80% utilization) the threshold. 

Update the examples/tests/etc to write DBs to /Volumes/wd_office_2/datasets/CT/ . And shard in sub-paths by ingestion YYYYMMDD.

Also, create a third SQLite DB to track ingestion progress and log cert specific metadata such as expiration time or CT API log URI. When clients resume ingestion with the service, it should automatically try to continue progress where it left off.

Create a ./tools/top_domains.sh <N> that queries the most recent log batch and returns the N most frequently seen Subject domains (rolling up subdomains to the parent domain). Add this to LET_IT_RIP.sh .

---

## Per-operator rate budget (follow-up — 2026-05-27)

The first multi-log staged run exposed a real bottleneck: rate limiting is enforced **per backend host**, not per log.

### What we observed
Geomys serves all four Tuscolo shards behind a single CDN front (`tuscolo-read.b621.net`). With the current per-log default of 3 QPS, the aggregate hitting that host is `4 logs × 3 QPS = 12 QPS`, which exceeds whatever cap they're enforcing. Result during the 21-log static-ct-api run:

- Tuscolo2027h2: errored after 6 retry attempts (~60s of exponential backoff) at tile 6
- Tuscolo2026h2: errored after 6 retry attempts at tile 21
- Tuscolo2026h1 + Tuscolo2027h1: ground forward at ~12 entries/sec (vs the theoretical 768/sec at 3 QPS × 256/page), implying steady 429s being absorbed by the retry loop

This is almost certainly the same shape for other multi-shard operators: Sectigo (Mammoth+Sabre+Elephant+Tiger), DigiCert (Sphinx+Wyvern), IPng (Gouda+Halloumi each with 4 shards), Let's Encrypt (Sycamore+Willow), Google (Argon+Xenon). LE and Google handled it fine in our run, but only because their per-log defaults (20 QPS) happen to land under their host caps for our 4–8 concurrent shards.

### Approaches

1. **Shared `rate.Limiter` per operator** (recommended). When constructing per-log clients, look up a process-wide `map[operator]*rate.Limiter` and inject the SAME limiter into every shard of that operator. All concurrent shards then queue against one budget. Operator-specific defaults stay the same numbers, but they now mean *aggregate across that operator*, not *per shard*.

2. **Per-host rate limiting** (more correct but more code). Group logs by the eTLD+1 of their submission/monitoring URL and share a limiter across the group. Catches cases where unrelated operators use the same CDN (none currently observed but possible).

3. **Lower per-log defaults so even aggregate stays safe** (band-aid). Drop static-ct-api default to 1 QPS-per-log; total stays bounded at `N_shards × 1 QPS`. Wastes capacity on operators that could go faster.

### Operator caps to encode (observed + reasonable inference)

| Operator | Suggested aggregate cap | Notes |
|---|---|---|
| Geomys | **5 QPS total** (across all 4 Tuscolo shards) | 429s above this; their `b621.net` CDN is the constraint |
| IPng Networks | **8 QPS total** (across 8 Gouda+Halloumi shards) | smaller infra, generous in our run but headroom is thin |
| Let's Encrypt | 50 QPS total (across 8 Sycamore+Willow shards) | published ≥80 QPS in their docs; this stays under |
| Google | 50 QPS total (across 4–6 Argon+Xenon shards) | published cap is 25/log; aggregate ~100 should be fine |
| Cloudflare | 20 QPS total | one CDN (cloudflare itself) |
| DigiCert / Sectigo | 10 QPS total each | published 5/log; aggregate ~10 should be safe |
| TrustAsia | 8 QPS total | mixed protocols |

### Retry policy follow-ups

- The `maxRetries=5` budget with 2s base + 32s cap = ~62 seconds of backoff total. Geomys 429s outlasted that. Either increase the cap (60–120s) or treat 429 as a "block until limiter recovers" signal rather than a transient retry.
- Workers that exhaust retries currently `return` from the goroutine and exit. Consider exponential backoff at the **worker** level (sleep 5min, then re-fetch tree size + resume) so transient operator outages don't kill a 24-hour run.

### Other observations from the same run

- **DB lock fix landed**: `MaxOpenConns(1)` on `ProgressDB` + `IssuerDB` eliminated `SQLITE_BUSY` storms when 21 workers race for the same connection-pool slot.
- **`HTTP 429` is now retryable**: `isFatalHTTP` excludes 429 so the client retries instead of bailing.
- **`HTTP 403 at frontier`**: static-ct-api logs publish tiles asynchronously after checkpoint advance. Worker now treats 403/404 from `FetchEntries` as `caught_up`, matching the legacy single-log behavior.
- **Memory**: ct-server holding 1.16 GB RSS with 63 monthly partition DBs open. Per-DB cache_size is 512 MiB max so this scales with partition fan-out. If RFC 6962 adds entries from older NotBefore months we should LRU-close idle partitions or trim cache_size.
- **Migration verified**: Sycamore2026h1 resumed cleanly at the migration point (912,839,168 → 913,000,704 after 100k session). No duplicate processing.

