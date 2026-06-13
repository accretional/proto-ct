# Query Patterns & Index-Design Evaluation

Status: design note / analysis. Not yet implemented.
Date: 2026-06-02.

This note plans the query patterns we want to support across the three sibling
datasets (CT, DNS, IP) and evaluates them against the current on-disk index
design. Grounding use case: a cloud platform that wants to understand the
**users, abusers, and peers** of its service — registration info, geographic
info, AS/LIR ownership, abuse/technical contacts, mail configuration, and
identifying other cloud platforms' IP ranges.

The goal here is *not* to build the end-to-end lookup tool. It is to validate
whether the current data gathering and partitioning are efficient for that
general shape of query, and to identify the cheapest changes that close the
biggest gaps.

---

## 1. What we actually have on disk

### proto-ct — ~115 GB, partitioned by cert-issuance month

Layout: `CT/YYYY-MM/subjects.db` (~150 partitions, 2–13 GB each), keyed on
`not_before`. Global `issuers.db` at the archive root maps `ca_id → CA`.

`subjects` columns:
`ca_id, serial_number, common_name, organization, state, country,
not_before, not_after, san_domains` (comma-joined TEXT blob), `san_ips`
(comma-joined TEXT blob), `url, is_wildcard, san_count, entry_type,
tile_idx, entry_idx, cert_hash, log_id`.

Indexes: `(tile_idx, entry_idx)` unique, `cert_hash` unique, `ca_id`,
`common_name`, `not_after`, `is_wildcard`.

Derived serving artifacts (the real index for entity lookups):
- export shards by eTLD+1 registrable domain (`shards/<tld>/<bucket>.tsv`)
- `seen_fqdns.db` (`fqdn → first_seen DATE`, indexed on both)

### proto-domain — ~70 GB DNS, partitioned by TLD

Layout: `dns/<tld>/...`. `.com` is further bucketed by the first character of
the registrable label (`com/a.db` … `com/z.db`, `com/0.db`; e.g. `com/e.db`
= 5.6 GB). Most other TLDs are a single `records.db`.

One table per record type — `dns_records_a, _aaaa, _cname, _dname, _ns, _mx,
_txt, _soa, _caa, _loc, _hinfo, _rp, _afsdb, _naptr, _kx, _sshfp, _svcb,
_https, _uri` — plus a `dns_records` UNION view. `fetch_log(domain → status,
fetched_at)`.

**Every record table is indexed on `domain` only.** IPs (`ipv4`/`ipv6`),
mail/name hosts (`host`), and CNAME/DNAME `target`s are unindexed TEXT.

### proto-ip — no bulk store

It is lookup *services* over reference files (`ip2asn-v4/v6.tsv`, dbip /
ip2location `.mmdb`, `rpki-vrps.json`, anycast prefix lists, geofeeds) plus a
live RDAP client/server. IP enrichment is computed per-query, **not**
materialized for joins.

### The join fabric

The only key shared across all three datasets is **the string**:
domain ↔ domain (CT SAN ↔ DNS `domain`) and the IP string (DNS `A`/`AAAA`
value ↔ proto-ip input). There are no numeric keys, and **IPs are stored as
text**, so there is no notion of an IP *range* anywhere in the persisted data.

---

## 2. Query patterns, scored

### Well served — forward, name-keyed, time-sliced

| # | Pattern | Why it works |
|---|---------|--------------|
| Q1 | Domain/FQDN → all DNS records | partition hit on TLD + `domain` index |
| Q2 | Domain → cert by exact CN; expiring certs; new certs in a date range | `common_name` / `not_after` indexes; month-partitioning prunes date ranges |
| Q3 | "New FQDNs since day X" | `seen_fqdns.first_seen` indexed |
| Q4 | Domain → A records → proto-ip ASN/geo/RDAP | each hop indexed until the live IP lookups (latency in that tail) |

### Partially served

| # | Pattern | Gap |
|---|---------|-----|
| Q5 | "All subdomains of example.com" | CT is the right source, but raw `subjects.db` can't answer it (`san_domains` is an unindexed blob, CT is partitioned by *time* not name). Only the derived export / `seen_fqdns` artifacts make this tractable. |
| Q6 | "All DNS under example.com" | Co-located in one SLD bucket (good), but `domain LIKE '%.example.com'` is a leading-wildcard match → can't use the `domain` index → bucket scan. |

### Poorly served — reverse / value-keyed (this is where the use case lives)

| # | Pattern | Gap |
|---|---------|-----|
| Q7 | IP → domains hosted there (reverse DNS) | no index on `ipv4`; full scan of all A-tables across 70 GB |
| Q8 | CIDR / IP-range → domains ("other cloud platforms' ranges", "peers") | IPs are TEXT → no range scan even *with* an index |
| Q9 | Nameserver → domains; mail-provider/MX → domains | `host` columns unindexed → full scan across ~25 per-TLD DBs |
| Q10 | Organization → domains/certs ("all certs for Acme Inc") | `organization` not indexed |
| Q11 | AS number → its domains | `ip2asn` gives prefixes, but prefix→domain is Q8 |
| Q12 | Full cert/SAN history for a domain | the `san_domains` blob + time-partition problem again |

**The shape of the gap:** the design is optimized for forward, name-keyed,
time-sliced access. Every reverse / value-keyed query — IP→domain,
CIDR→domain, NS→domain, MX→domain, org→domain — is unindexed. Those are
exactly the "users, abusers, peers, other cloud ranges" questions.

---

## 3. Recommendations

### R0 (foundational) — Commit to a uniform key convention

Normalize every dataset on two canonical keys:

- **registrable domain** (eTLD+1, PSL-derived) as the domain join key, with the
  full FQDN retained alongside it; and
- **integer IP** (`uint32` for v4, `uint128`/16-byte for v6) as the IP join key,
  with the text form retained for display.

This is not a "someday" cleanup. It is the schema contract that R1–R3 are all
built against: the moment we build the IP→domain index (R1) we are *forced* to
pick an IP representation, and the only representation that supports range/CIDR
queries is integer. Likewise the `domain` column in that index has to follow a
normalization rule or it won't join back to CT and DNS. **R0 and R1 are one
step, not two** — R1 is simply R0's first concrete application.

Practically: define this once (a small `key` package / proto, shared or vendored
across the three repos) so "registrable domain" and "integer IP" mean the same
bytes everywhere.

### R1 (first build) — Materialize an IP→domain inverted index, IPs as integers

Single highest-value addition. Table `(ip_int, domain, fetched_at)` partitioned
by `/8` or `/16`, indexed on `ip_int`. Built by scanning the existing
`dns_records_a` / `_aaaa` tables once.

Unlocks Q7 (reverse DNS), Q8 (CIDR/range → domain, because `ip_int` supports
`BETWEEN`), and Q11 (ASN → prefixes → `ip_int` range → domains). Without integer
IPs, Q8/Q11 are not "slow" — they are *impossible* without a full scan and a
per-row text-to-range comparison.

### R2 — Inverted tables for the other reverse keys

`ns_host → domain` and `mx_host → domain` aggregates (or, at minimum, indexes on
those `host` columns). A dedicated provider-keyed aggregate scales better than
scattering a scan across ~25 per-TLD DBs. Unlocks Q9.

### R3 — Normalized SAN index for CT

`(san_domain, cert_id)` indexed on `san_domain`, partitioned by eTLD+1 like the
export already is. Turns Q5 and Q12 from blob scans into index hits. We are
half-way there with `seen_fqdns`; this extends it from "exists / first_seen" to
"which certs." Add an `organization` index in the same pass to cover Q10.

> Caveat: the PSL wildcard-explosion issue already flagged in
> `proto-ct/DAILY_PIPELINE_PLAN.md` (`*.beget.app`, `*.lcl.dev` each becoming
> their own eTLD+1) will distort any eTLD+1-partitioned CT index. Resolve that
> before building R3 on top of it.

### R4 — Materialize IP enrichment as a local range table

`ip2asn` / geo are already local TSV/mmdb. Load them as an integer-range table
(keyed by the same `ip_int` as R1) so batch analytics over 70 GB of A-records
join ASN/geo **locally** instead of via per-IP live RDAP. Reserve live RDAP for
the registration / abuse-contact tail (Q-style lookups on a handful of IPs, not
the whole corpus).

---

## 4. Two cross-cutting notes

**The serving layer is per-file SQLite + UNION.** Even with the indexes above,
reverse queries that touch many partitions will be slow because there is no
single engine spanning files. For the analytic/reverse workloads, consider
pointing **DuckDB** at the SQLite files or the TSV exports — it parallel-scans
and range-filters far better than walking B-trees file by file, and it is a
low-commitment way to validate query shapes (Q7–Q11) *before* committing to
building the inverted indexes.

**Partitioning trade-offs as they stand:**
- CT by `not_before` month is great for temporal queries (Q2, Q3) and useless
  for entity lookup — which is why the eTLD+1 export shards exist and are doing
  the real serving work.
- DNS by TLD + SLD-bucket co-locates "all of example.com" (helps Q6) but only if
  you scan the bucket, and the SLD-first-char bucketing is uneven (`com/e.db`
  = 5.6 GB) with hot-bucket skew.

---

## 5. Suggested sequencing

1. **R0+R1 together** — key convention + IP→domain integer index. Validates the
   single most important reverse direction (peers / cloud ranges) and forces the
   key decision everything else depends on.
2. **R4** — local IP-enrichment range table, so R1's output is immediately
   joinable to ASN/geo without live lookups.
3. **R2 / R3** — the remaining reverse keys (NS/MX, SAN/org), once the key
   convention and the IP spine are proven.
4. Throughout: use **DuckDB over the existing files** to benchmark each query
   shape before locking in schema.

Open question to resolve before step 1: which reverse direction do we validate
first — **IP/CIDR → domain** (peers / cloud ranges) or **domain → full
cert+DNS+IP profile** (users / abusers)? They share the R0+R1 spine, so this
only changes which benchmark queries we write first.

---

## 6. Sequencing relative to bootstrap, and write-path isolation

The R-builds above are deferred until **after** the initial bootstrap ingestion
(full CT-log pull + DNS resolution of the FQDNs extracted from those logs; IP
data is already static/public). Three decisions are easy to conflate here; we
want them kept separate.

### 6a. Defer the reverse-index *build* — and build it as a bulk sort

An inverted index is fundamentally a **sort**, not a stream of inserts. The
right way to build R1 is: project `(ip_int, domain)` out of the A/AAAA tables,
`ORDER BY ip_int`, bulk-load sequentially. Done as one batch pass that is
sequential on the HDD; done incrementally instead, it is a random B-tree update
per row — on spinning disk that is the 1–2 orders-of-magnitude difference.

There is no value in maintaining reverse indexes mid-bootstrap (nothing queries
the reverse direction yet) and the data is still changing shape — CT
partitioning was just migrated, and DNS today only covers the subjects of a
**single** log (Let's Encrypt Sycamore2026h1, which finished first). As more
logs land, the unique-FQDN set grows and DNS coverage grows with it; anything
built now is rebuilt later anyway. So: defer, then build via bulk sort (DuckDB
over the existing files is the natural tool — see §4).

### 6b. Reverse indexes never touch the ingestion write path

This is the answer to the write-throughput worry. The reverse/analytic indexes
live in **separate derived DBs**, never as secondary indexes on the live
`subjects` / `dns_records_*` tables. Adding (say) an `ipv4` index or NS/MX
`host` indexes to the ingestion tables would make every insert do N extra
random-offset B-tree updates on the HDD — exactly the bottleneck we already
hit, made worse.

The discipline is a **write-store / read-store split**: ingestion carries only
the indexes that *dedup requires*; everything else is a rebuildable projection
built afterward by sequential passes. That split is also what makes deferral
safe — a reverse index being "behind" is a freshness property, never a
correctness one. After bootstrap, daily incremental appends plus periodic
re-sort/compaction keep the derived indexes current.

### 6c. The dedup bottleneck is orthogonal — and worth fixing *for* bootstrap

Independent of reverse indexes, the current `INSERT OR IGNORE` dedup against a
unique index on spinning disk is the bootstrap-critical bottleneck:

- The `(tile_idx, entry_idx)` unique index is naturally **append-ordered** when
  a log is ingested in tile order, so its hot pages stay cache-friendly.
- The `cert_hash` unique index is a **hash** — it scatters across the whole
  index, so every probe is a random HDD read.

CT logs from different providers are **largely overlapping**, so for logs 2..N a
large fraction of inserts are dedup *hits*: we pay a random HDD read **to
discover we did not need to write anything**. That cost dominates bootstrap on
its own. Options, by leverage:

1. **Probe in RAM first.** A Bloom filter on `cert_hash` at ~10 bits/elem is
   ~1 GB for ~772 M certs, fits in memory, and turns the random HDD probe into a
   RAM probe — with the SQLite unique constraint as the backstop for the rare
   false positive. Biggest win, least change.
2. **Dedup index on SSD, bulk data on HDD.** Random I/O for dedup on SSD is a
   non-issue; sequential bulk writes still go to the HDD. Extends the existing
   active-root-on-SSD pattern (a global `cert_hash` dedup DB on SSD).
3. **Defer dedup entirely:** ingest with duplicates (sequential HDD writes are
   cheap), then dedup once per partition at seal time via a sort. Converts
   per-insert random probes into one batch sort, at the cost of transient
   duplicate storage — significant under heavy overlap, so prefer (1) first.

### Resulting order of operations

1. Fix the dedup probe (Bloom filter and/or SSD dedup index) **before/during**
   bootstrap — it pays back across the whole multi-week pull.
2. Run bootstrap with ingestion carrying **only** dedup indexes.
3. After the corpus settles, build R0/R1 (then R2–R4) as **bulk sort passes**
   over the settled data, into separate derived DBs.
4. Keep the derived indexes fresh post-bootstrap via daily append + periodic
   re-sort, never via live secondary indexes on the ingestion tables.

---

## 7. Prototype validation (R1 + R3)

`cmd/reindex` + `reindex_validate.sh` (isolated from the shared build scripts so
it cannot disturb the live bootstrap) implement and validate R1 and R3 against
small static snapshots taken with the SQLite online-backup API.

### R0 made concrete

Every IP is stored as the **16-byte big-endian key**, with IPv4 written as its
IPv4-mapped IPv6 form (`::ffff:a.b.c.d`). A single BLOB index then orders both
families, and CIDR scans work as `WHERE ip BETWEEN lo AND hi`. Validated on the
`gov` DNS snapshot, which carried **both** families through the one key:
107,073 v4 + 50,594 v6 rows in a single `rev_ip` index.

**Alignment with proto-ip's `ip.IP` (verified).** proto-ip's `IP` message uses
the *same* mapping — `netip.Addr.As16()` → `::ffff:0:0/96` (see
`proto-ip/geoip/geofeed.go:177 protoFromAddr`) — but stores the 128 bits as two
big-endian `sint64` halves (`network_prefix`, `interface_identifier`) instead of
a contiguous BLOB. The two are byte-for-byte convertible:
`blob[0:8] = BE(uint64(network_prefix))`, `blob[8:16] = BE(uint64(interface_identifier))`.
`TestKey16MatchesProtoIPEncoding` pins this against the actual `ippb.IP` type,
including an IPv6 case whose interface half is a negative int64.

Two consequences for R0:
- **Index key vs interchange form.** proto-ip's `int64(BigEndian.Uint64(...))`
  cast makes any high-bit-set half (most real IPv6) negative, so a range/CIDR
  `BETWEEN` on the *signed halves* is wrong across the sign boundary. The
  contiguous BLOB sorts unsigned-bytewise, which is what range scans need.
  Conclusion: **BLOB is the index/sort key; `ip.IP` is the wire/interchange
  form** — same bytes, different lens.
- **Drift risk.** `protoFromAddr` is unexported, and the same As16↔halves
  conversion is currently hand-copied across proto-ip's `localip`, `rdap`,
  `geoip`, and three `cmd/*` tools. R0 should land a single **exported** shared
  helper (ideally a small `key` package) so proto-domain's index key and
  proto-ip's `IP` cannot silently diverge; the test above is the proto-domain
  side of that contract until then.

### What was measured

Snapshots: DNS `gov` (157,667 A/AAAA rows) and CT `2025-05` (525,939 certs).

| Build | Input | Output rows | Load | Index | Size |
|-------|-------|-------------|------|-------|------|
| R1 IP→domain | gov A/AAAA | 157,667 | 2.3 s | 83 ms | 12 MB |
| R3 SAN→cert | 2025-05 subjects | 1,122,262 | 5.2 s | 1.4 s | 134 MB |

| Query | Result | Indexed time |
|-------|--------|--------------|
| Q7 IP→domains (`54.177.40.166`) | 3,996 domains, exact match vs naive scan | 5.2 ms |
| Q8 CIDR→domains (`54.177.40.0/24`) | 3,996 domains | 6.8 ms |
| Q5/Q12 SAN at/under `azurecontainerapps.io` | 54,646 SAN rows / 11,608 certs | 161 ms |

Notes from the run:
- **Bulk-sort build confirmed.** Deferring index creation until after the load
  (the SQLite expression of "build as one sort", §6a) costs 83 ms for 157 K rows
  and 1.4 s for 1.1 M rows — negligible vs the load, and it is the *only* random
  work, done once.
- **Reverse queries that the source cannot do.** Q8 (CIDR→domain) has no
  equivalent on the source DNS DBs at all (text IPs, no range). Q7 matched a
  naive full scan exactly. Both return in single-digit ms against the index.
- **PSL roll-up behaves.** The busiest registrable domain in 2025-05 was the PaaS
  `azurecontainerapps.io` — customer subdomains correctly roll up to one eTLD+1
  (it is *not* a PSL wildcard entry). This is the benign mirror of the
  wildcard-explosion caveat in §3/R3; a true `*.`-wildcard PSL entry would
  instead fragment, and still needs handling before R3 ships.

### Partition fan-out (R1, validated on `uk`)

`build-ip-sharded` / `lookup-cidr-sharded` partition `rev_ip` into one DB per
**/16**, with a family-aware shard key (v4 by first two octets, v6 by first two
bytes — sharding the uniform key's leading /16 directly would dump all v4 in one
shard). The build streams rows in `ORDER BY shard, ip` so each shard file is
opened once and written contiguously (the §6a bulk sort). A CIDR query computes
the set of /16 shards overlapping its range and opens only those that exist.

Run on `uk` (2,047,854 A/AAAA rows), cross-checked against a single-file index:

| CIDR | shards in range | shards with data | domains | vs single-file |
|------|----------------:|-----------------:|--------:|----------------|
| `…81.0/24` | 1 | 1 | 155,614 | ✓ exact |
| `…0.0/16` | 1 | 1 | 155,654 | ✓ exact |
| `…0.0/14` | 4 | 3 | 155,692 | ✓ exact |
| `104.0.0.0/8` | 256 | 75 | 293,494 | ✓ exact |

**Routing is correct** at every width, and the router skips empty shards
(75 of 256 opened for the /8). Fan-out scales with query width exactly as the
/16 model predicts (1 → 4 → 256).

**But /16 is too granular.** One mid-size TLD produced **8,261 shard files**
(8,174 v4 + 87 v6), and the sharded layout was **229 MB vs 148 MB** single-file
(~+55%) from per-file page + per-shard-index overhead. Across the whole corpus
that is millions of tiny files. There's also a cold-open cost: the first query
to a shard paid ~880 ms (open + warm a 12 MB file) vs ~160 ms once warm.

**Recommendation:** refine R1's "/8 or /16" to **/8 for v4** (≤256 shards per
source, naturally bounded) — optionally splitting only the few hot /8s further —
and a coarse prefix for v6 (its fan-out is already tiny: 87 shards). The routing
code is identical; only the shard-key width changes.

**Confirmed by re-running at /8** (`SB=1`, same `uk` snapshot):

| | /16 | /8 |
|---|---:|---:|
| shard files | 8,261 | **225** (212 v4 + 13 v6) |
| sharded total vs 148 MB single-file | 229 MB (+55%) | **140 MB (−5%)** |
| `/24`,`/16`,`/14`,`/8` queries | 1–256 shards | **1 shard each** |
| routing correctness | ✓ exact | ✓ exact |

Going to /8 cut the file count **37×** and erased the storage overhead (the
per-shard fixed cost is now negligible — the layout is actually slightly smaller
than the single file). Because every shard is a /8, any query at /8 or finer
hits exactly one shard (the coarse-query fan-out only re-appears above /8, which
is rare), so coarse-range reads got faster too (the `/8` query dropped from
1.17 s across 75 shards to 485 ms on one). **/8 is the right v4 shard width.**

### Partition fan-out (R3, validated on CT `2025-05`)

`build-san-sharded` / `lookup-san-sharded` partition the SAN index by
**eTLD+1**, using the `(public-suffix, bucket)` key from `EXPORT_PLAN.md`
(large TLDs like `com` sub-bucket by the first char of the registrable label;
everything else is one file per suffix). Because every SAN of a registrable
domain — and all its subdomains — shares an eTLD+1, an "at/under D" query routes
to exactly one shard. Same bulk-sort build (stage, `ORDER BY shard`, fan out).

Run on CT `2025-05` (525,939 certs → 1,122,262 SAN rows), cross-checked against
the single-file index:

- **Routing correct.** `azurecontainerapps.io` (busiest registrable domain)
  routed to the single `san_io__all` shard and returned 54,646 SAN/cert pairs —
  exact match with the single-file index, 157 ms.

But the eTLD+1 key has **two skew problems**, both visible in one month:

1. **Long-tail fragmentation.** 1,523 shards / 1,497 distinct public suffixes,
   and **1,403 of them (92%) are near-empty (<64 KB)** — most ccTLD/gTLD
   suffixes have only a handful of certs per month. Sharded total 154 MB vs
   134 MB single-file (+15%), mostly per-file floor on the tiny tail. At
   full-corpus × per-month this is a large pile of near-empty files.
2. **Hot shards from PaaS-on-PSL.** Providers that are themselves public
   suffixes get one big shard: `san_azure-api.net__all` was **46 MB** in this
   one month, `san_io__all` 10.8 MB, `san_amplifyapp.com__all` 4.3 MB. (62
   suffixes had ≥3 labels — PSL private/wildcard entries — so the §3 wildcard
   concern is present but, this month, a minor contributor next to the tiny-tail
   problem.)

**Recommendation:** don't give every public suffix its own file. Reserve
dedicated shards for high-volume suffixes (a `largeTLD`-style allowlist or a
size threshold) and route the long tail into a **bounded catch-all** — e.g. by
first character of the suffix (~37 files). Routing stays single-shard (the query
domain deterministically picks the same catch-all), but shard count drops from
~1,500 to ~(hot suffixes + buckets) + 37, eliminating the near-empty tail. This
is the R3 analogue of moving R1 from /16 to /8. Hot-shard skew (azure-api.net)
is the opposite problem and would instead want *splitting* — deferred until it
matters.

**Confirmed by re-running with a catch-all** (`DEDICATE_MIN=5000`: suffixes with
≥5,000 SAN rows, plus the `largeTLD` set, get dedicated shards; the rest collapse
into `_tail__<first-char-of-suffix>` files; the dedicated set is persisted in
`manifest.json` so queries route identically):

| | per-suffix | catch-all (≥5000) |
|---|---:|---:|
| shard files | 1,523 | **75** (47 dedicated + 28 tail) |
| near-empty (<64 KB) | 1,403 | **6** |
| sharded total vs 134 MB single-file | 154 MB (+15%) | **133 MB (≈0)** |
| routing correctness | ✓ exact | ✓ exact |

The catch-all cut shard count **20×** and erased the near-empty tail (1,403 → 6)
and the storage overhead, while `azurecontainerapps.io` still routed to its one
`san_io__all` shard with an exact 54,646-pair match. The hot shards persist by
design (`azure-api.net` 46 MB, `io` 10.8 MB) — fragmentation is solved; hot-shard
*splitting* is the separate, still-open problem. **The catch-all is the right R3
shape**, the eTLD+1 analogue of /8.

### (ip, domain) dedup (R1, validated)

Both R1 builds now collapse duplicate `(ip, domain)` pairs (from DNS refetches),
keeping the most recent `fetched_at`. It rides the existing bulk sort as
**sort-then-unique**, not random `INSERT OR IGNORE` probing (docs §6c): the
single-file build stages to a side file and streams the sorted, deduped rows
into a clean output; the sharded build dedups inside each shard during the
`ORDER BY shard, ip, domain, fetched_at DESC` fan-out. `fetched_at` is now
carried in the sharded index too, so the value doubles as a freshness filter.

On `uk`: 2,047,854 rows → 2,047,816 (**38 dup pairs**). Tiny today — the DNS set
is a single-log bootstrap and `seen_fqdns` already dedups FQDNs — so this is
mainly *forward-looking* correctness for the daily-append world, where the same
`(ip, domain)` recurs across refetches. Single-file and sharded dedup identically
(same 38), so the oracle cross-check still matches exactly at every CIDR width;
the validation's naive check moved to `count(DISTINCT domain)` accordingly.
Staging to a side file (vs an in-place `CREATE TABLE AS … DROP`) also avoids
free-page bloat — the single-file index stayed 148 MB rather than ballooning.

### Hot-shard splitting (R3, validated)

A second threshold, `REINDEX_SAN_SPLIT_MIN`, promotes any suffix at/above it
(plus the static `largeTLD` set) to be **split by the first char of the
registrable label** — exactly how `com` is already bucketed, now size-driven.
The bucketed set is recorded in `manifest.json` alongside the dedicated set, so a
query still computes the same single shard (a domain's registrable label picks
its char bucket).

Run on CT `2025-05` with `dedicate-min=5000 split-min=100000` (the 273,836-row
`azure-api.net` shard is the only suffix over the split threshold):

- **The 46 MB shard is gone**, replaced by 26 `san_azure-api.net__<char>`
  sub-shards. With it split, the **whole index's largest shard dropped from
  46 MB to 10.8 MB** (`io`, deliberately left below the threshold).
- Routing stays exact: `azurecontainerapps.io` still matched the single-file
  oracle (54,646 pairs); the unit test `TestSanSplitScheme` covers routing into
  a split shard.

**Caveat — label-char skew.** Splitting is *best-effort*, not balanced: the
largest `azure-api.net` sub-shard (`__d`) is still 10.5 MB, so the 273 K rows
collapsed only ~4.4× (not 26×) because first chars are skewed. One round pulls a
monster down to the next tier; a suffix whose labels share a first char would
barely split at all. If a single round is not enough, the options are a **second
char** of the label or a **hash bucket** (guaranteed balance, same single-shard
routing) — left as a small follow-up since one round sufficed here.

### Scale check (R1 on a 5.3 GB com bucket)

Built R1 from `dns/com/g.db` (one of 17 `.com` buckets) — **14,861,796 A/AAAA
rows, ~7.3× the `uk` test** — snapshotted to local SSD and built there (the
bootstrap was using the HDD; see below):

- **Build cost** scales linearly and stays modest: single-file 2m46s, `/8`
  sharded 3m22s (~90 K rows/s on SSD); dedup found 1,760 dup pairs (~0.01%).
  Sharded total equals the single file (1.1 GB) — `/8` still adds no overhead.
- **Routing is exact** vs the single-file oracle at every width, at 14.9 M rows.

Two findings the small tests couldn't surface:

1. **`/8` hot shards get large at scale — the IP-side analogue of R3's
   PaaS-on-PSL problem.** In *one* com bucket the busiest /8 shards are already
   `v6_26` 174 MB, `v4_104` 162 MB, `v4_172` 107 MB (Cloudflare / hosting / v6).
   Across all 17 com buckets a hot /8 like `104.0.0.0/8` would be ~2–3 GB. So
   `/8` is right for the long tail but **the few hot /8s need the same
   size-driven split** we built for SAN suffixes (e.g. sub-shard a hot /8 by the
   next octet → /16). The R3 split tier and manifest pattern ports directly.
2. **Pathological-IP query latency is result-set-bound, not seek-bound.** The
   hot IP `104.247.81.99` has **1.18 M domains** pointing at it (parking/hosting),
   so a `/24` query returned 1.18 M rows in 5.7 s and the `/8` returned 2.0 M in
   8.6 s — the cost is materializing millions of domain strings, not the index
   probe. A real consumer must paginate/LIMIT (or aggregate) for such IPs;
   ordinary IPs with a handful of domains return in ms.

### Hot-`/8` split (R1, validated — with a limit)

`REINDEX_IP_SPLIT_MIN` splits any base `/8` over a row threshold one byte finer
(`/8` → `/16`) by the next octet, recorded in the shard dir's `manifest.json`;
CIDR routing reads it and opens a split base's overlapping `/16` sub-shards
instead of the base file (`fineNamesForBase`). Mechanism mirrors the R3 split.

Re-run on `com/g` (`split-min=1,000,000`): 4 hot `/8`s split → 645 shards (was
242), **routing exact at every width** vs the single-file oracle (the `/14` now
correctly fans to 4 `/16` sub-shards, the `/8` to 256). Sharded total unchanged
(1.1 GB). Largest shards: `v6_26_06` 109 MB, `v4_104_247` 98 MB, `v4_185` 67 MB
(an unsplit `/8` now the biggest base).

**The limit: prefix-splitting can't decompose a single hot IP.** `v4_104` (162 MB)
split down only to `v4_104_247` 98 MB — because that `/16` holds
`104.247.81.99`, the one IP carrying **1.18 M domains**. Those domains share the
*exact* 16-byte key, so no prefix split (not `/16`, not `/24`, not even `/32`)
can spread them across shards. Hot-`/8` split fixes a `/8` that's hot from *many*
addresses; a `/8` hot from *one* address is irreducible by sharding. The real
levers for a hot IP are at the data/consumer layer (store a count instead of
every parked FQDN; paginate/aggregate at query time) — not partitioning.

### Not yet validated (follow-ups)

- **Hot-IP handling.** Pathological single IPs (≫1 M domains; parking/hosting)
  bloat one leaf shard and dominate query time regardless of sharding. Needs a
  data-model answer (count/sample rather than store-all, or a side "popular IP"
  table), not a finer prefix.
- **Balanced hot-shard split.** Label-char splitting is skewed (above); a
  hash-bucket or recursive second-char split would guarantee balance for an
  extreme suffix. Unbuilt — one char round was enough at current scale.
- **R3 at scale.** A large CT month (e.g. 2025-08, 26 M certs) is not yet built —
  CT is actively backfilling (every month has today's mtime), so a clean
  snapshot is awkward; deferred until the bootstrap settles or done off-peak.
- **True HDD read latency.** The scale build read from an SSD snapshot to avoid
  contending with the live bootstrap; query/build latency against multi-GB
  partitions *on the spinning disk* is still unmeasured.
- **Naive SAN comparison is a bound, not equality.** The cross-check uses a
  `LIKE '%domain%'` substring scan, which is a superset sanity bound, not an
  exact oracle.
