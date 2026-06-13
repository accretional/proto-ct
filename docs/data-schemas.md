# Data Schemas & Fetch-Tool Patterns

Status: reference. Describes the **current** persisted DB schemas, the **planned**
reverse-index schemas (prototyped in `cmd/reindex`, see [[query-patterns]]), and
the **data patterns of the fetch-only tools** (RDAP, geo, resolver) that hold no
bulk store. Spans three repos: proto-ct (CT ingestion + storage), proto-domain
(DNS/RDAP/resolver services), proto-ip (IP mapping + lookup services).

Conventions used everywhere:
- SQLite, one logical dataset fanned across many files (partitioned). Bulk DBs
  are built write-once (delete-mode); the live per-TLD DNS DBs are WAL-mode.
- Timestamps are Unix epoch seconds in an `INTEGER` column (usually `fetched_at`
  / `seen_at` / `not_before`).
- The canonical cross-dataset keys are the **registrable domain** (eTLD+1) and
  the **16-byte IP key** (`ipkey.Key`, see §3.1). These are the planned join
  fabric; today's stores join on raw strings.

---

## 1. What persists vs. what is computed live

| Dataset | Repo | Persisted? | Partitioning |
|---|---|---|---|
| CT certificate subjects | proto-ct | yes (~115 GB) | by cert-issuance month |
| DNS records | proto-domain pipeline | yes (~70 GB) | by TLD (+ SLD bucket for com) |
| Reverse indexes (R1/R3) | (planned) | **planned** | by IP /8 / by eTLD+1 |
| IP → ASN / geo / RPKI / anycast | proto-ip geo | **no** — reference files | n/a (mmdb / TSV / JSON) |
| RDAP (domain & IP registration) | proto-ip + proto-domain | **no** — live network | n/a |
| DNS resolution | proto-domain | **no** — live network | n/a |
| Local host IPs | proto-ip localip | **no** — live host | n/a |

---

## 2. Current persisted schemas

### 2.1 CT subjects (proto-ct)

Layout: `{archive}/YYYY-MM/subjects.db`, partitioned by **cert issuance month**
(`not_before` truncated to `YYYY-MM`), ~150 monthly DBs, 2–21 GB each.

The CA dimension is a **single global `issuers.db`**, not partitioned — issuers
are consistent across every sharded month, so `ca_id` values are stable
corpus-wide. It lives in proto-ct's shared active-path storage
(`proto-ct/data/active/issuers.db`, ~34 K CAs):

```sql
CREATE TABLE issuers (
    ca_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint  TEXT    NOT NULL UNIQUE,   -- CA cert fingerprint (cache key)
    common_name  TEXT,
    organization TEXT,
    country      TEXT
);
```

The ingestion service caches `fingerprint → ca_id` in process and only hits this
DB on a new CA fingerprint, so one global writer suffices.

```sql
CREATE TABLE subjects (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ca_id         INTEGER NOT NULL,        -- -> global issuers.ca_id
    serial_number TEXT,
    common_name   TEXT,
    organization  TEXT,
    state         TEXT,
    country       TEXT,
    not_before    TEXT,                    -- partition key (YYYY-MM of this)
    not_after     TEXT,
    san_domains   TEXT,                    -- comma-joined SAN FQDNs (blob)
    san_ips       TEXT,                    -- comma-joined SAN IPs (blob)
    url           TEXT,
    is_wildcard   INTEGER DEFAULT 0,
    san_count     INTEGER DEFAULT 0,
    entry_type    TEXT    DEFAULT 'x509',
    tile_idx      INTEGER,                 -- CT log tile / entry coordinates
    entry_idx     INTEGER,
    cert_hash     BLOB,
    log_id        BLOB
);
CREATE UNIQUE INDEX idx_subjects_tile_entry ON subjects(tile_idx, entry_idx);
CREATE UNIQUE INDEX idx_subjects_cert_hash  ON subjects(cert_hash) WHERE cert_hash IS NOT NULL;
CREATE INDEX idx_subjects_ca_id     ON subjects(ca_id);
CREATE INDEX idx_subjects_cn        ON subjects(common_name);
CREATE INDEX idx_subjects_not_after ON subjects(not_after);
CREATE INDEX idx_subjects_wildcard  ON subjects(is_wildcard);

-- Per-log entry ledger (dedup of the same cert seen across logs is via the
-- cert_hash unique index above).
CREATE TABLE cert_log (
    log_id    BLOB    NOT NULL,
    entry_idx INTEGER NOT NULL,
    cert_hash BLOB    NOT NULL,
    seen_at   INTEGER NOT NULL,
    PRIMARY KEY (log_id, entry_idx)
) WITHOUT ROWID;
CREATE INDEX idx_cert_log_hash ON cert_log(cert_hash);
```

Access shape: indexed by `(tile,entry)`, `cert_hash`, `ca_id`, `common_name`,
`not_after`, `is_wildcard`. **Not** indexed by SAN (it's a comma-joined blob) or
`organization`. Entity lookups ("certs for example.com") go through the derived
export / reverse index, not this table directly.

### 2.2 DNS records (proto-domain pipeline)

Layout: `{root}/<tld>/records.db`; `.com` is bucketed `<tld>/<bucket>.db`
(`a.db`…`z.db`, `0.db`) by the first char of the registrable label. ~25 TLD
dirs. One table per RR type plus a UNION view and a fetch ledger. Every record
table is indexed on `domain` only.

```sql
-- fetch ledger: one row per attempted FQDN (dedup / status / recency)
CREATE TABLE fetch_log (domain TEXT PRIMARY KEY, status TEXT NOT NULL, fetched_at INTEGER NOT NULL);

-- address records
CREATE TABLE dns_records_a    (domain TEXT, ttl INTEGER, fetched_at INTEGER, ipv4 TEXT NOT NULL);
CREATE TABLE dns_records_aaaa (domain TEXT, ttl INTEGER, fetched_at INTEGER, ipv6 TEXT NOT NULL);
-- name/alias records
CREATE TABLE dns_records_cname (domain TEXT, ttl INTEGER, fetched_at INTEGER, target TEXT NOT NULL);
CREATE TABLE dns_records_dname (domain TEXT, ttl INTEGER, fetched_at INTEGER, target TEXT NOT NULL);
CREATE TABLE dns_records_ns    (domain TEXT, ttl INTEGER, fetched_at INTEGER, host   TEXT NOT NULL);
CREATE TABLE dns_records_mx    (domain TEXT, ttl INTEGER, fetched_at INTEGER, pref INTEGER NOT NULL, host TEXT NOT NULL);
CREATE TABLE dns_records_txt   (domain TEXT, ttl INTEGER, fetched_at INTEGER, value  TEXT NOT NULL);
CREATE TABLE dns_records_soa   (domain TEXT, ttl INTEGER, fetched_at INTEGER,
    ns TEXT, mbox TEXT, serial INTEGER, refresh INTEGER, retry INTEGER, expire INTEGER, min_ttl INTEGER);
CREATE TABLE dns_records_caa   (domain TEXT, ttl INTEGER, fetched_at INTEGER, flags INTEGER, tag TEXT, value TEXT);
-- service binding
CREATE TABLE dns_records_svcb  (domain TEXT, ttl INTEGER, fetched_at INTEGER, priority INTEGER, target_name TEXT, params TEXT);
CREATE TABLE dns_records_https (domain TEXT, ttl INTEGER, fetched_at INTEGER, priority INTEGER, target_name TEXT, params TEXT);
-- less common: loc, hinfo, rp, afsdb, naptr, kx, sshfp, uri (same domain/ttl/fetched_at + type-specific cols)
CREATE TABLE dns_records_loc   (domain TEXT, ttl INTEGER, fetched_at INTEGER,
    version INTEGER, size INTEGER, horiz_pre INTEGER, vert_pre INTEGER, latitude INTEGER, longitude INTEGER, altitude INTEGER);
CREATE TABLE dns_records_naptr (domain TEXT, ttl INTEGER, fetched_at INTEGER,
    ord INTEGER, preference INTEGER, flags TEXT, service TEXT, regexp TEXT, replacement TEXT);
CREATE TABLE dns_records_sshfp (domain TEXT, ttl INTEGER, fetched_at INTEGER, algorithm INTEGER, fp_type INTEGER, fingerprint TEXT);
CREATE TABLE dns_records_uri   (domain TEXT, ttl INTEGER, fetched_at INTEGER, priority INTEGER, weight INTEGER, target TEXT);
-- (hinfo: cpu/os; rp: mbox/txt; afsdb: subtype/hostname; kx: preference/exchanger)

CREATE INDEX idx_<type>_domain ON dns_records_<type>(domain);  -- one per table

-- read-only convenience union: (domain, type, ttl, fetched_at, value)
CREATE VIEW dns_records AS
  SELECT domain,'A',ttl,fetched_at,ipv4 FROM dns_records_a
  UNION ALL SELECT domain,'AAAA',ttl,fetched_at,ipv6 FROM dns_records_aaaa
  UNION ALL SELECT domain,'MX',ttl,fetched_at,pref||' '||host FROM dns_records_mx
  -- … one arm per RR type …
;
```

Access shape: forward only — `domain → records` is a direct partition + index
hit. Reverse lookups (`ipv4 → domain`, `host → domain`) are unindexed full
scans; that gap is what the planned reverse indexes (§3) close.

### 2.3 Derived / pipeline artifacts (proto-ct)

- `subjects_export.tsv` — per cert-month, three columns `domain\tdirect\twildcard`,
  alphabetically sorted (k-way merge input).
- export shards — `shards/<tld>/<bucket>.tsv`, eTLD+1-sharded FQDN lists.
- `seen_fqdns.db` — **planned** (DAILY_PIPELINE_PLAN.md), not yet on disk:
  `seen_fqdns(fqdn TEXT PRIMARY KEY, first_seen DATE)`, `INDEX(first_seen)`;
  the daily DNS-fetch worklist + FQDN dedup.

---

## 3. Planned reverse-index schemas (prototyped in `cmd/reindex`)

These are validated on the `reindex-prototype` branch but **not yet productized**.
They are *derived, rebuildable* indexes, never on the ingestion write path; built
as a bulk sort (stage → `ORDER BY` → fan out), deduped during the sort. The
durable home is proto-ct (write path) + a future read tool; see
[[reverse-index-architecture]].

### 3.1 R0 — the canonical IP key (proto-ip `ipkey`)

The shared storage/sort key for every IP, in `github.com/accretional/proto-ip/ipkey`:

```go
type Key [16]byte   // big-endian IPv4-mapped IPv6 (::ffff:0:0/96)
// Of(netip.Addr) Key · Key.Addr() · Key.Halves()/FromHalves · Key.Compare · Range(prefix)->(lo,hi)
```

- Sorts as **unsigned bytes** = numeric address order, so range/CIDR scans are a
  plain `BETWEEN lo AND hi`. IPv4 lives in its mapped block and sorts before
  global-unicast v6.
- Wire form is `ippb.IP` (two `sint64` halves `network_prefix`/`interface_identifier`
  + a `version` oneof). Same 16 bytes; **never sort on the signed halves** — a
  high-bit-set half goes negative. `IP.Key()` / `ippb.FromAddr` bridge the two.

### 3.2 R1 — IP → domain reverse index

Per-shard table:

```sql
CREATE TABLE rev_ip (
    ip         BLOB    NOT NULL,   -- ipkey.Key (16-byte)
    domain     TEXT    NOT NULL,
    ver        INTEGER NOT NULL,   -- 4 or 6 (provenance)
    fetched_at INTEGER             -- latest observation; also a freshness filter
);
CREATE INDEX idx_rev_ip ON rev_ip(ip);   -- built after the bulk load
```

- **Dedup**: one row per `(ip, domain)`, keeping the most recent `fetched_at`.
- **Partitioning**: by IP **/8** (base), one file per byte:
  `v4_<octet>.db`, `v6_<hexbyte>.db`. A base over `REINDEX_IP_SPLIT_MIN` rows is
  **split one byte finer** (`/16`): `v4_<o1>_<o2>.db`, `v6_<b0>_<b1>.db`.
- **Manifest** (`<dir>/manifest.json`): `{ "split_min": N, "split": ["v4_104", …] }`.
  CIDR routing reads it to open a split base's overlapping `/16` sub-shards.
- **Known limit**: prefix split cannot decompose a single hot IP (e.g. one IP
  with 1.18 M domains stays in one leaf) — that needs a data-model answer, not a
  finer prefix. See [[query-patterns]] §7.

### 3.3 R3 — SAN → cert reverse index

Per-shard table:

```sql
CREATE TABLE san_index (
    san_domain  TEXT    NOT NULL,  -- normalized SAN FQDN (wildcard '*.' stripped)
    reg_domain  TEXT    NOT NULL,  -- eTLD+1 (PSL)
    cert_id     INTEGER NOT NULL,  -- subjects.id within the source month
    is_wildcard INTEGER NOT NULL
);
CREATE INDEX idx_san_domain ON san_index(san_domain);
CREATE INDEX idx_san_reg    ON san_index(reg_domain);
```

- **Partitioning**: by **eTLD+1**, `san_<suffix>__<bucket>.db`. Bucketing tiers:
  - *bucketed* suffixes (largeTLD like `com`, or any suffix ≥ `REINDEX_SAN_SPLIT_MIN`)
    split by first char of the registrable label → `san_com__e.db`.
  - *dedicated* suffixes (≥ `REINDEX_SAN_DEDICATE_MIN`) → `san_<suffix>__all.db`.
  - everything else → bounded catch-all `san__tail__<first-char-of-suffix>.db`.
- **Manifest** (`<dir>/manifest.json`):
  `{ "dedicate_min": N, "split_min": M, "dedicated": [...], "bucketed": [...] }`.
  A query's eTLD+1 deterministically picks one shard (bucketed → dedicated → tail).

### 3.4 R4 — local IP-enrichment table (planned, not prototyped)

To batch-join the 70 GB of A-records to ASN/geo without per-IP live RDAP: load
the proto-ip reference data (§4.2) as an integer-range table keyed by the same
`ipkey.Key`, so enrichment is a local range join. Reserve live RDAP for the
registration/abuse-contact tail.

---

## 4. Fetch-only tools — data patterns (no bulk store)

These services are **stateless**: they answer per-query from reference files or
the live network, keyed by `ipkey.Key` / domain, and persist nothing. Implication
for the index work: enrichment is *computed at query time*; large-scale joins
need the materialized R4 snapshot rather than calling these per row.

### 4.1 IP RDAP — registration (proto-ip `rdap`, proto-domain RDAP)

Live RDAP over HTTP, bootstrapped from the IANA registries (RIR/registry → RDAP
base URL). No cache table. Response messages (proto-ip `rdap.proto`):

- `RDAPNetwork{ handle, name, type, start_address, end_address, country,
  status[], entities[], events[], cidr_blocks[], parent_handle, rdap_server }`
- `RDAPAutnum{ handle, name, … }`, `ASN{ number }`
- `RDAPEntity{ handle, fn, roles[], emails[], org, address, phone }` — the
  abuse/technical contact dimension.
- `RDAPEvent{ action, date }`, `RDAPCIDRBlock{ prefix, length }`,
  `RDAPResponse{ …, raw_json }` (raw passthrough retained).

proto-domain runs a domain-side RDAP resolver (`RDAPResolver`, `cmd/rdap-server`)
with the same live, no-store pattern for domain registration.

### 4.2 IP geo / network info (proto-ip `geo`) — reference files

No DB; lookups read these local reference sources (in `proto-ip/data/geoip`),
each effectively an IP-range → attribute map:

| File | Format | Provides |
|---|---|---|
| `ip2asn-v4.tsv`, `ip2asn-v6.tsv` | TSV range rows | ASN, AS name, registry country |
| `dbip-city-lite-*.mmdb`, `ip2location-lite-db9.mmdb` | MaxMind DB | city/region/country/lat-lon |
| `rpki-vrps.json` | JSON VRP list | RPKI ROAs (prefix, maxlen, asn) |
| `anycast-v4-prefixes.txt`, `anycast-v6-prefixes.txt` | prefix list | anycast flag |
| `ipmap-geolocations-latest.csv` | CSV | geofeed-style geolocation |
| operator geofeeds | RFC 9092 CSV | authoritative self-published geo |

Composed into `geo.proto` responses:
- `NetworkInfo{ asn, network, as_name, org, registry_country, abuse_email,
  rdap_handle, rpki_covering_roas[], reverse_dns }` — the AS-level spine.
- `GeoResponse{ sources[], asn, network, anycast, … }`,
  `GeoLocation{ lat, lon, country, region, city, postal_code, time_zone }`,
  `GeoSourceResult{ matched_prefix, authoritative, attribution, asn, network }`,
  `RpkiRoa{ prefix, max_length, asn }`.

### 4.3 Local host IPs (proto-ip `localip`) — live host

Reads the host's interfaces (`/proc/net` or the darwin equivalent), no store:
`Interface{ name, hardware_address, addresses[]CIDR, up }`, filtered by
`LookupFilter{ classes[], names[], only_routable }`.

### 4.4 DNS resolution (proto-domain resolver) — live network

`cmd/server` resolves a name live via the Go DNS resolver and returns records in
the `dns_record.proto` shape. The persisted DNS dataset (§2.2) is the *batch*
output of this same resolution run over CT-derived FQDNs; the live service holds
no store.

---

## 5. Join fabric (current vs planned)

| Edge | Today | Planned |
|---|---|---|
| CT SAN ↔ DNS | raw FQDN string | normalized registrable domain + FQDN |
| DNS A/AAAA ↔ IP tools | raw IP text | `ipkey.Key` (16-byte) |
| IP tools ↔ IP tools | per-query, recomputed | R4 range table on `ipkey.Key` |
| cert ↔ SAN | `san_domains` blob | `san_index(san_domain, cert_id)` (R3) |
| IP ↔ domains | full scan | `rev_ip(ip, domain)` (R1) |

The two canonical keys — **registrable domain** and **`ipkey.Key`** — are the
contract that lets the persisted stores (§2), the planned reverse indexes (§3),
and the live fetch tools (§4) line up without re-parsing strings at every hop.
