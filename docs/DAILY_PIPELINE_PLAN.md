# Daily incremental pipeline — implementation plan

A single binary, `cmd/dailycron`, runs on a daily schedule and replaces the
bulk pipeline. On each invocation it:

1. Pulls the CT-log delta from the last cursor up to the current STH.
2. Extracts SAN+CN FQDNs from the newly-ingested certs.
3. DNS-fetches the FQDNs that have not been seen before.
4. Appends results into per-TLD growing DBs.

The cursor in `progress.db` is shared with (and effectively replaces) the
bulk ingester, so once the new pipeline is online the bulk path can be
retired.

## Motivation

The bulk pipeline is slow to bootstrap and the export layer's PSL-derived
sharding produces low-value output: wildcard PSL entries (e.g.
`*.beget.app`, `*.lcl.dev`, `*.stg.dev`) treat each customer subdomain as
its own eTLD+1, exploding shard count with mostly ephemeral preview
hostnames. The daily delta is small enough that no sharding by registrable
domain is needed; sharding by TLD (last label) is enough and bypasses PSL
entirely.

## Architecture

```
cron @daily
  └─ dailycron
       ├─ IngestLog(--until-tip)         [gRPC → ct-server]
       ├─ extract.ExtractNewFQDNs(...)   [reads new tile range]
       └─ dnsfetch --fqdn-db --fqdn-date [subprocess]
```

Shared state:
- `progress.db` — existing CT cursor (one row per log).
- `seen_fqdns.db` — new; FQDN dedup table with `first_seen DATE`.

## Step 1 — `--until-tip` ingestion mode

**Proto** (`proto/ctingestion/v1/ingestion.proto`)
Add `bool until_tip = 7;` to `IngestRequest`.

**Server** (`internal/ingestion/service.go`)
- At `IngestLog` entry, when `req.UntilTip` is true: snapshot current tree
  size via the same path `Check()` uses (`computeMetrics` at ~line 311) and
  compute `targetTileIdx = ceil(treeSize / 256)`.
- Modify the loop guard at `service.go:205` so an until-tip run exits when
  `tileIdx >= targetTileIdx`. The existing `IsNotFound` exit at line 234
  remains a valid stop too.

**Client** (`cmd/client/main.go:74`)
Add `--until-tip` bool flag; mutually exclusive with `--continuous` and
`--batch`.

Estimated ~40 lines. No schema change.

## Step 2 — `seen_fqdns` table + extraction step

**New SQLite** at `{archiveDir}/seen_fqdns.db`:

```sql
CREATE TABLE seen_fqdns (
    fqdn       TEXT PRIMARY KEY,
    first_seen DATE NOT NULL
);
CREATE INDEX idx_seen_fqdns_first_seen ON seen_fqdns(first_seen);
```

**New package** `internal/extract/` with one entry point:

```go
// ExtractNewFQDNs reads SAN+CN from cert rows where
// tile_idx ∈ [startTile, endTile) across all subject DBs under
// archiveDir, INSERT-OR-IGNOREs into seen_fqdns, and returns the count of
// newly-inserted rows (the day's DNS workload).
func ExtractNewFQDNs(archiveDir string, startTile, endTile int, today time.Time) (newCount int, err error)
```

Implementation notes:
- Walk subject DBs under archiveDir (same walk as `cmd/export/main.go:84`).
- For each: `SELECT san_domains, common_name, is_wildcard FROM subjects
  WHERE tile_idx >= ? AND tile_idx < ?`.
- Split `san_domains` on comma, lowercase, trim trailing dot.
- Skip wildcards (`*.` prefix — unqueryable).
- Batch INSERT OR IGNORE into seen_fqdns with `first_seen = today`.
- No PSL.

## Step 3 — dnsfetch input: switch from TSV shards to `seen_fqdns`

**Modify** `cmd/dnsfetch/feed.go`:
- Add a new feed mode "fqdn-table": instead of `enumShards()` + TSV reads,
  query `seen_fqdns WHERE first_seen = ?` and stream rows.
- Group by TLD (last label) on the read side. `workItem.shard` collapses to
  a TLD string; no bucket.
- Keep the existing TSV-shard feed behind a flag for now in case we want to
  compare; prune later.

**New flags** in `cmd/dnsfetch/main.go`:
- `--fqdn-db {path}` and `--fqdn-date {YYYY-MM-DD}`, mutually exclusive
  with `--shards`.

## Step 4 — dnsfetch output: per-TLD growing DBs

**Modify** `cmd/dnsfetch/store.go`:
- Today: staging `{tld}/{bucket}.db` → finalized `{out}/{tld}/{bucket}.db`
  (move on completion).
- New: open `{out}/dns_{tld}.db` directly in append mode. No staging, no
  bucket, no finalize-move. Existing per-record-type table schema is
  reused unchanged.
- `finalizeAll()` becomes "close all open handles + WAL checkpoint each".
- Each row already carries a `fetched_at` column (verify on
  implementation) so daily appends are distinguishable.

The LRU DB pool needs a small audit to confirm growing DBs don't trip the
staging-dir checks.

## Step 5 — `cmd/dailycron` orchestrator

**New** `cmd/dailycron/main.go`, ~150 lines:

```
1. Read progress.db → startTile per log
2. Call IngestLog(--until-tip) over gRPC
3. Re-read progress.db → endTile per log
4. extract.ExtractNewFQDNs(archiveDir, startTile, endTile, today) → N new
5. Invoke dnsfetch as a subprocess with --fqdn-db --fqdn-date today
6. Log summary, exit
```

Flags: `--archive`, `--server-addr`, `--dns-out`, `--date` (default today),
`--dry-run`.

The orchestrator is a subprocess driver, not a library — keeps dnsfetch as
a standalone CLI and lets us cron individual stages if needed.

## Step 6 — Operational

- `tools/start_dns_stack.sh` already brings up unbound + proto-domain
  server idempotently; the cron invokes it before `dailycron`.
- The ct-server (gRPC ingestion service) needs to be running too; default
  to a persistent daemon since it's idle when not ingesting.
- Crontab:
  `@daily /path/to/dailycron --archive /Volumes/wd_office_2/datasets/CT --dns-out /Volumes/wd_office_2/datasets/dns >> /var/log/dailycron.log 2>&1`

## Orphaned components

- `cmd/export/` becomes unused. Keep for now (ad-hoc snapshots) but mark in
  README that the daily path does not use it.
- Existing per-shard DNS DBs at `/Volumes/wd_office_2/datasets/dns/` (the
  bulk-pipeline output) are *not* migrated into the new per-TLD layout.
  They sit in the old location; for a unified view, UNION across both at
  query time, or migrate later.

## Cutover

Default plan: fresh start. The new per-TLD DBs only contain daily-cron
output going forward. The bulk-pipeline output is frozen in its current
layout. A backfill migration (one-shot tool that re-inserts every existing
`{tld}/{bucket}.db` row into `dns_{tld}.db`) is possible but deferred — the
old data is already frozen in time and the new layout's value compounds
forward, not backward.

## Effort estimate

- Steps 1–2: ~1–2h.
- Step 3: ~4–6h (touches dnsfetch feed contract).
- Step 4: ~2–3h (LRU pool care).
- Step 5: ~2h glue.

Roughly half a focused day if nothing surprises.

## Open questions deferred

- DNS refresh policy for already-seen FQDNs (DNS mutates independent of
  certs). Current plan is new-only; revisit when there is a downstream need
  for fresh records on stable FQDNs.
