# Cert-Date Partitioning — Design Plan

## Motivation

Current archive dirs are named by **ingestion date** (`YYYYMMDD/`), which makes
each dir an arbitrary cross-section of cert-issuance time. Sampling `20260509`
shows 13.3M certs with `not_before = 2025-09` and only ~20K across all other
months — the partition boundary has no semantic meaning. This makes date-range
queries, incremental exports, and future DNS pipeline filtering by cert age all
harder than they need to be.

The goal is to partition by **cert issuance month** (`YYYY-MM/`, keyed on
`not_before`) so that each partition is a coherent, independently queryable
slice of the CT log.

---

## New Archive Layout

```
{archive-root}/
  issuers.db                  ← single global, append-only (all CAs)
  progress.db                 ← unchanged
  ingestion.log               ← unchanged
  YYYY-MM/
    subjects.db               ← all certs with not_before in that month
    subjects_export.tsv       ← export intermediate (written by ct-export)
```

Active (SSD) layout during an ingestion run:

```
{active-root}/
  {session-date}/
    YYYY-MM/
      subjects.db             ← active monthly DB, flushed to archive at session end
```

`issuers.db` lives only in the archive root and is opened directly by the
ingestion service (never copied through active, since it's small and
append-only).

---

## Issuers Design

**Single global `issuers.db` at the archive root.**

Rationale:
- All existing issuers.db files are 48–176 KB — the entire known CA corpus is
  tiny.
- A given CA issues certs across all months; per-partition copies would either
  disagree on `ca_id` values (breaking cross-partition queries) or redundantly
  store the same rows everywhere.
- The ingestion service already caches the `fingerprint → ca_id` mapping
  in-process (`issuerCache`), so the global DB is hit infrequently (only on
  new CA fingerprints).

The per-date-dir `issuers.db` files are **eliminated**.

`ca_id` values remain consistent across all monthly partitions because they all
reference the same global file. The `InsertSubjectBatch` path is unchanged.

---

## Partition Key and Granularity

**Key**: `subjects.not_before` truncated to `YYYY-MM`.

**Granularity: monthly.** The sampled distribution shows issuance months ranging
from ~500 to ~13M rows within a single ingestion-date DB. Across the full
corpus (772M rows), monthly partitions are expected to be 2–15 GB each —
well within the range that the existing SQLite tooling handles efficiently.

If a future issuance month exceeds ~30 GB, the partition can be split by
week (`YYYY-MM-W1` etc.) at that point. No schema change required.

**Fallback**: a cert with a missing or unparseable `not_before` goes to a
special `unknown/subjects.db` partition. In practice this should be empty.

---

## Schema Changes

**None to the `subjects` table itself.** All existing columns, indexes, and
constraints carry over.

The `(tile_idx, entry_idx)` uniqueness constraint remains correct per-partition:
a given (tile, entry) has exactly one `not_before` date and therefore maps to
exactly one monthly partition. No cert can appear in two monthly DBs.

`issuers` table schema is unchanged; it just lives in one file instead of many.

---

## Migration from Existing Data

Re-ingesting the full CT log from scratch would take 1–2 weeks. Re-partitioning
from existing data is feasible and preferred.

### What re-partitioning requires

1. **Build a unified `issuers.db`**: merge all 9 per-date `issuers.db` files
   into one, assigning stable global `ca_id` values keyed on fingerprint.
   (Use the existing `MergeIssuerDBs` logic.)

2. **Build a `ca_id` remap table**: for each source DB, load its local
   `fingerprint → local_ca_id` mapping. Construct a translation
   `(source_db, local_ca_id) → global_ca_id`.

3. **Stream and repartition each source DB**: for each row, remap `ca_id`,
   determine the target month from `not_before`, and write to the corresponding
   `YYYY-MM/subjects.db`.

4. **Write-side**: use the same build-on-new-file pattern as
   `buildMergedSubjectDB` — each monthly DB is built fresh (sequential pages,
   no fragmentation).

### Reading the large fragmented DB

`20260512/subjects.db` (226 GB, fragmented B-tree) would take ~35 hours via
SQLite cursor. Options:

- **Extend rawscan** to extract all subject columns (not just `san_domains`).
  The record format is already fully understood; adding column extraction for
  INTEGER and TEXT types for all 17 columns is straightforward. This brings
  read time back to ~18 min for that file.
- **Accept cursor slowness** for a one-time migration. Total estimated wall
  time via cursor: ~40 hours. Acceptable if run unattended.

Recommendation: extend rawscan into a general row extractor for the migration
tool. The column-parsing logic already exists in `sqliteColDataSize` and the
varint decoder; extracting all columns is ~50 lines more code.

### Migration tool: `cmd/repartition`

```
./bin/repartition \
  --src  /Volumes/wd_office_2/datasets/CT/ \
  --dst  /Volumes/wd_office_2/datasets/CT-v2/ \
  --tmp  /Volumes/wd_office_2/tmp/
```

Phases:
1. **Build global issuers.db** → `dst/issuers.db`
2. **Build remap table** in memory (all source issuers loaded)
3. **Stream each source subjects.db** (rawscan for fragmented, cursor for
   others) → fan-out writes to `dst/YYYY-MM/subjects.db` files
4. **Checkpoint+close** all output DBs, build query indexes

Output is a complete `dst/` tree ready to use as the new archive root.
The old `src/` tree is left untouched until validated.

---

## Ingestion Service Changes

### SubjectDB pool

Replace the single `subjectDB *db.SubjectDB` with a pool keyed by month:

```go
type monthPool struct {
    mu   sync.Mutex
    dbs  map[string]*db.SubjectDB  // "YYYY-MM" → open DB
    dir  string                    // active session dir
}
```

For each cert, extract `not_before[:7]` (or `"unknown"`) and route to the
correct DB, opening it lazily. The pool holds at most a few months open
simultaneously (certs in a live CT log are almost always within a 1–2 month
window; historical backfill spans more but writes to many is fine).

### IssuerDB

Open the global `issuers.db` from the archive root at session start. It is
**not** closed and re-opened on day rollover. Close it only on caught-up or
session end.

`issuerCache` (the in-process fingerprint map) spans the entire session,
not just one ingestion date. Remove the `clear(issuerCache)` on day rollover.

### Day rollover / session end (caught-up)

Replace `archiveDateDir` (which moved a whole dated dir) with a per-month
merge:

```go
// For each open monthly DB in the pool:
//   1. CheckpointAndClose the active DB
//   2. MergeSubjectDBs(activePath, archivePath)
//      (creates archive/YYYY-MM/subjects.db if it doesn't exist)
```

`MergeSubjectDBs` already uses the build-on-new-file approach, so the archive
partition stays unfragmented across incremental ingestion runs.

### Date rollover mid-session

With cert-date partitioning the ingestion-date rollover becomes a no-op for
the DB pool — the pool already writes each cert to the right month regardless
of what day the ingestion server's clock shows. The rollover event only needs
to trigger the archive flush (same as caught-up).

---

## Export Changes

`cmd/export` already uses co-located `subjects_export.tsv` per dir. The only
change is the directory name format: `YYYY-MM/` instead of `YYYYMMDD/`. No
code changes needed — `filepath.WalkDir` finds `subjects.db` wherever it lives.

The sharding and wildcard-split logic is unchanged.

---

## R2 Backup

`tools/r2_backup.sh` iterates `[0-9]*/` dirs. The glob needs to include
`YYYY-MM/` dirs:

```bash
for dir_entry in "$ARCHIVE"/[0-9]*/; do   # currently: 20260505, 20260506, ...
```

With monthly partitioning the dirs look like `2025-09/`, `2026-01/`, etc. A
pattern like `[0-9][0-9][0-9][0-9]-[0-9][0-9]/` matches both. Also add
`issuers.db` at the archive root (not inside a date dir) as a separate upload.

---

## Implementation Steps

### Phase 1 — Migration tool (`cmd/repartition`)
1. General raw-page row extractor (extend rawscan to all columns)
2. Build global issuers.db + remap table from source issuers DBs
3. Fan-out writer: month-keyed output DB pool using `buildMergedSubjectDB`
   pattern
4. Wire up: cursor for small DBs, raw extractor for fragmented ones
5. Validate: row counts, spot-check ca_id consistency, spot-check date ranges

### Phase 2 — Ingestion service
1. `db.go`: add `OpenSubjectDBPool` / `SubjectDBPool.GetOrOpen(month)` /
   `SubjectDBPool.FlushAll(archiveRoot)` — replacing the single SubjectDB
   open/close pattern
2. `db.go`: global IssuerDB open helper (no per-date path logic)
3. `service.go`: replace `openDatedDBs` with pool + global issuer open
4. `service.go`: replace `archiveDateDir` calls with `pool.FlushAll(archiveRoot)`
5. `service.go`: remove `clear(issuerCache)` on day rollover
6. Update `Check` / `computeMetrics` to count across YYYY-MM dirs

### Phase 3 — Tooling updates
1. `tools/r2_backup.sh`: update dir glob; add `issuers.db` at root
2. `cmd/export`: no code changes (WalkDir still finds `subjects.db`); update
   any path assumptions in comments
3. `EXPORT_PLAN.md`: note new dir format

### Phase 4 — Cutover
1. Run `repartition` against existing archive → new archive root
2. Validate new archive (row counts, sample queries)
3. Stop ct-server, point it at new archive root, restart
4. Upload new archive to R2 (replacing old layout)
5. Delete old archive once R2 backup confirmed

---

## Open Questions

1. **Session dir naming in active**: currently `{active}/{YYYYMMDD}/`. With
   cert-date partitioning the session date still matters for naming the active
   temp dir — keep it as-is or use a UUID/sequence?

2. **Concurrent ingestion sessions**: the current design assumes one writer at a
   time. The global issuers.db is fine (infrequent writes, WAL). The per-month
   active DBs are session-local so no contention. No change needed here.

3. **progress.db and tile_idx dedup**: tile_idx/entry_idx uniqueness is
   per-partition. If the same CT log is ingested twice (e.g., after a crash),
   the `INSERT OR IGNORE` on `(tile_idx, entry_idx)` still deduplicates
   correctly within each partition.

4. **Export intermediate compatibility**: existing `subjects_export.tsv` files
   in the old `YYYYMMDD/` dirs are not compatible with the new layout. They
   should be deleted or regenerated after migration (phase 0 of ct-export
   regenerates them on first run for each new dir).
