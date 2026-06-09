# Append-only flush + deferred seal (branch `ct-flush-append-only`)

Work in progress. Implements the throughput fix from the 2026-06-08 analysis:
turn the SSD→HDD flush from **O(archive-month) per flush** into **O(new-rows)
per flush**, with the expensive O(month) work deferred to a rare `SealMonth`.

## The problem (recap)

`FlushAll` routed every existing partition through `MergeSubjectDBsScratch`, a
full rebuild of the whole archive month. Evidence from `data/logs/remerge.log`:
adding **226 MiB** of new data to the 2025-05 month took **59 minutes** because
it rewrote the entire ~10 GB month through the `cert_hash` unique index. This is
both the throughput wall and the "giant-month wall" (each rebuild needs
18–24 GB of SSD scratch, forcing the park-one-pool-at-a-time drain).

The B2 append path (`dedup.go`) already pre-filtered new rows via the SSD dedup
set, but it still **dropped and rebuilt the `cert_hash` unique index on every
flush** (`rebuildUniqueCertHash`) — which on a >RAM HDD month is itself O(month).
So it never actually escaped the wall.

## What changed

1. **`appendDedupedNewRows` no longer rebuilds any index.** It drops the
   `cert_hash` + read-path query indexes (a one-time O(month) cost the first time
   a pre-existing month is flushed; a cheap no-op thereafter) and sequentially
   appends only the rows the SSD dedup set hasn't seen. Every flush after the
   first is a pure sequential append. Dedup authority is the SSD set.

2. **New `SealMonth(archivePath, scratchDir)`.** The deferred O(month) step:
   compacts any transient duplicate rows (the append path tolerates them — a
   dedup-set pre-filter miss or a crashed-retry re-append) and rebuilds the
   `cert_hash` unique + 4 read-path query indexes. With `scratchDir` set it does
   the rebuild on the SSD and copies the finished month back sequentially (giant
   months never do random index work on the HDD); with `""` it works in place
   (small months / tests). Meant to run **rarely** — month caught up, on a
   schedule, or once at the end of a bulk drain.

3. **`FlushAll` existing-partition branch** now calls `FlushMonthDeduped`
   instead of `MergeSubjectDBsScratch`.

   **One-time migration (avoids the in-place DROP wall).** A pre-existing month
   still carries its giant `cert_hash` unique index. Dropping that in place on a
   >RAM HDD month is itself the random-seek wall — measured at **36m58s** on the
   11 GB 2025-12 month. So the *first* flush of such a month detects the index
   (`hasCertHashIndex`) and rebuilds the month as an index-free heap via a
   sequential scratch rebuild (`migrateMonthToAppendOnly` → `buildIndexFreeHeap`
   → `scratchRebuildArchive`) — a sequential HDD read + SSD write + sequential
   copy-back instead of a random in-place DROP. Once migrated the index is gone,
   so every later flush skips straight to the fast append. `MergeSubjectDBsScratch`
   was refactored to share the `scratchRebuildArchive` boilerplate.

4. **`cmd/remerge-pools`** seals each touched month once at the very end (pools
   are drained by then, so the SSD has room for the seal's scratch rebuild even
   on the giants — the wall is gone). Removed the now-dead
   `RebuildQueryIndexesInline` toggle.

5. Tests reworked: per-flush tests assert append correctness + idempotency and
   that query indexes are *absent* after a flush; compaction + index presence are
   asserted after `SealMonth`. `TestFlushMonthDeduped_RealMonth` now also seals
   the giant-month copy and times it separately.

Net per-flush cost: the 59-minute flush becomes seconds, and no per-flush SSD
scratch headroom is needed. The O(month) work happens once per seal, not once
per (pool × month) rollover.

## Validate before deploying

- `bash test.sh` (passing).
- **Real-data timing** on COPIES (never the live archive — 2025-02 corruption
  history). Use ABSOLUTE paths (`go test` runs with CWD = the package dir), and
  put the big copies on the HDD + scratch/dedup on the SSD to mirror prod:
  ```
  CT_REAL_ARCHIVE=/Volumes/wd_office_2/datasets/CT/2025-12/subjects.db \
  CT_REAL_POOL=/Users/benfultz/Dev/proto-ct/data/active/<pool>/2025-12/subjects.db \
  CT_REAL_WORKDIR=/Volumes/wd_office_2/tmp/ct-realtest \
  CT_REAL_SCRATCH=/Users/benfultz/Dev/proto-ct/data/active \
  go test ./internal/db -run RealMonth -v -timeout 120m
  ```
  Watch COLD (first touch — now a scratch migration, not the 37 min DROP) vs
  WARM (steady state) vs SEAL timings.

### Measured (2025-12: 11.4 GB archive, 23.2M rows, 784K pool rows)

| Phase | Before migration opt | After migration opt |
|---|---|---|
| COLD (first touch) | 36m58s (in-place DROP) | _validating_ |
| WARM (steady state) | 25s | 25s |
| SEAL (SSD scratch) | 8m22s | 8m22s |

Dedup pre-filter dropped 519K of 784K pool rows (66% cross-log overlap); SEAL
compacted 9 transient dups; quick_check ok.

## Open follow-ups (NOT done on this branch)

- **Seal scheduling for the LIVE path.** `FlushAll` now never seals, so a live
  ct-server's touched archive months progressively lose their query indexes and
  accumulate transient dups until something seals them. Backfill is fine (seal
  when caught up). The live server needs a seal trigger — every N rollovers, on
  graceful shutdown, or a separate scheduled pass. Deliberately left as a
  decision rather than wired in unilaterally.
- **`cert_log` semantics (the secondary finding).** The scratch rebuild in
  `SealMonth` (via `buildMergedSubjectDB`) still produces a file with no
  `cert_log` table, so a scratch seal drops the archive's `cert_log` — same as
  the old full rebuild did. (The append path itself now *preserves* the existing
  `cert_log` instead of wiping it, but still doesn't carry new pool provenance.)
  Resolve the open question first: is `cert_log` disposable (then stop writing it
  on the multi-log ingest path — an ingestion-side win) or load-bearing (then
  carry it through append + seal)?
