# B2 fix + operational state — handoff (2026-06-05)

Written before a context compaction. This is the source of truth for what's
running, what to do next, and the standing directives. Companion to memory
`ct-b2-shelved-2025-02-repaired` and `docs/FLUSH_AND_SHUTDOWN_PLAN.md`.

## Standing directives (from the user — DO autonomously, don't ask)

1. **Keep CT ingestion and DNS fetch going however possible. Never leave
   ingestion stopped with a question for the user.** Resume after any
   maintenance.
2. **Get B2 working** (the fast SSD cert_hash dedup flush) to escape the
   stop+emergency-drain cycle. Fix → test → retry. Only fall back to the manual
   stop+drain if B2 still fails after *multiple* real attempts.
3. When SSD gets low: pause ct-client, let the flush drain (uncontended), then
   re-merge the orphaned pools to create headroom, then resume. (Done once; see
   "current op" — the orphaned-pool drain is the burst fallback, not the goal.)
4. dnsfetch may be paused briefly if SSD goes critical during a drain, but keep
   it up by default.

## Current operational state (as of ~19:50, 2026-06-05)

- **CT is DOWN** (ct-server + ct-client killed for the emergency drain). **dnsfetch is UP** (com/p, watchdog active), proto-domain pid 53184 up.
- **A drain is RUNNING:** `bin/remerge-pools --archive /Volumes/wd_office_2/datasets/CT` draining the 6 pool dirs under `data/active/` (~50 G: 3 orphaned pools `20260604_154612/164612/174612` + 3 from the resumed run `20260605_173211/183211/193211`) into the archive via the RELIABLE scratch-rebuild flush. Log: `data/logs/remerge.log`. Watcher: `data/logs/drain-watch.out` (fires on drain-done OR SSD≤12 G).
- SSD oscillates ~30–37 G as each giant's ~15–18 G scratch is built then reclaimed. Each giant month ~5 min. ETA a few hours.
- **NEXT when the drain finishes:** resume CT on the reliable flush (`tools/ct_start.sh`) + keep dnsfetch up, THEN do the B2 fix below in parallel.

## Why we're here

The committed flush (HEAD `20489cb`) uses `MergeSubjectDBsScratch` — an SSD-scratch FULL REBUILD of each touched archive month per pool flush. It's reliable (never hangs/corrupts) but O(archive month) per flush, so during heavy multi-log backfill it bleeds SSD to critical (~30 G→19 G in 13 min via giant-month scratch spikes) within ~1 h every run and leaves un-drainable pools. Unsustainable → the burst+drain cycle. **B2 is the real fix.**

## B2: status and the fix to make

**Shelved in `git stash@{0}`** ("B2 SSD-dedup flush — shelved 2026-06-05 …"). Files: `internal/db/dedup.go`, `internal/db/rawscan.go`, the `FlushAll` wiring + dedup DSN/Close in `internal/db/db.go`, and `TestFlushMonthDeduped` in `internal/db/multilog_test.go`.

**What already works in the stash:**
- The cross-connection-WAL-write DEADLOCK is FIXED via *phase separation*: the dedup set is written ONLY on its own connection (`FlushMonthDeduped` step 3); the archive connection ATTACHes the dedup set READ-ONLY for the pre-filter. Dedup DSN is WAL (fast seed) + `Close()` does `wal_checkpoint(TRUNCATE)` so the read-only ATTACH sees a clean file.
- The lazy seed reads cert_hashes via a SEQUENTIAL raw page scan (`scanArchiveCertHashes` in `rawscan.go`) — fast (~138 MB/s) even on fragmented archives, vs the ~10 MB/s random index scan. cert_hash is column 17.

**The REMAINING problem to fix = slow append on high-new-data months.** B2's `FlushMonthDeduped` pre-filters via the SSD set then `INSERT OR IGNORE`s new rows into the archive, which MAINTAINS all 6 HDD indexes per new row (random HDD I/O). For a month that got multi-GB of new data in an hour, that append is slow (this is the "Fork A" cost). It's O(new rows), better than the rebuild's O(archive), but heavy backfill still generates too much random HDD I/O.

**The fix to implement (write/read index split, §6b of FLUSH_AND_SHUTDOWN_PLAN):**
- Live append: pre-filter via the SSD dedup set, then APPEND new rows to the archive table with **NO indexes maintained** (sequential HDD write → fast). Dedup authority is the SSD set (no in-archive unique index during ingest).
- Crash-safety without a unique-index backstop: accept rare duplicate rows on a retry (append-then-record ordering) and remove them in the periodic rebuild. (§6c option 3: defer dedup, compact later.)
- Periodically (e.g., on a schedule or at month "seal", NOT every flush): rebuild the archive month = sort + dedup-compact + build the query indexes (reuse `MergeSubjectDBsScratch`-style rebuild on SSD scratch). This is O(archive) but INFREQUENT.
- Net: frequent appends stay O(new rows) sequential (keeps pace); infrequent rebuilds compact+index.

## B2 fix → test → deploy plan

1. `git stash apply stash@{0}` (keep the stash; don't pop) to restore B2 into the working tree alongside the kept `r2_backup.sh`/`run_dnsfetch.sh` changes. Consider doing the work on a branch so `main`/reliable binaries stay buildable.
2. Implement the index-split in `dedup.go`/`db.go`: append-only path (no per-row index maintenance) + a separate rebuild/compaction entry point + wire the periodic trigger (e.g., in `multilog.go` rollover, every N rollovers, run a compaction; or a flag/threshold).
3. **Test hard before deploying to the live archive:**
   - Unit tests (small data) — but they did NOT catch the earlier deadlock/perf, so also:
   - Realistic giant-data test against a COPY of an archive month (NOT the live archive) + a pool month: time the append (must be fast, O(new rows), sequential), verify dedup correctness + idempotency, verify a rebuild compacts dups + builds indexes, and stress the original deadlock path (concurrent/repeated flushes of the same month).
   - Verify no hot-journal / lock wedge (the failure mode that corrupted 2025-02).
4. Deploy: build B2 binaries, swap the server (`ct_stop.sh` then `ct_start.sh`), watch the first few rollovers' flushes complete fast and keep pace.
5. If B2 wedges/corrupts again after multiple genuine attempts → revert to reliable (`git checkout` db.go/multilog_test.go + remove dedup.go/rawscan.go), resume on reliable, fall back to burst+drain, and tell the user it needs deeper work.

## Key facts / safety

- **archive 2025-02 was REPAIRED** (B2's interrupted appends left a 1.2 GB hot journal neither SQLite engine could apply; file was dd-readable). Recovered via `sqlite3 .recover` (14.9 M rows, quick_check ok). Corrupt original preserved at `CT/2025-02/subjects.db.corrupt`, journal at `CT/2025-02/subjects.db-journal.quarantine` — keep until confident, then user can delete.
- **Full R2 backup DONE** 2026-06-05: 180 objects, 0 errors — `ct/<YYYY-MM>/subjects.db` ×152 + `ct/issuers.db` + `ct/progress.db` + `dns/<tld>/*.db`. Bucket `ct-index`, aws profile `r2`. Script: `tools/r2_backup.sh` (updated for YYYY-MM + DNS; `DRY_RUN=1`, `ONLY=ct|dns`). Pending pools intentionally NOT backed up.
- Binaries currently in `bin/` are the RELIABLE (pre-B2) flush. issuers.db/progress.db live on the SSD at `data/active/`.
- Resume CT: `tools/ct_start.sh` (server→wait :50051→client; refuses client if SSD<35 G). Resume dnsfetch: `caffeinate -i bash tools/run_dnsfetch.sh` (has proto-domain self-heal watchdog). Safe stop: `tools/ct_stop.sh`.
- HARD CONSTRAINTS (from the hourly monitor): never run `cmd/oneoff-merge`/old `cmd/merge-pools`/manual merges; never tune QPS/batch/workers; never delete pool month dirs or `-wal/-journal/-shm` sidecars or anything under `CT-legacy-backup`; never commit/push without explicit request; Geomys stays excluded; restart ct-client only when SSD comfortably >35 G.
- 3 orphaned pools are being drained now; once done the archive has all their data and SSD frees ~50 G.

## Uncommitted git state

`git status`: modified `tools/r2_backup.sh` + `tools/run_dnsfetch.sh` (both KEEP — proven). B2 in `stash@{0}`. The 7 commits 49afaa5..20489cb are the deps tidy + flush fix + tools + cleanup + docs reorg. Not pushed. (This handoff doc itself is a new untracked file.)
