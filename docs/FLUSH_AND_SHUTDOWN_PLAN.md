# CT ingestion — clean-shutdown & flush-bottleneck fix plan

Status: design note. Written 2026-06-03 during a live flush, grounded in the
incident below. Companion to the new `tools/ct_start.sh` / `tools/ct_stop.sh`.

## What we observed (2026-06-03)

A routine SSD-pressure restart exposed three coupled problems:

1. **No graceful shutdown.** `cmd/server/main.go` installs no signal handler.
   SIGTERM hard-kills the process *without* flushing the live pool — losing every
   un-archived subject in it and corrupting any half-written
   `subjects.db.new.<pid>`. (This is the mechanism that lost the 2024-12 archive.)
2. **Client-disconnect doesn't promptly stop the server.** Killing `ct-client`
   ends the IngestAll RPC, but the server's workers kept running for minutes
   (stuck in tile-fetch 429 retries, not re-checking `ctx`), so the deferred
   flush didn't start right away and the live pool kept growing.
3. **The flush is glacial and the pool grows unbounded between flushes.**
   Merging a pool month into its HDD archive runs at **~1 MB/s** on giant months.
   Root cause is the §6c diagnosis: the `cert_hash` unique index is a hash, so
   every dedup probe is a random read into a 10–18 GB archive month that does not
   fit in 16 GB RAM. Because CT logs overlap heavily, most probes are dedup
   *hits* — we pay a random HDD read to learn there's nothing to write. Worse,
   the rollover coordinator runs `FlushAll` **inline** (`multilog.go:204`), so the
   hourly rollover ticker is blocked for the multi-hour flush duration → the live
   pool accumulates ~50–64 GB between rollovers (we saw 11 h gaps).
4. **Lazy fd retention (minor).** After a pool is flushed it is never `Close()`d;
   its SQLite fds stay open until process exit, so the SSD space frees only
   lazily (we watched 50 GB linger for hours).

## Part A — Clean start/stop

### A1. Operational scripts (done)
`tools/ct_start.sh`, `tools/ct_stop.sh`, `tools/dns_stop.sh`,
`tools/services_status.sh`. The important one is **`ct_stop.sh`**: it stops the
client, then *waits* until no `subjects.db.new.<server-pid>` file remains (the
flush is fully drained) before stopping the server, and refuses to kill a server
that is still flushing (override with `FORCE=1`, accepting the loss). `ct_start.sh`
starts server→client in order and refuses to start the client when SSD < 35 GB.

These make shutdown *safe* today, but they paper over the code gaps below.

### A2. Code fix — real graceful shutdown (recommended next, small)
In `cmd/server/main.go`: `signal.Notify` on SIGINT/SIGTERM; on signal call
`grpc.Server.GracefulStop()` and cancel a root context handed to `ingestion.Service`
so the in-flight `IngestAll` sees `ctx.Done()`, drains workers, runs its deferred
`FlushAll`, and *then* the process exits. Pair with:

- **Make workers honor `ctx` between fetch retries.** The tile-fetch retry/backoff
  loop must check `ctx.Err()` each attempt so a 429-stuck worker exits in seconds,
  not minutes (problem #2).
- **`Close()` pools after flush** (problem #4) so SSD frees immediately, not at
  process exit. Both the rollover path and the exit path.

With A2, `ct_stop.sh` collapses to "SIGTERM the server and wait" — the wait-for-
`.new` dance becomes a backstop rather than the mechanism.

## Part B — Flush throughput

Targets problem #3. Options from `proto-domain/docs/query-patterns.md §6c`,
evaluated against what actually bites here (the merge probes the **archive**
`cert_hash` index on the HDD; live-ingestion dedup is already on the SSD pool and
is fine):

| | Option | Effect on the flush | Risk / cost |
|--|--------|--------------------|-------------|
| **B1** | Bloom filter on `cert_hash` in RAM (~1 GB / 772 M certs) | Fast-paths only *definitely-new* rows (a direct insert). Under heavy overlap most rows are *hits*, where Bloom says "probably present" and we must still confirm against the index — so it saves little on the hit-dominated **merge** path. Skipping on "probably present" instead would drop ~1% genuinely-new certs (no true backstop once you skip). | Probabilistic; best as a live-ingestion pre-filter, **not** the flush fix. |
| **B2** | `cert_hash` dedup index on **SSD**, bulk rows on HDD | Converts the merge's per-row existence check from random-HDD to random-SSD (cheap); new rows append to HDD sequentially. Directly kills the ~1 MB/s wall, **no data-loss risk.** | Schema split: dedup index separated from data. SSD cost ≈ the cert_hash index size (the 10–18 GB month *data* files are ~1/3 index → a global SSD dedup DB is plausibly tens of GB; measure). |
| **B3** | Defer dedup, sort at seal | Append pool rows to the archive with no probe (sequential HDD), dedup once per partition via external sort at seal time. | Transient duplicate storage (large under heavy overlap); needs a "seal" lifecycle. Strong for one-shot bootstrap, awkward for steady appends. |

**Independently — and highest leverage for the SSD-pressure symptom — decouple
rollover from flush:** run `FlushAll` in a background goroutine (the code already
flags "the background variant can come later", `multilog.go:204`) with at most one
flush in flight. Then rollover stays ~hourly regardless of flush speed, the live
pool is bounded to ~1 h of data instead of 50–64 GB, and SSD pressure stops being
a function of flush throughput. This alone would have prevented today's incident.

### Recommended sequencing
1. **A2** graceful shutdown + ctx-honoring workers + pool `Close()` — small, removes the operational footgun and the lazy-fd leak.
2. **Background flush** (decouple rollover from flush, single-flight) — bounds SSD growth; the biggest reliability win for the least schema change.
3. **B2** SSD `cert_hash` dedup index — the durable throughput fix; benchmark merge MB/s on a giant month (e.g. 2026-02→18 GB) before/after.
4. **B1** Bloom as a live-ingestion pre-filter on top of B2, if profiling shows the live path needs it.
5. Revisit **B3** only if still HDD-bound during the remaining bootstrap.

> Write-path discipline (from §6b): none of this adds secondary indexes to the
> ingestion tables. Ingestion carries only what dedup requires; reverse/analytic
> indexes (R1–R4) stay separate, rebuildable, sequential-sort projections.

## Implementation status (2026-06-04)

Implemented (steps 1–3 of the sequencing), built + unit-tested, **not yet deployed
or re-merged**:

- **A2 graceful shutdown** — `cmd/server/main.go` installs a SIGINT/SIGTERM
  handler (`signal.NotifyContext`) and `GracefulStop`s; `ingestion.Service` gains
  `SetShutdownContext` + `mergeContext`, folding the shutdown signal into each
  `IngestAll` worker context so a TERM drains workers and runs the deferred final
  flush. (Workers already honored `ctx` in the fetch-retry loop — the gap was only
  that nothing cancelled them on shutdown.) A second signal still hard-kills
  (escape hatch); `tools/ct_stop.sh` remains the patient path.
- **Background flush** — `internal/ingestion/multilog.go`: a single background
  flush worker drains a bounded (`flushQueueDepth=4`) channel of swapped-out
  pools. The rollover coordinator now *enqueues* the old pool instead of running
  `FlushAll` inline, so the hourly ticker never stalls on a multi-hour merge and
  the live pool stays ~1 h of data. Teardown stops the coordinator, flushes the
  live pool, and drains the worker.
- **B2 dedup-on-SSD (as a scratch build)** — `internal/db/db.go`:
  `MergeSubjectDBsScratch(src, dst, scratchDir)` builds the merged month + query
  indexes in `scratchDir` (the SSD pool dir), where the `cert_hash` random-probe
  I/O is cheap, then copies the finished month sequentially to the HDD and renames
  atomically. `FlushAll`'s rebuild path uses it; the new-partition path now builds
  query indexes on the SSD active file before copying. Falls back to HDD-adjacent
  build if no scratch dir. Covered by
  `TestMergeSubjectDBsScratch_DedupAndScratchHygiene`.

Deferred / next: re-merge the preserved `data/active` pools with the fixed binary
(idempotent), then `tools/ct_start.sh`. B1 (Bloom pre-filter) and B3 (sort-at-seal)
remain unbuilt — revisit only if profiling the new path still shows a wall.
