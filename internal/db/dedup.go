package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DedupStore is a per-archive-month set of cert_hashes that live on the SSD,
// used to pre-filter dedup HITS out of an incremental flush before they reach
// the HDD archive's unique-index probe (see docs/FLUSH_AND_SHUTDOWN_PLAN.md B2).
//
// It is a rebuildable performance cache, NOT the source of truth: the archive
// month keeps its cert_hash unique index as the correctness backstop, so a
// missing/stale/corrupt DedupStore only costs extra HDD probes — never
// duplicate or lost rows. Because of that it runs with aggressive pragmas and
// can always be rebuilt from the archive via PopulateFromArchive.
type DedupStore struct {
	db   *sql.DB
	path string
}

// dedupDSN keeps the set hot in RAM (per-month it is ~32 B * rows; a giant
// month is ~1-2 GB, well within the cache) and durability-light since it is
// rebuildable. WAL mode is essential for seed speed — the seed does tens of
// millions of random WITHOUT-ROWID PK inserts, which a rollback (DELETE) journal
// makes ~5-10x slower. The deadlock that WAL originally caused was a
// cross-connection WRITE to the attached set; FlushMonthDeduped no longer does
// that (it writes the set only on its own connection), and Close checkpoints the
// WAL so the archive connection ATTACHes a clean, WAL-empty file for the
// read-only pre-filter.
func dedupDSN(path string) string {
	return "file:" + path +
		"?_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(OFF)" +
		"&_pragma=busy_timeout(10000)" +
		"&_pragma=cache_size(-2097152)" + // 2 GiB
		"&_pragma=temp_store(MEMORY)" +
		"&_pragma=mmap_size(4294967296)" // 4 GiB
}

// OpenDedupStore opens (creating if needed) the SSD dedup set at path.
func OpenDedupStore(path string) (*DedupStore, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("mkdir dedup dir: %w", err)
	}
	d, err := sql.Open("sqlite", dedupDSN(path))
	if err != nil {
		return nil, fmt.Errorf("open dedup store: %w", err)
	}
	d.SetMaxOpenConns(1)
	if _, err := d.Exec(`CREATE TABLE IF NOT EXISTS seen (cert_hash BLOB PRIMARY KEY) WITHOUT ROWID`); err != nil {
		d.Close()
		return nil, fmt.Errorf("create seen table: %w", err)
	}
	return &DedupStore{db: d, path: path}, nil
}

// Count returns how many cert_hashes are recorded.
func (s *DedupStore) Count() (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT COUNT(*) FROM seen`).Scan(&n)
	return n, err
}

// PopulateFromArchive seeds the set with every cert_hash already present in the
// archive month at archivePath. Idempotent (INSERT OR IGNORE). This is the
// one-time lazy migration run the first time a month is flushed under B2, and
// the recovery path if the set is ever lost. Returns rows in the set afterward.
//
// It reads cert_hashes via a SEQUENTIAL raw page scan (scanArchiveCertHashes)
// rather than a SQL index scan: on a fragmented archive month the index scan
// degrades to random HDD reads (~10 MB/s), while the linear file read stays
// fast. Rows that spill to overflow pages are skipped — lossless, since the
// archive's unique index backstops dedup at flush time.
func (s *DedupStore) PopulateFromArchive(archivePath string) (int64, error) {
	if _, err := os.Stat(archivePath); err != nil {
		return s.Count() // no archive yet — nothing to seed
	}
	checkpointWAL(archivePath) // fold any WAL into the main file before scanning

	const batchSize = 1_000_000
	batch := make([][]byte, 0, batchSize)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		stmt, err := tx.Prepare(`INSERT OR IGNORE INTO seen (cert_hash) VALUES (?)`)
		if err != nil {
			tx.Rollback() //nolint:errcheck
			return err
		}
		for _, ch := range batch {
			if _, err := stmt.Exec(ch); err != nil {
				stmt.Close()
				tx.Rollback() //nolint:errcheck
				return err
			}
		}
		stmt.Close()
		batch = batch[:0]
		return tx.Commit()
	}

	var flushErr error
	scanErr := scanArchiveCertHashes(archivePath, func(ch []byte) {
		batch = append(batch, ch) // ch is a fresh copy from certHashFromCell
		if len(batch) >= batchSize && flushErr == nil {
			flushErr = flush()
		}
	})
	if scanErr != nil {
		return 0, fmt.Errorf("raw-scan archive for dedup seed: %w", scanErr)
	}
	if flushErr != nil {
		return 0, fmt.Errorf("seed dedup from archive: %w", flushErr)
	}
	if err := flush(); err != nil {
		return 0, fmt.Errorf("seed dedup from archive: %w", err)
	}
	return s.Count()
}

// Close checkpoints the WAL into the main file (so a later read-only ATTACH from
// the archive connection sees a clean, WAL-empty database — no -shm writer
// coordination) and closes the connection.
func (s *DedupStore) Close() error {
	s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`) //nolint:errcheck
	return s.db.Close()
}

// dedupPathFor returns the SSD dedup-set path for a month under dedupDir.
func dedupPathFor(dedupDir, month string) string {
	return filepath.Join(dedupDir, month+".db")
}

// appendBatchRows bounds how many source rows each append transaction covers.
// A finite batch keeps every rollback journal small, so an interrupted flush can
// always be cleanly rolled back and retried — the giant single-transaction
// append is what left the 1.2 GB un-appliable hot journal that corrupted the
// 2025-02 archive. It is a var only so tests can shrink it to force multiple
// batches over tiny inputs; production never changes it.
var appendBatchRows int64 = 250_000

// certHashUniqueStmt rebuilds the partial-unique cert_hash index.
const certHashUniqueStmt = `CREATE UNIQUE INDEX IF NOT EXISTS idx_subjects_cert_hash ON subjects(cert_hash) WHERE cert_hash IS NOT NULL`

// appendDedupedNewRows appends the new rows from the active month into the
// EXISTING archive month, skipping cert_hashes already in the SSD dedup set.
//
// The dominant cost on a giant (>RAM) archive month is the hash-scattered
// cert_hash index: maintaining it per-row means random HDD probes into a >RAM
// B-tree — the ~1 MB/s spinning-disk wall, and even DROPping or rebuilding it is
// O(month). So this DROPS the cert_hash and read-path query indexes and leaves
// them dropped, appending the new rows as a pure sequential table write. It does
// NOT rebuild any index — that O(month) work is deferred to SealMonth, which
// runs rarely (a caught-up month / end of a bulk drain), not on every rollover.
// In steady state the indexes are already absent, so the DROPs are cheap no-ops
// and only the very first flush of a pre-existing month pays the one-time
// O(month) cost of dropping its old cert_hash index. The tile_entry unique index
// is KEPT: it is empty (all-NULL keys) for multi-log rows and is the only dedup
// for legacy cert_hash-NULL rows, which the SSD set doesn't track.
//
// Dedup authority is the SSD set's NOT EXISTS pre-filter; with no cert_hash
// unique index during append, a hash the set missed (a raw-scan overflow miss on
// the initial seed, or a crashed-then-retried append) can land a transient
// duplicate row. That is by design (§6c): SealMonth compacts duplicates when it
// rebuilds the unique index, so the worst case is extra rows until the next seal,
// never lost rows.
//
// Crash-safety: appends commit in bounded batches (small rollback journals — the
// giant single transaction is what left the un-appliable 1.2 GB hot journal that
// corrupted 2025-02). The caller records the SSD set only AFTER this returns, so
// an interrupted flush is retried from the source.
func appendDedupedNewRows(ctx context.Context, activePath, archivePath, dedupPath string) error {
	arch, err := sql.Open("sqlite", "file:"+archivePath+"?_pragma=busy_timeout(60000)")
	if err != nil {
		return fmt.Errorf("open archive for deduped flush: %w", err)
	}
	defer arch.Close()
	arch.SetMaxOpenConns(1)

	// One pinned connection for the whole flush: the ATTACHes and the batched
	// BEGIN/COMMIT statements must all run on the same underlying connection.
	conn, err := arch.Conn(ctx)
	if err != nil {
		return fmt.Errorf("pin archive conn: %w", err)
	}
	defer conn.Close()

	// The append maintains no large random index, so a modest cache suffices.
	// temp_store=FILE makes the index-rebuild sorts spill to the OS temp dir (the
	// SSD), so even the biggest month can't OOM. The default rollback journal is
	// KEPT (not disabled) so each bounded batch stays crash-safe.
	for _, pragma := range []string{
		`PRAGMA synchronous=OFF`,
		`PRAGMA cache_size=-1048576`, // 1 GiB
		`PRAGMA temp_store=FILE`,
	} {
		if _, err := conn.ExecContext(ctx, pragma); err != nil {
			return fmt.Errorf("archive pragma %q: %w", pragma, err)
		}
	}
	if _, err := conn.ExecContext(ctx, `ATTACH ? AS src`, activePath); err != nil {
		return fmt.Errorf("attach active: %w", err)
	}
	if _, err := conn.ExecContext(ctx, `ATTACH ? AS dd`, dedupPath); err != nil {
		return fmt.Errorf("attach dedup: %w", err)
	}

	// Is there anything new to append? If not, leave the archive and ALL its
	// indexes completely untouched — this keeps a repeated rollover or a
	// multi-pool drain of an already-flushed month near-free (no pointless
	// O(month) index rebuild).
	newFilter := `a.cert_hash IS NULL
		       OR NOT EXISTS (SELECT 1 FROM dd.seen d WHERE d.cert_hash = a.cert_hash)`
	var hasNew int
	if err := conn.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM src.subjects a WHERE `+newFilter+`)`).Scan(&hasNew); err != nil {
		return fmt.Errorf("probe for new rows: %w", err)
	}
	if hasNew == 0 {
		return nil
	}

	var lo, hi sql.NullInt64
	if err := conn.QueryRowContext(ctx,
		`SELECT MIN(rowid), MAX(rowid) FROM src.subjects`).Scan(&lo, &hi); err != nil {
		return fmt.Errorf("scan src rowid range: %w", err)
	}
	if !lo.Valid { // active month is empty — nothing to append
		return nil
	}

	// Drop the cert_hash + query indexes so the append is a pure sequential write.
	dropIdx := append([]string{"idx_subjects_cert_hash"}, queryIndexNames...)
	for _, name := range dropIdx {
		if _, err := conn.ExecContext(ctx, `DROP INDEX IF EXISTS `+name); err != nil {
			return fmt.Errorf("drop index %s: %w", name, err)
		}
	}

	// Sequential batched append, pre-filtered by the SSD set. OR IGNORE still
	// dedups legacy rows via the kept tile_entry index.
	insert := `INSERT OR IGNORE INTO subjects (` + subjectCols + `)
		SELECT ` + subjectCols + ` FROM src.subjects a
		WHERE a.rowid BETWEEN ? AND ? AND (` + newFilter + `)`
	for start := lo.Int64; start <= hi.Int64; start += appendBatchRows {
		end := start + appendBatchRows - 1
		if _, err := conn.ExecContext(ctx, `BEGIN`); err != nil {
			return fmt.Errorf("begin append batch [%d,%d]: %w", start, end, err)
		}
		if _, err := conn.ExecContext(ctx, insert, start, end); err != nil {
			conn.ExecContext(ctx, `ROLLBACK`) //nolint:errcheck
			return fmt.Errorf("deduped append batch [%d,%d]: %w", start, end, err)
		}
		if _, err := conn.ExecContext(ctx, `COMMIT`); err != nil {
			return fmt.Errorf("commit append batch [%d,%d]: %w", start, end, err)
		}
	}

	// No index rebuild here — that is the whole point of the append-only path.
	// The cert_hash unique index and the read-path query indexes stay DROPPED,
	// so every subsequent flush of this month is a pure sequential append (the
	// DROPs above are then cheap no-ops). Dedup correctness is carried by the SSD
	// set; any duplicate that slipped past it is compacted by SealMonth, which
	// also rebuilds the query indexes — both O(month), both deferred to seal time.
	return nil
}

// rebuildUniqueCertHash rebuilds the partial-unique cert_hash index by sort.
// Normally the SSD-set pre-filter means there are no duplicates and this is a
// single CREATE INDEX. If the set missed a hash (raw-scan overflow rows) or a
// crashed retry re-appended rows, duplicates can exist and the unique build
// fails — so it compacts them (keeping the lowest rowid per hash, via a
// temporary non-unique index to make the GROUP BY cheap) and retries.
func rebuildUniqueCertHash(ctx context.Context, conn *sql.Conn) error {
	_, err := conn.ExecContext(ctx, certHashUniqueStmt)
	if err == nil {
		return nil
	}
	if !strings.Contains(err.Error(), "UNIQUE constraint") {
		return fmt.Errorf("build cert_hash index: %w", err)
	}
	if _, err := conn.ExecContext(ctx,
		`CREATE INDEX IF NOT EXISTS tmp_cert_hash ON subjects(cert_hash) WHERE cert_hash IS NOT NULL`); err != nil {
		return fmt.Errorf("build temp index for cert_hash compaction: %w", err)
	}
	// Delete every cert_hash row that has a lower-rowid twin — i.e. keep the
	// earliest of each duplicate set. The correlated EXISTS resolves via the temp
	// index (a point lookup per row), so this is a single index-assisted pass, not
	// the O(n) GROUP-BY/NOT-IN materialisation.
	if _, err := conn.ExecContext(ctx, `DELETE FROM subjects WHERE cert_hash IS NOT NULL AND EXISTS (
		SELECT 1 FROM subjects b WHERE b.cert_hash = subjects.cert_hash AND b.rowid < subjects.rowid)`); err != nil {
		return fmt.Errorf("compact duplicate cert_hash rows: %w", err)
	}
	if _, err := conn.ExecContext(ctx, `DROP INDEX tmp_cert_hash`); err != nil {
		return fmt.Errorf("drop temp cert_hash index: %w", err)
	}
	if _, err := conn.ExecContext(ctx, certHashUniqueStmt); err != nil {
		return fmt.Errorf("rebuild cert_hash index after compaction: %w", err)
	}
	return nil
}

// FlushMonthDeduped appends the new rows from the active month at activePath
// into the EXISTING archive month at archivePath, using the SSD dedup set at
// dedupPath to pre-filter out the rows already in the archive (the cross-log
// dedup HITS) before they reach the archive's HDD append. This turns the flush
// from O(archive month) into O(new rows). scratchDir (the SSD) is used for the
// one-time migration rebuild of a still-indexed month; "" builds adjacent.
//
// Correctness: the SSD dedup set is the dedup authority. Any hash it missed (a
// raw-scan overflow miss on the initial seed, or a crashed-then-retried append)
// can land a transient duplicate row, which SealMonth compacts when it rebuilds
// the unique index — never a lost row. The set is recorded AFTER the append, so a
// crash leaves the archive a superset of the set and a retry is idempotent.
//
// The archive month must already exist (FlushAll handles new partitions).
func FlushMonthDeduped(activePath, archivePath, dedupPath, scratchDir string) error {
	// 1. Ensure the dedup set exists and is seeded from the archive (one-time
	//    lazy migration; also the rebuild path if the set was lost). Close it so
	//    the archive connection below can ATTACH and write it without contention.
	ds, err := OpenDedupStore(dedupPath)
	if err != nil {
		return err
	}
	n, err := ds.Count()
	if err != nil {
		ds.Close()
		return err
	}
	if n == 0 {
		if _, err := ds.PopulateFromArchive(archivePath); err != nil {
			ds.Close()
			return err
		}
	}
	if err := ds.Close(); err != nil {
		return err
	}

	// 1b. First touch of a pre-existing, fully-indexed month: migrate it to the
	//     index-free append-only heap via a sequential scratch rebuild, rather
	//     than letting appendDedupedNewRows DROP the giant cert_hash index in
	//     place (the ~37 min random-HDD wall). Idempotent: once migrated the index
	//     is gone, so subsequent flushes skip straight to the fast append.
	hasIdx, err := hasCertHashIndex(archivePath)
	if err != nil {
		return err
	}
	if hasIdx {
		if err := migrateMonthToAppendOnly(archivePath, scratchDir); err != nil {
			return fmt.Errorf("migrate %s to append-only: %w", archivePath, err)
		}
	}

	// 2. Append the new rows into the archive, in bounded batches. The dedup set
	//    is ATTACHed READ-ONLY purely for the NOT EXISTS pre-filter — the archive
	//    connection never WRITES the attached dedup (that cross-connection write
	//    is what deadlocked). The only write is into the archive's own subjects
	//    table.
	if err := appendDedupedNewRows(context.Background(), activePath, archivePath, dedupPath); err != nil {
		return err
	}

	// 3. Record this month's hashes as seen — on the dedup set's OWN connection
	//    (never cross-connection), and AFTER the append for crash-safety: a crash
	//    here leaves the archive a superset of the set, so the retry's INSERT OR
	//    IGNORE append is a no-op and re-recording is idempotent.
	rec, err := OpenDedupStore(dedupPath)
	if err != nil {
		return err
	}
	defer rec.Close()
	if _, err := rec.db.Exec(`ATTACH ? AS src`, activePath); err != nil {
		return fmt.Errorf("attach active for seen record: %w", err)
	}
	defer rec.db.Exec(`DETACH src`) //nolint:errcheck
	if _, err := rec.db.Exec(`INSERT OR IGNORE INTO seen (cert_hash)
		SELECT cert_hash FROM src.subjects WHERE cert_hash IS NOT NULL`); err != nil {
		return fmt.Errorf("record seen: %w", err)
	}
	return nil
}

// hasCertHashIndex reports whether the archive month at archivePath still carries
// the cert_hash unique index — i.e. it has not yet been migrated to the
// index-free append-only heap.
func hasCertHashIndex(archivePath string) (bool, error) {
	d, err := sql.Open("sqlite", "file:"+archivePath+"?_pragma=busy_timeout(10000)")
	if err != nil {
		return false, fmt.Errorf("open archive for index check: %w", err)
	}
	defer d.Close()
	var name string
	err = d.QueryRow(
		`SELECT name FROM sqlite_master WHERE type='index' AND name='idx_subjects_cert_hash'`,
	).Scan(&name)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("query archive indexes: %w", err)
	}
	return true, nil
}

// migrateMonthToAppendOnly rebuilds the archive month at archivePath as the
// index-free append-only heap (only the tile_entry unique index), via a
// sequential scratch rebuild — see buildIndexFreeHeap. It exists so the first
// flush of a pre-existing, fully-indexed month does NOT pay the in-place DROP of
// the giant cert_hash index on the HDD (~37 min random-seek wall on an 11 GB
// month). scratchDir (the SSD) holds the rebuild; "" builds adjacent to the
// archive. The archive is atomically replaced only once the new heap is built.
func migrateMonthToAppendOnly(archivePath, scratchDir string) error {
	return scratchRebuildArchive(archivePath, scratchDir, "migrate", func(buildPath string) error {
		return buildIndexFreeHeap(archivePath, buildPath)
	})
}

// MigrateArchiveMonth converts a pre-existing archive month at archivePath to
// the append-only index-free heap (strips the cert_hash unique + read-path query
// indexes) via a sequential scratch rebuild in scratchDir (the SSD), so later
// FlushMonthDeduped appends are pure sequential writes with no per-flush index
// work. Idempotent: returns migrated=false (a no-op) if the month is already
// index-free.
//
// Intended for a one-time OFFLINE pass over every archive month BEFORE a heavy
// bootstrap, so the per-month migration cost (and its ~month-sized scratch spike)
// is paid once with full SSD headroom instead of stacking up against live
// ingestion. The caller MUST ensure no other process writes the archive
// (ct-server stopped): archiveFlushMu only serialises writers within one process.
func MigrateArchiveMonth(archivePath, scratchDir string) (migrated bool, err error) {
	archiveFlushMu.Lock()
	defer archiveFlushMu.Unlock()
	has, err := hasCertHashIndex(archivePath)
	if err != nil {
		return false, err
	}
	if !has {
		return false, nil
	}
	if err := migrateMonthToAppendOnly(archivePath, scratchDir); err != nil {
		return false, err
	}
	return true, nil
}

// SealMonth makes an archive month query-ready and duplicate-free after a series
// of append-only flushes (FlushMonthDeduped). The append path leaves the month
// as a heap with no cert_hash unique index and no read-path query indexes, and
// may hold a few transient duplicate rows (a dedup-set pre-filter miss, or a
// crashed-then-retried append). SealMonth:
//
//   - rebuilds the cert_hash partial-unique index, collapsing any duplicates;
//   - builds the four read-path query indexes.
//
// It is O(month) and therefore meant to run INFREQUENTLY — when a month is
// caught up, on a schedule, or once at the end of a bulk drain — never on every
// rollover (that O(month)-per-flush cost is exactly what the append path avoids).
//
// When scratchDir is non-empty the rebuild — including the random index-build
// work — happens in a fresh file there (the SSD) and the finished, compact month
// is copied sequentially back to the archive, so even a giant >RAM month never
// does the random index work on the HDD. When scratchDir is "" the compaction +
// index build run in place (fine for small months / tests).
func SealMonth(archivePath, scratchDir string) error {
	archiveFlushMu.Lock()
	defer archiveFlushMu.Unlock()
	if _, err := os.Stat(archivePath); err != nil {
		return fmt.Errorf("seal %s: %w", archivePath, err)
	}

	if scratchDir != "" {
		// Rebuild via an empty source: MergeSubjectDBsScratch re-inserts every
		// existing row through a fresh cert_hash unique index (INSERT OR IGNORE
		// collapses duplicates), builds the query indexes on the scratch
		// filesystem, and copies the finished month sequentially back.
		tmpDir, err := os.MkdirTemp(filepath.Dir(archivePath), ".seal-src-")
		if err != nil {
			return fmt.Errorf("seal scratch src dir: %w", err)
		}
		defer os.RemoveAll(tmpDir)
		emptySrc := filepath.Join(tmpDir, "subjects.db")
		es, err := OpenSubjectDB(emptySrc)
		if err != nil {
			return fmt.Errorf("seal empty src: %w", err)
		}
		es.CheckpointAndClose() //nolint:errcheck
		return MergeSubjectDBsScratch(emptySrc, archivePath, scratchDir)
	}

	// In-place: compact duplicate cert_hash rows + (re)build the unique index,
	// then build the read-path query indexes.
	ctx := context.Background()
	arch, err := sql.Open("sqlite", "file:"+archivePath+"?_pragma=busy_timeout(60000)")
	if err != nil {
		return fmt.Errorf("open archive for seal: %w", err)
	}
	defer arch.Close()
	arch.SetMaxOpenConns(1)
	conn, err := arch.Conn(ctx)
	if err != nil {
		return fmt.Errorf("pin archive conn: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `PRAGMA synchronous=OFF`); err != nil {
		return err
	}
	if err := rebuildUniqueCertHash(ctx, conn); err != nil {
		return err
	}
	for _, stmt := range queryIndexStmts {
		if _, err := conn.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("seal build query index: %w", err)
		}
	}
	return nil
}
