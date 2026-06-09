package db

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// makeSubjectsDB creates a checkpointed subjects.db at path holding one row per
// cert tag (cert_hash = sha256(tag), unique-dedup key).
func makeSubjectsDB(t *testing.T, path string, tags ...string) {
	t.Helper()
	sdb, err := OpenSubjectDB(path)
	if err != nil {
		t.Fatalf("OpenSubjectDB %s: %v", path, err)
	}
	var batch []Subject
	for i, tag := range tags {
		h := sha256.Sum256([]byte(tag))
		lg := sha256.Sum256([]byte("log"))
		batch = append(batch, Subject{
			CAID: 1, SerialNumber: tag, CommonName: tag + ".example.com",
			NotBefore: "2026-05-01", NotAfter: "2026-08-01", EntryType: "x509",
			CertHash: h[:], LogID: lg[:], SANCount: i,
		})
	}
	if err := sdb.InsertSubjectBatch(batch); err != nil {
		t.Fatalf("InsertSubjectBatch %s: %v", path, err)
	}
	if err := sdb.CheckpointAndClose(); err != nil {
		t.Fatalf("CheckpointAndClose %s: %v", path, err)
	}
}

// openRaw opens the subjects db at path WITHOUT OpenSubjectDB's schema/index
// creation side effects (which would try to rebuild the cert_hash index on a
// migrated, index-free archive — a slow no-op-or-fail on a giant HDD month).
func openRaw(t *testing.T, path string) *sql.DB {
	t.Helper()
	d, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(10000)")
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	return d
}

// hasIndex reports whether a named index exists on the subjects db at path.
func hasIndex(t *testing.T, path, name string) bool {
	t.Helper()
	d := openRaw(t, path)
	defer d.Close()
	var n int
	if err := d.QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?`, name,
	).Scan(&n); err != nil {
		t.Fatalf("index check %s: %v", path, err)
	}
	return n == 1
}

// dupCertHashes returns how many cert_hash values appear on more than one row.
func dupCertHashes(t *testing.T, path string) int {
	t.Helper()
	d := openRaw(t, path)
	defer d.Close()
	var n int
	if err := d.QueryRow(`SELECT COUNT(*) FROM (
		SELECT cert_hash FROM subjects WHERE cert_hash IS NOT NULL
		GROUP BY cert_hash HAVING COUNT(*) > 1)`).Scan(&n); err != nil {
		t.Fatalf("dup count %s: %v", path, err)
	}
	return n
}

func subjectsCount(t *testing.T, path string) int {
	t.Helper()
	d := openRaw(t, path)
	defer d.Close()
	var n int
	if err := d.QueryRow(`SELECT COUNT(*) FROM subjects`).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", path, err)
	}
	return n
}

// TestMergeSubjectDBsScratch_DedupAndScratchHygiene merges a pool month that
// overlaps the archive, building via a separate scratch dir (the SSD path), and
// checks: dedup across existing+src, query indexes present, and no scratch/.new
// leftovers.
func TestMergeSubjectDBsScratch_DedupAndScratchHygiene(t *testing.T) {
	root := t.TempDir()
	archiveDir := filepath.Join(root, "archive", "2026-05")
	if err := os.MkdirAll(archiveDir, 0o755); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(archiveDir, "subjects.db")
	scratchDir := filepath.Join(root, "scratch") // stands in for the SSD pool dir

	// Existing archive holds A, B; incoming pool holds B (dup), C, D (new).
	makeSubjectsDB(t, archivePath, "A", "B")
	srcPath := filepath.Join(root, "pool", "subjects.db")
	if err := os.MkdirAll(filepath.Dir(srcPath), 0o755); err != nil {
		t.Fatal(err)
	}
	makeSubjectsDB(t, srcPath, "B", "C", "D")

	if err := MergeSubjectDBsScratch(srcPath, archivePath, scratchDir); err != nil {
		t.Fatalf("MergeSubjectDBsScratch: %v", err)
	}

	// Hygiene (checked before any reopen, which would create its own -wal/-shm):
	// no scratch leftovers and no .new/.merge build orphans next to the archive.
	if ents, _ := os.ReadDir(scratchDir); len(ents) != 0 {
		t.Errorf("scratch dir not cleaned: %v", ents)
	}
	archiveEnts, _ := os.ReadDir(archiveDir)
	for _, e := range archiveEnts {
		if n := e.Name(); strings.Contains(n, ".new.") || strings.Contains(n, ".merge.") {
			t.Errorf("build orphan left in archive dir: %s", n)
		}
	}

	// A, B, C, D — B collapsed, so 4 unique rows.
	if got := subjectsCount(t, archivePath); got != 4 {
		t.Errorf("expected 4 deduped rows, got %d", got)
	}

	// Query indexes must have been built (on the scratch file, carried across).
	sdb, err := OpenSubjectDB(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	defer sdb.Close()
	var idxCount int
	if err := sdb.db.QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_subjects_cn'`,
	).Scan(&idxCount); err != nil {
		t.Fatal(err)
	}
	if idxCount != 1 {
		t.Errorf("query index idx_subjects_cn missing after scratch merge")
	}
}

// TestFlushMonthDeduped checks the B2 incremental path: pre-filter the pool's
// rows against the SSD dedup set (lazily seeded from the existing archive),
// append only the new ones, and stay idempotent on re-run.
func TestFlushMonthDeduped(t *testing.T) {
	root := t.TempDir()
	archiveDir := filepath.Join(root, "archive", "2026-05")
	if err := os.MkdirAll(archiveDir, 0o755); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(archiveDir, "subjects.db")
	poolPath := filepath.Join(root, "pool", "subjects.db")
	if err := os.MkdirAll(filepath.Dir(poolPath), 0o755); err != nil {
		t.Fatal(err)
	}
	dedupPath := dedupPathFor(filepath.Join(root, "dedup"), "2026-05")

	makeSubjectsDB(t, archivePath, "A", "B")   // existing archive month
	makeSubjectsDB(t, poolPath, "B", "C", "D") // incoming pool: B is a dup

	if err := FlushMonthDeduped(poolPath, archivePath, dedupPath, ""); err != nil {
		t.Fatalf("FlushMonthDeduped: %v", err)
	}

	// Archive should now hold A,B,C,D — B collapsed (pre-filtered), not duplicated.
	if got := subjectsCount(t, archivePath); got != 4 {
		t.Errorf("archive rows = %d, want 4", got)
	}
	// Dedup set lazily seeded from archive (A,B) + recorded pool hashes (C,D) = 4.
	ds, err := OpenDedupStore(dedupPath)
	if err != nil {
		t.Fatal(err)
	}
	n, err := ds.Count()
	ds.Close()
	if err != nil {
		t.Fatal(err)
	}
	if n != 4 {
		t.Errorf("dedup set size = %d, want 4", n)
	}

	// Re-running the same flush must be a no-op (crash-safety / re-flush).
	if err := FlushMonthDeduped(poolPath, archivePath, dedupPath, ""); err != nil {
		t.Fatalf("re-run FlushMonthDeduped: %v", err)
	}
	if got := subjectsCount(t, archivePath); got != 4 {
		t.Errorf("after re-run archive rows = %d, want 4 (idempotent)", got)
	}
}

// TestFlushMonthDeduped_MultiBatchIdempotent forces the append to span several
// bounded transactions (appendBatchRows shrunk to 2) and checks that the
// batching is both correct (dedups across the batch boundary) and idempotent
// (a re-run — standing in for a crash-then-retry — adds no duplicate rows).
func TestFlushMonthDeduped_MultiBatchIdempotent(t *testing.T) {
	prev := appendBatchRows
	appendBatchRows = 2 // tiny batches: 7 pool rows -> 4 append transactions
	defer func() { appendBatchRows = prev }()

	root := t.TempDir()
	archiveDir := filepath.Join(root, "archive", "2026-05")
	if err := os.MkdirAll(archiveDir, 0o755); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(archiveDir, "subjects.db")
	poolPath := filepath.Join(root, "pool", "subjects.db")
	if err := os.MkdirAll(filepath.Dir(poolPath), 0o755); err != nil {
		t.Fatal(err)
	}
	dedupPath := dedupPathFor(filepath.Join(root, "dedup"), "2026-05")

	// Archive has A,B; pool has 7 rows that straddle batch boundaries, including
	// dups of the archive (A,B) and an internal dup (E appears twice).
	makeSubjectsDB(t, archivePath, "A", "B")
	makeSubjectsDB(t, poolPath, "B", "C", "D", "E", "E", "F", "A")

	if err := FlushMonthDeduped(poolPath, archivePath, dedupPath, ""); err != nil {
		t.Fatalf("FlushMonthDeduped: %v", err)
	}
	// Unique set across archive+pool = A,B,C,D,E,F = 6 (B,A pre-filtered against
	// the archive; the pool's own cert_hash index already collapsed the E,E dup at
	// creation, so the append spans batch boundaries without ever duplicating).
	if got := subjectsCount(t, archivePath); got != 6 {
		t.Fatalf("archive rows = %d, want 6 after multi-batch dedup", got)
	}
	// The append path leaves the read-path query indexes dropped — they come back
	// only at SealMonth, not per flush.
	if hasIndex(t, archivePath, "idx_subjects_cn") {
		t.Errorf("query index idx_subjects_cn present after append (should be deferred to seal)")
	}

	// Run twice more — emulates retrying after an interrupted flush. The pool's
	// hashes are now all recorded in the set, so each re-run pre-filters them all
	// out and appends nothing: the row count must not grow.
	for i := range 2 {
		if err := FlushMonthDeduped(poolPath, archivePath, dedupPath, ""); err != nil {
			t.Fatalf("re-run %d: %v", i, err)
		}
		if got := subjectsCount(t, archivePath); got != 6 {
			t.Fatalf("re-run %d archive rows = %d, want 6 (idempotent)", i, got)
		}
	}

	// Seal: rebuilds the cert_hash unique + read-path query indexes.
	if err := SealMonth(archivePath, ""); err != nil {
		t.Fatalf("SealMonth: %v", err)
	}
	if got := subjectsCount(t, archivePath); got != 6 {
		t.Fatalf("archive rows = %d, want 6 after seal", got)
	}
	if d := dupCertHashes(t, archivePath); d != 0 {
		t.Errorf("found %d duplicated cert_hashes after seal", d)
	}
	if !hasIndex(t, archivePath, "idx_subjects_cn") {
		t.Errorf("query index idx_subjects_cn missing after seal")
	}

	// quick_check the archive — a batched append + seal must never corrupt it.
	sdb, err := OpenSubjectDB(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	defer sdb.Close()
	var qc string
	if err := sdb.db.QueryRow(`PRAGMA quick_check`).Scan(&qc); err != nil {
		t.Fatal(err)
	}
	if qc != "ok" {
		t.Errorf("quick_check = %q, want ok", qc)
	}
}

// TestSealMonth_CompactsDuplicates forces a duplicate to slip past the SSD-set
// pre-filter (simulating a raw-scan overflow miss or a crashed retry) so the
// append-only flush leaves a transient duplicate row, then verifies SealMonth
// compacts it back to one and rebuilds the cert_hash unique index.
func TestSealMonth_CompactsDuplicates(t *testing.T) {
	appendBatchRows = 2
	defer func() { appendBatchRows = 250_000 }()

	root := t.TempDir()
	archiveDir := filepath.Join(root, "archive", "2026-05")
	if err := os.MkdirAll(archiveDir, 0o755); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(archiveDir, "subjects.db")
	poolPath := filepath.Join(root, "pool", "subjects.db")
	if err := os.MkdirAll(filepath.Dir(poolPath), 0o755); err != nil {
		t.Fatal(err)
	}
	dedupPath := dedupPathFor(filepath.Join(root, "dedup"), "2026-05")

	makeSubjectsDB(t, archivePath, "A", "B", "C", "D")
	makeSubjectsDB(t, poolPath, "C", "E") // C is a dup of the archive; E is new

	if err := FlushMonthDeduped(poolPath, archivePath, dedupPath, ""); err != nil {
		t.Fatalf("first flush: %v", err)
	}
	if got := subjectsCount(t, archivePath); got != 5 { // A,B,C,D,E
		t.Fatalf("after flush = %d, want 5", got)
	}

	// Sabotage the dedup set: delete C's hash so the pre-filter MISSES it on the
	// next flush and C is re-appended as a genuine duplicate row.
	hC := sha256.Sum256([]byte("C"))
	ds, err := OpenDedupStore(dedupPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ds.db.Exec(`DELETE FROM seen WHERE cert_hash = ?`, hC[:]); err != nil {
		t.Fatal(err)
	}
	if err := ds.Close(); err != nil {
		t.Fatal(err)
	}

	// Re-flush: C now slips past the pre-filter and is appended (no cert_hash
	// index during append), so the archive transiently holds two C rows. The
	// append does NOT compact — that is deferred to SealMonth.
	if err := FlushMonthDeduped(poolPath, archivePath, dedupPath, ""); err != nil {
		t.Fatalf("second flush (transient dup): %v", err)
	}
	if got := subjectsCount(t, archivePath); got != 6 {
		t.Fatalf("after re-flush = %d, want 6 (C transiently duplicated, not yet compacted)", got)
	}
	if d := dupCertHashes(t, archivePath); d != 1 {
		t.Fatalf("expected 1 duplicated cert_hash before seal, got %d", d)
	}

	// Seal compacts the duplicate C back to one row and rebuilds the indexes.
	if err := SealMonth(archivePath, ""); err != nil {
		t.Fatalf("SealMonth: %v", err)
	}
	if got := subjectsCount(t, archivePath); got != 5 {
		t.Fatalf("after seal = %d, want 5 (C must collapse)", got)
	}
	if d := dupCertHashes(t, archivePath); d != 0 {
		t.Errorf("found %d duplicated cert_hashes after seal", d)
	}
	if !hasIndex(t, archivePath, "idx_subjects_cert_hash") {
		t.Errorf("cert_hash unique index missing after seal")
	}
}

// TestFlushMonthDeduped_RealMonth exercises the flush against COPIES of a real
// archive month + pool month (never the live files). Skipped unless
// CT_REAL_ARCHIVE and CT_REAL_POOL point at real subjects.db files. It measures
// the seed+append wall time, the second (all-dup) flush time, the seal time, and
// verifies row counts, idempotency, and quick_check integrity on a giant >RAM
// month.
//
// For a production-faithful benchmark, put the big archive+pool COPIES on the
// HDD (where archives really live) and the seal scratch + dedup set on the SSD
// (as in prod):
//
//	CT_REAL_ARCHIVE=/Volumes/wd_office_2/datasets/CT/2025-12/subjects.db \
//	CT_REAL_POOL=data/active/20260604_174612/2025-12/subjects.db \
//	CT_REAL_WORKDIR=/Volumes/wd_office_2/tmp/ct-realtest \
//	CT_REAL_SCRATCH=/Users/benfultz/Dev/proto-ct/data/active \
//	go test ./internal/db -run RealMonth -v -timeout 120m
//
// Both env vars default to a t.TempDir() (SSD) when unset.
func TestFlushMonthDeduped_RealMonth(t *testing.T) {
	archiveSrc := os.Getenv("CT_REAL_ARCHIVE")
	poolSrc := os.Getenv("CT_REAL_POOL")
	if archiveSrc == "" || poolSrc == "" {
		t.Skip("set CT_REAL_ARCHIVE and CT_REAL_POOL to run the real-data flush test")
	}

	// workDir holds the big archive+pool copies (point at the HDD); scratch holds
	// the seal scratch rebuild + dedup set (point at the SSD).
	workBase := os.Getenv("CT_REAL_WORKDIR")
	if workBase == "" {
		workBase = t.TempDir()
	}
	scratch := os.Getenv("CT_REAL_SCRATCH")
	if scratch == "" {
		scratch = t.TempDir()
	}
	work := filepath.Join(workBase, fmt.Sprintf("realmonth-%d", time.Now().UnixNano()))
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(work) })

	archivePath := filepath.Join(work, "archive", "2099-12", "subjects.db")
	poolPath := filepath.Join(work, "pool", "subjects.db")
	dedupPath := dedupPathFor(filepath.Join(scratch, "dedup"), "2099-12")
	t.Cleanup(func() { os.RemoveAll(filepath.Join(scratch, "dedup")) })
	if err := os.MkdirAll(filepath.Dir(archivePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(poolPath), 0o755); err != nil {
		t.Fatal(err)
	}

	t.Logf("copying archive %s -> %s", archiveSrc, archivePath)
	if err := copySubjectDB(archiveSrc, archivePath); err != nil {
		t.Fatalf("copy archive: %v", err)
	}
	if err := copySubjectDB(poolSrc, poolPath); err != nil {
		t.Fatalf("copy pool: %v", err)
	}
	before := subjectsCount(t, archivePath)
	poolRows := subjectsCount(t, poolPath)
	t.Logf("archive rows before = %d, pool rows = %d", before, poolRows)

	start := time.Now()
	if err := FlushMonthDeduped(poolPath, archivePath, dedupPath, scratch); err != nil {
		t.Fatalf("FlushMonthDeduped (cold, seeds dedup): %v", err)
	}
	cold := time.Since(start)
	after := subjectsCount(t, archivePath)
	t.Logf("COLD flush (seed+append) took %s; archive rows %d -> %d (+%d new)", cold.Round(time.Second), before, after, after-before)
	if after < before {
		t.Fatalf("archive shrank: %d -> %d", before, after)
	}

	// Second flush: dedup set already seeded, every pool row is now a dup, so it
	// must add zero rows. This is the steady-state cost during repeated rollovers.
	start = time.Now()
	if err := FlushMonthDeduped(poolPath, archivePath, dedupPath, scratch); err != nil {
		t.Fatalf("FlushMonthDeduped (warm, all-dup): %v", err)
	}
	warm := time.Since(start)
	after2 := subjectsCount(t, archivePath)
	t.Logf("WARM re-flush (all dup) took %s; archive rows = %d", warm.Round(time.Second), after2)
	if after2 != after {
		t.Fatalf("re-flush not idempotent: %d -> %d", after, after2)
	}

	// Seal the giant month on the SSD scratch dir: compact any transient dups +
	// rebuild the indexes. This is the O(month) work that the append path defers;
	// time it separately.
	start = time.Now()
	if err := SealMonth(archivePath, scratch); err != nil {
		t.Fatalf("SealMonth: %v", err)
	}
	sealed := subjectsCount(t, archivePath)
	t.Logf("SEAL took %s; archive rows %d -> %d (compacted %d transient dup(s))",
		time.Since(start).Round(time.Second), after2, sealed, after2-sealed)
	// Seal may only shrink the table (removing transient duplicates the append
	// left behind); it must never lose unique rows or grow it.
	if sealed > after2 {
		t.Fatalf("seal grew the table: %d -> %d", after2, sealed)
	}

	dq := openRaw(t, archivePath)
	defer dq.Close()
	var qc string
	if err := dq.QueryRow(`PRAGMA quick_check`).Scan(&qc); err != nil {
		t.Fatal(err)
	}
	if qc != "ok" {
		t.Errorf("quick_check = %q, want ok", qc)
	}
	// After seal the cert_hash unique index is back and enforces (no dups), and
	// the read-path query indexes are rebuilt.
	if d := dupCertHashes(t, archivePath); d != 0 {
		t.Errorf("found %d duplicated cert_hashes after seal", d)
	}
	if !hasIndex(t, archivePath, "idx_subjects_cn") {
		t.Errorf("query index idx_subjects_cn missing after seal")
	}
}

func TestProgressDB_LogRunRoundTrip(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "progress.db")
	p, err := OpenProgressDB(tmp)
	if err != nil {
		t.Fatalf("OpenProgressDB: %v", err)
	}
	defer p.Close()

	id := sha256.Sum256([]byte("test-log-1"))
	init := LogRunInit{
		LogID:         id,
		Description:   "Test Log 1",
		SubmissionURL: "https://example.com/",
		Protocol:      "static-ct-api",
		Operator:      "TestOp",
		State:         "usable",
	}
	run, err := p.GetOrCreateLogRun(init)
	if err != nil {
		t.Fatalf("GetOrCreateLogRun: %v", err)
	}
	if run.LogID != id {
		t.Errorf("LogID mismatch: got %x want %x", run.LogID, id)
	}
	if run.NextEntryIdx != 0 || run.TotalProcessed != 0 {
		t.Errorf("fresh run should have zero counters, got next=%d total=%d", run.NextEntryIdx, run.TotalProcessed)
	}

	// Second call should return the same row with progress preserved.
	if err := p.UpdateLogProgress(id, 1024, 1000); err != nil {
		t.Fatalf("UpdateLogProgress: %v", err)
	}
	if err := p.SetLogTreeSizeAtStart(id, 999_999); err != nil {
		t.Fatalf("SetLogTreeSizeAtStart: %v", err)
	}

	// Update metadata via a second GetOrCreate — progress must survive.
	init.State = "readonly"
	run2, err := p.GetOrCreateLogRun(init)
	if err != nil {
		t.Fatalf("GetOrCreateLogRun (refresh): %v", err)
	}
	if run2.NextEntryIdx != 1024 || run2.TotalProcessed != 1000 {
		t.Errorf("progress lost on refresh: next=%d total=%d", run2.NextEntryIdx, run2.TotalProcessed)
	}
	if run2.State != "readonly" {
		t.Errorf("state not refreshed: got %q want readonly", run2.State)
	}
	if run2.TreeSizeAtStart != 999_999 {
		t.Errorf("tree_size_at_start not preserved: got %d", run2.TreeSizeAtStart)
	}

	// SetLogTreeSizeAtStart must be idempotent — second call should NOT overwrite.
	if err := p.SetLogTreeSizeAtStart(id, 1_111_111); err != nil {
		t.Fatalf("SetLogTreeSizeAtStart (second): %v", err)
	}
	runs, err := p.ListLogRuns()
	if err != nil {
		t.Fatalf("ListLogRuns: %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("ListLogRuns: expected 1, got %d", len(runs))
	}
	if runs[0].TreeSizeAtStart != 999_999 {
		t.Errorf("SetLogTreeSizeAtStart overwrote on second call: got %d", runs[0].TreeSizeAtStart)
	}
}

func TestSubjectDB_CertHashDedup(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "subjects.db")
	sdb, err := OpenSubjectDB(tmp)
	if err != nil {
		t.Fatalf("OpenSubjectDB: %v", err)
	}
	defer sdb.Close()

	certHash := sha256.Sum256([]byte("cert-A"))
	logA := sha256.Sum256([]byte("log-A"))
	logB := sha256.Sum256([]byte("log-B"))

	// Same cert from two different logs — only one subjects row, two cert_log rows.
	subj := Subject{
		CAID: 1, SerialNumber: "01", CommonName: "example.com",
		NotBefore: "2026-05-01", NotAfter: "2026-08-01",
		EntryType: "x509",
		CertHash:  certHash[:],
		LogID:     logA[:],
	}
	if err := sdb.InsertSubjectBatch([]Subject{subj}); err != nil {
		t.Fatalf("insert from log A: %v", err)
	}
	subj.LogID = logB[:]
	if err := sdb.InsertSubjectBatch([]Subject{subj}); err != nil {
		t.Fatalf("insert from log B: %v", err)
	}

	var subjectsCount int
	if err := sdb.db.QueryRow(`SELECT COUNT(*) FROM subjects`).Scan(&subjectsCount); err != nil {
		t.Fatal(err)
	}
	if subjectsCount != 1 {
		t.Errorf("expected 1 subject row after dedup, got %d", subjectsCount)
	}

	// Record provenance in cert_log.
	entries := []CertLogEntry{
		{LogID: logA[:], EntryIdx: 100, CertHash: certHash[:], SeenAt: 1700000000},
		{LogID: logB[:], EntryIdx: 200, CertHash: certHash[:], SeenAt: 1700000001},
		// Duplicate (log, entry) — must be ignored.
		{LogID: logA[:], EntryIdx: 100, CertHash: certHash[:], SeenAt: 1700000002},
	}
	if err := sdb.InsertCertLogBatch(entries); err != nil {
		t.Fatalf("InsertCertLogBatch: %v", err)
	}

	var clCount int
	if err := sdb.db.QueryRow(`SELECT COUNT(*) FROM cert_log`).Scan(&clCount); err != nil {
		t.Fatal(err)
	}
	if clCount != 2 {
		t.Errorf("expected 2 cert_log rows after dedup, got %d", clCount)
	}

	// Verify lookup by cert_hash returns both logs.
	rows, err := sdb.db.Query(`SELECT log_id FROM cert_log WHERE cert_hash = ? ORDER BY entry_idx`, certHash[:])
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var seenLogs [][]byte
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			t.Fatal(err)
		}
		seenLogs = append(seenLogs, b)
	}
	if len(seenLogs) != 2 {
		t.Errorf("expected 2 logs for cert_hash, got %d", len(seenLogs))
	}
	if !bytes.Equal(seenLogs[0], logA[:]) || !bytes.Equal(seenLogs[1], logB[:]) {
		t.Errorf("log_id ordering wrong: %x then %x", seenLogs[0], seenLogs[1])
	}
}

func TestSubjectDB_LegacyTileEntryStillDedup(t *testing.T) {
	// Verify the legacy single-log code path (no CertHash) still dedups on (tile_idx, entry_idx).
	tmp := filepath.Join(t.TempDir(), "subjects.db")
	sdb, err := OpenSubjectDB(tmp)
	if err != nil {
		t.Fatalf("OpenSubjectDB: %v", err)
	}
	defer sdb.Close()

	subj := Subject{
		CAID: 1, SerialNumber: "01", CommonName: "example.com",
		NotBefore: "2026-05-01", NotAfter: "2026-08-01",
		EntryType: "x509",
		TileIdx:   5,
		EntryIdx:  42,
	}
	if err := sdb.InsertSubjectBatch([]Subject{subj, subj}); err != nil {
		t.Fatalf("insert twice: %v", err)
	}
	var n int
	if err := sdb.db.QueryRow(`SELECT COUNT(*) FROM subjects`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("legacy dedup failed: expected 1 row, got %d", n)
	}
}
