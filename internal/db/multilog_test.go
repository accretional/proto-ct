package db

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

func subjectsCount(t *testing.T, path string) int {
	t.Helper()
	sdb, err := OpenSubjectDB(path)
	if err != nil {
		t.Fatalf("reopen %s: %v", path, err)
	}
	defer sdb.Close()
	var n int
	if err := sdb.db.QueryRow(`SELECT COUNT(*) FROM subjects`).Scan(&n); err != nil {
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
