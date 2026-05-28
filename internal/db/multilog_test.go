package db

import (
	"bytes"
	"crypto/sha256"
	"path/filepath"
	"testing"
)

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
