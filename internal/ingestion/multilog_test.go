package ingestion

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/benfultz/proto-ct/gen/ctingestion/v1"
	"github.com/benfultz/proto-ct/internal/ctlist"
	"github.com/benfultz/proto-ct/internal/db"

	_ "modernc.org/sqlite"
)

// mintTestCert produces a self-signed leaf cert with a fixed NotBefore month.
func mintTestCert(t *testing.T, cn string, notBefore, notAfter time.Time) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"TestOrg"}, Country: []string{"US"}},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     []string{cn, "*." + cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// buildMerkleLeafBytes constructs the MerkleTreeLeaf wire form for an x509 entry.
func buildMerkleLeafBytes(timestamp uint64, certDER []byte) []byte {
	var buf bytes.Buffer
	buf.WriteByte(0) // version
	buf.WriteByte(0) // leaf_type (TimestampedEntry)
	_ = binary.Write(&buf, binary.BigEndian, timestamp)
	_ = binary.Write(&buf, binary.BigEndian, uint16(0)) // entry_type = x509
	n := len(certDER)
	buf.WriteByte(byte(n >> 16))
	buf.WriteByte(byte(n >> 8))
	buf.WriteByte(byte(n))
	buf.Write(certDER)
	_ = binary.Write(&buf, binary.BigEndian, uint16(0)) // extensions length = 0
	return buf.Bytes()
}

// buildExtraDataBytes constructs the extra_data for an x509 entry with a single chain cert.
func buildExtraDataBytes(chainDER []byte) []byte {
	// chain = uint24-prefixed concat of uint24-prefixed certs.
	var inner bytes.Buffer
	n := len(chainDER)
	inner.WriteByte(byte(n >> 16))
	inner.WriteByte(byte(n >> 8))
	inner.WriteByte(byte(n))
	inner.Write(chainDER)
	var out bytes.Buffer
	m := inner.Len()
	out.WriteByte(byte(m >> 16))
	out.WriteByte(byte(m >> 8))
	out.WriteByte(byte(m))
	out.Write(inner.Bytes())
	return out.Bytes()
}

func TestRunLogWorker_RFC6962_WritesRows(t *testing.T) {
	// Synthesise three certs in the same month so they land in one partition.
	notBefore := time.Date(2026, 5, 10, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.AddDate(0, 3, 0)
	certs := [][]byte{
		mintTestCert(t, "alpha.example.com", notBefore, notAfter),
		mintTestCert(t, "beta.example.com", notBefore, notAfter),
		mintTestCert(t, "gamma.example.com", notBefore, notAfter),
	}
	chainDER := mintTestCert(t, "Test Intermediate CA", notBefore.AddDate(-1, 0, 0), notAfter.AddDate(2, 0, 0))

	entries := make([]map[string]string, len(certs))
	for i, c := range certs {
		leafIn := buildMerkleLeafBytes(uint64(time.Now().UnixMilli()), c)
		extra := buildExtraDataBytes(chainDER)
		entries[i] = map[string]string{
			"leaf_input": base64.StdEncoding.EncodeToString(leafIn),
			"extra_data": base64.StdEncoding.EncodeToString(extra),
		}
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ct/v1/get-sth":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tree_size": int64(len(entries)),
				"timestamp": time.Now().UnixMilli(),
			})
		case "/ct/v1/get-entries":
			_ = json.NewEncoder(w).Encode(map[string]any{"entries": entries})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	// Build the synthetic Log entry pointing at the test server.
	var logID [32]byte
	copy(logID[:], sha256.New().Sum([]byte("synthetic-log-1"))[:32])
	lg := ctlist.Log{
		LogID:         logID,
		Description:   "Synthetic RFC6962 test log",
		Operator:      "TestOp",
		Protocol:      ctlist.ProtocolRFC6962,
		State:         ctlist.StateUsable,
		SubmissionURL: srv.URL + "/",
	}

	tmp := t.TempDir()
	activeDir := filepath.Join(tmp, "active")
	archiveDir := filepath.Join(tmp, "archive")
	if err := mkAll(activeDir, archiveDir); err != nil {
		t.Fatal(err)
	}

	progressDB, err := db.OpenProgressDB(filepath.Join(archiveDir, "progress.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer progressDB.Close()
	issuerDB, err := db.OpenIssuerDB(filepath.Join(archiveDir, "issuers.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer issuerDB.CheckpointAndClose()

	pool := db.NewSubjectDBPool(filepath.Join(activeDir, "20260510"))
	events := make(chan *pb.LogProgress, 16)

	var issuerMu sync.Mutex
	var poolRef atomic.Pointer[db.SubjectDBPool]
	poolRef.Store(pool)
	in := workerInputs{
		log:           lg,
		req:           &pb.IngestAllRequest{ProgressEvery: 1},
		progressDB:    progressDB,
		issuerDB:      issuerDB,
		issuerMu:      &issuerMu,
		poolRef:       &poolRef,
		events:        events,
		progressEvery: 1,
	}
	runLogWorker(context.Background(), in)
	close(events)

	// Drain events and ensure the worker terminated with caught_up.
	var statuses []string
	for ev := range events {
		statuses = append(statuses, ev.Status)
	}
	if len(statuses) == 0 || statuses[len(statuses)-1] != "caught_up" {
		t.Errorf("expected final status caught_up, got statuses=%v", statuses)
	}

	// Flush the pool and inspect the archived month partition.
	if err := pool.FlushAll(archiveDir); err != nil {
		t.Fatalf("FlushAll: %v", err)
	}

	monthDB := filepath.Join(archiveDir, "2026-05", "subjects.db")
	conn, err := sql.Open("sqlite", monthDB)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	var subjectsCount, withHashCount int
	if err := conn.QueryRow(`SELECT COUNT(*) FROM subjects`).Scan(&subjectsCount); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(`SELECT COUNT(*) FROM subjects WHERE cert_hash IS NOT NULL`).Scan(&withHashCount); err != nil {
		t.Fatal(err)
	}
	if subjectsCount != 3 {
		t.Errorf("expected 3 subjects rows, got %d", subjectsCount)
	}
	if withHashCount != 3 {
		t.Errorf("expected all 3 subjects to have cert_hash, got %d", withHashCount)
	}

	// log_runs should record the run with the right counters.
	runs, err := progressDB.ListLogRuns()
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 {
		t.Fatalf("expected 1 log_run, got %d", len(runs))
	}
	run := runs[0]
	if run.LogID != logID {
		t.Errorf("log_run.LogID mismatch")
	}
	if run.TotalProcessed != 3 {
		t.Errorf("log_run.TotalProcessed = %d, want 3", run.TotalProcessed)
	}
	if run.NextEntryIdx != 3 {
		t.Errorf("log_run.NextEntryIdx = %d, want 3", run.NextEntryIdx)
	}
	if run.TreeSizeAtStart != 3 {
		t.Errorf("log_run.TreeSizeAtStart = %d, want 3", run.TreeSizeAtStart)
	}
}

func TestRunLogWorker_RFC6962_DedupAcrossLogs(t *testing.T) {
	// Same cert appearing in two different "logs" — verifies cert_hash dedup
	// in subjects (one row regardless of how many logs carry the cert).
	notBefore := time.Date(2026, 5, 10, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.AddDate(0, 3, 0)
	cert := mintTestCert(t, "shared.example.com", notBefore, notAfter)
	chain := mintTestCert(t, "Test CA", notBefore.AddDate(-1, 0, 0), notAfter.AddDate(2, 0, 0))
	entries := []map[string]string{{
		"leaf_input": base64.StdEncoding.EncodeToString(buildMerkleLeafBytes(uint64(time.Now().UnixMilli()), cert)),
		"extra_data": base64.StdEncoding.EncodeToString(buildExtraDataBytes(chain)),
	}}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ct/v1/get-sth":
			_ = json.NewEncoder(w).Encode(map[string]any{"tree_size": 1, "timestamp": time.Now().UnixMilli()})
		case "/ct/v1/get-entries":
			_ = json.NewEncoder(w).Encode(map[string]any{"entries": entries})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	tmp := t.TempDir()
	activeDir := filepath.Join(tmp, "active")
	archiveDir := filepath.Join(tmp, "archive")
	if err := mkAll(activeDir, archiveDir); err != nil {
		t.Fatal(err)
	}

	progressDB, _ := db.OpenProgressDB(filepath.Join(archiveDir, "progress.db"))
	defer progressDB.Close()
	issuerDB, _ := db.OpenIssuerDB(filepath.Join(archiveDir, "issuers.db"))
	defer issuerDB.CheckpointAndClose()
	pool := db.NewSubjectDBPool(filepath.Join(activeDir, "20260510"))

	var issuerMu sync.Mutex
	var poolRef atomic.Pointer[db.SubjectDBPool]
	poolRef.Store(pool)
	events := make(chan *pb.LogProgress, 16)

	// Run two synthetic logs sequentially against the same server.
	for i, name := range []string{"logA", "logB"} {
		var logID [32]byte
		copy(logID[:], sha256.New().Sum([]byte(name))[:32])
		lg := ctlist.Log{
			LogID:         logID,
			Description:   "Synthetic log " + name,
			Operator:      "TestOp",
			Protocol:      ctlist.ProtocolRFC6962,
			State:         ctlist.StateUsable,
			SubmissionURL: srv.URL + "/",
		}
		runLogWorker(context.Background(), workerInputs{
			log: lg, req: &pb.IngestAllRequest{}, progressDB: progressDB,
			issuerDB: issuerDB, issuerMu: &issuerMu, poolRef: &poolRef,
			events: events, progressEvery: 100,
		})
		_ = i
	}
	close(events)
	// Drain.
	for range events {
	}

	if err := pool.FlushAll(archiveDir); err != nil {
		t.Fatal(err)
	}

	monthDB := filepath.Join(archiveDir, "2026-05", "subjects.db")
	conn, _ := sql.Open("sqlite", monthDB)
	defer conn.Close()

	var subjectsCount int
	_ = conn.QueryRow(`SELECT COUNT(*) FROM subjects`).Scan(&subjectsCount)
	if subjectsCount != 1 {
		t.Errorf("expected 1 deduped subjects row, got %d", subjectsCount)
	}
}

// TestRunLogWorker_Pipelined_MultiChunk exercises the concurrent prefetch
// pipeline across several chunks (pageSizeOverride forces multiple chunks per
// window) and a short trailing chunk at the frontier, verifying every entry is
// archived exactly once (no gaps/dups from out-of-order completion) and the
// persisted cursor advances contiguously to the tree size.
func TestRunLogWorker_Pipelined_MultiChunk(t *testing.T) {
	prev := pageSizeOverride
	pageSizeOverride = 2 // 2 entries/chunk → several chunks, last one short
	defer func() { pageSizeOverride = prev }()

	notBefore := time.Date(2026, 5, 10, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.AddDate(0, 3, 0)
	const N = 7 // not a multiple of the page size → forces a short final chunk
	certs := make([][]byte, N)
	for i := range certs {
		certs[i] = mintTestCert(t, fmt.Sprintf("host%d.example.com", i), notBefore, notAfter)
	}
	chainDER := mintTestCert(t, "Test Intermediate CA", notBefore.AddDate(-1, 0, 0), notAfter.AddDate(2, 0, 0))
	entries := make([]map[string]string, N)
	for i, c := range certs {
		entries[i] = map[string]string{
			"leaf_input": base64.StdEncoding.EncodeToString(buildMerkleLeafBytes(uint64(time.Now().UnixMilli()), c)),
			"extra_data": base64.StdEncoding.EncodeToString(buildExtraDataBytes(chainDER)),
		}
	}

	// get-entries handler that RESPECTS the requested [start,end] range, so the
	// pipeline's speculative sequential chunks return the correct sub-ranges.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ct/v1/get-sth":
			_ = json.NewEncoder(w).Encode(map[string]any{"tree_size": int64(N), "timestamp": time.Now().UnixMilli()})
		case "/ct/v1/get-entries":
			start, _ := strconv.Atoi(r.URL.Query().Get("start"))
			end, _ := strconv.Atoi(r.URL.Query().Get("end"))
			if end >= N {
				end = N - 1
			}
			var sub []map[string]string
			if start >= 0 && start < N && start <= end {
				sub = entries[start : end+1]
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"entries": sub})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	var logID [32]byte
	copy(logID[:], sha256.New().Sum([]byte("pipeline-log"))[:32])
	lg := ctlist.Log{
		LogID: logID, Description: "Pipeline test log", Operator: "TestOp",
		Protocol: ctlist.ProtocolRFC6962, State: ctlist.StateUsable, SubmissionURL: srv.URL + "/",
	}

	tmp := t.TempDir()
	activeDir := filepath.Join(tmp, "active")
	archiveDir := filepath.Join(tmp, "archive")
	if err := mkAll(activeDir, archiveDir); err != nil {
		t.Fatal(err)
	}
	progressDB, _ := db.OpenProgressDB(filepath.Join(archiveDir, "progress.db"))
	defer progressDB.Close()
	issuerDB, _ := db.OpenIssuerDB(filepath.Join(archiveDir, "issuers.db"))
	defer issuerDB.CheckpointAndClose()
	pool := db.NewSubjectDBPool(filepath.Join(activeDir, "20260510"))

	var issuerMu sync.Mutex
	var poolRef atomic.Pointer[db.SubjectDBPool]
	poolRef.Store(pool)
	events := make(chan *pb.LogProgress, 64)
	runLogWorker(context.Background(), workerInputs{
		log: lg, req: &pb.IngestAllRequest{ProgressEvery: 1}, progressDB: progressDB,
		issuerDB: issuerDB, issuerMu: &issuerMu, poolRef: &poolRef,
		events: events, progressEvery: 1,
	})
	close(events)
	var statuses []string
	for ev := range events {
		statuses = append(statuses, ev.Status)
	}
	if len(statuses) == 0 || statuses[len(statuses)-1] != "caught_up" {
		t.Errorf("expected final status caught_up, got %v", statuses)
	}

	if err := pool.FlushAll(archiveDir); err != nil {
		t.Fatalf("FlushAll: %v", err)
	}
	conn, _ := sql.Open("sqlite", filepath.Join(archiveDir, "2026-05", "subjects.db"))
	defer conn.Close()
	var got int
	_ = conn.QueryRow(`SELECT COUNT(*) FROM subjects`).Scan(&got)
	if got != N {
		t.Errorf("archived %d subjects, want %d (gap/dup from the fetch pipeline)", got, N)
	}
	runs, _ := progressDB.ListLogRuns()
	if len(runs) != 1 || runs[0].NextEntryIdx != N {
		t.Errorf("cursor not contiguous: %+v, want NextEntryIdx=%d", runs, N)
	}
}

// mkAll creates the given directories, returning the first error.
func mkAll(paths ...string) error {
	for _, p := range paths {
		if err := os.MkdirAll(p, 0o755); err != nil {
			return err
		}
	}
	return nil
}
