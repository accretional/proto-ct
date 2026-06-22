package ctv2

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/sunlight"
	pb "github.com/accretional/proto-ct/gen/ctingestion/v2"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	"google.golang.org/protobuf/proto"
)

// makeX509LeafInput marshals a minimal V1 x509 MerkleTreeLeaf for the given
// timestamp, exercising the same parse path as live get-entries data.
func makeX509LeafInput(t *testing.T, tsMs uint64, der []byte) []byte {
	t.Helper()
	leaf := ct.MerkleTreeLeaf{
		Version:  ct.V1,
		LeafType: ct.TimestampedEntryLeafType,
		TimestampedEntry: &ct.TimestampedEntry{
			Timestamp: tsMs,
			EntryType: ct.X509LogEntryType,
			X509Entry: &ct.ASN1Cert{Data: der},
		},
	}
	b, err := tls.Marshal(leaf)
	if err != nil {
		t.Fatalf("tls.Marshal leaf: %v", err)
	}
	return b
}

// makeCertChain TLS-encodes a CertificateChain (the RFC6962 x509 extra_data
// shape) from the given issuer cert DERs.
func makeCertChain(t *testing.T, ders ...[]byte) []byte {
	t.Helper()
	chain := ct.CertificateChain{}
	for _, d := range ders {
		chain.Entries = append(chain.Entries, ct.ASN1Cert{Data: d})
	}
	b, err := tls.Marshal(chain)
	if err != nil {
		t.Fatalf("tls.Marshal CertificateChain: %v", err)
	}
	return b
}

func TestRawEntryFromRFC6962_ParsesHeader(t *testing.T) {
	const tsMs = 1_700_000_000_000
	der := []byte{0x30, 0x03, 0x01, 0x02, 0x03}
	ca := []byte{0x30, 0x04, 0x0a, 0x0b, 0x0c, 0x0d}
	extra := makeCertChain(t, ca)
	leafInput := makeX509LeafInput(t, tsMs, der)

	r, chains, err := rawEntryFromRFC6962(42, leafInput, extra)
	if err != nil {
		t.Fatalf("rawEntryFromRFC6962: %v", err)
	}
	if r.Index != 42 {
		t.Errorf("index = %d, want 42", r.Index)
	}
	if r.TimestampMs != tsMs {
		t.Errorf("timestamp = %d, want %d", r.TimestampMs, tsMs)
	}
	if r.EntryType != pb.EntryType_ENTRY_TYPE_X509 {
		t.Errorf("entry type = %v, want X509", r.EntryType)
	}
	if r.Source != pb.LogProtocol_LOG_PROTOCOL_RFC6962 {
		t.Errorf("source = %v, want RFC6962", r.Source)
	}
	if string(r.LeafInput) != string(leafInput) {
		t.Errorf("leaf_input not stored verbatim")
	}
	// O1: the chain is not stored inline; it becomes one fingerprint + one chainCert.
	wantFP := sha256.Sum256(ca)
	if len(r.ChainFingerprints) != 1 || string(r.ChainFingerprints[0]) != string(wantFP[:]) {
		t.Errorf("chain_fingerprints = %v, want one SHA-256(ca)", r.ChainFingerprints)
	}
	if len(chains) != 1 || chains[0].hash != wantFP || string(chains[0].der) != string(ca) {
		t.Errorf("returned chain certs = %v, want one {hash, der} for ca", chains)
	}
}

func TestRawEntryFromRFC6962_BadLeaf(t *testing.T) {
	if _, _, err := rawEntryFromRFC6962(0, []byte{0x00}, nil); err == nil {
		t.Fatal("expected error on malformed leaf_input")
	}
}

func TestRawEntryFromStatic_Precert(t *testing.T) {
	e := &sunlight.LogEntry{
		LeafIndex:         7,
		Timestamp:         1_700_000_000_000,
		IsPrecert:         true,
		Certificate:       []byte{0x01, 0x02},
		PreCertificate:    []byte{0x03, 0x04},
		IssuerKeyHash:     [32]byte{0xFE},
		ChainFingerprints: [][32]byte{{0x11}, {0x22}},
	}
	r := rawEntryFromStatic(e)
	if r.EntryType != pb.EntryType_ENTRY_TYPE_PRECERT {
		t.Errorf("entry type = %v, want PRECERT", r.EntryType)
	}
	if r.Source != pb.LogProtocol_LOG_PROTOCOL_STATIC_CT_API {
		t.Errorf("source = %v, want STATIC", r.Source)
	}
	if len(r.ChainFingerprints) != 2 || r.ChainFingerprints[0][0] != 0x11 {
		t.Errorf("chain fingerprints not mapped: %v", r.ChainFingerprints)
	}
	if len(r.IssuerKeyHash) != 32 || r.IssuerKeyHash[0] != 0xFE {
		t.Errorf("issuer key hash not mapped")
	}
}

// memWriter is an in-memory, concurrency-safe Writer for tests. It enforces
// immutability (write-once) like LocalFSWriter.
type memWriter struct {
	mu    sync.Mutex
	files map[string][]byte
}

var errDuplicate = errors.New("duplicate partition path")

func (m *memWriter) Put(_ context.Context, relPath string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.files == nil {
		m.files = map[string][]byte{}
	}
	if _, exists := m.files[relPath]; exists {
		return errDuplicate
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	m.files[relPath] = cp
	return nil
}

func (m *memWriter) PutIfAbsent(_ context.Context, relPath string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.files == nil {
		m.files = map[string][]byte{}
	}
	if _, exists := m.files[relPath]; exists {
		return nil // content-addressed: no-op when present
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	m.files[relPath] = cp
	return nil
}

func (m *memWriter) has(suffix string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k := range m.files {
		if strings.HasSuffix(k, suffix) {
			return true
		}
	}
	return false
}

func TestBatchSink_SplitsBatchAcrossDayBoundary(t *testing.T) {
	day1 := time.Date(2024, 3, 15, 23, 0, 0, 0, time.UTC).UnixMilli()
	day2 := time.Date(2024, 3, 16, 1, 0, 0, 0, time.UTC).UnixMilli()
	meta := &pb.LogMeta{MonitoringUrl: "https://log.example/2024h1/"}

	mw := &memWriter{}
	s := newBatchSink(mw, meta, pb.PartitionGranularity_PARTITION_GRANULARITY_DAY, nil)

	// One contiguous batch straddling midnight -> two contiguous same-day files.
	err := s.writeBatch(context.Background(), entryBatch{entries: []*pb.RawLogEntry{
		{Index: 10, TimestampMs: day1},
		{Index: 11, TimestampMs: day1},
		{Index: 12, TimestampMs: day2},
	}})
	if err != nil {
		t.Fatalf("writeBatch: %v", err)
	}
	if len(mw.files) != 2 {
		t.Fatalf("got %d files, want 2: %v", len(mw.files), keys(mw.files))
	}
	// Paths are <day>/<first36>-<last36>.binpb (no log-id prefix); 10->a,11->b,12->c.
	wantSuffixes := []string{
		"2024-03-15/" + encodeBase36(10) + "-" + encodeBase36(11) + ".binpb",
		"2024-03-16/" + encodeBase36(12) + "-" + encodeBase36(12) + ".binpb",
	}
	for _, suf := range wantSuffixes {
		if !mw.has(suf) {
			t.Errorf("missing partition with suffix %q in %v", suf, keys(mw.files))
		}
	}
	if s.entriesWritten != 3 || s.firstIndex != 10 || s.lastIndex != 12 {
		t.Errorf("entriesWritten=%d first=%d last=%d, want 3/10/12", s.entriesWritten, s.firstIndex, s.lastIndex)
	}
	// (file count already asserted above via len(mw.files) == 2)
}

func TestBatchSink_DisjointBatchesSameDay(t *testing.T) {
	ts := time.Date(2024, 3, 15, 12, 0, 0, 0, time.UTC).UnixMilli()
	mw := &memWriter{}
	s := newBatchSink(mw, &pb.LogMeta{MonitoringUrl: "x"}, pb.PartitionGranularity_PARTITION_GRANULARITY_DAY, nil)
	ctx := context.Background()
	// Two disjoint batches in the same day -> two distinct files, no overlap.
	if err := s.writeBatch(ctx, entryBatch{entries: []*pb.RawLogEntry{{Index: 0, TimestampMs: ts}, {Index: 1, TimestampMs: ts}}}); err != nil {
		t.Fatalf("writeBatch 1: %v", err)
	}
	if err := s.writeBatch(ctx, entryBatch{entries: []*pb.RawLogEntry{{Index: 2, TimestampMs: ts}, {Index: 3, TimestampMs: ts}}}); err != nil {
		t.Fatalf("writeBatch 2: %v", err)
	}
	if len(mw.files) != 2 {
		t.Fatalf("got %d files, want 2: %v", len(mw.files), keys(mw.files))
	}
	if !mw.has("2024-03-15/0-1.binpb") || !mw.has("2024-03-15/2-3.binpb") {
		t.Errorf("expected 0-1 and 2-3 files, got %v", keys(mw.files))
	}
}

func TestBatchSink_ConcurrentBatchesSafe(t *testing.T) {
	ts := time.Date(2024, 3, 15, 12, 0, 0, 0, time.UTC).UnixMilli()
	mw := &memWriter{}
	s := newBatchSink(mw, &pb.LogMeta{MonitoringUrl: "x"}, pb.PartitionGranularity_PARTITION_GRANULARITY_DAY, nil)
	ctx := context.Background()

	const n = 50
	var wg sync.WaitGroup
	errs := make([]error, n)
	for b := range n {
		wg.Add(1)
		go func(b int) {
			defer wg.Done()
			idx := int64(b * 2)
			errs[b] = s.writeBatch(ctx, entryBatch{entries: []*pb.RawLogEntry{
				{Index: idx, TimestampMs: ts},
				{Index: idx + 1, TimestampMs: ts},
			}})
		}(b)
	}
	wg.Wait()
	for b, err := range errs {
		if err != nil {
			t.Fatalf("batch %d: %v", b, err)
		}
	}
	if len(mw.files) != n {
		t.Errorf("got %d files, want %d", len(mw.files), n)
	}
	if s.entriesWritten != int64(2*n) {
		t.Errorf("entriesWritten = %d, want %d", s.entriesWritten, 2*n)
	}
	if s.firstIndex != 0 || s.lastIndex != int64(2*n-1) {
		t.Errorf("first/last = %d/%d, want 0/%d", s.firstIndex, s.lastIndex, 2*n-1)
	}
}

func TestIssuerStore_DedupesAndWritesOnce(t *testing.T) {
	mw := &memWriter{}
	store := newIssuerStore(mw)
	ctx := context.Background()

	caA := []byte("CA-cert-A")
	caB := []byte("CA-cert-B")
	hA := sha256.Sum256(caA)
	hB := sha256.Sum256(caB)

	// Three "batches", all sharing caA; caB appears only in the second.
	for _, certs := range [][]chainCert{
		{{hash: hA, der: caA}},
		{{hash: hA, der: caA}, {hash: hB, der: caB}},
		{{hash: hA, der: caA}},
	} {
		if err := store.put(ctx, certs); err != nil {
			t.Fatalf("put: %v", err)
		}
	}

	if len(mw.files) != 2 {
		t.Fatalf("issuer store wrote %d files, want 2 (one per unique cert): %v", len(mw.files), keys(mw.files))
	}
	pathA := issuerStorePath(hA)
	pathB := issuerStorePath(hB)
	if string(mw.files[pathA]) != string(caA) {
		t.Errorf("%s = %q, want %q", pathA, mw.files[pathA], caA)
	}
	if string(mw.files[pathB]) != string(caB) {
		t.Errorf("%s = %q, want %q", pathB, mw.files[pathB], caB)
	}
}

// TestBatchSink_WritesIssuerCertsThenLeaves checks the RFC6962 sink path lands
// chain certs in the issuer store and the leaf records keep matching fingerprints.
func TestBatchSink_WritesIssuerCerts(t *testing.T) {
	const tsMs = 1_700_000_000_000
	leaf := makeX509LeafInput(t, tsMs, []byte{0x30, 0x03, 0x01, 0x02, 0x03})
	ca := []byte{0x30, 0x05, 0x09, 0x08, 0x07, 0x06, 0x05}
	extra := makeCertChain(t, ca)

	r, chains, err := rawEntryFromRFC6962(0, leaf, extra)
	if err != nil {
		t.Fatalf("rawEntryFromRFC6962: %v", err)
	}

	mw := &memWriter{}
	s := newBatchSink(mw, &pb.LogMeta{MonitoringUrl: "x"}, pb.PartitionGranularity_PARTITION_GRANULARITY_DAY, newIssuerStore(mw))
	if err := s.writeBatch(context.Background(), entryBatch{entries: []*pb.RawLogEntry{r}, chains: chains}); err != nil {
		t.Fatalf("writeBatch: %v", err)
	}

	if !mw.has(issuerStorePath(sha256.Sum256(ca))) {
		t.Errorf("issuer cert not written to store; files: %v", keys(mw.files))
	}
	if len(r.ChainFingerprints) != 1 {
		t.Errorf("leaf kept %d fingerprints, want 1", len(r.ChainFingerprints))
	}
}

func TestRawLogEntryBatch_BinaryRoundTrip(t *testing.T) {
	batch := &pb.RawLogEntryBatch{
		Log: &pb.LogMeta{MonitoringUrl: "https://log.example/", Protocol: pb.LogProtocol_LOG_PROTOCOL_RFC6962},
		Entries: []*pb.RawLogEntry{
			{Index: 1, TimestampMs: 100, EntryType: pb.EntryType_ENTRY_TYPE_X509, LeafInput: []byte{1, 2, 3}, ChainFingerprints: [][]byte{{4}}},
			{Index: 2, TimestampMs: 200, EntryType: pb.EntryType_ENTRY_TYPE_PRECERT, Precertificate: []byte{9}},
		},
	}
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(batch)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got pb.RawLogEntryBatch
	if err := proto.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !proto.Equal(batch, &got) {
		t.Errorf("round-trip mismatch:\nwant %v\ngot  %v", batch, &got)
	}
}

func TestLocalFSWriter_AtomicAndImmutable(t *testing.T) {
	dir := t.TempDir()
	w := &LocalFSWriter{Root: dir}
	ctx := context.Background()
	rel := "slug/2024-03-15/0-9.binpb"
	data := []byte("hello")

	if err := w.Put(ctx, rel, data); err != nil {
		t.Fatalf("first Put: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("content = %q, want hello", got)
	}
	// No leftover tmp file.
	if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(rel)) + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("tmp file not cleaned up")
	}
	// Immutable: second write to the same path must fail.
	if err := w.Put(ctx, rel, []byte("world")); err == nil {
		t.Errorf("expected immutability error on overwrite")
	}
}

func TestGzipWriter_AppendsSuffixAndCompresses(t *testing.T) {
	mw := &memWriter{}
	gw := newGzipWriter(mw)
	ctx := context.Background()

	// Highly compressible payload so we can assert the on-disk form is smaller.
	payload := bytes.Repeat([]byte("CT-leaf-bytes-"), 500)

	if err := gw.Put(ctx, "2024-03-15/0-9.binpb", payload); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := gw.PutIfAbsent(ctx, "issuers/abc.der", payload); err != nil {
		t.Fatalf("PutIfAbsent: %v", err)
	}

	for _, rel := range []string{"2024-03-15/0-9.binpb.gz", "issuers/abc.der.gz"} {
		stored, ok := mw.files[rel]
		if !ok {
			t.Fatalf("expected %q in store, have %v", rel, keys(mw.files))
		}
		if len(stored) >= len(payload) {
			t.Errorf("%s: compressed %d bytes >= raw %d, expected smaller", rel, len(stored), len(payload))
		}
		zr, err := gzip.NewReader(bytes.NewReader(stored))
		if err != nil {
			t.Fatalf("%s: gzip.NewReader: %v", rel, err)
		}
		got, err := io.ReadAll(zr)
		if err != nil {
			t.Fatalf("%s: read gz: %v", rel, err)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("%s: round-trip mismatch", rel)
		}
	}
	// The undecorated (".binpb") name must not exist — only the ".gz" form.
	if _, ok := mw.files["2024-03-15/0-9.binpb"]; ok {
		t.Errorf("uncompressed name should not be present alongside .gz")
	}
}

func TestBase36RoundTrip(t *testing.T) {
	cases := []int64{0, 1, 9, 10, 61, 62, 63, 255, 2799999000, 1<<62 - 1, 1<<63 - 1}
	for _, n := range cases {
		enc := encodeBase36(n)
		got, err := decodeBase36(enc)
		if err != nil {
			t.Errorf("decodeBase36(%q): %v", enc, err)
			continue
		}
		if got != n {
			t.Errorf("round-trip %d -> %q -> %d", n, enc, got)
		}
	}
	// Encoding must stay filesystem/separator-safe AND single-case, so it is
	// collision-free on case-INSENSITIVE filesystems (the bug that broke the
	// earlier base-62 scheme on APFS). Only digits and lowercase letters allowed.
	for _, n := range cases {
		for _, c := range encodeBase36(n) {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z')) {
				t.Errorf("encodeBase36(%d)=%q contains non-[0-9a-z] char %q", n, encodeBase36(n), c)
			}
		}
	}
	if _, err := decodeBase36("a-b"); err == nil {
		t.Errorf("expected error decoding string with '-'")
	}
}

func TestParseRangeFromName(t *testing.T) {
	cases := []struct {
		name      string
		wantStart int64
		wantEnd   int64
		wantOK    bool
	}{
		{"0-0.binpb", 0, 1, true},
		{"a-c.binpb", 10, 13, true},    // base36 a=10, c=12 -> [10,13)
		{"a-c.binpb.gz", 10, 13, true}, // gzip-compressed partition (O4)
		{"274-27t.binpb", 0, 0, true},  // just checks ok + first<=last (values below)
		{"foo.binpb", 0, 0, false},     // no dash
		{"0-9.textpb", 0, 0, false},    // wrong ext
		{"c-a.binpb", 0, 0, false},     // last < first
	}
	for _, c := range cases {
		r, ok := parseRangeFromName(c.name)
		if ok != c.wantOK {
			t.Errorf("%s: ok=%v want %v", c.name, ok, c.wantOK)
			continue
		}
		if c.wantOK && c.name == "a-c.binpb" && (r.start != 10 || r.end != 13) {
			t.Errorf("a-c: got [%d,%d) want [10,13)", r.start, r.end)
		}
		if c.wantOK && c.name == "274-27t.binpb" {
			f, _ := decodeBase36("274")
			l, _ := decodeBase36("27t")
			if r.start != f || r.end != l+1 {
				t.Errorf("274-27t: got [%d,%d) want [%d,%d)", r.start, r.end, f, l+1)
			}
		}
	}
}

func TestSummarizeRanges(t *testing.T) {
	// Contiguous from 0, with a known tree size -> tail gap.
	stored, frontier, contig, gaps := summarizeRanges([]idxRange{{1000, 2000}, {0, 1000}}, 5000)
	if stored != 2000 || frontier != 2000 || contig != 2000 {
		t.Errorf("contiguous: stored=%d frontier=%d contig=%d want 2000/2000/2000", stored, frontier, contig)
	}
	if len(gaps) != 1 || gaps[0] != (idxRange{2000, 5000}) {
		t.Errorf("contiguous: gaps=%v want [[2000,5000)]", gaps)
	}

	// Hole in the middle.
	stored, frontier, contig, gaps = summarizeRanges([]idxRange{{0, 1000}, {2000, 3000}}, 3000)
	if stored != 2000 || frontier != 3000 || contig != 1000 {
		t.Errorf("hole: stored=%d frontier=%d contig=%d want 2000/3000/1000", stored, frontier, contig)
	}
	if len(gaps) != 1 || gaps[0] != (idxRange{1000, 2000}) {
		t.Errorf("hole: gaps=%v want [[1000,2000)]", gaps)
	}

	// No tree size -> gaps bounded by frontier (just the internal hole).
	_, _, _, gaps = summarizeRanges([]idxRange{{0, 1000}, {2000, 3000}}, 0)
	if len(gaps) != 1 || gaps[0] != (idxRange{1000, 2000}) {
		t.Errorf("no-tree: gaps=%v want [[1000,2000)]", gaps)
	}

	// Empty.
	stored, frontier, contig, gaps = summarizeRanges(nil, 100)
	if stored != 0 || frontier != 0 || contig != 0 || len(gaps) != 1 || gaps[0] != (idxRange{0, 100}) {
		t.Errorf("empty: stored=%d frontier=%d contig=%d gaps=%v", stored, frontier, contig, gaps)
	}
}

func TestScanPartitionRanges(t *testing.T) {
	root := t.TempDir() // a single log's output prefix
	mk := func(rel string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// per-chunk subdirs + flat day partitions both scanned at any depth
	mk("chunk_a/2024-01-01/0-9.binpb") // [0,10)
	mk("chunk_a/2024-01-02/a-j.binpb") // [10,20)
	mk("chunk_b/2024-01-03/k-t.binpb") // [20,30)
	mk("chunk_a/2024-01-01/notes.txt") // not binpb -> ignored

	ranges, files, err := scanPartitionRanges(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if files != 3 {
		t.Errorf("files=%d want 3", files)
	}
	stored, frontier, contig, _ := summarizeRanges(ranges, 0)
	if stored != 30 || frontier != 30 || contig != 30 {
		t.Errorf("stored=%d frontier=%d contig=%d want 30/30/30", stored, frontier, contig)
	}
}

func keys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
