package ctv2

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/accretional/proto-ct/gen/ctingestion/v2"
	"filippo.io/sunlight"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	"google.golang.org/protobuf/encoding/prototext"
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

func TestRawEntryFromRFC6962_ParsesHeader(t *testing.T) {
	const tsMs = 1_700_000_000_000
	der := []byte{0x30, 0x03, 0x01, 0x02, 0x03}
	extra := []byte{0xAA, 0xBB}
	leafInput := makeX509LeafInput(t, tsMs, der)

	r, err := rawEntryFromRFC6962(42, leafInput, extra)
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
	if string(r.LeafInput) != string(leafInput) || string(r.ExtraData) != string(extra) {
		t.Errorf("raw bytes not stored verbatim")
	}
}

func TestRawEntryFromRFC6962_BadLeaf(t *testing.T) {
	if _, err := rawEntryFromRFC6962(0, []byte{0x00}, nil); err == nil {
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

// memWriter is an in-memory Writer for tests.
type memWriter struct {
	files map[string][]byte
}

func (m *memWriter) Put(_ context.Context, relPath string, data []byte) error {
	if m.files == nil {
		m.files = map[string][]byte{}
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	m.files[relPath] = cp
	return nil
}

func TestPartitionWriter_SplitsAcrossDayBoundary(t *testing.T) {
	day1 := time.Date(2024, 3, 15, 23, 0, 0, 0, time.UTC).UnixMilli()
	day2 := time.Date(2024, 3, 16, 1, 0, 0, 0, time.UTC).UnixMilli()
	meta := &pb.LogMeta{MonitoringUrl: "https://log.example/2024h1/"}

	mw := &memWriter{}
	pw := newPartitionWriter(mw, meta, pb.PartitionGranularity_PARTITION_GRANULARITY_DAY, 0)
	ctx := context.Background()

	for _, e := range []*pb.RawLogEntry{
		{Index: 10, TimestampMs: day1},
		{Index: 11, TimestampMs: day1},
		{Index: 12, TimestampMs: day2},
	} {
		if err := pw.add(ctx, e); err != nil {
			t.Fatalf("add: %v", err)
		}
	}
	if err := pw.flushAll(ctx); err != nil {
		t.Fatalf("flushAll: %v", err)
	}

	if len(mw.files) != 2 {
		t.Fatalf("got %d files, want 2: %v", len(mw.files), keys(mw.files))
	}
	wantSuffixes := []string{"/2024-03-15/10-11.textpb", "/2024-03-16/12-12.textpb"}
	for _, suf := range wantSuffixes {
		found := false
		for k := range mw.files {
			if strings.HasSuffix(k, suf) {
				found = true
			}
		}
		if !found {
			t.Errorf("missing partition with suffix %q in %v", suf, keys(mw.files))
		}
	}
	if pw.entriesWritten != 3 {
		t.Errorf("entriesWritten = %d, want 3", pw.entriesWritten)
	}
	if len(pw.manifests) != 2 {
		t.Errorf("manifests = %d, want 2", len(pw.manifests))
	}
}

func TestPartitionWriter_MaxEntriesRollsFile(t *testing.T) {
	ts := time.Date(2024, 3, 15, 12, 0, 0, 0, time.UTC).UnixMilli()
	mw := &memWriter{}
	pw := newPartitionWriter(mw, &pb.LogMeta{MonitoringUrl: "x"}, pb.PartitionGranularity_PARTITION_GRANULARITY_DAY, 2)
	ctx := context.Background()
	for i := range int64(5) {
		if err := pw.add(ctx, &pb.RawLogEntry{Index: i, TimestampMs: ts}); err != nil {
			t.Fatalf("add: %v", err)
		}
	}
	if err := pw.flushAll(ctx); err != nil {
		t.Fatalf("flushAll: %v", err)
	}
	// maxEntries=2 over 5 entries (same day) => 3 files (2+2+1).
	if len(mw.files) != 3 {
		t.Fatalf("got %d files, want 3: %v", len(mw.files), keys(mw.files))
	}
}

func TestRawLogEntryBatch_PrototextRoundTrip(t *testing.T) {
	batch := &pb.RawLogEntryBatch{
		Log: &pb.LogMeta{MonitoringUrl: "https://log.example/", Protocol: pb.LogProtocol_LOG_PROTOCOL_RFC6962},
		Entries: []*pb.RawLogEntry{
			{Index: 1, TimestampMs: 100, EntryType: pb.EntryType_ENTRY_TYPE_X509, LeafInput: []byte{1, 2, 3}, ExtraData: []byte{4}},
			{Index: 2, TimestampMs: 200, EntryType: pb.EntryType_ENTRY_TYPE_PRECERT, Certificate: []byte{9}},
		},
	}
	data, err := prototext.Marshal(batch)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got pb.RawLogEntryBatch
	if err := prototext.Unmarshal(data, &got); err != nil {
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
	rel := "slug/2024-03-15/0-9.textpb"
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
	if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(rel))+".tmp"); !os.IsNotExist(err) {
		t.Errorf("tmp file not cleaned up")
	}
	// Immutable: second write to the same path must fail.
	if err := w.Put(ctx, rel, []byte("world")); err == nil {
		t.Errorf("expected immutability error on overwrite")
	}
}

func keys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
