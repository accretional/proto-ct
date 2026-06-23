package ctv2

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/accretional/proto-ct/gen/ctingestion/v2"
	"google.golang.org/protobuf/proto"
)

// writePartition marshals a batch to <root>/<rel> (gzip-compressed iff rel ends
// in .gz), mirroring what the sink produces on disk.
func writePartition(t *testing.T, root, rel string, batch *pb.RawLogEntryBatch) {
	t.Helper()
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(batch)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.HasSuffix(rel, ".gz") {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		if _, err := zw.Write(data); err != nil {
			t.Fatalf("gzip: %v", err)
		}
		if err := zw.Close(); err != nil {
			t.Fatalf("gzip close: %v", err)
		}
		data = buf.Bytes()
	}
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(full, data, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func staticEntry(idx int64, fps ...[32]byte) *pb.RawLogEntry {
	e := &pb.RawLogEntry{Index: idx, Source: pb.LogProtocol_LOG_PROTOCOL_STATIC_CT_API}
	for _, fp := range fps {
		e.ChainFingerprints = append(e.ChainFingerprints, append([]byte(nil), fp[:]...))
	}
	return e
}

func TestResolveIssuers_FetchesMissingStaticChains(t *testing.T) {
	caA := []byte("issuer-cert-A-DER")
	caB := []byte("issuer-cert-B-DER")
	caC := []byte("rfc6962-issuer-C") // referenced only by an RFC6962 entry -> must be skipped
	fpA, fpB, fpC := sha256.Sum256(caA), sha256.Sum256(caB), sha256.Sum256(caC)

	// Static-ct-api issuer endpoint: GET /issuer/<hex> -> raw DER.
	var requested []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := strings.TrimPrefix(r.URL.Path, "/issuer/")
		requested = append(requested, h)
		switch h {
		case hex.EncodeToString(fpA[:]):
			w.Write(caA)
		case hex.EncodeToString(fpB[:]):
			w.Write(caB)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	root := t.TempDir()
	logMeta := &pb.LogMeta{MonitoringUrl: srv.URL, Protocol: pb.LogProtocol_LOG_PROTOCOL_STATIC_CT_API}
	// Plain partition: two static entries referencing fpA and {fpA,fpB}.
	writePartition(t, root, "2024-01-01/0-1.binpb", &pb.RawLogEntryBatch{
		Log:     logMeta,
		Entries: []*pb.RawLogEntry{staticEntry(0, fpA), staticEntry(1, fpA, fpB)},
	})
	// Gzipped partition: a static entry (fpB) + an RFC6962 entry (fpC, must be ignored).
	rfcEntry := &pb.RawLogEntry{Index: 3, Source: pb.LogProtocol_LOG_PROTOCOL_RFC6962,
		ChainFingerprints: [][]byte{append([]byte(nil), fpC[:]...)}}
	writePartition(t, root, "2024-01-02/2-3.binpb.gz", &pb.RawLogEntryBatch{
		Log:     logMeta,
		Entries: []*pb.RawLogEntry{staticEntry(2, fpB), rfcEntry},
	})

	svc := NewService(root)
	ctx := context.Background()

	// Dry run: reports 2 referenced static issuers, none present, fetches nothing.
	dry, err := svc.ResolveIssuers(ctx, &pb.ResolveIssuersRequest{OutputRoot: root, DryRun: true})
	if err != nil {
		t.Fatalf("ResolveIssuers dry: %v", err)
	}
	if dry.Referenced != 2 || dry.AlreadyPresent != 0 || dry.Fetched != 0 {
		t.Errorf("dry: referenced=%d present=%d fetched=%d, want 2/0/0", dry.Referenced, dry.AlreadyPresent, dry.Fetched)
	}
	if len(requested) != 0 {
		t.Errorf("dry run hit the network: %v", requested)
	}

	// Real run: fetch + store both static issuers.
	got, err := svc.ResolveIssuers(ctx, &pb.ResolveIssuersRequest{OutputRoot: root})
	if err != nil {
		t.Fatalf("ResolveIssuers: %v", err)
	}
	if got.Referenced != 2 || got.Fetched != 2 || got.Failed != 0 {
		t.Fatalf("referenced=%d fetched=%d failed=%d, want 2/2/0 (errs=%v)", got.Referenced, got.Fetched, got.Failed, got.Errors)
	}
	// fpC (RFC6962) must never have been requested.
	for _, h := range requested {
		if h == hex.EncodeToString(fpC[:]) {
			t.Errorf("RFC6962 issuer fpC was fetched; should be skipped")
		}
	}
	// Store now holds both certs, raw, with the content-address invariant.
	for fp, der := range map[[32]byte][]byte{fpA: caA, fpB: caB} {
		p := filepath.Join(root, filepath.FromSlash(issuerStorePath(fp)))
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %x: %v", fp, err)
		}
		if !bytes.Equal(b, der) {
			t.Errorf("%x: stored %q, want %q", fp, b, der)
		}
		if sha256.Sum256(b) != fp {
			t.Errorf("%x: content-address invariant broken", fp)
		}
	}

	// Idempotent: a second run fetches nothing.
	again, err := svc.ResolveIssuers(ctx, &pb.ResolveIssuersRequest{OutputRoot: root})
	if err != nil {
		t.Fatalf("ResolveIssuers rerun: %v", err)
	}
	if again.AlreadyPresent != 2 || again.Fetched != 0 {
		t.Errorf("rerun: present=%d fetched=%d, want 2/0", again.AlreadyPresent, again.Fetched)
	}
}

func TestResolveIssuers_VerifiesFingerprint(t *testing.T) {
	ca := []byte("real-issuer")
	fp := sha256.Sum256(ca)
	// Server returns the WRONG bytes for the fingerprint.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("tampered-issuer-bytes"))
	}))
	defer srv.Close()

	root := t.TempDir()
	writePartition(t, root, "2024-01-01/0-0.binpb", &pb.RawLogEntryBatch{
		Log:     &pb.LogMeta{MonitoringUrl: srv.URL, Protocol: pb.LogProtocol_LOG_PROTOCOL_STATIC_CT_API},
		Entries: []*pb.RawLogEntry{staticEntry(0, fp)},
	})

	got, err := NewService(root).ResolveIssuers(context.Background(), &pb.ResolveIssuersRequest{OutputRoot: root})
	if err != nil {
		t.Fatalf("ResolveIssuers: %v", err)
	}
	if got.Fetched != 0 || got.Failed != 1 {
		t.Errorf("fetched=%d failed=%d, want 0/1 (mismatch must be rejected)", got.Fetched, got.Failed)
	}
	if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(issuerStorePath(fp)))); err == nil {
		t.Errorf("tampered issuer was stored despite fingerprint mismatch")
	}
}
