package ctv2

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/accretional/proto-ct/gen/ctingestion/v2"
)

func ecKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	return k
}

func mkCert(t *testing.T, tmpl, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, pub *ecdsa.PublicKey) (*x509.Certificate, []byte) {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, parentKey)
	if err != nil {
		t.Fatalf("create cert %s: %v", tmpl.Subject, err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return c, der
}

// buildPKI returns a root CA, an intermediate (signed by root), and a leaf
// (signed by the intermediate), all valid around `at`.
func buildPKI(t *testing.T, at time.Time) (root, inter, leaf *x509.Certificate, rootDER, interDER, leafDER []byte) {
	nb, na := at.Add(-time.Hour), at.Add(time.Hour)
	caTmpl := func(serial int64, cn string) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
			NotBefore: nb, NotAfter: na, IsCA: true, BasicConstraintsValid: true,
			KeyUsage: x509.KeyUsageCertSign,
		}
	}
	rootKey, interKey, leafKey := ecKey(t), ecKey(t), ecKey(t)
	rootT := caTmpl(1, "Test Root CA")
	root, rootDER = mkCert(t, rootT, rootT, rootKey, &rootKey.PublicKey)
	inter, interDER = mkCert(t, caTmpl(2, "Test Intermediate CA"), root, rootKey, &interKey.PublicKey)
	leafT := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "leaf.example.com"},
		NotBefore: nb, NotAfter: na, DNSNames: []string{"leaf.example.com"},
	}
	leaf, leafDER = mkCert(t, leafT, inter, interKey, &leafKey.PublicKey)
	return
}

// stageEntry writes a single X509 entry + its issuer/root stores under a temp root.
func stageEntry(t *testing.T, tsMs int64) (root string, idx int64) {
	t.Helper()
	root = t.TempDir()
	at := time.UnixMilli(tsMs)
	_, inter, _, rootDER, interDER, leafDER := buildPKI(t, at)

	leafInput := makeX509LeafInput(t, uint64(tsMs), leafDER)
	interFP := sha256.Sum256(interDER)
	e := &pb.RawLogEntry{
		Index: 5, TimestampMs: tsMs, EntryType: pb.EntryType_ENTRY_TYPE_X509,
		Source: pb.LogProtocol_LOG_PROTOCOL_STATIC_CT_API, LeafInput: leafInput,
		ChainFingerprints: [][]byte{interFP[:]},
	}
	writePartition(t, root, "2024-01-01/5-5.binpb", &pb.RawLogEntryBatch{
		Log:     &pb.LogMeta{MonitoringUrl: "x", Protocol: pb.LogProtocol_LOG_PROTOCOL_STATIC_CT_API},
		Entries: []*pb.RawLogEntry{e},
	})
	// Issuer store: the intermediate. Roots store: the root.
	w := &LocalFSWriter{Root: root}
	if err := w.PutIfAbsent(context.Background(), issuerStorePath(interFP), interDER); err != nil {
		t.Fatal(err)
	}
	if err := w.PutIfAbsent(context.Background(), rootStorePath(sha256.Sum256(rootDER)), rootDER); err != nil {
		t.Fatal(err)
	}
	_ = inter
	return root, 5
}

func TestVerifyEntry_ValidChain(t *testing.T) {
	tsMs := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC).UnixMilli()
	root, idx := stageEntry(t, tsMs)

	e, err := findEntry(root, idx)
	if err != nil {
		t.Fatalf("findEntry: %v", err)
	}
	resp, err := verifyEntryChain(root, e)
	if err != nil {
		t.Fatalf("verifyEntryChain: %v", err)
	}
	if !resp.Valid {
		t.Fatalf("expected VALID, got invalid: %s", resp.Reason)
	}
	if resp.AnchorSubject != "CN=Test Root CA" {
		t.Errorf("anchor = %q, want CN=Test Root CA", resp.AnchorSubject)
	}
	if len(resp.ChainSubjects) != 1 || resp.ChainSubjects[0] != "CN=Test Intermediate CA" {
		t.Errorf("chain = %v, want [CN=Test Intermediate CA]", resp.ChainSubjects)
	}
	if !resp.WithinValidity {
		t.Errorf("within_validity = false, want true (certs valid at SCT time)")
	}
}

func TestVerifyEntry_MissingRootIsInvalid(t *testing.T) {
	tsMs := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC).UnixMilli()
	root, idx := stageEntry(t, tsMs)
	// Remove the mirrored root -> chain no longer terminates at an accepted anchor.
	rootsGlob, _ := filepath.Glob(filepath.Join(root, rootsDir, "*.der"))
	for _, f := range rootsGlob {
		os.Remove(f)
	}
	e, _ := findEntry(root, idx)
	resp, err := verifyEntryChain(root, e)
	if err != nil {
		t.Fatalf("verifyEntryChain: %v", err)
	}
	if resp.Valid {
		t.Errorf("expected INVALID without a mirrored root")
	}
}

func TestVerifyEntry_MissingIssuerIsInvalid(t *testing.T) {
	tsMs := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC).UnixMilli()
	root, idx := stageEntry(t, tsMs)
	issGlob, _ := filepath.Glob(filepath.Join(root, issuerDir, "*.der"))
	for _, f := range issGlob {
		os.Remove(f)
	}
	e, _ := findEntry(root, idx)
	resp, err := verifyEntryChain(root, e)
	if err != nil {
		t.Fatalf("verifyEntryChain: %v", err)
	}
	if resp.Valid {
		t.Errorf("expected INVALID with the issuer missing from the store")
	}
}

func TestMirrorRoots_FetchesAndStores(t *testing.T) {
	at := time.Now()
	root1, _, _, rootDER, _, _ := buildPKI(t, at)
	_, _, _, rootDER2, _, _ := buildPKI(t, at)
	_ = root1

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := struct {
			Certificates []string `json:"certificates"`
		}{Certificates: []string{
			base64.StdEncoding.EncodeToString(rootDER),
			base64.StdEncoding.EncodeToString(rootDER2),
		}}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	dir := t.TempDir()
	w := &LocalFSWriter{Root: dir}
	total, present, stored, err := mirrorRoots(context.Background(), w, srv.Client(), srv.URL, "test")
	if err != nil {
		t.Fatalf("mirrorRoots: %v", err)
	}
	if total != 2 || present != 0 || stored != 2 {
		t.Fatalf("total=%d present=%d stored=%d, want 2/0/2", total, present, stored)
	}
	// Content-address invariant + loadRoots round-trip.
	certs, set, err := loadRoots(dir)
	if err != nil {
		t.Fatalf("loadRoots: %v", err)
	}
	if len(certs) != 2 || len(set) != 2 {
		t.Errorf("loaded %d certs / %d fingerprints, want 2/2", len(certs), len(set))
	}
	if _, ok := set[sha256.Sum256(rootDER)]; !ok {
		t.Errorf("root fingerprint missing from loaded set")
	}
	// Idempotent: a second mirror stores nothing.
	_, present2, stored2, _ := mirrorRoots(context.Background(), w, srv.Client(), srv.URL, "test")
	if present2 != 2 || stored2 != 0 {
		t.Errorf("rerun present=%d stored=%d, want 2/0", present2, stored2)
	}
}
