package ctlog

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// buildMerkleLeafX509 builds a valid MerkleTreeLeaf for an x509 entry.
func buildMerkleLeafX509(timestamp uint64, cert []byte) []byte {
	var buf bytes.Buffer
	buf.WriteByte(rfc6962Version)    // version
	buf.WriteByte(rfc6962LeafTypeTS) // leaf_type
	binary.Write(&buf, binary.BigEndian, timestamp)
	binary.Write(&buf, binary.BigEndian, uint16(EntryTypeX509))
	writeUint24Prefixed(&buf, cert)
	binary.Write(&buf, binary.BigEndian, uint16(0)) // extensions length = 0
	return buf.Bytes()
}

// buildMerkleLeafPrecert builds a valid MerkleTreeLeaf for a precert entry.
func buildMerkleLeafPrecert(timestamp uint64, issuerKeyHash [32]byte, tbs []byte) []byte {
	var buf bytes.Buffer
	buf.WriteByte(rfc6962Version)
	buf.WriteByte(rfc6962LeafTypeTS)
	binary.Write(&buf, binary.BigEndian, timestamp)
	binary.Write(&buf, binary.BigEndian, uint16(EntryTypePrecert))
	buf.Write(issuerKeyHash[:])
	writeUint24Prefixed(&buf, tbs)
	binary.Write(&buf, binary.BigEndian, uint16(0))
	return buf.Bytes()
}

// buildExtraDataX509 builds extra_data for an x509 entry: a uint24-prefixed
// concatenation of uint24-prefixed chain certs.
func buildExtraDataX509(chain [][]byte) []byte {
	var inner bytes.Buffer
	for _, c := range chain {
		writeUint24Prefixed(&inner, c)
	}
	var out bytes.Buffer
	writeUint24Prefixed(&out, inner.Bytes())
	return out.Bytes()
}

// buildExtraDataPrecert builds extra_data for a precert entry: uint24-prefixed
// pre_certificate followed by uint24-prefixed chain.
func buildExtraDataPrecert(preCert []byte, chain [][]byte) []byte {
	var out bytes.Buffer
	writeUint24Prefixed(&out, preCert)
	var inner bytes.Buffer
	for _, c := range chain {
		writeUint24Prefixed(&inner, c)
	}
	writeUint24Prefixed(&out, inner.Bytes())
	return out.Bytes()
}

func writeUint24Prefixed(buf *bytes.Buffer, data []byte) {
	n := len(data)
	buf.WriteByte(byte(n >> 16))
	buf.WriteByte(byte(n >> 8))
	buf.WriteByte(byte(n))
	buf.Write(data)
}

func TestParseLeafInput_X509(t *testing.T) {
	cert := []byte("fake-cert-der")
	data := buildMerkleLeafX509(1700000000000, cert)
	leaf, err := parseLeafInput(data)
	if err != nil {
		t.Fatalf("parseLeafInput: %v", err)
	}
	if leaf.Timestamp != 1700000000000 {
		t.Errorf("timestamp = %d", leaf.Timestamp)
	}
	if leaf.EntryType != EntryX509 {
		t.Errorf("entry_type = %q", leaf.EntryType)
	}
	if !bytes.Equal(leaf.Certificate, cert) {
		t.Errorf("certificate mismatch")
	}
}

func TestParseLeafInput_Precert(t *testing.T) {
	tbs := []byte("fake-tbs-der")
	var keyHash [32]byte
	for i := range keyHash {
		keyHash[i] = byte(i)
	}
	data := buildMerkleLeafPrecert(1700000000001, keyHash, tbs)
	leaf, err := parseLeafInput(data)
	if err != nil {
		t.Fatalf("parseLeafInput: %v", err)
	}
	if leaf.EntryType != EntryPrecert {
		t.Errorf("entry_type = %q", leaf.EntryType)
	}
	if leaf.PreIssuerKeyHash != keyHash {
		t.Errorf("issuer_key_hash mismatch")
	}
	if !bytes.Equal(leaf.TBSCertificate, tbs) {
		t.Errorf("tbs_certificate mismatch")
	}
}

func TestParseLeafInput_BadVersion(t *testing.T) {
	data := []byte{0xFF, 0x00}
	if _, err := parseLeafInput(data); err == nil {
		t.Errorf("expected error for bad version")
	}
}

func TestParseExtraData_X509Chain(t *testing.T) {
	cert1 := []byte("intermediate-1")
	cert2 := []byte("root-1")
	extra := buildExtraDataX509([][]byte{cert1, cert2})

	leaf := &LogLeaf{EntryType: EntryX509}
	chain, err := parseExtraData(extra, leaf)
	if err != nil {
		t.Fatalf("parseExtraData: %v", err)
	}
	if len(chain) != 2 {
		t.Fatalf("chain len = %d, want 2", len(chain))
	}
	if !bytes.Equal(chain[0], cert1) || !bytes.Equal(chain[1], cert2) {
		t.Errorf("chain DER mismatch")
	}
	want1 := sha256.Sum256(cert1)
	want2 := sha256.Sum256(cert2)
	if leaf.ChainFingerprints[0] != want1 || leaf.ChainFingerprints[1] != want2 {
		t.Errorf("chain fingerprints mismatch")
	}
}

func TestParseExtraData_PrecertChain(t *testing.T) {
	preCert := []byte("full-pre-cert")
	cert1 := []byte("intermediate-1")
	extra := buildExtraDataPrecert(preCert, [][]byte{cert1})

	leaf := &LogLeaf{EntryType: EntryPrecert}
	chain, err := parseExtraData(extra, leaf)
	if err != nil {
		t.Fatalf("parseExtraData: %v", err)
	}
	if !bytes.Equal(leaf.Certificate, preCert) {
		t.Errorf("pre_certificate not populated")
	}
	if len(chain) != 1 || !bytes.Equal(chain[0], cert1) {
		t.Errorf("chain mismatch")
	}
}

func TestRFC6962Client_RoundTrip(t *testing.T) {
	cert := []byte("test-cert-der")
	chain := [][]byte{[]byte("intermediate"), []byte("root")}
	leafIn := buildMerkleLeafX509(1700000000000, cert)
	extra := buildExtraDataX509(chain)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ct/v1/get-sth":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"tree_size": 42,
				"timestamp": 1700000000000,
			})
		case "/ct/v1/get-entries":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"entries": []map[string]string{{
					"leaf_input": base64.StdEncoding.EncodeToString(leafIn),
					"extra_data": base64.StdEncoding.EncodeToString(extra),
				}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := NewRFC6962Client(srv.URL+"/", 0)
	ctx := context.Background()

	size, err := c.TreeSize(ctx)
	if err != nil {
		t.Fatalf("TreeSize: %v", err)
	}
	if size != 42 {
		t.Errorf("TreeSize = %d, want 42", size)
	}

	leaves, err := c.FetchEntries(ctx, 0, 1)
	if err != nil {
		t.Fatalf("FetchEntries: %v", err)
	}
	if len(leaves) != 1 {
		t.Fatalf("expected 1 leaf, got %d", len(leaves))
	}
	if leaves[0].EntryIdx != 0 {
		t.Errorf("EntryIdx = %d", leaves[0].EntryIdx)
	}
	if !bytes.Equal(leaves[0].Certificate, cert) {
		t.Errorf("Certificate mismatch")
	}
	if len(leaves[0].ChainFingerprints) != 2 {
		t.Errorf("chain fp count = %d", len(leaves[0].ChainFingerprints))
	}

	// FetchIssuer should hit the cache populated from the chain.
	fp := sha256.Sum256(chain[0])
	got, err := c.FetchIssuer(ctx, fp)
	if err != nil {
		t.Fatalf("FetchIssuer: %v", err)
	}
	if !bytes.Equal(got, chain[0]) {
		t.Errorf("issuer DER mismatch")
	}

	// Unknown fingerprint must error.
	var unknown [32]byte
	if _, err := c.FetchIssuer(ctx, unknown); err == nil {
		t.Errorf("expected error for unknown fingerprint")
	}
}

func TestRFC6962Client_FetchEntriesStopsOnEmpty(t *testing.T) {
	// Server returns one entry then an empty page — client should stop after
	// the empty response rather than spinning.
	calls := 0
	cert := []byte("c")
	leafIn := buildMerkleLeafX509(1, cert)
	extra := buildExtraDataX509(nil)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ct/v1/get-entries" {
			http.NotFound(w, r)
			return
		}
		calls++
		w.Header().Set("Content-Type", "application/json")
		if calls == 1 {
			json.NewEncoder(w).Encode(map[string]any{
				"entries": []map[string]string{{
					"leaf_input": base64.StdEncoding.EncodeToString(leafIn),
					"extra_data": base64.StdEncoding.EncodeToString(extra),
				}},
			})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"entries": []any{}})
	}))
	defer srv.Close()

	c := NewRFC6962Client(srv.URL+"/", 0)
	leaves, err := c.FetchEntries(context.Background(), 0, 100)
	if err != nil {
		t.Fatalf("FetchEntries: %v", err)
	}
	if len(leaves) != 1 {
		t.Errorf("expected 1 leaf, got %d", len(leaves))
	}
	if calls != 2 {
		t.Errorf("expected 2 server calls (1 page + 1 empty), got %d", calls)
	}
}
