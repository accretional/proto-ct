package ctlog

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// buildX509Entry constructs a minimal TileLeaf binary for an x509 entry.
func buildX509Entry(t *testing.T, timestamp uint64, cert []byte, chainFPs [][32]byte) []byte {
	t.Helper()
	var buf bytes.Buffer

	// timestamp (8 bytes)
	if err := binary.Write(&buf, binary.BigEndian, timestamp); err != nil {
		t.Fatal(err)
	}
	// entry_type = 0 (x509)
	if err := binary.Write(&buf, binary.BigEndian, uint16(0)); err != nil {
		t.Fatal(err)
	}
	// cert length (3 bytes)
	n := len(cert)
	buf.Write([]byte{byte(n >> 16), byte(n >> 8), byte(n)})
	buf.Write(cert)
	// extensions length (2 bytes) = 0
	if err := binary.Write(&buf, binary.BigEndian, uint16(0)); err != nil {
		t.Fatal(err)
	}
	// chain fingerprints
	chainLen := uint16(len(chainFPs) * 32)
	if err := binary.Write(&buf, binary.BigEndian, chainLen); err != nil {
		t.Fatal(err)
	}
	for _, fp := range chainFPs {
		buf.Write(fp[:])
	}
	return buf.Bytes()
}

func buildPrecertEntry(t *testing.T, timestamp uint64, issuerKeyHash [32]byte, tbs []byte, preCert []byte, chainFPs [][32]byte) []byte {
	t.Helper()
	var buf bytes.Buffer

	binary.Write(&buf, binary.BigEndian, timestamp)
	binary.Write(&buf, binary.BigEndian, uint16(1)) // precert

	buf.Write(issuerKeyHash[:])
	n := len(tbs)
	buf.Write([]byte{byte(n >> 16), byte(n >> 8), byte(n)})
	buf.Write(tbs)

	binary.Write(&buf, binary.BigEndian, uint16(0)) // no extensions

	// pre_certificate (TileLeaf field)
	m := len(preCert)
	buf.Write([]byte{byte(m >> 16), byte(m >> 8), byte(m)})
	buf.Write(preCert)

	chainLen := uint16(len(chainFPs) * 32)
	binary.Write(&buf, binary.BigEndian, chainLen)
	for _, fp := range chainFPs {
		buf.Write(fp[:])
	}
	return buf.Bytes()
}

func TestParseTile_X509Entry(t *testing.T) {
	cert := []byte("fake-der-cert-bytes")
	var fp [32]byte
	for i := range fp {
		fp[i] = byte(i)
	}
	ts := uint64(1_755_000_000_000)

	data := buildX509Entry(t, ts, cert, [][32]byte{fp})
	leaves, err := ParseTile(data, 0)
	if err != nil {
		t.Fatalf("ParseTile: %v", err)
	}
	if len(leaves) != 1 {
		t.Fatalf("expected 1 leaf, got %d", len(leaves))
	}
	leaf := leaves[0]
	if leaf.Timestamp != ts {
		t.Errorf("timestamp: got %d, want %d", leaf.Timestamp, ts)
	}
	if leaf.EntryType != EntryTypeX509 {
		t.Errorf("entry type: got %d, want %d", leaf.EntryType, EntryTypeX509)
	}
	if !bytes.Equal(leaf.Certificate, cert) {
		t.Errorf("cert mismatch")
	}
	if len(leaf.ChainFingerprints) != 1 || leaf.ChainFingerprints[0] != fp {
		t.Errorf("fingerprint mismatch")
	}
}

func TestParseTile_PrecertEntry(t *testing.T) {
	var ikHash [32]byte
	ikHash[0] = 0xAB
	tbs := []byte("fake-tbs-cert")
	preCert := []byte("fake-pre-cert-der")
	var fp [32]byte
	fp[31] = 0xFF
	ts := uint64(1_755_111_222_333)

	data := buildPrecertEntry(t, ts, ikHash, tbs, preCert, [][32]byte{fp})
	leaves, err := ParseTile(data, 0)
	if err != nil {
		t.Fatalf("ParseTile: %v", err)
	}
	if len(leaves) != 1 {
		t.Fatalf("expected 1 leaf, got %d", len(leaves))
	}
	leaf := leaves[0]
	if leaf.Timestamp != ts {
		t.Errorf("timestamp: got %d, want %d", leaf.Timestamp, ts)
	}
	if leaf.EntryType != EntryTypePrecert {
		t.Errorf("entry type: got %d, want %d", leaf.EntryType, EntryTypePrecert)
	}
	if leaf.PreIssuerKeyHash != ikHash {
		t.Errorf("issuer key hash mismatch")
	}
	if !bytes.Equal(leaf.TBSCertificate, tbs) {
		t.Errorf("tbs cert mismatch")
	}
	if !bytes.Equal(leaf.Certificate, preCert) {
		t.Errorf("pre_certificate mismatch")
	}
	if len(leaf.ChainFingerprints) != 1 || leaf.ChainFingerprints[0] != fp {
		t.Errorf("fingerprint mismatch")
	}
}

func TestParseTile_MultipleEntries(t *testing.T) {
	cert := []byte("abc")
	e1 := buildX509Entry(t, 100, cert, nil)
	e2 := buildX509Entry(t, 200, cert, nil)
	e3 := buildX509Entry(t, 300, cert, nil)

	data := append(append(e1, e2...), e3...)
	leaves, err := ParseTile(data, 0)
	if err != nil {
		t.Fatalf("ParseTile: %v", err)
	}
	if len(leaves) != 3 {
		t.Fatalf("expected 3 leaves, got %d", len(leaves))
	}
	for i, ts := range []uint64{100, 200, 300} {
		if leaves[i].Timestamp != ts {
			t.Errorf("leaf %d: timestamp %d, want %d", i, leaves[i].Timestamp, ts)
		}
	}
}

func TestParseTile_MaxEntries(t *testing.T) {
	cert := []byte("x")
	var all []byte
	for i := 0; i < 5; i++ {
		all = append(all, buildX509Entry(t, uint64(i), cert, nil)...)
	}
	leaves, err := ParseTile(all, 3)
	if err != nil {
		t.Fatalf("ParseTile: %v", err)
	}
	if len(leaves) != 3 {
		t.Fatalf("expected 3 leaves (maxEntries=3), got %d", len(leaves))
	}
}

func TestTileIndexPath(t *testing.T) {
	cases := []struct {
		n    int
		want string
	}{
		{0, "000"},
		{1, "001"},
		{999, "999"},
		{1000, "x001/000"},
		{1234, "x001/234"},
		{999999, "x999/999"},
		{1000000, "x001/x000/000"},
		{1234067, "x001/x234/067"},
	}
	for _, c := range cases {
		got := tileIndexPath(c.n)
		if got != c.want {
			t.Errorf("tileIndexPath(%d) = %q, want %q", c.n, got, c.want)
		}
	}
}
