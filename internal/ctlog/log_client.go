package ctlog

import "context"

// LogClient is the protocol-agnostic interface implemented by both the
// static-ct-api tile client and (eventually) the RFC 6962 get-entries client.
// All entry indices are global (0..tree_size); tile boundaries are an
// implementation detail of the tile transport.
type LogClient interface {
	// TreeSize returns the current signed tree size.
	TreeSize(ctx context.Context) (int64, error)

	// FetchEntries returns leaves with global indices in [start, end).
	FetchEntries(ctx context.Context, start, end int64) ([]*LogLeaf, error)

	// FetchIssuer returns the DER bytes of an issuer cert by SHA-256 fingerprint.
	FetchIssuer(ctx context.Context, fp [32]byte) ([]byte, error)

	// LogID is the canonical 32-byte log identity (SHA-256 of SubjectPublicKeyInfo).
	LogID() [32]byte
}

// EntryType distinguishes regular X.509 leaves from precert leaves.
type EntryType string

const (
	EntryX509    EntryType = "x509"
	EntryPrecert EntryType = "precert"
)

// LogLeaf is a parsed CT log entry, normalised across protocols.
type LogLeaf struct {
	EntryIdx          int64      // global index within the log
	EntryType         EntryType  // x509 or precert
	Timestamp         uint64     // ms since epoch (CT SCT timestamp)
	Certificate       []byte     // DER cert (x509) or pre-certificate (precert)
	TBSCertificate    []byte     // DER TBSCertificate (precert only)
	PreIssuerKeyHash  [32]byte   // precert only
	Extensions        []byte     // CT extensions blob
	ChainFingerprints [][32]byte // SHA-256 of issuer chain certs
}

// Compile-time check that both client implementations satisfy LogClient.
var (
	_ LogClient = (*TileClient)(nil)
	_ LogClient = (*RFC6962Client)(nil)
)

// tileLeafToLogLeaf adapts an internal TileLeaf to the protocol-agnostic LogLeaf.
func tileLeafToLogLeaf(t *TileLeaf, entryIdx int64) *LogLeaf {
	et := EntryX509
	if t.EntryType == EntryTypePrecert {
		et = EntryPrecert
	}
	return &LogLeaf{
		EntryIdx:          entryIdx,
		EntryType:         et,
		Timestamp:         t.Timestamp,
		Certificate:       t.Certificate,
		TBSCertificate:    t.TBSCertificate,
		PreIssuerKeyHash:  t.PreIssuerKeyHash,
		Extensions:        t.Extensions,
		ChainFingerprints: t.ChainFingerprints,
	}
}
