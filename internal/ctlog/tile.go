package ctlog

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	EntryTypeX509    = 0
	EntryTypePrecert = 1
)

// TileLeaf is a parsed entry from a static-ct-api data tile.
type TileLeaf struct {
	Timestamp         uint64
	EntryType         uint16
	Certificate       []byte   // DER-encoded cert (x509 entry) or pre-cert (precert entry, from TileLeaf field)
	TBSCertificate    []byte   // DER-encoded TBSCertificate (precert only, from TimestampedEntry)
	PreIssuerKeyHash  [32]byte // issuer key hash (precert only)
	Extensions        []byte
	ChainFingerprints [][32]byte // SHA-256 hashes of issuer certs in chain
}

// ParseTile parses a complete data tile returning up to maxEntries TileLeaf records.
func ParseTile(data []byte, maxEntries int) ([]*TileLeaf, error) {
	r := bytes.NewReader(data)
	var entries []*TileLeaf
	for r.Len() > 0 && (maxEntries <= 0 || len(entries) < maxEntries) {
		leaf, err := parseTileLeaf(r)
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			return nil, fmt.Errorf("entry %d: %w", len(entries), err)
		}
		entries = append(entries, leaf)
	}
	return entries, nil
}

func parseTileLeaf(r *bytes.Reader) (*TileLeaf, error) {
	leaf := &TileLeaf{}

	if err := binary.Read(r, binary.BigEndian, &leaf.Timestamp); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.BigEndian, &leaf.EntryType); err != nil {
		return nil, err
	}

	switch leaf.EntryType {
	case EntryTypeX509:
		cert, err := readUint24LenPrefixed(r)
		if err != nil {
			return nil, fmt.Errorf("x509 cert: %w", err)
		}
		leaf.Certificate = cert

	case EntryTypePrecert:
		if _, err := io.ReadFull(r, leaf.PreIssuerKeyHash[:]); err != nil {
			return nil, fmt.Errorf("issuer key hash: %w", err)
		}
		tbs, err := readUint24LenPrefixed(r)
		if err != nil {
			return nil, fmt.Errorf("tbs cert: %w", err)
		}
		leaf.TBSCertificate = tbs

	default:
		return nil, fmt.Errorf("unknown entry type: %d", leaf.EntryType)
	}

	// CtExtensions (2-byte length prefix)
	ext, err := readUint16LenPrefixed(r)
	if err != nil {
		return nil, fmt.Errorf("extensions: %w", err)
	}
	leaf.Extensions = ext

	// For precert entries, TileLeaf includes the actual pre-certificate (ASN.1Cert)
	if leaf.EntryType == EntryTypePrecert {
		preCert, err := readUint24LenPrefixed(r)
		if err != nil {
			return nil, fmt.Errorf("pre_certificate: %w", err)
		}
		leaf.Certificate = preCert
	}

	// certificate_chain fingerprints (2-byte total byte length, each fp is 32 bytes)
	chainBytes, err := readUint16LenPrefixed(r)
	if err != nil {
		return nil, fmt.Errorf("chain fingerprints: %w", err)
	}
	for i := 0; i+32 <= len(chainBytes); i += 32 {
		var fp [32]byte
		copy(fp[:], chainBytes[i:i+32])
		leaf.ChainFingerprints = append(leaf.ChainFingerprints, fp)
	}

	return leaf, nil
}

func readUint24LenPrefixed(r *bytes.Reader) ([]byte, error) {
	var b [3]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return nil, err
	}
	n := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func readUint16LenPrefixed(r *bytes.Reader) ([]byte, error) {
	var n uint16
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, err
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
