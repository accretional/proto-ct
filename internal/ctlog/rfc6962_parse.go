package ctlog

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
)

// RFC 6962 / 4.6 MerkleTreeLeaf encoding constants.
const (
	rfc6962Version    = 0 // v1
	rfc6962LeafTypeTS = 0 // TimestampedEntry
)

// parseLeafInput decodes the leaf_input field of a get-entries response.
// It produces a LogLeaf with EntryIdx unset (the caller fills it from the
// request range) and chain fingerprints unset (filled by parseExtraData).
func parseLeafInput(data []byte) (*LogLeaf, error) {
	r := bytes.NewReader(data)
	var version, leafType uint8
	if err := binary.Read(r, binary.BigEndian, &version); err != nil {
		return nil, fmt.Errorf("version: %w", err)
	}
	if version != rfc6962Version {
		return nil, fmt.Errorf("unsupported MerkleTreeLeaf version %d", version)
	}
	if err := binary.Read(r, binary.BigEndian, &leafType); err != nil {
		return nil, fmt.Errorf("leaf_type: %w", err)
	}
	if leafType != rfc6962LeafTypeTS {
		return nil, fmt.Errorf("unsupported leaf_type %d", leafType)
	}

	leaf := &LogLeaf{}
	if err := binary.Read(r, binary.BigEndian, &leaf.Timestamp); err != nil {
		return nil, fmt.Errorf("timestamp: %w", err)
	}
	var entryType uint16
	if err := binary.Read(r, binary.BigEndian, &entryType); err != nil {
		return nil, fmt.Errorf("entry_type: %w", err)
	}

	switch entryType {
	case EntryTypeX509:
		leaf.EntryType = EntryX509
		cert, err := readUint24LenPrefixed(r)
		if err != nil {
			return nil, fmt.Errorf("x509 cert: %w", err)
		}
		leaf.Certificate = cert

	case EntryTypePrecert:
		leaf.EntryType = EntryPrecert
		if _, err := io.ReadFull(r, leaf.PreIssuerKeyHash[:]); err != nil {
			return nil, fmt.Errorf("issuer_key_hash: %w", err)
		}
		tbs, err := readUint24LenPrefixed(r)
		if err != nil {
			return nil, fmt.Errorf("tbs_certificate: %w", err)
		}
		leaf.TBSCertificate = tbs

	default:
		return nil, fmt.Errorf("unknown entry_type %d", entryType)
	}

	ext, err := readUint16LenPrefixed(r)
	if err != nil {
		return nil, fmt.Errorf("extensions: %w", err)
	}
	leaf.Extensions = ext
	return leaf, nil
}

// parseExtraData fills in chain fingerprints (and Certificate for precert entries)
// from the extra_data field of a get-entries response. It also returns the chain
// DER bytes so the caller can populate an issuer cache.
func parseExtraData(data []byte, leaf *LogLeaf) (chainDER [][]byte, err error) {
	r := bytes.NewReader(data)

	switch leaf.EntryType {
	case EntryX509:
		// extra_data = ASN.1Cert certificate_chain<0..2^24-1>
		chainBytes, err := readUint24LenPrefixed(r)
		if err != nil {
			return nil, fmt.Errorf("certificate_chain: %w", err)
		}
		return parseCertChain(chainBytes, leaf)

	case EntryPrecert:
		// extra_data = ASN.1Cert pre_certificate; ASN.1Cert precertificate_chain<0..2^24-1>
		preCert, err := readUint24LenPrefixed(r)
		if err != nil {
			return nil, fmt.Errorf("pre_certificate: %w", err)
		}
		leaf.Certificate = preCert
		chainBytes, err := readUint24LenPrefixed(r)
		if err != nil {
			return nil, fmt.Errorf("precertificate_chain: %w", err)
		}
		return parseCertChain(chainBytes, leaf)
	}
	return nil, fmt.Errorf("unknown entry type %q", leaf.EntryType)
}

// parseCertChain splits a concatenation of uint24-prefixed ASN.1Cert entries
// and populates leaf.ChainFingerprints with each cert's SHA-256.
func parseCertChain(chainBytes []byte, leaf *LogLeaf) ([][]byte, error) {
	var chain [][]byte
	r := bytes.NewReader(chainBytes)
	for r.Len() > 0 {
		cert, err := readUint24LenPrefixed(r)
		if err != nil {
			return nil, fmt.Errorf("chain cert: %w", err)
		}
		fp := sha256.Sum256(cert)
		leaf.ChainFingerprints = append(leaf.ChainFingerprints, fp)
		chain = append(chain, cert)
	}
	return chain, nil
}
