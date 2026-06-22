// Package ctv2 implements the proto-ct v2 raw-leaf range archiver: a stateless
// service that fetches a half-open entry range [start, end) from one CT log and
// persists the Merkle tree leaves verbatim to disk as a base layer. Cert/subject
// parsing is deferred to later tools.
package ctv2

import (
	"crypto/sha256"
	"fmt"

	pb "github.com/accretional/proto-ct/gen/ctingestion/v2"
	ct "github.com/google/certificate-transparency-go"
	"filippo.io/sunlight"
)

// rawEntryFromRFC6962 builds a unified RawLogEntry from a verbatim get-entries
// leaf. leaf_input is kept verbatim (it embeds the leaf cert / TBSCertificate and
// the timestamp). extra_data is NOT stored: it carries the issuer chain (~79% of
// the record, mostly duplicate CA certs), so we parse it out, replace it with the
// per-cert SHA-256 chain_fingerprints, and return the chain certs for the caller
// to dedupe into the shared issuer store (storage opt O1/O3). For precerts the
// full submitted precertificate (the only part of extra_data not recoverable from
// leaf_input) is preserved in precertificate.
func rawEntryFromRFC6962(index int64, leafInput, extraData []byte) (*pb.RawLogEntry, []chainCert, error) {
	rle, err := ct.RawLogEntryFromLeaf(index, &ct.LeafEntry{LeafInput: leafInput, ExtraData: extraData})
	if err != nil {
		return nil, nil, fmt.Errorf("parse raw log entry @%d: %w", index, err)
	}
	te := rle.Leaf.TimestampedEntry
	if te == nil {
		return nil, nil, fmt.Errorf("entry @%d: nil TimestampedEntry", index)
	}
	isPrecert := te.EntryType == ct.PrecertLogEntryType
	r := &pb.RawLogEntry{
		Index:       index,
		TimestampMs: int64(te.Timestamp),
		EntryType:   entryType(isPrecert),
		Source:      pb.LogProtocol_LOG_PROTOCOL_RFC6962,
		LeafInput:   leafInput, // verbatim; embeds the leaf cert / TBSCertificate
	}
	if isPrecert {
		// leaf_input holds only the TBSCertificate; the full submitted precert is
		// in extra_data (rle.Cert), so keep it. issuer_key_hash is in leaf_input
		// too but mirrored here for parity with the static record.
		r.Precertificate = rle.Cert.Data
		if pe := te.PrecertEntry; pe != nil {
			ikh := pe.IssuerKeyHash
			r.IssuerKeyHash = ikh[:]
		}
	}
	var chains []chainCert
	for _, c := range rle.Chain {
		h := sha256.Sum256(c.Data)
		r.ChainFingerprints = append(r.ChainFingerprints, h[:])
		chains = append(chains, chainCert{hash: h, der: c.Data})
	}
	return r, chains, nil
}

// rawEntryFromStatic builds a unified RawLogEntry from a sunlight LogEntry. The
// reconstructed MerkleTreeLeaf is stored in leaf_input so the record shape
// matches the RFC6962 path. The leaf cert is NOT stored separately: it is already
// embedded in leaf_input (storage opt O2), so we drop sunlight's split
// Certificate field to avoid duplicating ~1.4 KB/entry. precertificate is kept
// because the full submitted precert is not recoverable from leaf_input.
func rawEntryFromStatic(e *sunlight.LogEntry) *pb.RawLogEntry {
	r := &pb.RawLogEntry{
		Index:          e.LeafIndex,
		TimestampMs:    e.Timestamp,
		EntryType:      entryType(e.IsPrecert),
		Source:         pb.LogProtocol_LOG_PROTOCOL_STATIC_CT_API,
		LeafInput:      e.MerkleTreeLeaf(),
		Precertificate: e.PreCertificate,
	}
	for _, fp := range e.ChainFingerprints {
		r.ChainFingerprints = append(r.ChainFingerprints, fp[:])
	}
	if e.IsPrecert {
		ikh := e.IssuerKeyHash
		r.IssuerKeyHash = ikh[:]
	}
	return r
}

func entryType(isPrecert bool) pb.EntryType {
	if isPrecert {
		return pb.EntryType_ENTRY_TYPE_PRECERT
	}
	return pb.EntryType_ENTRY_TYPE_X509
}
