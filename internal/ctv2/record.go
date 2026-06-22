// Package ctv2 implements the proto-ct v2 raw-leaf range archiver: a stateless
// service that fetches a half-open entry range [start, end) from one CT log and
// persists the Merkle tree leaves verbatim to disk as a base layer. Cert/subject
// parsing is deferred to later tools.
package ctv2

import (
	"fmt"

	pb "github.com/accretional/proto-ct/gen/ctingestion/v2"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	"filippo.io/sunlight"
)

// rawEntryFromRFC6962 builds a unified RawLogEntry from a verbatim get-entries
// leaf. The leaf_input/extra_data are stored as-is; only the MerkleTreeLeaf
// header is parsed (cheaply, no x509) to recover the timestamp + entry type
// needed for time partitioning.
func rawEntryFromRFC6962(index int64, leafInput, extraData []byte) (*pb.RawLogEntry, error) {
	var leaf ct.MerkleTreeLeaf
	if _, err := tls.Unmarshal(leafInput, &leaf); err != nil {
		return nil, fmt.Errorf("parse MerkleTreeLeaf @%d: %w", index, err)
	}
	if leaf.TimestampedEntry == nil {
		return nil, fmt.Errorf("entry @%d: nil TimestampedEntry", index)
	}
	return &pb.RawLogEntry{
		Index:       index,
		TimestampMs: int64(leaf.TimestampedEntry.Timestamp),
		EntryType:   entryType(leaf.TimestampedEntry.EntryType == ct.PrecertLogEntryType),
		Source:      pb.LogProtocol_LOG_PROTOCOL_RFC6962,
		LeafInput:   leafInput,
		ExtraData:   extraData,
	}, nil
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
