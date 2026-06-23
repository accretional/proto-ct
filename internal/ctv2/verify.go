package ctv2

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	pb "github.com/accretional/proto-ct/gen/ctingestion/v2"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	cx509 "github.com/google/certificate-transparency-go/x509"
	"google.golang.org/protobuf/proto"
)

// findEntry locates the entry at index by reading the single partition whose
// filename range brackets it.
func findEntry(root string, index int64) (*pb.RawLogEntry, error) {
	var found *pb.RawLogEntry
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := strings.TrimSuffix(d.Name(), ".gz")
		if d.IsDir() || !strings.HasSuffix(name, ".binpb") {
			return nil
		}
		r, ok := parseRangeFromName(d.Name())
		if !ok || index < r.start || index >= r.end {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if strings.HasSuffix(d.Name(), ".gz") {
			zr, err := gzip.NewReader(bytes.NewReader(data))
			if err != nil {
				return fmt.Errorf("%s: gunzip: %w", p, err)
			}
			if data, err = io.ReadAll(zr); err != nil {
				return fmt.Errorf("%s: gunzip: %w", p, err)
			}
		}
		var batch pb.RawLogEntryBatch
		if err := proto.Unmarshal(data, &batch); err != nil {
			return fmt.Errorf("%s: unmarshal: %w", p, err)
		}
		for _, e := range batch.GetEntries() {
			if e.GetIndex() == index {
				found = e
				return fs.SkipAll
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if found == nil {
		return nil, fmt.Errorf("index %d not found under %s", index, root)
	}
	return found, nil
}

// leafCertificate extracts the leaf cert as x509: from leaf_input for X509
// entries, from the precertificate field for precerts (leaf_input holds only the
// poisoned TBS there). crypto/x509 parses precerts fine — the CT poison goes to
// UnhandledCriticalExtensions, which only matters to policy-aware Verify, not the
// signature-path checks we do.
func leafCertificate(e *pb.RawLogEntry) (*cx509.Certificate, error) {
	if e.GetEntryType() == pb.EntryType_ENTRY_TYPE_PRECERT {
		if len(e.GetPrecertificate()) == 0 {
			return nil, fmt.Errorf("precert entry has no precertificate")
		}
		return cx509.ParseCertificate(e.GetPrecertificate())
	}
	var leaf ct.MerkleTreeLeaf
	if _, err := tls.Unmarshal(e.GetLeafInput(), &leaf); err != nil {
		return nil, fmt.Errorf("parse leaf_input: %w", err)
	}
	if leaf.TimestampedEntry == nil || leaf.TimestampedEntry.X509Entry == nil {
		return nil, fmt.Errorf("leaf_input has no X509 entry")
	}
	return cx509.ParseCertificate(leaf.TimestampedEntry.X509Entry.Data)
}

// verifyEntryChain reconstructs and validates one entry's chain offline: leaf +
// issuer chain (local store, by fingerprint) verified link-by-link, terminating
// at a mirrored accepted root. Signature path only (not full RFC5280 policy), so
// it works uniformly for precerts (poison/EKU don't matter to issuance).
func verifyEntryChain(root string, e *pb.RawLogEntry) (*pb.VerifyEntryResponse, error) {
	resp := &pb.VerifyEntryResponse{}

	leaf, err := leafCertificate(e)
	if err != nil {
		resp.Reason = err.Error()
		return resp, nil
	}
	resp.LeafSubject = leaf.Subject.String()

	// Issuer chain, in stored order (leaf's issuer first).
	var chain []*cx509.Certificate
	for _, fp := range e.GetChainFingerprints() {
		if len(fp) != sha256.Size {
			resp.Reason = "malformed chain fingerprint"
			return resp, nil
		}
		var h [32]byte
		copy(h[:], fp)
		der, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(issuerStorePath(h))))
		if err != nil {
			resp.Reason = fmt.Sprintf("missing issuer %s in store (run ResolveIssuers): %v", hex.EncodeToString(fp), err)
			return resp, nil
		}
		c, err := cx509.ParseCertificate(der)
		if err != nil {
			resp.Reason = fmt.Sprintf("parse issuer %s: %v", hex.EncodeToString(fp), err)
			return resp, nil
		}
		chain = append(chain, c)
		resp.ChainSubjects = append(resp.ChainSubjects, c.Subject.String())
	}

	// Verify the issuance signature path leaf -> chain[0] -> ... -> chain[last].
	prev := leaf
	for _, c := range chain {
		if err := prev.CheckSignatureFrom(c); err != nil {
			resp.Reason = fmt.Sprintf("broken link %q signed by %q: %v", prev.Subject, c.Subject, err)
			return resp, nil
		}
		prev = c
	}
	top := prev // last chain cert (or the leaf, if no chain)

	// Anchor: `top` must be a mirrored accepted root, or be signed by one.
	roots, set, err := loadRoots(root)
	if err != nil {
		return nil, err
	}
	if _, ok := set[sha256.Sum256(top.Raw)]; ok {
		resp.AnchorSubject = top.Subject.String()
		resp.Valid = true
	} else {
		for _, r := range roots {
			if top.CheckSignatureFrom(r) == nil {
				resp.AnchorSubject = r.Subject.String()
				resp.Valid = true
				break
			}
		}
		if !resp.Valid {
			resp.Reason = fmt.Sprintf("chain terminates at %q, which is not a mirrored accepted root (run MirrorRoots)", top.Subject)
			return resp, nil
		}
	}

	// Report time-validity at the entry's SCT timestamp (informational: CT logs
	// accept certs valid at submission, so this is usually true even for entries
	// long expired by wall-clock now).
	t := time.UnixMilli(e.GetTimestampMs())
	resp.WithinValidity = true
	for _, c := range append([]*cx509.Certificate{leaf}, chain...) {
		if t.Before(c.NotBefore) || t.After(c.NotAfter) {
			resp.WithinValidity = false
			break
		}
	}
	return resp, nil
}
