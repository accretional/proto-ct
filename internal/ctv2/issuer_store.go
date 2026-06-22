package ctv2

import (
	"context"
	"encoding/hex"
	"path"
	"sync"
)

// chainCert is one issuer-chain certificate (DER) together with its SHA-256
// fingerprint — the same hash recorded in RawLogEntry.chain_fingerprints and used
// as the issuer store's content address.
type chainCert struct {
	hash [32]byte
	der  []byte
}

const issuerDir = "issuers"

// issuerStorePath is the store-relative path for a chain cert: issuers/<hex>.der.
func issuerStorePath(hash [32]byte) string {
	return path.Join(issuerDir, hex.EncodeToString(hash[:])+".der")
}

// issuerStore writes each unique issuer-chain certificate exactly once to a
// shared, content-addressed store under <output_root>/issuers/<hex>.der. RFC 6962
// get-entries returns the full issuer chain verbatim in extra_data (~3.9 KB of
// mostly-duplicate CA certs per leaf); rather than repeat that in every record we
// keep only chain_fingerprints in the leaf and land the certs here once — a few
// thousand CA certs versus millions of copies (storage opt O1).
//
// Because files are content-addressed and PutIfAbsent is idempotent, concurrent
// range jobs for the same log (same output_root) can share the store with no
// coordination, preserving v2's stateless fan-out model. The in-memory `seen` set
// just avoids redundant filesystem stats within one run.
type issuerStore struct {
	w Writer

	mu   sync.Mutex
	seen map[[32]byte]struct{}
}

func newIssuerStore(w Writer) *issuerStore {
	return &issuerStore{w: w, seen: make(map[[32]byte]struct{})}
}

// put writes any not-yet-seen chain certs to the store. Safe for concurrent use.
func (s *issuerStore) put(ctx context.Context, certs []chainCert) error {
	for _, c := range certs {
		s.mu.Lock()
		_, known := s.seen[c.hash]
		if !known {
			s.seen[c.hash] = struct{}{}
		}
		s.mu.Unlock()
		if known {
			continue
		}
		if err := s.w.PutIfAbsent(ctx, issuerStorePath(c.hash), c.der); err != nil {
			// Let a later batch retry this cert rather than silently dropping it.
			s.mu.Lock()
			delete(s.seen, c.hash)
			s.mu.Unlock()
			return err
		}
	}
	return nil
}
