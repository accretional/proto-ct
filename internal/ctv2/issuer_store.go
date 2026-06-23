package ctv2

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"sync"
	"sync/atomic"

	pb "github.com/accretional/proto-ct/gen/ctingestion/v2"
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

	// resolver, when set (static-ct-api path), fetches a chain cert's DER by its
	// SHA-256 fingerprint from the log's issuer endpoint. nil for RFC6962, whose
	// chain certs arrive inline with the entries.
	resolver func(context.Context, [32]byte) ([]byte, error)

	mu   sync.Mutex
	seen map[[32]byte]struct{}

	fetched atomic.Int64 // issuers fetched + stored via the resolver
	failed  atomic.Int64 // resolver fetch/verify failures (best-effort; not fatal)
	errMu   sync.Mutex
	errs    []string // bounded sample of resolver failures
}

func newIssuerStore(w Writer, resolver func(context.Context, [32]byte) ([]byte, error)) *issuerStore {
	return &issuerStore{w: w, resolver: resolver, seen: make(map[[32]byte]struct{})}
}

// ingest persists the issuer certs implied by a batch. RFC6962 batches carry the
// chain DER inline (b.chains); a write failure there is fatal. static batches
// carry only fingerprints (inside the entries) — when a resolver is configured we
// fetch the missing certs best-effort: failures are counted but never fail the
// ingest, so a flaky or absent issuer endpoint can't break archiving (the
// standalone ResolveIssuers pass backfills later).
func (s *issuerStore) ingest(ctx context.Context, b entryBatch) error {
	if len(b.chains) > 0 {
		if err := s.put(ctx, b.chains); err != nil {
			return err
		}
	}
	if s.resolver != nil {
		s.resolveFromEntries(ctx, b.entries)
	}
	return nil
}

// resolveFromEntries fetches+stores any not-yet-seen, not-already-stored issuer
// fingerprints referenced by the batch's entries. Best-effort.
func (s *issuerStore) resolveFromEntries(ctx context.Context, entries []*pb.RawLogEntry) {
	// Collapse to the batch's unique fingerprints first to cut lock churn.
	local := make(map[[32]byte]struct{})
	for _, e := range entries {
		for _, fp := range e.GetChainFingerprints() {
			if len(fp) == sha256.Size {
				var a [32]byte
				copy(a[:], fp)
				local[a] = struct{}{}
			}
		}
	}
	for fp := range local {
		if ctx.Err() != nil {
			return
		}
		s.mu.Lock()
		_, known := s.seen[fp]
		if !known {
			s.seen[fp] = struct{}{}
		}
		s.mu.Unlock()
		if known {
			continue
		}
		rel := issuerStorePath(fp)
		if ok, _ := s.w.Has(ctx, rel); ok {
			continue // already stored: cheap no-op (the common re-run case)
		}
		der, err := s.resolver(ctx, fp)
		if err == nil {
			err = s.w.PutIfAbsent(ctx, rel, der)
		}
		if err != nil {
			// Keep `seen` set so a persistently-failing endpoint isn't hammered
			// once per batch for the rest of the run.
			s.failed.Add(1)
			s.errMu.Lock()
			if len(s.errs) < 10 {
				s.errs = append(s.errs, fmt.Sprintf("%x: %v", fp, err))
			}
			s.errMu.Unlock()
			continue
		}
		s.fetched.Add(1)
	}
}

// resolveStats returns the resolver outcome (0/0/nil when no resolver is set).
func (s *issuerStore) resolveStats() (fetched, failed int64, errs []string) {
	s.errMu.Lock()
	defer s.errMu.Unlock()
	return s.fetched.Load(), s.failed.Load(), append([]string(nil), s.errs...)
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
