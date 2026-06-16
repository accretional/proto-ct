package ctv2

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"

	"filippo.io/sunlight"
	pb "github.com/accretional/proto-ct/gen/ctingestion/v2"
)

// staticFetcher wraps filippo.io/sunlight's static-ct-api client. Entries are
// authenticated against the log checkpoint (nearly free), so the static path is
// always "verified" regardless of the request's verify flag. fetch_concurrency
// maps to sunlight's ConcurrencyLimit.
type staticFetcher struct {
	client *sunlight.Client
}

func newStaticFetcher(sel *pb.LogSelector, userAgent string, qps float64, concurrency int) (*staticFetcher, error) {
	if len(sel.GetPublicKey()) == 0 {
		return nil, errors.New("static-ct-api log requires public_key (DER SPKI) to verify the checkpoint")
	}
	pub, err := x509.ParsePKIXPublicKey(sel.GetPublicKey())
	if err != nil {
		return nil, fmt.Errorf("parse static log public key: %w", err)
	}
	cfg := &sunlight.ClientConfig{
		MonitoringPrefix: sel.GetMonitoringUrl(),
		PublicKey:        pub,
		UserAgent:        userAgent,
		ConcurrencyLimit: concurrency,
		HTTPClient:       rateLimitedClient(qps),
	}
	c, err := sunlight.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("new sunlight client: %w", err)
	}
	return &staticFetcher{client: c}, nil
}

// sth returns the static log's current checkpoint as an STHResponse. The
// static-ct-api checkpoint carries no RFC6962-style signature blob, so
// tree_head_signature is left empty; the timestamp is recovered from the note's
// RFC6962 co-signature when present.
func (f *staticFetcher) sth(ctx context.Context, logID []byte) (*pb.STHResponse, error) {
	cp, n, err := f.client.Checkpoint(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch checkpoint: %w", err)
	}
	var tsMs int64
	if n != nil {
		for _, sig := range n.Sigs {
			if ts, err := sunlight.RFC6962SignatureTimestamp(sig); err == nil {
				tsMs = ts
				break
			}
		}
	}
	hash := cp.Hash
	return &pb.STHResponse{
		LogId:          logID,
		TreeSize:       cp.N,
		Timestamp:      tsMs,
		Sha256RootHash: hash[:],
	}, nil
}

func (f *staticFetcher) Fetch(ctx context.Context, start, end int64, emit func(*pb.RawLogEntry) error) error {
	cp, _, err := f.client.Checkpoint(ctx)
	if err != nil {
		return fmt.Errorf("fetch checkpoint: %w", err)
	}
	if cp.N < end {
		end = cp.N // can't read past the current tree
	}
	if start >= end {
		return nil
	}
	for idx, e := range f.client.Entries(ctx, cp.Tree, start) {
		if idx >= end {
			break
		}
		if err := emit(rawEntryFromStatic(e)); err != nil {
			return err
		}
	}
	return f.client.Err()
}
