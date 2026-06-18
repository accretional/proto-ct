package ctv2

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"

	"filippo.io/sunlight"
	pb "github.com/accretional/proto-ct/gen/ctingestion/v2"
)

const defaultStaticBatchSize = 256

// staticFetcher wraps filippo.io/sunlight's static-ct-api client. Entries are
// authenticated against the log checkpoint (nearly free), so the static path is
// always "verified" regardless of the request's verify flag. fetch_concurrency
// maps to sunlight's internal ConcurrencyLimit; the iterator yields in order, so
// we chunk it into batchSize-sized batches and hand them to the sink serially.
type staticFetcher struct {
	client    *sunlight.Client
	batchSize int
}

func newStaticFetcher(sel *pb.LogSelector, userAgent string, qps float64, concurrency, batchSize int) (*staticFetcher, error) {
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
		HTTPClient:       httpClientFor(qps, false),
	}
	c, err := sunlight.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("new sunlight client: %w", err)
	}
	bs := batchSize
	if bs <= 0 {
		bs = defaultStaticBatchSize
	}
	return &staticFetcher{client: c, batchSize: bs}, nil
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

func (f *staticFetcher) Fetch(ctx context.Context, start, end int64, sink func([]*pb.RawLogEntry) error) error {
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
	batch := make([]*pb.RawLogEntry, 0, f.batchSize)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		if err := sink(batch); err != nil {
			return err
		}
		batch = make([]*pb.RawLogEntry, 0, f.batchSize)
		return nil
	}
	for idx, e := range f.client.Entries(ctx, cp.Tree, start) {
		if idx >= end {
			break
		}
		batch = append(batch, rawEntryFromStatic(e))
		if len(batch) >= f.batchSize {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	if err := f.client.Err(); err != nil {
		return err
	}
	return flush()
}
