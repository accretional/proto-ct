package ctv2

import (
	"context"
	"fmt"
	"sync"

	pb "github.com/accretional/proto-ct/gen/ctingestion/v2"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/scanner"
)

const defaultRFC6962BatchSize = 256

// rfc6962Fetcher wraps certificate-transparency-go's scanner.Fetcher, which runs
// a pool of get-entries workers, completes server-paged short reads internally,
// and retries 429s with backoff. It emits contiguous EntryBatches (possibly out
// of order across workers); each is converted and handed to the sink, which is
// concurrency-safe.
type rfc6962Fetcher struct {
	lc        *client.LogClient
	batchSize int
	parallel  int
}

func newRFC6962Fetcher(sel *pb.LogSelector, userAgent string, qps float64, pageSize, concurrency int, disableKeepAlive bool) (*rfc6962Fetcher, error) {
	hc := httpClientFor(qps, disableKeepAlive)
	opts := jsonclient.Options{UserAgent: userAgent}
	if len(sel.GetPublicKey()) > 0 {
		opts.PublicKeyDER = sel.GetPublicKey()
	}
	lc, err := client.New(sel.GetMonitoringUrl(), hc, opts)
	if err != nil {
		return nil, fmt.Errorf("new rfc6962 client: %w", err)
	}
	bs := pageSize
	if bs <= 0 {
		bs = defaultRFC6962BatchSize
	}
	par := max(concurrency, 1)
	return &rfc6962Fetcher{lc: lc, batchSize: bs, parallel: par}, nil
}

func (f *rfc6962Fetcher) Fetch(ctx context.Context, start, end int64, sink func(entryBatch) error) error {
	// Clamp to the current tree: scanner workers that request past the tree get
	// empty responses and would spin (advancing by 0).
	sth, err := f.lc.GetSTH(ctx)
	if err != nil {
		return fmt.Errorf("get-sth: %w", err)
	}
	if int64(sth.TreeSize) < end {
		end = int64(sth.TreeSize)
	}
	if start >= end {
		return nil
	}

	fetcher := scanner.NewFetcher(f.lc, &scanner.FetcherOptions{
		BatchSize:     f.batchSize,
		ParallelFetch: f.parallel,
		StartIndex:    start,
		EndIndex:      end,
	})

	var mu sync.Mutex
	var firstErr error
	fail := func(e error) {
		mu.Lock()
		if firstErr == nil {
			firstErr = e
			fetcher.Stop()
		}
		mu.Unlock()
	}

	runErr := fetcher.Run(ctx, func(b scanner.EntryBatch) {
		entries := make([]*pb.RawLogEntry, 0, len(b.Entries))
		var chains []chainCert
		seen := make(map[[32]byte]struct{}) // collapse the obvious per-batch chain dups
		for i, le := range b.Entries {
			r, cs, err := rawEntryFromRFC6962(b.Start+int64(i), le.LeafInput, le.ExtraData)
			if err != nil {
				fail(err)
				return
			}
			entries = append(entries, r)
			for _, c := range cs {
				if _, ok := seen[c.hash]; ok {
					continue
				}
				seen[c.hash] = struct{}{}
				chains = append(chains, c)
			}
		}
		if err := sink(entryBatch{entries: entries, chains: chains}); err != nil {
			fail(err)
		}
	})

	mu.Lock()
	defer mu.Unlock()
	if firstErr != nil {
		return firstErr
	}
	return runErr
}
