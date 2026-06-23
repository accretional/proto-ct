package ctv2

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"filippo.io/sunlight"
	pb "github.com/accretional/proto-ct/gen/ctingestion/v2"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
)

const tileWidth = 256 // static-ct-api full data tile = 256 entries

// tileFetcher reads static-ct-api data tiles (256 entries/request) from a log
// that exposes the tile interface but NO signed checkpoint — so the tree size
// comes from the log's RFC6962 get-sth instead. This is the experimental tile
// front-end some RFC6962 logs offer (e.g. TrustAsia log2026a/b), ~8x the
// entries/request of get-entries. Reads are unauthenticated (no checkpoint /
// inclusion proof). Records are static-style (leaf + chain fingerprints).
type tileFetcher struct {
	lc           *client.LogClient // RFC6962 client, used only for get-sth (tree size)
	httpClient   *http.Client
	tileDataRoot string // <prefix>/tile/data/
	userAgent    string
	concurrency  int
}

func newTileFetcher(sel *pb.LogSelector, userAgent string, qps float64, concurrency int) (*tileFetcher, error) {
	base := strings.TrimRight(sel.GetMonitoringUrl(), "/")
	if base == "" {
		return nil, fmt.Errorf("tile fetcher needs monitoring_url (the log's base, serving /tile/data and /ct/v1/get-sth)")
	}
	hc := httpClientFor(qps, false) // tiles are CDN-served; keep-alive is fine
	lc, err := client.New(base, hc, jsonclient.Options{UserAgent: userAgent})
	if err != nil {
		return nil, fmt.Errorf("new rfc6962 client (for get-sth): %w", err)
	}
	return &tileFetcher{
		lc:           lc,
		httpClient:   hc,
		tileDataRoot: base + "/tile/data/",
		userAgent:    userAgent,
		concurrency:  max(concurrency, 1),
	}, nil
}

func (f *tileFetcher) Fetch(ctx context.Context, start, end int64, sink func(entryBatch) error) error {
	// No checkpoint is served, so the readable frontier comes from RFC6962 get-sth,
	// clamped down to the last COMPLETE 256-tile (partial tiles aren't served).
	sth, err := f.lc.GetSTH(ctx)
	if err != nil {
		return fmt.Errorf("get-sth (for tree size): %w", err)
	}
	lastFull := (int64(sth.TreeSize) / tileWidth) * tileWidth
	if end > lastFull {
		end = lastFull
	}
	if start >= end {
		return nil
	}
	firstTile := start / tileWidth
	lastTile := (end - 1) / tileWidth

	var mu sync.Mutex
	var firstErr error
	fail := func(e error) {
		mu.Lock()
		if firstErr == nil {
			firstErr = e
		}
		mu.Unlock()
	}
	failed := func() bool { mu.Lock(); defer mu.Unlock(); return firstErr != nil }

	tilesCh := make(chan int64, f.concurrency)
	var wg sync.WaitGroup
	for w := 0; w < f.concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range tilesCh {
				if failed() || ctx.Err() != nil {
					continue // drain
				}
				leaves, err := f.fetchTile(ctx, t)
				if err != nil {
					fail(fmt.Errorf("tile %d: %w", t, err))
					continue
				}
				base := t * tileWidth
				batch := make([]*pb.RawLogEntry, 0, len(leaves))
				for i, e := range leaves {
					idx := base + int64(i)
					if idx < start || idx >= end {
						continue
					}
					r := rawEntryFromStatic(e)
					r.Index = idx // authoritative; don't trust the tile's LeafIndex extension
					batch = append(batch, r)
				}
				if len(batch) > 0 {
					if err := sink(entryBatch{entries: batch}); err != nil {
						fail(err)
					}
				}
			}
		}()
	}
	for t := firstTile; t <= lastTile; t++ {
		tilesCh <- t
	}
	close(tilesCh)
	wg.Wait()
	return firstErr
}

// fetchTile downloads and parses one data tile (up to 256 leaves), with a small
// retry for the transient errors observed on the experimental endpoint.
func (f *tileFetcher) fetchTile(ctx context.Context, tileIdx int64) ([]*sunlight.LogEntry, error) {
	url := f.tileDataRoot + tileDataPath(tileIdx)
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt) * 2 * time.Second):
			}
		}
		body, err := f.get(ctx, url)
		if err != nil {
			lastErr = err
			continue
		}
		var out []*sunlight.LogEntry
		data := body
		for len(data) > 0 {
			e, rest, err := sunlight.ReadTileLeaf(data)
			if err != nil {
				lastErr = fmt.Errorf("parse leaf: %w", err)
				out = nil
				break
			}
			out = append(out, e)
			data = rest
		}
		if out != nil {
			return out, nil
		}
	}
	return nil, lastErr
}

func (f *tileFetcher) get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", f.userAgent)
	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// tileDataPath encodes a data-tile index per static-ct-api: 3-digit groups,
// non-final groups prefixed with "x" (0 -> "000", 1234 -> "x001/234").
func tileDataPath(n int64) string {
	s := fmt.Sprintf("%d", n)
	for len(s)%3 != 0 {
		s = "0" + s
	}
	var parts []string
	for i := 0; i < len(s); i += 3 {
		seg := s[i : i+3]
		if i < len(s)-3 {
			parts = append(parts, "x"+seg)
		} else {
			parts = append(parts, seg)
		}
	}
	return strings.Join(parts, "/")
}
