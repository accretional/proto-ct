package ctv2

import (
	"context"
	"fmt"
	"net/http"
	"time"

	pb "github.com/accretional/proto-ct/gen/ctingestion/v2"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
)

// rfc6962Fetcher wraps certificate-transparency-go's get-entries client.
//
// get-entries is server-paged: a single GetRawEntries(start, end) may return
// fewer entries than requested, so we advance by the actual returned count
// (serial). fetch_concurrency does not apply here — overlap-safe pipelining of
// variable-size pages is a future enhancement; concurrency is honored on the
// static path where the tile layout makes it safe.
type rfc6962Fetcher struct {
	lc       *client.LogClient
	pageSpan int64 // requested span per get-entries call (server may shorten)
}

func newRFC6962Fetcher(sel *pb.LogSelector, userAgent string, qps float64, pageSize int) (*rfc6962Fetcher, error) {
	hc := rateLimitedClient(qps)
	if hc == nil {
		hc = &http.Client{
			Transport: &http.Transport{MaxIdleConnsPerHost: 512, MaxConnsPerHost: 512},
			Timeout:   60 * time.Second,
		}
	}
	opts := jsonclient.Options{UserAgent: userAgent}
	if len(sel.GetPublicKey()) > 0 {
		opts.PublicKeyDER = sel.GetPublicKey()
	}
	lc, err := client.New(sel.GetMonitoringUrl(), hc, opts)
	if err != nil {
		return nil, fmt.Errorf("new rfc6962 client: %w", err)
	}
	span := int64(pageSize)
	if span <= 0 {
		span = 256
	}
	return &rfc6962Fetcher{lc: lc, pageSpan: span}, nil
}

func (f *rfc6962Fetcher) Fetch(ctx context.Context, start, end int64, emit func(*pb.RawLogEntry) error) error {
	for idx := start; idx < end; {
		if err := ctx.Err(); err != nil {
			return err
		}
		reqEnd := min(idx+f.pageSpan, end)
		// GetRawEntries treats both bounds as inclusive.
		resp, err := f.lc.GetRawEntries(ctx, idx, reqEnd-1)
		if err != nil {
			return fmt.Errorf("get-entries [%d,%d]: %w", idx, reqEnd-1, err)
		}
		if len(resp.Entries) == 0 {
			return fmt.Errorf("get-entries returned 0 entries at index %d (range past tree size?)", idx)
		}
		for _, le := range resp.Entries {
			if idx >= end {
				break
			}
			r, err := rawEntryFromRFC6962(idx, le.LeafInput, le.ExtraData)
			if err != nil {
				return err
			}
			if err := emit(r); err != nil {
				return err
			}
			idx++
		}
	}
	return nil
}
