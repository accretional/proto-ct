package ctv2

import (
	"context"
	"net/http"
	"time"

	pb "github.com/accretional/proto-ct/gen/ctingestion/v2"
	"golang.org/x/time/rate"
)

// RangeFetcher fetches entries with index in [start, end) from a single log and
// hands them to sink in contiguous, index-ordered batches. Each batch's entries
// are consecutive (entry i has index entries[0].Index+i). Batches from different
// calls are disjoint but may arrive concurrently / out of order across batches
// (the RFC6962 path uses a parallel worker pool), so sink must be safe for
// concurrent use. Implementations are protocol-specific (RFC 6962 get-entries vs
// static-ct-api tiles).
type RangeFetcher interface {
	Fetch(ctx context.Context, start, end int64, sink func(entries []*pb.RawLogEntry) error) error
}

// rateLimitedTransport wraps an http.RoundTripper with a QPS limiter. Shared by
// both protocol clients so target_qps is honored uniformly.
type rateLimitedTransport struct {
	base http.RoundTripper
	lim  *rate.Limiter
}

func (t *rateLimitedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.lim != nil {
		if err := t.lim.Wait(req.Context()); err != nil {
			return nil, err
		}
	}
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}

// httpClientFor builds the fetcher HTTP client. qps>0 adds a rate limiter.
// disableKeepAlive forces a new connection per request — needed for DigiCert,
// whose per-Nginx-server ~1 req/s limit pins a persistent connection to one
// server; closing connections re-rolls the load balancer across all its servers.
// (Costs a TLS handshake per request, so it's off by default.)
func httpClientFor(qps float64, disableKeepAlive bool) *http.Client {
	tr := &http.Transport{
		MaxIdleConnsPerHost: 512,
		MaxConnsPerHost:     512,
		DisableKeepAlives:   disableKeepAlive,
	}
	c := &http.Client{Timeout: 60 * time.Second}
	if qps > 0 {
		c.Transport = &rateLimitedTransport{base: tr, lim: rate.NewLimiter(rate.Limit(qps), int(qps)+1)}
	} else {
		c.Transport = tr
	}
	return c
}
