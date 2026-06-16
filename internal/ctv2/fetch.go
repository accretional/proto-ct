package ctv2

import (
	"context"
	"net/http"

	pb "github.com/accretional/proto-ct/gen/ctingestion/v2"
	"golang.org/x/time/rate"
)

// RangeFetcher fetches entries with index in [start, end) from a single log and
// calls emit for each, in ascending index order. Implementations are
// protocol-specific (RFC 6962 get-entries vs static-ct-api tiles).
type RangeFetcher interface {
	Fetch(ctx context.Context, start, end int64, emit func(*pb.RawLogEntry) error) error
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

// rateLimitedClient returns an *http.Client whose requests are rate-limited to
// qps (0 = no limit, returns nil so the caller's library default is used).
func rateLimitedClient(qps float64) *http.Client {
	if qps <= 0 {
		return nil
	}
	tr := &http.Transport{
		MaxIdleConnsPerHost: 512,
		MaxConnsPerHost:     512,
	}
	return &http.Client{
		Transport: &rateLimitedTransport{base: tr, lim: rate.NewLimiter(rate.Limit(qps), int(qps)+1)},
	}
}
