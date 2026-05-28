package ctlog

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

const (
	maxRetries    = 5
	retryBaseWait = 2 * time.Second
)

// TileSize is the static-ct-api entries-per-tile constant.
const TileSize = 256

// TileClient fetches tiles from a static-ct-api log. It implements LogClient.
type TileClient struct {
	httpClient   *http.Client
	tileDataRoot string
	logRoot      string
	limiter      *rate.Limiter // nil = unlimited
	logID        [32]byte      // zero until SetLogID is called
}

// NewTileClient creates a TileClient from a tile/data root URL.
// targetQPS controls the maximum request rate; actual rate is 80% of that.
// Pass 0 for unlimited. LogID is left zero — call SetLogID once known.
func NewTileClient(tileDataRoot string, targetQPS float64) *TileClient {
	if !strings.HasSuffix(tileDataRoot, "/") {
		tileDataRoot += "/"
	}
	logRoot := strings.TrimSuffix(tileDataRoot, "tile/data/")

	var lim *rate.Limiter
	if targetQPS > 0 {
		actual := rate.Limit(targetQPS * 0.8)
		burst := int(targetQPS) + 1
		lim = rate.NewLimiter(actual, burst)
	}

	transport := &http.Transport{
		MaxIdleConnsPerHost: 512,
		MaxConnsPerHost:     512,
		IdleConnTimeout:     90 * time.Second,
	}
	return &TileClient{
		httpClient:   &http.Client{Timeout: 30 * time.Second, Transport: transport},
		tileDataRoot: tileDataRoot,
		logRoot:      logRoot,
		limiter:      lim,
	}
}

// SetLogID records the canonical 32-byte log identity.
func (c *TileClient) SetLogID(id [32]byte) { c.logID = id }

// LogID returns the canonical 32-byte log identity (zero until SetLogID is called).
func (c *TileClient) LogID() [32]byte { return c.logID }

// TreeSize fetches and returns the current tree size from the checkpoint.
func (c *TileClient) TreeSize(ctx context.Context) (int64, error) {
	body, err := c.get(ctx, c.logRoot+"checkpoint")
	if err != nil {
		return 0, fmt.Errorf("checkpoint: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(lines) < 2 {
		return 0, fmt.Errorf("checkpoint: unexpected format")
	}
	var size int64
	if _, err := fmt.Sscanf(lines[1], "%d", &size); err != nil {
		return 0, fmt.Errorf("checkpoint parse: %w", err)
	}
	return size, nil
}

// TileURL returns the URL for a given tile index.
func (c *TileClient) TileURL(tileIdx int) string {
	return c.tileDataRoot + tileIndexPath(tileIdx)
}

// FetchTile downloads tile at the given index. maxEntries limits parsing (0 = all 256).
func (c *TileClient) FetchTile(ctx context.Context, tileIdx int, maxEntries int) ([]*TileLeaf, error) {
	data, err := c.get(ctx, c.TileURL(tileIdx))
	if err != nil {
		return nil, fmt.Errorf("tile %d: %w", tileIdx, err)
	}
	return ParseTile(data, maxEntries)
}

// FetchEntries returns leaves with global indices in [start, end). It fetches
// whichever tiles cover the range and slices to the exact bounds. start and end
// are global entry indices, not tile indices.
func (c *TileClient) FetchEntries(ctx context.Context, start, end int64) ([]*LogLeaf, error) {
	if start < 0 || end < start {
		return nil, fmt.Errorf("FetchEntries: invalid range [%d, %d)", start, end)
	}
	if start == end {
		return nil, nil
	}
	firstTile := start / TileSize
	lastTile := (end - 1) / TileSize
	out := make([]*LogLeaf, 0, end-start)
	for t := firstTile; t <= lastTile; t++ {
		leaves, err := c.FetchTile(ctx, int(t), TileSize)
		if err != nil {
			return nil, err
		}
		base := t * TileSize
		for i, l := range leaves {
			idx := base + int64(i)
			if idx < start || idx >= end {
				continue
			}
			out = append(out, tileLeafToLogLeaf(l, idx))
		}
	}
	return out, nil
}

// FetchIssuer downloads the DER-encoded issuer certificate for the given fingerprint.
func (c *TileClient) FetchIssuer(ctx context.Context, fingerprint [32]byte) ([]byte, error) {
	hex := fmt.Sprintf("%x", fingerprint)
	data, err := c.get(ctx, c.logRoot+"issuer/"+hex)
	if err != nil {
		return nil, fmt.Errorf("issuer %s: %w", hex[:8], err)
	}
	return data, nil
}

func (c *TileClient) get(ctx context.Context, url string) ([]byte, error) {
	if c.limiter != nil {
		if err := c.limiter.Wait(ctx); err != nil {
			return nil, err
		}
	}

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			wait := retryBaseWait * (1 << (attempt - 1)) // 2s, 4s, 8s, 16s, 32s
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
			}
		}

		data, err := c.doGet(ctx, url)
		if err == nil {
			return data, nil
		}
		lastErr = err

		// Don't retry on context cancellation or definitive HTTP errors.
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// Don't retry 4xx — those are permanent failures.
		if isFatalHTTP(err) {
			return nil, err
		}
		if attempt < maxRetries {
			fmt.Printf("warn: GET %s attempt %d/%d: %v — retrying\n", url, attempt+1, maxRetries, err)
		}
	}
	return nil, fmt.Errorf("after %d attempts: %w", maxRetries+1, lastErr)
}

func (c *TileClient) doGet(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("User-Agent", "proto-ct/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{code: resp.StatusCode, url: url}
	}

	return readMaybeGzip(resp)
}

// readMaybeGzip reads resp.Body, transparently decompressing if Content-Encoding is gzip.
func readMaybeGzip(resp *http.Response) ([]byte, error) {
	var reader io.Reader = resp.Body
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("gzip: %w", err)
		}
		defer gz.Close()
		reader = gz
	}
	return io.ReadAll(reader)
}

type httpError struct {
	code int
	url  string
}

func (e *httpError) Error() string {
	return fmt.Sprintf("HTTP %d for %s", e.code, e.url)
}

// IsNotFound reports whether err signals the log frontier.
// LE's monitoring endpoint returns 403 (not 404) for tiles past the current tree,
// so both are treated as "no tile here yet."
func IsNotFound(err error) bool {
	var he *httpError
	return errors.As(err, &he) && (he.code == http.StatusNotFound || he.code == http.StatusForbidden)
}

func isFatalHTTP(err error) bool {
	var he *httpError
	return errors.As(err, &he) && he.code >= 400 && he.code < 500
}

// tileIndexPath encodes a tile index as a path per the static-ct-api spec.
// e.g., 0 → "000", 1000 → "x001/000", 1234067 → "x001/x234/067"
func tileIndexPath(n int) string {
	s := fmt.Sprintf("%d", n)
	for len(s)%3 != 0 {
		s = "0" + s
	}
	var parts []string
	for i := 0; i < len(s); i += 3 {
		segment := s[i : i+3]
		if i < len(s)-3 {
			parts = append(parts, "x"+segment)
		} else {
			parts = append(parts, segment)
		}
	}
	return strings.Join(parts, "/")
}
