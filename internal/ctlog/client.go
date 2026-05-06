package ctlog

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

// Client fetches tiles from a static-ct-api log.
type Client struct {
	httpClient   *http.Client
	tileDataRoot string
	logRoot      string
	limiter      *rate.Limiter // nil = unlimited
}

// NewClient creates a Client from a tile/data root URL.
// targetQPS controls the maximum request rate; actual rate is 80% of that.
// Pass 0 for unlimited.
func NewClient(tileDataRoot string, targetQPS float64) *Client {
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

	return &Client{
		httpClient:   &http.Client{Timeout: 30 * time.Second},
		tileDataRoot: tileDataRoot,
		logRoot:      logRoot,
		limiter:      lim,
	}
}

// TreeSize fetches and returns the current tree size from the checkpoint.
func (c *Client) TreeSize(ctx context.Context) (int64, error) {
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
func (c *Client) TileURL(tileIdx int) string {
	return c.tileDataRoot + tileIndexPath(tileIdx)
}

// FetchTile downloads tile at the given index. maxEntries limits parsing (0 = all 256).
func (c *Client) FetchTile(ctx context.Context, tileIdx int, maxEntries int) ([]*TileLeaf, error) {
	data, err := c.get(ctx, c.TileURL(tileIdx))
	if err != nil {
		return nil, fmt.Errorf("tile %d: %w", tileIdx, err)
	}
	return ParseTile(data, maxEntries)
}

// FetchIssuer downloads the DER-encoded issuer certificate for the given fingerprint.
func (c *Client) FetchIssuer(ctx context.Context, fingerprint [32]byte) ([]byte, error) {
	hex := fmt.Sprintf("%x", fingerprint)
	data, err := c.get(ctx, c.logRoot+"issuer/"+hex)
	if err != nil {
		return nil, fmt.Errorf("issuer %s: %w", hex[:8], err)
	}
	return data, nil
}

func (c *Client) get(ctx context.Context, url string) ([]byte, error) {
	if c.limiter != nil {
		if err := c.limiter.Wait(ctx); err != nil {
			return nil, err
		}
	}

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
		return nil, fmt.Errorf("HTTP %d for %s", resp.StatusCode, url)
	}

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
