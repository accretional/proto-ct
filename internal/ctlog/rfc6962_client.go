package ctlog

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RFC6962Client fetches entries from an RFC 6962 log via /ct/v1/get-entries.
// It implements LogClient. Unlike static-ct-api, RFC 6962 has no separate
// issuer endpoint — chain certs are returned inline with each entry, so the
// client maintains an in-memory issuer cache populated during FetchEntries.
type RFC6962Client struct {
	httpClient *http.Client
	apiRoot    string // ends with "/"
	limiter    *rate.Limiter
	logID      [32]byte

	issuerMu sync.RWMutex
	issuers  map[[32]byte][]byte // fingerprint → DER
}

// NewRFC6962Client builds a client pointing at apiRoot (e.g.
// "https://ct.googleapis.com/logs/us1/argon2026h1/"). targetQPS=0 = unlimited.
func NewRFC6962Client(apiRoot string, targetQPS float64) *RFC6962Client {
	if !strings.HasSuffix(apiRoot, "/") {
		apiRoot += "/"
	}
	var lim *rate.Limiter
	if targetQPS > 0 {
		lim = rate.NewLimiter(rate.Limit(targetQPS*0.8), int(targetQPS)+1)
	}
	transport := &http.Transport{
		MaxIdleConnsPerHost: 64,
		MaxConnsPerHost:     64,
		IdleConnTimeout:     90 * time.Second,
	}
	return &RFC6962Client{
		httpClient: &http.Client{Timeout: 30 * time.Second, Transport: transport},
		apiRoot:    apiRoot,
		limiter:    lim,
		issuers:    make(map[[32]byte][]byte),
	}
}

// SetLogID records the canonical 32-byte log identity.
func (c *RFC6962Client) SetLogID(id [32]byte) { c.logID = id }

// LogID returns the canonical 32-byte log identity.
func (c *RFC6962Client) LogID() [32]byte { return c.logID }

// TreeSize fetches the current STH and returns the signed tree size.
func (c *RFC6962Client) TreeSize(ctx context.Context) (int64, error) {
	body, err := c.get(ctx, c.apiRoot+"ct/v1/get-sth")
	if err != nil {
		return 0, fmt.Errorf("get-sth: %w", err)
	}
	var sth struct {
		TreeSize int64 `json:"tree_size"`
	}
	if err := json.Unmarshal(body, &sth); err != nil {
		return 0, fmt.Errorf("parse sth: %w", err)
	}
	return sth.TreeSize, nil
}

// FetchEntries returns leaves with global indices in [start, end). RFC 6962
// logs cap the per-request batch size (typically 32–256); the client loops
// until [start, end) is filled or a request returns zero entries.
func (c *RFC6962Client) FetchEntries(ctx context.Context, start, end int64) ([]*LogLeaf, error) {
	if start < 0 || end < start {
		return nil, fmt.Errorf("FetchEntries: invalid range [%d, %d)", start, end)
	}
	if start == end {
		return nil, nil
	}
	var out []*LogLeaf
	cursor := start
	for cursor < end {
		page, err := c.fetchEntriesPage(ctx, cursor, end-1)
		if err != nil {
			return nil, err
		}
		if len(page) == 0 {
			break
		}
		for i, leaf := range page {
			leaf.EntryIdx = cursor + int64(i)
		}
		out = append(out, page...)
		cursor += int64(len(page))
	}
	return out, nil
}

// FetchIssuer returns the DER bytes for an issuer fingerprint. RFC 6962
// embeds chains in get-entries responses, so this is purely a cache lookup
// populated as a side effect of FetchEntries.
func (c *RFC6962Client) FetchIssuer(_ context.Context, fp [32]byte) ([]byte, error) {
	c.issuerMu.RLock()
	der, ok := c.issuers[fp]
	c.issuerMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("issuer %x not in chain cache", fp[:4])
	}
	return der, nil
}

// fetchEntriesPage performs one GET /ct/v1/get-entries call and returns the
// parsed leaves. The log may return fewer entries than requested.
func (c *RFC6962Client) fetchEntriesPage(ctx context.Context, start, end int64) ([]*LogLeaf, error) {
	u := c.apiRoot + "ct/v1/get-entries?" + url.Values{
		"start": []string{fmt.Sprintf("%d", start)},
		"end":   []string{fmt.Sprintf("%d", end)},
	}.Encode()
	body, err := c.get(ctx, u)
	if err != nil {
		return nil, fmt.Errorf("get-entries [%d,%d]: %w", start, end, err)
	}
	var resp struct {
		Entries []struct {
			LeafInput string `json:"leaf_input"`
			ExtraData string `json:"extra_data"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse get-entries: %w", err)
	}
	out := make([]*LogLeaf, 0, len(resp.Entries))
	for i, e := range resp.Entries {
		leafIn, err := base64.StdEncoding.DecodeString(e.LeafInput)
		if err != nil {
			return nil, fmt.Errorf("entry %d leaf_input b64: %w", i, err)
		}
		extra, err := base64.StdEncoding.DecodeString(e.ExtraData)
		if err != nil {
			return nil, fmt.Errorf("entry %d extra_data b64: %w", i, err)
		}
		leaf, err := parseLeafInput(leafIn)
		if err != nil {
			return nil, fmt.Errorf("entry %d leaf: %w", i, err)
		}
		chainDER, err := parseExtraData(extra, leaf)
		if err != nil {
			return nil, fmt.Errorf("entry %d extra: %w", i, err)
		}
		c.cacheIssuers(leaf.ChainFingerprints, chainDER)
		out = append(out, leaf)
	}
	return out, nil
}

func (c *RFC6962Client) cacheIssuers(fps [][32]byte, ders [][]byte) {
	if len(fps) == 0 {
		return
	}
	c.issuerMu.Lock()
	defer c.issuerMu.Unlock()
	for i, fp := range fps {
		if i >= len(ders) {
			break
		}
		if _, ok := c.issuers[fp]; !ok {
			c.issuers[fp] = ders[i]
		}
	}
}

// get is the rate-limited + retried HTTP fetch shared by TreeSize and
// fetchEntriesPage. Mirrors the TileClient retry policy but uses a simpler
// transport since RFC 6962 responses are small JSON payloads.
func (c *RFC6962Client) get(ctx context.Context, u string) ([]byte, error) {
	if c.limiter != nil {
		if err := c.limiter.Wait(ctx); err != nil {
			return nil, err
		}
	}
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			wait := retryBaseWait * (1 << (attempt - 1))
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
			}
		}
		data, err := c.doGet(ctx, u)
		if err == nil {
			return data, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if isFatalHTTP(err) {
			return nil, err
		}
	}
	return nil, fmt.Errorf("after %d attempts: %w", maxRetries+1, lastErr)
}

func (c *RFC6962Client) doGet(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("User-Agent", "proto-ct/1.0")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{code: resp.StatusCode, url: u}
	}
	return readMaybeGzip(resp)
}
