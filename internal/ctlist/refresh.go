package ctlist

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// DefaultSnapshotPath is the canonical location for a persisted log_list.json.
const DefaultSnapshotPath = "data/log_list.json"

// LoadOrFetch returns parsed logs from a cached snapshot at snapshotPath when
// the snapshot is younger than maxAge. Otherwise it fetches from url (empty =
// DefaultLogListURL), persists the bytes to snapshotPath, and returns the
// parsed result. If the network fetch fails but a snapshot exists, the stale
// snapshot is used and an error is logged.
func LoadOrFetch(ctx context.Context, url, snapshotPath string, maxAge time.Duration) ([]Log, error) {
	if snapshotPath == "" {
		snapshotPath = DefaultSnapshotPath
	}
	if fi, err := os.Stat(snapshotPath); err == nil && time.Since(fi.ModTime()) < maxAge {
		data, err := os.ReadFile(snapshotPath)
		if err == nil {
			return ParseLogList(data)
		}
	}

	data, fetchErr := fetchBytes(ctx, url)
	if fetchErr != nil {
		// Fall back to a stale snapshot rather than failing outright.
		if data2, err := os.ReadFile(snapshotPath); err == nil {
			log.Printf("ctlist: fetch failed (%v); using stale snapshot %s", fetchErr, snapshotPath)
			return ParseLogList(data2)
		}
		return nil, fetchErr
	}
	if err := writeAtomic(snapshotPath, data); err != nil {
		log.Printf("ctlist: warn write snapshot %s: %v", snapshotPath, err)
	}
	return ParseLogList(data)
}

// RefreshLoop fetches the log list every interval and writes it to
// snapshotPath. Returns when ctx is cancelled. Errors are logged but never
// fatal — the persisted snapshot survives transient outages.
func RefreshLoop(ctx context.Context, url, snapshotPath string, interval time.Duration) {
	if snapshotPath == "" {
		snapshotPath = DefaultSnapshotPath
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		data, err := fetchBytes(ctx, url)
		if err != nil {
			log.Printf("ctlist refresh: %v", err)
		} else if err := writeAtomic(snapshotPath, data); err != nil {
			log.Printf("ctlist refresh write %s: %v", snapshotPath, err)
		} else {
			log.Printf("ctlist refresh: wrote %d bytes to %s", len(data), snapshotPath)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// fetchBytes downloads the raw log_list.json bytes from url (empty = default).
func fetchBytes(ctx context.Context, url string) ([]byte, error) {
	if url == "" {
		url = DefaultLogListURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "proto-ct/1.0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get %s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// writeAtomic writes data to path via path.tmp + rename to avoid torn files.
func writeAtomic(path string, data []byte) error {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
