package ctlist

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadOrFetch_UsesCacheWhenFresh(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Write([]byte(fixtureJSON))
	}))
	defer srv.Close()

	snapshot := filepath.Join(t.TempDir(), "log_list.json")

	// First call writes the snapshot.
	if _, err := LoadOrFetch(context.Background(), srv.URL, snapshot, time.Hour); err != nil {
		t.Fatalf("first LoadOrFetch: %v", err)
	}
	if calls != 1 {
		t.Errorf("expected 1 HTTP call, got %d", calls)
	}

	// Second call within maxAge reads from the snapshot.
	if _, err := LoadOrFetch(context.Background(), srv.URL, snapshot, time.Hour); err != nil {
		t.Fatalf("second LoadOrFetch: %v", err)
	}
	if calls != 1 {
		t.Errorf("cache miss: expected 1 HTTP call, got %d", calls)
	}

	// A zero maxAge forces a refresh.
	if _, err := LoadOrFetch(context.Background(), srv.URL, snapshot, 0); err != nil {
		t.Fatalf("forced refresh: %v", err)
	}
	if calls != 2 {
		t.Errorf("expected 2 HTTP calls after forced refresh, got %d", calls)
	}
}

func TestLoadOrFetch_FallsBackToStaleSnapshot(t *testing.T) {
	snapshot := filepath.Join(t.TempDir(), "log_list.json")
	if err := os.WriteFile(snapshot, []byte(fixtureJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	// Backdate the file so maxAge=1ms forces a refresh.
	past := time.Now().Add(-time.Hour)
	if err := os.Chtimes(snapshot, past, past); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	logs, err := LoadOrFetch(context.Background(), srv.URL, snapshot, time.Millisecond)
	if err != nil {
		t.Fatalf("LoadOrFetch should fall back to stale snapshot, got error: %v", err)
	}
	if len(logs) == 0 {
		t.Errorf("expected stale snapshot logs to load, got empty")
	}
}

func TestWriteAtomic_NoTornFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.json")
	if err := writeAtomic(path, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello" {
		t.Errorf("got %q want %q", string(data), "hello")
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf(".tmp file should have been renamed away")
	}
}
