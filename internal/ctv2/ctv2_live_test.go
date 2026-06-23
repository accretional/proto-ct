package ctv2

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/accretional/proto-ct/gen/ctingestion/v2"
)

// Live tests hit real CT logs over the network. Gated behind CTV2_LIVE=1 so the
// default `go test` stays hermetic.
//
//	CTV2_LIVE=1 go test ./internal/ctv2/ -run Live -v

func liveOrSkip(t *testing.T) {
	t.Helper()
	if os.Getenv("CTV2_LIVE") != "1" {
		t.Skip("set CTV2_LIVE=1 to run live network tests")
	}
}

// Google Argon 2026h1 (RFC6962) and Let's Encrypt Sycamore 2026h1 (static).
const (
	liveRFC6962LogIDHex = "0e5794bcf3aea93e331b2c9907b3f790df9bc23d713225dd21a925ac61c54e21"
	liveStaticLogIDHex  = "a5c978925d57461782870dd889660b5c55648b7d0040f2ec076851d1886919f7"
)

func decodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

func TestLive_GetLogEntries(t *testing.T) {
	liveOrSkip(t)
	for _, tc := range []struct {
		name string
		id   string
	}{
		{"rfc6962", liveRFC6962LogIDHex},
		{"static", liveStaticLogIDHex},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			svc := NewService(root)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			resp, err := svc.GetLogEntries(ctx, &pb.GetLogEntriesRequest{
				Log:        &pb.LogSelector{LogId: decodeHex(t, tc.id)},
				StartIndex: 0,
				EndIndex:   5,
			})
			if err != nil {
				t.Fatalf("GetLogEntries: %v", err)
			}
			if resp.EntriesWritten != 5 {
				t.Errorf("entries_written = %d, want 5", resp.EntriesWritten)
			}
			if resp.LastIndex != 4 {
				t.Errorf("last_index = %d, want 4", resp.LastIndex)
			}
			// Both source types must populate the local issuer store: RFC6962
			// dedupes the inline chain into it; static resolves chains from the
			// log's issuer endpoint inline during the fetch.
			ders, _ := filepath.Glob(filepath.Join(root, issuerDir, "*.der"))
			if len(ders) == 0 {
				t.Errorf("%s: issuer store %s/ is empty, want >=1 chain cert", tc.name, issuerDir)
			}
		})
	}
}

func TestLive_GetSTH(t *testing.T) {
	liveOrSkip(t)
	svc := NewService(t.TempDir())
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	resp, err := svc.GetSTH(ctx, &pb.GetSTHRequest{Log: &pb.LogSelector{LogId: decodeHex(t, liveRFC6962LogIDHex)}})
	if err != nil {
		t.Fatalf("GetSTH: %v", err)
	}
	if resp.TreeSize <= 0 {
		t.Errorf("tree_size = %d, want > 0", resp.TreeSize)
	}
}
