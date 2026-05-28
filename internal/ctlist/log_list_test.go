package ctlist

import (
	"encoding/base64"
	"testing"
	"time"
)

// Trimmed fixture covering both shapes (logs / tiled_logs) and three states.
const fixtureJSON = `{
  "version": "85.0",
  "log_list_timestamp": "2026-05-27T13:41:20Z",
  "operators": [
    {
      "name": "Let's Encrypt",
      "email": ["a@b"],
      "tiled_logs": [
        {
          "description": "Let's Encrypt 'Sycamore2026h1'",
          "log_id": "pcl4kl1XRheChw3YiWYLXFVki30AQPLsB2hR0YhpGfc=",
          "key": "MFkwEw==",
          "submission_url": "https://log.sycamore.ct.letsencrypt.org/2026h1/",
          "monitoring_url": "https://mon.sycamore.ct.letsencrypt.org/2026h1/",
          "mmd": 60,
          "state": { "usable": { "timestamp": "2025-11-27T03:00:00Z" } },
          "temporal_interval": {
            "start_inclusive": "2025-12-18T00:00:00Z",
            "end_exclusive":   "2026-06-18T00:00:00Z"
          }
        }
      ]
    },
    {
      "name": "Google",
      "logs": [
        {
          "description": "Google 'Argon2026h1' log",
          "log_id": "DleUvPOuqT4zGyyZB7P3kN+bwj1xMiXdIaklrGHFTiE=",
          "key": "MFkwEw==",
          "url": "https://ct.googleapis.com/logs/us1/argon2026h1/",
          "mmd": 86400,
          "state": { "usable": { "timestamp": "2024-09-30T22:19:27Z" } },
          "temporal_interval": {
            "start_inclusive": "2026-01-01T00:00:00Z",
            "end_exclusive":   "2026-07-01T00:00:00Z"
          }
        }
      ]
    },
    {
      "name": "Sectigo",
      "logs": [
        {
          "description": "Sectigo 'Mammoth2026h1'",
          "log_id": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
          "key": "MFkwEw==",
          "url": "https://mammoth2026h1.ct.sectigo.com/",
          "mmd": 86400,
          "state": {
            "readonly": {
              "timestamp": "2026-04-15T00:00:00Z",
              "final_tree_head": { "tree_size": 65240567, "sha256_root_hash": "deadbeef" }
            }
          }
        }
      ]
    }
  ]
}`

func TestParseLogList(t *testing.T) {
	logs, err := ParseLogList([]byte(fixtureJSON))
	if err != nil {
		t.Fatalf("ParseLogList: %v", err)
	}
	if len(logs) != 3 {
		t.Fatalf("expected 3 logs, got %d", len(logs))
	}

	// The fixture iteration order is: Let's Encrypt tiled_logs, Google logs, Sectigo logs.
	want := []struct {
		desc     string
		op       string
		proto    Protocol
		state    State
		apiRoot  string
		hasTemp  bool
		finalSz  int64
	}{
		{"Let's Encrypt 'Sycamore2026h1'", "Let's Encrypt", ProtocolStaticCT, StateUsable, "https://mon.sycamore.ct.letsencrypt.org/2026h1/", true, 0},
		{"Google 'Argon2026h1' log", "Google", ProtocolRFC6962, StateUsable, "https://ct.googleapis.com/logs/us1/argon2026h1/", true, 0},
		{"Sectigo 'Mammoth2026h1'", "Sectigo", ProtocolRFC6962, StateReadonly, "https://mammoth2026h1.ct.sectigo.com/", false, 65240567},
	}

	// Operator order is preserved by encoding/json for arrays, so we can index directly.
	for i, w := range want {
		got := logs[i]
		if got.Description != w.desc {
			t.Errorf("logs[%d].Description = %q, want %q", i, got.Description, w.desc)
		}
		if got.Operator != w.op {
			t.Errorf("logs[%d].Operator = %q, want %q", i, got.Operator, w.op)
		}
		if got.Protocol != w.proto {
			t.Errorf("logs[%d].Protocol = %q, want %q", i, got.Protocol, w.proto)
		}
		if got.State != w.state {
			t.Errorf("logs[%d].State = %q, want %q", i, got.State, w.state)
		}
		if got.APIRoot() != w.apiRoot {
			t.Errorf("logs[%d].APIRoot() = %q, want %q", i, got.APIRoot(), w.apiRoot)
		}
		if got.FinalTreeSize != w.finalSz {
			t.Errorf("logs[%d].FinalTreeSize = %d, want %d", i, got.FinalTreeSize, w.finalSz)
		}
		if w.hasTemp && got.TemporalStart.IsZero() {
			t.Errorf("logs[%d].TemporalStart unset", i)
		}
		if got.LogID == ([32]byte{}) && i < 2 {
			t.Errorf("logs[%d].LogID is zero", i)
		}
	}
}

func TestDecodeLogID(t *testing.T) {
	b64 := "pcl4kl1XRheChw3YiWYLXFVki30AQPLsB2hR0YhpGfc="
	want, _ := base64.StdEncoding.DecodeString(b64)
	got, err := decodeLogID(b64)
	if err != nil {
		t.Fatalf("decodeLogID: %v", err)
	}
	if string(got[:]) != string(want) {
		t.Errorf("decodeLogID round-trip mismatch")
	}
}

func TestDecodeLogID_WrongLength(t *testing.T) {
	if _, err := decodeLogID(base64.StdEncoding.EncodeToString([]byte("short"))); err == nil {
		t.Errorf("expected error for short log_id")
	}
}

func TestFilterUsable(t *testing.T) {
	logs, _ := ParseLogList([]byte(fixtureJSON))
	usable := FilterUsable(logs)
	if len(usable) != 2 {
		t.Errorf("FilterUsable: expected 2, got %d", len(usable))
	}
}

func TestFilterByProtocol(t *testing.T) {
	logs, _ := ParseLogList([]byte(fixtureJSON))
	tiled := FilterByProtocol(logs, ProtocolStaticCT)
	if len(tiled) != 1 || tiled[0].Protocol != ProtocolStaticCT {
		t.Errorf("FilterByProtocol(static): unexpected result %+v", tiled)
	}
	rfc := FilterByProtocol(logs, ProtocolRFC6962)
	if len(rfc) != 2 {
		t.Errorf("FilterByProtocol(rfc): expected 2, got %d", len(rfc))
	}
	all := FilterByProtocol(logs)
	if len(all) != len(logs) {
		t.Errorf("FilterByProtocol(empty): expected passthrough, got %d/%d", len(all), len(logs))
	}
}

func TestMMDParsing(t *testing.T) {
	logs, _ := ParseLogList([]byte(fixtureJSON))
	if logs[0].MMD != 60*time.Second {
		t.Errorf("Sycamore MMD = %v, want 60s", logs[0].MMD)
	}
	if logs[1].MMD != 24*time.Hour {
		t.Errorf("Argon MMD = %v, want 24h", logs[1].MMD)
	}
}
