// Package ctlist fetches and parses the Google CT log list v3
// (https://www.gstatic.com/ct/log_list/v3/log_list.json) into a uniform
// Log representation that hides the static-ct-api vs RFC 6962 distinction
// from callers.
package ctlist

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultLogListURL is Google's canonical v3 CT log list.
const DefaultLogListURL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"

// Protocol identifies which CT API a log speaks.
type Protocol string

const (
	ProtocolStaticCT Protocol = "static-ct-api" // C2SP tile-based
	ProtocolRFC6962  Protocol = "rfc6962"       // legacy JSON get-entries
)

// State mirrors the per-log state keys used in the v3 JSON.
type State string

const (
	StatePending   State = "pending"
	StateQualified State = "qualified"
	StateUsable    State = "usable"
	StateReadonly  State = "readonly"
	StateRetired   State = "retired"
	StateRejected  State = "rejected"
)

// Log is the unified record for one CT log.
type Log struct {
	LogID         [32]byte      // SHA-256 of SubjectPublicKeyInfo (canonical identity)
	Description   string        // human-readable name
	Operator      string        // operator org name
	Protocol      Protocol      // static-ct-api or rfc6962
	State         State         // usable, readonly, retired, ...
	StateSince    time.Time     // timestamp of the current state
	SubmissionURL string        // submission endpoint (also the API root for both protocols)
	MonitoringURL string        // tile logs only — read endpoint (mon. host)
	MMD           time.Duration // maximum merge delay
	TemporalStart time.Time     // zero if not set
	TemporalEnd   time.Time     // zero if not set
	FinalTreeSize int64         // readonly only — last tree size before freeze
}

// IsUsable reports whether the log accepts new submissions and serves entries.
func (l *Log) IsUsable() bool { return l.State == StateUsable }

// APIRoot returns the URL the ingester should pull from. For tile logs this is
// the monitoring URL; for RFC 6962 the submission URL doubles as the read host.
func (l *Log) APIRoot() string {
	if l.Protocol == ProtocolStaticCT && l.MonitoringURL != "" {
		return l.MonitoringURL
	}
	return l.SubmissionURL
}

// FetchLogList downloads and parses the log list at url. Pass "" for the default.
func FetchLogList(ctx context.Context, url string) ([]Log, error) {
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
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return ParseLogList(body)
}

// ParseLogList parses log_list.json bytes into Log records.
func ParseLogList(data []byte) ([]Log, error) {
	var raw rawLogList
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse log_list.json: %w", err)
	}
	var out []Log
	for _, op := range raw.Operators {
		for _, rl := range op.Logs {
			l, err := buildLog(rl, op.Name, ProtocolRFC6962)
			if err != nil {
				return nil, fmt.Errorf("operator %q log %q: %w", op.Name, rl.Description, err)
			}
			out = append(out, l)
		}
		for _, rl := range op.TiledLogs {
			l, err := buildLog(rl, op.Name, ProtocolStaticCT)
			if err != nil {
				return nil, fmt.Errorf("operator %q tiled_log %q: %w", op.Name, rl.Description, err)
			}
			out = append(out, l)
		}
	}
	return out, nil
}

// FilterUsable returns only logs with state == usable.
func FilterUsable(logs []Log) []Log {
	out := make([]Log, 0, len(logs))
	for _, l := range logs {
		if l.IsUsable() {
			out = append(out, l)
		}
	}
	return out
}

// FilterExcludeOperators removes logs whose Operator matches any name in ops.
// Useful for skipping operators that are not worth the rate-limit overhead.
func FilterExcludeOperators(logs []Log, ops []string) []Log {
	if len(ops) == 0 {
		return logs
	}
	skip := make(map[string]bool, len(ops))
	for _, o := range ops {
		skip[o] = true
	}
	out := make([]Log, 0, len(logs))
	for _, l := range logs {
		if !skip[l.Operator] {
			out = append(out, l)
		}
	}
	return out
}

// FilterByProtocol returns only logs matching one of the given protocols.
// Pass no arguments to return all.
func FilterByProtocol(logs []Log, protos ...Protocol) []Log {
	if len(protos) == 0 {
		return logs
	}
	want := make(map[Protocol]bool, len(protos))
	for _, p := range protos {
		want[p] = true
	}
	out := make([]Log, 0, len(logs))
	for _, l := range logs {
		if want[l.Protocol] {
			out = append(out, l)
		}
	}
	return out
}

// ── private parsing ─────────────────────────────────────────────────────────

type rawLogList struct {
	Version          string        `json:"version"`
	LogListTimestamp string        `json:"log_list_timestamp"`
	Operators        []rawOperator `json:"operators"`
}

type rawOperator struct {
	Name      string   `json:"name"`
	Email     []string `json:"email"`
	Logs      []rawLog `json:"logs"`
	TiledLogs []rawLog `json:"tiled_logs"`
}

type rawLog struct {
	Description      string                 `json:"description"`
	LogID            string                 `json:"log_id"` // base64
	Key              string                 `json:"key"`
	URL              string                 `json:"url"`            // rfc6962
	SubmissionURL    string                 `json:"submission_url"` // tiled
	MonitoringURL    string                 `json:"monitoring_url"` // tiled
	MMD              int64                  `json:"mmd"`
	State            map[string]rawStateVal `json:"state"`
	TemporalInterval *rawInterval           `json:"temporal_interval"`
}

type rawStateVal struct {
	Timestamp     string           `json:"timestamp"`
	FinalTreeHead *rawFinalTreeHead `json:"final_tree_head"`
}

type rawFinalTreeHead struct {
	TreeSize int64  `json:"tree_size"`
	SHA256   string `json:"sha256_root_hash"`
}

type rawInterval struct {
	StartInclusive string `json:"start_inclusive"`
	EndExclusive   string `json:"end_exclusive"`
}

func buildLog(r rawLog, operator string, proto Protocol) (Log, error) {
	id, err := decodeLogID(r.LogID)
	if err != nil {
		return Log{}, fmt.Errorf("log_id: %w", err)
	}

	state, stateSince, finalSize := pickState(r.State)

	l := Log{
		LogID:         id,
		Description:   r.Description,
		Operator:      operator,
		Protocol:      proto,
		State:         state,
		StateSince:    stateSince,
		MMD:           time.Duration(r.MMD) * time.Second,
		FinalTreeSize: finalSize,
	}

	switch proto {
	case ProtocolRFC6962:
		l.SubmissionURL = ensureTrailingSlash(r.URL)
	case ProtocolStaticCT:
		l.SubmissionURL = ensureTrailingSlash(r.SubmissionURL)
		l.MonitoringURL = ensureTrailingSlash(r.MonitoringURL)
	}

	if r.TemporalInterval != nil {
		if t, err := time.Parse(time.RFC3339, r.TemporalInterval.StartInclusive); err == nil {
			l.TemporalStart = t
		}
		if t, err := time.Parse(time.RFC3339, r.TemporalInterval.EndExclusive); err == nil {
			l.TemporalEnd = t
		}
	}
	return l, nil
}

func decodeLogID(s string) ([32]byte, error) {
	var id [32]byte
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return id, err
	}
	if len(b) != 32 {
		return id, fmt.Errorf("expected 32 bytes, got %d", len(b))
	}
	copy(id[:], b)
	return id, nil
}

func pickState(m map[string]rawStateVal) (State, time.Time, int64) {
	for k, v := range m {
		ts, _ := time.Parse(time.RFC3339, v.Timestamp)
		var size int64
		if v.FinalTreeHead != nil {
			size = v.FinalTreeHead.TreeSize
		}
		return State(k), ts, size
	}
	return "", time.Time{}, 0
}

func ensureTrailingSlash(s string) string {
	if s == "" || strings.HasSuffix(s, "/") {
		return s
	}
	return s + "/"
}
