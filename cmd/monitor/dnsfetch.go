package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/accretional/proto-ct/internal/dashboard"
)

var (
	reRunnerStart = regexp.MustCompile(`\[\d{2}:\d{2}:\d{2}\] === (.+?) \(\s*([\d ]+)\s*domains\) ===`)
	reRunnerDone  = regexp.MustCompile(`\[\d{2}:\d{2}:\d{2}\] === done (\S+)`)
	reMetrics     = regexp.MustCompile(`metrics: done=(\d+) rate=([\d.]+)/s ok=(\d+) nxd=(\d+) timeout=(\d+) err=(\d+)\([^)]+\) cb=(\S+)`)
	reFeed        = regexp.MustCompile(`feed: \S+ → (\d+) domains queued`)
	reComplete    = regexp.MustCompile(`complete: total=(\d+)`)
)

type shardState struct {
	key     string
	total   int64
	done    int64
	rate    float64
	ok      int64
	nxd     int64
	timeout int64
	errs    int64
	cbState string
	status  string // "running" | "complete" | "finalized" | "interrupted"
	// lastMetricAt is the timestamp parsed from the most recent
	// "metrics:" line in the per-shard log. Zero means the log was
	// empty or had no metrics. Used to disambiguate which shard is
	// actually running when runner.log accumulates stale "===" markers
	// across runner restarts.
	lastMetricAt time.Time
}

type dnsfetchPanel struct {
	logsDir string
	current *shardState
	history []shardState
}

func (p *dnsfetchPanel) Update() {
	p.current, p.history = parseShardLogs(p.logsDir)
}

func (p *dnsfetchPanel) Render(w int) string {
	var sb strings.Builder

	if p.current != nil {
		sb.WriteString(renderShard(p.current, w, true))
	}

	if len(p.history) > 0 {
		sb.WriteString(dashboard.Header("Completed", w) + "\n")
		for _, sh := range p.history {
			icon := dashboard.Green + "✓" + dashboard.Reset
			if sh.status == "interrupted" {
				icon = dashboard.Red + "✕" + dashboard.Reset
			}
			line := fmt.Sprintf("  %s %-22s  %s%s%s  ok=%s  nxd=%s  timeout=%s",
				icon, sh.key,
				dashboard.Bold, dashboard.CommaSep(sh.done), dashboard.Reset,
				dashboard.CommaSep(sh.ok), dashboard.CommaSep(sh.nxd), dashboard.CommaSep(sh.timeout))
			if sh.rate > 0 {
				line += fmt.Sprintf("  rate=%.0f/s", sh.rate)
			}
			sb.WriteString(line + "\n")
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

func renderShard(sh *shardState, w int, active bool) string {
	title := "◉ DNS Fetch: " + sh.key
	if !active || sh.status != "running" {
		title = "✓ DNS Fetch: " + sh.key
	}
	if sh.status == "interrupted" {
		title = "✕ DNS Fetch: " + sh.key
	}

	var sb strings.Builder
	sb.WriteString(dashboard.Header(title, w) + "\n")

	if sh.total > 0 {
		pct := 100.0 * float64(sh.done) / float64(sh.total)
		eta := ""
		if sh.rate > 0 && sh.done < sh.total {
			rem := float64(sh.total-sh.done) / sh.rate
			eta = "  ETA " + dashboard.Yellow + dashboard.FormatETA(rem) + dashboard.Reset
		}
		fmt.Fprintf(&sb, "  Done: %s%s%s / %s  (%s%.1f%%%s)  Rate: %s%.1f/s%s%s\n",
			dashboard.Bold, dashboard.CommaSep(sh.done), dashboard.Reset,
			dashboard.CommaSep(sh.total),
			dashboard.Yellow, pct, dashboard.Reset,
			dashboard.Cyan, sh.rate, dashboard.Reset,
			eta,
		)
		if barW := w - 4; barW > 0 {
			sb.WriteString("  " + dashboard.ProgressBar(pct, barW) + "\n")
		}
	} else if sh.done > 0 {
		fmt.Fprintf(&sb, "  Done: %s%s%s  Rate: %s%.1f/s%s\n",
			dashboard.Bold, dashboard.CommaSep(sh.done), dashboard.Reset,
			dashboard.Cyan, sh.rate, dashboard.Reset)
	}

	errCol := dashboard.Green
	if sh.errs > 0 {
		errCol = dashboard.Red
	}
	fmt.Fprintf(&sb, "  OK: %s%s%s  NXDOM: %s  Timeout: %s  Err: %s%s%s  CB: %s\n\n",
		dashboard.Green, dashboard.CommaSep(sh.ok), dashboard.Reset,
		dashboard.CommaSep(sh.nxd),
		dashboard.CommaSep(sh.timeout),
		errCol, dashboard.CommaSep(sh.errs), dashboard.Reset,
		sh.cbState,
	)
	return sb.String()
}

// ── log parsers ───────────────────────────────────────────────────────────────

type runnerEntry struct {
	key    string
	total  int64
	status string // "running" | "complete"
}

func parseRunnerLog(path string) []runnerEntry {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var order []string
	byKey := map[string]*runnerEntry{}

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if m := reRunnerStart.FindStringSubmatch(line); m != nil {
			key := strings.TrimSpace(m[1])
			total, _ := strconv.ParseInt(strings.ReplaceAll(m[2], " ", ""), 10, 64)
			if _, seen := byKey[key]; !seen {
				order = append(order, key)
				byKey[key] = &runnerEntry{key: key}
			}
			byKey[key].total = total
			byKey[key].status = "running"
		} else if m := reRunnerDone.FindStringSubmatch(line); m != nil {
			key := m[1]
			if e, ok := byKey[key]; ok {
				e.status = "complete"
			} else {
				order = append(order, key)
				byKey[key] = &runnerEntry{key: key, status: "complete"}
			}
		}
	}

	out := make([]runnerEntry, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	return out
}

func parseShardLogFile(path string) shardState {
	var sh shardState
	sh.status = "running"

	f, err := os.Open(path)
	if err != nil {
		return sh
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.Contains(line, "metrics:"):
			if m := reMetrics.FindStringSubmatch(line); m != nil {
				sh.done, _ = strconv.ParseInt(m[1], 10, 64)
				sh.rate, _ = strconv.ParseFloat(m[2], 64)
				sh.ok, _ = strconv.ParseInt(m[3], 10, 64)
				sh.nxd, _ = strconv.ParseInt(m[4], 10, 64)
				sh.timeout, _ = strconv.ParseInt(m[5], 10, 64)
				sh.errs, _ = strconv.ParseInt(m[6], 10, 64)
				sh.cbState = m[7]
			}
			// Capture the leading "YYYY/MM/DD HH:MM:SS" timestamp so
			// parseShardLogs can disambiguate concurrent "running"
			// entries by last-seen metric time.
			if len(line) >= 19 {
				if t, err := time.ParseInLocation("2006/01/02 15:04:05", line[:19], time.Local); err == nil {
					sh.lastMetricAt = t
				}
			}
		case strings.Contains(line, "feed:"):
			if sh.total == 0 {
				if m := reFeed.FindStringSubmatch(line); m != nil {
					sh.total, _ = strconv.ParseInt(m[1], 10, 64)
				}
			}
		case strings.Contains(line, "complete: total="):
			sh.status = "complete"
			if m := reComplete.FindStringSubmatch(line); m != nil {
				sh.done, _ = strconv.ParseInt(m[1], 10, 64)
			}
		case strings.Contains(line, "finalized:"):
			sh.status = "finalized"
		case strings.Contains(line, "shutting down"):
			sh.status = "interrupted"
		}
	}
	return sh
}

func parseShardLogs(logsDir string) (current *shardState, history []shardState) {
	entries := parseRunnerLog(filepath.Join(logsDir, "runner.log"))

	parsed := make([]shardState, len(entries))
	mtimes := make([]time.Time, len(entries))
	for i, e := range entries {
		path := filepath.Join(logsDir, strings.ReplaceAll(e.key, "/", "-")+".log")
		sh := parseShardLogFile(path)
		sh.key = e.key
		if e.total > 0 && sh.total == 0 {
			sh.total = e.total
		}
		if e.status == "complete" && sh.status == "running" {
			sh.status = "complete"
		}
		parsed[i] = sh
		if st, err := os.Stat(path); err == nil {
			mtimes[i] = st.ModTime()
		}
	}

	// Pick "current" as the running entry whose log shows the most
	// recent metrics-line timestamp — the only signal that proves a
	// dnsfetch process is actively writing to it. runner.log alone
	// isn't enough: when an SIGINT'd run looks like a clean exit, the
	// runner script emits "=== done X ===" and loop-spawns the next
	// shard before being killed too, leaving both the previous and
	// the next shard with "running" markers in runner.log.
	bestIdx := -1
	var bestTime time.Time
	for i, sh := range parsed {
		if sh.status != "running" || sh.lastMetricAt.IsZero() {
			continue
		}
		if sh.lastMetricAt.After(bestTime) {
			bestTime = sh.lastMetricAt
			bestIdx = i
		}
	}
	// Fallback for brand-new shards (process just started, no metrics
	// line yet): pick the running entry whose log file mtime is most
	// recent. The active tee'd-into file gets touched on every flush.
	if bestIdx == -1 {
		for i, sh := range parsed {
			if sh.status != "running" {
				continue
			}
			if mtimes[i].After(bestTime) {
				bestTime = mtimes[i]
				bestIdx = i
			}
		}
	}

	for i := len(parsed) - 1; i >= 0; i-- {
		if i == bestIdx {
			shCopy := parsed[i]
			current = &shCopy
		} else {
			sh := parsed[i]
			// A "running" entry that isn't the active one was started
			// in some earlier runner pass and never finished — its
			// dnsfetch process is gone. Show it as interrupted, not as
			// completed (the default ✓ icon would be misleading).
			if sh.status == "running" {
				sh.status = "interrupted"
			}
			history = append(history, sh)
		}
	}
	return
}
