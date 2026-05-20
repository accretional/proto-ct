package main

import (
	"bufio"
	"flag"
	"fmt"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var (
	flagLogs    = flag.String("logs", "data/logs", "directory containing shard and runner log files")
	flagIngLog  = flag.String("ingestion-log", "", "path to ingestion.log (auto-detected if empty)")
	flagRefresh = flag.Duration("refresh", 5*time.Second, "refresh interval")
)

// ── ANSI ─────────────────────────────────────────────────────────────────────

const (
	clrScreen = "\033[2J\033[H"
	reset     = "\033[0m"
	bold      = "\033[1m"
	green     = "\033[32m"
	yellow    = "\033[33m"
	cyan      = "\033[36m"
	gray      = "\033[90m"
	red       = "\033[31m"
)

// ── regex ─────────────────────────────────────────────────────────────────────

var (
	reRunnerStart   = regexp.MustCompile(`\[\d{2}:\d{2}:\d{2}\] === (.+?) \(\s*([\d ]+)\s*domains\) ===`)
	reRunnerDone    = regexp.MustCompile(`\[\d{2}:\d{2}:\d{2}\] === done (\S+)`)
	reMetrics       = regexp.MustCompile(`metrics: done=(\d+) rate=([\d.]+)/s ok=(\d+) nxd=(\d+) timeout=(\d+) err=(\d+)\([^)]+\) cb=(\S+)`)
	reFeed          = regexp.MustCompile(`feed: \S+ → (\d+) domains queued`)
	reComplete      = regexp.MustCompile(`complete: total=(\d+)`)
	reIngestionLine = regexp.MustCompile(`\[metrics ([^\]]+)\] tree=(\d+) processed=(\d+) coverage=([\d.]+)% db_total=(.+)`)
)

// ── data types ────────────────────────────────────────────────────────────────

type ingestionState struct {
	tree      int64
	processed int64
	coverage  float64
	dbTotal   string
	updatedAt string
}

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
}

// ── parsers ───────────────────────────────────────────────────────────────────

func parseIngestionLog(path string) *ingestionState {
	if path == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var last string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if l := sc.Text(); strings.HasPrefix(l, "[metrics ") {
			last = l
		}
	}
	m := reIngestionLine.FindStringSubmatch(last)
	if m == nil {
		return nil
	}
	s := &ingestionState{updatedAt: m[1], dbTotal: strings.TrimSpace(m[5])}
	s.tree, _ = strconv.ParseInt(m[2], 10, 64)
	s.processed, _ = strconv.ParseInt(m[3], 10, 64)
	s.coverage, _ = strconv.ParseFloat(m[4], 64)
	return s
}

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
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		sh := parseShardLogFile(filepath.Join(logsDir, strings.ReplaceAll(e.key, "/", "-")+".log"))
		sh.key = e.key
		if e.total > 0 && sh.total == 0 {
			sh.total = e.total
		}
		if e.status == "complete" && sh.status == "running" {
			sh.status = "complete"
		}
		if current == nil && sh.status == "running" {
			shCopy := sh
			current = &shCopy
		} else {
			history = append(history, sh)
		}
	}
	return
}

// ── rendering ────────────────────────────────────────────────────────────────

type winsize struct{ Row, Col, Xpixel, Ypixel uint16 }

func termWidth() int {
	ws := winsize{}
	syscall.Syscall(syscall.SYS_IOCTL, uintptr(os.Stdout.Fd()), syscall.TIOCGWINSZ, uintptr(unsafe.Pointer(&ws)))
	if ws.Col > 0 {
		return int(ws.Col)
	}
	if s := os.Getenv("COLUMNS"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			return n
		}
	}
	return 80
}

func header(title string, w int) string {
	line := "── " + title + " "
	if rem := w - len(line) - 1; rem > 0 {
		line += strings.Repeat("─", rem)
	}
	return bold + cyan + line + reset
}

func progressBar(pct float64, w int) string {
	n := int(math.Round(float64(w) * pct / 100.0))
	n = min(n, w)
	return green + strings.Repeat("█", n) + gray + strings.Repeat("░", w-n) + reset
}

func commaSep(n int64) string {
	s := strconv.FormatInt(n, 10)
	if len(s) <= 3 {
		return s
	}
	var b strings.Builder
	pre := len(s) % 3
	if pre > 0 {
		b.WriteString(s[:pre])
	}
	for i := pre; i < len(s); i += 3 {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(s[i : i+3])
	}
	return b.String()
}

func formatETA(sec float64) string {
	switch {
	case sec < 90:
		return fmt.Sprintf("~%.0fs", sec)
	case sec < 5400:
		return fmt.Sprintf("~%.0fm", sec/60)
	default:
		return fmt.Sprintf("~%.1fh", sec/3600)
	}
}

func render(ing *ingestionState, cur *shardState, hist []shardState, lastSeen time.Time) {
	w := termWidth()
	var sb strings.Builder
	sb.WriteString(clrScreen)

	if ing != nil {
		sb.WriteString(header("CT Ingestion", w) + "\n")
		fmt.Fprintf(&sb, "  Tree: %s%s%s  Processed: %s%s%s  Coverage: %s%.2f%%%s  DB: %s\n",
			bold, commaSep(ing.tree), reset,
			bold, commaSep(ing.processed), reset,
			yellow, ing.coverage, reset,
			ing.dbTotal,
		)
		fmt.Fprintf(&sb, "  %sUpdated: %s%s\n\n", gray, ing.updatedAt, reset)
	}

	if cur != nil {
		sb.WriteString(header("◉ DNS Fetch: "+cur.key, w) + "\n")
		if cur.total > 0 {
			pct := 100.0 * float64(cur.done) / float64(cur.total)
			eta := ""
			if cur.rate > 0 && cur.done < cur.total {
				rem := float64(cur.total-cur.done) / cur.rate
				eta = "  ETA " + yellow + formatETA(rem) + reset
			}
			fmt.Fprintf(&sb, "  Done: %s%s%s / %s  (%s%.1f%%%s)  Rate: %s%.1f/s%s%s\n",
				bold, commaSep(cur.done), reset,
				commaSep(cur.total),
				yellow, pct, reset,
				cyan, cur.rate, reset,
				eta,
			)
			if barW := w - 4; barW > 0 {
				sb.WriteString("  " + progressBar(pct, barW) + "\n")
			}
		} else if cur.done > 0 {
			fmt.Fprintf(&sb, "  Done: %s%s%s  Rate: %s%.1f/s%s\n",
				bold, commaSep(cur.done), reset, cyan, cur.rate, reset)
		}
		errCol := green
		if cur.errs > 0 {
			errCol = red
		}
		fmt.Fprintf(&sb, "  OK: %s%s%s  NXDOM: %s  Timeout: %s  Err: %s%s%s  CB: %s\n\n",
			green, commaSep(cur.ok), reset,
			commaSep(cur.nxd),
			commaSep(cur.timeout),
			errCol, commaSep(cur.errs), reset,
			cur.cbState,
		)
	}

	if len(hist) > 0 {
		sb.WriteString(header("Completed", w) + "\n")
		for _, sh := range hist {
			icon := green + "✓" + reset
			if sh.status == "interrupted" {
				icon = red + "✕" + reset
			}
			line := fmt.Sprintf("  %s %-22s  %s%s%s  ok=%s  nxd=%s  timeout=%s",
				icon, sh.key,
				bold, commaSep(sh.done), reset,
				commaSep(sh.ok), commaSep(sh.nxd), commaSep(sh.timeout))
			if sh.rate > 0 {
				line += fmt.Sprintf("  rate=%.0f/s", sh.rate)
			}
			sb.WriteString(line + "\n")
		}
		sb.WriteString("\n")
	}

	if ing == nil && cur == nil && len(hist) == 0 {
		sb.WriteString(gray + "  Waiting for data — check --logs and --ingestion-log flags\n\n" + reset)
	}

	ts := "—"
	if !lastSeen.IsZero() {
		ts = lastSeen.Format("15:04:05")
	}
	fmt.Fprintf(&sb, "%s  Ctrl+C to quit  updated: %s%s\n", gray, ts, reset)

	fmt.Print(sb.String())
}

// ── main ─────────────────────────────────────────────────────────────────────

func main() {
	flag.Parse()

	ingLog := *flagIngLog
	if ingLog == "" {
		for _, p := range []string{
			"/Volumes/wd_office_2/datasets/CT/ingestion.log",
			"/tmp/ct-data/ingestion.log",
		} {
			if _, err := os.Stat(p); err == nil {
				ingLog = p
				break
			}
		}
	}

	refresh := func() {
		ing := parseIngestionLog(ingLog)
		cur, hist := parseShardLogs(*flagLogs)
		render(ing, cur, hist, time.Now())
	}

	refresh()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(*flagRefresh)
	defer ticker.Stop()
	for {
		select {
		case <-sig:
			fmt.Print(clrScreen)
			return
		case <-ticker.C:
			refresh()
		}
	}
}
