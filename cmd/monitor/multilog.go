package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/benfultz/proto-ct/internal/dashboard"
	"github.com/benfultz/proto-ct/internal/db"
)

// multilogPanel reads the log_runs table from progress.db and renders a row
// per CT log, ordered by operator + description.
type multilogPanel struct {
	progressDBPath string
	runs           []db.LogRun
	err            string
	updatedAt      time.Time
}

func (p *multilogPanel) Update() {
	if _, err := os.Stat(p.progressDBPath); err != nil {
		p.err = "progress.db not found at " + p.progressDBPath
		p.runs = nil
		return
	}
	pdb, err := db.OpenProgressDB(p.progressDBPath)
	if err != nil {
		p.err = "open: " + err.Error()
		return
	}
	defer pdb.Close()
	runs, err := pdb.ListLogRuns()
	if err != nil {
		p.err = "query: " + err.Error()
		return
	}
	// Sort: still-running (state=usable, NextEntryIdx < TreeSizeAtStart) first,
	// then by operator + description for stable ordering.
	sort.SliceStable(runs, func(i, j int) bool {
		ai := runs[i].NextEntryIdx < runs[i].TreeSizeAtStart
		aj := runs[j].NextEntryIdx < runs[j].TreeSizeAtStart
		if ai != aj {
			return ai
		}
		if runs[i].Operator != runs[j].Operator {
			return runs[i].Operator < runs[j].Operator
		}
		return runs[i].Description < runs[j].Description
	})
	p.runs = runs
	p.err = ""
	p.updatedAt = time.Now()
}

func (p *multilogPanel) Render(w int) string {
	var sb strings.Builder
	sb.WriteString(dashboard.Header("CT Multi-Log Progress", w) + "\n")
	if p.err != "" {
		fmt.Fprintf(&sb, "  %s%s%s\n\n", dashboard.Red, p.err, dashboard.Reset)
		return sb.String()
	}
	if len(p.runs) == 0 {
		fmt.Fprintf(&sb, "  %s(no log_runs rows yet — start IngestAll on the server)%s\n\n",
			dashboard.Gray, dashboard.Reset)
		return sb.String()
	}

	// Column layout:
	//   operator (12) | description (32) | proto (12) | progress bar (16) | pct (6) | processed (12)
	fmt.Fprintf(&sb, "  %s%-12s %-32s %-12s %-16s %6s %12s%s\n",
		dashboard.Gray, "OPERATOR", "LOG", "PROTOCOL", "PROGRESS", "PCT", "PROCESSED", dashboard.Reset)
	for _, r := range p.runs {
		pct := 0.0
		if r.TreeSizeAtStart > 0 {
			pct = float64(r.NextEntryIdx) / float64(r.TreeSizeAtStart) * 100
			if pct > 100 {
				pct = 100
			}
		}
		bar := dashboard.ProgressBar(pct, 16)
		op := truncate(r.Operator, 12)
		desc := truncate(r.Description, 32)
		proto := truncate(r.Protocol, 12)
		stateColor := stateColorFor(r.State, pct)
		fmt.Fprintf(&sb, "  %-12s %s%-32s%s %-12s %s %s%5.1f%%%s %12s\n",
			op, stateColor, desc, dashboard.Reset, proto, bar, dashboard.Yellow, pct, dashboard.Reset,
			dashboard.CommaSep(r.TotalProcessed))
	}
	fmt.Fprintf(&sb, "  %sUpdated: %s%s\n\n", dashboard.Gray, p.updatedAt.Format("15:04:05"), dashboard.Reset)
	return sb.String()
}

func stateColorFor(state string, pct float64) string {
	switch state {
	case "readonly", "retired":
		return dashboard.Gray
	}
	if pct >= 99.5 {
		return dashboard.Green
	}
	return dashboard.Cyan
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n < 3 {
		return s[:n]
	}
	return s[:n-1] + "…"
}
