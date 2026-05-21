package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/benfultz/proto-ct/internal/dashboard"
)

var reIngestionLine = regexp.MustCompile(
	`\[metrics ([^\]]+)\] tree=(\d+) processed=(\d+) coverage=([\d.]+)% db_total=(.+)`)

type ingestionState struct {
	tree      int64
	processed int64
	coverage  float64
	dbTotal   string
	updatedAt string
}

type ingestionPanel struct {
	logPath string
	state   *ingestionState
}

func (p *ingestionPanel) Update() {
	f, err := os.Open(p.logPath)
	if err != nil {
		return
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
		return
	}
	s := &ingestionState{updatedAt: m[1], dbTotal: strings.TrimSpace(m[5])}
	s.tree, _ = strconv.ParseInt(m[2], 10, 64)
	s.processed, _ = strconv.ParseInt(m[3], 10, 64)
	s.coverage, _ = strconv.ParseFloat(m[4], 64)
	p.state = s
}

func (p *ingestionPanel) Render(w int) string {
	if p.state == nil {
		return ""
	}
	s := p.state
	var sb strings.Builder
	sb.WriteString(dashboard.Header("CT Ingestion", w) + "\n")
	fmt.Fprintf(&sb, "  Tree: %s%s%s  Processed: %s%s%s  Coverage: %s%.2f%%%s  DB: %s\n",
		dashboard.Bold, dashboard.CommaSep(s.tree), dashboard.Reset,
		dashboard.Bold, dashboard.CommaSep(s.processed), dashboard.Reset,
		dashboard.Yellow, s.coverage, dashboard.Reset,
		s.dbTotal,
	)
	fmt.Fprintf(&sb, "  %sUpdated: %s%s\n\n", dashboard.Gray, s.updatedAt, dashboard.Reset)
	return sb.String()
}
