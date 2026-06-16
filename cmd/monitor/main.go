package main

import (
	"flag"
	"os"
	"time"

	"github.com/accretional/proto-ct/internal/dashboard"
)

var (
	flagLogs       = flag.String("logs", "data/logs", "directory containing shard and runner log files")
	flagIngLog     = flag.String("ingestion-log", "", "path to ingestion.log (auto-detected if empty)")
	flagProgressDB = flag.String("progress-db", "", "path to progress.db (auto-detected if empty); enables the CT multi-log panel")
	flagRefresh    = flag.Duration("refresh", 5*time.Second, "refresh interval")
)

func main() {
	flag.Parse()

	ingLog := resolveIngestionLog(*flagIngLog)
	progressDB := resolveProgressDB(*flagProgressDB)

	var panels []dashboard.Panel
	if progressDB != "" {
		panels = append(panels, &multilogPanel{progressDBPath: progressDB})
	}
	if ingLog != "" {
		panels = append(panels, &ingestionPanel{logPath: ingLog})
	}
	panels = append(panels, &dnsfetchPanel{logsDir: *flagLogs})

	dashboard.Run(*flagRefresh, panels...)
}

// resolveProgressDB returns path if non-empty, otherwise probes known archive locations.
func resolveProgressDB(path string) string {
	if path != "" {
		return path
	}
	for _, candidate := range []string{
		"data/active/progress.db", // SSD location after the rollover/shared-DB move
		"/Volumes/wd_office_2/datasets/CT/progress.db",
		"/tmp/ct-data/progress.db",
		"data/progress.db",
	} {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return ""
}

// resolveIngestionLog returns path if non-empty, otherwise checks well-known
// locations and returns the first one that exists.
func resolveIngestionLog(path string) string {
	if path != "" {
		return path
	}
	for _, candidate := range []string{
		"/Volumes/wd_office_2/datasets/CT/ingestion.log",
		"/tmp/ct-data/ingestion.log",
	} {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return ""
}
