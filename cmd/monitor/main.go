package main

import (
	"flag"
	"os"
	"time"

	"github.com/benfultz/proto-ct/internal/dashboard"
)

var (
	flagLogs    = flag.String("logs", "data/logs", "directory containing shard and runner log files")
	flagIngLog  = flag.String("ingestion-log", "", "path to ingestion.log (auto-detected if empty)")
	flagRefresh = flag.Duration("refresh", 5*time.Second, "refresh interval")
)

func main() {
	flag.Parse()

	ingLog := resolveIngestionLog(*flagIngLog)

	var panels []dashboard.Panel
	if ingLog != "" {
		panels = append(panels, &ingestionPanel{logPath: ingLog})
	}
	panels = append(panels, &dnsfetchPanel{logsDir: *flagLogs})

	dashboard.Run(*flagRefresh, panels...)
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
