package ingestion

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	pb "github.com/benfultz/proto-ct/gen/ctingestion/v1"
	"github.com/benfultz/proto-ct/internal/ctlog"
	"github.com/benfultz/proto-ct/internal/db"
)

// computeMetrics assembles a CheckResponse by reading the progress DB, walking
// both the active and archive directories for file sizes, and fetching the live
// tree size.
func computeMetrics(ctx context.Context, activeDir, archiveDir, monitoringRoot string) (*pb.CheckResponse, error) {
	resp := &pb.CheckResponse{
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}

	// Sum all SQLite files under both dirs (active has today's, archive has all prior days').
	walkDir := func(dir string) {
		if dir == "" {
			return
		}
		_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".db") {
				return nil
			}
			resp.DbFiles = append(resp.DbFiles, &pb.DbInfo{
				Path:      path,
				SizeBytes: info.Size(),
			})
			resp.DbBytesTotal += info.Size()
			return nil
		})
	}
	walkDir(activeDir)
	walkDir(archiveDir)

	// Total entries mirrored from progress DB (lives in archive dir).
	progressPath := filepath.Join(archiveDir, "progress.db")
	if pdb, err := db.OpenProgressDB(progressPath); err == nil {
		if n, err := pdb.GetTotalProcessed(monitoringRoot); err == nil {
			resp.TotalProcessed = n
		}
		pdb.Close()
	}

	// Live tree size from the CT log checkpoint (uses unlimited client).
	if monitoringRoot != "" {
		c := ctlog.NewClient(monitoringRoot, 0)
		if size, err := c.TreeSize(ctx); err == nil {
			resp.TreeSize = size
		}
	}

	if resp.TreeSize > 0 {
		resp.CoveragePct = float64(resp.TotalProcessed) / float64(resp.TreeSize) * 100
	}

	return resp, nil
}

// writeMetricsLine formats and writes a single metrics log line to w.
func writeMetricsLine(w io.Writer, resp *pb.CheckResponse) {
	fmt.Fprintf(w,
		"[metrics %s] tree=%d processed=%d coverage=%.6f%% db_total=%s\n",
		resp.UpdatedAt,
		resp.TreeSize,
		resp.TotalProcessed,
		resp.CoveragePct,
		formatBytes(resp.DbBytesTotal),
	)
}

// openIngestionLog opens (or creates) the append-mode metrics log file.
func openIngestionLog(outputDir string) (*os.File, error) {
	return os.OpenFile(
		filepath.Join(outputDir, "ingestion.log"),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY,
		0o644,
	)
}

func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
