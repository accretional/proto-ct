package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	pb "github.com/benfultz/proto-ct/gen/ctingestion/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	serverAddr     = flag.String("addr", "localhost:50051", "server address")
	monitoringRoot = flag.String("root", "https://mon.sycamore.ct.letsencrypt.org/2026h1/tile/data/", "monitoring API root (tile/data/ endpoint)")
	batchSize      = flag.Int64("batch", 1000, "entries to mirror this session (ignored when --continuous is set)")
	activeDir      = flag.String("out", "data/active/", "active staging dir (fast local SSD); dated subdirs are written here")
	archiveDir     = flag.String("archive", "/Volumes/wd_office_2/datasets/CT/", "persistent archive dir; receives completed dated dirs on rollover, holds progress.db")
	targetQPS      = flag.Float64("qps", 500, "target QPS to monitoring endpoint (actual = 80%); 0 = unlimited")
	checkMode      = flag.Bool("check", false, "run a one-shot metrics check instead of ingesting")
	continuous     = flag.Bool("continuous", false, "mirror until fully caught up with the live log (no batch limit)")
	sizeLimit      = flag.Int64("size-limit", 50, "roll over active DB to archive when subjects.db reaches this size in GiB (0 = disabled)")

	// IngestAll (multi-log) mode flags.
	allMode             = flag.Bool("all", false, "run multi-log ingestion across every usable CT log in the gstatic v3 log_list")
	logListURL          = flag.String("log-list", "", "log_list.json URL (empty = gstatic v3 default)")
	protocols           = flag.String("protocols", "", "comma-separated protocol filter for --all (e.g. 'static-ct-api,rfc6962'); empty = both")
	operators           = flag.String("operators", "", "comma-separated operator filter for --all (e.g. \"Let's Encrypt,Google\"); empty = all")
	descContains        = flag.String("desc-contains", "", "only logs whose description contains this substring (e.g. '2026h1')")
	perLogQPS           = flag.Float64("per-log-qps", 0, "target QPS per log under --all; 0 = protocol default (static=20, rfc6962=10)")
	batchSizePerLog     = flag.Int64("batch-per-log", 0, "entries-per-log cap for --all (0 = run until each log is caught up)")
	progressEvery       = flag.Int64("progress-every", 10000, "emit a LogProgress event every N entries per log")
)

func main() {
	flag.Parse()

	conn, err := grpc.NewClient(*serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("connect %s: %v", *serverAddr, err)
	}
	defer conn.Close()

	client := pb.NewCTIngestionServiceClient(conn)

	if *checkMode {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		runCheck(ctx, client)
		return
	}
	// Ingest mode: no deadline — jobs can run for many hours.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if *allMode {
		runIngestAll(ctx, client)
		return
	}
	runIngest(ctx, client)
}

func runIngestAll(ctx context.Context, client pb.CTIngestionServiceClient) {
	req := &pb.IngestAllRequest{
		LogListUrl:          *logListURL,
		Protocols:           splitCSV(*protocols),
		Operators:           splitCSV(*operators),
		DescriptionContains: *descContains,
		PerLogQps:           *perLogQPS,
		BatchSizePerLog:     *batchSizePerLog,
		OutputDir:           *activeDir,
		ArchiveDir:          *archiveDir,
		ProgressEvery:       *progressEvery,
	}
	log.Printf("IngestAll: protocols=%v operators=%v desc=%q per-log-qps=%.0f batch-per-log=%d",
		req.Protocols, req.Operators, req.DescriptionContains, req.PerLogQps, req.BatchSizePerLog)

	stream, err := client.IngestAll(ctx, req)
	if err != nil {
		log.Fatalf("IngestAll: %v", err)
	}
	for {
		ev, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatalf("stream recv: %v", err)
		}
		pct := 0.0
		if ev.TreeSize > 0 {
			pct = float64(ev.NextEntryIdx) / float64(ev.TreeSize) * 100
		}
		switch ev.Status {
		case "error":
			log.Printf("[%s] %-40s ERROR: %s", ev.Operator, ev.Description, ev.Error)
		case "caught_up":
			log.Printf("[%s] %-40s CAUGHT UP at %d (tree=%d)", ev.Operator, ev.Description, ev.NextEntryIdx, ev.TreeSize)
		case "complete":
			log.Printf("[%s] %-40s COMPLETE session=%d total=%d", ev.Operator, ev.Description, ev.EntriesProcessed, ev.TotalProcessed)
		default:
			log.Printf("[%s] %-40s session=%d total=%d next=%d/%d  %.2f%%",
				ev.Operator, ev.Description, ev.EntriesProcessed, ev.TotalProcessed, ev.NextEntryIdx, ev.TreeSize, pct)
		}
	}
	log.Printf("IngestAll: stream closed")
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func runCheck(ctx context.Context, client pb.CTIngestionServiceClient) {
	resp, err := client.Check(ctx, &pb.CheckRequest{
		OutputDir:         *activeDir,
		ArchiveDir:        *archiveDir,
		MonitoringApiRoot: *monitoringRoot,
	})
	if err != nil {
		log.Fatalf("Check: %v", err)
	}
	fmt.Fprintf(os.Stdout, "tree_size:       %d\n", resp.TreeSize)
	fmt.Fprintf(os.Stdout, "total_processed: %d\n", resp.TotalProcessed)
	fmt.Fprintf(os.Stdout, "coverage_pct:    %.6f%%\n", resp.CoveragePct)
	fmt.Fprintf(os.Stdout, "db_total:        %s\n", formatBytes(resp.DbBytesTotal))
	fmt.Fprintf(os.Stdout, "updated_at:      %s\n", resp.UpdatedAt)
	if len(resp.DbFiles) > 0 {
		fmt.Fprintln(os.Stdout, "\nDatabase files:")
		for _, f := range resp.DbFiles {
			fmt.Fprintf(os.Stdout, "  %s  (%s)\n", f.Path, formatBytes(f.SizeBytes))
		}
	}
}

func runIngest(ctx context.Context, client pb.CTIngestionServiceClient) {
	batch := *batchSize
	if *continuous {
		batch = 0
	}
	req := &pb.IngestRequest{
		MonitoringApiRoot: *monitoringRoot,
		BatchSize:         batch,
		OutputDir:         *activeDir,
		ArchiveDir:        *archiveDir,
		TargetQps:         *targetQPS,
		SizeRolloverBytes: *sizeLimit * 1024 * 1024 * 1024,
	}
	if *continuous {
		log.Printf("starting continuous mirror: qps=%.0f active=%s archive=%s",
			*targetQPS, *activeDir, *archiveDir)
	} else {
		log.Printf("starting mirror: batch=%d qps=%.0f active=%s archive=%s",
			batch, *targetQPS, *activeDir, *archiveDir)
	}

	stream, err := client.IngestLog(ctx, req)
	if err != nil {
		log.Fatalf("IngestLog: %v", err)
	}

	count := 0
	for {
		rec, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatalf("stream recv: %v", err)
		}
		count++
		if count <= 5 || count%100 == 0 {
			log.Printf("[%d] %s  issuer=%q ca_id=%d", count, rec.Url, rec.IssuerCommonName, rec.CaId)
		}
	}
	log.Printf("done: mirrored %d certificates", count)
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
