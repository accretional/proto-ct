package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	pb "github.com/benfultz/proto-ct/gen/ctingestion/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	serverAddr  = flag.String("addr", "localhost:50051", "server address")
	monitoringRoot = flag.String("root", "https://mon.sycamore.ct.letsencrypt.org/2026h1/tile/data/", "monitoring API root (tile/data/ endpoint)")
	batchSize   = flag.Int64("batch", 1000, "entries to mirror this session (ignored when --continuous is set)")
	activeDir   = flag.String("out", "data/active/", "active staging dir (fast local SSD); dated subdirs are written here")
	archiveDir  = flag.String("archive", "/Volumes/wd_office_2/datasets/CT/", "persistent archive dir; receives completed dated dirs on rollover, holds progress.db")
	targetQPS   = flag.Float64("qps", 500, "target QPS to monitoring endpoint (actual = 80%); 0 = unlimited")
	checkMode   = flag.Bool("check", false, "run a one-shot metrics check instead of ingesting")
	continuous  = flag.Bool("continuous", false, "mirror until fully caught up with the live log (no batch limit)")
	sizeLimit   = flag.Int64("size-limit", 50, "roll over active DB to archive when subjects.db reaches this size in GiB (0 = disabled)")
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
	runIngest(ctx, client)
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
