package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/benfultz/proto-ct/internal/domainpb"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	flagShards   = flag.String("shards", "", "input shards directory (required)")
	flagOut      = flag.String("out", "", "output directory for DNS databases (required)")
	flagAddr     = flag.String("addr", "localhost:50098", "proto-domain gRPC address")
	flagWorkers  = flag.Int("workers", 50, "concurrent domain resolver workers")
	flagQPS      = flag.Float64("qps", 50.0, "max domains/sec (each domain triggers ~16 DNS queries)")
	flagTimeout  = flag.Duration("timeout", 8*time.Second, "per-domain resolution timeout")
	flagMaxRdata = flag.Int("max-rdata", 2048, "max bytes to store per resource record value")
)

// ── shared types ─────────────────────────────────────────────────────────────

type shardKey struct {
	tld    string
	bucket string
}

func (k shardKey) String() string { return k.tld + "/" + k.bucket }

type workItem struct {
	domain string
	shard  shardKey
}

type recordRow struct {
	recordType string
	ttl        int32
	rdata      string
}

type resultItem struct {
	domain    string
	shard     shardKey
	status    string // ok | nxdomain | timeout | error
	records   []recordRow
	fetchedAt int64
}

// ── stats ────────────────────────────────────────────────────────────────────

type runStats struct {
	done     atomic.Int64
	ok       atomic.Int64
	nxd      atomic.Int64
	timeouts atomic.Int64
	errs     atomic.Int64
}

func (s *runStats) record(status string) {
	s.done.Add(1)
	switch status {
	case "ok":
		s.ok.Add(1)
	case "nxdomain":
		s.nxd.Add(1)
	case "timeout":
		s.timeouts.Add(1)
	default:
		s.errs.Add(1)
	}
}

// ── main ─────────────────────────────────────────────────────────────────────

func main() {
	flag.Parse()
	if *flagShards == "" || *flagOut == "" {
		fmt.Fprintln(os.Stderr, "usage: dnsfetch --shards <dir> --out <dir> [flags]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	conn, err := grpc.NewClient(*flagAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("dial %s: %v", *flagAddr, err)
	}
	defer conn.Close()
	client := domainpb.NewResolverClient(conn)

	shards, err := enumShards(*flagShards)
	if err != nil {
		log.Fatalf("enumerate shards: %v", err)
	}
	log.Printf("found %d shard files", len(shards))

	workCh := make(chan workItem, 5000)
	resultCh := make(chan resultItem, 5000)

	st := &runStats{}
	cb := newCircuitBreaker(0.30, 100)
	lim := rate.NewLimiter(rate.Limit(*flagQPS), int(*flagQPS)+10)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		log.Println("shutting down…")
		cancel()
	}()

	var writerWg sync.WaitGroup
	writerWg.Add(1)
	go func() {
		defer writerWg.Done()
		runWriter(resultCh, *flagOut, *flagMaxRdata)
	}()

	var workerWg sync.WaitGroup
	for i := 0; i < *flagWorkers; i++ {
		workerWg.Add(1)
		go func() {
			defer workerWg.Done()
			runWorker(ctx, workCh, resultCh, client, lim, cb, *flagTimeout, st)
		}()
	}

	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		start := time.Now()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				done := st.done.Load()
				elapsed := time.Since(start).Seconds()
				denom := max(float64(done), 1)
				log.Printf("metrics: done=%d rate=%.1f/s ok=%d nxd=%d timeout=%d err=%d(%.1f%%) cb=%s",
					done, float64(done)/elapsed,
					st.ok.Load(), st.nxd.Load(), st.timeouts.Load(), st.errs.Load(),
					100*float64(st.errs.Load())/denom,
					cb.state())
			}
		}
	}()

	if err := runFeeder(ctx, shards, *flagOut, workCh); err != nil && ctx.Err() == nil {
		log.Printf("feeder: %v", err)
	}
	close(workCh)

	workerWg.Wait()
	close(resultCh)
	writerWg.Wait()

	done := st.done.Load()
	log.Printf("complete: total=%d ok=%d nxdomain=%d timeout=%d error=%d",
		done, st.ok.Load(), st.nxd.Load(), st.timeouts.Load(), st.errs.Load())
}
