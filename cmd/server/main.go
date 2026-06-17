package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	pb "github.com/accretional/proto-ct/gen/ctingestion/v1"
	"github.com/accretional/proto-ct/internal/ctlist"
	"github.com/accretional/proto-ct/internal/ingestion"
	"google.golang.org/grpc"
)

var (
	port             = flag.Int("port", 50051, "gRPC server port")
	logListSnapshot  = flag.String("log-list-snapshot", "data/log_list.json", "where to persist the CT log catalog")
	logListRefresh   = flag.Duration("log-list-refresh", 24*time.Hour, "how often to refresh the log catalog (0 = disable background refresh)")
)

func main() {
	flag.Parse()
	addr := fmt.Sprintf(":%d", *port)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("listen %s: %v", addr, err)
	}

	if *logListRefresh > 0 {
		go ctlist.RefreshLoop(context.Background(), "", *logListSnapshot, *logListRefresh)
	}

	// Graceful shutdown: a SIGINT/SIGTERM cancels shutdownCtx, which IngestAll
	// folds into its worker context — workers drain, the deferred final flush
	// runs, the RPC returns, and GracefulStop then lets Serve exit cleanly. The
	// flush can take a while on big months; do NOT SIGKILL (a second signal
	// bypasses NotifyContext and hard-kills mid-flush, the unsafe path).
	shutdownCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	svc := &ingestion.Service{}
	svc.SetShutdownContext(shutdownCtx)

	s := grpc.NewServer()
	pb.RegisterCTIngestionServiceServer(s, svc)

	go func() {
		<-shutdownCtx.Done()
		log.Printf("shutdown signal received: draining in-flight ingestion and flushing (may take a while; do NOT SIGKILL)")
		s.GracefulStop()
	}()

	log.Printf("CT ingestion server listening on %s", addr)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
