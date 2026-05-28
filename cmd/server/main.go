package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	pb "github.com/benfultz/proto-ct/gen/ctingestion/v1"
	"github.com/benfultz/proto-ct/internal/ctlist"
	"github.com/benfultz/proto-ct/internal/ingestion"
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

	s := grpc.NewServer()
	pb.RegisterCTIngestionServiceServer(s, &ingestion.Service{})
	log.Printf("CT ingestion server listening on %s", addr)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
