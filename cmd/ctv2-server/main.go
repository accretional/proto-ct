// Command ctv2-server runs the proto-ct v2 raw-leaf archiver gRPC service.
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

	pb "github.com/accretional/proto-ct/gen/ctingestion/v2"
	"github.com/accretional/proto-ct/internal/ctv2"
	"google.golang.org/grpc"
)

var (
	port        = flag.Int("port", 50052, "gRPC server port")
	defaultRoot = flag.String("out", "data/v2", "default output root for written partitions (overridable per request)")
)

func main() {
	flag.Parse()

	addr := fmt.Sprintf(":%d", *port)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("listen %s: %v", addr, err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	svc := ctv2.NewService(*defaultRoot)
	s := grpc.NewServer()
	pb.RegisterCTIngestionServiceServer(s, svc)

	go func() {
		<-ctx.Done()
		log.Printf("shutdown signal received: GracefulStop")
		s.GracefulStop()
	}()

	log.Printf("ctv2 raw-leaf archiver listening on %s (default out=%s)", addr, *defaultRoot)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
