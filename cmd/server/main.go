package main

import (
	"flag"
	"fmt"
	"log"
	"net"

	pb "github.com/benfultz/proto-ct/gen/ctingestion/v1"
	"github.com/benfultz/proto-ct/internal/ingestion"
	"google.golang.org/grpc"
)

var port = flag.Int("port", 50051, "gRPC server port")

func main() {
	flag.Parse()
	addr := fmt.Sprintf(":%d", *port)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("listen %s: %v", addr, err)
	}
	s := grpc.NewServer()
	pb.RegisterCTIngestionServiceServer(s, &ingestion.Service{})
	log.Printf("CT ingestion server listening on %s", addr)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
