// Package service is the importable entrypoint for composing proto-ct's
// CTIngestionService onto a shared *grpc.Server (the proto-go "Register"
// convention). It also re-exports the archive-reading helper crawl tooling
// needs, keeping the internal implementation packages private.
package service

import (
	"google.golang.org/grpc"

	pb "github.com/accretional/proto-ct/gen/ctingestion/v2"
	"github.com/accretional/proto-ct/internal/ctv2"
	cx509 "github.com/google/certificate-transparency-go/x509"
)

// Register registers the CTIngestionService (v2) on s, backed by a fresh
// ctv2.Service with no default output root (callers pass OutputRoot per RPC).
func Register(s *grpc.Server) {
	pb.RegisterCTIngestionServiceServer(s, ctv2.NewService(""))
}

// EntryWithSubjects loads the archived RawLogEntry at index from the archive
// rooted at root and returns it alongside the leaf cert's CommonName and SAN
// dNSNames. See ctv2.EntryWithSubjects.
func EntryWithSubjects(root string, index int64) (*pb.RawLogEntry, string, []string, error) {
	return ctv2.EntryWithSubjects(root, index)
}

// EntryWithCert returns the archived RawLogEntry at index and its fully parsed
// leaf certificate. See ctv2.EntryWithCert.
func EntryWithCert(root string, index int64) (*pb.RawLogEntry, *cx509.Certificate, error) {
	return ctv2.EntryWithCert(root, index)
}
