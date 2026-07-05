package ctv2

import pb "github.com/accretional/proto-ct/gen/ctingestion/v2"

// EntryWithSubjects loads the RawLogEntry at index from an on-disk archive
// rooted at root (the OutputRoot a GetLogEntries call wrote to) and extracts the
// leaf certificate's subject CommonName and SAN dNSNames.
//
// It is an exported wrapper over the internal findEntry/leafCertificate helpers
// so external tooling (e.g. crawlrpc) can pull the hostnames out of a single
// archived entry without reimplementing the TLS MerkleTreeLeaf parsing. The
// RawLogEntry is returned even when certificate parsing fails, so callers can
// still inspect/embed the raw entry.
func EntryWithSubjects(root string, index int64) (*pb.RawLogEntry, string, []string, error) {
	e, err := findEntry(root, index)
	if err != nil {
		return nil, "", nil, err
	}
	cert, err := leafCertificate(e)
	if err != nil {
		return e, "", nil, err
	}
	return e, cert.Subject.CommonName, cert.DNSNames, nil
}
