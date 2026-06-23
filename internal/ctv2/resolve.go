package ctv2

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	pb "github.com/accretional/proto-ct/gen/ctingestion/v2"
	"google.golang.org/protobuf/proto"
)

// collectStaticIssuerRefs walks an output root and returns the distinct
// issuer-chain fingerprints referenced by STATIC-source entries, plus the log's
// monitoring URL (read from the stored batches). RFC 6962 entries are skipped:
// their issuer certs are already written to the local store during ingestion, and
// RFC 6962 logs expose no issuer endpoint to fetch from. Reads partition contents
// (transparently handling gzip), not just filenames.
func collectStaticIssuerRefs(root string) (map[[32]byte]struct{}, string, error) {
	fps := make(map[[32]byte]struct{})
	var monURL string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := strings.TrimSuffix(d.Name(), ".gz")
		if d.IsDir() || !strings.HasSuffix(name, ".binpb") {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if strings.HasSuffix(d.Name(), ".gz") {
			zr, err := gzip.NewReader(bytes.NewReader(data))
			if err != nil {
				return fmt.Errorf("%s: gunzip: %w", p, err)
			}
			data, err = io.ReadAll(zr)
			if err != nil {
				return fmt.Errorf("%s: gunzip: %w", p, err)
			}
		}
		var batch pb.RawLogEntryBatch
		if err := proto.Unmarshal(data, &batch); err != nil {
			return fmt.Errorf("%s: unmarshal: %w", p, err)
		}
		if monURL == "" {
			monURL = batch.GetLog().GetMonitoringUrl()
		}
		for _, e := range batch.GetEntries() {
			switch e.GetSource() {
			case pb.LogProtocol_LOG_PROTOCOL_STATIC_CT_API,
				pb.LogProtocol_LOG_PROTOCOL_STATIC_CT_API_NO_CHECKPOINT:
			default:
				continue // RFC6962 chains are already in the local store
			}
			for _, fp := range e.GetChainFingerprints() {
				if len(fp) == sha256.Size {
					var a [32]byte
					copy(a[:], fp)
					fps[a] = struct{}{}
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	return fps, monURL, nil
}

// fetchIssuerDER GETs the static-ct-api issuer endpoint (<prefix>/issuer/<hex>)
// and verifies the returned DER hashes to the requested fingerprint — the same
// content-address invariant the store relies on.
func fetchIssuerDER(ctx context.Context, hc *http.Client, prefix, userAgent string, fp [32]byte) ([]byte, error) {
	url := strings.TrimRight(prefix, "/") + "/issuer/" + hex.EncodeToString(fp[:])
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	der, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if got := sha256.Sum256(der); got != fp {
		return nil, fmt.Errorf("fingerprint mismatch: got %x", got)
	}
	return der, nil
}

// issuerPresent reports whether a fingerprint's cert is already in the store.
func issuerPresent(root string, fp [32]byte) bool {
	_, err := os.Stat(filepath.Join(root, filepath.FromSlash(issuerStorePath(fp))))
	return err == nil
}
