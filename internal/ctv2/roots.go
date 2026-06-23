package ctv2

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	cx509 "github.com/google/certificate-transparency-go/x509"
)

const rootsDir = "roots"

// rootStorePath is the store-relative path for an accepted-root cert, content-
// addressed exactly like the issuer store: roots/<hex-sha256>.der, so
// sha256(file) == filename.
func rootStorePath(hash [32]byte) string {
	return path.Join(rootsDir, hex.EncodeToString(hash[:])+".der")
}

// fetchRoots retrieves the log's accepted roots via the RFC6962 get-roots
// endpoint at base (the RFC6962 url, or a static log's submission_url).
func fetchRoots(ctx context.Context, hc *http.Client, base, userAgent string) ([][]byte, error) {
	lc, err := client.New(strings.TrimRight(base, "/"), hc, jsonclient.Options{UserAgent: userAgent})
	if err != nil {
		return nil, fmt.Errorf("new client for get-roots: %w", err)
	}
	roots, err := lc.GetAcceptedRoots(ctx)
	if err != nil {
		return nil, err
	}
	out := make([][]byte, 0, len(roots))
	for _, r := range roots {
		out = append(out, r.Data)
	}
	return out, nil
}

// mirrorRoots fetches the log's accepted roots and writes each, content-addressed,
// into the store. Returns counts; a fetch error is returned without writing.
func mirrorRoots(ctx context.Context, w Writer, hc *http.Client, base, userAgent string) (total, present, stored int, err error) {
	roots, err := fetchRoots(ctx, hc, base, userAgent)
	if err != nil {
		return 0, 0, 0, err
	}
	for _, der := range roots {
		total++
		rel := rootStorePath(sha256.Sum256(der))
		if ok, _ := w.Has(ctx, rel); ok {
			present++
			continue
		}
		if err := w.PutIfAbsent(ctx, rel, der); err != nil {
			return total, present, stored, err
		}
		stored++
	}
	return total, present, stored, nil
}

// loadRoots parses every roots/<hex>.der under root, returning the certs plus a
// fingerprint set (for "is this cert itself an accepted root" checks). Uses the
// CT-aware x509 fork so legacy (e.g. SHA1) roots load and verify.
func loadRoots(root string) ([]*cx509.Certificate, map[[32]byte]struct{}, error) {
	var certs []*cx509.Certificate
	set := make(map[[32]byte]struct{})
	dir := filepath.Join(root, rootsDir)
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil // no roots mirrored yet
			}
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".der") {
			return nil
		}
		der, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		cert, err := cx509.ParseCertificate(der)
		if err != nil {
			return nil // skip unparseable roots rather than failing the whole load
		}
		certs = append(certs, cert)
		set[sha256.Sum256(der)] = struct{}{}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return certs, set, nil
}

// rootsAlreadyMirrored reports whether root/roots/ holds at least one cert.
func rootsAlreadyMirrored(root string) bool {
	entries, err := os.ReadDir(filepath.Join(root, rootsDir))
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".der") {
			return true
		}
	}
	return false
}
