package ingestion

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	pb "github.com/benfultz/proto-ct/gen/ctingestion/v1"
	"github.com/benfultz/proto-ct/internal/ctlog"
	"github.com/benfultz/proto-ct/internal/db"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Service implements the CTIngestionService gRPC server.
type Service struct {
	pb.UnimplementedCTIngestionServiceServer

	mu             sync.RWMutex
	lastActiveDir  string
	lastArchiveDir string
	lastRoot       string
	lastMetrics    *pb.CheckResponse // refreshed every 5 min during IngestLog
}

type issuerInfo struct {
	caID         int64
	commonName   string
	organization string
	country      string
}

// ── Check ────────────────────────────────────────────────────────────────────

func (s *Service) Check(ctx context.Context, req *pb.CheckRequest) (*pb.CheckResponse, error) {
	activeDir := req.OutputDir
	archiveDir := req.ArchiveDir
	root := req.MonitoringApiRoot

	s.mu.RLock()
	if activeDir == "" {
		activeDir = s.lastActiveDir
	}
	if archiveDir == "" {
		archiveDir = s.lastArchiveDir
	}
	if root == "" {
		root = s.lastRoot
	}
	cached := s.lastMetrics
	s.mu.RUnlock()

	// Return cached snapshot if fresh and caller supplied no explicit coords.
	if cached != nil && req.OutputDir == "" && req.MonitoringApiRoot == "" {
		if t, err := time.Parse(time.RFC3339, cached.UpdatedAt); err == nil && time.Since(t) < 10*time.Second {
			return cached, nil
		}
	}

	if archiveDir == "" {
		return nil, status.Error(codes.InvalidArgument,
			"archive_dir required (no prior IngestLog call on this server)")
	}

	resp, err := computeMetrics(ctx, activeDir, archiveDir, root)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "compute metrics: %v", err)
	}
	s.setMetrics(resp, activeDir, archiveDir, root)
	return resp, nil
}

func (s *Service) setMetrics(m *pb.CheckResponse, activeDir, archiveDir, root string) {
	s.mu.Lock()
	s.lastMetrics = m
	if activeDir != "" {
		s.lastActiveDir = activeDir
	}
	if archiveDir != "" {
		s.lastArchiveDir = archiveDir
	}
	if root != "" {
		s.lastRoot = root
	}
	s.mu.Unlock()
}

// ── IngestLog ────────────────────────────────────────────────────────────────

func (s *Service) IngestLog(req *pb.IngestRequest, stream pb.CTIngestionService_IngestLogServer) error {
	ctx := stream.Context()

	if req.MonitoringApiRoot == "" {
		return status.Error(codes.InvalidArgument, "monitoring_api_root is required")
	}
	if req.BatchSize < 0 {
		return status.Error(codes.InvalidArgument, "batch_size must be non-negative (0 = continuous)")
	}

	activeDir := req.OutputDir
	if activeDir == "" {
		activeDir = "data/active/"
	}
	if !strings.HasSuffix(activeDir, "/") {
		activeDir += "/"
	}

	archiveDir := req.ArchiveDir
	if archiveDir == "" {
		archiveDir = "/Volumes/wd_office_2/datasets/CT/"
	}
	if !strings.HasSuffix(archiveDir, "/") {
		archiveDir += "/"
	}

	s.setMetrics(nil, activeDir, archiveDir, req.MonitoringApiRoot)

	if err := os.MkdirAll(activeDir, 0o755); err != nil {
		return status.Errorf(codes.Internal, "mkdir active dir: %v", err)
	}
	if err := os.MkdirAll(archiveDir, 0o755); err != nil {
		return status.Errorf(codes.Internal, "mkdir archive dir: %v", err)
	}

	// progress.db lives in the archive dir — durable across sessions and reboots.
	progressDB, err := db.OpenProgressDB(filepath.Join(archiveDir, "progress.db"))
	if err != nil {
		return status.Errorf(codes.Internal, "open progress db: %v", err)
	}
	defer progressDB.Close()

	// Metrics log also goes in the archive dir alongside progress.db.
	logFile, err := openIngestionLog(archiveDir)
	if err != nil {
		log.Printf("warn: cannot open ingestion.log: %v", err)
	} else {
		defer logFile.Close()
	}

	// Start the periodic metrics goroutine (every 5 min).
	go s.metricsLoop(ctx, activeDir, archiveDir, req.MonitoringApiRoot, logFile)

	// Resume: find or create a run record for this monitoring root.
	run, err := progressDB.GetOrCreateRun(req.MonitoringApiRoot)
	if err != nil {
		return status.Errorf(codes.Internal, "get run: %v", err)
	}
	if run.NextTileIdx > 0 {
		log.Printf("resuming from tile %d (total previously mirrored: %d)",
			run.NextTileIdx, run.TotalProcessed)
	}

	client := ctlog.NewClient(req.MonitoringApiRoot, req.TargetQps)

	// Per-session state.
	issuerCache := make(map[[32]byte]*issuerInfo)
	sessionProcessed := 0
	globalProcessed := run.TotalProcessed
	tileIdx := run.NextTileIdx

	// Dated run directory lives in activeDir (SSD). Rotates at local midnight.
	currentDate := time.Now().Local().Format("20060102")
	runDir := filepath.Join(activeDir, currentDate)
	issuerDB, subjectDB, err := openDatedDBs(runDir)
	if err != nil {
		return status.Errorf(codes.Internal, "open dated dbs: %v", err)
	}

	continuous := req.BatchSize == 0
	totalTarget := int(req.BatchSize)

	const defaultSizeRollover = 50 * 1024 * 1024 * 1024 // 50 GiB
	sizeRolloverBytes := req.SizeRolloverBytes
	if sizeRolloverBytes == 0 {
		sizeRolloverBytes = defaultSizeRollover
	}

	// Sliding-window prefetch: keep tileFetchLookahead tile fetches in flight
	// at all times so HTTP latency is hidden behind write time.
	const tileFetchLookahead = 128
	type tileResult struct {
		leaves []*ctlog.TileLeaf
		err    error
	}
	fetchBuf := make([]chan tileResult, tileFetchLookahead)
	startTile := tileIdx
	launchFetch := func(idx int, ch chan<- tileResult) {
		go func() {
			leaves, err := client.FetchTile(ctx, idx, 256)
			ch <- tileResult{leaves, err}
		}()
	}
	for i := 0; i < tileFetchLookahead; i++ {
		ch := make(chan tileResult, 1)
		fetchBuf[i] = ch
		launchFetch(startTile+i, ch)
	}
	nextFetch := startTile + tileFetchLookahead

	for continuous || sessionProcessed < totalTarget {
		if err := ctx.Err(); err != nil {
			issuerDB.Close()
			subjectDB.Close()
			return status.FromContextError(err).Err()
		}

		// Daily cutover: checkpoint+close old DBs, archive them, open new day on SSD.
		if today := time.Now().Local().Format("20060102"); today != currentDate {
			log.Printf("date rollover %s → %s: archiving and rotating databases", currentDate, today)
			issuerDB.CheckpointAndClose()
			subjectDB.CheckpointAndClose()
			// Copy completed dated dir from SSD to archive in background.
			completedActive := filepath.Join(activeDir, currentDate)
			completedArchive := filepath.Join(archiveDir, currentDate)
			go archiveDateDir(completedActive, completedArchive)
			currentDate = today
			runDir = filepath.Join(activeDir, currentDate)
			issuerDB, subjectDB, err = openDatedDBs(runDir)
			if err != nil {
				return status.Errorf(codes.Internal, "open rotated dbs: %v", err)
			}
			clear(issuerCache) // ca_ids restart in the new issuerDB
		}

		// Wait for the next tile from the prefetch window.
		slot := (tileIdx - startTile) % tileFetchLookahead
		result := <-fetchBuf[slot]

		// Immediately dispatch the next fetch into the freed slot.
		newCh := make(chan tileResult, 1)
		fetchBuf[slot] = newCh
		launchFetch(nextFetch, newCh)
		nextFetch++

		if result.err != nil {
			issuerDB.Close()
			subjectDB.Close()
			if continuous && ctlog.IsNotFound(result.err) {
				log.Printf("caught up at tile %d (total mirrored: %d)", tileIdx, globalProcessed)
				return nil
			}
			return status.Errorf(codes.Internal, "fetch tile %d: %v", tileIdx, result.err)
		}
		if len(result.leaves) == 0 {
			break
		}

		log.Printf("tile %d  session %d  total %d",
			tileIdx, sessionProcessed, globalProcessed)

		// Parallel-fetch all new issuer certs for this tile, then serial DB writes.
		if err := prefetchIssuers(ctx, result.leaves, client, issuerDB, issuerCache); err != nil {
			log.Printf("warn: prefetch issuers tile %d: %v", tileIdx, err)
		}

		tileURL := client.TileURL(tileIdx)

		var batch []db.Subject
		var recs []*pb.SubjectRecord
		for entryIdx, leaf := range result.leaves {
			if !continuous && sessionProcessed >= totalTarget {
				break
			}
			ctLogURI := fmt.Sprintf("%s#entry=%d", tileURL, entryIdx)

			rec, subject, err := processLeaf(leaf, tileIdx, entryIdx, ctLogURI, issuerCache)
			if err != nil {
				log.Printf("tile=%d entry=%d skip: %v", tileIdx, entryIdx, err)
			} else {
				batch = append(batch, subject)
				recs = append(recs, rec)
			}
			sessionProcessed++
			globalProcessed++
		}

		if len(batch) > 0 {
			if err := subjectDB.InsertSubjectBatch(batch); err != nil {
				log.Printf("warn: insert batch tile %d: %v", tileIdx, err)
			}
			for _, rec := range recs {
				if err := stream.Send(rec); err != nil {
					issuerDB.Close()
					subjectDB.Close()
					return err
				}
			}
		}

		if err := progressDB.UpdateProgress(run.ID, tileIdx+1, globalProcessed); err != nil {
			log.Printf("warn: update progress tile %d: %v", tileIdx, err)
		}

		tileIdx++

		// Size-based rollover: check every 500 tiles to keep stat overhead low.
		if tileIdx%500 == 0 {
			subjectsPath := filepath.Join(activeDir, currentDate, "subjects.db")
			if dbSizeBytes(subjectsPath) >= sizeRolloverBytes {
				issuerDB, subjectDB, err = sizeRollover(activeDir, archiveDir, currentDate, issuerDB, subjectDB, issuerCache)
				if err != nil {
					return status.Errorf(codes.Internal, "size rollover: %v", err)
				}
			}
		}
	}

	issuerDB.Close()
	subjectDB.Close()
	log.Printf("ingestion complete: session=%d total=%d", sessionProcessed, globalProcessed)
	return nil
}

// metricsLoop runs every 5 minutes, logging metrics to stderr and logFile.
func (s *Service) metricsLoop(ctx context.Context, activeDir, archiveDir, root string, logFile *os.File) {
	emit := func() {
		resp, err := computeMetrics(ctx, activeDir, archiveDir, root)
		if err != nil {
			log.Printf("metrics error: %v", err)
			return
		}
		writeMetricsLine(os.Stderr, resp)
		if logFile != nil {
			writeMetricsLine(logFile, resp)
		}
		s.setMetrics(resp, activeDir, archiveDir, root)
	}

	emit() // immediate first snapshot
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			emit()
		case <-ctx.Done():
			return
		}
	}
}

// openDatedDBs creates the dated directory and opens both SQLite files.
func openDatedDBs(runDir string) (*db.IssuerDB, *db.SubjectDB, error) {
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return nil, nil, fmt.Errorf("mkdir %s: %w", runDir, err)
	}
	issuerDB, err := db.OpenIssuerDB(filepath.Join(runDir, "issuers.db"))
	if err != nil {
		return nil, nil, err
	}
	subjectDB, err := db.OpenSubjectDB(filepath.Join(runDir, "subjects.db"))
	if err != nil {
		issuerDB.Close()
		return nil, nil, err
	}
	return issuerDB, subjectDB, nil
}

// ── archiveDateDir / sizeRollover ────────────────────────────────────────────

// archiveDateDir is called at midnight in a background goroutine. It merges or
// copies the completed SSD dated dir into the archive drive, builds query
// indexes on the final archive copy, then removes the SSD copy.
func archiveDateDir(src, dst string) {
	if err := mergeOrCopy(src, dst); err != nil {
		log.Printf("archive: %v", err)
		return
	}
	// Build query indexes on the archive copy (HDD) after all data is there.
	archiveSubjects := filepath.Join(dst, "subjects.db")
	log.Printf("archive: building query indexes on %s", archiveSubjects)
	if err := db.BuildQueryIndexes(archiveSubjects); err != nil {
		log.Printf("archive: build indexes: %v", err) // non-fatal
	}
	if err := os.RemoveAll(src); err != nil {
		log.Printf("archive: remove %s: %v", src, err)
		return
	}
	log.Printf("archive: %s complete", dst)
}

// sizeRollover is called synchronously when the active subjects.db exceeds the
// size threshold. It checkpoints, archives or merges into the archive drive,
// deletes the SSD copy, and opens fresh databases. Ingestion is paused while
// this runs. Returns the new open DB handles.
func sizeRollover(
	activeDir, archiveDir, currentDate string,
	issuerDB *db.IssuerDB,
	subjectDB *db.SubjectDB,
	issuerCache map[[32]byte]*issuerInfo,
) (*db.IssuerDB, *db.SubjectDB, error) {
	activeDateDir := filepath.Join(activeDir, currentDate)
	log.Printf("size rollover: subjects.db exceeded threshold, archiving %s", activeDateDir)

	issuerDB.CheckpointAndClose()
	subjectDB.CheckpointAndClose()

	archiveDateDirPath := filepath.Join(archiveDir, currentDate)
	if err := mergeOrCopy(activeDateDir, archiveDateDirPath); err != nil {
		// Archive failed — reopen the same dir and keep going.
		log.Printf("size rollover: archive failed (%v), continuing in same active dir", err)
		idb, sdb, reopenErr := openDatedDBs(activeDateDir)
		if reopenErr != nil {
			return nil, nil, fmt.Errorf("size rollover archive failed and reopen failed: %v / %v", err, reopenErr)
		}
		return idb, sdb, nil
	}

	if err := os.RemoveAll(activeDateDir); err != nil {
		log.Printf("size rollover: cleanup %s: %v", activeDateDir, err)
	}

	idb, sdb, err := openDatedDBs(activeDateDir)
	if err != nil {
		return nil, nil, fmt.Errorf("open fresh dbs after size rollover: %w", err)
	}
	clear(issuerCache)
	log.Printf("size rollover: complete, fresh active db opened")
	return idb, sdb, nil
}

// mergeOrCopy copies src into dst. If dst already has a subjects.db (from a
// prior size rollover), the rows are merged using INSERT OR IGNORE with explicit
// column lists to avoid autoincrement id collisions.
func mergeOrCopy(src, dst string) error {
	if _, err := os.Stat(filepath.Join(dst, "subjects.db")); err == nil {
		log.Printf("archive: merging %s into existing %s", src, dst)
		if err := db.MergeIssuerDBs(
			filepath.Join(src, "issuers.db"),
			filepath.Join(dst, "issuers.db"),
		); err != nil {
			return fmt.Errorf("merge issuers %s → %s: %w", src, dst, err)
		}
		return db.MergeSubjectDBs(
			filepath.Join(src, "subjects.db"),
			filepath.Join(dst, "subjects.db"),
		)
	}
	return copyDir(src, dst)
}

// dbSizeBytes returns the on-disk size of a SQLite database including its WAL.
func dbSizeBytes(path string) int64 {
	var total int64
	for _, p := range []string{path, path + "-wal"} {
		if fi, err := os.Stat(p); err == nil {
			total += fi.Size()
		}
	}
	return total
}

// copyDir copies all regular files from src to dst, creating dst if needed.
func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode())
		}
		return copyFile(path, target)
	})
}

// copyFile copies a single file, creating the destination directory if needed.
func copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// ── prefetchIssuers ──────────────────────────────────────────────────────────

func prefetchIssuers(
	ctx context.Context,
	leaves []*ctlog.TileLeaf,
	client *ctlog.Client,
	issuerDB *db.IssuerDB,
	cache map[[32]byte]*issuerInfo,
) error {
	var newFPs [][32]byte
	seen := make(map[[32]byte]bool)
	for _, leaf := range leaves {
		if len(leaf.ChainFingerprints) == 0 {
			continue
		}
		fp := leaf.ChainFingerprints[0]
		if _, ok := cache[fp]; !ok && !seen[fp] {
			seen[fp] = true
			newFPs = append(newFPs, fp)
		}
	}
	if len(newFPs) == 0 {
		return nil
	}

	type fetched struct {
		fp   [32]byte
		info issuerInfo
	}
	results := make([]fetched, len(newFPs))
	var wg sync.WaitGroup
	for i, fp := range newFPs {
		wg.Add(1)
		go func(i int, fp [32]byte) {
			defer wg.Done()
			info := issuerInfo{}
			der, err := client.FetchIssuer(ctx, fp)
			if err != nil {
				log.Printf("warn: fetch issuer %x: %v", fp[:4], err)
			} else if cert, err := parseAnyCert(der); err == nil {
				info.commonName = cert.Subject.CommonName
				if len(cert.Subject.Organization) > 0 {
					info.organization = cert.Subject.Organization[0]
				}
				if len(cert.Subject.Country) > 0 {
					info.country = cert.Subject.Country[0]
				}
			}
			results[i] = fetched{fp, info}
		}(i, fp)
	}
	wg.Wait()

	// Serial DB writes to avoid SQLite contention.
	for _, r := range results {
		id, err := issuerDB.UpsertIssuer(r.fp, r.info.commonName, r.info.organization, r.info.country)
		if err != nil {
			log.Printf("warn: upsert issuer %x: %v", r.fp[:4], err)
		}
		r.info.caID = id
		info := r.info
		cache[r.fp] = &info
	}
	return nil
}

// ── processLeaf ──────────────────────────────────────────────────────────────

func processLeaf(
	leaf *ctlog.TileLeaf,
	tileIdx, entryIdx int,
	ctLogURI string,
	issuerCache map[[32]byte]*issuerInfo,
) (*pb.SubjectRecord, db.Subject, error) {
	cert, err := parseCert(leaf)
	if err != nil {
		return nil, db.Subject{}, fmt.Errorf("parse cert: %w", err)
	}

	var info *issuerInfo
	if len(leaf.ChainFingerprints) > 0 {
		info = issuerCache[leaf.ChainFingerprints[0]]
	}

	var cn, org, state, country, serial string
	var sans, ips []string
	var notBefore, notAfter string

	if cert != nil {
		cn = cert.Subject.CommonName
		if len(cert.Subject.Organization) > 0 {
			org = cert.Subject.Organization[0]
		}
		if len(cert.Subject.Province) > 0 {
			state = cert.Subject.Province[0]
		}
		if len(cert.Subject.Country) > 0 {
			country = cert.Subject.Country[0]
		}
		serial = serialHex(cert.SerialNumber)
		sans = cert.DNSNames
		for _, ip := range cert.IPAddresses {
			ips = append(ips, ip.String())
		}
		notBefore = cert.NotBefore.UTC().Format("2006-01-02T15:04:05Z")
		notAfter = cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z")
	}

	subjectURL := buildURL(sans, cn)
	isWildcard := 0
	for _, s := range sans {
		if strings.HasPrefix(s, "*.") {
			isWildcard = 1
			break
		}
	}
	entryType := "x509"
	if leaf.EntryType == ctlog.EntryTypePrecert {
		entryType = "precert"
	}

	var caID int64
	var issuerCN, issuerOrg, issuerCountry string
	if info != nil {
		caID = info.caID
		issuerCN = info.commonName
		issuerOrg = info.organization
		issuerCountry = info.country
	}

	subject := db.Subject{
		CAID:         caID,
		SerialNumber: serial,
		CommonName:   cn,
		Organization: org,
		State:        state,
		Country:      country,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		SANDomains:   strings.Join(sans, ","),
		SANIPS:       strings.Join(ips, ","),
		URL:          subjectURL,
		IsWildcard:   isWildcard,
		SANCount:     len(sans),
		EntryType:    entryType,
		TileIdx:      tileIdx,
		EntryIdx:     entryIdx,
	}

	rec := &pb.SubjectRecord{
		Url:                subjectURL,
		CommonName:         cn,
		Organization:       org,
		State:              state,
		Country:            country,
		CaId:               caID,
		SanDomains:         sans,
		NotBefore:          notBefore,
		NotAfter:           notAfter,
		IssuerCommonName:   issuerCN,
		IssuerOrganization: issuerOrg,
		IssuerCountry:      issuerCountry,
		SerialNumber:       serial,
		CtLogUri:           ctLogURI,
	}

	return rec, subject, nil
}

// ── cert parsing helpers ──────────────────────────────────────────────────────

func parseCert(leaf *ctlog.TileLeaf) (*x509.Certificate, error) {
	if len(leaf.Certificate) == 0 {
		return nil, fmt.Errorf("no certificate data")
	}
	cert, err := x509.ParseCertificate(leaf.Certificate)
	if err != nil {
		ctCert, ctErr := ctx509.ParseCertificate(leaf.Certificate)
		if ctErr != nil {
			return nil, fmt.Errorf("std: %v; ct: %v", err, ctErr)
		}
		return convertCTCert(ctCert), nil
	}
	return cert, nil
}

func parseAnyCert(der []byte) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(der)
	if err == nil {
		return cert, nil
	}
	ctCert, ctErr := ctx509.ParseCertificate(der)
	if ctErr != nil {
		return nil, fmt.Errorf("std: %v; ct: %v", err, ctErr)
	}
	return convertCTCert(ctCert), nil
}

func convertCTCert(c *ctx509.Certificate) *x509.Certificate {
	cert := &x509.Certificate{}
	cert.Subject.CommonName = c.Subject.CommonName
	cert.Subject.Organization = c.Subject.Organization
	cert.Subject.Province = c.Subject.Province
	cert.Subject.Country = c.Subject.Country
	cert.DNSNames = c.DNSNames
	cert.NotBefore = c.NotBefore
	cert.NotAfter = c.NotAfter
	cert.SerialNumber = c.SerialNumber
	return cert
}

func buildURL(sans []string, cn string) string {
	for _, san := range sans {
		if !strings.HasPrefix(san, "*.") {
			return "https://" + san
		}
	}
	if len(sans) > 0 {
		return "https://" + strings.TrimPrefix(sans[0], "*.")
	}
	if cn != "" {
		return "https://" + cn
	}
	return ""
}

func serialHex(n *big.Int) string {
	if n == nil {
		return ""
	}
	return hex.EncodeToString(n.Bytes())
}
