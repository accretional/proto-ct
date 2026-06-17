package ingestion

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/accretional/proto-ct/gen/ctingestion/v1"
	"github.com/accretional/proto-ct/internal/ctlist"
	"github.com/accretional/proto-ct/internal/ctlog"
	"github.com/accretional/proto-ct/internal/db"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// rolloverInterval is how often IngestAll swaps to a fresh SubjectDBPool and
// flushes the previous one to the archive. Bounded SSD usage is the main goal;
// secondary benefit is making the archive snapshot-current at predictable
// intervals. Constant for now; can become configurable when there's reason.
const rolloverInterval = 1 * time.Hour

// rolloverDrainGrace is how long to wait between atomically swapping the pool
// reference and calling FlushAll on the old pool. Any worker that loaded the
// old pool reference just before the swap has this much time to finish its
// current insert. Workers still in-flight after the grace will see "DB closed"
// errors when FlushAll closes the old pool's DBs — those batches are lost, but
// the worker logs and moves on; INSERT OR IGNORE makes a subsequent re-fetch
// of the same cursor range idempotent.
const rolloverDrainGrace = 3 * time.Second

// flushQueueDepth bounds how many swapped-out pools may wait for the background
// flush worker before the rollover coordinator blocks (backpressure). Each
// queued pool is ~one rolloverInterval of staged data sitting on the SSD, so a
// small depth keeps SSD use bounded while still absorbing brief flush bursts.
const flushQueueDepth = 4

// Page size for one FetchEntries call per worker. 256 lines up with the tile
// boundary used by static-ct-api; RFC 6962 logs will return up to whatever
// their per-call cap is (typically 32–256) and the client loops internally.
const multilogPageSize = 256

// poolDirName builds a per-rollover staging dir name. Includes time so several
// rollovers in the same day get distinct dirs (avoids collisions with prior
// session leftovers and makes each pool's active path unique).
func poolDirName(t time.Time) string {
	return t.Local().Format("20060102_150405")
}

// defaultQPS picks a conservative per-log rate based on operator + protocol.
// Smaller operators (Geomys, IPng, TrustAsia) cap below 10 QPS and return 429
// at higher rates; Let's Encrypt and Google tolerate more. Used when the
// request leaves per_log_qps == 0.
func defaultQPS(lg ctlist.Log) float64 {
	// Tuned 2026-05-27 21:00 from autonomous QPS loop — bumped operators with
	// zero rate-limit errors in the prior cycle by 50%, kept Geomys/Sectigo
	// pinned (429s / 409s observed).
	switch lg.Operator {
	case "Let's Encrypt":
		return 30 // up from 20; 0 errors at 20 with 8 shards
	case "Google":
		return 25 // at the published per-log cap
	case "Cloudflare":
		return 15 // up from 10
	case "Geomys":
		// 4 Tuscolo shards × 1 QPS = 4 aggregate. Still 429s occasionally.
		return 1
	case "IPng Networks":
		// 12 → 4 (2026-06-09): with gouda2026h1+h2 both backfilling, per-shard 12
		// blew past IPng's per-operator limit — observed ~99% 429 on gouda. IPng is
		// a multi-shard operator (per-host limiter overshoots aggregate, like
		// Geomys); 4/shard keeps the operator total saner. Reassess at checkins.
		return 4
	case "TrustAsia":
		return 8
	case "DigiCert":
		return 12 // 8 → 12 (algorithm bump, 52% threshold, clean)
	case "Sectigo":
		return 12 // 8 → 12 (algorithm bump, 65% threshold, clean)
	}
	switch lg.Protocol {
	case ctlist.ProtocolStaticCT:
		return 5
	case ctlist.ProtocolRFC6962:
		return 5
	}
	return 3
}

// IngestAll fans out one worker per usable log in the catalog and streams
// per-log heartbeat events. It is independent of IngestLog and writes through
// the new cert_hash / log_runs schema.
func (s *Service) IngestAll(req *pb.IngestAllRequest, stream pb.CTIngestionService_IngestAllServer) error {
	ctx := stream.Context()
	// Fold the server-wide shutdown signal into the worker context so a SIGTERM
	// drains workers and triggers the deferred final flush (graceful shutdown).
	if s.shutdownCtx != nil {
		var cancel context.CancelFunc
		ctx, cancel = mergeContext(ctx, s.shutdownCtx)
		defer cancel()
	}

	// ── catalog ────────────────────────────────────────────────────────────
	// Use the persisted snapshot when it's recent; otherwise fetch, persist,
	// and fall back to a stale snapshot if the network is down.
	snapshotPath := filepath.Join("data", "log_list.json")
	catalog, err := ctlist.LoadOrFetch(ctx, req.LogListUrl, snapshotPath, 24*time.Hour)
	if err != nil {
		return status.Errorf(codes.Unavailable, "load log_list: %v", err)
	}
	catalog = ctlist.FilterUsable(catalog)
	if len(req.Protocols) > 0 {
		protos := make([]ctlist.Protocol, 0, len(req.Protocols))
		for _, p := range req.Protocols {
			protos = append(protos, ctlist.Protocol(p))
		}
		catalog = ctlist.FilterByProtocol(catalog, protos...)
	}
	if len(req.Operators) > 0 {
		catalog = filterByOperators(catalog, req.Operators)
	}
	if len(req.ExcludedOperators) > 0 {
		catalog = ctlist.FilterExcludeOperators(catalog, req.ExcludedOperators)
	}
	if req.DescriptionContains != "" {
		catalog = filterByDescription(catalog, req.DescriptionContains)
	}
	if len(catalog) == 0 {
		return status.Error(codes.NotFound, "no logs match the requested filters")
	}

	// ── shared storage ─────────────────────────────────────────────────────
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
	if err := os.MkdirAll(activeDir, 0o755); err != nil {
		return status.Errorf(codes.Internal, "mkdir active dir: %v", err)
	}
	if err := os.MkdirAll(archiveDir, 0o755); err != nil {
		return status.Errorf(codes.Internal, "mkdir archive dir: %v", err)
	}
	s.setMetrics(nil, activeDir, archiveDir, "")

	// Shared DBs live on the SSD next to the active staging dir — they're
	// small (KBs-MBs) but hot-write (every UpdateLogProgress / UpsertIssuer
	// hits them). Keeping them off the HDD eliminates ~all the audible
	// platter activity during steady-state ingest.
	progressDB, err := db.OpenProgressDB(filepath.Join(activeDir, "progress.db"))
	if err != nil {
		return status.Errorf(codes.Internal, "open progress db: %v", err)
	}
	defer progressDB.Close()

	issuerDB, err := db.OpenIssuerDB(filepath.Join(activeDir, "issuers.db"))
	if err != nil {
		return status.Errorf(codes.Internal, "open issuer db: %v", err)
	}
	defer issuerDB.CheckpointAndClose()
	var issuerMu sync.Mutex

	// Atomic-swappable pool reference: the rollover coordinator below replaces
	// it with a fresh pool every rolloverInterval and hands the old one to the
	// background flush worker. Workers re-load this on every iteration so they
	// always write into the current pool.
	var poolRef atomic.Pointer[db.SubjectDBPool]
	poolRef.Store(db.NewSubjectDBPool(filepath.Join(activeDir, poolDirName(time.Now()))))

	// Background flush worker: a single goroutine merges pools into the archive
	// one at a time, OFF the rollover and ingest paths. Previously the rollover
	// coordinator ran FlushAll inline, so a multi-hour merge stalled the hourly
	// ticker and the live pool grew to 50-64 GB between rollovers. Now the ticker
	// keeps firing; the bounded queue applies backpressure only if flushing falls
	// more than flushQueueDepth merges behind. (archiveFlushMu in FlushAll still
	// guards the archive, but a single flusher means no contention.)
	flushCh := make(chan *db.SubjectDBPool, flushQueueDepth)
	flushWorkerDone := make(chan struct{})
	go func() {
		defer close(flushWorkerDone)
		for pool := range flushCh {
			if err := pool.FlushAll(archiveDir); err != nil {
				log.Printf("background flush: %v", err)
			} else {
				log.Printf("background flush: pool flushed to archive")
			}
		}
	}()

	// ingestCtx is cancelled when IngestAll returns, to stop the rollover
	// coordinator — it otherwise blocks on its ticker until the stream context
	// is done, which on a clean caught-up finish never happens.
	ingestCtx, ingestCancel := context.WithCancel(ctx)
	var rolloverWg sync.WaitGroup

	defer func() {
		// Final flush + teardown, on every post-setup return path: stop the
		// rollover coordinator, flush whatever's still in the live pool, then
		// drain the worker (incl. any pools the coordinator queued).
		ingestCancel()
		rolloverWg.Wait()
		flushCh <- poolRef.Load()
		close(flushCh)
		<-flushWorkerDone
	}()

	progressEvery := req.ProgressEvery
	if progressEvery <= 0 {
		progressEvery = 10_000
	}

	// ── fan out ─────────────────────────────────────────────────────────────
	events := make(chan *pb.LogProgress, 64)
	var wg sync.WaitGroup

	for _, lg := range catalog {
		wg.Add(1)
		go func(lg ctlist.Log) {
			defer wg.Done()
			runLogWorker(ctx, workerInputs{
				log:           lg,
				req:           req,
				progressDB:    progressDB,
				issuerDB:      issuerDB,
				issuerMu:      &issuerMu,
				poolRef:       &poolRef,
				events:        events,
				progressEvery: progressEvery,
			})
		}(lg)
	}

	// Rollover coordinator: every rolloverInterval, swap to a fresh pool and
	// hand the old one to the background flush worker. The swap is instant; the
	// flush happens off this goroutine, so the ticker keeps a steady cadence.
	rolloverWg.Add(1)
	go func() {
		defer rolloverWg.Done()
		tick := time.NewTicker(rolloverInterval)
		defer tick.Stop()
		for {
			select {
			case <-ingestCtx.Done():
				return
			case <-tick.C:
				newPool := db.NewSubjectDBPool(filepath.Join(activeDir, poolDirName(time.Now())))
				oldPool := poolRef.Swap(newPool)
				log.Printf("rollover: pool swapped, draining %s grace before handoff", rolloverDrainGrace)
				// Brief grace for any worker that loaded oldPool just before
				// the swap to finish its current batch.
				time.Sleep(rolloverDrainGrace)
				select {
				case flushCh <- oldPool:
					log.Printf("rollover: queued old pool for background flush")
				case <-ingestCtx.Done():
					// Returning: enqueue synchronously so the pool isn't dropped
					// (teardown drains the worker), then stop.
					flushCh <- oldPool
					return
				}
			}
		}
	}()

	go func() {
		wg.Wait()
		close(events)
	}()

	for ev := range events {
		if err := stream.Send(ev); err != nil {
			return err
		}
	}
	log.Printf("IngestAll: %d workers finished", len(catalog))
	return nil
}

// ── worker ────────────────────────────────────────────────────────────────

type workerInputs struct {
	log           ctlist.Log
	req           *pb.IngestAllRequest
	progressDB    *db.ProgressDB
	issuerDB      *db.IssuerDB
	issuerMu      *sync.Mutex
	poolRef       *atomic.Pointer[db.SubjectDBPool]
	events        chan<- *pb.LogProgress
	progressEvery int64
}

func runLogWorker(ctx context.Context, in workerInputs) {
	lg := in.log
	qps := in.req.PerLogQps
	if qps == 0 {
		qps = defaultQPS(lg)
	}

	var client ctlog.LogClient
	switch lg.Protocol {
	case ctlist.ProtocolStaticCT:
		// Tile API root is "<monitoring_url>tile/data/".
		tc := ctlog.NewTileClient(lg.APIRoot()+"tile/data/", qps)
		tc.SetLogID(lg.LogID)
		client = tc
	case ctlist.ProtocolRFC6962:
		rc := ctlog.NewRFC6962Client(lg.APIRoot(), qps)
		rc.SetLogID(lg.LogID)
		client = rc
	default:
		in.events <- buildErrorEvent(lg, 0, 0, fmt.Errorf("unknown protocol %q", lg.Protocol))
		return
	}

	run, err := in.progressDB.GetOrCreateLogRun(db.LogRunInit{
		LogID:         lg.LogID,
		Description:   lg.Description,
		SubmissionURL: lg.SubmissionURL,
		MonitoringURL: lg.MonitoringURL,
		Protocol:      string(lg.Protocol),
		Operator:      lg.Operator,
		State:         string(lg.State),
	})
	if err != nil {
		in.events <- buildErrorEvent(lg, 0, 0, fmt.Errorf("get_or_create log_run: %w", err))
		return
	}

	treeSize, err := client.TreeSize(ctx)
	if err != nil {
		in.events <- buildErrorEvent(lg, run.NextEntryIdx, run.TotalProcessed, fmt.Errorf("tree_size: %w", err))
		return
	}
	_ = in.progressDB.SetLogTreeSizeAtStart(lg.LogID, treeSize)

	totalTarget := in.req.BatchSizePerLog
	cursor := run.NextEntryIdx
	sessionProcessed := int64(0)
	lastEventAt := int64(0)

	issuerCache := make(map[[32]byte]*issuerInfo)

	for {
		if err := ctx.Err(); err != nil {
			in.events <- buildEvent(lg, "error", err.Error(), sessionProcessed, run.TotalProcessed+sessionProcessed, cursor, treeSize)
			return
		}
		if totalTarget > 0 && sessionProcessed >= totalTarget {
			in.events <- buildEvent(lg, "complete", "", sessionProcessed, run.TotalProcessed+sessionProcessed, cursor, treeSize)
			return
		}
		if cursor >= treeSize {
			in.events <- buildEvent(lg, "caught_up", "", sessionProcessed, run.TotalProcessed+sessionProcessed, cursor, treeSize)
			return
		}

		end := cursor + multilogPageSize
		if end > treeSize {
			end = treeSize
		}
		leaves, err := client.FetchEntries(ctx, cursor, end)
		if err != nil {
			// Static-ct-api logs publish tiles asynchronously after the
			// checkpoint advances; the trailing tile can 403/404 for a few
			// seconds while we're at the frontier. Treat that as caught_up
			// rather than a fatal error.
			if ctlog.IsNotFound(err) {
				in.events <- buildEvent(lg, "caught_up", "", sessionProcessed, run.TotalProcessed+sessionProcessed, cursor, treeSize)
				return
			}
			in.events <- buildErrorEvent(lg, cursor, run.TotalProcessed+sessionProcessed, err)
			return
		}
		if len(leaves) == 0 {
			in.events <- buildEvent(lg, "caught_up", "", sessionProcessed, run.TotalProcessed+sessionProcessed, cursor, treeSize)
			return
		}

		// Resolve issuers for this batch (mutex-protected because issuers.db is shared).
		if err := prefetchIssuersLog(ctx, leaves, client, in.issuerDB, in.issuerMu, issuerCache); err != nil {
			log.Printf("%s: prefetch issuers cursor=%d: %v", shortDesc(lg), cursor, err)
		}

		// Build subject batches grouped by NotBefore month.
		byMonth := make(map[string]*monthBatch)
		for _, leaf := range leaves {
			subject, err := processLogLeaf(leaf, lg.LogID, issuerCache)
			if err != nil {
				log.Printf("%s entry=%d skip: %v", shortDesc(lg), leaf.EntryIdx, err)
				continue
			}
			month := monthKey(subject.NotBefore)
			b, ok := byMonth[month]
			if !ok {
				b = &monthBatch{}
				byMonth[month] = b
			}
			b.subjects = append(b.subjects, subject)
		}
		// Load the current pool. The rollover coordinator may swap it out
		// from under us between iterations; loading here lets the swap take
		// effect on the very next batch without further coordination.
		currentPool := in.poolRef.Load()
		for month, batch := range byMonth {
			sdb, err := currentPool.GetOrOpen(month)
			if err != nil {
				log.Printf("%s open month %s: %v", shortDesc(lg), month, err)
				continue
			}
			if err := sdb.InsertSubjectBatch(batch.subjects); err != nil {
				log.Printf("%s insert subjects month=%s: %v", shortDesc(lg), month, err)
			}
		}

		// Advance cursor to one past the last leaf returned (handles short pages).
		cursor = leaves[len(leaves)-1].EntryIdx + 1
		sessionProcessed += int64(len(leaves))
		if err := in.progressDB.UpdateLogProgress(lg.LogID, cursor, run.TotalProcessed+sessionProcessed); err != nil {
			log.Printf("%s update progress: %v", shortDesc(lg), err)
		}

		if sessionProcessed-lastEventAt >= in.progressEvery {
			in.events <- buildEvent(lg, "running", "", sessionProcessed, run.TotalProcessed+sessionProcessed, cursor, treeSize)
			lastEventAt = sessionProcessed
		}
	}
}

type monthBatch struct {
	subjects []db.Subject
}

// ── helpers ───────────────────────────────────────────────────────────────

func filterByOperators(catalog []ctlist.Log, ops []string) []ctlist.Log {
	want := make(map[string]bool, len(ops))
	for _, o := range ops {
		want[o] = true
	}
	out := catalog[:0]
	for _, lg := range catalog {
		if want[lg.Operator] {
			out = append(out, lg)
		}
	}
	return out
}

func filterByDescription(catalog []ctlist.Log, substr string) []ctlist.Log {
	out := catalog[:0]
	for _, lg := range catalog {
		if strings.Contains(lg.Description, substr) {
			out = append(out, lg)
		}
	}
	return out
}

func shortDesc(lg ctlist.Log) string {
	return fmt.Sprintf("%s/%s", lg.Operator, lg.Description)
}

func buildEvent(lg ctlist.Log, status, errStr string, sessionProcessed, totalProcessed, nextIdx, treeSize int64) *pb.LogProgress {
	return &pb.LogProgress{
		LogId:            lg.LogID[:],
		Description:      lg.Description,
		Operator:         lg.Operator,
		Protocol:         string(lg.Protocol),
		EntriesProcessed: sessionProcessed,
		TotalProcessed:   totalProcessed,
		NextEntryIdx:     nextIdx,
		TreeSize:         treeSize,
		Status:           status,
		Error:            errStr,
		UpdatedAt:        time.Now().UTC().Format(time.RFC3339),
	}
}

func buildErrorEvent(lg ctlist.Log, nextIdx, total int64, err error) *pb.LogProgress {
	return buildEvent(lg, "error", err.Error(), 0, total, nextIdx, 0)
}

// monthKey mirrors db.certMonth but is reachable from this file.
func monthKey(notBefore string) string {
	if len(notBefore) >= 7 {
		return notBefore[:7]
	}
	return "unknown"
}

// ── log-leaf processing (multi-log) ───────────────────────────────────────

// processLogLeaf builds a db.Subject populated with cert_hash + log_id for
// the multi-log dedup path.
func processLogLeaf(leaf *ctlog.LogLeaf, logID [32]byte, cache map[[32]byte]*issuerInfo) (db.Subject, error) {
	cert, err := parseCertLogLeaf(leaf)
	if err != nil {
		return db.Subject{}, fmt.Errorf("parse cert: %w", err)
	}
	var info *issuerInfo
	if len(leaf.ChainFingerprints) > 0 {
		info = cache[leaf.ChainFingerprints[0]]
	}

	cn := cert.Subject.CommonName
	var org, state, country string
	if len(cert.Subject.Organization) > 0 {
		org = cert.Subject.Organization[0]
	}
	if len(cert.Subject.Province) > 0 {
		state = cert.Subject.Province[0]
	}
	if len(cert.Subject.Country) > 0 {
		country = cert.Subject.Country[0]
	}
	serial := serialHex(cert.SerialNumber)
	sans := cert.DNSNames
	var ips []string
	for _, ip := range cert.IPAddresses {
		ips = append(ips, ip.String())
	}
	notBefore := cert.NotBefore.UTC().Format("2006-01-02T15:04:05Z")
	notAfter := cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z")

	isWildcard := 0
	for _, s := range sans {
		if strings.HasPrefix(s, "*.") {
			isWildcard = 1
			break
		}
	}

	var caID int64
	if info != nil {
		caID = info.caID
	}

	// Stable cert identity across logs: SHA-256 of the leaf certificate DER.
	certHash := sha256.Sum256(leaf.Certificate)

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
		URL:          buildURL(sans, cn),
		IsWildcard:   isWildcard,
		SANCount:     len(sans),
		EntryType:    string(leaf.EntryType),
		CertHash:     certHash[:],
		LogID:        logID[:],
	}
	return subject, nil
}

// parseCertLogLeaf is the LogLeaf-shaped twin of parseCert (TileLeaf-based).
// It tolerates the same set of malformed certificates by falling back to
// google/certificate-transparency-go's lenient parser.
func parseCertLogLeaf(leaf *ctlog.LogLeaf) (*x509.Certificate, error) {
	if len(leaf.Certificate) == 0 {
		return nil, fmt.Errorf("no certificate data")
	}
	return parseAnyCert(leaf.Certificate)
}

// prefetchIssuersLog is the LogClient-shaped twin of prefetchIssuers. It uses
// LogClient.FetchIssuer (cache-backed for RFC 6962, HTTP for tile logs) and a
// caller-supplied mutex around the shared issuers.db.
func prefetchIssuersLog(
	ctx context.Context,
	leaves []*ctlog.LogLeaf,
	client ctlog.LogClient,
	issuerDB *db.IssuerDB,
	issuerMu *sync.Mutex,
	cache map[[32]byte]*issuerInfo,
) error {
	var newFPs [][32]byte
	seen := make(map[[32]byte]bool)
	for _, leaf := range leaves {
		if len(leaf.ChainFingerprints) == 0 {
			continue
		}
		fp := leaf.ChainFingerprints[0]
		if _, ok := cache[fp]; ok {
			continue
		}
		if seen[fp] {
			continue
		}
		seen[fp] = true
		newFPs = append(newFPs, fp)
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
			if err == nil {
				if cert, err := parseAnyCert(der); err == nil {
					info.commonName = cert.Subject.CommonName
					if len(cert.Subject.Organization) > 0 {
						info.organization = cert.Subject.Organization[0]
					}
					if len(cert.Subject.Country) > 0 {
						info.country = cert.Subject.Country[0]
					}
				}
			}
			results[i] = fetched{fp, info}
		}(i, fp)
	}
	wg.Wait()

	issuerMu.Lock()
	defer issuerMu.Unlock()
	for _, r := range results {
		id, err := issuerDB.UpsertIssuer(r.fp, r.info.commonName, r.info.organization, r.info.country)
		if err != nil {
			log.Printf("warn: upsert issuer %x: %v", r.fp[:4], err)
			continue
		}
		r.info.caID = id
		info := r.info
		cache[r.fp] = &info
	}
	return nil
}
