package db

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"

	_ "modernc.org/sqlite"
)

// certMonth returns the "YYYY-MM" partition key for a not_before string.
// Falls back to "unknown" for missing or malformed values.
func certMonth(notBefore string) string {
	if len(notBefore) >= 7 {
		return notBefore[:7]
	}
	return "unknown"
}

// IssuerDB manages the issuers SQLite database.
type IssuerDB struct {
	db *sql.DB
}

// SubjectDB manages the subjects SQLite database.
type SubjectDB struct {
	db *sql.DB
}

// Subject holds certificate subject information extracted from a CT log entry.
type Subject struct {
	CAID         int64
	SerialNumber string
	CommonName   string
	Organization string
	State        string
	Country      string
	NotBefore    string
	NotAfter     string
	SANDomains   string // comma-separated DNS SANs
	SANIPS       string // comma-separated IP SANs
	URL          string
	IsWildcard   int // 1 if any SAN starts with "*."
	SANCount     int
	EntryType    string // "x509" | "precert"
	TileIdx      int
	EntryIdx     int

	// Multi-log fields (zero/empty for the legacy single-log path):
	CertHash []byte // SHA-256(TBSCertificate); 32 bytes when set, nil otherwise
	LogID    []byte // canonical log identity; 32 bytes when set, nil otherwise
}

// CertLogEntry records that a leaf with cert_hash was observed in log_id at entry_idx.
// One subjects row + N cert_log rows represent the same cert appearing in N logs.
type CertLogEntry struct {
	LogID    []byte // 32 bytes
	EntryIdx int64  // global index within the log
	CertHash []byte // 32 bytes
	SeenAt   int64  // unix epoch seconds
}

// OpenIssuerDB opens or creates the issuer database at path.
func OpenIssuerDB(path string) (*IssuerDB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open issuer db: %w", err)
	}
	// Single writer connection — multi-log workers serialise through one
	// connection so per-connection PRAGMAs stay in effect everywhere and
	// concurrent inserts queue in Go instead of racing for the SQLite lock.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`
		PRAGMA journal_mode=WAL;
		PRAGMA synchronous=NORMAL;
		PRAGMA busy_timeout=10000;
		PRAGMA cache_size=-32768;
		PRAGMA temp_store=MEMORY;
	`); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS issuers (
			ca_id        INTEGER PRIMARY KEY AUTOINCREMENT,
			fingerprint  TEXT    NOT NULL UNIQUE,
			common_name  TEXT,
			organization TEXT,
			country      TEXT
		);
	`); err != nil {
		db.Close()
		return nil, fmt.Errorf("create issuers table: %w", err)
	}
	return &IssuerDB{db: db}, nil
}

// UpsertIssuer inserts an issuer if not present and returns its ca_id.
func (idb *IssuerDB) UpsertIssuer(fp [32]byte, commonName, organization, country string) (int64, error) {
	fpHex := hex.EncodeToString(fp[:])
	var caID int64
	err := idb.db.QueryRow(`SELECT ca_id FROM issuers WHERE fingerprint = ?`, fpHex).Scan(&caID)
	if err == nil {
		return caID, nil
	}
	if err != sql.ErrNoRows {
		return 0, fmt.Errorf("query issuer: %w", err)
	}
	res, err := idb.db.Exec(
		`INSERT INTO issuers (fingerprint, common_name, organization, country) VALUES (?, ?, ?, ?)`,
		fpHex, commonName, organization, country,
	)
	if err != nil {
		return 0, fmt.Errorf("insert issuer: %w", err)
	}
	return res.LastInsertId()
}

// CheckpointAndClose flushes the WAL into the main file before closing.
// This leaves the database file in a consistent, copyable state with no WAL.
func (idb *IssuerDB) CheckpointAndClose() error {
	idb.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`) //nolint:errcheck
	return idb.db.Close()
}

// Close closes the database.
func (idb *IssuerDB) Close() error { return idb.db.Close() }

// OpenSubjectDB opens or creates the subject database at path, configured for
// write-optimised ingestion. Query indexes (ca_id, cn, not_after, wildcard) are
// intentionally omitted — call BuildQueryIndexes before archiving.
//
// Multi-writer note: PRAGMAs go in the DSN so every connection in the pool
// inherits them (a one-off `db.Exec("PRAGMA ...")` only affects whichever
// connection happened to run it). EXCLUSIVE locking is dropped so concurrent
// workers in the multi-log fan-out can queue on the brief per-transaction WAL
// writer lock instead of serialising on one Go-level connection.
func OpenSubjectDB(path string) (*SubjectDB, error) {
	dsn := "file:" + path +
		"?_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(OFF)" +
		"&_pragma=busy_timeout(10000)" +
		"&_pragma=cache_size(-524288)" +
		"&_pragma=wal_autocheckpoint(20000)" +
		"&_pragma=temp_store(MEMORY)" +
		"&_pragma=mmap_size(2147483648)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open subject db: %w", err)
	}
	// Allow concurrent writer connections; SQLite's WAL writer lock still
	// serialises the actual transactions, but contention is brief per-tx
	// rather than per-connection-lifetime.
	db.SetMaxOpenConns(8)

	// Base table (created fresh or already exists).
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS subjects (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			ca_id         INTEGER NOT NULL,
			serial_number TEXT,
			common_name   TEXT,
			organization  TEXT,
			state         TEXT,
			country       TEXT,
			not_before    TEXT,
			not_after     TEXT,
			san_domains   TEXT,
			san_ips       TEXT,
			url           TEXT,
			is_wildcard   INTEGER DEFAULT 0,
			san_count     INTEGER DEFAULT 0,
			entry_type    TEXT    DEFAULT 'x509',
			tile_idx      INTEGER,
			entry_idx     INTEGER
		);
		CREATE UNIQUE INDEX IF NOT EXISTS idx_subjects_tile_entry ON subjects(tile_idx, entry_idx);
	`); err != nil {
		db.Close()
		return nil, fmt.Errorf("create subjects table: %w", err)
	}

	// Additive migrations for databases created before new columns existed.
	migrations := []string{
		`ALTER TABLE subjects ADD COLUMN san_ips     TEXT`,
		`ALTER TABLE subjects ADD COLUMN is_wildcard INTEGER DEFAULT 0`,
		`ALTER TABLE subjects ADD COLUMN san_count   INTEGER DEFAULT 0`,
		`ALTER TABLE subjects ADD COLUMN entry_type  TEXT DEFAULT 'x509'`,
		`ALTER TABLE subjects ADD COLUMN tile_idx    INTEGER`,
		`ALTER TABLE subjects ADD COLUMN entry_idx   INTEGER`,
		// Multi-log additions:
		`ALTER TABLE subjects ADD COLUMN cert_hash   BLOB`,
		`ALTER TABLE subjects ADD COLUMN log_id      BLOB`,
	}
	for _, m := range migrations {
		db.Exec(m) //nolint:errcheck
	}
	// Ensure both idempotency indexes exist on older databases.
	// Tile-entry index stays for legacy single-log writes (with non-NULL values).
	// Log (don't swallow) failures: a failure here means the table already holds
	// duplicate keys, so the unique index is NOT enforced and dedup is silently
	// broken — exactly how a partition ends up with the dups that later wedge a
	// full rebuild. Surfacing it lets us catch a corrupt/legacy DB early.
	if _, err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_subjects_tile_entry ON subjects(tile_idx, entry_idx)`); err != nil {
		log.Printf("warn: %s: idx_subjects_tile_entry not enforced (existing duplicate keys?): %v", path, err)
	}
	// Partial unique index — only enforced when cert_hash is set. New multi-log
	// writes populate cert_hash and leave tile/entry NULL, so the two indexes
	// don't conflict.
	if _, err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_subjects_cert_hash ON subjects(cert_hash) WHERE cert_hash IS NOT NULL`); err != nil {
		log.Printf("warn: %s: idx_subjects_cert_hash not enforced (existing duplicate keys?): %v", path, err)
	}

	// Per-log provenance: tracks where each cert was seen. PK (log_id, entry_idx)
	// makes resume idempotent — re-fetching an entry is a no-op insert.
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS cert_log (
			log_id    BLOB    NOT NULL,
			entry_idx INTEGER NOT NULL,
			cert_hash BLOB    NOT NULL,
			seen_at   INTEGER NOT NULL,
			PRIMARY KEY (log_id, entry_idx)
		) WITHOUT ROWID;
	`); err != nil {
		db.Close()
		return nil, fmt.Errorf("create cert_log: %w", err)
	}
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_cert_log_hash ON cert_log(cert_hash)`) //nolint:errcheck

	return &SubjectDB{db: db}, nil
}

// subjectCols is the explicit column list used for cross-database INSERT to
// avoid autoincrement id conflicts.
const subjectCols = `ca_id, serial_number, common_name, organization, state, country,
	not_before, not_after, san_domains, san_ips, url,
	is_wildcard, san_count, entry_type, tile_idx, entry_idx,
	cert_hash, log_id`

// MergeSubjectDBsScratch merges all rows from srcPath into dstPath, skipping
// duplicates on cert_hash / (tile_idx, entry_idx), with control over WHERE the
// merged file is built. The merge re-inserts every existing archive row plus
// the src rows through the unique indexes — random B-tree I/O that, on a giant
// (>RAM) archive month living on the HDD, degrades to the ~1 MB/s
// spinning-disk-seek wall (see docs/FLUSH_AND_SHUTDOWN_PLAN.md §B2).
//
// When scratchDir is non-empty (and writable), the whole merge — including the
// query-index build — happens in a file there (the SSD), where random I/O is a
// non-issue, and only the finished, compact month is copied SEQUENTIALLY to the
// HDD and atomically renamed into place. This converts the bottleneck from
// random-HDD to random-SSD: the §6c "dedup on SSD, bulk writes to HDD" split.
//
// When scratchDir is "" the merged file is built adjacent to dstPath (the old
// behavior). A scratchDir that can't be created falls back to that too, so the
// flush always makes progress.
//
// Either way dstPath is replaced via os.Rename only after the new file is fully
// built (never pre-deleted), so an interruption leaves the existing archive
// month intact — never the no-file window that destroyed 2024-12.
func MergeSubjectDBsScratch(srcPath, dstPath, scratchDir string) error {
	pid := os.Getpid()
	hddNew := fmt.Sprintf("%s.new.%d", dstPath, pid)

	// Decide where to build. crossFS == true means buildPath is on a (likely
	// faster) filesystem than dstPath, so the finished file must be COPIED to
	// the HDD before the atomic rename.
	buildPath := hddNew
	crossFS := false
	if scratchDir != "" {
		if err := os.MkdirAll(scratchDir, 0o755); err != nil {
			log.Printf("warn: merge scratch dir %s unusable (%v); building adjacent to archive", scratchDir, err)
		} else {
			month := filepath.Base(filepath.Dir(dstPath))
			buildPath = filepath.Join(scratchDir, fmt.Sprintf("%s.merge.%d", month, pid))
			crossFS = true
		}
	}
	removeDBFiles(buildPath) // clear any stale build from a prior interrupted run

	if err := buildMergedSubjectDB(dstPath, srcPath, buildPath); err != nil {
		removeDBFiles(buildPath)
		return err
	}
	// Build the read-path indexes here too, so that random work also lands on
	// the scratch filesystem rather than the HDD.
	if err := BuildQueryIndexes(buildPath); err != nil {
		log.Printf("warn: build query indexes on %s: %v", buildPath, err)
	}

	// Replace dstPath atomically. Drop the old WAL/SHM so the replaced file
	// isn't paired with a stale sidecar.
	os.Remove(dstPath + "-wal")
	os.Remove(dstPath + "-shm")
	if !crossFS {
		return os.Rename(buildPath, dstPath)
	}
	// Cross-filesystem: os.Rename can't move SSD→HDD, so copy the finished file
	// to an HDD-adjacent temp (sequential write), then atomically rename it.
	if err := copySubjectDB(buildPath, hddNew); err != nil {
		removeDBFiles(buildPath)
		os.Remove(hddNew)
		return fmt.Errorf("copy merged month to archive fs: %w", err)
	}
	removeDBFiles(buildPath)
	return os.Rename(hddNew, dstPath)
}

// removeDBFiles deletes a SQLite db path and its WAL/SHM/journal sidecars.
func removeDBFiles(path string) {
	for _, suf := range []string{"", "-wal", "-shm", "-journal"} {
		os.Remove(path + suf)
	}
}

// buildMergedSubjectDB creates newPath as a fresh subjects database containing
// all rows from existingPath followed by non-duplicate rows from srcPath.
// Uses journal_mode=OFF since newPath is a build-once file: if interrupted,
// the caller removes it and retries from scratch.
func buildMergedSubjectDB(existingPath, srcPath, newPath string) error {
	db, err := sql.Open("sqlite", newPath)
	if err != nil {
		return fmt.Errorf("create merged subjects db: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	// Large cache + mmap keep the cert_hash unique-index working set resident in
	// RAM during the rebuild, so the random index probes hit memory instead of
	// the scratch filesystem — the dominant cost of the merge. Sized to match
	// MergeArchiveMonth (4 GiB cache, 8 GiB mmap); leaves headroom on 16 GB.
	if _, err := db.Exec(`
		PRAGMA journal_mode=OFF;
		PRAGMA synchronous=OFF;
		PRAGMA cache_size=-4194304;
		PRAGMA temp_store=MEMORY;
		PRAGMA mmap_size=8589934592;
	`); err != nil {
		return err
	}
	if _, err := db.Exec(`
		CREATE TABLE subjects (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			ca_id         INTEGER NOT NULL,
			serial_number TEXT,
			common_name   TEXT,
			organization  TEXT,
			state         TEXT,
			country       TEXT,
			not_before    TEXT,
			not_after     TEXT,
			san_domains   TEXT,
			san_ips       TEXT,
			url           TEXT,
			is_wildcard   INTEGER DEFAULT 0,
			san_count     INTEGER DEFAULT 0,
			entry_type    TEXT    DEFAULT 'x509',
			tile_idx      INTEGER,
			entry_idx     INTEGER,
			cert_hash     BLOB,
			log_id        BLOB
		);
		CREATE UNIQUE INDEX idx_subjects_tile_entry ON subjects(tile_idx, entry_idx);
		CREATE UNIQUE INDEX idx_subjects_cert_hash ON subjects(cert_hash) WHERE cert_hash IS NOT NULL;
	`); err != nil {
		return fmt.Errorf("create schema in merged db: %w", err)
	}
	if _, err := db.Exec(fmt.Sprintf(`ATTACH '%s' AS existing`, existingPath)); err != nil {
		return fmt.Errorf("attach existing subjects: %w", err)
	}
	if _, err := db.Exec(fmt.Sprintf(`ATTACH '%s' AS src`, srcPath)); err != nil {
		return fmt.Errorf("attach src subjects: %w", err)
	}
	// All existing archive rows first — written as sequential fresh pages.
	// OR IGNORE (not plain INSERT) so a legacy/corrupt archive that already
	// contains duplicate (tile_idx,entry_idx) or cert_hash rows is healed by
	// collapsing the dup to a single row, rather than aborting the whole
	// rebuild. The unique indexes define row identity, so this is lossless.
	if _, err := db.Exec(`INSERT OR IGNORE INTO subjects (` + subjectCols + `)
		SELECT ` + subjectCols + ` FROM existing.subjects`); err != nil {
		return fmt.Errorf("copy existing subjects: %w", err)
	}
	// New rows from the active DB, skipping any already present.
	if _, err := db.Exec(`INSERT OR IGNORE INTO subjects (` + subjectCols + `)
		SELECT ` + subjectCols + ` FROM src.subjects`); err != nil {
		return fmt.Errorf("merge src subjects: %w", err)
	}
	if _, err := db.Exec(`DETACH existing; DETACH src`); err != nil {
		return err
	}
	return nil
}

// queryIndexStmts builds the read-path indexes. They are created after bulk
// ingestion (never maintained per-row during a write-only load), so the B2
// in-place append can drop them, append with only the unique dedup indexes
// resident, and rebuild them once via an efficient sort.
var queryIndexStmts = []string{
	`CREATE INDEX IF NOT EXISTS idx_subjects_ca_id     ON subjects(ca_id)`,
	`CREATE INDEX IF NOT EXISTS idx_subjects_cn        ON subjects(common_name)`,
	`CREATE INDEX IF NOT EXISTS idx_subjects_not_after ON subjects(not_after)`,
	`CREATE INDEX IF NOT EXISTS idx_subjects_wildcard  ON subjects(is_wildcard)`,
}

// queryIndexNames are the same indexes as queryIndexStmts, for DROP INDEX.
var queryIndexNames = []string{
	"idx_subjects_ca_id",
	"idx_subjects_cn",
	"idx_subjects_not_after",
	"idx_subjects_wildcard",
}

// BuildQueryIndexes creates the read-oriented indexes on a subjects.db that was
// opened for write-only ingestion. Call this on the SSD copy before archiving.
func BuildQueryIndexes(path string) error {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return fmt.Errorf("open for indexing: %w", err)
	}
	defer db.Close()
	if _, err := db.Exec(`PRAGMA synchronous=OFF; PRAGMA cache_size=-524288;`); err != nil {
		return err
	}
	for _, stmt := range queryIndexStmts {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("create index: %w", err)
		}
	}
	return nil
}

// InsertSubject records a certificate subject. Silently ignores duplicate tile+entry.
func (sdb *SubjectDB) InsertSubject(s Subject) error {
	return sdb.InsertSubjectBatch([]Subject{s})
}

// InsertSubjectBatch records a batch of subjects in a single transaction.
// Silently ignores duplicates on (tile_idx, entry_idx).
func (sdb *SubjectDB) InsertSubjectBatch(subjects []Subject) error {
	if len(subjects) == 0 {
		return nil
	}
	tx, err := sdb.db.Begin()
	if err != nil {
		return fmt.Errorf("begin batch: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck
	stmt, err := tx.Prepare(`
		INSERT OR IGNORE INTO subjects
			(ca_id, serial_number, common_name, organization, state, country,
			 not_before, not_after, san_domains, san_ips, url,
			 is_wildcard, san_count, entry_type, tile_idx, entry_idx,
			 cert_hash, log_id)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return fmt.Errorf("prepare insert: %w", err)
	}
	defer stmt.Close()
	for _, s := range subjects {
		var certHash, logID any
		if len(s.CertHash) > 0 {
			certHash = s.CertHash
		}
		if len(s.LogID) > 0 {
			logID = s.LogID
		}
		// Legacy path: when tile_idx/entry_idx are the dedup key, leave them set.
		// Multi-log path: caller passes zero for both and a non-empty CertHash so
		// dedup happens on the partial unique index instead.
		var tileIdx, entryIdx any
		if len(s.CertHash) == 0 {
			tileIdx = s.TileIdx
			entryIdx = s.EntryIdx
		}
		if _, err := stmt.Exec(
			s.CAID, s.SerialNumber, s.CommonName, s.Organization, s.State, s.Country,
			s.NotBefore, s.NotAfter, s.SANDomains, s.SANIPS, s.URL,
			s.IsWildcard, s.SANCount, s.EntryType, tileIdx, entryIdx,
			certHash, logID,
		); err != nil {
			return fmt.Errorf("insert subject tile=%d entry=%d: %w", s.TileIdx, s.EntryIdx, err)
		}
	}
	return tx.Commit()
}

// InsertCertLogBatch records per-log provenance for a batch of (log_id, entry_idx, cert_hash)
// observations in a single transaction. Duplicate (log_id, entry_idx) rows are silently ignored.
func (sdb *SubjectDB) InsertCertLogBatch(entries []CertLogEntry) error {
	if len(entries) == 0 {
		return nil
	}
	tx, err := sdb.db.Begin()
	if err != nil {
		return fmt.Errorf("begin cert_log batch: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck
	stmt, err := tx.Prepare(`
		INSERT OR IGNORE INTO cert_log (log_id, entry_idx, cert_hash, seen_at)
		VALUES (?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare cert_log insert: %w", err)
	}
	defer stmt.Close()
	for _, e := range entries {
		if _, err := stmt.Exec(e.LogID, e.EntryIdx, e.CertHash, e.SeenAt); err != nil {
			return fmt.Errorf("insert cert_log entry=%d: %w", e.EntryIdx, err)
		}
	}
	return tx.Commit()
}

// CheckpointAndClose flushes the WAL into the main file before closing.
func (sdb *SubjectDB) CheckpointAndClose() error {
	sdb.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`) //nolint:errcheck
	return sdb.db.Close()
}

// Close closes the database.
func (sdb *SubjectDB) Close() error { return sdb.db.Close() }

// ── SubjectDBPool ─────────────────────────────────────────────────────────────

// SubjectDBPool manages per-cert-issuance-month SubjectDB handles within a
// single ingestion session. Each month's DB lives at activeDir/YYYY-MM/subjects.db.
// FlushAll checkpoints every open DB and merges it into the archive, keeping
// each partition unfragmented via the build-on-new-file MergeSubjectDBs pattern.
type SubjectDBPool struct {
	mu        sync.Mutex
	dbs       map[string]*SubjectDB
	activeDir string // e.g. data/active/20260519/
}

// NewSubjectDBPool creates an empty pool rooted at activeDir.
func NewSubjectDBPool(activeDir string) *SubjectDBPool {
	return &SubjectDBPool{
		dbs:       make(map[string]*SubjectDB),
		activeDir: activeDir,
	}
}

// GetOrOpen returns the SubjectDB for the given month, opening it lazily.
func (p *SubjectDBPool) GetOrOpen(month string) (*SubjectDB, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if sdb, ok := p.dbs[month]; ok {
		return sdb, nil
	}
	dir := filepath.Join(p.activeDir, month)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("pool mkdir %s: %w", dir, err)
	}
	sdb, err := OpenSubjectDB(filepath.Join(dir, "subjects.db"))
	if err != nil {
		return nil, err
	}
	p.dbs[month] = sdb
	return sdb, nil
}

// InsertBatch groups subjects by cert issuance month and inserts each group
// into the appropriate monthly DB, opening it lazily.
func (p *SubjectDBPool) InsertBatch(subjects []Subject) error {
	byMonth := make(map[string][]Subject, 4)
	for _, s := range subjects {
		m := certMonth(s.NotBefore)
		byMonth[m] = append(byMonth[m], s)
	}
	for month, batch := range byMonth {
		sdb, err := p.GetOrOpen(month)
		if err != nil {
			return err
		}
		if err := sdb.InsertSubjectBatch(batch); err != nil {
			return err
		}
	}
	return nil
}


// archiveFlushMu serializes ALL writes into the shared HDD archive across the
// whole process. Two FlushAll passes (e.g. the hourly rollover flush and the
// IngestAll-exit deferred flush) operate on different pool instances but write
// the same archive months; without this lock they race on each month's
// build/rename and can destroy an archive month. Every entry point that merges
// into the archive (FlushAll, FlushArchiveMonth) takes this lock.
var archiveFlushMu sync.Mutex

// FlushAll checkpoints and closes every open DB, then merges each into
// archiveRoot/YYYY-MM/subjects.db:
//
//   - Archive doesn't exist: build query indexes on the active file, copy it
//     across as the new month, and seed the SSD dedup set from it.
//   - Archive exists: append-only deduped flush (FlushMonthDeduped) — pre-filter
//     the active rows against the SSD dedup set and sequentially append only the
//     new ones (O(new rows)). No O(archive-month) rebuild and no SSD scratch per
//     flush. Compaction + read-path index rebuild are deferred to SealMonth, run
//     rarely (a caught-up month / end of a bulk drain), not on every rollover.
//
// All months are attempted regardless of individual errors; the first error
// encountered is returned.
func (p *SubjectDBPool) FlushAll(archiveRoot string) error {
	archiveFlushMu.Lock()
	defer archiveFlushMu.Unlock()
	p.mu.Lock()
	defer p.mu.Unlock()
	var firstErr error
	// Per-month cert_hash dedup sets live on the SSD next to the active root and
	// persist across pools/sessions (they mirror the archive months).
	dedupDir := filepath.Join(filepath.Dir(filepath.Clean(p.activeDir)), "dedup")
	for month, sdb := range p.dbs {
		if err := sdb.CheckpointAndClose(); err != nil {
			log.Printf("pool: checkpoint %s: %v", month, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		activePath := filepath.Join(p.activeDir, month, "subjects.db")
		archivePath := filepath.Join(archiveRoot, month, "subjects.db")
		if err := os.MkdirAll(filepath.Dir(archivePath), 0o755); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}

		dedupPath := dedupPathFor(dedupDir, month)
		var mergeErr error
		if _, statErr := os.Stat(archivePath); os.IsNotExist(statErr) {
			// New partition: build the query indexes on the SSD active file
			// (random work stays off the HDD), copy it across as the archive
			// month, then seed the SSD dedup set from it.
			if err := BuildQueryIndexes(activePath); err != nil {
				log.Printf("pool: build indexes %s: %v", month, err)
			}
			mergeErr = copySubjectDB(activePath, archivePath)
			if mergeErr == nil {
				if ds, e := OpenDedupStore(dedupPath); e != nil {
					log.Printf("pool: open dedup %s: %v", month, e)
				} else {
					if _, e := ds.PopulateFromArchive(archivePath); e != nil {
						log.Printf("pool: seed dedup %s: %v", month, e)
					}
					ds.Close()
				}
			}
		} else {
			// Existing partition: append-only deduped flush. Pre-filter the pool's
			// rows against the SSD dedup set and sequentially append only the new
			// ones (O(new rows)), leaving the archive's cert_hash + query indexes
			// dropped — no O(archive-month) rebuild per flush and no SSD scratch
			// headroom needed. Compaction + index rebuild are deferred to SealMonth,
			// run rarely (caught-up month / end of a bulk drain), not on every
			// rollover. Only the first flush of a pre-existing month pays a one-time
			// O(month) DROP of its old cert_hash index; every flush after is fast.
			mergeErr = FlushMonthDeduped(activePath, archivePath, dedupPath)
		}
		if mergeErr != nil {
			log.Printf("pool: flush %s: %v", month, mergeErr)
			if firstErr == nil {
				firstErr = mergeErr
			}
			continue
		}

		if err := os.RemoveAll(filepath.Join(p.activeDir, month)); err != nil {
			log.Printf("pool: remove active %s: %v", month, err)
		}
	}
	p.dbs = make(map[string]*SubjectDB)
	return firstErr
}

// CloseAll closes all open DBs without merging. Used on error paths where the
// active data will be re-ingested on the next session.
func (p *SubjectDBPool) CloseAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, sdb := range p.dbs {
		sdb.Close()
	}
	p.dbs = make(map[string]*SubjectDB)
}

// copySubjectDB copies a checkpointed subjects.db from src to dst using a
// streaming file copy. Used when an archive partition doesn't exist yet.
func copySubjectDB(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(dst)
		return err
	}
	return out.Close()
}
