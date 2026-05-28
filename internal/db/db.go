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
	SANIPS        string // comma-separated IP SANs
	URL          string
	IsWildcard   int    // 1 if any SAN starts with "*."
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
	LogID     []byte // 32 bytes
	EntryIdx  int64  // global index within the log
	CertHash  []byte // 32 bytes
	SeenAt    int64  // unix epoch seconds
}

// OpenIssuerDB opens or creates the issuer database at path.
func OpenIssuerDB(path string) (*IssuerDB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open issuer db: %w", err)
	}
	if _, err := db.Exec(`
		PRAGMA journal_mode=WAL;
		PRAGMA synchronous=NORMAL;
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
func OpenSubjectDB(path string) (*SubjectDB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open subject db: %w", err)
	}
	// Single writer only — hold the exclusive lock for the connection lifetime.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`
		PRAGMA journal_mode=WAL;
		PRAGMA synchronous=OFF;
		PRAGMA locking_mode=EXCLUSIVE;
		PRAGMA cache_size=-524288;
		PRAGMA wal_autocheckpoint=20000;
		PRAGMA temp_store=MEMORY;
		PRAGMA mmap_size=2147483648;
	`); err != nil {
		db.Close()
		return nil, err
	}

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
	db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_subjects_tile_entry ON subjects(tile_idx, entry_idx)`) //nolint:errcheck
	// Partial unique index — only enforced when cert_hash is set. New multi-log
	// writes populate cert_hash and leave tile/entry NULL, so the two indexes
	// don't conflict.
	db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_subjects_cert_hash ON subjects(cert_hash) WHERE cert_hash IS NOT NULL`) //nolint:errcheck

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

// MergeSubjectDBs appends all rows from srcPath into dstPath, skipping
// duplicates on (tile_idx, entry_idx). The id column is omitted so the
// destination assigns fresh autoincrement values — avoiding PK conflicts.
//
// Instead of inserting into the existing dstPath (which fragments the B-tree
// as new pages are appended non-contiguously), this builds a brand-new file
// with all rows written sequentially, then atomically replaces dstPath.
// The result is a compact, unfragmented database with fast sequential reads.
func MergeSubjectDBs(srcPath, dstPath string) error {
	newPath := dstPath + ".new"
	os.Remove(newPath) // remove any stale file from a prior interrupted run
	if err := buildMergedSubjectDB(dstPath, srcPath, newPath); err != nil {
		os.Remove(newPath)
		return err
	}
	// Atomically replace the old file. Clean up WAL artifacts from the old DB
	// first so the new file isn't mistakenly paired with a stale WAL.
	os.Remove(dstPath + "-wal")
	os.Remove(dstPath + "-shm")
	if err := os.Remove(dstPath); err != nil {
		os.Remove(newPath)
		return fmt.Errorf("remove old subjects db: %w", err)
	}
	return os.Rename(newPath, dstPath)
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
	if _, err := db.Exec(`
		PRAGMA journal_mode=OFF;
		PRAGMA synchronous=OFF;
		PRAGMA cache_size=-524288;
		PRAGMA temp_store=MEMORY;
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
	if _, err := db.Exec(`INSERT INTO subjects (` + subjectCols + `)
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

// MergeIssuerDBs appends all rows from srcPath into dstPath, skipping
// duplicates on fingerprint. ca_id is omitted so fresh values are assigned.
func MergeIssuerDBs(srcPath, dstPath string) error {
	if _, err := os.Stat(srcPath); err != nil {
		return nil // nothing to merge if src doesn't exist
	}
	dst, err := sql.Open("sqlite", dstPath)
	if err != nil {
		return fmt.Errorf("open dst issuers: %w", err)
	}
	defer dst.Close()
	dst.SetMaxOpenConns(1)
	if _, err := dst.Exec(`PRAGMA synchronous=OFF;`); err != nil {
		return err
	}
	if _, err := dst.Exec(fmt.Sprintf(`ATTACH '%s' AS src`, srcPath)); err != nil {
		return fmt.Errorf("attach src issuers: %w", err)
	}
	if _, err := dst.Exec(`INSERT OR IGNORE INTO issuers (fingerprint, common_name, organization, country)
		SELECT fingerprint, common_name, organization, country FROM src.issuers`); err != nil {
		return fmt.Errorf("merge issuer rows: %w", err)
	}
	_, err = dst.Exec(`DETACH src`)
	return err
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
	for _, stmt := range []string{
		`CREATE INDEX IF NOT EXISTS idx_subjects_ca_id     ON subjects(ca_id)`,
		`CREATE INDEX IF NOT EXISTS idx_subjects_cn        ON subjects(common_name)`,
		`CREATE INDEX IF NOT EXISTS idx_subjects_not_after ON subjects(not_after)`,
		`CREATE INDEX IF NOT EXISTS idx_subjects_wildcard  ON subjects(is_wildcard)`,
	} {
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

// incrementalMergeThreshold is the active DB size below which FlushAll uses a
// direct INSERT OR IGNORE into the archive rather than a full rebuild. For
// live incremental ingestion (small active DBs), direct insert is fast and
// causes negligible B-tree fragmentation. For historical bulk ingestion (large
// active DBs), MergeSubjectDBs rebuilds the archive from scratch to keep pages
// contiguous and avoid read-path degradation.
const incrementalMergeThreshold = 256 << 20 // 256 MiB

// FlushAll checkpoints and closes every open DB, then merges each into
// archiveRoot/YYYY-MM/subjects.db using the most appropriate strategy:
//
//   - Archive doesn't exist: copy active file across, build query indexes.
//   - Active < 256 MiB:      INSERT OR IGNORE directly into archive (fast,
//                             minimal fragmentation for small incremental batches).
//   - Active >= 256 MiB:     full rebuild via MergeSubjectDBs (prevents B-tree
//                             fragmentation after large bulk ingestion runs).
//
// All months are attempted regardless of individual errors; the first error
// encountered is returned.
func (p *SubjectDBPool) FlushAll(archiveRoot string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	var firstErr error
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

		var mergeErr error
		if _, statErr := os.Stat(archivePath); os.IsNotExist(statErr) {
			// New partition: copy file and build all query indexes.
			mergeErr = copySubjectDB(activePath, archivePath)
			if mergeErr == nil {
				if err := BuildQueryIndexes(archivePath); err != nil {
					log.Printf("pool: build indexes %s: %v", month, err)
				}
			}
		} else {
			fi, _ := os.Stat(activePath)
			if fi != nil && fi.Size() < incrementalMergeThreshold {
				// Small incremental batch: insert directly, no rebuild.
				mergeErr = mergeSubjectDBsDirect(activePath, archivePath)
			} else {
				// Large bulk flush: rebuild from scratch to prevent fragmentation.
				mergeErr = MergeSubjectDBs(activePath, archivePath)
				if mergeErr == nil {
					if err := BuildQueryIndexes(archivePath); err != nil {
						log.Printf("pool: build indexes %s: %v", month, err)
					}
				}
			}
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

// mergeSubjectDBsDirect inserts all rows from srcPath into dstPath using
// INSERT OR IGNORE, skipping duplicates on (tile_idx, entry_idx). Used for
// small incremental flushes where a full rebuild would be disproportionately
// expensive.
func mergeSubjectDBsDirect(srcPath, dstPath string) error {
	dst, err := sql.Open("sqlite", dstPath)
	if err != nil {
		return fmt.Errorf("open dst for direct merge: %w", err)
	}
	defer dst.Close()
	dst.SetMaxOpenConns(1)
	dst.Exec(`PRAGMA synchronous=OFF; PRAGMA cache_size=-524288;`) //nolint:errcheck
	if _, err := dst.Exec(fmt.Sprintf(`ATTACH '%s' AS src`, srcPath)); err != nil {
		return fmt.Errorf("attach src for direct merge: %w", err)
	}
	if _, err := dst.Exec(`INSERT OR IGNORE INTO subjects (` + subjectCols + `)
		SELECT ` + subjectCols + ` FROM src.subjects`); err != nil {
		return fmt.Errorf("direct merge insert: %w", err)
	}
	_, err = dst.Exec(`DETACH src`)
	return err
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
