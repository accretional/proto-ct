package db

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"

	_ "modernc.org/sqlite"
)

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
	}
	for _, m := range migrations {
		db.Exec(m) //nolint:errcheck
	}
	// Ensure the idempotency index exists on older databases.
	db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_subjects_tile_entry ON subjects(tile_idx, entry_idx)`) //nolint:errcheck

	return &SubjectDB{db: db}, nil
}

// subjectCols is the explicit column list used for cross-database INSERT to
// avoid autoincrement id conflicts.
const subjectCols = `ca_id, serial_number, common_name, organization, state, country,
	not_before, not_after, san_domains, san_ips, url,
	is_wildcard, san_count, entry_type, tile_idx, entry_idx`

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
			entry_idx     INTEGER
		);
		CREATE UNIQUE INDEX idx_subjects_tile_entry ON subjects(tile_idx, entry_idx);
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
			 is_wildcard, san_count, entry_type, tile_idx, entry_idx)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return fmt.Errorf("prepare insert: %w", err)
	}
	defer stmt.Close()
	for _, s := range subjects {
		if _, err := stmt.Exec(
			s.CAID, s.SerialNumber, s.CommonName, s.Organization, s.State, s.Country,
			s.NotBefore, s.NotAfter, s.SANDomains, s.SANIPS, s.URL,
			s.IsWildcard, s.SANCount, s.EntryType, s.TileIdx, s.EntryIdx,
		); err != nil {
			return fmt.Errorf("insert subject tile=%d entry=%d: %w", s.TileIdx, s.EntryIdx, err)
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
