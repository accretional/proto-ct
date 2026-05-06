package db

import (
	"database/sql"
	"encoding/hex"
	"fmt"

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

// Issuer holds CA certificate information.
type Issuer struct {
	CAID         int64
	Fingerprint  string
	CommonName   string
	Organization string
	Country      string
}

// Subject holds certificate subject information.
type Subject struct {
	CAID         int64
	SerialNumber string
	CommonName   string
	Organization string
	State        string
	Country      string
	NotBefore    string
	NotAfter     string
	SANDomains   string // comma-separated
	URL          string
}

// OpenIssuerDB opens or creates the issuer database at path.
func OpenIssuerDB(path string) (*IssuerDB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open issuer db: %w", err)
	}
	if _, err := db.Exec(`PRAGMA journal_mode=WAL;`); err != nil {
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

// Close closes the database.
func (idb *IssuerDB) Close() error { return idb.db.Close() }

// OpenSubjectDB opens or creates the subject database at path.
func OpenSubjectDB(path string) (*SubjectDB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open subject db: %w", err)
	}
	if _, err := db.Exec(`PRAGMA journal_mode=WAL;`); err != nil {
		db.Close()
		return nil, err
	}
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
			url           TEXT
		);
		CREATE INDEX IF NOT EXISTS idx_subjects_ca_id ON subjects(ca_id);
		CREATE INDEX IF NOT EXISTS idx_subjects_cn    ON subjects(common_name);
	`); err != nil {
		db.Close()
		return nil, fmt.Errorf("create subjects table: %w", err)
	}
	return &SubjectDB{db: db}, nil
}

// InsertSubject records a certificate subject.
func (sdb *SubjectDB) InsertSubject(s Subject) error {
	_, err := sdb.db.Exec(`
		INSERT INTO subjects
			(ca_id, serial_number, common_name, organization, state, country,
			 not_before, not_after, san_domains, url)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.CAID, s.SerialNumber, s.CommonName, s.Organization, s.State, s.Country,
		s.NotBefore, s.NotAfter, s.SANDomains, s.URL,
	)
	if err != nil {
		return fmt.Errorf("insert subject: %w", err)
	}
	return nil
}

// Close closes the database.
func (sdb *SubjectDB) Close() error { return sdb.db.Close() }
