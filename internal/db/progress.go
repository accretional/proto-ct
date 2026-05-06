package db

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// ProgressDB tracks ingestion runs and per-cert metadata.
type ProgressDB struct {
	db *sql.DB
}

// Run represents a tracked ingestion session for a monitoring root.
type Run struct {
	ID             int64
	MonitoringRoot string
	StartedAt      string
	UpdatedAt      string
	Status         string // "in_progress" | "complete"
	NextTileIdx    int
	TotalProcessed int
}

// OpenProgressDB opens or creates the progress database at path.
func OpenProgressDB(path string) (*ProgressDB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open progress db: %w", err)
	}
	if _, err := db.Exec(`PRAGMA journal_mode=WAL;`); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS runs (
			id              INTEGER PRIMARY KEY AUTOINCREMENT,
			monitoring_root TEXT    NOT NULL UNIQUE,
			started_at      TEXT    NOT NULL,
			updated_at      TEXT    NOT NULL,
			status          TEXT    NOT NULL DEFAULT 'in_progress',
			next_tile_idx   INTEGER NOT NULL DEFAULT 0,
			total_processed INTEGER NOT NULL DEFAULT 0
		);
		CREATE TABLE IF NOT EXISTS cert_log (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			run_id      INTEGER NOT NULL,
			tile_idx    INTEGER NOT NULL,
			entry_idx   INTEGER NOT NULL,
			not_after   TEXT,
			ct_log_uri  TEXT,
			FOREIGN KEY(run_id) REFERENCES runs(id)
		);
		CREATE UNIQUE INDEX IF NOT EXISTS idx_cert_log_tile_entry
			ON cert_log(tile_idx, entry_idx);
	`); err != nil {
		db.Close()
		return nil, fmt.Errorf("create progress tables: %w", err)
	}
	return &ProgressDB{db: db}, nil
}

// GetOrCreateRun returns an existing run for monitoring_root or creates a new one.
func (p *ProgressDB) GetOrCreateRun(monitoringRoot string) (*Run, error) {
	run := &Run{}
	err := p.db.QueryRow(`
		SELECT id, monitoring_root, started_at, updated_at, status, next_tile_idx, total_processed
		FROM runs WHERE monitoring_root = ?`, monitoringRoot,
	).Scan(&run.ID, &run.MonitoringRoot, &run.StartedAt, &run.UpdatedAt,
		&run.Status, &run.NextTileIdx, &run.TotalProcessed)
	if err == nil {
		return run, nil
	}
	if err != sql.ErrNoRows {
		return nil, fmt.Errorf("query run: %w", err)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	res, err := p.db.Exec(`
		INSERT INTO runs (monitoring_root, started_at, updated_at, status, next_tile_idx, total_processed)
		VALUES (?, ?, ?, 'in_progress', 0, 0)`, monitoringRoot, now, now)
	if err != nil {
		return nil, fmt.Errorf("insert run: %w", err)
	}
	id, _ := res.LastInsertId()
	return &Run{
		ID:             id,
		MonitoringRoot: monitoringRoot,
		StartedAt:      now,
		UpdatedAt:      now,
		Status:         "in_progress",
	}, nil
}

// UpdateProgress records completion of a tile, advancing next_tile_idx.
func (p *ProgressDB) UpdateProgress(runID int64, nextTileIdx, totalProcessed int) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := p.db.Exec(`
		UPDATE runs
		SET next_tile_idx = ?, total_processed = ?, updated_at = ?
		WHERE id = ?`, nextTileIdx, totalProcessed, now, runID)
	if err != nil {
		return fmt.Errorf("update progress: %w", err)
	}
	return nil
}

// LogCerts records metadata for a batch of processed entries. Ignores duplicates.
func (p *ProgressDB) LogCerts(runID int64, entries []CertLogEntry) error {
	tx, err := p.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	stmt, err := tx.Prepare(`
		INSERT OR IGNORE INTO cert_log (run_id, tile_idx, entry_idx, not_after, ct_log_uri)
		VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, e := range entries {
		if _, err := stmt.Exec(runID, e.TileIdx, e.EntryIdx, e.NotAfter, e.CTLogURI); err != nil {
			return fmt.Errorf("log cert %d/%d: %w", e.TileIdx, e.EntryIdx, err)
		}
	}
	return tx.Commit()
}

// CertLogEntry holds per-cert metadata for the progress log.
type CertLogEntry struct {
	TileIdx  int
	EntryIdx int
	NotAfter string
	CTLogURI string
}

// GetTotalProcessed returns the cumulative entries mirrored for a monitoring root.
func (p *ProgressDB) GetTotalProcessed(monitoringRoot string) (int64, error) {
	var total int64
	err := p.db.QueryRow(
		`SELECT COALESCE(total_processed, 0) FROM runs WHERE monitoring_root = ?`,
		monitoringRoot,
	).Scan(&total)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return total, err
}

// Close closes the database.
func (p *ProgressDB) Close() error { return p.db.Close() }
