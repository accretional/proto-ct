package db

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// ProgressDB tracks ingestion runs.
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
	`); err != nil {
		db.Close()
		return nil, fmt.Errorf("create progress tables: %w", err)
	}
	// Drop the legacy cert_log table (redundant — subjects.db enforces idempotency).
	// VACUUM reclaims the freed pages on first open after upgrade.
	if _, err := db.Exec(`DROP TABLE IF EXISTS cert_log;`); err != nil {
		db.Close()
		return nil, fmt.Errorf("drop cert_log: %w", err)
	}
	if _, err := db.Exec(`VACUUM;`); err != nil {
		// Non-fatal: space will be reclaimed incrementally.
		fmt.Printf("warn: vacuum progress.db: %v\n", err)
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
