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
	// One-time migration: drop legacy cert_log if it still exists.
	if _, err := db.Exec(`DROP TABLE IF EXISTS cert_log;`); err != nil {
		db.Close()
		return nil, fmt.Errorf("drop cert_log: %w", err)
	}
	// Multi-log progress table — keyed by canonical log_id (SHA-256 of pubkey).
	// Coexists with the legacy single-log `runs` table during the rollout.
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS log_runs (
			id                 INTEGER PRIMARY KEY AUTOINCREMENT,
			log_id             BLOB    NOT NULL UNIQUE,
			description        TEXT    NOT NULL,
			submission_url     TEXT    NOT NULL,
			monitoring_url     TEXT,
			protocol           TEXT    NOT NULL,
			operator           TEXT    NOT NULL,
			state              TEXT    NOT NULL,
			next_entry_idx     INTEGER NOT NULL DEFAULT 0,
			tree_size_at_start INTEGER,
			total_processed    INTEGER NOT NULL DEFAULT 0,
			started_at         TEXT    NOT NULL,
			updated_at         TEXT    NOT NULL
		);
	`); err != nil {
		db.Close()
		return nil, fmt.Errorf("create log_runs: %w", err)
	}
	return &ProgressDB{db: db}, nil
}

// LogRun is a per-log ingestion record keyed by the canonical 32-byte LogID.
type LogRun struct {
	ID               int64
	LogID            [32]byte
	Description      string
	SubmissionURL    string
	MonitoringURL    string
	Protocol         string // "static-ct-api" | "rfc6962"
	Operator         string
	State            string // "usable" | "readonly" | ...
	NextEntryIdx     int64  // global entry index, not tile index
	TreeSizeAtStart  int64
	TotalProcessed   int64
	StartedAt        string
	UpdatedAt        string
}

// LogRunInit is the metadata required to register or look up a log run.
type LogRunInit struct {
	LogID         [32]byte
	Description   string
	SubmissionURL string
	MonitoringURL string
	Protocol      string
	Operator      string
	State         string
}

// GetOrCreateLogRun returns an existing log_runs row for init.LogID or creates a
// new one. The caller's metadata is updated on existing rows to track state
// transitions (e.g., usable → readonly) but progress counters are preserved.
func (p *ProgressDB) GetOrCreateLogRun(init LogRunInit) (*LogRun, error) {
	row := p.db.QueryRow(`
		SELECT id, log_id, description, submission_url, COALESCE(monitoring_url, ''),
		       protocol, operator, state, next_entry_idx, COALESCE(tree_size_at_start, 0),
		       total_processed, started_at, updated_at
		FROM log_runs WHERE log_id = ?`, init.LogID[:])
	run := &LogRun{}
	var idBlob []byte
	err := row.Scan(&run.ID, &idBlob, &run.Description, &run.SubmissionURL, &run.MonitoringURL,
		&run.Protocol, &run.Operator, &run.State, &run.NextEntryIdx, &run.TreeSizeAtStart,
		&run.TotalProcessed, &run.StartedAt, &run.UpdatedAt)
	if err == nil {
		copy(run.LogID[:], idBlob)
		// Refresh mutable metadata; never touch progress counters here.
		now := time.Now().UTC().Format(time.RFC3339)
		if _, err := p.db.Exec(`
			UPDATE log_runs
			SET description=?, submission_url=?, monitoring_url=?, protocol=?,
			    operator=?, state=?, updated_at=?
			WHERE id=?`,
			init.Description, init.SubmissionURL, init.MonitoringURL, init.Protocol,
			init.Operator, init.State, now, run.ID,
		); err != nil {
			return nil, fmt.Errorf("refresh log_run metadata: %w", err)
		}
		run.Description = init.Description
		run.SubmissionURL = init.SubmissionURL
		run.MonitoringURL = init.MonitoringURL
		run.Protocol = init.Protocol
		run.Operator = init.Operator
		run.State = init.State
		run.UpdatedAt = now
		return run, nil
	}
	if err != sql.ErrNoRows {
		return nil, fmt.Errorf("query log_run: %w", err)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	res, err := p.db.Exec(`
		INSERT INTO log_runs
			(log_id, description, submission_url, monitoring_url, protocol,
			 operator, state, next_entry_idx, total_processed, started_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, ?, ?)`,
		init.LogID[:], init.Description, init.SubmissionURL, init.MonitoringURL,
		init.Protocol, init.Operator, init.State, now, now,
	)
	if err != nil {
		return nil, fmt.Errorf("insert log_run: %w", err)
	}
	id, _ := res.LastInsertId()
	return &LogRun{
		ID:            id,
		LogID:         init.LogID,
		Description:   init.Description,
		SubmissionURL: init.SubmissionURL,
		MonitoringURL: init.MonitoringURL,
		Protocol:      init.Protocol,
		Operator:      init.Operator,
		State:         init.State,
		StartedAt:     now,
		UpdatedAt:     now,
	}, nil
}

// UpdateLogProgress advances a log_run's next_entry_idx and total_processed.
func (p *ProgressDB) UpdateLogProgress(logID [32]byte, nextEntryIdx, totalProcessed int64) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := p.db.Exec(`
		UPDATE log_runs
		SET next_entry_idx = ?, total_processed = ?, updated_at = ?
		WHERE log_id = ?`, nextEntryIdx, totalProcessed, now, logID[:])
	if err != nil {
		return fmt.Errorf("update log_run progress: %w", err)
	}
	return nil
}

// SetLogTreeSizeAtStart records the tree size observed at run start.
// Idempotent: only writes when the existing value is zero.
func (p *ProgressDB) SetLogTreeSizeAtStart(logID [32]byte, treeSize int64) error {
	_, err := p.db.Exec(`
		UPDATE log_runs
		SET tree_size_at_start = ?
		WHERE log_id = ? AND (tree_size_at_start IS NULL OR tree_size_at_start = 0)`,
		treeSize, logID[:])
	return err
}

// ListLogRuns returns all log_runs rows for monitoring/dashboard use.
func (p *ProgressDB) ListLogRuns() ([]LogRun, error) {
	rows, err := p.db.Query(`
		SELECT id, log_id, description, submission_url, COALESCE(monitoring_url, ''),
		       protocol, operator, state, next_entry_idx, COALESCE(tree_size_at_start, 0),
		       total_processed, started_at, updated_at
		FROM log_runs
		ORDER BY operator, description`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LogRun
	for rows.Next() {
		var r LogRun
		var idBlob []byte
		if err := rows.Scan(&r.ID, &idBlob, &r.Description, &r.SubmissionURL, &r.MonitoringURL,
			&r.Protocol, &r.Operator, &r.State, &r.NextEntryIdx, &r.TreeSizeAtStart,
			&r.TotalProcessed, &r.StartedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		copy(r.LogID[:], idBlob)
		out = append(out, r)
	}
	return out, rows.Err()
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
