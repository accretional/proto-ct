package main

import (
	"database/sql"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

const (
	maxOpenDBs  = 128
	txBatchSize = 500
	flushPeriod = 5 * time.Second

	schemaDDL = `
CREATE TABLE IF NOT EXISTS dns_records (
    domain      TEXT    NOT NULL,
    record_type TEXT    NOT NULL,
    ttl_seconds INTEGER NOT NULL,
    rdata       TEXT    NOT NULL,
    truncated   INTEGER NOT NULL DEFAULT 0,
    fetched_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_domain ON dns_records(domain);
CREATE TABLE IF NOT EXISTS fetch_log (
    domain     TEXT PRIMARY KEY,
    status     TEXT NOT NULL,
    fetched_at INTEGER NOT NULL
);`
)

// dbName maps a shard bucket to its DNS database filename.
// The "exports" bucket name is inherited from the CT export pipeline's
// shard file naming; it is replaced here to reflect the DB content.
func dbName(bucket string) string {
	if bucket == "exports" {
		return "records.db"
	}
	return bucket + ".db"
}

// ── DB pool ──────────────────────────────────────────────────────────────────

type dbEntry struct {
	db       *sql.DB
	pending  []resultItem
	lastUsed time.Time
}

type dbPool struct {
	entries    map[shardKey]*dbEntry
	stagingDir string
	maxRdata   int
}

func newDBPool(stagingDir string, maxRdata int) *dbPool {
	return &dbPool{
		entries:    make(map[shardKey]*dbEntry, maxOpenDBs+1),
		stagingDir: stagingDir,
		maxRdata:   maxRdata,
	}
}

func (p *dbPool) stagingPath(k shardKey) string {
	return filepath.Join(p.stagingDir, k.tld, dbName(k.bucket))
}

func (p *dbPool) get(k shardKey) (*dbEntry, error) {
	if e, ok := p.entries[k]; ok {
		e.lastUsed = time.Now()
		return e, nil
	}
	if len(p.entries) >= maxOpenDBs {
		if err := p.evictLRU(); err != nil {
			log.Printf("evict lru: %v", err)
		}
	}
	path := p.stagingPath(k)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA cache_size=-65536; PRAGMA busy_timeout=5000;`); err != nil {
		db.Close()
		return nil, fmt.Errorf("pragma %s: %w", path, err)
	}
	if _, err := db.Exec(schemaDDL); err != nil {
		db.Close()
		return nil, fmt.Errorf("schema %s: %w", path, err)
	}
	e := &dbEntry{db: db, lastUsed: time.Now()}
	p.entries[k] = e
	return e, nil
}

func (p *dbPool) evictLRU() error {
	var (
		lruKey   shardKey
		lruTime  time.Time
		hasEntry bool
	)
	for k, e := range p.entries {
		if !hasEntry || e.lastUsed.Before(lruTime) {
			lruKey = k
			lruTime = e.lastUsed
			hasEntry = true
		}
	}
	if !hasEntry {
		return nil
	}
	if err := p.flush(lruKey); err != nil {
		return err
	}
	p.entries[lruKey].db.Close()
	delete(p.entries, lruKey)
	return nil
}

// flush writes all pending results for shard k in a single transaction.
// INSERT OR IGNORE into fetch_log ensures idempotency across re-runs.
func (p *dbPool) flush(k shardKey) error {
	e, ok := p.entries[k]
	if !ok || len(e.pending) == 0 {
		return nil
	}

	tx, err := e.db.Begin()
	if err != nil {
		return fmt.Errorf("begin %s: %w", k, err)
	}

	logStmt, err := tx.Prepare(`INSERT OR IGNORE INTO fetch_log (domain, status, fetched_at) VALUES (?, ?, ?)`)
	if err != nil {
		tx.Rollback()
		return err
	}
	recStmt, err := tx.Prepare(`INSERT INTO dns_records (domain, record_type, ttl_seconds, rdata, truncated, fetched_at) VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		tx.Rollback()
		return err
	}

	for _, item := range e.pending {
		res, err := logStmt.Exec(item.domain, item.status, item.fetchedAt)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("fetch_log %s: %w", item.domain, err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			continue
		}
		for _, rec := range item.records {
			rdata := rec.rdata
			truncated := 0
			if len(rdata) > p.maxRdata {
				rdata = rdata[:p.maxRdata]
				truncated = 1
			}
			if _, err := recStmt.Exec(item.domain, rec.recordType, rec.ttl, rdata, truncated, item.fetchedAt); err != nil {
				tx.Rollback()
				return fmt.Errorf("dns_records %s %s: %w", item.domain, rec.recordType, err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit %s: %w", k, err)
	}
	e.pending = e.pending[:0]
	return nil
}

func (p *dbPool) write(item resultItem) {
	e, err := p.get(item.shard)
	if err != nil {
		log.Printf("open db %s: %v", item.shard, err)
		return
	}
	e.pending = append(e.pending, item)
	e.lastUsed = time.Now()
	if len(e.pending) >= txBatchSize {
		if err := p.flush(item.shard); err != nil {
			log.Printf("flush %s: %v", item.shard, err)
		}
	}
}

func (p *dbPool) flushAll() {
	for k := range p.entries {
		if err := p.flush(k); err != nil {
			log.Printf("flush %s: %v", k, err)
		}
	}
}

func (p *dbPool) closeAll() {
	for k, e := range p.entries {
		p.flush(k)
		e.db.Close()
		delete(p.entries, k)
	}
}

// finalizeAll flushes, closes, and moves every staged DB to finalDir,
// preserving the tld/name structure. Only called on clean completion.
func (p *dbPool) finalizeAll(finalDir string) error {
	var firstErr error
	for k, e := range p.entries {
		if err := p.flush(k); err != nil {
			log.Printf("finalize flush %s: %v", k, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		// Checkpoint WAL into the main db file before moving, so no
		// orphaned -wal/-shm files are left behind when we rename.
		e.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
		e.db.Close()
		delete(p.entries, k)

		src := p.stagingPath(k)
		// Remove empty WAL/shm files left after checkpoint.
		os.Remove(src + "-wal")
		os.Remove(src + "-shm")
		dst := filepath.Join(finalDir, k.tld, dbName(k.bucket))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			log.Printf("finalize mkdir %s: %v", dst, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if err := os.Rename(src, dst); err != nil {
			// Cross-filesystem: fall back to copy + delete.
			if err2 := copyFile(src, dst); err2 != nil {
				log.Printf("finalize copy %s: %v", k, err2)
				if firstErr == nil {
					firstErr = err2
				}
				continue
			}
			os.Remove(src)
		}
		log.Printf("finalized: %s → %s", src, dst)
	}
	// Clean up empty staging subdirs.
	_ = removeEmptyDirs(p.stagingDir)
	return firstErr
}

func copyFile(src, dst string) error {
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

func removeEmptyDirs(root string) error {
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() || path == root {
			return err
		}
		entries, _ := os.ReadDir(path)
		if len(entries) == 0 {
			os.Remove(path)
		}
		return nil
	})
}

// ── writer goroutine ─────────────────────────────────────────────────────────

// runWriter drains resultCh into the DB pool, flushing periodically.
// It flushes pending writes on channel close but does NOT close or move
// the DBs — the caller owns that decision (finalize on clean exit,
// closeAll on interrupt).
func runWriter(resultCh <-chan resultItem, pool *dbPool) {
	ticker := time.NewTicker(flushPeriod)
	defer ticker.Stop()

	for {
		select {
		case item, ok := <-resultCh:
			if !ok {
				pool.flushAll()
				return
			}
			pool.write(item)
		case <-ticker.C:
			pool.flushAll()
		}
	}
}
