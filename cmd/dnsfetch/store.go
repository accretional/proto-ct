package main

import (
	"database/sql"
	"fmt"
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

// ── DB pool ──────────────────────────────────────────────────────────────────

type dbEntry struct {
	db       *sql.DB
	pending  []resultItem
	lastUsed time.Time
}

type dbPool struct {
	entries  map[shardKey]*dbEntry
	outDir   string
	maxRdata int
}

func newDBPool(outDir string, maxRdata int) *dbPool {
	return &dbPool{
		entries:  make(map[shardKey]*dbEntry, maxOpenDBs+1),
		outDir:   outDir,
		maxRdata: maxRdata,
	}
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
	path := filepath.Join(p.outDir, k.tld, k.bucket+".db")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA cache_size=-65536;`); err != nil {
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
			continue // already recorded on a previous run
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

// ── writer goroutine ─────────────────────────────────────────────────────────

// runWriter drains resultCh, batching writes per shard DB. Flushes all open
// DBs every flushPeriod and on channel close.
func runWriter(resultCh <-chan resultItem, outDir string, maxRdata int) {
	pool := newDBPool(outDir, maxRdata)
	ticker := time.NewTicker(flushPeriod)
	defer ticker.Stop()

	for {
		select {
		case item, ok := <-resultCh:
			if !ok {
				pool.flushAll()
				pool.closeAll()
				return
			}
			pool.write(item)
		case <-ticker.C:
			pool.flushAll()
		}
	}
}
