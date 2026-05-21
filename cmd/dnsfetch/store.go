package main

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/accretional/proto-domain/proto/domainpb"
	_ "modernc.org/sqlite"
)

const (
	maxOpenDBs  = 128
	txBatchSize = 500
	flushPeriod = 5 * time.Second
)

// schemaDDL is the per-shard SQLite schema: one fetch_log + 19
// per-record-type tables + a UNION-ALL view (dns_records) for
// cross-type queries. Per-type tables expose proto-faithful columns;
// the view's value column is a presentation-form rendering for ad-hoc
// SQL.
const schemaDDL = `
CREATE TABLE IF NOT EXISTS fetch_log (
    domain     TEXT PRIMARY KEY,
    status     TEXT NOT NULL,
    fetched_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS dns_records_a (
    domain TEXT NOT NULL, ttl INTEGER NOT NULL, fetched_at INTEGER NOT NULL,
    ipv4 TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_a_domain ON dns_records_a(domain);

CREATE TABLE IF NOT EXISTS dns_records_aaaa (
    domain TEXT NOT NULL, ttl INTEGER NOT NULL, fetched_at INTEGER NOT NULL,
    ipv6 TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_aaaa_domain ON dns_records_aaaa(domain);

CREATE TABLE IF NOT EXISTS dns_records_cname (
    domain TEXT NOT NULL, ttl INTEGER NOT NULL, fetched_at INTEGER NOT NULL,
    target TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cname_domain ON dns_records_cname(domain);

CREATE TABLE IF NOT EXISTS dns_records_dname (
    domain TEXT NOT NULL, ttl INTEGER NOT NULL, fetched_at INTEGER NOT NULL,
    target TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dname_domain ON dns_records_dname(domain);

CREATE TABLE IF NOT EXISTS dns_records_ns (
    domain TEXT NOT NULL, ttl INTEGER NOT NULL, fetched_at INTEGER NOT NULL,
    host TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ns_domain ON dns_records_ns(domain);

CREATE TABLE IF NOT EXISTS dns_records_mx (
    domain TEXT NOT NULL, ttl INTEGER NOT NULL, fetched_at INTEGER NOT NULL,
    pref INTEGER NOT NULL, host TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mx_domain ON dns_records_mx(domain);

CREATE TABLE IF NOT EXISTS dns_records_txt (
    domain TEXT NOT NULL, ttl INTEGER NOT NULL, fetched_at INTEGER NOT NULL,
    value TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_txt_domain ON dns_records_txt(domain);

CREATE TABLE IF NOT EXISTS dns_records_soa (
    domain TEXT NOT NULL, ttl INTEGER NOT NULL, fetched_at INTEGER NOT NULL,
    ns TEXT NOT NULL, mbox TEXT NOT NULL,
    serial INTEGER NOT NULL, refresh INTEGER NOT NULL, retry INTEGER NOT NULL,
    expire INTEGER NOT NULL, min_ttl INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_soa_domain ON dns_records_soa(domain);

CREATE TABLE IF NOT EXISTS dns_records_loc (
    domain TEXT NOT NULL, ttl INTEGER NOT NULL, fetched_at INTEGER NOT NULL,
    version INTEGER NOT NULL, size INTEGER NOT NULL,
    horiz_pre INTEGER NOT NULL, vert_pre INTEGER NOT NULL,
    latitude INTEGER NOT NULL, longitude INTEGER NOT NULL, altitude INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_loc_domain ON dns_records_loc(domain);

CREATE TABLE IF NOT EXISTS dns_records_hinfo (
    domain TEXT NOT NULL, ttl INTEGER NOT NULL, fetched_at INTEGER NOT NULL,
    cpu TEXT NOT NULL, os TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_hinfo_domain ON dns_records_hinfo(domain);

CREATE TABLE IF NOT EXISTS dns_records_rp (
    domain TEXT NOT NULL, ttl INTEGER NOT NULL, fetched_at INTEGER NOT NULL,
    mbox TEXT NOT NULL, txt TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rp_domain ON dns_records_rp(domain);

CREATE TABLE IF NOT EXISTS dns_records_afsdb (
    domain TEXT NOT NULL, ttl INTEGER NOT NULL, fetched_at INTEGER NOT NULL,
    subtype INTEGER NOT NULL, hostname TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_afsdb_domain ON dns_records_afsdb(domain);

-- "order" is a SQLite reserved word; the column is named "ord".
CREATE TABLE IF NOT EXISTS dns_records_naptr (
    domain TEXT NOT NULL, ttl INTEGER NOT NULL, fetched_at INTEGER NOT NULL,
    ord INTEGER NOT NULL, preference INTEGER NOT NULL,
    flags TEXT NOT NULL, service TEXT NOT NULL,
    regexp TEXT NOT NULL, replacement TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_naptr_domain ON dns_records_naptr(domain);

CREATE TABLE IF NOT EXISTS dns_records_kx (
    domain TEXT NOT NULL, ttl INTEGER NOT NULL, fetched_at INTEGER NOT NULL,
    preference INTEGER NOT NULL, exchanger TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_kx_domain ON dns_records_kx(domain);

CREATE TABLE IF NOT EXISTS dns_records_sshfp (
    domain TEXT NOT NULL, ttl INTEGER NOT NULL, fetched_at INTEGER NOT NULL,
    algorithm INTEGER NOT NULL, fp_type INTEGER NOT NULL,
    fingerprint TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sshfp_domain ON dns_records_sshfp(domain);

CREATE TABLE IF NOT EXISTS dns_records_svcb (
    domain TEXT NOT NULL, ttl INTEGER NOT NULL, fetched_at INTEGER NOT NULL,
    priority INTEGER NOT NULL, target_name TEXT NOT NULL, params TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_svcb_domain ON dns_records_svcb(domain);

CREATE TABLE IF NOT EXISTS dns_records_https (
    domain TEXT NOT NULL, ttl INTEGER NOT NULL, fetched_at INTEGER NOT NULL,
    priority INTEGER NOT NULL, target_name TEXT NOT NULL, params TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_https_domain ON dns_records_https(domain);

CREATE TABLE IF NOT EXISTS dns_records_caa (
    domain TEXT NOT NULL, ttl INTEGER NOT NULL, fetched_at INTEGER NOT NULL,
    flags INTEGER NOT NULL, tag TEXT NOT NULL, value TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_caa_domain ON dns_records_caa(domain);

CREATE TABLE IF NOT EXISTS dns_records_uri (
    domain TEXT NOT NULL, ttl INTEGER NOT NULL, fetched_at INTEGER NOT NULL,
    priority INTEGER NOT NULL, weight INTEGER NOT NULL, target TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_uri_domain ON dns_records_uri(domain);

CREATE VIEW IF NOT EXISTS dns_records AS
    SELECT domain, 'A' AS type, ttl, fetched_at, ipv4 AS value FROM dns_records_a
    UNION ALL SELECT domain, 'AAAA', ttl, fetched_at, ipv6 FROM dns_records_aaaa
    UNION ALL SELECT domain, 'CNAME', ttl, fetched_at, target FROM dns_records_cname
    UNION ALL SELECT domain, 'DNAME', ttl, fetched_at, target FROM dns_records_dname
    UNION ALL SELECT domain, 'NS', ttl, fetched_at, host FROM dns_records_ns
    UNION ALL SELECT domain, 'MX', ttl, fetched_at, pref || ' ' || host FROM dns_records_mx
    UNION ALL SELECT domain, 'TXT', ttl, fetched_at, value FROM dns_records_txt
    UNION ALL SELECT domain, 'SOA', ttl, fetched_at,
        ns || ' ' || mbox || ' ' || serial || ' ' || refresh || ' ' || retry || ' ' || expire || ' ' || min_ttl
        FROM dns_records_soa
    UNION ALL SELECT domain, 'LOC', ttl, fetched_at,
        latitude || ' ' || longitude || ' ' || altitude FROM dns_records_loc
    UNION ALL SELECT domain, 'HINFO', ttl, fetched_at, cpu || ' ' || os FROM dns_records_hinfo
    UNION ALL SELECT domain, 'RP', ttl, fetched_at, mbox || ' ' || txt FROM dns_records_rp
    UNION ALL SELECT domain, 'AFSDB', ttl, fetched_at, subtype || ' ' || hostname FROM dns_records_afsdb
    UNION ALL SELECT domain, 'NAPTR', ttl, fetched_at,
        ord || ' ' || preference || ' ' || flags || ' ' || service || ' ' || regexp || ' ' || replacement
        FROM dns_records_naptr
    UNION ALL SELECT domain, 'KX', ttl, fetched_at, preference || ' ' || exchanger FROM dns_records_kx
    UNION ALL SELECT domain, 'SSHFP', ttl, fetched_at,
        algorithm || ' ' || fp_type || ' ' || fingerprint FROM dns_records_sshfp
    UNION ALL SELECT domain, 'SVCB', ttl, fetched_at,
        priority || ' ' || target_name || ' ' || params FROM dns_records_svcb
    UNION ALL SELECT domain, 'HTTPS', ttl, fetched_at,
        priority || ' ' || target_name || ' ' || params FROM dns_records_https
    UNION ALL SELECT domain, 'CAA', ttl, fetched_at,
        flags || ' ' || tag || ' ' || value FROM dns_records_caa
    UNION ALL SELECT domain, 'URI', ttl, fetched_at,
        priority || ' ' || weight || ' ' || target FROM dns_records_uri;
`

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
}

func newDBPool(stagingDir string) *dbPool {
	return &dbPool{
		entries:    make(map[shardKey]*dbEntry, maxOpenDBs+1),
		stagingDir: stagingDir,
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
// INSERT OR IGNORE into fetch_log ensures idempotency across re-runs:
// any domain already in fetch_log skips its records here.
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
			if err := insertRecord(tx, item.domain, item.fetchedAt, rec); err != nil {
				tx.Rollback()
				return fmt.Errorf("insert %s %s: %w", item.domain, rec.GetType(), err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit %s: %w", k, err)
	}
	e.pending = e.pending[:0]
	return nil
}

// insertRecord dispatches one DNSRecord into its per-type table. The
// switch is exhaustive over proto's body oneof — adding a new record
// type means adding (1) the proto body, (2) the table in schemaDDL, and
// (3) a case here.
func insertRecord(tx *sql.Tx, domain string, fetchedAt int64, rec *domainpb.DNSRecord) error {
	ttl := rec.GetTtlSeconds()
	switch b := rec.GetBody().(type) {
	case *domainpb.DNSRecord_A:
		_, err := tx.Exec(`INSERT INTO dns_records_a (domain, ttl, fetched_at, ipv4) VALUES (?, ?, ?, ?)`,
			domain, ttl, fetchedAt, net.IP(b.A.GetIpv4()).String())
		return err
	case *domainpb.DNSRecord_Aaaa:
		_, err := tx.Exec(`INSERT INTO dns_records_aaaa (domain, ttl, fetched_at, ipv6) VALUES (?, ?, ?, ?)`,
			domain, ttl, fetchedAt, net.IP(b.Aaaa.GetIpv6()).String())
		return err
	case *domainpb.DNSRecord_Cname:
		_, err := tx.Exec(`INSERT INTO dns_records_cname (domain, ttl, fetched_at, target) VALUES (?, ?, ?, ?)`,
			domain, ttl, fetchedAt, b.Cname.GetTarget())
		return err
	case *domainpb.DNSRecord_Dname:
		_, err := tx.Exec(`INSERT INTO dns_records_dname (domain, ttl, fetched_at, target) VALUES (?, ?, ?, ?)`,
			domain, ttl, fetchedAt, b.Dname.GetTarget())
		return err
	case *domainpb.DNSRecord_Ns:
		_, err := tx.Exec(`INSERT INTO dns_records_ns (domain, ttl, fetched_at, host) VALUES (?, ?, ?, ?)`,
			domain, ttl, fetchedAt, b.Ns.GetHost())
		return err
	case *domainpb.DNSRecord_Mx:
		_, err := tx.Exec(`INSERT INTO dns_records_mx (domain, ttl, fetched_at, pref, host) VALUES (?, ?, ?, ?, ?)`,
			domain, ttl, fetchedAt, b.Mx.GetPref(), b.Mx.GetHost())
		return err
	case *domainpb.DNSRecord_Txt:
		_, err := tx.Exec(`INSERT INTO dns_records_txt (domain, ttl, fetched_at, value) VALUES (?, ?, ?, ?)`,
			domain, ttl, fetchedAt, strings.Join(b.Txt.GetStrings(), ""))
		return err
	case *domainpb.DNSRecord_Soa:
		s := b.Soa
		_, err := tx.Exec(`INSERT INTO dns_records_soa (domain, ttl, fetched_at, ns, mbox, serial, refresh, retry, expire, min_ttl) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			domain, ttl, fetchedAt, s.GetNs(), s.GetMbox(), s.GetSerial(), s.GetRefresh(), s.GetRetry(), s.GetExpire(), s.GetMinTtl())
		return err
	case *domainpb.DNSRecord_Loc:
		l := b.Loc
		_, err := tx.Exec(`INSERT INTO dns_records_loc (domain, ttl, fetched_at, version, size, horiz_pre, vert_pre, latitude, longitude, altitude) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			domain, ttl, fetchedAt, l.GetVersion(), l.GetSize(), l.GetHorizPre(), l.GetVertPre(),
			l.GetLatitude(), l.GetLongitude(), l.GetAltitude())
		return err
	case *domainpb.DNSRecord_Hinfo:
		_, err := tx.Exec(`INSERT INTO dns_records_hinfo (domain, ttl, fetched_at, cpu, os) VALUES (?, ?, ?, ?, ?)`,
			domain, ttl, fetchedAt, b.Hinfo.GetCpu(), b.Hinfo.GetOs())
		return err
	case *domainpb.DNSRecord_Rp:
		_, err := tx.Exec(`INSERT INTO dns_records_rp (domain, ttl, fetched_at, mbox, txt) VALUES (?, ?, ?, ?, ?)`,
			domain, ttl, fetchedAt, b.Rp.GetMbox(), b.Rp.GetTxt())
		return err
	case *domainpb.DNSRecord_Afsdb:
		_, err := tx.Exec(`INSERT INTO dns_records_afsdb (domain, ttl, fetched_at, subtype, hostname) VALUES (?, ?, ?, ?, ?)`,
			domain, ttl, fetchedAt, b.Afsdb.GetSubtype(), b.Afsdb.GetHostname())
		return err
	case *domainpb.DNSRecord_Naptr:
		n := b.Naptr
		_, err := tx.Exec(`INSERT INTO dns_records_naptr (domain, ttl, fetched_at, ord, preference, flags, service, regexp, replacement) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			domain, ttl, fetchedAt, n.GetOrder(), n.GetPreference(), n.GetFlags(), n.GetService(), n.GetRegexp(), n.GetReplacement())
		return err
	case *domainpb.DNSRecord_Kx:
		_, err := tx.Exec(`INSERT INTO dns_records_kx (domain, ttl, fetched_at, preference, exchanger) VALUES (?, ?, ?, ?, ?)`,
			domain, ttl, fetchedAt, b.Kx.GetPreference(), b.Kx.GetExchanger())
		return err
	case *domainpb.DNSRecord_Sshfp:
		s := b.Sshfp
		_, err := tx.Exec(`INSERT INTO dns_records_sshfp (domain, ttl, fetched_at, algorithm, fp_type, fingerprint) VALUES (?, ?, ?, ?, ?, ?)`,
			domain, ttl, fetchedAt, s.GetAlgorithm(), s.GetFpType(), hex.EncodeToString(s.GetFingerprint()))
		return err
	case *domainpb.DNSRecord_Svcb:
		s := b.Svcb
		_, err := tx.Exec(`INSERT INTO dns_records_svcb (domain, ttl, fetched_at, priority, target_name, params) VALUES (?, ?, ?, ?, ?, ?)`,
			domain, ttl, fetchedAt, s.GetPriority(), s.GetTargetName(), svcbParamsText(s.GetParams()))
		return err
	case *domainpb.DNSRecord_Https:
		h := b.Https
		_, err := tx.Exec(`INSERT INTO dns_records_https (domain, ttl, fetched_at, priority, target_name, params) VALUES (?, ?, ?, ?, ?, ?)`,
			domain, ttl, fetchedAt, h.GetPriority(), h.GetTargetName(), svcbParamsText(h.GetParams()))
		return err
	case *domainpb.DNSRecord_Caa:
		_, err := tx.Exec(`INSERT INTO dns_records_caa (domain, ttl, fetched_at, flags, tag, value) VALUES (?, ?, ?, ?, ?, ?)`,
			domain, ttl, fetchedAt, b.Caa.GetFlags(), b.Caa.GetTag(), b.Caa.GetValue())
		return err
	case *domainpb.DNSRecord_Uri:
		_, err := tx.Exec(`INSERT INTO dns_records_uri (domain, ttl, fetched_at, priority, weight, target) VALUES (?, ?, ?, ?, ?, ?)`,
			domain, ttl, fetchedAt, b.Uri.GetPriority(), b.Uri.GetWeight(), b.Uri.GetTarget())
		return err
	default:
		// Body is nil or a type we don't yet store. Skip silently —
		// the server has its own list of supported types.
		return nil
	}
}

// svcbParamsText renders SVCB/HTTPS params as space-separated key=hex
// pairs (e.g. "1=026833 4=681084e5"). Matches the wire-faithful
// rendering the resolver used pre-typed-bodies; downstream consumers
// can parse with strings.Split + strings.SplitN.
func svcbParamsText(params []*domainpb.SvcbParam) string {
	if len(params) == 0 {
		return ""
	}
	var b strings.Builder
	for i, p := range params {
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%d=%s", p.GetKey(), hex.EncodeToString(p.GetValue()))
	}
	return b.String()
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
