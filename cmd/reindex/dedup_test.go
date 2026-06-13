package main

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

// makeDupDNS writes a source where (1.1.1.1, a.example) appears three times
// (refetches at different fetched_at) plus a distinct (1.1.1.1, b.example).
func makeDupDNS(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mustExec(t, db, `CREATE TABLE dns_records_a (domain TEXT, ttl INTEGER, fetched_at INTEGER, ipv4 TEXT)`)
	mustExec(t, db, `CREATE TABLE dns_records_aaaa (domain TEXT, ttl INTEGER, fetched_at INTEGER, ipv6 TEXT)`)
	mustExec(t, db, `INSERT INTO dns_records_a VALUES
		('a.example', 300, 100, '1.1.1.1'),
		('a.example', 300, 200, '1.1.1.1'),
		('a.example', 300, 150, '1.1.1.1'),
		('b.example', 300, 100, '1.1.1.1')`)
}

func assertDedup(t *testing.T, dbPath string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+dbPath+"?immutable=1")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	var total int
	if err := db.QueryRow(`SELECT count(*) FROM rev_ip`).Scan(&total); err != nil {
		t.Fatal(err)
	}
	if total != 2 {
		t.Fatalf("total rows = %d, want 2 (one per distinct ip,domain)", total)
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM rev_ip WHERE domain='a.example'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("a.example rows = %d, want 1", n)
	}
	var fa int64
	if err := db.QueryRow(`SELECT fetched_at FROM rev_ip WHERE domain='a.example'`).Scan(&fa); err != nil {
		t.Fatal(err)
	}
	if fa != 200 {
		t.Fatalf("a.example fetched_at = %d, want 200 (most recent kept)", fa)
	}
}

func TestBuildIPDedup(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "dns.db")
	out := filepath.Join(dir, "rev.db")
	makeDupDNS(t, src)
	if err := buildIP([]string{src, out}); err != nil {
		t.Fatal(err)
	}
	assertDedup(t, out)
}

func TestBuildIPShardedDedup(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "dns.db")
	out := filepath.Join(dir, "rev")
	makeDupDNS(t, src)
	if err := buildIPSharded([]string{src, out}); err != nil {
		t.Fatal(err)
	}
	// 1.1.1.1 -> /16 shard v4_1_1; dedup happens within the shard.
	assertDedup(t, filepath.Join(out, "v4_1_1.db"))
}
