package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestSanShardKey(t *testing.T) {
	cases := []struct {
		reg            string
		suffix, bucket string
	}{
		{"example.com", "com", "e"},          // large TLD -> bucket by label[0]
		{"ebay.com", "com", "e"},             // same bucket as example.com
		{"9292.com", "com", "0"},             // digit label -> "0"
		{"example.co.uk", "co.uk", "all"},    // multi-label suffix, not large
		{"azurecontainerapps.io", "io", "all"}, // benign PaaS: io is the suffix
		{"_other", "_other", "all"},          // unparseable fallback
	}
	for _, c := range cases {
		s, b := sanShardKey(c.reg)
		if s != c.suffix || b != c.bucket {
			t.Errorf("sanShardKey(%q) = (%q,%q), want (%q,%q)", c.reg, s, b, c.suffix, c.bucket)
		}
	}
}

func TestColocation(t *testing.T) {
	// A registrable domain and its subdomain must land in the same shard so an
	// at/under query routes to one file.
	if sanShardBase(regDomain("example.com")) != sanShardBase(regDomain("api.example.com")) {
		t.Fatalf("example.com and api.example.com landed in different shards")
	}
}

func TestBuildSanShardedAndRoute(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "ct.db")
	out := filepath.Join(dir, "san")

	db, err := sql.Open("sqlite", "file:"+src)
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, `CREATE TABLE subjects (id INTEGER PRIMARY KEY, san_domains TEXT)`)
	mustExec(t, db, `INSERT INTO subjects(id, san_domains) VALUES
		(1, 'example.com,www.example.com'),
		(2, '*.example.com'),
		(3, 'shop.example.com,example.com'),
		(4, 'unrelated.org'),
		(5, 'ebay.com')`)
	db.Close()

	if err := buildSANSharded([]string{src, out}); err != nil {
		t.Fatal(err)
	}

	// example.com and ebay.com share the com/e shard; unrelated.org is its own.
	for _, f := range []string{"san_com__e.db", "san_org__all.db"} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Errorf("expected shard %s: %v", f, err)
		}
	}
	if _, err := os.Stat(filepath.Join(out, "_stage.db")); err == nil {
		t.Errorf("staging db should have been removed")
	}

	// Route example.com -> the com/e shard, distinct certs 1,2,3 (not 4 or 5).
	shard := filepath.Join(out, "san_com__e.db")
	sdb, err := sql.Open("sqlite", "file:"+shard+"?immutable=1")
	if err != nil {
		t.Fatal(err)
	}
	defer sdb.Close()
	rows, err := sdb.Query(`SELECT DISTINCT cert_id FROM san_index
		WHERE san_domain = ? OR reg_domain = ? ORDER BY cert_id`, "example.com", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		got = append(got, id)
	}
	if len(got) != 3 || got[0] != 1 || got[1] != 2 || got[2] != 3 {
		t.Fatalf("certs under example.com = %v, want [1 2 3]", got)
	}
}

func TestSanCatchAllScheme(t *testing.T) {
	t.Setenv("REINDEX_SAN_DEDICATE_MIN", "100")
	dir := t.TempDir()
	src := filepath.Join(dir, "ct.db")
	out := filepath.Join(dir, "san")

	db, err := sql.Open("sqlite", "file:"+src)
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, `CREATE TABLE subjects (id INTEGER PRIMARY KEY, san_domains TEXT)`)
	mustExec(t, db, `INSERT INTO subjects(id, san_domains) VALUES
		(1, 'example.com,www.example.com'),
		(2, 'foo.org'),
		(3, 'bar.net'),
		(4, 'baz.io')`)
	db.Close()

	if err := buildSANSharded([]string{src, out}); err != nil {
		t.Fatal(err)
	}

	// Manifest: com is bucketed (largeTLD); the low-volume suffixes are tail
	// (neither bucketed nor dedicated).
	rt, ok := readRouting(out)
	if !ok {
		t.Fatal("expected manifest.json")
	}
	if !rt.bucketed["com"] {
		t.Error("com should be bucketed (largeTLD)")
	}
	for _, s := range []string{"org", "net", "io"} {
		if rt.bucketed[s] || rt.dedicated[s] {
			t.Errorf("%s should be in the tail, not bucketed/dedicated", s)
		}
	}

	// Low-volume suffixes collapsed into _tail__<char> files; com kept its own.
	for _, f := range []string{"san__tail__o.db", "san__tail__n.db", "san__tail__i.db", "san_com__e.db"} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Errorf("expected shard %s: %v", f, err)
		}
	}

	// Query routing honors the manifest.
	if got := sanQueryShardBase(out, regDomain("foo.org")); got != "san__tail__o" {
		t.Errorf("foo.org routed to %q, want san__tail__o", got)
	}
	if got := sanQueryShardBase(out, regDomain("api.example.com")); got != "san_com__e" {
		t.Errorf("api.example.com routed to %q, want san_com__e", got)
	}

	// The tail shard actually holds foo.org.
	tdb, err := sql.Open("sqlite", "file:"+filepath.Join(out, "san__tail__o.db")+"?immutable=1")
	if err != nil {
		t.Fatal(err)
	}
	defer tdb.Close()
	var n int
	if err := tdb.QueryRow(`SELECT count(*) FROM san_index WHERE reg_domain='foo.org'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("foo.org rows in tail shard = %d, want 1", n)
	}
}

func TestSanSplitScheme(t *testing.T) {
	// split-min=3 promotes a hot non-largeTLD suffix (io, 4 registrable labels)
	// to label-char bucketing; a low-volume suffix stays in the tail.
	t.Setenv("REINDEX_SAN_DEDICATE_MIN", "2")
	t.Setenv("REINDEX_SAN_SPLIT_MIN", "3")
	dir := t.TempDir()
	src := filepath.Join(dir, "ct.db")
	out := filepath.Join(dir, "san")

	db, err := sql.Open("sqlite", "file:"+src)
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, `CREATE TABLE subjects (id INTEGER PRIMARY KEY, san_domains TEXT)`)
	mustExec(t, db, `INSERT INTO subjects(id, san_domains) VALUES
		(1, 'alpha.io'),
		(2, 'bravo.io'),
		(3, 'charlie.io'),
		(4, 'delta.io'),
		(5, 'lonely.net')`)
	db.Close()

	if err := buildSANSharded([]string{src, out}); err != nil {
		t.Fatal(err)
	}

	rt, ok := readRouting(out)
	if !ok {
		t.Fatal("expected manifest.json")
	}
	if !rt.bucketed["io"] {
		t.Error("io (4 rows >= split-min 3) should be bucketed")
	}
	if rt.bucketed["net"] || rt.dedicated["net"] {
		t.Error("net (1 row) should be in the tail")
	}

	// io split across label-char shards, one per registrable label.
	for _, f := range []string{"san_io__a.db", "san_io__b.db", "san_io__c.db", "san_io__d.db"} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Errorf("expected split shard %s: %v", f, err)
		}
	}
	if _, err := os.Stat(filepath.Join(out, "san_io__all.db")); err == nil {
		t.Error("io should be split, not a single __all shard")
	}

	// Routing follows the split: a query for alpha.io hits san_io__a only.
	if got := sanQueryShardBase(out, regDomain("alpha.io")); got != "san_io__a" {
		t.Errorf("alpha.io routed to %q, want san_io__a", got)
	}
	// Tail buckets by first char of the suffix (net -> n), not the label.
	if got := sanQueryShardBase(out, regDomain("lonely.net")); got != "san__tail__n" {
		t.Errorf("lonely.net routed to %q, want san__tail__n", got)
	}

	// Correctness: alpha.io lands in its split shard.
	adb, err := sql.Open("sqlite", "file:"+filepath.Join(out, "san_io__a.db")+"?immutable=1")
	if err != nil {
		t.Fatal(err)
	}
	defer adb.Close()
	var n int
	if err := adb.QueryRow(`SELECT count(*) FROM san_index WHERE reg_domain='alpha.io'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("alpha.io rows in san_io__a = %d, want 1", n)
	}
}
