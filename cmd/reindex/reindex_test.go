package main

import (
	"bytes"
	"database/sql"
	"net/netip"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestKey16AndOrdering(t *testing.T) {
	k, ver, ok := key16("1.2.3.4")
	if !ok || ver != 4 {
		t.Fatalf("key16(1.2.3.4) ok=%v ver=%d", ok, ver)
	}
	want := netip.MustParseAddr("1.2.3.4").As16()
	if !bytes.Equal(k, want[:]) {
		t.Fatalf("key16 mismatch: %x != %x", k, want)
	}
	// v4-mapped form must keep the ::ffff: marker so families share an order.
	if k[10] != 0xff || k[11] != 0xff {
		t.Fatalf("expected v4-mapped marker, got %x", k)
	}
	// An in-range address must sort between the /24 bounds.
	lo, hi := prefixRange(netip.MustParsePrefix("1.2.3.0/24"))
	mid, _, _ := key16("1.2.3.4")
	if bytes.Compare(lo, mid) > 0 || bytes.Compare(mid, hi) > 0 {
		t.Fatalf("1.2.3.4 not within 1.2.3.0/24 bounds")
	}
	// Just outside the /24 must fall outside.
	out, _, _ := key16("1.2.4.0")
	if bytes.Compare(out, hi) <= 0 {
		t.Fatalf("1.2.4.0 should be above 1.2.3.0/24 hi bound")
	}
}

func TestPrefixRangeV6(t *testing.T) {
	lo, hi := prefixRange(netip.MustParsePrefix("2001:db8::/32"))
	in, _, _ := key16("2001:db8:dead:beef::1")
	if bytes.Compare(lo, in) > 0 || bytes.Compare(in, hi) > 0 {
		t.Fatalf("address not within 2001:db8::/32 bounds")
	}
	outside, _, _ := key16("2001:db9::1")
	if bytes.Compare(outside, hi) <= 0 {
		t.Fatalf("2001:db9::1 should be above the /32 hi bound")
	}
}

func TestNormFQDN(t *testing.T) {
	cases := []struct {
		in   string
		name string
		wild bool
	}{
		{"*.Example.COM.", "example.com", true},
		{"  API.Example.com ", "api.example.com", false},
		{"*.foo.bar.co.uk", "foo.bar.co.uk", true},
	}
	for _, c := range cases {
		n, w := normFQDN(c.in)
		if n != c.name || w != c.wild {
			t.Errorf("normFQDN(%q) = (%q,%v), want (%q,%v)", c.in, n, w, c.name, c.wild)
		}
	}
}

// makeDNS builds a minimal source DNS DB matching the real per-type schema.
func makeDNS(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mustExec(t, db, `CREATE TABLE dns_records_a (domain TEXT, ttl INTEGER, fetched_at INTEGER, ipv4 TEXT)`)
	mustExec(t, db, `CREATE TABLE dns_records_aaaa (domain TEXT, ttl INTEGER, fetched_at INTEGER, ipv6 TEXT)`)
	mustExec(t, db, `INSERT INTO dns_records_a VALUES
		('a.example.com', 300, 1000, '203.0.113.7'),
		('b.example.com', 300, 1000, '203.0.113.7'),
		('c.example.com', 300, 1000, '203.0.113.200'),
		('far.example.net', 300, 1000, '198.51.100.1')`)
	mustExec(t, db, `INSERT INTO dns_records_aaaa VALUES
		('v6.example.com', 300, 1000, '2001:db8::1')`)
}

func makeCT(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mustExec(t, db, `CREATE TABLE subjects (id INTEGER PRIMARY KEY, san_domains TEXT)`)
	mustExec(t, db, `INSERT INTO subjects(id, san_domains) VALUES
		(1, 'example.com,www.example.com'),
		(2, '*.example.com'),
		(3, 'shop.example.com,example.com'),
		(4, 'unrelated.org')`)
}

func mustExec(t *testing.T, db *sql.DB, q string) {
	t.Helper()
	if _, err := db.Exec(q); err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}

func TestBuildIPAndReverseQueries(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "dns.db")
	out := filepath.Join(dir, "rev.db")
	makeDNS(t, src)
	if err := buildIP([]string{src, out}); err != nil {
		t.Fatal(err)
	}

	db, err := sql.Open("sqlite", "file:"+out+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Q7: exact IP -> two domains sharing 203.0.113.7.
	got := queryDomains(t, db, `SELECT domain FROM rev_ip WHERE ip = ? ORDER BY domain`, key(t, "203.0.113.7"))
	wantEq(t, got, []string{"a.example.com", "b.example.com"})

	// Q8: CIDR 203.0.113.0/24 -> all three .113.x hosts, not the .100.1 host.
	lo, hi := prefixRange(netip.MustParsePrefix("203.0.113.0/24"))
	got = queryDomains(t, db, `SELECT domain FROM rev_ip WHERE ip BETWEEN ? AND ? ORDER BY domain`, lo, hi)
	wantEq(t, got, []string{"a.example.com", "b.example.com", "c.example.com"})

	// v6 row survives the uniform key and is found by its own /32.
	lo6, hi6 := prefixRange(netip.MustParsePrefix("2001:db8::/32"))
	got = queryDomains(t, db, `SELECT domain FROM rev_ip WHERE ip BETWEEN ? AND ? ORDER BY domain`, lo6, hi6)
	wantEq(t, got, []string{"v6.example.com"})
}

func TestBuildSANAndReverseQuery(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "ct.db")
	out := filepath.Join(dir, "san.db")
	makeCT(t, src)
	if err := buildSAN([]string{src, out}); err != nil {
		t.Fatal(err)
	}

	db, err := sql.Open("sqlite", "file:"+out+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Q5/Q12: everything at or under example.com -> certs 1,2,3 (not 4).
	rows, err := db.Query(`SELECT DISTINCT cert_id FROM san_index
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

	// The wildcard SAN must be recorded as such.
	var wild int
	if err := db.QueryRow(`SELECT is_wildcard FROM san_index WHERE cert_id = 2`).Scan(&wild); err != nil {
		t.Fatal(err)
	}
	if wild != 1 {
		t.Fatalf("cert 2 san should be wildcard")
	}
}

func key(t *testing.T, s string) []byte {
	t.Helper()
	k, _, ok := key16(s)
	if !ok {
		t.Fatalf("key16(%q) failed", s)
	}
	return k
}

func queryDomains(t *testing.T, db *sql.DB, q string, args ...any) []string {
	t.Helper()
	rows, err := db.Query(q, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			t.Fatal(err)
		}
		out = append(out, d)
	}
	return out
}

func wantEq(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}
