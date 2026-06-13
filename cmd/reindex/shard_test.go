package main

import (
	"database/sql"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"testing"

	_ "modernc.org/sqlite"
)

func TestShardsForPrefix(t *testing.T) {
	cases := []struct {
		cidr string
		want int
	}{
		{"203.0.113.0/24", 1},  // finer than /16 -> single shard
		{"203.0.113.0/16", 1},  // exactly /16
		{"10.20.0.0/15", 2},    // spans 10.20 and 10.21
		{"10.20.0.0/14", 4},    // spans 10.20..10.23
		{"10.0.0.0/8", 256},    // octet1 0..255
		{"2001:db8::/32", 1},   // first two bytes fixed
		{"2001:db8::/16", 1},   // exactly the shard prefix
		{"2001:0000::/12", 16}, // low nibble of byte 1 varies
	}
	for _, c := range cases {
		got := len(shardsForPrefix(netip.MustParsePrefix(c.cidr)))
		if got != c.want {
			t.Errorf("shardsForPrefix(%s) = %d shards, want %d", c.cidr, got, c.want)
		}
	}
}

func TestShardIDFamilySeparation(t *testing.T) {
	// A v4 address and a v6 address whose first bytes collide numerically must
	// land in different shards (the family bit keeps them apart).
	v4, _, _ := key16("0.1.0.0") // v4 octets 0,1
	v6, _, _ := key16("0001::")  // v6 bytes 0x00,0x01
	if shardID(v4, 4) == shardID(v6, 6) {
		t.Fatalf("v4 and v6 shards collided: %d", shardID(v4, 4))
	}
}

func TestBuildShardedAndRoute(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "dns.db")
	out := filepath.Join(dir, "rev")

	db, err := sql.Open("sqlite", "file:"+src)
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, `CREATE TABLE dns_records_a (domain TEXT, ttl INTEGER, fetched_at INTEGER, ipv4 TEXT)`)
	mustExec(t, db, `CREATE TABLE dns_records_aaaa (domain TEXT, ttl INTEGER, fetched_at INTEGER, ipv6 TEXT)`)
	mustExec(t, db, `INSERT INTO dns_records_a VALUES
		('a.example', 300, 1, '10.20.0.5'),
		('b.example', 300, 1, '10.20.0.5'),
		('c.example', 300, 1, '10.21.0.9'),
		('d.example', 300, 1, '192.0.2.1')`)
	mustExec(t, db, `INSERT INTO dns_records_aaaa VALUES
		('v6.example', 300, 1, '2001:db8::1')`)
	db.Close()

	if err := buildIPSharded([]string{src, out}); err != nil {
		t.Fatal(err)
	}

	// Expect a shard file per distinct /16 present: 10.20, 10.21, 192.0, v6 2001:0db8.
	wantFiles := []string{"v4_10_20.db", "v4_10_21.db", "v4_192_0.db", "v6_2001.db"}
	for _, f := range wantFiles {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Errorf("expected shard file %s: %v", f, err)
		}
	}
	if _, err := os.Stat(filepath.Join(out, "_stage.db")); err == nil {
		t.Errorf("staging db should have been removed")
	}

	// Route a /24 -> single shard, two domains on 10.20.0.5.
	got := routeCIDR(t, out, "10.20.0.0/24")
	wantSlice(t, got, []string{"a.example", "b.example"})

	// Route a /15 -> two shards (10.20 + 10.21), three domains total.
	got = routeCIDR(t, out, "10.20.0.0/15")
	wantSlice(t, got, []string{"a.example", "b.example", "c.example"})

	// Route the v6 /32 -> the single v6 shard.
	got = routeCIDR(t, out, "2001:db8::/32")
	wantSlice(t, got, []string{"v6.example"})
}

// routeCIDR replicates lookupCIDRSharded's routing but collects results so the
// test can assert on them.
func routeCIDR(t *testing.T, outDir, cidr string) []string {
	t.Helper()
	p := netip.MustParsePrefix(cidr)
	lo, hi := prefixRange(p)
	var out []string
	for _, id := range shardsForPrefix(p) {
		path := filepath.Join(outDir, shardName(id)+".db")
		if _, err := os.Stat(path); err != nil {
			continue
		}
		db, err := sql.Open("sqlite", "file:"+path+"?immutable=1")
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, queryDomains(t, db, `SELECT domain FROM rev_ip WHERE ip BETWEEN ? AND ?`, lo, hi)...)
		db.Close()
	}
	return out
}

// resolveIPShardNames replicates lookupCIDRSharded's base->file resolution so a
// test can assert which shards a CIDR routes to.
func resolveIPShardNames(outDir, cidr string) []string {
	p := netip.MustParsePrefix(cidr)
	lo, hi := prefixRange(p)
	ver := 6
	if p.Addr().Is4() {
		ver = 4
	}
	split := readIPSplit(outDir)
	var names []string
	for _, id := range shardsForPrefix(p) {
		base := shardName(id)
		if split[base] {
			names = append(names, fineNamesForBase(base, id, ver, lo, hi)...)
		} else {
			names = append(names, base)
		}
	}
	return names
}

func TestIPHotShardSplit(t *testing.T) {
	old := gShardBytes // exercise /8 base -> /16 split
	gShardBytes = 1
	defer func() { gShardBytes = old }()
	t.Setenv("REINDEX_IP_SPLIT_MIN", "3")

	dir := t.TempDir()
	src := filepath.Join(dir, "dns.db")
	out := filepath.Join(dir, "rev")
	db, err := sql.Open("sqlite", "file:"+src)
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, `CREATE TABLE dns_records_a (domain TEXT, ttl INTEGER, fetched_at INTEGER, ipv4 TEXT)`)
	mustExec(t, db, `CREATE TABLE dns_records_aaaa (domain TEXT, ttl INTEGER, fetched_at INTEGER, ipv6 TEXT)`)
	// 104/8 is hot (3 rows across second octets 1,2,3 -> split); 8/8 is cold.
	mustExec(t, db, `INSERT INTO dns_records_a VALUES
		('a.example', 300, 1, '104.1.0.1'),
		('b.example', 300, 1, '104.2.0.1'),
		('c.example', 300, 1, '104.3.0.1'),
		('cold.example', 300, 1, '8.8.8.8')`)
	db.Close()

	if err := buildIPSharded([]string{src, out}); err != nil {
		t.Fatal(err)
	}

	// Manifest: 104 split, 8 not.
	split := readIPSplit(out)
	if !split["v4_104"] {
		t.Error("v4_104 (3 rows >= split-min 3) should be split")
	}
	if split["v4_8"] {
		t.Error("v4_8 (1 row) should not be split")
	}

	// Files: hot /8 replaced by /16 sub-shards; cold /8 stays whole.
	for _, f := range []string{"v4_104_1.db", "v4_104_2.db", "v4_104_3.db", "v4_8.db"} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Errorf("expected shard %s: %v", f, err)
		}
	}
	if _, err := os.Stat(filepath.Join(out, "v4_104.db")); err == nil {
		t.Error("v4_104 should be split, not a single /8 shard")
	}

	// Routing: a /16 in the hot /8 hits exactly its sub-shard; the whole /8 hits
	// all three; a /8 query coarser-or-equal still resolves correctly.
	if got := resolveIPShardNames(out, "104.2.0.0/16"); len(got) != 1 || got[0] != "v4_104_2" {
		t.Errorf("104.2.0.0/16 routed to %v, want [v4_104_2]", got)
	}
	whole := resolveIPShardNames(out, "104.0.0.0/8")
	if len(whole) != 256 { // 0..255 second octets enumerated
		t.Errorf("104.0.0.0/8 resolved %d sub-shards, want 256", len(whole))
	}

	// Correctness: the /8 query returns all three domains from the split shards.
	got := map[string]bool{}
	for _, name := range whole {
		path := filepath.Join(out, name+".db")
		if _, err := os.Stat(path); err != nil {
			continue
		}
		sdb, err := sql.Open("sqlite", "file:"+path+"?immutable=1")
		if err != nil {
			t.Fatal(err)
		}
		lo, hi := prefixRange(netip.MustParsePrefix("104.0.0.0/8"))
		for _, d := range queryDomains(t, sdb, `SELECT domain FROM rev_ip WHERE ip BETWEEN ? AND ?`, lo, hi) {
			got[d] = true
		}
		sdb.Close()
	}
	for _, want := range []string{"a.example", "b.example", "c.example"} {
		if !got[want] {
			t.Errorf("missing %s from split /8 query", want)
		}
	}
	if got["cold.example"] {
		t.Error("cold.example (8.8.8.8) should not appear in a 104/8 query")
	}
}

func wantSlice(t *testing.T, got, want []string) {
	t.Helper()
	sort.Strings(got)
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}
