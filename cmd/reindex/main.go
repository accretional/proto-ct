// Command reindex is a prototype/migration tool that validates the planned
// reverse-index schema changes (R1 and R3 in docs/query-patterns.md) against a
// small snapshot of the bootstrap corpus.
//
// It implements, as a one-shot bulk-sort build (never on the ingestion write
// path):
//
//	R1  build-ip   DNS A/AAAA  -> rev_ip(ip, domain, ver, fetched_at)
//	                indexed on a uniform 16-byte big-endian IP key.
//	R3  build-san  CT subjects -> san_index(san_domain, reg_domain, cert_id, ...)
//	                indexed on san_domain and reg_domain (eTLD+1, PSL).
//
// And the reverse queries those indexes are meant to make cheap:
//
//	lookup-ip    Q7   one IP            -> domains
//	lookup-cidr  Q8   a CIDR / range    -> domains
//	lookup-san   Q5   a domain / eTLD+1 -> certs (SANs at or under it)
//
// R0 (uniform keying) is made concrete here: every IP is stored as the 16-byte
// big-endian form, with IPv4 written as its IPv4-mapped IPv6 address
// (::ffff:a.b.c.d). A single BLOB index then serves both families, and CIDR
// range scans work via BETWEEN because big-endian bytes sort in numeric order.
package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"golang.org/x/net/publicsuffix"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	if os.Getenv("REINDEX_SHARD_BYTES") == "1" {
		gShardBytes = 1
	}
	var err error
	switch os.Args[1] {
	case "build-ip":
		err = buildIP(os.Args[2:])
	case "build-ip-sharded":
		err = buildIPSharded(os.Args[2:])
	case "lookup-cidr-sharded":
		err = lookupCIDRSharded(os.Args[2:])
	case "build-san":
		err = buildSAN(os.Args[2:])
	case "build-san-sharded":
		err = buildSANSharded(os.Args[2:])
	case "lookup-san-sharded":
		err = lookupSANSharded(os.Args[2:])
	case "lookup-ip":
		err = lookupIP(os.Args[2:])
	case "lookup-cidr":
		err = lookupCIDR(os.Args[2:])
	case "lookup-san":
		err = lookupSAN(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "reindex: "+err.Error())
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage:
  reindex build-ip            <src-dns.db> <out-rev.db>
  reindex build-ip-sharded    <src-dns.db> <out-dir>
  reindex build-san           <src-ct.db>  <out-san.db>
  reindex build-san-sharded   <src-ct.db>  <out-dir>
  reindex lookup-ip           <rev.db> <ip>
  reindex lookup-cidr         <rev.db> <cidr>
  reindex lookup-cidr-sharded <out-dir> <cidr>
  reindex lookup-san          <san.db> <domain>
  reindex lookup-san-sharded  <out-dir> <domain>
`)
	os.Exit(2)
}

// ---- shared helpers --------------------------------------------------------

// openRO opens a source DB read-only and immutable so it never contends with a
// live ingestion writer (and so we can read a file that has a stale -wal).
func openRO(path string) (*sql.DB, error) {
	return sql.Open("sqlite", "file:"+path+"?mode=ro&immutable=1")
}

// openBulk opens an output DB tuned for a single-pass bulk-sort build: no
// journal, no fsync, large page cache. These are safe because the build is
// re-runnable from source — a crash just means rebuild.
func openBulk(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(OFF)&_pragma=synchronous(OFF)&_pragma=cache_size(-200000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // single writer; keeps the pragmas on one connection
	return db, nil
}

// key16 returns the canonical 16-byte big-endian key for an address string.
// IPv4 becomes its IPv4-mapped IPv6 form so v4 and v6 share one ordered space.
func key16(s string) ([]byte, int, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil || !addr.IsValid() {
		return nil, 0, false
	}
	b := addr.As16()
	ver := 6
	if addr.Is4() || addr.Is4In6() {
		ver = 4
	}
	return b[:], ver, true
}

// prefixRange returns the inclusive [lo, hi] 16-byte key bounds covering a CIDR.
func prefixRange(p netip.Prefix) (lo, hi []byte) {
	p = p.Masked()
	a := p.Addr().As16()
	bits := p.Bits()
	if p.Addr().Is4() {
		bits += 96 // host bits live in the low 32 of the v4-mapped form
	}
	loArr, hiArr := a, a
	for i := bits; i < 128; i++ {
		hiArr[i/8] |= 1 << (7 - uint(i%8))
	}
	return loArr[:], hiArr[:]
}

// --- /16 partition routing ---------------------------------------------------
//
// Sharding the uniform 16-byte key by its leading /16 would put all of v4 in
// one shard (v4-mapped addresses share the ::ffff: prefix). So the shard id is
// family-aware: v4 by its first two octets, v6 by its first two bytes, with the
// family in a high bit so the two never collide and ORDER BY shard groups them.

const v6ShardBit = 1 << 16

// gShardBytes is the number of leading prefix bytes used to partition the IP
// reverse index: 2 => /16 shards, 1 => /8 shards. Set once in main() from
// REINDEX_SHARD_BYTES (default 2). Tests do not call main(), so they exercise
// the /16 default.
var gShardBytes = 2

// shardPrefixInt extracts the leading shard prefix (without the family bit) from
// a 16-byte key: v4 reads from the mapped octets at offset 12, v6 from offset 0.
func shardPrefixInt(k []byte, ver int) int {
	off := 0
	if ver == 4 {
		off = 12
	}
	v := 0
	for i := 0; i < gShardBytes; i++ {
		v = v<<8 | int(k[off+i])
	}
	return v
}

func shardID(k []byte, ver int) int {
	v := shardPrefixInt(k, ver)
	if ver != 4 {
		v |= v6ShardBit
	}
	return v
}

func shardName(id int) string {
	v6 := id&v6ShardBit != 0
	v := id &^ v6ShardBit
	switch {
	case !v6 && gShardBytes == 1:
		return fmt.Sprintf("v4_%d", v&0xff)
	case !v6:
		return fmt.Sprintf("v4_%d_%d", (v>>8)&0xff, v&0xff)
	case gShardBytes == 1:
		return fmt.Sprintf("v6_%02x", v&0xff)
	default:
		return fmt.Sprintf("v6_%02x%02x", (v>>8)&0xff, v&0xff)
	}
}

// shardsForPrefix returns every shard id whose key space overlaps the CIDR. A
// query coarser than the shard width fans out across many shards; one at or
// finer than the shard width touches exactly one.
func shardsForPrefix(p netip.Prefix) []int {
	p = p.Masked()
	lo, hi := prefixRange(p)
	ver := 6
	if p.Addr().Is4() {
		ver = 4
	}
	loS, hiS := shardPrefixInt(lo, ver), shardPrefixInt(hi, ver)
	var ids []int
	for s := loS; s <= hiS; s++ {
		if ver == 4 {
			ids = append(ids, s)
		} else {
			ids = append(ids, v6ShardBit|s)
		}
	}
	return ids
}

// normFQDN lowercases, strips a trailing dot, and strips a leading "*." wildcard
// label. Returns the cleaned name and whether it was a wildcard.
func normFQDN(s string) (name string, wildcard bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, ".")
	if rest, ok := strings.CutPrefix(s, "*."); ok {
		return rest, true
	}
	return s, false
}

func regDomain(fqdn string) string {
	if e, err := publicsuffix.EffectiveTLDPlusOne(fqdn); err == nil {
		return e
	}
	return "_other"
}

// largeTLD lists public suffixes always bucketed by the first character of the
// registrable label (mirroring EXPORT_PLAN.md's shardKey), regardless of volume.
// REINDEX_SAN_SPLIT_MIN promotes other hot suffixes to the same treatment at
// build time, so this stays conservative (com only).
var largeTLD = map[string]bool{"com": true}

// regSuffix returns the public suffix of a registrable domain (eTLD+1), with the
// edge handling sanShardKey relies on.
func regSuffix(reg string) string {
	if reg == "" || reg == "_other" {
		return "_other"
	}
	s, _ := publicsuffix.PublicSuffix(reg)
	if s == "" || s == reg {
		return reg
	}
	return s
}

// labelBucket returns the char bucket (a-z / 0 / _other) of the registrable
// label — the part of reg just below the public suffix — or "all" if none.
func labelBucket(reg, suffix string) string {
	label := strings.TrimSuffix(reg, "."+suffix)
	if label == "" {
		return "all"
	}
	return firstCharBucket(label)
}

// sanShardKey maps a registrable domain (eTLD+1) to its static SAN-index
// partition (public suffix, bucket); only largeTLD is bucketed here. The build's
// manifest may additionally bucket hot suffixes — see sanQueryShardBase. All
// SANs of a registrable domain share an eTLD+1, so a query for everything
// at/under a domain routes to exactly one file.
func sanShardKey(reg string) (suffix, bucket string) {
	suffix = regSuffix(reg)
	if !largeTLD[suffix] {
		return suffix, "all"
	}
	return suffix, labelBucket(reg, suffix)
}

func sanShardBase(reg string) string {
	suffix, bucket := sanShardKey(reg)
	return "san_" + suffix + "__" + bucket
}

// --- bounded catch-all + hot-shard split (R3) -------------------------------
//
// Per-suffix sharding fragments into a long tail of near-empty files, while a
// few PaaS-on-PSL suffixes make oversized shards. Two thresholds tame both:
//   REINDEX_SAN_DEDICATE_MIN — suffixes below it collapse into bounded
//     _tail__<first-char-of-suffix> catch-alls (0 => every suffix its own shard).
//   REINDEX_SAN_SPLIT_MIN    — suffixes at/above it (plus largeTLD) are split by
//     the first char of the registrable label (0 => only largeTLD is split).
// The dedicated and bucketed sets are persisted in manifest.json so queries
// route identically.

func sanDedicateMin() int64 { return envInt("REINDEX_SAN_DEDICATE_MIN") }
func sanSplitMin() int64    { return envInt("REINDEX_SAN_SPLIT_MIN") }

func envInt(name string) int64 {
	if v, err := strconv.ParseInt(os.Getenv(name), 10, 64); err == nil && v > 0 {
		return v
	}
	return 0
}

func firstCharBucket(s string) string {
	if s == "" {
		return "_other"
	}
	switch c := s[0]; {
	case c >= 'a' && c <= 'z':
		return string(c)
	case c >= '0' && c <= '9':
		return "0"
	default:
		return "_other"
	}
}

func sanShardBaseTail(suffix string) string {
	return "san__tail__" + firstCharBucket(suffix)
}

type sanManifest struct {
	DedicateMin int      `json:"dedicate_min"`
	SplitMin    int      `json:"split_min"`
	Dedicated   []string `json:"dedicated"` // own shard, single "all" bucket
	Bucketed    []string `json:"bucketed"`  // own shard, split by label char
}

func writeManifest(dir string, m sanManifest) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "manifest.json"), b, 0o644)
}

type sanRouting struct {
	dedicated map[string]bool
	bucketed  map[string]bool
}

func readRouting(dir string) (*sanRouting, bool) {
	b, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, false
	}
	var m sanManifest
	if json.Unmarshal(b, &m) != nil {
		return nil, false
	}
	rt := &sanRouting{dedicated: map[string]bool{}, bucketed: map[string]bool{}}
	for _, s := range m.Dedicated {
		rt.dedicated[s] = true
	}
	for _, s := range m.Bucketed {
		rt.bucketed[s] = true
	}
	return rt, true
}

// sanQueryShardBase picks the shard file base for a query domain's registrable
// domain, honoring the manifest (bucketed > dedicated > tail).
func sanQueryShardBase(dir, reg string) string {
	rt, ok := readRouting(dir)
	if !ok {
		return sanShardBase(reg) // no manifest: per-suffix
	}
	suffix := regSuffix(reg)
	switch {
	case rt.bucketed[suffix]:
		return "san_" + suffix + "__" + labelBucket(reg, suffix)
	case rt.dedicated[suffix]:
		return "san_" + suffix + "__all"
	default:
		return sanShardBaseTail(suffix)
	}
}

// assignShards classifies each public suffix into bucketed (own shard, split by
// label char), dedicated (own shard, single "all" bucket), or tail (bounded
// catch-all), sets staged.shard accordingly, and records the dedicated/bucketed
// sets in the manifest so lookups route identically.
func assignShards(stage *sql.DB, count map[string]int64, dedicateMin, splitMin int64, outDir string) error {
	for _, ddl := range []string{
		`CREATE TABLE bucketed (suffix TEXT PRIMARY KEY)`,
		`CREATE TABLE dedicated (suffix TEXT PRIMARY KEY)`,
		`CREATE TABLE tailroute (suffix TEXT PRIMARY KEY, tail TEXT)`,
	} {
		if _, err := stage.Exec(ddl); err != nil {
			return err
		}
	}
	tx, err := stage.Begin()
	if err != nil {
		return err
	}
	bins, err := tx.Prepare(`INSERT INTO bucketed(suffix) VALUES(?)`)
	if err != nil {
		return err
	}
	dins, err := tx.Prepare(`INSERT INTO dedicated(suffix) VALUES(?)`)
	if err != nil {
		return err
	}
	tins, err := tx.Prepare(`INSERT INTO tailroute(suffix, tail) VALUES(?,?)`)
	if err != nil {
		return err
	}
	var bucketedList, dedList []string
	for s, c := range count {
		switch {
		case largeTLD[s] || (splitMin > 0 && c >= splitMin):
			if _, err := bins.Exec(s); err != nil {
				return err
			}
			bucketedList = append(bucketedList, s)
		case dedicateMin == 0 || c >= dedicateMin:
			if _, err := dins.Exec(s); err != nil {
				return err
			}
			dedList = append(dedList, s)
		default:
			if _, err := tins.Exec(s, sanShardBaseTail(s)); err != nil {
				return err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if _, err := stage.Exec(`UPDATE staged SET shard = CASE
		WHEN suffix IN (SELECT suffix FROM bucketed)  THEN 'san_' || suffix || '__' || labelchar
		WHEN suffix IN (SELECT suffix FROM dedicated) THEN 'san_' || suffix || '__all'
		ELSE (SELECT tail FROM tailroute WHERE tailroute.suffix = staged.suffix) END`); err != nil {
		return err
	}
	sort.Strings(bucketedList)
	sort.Strings(dedList)
	return writeManifest(outDir, sanManifest{
		DedicateMin: int(dedicateMin), SplitMin: int(splitMin),
		Dedicated: dedList, Bucketed: bucketedList,
	})
}

// ---- R1: build IP -> domain reverse index ----------------------------------

func buildIP(args []string) error {
	if len(args) != 2 {
		usage()
	}
	src, out := args[0], args[1]
	_ = os.Remove(out)

	in, err := openRO(src)
	if err != nil {
		return err
	}
	defer in.Close()

	// Stage the dup-laden rows in a side file, then stream them sorted into a
	// fresh output so the output only ever holds deduped rows (no free-page
	// bloat from an in-place CTAS). Same sort-then-unique as the sharded build.
	stagePath := out + ".stage"
	_ = os.Remove(stagePath)
	stage, err := openBulk(stagePath)
	if err != nil {
		return err
	}
	defer func() { stage.Close(); os.Remove(stagePath) }()
	if _, err := stage.Exec(`CREATE TABLE staged (ip BLOB, domain TEXT, ver INTEGER, fetched_at INTEGER)`); err != nil {
		return err
	}

	start := time.Now()
	tx, err := stage.Begin()
	if err != nil {
		return err
	}
	ins, err := tx.Prepare(`INSERT INTO staged(ip, domain, ver, fetched_at) VALUES(?,?,?,?)`)
	if err != nil {
		return err
	}
	var rows, skipped int64
	// One pass per address family table; both feed the same uniform key.
	for _, q := range []string{
		`SELECT domain, ipv4, fetched_at FROM dns_records_a`,
		`SELECT domain, ipv6, fetched_at FROM dns_records_aaaa`,
	} {
		r, err := in.Query(q)
		if err != nil {
			// AAAA table may be absent/empty in tiny snapshots; tolerate.
			continue
		}
		for r.Next() {
			var domain, ipstr string
			var fetched sql.NullInt64
			if err := r.Scan(&domain, &ipstr, &fetched); err != nil {
				r.Close()
				return err
			}
			k, ver, ok := key16(ipstr)
			if !ok {
				skipped++
				continue
			}
			if _, err := ins.Exec(k, strings.ToLower(domain), ver, fetched); err != nil {
				r.Close()
				return err
			}
			rows++
		}
		r.Close()
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	loaded := time.Since(start)

	db, err := openBulk(out)
	if err != nil {
		return err
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE rev_ip (ip BLOB NOT NULL, domain TEXT NOT NULL, ver INTEGER NOT NULL, fetched_at INTEGER)`); err != nil {
		return err
	}

	// Stream sorted by (ip,domain) with the freshest row first; collapse
	// consecutive duplicate (ip,domain) pairs, then index (docs §6c).
	dedupStart := time.Now()
	otx, err := db.Begin()
	if err != nil {
		return err
	}
	oins, err := otx.Prepare(`INSERT INTO rev_ip(ip, domain, ver, fetched_at) VALUES(?,?,?,?)`)
	if err != nil {
		return err
	}
	sr, err := stage.Query(`SELECT ip, domain, ver, fetched_at FROM staged ORDER BY ip, domain, fetched_at DESC`)
	if err != nil {
		return err
	}
	var emitted, deduped int64
	var prevIP []byte
	var prevDomain string
	havePrev := false
	for sr.Next() {
		var ip []byte
		var domain string
		var ver int
		var fetched sql.NullInt64
		if err := sr.Scan(&ip, &domain, &ver, &fetched); err != nil {
			sr.Close()
			return err
		}
		if havePrev && domain == prevDomain && bytes.Equal(ip, prevIP) {
			deduped++
			continue
		}
		if _, err := oins.Exec(ip, domain, ver, fetched); err != nil {
			sr.Close()
			return err
		}
		prevIP, prevDomain, havePrev = ip, domain, true
		emitted++
	}
	sr.Close()
	if err := otx.Commit(); err != nil {
		return err
	}
	if _, err := db.Exec(`CREATE INDEX idx_rev_ip ON rev_ip(ip)`); err != nil {
		return err
	}
	dedupIndexed := time.Since(dedupStart)

	fmt.Printf("build-ip: %d rows -> %d after dedup (%d dup pairs, %d unparseable)\n", rows, emitted, deduped, skipped)
	fmt.Printf("  load:        %s\n  dedup+index: %s\n  total:       %s\n", loaded.Round(time.Millisecond), dedupIndexed.Round(time.Millisecond), (loaded + dedupIndexed).Round(time.Millisecond))
	return nil
}

// --- hot-/8 split (R1) -------------------------------------------------------
//
// Base shards are gShardBytes wide (e.g. /8). A base whose row count reaches
// REINDEX_IP_SPLIT_MIN is split one byte finer (e.g. /8 -> /16) by the next
// octet, so a hot /8 (Cloudflare, a busy v6 /8) does not become a multi-GB
// shard. The split set is persisted so CIDR routing opens the right sub-shards.
// This is the IP-side analogue of the SAN catch-all/split tier.

func ipSplitMin() int64 { return envInt("REINDEX_IP_SPLIT_MIN") }

func octetStr(ver, n int) string {
	if ver == 4 {
		return strconv.Itoa(n)
	}
	return fmt.Sprintf("%02x", n)
}

// fineName extends a base shard name by the next byte after the base prefix.
func fineName(base string, k []byte, ver int) string {
	off := 0
	if ver == 4 {
		off = 12
	}
	return base + "_" + octetStr(ver, int(k[off+gShardBytes]))
}

type ipManifest struct {
	SplitMin int      `json:"split_min"`
	Split    []string `json:"split"` // base shard names split one byte finer
}

func writeIPManifest(dir string, m ipManifest) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "manifest.json"), b, 0o644)
}

func readIPSplit(dir string) map[string]bool {
	b, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil
	}
	var m ipManifest
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	set := make(map[string]bool, len(m.Split))
	for _, s := range m.Split {
		set[s] = true
	}
	return set
}

// fineNamesForBase enumerates the finer sub-shard names of a split base shard
// that overlap the query bounds [lo,hi].
func fineNamesForBase(base string, baseID, ver int, lo, hi []byte) []string {
	off := 0
	if ver == 4 {
		off = 12
	}
	loP, hiP := shardPrefixInt(lo, ver), shardPrefixInt(hi, ver)
	bp := baseID &^ v6ShardBit
	nLo, nHi := 0, 255
	if bp == loP {
		nLo = int(lo[off+gShardBytes])
	}
	if bp == hiP {
		nHi = int(hi[off+gShardBytes])
	}
	names := make([]string, 0, nHi-nLo+1)
	for n := nLo; n <= nHi; n++ {
		names = append(names, base+"_"+octetStr(ver, n))
	}
	return names
}

// ---- R1 sharded: /8-partitioned IP -> domain index, hot /8s split finer -----

func buildIPSharded(args []string) error {
	if len(args) != 2 {
		usage()
	}
	src, outDir := args[0], args[1]
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}

	in, err := openRO(src)
	if err != nil {
		return err
	}
	defer in.Close()

	// Stage every row unsorted with its base and (potential) fine shard name,
	// then stream it out in shard order. The ORDER BY is the bulk sort (docs
	// §6a): each shard file is opened once and written contiguously.
	stagePath := filepath.Join(outDir, "_stage.db")
	_ = os.Remove(stagePath)
	stage, err := openBulk(stagePath)
	if err != nil {
		return err
	}
	if _, err := stage.Exec(`CREATE TABLE staged (base TEXT, fine TEXT, shard TEXT, ip BLOB, domain TEXT, ver INTEGER, fetched_at INTEGER)`); err != nil {
		stage.Close()
		return err
	}

	start := time.Now()
	tx, err := stage.Begin()
	if err != nil {
		stage.Close()
		return err
	}
	ins, err := tx.Prepare(`INSERT INTO staged(base, fine, ip, domain, ver, fetched_at) VALUES(?,?,?,?,?,?)`)
	if err != nil {
		stage.Close()
		return err
	}
	var rows, skipped int64
	count := map[string]int64{} // rows per base shard, for the split threshold
	for _, q := range []string{
		`SELECT domain, ipv4, fetched_at FROM dns_records_a`,
		`SELECT domain, ipv6, fetched_at FROM dns_records_aaaa`,
	} {
		r, err := in.Query(q)
		if err != nil {
			continue
		}
		for r.Next() {
			var domain, ipstr string
			var fetched sql.NullInt64
			if err := r.Scan(&domain, &ipstr, &fetched); err != nil {
				r.Close()
				stage.Close()
				return err
			}
			k, ver, ok := key16(ipstr)
			if !ok {
				skipped++
				continue
			}
			base := shardName(shardID(k, ver))
			count[base]++
			if _, err := ins.Exec(base, fineName(base, k, ver), k, strings.ToLower(domain), ver, fetched); err != nil {
				r.Close()
				stage.Close()
				return err
			}
			rows++
		}
		r.Close()
	}
	if err := tx.Commit(); err != nil {
		stage.Close()
		return err
	}

	// Split base shards over the threshold one byte finer; persist the set.
	splitMin := ipSplitMin()
	var splitList []string
	if splitMin > 0 {
		if _, err := stage.Exec(`CREATE TABLE splitbase (base TEXT PRIMARY KEY)`); err != nil {
			stage.Close()
			return err
		}
		stx, err := stage.Begin()
		if err != nil {
			stage.Close()
			return err
		}
		sins, err := stx.Prepare(`INSERT INTO splitbase(base) VALUES(?)`)
		if err != nil {
			stage.Close()
			return err
		}
		for b, c := range count {
			if c >= splitMin {
				if _, err := sins.Exec(b); err != nil {
					stage.Close()
					return err
				}
				splitList = append(splitList, b)
			}
		}
		if err := stx.Commit(); err != nil {
			stage.Close()
			return err
		}
		if _, err := stage.Exec(`UPDATE staged SET shard = CASE WHEN base IN (SELECT base FROM splitbase) THEN fine ELSE base END`); err != nil {
			stage.Close()
			return err
		}
	} else if _, err := stage.Exec(`UPDATE staged SET shard = base`); err != nil {
		stage.Close()
		return err
	}
	sort.Strings(splitList)
	if err := writeIPManifest(outDir, ipManifest{SplitMin: int(splitMin), Split: splitList}); err != nil {
		stage.Close()
		return err
	}
	staged := time.Since(start)

	// Stream in shard order, fanning out one DB file per shard.
	fanStart := time.Now()
	cur := ""
	var (
		curDB  *sql.DB
		curTx  *sql.Tx
		curIns *sql.Stmt
		shards int
	)
	closeShard := func() error {
		if curDB == nil {
			return nil
		}
		if err := curTx.Commit(); err != nil {
			return err
		}
		if _, err := curDB.Exec(`CREATE INDEX idx_rev_ip ON rev_ip(ip)`); err != nil {
			return err
		}
		return curDB.Close()
	}
	openShard := func(name string) error {
		path := filepath.Join(outDir, name+".db")
		_ = os.Remove(path)
		db, err := openBulk(path)
		if err != nil {
			return err
		}
		if _, err := db.Exec(`CREATE TABLE rev_ip (ip BLOB NOT NULL, domain TEXT NOT NULL, ver INTEGER NOT NULL, fetched_at INTEGER)`); err != nil {
			return err
		}
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		st, err := tx.Prepare(`INSERT INTO rev_ip(ip, domain, ver, fetched_at) VALUES(?,?,?,?)`)
		if err != nil {
			return err
		}
		curDB, curTx, curIns = db, tx, st
		shards++
		return nil
	}

	// Sorted by (ip, domain) within each shard, with the freshest row first, so
	// consecutive duplicate (ip,domain) pairs collapse to one in a single pass —
	// sort-then-unique, no random probing (docs §6c).
	sr, err := stage.Query(`SELECT shard, ip, domain, ver, fetched_at FROM staged ORDER BY shard, ip, domain, fetched_at DESC`)
	if err != nil {
		stage.Close()
		return err
	}
	var emitted, deduped int64
	var prevIP []byte
	var prevDomain string
	havePrev := false
	for sr.Next() {
		var shard, domain string
		var ip []byte
		var ver int
		var fetched sql.NullInt64
		if err := sr.Scan(&shard, &ip, &domain, &ver, &fetched); err != nil {
			sr.Close()
			return err
		}
		if shard != cur {
			if err := closeShard(); err != nil {
				sr.Close()
				return err
			}
			if err := openShard(shard); err != nil {
				sr.Close()
				return err
			}
			cur = shard
			havePrev = false
		}
		if havePrev && domain == prevDomain && bytes.Equal(ip, prevIP) {
			deduped++
			continue // same (ip,domain); keep only the first (freshest) row
		}
		if _, err := curIns.Exec(ip, domain, ver, fetched); err != nil {
			sr.Close()
			return err
		}
		prevIP, prevDomain, havePrev = ip, domain, true
		emitted++
	}
	sr.Close()
	if err := closeShard(); err != nil {
		return err
	}
	stage.Close()
	_ = os.Remove(stagePath)
	fan := time.Since(fanStart)

	scheme := fmt.Sprintf("/%d base", gShardBytes*8)
	if splitMin > 0 {
		scheme += fmt.Sprintf(", split-min=%d (%d split)", splitMin, len(splitList))
	}
	fmt.Printf("build-ip-sharded: %d rows -> %d after dedup (%d dup pairs, %d skipped) -> %d shards [%s]\n", rows, emitted, deduped, skipped, shards, scheme)
	fmt.Printf("  stage:  %s\n  fanout: %s\n  total:  %s\n", staged.Round(time.Millisecond), fan.Round(time.Millisecond), (staged + fan).Round(time.Millisecond))
	return nil
}

func lookupCIDRSharded(args []string) error {
	if len(args) != 2 {
		usage()
	}
	outDir := args[0]
	p, err := netip.ParsePrefix(args[1])
	if err != nil {
		return err
	}
	lo, hi := prefixRange(p)
	ver := 6
	if p.Addr().Is4() {
		ver = 4
	}
	split := readIPSplit(outDir)

	// Resolve the base shards overlapping the CIDR to concrete file names: a
	// split base contributes its overlapping fine sub-shards, the rest the base.
	var names []string
	for _, id := range shardsForPrefix(p) {
		base := shardName(id)
		if split[base] {
			names = append(names, fineNamesForBase(base, id, ver, lo, hi)...)
		} else {
			names = append(names, base)
		}
	}

	start := time.Now()
	var found, opened int
	for _, name := range names {
		path := filepath.Join(outDir, name+".db")
		if _, err := os.Stat(path); err != nil {
			continue // no data in this shard
		}
		opened++
		db, err := sql.Open("sqlite", "file:"+path+"?immutable=1")
		if err != nil {
			return err
		}
		r, err := db.Query(`SELECT domain FROM rev_ip WHERE ip BETWEEN ? AND ? ORDER BY ip, domain`, lo, hi)
		if err != nil {
			db.Close()
			return err
		}
		for r.Next() {
			var d string
			if err := r.Scan(&d); err != nil {
				r.Close()
				db.Close()
				return err
			}
			fmt.Println(d)
			found++
		}
		r.Close()
		db.Close()
	}
	fmt.Printf("-- %d domain(s) in %s: %d shard(s) in range, %d held data, in %s\n",
		found, args[1], len(names), opened, time.Since(start).Round(time.Microsecond))
	return nil
}

// ---- R3: build SAN -> cert reverse index -----------------------------------

func buildSAN(args []string) error {
	if len(args) != 2 {
		usage()
	}
	src, out := args[0], args[1]
	_ = os.Remove(out)

	in, err := openRO(src)
	if err != nil {
		return err
	}
	defer in.Close()
	db, err := openBulk(out)
	if err != nil {
		return err
	}
	defer db.Close()

	if _, err := db.Exec(`CREATE TABLE san_index (
		san_domain  TEXT    NOT NULL,
		reg_domain  TEXT    NOT NULL,
		cert_id     INTEGER NOT NULL,
		is_wildcard INTEGER NOT NULL
	)`); err != nil {
		return err
	}

	start := time.Now()
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	ins, err := tx.Prepare(`INSERT INTO san_index(san_domain, reg_domain, cert_id, is_wildcard) VALUES(?,?,?,?)`)
	if err != nil {
		return err
	}

	r, err := in.Query(`SELECT id, san_domains FROM subjects`)
	if err != nil {
		return err
	}
	var certs, sans int64
	for r.Next() {
		var id int64
		var sansCol sql.NullString
		if err := r.Scan(&id, &sansCol); err != nil {
			r.Close()
			return err
		}
		certs++
		if !sansCol.Valid || sansCol.String == "" {
			continue
		}
		for raw := range strings.SplitSeq(sansCol.String, ",") {
			name, wild := normFQDN(raw)
			if name == "" {
				continue
			}
			w := 0
			if wild {
				w = 1
			}
			if _, err := ins.Exec(name, regDomain(name), id, w); err != nil {
				r.Close()
				return err
			}
			sans++
		}
	}
	r.Close()
	if err := tx.Commit(); err != nil {
		return err
	}
	loaded := time.Since(start)

	idxStart := time.Now()
	if _, err := db.Exec(`CREATE INDEX idx_san_domain ON san_index(san_domain)`); err != nil {
		return err
	}
	if _, err := db.Exec(`CREATE INDEX idx_san_reg ON san_index(reg_domain)`); err != nil {
		return err
	}
	indexed := time.Since(idxStart)

	fmt.Printf("build-san: %d certs -> %d SAN rows\n", certs, sans)
	fmt.Printf("  load:  %s\n  index: %s\n  total: %s\n", loaded.Round(time.Millisecond), indexed.Round(time.Millisecond), (loaded + indexed).Round(time.Millisecond))
	return nil
}

// ---- R3 sharded: eTLD+1-partitioned SAN -> cert index ----------------------

func buildSANSharded(args []string) error {
	if len(args) != 2 {
		usage()
	}
	src, outDir := args[0], args[1]
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}

	in, err := openRO(src)
	if err != nil {
		return err
	}
	defer in.Close()

	// Stage unsorted, then stream in shard order so each shard file is written
	// once and contiguously (the §6a bulk sort).
	stagePath := filepath.Join(outDir, "_stage.db")
	_ = os.Remove(stagePath)
	stage, err := openBulk(stagePath)
	if err != nil {
		return err
	}
	if _, err := stage.Exec(`CREATE TABLE staged (suffix TEXT, labelchar TEXT, shard TEXT, san_domain TEXT, reg_domain TEXT, cert_id INTEGER, wild INTEGER)`); err != nil {
		stage.Close()
		return err
	}

	start := time.Now()
	tx, err := stage.Begin()
	if err != nil {
		stage.Close()
		return err
	}
	ins, err := tx.Prepare(`INSERT INTO staged(suffix, labelchar, san_domain, reg_domain, cert_id, wild) VALUES(?,?,?,?,?,?)`)
	if err != nil {
		stage.Close()
		return err
	}
	r, err := in.Query(`SELECT id, san_domains FROM subjects`)
	if err != nil {
		stage.Close()
		return err
	}
	var certs, sans int64
	count := map[string]int64{} // SAN rows per public suffix, for the thresholds
	for r.Next() {
		var id int64
		var sansCol sql.NullString
		if err := r.Scan(&id, &sansCol); err != nil {
			r.Close()
			stage.Close()
			return err
		}
		certs++
		if !sansCol.Valid || sansCol.String == "" {
			continue
		}
		for raw := range strings.SplitSeq(sansCol.String, ",") {
			name, wild := normFQDN(raw)
			if name == "" {
				continue
			}
			reg := regDomain(name)
			suffix := regSuffix(reg)
			count[suffix]++
			w := 0
			if wild {
				w = 1
			}
			// labelchar is staged per row so the assign step can bucket any
			// suffix by registrable label without re-deriving it.
			if _, err := ins.Exec(suffix, labelBucket(reg, suffix), name, reg, id, w); err != nil {
				r.Close()
				stage.Close()
				return err
			}
			sans++
		}
	}
	r.Close()
	if err := tx.Commit(); err != nil {
		stage.Close()
		return err
	}

	// Classify suffixes (bucketed / dedicated / tail) from their counts and set
	// each staged row's final shard; the routing sets go to manifest.json.
	dedicateMin, splitMin := sanDedicateMin(), sanSplitMin()
	if err := assignShards(stage, count, dedicateMin, splitMin, outDir); err != nil {
		stage.Close()
		return err
	}
	staged := time.Since(start)

	fanStart := time.Now()
	cur := ""
	var (
		curDB  *sql.DB
		curTx  *sql.Tx
		curIns *sql.Stmt
		shards int
	)
	closeShard := func() error {
		if curDB == nil {
			return nil
		}
		if err := curTx.Commit(); err != nil {
			return err
		}
		if _, err := curDB.Exec(`CREATE INDEX idx_san_domain ON san_index(san_domain)`); err != nil {
			return err
		}
		if _, err := curDB.Exec(`CREATE INDEX idx_san_reg ON san_index(reg_domain)`); err != nil {
			return err
		}
		return curDB.Close()
	}
	openShard := func(base string) error {
		path := filepath.Join(outDir, base+".db")
		_ = os.Remove(path)
		db, err := openBulk(path)
		if err != nil {
			return err
		}
		if _, err := db.Exec(`CREATE TABLE san_index (san_domain TEXT NOT NULL, reg_domain TEXT NOT NULL, cert_id INTEGER NOT NULL, is_wildcard INTEGER NOT NULL)`); err != nil {
			return err
		}
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		st, err := tx.Prepare(`INSERT INTO san_index(san_domain, reg_domain, cert_id, is_wildcard) VALUES(?,?,?,?)`)
		if err != nil {
			return err
		}
		curDB, curTx, curIns = db, tx, st
		shards++
		return nil
	}

	sr, err := stage.Query(`SELECT shard, san_domain, reg_domain, cert_id, wild FROM staged ORDER BY shard`)
	if err != nil {
		stage.Close()
		return err
	}
	for sr.Next() {
		var shard, san, reg string
		var cert int64
		var wild int
		if err := sr.Scan(&shard, &san, &reg, &cert, &wild); err != nil {
			sr.Close()
			return err
		}
		if shard != cur {
			if err := closeShard(); err != nil {
				sr.Close()
				return err
			}
			if err := openShard(shard); err != nil {
				sr.Close()
				return err
			}
			cur = shard
		}
		if _, err := curIns.Exec(san, reg, cert, wild); err != nil {
			sr.Close()
			return err
		}
	}
	sr.Close()
	if err := closeShard(); err != nil {
		return err
	}
	stage.Close()
	_ = os.Remove(stagePath)
	fan := time.Since(fanStart)

	scheme := "per-suffix eTLD+1"
	if dedicateMin > 0 {
		scheme = fmt.Sprintf("dedicate-min=%d", dedicateMin)
	}
	if splitMin > 0 {
		scheme += fmt.Sprintf(" split-min=%d", splitMin)
	}
	fmt.Printf("build-san-sharded: %d certs -> %d SAN rows -> %d shards [%s]\n", certs, sans, shards, scheme)
	fmt.Printf("  stage:  %s\n  fanout: %s\n  total:  %s\n", staged.Round(time.Millisecond), fan.Round(time.Millisecond), (staged + fan).Round(time.Millisecond))
	return nil
}

func lookupSANSharded(args []string) error {
	if len(args) != 2 {
		usage()
	}
	outDir := args[0]
	name, _ := normFQDN(args[1])
	// The query's own eTLD+1 selects the single shard holding it and anything
	// under it — honoring the catch-all manifest if the index has one.
	base := sanQueryShardBase(outDir, regDomain(name))
	path := filepath.Join(outDir, base+".db")

	start := time.Now()
	if _, err := os.Stat(path); err != nil {
		fmt.Printf("-- 0 SAN/cert pair(s): shard %s absent\n", base)
		return nil
	}
	db, err := sql.Open("sqlite", "file:"+path+"?immutable=1")
	if err != nil {
		return err
	}
	defer db.Close()
	r, err := db.Query(`SELECT DISTINCT san_domain, is_wildcard, cert_id
		FROM san_index WHERE san_domain = ? OR reg_domain = ?
		ORDER BY san_domain, cert_id`, name, name)
	if err != nil {
		return err
	}
	defer r.Close()
	var n int
	for r.Next() {
		var san string
		var wild int
		var cert int64
		if err := r.Scan(&san, &wild, &cert); err != nil {
			return err
		}
		star := ""
		if wild == 1 {
			star = "*."
		}
		fmt.Printf("%s%s\tcert=%d\n", star, san, cert)
		n++
	}
	fmt.Printf("-- %d SAN/cert pair(s) at or under %s via shard %s in %s\n",
		n, name, base, time.Since(start).Round(time.Microsecond))
	return nil
}

// ---- queries ---------------------------------------------------------------

func lookupIP(args []string) error {
	if len(args) != 2 {
		usage()
	}
	db, err := sql.Open("sqlite", "file:"+args[0]+"?immutable=1")
	if err != nil {
		return err
	}
	defer db.Close()
	k, _, ok := key16(args[1])
	if !ok {
		return fmt.Errorf("invalid IP: %q", args[1])
	}
	start := time.Now()
	r, err := db.Query(`SELECT domain FROM rev_ip WHERE ip = ? ORDER BY domain`, k)
	if err != nil {
		return err
	}
	defer r.Close()
	var n int
	for r.Next() {
		var d string
		if err := r.Scan(&d); err != nil {
			return err
		}
		fmt.Println(d)
		n++
	}
	fmt.Printf("-- %d domain(s) for %s in %s\n", n, args[1], time.Since(start).Round(time.Microsecond))
	return nil
}

func lookupCIDR(args []string) error {
	if len(args) != 2 {
		usage()
	}
	p, err := netip.ParsePrefix(args[1])
	if err != nil {
		return err
	}
	db, err := sql.Open("sqlite", "file:"+args[0]+"?immutable=1")
	if err != nil {
		return err
	}
	defer db.Close()
	lo, hi := prefixRange(p)
	start := time.Now()
	r, err := db.Query(`SELECT domain FROM rev_ip WHERE ip BETWEEN ? AND ? ORDER BY ip, domain`, lo, hi)
	if err != nil {
		return err
	}
	defer r.Close()
	var n int
	for r.Next() {
		var d string
		if err := r.Scan(&d); err != nil {
			return err
		}
		fmt.Println(d)
		n++
	}
	fmt.Printf("-- %d domain(s) in %s in %s\n", n, args[1], time.Since(start).Round(time.Microsecond))
	return nil
}

func lookupSAN(args []string) error {
	if len(args) != 2 {
		usage()
	}
	db, err := sql.Open("sqlite", "file:"+args[0]+"?immutable=1")
	if err != nil {
		return err
	}
	defer db.Close()
	name, _ := normFQDN(args[1])
	start := time.Now()
	// Match the exact FQDN OR anything under the same registrable domain.
	r, err := db.Query(`SELECT DISTINCT san_domain, is_wildcard, cert_id
		FROM san_index WHERE san_domain = ? OR reg_domain = ?
		ORDER BY san_domain, cert_id`, name, name)
	if err != nil {
		return err
	}
	defer r.Close()
	var n int
	for r.Next() {
		var san string
		var wild int
		var cert int64
		if err := r.Scan(&san, &wild, &cert); err != nil {
			return err
		}
		star := ""
		if wild == 1 {
			star = "*."
		}
		fmt.Printf("%s%s\tcert=%d\n", star, san, cert)
		n++
	}
	fmt.Printf("-- %d SAN/cert pair(s) at or under %s in %s\n", n, name, time.Since(start).Round(time.Microsecond))
	return nil
}
