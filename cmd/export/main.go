// export aggregates DNS SANs from archived subjects.db files into a sharded,
// DNS-pipeline-ready dataset.
//
// Pipeline:
//
//	Phase 0: for each archive date dir without subjects_export.tsv, scan
//	         subjects.db and write a co-located sorted three-column TSV
//	         (domain, direct_count, wildcard_count). Skipped for dirs that
//	         already have the file, making re-runs incremental.
//
//	Phase 1+2: k-way merge all subjects_export.tsv files; fan-out into
//	           per-eTLD+1 shard files and flat summary files.
//
// Shard layout (under --out/shards/):
//
//	com/{a-z,0,_other}.tsv   — split by first char of SLD (large TLD)
//	<tld>/exports.tsv        — all other TLDs in a single file
//	_other/exports.tsv       — domains with no recognisable public suffix
//
// Summary files (under --out/):
//
//	subdomains_direct.txt        — FQDNs seen as direct SANs, alphabetical
//	subdomains_wildcard_only.txt — FQDNs seen only under wildcards, alphabetical
//	subdomains_counts.tsv        — direct<TAB>wildcard<TAB>domain, desc by direct
//
// If source databases have heavily fragmented B-trees (e.g. after large bulk
// merges), use tools/rawscan to produce subjects_export.tsv for the affected
// date dirs, then run this tool normally — phase 0 skips dirs that already
// have the file.
package main

import (
	"bufio"
	"container/heap"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	_ "modernc.org/sqlite"
	"golang.org/x/net/publicsuffix"
)

var (
	baseDir   = flag.String("dir", "/Volumes/wd_office_2/datasets/CT/", "archive base directory")
	outDir    = flag.String("out", "", "output directory (defaults to base dir)")
	tmpDir    = flag.String("tmp", "", "temp directory for chunk files (defaults to out dir)")
	flushRows = flag.Int("flush", 10_000_000, "flush map to sorted chunk every N rows")
)

// largeTLD lists TLDs whose shard files are split by first char of the SLD
// rather than written to a single exports.tsv. Add a TLD here if its flat
// shard file would exceed ~2 GB.
var largeTLD = map[string]bool{
	"com": true,
}

// ── packed uint64 helpers ─────────────────────────────────────────────────────

func addDirect(m map[string]uint64, d string)   { m[d]++ }
func addWildcard(m map[string]uint64, d string) { m[d] += 1 << 32 }
func directCount(v uint64) uint32               { return uint32(v) }
func wildcardCount(v uint64) uint32             { return uint32(v >> 32) }

// ── main ──────────────────────────────────────────────────────────────────────

func main() {
	flag.Parse()
	if *outDir == "" {
		*outDir = *baseDir
	}
	if *tmpDir == "" {
		*tmpDir = *outDir
	}

	// Phase 0: produce subjects_export.tsv for each date dir that lacks one.
	var exports []string
	err := filepath.WalkDir(*baseDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() != "subjects.db" {
			return nil
		}
		dateDir := filepath.Dir(path)
		exportPath := filepath.Join(dateDir, "subjects_export.tsv")
		if _, statErr := os.Stat(exportPath); statErr == nil {
			log.Printf("phase 0: [skip] %s", filepath.Base(dateDir))
		} else {
			log.Printf("phase 0: scanning %s", path)
			if buildErr := buildDateExport(path, exportPath, *tmpDir, *flushRows); buildErr != nil {
				return fmt.Errorf("build export %s: %w", path, buildErr)
			}
		}
		exports = append(exports, exportPath)
		return nil
	})
	if err != nil {
		log.Fatalf("phase 0: %v", err)
	}
	if len(exports) == 0 {
		log.Fatalf("no subjects.db files found under %s", *baseDir)
	}
	log.Printf("phase 0 complete: %d export file(s)", len(exports))

	// Phase 1+2: merge all per-date exports and fan-out into shards.
	log.Printf("phase 1+2: merging and sharding %d file(s) ...", len(exports))
	if err := mergeAndShard(exports, *outDir, *tmpDir); err != nil {
		log.Fatalf("merge+shard: %v", err)
	}
	log.Printf("done")
}

// ── phase 0: per-date-dir export ─────────────────────────────────────────────

// buildDateExport scans a subjects.db and writes a co-located subjects_export.tsv
// containing domain, direct_count, wildcard_count — sorted by domain.
func buildDateExport(dbPath, exportPath, tmpDirPath string, flushEvery int) error {
	prefix := filepath.Join(tmpDirPath, "p0_"+filepath.Base(filepath.Dir(dbPath)))
	chunks, err := buildChunks(dbPath, prefix, flushEvery)
	if err != nil {
		return err
	}
	defer removeFiles(chunks)
	return kMergeToFile(chunks, exportPath)
}

// buildChunks scans dbPath via SQLite cursor, accumulates domain counts
// (tracking direct vs wildcard appearances separately), and flushes to
// sorted three-column chunk files every flushEvery rows.
func buildChunks(dbPath, prefix string, flushEvery int) ([]string, error) {
	src, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	defer src.Close()
	src.SetMaxOpenConns(1)
	src.Exec(`PRAGMA query_only=ON; PRAGMA cache_size=-262144;`)

	rows, err := src.Query(`SELECT san_domains FROM subjects WHERE san_domains != '' AND san_domains IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var parts []string
	partIdx := 0
	counts := make(map[string]uint64, 1<<21)
	rowCount := 0

	flushMap := func() error {
		if len(counts) == 0 {
			return nil
		}
		path := fmt.Sprintf("%s_p%03d.sorted.tsv", prefix, partIdx)
		partIdx++
		if err := writeSortedChunk(counts, path); err != nil {
			return err
		}
		parts = append(parts, path)
		counts = make(map[string]uint64, 1<<21)
		return nil
	}

	for rows.Next() {
		var sanDomains string
		if err := rows.Scan(&sanDomains); err != nil {
			continue
		}
		for _, raw := range strings.Split(sanDomains, ",") {
			raw = strings.TrimSpace(raw)
			isWild := strings.HasPrefix(raw, "*.")
			if isWild {
				raw = raw[2:]
			}
			if d := normalize(raw); d != "" {
				if isWild {
					addWildcard(counts, d)
				} else {
					addDirect(counts, d)
				}
			}
		}
		rowCount++
		if rowCount%flushEvery == 0 {
			log.Printf("  ... %dM rows, flushing part %d (%d unique)",
				rowCount/1_000_000, partIdx, len(counts))
			if err := flushMap(); err != nil {
				return nil, err
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := flushMap(); err != nil {
		return nil, err
	}
	log.Printf("  %d rows → %d chunk(s)", rowCount, len(parts))
	return parts, nil
}

// ── phase 1+2: merge + shard ─────────────────────────────────────────────────

func mergeAndShard(exports []string, outDir, tmpDirPath string) error {
	shardsDir := filepath.Join(outDir, "shards")
	directOut := filepath.Join(outDir, "subdomains_direct.txt")
	wildOut := filepath.Join(outDir, "subdomains_wildcard_only.txt")
	countAlpha := filepath.Join(tmpDirPath, "domains_count_alpha.tsv")
	countOut := filepath.Join(outDir, "subdomains_counts.tsv")

	df, err := os.Create(directOut)
	if err != nil {
		return err
	}
	defer df.Close()
	dw := bufio.NewWriterSize(df, 1<<20)

	wf, err := os.Create(wildOut)
	if err != nil {
		return err
	}
	defer wf.Close()
	ww := bufio.NewWriterSize(wf, 1<<20)

	cf, err := os.Create(countAlpha)
	if err != nil {
		return err
	}
	defer cf.Close()
	cw := bufio.NewWriterSize(cf, 1<<20)

	type shardWriter struct {
		f *os.File
		w *bufio.Writer
	}
	shardWriters := map[string]*shardWriter{}
	openShard := func(path string) (*shardWriter, error) {
		if sw, ok := shardWriters[path]; ok {
			return sw, nil
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, err
		}
		f, err := os.Create(path)
		if err != nil {
			return nil, err
		}
		sw := &shardWriter{f: f, w: bufio.NewWriterSize(f, 256<<10)}
		shardWriters[path] = sw
		return sw, nil
	}

	var totalDirect, totalWild int64
	mergeErr := kMerge(exports, func(domain string, direct, wildcard uint32) error {
		tld, bucket := shardKey(domain)
		sw, err := openShard(filepath.Join(shardsDir, tld, bucket+".tsv"))
		if err != nil {
			return err
		}
		fmt.Fprintf(sw.w, "%s\t%d\t%d\n", domain, direct, wildcard)

		if direct > 0 {
			dw.WriteString(domain)
			dw.WriteByte('\n')
			totalDirect++
		} else {
			ww.WriteString(domain)
			ww.WriteByte('\n')
			totalWild++
		}
		fmt.Fprintf(cw, "%d\t%d\t%s\n", direct, wildcard, domain)
		return nil
	})

	for _, sw := range shardWriters {
		sw.w.Flush()
		sw.f.Close()
	}
	if mergeErr != nil {
		return mergeErr
	}
	if err := dw.Flush(); err != nil {
		return err
	}
	if err := ww.Flush(); err != nil {
		return err
	}
	if err := cw.Flush(); err != nil {
		return err
	}
	cf.Close()

	log.Printf("unique FQDNs: %d direct, %d wildcard-only", totalDirect, totalWild)
	log.Printf("sorting counts ...")
	cmd := exec.Command("sort", "-t\t", "-k1,1rn", "-o", countOut, countAlpha)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("sort counts: %w", err)
	}
	os.Remove(countAlpha)
	return nil
}

// shardKey returns the TLD directory and bucket filename (without .tsv extension)
// for the given normalized FQDN, using the public suffix list.
func shardKey(domain string) (tld, bucket string) {
	etld1, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return "_other", "exports"
	}
	suffix, _ := publicsuffix.PublicSuffix(domain)
	if suffix == "" {
		return "_other", "exports"
	}
	tld = suffix
	if !largeTLD[tld] {
		return tld, "exports"
	}
	sld := strings.TrimSuffix(etld1, "."+tld)
	if len(sld) == 0 {
		return tld, "exports"
	}
	c := sld[0]
	switch {
	case c >= 'a' && c <= 'z':
		return tld, string([]byte{c})
	case c >= '0' && c <= '9':
		return tld, "0"
	default:
		return tld, "_other"
	}
}

// ── k-way merge ───────────────────────────────────────────────────────────────

// kMerge performs a k-way merge of pre-sorted three-column TSV files, summing
// direct and wildcard counts for identical domain keys, and calls fn for each
// unique domain in sorted order.
func kMerge(inputs []string, fn func(domain string, direct, wildcard uint32) error) error {
	h := &domainHeap{}
	heap.Init(h)
	for _, path := range inputs {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		item := &heapItem{file: f, scanner: bufio.NewScanner(f)}
		item.scanner.Buffer(make([]byte, 1<<20), 1<<20)
		if advance(item) {
			heap.Push(h, item)
		} else {
			f.Close()
		}
	}

	var curDomain string
	var curDirect, curWild uint32

	emit := func() error {
		if curDomain == "" {
			return nil
		}
		return fn(curDomain, curDirect, curWild)
	}

	for h.Len() > 0 {
		item := heap.Pop(h).(*heapItem)
		if item.domain != curDomain {
			if err := emit(); err != nil {
				return err
			}
			curDomain = item.domain
			curDirect = item.direct
			curWild = item.wildcard
		} else {
			curDirect += item.direct
			curWild += item.wildcard
		}
		if advance(item) {
			heap.Push(h, item)
		}
	}
	return emit()
}

// kMergeToFile merges sorted chunk files into a single sorted three-column TSV.
func kMergeToFile(chunks []string, outPath string) error {
	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	w := bufio.NewWriterSize(f, 1<<20)
	mergeErr := kMerge(chunks, func(domain string, direct, wildcard uint32) error {
		_, err := fmt.Fprintf(w, "%s\t%d\t%d\n", domain, direct, wildcard)
		return err
	})
	if flushErr := w.Flush(); flushErr != nil && mergeErr == nil {
		mergeErr = flushErr
	}
	if closeErr := f.Close(); closeErr != nil && mergeErr == nil {
		mergeErr = closeErr
	}
	if mergeErr != nil {
		os.Remove(outPath)
	}
	return mergeErr
}

// ── heap types ───────────────────────────────────────────────────────────────

type heapItem struct {
	domain   string
	direct   uint32
	wildcard uint32
	scanner  *bufio.Scanner
	file     *os.File
}

type domainHeap []*heapItem

func (h domainHeap) Len() int            { return len(h) }
func (h domainHeap) Less(i, j int) bool  { return h[i].domain < h[j].domain }
func (h domainHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *domainHeap) Push(x interface{}) { *h = append(*h, x.(*heapItem)) }
func (h *domainHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

func advance(item *heapItem) bool {
	if !item.scanner.Scan() {
		item.file.Close()
		return false
	}
	line := item.scanner.Text()
	// Format: domain\tdirect\twildcard
	t1 := strings.IndexByte(line, '\t')
	if t1 < 0 {
		return false
	}
	rest := line[t1+1:]
	t2 := strings.IndexByte(rest, '\t')
	if t2 < 0 {
		return false
	}
	item.domain = line[:t1]
	d, _ := strconv.ParseUint(rest[:t2], 10, 32)
	item.direct = uint32(d)
	w, _ := strconv.ParseUint(rest[t2+1:], 10, 32)
	item.wildcard = uint32(w)
	return true
}

// ── chunk I/O ────────────────────────────────────────────────────────────────

// writeSortedChunk sorts domain keys and writes domain\tdirect\twildcard lines.
func writeSortedChunk(counts map[string]uint64, path string) error {
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	w := bufio.NewWriterSize(f, 1<<20)
	for _, k := range keys {
		v := counts[k]
		fmt.Fprintf(w, "%s\t%d\t%d\n", k, directCount(v), wildcardCount(v))
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// ── helpers ──────────────────────────────────────────────────────────────────

func removeFiles(paths []string) {
	for _, p := range paths {
		os.Remove(p)
	}
}

// normalize lowercases and validates a domain string. The caller must strip
// any leading "*." before calling — wildcard handling is the caller's responsibility.
func normalize(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	s = strings.ToLower(s)
	dot := false
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '-' || c == '_':
		case c == '.':
			dot = true
		default:
			return ""
		}
	}
	if !dot || s[0] == '.' || s[len(s)-1] == '.' {
		return ""
	}
	return s
}
