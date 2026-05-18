// export aggregates DNS SANs from archived subjects.db files into:
//   subdomains_unique.txt       — one FQDN per line, alphabetical
//   subdomains_with_count.tsv   — <count>\t<fqdn>, descending by count
//
// Algorithm:
//   Phase 1: for each source DB, stream san_domains via SQLite cursor,
//            accumulate domain counts in a Go map, flush every N rows to a
//            sorted temp file to cap memory use.
//   Phase 2: k-way merge of all sorted temp files, summing counts.
//   Phase 3: sort the merged file by count desc → final output.
//
// If source databases have heavily fragmented B-trees (e.g. after large
// bulk merges), use tools/rawscan instead — it reads pages sequentially
// bypassing the cursor and is orders of magnitude faster in that case.
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
)

var (
	baseDir   = flag.String("dir", "/Volumes/wd_office_2/datasets/CT/", "archive base directory")
	outDir    = flag.String("out", "", "output directory (defaults to base dir)")
	tmpDir    = flag.String("tmp", "", "directory for temp sorted chunk files (defaults to out dir)")
	flushRows = flag.Int("flush", 10_000_000, "flush map to disk every N rows to cap memory use")
)

func main() {
	flag.Parse()
	if *outDir == "" {
		*outDir = *baseDir
	}
	if *tmpDir == "" {
		*tmpDir = *outDir
	}

	var dbs []string
	filepath.WalkDir(*baseDir, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && d.Name() == "subjects.db" {
			dbs = append(dbs, path)
		}
		return nil
	})
	if len(dbs) == 0 {
		log.Fatalf("no subjects.db files found under %s", *baseDir)
	}
	log.Printf("found %d subjects.db file(s)", len(dbs))

	// Phase 1: per-file sorted chunk files.
	var chunks []string
	for i, dbPath := range dbs {
		prefix := filepath.Join(*tmpDir, fmt.Sprintf("chunk_%02d", i))
		log.Printf("[%d/%d] reading %s", i+1, len(dbs), dbPath)
		parts, err := buildChunks(dbPath, prefix, *flushRows)
		if err != nil {
			log.Fatalf("build chunk %s: %v", dbPath, err)
		}
		chunks = append(chunks, parts...)
	}

	// Phase 2: k-way merge → unique list + alpha-ordered count temp file.
	uniqueOut := filepath.Join(*outDir, "subdomains_unique.txt")
	countAlpha := filepath.Join(*tmpDir, "domains_count_alpha.tsv")
	log.Printf("merging %d chunk files ...", len(chunks))
	n, err := mergeChunks(chunks, uniqueOut, countAlpha)
	if err != nil {
		log.Fatalf("merge: %v", err)
	}
	log.Printf("unique FQDNs: %d", n)

	// Phase 3: sort count temp file by count desc → final output.
	countOut := filepath.Join(*outDir, "subdomains_with_count.tsv")
	log.Printf("sorting by count desc ...")
	cmd := exec.Command("sort", "-t\t", "-k1,1rn", "-o", countOut, countAlpha)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("sort counts: %v", err)
	}

	for _, c := range chunks {
		os.Remove(c)
	}
	os.Remove(countAlpha)
	log.Printf("done → %s, %s", uniqueOut, countOut)
}

// buildChunks reads san_domains from dbPath via SQLite cursor, flushing the
// accumulation map to a sorted temp file every flushEvery rows. Returns all
// temp file paths produced.
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
	counts := make(map[string]uint32, 1<<21)
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
		counts = make(map[string]uint32, 1<<21)
		return nil
	}

	for rows.Next() {
		var sanDomains string
		if err := rows.Scan(&sanDomains); err != nil {
			continue
		}
		for _, raw := range strings.Split(sanDomains, ",") {
			if d := normalize(raw); d != "" {
				counts[d]++
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
	log.Printf("  %d rows → %d part(s)", rowCount, len(parts))
	return parts, nil
}

// writeSortedChunk sorts map keys and writes domain\tcount lines to path.
func writeSortedChunk(counts map[string]uint32, path string) error {
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
		fmt.Fprintf(w, "%s\t%d\n", k, counts[k])
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// ── k-way merge ───────────────────────────────────────────────────────────────

type heapItem struct {
	domain  string
	count   uint32
	scanner *bufio.Scanner
	file    *os.File
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
	tab := strings.LastIndexByte(line, '\t')
	if tab < 0 {
		return false
	}
	item.domain = line[:tab]
	n, _ := strconv.ParseUint(line[tab+1:], 10, 32)
	item.count = uint32(n)
	return true
}

func mergeChunks(chunks []string, uniqueOut, countAlpha string) (int64, error) {
	h := &domainHeap{}
	heap.Init(h)
	for _, path := range chunks {
		f, err := os.Open(path)
		if err != nil {
			return 0, err
		}
		item := &heapItem{file: f, scanner: bufio.NewScanner(f)}
		item.scanner.Buffer(make([]byte, 1<<20), 1<<20)
		if advance(item) {
			heap.Push(h, item)
		} else {
			f.Close()
		}
	}

	uf, err := os.Create(uniqueOut)
	if err != nil {
		return 0, err
	}
	defer uf.Close()
	uw := bufio.NewWriterSize(uf, 1<<20)

	cf, err := os.Create(countAlpha)
	if err != nil {
		return 0, err
	}
	defer cf.Close()
	cw := bufio.NewWriterSize(cf, 1<<20)

	var n int64
	var curDomain string
	var curCount uint32

	emit := func() {
		if curDomain == "" {
			return
		}
		uw.WriteString(curDomain)
		uw.WriteByte('\n')
		fmt.Fprintf(cw, "%d\t%s\n", curCount, curDomain)
		n++
	}

	for h.Len() > 0 {
		item := heap.Pop(h).(*heapItem)
		if item.domain != curDomain {
			emit()
			curDomain = item.domain
			curCount = item.count
		} else {
			curCount += item.count
		}
		if advance(item) {
			heap.Push(h, item)
		}
	}
	emit()

	if err := uw.Flush(); err != nil {
		return 0, err
	}
	return n, cw.Flush()
}

// normalize lowercases, strips leading "*.", and validates the domain.
func normalize(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	s = strings.ToLower(s)
	s = strings.TrimPrefix(s, "*.")
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
