// rawscan is a drop-in alternative to cmd/export that extracts DNS SANs by
// reading SQLite database pages sequentially (raw file I/O) rather than via a
// B-tree cursor. This bypasses fragmentation: a heavily fragmented subjects.db
// that would take days to scan with a cursor is read in under an hour here.
//
// Use this tool when a subjects.db has been written by a bulk merge operation
// that appended large numbers of rows non-contiguously, causing the B-tree
// leaf pages to be scattered across the file. The B-tree cursor follows logical
// row order (lots of seeks); this tool follows physical page order (sequential).
//
// Output format and flags are identical to cmd/export so the tools are
// interchangeable. Rows whose san_domains payload overflows onto SQLite overflow
// pages are silently skipped (uncommon for typical SAN lists; <0.02% observed).
//
// Usage:
//
//	./bin/rawscan [--dir <archive>] [--out <outdir>] [--flush N]
package main

import (
	"bufio"
	"container/heap"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// sanDomainsColIdx is the 0-indexed column position of san_domains in the
// subjects table schema:
//
//	id(0) ca_id(1) serial_number(2) common_name(3) organization(4)
//	state(5) country(6) not_before(7) not_after(8) san_domains(9) ...
const sanDomainsColIdx = 9

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

	var chunks []string
	for i, dbPath := range dbs {
		prefix := filepath.Join(*tmpDir, fmt.Sprintf("chunk_%02d", i))
		log.Printf("[%d/%d] scanning %s", i+1, len(dbs), dbPath)
		parts, err := buildChunks(dbPath, prefix, *flushRows)
		if err != nil {
			log.Fatalf("scan %s: %v", dbPath, err)
		}
		chunks = append(chunks, parts...)
	}

	uniqueOut := filepath.Join(*outDir, "subdomains_unique.txt")
	countAlpha := filepath.Join(*tmpDir, "domains_count_alpha.tsv")
	log.Printf("merging %d chunk files ...", len(chunks))
	n, err := mergeChunks(chunks, uniqueOut, countAlpha)
	if err != nil {
		log.Fatalf("merge: %v", err)
	}
	log.Printf("unique FQDNs: %d", n)

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

// buildChunks scans dbPath using raw page reads, accumulates domain counts,
// and flushes to sorted temp files every flushEvery rows.
func buildChunks(dbPath, prefix string, flushEvery int) ([]string, error) {
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

	err := rawScanSanDomains(dbPath, func(sanDomains string) error {
		for _, raw := range strings.Split(sanDomains, ",") {
			if d := normalize(raw); d != "" {
				counts[d]++
			}
		}
		rowCount++
		if rowCount%flushEvery == 0 {
			log.Printf("  ... %dM rows, flushing part %d (%d unique)",
				rowCount/1_000_000, partIdx, len(counts))
			return flushMap()
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := flushMap(); err != nil {
		return nil, err
	}
	log.Printf("  %d rows → %d part(s)", rowCount, len(parts))
	return parts, nil
}

// rawScanSanDomains reads a SQLite subjects.db sequentially, page by page,
// extracting san_domains (column index 9) from every leaf table B-tree page
// without using a B-tree cursor. Reads at full sequential HDD throughput.
func rawScanSanDomains(dbPath string, fn func(string) error) error {
	f, err := os.Open(dbPath)
	if err != nil {
		return err
	}
	defer f.Close()

	var hdr [100]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return fmt.Errorf("read header: %w", err)
	}
	if string(hdr[:16]) != "SQLite format 3\x00" {
		return fmt.Errorf("%s: not a SQLite database", dbPath)
	}
	rawPS := binary.BigEndian.Uint16(hdr[16:18])
	pageSize := int(rawPS)
	if pageSize == 1 {
		pageSize = 65536
	}

	fi, err := f.Stat()
	if err != nil {
		return err
	}
	nPages := int(fi.Size() / int64(pageSize))

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	r := bufio.NewReaderSize(f, 8<<20) // 8 MB read-ahead
	page := make([]byte, pageSize)

	for pageNum := 1; pageNum <= nPages; pageNum++ {
		if _, err := io.ReadFull(r, page); err != nil {
			break
		}

		// Page 1 has the 100-byte SQLite file header before the B-tree header.
		hdrOff := 0
		if pageNum == 1 {
			hdrOff = 100
		}

		// Only leaf table B-tree pages (0x0D) contain row data.
		if page[hdrOff] != 0x0D {
			continue
		}

		numCells := int(binary.BigEndian.Uint16(page[hdrOff+3 : hdrOff+5]))
		cellArrayBase := hdrOff + 8

		for i := 0; i < numCells; i++ {
			cpOff := cellArrayBase + i*2
			if cpOff+2 > pageSize {
				break
			}
			cellOff := int(binary.BigEndian.Uint16(page[cpOff : cpOff+2]))
			if cellOff <= hdrOff || cellOff >= pageSize {
				continue
			}
			pos := cellOff

			// Skip payload length varint.
			_, n := sqliteVarint(page[pos:])
			if n == 0 {
				continue
			}
			pos += n

			// Skip row ID varint.
			_, n = sqliteVarint(page[pos:])
			if n == 0 {
				continue
			}
			pos += n

			// Payload: record header then data.
			payloadStart := pos
			headerSize, n := sqliteVarint(page[pos:])
			if n == 0 || int(headerSize) > pageSize-payloadStart {
				continue
			}
			pos += n
			headerEnd := payloadStart + int(headerSize)

			// Parse type codes for columns 0..sanDomainsColIdx.
			var typeCodes [sanDomainsColIdx + 1]uint64
			colsParsed := 0
			for pos < headerEnd && colsParsed <= sanDomainsColIdx {
				tc, n := sqliteVarint(page[pos:])
				if n == 0 {
					break
				}
				pos += n
				typeCodes[colsParsed] = tc
				colsParsed++
			}
			if colsParsed < sanDomainsColIdx+1 {
				continue // too few columns — not a subjects row
			}

			// Walk past columns 0..sanDomainsColIdx-1 to reach column 9's data.
			dataOff := headerEnd
			for col := 0; col < sanDomainsColIdx; col++ {
				dataOff += int(sqliteColDataSize(typeCodes[col]))
			}

			tc := typeCodes[sanDomainsColIdx]
			if tc < 13 || tc%2 == 0 {
				continue // NULL or non-TEXT
			}
			textLen := int((tc - 13) / 2)
			if textLen == 0 || dataOff+textLen > pageSize {
				continue // empty or overflows into overflow page — skip
			}

			if err := fn(string(page[dataOff : dataOff+textLen])); err != nil {
				return err
			}
		}
	}
	return nil
}

// sqliteVarint decodes a SQLite variable-length integer.
func sqliteVarint(b []byte) (v uint64, n int) {
	for i := 0; i < 9 && i < len(b); i++ {
		if i == 8 {
			return (v << 8) | uint64(b[i]), 9
		}
		v = (v << 7) | uint64(b[i]&0x7F)
		if b[i]&0x80 == 0 {
			return v, i + 1
		}
	}
	return 0, 0
}

// sqliteColDataSize returns the on-disk byte size for a SQLite serial type code.
func sqliteColDataSize(tc uint64) uint64 {
	switch tc {
	case 0, 8, 9:
		return 0
	case 1:
		return 1
	case 2:
		return 2
	case 3:
		return 3
	case 4:
		return 4
	case 5:
		return 6
	case 6, 7:
		return 8
	}
	if tc >= 12 {
		if tc%2 == 0 {
			return (tc - 12) / 2 // BLOB
		}
		return (tc - 13) / 2 // TEXT
	}
	return 0
}

// ── shared helpers (merge, sort, normalize) ───────────────────────────────────

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
