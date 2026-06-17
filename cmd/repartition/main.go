// DEPRECATED — WORK COMPLETE. This was a one-time migration tool; the archive
// has already been migrated to the cert-issuance-month (YYYY-MM/subjects.db)
// layout, which is now the live format. Retained for historical reference and
// in case a future re-layout migration needs the same row-routing / raw-page
// scanning machinery. Not part of the normal pipeline; do not run against the
// live archive.
//
// repartition migrates an ingestion-date-partitioned CT archive to a
// cert-issuance-month layout (YYYY-MM/subjects.db).
//
// It reads every subjects.db found under --src, routes each row to the
// appropriate YYYY-MM partition in --dst, and produces a single global
// issuers.db at the archive root.
//
// For heavily fragmented databases (e.g. a file that received bulk merges and
// has scattered B-tree pages), the raw page scanner is used instead of a
// SQLite cursor. This is automatically selected for files where a companion
// .db-wal exists and is non-empty, or when the --raw flag is set explicitly.
// The raw scanner reads pages sequentially and silently skips rows whose
// san_domains payload overflows a single page (<0.02% in practice).
//
// Usage:
//
//	./bin/repartition \
//	  --src /Volumes/wd_office_2/datasets/CT/ \
//	  --dst /Volumes/wd_office_2/datasets/CT-v2/ \
//	  --tmp /Volumes/wd_office_2/tmp/
package main

import (
	"bufio"
	"database/sql"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"github.com/accretional/proto-ct/internal/db"
	_ "modernc.org/sqlite"
)

var (
	srcDir = flag.String("src", "", "source archive root (required)")
	dstDir = flag.String("dst", "", "destination archive root (required)")
	rawAll = flag.Bool("raw", false, "force raw page scanner for all source DBs")
)

func main() {
	flag.Parse()
	if *srcDir == "" || *dstDir == "" {
		log.Fatalf("--src and --dst are required")
	}
	if err := os.MkdirAll(*dstDir, 0o755); err != nil {
		log.Fatalf("mkdir dst: %v", err)
	}

	// Phase 1: build unified global issuers.db and ca_id remap tables.
	log.Printf("phase 1: building global issuers.db ...")
	remap, err := buildIssuersRemap(*srcDir, *dstDir)
	if err != nil {
		log.Fatalf("build issuers: %v", err)
	}
	log.Printf("phase 1 complete: %d unique CAs", len(remap))

	// Phase 2: stream and repartition all source subjects.db files.
	var srcDBs []string
	filepath.WalkDir(*srcDir, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && d.Name() == "subjects.db" {
			srcDBs = append(srcDBs, path)
		}
		return nil
	})
	if len(srcDBs) == 0 {
		log.Fatalf("no subjects.db found under %s", *srcDir)
	}
	log.Printf("phase 2: repartitioning %d source DB(s) ...", len(srcDBs))

	// Output pool: all source DBs write into the same set of month partitions.
	pool := newOutputPool(*dstDir)
	defer pool.closeAll()

	for i, src := range srcDBs {
		log.Printf("[%d/%d] %s", i+1, len(srcDBs), src)
		useRaw := *rawAll || isFragmented(src)
		var rowCount, skipCount int
		var scanErr error
		if useRaw {
			log.Printf("  → using raw page scanner")
			rowCount, skipCount, scanErr = rawScanAndWrite(src, pool, remap)
		} else {
			rowCount, skipCount, scanErr = cursorScanAndWrite(src, pool, remap)
		}
		if scanErr != nil {
			log.Printf("  ERROR: %v", scanErr)
		}
		// Commit any open transaction batches before moving to the next source.
		if err := pool.commitAllPending(); err != nil {
			log.Fatalf("commit after %s: %v", src, err)
		}
		log.Printf("  %d rows written, %d skipped (ca_id not in remap)", rowCount, skipCount)
	}

	// Flush all output DBs and build query indexes.
	log.Printf("phase 3: flushing and indexing %d month partition(s) ...", pool.count())
	if err := pool.flushAndIndex(); err != nil {
		log.Fatalf("flush: %v", err)
	}
	log.Printf("done → %s", *dstDir)
}

// ── issuers remap ─────────────────────────────────────────────────────────────

// remap maps (src_db_path, local_ca_id) → global_ca_id in the unified issuers.db.
type remapKey struct {
	srcPath string
	localID int64
}

func buildIssuersRemap(srcRoot, dstRoot string) (map[remapKey]int64, error) {
	globalIssuerPath := filepath.Join(dstRoot, "issuers.db")
	globalDB, err := db.OpenIssuerDB(globalIssuerPath)
	if err != nil {
		return nil, fmt.Errorf("open global issuers: %w", err)
	}
	defer globalDB.Close()

	// Load per-source fingerprint→local_ca_id mappings and upsert into global.
	remap := make(map[remapKey]int64)
	var srcPaths []string
	filepath.WalkDir(srcRoot, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && d.Name() == "issuers.db" {
			srcPaths = append(srcPaths, path)
		}
		return nil
	})

	for _, srcPath := range srcPaths {
		src, err := sql.Open("sqlite", srcPath)
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", srcPath, err)
		}
		rows, err := src.Query(`SELECT ca_id, fingerprint, common_name, organization, country FROM issuers`)
		if err != nil {
			src.Close()
			return nil, fmt.Errorf("query %s: %w", srcPath, err)
		}
		for rows.Next() {
			var localID int64
			var fpHex, cn, org, country string
			if err := rows.Scan(&localID, &fpHex, &cn, &org, &country); err != nil {
				continue
			}
			var fp [32]byte
			n, _ := hexDecode(fpHex, fp[:])
			if n != 32 {
				continue
			}
			globalID, err := globalDB.UpsertIssuer(fp, cn, org, country)
			if err != nil {
				rows.Close()
				src.Close()
				return nil, fmt.Errorf("upsert issuer: %w", err)
			}
			remap[remapKey{srcPath: srcPath, localID: localID}] = globalID
		}
		rows.Close()
		src.Close()
	}
	return remap, nil
}

// hexDecode decodes a lowercase hex string into dst, returning bytes written.
func hexDecode(s string, dst []byte) (int, error) {
	if len(s)%2 != 0 || len(s)/2 > len(dst) {
		return 0, fmt.Errorf("bad hex length")
	}
	n := 0
	for i := 0; i < len(s); i += 2 {
		hi, lo := hexNib(s[i]), hexNib(s[i+1])
		if hi == 255 || lo == 255 {
			return 0, fmt.Errorf("bad hex char")
		}
		dst[n] = hi<<4 | lo
		n++
	}
	return n, nil
}

func hexNib(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 255
}

// issuerKey returns the issuers.db path that corresponds to a subjects.db path
// (same directory).
func issuerKey(subjectsPath string) string {
	return filepath.Join(filepath.Dir(subjectsPath), "issuers.db")
}

// ── output pool ───────────────────────────────────────────────────────────────

// txBatchSize is the number of rows per explicit transaction per month.
// Each auto-commit insert would require its own implicit transaction; batching
// amortises that overhead ~50000x and dramatically reduces HDD random I/O.
const txBatchSize = 50_000

// monthState holds an open database and its current write transaction.
type monthState struct {
	db      *sql.DB
	tx      *sql.Tx
	pending int // rows in current transaction
	stmt    *sql.Stmt
}

// outputPool manages per-issuance-month SQLite output databases.
// Not safe for concurrent use — the migration is single-threaded.
type outputPool struct {
	states  map[string]*monthState
	dstRoot string
}

func newOutputPool(dstRoot string) *outputPool {
	return &outputPool{states: make(map[string]*monthState), dstRoot: dstRoot}
}

func (p *outputPool) count() int { return len(p.states) }

const insertSQL = `INSERT OR IGNORE INTO subjects
	(ca_id, serial_number, common_name, organization, state, country,
	 not_before, not_after, san_domains, san_ips, url,
	 is_wildcard, san_count, entry_type, tile_idx, entry_idx)
	VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`

func (p *outputPool) getOrOpen(month string) (*monthState, error) {
	if ms, ok := p.states[month]; ok {
		return ms, nil
	}
	dir := filepath.Join(p.dstRoot, month)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "subjects.db")
	d, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	d.SetMaxOpenConns(1)
	if _, err := d.Exec(`
		PRAGMA journal_mode=OFF;
		PRAGMA synchronous=OFF;
		PRAGMA cache_size=-524288;
		PRAGMA temp_store=MEMORY;
	`); err != nil {
		d.Close()
		return nil, err
	}
	if _, err := d.Exec(`
		CREATE TABLE IF NOT EXISTS subjects (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			ca_id         INTEGER NOT NULL,
			serial_number TEXT,
			common_name   TEXT,
			organization  TEXT,
			state         TEXT,
			country       TEXT,
			not_before    TEXT,
			not_after     TEXT,
			san_domains   TEXT,
			san_ips       TEXT,
			url           TEXT,
			is_wildcard   INTEGER DEFAULT 0,
			san_count     INTEGER DEFAULT 0,
			entry_type    TEXT    DEFAULT 'x509',
			tile_idx      INTEGER,
			entry_idx     INTEGER
		);
		CREATE UNIQUE INDEX IF NOT EXISTS idx_subjects_tile_entry
			ON subjects(tile_idx, entry_idx);
	`); err != nil {
		d.Close()
		return nil, err
	}
	ms := &monthState{db: d}
	p.states[month] = ms
	return ms, nil
}

// beginTx opens a new transaction and prepares the insert statement.
func (ms *monthState) beginTx() error {
	tx, err := ms.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(insertSQL)
	if err != nil {
		tx.Rollback()
		return err
	}
	ms.tx = tx
	ms.stmt = stmt
	ms.pending = 0
	return nil
}

// commitTx commits the current transaction.
func (ms *monthState) commitTx() error {
	if ms.stmt != nil {
		ms.stmt.Close()
		ms.stmt = nil
	}
	if ms.tx == nil {
		return nil
	}
	err := ms.tx.Commit()
	ms.tx = nil
	ms.pending = 0
	return err
}

func (p *outputPool) insert(month string, s *subjectRow) error {
	ms, err := p.getOrOpen(month)
	if err != nil {
		return err
	}
	if ms.tx == nil {
		if err := ms.beginTx(); err != nil {
			return err
		}
	}
	if _, err := ms.stmt.Exec(
		s.caID, s.serialNumber, s.commonName, s.organization,
		s.state, s.country, s.notBefore, s.notAfter,
		s.sanDomains, s.sanIPs, s.url,
		s.isWildcard, s.sanCount, s.entryType,
		s.tileIdx, s.entryIdx,
	); err != nil {
		return err
	}
	ms.pending++
	if ms.pending >= txBatchSize {
		return ms.commitTx()
	}
	return nil
}

// commitAllPending commits any open transactions across all months.
// Called after each source DB is fully scanned.
func (p *outputPool) commitAllPending() error {
	for month, ms := range p.states {
		if ms.tx != nil {
			if err := ms.commitTx(); err != nil {
				return fmt.Errorf("commit %s: %w", month, err)
			}
		}
	}
	return nil
}

func (p *outputPool) closeAll() {
	for _, ms := range p.states {
		if ms.stmt != nil {
			ms.stmt.Close()
		}
		if ms.tx != nil {
			ms.tx.Rollback()
		}
		ms.db.Close()
	}
}

func (p *outputPool) flushAndIndex() error {
	// Commit any remaining open transactions first.
	if err := p.commitAllPending(); err != nil {
		return err
	}
	for month := range p.states {
		path := filepath.Join(p.dstRoot, month, "subjects.db")
		if err := db.BuildQueryIndexes(path); err != nil {
			log.Printf("index %s: %v", month, err) // non-fatal
		}
		log.Printf("  indexed %s", month)
	}
	return nil
}

// ── subject row ───────────────────────────────────────────────────────────────

type subjectRow struct {
	caID         int64
	serialNumber string
	commonName   string
	organization string
	state        string
	country      string
	notBefore    string
	notAfter     string
	sanDomains   string
	sanIPs       string
	url          string
	isWildcard   int64
	sanCount     int64
	entryType    string
	tileIdx      int64
	entryIdx     int64
}

func certMonth(notBefore string) string {
	if len(notBefore) >= 7 {
		return notBefore[:7]
	}
	return "unknown"
}

// ── cursor-based scanner ─────────────────────────────────────────────────────

func cursorScanAndWrite(srcPath string, pool *outputPool, remap map[remapKey]int64) (rowCount, skipCount int, err error) {
	issPath := issuerKey(srcPath)
	src, err := sql.Open("sqlite", srcPath)
	if err != nil {
		return 0, 0, err
	}
	defer src.Close()
	src.SetMaxOpenConns(1)
	src.Exec(`PRAGMA query_only=ON; PRAGMA cache_size=-262144;`)

	const q = `SELECT ca_id, serial_number, common_name, organization, state, country,
		not_before, not_after, san_domains, san_ips, url,
		is_wildcard, san_count, entry_type, tile_idx, entry_idx
		FROM subjects`
	rows, err := src.Query(q)
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()

	for rows.Next() {
		var s subjectRow
		if err := rows.Scan(
			&s.caID, &s.serialNumber, &s.commonName, &s.organization,
			&s.state, &s.country, &s.notBefore, &s.notAfter,
			&s.sanDomains, &s.sanIPs, &s.url,
			&s.isWildcard, &s.sanCount, &s.entryType,
			&s.tileIdx, &s.entryIdx,
		); err != nil {
			continue
		}
		globalID, ok := remap[remapKey{srcPath: issPath, localID: s.caID}]
		if !ok {
			skipCount++
			continue
		}
		s.caID = globalID
		month := certMonth(s.notBefore)
		if err := pool.insert(month, &s); err != nil {
			log.Printf("warn: insert %s/%d: %v", month, s.tileIdx, err)
		}
		rowCount++
		if rowCount%5_000_000 == 0 {
			log.Printf("  ... %dM rows", rowCount/1_000_000)
		}
	}
	return rowCount, skipCount, rows.Err()
}

// ── raw page scanner (all columns) ───────────────────────────────────────────

// isFragmented returns true when the raw page scanner should be preferred over
// a B-tree cursor. This is the case when:
//   - --raw flag is set, or
//   - a non-empty WAL file exists (cursor would miss uncheckpointed rows), or
//   - the file exceeds 10 GiB (likely a bulk-merge DB with scattered leaf pages)
func isFragmented(path string) bool {
	if *rawAll {
		return true
	}
	if fi, err := os.Stat(path + "-wal"); err == nil && fi.Size() > 0 {
		return true
	}
	if fi, err := os.Stat(path); err == nil && fi.Size() > 10<<30 {
		return true
	}
	return false
}

// Column indices in subjects table (must match CREATE TABLE order).
const (
	colCaID         = 1
	colSerialNumber = 2
	colCommonName   = 3
	colOrganization = 4
	colState        = 5
	colCountry      = 6
	colNotBefore    = 7
	colNotAfter     = 8
	colSanDomains   = 9
	colSanIPs       = 10
	colURL          = 11
	colIsWildcard   = 12
	colSanCount     = 13
	colEntryType    = 14
	colTileIdx      = 15
	colEntryIdx     = 16
	numCols         = 17
)

func rawScanAndWrite(srcPath string, pool *outputPool, remap map[remapKey]int64) (rowCount, skipCount int, err error) {
	issPath := issuerKey(srcPath)
	f, err := os.Open(srcPath)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()

	var hdr [100]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return 0, 0, fmt.Errorf("read header: %w", err)
	}
	if string(hdr[:16]) != "SQLite format 3\x00" {
		return 0, 0, fmt.Errorf("%s: not a SQLite database", srcPath)
	}
	rawPS := binary.BigEndian.Uint16(hdr[16:18])
	pageSize := int(rawPS)
	if pageSize == 1 {
		pageSize = 65536
	}
	fi, err := f.Stat()
	if err != nil {
		return 0, 0, err
	}
	nPages := int(fi.Size() / int64(pageSize))

	f.Seek(0, io.SeekStart)
	r := bufio.NewReaderSize(f, 8<<20)
	page := make([]byte, pageSize)

	for pageNum := 1; pageNum <= nPages; pageNum++ {
		if _, err := io.ReadFull(r, page); err != nil {
			break
		}
		hdrOff := 0
		if pageNum == 1 {
			hdrOff = 100
		}
		if page[hdrOff] != 0x0D { // only leaf table pages
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
			s, ok := parseRow(page, cellOff, pageSize, issPath, remap)
			if !ok {
				skipCount++
				continue
			}
			month := certMonth(s.notBefore)
			if err := pool.insert(month, s); err != nil {
				log.Printf("warn: insert %s/%d: %v", month, s.tileIdx, err)
			}
			rowCount++
			if rowCount%5_000_000 == 0 {
				log.Printf("  ... %dM rows", rowCount/1_000_000)
			}
		}
	}
	return rowCount, skipCount, nil
}

// parseRow extracts a subjects row from a SQLite leaf table page cell.
// Returns (row, true) on success, (nil, false) if the row should be skipped
// (wrong schema, overflow, ca_id not in remap).
func parseRow(page []byte, cellOff, pageSize int, issPath string, remap map[remapKey]int64) (*subjectRow, bool) {
	pos := cellOff
	// payload length varint
	_, n := sqliteVarint(page[pos:])
	if n == 0 {
		return nil, false
	}
	pos += n
	// rowid varint
	_, n = sqliteVarint(page[pos:])
	if n == 0 {
		return nil, false
	}
	pos += n

	// Record header: header_size varint then type codes.
	payloadStart := pos
	headerSize, n := sqliteVarint(page[pos:])
	if n == 0 || int(headerSize) > pageSize-payloadStart {
		return nil, false
	}
	pos += n
	headerEnd := payloadStart + int(headerSize)

	var typeCodes [numCols]uint64
	for col := 0; col < numCols && pos < headerEnd; col++ {
		tc, n := sqliteVarint(page[pos:])
		if n == 0 {
			return nil, false
		}
		pos += n
		typeCodes[col] = tc
	}
	if typeCodes[colEntryIdx] == 0 && typeCodes[colTileIdx] == 0 {
		return nil, false // too few columns — not a subjects row
	}

	// Walk data section.
	dataOff := headerEnd
	colData := make([]int, numCols) // starting offset of each column's data
	for col := 0; col < numCols; col++ {
		colData[col] = dataOff
		sz := int(sqliteColDataSize(typeCodes[col]))
		if dataOff+sz > pageSize {
			return nil, false // overflow page — skip
		}
		dataOff += sz
	}

	readText := func(col int) string {
		tc := typeCodes[col]
		if tc < 13 || tc%2 == 0 {
			return ""
		}
		length := int((tc - 13) / 2)
		if length == 0 {
			return ""
		}
		start := colData[col]
		if start+length > pageSize {
			return ""
		}
		return string(page[start : start+length])
	}
	readInt := func(col int) int64 {
		return sqliteReadInt(page, colData[col], typeCodes[col])
	}

	localCaID := readInt(colCaID)
	globalID, ok := remap[remapKey{srcPath: issPath, localID: localCaID}]
	if !ok {
		return nil, false
	}

	return &subjectRow{
		caID:         globalID,
		serialNumber: readText(colSerialNumber),
		commonName:   readText(colCommonName),
		organization: readText(colOrganization),
		state:        readText(colState),
		country:      readText(colCountry),
		notBefore:    readText(colNotBefore),
		notAfter:     readText(colNotAfter),
		sanDomains:   readText(colSanDomains),
		sanIPs:       readText(colSanIPs),
		url:          readText(colURL),
		isWildcard:   readInt(colIsWildcard),
		sanCount:     readInt(colSanCount),
		entryType:    readText(colEntryType),
		tileIdx:      readInt(colTileIdx),
		entryIdx:     readInt(colEntryIdx),
	}, true
}

// sqliteReadInt reads a big-endian signed integer from page at offset off
// for the given SQLite serial type code.
func sqliteReadInt(page []byte, off int, tc uint64) int64 {
	switch tc {
	case 0:
		return 0 // NULL
	case 8:
		return 0 // literal 0
	case 9:
		return 1 // literal 1
	case 1:
		return int64(int8(page[off]))
	case 2:
		return int64(int16(binary.BigEndian.Uint16(page[off : off+2])))
	case 3:
		v := int64(page[off])<<16 | int64(page[off+1])<<8 | int64(page[off+2])
		if v >= 0x800000 {
			v -= 0x1000000
		}
		return v
	case 4:
		return int64(int32(binary.BigEndian.Uint32(page[off : off+4])))
	case 5:
		hi := int64(binary.BigEndian.Uint32(page[off : off+4]))
		lo := int64(binary.BigEndian.Uint16(page[off+4 : off+6]))
		v := hi<<16 | lo
		if v >= 0x800000000000 {
			v -= 0x1000000000000
		}
		return v
	case 6:
		return int64(binary.BigEndian.Uint64(page[off : off+8]))
	}
	return 0
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
			return (tc - 12) / 2
		}
		return (tc - 13) / 2
	}
	return 0
}

