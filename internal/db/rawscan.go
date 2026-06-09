package db

import (
	"bufio"
	"database/sql"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// certHashCol is the 0-based column position of cert_hash in the subjects record
// (id, ca_id, serial_number, common_name, organization, state, country,
// not_before, not_after, san_domains, san_ips, url, is_wildcard, san_count,
// entry_type, tile_idx, entry_idx, cert_hash, log_id).
const certHashCol = 17

// scanArchiveCertHashes reads the SQLite file at path PAGE-BY-PAGE SEQUENTIALLY
// and calls emit for every non-null cert_hash it finds in a subjects leaf row.
//
// This is the same trick cmd/repartition uses: walking the file linearly avoids
// the random reads of a B-tree index scan, which is the bottleneck when seeding
// a dedup set from a fragmented archive month on a spinning disk. Rows whose
// payload spills onto an overflow page are skipped — their cert_hash is then
// simply not pre-filtered at flush time, which is lossless because the archive's
// cert_hash unique index is the dedup backstop.
//
// It reads only the main database file, so the caller should checkpoint the WAL
// first if it wants uncheckpointed rows included (again, missing some is safe).
func scanArchiveCertHashes(path string, emit func(certHash []byte)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	var hdr [100]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return fmt.Errorf("read sqlite header: %w", err)
	}
	if string(hdr[:16]) != "SQLite format 3\x00" {
		return fmt.Errorf("%s: not a SQLite database", path)
	}
	pageSize := int(binary.BigEndian.Uint16(hdr[16:18]))
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
	r := bufio.NewReaderSize(f, 8<<20)
	page := make([]byte, pageSize)

	for pageNum := 1; pageNum <= nPages; pageNum++ {
		if _, err := io.ReadFull(r, page); err != nil {
			break
		}
		hdrOff := 0
		if pageNum == 1 {
			hdrOff = 100 // page 1 starts after the 100-byte file header
		}
		if page[hdrOff] != 0x0D { // 0x0D = leaf table b-tree page
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
			if ch := certHashFromCell(page, cellOff, pageSize); ch != nil {
				emit(ch)
			}
		}
	}
	return nil
}

// certHashFromCell extracts the cert_hash BLOB (column certHashCol) from a leaf
// table cell at cellOff, or nil if the row is too short, has a null/non-blob
// cert_hash, or its cert_hash data spilled onto an overflow page.
func certHashFromCell(page []byte, cellOff, pageSize int) []byte {
	pos := cellOff
	if _, n := sqliteVarint(page[pos:]); n == 0 { // payload length
		return nil
	} else {
		pos += n
	}
	if _, n := sqliteVarint(page[pos:]); n == 0 { // rowid
		return nil
	} else {
		pos += n
	}
	payloadStart := pos
	headerSize, n := sqliteVarint(page[pos:])
	if n == 0 {
		return nil
	}
	pos += n
	headerEnd := payloadStart + int(headerSize)
	if headerEnd > pageSize {
		return nil
	}
	// Walk type codes, accumulating the data-section offset, until cert_hash.
	dataOff := headerEnd
	for col := 0; pos < headerEnd; col++ {
		tc, n := sqliteVarint(page[pos:])
		if n == 0 {
			return nil
		}
		pos += n
		if col == certHashCol {
			// cert_hash must be a non-empty BLOB: serial type >= 12 and even.
			if tc < 12 || tc%2 != 0 {
				return nil
			}
			length := int((tc - 12) / 2)
			if length == 0 || dataOff+length > pageSize {
				return nil // empty, or spilled to an overflow page — skip
			}
			out := make([]byte, length)
			copy(out, page[dataOff:dataOff+length])
			return out
		}
		dataOff += sqliteColDataSize(tc)
		if dataOff > pageSize {
			return nil // overflow before reaching cert_hash
		}
	}
	return nil // record had fewer than certHashCol+1 columns
}

// sqliteColDataSize returns the on-disk byte size of a column value given its
// SQLite serial type code.
func sqliteColDataSize(tc uint64) int {
	switch {
	case tc == 0 || tc == 8 || tc == 9:
		return 0 // NULL / literal 0 / literal 1
	case tc >= 1 && tc <= 4:
		return int(tc) // 1..4-byte ints
	case tc == 5:
		return 6
	case tc == 6 || tc == 7:
		return 8 // 8-byte int / float
	case tc >= 12:
		return int((tc - 12) / 2) // BLOB (even) or TEXT (odd) — floor div works for both
	}
	return 0 // 10,11 reserved
}

// sqliteVarint decodes a SQLite variable-length integer, returning the value and
// the number of bytes consumed (0 on a malformed/truncated varint).
func sqliteVarint(b []byte) (v uint64, n int) {
	for i := 0; i < 9 && i < len(b); i++ {
		if i == 8 {
			return v<<8 | uint64(b[i]), 9
		}
		v = v<<7 | uint64(b[i]&0x7f)
		if b[i]&0x80 == 0 {
			return v, i + 1
		}
	}
	return 0, 0
}

// checkpointWAL flushes a WAL-mode db's WAL into its main file so a subsequent
// raw page scan sees all committed rows. Best-effort.
func checkpointWAL(path string) {
	d, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(10000)")
	if err != nil {
		return
	}
	defer d.Close()
	d.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`) //nolint:errcheck
}
