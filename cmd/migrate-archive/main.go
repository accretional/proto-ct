// Command migrate-archive does a one-time OFFLINE pass over every archive month,
// stripping each pre-existing month's cert_hash + read-path query indexes to the
// append-only index-free heap (db.MigrateArchiveMonth). Run it ONCE before a
// heavy bootstrap so the per-month migration cost — and its ~month-sized SSD
// scratch spike — is paid up front with full headroom, instead of stacking up
// against live ingestion (which forces a disk-pressure pause and slows the
// download).
//
// After this pass every FlushMonthDeduped during ingestion is a pure sequential
// append (no index work, no scratch spike). The read-path indexes are rebuilt
// later by the one-time SealMonth pass when the bootstrap reaches the live tail.
//
// Must run with ct-server STOPPED: a second process writing the archive races
// the server's flushes (archiveFlushMu only guards within one process).
//
// Usage:
//
//	go run ./cmd/migrate-archive --archive /Volumes/wd_office_2/datasets/CT \
//	    [--scratch data/active] [--dry-run]
package main

import (
	"flag"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/accretional/proto-ct/internal/db"
)

var monthRe = regexp.MustCompile(`^\d{4}-\d{2}$`)

func main() {
	archiveDir := flag.String("archive", "/Volumes/wd_office_2/datasets/CT", "HDD archive root (<YYYY-MM>/subjects.db)")
	scratchDir := flag.String("scratch", "data/active", "SSD scratch dir for the rebuild (needs ~one giant-month of free space)")
	dryRun := flag.Bool("dry-run", false, "list the months and whether each needs migration, then exit")
	flag.Parse()

	if pids := pgrep("ct-server"); len(pids) > 0 {
		log.Fatalf("ct-server appears to be running (pids %v) — stop it before migrating (cross-process archive writes are unsafe); aborting", pids)
	}

	months, err := listArchiveMonths(*archiveDir)
	if err != nil {
		log.Fatalf("list archive months: %v", err)
	}
	if len(months) == 0 {
		log.Printf("no archive months with subjects.db under %s — nothing to do", *archiveDir)
		return
	}
	log.Printf("%d archive month(s) under %s; scratch=%s", len(months), *archiveDir, *scratchDir)

	var migrated, skipped, failed int
	for _, m := range months {
		archivePath := filepath.Join(*archiveDir, m, "subjects.db")
		sizeMB := fileSizeMB(archivePath)
		if *dryRun {
			log.Printf("  %s (%.0f MiB)", m, sizeMB)
			continue
		}
		start := time.Now()
		did, err := db.MigrateArchiveMonth(archivePath, *scratchDir)
		switch {
		case err != nil:
			log.Printf("  [%s] migrate (%.0f MiB): %v", m, sizeMB, err)
			failed++
		case did:
			log.Printf("  [%s] migrated (%.0f MiB) in %s; SSD %sG free", m, sizeMB, took(start), ssdFreeGB(*scratchDir))
			migrated++
		default:
			log.Printf("  [%s] already index-free — skipped", m)
			skipped++
		}
	}

	log.Printf("migrate-archive done: migrated=%d skipped=%d failed=%d", migrated, skipped, failed)
	if failed > 0 {
		os.Exit(1)
	}
}

// listArchiveMonths returns YYYY-MM dir names with a subjects.db under archiveDir,
// sorted ascending (oldest first).
func listArchiveMonths(archiveDir string) ([]string, error) {
	ents, err := os.ReadDir(archiveDir)
	if err != nil {
		return nil, err
	}
	var months []string
	for _, e := range ents {
		if e.IsDir() && monthRe.MatchString(e.Name()) &&
			exists(filepath.Join(archiveDir, e.Name(), "subjects.db")) {
			months = append(months, e.Name())
		}
	}
	sort.Strings(months)
	return months, nil
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func fileSizeMB(p string) float64 {
	fi, err := os.Stat(p)
	if err != nil {
		return 0
	}
	return float64(fi.Size()) / (1 << 20)
}

func took(start time.Time) string { return time.Since(start).Round(time.Second).String() }

// ssdFreeGB returns free GiB on the filesystem holding path, best-effort.
func ssdFreeGB(path string) string {
	out, err := exec.Command("df", "-g", path).Output()
	if err != nil {
		return "?"
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 2 {
		return "?"
	}
	f := strings.Fields(lines[len(lines)-1])
	if len(f) < 4 {
		return "?"
	}
	return f[3]
}

func pgrep(pat string) []string {
	out, err := exec.Command("pgrep", "-x", pat).Output()
	if err != nil {
		return nil
	}
	return strings.Fields(string(out))
}
