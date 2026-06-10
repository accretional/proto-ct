// Command remerge-pools drains preserved orphan pool dirs under data/active into
// the HDD archive by loading each as a db.SubjectDBPool and calling the
// (now SSD-scratch-accelerated) FlushAll — exercising the real ingestion flush
// path on real data to validate the FlushAll/MergeSubjectDBsScratch updates.
//
// It flushes one month at a time (a fresh GetOrOpen + FlushAll per month) so:
//   - only one month's SQLite handles are open at once (fd-friendly),
//   - each month's SSD source is reclaimed before the next opens (bounded SSD),
//   - progress is visible per month, and timing per month is logged.
//
// Distinct from the deprecated cmd/merge-pools (slow in-place HDD merge). Run
// with NO ct-server running.
//
// Usage:
//
//	go run ./cmd/remerge-pools --archive /Volumes/wd_office_2/datasets/CT \
//	    [--active data/active] [--pool <name>] [--dry-run]
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

	"github.com/benfultz/proto-ct/internal/db"
)

var monthRe = regexp.MustCompile(`^\d{4}-\d{2}$`)

func main() {
	activeDir := flag.String("active", "data/active", "active pool root containing <pool>/<YYYY-MM>/subjects.db dirs")
	archiveDir := flag.String("archive", "/Volumes/wd_office_2/datasets/CT", "HDD archive root (<YYYY-MM>/subjects.db)")
	onlyPool := flag.String("pool", "", "only process this single pool dir name")
	dryRun := flag.Bool("dry-run", false, "list the work, then exit without flushing")
	noSeal := flag.Bool("no-seal", false, "append only; skip the final per-month SealMonth (keeps months index-free for an ongoing append-only bootstrap — the seal-at-tail pass rebuilds indexes later)")
	flag.Parse()

	if pids := pgrep("ct-server"); len(pids) > 0 {
		log.Fatalf("ct-server appears to be running (pids %v) — stop it before re-merging; aborting", pids)
	}

	// Bulk drain: each per-pool, per-month flush is now an append-only
	// FlushMonthDeduped (O(new rows), no index rebuild). The O(month) compaction
	// + query-index build is done once per touched month at the very end via
	// SealMonth — by which point the pool dirs are drained and the SSD has room
	// for the seal's scratch rebuild, so the giant months never hit the
	// scratch-headroom wall mid-drain.
	pools, err := listPools(*activeDir)
	if err != nil {
		log.Fatalf("list pools: %v", err)
	}
	if len(pools) == 0 {
		log.Printf("no pool dirs with months found under %s — nothing to do", *activeDir)
		return
	}

	touched := map[string]bool{}
	var totalMonths, totalFailed int
	for _, pool := range pools {
		if *onlyPool != "" && pool != *onlyPool {
			continue
		}
		poolPath := filepath.Join(*activeDir, pool)
		months, err := listMonths(poolPath)
		if err != nil {
			log.Printf("[%s] list months: %v — skipping", pool, err)
			continue
		}
		log.Printf("[%s] %d month(s) to flush", pool, len(months))
		if *dryRun {
			for _, m := range months {
				log.Printf("  would flush %s/%s (%.0f MiB)", pool, m, fileSizeMB(filepath.Join(poolPath, m, "subjects.db")))
			}
			totalMonths += len(months)
			continue
		}

		p := db.NewSubjectDBPool(poolPath)
		for _, m := range months {
			sizeMB := fileSizeMB(filepath.Join(poolPath, m, "subjects.db"))
			if _, err := p.GetOrOpen(m); err != nil {
				log.Printf("  [%s/%s] open: %v", pool, m, err)
				totalFailed++
				continue
			}
			start := time.Now()
			// Only month m is loaded, so FlushAll flushes exactly it and clears.
			if err := p.FlushAll(*archiveDir); err != nil {
				log.Printf("  [%s/%s] FlushAll (%.0f MiB): %v", pool, m, sizeMB, err)
				totalFailed++
				continue
			}
			log.Printf("  [%s/%s] flushed (%.0f MiB) in %s; SSD %sG free",
				pool, m, sizeMB, took(start), ssdFreeGB(*activeDir))
			touched[m] = true
			totalMonths++
		}
		// Drop the pool dir if fully drained.
		if rem, _ := listMonths(poolPath); len(rem) == 0 {
			if err := os.Remove(poolPath); err == nil {
				log.Printf("[%s] drained and removed", pool)
			}
		}
	}

	// Seal each touched month once at the end: compact any transient duplicates
	// the append path left behind and (re)build the cert_hash unique + read-path
	// query indexes. The scratch rebuild runs on the SSD active dir; pools are
	// drained by now so there is room even for the giant months.
	//
	// --no-seal skips this: when draining into an archive that an append-only
	// bootstrap is still using, re-indexing a month would force the next live
	// flush to re-migrate it. Leave the months index-free; the seal-at-tail pass
	// rebuilds indexes for everything once the bootstrap is caught up.
	if *noSeal && !*dryRun && len(touched) > 0 {
		log.Printf("--no-seal: leaving %d touched month(s) index-free (seal deferred to the tail pass)", len(touched))
	}
	if !*noSeal && !*dryRun && len(touched) > 0 {
		months := make([]string, 0, len(touched))
		for m := range touched {
			months = append(months, m)
		}
		sort.Strings(months)
		log.Printf("sealing %d touched month(s)", len(months))
		for _, m := range months {
			archivePath := filepath.Join(*archiveDir, m, "subjects.db")
			start := time.Now()
			if err := db.SealMonth(archivePath, *activeDir); err != nil {
				log.Printf("  [%s] seal: %v", m, err)
				totalFailed++
				continue
			}
			log.Printf("  [%s] sealed in %s; SSD %sG free", m, took(start), ssdFreeGB(*activeDir))
		}
	}

	log.Printf("remerge-pools done: months flushed=%d failed=%d", totalMonths, totalFailed)
	if totalFailed > 0 {
		os.Exit(1)
	}
}

// listPools returns pool dir names under activeDir that contain at least one
// YYYY-MM/subjects.db, lexically sorted (== oldest→newest for timestamp names).
func listPools(activeDir string) ([]string, error) {
	ents, err := os.ReadDir(activeDir)
	if err != nil {
		return nil, err
	}
	var pools []string
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		if ms, _ := listMonths(filepath.Join(activeDir, e.Name())); len(ms) > 0 {
			pools = append(pools, e.Name())
		}
	}
	sort.Strings(pools)
	return pools, nil
}

func listMonths(poolPath string) ([]string, error) {
	ents, err := os.ReadDir(poolPath)
	if err != nil {
		return nil, err
	}
	var months []string
	for _, e := range ents {
		if e.IsDir() && monthRe.MatchString(e.Name()) &&
			exists(filepath.Join(poolPath, e.Name(), "subjects.db")) {
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
