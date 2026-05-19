package main

import (
	"bufio"
	"context"
	"database/sql"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

type shardEntry struct {
	path string
	key  shardKey
}

// enumShards walks shardsDir, collects all *.tsv files as shardEntry values,
// and shuffles them for cross-TLD interleaving.
func enumShards(shardsDir string) ([]shardEntry, error) {
	var entries []shardEntry
	err := filepath.WalkDir(shardsDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".tsv" {
			return err
		}
		rel, _ := filepath.Rel(shardsDir, path)
		parts := strings.SplitN(rel, string(filepath.Separator), 2)
		if len(parts) != 2 {
			return nil
		}
		entries = append(entries, shardEntry{
			path: path,
			key:  shardKey{tld: parts[0], bucket: strings.TrimSuffix(parts[1], ".tsv")},
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	rand.Shuffle(len(entries), func(i, j int) { entries[i], entries[j] = entries[j], entries[i] })
	return entries, nil
}

// loadSkipSet reads all domains from the fetch_log of an existing shard DB.
// Returns an empty set if the DB does not exist. Capped at 1M entries; a
// warning is logged when the cap is hit (INSERT OR IGNORE handles dedup for
// the remainder on re-run).
func loadSkipSet(dbPath string) map[string]struct{} {
	const maxSkip = 1_000_000
	skip := make(map[string]struct{})
	if _, err := os.Stat(dbPath); err != nil {
		return skip
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return skip
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	rows, err := db.Query(`SELECT domain FROM fetch_log LIMIT ?`, maxSkip+1)
	if err != nil {
		return skip
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var d string
		if rows.Scan(&d) == nil {
			skip[d] = struct{}{}
			count++
		}
	}
	if count > maxSkip {
		log.Printf("skip set for %s capped at %d entries; INSERT OR IGNORE handles remaining dedup", dbPath, maxSkip)
	}
	return skip
}

// runFeeder reads all shard TSV files, skips already-resolved domains, and
// pushes work items to workCh in the order shards were shuffled.
func runFeeder(ctx context.Context, shards []shardEntry, outDir string, workCh chan<- workItem) error {
	for _, shard := range shards {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		dbPath := filepath.Join(outDir, shard.key.tld, shard.key.bucket+".db")
		skip := loadSkipSet(dbPath)

		f, err := os.Open(shard.path)
		if err != nil {
			log.Printf("open shard %s: %v", shard.path, err)
			continue
		}

		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 1<<20), 1<<20)
		fed := 0
		for scanner.Scan() {
			if ctx.Err() != nil {
				f.Close()
				return ctx.Err()
			}
			line := scanner.Text()
			domain := line
			if t := strings.IndexByte(line, '\t'); t >= 0 {
				domain = line[:t]
			}
			if domain == "" {
				continue
			}
			if _, done := skip[domain]; done {
				continue
			}
			select {
			case workCh <- workItem{domain: domain, shard: shard.key}:
				fed++
			case <-ctx.Done():
				f.Close()
				return ctx.Err()
			}
		}
		f.Close()
		if err := scanner.Err(); err != nil {
			log.Printf("scan %s: %v", shard.path, err)
		}
		log.Printf("feed: %s → %d domains queued (skip=%d)", shard.key, fed, len(skip))
	}
	return nil
}
