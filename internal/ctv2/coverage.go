package ctv2

// NOTE: this file was reconstructed from its usages (verify.go findEntry,
// service.go CheckCoverage) and the tests in ctv2_test.go. The original
// coverage.go was never committed upstream: .gitignore's `coverage.*` rule
// silently excludes it, so a fresh clone of proto-ct does not build. Behavior
// here is pinned by TestParseRangeFromName / TestSummarizeRanges /
// TestScanPartitionRanges.

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// idxRange is a half-open entry-index interval [start, end).
type idxRange struct {
	start int64
	end   int64
}

// parseRangeFromName parses a partition filename ("<first>-<last>.binpb", with an
// optional ".gz" suffix; indices base-36 encoded) into the half-open range
// [first, last+1). It reports false for names that are not well-formed partition
// files (wrong extension, no dash, undecodable index, or last < first).
func parseRangeFromName(name string) (idxRange, bool) {
	n := strings.TrimSuffix(name, ".gz")
	if !strings.HasSuffix(n, ".binpb") {
		return idxRange{}, false
	}
	n = strings.TrimSuffix(n, ".binpb")
	dash := strings.IndexByte(n, '-')
	if dash < 0 {
		return idxRange{}, false
	}
	first, err := decodeBase36(n[:dash])
	if err != nil {
		return idxRange{}, false
	}
	last, err := decodeBase36(n[dash+1:])
	if err != nil {
		return idxRange{}, false
	}
	if last < first {
		return idxRange{}, false
	}
	return idxRange{start: first, end: last + 1}, true
}

// scanPartitionRanges walks root (a single log's output prefix) at any depth and
// returns the index ranges of every partition file found plus the file count.
// Non-partition files are ignored; a missing root yields an empty result.
func scanPartitionRanges(root string) ([]idxRange, int, error) {
	var ranges []idxRange
	files := 0
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if d.IsDir() {
			return nil
		}
		r, ok := parseRangeFromName(d.Name())
		if !ok {
			return nil
		}
		ranges = append(ranges, r)
		files++
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	return ranges, files, nil
}

// summarizeRanges reduces a set of partition ranges to coverage stats:
//
//   - stored:     total distinct entries on disk (merged, so overlaps aren't double-counted)
//   - frontier:   highest index+1 seen (max end)
//   - contiguous: end of the unbroken run starting at index 0
//   - gaps:       uncovered sub-intervals of [0, bound), where bound is treeSize
//     when > 0 (so a tail gap up to the live tree is reported) else the frontier.
func summarizeRanges(ranges []idxRange, treeSize int64) (stored, frontier, contiguous int64, gaps []idxRange) {
	if len(ranges) > 0 {
		sorted := make([]idxRange, len(ranges))
		copy(sorted, ranges)
		sort.Slice(sorted, func(i, j int) bool {
			if sorted[i].start != sorted[j].start {
				return sorted[i].start < sorted[j].start
			}
			return sorted[i].end < sorted[j].end
		})

		// Merge overlapping/adjacent ranges.
		merged := []idxRange{sorted[0]}
		for _, r := range sorted[1:] {
			last := &merged[len(merged)-1]
			if r.start <= last.end {
				if r.end > last.end {
					last.end = r.end
				}
			} else {
				merged = append(merged, r)
			}
		}

		for _, r := range merged {
			stored += r.end - r.start
			if r.end > frontier {
				frontier = r.end
			}
		}
		// Contiguous run from 0.
		for _, r := range merged {
			if r.start <= contiguous {
				if r.end > contiguous {
					contiguous = r.end
				}
			} else {
				break
			}
		}

		bound := frontier
		if treeSize > 0 {
			bound = treeSize
		}
		cursor := int64(0)
		for _, r := range merged {
			if r.start > cursor && cursor < bound {
				gaps = append(gaps, idxRange{start: cursor, end: min(r.start, bound)})
			}
			if r.end > cursor {
				cursor = r.end
			}
		}
		if cursor < bound {
			gaps = append(gaps, idxRange{start: cursor, end: bound})
		}
		return stored, frontier, contiguous, gaps
	}

	// No ranges: everything up to bound is a gap.
	bound := frontier // 0
	if treeSize > 0 {
		bound = treeSize
	}
	if bound > 0 {
		gaps = append(gaps, idxRange{start: 0, end: bound})
	}
	return 0, 0, 0, gaps
}
