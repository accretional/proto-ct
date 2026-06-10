# CT Export Pipeline — Redesign Plan

## Goal

Produce a sharded, DNS-pipeline-ready dataset of all FQDNs observed in CT logs,
with wildcard and direct SAN appearances tracked separately, and with a
per-date-dir intermediate format that makes future incremental re-exports cheap.

---

## Pipeline Overview

```
Phase 0  (skip if already done)
  For each archive date dir that lacks subjects_export.tsv:
    Scan subjects.db → write subjects_export.tsv (domain, direct, wildcard)

Phase 1  (always)
  K-way merge of all subjects_export.tsv files
  → master counts in memory (or streamed)

Phase 2  (always)
  Fan-out master counts into shards by eTLD+1 registrable domain
  → shards/<tld>/<bucket>.tsv  and  flat summary files
```

---

## Data Structures

### In-memory accumulation map

```go
// Packed uint64: high 32 bits = wildcard count, low 32 bits = direct count.
// Same memory footprint as the current map[string]uint32.
type domainMap map[string]uint64

func addDirect(m domainMap, d string)   { m[d]++ }
func addWildcard(m domainMap, d string) { m[d] += 1 << 32 }

func directCount(v uint64) uint32   { return uint32(v) }
func wildcardCount(v uint64) uint32 { return uint32(v >> 32) }
```

When scanning a `san_domains` value, split by comma then:
- Entry starts with `*.` → strip prefix, normalize, call `addWildcard`
- Entry does not start with `*.` → normalize, call `addDirect`

A cert with both `*.example.com` and `example.com` in its SAN list increments
both halves of the packed value for `example.com`.

---

## File Formats

### Phase 0 output — `subjects_export.tsv`

Co-located with each `subjects.db`:

```
/Volumes/wd_office_2/datasets/CT/
  2025-11-01/
    subjects.db
    subjects_export.tsv   ← produced by phase 0
  2025-11-02/
    subjects.db
    subjects_export.tsv
  ...
```

Format: three-column TSV, **alphabetically sorted by domain**:

```
domain<TAB>direct_count<TAB>wildcard_count<LF>
```

Example:
```
api.example.com	14	0
example.com	3	22
www.example.com	41	0
```

Sorting by domain is required for the k-way merge in phase 1.
Wildcard counts are emitted even when zero so the format is uniform.

### Phase 1 temp chunks

Same three-column format as `subjects_export.tsv`. Used when the in-memory
map for a single DB exceeds the flush threshold (default 10 M rows).
Written to `--tmp` dir as `chunk_NN_pMMM.sorted.tsv`, deleted after merge.

### Phase 2 output — shard files

```
<outdir>/
  shards/
    com/
      a.tsv          ← eTLD+1 starts with 'a' (amazon.com, apple.com, …)
      b.tsv
      …
      z.tsv
      0.tsv          ← starts with digit
    net/
      exports.tsv    ← all of net (flat, single file unless >threshold)
    org/
      exports.tsv
    io/
      exports.tsv
    <tld>/
      exports.tsv
    _other/
      exports.tsv    ← catch-all for low-volume / unknown TLDs
  subdomains_direct.txt       ← FQDNs with direct_count > 0, alphabetical
  subdomains_wildcard_only.txt ← FQDNs with direct_count == 0, alphabetical
  subdomains_counts.tsv        ← direct<TAB>wildcard<TAB>domain, desc by direct
```

Shard file format (same three-column TSV, sorted by domain):
```
domain<TAB>direct_count<TAB>wildcard_count<LF>
```

---

## Sharding Logic

Uses `golang.org/x/net/publicsuffix` (already a transitive dep via `golang.org/x/net`).

```go
import "golang.org/x/net/publicsuffix"

func shardKey(domain string) (tld, bucket string) {
    etld1, err := publicsuffix.EffectiveTLDPlusOne(domain)
    if err != nil {
        return "_other", "exports"
    }
    tld = publicsuffix.PublicSuffix(etld1)  // e.g. "com", "co.uk", "com.cn"
    if tld == "" {
        tld = "_other"
    }
    // Shard .com (and any other TLD above the size threshold) by first
    // character of the second-level label (the part before the TLD).
    if largeTLD[tld] {
        sld := strings.TrimSuffix(etld1, "."+tld)
        if len(sld) == 0 {
            return tld, "exports"
        }
        c := sld[0]
        switch {
        case c >= 'a' && c <= 'z':
            bucket = string(c)
        case c >= '0' && c <= '9':
            bucket = "0"
        default:
            bucket = "_other"
        }
        return tld, bucket
    }
    return tld, "exports"
}

// Determined empirically from current export run. Extend as needed.
var largeTLD = map[string]bool{
    "com": true,
    "net": false,  // revisit if net grows past ~5 GB
}
```

The `largeTLD` map starts with only `com`. Add others if a shard file exceeds
a manageable size (rough target: < 2 GB per file).

---

## Incremental Update Flow

When new CT log data is ingested and archived:

```
1. New date dirs appear under the archive root (e.g. 2025-12-01/).
2. Run export with --incremental flag (or always — phase 0 is a no-op for
   dirs that already have subjects_export.tsv).
3. Phase 0 scans only the new dir(s) and writes their subjects_export.tsv.
4. Phase 1 re-merges all subjects_export.tsv files (fast: pre-sorted TSVs,
   no DB I/O).
5. Phase 2 rewrites the shard files and summary files.
```

Phase 1+2 on pre-sorted TSV files is IO-bound on the output side only; the
entire merge pass takes seconds to minutes rather than hours.

---

## Implementation Plan

### Step 1 — add PSL dependency explicitly

`golang.org/x/net/publicsuffix` is already available transitively. No `go get`
needed; just import it.

### Step 2 — update `cmd/export/main.go`

- Change accumulation map type from `map[string]uint32` to `map[string]uint64`
- Update `buildChunks`: split wildcard vs direct during `san_domains` parse
- Update `writeSortedChunk`: emit three columns (`domain\tdirect\twildcard`)
- Update `advance` / `mergeChunks`: sum `direct` and `wildcard` columns
  separately; write three-column output

### Step 3 — add phase 0 (per-date-dir intermediates)

- New function `buildDateExport(dateDir string) error`
  - Skips if `subjects_export.tsv` already exists in `dateDir`
  - Calls `buildChunks` on the `subjects.db` in that dir
  - Merges chunks → `subjects_export.tsv` (three-column sorted TSV)
- `main` walks the archive tree, calls `buildDateExport` for each date dir

### Step 4 — add phase 2 (sharded fan-out)

- New function `writeShards(mergedChunks []string, outDir string) error`
- Streams the merged output through `shardKey`, opens/buffers one writer per
  `(tld, bucket)` pair, writes rows, closes and sorts each shard file
- Writes `subdomains_direct.txt`, `subdomains_wildcard_only.txt`, and
  `subdomains_counts.tsv` in the same pass

### Step 5 — update `tools/rawscan/main.go`

Mirror the same wildcard-tracking and three-column chunk format changes so
rawscan output is compatible with the phase 1 merge.

### Step 6 — update `tools/rawscan` chunk format (parallel with step 2)

Both tools must produce identical chunk formats for phase 1 to merge them.
The rawscan wildcard logic is the same: check `strings.HasPrefix(raw, "*.")`.

---

## Compatibility Notes

- `subdomains_unique.txt` is dropped; `subdomains_direct.txt` +
  `subdomains_wildcard_only.txt` together cover the same set.
- `subdomains_with_count.tsv` is replaced by `subdomains_counts.tsv` (column
  order changes from `count\tdomain` to `direct\twildcard\tdomain`).
- Existing `subjects_export.tsv` files from a previous run can be regenerated
  by deleting them; phase 0 will rebuild.
- `largeTLD` starts conservative (`com` only). The `.net` threshold is noted
  for review after the first full export run with this design.
