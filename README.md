# proto-ct — Certificate Transparency Mirror

A high-throughput tool for mirroring [Certificate Transparency](https://certificate.transparency.dev/) logs to local SQLite databases, with a gRPC API for streaming ingestion and progress monitoring.

## What it does

Certificate Transparency logs are append-only public records of every TLS certificate issued by participating CAs. This tool mirrors those logs locally by:

1. Downloading binary tile data from any [static-ct-api](https://github.com/C2SP/C2SP/blob/main/static-ct-api.md) compatible log
2. Parsing X.509 certificates and pre-certificates from each tile
3. Writing subject (certificate) data to SQLite databases partitioned by **cert issuance month** (`YYYY-MM/`)
4. Maintaining a single global issuers (CA) database at the archive root
5. Streaming parsed certificate records to connected gRPC clients in real time
6. Tracking progress so mirroring can be interrupted and resumed at any time

## Architecture

```
proto-ct/
├── cmd/
│   ├── server/          # gRPC server binary
│   ├── client/          # CLI client (mirror + check modes)
│   ├── export/          # Aggregate DNS SANs from archive into sharded output files
│   └── repartition/     # One-shot migration: rekey an archive by cert issuance month
├── internal/
│   ├── ctlog/           # Tile downloader & binary TileLeaf parser
│   ├── db/              # SQLite: issuers, subjects, pool, progress tracking
│   └── ingestion/       # gRPC service implementation + metrics
├── proto/ctingestion/v1/ # Protobuf service definition
└── tools/
    ├── rawscan/         # Raw SQLite page scanner (bypass cursor for fragmented DBs)
    └── r2_backup.sh     # Sync archive DBs to Cloudflare R2
```

## Storage layout

Archive partitions are keyed by **cert issuance month** (`not_before` truncated to `YYYY-MM`), not by the date the data was ingested. This makes date-range queries, incremental exports, and cert-age filtering efficient.

```
<archive_dir>/
  issuers.db             ← global CA table (ca_id PK, fingerprint, CN, org, country)
  progress.db            ← resumption state across sessions
  ingestion.log          ← periodic metrics (appended every 5 min)
  2025-09/
    subjects.db          ← all certs with not_before in September 2025
    subjects_export.tsv  ← export intermediate (written by ct-export, if run)
  2025-10/
    subjects.db          ← all certs with not_before in October 2025
  2026-01/
    subjects.db
  ...
```

A single `issuers.db` at the archive root holds all CA records. `ca_id` is consistent across every monthly partition, so cross-partition joins work without remapping:

```sql
ATTACH '/archive/issuers.db' AS idb;
SELECT s.common_name, i.common_name AS issuer, s.not_after
FROM subjects s JOIN idb.issuers i ON s.ca_id = i.ca_id
LIMIT 10;
```

### Active (in-progress) layout

During an ingestion session, each partition is written to a fast local staging area first, then flushed to the archive drive on completion or at midnight:

```
<active_dir>/
  20260519/              ← session date (ingestion date, not cert date)
    2026-02/
      subjects.db        ← certs with not_before in Feb 2026, being ingested now
    2026-03/
      subjects.db
```

Small batches (< 256 MiB active DB) are merged into the archive via direct `INSERT OR IGNORE`. Large bulk ingestion runs use a full rebuild to keep archive pages contiguous.

## Quick start

**Requirements:** Go 1.26, `protoc`, `protoc-gen-go`, `protoc-gen-go-grpc`, `sqlite3`

```bash
# Build everything
bash build.sh

# Start the server
./bin/ct-server --port 50051

# Mirror 1 million entries from Let's Encrypt's sycamore log
./bin/ct-client \
  --root https://mon.sycamore.ct.letsencrypt.org/2026h1/tile/data/ \
  --batch 1000000 \
  --qps 500 \
  --out /fast/ssd/active/ \
  --archive /slow/hdd/archive/

# Check current progress
./bin/ct-client --check --archive /slow/hdd/archive/
```

## Scripts and tools

| Script / binary | Purpose |
|---|---|
| `setup.sh` | Install protoc plugins, regenerate gRPC stubs, `go mod tidy` |
| `build.sh` | Run setup + compile binaries to `bin/` |
| `test.sh` | Run build + `go test ./...` |
| `LET_IT_RIP.sh` | Full round-trip test: start server, mirror 1000 entries, verify DBs |
| `bin/ct-export` | Aggregate DNS SANs across all archive partitions into sharded output files |
| `bin/ct-repartition` | One-shot migration: rekey an ingestion-date archive to cert-issuance-month layout |
| `bin/rawscan` | Raw SQLite page scanner — bypass B-tree cursor on heavily fragmented DBs |
| `tools/r2_backup.sh` | Upload archive DBs to Cloudflare R2 (resumable, manifest-tracked) |

## gRPC API

```protobuf
service CTIngestionService {
  // Stream certificate records as they are mirrored.
  rpc IngestLog(IngestRequest) returns (stream SubjectRecord);
  // Return current mirroring progress and storage metrics.
  rpc Check(CheckRequest) returns (CheckResponse);
}
```

`CheckResponse` includes the live log tree size (from the checkpoint endpoint), total entries mirrored, coverage percentage, and sizes of all local database files.

## Rate limiting

Pass `--qps N` to cap HTTP requests to the monitoring endpoint. The actual rate is throttled to **80% of the target** via a token bucket. All requests — tile downloads and issuer cert fetches — share the same limiter.

At 500 QPS (400 effective): ~900,000 entries/hour (400 tiles/sec × 256 entries/tile peak).

## Resumption

Progress is tracked in `<archive_dir>/progress.db` keyed by monitoring root URL. Restarting the client with the same `--archive` and `--root` automatically continues from the last completed tile.

## Querying the archive

Each monthly partition is a standalone SQLite database. Attach `issuers.db` from the archive root for issuer lookups:

```sql
-- Query a single month's certs with issuer info
sqlite3 /archive/2026-01/subjects.db
ATTACH '/archive/issuers.db' AS idb;
SELECT s.common_name, i.common_name AS issuer, s.not_after
FROM subjects s JOIN idb.issuers i ON s.ca_id = i.ca_id
LIMIT 10;

-- Count certs by issuer across all of Q1 2026 (attach multiple partitions)
ATTACH '/archive/2026-02/subjects.db' AS feb;
ATTACH '/archive/2026-03/subjects.db' AS mar;
SELECT i.common_name, count(*) AS n
FROM (
  SELECT ca_id FROM subjects
  UNION ALL SELECT ca_id FROM feb.subjects
  UNION ALL SELECT ca_id FROM mar.subjects
) c JOIN idb.issuers i ON c.ca_id = i.ca_id
GROUP BY i.common_name ORDER BY n DESC LIMIT 10;
```

## Data source

Tested against [Let's Encrypt's sycamore log](https://letsencrypt.org/docs/ct-logs/) (`https://mon.sycamore.ct.letsencrypt.org/2026h1/tile/data/`), which implements the [C2SP static-ct-api](https://github.com/C2SP/C2SP/blob/main/static-ct-api.md) spec. Any compliant static-ct-api log is supported.
