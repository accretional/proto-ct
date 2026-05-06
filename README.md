# proto-ct — Certificate Transparency Mirror

A high-throughput tool for mirroring [Certificate Transparency](https://certificate.transparency.dev/) logs to local SQLite databases, with a gRPC API for streaming ingestion and progress monitoring.

## What it does

Certificate Transparency logs are append-only public records of every TLS certificate issued by participating CAs. This tool mirrors those logs locally by:

1. Downloading binary tile data from any [static-ct-api](https://github.com/C2SP/C2SP/blob/main/static-ct-api.md) compatible log
2. Parsing X.509 certificates and pre-certificates from each tile
3. Writing issuer (CA) and subject (certificate) data to separate SQLite databases, sharded by date
4. Streaming parsed certificate records to connected gRPC clients in real time
5. Tracking progress so mirroring can be interrupted and resumed at any time

## Architecture

```
proto-ct/
├── cmd/
│   ├── server/          # gRPC server binary
│   └── client/          # CLI client (mirror + check modes)
├── internal/
│   ├── ctlog/           # Tile downloader & binary TileLeaf parser
│   ├── db/              # SQLite: issuers, subjects, progress tracking
│   └── ingestion/       # gRPC service implementation + metrics
├── proto/ctingestion/v1/ # Protobuf service definition
└── tools/
    └── top_domains.sh   # Analyze top parent domains in a mirrored batch
```

## Output layout

```
<output_dir>/
  progress.db            ← resumption state across sessions
  ingestion.log          ← periodic metrics (appended every 5 min)
  20260506/
    issuers.db           ← CA certificates (ca_id PK, fingerprint, CN, org, country)
    subjects.db          ← Certificate subjects (ca_id FK, SANs, validity, URL)
  20260507/              ← rotated automatically at local midnight
    issuers.db
    subjects.db
```

Issuers and subjects are in separate files with `ca_id` linking them (queryable via SQLite `ATTACH`).

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
  --out /path/to/output/

# Check current progress
./bin/ct-client --check --out /path/to/output/
```

## Scripts

| Script | Purpose |
|--------|---------|
| `setup.sh` | Install protoc plugins, regenerate gRPC stubs, `go mod tidy` |
| `build.sh` | Run setup + compile binaries to `bin/` |
| `test.sh` | Run build + `go test ./...` |
| `LET_IT_RIP.sh` | Full round-trip test: start server, mirror 1000 entries, verify DBs, show top domains |
| `tools/top_domains.sh <N>` | Top N parent domains from the most recent mirrored batch |

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

Progress is tracked in `progress.db` keyed by monitoring root URL. Restarting the client with the same `--out` and `--root` automatically continues from the last completed tile.

## Cross-database queries

```sql
-- Attach both files to query subjects with issuer info
sqlite3 /Volumes/wd_office_2/datasets/CT/20260506/subjects.db
ATTACH '/Volumes/wd_office_2/datasets/CT/20260506/issuers.db' AS idb;
SELECT s.common_name, i.common_name AS issuer, s.not_after
FROM subjects s JOIN idb.issuers i ON s.ca_id = i.ca_id
LIMIT 10;
```

## Data source

Tested against [Let's Encrypt's sycamore log](https://letsencrypt.org/docs/ct-logs/) (`https://mon.sycamore.ct.letsencrypt.org/2026h1/tile/data/`), which implements the [C2SP static-ct-api](https://github.com/C2SP/C2SP/blob/main/static-ct-api.md) spec. Any compliant static-ct-api log is supported.
