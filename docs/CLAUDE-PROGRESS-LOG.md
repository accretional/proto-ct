# CT Log Ingestion - Progress Log

## Status: COMPLETE ✓

Successful round-trip verified: 1000 records from `https://mon.sycamore.ct.letsencrypt.org/2026h1/tile/data/`

**Phase 2 complete (2026-05-06):** Rate limiting, dated output sharding, progress/resumption DB, and top_domains tool.

---

## Architecture

```
proto-ct/
├── setup.sh            # installs protoc plugins, generates proto, runs go mod tidy
├── build.sh            # runs setup then builds cmd/server + cmd/client → bin/
├── test.sh             # runs build then go test ./...
├── LET_IT_RIP.sh       # full round-trip: starts server, runs client, verifies DBs
├── go.mod              # module github.com/benfultz/proto-ct, go 1.26
├── proto/ctingestion/v1/ingestion.proto   # gRPC service definition
├── gen/ctingestion/v1/                    # generated pb+grpc stubs
├── internal/
│   ├── ctlog/
│   │   ├── client.go   # HTTP client for static-ct-api tile/data/ + issuer/ endpoints
│   │   ├── tile.go     # binary TileLeaf parser (C2SP static-ct-api format)
│   │   └── tile_test.go
│   ├── db/
│   │   └── db.go       # SQLite: IssuerDB + SubjectDB (modernc.org/sqlite, no CGO)
│   └── ingestion/
│       └── service.go  # gRPC CTIngestionService implementation
└── cmd/
    ├── server/main.go  # gRPC server binary (--port, default 50051)
    └── client/main.go  # test client (--addr, --root, --batch, --out)
```

---

## Key Design Decisions

### Static CT API (C2SP) vs RFC6962
The sycamore log uses the [C2SP static-ct-api](https://github.com/C2SP/C2SP/blob/main/static-ct-api.md),
**not** the RFC6962 JSON API. Tiles are binary-encoded at:
```
<log_root>/tile/data/<tile_index>
```

### TileLeaf Binary Format (manually parsed)
Each entry in a data tile:
```
uint64  timestamp            (8 bytes, ms since epoch)
uint16  entry_type           (0=x509, 1=precert)
[for x509]  uint24 cert_len + cert_bytes
[for precert] [32]byte issuer_key_hash + uint24 tbs_len + tbs_bytes
uint16  extensions_len + extension_bytes
[for precert only in TileLeaf] uint24 pre_cert_len + pre_cert_bytes
uint16  chain_bytes_len + 32*N fingerprint_bytes
```

### Tile Index URL Encoding
Per C2SP spec: indices are 3-digit path segments, all but the last prefixed with `x`:
- `0` → `000`
- `1000` → `x001/000`
- `1234067` → `x001/x234/067`

### Issuer Resolution
Each TileLeaf contains SHA-256 fingerprints of the issuer chain. The first fingerprint
is the immediate issuer. Resolved via `<log_root>/issuer/<hex_fingerprint>` → DER cert.
Results cached in-memory to avoid re-fetching the same CA repeatedly.

### Two SQLite Databases
- **issuers.db**: `ca_id` (PK autoincrement), `fingerprint` (unique), `common_name`, `organization`, `country`
- **subjects.db**: `id`, `ca_id` (FK by convention), `serial_number`, `common_name`, `organization`, `state`, `country`, `not_before`, `not_after`, `san_domains`, `url`

Cross-DB join via SQLite `ATTACH`:
```sql
ATTACH '/tmp/urls/issuers.db' AS idb;
SELECT s.common_name, i.common_name AS issuer
FROM subjects s JOIN idb.issuers i ON s.ca_id = i.ca_id LIMIT 5;
```

### gRPC Streaming
The `IngestLog` RPC streams `SubjectRecord` messages back as entries are processed,
allowing the client to receive results before all tiles are downloaded.

---

## Useful Commands

```bash
# Build everything
bash build.sh

# Run full round-trip test (1000 records)
bash LET_IT_RIP.sh

# Start server only
./bin/ct-server --port 50051

# Run client with custom params
./bin/ct-client \
  --addr localhost:50051 \
  --root https://mon.sycamore.ct.letsencrypt.org/2026h1/tile/data/ \
  --batch 1000 \
  --out /tmp/urls/

# Unit tests
go test ./... -v

# Inspect results
sqlite3 /tmp/urls/issuers.db "SELECT * FROM issuers LIMIT 10;"
sqlite3 /tmp/urls/subjects.db "SELECT * FROM subjects LIMIT 10;"

# Cross-DB join
sqlite3 /tmp/urls/subjects.db \
  "ATTACH '/tmp/urls/issuers.db' AS idb;
   SELECT s.common_name, i.common_name AS issuer, s.not_after
   FROM subjects s JOIN idb.issuers i ON s.ca_id = i.ca_id
   LIMIT 10;"

# Check checkpoint (tree size)
curl -s https://mon.sycamore.ct.letsencrypt.org/2026h1/checkpoint

# Fetch a raw data tile
curl -s https://mon.sycamore.ct.letsencrypt.org/2026h1/tile/data/000 | xxd | head -20
```

---

## Round-Trip Verification Results (2026-05-05)

```
Issuers:  51 rows
Subjects: 1000 rows
✓ Subject count matches batch size (1000)
```

Sample issuers:
| ca_id | common_name | organization | country |
|-------|-------------|--------------|---------|
| 1 | Amazon RSA 2048 M02 | Amazon | US |
| 2 | Merge Delay Intermediate 1 | Google UK Ltd. | GB |
| 3 | Microsoft Azure ECC TLS Issuing CA 04 | Microsoft Corporation | US |
| 4 | Amazon RSA 2048 M01 | Amazon | US |
| 5 | GlobalSign Atlas R3 DV TLS CA 2025 Q3 | GlobalSign nv-sa | BE |

Sample subjects (linked to issuers via ca_id):
| common_name | issuer | country |
|-------------|--------|---------|
| *.us-east-1.console.aws.amazon.com | Amazon RSA 2048 M02 | US |
| flowers-to-the-world.com | Merge Delay Intermediate 1 | GB |

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `github.com/google/certificate-transparency-go` | CT types + fallback x509 parser for pre-certs |
| `modernc.org/sqlite` | Pure-Go SQLite (no CGO) |
| `google.golang.org/grpc` | gRPC server/client |
| `google.golang.org/protobuf` | Protocol Buffers |
