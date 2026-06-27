# proto-ct — Certificate Transparency archiver

Tools for mirroring [Certificate Transparency](https://certificate.transparency.dev/) logs to local
storage. The repository contains two generations:

- **proto-ct v2** (current) — a stateless, range-addressable **raw-leaf archiver**. This README
  covers it.
- **proto-ct v1** (legacy) — the original single-host mirror that parses certs into month-sharded
  SQLite. Preserved in [README_v1.md](README_v1.md).

---

## proto-ct v2

### What it is

v2 fetches a half-open entry range `[start, end)` from a CT log and writes the log's raw Merkle
leaves to disk, partitioned by time and index, with deduplicated issuer and accepted-root
certificates stored alongside. All cert/subject parsing is deferred to later tools.

Each fetch is an independent unit of work — **no shared writer, no merge or flush step** — so jobs
fan out across hosts and ranges, with an external orchestrator assigning ranges.

Both CT APIs are supported and unified: **RFC 6962** (`get-entries`) and **static-ct-api** (tiles)
produce identical on-disk output.

### Storage layout

One directory tree per log (the caller owns the top-level prefix, conventionally the hex log id):

```
<output_root>/
├── <YYYY-MM-DD>/<first>-<last>.binpb[.gz]   # raw leaves (RawLogEntryBatch), partitioned by leaf day + index
├── issuers/<sha256-hex>.der                 # each unique issuer-chain cert, once (content-addressed)
└── roots/<sha256-hex>.der                   # the log's accepted roots (trust anchors)
```

Each record (`RawLogEntry`) is minimal and protocol-uniform: the raw `leaf_input` (TLS
`MerkleTreeLeaf`) + `chain_fingerprints` (SHA-256 of each issuer cert, resolved through `issuers/`)
and precert fields. See **[docs/v2_storage_format.md](docs/v2_storage_format.md)** for the full format.

### Components

| Path | Role |
|---|---|
| `cmd/ctv2-server` | gRPC server (default `:50052`, gRPC reflection enabled) |
| `cmd/ctv2` | CLI: range jobs + maintenance/inspection (dials the server) |
| `internal/ctv2` | implementation (fetchers, partition writer, issuer/root stores, verify) |
| `proto/ctingestion/v2` | service definition → `gen/ctingestion/v2` |

### gRPC API — `CTIngestionService`

| RPC | Purpose |
|---|---|
| `GetLogEntries` | Fetch a range and write partitions. Resolves issuer certs and mirrors the log's roots automatically. |
| `GetLogList` | Current CT log catalogue (default: Google's v3 `log_list.json`). |
| `GetSTH` | The log's current signed tree head / checkpoint. |
| `CheckCoverage` | How much of a log is on disk — derived from partition filenames, no progress DB. Optional gaps + live-STH coverage %. |
| `ResolveIssuers` | Standalone backfill of the issuer store for a static log. |
| `MirrorRoots` | Fetch the log's accepted roots (`get-roots`) into `roots/`. |
| `VerifyEntry` | Validate an entry's chain fully offline: leaf + issuer store + mirrored roots. |

### Remote gRPC clients (no CLI)

The server exposes the full API over gRPC with **reflection enabled**, so any gRPC client can drive
it without the `ctv2` CLI or the `.proto` files. The walkthrough below uses
[`grpcurl`](https://github.com/fullstorydev/grpcurl); a Go/Python/… client using reflection or the
generated stubs makes the same calls.

Conventions: requests are proto3 JSON (field names are **lowerCamelCase**); `bytes` fields
(`logId`, `publicKey`) are **base64**. `outputRoot` is a path on the **server's** filesystem — the
server reads and writes the archive, not the client. The server listens on `:50052` plaintext.

```bash
HOST=server.example:50052
SVC=ctingestion.v2.CTIngestionService
```

**1. Discover the service (reflection).**

```bash
grpcurl -plaintext $HOST list                 # services
grpcurl -plaintext $HOST list $SVC            # RPCs
grpcurl -plaintext $HOST describe $SVC.GetLogEntriesRequest   # message schema
```

**2. Fetch the log list** (`GetLogList`) and **3. select a log by id**. Each log carries a base64
`logId`, a `protocol`, and its URLs; pick one and reuse its `logId` everywhere below:

```bash
grpcurl -plaintext -d '{}' $HOST $SVC/GetLogList \
  | jq -r '.operators[].logs[]
           | select(.protocol=="LOG_PROTOCOL_STATIC_CT_API")
           | "\(.logId)\t\(.description // .monitoringUrl)"'
# -> AnVk7P...=    Let's Encrypt 'Sycamore2026h2'
ID='AnVk7P...='    # the base64 logId you picked
```

(Or skip the list and select explicitly: `"log":{"monitoringUrl":"<base>","protocol":"LOG_PROTOCOL_RFC6962"}`,
adding `"publicKey":"<base64 DER SPKI>"` for static logs.)

**4. Current tree size (`GetSTH`) and local status (`CheckCoverage`).**

```bash
grpcurl -plaintext -d '{"log":{"logId":"'$ID'"}}' $HOST $SVC/GetSTH
# -> { "treeSize": "306003337", "timestamp": "...", ... }

grpcurl -plaintext -d '{"log":{"logId":"'$ID'"},"outputRoot":"/data/ct-v2/mylog",
  "querySth":true,"includeGaps":true}' $HOST $SVC/CheckCoverage
# -> { "treeSize", "storedEntries", "contiguousThrough", "coveragePct", "gaps":[{"start","end"}] }
```

`CheckCoverage` is derived from the files on disk (no progress DB); use its `gaps` to plan or resume.

**5. Ingestion — range requests (`GetLogEntries`).** One call fetches `[startIndex, endIndex)`,
writes the partitions, and auto-resolves issuers + mirrors roots. It is a self-contained unit of
work, so an orchestrator splits a log into ranges and issues them independently (and across hosts):

```bash
grpcurl -plaintext -d '{
  "log": {"logId":"'$ID'"},
  "startIndex": 0, "endIndex": 1048576,
  "fetchConcurrency": 32, "pageSize": 256,
  "compression": "COMPRESSION_GZIP",
  "outputRoot": "/data/ct-v2/mylog"
}' $HOST $SVC/GetLogEntries
# -> { "entriesWritten", "bytesWritten", "firstIndex", "lastIndex" }
```

Patterns:
- **Chunk** `[0, treeSize)` into fixed ranges (e.g. 1,048,576). Keep boundaries **256-aligned** for
  static logs and DigiCert/Sectigo.
- **Tune per provider** with `fetchConcurrency`, `targetQps`, `disableKeepAlive` (see the tuning doc).
- **Resume** by re-issuing `GetLogEntries` for the `gaps` from `CheckCoverage`. Partitions are
  immutable — re-fetching an already-written range into the same `outputRoot` errors, so fetch only
  the missing ranges (or use a fresh `outputRoot`).

**6. Chain verification.** `GetLogEntries` already populates `issuers/` and `roots/`; to refresh or
backfill them explicitly, then validate an entry's chain fully offline:

```bash
grpcurl -plaintext -d '{"log":{"logId":"'$ID'"},"outputRoot":"/data/ct-v2/mylog"}' $HOST $SVC/MirrorRoots
grpcurl -plaintext -d '{"log":{"logId":"'$ID'"},"outputRoot":"/data/ct-v2/mylog"}' $HOST $SVC/ResolveIssuers

grpcurl -plaintext -d '{"outputRoot":"/data/ct-v2/mylog","index":1024}' $HOST $SVC/VerifyEntry
# -> { "valid":true, "leafSubject", "chainSubjects":[...], "anchorSubject", "withinValidity" }
```

`VerifyEntry` rebuilds the chain from the leaf + the local `issuers/` store and checks the signature
path terminates at a mirrored accepted root in `roots/`. `MirrorRoots`/`ResolveIssuers` are only
needed for an explicit refresh or to backfill data ingested elsewhere.

### Quick start

**Requirements:** Go 1.26. (`protoc` + `protoc-gen-go` / `protoc-gen-go-grpc` only to regenerate
protos; the generated code is committed.)

```bash
# Build everything (v2 binaries first, then the legacy v1 ones)
bash build.sh
# or just the v2 binaries:
#   go build -o bin/ctv2-server ./cmd/ctv2-server
#   go build -o bin/ctv2        ./cmd/ctv2

# Start the server
./bin/ctv2-server -out /data/ct-v2

# Discover logs / inspect a tree head
./bin/ctv2 -mode list
./bin/ctv2 -mode sth -log-id <hex>

# Fetch a range of one log -> writes partitions + issuers/ + roots/
./bin/ctv2 -mode fetch -log-id <hex> -start 0 -end 102400 \
  -concurrency 64 -compress gzip -out /data/ct-v2/<hex>

# Check coverage, then validate a stored entry's chain offline
./bin/ctv2 -mode coverage -log-id <hex> -out /data/ct-v2/<hex>
./bin/ctv2 -mode verify   -index 5000   -out /data/ct-v2/<hex>
```

### CLI modes

| `-mode` | Does |
|---|---|
| `fetch` | Fetch `[start, end)` of a log and write it (issuers + roots resolved automatically). |
| `list` | Print the CT log catalogue (id, protocol, operator, URL). |
| `sth` | Print a log's current tree size / checkpoint. |
| `coverage` | Report stored entries, contiguous range, gaps, and (with `-coverage-sth`) live coverage %. |
| `resolve-issuers` | Backfill missing issuer certs for a static log's output root. |
| `mirror-roots` | (Re-)mirror a log's accepted roots. |
| `verify` | Validate the chain of entry `-index N` against the local issuer + root stores. |

### Selecting a log

- **By id:** `-log-id <hex>` — resolved against the cached log list (supplies URL, protocol, key).
- **Explicitly:** `-url <base> -protocol rfc6962|static|tiles` (add `-pubkey <base64 DER SPKI>` for
  static logs to verify the checkpoint). `tiles` is the checkpoint-free static tile front-end some
  RFC 6962 logs expose.

### Tuning

Throughput knobs are exposed per request: `-concurrency`, `-qps`, `-page-size`, `-compress`,
`-granularity`, and `-no-keepalive`. CT operators differ a lot in rate-limiting behaviour — see
**[docs/v2_request_tuning.md](docs/v2_request_tuning.md)** for per-provider recommendations
(e.g. DigiCert needs `-no-keepalive`, Cloudflare a low `-qps`, TrustAsia the tile front-end).

### Build & test scripts

| Script | Does |
|---|---|
| `setup.sh` | Check Go, install protoc plugins, regenerate proto stubs (v2 + v1), `go mod tidy`. |
| `build.sh` | `setup.sh` + compile all binaries to `bin/`. |
| `test.sh` | `build.sh` + `go test ./...`. |
| `LET_IT_RIP.sh` | End-to-end round-trip: fetch a small live range, then check coverage and verify a chain. |

---

## proto-ct v1 (legacy)

The original implementation: a gRPC service that downloads static-ct-api tiles, parses X.509
certs, and writes them to SQLite partitioned by certificate issuance month, behind a single writer
with an SSD→HDD flush. It still builds (`bash build.sh` → `bin/ct-server`, `bin/ct-client`, …) and
its documentation is preserved verbatim in **[README_v1.md](README_v1.md)**.

v2 was written to replace v1's flush-bound central-writer model with stateless, fan-out range jobs.

## Repository layout

```
proto-ct/
├── cmd/
│   ├── ctv2-server/   ctv2/        # v2: server + CLI
│   └── server/ client/ export/ …   # v1: SQLite mirror (see README_v1.md)
├── internal/
│   ├── ctv2/                       # v2 implementation
│   └── ctlog/ db/ ingestion/       # v1 implementation
├── proto/ctingestion/{v1,v2}/      # protobuf service definitions
├── gen/ctingestion/{v1,v2}/        # generated Go
└── docs/                           # v2_storage_format.md, v2_request_tuning.md, …
```

## License

MIT — see [LICENSE](LICENSE).
