#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

# ── Go version check ────────────────────────────────────────────────────────
REQUIRED_GO="1.26"
if ! go version 2>/dev/null | grep -q "go${REQUIRED_GO}"; then
  echo "ERROR: Go ${REQUIRED_GO} required (found: $(go version 2>/dev/null || echo 'none'))"
  exit 1
fi
echo "✓ Go $(go version | awk '{print $3}')"

# ── protoc plugins ──────────────────────────────────────────────────────────
if ! command -v protoc-gen-go &>/dev/null; then
  echo "Installing protoc-gen-go..."
  go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
fi
if ! command -v protoc-gen-go-grpc &>/dev/null; then
  echo "Installing protoc-gen-go-grpc..."
  go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
fi
echo "✓ protoc plugins"

# ── generate proto code ──────────────────────────────────────────────────────
# Regenerate a proto group only when a source is newer than its generated code.
# $1 = a representative generated file to stat against; $2.. = proto sources.
gen_proto() {
  local marker="$1"; shift
  local need=false src
  [ -f "$marker" ] || need=true
  for src in "$@"; do
    [ "$src" -nt "$marker" ] && need=true
  done
  if $need; then
    echo "Generating ${*}..."
    protoc \
      --proto_path=proto \
      --go_out=gen \
      --go_opt=paths=source_relative \
      --go-grpc_out=gen \
      --go-grpc_opt=paths=source_relative \
      "$@"
  fi
}

mkdir -p gen/ctingestion/v2 gen/ctingestion/v1

# v2 (current): the raw-leaf archiver service.
gen_proto gen/ctingestion/v2/ingestion.pb.go \
  proto/ctingestion/v2/ingestion.proto \
  proto/ctingestion/v2/log_list.proto

# v1 (legacy): the SQLite mirror service.
gen_proto gen/ctingestion/v1/ingestion.pb.go \
  proto/ctingestion/v1/ingestion.proto

echo "✓ Proto up-to-date"

# ── go mod tidy ──────────────────────────────────────────────────────────────
if [ ! -f go.sum ] || [ go.mod -nt go.sum ]; then
  echo "Running go mod tidy..."
  go mod tidy
  echo "✓ go mod tidy"
else
  echo "✓ go.sum up-to-date"
fi
