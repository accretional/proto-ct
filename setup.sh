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
PROTO_OUT_DIR="gen/ctingestion/v1"
mkdir -p "$PROTO_OUT_DIR"

PROTO_SRC="proto/ctingestion/v1/ingestion.proto"
GEN_FILES=("${PROTO_OUT_DIR}/ingestion.pb.go" "${PROTO_OUT_DIR}/ingestion_grpc.pb.go")
NEED_GEN=false
for f in "${GEN_FILES[@]}"; do
  if [ ! -f "$f" ] || [ "$PROTO_SRC" -nt "$f" ]; then
    NEED_GEN=true; break
  fi
done

if $NEED_GEN; then
  echo "Generating gRPC code from proto..."
  protoc \
    --proto_path=proto \
    --go_out=gen \
    --go_opt=paths=source_relative \
    --go-grpc_out=gen \
    --go-grpc_opt=paths=source_relative \
    "$PROTO_SRC"
  echo "✓ Proto generated"
else
  echo "✓ Proto up-to-date"
fi

# ── go mod tidy ──────────────────────────────────────────────────────────────
if [ ! -f go.sum ] || [ go.mod -nt go.sum ]; then
  echo "Running go mod tidy..."
  go mod tidy
  echo "✓ go mod tidy"
else
  echo "✓ go.sum up-to-date"
fi
