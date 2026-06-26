#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

# Run setup first (idempotent)
bash setup.sh

echo "Building binaries..."
mkdir -p bin

# ── proto-ct v2 (current): raw-leaf archiver ─────────────────────────────────
go build -o bin/ctv2-server ./cmd/ctv2-server
echo "✓ bin/ctv2-server"

go build -o bin/ctv2 ./cmd/ctv2
echo "✓ bin/ctv2"

# ── proto-ct v1 (legacy): SQLite mirror — see README_v1.md ────────────────────
go build -o bin/ct-server ./cmd/server
echo "✓ bin/ct-server"

go build -o bin/ct-client ./cmd/client
echo "✓ bin/ct-client"

go build -o bin/ct-export ./cmd/export
echo "✓ bin/ct-export"

# DEPRECATED (work complete): one-time tile→YYYY-MM migration tool, kept for
# reference. Still built so it stays compiling; not used by the live pipeline.
go build -o bin/ct-repartition ./cmd/repartition
echo "✓ bin/ct-repartition"

go build -o bin/dnsfetch ./cmd/dnsfetch
echo "✓ bin/dnsfetch"

go build -o bin/monitor ./cmd/monitor
echo "✓ bin/monitor"

echo "Build complete."
