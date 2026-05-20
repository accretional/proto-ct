#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

# Run setup first (idempotent)
bash setup.sh

echo "Building binaries..."
mkdir -p bin

go build -o bin/ct-server ./cmd/server
echo "✓ bin/ct-server"

go build -o bin/ct-client ./cmd/client
echo "✓ bin/ct-client"

go build -o bin/monitor ./cmd/monitor
echo "✓ bin/monitor"

echo "Build complete."
