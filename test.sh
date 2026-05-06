#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

# Run build first (idempotent)
bash build.sh

echo "Running tests..."
go test ./... -count=1 -timeout 60s
echo "✓ All tests passed"
