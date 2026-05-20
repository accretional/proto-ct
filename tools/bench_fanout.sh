#!/usr/bin/env bash
# Sweeps worker counts against gov/exports. Each config runs for
# $DURATION, isolated staging dir per run so the skip-set starts empty.
# Set UPSTREAM=127.0.0.1:5353 to point proto-domain at a local resolver.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROTO_DOMAIN="${PROTO_DOMAIN:-/Users/benfultz/Dev/proto-domain}"
SHARDS="${SHARDS:-/Volumes/wd_office_2/datasets/CT-old/export_v2/shards}"
DURATION="${DURATION:-120}"
SHARD="${SHARD:-gov/exports}"
UPSTREAM="${UPSTREAM:-}"

BENCH_DIR=/tmp/dnsfetch-bench
mkdir -p "$BENCH_DIR"
SUMMARY="$BENCH_DIR/summary.tsv"
: > "$SUMMARY"
printf 'workers\tdone\trate\tok\tnxd\ttimeout\terr\terr_pct\n' >> "$SUMMARY"

cleanup() {
  pkill -f "proto-domain/bin/server" 2>/dev/null || true
  pkill -f "proto-ct/bin/dnsfetch" 2>/dev/null || true
  sleep 2
}
trap cleanup EXIT

run_one() {
  local workers=$1
  local tag="w${workers}"
  local staging="$BENCH_DIR/staging-$tag"
  local out="$BENCH_DIR/out-$tag"
  local slog="$BENCH_DIR/server-$tag.log"
  local dlog="$BENCH_DIR/dnsfetch-$tag.log"

  cleanup
  rm -rf "$staging" "$out"

  echo "[$(date '+%H:%M:%S')] === config: workers=$workers ==="

  local upstream_args=()
  if [ -n "$UPSTREAM" ]; then
    upstream_args=(--upstream="$UPSTREAM")
  fi
  "$PROTO_DOMAIN/bin/server" "${upstream_args[@]}" >"$slog" 2>&1 &
  local spid=$!
  sleep 2

  "$REPO/bin/dnsfetch" \
    --shards "$SHARDS" \
    --shard "$SHARD" \
    --staging "$staging" \
    --out "$out" \
    --workers "$workers" \
    --qps 9999 \
    --timeout 8s \
    --metrics-interval 20s \
    >"$dlog" 2>&1 &
  local dpid=$!

  sleep "$DURATION"

  kill -INT $dpid 2>/dev/null || true
  sleep 2
  kill $spid 2>/dev/null || true
  sleep 1

  local last=$(grep "metrics:" "$dlog" | tail -1)
  if [ -z "$last" ]; then
    echo "  no metrics line — check $dlog"
    return
  fi
  echo "  $last"

  # Parse: "metrics: done=X rate=Y.Y/s ok=A nxd=B timeout=C err=D(E.E%) cb=…"
  local done=$(echo "$last" | grep -oE "done=[0-9]+" | head -1 | cut -d= -f2)
  local rate=$(echo "$last" | grep -oE "rate=[0-9.]+" | head -1 | cut -d= -f2)
  local ok=$(echo "$last" | grep -oE "ok=[0-9]+" | head -1 | cut -d= -f2)
  local nxd=$(echo "$last" | grep -oE "nxd=[0-9]+" | head -1 | cut -d= -f2)
  local to=$(echo "$last" | grep -oE "timeout=[0-9]+" | head -1 | cut -d= -f2)
  local err=$(echo "$last" | grep -oE "err=[0-9]+" | head -1 | cut -d= -f2)
  local errpct=$(echo "$last" | grep -oE "\([0-9.]+%\)" | tr -d '()%')

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$workers" "$done" "$rate" "$ok" "$nxd" "$to" "$err" "$errpct" \
    >> "$SUMMARY"
}

# WORKERS is a space-separated list, defaults to a small sweep.
WORKERS="${WORKERS:-100 200 400 800}"
for w in $WORKERS; do
  run_one "$w"
done

echo ""
echo "=== summary ==="
column -t -s $'\t' "$SUMMARY"
