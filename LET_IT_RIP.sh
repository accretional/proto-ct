#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

# Run tests first (idempotent): builds the v2 binaries + runs the unit tests.
bash test.sh

# ── round-trip parameters ────────────────────────────────────────────────────
END=2048           # 256-aligned -> the static frontier covers the whole range
CONCURRENCY=16
SERVER_PORT=50060  # off the default :50052 to avoid colliding with a running server

if [ -d "/Volumes/wd_office_2" ]; then
  OUTPUT_BASE="/Volumes/wd_office_2/ct-v2/_smoke"
else
  echo "Note: /Volumes/wd_office_2 not mounted, using /tmp/ct-v2-smoke/"
  OUTPUT_BASE="/tmp/ct-v2-smoke"
fi
mkdir -p "$OUTPUT_BASE"

# Start the server in the background.
bin/ctv2-server -port "$SERVER_PORT" -out "$OUTPUT_BASE" &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null || true' EXIT
sleep 1
ADDR="localhost:${SERVER_PORT}"

# Pick a usable static log from the live list at runtime (log shards rotate, so
# don't hardcode an id). Prefer a large operator; fall back to any static log.
LOG_ID=$(bin/ctv2 -addr "$ADDR" -mode list 2>/dev/null | awk '$2=="static" && /Encrypt/ {print $1; exit}')
[ -z "$LOG_ID" ] && LOG_ID=$(bin/ctv2 -addr "$ADDR" -mode list 2>/dev/null | awk '$2=="static" {print $1; exit}')
if [ -z "$LOG_ID" ]; then
  echo "✗ no static log found in the log list"; exit 1
fi

OUT="${OUTPUT_BASE}/${LOG_ID}"
rm -rf "$OUT"        # partitions are immutable: start each round-trip clean
mkdir -p "$OUT"

echo ""
echo "═══════════════════════════════════════════════════════════"
echo " proto-ct v2 round-trip"
echo " log_id=${LOG_ID:0:16}…  range=[0,$END)  concurrency=$CONCURRENCY"
echo " server PID=$SERVER_PID  out=$OUT"
echo "═══════════════════════════════════════════════════════════"

# ── fetch the range (writes partitions + issuers/ + roots/) ──────────────────
echo ""
echo "── fetch ──"
bin/ctv2 -addr "$ADDR" -mode fetch -log-id "$LOG_ID" \
  -start 0 -end "$END" -concurrency "$CONCURRENCY" -compress gzip -out "$OUT"

# ── coverage ─────────────────────────────────────────────────────────────────
echo ""
echo "── coverage ──"
bin/ctv2 -addr "$ADDR" -mode coverage -log-id "$LOG_ID" -out "$OUT"

# ── verify a couple of stored entries against the mirrored roots ─────────────
echo ""
echo "── verify ──"
for i in 0 1024; do
  bin/ctv2 -addr "$ADDR" -mode verify -out "$OUT" -index "$i"
  echo ""
done

# ── layout + assertions ──────────────────────────────────────────────────────
echo "── layout ──"
PARTS=$(find "$OUT" -name '*.binpb.gz' | wc -l | tr -d ' ')
ISSUERS=$(find "$OUT/issuers" -name '*.der' 2>/dev/null | wc -l | tr -d ' ')
ROOTS=$(find "$OUT/roots" -name '*.der' 2>/dev/null | wc -l | tr -d ' ')
echo "partitions: $PARTS   issuers: $ISSUERS   roots: $ROOTS"
echo "size: $(du -sh "$OUT" | cut -f1)"

echo ""
STORED=$(bin/ctv2 -addr "$ADDR" -mode coverage -log-id "$LOG_ID" -out "$OUT" 2>/dev/null \
  | awk '/stored entries/{print $4}')
[ "$STORED" = "$END" ] && echo "✓ stored entries match the requested range ($END)" \
                       || { echo "✗ stored entries $STORED ≠ expected $END"; exit 1; }
[ "$ISSUERS" -gt 0 ] && echo "✓ issuer store populated"  || { echo "✗ issuer store empty"; exit 1; }
[ "$ROOTS"   -gt 0 ] && echo "✓ accepted roots mirrored" || { echo "✗ roots store empty"; exit 1; }

echo ""
echo "Round-trip complete."
