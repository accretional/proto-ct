#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

# Run tests first (idempotent)
bash test.sh

# ── round-trip parameters ────────────────────────────────────────────────────
BATCH_SIZE=1000
MONITORING_ROOT="https://mon.sycamore.ct.letsencrypt.org/2026h1/tile/data/"
TARGET_QPS=20      # actual = 80% = 16 QPS
SERVER_PORT=50051

# Use the external drive; fall back only if the volume is not mounted at all.
if [ -d "/Volumes/wd_office_2" ]; then
  OUTPUT_DIR="/Volumes/wd_office_2/datasets/CT/"
  mkdir -p "$OUTPUT_DIR"
else
  echo "Note: /Volumes/wd_office_2 not mounted, using /tmp/ct-data/"
  OUTPUT_DIR="/tmp/ct-data/"
fi

RUN_DATE=$(date -u +%Y%m%d)
RUN_DIR="${OUTPUT_DIR}${RUN_DATE}"

mkdir -p "$RUN_DIR"
# Clean previous run's DBs (but keep progress.db for resumption testing)
rm -f "${RUN_DIR}/issuers.db" "${RUN_DIR}/subjects.db"

echo ""
echo "═══════════════════════════════════════════════════════════"
echo " CT Log Ingestion Round-trip"
echo " batch=$BATCH_SIZE  qps=$TARGET_QPS  out=$OUTPUT_DIR"
echo " root=$MONITORING_ROOT"
echo " run_dir=$RUN_DIR"
echo "═══════════════════════════════════════════════════════════"
echo ""

# Start server in background
bin/ct-server --port "$SERVER_PORT" &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null || true' EXIT
sleep 1

echo "Server PID: $SERVER_PID"

# Run client
bin/ct-client \
  --addr "localhost:${SERVER_PORT}" \
  --root "$MONITORING_ROOT" \
  --batch "$BATCH_SIZE" \
  --qps "$TARGET_QPS" \
  --out "$OUTPUT_DIR"

echo ""
echo "═══════════════════════════════════════════════════════════"
echo " Verification"
echo "═══════════════════════════════════════════════════════════"

ISSUER_COUNT=$(sqlite3 "${RUN_DIR}/issuers.db" "SELECT COUNT(*) FROM issuers;" 2>/dev/null || echo "N/A")
SUBJECT_COUNT=$(sqlite3 "${RUN_DIR}/subjects.db" "SELECT COUNT(*) FROM subjects;" 2>/dev/null || echo "N/A")
PROGRESS_RUNS=$(sqlite3 "${OUTPUT_DIR}progress.db" "SELECT COUNT(*) FROM runs;" 2>/dev/null || echo "N/A")
CERT_LOG_COUNT=$(sqlite3 "${OUTPUT_DIR}progress.db" "SELECT COUNT(*) FROM cert_log;" 2>/dev/null || echo "N/A")

echo "Issuers:       $ISSUER_COUNT rows  (${RUN_DIR}/issuers.db)"
echo "Subjects:      $SUBJECT_COUNT rows  (${RUN_DIR}/subjects.db)"
echo "Progress runs: $PROGRESS_RUNS       (${OUTPUT_DIR}progress.db)"
echo "Cert log:      $CERT_LOG_COUNT rows"

if [ "$SUBJECT_COUNT" = "$BATCH_SIZE" ]; then
  echo "✓ Subject count matches batch size ($BATCH_SIZE)"
else
  echo "✗ Subject count $SUBJECT_COUNT ≠ expected $BATCH_SIZE"
fi

echo ""
echo "Sample issuers:"
sqlite3 "${RUN_DIR}/issuers.db" \
  "SELECT ca_id, common_name, organization, country FROM issuers LIMIT 5;" \
  2>/dev/null | column -t -s '|'

echo ""
echo "Sample subjects:"
sqlite3 "${RUN_DIR}/subjects.db" \
  "SELECT id, ca_id, common_name, not_after FROM subjects LIMIT 5;" \
  2>/dev/null | column -t -s '|'

echo ""
echo "CA join check:"
sqlite3 "${RUN_DIR}/subjects.db" \
  "ATTACH '${RUN_DIR}/issuers.db' AS idb;
   SELECT s.id, s.common_name, i.common_name AS issuer, i.country
   FROM subjects s
   JOIN idb.issuers i ON s.ca_id = i.ca_id
   LIMIT 5;" 2>/dev/null | column -t -s '|'

echo ""
echo "Progress / resumption state:"
sqlite3 "${OUTPUT_DIR}progress.db" \
  "SELECT monitoring_root, next_tile_idx, total_processed, updated_at FROM runs;" \
  2>/dev/null | column -t -s '|'

echo ""
echo "Recent cert_log entries:"
sqlite3 "${OUTPUT_DIR}progress.db" \
  "SELECT tile_idx, entry_idx, not_after, ct_log_uri FROM cert_log LIMIT 5;" \
  2>/dev/null | column -t -s '|'

echo ""
echo "═══════════════════════════════════════════════════════════"
echo " Top 10 Parent Domains"
echo "═══════════════════════════════════════════════════════════"
bash tools/top_domains.sh 10 "$OUTPUT_DIR"

echo ""
echo "Round-trip complete."
