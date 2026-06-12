#!/usr/bin/env bash
# Starts the CT ingestion pipeline in the correct order:
#   1. ct-server (gRPC writer) — must be LISTENING before the client dials it
#   2. ct-client (the IngestAll driver) — only after :50051 accepts a connection
#
# Both are wrapped in `caffeinate -i` (keep the Mac awake while ingesting) and
# log to data/logs/. Idempotent-ish: refuses to start a second copy of either.
#
# Safety: ct-client is NOT started unless the SSD has comfortable headroom
# (>MIN_FREE_GB). Restarting ingestion into a near-full SSD re-triggers the
# disk-full crisis the stop/flush machinery exists to avoid.
#
# Usage:  bash tools/ct_start.sh          # server + client
#         SERVER_ONLY=1 bash tools/ct_start.sh   # just the server
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

PORT="${PORT:-50051}"
MIN_FREE_GB="${MIN_FREE_GB:-35}"
EXCLUDE_OPERATORS="${EXCLUDE_OPERATORS:-Geomys}"   # Geomys 429s aggressively; keep excluded
EXCLUDE_DESC="${EXCLUDE_DESC:-Gouda}"              # IPng gouda shards: single-IP 429 wall, not worth it
FETCH_CONC="${FETCH_CONC:-}"                       # per-log prefetch depth; empty = code default (4 rfc6962/2 static)
SERVER_LOG="$REPO/data/logs/ct-server.log"
CLIENT_LOG="$REPO/data/logs/ct-client.log"
SERVER_ONLY="${SERVER_ONLY:-}"

log() { echo "[$(date '+%H:%M:%S')] $*"; }
ssd_free_gb() { df -g "$REPO" | awk 'NR==2{print $4}'; }
listening() { (echo >/dev/tcp/127.0.0.1/"$PORT") >/dev/null 2>&1; }

mkdir -p "$REPO/data/logs"

[ -x "$REPO/bin/ct-server" ] || { log "ERROR: bin/ct-server missing — run the build first"; exit 1; }
[ -x "$REPO/bin/ct-client" ] || { log "ERROR: bin/ct-client missing — run the build first"; exit 1; }

# ── 1. ct-server ──────────────────────────────────────────────────────────
if pgrep -x ct-server >/dev/null; then
  log "ct-server already running (pids $(pgrep -x ct-server | tr '\n' ' '))"
elif listening; then
  log "something already listening on :$PORT — not starting ct-server"
else
  log "starting ct-server on :$PORT"
  caffeinate -i "$REPO/bin/ct-server" --port "$PORT" --log-list-refresh 0 >>"$SERVER_LOG" 2>&1 &
  for i in $(seq 1 30); do
    sleep 1
    listening && break
    [ "$i" = 30 ] && { log "ERROR: ct-server never came up on :$PORT (see $SERVER_LOG)"; exit 1; }
  done
  log "ct-server listening on :$PORT"
fi

[ -n "$SERVER_ONLY" ] && { log "SERVER_ONLY set — done"; exit 0; }

# ── 2. ct-client ──────────────────────────────────────────────────────────
if pgrep -x ct-client >/dev/null; then
  log "ct-client already running (pids $(pgrep -x ct-client | tr '\n' ' ')) — leaving it"
  exit 0
fi

free="$(ssd_free_gb)"
if [ "$free" -lt "$MIN_FREE_GB" ]; then
  log "REFUSING to start ct-client: SSD only ${free}G free (< MIN_FREE_GB=${MIN_FREE_GB}G)."
  log "Let the flush reclaim space first, or override with MIN_FREE_GB=<n>. Server is up; client NOT started."
  exit 1
fi

CLIENT_ARGS=(--all --exclude-operators "$EXCLUDE_OPERATORS")
[ -n "$EXCLUDE_DESC" ] && CLIENT_ARGS+=(--exclude-desc-contains "$EXCLUDE_DESC")
[ -n "$FETCH_CONC" ]   && CLIENT_ARGS+=(--fetch-concurrency "$FETCH_CONC")
log "starting ct-client (${CLIENT_ARGS[*]}); SSD ${free}G free"
caffeinate -i "$REPO/bin/ct-client" "${CLIENT_ARGS[@]}" >>"$CLIENT_LOG" 2>&1 &
sleep 2
pgrep -x ct-client >/dev/null && log "ct-client started (pid $(pgrep -x ct-client | tr '\n' ' '))" \
                              || { log "ERROR: ct-client failed to start (see $CLIENT_LOG)"; exit 1; }
log "CT pipeline up."
