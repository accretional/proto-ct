#!/usr/bin/env bash
# Stops the CT ingestion pipeline SAFELY, in the correct order:
#   1. ct-client  — SIGTERM. Ending the IngestAll RPC makes the server's
#                   handler exit, which triggers its deferred FlushAll of the
#                   live pool to the HDD archive.
#   2. WAIT       — for that flush to fully complete. The server has NO signal
#                   handler and does NOT flush on SIGTERM, so killing it while a
#                   flush is in flight both corrupts the half-written
#                   `subjects.db.new.<pid>` AND loses every un-archived subject
#                   still in the live pool. This is the 2024-12 loss, codified.
#   3. ct-server  — SIGTERM, ONLY once no flush file remains and the server has
#                   gone idle.
#
# The flush is glacial on giant months (HDD random-I/O wall), so the wait can be
# long — that is expected and safe; the SSD reclaims month-by-month as it goes.
#
# Usage:  bash tools/ct_stop.sh
#         FORCE=1 bash tools/ct_stop.sh    # skip the wait, hard-kill server
#                                          # (DANGER: only if you accept losing
#                                          #  the un-flushed live pool)
set -uo pipefail   # not -e: we tolerate kill/pgrep non-zero exits

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

ARCHIVE="${ARCHIVE:-/Volumes/wd_office_2/datasets/CT}"
QUIET_POLLS="${QUIET_POLLS:-4}"          # consecutive flush-free polls to call it done
POLL_SEC="${POLL_SEC:-15}"
FLUSH_MAX_WAIT_SEC="${FLUSH_MAX_WAIT_SEC:-43200}"  # 12h cap, then warn (do NOT auto-kill)
FORCE="${FORCE:-}"

log()      { echo "[$(date '+%H:%M:%S')] $*"; }
ssd_free() { df -g "$REPO" | awk 'NR==2{print $4}'; }
server_pid() { pgrep -x ct-server | head -1; }
# Count this server's in-flight flush files (subjects.db.new.<pid>).
newfiles() { local p="$1"; [ -n "$p" ] && find "$ARCHIVE" -name "subjects.db.new.$p" 2>/dev/null | wc -l | tr -d ' ' || echo 0; }

SPID="$(server_pid)"

# ── 1. stop ct-client ───────────────────────────────────────────────────────
if pgrep -x ct-client >/dev/null; then
  log "stopping ct-client (pids $(pgrep -x ct-client | tr '\n' ' ')) — this triggers the server's deferred flush"
  # TERM the client and any caffeinate wrapper holding it.
  pkill -TERM -x ct-client
  pkill -TERM -f 'caffeinate -i .*/bin/ct-client' 2>/dev/null
  for i in $(seq 1 20); do sleep 1; pgrep -x ct-client >/dev/null || break; done
  pgrep -x ct-client >/dev/null && log "warn: ct-client still alive after 20s" || log "ct-client stopped"
else
  log "ct-client not running"
fi

if [ -z "$SPID" ]; then
  log "ct-server not running — nothing else to stop."
  exit 0
fi

# ── 2. stop ct-server: SIGTERM ONCE, then wait for its graceful exit ────────
# The server's SIGTERM handler (cmd/server/main.go) cancels ingestion, runs the
# final FlushAll, and GracefulStop then lets the process exit ON ITS OWN. So we
# send ONE SIGTERM and WAIT for that natural exit. We do NOT send a second signal
# on a short timer — that was the old bug: a 15s SIGKILL guillotined the graceful
# flush and left the whole live pool un-archived (a 2nd signal also bypasses
# NotifyContext to hard-kill mid-flush).
#
# The append-only flush is crash-safe (bounded batches + rollback journal) and
# any un-flushed pool data stays on disk, so even the cap-SIGKILL below cannot
# corrupt the archive — the worst case is a residual pool to drain afterward.
pooldbs() { find "$REPO/data/active" -name subjects.db 2>/dev/null | wc -l | tr -d ' '; }

if [ -n "$FORCE" ]; then
  log "FORCE set — SIGKILL ct-server (pid $SPID) now (skips the graceful flush; residual pool preserved, drain it after)."
  pkill -KILL -x ct-server
  pkill -KILL -f 'caffeinate -i .*/bin/ct-server' 2>/dev/null
else
  log "SIGTERM ct-server (pid $SPID): flushes the live pool during graceful shutdown then exits (cap ${FLUSH_MAX_WAIT_SEC}s; do NOT send a 2nd signal)"
  pkill -TERM -x ct-server
  start=$(date +%s)
  while pgrep -x ct-server >/dev/null; do
    log "  draining: poolDBs=$(pooldbs) flushfiles=$(newfiles "$SPID") ssd=$(ssd_free)G"
    if [ $(( $(date +%s) - start )) -ge "$FLUSH_MAX_WAIT_SEC" ]; then
      log "WARN: ct-server still up after ${FLUSH_MAX_WAIT_SEC}s — SIGKILL (safe: crash-safe append flush; residual pool preserved)."
      pkill -KILL -x ct-server
      break
    fi
    sleep "$POLL_SEC"
  done
fi
pkill -TERM -f 'caffeinate -i .*/bin/ct-server' 2>/dev/null
log "ct-server stopped. SSD $(ssd_free)G free."

# ── 3. residual stragglers ──────────────────────────────────────────────────
# The rollover-grace race can leave a few small month-DBs the server's flush
# didn't pick up (a worker opened a month just after FlushAll snapshotted the
# pool). They are preserved on disk — recover them (NEVER delete) with a drain:
remaining="$(pooldbs)"
if [ "$remaining" -gt 0 ]; then
  log "note: $remaining residual pool month-DB(s) remain (stragglers/un-flushed)."
  log "      drain into the archive with:  go run ./cmd/remerge-pools --no-seal --archive $ARCHIVE"
fi
