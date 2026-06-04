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

# ── 2. wait for the server's flush to drain ─────────────────────────────────
if [ -n "$FORCE" ]; then
  log "FORCE set — skipping flush wait. Hard-killing ct-server (pid $SPID). Un-flushed live-pool data WILL be lost."
else
  log "waiting for ct-server (pid $SPID) flush to complete before stopping it (cap ${FLUSH_MAX_WAIT_SEC}s)"
  start=$(date +%s); quiet=0
  while :; do
    nf="$(newfiles "$SPID")"
    st="$(ps -o state= -p "$SPID" 2>/dev/null | tr -d ' ')"
    [ -z "$st" ] && { log "ct-server exited on its own during the wait"; exit 0; }
    if [ "$nf" -eq 0 ]; then
      quiet=$((quiet+1))
    else
      quiet=0
    fi
    cur="$(find "$ARCHIVE" -name "subjects.db.new.$SPID" 2>/dev/null | sed "s#.*/CT/##;s#/.*##" | tr '\n' ',')"
    log "  flushing=[${cur}] flushfiles=$nf state=$st ssd=$(ssd_free)G quiet=${quiet}/${QUIET_POLLS}"
    [ "$quiet" -ge "$QUIET_POLLS" ] && { log "no flush files for $((QUIET_POLLS*POLL_SEC))s — flush complete"; break; }
    if [ $(( $(date +%s) - start )) -ge "$FLUSH_MAX_WAIT_SEC" ]; then
      log "ERROR: flush still active after ${FLUSH_MAX_WAIT_SEC}s. NOT killing the server (would corrupt the archive)."
      log "       Investigate manually, or re-run with FORCE=1 if you accept the data loss."
      exit 1
    fi
    sleep "$POLL_SEC"
  done
fi

# ── 3. stop ct-server ───────────────────────────────────────────────────────
log "stopping ct-server (pid $SPID)"
pkill -TERM -x ct-server
pkill -TERM -f 'caffeinate -i .*/bin/ct-server' 2>/dev/null
for i in $(seq 1 15); do sleep 1; pgrep -x ct-server >/dev/null || break; done
if pgrep -x ct-server >/dev/null; then
  log "ct-server didn't exit on TERM; sending KILL"
  pkill -KILL -x ct-server
fi
log "CT pipeline stopped. SSD $(ssd_free)G free."
