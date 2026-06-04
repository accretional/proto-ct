#!/usr/bin/env bash
# Stops the DNS fetch pipeline. The dnsfetch runner is resume-safe (it skips
# shards whose final DB exists and re-runs an interrupted shard from scratch),
# so stopping it is low-risk — an in-flight shard's SSD staging is discarded and
# redone on the next start.
#
# By default this leaves the proto-domain resolver (:50098) UP, since it is a
# shared dependency and cheap to keep. Pass STOP_RESOLVER=1 to stop it too.
#
# Usage:  bash tools/dns_stop.sh
#         STOP_RESOLVER=1 bash tools/dns_stop.sh
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STOP_RESOLVER="${STOP_RESOLVER:-}"
log() { echo "[$(date '+%H:%M:%S')] $*"; }

if pgrep -f run_dnsfetch.sh >/dev/null || pgrep -f 'bin/dnsfetch' >/dev/null; then
  log "stopping dnsfetch runner + worker"
  pkill -TERM -f 'caffeinate -i .*run_dnsfetch.sh' 2>/dev/null
  pkill -TERM -f run_dnsfetch.sh 2>/dev/null
  pkill -TERM -f 'bin/dnsfetch'  2>/dev/null
  for i in $(seq 1 15); do sleep 1; pgrep -f 'bin/dnsfetch' >/dev/null || break; done
  pgrep -f 'bin/dnsfetch' >/dev/null && { log "worker still alive; KILL"; pkill -KILL -f 'bin/dnsfetch'; }
  log "dnsfetch stopped"
else
  log "dnsfetch not running"
fi

if [ -n "$STOP_RESOLVER" ]; then
  if (echo >/dev/tcp/127.0.0.1/50098) >/dev/null 2>&1; then
    log "stopping proto-domain resolver (:50098)"
    pkill -TERM -f 'bin/server --upstream' 2>/dev/null
    log "proto-domain stopped"
  else
    log "proto-domain not listening"
  fi
else
  log "leaving proto-domain resolver up (STOP_RESOLVER=1 to stop it)"
fi
