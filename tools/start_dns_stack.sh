#!/usr/bin/env bash
# Brings up the local DNS stack used by the dnsfetch pipeline:
#   - unbound on 127.0.0.1:5353 (tools/unbound.conf)
#   - proto-domain server on :50098 with --upstream=127.0.0.1:5353
# Idempotent — re-running won't double-start either component.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROTO_DOMAIN="${PROTO_DOMAIN:-/Users/benfultz/Dev/proto-domain}"
UNBOUND_CONF="$REPO/tools/unbound.conf"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

ensure_unbound() {
  if pgrep -f "unbound -c $UNBOUND_CONF" >/dev/null; then
    log "unbound already running"
    return
  fi
  if ! command -v unbound >/dev/null; then
    log "ERROR: unbound not on PATH (brew install unbound)"
    exit 1
  fi
  log "starting unbound (config: $UNBOUND_CONF)"
  unbound -c "$UNBOUND_CONF" -d >/dev/null 2>&1 &
  sleep 2
  if ! dig @127.0.0.1 -p 5353 +time=3 +tries=1 +short example.com A >/dev/null 2>&1; then
    log "ERROR: unbound failed to answer on 127.0.0.1:5353"
    exit 1
  fi
  log "unbound up"
}

ensure_proto_domain() {
  local addr="${PROTO_DOMAIN_ADDR:-:50098}"
  if pgrep -f "proto-domain/bin/server" >/dev/null; then
    log "proto-domain server already running"
    return
  fi
  if [ ! -x "$PROTO_DOMAIN/bin/server" ]; then
    log "ERROR: $PROTO_DOMAIN/bin/server not found (run build.sh in proto-domain)"
    exit 1
  fi
  log "starting proto-domain server --upstream=127.0.0.1:5353"
  (cd "$PROTO_DOMAIN" && ./bin/server --upstream=127.0.0.1:5353 >/tmp/proto-domain-server.log 2>&1 &)
  sleep 2
  if ! pgrep -f "proto-domain/bin/server" >/dev/null; then
    log "ERROR: proto-domain server failed to start (see /tmp/proto-domain-server.log)"
    exit 1
  fi
  log "proto-domain server up"
}

ensure_unbound
ensure_proto_domain
log "DNS stack ready"
