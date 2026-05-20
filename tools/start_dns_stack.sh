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
  # Liveness is "port 50098 accepts a TCP connection," not "a matching
  # process exists." A graceful-shutdown of an old server can keep its
  # cmdline visible to pgrep for several seconds after it has stopped
  # listening — a positive port check avoids that race.
  if (echo >/dev/tcp/127.0.0.1/50098) >/dev/null 2>&1; then
    log "proto-domain server already listening on :50098"
    return
  fi
  if [ ! -x "$PROTO_DOMAIN/bin/server" ]; then
    log "ERROR: $PROTO_DOMAIN/bin/server not found (run build.sh in proto-domain)"
    exit 1
  fi
  log "starting proto-domain server --upstream=127.0.0.1:5353"
  (cd "$PROTO_DOMAIN" && ./bin/server --upstream=127.0.0.1:5353 >/tmp/proto-domain-server.log 2>&1 &)
  for i in 1 2 3 4 5; do
    sleep 1
    if (echo >/dev/tcp/127.0.0.1/50098) >/dev/null 2>&1; then
      log "proto-domain server up"
      return
    fi
  done
  log "ERROR: proto-domain server did not start listening on :50098 (see /tmp/proto-domain-server.log)"
  exit 1
}

ensure_unbound
ensure_proto_domain
log "DNS stack ready"
