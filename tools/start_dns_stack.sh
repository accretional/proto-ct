#!/usr/bin/env bash
# Brings up the proto-domain server with a round-robin pool of public
# recursive resolvers. Idempotent — re-running won't double-start the
# server. unbound is no longer in the path (shelved); tools/unbound.conf
# is kept in the repo for reference if we ever want to restore local
# recursion.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROTO_DOMAIN="${PROTO_DOMAIN:-/Users/benfultz/Dev/proto-domain}"

# 16-endpoint pool: two IPs each across 8 providers. Round-robin
# distribution at the proto-domain server keeps any one provider well
# below its per-source-IP rate ceiling (~1000 q/s for Google, similar
# for others). Override via UPSTREAMS=... if a provider misbehaves.
UPSTREAMS="${UPSTREAMS:-\
8.8.8.8:53,8.8.4.4:53,\
1.1.1.1:53,1.0.0.1:53,\
9.9.9.9:53,149.112.112.112:53,\
208.67.222.222:53,208.67.220.220:53,\
94.140.14.14:53,94.140.15.15:53,\
64.6.64.6:53,64.6.65.6:53,\
4.2.2.1:53,4.2.2.2:53,\
185.228.168.9:53,185.228.169.9:53\
}"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

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
  log "starting proto-domain server with $(echo "$UPSTREAMS" | tr ',' '\n' | wc -l | tr -d ' ') upstreams"
  (cd "$PROTO_DOMAIN" && ./bin/server --upstream="$UPSTREAMS" --upstream-stats-interval=60s >/tmp/proto-domain-server.log 2>&1 &)
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

ensure_proto_domain
log "DNS stack ready"
