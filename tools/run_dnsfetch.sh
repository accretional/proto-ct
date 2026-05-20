#!/usr/bin/env bash
# Sequentially fetches DNS records for each shard in ascending size order.
# Reads TSVs from HDD, stages writes on SSD, finalizes DBs to HDD_DNS.
# Resume-safe: skips shards whose final DB already exists.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DNSFETCH="$REPO/bin/dnsfetch"

HDD_SHARDS="${HDD_SHARDS:-/Volumes/wd_office_2/datasets/CT-old/export_v2/shards}"
HDD_DNS="${HDD_DNS:-/Volumes/wd_office_2/datasets/dns}"
STAGING="${STAGING:-$REPO/data/dns-staging}"
WORKERS="${WORKERS:-100}"
QPS="${QPS:-100}"
TIMEOUT="${TIMEOUT:-8s}"
START_FROM="${START_FROM:-}"  # skip shards before this label

log() { echo "[$(date '+%H:%M:%S')] $*"; }

# Map "tld/bucket" → final DB path (mirrors dbName() in store.go).
final_db() {
  local tld="${1%/*}" bucket="${1##*/}"
  [ "$bucket" = "exports" ] && echo "$HDD_DNS/$tld/records.db" \
                             || echo "$HDD_DNS/$tld/$bucket.db"
}

# Shards in ascending domain-count order.
# "tld/exports" = single-file TLD shard; "com/q" etc = com sub-shards.
SHARDS=(
  gov/exports      #    74 690  (done)
  edu/exports      #   365 848
  uk/exports       # 1 545 722
  com/q            # 1 893 288
  app/exports      # 2 243 979
  com/y
  com/x
  dev/exports      # 4 116 759
  com/u
  co/exports       # 4 646 894
  com/z
  com/j
  com/v
  com/0
  com/k
  io/exports       # 14 141 484
  com/n
  com/o
  com/i
  com/w
  com/e
  com/r
  com/g
  com/f
  com/l
  com/d
  com/p
  org/exports      # 21 074 292
  com/b
  com/h
  com/t
  com/c
  com/s
  com/m
  net/exports      # 32 239 119
  com/a
)

mkdir -p "$HDD_DNS" "$REPO/data/logs"
started=false

for shard in "${SHARDS[@]}"; do
  if [ -n "$START_FROM" ] && [ "$shard" != "$START_FROM" ] && [ "$started" = false ]; then
    log "skip $shard (before START_FROM=$START_FROM)"
    continue
  fi
  started=true

  db="$(final_db "$shard")"
  if [ -f "$db" ]; then
    log "skip $shard (already at $db)"
    continue
  fi

  tld="${shard%/*}" bucket="${shard##*/}"
  tsv="$HDD_SHARDS/$tld/${bucket}.tsv"
  if [ ! -f "$tsv" ]; then
    log "skip $shard (source not found: $tsv)"
    continue
  fi

  count=$(wc -l < "$tsv")
  log "=== $shard ($count domains) ==="

  run_log="$REPO/data/logs/${shard//\//-}.log"
  "$DNSFETCH" \
    --shards  "$HDD_SHARDS" \
    --shard   "$shard" \
    --staging "$STAGING" \
    --out     "$HDD_DNS" \
    --workers "$WORKERS" \
    --qps     "$QPS" \
    --timeout "$TIMEOUT" \
    2>&1 | tee "$run_log"

  log "=== done $shard — SSD free: $(df -g "$REPO" | awk 'NR==2{print $4}')GB ==="
done

log "all shards complete"
