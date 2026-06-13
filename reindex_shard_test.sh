#!/usr/bin/env bash
# reindex_shard_test.sh — ISOLATED partition-fan-out validation for R1.
#
# Builds the IP->domain reverse index two ways on a mid-size TLD snapshot:
#   1. single-file  rev_<tld>.db          (reference oracle)
#   2. /16-sharded  rev_<tld>_sharded/    (one DB per /16)
# then routes CIDR queries of increasing width across the shards and checks the
# sharded results match the single-file index exactly.
#
# Self-contained: own build + run, does NOT touch build.sh/test.sh. Snapshot via
# online backup (.backup), safe alongside the live bootstrap.
set -euo pipefail
cd "$(dirname "$0")"

DATASETS="${DATASETS:-/Volumes/wd_office_2/datasets}"
SCRATCH=".reindex"
TLD="${TLD:-uk}"                         # mid-size: uk (~740MB) or io (~4.5GB)
# DNS_SRC overrides the source DB (e.g. a single com bucket: dns/com/g.db);
# LABEL names the snapshot/output so distinct sources don't collide.
SRC="${DNS_SRC:-$DATASETS/dns/$TLD/records.db}"
LABEL="${LABEL:-$TLD}"
SB="${SB:-2}"                            # shard width in bytes: 2 => /16, 1 => /8
IPSPLIT="${IP_SPLIT_MIN:-0}"             # >0 => split hot base shards one byte finer
export REINDEX_SHARD_BYTES="$SB"
export REINDEX_IP_SPLIT_MIN="$IPSPLIT"
case "$SB" in 1) WIDTH="/8";; 2) WIDTH="/16";; *) echo "SB must be 1 or 2"; exit 1;; esac
[[ "$IPSPLIT" -gt 0 ]] && WIDTH="$WIDTH split-min=$IPSPLIT"
mkdir -p "$SCRATCH"

echo "=== reindex_shard_test (ISOLATED) — src=$LABEL  shard=$WIDTH ==="
go get modernc.org/sqlite >/dev/null 2>&1 || true
go build -o "$SCRATCH/reindex" ./cmd/reindex
REINDEX="$SCRATCH/reindex"

SNAP="$SCRATCH/dns_$LABEL.db"
if [[ -f "$SNAP" && -s "$SNAP" ]]; then
    echo "  snapshot exists: $SNAP"
else
    [[ -f "$SRC" ]] || { echo "MISSING SOURCE: $SRC"; exit 1; }
    rm -f "$SNAP"
    echo "  snapshotting $SRC (online backup)"
    # Prefer mode=ro (safe alongside a live writer). Delete-mode DBs on the
    # external volume reject the ro lock path (err 14); for those, fall back to
    # immutable only after confirming the source is static (no -wal).
    if ! sqlite3 "file:$SRC?mode=ro" ".backup '$SNAP'" 2>/dev/null; then
        rm -f "$SNAP"
        [[ -f "$SRC-wal" ]] && { echo "  ERROR: $SRC has an active -wal; refusing immutable"; exit 1; }
        echo "  (static source) immutable snapshot"
        sqlite3 "file:$SRC?immutable=1" ".backup '$SNAP'"
    fi
fi

REV="$SCRATCH/rev_$LABEL.db"
SHARDDIR="$SCRATCH/rev_${LABEL}_sharded_b${SB}"

echo
echo "--- reference: single-file build ---"
if [[ -f "$REV" ]]; then
    echo "  reusing existing single-file index: $REV"
else
    "$REINDEX" build-ip "$SNAP" "$REV"
fi

echo
echo "--- sharded: $WIDTH fan-out build ---"
rm -rf "$SHARDDIR"
"$REINDEX" build-ip-sharded "$SNAP" "$SHARDDIR"
NSHARDS=$(find "$SHARDDIR" -name '*.db' | wc -l | tr -d ' ')
V4SHARDS=$(find "$SHARDDIR" -name 'v4_*.db' | wc -l | tr -d ' ')
V6SHARDS=$(find "$SHARDDIR" -name 'v6_*.db' | wc -l | tr -d ' ')
echo "  shard files: $NSHARDS  (v4=$V4SHARDS v6=$V6SHARDS)"
echo "  single-file size: $(ls -lh "$REV" | awk '{print $5}')   sharded total: $(du -sh "$SHARDDIR" | awk '{print $1}')"
echo "  largest shards:"; find "$SHARDDIR" -name '*.db' -exec ls -la {} \; | sort -k5 -n | tail -3 | awk '{print "    "$5"  "$NF}'

# Hottest IP -> derive CIDRs of increasing width around it.
HOT_IP=$(sqlite3 "file:$SNAP?immutable=1" \
    "SELECT ipv4 FROM dns_records_a GROUP BY ipv4 ORDER BY count(*) DESC LIMIT 1;")
O1=$(echo "$HOT_IP" | cut -d. -f1); O2=$(echo "$HOT_IP" | cut -d. -f2); O3=$(echo "$HOT_IP" | cut -d. -f3)
echo
echo "--- routing across widths (hot IP $HOT_IP) ---"

# count_single CIDR -> count from single-file index
count_single() { "$REINDEX" lookup-cidr "$REV" "$1" | tail -1 | grep -oE '[0-9]+ domain' | grep -oE '[0-9]+'; }

check_cidr() {
    local cidr="$1"
    local sharded_line single_cnt sharded_cnt
    sharded_line=$("$REINDEX" lookup-cidr-sharded "$SHARDDIR" "$cidr" | tail -1)
    sharded_cnt=$(echo "$sharded_line" | grep -oE '^-- [0-9]+' | grep -oE '[0-9]+')
    single_cnt=$(count_single "$cidr")
    printf "  %-18s %s\n" "$cidr" "$sharded_line"
    if [[ "$sharded_cnt" == "$single_cnt" ]]; then
        echo "                     ✓ matches single-file index ($single_cnt)"
    else
        echo "                     ✗ MISMATCH sharded=$sharded_cnt single=$single_cnt"
    fi
}

check_cidr "$O1.$O2.$O3.0/24"
check_cidr "$O1.$O2.0.0/16"
check_cidr "$O1.$O2.0.0/14"
check_cidr "$O1.0.0.0/8"

echo
echo "=== reindex_shard_test complete ==="
