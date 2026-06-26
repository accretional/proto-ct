#!/usr/bin/env bash
# reindex_san_shard_test.sh — ISOLATED eTLD+1 partition-fan-out validation (R3).
#
# Builds the SAN->cert index two ways on a CT month snapshot:
#   1. single-file  san_<month>.db            (reference oracle)
#   2. eTLD+1-sharded san_<month>_sharded/     (one DB per (suffix,bucket))
# routes a domain query to its single shard and checks the result matches the
# single-file index, and reports shard-count / skew / PSL-wildcard signal.
#
# Self-contained: own build + run; does NOT touch build.sh/test.sh.
set -euo pipefail
cd "$(dirname "$0")"

DATASETS="${DATASETS:-/Volumes/wd_office_2/datasets}"
SCRATCH=".reindex"
MONTH="${MONTH:-2025-05}"
DMIN="${DEDICATE_MIN:-0}"                 # 0 => per-suffix; >0 => catch-all threshold
SMIN="${SPLIT_MIN:-0}"                    # 0 => only largeTLD split; >0 => split hot suffixes
export REINDEX_SAN_DEDICATE_MIN="$DMIN"
export REINDEX_SAN_SPLIT_MIN="$SMIN"
SRC="$DATASETS/CT/$MONTH/subjects.db"
mkdir -p "$SCRATCH"

SCHEME="per-suffix eTLD+1"
[[ "$DMIN" -gt 0 ]] && SCHEME="dedicate-min=$DMIN"
[[ "$SMIN" -gt 0 ]] && SCHEME="$SCHEME split-min=$SMIN"
echo "=== reindex_san_shard_test (ISOLATED) — month=$MONTH  scheme=$SCHEME ==="
go get modernc.org/sqlite >/dev/null 2>&1 || true
go build -o "$SCRATCH/reindex" ./cmd/reindex
REINDEX="$SCRATCH/reindex"

SNAP="$SCRATCH/ct_$MONTH.db"
if [[ -f "$SNAP" && -s "$SNAP" ]]; then
    echo "  snapshot exists: $SNAP"
else
    [[ -f "$SRC" ]] || { echo "MISSING SOURCE: $SRC"; exit 1; }
    echo "  snapshotting $SRC"
    sqlite3 "file:$SRC?mode=ro" ".backup '$SNAP'" 2>/dev/null \
        || { [[ -f "$SRC-wal" ]] && { echo "active -wal; abort"; exit 1; }; \
             echo "  (static source) immutable snapshot"; sqlite3 "file:$SRC?immutable=1" ".backup '$SNAP'"; }
fi

SAN="$SCRATCH/san_$MONTH.db"
SHARDDIR="$SCRATCH/san_${MONTH}_sharded_d${DMIN}_s${SMIN}"

echo
echo "--- reference: single-file build ---"
if [[ -f "$SAN" ]]; then echo "  reusing $SAN"; else "$REINDEX" build-san "$SNAP" "$SAN"; fi

echo
echo "--- sharded: eTLD+1 fan-out build ---"
rm -rf "$SHARDDIR"
"$REINDEX" build-san-sharded "$SNAP" "$SHARDDIR"

NSHARDS=$(find "$SHARDDIR" -name '*.db' | wc -l | tr -d ' ')
# distinct public suffixes and multi-label (>=3 label) suffixes from filenames.
SUFFIXES=$(find "$SHARDDIR" -name 'san_*.db' -exec basename {} .db \; \
    | sed -E 's/^san_(.*)__[^_]*$/\1/' )
NSUFFIX=$(echo "$SUFFIXES" | sort -u | wc -l | tr -d ' ')
NDEEP=$(echo "$SUFFIXES" | sort -u | awk -F. 'NF>=3' | wc -l | tr -d ' ')
NTINY=$(find "$SHARDDIR" -name '*.db' -size -64k | wc -l | tr -d ' ')
NTAIL=$(find "$SHARDDIR" -name 'san__tail__*.db' | wc -l | tr -d ' ')
echo "  shard files: $NSHARDS   (catch-all tail files: $NTAIL)   distinct public suffixes: $NSUFFIX"
echo "  suffixes with >=3 labels (PSL private/wildcard candidates): $NDEEP"
echo "  near-empty shards (<64KB): $NTINY   single-file size: $(ls -lh "$SAN" | awk '{print $5}')   sharded total: $(du -sh "$SHARDDIR" | awk '{print $1}')"
echo "  largest shards:"; find "$SHARDDIR" -name '*.db' -exec ls -la {} \; | sort -k5 -n | tail -4 | awk '{print "    "$5"  "$NF}'

# If a hot suffix was split, show how its label-char sub-shards distribute.
if [[ "$SMIN" -gt 0 ]]; then
    SPLITSUF="${SPLIT_SUFFIX:-azure-api.net}"
    NSUB=$(find "$SHARDDIR" -name "san_${SPLITSUF}__*.db" | wc -l | tr -d ' ')
    if [[ "$NSUB" -gt 0 ]]; then
        echo "  split of $SPLITSUF -> $NSUB label-char sub-shards; largest:"
        find "$SHARDDIR" -name "san_${SPLITSUF}__*.db" -exec ls -la {} \; | sort -k5 -n | tail -3 | awk '{print "    "$5"  "$NF}'
        if [[ -f "$SHARDDIR/san_${SPLITSUF}__all.db" ]]; then
            echo "    ⚠ $SPLITSUF still has an __all shard (not split)"
        else
            echo "    ✓ $SPLITSUF __all shard is gone (fully split)"
        fi
    fi
fi

echo
echo "--- routing cross-check ---"
REG=$(sqlite3 "file:$SAN?immutable=1" \
    "SELECT reg_domain FROM san_index WHERE reg_domain != '_other' GROUP BY reg_domain ORDER BY count(*) DESC LIMIT 1;")
echo "  busiest registrable domain: $REG"

SINGLE=$("$REINDEX" lookup-san "$SAN" "$REG" | tail -1 | grep -oE '^-- [0-9]+' | grep -oE '[0-9]+')
SHARDED_LINE=$("$REINDEX" lookup-san-sharded "$SHARDDIR" "$REG" | tail -1)
SHARDED=$(echo "$SHARDED_LINE" | grep -oE '^-- [0-9]+' | grep -oE '[0-9]+')
echo "  single-file:  $SINGLE pairs"
echo "  sharded:      $SHARDED_LINE"
if [[ "$SINGLE" == "$SHARDED" ]]; then
    echo "  ✓ sharded routing matches single-file ($SINGLE)"
else
    echo "  ✗ MISMATCH single=$SINGLE sharded=$SHARDED"
fi

echo
echo "=== reindex_san_shard_test complete ==="
