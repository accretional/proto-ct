#!/usr/bin/env bash
# reindex_validate.sh — ISOLATED prototype validation for the planned reverse
# indexes (R1 IP->domain, R3 SAN->cert) from docs/query-patterns.md.
#
# Deliberately self-contained: it does its own targeted `go build ./cmd/reindex`
# and run, and does NOT touch build.sh / test.sh / LET_IT_RIP.sh. This keeps it
# from interfering with an in-progress dnsfetch bootstrap.
#
# Source DBs are snapshotted with the SQLite online backup API (.backup), which
# is safe alongside a concurrent writer, into a local gitignored scratch dir.
# Re-running is idempotent (snapshots and the binary are reused if present).
set -euo pipefail
cd "$(dirname "$0")"

DATASETS="${DATASETS:-/Volumes/wd_office_2/datasets}"
SCRATCH=".reindex"
DNS_TLD="${DNS_TLD:-gov}"                # small, self-contained DNS snapshot
CT_MONTH="${CT_MONTH:-2025-05}"          # ~160MB CT month with real SAN volume

DNS_SRC="$DATASETS/dns/$DNS_TLD/records.db"
CT_SRC="$DATASETS/CT/$CT_MONTH/subjects.db"

mkdir -p "$SCRATCH"

echo "=== reindex_validate (ISOLATED — does not run build.sh/test.sh) ==="

echo "--- targeted dep + build ---"
go get modernc.org/sqlite >/dev/null 2>&1 || true
go build -o "$SCRATCH/reindex" ./cmd/reindex
REINDEX="$SCRATCH/reindex"
echo "  built $REINDEX"

# safe_snapshot SRC DST — consistent copy via online backup API; skip if present.
# Prefers a mode=ro read (safe alongside a live writer). Some DBs on the
# external volume reject the read-only lock path (err 14); for those we retry
# with immutable=1, which is correct ONLY because the source is static — we
# verify it has no -wal (no in-flight transaction) before doing so.
safe_snapshot() {
    local src="$1" dst="$2"
    if [[ -f "$dst" && -s "$dst" ]]; then echo "  snapshot exists: $dst"; return; fi
    rm -f "$dst"
    if [[ ! -f "$src" ]]; then echo "  MISSING SOURCE: $src"; exit 1; fi
    echo "  snapshotting $src -> $dst (online backup)"
    if sqlite3 "file:$src?mode=ro" ".backup '$dst'" 2>/dev/null; then
        return
    fi
    rm -f "$dst"
    if [[ -f "$src-wal" ]]; then
        echo "  ERROR: $src has an active -wal; refusing immutable fallback"
        exit 1
    fi
    echo "  WARN: mode=ro open failed; source is static (no -wal), using immutable=1"
    sqlite3 "file:$src?immutable=1" ".backup '$dst'"
}

echo "--- snapshot sources ---"
safe_snapshot "$DNS_SRC" "$SCRATCH/dns_$DNS_TLD.db"
safe_snapshot "$CT_SRC"  "$SCRATCH/ct_$CT_MONTH.db"

DNS_SNAP="$SCRATCH/dns_$DNS_TLD.db"
CT_SNAP="$SCRATCH/ct_$CT_MONTH.db"
REV="$SCRATCH/rev_$DNS_TLD.db"
SAN="$SCRATCH/san_$CT_MONTH.db"

echo
echo "=== R1: build IP->domain reverse index ($DNS_TLD) ==="
"$REINDEX" build-ip "$DNS_SNAP" "$REV"
echo "  output size: $(ls -lh "$REV" | awk '{print $5}')"

echo
echo "=== R1 validation ==="
# Hottest IP in the snapshot (most domains sharing one address).
HOT_IP=$(sqlite3 "file:$DNS_SNAP?immutable=1" \
    "SELECT ipv4 FROM dns_records_a GROUP BY ipv4 ORDER BY count(*) DESC LIMIT 1;")
echo "  hottest IP in snapshot: $HOT_IP"

echo "  [Q7] reindex lookup-ip $HOT_IP:"
"$REINDEX" lookup-ip "$REV" "$HOT_IP" | tail -1
IDX_CNT=$("$REINDEX" lookup-ip "$REV" "$HOT_IP" | grep -c -v '^--' || true)

echo "  [naive] full-scan distinct-domain count of that IP on the SOURCE snapshot:"
NAIVE_START=$(python3 -c 'import time;print(time.time())')
# count(DISTINCT domain): the index dedups (ip,domain), so the source oracle
# must also collapse refetch duplicates.
NAIVE_CNT=$(sqlite3 "file:$DNS_SNAP?immutable=1" \
    "SELECT count(DISTINCT domain) FROM dns_records_a WHERE ipv4='$HOT_IP';")
NAIVE_END=$(python3 -c 'import time;print(time.time())')
echo "    naive distinct-domain count=$NAIVE_CNT  (full table scan, no ipv4 index)"
echo "    indexed count=$IDX_CNT"
if [[ "$IDX_CNT" == "$NAIVE_CNT" ]]; then
    echo "    ✓ counts match"
else
    echo "    ✗ MISMATCH (index=$IDX_CNT naive=$NAIVE_CNT)"
fi

# Demonstrate the CIDR query the source data structurally cannot do.
CIDR="$(echo "$HOT_IP" | awk -F. '{print $1"."$2"."$3".0/24"}')"
echo "  [Q8] reindex lookup-cidr $CIDR (impossible as an index scan on source):"
"$REINDEX" lookup-cidr "$REV" "$CIDR" | tail -1

echo
echo "=== R3: build SAN->cert reverse index ($CT_MONTH) ==="
"$REINDEX" build-san "$CT_SNAP" "$SAN"
echo "  output size: $(ls -lh "$SAN" | awk '{print $5}')"

echo
echo "=== R3 validation ==="
# A registrable domain that actually appears in this month's SANs.
REG=$(sqlite3 "file:$SAN?immutable=1" \
    "SELECT reg_domain FROM san_index WHERE reg_domain != '_other' GROUP BY reg_domain ORDER BY count(*) DESC LIMIT 1;")
echo "  busiest registrable domain in snapshot: $REG"

echo "  [Q5/Q12] reindex lookup-san $REG:"
"$REINDEX" lookup-san "$SAN" "$REG" | tail -1
IDX_CERTS=$(sqlite3 "file:$SAN?immutable=1" \
    "SELECT count(DISTINCT cert_id) FROM san_index WHERE san_domain='$REG' OR reg_domain='$REG';")
echo "    indexed distinct certs at/under $REG = $IDX_CERTS"

echo "  [naive] LIKE-scan on SOURCE subjects.san_domains for '$REG':"
NAIVE_CERTS=$(sqlite3 "file:$CT_SNAP?immutable=1" \
    "SELECT count(*) FROM subjects WHERE san_domains LIKE '%$REG%';")
echo "    naive matching cert rows = $NAIVE_CERTS (substring match — superset, sanity bound only)"
if [[ "$IDX_CERTS" -le "$NAIVE_CERTS" ]]; then
    echo "    ✓ indexed exact-count is within the naive substring superset"
else
    echo "    ✗ unexpected: indexed > naive substring count"
fi

echo
echo "=== reindex_validate complete ==="
