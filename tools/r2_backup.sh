#!/usr/bin/env bash
# Backs up the CT archive AND the DNS dataset to Cloudflare R2, preserving
# structure under "ct/" and "dns/" key prefixes in one bucket. Resumable via a
# local manifest (each object recorded once uploaded), so it is safe to
# interrupt and re-run.
#
# Current layout (post month-partition migration + multi-log ingestion):
#   CT archive   /Volumes/wd_office_2/datasets/CT/<YYYY-MM>/subjects.db   (~152 months)
#   CT shared    data/active/{issuers.db,progress.db}   (global, on the SSD)
#   DNS dataset  /Volumes/wd_office_2/datasets/dns/<tld>/<bucket>.db
#
# CT-legacy-backup (Sycamore single-log data) is intentionally NOT backed up
# here — it is refetchable and huge. The SSD dedup sets (data/active/dedup) are
# rebuildable and also skipped.
#
# Run with CT + DNS ingestion STOPPED so the SQLite files are quiescent (a cp of
# a file being written by SQLite can be inconsistent).
#
# Uses the aws CLI against the R2 S3-compatible endpoint (profile: r2), which
# does multipart uploads for the large (multi-GB) month/shard files.
#
# Usage:   ./tools/r2_backup.sh            # back up CT + DNS
#          DRY_RUN=1 ./tools/r2_backup.sh  # list what would upload, no transfer
#          ONLY=ct ./tools/r2_backup.sh    # ONLY=ct or ONLY=dns to limit scope
set -uo pipefail

CT_ARCHIVE="${CT_ARCHIVE:-/Volumes/wd_office_2/datasets/CT}"
DNS_ROOT="${DNS_ROOT:-/Volumes/wd_office_2/datasets/dns}"
SHARED_DIR="${SHARED_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/data/active}"
BUCKET="${BUCKET:-ct-index}"
R2_ENDPOINT="${R2_ENDPOINT:-https://0e0bfc4cc92016594820fe3d9049fc74.r2.cloudflarestorage.com}"
AWS_PROFILE="${AWS_PROFILE:-r2}"
STATE_DIR="${STATE_DIR:-$CT_ARCHIVE}"
LOG="$STATE_DIR/r2_backup.log"
MANIFEST="$STATE_DIR/r2_backup_manifest.txt"
DRY_RUN="${DRY_RUN:-}"
ONLY="${ONLY:-}" # "", "ct", or "dns"

touch "$MANIFEST"
log() { echo "$(date '+%Y/%m/%d %H:%M:%S') $*" | tee -a "$LOG"; }
is_uploaded() { grep -qxF "$1" "$MANIFEST"; }
mark_uploaded() { echo "$1" >> "$MANIFEST"; }

uploaded=0 skipped=0 failed=0 missing=0

upload() { # $1 = local path, $2 = r2 key
	local local_path="$1" r2_key="$2"
	if [ ! -f "$local_path" ]; then
		log "[miss] $r2_key (no file at $local_path)"
		missing=$((missing + 1))
		return
	fi
	if is_uploaded "$r2_key"; then
		skipped=$((skipped + 1))
		return
	fi
	local size
	size=$(du -h "$local_path" | cut -f1)
	if [ -n "$DRY_RUN" ]; then
		log "[would upload] $r2_key ($size)"
		return
	fi
	log "[upload] $r2_key ($size)"
	if aws s3 cp "$local_path" "s3://$BUCKET/$r2_key" \
		--profile "$AWS_PROFILE" \
		--endpoint-url "$R2_ENDPOINT" \
		--storage-class STANDARD \
		--no-progress 2>>"$LOG"; then
		mark_uploaded "$r2_key"
		uploaded=$((uploaded + 1))
		log "[done]  $r2_key"
	else
		log "[ERROR] $r2_key — upload failed, continuing"
		failed=$((failed + 1))
	fi
}

log "=== r2 backup start (bucket=$BUCKET only=${ONLY:-all} dry_run=${DRY_RUN:-no}) ==="

# ── CT ───────────────────────────────────────────────────────────────────────
if [ "$ONLY" != "dns" ]; then
	for month_dir in "$CT_ARCHIVE"/[0-9][0-9][0-9][0-9]-[0-9][0-9]/; do
		[ -d "$month_dir" ] || continue
		upload "${month_dir}subjects.db" "ct/$(basename "$month_dir")/subjects.db"
	done
	# Global shared DBs: issuers maps ca_id -> CA; progress is the resume cursor.
	upload "$SHARED_DIR/issuers.db" "ct/issuers.db"
	upload "$SHARED_DIR/progress.db" "ct/progress.db"
fi

# ── DNS ──────────────────────────────────────────────────────────────────────
if [ "$ONLY" != "ct" ]; then
	for tld_dir in "$DNS_ROOT"/*/; do
		[ -d "$tld_dir" ] || continue
		tld=$(basename "$tld_dir")
		for db in "$tld_dir"*.db; do
			[ -f "$db" ] || continue
			upload "$db" "dns/$tld/$(basename "$db")"
		done
	done
fi

log "=== r2 backup complete: uploaded=$uploaded skipped=$skipped failed=$failed missing=$missing ==="
[ "$failed" -eq 0 ]
