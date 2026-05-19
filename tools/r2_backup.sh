#!/usr/bin/env bash
# Uploads subjects.db and issuers.db for every archive date dir to R2 bucket
# ct-index, preserving the YYYYMMDD/filename directory structure.
#
# Uses the aws CLI with the R2 S3-compatible endpoint (profile: r2) for
# multipart support on large files. Credentials are configured from the
# blob-service config.yaml (account 0e0bfc4cc92016594820fe3d9049fc74).
#
# A local manifest (r2_backup_manifest.txt alongside the archive) tracks
# completed uploads so the script is safe to interrupt and re-run.
#
# Usage: ./tools/r2_backup.sh [archive_dir]
set -euo pipefail

ARCHIVE="${1:-/Volumes/wd_office_2/datasets/CT}"
BUCKET="ct-index"
R2_ENDPOINT="https://0e0bfc4cc92016594820fe3d9049fc74.r2.cloudflarestorage.com"
AWS_PROFILE="r2"
LOG="$ARCHIVE/r2_backup.log"
MANIFEST="$ARCHIVE/r2_backup_manifest.txt"

touch "$MANIFEST"

log() { echo "$(date '+%Y/%m/%d %H:%M:%S') $*" | tee -a "$LOG"; }

is_uploaded() { grep -qxF "$1" "$MANIFEST"; }
mark_uploaded() { echo "$1" >> "$MANIFEST"; }

log "=== r2 backup start ==="

for date_dir in "$ARCHIVE"/[0-9]*/; do
    date_name=$(basename "$date_dir")
    for db in subjects.db issuers.db; do
        local_path="$date_dir$db"
        r2_key="$date_name/$db"

        [[ -f "$local_path" ]] || continue

        if is_uploaded "$r2_key"; then
            log "[skip] $r2_key (manifest)"
            continue
        fi

        size=$(du -sh "$local_path" | cut -f1)
        log "[upload] $r2_key ($size)"

        if aws s3 cp "$local_path" "s3://$BUCKET/$r2_key" \
               --profile "$AWS_PROFILE" \
               --endpoint-url "$R2_ENDPOINT" \
               --storage-class STANDARD \
               --no-progress 2>>"$LOG"; then
            mark_uploaded "$r2_key"
            log "[done]  $r2_key"
        else
            log "[ERROR] $r2_key — upload failed, continuing"
        fi
    done
done

log "=== r2 backup complete ==="
