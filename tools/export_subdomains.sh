#!/usr/bin/env bash
# export_subdomains.sh [base_dir] [out_dir]
#
# Extracts every unique DNS name seen across all mirrored subjects.db files and
# writes two output files for use in downstream data pipelines:
#
#   subdomains_unique.txt       — one FQDN per line, sorted alphabetically
#   subdomains_with_count.tsv   — <count>\t<fqdn>, sorted by descending count
#
# Wildcards are normalised (*.example.com → example.com).
# All names are lowercased and validated to contain at least one dot.
set -euo pipefail

BASE_DIR="${1:-/Volumes/wd_office_2/datasets/CT/}"
OUT_DIR="${2:-$BASE_DIR}"

if [ ! -d "$BASE_DIR" ]; then
  echo "Error: base directory not found: $BASE_DIR" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
UNIQUE_OUT="${OUT_DIR}/subdomains_unique.txt"
COUNT_OUT="${OUT_DIR}/subdomains_with_count.tsv"

echo "Scanning subjects.db files under $BASE_DIR ..." >&2

DB_COUNT=$(find "$BASE_DIR" -name "subjects.db" | wc -l | tr -d ' ')
if [ "$DB_COUNT" -eq 0 ]; then
  echo "No subjects.db files found." >&2
  exit 1
fi
echo "Found $DB_COUNT database(s)" >&2

# Stream san_domains from every DB, split on commas, normalise, count.
{
  find "$BASE_DIR" -name "subjects.db" | sort | while read -r db; do
    sqlite3 "$db" "SELECT san_domains FROM subjects WHERE san_domains != '' AND san_domains IS NOT NULL;"
  done
} \
  | tr ',' '\n' \
  | tr '[:upper:]' '[:lower:]' \
  | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' \
  | sed 's/^\*\.//' \
  | grep -E '^[a-z0-9._-]+\.[a-z]{2,}$' \
  | sort \
  | uniq -c \
  | sort -rn \
  | awk '{printf "%s\t%s\n", $1, $2}' \
  > "$COUNT_OUT"

# Sorted unique list (alphabetical)
awk '{print $2}' "$COUNT_OUT" | sort > "$UNIQUE_OUT"

UNIQUE_COUNT=$(wc -l < "$UNIQUE_OUT")
echo "" >&2
echo "Written:" >&2
echo "  $UNIQUE_OUT  ($UNIQUE_COUNT unique FQDNs)" >&2
echo "  $COUNT_OUT" >&2
echo "" >&2
echo "Top 10 most-seen domains:" >&2
head -10 "$COUNT_OUT" | awk '{printf "  %7s  %s\n", $1, $2}' >&2
