#!/usr/bin/env bash
# top_domains.sh <N> [output_dir]
# Queries the most recent ingestion batch's subjects.db and prints the N most
# frequently seen parent domains (subdomains rolled up to eTLD+1).
set -euo pipefail

N=${1:-10}
BASE_DIR="${2:-/Volumes/wd_office_2/datasets/CT/}"

# Fallback to /tmp/ct-data/ if the primary path is absent
if [ ! -d "$BASE_DIR" ]; then
  BASE_DIR="/tmp/ct-data/"
fi

# Find most recent YYYYMMDD dated subdirectory
LATEST=$(find "$BASE_DIR" -maxdepth 1 -type d -name '20[0-9][0-9][0-9][0-9][0-9][0-9]' \
  | sort -r | head -1)

if [ -z "$LATEST" ]; then
  echo "No dated ingestion directories found in $BASE_DIR" >&2
  exit 1
fi

DB="${LATEST}/subjects.db"
if [ ! -f "$DB" ]; then
  echo "subjects.db not found in $LATEST" >&2
  exit 1
fi

echo "Querying: $DB"
echo "Top $N parent domains:"
echo ""

# Pull all comma-separated san_domains out of sqlite, one domain per line.
# Then use awk to extract the parent domain (last 2 or 3 dot-segments) and count.
sqlite3 "$DB" "SELECT san_domains FROM subjects WHERE san_domains != '';" \
  | tr ',' '\n' \
  | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' \
  | grep -v '^$' \
  | awk '
    # Strip leading wildcard
    { sub(/^\*\./, "", $0) }
    NF == 0 { next }
    {
      n = split($0, parts, ".")
      if (n < 2) { print $0; next }

      # Known 2-part TLDs that need 3 segments for the parent domain
      twopart["co.uk"] = 1; twopart["com.au"] = 1; twopart["org.uk"] = 1
      twopart["co.nz"] = 1; twopart["com.br"] = 1; twopart["co.jp"] = 1
      twopart["co.za"] = 1; twopart["org.au"] = 1; twopart["net.au"] = 1
      twopart["gov.uk"] = 1; twopart["ac.uk"] = 1;  twopart["me.uk"] = 1

      suffix2 = parts[n-1] "." parts[n]
      if (n >= 3 && (suffix2 in twopart)) {
        print parts[n-2] "." parts[n-1] "." parts[n]
      } else {
        print parts[n-1] "." parts[n]
      }
    }
  ' \
  | sort \
  | uniq -c \
  | sort -rn \
  | head -n "$N" \
  | awk '{ printf "%6d  %s\n", $1, $2 }'
