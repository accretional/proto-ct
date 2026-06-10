#!/usr/bin/env bash
# One-shot health snapshot of all related services + SSD headroom.
# Codifies the hourly monitor's checks so they can be run by hand or from cron.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"
ARCHIVE="${ARCHIVE:-/Volumes/wd_office_2/datasets/CT}"

hr() { printf '%s\n' "------------------------------------------------------------"; }
proc() { pgrep -x "$1" >/dev/null && echo "UP   ($(pgrep -x "$1" | tr '\n' ' '))" || echo "DOWN"; }

echo "proto-ct services @ $(date '+%F %T')"; hr
printf "SSD free        : %sG  (data/active: %s)\n" \
  "$(df -g "$REPO" | awk 'NR==2{print $4}')" "$(du -sh data/active 2>/dev/null | cut -f1)"
printf "ct-server       : %s\n" "$(proc ct-server)"
printf "ct-client       : %s\n" "$(proc ct-client)"
printf "run_dnsfetch    : %s\n" "$(pgrep -f run_dnsfetch.sh >/dev/null && echo UP || echo DOWN)"
dpid="$(pgrep -f 'bin/dnsfetch' | head -1)"
printf "dnsfetch worker : %s\n" "$([ -n "$dpid" ] && ps -o command= -p "$dpid" | grep -oE '\-\-shard [^ ]+' || echo 'DOWN (or between shards)')"
printf "proto-domain    : %s\n" "$( (echo >/dev/tcp/127.0.0.1/50098) >/dev/null 2>&1 && echo 'UP (:50098)' || echo DOWN)"

# Active flush?  (any subjects.db.new.<pid> by the running server)
SPID="$(pgrep -x ct-server | head -1)"
if [ -n "$SPID" ]; then
  nf="$(find "$ARCHIVE" -name "subjects.db.new.$SPID" 2>/dev/null | sed "s#.*/CT/##;s#/.*##" | tr '\n' ',')"
  [ -n "$nf" ] && printf "flush in progress: [%s]\n" "$nf"
fi
hr
echo "CT (server)   : $(tail -1 data/logs/ct-server.log 2>/dev/null || tail -1 data/logs/ct-server-multilog.log 2>/dev/null)"
echo "dnsfetch      : $(tail -1 data/logs/runner.log 2>/dev/null)"
