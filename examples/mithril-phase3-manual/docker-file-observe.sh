#!/usr/bin/env bash
set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/common.sh"
[[ $# -eq 3 ]] || {
  echo "usage: sudo $0 <phase2-node.json> <container> <absolute-secret-path>" >&2
  exit 2
}

phase3_prepare_docker "$1" "$2" "$3"
phase2_start_node
docker exec "$2" head -c 1 "$3" >/dev/null
phase3_wait_for_observation 'reason=WOULD_DENY' "$phase2_work/effects.txt"
grep -q 'result=UNKNOWN_AFTER_PRE_EFFECT' "$phase2_work/effects.txt"
phase2_pass "PASS: file read completed and Mithril reported the exact observe-only WOULD_DENY."

