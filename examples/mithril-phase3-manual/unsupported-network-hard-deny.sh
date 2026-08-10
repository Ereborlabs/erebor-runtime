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
if docker exec "$2" python3 -c \
  'import socket; socket.create_connection(("127.0.0.1", 9), timeout=1)'; then
  echo "unsupported protected network connect unexpectedly completed" >&2
  exit 1
fi
phase3_wait_for_observation 'reason=UNSUPPORTED_OBJECT' "$phase2_work/effects.txt"
grep -q 'result=DENIED_BEFORE_EFFECT' "$phase2_work/effects.txt"
phase2_pass "PASS: unsupported network identity stayed a hard denial in observe mode."

