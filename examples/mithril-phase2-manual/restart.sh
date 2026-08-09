#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/common.sh"

[[ $# -eq 2 ]] || {
  echo "usage: sudo $0 NODE_CONFIG DOCKER_CONTAINER_OR_FULL_CRI_ID" >&2
  exit 2
}

phase2_prepare_auto "$1" "$2"
phase2_start_node
phase2_inspect_task before-restart "$phase2_init_pid"
phase2_assert_recovered "$phase2_work/before-restart.json"

phase2_stop_node
phase2_start_node
phase2_inspect_task after-restart "$phase2_init_pid"
[[ $(jq -er '.process_state_id' "$phase2_work/before-restart.json") == \
   $(jq -er '.process_state_id' "$phase2_work/after-restart.json") ]] || {
  echo "live task identity changed across pinned-state recovery" >&2
  exit 1
}
phase2_pass "PASS: live task identity survives exact node restart recovery"
