#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/identity-runtime.sh"

[[ $# -eq 2 ]] || {
  echo "usage: sudo $0 NODE_CONFIG DOCKER_CONTAINER_OR_FULL_CRI_ID" >&2
  exit 2
}

identity_prepare_auto "$1" "$2"
identity_start_node
identity_inspect_task before-restart "$identity_init_pid"
identity_assert_recovered "$identity_work/before-restart.json"

identity_stop_node
identity_start_node
identity_inspect_task after-restart "$identity_init_pid"
[[ $(jq -er '.process_state_id' "$identity_work/before-restart.json") == \
   $(jq -er '.process_state_id' "$identity_work/after-restart.json") ]] || {
  echo "live task identity changed across pinned-state recovery" >&2
  exit 1
}
identity_pass "PASS: live task identity survives exact node restart recovery"
