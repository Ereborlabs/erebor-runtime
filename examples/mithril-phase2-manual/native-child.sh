#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/common.sh"

[[ $# -eq 2 ]] || {
  echo "usage: sudo $0 NODE_CONFIG DOCKER_CONTAINER_OR_FULL_CRI_ID" >&2
  exit 2
}

phase2_prepare_auto "$1" "$2"
phase2_start_node

echo "Run in another root terminal:"
phase2_print_runtime_exec 'sleep 300 & wait'
echo "Enter that shell's host PID, then its sleep child's host PID."
phase2_read_host_pid "shell host PID: "
parent_pid=$phase2_read_pid
phase2_read_host_pid "native child host PID: "
child_pid=$phase2_read_pid
phase2_inspect_task native-parent "$parent_pid"
phase2_inspect_task native-child "$child_pid"

parent_cookie=$(jq -er '.task_cookie' "$phase2_work/native-parent.json")
child_creator=$(jq -er '.creator_task_cookie' "$phase2_work/native-child.json")
[[ $parent_cookie == "$child_creator" ]] || {
  echo "native child creator edge does not name the actual parent" >&2
  exit 1
}
jq -e '.root_class == null and .installed_role_class == null' \
  "$phase2_work/native-child.json" >/dev/null
phase2_pass "PASS: native child names its actual creator and is not an external root"
