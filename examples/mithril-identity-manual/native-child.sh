#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/identity-runtime.sh"

[[ $# -eq 2 ]] || {
  echo "usage: sudo $0 NODE_CONFIG DOCKER_CONTAINER_OR_FULL_CRI_ID" >&2
  exit 2
}

identity_prepare_auto "$1" "$2"
identity_start_node

echo "Run in another root terminal:"
identity_print_runtime_exec 'sleep 300 & wait'
echo "Enter that shell's host PID, then its sleep child's host PID."
identity_read_host_pid "shell host PID: "
parent_pid=$identity_read_pid
identity_read_host_pid "native child host PID: "
child_pid=$identity_read_pid
identity_inspect_task native-parent "$parent_pid"
identity_inspect_task native-child "$child_pid"

parent_cookie=$(jq -er '.task_cookie' "$identity_work/native-parent.json")
child_creator=$(jq -er '.creator_task_cookie' "$identity_work/native-child.json")
[[ $parent_cookie == "$child_creator" ]] || {
  echo "native child creator edge does not name the actual parent" >&2
  exit 1
}
jq -e '.root_class == null and .installed_role_class == null' \
  "$identity_work/native-child.json" >/dev/null
identity_pass "PASS: native child names its actual creator and is not an external root"
