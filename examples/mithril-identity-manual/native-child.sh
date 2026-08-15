#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/identity-runtime.sh"

[[ $# -eq 2 || ($# -eq 3 && ${3:-} == --orphan) ]] || {
  echo "usage: sudo $0 NODE_CONFIG DOCKER_CONTAINER_OR_FULL_CRI_ID [--orphan]" >&2
  exit 2
}

identity_prepare_auto "$1" "$2"
identity_start_node

if [[ ${3:-} == --orphan ]]; then
  echo "Run in another root terminal:"
  identity_print_runtime_exec '(read child_pid _ < /proc/self/stat; kill -STOP "$child_pid"; exec sleep 300) & wait'
  echo "Enter that shell's host PID, then its stopped child host PID."
  identity_read_host_pid "shell host PID: "
  parent_pid=$identity_read_pid
  identity_read_host_pid "stopped native child host PID: "
  child_pid=$identity_read_pid
  identity_inspect_task orphan-native-parent "$parent_pid"
  identity_inspect_task orphan-native-child-before "$child_pid"

  parent_cookie=$(jq -er '.task_cookie' "$identity_work/orphan-native-parent.json")
  parent_role=$(jq -er '.active_role_id' "$identity_work/orphan-native-parent.json")
  child_cookie=$(jq -er '.task_cookie' "$identity_work/orphan-native-child-before.json")
  child_creator=$(jq -er '.creator_task_cookie' "$identity_work/orphan-native-child-before.json")
  child_real_parent=$(jq -er '.real_parent_task_cookie' "$identity_work/orphan-native-child-before.json")
  child_interval=$(jq -er '.real_parent_interval_sequence' "$identity_work/orphan-native-child-before.json")
  [[ $parent_cookie == "$child_creator" && $parent_cookie == "$child_real_parent" ]] || {
    echo "native child does not name the exact live creator" >&2
    exit 1
  }

  echo "In another root terminal, run: kill -KILL $parent_pid"
  read -r -p "Press Enter after the creator has exited: " _
  for ((attempt = 0; attempt < 100; attempt++)); do
    [[ ! -d /proc/$parent_pid ]] && break
    sleep 0.1
  done
  [[ ! -d /proc/$parent_pid ]] || {
    echo "creator task is still live" >&2
    exit 1
  }
  kill -CONT "$child_pid"
  for ((attempt = 0; attempt < 100; attempt++)); do
    [[ $(tr -d '\n' </proc/$child_pid/comm 2>/dev/null || true) == sleep ]] && break
    sleep 0.1
  done
  [[ $(tr -d '\n' </proc/$child_pid/comm 2>/dev/null || true) == sleep ]] || {
    echo "native child did not exec sleep after the creator exited" >&2
    exit 1
  }
  identity_inspect_task orphan-native-child-after "$child_pid"
  jq -e --argjson parent_cookie "$parent_cookie" \
    --argjson parent_role "$parent_role" \
    --argjson child_cookie "$child_cookie" \
    --argjson child_interval "$child_interval" \
    '.task_cookie == $child_cookie
     and .creator_task_cookie == $parent_cookie
     and .real_parent_task_cookie != $parent_cookie
     and .real_parent_interval_sequence > $child_interval
     and .root_class == null
     and .installed_role_class == null
     and .active_role_id == $parent_role' \
    "$identity_work/orphan-native-child-after.json" >/dev/null
  identity_pass "PASS: creator identity stayed exact after parent exit and the real-parent interval changed."
  exit 0
fi

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
