#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/identity-runtime.sh"

[[ $# -eq 2 || ($# -eq 3 && (${3:-} == --orphan || ${3:-} == --double-fork || ${3:-} == --moved-exec)) ]] || {
  echo "usage: sudo $0 NODE_CONFIG DOCKER_CONTAINER_OR_FULL_CRI_ID [--orphan|--double-fork|--moved-exec]" >&2
  exit 2
}

identity_prepare_auto "$1" "$2"
identity_start_node

if [[ ${3:-} == --double-fork ]]; then
  echo "Run in another root terminal:"
  identity_print_runtime_exec '( ( read child_pid _ < /proc/self/stat; kill -STOP "$child_pid"; exec sleep 300 ) & wait ) & middle_pid=$!; wait "$middle_pid"; exec sleep 300'
  echo "Enter the outer shell, its intermediate child, then its stopped grandchild host PIDs."
  identity_read_host_pid "outer shell host PID: "
  outer_pid=$identity_read_pid
  identity_read_host_pid "intermediate native child host PID: "
  intermediate_pid=$identity_read_pid
  identity_read_host_pid "stopped native grandchild host PID: "
  child_pid=$identity_read_pid
  grep -q $'^State:\tT' "/proc/$child_pid/status" || {
    echo "native grandchild is not stopped before the intermediate exits" >&2
    exit 1
  }
  identity_inspect_task double-fork-outer "$outer_pid"
  identity_inspect_task double-fork-intermediate "$intermediate_pid"
  identity_inspect_task double-fork-child-before "$child_pid"

  outer_cookie=$(jq -er '.task_cookie' "$identity_work/double-fork-outer.json")
  outer_role=$(jq -er '.active_role_id' "$identity_work/double-fork-outer.json")
  intermediate_cookie=$(jq -er '.task_cookie' "$identity_work/double-fork-intermediate.json")
  child_cookie=$(jq -er '.task_cookie' "$identity_work/double-fork-child-before.json")
  child_interval=$(jq -er '.real_parent_interval_sequence' "$identity_work/double-fork-child-before.json")
  identity_assert_external "$identity_work/double-fork-outer.json"
  jq -e --argjson outer_cookie "$outer_cookie" \
    --argjson outer_role "$outer_role" \
    '.creator_task_cookie == $outer_cookie
     and .real_parent_task_cookie == $outer_cookie
     and .root_class == null
     and .installed_role_class == null
     and .active_role_id == $outer_role' \
    "$identity_work/double-fork-intermediate.json" >/dev/null
  jq -e --argjson intermediate_cookie "$intermediate_cookie" \
    --argjson outer_role "$outer_role" \
    '.creator_task_cookie == $intermediate_cookie
     and .real_parent_task_cookie == $intermediate_cookie
     and .root_class == null
     and .installed_role_class == null
     and .active_role_id == $outer_role' \
    "$identity_work/double-fork-child-before.json" >/dev/null

  echo "In another root terminal, run: kill -KILL $intermediate_pid"
  read -r -p "Press Enter after the intermediate child has exited: " _
  for ((attempt = 0; attempt < 100; attempt++)); do
    [[ ! -d /proc/$intermediate_pid ]] && break
    sleep 0.1
  done
  [[ ! -d /proc/$intermediate_pid ]] || {
    echo "intermediate native child is still live" >&2
    exit 1
  }
  for ((attempt = 0; attempt < 100; attempt++)); do
    [[ $(tr -d '\n' </proc/$outer_pid/comm 2>/dev/null || true) == sleep ]] && break
    sleep 0.1
  done
  [[ $(tr -d '\n' </proc/$outer_pid/comm 2>/dev/null || true) == sleep ]] || {
    echo "outer shell did not remain live after the intermediate exited" >&2
    exit 1
  }
  kill -CONT "$child_pid"
  for ((attempt = 0; attempt < 100; attempt++)); do
    [[ $(tr -d '\n' </proc/$child_pid/comm 2>/dev/null || true) == sleep ]] && break
    sleep 0.1
  done
  [[ $(tr -d '\n' </proc/$child_pid/comm 2>/dev/null || true) == sleep ]] || {
    echo "native grandchild did not exec sleep after the intermediate exited" >&2
    exit 1
  }
  identity_inspect_task double-fork-child-after "$child_pid"
  jq -e --argjson intermediate_cookie "$intermediate_cookie" \
    --argjson outer_role "$outer_role" \
    --argjson child_cookie "$child_cookie" \
    --argjson child_interval "$child_interval" \
    '.task_cookie == $child_cookie
     and .creator_task_cookie == $intermediate_cookie
     and .real_parent_task_cookie != $intermediate_cookie
     and .real_parent_interval_sequence > $child_interval
     and .root_class == null
     and .installed_role_class == null
     and .active_role_id == $outer_role' \
    "$identity_work/double-fork-child-after.json" >/dev/null
  identity_pass "PASS: double-fork creator identity stayed exact after intermediate exit."
  exit 0
fi

if [[ ${3:-} == --moved-exec ]]; then
  echo "Run in another root terminal:"
  identity_print_runtime_exec '(read child_pid _ < /proc/self/stat; kill -STOP "$child_pid"; exec sleep 300) & wait'
  echo "Enter that shell's host PID, then its stopped native child host PID."
  identity_read_host_pid "shell host PID: "
  parent_pid=$identity_read_pid
  identity_read_host_pid "stopped native child host PID: "
  child_pid=$identity_read_pid
  grep -q $'^State:\tT' "/proc/$child_pid/status" || {
    echo "native child is not stopped before cgroup movement" >&2
    exit 1
  }
  identity_inspect_task moved-exec-parent "$parent_pid"
  identity_inspect_task moved-exec-child-before "$child_pid"

  parent_cookie=$(jq -er '.task_cookie' "$identity_work/moved-exec-parent.json")
  child_cookie=$(jq -er '.task_cookie' "$identity_work/moved-exec-child-before.json")
  identity_assert_external "$identity_work/moved-exec-parent.json"
  jq -e --argjson parent_cookie "$parent_cookie" \
    '.creator_task_cookie == $parent_cookie
     and .real_parent_task_cookie == $parent_cookie
     and .root_class == null
     and .installed_role_class == null
     and .coordinate_state == 3' \
    "$identity_work/moved-exec-child-before.json" >/dev/null

  parent_cgroup=$(dirname -- "$identity_cgroup_path")
  parent_procs=$parent_cgroup/cgroup.procs
  [[ -w $parent_procs ]] || {
    echo "cannot move the native child to $parent_procs" >&2
    exit 1
  }
  printf '%s\n' "$child_pid" >"$parent_procs"
  for ((attempt = 0; attempt < 100; attempt++)); do
    identity_inspect_task moved-exec-child-after-move "$child_pid" >/dev/null
    jq -e --argjson parent_cookie "$parent_cookie" \
      --argjson child_cookie "$child_cookie" \
      '.task_cookie == $child_cookie
       and .creator_task_cookie == $parent_cookie
       and .real_parent_task_cookie == $parent_cookie
       and .root_class == null
       and .installed_role_class == null
       and .coordinate_state == 6' \
      "$identity_work/moved-exec-child-after-move.json" >/dev/null && break
    sleep 0.1
  done
  jq -e --argjson parent_cookie "$parent_cookie" \
    --argjson child_cookie "$child_cookie" \
    '.task_cookie == $child_cookie
     and .creator_task_cookie == $parent_cookie
     and .real_parent_task_cookie == $parent_cookie
     and .root_class == null
     and .installed_role_class == null
     and .coordinate_state == 6' \
    "$identity_work/moved-exec-child-after-move.json" >/dev/null || {
      echo "moved native child did not become fail closed" >&2
      exit 1
    }

  kill -CONT "$child_pid"
  for ((attempt = 0; attempt < 50; attempt++)); do
    [[ ! -d /proc/$child_pid ]] && break
    [[ $(tr -d '\n' </proc/$child_pid/comm 2>/dev/null || true) != sleep ]] || {
      echo "moved native child executed sleep" >&2
      exit 1
    }
    sleep 0.1
  done
  [[ ! -d /proc/$child_pid ]] || {
    echo "moved native child did not exit after its denied exec" >&2
    exit 1
  }
  identity_pass "PASS: a moved native child kept its identity and its exec was denied."
  exit 0
fi

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
