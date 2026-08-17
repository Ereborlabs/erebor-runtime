#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/identity-runtime.sh"

identity_labeled_task=false
if [[ $# -eq 1 && $1 == --labeled-task ]]; then
  identity_labeled_task=true
elif [[ $# -ne 0 ]]; then
  echo "usage: sudo $0 [--labeled-task]" >&2
  exit 2
fi

identity_require_command nsenter
identity_prepare_k3s_case \
  docker.io/library/python@sha256:78098ea6a3a9c6a7727a5d4674e4a44e57e01fac878ee9cb4d24a86bd93916ff
identity_start_node

if [[ $identity_labeled_task == true ]]; then
  identity_root_exec_release=$identity_work/labeled-root-exec-release
  identity_namespace_release=$identity_work/labeled-namespace-release
  bash -c '
    while [[ ! -e $1 ]]; do
      sleep 0.1
    done
    exec bash -c "$2" bash "$3" "$4"
  ' bash "$identity_root_exec_release" '
    while [[ ! -e $1 ]]; do
      sleep 0.1
    done
    (
      read -r child_pid _ < /proc/self/stat
      kill -STOP "$child_pid"
      exec nsenter -t "$2" -m -- sleep 300
    ) &
    wait "$!"
  ' "$identity_namespace_release" "$identity_init_pid" &
  labeled_root_pid=$!
  identity_task_pids+=("$labeled_root_pid")
  printf '%s\n' "$labeled_root_pid" >"$identity_cgroup_path/cgroup.procs"
  : >"$identity_root_exec_release"

  for ((attempt = 0; attempt < 100; attempt++)); do
    identity_inspect_task labeled-namespace-root "$labeled_root_pid" >/dev/null 2>&1 || true
    jq -e '.creator_task_cookie == null
           and .root_class == "external_runtime_root"
           and .installed_role_class == "runtime_external_restricted"
           and .coordinate_state == 3' \
      "$identity_work/labeled-namespace-root.json" >/dev/null 2>&1 && break
    sleep 0.1
  done
  identity_assert_external "$identity_work/labeled-namespace-root.json"
  labeled_root_cookie=$(jq -er '.task_cookie' "$identity_work/labeled-namespace-root.json")
  labeled_root_role=$(jq -er '.active_role_id' "$identity_work/labeled-namespace-root.json")

  : >"$identity_namespace_release"
  for ((attempt = 0; attempt < 100; attempt++)); do
    labeled_children=()
    read -r -a labeled_children \
      <"/proc/$labeled_root_pid/task/$labeled_root_pid/children" || true
    if [[ ${#labeled_children[@]} -eq 1 ]] \
      && grep -q $'^State:\tT' "/proc/${labeled_children[0]}/status"; then
      labeled_child_pid=${labeled_children[0]}
      break
    fi
    sleep 0.1
  done
  [[ -n ${labeled_child_pid:-} ]] || {
    echo "labeled namespace child did not become the root's stopped direct child" >&2
    exit 1
  }
  identity_task_pids+=("$labeled_child_pid")
  identity_inspect_task labeled-namespace-before "$labeled_child_pid"
  labeled_child_cookie=$(jq -er '.task_cookie' "$identity_work/labeled-namespace-before.json")
  labeled_child_process=$(jq -er '.process_state_id' "$identity_work/labeled-namespace-before.json")
  labeled_child_execution=$(jq -er '.active_execution_id' "$identity_work/labeled-namespace-before.json")
  labeled_child_image=$(jq -er '.image_provenance_id' "$identity_work/labeled-namespace-before.json")
  jq -e --argjson root_cookie "$labeled_root_cookie" \
    --argjson root_role "$labeled_root_role" \
    '.creator_task_cookie == $root_cookie
     and .real_parent_task_cookie == $root_cookie
     and .active_role_id == $root_role
     and .root_class == null
     and .installed_role_class == null
     and .coordinate_state == 3' \
    "$identity_work/labeled-namespace-before.json" >/dev/null
  labeled_child_mount_namespace=$(readlink "/proc/$labeled_child_pid/ns/mnt")
  labeled_target_mount_namespace=$(readlink "/proc/$identity_init_pid/ns/mnt")
  [[ $labeled_child_mount_namespace != "$labeled_target_mount_namespace" ]] || {
    echo "labeled namespace child already has the target mount namespace" >&2
    exit 1
  }

  kill -CONT "$labeled_child_pid"
  for ((attempt = 0; attempt < 100; attempt++)); do
    [[ $(tr -d '\n' <"/proc/$labeled_child_pid/comm" 2>/dev/null || true) == sleep ]] && break
    sleep 0.1
  done
  [[ $(tr -d '\n' <"/proc/$labeled_child_pid/comm" 2>/dev/null || true) == sleep ]] || {
    echo "labeled namespace child did not exec sleep" >&2
    exit 1
  }
  [[ $(readlink "/proc/$labeled_child_pid/ns/mnt") == "$labeled_target_mount_namespace" ]] || {
    echo "labeled namespace child did not enter the target mount namespace" >&2
    exit 1
  }
  identity_inspect_task labeled-namespace-after "$labeled_child_pid"
  jq -e --argjson child_cookie "$labeled_child_cookie" \
    --argjson root_cookie "$labeled_root_cookie" \
    --arg child_process "$labeled_child_process" \
    --arg child_execution "$labeled_child_execution" \
    --arg child_image "$labeled_child_image" \
    --argjson root_role "$labeled_root_role" \
    '.task_cookie == $child_cookie
     and .creator_task_cookie == $root_cookie
     and .real_parent_task_cookie == $root_cookie
     and .process_state_id == $child_process
     and .active_execution_id != $child_execution
     and .image_provenance_id != $child_image
     and .active_role_id == $root_role
     and .root_class == null
     and .installed_role_class == null
     and .coordinate_state == 3
     and .process_execution_state == 2
     and .process_state_vector_state == 2
     and .exec_guard_state == 0' \
    "$identity_work/labeled-namespace-after.json" >/dev/null
  identity_pass "PASS: a labeled native child kept its identity after mount-namespace entry."
  exit 0
fi

nsenter -t "$identity_init_pid" -m -u -i -n -p sh -c 'exec sleep 300' &
nsenter_helper_pid=$!
identity_task_pids+=("$nsenter_helper_pid")
for ((attempt = 0; attempt < 100; attempt++)); do
  read -r -a nsenter_children \
    <"/proc/$nsenter_helper_pid/task/$nsenter_helper_pid/children" || true
  [[ ${#nsenter_children[@]} -eq 1 ]] && break
  sleep 0.1
done
nsenter_children=()
read -r -a nsenter_children \
  <"/proc/$nsenter_helper_pid/task/$nsenter_helper_pid/children" || true
[[ ${#nsenter_children[@]} -eq 1 ]] || {
  echo "nsenter sleep is not the helper's only direct child" >&2
  exit 1
}
nsenter_pid=${nsenter_children[0]}
identity_task_pids+=("$nsenter_pid")
[[ $(<"/proc/$nsenter_pid/comm") == sleep ]] || {
  echo "nsenter child is not sleep" >&2
  exit 1
}
[[ $(tr '\0' ' ' <"/proc/$nsenter_pid/cmdline") == 'sleep 300 ' ]] || {
  echo "nsenter child command is not exactly sleep 300" >&2
  exit 1
}
for namespace in mnt uts ipc net pid; do
  nsenter_namespace=$(readlink "/proc/$nsenter_pid/ns/$namespace")
  target_namespace=$(readlink "/proc/$identity_init_pid/ns/$namespace")
  [[ $nsenter_namespace == "$target_namespace" ]] || {
    echo "nsenter sleep is outside the target $namespace namespace: $nsenter_namespace != $target_namespace" >&2
    exit 1
  }
done
nsenter_cgroup=$(identity_cgroup_for_pid "$nsenter_pid")
case $nsenter_cgroup in
  "$identity_cgroup_path"|"$identity_cgroup_path"/*)
    echo "nsenter sleep is already in the configured cgroup" >&2
    exit 1
    ;;
esac
if no_identity_output=$("$identity_inspect" --pin-root "$identity_pin_root" \
  task --host-pid "$nsenter_pid" 2>&1); then
  echo "namespace entry alone incorrectly granted workload identity" >&2
  exit 1
elif [[ $no_identity_output != \
  "Mithril native identity state is invalid: host PID $nsenter_pid has no Mithril task identity" ]]; then
  echo "Mithril did not confirm the expected missing task identity:" >&2
  echo "$no_identity_output" >&2
  exit 1
fi

echo "$nsenter_pid" >"$identity_cgroup_path/cgroup.procs"
identity_inspect_task nsenter-after-move "$nsenter_pid"
identity_assert_external "$identity_work/nsenter-after-move.json"
external_role_id=$(jq -er '.workload_bindings[0].external_role_id' "$identity_config")
jq -e --argjson external_role_id "$external_role_id" \
  '.active_role_id == $external_role_id and .coordinate_state == 3' \
  "$identity_work/nsenter-after-move.json" >/dev/null
identity_pass "PASS: nsenter grants nothing; cgroup movement creates a restricted external root"
