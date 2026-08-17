#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/identity-runtime.sh"

[[ $# -eq 0 ]] || {
  echo "usage: sudo $0" >&2
  exit 2
}

binding_gap_verify_cgroup_removed() {
  [[ ! -e $binding_gap_cgroup_path ]] || {
    echo "binding-gap Pod cgroup survived cleanup: $binding_gap_cgroup_path" >&2
    return 1
  }
}

identity_prepare_k3s_case \
  docker.io/library/python@sha256:78098ea6a3a9c6a7727a5d4674e4a44e57e01fac878ee9cb4d24a86bd93916ff
binding_gap_cgroup_path=$identity_cgroup_path
identity_cleanup_functions+=(binding_gap_verify_cgroup_removed)

binding_gap_release=$identity_work/binding-gap-release
bash -c '
  while [[ ! -e $1 ]]; do
    sleep 0.1
  done
  exec sleep 300
' bash "$binding_gap_release" &
binding_gap_pid=$!
identity_task_pids+=("$binding_gap_pid")
printf '%s\n' "$binding_gap_pid" >"$identity_cgroup_path/cgroup.procs"

identity_start_node
identity_inspect_task binding-gap-root "$binding_gap_pid"
identity_assert_recovered "$identity_work/binding-gap-root.json"
external_role_id=$(jq -er '.workload_bindings[0].external_role_id' "$identity_config")
jq -e --argjson external_role_id "$external_role_id" \
  '.creator_task_cookie == null
   and .active_role_id == $external_role_id
   and .coordinate_state == 3' \
  "$identity_work/binding-gap-root.json" >/dev/null

control_release=$identity_work/binding-gap-control-release
bash -c '
  while [[ ! -e $1 ]]; do
    sleep 0.1
  done
  exec sleep 300
' bash "$control_release" &
control_pid=$!
identity_task_pids+=("$control_pid")
printf '%s\n' "$control_pid" >"$identity_cgroup_path/cgroup.procs"

for ((attempt = 0; attempt < 100; attempt++)); do
  identity_inspect_task binding-gap-control "$control_pid" >/dev/null 2>&1 || true
  jq -e '.creator_task_cookie == null
         and .root_class == "external_runtime_root"
         and .installed_role_class == "runtime_external_restricted"
         and .coordinate_state == 3' \
    "$identity_work/binding-gap-control.json" >/dev/null 2>&1 && break
  sleep 0.1
done
identity_assert_external "$identity_work/binding-gap-control.json"

: >"$binding_gap_release"
: >"$control_release"
identity_pass "PASS: a live pre-binding root reconciles fail closed; a later root is restricted external."
