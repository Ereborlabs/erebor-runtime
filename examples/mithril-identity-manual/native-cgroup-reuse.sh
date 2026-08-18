#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/identity-runtime.sh"

[[ $# -eq 0 ]] || {
  echo "usage: sudo $0" >&2
  exit 2
}

reuse_source=$identity_repository/crates/mithril-e2e/harness/vm/k3s-cri-effect-node-v1.json
identity_check_base "$reuse_source"
identity_begin

reuse_suffix=$(tr '[:upper:]' '[:lower:]' <<<"${identity_work##*.}")
identity_cgroup_path=/sys/fs/cgroup/mithril-identity-reuse-$reuse_suffix
reuse_cleanup_cgroup() {
  local status=0
  if [[ -d $identity_cgroup_path ]]; then
    printf '1\n' >"$identity_cgroup_path/cgroup.kill" || status=1
    rmdir -- "$identity_cgroup_path" || status=1
  fi
  return "$status"
}
identity_cleanup_functions+=(reuse_cleanup_cgroup)

reuse_write_config() {
  local container_id=$1
  local pod_uid=$2
  local sandbox_id=$3
  local generation=$4
  jq --arg state "$identity_state" \
    --arg pin_root "$identity_pin_root" \
    --arg lease "$identity_lease" \
    --arg cgroup "$identity_cgroup_path" \
    --arg container_id "$container_id" \
    --arg pod_uid "$pod_uid" \
    --arg sandbox_id "$sandbox_id" \
    --argjson generation "$generation" \
    '.state_directory = $state
     | .interceptor.pin_root = $pin_root
     | .interceptor.lease_path = $lease
     | .runtime_observation = null
     | .container_runtime = null
     | .workload_bindings[0].container_id = $container_id
     | .workload_bindings[0].namespace = "manual-reuse"
     | .workload_bindings[0].pod_uid = $pod_uid
     | .workload_bindings[0].sandbox_id = $sandbox_id
     | .workload_bindings[0].container_name = "worker"
     | .workload_bindings[0].image_digest = "sha256:manual-reuse"
     | .workload_bindings[0].container_generation = $generation
     | .workload_bindings[0].root_cgroup_path = $cgroup
     | .workload_bindings[0].arm_initial_root = false' \
    "$reuse_source" >"$identity_config"
}

mkdir -- "$identity_cgroup_path"
/bin/sleep 300 &
reuse_first_pid=$!
identity_task_pids+=("$reuse_first_pid")
printf '%s\n' "$reuse_first_pid" >"$identity_cgroup_path/cgroup.procs"
reuse_write_config "$(printf 'a%.0s' {1..64})" first-pod first-sandbox 1
identity_start_node
identity_wait_for_task_snapshot cgroup-reuse-first "$reuse_first_pid"
identity_assert_recovered "$identity_work/cgroup-reuse-first.json"
identity_read_binding_state "$identity_cgroup_path" \
  "$identity_work/cgroup-reuse-first-binding.json"

identity_stop_node
kill -TERM "$reuse_first_pid"
wait "$reuse_first_pid" 2>/dev/null || true
rmdir -- "$identity_cgroup_path"
mkdir -- "$identity_cgroup_path"

/bin/sleep 300 &
reuse_second_pid=$!
identity_task_pids+=("$reuse_second_pid")
printf '%s\n' "$reuse_second_pid" >"$identity_cgroup_path/cgroup.procs"
reuse_write_config "$(printf 'b%.0s' {1..64})" second-pod second-sandbox 2
identity_start_node
identity_wait_for_task_snapshot cgroup-reuse-second "$reuse_second_pid"
identity_assert_recovered "$identity_work/cgroup-reuse-second.json"
identity_read_binding_state "$identity_cgroup_path" \
  "$identity_work/cgroup-reuse-second-binding.json"

jq -e --slurpfile second "$identity_work/cgroup-reuse-second.json" '
  .task_cookie != $second[0].task_cookie
  and .process_state_id != $second[0].process_state_id
  and .active_execution_id != $second[0].active_execution_id
  and .active_role_id == $second[0].active_role_id
' "$identity_work/cgroup-reuse-first.json" >/dev/null
jq -e --slurpfile second "$identity_work/cgroup-reuse-second-binding.json" '
  .root_cgroup_id != $second[0].root_cgroup_id
  and .binding_nonce != $second[0].binding_nonce
  and .root_cgroup_live_interval_id != $second[0].root_cgroup_live_interval_id
' "$identity_work/cgroup-reuse-first-binding.json" >/dev/null

identity_pass \
  "PASS: one cgroup path was recreated with a fresh cgroup, binding, task, and process lifetime."
