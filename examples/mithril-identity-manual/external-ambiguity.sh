#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/identity-runtime.sh"

[[ $# -eq 0 ]] || {
  echo "usage: sudo $0" >&2
  exit 2
}

external_ambiguity_verify_cgroup_removed() {
  [[ ! -e $external_ambiguity_cgroup_path ]] || {
    echo "external-ambiguity Pod cgroup survived cleanup: $external_ambiguity_cgroup_path" >&2
    return 1
  }
}

identity_prepare_k3s_case \
  docker.io/library/python@sha256:78098ea6a3a9c6a7727a5d4674e4a44e57e01fac878ee9cb4d24a86bd93916ff
external_ambiguity_cgroup_path=$identity_cgroup_path
identity_cleanup_functions+=(external_ambiguity_verify_cgroup_removed)
identity_start_node

external_ambiguity_release=$identity_work/external-ambiguity-release
external_ambiguity_pids=()
for _ in 1 2; do
  bash -c '
    while [[ ! -e $1 ]]; do
      sleep 0.1
    done
    exec sleep 300
  ' bash "$external_ambiguity_release" &
  external_ambiguity_pids+=("$!")
  identity_task_pids+=("$!")
done

for pid in "${external_ambiguity_pids[@]}"; do
  printf '%s\n' "$pid" >"$identity_cgroup_path/cgroup.procs"
done

for index in 0 1; do
  name=external-ambiguity-$index
  pid=${external_ambiguity_pids[$index]}
  for ((attempt = 0; attempt < 100; attempt++)); do
    identity_inspect_task "$name" "$pid" >/dev/null 2>&1 || true
    jq -e '.creator_task_cookie == null
           and .root_class == "external_runtime_root"
           and .installed_role_class == "runtime_external_restricted"
           and .coordinate_state == 3' \
      "$identity_work/$name.json" >/dev/null 2>&1 && break
    sleep 0.1
  done
  identity_assert_external "$identity_work/$name.json"
done

first=$identity_work/external-ambiguity-0.json
second=$identity_work/external-ambiguity-1.json
external_role_id=$(jq -er '.workload_bindings[0].external_role_id' "$identity_config")
jq -e --slurpfile second "$second" --argjson external_role_id "$external_role_id" '
  .task_cookie != $second[0].task_cookie
  and .process_state_id != $second[0].process_state_id
  and .active_role_id == $external_role_id
  and .active_role_id == $second[0].active_role_id
' "$first" >/dev/null

: >"$external_ambiguity_release"
identity_pass "PASS: concurrent indistinguishable external roots stay separate and restricted."
