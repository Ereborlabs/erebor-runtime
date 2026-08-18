#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/identity-runtime.sh"

[[ $# -eq 0 ]] || {
  echo "usage: sudo $0" >&2
  exit 2
}

identity_prepare_k3s_ephemeral_case
identity_start_node
identity_wait_for_task_snapshot application-root "$identity_k3s_application_pid"
identity_wait_for_task_snapshot ephemeral-root "$identity_k3s_ephemeral_pid"
identity_assert_recovered "$identity_work/application-root.json"
identity_assert_recovered "$identity_work/ephemeral-root.json"

application_pid_namespace=$(stat -Lc %i "/proc/$identity_k3s_application_pid/ns/pid")
ephemeral_pid_namespace=$(stat -Lc %i "/proc/$identity_k3s_ephemeral_pid/ns/pid")
[[ $application_pid_namespace == "$ephemeral_pid_namespace" ]] || {
  echo "the ephemeral container does not share the application PID namespace" >&2
  exit 1
}
jq -e --slurpfile ephemeral "$identity_work/ephemeral-root.json" '
  .task_cookie != $ephemeral[0].task_cookie
    and .process_state_id != $ephemeral[0].process_state_id
    and .execution_set_id != null
    and $ephemeral[0].execution_set_id != null
    and .execution_set_id != $ephemeral[0].execution_set_id
    and .profile_generation_ref_id != $ephemeral[0].profile_generation_ref_id
' "$identity_work/application-root.json" >/dev/null || {
  echo "the ephemeral container merged with the application identity tree" >&2
  exit 1
}
jq -e '
  .workload_bindings[0].sandbox_id == .workload_bindings[1].sandbox_id
    and .workload_bindings[0].container_kind == "application"
    and .workload_bindings[1].container_kind == "ephemeral"
' "$identity_config" >/dev/null || {
  echo "the application and ephemeral CRI bindings do not share one Pod sandbox" >&2
  exit 1
}

printf 'application root: task %s; execution set %s; profile %s\n' \
  "$(jq -r '.task_cookie' "$identity_work/application-root.json")" \
  "$(jq -r '.execution_set_id' "$identity_work/application-root.json")" \
  "$(jq -r '.profile_generation_ref_id' "$identity_work/application-root.json")"
printf 'ephemeral root: task %s; execution set %s; profile %s\n' \
  "$(jq -r '.task_cookie' "$identity_work/ephemeral-root.json")" \
  "$(jq -r '.execution_set_id' "$identity_work/ephemeral-root.json")" \
  "$(jq -r '.profile_generation_ref_id' "$identity_work/ephemeral-root.json")"
printf 'shared PID namespace inode: %s\n' "$application_pid_namespace"
identity_pass "PASS: the targeted ephemeral container kept an independent identity tree."
