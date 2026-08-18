#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/identity-runtime.sh"

[[ $# -eq 0 ]] || {
  echo "usage: sudo $0" >&2
  exit 2
}

wait_for_task_snapshot() {
  local name=$1
  local pid=$2
  local attempt
  for ((attempt = 0; attempt < 300; attempt++)); do
    if "$identity_inspect" --pin-root "$identity_pin_root" task --host-pid "$pid" \
      >"$identity_work/$name.json" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  echo "Mithril did not publish the $name identity" >&2
  return 1
}

identity_prepare_k3s_containers_case
identity_configure_k3s_containers_stage init
identity_start_node

wait_for_task_snapshot init-root "$identity_k3s_init_pid"
wait_for_task_snapshot sidecar-before "$identity_k3s_sidecar_pid"
identity_assert_recovered "$identity_work/init-root.json"
identity_assert_recovered "$identity_work/sidecar-before.json"
jq -e --slurpfile sidecar "$identity_work/sidecar-before.json" '
  .task_cookie != $sidecar[0].task_cookie
    and .process_state_id != $sidecar[0].process_state_id
    and .execution_set_id != null
    and $sidecar[0].execution_set_id != null
    and .execution_set_id != $sidecar[0].execution_set_id
' "$identity_work/init-root.json" >/dev/null || {
  echo "the init and native sidecar roots are not independent" >&2
  exit 1
}
init_execution_set=$(jq -er '.execution_set_id' "$identity_work/init-root.json")
sidecar_execution_set=$(jq -er '.execution_set_id' "$identity_work/sidecar-before.json")

identity_stop_node
touch "$identity_k3s_shared_directory/release-init"
kubectl -n "$identity_k3s_namespace" wait --for=condition=Ready \
  pod/mithril-containers --timeout=180s >/dev/null

identity_configure_k3s_containers_stage application
identity_start_node
wait_for_task_snapshot sidecar-root "$identity_k3s_sidecar_pid"
wait_for_task_snapshot application-root "$identity_k3s_application_pid"
identity_assert_recovered "$identity_work/sidecar-root.json"
identity_assert_recovered "$identity_work/application-root.json"
jq -e --slurpfile application "$identity_work/application-root.json" \
  --arg init_execution_set "$init_execution_set" \
  --arg sidecar_execution_set "$sidecar_execution_set" '
  .task_cookie != $application[0].task_cookie
    and .process_state_id != $application[0].process_state_id
    and .execution_set_id == $sidecar_execution_set
    and $application[0].execution_set_id != null
    and $application[0].execution_set_id != $init_execution_set
    and $application[0].execution_set_id != $sidecar_execution_set
' "$identity_work/sidecar-root.json" >/dev/null || {
  echo "the native sidecar and application roots are not independent" >&2
  exit 1
}

printf 'init root: task %s; execution set %s\n' \
  "$(jq -r '.task_cookie' "$identity_work/init-root.json")" "$init_execution_set"
printf 'native sidecar root: task %s; execution set %s\n' \
  "$(jq -r '.task_cookie' "$identity_work/sidecar-root.json")" "$sidecar_execution_set"
printf 'application root: task %s; execution set %s\n' \
  "$(jq -r '.task_cookie' "$identity_work/application-root.json")" \
  "$(jq -r '.execution_set_id' "$identity_work/application-root.json")"
identity_pass "PASS: init, native sidecar, and application kept independent roots and execution sets."
