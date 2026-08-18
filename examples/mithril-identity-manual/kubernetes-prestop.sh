#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/identity-runtime.sh"

[[ $# -eq 0 ]] || {
  echo "usage: sudo $0" >&2
  exit 2
}

wait_for_prestop_pid() {
  local attempt marker marker_pid pid
  for ((attempt = 0; attempt < 600; attempt++)); do
    for marker in "$identity_k3s_shared_directory/prestop-"*.pid; do
      [[ -f $marker ]] || continue
      pid=$(<"$marker")
      marker_pid=${marker##*/prestop-}
      marker_pid=${marker_pid%.pid}
      [[ $pid =~ ^[1-9][0-9]*$ && $pid == "$marker_pid" ]] || {
        echo "the PreStop PID marker is invalid: $marker" >&2
        return 1
      }
      printf '%s\n' "$pid"
      return 0
    done
    sleep 0.1
  done
  echo "the Kubernetes PreStop hook did not report its namespace PID" >&2
  return 1
}

host_pid_in_application() {
  local namespace_pid=$1
  local host_pid mapped_pid
  while read -r host_pid; do
    [[ -r /proc/$host_pid/status ]] || continue
    mapped_pid=$(awk '/^NSpid:/ {print $NF}' "/proc/$host_pid/status")
    if [[ $mapped_pid == "$namespace_pid" ]]; then
      printf '%s\n' "$host_pid"
      return 0
    fi
  done <"$identity_cgroup_path/cgroup.procs"
  return 1
}

identity_prepare_k3s_prestop_case
identity_start_node
identity_wait_for_task_snapshot application-before "$identity_k3s_application_pid"
identity_assert_recovered "$identity_work/application-before.json"

kubectl -n "$identity_k3s_namespace" delete pod mithril-prestop \
  --wait=true --timeout=90s >/dev/null &
delete_pid=$!
identity_task_pids+=("$delete_pid")
prestop_namespace_pid=$(wait_for_prestop_pid)
identity_prestop_release_fifo=$identity_k3s_shared_directory/prestop-release-$prestop_namespace_pid
prestop_host_pid=$(host_pid_in_application "$prestop_namespace_pid")
[[ $prestop_host_pid != "$identity_k3s_application_pid" ]] || {
  echo "the Kubernetes PreStop hook did not create a separate task" >&2
  exit 1
}
kill -0 "$delete_pid"

identity_wait_for_task_snapshot application-during "$identity_k3s_application_pid"
identity_wait_for_task_snapshot prestop-root "$prestop_host_pid"
identity_assert_external "$identity_work/prestop-root.json"
jq -s -e '.[0] == .[1]' \
  "$identity_work/application-before.json" \
  "$identity_work/application-during.json" >/dev/null
external_role=$(jq -er '.workload_bindings[0].external_role_id' "$identity_config")
jq -e --argjson external_role "$external_role" \
  '.active_role_id == $external_role' "$identity_work/prestop-root.json" >/dev/null
jq -s -e '
  .[0].task_cookie != .[1].task_cookie
    and .[0].process_state_id != .[1].process_state_id
' "$identity_work/application-before.json" "$identity_work/prestop-root.json" >/dev/null

printf 'release\n' >"$identity_prestop_release_fifo"
wait "$delete_pid"
identity_prestop_release_fifo=
if kubectl -n "$identity_k3s_namespace" get pod mithril-prestop >/dev/null 2>&1; then
  echo "the Kubernetes PreStop Pod remains after hook release" >&2
  exit 1
fi

printf 'application task retained during termination: %s\n' \
  "$(jq -r '.task_cookie' "$identity_work/application-during.json")"
printf 'PreStop task: %s; root: %s\n' \
  "$(jq -r '.task_cookie' "$identity_work/prestop-root.json")" \
  "$(jq -r '.root_class' "$identity_work/prestop-root.json")"
identity_pass "PASS: PreStop kept application identity and used a fresh restricted external root."
