#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/identity-runtime.sh"

[[ $# -eq 0 ]] || {
  echo "usage: sudo $0" >&2
  exit 2
}

wait_for_new_slot_pid() {
  local slot=$1
  shift
  local attempt marker marker_pid pid excluded is_excluded
  for ((attempt = 0; attempt < 300; attempt++)); do
    for marker in "$identity_k3s_shared_directory/$slot-"*.pid; do
      [[ -f $marker ]] || continue
      pid=$(<"$marker")
      marker_pid=${marker##*/$slot-}
      marker_pid=${marker_pid%.pid}
      [[ $pid =~ ^[1-9][0-9]*$ && $pid == "$marker_pid" ]] || {
        echo "the $slot PID marker is invalid: $marker" >&2
        return 1
      }
      is_excluded=false
      for excluded in "$@"; do
        [[ $pid == "$excluded" ]] && is_excluded=true
      done
      if [[ $is_excluded == false ]]; then
        printf '%s\n' "$pid"
        return 0
      fi
    done
    sleep 0.1
  done
  echo "the $slot entry did not report a new namespace PID" >&2
  return 1
}

host_pid_in_container() {
  local init_pid=$1
  local namespace_pid=$2
  local cgroup host_pid mapped_pid
  cgroup=$(identity_cgroup_for_pid "$init_pid")
  while read -r host_pid; do
    [[ -r /proc/$host_pid/status ]] || continue
    mapped_pid=$(awk '/^NSpid:/ {print $NF}' "/proc/$host_pid/status")
    if [[ $mapped_pid == "$namespace_pid" ]]; then
      printf '%s\n' "$host_pid"
      return 0
    fi
  done <"$cgroup/cgroup.procs"
  return 1
}

release_slot_pid() {
  local slot=$1
  local namespace_pid=$2
  local fifo=$identity_k3s_shared_directory/$slot-release-$namespace_pid
  local attempt
  for ((attempt = 0; attempt < 300; attempt++)); do
    [[ -p $fifo ]] && break
    sleep 0.1
  done
  [[ -p $fifo ]] || {
    echo "the $slot release FIFO does not exist for namespace PID $namespace_pid" >&2
    return 1
  }
  printf 'release\n' >"$fifo"
}

identity_prepare_k3s_probe_impersonation_case
identity_start_node
identity_wait_for_task_snapshot application-parent "$identity_k3s_application_pid"
identity_assert_recovered "$identity_work/application-parent.json"

printf 'start\n' >"$identity_k3s_shared_directory/native-start"
native_namespace_pid=$(wait_for_new_slot_pid application)
native_host_pid=$(host_pid_in_container \
  "$identity_k3s_application_pid" "$native_namespace_pid")

kubectl -n "$identity_k3s_namespace" exec mithril-probe-impersonation \
  -c application -- /bin/sh -c "$identity_probe_command" >/dev/null 2>&1 &
kubectl_client_pid=$!
identity_task_pids+=("$kubectl_client_pid")
kubectl_namespace_pid=$(wait_for_new_slot_pid application "$native_namespace_pid")
kubectl_host_pid=$(host_pid_in_container \
  "$identity_k3s_application_pid" "$kubectl_namespace_pid")

crictl --runtime-endpoint "$identity_runtime_endpoint" exec \
  "$identity_k3s_application_container_id" \
  /bin/sh -c "$identity_probe_command" >/dev/null 2>&1 &
cri_client_pid=$!
identity_task_pids+=("$cri_client_pid")
cri_namespace_pid=$(wait_for_new_slot_pid \
  application "$native_namespace_pid" "$kubectl_namespace_pid")
cri_host_pid=$(host_pid_in_container \
  "$identity_k3s_application_pid" "$cri_namespace_pid")

startup_namespace_pid=$(wait_for_new_slot_pid startup)
readiness_namespace_pid=$(wait_for_new_slot_pid readiness)
liveness_namespace_pid=$(wait_for_new_slot_pid liveness)
startup_host_pid=$(host_pid_in_container \
  "$identity_k3s_startup_pid" "$startup_namespace_pid")
readiness_host_pid=$(host_pid_in_container \
  "$identity_k3s_readiness_pid" "$readiness_namespace_pid")
liveness_host_pid=$(host_pid_in_container \
  "$identity_k3s_liveness_pid" "$liveness_namespace_pid")

kill -0 "$kubectl_client_pid"
kill -0 "$cri_client_pid"
for entry in \
  "startup-probe:$startup_host_pid" \
  "readiness-probe:$readiness_host_pid" \
  "liveness-probe:$liveness_host_pid" \
  "native-child:$native_host_pid" \
  "kubectl-exec:$kubectl_host_pid" \
  "cri-exec:$cri_host_pid"; do
  name=${entry%%:*}
  pid=${entry#*:}
  identity_wait_for_task_snapshot "$name" "$pid"
done

for name in startup-probe readiness-probe liveness-probe kubectl-exec cri-exec; do
  identity_assert_external "$identity_work/$name.json"
done
external_role=$(jq -er '.workload_bindings[3].external_role_id' "$identity_config")
jq -s -e --argjson external_role "$external_role" \
  'all(.[]; .active_role_id == $external_role)' \
  "$identity_work/startup-probe.json" \
  "$identity_work/readiness-probe.json" \
  "$identity_work/liveness-probe.json" \
  "$identity_work/kubectl-exec.json" \
  "$identity_work/cri-exec.json" >/dev/null
parent_cookie=$(jq -er '.task_cookie' "$identity_work/application-parent.json")
parent_role=$(jq -er '.active_role_id' "$identity_work/application-parent.json")
jq -e --argjson parent_cookie "$parent_cookie" --argjson parent_role "$parent_role" '
  .creator_task_cookie == $parent_cookie
    and .real_parent_task_cookie == $parent_cookie
    and .root_class == null
    and .installed_role_class == null
    and .active_role_id == $parent_role
' "$identity_work/native-child.json" >/dev/null
jq -s -e '
  (map(.task_cookie) | unique | length) == 7
    and (map(.process_state_id) | unique | length) == 7
' \
  "$identity_work/application-parent.json" \
  "$identity_work/startup-probe.json" \
  "$identity_work/readiness-probe.json" \
  "$identity_work/liveness-probe.json" \
  "$identity_work/native-child.json" \
  "$identity_work/kubectl-exec.json" \
  "$identity_work/cri-exec.json" >/dev/null

for release in \
  "startup:$startup_namespace_pid" \
  "readiness:$readiness_namespace_pid" \
  "liveness:$liveness_namespace_pid" \
  "application:$native_namespace_pid" \
  "application:$kubectl_namespace_pid" \
  "application:$cri_namespace_pid"; do
  release_slot_pid "${release%%:*}" "${release#*:}"
done
wait "$kubectl_client_pid"
wait "$cri_client_pid"

printf 'application parent task: %s\n' "$parent_cookie"
for name in startup-probe readiness-probe liveness-probe native-child kubectl-exec cri-exec; do
  printf '%s task: %s; root: %s\n' \
    "$name" \
    "$(jq -r '.task_cookie' "$identity_work/$name.json")" \
    "$(jq -r '.root_class // "native"' "$identity_work/$name.json")"
done
identity_pass "PASS: identical bytes kept native lineage and every independent entry restricted."
