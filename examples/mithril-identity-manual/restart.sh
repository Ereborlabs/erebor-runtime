#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/identity-runtime.sh"

[[ $# -eq 0 ]] || {
  echo "usage: sudo $0" >&2
  exit 2
}

restart_k3s_stopped=false
restart_restore_k3s() {
  if [[ $restart_k3s_stopped == true ]]; then
    systemctl start k3s || return 1
    kubectl wait --for=condition=Ready node --all --timeout=120s >/dev/null || return 1
    restart_k3s_stopped=false
  fi
}

restart_wait_supported() {
  local output=$1
  for ((attempt = 0; attempt < 300; attempt++)); do
    if "$identity_inspect" effects --socket-path "$restart_socket" --cgroup-scope / \
      >"$output" 2>/dev/null \
      && grep -Fq 'capability=EXACT_NATIVE_IDENTITY state=SUPPORTED' "$output"; then
      return 0
    fi
    sleep 0.1
  done
  echo "exact native identity did not return to supported state" >&2
  return 1
}

identity_prepare_k3s_case \
  docker.io/library/python@sha256:78098ea6a3a9c6a7727a5d4674e4a44e57e01fac878ee9cb4d24a86bd93916ff
identity_cleanup_functions=(restart_restore_k3s "${identity_cleanup_functions[@]}")

restart_socket=$identity_work/observation.sock
jq --arg socket "$restart_socket" \
  '.runtime_observation = {
     socket_path: $socket,
     allowed_uid: 0,
     cgroup_scope: "/"
   }' "$identity_config" >"$identity_work/node-with-observation.json"
mv -- "$identity_work/node-with-observation.json" "$identity_config"

identity_start_node
identity_wait_for_initial_binding
identity_inspect_task restart-discovered "$identity_init_pid" >/dev/null
identity_assert_recovered "$identity_work/restart-discovered.json"
restart_wait_supported "$identity_work/restart-initial-supported.txt"

restart_ready=$identity_k3s_shared_directory/restart.pid
restart_ready_container=$identity_k3s_container_shared_directory/restart.pid
rm -f -- "$restart_ready"
crictl --runtime-endpoint "$identity_runtime_endpoint" exec "$identity_container_id" \
  /bin/sh -c '
    printf "%s\n" "$$" >"$1"
    kill -STOP "$$"
    read -r restart_hostname < /etc/hostname
  ' sh "$restart_ready_container" >/dev/null 2>&1 &
restart_client_pid=$!
identity_task_pids+=("$restart_client_pid")
for ((attempt = 0; attempt < 300; attempt++)); do
  [[ -s $restart_ready ]] && break
  kill -0 "$restart_client_pid" 2>/dev/null || {
    echo "direct CRI exec exited before it reported its container PID" >&2
    exit 1
  }
  sleep 0.1
done
[[ -s $restart_ready ]] || {
  echo "direct CRI exec did not report its container PID" >&2
  exit 1
}
restart_namespace_pid=$(<"$restart_ready")
restart_host_pid=$(identity_kubernetes_host_pid "$restart_namespace_pid") || {
  echo "could not map the direct CRI exec to its host PID" >&2
  exit 1
}
for ((attempt = 0; attempt < 300; attempt++)); do
  grep -q $'^State:\tT' "/proc/$restart_host_pid/status" && break
  sleep 0.1
done
grep -q $'^State:\tT' "/proc/$restart_host_pid/status"
identity_wait_for_task_snapshot restart-bound "$restart_host_pid"
identity_assert_external "$identity_work/restart-bound.json"

systemctl stop k3s
restart_k3s_stopped=true
for ((attempt = 0; attempt < 300; attempt++)); do
  if "$identity_inspect" effects --socket-path "$restart_socket" --cgroup-scope / \
    >"$identity_work/restart-runtime-gap.txt" 2>/dev/null \
    && grep -Fq \
      'capability=EXACT_NATIVE_IDENTITY state=UNHEALTHY reason=LIVE_IDENTITY_RECONCILIATION_FAILED' \
      "$identity_work/restart-runtime-gap.txt"; then
    break
  fi
  sleep 0.1
done
grep -Fq \
  'capability=EXACT_NATIVE_IDENTITY state=UNHEALTHY reason=LIVE_IDENTITY_RECONCILIATION_FAILED' \
  "$identity_work/restart-runtime-gap.txt"
identity_inspect_task restart-runtime-gap "$restart_host_pid" >/dev/null
cmp --silent "$identity_work/restart-bound.json" \
  "$identity_work/restart-runtime-gap.json"

restart_restore_k3s
restart_wait_supported "$identity_work/restart-runtime-supported.txt"
identity_inspect_task restart-runtime-recovered "$restart_host_pid" >/dev/null
cmp --silent "$identity_work/restart-bound.json" \
  "$identity_work/restart-runtime-recovered.json"

identity_stop_node
if "$identity_inspect" effects --socket-path "$restart_socket" --cgroup-scope / \
  >"$identity_work/restart-node-gap.txt" 2>&1; then
  echo "node observation remained available after the node stopped" >&2
  exit 1
fi
identity_inspect_task restart-node-gap "$restart_host_pid" >/dev/null
cmp --silent "$identity_work/restart-bound.json" \
  "$identity_work/restart-node-gap.json"

identity_start_node
restart_wait_supported "$identity_work/restart-node-supported.txt"
identity_inspect_task restart-node-recovered "$restart_host_pid" >/dev/null
cmp --silent "$identity_work/restart-bound.json" \
  "$identity_work/restart-node-recovered.json"

kill -CONT "$restart_host_pid"
wait "$restart_client_pid"
identity_pass "PASS: Kubernetes service and node restart gaps remain explicit and retain the live identity."
