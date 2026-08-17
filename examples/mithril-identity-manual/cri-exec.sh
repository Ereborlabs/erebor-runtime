#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/identity-runtime.sh"

[[ $# -eq 0 ]] || {
  echo "usage: sudo $0" >&2
  exit 2
}

identity_prepare_k3s_case \
  docker.io/library/python@sha256:78098ea6a3a9c6a7727a5d4674e4a44e57e01fac878ee9cb4d24a86bd93916ff
identity_start_node
identity_wait_for_initial_binding

ready_name=cri-exec-pid
release_name=cri-exec-release
ready_host=$identity_k3s_shared_directory/$ready_name
release_host=$identity_k3s_shared_directory/$release_name
ready_container=$identity_k3s_container_shared_directory/$ready_name
release_container=$identity_k3s_container_shared_directory/$release_name
rm -f -- "$ready_host" "$release_host"

crictl --runtime-endpoint "$identity_runtime_endpoint" exec "$identity_container_id" \
  /bin/sh -c 'printf "%s\n" "$$" >"$1"; while [ ! -f "$2" ]; do sleep 0.1; done' \
  sh "$ready_container" "$release_container" >/dev/null 2>&1 &
client_pid=$!
identity_task_pids+=("$client_pid")
for ((attempt = 0; attempt < 300; attempt++)); do
  [[ -s $ready_host ]] && break
  kill -0 "$client_pid" 2>/dev/null || {
    echo "direct CRI exec exited before it reported its container PID" >&2
    exit 1
  }
  sleep 0.1
done
[[ -s $ready_host ]] || {
  echo "direct CRI exec did not report its container PID" >&2
  exit 1
}
namespace_pid=$(<"$ready_host")
identity_read_pid=$(identity_kubernetes_host_pid "$namespace_pid") || {
  echo "could not map the direct CRI exec to its host PID" >&2
  exit 1
}
identity_inspect_task cri-exec "$identity_read_pid"
identity_assert_external "$identity_work/cri-exec.json"
printf 'release\n' >"$release_host"
wait "$client_pid"
identity_pass "PASS: direct CRI exec is a restricted external root."
