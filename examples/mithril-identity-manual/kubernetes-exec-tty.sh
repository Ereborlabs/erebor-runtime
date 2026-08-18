#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/identity-runtime.sh"

[[ $# -eq 0 ]] || {
  echo "usage: sudo $0" >&2
  exit 2
}

identity_require_command script
identity_prepare_k3s_case \
  docker.io/library/python@sha256:78098ea6a3a9c6a7727a5d4674e4a44e57e01fac878ee9cb4d24a86bd93916ff
identity_start_node
identity_wait_for_initial_binding

ready_name=kubectl-tty-exec-pid
release_name=kubectl-tty-exec-release
ready_host=$identity_k3s_shared_directory/$ready_name
release_host=$identity_k3s_shared_directory/$release_name
ready_container=$identity_k3s_container_shared_directory/$ready_name
release_container=$identity_k3s_container_shared_directory/$release_name
entry_command='read identity_pid _ < /proc/self/stat; printf "%s\n" "$identity_pid" > "$1"; while [ ! -f "$2" ]; do sleep 0.1; done'
rm -f -- "$ready_host" "$release_host"

printf -v tty_command '%q ' \
  kubectl -n "$identity_k3s_namespace" exec -i -t mithril-runtime -c runtime -- \
  /bin/sh -c "$entry_command" sh "$ready_container" "$release_container"
script -qfec "$tty_command" /dev/null >"$identity_work/kubectl-tty.log" 2>&1 &
client_pid=$!
identity_task_pids+=("$client_pid")
for ((attempt = 0; attempt < 300; attempt++)); do
  [[ -s $ready_host ]] && break
  kill -0 "$client_pid" 2>/dev/null || {
    echo "TTY kubectl exec exited before it reported its container PID" >&2
    tail -n 20 "$identity_work/kubectl-tty.log" >&2
    exit 1
  }
  sleep 0.1
done
[[ -s $ready_host ]] || {
  echo "TTY kubectl exec did not report its container PID" >&2
  exit 1
}
namespace_pid=$(<"$ready_host")
identity_read_pid=$(identity_kubernetes_host_pid "$namespace_pid") || {
  echo "could not map TTY kubectl exec to its host PID" >&2
  exit 1
}
identity_inspect_task kubernetes-tty-exec "$identity_read_pid"
identity_assert_external "$identity_work/kubernetes-tty-exec.json"
printf 'release\n' >"$release_host"
wait "$client_pid"
identity_pass "PASS: TTY kubectl exec is a restricted external root."
