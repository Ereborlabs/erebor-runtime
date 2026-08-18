#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/identity-runtime.sh"

[[ $# -eq 0 ]] || {
  echo "usage: sudo $0" >&2
  exit 2
}

identity_require_command cmp
identity_prepare_k3s_case \
  docker.io/library/busybox:1.36.1@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662
identity_start_node
identity_wait_for_initial_binding

ready_name=kubectl-copy-pid
release_name=kubectl-copy-release
source_name=kubectl-copy-source
ready_host=$identity_k3s_shared_directory/$ready_name
release_host=$identity_k3s_shared_directory/$release_name
ready_container=$identity_k3s_container_shared_directory/$ready_name
release_container=$identity_k3s_container_shared_directory/$release_name
source_host=$identity_k3s_shared_directory/$source_name
source_container=$identity_k3s_container_shared_directory/$source_name
copy_result=$identity_work/kubectl-copy-result
tar_wrapper=$identity_k3s_shared_directory/tar
rm -f -- "$ready_host" "$release_host" "$copy_result"
printf 'mithril kubectl copy fixture\n' >"$source_host"
printf '%s\n' \
  '#!/bin/sh' \
  'read identity_pid _ < /proc/self/stat' \
  "printf '%s\\n' \"\$identity_pid\" > '$ready_container'" \
  "while [ ! -f '$release_container' ]; do sleep 0.1; done" \
  'exec /bin/tar "$@"' >"$tar_wrapper"
chmod 0700 "$tar_wrapper"

kubectl -n "$identity_k3s_namespace" cp \
  "mithril-runtime:$source_container" "$copy_result" -c runtime \
  >"$identity_work/kubectl-copy.log" 2>&1 &
client_pid=$!
identity_task_pids+=("$client_pid")
for ((attempt = 0; attempt < 300; attempt++)); do
  [[ -s $ready_host ]] && break
  kill -0 "$client_pid" 2>/dev/null || {
    echo "kubectl cp exited before it reported its container PID" >&2
    tail -n 20 "$identity_work/kubectl-copy.log" >&2
    exit 1
  }
  sleep 0.1
done
[[ -s $ready_host ]] || {
  echo "kubectl cp did not report its container PID" >&2
  exit 1
}
namespace_pid=$(<"$ready_host")
identity_read_pid=$(identity_kubernetes_host_pid "$namespace_pid") || {
  echo "could not map kubectl cp to its host PID" >&2
  exit 1
}
identity_inspect_task kubernetes-copy "$identity_read_pid"
identity_assert_external "$identity_work/kubernetes-copy.json"
printf 'release\n' >"$release_host"
wait "$client_pid"
cmp -s "$source_host" "$copy_result" || {
  echo "kubectl cp did not copy the exact fixture bytes" >&2
  exit 1
}
identity_pass "PASS: kubectl cp is a restricted external root and copied the exact bytes."
