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

ready_name=native-command-pid
release_name=native-command-release
ready_host=$identity_k3s_shared_directory/$ready_name
release_host=$identity_k3s_shared_directory/$release_name
ready_container=$identity_k3s_container_shared_directory/$ready_name
release_container=$identity_k3s_container_shared_directory/$release_name
entry_command='read identity_pid _ < /proc/self/stat; printf "%s\n" "$identity_pid" > "$1"; while [ ! -f "$2" ]; do sleep 0.1; done'
rm -f -- "$ready_host" "$release_host"

crictl --runtime-endpoint "$identity_runtime_endpoint" exec "$identity_container_id" \
  /bin/sh -c '/bin/sh -c "$1" sh "$2" "$3" & wait "$!"' \
  mithril-native-parent "$entry_command" "$ready_container" "$release_container" \
  >/dev/null 2>&1 &
client_pid=$!
identity_task_pids+=("$client_pid")
for ((attempt = 0; attempt < 300; attempt++)); do
  [[ -s $ready_host ]] && break
  kill -0 "$client_pid" 2>/dev/null || {
    echo "native-child control exited before it reported its container PID" >&2
    exit 1
  }
  sleep 0.1
done
[[ -s $ready_host ]] || {
  echo "native-child control did not report its container PID" >&2
  exit 1
}
namespace_pid=$(<"$ready_host")
child_host_pid=$(identity_kubernetes_host_pid "$namespace_pid") || {
  echo "could not map the native-child control to its host PID" >&2
  exit 1
}
parent_host_pid=$(awk '/^PPid:/ {print $2}' "/proc/$child_host_pid/status")
[[ $parent_host_pid =~ ^[1-9][0-9]*$ && -d /proc/$parent_host_pid ]] || {
  echo "native-child control has no live parent" >&2
  exit 1
}
identity_inspect_task native-command-parent "$parent_host_pid"
identity_inspect_task native-command-child "$child_host_pid"
identity_assert_external "$identity_work/native-command-parent.json"
parent_cookie=$(jq -er '.task_cookie' "$identity_work/native-command-parent.json")
parent_role=$(jq -er '.active_role_id' "$identity_work/native-command-parent.json")
jq -e --argjson parent_cookie "$parent_cookie" --argjson parent_role "$parent_role" \
  '.creator_task_cookie == $parent_cookie
   and .real_parent_task_cookie == $parent_cookie
   and .root_class == null
   and .installed_role_class == null
   and .active_role_id == $parent_role' \
  "$identity_work/native-command-child.json" >/dev/null
printf 'release\n' >"$release_host"
wait "$client_pid"
identity_pass "PASS: the identical native child kept its parent lineage and role."
