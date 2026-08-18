#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/identity-runtime.sh"

[[ $# -eq 0 ]] || {
  echo "usage: sudo $0" >&2
  exit 2
}

wait_for_slot_pid() {
  local slot=$1
  shift
  local attempt marker marker_pid pid excluded skip
  for ((attempt = 0; attempt < 600; attempt++)); do
    for marker in "$identity_k3s_shared_directory/$slot-"*.pid; do
      [[ -f $marker ]] || continue
      pid=$(<"$marker")
      marker_pid=${marker##*/$slot-}
      marker_pid=${marker_pid%.pid}
      [[ $pid =~ ^[1-9][0-9]*$ && $pid == "$marker_pid" ]] || {
        echo "the $slot PID marker is invalid: $marker" >&2
        return 1
      }
      skip=false
      for excluded in "$@"; do
        [[ $pid == "$excluded" ]] && skip=true
      done
      if [[ $skip == false ]]; then
        printf '%s\n' "$pid"
        return 0
      fi
    done
    sleep 0.1
  done
  echo "the $slot task did not report a namespace PID" >&2
  return 1
}

wait_for_order() {
  local slot=$1
  local path=$identity_k3s_shared_directory/$slot.order
  local attempt value
  for ((attempt = 0; attempt < 600; attempt++)); do
    if [[ -s $path ]]; then
      value=$(<"$path")
      if awk -v value="$value" 'BEGIN { exit !(value > 0) }'; then
        printf '%s\n' "$value"
        return 0
      fi
      echo "the $slot order is invalid: $value" >&2
      return 1
    fi
    sleep 0.1
  done
  echo "the $slot task did not report its order" >&2
  return 1
}

wait_for_host_pid() {
  local init_pid=$1
  local namespace_pid=$2
  local cgroup attempt host_pid mapped_pid
  cgroup=$(identity_cgroup_for_pid "$init_pid")
  for ((attempt = 0; attempt < 300; attempt++)); do
    while read -r host_pid; do
      [[ -r /proc/$host_pid/status ]] || continue
      mapped_pid=$(awk '/^NSpid:/ {print $NF}' "/proc/$host_pid/status")
      if [[ $mapped_pid == "$namespace_pid" ]]; then
        printf '%s\n' "$host_pid"
        return 0
      fi
    done <"$cgroup/cgroup.procs"
    sleep 0.1
  done
  echo "could not map namespace PID $namespace_pid in $cgroup" >&2
  return 1
}

release_slot_pid() {
  local slot=$1
  local namespace_pid=$2
  local fifo=$identity_k3s_shared_directory/$slot-release-$namespace_pid
  local attempt
  identity_poststart_release_fifos+=("$fifo")
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

identity_prepare_k3s_poststart_case

entrypoint_first_pid=$(wait_for_slot_pid entrypoint-first)
entrypoint_first_hook_pid=$(wait_for_slot_pid poststart-entrypoint-first)
hook_first_pid=$(wait_for_slot_pid entrypoint-hook-first)
hook_first_hook_pid=$(wait_for_slot_pid poststart-hook-first)
repeat_first_hook_pid=$(wait_for_slot_pid poststart-repeat)
entrypoint_first_order=$(wait_for_order entrypoint-first)
entrypoint_first_hook_order=$(wait_for_order poststart-entrypoint-first)
hook_first_order=$(wait_for_order entrypoint-hook-first)
hook_first_hook_order=$(wait_for_order poststart-hook-first)
awk \
  -v entrypoint="$entrypoint_first_order" \
  -v entrypoint_hook="$entrypoint_first_hook_order" \
  -v hook="$hook_first_order" \
  -v hook_first="$hook_first_hook_order" \
  'BEGIN { exit !(entrypoint < entrypoint_hook && hook_first < hook) }' || {
  echo "Kubernetes did not run PostStart and the entrypoint in both orders" >&2
  exit 1
}

entrypoint_first_host_pid=$(wait_for_host_pid \
  "$identity_poststart_entrypoint_first_pid" "$entrypoint_first_pid")
entrypoint_first_hook_host_pid=$(wait_for_host_pid \
  "$identity_poststart_entrypoint_first_pid" "$entrypoint_first_hook_pid")
hook_first_host_pid=$(wait_for_host_pid \
  "$identity_poststart_hook_first_pid" "$hook_first_pid")
hook_first_hook_host_pid=$(wait_for_host_pid \
  "$identity_poststart_hook_first_pid" "$hook_first_hook_pid")
repeat_first_hook_host_pid=$(wait_for_host_pid \
  "$identity_poststart_repeat_pid" "$repeat_first_hook_pid")

for entry in \
  "entrypoint-first-application:$entrypoint_first_host_pid" \
  "hook-first-application:$hook_first_host_pid" \
  "repeat-application-before:$identity_poststart_repeat_pid"; do
  name=${entry%%:*}
  pid=${entry#*:}
  identity_wait_for_task_snapshot "$name" "$pid"
  identity_assert_initial "$identity_work/$name.json"
done
for entry in \
  "entrypoint-first-hook:$entrypoint_first_hook_host_pid" \
  "hook-first-hook:$hook_first_hook_host_pid" \
  "repeat-first-hook:$repeat_first_hook_host_pid"; do
  name=${entry%%:*}
  pid=${entry#*:}
  identity_wait_for_task_snapshot "$name" "$pid"
  identity_assert_external "$identity_work/$name.json"
done
jq -s -e '
  (map(.task_cookie) | unique | length) == 6
    and (map(.process_state_id) | unique | length) == 6
    and all(.[]; .creator_task_cookie == null)
' \
  "$identity_work/entrypoint-first-application.json" \
  "$identity_work/entrypoint-first-hook.json" \
  "$identity_work/hook-first-application.json" \
  "$identity_work/hook-first-hook.json" \
  "$identity_work/repeat-application-before.json" \
  "$identity_work/repeat-first-hook.json" >/dev/null
for index in 0 1 2; do
  initial_role=$(jq -er ".workload_bindings[$index].initial_role_id" "$identity_config")
  external_role=$(jq -er ".workload_bindings[$index].external_role_id" "$identity_config")
  case $index in
    0)
      application=entrypoint-first-application
      hook=entrypoint-first-hook
      ;;
    1)
      application=hook-first-application
      hook=hook-first-hook
      ;;
    2)
      application=repeat-application-before
      hook=repeat-first-hook
      ;;
  esac
  jq -e --argjson role "$initial_role" '.active_role_id == $role' \
    "$identity_work/$application.json" >/dev/null
  jq -e --argjson role "$external_role" '.active_role_id == $role' \
    "$identity_work/$hook.json" >/dev/null
done

for release in \
  "entrypoint-first:$entrypoint_first_pid" \
  "poststart-entrypoint-first:$entrypoint_first_hook_pid" \
  "entrypoint-hook-first:$hook_first_pid" \
  "poststart-hook-first:$hook_first_hook_pid"; do
  release_slot_pid "${release%%:*}" "${release#*:}"
done
kubectl -n "$identity_k3s_namespace" wait --for=condition=Ready \
  pod/mithril-poststart-entrypoint-first --timeout=60s >/dev/null
kubectl -n "$identity_k3s_namespace" wait --for=condition=Ready \
  pod/mithril-poststart-hook-first --timeout=60s >/dev/null

systemctl kill --kill-who=main --signal=SIGKILL k3s
systemctl start k3s
kill -0 "$identity_node_pid" || {
  echo "mithril-node exited during the Kubernetes node restart" >&2
  exit 1
}

repeat_pod_json=
for ((attempt = 0; attempt < 600; attempt++)); do
  if repeat_pod_json=$(kubectl -n "$identity_k3s_namespace" get pod \
    mithril-poststart-repeat -o json 2>/dev/null); then
    break
  fi
  sleep 0.1
done
[[ -n $repeat_pod_json ]] || {
  echo "the Kubernetes API did not return the PostStart fixture after restart" >&2
  exit 1
}
repeat_command_json=$(jq -cer '
  first(.spec.containers[]
    | select(.name == "application")
    | .lifecycle.postStart.exec.command)
  | select(type == "array" and length > 0)
' <<<"$repeat_pod_json")
mapfile -t repeat_command < <(jq -r '.[]' <<<"$repeat_command_json")
[[ ${#repeat_command[@]} -gt 0 ]] || {
  echo "the live Pod has no PostStart exec command" >&2
  exit 1
}
crictl --runtime-endpoint "$identity_runtime_endpoint" exec --sync \
  "$identity_poststart_repeat_container_id" "${repeat_command[@]}" \
  >/dev/null 2>&1 &
repeat_delivery_pid=$!
identity_task_pids+=("$repeat_delivery_pid")

repeat_second_hook_pid=$(wait_for_slot_pid poststart-repeat "$repeat_first_hook_pid")
repeat_second_hook_host_pid=$(wait_for_host_pid \
  "$identity_poststart_repeat_pid" "$repeat_second_hook_pid")
[[ -r /proc/$repeat_first_hook_host_pid/status ]] || {
  echo "the first in-flight PostStart task did not survive the Kubernetes node restart" >&2
  exit 1
}

identity_wait_for_task_snapshot repeat-application-after "$identity_poststart_repeat_pid"
identity_wait_for_task_snapshot repeat-second-hook "$repeat_second_hook_host_pid"
identity_assert_external "$identity_work/repeat-second-hook.json"
jq -s -e '.[0] == .[1]' \
  "$identity_work/repeat-application-before.json" \
  "$identity_work/repeat-application-after.json" >/dev/null
external_role=$(jq -er '.workload_bindings[2].external_role_id' "$identity_config")
jq -e --argjson external_role "$external_role" \
  '.active_role_id == $external_role' "$identity_work/repeat-second-hook.json" >/dev/null
jq -s -e '
  .[0].task_cookie != .[1].task_cookie
    and .[0].process_state_id != .[1].process_state_id
' "$identity_work/repeat-first-hook.json" \
  "$identity_work/repeat-second-hook.json" >/dev/null

release_slot_pid poststart-repeat "$repeat_first_hook_pid"
release_slot_pid poststart-repeat "$repeat_second_hook_pid"
wait "$repeat_delivery_pid"
kubectl -n "$identity_k3s_namespace" wait --for=condition=Ready \
  pod/mithril-poststart-repeat --timeout=60s >/dev/null

printf 'entrypoint-first order: %s before %s\n' \
  "$entrypoint_first_order" "$entrypoint_first_hook_order"
printf 'PostStart-first order: %s before %s\n' \
  "$hook_first_hook_order" "$hook_first_order"
printf 'repeated PostStart tasks: %s then %s\n' \
  "$(jq -r '.task_cookie' "$identity_work/repeat-first-hook.json")" \
  "$(jq -r '.task_cookie' "$identity_work/repeat-second-hook.json")"
identity_pass "PASS: prestart bound each application before exec; both PostStart orders and the repeated CRI delivery received distinct restricted identities."
