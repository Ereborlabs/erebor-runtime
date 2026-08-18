#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/identity-runtime.sh"

[[ $# -eq 0 ]] || {
  echo "usage: sudo $0" >&2
  exit 2
}

entry_loss_test=$identity_bin_directory/mithril-identity-test
[[ -x $entry_loss_test ]] || {
  echo "build first: cargo build -p mithril-e2e --bin mithril-identity-test" >&2
  exit 2
}

entry_loss_k3s_stopped=false
entry_loss_restore_k3s() {
  if [[ $entry_loss_k3s_stopped == true ]]; then
    systemctl start k3s || return 1
    kubectl wait --for=condition=Ready node --all --timeout=120s >/dev/null || return 1
    entry_loss_k3s_stopped=false
  fi
}

identity_prepare_k3s_case \
  docker.io/library/python@sha256:78098ea6a3a9c6a7727a5d4674e4a44e57e01fac878ee9cb4d24a86bd93916ff
identity_cleanup_functions=(entry_loss_restore_k3s "${identity_cleanup_functions[@]}")

entry_loss_socket=$identity_work/observation.sock
jq --arg socket "$entry_loss_socket" \
  '.runtime_observation = {
     socket_path: $socket,
     allowed_uid: 0,
     cgroup_scope: "/"
   }' "$identity_config" >"$identity_work/node-with-observation.json"
mv -- "$identity_work/node-with-observation.json" "$identity_config"

identity_start_node
identity_wait_for_initial_binding
for ((attempt = 0; attempt < 300; attempt++)); do
  if "$identity_inspect" effects --socket-path "$entry_loss_socket" --cgroup-scope / \
    >"$identity_work/healthy.txt" 2>/dev/null \
    && grep -Fq 'capability=EXACT_NATIVE_IDENTITY state=SUPPORTED' \
      "$identity_work/healthy.txt"; then
    break
  fi
  sleep 0.1
done
grep -Fq 'capability=EXACT_NATIVE_IDENTITY state=SUPPORTED' \
  "$identity_work/healthy.txt"

entry_loss_ready=$identity_k3s_shared_directory/entry-loss.pid
entry_loss_ready_container=$identity_k3s_container_shared_directory/entry-loss.pid
rm -f -- "$entry_loss_ready"

crictl --runtime-endpoint "$identity_runtime_endpoint" exec "$identity_container_id" \
  /bin/sh -c '
    printf "%s\n" "$$" >"$1"
    kill -STOP "$$"
    read -r entry_loss_hostname < /etc/hostname
    kill -STOP "$$"
  ' sh "$entry_loss_ready_container" >/dev/null 2>&1 &
entry_loss_client_pid=$!
identity_task_pids+=("$entry_loss_client_pid")
for ((attempt = 0; attempt < 300; attempt++)); do
  [[ -s $entry_loss_ready ]] && break
  kill -0 "$entry_loss_client_pid" 2>/dev/null || {
    echo "direct CRI exec exited before it reported its container PID" >&2
    exit 1
  }
  sleep 0.1
done
[[ -s $entry_loss_ready ]] || {
  echo "direct CRI exec did not report its container PID" >&2
  exit 1
}
entry_loss_namespace_pid=$(<"$entry_loss_ready")
entry_loss_host_pid=$(identity_kubernetes_host_pid "$entry_loss_namespace_pid") || {
  echo "could not map the direct CRI exec to its host PID" >&2
  exit 1
}
for ((attempt = 0; attempt < 300; attempt++)); do
  grep -q $'^State:\tT' "/proc/$entry_loss_host_pid/status" && break
  sleep 0.1
done
grep -q $'^State:\tT' "/proc/$entry_loss_host_pid/status"

identity_wait_for_task_snapshot entry-loss-audit-absent "$entry_loss_host_pid"
identity_assert_external "$identity_work/entry-loss-audit-absent.json"
entry_loss_external_role=$(jq -er '.workload_bindings[0].external_role_id' "$identity_config")

"$entry_loss_test" --repo-root "$identity_repository" \
  --output-directory "$identity_work" inject-task-label-loss \
  --pin-root "$identity_pin_root" --host-pid "$entry_loss_host_pid"
if "$identity_inspect" --pin-root "$identity_pin_root" task \
  --host-pid "$entry_loss_host_pid" >/dev/null 2>&1; then
  echo "the task label survived independent loss injection" >&2
  exit 1
fi

kill -CONT "$entry_loss_host_pid"
identity_wait_for_task_snapshot entry-loss-bpf-recovered "$entry_loss_host_pid"
for ((attempt = 0; attempt < 300; attempt++)); do
  grep -q $'^State:\tT' "/proc/$entry_loss_host_pid/status" && break
  sleep 0.1
done
grep -q $'^State:\tT' "/proc/$entry_loss_host_pid/status"
jq -e --argjson role "$entry_loss_external_role" \
  '.creator_task_cookie == null
   and .root_class == "external_runtime_root"
   and .installed_role_class == "runtime_external_restricted"
   and .active_role_id == $role' \
  "$identity_work/entry-loss-bpf-recovered.json" >/dev/null || {
  cat "$identity_work/entry-loss-bpf-recovered.json" >&2
  exit 1
}
jq -e -s \
  '.[0].task_cookie != .[1].task_cookie
   and .[0].process_state_id != .[1].process_state_id' \
  "$identity_work/entry-loss-audit-absent.json" \
  "$identity_work/entry-loss-bpf-recovered.json" >/dev/null || {
  echo "the recovered task and process identity are not fresh" >&2
  exit 1
}

systemctl stop k3s
entry_loss_k3s_stopped=true
for ((attempt = 0; attempt < 300; attempt++)); do
  if "$identity_inspect" effects --socket-path "$entry_loss_socket" --cgroup-scope / \
    >"$identity_work/unhealthy.txt" 2>/dev/null \
    && grep -Fq \
      'capability=EXACT_NATIVE_IDENTITY state=UNHEALTHY reason=LIVE_IDENTITY_RECONCILIATION_FAILED' \
      "$identity_work/unhealthy.txt"; then
    break
  fi
  sleep 0.1
done
grep -Fq \
  'capability=EXACT_NATIVE_IDENTITY state=UNHEALTHY reason=LIVE_IDENTITY_RECONCILIATION_FAILED' \
  "$identity_work/unhealthy.txt"
identity_inspect_task entry-loss-runtime "$entry_loss_host_pid" >/dev/null
cmp --silent "$identity_work/entry-loss-bpf-recovered.json" \
  "$identity_work/entry-loss-runtime.json"

entry_loss_restore_k3s
kill -CONT "$entry_loss_host_pid"
wait "$entry_loss_client_pid"
identity_pass "PASS: audit, BPF task-label, and Kubernetes runtime loss stay conservative and explicit."
