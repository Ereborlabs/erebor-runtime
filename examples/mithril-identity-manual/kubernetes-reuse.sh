#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/identity-runtime.sh"

[[ $# -eq 0 ]] || {
  echo "usage: sudo $0" >&2
  exit 2
}

reuse_refresh_binding() {
  local container_ref container_json created_at generation image_digest
  local pod_uid sandbox_id

  container_ref=$(kubectl -n "$identity_k3s_namespace" get pod mithril-runtime \
    -o jsonpath='{.status.containerStatuses[0].containerID}')
  [[ $container_ref == containerd://* ]] || {
    echo "Kubernetes did not return a containerd container ID" >&2
    return 1
  }
  identity_container_id=${container_ref#containerd://}
  identity_container=$identity_container_id
  pod_uid=$(kubectl -n "$identity_k3s_namespace" get pod mithril-runtime \
    -o jsonpath='{.metadata.uid}')
  container_json=$(crictl --runtime-endpoint "$identity_runtime_endpoint" \
    inspect "$identity_container_id")
  created_at=$(jq -er '.status.createdAt' <<<"$container_json")
  generation=$(date --utc --date "$created_at" +%s%N)
  image_digest=$(jq -er '.status.imageRef' <<<"$container_json")
  sandbox_id=$(crictl --runtime-endpoint "$identity_runtime_endpoint" \
    ps --id "$identity_container_id" -o json | jq -er '.containers[0].podSandboxId')
  identity_init_pid=$(jq -er '.info.pid' <<<"$container_json")
  identity_cgroup_path=$(identity_cgroup_for_pid "$identity_init_pid")

  jq --arg container_id "$identity_container_id" \
    --arg pod_uid "$pod_uid" \
    --arg sandbox_id "$sandbox_id" \
    --arg image_digest "$image_digest" \
    --argjson generation "$generation" \
    '.workload_bindings[0].container_id = $container_id
     | .workload_bindings[0].pod_uid = $pod_uid
     | .workload_bindings[0].sandbox_id = $sandbox_id
     | .workload_bindings[0].image_digest = $image_digest
     | .workload_bindings[0].container_generation = $generation' \
    "$identity_config" >"$identity_work/refreshed-node.json"
  mv -- "$identity_work/refreshed-node.json" "$identity_config"
}

identity_prepare_k3s_case \
  docker.io/library/python@sha256:78098ea6a3a9c6a7727a5d4674e4a44e57e01fac878ee9cb4d24a86bd93916ff
identity_start_node
identity_wait_for_initial_binding
identity_inspect_task reuse-first "$identity_init_pid" >/dev/null
identity_assert_recovered "$identity_work/reuse-first.json"
identity_read_binding_state "$identity_cgroup_path" \
  "$identity_work/reuse-first-binding.json"
reuse_first_pod_uid=$(jq -er '.workload_bindings[0].pod_uid' "$identity_config")
reuse_first_sandbox_id=$(jq -er '.workload_bindings[0].sandbox_id' "$identity_config")
reuse_first_container_id=$(jq -er '.workload_bindings[0].container_id' "$identity_config")
reuse_first_generation=$(jq -er '.workload_bindings[0].container_generation' "$identity_config")
reuse_first_namespace=$(jq -er '.workload_bindings[0].namespace' "$identity_config")
reuse_first_container_name=$(jq -er '.workload_bindings[0].container_name' "$identity_config")
reuse_first_cgroup=$identity_cgroup_path

identity_stop_node
kubectl -n "$identity_k3s_namespace" delete pod mithril-runtime \
  --wait=true --timeout=120s >/dev/null
for ((attempt = 0; attempt < 300; attempt++)); do
  [[ ! -e $reuse_first_cgroup ]] && break
  sleep 0.1
done
[[ ! -e $reuse_first_cgroup ]] || {
  echo "the first Kubernetes container cgroup survived deletion" >&2
  exit 1
}
kubectl apply -f "$identity_work/workload.yaml" >/dev/null
kubectl -n "$identity_k3s_namespace" wait \
  --for=condition=Ready pod/mithril-runtime --timeout=300s >/dev/null
reuse_refresh_binding

identity_start_node
identity_wait_for_initial_binding
identity_inspect_task reuse-second "$identity_init_pid" >/dev/null
identity_assert_recovered "$identity_work/reuse-second.json"
identity_read_binding_state "$identity_cgroup_path" \
  "$identity_work/reuse-second-binding.json"
reuse_second_pod_uid=$(jq -er '.workload_bindings[0].pod_uid' "$identity_config")
reuse_second_sandbox_id=$(jq -er '.workload_bindings[0].sandbox_id' "$identity_config")
reuse_second_container_id=$(jq -er '.workload_bindings[0].container_id' "$identity_config")
reuse_second_generation=$(jq -er '.workload_bindings[0].container_generation' "$identity_config")
reuse_second_namespace=$(jq -er '.workload_bindings[0].namespace' "$identity_config")
reuse_second_container_name=$(jq -er '.workload_bindings[0].container_name' "$identity_config")

[[ $reuse_first_pod_uid != "$reuse_second_pod_uid" \
  && $reuse_first_sandbox_id != "$reuse_second_sandbox_id" \
  && $reuse_first_container_id != "$reuse_second_container_id" \
  && $reuse_first_generation != "$reuse_second_generation" \
  && $reuse_first_namespace == "$reuse_second_namespace" \
  && $reuse_first_container_name == "$reuse_second_container_name" \
  && $reuse_first_cgroup != "$identity_cgroup_path" ]] || {
  echo "the recreated Pod did not receive a fresh full runtime identity" >&2
  exit 1
}
jq -e --slurpfile second "$identity_work/reuse-second.json" '
  .task_cookie != $second[0].task_cookie
  and .process_state_id != $second[0].process_state_id
  and .active_execution_id != $second[0].active_execution_id
  and .active_role_id == $second[0].active_role_id
' "$identity_work/reuse-first.json" >/dev/null
jq -e --slurpfile second "$identity_work/reuse-second-binding.json" '
  .root_cgroup_id != $second[0].root_cgroup_id
  and .binding_nonce != $second[0].binding_nonce
  and .root_cgroup_live_interval_id != $second[0].root_cgroup_live_interval_id
' "$identity_work/reuse-first-binding.json" >/dev/null

identity_pass \
  "PASS: one Kubernetes Pod and container name was recreated with a fresh full and binding identity."
