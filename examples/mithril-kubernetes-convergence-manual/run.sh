#!/usr/bin/env bash

set -Eeuo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source_root=$(cd -- "$directory/../.." && pwd)
system_namespace=${MITHRIL_SYSTEM_NAMESPACE:-mithril-system}
scenario_namespace=mithril-convergence-manual
profile_name=converter-policy
runtime_class=mithril-convergence-manual
failed_runtime_class=mithril-convergence-manual-fail
protected_pod=protected
failed_pod=gate-failure
work_directory=$(mktemp -d /tmp/mithril-convergence-manual.XXXXXX)
policy_tool=${MITHRIL_BIN_DIRECTORY:-$source_root/target/debug}/mithril-policy
eligible_nodes=()

require_command() {
  command -v "$1" >/dev/null || {
    echo "required command is not installed: $1" >&2
    exit 2
  }
}

node_pod() {
  local node_name=$1
  kubectl -n "$system_namespace" get pods \
    -l app.kubernetes.io/name=mithril-node \
    --field-selector "spec.nodeName=$node_name" \
    -o jsonpath='{.items[0].metadata.name}'
}

remove_marker() {
  local node_name=$1
  local marker=$2
  local pod
  pod=$(node_pod "$node_name")
  kubectl -n "$system_namespace" exec "$pod" -- \
    rm -f "/var/lib/mithril/markers/$marker"
}

cleanup() {
  local status=$?
  trap - EXIT
  set +e
  for node_name in "${eligible_nodes[@]}"; do
    remove_marker "$node_name" "$protected_pod.started" >/dev/null 2>&1 ||
      status=1
    remove_marker "$node_name" "$protected_pod.restart" >/dev/null 2>&1 ||
      status=1
    remove_marker "$node_name" "$failed_pod.started" >/dev/null 2>&1 ||
      status=1
  done
  kubectl delete namespace "$scenario_namespace" --ignore-not-found=true \
    --wait=true --timeout=120s >/dev/null 2>&1 || status=1
  kubectl delete runtimeclass "$runtime_class" "$failed_runtime_class" \
    --ignore-not-found=true --wait=true --timeout=120s >/dev/null 2>&1 ||
    status=1
  [[ $work_directory == /tmp/mithril-convergence-manual.* ]] &&
    rm -rf -- "$work_directory"
  if ((status == 0)); then
    kubectl get namespace "$scenario_namespace" >/dev/null 2>&1 && status=1
    kubectl get runtimeclass "$runtime_class" >/dev/null 2>&1 && status=1
    kubectl get runtimeclass "$failed_runtime_class" >/dev/null 2>&1 && status=1
  fi
  exit "$status"
}
trap cleanup EXIT

assert_absent() {
  # Resource absence establishes cleanup ownership before this case changes
  # the cluster.
  if kubectl get "$@" >/dev/null 2>&1; then
    echo "manual scenario refuses to replace an existing resource: $*" >&2
    exit 2
  fi
}

assert_cluster_access() {
  local expected=$1
  local user=$2
  local verb=$3
  local group=$4
  local resource=$5
  local subresource=${6:-}
  local request
  local response

  request=$(jq -n \
    --arg user "$user" \
    --arg verb "$verb" \
    --arg group "$group" \
    --arg resource "$resource" \
    --arg subresource "$subresource" '
      {
        apiVersion: "authorization.k8s.io/v1",
        kind: "SubjectAccessReview",
        spec: {
          user: $user,
          resourceAttributes: ({
            verb: $verb,
            group: $group,
            resource: $resource
          } + if $subresource == "" then {} else {
            subresource: $subresource
          } end)
        }
      }
    ')
  response=$(kubectl create --raw \
    /apis/authorization.k8s.io/v1/subjectaccessreviews -f - <<<"$request")

  # A completed review distinguishes an RBAC denial from a failed API call.
  jq -e --argjson expected "$expected" '
    .apiVersion == "authorization.k8s.io/v1" and
    .kind == "SubjectAccessReview" and
    .status.allowed == $expected and
    ((.status.evaluationError // "") == "")
  ' <<<"$response" >/dev/null || {
    echo "RBAC review returned an unexpected decision: $user $verb $resource" >&2
    return 1
  }
}

wait_policy_compiled() {
  local policy_json
  for _attempt in {1..300}; do
    policy_json=$(kubectl -n "$scenario_namespace" get \
      workloadprotectionprofile "$profile_name" -o json 2>/dev/null || true)
    if [[ -n $policy_json ]] && jq -e '
      any(.status.conditions[]?; .condition == "ACCEPTED" and .status == true) and
      any(.status.conditions[]?; .condition == "COMPILED" and .status == true)
    ' <<<"$policy_json" >/dev/null; then
      return 0
    fi
    sleep 1
  done
  echo "the manual policy did not reach accepted and compiled state" >&2
  return 1
}

node_status() {
  local node_name=$1
  local pod
  pod=$(node_pod "$node_name")
  kubectl -n "$system_namespace" exec "$pod" -- \
    mithril-inspect policy-delivery --state-directory /var/lib/mithril
}

for command in grep jq kubectl sed sort; do
  require_command "$command"
done
[[ $(id -u) -eq 0 ]] || {
  echo "run this manual case from the documented root guest shell" >&2
  exit 2
}
[[ -x $policy_tool ]] || {
  echo "the production policy tool is not executable: $policy_tool" >&2
  exit 2
}
kubectl get --raw=/readyz >/dev/null
kubectl -n "$system_namespace" rollout status deployment/mithril-control \
  --timeout=120s >/dev/null
kubectl -n "$system_namespace" rollout status daemonset/mithril-node \
  --timeout=120s >/dev/null

mapfile -t eligible_nodes < <(
  kubectl -n "$system_namespace" get pods \
    -l app.kubernetes.io/name=mithril-node -o json |
    jq -er '.items[]
      | select(any(.status.conditions[]?; .type == "Ready" and .status == "True"))
      | .spec.nodeName' | sort -u
)
((${#eligible_nodes[@]} >= 2)) || {
  echo "the manual case requires two ready Mithril DaemonSet nodes" >&2
  exit 2
}
for node_name in "${eligible_nodes[@]}"; do
  # A fresh environment must not carry authority from an earlier manual run.
  node_json=$(kubectl get node "$node_name" -o json)
  jq -e '
    .metadata.labels["mithril.erebor.dev/ready"] == "true" and
    all(.spec.taints[]?;
      .key != "mithril.erebor.dev/not-ready" or .effect != "NoSchedule")
  ' <<<"$node_json" >/dev/null
  jq -e '
    .active_candidate_content_id == null and
    .active_profile_ids == [] and
    .scheduled_binding_count == 0 and
    .runtime_binding_count == 0
  ' <<<"$(node_status "$node_name")" >/dev/null
  remove_marker "$node_name" "$protected_pod.started"
  remove_marker "$node_name" "$protected_pod.restart"
  remove_marker "$node_name" "$failed_pod.started"
done

control_subject=system:serviceaccount:$system_namespace:mithril-control
node_subject=system:serviceaccount:$system_namespace:mithril-node
assert_cluster_access true "$control_subject" list mithril.erebor.dev \
  workloadprotectionprofiles
assert_cluster_access true "$control_subject" patch mithril.erebor.dev \
  workloadprotectionprofiles status
assert_cluster_access true "$control_subject" patch "" nodes
assert_cluster_access false "$control_subject" update mithril.erebor.dev \
  workloadprotectionprofiles
assert_cluster_access false "$node_subject" get "" nodes

assert_absent namespace "$scenario_namespace"
assert_absent runtimeclass "$runtime_class"
assert_absent runtimeclass "$failed_runtime_class"

cat >"$work_directory/runtime-classes.yaml" <<EOF
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: $runtime_class
handler: mithril
---
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: $failed_runtime_class
handler: mithril-fail
EOF
kubectl apply --server-side --field-manager=mithril-convergence-manual \
  --validate=strict -f "$work_directory/runtime-classes.yaml" >/dev/null
kubectl create namespace "$scenario_namespace" >/dev/null
kubectl -n "$scenario_namespace" create serviceaccount converter >/dev/null

namespace_uid=$(kubectl get namespace "$scenario_namespace" \
  -o jsonpath='{.metadata.uid}')
service_account_uid=$(kubectl -n "$scenario_namespace" get serviceaccount converter \
  -o jsonpath='{.metadata.uid}')
sed \
  -e "s/66666666-6666-4666-8666-666666666666/$namespace_uid/g" \
  -e "s/77777777-7777-4777-8777-777777777777/$service_account_uid/g" \
  "$directory/policy-v1.yaml" >"$work_directory/policy-v1.yaml"
"$policy_tool" print-policy-manifest \
  --source "$work_directory/policy-v1.yaml" \
  --name "$profile_name" --namespace "$scenario_namespace" \
  --output "$work_directory/policy-v1.json"
kubectl apply --server-side --field-manager=mithril-convergence-manual \
  --validate=strict -f "$work_directory/policy-v1.json" >/dev/null
wait_policy_compiled

sed \
  -e "s/MITHRIL_MANUAL_NAMESPACE/$scenario_namespace/g" \
  -e "s/MITHRIL_MANUAL_POD/$protected_pod/g" \
  -e "s/MITHRIL_MANUAL_RUNTIME_CLASS/$runtime_class/g" \
  "$directory/protected-pod-v1.yaml" >"$work_directory/protected.yaml"
protected_dry_run=$(kubectl create --dry-run=server \
  -f "$work_directory/protected.yaml" -o json)
# The API-server result proves that admission constrains the scheduler.
# Admission does not select a Node.
jq -e '
  .metadata.annotations["mithril.erebor.dev/profile-id"] ==
    "11111111-1111-4111-8111-111111111111" and
  (.metadata.annotations["mithril.erebor.dev/policy-source-revision"] | length) == 64 and
  (.spec.nodeName // "") == "" and
  .spec.nodeSelector["mithril.erebor.dev/pool"] == "protected" and
  .spec.nodeSelector["mithril.erebor.dev/ready"] == "true" and
  any(.spec.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution
      .nodeSelectorTerms[].matchExpressions[]?;
      .key == "kubernetes.io/arch" and .operator == "In" and
      .values == ["amd64"])
' <<<"$protected_dry_run" >/dev/null

jq --arg node "${eligible_nodes[0]}" '.spec.nodeName = $node' \
  <<<"$protected_dry_run" >"$work_directory/bypass.json"
if kubectl create -f "$work_directory/bypass.json" >/dev/null 2>&1; then
  echo "admission accepted a protected Pod with direct nodeName" >&2
  exit 1
fi

kubectl create -f "$work_directory/protected.yaml" >/dev/null
kubectl -n "$scenario_namespace" wait --for=condition=Ready \
  pod/"$protected_pod" --timeout=300s >/dev/null
selected_node=$(kubectl -n "$scenario_namespace" get pod "$protected_pod" \
  -o jsonpath='{.spec.nodeName}')
printf '%s\n' "${eligible_nodes[@]}" | grep -Fx "$selected_node" >/dev/null || {
  echo "the scheduler selected a node outside the ready DaemonSet set" >&2
  exit 1
}

jq -e '
  .active_candidate_content_id != null and
  .active_profile_ids == ["11111111-1111-4111-8111-111111111111"] and
  .scheduled_binding_count == 0 and
  .runtime_binding_count == 1 and
  .activation_pending == false and
  .control_acknowledged == true
' <<<"$(node_status "$selected_node")" >/dev/null
for node_name in "${eligible_nodes[@]}"; do
  # The scheduler-selected node is the only node that can hold this Pod lifetime.
  if [[ $node_name == "$selected_node" ]]; then
    kubectl -n "$system_namespace" exec "$(node_pod "$node_name")" -- \
      test -e "/var/lib/mithril/markers/$protected_pod.started"
  else
    jq -e '
      .active_candidate_content_id == null and
      .active_profile_ids == [] and
      .scheduled_binding_count == 0 and
      .runtime_binding_count == 0
    ' <<<"$(node_status "$node_name")" >/dev/null
    kubectl -n "$system_namespace" exec "$(node_pod "$node_name")" -- \
      test ! -e "/var/lib/mithril/markers/$protected_pod.started"
  fi
done

sed \
  -e "s/MITHRIL_MANUAL_NAMESPACE/$scenario_namespace/g" \
  -e "s/MITHRIL_MANUAL_POD/$failed_pod/g" \
  -e "s/MITHRIL_MANUAL_RUNTIME_CLASS/$failed_runtime_class/g" \
  "$directory/protected-pod-v1.yaml" >"$work_directory/gate-failure.yaml"
# The alternate runtime keeps the admitted Pod identity but has no gate endpoint.
kubectl create -f "$work_directory/gate-failure.yaml" >/dev/null
for _attempt in {1..120}; do
  failure_json=$(kubectl -n "$scenario_namespace" get pod "$failed_pod" -o json)
  if jq -e 'any(.status.containerStatuses[]?.state.waiting.reason;
      . == "CreateContainerError" or . == "RunContainerError")' \
      <<<"$failure_json" >/dev/null; then
    break
  fi
  [[ $_attempt -lt 120 ]] || {
    echo "the unavailable runtime-admission endpoint did not fail container start" >&2
    exit 1
  }
  sleep 1
done
for node_name in "${eligible_nodes[@]}"; do
  kubectl -n "$system_namespace" exec "$(node_pod "$node_name")" -- \
    test ! -e "/var/lib/mithril/markers/$failed_pod.started"
done
kubectl -n "$scenario_namespace" delete pod "$failed_pod" \
  --wait=true --timeout=120s >/dev/null

# A restart must replace the exact runtime authority, not reactivate the first binding.
container_before=$(kubectl -n "$scenario_namespace" get pod "$protected_pod" \
  -o jsonpath='{.status.containerStatuses[0].containerID}')
kubectl -n "$system_namespace" exec "$(node_pod "$selected_node")" -- \
  touch "/var/lib/mithril/markers/$protected_pod.restart"
for _attempt in {1..180}; do
  container_after=$(kubectl -n "$scenario_namespace" get pod "$protected_pod" \
    -o jsonpath='{.status.containerStatuses[0].containerID}')
  [[ -n $container_after && $container_after != "$container_before" ]] && break
  [[ $_attempt -lt 180 ]] || {
    echo "the protected container did not receive a new runtime lifetime" >&2
    exit 1
  }
  sleep 1
done
kubectl -n "$scenario_namespace" wait --for=condition=Ready \
  pod/"$protected_pod" --timeout=180s >/dev/null
jq -e '.runtime_binding_count == 1 and .scheduled_binding_count == 0' \
  <<<"$(node_status "$selected_node")" >/dev/null

jq -n --arg namespace "$scenario_namespace" --arg node "$selected_node" \
  --arg previous "$container_before" --arg current "$container_after" \
  '{
    result: "PASS",
    namespace: $namespace,
    scheduler_selected_node: $node,
    first_container_lifetime: $previous,
    replacement_container_lifetime: $current,
    exact_node_delivery: true,
    runtime_gate_failure_closed: true,
    cleanup: "the EXIT trap removes all scenario resources"
  }'
