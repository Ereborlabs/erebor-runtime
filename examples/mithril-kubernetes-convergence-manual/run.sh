#!/usr/bin/env bash

set -Eeuo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/kubernetes-oracles.sh"
system_namespace=${MITHRIL_SYSTEM_NAMESPACE:-mithril-system}
scenario_namespace=mithril-convergence-manual
profile_name=converter-policy
runtime_class=mithril-convergence-manual
failed_runtime_class=mithril-convergence-manual-fail
protected_pod=protected
failed_pod=gate-failure
work_directory=$(mktemp -d /tmp/mithril-convergence-manual.XXXXXX)
eligible_nodes=()
owns_namespace=false
owns_runtime_class=false
owns_failed_runtime_class=false

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
  kubectl -n "$system_namespace" exec -c mithril-node "$pod" -- \
    rm -f "/var/lib/mithril/markers/$marker"
}

write_marker() {
  local node_name=$1
  local marker=$2
  local pod
  pod=$(node_pod "$node_name")
  kubectl -n "$system_namespace" exec -c mithril-node "$pod" -- \
    touch "/var/lib/mithril/markers/$marker"
}

read_marker() {
  local node_name=$1
  local marker=$2
  local pod
  pod=$(node_pod "$node_name")
  kubectl -n "$system_namespace" exec -c mithril-node "$pod" -- \
    cat "/var/lib/mithril/markers/$marker"
}

wait_marker_value() {
  local node_name=$1
  local marker=$2
  local expected=$3
  local actual
  for _attempt in {1..120}; do
    actual=$(read_marker "$node_name" "$marker" 2>/dev/null || true)
    [[ $actual == "$expected" ]] && return 0
    sleep 1
  done
  echo "marker $marker did not reach $expected on node $node_name" >&2
  return 1
}

marker_is_absent() {
  local node_name=$1
  local marker=$2
  local pod
  pod=$(node_pod "$node_name")
  kubectl -n "$system_namespace" exec -c mithril-node "$pod" -- \
    test ! -e "/var/lib/mithril/markers/$marker"
}

kubernetes_resource_is_absent() {
  local output
  output=$(kubectl get "$@" 2>&1)
  local status=$?
  ((status != 0)) && [[ $output == *'(NotFound)'* ]]
}

cleanup() {
  local original_status=$?
  local cleanup_failed=false
  local marker
  local node_name
  trap - EXIT
  set +e
  for node_name in "${eligible_nodes[@]}"; do
    for marker in \
      "$protected_pod.started" \
      "$protected_pod.restart" \
      "$failed_pod.started" \
      "$protected_pod.exception-target" \
      "$protected_pod.exception-request" \
      "$protected_pod.exception-result"; do
      remove_marker "$node_name" "$marker" >/dev/null 2>&1 || cleanup_failed=true
      marker_is_absent "$node_name" "$marker" >/dev/null 2>&1 || cleanup_failed=true
    done
  done
  if [[ $owns_namespace == true ]]; then
    kubectl delete namespace "$scenario_namespace" --ignore-not-found=true \
      --wait=true --timeout=120s >/dev/null 2>&1 || cleanup_failed=true
    kubernetes_resource_is_absent namespace "$scenario_namespace" || cleanup_failed=true
  fi
  if [[ $owns_runtime_class == true ]]; then
    kubectl delete runtimeclass "$runtime_class" --ignore-not-found=true \
      --wait=true --timeout=120s >/dev/null 2>&1 || cleanup_failed=true
    kubernetes_resource_is_absent runtimeclass "$runtime_class" || cleanup_failed=true
  fi
  if [[ $owns_failed_runtime_class == true ]]; then
    kubectl delete runtimeclass "$failed_runtime_class" --ignore-not-found=true \
      --wait=true --timeout=120s >/dev/null 2>&1 || cleanup_failed=true
    kubernetes_resource_is_absent runtimeclass "$failed_runtime_class" || cleanup_failed=true
  fi
  if [[ $work_directory == /tmp/mithril-convergence-manual.* ]]; then
    rm -rf -- "$work_directory" || cleanup_failed=true
  else
    cleanup_failed=true
  fi
  [[ ! -e $work_directory ]] || cleanup_failed=true
  # Preserve the scenario failure after all independent cleanup checks run.
  if ((original_status != 0)); then
    exit "$original_status"
  fi
  [[ $cleanup_failed == false ]] || exit 1
  exit 0
}
trap cleanup EXIT

assert_absent() {
  local output
  if output=$(kubectl get "$@" 2>&1); then
    echo "manual scenario refuses to replace an existing resource: $*" >&2
    exit 2
  fi
  [[ $output == *'(NotFound)'* ]] || {
    echo "manual scenario could not verify that the resource is absent: $output" >&2
    exit 1
  }
}

assert_cluster_access() {
  local expected=$1
  local user=$2
  local verb=$3
  local group=$4
  local resource=$5
  local subresource=${6:-}
  local namespace=${7:-}
  local request
  local response

  request=$(jq -n \
    --arg user "$user" \
    --arg verb "$verb" \
    --arg group "$group" \
    --arg resource "$resource" \
    --arg subresource "$subresource" \
    --arg namespace "$namespace" '
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
          } end + if $namespace == "" then {} else {
            namespace: $namespace
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
      workloadprotectionpolicy "$profile_name" -o json 2>/dev/null || true)
    if [[ -n $policy_json ]] && jq -e '
      .status.observedGeneration == .metadata.generation and
      any(.status.conditions[]?; .type == "Accepted" and .status == "True") and
      any(.status.conditions[]?; .type == "Compiled" and .status == "True")
    ' <<<"$policy_json" >/dev/null; then
      return 0
    fi
    sleep 1
  done
  echo "the manual policy did not reach accepted and compiled state" >&2
  return 1
}

wait_exception_state() {
  local expected=$1
  local exception_json
  for _attempt in {1..300}; do
    exception_json=$(kubectl -n "$scenario_namespace" get \
      workloadprotectionexception temporary-file-access -o json 2>/dev/null || true)
    if [[ -n $exception_json ]] && jq -e --arg expected "$expected" '
      .status.observedGeneration == .metadata.generation and
      .status.state == $expected
    ' <<<"$exception_json" >/dev/null; then
      return 0
    fi
    sleep 1
  done
  echo "the manual exception did not reach $expected" >&2
  return 1
}

node_status() {
  local node_name=$1
  local pod
  pod=$(node_pod "$node_name")
  kubectl -n "$system_namespace" exec -c mithril-node "$pod" -- \
    mithril-inspect policy-delivery --state-directory /var/lib/mithril
}

assert_live_exact_target() {
  local node_name=$1
  local profile_id=$2
  local operation=$3
  local predecessor=${4:-}
  local status_json
  local node_json
  local pod_json
  status_json=$(node_status "$node_name")
  node_json=$(kubectl get node "$node_name" -o json)
  pod_json=$(kubectl -n "$scenario_namespace" get pod "$protected_pod" -o json)
  assert_exact_policy_target "$status_json" "$node_json" "$pod_json" \
    "$profile_id" converter "$operation" "$predecessor"
}

wait_policy_delivery_empty() {
  local node_name=$1
  local status_json
  for _attempt in {1..300}; do
    status_json=$(node_status "$node_name" 2>/dev/null || true)
    if [[ -n $status_json ]] && jq -e '
      .active_candidate_content_id == null and
      .active_profile_ids == [] and
      .active_target_count == 0 and
      .active_targets_truncated == false and
      .active_targets == [] and
      .scheduled_binding_count == 0 and
      .runtime_binding_count == 0 and
      .activation_pending == false
    ' <<<"$status_json" >/dev/null; then
      return 0
    fi
    sleep 1
  done
  echo "policy delivery did not retire all authority on node $node_name" >&2
  return 1
}

wait_node_ready() {
  local node_name=$1
  local node_json
  for _attempt in {1..300}; do
    node_json=$(kubectl get node "$node_name" -o json 2>/dev/null || true)
    if [[ -n $node_json ]] && jq -e '
      .metadata.labels["mithril.erebor.dev/ready"] == "true" and
      all(.spec.taints[]?;
        .key != "mithril.erebor.dev/not-ready" or .effect != "NoSchedule")
    ' <<<"$node_json" >/dev/null; then
      return 0
    fi
    sleep 1
  done
  echo "node $node_name did not recover Mithril readiness" >&2
  return 1
}

for command in grep jq kubectl sed sort; do
  require_command "$command"
done
[[ $(id -u) -eq 0 ]] || {
  echo "run this manual case from the documented root guest shell" >&2
  exit 2
}
kubectl get --raw=/readyz >/dev/null
kubectl -n "$system_namespace" rollout status deployment/mithril-control \
  --timeout=120s >/dev/null
kubectl -n "$system_namespace" rollout status daemonset/mithril-node \
  --timeout=120s >/dev/null

# Refuse existing names before marker or Kubernetes state changes.
assert_absent namespace "$scenario_namespace"
assert_absent runtimeclass "$runtime_class"
assert_absent runtimeclass "$failed_runtime_class"

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
    .active_target_count == 0 and
    .active_targets_truncated == false and
    .active_targets == [] and
    .scheduled_binding_count == 0 and
    .runtime_binding_count == 0 and
    .pending_exception_count == 0 and
    .active_exception_count == 0 and
    .terminal_exception_count == 0
  ' <<<"$(node_status "$node_name")" >/dev/null
  remove_marker "$node_name" "$protected_pod.started"
  remove_marker "$node_name" "$protected_pod.restart"
  remove_marker "$node_name" "$failed_pod.started"
  remove_marker "$node_name" "$protected_pod.exception-target"
  remove_marker "$node_name" "$protected_pod.exception-request"
  remove_marker "$node_name" "$protected_pod.exception-result"
  # The host creates the denied object before a protected process can open it.
  write_marker "$node_name" "$protected_pod.exception-target"
done

control_subject=system:serviceaccount:$system_namespace:mithril-control
node_subject=system:serviceaccount:$system_namespace:mithril-node
assert_cluster_access true "$control_subject" list mithril.erebor.dev \
  workloadprotectionpolicies
assert_cluster_access true "$control_subject" patch mithril.erebor.dev \
  workloadprotectionpolicies status
assert_cluster_access true "$control_subject" list mithril.erebor.dev \
  workloadprotectionexceptions
assert_cluster_access true "$control_subject" patch mithril.erebor.dev \
  workloadprotectionexceptions status
assert_cluster_access true "$control_subject" patch "" nodes
assert_cluster_access false "$control_subject" update mithril.erebor.dev \
  workloadprotectionpolicies
assert_cluster_access false "$control_subject" update mithril.erebor.dev \
  workloadprotectionexceptions
assert_cluster_access false "$node_subject" get "" nodes

kubectl apply --server-side --field-manager=mithril-convergence-manual \
  --validate=strict -f - >/dev/null <<EOF
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: $runtime_class
handler: mithril
EOF
owns_runtime_class=true
kubectl apply --server-side --field-manager=mithril-convergence-manual \
  --validate=strict -f - >/dev/null <<EOF
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: $failed_runtime_class
handler: mithril-fail
EOF
owns_failed_runtime_class=true
kubectl create namespace "$scenario_namespace" >/dev/null
owns_namespace=true
kubectl -n "$scenario_namespace" create serviceaccount converter >/dev/null
kubectl -n "$scenario_namespace" create serviceaccount policy-writer >/dev/null
kubectl -n "$scenario_namespace" create serviceaccount exception-writer >/dev/null
kubectl -n "$scenario_namespace" create rolebinding policy-writer \
  --clusterrole=mithril-policy-writer \
  --serviceaccount="$scenario_namespace:policy-writer" >/dev/null
kubectl -n "$scenario_namespace" create rolebinding exception-writer \
  --clusterrole=mithril-exception-writer \
  --serviceaccount="$scenario_namespace:exception-writer" >/dev/null
policy_subject=system:serviceaccount:$scenario_namespace:policy-writer
exception_subject=system:serviceaccount:$scenario_namespace:exception-writer
assert_cluster_access true "$policy_subject" create mithril.erebor.dev \
  workloadprotectionpolicies "" "$scenario_namespace"
assert_cluster_access false "$policy_subject" create mithril.erebor.dev \
  workloadprotectionexceptions "" "$scenario_namespace"
assert_cluster_access true "$exception_subject" create mithril.erebor.dev \
  workloadprotectionexceptions "" "$scenario_namespace"
assert_cluster_access false "$exception_subject" create mithril.erebor.dev \
  workloadprotectionpolicies "" "$scenario_namespace"

sed \
  -e "s/MITHRIL_MANUAL_NAMESPACE/$scenario_namespace/g" \
  "$directory/policy-v1.yaml" >"$work_directory/policy-v1.yaml"
kubectl --as="$policy_subject" apply --server-side \
  --field-manager=mithril-convergence-manual --validate=strict \
  -f "$work_directory/policy-v1.yaml" >/dev/null
wait_policy_compiled
profile_id=$(kubectl -n "$scenario_namespace" get \
  workloadprotectionpolicy "$profile_name" -o jsonpath='{.metadata.uid}')

sed \
  -e "s/MITHRIL_MANUAL_NAMESPACE/$scenario_namespace/g" \
  -e "s/MITHRIL_MANUAL_POD/$protected_pod/g" \
  -e "s/MITHRIL_MANUAL_RUNTIME_CLASS/$runtime_class/g" \
  "$directory/protected-pod-v1.yaml" >"$work_directory/protected.yaml"
protected_dry_run=$(kubectl create --dry-run=server \
  -f "$work_directory/protected.yaml" -o json)
# The API-server result proves that admission constrains the scheduler.
# Admission does not select a Node.
jq -e --arg profile_id "$profile_id" '
  .metadata.annotations["mithril.erebor.dev/profile-id"] ==
    $profile_id and
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
assert_mithril_node_name_denial kubectl create \
  -f "$work_directory/bypass.json"

kubectl create -f "$work_directory/protected.yaml" >/dev/null
kubectl -n "$scenario_namespace" wait --for=condition=Ready \
  pod/"$protected_pod" --timeout=300s >/dev/null
selected_node=$(kubectl -n "$scenario_namespace" get pod "$protected_pod" \
  -o jsonpath='{.spec.nodeName}')
printf '%s\n' "${eligible_nodes[@]}" | grep -Fx "$selected_node" >/dev/null || {
  echo "the scheduler selected a node outside the ready DaemonSet set" >&2
  exit 1
}

jq -e --arg profile_id "$profile_id" '
  .active_candidate_content_id != null and
  .active_profile_ids == [$profile_id] and
  .scheduled_binding_count == 0 and
  .runtime_binding_count == 1 and
  .activation_pending == false and
  .control_acknowledged == true
' <<<"$(node_status "$selected_node")" >/dev/null
assert_live_exact_target "$selected_node" "$profile_id" ACTIVATE
initial_delivery_status=$(node_status "$selected_node")
runtime_binding_before=$(jq -er '.active_targets[0].runtime_binding_id' \
  <<<"$initial_delivery_status")
for node_name in "${eligible_nodes[@]}"; do
  # The scheduler-selected node is the only node that can hold this Pod lifetime.
  if [[ $node_name == "$selected_node" ]]; then
    kubectl -n "$system_namespace" exec -c mithril-node "$(node_pod "$node_name")" -- \
      test -e "/var/lib/mithril/markers/$protected_pod.started"
  else
    jq -e '
      .active_candidate_content_id == null and
      .active_profile_ids == [] and
      .scheduled_binding_count == 0 and
      .runtime_binding_count == 0
    ' <<<"$(node_status "$node_name")" >/dev/null
    kubectl -n "$system_namespace" exec -c mithril-node "$(node_pod "$node_name")" -- \
      test ! -e "/var/lib/mithril/markers/$protected_pod.started"
  fi
done

wait_marker_value "$selected_node" "$protected_pod.exception-result" BASE_DENIED
protected_uid=$(kubectl -n "$scenario_namespace" get pod "$protected_pod" \
  -o jsonpath='{.metadata.uid}')
sed \
  -e "s/MITHRIL_MANUAL_NAMESPACE/$scenario_namespace/g" \
  -e "s/MITHRIL_MANUAL_POD_UID/$protected_uid/g" \
  "$directory/exception-v1.yaml" >"$work_directory/exception-v1.yaml"
kubectl --as="$exception_subject" create \
  -f "$work_directory/exception-v1.yaml" >/dev/null
wait_exception_state Active
for _attempt in {1..120}; do
  exception_status=$(node_status "$selected_node")
  if jq -e '
      .active_exception_count == 1 and
      .exception_ack_pending_count == 0
    ' <<<"$exception_status" >/dev/null; then
    break
  fi
  [[ $_attempt -lt 120 ]] || {
    echo "the selected node did not activate the bounded exception" >&2
    exit 1
  }
  sleep 1
done
for node_name in "${eligible_nodes[@]}"; do
  [[ $node_name == "$selected_node" ]] && continue
  jq -e '
    .pending_exception_count == 0 and
    .active_exception_count == 0 and
    .terminal_exception_count == 0
  ' <<<"$(node_status "$node_name")" >/dev/null
done

# The first open consumes the grant. The second open proves that the node
# removed its temporary authority before the process reports success.
write_marker "$selected_node" "$protected_pod.exception-request"
wait_marker_value "$selected_node" "$protected_pod.exception-result" ONE_USE
wait_exception_state Consumed
jq -e '
  .consumed_exception_count == 1 and
  .active_exception_count == 0
' <<<"$(node_status "$selected_node")" >/dev/null
kubectl --as="$exception_subject" -n "$scenario_namespace" delete \
  workloadprotectionexception temporary-file-access \
  --wait=true --timeout=120s >/dev/null
for _attempt in {1..120}; do
  if jq -e '
      .revoked_exception_count == 1 and
      .exception_ack_pending_count == 0
    ' <<<"$(node_status "$selected_node")" >/dev/null; then
    break
  fi
  [[ $_attempt -lt 120 ]] || {
    echo "exception deletion did not converge to node-local revocation" >&2
    exit 1
  }
  sleep 1
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
  kubectl -n "$system_namespace" exec -c mithril-node "$(node_pod "$node_name")" -- \
    test ! -e "/var/lib/mithril/markers/$failed_pod.started"
done
kubectl -n "$scenario_namespace" delete pod "$failed_pod" \
  --wait=true --timeout=120s >/dev/null

# A restart must replace the exact runtime authority, not reactivate the first binding.
container_before=$(kubectl -n "$scenario_namespace" get pod "$protected_pod" \
  -o jsonpath='{.status.containerStatuses[0].containerID}')
kubectl -n "$system_namespace" exec -c mithril-node "$(node_pod "$selected_node")" -- \
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
assert_live_exact_target "$selected_node" "$profile_id" ACTIVATE
runtime_binding_after=$(jq -er '.active_targets[0].runtime_binding_id' \
  <<<"$(node_status "$selected_node")")
[[ $runtime_binding_after != "$runtime_binding_before" ]] || {
  echo "the restarted container retained its old runtime binding" >&2
  exit 1
}

# Keep a second grant unused. Pod removal must revoke it without a use refund.
consumed_before_retirement=$(jq -er '.consumed_exception_count' \
  <<<"$(node_status "$selected_node")")
kubectl --as="$exception_subject" create \
  -f "$work_directory/exception-v1.yaml" >/dev/null
wait_exception_state Active
for _attempt in {1..120}; do
  if jq -e '
      .active_exception_count == 1 and
      .exception_ack_pending_count == 0
    ' <<<"$(node_status "$selected_node")" >/dev/null; then
    break
  fi
  [[ $_attempt -lt 120 ]] || {
    echo "the replacement exception did not become active" >&2
    exit 1
  }
  sleep 1
done

kubectl -n "$scenario_namespace" delete pod "$protected_pod" \
  --wait=true --timeout=120s >/dev/null
wait_exception_state Revoked
for _attempt in {1..120}; do
  exception_status=$(node_status "$selected_node")
  if jq -e --argjson consumed "$consumed_before_retirement" '
      .active_exception_count == 0 and
      .consumed_exception_count == $consumed and
      .exception_ack_pending_count == 0
    ' <<<"$exception_status" >/dev/null; then
    break
  fi
  [[ $_attempt -lt 120 ]] || {
    echo "Pod removal did not retire its unused exception authority" >&2
    exit 1
  }
  sleep 1
done
wait_policy_delivery_empty "$selected_node"
kubectl --as="$exception_subject" -n "$scenario_namespace" delete \
  workloadprotectionexception temporary-file-access \
  --wait=true --timeout=120s >/dev/null
kubectl --as="$policy_subject" -n "$scenario_namespace" delete \
  workloadprotectionpolicy "$profile_name" \
  --wait=true --timeout=120s >/dev/null

# Restarts after terminal cleanup must not replay an old root candidate.
old_node_pod=$(node_pod "$selected_node")
kubectl -n "$system_namespace" rollout restart deployment/mithril-control >/dev/null
kubectl -n "$system_namespace" rollout status deployment/mithril-control \
  --timeout=300s >/dev/null
kubectl -n "$system_namespace" delete pod "$old_node_pod" \
  --wait=true --timeout=120s >/dev/null
kubectl -n "$system_namespace" rollout status daemonset/mithril-node \
  --timeout=300s >/dev/null
wait_node_ready "$selected_node"
wait_policy_delivery_empty "$selected_node"

kubectl --as="$policy_subject" apply --server-side \
  --field-manager=mithril-convergence-manual --validate=strict \
  -f "$work_directory/policy-v1.yaml" >/dev/null
wait_policy_compiled
recreated_profile_id=$(kubectl -n "$scenario_namespace" get \
  workloadprotectionpolicy "$profile_name" -o jsonpath='{.metadata.uid}')
[[ $recreated_profile_id != "$profile_id" ]] || {
  echo "the recreated policy retained its deleted Kubernetes UID" >&2
  exit 1
}
for node_name in "${eligible_nodes[@]}"; do
  remove_marker "$node_name" "$protected_pod.started"
  remove_marker "$node_name" "$protected_pod.restart"
  remove_marker "$node_name" "$protected_pod.exception-request"
  remove_marker "$node_name" "$protected_pod.exception-result"
done
kubectl create -f "$work_directory/protected.yaml" >/dev/null
kubectl -n "$scenario_namespace" wait --for=condition=Ready \
  pod/"$protected_pod" --timeout=300s >/dev/null
recreated_node=$(kubectl -n "$scenario_namespace" get pod "$protected_pod" \
  -o jsonpath='{.spec.nodeName}')
assert_live_exact_target "$recreated_node" "$recreated_profile_id" ACTIVATE
recreated_status=$(node_status "$recreated_node")
jq -e '
  .active_targets[0].operation == "ACTIVATE" and
  .active_targets[0].predecessor_candidate_content_id == null
' <<<"$recreated_status" >/dev/null

kubectl -n "$scenario_namespace" delete pod "$protected_pod" \
  --wait=true --timeout=120s >/dev/null
wait_policy_delivery_empty "$recreated_node"
kubectl --as="$policy_subject" -n "$scenario_namespace" delete \
  workloadprotectionpolicy "$profile_name" \
  --wait=true --timeout=120s >/dev/null

jq -n --arg namespace "$scenario_namespace" --arg node "$selected_node" \
  --arg recreated_node "$recreated_node" \
  --arg previous "$container_before" --arg current "$container_after" \
  '{
    result: "PASS",
    namespace: $namespace,
    scheduler_selected_node: $node,
    recreated_scheduler_selected_node: $recreated_node,
    first_container_lifetime: $previous,
    replacement_container_lifetime: $current,
    exact_node_delivery: true,
    exact_target_proven: true,
    crd_desired_state: true,
    writer_rbac_separated: true,
    exception_one_use_consumed: true,
    exception_revoked: true,
    exception_target_retired: true,
    terminal_chain_cleaned: true,
    old_root_replay_refused: true,
    fresh_policy_uses_root_activation: true,
    runtime_gate_failure_closed: true,
    cleanup: "the EXIT trap removes all scenario resources"
  }'
