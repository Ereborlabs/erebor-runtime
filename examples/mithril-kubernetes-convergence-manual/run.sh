#!/usr/bin/env bash

set -Eeuo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
system_namespace=${MITHRIL_SYSTEM_NAMESPACE:-mithril-system}
scenario_namespace=mithril-convergence-manual
profile_name=converter-policy
runtime_class=mithril-convergence-manual
failed_runtime_class=mithril-convergence-manual-fail
protected_pod=protected
failed_pod=gate-failure
work_directory=$(mktemp -d /tmp/mithril-convergence-manual.XXXXXX)
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
    remove_marker "$node_name" "$protected_pod.exception-target" >/dev/null 2>&1 ||
      status=1
    remove_marker "$node_name" "$protected_pod.exception-request" >/dev/null 2>&1 ||
      status=1
    remove_marker "$node_name" "$protected_pod.exception-result" >/dev/null 2>&1 ||
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

jq -e --arg profile_id "$profile_id" '
  .active_candidate_content_id != null and
  .active_profile_ids == [$profile_id] and
  .scheduled_binding_count == 0 and
  .runtime_binding_count == 1 and
  .activation_pending == false and
  .control_acknowledged == true
' <<<"$(node_status "$selected_node")" >/dev/null
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

jq -n --arg namespace "$scenario_namespace" --arg node "$selected_node" \
  --arg previous "$container_before" --arg current "$container_after" \
  '{
    result: "PASS",
    namespace: $namespace,
    scheduler_selected_node: $node,
    first_container_lifetime: $previous,
    replacement_container_lifetime: $current,
    exact_node_delivery: true,
    crd_desired_state: true,
    writer_rbac_separated: true,
    exception_one_use_consumed: true,
    exception_revoked: true,
    runtime_gate_failure_closed: true,
    cleanup: "the EXIT trap removes all scenario resources"
  }'
