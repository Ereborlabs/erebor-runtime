#!/usr/bin/env bash

set -Eeuo pipefail

trap 'echo "outage recovery example failed at line $LINENO: $BASH_COMMAND" >&2' ERR

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
system_namespace=mithril-system
scenario_namespace=mithril-outage-recovery-example
runtime_class=mithril-outage-recovery-example
policy_name=outage-policy
node_label=example.mithril.erebor.dev/outage-node
owns_namespace=false
owns_runtime_class=false
owns_node_labels=false
control_scaled=false
work_directory=

[[ $# -eq 0 ]] || {
  echo "usage: $0" >&2
  exit 2
}
for command in jq kubectl sed sort; do
  command -v "$command" >/dev/null || {
    echo "required command is not installed: $command" >&2
    exit 2
  }
done

assert_absent() {
  local output
  if output=$(kubectl get "$@" 2>&1); then
    echo "the example refuses to replace an existing resource: $*" >&2
    exit 2
  fi
  [[ $output == *'(NotFound)'* ]] || {
    echo "the example could not prove resource absence: $output" >&2
    exit 1
  }
}

wait_control_absent() {
  local count
  for _attempt in {1..120}; do
    count=$(kubectl -n "$system_namespace" get pods \
      -l app.kubernetes.io/name=mithril-control \
      -o json 2>/dev/null | jq '.items | length' || true)
    [[ $count == 0 ]] && return 0
    sleep 1
  done
  echo "Control did not stop" >&2
  return 1
}

wait_denied_after() {
  local pod=$1
  local earliest=$2
  local line
  local timestamp
  for _attempt in {1..120}; do
    line=$(kubectl -n "$scenario_namespace" logs "$pod" --tail=20 \
      2>/dev/null | awk '$1 == "DENIED" { value = $0 } END { print value }')
    timestamp=${line#DENIED }
    if [[ $timestamp =~ ^[0-9]+$ ]] && ((timestamp >= earliest)); then
      return 0
    fi
    sleep 1
  done
  echo "Pod $pod did not report a current local denial" >&2
  return 1
}

wait_rollout() {
  local policy_json
  for _attempt in {1..300}; do
    policy_json=$(kubectl -n "$scenario_namespace" get \
      workloadprotectionpolicy "$policy_name" -o json 2>/dev/null || true)
    if [[ -n $policy_json ]] && jq -e '
        .status.observedGeneration == .metadata.generation and
        .status.rollout.desired == 2 and
        .status.rollout.active == 2 and
        .status.rollout.updating == 0 and
        .status.rollout.failed == 0
      ' <<<"$policy_json" >/dev/null; then
      return 0
    fi
    sleep 1
  done
  echo "the policy did not become active on both Nodes" >&2
  return 1
}

control_segment_manifest() {
  kubectl -n "$system_namespace" exec deployment/mithril-control -- \
    sh -c 'set -- /var/lib/mithril-control/store/evidence/segments/*.pb; [ -e "$1" ]; sha256sum "$@"'
}

cleanup() {
  local original_status=$?
  local cleanup_failed=false
  trap - EXIT
  set +e
  if [[ $control_scaled == true ]]; then
    kubectl -n "$system_namespace" scale deployment/mithril-control \
      --replicas="$control_replicas" >/dev/null 2>&1 || cleanup_failed=true
    kubectl -n "$system_namespace" rollout status deployment/mithril-control \
      --timeout=300s >/dev/null 2>&1 || cleanup_failed=true
  fi
  if [[ $owns_namespace == true ]]; then
    kubectl delete namespace "$scenario_namespace" --ignore-not-found=true \
      --wait=true --timeout=180s >/dev/null 2>&1 || cleanup_failed=true
  fi
  if [[ $owns_runtime_class == true ]]; then
    kubectl delete runtimeclass "$runtime_class" --ignore-not-found=true \
      --wait=true --timeout=120s >/dev/null 2>&1 || cleanup_failed=true
  fi
  if [[ $owns_node_labels == true ]]; then
    kubectl label node "${nodes[0]}" "${nodes[1]}" "$node_label"- \
      --overwrite >/dev/null 2>&1 || cleanup_failed=true
  fi
  if [[ -n $work_directory && $work_directory == /tmp/mithril-outage-example.* ]]; then
    rm -rf -- "$work_directory" || cleanup_failed=true
  fi
  if ((original_status != 0)); then
    exit "$original_status"
  fi
  [[ $cleanup_failed == false ]] || exit 1
}
trap cleanup EXIT

kubectl get --raw=/readyz >/dev/null
kubectl -n "$system_namespace" rollout status deployment/mithril-control \
  --timeout=180s >/dev/null
kubectl -n "$system_namespace" rollout status daemonset/mithril-node \
  --timeout=180s >/dev/null
control_replicas=$(kubectl -n "$system_namespace" get deployment/mithril-control \
  -o jsonpath='{.spec.replicas}')
[[ $control_replicas =~ ^[1-9][0-9]*$ ]] || {
  echo "Control must have at least one replica before the example starts" >&2
  exit 2
}

mapfile -t nodes < <(kubectl get nodes -o json | jq -r '
  .items[] |
  select(any(.status.conditions[];
    .type == "Ready" and .status == "True")) |
  .metadata.name
' | sort)
[[ ${#nodes[@]} -eq 2 ]] || {
  echo "the example requires exactly two Ready Kubernetes Nodes" >&2
  exit 2
}
assert_absent namespace "$scenario_namespace"
assert_absent runtimeclass "$runtime_class"

work_directory=$(mktemp -d /tmp/mithril-outage-example.XXXXXX)
kubectl label node "${nodes[0]}" "$node_label=a" --overwrite >/dev/null
kubectl label node "${nodes[1]}" "$node_label=b" --overwrite >/dev/null
owns_node_labels=true

kubectl apply --server-side --field-manager=mithril-outage-example \
  --validate=strict -f - >/dev/null <<EOF
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: $runtime_class
handler: mithril
EOF
owns_runtime_class=true
kubectl create namespace "$scenario_namespace" >/dev/null
owns_namespace=true
kubectl -n "$scenario_namespace" create serviceaccount worker >/dev/null

sed "s/MITHRIL_OUTAGE_NAMESPACE/$scenario_namespace/g" \
  "$directory/policy-v1.yaml" >"$work_directory/policy.yaml"
kubectl apply --server-side --field-manager=mithril-outage-example \
  --validate=strict -f "$work_directory/policy.yaml" >/dev/null
for suffix in a b; do
  sed \
    -e "s/MITHRIL_OUTAGE_NAMESPACE/$scenario_namespace/g" \
    -e "s/MITHRIL_OUTAGE_RUNTIME_CLASS/$runtime_class/g" \
    -e "s/MITHRIL_OUTAGE_POD/outage-$suffix/g" \
    -e "s/MITHRIL_OUTAGE_NODE/$suffix/g" \
    "$directory/protected-pod-v1.yaml" >"$work_directory/pod-$suffix.yaml"
  kubectl create -f "$work_directory/pod-$suffix.yaml" >/dev/null
done
kubectl -n "$scenario_namespace" wait --for=condition=Ready \
  pod/outage-a pod/outage-b --timeout=300s >/dev/null
[[ $(kubectl -n "$scenario_namespace" get pod outage-a \
  -o jsonpath='{.spec.nodeName}') == "${nodes[0]}" ]]
[[ $(kubectl -n "$scenario_namespace" get pod outage-b \
  -o jsonpath='{.spec.nodeName}') == "${nodes[1]}" ]]
wait_rollout
wait_denied_after outage-a 0
wait_denied_after outage-b 0
control_segment_manifest >"$work_directory/control-segments-before-outage.txt"
[[ -s $work_directory/control-segments-before-outage.txt ]] || {
  echo "Control retained no evidence segments before its outage" >&2
  exit 1
}
pod_a_uid=$(kubectl -n "$scenario_namespace" get pod outage-a \
  -o jsonpath='{.metadata.uid}')
pod_b_uid=$(kubectl -n "$scenario_namespace" get pod outage-b \
  -o jsonpath='{.metadata.uid}')

kubectl -n "$system_namespace" scale deployment/mithril-control \
  --replicas=0 >/dev/null
control_scaled=true
wait_control_absent
outage_started=$(date +%s)
wait_denied_after outage-a "$outage_started"
wait_denied_after outage-b "$outage_started"
[[ $(kubectl -n "$scenario_namespace" get pod outage-a \
  -o jsonpath='{.metadata.uid}') == "$pod_a_uid" ]]
[[ $(kubectl -n "$scenario_namespace" get pod outage-b \
  -o jsonpath='{.metadata.uid}') == "$pod_b_uid" ]]

sed \
  -e "s/MITHRIL_OUTAGE_NAMESPACE/$scenario_namespace/g" \
  -e "s/MITHRIL_OUTAGE_RUNTIME_CLASS/$runtime_class/g" \
  -e 's/MITHRIL_OUTAGE_POD/outage-new/g' \
  -e 's/MITHRIL_OUTAGE_NODE/a/g' \
  "$directory/protected-pod-v1.yaml" >"$work_directory/pod-new.yaml"
if unavailable_output=$(kubectl create --dry-run=server \
    -f "$work_directory/pod-new.yaml" 2>&1); then
  unavailable_status=0
else
  unavailable_status=$?
fi
[[ $unavailable_status -ne 0 &&
   $unavailable_output == *'failed calling webhook'* ]] || {
  echo "a new protected Pod was not fail-closed while Control was unavailable" >&2
  exit 1
}

kubectl -n "$system_namespace" scale deployment/mithril-control \
  --replicas="$control_replicas" >/dev/null
kubectl -n "$system_namespace" rollout status deployment/mithril-control \
  --timeout=300s >/dev/null
control_scaled=false
wait_rollout
control_segment_manifest >"$work_directory/control-segments-after-outage.txt"
while IFS= read -r segment; do
  grep -Fqx -- "$segment" "$work_directory/control-segments-after-outage.txt" || {
    echo "Control removed an unconsumed evidence segment during restart: $segment" >&2
    exit 1
  }
done <"$work_directory/control-segments-before-outage.txt"
recovery_started=$(date +%s)
wait_denied_after outage-a "$recovery_started"
wait_denied_after outage-b "$recovery_started"

echo "PASS: existing Pods kept denial, new work failed closed, and Control retained unconsumed evidence."
