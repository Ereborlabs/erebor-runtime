#!/usr/bin/env bash

set -Eeuo pipefail

trap 'echo "outage recovery failed at line $LINENO: $BASH_COMMAND" >&2' ERR

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
fixture_directory=$(cd -- "$directory/../../fixtures/convergence" && pwd)
environment=
provider=
output_directory=
system_namespace=mithril-system
scenario_namespace=mithril-outage-recovery
runtime_class=mithril-outage-recovery
policy_name=outage-policy
network_table=mithril_outage_qualification
marker_root=/var/lib/mithril-convergence/markers
owns_namespace=false
owns_runtime_class=false
owns_node_labels=false
network_blocked=false
api_stopped=false

usage() {
  echo "usage: $0 --environment PATH [--provider PATH] [--output-directory PATH]" >&2
}

while (($#)); do
  case $1 in
    --environment)
      (($# >= 2)) || { usage; exit 2; }
      environment=$2
      shift 2
      ;;
    --provider)
      (($# >= 2)) || { usage; exit 2; }
      provider=$2
      shift 2
      ;;
    --output-directory)
      (($# >= 2)) || { usage; exit 2; }
      output_directory=$2
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

[[ -n $environment && -r $environment ]] || {
  echo "retained environment is not readable: $environment" >&2
  exit 2
}
for command in jq sed sort timeout; do
  command -v "$command" >/dev/null || {
    echo "required command is not installed: $command" >&2
    exit 2
  }
done

environment=$(cd -- "$(dirname -- "$environment")" && pwd)/$(basename -- "$environment")
jq -e '.schema_version == 1' "$environment" >/dev/null
vm_a=$(jq -er '.node_a' "$environment")
vm_b=$(jq -er '.node_b' "$environment")
work_a=$(jq -er '.node_a_work_directory' "$environment")
work_b=$(jq -er '.node_b_work_directory' "$environment")
retained_provider=$(jq -er '.provider' "$environment")
known_hosts=$(jq -er '.known_hosts' "$environment")
[[ -n $provider ]] || provider=$retained_provider
[[ $provider == "$retained_provider" && -x $provider ]] || {
  echo "provider does not match the retained environment: $provider" >&2
  exit 2
}
[[ $vm_a == mithril-runtime-qualification-[0-9]* &&
   $vm_b == mithril-runtime-qualification-[0-9]* && $vm_a != "$vm_b" &&
   $work_a == /tmp/mithril-vm-test.* && $work_b == /tmp/mithril-vm-test.* &&
   -d $work_a && -d $work_b && $known_hosts == "$work_a/known_hosts" ]] || {
  echo "retained environment does not identify two owned harness VMs" >&2
  exit 2
}
export MITHRIL_VM_KNOWN_HOSTS=$known_hosts

if [[ -z $output_directory ]]; then
  output_directory=/tmp/mithril-kubernetes-outage-recovery-$(date -u +%Y%m%dT%H%M%SZ)-$$
fi
if [[ -e $output_directory && ! -d $output_directory ]]; then
  echo "evidence output is not a directory: $output_directory" >&2
  exit 2
fi
if [[ -d $output_directory ]] &&
    [[ -n $(find "$output_directory" -mindepth 1 -maxdepth 1 -print -quit) ]]; then
  echo "evidence output directory is not empty: $output_directory" >&2
  exit 2
fi
mkdir -p -- "$output_directory"
output_directory=$(cd -- "$output_directory" && pwd)
work_directory=$(mktemp -d /tmp/mithril-outage-recovery.XXXXXX)

remote_kubectl() {
  local command
  printf -v command '%q ' sudo /usr/local/bin/k3s kubectl "$@"
  "$provider" run "$vm_a" "$command"
}

control_segment_manifest() {
  remote_kubectl -n "$system_namespace" exec deployment/mithril-control -- \
    sh -c 'set -- /var/lib/mithril-control/store/evidence/segments/*; [ -e "$1" ]; sha256sum "$@"'
}

remove_network_block() {
  if [[ $network_blocked == true ]]; then
    "$provider" run "$vm_b" sudo nft delete table inet "$network_table"
    network_blocked=false
  fi
}

remove_markers() {
  local pod
  local vm
  for vm in "$vm_a" "$vm_b"; do
    for pod in outage-a outage-b outage-new; do
      "$provider" run "$vm" sudo rm -f \
        "$marker_root/$pod.started" \
        "$marker_root/$pod.request" \
        "$marker_root/$pod.result"
    done
    "$provider" run "$vm" sudo rm -f \
      "$marker_root/outage.denied" \
      "$marker_root/outage-update.denied"
  done
}

wait_api() {
  local deadline=$((SECONDS + 180))
  while ((SECONDS < deadline)); do
    if remote_kubectl get --raw=/readyz >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "the Kubernetes API did not recover" >&2
  return 1
}

cleanup() {
  local original_status=$?
  local cleanup_failed=false
  trap - EXIT
  set +e
  remove_network_block || cleanup_failed=true
  if [[ $api_stopped == true ]]; then
    "$provider" run "$vm_a" sudo systemctl start k3s || cleanup_failed=true
    api_stopped=false
    wait_api || cleanup_failed=true
  fi
  if remote_kubectl get --raw=/readyz >/dev/null 2>&1; then
    remote_kubectl -n "$system_namespace" scale deployment/mithril-control \
      --replicas=1 >/dev/null 2>&1 || cleanup_failed=true
    if [[ $owns_namespace == true ]]; then
      remote_kubectl delete namespace "$scenario_namespace" --ignore-not-found=true \
        --wait=true --timeout=180s >/dev/null 2>&1 || cleanup_failed=true
      if [[ -n ${node_a_name:-} && -n ${node_b_name:-} ]]; then
        wait_policy_delivery_empty "$node_a_name" || cleanup_failed=true
        wait_policy_delivery_empty "$node_b_name" || cleanup_failed=true
      fi
    fi
    if [[ $owns_runtime_class == true ]]; then
      remote_kubectl delete runtimeclass "$runtime_class" --ignore-not-found=true \
        --wait=true --timeout=120s >/dev/null 2>&1 || cleanup_failed=true
    fi
    if [[ $owns_node_labels == true ]]; then
      remote_kubectl label node "$node_a_name" "$node_b_name" \
        qualification.mithril.erebor.dev/node- --overwrite \
        >/dev/null 2>&1 || cleanup_failed=true
    fi
  else
    cleanup_failed=true
  fi
  remove_markers || cleanup_failed=true
  if [[ $work_directory == /tmp/mithril-outage-recovery.* ]]; then
    rm -rf -- "$work_directory" || cleanup_failed=true
  else
    cleanup_failed=true
  fi
  if ((original_status != 0)); then
    exit "$original_status"
  fi
  [[ $cleanup_failed == false ]] || exit 1
}
trap cleanup EXIT

assert_absent() {
  local output
  if output=$(remote_kubectl get "$@" 2>&1); then
    echo "outage recovery qualification refuses to replace an existing resource: $*" >&2
    exit 2
  fi
  [[ $output == *'(NotFound)'* ]] || {
    echo "outage recovery qualification could not prove resource absence: $output" >&2
    exit 1
  }
}

node_pod() {
  local node_name=$1
  remote_kubectl -n "$system_namespace" get pods \
    -l app.kubernetes.io/name=mithril-node \
    --field-selector "spec.nodeName=$node_name" \
    -o jsonpath='{.items[0].metadata.name}'
}

node_status() {
  local node_name=$1
  local pod
  pod=$(node_pod "$node_name")
  remote_kubectl -n "$system_namespace" exec -c mithril-node "$pod" -- \
    mithril-inspect policy-delivery --state-directory /var/lib/mithril
}

active_candidate() {
  node_status "$1" | jq -er '.active_candidate_content_id'
}

wait_policy_delivery_empty() {
  local node_name=$1
  local deadline=$((SECONDS + 180))
  local status
  while ((SECONDS < deadline)); do
    status=$(node_status "$node_name" 2>/dev/null || true)
    if [[ -n $status ]] && jq -e '
        .active_candidate_content_id == null and
        .active_target_count == 0 and
        .scheduled_binding_count == 0 and
        .runtime_binding_count == 0
      ' <<<"$status" >/dev/null; then
      return 0
    fi
    sleep 1
  done
  echo "node $node_name retained policy delivery after workload removal" >&2
  return 1
}

wait_candidate_change() {
  local node_name=$1
  local previous=$2
  local candidate
  local deadline=$((SECONDS + 180))
  while ((SECONDS < deadline)); do
    candidate=$(active_candidate "$node_name" 2>/dev/null || true)
    if [[ -n $candidate && $candidate != "$previous" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
    sleep 1
  done
  echo "node $node_name did not activate a replacement candidate" >&2
  return 1
}

wait_candidate_value() {
  local node_name=$1
  local expected=$2
  local candidate
  local deadline=$((SECONDS + 180))
  while ((SECONDS < deadline)); do
    candidate=$(active_candidate "$node_name" 2>/dev/null || true)
    [[ $candidate == "$expected" ]] && return 0
    sleep 1
  done
  echo "node $node_name did not retain candidate $expected" >&2
  return 1
}

wait_node_control_acknowledgement() {
  local node_name=$1
  local deadline=$((SECONDS + 180))
  local status
  while ((SECONDS < deadline)); do
    status=$(node_status "$node_name" 2>/dev/null || true)
    if [[ -n $status ]] && jq -e '
        .active_candidate_content_id != null and
        .active_target_count == 1 and
        .activation_pending == false and
        .control_acknowledged == true
      ' <<<"$status" >/dev/null; then
      return 0
    fi
    sleep 1
  done
  echo "node $node_name did not acknowledge its active target" >&2
  return 1
}

wait_control_session() {
  local node_id=$1
  local deadline=$((SECONDS + 180))
  local logs
  while ((SECONDS < deadline)); do
    logs=$(remote_kubectl -n "$system_namespace" logs \
      deployment/mithril-control 2>/dev/null || true)
    if grep -F "authenticated a Mithril node session node_id=$node_id" \
        <<<"$logs" >/dev/null; then
      return 0
    fi
    sleep 1
  done
  echo "Control did not authenticate a recovered session for $node_id" >&2
  return 1
}

refresh_policy_status() {
  local step=$1
  remote_kubectl -n "$scenario_namespace" annotate \
    workloadprotectionpolicy "$policy_name" \
    "qualification.mithril.erebor.dev/reconcile-step=$step" \
    --overwrite >/dev/null
}

wait_rollout() {
  local active=$1
  local updating=$2
  local deadline=$((SECONDS + 360))
  local policy_json
  while ((SECONDS < deadline)); do
    policy_json=$(remote_kubectl -n "$scenario_namespace" get \
      workloadprotectionpolicy "$policy_name" -o json 2>/dev/null || true)
    if [[ -n $policy_json ]] && jq -e \
      --argjson active "$active" --argjson updating "$updating" '
        .status.observedGeneration == .metadata.generation and
        .status.rollout.desired == 2 and
        .status.rollout.active == $active and
        .status.rollout.updating == $updating and
        .status.rollout.failed == 0
      ' <<<"$policy_json" >/dev/null; then
      return 0
    fi
    sleep 1
  done
  echo "policy rollout did not reach active=$active updating=$updating" >&2
  return 1
}

wait_node_ready() {
  local node_name=$1
  local expected=$2
  local deadline=$((SECONDS + 120))
  local node_json
  while ((SECONDS < deadline)); do
    node_json=$(remote_kubectl get node "$node_name" -o json 2>/dev/null || true)
    if [[ $expected == true ]] && [[ -n $node_json ]] && jq -e '
        .metadata.labels["mithril.erebor.dev/ready"] == "true" and
        all(.spec.taints[]?;
          .key != "mithril.erebor.dev/not-ready" or .effect != "NoSchedule")
      ' <<<"$node_json" >/dev/null; then
      return 0
    fi
    if [[ $expected == false ]] && [[ -n $node_json ]] && jq -e '
        (.metadata.labels["mithril.erebor.dev/ready"] // "") != "true" and
        any(.spec.taints[]?;
          .key == "mithril.erebor.dev/not-ready" and .effect == "NoSchedule")
      ' <<<"$node_json" >/dev/null; then
      return 0
    fi
    sleep 1
  done
  echo "node $node_name did not reach Mithril ready=$expected" >&2
  return 1
}

request_denial() {
  local vm=$1
  local pod=$2
  local request=$3
  local deadline=$((SECONDS + 60))
  local result
  "$provider" run "$vm" \
    "printf '%s\\n' '$request' | sudo tee '$marker_root/$pod.request' >/dev/null"
  while ((SECONDS < deadline)); do
    result=$("$provider" run "$vm" sudo cat \
      "$marker_root/$pod.result" 2>/dev/null || true)
    [[ $result == "$request:DENIED" ]] && return 0
    sleep 1
  done
  echo "protected Pod $pod did not deny request $request: $result" >&2
  return 1
}

wait_application_started() {
  local vm=$1
  local pod=$2
  local deadline=$((SECONDS + 120))
  while ((SECONDS < deadline)); do
    if "$provider" run "$vm" sudo test -e \
        "$marker_root/$pod.started" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "protected Pod $pod did not publish its application marker" >&2
  return 1
}

wait_api
remote_kubectl -n "$system_namespace" rollout status deployment/mithril-control \
  --timeout=180s >/dev/null
remote_kubectl -n "$system_namespace" rollout status daemonset/mithril-node \
  --timeout=180s >/dev/null
assert_absent namespace "$scenario_namespace"
assert_absent runtimeclass "$runtime_class"
if "$provider" run "$vm_b" sudo nft list table inet "$network_table" \
    >/dev/null 2>&1; then
  echo "outage recovery qualification refuses to replace nft table $network_table" >&2
  exit 2
fi

address_a=$("$provider" address "$vm_a")
address_b=$("$provider" address "$vm_b")
nodes_json=$(remote_kubectl get nodes -o json)
node_a_name=$(jq -er --arg address "$address_a" '
  .items[] |
  select(any(.status.addresses[];
    .type == "InternalIP" and .address == $address)) |
  .metadata.name
' <<<"$nodes_json")
node_b_name=$(jq -er --arg address "$address_b" '
  .items[] |
  select(any(.status.addresses[];
    .type == "InternalIP" and .address == $address)) |
  .metadata.name
' <<<"$nodes_json")
[[ -n $node_a_name && -n $node_b_name && $node_a_name != "$node_b_name" ]] || {
  echo "retained VMs do not map to two exact Kubernetes Nodes" >&2
  exit 1
}
wait_policy_delivery_empty "$node_a_name"
wait_policy_delivery_empty "$node_b_name"

remove_markers
for vm in "$vm_a" "$vm_b"; do
  "$provider" run "$vm" sudo touch \
    "$marker_root/outage.denied" "$marker_root/outage-update.denied"
done
remote_kubectl label node "$node_a_name" \
  qualification.mithril.erebor.dev/node=a --overwrite >/dev/null
remote_kubectl label node "$node_b_name" \
  qualification.mithril.erebor.dev/node=b --overwrite >/dev/null
owns_node_labels=true

remote_kubectl apply --server-side --field-manager=mithril-outage-recovery \
  --validate=strict -f - >/dev/null <<EOF
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: $runtime_class
handler: mithril
EOF
owns_runtime_class=true
remote_kubectl create namespace "$scenario_namespace" >/dev/null
owns_namespace=true
remote_kubectl -n "$scenario_namespace" create serviceaccount worker >/dev/null

sed "s/MITHRIL_OUTAGE_NAMESPACE/$scenario_namespace/g" \
  "$fixture_directory/outage-policy-v1.json" >"$work_directory/policy.json"
"$provider" put "$vm_a" "$work_directory/policy.json" \
  "/var/tmp/mithril-outage-policy.json"
remote_kubectl apply --server-side --field-manager=mithril-outage-recovery \
  --validate=strict -f /var/tmp/mithril-outage-policy.json >/dev/null

for suffix in a b; do
  sed \
    -e "s/MITHRIL_OUTAGE_NAMESPACE/$scenario_namespace/g" \
    -e "s/MITHRIL_OUTAGE_POD/outage-$suffix/g" \
    -e "s/MITHRIL_OUTAGE_NODE/$suffix/g" \
    "$fixture_directory/outage-protected-pod-v1.yaml" >"$work_directory/pod-$suffix.yaml"
  "$provider" put "$vm_a" "$work_directory/pod-$suffix.yaml" \
    "/var/tmp/mithril-outage-pod-$suffix.yaml"
  remote_kubectl create -f "/var/tmp/mithril-outage-pod-$suffix.yaml" >/dev/null
done
remote_kubectl -n "$scenario_namespace" wait --for=condition=Ready pod/outage-a \
  pod/outage-b --timeout=300s >/dev/null
[[ $(remote_kubectl -n "$scenario_namespace" get pod outage-a \
  -o jsonpath='{.spec.nodeName}') == "$node_a_name" ]]
[[ $(remote_kubectl -n "$scenario_namespace" get pod outage-b \
  -o jsonpath='{.spec.nodeName}') == "$node_b_name" ]]
wait_application_started "$vm_a" outage-a
wait_application_started "$vm_b" outage-b
wait_node_control_acknowledgement "$node_a_name"
wait_node_control_acknowledgement "$node_b_name"
refresh_policy_status baseline
wait_rollout 2 0
candidate_a_v1=$(active_candidate "$node_a_name")
candidate_b_v1=$(active_candidate "$node_b_name")
request_denial "$vm_a" outage-a baseline-a
request_denial "$vm_b" outage-b baseline-b
control_segment_manifest >"$work_directory/control-segments-before-outage.txt"
[[ -s $work_directory/control-segments-before-outage.txt ]] || {
  echo "Control retained no evidence segments before its outage" >&2
  exit 1
}

remote_kubectl -n "$system_namespace" scale deployment/mithril-control \
  --replicas=0 >/dev/null
control_stop_deadline=$((SECONDS + 120))
control_stopped=false
while ((SECONDS < control_stop_deadline)); do
  if [[ $(remote_kubectl -n "$system_namespace" get pods \
    -l app.kubernetes.io/name=mithril-control -o json | jq '.items | length') -eq 0 ]]; then
    control_stopped=true
    break
  fi
  sleep 1
done
if [[ $control_stopped != true ]]; then
  echo "Control did not stop" >&2
  exit 1
fi
request_denial "$vm_a" outage-a control-outage-a
request_denial "$vm_b" outage-b control-outage-b
sed \
  -e "s/MITHRIL_OUTAGE_NAMESPACE/$scenario_namespace/g" \
  -e 's/MITHRIL_OUTAGE_POD/outage-new/g' \
  -e 's/MITHRIL_OUTAGE_NODE/a/g' \
  "$fixture_directory/outage-protected-pod-v1.yaml" >"$work_directory/pod-new.yaml"
"$provider" put "$vm_a" "$work_directory/pod-new.yaml" \
  /var/tmp/mithril-outage-pod-new.yaml
if unavailable_output=$(remote_kubectl create --dry-run=server \
    -f /var/tmp/mithril-outage-pod-new.yaml 2>&1); then
  unavailable_status=0
else
  unavailable_status=$?
fi
[[ $unavailable_status -ne 0 &&
   $unavailable_output == *'failed calling webhook'* ]] || {
  echo "a new protected Pod was not fail-closed while Control was unavailable" >&2
  exit 1
}
remote_kubectl -n "$system_namespace" scale deployment/mithril-control \
  --replicas=1 >/dev/null
remote_kubectl -n "$system_namespace" rollout status deployment/mithril-control \
  --timeout=300s >/dev/null
wait_control_session mithril-node-a
wait_control_session mithril-node-b
wait_node_control_acknowledgement "$node_a_name"
wait_node_control_acknowledgement "$node_b_name"
control_segment_manifest >"$work_directory/control-segments-after-outage.txt"
while IFS= read -r segment; do
  grep -Fqx -- "$segment" "$work_directory/control-segments-after-outage.txt" || {
    echo "Control removed an unconsumed evidence segment during restart: $segment" >&2
    exit 1
  }
done <"$work_directory/control-segments-before-outage.txt"
refresh_policy_status control-recovered
wait_rollout 2 0
candidate_a_pre_partition=$(active_candidate "$node_a_name")
candidate_b_pre_partition=$(active_candidate "$node_b_name")

node_b_pod_ip=$(remote_kubectl -n "$system_namespace" get pod \
  "$(node_pod "$node_b_name")" -o jsonpath='{.status.podIP}')
control_pod_ip=$(remote_kubectl -n "$system_namespace" get pods \
  -l app.kubernetes.io/name=mithril-control \
  -o jsonpath='{.items[0].status.podIP}')
[[ -n $node_b_pod_ip && -n $control_pod_ip ]] || {
  echo "network partition targets are incomplete" >&2
  exit 1
}
"$provider" run "$vm_b" sudo nft add table inet "$network_table"
network_blocked=true
"$provider" run "$vm_b" \
  "sudo nft add chain inet $network_table forward '{ type filter hook forward priority -50; policy accept; }'"
"$provider" run "$vm_b" sudo nft add rule inet "$network_table" forward \
  ip saddr "$node_b_pod_ip" ip daddr "$control_pod_ip" tcp dport 8443 drop
wait_node_ready "$node_b_name" false

policy_patch='[{"op":"add","path":"/spec/roles/0/files/-","value":{"name":"deny-update-target","path":"/var/lib/mithril-convergence/outage-update.denied","recursive":false,"operations":["OpenRead"],"action":"Deny"}}]'
remote_kubectl -n "$scenario_namespace" patch workloadprotectionpolicy \
  "$policy_name" --type=json -p "$policy_patch" >/dev/null
candidate_a_v2=$(wait_candidate_change "$node_a_name" "$candidate_a_pre_partition")
wait_candidate_value "$node_b_name" "$candidate_b_pre_partition"
wait_node_control_acknowledgement "$node_a_name"
refresh_policy_status mixed-rollout
wait_rollout 1 1
request_denial "$vm_b" outage-b partition-b

remove_network_block
wait_node_ready "$node_b_name" true
candidate_b_v2=$(wait_candidate_change "$node_b_name" "$candidate_b_pre_partition")
wait_node_control_acknowledgement "$node_b_name"
refresh_policy_status partition-recovered
wait_rollout 2 0
request_denial "$vm_b" outage-b reconnected-b

"$provider" run "$vm_a" sudo systemctl stop k3s
api_stopped=true
[[ $("$provider" run "$vm_a" sudo systemctl show \
  --property ActiveState --value k3s) == inactive ]]
request_denial "$vm_b" outage-b api-outage-b
"$provider" run "$vm_a" sudo systemctl start k3s
api_stopped=false
wait_api
remote_kubectl wait --for=condition=Ready node --all --timeout=300s >/dev/null
remote_kubectl -n "$system_namespace" rollout status deployment/mithril-control \
  --timeout=300s >/dev/null
remote_kubectl -n "$system_namespace" rollout status daemonset/mithril-node \
  --timeout=300s >/dev/null
wait_node_ready "$node_a_name" true
wait_node_ready "$node_b_name" true
wait_control_session mithril-node-a
wait_control_session mithril-node-b
wait_node_control_acknowledgement "$node_a_name"
wait_node_control_acknowledgement "$node_b_name"
refresh_policy_status api-recovered
wait_rollout 2 0
candidate_a_recovered=$(active_candidate "$node_a_name")
candidate_b_recovered=$(active_candidate "$node_b_name")
request_denial "$vm_b" outage-b recovered-b
cp "$work_directory/control-segments-before-outage.txt" \
  "$output_directory/control-segments-before-outage.txt"
cp "$work_directory/control-segments-after-outage.txt" \
  "$output_directory/control-segments-after-outage.txt"
segments_before_outage=$(wc -l <"$work_directory/control-segments-before-outage.txt")
segments_after_outage=$(wc -l <"$work_directory/control-segments-after-outage.txt")

jq -n \
  --arg node_a "$node_a_name" \
  --arg node_b "$node_b_name" \
  --arg candidate_a_v1 "$candidate_a_pre_partition" \
  --arg candidate_b_v1 "$candidate_b_pre_partition" \
  --arg candidate_a_v2 "$candidate_a_v2" \
  --arg candidate_b_v2 "$candidate_b_v2" \
  --arg candidate_a_recovered "$candidate_a_recovered" \
  --arg candidate_b_recovered "$candidate_b_recovered" \
  --argjson segments_before_outage "$segments_before_outage" \
  --argjson segments_after_outage "$segments_after_outage" '
  {
    result: "PASS",
    nodes: [$node_a, $node_b],
    control_outage_kept_local_denial: true,
    control_outage_blocked_new_protected_work: true,
    control_restart_retained_unconsumed_evidence: true,
    evidence_segments: {
      before_outage: $segments_before_outage,
      after_outage: $segments_after_outage
    },
    network_partition_kept_predecessor: true,
    mixed_rollout: {desired: 2, active: 1, updating: 1, failed: 0},
    reconnect_converged: true,
    api_outage_kept_worker_denial: true,
    api_recovery_converged: true,
    candidates: {
      node_a: {
        before_partition: $candidate_a_v1,
        after_partition: $candidate_a_v2,
        after_api_recovery: $candidate_a_recovered
      },
      node_b: {
        before_partition: $candidate_b_v1,
        after_partition: $candidate_b_v2,
        after_api_recovery: $candidate_b_recovered
      }
    }
  }
' | tee "$output_directory/result.json"
