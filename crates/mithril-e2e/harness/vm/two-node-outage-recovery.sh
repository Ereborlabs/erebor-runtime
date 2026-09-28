#!/usr/bin/env bash

set -Eeuo pipefail

trap 'echo "outage recovery failed at line $LINENO: $BASH_COMMAND" >&2' ERR

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
fixture_directory=$(cd -- "$directory/../../fixtures/convergence" && pwd)
source "$directory/../kubernetes-oracles.sh"
source "$directory/outage-rollout.sh"
environment=
provider=
output_directory=
data_check=
remote_check=
system_namespace=mithril-system
scenario_namespace=mithril-outage-recovery
policy_name=outage-policy
network_table=mithril_outage_qualification
watch_table=mithril_watch_relist_qualification
marker_root=/var/lib/mithril-convergence/markers
owns_namespace=false
owns_node_labels=false
owns_markers=false
network_blocked=false
watch_blocked=false
watch_vm=
api_stopped=false
control_storage_read_only=false
control_managed=false

usage() {
  echo "usage: $0 --environment PATH --data-check PATH [--provider PATH] [--output-directory PATH]" >&2
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
    --data-check)
      (($# >= 2)) || { usage; exit 2; }
      data_check=$2
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
for command in jq sed timeout wc; do
  command -v "$command" >/dev/null || {
    echo "required command is not installed: $command" >&2
    exit 2
  }
done

environment=$(cd -- "$(dirname -- "$environment")" && pwd)/$(basename -- "$environment")
jq -e '.schema_version == 2' "$environment" >/dev/null
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
[[ -n $data_check && -x $data_check ]] || {
  echo "--data-check requires the current mithril_discovery_test executable" >&2
  exit 2
}
read -r retained_state state_claim config_secret tls_secret < <(retained_mithril_state "$environment")
[[ $retained_state == retained ]] || {
  echo "outage qualification requires retained Mithril storage" >&2
  exit 2
}

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

inspect_control_data() {
  local label=$1
  local baseline=${2:-}
  local command
  local args=(--case data-store-inspect --data-directory "$remote_check/data"
    --tenant-id aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa
    --output-directory "$remote_check/results/$label")
  [[ $(remote_kubectl -n "$system_namespace" get deployment mithril-control \
    -o jsonpath='{.spec.replicas}') == 0 ]]
  [[ $(remote_kubectl -n "$system_namespace" get pods \
    -l app.kubernetes.io/name=mithril-control -o json | jq '.items | length') == 0 ]]
  if [[ -n $baseline ]]; then
    args+=(--baseline "$remote_check/results/$baseline/result.json")
  fi
  printf -v command '%q ' sudo bash "$remote_check/inspect-data.sh" \
    "$data_path" "$remote_check" "${args[@]}"
  "$provider" run "$vm_a" "$command"
  "$provider" run "$vm_a" sudo cat "$remote_check/results/$label/result.json" \
    >"$output_directory/$label.json"
}

require_replayed_data() {
  jq -e --slurpfile prior "$1" --argjson node_a "$3" --argjson node_b "$4" '
    def records($node):
      [.sources[] | select(.identity.node_id == $node) | .record_count] | add // 0;
    records("mithril-node-a") >= ($prior[0] | records("mithril-node-a")) + $node_a and
    records("mithril-node-b") >= ($prior[0] | records("mithril-node-b")) + $node_b
  ' "$2" >/dev/null
}

control_data_path() {
  jq -er --arg claim "$1" --arg uid "$2" --arg node "$3" --arg namespace "$4" '
    select(.spec.claimRef.name == $claim and .spec.claimRef.uid == $uid and
      .spec.claimRef.namespace == $namespace) |
    select(any(.spec.nodeAffinity.required.nodeSelectorTerms[].matchExpressions[];
      .key == "kubernetes.io/hostname" and .operator == "In" and .values == [$node])) |
    .spec.local.path
  '
}

remove_network_block() {
  if [[ $network_blocked == true ]]; then
    "$provider" run "$vm_b" sudo nft delete table inet "$network_table"
    network_blocked=false
  fi
}

remove_watch_block() {
  if [[ $watch_blocked == true ]]; then
    "$provider" run "$watch_vm" sudo nft delete table inet "$watch_table"
    watch_blocked=false
  fi
}

restore_control_storage() {
  if [[ $control_storage_read_only == true ]]; then
    remote_kubectl -n "$system_namespace" patch deployment mithril-control \
      --type=strategic -p '{"spec":{"template":{"spec":{"containers":[{"name":"mithril-control","volumeMounts":[{"mountPath":"/var/lib/mithril-control/evidence/analysis","$patch":"delete"}]}]}}}}' \
      >/dev/null || return $?
    control_storage_read_only=false
  fi
}

block_control_storage() {
  control_storage_read_only=true
  remote_kubectl -n "$system_namespace" patch deployment mithril-control \
    --type=strategic -p '{"spec":{"template":{"spec":{"containers":[{"name":"mithril-control","volumeMounts":[{"name":"state","mountPath":"/var/lib/mithril-control/evidence/analysis","subPath":"evidence/analysis","readOnly":true}]}]}}}}' \
    >/dev/null
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

capture_failure_diagnostics() {
  local pod
  remote_kubectl -n "$scenario_namespace" get \
    pods,workloadprotectionpolicies -o yaml \
    >"$output_directory/failure-resources.yaml" 2>&1 || true
  remote_kubectl -n "$scenario_namespace" get events \
    --sort-by=.lastTimestamp \
    >"$output_directory/failure-events.txt" 2>&1 || true
  for pod in outage-a outage-b outage-new; do
    remote_kubectl -n "$scenario_namespace" describe pod "$pod" \
      >"$output_directory/$pod-describe.txt" 2>&1 || true
    remote_kubectl -n "$scenario_namespace" logs "$pod" \
      --all-containers --previous \
      >"$output_directory/$pod-previous.log" 2>&1 || true
  done
}

cleanup() {
  local original_status=$?
  local cleanup_failed=false
  trap - EXIT
  set +e
  remove_network_block || cleanup_failed=true
  remove_watch_block || cleanup_failed=true
  if [[ $api_stopped == true ]]; then
    "$provider" run "$vm_a" sudo systemctl start k3s || cleanup_failed=true
    api_stopped=false
    wait_api || cleanup_failed=true
  fi
  if remote_kubectl get --raw=/readyz >/dev/null 2>&1; then
    if ((original_status != 0)) && [[ $owns_namespace == true ]]; then
      capture_failure_diagnostics
    fi
    restore_control_storage || cleanup_failed=true
    if [[ $control_managed == true ]]; then
      remote_kubectl -n "$system_namespace" scale deployment/mithril-control \
        --replicas=1 >/dev/null 2>&1 || cleanup_failed=true
    fi
    if [[ $owns_namespace == true ]]; then
      remote_kubectl delete namespace "$scenario_namespace" --ignore-not-found=true \
        --wait=true --timeout=180s >/dev/null 2>&1 || cleanup_failed=true
      if [[ -n ${node_a_name:-} && -n ${node_b_name:-} ]]; then
        wait_policy_delivery_empty "$node_a_name" || cleanup_failed=true
        wait_policy_delivery_empty "$node_b_name" || cleanup_failed=true
      fi
    fi
    if [[ $owns_node_labels == true ]]; then
      remote_kubectl label node "$node_a_name" "$node_b_name" \
        qualification.mithril.erebor.dev/node- --overwrite \
        >/dev/null 2>&1 || cleanup_failed=true
    fi
  else
    cleanup_failed=true
  fi
  if [[ $owns_markers == true ]]; then
    remove_markers || cleanup_failed=true
  fi
  if [[ $remote_check =~ ^/var/tmp/mithril-data-check\.[A-Za-z0-9]+$ ]]; then
    "$provider" run "$vm_a" sudo rm -rf -- "$remote_check" || cleanup_failed=true
  elif [[ -n $remote_check ]]; then
    cleanup_failed=true
  fi
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
    -o json | jq -er '
      .items[] | select(.metadata.deletionTimestamp == null) | .metadata.name
    ' | head -n 1
}

node_status() {
  local node_name=$1
  local pod
  pod=$(node_pod "$node_name")
  remote_kubectl -n "$system_namespace" exec -c mithril-node "$pod" -- \
    mithril-inspect policy-delivery --state-directory /var/lib/mithril
}

node_wal_manifest() {
  local node_name=$1
  local pod
  pod=$(node_pod "$node_name")
  remote_kubectl -n "$system_namespace" exec -c mithril-node "$pod" -- \
    sh -c "find /var/lib/mithril/evidence-wal-v2 -type f \
      \( -name '*.open' -o -name '*.seg' \) \
      -exec sh -c 'for path do size=\$(stat -c %s \"\$path\"); \
        digest=\$(head -c \"\$size\" \"\$path\" | sha256sum | sed -n \"1s/[[:space:]].*//p\"); \
        printf \"%s %s %s\\n\" \"\$size\" \"\$digest\" \"\$path\"; done' sh '{}' +"
}

node_wal_count() {
  local node_name=$1
  local pod
  pod=$(node_pod "$node_name")
  remote_kubectl -n "$system_namespace" exec -c mithril-node "$pod" -- \
    mithril-inspect effects --socket-path /run/mithril/observation.sock \
      --cgroup-scope / --samples 1 | sed -n \
      '1s/.*pending_evidence_records=\([0-9][0-9]*\).*/\1/p'
}

verify_node_wal_prefixes() {
  local node_name=$1
  local manifest=$2
  local pod
  local size
  local expected
  local path
  local actual
  pod=$(node_pod "$node_name")
  while read -r size expected path; do
    actual=$(remote_kubectl -n "$system_namespace" exec -c mithril-node "$pod" -- \
      sh -c "head -c '$size' '$path' | sha256sum" | sed -n '1s/[[:space:]].*//p')
    [[ $actual == "$expected" ]] || {
      echo "Node $node_name changed or removed retained WAL prefix $path" >&2
      return 1
    }
  done <"$manifest"
}

wait_node_wal_count() {
  local node_name=$1
  local minimum=$2
  local deadline=$((SECONDS + 120))
  local count
  while ((SECONDS < deadline)); do
    count=$(node_wal_count "$node_name" 2>/dev/null || true)
    [[ $count =~ ^[0-9]+$ ]] || count=0
    if ((count >= minimum)); then
      printf '%s\n' "$count"
      return 0
    fi
    sleep 1
  done
  echo "node $node_name retained fewer than $minimum evidence records" >&2
  return 1
}

wait_node_wal_empty() {
  local node_name=$1
  local deadline=$((SECONDS + 180))
  local count
  local previous_count=
  while true; do
    count=$(node_wal_count "$node_name" 2>/dev/null || true)
    if [[ $count == 0 ]]; then
      return 0
    fi
    if [[ $count =~ ^[0-9]+$ ]] &&
        [[ -z $previous_count || $count -lt $previous_count ]]; then
      deadline=$((SECONDS + 180))
      previous_count=$count
    fi
    if ((SECONDS >= deadline)); then
      break
    fi
    sleep 1
  done
  echo "node $node_name did not truncate acknowledged evidence" >&2
  return 1
}

wait_node_pod_replaced() {
  local node_name=$1
  local previous_uid=$2
  local deadline=$((SECONDS + 180))
  local pod_json
  while ((SECONDS < deadline)); do
    pod_json=$(remote_kubectl -n "$system_namespace" get pods \
      -l app.kubernetes.io/name=mithril-node \
      --field-selector "spec.nodeName=$node_name" -o json 2>/dev/null || true)
    if [[ -n $pod_json ]] && jq -e --arg previous_uid "$previous_uid" '
        any(.items[];
          .metadata.uid != $previous_uid and
          .status.phase == "Running" and
          .metadata.deletionTimestamp == null)
      ' <<<"$pod_json" >/dev/null; then
      return 0
    fi
    sleep 1
  done
  echo "node $node_name did not replace its Mithril Pod" >&2
  return 1
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

wait_policy_accepted() {
  local name=$1
  local deadline=$((SECONDS + 180))
  local policy_json
  while ((SECONDS < deadline)); do
    policy_json=$(remote_kubectl -n "$scenario_namespace" get \
      workloadprotectionpolicy "$name" -o json 2>/dev/null || true)
    if [[ -n $policy_json ]] && jq -e '
        .status.observedGeneration == .metadata.generation and
        any(.status.conditions[]?; .type == "Accepted" and .status == "True")
      ' <<<"$policy_json" >/dev/null; then
      return 0
    fi
    sleep 1
  done
  echo "policy $name did not become accepted" >&2
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

"$data_check" --case data-store-startup \
  --output-directory "$output_directory/lightweight-startup"
"$data_check" --case data-store-recovery \
  --output-directory "$output_directory/lightweight-recovery"
sha256sum "$data_check" >"$output_directory/data-check.sha256"

wait_api
remote_kubectl -n "$system_namespace" rollout status deployment/mithril-control \
  --timeout=180s >/dev/null
remote_kubectl -n "$system_namespace" rollout status daemonset/mithril-node \
  --timeout=180s >/dev/null
assert_absent namespace "$scenario_namespace"
if "$provider" run "$vm_b" sudo nft list table inet "$network_table" \
    >/dev/null 2>&1; then
  echo "outage recovery qualification refuses to replace nft table $network_table" >&2
  exit 2
fi
for vm in "$vm_a" "$vm_b"; do
  if "$provider" run "$vm" sudo nft list table inet "$watch_table" \
      >/dev/null 2>&1; then
    echo "outage recovery qualification refuses to replace nft table $watch_table" >&2
    exit 2
  fi
done

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
control_deployment=$(remote_kubectl -n "$system_namespace" get deployment mithril-control -o json)
jq -e --arg claim "$state_claim" --arg node "$node_a_name" '
  .spec.replicas == 1 and
  .spec.template.spec.nodeSelector["kubernetes.io/hostname"] == $node and
  any(.spec.template.spec.volumes[];
    .name == "state" and .persistentVolumeClaim.claimName == $claim) and
  any(.spec.template.spec.containers[];
    .name == "mithril-control" and
    any(.volumeMounts[]; .name == "state" and
      .mountPath == "/var/lib/mithril-control" and .readOnly != true) and
    all(.volumeMounts[]; .mountPath != "/var/lib/mithril-control/evidence/analysis"))
' <<<"$control_deployment" >/dev/null
claim_json=$(remote_kubectl -n "$system_namespace" get pvc "$state_claim" -o json)
claim_uid=$(jq -er '.metadata.uid' <<<"$claim_json")
volume_name=$(jq -er '.spec.volumeName' <<<"$claim_json")
volume_json=$(remote_kubectl get pv "$volume_name" -o json)
data_base=$(control_data_path "$state_claim" "$claim_uid" "$node_a_name" \
  "$system_namespace" <<<"$volume_json")
[[ $data_base == "/var/lib/rancher/k3s/storage/pvc-${claim_uid}_${system_namespace}_${state_claim}" ]] || {
  echo "Control data path does not match its retained local-path volume" >&2
  exit 2
}
data_path=$data_base/evidence/analysis
[[ $("$provider" run "$vm_a" sudo realpath -e -- "$data_path") == "$data_path" ]]
remote_check=$("$provider" run "$vm_a" mktemp -d /var/tmp/mithril-data-check.XXXXXXXX)
[[ $remote_check =~ ^/var/tmp/mithril-data-check\.[A-Za-z0-9]+$ ]]
"$provider" put "$vm_a" "$data_check" "$remote_check/check"
"$provider" put "$vm_a" "$directory/inspect-data.sh" "$remote_check/inspect-data.sh"
"$provider" run "$vm_a" chmod 755 "$remote_check" "$remote_check/check"
"$provider" run "$vm_a" mkdir "$remote_check/data"
"$provider" run "$vm_a" sudo install -d -m 700 -o 65532 -g 65532 "$remote_check/results"
"$provider" run "$vm_a" "$remote_check/check" --help >/dev/null
remote_digest=$("$provider" run "$vm_a" sha256sum "$remote_check/check" | cut -d ' ' -f1)
[[ $remote_digest == $(cut -d ' ' -f1 "$output_directory/data-check.sha256") ]]
wait_policy_delivery_empty "$node_a_name"
wait_policy_delivery_empty "$node_b_name"

owns_markers=true
remove_markers
for vm in "$vm_a" "$vm_b"; do
  "$provider" run "$vm" sudo mkfifo \
    "$marker_root/outage-a.request" \
    "$marker_root/outage-b.request" \
    "$marker_root/outage-new.request"
  "$provider" run "$vm" sudo touch \
    "$marker_root/outage.denied" "$marker_root/outage-update.denied"
done
remote_kubectl label node "$node_a_name" \
  qualification.mithril.erebor.dev/node=a --overwrite >/dev/null
remote_kubectl label node "$node_b_name" \
  qualification.mithril.erebor.dev/node=b --overwrite >/dev/null
owns_node_labels=true

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
wait_node_wal_empty "$node_a_name"
wait_node_wal_empty "$node_b_name"

control_managed=true
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
inspect_control_data data-before-outage
for sequence in 1 2 3 4; do
  request_denial "$vm_a" outage-a "control-outage-a-$sequence"
  request_denial "$vm_b" outage-b "control-outage-b-$sequence"
done
retained_records_a=$(wait_node_wal_count "$node_a_name" 4)
retained_records_b=$(wait_node_wal_count "$node_b_name" 4)
node_wal_manifest "$node_a_name" >"$work_directory/node-a-wal-before-restart.txt"
node_a_pod=$(node_pod "$node_a_name")
node_a_pod_uid=$(remote_kubectl -n "$system_namespace" get pod "$node_a_pod" \
  -o jsonpath='{.metadata.uid}')
remote_kubectl -n "$system_namespace" delete pod "$node_a_pod" \
  --wait=false >/dev/null
wait_node_pod_replaced "$node_a_name" "$node_a_pod_uid"
node_wal_manifest "$node_a_name" >"$work_directory/node-a-wal-after-restart.txt"
if ! verify_node_wal_prefixes "$node_a_name" \
    "$work_directory/node-a-wal-before-restart.txt"; then
  cp "$work_directory/node-a-wal-before-restart.txt" \
    "$output_directory/node-a-wal-before-restart.txt"
  cp "$work_directory/node-a-wal-after-restart.txt" \
    "$output_directory/node-a-wal-after-restart.txt"
  exit 1
fi
retained_records_a_after_restart=$(wait_node_wal_count "$node_a_name" "$retained_records_a")
request_denial "$vm_a" outage-a control-outage-a-after-node-restart
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
wait_node_wal_empty "$node_a_name"
wait_node_wal_empty "$node_b_name"

remote_kubectl -n "$system_namespace" scale deployment/mithril-control \
  --replicas=0 >/dev/null
storage_stop_deadline=$((SECONDS + 120))
storage_control_stopped=false
while ((SECONDS < storage_stop_deadline)); do
  if [[ $(remote_kubectl -n "$system_namespace" get pods \
    -l app.kubernetes.io/name=mithril-control -o json | jq '.items | length') -eq 0 ]]; then
    storage_control_stopped=true
    break
  fi
  sleep 1
done
[[ $storage_control_stopped == true ]] || {
  echo "Control did not stop before its storage outage" >&2
  exit 1
}
inspect_control_data data-after-outage data-before-outage
records_before=$(jq '[.sources[].record_count] | add' "$output_directory/data-before-outage.json")
records_after=$(jq '[.sources[].record_count] | add' "$output_directory/data-after-outage.json")
require_replayed_data "$output_directory/data-before-outage.json" \
  "$output_directory/data-after-outage.json" "$retained_records_a_after_restart" "$retained_records_b"
block_control_storage
remote_kubectl -n "$system_namespace" scale deployment/mithril-control \
  --replicas=1 >/dev/null
storage_failure_deadline=$((SECONDS + 120))
storage_failure_observed=false
while ((SECONDS < storage_failure_deadline)); do
  storage_failure_output=$(remote_kubectl -n "$system_namespace" logs \
    deployment/mithril-control --tail=40 2>&1 || true)
  if [[ $storage_failure_output == *'Read-only file system'* ]]; then
    storage_failure_observed=true
    break
  fi
  sleep 1
done
[[ $storage_failure_observed == true ]] || {
  echo "Control did not report its unavailable evidence store" >&2
  exit 1
}
remote_kubectl -n "$system_namespace" rollout status deployment/mithril-control \
  --timeout=180s >/dev/null
wait_control_session mithril-node-a
wait_control_session mithril-node-b
wait_node_control_acknowledgement "$node_a_name"
wait_node_control_acknowledgement "$node_b_name"
request_denial "$vm_a" outage-a storage-outage-a
request_denial "$vm_b" outage-b storage-outage-b
storage_retained_records_a=$(wait_node_wal_count "$node_a_name" 1)
storage_retained_records_b=$(wait_node_wal_count "$node_b_name" 1)
restore_control_storage
remote_kubectl -n "$system_namespace" rollout status deployment/mithril-control \
  --timeout=300s >/dev/null
wait_control_session mithril-node-a
wait_control_session mithril-node-b
wait_node_control_acknowledgement "$node_a_name"
wait_node_control_acknowledgement "$node_b_name"
wait_node_wal_empty "$node_a_name"
wait_node_wal_empty "$node_b_name"
remote_kubectl -n "$system_namespace" scale deployment/mithril-control \
  --replicas=0 >/dev/null
remote_kubectl -n "$system_namespace" wait --for=delete pod \
  -l app.kubernetes.io/name=mithril-control --timeout=120s >/dev/null
inspect_control_data data-after-storage data-after-outage
records_storage=$(jq '[.sources[].record_count] | add' "$output_directory/data-after-storage.json")
require_replayed_data "$output_directory/data-after-outage.json" \
  "$output_directory/data-after-storage.json" "$storage_retained_records_a" "$storage_retained_records_b"
remote_kubectl -n "$system_namespace" scale deployment/mithril-control \
  --replicas=1 >/dev/null
remote_kubectl -n "$system_namespace" rollout status deployment/mithril-control \
  --timeout=300s >/dev/null
wait_node_control_acknowledgement "$node_a_name"
wait_node_control_acknowledgement "$node_b_name"
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
wait_rollout 2 0 true
candidate_a_recovered=$(active_candidate "$node_a_name")
candidate_b_recovered=$(active_candidate "$node_b_name")
request_denial "$vm_b" outage-b recovered-b

compacted_watch_event=$(remote_kubectl get --raw \
  '/apis/mithril.erebor.dev/v1alpha1/workloadprotectionpolicies?watch=true&resourceVersion=1&timeoutSeconds=5')
kubernetes_watch_cursor_is_compacted "$compacted_watch_event" || {
  echo "Kubernetes did not reject the compacted policy watch cursor" >&2
  exit 1
}
control_pod_json=$(remote_kubectl -n "$system_namespace" get pods \
  -l app.kubernetes.io/name=mithril-control -o json)
control_pod_uid_before_relist=$(jq -er '.items[0].metadata.uid' <<<"$control_pod_json")
control_pod_ip=$(jq -er '.items[0].status.podIP' <<<"$control_pod_json")
control_pod_node=$(jq -er '.items[0].spec.nodeName' <<<"$control_pod_json")
case $control_pod_node in
  "$node_a_name") watch_vm=$vm_a ;;
  "$node_b_name") watch_vm=$vm_b ;;
  *)
    echo "Control Pod is not on either retained test Node: $control_pod_node" >&2
    exit 1
    ;;
esac
api_endpoints_json=$(remote_kubectl -n default get endpointslices.discovery.k8s.io \
  -l kubernetes.io/service-name=kubernetes -o json)
api_endpoint_ip=$(jq -er '
  [.items[].endpoints[] |
    select(.conditions.ready != false) |
    .addresses[]][0]
' <<<"$api_endpoints_json")
api_endpoint_port=$(jq -er '
  [.items[].ports[] |
    select(.protocol == "TCP" and .name == "https") |
    .port][0]
' <<<"$api_endpoints_json")
[[ -n $control_pod_ip && -n $api_endpoint_ip && -n $api_endpoint_port ]] || {
  echo "watch interruption targets are incomplete" >&2
  exit 1
}
old_policy_uid=$(remote_kubectl -n "$scenario_namespace" get \
  workloadprotectionpolicy "$policy_name" -o jsonpath='{.metadata.uid}')
jq '
  .metadata.name = "relist-sentinel" |
  .spec.podSelector.matchLabels["app.kubernetes.io/name"] = "mithril-relist-sentinel"
' "$work_directory/policy.json" >"$work_directory/relist-sentinel.json"
"$provider" put "$vm_a" "$work_directory/relist-sentinel.json" \
  /var/tmp/mithril-relist-sentinel.json

"$provider" run "$watch_vm" sudo nft add table inet "$watch_table"
watch_blocked=true
"$provider" run "$watch_vm" \
  "sudo nft add chain inet $watch_table input '{ type filter hook input priority -50; policy accept; }'"
"$provider" run "$watch_vm" sudo nft add rule inet "$watch_table" input \
  ip saddr "$control_pod_ip" ip daddr "$api_endpoint_ip" \
  tcp dport "$api_endpoint_port" drop
remote_kubectl apply --server-side --field-manager=mithril-outage-recovery \
  --validate=strict -f /var/tmp/mithril-relist-sentinel.json >/dev/null
remote_kubectl -n "$scenario_namespace" delete workloadprotectionpolicy \
  "$policy_name" --wait=true --timeout=120s >/dev/null
if remote_kubectl -n "$scenario_namespace" get workloadprotectionpolicy \
    relist-sentinel -o json | jq -e '.status != null' >/dev/null; then
  echo "Control observed the sentinel while its Kubernetes watch was blocked" >&2
  exit 1
fi
request_denial "$vm_a" outage-a watch-blocked-a
request_denial "$vm_b" outage-b watch-blocked-b

"$provider" run "$watch_vm" sudo nft insert rule inet "$watch_table" input \
  ip saddr "$control_pod_ip" ip daddr "$api_endpoint_ip" \
  tcp dport "$api_endpoint_port" reject with tcp reset
sleep 2
remove_watch_block
wait_policy_accepted relist-sentinel
control_pod_uid_after_relist=$(remote_kubectl -n "$system_namespace" get pods \
  -l app.kubernetes.io/name=mithril-control -o jsonpath='{.items[0].metadata.uid}')
[[ $control_pod_uid_after_relist == "$control_pod_uid_before_relist" ]] || {
  echo "Control restarted instead of recovering its Kubernetes watch" >&2
  exit 1
}

remote_kubectl -n "$scenario_namespace" delete pod outage-a outage-b \
  --wait=true --timeout=120s >/dev/null
wait_policy_delivery_empty "$node_a_name"
wait_policy_delivery_empty "$node_b_name"
remote_kubectl -n "$scenario_namespace" delete workloadprotectionpolicy \
  relist-sentinel --wait=true --timeout=120s >/dev/null
remote_kubectl apply --server-side --field-manager=mithril-outage-recovery \
  --validate=strict -f /var/tmp/mithril-outage-policy.json >/dev/null
wait_policy_accepted "$policy_name"
new_policy_uid=$(remote_kubectl -n "$scenario_namespace" get \
  workloadprotectionpolicy "$policy_name" -o jsonpath='{.metadata.uid}')
[[ $new_policy_uid != "$old_policy_uid" ]] || {
  echo "the relist case reused the deleted policy UID" >&2
  exit 1
}
for suffix in a b; do
  "$provider" run "$vm_a" sudo rm -f \
    "$marker_root/outage-$suffix.started" "$marker_root/outage-$suffix.result"
  remote_kubectl create -f "/var/tmp/mithril-outage-pod-$suffix.yaml" >/dev/null
done
remote_kubectl -n "$scenario_namespace" wait --for=condition=Ready pod/outage-a \
  pod/outage-b --timeout=300s >/dev/null
wait_application_started "$vm_a" outage-a
wait_application_started "$vm_b" outage-b
wait_node_control_acknowledgement "$node_a_name"
wait_node_control_acknowledgement "$node_b_name"
refresh_policy_status relist-recreated
wait_rollout 2 0
candidate_a_after_relist=$(wait_candidate_change "$node_a_name" "$candidate_a_recovered")
candidate_b_after_relist=$(wait_candidate_change "$node_b_name" "$candidate_b_recovered")
for node_name in "$node_a_name" "$node_b_name"; do
  node_status "$node_name" | jq -e --arg profile_id "$new_policy_uid" '
    .active_target_count == 1 and
    .active_targets[0].profile_id == $profile_id and
    .active_targets[0].policy_source_revision_id != "" and
    (
      (
        .active_targets[0].operation == "ACTIVATE" and
        .active_targets[0].predecessor_candidate_content_id == null
      ) or
      (
        .active_targets[0].operation == "REPLACE" and
        .active_targets[0].predecessor_candidate_content_id != null
      )
    )
  ' >/dev/null
done
request_denial "$vm_a" outage-a relist-recreated-a
request_denial "$vm_b" outage-b relist-recreated-b
cp "$work_directory/node-a-wal-before-restart.txt" \
  "$output_directory/node-a-wal-before-restart.txt"
cp "$work_directory/node-a-wal-after-restart.txt" \
  "$output_directory/node-a-wal-after-restart.txt"
jq -n \
  --arg node_a "$node_a_name" \
  --arg node_b "$node_b_name" \
  --arg candidate_a_v1 "$candidate_a_pre_partition" \
  --arg candidate_b_v1 "$candidate_b_pre_partition" \
  --arg candidate_a_v2 "$candidate_a_v2" \
  --arg candidate_b_v2 "$candidate_b_v2" \
  --arg candidate_a_recovered "$candidate_a_recovered" \
  --arg candidate_b_recovered "$candidate_b_recovered" \
  --argjson records_before "$records_before" \
  --argjson records_after "$records_after" \
  --argjson records_storage "$records_storage" \
  --argjson retained_records_a "$retained_records_a" \
  --argjson retained_records_a_after_restart "$retained_records_a_after_restart" \
  --argjson retained_records_b "$retained_records_b" \
  --argjson storage_retained_records_a "$storage_retained_records_a" \
  --argjson storage_retained_records_b "$storage_retained_records_b" '
  {
    result: "PASS",
    nodes: [$node_a, $node_b],
    control_outage_kept_local_denial: true,
    control_outage_blocked_new_protected_work: true,
    control_restart_retained_evidence: true,
    storage_failure_withheld_acknowledgement: true,
    storage_failure_kept_policy_service: true,
    storage_recovery_replayed_retained_evidence: true,
    storage_outage_retained_node_records: {
      node_a: $storage_retained_records_a,
      node_b: $storage_retained_records_b
    },
    node_retain_exceeded_soft_bound_without_loss: true,
    node_restart_retained_unacknowledged_evidence: true,
    control_acknowledgement_truncated_node_wal: true,
    retained_node_records: {
      node_a: $retained_records_a,
      node_a_after_restart: $retained_records_a_after_restart,
      node_b: $retained_records_b
    },
    retained_data_records: {
      before_outage: $records_before,
      after_outage: $records_after,
      after_storage_outage: $records_storage
    },
    network_partition_kept_predecessor: true,
    mixed_rollout: {desired: 2, active: 1, updating: 1, failed: 0},
    reconnect_converged: true,
    api_outage_kept_worker_denial: true,
    api_recovery_converged: true,
    watch_compaction_observed: true,
    watch_relist_converged: true,
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
