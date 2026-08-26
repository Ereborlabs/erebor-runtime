#!/usr/bin/env bash

set -Eeuo pipefail

trap 'echo "two-node convergence failed at line $LINENO: $BASH_COMMAND" >&2' ERR

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/convergence-cleanup.sh"
source "$directory/../kubernetes-oracles.sh"
repo_root=$(cd -- "$directory/../../../.." && pwd)
provider=$directory/providers/libvirt.sh
output_directory=
keep_vms=false
manual_environment=false
protected_start_only=false
reuse_environment=
k3s_version=${MITHRIL_VM_K3S_VERSION:-v1.35.5+k3s1}
reuse_images=${MITHRIL_VM_REUSE_IMAGES:-false}
system_namespace=mithril-system
workload_namespace=mithril-convergence
runtime_hook_owner=$system_namespace/mithril
runtime_hook_socket=/run/mithril/runtime-admission.sock
entry_effect_capture_pids=()

usage() {
  echo "usage: $0 [--provider PATH] [--output-directory PATH] [--keep-vms] [--manual-environment] [--protected-start-only] [--reuse-environment PATH]" >&2
}

while (($#)); do
  case $1 in
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
    --keep-vms)
      keep_vms=true
      shift
      ;;
    --manual-environment)
      manual_environment=true
      keep_vms=true
      shift
      ;;
    --protected-start-only)
      protected_start_only=true
      shift
      ;;
    --reuse-environment)
      (($# >= 2)) || { usage; exit 2; }
      reuse_environment=$2
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

[[ $protected_start_only == false || $manual_environment == false ]] || {
  echo "--protected-start-only cannot run with --manual-environment" >&2
  exit 2
}
[[ -z $reuse_environment || $manual_environment == false ]] || {
  echo "--reuse-environment cannot run with --manual-environment" >&2
  exit 2
}

for command in base64 cargo docker helm jq openssl sed sha256sum timeout; do
  command -v "$command" >/dev/null || {
    echo "required command is not installed: $command" >&2
    exit 2
  }
done
[[ -x $provider ]] || {
  echo "VM provider is not executable: $provider" >&2
  exit 2
}
[[ $k3s_version =~ ^v[0-9]+\.[0-9]+\.[0-9]+\+k3s[0-9]+$ ]] || {
  echo "invalid MITHRIL_VM_K3S_VERSION: $k3s_version" >&2
  exit 2
}
[[ $reuse_images == true || $reuse_images == false ]] || {
  echo "MITHRIL_VM_REUSE_IMAGES must be true or false" >&2
  exit 2
}
[[ $(uname -m) == x86_64 ]] || {
  echo "the two-node convergence fixture requires an x86_64 host" >&2
  exit 2
}
if [[ $manual_environment == true &&
      ${MITHRIL_VM_SOURCE_MOUNT:-} != "$repo_root" ]]; then
  echo "the manual environment requires MITHRIL_VM_SOURCE_MOUNT=$repo_root" >&2
  exit 2
fi

if [[ -z $output_directory ]]; then
  output_directory=$repo_root/target/mithril-two-node-convergence/$(date -u +%Y%m%dT%H%M%SZ)-$$
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

reusing_environment=false
if [[ -n $reuse_environment ]]; then
  [[ -r $reuse_environment ]] || {
    echo "retained environment is not readable: $reuse_environment" >&2
    exit 2
  }
  reuse_environment=$(cd -- "$(dirname -- "$reuse_environment")" && pwd)/$(basename -- "$reuse_environment")
  jq -e '.schema_version == 1' "$reuse_environment" >/dev/null
  vm_a=$(jq -er '.node_a' "$reuse_environment")
  vm_b=$(jq -er '.node_b' "$reuse_environment")
  work_a=$(jq -er '.node_a_work_directory' "$reuse_environment")
  work_b=$(jq -er '.node_b_work_directory' "$reuse_environment")
  retained_provider=$(jq -er '.provider' "$reuse_environment")
  retained_known_hosts=$(jq -er '.known_hosts' "$reuse_environment")
  [[ $retained_provider == "$provider" ]] || {
    echo "retained provider does not match --provider: $retained_provider" >&2
    exit 2
  }
  [[ $vm_a == mithril-runtime-qualification-[0-9]* &&
      $vm_b == mithril-runtime-qualification-[0-9]* && $vm_a != "$vm_b" &&
      $work_a == /tmp/mithril-vm-test.* &&
      $work_b == /tmp/mithril-vm-test.* && -d $work_a && -d $work_b &&
      $retained_known_hosts == "$work_a/known_hosts" ]] || {
    echo "retained environment does not identify two owned harness VMs" >&2
    exit 2
  }
  mapfile -t owner_a <"$work_a/libvirt-domain-owner"
  mapfile -t owner_b <"$work_b/libvirt-domain-owner"
  [[ ${#owner_a[@]} -eq 2 && ${owner_a[0]} == "$vm_a" &&
      ${owner_a[1]} =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ &&
      ${#owner_b[@]} -eq 2 && ${owner_b[0]} == "$vm_b" &&
      ${owner_b[1]} =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ &&
      -r $work_a/kubeconfig.yaml ]] || {
    echo "retained environment ownership records are invalid" >&2
    exit 2
  }
  export MITHRIL_VM_KNOWN_HOSTS=$retained_known_hosts
  keep_vms=true
  reusing_environment=true
else
  work_a=$(mktemp -d /tmp/mithril-vm-test.XXXXXX)
  work_b=$(mktemp -d /tmp/mithril-vm-test.XXXXXX)
  vm_a=mithril-runtime-qualification-$$1
  vm_b=mithril-runtime-qualification-$$2
  export MITHRIL_VM_KNOWN_HOSTS=$work_a/known_hosts
fi
ssh_public_key=${MITHRIL_VM_SSH_PUBLIC_KEY:-$HOME/.ssh/id_rsa.pub}
created_a=false
created_b=false
cluster_created=false
kubeconfig=$work_a/kubeconfig.yaml

diagnostic_kubectl() {
  timeout 20s "$provider" run "$vm_a" sudo /usr/local/bin/k3s kubectl \
    --request-timeout=10s "$@"
}

assert_runtime_hook() {
  local state=$1
  local node=$2
  local remote=$3
  local arguments=("$state" /)
  if [[ $state == installed ]]; then
    arguments+=("$runtime_hook_owner" "$runtime_hook_socket" 4000 5)
  else
    arguments+=("$runtime_hook_socket")
  fi
  if [[ $state == installed ]]; then
    timeout 20s "$provider" run "$node" sudo bash \
      "$remote/harness/runtime-hook-oracle.sh" "${arguments[@]}"
    return
  fi
  # Runtime socket removal follows DaemonSet termination after the hook files leave.
  for _attempt in {1..30}; do
    if timeout 10s "$provider" run "$node" sudo bash \
        "$remote/harness/runtime-hook-oracle.sh" "${arguments[@]}" \
        >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "Mithril runtime-hook paths remained on $node after uninstall" >&2
  return 1
}

stop_entry_effect_capture() {
  local pid
  for pid in "${entry_effect_capture_pids[@]}"; do
    kill "$pid" >/dev/null 2>&1 || true
  done
  for pid in "${entry_effect_capture_pids[@]}"; do
    wait "$pid" >/dev/null 2>&1 || true
  done
  entry_effect_capture_pids=()
}

cleanup() {
  local original_status=$?
  local cleanup_failed=false
  local cleanup_result_file
  local resources_removed
  trap - EXIT
  set +e
  stop_entry_effect_capture
  if ((original_status != 0)) && [[ $cluster_created == true ]]; then
    collect_mithril_diagnostics "$output_directory" "$system_namespace" \
      "$workload_namespace" || cleanup_failed=true
  fi
  remove_mithril_release "$cluster_created" "$keep_vms" \
    "$manual_environment" "$kubeconfig" "$system_namespace" || cleanup_failed=true
  if [[ $cluster_created == true && $keep_vms == false &&
        $manual_environment == false ]]; then
    assert_runtime_hook removed "$vm_a" "$remote_a" || cleanup_failed=true
    assert_runtime_hook removed "$vm_b" "$remote_b" || cleanup_failed=true
  fi
  if [[ $created_b == true && $keep_vms == false ]]; then
    "$provider" destroy "$vm_b" "$work_b" || cleanup_failed=true
  fi
  if [[ $created_a == true && $keep_vms == false ]]; then
    "$provider" destroy "$vm_a" "$work_a" || cleanup_failed=true
  fi
  if [[ $keep_vms == true ]]; then
    {
      printf 'node_a=%q\nnode_a_work_directory=%q\n' "$vm_a" "$work_a"
      printf 'node_b=%q\nnode_b_work_directory=%q\n' "$vm_b" "$work_b"
      printf 'provider=%q\n' "$provider"
      printf 'export MITHRIL_VM_KNOWN_HOSTS=%q\n' "$MITHRIL_VM_KNOWN_HOSTS"
      printf 'manual_environment=%q\n' "$manual_environment"
    } >"$output_directory/retained-vms.txt" || cleanup_failed=true
    jq -n \
      --arg node_a "$vm_a" \
      --arg node_a_work_directory "$work_a" \
      --arg node_b "$vm_b" \
      --arg node_b_work_directory "$work_b" \
      --arg provider "$provider" \
      --arg known_hosts "$MITHRIL_VM_KNOWN_HOSTS" \
      '{
        schema_version: 1,
        node_a: $node_a,
        node_a_work_directory: $node_a_work_directory,
        node_b: $node_b,
        node_b_work_directory: $node_b_work_directory,
        provider: $provider,
        known_hosts: $known_hosts
      }' >"$output_directory/retained-environment.json" || cleanup_failed=true
  else
    if [[ $work_a == /tmp/mithril-vm-test.* ]]; then
      rm -rf -- "$work_a" || cleanup_failed=true
    else
      cleanup_failed=true
    fi
    if [[ $work_b == /tmp/mithril-vm-test.* ]]; then
      rm -rf -- "$work_b" || cleanup_failed=true
    else
      cleanup_failed=true
    fi
    [[ ! -e $work_a ]] || cleanup_failed=true
    [[ ! -e $work_b ]] || cleanup_failed=true
  fi
  if [[ -f $output_directory/protected-start-result.json &&
        $cleanup_failed == false ]]; then
    cleanup_result_file=$output_directory/.protected-start-result.$$.json
    resources_removed=false
    [[ $keep_vms == true ]] || resources_removed=true
    jq --argjson resources_removed "$resources_removed" \
      --argjson environment_retained "$keep_vms" \
      '.repository_owned_test_resources_removed = $resources_removed |
       .repository_owned_environment_retained = $environment_retained' \
      "$output_directory/protected-start-result.json" \
      >"$cleanup_result_file" || cleanup_failed=true
    if [[ $cleanup_failed == false ]]; then
      mv -- "$cleanup_result_file" \
        "$output_directory/protected-start-result.json" || cleanup_failed=true
    fi
  fi
  cleanup_result "$original_status" "$cleanup_failed"
  local final_status=$?
  exit "$final_status"
}
trap cleanup EXIT

[[ -r $ssh_public_key ]] || {
  echo "SSH public key is not readable: $ssh_public_key" >&2
  exit 2
}

echo "Building the policy fixture tool"
(cd -- "$repo_root" && cargo build --locked -p mithril-control --bin mithril-policy)
if [[ $reuse_images == true ]]; then
  echo "Reusing the local Mithril owner images"
  docker image inspect mithril-node:convergence mithril-control:convergence >/dev/null
else
  echo "Building the packaged Mithril owners"
  (cd -- "$repo_root" && docker build --file packaging/mithril/Dockerfile \
    --target node --tag mithril-node:convergence .)
  (cd -- "$repo_root" && docker build --file packaging/mithril/Dockerfile \
    --target control --tag mithril-control:convergence .)
fi
image_archive=$work_a/mithril-images.tar
docker save --output "$image_archive" \
  mithril-node:convergence mithril-control:convergence

materials=$work_a/materials
install -d -m 700 "$materials"
ca_key=$materials/ca-key.pem
ca=$materials/ca.pem
server_key=$materials/tls.key
server_csr=$materials/server.csr
server_certificate=$materials/tls.crt
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
  -subj /CN=Mithril-Convergence-CA \
  -addext basicConstraints=critical,CA:TRUE \
  -keyout "$ca_key" -out "$ca" >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -nodes -sha256 \
  -subj /CN=mithril-control \
  -addext subjectAltName=DNS:mithril-control.$system_namespace.svc,DNS:mithril-control.$system_namespace.svc.cluster.local \
  -addext extendedKeyUsage=serverAuth \
  -keyout "$server_key" -out "$server_csr" >/dev/null 2>&1
openssl x509 -req -days 1 -sha256 -in "$server_csr" -CA "$ca" \
  -CAkey "$ca_key" -CAcreateserial -copy_extensions copy \
  -out "$server_certificate" >/dev/null 2>&1

node_ids=(mithril-node-a mithril-node-b)
node_digests=()
for node_id in "${node_ids[@]}"; do
  key=$materials/$node_id-key.pem
  csr=$materials/$node_id.csr
  certificate=$materials/$node_id.pem
  openssl req -new -newkey rsa:2048 -nodes -sha256 -subj "/CN=$node_id" \
    -addext extendedKeyUsage=clientAuth \
    -keyout "$key" -out "$csr" >/dev/null 2>&1
  openssl x509 -req -days 1 -sha256 -in "$csr" -CA "$ca" \
    -CAkey "$ca_key" -CAcreateserial -copy_extensions copy \
    -out "$certificate" >/dev/null 2>&1
  openssl x509 -in "$certificate" -outform DER -out "$materials/$node_id.der"
  node_digests+=("$(sha256sum "$materials/$node_id.der" | awk '{print $1}')")
done
chmod 600 "$materials"/*-key.pem "$server_key"

cp -- "$repo_root/crates/mithril-e2e/fixtures/mithril-policy/test-signing-key.hex" \
  "$materials/policy-signing-key"
cp -- "$repo_root/crates/mithril-e2e/fixtures/mithril-policy/test-public-key.hex" \
  "$materials/administrative-public-key.hex"
cp -- "$repo_root/crates/mithril-e2e/fixtures/mithril-policy/observe-profile-seal-request.json" \
  "$materials/profile-seal-request.json"
"$repo_root/target/debug/mithril-policy" print-trust-generation \
  --signing-key-id effect-observation-test-key \
  --public-key "$repo_root/crates/mithril-e2e/fixtures/mithril-policy/test-public-key.hex" \
  --issuer-epoch 1 --output "$materials/trust.json"

if [[ $reusing_environment == false ]]; then
  "$provider" create "$vm_a" "$work_a" "$ssh_public_key"
  created_a=true
  "$provider" create "$vm_b" "$work_b" "$ssh_public_key"
  created_b=true
else
  created_a=true
  created_b=true
fi
"$provider" wait "$vm_a"
"$provider" wait "$vm_b"
address_a=$("$provider" address "$vm_a")
address_b=$("$provider" address "$vm_b")
[[ -n $address_a && -n $address_b && $address_a != "$address_b" ]] || {
  echo "the fixture VMs do not have distinct provider addresses" >&2
  exit 1
}

remote_a=/var/tmp/$vm_a
remote_b=/var/tmp/$vm_b
for node in "$vm_a" "$vm_b"; do
  remote=$remote_a
  [[ $node == "$vm_a" ]] || remote=$remote_b
  "$provider" run "$node" mkdir -p "$remote/harness" "$remote/materials"
  "$provider" put "$node" "$directory/guest.sh" "$remote/harness/guest.sh"
  "$provider" put "$node" "$directory/runtime-hook-oracle.sh" \
    "$remote/harness/runtime-hook-oracle.sh"
  "$provider" put "$node" "$directory/k3s-config-v1.yaml" \
    "$remote/harness/k3s-config-v1.yaml"
  "$provider" put "$node" "$image_archive" "$remote/mithril-images.tar"
  "$provider" run "$node" \
    'sudo apt-get update && sudo apt-get install -y --no-install-recommends jq openssl'
done

if [[ $reusing_environment == false ]]; then
  "$provider" run "$vm_a" sudo bash "$remote_a/harness/guest.sh" \
    k3s-install "$k3s_version" "$remote_a/harness/k3s-config-v1.yaml" "$remote_a"
  node_token=$("$provider" run "$vm_a" sudo cat /var/lib/rancher/k3s/server/node-token)
  "$provider" run "$vm_b" sudo bash "$remote_b/harness/guest.sh" \
    k3s-agent-install "$k3s_version" "https://$address_a:6443" "$node_token" "$remote_b"
else
  "$provider" run "$vm_a" sudo /usr/local/bin/k3s kubectl wait \
    --for=condition=Ready "node" --all --timeout=180s >/dev/null
fi
cluster_created=true

for node in "$vm_a" "$vm_b"; do
  remote=$remote_a
  [[ $node == "$vm_a" ]] || remote=$remote_b
  "$provider" run "$node" sudo /usr/local/bin/k3s ctr images import \
    "$remote/mithril-images.tar" >/dev/null
done
"$provider" run "$vm_b" sudo bash "$remote_b/harness/guest.sh" \
  k3s-product-runtime "$remote_b"
"$provider" run "$vm_a" sudo bash "$remote_a/harness/guest.sh" \
  k3s-product-runtime "$remote_a"

nodes_json=$("$provider" run "$vm_a" sudo /usr/local/bin/k3s kubectl get nodes -o json)
node_a_name=$(jq -er --arg address "$address_a" '
  .items[] | select(any(.status.addresses[]; .type == "InternalIP" and .address == $address)) | .metadata.name
' <<<"$nodes_json")
node_b_name=$(jq -er --arg address "$address_b" '
  .items[] | select(any(.status.addresses[]; .type == "InternalIP" and .address == $address)) | .metadata.name
' <<<"$nodes_json")
[[ $node_a_name != "$node_b_name" ]] || {
  echo "the scheduler does not have two distinct Kubernetes Nodes" >&2
  exit 1
}

remote_kubectl() {
  "$provider" run "$vm_a" sudo /usr/local/bin/k3s kubectl "$@"
}

replace_retained_test_resources() {
  local node
  local path

  echo "Replacing Mithril and the protected workload in the retained K3s cluster"
  if remote_kubectl get namespace "$workload_namespace" >/dev/null 2>&1; then
    for node in "$vm_a" "$vm_b"; do
      if "$provider" run "$node" sudo test -d \
          /var/lib/mithril-convergence/markers; then
        "$provider" run "$node" sudo touch \
          /var/lib/mithril-convergence/markers/protected.exception-request \
          /var/lib/mithril-convergence/markers/protected.restart
      fi
    done
    remote_kubectl delete namespace "$workload_namespace" \
      --wait=true --timeout=180s >/dev/null
  fi
  if helm --kubeconfig "$kubeconfig" status mithril \
      --namespace "$system_namespace" >/dev/null 2>&1; then
    helm --kubeconfig "$kubeconfig" uninstall mithril \
      --namespace "$system_namespace" --wait --timeout=180s >/dev/null
  fi
  if remote_kubectl get namespace "$system_namespace" >/dev/null 2>&1; then
    remote_kubectl delete namespace "$system_namespace" \
      --wait=true --timeout=180s >/dev/null
  fi
  assert_runtime_hook removed "$vm_a" "$remote_a"
  assert_runtime_hook removed "$vm_b" "$remote_b"
  for node in "$vm_a" "$vm_b"; do
    for path in /var/lib/mithril-convergence /run/mithril \
        /sys/fs/bpf/mithril-convergence; do
      if "$provider" run "$node" sudo test -d "$path"; then
        "$provider" run "$node" sudo find "$path" -mindepth 1 -delete
      fi
    done
    "$provider" run "$node" sudo rm -f \
      /etc/mithril/node.json /etc/mithril/node.json.held
  done
  remote_kubectl label node "$node_a_name" "$node_b_name" \
    mithril.erebor.dev/ready- --overwrite >/dev/null
  remote_kubectl annotate node "$node_a_name" "$node_b_name" \
    mithril.erebor.dev/node-id- \
    mithril.erebor.dev/node-uid- \
    mithril.erebor.dev/node-boot-id- \
    mithril.erebor.dev/label-epoch- --overwrite >/dev/null
}

if [[ $reusing_environment == true ]]; then
  replace_retained_test_resources
fi

for crd in "$repo_root"/packaging/mithril/helm/crds/*.yaml; do
  crd_name=$(basename -- "$crd")
  "$provider" put "$vm_a" "$crd" "$remote_a/$crd_name"
  remote_kubectl apply --server-side --force-conflicts \
    --field-manager=mithril-convergence -f "$remote_a/$crd_name" >/dev/null
done
remote_kubectl wait --for=condition=Established \
  customresourcedefinition/workloadprotectionpolicies.mithril.erebor.dev \
  customresourcedefinition/workloadprotectionexceptions.mithril.erebor.dev \
  --timeout=120s >/dev/null

nri_hook_logs() {
  remote_kubectl -n "$system_namespace" logs \
    -l app.kubernetes.io/name=mithril-node -c runtime-hook-injector \
    --prefix=true --tail=200 --limit-bytes=131072
}

assert_nri_hook_loader_healthy() {
  local logs
  logs=$(nri_hook_logs)
  if grep -F 'level=error' <<<"$logs" >/dev/null; then
    printf '%s\n' "$logs" >&2
    echo "the stock NRI hook injector reported a loader error" >&2
    return 1
  fi
}

wait_nri_hook_injection() {
  local pod_name=$1
  local container_name=$2
  local logs
  for _attempt in {1..120}; do
    logs=$(nri_hook_logs 2>/dev/null || true)
    if grep -F "$pod_name/$container_name: OCI hooks injected" \
        <<<"$logs" >/dev/null; then
      return 0
    fi
    sleep 1
  done
  echo "the stock NRI plugin did not inject the Mithril hooks" >&2
  return 1
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
  response=$(remote_kubectl create --raw \
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

remote_kubectl label node "$node_a_name" "$node_b_name" \
  mithril.erebor.dev/pool=protected --overwrite >/dev/null

make_node_config() {
  local output=$1
  local node_id=$2
  local node_name=$3
  local source_id=$4
  jq -n --arg node_id "$node_id" --arg node_name "$node_name" \
    --arg source_id "$source_id" \
    '{
      node_id: $node_id,
      kubernetes_node_name: $node_name,
      state_directory: "/var/lib/mithril",
      interceptor: {
        runtime_btf_path: "/sys/kernel/btf/vmlinux",
        lease_path: "/var/lib/mithril/owner.lock",
        pin_root: "/sys/fs/bpf/mithril-convergence"
      },
      control: {
        endpoint: "https://mithril-control.mithril-system.svc:8443",
        server_name: "mithril-control.mithril-system.svc",
        ca_path: "/etc/mithril/identity/ca.pem",
        certificate_path: "/etc/mithril/identity/node.pem",
        private_key_path: "/etc/mithril/identity/node-key.pem",
        reconnect_minimum_ms: 100,
        reconnect_maximum_ms: 1000
      },
      evidence: {
        tenant_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        source_id: $source_id,
        maximum_record_bytes: 131072,
        maximum_retained_bytes: 16777216,
        maximum_retained_records: 10000,
        maximum_batch_records: 256,
        maximum_control_delay_ms: 100
      },
      runtime_observation: {
        socket_path: "/run/mithril/observation.sock",
        allowed_uid: 0,
        cgroup_scope: "/"
      },
      runtime_admission: {
        socket_path: "/run/mithril/runtime-admission.sock",
        maximum_request_bytes: 65536,
        timeout_ms: 4000
      },
      container_runtime: {
        socket_path: "/run/k3s/containerd/containerd.sock",
        effect_controller_cgroup_path: "/sys/fs/cgroup/mithril-placeholder",
        reconciliation_interval_ms: 100
      },
      administrative_authorization: {
        tenant_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        cluster_uid: "55555555-5555-4555-8555-555555555555",
        trust_domain_id: "22222222-2222-4222-8222-222222222222",
        issuer_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        key_id: "mithril-convergence-administrative-key-v1",
        public_key_path: "/etc/mithril/identity/administrative-public-key.hex",
        sequence_epoch: 1,
        valid_from_utc_ns: 1767225600000000000,
        valid_until_utc_ns: 1893456000000000000,
        maximum_clock_skew_ns: 300000000000
      },
      workload_bindings: [],
      policy_candidates: []
    }' >"$output"
}
make_node_config "$materials/node-a.json" "${node_ids[0]}" "$node_a_name" \
  66666666-6666-4666-8666-666666666661
make_node_config "$materials/node-b.json" "${node_ids[1]}" "$node_b_name" \
  66666666-6666-4666-8666-666666666662

jq -n \
  --arg digest_a "${node_digests[0]}" --arg digest_b "${node_digests[1]}" \
  --slurpfile trust "$materials/trust.json" \
  '{
    listen: "0.0.0.0:8443",
    tls: {
      certificate_path: "/etc/mithril/tls.crt",
      private_key_path: "/etc/mithril/tls.key",
      node_ca_path: "/etc/mithril/ca.pem"
    },
    allowed_nodes: [
      {node_id: "mithril-node-a", certificate_sha256: $digest_a, tenant_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"},
      {node_id: "mithril-node-b", certificate_sha256: $digest_b, tenant_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}
    ],
    trust: $trust[0],
    evidence_directory: "/var/lib/mithril-control/evidence",
    control_store_directory: "/var/lib/mithril-control/store",
    kubernetes_policy: {
      tenant_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      cluster_uid: "55555555-5555-4555-8555-555555555555",
      signer: {
        signing_key_id: "effect-observation-test-key",
        signing_key_path: "/etc/mithril/policy-signing-key",
        seal_request_path: "/etc/mithril/profile-seal-request.json",
        distribution_sequence_epoch: 1,
        candidate_validity_ns: 300000000000
      }
    },
    kubernetes_nodes: {
      daemon_set_namespace: "mithril-system",
      daemon_set_name: "mithril-node",
      session_ttl_seconds: 5,
      reconcile_interval_ms: 250
    },
    kubernetes_admission: {
      listen: "0.0.0.0:9443",
      tls_certificate_path: "/etc/mithril/admission-tls/tls.crt",
      tls_private_key_path: "/etc/mithril/admission-tls/tls.key",
      maximum_request_bytes: 1048576,
      request_timeout_ms: 4000
    }
  }' >"$materials/control.json"

for file in ca.pem tls.crt tls.key policy-signing-key profile-seal-request.json control.json; do
  "$provider" put "$vm_a" "$materials/$file" "$remote_a/materials/$file"
done
for index in 0 1; do
  node=$vm_a
  remote=$remote_a
  label=a
  [[ $index -eq 0 ]] || { node=$vm_b; remote=$remote_b; label=b; }
  "$provider" put "$node" "$ca" "$remote/materials/ca.pem"
  "$provider" put "$node" "$materials/${node_ids[$index]}.pem" \
    "$remote/materials/node.pem"
  "$provider" put "$node" "$materials/${node_ids[$index]}-key.pem" \
    "$remote/materials/node-key.pem"
  "$provider" put "$node" "$materials/administrative-public-key.hex" \
    "$remote/materials/administrative-public-key.hex"
  "$provider" put "$node" "$materials/node-$label.json" \
    "$remote/materials/node.json"
  "$provider" run "$node" \
    "sudo install -d -m 0700 /etc/mithril/identity /var/lib/mithril-convergence/markers /run/mithril && \
     sudo install -m 0444 '$remote/materials/ca.pem' /etc/mithril/identity/ca.pem && \
     sudo install -m 0444 '$remote/materials/node.pem' /etc/mithril/identity/node.pem && \
     sudo install -m 0400 '$remote/materials/node-key.pem' /etc/mithril/identity/node-key.pem && \
     sudo install -m 0444 '$remote/materials/administrative-public-key.hex' /etc/mithril/identity/administrative-public-key.hex"
done

remote_kubectl create namespace "$system_namespace" >/dev/null
remote_kubectl -n "$system_namespace" create secret generic mithril-control-config \
  --from-file=control.json="$remote_a/materials/control.json" \
  --from-file=policy-signing-key="$remote_a/materials/policy-signing-key" \
  --from-file=profile-seal-request.json="$remote_a/materials/profile-seal-request.json" \
  --from-file=ca.pem="$remote_a/materials/ca.pem" \
  --from-file=tls.crt="$remote_a/materials/tls.crt" \
  --from-file=tls.key="$remote_a/materials/tls.key" >/dev/null
remote_kubectl -n "$system_namespace" create secret tls mithril-admission-tls \
  --cert="$remote_a/materials/tls.crt" --key="$remote_a/materials/tls.key" >/dev/null

pvc=$work_a/control-pvc.yaml
cat >"$pvc" <<EOF
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: mithril-control-state
  namespace: $system_namespace
spec:
  accessModes: [ReadWriteOnce]
  resources:
    requests:
      storage: 1Gi
EOF
"$provider" put "$vm_a" "$pvc" "$remote_a/control-pvc.yaml"
remote_kubectl apply --server-side --validate=strict \
  -f "$remote_a/control-pvc.yaml" >/dev/null

"$provider" run "$vm_a" sudo cp /etc/rancher/k3s/k3s.yaml "$remote_a/kubeconfig.yaml"
"$provider" run "$vm_a" sudo chown ubuntu:ubuntu "$remote_a/kubeconfig.yaml"
"$provider" get "$vm_a" "$remote_a/kubeconfig.yaml" "$kubeconfig"
sed -i "s|https://127.0.0.1:6443|https://$address_a:6443|" "$kubeconfig"
ca_bundle=$(base64 -w0 "$ca")
values=$work_a/values.yaml
cat >"$values" <<EOF
node:
  image: mithril-node:convergence
  imagePullPolicy: Never
  configHostPath: /etc/mithril/node.json
  identityHostPath: /etc/mithril/identity
  stateHostPath: /var/lib/mithril-convergence
  runHostPath: /run/mithril
  containerRuntimeSocket: /run/k3s/containerd/containerd.sock
  nodeSelector:
    mithril.erebor.dev/pool: protected
  affinity:
    nodeAffinity:
      requiredDuringSchedulingIgnoredDuringExecution:
        nodeSelectorTerms:
          - matchExpressions:
              - key: kubernetes.io/arch
                operator: In
                values: [amd64]
  runtimeHook:
    install: true
    hostBinaryDirectory: /usr/libexec/oci/hooks.d
    hostConfigDirectory: /usr/share/containers/oci/hooks.d
    socketPath: /run/mithril/runtime-admission.sock
    timeoutMs: 4000
    runtimeTimeoutSeconds: 5
control:
  enabled: true
  image: mithril-control:convergence
  imagePullPolicy: Never
  configSecretName: mithril-control-config
  statePersistentVolumeClaim: mithril-control-state
  grpcPort: 8443
  # Keep the durable Control owner available while the worker Node UID changes.
  nodeSelector:
    kubernetes.io/hostname: $node_a_name
  admission:
    enabled: true
    port: 9443
    tlsSecretName: mithril-admission-tls
    caBundle: $ca_bundle
    webhookTimeoutSeconds: 5
EOF
helm --kubeconfig "$kubeconfig" upgrade --install mithril \
  "$repo_root/packaging/mithril/helm" --namespace "$system_namespace" \
  --values "$values"
remote_kubectl -n "$system_namespace" rollout status deployment/mithril-control \
  --timeout=300s >/dev/null

wait_node_projection() {
  local node_name=$1
  local ready=$2
  local quarantined=$3
  local node_json
  for _attempt in {1..300}; do
    node_json=$(remote_kubectl get node "$node_name" -o json 2>/dev/null || true)
    if [[ -n $node_json ]] && jq -e \
      --arg ready "$ready" --argjson quarantined "$quarantined" '
        ((.metadata.labels["mithril.erebor.dev/ready"] // "") == $ready) and
        ([.spec.taints[]? | select(.key == "mithril.erebor.dev/not-ready" and .effect == "NoSchedule")] | length > 0) == $quarantined
      ' <<<"$node_json" >/dev/null; then
      return 0
    fi
    sleep 1
  done
  echo "Node $node_name did not reach ready=$ready quarantined=$quarantined" >&2
  return 1
}

assert_ready_projection_stable() {
  local node_name=$1
  local node_json
  # Hold beyond the configured five-second session TTL to reject transient readiness.
  for _attempt in {1..7}; do
    node_json=$(remote_kubectl get node "$node_name" -o json)
    jq -e '
      .metadata.labels["mithril.erebor.dev/ready"] == "true" and
      (.metadata.annotations["mithril.erebor.dev/node-id"] | length > 0) and
      .metadata.annotations["mithril.erebor.dev/node-uid"] == .metadata.uid and
      (.metadata.annotations["mithril.erebor.dev/node-boot-id"] |
        test("^[0-9a-f]{32}$")) and
      (.metadata.annotations["mithril.erebor.dev/label-epoch"] | tonumber) > 0 and
      all(.spec.taints[]?;
        .key != "mithril.erebor.dev/not-ready" or .effect != "NoSchedule")
    ' <<<"$node_json" >/dev/null
    sleep 1
  done
}

wait_replaced_node_uid() {
  local node_name=$1
  local old_uid=$2
  local node_json
  for _attempt in {1..300}; do
    node_json=$(remote_kubectl get node "$node_name" -o json 2>/dev/null || true)
    if [[ -n $node_json ]] && jq -e --arg old_uid "$old_uid" '
      .metadata.uid != $old_uid and
      (.metadata.labels["mithril.erebor.dev/ready"] // "") == "" and
      all(.spec.taints[]?;
        .key != "mithril.erebor.dev/not-ready" or .effect != "NoSchedule")
    ' <<<"$node_json" >/dev/null; then
      return 0
    fi
    sleep 1
  done
  echo "Node $node_name did not reappear without inherited Mithril state" >&2
  return 1
}

wait_node_epoch_advance() {
  local node_name=$1
  local old_boot_id=$2
  local old_label_epoch=$3
  local node_json
  for _attempt in {1..300}; do
    node_json=$(remote_kubectl get node "$node_name" -o json 2>/dev/null || true)
    if [[ -n $node_json ]] && jq -e \
      --arg old_boot_id "$old_boot_id" --argjson old_label_epoch "$old_label_epoch" '
        .metadata.annotations["mithril.erebor.dev/node-boot-id"] != $old_boot_id and
        (.metadata.annotations["mithril.erebor.dev/label-epoch"] | tonumber) >
          $old_label_epoch and
        .metadata.labels["mithril.erebor.dev/ready"] == "true" and
        all(.spec.taints[]?;
          .key != "mithril.erebor.dev/not-ready" or .effect != "NoSchedule")
      ' <<<"$node_json" >/dev/null; then
      return 0
    fi
    sleep 1
  done
  echo "Node $node_name did not register a new ready physical epoch" >&2
  return 1
}

# Config is withheld until Control proves that matching Nodes begin quarantined.
wait_node_projection "$node_a_name" "" true
wait_node_projection "$node_b_name" "" true
for index in 0 1; do
  node=$vm_a
  remote=$remote_a
  [[ $index -eq 0 ]] || { node=$vm_b; remote=$remote_b; }
  "$provider" run "$node" sudo install -m 0400 \
    "$remote/materials/node.json" /etc/mithril/node.json
done
remote_kubectl -n "$system_namespace" rollout status daemonset/mithril-node \
  --timeout=300s >/dev/null
wait_node_projection "$node_a_name" true false
wait_node_projection "$node_b_name" true false
assert_runtime_hook installed "$vm_a" "$remote_a"
assert_runtime_hook installed "$vm_b" "$remote_b"
assert_nri_hook_loader_healthy

if [[ $protected_start_only == false ]]; then
  # The full suite proves Node UID replacement. The focused startup lane keeps
  # the retained Kubernetes Nodes stable and replaces only product resources.
  old_node_b_uid=$(remote_kubectl get node "$node_b_name" -o jsonpath='{.metadata.uid}')
  "$provider" run "$vm_b" sudo mv \
    /etc/mithril/node.json /etc/mithril/node.json.held
  node_b_pod=$(remote_kubectl -n "$system_namespace" get pods \
    -l app.kubernetes.io/name=mithril-node \
    --field-selector "spec.nodeName=$node_b_name" \
    -o jsonpath='{.items[0].metadata.name}')
  remote_kubectl -n "$system_namespace" delete pod "$node_b_pod" \
    --wait=true --timeout=120s >/dev/null
  wait_node_projection "$node_b_name" "" true
  remote_kubectl delete node "$node_b_name" --wait=true --timeout=120s >/dev/null
  # Kubelet recreates the Node object only after its process restarts.
  "$provider" run "$vm_b" sudo systemctl restart k3s-agent
  wait_replaced_node_uid "$node_b_name" "$old_node_b_uid"
  remote_kubectl label node "$node_b_name" \
    mithril.erebor.dev/pool=protected --overwrite >/dev/null
  wait_node_projection "$node_b_name" "" true
  "$provider" run "$vm_b" sudo mv \
    /etc/mithril/node.json.held /etc/mithril/node.json
  remote_kubectl -n "$system_namespace" rollout status daemonset/mithril-node \
    --timeout=300s >/dev/null
  wait_node_projection "$node_b_name" true false
  assert_ready_projection_stable "$node_b_name"
fi

if [[ $manual_environment == true ]]; then
  manual_env=$work_a/mithril-convergence-manual.env
  # K3s dispatches kubectl by executable name in the operator shell.
  "$provider" run "$vm_a" sudo ln -s /usr/local/bin/k3s /usr/local/bin/kubectl
  {
    printf 'MITHRIL_MANUAL_SOURCE=%q\n' /mnt/mithril-source
    printf 'MITHRIL_BIN_DIRECTORY=%q\n' /mnt/mithril-source/target/debug
    printf 'MITHRIL_SYSTEM_NAMESPACE=%q\n' "$system_namespace"
  } >"$manual_env"
  "$provider" put "$vm_a" "$manual_env" "$remote_a/mithril-convergence-manual.env"
  "$provider" run "$vm_a" sudo install -m 0444 \
    "$remote_a/mithril-convergence-manual.env" \
    /var/tmp/mithril-convergence-manual.env
  echo "Two-node manual environment ready."
  exit 0
fi

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

"$provider" put "$vm_a" \
  "$repo_root/crates/mithril-e2e/fixtures/convergence/runtime-classes-v1.yaml" \
  "$remote_a/runtime-classes-v1.yaml"
remote_kubectl apply --server-side --validate=strict \
  -f "$remote_a/runtime-classes-v1.yaml" >/dev/null
remote_kubectl create namespace "$workload_namespace" >/dev/null
remote_kubectl -n "$workload_namespace" create serviceaccount converter >/dev/null
remote_kubectl -n "$workload_namespace" create serviceaccount policy-writer >/dev/null
remote_kubectl -n "$workload_namespace" create serviceaccount exception-writer >/dev/null
remote_kubectl -n "$workload_namespace" create rolebinding policy-writer \
  --clusterrole=mithril-policy-writer \
  --serviceaccount="$workload_namespace:policy-writer" >/dev/null
remote_kubectl -n "$workload_namespace" create rolebinding exception-writer \
  --clusterrole=mithril-exception-writer \
  --serviceaccount="$workload_namespace:exception-writer" >/dev/null
policy_subject=system:serviceaccount:$workload_namespace:policy-writer
exception_subject=system:serviceaccount:$workload_namespace:exception-writer
assert_cluster_access true "$policy_subject" create mithril.erebor.dev \
  workloadprotectionpolicies "" "$workload_namespace"
assert_cluster_access false "$policy_subject" create mithril.erebor.dev \
  workloadprotectionexceptions "" "$workload_namespace"
assert_cluster_access true "$exception_subject" create mithril.erebor.dev \
  workloadprotectionexceptions "" "$workload_namespace"
assert_cluster_access false "$exception_subject" create mithril.erebor.dev \
  workloadprotectionpolicies "" "$workload_namespace"

make_policy_manifest() {
  local version=$1
  local duration=$((6 - version))m
  local manifest=$work_a/policy-v$version.yaml
  sed \
    -e "s/MITHRIL_CONVERGENCE_NAMESPACE/$workload_namespace/g" \
    -e "s/maximumDuration: 5m/maximumDuration: $duration/" \
    "$repo_root/crates/mithril-e2e/fixtures/convergence/policy-v1.yaml" >"$manifest"
  "$provider" put "$vm_a" "$manifest" "$remote_a/policy-v$version.yaml"
}

wait_policy_compiled() {
  for _attempt in {1..300}; do
    policy_json=$(remote_kubectl -n "$workload_namespace" get \
      workloadprotectionpolicy converter-policy -o json 2>/dev/null || true)
    if [[ -n $policy_json ]] && jq -e '
      .status.observedGeneration == .metadata.generation and
      any(.status.conditions[]?; .type == "Accepted" and .status == "True") and
      any(.status.conditions[]?; .type == "Compiled" and .status == "True")
    ' <<<"$policy_json" >/dev/null; then
      return 0
    fi
    sleep 1
  done
  echo "the policy did not reach accepted and compiled state" >&2
  return 1
}

wait_exception_state() {
  local name=$1
  local expected=$2
  local resource
  for _attempt in {1..300}; do
    resource=$(remote_kubectl -n "$workload_namespace" get \
      workloadprotectionexception "$name" -o json 2>/dev/null || true)
    if [[ -n $resource ]] && jq -e --arg expected "$expected" '
      .status.observedGeneration == .metadata.generation and
      .status.state == $expected
    ' <<<"$resource" >/dev/null; then
      return 0
    fi
    sleep 1
  done
  echo "exception $name did not reach $expected" >&2
  return 1
}

make_policy_manifest 1
remote_kubectl --as="$policy_subject" apply --server-side --validate=strict \
  -f "$remote_a/policy-v1.yaml" >/dev/null
wait_policy_compiled
profile_id=$(remote_kubectl -n "$workload_namespace" get \
  workloadprotectionpolicy converter-policy -o jsonpath='{.metadata.uid}')
remote_kubectl -n "$workload_namespace" get workloadprotectionpolicy converter-policy \
  -o json | jq -e '
    (.status | keys) == ["conditions", "observedGeneration", "rollout"] and
    all(.status.conditions[];
      (keys) == ["lastTransitionTime", "message", "observedGeneration", "reason", "status", "type"])
  ' >/dev/null

render_pod() {
  local pod=$1
  local runtime_class=$2
  local output=$work_a/$pod.yaml
  sed \
    -e "s/MITHRIL_CONVERGENCE_NAMESPACE/$workload_namespace/g" \
    -e "s/MITHRIL_CONVERGENCE_POD/$pod/g" \
    -e "s/MITHRIL_CONVERGENCE_RUNTIME_CLASS/$runtime_class/g" \
    "$repo_root/crates/mithril-e2e/fixtures/convergence/protected-pod-v1.yaml" \
    >"$output"
  "$provider" put "$vm_a" "$output" "$remote_a/$pod.yaml"
}
render_pod protected mithril
render_pod gate-failure mithril-fail
render_pod entry-roles mithril

unprotected=$work_a/unprotected.yaml
sed "s/MITHRIL_CONVERGENCE_NAMESPACE/$workload_namespace/g" \
  "$repo_root/crates/mithril-e2e/fixtures/convergence/unprotected-pod-v1.yaml" \
  >"$unprotected"
"$provider" put "$vm_a" "$unprotected" "$remote_a/unprotected.yaml"
unprotected_json=$(remote_kubectl create --dry-run=server \
  -f "$remote_a/unprotected.yaml" -o json)
jq -e '
  (.metadata.annotations["mithril.erebor.dev/profile-id"] // "") == "" and
  (.spec.nodeName // "") == ""
' <<<"$unprotected_json" >/dev/null

protected_dry_run=$(remote_kubectl create --dry-run=server \
  -f "$remote_a/protected.yaml" -o json)
jq -e --arg profile_id "$profile_id" '
  .metadata.annotations["mithril.erebor.dev/profile-id"] == $profile_id and
  (.metadata.annotations["mithril.erebor.dev/policy-source-revision"] | length) == 64 and
  (.spec.nodeName // "") == "" and
  .spec.nodeSelector["mithril.erebor.dev/pool"] == "protected" and
  .spec.nodeSelector["mithril.erebor.dev/ready"] == "true" and
  any(.spec.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[].matchExpressions[]?;
      .key == "kubernetes.io/arch" and .operator == "In" and .values == ["amd64"])
' <<<"$protected_dry_run" >/dev/null

bypass=$work_a/bypass.json
protected_input=$(remote_kubectl create --dry-run=client \
  -f "$remote_a/protected.yaml" -o json)
jq --arg node "$node_a_name" '.spec.nodeName = $node' \
  <<<"$protected_input" >"$bypass"
"$provider" put "$vm_a" "$bypass" "$remote_a/bypass.json"
assert_mithril_node_name_denial remote_kubectl create \
  -f "$remote_a/bypass.json"

node_status() {
  local node_name=$1
  local pod
  pod=$(remote_kubectl -n "$system_namespace" get pods \
    -l app.kubernetes.io/name=mithril-node \
    --field-selector "spec.nodeName=$node_name" \
    -o jsonpath='{.items[0].metadata.name}')
  remote_kubectl -n "$system_namespace" exec -c mithril-node "$pod" -- \
    mithril-inspect policy-delivery --state-directory /var/lib/mithril
}

assert_live_exact_target() {
  local node_name=$1
  local profile=$2
  local operation=$3
  local predecessor=${4:-}
  local status_json
  local node_json
  local pod_json
  status_json=$(node_status "$node_name")
  node_json=$(remote_kubectl get node "$node_name" -o json)
  pod_json=$(remote_kubectl -n "$workload_namespace" get pod protected -o json)
  assert_exact_policy_target "$status_json" "$node_json" "$pod_json" \
    "$profile" converter "$operation" "$predecessor"
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

runtime_task_snapshot() {
  local node_name=$1
  local host_pid=$2
  local pod
  pod=$(remote_kubectl -n "$system_namespace" get pods \
    -l app.kubernetes.io/name=mithril-node \
    --field-selector "spec.nodeName=$node_name" \
    -o jsonpath='{.items[0].metadata.name}')
  remote_kubectl -n "$system_namespace" exec -c mithril-node "$pod" -- \
    mithril-inspect --pin-root /sys/fs/bpf/mithril-convergence \
      task --host-pid "$host_pid"
}

node_effects() {
  local node_name=$1
  local pod
  pod=$(remote_kubectl -n "$system_namespace" get pods \
    -l app.kubernetes.io/name=mithril-node \
    --field-selector "spec.nodeName=$node_name" \
    -o jsonpath='{.items[0].metadata.name}')
  remote_kubectl -n "$system_namespace" exec -c mithril-node "$pod" -- \
    mithril-inspect effects --socket-path /run/mithril/observation.sock \
      --cgroup-scope /
}

start_entry_effect_capture() {
  local node_name=$1
  local output=$2
  local pod
  pod=$(remote_kubectl -n "$system_namespace" get pods \
    -l app.kubernetes.io/name=mithril-node \
    --field-selector "spec.nodeName=$node_name" \
    -o jsonpath='{.items[0].metadata.name}')
  remote_kubectl -n "$system_namespace" exec -c mithril-node "$pod" -- \
    mithril-inspect effects --socket-path /run/mithril/observation.sock \
      --cgroup-scope / --samples 6000 --sample-interval-ms 10 \
      >"$output" 2>/dev/null &
  entry_effect_capture_pids+=("$!")
}

prepare_pod_markers() {
  local pod_name=$1
  local node
  local marker_root=/var/lib/mithril-convergence/markers
  for node in "$vm_a" "$vm_b"; do
    "$provider" run "$node" sudo rm -f \
      "$marker_root/$pod_name.started" \
      "$marker_root/$pod_name.restart" \
      "$marker_root/$pod_name.prepared-result" \
      "$marker_root/$pod_name.exception-request" \
      "$marker_root/$pod_name.exception-result" \
      "$marker_root/$pod_name.poststart-observed" \
      "$marker_root/$pod_name.prestop-observed"
    "$provider" run "$node" sudo touch \
      "$marker_root/$pod_name.exception-target"
    "$provider" run "$node" \
      "printf '%s\\n' READY | sudo tee '$marker_root/$pod_name.lifecycle-ready' >/dev/null"
  done
}

admitted_entry_counts() {
  awk '
    /^observed_boottime_ns=/ && / reason=APPLICATION_DEFAULT_ALLOW / {
      role = 0
      admission = 0
      for (field_index = 1; field_index <= NF; field_index++) {
        split($field_index, field, "=")
        if (field[1] == "active_role_id") {
          role = field[2]
        } else if (field[1] == "admitted_entry_rule_id") {
          admission = field[2]
        }
      }
      if (role > 0 && admission > 0) {
        roles[role] = 1
        admissions[admission] = 1
        pairs[role ":" admission] = 1
      }
    }
    END {
      for (role_key in roles) role_count++
      for (admission_key in admissions) admission_count++
      for (pair_key in pairs) pair_count++
      print role_count + 0, admission_count + 0, pair_count + 0
    }
  '
}

prepare_pod_markers entry-roles
entry_role_capture_a=$output_directory/declared-entry-role-capture-node-a.txt
entry_role_capture_b=$output_directory/declared-entry-role-capture-node-b.txt
start_entry_effect_capture "$node_a_name" "$entry_role_capture_a"
start_entry_effect_capture "$node_b_name" "$entry_role_capture_b"
sleep 1
remote_kubectl create -f "$remote_a/entry-roles.yaml" >/dev/null
remote_kubectl -n "$workload_namespace" wait \
  --for=condition=Ready pod/entry-roles --timeout=300s >/dev/null
wait_nri_hook_injection entry-roles converter
entry_roles_node=$(remote_kubectl -n "$workload_namespace" get pod entry-roles \
  -o jsonpath='{.spec.nodeName}')
[[ $entry_roles_node == "$node_a_name" || $entry_roles_node == "$node_b_name" ]] || {
  echo "the entry-role Pod scheduled outside the protected Node set" >&2
  exit 1
}
entry_roles_vm=$vm_a
entry_roles_other_vm=$vm_b
if [[ $entry_roles_node == "$node_b_name" ]]; then
  entry_roles_vm=$vm_b
  entry_roles_other_vm=$vm_a
fi
"$provider" run "$entry_roles_vm" sudo cmp -s \
  /var/lib/mithril-convergence/markers/entry-roles.lifecycle-ready \
  /var/lib/mithril-convergence/markers/entry-roles.poststart-observed
"$provider" run "$entry_roles_other_vm" sudo test ! -e \
  /var/lib/mithril-convergence/markers/entry-roles.poststart-observed
sleep 0.1
stop_entry_effect_capture

entry_role_capture=$entry_role_capture_a
if [[ $entry_roles_node == "$node_b_name" ]]; then
  entry_role_capture=$entry_role_capture_b
fi

entry_role_effects_before=
for _attempt in {1..120}; do
  entry_role_effects_before=$(printf '%s\n%s\n' \
    "$(<"$entry_role_capture")" "$(node_effects "$entry_roles_node")")
  read -r entry_role_count entry_admission_count entry_pair_count \
    <<<"$(admitted_entry_counts <<<"$entry_role_effects_before")"
  if [[ $entry_role_count -eq 5 && $entry_admission_count -eq 5 &&
        $entry_pair_count -eq 5 ]]; then
    break
  fi
  [[ $_attempt -lt 120 ]] || {
    echo "the application, PostStart, and probe entries did not install five independent roles" >&2
    exit 1
  }
  sleep 1
done

entry_prestop_capture=$output_directory/declared-entry-role-capture-prestop.txt
start_entry_effect_capture "$entry_roles_node" "$entry_prestop_capture"
sleep 0.1
remote_kubectl -n "$workload_namespace" delete pod entry-roles \
  --wait=true --timeout=120s >/dev/null
sleep 0.1
stop_entry_effect_capture
"$provider" run "$entry_roles_vm" sudo cmp -s \
  /var/lib/mithril-convergence/markers/entry-roles.lifecycle-ready \
  /var/lib/mithril-convergence/markers/entry-roles.prestop-observed
"$provider" run "$entry_roles_other_vm" sudo test ! -e \
  /var/lib/mithril-convergence/markers/entry-roles.prestop-observed

entry_role_effects=
for _attempt in {1..120}; do
  entry_role_effects_after=$(node_effects "$entry_roles_node" 2>/dev/null || true)
  entry_role_effects=$(printf '%s\n%s\n%s\n' \
    "$entry_role_effects_before" "$(<"$entry_prestop_capture")" \
    "$entry_role_effects_after")
  read -r entry_role_count entry_admission_count entry_pair_count \
    <<<"$(admitted_entry_counts <<<"$entry_role_effects")"
  if [[ $entry_role_count -eq 6 && $entry_admission_count -eq 6 &&
        $entry_pair_count -eq 6 ]]; then
    break
  fi
  [[ $_attempt -lt 120 ]] || {
    echo "PreStop did not install its independent admitted role" >&2
    exit 1
  }
  sleep 0.25
done
printf '%s\n' "$entry_role_effects" \
  >"$output_directory/declared-entry-role-effects.txt"
install -m 0600 "$work_a/entry-roles.yaml" \
  "$output_directory/declared-entry-role-pod.yaml"
install -m 0600 "$work_a/policy-v1.yaml" \
  "$output_directory/declared-entry-role-policy.yaml"
wait_policy_delivery_empty "$entry_roles_node"

# Both possible scheduler targets receive the same inert files, not policy authority.
prepare_pod_markers protected
remote_kubectl create -f "$remote_a/protected.yaml" >/dev/null
remote_kubectl -n "$workload_namespace" wait --for=condition=Ready pod/protected \
  --timeout=300s >/dev/null
wait_nri_hook_injection protected converter
selected_node=$(remote_kubectl -n "$workload_namespace" get pod protected \
  -o jsonpath='{.spec.nodeName}')
[[ $selected_node == "$node_a_name" || $selected_node == "$node_b_name" ]] || {
  echo "the scheduler selected a Node outside the DaemonSet-derived set" >&2
  exit 1
}
other_node=$node_a_name
[[ $selected_node == "$node_b_name" ]] || other_node=$node_b_name

assert_prepared_container_activation() {
  local task_json=$1
  local runtime_binding_id=$2
  jq -e --arg runtime_binding_id "$runtime_binding_id" '
    .runtime_binding.binding_id == ($runtime_binding_id | gsub("-"; "")) and
    .runtime_binding.root_cgroup_id > 0 and
    .runtime_binding.prepared_container_state == "active" and
    .runtime_binding.prepared_container_entry_instance_id != "00000000000000000000000000000000" and
    .entry_instance_id == .runtime_binding.prepared_container_entry_instance_id and
    .runtime_binding.prepared_container_exec_task_cookie == 0 and
    .runtime_binding.prepared_container_initial_host_tgid == .host_tgid and
    .root_class == "initial_container_root" and
    .installed_role_class == "initial_role"
  ' <<<"$task_json" >/dev/null
}

wait_runtime_delivery() {
  local node_name=$1
  local profile=$2
  local status_json
  for _attempt in {1..180}; do
    status_json=$(node_status "$node_name" 2>/dev/null || true)
    if [[ -n $status_json ]] && jq -e --arg profile_id "$profile" '
      .active_candidate_content_id != null and
      .active_profile_ids == [$profile_id] and
      .scheduled_binding_count == 0 and
      .runtime_binding_count == 1 and
      .activation_pending == false and
      .control_acknowledged == true
    ' <<<"$status_json" >/dev/null; then
      printf '%s\n' "$status_json"
      return 0
    fi
    sleep 1
  done
  echo "selected-node runtime delivery did not converge: $status_json" >&2
  return 1
}

selected_status=$(wait_runtime_delivery "$selected_node" "$profile_id")
other_status=$(node_status "$other_node")
assert_live_exact_target "$selected_node" "$profile_id" ACTIVATE
runtime_binding_before=$(jq -er '.active_targets[0].runtime_binding_id' \
  <<<"$selected_status")
jq -e '
  .active_candidate_content_id == null and
  .active_profile_ids == [] and
  .scheduled_binding_count == 0 and
  .runtime_binding_count == 0
' <<<"$other_status" >/dev/null

if [[ $selected_node == "$node_a_name" ]]; then
  selected_vm=$vm_a
  other_vm=$vm_b
else
  selected_vm=$vm_b
  other_vm=$vm_a
fi
container_before=$(remote_kubectl -n "$workload_namespace" get pod protected \
  -o jsonpath='{.status.containerStatuses[0].containerID}')
container_before_id=${container_before#containerd://}
container_before_json=$("$provider" run "$selected_vm" sudo \
  /usr/local/bin/k3s crictl inspect "$container_before_id")
host_pid_before=$(jq -er '.info.pid' <<<"$container_before_json")
task_before=$(runtime_task_snapshot "$selected_node" "$host_pid_before")
task_cookie_before=$(jq -er '.task_cookie' <<<"$task_before")
assert_prepared_container_activation "$task_before" "$runtime_binding_before"
"$provider" run "$selected_vm" sudo test -e \
  /var/lib/mithril-convergence/markers/protected.started
"$provider" run "$other_vm" sudo test ! -e \
  /var/lib/mithril-convergence/markers/protected.started
for _attempt in {1..120}; do
  prepared_result=$("$provider" run "$selected_vm" sudo cat \
    /var/lib/mithril-convergence/markers/protected.prepared-result \
    2>/dev/null || true)
  [[ $prepared_result == APPLICATION_DEFAULT_ALLOWED ]] && break
  [[ $_attempt -lt 120 ]] || {
    echo "the activated application did not receive its default authority" >&2
    exit 1
  }
  sleep 1
done
"$provider" run "$other_vm" sudo test ! -e \
  /var/lib/mithril-convergence/markers/protected.prepared-result

for _attempt in {1..120}; do
  base_result=$("$provider" run "$selected_vm" sudo cat \
    /var/lib/mithril-convergence/markers/protected.exception-result 2>/dev/null || true)
  [[ $base_result == BASE_DENIED ]] && break
  [[ $_attempt -lt 120 ]] || {
    echo "the base policy did not deny the exception target" >&2
    exit 1
  }
  sleep 1
done

application_effects=$(node_effects "$selected_node")
printf '%s\n' "$application_effects" \
  >"$output_directory/application-effects.txt"
awk '
  /^observed_boottime_ns=/ &&
  / family=1 operation=1 / &&
  / reason=APPLICATION_DEFAULT_ALLOW / &&
  / exact_object_key_id=0 composite_atom_id=0 / { found = 1 }
  END { exit !found }
' <<<"$application_effects" || {
  echo "a later application exec did not receive default authority" >&2
  exit 1
}
application_exec_default_allowed=true
effect_marker=$(awk '
  /^observed_boottime_ns=/ {
    split($1, field, "=")
    if (field[2] > marker) {
      marker = field[2]
    }
  }
  END { print marker + 0 }
' <<<"$application_effects")

external_marker=/var/lib/mithril-convergence/markers/protected.external-entry
"$provider" run "$selected_vm" sudo rm -f "$external_marker"
"$provider" run "$other_vm" sudo rm -f "$external_marker"
if "$provider" run "$selected_vm" sudo /usr/local/bin/k3s crictl exec \
    "$container_before_id" /bin/touch "$external_marker" \
    >"$output_directory/external-cgroup-entry.out" 2>&1; then
  external_status=0
else
  external_status=$?
fi
[[ $external_status -ne 0 ]] || {
  echo "an external process entered the protected container" >&2
  exit 1
}
"$provider" run "$selected_vm" sudo test ! -e "$external_marker"
"$provider" run "$other_vm" sudo test ! -e "$external_marker"

external_cgroup_entry_denied=false
for _attempt in {1..40}; do
  external_effects=$(node_effects "$selected_node")
  if awk -v marker="$effect_marker" '
      /^observed_boottime_ns=/ {
        split($1, field, "=")
        if (field[2] > marker &&
            $0 ~ / family=1 operation=1 / &&
            $0 ~ / reason=UNSUPPORTED_OBJECT / &&
            $0 ~ / result=DENIED_BEFORE_EFFECT / &&
            $0 ~ / kernel_result=-13$/) {
          found = 1
        }
      }
      END { exit !found }
    ' <<<"$external_effects"; then
    external_cgroup_entry_denied=true
    break
  fi
  sleep 0.25
done
printf '%s\n' "$external_effects" \
  >"$output_directory/external-cgroup-entry-effects.txt"
[[ $external_cgroup_entry_denied == true ]] || {
  echo "the external cgroup entry did not produce a denied exec effect" >&2
  exit 1
}

protected_uid=$(remote_kubectl -n "$workload_namespace" get pod protected \
  -o jsonpath='{.metadata.uid}')
if [[ $protected_start_only == true ]]; then
  kubernetes_version=$(remote_kubectl version -o json | jq -er \
    '.serverVersion.gitVersion')
  container_runtime_version=$(remote_kubectl get node "$selected_node" \
    -o jsonpath='{.status.nodeInfo.containerRuntimeVersion}')
  policy_source_revision=$(remote_kubectl -n "$workload_namespace" get pod protected \
    -o json | jq -er \
    '.metadata.annotations["mithril.erebor.dev/policy-source-revision"]')
  prepared_state=$(jq -er '.runtime_binding.prepared_container_state' \
    <<<"$task_before")
  admitted_entry_instance_id=$(jq -er '.entry_instance_id' <<<"$task_before")
  jq -n \
    --arg kubernetes_version "$kubernetes_version" \
    --arg container_runtime_version "$container_runtime_version" \
    --arg namespace "$workload_namespace" \
    --arg pod_name protected \
    --arg pod_uid "$protected_uid" \
    --arg container_id "$container_before" \
    --arg selected_node "$selected_node" \
    --arg profile_id "$profile_id" \
    --arg policy_source_revision "$policy_source_revision" \
    --arg runtime_binding_id "$runtime_binding_before" \
    --arg task_cookie "$task_cookie_before" \
    --arg prepared_state "$prepared_state" \
    --arg admitted_entry_instance_id "$admitted_entry_instance_id" \
    --arg application_default_marker "$prepared_result" \
    --arg explicit_deny_marker "$base_result" \
    --argjson later_busybox_applet_exec_default_allowed \
      "$application_exec_default_allowed" \
    --argjson external_cgroup_entry_denied \
      "$external_cgroup_entry_denied" \
    --argjson declared_entry_role_count "$entry_role_count" \
    '{
      schema_version: 1,
      kubernetes_version: $kubernetes_version,
      container_runtime_version: $container_runtime_version,
      namespace: $namespace,
      pod_name: $pod_name,
      pod_uid: $pod_uid,
      container_id: $container_id,
      selected_node: $selected_node,
      profile_id: $profile_id,
      policy_source_revision: $policy_source_revision,
      runtime_binding_id: $runtime_binding_id,
      task_cookie: $task_cookie,
      prepared_state: $prepared_state,
      admitted_entry_instance_id: $admitted_entry_instance_id,
      application_default_allowed: ($application_default_marker == "APPLICATION_DEFAULT_ALLOWED"),
      later_busybox_applet_exec_default_allowed: $later_busybox_applet_exec_default_allowed,
      explicit_matching_deny_observed: ($explicit_deny_marker == "BASE_DENIED"),
      external_cgroup_entry_denied: $external_cgroup_entry_denied,
      poststart_entry_allowed: true,
      prestop_entry_allowed: true,
      startup_probe_entry_allowed: true,
      readiness_probe_entry_allowed: true,
      liveness_probe_entry_allowed: true,
      declared_entry_roles_independent: ($declared_entry_role_count == 6),
      declared_entry_role_count: $declared_entry_role_count,
      repository_owned_test_resources_removed: false
    }' >"$output_directory/protected-start-result.json"
  install -m 0600 "$kubeconfig" "$output_directory/kubeconfig.yaml"
  echo "Protected Kubernetes application startup passed. Evidence: $output_directory"
  exit 0
fi
exception=$work_a/exception-v1.yaml
sed \
  -e "s/MITHRIL_CONVERGENCE_NAMESPACE/$workload_namespace/g" \
  -e "s/MITHRIL_CONVERGENCE_POD_UID/$protected_uid/g" \
  "$repo_root/crates/mithril-e2e/fixtures/convergence/exception-v1.yaml" \
  >"$exception"
"$provider" put "$vm_a" "$exception" "$remote_a/exception-v1.yaml"
remote_kubectl --as="$exception_subject" create \
  -f "$remote_a/exception-v1.yaml" >/dev/null
wait_exception_state temporary-file-access Active
remote_kubectl -n "$workload_namespace" get \
  workloadprotectionexception temporary-file-access -o json | jq -e '
    (.status | keys) == ["conditions", "observedGeneration", "state"] and
    all(.status.conditions[];
      (keys) == ["lastTransitionTime", "message", "observedGeneration", "reason", "status", "type"])
  ' >/dev/null
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
jq -e '
  .pending_exception_count == 0 and
  .active_exception_count == 0 and
  .terminal_exception_count == 0
' <<<"$(node_status "$other_node")" >/dev/null

overlap=$work_a/exception-overlap.yaml
sed '0,/name: temporary-file-access/s//name: overlapping-file-access/' \
  "$exception" >"$overlap"
"$provider" put "$vm_a" "$overlap" "$remote_a/exception-overlap.yaml"
remote_kubectl --as="$exception_subject" create \
  -f "$remote_a/exception-overlap.yaml" >/dev/null
wait_exception_state overlapping-file-access Failed
remote_kubectl --as="$exception_subject" -n "$workload_namespace" delete \
  workloadprotectionexception overlapping-file-access --wait=true --timeout=120s >/dev/null

"$provider" run "$selected_vm" sudo touch \
  /var/lib/mithril-convergence/markers/protected.exception-request
for _attempt in {1..120}; do
  exception_result=$("$provider" run "$selected_vm" sudo cat \
    /var/lib/mithril-convergence/markers/protected.exception-result 2>/dev/null || true)
  [[ $exception_result == ONE_USE ]] && break
  [[ $_attempt -lt 120 ]] || {
    echo "the bounded exception did not allow exactly one target open" >&2
    exit 1
  }
  sleep 1
done
wait_exception_state temporary-file-access Consumed
jq -e '.consumed_exception_count == 1 and .active_exception_count == 0' \
  <<<"$(node_status "$selected_node")" >/dev/null

first_exception_uid=$(remote_kubectl -n "$workload_namespace" get \
  workloadprotectionexception temporary-file-access -o jsonpath='{.metadata.uid}')
remote_kubectl --as="$exception_subject" -n "$workload_namespace" delete \
  workloadprotectionexception temporary-file-access --wait=true --timeout=120s >/dev/null
for _attempt in {1..120}; do
  if jq -e '.revoked_exception_count == 1 and .exception_ack_pending_count == 0' \
      <<<"$(node_status "$selected_node")" >/dev/null; then
    break
  fi
  [[ $_attempt -lt 120 ]] || {
    echo "exception deletion did not converge to node-local revocation" >&2
    exit 1
  }
  sleep 1
done

expired=$work_a/exception-expired.yaml
sed \
  -e '0,/name: temporary-file-access/s//name: expiring-file-access/' \
  -e 's/requestedDuration: 2m/requestedDuration: 3s/' \
  "$exception" >"$expired"
"$provider" put "$vm_a" "$expired" "$remote_a/exception-expired.yaml"
remote_kubectl --as="$exception_subject" create \
  -f "$remote_a/exception-expired.yaml" >/dev/null
wait_exception_state expiring-file-access Active
wait_exception_state expiring-file-access Expired
jq -e '.expired_exception_count == 1 and .active_exception_count == 0' \
  <<<"$(node_status "$selected_node")" >/dev/null
remote_kubectl --as="$exception_subject" -n "$workload_namespace" delete \
  workloadprotectionexception expiring-file-access --wait=true --timeout=120s >/dev/null
for _attempt in {1..120}; do
  if jq -e '.revoked_exception_count == 2 and .exception_ack_pending_count == 0' \
      <<<"$(node_status "$selected_node")" >/dev/null; then
    break
  fi
  [[ $_attempt -lt 120 ]] || {
    echo "the expired exception did not receive an exact revocation" >&2
    exit 1
  }
  sleep 1
done

excess=$work_a/exception-excess.yaml
sed \
  -e '0,/name: temporary-file-access/s//name: excessive-file-access/' \
  -e 's/requestedUses: 1/requestedUses: 2/' \
  "$exception" >"$excess"
"$provider" put "$vm_a" "$excess" "$remote_a/exception-excess.yaml"
remote_kubectl --as="$exception_subject" create \
  -f "$remote_a/exception-excess.yaml" >/dev/null
wait_exception_state excessive-file-access Failed
remote_kubectl --as="$exception_subject" -n "$workload_namespace" delete \
  workloadprotectionexception excessive-file-access --wait=true --timeout=120s >/dev/null

remote_kubectl create -f "$remote_a/gate-failure.yaml" >/dev/null
for _attempt in {1..120}; do
  failure_json=$(remote_kubectl -n "$workload_namespace" get pod gate-failure -o json)
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
"$provider" run "$vm_a" sudo test ! -e \
  /var/lib/mithril-convergence/markers/gate-failure.started
"$provider" run "$vm_b" sudo test ! -e \
  /var/lib/mithril-convergence/markers/gate-failure.started
remote_kubectl -n "$workload_namespace" delete pod gate-failure \
  --wait=true --timeout=120s >/dev/null

container_before=$(remote_kubectl -n "$workload_namespace" get pod protected \
  -o jsonpath='{.status.containerStatuses[0].containerID}')
"$provider" run "$selected_vm" sudo touch \
  /var/lib/mithril-convergence/markers/protected.restart
for _attempt in {1..180}; do
  container_after=$(remote_kubectl -n "$workload_namespace" get pod protected \
    -o jsonpath='{.status.containerStatuses[0].containerID}')
  [[ -n $container_after && $container_after != "$container_before" ]] && break
  [[ $_attempt -lt 180 ]] || {
    echo "the protected container did not receive a new runtime lifetime" >&2
    exit 1
  }
  sleep 1
done
remote_kubectl -n "$workload_namespace" wait --for=condition=Ready pod/protected \
  --timeout=180s >/dev/null
jq -e '.runtime_binding_count == 1 and .scheduled_binding_count == 0' \
  <<<"$(node_status "$selected_node")" >/dev/null
assert_live_exact_target "$selected_node" "$profile_id" ACTIVATE
restarted_status=$(node_status "$selected_node")
runtime_binding_after=$(jq -er '.active_targets[0].runtime_binding_id' \
  <<<"$restarted_status")
[[ $runtime_binding_after != "$runtime_binding_before" ]] || {
  echo "the restarted container retained its old runtime binding" >&2
  exit 1
}
container_after_id=${container_after#containerd://}
container_after_json=$("$provider" run "$selected_vm" sudo \
  /usr/local/bin/k3s crictl inspect "$container_after_id")
host_pid_after=$(jq -er '.info.pid' <<<"$container_after_json")
task_after=$(runtime_task_snapshot "$selected_node" "$host_pid_after")
task_cookie_after=$(jq -er '.task_cookie' <<<"$task_after")
assert_prepared_container_activation "$task_after" "$runtime_binding_after"
prepared_entry_before=$(jq -er \
  '.runtime_binding.prepared_container_entry_instance_id' <<<"$task_before")
prepared_entry_after=$(jq -er \
  '.runtime_binding.prepared_container_entry_instance_id' <<<"$task_after")
[[ $prepared_entry_after != "$prepared_entry_before" ]] || {
  echo "the restarted container retained its old PreparedContainer entry" >&2
  exit 1
}
[[ $task_cookie_after != "$task_cookie_before" ]] || {
  echo "the restarted container retained its old host task identity" >&2
  exit 1
}
old_task_after=$(runtime_task_snapshot "$selected_node" "$host_pid_before" 2>/dev/null || true)
if [[ -n $old_task_after ]] &&
    jq -e --argjson old "$task_cookie_before" '.task_cookie == $old' \
      <<<"$old_task_after" >/dev/null; then
  echo "the retired host task identity remained active after container restart" >&2
  exit 1
fi

candidate_before_node_restart=$(jq -er '.active_candidate_content_id' \
  <<<"$(node_status "$selected_node")")
selected_node_pod=$(remote_kubectl -n "$system_namespace" get pods \
  -l app.kubernetes.io/name=mithril-node \
  --field-selector "spec.nodeName=$selected_node" \
  -o jsonpath='{.items[0].metadata.name}')
remote_kubectl -n "$system_namespace" delete pod "$selected_node_pod" \
  --wait=true --timeout=120s >/dev/null
remote_kubectl -n "$system_namespace" rollout status daemonset/mithril-node \
  --timeout=300s >/dev/null
wait_node_projection "$selected_node" true false
# Ready projection is necessary but not sufficient. Recovery must restore the
# exact active policy and live runtime binding that existed before restart.
for _attempt in {1..180}; do
  recovered_status=$(node_status "$selected_node" 2>/dev/null || true)
  if [[ -n $recovered_status ]] && jq -e \
      --arg candidate "$candidate_before_node_restart" --arg profile_id "$profile_id" '
        .active_candidate_content_id == $candidate and
        .active_profile_ids == [$profile_id] and
        .scheduled_binding_count == 0 and
        .runtime_binding_count == 1 and
        .activation_pending == false and
        .control_acknowledged == true
      ' <<<"$recovered_status" >/dev/null; then
    break
  fi
  [[ $_attempt -lt 180 ]] || {
    echo "the scheduler-selected node did not recover its active policy" >&2
    exit 1
  }
  sleep 1
done
assert_live_exact_target "$selected_node" "$profile_id" ACTIVATE

# Hold one matching node without a node process and prove that it stays quarantined.
"$provider" run "$other_vm" sudo mv /etc/mithril/node.json /etc/mithril/node.json.held
other_node_pod=$(remote_kubectl -n "$system_namespace" get pods \
  -l app.kubernetes.io/name=mithril-node --field-selector "spec.nodeName=$other_node" \
  -o jsonpath='{.items[0].metadata.name}')
remote_kubectl -n "$system_namespace" delete pod "$other_node_pod" \
  --wait=true --timeout=120s >/dev/null
wait_node_projection "$other_node" "" true
render_pod ready-node-only mithril
remote_kubectl create -f "$remote_a/ready-node-only.yaml" >/dev/null
remote_kubectl -n "$workload_namespace" wait --for=condition=Ready pod/ready-node-only \
  --timeout=300s >/dev/null
[[ $(remote_kubectl -n "$workload_namespace" get pod ready-node-only \
  -o jsonpath='{.spec.nodeName}') == "$selected_node" ]]
remote_kubectl -n "$workload_namespace" delete pod ready-node-only \
  --wait=true --timeout=120s >/dev/null
"$provider" run "$other_vm" sudo mv /etc/mithril/node.json.held /etc/mithril/node.json
remote_kubectl -n "$system_namespace" rollout status daemonset/mithril-node \
  --timeout=300s >/dev/null
wait_node_projection "$other_node" true false

# Change only the live DaemonSet. Admission must derive the new selector.
remote_kubectl label node "$node_a_name" mithril.erebor.dev/fixture=selected --overwrite >/dev/null
remote_kubectl -n "$system_namespace" patch daemonset mithril-node --type=merge \
  -p '{"spec":{"template":{"spec":{"nodeSelector":{"mithril.erebor.dev/fixture":"selected"}}}}}' \
  >/dev/null
wait_node_projection "$node_b_name" "" false
selector_dry_run=$(remote_kubectl create --dry-run=server \
  -f "$remote_a/protected.yaml" -o json)
jq -e '.spec.nodeSelector["mithril.erebor.dev/fixture"] == "selected"' \
  <<<"$selector_dry_run" >/dev/null
render_pod selector-derived mithril
remote_kubectl create -f "$remote_a/selector-derived.yaml" >/dev/null
remote_kubectl -n "$workload_namespace" wait --for=condition=Ready pod/selector-derived \
  --timeout=300s >/dev/null
[[ $(remote_kubectl -n "$workload_namespace" get pod selector-derived \
  -o jsonpath='{.spec.nodeName}') == "$node_a_name" ]]
remote_kubectl -n "$workload_namespace" delete pod selector-derived \
  --wait=true --timeout=120s >/dev/null
"$provider" run "$vm_b" sudo mv /etc/mithril/node.json /etc/mithril/node.json.held
remote_kubectl -n "$system_namespace" patch daemonset mithril-node --type=merge \
  -p '{"spec":{"template":{"spec":{"nodeSelector":{"mithril.erebor.dev/fixture":null}}}}}' \
  >/dev/null
wait_node_projection "$node_b_name" "" true
"$provider" run "$vm_b" sudo mv /etc/mithril/node.json.held /etc/mithril/node.json
remote_kubectl -n "$system_namespace" rollout status daemonset/mithril-node \
  --timeout=300s >/dev/null
wait_node_projection "$node_b_name" true false

candidate_before=$(jq -er '.active_candidate_content_id' <<<"$(node_status "$selected_node")")
make_policy_manifest 2
remote_kubectl --as="$policy_subject" apply --server-side --validate=strict \
  -f "$remote_a/policy-v2.yaml" >/dev/null
wait_policy_compiled
for _attempt in {1..180}; do
  candidate_after=$(jq -er '.active_candidate_content_id // ""' \
    <<<"$(node_status "$selected_node")")
  [[ -n $candidate_after && $candidate_after != "$candidate_before" ]] && break
  [[ $_attempt -lt 180 ]] || {
    echo "the policy update did not replace the selected node generation" >&2
    exit 1
  }
  sleep 1
done
invalid_policy=$work_a/invalid-policy.json
remote_kubectl -n "$workload_namespace" get workloadprotectionpolicy converter-policy \
  -o json | jq '
    del(.metadata.creationTimestamp, .metadata.generation, .metadata.managedFields,
        .metadata.uid, .status) |
    .spec.unexpectedField = true
  ' >"$invalid_policy"
"$provider" put "$vm_a" "$invalid_policy" "$remote_a/invalid-policy.json"
assert_kubernetes_strict_field_denial remote_kubectl \
  --as="$policy_subject" replace --validate=strict \
  -f "$remote_a/invalid-policy.json"
[[ $(jq -er '.active_candidate_content_id' <<<"$(node_status "$selected_node")") \
  == "$candidate_after" ]]

# Reboot removes the host BPF maps. The new boot and label epoch must start a
# new policy chain only after the node proves that the old authority is absent.
pre_reboot_node=$(remote_kubectl get node "$selected_node" -o json)
pre_reboot_boot_id=$(jq -er \
  '.metadata.annotations["mithril.erebor.dev/node-boot-id"]' <<<"$pre_reboot_node")
pre_reboot_label_epoch=$(jq -er \
  '.metadata.annotations["mithril.erebor.dev/label-epoch"] | tonumber' \
  <<<"$pre_reboot_node")
"$provider" run "$selected_vm" sudo systemctl reboot --no-block >/dev/null
"$provider" wait "$selected_vm"
for _attempt in {1..300}; do
  if remote_kubectl get --raw=/readyz >/dev/null 2>&1; then
    break
  fi
  [[ $_attempt -lt 300 ]] || {
    echo "the Kubernetes API did not recover after the selected-node reboot" >&2
    exit 1
  }
  sleep 1
done
remote_kubectl -n "$system_namespace" rollout status deployment/mithril-control \
  --timeout=300s >/dev/null
remote_kubectl -n "$system_namespace" rollout status daemonset/mithril-node \
  --timeout=300s >/dev/null
wait_node_epoch_advance \
  "$selected_node" "$pre_reboot_boot_id" "$pre_reboot_label_epoch"
wait_node_projection "$other_node" true false
remote_kubectl -n "$workload_namespace" wait --for=condition=Ready pod/protected \
  --timeout=300s >/dev/null
for _attempt in {1..180}; do
  post_reboot_status=$(node_status "$selected_node" 2>/dev/null || true)
  post_reboot_candidate=
  if [[ -n $post_reboot_status ]]; then
    post_reboot_candidate=$(jq -er '.active_candidate_content_id // ""' \
      <<<"$post_reboot_status")
  fi
  [[ -n $post_reboot_candidate && $post_reboot_candidate != "$candidate_after" ]] && break
  [[ $_attempt -lt 180 ]] || {
    echo "the new physical epoch did not receive a new root policy" >&2
    exit 1
  }
  sleep 1
done
assert_live_exact_target "$selected_node" "$profile_id" ACTIVATE

remote_kubectl -n "$system_namespace" rollout restart deployment/mithril-control >/dev/null
remote_kubectl -n "$system_namespace" rollout status deployment/mithril-control \
  --timeout=300s >/dev/null
wait_node_projection "$node_a_name" true false
wait_node_projection "$node_b_name" true false
remote_kubectl -n "$workload_namespace" wait --for=condition=Ready pod/protected \
  --timeout=120s >/dev/null
assert_live_exact_target "$selected_node" "$profile_id" ACTIVATE

old_pod_uid=$(remote_kubectl -n "$workload_namespace" get pod protected \
  -o jsonpath='{.metadata.uid}')
# Keep the recreated grant unused. Removing its exact Pod must retire it.
consumed_before_retirement=$(jq -er '.consumed_exception_count' \
  <<<"$(node_status "$selected_node")")
remote_kubectl --as="$exception_subject" create \
  -f "$remote_a/exception-v1.yaml" >/dev/null
wait_exception_state temporary-file-access Active
second_exception_uid=$(remote_kubectl -n "$workload_namespace" get \
  workloadprotectionexception temporary-file-access -o jsonpath='{.metadata.uid}')
[[ $second_exception_uid != "$first_exception_uid" ]]
for _attempt in {1..120}; do
  if jq -e '.active_exception_count == 1 and .exception_ack_pending_count == 0' \
      <<<"$(node_status "$selected_node")" >/dev/null; then
    break
  fi
  [[ $_attempt -lt 120 ]] || {
    echo "the recreated exception did not become active" >&2
    exit 1
  }
  sleep 1
done
remote_kubectl -n "$workload_namespace" delete pod protected \
  --wait=true --timeout=120s >/dev/null
wait_exception_state temporary-file-access Revoked
for _attempt in {1..120}; do
  exception_status=$(node_status "$selected_node")
  if jq -e --argjson consumed "$consumed_before_retirement" '
      .active_exception_count == 0 and
      .consumed_exception_count == $consumed and
      .revoked_exception_count == 3 and
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
remote_kubectl --as="$exception_subject" -n "$workload_namespace" delete \
  workloadprotectionexception temporary-file-access \
  --wait=true --timeout=120s >/dev/null
remote_kubectl --as="$policy_subject" -n "$workload_namespace" delete \
  workloadprotectionpolicy converter-policy \
  --wait=true --timeout=120s >/dev/null

# A Control and node restart must not replay the closed root chain.
selected_node_pod=$(remote_kubectl -n "$system_namespace" get pods \
  -l app.kubernetes.io/name=mithril-node \
  --field-selector "spec.nodeName=$selected_node" \
  -o jsonpath='{.items[0].metadata.name}')
remote_kubectl -n "$system_namespace" rollout restart deployment/mithril-control >/dev/null
remote_kubectl -n "$system_namespace" rollout status deployment/mithril-control \
  --timeout=300s >/dev/null
remote_kubectl -n "$system_namespace" delete pod "$selected_node_pod" \
  --wait=true --timeout=120s >/dev/null
remote_kubectl -n "$system_namespace" rollout status daemonset/mithril-node \
  --timeout=300s >/dev/null
wait_node_projection "$selected_node" true false
wait_policy_delivery_empty "$selected_node"

"$provider" run "$vm_a" sudo rm -f \
  /var/lib/mithril-convergence/markers/protected.started \
  /var/lib/mithril-convergence/markers/protected.restart \
  /var/lib/mithril-convergence/markers/protected.prepared-result \
  /var/lib/mithril-convergence/markers/protected.exception-request \
  /var/lib/mithril-convergence/markers/protected.exception-result
"$provider" run "$vm_b" sudo rm -f \
  /var/lib/mithril-convergence/markers/protected.started \
  /var/lib/mithril-convergence/markers/protected.restart \
  /var/lib/mithril-convergence/markers/protected.prepared-result \
  /var/lib/mithril-convergence/markers/protected.exception-request \
  /var/lib/mithril-convergence/markers/protected.exception-result
make_policy_manifest 3
remote_kubectl --as="$policy_subject" apply --server-side --validate=strict \
  -f "$remote_a/policy-v3.yaml" >/dev/null
wait_policy_compiled
recreated_profile_id=$(remote_kubectl -n "$workload_namespace" get \
  workloadprotectionpolicy converter-policy -o jsonpath='{.metadata.uid}')
[[ $recreated_profile_id != "$profile_id" ]]
for node in "$vm_a" "$vm_b"; do
  "$provider" run "$node" sudo rm -f \
    /var/lib/mithril-convergence/markers/protected.started \
    /var/lib/mithril-convergence/markers/protected.restart \
    /var/lib/mithril-convergence/markers/protected.prepared-result \
    /var/lib/mithril-convergence/markers/protected.exception-request \
    /var/lib/mithril-convergence/markers/protected.exception-result
done
remote_kubectl create -f "$remote_a/protected.yaml" >/dev/null
remote_kubectl -n "$workload_namespace" wait --for=condition=Ready pod/protected \
  --timeout=300s >/dev/null
new_pod_uid=$(remote_kubectl -n "$workload_namespace" get pod protected \
  -o jsonpath='{.metadata.uid}')
[[ -n $new_pod_uid && $new_pod_uid != "$old_pod_uid" ]]
[[ $(remote_kubectl -n "$workload_namespace" get pod protected -o json | \
  jq -er '.metadata.annotations["mithril.erebor.dev/profile-id"]') \
  == "$recreated_profile_id" ]]
recreated_node=$(remote_kubectl -n "$workload_namespace" get pod protected \
  -o jsonpath='{.spec.nodeName}')
assert_live_exact_target "$recreated_node" "$recreated_profile_id" ACTIVATE
jq -e '
  .active_targets[0].operation == "ACTIVATE" and
  .active_targets[0].predecessor_candidate_content_id == null
' <<<"$(node_status "$recreated_node")" >/dev/null

remote_kubectl -n "$workload_namespace" delete pod protected \
  --wait=true --timeout=120s >/dev/null
wait_policy_delivery_empty "$recreated_node"
remote_kubectl --as="$policy_subject" -n "$workload_namespace" delete \
  workloadprotectionpolicy converter-policy \
  --wait=true --timeout=120s >/dev/null
remote_kubectl delete namespace "$workload_namespace" \
  --wait=true --timeout=120s >/dev/null

jq -n \
  --arg kubernetes_version "$(remote_kubectl version -o json | jq -r '.serverVersion.gitVersion')" \
  --arg containerd_version "$("$provider" run "$vm_a" sudo /usr/local/bin/k3s ctr version | awk '/Version:/ {print $2; exit}')" \
  --arg node_a "$node_a_name" --arg node_b "$node_b_name" \
  --arg scheduler_selected "$selected_node" \
  '{
    schema_version: 1,
    kubernetes_version: $kubernetes_version,
    containerd_version: $containerd_version,
    eligible_nodes: [$node_a, $node_b],
    scheduler_selected_node: $scheduler_selected,
    exact_node_delivery: true,
    exact_target_proven: true,
    ordered_create_runtime_release: true,
    prepared_container_active: true,
    post_activation_ipc_denied: true,
    unavailable_endpoint_denied: true,
    unready_node_quarantined: true,
    replaced_node_uid_quarantined: true,
    daemonset_selector_derived: true,
    node_restart_recovered: true,
    host_epoch_advanced: true,
    runtime_lifetime_replaced: true,
    runtime_task_identity_replaced: true,
    pod_uid_replaced: true,
    policy_update_and_recreate: true,
    exception_one_use_consumed: true,
    exception_expired: true,
    exception_revoked: true,
    exception_target_retired: true,
    exception_recreated_with_new_uid: true,
    exception_overlap_rejected: true,
    exception_excess_bound_rejected: true,
    terminal_chain_cleaned: true,
    old_root_replay_refused: true,
    fresh_policy_uses_root_activation: true,
    rbac_boundary: true
  }' >"$output_directory/two-node-convergence.json"

echo "Two-node Kubernetes policy convergence passed. Evidence: $output_directory"
