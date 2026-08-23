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
k3s_version=${MITHRIL_VM_K3S_VERSION:-v1.35.5+k3s1}
nri_release=${MITHRIL_VM_NRI_RELEASE:-v0.10.0}
reuse_images=${MITHRIL_VM_REUSE_IMAGES:-false}
system_namespace=mithril-system
workload_namespace=mithril-convergence
runtime_hook_owner=$system_namespace/mithril
runtime_hook_socket=/run/mithril/runtime-admission.sock

usage() {
  echo "usage: $0 [--provider PATH] [--output-directory PATH] [--keep-vms] [--manual-environment]" >&2
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
[[ $nri_release =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  echo "invalid MITHRIL_VM_NRI_RELEASE: $nri_release" >&2
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

work_a=$(mktemp -d /tmp/mithril-vm-test.XXXXXX)
work_b=$(mktemp -d /tmp/mithril-vm-test.XXXXXX)
vm_a=mithril-runtime-qualification-$$1
vm_b=mithril-runtime-qualification-$$2
export MITHRIL_VM_KNOWN_HOSTS=$work_a/known_hosts
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

cleanup() {
  local original_status=$?
  local cleanup_failed=false
  trap - EXIT
  set +e
  if ((original_status != 0)) && [[ $cluster_created == true ]]; then
    collect_mithril_diagnostics "$output_directory" "$system_namespace" || cleanup_failed=true
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
cp -- "$repo_root/crates/mithril-e2e/fixtures/mithril-policy/observe-profile-seal-request.json" \
  "$materials/profile-seal-request.json"
"$repo_root/target/debug/mithril-policy" print-trust-generation \
  --signing-key-id effect-observation-test-key \
  --public-key "$repo_root/crates/mithril-e2e/fixtures/mithril-policy/test-public-key.hex" \
  --issuer-epoch 1 --output "$materials/trust.json"

"$provider" create "$vm_a" "$work_a" "$ssh_public_key"
created_a=true
"$provider" create "$vm_b" "$work_b" "$ssh_public_key"
created_b=true
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

"$provider" run "$vm_a" sudo bash "$remote_a/harness/guest.sh" \
  k3s-install "$k3s_version" "$remote_a/harness/k3s-config-v1.yaml" "$remote_a"
node_token=$("$provider" run "$vm_a" sudo cat /var/lib/rancher/k3s/server/node-token)
"$provider" run "$vm_b" sudo bash "$remote_b/harness/guest.sh" \
  k3s-agent-install "$k3s_version" "https://$address_a:6443" "$node_token" "$remote_b"
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

# The stock NRI plugin is the containerd owner that reads the chart's hook file.
# The positive runtime has no base-spec hook, so it cannot bypass this path.
"$provider" run "$vm_a" sudo /usr/local/bin/k3s kubectl apply -k \
  "github.com/containerd/nri/contrib/kustomize/hook-injector?ref=$nri_release" >/dev/null
"$provider" run "$vm_a" sudo /usr/local/bin/k3s kubectl -n kube-system \
  rollout status daemonset/nri-plugin-hook-injector --timeout=300s >/dev/null

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
  "$provider" put "$node" "$materials/node-$label.json" \
    "$remote/materials/node.json"
  "$provider" run "$node" \
    "sudo install -d -m 0700 /etc/mithril/identity /var/lib/mithril-convergence/markers /run/mithril && \
     sudo install -m 0444 '$remote/materials/ca.pem' /etc/mithril/identity/ca.pem && \
     sudo install -m 0444 '$remote/materials/node.pem' /etc/mithril/identity/node.pem && \
     sudo install -m 0400 '$remote/materials/node-key.pem' /etc/mithril/identity/node-key.pem"
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
    hostBinaryDirectory: /opt/mithril/bin
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
jq --arg node "$node_a_name" '.spec.nodeName = $node' <<<"$protected_dry_run" >"$bypass"
"$provider" put "$vm_a" "$bypass" "$remote_a/bypass.json"
assert_mithril_node_name_denial remote_kubectl create \
  -f "$remote_a/bypass.json"

# Both possible scheduler targets receive the same inert test file, not policy authority.
for node in "$vm_a" "$vm_b"; do
  "$provider" run "$node" sudo rm -f \
    /var/lib/mithril-convergence/markers/protected.started \
    /var/lib/mithril-convergence/markers/protected.restart \
    /var/lib/mithril-convergence/markers/protected.exception-request \
    /var/lib/mithril-convergence/markers/protected.exception-result
  "$provider" run "$node" sudo touch \
    /var/lib/mithril-convergence/markers/protected.exception-target
done

remote_kubectl create -f "$remote_a/protected.yaml" >/dev/null
remote_kubectl -n "$workload_namespace" wait --for=condition=Ready pod/protected \
  --timeout=300s >/dev/null
selected_node=$(remote_kubectl -n "$workload_namespace" get pod protected \
  -o jsonpath='{.spec.nodeName}')
[[ $selected_node == "$node_a_name" || $selected_node == "$node_b_name" ]] || {
  echo "the scheduler selected a Node outside the DaemonSet-derived set" >&2
  exit 1
}
other_node=$node_a_name
[[ $selected_node == "$node_b_name" ]] || other_node=$node_b_name

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

selected_status=$(node_status "$selected_node")
other_status=$(node_status "$other_node")
jq -e --arg profile_id "$profile_id" '
  .active_candidate_content_id != null and
  .active_profile_ids == [$profile_id] and
  .scheduled_binding_count == 0 and
  .runtime_binding_count == 1 and
  .activation_pending == false and
  .control_acknowledged == true
' <<<"$selected_status" >/dev/null
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
"$provider" run "$selected_vm" sudo test -e \
  /var/lib/mithril-convergence/markers/protected.started
"$provider" run "$other_vm" sudo test ! -e \
  /var/lib/mithril-convergence/markers/protected.started

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

protected_uid=$(remote_kubectl -n "$workload_namespace" get pod protected \
  -o jsonpath='{.metadata.uid}')
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

remote_kubectl --as="$exception_subject" create \
  -f "$remote_a/exception-v1.yaml" >/dev/null
wait_exception_state temporary-file-access Active
second_exception_uid=$(remote_kubectl -n "$workload_namespace" get \
  workloadprotectionexception temporary-file-access -o jsonpath='{.metadata.uid}')
[[ $second_exception_uid != "$first_exception_uid" ]]
remote_kubectl --as="$exception_subject" -n "$workload_namespace" delete \
  workloadprotectionexception temporary-file-access --wait=true --timeout=120s >/dev/null
for _attempt in {1..120}; do
  if jq -e '.revoked_exception_count == 2 and .exception_ack_pending_count == 0' \
      <<<"$(node_status "$selected_node")" >/dev/null; then
    break
  fi
  [[ $_attempt -lt 120 ]] || {
    echo "the recreated exception did not receive an independent revocation" >&2
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
  if jq -e '.revoked_exception_count == 3 and .exception_ack_pending_count == 0' \
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
for _attempt in {1..180}; do
  b_json=$(remote_kubectl get node "$node_b_name" -o json)
  if jq -e '(.metadata.labels["mithril.erebor.dev/ready"] // "") == ""' \
      <<<"$b_json" >/dev/null; then
    break
  fi
  sleep 1
done
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
remote_kubectl -n "$system_namespace" patch daemonset mithril-node --type=merge \
  -p '{"spec":{"template":{"spec":{"nodeSelector":{"mithril.erebor.dev/fixture":null}}}}}' \
  >/dev/null
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

remote_kubectl -n "$system_namespace" rollout restart deployment/mithril-control >/dev/null
remote_kubectl -n "$system_namespace" rollout status deployment/mithril-control \
  --timeout=300s >/dev/null
wait_node_projection "$node_a_name" true false
wait_node_projection "$node_b_name" true false
remote_kubectl -n "$workload_namespace" wait --for=condition=Ready pod/protected \
  --timeout=120s >/dev/null

old_pod_uid=$(remote_kubectl -n "$workload_namespace" get pod protected \
  -o jsonpath='{.metadata.uid}')
remote_kubectl -n "$workload_namespace" delete pod protected \
  --wait=true --timeout=120s >/dev/null
"$provider" run "$vm_a" sudo rm -f \
  /var/lib/mithril-convergence/markers/protected.started \
  /var/lib/mithril-convergence/markers/protected.restart
"$provider" run "$vm_b" sudo rm -f \
  /var/lib/mithril-convergence/markers/protected.started \
  /var/lib/mithril-convergence/markers/protected.restart
remote_kubectl create -f "$remote_a/protected.yaml" >/dev/null
remote_kubectl -n "$workload_namespace" wait --for=condition=Ready pod/protected \
  --timeout=300s >/dev/null
new_pod_uid=$(remote_kubectl -n "$workload_namespace" get pod protected \
  -o jsonpath='{.metadata.uid}')
[[ -n $new_pod_uid && $new_pod_uid != "$old_pod_uid" ]]

remote_kubectl -n "$workload_namespace" delete pod protected \
  --wait=true --timeout=120s >/dev/null
remote_kubectl --as="$policy_subject" -n "$workload_namespace" delete \
  workloadprotectionpolicy converter-policy \
  --wait=true --timeout=120s >/dev/null
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
    /var/lib/mithril-convergence/markers/protected.exception-request \
    /var/lib/mithril-convergence/markers/protected.exception-result
done
remote_kubectl create -f "$remote_a/protected.yaml" >/dev/null
remote_kubectl -n "$workload_namespace" wait --for=condition=Ready pod/protected \
  --timeout=300s >/dev/null
[[ $(remote_kubectl -n "$workload_namespace" get pod protected \
  -o jsonpath='{.metadata.annotations.mithril\.erebor\.dev/profile-id}') \
  == "$recreated_profile_id" ]]

remote_kubectl -n "$workload_namespace" delete pod protected \
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
    stock_prestart_release: true,
    unavailable_endpoint_denied: true,
    unready_node_quarantined: true,
    daemonset_selector_derived: true,
    node_restart_recovered: true,
    runtime_lifetime_replaced: true,
    pod_uid_replaced: true,
    policy_update_and_recreate: true,
    exception_one_use_consumed: true,
    exception_expired: true,
    exception_revoked: true,
    exception_recreated_with_new_uid: true,
    exception_overlap_rejected: true,
    exception_excess_bound_rejected: true,
    rbac_boundary: true
  }' >"$output_directory/two-node-convergence.json"

echo "Two-node Kubernetes policy convergence passed. Evidence: $output_directory"
