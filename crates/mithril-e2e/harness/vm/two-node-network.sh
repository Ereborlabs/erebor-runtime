#!/usr/bin/env bash

set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$directory/../../../.." && pwd)
. "$directory/identity.sh"
branch_name=$(mithril_vm_branch_name "$repo_root")
branch_key=$(mithril_vm_branch_key "$branch_name")
provider=$directory/providers/libvirt.sh
output_directory=
keep_vms=false
k3s_version=${MITHRIL_VM_K3S_VERSION:-v1.35.5+k3s1}

usage() {
  echo "usage: $0 [--provider PATH] [--output-directory PATH] [--keep-vms]" >&2
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

[[ -x $provider ]] || {
  echo "VM provider is not executable: $provider" >&2
  exit 2
}
[[ $k3s_version =~ ^v[0-9]+\.[0-9]+\.[0-9]+\+k3s[0-9]+$ ]] || {
  echo "invalid MITHRIL_VM_K3S_VERSION: $k3s_version" >&2
  exit 2
}
[[ $(uname -m) == x86_64 ]] || {
  echo "the two-node network probe requires an x86_64 host" >&2
  exit 2
}
command -v jq >/dev/null || {
  echo "required command is not installed: jq" >&2
  exit 2
}

if [[ -z $output_directory ]]; then
  output_directory=$repo_root/target/mithril-two-node-network/$(date -u +%Y%m%dT%H%M%SZ)-$$
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
vm_a=$(mithril_vm_name "$branch_key" n "$$" a)
vm_b=$(mithril_vm_name "$branch_key" n "$$" b)
export MITHRIL_VM_KNOWN_HOSTS=$work_a/known_hosts
ssh_public_key=${MITHRIL_VM_SSH_PUBLIC_KEY:-$HOME/.ssh/id_rsa.pub}
created_a=false
created_b=false
peer_job=

cleanup() {
  local status=$?
  trap - EXIT
  if [[ -n $peer_job ]]; then
    kill "$peer_job" >/dev/null 2>&1 || true
    wait "$peer_job" >/dev/null 2>&1 || true
  fi
  if [[ $created_b == true && $keep_vms == false ]]; then
    "$provider" destroy "$vm_b" "$work_b" || status=1
  fi
  if [[ $created_a == true && $keep_vms == false ]]; then
    "$provider" destroy "$vm_a" "$work_a" || status=1
  fi
  if [[ $keep_vms == true ]]; then
    {
      printf 'branch_name=%q\nbranch_key=%q\n' "$branch_name" "$branch_key"
      printf 'node_a=%q\nnode_a_work_directory=%q\n' "$vm_a" "$work_a"
      printf 'node_b=%q\nnode_b_work_directory=%q\n' "$vm_b" "$work_b"
      printf 'provider=%q\n' "$provider"
      printf 'export MITHRIL_VM_KNOWN_HOSTS=%q\n' "$MITHRIL_VM_KNOWN_HOSTS"
    } >"$output_directory/retained-vms.txt"
  else
    [[ $work_a == /tmp/mithril-vm-test.* ]] && rm -rf -- "$work_a"
    [[ $work_b == /tmp/mithril-vm-test.* ]] && rm -rf -- "$work_b"
  fi
  exit "$status"
}
trap cleanup EXIT

[[ -r $ssh_public_key ]] || {
  echo "SSH public key is not readable: $ssh_public_key" >&2
  exit 2
}

echo "Building the two-node network probe and platform inspector"
(cd -- "$repo_root" && cargo build --locked -p mithril-e2e \
  --bin mithril-network-test -p mithril-node --bin mithril-inspect)

"$provider" create "$vm_a" "$work_a" "$ssh_public_key"
created_a=true
"$provider" create "$vm_b" "$work_b" "$ssh_public_key"
created_b=true
"$provider" wait "$vm_a"
"$provider" wait "$vm_b"
address_a=$("$provider" address "$vm_a")
address_b=$("$provider" address "$vm_b")
[[ -n $address_a && -n $address_b && $address_a != "$address_b" ]] || {
  echo "the two nodes do not have distinct provider addresses" >&2
  exit 1
}

remote_a=/var/tmp/$vm_a
remote_b=/var/tmp/$vm_b
for node in "$vm_a" "$vm_b"; do
  if [[ $node == "$vm_a" ]]; then
    remote=$remote_a
  else
    remote=$remote_b
  fi
  "$provider" run "$node" mkdir -p \
    "$remote/bin" "$remote/source/crates/mithril-e2e/fixtures/mithril-policy" \
    "$remote/harness"
  "$provider" put "$node" "$repo_root/target/debug/mithril-network-test" \
    "$remote/bin/mithril-network-test"
  "$provider" put "$node" "$repo_root/target/debug/mithril-inspect" \
    "$remote/bin/mithril-inspect"
  "$provider" put "$node" "$directory/guest.sh" "$remote/harness/guest.sh"
  "$provider" put "$node" "$directory/k3s-config-v1.yaml" \
    "$remote/harness/k3s-config-v1.yaml"
  for fixture in protect-policy-v1.yaml observe-profile-seal-request.json \
    test-signing-key.hex test-public-key.hex; do
    "$provider" put "$node" \
      "$repo_root/crates/mithril-e2e/fixtures/mithril-policy/$fixture" \
      "$remote/source/crates/mithril-e2e/fixtures/mithril-policy/$fixture"
  done
  "$provider" run "$node" \
    'sudo apt-get update && sudo apt-get install -y --no-install-recommends iproute2 nftables'
  "$provider" run "$node" sudo bash "$remote/harness/guest.sh" \
    platform "$remote/bin/mithril-inspect" "$remote" \
    >"$output_directory/$node-platform.txt"
done

boot_a=$(awk -F= '$1 == "boot_id" {print $2}' "$output_directory/$vm_a-platform.txt")
boot_b=$(awk -F= '$1 == "boot_id" {print $2}' "$output_directory/$vm_b-platform.txt")
[[ -n $boot_a && -n $boot_b && $boot_a != "$boot_b" ]] || {
  echo "the two nodes do not have independent boot identities" >&2
  exit 1
}

"$provider" run "$vm_a" sudo bash "$remote_a/harness/guest.sh" \
  k3s-install "$k3s_version" "$remote_a/harness/k3s-config-v1.yaml" "$remote_a"
node_token=$("$provider" run "$vm_a" sudo cat /var/lib/rancher/k3s/server/node-token)
"$provider" run "$vm_b" sudo bash "$remote_b/harness/guest.sh" \
  k3s-agent-install "$k3s_version" "https://$address_a:6443" "$node_token" "$remote_b"
node_count=0
for attempt in {1..300}; do
  node_count=$("$provider" run "$vm_a" sudo /usr/local/bin/k3s kubectl get nodes \
    -o jsonpath='{.items[*].metadata.name}' 2>/dev/null | awk '{print NF}')
  if [[ $node_count == 2 ]]; then
    break
  fi
  [[ $attempt -lt 300 ]] || {
    echo "the k3s cluster did not register exactly two nodes" >&2
    exit 1
  }
  sleep 1
done
"$provider" run "$vm_a" sudo /usr/local/bin/k3s kubectl wait \
  --for=condition=Ready node --all --timeout=300s
"$provider" run "$vm_a" sudo /usr/local/bin/k3s kubectl get nodes -o wide \
  >"$output_directory/kubernetes-nodes.txt"
[[ $node_count == 2 ]] || {
  echo "the k3s cluster did not report exactly two nodes" >&2
  exit 1
}
nodes_json=$("$provider" run "$vm_a" sudo /usr/local/bin/k3s kubectl get nodes -o json)
node_a_name=$(jq -r --arg address "$address_a" '
  .items[] |
  select(any(.status.addresses[]; .type == "InternalIP" and .address == $address)) |
  .metadata.name
' <<<"$nodes_json")
node_b_name=$(jq -r --arg address "$address_b" '
  .items[] |
  select(any(.status.addresses[]; .type == "InternalIP" and .address == $address)) |
  .metadata.name
' <<<"$nodes_json")
[[ -n $node_a_name && -n $node_b_name && $node_a_name != "$node_b_name" ]] || {
  echo "the provider addresses do not resolve to two exact Kubernetes nodes" >&2
  exit 1
}

namespace=mithril-two-node-network
image=docker.io/library/busybox:1.36.1@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662
pod_a_overrides=$(jq -cn --arg node "$node_a_name" \
  '{apiVersion: "v1", spec: {nodeName: $node}}')
pod_b_overrides=$(jq -cn --arg node "$node_b_name" \
  '{apiVersion: "v1", spec: {nodeName: $node}}')
"$provider" run "$vm_a" sudo /usr/local/bin/k3s kubectl create namespace "$namespace"
"$provider" run "$vm_a" sudo /usr/local/bin/k3s kubectl -n "$namespace" run node-a-peer \
  --image="$image" --restart=Never \
  "--overrides='$pod_a_overrides'" \
  --command -- sleep 600
"$provider" run "$vm_a" sudo /usr/local/bin/k3s kubectl -n "$namespace" run node-b-peer \
  --image="$image" --restart=Never \
  "--overrides='$pod_b_overrides'" \
  --command -- sleep 600
"$provider" run "$vm_a" sudo /usr/local/bin/k3s kubectl -n "$namespace" wait \
  --for=condition=Ready pod --all --timeout=300s
pod_a_ip=$("$provider" run "$vm_a" sudo /usr/local/bin/k3s kubectl -n "$namespace" \
  get pod node-a-peer -o jsonpath='{.status.podIP}')
pod_b_ip=$("$provider" run "$vm_a" sudo /usr/local/bin/k3s kubectl -n "$namespace" \
  get pod node-b-peer -o jsonpath='{.status.podIP}')
container_a=$("$provider" run "$vm_a" sudo /usr/local/bin/k3s kubectl -n "$namespace" \
  get pod node-a-peer -o jsonpath='{.status.containerStatuses[0].containerID}')
container_b=$("$provider" run "$vm_a" sudo /usr/local/bin/k3s kubectl -n "$namespace" \
  get pod node-b-peer -o jsonpath='{.status.containerStatuses[0].containerID}')
container_a=${container_a#containerd://}
container_b=${container_b#containerd://}
inspect_a=$("$provider" run "$vm_a" sudo /usr/local/bin/k3s crictl inspect "$container_a")
inspect_b=$("$provider" run "$vm_b" sudo /usr/local/bin/k3s crictl inspect "$container_b")
pod_a_pid=$(jq -r '.info.pid' <<<"$inspect_a")
pod_b_pid=$(jq -r '.info.pid' <<<"$inspect_b")
[[ $pod_a_ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ \
  && $pod_b_ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ \
  && $pod_a_ip != "$pod_b_ip" \
  && $pod_a_pid =~ ^[1-9][0-9]*$ \
  && $pod_b_pid =~ ^[1-9][0-9]*$ ]] || {
  echo "the CNI peer Pods do not have exact addresses and process identities" >&2
  exit 1
}

run_direction() {
  local source_node=$1
  local source_remote=$2
  local peer_node=$3
  local peer_remote=$4
  local peer_address=$5
  local peer_pid=$6
  local label=$7
  local ready=$peer_remote/$label-peer-ready
  local peer_result=$peer_remote/$label-peer.json
  local probe_result=$source_remote/$label-probe

  "$provider" run "$peer_node" sudo nsenter --target "$peer_pid" --net -- \
    "$peer_remote/bin/mithril-network-test" peer-server \
    --ready-path "$ready" --output "$peer_result" \
    >"$output_directory/$label-peer.log" 2>&1 &
  peer_job=$!
  for attempt in {1..120}; do
    if "$provider" run "$peer_node" test -f "$ready"; then
      break
    fi
    [[ $attempt -lt 120 ]] || {
      echo "the $label peer server did not become ready" >&2
      return 1
    }
    sleep 1
  done

  "$provider" run "$source_node" sudo "$source_remote/bin/mithril-network-test" \
    --repo-root "$source_remote/source" physical-probe \
    --output-directory "$probe_result" \
    --pin-root "/sys/fs/bpf/$source_node-$label" \
    --lease-path "$probe_result.owner.lock" \
    --cgroup-path "/sys/fs/cgroup/$source_node-$label" \
    --peer-address "$peer_address"
  wait "$peer_job"
  peer_job=
  "$provider" get "$source_node" "$probe_result/network-physical-probe.json" \
    "$output_directory/$label-probe.json"
  "$provider" get "$peer_node" "$peer_result" "$output_directory/$label-peer.json"
  jq -e '
    .schema_version == 1 and
    .peer_tcp_allowed == true and
    .peer_udp_allowed == true and
    .peer_denied_connect == true and
    (.fixture_results | length == 13) and
    all(.fixture_results[]; .result == "PASS")
  ' "$output_directory/$label-probe.json" >/dev/null
  jq -e '
    .schema_version == 1 and
    .tcp_payload_received == true and
    .udp_payload_received == true and
    .denied_connection_absent == true
  ' "$output_directory/$label-peer.json" >/dev/null
}

run_direction "$vm_a" "$remote_a" "$vm_b" "$remote_b" "$pod_b_ip" "$pod_b_pid" \
  node-a-to-node-b
run_direction "$vm_b" "$remote_b" "$vm_a" "$remote_a" "$pod_a_ip" "$pod_a_pid" \
  node-b-to-node-a

"$provider" run "$vm_a" sudo /usr/local/bin/k3s kubectl delete namespace "$namespace" \
  --wait=true --timeout=120s

"$provider" run "$vm_b" sudo bash "$remote_b/harness/guest.sh" \
  k3s-agent-remove "$remote_b"
"$provider" run "$vm_a" sudo bash "$remote_a/harness/guest.sh" \
  k3s-remove "$remote_a"

jq -n \
  --arg node_a "$vm_a" --arg node_a_boot_id "$boot_a" \
  --arg node_a_cni_peer "$pod_a_ip" \
  --arg node_b "$vm_b" --arg node_b_boot_id "$boot_b" \
  --arg node_b_cni_peer "$pod_b_ip" \
  '{
    schema_version: 1,
    node_a: $node_a,
    node_a_boot_id: $node_a_boot_id,
    node_a_cni_peer: $node_a_cni_peer,
    node_b: $node_b,
    node_b_boot_id: $node_b_boot_id,
    node_b_cni_peer: $node_b_cni_peer,
    kubernetes_ready_node_count: 2,
    node_a_to_node_b: true,
    node_b_to_node_a: true
  }' >"$output_directory/two-node-network.json"

echo "Two-node Kubernetes and network physical probes passed. Evidence: $output_directory"
