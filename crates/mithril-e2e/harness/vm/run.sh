#!/usr/bin/env bash

set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$directory/../../../.." && pwd)
provider=$directory/providers/libvirt.sh
output_directory=
with_k3s=false
keep_vm=false
skip_administrative_exec=false
manual_vm=false
k3s_version=${MITHRIL_VM_K3S_VERSION:-v1.35.5+k3s1}
source_mount=${MITHRIL_VM_SOURCE_MOUNT:-}

usage() {
  echo "usage: $0 [--provider PATH] [--output-directory PATH] [--with-k3s] [--skip-administrative-exec] [--keep-vm] [--manual]" >&2
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
    --with-k3s)
      with_k3s=true
      shift
      ;;
    --skip-administrative-exec)
      skip_administrative_exec=true
      shift
      ;;
    --keep-vm)
      keep_vm=true
      shift
      ;;
    --manual)
      manual_vm=true
      with_k3s=true
      keep_vm=true
      skip_administrative_exec=true
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

[[ $skip_administrative_exec == false || $with_k3s == true ]] || {
  echo "--skip-administrative-exec requires --with-k3s" >&2
  exit 2
}
[[ -x $provider ]] || {
  echo "VM provider is not executable: $provider" >&2
  exit 2
}
[[ $k3s_version =~ ^v[0-9]+\.[0-9]+\.[0-9]+\+k3s[0-9]+$ ]] || {
  echo "invalid MITHRIL_VM_K3S_VERSION: $k3s_version" >&2
  exit 2
}
[[ $(uname -m) == x86_64 ]] || {
  echo "kernel qualification record generation requires an x86_64 host" >&2
  exit 2
}
if [[ -n $source_mount ]]; then
  [[ $source_mount == /* && -d $source_mount ]] || {
    echo "MITHRIL_VM_SOURCE_MOUNT must be an existing absolute directory: $source_mount" >&2
    exit 2
  }
  source_mount=$(cd -- "$source_mount" && pwd -P)
  export MITHRIL_VM_SOURCE_MOUNT=$source_mount
fi
[[ $manual_vm == false || -n $source_mount ]] || {
  echo "--manual requires MITHRIL_VM_SOURCE_MOUNT" >&2
  exit 2
}

if [[ -z $output_directory ]]; then
  output_directory=$repo_root/target/mithril-vm-test/$(date -u +%Y%m%dT%H%M%SZ)-$$
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

vm_name=mithril-runtime-qualification-$$
work_directory=$(mktemp -d /tmp/mithril-vm-test.XXXXXX)
export MITHRIL_VM_KNOWN_HOSTS=${MITHRIL_VM_KNOWN_HOSTS:-$work_directory/known_hosts}
ssh_user=${MITHRIL_VM_SSH_USER:-ubuntu}
ssh_private_key=${MITHRIL_VM_SSH_PRIVATE_KEY:-$HOME/.ssh/id_rsa}
created=false

cleanup() {
  local status=$?
  local destroy_ok=true
  trap - EXIT
  if [[ $created == true && $keep_vm == false ]] &&
      ! "$provider" destroy "$vm_name" "$work_directory"; then
    status=1
    destroy_ok=false
  fi
  if [[ $created == true && $keep_vm == true ]]; then
    {
      printf 'vm_name=%q\nwork_directory=%q\nprovider=%q\n' \
        "$vm_name" "$work_directory" "$provider"
      printf 'export MITHRIL_VM_KNOWN_HOSTS=%q\n' "$MITHRIL_VM_KNOWN_HOSTS"
      printf 'export MITHRIL_VM_SSH_USER=%q\n' "$ssh_user"
      printf 'export MITHRIL_VM_SSH_PRIVATE_KEY=%q\n' "$ssh_private_key"
      if [[ -n $source_mount ]]; then
        printf 'export MITHRIL_VM_SOURCE_MOUNT=%q\nsource_mountpoint=%q\n' \
          "$source_mount" /mnt/mithril-source
      fi
    } >"$output_directory/retained-vm.txt"
    echo "VM retained: $vm_name ($work_directory)" >&2
  elif [[ $destroy_ok == true && -d $work_directory && $work_directory == /tmp/mithril-vm-test.* ]]; then
    rm -rf -- "$work_directory"
  elif [[ $destroy_ok == false ]]; then
    echo "VM cleanup failed; retained provider state in $work_directory" >&2
  fi
  exit "$status"
}
trap cleanup EXIT

ssh_public_key=${MITHRIL_VM_SSH_PUBLIC_KEY:-$HOME/.ssh/id_rsa.pub}
[[ -r $ssh_public_key ]] || {
  echo "SSH public key is not readable: $ssh_public_key" >&2
  exit 2
}

if [[ $manual_vm == true ]]; then
  echo "Building the Mithril binaries for the manual VM"
  (cd -- "$repo_root" && cargo build --locked \
    -p mithril-node --bin mithril-node --bin mithril-inspect \
    -p mithril-control --bin mithril-policy)
else
  echo "Building the repository-owned physical probes and platform inspector"
  (cd -- "$repo_root" && cargo build --locked -p mithril-e2e \
    --bin mithril-identity-test --bin mithril-effect-test \
    --bin mithril-network-test \
    --bin mithril-kernel-qualification \
    -p mithril-node --bin mithril-node --bin mithril-inspect \
    -p mithril-control --bin mithril-control --bin mithril-policy \
    --bin kubectl-mithril)

  qualification_build=$work_directory/kernel-qualification-build
  "$repo_root/target/debug/mithril-kernel-qualification" \
    --repo-root "$repo_root" probe --output-directory "$qualification_build"
fi

"$provider" create "$vm_name" "$work_directory" "$ssh_public_key"
created=true
"$provider" wait "$vm_name"

remote_root=/var/tmp/$vm_name
remote_source=$remote_root/source
remote_bin=$remote_root/bin
if [[ $manual_vm == true ]]; then
  "$provider" run "$vm_name" mkdir -p "$remote_root"
  "$provider" run "$vm_name" test -x \
    /mnt/mithril-source/target/debug/mithril-node
  "$provider" run "$vm_name" sudo bash \
    /mnt/mithril-source/crates/mithril-e2e/harness/vm/guest.sh \
    k3s-install "$k3s_version" \
    /mnt/mithril-source/crates/mithril-e2e/harness/vm/k3s-config-v1.yaml \
    "$remote_root"
  "$provider" run "$vm_name" sudo bash \
    /mnt/mithril-source/crates/mithril-e2e/harness/vm/guest.sh \
    k3s-runtime-hook \
    /mnt/mithril-source/crates/mithril-e2e/fixtures/identity/oci-prestart-admission-v1.sh \
    "$remote_root"
  "$provider" run "$vm_name" \
    'sudo apt-get update && sudo apt-get install -y --no-install-recommends iproute2 net-tools nftables'
  "$provider" run "$vm_name" "set -e; cd '$remote_root'; \
    archive='$remote_root/k9s_Linux_amd64.tar.gz'; \
    checksums='$remote_root/k9s-checksums.sha256'; \
    curl --fail --location --silent --show-error --output \"\$archive\" \
      https://github.com/derailed/k9s/releases/download/v0.51.0/k9s_Linux_amd64.tar.gz; \
    curl --fail --location --silent --show-error --output \"\$checksums\" \
      https://github.com/derailed/k9s/releases/download/v0.51.0/checksums.sha256; \
    awk '\$2 == \"k9s_Linux_amd64.tar.gz\" { print; found = 1 } END { exit !found }' \
      \"\$checksums\" | sha256sum --check --status -; \
    tar -xzf \"\$archive\" -C '$remote_root' k9s; \
    sudo install -m 0755 '$remote_root/k9s' /usr/local/bin/k9s; \
    rm -f -- \"\$archive\" \"\$checksums\" '$remote_root/k9s'"
  "$provider" run "$vm_name" "sudo install -d -o ubuntu -g ubuntu -m 0700 -- /home/ubuntu/.kube && \
    sudo install -o ubuntu -g ubuntu -m 0600 /etc/rancher/k3s/k3s.yaml /home/ubuntu/.kube/config && \
    sudo install -d -m 0700 -- /root/.kube && \
    sudo install -m 0600 /etc/rancher/k3s/k3s.yaml /root/.kube/config && \
    sudo ln -sfn /usr/local/bin/k3s /usr/local/bin/crictl && \
    sudo ln -sfn /usr/local/bin/k3s /usr/local/bin/kubectl && \
    printf '%s\\n' 'export MITHRIL_MANUAL_SOURCE=/mnt/mithril-source' \
      'export MITHRIL_BIN_DIRECTORY=/mnt/mithril-source/target/debug' | \
      sudo tee /var/tmp/mithril-manual.env >/dev/null && \
    sudo chmod 0644 /var/tmp/mithril-manual.env"
  echo "Manual VM ready. SSH, then run: sudo -i; . /var/tmp/mithril-manual.env"
  exit 0
fi

"$provider" run "$vm_name" \
  'sudo apt-get update && sudo apt-get install -y --no-install-recommends iproute2 nftables runc'

"$provider" run "$vm_name" mkdir -p \
  "$remote_source/bpf/erebor-interceptor/qualification" \
  "$remote_source/crates/mithril-e2e/fixtures/hugging-face/platforms" \
  "$remote_source/crates/mithril-e2e/fixtures/hugging-face/protected" \
  "$remote_source/crates/mithril-e2e/fixtures/identity" \
  "$remote_source/crates/mithril-e2e/fixtures/mithril-policy" \
  "$remote_source/crates/mithril-e2e/harness/vm" \
  "$remote_root/harness" "$remote_bin"

"$provider" put "$vm_name" "$repo_root/target/debug/mithril-identity-test" \
  "$remote_bin/mithril-identity-test"
"$provider" put "$vm_name" "$repo_root/target/debug/mithril-effect-test" \
  "$remote_bin/mithril-effect-test"
"$provider" put "$vm_name" "$repo_root/target/debug/mithril-network-test" \
  "$remote_bin/mithril-network-test"
"$provider" put "$vm_name" "$repo_root/target/debug/mithril-inspect" \
  "$remote_bin/mithril-inspect"
"$provider" put "$vm_name" "$repo_root/target/debug/mithril-node" \
  "$remote_bin/mithril-node"
"$provider" put "$vm_name" "$repo_root/target/debug/mithril-policy" \
  "$remote_bin/mithril-policy"
"$provider" put "$vm_name" "$repo_root/target/debug/mithril-control" \
  "$remote_bin/mithril-control"
"$provider" put "$vm_name" "$repo_root/target/debug/kubectl-mithril" \
  "$remote_bin/kubectl-mithril"
"$provider" put "$vm_name" "$repo_root/target/debug/mithril-kernel-qualification" \
  "$remote_bin/mithril-kernel-qualification"
"$provider" put "$vm_name" "$qualification_build/feasibility.bpf.o" \
  "$remote_bin/feasibility.bpf.o"
"$provider" put "$vm_name" \
  "$repo_root/bpf/erebor-interceptor/qualification/feasibility.bpf.c" \
  "$remote_source/bpf/erebor-interceptor/qualification/feasibility.bpf.c"
"$provider" put "$vm_name" "$directory/guest.sh" \
  "$remote_root/harness/guest.sh"
for fixture in \
  kubernetes-entry-workload-v1.yaml \
  kubernetes-lifecycle-sleep-workload-v1.yaml \
  kubernetes-network-probes-workload-v1.yaml \
  kubernetes-containers-workload-v1.yaml \
  kubernetes-ephemeral-workload-v1.yaml \
  kubernetes-probe-impersonation-workload-v1.yaml \
  kubernetes-prestop-workload-v1.yaml \
  kubernetes-poststart-workload-v1.yaml \
  kubernetes-resilience-workload-v1.yaml \
  kubernetes-stock-hook-failure-workload-v1.yaml; do
  "$provider" put "$vm_name" \
    "$repo_root/crates/mithril-e2e/fixtures/identity/$fixture" \
    "$remote_source/crates/mithril-e2e/fixtures/identity/$fixture"
done
"$provider" put "$vm_name" \
  "$repo_root/crates/mithril-e2e/fixtures/identity/oci-prestart-admission-v1.sh" \
  "$remote_source/crates/mithril-e2e/fixtures/identity/oci-prestart-admission-v1.sh"
for fixture in observe-profile-seal-request.json test-public-key.hex test-signing-key.hex observe-policy-v1.yaml; do
  "$provider" put "$vm_name" \
    "$repo_root/crates/mithril-e2e/fixtures/mithril-policy/$fixture" \
    "$remote_source/crates/mithril-e2e/fixtures/mithril-policy/$fixture"
done
"$provider" put "$vm_name" \
  "$repo_root/crates/mithril-e2e/fixtures/mithril-policy/protect-policy-v1.yaml" \
  "$remote_source/crates/mithril-e2e/fixtures/mithril-policy/protect-policy-v1.yaml"
for fixture in \
  fixture.json baseline.json replay.jsonl \
  platforms/node-a.json platforms/node-b.json \
  protected/image-digest.txt protected/network.json protected/rbac.yaml \
  protected/topology.json protected/workload.yaml; do
  "$provider" put "$vm_name" \
    "$repo_root/crates/mithril-e2e/fixtures/hugging-face/$fixture" \
    "$remote_source/crates/mithril-e2e/fixtures/hugging-face/$fixture"
done

"$provider" run "$vm_name" sudo bash "$remote_root/harness/guest.sh" \
  platform "$remote_bin/mithril-inspect" "$remote_root" \
  >"$output_directory/platform.txt"

identity_output=$remote_root/identity
"$provider" run "$vm_name" sudo "$remote_bin/mithril-identity-test" \
  --repo-root "$remote_source" --output-directory "$identity_output" \
  physical-probe --pin-root "/sys/fs/bpf/$vm_name-identity" \
  --lease-path "$identity_output/owner.lock" \
  --cgroup-path "/sys/fs/cgroup/$vm_name-identity"
"$provider" get "$vm_name" "$identity_output/identity-physical-probe.json" \
  "$output_directory/identity-physical-probe.json"

prepared_output=$remote_root/stock-runc-prepared
"$provider" run "$vm_name" sudo "$remote_bin/mithril-effect-test" \
  --repo-root "$remote_source" runc-prepared-probe \
  --output-directory "$prepared_output" \
  --pin-root "/sys/fs/bpf/$vm_name-stock-runc-prepared" \
  --lease-path "$prepared_output/owner.lock" \
  --runc-path /usr/sbin/runc --workload-path /usr/bin/sleep \
  --prestart-hook \
  "$remote_source/crates/mithril-e2e/fixtures/identity/oci-prestart-admission-v1.sh"
"$provider" get "$vm_name" "$prepared_output/runc-prepared-probe.json" \
  "$output_directory/runc-prepared-probe.json"

observation_output=$remote_root/effect-observation
"$provider" run "$vm_name" sudo "$remote_bin/mithril-effect-test" \
  --repo-root "$remote_source" physical-probe \
  --output-directory "$observation_output" \
  --pin-root "/sys/fs/bpf/$vm_name-effect-observation" \
  --lease-path "$observation_output/owner.lock" \
  --cgroup-path "/sys/fs/cgroup/$vm_name-effect-observation"
"$provider" get "$vm_name" "$observation_output/effect-physical-probe.json" \
  "$output_directory/effect-observation-physical-probe.json"

enforcement_output=$remote_root/local-enforcement
"$provider" run "$vm_name" sudo "$remote_bin/mithril-effect-test" \
  --repo-root "$remote_source" physical-probe --protect \
  --output-directory "$enforcement_output" \
  --pin-root "/sys/fs/bpf/$vm_name-local-enforcement" \
  --lease-path "$enforcement_output/owner.lock" \
  --cgroup-path "/sys/fs/cgroup/$vm_name-local-enforcement"
"$provider" get "$vm_name" "$enforcement_output/effect-physical-probe.json" \
  "$output_directory/local-enforcement-physical-probe.json"

if [[ $with_k3s == true ]]; then
  run_k3s_cri_effect() {
    local effect_mode=$1
    "$provider" run "$vm_name" sudo env \
      "MITHRIL_VM_CRI_EFFECT_MODE=$effect_mode" \
      bash "$remote_root/harness/guest.sh" \
      k3s-cri-effect "$remote_bin/mithril-node" "$remote_bin/mithril-inspect" \
      "$remote_bin/mithril-policy" \
      "$remote_source/crates/mithril-e2e/harness/vm/k3s-cri-effect-node-v1.json" \
      "$remote_source/crates/mithril-e2e/fixtures/mithril-policy/observe-policy-v1.yaml" \
      "$remote_source/crates/mithril-e2e/fixtures/mithril-policy/observe-profile-seal-request.json" \
      "$remote_source/crates/mithril-e2e/fixtures/mithril-policy/test-signing-key.hex" \
      "$remote_source/crates/mithril-e2e/fixtures/mithril-policy/test-public-key.hex" \
      "$remote_root/harness/k3s-workload-v1.yaml" "$remote_root"
  }
  "$provider" put "$vm_name" "$directory/k3s-config-v1.yaml" \
    "$remote_root/harness/k3s-config-v1.yaml"
  "$provider" put "$vm_name" "$directory/k3s-workload-v1.yaml" \
    "$remote_root/harness/k3s-workload-v1.yaml"
  "$provider" put "$vm_name" "$directory/k3s-cri-effect-node-v1.json" \
    "$remote_source/crates/mithril-e2e/harness/vm/k3s-cri-effect-node-v1.json"
  "$provider" put "$vm_name" "$directory/k3s-administrative-node-v1.json" \
    "$remote_root/harness/k3s-administrative-node-v1.json"
  "$provider" put "$vm_name" "$directory/k3s-administrative-policy-v1.yaml" \
    "$remote_root/harness/k3s-administrative-policy-v1.yaml"
  "$provider" put "$vm_name" "$directory/oidc-fixture.py" \
    "$remote_root/harness/oidc-fixture.py"
  "$provider" run "$vm_name" sudo bash "$remote_root/harness/guest.sh" \
    k3s-install "$k3s_version" "$remote_root/harness/k3s-config-v1.yaml" \
    "$remote_root"
  "$provider" run "$vm_name" sudo bash "$remote_root/harness/guest.sh" \
    k3s-runtime-hook \
    "$remote_source/crates/mithril-e2e/fixtures/identity/oci-prestart-admission-v1.sh" \
    "$remote_root"
  "$provider" run "$vm_name" sudo bash "$remote_root/harness/guest.sh" \
    k3s-qualify "$remote_root/harness/k3s-workload-v1.yaml" "$remote_root" \
    >"$output_directory/k3s.txt"
  k3s_cri_observe_partial=$output_directory/k3s-cri-observe.txt.partial
  run_k3s_cri_effect OBSERVE >"$k3s_cri_observe_partial"
  mv -- "$k3s_cri_observe_partial" "$output_directory/k3s-cri-observe.txt"
  k3s_cri_effect_partial=$output_directory/k3s-cri-effect.txt.partial
  run_k3s_cri_effect PROTECT >"$k3s_cri_effect_partial"
  mv -- "$k3s_cri_effect_partial" "$output_directory/k3s-cri-effect.txt"
  if [[ $skip_administrative_exec == false ]]; then
    k3s_administrative_partial=$output_directory/k3s-administrative-exec.txt.partial
    administrative_command=(sudo)
    if [[ $keep_vm == true ]]; then
      administrative_command=(sudo env MITHRIL_VM_KEEP_FAILURE_STATE=true)
    fi
    "$provider" run "$vm_name" "${administrative_command[@]}" bash "$remote_root/harness/guest.sh" \
      k3s-administrative-exec "$remote_bin/mithril-control" \
      "$remote_bin/mithril-node" "$remote_bin/mithril-inspect" \
      "$remote_bin/mithril-policy" "$remote_bin/kubectl-mithril" \
      "$remote_root/harness/oidc-fixture.py" \
      "$remote_root/harness/k3s-administrative-node-v1.json" \
      "$remote_root/harness/k3s-administrative-policy-v1.yaml" \
      "$remote_source/crates/mithril-e2e/fixtures/mithril-policy/observe-profile-seal-request.json" \
      "$remote_source/crates/mithril-e2e/fixtures/mithril-policy/test-signing-key.hex" \
      "$remote_source/crates/mithril-e2e/fixtures/mithril-policy/test-public-key.hex" \
      "$remote_root/harness/k3s-workload-v1.yaml" "$remote_root" \
      >"$k3s_administrative_partial"
    mv -- "$k3s_administrative_partial" \
      "$output_directory/k3s-administrative-exec.txt"
  fi
fi

qualification_output=$remote_root/kernel-qualification
"$provider" run "$vm_name" sudo "$remote_bin/mithril-kernel-qualification" \
  --repo-root "$remote_source" physical-probe \
  --output-directory "$qualification_output" \
  --bpf-object "$remote_bin/feasibility.bpf.o"
"$provider" run "$vm_name" sudo "$remote_bin/mithril-kernel-qualification" \
  --repo-root "$remote_source" benchmark \
  --target "$remote_source/bpf/erebor-interceptor/qualification/feasibility.bpf.c" \
  --mode baseline --output "$qualification_output/baseline-open-benchmark.json"
"$provider" run "$vm_name" sudo "$remote_bin/mithril-kernel-qualification" \
  --repo-root "$remote_source" benchmark \
  --target "$remote_source/bpf/erebor-interceptor/qualification/feasibility.bpf.c" \
  --mode protected --bpf-object "$remote_bin/feasibility.bpf.o" \
  --output "$qualification_output/protected-open-benchmark.json"
"$provider" get "$vm_name" \
  "$qualification_output/physical-file-open-probe.json" \
  "$output_directory/physical-file-open-probe.json"
"$provider" get "$vm_name" \
  "$qualification_output/baseline-open-benchmark.json" \
  "$output_directory/baseline-open-benchmark.json"
"$provider" get "$vm_name" \
  "$qualification_output/protected-open-benchmark.json" \
  "$output_directory/protected-open-benchmark.json"
"$repo_root/target/debug/mithril-kernel-qualification" \
  --repo-root "$repo_root" record-physical-qualification \
  --physical-probe "$output_directory/physical-file-open-probe.json" \
  --baseline-benchmark "$output_directory/baseline-open-benchmark.json" \
  --protected-benchmark "$output_directory/protected-open-benchmark.json" \
  --probe-binary "$repo_root/target/debug/mithril-kernel-qualification" \
  --output "$output_directory/kernel-qualification-x86_64.json"

network_output=$remote_root/network-enforcement
"$provider" run "$vm_name" sudo "$remote_bin/mithril-network-test" \
  --repo-root "$remote_source" physical-probe \
  --output-directory "$network_output" \
  --pin-root "/sys/fs/bpf/$vm_name-network-enforcement" \
  --lease-path "$network_output/owner.lock" \
  --cgroup-path "/sys/fs/cgroup/$vm_name-network-enforcement"
"$provider" get "$vm_name" "$network_output/network-physical-probe.json" \
  "$output_directory/network-physical-probe.json"

if [[ $with_k3s == true ]]; then
  kubernetes_identity_output=$remote_root/kubernetes-identity
  "$provider" run "$vm_name" sudo "$remote_bin/mithril-identity-test" \
    --repo-root "$remote_source" --output-directory "$kubernetes_identity_output" \
    physical-probe --pin-root "/sys/fs/bpf/$vm_name-kubernetes-identity" \
    --lease-path "$kubernetes_identity_output/owner.lock" \
    --cgroup-path "/sys/fs/cgroup/$vm_name-kubernetes-identity" \
    --with-kubernetes \
    --previous-bundle "$identity_output/identity-physical-probe.json"
  "$provider" get "$vm_name" \
    "$kubernetes_identity_output/identity-physical-probe.json" \
    "$output_directory/identity-physical-probe.json"
fi

verify_absent() {
  local path=$1
  "$provider" run "$vm_name" sudo test ! -e "$path" || {
    echo "VM probe left an owned artifact: $path" >&2
    return 1
  }
}

verify_absent "/sys/fs/bpf/$vm_name-identity"
verify_absent "/sys/fs/bpf/$vm_name-stock-runc-prepared"
verify_absent "/sys/fs/bpf/$vm_name-effect-observation"
verify_absent "/sys/fs/bpf/$vm_name-local-enforcement"
verify_absent "/sys/fs/bpf/$vm_name-network-enforcement"
verify_absent "/sys/fs/cgroup/$vm_name-identity"
verify_absent "/sys/fs/cgroup/$vm_name-effect-observation"
verify_absent "/sys/fs/cgroup/$vm_name-local-enforcement"
verify_absent "/sys/fs/cgroup/$vm_name-network-enforcement"
verify_absent "$identity_output/owner.lock"
verify_absent "$prepared_output/owner.lock"
if [[ $with_k3s == true ]]; then
  verify_absent "$remote_root/kubernetes-identity/kubernetes-entry"
  verify_absent "$remote_root/kubernetes-identity/owner.lock"
  verify_absent "/sys/fs/bpf/$vm_name-kubernetes-identity"
  verify_absent "/sys/fs/cgroup/$vm_name-kubernetes-identity"
fi
verify_absent "$observation_output/owner.lock"
verify_absent "$enforcement_output/owner.lock"
verify_absent "$network_output/owner.lock"
verify_absent "$remote_bin/feasibility.bpf.owner.lock"

if [[ $with_k3s == true ]]; then
  "$provider" run "$vm_name" sudo bash "$remote_root/harness/guest.sh" \
    k3s-remove "$remote_root"
fi

echo "Kernel, identity, stock-runc, effect-observation, local-enforcement, and network-enforcement VM probes passed. Evidence: $output_directory"
