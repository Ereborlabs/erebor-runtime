#!/usr/bin/env bash

set -Eeuo pipefail

trap 'echo "two-node convergence failed at line $LINENO: $BASH_COMMAND" >&2' ERR

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/convergence-cleanup.sh"
source "$directory/clock.sh"
source "$directory/../kubernetes-oracles.sh"
repo_root=$(cd -- "$directory/../../../.." && pwd)
provider=$directory/providers/libvirt.sh
output_directory=
keep_vms=false
manual_environment=false
protected_start_only=false
lightweight_only=false
reuse_environment=
k3s_version=${MITHRIL_VM_K3S_VERSION:-v1.35.5+k3s1}
reuse_images=${MITHRIL_VM_REUSE_IMAGES:-false}
system_namespace=mithril-system
workload_namespace=mithril-convergence
runtime_hook_owner=$system_namespace/mithril
runtime_hook_socket=/run/mithril/runtime-admission.sock
run_id=$(date -u +%Y%m%d%H%M%S)-$$
node_state_host_path=/var/lib/mithril-node-$run_id
control_config_secret=mithril-control-config-$run_id
control_state_claim=mithril-control-state-$run_id
admission_tls_secret=mithril-admission-tls-$run_id
reuse_mithril_state=false
retained_mithril_state_ready=false
entry_effect_capture_pids=()
runtime_sockets_held=false
held_runtime_socket=$runtime_hook_socket.gate-$run_id

usage() {
  echo "usage: $0 [--provider PATH] [--output-directory PATH] [--keep-vms] [--manual-environment] [--protected-start-only] [--lightweight-only] [--reuse-environment PATH]" >&2
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
    --lightweight-only)
      lightweight_only=true
      keep_vms=true
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

required_commands=(cargo jq timeout)
if [[ $lightweight_only == false ]]; then
  required_commands+=(base64 docker helm openssl sed sha256sum)
fi
for command in "${required_commands[@]}"; do
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
if [[ $manual_environment == true && -z $reuse_environment &&
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
  jq -e '.schema_version == 2' "$reuse_environment" >/dev/null
  IFS=$'\t' read -r state control_claim control_secret admission_secret \
    < <(retained_mithril_state "$reuse_environment")
  if [[ $state == retained ]]; then
    control_state_claim=$control_claim
    control_config_secret=$control_secret
    admission_tls_secret=$admission_secret
    reuse_mithril_state=true
    retained_mithril_state_ready=true
  fi
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
      ( $lightweight_only == true || -r $work_a/kubeconfig.yaml ) ]] || {
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
[[ $lightweight_only == false || $reusing_environment == true ]] || {
  echo "--lightweight-only requires --reuse-environment" >&2
  exit 2
}

run_lightweight_upgrade_probe() {
  local vm=$1
  local remote_root=$2
  local hook=$3
  local remote=$remote_root/runtime-gate-lightweight-$run_id

  "$provider" run "$vm" mkdir -p "$remote"
  "$provider" put "$vm" "$repo_root/target/debug/mithril-effect-test" \
    "$remote/mithril-effect-test"
  "$provider" put "$vm" "$hook" "$remote/mithril-oci-hook"
  "$provider" run "$vm" sudo "$remote/mithril-effect-test" \
    --repo-root "$remote" runc-retained-runtime-gate-probe \
    --output-directory "$remote/evidence" \
    --runc-path /var/lib/rancher/k3s/data/current/bin/runc \
    --hook-path "$remote/mithril-oci-hook"
  "$provider" get "$vm" \
    "$remote/evidence/runc-retained-runtime-gate-probe.json" \
    "$output_directory/runc-retained-runtime-gate-probe.json"
  jq -e '
    .hostile_container_denied == true and
    .hostile_process_never_started == true and
    .hostile_decision_logged == true and
    .cri_sandbox_allowed == true and
    .cri_sandbox_process_started == true and
    .cri_sandbox_decision_logged == true and
    .forged_cri_sandbox_denied == true and
    .forged_cri_sandbox_process_never_started == true and
    .forged_cri_sandbox_decision_logged == true and
    .exact_recovery_allowed == true and
    .exact_recovery_process_started == true and
    .exact_recovery_decision_logged == true and
    .exact_control_recovery_allowed == true and
    .exact_control_recovery_process_started == true and
    .exact_control_recovery_decision_logged == true and
    .changed_control_recovery_denied == true and
    .changed_control_recovery_process_never_started == true and
    .changed_control_recovery_decision_logged == true and
    .version_changed_control_recovery_allowed == true and
    .version_changed_control_recovery_process_started == true and
    .exact_installer_allowed == true and
    .exact_installer_process_started == true and
    .changed_installer_allowed == true and
    .changed_installer_process_started == true and
    .changed_installer_decision_logged == true and
    .forged_installer_denied == true and
    .forged_installer_process_never_started == true and
    .forged_installer_decision_logged == true and
    .version_changed_node_recovery_allowed == true and
    .version_changed_node_recovery_process_started == true and
    .changed_recovery_denied == true and
    .changed_recovery_process_never_started == true and
    .unavailable_decision_logged == true and
    .host_stock_spec_generated == true and
    .fixture_root_removed == true
  ' "$output_directory/runc-retained-runtime-gate-probe.json" >/dev/null
  "$provider" run "$vm" sudo rm -rf -- "$remote"
}

if [[ $lightweight_only == true ]]; then
  echo "Building the lightweight retained-upgrade probe"
  (cd -- "$repo_root" && cargo build --locked \
    -p mithril-e2e --bin mithril-effect-test && \
    cargo rustc --locked -p mithril-node --bin mithril-oci-hook -- \
      -C target-feature=+crt-static)
  "$provider" wait "$vm_a"
  remote_a=/var/tmp/$vm_a
  "$provider" run "$vm_a" mkdir -p "$remote_a"
  run_lightweight_upgrade_probe "$vm_a" "$remote_a" \
    "$repo_root/target/debug/mithril-oci-hook"
  echo "Mithril lightweight upgrade qualification passed"
  exit 0
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

request_vm_reboot() {
  local vm=$1
  local status

  set +e
  timeout --kill-after=5s 20s "$provider" run "$vm" \
    sudo systemctl reboot --no-block >/dev/null 2>&1
  status=$?
  set -e
  case $status in
    0 | 124 | 255) ;;
    *)
      echo "the reboot request failed for $vm with status $status" >&2
      return "$status"
      ;;
  esac
  if ! "$provider" wait "$vm"; then
    echo "the rebooted VM did not pass the provider readiness gate: $vm" >&2
    return 1
  fi
}

synchronize_vm_clock() {
  local vm=$1
  local host_epoch
  local guest_epoch

  host_epoch=$(date -u +%s)
  guest_epoch=$("$provider" run "$vm" date -u +%s)
  if clock_is_within_tolerance "$host_epoch" "$guest_epoch" 15; then
    return 0
  fi

  # A libvirt I/O pause stops the guest clock. Advance it before generated TLS
  # identities reach K3s admission, which rejects a future NotBefore value.
  "$provider" run "$vm" sudo date -u --set "@$host_epoch" >/dev/null
  guest_epoch=$("$provider" run "$vm" date -u +%s)
  clock_is_within_tolerance "$(date -u +%s)" "$guest_epoch" 15 || {
    echo "VM clock did not converge with the certificate owner: $vm" >&2
    return 1
  }
}

assert_runtime_hook() {
  local state=$1
  local node=$2
  local remote=$3
  local arguments=("$state" /)
  if [[ $state == installed || $state == retained ]]; then
    arguments+=("$runtime_hook_owner" "$runtime_hook_socket" 4000 5)
  else
    arguments+=("$runtime_hook_socket")
  fi
  if [[ $state == installed ]]; then
    timeout 20s "$provider" run "$node" sudo bash \
      "$remote/harness/runtime-hook-oracle.sh" "${arguments[@]}"
    return
  fi
  # Runtime socket removal follows DaemonSet termination. Host integration stays.
  for _attempt in {1..30}; do
    if timeout 10s "$provider" run "$node" sudo bash \
        "$remote/harness/runtime-hook-oracle.sh" "${arguments[@]}" \
        >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "Mithril runtime integration did not reach $state on $node" >&2
  return 1
}

stop_entry_effect_capture() {
  local node
  local pid
  for pid in "${entry_effect_capture_pids[@]}"; do
    kill "$pid" >/dev/null 2>&1 || true
  done
  for pid in "${entry_effect_capture_pids[@]}"; do
    wait "$pid" >/dev/null 2>&1 || true
  done
  entry_effect_capture_pids=()
  for node in "${vm_a:-}" "${vm_b:-}"; do
    [[ -n $node && -x ${provider:-} ]] || continue
    "$provider" run "$node" \
      'for process in /proc/[0-9]*; do read -r name < "$process/comm" || continue; [ "$name" = mithril-inspect ] || continue; sudo kill "${process##*/}"; done' \
      >/dev/null 2>&1 || true
  done
}

restore_runtime_sockets() {
  local node
  if [[ $runtime_sockets_held == false ]]; then
    return 0
  fi
  for node in "$vm_a" "$vm_b"; do
    if "$provider" run "$node" sudo test -S "$held_runtime_socket"; then
      "$provider" run "$node" sudo mv -- \
        "$held_runtime_socket" "$runtime_hook_socket"
    fi
  done
  runtime_sockets_held=false
}

cleanup() {
  local original_status=$?
  local cleanup_failed=false
  local cleanup_result_file
  local resources_removed
  trap - EXIT
  set +e
  stop_entry_effect_capture
  restore_runtime_sockets || cleanup_failed=true
  if ((original_status != 0)) && [[ $cluster_created == true ]]; then
    collect_mithril_diagnostics "$output_directory" "$system_namespace" \
      "$workload_namespace" || cleanup_failed=true
  fi
  remove_mithril_release "$cluster_created" "$keep_vms" \
    "$manual_environment" "$kubeconfig" "$system_namespace" || cleanup_failed=true
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
    write_retained_environment \
      "$output_directory/retained-environment.json" \
      "$retained_mithril_state_ready" \
      "$vm_a" "$work_a" "$vm_b" "$work_b" "$provider" \
      "$MITHRIL_VM_KNOWN_HOSTS" "$control_state_claim" \
      "$control_config_secret" "$admission_tls_secret" || cleanup_failed=true
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
(cd -- "$repo_root" && cargo build --locked \
  -p mithril-control --bin mithril-policy \
  -p mithril-e2e --bin mithril-effect-test)
if [[ $reuse_images == true ]]; then
  echo "Reusing the local Mithril owner images"
  docker image inspect \
    mithril-node:convergence mithril-control:convergence \
    mithril-node:upgrade-baseline mithril-control:upgrade-baseline >/dev/null
else
  echo "Building the packaged Mithril owners"
  (cd -- "$repo_root" && docker build --file packaging/mithril/Dockerfile \
    --target node --tag mithril-node:convergence .)
  (cd -- "$repo_root" && docker build --file packaging/mithril/Dockerfile \
    --target control --tag mithril-control:convergence .)
  echo "Building the prior-version upgrade fixtures"
  (cd -- "$repo_root" && docker build \
    --file crates/mithril-e2e/fixtures/convergence/Dockerfile.upgrade-baseline \
    --target node --tag mithril-node:upgrade-baseline .)
  (cd -- "$repo_root" && docker build \
    --file crates/mithril-e2e/fixtures/convergence/Dockerfile.upgrade-baseline \
    --target control --tag mithril-control:upgrade-baseline .)
fi
docker run --rm --entrypoint /bin/cp \
  --user "$(id -u):$(id -g)" \
  --volume "$work_a:/output" mithril-node:convergence \
  /usr/local/bin/mithril-oci-hook /output/mithril-oci-hook
docker run --rm --entrypoint /bin/cp \
  --user "$(id -u):$(id -g)" \
  --volume "$work_a:/output" mithril-node:upgrade-baseline \
  /usr/local/bin/mithril-oci-hook /output/mithril-oci-hook-upgrade-baseline
chmod 755 "$work_a/mithril-oci-hook"
chmod 755 "$work_a/mithril-oci-hook-upgrade-baseline"
current_hook_digest=$(sha256sum "$work_a/mithril-oci-hook" | awk '{print $1}')
baseline_hook_digest=$(sha256sum "$work_a/mithril-oci-hook-upgrade-baseline" | awk '{print $1}')
[[ $current_hook_digest != "$baseline_hook_digest" ]] || {
  echo "the upgrade fixture did not change the runtime hook binary" >&2
  exit 1
}
image_archive=$work_a/mithril-images.tar
docker save --output "$image_archive" \
  mithril-node:convergence mithril-control:convergence \
  mithril-node:upgrade-baseline mithril-control:upgrade-baseline

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
synchronize_vm_clock "$vm_a"
synchronize_vm_clock "$vm_b"
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
  "$provider" put "$node" "$directory/concurrent-exec-overlap.sh" \
    "$remote/harness/concurrent-exec-overlap.sh"
  "$provider" put "$node" "$directory/k3s-config-v1.yaml" \
    "$remote/harness/k3s-config-v1.yaml"
  "$provider" put "$node" "$image_archive" "$remote/mithril-images.tar"
  if ! "$provider" run "$node" \
      'command -v jq >/dev/null && command -v openssl >/dev/null'; then
    "$provider" run "$node" \
      'sudo apt-get update && sudo apt-get install -y --no-install-recommends jq openssl'
  fi
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

if [[ $reusing_environment == true ]]; then
  retained_state_a=false
  retained_state_b=false
  "$provider" run "$vm_a" sudo test -f \
    /var/lib/rancher/k3s/agent/etc/containerd/mithril-recovery.json && \
    retained_state_a=true
  "$provider" run "$vm_b" sudo test -f \
    /var/lib/rancher/k3s/agent/etc/containerd/mithril-recovery.json && \
    retained_state_b=true
  [[ $retained_state_a == "$retained_state_b" ]] || {
    echo "retained nodes disagree about the Mithril recovery manifest" >&2
    exit 1
  }
  [[ $retained_state_a == "$reuse_mithril_state" ]] || {
    echo "retained environment does not match its durable Mithril state" >&2
    exit 1
  }
  if [[ $retained_state_a == true ]]; then
    retained_node_state_a=$("$provider" run "$vm_a" sudo bash \
      "$remote_a/harness/runtime-hook-oracle.sh" node-state-path /)
    retained_node_state_b=$("$provider" run "$vm_b" sudo bash \
      "$remote_b/harness/runtime-hook-oracle.sh" node-state-path /)
    [[ $retained_node_state_a == "$retained_node_state_b" ]] || {
      echo "retained nodes disagree about the Mithril Node state path" >&2
      exit 1
    }
    node_state_host_path=$retained_node_state_a
  fi
fi

run_lightweight_upgrade_probe "$vm_a" "$remote_a" \
  "$work_a/mithril-oci-hook"

remote_kubectl() {
  local command

  printf -v command '%q ' sudo /usr/local/bin/k3s kubectl "$@"
  "$provider" run "$vm_a" "$command"
}

signal_pod_request() {
  local vm=$1
  local path=$2
  local request=$3

  "$provider" run "$vm" \
    "printf '%s\\n' '$request' | timeout 30 sudo tee '$path' >/dev/null"
}

remove_retained_kubernetes_resources() {
  local node
  local node_name
  local protected_node

  echo "Removing the prior Mithril release from the retained K3s cluster"
  if remote_kubectl get namespace "$workload_namespace" >/dev/null 2>&1; then
    protected_node=$(remote_kubectl -n "$workload_namespace" get pod protected \
      -o json 2>/dev/null | jq -r \
      'select(.status.phase == "Running") | .spec.nodeName' || true)
    if [[ -n $protected_node ]]; then
      for node in "$vm_a" "$vm_b"; do
        node_name=$("$provider" run "$node" hostname)
        [[ $node_name == "$protected_node" ]] || continue
        if "$provider" run "$node" sudo test -d \
            /var/lib/mithril-convergence/markers; then
          signal_pod_request "$node" \
            /var/lib/mithril-convergence/markers/protected.application-request \
            APPLICATION || true
          signal_pod_request "$node" \
            /var/lib/mithril-convergence/markers/protected.exception-request \
            EXCEPTION || true
          signal_pod_request "$node" \
            /var/lib/mithril-convergence/markers/protected.restart RESTART || true
        fi
      done
    fi
    remote_kubectl delete namespace "$workload_namespace" \
      --wait=true --timeout=180s >/dev/null
  fi
  if helm --kubeconfig "$kubeconfig" status mithril \
      --namespace "$system_namespace" >/dev/null 2>&1; then
    helm --kubeconfig "$kubeconfig" uninstall mithril \
      --namespace "$system_namespace" --wait --timeout=180s >/dev/null
  fi
  remote_kubectl -n "$system_namespace" delete pod forged-upgrade-installer \
    --ignore-not-found --wait=true --timeout=120s >/dev/null
}

if [[ $reusing_environment == true ]]; then
  # Remove admission webhooks before a K3s service restart must register its Node.
  remove_retained_kubernetes_resources
fi

for node in "$vm_a" "$vm_b"; do
  remote=$remote_a
  [[ $node == "$vm_a" ]] || remote=$remote_b
  "$provider" run "$node" sudo /usr/local/bin/k3s ctr images import \
    "$remote/mithril-images.tar" >/dev/null
done

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

replace_retained_test_resources() {
  local node
  local path

  echo "Preparing new Mithril state in the retained K3s cluster"
  # A prior forced Pod loss can leave an unowned socket inode. The new node
  # owner proves that no listener is live before it replaces that inode.
  for node in "$vm_a" "$vm_b"; do
    remote=$remote_a
    [[ $node == "$vm_a" ]] || remote=$remote_b
    if "$provider" run "$node" sudo test -f \
        /usr/libexec/oci/hooks.d/mithril-oci-hook; then
      assert_runtime_hook retained "$node" "$remote"
    fi
  done
  for node in "$vm_a" "$vm_b"; do
    for path in /var/lib/mithril-convergence/markers \
        /sys/fs/bpf/mithril-convergence; do
      if "$provider" run "$node" sudo test -d "$path"; then
        "$provider" run "$node" sudo find "$path" -mindepth 1 -delete
      fi
    done
    if [[ $reuse_mithril_state == false ]]; then
      "$provider" run "$node" sudo rm -f \
        /etc/mithril/node.json /etc/mithril/node.json.held
    fi
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
        maximum_retained_bytes: 268435456,
        maximum_retained_records: 2,
        maximum_batch_records: 4096,
        maximum_control_delay_ms: 30000,
        maximum_reader_queue_records: 65535,
        capacity_policy: "RETAIN"
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
if ! remote_kubectl get namespace "$system_namespace" >/dev/null 2>&1; then
  remote_kubectl create namespace "$system_namespace" >/dev/null
fi

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
    evidence_store: {
      maximum_retained_bytes: 1073741824,
      maximum_retained_records: 1000000,
      capacity_policy: "RETAIN"
    },
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
  if [[ $reusing_environment == true ]]; then
    "$provider" run "$node" sudo install -m 0400 \
      "$remote/materials/node.json" /etc/mithril/node.json
    "$provider" run "$node" sudo bash \
      "$remote/harness/runtime-hook-oracle.sh" recovery-inputs /
  fi
done

if [[ $reuse_mithril_state == false ]]; then
  remote_kubectl -n "$system_namespace" create secret generic "$control_config_secret" \
    --from-file=control.json="$remote_a/materials/control.json" \
    --from-file=policy-signing-key="$remote_a/materials/policy-signing-key" \
    --from-file=profile-seal-request.json="$remote_a/materials/profile-seal-request.json" \
    --from-file=ca.pem="$remote_a/materials/ca.pem" \
    --from-file=tls.crt="$remote_a/materials/tls.crt" \
    --from-file=tls.key="$remote_a/materials/tls.key" >/dev/null
  remote_kubectl -n "$system_namespace" create secret tls "$admission_tls_secret" \
    --cert="$remote_a/materials/tls.crt" --key="$remote_a/materials/tls.key" >/dev/null

  pvc=$work_a/control-pvc.yaml
  cat >"$pvc" <<EOF
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: $control_state_claim
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
else
  control_secret_manifest=$work_a/control-secret.json
  admission_secret_manifest=$work_a/admission-secret.json
  remote_kubectl -n "$system_namespace" create secret generic "$control_config_secret" \
    --from-file=control.json="$remote_a/materials/control.json" \
    --from-file=policy-signing-key="$remote_a/materials/policy-signing-key" \
    --from-file=profile-seal-request.json="$remote_a/materials/profile-seal-request.json" \
    --from-file=ca.pem="$remote_a/materials/ca.pem" \
    --from-file=tls.crt="$remote_a/materials/tls.crt" \
    --from-file=tls.key="$remote_a/materials/tls.key" \
    --dry-run=client -o json >"$control_secret_manifest"
  remote_kubectl -n "$system_namespace" create secret tls "$admission_tls_secret" \
    --cert="$remote_a/materials/tls.crt" --key="$remote_a/materials/tls.key" \
    --dry-run=client -o json >"$admission_secret_manifest"
  "$provider" put "$vm_a" "$control_secret_manifest" \
    "$remote_a/control-secret.json"
  "$provider" put "$vm_a" "$admission_secret_manifest" \
    "$remote_a/admission-secret.json"
  remote_kubectl apply -f "$remote_a/control-secret.json" >/dev/null
  remote_kubectl apply -f "$remote_a/admission-secret.json" >/dev/null
  for node in "$vm_a" "$vm_b"; do
    remote=$remote_a
    [[ $node == "$vm_a" ]] || remote=$remote_b
    "$provider" run "$node" sudo install -d -m 0700 \
      /var/lib/mithril-convergence/markers /run/mithril
    "$provider" run "$node" sudo bash \
      "$remote/harness/runtime-hook-oracle.sh" recovery-inputs /
  done
  remote_kubectl -n "$system_namespace" get secret "$control_config_secret" \
    -o json | jq -e '.data["control.json"] and .data["ca.pem"]' >/dev/null
  remote_kubectl -n "$system_namespace" get secret "$admission_tls_secret" \
    -o json | jq -e '.type == "kubernetes.io/tls"' >/dev/null
  remote_kubectl -n "$system_namespace" get pvc "$control_state_claim" \
    -o json | jq -e '.status.phase == "Bound"' >/dev/null
fi
retained_mithril_state_ready=true

for node in "$vm_a" "$vm_b"; do
  "$provider" run "$node" \
    "sudo install -d -m 0755 /var/lib/mithril-convergence/path-tree/models && \
     printf '%s\n' secret | sudo tee /var/lib/mithril-convergence/path-tree/models/secret >/dev/null"
done

"$provider" run "$vm_a" sudo cp /etc/rancher/k3s/k3s.yaml "$remote_a/kubeconfig.yaml"
"$provider" run "$vm_a" sudo chown ubuntu:ubuntu "$remote_a/kubeconfig.yaml"
"$provider" get "$vm_a" "$remote_a/kubeconfig.yaml" "$kubeconfig"
sed -i "s|https://127.0.0.1:6443|https://$address_a:6443|" "$kubeconfig"
ca_bundle=$(base64 -w0 "$ca")
node_image=mithril-node:upgrade-baseline
control_image=mithril-control:upgrade-baseline
qualify_state_preserving_upgrade=true
if [[ $reuse_mithril_state == true ]]; then
  retained_hook_digest_a=$("$provider" run "$vm_a" sudo sha256sum \
    /usr/libexec/oci/hooks.d/mithril-oci-hook | awk '{print $1}')
  retained_hook_digest_b=$("$provider" run "$vm_b" sudo sha256sum \
    /usr/libexec/oci/hooks.d/mithril-oci-hook | awk '{print $1}')
  [[ $retained_hook_digest_a == "$retained_hook_digest_b" ]] || {
    echo "retained nodes have different runtime-hook versions" >&2
    exit 1
  }
  if [[ $retained_hook_digest_a == "$current_hook_digest" ]]; then
    node_image=mithril-node:convergence
    control_image=mithril-control:convergence
    qualify_state_preserving_upgrade=false
  elif [[ $retained_hook_digest_a != "$baseline_hook_digest" ]]; then
    # The retained gate admits a changed installer by its exact host authority,
    # not by a digest list from the new build.
    node_image=mithril-node:convergence
    control_image=mithril-control:convergence
    qualify_state_preserving_upgrade=false
  fi
fi
values=$work_a/values.yaml
cat >"$values" <<EOF
node:
  image: $node_image
  imagePullPolicy: Never
  logFilter: info,mithril_node::node=debug,mithril_node::policy=debug,mithril_node::runtime_seccomp=debug
  configHostPath: /etc/mithril/node.json
  identityHostPath: /etc/mithril/identity
  stateHostPath: $node_state_host_path
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
    hostBinaryDirectory: /usr/libexec/oci/hooks.d
    containerdConfigHostDirectory: /var/lib/rancher/k3s/agent/etc/containerd
    containerdDropInDirectory: config-v3.toml.d
    runtimeCliHostPath: /usr/local/bin/k3s
    runtimeCliArgs:
      - ctr
      - oci
      - spec
    runtimeServices:
      - k3s
      - k3s-agent
    socketPath: /run/mithril/runtime-admission.sock
    timeoutMs: 4000
    runtimeTimeoutSeconds: 5
control:
  enabled: true
  image: $control_image
  imagePullPolicy: Never
  configSecretName: $control_config_secret
  statePersistentVolumeClaim: $control_state_claim
  grpcPort: 8443
  administrativeExec:
    enabled: false
  # Keep the durable Control owner available while the worker Node UID changes.
  nodeSelector:
    kubernetes.io/hostname: $node_a_name
  admission:
    enabled: true
    port: 9443
    tlsSecretName: $admission_tls_secret
    caBundle: $ca_bundle
    webhookTimeoutSeconds: 5
EOF
current_values=$work_a/values-current.yaml
sed \
  -e 's/mithril-node:upgrade-baseline/mithril-node:convergence/' \
  -e 's/mithril-control:upgrade-baseline/mithril-control:convergence/' \
  "$values" >"$current_values"
helm --kubeconfig "$kubeconfig" upgrade --install mithril \
  "$repo_root/packaging/mithril/helm" --namespace "$system_namespace" \
  --values "$values"
retry_kubernetes_command 30 1 remote_kubectl -n "$system_namespace" \
  rollout status deployment/mithril-control --timeout=10s >/dev/null

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
  local stable_observations=0
  # Hold beyond the configured five-second session TTL to reject transient readiness.
  for _attempt in {1..180}; do
    node_json=$(remote_kubectl get node "$node_name" -o json 2>/dev/null || true)
    if [[ -n $node_json ]] && jq -e '
      .metadata.labels["mithril.erebor.dev/ready"] == "true" and
      (.metadata.annotations["mithril.erebor.dev/node-id"] | length > 0) and
      .metadata.annotations["mithril.erebor.dev/node-uid"] == .metadata.uid and
      (.metadata.annotations["mithril.erebor.dev/node-boot-id"] |
        test("^[0-9a-f]{32}$")) and
      (.metadata.annotations["mithril.erebor.dev/label-epoch"] | tonumber) > 0 and
      all(.spec.taints[]?;
        .key != "mithril.erebor.dev/not-ready" or .effect != "NoSchedule")
    ' <<<"$node_json" >/dev/null; then
      ((stable_observations += 1))
      if ((stable_observations >= 7)); then
        return 0
      fi
    else
      stable_observations=0
    fi
    sleep 1
  done
  echo "Node $node_name did not sustain an authenticated ready projection" >&2
  return 1
}

wait_replaced_node_uid() {
  local node_name=$1
  local old_uid=$2
  local node_json
  for _attempt in {1..300}; do
    node_json=$(remote_kubectl get node "$node_name" -o json 2>/dev/null || true)
    if [[ -n $node_json ]] &&
        assert_recreated_node_unbound "$node_json" "$old_uid"; then
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
        ((.metadata.annotations["mithril.erebor.dev/label-epoch"] | tonumber?) // 0) >
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

# A fresh cluster withholds config until Control proves that matching Nodes
# begin quarantined. Retained recovery needs the measured config before its
# exact installer and node containers can start.
if [[ $reusing_environment == false ]]; then
  wait_node_projection "$node_a_name" "" true
  wait_node_projection "$node_b_name" "" true
  for index in 0 1; do
    node=$vm_a
    remote=$remote_a
    [[ $index -eq 0 ]] || { node=$vm_b; remote=$remote_b; }
    "$provider" run "$node" sudo install -m 0400 \
      "$remote/materials/node.json" /etc/mithril/node.json
  done
fi
remote_kubectl -n "$system_namespace" rollout status daemonset/mithril-node \
  --timeout=300s >/dev/null
wait_node_projection "$node_a_name" true false
wait_node_projection "$node_b_name" true false
assert_runtime_hook installed "$vm_a" "$remote_a"
assert_runtime_hook installed "$vm_b" "$remote_b"

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
  manual_source=/mnt/mithril-source
  manual_bin_directory=$manual_source/target/debug
  if [[ ${MITHRIL_VM_SOURCE_MOUNT:-} != "$repo_root" ]]; then
    manual_source=/var/tmp/mithril-convergence-manual-source
    manual_bin_directory=/usr/local/bin
    manual_example=$manual_source/examples/mithril-kubernetes-convergence-manual
    manual_oracle_directory=$manual_source/crates/mithril-e2e/harness
    "$provider" run "$vm_a" mkdir -p \
      "$manual_example" "$manual_oracle_directory"
    for file in run.sh policy-v1.yaml exception-v1.yaml protected-pod-v1.yaml; do
      "$provider" put "$vm_a" \
        "$repo_root/examples/mithril-kubernetes-convergence-manual/$file" \
        "$manual_example/$file"
    done
    "$provider" put "$vm_a" \
      "$repo_root/crates/mithril-e2e/harness/kubernetes-oracles.sh" \
      "$manual_oracle_directory/kubernetes-oracles.sh"
  fi
  manual_env=$work_a/mithril-convergence-manual.env
  # K3s dispatches kubectl by executable name. A retained reset keeps this link.
  "$provider" run "$vm_a" sudo ln -sfn \
    /usr/local/bin/k3s /usr/local/bin/kubectl
  {
    printf 'MITHRIL_MANUAL_SOURCE=%q\n' "$manual_source"
    printf 'MITHRIL_BIN_DIRECTORY=%q\n' "$manual_bin_directory"
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
  local output=$work_a/$pod.yaml
  sed \
    -e "s/MITHRIL_CONVERGENCE_NAMESPACE/$workload_namespace/g" \
    -e "s/MITHRIL_CONVERGENCE_POD/$pod/g" \
    "$repo_root/crates/mithril-e2e/fixtures/convergence/protected-pod-v1.yaml" \
    >"$output"
  "$provider" put "$vm_a" "$output" "$remote_a/$pod.yaml"
}
render_pod protected
render_pod gate-failure
render_pod entry-roles

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
write_mithril_node_name_bypass "$remote_a/protected.yaml" \
  "$node_a_name" "$bypass" remote_kubectl
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
  local operation=${3:-}
  local predecessor=${4:-}
  local source_revision=${5:-}
  local status_json
  local node_json
  local pod_json
  local expected_operation
  local expected_predecessor
  for _attempt in {1..180}; do
    status_json=$(node_status "$node_name" 2>/dev/null || true)
    node_json=$(remote_kubectl get node "$node_name" -o json 2>/dev/null || true)
    pod_json=$(remote_kubectl -n "$workload_namespace" get pod protected \
      -o json 2>/dev/null || true)
    expected_operation=$operation
    expected_predecessor=$predecessor
    if [[ -z $expected_operation && -n $status_json ]]; then
      expected_operation=$(jq -r '.active_targets[0].operation // ""' \
        <<<"$status_json")
      expected_predecessor=$(jq -r \
        '.active_targets[0].predecessor_candidate_content_id // ""' \
        <<<"$status_json")
    fi
    if [[ -n $status_json && -n $node_json && -n $pod_json ]] &&
        [[ -n $expected_operation ]] &&
        assert_exact_policy_target "$status_json" "$node_json" "$pod_json" \
          "$profile" converter "$expected_operation" "$expected_predecessor" \
          "$source_revision"; then
      return 0
    fi
    sleep 1
  done
  echo "the live policy target did not converge to its exact identity tuple" >&2
  return 1
}

wait_stable_live_replacement() {
  local node_name=$1
  local profile=$2
  local prior_candidate=$3
  local prior_source_revision=$4
  local stable_candidate=
  local stable_observations=0
  local status_json
  local node_json
  local pod_json
  local candidate
  local predecessor
  local source_revision
  for _attempt in {1..180}; do
    status_json=$(node_status "$node_name" 2>/dev/null || true)
    node_json=$(remote_kubectl get node "$node_name" -o json 2>/dev/null || true)
    pod_json=$(remote_kubectl -n "$workload_namespace" get pod protected \
      -o json 2>/dev/null || true)
    candidate=$(jq -r '.active_candidate_content_id // ""' <<<"$status_json")
    predecessor=$(jq -r \
      '.active_targets[0].predecessor_candidate_content_id // ""' \
      <<<"$status_json")
    source_revision=$(jq -r \
      '.active_targets[0].policy_source_revision_id // ""' \
      <<<"$status_json")
    if [[ -n $candidate && $candidate != "$prior_candidate" && -n $predecessor &&
          $source_revision =~ ^[0-9a-f]{64}$ &&
          $source_revision != "$prior_source_revision" ]] &&
        jq -e '.control_acknowledged == true and .activation_pending == false' \
          <<<"$status_json" >/dev/null &&
        assert_exact_policy_target "$status_json" "$node_json" "$pod_json" \
          "$profile" converter REPLACE "$predecessor" "$source_revision"; then
      if [[ $candidate == "$stable_candidate" ]]; then
        ((stable_observations += 1))
      else
        stable_candidate=$candidate
        stable_observations=1
      fi
      if ((stable_observations >= 7)); then
        printf '%s\n' "$stable_candidate"
        return 0
      fi
    else
      stable_candidate=
      stable_observations=0
    fi
    sleep 1
  done
  echo "the policy update did not produce a stable exact live replacement" >&2
  return 1
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

mount_map_counter() {
  local vm=$1
  local map_name=$2
  "$provider" run "$vm" sudo bpftool -j map lookup pinned \
    "/sys/fs/bpf/mithril-convergence/maps/$map_name" \
    key hex 00 00 00 00 | jq -er '
      def hex_byte:
        if type == "number" then .
        else ascii_downcase | ltrimstr("0x") |
          reduce (explode[]) as $code
            (0; . * 16 + if $code >= 97 then $code - 87 else $code - 48 end)
        end;
      .value | reduce to_entries[] as $byte
        (0; . + (($byte.value | hex_byte) * pow(256; $byte.key)))
    '
}

mount_topology_snapshot() {
  local vm=$1
  local host_pid=$2
  local mount_namespace_inode
  local mountinfo_sha256
  local topology_generation
  local activity_sequence
  local cache_states
  local ready_snapshot_keys

  mount_namespace_inode=$("$provider" run "$vm" sudo stat -Lc %i \
    "/proc/$host_pid/ns/mnt")
  topology_generation=$(mount_map_counter "$vm" mount_global_mutation_epoch)
  cache_states=$("$provider" run "$vm" sudo bpftool -j map dump pinned \
    /sys/fs/bpf/mithril-convergence/maps/canonical_mount_cache_states)
  ready_snapshot_keys=$(jq -cer --argjson generation "$topology_generation" '
    def hex_byte:
      if type == "number" then .
      else ascii_downcase | ltrimstr("0x") |
        reduce (explode[]) as $code
          (0; . * 16 + if $code >= 97 then $code - 87 else $code - 48 end)
      end;
    def little_endian:
      reduce to_entries[] as $byte
        (0; . + (($byte.value | hex_byte) * pow(256; $byte.key)));
    [
      .[] |
      select((.key[16:24] | little_endian) == $generation) |
      select((.key[24:32] | little_endian) == 0) |
      select((.value[0:4] | little_endian) > 0) |
      select((.value[4:8] | little_endian) == 1) |
      (.key | map(hex_byte))
    ] | unique | sort |
    if length > 0 then .
    else error("the current mount epoch has no BPF-ready topology snapshot")
    end
  ' <<<"$cache_states")
  mountinfo_sha256=$("$provider" run "$vm" sudo sha256sum \
    "/proc/$host_pid/mountinfo" | awk '{print $1}')
  activity_sequence=$(mount_map_counter "$vm" mount_global_activity_sequence)
  jq -cn --argjson mount_namespace_inode "$mount_namespace_inode" \
    --argjson topology_generation "$topology_generation" \
    --argjson ready_snapshot_keys "$ready_snapshot_keys" \
    --arg mountinfo_sha256 "$mountinfo_sha256" \
    --argjson activity_sequence "$activity_sequence" '
    {
      mount_namespace_inode: $mount_namespace_inode,
      topology_generation: $topology_generation,
      ready_snapshot_keys: $ready_snapshot_keys,
      mountinfo_sha256: $mountinfo_sha256,
      activity_sequence: $activity_sequence
    }
  '
}

capture_concurrent_recursive_timeout() {
  local after_stop=null
  local map

  after_stop=$(mount_topology_snapshot \
    "$selected_vm" "$concurrent_host_pid" 2>/dev/null || true)
  [[ -n $after_stop ]] || after_stop=null
  jq -n --argjson before "$concurrent_mount_before" \
    --argjson after_exec "$concurrent_mount_after" \
    --argjson after_stop "$after_stop" \
    '{before: $before, after_exec: $after_exec, after_stop: $after_stop}' \
    >"$output_directory/concurrent-exec-mount-timeout.json"
  "$provider" run "$selected_vm" sudo stat -Lc \
    'device=%d inode=%i mode=%f size=%s' \
    /var/lib/mithril-convergence/markers/protected.concurrent-recursive-stop \
    >"$output_directory/concurrent-recursive-stop-host.txt" 2>&1 || true
  "$provider" run "$selected_vm" sudo nsenter \
    -t "$concurrent_host_pid" -m -- stat -Lc \
    'device=%d inode=%i mode=%f size=%s' \
    /var/lib/mithril-convergence/markers/protected.concurrent-recursive-stop \
    >"$output_directory/concurrent-recursive-stop-container.txt" 2>&1 || true
  "$provider" run "$selected_vm" sudo cat \
    "/proc/$concurrent_host_pid/status" \
    >"$output_directory/concurrent-recursive-process-status.txt" 2>&1 || true
  "$provider" run "$selected_vm" sudo cat \
    "/proc/$concurrent_host_pid/wchan" \
    >"$output_directory/concurrent-recursive-process-wchan.txt" 2>&1 || true
  for map in \
    canonical_mount_cache_states \
    exact_mount_events \
    mount_global_mutation_epoch \
    mount_global_pending_mutations \
    mount_global_activity_sequence; do
    "$provider" run "$selected_vm" sudo bpftool -j map dump pinned \
      "/sys/fs/bpf/mithril-convergence/maps/$map" \
      >"$output_directory/concurrent-recursive-timeout-$map.json" 2>&1 || true
  done
}

wait_running_container_identity() {
  local vm=$1
  local namespace=$2
  local pod_name=$3
  local prior_container_uri=${4:-}
  local pod_json
  local container_uri
  local container_id
  local container_json
  local host_pid
  for _attempt in {1..180}; do
    pod_json=$(remote_kubectl -n "$namespace" get pod "$pod_name" -o json \
      2>/dev/null || true)
    container_uri=$(jq -er '
      .status.containerStatuses[0] |
      select(.ready == true and .state.running != null) |
      .containerID
    ' <<<"$pod_json" 2>/dev/null || true)
    if [[ -n $container_uri && $container_uri != "$prior_container_uri" ]]; then
      container_id=${container_uri#containerd://}
      container_json=$("$provider" run "$vm" sudo \
        /usr/local/bin/k3s crictl inspect "$container_id" 2>/dev/null || true)
      host_pid=$(jq -er '.info.pid | select(. > 0)' \
        <<<"$container_json" 2>/dev/null || true)
      if [[ -n $host_pid ]]; then
        jq -cn --arg container_uri "$container_uri" \
          --arg container_id "$container_id" --argjson host_pid "$host_pid" \
          '{container_uri: $container_uri, container_id: $container_id, host_pid: $host_pid}'
        return 0
      fi
    fi
    sleep 1
  done
  echo "container $namespace/$pod_name did not publish a running host PID" >&2
  return 1
}

capture_entry_role_failure_diagnostics() {
  local node_name=$1
  local vm=$2
  local snapshot
  local host_pid
  local map

  for map in \
    execution_set_bindings \
    entry_admission_rules \
    declared_entry_requests \
    exact_file_objects \
    canonical_mount_roots \
    canonical_mount_cache_states; do
    "$provider" run "$vm" sudo bpftool -j map dump pinned \
      "/sys/fs/bpf/mithril-convergence/maps/$map" \
      >"$output_directory/entry-role-failure-$map.json" 2>&1 || true
  done
  for map in \
    mount_global_mutation_epoch \
    mount_global_pending_mutations \
    mount_global_activity_sequence; do
    mount_map_counter "$vm" "$map" \
      >"$output_directory/entry-role-failure-$map.txt" 2>&1 || true
  done
  snapshot=$(wait_running_container_identity \
    "$vm" "$workload_namespace" entry-roles 2>/dev/null) || return 0
  host_pid=$(jq -er '.host_pid' <<<"$snapshot") || return 0
  runtime_task_snapshot "$node_name" "$host_pid" \
    >"$output_directory/entry-role-failure-task.json" 2>&1 || true
}

capture_entry_role_kubernetes_failure() {
  local pod_json
  local node_name
  local vm

  remote_kubectl -n "$workload_namespace" get pod entry-roles -o json \
    >"$output_directory/entry-role-failure-pod.json" 2>&1 || true
  remote_kubectl -n "$workload_namespace" describe pod entry-roles \
    >"$output_directory/entry-role-failure-pod.txt" 2>&1 || true
  remote_kubectl -n "$workload_namespace" logs entry-roles \
    >"$output_directory/entry-role-failure-current.log" 2>&1 || true
  remote_kubectl -n "$workload_namespace" logs entry-roles --previous \
    >"$output_directory/entry-role-failure-previous.log" 2>&1 || true
  pod_json=$(<"$output_directory/entry-role-failure-pod.json")
  node_name=$(jq -r '.spec.nodeName // empty' <<<"$pod_json" 2>/dev/null || true)
  vm=$vm_a
  [[ $node_name == "$node_a_name" ]] || vm=$vm_b
  [[ -n $node_name ]] || return 0
  capture_entry_role_failure_diagnostics "$node_name" "$vm"
}

wait_for_entry_role_ready() {
  local pod_json
  local ready
  local restarts
  local phase

  for _attempt in {1..300}; do
    pod_json=$(remote_kubectl -n "$workload_namespace" get pod entry-roles -o json)
    ready=$(jq -r '
      [.status.conditions[]? | select(.type == "Ready") | .status] |
      first // "False"
    ' <<<"$pod_json")
    [[ $ready == True ]] && return 0
    phase=$(jq -r '.status.phase // "Unknown"' <<<"$pod_json")
    restarts=$(jq -r '[.status.containerStatuses[]?.restartCount] | add // 0' \
      <<<"$pod_json")
    if [[ $phase == Failed || $restarts -gt 0 ]]; then
      capture_entry_role_kubernetes_failure
      echo "the entry-role Pod failed before readiness: phase=$phase restarts=$restarts" >&2
      return 1
    fi
    sleep 1
  done
  capture_entry_role_kubernetes_failure
  echo "the entry-role Pod did not become ready" >&2
  return 1
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
      --cgroup-scope / --reason APPLICATION_DEFAULT_ALLOW \
      --reason UNSUPPORTED_OBJECT --reason UNRESOLVED_OBJECT \
      --reason PATH_TREE_POLICY_DENY
}

effect_health_value() {
  local health=$1
  local field_name=$2
  awk -v field_name="$field_name" '
    NR == 1 {
      for (field_index = 1; field_index <= NF; field_index++) {
        split($field_index, field, "=")
        if (field[1] == field_name) {
          print field[2]
          exit
        }
      }
    }
  ' <<<"$health"
}

assert_node_evidence_health_clean() {
  local node_name=$1
  local pod
  local pod_json
  local restart_count
  local health
  local logs
  pod_json=$(remote_kubectl -n "$system_namespace" get pods \
    -l app.kubernetes.io/name=mithril-node \
    --field-selector "spec.nodeName=$node_name" \
    -o json)
  pod=$(jq -er '.items[0].metadata.name' <<<"$pod_json")
  restart_count=$(jq -er '
    .items[0].status.containerStatuses[] |
    select(.name == "mithril-node") |
    .restartCount
  ' <<<"$pod_json")
  if ((restart_count != 0)); then
    echo "node $node_name restarted $restart_count times in its current Pod" >&2
    return 1
  fi
  health=$(remote_kubectl -n "$system_namespace" exec -c mithril-node "$pod" -- \
    mithril-inspect effects --socket-path /run/mithril/observation.sock \
      --cgroup-scope /)
  for expected in \
    'lost=0' \
    'evidence_errors=0' \
    'wal_capacity_blocked=0' \
    'reader_queue_dropped_events=0'; do
    if ! grep -Eq "(^| )$expected( |$)" <<<"$health"; then
      printf '%s\n' "$health" >&2
      echo "node $node_name has unhealthy effect evidence: $expected is absent" >&2
      return 1
    fi
  done
  if ! grep -F \
      'capability=LOCAL_EFFECT_OBSERVATION state=SUPPORTED' \
      <<<"$health" >/dev/null; then
    printf '%s\n' "$health" >&2
    echo "node $node_name does not have healthy effect observation" >&2
    return 1
  fi

  logs=$(remote_kubectl -n "$system_namespace" logs "$pod" -c mithril-node)
  if [[ $(grep -Fc 'connected to Mithril Control' <<<"$logs") -ne 1 ]] ||
    grep -Eq \
      'lost the Mithril Control stream|Mithril Node stopped with an error|Mithril node control protocol failed|WAL_FAILURE|out-of-order evidence|durable evidence operation failed|evidence reconciliation became unhealthy' \
      <<<"$logs"; then
    printf '%s\n' "$logs" >&2
    echo "node $node_name did not retain one healthy Control evidence stream" >&2
    return 1
  fi
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
      --cgroup-scope / --samples 6000 --sample-interval-ms 100 \
      --reason APPLICATION_DEFAULT_ALLOW \
      --reason PREPARED_RUNTIME_INFRASTRUCTURE \
      --reason RUNTIME_ENTRY_INFRASTRUCTURE \
      --reason EXECUTION_APPROVAL_VERIFICATION_FAILED \
      --reason UNSUPPORTED_OBJECT \
      --reason UNRESOLVED_OBJECT \
      --reason PATH_TREE_POLICY_DENY \
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
      "$marker_root/$pod_name.application-request" \
      "$marker_root/$pod_name.application-result" \
      "$marker_root/$pod_name.exception-request" \
      "$marker_root/$pod_name.exception-result" \
      "$marker_root/$pod_name.path-tree-mount-result" \
      "$marker_root/$pod_name.path-tree-subpath-result" \
      "$marker_root/$pod_name.path-tree-subpath-newer-result" \
      "$marker_root/$pod_name.path-tree-bind-result" \
      "$marker_root/$pod_name.path-tree-wildcard-result" \
      "$marker_root/$pod_name.path-tree-recursive-wildcard-result" \
      "$marker_root/$pod_name.path-tree-recursive-wildcard-stable-result" \
      "$marker_root/$pod_name.path-tree-control-result" \
      "$marker_root/$pod_name.concurrent-recursive-ready" \
      "$marker_root/$pod_name.concurrent-recursive-start" \
      "$marker_root/$pod_name.concurrent-recursive-result" \
      "$marker_root/$pod_name.concurrent-recursive-count" \
      "$marker_root/$pod_name.concurrent-recursive-stop" \
      "$marker_root/$pod_name.concurrent-startup-gate" \
      "$marker_root/$pod_name.stable-recursive-start" \
      "$marker_root/$pod_name.poststart-observed" \
      "$marker_root/$pod_name.prestop-observed"
    "$provider" run "$node" sudo touch \
      "$marker_root/$pod_name.exception-target"
    if [[ $pod_name != protected ]]; then
      "$provider" run "$node" sudo touch \
        "$marker_root/$pod_name.concurrent-startup-gate"
    fi
    "$provider" run "$node" sudo mkfifo \
      "$marker_root/$pod_name.application-request" \
      "$marker_root/$pod_name.exception-request" \
      "$marker_root/$pod_name.concurrent-recursive-start" \
      "$marker_root/$pod_name.stable-recursive-start" \
      "$marker_root/$pod_name.restart"
    "$provider" run "$node" \
      "printf '%s\\n' READY | sudo tee '$marker_root/$pod_name.lifecycle-ready' >/dev/null"
  done
}

admitted_entry_counts() {
  local after_boottime_ns=$1
  awk -v after_boottime_ns="$after_boottime_ns" '
    /^observed_boottime_ns=/ {
      observed_boottime_ns = 0
      role = 0
      admission = 0
      for (field_index = 1; field_index <= NF; field_index++) {
        split($field_index, field, "=")
        if (field[1] == "observed_boottime_ns") {
          observed_boottime_ns = field[2]
        } else if (field[1] == "active_role_id") {
          role = field[2]
        } else if (field[1] == "admitted_entry_rule_id") {
          admission = field[2]
        }
      }
      if (observed_boottime_ns > after_boottime_ns && role > 0 && admission > 0) {
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

max_effect_boottime() {
  awk '
    /^observed_boottime_ns=/ {
      split($1, field, "=")
      if (field[2] > maximum) maximum = field[2]
    }
    END { printf "%.0f\n", maximum }
  '
}

prepare_pod_markers entry-roles
entry_role_capture_a=$output_directory/declared-entry-role-capture-node-a.txt
entry_role_capture_b=$output_directory/declared-entry-role-capture-node-b.txt
start_entry_effect_capture "$node_a_name" "$entry_role_capture_a"
start_entry_effect_capture "$node_b_name" "$entry_role_capture_b"
sleep 1
entry_role_boundary_a=$(max_effect_boottime <"$entry_role_capture_a")
entry_role_boundary_b=$(max_effect_boottime <"$entry_role_capture_b")
remote_kubectl create -f "$remote_a/entry-roles.yaml" >/dev/null
wait_for_entry_role_ready
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
entry_role_boundary=$entry_role_boundary_a
if [[ $entry_roles_node == "$node_b_name" ]]; then
  entry_role_capture=$entry_role_capture_b
  entry_role_boundary=$entry_role_boundary_b
fi
entry_role_count_before_delete=5
if "$provider" run "$entry_roles_vm" sudo test -e \
    /var/lib/mithril-convergence/markers/entry-roles.prestop-observed; then
  entry_role_count_before_delete=6
fi

entry_role_effects_before=
for _attempt in {1..120}; do
  entry_role_effects_before=$(printf '%s\n%s\n' \
    "$(<"$entry_role_capture")" "$(node_effects "$entry_roles_node")")
  read -r entry_role_count entry_admission_count entry_pair_count \
    <<<"$(admitted_entry_counts "$entry_role_boundary" <<<"$entry_role_effects_before")"
  if [[ $entry_role_count -eq $entry_role_count_before_delete &&
        $entry_admission_count -eq $entry_role_count_before_delete &&
        $entry_pair_count -eq $entry_role_count_before_delete ]]; then
    break
  fi
  [[ $_attempt -lt 120 ]] || {
    printf '%s\n' "$entry_role_effects_before" \
      >"$output_directory/entry-role-failure-effects.txt"
    jq -cn \
      --argjson roles "$entry_role_count" \
      --argjson admissions "$entry_admission_count" \
      --argjson pairs "$entry_pair_count" \
      '{roles: $roles, admissions: $admissions, pairs: $pairs}' \
      >"$output_directory/entry-role-failure-counts.json"
    capture_entry_role_failure_diagnostics \
      "$entry_roles_node" "$entry_roles_vm"
    echo "the application, PostStart, and probe entries did not install five independent roles" >&2
    exit 1
  }
  sleep 1
done

entry_role_candidate=$(jq -er --arg profile_id "$profile_id" '
  select(
    .active_profile_ids == [$profile_id] and
    .active_target_count == 1 and
    .runtime_binding_count == 1
  ) | .active_candidate_content_id
' <<<"$(node_status "$entry_roles_node")")
entry_prestop_capture=$output_directory/declared-entry-role-capture-prestop.txt
start_entry_effect_capture "$entry_roles_node" "$entry_prestop_capture"
sleep 0.1
entry_prestop_boundary=$(max_effect_boottime <"$entry_prestop_capture")
"$provider" run "$entry_roles_vm" sudo rm -f \
  /var/lib/mithril-convergence/markers/entry-roles.prestop-observed
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
  entry_prestop_effects=$(printf '%s\n%s\n' \
    "$(<"$entry_prestop_capture")" "$entry_role_effects_after")
  entry_role_effects=$(printf '%s\n%s\n%s\n' \
    "$entry_role_effects_before" "$(<"$entry_prestop_capture")" \
    "$entry_role_effects_after")
  read -r entry_role_count entry_admission_count entry_pair_count \
    <<<"$(admitted_entry_counts "$entry_role_boundary" <<<"$entry_role_effects")"
  read -r _prestop_role_count _prestop_admission_count prestop_pair_count \
    <<<"$(admitted_entry_counts "$entry_prestop_boundary" <<<"$entry_prestop_effects")"
  if [[ $entry_role_count -eq 6 && $entry_admission_count -eq 6 &&
        $entry_pair_count -eq 6 && $prestop_pair_count -ge 1 ]]; then
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
protected_effect_capture_a=$output_directory/protected-effect-capture-node-a.txt
protected_effect_capture_b=$output_directory/protected-effect-capture-node-b.txt
start_entry_effect_capture "$node_a_name" "$protected_effect_capture_a"
start_entry_effect_capture "$node_b_name" "$protected_effect_capture_b"
remote_kubectl create -f "$remote_a/protected.yaml" >/dev/null
selected_node=
for _attempt in {1..120}; do
  selected_node=$(remote_kubectl -n "$workload_namespace" get pod protected \
    -o jsonpath='{.spec.nodeName}')
  [[ -n $selected_node ]] && break
  [[ $_attempt -lt 120 ]] || {
    echo "the protected Pod was not scheduled" >&2
    exit 1
  }
  sleep 1
done
[[ $selected_node == "$node_a_name" || $selected_node == "$node_b_name" ]] || {
  echo "the scheduler selected a Node outside the DaemonSet-derived set" >&2
  exit 1
}
if [[ $selected_node == "$node_a_name" ]]; then
  selected_vm=$vm_a
  selected_remote=$remote_a
  other_node=$node_b_name
  other_vm=$vm_b
else
  selected_vm=$vm_b
  selected_remote=$remote_b
  other_node=$node_a_name
  other_vm=$vm_a
fi
for _attempt in {1..120}; do
  protected_restart_count=$(remote_kubectl -n "$workload_namespace" get pod protected \
    -o jsonpath='{.status.containerStatuses[0].restartCount}' 2>/dev/null || true)
  [[ $protected_restart_count =~ ^[0-9]+$ ]] || protected_restart_count=-1
  ((protected_restart_count == 0)) || {
    echo "the protected Pod restarted before the concurrent containerd exec proof" >&2
    exit 1
  }
  if "$provider" run "$selected_vm" sudo cmp -s \
    /var/lib/mithril-convergence/markers/protected.lifecycle-ready \
    /var/lib/mithril-convergence/markers/protected.poststart-observed; then
    break
  fi
  [[ $_attempt -lt 120 ]] || {
    echo "the protected Pod did not complete PostStart before the concurrent containerd exec proof" >&2
    exit 1
  }
  sleep 1
done
for _attempt in {1..120}; do
  if "$provider" run "$selected_vm" sudo test -e \
    /var/lib/mithril-convergence/markers/protected.concurrent-recursive-ready; then
    break
  fi
  [[ $_attempt -lt 120 ]] || {
    echo "the protected Pod did not start its concurrent recursive read loop" >&2
    exit 1
  }
  sleep 1
done
concurrent_container_uri=
for _attempt in {1..120}; do
  concurrent_container_uri=$(remote_kubectl -n "$workload_namespace" \
    get pod protected -o jsonpath='{.status.containerStatuses[0].containerID}' \
    2>/dev/null || true)
  [[ $concurrent_container_uri == containerd://* ]] && break
  [[ $_attempt -lt 120 ]] || {
    echo "the protected Pod did not publish its running container ID" >&2
    exit 1
  }
  sleep 0.25
done
concurrent_container_id=${concurrent_container_uri#containerd://}
[[ $concurrent_container_id =~ ^[0-9a-f]{64}$ ]] || {
  echo "the protected Pod published an invalid container ID" >&2
  exit 1
}
concurrent_container_json=$("$provider" run "$selected_vm" sudo \
  /usr/local/bin/k3s crictl inspect "$concurrent_container_id")
concurrent_host_pid=$(jq -er '.info.pid | select(. > 0)' \
  <<<"$concurrent_container_json")
concurrent_mount_before=$(mount_topology_snapshot \
  "$selected_vm" "$concurrent_host_pid")
concurrent_exec_root=/var/tmp/mithril-concurrent-exec-$run_id
concurrent_exec_evidence=$output_directory/concurrent-exec-mount-overlap.txt
set +e
"$provider" run "$selected_vm" sudo bash \
  "$selected_remote/harness/concurrent-exec-overlap.sh" \
  /var/lib/mithril-convergence/markers/protected.concurrent-recursive-start \
  "$concurrent_exec_root" "$concurrent_container_id" 32 \
  >"$concurrent_exec_evidence" 2>&1
concurrent_exec_status=$?
set -e
"$provider" run "$selected_vm" sudo rm -rf -- "$concurrent_exec_root"
[[ $concurrent_exec_status -eq 0 ]] || {
  cat "$concurrent_exec_evidence" >&2
  echo "the concurrent containerd exec preparations did not all fail closed" >&2
  exit 1
}
concurrent_mount_after=$(mount_topology_snapshot \
  "$selected_vm" "$concurrent_host_pid")
jq -n --argjson before "$concurrent_mount_before" \
  --argjson after "$concurrent_mount_after" \
  '{before: $before, after: $after}' \
  >"$output_directory/concurrent-exec-mount-topology.json"
jq -e --argjson before "$concurrent_mount_before" \
  --argjson after "$concurrent_mount_after" '
  ($before.mount_namespace_inode == $after.mount_namespace_inode) and
  ($before.mountinfo_sha256 == $after.mountinfo_sha256) and
  ($before.topology_generation == $after.topology_generation) and
  ($before.ready_snapshot_keys == $after.ready_snapshot_keys) and
  ($after.activity_sequence > $before.activity_sequence)
' <<<null >/dev/null || {
  echo "detached containerd exec preparation changed the protected mount view" >&2
  exit 1
}
"$provider" run "$selected_vm" sudo touch \
  /var/lib/mithril-convergence/markers/protected.concurrent-recursive-stop \
  /var/lib/mithril-convergence/markers/protected.concurrent-startup-gate
for _attempt in {1..120}; do
  concurrent_recursive_result=$("$provider" run "$selected_vm" sudo cat \
    /var/lib/mithril-convergence/markers/protected.concurrent-recursive-result \
    2>/dev/null || true)
  [[ $concurrent_recursive_result == PATH_TREE_DENIED ]] && break
  [[ $_attempt -lt 120 ]] || {
    capture_concurrent_recursive_timeout
    echo "the protected Pod did not complete its concurrent recursive read after the stop marker" >&2
    exit 1
  }
  sleep 1
done
remote_kubectl -n "$workload_namespace" wait --for=condition=Ready pod/protected \
  --timeout=300s >/dev/null
"$provider" run "$selected_vm" \
  "printf 'start\\n' | sudo timeout 30s tee /var/lib/mithril-convergence/markers/protected.stable-recursive-start >/dev/null"

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
  local expected_target_count=${3:-1}
  local expected_scheduled_count=${4:-0}
  local expected_runtime_count=${5:-1}
  local excluded_candidate=${6:-}
  local expected_container_id=${7:-}
  local status_json
  for _attempt in {1..180}; do
    status_json=$(node_status "$node_name" 2>/dev/null || true)
    if [[ -n $status_json ]] && jq -e --arg profile_id "$profile" \
      --arg excluded_candidate "$excluded_candidate" \
      --arg expected_container_id "$expected_container_id" \
      --argjson target_count "$expected_target_count" \
      --argjson scheduled_count "$expected_scheduled_count" \
      --argjson runtime_count "$expected_runtime_count" '
      .active_candidate_content_id != null and
      ($excluded_candidate == "" or
        .active_candidate_content_id != $excluded_candidate) and
      .active_profile_ids == [$profile_id] and
      .active_target_count == $target_count and
      .active_targets_truncated == false and
      (.active_targets | length) == $target_count and
      ($expected_container_id == "" or
        all(.active_targets[]; .runtime_container_id == $expected_container_id)) and
      .scheduled_binding_count == $scheduled_count and
      .runtime_binding_count == $runtime_count and
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
initial_operation=ACTIVATE
initial_predecessor=
if [[ $selected_node == "$entry_roles_node" ]]; then
  initial_operation=REPLACE
  initial_predecessor=$entry_role_candidate
fi
assert_live_exact_target "$selected_node" "$profile_id" \
  "$initial_operation" "$initial_predecessor"
selected_status=$(node_status "$selected_node")
protected_candidate=$(jq -er '.active_candidate_content_id' <<<"$selected_status")
protected_operation=$(jq -er '.active_targets[0].operation' <<<"$selected_status")
protected_predecessor=$(jq -er \
  '.active_targets[0].predecessor_candidate_content_id // ""' \
  <<<"$selected_status")
runtime_binding_before=$(jq -er '.active_targets[0].runtime_binding_id' \
  <<<"$selected_status")
jq -e '
  .active_candidate_content_id == null and
  .active_profile_ids == [] and
  .scheduled_binding_count == 0 and
  .runtime_binding_count == 0
' <<<"$other_status" >/dev/null

if [[ $qualify_state_preserving_upgrade == true ]]; then
  upgrade_candidate_before=$protected_candidate
  upgrade_source_revision_before=$(jq -er \
    '.active_targets[0].policy_source_revision_id' <<<"$selected_status")
  upgrade_operation_before=$protected_operation
  upgrade_predecessor_before=$protected_predecessor
  upgrade_runtime_binding_before=$runtime_binding_before
  upgrade_pod_uid_before=$(remote_kubectl -n "$workload_namespace" get pod protected \
    -o jsonpath='{.metadata.uid}')
  upgrade_container_before=$(remote_kubectl -n "$workload_namespace" get pod protected \
    -o jsonpath='{.status.containerStatuses[0].containerID}')
  control_pvc_uid_before=$(remote_kubectl -n "$system_namespace" get pvc \
    "$control_state_claim" -o jsonpath='{.metadata.uid}')

  for node in "$vm_a" "$vm_b"; do
    [[ $("$provider" run "$node" sudo sha256sum \
      /usr/libexec/oci/hooks.d/mithril-oci-hook | awk '{print $1}') \
      == "$baseline_hook_digest" ]] || {
      echo "the initial runtime hook does not contain the prior-version fixture on $node" >&2
      exit 1
    }
  done

  helm --kubeconfig "$kubeconfig" uninstall mithril \
    --namespace "$system_namespace" --wait --timeout=180s >/dev/null
  for node in "$vm_a" "$vm_b"; do
    remote=$remote_a
    [[ $node == "$vm_a" ]] || remote=$remote_b
    assert_runtime_hook retained "$node" "$remote"
    [[ $("$provider" run "$node" sudo sha256sum \
      /usr/libexec/oci/hooks.d/mithril-oci-hook | awk '{print $1}') \
      == "$baseline_hook_digest" ]] || {
      echo "Helm uninstall changed the retained runtime hook on $node" >&2
      exit 1
    }
  done

  forged_upgrade=$work_a/forged-upgrade-installer.yaml
  sed "s/MITHRIL_UPGRADE_NODE/$selected_node/" \
    "$repo_root/crates/mithril-e2e/fixtures/convergence/forged-upgrade-installer-v1.yaml" \
    >"$forged_upgrade"
  "$provider" put "$vm_a" "$forged_upgrade" \
    "$remote_a/forged-upgrade-installer.yaml"
  remote_kubectl create -f "$remote_a/forged-upgrade-installer.yaml" >/dev/null
  forged_sandbox_id=
  forged_container_id=
  for _attempt in {1..120}; do
    forged_status=$(remote_kubectl -n "$system_namespace" get pod \
      forged-upgrade-installer -o json 2>/dev/null || true)
    forged_sandbox_id=$("$provider" run "$selected_vm" \
      "sudo /usr/local/bin/k3s crictl pods --name forged-upgrade-installer -q | head -1" \
      2>/dev/null || true)
    forged_container_id=$(jq -er \
      '.status.containerStatuses[0].containerID | sub("^containerd://"; "")' \
      <<<"$forged_status" 2>/dev/null || true)
    if [[ $forged_sandbox_id =~ ^[0-9a-f]{64}$ ]] &&
        [[ $forged_container_id =~ ^[0-9a-f]{64}$ ]] &&
        jq -e '
          .status.phase == "Failed" and
          .status.containerStatuses[0].started == false and
          .status.containerStatuses[0].state.terminated.reason == "StartError" and
          .status.containerStatuses[0].state.terminated.startedAt == "1970-01-01T00:00:00Z" and
          (.status.containerStatuses[0].state.terminated.message |
            contains("decision=DENY_NODE_UNAVAILABLE") and
            contains("retained gate denied a non-recovery start"))
        ' <<<"$forged_status" >/dev/null; then
      forged_container_status=$("$provider" run "$selected_vm" sudo \
        /usr/local/bin/k3s crictl inspect "$forged_container_id" 2>/dev/null || true)
      if jq -e '
          .info.pid == 0 and
          .status.state == "CONTAINER_EXITED" and
          .status.startedAt == "1970-01-01T00:00:00Z"
        ' <<<"$forged_container_status" >/dev/null; then
        break
      fi
    fi
    [[ $_attempt -lt 120 ]] || {
      echo "the forged installer did not reach sandbox-only denial: $forged_status" >&2
      exit 1
    }
    sleep 1
  done
  [[ $("$provider" run "$selected_vm" sudo sha256sum \
    /usr/libexec/oci/hooks.d/mithril-oci-hook | awk '{print $1}') \
    == "$baseline_hook_digest" ]] || {
    echo "the forged installer changed the retained runtime hook" >&2
    exit 1
  }
  remote_kubectl -n "$system_namespace" delete pod forged-upgrade-installer \
    --wait=true --timeout=120s >/dev/null

  helm --kubeconfig "$kubeconfig" upgrade --install mithril \
    "$repo_root/packaging/mithril/helm" --namespace "$system_namespace" \
    --values "$current_values"
  remote_kubectl -n "$system_namespace" rollout status daemonset/mithril-node \
    --timeout=300s >/dev/null
  retry_kubernetes_command 30 1 remote_kubectl -n "$system_namespace" \
    rollout status deployment/mithril-control --timeout=10s >/dev/null
  wait_node_projection "$node_a_name" true false
  wait_node_projection "$node_b_name" true false

  for node in "$vm_a" "$vm_b"; do
    remote=$remote_a
    [[ $node == "$vm_a" ]] || remote=$remote_b
    assert_runtime_hook installed "$node" "$remote"
    [[ $("$provider" run "$node" sudo sha256sum \
      /usr/libexec/oci/hooks.d/mithril-oci-hook | awk '{print $1}') \
      == "$current_hook_digest" ]] || {
      echo "the upgraded runtime hook does not contain the current binary on $node" >&2
      exit 1
    }
  done
  [[ $(remote_kubectl -n "$system_namespace" get pvc "$control_state_claim" \
    -o jsonpath='{.metadata.uid}') == "$control_pvc_uid_before" ]]
  remote_kubectl -n "$system_namespace" get deployment mithril-control -o json | \
    jq -e '.spec.template.spec.containers[0].image == "mithril-control:convergence"' \
      >/dev/null
  remote_kubectl -n "$system_namespace" get daemonset mithril-node -o json | jq -e '
    .spec.template.spec.initContainers[0].image == "mithril-node:convergence" and
    .spec.template.spec.containers[0].image == "mithril-node:convergence"
  ' >/dev/null

  upgraded_status=$(wait_runtime_delivery "$selected_node" "$profile_id")
  jq -e \
    --arg candidate "$upgrade_candidate_before" \
    --arg operation "$upgrade_operation_before" \
    --arg predecessor "$upgrade_predecessor_before" \
    --arg source_revision "$upgrade_source_revision_before" \
    --arg runtime_binding "$upgrade_runtime_binding_before" '
      .active_candidate_content_id == $candidate and
      .active_targets[0].operation == $operation and
      (.active_targets[0].predecessor_candidate_content_id // "") == $predecessor and
      .active_targets[0].policy_source_revision_id == $source_revision and
      .active_targets[0].runtime_binding_id == $runtime_binding and
      .control_acknowledged == true and
      .activation_pending == false
    ' <<<"$upgraded_status" >/dev/null
  [[ $(remote_kubectl -n "$workload_namespace" get pod protected \
    -o jsonpath='{.metadata.uid}') == "$upgrade_pod_uid_before" ]]
  [[ $(remote_kubectl -n "$workload_namespace" get pod protected \
    -o jsonpath='{.status.containerStatuses[0].containerID}') \
    == "$upgrade_container_before" ]]
  assert_live_exact_target "$selected_node" "$profile_id" \
    "$upgrade_operation_before" "$upgrade_predecessor_before"

fi

selected_status=$(node_status "$selected_node")
live_update_candidate_before=$(jq -er '.active_candidate_content_id' <<<"$selected_status")
live_update_source_revision_before=$(jq -er \
  '.active_targets[0].policy_source_revision_id' <<<"$selected_status")
make_policy_manifest 2
remote_kubectl --as="$policy_subject" apply --server-side --validate=strict \
  -f "$remote_a/policy-v2.yaml" >/dev/null
wait_policy_compiled
protected_candidate=$(wait_stable_live_replacement \
  "$selected_node" "$profile_id" "$live_update_candidate_before" \
  "$live_update_source_revision_before")
selected_status=$(node_status "$selected_node")
protected_operation=$(jq -er '.active_targets[0].operation' <<<"$selected_status")
protected_predecessor=$(jq -er \
  '.active_targets[0].predecessor_candidate_content_id' <<<"$selected_status")
runtime_binding_before=$(jq -er '.active_targets[0].runtime_binding_id' \
  <<<"$selected_status")
[[ $protected_operation == REPLACE &&
   $protected_predecessor == "$live_update_candidate_before" ]]

if [[ $qualify_state_preserving_upgrade == true ]]; then
  jq -n \
    --arg baseline_hook_digest "$baseline_hook_digest" \
    --arg current_hook_digest "$current_hook_digest" \
    --arg control_pvc_uid "$control_pvc_uid_before" \
    --arg pod_uid "$upgrade_pod_uid_before" \
    --arg container_id "$upgrade_container_before" \
    --arg forged_sandbox_id "$forged_sandbox_id" \
    --arg forged_container_id "$forged_container_id" \
    --arg candidate_before "$upgrade_candidate_before" \
    --arg candidate_after "$protected_candidate" \
    --arg predecessor "$protected_predecessor" '
      {
        schema_version: 1,
        baseline_hook_digest: $baseline_hook_digest,
        current_hook_digest: $current_hook_digest,
        control_pvc_uid: $control_pvc_uid,
        protected_pod_uid: $pod_uid,
        protected_container_id: $container_id,
        forged_installer_sandbox_id: $forged_sandbox_id,
        forged_installer_container_id: $forged_container_id,
        forged_installer_process_never_started: true,
        candidate_before: $candidate_before,
        candidate_after: $candidate_after,
        predecessor_candidate: $predecessor,
        control_state_reopened: true,
        node_state_reopened: true
      }
    ' >"$output_directory/state-preserving-upgrade-result.json"
fi

container_identity_before=$(wait_running_container_identity \
  "$selected_vm" "$workload_namespace" protected)
container_before=$(jq -er '.container_uri' <<<"$container_identity_before")
container_before_id=$(jq -er '.container_id' <<<"$container_identity_before")
host_pid_before=$(jq -er '.host_pid' <<<"$container_identity_before")
task_before=$(runtime_task_snapshot "$selected_node" "$host_pid_before")
task_cookie_before=$(jq -er '.task_cookie' <<<"$task_before")
application_admission_id=$(jq -er '.admitted_entry_rule_id' <<<"$task_before")
application_role_id=$(jq -er '.active_role_id' <<<"$task_before")
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

for path_tree_result in \
    path-tree-mount-result:MOUNT_READY \
    path-tree-subpath-result:PATH_TREE_DENIED \
    path-tree-subpath-newer-result:PATH_TREE_DENIED \
    path-tree-bind-result:PATH_TREE_DENIED \
    path-tree-wildcard-result:PATH_TREE_DENIED \
    path-tree-recursive-wildcard-result:PATH_TREE_DENIED \
    path-tree-recursive-wildcard-stable-result:PATH_TREE_DENIED \
    path-tree-control-result:CONTROL_ALLOWED \
    concurrent-recursive-result:PATH_TREE_DENIED; do
  marker_name=${path_tree_result%%:*}
  expected_result=${path_tree_result#*:}
  for _attempt in {1..120}; do
    observed_result=$("$provider" run "$selected_vm" sudo cat \
      "/var/lib/mithril-convergence/markers/protected.$marker_name" \
      2>/dev/null || true)
    [[ $observed_result == "$expected_result" ]] && break
    [[ $_attempt -lt 120 ]] || {
      echo "the protected Pod path-tree result $marker_name was $observed_result, expected $expected_result" >&2
      exit 1
    }
    sleep 1
  done
  "$provider" run "$other_vm" sudo test ! -e \
    "/var/lib/mithril-convergence/markers/protected.$marker_name"
done
concurrent_recursive_count=$("$provider" run "$selected_vm" sudo cat \
  /var/lib/mithril-convergence/markers/protected.concurrent-recursive-count)
[[ $concurrent_recursive_count =~ ^[1-9][0-9]*$ ]] || {
  echo "the concurrent protected-read loop did not complete one read" >&2
  exit 1
}

stop_entry_effect_capture
protected_effect_capture=$protected_effect_capture_a
[[ $selected_node == "$node_b_name" ]] && \
  protected_effect_capture=$protected_effect_capture_b
read -r application_entry_rule_id path_tree_effect_count \
  unresolved_object_effect_count < <(awk -v role="$application_role_id" '
      /^observed_boottime_ns=/ {
        reason = ""
        family = 0
        operation = 0
        kernel_result = 0
        active_role_id = 0
        admitted_entry_rule_id = 0
        for (field_index = 1; field_index <= NF; field_index++) {
          split($field_index, field, "=")
          if (field[1] == "reason") {
            reason = field[2]
          } else if (field[1] == "family") {
            family = field[2]
          } else if (field[1] == "operation") {
            operation = field[2]
          } else if (field[1] == "kernel_result") {
            kernel_result = field[2]
          } else if (field[1] == "active_role_id") {
            active_role_id = field[2]
          } else if (field[1] == "admitted_entry_rule_id") {
            admitted_entry_rule_id = field[2]
          }
        }
        if ((reason == "PATH_TREE_POLICY_DENY" ||
             reason == "UNRESOLVED_OBJECT") &&
            family == 2 && operation == 2 && kernel_result == -13 &&
            active_role_id == role && admitted_entry_rule_id > 0) {
          if (entry_rule_id == 0) {
            entry_rule_id = admitted_entry_rule_id
          }
          if (admitted_entry_rule_id == entry_rule_id) {
            if (reason == "PATH_TREE_POLICY_DENY") {
              path_count++
            } else {
              guard_count++
            }
          }
        }
      }
      END { print entry_rule_id + 0, path_count + 0, guard_count + 0 }
    ' "$protected_effect_capture")
[[ $application_entry_rule_id -gt 0 && $path_tree_effect_count -ge 5 && \
  $unresolved_object_effect_count -eq 0 ]] || {
  echo "the protected Pod path proof used entry rule $application_entry_rule_id, $path_tree_effect_count path denials, and $unresolved_object_effect_count unresolved-object denials; expected one rule, at least five path denials, and no unresolved-object denial" >&2
  exit 1
}

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
application_effect_marker=$(awk '
  /^observed_boottime_ns=/ {
    split($1, field, "=")
    if (field[2] > marker) {
      marker = field[2]
    }
  }
  END { print marker + 0 }
' <<<"$application_effects")
application_effect_capture=$output_directory/application-effect-capture.txt
start_entry_effect_capture "$selected_node" "$application_effect_capture"
sleep 0.1
signal_pod_request "$selected_vm" \
  /var/lib/mithril-convergence/markers/protected.application-request APPLICATION
for _attempt in {1..120}; do
  application_result=$("$provider" run "$selected_vm" sudo cat \
    /var/lib/mithril-convergence/markers/protected.application-result \
    2>/dev/null || true)
  [[ $application_result == APPLICATION_DEFAULT_ALLOWED ]] && break
  [[ $_attempt -lt 120 ]] || {
    echo "the later application exec did not receive default authority" >&2
    exit 1
  }
  sleep 1
done
"$provider" run "$other_vm" sudo test ! -e \
  /var/lib/mithril-convergence/markers/protected.application-result

for _attempt in {1..600}; do
  if awk -v marker="$application_effect_marker" \
      -v role="$application_role_id" \
      -v admission="$application_admission_id" '
    /^observed_boottime_ns=/ &&
    / family=1 operation=1 / &&
    / reason=APPLICATION_DEFAULT_ALLOW / &&
    / exact_object_key_id=0 composite_atom_id=0 / {
      observed_role = 0
      observed_admission = 0
      split($1, observed_time, "=")
      for (field_index = 1; field_index <= NF; field_index++) {
        split($field_index, field, "=")
        if (field[1] == "active_role_id") {
          observed_role = field[2]
        } else if (field[1] == "admitted_entry_rule_id") {
          observed_admission = field[2]
        }
      }
      if (observed_time[2] > marker && observed_role == role &&
          observed_admission == admission) found = 1
    }
    END { exit !found }
  ' "$application_effect_capture"; then
    break
  fi
  [[ $_attempt -lt 600 ]] || {
    echo "a later application exec did not inherit its application role" >&2
    exit 1
  }
  sleep 0.1
done
stop_entry_effect_capture
application_effects=$(printf '%s\n%s\n%s\n' \
  "$application_effects" "$(<"$application_effect_capture")" \
  "$(node_effects "$selected_node")")
printf '%s\n' "$application_effects" \
  >"$output_directory/application-effects.txt"
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
external_unresolved_before=$(effect_health_value "$application_effects" unresolved)
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
external_cgroup_entry_denial_count=0
for _attempt in {1..40}; do
  external_effects=$(node_effects "$selected_node")
  external_cgroup_entry_denial_count=$(
    external_cgroup_exec_denial_count_after "$external_effects" "$effect_marker"
  )
  if ((external_cgroup_entry_denial_count > 0)); then
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
external_unresolved=$(effect_health_value "$external_effects" unresolved)
expected_external_unresolved=$((
  external_unresolved_before + external_cgroup_entry_denial_count
))
[[ $external_unresolved == "$expected_external_unresolved" ]] || {
  echo "the external cgroup denials did not record their exact unresolved effects" >&2
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
exception_baseline_status=$(node_status "$selected_node")
IFS=$'\t' read -r consumed_exception_baseline expired_exception_baseline \
  revoked_exception_baseline \
  < <(jq -er '[
      .consumed_exception_count,
      .expired_exception_count,
      .revoked_exception_count
    ] | @tsv' <<<"$exception_baseline_status")
other_terminal_exception_baseline=$(jq -er '.terminal_exception_count' \
  <<<"$(node_status "$other_node")")
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
  .exception_ack_pending_count == 0
' <<<"$(node_status "$other_node")" >/dev/null
[[ $(jq -er '.terminal_exception_count' <<<"$(node_status "$other_node")") \
  -eq $other_terminal_exception_baseline ]]

overlap=$work_a/exception-overlap.yaml
sed '0,/name: temporary-file-access/s//name: overlapping-file-access/' \
  "$exception" >"$overlap"
"$provider" put "$vm_a" "$overlap" "$remote_a/exception-overlap.yaml"
remote_kubectl --as="$exception_subject" create \
  -f "$remote_a/exception-overlap.yaml" >/dev/null
if ! remote_kubectl -n "$workload_namespace" wait \
    --for=jsonpath='{.status.state}'=Failed \
    workloadprotectionexception/overlapping-file-access \
    --timeout=180s >/dev/null; then
  echo "exception overlapping-file-access did not reject while the first grant was active" >&2
  exit 1
fi
remote_kubectl --as="$exception_subject" -n "$workload_namespace" delete \
  workloadprotectionexception overlapping-file-access --wait=true --timeout=120s >/dev/null

signal_pod_request "$selected_vm" \
  /var/lib/mithril-convergence/markers/protected.exception-request EXCEPTION
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
exception_status=$(node_status "$selected_node")
exception_status_counter_advanced_by "$exception_status" \
  consumed_exception_count "$consumed_exception_baseline" 1
jq -e '.active_exception_count == 0' <<<"$exception_status" >/dev/null

first_exception_uid=$(remote_kubectl -n "$workload_namespace" get \
  workloadprotectionexception temporary-file-access -o jsonpath='{.metadata.uid}')
remote_kubectl --as="$exception_subject" -n "$workload_namespace" delete \
  workloadprotectionexception temporary-file-access --wait=true --timeout=120s >/dev/null
for _attempt in {1..120}; do
  exception_status=$(node_status "$selected_node")
  if exception_status_counter_advanced_by "$exception_status" \
      revoked_exception_count "$revoked_exception_baseline" 1 &&
      jq -e '.exception_ack_pending_count == 0' \
        <<<"$exception_status" >/dev/null; then
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
  -e 's/requestedDuration: 4m/requestedDuration: 30s/' \
  "$exception" >"$expired"
"$provider" put "$vm_a" "$expired" "$remote_a/exception-expired.yaml"
remote_kubectl --as="$exception_subject" create \
  -f "$remote_a/exception-expired.yaml" >/dev/null
wait_exception_state expiring-file-access Active
wait_exception_state expiring-file-access Expired
exception_status=$(node_status "$selected_node")
exception_status_counter_advanced_by "$exception_status" \
  expired_exception_count "$expired_exception_baseline" 1
jq -e '.active_exception_count == 0' <<<"$exception_status" >/dev/null
remote_kubectl --as="$exception_subject" -n "$workload_namespace" delete \
  workloadprotectionexception expiring-file-access --wait=true --timeout=120s >/dev/null
for _attempt in {1..120}; do
  exception_status=$(node_status "$selected_node")
  if exception_status_counter_advanced_by "$exception_status" \
      revoked_exception_count "$revoked_exception_baseline" 2 &&
      jq -e '.exception_ack_pending_count == 0' \
        <<<"$exception_status" >/dev/null; then
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

for node in "$vm_a" "$vm_b"; do
  "$provider" run "$node" sudo mv -- \
    "$runtime_hook_socket" "$held_runtime_socket"
done
runtime_sockets_held=true
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
gate_status=$(wait_runtime_delivery "$selected_node" "$profile_id" \
  2 1 1 "$protected_candidate")
gate_candidate=$(jq -er '.active_candidate_content_id' <<<"$gate_status")
jq -e --arg predecessor "$protected_candidate" '
  .active_candidate_content_id as $candidate |
  all(.active_targets[];
    .candidate_content_id == $candidate and
    .operation == "REPLACE" and
    .predecessor_candidate_content_id == $predecessor)
' <<<"$gate_status" >/dev/null
"$provider" run "$vm_a" sudo test ! -e \
  /var/lib/mithril-convergence/markers/gate-failure.started
"$provider" run "$vm_b" sudo test ! -e \
  /var/lib/mithril-convergence/markers/gate-failure.started
remote_kubectl -n "$workload_namespace" delete pod gate-failure \
  --wait=true --timeout=120s >/dev/null
restore_runtime_sockets

restart_baseline=$(wait_runtime_delivery "$selected_node" "$profile_id" \
  1 0 1 "$gate_candidate")
protected_candidate=$(jq -er '.active_candidate_content_id' <<<"$restart_baseline")
protected_operation=$(jq -er '.active_targets[0].operation' <<<"$restart_baseline")
protected_predecessor=$(jq -er \
  '.active_targets[0].predecessor_candidate_content_id // ""' \
  <<<"$restart_baseline")
protected_source_revision=$(jq -er \
  '.active_targets[0].policy_source_revision_id' <<<"$restart_baseline")
jq -e --arg predecessor "$gate_candidate" '
  .active_targets[0].operation == "REPLACE" and
  .active_targets[0].predecessor_candidate_content_id == $predecessor
' <<<"$restart_baseline" >/dev/null
assert_live_exact_target "$selected_node" "$profile_id" \
  "$protected_operation" "$protected_predecessor" "$protected_source_revision"

container_before=$(remote_kubectl -n "$workload_namespace" get pod protected \
  -o jsonpath='{.status.containerStatuses[0].containerID}')
signal_pod_request "$selected_vm" \
  /var/lib/mithril-convergence/markers/protected.restart RESTART
container_identity_after=$(wait_running_container_identity \
  "$selected_vm" "$workload_namespace" protected "$container_before")
container_after=$(jq -er '.container_uri' <<<"$container_identity_after")
container_after_id=$(jq -er '.container_id' <<<"$container_identity_after")
host_pid_after=$(jq -er '.host_pid' <<<"$container_identity_after")
restarted_status=$(wait_runtime_delivery "$selected_node" "$profile_id" \
  1 0 1 "" "$container_after_id")
assert_live_exact_target "$selected_node" "$profile_id" \
  "$protected_operation" "$protected_predecessor" "$protected_source_revision"
jq -e --arg candidate "$protected_candidate" \
  '.active_candidate_content_id == $candidate' <<<"$restarted_status" >/dev/null
runtime_binding_after=$(jq -er '.active_targets[0].runtime_binding_id' \
  <<<"$restarted_status")
[[ $runtime_binding_after != "$runtime_binding_before" ]] || {
  echo "the restarted container retained its old runtime binding" >&2
  exit 1
}
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
assert_live_exact_target "$selected_node" "$profile_id" \
  "$protected_operation" "$protected_predecessor" "$protected_source_revision"

# Hold one matching node without a node process and prove that it stays quarantined.
"$provider" run "$other_vm" sudo mv /etc/mithril/node.json /etc/mithril/node.json.held
other_node_pod=$(remote_kubectl -n "$system_namespace" get pods \
  -l app.kubernetes.io/name=mithril-node --field-selector "spec.nodeName=$other_node" \
  -o jsonpath='{.items[0].metadata.name}')
remote_kubectl -n "$system_namespace" delete pod "$other_node_pod" \
  --wait=true --timeout=120s >/dev/null
wait_node_projection "$other_node" "" true
render_pod ready-node-only mithril
prepare_pod_markers ready-node-only
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
remote_kubectl label node "$node_a_name" "$node_b_name" \
  mithril.erebor.dev/fixture- >/dev/null
remote_kubectl label node "$selected_node" mithril.erebor.dev/fixture=selected --overwrite >/dev/null
remote_kubectl -n "$system_namespace" patch daemonset mithril-node --type=merge \
  -p '{"spec":{"template":{"spec":{"nodeSelector":{"mithril.erebor.dev/fixture":"selected"}}}}}' \
  >/dev/null
wait_node_projection "$other_node" "" false
remote_kubectl -n "$system_namespace" rollout status daemonset/mithril-node \
  --timeout=300s >/dev/null
wait_node_projection "$selected_node" true false
render_pod selector-derived mithril
selector_dry_run=$(remote_kubectl create --dry-run=server \
  -f "$remote_a/selector-derived.yaml" -o json)
jq -e '.spec.nodeSelector["mithril.erebor.dev/fixture"] == "selected"' \
  <<<"$selector_dry_run" >/dev/null
prepare_pod_markers selector-derived
remote_kubectl create -f "$remote_a/selector-derived.yaml" >/dev/null
remote_kubectl -n "$workload_namespace" wait --for=condition=Ready pod/selector-derived \
  --timeout=300s >/dev/null
[[ $(remote_kubectl -n "$workload_namespace" get pod selector-derived \
  -o jsonpath='{.spec.nodeName}') == "$selected_node" ]]
remote_kubectl -n "$workload_namespace" delete pod selector-derived \
  --wait=true --timeout=120s >/dev/null
"$provider" run "$other_vm" sudo mv /etc/mithril/node.json /etc/mithril/node.json.held
remote_kubectl -n "$system_namespace" patch daemonset mithril-node --type=merge \
  -p '{"spec":{"template":{"spec":{"nodeSelector":{"mithril.erebor.dev/fixture":null}}}}}' \
  >/dev/null
wait_node_projection "$other_node" "" true
"$provider" run "$other_vm" sudo mv /etc/mithril/node.json.held /etc/mithril/node.json
remote_kubectl -n "$system_namespace" rollout status daemonset/mithril-node \
  --timeout=300s >/dev/null
wait_node_projection "$other_node" true false
wait_node_projection "$selected_node" true false
assert_ready_projection_stable "$selected_node"
assert_live_exact_target "$selected_node" "$profile_id" "" "" \
  "$protected_source_revision"

policy_before=$(node_status "$selected_node")
candidate_before=$(jq -er '.active_candidate_content_id' <<<"$policy_before")
source_revision_before=$(jq -er \
  '.active_targets[0].policy_source_revision_id' <<<"$policy_before")
make_policy_manifest 3
remote_kubectl --as="$policy_subject" apply --server-side --validate=strict \
  -f "$remote_a/policy-v3.yaml" >/dev/null
wait_policy_compiled
candidate_after=$(wait_stable_live_replacement \
  "$selected_node" "$profile_id" "$candidate_before" "$source_revision_before")
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

assert_node_evidence_health_clean "$selected_node"
assert_node_evidence_health_clean "$other_node"

# Reboot removes the host BPF maps. The new boot and label epoch must start a
# new policy chain only after the node proves that the old authority is absent.
pre_reboot_pod_uid=$(remote_kubectl -n "$workload_namespace" get pod protected \
  -o jsonpath='{.metadata.uid}')
reboot_pod=$work_a/protected-after-reboot.json
remote_kubectl create --dry-run=client -f "$remote_a/protected.yaml" -o json | jq '
  .spec.nodeSelector = ((.spec.nodeSelector // {}) +
    {"mithril.erebor.dev/fixture": "selected"})
' >"$reboot_pod"
"$provider" put "$vm_a" "$reboot_pod" "$remote_a/protected-after-reboot.json"
pre_reboot_node=$(remote_kubectl get node "$selected_node" -o json)
pre_reboot_boot_id=$(jq -er \
  '.metadata.annotations["mithril.erebor.dev/node-boot-id"]' <<<"$pre_reboot_node")
pre_reboot_label_epoch=$(jq -er \
  '.metadata.annotations["mithril.erebor.dev/label-epoch"] | tonumber' \
  <<<"$pre_reboot_node")
request_vm_reboot "$selected_vm"
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
# A Pod that kubelet rejects during the quarantine interval is terminal. Start
# a new workload lifetime after the new physical epoch becomes ready.
remote_kubectl -n "$workload_namespace" delete pod protected \
  --ignore-not-found --wait=true --timeout=120s >/dev/null
prepare_pod_markers protected
remote_kubectl create -f "$remote_a/protected-after-reboot.json" >/dev/null
remote_kubectl -n "$workload_namespace" wait --for=condition=Ready pod/protected \
  --timeout=300s >/dev/null
post_reboot_pod_uid=$(remote_kubectl -n "$workload_namespace" get pod protected \
  -o jsonpath='{.metadata.uid}')
[[ -n $post_reboot_pod_uid && $post_reboot_pod_uid != "$pre_reboot_pod_uid" ]]
[[ $(remote_kubectl -n "$workload_namespace" get pod protected \
  -o jsonpath='{.spec.nodeName}') == "$selected_node" ]]
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
# The root activation was proved before restart. Inventory can produce a valid
# successor while the Control readiness projection recovers.
assert_live_exact_target "$selected_node" "$profile_id"

old_pod_uid=$(remote_kubectl -n "$workload_namespace" get pod protected \
  -o jsonpath='{.metadata.uid}')
# Keep the recreated grant unused. Removing its exact Pod must retire it.
consumed_before_retirement=$(jq -er '.consumed_exception_count' \
  <<<"$(node_status "$selected_node")")
sed \
  -e "s/MITHRIL_CONVERGENCE_NAMESPACE/$workload_namespace/g" \
  -e "s/MITHRIL_CONVERGENCE_POD_UID/$post_reboot_pod_uid/g" \
  -e 's/requestedDuration: 4m/requestedDuration: 2m/' \
  "$repo_root/crates/mithril-e2e/fixtures/convergence/exception-v1.yaml" \
  >"$exception"
"$provider" put "$vm_a" "$exception" "$remote_a/exception-v1.yaml"
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
      .exception_ack_pending_count == 0
    ' <<<"$exception_status" >/dev/null &&
      exception_status_counter_advanced_by "$exception_status" \
        revoked_exception_count "$revoked_exception_baseline" 3; then
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

# A Control and node restart must not replay stale policy after inventory cleanup.
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

prepare_pod_markers protected
make_policy_manifest 4
remote_kubectl --as="$policy_subject" apply --server-side --validate=strict \
  -f "$remote_a/policy-v4.yaml" >/dev/null
wait_policy_compiled
recreated_profile_id=$(remote_kubectl -n "$workload_namespace" get \
  workloadprotectionpolicy converter-policy -o jsonpath='{.metadata.uid}')
[[ $recreated_profile_id != "$profile_id" ]]
prepare_pod_markers protected
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

# Use fresh Node Pods to prove that durable cleanup does not replay a stale close.
remote_kubectl -n "$system_namespace" rollout restart daemonset/mithril-node >/dev/null
remote_kubectl -n "$system_namespace" rollout status daemonset/mithril-node \
  --timeout=300s >/dev/null
for node_name in "$node_a_name" "$node_b_name"; do
  wait_node_projection "$node_name" true false
  assert_ready_projection_stable "$node_name"
  assert_node_evidence_health_clean "$node_name"
done

jq -n \
  --arg kubernetes_version "$(remote_kubectl version -o json | jq -r '.serverVersion.gitVersion')" \
  --arg containerd_version "$("$provider" run "$vm_a" sudo /usr/local/bin/k3s ctr version | awk '/Version:/ && !found {print $2; found = 1}')" \
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
    running_policy_update: true,
    exception_one_use_consumed: true,
    exception_expired: true,
    exception_revoked: true,
    exception_target_retired: true,
    exception_recreated_with_new_uid: true,
    exception_overlap_rejected: true,
    exception_excess_bound_rejected: true,
    desired_inventory_cleaned: true,
    deleted_root_not_inspected: true,
    old_root_replay_refused: true,
    fresh_policy_uses_root_activation: true,
    direct_runc_runtime_gate_passed: true,
    rbac_boundary: true
  }' >"$output_directory/two-node-convergence.json"

echo "Two-node Kubernetes policy convergence passed. Evidence: $output_directory"
