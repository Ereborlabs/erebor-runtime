#!/usr/bin/env bash

set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/clock.sh"
test_root=$(mktemp -d /tmp/mithril-vm-harness-test.XXXXXX)
test_cleanup() {
  local status=$?
  trap - EXIT
  rm -rf -- "$test_root"
  exit "$status"
}
trap test_cleanup EXIT

[[ $(clock_skew_seconds 100 91) -eq 9 ]]
[[ $(clock_skew_seconds 91 100) -eq 9 ]]
clock_is_within_tolerance 100 85 15
if clock_is_within_tolerance 100 84 15; then
  echo "a future TLS identity accepted excessive guest clock skew" >&2
  exit 1
fi

help=$("$directory/run.sh" --help 2>&1)
[[ $help == *--with-k3s* ]]
[[ $help == *--skip-administrative-exec* ]]
[[ $help == *--keep-vm* ]]
[[ $help == *--manual* ]]
"$directory/guest.sh" --help >/dev/null 2>&1
two_node_help=$("$directory/two-node-network.sh" --help 2>&1)
[[ $two_node_help == *--keep-vms* ]]
convergence_help=$("$directory/two-node-convergence.sh" --help 2>&1)
[[ $convergence_help == *--keep-vms* ]]
[[ $convergence_help == *--manual-environment* ]]
[[ $convergence_help == *--protected-start-only* ]]
[[ $convergence_help == *--reuse-environment* ]]
grep -Fq 'node_state_host_path=/var/lib/mithril-node-$run_id' \
  "$directory/two-node-convergence.sh"
grep -Fq 'control_state_claim=mithril-control-state-$run_id' \
  "$directory/two-node-convergence.sh"
grep -Fq 'capacity_policy: "RETAIN"' "$directory/two-node-convergence.sh"
grep -Fq 'maximum_retained_records: 2' "$directory/two-node-convergence.sh"
grep -Fq 'node_retain_exceeded_soft_bound_without_loss: true' \
  "$directory/two-node-outage-recovery.sh"
grep -Fq "-exec sha256sum '{}' +" \
  "$directory/two-node-outage-recovery.sh"
if grep -Fq 'delete namespace "$system_namespace"' \
    "$directory/two-node-convergence.sh"; then
  echo "the retained convergence lane deletes durable Control evidence" >&2
  exit 1
fi
if grep -Fq 'for path in /var/lib/mithril-convergence \' \
    "$directory/two-node-convergence.sh"; then
  echo "the retained convergence lane deletes durable Node evidence" >&2
  exit 1
fi
outage_help=$("$directory/two-node-outage-recovery.sh" --help 2>&1)
[[ $outage_help == *--environment* ]]
[[ $outage_help == *--output-directory* ]]
grep -Fq 'systemctl show' "$directory/two-node-outage-recovery.sh"
grep -Fq -- '--property ActiveState --value k3s' \
  "$directory/two-node-outage-recovery.sh"
if grep -Fq 'systemctl is-inactive' "$directory/two-node-outage-recovery.sh"; then
  echo "the outage harness uses an unsupported systemctl state verb" >&2
  exit 1
fi
set +e
outage_without_environment=$("$directory/two-node-outage-recovery.sh" 2>&1)
status=$?
set -e
[[ $status -eq 2 && $outage_without_environment == \
  "retained environment is not readable: " ]]
set +e
protected_manual=$("$directory/two-node-convergence.sh" \
  --protected-start-only --manual-environment 2>&1)
status=$?
set -e
[[ $status -eq 2 && $protected_manual == \
  "--protected-start-only cannot run with --manual-environment" ]]

set +e
reuse_manual=$("$directory/two-node-convergence.sh" \
  --reuse-environment /tmp/not-used --manual-environment 2>&1)
status=$?
set -e
[[ $status -eq 2 && $reuse_manual == \
  "retained environment is not readable: /tmp/not-used" ]]

set +e
convergence_without_mount=$("$directory/two-node-convergence.sh" \
  --manual-environment 2>&1)
status=$?
set -e
[[ $status -eq 2 && $convergence_without_mount == \
  "the manual environment requires MITHRIL_VM_SOURCE_MOUNT="* ]]

set +e
manual_without_mount=$("$directory/run.sh" --manual 2>&1)
status=$?
set -e
[[ $status -eq 2 && $manual_without_mount == "--manual requires MITHRIL_VM_SOURCE_MOUNT" ]]

set +e
manual_usage=$("$directory/manual.sh" 2>&1)
status=$?
set -e
[[ $status -eq 2 && $manual_usage == \
  "usage: $directory/manual.sh {start|ssh|destroy|start-convergence|ssh-convergence|destroy-convergence}" ]]

manual_state=$test_root/manual-state
mkdir -p "$manual_state/mithril-manual-vm"
touch "$manual_state/mithril-manual-vm/retained-vm.txt"
set +e
manual_existing=$(XDG_STATE_HOME=$manual_state "$directory/manual.sh" start 2>&1)
status=$?
set -e
[[ $status -eq 2 && $manual_existing == *"manual VM already exists"* ]]

mkdir -p "$manual_state/mithril-convergence-manual-vm"
touch "$manual_state/mithril-convergence-manual-vm/retained-vms.txt"
set +e
convergence_existing=$(XDG_STATE_HOME=$manual_state \
  "$directory/manual.sh" start-convergence 2>&1)
status=$?
set -e
[[ $status -eq 2 && $convergence_existing == \
  *"convergence environment already exists"* ]]

set +e
invalid_effect_mode=$(MITHRIL_VM_CRI_EFFECT_MODE=invalid \
  "$directory/guest.sh" k3s-cri-effect 2>&1)
status=$?
set -e
[[ $status -eq 2 && $invalid_effect_mode == "invalid MITHRIL_VM_CRI_EFFECT_MODE: invalid" ]]

set +e
invalid=$("$directory/guest.sh" k3s-install latest /dev/null /tmp 2>&1)
status=$?
set -e
[[ $status -eq 2 && $invalid == "invalid k3s version: latest" ]]

set +e
skip_without_k3s=$("$directory/run.sh" --skip-administrative-exec 2>&1)
status=$?
set -e
[[ $status -eq 2 && $skip_without_k3s == "--skip-administrative-exec requires --with-k3s" ]]

cleanup_bin=$test_root/cleanup-bin
mkdir "$cleanup_bin"
cat >"$cleanup_bin/helm" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${TEST_HELM_LOG:?}"
EOF
chmod +x "$cleanup_bin/helm"
source "$directory/convergence-cleanup.sh"
cleanup_result 0 false
if cleanup_result 0 true; then
  echo "a cleanup failure returned success" >&2
  exit 1
fi
set +e
cleanup_result 42 true
status=$?
set -e
[[ $status -eq 42 ]]
retained_helm_log=$test_root/retained-helm.log
touch "$test_root/kubeconfig"
PATH="$cleanup_bin:$PATH" TEST_HELM_LOG="$retained_helm_log" \
  remove_mithril_release true true false "$test_root/kubeconfig" mithril-system
[[ ! -e $retained_helm_log ]]
removed_helm_log=$test_root/removed-helm.log
PATH="$cleanup_bin:$PATH" TEST_HELM_LOG="$removed_helm_log" \
  remove_mithril_release true false false "$test_root/kubeconfig" mithril-system
grep -q '^--kubeconfig .* uninstall mithril -n mithril-system$' "$removed_helm_log"

hook_root=$test_root/hook-root
hook_binary=$hook_root/usr/libexec/oci/hooks.d/mithril-oci-hook
hook_binary_owner=$hook_root/usr/libexec/oci/hooks.d/.mithril-oci-hook.helm-owner
hook_stage_config=$hook_root/usr/share/containers/oci/hooks.d/98-mithril-runtime-stage.json
hook_stage_config_owner=$hook_root/usr/libexec/oci/hooks.d/.98-mithril-runtime-stage.json.helm-owner
hook_admission_config=$hook_root/usr/share/containers/oci/hooks.d/99-mithril-runtime-admission.json
hook_admission_config_owner=$hook_root/usr/libexec/oci/hooks.d/.99-mithril-runtime-admission.json.helm-owner
hook_entry_config=$hook_root/usr/share/containers/oci/hooks.d/99-mithril-runtime-entry-preparation.json
hook_entry_config_owner=$hook_root/usr/libexec/oci/hooks.d/.99-mithril-runtime-entry-preparation.json.helm-owner
hook_socket=$hook_root/run/mithril/runtime-admission.sock
mkdir -p "$(dirname "$hook_binary")" "$(dirname "$hook_stage_config")" \
  "$(dirname "$hook_socket")" "$test_root/hook-bin"
printf '#!/bin/sh\nexit 0\n' >"$hook_binary"
chmod 755 "$hook_binary"
printf 'mithril-system/mithril\n' >"$hook_binary_owner"
printf 'mithril-system/mithril\n' >"$hook_stage_config_owner"
printf 'mithril-system/mithril\n' >"$hook_admission_config_owner"
printf 'mithril-system/mithril\n' >"$hook_entry_config_owner"
chmod 600 "$hook_binary_owner" "$hook_stage_config_owner" \
  "$hook_admission_config_owner" "$hook_entry_config_owner"
cat >"$hook_stage_config" <<'EOF'
{
  "version": "1.0.0",
  "hook": {
    "path": "/usr/libexec/oci/hooks.d/mithril-oci-hook",
    "args": ["mithril-oci-hook", "--stage", "stage-runtime-facts", "--socket", "/run/mithril/runtime-admission.sock", "--timeout-ms", "4000"],
    "timeout": 5
  },
  "when": {"annotations": {"^mithril\\.erebor\\.dev/profile-id$": ".+"}},
  "stages": ["createRuntime"]
}
EOF
cat >"$hook_admission_config" <<'EOF'
{
  "version": "1.0.0",
  "hook": {
    "path": "/usr/libexec/oci/hooks.d/mithril-oci-hook",
    "args": ["mithril-oci-hook", "--stage", "prepare-container", "--socket", "/run/mithril/runtime-admission.sock", "--timeout-ms", "4000"],
    "timeout": 5
  },
  "when": {"annotations": {"^mithril\\.erebor\\.dev/profile-id$": ".+"}},
  "stages": ["createRuntime"]
}
EOF
cat >"$hook_entry_config" <<'EOF'
{
  "version": "1.0.0",
  "hook": {
    "path": "/usr/libexec/oci/hooks.d/mithril-oci-hook",
    "args": ["mithril-oci-hook", "--stage", "prepare-declared-entries", "--socket", "/run/mithril/runtime-admission.sock", "--timeout-ms", "4000"],
    "timeout": 5
  },
  "when": {"annotations": {"^mithril\\.erebor\\.dev/profile-id$": ".+"}},
  "stages": ["createContainer"]
}
EOF
chmod 644 "$hook_stage_config" "$hook_admission_config" "$hook_entry_config"
cat >"$test_root/hook-bin/stat" <<'EOF'
#!/usr/bin/env bash
path=${!#}
# Preserve actual modes, but supply the root identity that the physical host provides.
if [[ ${2:-} == %F ]]; then
  printf '%s\n' "${TEST_SOCKET_TYPE:-socket}"
  exit 0
fi
printf '%s:0:%s\n' "${TEST_STAT_UID:-0}" "$(/usr/bin/stat -c %a "$path")"
EOF
chmod +x "$test_root/hook-bin/stat"
touch "$hook_socket"
chmod 600 "$hook_socket"
PATH="$test_root/hook-bin:$PATH" bash "$directory/runtime-hook-oracle.sh" \
  installed "$hook_root" mithril-system/mithril \
  /run/mithril/runtime-admission.sock 4000 5
if PATH="$test_root/hook-bin:$PATH" TEST_STAT_UID=1000 \
    bash "$directory/runtime-hook-oracle.sh" installed "$hook_root" \
      mithril-system/mithril /run/mithril/runtime-admission.sock 4000 5 \
      >/dev/null 2>&1; then
  echo "a non-root runtime hook satisfied the installation oracle" >&2
  exit 1
fi
if PATH="$test_root/hook-bin:$PATH" TEST_SOCKET_TYPE='regular file' \
    bash "$directory/runtime-hook-oracle.sh" installed "$hook_root" \
      mithril-system/mithril /run/mithril/runtime-admission.sock 4000 5 \
      >/dev/null 2>&1; then
  echo "a non-socket path satisfied the installation oracle" >&2
  exit 1
fi
if PATH="$test_root/hook-bin:$PATH" bash "$directory/runtime-hook-oracle.sh" \
    installed "$hook_root" mithril-system/mithril \
      /run/mithril/runtime-admission.sock 5000 5 >/dev/null 2>&1; then
  echo "incorrect runtime-hook arguments satisfied the installation oracle" >&2
  exit 1
fi
if bash "$directory/runtime-hook-oracle.sh" removed "$hook_root" \
    /run/mithril/runtime-admission.sock >/dev/null 2>&1; then
  echo "installed runtime-hook paths satisfied the removal oracle" >&2
  exit 1
fi
rm -f -- "$hook_binary" "$hook_binary_owner" \
  "$hook_stage_config" "$hook_stage_config_owner" \
  "$hook_admission_config" "$hook_admission_config_owner" \
  "$hook_entry_config" "$hook_entry_config_owner"
bash "$directory/runtime-hook-oracle.sh" hooks-removed "$hook_root" \
  /run/mithril/runtime-admission.sock
if bash "$directory/runtime-hook-oracle.sh" removed "$hook_root" \
    /run/mithril/runtime-admission.sock >/dev/null 2>&1; then
  echo "a stale runtime socket satisfied the complete removal oracle" >&2
  exit 1
fi
rm -f -- "$hook_socket"
bash "$directory/runtime-hook-oracle.sh" removed "$hook_root" \
  /run/mithril/runtime-admission.sock

diagnostic_kubectl() {
  printf '%s\n' "$*" >>"$test_root/diagnostic-kubectl.log"
  echo "bounded diagnostic output"
}
collect_mithril_diagnostics "$test_root" mithril-system tenant-a
[[ -s $test_root/diagnostics/resources.txt ]]
[[ -s $test_root/diagnostics/nodes.json ]]
[[ -s $test_root/diagnostics/control.log ]]
[[ -s $test_root/diagnostics/nodes.log ]]
[[ -s $test_root/diagnostics/nodes-previous.log ]]
[[ -s $test_root/diagnostics/nri-hook-injector.log ]]
[[ -s $test_root/diagnostics/node-effects-0.log ]]
[[ -s $test_root/diagnostics/node-policy-delivery-0.json ]]
[[ -s $test_root/diagnostics/workload.txt ]]
[[ -s $test_root/diagnostics/workload-events.txt ]]
[[ -s $test_root/diagnostics/workload.log ]]
[[ -s $test_root/diagnostics/workload-previous.log ]]
grep -q -- '--tail=200 --limit-bytes=131072' "$test_root/diagnostic-kubectl.log"
grep -q -- 'app.kubernetes.io/name=mithril-node -c runtime-hook-injector' \
  "$test_root/diagnostic-kubectl.log"
grep -q -- 'mithril-inspect effects --socket-path /run/mithril/observation.sock' \
  "$test_root/diagnostic-kubectl.log"

oracle_bin=$test_root/oracle-bin
mkdir "$oracle_bin"
cat >"$oracle_bin/kubectl" <<'EOF'
#!/usr/bin/env bash
case ${FAKE_KUBECTL_RESULT:?} in
  client)
    printf '%s\n' '{"apiVersion":"v1","kind":"Pod","metadata":{"annotations":{}},"spec":{}}'
    ;;
  node-name)
    echo 'Error from server: admission webhook "pods.mithril.erebor.dev" denied the request: Mithril Control configuration is invalid: protected Pod cannot set spec.nodeName' >&2
    exit 1
    ;;
  strict-field)
    echo 'Error from server (BadRequest): strict decoding error: unknown field "spec.unexpectedField"' >&2
    exit 1
    ;;
  unrelated)
    echo 'Unable to connect to the server' >&2
    exit 1
    ;;
  success)
    exit 0
    ;;
esac
EOF
chmod +x "$oracle_bin/kubectl"
# These checks execute the command path. They do not inspect either fixture script.
source "$directory/../kubernetes-oracles.sh"
node_name_bypass=$test_root/node-name-bypass.json
PATH="$oracle_bin:$PATH" FAKE_KUBECTL_RESULT=client \
  write_mithril_node_name_bypass protected.yaml node-a "$node_name_bypass" kubectl
jq -e '
  .spec.nodeName == "node-a" and
  ([.metadata.annotations | keys[] | select(startswith("mithril.erebor.dev/"))] |
    length) == 0
' "$node_name_bypass" >/dev/null
PATH="$oracle_bin:$PATH" FAKE_KUBECTL_RESULT=node-name \
  assert_mithril_node_name_denial kubectl create -f bypass.json
PATH="$oracle_bin:$PATH" FAKE_KUBECTL_RESULT=strict-field \
  assert_kubernetes_strict_field_denial kubectl replace -f invalid-policy.json
if PATH="$oracle_bin:$PATH" FAKE_KUBECTL_RESULT=unrelated \
    assert_mithril_node_name_denial kubectl create -f bypass.json >/dev/null 2>&1; then
  echo "an unrelated API failure satisfied the nodeName denial oracle" >&2
  exit 1
fi
if PATH="$oracle_bin:$PATH" FAKE_KUBECTL_RESULT=success \
    assert_mithril_node_name_denial kubectl create -f bypass.json >/dev/null 2>&1; then
  echo "a successful Pod create satisfied the nodeName denial oracle" >&2
  exit 1
fi
if PATH="$oracle_bin:$PATH" FAKE_KUBECTL_RESULT=unrelated \
    assert_kubernetes_strict_field_denial kubectl replace \
      -f invalid-policy.json >/dev/null 2>&1; then
  echo "an unrelated API failure satisfied the strict-field denial oracle" >&2
  exit 1
fi
if PATH="$oracle_bin:$PATH" FAKE_KUBECTL_RESULT=success \
    assert_kubernetes_strict_field_denial kubectl replace \
      -f invalid-policy.json >/dev/null 2>&1; then
  echo "a successful policy replace satisfied the strict-field denial oracle" >&2
  exit 1
fi

recreated_node_untainted='{"metadata":{"uid":"new-uid","labels":{},"annotations":{}},"spec":{}}'
recreated_node_quarantined='{"metadata":{"uid":"new-uid","labels":{},"annotations":{}},"spec":{"taints":[{"key":"mithril.erebor.dev/not-ready","effect":"NoSchedule"}]}}'
assert_recreated_node_unbound "$recreated_node_untainted" old-uid
assert_recreated_node_unbound "$recreated_node_quarantined" old-uid
if assert_recreated_node_unbound \
    "$(jq -c '.metadata.annotations["mithril.erebor.dev/node-id"] = "old-node"' \
      <<<"$recreated_node_quarantined")" old-uid; then
  echo "a recreated Node with inherited Mithril identity satisfied the unbound oracle" >&2
  exit 1
fi
if assert_recreated_node_unbound \
    "$(jq -c '.metadata.uid = "old-uid"' <<<"$recreated_node_untainted")" old-uid; then
  echo "the old Node UID satisfied the recreated-Node oracle" >&2
  exit 1
fi

node_json='{"metadata":{"name":"node-a","uid":"node-uid-a","annotations":{"mithril.erebor.dev/node-id":"node-id-a","mithril.erebor.dev/node-uid":"node-uid-a","mithril.erebor.dev/node-boot-id":"boot-a","mithril.erebor.dev/label-epoch":"7"}}}'
pod_json='{"metadata":{"name":"protected","namespace":"tenant-a","uid":"pod-uid-a","annotations":{"mithril.erebor.dev/policy-source-revision":"source-a"}},"spec":{"nodeName":"node-a","containers":[{"name":"app","image":"busybox@sha256:image-a"}]},"status":{"containerStatuses":[{"name":"app","containerID":"containerd://container-a"}]}}'
status_json='{"active_candidate_content_id":"candidate-a","active_target_count":1,"active_targets_truncated":false,"active_targets":[{"profile_id":"profile-a","candidate_content_id":"candidate-a","operation":"ACTIVATE","predecessor_candidate_content_id":null,"policy_source_revision_id":"source-a","workload_binding_generation_digest":"binding-generation-a","node_id":"node-id-a","kubernetes_node_name":"node-a","kubernetes_node_uid":"node-uid-a","node_boot_id":"boot-a","label_epoch":7,"namespace_name":"tenant-a","pod_name":"protected","pod_uid":"pod-uid-a","container_name":"app","image_digest":"sha256:image-a","runtime_container_id":"container-a","runtime_binding_id":"runtime-binding-a","container_generation":1}]}'
assert_exact_policy_target "$status_json" "$node_json" "$pod_json" \
  profile-a app ACTIVATE
if assert_exact_policy_target "$(jq -c '.active_targets[0].runtime_container_id = "wrong"' \
    <<<"$status_json")" "$node_json" "$pod_json" profile-a app ACTIVATE; then
  echo "a target for a different runtime container satisfied the exact-target oracle" >&2
  exit 1
fi
if assert_exact_policy_target "$status_json" "$node_json" "$pod_json" \
    profile-a app REPLACE candidate-before; then
  echo "a root activation satisfied a predecessor-bound replacement oracle" >&2
  exit 1
fi
restarted_pod_json=$(jq -c \
  '.status.containerStatuses[0].containerID = "containerd://container-b"' \
  <<<"$pod_json")
replacement_status_json=$(jq -c '
  .active_candidate_content_id = "candidate-b" |
  .active_targets[0].candidate_content_id = "candidate-b" |
  .active_targets[0].operation = "REPLACE" |
  .active_targets[0].predecessor_candidate_content_id = "candidate-a" |
  .active_targets[0].policy_source_revision_id = "source-b"
' <<<"$status_json")
assert_exact_policy_target "$replacement_status_json" "$node_json" \
  "$pod_json" profile-a app REPLACE candidate-a source-b
if assert_exact_policy_target "$replacement_status_json" "$node_json" \
    "$pod_json" profile-a app REPLACE candidate-a; then
  echo "a live policy revision satisfied the admission-source oracle" >&2
  exit 1
fi
restarted_status_json=$(jq -c '
  .active_targets[0].runtime_container_id = "container-b" |
  .active_targets[0].runtime_binding_id = "runtime-binding-b" |
  .active_targets[0].container_generation = 2
' <<<"$replacement_status_json")
assert_exact_policy_target "$restarted_status_json" "$node_json" \
  "$restarted_pod_json" profile-a app REPLACE candidate-a source-b
[[ $(jq -er '.active_candidate_content_id' <<<"$restarted_status_json") == \
   $(jq -er '.active_candidate_content_id' <<<"$replacement_status_json") ]]
if assert_exact_policy_target "$(jq -c \
    '.active_targets[0].predecessor_candidate_content_id = "candidate-b"' \
    <<<"$restarted_status_json")" "$node_json" \
    "$restarted_pod_json" profile-a app REPLACE candidate-a source-b; then
  echo "a runtime restart changed the signed candidate predecessor" >&2
  exit 1
fi

fake_provider=$test_root/provider
printf '#!/usr/bin/env bash\nexit 0\n' >"$fake_provider"
chmod +x "$fake_provider"
mkdir "$test_root/evidence"
touch "$test_root/evidence/stale.json"
set +e
nonempty=$(
  "$directory/run.sh" --provider "$fake_provider" \
    --output-directory "$test_root/evidence" 2>&1
)
status=$?
set -e
[[ $status -eq 2 && $nonempty == *"evidence output directory is not empty"* ]]

set +e
two_node_nonempty=$(
  "$directory/two-node-network.sh" --provider "$fake_provider" \
    --output-directory "$test_root/evidence" 2>&1
)
status=$?
set -e
[[ $status -eq 2 && $two_node_nonempty == *"evidence output directory is not empty"* ]]

set +e
convergence_nonempty=$(
  "$directory/two-node-convergence.sh" --provider "$fake_provider" \
    --output-directory "$test_root/evidence" 2>&1
)
status=$?
set -e
[[ $status -eq 2 && $convergence_nonempty == *"evidence output directory is not empty"* ]]

fake_bin=$test_root/bin
mkdir "$fake_bin"
cat >"$fake_bin/virsh" <<'EOF'
#!/usr/bin/env bash
case " $* " in
  *" dominfo "*) exit 0 ;;
  *" domuuid "*) printf '%s\n' "${TEST_DOMAIN_UUID:?}" ;;
  *" destroy "*|*" undefine "*) printf '%s\n' "$*" >>"${TEST_VIRSH_LOG:?}" ;;
esac
EOF
chmod +x "$fake_bin/virsh"
work_directory=$(mktemp -d /tmp/mithril-vm-test.XXXXXX)
domain_name=mithril-runtime-qualification-123
owner_uuid=11111111-2222-4333-8444-555555555555
other_uuid=aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee
printf '%s\n%s\n' "$domain_name" "$owner_uuid" \
  >"$work_directory/libvirt-domain-owner"
set +e
mismatch=$(
  PATH="$fake_bin:$PATH" TEST_DOMAIN_UUID="$other_uuid" \
    TEST_VIRSH_LOG="$test_root/virsh.log" \
    "$directory/providers/libvirt.sh" destroy "$domain_name" "$work_directory" 2>&1
)
status=$?
set -e
[[ $status -eq 2 && $mismatch == *"different UUID"* ]]
[[ ! -e $test_root/virsh.log ]]
PATH="$fake_bin:$PATH" TEST_DOMAIN_UUID="$owner_uuid" \
  TEST_VIRSH_LOG="$test_root/virsh.log" \
  "$directory/providers/libvirt.sh" destroy "$domain_name" "$work_directory"
grep -q 'destroy.*mithril-runtime-qualification-123' "$test_root/virsh.log"
[[ ! -e $work_directory/libvirt-domain-owner ]]
rm -rf -- "$work_directory"

echo "VM harness behavior checks passed"
