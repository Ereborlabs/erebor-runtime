#!/usr/bin/env bash

set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
manual_case=$directory/../../../../examples/mithril-kubernetes-convergence-manual/run.sh
test_root=$(mktemp -d /tmp/mithril-vm-harness-test.XXXXXX)
trap 'rm -rf -- "$test_root"' EXIT

for script in "$directory/run.sh" "$directory/two-node-network.sh" \
  "$directory/two-node-convergence.sh" \
  "$directory/convergence-cleanup.sh" \
  "$directory/../kubernetes-oracles.sh" \
  "$directory/manual.sh" "$directory/guest.sh" \
  "$directory/providers/libvirt.sh" "$directory/test.sh" "$manual_case"; do
  bash -n "$script"
done

fake_manual_bin=$test_root/manual-bin
mkdir "$fake_manual_bin"
cat >"$fake_manual_bin/kubectl" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${TEST_KUBECTL_LOG:?}"
[[ $* == "get --raw=/readyz" ]] && exit 0
[[ ${1:-} == -n && ${3:-} == rollout && ${4:-} == status ]] && exit 0
if [[ ${1:-} == get && ${2:-} == namespace ]]; then
  [[ ${TEST_EXISTING_RESOURCE:?} == namespace ]]
  exit
fi
if [[ ${1:-} == get && ${2:-} == runtimeclass ]]; then
  [[ ${TEST_EXISTING_RESOURCE:?} == runtimeclass && ${3:-} == mithril-convergence-manual ]]
  exit
fi
[[ " $* " == *" delete "* ]] && exit 97
exit 98
EOF
chmod +x "$fake_manual_bin/kubectl"
cat >"$fake_manual_bin/id" <<'EOF'
#!/usr/bin/env bash
if [[ ${1:-} == -u ]]; then
  echo 0
else
  exec /usr/bin/id "$@"
fi
EOF
chmod +x "$fake_manual_bin/id"
for existing_resource in namespace runtimeclass; do
  manual_log=$test_root/manual-$existing_resource.log
  set +e
  manual_refusal=$(PATH="$fake_manual_bin:$PATH" \
    TEST_KUBECTL_LOG="$manual_log" TEST_EXISTING_RESOURCE="$existing_resource" \
    "$manual_case" 2>&1)
  status=$?
  set -e
  [[ $status -eq 2 && $manual_refusal == \
    *"manual scenario refuses to replace an existing resource"* ]]
  ! grep -q ' delete ' "$manual_log"
done

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
retained_helm_log=$test_root/retained-helm.log
touch "$test_root/kubeconfig"
PATH="$cleanup_bin:$PATH" TEST_HELM_LOG="$retained_helm_log" \
  remove_mithril_release true true false "$test_root/kubeconfig" mithril-system
[[ ! -e $retained_helm_log ]]
removed_helm_log=$test_root/removed-helm.log
PATH="$cleanup_bin:$PATH" TEST_HELM_LOG="$removed_helm_log" \
  remove_mithril_release true false false "$test_root/kubeconfig" mithril-system
grep -q '^--kubeconfig .* uninstall mithril -n mithril-system$' "$removed_helm_log"

diagnostic_kubectl() {
  printf '%s\n' "$*" >>"$test_root/diagnostic-kubectl.log"
  echo "bounded diagnostic output"
}
collect_mithril_diagnostics "$test_root" mithril-system
[[ -s $test_root/diagnostics/resources.txt ]]
[[ -s $test_root/diagnostics/control.log ]]
[[ -s $test_root/diagnostics/nodes.log ]]
grep -q -- '--tail=200 --limit-bytes=131072' "$test_root/diagnostic-kubectl.log"

oracle_bin=$test_root/oracle-bin
mkdir "$oracle_bin"
cat >"$oracle_bin/kubectl" <<'EOF'
#!/usr/bin/env bash
case ${FAKE_KUBECTL_RESULT:?} in
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
