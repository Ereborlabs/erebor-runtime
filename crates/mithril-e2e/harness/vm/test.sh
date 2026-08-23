#!/usr/bin/env bash

set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
test_root=$(mktemp -d /tmp/mithril-vm-harness-test.XXXXXX)
trap 'rm -rf -- "$test_root"' EXIT

for script in "$directory/run.sh" "$directory/two-node-network.sh" \
  "$directory/two-node-convergence.sh" \
  "$directory/manual.sh" "$directory/identity.sh" "$directory/guest.sh" \
  "$directory/runtime-interceptor.sh" "$directory/providers/libvirt.sh" \
  "$directory/test.sh"; do
  bash -n "$script"
done

. "$directory/runtime-interceptor.sh"
diagnostic_root=$test_root/runtime-interceptor-diagnostics
mkdir -p "$diagnostic_root"
set +e
(
  set -Ee
  lane_root=$diagnostic_root
  trap report_probe_failure ERR
  [[ diagnostic-left == diagnostic-right ]]
) 2>"$diagnostic_root/stderr.txt"
status=$?
set -e
[[ $status -eq 1 ]]
grep -qx 'status=1' "$diagnostic_root/failure.txt"
grep -Eq '^line=[0-9]+$' "$diagnostic_root/failure.txt"
grep -Fqx 'command=[[ diagnostic-left == diagnostic-right ]]' \
  "$diagnostic_root/failure.txt"
grep -Eq '^Runtime Interceptor probe failed at line [0-9]+: ' \
  "$diagnostic_root/stderr.txt"

failure_session_root=$test_root/runtime-interceptor-session-state
failure_binding_root=$test_root/runtime-interceptor-binding-state
for index in $(seq -w 0 32); do
  mkdir -p "$failure_session_root/session-$index/output"
done
printf '%s\n' '{"state":"failed"}' \
  >"$failure_session_root/session-00/session.json"
truncate -s 1048577 \
  "$failure_session_root/session-00/output/linux-controller-diagnostics.log"
mkdir -p "$failure_binding_root"
printf '%s\n' '{"status":"active"}' >"$failure_binding_root/binding.json"
collect_failure_state "$diagnostic_root/durable-state" \
  "$failure_session_root" "$failure_binding_root"
cmp -s "$failure_session_root/session-00/session.json" \
  "$diagnostic_root/durable-state/sessions/session-00/session.json"
captured_diagnostics=$diagnostic_root/durable-state/sessions/session-00/linux-controller-diagnostics.log
[[ $(stat -c %s "$captured_diagnostics") == 1048576 ]]
[[ -f $captured_diagnostics.truncated ]]
[[ -f "$diagnostic_root/durable-state/sessions.limit" ]]
cmp -s "$failure_binding_root/binding.json" \
  "$diagnostic_root/durable-state/bindings/binding.json"

runtime_file_probe=$test_root/runtime-file-probe
runtime_file_target=$test_root/runtime-file-target
cc -nostdlib -static -no-pie -Wl,--build-id=none -Wl,-z,noexecstack \
  -Wl,-T,"$directory/runtime-file-probe.ld" \
  "$directory/runtime-file-probe.S" -o "$runtime_file_probe"
file "$runtime_file_probe" | grep -q 'statically linked'
! readelf -l "$runtime_file_probe" | grep -q ' INTERP '
[[ $(readelf -lW "$runtime_file_probe" \
  | awk '$1 == "LOAD" { print $7 }') == E ]]
printf '%s' runtime-target >"$runtime_file_target"
[[ $($runtime_file_probe open "$runtime_file_target") == \
  runtime-file-open-succeeded ]]
[[ $(<"$runtime_file_target") == runtime-target ]]
[[ $(printf r | "$runtime_file_probe" read "$runtime_file_target") == \
  runtime-file-read-succeeded ]]
printf '%s' mutation-sentinel >"$runtime_file_target"
[[ $("$runtime_file_probe" mutation "$runtime_file_target") == \
  runtime-file-mutation-succeeded ]]
[[ $(<"$runtime_file_target") == Xutation-sentinel ]]
runtime_file_pty_output=$(printf 'r\n' | script -qefc \
  "stty rows 24 cols 80; exec $runtime_file_probe read $runtime_file_target" \
  /dev/null)
[[ $runtime_file_pty_output == *runtime-file-read-succeeded* ]]

. "$directory/identity.sh"
repo_root=$(cd -- "$directory/../../../.." && pwd)
branch_name=$(mithril_vm_branch_name "$repo_root")
branch_key=$(mithril_vm_branch_key "$branch_name")
[[ $branch_key =~ ^[a-z0-9]+(-[a-z0-9]+)*-[0-9a-f]{12}$ ]]
[[ $(mithril_vm_branch_key feature/a_b) != \
   "$(mithril_vm_branch_key feature/a-b)" ]]
long_key=$(mithril_vm_branch_key \
  feature/this-is-a-very-long-branch-name-that-must-not-reach-the-hostname-limit)
single_name=$(mithril_vm_name "$long_key" s 4194304)
runtime_name=$(mithril_vm_name "$long_key" r 4194304)
network_a=$(mithril_vm_name "$long_key" n 4194304 a)
network_b=$(mithril_vm_name "$long_key" n 4194304 b)
convergence_a=$(mithril_vm_name "$long_key" c 4194304 a)
[[ ${#single_name} -le 63 && ${#runtime_name} -le 63 && ${#network_a} -le 63 ]]
[[ $single_name != "$runtime_name" && $runtime_name != "$network_a" &&
   $network_a != "$network_b" &&
   $network_a != "$convergence_a" ]]
if mithril_vm_name "$long_key" invalid 4194304 >/dev/null; then
  echo "invalid VM lanes must fail" >&2
  exit 1
fi

help=$("$directory/run.sh" --help 2>&1)
[[ $help == *--with-k3s* ]]
[[ $help == *--skip-administrative-exec* ]]
[[ $help == *--runtime-interceptor* ]]
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
  "usage: $directory/manual.sh {create|status|reconnect|destroy|create-convergence|status-convergence|reconnect-convergence|destroy-convergence}" ]]

manual_state=$test_root/manual-state
other_branch_key=$(mithril_vm_branch_key other/work)
mkdir -p "$manual_state/mithril-manual-vm/$other_branch_key"
touch "$manual_state/mithril-manual-vm/$other_branch_key/retained-vm.txt"
set +e
branch_isolated=$(XDG_STATE_HOME=$manual_state \
  "$directory/manual.sh" status 2>&1)
status=$?
set -e
[[ $status -eq 2 && $branch_isolated == \
  *"no manual VM exists for $branch_name"* ]]

mkdir -p "$manual_state/mithril-manual-vm/$branch_key"
touch "$manual_state/mithril-manual-vm/$branch_key/retained-vm.txt"
set +e
manual_existing=$(XDG_STATE_HOME=$manual_state "$directory/manual.sh" create 2>&1)
status=$?
set -e
[[ $status -eq 2 && $manual_existing == *"manual VM already exists"* ]]

mkdir -p "$manual_state/mithril-convergence-manual-vm/$branch_key"
touch "$manual_state/mithril-convergence-manual-vm/$branch_key/retained-vms.txt"
set +e
convergence_existing=$(XDG_STATE_HOME=$manual_state \
  "$directory/manual.sh" create-convergence 2>&1)
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

set +e
runtime_with_k3s=$("$directory/run.sh" --runtime-interceptor --with-k3s 2>&1)
status=$?
set -e
[[ $status -eq 2 && $runtime_with_k3s == \
  "--runtime-interceptor cannot run with --with-k3s or --manual" ]]

fake_provider=$test_root/provider
printf '%s\n' '#!/usr/bin/env bash' \
  'case ${1:-} in' \
  '  status) echo running ;;' \
  '  ssh) printf "ssh=%s\\n" "$2" ;;' \
  '  destroy) exit 0 ;;' \
  'esac' >"$fake_provider"
chmod +x "$fake_provider"

manual_work=$(mktemp -d /tmp/mithril-vm-test.XXXXXX)
manual_vm=$(mithril_vm_name "$branch_key" s 12345)
manual_state_file=$manual_state/mithril-manual-vm/$branch_key/retained-vm.txt
printf 'branch_name=%q\nbranch_key=%q\nvm_name=%q\nwork_directory=%q\nprovider=%q\n' \
  "$branch_name" "$branch_key" "$manual_vm" "$manual_work" "$fake_provider" \
  >"$manual_state_file"
manual_status=$(XDG_STATE_HOME=$manual_state "$directory/manual.sh" status)
[[ $manual_status == *"branch=$branch_name"* && $manual_status == *"vm=$manual_vm"* &&
   $manual_status == *running* ]]
manual_reconnect=$(XDG_STATE_HOME=$manual_state "$directory/manual.sh" reconnect)
[[ $manual_reconnect == "ssh=$manual_vm" ]]
XDG_STATE_HOME=$manual_state "$directory/manual.sh" destroy >/dev/null
[[ ! -e $manual_state_file && ! -d $manual_work ]]

convergence_work_a=$(mktemp -d /tmp/mithril-vm-test.XXXXXX)
convergence_work_b=$(mktemp -d /tmp/mithril-vm-test.XXXXXX)
convergence_vm_a=$(mithril_vm_name "$branch_key" c 12345 a)
convergence_vm_b=$(mithril_vm_name "$branch_key" c 12345 b)
convergence_state_file=$manual_state/mithril-convergence-manual-vm/$branch_key/retained-vms.txt
printf 'branch_name=%q\nbranch_key=%q\nnode_a=%q\nnode_a_work_directory=%q\n' \
  "$branch_name" "$branch_key" "$convergence_vm_a" "$convergence_work_a" \
  >"$convergence_state_file"
printf 'node_b=%q\nnode_b_work_directory=%q\nprovider=%q\nmanual_environment=true\n' \
  "$convergence_vm_b" "$convergence_work_b" "$fake_provider" \
  >>"$convergence_state_file"
convergence_status=$(XDG_STATE_HOME=$manual_state \
  "$directory/manual.sh" status-convergence)
[[ $convergence_status == *"branch=$branch_name"* &&
   $convergence_status == *"vm=$convergence_vm_a"* &&
   $convergence_status == *"vm=$convergence_vm_b"* ]]
convergence_reconnect=$(XDG_STATE_HOME=$manual_state \
  "$directory/manual.sh" reconnect-convergence)
[[ $convergence_reconnect == "ssh=$convergence_vm_a" ]]
XDG_STATE_HOME=$manual_state "$directory/manual.sh" destroy-convergence >/dev/null
[[ ! -e $convergence_state_file && ! -d $convergence_work_a &&
   ! -d $convergence_work_b ]]

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
  *" domstate "*) printf 'running\n' ;;
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

work_directory=$(mktemp -d /tmp/mithril-vm-test.XXXXXX)
domain_name=$(mithril_vm_name "$branch_key" s 123)
printf '%s\n%s\n' "$domain_name" "$owner_uuid" \
  >"$work_directory/libvirt-domain-owner"
domain_status=$(PATH="$fake_bin:$PATH" TEST_DOMAIN_UUID="$owner_uuid" \
  "$directory/providers/libvirt.sh" status "$domain_name" "$work_directory")
[[ $domain_status == running ]]
PATH="$fake_bin:$PATH" TEST_DOMAIN_UUID="$owner_uuid" \
  TEST_VIRSH_LOG="$test_root/virsh.log" \
  "$directory/providers/libvirt.sh" destroy "$domain_name" "$work_directory"
grep -q "destroy.*$domain_name" "$test_root/virsh.log"
[[ ! -e $work_directory/libvirt-domain-owner ]]
rm -rf -- "$work_directory"

echo "VM harness behavior checks passed"
