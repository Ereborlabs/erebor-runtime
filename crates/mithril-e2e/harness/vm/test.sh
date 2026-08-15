#!/usr/bin/env bash

set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
test_root=$(mktemp -d /tmp/mithril-vm-harness-test.XXXXXX)
trap 'rm -rf -- "$test_root"' EXIT

for script in "$directory/run.sh" "$directory/guest.sh" \
  "$directory/providers/libvirt.sh" "$directory/test.sh"; do
  bash -n "$script"
done

help=$($directory/run.sh --help 2>&1)
[[ $help == *--with-k3s* ]]
[[ $help == *--skip-administrative-exec* ]]
[[ $help == *--keep-vm* ]]
$directory/guest.sh --help >/dev/null 2>&1

set +e
invalid_effect_mode=$(MITHRIL_VM_CRI_EFFECT_MODE=invalid \
  "$directory/guest.sh" k3s-cri-effect 2>&1)
status=$?
set -e
[[ $status -eq 2 && $invalid_effect_mode == "invalid MITHRIL_VM_CRI_EFFECT_MODE: invalid" ]]

set +e
invalid=$($directory/guest.sh k3s-install latest /dev/null /tmp 2>&1)
status=$?
set -e
[[ $status -eq 2 && $invalid == "invalid k3s version: latest" ]]

set +e
skip_without_k3s=$($directory/run.sh --skip-administrative-exec 2>&1)
status=$?
set -e
[[ $status -eq 2 && $skip_without_k3s == "--skip-administrative-exec requires --with-k3s" ]]

grep -q '^write-kubeconfig-mode: "0600"$' "$directory/k3s-config-v1.yaml"
grep -q '^#cloud-config$' "$directory/cloud-init-v1.yaml"
grep -q '__MITHRIL_SSH_PUBLIC_KEY__' "$directory/cloud-init-v1.yaml"
grep -q '^  name: mithril-vm-qualification$' "$directory/k3s-workload-v1.yaml"
grep -q '^  serviceAccountName: mithril-runtime$' \
  "$directory/k3s-workload-v1.yaml"
grep -q '^          readOnly: true$' "$directory/k3s-workload-v1.yaml"
grep -q '^        path: /var/lib/mithril-vm-qualification/secret$' \
  "$directory/k3s-workload-v1.yaml"
grep -q '^        path: /var/lib/mithril-vm-qualification/busybox$' \
  "$directory/k3s-workload-v1.yaml"
grep -q '^        type: File$' "$directory/k3s-workload-v1.yaml"
grep -q '^      image: docker.io/library/busybox:1.36.1@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662$' \
  "$directory/k3s-workload-v1.yaml"
python3 -c 'import json,re,sys; raw=open(sys.argv[1], encoding="utf-8").read(); config=json.loads(raw); expected={"MITHRIL_CONTAINER_ID", "MITHRIL_POD_UID", "MITHRIL_SANDBOX_ID", "MITHRIL_IMAGE_DIGEST"}; assert config["container_runtime"]["socket_path"] == "/run/k3s/containerd/containerd.sock"; assert config["workload_bindings"][0]["container_id"] == "MITHRIL_CONTAINER_ID"; assert not config["policy_candidates"]; assert set(re.findall(r"MITHRIL_[A-Z_]+", raw)) == expected; assert all(raw.count(value) == 1 for value in expected); assert raw.count("\"container_generation\": 1") == 1' \
  "$directory/k3s-cri-effect-node-v1.json"
python3 -c 'import json,re,sys; raw=open(sys.argv[1], encoding="utf-8").read(); config=json.loads(raw); expected={"MITHRIL_CONTAINER_ID", "MITHRIL_POD_UID", "MITHRIL_SANDBOX_ID", "MITHRIL_IMAGE_DIGEST"}; assert config["node_id"] == "77777777-7777-4777-8777-777777777777"; assert config["container_runtime"]["socket_path"] == "/run/k3s/containerd/containerd.sock"; assert config["administrative_authorization"]["key_id"] == "mithril-vm-administrative-key-v1"; assert not config["policy_candidates"]; assert not config["exact_file_objects"]; assert set(re.findall(r"MITHRIL_[A-Z_]+", raw)) == expected; assert all(raw.count(value) == 1 for value in expected); assert raw.count("\"container_generation\": 1") == 1' \
  "$directory/k3s-administrative-node-v1.json"
python3 -c 'import sys; compile(open(sys.argv[1], encoding="utf-8").read(), sys.argv[1], "exec")' \
  "$directory/oidc-fixture.py"
! grep -Eqi 'private[_ -]?key.*(begin|[0-9a-f]{32})|certificate.*begin' \
  "$directory/k3s-cri-effect-node-v1.json"
! grep -Eqi 'private[_ -]?key.*(begin|[0-9a-f]{32})|certificate.*begin' \
  "$directory/k3s-administrative-node-v1.json"
grep -q 'record-physical-qualification' "$directory/run.sh"
grep -q 'kernel-qualification-x86_64.json' "$directory/run.sh"
grep -q 'k3s-cri-observe.txt' "$directory/run.sh"
grep -q 'k3s-cri-effect.txt' "$directory/run.sh"
grep -q 'k3s-administrative-exec.txt' "$directory/run.sh"
grep -q 'run_k3s_cri_effect OBSERVE' "$directory/run.sh"
grep -q 'run_k3s_cri_effect PROTECT' "$directory/run.sh"
grep -Fq 'if [[ $skip_administrative_exec == false ]]; then' "$directory/run.sh"
grep -q 'retained-vm.txt' "$directory/run.sh"
grep -q 'MITHRIL_VM_KEEP_FAILURE_STATE=true' "$directory/run.sh"
grep -q 'administrative failure state retained' "$directory/guest.sh"
grep -q 'k3s-administrative-policy-v1.yaml' "$directory/run.sh"
grep -q '^  desired_profile_mode: PROTECT$' \
  "$directory/k3s-administrative-policy-v1.yaml"
grep -q '^        exact_object_key_ids: \[12\]$' \
  "$directory/k3s-administrative-policy-v1.yaml"
grep -q '^  k3s-cri-effect)$' "$directory/guest.sh"
grep -q '^  k3s-administrative-exec)$' "$directory/guest.sh"
grep -q 'pod_initial_root=restored_or_unknown_root:fail_closed_unknown' \
  "$directory/guest.sh"
grep -q 'kubectl_exec_root=external_runtime_root:runtime_external_restricted' \
  "$directory/guest.sh"
grep -q 'MITHRIL_VM_CRI_EFFECT_MODE' "$directory/guest.sh"
grep -Fq 'effect_policy_source=$policy_source' "$directory/guest.sh"
grep -q 'reason=WOULD_DENY result=UNKNOWN_AFTER_PRE_EFFECT' "$directory/guest.sh"
grep -q 'exact_file_open=allowed-after-effect:WOULD_DENY' "$directory/guest.sh"
grep -q 'exact_effect=%s' "$directory/guest.sh"
grep -Fq '[[ $exec_status -eq 0 ]]' "$directory/guest.sh"
grep -q 'baseline_file_open=allowed-before-protect' "$directory/guest.sh"
grep -q 'exact_file_open=denied-before-effect:EXACT_POLICY_DENY' \
  "$directory/guest.sh"
grep -q 'task_cookie=\$external_task_cookie family=2 operation=2' \
  "$directory/guest.sh"
grep -q 'k3s-cri-effect.txt.partial' "$directory/run.sh"
grep -q 'mv -- "\$k3s_cri_effect_partial"' "$directory/run.sh"
grep -q 'k3s-cri-observe.txt.partial' "$directory/run.sh"
grep -q 'mv -- "\$k3s_cri_observe_partial"' "$directory/run.sh"
grep -q 'k3s-administrative-exec.txt.partial' "$directory/run.sh"
grep -q 'mv -- "\$k3s_administrative_partial"' "$directory/run.sh"
grep -q 'product_path=kubectl-mithril+oidc-pkce+self-approval+tokenreview+connect-admission+node-slot' \
  "$directory/guest.sh"
grep -q 'api-audiences=mithril-administrative-exec' "$directory/guest.sh"
grep -q 'verbs: \["get", "create"\]' "$directory/guest.sh"
grep -q 'ordinary_kubectl_exec=denied-by-admission' "$directory/guest.sh"
grep -q 'post-consumption_direct_runtime_root=external_runtime_root:runtime_external_restricted' \
  "$directory/guest.sh"
grep -q 'admission identity has no Mithril approval ID' "$directory/guest.sh"
grep -q -- '--bpf-object "$remote_bin/feasibility.bpf.o"' "$directory/run.sh"
grep -q 'crates/mithril-e2e/fixtures/hugging-face/\$fixture' \
  "$directory/run.sh"
grep -q 'k3s-cri-observe.txt' "$directory/README.md"
grep -q -- '--skip-administrative-exec' "$directory/README.md"

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

echo "VM harness shell checks passed"
