#!/usr/bin/env bash

set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
nsenter_observation_script=$directory/../../../../examples/mithril-effect-observation-manual/nsenter-file-observe.sh
test_root=$(mktemp -d /tmp/mithril-vm-harness-test.XXXXXX)
trap 'rm -rf -- "$test_root"' EXIT

for script in "$directory/run.sh" "$directory/guest.sh" \
  "$directory/providers/libvirt.sh" "$directory/test.sh" \
  "$nsenter_observation_script"; do
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

grep -Fq 'case $# in' "$nsenter_observation_script"
grep -Fq 'observation_prepare_docker "$1" "$2" "$3"' "$nsenter_observation_script"
grep -Fq 'observation_prepare_cri "$1" "$2" "$3" "$4" "$5"' "$nsenter_observation_script"
grep -Fq 'observation_preload_nsenter_probe sh -ec' "$nsenter_observation_script"
! grep -Fq 'python3 -c' "$nsenter_observation_script"
grep -Fq 'exec 4<"$2"' "$nsenter_observation_script"
grep -Fq 'IFS= read -r -n 1 _ <&4 || :' "$nsenter_observation_script"
grep -Fq 'identity_inspect_task cri-nsenter-effect-probe "$observation_probe_host_pid"' \
  "$nsenter_observation_script"
grep -Fq 'identity_assert_external "$identity_work/cri-nsenter-effect-probe.json"' \
  "$nsenter_observation_script"
grep -Fq '.active_role_id == $external_role_id and .coordinate_state == 3' \
  "$nsenter_observation_script"
grep -Fq 'task_cookie=$task_cookie family=2 operation=2 reason=WOULD_DENY result=UNKNOWN_AFTER_PRE_EFFECT' \
  "$nsenter_observation_script"
grep -Fq 'exact_object_key_id=7' "$nsenter_observation_script"

grep -q '^write-kubeconfig-mode: "0600"$' "$directory/k3s-config-v1.yaml"
grep -q '^#cloud-config$' "$directory/cloud-init-v1.yaml"
grep -q '__MITHRIL_SSH_PUBLIC_KEY__' "$directory/cloud-init-v1.yaml"
grep -q '^  name: mithril-vm-qualification$' "$directory/k3s-workload-v1.yaml"
grep -q '^  serviceAccountName: mithril-runtime$' \
  "$directory/k3s-workload-v1.yaml"
grep -q '^          readOnly: true$' "$directory/k3s-workload-v1.yaml"
grep -q '^        path: /var/lib/mithril-vm-qualification/secret$' \
  "$directory/k3s-workload-v1.yaml"
grep -q '^        path: /var/lib/mithril-vm-qualification/benign$' \
  "$directory/k3s-workload-v1.yaml"
grep -Fq ': >"$fixture_root/release"' "$directory/guest.sh"
grep -q 'empty direct CRI release fixture is not visible through the workload root' \
  "$directory/guest.sh"
grep -q '^    # This token checks only the projected-token mount at Pod startup\.$' \
  "$directory/k3s-workload-v1.yaml"
grep -q '^    # It is not an exact-file enforcement fixture\.$' \
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
grep -Fq "printf 'mithril-k3s-cri-benign\\n' >\"\$fixture_root/benign\"" \
  "$directory/guest.sh"
grep -Fq 'chmod 444 "$fixture_root/benign"' "$directory/guest.sh"
grep -q 'benign hostPath fixture is not visible through the workload root' \
  "$directory/guest.sh"
grep -Fq 'mountPath: /var/lib/mithril/release' "$directory/k3s-workload-v1.yaml"
grep -Fq 'path: /var/lib/mithril-vm-qualification/release' \
  "$directory/k3s-workload-v1.yaml"
grep -q 'direct CRI release fixture is not visible through the Pod root' \
  "$directory/guest.sh"
grep -Fq '[[ $fixture_owned == false ]] || rm -rf -- "$fixture_root"' \
  "$directory/guest.sh"
grep -q 'pod_initial_root=restored_or_unknown_root:fail_closed_unknown' \
  "$directory/guest.sh"
grep -q 'crictl exec "\$container_id"' "$directory/guest.sh"
grep -q 'Mithril did not classify direct CRI exec as a restricted external root' \
  "$directory/guest.sh"
grep -q 'cri_exec_root=external_runtime_root:runtime_external_restricted' \
  "$directory/guest.sh"
grep -q 'cri_state=\$pod_state/cri-exec' "$directory/guest.sh"
grep -q 'kubectl_state=\$pod_state/kubectl-exec' "$directory/guest.sh"
grep -q 'mkdir -m 700 -- "/proc/\$init_pid/root\$pod_state"' "$directory/guest.sh"
grep -Fq 'sh "$kubectl_state" "$pod_pid_file" "$pod_release_file"' \
  "$directory/guest.sh"
grep -q 'CRI_BASELINE_ALLOWED' "$directory/guest.sh"
grep -q 'CRI_EXACT_ALLOWED' "$directory/guest.sh"
grep -q 'CRI_EXACT_DENIED' "$directory/guest.sh"
! grep -q 'cri_release_file' "$directory/guest.sh"
! grep -q 'cri_release_fd_open' "$directory/guest.sh"
! grep -Fq 'kill -STOP $$' "$directory/guest.sh"
! grep -Fq 'nsenter -t "$init_pid" -U -p' "$directory/guest.sh"
grep -Fq 'while [ ! -s /var/lib/mithril/release ]; do :; done' \
  "$directory/guest.sh"
grep -q 'direct CRI release fixture is not empty before signed recovery' \
  "$directory/guest.sh"
grep -Fq "printf '1\\n' >\"\$release_fixture_path\"" \
  "$directory/guest.sh"
grep -Fq ': >"$release_fixture_path"' "$directory/guest.sh"
grep -Fq '[[ ! -s $release_fixture_path \' \
  "$directory/guest.sh"
grep -q 'cri_baseline_file=\$cri_state/baseline' "$directory/guest.sh"
grep -q 'expected_cri_effect="task_cookie=\$cri_task_cookie family=2 operation=2' \
  "$directory/guest.sh"
grep -q 'cri_baseline_file_open=allowed-before-observe' "$directory/guest.sh"
grep -q 'cri_exact_file_open=allowed-after-effect:WOULD_DENY' "$directory/guest.sh"
grep -q 'cri_exact_file_open=denied-before-effect:EXACT_POLICY_DENY' \
  "$directory/guest.sh"
grep -q 'cri_exact_effect=%s' "$directory/guest.sh"
grep -Fq '[ "$5" = OBSERVE ] && [ "$cri_result" = CRI_EXACT_ALLOWED ]' \
  "$directory/guest.sh"
grep -Fq '[ "$5" = PROTECT ] && [ "$cri_result" = CRI_EXACT_DENIED ]' \
  "$directory/guest.sh"
grep -Fq '[[ $cri_status -eq 0 ]]' "$directory/guest.sh"
! grep -Fq 'rm -rf -- "/proc/$init_pid/root$pod_state"' \
  "$directory/guest.sh"
grep -q 'k3s CRI effect qualification left its namespace' \
  "$directory/guest.sh"
python3 -c 'import sys; source=open(sys.argv[1], encoding="utf-8").read(); cleanup=source.split("cleanup_cri_effect() {", 1)[1].split("trap cleanup_cri_effect EXIT", 1)[0]; assert cleanup.index("rm -rf -- /sys/fs/bpf/mithril-k3s-cri-effect") < cleanup.index("/usr/local/bin/k3s kubectl delete namespace \"$namespace\""); success=source.split("qualification_fixture=read-only-hostPath-secret-benign-and-release-files", 1)[1].split("trap - EXIT", 1)[0]; assert success.index("stop_node") < success.index("rm -rf -- /sys/fs/bpf/mithril-k3s-cri-effect") < success.index("/usr/local/bin/k3s kubectl delete namespace \"$namespace\"")' \
  "$directory/guest.sh"
grep -q 'kubectl_exec_root=external_runtime_root:runtime_external_restricted' \
  "$directory/guest.sh"
grep -q 'MITHRIL_VM_CRI_EFFECT_MODE' "$directory/guest.sh"
grep -Fq 'effect_policy_source=$policy_source' "$directory/guest.sh"
grep -q 'reason=WOULD_DENY result=UNKNOWN_AFTER_PRE_EFFECT' "$directory/guest.sh"
grep -q 'exact_file_open=allowed-after-effect:WOULD_DENY' "$directory/guest.sh"
grep -q 'exact_effect=%s' "$directory/guest.sh"
grep -q 'benign_fixture_path=\$fixture_root/benign' "$directory/guest.sh"
grep -q -- '--exact-object-key 8 --object-class MANUAL_BENIGN' "$directory/guest.sh"
grep -Fq '.exact_file_objects = ($object + $benign)' "$directory/guest.sh"
grep -q 'BENIGN_ALLOWED' "$directory/guest.sh"
grep -q 'reason=EXACT_POLICY_ALLOW result=UNKNOWN_AFTER_PRE_EFFECT' \
  "$directory/guest.sh"
grep -q 'benign_file_open=%s' "$directory/guest.sh"
grep -q 'benign_effect=%s' "$directory/guest.sh"
grep -q 'qualification_fixture=read-only-hostPath-secret-benign-and-release-files' \
  "$directory/guest.sh"
grep -Fq '[[ $exec_status -eq 0 ]]' "$directory/guest.sh"
grep -Fq '[ "$6" = OBSERVE ] && [ "$secret_result" = SECRET_ALLOWED ] && [ "$benign_result" = BENIGN_ALLOWED ]' \
  "$directory/guest.sh"
grep -Fq '[ "$6" = PROTECT ] && [ "$secret_result" = SECRET_DENIED ] && [ "$benign_result" = BENIGN_ALLOWED ]' \
  "$directory/guest.sh"
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
grep -q 'read-only hostPath release file' "$directory/README.md"
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
