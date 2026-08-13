#!/usr/bin/env bash

set -euo pipefail

usage() {
  echo "usage: $0 {platform INSPECT WORK_DIRECTORY|k3s-install VERSION CONFIG WORK_DIRECTORY|k3s-qualify MANIFEST WORK_DIRECTORY|k3s-cri-effect NODE INSPECT POLICY TEMPLATE POLICY_SOURCE SEAL_REQUEST SIGNING_KEY PUBLIC_KEY MANIFEST WORK_DIRECTORY|k3s-remove WORK_DIRECTORY}" >&2
}

require_root() {
  [[ $(id -u) -eq 0 ]] || {
    echo "guest qualification command requires root" >&2
    exit 2
  }
}

require_command() {
  command -v "$1" >/dev/null || {
    echo "guest is missing required command: $1" >&2
    exit 2
  }
}

require_harness_guest() {
  [[ $1 =~ ^/var/tmp/mithril-runtime-qualification-[0-9]+$ && -d $1 ]] || {
    echo "refusing to modify a guest outside the disposable VM harness: $1" >&2
    exit 2
  }
}

case ${1:-} in
  platform)
    (($# == 3)) || { usage; exit 2; }
    inspect=$2
    work_directory=$3
    require_root
    require_command lsattr
    [[ -x $inspect && -d $work_directory ]] || {
      echo "platform qualification needs the inspector and guest work directory" >&2
      exit 2
    }
    [[ -r /sys/kernel/btf/vmlinux ]] || {
      echo "runtime BTF is not readable" >&2
      exit 1
    }
    [[ $(stat -fc %T /sys/fs/cgroup) == cgroup2fs ]] || {
      echo "cgroup v2 is not mounted" >&2
      exit 1
    }
    [[ $(stat -fc %T /sys/fs/bpf) == bpf_fs ]] || {
      echo "bpffs is not mounted" >&2
      exit 1
    }
    grep -qw bpf /sys/kernel/security/lsm || {
      echo "BPF LSM is not active" >&2
      exit 1
    }

    probe=$work_directory/statx-mount-id-probe
    trap 'rm -f -- "$probe"' EXIT
    : >"$probe"
    inode_generation=$(lsattr -v "$probe" | awk 'NR == 1 {print $1}')
    [[ $inode_generation =~ ^[1-9][0-9]*$ ]] || {
      echo "qualification filesystem does not expose a nonzero inode generation" >&2
      exit 1
    }
    exact_object=$(
      "$inspect" file-object --root-pid 1 --path "$probe" \
        --profile-generation 1 --exact-object-key 1 \
        --object-class VM_PLATFORM_PROBE --inode-generation "$inode_generation"
    )

    printf 'kernel_release=%s\n' "$(uname -r)"
    printf 'architecture=%s\n' "$(uname -m)"
    printf 'kernel_command_line=%s\n' "$(cat /proc/cmdline)"
    printf 'active_lsm_order=%s\n' "$(cat /sys/kernel/security/lsm)"
    printf 'boot_id=%s\n' "$(cat /proc/sys/kernel/random/boot_id)"
    printf 'cgroup_filesystem=%s\n' "$(stat -fc %T /sys/fs/cgroup)"
    printf 'bpf_filesystem=%s\n' "$(stat -fc %T /sys/fs/bpf)"
    printf 'statx_mnt_id_unique=available\n'
    printf 'exact_object=%s\n' "$(tr -d '\n' <<<"$exact_object")"
    ;;
  k3s-install)
    (($# == 4)) || { usage; exit 2; }
    version=$2
    config=$3
    work_directory=$4
    [[ $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+\+k3s[0-9]+$ ]] || {
      echo "invalid k3s version: $version" >&2
      exit 2
    }
    require_root
    require_command curl
    require_command systemctl
    require_harness_guest "$work_directory"
    [[ -r $config ]] || {
      echo "k3s qualification needs its checked config and guest work directory" >&2
      exit 2
    }
    installer=$work_directory/install-k3s.sh
    curl --fail --location --proto '=https' --tlsv1.2 \
      --output "$installer" \
      "https://raw.githubusercontent.com/k3s-io/k3s/$version/install.sh"
    install -d -m 700 /etc/rancher/k3s
    install -m 600 "$config" /etc/rancher/k3s/config.yaml
    INSTALL_K3S_VERSION=$version INSTALL_K3S_SYMLINK=skip \
      sh "$installer" server
    rm -f -- "$installer"
    systemctl is-active --quiet k3s
    actual_version=$(/usr/local/bin/k3s --version | awk 'NR == 1 {print $3}')
    [[ $actual_version == "$version" ]] || {
      echo "installed k3s version $actual_version, expected $version" >&2
      exit 1
    }
    for attempt in {1..300}; do
      if /usr/local/bin/k3s kubectl get node -o name 2>/dev/null \
        | grep -q '^node/'; then
        break
      fi
      if [[ $attempt -eq 300 ]]; then
        echo "k3s node did not register" >&2
        exit 1
      fi
      sleep 1
    done
    /usr/local/bin/k3s kubectl wait --for=condition=Ready node --all --timeout=300s
    /usr/local/bin/k3s crictl info >/dev/null
    : >"$work_directory/k3s-installed-by-harness"
    ;;
  k3s-qualify)
    (($# == 3)) || { usage; exit 2; }
    manifest=$2
    work_directory=$3
    require_root
    require_command python3
    require_harness_guest "$work_directory"
    [[ -r $manifest && -f $work_directory/k3s-installed-by-harness ]] || {
      echo "k3s qualification needs its checked workload and guest work directory" >&2
      exit 2
    }
    namespace=mithril-vm-qualification
    inspect_json=
    fixture_root=/var/lib/mithril-vm-qualification
    fixture_owned=false
    cleanup_qualification() {
      /usr/local/bin/k3s kubectl delete namespace "$namespace" \
        --ignore-not-found --wait=true --timeout=120s >/dev/null 2>&1 || true
      [[ -z $inspect_json || ! -e $inspect_json ]] || rm -f -- "$inspect_json"
      [[ $fixture_owned == false ]] || rm -rf -- "$fixture_root"
    }
    trap cleanup_qualification EXIT
    cleanup_qualification
    [[ ! -e $fixture_root ]] || {
      echo "k3s qualification fixture already exists: $fixture_root" >&2
      exit 2
    }
    install -d -m 700 "$fixture_root"
    fixture_owned=true
    printf 'mithril-k3s-cri-effect\n' >"$fixture_root/secret"
    chmod 400 "$fixture_root/secret"
    /usr/local/bin/k3s kubectl apply -f "$manifest" >/dev/null
    /usr/local/bin/k3s kubectl -n "$namespace" wait \
      --for=condition=Ready pod/mithril-runtime --timeout=300s
    /usr/local/bin/k3s kubectl -n "$namespace" exec mithril-runtime -- \
      test -s /var/run/secrets/tokens/mithril

    container_ref=$(
      /usr/local/bin/k3s kubectl -n "$namespace" get pod mithril-runtime \
        -o jsonpath='{.status.containerStatuses[0].containerID}'
    )
    image_id=$(
      /usr/local/bin/k3s kubectl -n "$namespace" get pod mithril-runtime \
        -o jsonpath='{.status.containerStatuses[0].imageID}'
    )
    [[ $container_ref == containerd://* && $image_id == *sha256:* ]] || {
      echo "k3s did not report an exact containerd ID and resolved image digest" >&2
      exit 1
    }
    container_id=${container_ref#containerd://}
    inspect_json=$work_directory/k3s-container-inspect.json
    /usr/local/bin/k3s crictl inspect "$container_id" >"$inspect_json"
    container_pid=$(python3 -c \
      'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["info"]["pid"])' \
      "$inspect_json")
    [[ $container_pid =~ ^[1-9][0-9]*$ && -d /proc/$container_pid/root ]] || {
      echo "CRI did not expose a live workload root" >&2
      exit 1
    }
    [[ -s /proc/$container_pid/root/var/run/secrets/tokens/mithril ]] || {
      echo "projected service-account token is not visible through the workload root" >&2
      exit 1
    }
    grep -q ' / .* - overlay ' "/proc/$container_pid/mountinfo" || {
      echo "workload root is not backed by the containerd overlay snapshotter" >&2
      exit 1
    }

    printf 'lane=k3s\n'
    printf 'k3s_version=%s\n' "$(/usr/local/bin/k3s --version | awk 'NR == 1 {print $3}')"
    printf 'node=%s\n' "$(/usr/local/bin/k3s kubectl get node -o name)"
    printf 'cri_endpoint=unix:///run/k3s/containerd/containerd.sock\n'
    printf 'container_id=%s\n' "$container_ref"
    printf 'image_id=%s\n' "$image_id"
    printf 'workload_root=available\n'
    printf 'root_snapshotter=overlay\n'
    printf 'projected_token=available-through-exec-and-workload-root\n'
    cleanup_qualification
    trap - EXIT
    if /usr/local/bin/k3s kubectl get namespace "$namespace" >/dev/null 2>&1; then
      echo "k3s qualification namespace was not removed" >&2
      exit 1
    fi
    ;;
  k3s-cri-effect)
    (($# == 11)) || { usage; exit 2; }
    node=$2
    inspect=$3
    policy=$4
    template=$5
    policy_source=$6
    seal_request=$7
    signing_key=$8
    public_key=$9
    manifest=${10}
    work_directory=${11}
    require_root
    require_command jq
    require_command lsattr
    require_command date
    require_harness_guest "$work_directory"
    for input in "$node" "$inspect" "$policy" "$template" "$policy_source" \
      "$seal_request" "$signing_key" "$public_key" "$manifest"; do
      [[ -r $input ]] || {
        echo "k3s CRI effect qualification input is not readable: $input" >&2
        exit 2
      }
    done

    namespace=mithril-vm-qualification
    pod=mithril-runtime
    container=runtime
    fixture_root=/var/lib/mithril-vm-qualification
    fixture_path=$fixture_root/secret
    lane_root=$work_directory/k3s-cri-effect
    identity_config=$lane_root/identity-node.json
    protect_config=$lane_root/protect-node.json
    artifact=$lane_root/profile.json
    object=$lane_root/exact-file-object.json
    node_log=$lane_root/mithril-node.log
    pod_state=/tmp/mithril-k3s-cri-effect
    pod_pid_file=$pod_state/exec.pid
    pod_result_file=$pod_state/exec.result
    pod_release_file=$pod_state/release
    initial_snapshot=$lane_root/pod-initial-root.json
    external_snapshot=$lane_root/kubectl-exec-root.json
    effects=$lane_root/effects.txt
    node_pid=
    exec_client_pid=
    release_fd_open=false
    result_fd_open=false
    fixture_owned=false
    pin_owned=false

    stop_node() {
      local pid=$node_pid
      if [[ -n $pid ]] && kill -0 "$pid" 2>/dev/null; then
        kill -INT "$pid"
        for _attempt in {1..100}; do
          kill -0 "$pid" 2>/dev/null || break
          sleep 0.1
        done
        if kill -0 "$pid" 2>/dev/null; then
          kill -TERM "$pid"
          for _attempt in {1..20}; do
            kill -0 "$pid" 2>/dev/null || break
            sleep 0.1
          done
        fi
        kill -0 "$pid" 2>/dev/null && kill -KILL "$pid"
      fi
      [[ -z $pid ]] || wait "$pid" 2>/dev/null || true
      node_pid=
    }
    cleanup_cri_effect() {
      local status=$?
      trap - EXIT
      set +e
      if [[ -n $exec_client_pid ]]; then
        kill -TERM "$exec_client_pid" 2>/dev/null
        wait "$exec_client_pid" 2>/dev/null || true
        exec_client_pid=
      fi
      if [[ $release_fd_open == true ]]; then
        exec 9>&-
        release_fd_open=false
      fi
      if [[ $result_fd_open == true ]]; then
        exec 8<&-
        result_fd_open=false
      fi
      stop_node
      /usr/local/bin/k3s kubectl delete namespace "$namespace" \
        --ignore-not-found --wait=true --timeout=120s >/dev/null 2>&1
      [[ $pin_owned == false ]] || rm -rf -- /sys/fs/bpf/mithril-k3s-cri-effect
      [[ $fixture_owned == false ]] || rm -rf -- "$fixture_root"
      rm -rf -- "$lane_root"
      exit "$status"
    }
    trap cleanup_cri_effect EXIT
    trap 'echo "k3s CRI effect failed at line $LINENO: $BASH_COMMAND" >&2' ERR

    [[ -f $work_directory/k3s-installed-by-harness ]] || {
      echo "k3s CRI effect qualification needs the harness-owned k3s install" >&2
      exit 2
    }
    [[ ! -e $fixture_root ]] || {
      echo "k3s CRI effect qualification fixture already exists: $fixture_root" >&2
      exit 2
    }
    [[ ! -e /sys/fs/bpf/mithril-k3s-cri-effect ]] || {
      echo "k3s CRI effect qualification pin root already exists" >&2
      exit 2
    }
    install -d -m 700 "$fixture_root" "$lane_root"
    fixture_owned=true
    printf 'mithril-k3s-cri-effect\n' >"$fixture_path"
    chmod 400 "$fixture_path"

    /usr/local/bin/k3s kubectl delete namespace "$namespace" \
      --ignore-not-found --wait=true --timeout=120s >/dev/null 2>&1 || true
    /usr/local/bin/k3s kubectl apply -f "$manifest" >/dev/null
    /usr/local/bin/k3s kubectl -n "$namespace" wait \
      --for=condition=Ready "pod/$pod" --timeout=300s

    pod_uid=$(
      /usr/local/bin/k3s kubectl -n "$namespace" get pod "$pod" \
        -o jsonpath='{.metadata.uid}'
    )
    container_ref=$(
      /usr/local/bin/k3s kubectl -n "$namespace" get pod "$pod" \
        -o jsonpath='{.status.containerStatuses[0].containerID}'
    )
    [[ $container_ref == containerd://* ]] || {
      echo "k3s did not report an exact containerd ID" >&2
      exit 1
    }
    container_id=${container_ref#containerd://}
    container_json=$lane_root/container.json
    /usr/local/bin/k3s crictl inspect "$container_id" >"$container_json"
    init_pid=$(jq -er '.info.pid' "$container_json")
    created_at=$(jq -er '.status.createdAt' "$container_json")
    generation=$(date --utc --date "$created_at" +%s%N)
    image_digest=$(jq -er '.status.imageRef' "$container_json")
    sandbox_id=$(
      /usr/local/bin/k3s crictl ps --id "$container_id" -o json \
        | jq -er '.containers[0].podSandboxId'
    )
    [[ $pod_uid =~ ^[0-9a-f-]{36}$ ]] || {
      echo "k3s returned an invalid Pod UID: $pod_uid" >&2
      exit 1
    }
    [[ $container_id =~ ^[0-9a-f]{64}$ ]] || {
      echo "k3s returned an invalid container ID: $container_id" >&2
      exit 1
    }
    [[ $sandbox_id =~ ^[0-9a-f]{64}$ ]] || {
      echo "k3s returned an invalid sandbox ID: $sandbox_id" >&2
      exit 1
    }
    [[ $init_pid =~ ^[1-9][0-9]*$ ]] || {
      echo "k3s CRI returned an invalid init PID: $init_pid" >&2
      exit 1
    }
    [[ $generation =~ ^[1-9][0-9]*$ ]] || {
      echo "k3s CRI returned an invalid creation time: $generation" >&2
      exit 1
    }
    [[ $image_digest == *sha256:* ]] || {
      echo "k3s CRI returned an unresolved image reference: $image_digest" >&2
      exit 1
    }
    [[ -r /proc/$init_pid/root/var/lib/mithril/secret ]] || {
      echo "read-only qualification fixture is not visible through the Pod root" >&2
      exit 1
    }

    sed \
      -e "s|/var/tmp/mithril-runtime-qualification-0|$work_directory|g" \
      -e "s|MITHRIL_CONTAINER_ID|$container_id|g" \
      -e "s|MITHRIL_POD_UID|$pod_uid|g" \
      -e "s|MITHRIL_SANDBOX_ID|$sandbox_id|g" \
      -e "s|\"container_generation\": 1|\"container_generation\": $generation|" \
      -e "s|MITHRIL_IMAGE_DIGEST|$image_digest|g" \
      "$template" >"$identity_config"

    inode_generation=$(lsattr -v "$fixture_path" | awk 'NR == 1 {print $1}')
    [[ $inode_generation =~ ^[1-9][0-9]*$ ]] || {
      echo "qualification fixture has no nonzero inode generation" >&2
      exit 1
    }
    "$inspect" file-object --root-pid "$init_pid" \
      --path /var/lib/mithril/secret --profile-generation 1 \
      --exact-object-key 7 --object-class MANUAL_SECRET \
      --inode-generation "$inode_generation" >"$object"

    protect_policy=$lane_root/protect-policy-v1.yaml
    sed \
      -e 's/desired_profile_mode: OBSERVE/desired_profile_mode: PROTECT/' \
      "$policy_source" >"$protect_policy"
    "$policy" compile --source "$protect_policy" --seal-request "$seal_request" \
      --signing-key "$signing_key" --output "$artifact"
    "$policy" verify --artifact "$artifact" --public-key "$public_key"
    jq --arg artifact "$artifact" --arg public_key "$public_key" \
      --slurpfile object "$object" \
      '.policy_candidates = [{artifact_path: $artifact, public_key_path: $public_key}]
       | .exact_file_objects = $object' "$identity_config" >"$protect_config"

    pin_owned=true
    "$node" --config "$identity_config" >>"$node_log" 2>&1 &
    node_pid=$!
    for _attempt in {1..200}; do
      if "$inspect" --pin-root /sys/fs/bpf/mithril-k3s-cri-effect \
        task --host-pid "$init_pid" >"$initial_snapshot" 2>/dev/null; then
        break
      fi
      kill -0 "$node_pid" 2>/dev/null || {
        echo "Mithril node exited before it labeled the Pod root" >&2
        tail -n 40 "$node_log" >&2
        exit 1
      }
      sleep 0.1
    done
    jq -e '.creator_task_cookie == null
           and .root_class == "restored_or_unknown_root"
           and .installed_role_class == "fail_closed_unknown"' \
      "$initial_snapshot" >/dev/null || {
      echo "Mithril did not classify the pre-existing Pod root conservatively" >&2
      cat "$initial_snapshot" >&2
      exit 1
    }

    rm -rf -- "/proc/$init_pid/root$pod_state"
    /usr/local/bin/k3s kubectl -n "$namespace" exec "$pod" -c "$container" -- \
      sh -c 'mkdir -m 700 "$1"; mkfifo "$3"; exec 3>"$5"; if IFS= read -r _ <"$4"; then printf "BASELINE_ALLOWED\n" >&3; else printf "BASELINE_DENIED\n" >&3; exit 42; fi; echo $$ >"$2"; IFS= read -r _ <"$3"; if IFS= read -r _ <"$4"; then printf "ALLOWED\n" >&3; exit 41; else status=$?; printf "DENIED:%s\n" "$status" >&3; sleep 1; exit 0; fi' \
      sh "$pod_state" "$pod_pid_file" "$pod_release_file" \
      /var/lib/mithril/secret "$pod_result_file" &
    exec_client_pid=$!
    for _attempt in {1..200}; do
      [[ -s /proc/$init_pid/root$pod_pid_file ]] && break
      kill -0 "$exec_client_pid" 2>/dev/null || {
        echo "kubectl exec exited before publishing its namespace PID" >&2
        exit 1
      }
      sleep 0.1
    done
    namespace_pid=$(<"/proc/$init_pid/root$pod_pid_file")
    [[ $namespace_pid =~ ^[1-9][0-9]*$ ]] || {
      echo "kubectl exec wrote an invalid namespace PID" >&2
      exit 1
    }
    exec 8<"/proc/$init_pid/root$pod_result_file"
    result_fd_open=true
    IFS= read -r baseline_result <&8
    [[ $baseline_result == BASELINE_ALLOWED ]] || {
      echo "the kubectl exec task could not read the fixture before PROTECT" >&2
      exit 1
    }
    exec_host_pid=
    cgroup_path=$(sed -n 's|^0::|/sys/fs/cgroup|p' "/proc/$init_pid/cgroup")
    [[ -d $cgroup_path ]] || {
      echo "Pod init has no live unified cgroup" >&2
      exit 1
    }
    while read -r host_pid; do
      [[ -r /proc/$host_pid/status ]] || continue
      mapped_pid=$(awk '/^NSpid:/ {print $NF}' "/proc/$host_pid/status")
      if [[ $mapped_pid == "$namespace_pid" ]]; then
        exec_host_pid=$host_pid
        break
      fi
    done <"$cgroup_path/cgroup.procs"
    [[ -n $exec_host_pid ]] || {
      echo "could not map kubectl exec to its host PID" >&2
      exit 1
    }
    "$inspect" --pin-root /sys/fs/bpf/mithril-k3s-cri-effect \
      task --host-pid "$exec_host_pid" >"$external_snapshot"
    jq -e '.creator_task_cookie == null
           and .root_class == "external_runtime_root"
           and .installed_role_class == "runtime_external_restricted"' \
      "$external_snapshot" >/dev/null || {
      echo "Mithril did not classify kubectl exec as a restricted external root" >&2
      cat "$external_snapshot" >&2
      exit 1
    }
    external_task_cookie=$(jq -er '.task_cookie' "$external_snapshot")
    [[ $external_task_cookie =~ ^[1-9][0-9]*$ ]] || {
      echo "kubectl exec has no exact Mithril task cookie" >&2
      exit 1
    }
    exec 9>"/proc/$init_pid/root$pod_release_file"
    release_fd_open=true

    stop_node
    "$node" --config "$protect_config" >>"$node_log" 2>&1 &
    node_pid=$!
    for _attempt in {1..200}; do
      [[ -S $lane_root/observation.sock ]] && break
      kill -0 "$node_pid" 2>/dev/null || {
        echo "Mithril node exited before signed PROTECT recovery" >&2
        tail -n 40 "$node_log" >&2
        exit 1
      }
      sleep 0.1
    done
    [[ -S $lane_root/observation.sock ]] || {
      echo "Mithril did not publish the observation socket" >&2
      exit 1
    }

    printf '1\n' >&9
    exec 9>&-
    release_fd_open=false
    IFS= read -r result <&8
    exec 8<&-
    result_fd_open=false
    if ! wait "$exec_client_pid"; then
      [[ $result == DENIED:* || $result == ALLOWED ]] || {
        echo "kubectl exec exited before reporting the file-open result" >&2
        exit 1
      }
    fi
    exec_client_pid=
    [[ $result == DENIED:* ]] || {
      echo "kubectl exec read was not denied: $result" >&2
      exit 1
    }
    expected_effect="task_cookie=$external_task_cookie family=2 operation=2 reason=EXACT_POLICY_DENY result=DENIED_BEFORE_EFFECT"
    for _attempt in {1..100}; do
      "$inspect" effects --socket-path "$lane_root/observation.sock" \
        --cgroup-scope / >"$effects"
      if grep -F "$expected_effect" "$effects" \
        | grep -Fq 'exact_object_key_id=7'; then
        break
      fi
      sleep 0.1
    done
    grep -F "$expected_effect" "$effects" \
      | grep -Fq 'exact_object_key_id=7' || {
      echo "Mithril did not report the exact pre-effect denial" >&2
      cat "$effects" >&2
      exit 1
    }

    printf 'lane=k3s-cri-effect\n'
    printf 'pod_uid=%s\n' "$pod_uid"
    printf 'container_id=%s\n' "$container_ref"
    printf 'pod_initial_root=restored_or_unknown_root:fail_closed_unknown\n'
    printf 'kubectl_exec_root=external_runtime_root:runtime_external_restricted\n'
    printf 'baseline_file_open=allowed-before-protect\n'
    printf 'exact_file_open=denied-before-effect:EXACT_POLICY_DENY\n'
    printf 'qualification_fixture=read-only-hostPath-file\n'
    rm -rf -- "/proc/$init_pid/root$pod_state"
    stop_node
    /usr/local/bin/k3s kubectl delete namespace "$namespace" \
      --ignore-not-found --wait=true --timeout=120s >/dev/null
    [[ $pin_owned == false ]] || rm -rf -- /sys/fs/bpf/mithril-k3s-cri-effect
    [[ $fixture_owned == false ]] || rm -rf -- "$fixture_root"
    rm -rf -- "$lane_root"
    trap - EXIT
    trap - ERR
    [[ ! -e /sys/fs/bpf/mithril-k3s-cri-effect \
      && ! -e $fixture_root && ! -e $lane_root ]] || {
      echo "k3s CRI effect qualification left an owned artifact" >&2
      exit 1
    }
    ;;
  k3s-remove)
    (($# == 2)) || { usage; exit 2; }
    work_directory=$2
    require_root
    require_harness_guest "$work_directory"
    [[ -f $work_directory/k3s-installed-by-harness \
      && -x /usr/local/bin/k3s-uninstall.sh ]] || {
      echo "k3s uninstall owner is missing" >&2
      exit 1
    }
    /usr/local/bin/k3s-uninstall.sh
    rm -f -- /etc/rancher/k3s/config.yaml
    ! systemctl is-active --quiet k3s
    [[ ! -S /run/k3s/containerd/containerd.sock ]]
    rm -f -- "$work_directory/k3s-installed-by-harness"
    ;;
  --help|-h)
    usage
    ;;
  *)
    usage
    exit 2
    ;;
esac
