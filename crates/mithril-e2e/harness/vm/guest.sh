#!/usr/bin/env bash

set -euo pipefail

usage() {
  echo "usage: MITHRIL_VM_CRI_EFFECT_MODE=OBSERVE|PROTECT $0 {platform INSPECT WORK_DIRECTORY|k3s-install VERSION CONFIG WORK_DIRECTORY|k3s-agent-install VERSION SERVER TOKEN WORK_DIRECTORY|k3s-runtime-hook HOOK WORK_DIRECTORY|k3s-qualify MANIFEST WORK_DIRECTORY|k3s-cri-effect NODE INSPECT POLICY TEMPLATE POLICY_SOURCE SEAL_REQUEST SIGNING_KEY PUBLIC_KEY MANIFEST WORK_DIRECTORY|k3s-administrative-exec CONTROL NODE INSPECT POLICY KUBECTL_MITHRIL OIDC TEMPLATE POLICY_SOURCE SEAL_REQUEST SIGNING_KEY PUBLIC_KEY MANIFEST WORK_DIRECTORY|k3s-remove WORK_DIRECTORY|k3s-agent-remove WORK_DIRECTORY}" >&2
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
  k3s-agent-install)
    (($# == 5)) || { usage; exit 2; }
    version=$2
    server=$3
    token=$4
    work_directory=$5
    [[ $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+\+k3s[0-9]+$ ]] || {
      echo "invalid k3s version: $version" >&2
      exit 2
    }
    [[ $server =~ ^https://[0-9a-fA-F:.]+:6443$ && -n $token ]] || {
      echo "invalid k3s agent server or token" >&2
      exit 2
    }
    require_root
    require_command curl
    require_command systemctl
    require_harness_guest "$work_directory"
    installer=$work_directory/install-k3s-agent.sh
    curl --fail --location --proto '=https' --tlsv1.2 \
      --output "$installer" \
      "https://raw.githubusercontent.com/k3s-io/k3s/$version/install.sh"
    INSTALL_K3S_VERSION=$version INSTALL_K3S_SYMLINK=skip \
      INSTALL_K3S_EXEC='agent --with-node-id' \
      INSTALL_K3S_SKIP_START=true \
      K3S_URL=$server K3S_TOKEN=$token sh "$installer" agent
    rm -f -- "$installer"
    systemctl start --no-block k3s-agent
    actual_version=$(/usr/local/bin/k3s --version | awk 'NR == 1 {print $3}')
    [[ $actual_version == "$version" ]] || {
      echo "installed k3s version $actual_version, expected $version" >&2
      exit 1
    }
    : >"$work_directory/k3s-agent-installed-by-harness"
    ;;
  k3s-runtime-hook)
    (($# == 3)) || { usage; exit 2; }
    hook_source=$2
    work_directory=$3
    require_root
    require_command jq
    require_command systemctl
    require_harness_guest "$work_directory"
    [[ -r $hook_source && -f $work_directory/k3s-installed-by-harness ]] || {
      echo "K3s runtime setup needs the checked hook and installed K3s" >&2
      exit 2
    }

    hook=/usr/local/libexec/mithril-oci-prestart-admission
    base_spec=/etc/containerd/mithril-base-spec.json
    template=/var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.tmpl
    temporary_spec=$work_directory/mithril-base-spec.json
    install -d -m 755 /usr/local/libexec /etc/containerd "$(dirname "$template")"
    rm -f -- /usr/local/libexec/mithril-oci-create-runtime-stage
    rm -f -- /usr/local/libexec/mithril-oci-create-container-stage
    install -m 700 "$hook_source" "$hook"
    /usr/local/bin/k3s ctr oci spec | jq \
      --arg hook "$hook" \
      '.hooks.prestart = [{path: $hook, args: [$hook, "prestart", "/run/mithril-identity-prestart"]}]' \
      >"$temporary_spec"
    install -m 600 "$temporary_spec" "$base_spec"
    rm -f -- "$temporary_spec"
    printf '%s\n' \
      '{{ template "base" . }}' \
      '[plugins.'\''io.containerd.cri.v1.runtime'\''.containerd.runtimes.mithril]' \
      'runtime_type = "io.containerd.runc.v2"' \
      'base_runtime_spec = "/etc/containerd/mithril-base-spec.json"' \
      '[plugins.'\''io.containerd.cri.v1.runtime'\''.containerd.runtimes.mithril.options]' \
      'SystemdCgroup = true' >"$template"
    chmod 600 "$template"
    systemctl restart k3s
    /usr/local/bin/k3s kubectl wait --for=condition=Ready node --all --timeout=300s
    : >"$work_directory/k3s-runtime-hook-installed-by-harness"
    ;;
  k3s-qualify)
    (($# == 3)) || { usage; exit 2; }
    manifest=$2
    work_directory=$3
    require_root
    require_command python3
    require_command busybox
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
    printf 'mithril-k3s-cri-benign\n' >"$fixture_root/benign"
    chmod 444 "$fixture_root/benign"
    : >"$fixture_root/release"
    chmod 644 "$fixture_root/release"
    install -m 0555 "$(command -v busybox)" "$fixture_root/busybox"
    /usr/local/bin/k3s kubectl apply -f "$manifest" >/dev/null
    /usr/local/bin/k3s kubectl -n "$namespace" wait \
      --for=condition=Ready pod/mithril-runtime --timeout=300s
    for attempt in {1..30}; do
      if /usr/local/bin/k3s kubectl -n "$namespace" exec mithril-runtime \
        -c runtime -- sh -c \
        'test -s /var/run/secrets/tokens/mithril &&
         mkdir -p /home/attack &&
         mount --bind /home/secret /home/attack &&
         test -r /home/attack/models/secret'; then
        break
      fi
      [[ $attempt -lt 30 ]] || {
        echo "k3s runtime container did not accept the readiness exec" >&2
        exit 1
      }
      sleep 1
    done

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
    [[ -r /proc/$container_pid/root/var/lib/mithril/benign ]] || {
      echo "benign hostPath fixture is not visible through the workload root" >&2
      exit 1
    }
    [[ -r /proc/$container_pid/root/run/mithril-fixture/release \
      && ! -s /proc/$container_pid/root/run/mithril-fixture/release ]] || {
      echo "empty direct CRI release fixture is not visible through the workload root" >&2
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
    effect_mode=${MITHRIL_VM_CRI_EFFECT_MODE:-PROTECT}
    case $effect_mode in
      OBSERVE|PROTECT) ;;
      *)
        echo "invalid MITHRIL_VM_CRI_EFFECT_MODE: $effect_mode" >&2
        exit 2
        ;;
    esac
    (($# == 12)) || { usage; exit 2; }
    node=$2
    inspect=$3
    policy=$4
    open_probe=$5
    template=$6
    policy_source=$7
    seal_request=$8
    signing_key=$9
    public_key=${10}
    manifest=${11}
    work_directory=${12}
    require_root
    require_command jq
    require_command lsattr
    require_command date
    require_command busybox
    require_command bpftool
    require_harness_guest "$work_directory"
    for input in "$node" "$inspect" "$policy" "$open_probe" "$template" \
      "$policy_source" "$seal_request" "$signing_key" "$public_key" \
      "$manifest"; do
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
    benign_fixture_path=$fixture_root/benign
    open_probe_fixture_path=$fixture_root/open-probe
    release_fixture_path=$fixture_root/release
    lane_root=$work_directory/k3s-cri-effect
    identity_config=$lane_root/identity-node.json
    effect_config=$lane_root/effect-node.json
    artifact=$lane_root/profile.json
    node_log=$lane_root/mithril-node.log
    pod_state=/tmp/mithril-k3s-cri-effect
    cri_state=$pod_state/cri-exec
    kubectl_state=$pod_state/kubectl-exec
    pod_pid_file=$kubectl_state/exec.pid
    cri_pid_file=$cri_state/exec.pid
    benign_pid_file=$pod_state/benign/exec.pid
    kubelet_bind_pid_file=$pod_state/kubelet-bind/exec.pid
    container_bind_pid_file=$pod_state/container-bind/exec.pid
    initial_snapshot=$lane_root/pod-initial-root.json
    cri_snapshot=$lane_root/cri-exec-root.json
    external_snapshot=$lane_root/kubectl-exec-root.json
    effects=$lane_root/effects.txt
    controller_cgroup=/sys/fs/cgroup/mithril-k3s-cri-effect-controller
    secret_selector_handle=943398411243188049
    benign_selector_handle=442755278878333200
    node_pid=
    cri_client_pid=
    cri_host_pid=
    exec_client_pid=
    benign_client_pid=
    kubelet_bind_client_pid=
    container_bind_client_pid=
    benign_host_pid=
    kubelet_bind_host_pid=
    container_bind_host_pid=
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
      [[ -z $release_fixture_path ]] || \
        printf '1\n' >"$release_fixture_path" 2>/dev/null
      if [[ -n $cri_client_pid ]]; then
        kill -TERM "$cri_client_pid" 2>/dev/null
        wait "$cri_client_pid" 2>/dev/null || true
        cri_client_pid=
      fi
      if [[ -n $exec_client_pid ]]; then
        kill -TERM "$exec_client_pid" 2>/dev/null
        wait "$exec_client_pid" 2>/dev/null || true
        exec_client_pid=
      fi
      if [[ -n $benign_client_pid ]]; then
        kill -TERM "$benign_client_pid" 2>/dev/null
        wait "$benign_client_pid" 2>/dev/null || true
        benign_client_pid=
      fi
      if [[ -n $kubelet_bind_client_pid ]]; then
        kill -TERM "$kubelet_bind_client_pid" 2>/dev/null
        wait "$kubelet_bind_client_pid" 2>/dev/null || true
        kubelet_bind_client_pid=
      fi
      if [[ -n $container_bind_client_pid ]]; then
        kill -TERM "$container_bind_client_pid" 2>/dev/null
        wait "$container_bind_client_pid" 2>/dev/null || true
        container_bind_client_pid=
      fi
      if [[ $result_fd_open == true ]]; then
        exec 8>&-
        result_fd_open=false
      fi
      stop_node
      [[ $pin_owned == false ]] || rm -rf -- /sys/fs/bpf/mithril-k3s-cri-effect
      pin_owned=false
      /usr/local/bin/k3s kubectl delete namespace "$namespace" \
        --ignore-not-found --wait=true --timeout=120s >/dev/null 2>&1
      [[ $fixture_owned == false ]] || rm -rf -- "$fixture_root"
      fixture_owned=false
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
    [[ ! -e $controller_cgroup || -d $controller_cgroup ]] || {
      echo "effect controller cgroup path is not a directory" >&2
      exit 2
    }
    install -d -m 700 "$controller_cgroup"
    [[ ! -s $controller_cgroup/cgroup.procs ]] || {
      echo "effect controller cgroup is not empty" >&2
      exit 2
    }
    install -d -m 700 "$fixture_root" "$lane_root"
    fixture_owned=true
    printf 'mithril-k3s-cri-effect\n' >"$fixture_path"
    chmod 400 "$fixture_path"
    printf 'mithril-k3s-cri-benign\n' >"$benign_fixture_path"
    chmod 444 "$benign_fixture_path"
    : >"$release_fixture_path"
    chmod 644 "$release_fixture_path"
    install -m 0555 "$(command -v busybox)" "$fixture_root/busybox"
    install -m 0555 "$open_probe" "$open_probe_fixture_path"

    /usr/local/bin/k3s kubectl delete namespace "$namespace" \
      --ignore-not-found --wait=true --timeout=120s >/dev/null 2>&1 || true
    /usr/local/bin/k3s kubectl apply -f "$manifest" >/dev/null
    /usr/local/bin/k3s kubectl -n "$namespace" wait \
      --for=condition=Ready "pod/$pod" --timeout=300s
    /usr/local/bin/k3s kubectl -n "$namespace" exec "$pod" -c "$container" -- \
      sh -c 'mkdir -p /home/attack &&
             mount --bind /home/secret /home/attack &&
             test -r /home/attack/models/secret'

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
    container_state=$(jq -er '.status.state' "$container_json")
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
    [[ $container_state == CONTAINER_RUNNING ]] || {
      echo "k3s CRI did not report the container as running" >&2
      exit 1
    }
    [[ -r /proc/$init_pid/root/var/lib/mithril/secret \
      && -r /proc/$init_pid/root/var/lib/mithril/benign \
      && -r /proc/$init_pid/root/run/mithril-fixture/release \
      && -x /proc/$init_pid/root/var/lib/mithril/open-probe \
      && -r /proc/$init_pid/root/home/secret/models/secret \
      && -r /proc/$init_pid/root/home/kubelet-attack/secret \
      && -r /proc/$init_pid/root/home/attack/models/secret ]] || {
      echo "qualification fixtures are not visible through the Pod root" >&2
      exit 1
    }
    rm -rf -- "/proc/$init_pid/root$pod_state"
    mkdir -m 700 -- "/proc/$init_pid/root$pod_state"
    sed \
      -e "s|/var/tmp/mithril-runtime-qualification-0|$work_directory|g" \
      -e "s|MITHRIL_CONTAINER_ID|$container_id|g" \
      -e "s|MITHRIL_POD_UID|$pod_uid|g" \
      -e "s|MITHRIL_SANDBOX_ID|$sandbox_id|g" \
      -e "s|\"container_generation\": 1|\"container_generation\": $generation|" \
      -e "s|MITHRIL_IMAGE_DIGEST|$image_digest|g" \
      "$template" >"$identity_config"

    effect_policy_source=$policy_source
    if [[ $effect_mode == PROTECT ]]; then
      effect_policy_source=$lane_root/protect-policy-v1.yaml
      sed \
        -e 's/desired_profile_mode: OBSERVE/desired_profile_mode: PROTECT/' \
        -e '/^path_tree_deny_floors: \[\]$/c\
path_tree_deny_floors:\
  - rule_id: deny-container-child-bind\
    role_id: converter\
    path: /home/secret\
    operation_ids: [OPEN_READ]' \
        "$policy_source" >"$effect_policy_source"
    fi
    "$policy" compile --source "$effect_policy_source" --seal-request "$seal_request" \
      --signing-key "$signing_key" --output "$artifact"
    "$policy" verify --artifact "$artifact" --public-key "$public_key"
    jq --arg artifact "$artifact" --arg public_key "$public_key" \
      '.policy_candidates = [{artifact_path: $artifact, public_key_path: $public_key}]' \
      "$identity_config" >"$effect_config"

    pin_owned=true
    (
      printf '%s\n' "$BASHPID" >"$controller_cgroup/cgroup.procs"
      exec env RUST_LOG=warn "$node" --config "$identity_config"
    ) >>"$node_log" 2>&1 &
    node_pid=$!
    for _attempt in {1..200}; do
      [[ -S $lane_root/observation.sock ]] && break
      kill -0 "$node_pid" 2>/dev/null || {
        echo "Mithril node exited before signed policy activation" >&2
        tail -n 40 "$node_log" >&2
        exit 1
      }
      sleep 0.1
    done
    [[ -S $lane_root/observation.sock ]] || {
      echo "Mithril did not activate signed policy" >&2
      exit 1
    }
    for _attempt in {1..200}; do
      if "$inspect" --pin-root /sys/fs/bpf/mithril-k3s-cri-effect \
        task --host-pid "$init_pid" >"$initial_snapshot" 2>/dev/null; then
        break
      fi
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
    cgroup_path=$(sed -n 's|^0::|/sys/fs/cgroup|p' "/proc/$init_pid/cgroup")
    [[ -d $cgroup_path ]] || {
      echo "Pod init has no live unified cgroup" >&2
      exit 1
    }

    /usr/local/bin/k3s crictl exec "$container_id" \
      /var/lib/mithril/open-probe \
      --pid-file "$cri_pid_file" \
      --release-file /run/mithril-fixture/release \
      /var/lib/mithril/secret \
      >"$lane_root/cri-result.out" 2>&1 &
    cri_client_pid=$!
    for _attempt in {1..200}; do
      [[ -s /proc/$init_pid/root$cri_pid_file ]] && break
      kill -0 "$cri_client_pid" 2>/dev/null || {
        echo "direct CRI exec exited before publishing its namespace PID" >&2
        cat "$lane_root/cri-result.out" >&2
        "$inspect" effects --socket-path "$lane_root/observation.sock" \
          --cgroup-scope / >&2 || true
        exit 1
      }
      sleep 0.1
    done
    cri_namespace_pid=$(<"/proc/$init_pid/root$cri_pid_file")
    [[ $cri_namespace_pid =~ ^[1-9][0-9]*$ ]] || {
      echo "direct CRI exec wrote an invalid namespace PID" >&2
      exit 1
    }
    while read -r host_pid; do
      [[ -r /proc/$host_pid/status ]] || continue
      mapped_pid=$(awk '/^NSpid:/ {print $NF}' "/proc/$host_pid/status")
      if [[ $mapped_pid == "$cri_namespace_pid" ]]; then
        cri_host_pid=$host_pid
        break
      fi
    done <"$cgroup_path/cgroup.procs"
    [[ -n $cri_host_pid ]] || {
      echo "could not map direct CRI exec to its host PID" >&2
      exit 1
    }
    "$inspect" --pin-root /sys/fs/bpf/mithril-k3s-cri-effect \
      task --host-pid "$cri_host_pid" >"$cri_snapshot"
    jq -e '.creator_task_cookie == null
           and .root_class == "external_runtime_root"
           and .installed_role_class == "runtime_external_restricted"' \
      "$cri_snapshot" >/dev/null || {
      echo "Mithril did not classify direct CRI exec as a restricted external root" >&2
      cat "$cri_snapshot" >&2
      exit 1
    }
    cri_task_cookie=$(jq -er '.task_cookie' "$cri_snapshot")
    [[ $cri_task_cookie =~ ^[1-9][0-9]*$ ]] || {
      echo "direct CRI exec has no exact Mithril task cookie" >&2
      exit 1
    }
    [[ ! -s $release_fixture_path \
      && ! -s /proc/$init_pid/root/run/mithril-fixture/release ]] || {
      echo "direct CRI release fixture is not empty before the exact check" >&2
      exit 1
    }

    exec 8>"$lane_root/exec-result"
    result_fd_open=true
    /usr/local/bin/k3s kubectl -n "$namespace" exec "$pod" -c "$container" -- \
      /var/lib/mithril/open-probe \
      --pid-file "$pod_pid_file" \
      --release-file /run/mithril-fixture/release \
      /var/lib/mithril/secret >&8 &
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
    exec_host_pid=
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
    /usr/local/bin/k3s kubectl -n "$namespace" exec "$pod" -c "$container" -- \
      /var/lib/mithril/open-probe \
      --pid-file "$benign_pid_file" \
      --release-file /run/mithril-fixture/release \
      /var/lib/mithril/benign >"$lane_root/benign-result.out" 2>&1 &
    benign_client_pid=$!
    probe_pid_files=("$benign_pid_file")
    probe_client_pids=("$benign_client_pid")
    if [[ $effect_mode == PROTECT ]]; then
      /usr/local/bin/k3s kubectl -n "$namespace" exec "$pod" -c "$container" -- \
        /var/lib/mithril/open-probe \
        --pid-file "$kubelet_bind_pid_file" \
        --release-file /run/mithril-fixture/release \
        /home/kubelet-attack/secret >"$lane_root/kubelet-bind-result.out" 2>&1 &
      kubelet_bind_client_pid=$!
      /usr/local/bin/k3s kubectl -n "$namespace" exec "$pod" -c "$container" -- \
        /var/lib/mithril/open-probe \
        --pid-file "$container_bind_pid_file" \
        --release-file /run/mithril-fixture/release \
        /home/attack/models/secret >"$lane_root/container-bind-result.out" 2>&1 &
      container_bind_client_pid=$!
      probe_pid_files+=("$kubelet_bind_pid_file" "$container_bind_pid_file")
      probe_client_pids+=("$kubelet_bind_client_pid" "$container_bind_client_pid")
    fi
    probe_host_pids=()
    for probe_index in "${!probe_pid_files[@]}"; do
      probe_pid_file=${probe_pid_files[$probe_index]}
      probe_client_pid=${probe_client_pids[$probe_index]}
      for _attempt in {1..200}; do
        [[ -s /proc/$init_pid/root$probe_pid_file ]] && break
        kill -0 "$probe_client_pid" 2>/dev/null || {
          echo "held Kubernetes file-open probe exited before publishing its namespace PID" >&2
          exit 1
        }
        sleep 0.1
      done
      [[ -s /proc/$init_pid/root$probe_pid_file ]] || {
        echo "held Kubernetes file-open probe did not publish its namespace PID" >&2
        exit 1
      }
      probe_namespace_pid=$(<"/proc/$init_pid/root$probe_pid_file")
      probe_host_pid=
      while read -r host_pid; do
        [[ -r /proc/$host_pid/status ]] || continue
        mapped_pid=$(awk '/^NSpid:/ {print $NF}' "/proc/$host_pid/status")
        if [[ $mapped_pid == "$probe_namespace_pid" ]]; then
          probe_host_pid=$host_pid
          break
        fi
      done <"$cgroup_path/cgroup.procs"
      [[ -n $probe_host_pid ]] || {
        echo "could not map held Kubernetes file-open probe to its host PID" >&2
        exit 1
      }
      probe_host_pids+=("$probe_host_pid")
    done
    benign_host_pid=${probe_host_pids[0]}
    if [[ $effect_mode == PROTECT ]]; then
      kubelet_bind_host_pid=${probe_host_pids[1]}
      container_bind_host_pid=${probe_host_pids[2]}
    fi
    stop_node
    (
      printf '%s\n' "$BASHPID" >"$controller_cgroup/cgroup.procs"
      exec env RUST_LOG=warn "$node" --config "$effect_config"
    ) >>"$node_log" 2>&1 &
    node_pid=$!
    for _attempt in {1..200}; do
      [[ -S $lane_root/observation.sock ]] && break
      kill -0 "$node_pid" 2>/dev/null || {
        echo "Mithril node exited before signed $effect_mode recovery" >&2
        tail -n 80 "$node_log" >&2
        exit 1
      }
      sleep 0.1
    done
    [[ -S $lane_root/observation.sock ]] || {
      echo "Mithril did not recover the signed $effect_mode policy" >&2
      exit 1
    }
    exact_object_map=/sys/fs/bpf/mithril-k3s-cri-effect/maps/exact_file_objects
    exact_object_count=0
    for _attempt in {1..200}; do
      if [[ -e $exact_object_map ]]; then
        exact_object_count=$(bpftool -j map dump pinned "$exact_object_map" \
          | jq 'length')
      fi
      [[ $exact_object_count -eq 2 ]] && break
      kill -0 "$node_pid" 2>/dev/null || {
        echo "Mithril node exited before the containerd Running binding" >&2
        tail -n 80 "$node_log" >&2
        exit 1
      }
      sleep 0.1
    done
    [[ $exact_object_count -eq 2 ]] || {
      echo "containerd Running inventory did not install both signed Exact selectors" >&2
      [[ ! -e $exact_object_map ]] \
        || bpftool -j map dump pinned "$exact_object_map" >&2
      tail -n 80 "$node_log" >&2
      exit 1
    }
    if { exec {namespace_probe_fd}<"/proc/$init_pid/ns/mnt"; } 2>/dev/null; then
      exec {namespace_probe_fd}<&-
      echo "external process used the effect controller inspection path" >&2
      exit 1
    fi

    printf '1\n' >"$release_fixture_path"
    exec 8>&-
    result_fd_open=false
    for _attempt in {1..200}; do
      cri_alive=false
      exec_alive=false
      benign_alive=false
      kubelet_bind_alive=false
      container_bind_alive=false
      [[ -d /proc/$cri_host_pid ]] && cri_alive=true
      [[ -d /proc/$exec_host_pid ]] && exec_alive=true
      [[ -d /proc/$benign_host_pid ]] && benign_alive=true
      if [[ -n $kubelet_bind_host_pid \
        && -d /proc/$kubelet_bind_host_pid ]]; then
        kubelet_bind_alive=true
      fi
      if [[ -n $container_bind_host_pid \
        && -d /proc/$container_bind_host_pid ]]; then
        container_bind_alive=true
      fi
      if [[ $effect_mode == OBSERVE && $cri_alive == true \
        && $exec_alive == true && $benign_alive == true ]]; then
        break
      fi
      if [[ $effect_mode == PROTECT && $cri_alive == false \
        && $exec_alive == false && $benign_alive == true \
        && $kubelet_bind_alive == false && $container_bind_alive == false ]]; then
        break
      fi
      sleep 0.1
    done
    case $effect_mode in
      OBSERVE)
        [[ $cri_alive == true && $exec_alive == true \
          && $benign_alive == true ]] || {
          echo "OBSERVE file-open probes did not remain active after successful opens" >&2
          exit 1
        }
        exec_status=0
        cri_status=0
        benign_status=0
        kubelet_bind_status=0
        container_bind_status=0
        ;;
      PROTECT)
        [[ $cri_alive == false && $exec_alive == false \
          && $benign_alive == true && $kubelet_bind_alive == false \
          && $container_bind_alive == false ]] || {
          echo "PROTECT file-open probes did not reach the expected denied and allowed states" >&2
          exit 1
        }
        trap - ERR
        set +e
        wait "$exec_client_pid"
        exec_status=$?
        wait "$cri_client_pid"
        cri_status=$?
        wait "$kubelet_bind_client_pid"
        kubelet_bind_status=$?
        wait "$container_bind_client_pid"
        container_bind_status=$?
        set -e
        trap 'echo "k3s CRI effect failed at line $LINENO: $BASH_COMMAND" >&2' ERR
        benign_status=0
        exec_client_pid=
        cri_client_pid=
        kubelet_bind_client_pid=
        container_bind_client_pid=
        ;;
    esac
    case $effect_mode in
      OBSERVE)
        [[ $exec_status -eq 0 && $cri_status -eq 0 \
          && $benign_status -eq 0 && $kubelet_bind_status -eq 0 \
          && $container_bind_status -eq 0 ]] || {
          echo "OBSERVE file-open probes did not all allow" >&2
          cat "$lane_root/exec-result" "$lane_root/cri-result.out" \
            "$lane_root/benign-result.out" \
            "$lane_root/kubelet-bind-result.out" \
            "$lane_root/container-bind-result.out" >&2
          exit 1
        }
        expected_cri_effect="family=2 operation=2 operation_argument=0 reason=WOULD_DENY result=UNKNOWN_AFTER_PRE_EFFECT"
        expected_effect=$expected_cri_effect
        expected_benign_effect="active_role_id=2 family=2 operation=2 operation_argument=0 reason=EXACT_POLICY_ALLOW result=UNKNOWN_AFTER_PRE_EFFECT"
        cri_exact_file_open=allowed-after-running-binding:WOULD_DENY
        exact_file_open=allowed-after-running-binding:WOULD_DENY
        benign_file_open=allowed-after-running-binding:EXACT_POLICY_ALLOW
        path_tree_kubelet_file_open=not-run-without-denial-floor
        path_tree_container_file_open=not-run-without-denial-floor
        ;;
      PROTECT)
        [[ $exec_status -ne 0 && $cri_status -ne 0 \
          && $benign_status -eq 0 && $kubelet_bind_status -ne 0 \
          && $container_bind_status -ne 0 ]] || {
          echo "PROTECT file-open probes did not preserve exact and path-tree denials" >&2
          cat "$lane_root/exec-result" "$lane_root/cri-result.out" \
            "$lane_root/benign-result.out" \
            "$lane_root/kubelet-bind-result.out" \
            "$lane_root/container-bind-result.out" >&2
          exit 1
        }
        expected_cri_effect="family=2 operation=2 operation_argument=0 reason=EXACT_POLICY_DENY result=DENIED_BEFORE_EFFECT"
        expected_effect=$expected_cri_effect
        expected_benign_effect="active_role_id=2 family=2 operation=2 operation_argument=0 reason=EXACT_POLICY_ALLOW result=UNKNOWN_AFTER_PRE_EFFECT"
        cri_exact_file_open=denied-after-running-binding:EXACT_POLICY_DENY
        exact_file_open=denied-after-running-binding:EXACT_POLICY_DENY
        benign_file_open=allowed-after-running-binding:EXACT_POLICY_ALLOW
        expected_path_tree_effect="active_role_id=2 family=2 operation=2 operation_argument=0 reason=PATH_TREE_POLICY_DENY result=DENIED_BEFORE_EFFECT"
        expected_path_tree_kernel="kernel_result=-13"
        path_tree_kubelet_file_open=denied-after-kubelet-child-bind:PATH_TREE_POLICY_DENY
        path_tree_container_file_open=denied-after-container-bind:PATH_TREE_POLICY_DENY
        ;;
    esac
    for _attempt in {1..100}; do
      "$inspect" effects --socket-path "$lane_root/observation.sock" \
        --cgroup-scope / >"$effects"
      if grep -F "$expected_cri_effect" "$effects" \
        | grep -F "task_cookie=$cri_task_cookie target_task_cookie=" \
        | grep -Fq "exact_object_key_id=$secret_selector_handle" \
        && grep -F "$expected_effect" "$effects" \
        | grep -F "task_cookie=$external_task_cookie target_task_cookie=" \
        | grep -Fq "exact_object_key_id=$secret_selector_handle" \
        && grep -F "$expected_benign_effect" "$effects" \
          | grep -Fq "exact_object_key_id=$benign_selector_handle"; then
        break
      fi
      sleep 0.1
    done
    grep -F "$expected_cri_effect" "$effects" \
      | grep -F "task_cookie=$cri_task_cookie target_task_cookie=" \
      | grep -Fq "exact_object_key_id=$secret_selector_handle" || {
      echo "Mithril did not report the expected $effect_mode direct CRI exact file-open result" >&2
      cat "$effects" >&2
      exit 1
    }
    grep -F "$expected_effect" "$effects" \
      | grep -F "task_cookie=$external_task_cookie target_task_cookie=" \
      | grep -Fq "exact_object_key_id=$secret_selector_handle" || {
      echo "Mithril did not report the expected $effect_mode exact file-open result" >&2
      cat "$effects" >&2
      exit 1
    }
    grep -F "$expected_benign_effect" "$effects" \
      | grep -Fq "exact_object_key_id=$benign_selector_handle" || {
      echo "Mithril did not report the expected $effect_mode benign file-open result" >&2
      cat "$effects" >&2
      exit 1
    }
    path_tree_effect_count=0
    path_tree_effect=
    if [[ $effect_mode == PROTECT ]]; then
      for _attempt in {1..100}; do
        "$inspect" effects --socket-path "$lane_root/observation.sock" \
          --cgroup-scope / >"$effects"
        path_tree_effect_count=$(
          grep -F "$expected_path_tree_effect" "$effects" \
            | grep -F "exact_object_key_id=0" \
            | grep -F "$expected_path_tree_kernel" \
            | grep -Ec 'task_cookie=[1-9][0-9]*' \
            || true
        )
        [[ $path_tree_effect_count -ge 2 ]] && break
        sleep 0.1
      done
      [[ $path_tree_effect_count -ge 2 ]] || {
        echo "Mithril did not report both Kubernetes path-tree alias results" >&2
        cat "$effects" >&2
        exit 1
      }
      path_tree_effect=$(
        grep -F "$expected_path_tree_effect" "$effects" | sed -n '1p'
      )
    fi

    cri_exact_effect=$(grep -F "$expected_cri_effect" "$effects" \
      | grep -F "task_cookie=$cri_task_cookie target_task_cookie=" \
      | grep -F "exact_object_key_id=$secret_selector_handle" | sed -n '1p')
    exact_effect=$(grep -F "$expected_effect" "$effects" \
      | grep -F "task_cookie=$external_task_cookie target_task_cookie=" \
      | grep -F "exact_object_key_id=$secret_selector_handle" | sed -n '1p')
    benign_effect=$(grep -F "$expected_benign_effect" "$effects" | grep -F "exact_object_key_id=$benign_selector_handle" | sed -n '1p')

    printf 'lane=k3s-cri-effect\n'
    printf 'pod_uid=%s\n' "$pod_uid"
    printf 'container_id=%s\n' "$container_ref"
    printf 'pod_initial_root=restored_or_unknown_root:fail_closed_unknown\n'
    printf 'exact_binding_stage=containerd-running-inventory\n'
    printf 'initial_binding_start_gap=recorded:container-running-before-node-binding\n'
    printf 'effect_controller_scope=dedicated-cgroup-read-inspection\n'
    printf 'cri_exec_root=external_runtime_root:runtime_external_restricted\n'
    printf 'cri_exact_file_open=%s\n' "$cri_exact_file_open"
    printf 'cri_exact_effect=%s\n' "$cri_exact_effect"
    printf 'kubectl_exec_root=external_runtime_root:runtime_external_restricted\n'
    printf 'policy_mode=%s\n' "$effect_mode"
    printf 'exact_file_open=%s\n' "$exact_file_open"
    printf 'exact_effect=%s\n' "$exact_effect"
    printf 'benign_file_open=%s\n' "$benign_file_open"
    printf 'benign_effect=%s\n' "$benign_effect"
    printf 'path_tree_kubelet_file_open=%s\n' "$path_tree_kubelet_file_open"
    printf 'path_tree_container_file_open=%s\n' "$path_tree_container_file_open"
    printf 'path_tree_effect_count=%s\n' "$path_tree_effect_count"
    printf 'path_tree_effect=%s\n' "$path_tree_effect"
    printf 'qualification_probe=static-direct-open\n'
    printf 'qualification_fixture=container-tmpfs-runtime-with-read-only-hostPath-inputs\n'
    stop_node
    [[ -d $controller_cgroup && ! -s $controller_cgroup/cgroup.procs ]] || {
      echo "effect controller cgroup did not become reusable" >&2
      exit 1
    }
    [[ $pin_owned == false ]] || rm -rf -- /sys/fs/bpf/mithril-k3s-cri-effect
    pin_owned=false
    /usr/local/bin/k3s kubectl delete namespace "$namespace" \
      --ignore-not-found --wait=true --timeout=120s >/dev/null
    for probe_client_pid in "$cri_client_pid" "$exec_client_pid" \
      "$benign_client_pid" "$kubelet_bind_client_pid" \
      "$container_bind_client_pid"; do
      [[ -z $probe_client_pid ]] || wait "$probe_client_pid" 2>/dev/null || true
    done
    cri_client_pid=
    exec_client_pid=
    benign_client_pid=
    kubelet_bind_client_pid=
    container_bind_client_pid=
    [[ $fixture_owned == false ]] || rm -rf -- "$fixture_root"
    fixture_owned=false
    rm -rf -- "$lane_root"
    trap - EXIT
    trap - ERR
    if /usr/local/bin/k3s kubectl get namespace "$namespace" >/dev/null 2>&1; then
      echo "k3s CRI effect qualification left its namespace" >&2
      exit 1
    fi
    [[ ! -e /sys/fs/bpf/mithril-k3s-cri-effect \
      && ! -e $fixture_root && ! -e $lane_root ]] || {
      echo "k3s CRI effect qualification left an owned artifact" >&2
      exit 1
    }
    ;;
  k3s-administrative-exec)
    (($# == 14)) || { usage; exit 2; }
    control=$2
    node=$3
    inspect=$4
    policy=$5
    kubectl_mithril=$6
    oidc=$7
    template=$8
    policy_source=$9
    seal_request=${10}
    signing_key=${11}
    public_key=${12}
    manifest=${13}
    work_directory=${14}
    require_root
    require_command base64
    require_command busybox
    require_command curl
    require_command date
    require_command jq
    require_command lsattr
    require_command openssl
    require_command python3
    require_command sha256sum
    require_command systemctl
    require_command update-ca-certificates
    require_harness_guest "$work_directory"
    for input in "$control" "$node" "$inspect" "$policy" \
      "$kubectl_mithril" "$oidc" "$template" "$policy_source" \
      "$seal_request" "$signing_key" "$public_key" "$manifest"; do
      [[ -r $input ]] || {
        echo "k3s administrative-exec input is not readable: $input" >&2
        exit 2
      }
    done

    namespace=mithril-vm-qualification
    pod=mithril-runtime
    container=runtime
    node_id=77777777-7777-4777-8777-777777777777
    fixture_root=/var/lib/mithril-vm-qualification
    executable_path=$fixture_root/busybox
    lane_root=$work_directory/k3s-administrative-exec
    pin_root=/sys/fs/bpf/mithril-k3s-administrative-exec
    node_config=$lane_root/node.json
    control_config=$lane_root/control.json
    artifact=$lane_root/profile.json
    node_log=$lane_root/node.log
    control_log=$lane_root/control.log
    oidc_log=$lane_root/oidc.log
    plugin_log=$lane_root/kubectl-mithril.log
    controller_cgroup=/sys/fs/cgroup/mithril-k3s-administrative-controller
    plugin_pid=
    runtime_client_pid=
    node_pid=
    control_pid=
    oidc_pid=
    fixture_owned=false
    pin_owned=false
    k3s_configured=false
    ca_installed=false

    stop_process() {
      local pid=${1:-}
      [[ -n $pid ]] || return 0
      if kill -0 "$pid" 2>/dev/null; then
        kill -TERM "$pid" 2>/dev/null || true
        for _attempt in {1..50}; do
          kill -0 "$pid" 2>/dev/null || break
          sleep 0.1
        done
        kill -0 "$pid" 2>/dev/null && kill -KILL "$pid" 2>/dev/null || true
      fi
      wait "$pid" 2>/dev/null || true
    }
    wait_for_k3s() {
      for _attempt in {1..300}; do
        if systemctl is-active --quiet k3s \
          && /usr/local/bin/k3s kubectl get node -o name 2>/dev/null \
            | grep -q '^node/'; then
          return 0
        fi
        sleep 1
      done
      echo "k3s did not recover after administrative webhook configuration" >&2
      return 1
    }
    cleanup_administrative_exec() {
      local status=$?
      trap - EXIT
      if [[ $status -ne 0 && ${MITHRIL_VM_KEEP_FAILURE_STATE:-false} == true ]]; then
        echo "administrative failure state retained in $lane_root" >&2
        exit "$status"
      fi
      set +e
      stop_process "$plugin_pid"
      stop_process "$runtime_client_pid"
      stop_process "$node_pid"
      if [[ -d $controller_cgroup && -s $controller_cgroup/cgroup.procs ]]; then
        status=1
      fi
      stop_process "$control_pid"
      stop_process "$oidc_pid"
      /usr/local/bin/k3s kubectl delete validatingwebhookconfiguration \
        mithril-administrative-exec --ignore-not-found >/dev/null 2>&1
      /usr/local/bin/k3s kubectl delete clusterrolebinding \
        mithril-approved-administrative-exec --ignore-not-found >/dev/null 2>&1
      /usr/local/bin/k3s kubectl delete clusterrole \
        mithril-approved-administrative-exec --ignore-not-found >/dev/null 2>&1
      /usr/local/bin/k3s kubectl delete namespace "$namespace" \
        --ignore-not-found --wait=true --timeout=120s >/dev/null 2>&1
      if [[ $k3s_configured == true && -r $lane_root/k3s-config.yaml ]]; then
        install -m 600 "$lane_root/k3s-config.yaml" /etc/rancher/k3s/config.yaml
        systemctl restart k3s >/dev/null 2>&1
        wait_for_k3s >/dev/null 2>&1 || status=1
      fi
      if [[ $ca_installed == true ]]; then
        rm -f -- /usr/local/share/ca-certificates/mithril-vm-administrative.crt
        update-ca-certificates >/dev/null 2>&1 || status=1
      fi
      [[ $pin_owned == false ]] || rm -rf -- "$pin_root"
      [[ $fixture_owned == false ]] || rm -rf -- "$fixture_root"
      rm -rf -- "$lane_root"
      exit "$status"
    }
    trap cleanup_administrative_exec EXIT
    trap 'echo "k3s administrative exec failed at line $LINENO: $BASH_COMMAND" >&2' ERR

    [[ -f $work_directory/k3s-installed-by-harness ]] || {
      echo "k3s administrative exec needs the harness-owned k3s install" >&2
      exit 2
    }
    [[ ! -e $fixture_root && ! -e $pin_root && ! -e $lane_root ]] || {
      echo "k3s administrative-exec fixture, pin, or state already exists" >&2
      exit 2
    }
    [[ ! -e $controller_cgroup || -d $controller_cgroup ]] || {
      echo "administrative controller cgroup path is not a directory" >&2
      exit 2
    }
    install -d -m 700 "$controller_cgroup"
    [[ ! -s $controller_cgroup/cgroup.procs ]] || {
      echo "administrative controller cgroup is not empty" >&2
      exit 2
    }
    install -d -m 700 "$fixture_root" "$lane_root" "$lane_root/control-state"
    fixture_owned=true
    printf 'mithril-k3s-administrative-exec\n' >"$fixture_root/secret"
    printf 'mithril-k3s-administrative-benign\n' >"$fixture_root/benign"
    : >"$fixture_root/release"
    chmod 400 "$fixture_root/secret" "$fixture_root/benign" \
      "$fixture_root/release"
    install -m 0555 "$(command -v busybox)" "$executable_path"

    ca_key=$lane_root/ca-key.pem
    ca=$lane_root/ca.pem
    server_key=$lane_root/server-key.pem
    server_csr=$lane_root/server.csr
    server_certificate=$lane_root/server.pem
    node_key=$lane_root/node-key.pem
    node_csr=$lane_root/node.csr
    node_certificate=$lane_root/node.pem
    openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
      -subj /CN=Mithril-VM-CA -addext basicConstraints=critical,CA:TRUE \
      -keyout "$ca_key" -out "$ca" >/dev/null 2>&1
    openssl req -new -newkey rsa:2048 -nodes -sha256 -subj /CN=localhost \
      -addext subjectAltName=DNS:localhost,IP:127.0.0.1 \
      -addext extendedKeyUsage=serverAuth \
      -keyout "$server_key" -out "$server_csr" >/dev/null 2>&1
    openssl x509 -req -days 1 -sha256 -in "$server_csr" -CA "$ca" \
      -CAkey "$ca_key" -CAcreateserial -copy_extensions copy \
      -out "$server_certificate" >/dev/null 2>&1
    openssl req -new -newkey rsa:2048 -nodes -sha256 -subj /CN="$node_id" \
      -addext extendedKeyUsage=clientAuth \
      -keyout "$node_key" -out "$node_csr" >/dev/null 2>&1
    openssl x509 -req -days 1 -sha256 -in "$node_csr" -CA "$ca" \
      -CAkey "$ca_key" -CAcreateserial -copy_extensions copy \
      -out "$node_certificate" >/dev/null 2>&1
    chmod 600 "$ca_key" "$server_key" "$node_key"
    openssl x509 -in "$node_certificate" -outform DER \
      -out "$lane_root/node.der"
    node_certificate_sha256=$(sha256sum "$lane_root/node.der" | awk '{print $1}')

    install -m 0644 "$ca" \
      /usr/local/share/ca-certificates/mithril-vm-administrative.crt
    ca_installed=true
    update-ca-certificates >/dev/null
    webhook_token=$(openssl rand -hex 32)
    printf '%s\n' "$webhook_token" >"$lane_root/webhook-token"
    chmod 600 "$lane_root/webhook-token"
    authentication_kubeconfig=$lane_root/authentication-webhook.kubeconfig
    cat >"$authentication_kubeconfig" <<EOF
apiVersion: v1
kind: Config
clusters:
  - name: mithril
    cluster:
      certificate-authority: $ca
      server: https://localhost:9443/kubernetes/$webhook_token/authenticate
contexts:
  - name: mithril
    context:
      cluster: mithril
      user: kube-apiserver
current-context: mithril
users:
  - name: kube-apiserver
    user: {}
EOF
    chmod 600 "$authentication_kubeconfig"
    cp -- /etc/rancher/k3s/config.yaml "$lane_root/k3s-config.yaml"
    cat >>/etc/rancher/k3s/config.yaml <<EOF
kube-apiserver-arg:
  - api-audiences=mithril-administrative-exec
  - authentication-token-webhook-config-file=$authentication_kubeconfig
  - authentication-token-webhook-version=v1
  - authentication-token-webhook-cache-ttl=0s
EOF
    k3s_configured=true
    systemctl restart k3s
    wait_for_k3s

    /usr/local/bin/k3s kubectl delete namespace "$namespace" \
      --ignore-not-found --wait=true --timeout=120s >/dev/null 2>&1 || true
    /usr/local/bin/k3s kubectl apply -f "$manifest" >/dev/null
    /usr/local/bin/k3s kubectl -n "$namespace" wait \
      --for=condition=Ready "pod/$pod" --timeout=300s
    kubernetes_node=$(
      /usr/local/bin/k3s kubectl -n "$namespace" get pod "$pod" \
        -o jsonpath='{.spec.nodeName}'
    )
    pod_uid=$(
      /usr/local/bin/k3s kubectl -n "$namespace" get pod "$pod" \
        -o jsonpath='{.metadata.uid}'
    )
    container_ref=$(
      /usr/local/bin/k3s kubectl -n "$namespace" get pod "$pod" \
        -o jsonpath='{.status.containerStatuses[0].containerID}'
    )
    [[ -n $kubernetes_node && $container_ref == containerd://* ]] || {
      echo "k3s did not report one exact administrative target" >&2
      exit 1
    }
    container_id=${container_ref#containerd://}
    container_json=$lane_root/container.json
    /usr/local/bin/k3s crictl inspect "$container_id" >"$container_json"
    init_pid=$(jq -er '.info.pid' "$container_json")
    created_at=$(jq -er '.status.createdAt' "$container_json")
    container_state=$(jq -er '.status.state' "$container_json")
    generation=$(date --utc --date "$created_at" +%s%N)
    image_digest=$(jq -er '.status.imageRef' "$container_json")
    sandbox_id=$(
      /usr/local/bin/k3s crictl ps --id "$container_id" -o json \
        | jq -er '.containers[0].podSandboxId'
    )
    [[ $pod_uid =~ ^[0-9a-f-]{36}$ \
      && $container_id =~ ^[0-9a-f]{64}$ \
      && $sandbox_id =~ ^[0-9a-f]{64}$ \
      && $init_pid =~ ^[1-9][0-9]*$ \
      && $generation =~ ^[1-9][0-9]*$ \
      && $image_digest == *sha256:* \
      && $container_state == CONTAINER_RUNNING ]] || {
      echo "k3s returned an invalid administrative target identity" >&2
      exit 1
    }

    sed \
      -e "s|/var/tmp/mithril-runtime-qualification-0|$work_directory|g" \
      -e "s|MITHRIL_CONTAINER_ID|$container_id|g" \
      -e "s|MITHRIL_POD_UID|$pod_uid|g" \
      -e "s|MITHRIL_SANDBOX_ID|$sandbox_id|g" \
      -e "s|\"container_generation\": 1|\"container_generation\": $generation|" \
      -e "s|MITHRIL_IMAGE_DIGEST|$image_digest|g" \
      "$template" >"$node_config"
    "$policy" compile --source "$policy_source" --seal-request "$seal_request" \
      --signing-key "$signing_key" --output "$artifact"
    "$policy" verify --artifact "$artifact" --public-key "$public_key"
    jq --arg artifact "$artifact" --arg public_key "$public_key" \
      '.policy_candidates = [{artifact_path: $artifact, public_key_path: $public_key}]' \
      "$node_config" >"$lane_root/node-prepared.json"
    mv -- "$lane_root/node-prepared.json" "$node_config"

    jq -n --arg ca "$ca" --arg server_certificate "$server_certificate" \
      --arg server_key "$server_key" --arg node_id "$node_id" \
      --arg node_certificate_sha256 "$node_certificate_sha256" \
      --arg state "$lane_root/control-state" --arg signing_key "$signing_key" \
      --arg webhook_token_path "$lane_root/webhook-token" \
      --arg kubernetes_node "$kubernetes_node" \
      '{listen:"127.0.0.1:7443",
        tls:{certificate_path:$server_certificate,private_key_path:$server_key,node_ca_path:$ca},
        allowed_nodes:[{node_id:$node_id,certificate_sha256:$node_certificate_sha256,
          tenant_id:"00000000-0000-0001-0000-000000000002"}],
        trust:{generation:1,bundle_digest:("d" * 64)},
        evidence_directory:($state + "/evidence"),
        administrative_exec:{listen:"127.0.0.1:9443",
          public_base_url:"https://localhost:9443",
          tls_certificate_path:$server_certificate,tls_private_key_path:$server_key,
          oidc_issuer_url:"https://localhost:9444",oidc_client_id:"mithril-vm",
          oidc_client_secret_path:null,oidc_ca_path:$ca,
          kubernetes_audience:"mithril-administrative-exec",
          kubernetes_webhook_token_path:$webhook_token_path,
          node_ids_by_kubernetes_name:{($kubernetes_node):$node_id},request_lifetime_seconds:120,
          approval:{state_directory:$state,tenant_id:"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            cluster_uid:"55555555-5555-4555-8555-555555555555",
            trust_domain_id:"22222222-2222-4222-8222-222222222222",
            issuer_id:"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            key_id:"mithril-vm-administrative-key-v1",private_key_path:$signing_key,
            sequence_epoch:1,authorization_lifetime_seconds:120}}}' >"$control_config"

    python3 "$oidc" --certificate "$server_certificate" \
      --private-key "$server_key" --issuer https://localhost:9444 \
      >"$oidc_log" 2>&1 &
    oidc_pid=$!
    for _attempt in {1..100}; do
      curl --silent --show-error --fail --cacert "$ca" \
        https://localhost:9444/healthz >/dev/null 2>&1 && break
      kill -0 "$oidc_pid" 2>/dev/null || {
        echo "OIDC fixture exited before readiness" >&2
        cat "$oidc_log" >&2
        exit 1
      }
      sleep 0.1
    done
    curl --silent --show-error --fail --cacert "$ca" \
      https://localhost:9444/healthz >/dev/null
    KUBECONFIG=/etc/rancher/k3s/k3s.yaml "$control" --config "$control_config" \
      >"$control_log" 2>&1 &
    control_pid=$!
    for _attempt in {1..100}; do
      status=$(curl --silent --show-error --cacert "$ca" --output /dev/null \
        --write-out '%{http_code}' https://localhost:9443/activate/missing || true)
      [[ $status == 404 ]] && break
      kill -0 "$control_pid" 2>/dev/null || {
        echo "Mithril Control exited before administrative HTTPS readiness" >&2
        cat "$control_log" >&2
        exit 1
      }
      sleep 0.1
    done
    pin_owned=true
    (
      printf '%s\n' "$BASHPID" >"$controller_cgroup/cgroup.procs"
      exec env RUST_LOG=warn "$node" --config "$node_config"
    ) >"$node_log" 2>&1 &
    node_pid=$!
    for _attempt in {1..300}; do
      if [[ -S $lane_root/observation.sock ]] \
        && "$inspect" --pin-root "$pin_root" task --host-pid "$init_pid" \
          >"$lane_root/initial-root.json" 2>/dev/null; then
        break
      fi
      kill -0 "$node_pid" 2>/dev/null || {
        echo "Mithril node exited before administrative readiness" >&2
        tail -n 60 "$node_log" >&2
        exit 1
      }
      sleep 0.1
    done
    [[ -s $lane_root/initial-root.json ]] || {
      echo "Mithril node did not publish the administrative binding" >&2
      exit 1
    }
    sleep 1

    ca_bundle=$(base64 -w0 "$ca")
    rbac=$lane_root/administrative-rbac.yaml
    webhook=$lane_root/administrative-webhook.yaml
    cat >"$rbac" <<'EOF'
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: mithril-approved-administrative-exec
rules:
  - apiGroups: [""]
    resources: ["pods/exec"]
    verbs: ["get", "create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: mithril-approved-administrative-exec
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: mithril-approved-administrative-exec
subjects:
  - kind: Group
    name: mithril:administrative-exec
    apiGroup: rbac.authorization.k8s.io
EOF
    cat >"$webhook" <<EOF
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: mithril-administrative-exec
webhooks:
  - name: administrative-exec.mithril.ereborlabs.com
    admissionReviewVersions: ["v1"]
    sideEffects: None
    failurePolicy: Fail
    matchPolicy: Exact
    timeoutSeconds: 5
    clientConfig:
      url: https://localhost:9443/kubernetes/$webhook_token/admit
      caBundle: $ca_bundle
    rules:
      - operations: ["CONNECT"]
        apiGroups: [""]
        apiVersions: ["v1"]
        resources: ["pods/exec"]
        scope: Namespaced
EOF
    /usr/local/bin/k3s kubectl apply -f "$rbac" >/dev/null
    /usr/local/bin/k3s kubectl apply -f "$webhook" >/dev/null
    credential_kubeconfig=$lane_root/credential-kubeconfig.yaml
    cat >"$credential_kubeconfig" <<EOF
apiVersion: v1
kind: Config
clusters:
  - name: k3s
    cluster:
      certificate-authority: /var/lib/rancher/k3s/server/tls/server-ca.crt
      server: https://127.0.0.1:6443
contexts:
  - name: k3s
    context:
      cluster: k3s
      user: mithril
current-context: k3s
users:
  - name: mithril
    user: {}
EOF
    chmod 600 "$credential_kubeconfig"

    KUBECONFIG="$credential_kubeconfig" "$kubectl_mithril" \
      --control-url https://localhost:9443 --control-ca "$ca" \
      exec -n "$namespace" -c "$container" \
      "$pod" /var/lib/mithril/busybox sleep 20 >"$plugin_log" 2>&1 &
    plugin_pid=$!
    activation_url=
    for _attempt in {1..300}; do
      activation_url=$(sed -n 's/^Opening \(https:[^[:space:]]*\)$/\1/p' \
        "$plugin_log" | head -n 1)
      [[ -n $activation_url ]] && break
      kill -0 "$plugin_pid" 2>/dev/null || {
        echo "kubectl-mithril exited before it requested approval" >&2
        cat "$plugin_log" >&2
        exit 1
      }
      sleep 0.1
    done
    [[ $activation_url == https://localhost:9443/activate/* ]] || {
      echo "kubectl-mithril did not print one local activation URL" >&2
      cat "$plugin_log" >&2
      exit 1
    }
    curl --silent --show-error --fail --cacert "$ca" "$activation_url" \
      >"$lane_root/activation.html"
    grep -Fq '/var/lib/mithril/busybox sleep 20' \
      "$lane_root/activation.html"
    curl --silent --show-error --cacert "$ca" --dump-header "$lane_root/authorize.headers" \
      --output /dev/null "$activation_url/authorize"
    oidc_authorize_url=$(awk 'tolower($1) == "location:" {$1=""; sub(/^ /, ""); gsub(/\r/, ""); print; exit}' \
      "$lane_root/authorize.headers")
    [[ $oidc_authorize_url == https://localhost:9444/authorize* ]] || {
      echo "Control did not start the checked OIDC authorization-code flow" >&2
      exit 1
    }
    curl --silent --show-error --cacert "$ca" --dump-header "$lane_root/oidc.headers" \
      --output /dev/null "$oidc_authorize_url"
    oidc_callback_url=$(awk 'tolower($1) == "location:" {$1=""; sub(/^ /, ""); gsub(/\r/, ""); print; exit}' \
      "$lane_root/oidc.headers")
    [[ $oidc_callback_url == https://localhost:9443/oidc/callback* ]] || {
      echo "OIDC fixture did not return to the exact Control callback" >&2
      exit 1
    }
    curl --silent --show-error --fail --cacert "$ca" "$oidc_callback_url" \
      >"$lane_root/confirmation.html"
    grep -Fq 'operator@mithril.invalid' "$lane_root/confirmation.html"
    grep -Fq 'I accept this race and approve once' "$lane_root/confirmation.html"
    curl --silent --show-error --fail --cacert "$ca" --request POST \
      "$activation_url/approve" >"$lane_root/approved.html"
    grep -Fq 'Administrative exec approved' "$lane_root/approved.html"

    cgroup_path=$(sed -n 's|^0::|/sys/fs/cgroup|p' "/proc/$init_pid/cgroup")
    [[ -d $cgroup_path ]] || {
      echo "administrative target has no live unified cgroup" >&2
      exit 1
    }
    approved_pid=
    for _attempt in {1..300}; do
      while read -r host_pid; do
        [[ -r /proc/$host_pid/cmdline ]] || continue
        command_line=$(tr '\0' ' ' <"/proc/$host_pid/cmdline")
        if [[ $command_line == '/var/lib/mithril/busybox sleep 20 ' ]]; then
          approved_pid=$host_pid
          break
        fi
      done <"$cgroup_path/cgroup.procs"
      [[ -n $approved_pid ]] && break
      kill -0 "$plugin_pid" 2>/dev/null || {
        echo "approved kubectl exec exited before the role was inspected" >&2
        cat "$plugin_log" >&2
        tail -n 80 "$node_log" >&2
        "$inspect" effects --socket-path "$lane_root/observation.sock" \
          --cgroup-scope / >&2 || true
        exit 1
      }
      sleep 0.1
    done
    [[ -n $approved_pid ]] || {
      echo "approved kubectl exec did not create the exact runtime task" >&2
      exit 1
    }
    "$inspect" --pin-root "$pin_root" task --host-pid "$approved_pid" \
      >"$lane_root/approved-task.json"
    jq -e '.root_class == "external_runtime_root"
           and .installed_role_class == "approved_administrative_role"
           and .active_role_id == 3' "$lane_root/approved-task.json" >/dev/null || {
      echo "approved kubectl exec did not consume the administrative role" >&2
      cat "$lane_root/approved-task.json" >&2
      exit 1
    }
    approved_task_cookie=$(jq -er '.task_cookie' "$lane_root/approved-task.json")
    set +e
    wait "$plugin_pid"
    plugin_status=$?
    set -e
    plugin_pid=
    [[ $plugin_status -eq 0 ]] || {
      echo "approved kubectl-mithril exec failed with status $plugin_status" >&2
      cat "$plugin_log" >&2
      exit 1
    }

    set +e
    /usr/local/bin/k3s kubectl -n "$namespace" exec "$pod" -c "$container" -- \
      /var/lib/mithril/busybox true >"$lane_root/unapproved.out" 2>&1
    unapproved_status=$?
    set -e
    [[ $unapproved_status -ne 0 ]] \
      && grep -Fq 'admission identity has no Mithril approval ID' \
        "$lane_root/unapproved.out" || {
      echo "ordinary kubectl exec bypassed the fail-closed admission owner" >&2
      cat "$lane_root/unapproved.out" >&2
      exit 1
    }

    /usr/local/bin/k3s crictl exec "$container_id" \
      /var/lib/mithril/busybox sleep 10 >"$lane_root/direct-runtime.out" 2>&1 &
    runtime_client_pid=$!
    restricted_pid=
    for _attempt in {1..200}; do
      while read -r host_pid; do
        [[ $host_pid == "$approved_pid" || ! -r /proc/$host_pid/cmdline ]] && continue
        command_line=$(tr '\0' ' ' <"/proc/$host_pid/cmdline")
        if [[ $command_line == '/var/lib/mithril/busybox sleep 10 ' ]]; then
          restricted_pid=$host_pid
          break
        fi
      done <"$cgroup_path/cgroup.procs"
      [[ -n $restricted_pid ]] && break
      kill -0 "$runtime_client_pid" 2>/dev/null || break
      sleep 0.1
    done
    [[ -n $restricted_pid ]] || {
      echo "direct runtime non-winner did not create an inspectable root" >&2
      cat "$lane_root/direct-runtime.out" >&2
      exit 1
    }
    "$inspect" --pin-root "$pin_root" task --host-pid "$restricted_pid" \
      >"$lane_root/restricted-task.json"
    jq -e '.root_class == "external_runtime_root"
           and .installed_role_class == "runtime_external_restricted"
           and .active_role_id == 2' "$lane_root/restricted-task.json" >/dev/null || {
      echo "the post-consumption direct runtime root gained administrative authority" >&2
      cat "$lane_root/restricted-task.json" >&2
      exit 1
    }
    wait "$runtime_client_pid"
    runtime_client_pid=

    printf 'lane=k3s-administrative-exec\n'
    printf 'product_path=kubectl-mithril+oidc-pkce+self-approval+tokenreview+connect-admission+node-slot\n'
    printf 'approver=operator@mithril.invalid:self-approved\n'
    printf 'pod_uid=%s\n' "$pod_uid"
    printf 'container_id=%s\n' "$container_ref"
    printf 'approved_task_cookie=%s\n' "$approved_task_cookie"
    printf 'approved_root=external_runtime_root:approved_administrative_role\n'
    printf 'ordinary_kubectl_exec=denied-by-admission\n'
    printf 'post-consumption_direct_runtime_root=external_runtime_root:runtime_external_restricted\n'
    printf 'start_gap=recorded:container-running-before-node-binding\n'

    stop_process "$node_pid"
    node_pid=
    stop_process "$control_pid"
    control_pid=
    stop_process "$oidc_pid"
    oidc_pid=
    /usr/local/bin/k3s kubectl delete validatingwebhookconfiguration \
      mithril-administrative-exec --ignore-not-found >/dev/null
    /usr/local/bin/k3s kubectl delete clusterrolebinding \
      mithril-approved-administrative-exec --ignore-not-found >/dev/null
    /usr/local/bin/k3s kubectl delete clusterrole \
      mithril-approved-administrative-exec --ignore-not-found >/dev/null
    /usr/local/bin/k3s kubectl delete namespace "$namespace" \
      --ignore-not-found --wait=true --timeout=120s >/dev/null
    install -m 600 "$lane_root/k3s-config.yaml" /etc/rancher/k3s/config.yaml
    systemctl restart k3s
    wait_for_k3s
    k3s_configured=false
    rm -f -- /usr/local/share/ca-certificates/mithril-vm-administrative.crt
    update-ca-certificates >/dev/null
    ca_installed=false
    rm -rf -- "$pin_root" "$fixture_root"
    pin_owned=false
    fixture_owned=false
    rm -rf -- "$lane_root"
    trap - EXIT
    trap - ERR
    [[ ! -e $pin_root && ! -e $fixture_root && ! -e $lane_root ]] || {
      echo "k3s administrative-exec qualification left an owned artifact" >&2
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
    if [[ -f $work_directory/k3s-runtime-hook-installed-by-harness ]]; then
      rm -f -- /usr/local/libexec/mithril-oci-prestart-admission \
        /usr/local/libexec/mithril-oci-create-container-stage \
        /usr/local/libexec/mithril-oci-create-runtime-stage \
        /etc/containerd/mithril-base-spec.json \
        /var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.tmpl
      rm -f -- "$work_directory/k3s-runtime-hook-installed-by-harness"
    fi
    ! systemctl is-active --quiet k3s
    [[ ! -S /run/k3s/containerd/containerd.sock ]]
    rm -f -- "$work_directory/k3s-installed-by-harness"
    ;;
  k3s-agent-remove)
    (($# == 2)) || { usage; exit 2; }
    work_directory=$2
    require_root
    require_harness_guest "$work_directory"
    [[ -f $work_directory/k3s-agent-installed-by-harness \
      && -x /usr/local/bin/k3s-agent-uninstall.sh ]] || {
      echo "k3s agent uninstall owner is missing" >&2
      exit 1
    }
    /usr/local/bin/k3s-agent-uninstall.sh
    ! systemctl is-active --quiet k3s-agent
    [[ ! -S /run/k3s/containerd/containerd.sock ]]
    rm -f -- "$work_directory/k3s-agent-installed-by-harness"
    ;;
  --help|-h)
    usage
    ;;
  *)
    usage
    exit 2
    ;;
esac
