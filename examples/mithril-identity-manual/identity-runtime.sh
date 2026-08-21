#!/usr/bin/env bash

# Shared real-node startup and cleanup for the native identity case scripts.
# Source this file; do not run it directly.

identity_bin_directory=${MITHRIL_BIN_DIRECTORY:-target/debug}
identity_node=$identity_bin_directory/mithril-node
identity_inspect=$identity_bin_directory/mithril-inspect
identity_node_pid=
identity_task_pids=()
identity_cleanup_functions=()
identity_success_message=
identity_work=
identity_pin_root=
identity_effect_controller_cgroup_path=
identity_effect_controller_cgroup_owned=false
identity_repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
identity_k3s_namespace=
identity_k3s_namespace_created=false
identity_k3s_fixture_root=
identity_k3s_shared_directory=
identity_k3s_node_config=
identity_k3s_secret_path=
identity_k3s_container_shared_directory=
identity_k3s_init_container_id=
identity_k3s_sidecar_container_id=
identity_k3s_application_container_id=
identity_k3s_ephemeral_container_id=
identity_k3s_startup_container_id=
identity_k3s_readiness_container_id=
identity_k3s_liveness_container_id=
identity_k3s_init_pid=
identity_k3s_sidecar_pid=
identity_k3s_application_pid=
identity_k3s_ephemeral_pid=
identity_k3s_startup_pid=
identity_k3s_readiness_pid=
identity_k3s_liveness_pid=
identity_poststart_entrypoint_first_pid=
identity_poststart_hook_first_pid=
identity_poststart_repeat_pid=
identity_poststart_repeat_container_id=
identity_held_initial_pids=()
identity_prestart_requests=()
identity_prestart_request_directory=/run/mithril-identity-prestart
identity_k3s_runtime_class_created=false
identity_probe_command=
identity_prestop_release_fifo=
identity_poststart_release_fifos=()
identity_stock_hook_manifest_template=

identity_require_command() {
  command -v "$1" >/dev/null || {
    echo "missing required command: $1" >&2
    exit 2
  }
}

identity_check_base() {
  identity_source_config=$1
  identity_require_command bpftool
  identity_require_command jq
  [[ $(id -u) -eq 0 ]] || {
    echo "run this example with sudo" >&2
    exit 2
  }
  [[ -x $identity_node && -x $identity_inspect ]] || {
    echo "build first: cargo build -p mithril-node --bins" >&2
    exit 2
  }
  [[ -f $identity_source_config ]] || {
    echo "node config does not exist: $identity_source_config" >&2
    exit 2
  }
}

identity_wait_for_interceptor_detach() {
  local attempt
  for ((attempt = 0; attempt < 300; attempt++)); do
    if ! bpftool -j prog show | jq -e \
      'any(.[]; ((.name? // "") | startswith("erebor_")))' >/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  echo "Erebor Interceptor programs remain loaded after cleanup" >&2
  bpftool -j prog show | jq \
    '[.[] | select(((.name? // "") | startswith("erebor_"))) | {id, name}]' >&2
  return 1
}

identity_begin() {
  trap identity_on_exit EXIT
  identity_work=$(mktemp -d /tmp/mithril-identity-manual.XXXXXX)
  identity_pin_root=/sys/fs/bpf/erebor-mithril-identity-manual-${identity_work##*.}
  identity_effect_controller_cgroup_path=/sys/fs/cgroup/mithril-effect-controller-${identity_work##*.}
  mkdir -m 700 -- "$identity_pin_root"
  identity_config=$identity_work/node.json
  identity_state=$identity_work/state
  identity_lease=$identity_work/owner.lock
}

identity_cgroup_for_pid() {
  local hierarchy controllers path
  while IFS=: read -r hierarchy controllers path; do
    if [[ $hierarchy == 0 && -z $controllers ]]; then
      printf '/sys/fs/cgroup%s\n' "$path"
      return
    fi
  done <"/proc/$1/cgroup"
  return 1
}

identity_on_exit() {
  local status=$?
  local cleanup_failed=0
  trap - EXIT
  set +e
  if [[ $status -ne 0 && -n $identity_work && -f $identity_work/mithril-node.log ]]; then
    echo "mithril-node log:" >&2
    tail -n 30 "$identity_work/mithril-node.log" >&2
  fi
  for pid in "${identity_task_pids[@]}"; do
    kill -TERM "$pid" 2>/dev/null
  done
  identity_stop_node || cleanup_failed=1
  for cleanup in "${identity_cleanup_functions[@]}"; do
    "$cleanup" || cleanup_failed=1
  done
  [[ -z $identity_pin_root || ! -e $identity_pin_root ]] || rm -r -- "$identity_pin_root"
  [[ -z $identity_work || ! -e $identity_work ]] || rm -r -- "$identity_work"
  identity_wait_for_interceptor_detach || cleanup_failed=1
  [[ (-z $identity_pin_root || ! -e $identity_pin_root) \
    && (-z $identity_work || ! -e $identity_work) ]] || cleanup_failed=1

  if [[ $cleanup_failed -ne 0 ]]; then
    echo "native identity manual cleanup failed" >&2
    status=1
  elif [[ $status -eq 0 && -n $identity_success_message ]]; then
    echo
    echo "$identity_success_message"
    echo "Mithril, tasks, pins, state, lease, config, and logs removed."
  fi
  exit "$status"
}

identity_prepare_docker() {
  identity_check_base "$1"
  identity_require_command docker
  identity_mode=docker
  identity_container=$2
  docker inspect "$identity_container" >/dev/null
  identity_begin

  identity_container_id=$(docker inspect --format '{{.Id}}' "$identity_container")
  identity_init_pid=$(docker inspect --format '{{.State.Pid}}' "$identity_container")
  local container_name image_digest generation
  container_name=$(docker inspect --format '{{.Name}}' "$identity_container")
  container_name=${container_name#/}
  image_digest=$(docker inspect --format '{{.Image}}' "$identity_container")
  generation=$(stat -c %Y "/proc/$identity_init_pid")
  identity_cgroup_path=$(identity_cgroup_for_pid "$identity_init_pid")
  [[ -n $identity_cgroup_path ]] || {
    echo "Docker container is not using cgroup v2" >&2
    exit 2
  }

  jq --arg state "$identity_state" \
    --arg pin_root "$identity_pin_root" \
    --arg lease "$identity_lease" \
    --arg id "$identity_container_id" \
    --arg name "$container_name" \
    --arg image "$image_digest" \
    --arg cgroup "$identity_cgroup_path" \
    --argjson generation "$generation" \
    '.state_directory = $state
     | .interceptor.pin_root = $pin_root
     | .interceptor.lease_path = $lease
     | .runtime_observation = null
     | .container_runtime = null
     | .workload_bindings = [{
         binding_id: "11111111-1111-4111-8111-111111111111",
         execution_set_id: "22222222-2222-4222-8222-222222222222",
         protected_scope_id: "44444444-4444-4444-8444-444444444444",
         workload_selector_id: "worker",
         profile_id: "33333333-3333-4333-8333-333333333333",
         container_id: $id,
         namespace: "docker-manual",
         pod_uid: "docker-manual",
         sandbox_id: $id,
         container_name: $name,
         image_digest: $image,
         container_kind: "application",
         container_generation: $generation,
         root_cgroup_path: $cgroup,
         lifecycle_generation: 1,
         active_profile_generation_ref_id: 1,
         initial_role_id: 1,
         external_role_id: 2,
         arm_initial_root: false
       }]' "$identity_source_config" >"$identity_config"
}

identity_prepare_cri() {
  identity_check_base "$1"
  identity_require_command crictl
  identity_mode=cri
  identity_container_id=$2
  identity_container=$identity_container_id
  identity_begin

  identity_configure_cri "$1" "$2"
}

identity_configure_cri() {
  identity_source_config=$1
  identity_container_id=$2
  identity_container=$identity_container_id

  local matching_bindings runtime_socket
  matching_bindings=$(jq --arg id "$identity_container_id" \
    '[.workload_bindings[] | select(.container_id == $id)] | length' \
    "$identity_source_config")
  [[ $matching_bindings -eq 1 ]] || {
    echo "node config must contain exactly one binding for $identity_container_id" >&2
    exit 2
  }
  jq --arg id "$identity_container_id" \
    --arg state "$identity_state" \
    --arg pin_root "$identity_pin_root" \
    --arg lease "$identity_lease" \
    '.state_directory = $state
     | .interceptor.pin_root = $pin_root
     | .interceptor.lease_path = $lease
     | .runtime_observation = null
     | .workload_bindings = [.workload_bindings[] | select(.container_id == $id)]
     | .workload_bindings[0].arm_initial_root = false
     | del(.workload_bindings[0].root_cgroup_path)' \
    "$identity_source_config" >"$identity_config"

  runtime_socket=$(jq -er '.container_runtime.socket_path' "$identity_config")
  identity_runtime_endpoint="unix://$runtime_socket"
  identity_init_pid=$(crictl --runtime-endpoint "$identity_runtime_endpoint" \
    inspect "$identity_container_id" | jq -er '.info.pid')
  identity_cgroup_path=$(identity_cgroup_for_pid "$identity_init_pid")
}

identity_prepare_k3s_case() {
  local image=$1
  local source_config=$identity_repository/crates/mithril-e2e/harness/vm/k3s-cri-effect-node-v1.json
  local workload_template=$identity_repository/examples/mithril-effect-observation-manual/k3s-cri-manual-workload-v1.yaml
  identity_check_base "$source_config"
  identity_require_command crictl
  identity_require_command date
  identity_require_command kubectl
  identity_mode=cri
  identity_begin

  local suffix
  suffix=$(tr '[:upper:]' '[:lower:]' <<<"${identity_work##*.}")
  identity_k3s_namespace=mithril-manual-$suffix
  identity_k3s_fixture_root=/var/lib/mithril-manual-$suffix
  identity_k3s_shared_directory=$identity_k3s_fixture_root/shared
  identity_k3s_node_config=$identity_work/k3s-node.json
  identity_k3s_secret_path=/var/lib/mithril/secret
  identity_k3s_container_shared_directory=/var/lib/mithril/manual-shared
  identity_cleanup_functions+=(identity_cleanup_k3s_case)

  install -d -m 700 -- "$identity_k3s_fixture_root" "$identity_k3s_shared_directory"
  printf 'mithril manual secret\n' >"$identity_k3s_fixture_root/secret"
  chmod 0400 -- "$identity_k3s_fixture_root/secret"

  local workload=$identity_work/workload.yaml
  sed \
    -e "s|MITHRIL_MANUAL_NAMESPACE|$identity_k3s_namespace|g" \
    -e "s|MITHRIL_MANUAL_SECRET_HOST_PATH|$identity_k3s_fixture_root/secret|g" \
    -e "s|MITHRIL_MANUAL_SHARED_HOST_DIRECTORY|$identity_k3s_shared_directory|g" \
    -e "s|MITHRIL_MANUAL_IMAGE|$image|g" \
    "$workload_template" >"$workload"
  kubectl create namespace "$identity_k3s_namespace" >/dev/null
  identity_k3s_namespace_created=true
  kubectl apply -f "$workload" >/dev/null
  kubectl -n "$identity_k3s_namespace" wait \
    --for=condition=Ready pod/mithril-runtime --timeout=300s >/dev/null

  local container_ref container_json created_at generation image_digest pod_uid sandbox_id
  container_ref=$(kubectl -n "$identity_k3s_namespace" get pod mithril-runtime \
    -o jsonpath='{.status.containerStatuses[0].containerID}')
  [[ $container_ref == containerd://* ]] || {
    echo "K3s did not return a containerd container ID" >&2
    return 1
  }
  identity_container_id=${container_ref#containerd://}
  identity_container=$identity_container_id
  pod_uid=$(kubectl -n "$identity_k3s_namespace" get pod mithril-runtime \
    -o jsonpath='{.metadata.uid}')
  container_json=$(crictl inspect "$identity_container_id")
  created_at=$(jq -er '.status.createdAt' <<<"$container_json")
  generation=$(date --utc --date "$created_at" +%s%N)
  image_digest=$(jq -er '.status.imageRef' <<<"$container_json")
  sandbox_id=$(crictl ps --id "$identity_container_id" -o json \
    | jq -er '.containers[0].podSandboxId')
  [[ $generation =~ ^[1-9][0-9]*$ && -n $pod_uid && -n $sandbox_id && -n $image_digest ]] || {
    echo "K3s did not return a complete live workload binding" >&2
    return 1
  }

  jq --arg id "$identity_container_id" \
    --arg namespace "$identity_k3s_namespace" \
    --arg pod_uid "$pod_uid" \
    --arg sandbox_id "$sandbox_id" \
    --arg image_digest "$image_digest" \
    --argjson generation "$generation" \
    '.workload_bindings[0].container_id = $id
     | .workload_bindings[0].namespace = $namespace
     | .workload_bindings[0].pod_uid = $pod_uid
     | .workload_bindings[0].sandbox_id = $sandbox_id
     | .workload_bindings[0].image_digest = $image_digest
     | .workload_bindings[0].container_generation = $generation' \
    "$source_config" >"$identity_k3s_node_config"
  identity_configure_cri "$identity_k3s_node_config" "$identity_container_id"
}

identity_prepare_k3s_lifecycle_sleep_case() {
  local source_config=$identity_repository/crates/mithril-e2e/harness/vm/k3s-cri-effect-node-v1.json
  local workload_template=$identity_repository/crates/mithril-e2e/fixtures/identity/kubernetes-lifecycle-sleep-workload-v1.yaml
  identity_check_base "$source_config"
  identity_require_command crictl
  identity_require_command kubectl
  identity_begin

  local suffix workload
  suffix=$(tr '[:upper:]' '[:lower:]' <<<"${identity_work##*.}")
  identity_k3s_namespace=mithril-manual-$suffix
  identity_k3s_fixture_root=/var/lib/mithril-manual-$suffix
  identity_k3s_shared_directory=$identity_k3s_fixture_root/shared
  identity_cleanup_functions+=(identity_cleanup_k3s_case)
  install -d -m 700 -- "$identity_k3s_fixture_root" "$identity_k3s_shared_directory"

  workload=$identity_work/workload.yaml
  sed -e "s|MITHRIL_IDENTITY_SLEEP_NAMESPACE|$identity_k3s_namespace|g" \
    "$workload_template" >"$workload"
  identity_k3s_namespace_created=true
  kubectl apply -f "$workload" >/dev/null
}

identity_prepare_k3s_network_probe_case() {
  local source_config=$identity_repository/crates/mithril-e2e/harness/vm/k3s-cri-effect-node-v1.json
  local workload_template=$identity_repository/crates/mithril-e2e/fixtures/identity/kubernetes-network-probes-workload-v1.yaml
  identity_check_base "$source_config"
  identity_require_command crictl
  identity_require_command kubectl
  identity_begin

  local suffix workload
  suffix=$(tr '[:upper:]' '[:lower:]' <<<"${identity_work##*.}")
  identity_k3s_namespace=mithril-manual-$suffix
  identity_k3s_fixture_root=/var/lib/mithril-manual-$suffix
  identity_k3s_shared_directory=$identity_k3s_fixture_root/shared
  identity_cleanup_functions+=(identity_cleanup_k3s_case)
  install -d -m 700 -- "$identity_k3s_fixture_root" "$identity_k3s_shared_directory"

  workload=$identity_work/workload.yaml
  sed -e "s|MITHRIL_IDENTITY_NETWORK_PROBE_NAMESPACE|$identity_k3s_namespace|g" \
    "$workload_template" >"$workload"
  identity_k3s_namespace_created=true
  kubectl apply -f "$workload" >/dev/null
}

identity_prepare_k3s_containers_case() {
  local source_config=$identity_repository/crates/mithril-e2e/harness/vm/k3s-cri-effect-node-v1.json
  local workload_template=$identity_repository/crates/mithril-e2e/fixtures/identity/kubernetes-containers-workload-v1.yaml
  identity_check_base "$source_config"
  identity_require_command crictl
  identity_require_command date
  identity_require_command kubectl
  identity_mode=cri
  identity_begin

  local suffix workload runtime_socket
  suffix=$(tr '[:upper:]' '[:lower:]' <<<"${identity_work##*.}")
  identity_k3s_namespace=mithril-manual-$suffix
  identity_k3s_fixture_root=/var/lib/mithril-manual-$suffix
  identity_k3s_shared_directory=$identity_k3s_fixture_root/shared
  identity_k3s_node_config=$identity_work/k3s-node.json
  identity_cleanup_functions+=(identity_cleanup_k3s_case)
  install -d -m 700 -- "$identity_k3s_fixture_root" "$identity_k3s_shared_directory"

  runtime_socket=$(jq -er '.container_runtime.socket_path' "$source_config")
  identity_runtime_endpoint=unix://$runtime_socket
  workload=$identity_work/workload.yaml
  sed \
    -e "s|MITHRIL_IDENTITY_CONTAINERS_NAMESPACE|$identity_k3s_namespace|g" \
    -e "s|MITHRIL_IDENTITY_CONTAINERS_FIXTURE_ROOT|$identity_k3s_shared_directory|g" \
    "$workload_template" >"$workload"
  identity_k3s_namespace_created=true
  kubectl apply -f "$workload" >/dev/null
}

identity_k3s_wait_container_id() {
  local container_name=$1
  local attempt container_id
  for ((attempt = 0; attempt < 600; attempt++)); do
    container_id=$(crictl --runtime-endpoint "$identity_runtime_endpoint" ps -o json \
      | jq -r --arg namespace "$identity_k3s_namespace" --arg name "$container_name" \
        '.containers[]?
         | select(.metadata.name == $name)
         | select(.labels["io.kubernetes.pod.namespace"] == $namespace)
         | .id' | head -n 1)
    if [[ -n $container_id ]]; then
      printf '%s\n' "$container_id"
      return 0
    fi
    sleep 0.1
  done
  echo "the $container_name container did not start" >&2
  return 1
}

identity_k3s_container_binding_json() {
  local container_name=$1
  local container_kind=$2
  local binding_id=$3
  local execution_set_id=$4
  local pod_name=$5
  local profile_id=${6:-33333333-3333-4333-8333-333333333333}
  local profile_ref_id=${7:-1}
  local container_id container_json created_at generation image_digest pod_uid sandbox_id

  container_id=$(identity_k3s_wait_container_id "$container_name")
  container_json=$(crictl --runtime-endpoint "$identity_runtime_endpoint" \
    inspect "$container_id")
  created_at=$(jq -er '.status.createdAt' <<<"$container_json")
  generation=$(date --utc --date "$created_at" +%s%N)
  image_digest=$(jq -er '.status.imageRef' <<<"$container_json")
  pod_uid=$(kubectl -n "$identity_k3s_namespace" get pod "$pod_name" \
    -o jsonpath='{.metadata.uid}')
  sandbox_id=$(crictl --runtime-endpoint "$identity_runtime_endpoint" \
    ps --id "$container_id" -o json | jq -er '.containers[0].podSandboxId')
  [[ $generation =~ ^[1-9][0-9]*$ && -n $pod_uid && -n $sandbox_id && -n $image_digest ]] || {
    echo "Kubernetes did not return a complete $container_name binding" >&2
    return 1
  }

  jq -n \
    --arg binding_id "$binding_id" \
    --arg execution_set_id "$execution_set_id" \
    --arg container_id "$container_id" \
    --arg namespace "$identity_k3s_namespace" \
    --arg pod_uid "$pod_uid" \
    --arg sandbox_id "$sandbox_id" \
    --arg container_name "$container_name" \
    --arg image_digest "$image_digest" \
    --arg container_kind "$container_kind" \
    --arg profile_id "$profile_id" \
    --argjson generation "$generation" \
    --argjson profile_ref_id "$profile_ref_id" \
    '{
      binding_id: $binding_id,
      execution_set_id: $execution_set_id,
      protected_scope_id: "44444444-4444-4444-8444-444444444444",
      workload_selector_id: $container_name,
      profile_id: $profile_id,
      container_id: $container_id,
      namespace: $namespace,
      pod_uid: $pod_uid,
      sandbox_id: $sandbox_id,
      container_name: $container_name,
      image_digest: $image_digest,
      container_kind: $container_kind,
      container_generation: $generation,
      lifecycle_generation: 1,
      active_profile_generation_ref_id: $profile_ref_id,
      initial_role_id: 1,
      external_role_id: 2,
      arm_initial_root: false
    }'
}

identity_configure_k3s_containers_stage() {
  local stage=$1
  local source_config=$identity_repository/crates/mithril-e2e/harness/vm/k3s-cri-effect-node-v1.json
  local first second first_pid second_pid
  case "$stage" in
    init)
      first=$(identity_k3s_container_binding_json init init \
        11111111-1111-4111-8111-111111111101 \
        22222222-2222-4222-8222-222222222201 mithril-containers)
      second=$(identity_k3s_container_binding_json sidecar sidecar \
        11111111-1111-4111-8111-111111111102 \
        22222222-2222-4222-8222-222222222202 mithril-containers)
      identity_k3s_init_container_id=$(jq -er '.container_id' <<<"$first")
      identity_k3s_sidecar_container_id=$(jq -er '.container_id' <<<"$second")
      identity_k3s_init_pid=$(crictl --runtime-endpoint "$identity_runtime_endpoint" \
        inspect "$identity_k3s_init_container_id" | jq -er '.info.pid')
      identity_k3s_sidecar_pid=$(crictl --runtime-endpoint "$identity_runtime_endpoint" \
        inspect "$identity_k3s_sidecar_container_id" | jq -er '.info.pid')
      first_pid=$identity_k3s_init_pid
      second_pid=$identity_k3s_sidecar_pid
      ;;
    application)
      first=$(identity_k3s_container_binding_json sidecar sidecar \
        11111111-1111-4111-8111-111111111102 \
        22222222-2222-4222-8222-222222222202 mithril-containers)
      second=$(identity_k3s_container_binding_json application application \
        11111111-1111-4111-8111-111111111103 \
        22222222-2222-4222-8222-222222222203 mithril-containers)
      identity_k3s_sidecar_container_id=$(jq -er '.container_id' <<<"$first")
      identity_k3s_application_container_id=$(jq -er '.container_id' <<<"$second")
      identity_k3s_sidecar_pid=$(crictl --runtime-endpoint "$identity_runtime_endpoint" \
        inspect "$identity_k3s_sidecar_container_id" | jq -er '.info.pid')
      identity_k3s_application_pid=$(crictl --runtime-endpoint "$identity_runtime_endpoint" \
        inspect "$identity_k3s_application_container_id" | jq -er '.info.pid')
      first_pid=$identity_k3s_sidecar_pid
      second_pid=$identity_k3s_application_pid
      ;;
    *)
      echo "unknown Kubernetes containers stage: $stage" >&2
      return 2
      ;;
  esac

  jq \
    --arg state "$identity_state" \
    --arg pin_root "$identity_pin_root" \
    --arg lease "$identity_lease" \
    --argjson first "$first" \
    --argjson second "$second" \
    '.state_directory = $state
     | .interceptor.pin_root = $pin_root
     | .interceptor.lease_path = $lease
     | .runtime_observation = null
     | .workload_bindings = [$first, $second]' \
    "$source_config" >"$identity_config"
  [[ $first_pid =~ ^[1-9][0-9]*$ && $second_pid =~ ^[1-9][0-9]*$ ]] || {
    echo "Kubernetes returned an invalid container PID for stage $stage" >&2
    return 1
  }
  identity_init_pid=$second_pid
  identity_cgroup_path=$(identity_cgroup_for_pid "$identity_init_pid")
}

identity_prepare_k3s_ephemeral_case() {
  local source_config=$identity_repository/crates/mithril-e2e/harness/vm/k3s-cri-effect-node-v1.json
  local workload_template=$identity_repository/crates/mithril-e2e/fixtures/identity/kubernetes-ephemeral-workload-v1.yaml
  local ephemeral_patch='{"spec":{"ephemeralContainers":[{"name":"debugger","image":"docker.io/library/busybox:1.36.1@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662","imagePullPolicy":"IfNotPresent","targetContainerName":"application","command":["/bin/sh","-c","exec sleep 3600"],"stdin":false,"tty":false}]}}'
  identity_check_base "$source_config"
  identity_require_command crictl
  identity_require_command date
  identity_require_command kubectl
  identity_mode=cri
  identity_begin

  local suffix workload runtime_socket target ephemeral
  suffix=$(tr '[:upper:]' '[:lower:]' <<<"${identity_work##*.}")
  identity_k3s_namespace=mithril-manual-$suffix
  identity_k3s_fixture_root=/var/lib/mithril-manual-$suffix
  identity_k3s_shared_directory=$identity_k3s_fixture_root/shared
  identity_k3s_node_config=$identity_work/k3s-node.json
  identity_cleanup_functions+=(identity_cleanup_k3s_case)
  install -d -m 700 -- "$identity_k3s_fixture_root" "$identity_k3s_shared_directory"

  runtime_socket=$(jq -er '.container_runtime.socket_path' "$source_config")
  identity_runtime_endpoint=unix://$runtime_socket
  workload=$identity_work/workload.yaml
  sed -e "s|MITHRIL_IDENTITY_EPHEMERAL_NAMESPACE|$identity_k3s_namespace|g" \
    "$workload_template" >"$workload"
  identity_k3s_namespace_created=true
  kubectl apply -f "$workload" >/dev/null
  kubectl -n "$identity_k3s_namespace" wait --for=condition=Ready \
    pod/mithril-ephemeral --timeout=180s >/dev/null
  kubectl -n "$identity_k3s_namespace" patch pod mithril-ephemeral \
    --subresource=ephemeralcontainers --type=merge -p "$ephemeral_patch" >/dev/null

  target=$(identity_k3s_container_binding_json application application \
    11111111-1111-4111-8111-111111111201 \
    22222222-2222-4222-8222-222222222301 mithril-ephemeral \
    33333333-3333-4333-8333-333333333301 7)
  ephemeral=$(identity_k3s_container_binding_json debugger ephemeral \
    11111111-1111-4111-8111-111111111202 \
    22222222-2222-4222-8222-222222222302 mithril-ephemeral \
    33333333-3333-4333-8333-333333333302 8)
  identity_k3s_application_container_id=$(jq -er '.container_id' <<<"$target")
  identity_k3s_ephemeral_container_id=$(jq -er '.container_id' <<<"$ephemeral")
  identity_k3s_application_pid=$(crictl --runtime-endpoint "$identity_runtime_endpoint" \
    inspect "$identity_k3s_application_container_id" | jq -er '.info.pid')
  identity_k3s_ephemeral_pid=$(crictl --runtime-endpoint "$identity_runtime_endpoint" \
    inspect "$identity_k3s_ephemeral_container_id" | jq -er '.info.pid')
  [[ $identity_k3s_application_pid =~ ^[1-9][0-9]*$ \
    && $identity_k3s_ephemeral_pid =~ ^[1-9][0-9]*$ ]] || {
    echo "Kubernetes returned an invalid application or ephemeral PID" >&2
    return 1
  }

  jq \
    --arg state "$identity_state" \
    --arg pin_root "$identity_pin_root" \
    --arg lease "$identity_lease" \
    --argjson target "$target" \
    --argjson ephemeral "$ephemeral" \
    '.state_directory = $state
     | .interceptor.pin_root = $pin_root
     | .interceptor.lease_path = $lease
     | .runtime_observation = null
     | .workload_bindings = [$target, $ephemeral]' \
    "$source_config" >"$identity_config"
  identity_init_pid=$identity_k3s_application_pid
  identity_cgroup_path=$(identity_cgroup_for_pid "$identity_init_pid")
}

identity_prepare_k3s_probe_impersonation_case() {
  local source_config=$identity_repository/crates/mithril-e2e/harness/vm/k3s-cri-effect-node-v1.json
  local workload_template=$identity_repository/crates/mithril-e2e/fixtures/identity/kubernetes-probe-impersonation-workload-v1.yaml
  identity_check_base "$source_config"
  identity_require_command crictl
  identity_require_command date
  identity_require_command kubectl
  identity_require_command mkfifo
  identity_mode=cri
  identity_begin

  local suffix workload runtime_socket startup readiness liveness application command_count
  suffix=$(tr '[:upper:]' '[:lower:]' <<<"${identity_work##*.}")
  identity_k3s_namespace=mithril-manual-$suffix
  identity_k3s_fixture_root=/var/lib/mithril-manual-$suffix
  identity_k3s_shared_directory=$identity_k3s_fixture_root/shared
  identity_k3s_node_config=$identity_work/k3s-node.json
  identity_cleanup_functions+=(identity_cleanup_k3s_case)
  install -d -m 700 -- "$identity_k3s_fixture_root" "$identity_k3s_shared_directory"
  mkfifo -- "$identity_k3s_shared_directory/native-start"

  identity_probe_command='read identity_pid _ < /proc/self/stat; directory=/var/lib/mithril/probe; marker="$directory/$MITHRIL_PROBE_SLOT-$identity_pid.pid"; fifo="$directory/$MITHRIL_PROBE_SLOT-release-$identity_pid"; printf "%s\n" "$identity_pid" > "$marker"; mkfifo "$fifo"; read -r identity_release < "$fifo"; rm -f "$fifo"'
  runtime_socket=$(jq -er '.container_runtime.socket_path' "$source_config")
  identity_runtime_endpoint=unix://$runtime_socket
  workload=$identity_work/workload.yaml
  sed \
    -e "s|MITHRIL_IDENTITY_PROBE_NAMESPACE|$identity_k3s_namespace|g" \
    -e "s|MITHRIL_IDENTITY_PROBE_FIXTURE_ROOT|$identity_k3s_shared_directory|g" \
    "$workload_template" >"$workload"
  command_count=$(grep -Fo -- "$identity_probe_command" "$workload" | wc -l)
  [[ $command_count -eq 4 ]] || {
    echo "the stock probes and independent entries do not use identical command bytes" >&2
    return 1
  }
  identity_k3s_namespace_created=true
  kubectl apply -f "$workload" >/dev/null

  startup=$(identity_k3s_container_binding_json startup application \
    11111111-1111-4111-8111-111111111301 \
    22222222-2222-4222-8222-222222222401 mithril-probe-impersonation \
    33333333-3333-4333-8333-333333333333 7)
  readiness=$(identity_k3s_container_binding_json readiness application \
    11111111-1111-4111-8111-111111111302 \
    22222222-2222-4222-8222-222222222402 mithril-probe-impersonation \
    33333333-3333-4333-8333-333333333333 7)
  liveness=$(identity_k3s_container_binding_json liveness application \
    11111111-1111-4111-8111-111111111303 \
    22222222-2222-4222-8222-222222222403 mithril-probe-impersonation \
    33333333-3333-4333-8333-333333333333 7)
  application=$(identity_k3s_container_binding_json application application \
    11111111-1111-4111-8111-111111111304 \
    22222222-2222-4222-8222-222222222404 mithril-probe-impersonation \
    33333333-3333-4333-8333-333333333333 7)

  identity_k3s_startup_container_id=$(jq -er '.container_id' <<<"$startup")
  identity_k3s_readiness_container_id=$(jq -er '.container_id' <<<"$readiness")
  identity_k3s_liveness_container_id=$(jq -er '.container_id' <<<"$liveness")
  identity_k3s_application_container_id=$(jq -er '.container_id' <<<"$application")
  identity_k3s_startup_pid=$(crictl --runtime-endpoint "$identity_runtime_endpoint" \
    inspect "$identity_k3s_startup_container_id" | jq -er '.info.pid')
  identity_k3s_readiness_pid=$(crictl --runtime-endpoint "$identity_runtime_endpoint" \
    inspect "$identity_k3s_readiness_container_id" | jq -er '.info.pid')
  identity_k3s_liveness_pid=$(crictl --runtime-endpoint "$identity_runtime_endpoint" \
    inspect "$identity_k3s_liveness_container_id" | jq -er '.info.pid')
  identity_k3s_application_pid=$(crictl --runtime-endpoint "$identity_runtime_endpoint" \
    inspect "$identity_k3s_application_container_id" | jq -er '.info.pid')
  [[ $identity_k3s_startup_pid =~ ^[1-9][0-9]*$ \
    && $identity_k3s_readiness_pid =~ ^[1-9][0-9]*$ \
    && $identity_k3s_liveness_pid =~ ^[1-9][0-9]*$ \
    && $identity_k3s_application_pid =~ ^[1-9][0-9]*$ ]] || {
    echo "Kubernetes returned an invalid probe fixture PID" >&2
    return 1
  }

  jq \
    --arg state "$identity_state" \
    --arg pin_root "$identity_pin_root" \
    --arg lease "$identity_lease" \
    --argjson startup "$startup" \
    --argjson readiness "$readiness" \
    --argjson liveness "$liveness" \
    --argjson application "$application" \
    '.state_directory = $state
     | .interceptor.pin_root = $pin_root
     | .interceptor.lease_path = $lease
     | .runtime_observation = null
     | .workload_bindings = [$startup, $readiness, $liveness, $application]' \
    "$source_config" >"$identity_config"
  identity_init_pid=$identity_k3s_application_pid
  identity_cgroup_path=$(identity_cgroup_for_pid "$identity_init_pid")
}

identity_prepare_k3s_prestop_case() {
  local source_config=$identity_repository/crates/mithril-e2e/harness/vm/k3s-cri-effect-node-v1.json
  local workload_template=$identity_repository/crates/mithril-e2e/fixtures/identity/kubernetes-prestop-workload-v1.yaml
  identity_check_base "$source_config"
  identity_require_command crictl
  identity_require_command date
  identity_require_command dd
  identity_require_command kubectl
  identity_require_command timeout
  identity_mode=cri
  identity_begin

  local suffix workload runtime_socket application
  suffix=$(tr '[:upper:]' '[:lower:]' <<<"${identity_work##*.}")
  identity_k3s_namespace=mithril-manual-$suffix
  identity_k3s_fixture_root=/var/lib/mithril-manual-$suffix
  identity_k3s_shared_directory=$identity_k3s_fixture_root/shared
  identity_k3s_node_config=$identity_work/k3s-node.json
  identity_cleanup_functions+=(identity_cleanup_prestop_case identity_cleanup_k3s_case)
  install -d -m 700 -- "$identity_k3s_fixture_root" "$identity_k3s_shared_directory"

  runtime_socket=$(jq -er '.container_runtime.socket_path' "$source_config")
  identity_runtime_endpoint=unix://$runtime_socket
  workload=$identity_work/workload.yaml
  sed \
    -e "s|MITHRIL_IDENTITY_PRESTOP_NAMESPACE|$identity_k3s_namespace|g" \
    -e "s|MITHRIL_IDENTITY_PRESTOP_FIXTURE_ROOT|$identity_k3s_shared_directory|g" \
    "$workload_template" >"$workload"
  identity_k3s_namespace_created=true
  kubectl apply -f "$workload" >/dev/null

  application=$(identity_k3s_container_binding_json application application \
    11111111-1111-4111-8111-111111111401 \
    22222222-2222-4222-8222-222222222501 mithril-prestop \
    33333333-3333-4333-8333-333333333333 7)
  identity_k3s_application_container_id=$(jq -er '.container_id' <<<"$application")
  identity_k3s_application_pid=$(crictl --runtime-endpoint "$identity_runtime_endpoint" \
    inspect "$identity_k3s_application_container_id" | jq -er '.info.pid')
  [[ $identity_k3s_application_pid =~ ^[1-9][0-9]*$ ]] || {
    echo "Kubernetes returned an invalid PreStop application PID" >&2
    return 1
  }

  jq \
    --arg state "$identity_state" \
    --arg pin_root "$identity_pin_root" \
    --arg lease "$identity_lease" \
    --argjson application "$application" \
    '.state_directory = $state
     | .interceptor.pin_root = $pin_root
     | .interceptor.lease_path = $lease
     | .runtime_observation = null
     | .workload_bindings = [$application]' \
    "$source_config" >"$identity_config"
  identity_init_pid=$identity_k3s_application_pid
  identity_cgroup_path=$(identity_cgroup_for_pid "$identity_init_pid")
}

identity_prepare_k3s_poststart_case() {
  local source_config=$identity_repository/crates/mithril-e2e/harness/vm/k3s-cri-effect-node-v1.json
  local workload_template=$identity_repository/crates/mithril-e2e/fixtures/identity/kubernetes-poststart-workload-v1.yaml
  identity_check_base "$source_config"
  identity_require_command crictl
  identity_require_command date
  identity_require_command dd
  identity_require_command kubectl
  identity_require_command systemctl
  identity_require_command timeout
  identity_mode=cri
  identity_begin

  local suffix workload runtime_socket entrypoint_first hook_first repeat
  suffix=$(tr '[:upper:]' '[:lower:]' <<<"${identity_work##*.}")
  identity_k3s_namespace=mithril-manual-$suffix
  identity_k3s_fixture_root=/var/lib/mithril-manual-$suffix
  identity_k3s_shared_directory=$identity_k3s_fixture_root/shared
  identity_k3s_node_config=$identity_work/k3s-node.json
  identity_cleanup_functions+=(
    identity_cleanup_poststart_case
    identity_cleanup_k3s_case
    identity_cleanup_prestart_case
  )
  install -d -m 700 -- "$identity_k3s_fixture_root" "$identity_k3s_shared_directory"
  [[ ! -e $identity_prestart_request_directory ]] || {
    echo "the prestart request directory already exists" >&2
    return 1
  }
  install -d -o root -g root -m 700 -- "$identity_prestart_request_directory"

  runtime_socket=$(jq -er '.container_runtime.socket_path' "$source_config")
  identity_runtime_endpoint=unix://$runtime_socket
  workload=$identity_work/workload.yaml
  sed \
    -e "s|MITHRIL_IDENTITY_POSTSTART_NAMESPACE|$identity_k3s_namespace|g" \
    -e "s|MITHRIL_IDENTITY_POSTSTART_FIXTURE_ROOT|$identity_k3s_shared_directory|g" \
    "$workload_template" >"$workload"
  identity_k3s_namespace_created=true
  identity_k3s_runtime_class_created=true
  kubectl apply -f "$workload" >/dev/null

  entrypoint_first=$(identity_prestart_binding_json application application \
    11111111-1111-4111-8111-111111111501 \
    22222222-2222-4222-8222-222222222601 mithril-poststart-entrypoint-first \
    33333333-3333-4333-8333-333333333333 7)
  hook_first=$(identity_prestart_binding_json application application \
    11111111-1111-4111-8111-111111111502 \
    22222222-2222-4222-8222-222222222602 mithril-poststart-hook-first \
    33333333-3333-4333-8333-333333333333 7)
  repeat=$(identity_prestart_binding_json application application \
    11111111-1111-4111-8111-111111111503 \
    22222222-2222-4222-8222-222222222603 mithril-poststart-repeat \
    33333333-3333-4333-8333-333333333333 7)

  identity_poststart_entrypoint_first_pid=$(jq -er '.pid' <<<"$entrypoint_first")
  identity_poststart_hook_first_pid=$(jq -er '.pid' <<<"$hook_first")
  identity_poststart_repeat_pid=$(jq -er '.pid' <<<"$repeat")
  identity_poststart_repeat_container_id=$(jq -er '.binding.container_id' <<<"$repeat")
  [[ $identity_poststart_entrypoint_first_pid =~ ^[1-9][0-9]*$ \
    && $identity_poststart_hook_first_pid =~ ^[1-9][0-9]*$ \
    && $identity_poststart_repeat_pid =~ ^[1-9][0-9]*$ \
    && $identity_poststart_repeat_container_id =~ ^[0-9a-f]{64}$ ]] || {
    echo "Kubernetes returned an invalid PostStart application PID" >&2
    return 1
  }

  jq \
    --arg state "$identity_state" \
    --arg pin_root "$identity_pin_root" \
    --arg lease "$identity_lease" \
    --argjson entrypoint_first "$(jq -c '.binding' <<<"$entrypoint_first")" \
    --argjson hook_first "$(jq -c '.binding' <<<"$hook_first")" \
    --argjson repeat "$(jq -c '.binding' <<<"$repeat")" \
    '.state_directory = $state
     | .interceptor.pin_root = $pin_root
     | .interceptor.lease_path = $lease
     | .runtime_observation = null
     | .container_runtime = null
     | .workload_bindings = [$entrypoint_first, $hook_first, $repeat]' \
    "$source_config" >"$identity_config"
  identity_held_initial_pids=(
    "$identity_poststart_entrypoint_first_pid"
    "$identity_poststart_hook_first_pid"
    "$identity_poststart_repeat_pid"
  )
  identity_prestart_requests=(
    "$(jq -er '.request' <<<"$entrypoint_first")"
    "$(jq -er '.request' <<<"$hook_first")"
    "$(jq -er '.request' <<<"$repeat")"
  )
  identity_init_pid=$identity_poststart_entrypoint_first_pid
  identity_cgroup_path=$(identity_cgroup_for_pid "$identity_init_pid")
  identity_start_node
  identity_release_prestarts
}

identity_prepare_k3s_stock_hook_failure_case() {
  local source_config=$identity_repository/crates/mithril-e2e/harness/vm/k3s-cri-effect-node-v1.json
  local runtime_socket
  identity_stock_hook_manifest_template=$identity_repository/crates/mithril-e2e/fixtures/identity/kubernetes-stock-hook-failure-workload-v1.yaml
  identity_check_base "$source_config"
  identity_require_command crictl
  identity_require_command journalctl
  identity_require_command kubectl
  identity_mode=cri
  identity_begin

  local suffix
  suffix=$(tr '[:upper:]' '[:lower:]' <<<"${identity_work##*.}")
  identity_k3s_namespace=mithril-manual-$suffix
  identity_k3s_fixture_root=/var/lib/mithril-manual-$suffix
  identity_k3s_shared_directory=$identity_k3s_fixture_root/shared
  identity_cleanup_functions+=(
    identity_cleanup_stock_hook_failure_case
    identity_cleanup_k3s_case
    identity_cleanup_prestart_case
  )
  install -d -m 700 -- "$identity_k3s_fixture_root" "$identity_k3s_shared_directory"
  [[ ! -e $identity_prestart_request_directory ]] || {
    echo "the prestart request directory already exists" >&2
    return 1
  }
  install -d -o root -g root -m 700 -- "$identity_prestart_request_directory"
  runtime_socket=$(jq -er '.container_runtime.socket_path' "$source_config")
  identity_runtime_endpoint=unix://$runtime_socket
}

identity_create_stock_hook_failure_pod() {
  local case_name=$1
  local workload=$identity_work/stock-hook-$case_name.yaml
  [[ $case_name == timeout || $case_name == mismatch || $case_name == missing-field ]] || {
    echo "invalid stock-hook failure case: $case_name" >&2
    return 1
  }
  sed \
    -e "s|MITHRIL_IDENTITY_STOCK_HOOK_NAMESPACE|$identity_k3s_namespace|g" \
    -e "s|MITHRIL_IDENTITY_STOCK_HOOK_CASE|$case_name|g" \
    -e "s|MITHRIL_IDENTITY_STOCK_HOOK_FIXTURE_ROOT|$identity_k3s_shared_directory|g" \
    "$identity_stock_hook_manifest_template" >"$workload"
  identity_k3s_namespace_created=true
  identity_k3s_runtime_class_created=true
  kubectl apply -f "$workload" >/dev/null
}

identity_wait_prestart_request() {
  local pod_name=$1
  local container_name=$2
  local attempt request count match
  for ((attempt = 0; attempt < 300; attempt++)); do
    match=
    count=0
    for request in "$identity_prestart_request_directory"/*.json; do
      [[ -f $request ]] || continue
      if jq -e \
        --arg namespace "$identity_k3s_namespace" \
        --arg pod "$pod_name" \
        --arg container "$container_name" \
        '.annotations["io.kubernetes.cri.sandbox-namespace"] == $namespace
         and .annotations["io.kubernetes.cri.sandbox-name"] == $pod
         and .annotations["io.kubernetes.cri.container-name"] == $container' \
        "$request" >/dev/null; then
        match=$request
        ((count += 1))
      fi
    done
    [[ $count -le 1 ]] || {
      echo "more than one prestart request matched $pod_name/$container_name" >&2
      return 1
    }
    if [[ $count -eq 1 ]]; then
      printf '%s\n' "$match"
      return 0
    fi
    sleep 0.1
  done
  echo "the $pod_name/$container_name prestart request did not arrive" >&2
  return 1
}

identity_prestart_binding_json() {
  local container_name=$1
  local container_kind=$2
  local binding_id=$3
  local execution_set_id=$4
  local pod_name=$5
  local profile_id=$6
  local profile_ref_id=$7
  local request container_id pid cgroup live_cgroup root_cgroup
  local container_json listed created_at generation image_digest pod_uid sandbox_id
  local -a live_pids

  request=$(identity_wait_prestart_request "$pod_name" "$container_name") || return
  container_id=${request##*/}
  container_id=${container_id%.json}
  pid=$(jq -er '.pid' "$request")
  cgroup=$(jq -er '.cgroup' "$request")
  [[ $container_id =~ ^[0-9a-f]{64}$ && $pid =~ ^[1-9][0-9]*$ \
    && $cgroup == /* && $cgroup != / ]] || {
    echo "the prestart request has an invalid identity" >&2
    return 1
  }
  root_cgroup=/sys/fs/cgroup${cgroup}
  live_cgroup=$(identity_cgroup_for_pid "$pid")
  [[ $root_cgroup == "$live_cgroup" ]] || {
    echo "the prestart request cgroup does not match PID $pid" >&2
    return 1
  }
  mapfile -t live_pids <"$root_cgroup/cgroup.procs"
  [[ ${#live_pids[@]} -eq 1 && ${live_pids[0]} == "$pid" ]] || {
    echo "the prestart cgroup does not contain only PID $pid" >&2
    return 1
  }
  jq -e --arg id "$container_id" --argjson pid "$pid" \
    '.stage == "prestart" and .state.id == $id and .state.pid == $pid
     and .annotations["io.kubernetes.cri.container-type"] == "container"' \
    "$request" >/dev/null || {
    echo "prestart OCI state does not match the live container identity" >&2
    return 1
  }

  container_json=$(crictl --runtime-endpoint "$identity_runtime_endpoint" \
    inspect "$container_id")
  listed=$(crictl --runtime-endpoint "$identity_runtime_endpoint" \
    ps -a --id "$container_id" -o json)
  created_at=$(jq -er '.status.createdAt' <<<"$container_json")
  if [[ $created_at =~ ^[1-9][0-9]*$ ]]; then
    generation=$created_at
  else
    generation=$(date --utc --date "$created_at" +%s%N)
  fi
  image_digest=$(jq -er '.status.imageRef | select(contains("sha256:"))' \
    <<<"$container_json")
  pod_uid=$(jq -er '.annotations["io.kubernetes.cri.sandbox-uid"]' "$request") || {
    echo "prestart request has no Pod UID" >&2
    return 1
  }
  sandbox_id=$(jq -er '.annotations["io.kubernetes.cri.sandbox-id"]' "$request")
  jq -e \
    --arg id "$container_id" \
    '.status.id == $id and .status.state == "CONTAINER_CREATED"
     and .info.pid == 0
     and (.info.runtimeSpec.linux.cgroupsPath | contains($id))' \
    <<<"$container_json" >/dev/null
  jq -e --arg sandbox "$sandbox_id" --arg pod_uid "$pod_uid" \
    '.containers | length == 1
     and .[0].podSandboxId == $sandbox
     and .[0].labels["io.kubernetes.pod.uid"] == $pod_uid' \
    <<<"$listed" >/dev/null

  jq -n \
    --arg binding_id "$binding_id" \
    --arg execution_set_id "$execution_set_id" \
    --arg container_id "$container_id" \
    --arg namespace "$identity_k3s_namespace" \
    --arg pod_uid "$pod_uid" \
    --arg sandbox_id "$sandbox_id" \
    --arg container_name "$container_name" \
    --arg image_digest "$image_digest" \
    --arg container_kind "$container_kind" \
    --arg profile_id "$profile_id" \
    --arg root_cgroup "$root_cgroup" \
    --arg request "$request" \
    --argjson generation "$generation" \
    --argjson profile_ref_id "$profile_ref_id" \
    --argjson pid "$pid" \
    '{
      pid: $pid,
      request: $request,
      binding: {
        binding_id: $binding_id,
        execution_set_id: $execution_set_id,
        protected_scope_id: "44444444-4444-4444-8444-444444444444",
        workload_selector_id: $container_name,
        profile_id: $profile_id,
        container_id: $container_id,
        namespace: $namespace,
        pod_uid: $pod_uid,
        sandbox_id: $sandbox_id,
        container_name: $container_name,
        image_digest: $image_digest,
        container_kind: $container_kind,
        container_generation: $generation,
        root_cgroup_path: $root_cgroup,
        lifecycle_generation: 1,
        active_profile_generation_ref_id: $profile_ref_id,
        initial_role_id: 1,
        external_role_id: 2,
        arm_initial_root: true
      }
    }'
}

identity_release_prestarts() {
  local index request release pid attempt
  for index in "${!identity_prestart_requests[@]}"; do
    request=${identity_prestart_requests[$index]}
    pid=$(jq -er '.pid' "$request")
    release=${request%.json}.release
    printf 'accepted:%s\n' "$pid" >"$release"
  done
  for request in "${identity_prestart_requests[@]}"; do
    release=${request%.json}.release
    for ((attempt = 0; attempt < 300; attempt++)); do
      [[ ! -e $request && ! -e $release ]] && break
      sleep 0.1
    done
    [[ ! -e $request && ! -e $release ]] || {
      echo "the prestart hook did not consume $release" >&2
      return 1
    }
  done
}

identity_cleanup_prestop_case() {
  if [[ -n $identity_prestop_release_fifo && -p $identity_prestop_release_fifo ]]; then
    timeout 2s dd if=/dev/null of="$identity_prestop_release_fifo" status=none || true
  fi
}

identity_cleanup_poststart_case() {
  local fifo request
  for fifo in "${identity_poststart_release_fifos[@]}"; do
    if [[ -p $fifo ]]; then
      timeout 2s dd if=/dev/null of="$fifo" status=none || true
    fi
  done
  for request in "${identity_prestart_requests[@]}"; do
    if [[ -f $request ]]; then
      printf 'rejected\n' >"${request%.json}.release"
    fi
  done
}

identity_settle_stock_hook_requests() {
  local request release
  [[ -d $identity_prestart_request_directory ]] || return 0
  for request in "$identity_prestart_request_directory"/*.json; do
    [[ -f $request ]] || continue
    release=${request%.json}.release
    printf 'rejected\n' >"$release"
  done
  sleep 0.5
  for request in "$identity_prestart_request_directory"/*.json; do
    [[ -f $request ]] || continue
    release=${request%.json}.release
    rm -f -- "$request" "$release"
  done
  for release in "$identity_prestart_request_directory"/*.release; do
    [[ -f $release ]] || continue
    rm -f -- "$release"
  done
}

identity_cleanup_stock_hook_failure_case() {
  identity_settle_stock_hook_requests
}

identity_cleanup_prestart_case() {
  local status=0
  if [[ -n $identity_prestart_request_directory ]]; then
    [[ $identity_prestart_request_directory == /run/mithril-identity-prestart ]] \
      || return 1
    rm -rf -- "$identity_prestart_request_directory" || status=1
  fi
  return "$status"
}

identity_cleanup_k3s_case() {
  local status=0
  if [[ $identity_k3s_namespace_created == true ]]; then
    kubectl -n "$identity_k3s_namespace" delete pod mithril-runtime \
      --ignore-not-found --wait=true --timeout=120s >/dev/null || status=1
    kubectl delete namespace "$identity_k3s_namespace" --wait=true --timeout=120s >/dev/null || status=1
  fi
  if [[ $identity_k3s_runtime_class_created == true ]]; then
    kubectl delete runtimeclass mithril --ignore-not-found \
      --wait=true --timeout=60s >/dev/null || status=1
  fi
  if [[ -n $identity_k3s_fixture_root ]]; then
    [[ $identity_k3s_fixture_root == /var/lib/mithril-manual-* ]] || return 1
    rm -rf -- "$identity_k3s_fixture_root" || status=1
  fi
  return "$status"
}

identity_prepare_auto() {
  if command -v docker >/dev/null && docker inspect "$2" >/dev/null 2>&1; then
    identity_prepare_docker "$1" "$2"
  else
    identity_prepare_cri "$1" "$2"
  fi
}

identity_start_node() {
  local controller_cgroup pid
  local -a command
  [[ -d $identity_cgroup_path ]] || {
    echo "configured container cgroup does not exist: $identity_cgroup_path" >&2
    return 1
  }
  command=("$identity_node" --config "$identity_config")
  for pid in "${identity_held_initial_pids[@]}"; do
    command+=(--held-initial-pid "$pid")
  done
  controller_cgroup=$(jq -er '.container_runtime.effect_controller_cgroup_path // empty' \
    "$identity_config")
  if [[ -n $controller_cgroup ]]; then
    [[ $controller_cgroup == "$identity_effect_controller_cgroup_path" \
      && ! -e $controller_cgroup ]] || {
      echo "effect controller cgroup is not an unused manual-owned path" >&2
      return 1
    }
    install -d -m 700 -- "$controller_cgroup"
    identity_effect_controller_cgroup_owned=true
    (
      printf '%s\n' "$BASHPID" >"$controller_cgroup/cgroup.procs"
      exec "${command[@]}"
    ) >>"$identity_work/mithril-node.log" 2>&1 &
  else
    "${command[@]}" >>"$identity_work/mithril-node.log" 2>&1 &
  fi
  identity_node_pid=$!

  for ((attempt = 0; attempt < 600; attempt++)); do
    # This final attached link signals that all map and link pins are ready.
    [[ -d $identity_pin_root/maps \
      && -e $identity_pin_root/links/erebor_sched_process_exit ]] && return 0
    if ! kill -0 "$identity_node_pid" 2>/dev/null; then
      echo "mithril-node exited:" >&2
      tail -n 30 "$identity_work/mithril-node.log" >&2
      return 1
    fi
    sleep 0.1
  done
  echo "mithril-node did not publish its pins within 60 seconds" >&2
  tail -n 30 "$identity_work/mithril-node.log" >&2
  return 1
}

identity_wait_for_initial_binding() {
  local snapshot=$identity_work/initial-root.json
  for ((attempt = 0; attempt < 300; attempt++)); do
    if "$identity_inspect" --pin-root "$identity_pin_root" task --host-pid "$identity_init_pid" \
      >"$snapshot" 2>/dev/null \
      && jq -e '.creator_task_cookie == null
                 and .root_class == "restored_or_unknown_root"
                 and .installed_role_class == "fail_closed_unknown"' \
        "$snapshot" >/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  echo "Mithril did not reconcile the Kubernetes Pod root before later entry" >&2
  return 1
}

identity_stop_node() {
  local pid=$identity_node_pid
  local status=0
  if [[ -n $pid ]] && kill -0 "$pid" 2>/dev/null; then
    kill -INT "$pid"
    for ((attempt = 0; attempt < 50; attempt++)); do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.1
    done
    if kill -0 "$pid" 2>/dev/null; then
      kill -TERM "$pid"
      for ((attempt = 0; attempt < 20; attempt++)); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
      done
    fi
    kill -0 "$pid" 2>/dev/null && kill -KILL "$pid"
    wait "$pid" 2>/dev/null || true
  fi
  identity_node_pid=
  if [[ $identity_effect_controller_cgroup_owned == true ]]; then
    [[ -d $identity_effect_controller_cgroup_path \
      && ! -s $identity_effect_controller_cgroup_path/cgroup.procs ]] \
      && rmdir -- "$identity_effect_controller_cgroup_path" \
      || status=1
    identity_effect_controller_cgroup_owned=false
  fi
  return "$status"
}

identity_inspect_task() {
  local name=$1
  local pid=$2
  "$identity_inspect" --pin-root "$identity_pin_root" task --host-pid "$pid" \
    | tee "$identity_work/$name.json"
}

identity_wait_for_task_snapshot() {
  local name=$1
  local pid=$2
  local attempt
  for ((attempt = 0; attempt < 300; attempt++)); do
    if "$identity_inspect" --pin-root "$identity_pin_root" task --host-pid "$pid" \
      >"$identity_work/$name.json" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  echo "Mithril did not publish the $name identity" >&2
  return 1
}

identity_read_binding_state() {
  local cgroup_path=$1
  local output=$2
  local root_cgroup_id value_hex key_hex byte
  local -a key_bytes=()

  root_cgroup_id=$(stat -c %i -- "$cgroup_path")
  for ((shift = 0; shift < 64; shift += 8)); do
    printf -v byte '%02x' "$(((root_cgroup_id >> shift) & 255))"
    key_bytes+=("$byte")
  done
  printf -v key_hex '%s' "${key_bytes[@]}"
  value_hex=$(bpftool -j map lookup pinned \
    "$identity_pin_root/maps/execution_set_bindings" \
    key hex "${key_bytes[@]}" \
    | jq -er '.value | map(sub("^0x"; "")) | join("")')
  [[ ${#value_hex} -ge 272 && ${value_hex:224:16} == "$key_hex" ]] || {
    echo "execution-set binding has an invalid cgroup identity" >&2
    return 1
  }
  jq -n \
    --argjson root_cgroup_id "$root_cgroup_id" \
    --arg binding_nonce "${value_hex:32:32}" \
    --arg root_cgroup_live_interval_id "${value_hex:240:32}" \
    '{
      root_cgroup_id: $root_cgroup_id,
      binding_nonce: $binding_nonce,
      root_cgroup_live_interval_id: $root_cgroup_live_interval_id
    }' >"$output"
}

identity_read_host_pid() {
  local prompt=$1
  read -r -p "$prompt" identity_read_pid
  [[ $identity_read_pid =~ ^[1-9][0-9]*$ && -d /proc/$identity_read_pid ]] || {
    echo "enter a live host PID" >&2
    return 1
  }
  identity_task_pids+=("$identity_read_pid")
}

identity_kubernetes_host_pid() {
  local namespace_pid=$1
  local host_pid mapped_pid
  [[ $namespace_pid =~ ^[1-9][0-9]*$ ]] || {
    echo "Kubernetes fixture did not report a valid namespace PID" >&2
    return 1
  }
  while read -r host_pid; do
    [[ -r /proc/$host_pid/status ]] || continue
    mapped_pid=$(awk '/^NSpid:/ {print $NF}' "/proc/$host_pid/status")
    if [[ $mapped_pid == "$namespace_pid" ]]; then
      printf '%s\n' "$host_pid"
      return 0
    fi
  done <"$identity_cgroup_path/cgroup.procs"
  return 1
}

identity_print_runtime_exec() {
  local command=$1
  if [[ $identity_mode == docker ]]; then
    printf "  docker exec %q sh -c %q\n" "$identity_container" "$command"
  else
    printf "  crictl --runtime-endpoint %q exec %q sh -c %q\n" \
      "$identity_runtime_endpoint" "$identity_container_id" "$command"
  fi
}

identity_assert_external() {
  jq -e '.creator_task_cookie == null
         and .root_class == "external_runtime_root"
         and .installed_role_class == "runtime_external_restricted"' \
    "$1" >/dev/null
}

identity_assert_initial() {
  jq -e '.creator_task_cookie == null
         and .root_class == "initial_container_root"
         and .installed_role_class == "initial_role"' \
    "$1" >/dev/null
}

identity_assert_recovered() {
  jq -e '.root_class == "restored_or_unknown_root"
         and .installed_role_class == "fail_closed_unknown"' \
    "$1" >/dev/null
}

identity_pass() {
  identity_success_message=$1
}
