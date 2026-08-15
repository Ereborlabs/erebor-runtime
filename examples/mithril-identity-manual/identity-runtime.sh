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

identity_require_command() {
  command -v "$1" >/dev/null || {
    echo "missing required command: $1" >&2
    exit 2
  }
}

identity_check_base() {
  identity_source_config=$1
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

identity_begin() {
  trap identity_on_exit EXIT
  identity_work=$(mktemp -d /tmp/mithril-identity-manual.XXXXXX)
  identity_pin_root=/sys/fs/bpf/erebor-mithril-identity-manual-${identity_work##*.}
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
  identity_stop_node
  for cleanup in "${identity_cleanup_functions[@]}"; do
    "$cleanup" || cleanup_failed=1
  done
  [[ -z $identity_pin_root || ! -e $identity_pin_root ]] || rm -r -- "$identity_pin_root"
  [[ -z $identity_work || ! -e $identity_work ]] || rm -r -- "$identity_work"
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

identity_prepare_auto() {
  if command -v docker >/dev/null && docker inspect "$2" >/dev/null 2>&1; then
    identity_prepare_docker "$1" "$2"
  else
    identity_prepare_cri "$1" "$2"
  fi
}

identity_start_node() {
  [[ -d $identity_cgroup_path ]] || {
    echo "configured container cgroup does not exist: $identity_cgroup_path" >&2
    return 1
  }
  "$identity_node" --config "$identity_config" >>"$identity_work/mithril-node.log" 2>&1 &
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

identity_stop_node() {
  local pid=$identity_node_pid
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
}

identity_inspect_task() {
  local name=$1
  local pid=$2
  "$identity_inspect" --pin-root "$identity_pin_root" task --host-pid "$pid" \
    | tee "$identity_work/$name.json"
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

identity_assert_recovered() {
  jq -e '.root_class == "restored_or_unknown_root"
         and .installed_role_class == "fail_closed_unknown"' \
    "$1" >/dev/null
}

identity_pass() {
  identity_success_message=$1
}
