#!/usr/bin/env bash

# Shared real-node startup and cleanup for the small Phase 2 case scripts.
# Source this file; do not run it directly.

phase2_node=target/debug/mithril-node
phase2_inspect=target/debug/mithril-inspect
phase2_node_pid=
phase2_task_pids=()
phase2_cleanup_functions=()
phase2_success_message=
phase2_work=
phase2_pin_root=

phase2_require_command() {
  command -v "$1" >/dev/null || {
    echo "missing required command: $1" >&2
    exit 2
  }
}

phase2_check_base() {
  phase2_source_config=$1
  phase2_require_command jq
  [[ $(id -u) -eq 0 ]] || {
    echo "run this example with sudo" >&2
    exit 2
  }
  [[ -x $phase2_node && -x $phase2_inspect ]] || {
    echo "build first: cargo build -p mithril-node --bins" >&2
    exit 2
  }
  [[ -f $phase2_source_config ]] || {
    echo "node config does not exist: $phase2_source_config" >&2
    exit 2
  }
}

phase2_begin() {
  trap phase2_on_exit EXIT
  phase2_work=$(mktemp -d /tmp/mithril-phase2-manual.XXXXXX)
  phase2_pin_root=$(mktemp -d /sys/fs/bpf/erebor-mithril-phase2-manual.XXXXXX)
  phase2_config=$phase2_work/node.json
  phase2_state=$phase2_work/state
  phase2_lease=$phase2_work/owner.lock
}

phase2_cgroup_for_pid() {
  local hierarchy controllers path
  while IFS=: read -r hierarchy controllers path; do
    if [[ $hierarchy == 0 && -z $controllers ]]; then
      printf '/sys/fs/cgroup%s\n' "$path"
      return
    fi
  done <"/proc/$1/cgroup"
  return 1
}

phase2_on_exit() {
  local status=$?
  local cleanup_failed=0
  trap - EXIT
  set +e
  for pid in "${phase2_task_pids[@]}"; do
    kill -TERM "$pid" 2>/dev/null
  done
  phase2_stop_node
  for cleanup in "${phase2_cleanup_functions[@]}"; do
    "$cleanup" || cleanup_failed=1
  done
  [[ -z $phase2_pin_root || ! -e $phase2_pin_root ]] || rm -r -- "$phase2_pin_root"
  [[ -z $phase2_work || ! -e $phase2_work ]] || rm -r -- "$phase2_work"
  [[ (-z $phase2_pin_root || ! -e $phase2_pin_root) \
    && (-z $phase2_work || ! -e $phase2_work) ]] || cleanup_failed=1

  if [[ $cleanup_failed -ne 0 ]]; then
    echo "Phase 2 manual cleanup failed" >&2
    status=1
  elif [[ $status -eq 0 && -n $phase2_success_message ]]; then
    echo
    echo "$phase2_success_message"
    echo "Mithril, tasks, pins, state, lease, config, and logs removed."
  fi
  exit "$status"
}

phase2_prepare_docker() {
  phase2_check_base "$1"
  phase2_require_command docker
  phase2_mode=docker
  phase2_container=$2
  docker inspect "$phase2_container" >/dev/null
  phase2_begin

  phase2_container_id=$(docker inspect --format '{{.Id}}' "$phase2_container")
  phase2_init_pid=$(docker inspect --format '{{.State.Pid}}' "$phase2_container")
  local container_name image_digest generation
  container_name=$(docker inspect --format '{{.Name}}' "$phase2_container")
  container_name=${container_name#/}
  image_digest=$(docker inspect --format '{{.Image}}' "$phase2_container")
  generation=$(stat -c %Y "/proc/$phase2_init_pid")
  phase2_cgroup_path=$(phase2_cgroup_for_pid "$phase2_init_pid")
  [[ -n $phase2_cgroup_path ]] || {
    echo "Docker container is not using cgroup v2" >&2
    exit 2
  }

  jq --arg state "$phase2_state" \
    --arg pin_root "$phase2_pin_root" \
    --arg lease "$phase2_lease" \
    --arg id "$phase2_container_id" \
    --arg name "$container_name" \
    --arg image "$image_digest" \
    --arg cgroup "$phase2_cgroup_path" \
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
       }]' "$phase2_source_config" >"$phase2_config"
}

phase2_prepare_cri() {
  phase2_check_base "$1"
  phase2_require_command crictl
  phase2_mode=cri
  phase2_container_id=$2
  phase2_container=$phase2_container_id
  phase2_begin

  local matching_bindings runtime_socket
  matching_bindings=$(jq --arg id "$phase2_container_id" \
    '[.workload_bindings[] | select(.container_id == $id)] | length' \
    "$phase2_source_config")
  [[ $matching_bindings -eq 1 ]] || {
    echo "node config must contain exactly one binding for $phase2_container_id" >&2
    exit 2
  }
  jq --arg id "$phase2_container_id" \
    --arg state "$phase2_state" \
    --arg pin_root "$phase2_pin_root" \
    --arg lease "$phase2_lease" \
    '.state_directory = $state
     | .interceptor.pin_root = $pin_root
     | .interceptor.lease_path = $lease
     | .runtime_observation = null
     | .workload_bindings = [.workload_bindings[] | select(.container_id == $id)]
     | .workload_bindings[0].arm_initial_root = false
     | del(.workload_bindings[0].root_cgroup_path)' \
    "$phase2_source_config" >"$phase2_config"

  runtime_socket=$(jq -er '.container_runtime.socket_path' "$phase2_config")
  phase2_runtime_endpoint="unix://$runtime_socket"
  phase2_init_pid=$(crictl --runtime-endpoint "$phase2_runtime_endpoint" \
    inspect "$phase2_container_id" | jq -er '.info.pid')
  phase2_cgroup_path=$(phase2_cgroup_for_pid "$phase2_init_pid")
}

phase2_prepare_auto() {
  if command -v docker >/dev/null && docker inspect "$2" >/dev/null 2>&1; then
    phase2_prepare_docker "$1" "$2"
  else
    phase2_prepare_cri "$1" "$2"
  fi
}

phase2_start_node() {
  [[ -d $phase2_cgroup_path ]] || {
    echo "configured container cgroup does not exist: $phase2_cgroup_path" >&2
    return 1
  }
  "$phase2_node" --config "$phase2_config" >>"$phase2_work/mithril-node.log" 2>&1 &
  phase2_node_pid=$!

  for ((attempt = 0; attempt < 100; attempt++)); do
    [[ -d $phase2_pin_root/maps && -d $phase2_pin_root/links ]] && return 0
    if ! kill -0 "$phase2_node_pid" 2>/dev/null; then
      echo "mithril-node exited:" >&2
      tail -n 30 "$phase2_work/mithril-node.log" >&2
      return 1
    fi
    sleep 0.1
  done
  echo "mithril-node did not publish its pins within 10 seconds" >&2
  tail -n 30 "$phase2_work/mithril-node.log" >&2
  return 1
}

phase2_stop_node() {
  local pid=$phase2_node_pid
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
  phase2_node_pid=
}

phase2_inspect_task() {
  local name=$1
  local pid=$2
  "$phase2_inspect" --pin-root "$phase2_pin_root" task --host-pid "$pid" \
    | tee "$phase2_work/$name.json"
}

phase2_read_host_pid() {
  local prompt=$1
  read -r -p "$prompt" phase2_read_pid
  [[ $phase2_read_pid =~ ^[1-9][0-9]*$ && -d /proc/$phase2_read_pid ]] || {
    echo "enter a live host PID" >&2
    return 1
  }
  phase2_task_pids+=("$phase2_read_pid")
}

phase2_print_runtime_exec() {
  local command=$1
  if [[ $phase2_mode == docker ]]; then
    printf "  docker exec %q sh -c %q\n" "$phase2_container" "$command"
  else
    printf "  crictl --runtime-endpoint %q exec %q sh -c %q\n" \
      "$phase2_runtime_endpoint" "$phase2_container_id" "$command"
  fi
}

phase2_assert_external() {
  jq -e '.creator_task_cookie == null
         and .root_class == "external_runtime_root"
         and .installed_role_class == "runtime_external_restricted"' \
    "$1" >/dev/null
}

phase2_assert_recovered() {
  jq -e '.root_class == "restored_or_unknown_root"
         and .installed_role_class == "fail_closed_unknown"' \
    "$1" >/dev/null
}

phase2_pass() {
  phase2_success_message=$1
}
