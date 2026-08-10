#!/usr/bin/env bash

# Shared policy setup for the small Phase 3 cases. Source this file.

phase3_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# Reuse the established real-node lifecycle and complete cleanup owner.
source "$phase3_directory/../mithril-phase2-manual/common.sh"

phase3_policy=target/debug/mithril-policy
phase3_socket=
phase3_scope=
phase3_identity_config=
phase3_final_config=
phase3_probe_ready=
phase3_probe_pid=
phase3_probe_host_pid=

phase3_prepare_docker() {
  phase2_prepare_docker "$1" "$2"
  phase3_configure_secret "$3"
}

phase3_prepare_cri() {
  phase2_prepare_cri "$1" "$2"
  phase3_configure_secret "$3"
}

phase3_configure_secret() {
  [[ -x $phase3_policy ]] || {
    echo "build first: cargo build -p mithril-node --bins -p mithril-control --bin mithril-policy" >&2
    exit 2
  }
  local secret_path=$1
  [[ $secret_path == /* && -f /proc/$phase2_init_pid/root$secret_path ]] || {
    echo "secret path must be an existing absolute container file: $secret_path" >&2
    exit 2
  }

  phase3_scope=$(sed -n 's/^0:://p' /proc/self/cgroup)
  [[ -n $phase3_scope ]] || {
    echo "the manual client needs a unified cgroup v2 scope" >&2
    exit 2
  }
  phase3_socket=$phase2_work/observation.sock
  phase3_probe_ready=/tmp/mithril-phase3-probe-$$.ready
  phase3_identity_config=$phase2_work/identity-node.json
  phase3_final_config=$phase2_work/observe-node.json
  jq '.policy_candidates = []
      | .exact_file_objects = []
      | .runtime_observation = null' \
    "$phase2_config" >"$phase3_identity_config"
  local artifact=$phase2_work/profile.json
  "$phase3_policy" compile \
    --source "$phase3_directory/policy-v1.yaml" \
    --seal-request "$phase3_directory/seal-request.json" \
    --signing-key "$phase3_directory/test-signing-key.hex" \
    --output "$artifact"
  "$phase3_policy" verify \
    --artifact "$artifact" \
    --public-key "$phase3_directory/test-public-key.hex"

  local inode_generation object
  inode_generation=$(lsattr -v "/proc/$phase2_init_pid/root$secret_path" | awk 'NR == 1 {print $1}')
  [[ $inode_generation =~ ^[1-9][0-9]*$ ]] || {
    echo "filesystem did not expose a nonzero inode generation through lsattr -v" >&2
    exit 2
  }
  object=$phase2_work/exact-file-object.json
  "$phase2_inspect" file-object \
    --root-pid "$phase2_init_pid" \
    --path "$secret_path" \
    --profile-generation 1 \
    --exact-object-key 7 \
    --object-class MANUAL_SECRET \
    --inode-generation "$inode_generation" >"$object"

  jq --arg artifact "$artifact" \
    --arg public_key "$phase3_directory/test-public-key.hex" \
    --arg socket "$phase3_socket" \
    --arg scope "$phase3_scope" \
    --slurpfile object "$object" \
    '.workload_bindings[0].profile_id = "11111111-1111-4111-8111-111111111111"
     | .workload_bindings[0].protected_scope_id = "33333333-3333-4333-8333-333333333333"
     | .workload_bindings[0].execution_set_id = "44444444-4444-4444-8444-444444444444"
     | .workload_bindings[0].initial_role_id = 1
     | .workload_bindings[0].external_role_id = 2
     | .policy_candidates = [{artifact_path: $artifact, public_key_path: $public_key}]
     | .exact_file_objects = $object
     | .runtime_observation = {socket_path: $socket, allowed_uid: 0, cgroup_scope: $scope}' \
    "$phase2_config" >"$phase3_final_config"
  cp -- "$phase3_final_config" "$phase2_config"
  phase2_cleanup_functions+=(phase3_cleanup_probe_files)
}

# Start the probe while effect observation is disabled, then recover the same
# pinned identity state with the signed observe candidate before releasing it.
phase3_preload_probe() {
  phase3_begin_preload
  if [[ $phase2_mode == docker ]]; then
    docker exec "$phase2_container" "$@" &
  else
    crictl --runtime-endpoint "$phase2_runtime_endpoint" \
      exec "$phase2_container_id" "$@" &
  fi
  phase3_probe_pid=$!
  phase3_finish_preload false
}

phase3_preload_nsenter_probe() {
  phase2_require_command nsenter
  phase3_begin_preload
  nsenter -t "$phase2_init_pid" -m -r -- "$@" &
  phase3_probe_pid=$!
  phase3_finish_preload true
}

phase3_begin_preload() {
  local host_ready=/proc/$phase2_init_pid/root$phase3_probe_ready
  rm -f -- "$host_ready"
  cp -- "$phase3_identity_config" "$phase2_config"
  phase2_start_node
}

phase3_finish_preload() {
  local move_to_cgroup=$1
  local host_ready=/proc/$phase2_init_pid/root$phase3_probe_ready
  phase2_task_pids+=("$phase3_probe_pid")
  for ((attempt = 0; attempt < 50; attempt++)); do
    [[ -e $host_ready ]] && break
    if ! kill -0 "$phase3_probe_pid" 2>/dev/null; then
      echo "preloaded Phase 3 probe exited before becoming ready" >&2
      return 1
    fi
    sleep 0.1
  done
  [[ -e $host_ready ]] || {
    echo "preloaded Phase 3 probe did not become ready" >&2
    return 1
  }
  local namespace_pid
  namespace_pid=$(<"$host_ready")
  [[ $namespace_pid =~ ^[1-9][0-9]*$ ]] || {
    echo "preloaded Phase 3 probe wrote an invalid namespace PID" >&2
    return 1
  }
  if [[ $move_to_cgroup == true ]]; then
    phase3_probe_host_pid=$namespace_pid
    printf '%s\n' "$phase3_probe_host_pid" >"$phase2_cgroup_path/cgroup.procs"
  else
    for host_pid in $(<"$phase2_cgroup_path/cgroup.procs"); do
      [[ -r /proc/$host_pid/status ]] || continue
      local mapped_pid
      mapped_pid=$(awk '/^NSpid:/ {print $NF}' "/proc/$host_pid/status")
      if [[ $mapped_pid == "$namespace_pid" ]]; then
        phase3_probe_host_pid=$host_pid
        break
      fi
    done
  fi
  [[ -n $phase3_probe_host_pid ]] || {
    echo "could not map the preloaded probe to its host PID" >&2
    return 1
  }
  phase2_stop_node
  cp -- "$phase3_final_config" "$phase2_config"
  phase2_start_node
  for ((attempt = 0; attempt < 100; attempt++)); do
    [[ -S $phase3_socket ]] && return 0
    if ! kill -0 "$phase2_node_pid" 2>/dev/null; then
      echo "mithril-node exited before publishing the observation socket" >&2
      tail -n 30 "$phase2_work/mithril-node.log" >&2
      return 1
    fi
    sleep 0.1
  done
  echo "mithril-node did not publish the observation socket within 10 seconds" >&2
  tail -n 30 "$phase2_work/mithril-node.log" >&2
  return 1
}

phase3_release_probe() {
  kill -USR1 "$phase3_probe_host_pid"
  wait "$phase3_probe_pid"
  phase3_probe_pid=
  phase3_probe_host_pid=
}

phase3_cleanup_probe_files() {
  [[ -z $phase3_probe_pid ]] || kill -TERM "$phase3_probe_pid" 2>/dev/null
  [[ -z $phase3_probe_host_pid ]] || kill -TERM "$phase3_probe_host_pid" 2>/dev/null
  [[ -z $phase3_probe_ready ]] || rm -f -- "/proc/$phase2_init_pid/root$phase3_probe_ready"
}

phase3_wait_for_observation() {
  local expected=$1
  local output=$2
  for ((attempt = 0; attempt < 50; attempt++)); do
    "$phase2_inspect" effects --socket-path "$phase3_socket" \
      --cgroup-scope "$phase3_scope" >"$output"
    grep -q "$expected" "$output" && return 0
    sleep 0.1
  done
  cat "$output" >&2
  echo "observation did not contain: $expected" >&2
  return 1
}

phase3_health_field() {
  local field=$1
  local input=$2
  sed -n "1s/.*${field}=\\([0-9][0-9]*\\).*/\\1/p" "$input"
}
