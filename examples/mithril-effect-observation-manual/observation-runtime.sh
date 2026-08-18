#!/usr/bin/env bash

# Shared policy setup for the effect-observation cases. Source this file.

observation_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
observation_repository=$(cd -- "$observation_directory/../.." && pwd)
observation_policy_fixture_directory=${MITHRIL_POLICY_FIXTURE_DIRECTORY:-$observation_repository/crates/mithril-e2e/fixtures/mithril-policy}
observation_policy_mode=${observation_policy_mode:-OBSERVE}
observation_policy_source=${observation_policy_source:-$observation_policy_fixture_directory/observe-policy-v1.yaml}
# Reuse the established real-node lifecycle and complete cleanup owner.
source "$observation_directory/../mithril-identity-manual/identity-runtime.sh"

observation_policy=${MITHRIL_BIN_DIRECTORY:-target/debug}/mithril-policy
observation_socket=
observation_scope=
observation_identity_config=
observation_final_config=
observation_probe_ready=
observation_probe_release=
observation_probe_ready_host=
observation_probe_release_host=
observation_probe_marker_host=
observation_probe_pid=
observation_probe_host_pid=
observation_extra_exact_path=
observation_extra_exact_key=
observation_extra_exact_class=

observation_prepare_docker() {
  identity_prepare_docker "$1" "$2"
  observation_configure_secret "$3"
}

observation_prepare_cri() {
  [[ $# -eq 5 ]] || {
    echo "CRI observation needs a host and container shared directory" >&2
    return 2
  }
  identity_prepare_cri "$1" "$2"
  observation_configure_secret "$3"
  observation_configure_shared_directory cri "$4" "$5"
}

observation_prepare_k3s() {
  identity_prepare_k3s_case "$1"
  observation_configure_secret "$identity_k3s_secret_path"
  observation_configure_shared_directory cri \
    "$identity_k3s_shared_directory" "$identity_k3s_container_shared_directory"
}

observation_configure_shared_directory() {
  [[ $# -eq 3 ]] || {
    echo "observation needs a runtime and host/container shared directories" >&2
    return 2
  }
  local runtime=$1
  local host_shared_directory=$2
  local container_shared_directory=$3
  [[ -d $host_shared_directory && -w $host_shared_directory ]] || {
    echo "the host shared directory must exist and be writable" >&2
    return 2
  }
  [[ $container_shared_directory == /* ]] || {
    echo "the container shared directory must be absolute" >&2
    return 2
  }

  local probe_name marker container_marker
  probe_name=.mithril-effect-observation-${identity_work##*.}-$$
  marker=$probe_name.marker
  container_marker=$container_shared_directory/$marker
  observation_probe_ready=$container_shared_directory/$probe_name.ready
  observation_probe_release=$container_shared_directory/$probe_name.release
  observation_probe_ready_host=$host_shared_directory/$probe_name.ready
  observation_probe_release_host=$host_shared_directory/$probe_name.release
  observation_probe_marker_host=$host_shared_directory/$probe_name.marker

  umask 077
  printf '%s\n' "$marker" >"$observation_probe_marker_host"
  if [[ $runtime == docker ]]; then
    docker exec "$identity_container" sh -ec '
      IFS= read -r observed < "$1"
      [ "$observed" = "$2" ]
    ' sh "$container_marker" "$marker" || {
      echo "the Docker shared directory is not mounted at the requested container path" >&2
      return 1
    }
  elif [[ $runtime == cri ]]; then
    crictl --runtime-endpoint "$identity_runtime_endpoint" \
      exec "$identity_container_id" sh -ec '
        IFS= read -r observed < "$1"
        [ "$observed" = "$2" ]
      ' sh "$container_marker" "$marker" || {
      echo "the CRI shared directory is not mounted at the requested container path" >&2
      return 1
    }
  else
    echo "unsupported shared-directory runtime: $runtime" >&2
    return 1
  fi
  rm -f -- "$observation_probe_marker_host"
  observation_probe_marker_host=
}

observation_configure_secret() {
  identity_require_command timeout
  [[ -x $observation_policy ]] || {
    echo "build first: cargo build -p mithril-node --bins -p mithril-control --bin mithril-policy" >&2
    exit 2
  }
  local secret_path=$1
  [[ $secret_path == /* && -f /proc/$identity_init_pid/root$secret_path ]] || {
    echo "secret path must be an existing absolute container file: $secret_path" >&2
    exit 2
  }

  observation_scope=$(sed -n 's/^0:://p' /proc/self/cgroup)
  [[ -n $observation_scope ]] || {
    echo "the manual client needs a unified cgroup v2 scope" >&2
    exit 2
  }
  observation_socket=$identity_work/observation.sock
  observation_probe_ready=/tmp/mithril-effect-observation-probe-$$.ready
  observation_probe_release=/tmp/mithril-effect-observation-probe-$$.release
  observation_identity_config=$identity_work/identity-node.json
  observation_final_config=$identity_work/observe-node.json
  local artifact=$identity_work/profile.json
  local policy_source=$observation_policy_source
  if [[ $observation_policy_mode == PROTECT \
    && $policy_source == "$observation_policy_fixture_directory/observe-policy-v1.yaml" ]]; then
    policy_source=$identity_work/protect-observe-policy-v1.yaml
    sed -e 's/desired_profile_mode: OBSERVE/desired_profile_mode: PROTECT/' \
      -e 's/operation_ids: \[OPEN_READ\]/operation_ids: [OPEN_READ, READ, MMAP_READ]/' \
      "$observation_policy_fixture_directory/observe-policy-v1.yaml" >"$policy_source"
  fi
  "$observation_policy" compile \
    --source "$policy_source" \
    --seal-request "$observation_policy_fixture_directory/observe-profile-seal-request.json" \
    --signing-key "$observation_policy_fixture_directory/test-signing-key.hex" \
    --output "$artifact" >/dev/null
  "$observation_policy" verify \
    --artifact "$artifact" \
    --public-key "$observation_policy_fixture_directory/test-public-key.hex" >/dev/null

  local inode_generation object
  inode_generation=$(lsattr -v "/proc/$identity_init_pid/root$secret_path" | awk 'NR == 1 {print $1}')
  [[ $inode_generation =~ ^[1-9][0-9]*$ ]] || {
    echo "filesystem did not expose a nonzero inode generation through lsattr -v" >&2
    exit 2
  }
  object=$identity_work/exact-file-object.json
  "$identity_inspect" file-object \
    --root-pid "$identity_init_pid" \
    --path "$secret_path" \
    --profile-generation 1 \
    --exact-object-key 7 \
    --object-class MANUAL_SECRET \
    --inode-generation "$inode_generation" >"$object"

  jq --arg artifact "$artifact" \
    --arg public_key "$observation_policy_fixture_directory/test-public-key.hex" \
    --arg socket "$observation_socket" \
    --arg scope "$observation_scope" \
    --slurpfile object "$object" \
    '.workload_bindings[0].profile_id = "11111111-1111-4111-8111-111111111111"
     | .workload_bindings[0].protected_scope_id = "33333333-3333-4333-8333-333333333333"
     | .workload_bindings[0].execution_set_id = "44444444-4444-4444-8444-444444444444"
     | .workload_bindings[0].initial_role_id = 1
     | .workload_bindings[0].external_role_id = 2
     | .policy_candidates = [{artifact_path: $artifact, public_key_path: $public_key}]
     | .exact_file_objects = $object
     | .runtime_observation = {socket_path: $socket, allowed_uid: 0, cgroup_scope: $scope}' \
    "$identity_config" >"$observation_final_config"
  if [[ -n $observation_extra_exact_path ]]; then
    [[ $observation_extra_exact_path == /* \
      && $observation_extra_exact_key =~ ^[1-9][0-9]*$ \
      && -n $observation_extra_exact_class \
      && -f /proc/$identity_init_pid/root$observation_extra_exact_path ]] || {
      echo "extra exact-file fixture is incomplete" >&2
      exit 2
    }
    local extra_generation extra_object
    extra_generation=$(lsattr -v "/proc/$identity_init_pid/root$observation_extra_exact_path" \
      | awk 'NR == 1 {print $1}')
    [[ $extra_generation =~ ^[1-9][0-9]*$ ]] || {
      echo "extra exact file has no nonzero inode generation" >&2
      exit 2
    }
    extra_object=$identity_work/extra-exact-file-object.json
    "$identity_inspect" file-object \
      --root-pid "$identity_init_pid" \
      --path "$observation_extra_exact_path" \
      --profile-generation 1 \
      --exact-object-key "$observation_extra_exact_key" \
      --object-class "$observation_extra_exact_class" \
      --inode-generation "$extra_generation" >"$extra_object"
    jq --slurpfile extra "$extra_object" '.exact_file_objects += $extra' \
      "$observation_final_config" >"$observation_final_config.extra"
    mv -- "$observation_final_config.extra" "$observation_final_config"
  fi
  jq '.policy_candidates = []
      | .exact_file_objects = []
      | .runtime_observation = null' \
    "$observation_final_config" >"$observation_identity_config"
  cp -- "$observation_final_config" "$identity_config"
  identity_cleanup_functions+=(observation_cleanup_probe_files)
  if [[ $identity_mode == docker ]]; then
    local docker_host_shared=${MITHRIL_MANUAL_DOCKER_HOST_SHARED_DIRECTORY:-}
    local docker_container_shared=${MITHRIL_MANUAL_DOCKER_CONTAINER_SHARED_DIRECTORY:-}
    [[ -n $docker_host_shared && -n $docker_container_shared ]] || {
      echo "Docker observation needs MITHRIL_MANUAL_DOCKER_HOST_SHARED_DIRECTORY and MITHRIL_MANUAL_DOCKER_CONTAINER_SHARED_DIRECTORY" >&2
      exit 2
    }
    observation_configure_shared_directory docker \
      "$docker_host_shared" "$docker_container_shared"
  fi
}

# Start the probe while effect observation is disabled, then recover the same
# pinned identity state with the signed observe candidate before releasing it.
observation_preload_probe() {
  observation_begin_preload
  if [[ $identity_mode == docker ]]; then
    docker exec --env "MITHRIL_MANUAL_RELEASE=$observation_probe_release" \
      "$identity_container" "$@" &
  else
    crictl --runtime-endpoint "$identity_runtime_endpoint" \
      exec "$identity_container_id" env \
      "MITHRIL_MANUAL_RELEASE=$observation_probe_release" "$@" &
  fi
  observation_probe_pid=$!
  observation_finish_preload false
}

observation_preload_nsenter_probe() {
  identity_require_command nsenter
  observation_begin_preload
  MITHRIL_MANUAL_RELEASE=$observation_probe_release \
    nsenter -t "$identity_init_pid" -m -r -- "$@" &
  observation_probe_pid=$!
  observation_finish_preload true
}

observation_begin_preload() {
  local host_ready=${observation_probe_ready_host:-/proc/$identity_init_pid/root$observation_probe_ready}
  local host_release=${observation_probe_release_host:-/proc/$identity_init_pid/root$observation_probe_release}
  rm -f -- "$host_ready"
  rm -f -- "$host_release"
  cp -- "$observation_identity_config" "$identity_config"
  identity_start_node
}

observation_finish_preload() {
  local move_to_cgroup=$1
  local host_ready=${observation_probe_ready_host:-/proc/$identity_init_pid/root$observation_probe_ready}
  identity_task_pids+=("$observation_probe_pid")
  for ((attempt = 0; attempt < 50; attempt++)); do
    [[ -e $host_ready ]] && break
    if ! kill -0 "$observation_probe_pid" 2>/dev/null; then
      echo "preloaded effect-observation probe exited before becoming ready" >&2
      return 1
    fi
    sleep 0.1
  done
  [[ -e $host_ready ]] || {
    echo "preloaded effect-observation probe did not become ready" >&2
    return 1
  }
  local namespace_pid
  namespace_pid=$(<"$host_ready")
  [[ $namespace_pid =~ ^[1-9][0-9]*$ ]] || {
    echo "preloaded effect-observation probe wrote an invalid namespace PID" >&2
    return 1
  }
  if [[ $move_to_cgroup == true ]]; then
    observation_probe_host_pid=$namespace_pid
    printf '%s\n' "$observation_probe_host_pid" >"$identity_cgroup_path/cgroup.procs"
  else
    for host_pid in $(<"$identity_cgroup_path/cgroup.procs"); do
      [[ -r /proc/$host_pid/status ]] || continue
      local mapped_pid
      mapped_pid=$(awk '/^NSpid:/ {print $NF}' "/proc/$host_pid/status")
      if [[ $mapped_pid == "$namespace_pid" ]]; then
        observation_probe_host_pid=$host_pid
        break
      fi
    done
  fi
  [[ -n $observation_probe_host_pid ]] || {
    echo "could not map the preloaded probe to its host PID" >&2
    return 1
  }
  identity_stop_node
  cp -- "$observation_final_config" "$identity_config"
  identity_start_node
  observation_wait_for_runtime_socket
}

observation_wait_for_runtime_socket() {
  for ((attempt = 0; attempt < 100; attempt++)); do
    [[ -S $observation_socket ]] && return 0
    if ! kill -0 "$identity_node_pid" 2>/dev/null; then
      echo "mithril-node exited before publishing the observation socket" >&2
      tail -n 30 "$identity_work/mithril-node.log" >&2
      return 1
    fi
    sleep 0.1
  done
  echo "mithril-node did not publish the observation socket within 10 seconds" >&2
  tail -n 30 "$identity_work/mithril-node.log" >&2
  return 1
}

observation_open_probe_gate() {
  local host_release=${observation_probe_release_host:-/proc/$identity_init_pid/root$observation_probe_release}
  timeout 5s sh -c 'printf 1 >"$1"' sh "$host_release"
}

observation_release_probe() {
  observation_open_probe_gate
  if ! wait "$observation_probe_pid"; then
    observation_probe_pid=
    return 1
  fi
  observation_probe_pid=
  observation_probe_host_pid=
}

observation_cleanup_probe_files() {
  [[ -z $observation_probe_pid ]] || kill -TERM "$observation_probe_pid" 2>/dev/null
  [[ -z $observation_probe_host_pid ]] || kill -TERM "$observation_probe_host_pid" 2>/dev/null
  [[ -z $observation_probe_marker_host ]] || rm -f -- "$observation_probe_marker_host"
  [[ -z $observation_probe_ready ]] || rm -f -- "${observation_probe_ready_host:-/proc/$identity_init_pid/root$observation_probe_ready}"
  [[ -z $observation_probe_release ]] || rm -f -- "${observation_probe_release_host:-/proc/$identity_init_pid/root$observation_probe_release}"
}

observation_wait_for_observation() {
  local expected=$1
  local output=$2
  for ((attempt = 0; attempt < 50; attempt++)); do
    "$identity_inspect" effects --socket-path "$observation_socket" \
      --cgroup-scope "$observation_scope" >"$output"
    grep -q "$expected" "$output" && return 0
    sleep 0.1
  done
  cat "$output" >&2
  echo "observation did not contain: $expected" >&2
  return 1
}

observation_health_field() {
  local field=$1
  local input=$2
  sed -n "1s/.*${field}=\\([0-9][0-9]*\\).*/\\1/p" "$input"
}
