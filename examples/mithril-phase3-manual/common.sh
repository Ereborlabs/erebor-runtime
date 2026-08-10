#!/usr/bin/env bash

# Shared policy setup for the small Phase 3 cases. Source this file.

phase3_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# Reuse the established real-node lifecycle and complete cleanup owner.
source "$phase3_directory/../mithril-phase2-manual/common.sh"

phase3_policy=target/debug/mithril-policy
phase3_socket=
phase3_scope=

phase3_prepare_docker() {
  phase2_prepare_docker "$1" "$2"
  [[ -x $phase3_policy ]] || {
    echo "build first: cargo build -p mithril-node --bins -p mithril-control --bin mithril-policy" >&2
    exit 2
  }
  local secret_path=$3
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
    "$phase2_config" >"$phase2_config.next"
  mv -- "$phase2_config.next" "$phase2_config"
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

