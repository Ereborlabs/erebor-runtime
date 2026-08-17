#!/usr/bin/env bash

# Local enforcement promotes the established signed observation fixture to
# PROTECT. The identity and observation owner supplies lifecycle and EXIT cleanup.
enforcement_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
enforcement_repository=$(cd -- "$enforcement_directory/../.." && pwd)
enforcement_policy_fixture_directory=${MITHRIL_POLICY_FIXTURE_DIRECTORY:-$enforcement_repository/crates/mithril-e2e/fixtures/mithril-policy}
observation_policy_mode=PROTECT
observation_policy_source=$enforcement_policy_fixture_directory/protect-policy-v1.yaml
source "$enforcement_directory/../mithril-effect-observation-manual/observation-runtime.sh"

enforcement_benign_path=
enforcement_exception_lifetime_ns=${enforcement_exception_lifetime_ns:-}

enforcement_configure_policy_source() {
  [[ -n $enforcement_exception_lifetime_ns ]] || return 0
  [[ $enforcement_exception_lifetime_ns =~ ^[1-9][0-9]*$ ]] || {
    echo "enforcement_exception_lifetime_ns must be a positive integer" >&2
    return 2
  }
  observation_policy_source=$identity_work/local-protect-policy-v1.yaml
  sed "s/maximum_lifetime_ns: 3600000000000/maximum_lifetime_ns: $enforcement_exception_lifetime_ns/" \
    "$enforcement_policy_fixture_directory/protect-policy-v1.yaml" >"$observation_policy_source"
}

enforcement_configure_benign_control() {
  [[ $enforcement_benign_path == /* \
    && -f /proc/$identity_init_pid/root$enforcement_benign_path ]] || {
    echo "benign path must be an existing absolute container file" >&2
    return 2
  }
  observation_extra_exact_path=$enforcement_benign_path
  observation_extra_exact_key=8
  observation_extra_exact_class=MANUAL_BENIGN
}

enforcement_add_device_object() {
  local path=$1
  local key=$2
  local object_class=$3
  local device_class=$4
  [[ $path == /* && -c /proc/$identity_init_pid/root$path ]] || {
    echo "device path must name a character device in the container: $path" >&2
    return 2
  }
  local object=$identity_work/exact-device-$key.json
  "$identity_inspect" file-object \
    --root-pid "$identity_init_pid" \
    --path "$path" \
    --profile-generation 1 \
    --exact-object-key "$key" \
    --object-class "$object_class" \
    --inode-generation 0 \
    --device-class "$device_class" >"$object"
  jq --slurpfile object "$object" '.exact_file_objects += $object' \
    "$observation_final_config" >"$observation_final_config.device"
  mv -- "$observation_final_config.device" "$observation_final_config"
}

observation_prepare_docker() {
  identity_prepare_docker "$1" "$2"
  enforcement_configure_policy_source
  [[ -z $enforcement_benign_path ]] || enforcement_configure_benign_control
  observation_configure_secret "$3"
}

observation_prepare_cri() {
  identity_prepare_cri "$1" "$2"
  enforcement_configure_policy_source
  [[ -z $enforcement_benign_path ]] || enforcement_configure_benign_control
  observation_configure_secret "$3"
}

enforcement_prepare_cri_shared() {
  [[ $# -eq 5 ]] || {
    echo "CRI enforcement needs a host and container shared directory" >&2
    return 2
  }
  identity_prepare_cri "$1" "$2"
  observation_policy_source=$observation_policy_fixture_directory/observe-policy-v1.yaml
  [[ -z $enforcement_benign_path ]] || enforcement_configure_benign_control
  observation_configure_secret "$3"
  observation_configure_cri_shared_directory "$4" "$5"
}

enforcement_prepare_k3s() {
  identity_prepare_k3s_case "$1"
  observation_policy_source=$observation_policy_fixture_directory/observe-policy-v1.yaml
  [[ -z $enforcement_benign_path ]] || enforcement_configure_benign_control
  observation_configure_secret "$identity_k3s_secret_path"
  observation_configure_cri_shared_directory \
    "$identity_k3s_shared_directory" "$identity_k3s_container_shared_directory"
}

enforcement_expect_exact_denial() {
  observation_wait_for_observation 'reason=EXACT_POLICY_DENY' "$identity_work/effects.txt"
  grep -q 'result=DENIED_BEFORE_EFFECT' "$identity_work/effects.txt"
}

enforcement_expect_hard_close() {
  observation_wait_for_observation "reason=$1" "$identity_work/effects.txt"
  grep -q 'result=DENIED_BEFORE_EFFECT' "$identity_work/effects.txt"
}
