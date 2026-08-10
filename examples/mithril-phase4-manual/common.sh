#!/usr/bin/env bash

# Phase 4 promotes the established Phase 3 signed fixture to PROTECT. The
# Phase 2/3 owner still supplies the real-node lifecycle and EXIT cleanup.
phase4_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
phase3_policy_mode=PROTECT
phase3_policy_source=$phase4_directory/policy-v1.yaml
source "$phase4_directory/../mithril-phase3-manual/common.sh"

phase4_benign_path=/tmp/mithril-phase4-benign-$$
phase4_exception_lifetime_ns=${phase4_exception_lifetime_ns:-}

phase4_configure_policy_source() {
  [[ -n $phase4_exception_lifetime_ns ]] || return 0
  [[ $phase4_exception_lifetime_ns =~ ^[1-9][0-9]*$ ]] || {
    echo "phase4_exception_lifetime_ns must be a positive integer" >&2
    return 2
  }
  phase3_policy_source=$phase2_work/phase4-policy-v1.yaml
  sed "s/maximum_lifetime_ns: 3600000000000/maximum_lifetime_ns: $phase4_exception_lifetime_ns/" \
    "$phase4_directory/policy-v1.yaml" >"$phase3_policy_source"
}

phase4_configure_benign_control() {
  printf 'benign\n' >"/proc/$phase2_init_pid/root$phase4_benign_path"
  phase3_extra_exact_path=$phase4_benign_path
  phase3_extra_exact_key=8
  phase3_extra_exact_class=MANUAL_BENIGN
  phase2_cleanup_functions+=(phase4_cleanup_benign_control)
}

phase4_cleanup_benign_control() {
  rm -f -- "/proc/$phase2_init_pid/root$phase4_benign_path"
}

phase3_prepare_docker() {
  phase2_prepare_docker "$1" "$2"
  phase4_configure_policy_source
  phase4_configure_benign_control
  phase3_configure_secret "$3"
}

phase3_prepare_cri() {
  phase2_prepare_cri "$1" "$2"
  phase4_configure_policy_source
  phase4_configure_benign_control
  phase3_configure_secret "$3"
}

phase4_expect_exact_denial() {
  phase3_wait_for_observation 'reason=EXACT_POLICY_DENY' "$phase2_work/effects.txt"
  grep -q 'result=DENIED_BEFORE_EFFECT' "$phase2_work/effects.txt"
}

phase4_expect_hard_close() {
  phase3_wait_for_observation "reason=$1" "$phase2_work/effects.txt"
  grep -q 'result=DENIED_BEFORE_EFFECT' "$phase2_work/effects.txt"
}
