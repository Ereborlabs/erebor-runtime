#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/common.sh"

[[ $# -eq 2 ]] || {
  echo "usage: sudo $0 NODE_CONFIG DOCKER_CONTAINER_OR_FULL_CRI_ID" >&2
  exit 2
}

phase2_require_command nsenter
phase2_prepare_auto "$1" "$2"
phase2_start_node

echo "Run in another root terminal; namespace entry alone stays outside:"
printf "  sudo nsenter -t %q -m -u -i -n -p sh -c %q\n" \
  "$phase2_init_pid" 'echo nsenter-ready; exec sleep 300'
phase2_read_host_pid "nsenter sleep host PID: "
nsenter_pid=$phase2_read_pid
if "$phase2_inspect" --pin-root "$phase2_pin_root" task --host-pid "$nsenter_pid" \
  >/dev/null 2>&1; then
  echo "namespace entry alone incorrectly granted workload identity" >&2
  exit 1
fi

echo "$nsenter_pid" >"$phase2_cgroup_path/cgroup.procs"
phase2_inspect_task nsenter-after-move "$nsenter_pid"
phase2_assert_external "$phase2_work/nsenter-after-move.json"
phase2_pass "PASS: nsenter grants nothing; cgroup movement creates a restricted external root"
