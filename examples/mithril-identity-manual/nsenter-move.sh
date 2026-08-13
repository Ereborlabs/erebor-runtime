#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/identity-runtime.sh"

[[ $# -eq 2 ]] || {
  echo "usage: sudo $0 NODE_CONFIG DOCKER_CONTAINER_OR_FULL_CRI_ID" >&2
  exit 2
}

identity_require_command nsenter
identity_prepare_auto "$1" "$2"
identity_start_node

echo "Run in another root terminal; namespace entry alone stays outside:"
printf "  sudo nsenter -t %q -m -u -i -n -p sh -c %q\n" \
  "$identity_init_pid" 'echo nsenter-ready; exec sleep 300'
identity_read_host_pid "nsenter sleep host PID: "
nsenter_pid=$identity_read_pid
if "$identity_inspect" --pin-root "$identity_pin_root" task --host-pid "$nsenter_pid" \
  >/dev/null 2>&1; then
  echo "namespace entry alone incorrectly granted workload identity" >&2
  exit 1
fi

echo "$nsenter_pid" >"$identity_cgroup_path/cgroup.procs"
identity_inspect_task nsenter-after-move "$nsenter_pid"
identity_assert_external "$identity_work/nsenter-after-move.json"
identity_pass "PASS: nsenter grants nothing; cgroup movement creates a restricted external root"
