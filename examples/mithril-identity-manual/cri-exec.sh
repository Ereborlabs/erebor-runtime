#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/identity-runtime.sh"

[[ $# -eq 2 ]] || {
  echo "usage: sudo $0 NODE_CONFIG FULL_CRI_CONTAINER_ID" >&2
  exit 2
}

identity_prepare_cri "$1" "$2"
identity_start_node

echo "Run in another root terminal:"
identity_print_runtime_exec 'echo external-ready; exec sleep 300'
echo "Its host PID appears in $identity_cgroup_path/cgroup.procs."
identity_read_host_pid "crictl exec sleep host PID: "
identity_inspect_task cri-exec "$identity_read_pid"
identity_assert_external "$identity_work/cri-exec.json"
identity_pass "PASS: crictl exec is a restricted external root"
