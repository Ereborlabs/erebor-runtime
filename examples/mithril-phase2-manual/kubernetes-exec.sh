#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/common.sh"

[[ $# -eq 5 ]] || {
  echo "usage: sudo $0 NODE_CONFIG FULL_CRI_CONTAINER_ID NAMESPACE POD CONTAINER" >&2
  exit 2
}

phase2_require_command kubectl
phase2_prepare_cri "$1" "$2"
phase2_start_node

echo "Run in another terminal:"
printf "  kubectl -n %q exec %q -c %q -- sh -c %q\n" \
  "$3" "$4" "$5" 'echo external-ready; exec sleep 300'
echo "Its host PID appears in $phase2_cgroup_path/cgroup.procs."
phase2_read_host_pid "kubectl exec sleep host PID: "
phase2_inspect_task kubernetes-exec "$phase2_read_pid"
phase2_assert_external "$phase2_work/kubernetes-exec.json"
phase2_pass "PASS: kubectl exec is a restricted external root"
