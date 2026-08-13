#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/identity-runtime.sh"

[[ $# -eq 5 ]] || {
  echo "usage: sudo $0 NODE_CONFIG FULL_CRI_CONTAINER_ID NAMESPACE POD CONTAINER" >&2
  exit 2
}

identity_require_command kubectl
identity_prepare_cri "$1" "$2"
identity_start_node

echo "Run in another terminal:"
printf "  kubectl -n %q exec %q -c %q -- sh -c %q\n" \
  "$3" "$4" "$5" 'echo external-ready; exec sleep 300'
echo "Its host PID appears in $identity_cgroup_path/cgroup.procs."
identity_read_host_pid "kubectl exec sleep host PID: "
identity_inspect_task kubernetes-exec "$identity_read_pid"
identity_assert_external "$identity_work/kubernetes-exec.json"
identity_pass "PASS: kubectl exec is a restricted external root"
