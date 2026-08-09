#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/common.sh"

[[ $# -eq 2 ]] || {
  echo "usage: sudo $0 NODE_CONFIG DOCKER_CONTAINER" >&2
  exit 2
}

phase2_prepare_docker "$1" "$2"
phase2_start_node

echo "Run in another root terminal:"
phase2_print_runtime_exec 'echo external-ready; exec sleep 300'
echo "Its host PID appears in $phase2_cgroup_path/cgroup.procs."
phase2_read_host_pid "docker exec sleep host PID: "
phase2_inspect_task docker-exec "$phase2_read_pid"
phase2_assert_external "$phase2_work/docker-exec.json"
phase2_pass "PASS: docker exec is a restricted external root"
