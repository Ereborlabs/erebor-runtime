#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/identity-runtime.sh"

[[ $# -eq 0 ]] || {
  echo "usage: sudo $0" >&2
  exit 2
}

cgroup_escape_verify_cgroup_removed() {
  [[ ! -e $cgroup_escape_cgroup_path ]] || {
    echo "cgroup-escape Pod cgroup survived cleanup: $cgroup_escape_cgroup_path" >&2
    return 1
  }
}

identity_prepare_k3s_case \
  docker.io/library/python@sha256:78098ea6a3a9c6a7727a5d4674e4a44e57e01fac878ee9cb4d24a86bd93916ff
identity_require_command python3
cgroup_escape_cgroup_path=$identity_cgroup_path
cgroup_escape_unprotected_procs=/sys/fs/cgroup/cgroup.procs
[[ -w $cgroup_escape_unprotected_procs ]] || {
  echo "unprotected root cgroup is not writable: $cgroup_escape_unprotected_procs" >&2
  exit 1
}
identity_cleanup_functions+=(cgroup_escape_verify_cgroup_removed)
cgroup_escape_sentinel=$identity_k3s_fixture_root/cgroup-escape-sentinel
printf 'identity cgroup escape sentinel\n' >"$cgroup_escape_sentinel"
identity_start_node
cgroup_escape_start_index=0
cgroup_escape_external_role=$(jq -er '.workload_bindings[0].external_role_id' "$identity_config")

cgroup_escape_start_root() {
  ((++cgroup_escape_start_index))
  cgroup_escape_ready=$identity_work/cgroup-escape-ready-$cgroup_escape_start_index
  python3 -c '
import os
import signal
import sys

def open_sentinel(_signal, _frame):
    try:
        descriptor = os.open(sys.argv[1], os.O_RDONLY | os.O_CLOEXEC)
    except OSError as error:
        os._exit(error.errno or 127)
    os.close(descriptor)
    os._exit(0)

signal.signal(signal.SIGUSR1, open_sentinel)
ready = os.open(sys.argv[2], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
os.close(ready)
signal.pause()
  ' "$cgroup_escape_sentinel" "$cgroup_escape_ready" &
  cgroup_escape_root_pid=$!
  identity_task_pids+=("$cgroup_escape_root_pid")
  for ((attempt = 0; attempt < 100; attempt++)); do
    [[ -e $cgroup_escape_ready ]] && break
    sleep 0.1
  done
  [[ -e $cgroup_escape_ready ]] || {
    echo "cgroup-escape root did not prepare its direct file open" >&2
    return 1
  }
  printf '%s\n' "$cgroup_escape_root_pid" >"$identity_cgroup_path/cgroup.procs"
}

cgroup_escape_wait_for_stop() {
  for ((attempt = 0; attempt < 100; attempt++)); do
    grep -q $'^State:\tT' "/proc/$cgroup_escape_root_pid/status" && return 0
    sleep 0.1
  done
  echo "cgroup-escape root did not stop before its file open" >&2
  return 1
}

cgroup_escape_wait_for_external() {
  local name=$1
  for ((attempt = 0; attempt < 100; attempt++)); do
    identity_inspect_task "$name" "$cgroup_escape_root_pid" >/dev/null 2>&1 || true
    jq -e --argjson external_role "$cgroup_escape_external_role" '.creator_task_cookie == null
           and .root_class == "external_runtime_root"
           and .installed_role_class == "runtime_external_restricted"
           and .active_role_id == $external_role
           and .coordinate_state == 3' \
      "$identity_work/$name.json" >/dev/null 2>&1 && return 0
    sleep 0.1
  done
  echo "cgroup-escape root did not get a restricted external identity" >&2
  return 1
}

cgroup_escape_start_root
cgroup_escape_wait_for_external cgroup-escape-unmoved-control
kill -USR1 "$cgroup_escape_root_pid"
wait "$cgroup_escape_root_pid"

cgroup_escape_start_root
cgroup_escape_wait_for_external cgroup-escape-before-move
escape_task_cookie=$(jq -er '.task_cookie' "$identity_work/cgroup-escape-before-move.json")
escape_process_state=$(jq -er '.process_state_id' "$identity_work/cgroup-escape-before-move.json")
kill -STOP "$cgroup_escape_root_pid"
cgroup_escape_wait_for_stop
printf '%s\n' "$cgroup_escape_root_pid" >"$cgroup_escape_unprotected_procs"
for ((attempt = 0; attempt < 100; attempt++)); do
  identity_inspect_task cgroup-escape-after-move "$cgroup_escape_root_pid" >/dev/null 2>&1 || true
  jq -e --argjson task_cookie "$escape_task_cookie" --arg process_state "$escape_process_state" \
    --argjson external_role "$cgroup_escape_external_role" \
    '.task_cookie == $task_cookie
     and .process_state_id == $process_state
     and .root_class == "external_runtime_root"
     and .installed_role_class == "runtime_external_restricted"
     and .active_role_id == $external_role
     and .coordinate_state == 6' \
    "$identity_work/cgroup-escape-after-move.json" >/dev/null 2>&1 && break
  sleep 0.1
done
jq -e --argjson task_cookie "$escape_task_cookie" --arg process_state "$escape_process_state" \
  --argjson external_role "$cgroup_escape_external_role" \
  '.task_cookie == $task_cookie
   and .process_state_id == $process_state
   and .root_class == "external_runtime_root"
   and .installed_role_class == "runtime_external_restricted"
   and .active_role_id == $external_role
   and .coordinate_state == 6' \
  "$identity_work/cgroup-escape-after-move.json" >/dev/null
kill -USR1 "$cgroup_escape_root_pid"
kill -CONT "$cgroup_escape_root_pid"
if wait "$cgroup_escape_root_pid"; then
  echo "moved root opened the sentinel" >&2
  exit 1
else
  cgroup_escape_status=$?
fi
[[ $cgroup_escape_status -eq 13 ]] || {
  echo "moved root exit status is $cgroup_escape_status, expected 13" >&2
  exit 1
}

identity_pass "PASS: an unmoved root opened the sentinel; the moved root was fail closed and got EACCES."
