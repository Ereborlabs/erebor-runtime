#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/identity-runtime.sh"

[[ $# -eq 0 ]] || {
  echo "usage: sudo $0" >&2
  exit 2
}

identity_require_command unshare
identity_prepare_k3s_case \
  docker.io/library/python@sha256:78098ea6a3a9c6a7727a5d4674e4a44e57e01fac878ee9cb4d24a86bd93916ff
identity_start_node

reuse_directory=$identity_work/native-pid-reuse
reuse_outer_pid=
reuse_init_pid=
reuse_fixture_pid_matches() {
  local pid=$1
  local command
  [[ $pid =~ ^[1-9][0-9]*$ && -r /proc/$pid/cmdline ]] || return 1
  command=$(tr '\0' ' ' <"/proc/$pid/cmdline")
  [[ $command == *" $reuse_directory/fixture.py $reuse_directory "* ]]
}
reuse_cleanup_processes() {
  local pid attempt
  for pid in "$reuse_init_pid" "$reuse_outer_pid"; do
    reuse_fixture_pid_matches "$pid" && kill -TERM "$pid"
  done
  for ((attempt = 0; attempt < 20; attempt++)); do
    if ! reuse_fixture_pid_matches "$reuse_init_pid" \
      && ! reuse_fixture_pid_matches "$reuse_outer_pid"; then
      break
    fi
    sleep 0.1
  done
  for pid in "$reuse_init_pid" "$reuse_outer_pid"; do
    reuse_fixture_pid_matches "$pid" && kill -KILL "$pid"
  done
  [[ -z $reuse_outer_pid ]] || wait "$reuse_outer_pid" 2>/dev/null || true
  ! reuse_fixture_pid_matches "$reuse_init_pid" \
    && ! reuse_fixture_pid_matches "$reuse_outer_pid"
}
identity_cleanup_functions=(reuse_cleanup_processes "${identity_cleanup_functions[@]}")
mkdir -m 700 -- "$reuse_directory"
cat >"$reuse_directory/fixture.py" <<'PY'
import os
import sys
import time

work = sys.argv[1]


def path(name):
    return os.path.join(work, name)


def mark(name, value):
    temporary = f"{path(name)}.tmp"
    with open(temporary, "x", encoding="ascii") as output:
        output.write(f"{value}\n")
    os.replace(temporary, path(name))


def wait_for(name):
    while not os.path.exists(path(name)):
        time.sleep(0.01)


def child(name, release):
    mark(name, os.getpid())
    wait_for(release)
    os._exit(0)


wait_for("start")
first = os.fork()
if first == 0:
    child("first", "release-first")
os.waitpid(first, 0)
with open("/proc/sys/kernel/ns_last_pid", "w", encoding="ascii") as output:
    output.write(str(first - 1))
second = os.fork()
if second == 0:
    child("second", "release-second")
os.waitpid(second, 0)
mark("complete", "complete")
PY

/usr/bin/unshare --pid --fork --mount-proc \
  python3 "$reuse_directory/fixture.py" "$reuse_directory" &
reuse_outer_pid=$!
identity_task_pids+=("$reuse_outer_pid")

for ((attempt = 0; attempt < 100; attempt++)); do
  read -r reuse_init_pid _ \
    <"/proc/$reuse_outer_pid/task/$reuse_outer_pid/children" || true
  [[ $reuse_init_pid =~ ^[1-9][0-9]*$ ]] && break
  sleep 0.1
done
[[ $reuse_init_pid =~ ^[1-9][0-9]*$ ]] || {
  echo "cannot find the stopped PID-namespace init" >&2
  exit 1
}
identity_task_pids+=("$reuse_init_pid")
printf '%s\n' "$reuse_init_pid" >"$identity_cgroup_path/cgroup.procs"
identity_wait_for_task_snapshot reuse-init "$reuse_init_pid"
identity_assert_external "$identity_work/reuse-init.json"
reuse_init_cookie=$(jq -er '.task_cookie' "$identity_work/reuse-init.json")
reuse_role=$(jq -er '.active_role_id' "$identity_work/reuse-init.json")
: >"$reuse_directory/start"

reuse_first_namespace_pid=
for ((attempt = 0; attempt < 100; attempt++)); do
  [[ -f $reuse_directory/first ]] \
    && reuse_first_namespace_pid=$(<"$reuse_directory/first")
  [[ $reuse_first_namespace_pid =~ ^[1-9][0-9]*$ ]] && break
  sleep 0.1
done
read -r reuse_first_host_pid _ \
  <"/proc/$reuse_init_pid/task/$reuse_init_pid/children" || true
[[ $reuse_first_host_pid =~ ^[1-9][0-9]*$ ]] || {
  echo "cannot find the first reusable host PID" >&2
  exit 1
}
reuse_first_live_namespace_pid=$(awk '/^NSpid:/ {print $NF}' \
  "/proc/$reuse_first_host_pid/status")
identity_inspect_task reuse-first "$reuse_first_host_pid" >/dev/null
: >"$reuse_directory/release-first"

reuse_second_namespace_pid=
for ((attempt = 0; attempt < 100; attempt++)); do
  [[ -f $reuse_directory/second ]] \
    && reuse_second_namespace_pid=$(<"$reuse_directory/second")
  [[ $reuse_second_namespace_pid =~ ^[1-9][0-9]*$ ]] || {
    sleep 0.1
    continue
  }
  read -r reuse_second_host_pid _ \
    <"/proc/$reuse_init_pid/task/$reuse_init_pid/children" || true
  [[ $reuse_second_host_pid =~ ^[1-9][0-9]*$ ]] && break
  sleep 0.1
done
[[ $reuse_second_host_pid =~ ^[1-9][0-9]*$ ]] || {
  echo "cannot find the second reusable host PID" >&2
  exit 1
}
reuse_second_live_namespace_pid=$(awk '/^NSpid:/ {print $NF}' \
  "/proc/$reuse_second_host_pid/status")
identity_inspect_task reuse-second "$reuse_second_host_pid" >/dev/null

jq -e --slurpfile second "$identity_work/reuse-second.json" \
  --argjson creator "$reuse_init_cookie" \
  --argjson role "$reuse_role" '
  .creator_task_cookie == $creator
  and $second[0].creator_task_cookie == $creator
  and .task_cookie != $second[0].task_cookie
  and .process_state_id != $second[0].process_state_id
  and .active_execution_id != $second[0].active_execution_id
  and .active_role_id == $role
  and $second[0].active_role_id == $role
  and .root_class == null
  and $second[0].root_class == null
  and .coordinate_state == 3
  and $second[0].coordinate_state == 3
' "$identity_work/reuse-first.json" >/dev/null
[[ $reuse_first_namespace_pid == "$reuse_second_namespace_pid" \
  && $reuse_first_live_namespace_pid == "$reuse_first_namespace_pid" \
  && $reuse_second_live_namespace_pid == "$reuse_first_namespace_pid" \
  && $reuse_first_host_pid != "$reuse_second_host_pid" ]] || {
  echo "the PID number was not reused with a fresh host task" >&2
  exit 1
}

: >"$reuse_directory/release-second"
for ((attempt = 0; attempt < 100; attempt++)); do
  [[ -f $reuse_directory/complete ]] && break
  sleep 0.1
done
[[ -f $reuse_directory/complete ]] || {
  echo "PID-reuse fixture did not finish" >&2
  exit 1
}
wait "$reuse_outer_pid"
reuse_outer_pid=
reuse_init_pid=
identity_task_pids=()

identity_pass \
  "PASS: namespace PID $reuse_first_namespace_pid was reused by fresh tasks; both creator edges stayed exact."
