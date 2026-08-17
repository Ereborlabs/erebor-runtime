#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/identity-runtime.sh"

identity_case_mode=
identity_case_k3s=false
if [[ $# -eq 1 && ($1 == --thread-exec || $1 == --concurrent-thread-exec || $1 == --subreaper || $1 == --namespace-init) ]]; then
  identity_case_mode=$1
  identity_case_k3s=true
elif [[ $# -eq 2 || ($# -eq 3 && (${3:-} == --orphan || ${3:-} == --double-fork || ${3:-} == --moved-exec || ${3:-} == --failed-exec || ${3:-} == --thread-exec || ${3:-} == --namespace-init)) ]]; then
  identity_case_mode=${3:-}
else
  echo "usage: sudo $0 NODE_CONFIG DOCKER_CONTAINER_OR_FULL_CRI_ID [--orphan|--double-fork|--moved-exec|--failed-exec|--thread-exec|--namespace-init]" >&2
  echo "   or: sudo $0 --thread-exec|--concurrent-thread-exec|--subreaper|--namespace-init" >&2
  exit 2
fi

if [[ $identity_case_k3s == true ]]; then
  identity_prepare_k3s_case \
    docker.io/library/python@sha256:78098ea6a3a9c6a7727a5d4674e4a44e57e01fac878ee9cb4d24a86bd93916ff
else
  identity_prepare_auto "$1" "$2"
fi
identity_start_node

if [[ $identity_case_mode == --double-fork ]]; then
  echo "Run in another root terminal:"
  identity_print_runtime_exec '( ( read child_pid _ < /proc/self/stat; kill -STOP "$child_pid"; exec sleep 300 ) & wait ) & middle_pid=$!; wait "$middle_pid"; exec sleep 300'
  echo "Enter the outer shell, its intermediate child, then its stopped grandchild host PIDs."
  identity_read_host_pid "outer shell host PID: "
  outer_pid=$identity_read_pid
  identity_read_host_pid "intermediate native child host PID: "
  intermediate_pid=$identity_read_pid
  identity_read_host_pid "stopped native grandchild host PID: "
  child_pid=$identity_read_pid
  grep -q $'^State:\tT' "/proc/$child_pid/status" || {
    echo "native grandchild is not stopped before the intermediate exits" >&2
    exit 1
  }
  identity_inspect_task double-fork-outer "$outer_pid"
  identity_inspect_task double-fork-intermediate "$intermediate_pid"
  identity_inspect_task double-fork-child-before "$child_pid"

  outer_cookie=$(jq -er '.task_cookie' "$identity_work/double-fork-outer.json")
  outer_role=$(jq -er '.active_role_id' "$identity_work/double-fork-outer.json")
  intermediate_cookie=$(jq -er '.task_cookie' "$identity_work/double-fork-intermediate.json")
  child_cookie=$(jq -er '.task_cookie' "$identity_work/double-fork-child-before.json")
  child_interval=$(jq -er '.real_parent_interval_sequence' "$identity_work/double-fork-child-before.json")
  identity_assert_external "$identity_work/double-fork-outer.json"
  jq -e --argjson outer_cookie "$outer_cookie" \
    --argjson outer_role "$outer_role" \
    '.creator_task_cookie == $outer_cookie
     and .real_parent_task_cookie == $outer_cookie
     and .root_class == null
     and .installed_role_class == null
     and .active_role_id == $outer_role' \
    "$identity_work/double-fork-intermediate.json" >/dev/null
  jq -e --argjson intermediate_cookie "$intermediate_cookie" \
    --argjson outer_role "$outer_role" \
    '.creator_task_cookie == $intermediate_cookie
     and .real_parent_task_cookie == $intermediate_cookie
     and .root_class == null
     and .installed_role_class == null
     and .active_role_id == $outer_role' \
    "$identity_work/double-fork-child-before.json" >/dev/null

  echo "In another root terminal, run: kill -KILL $intermediate_pid"
  read -r -p "Press Enter after the intermediate child has exited: " _
  for ((attempt = 0; attempt < 100; attempt++)); do
    [[ ! -d /proc/$intermediate_pid ]] && break
    sleep 0.1
  done
  [[ ! -d /proc/$intermediate_pid ]] || {
    echo "intermediate native child is still live" >&2
    exit 1
  }
  for ((attempt = 0; attempt < 100; attempt++)); do
    [[ $(tr -d '\n' </proc/$outer_pid/comm 2>/dev/null || true) == sleep ]] && break
    sleep 0.1
  done
  [[ $(tr -d '\n' </proc/$outer_pid/comm 2>/dev/null || true) == sleep ]] || {
    echo "outer shell did not remain live after the intermediate exited" >&2
    exit 1
  }
  kill -CONT "$child_pid"
  for ((attempt = 0; attempt < 100; attempt++)); do
    [[ $(tr -d '\n' </proc/$child_pid/comm 2>/dev/null || true) == sleep ]] && break
    sleep 0.1
  done
  [[ $(tr -d '\n' </proc/$child_pid/comm 2>/dev/null || true) == sleep ]] || {
    echo "native grandchild did not exec sleep after the intermediate exited" >&2
    exit 1
  }
  identity_inspect_task double-fork-child-after "$child_pid"
  jq -e --argjson intermediate_cookie "$intermediate_cookie" \
    --argjson outer_role "$outer_role" \
    --argjson child_cookie "$child_cookie" \
    --argjson child_interval "$child_interval" \
    '.task_cookie == $child_cookie
     and .creator_task_cookie == $intermediate_cookie
     and .real_parent_task_cookie != $intermediate_cookie
     and .real_parent_interval_sequence > $child_interval
     and .root_class == null
     and .installed_role_class == null
     and .active_role_id == $outer_role' \
    "$identity_work/double-fork-child-after.json" >/dev/null
  identity_pass "PASS: double-fork creator identity stayed exact after intermediate exit."
  exit 0
fi

if [[ $identity_case_mode == --moved-exec ]]; then
  echo "Run in another root terminal:"
  identity_print_runtime_exec '(read child_pid _ < /proc/self/stat; kill -STOP "$child_pid"; exec sleep 300) & wait'
  echo "Enter that shell's host PID, then its stopped native child host PID."
  identity_read_host_pid "shell host PID: "
  parent_pid=$identity_read_pid
  identity_read_host_pid "stopped native child host PID: "
  child_pid=$identity_read_pid
  grep -q $'^State:\tT' "/proc/$child_pid/status" || {
    echo "native child is not stopped before cgroup movement" >&2
    exit 1
  }
  identity_inspect_task moved-exec-parent "$parent_pid"
  identity_inspect_task moved-exec-child-before "$child_pid"

  parent_cookie=$(jq -er '.task_cookie' "$identity_work/moved-exec-parent.json")
  child_cookie=$(jq -er '.task_cookie' "$identity_work/moved-exec-child-before.json")
  identity_assert_external "$identity_work/moved-exec-parent.json"
  jq -e --argjson parent_cookie "$parent_cookie" \
    '.creator_task_cookie == $parent_cookie
     and .real_parent_task_cookie == $parent_cookie
     and .root_class == null
     and .installed_role_class == null
     and .coordinate_state == 3' \
    "$identity_work/moved-exec-child-before.json" >/dev/null

  parent_cgroup=$(dirname -- "$identity_cgroup_path")
  parent_procs=$parent_cgroup/cgroup.procs
  [[ -w $parent_procs ]] || {
    echo "cannot move the native child to $parent_procs" >&2
    exit 1
  }
  printf '%s\n' "$child_pid" >"$parent_procs"
  for ((attempt = 0; attempt < 100; attempt++)); do
    identity_inspect_task moved-exec-child-after-move "$child_pid" >/dev/null
    jq -e --argjson parent_cookie "$parent_cookie" \
      --argjson child_cookie "$child_cookie" \
      '.task_cookie == $child_cookie
       and .creator_task_cookie == $parent_cookie
       and .real_parent_task_cookie == $parent_cookie
       and .root_class == null
       and .installed_role_class == null
       and .coordinate_state == 6' \
      "$identity_work/moved-exec-child-after-move.json" >/dev/null && break
    sleep 0.1
  done
  jq -e --argjson parent_cookie "$parent_cookie" \
    --argjson child_cookie "$child_cookie" \
    '.task_cookie == $child_cookie
     and .creator_task_cookie == $parent_cookie
     and .real_parent_task_cookie == $parent_cookie
     and .root_class == null
     and .installed_role_class == null
     and .coordinate_state == 6' \
    "$identity_work/moved-exec-child-after-move.json" >/dev/null || {
      echo "moved native child did not become fail closed" >&2
      exit 1
    }

  kill -CONT "$child_pid"
  for ((attempt = 0; attempt < 50; attempt++)); do
    [[ ! -d /proc/$child_pid ]] && break
    [[ $(tr -d '\n' </proc/$child_pid/comm 2>/dev/null || true) != sleep ]] || {
      echo "moved native child executed sleep" >&2
      exit 1
    }
    sleep 0.1
  done
  [[ ! -d /proc/$child_pid ]] || {
    echo "moved native child did not exit after its denied exec" >&2
    exit 1
  }
  identity_pass "PASS: a moved native child kept its identity and its exec was denied."
  exit 0
fi

if [[ $identity_case_mode == --failed-exec ]]; then
  echo "This check requires /bin/bash, python3, and a dynamically linked /bin/true in the workload."
  echo "Run this in another root terminal:"
  if [[ $identity_mode == docker ]]; then
    printf '  docker exec %q /bin/bash\n' "$identity_container"
  else
    printf '  crictl --runtime-endpoint %q exec %q /bin/bash\n' \
      "$identity_runtime_endpoint" "$identity_container_id"
  fi
  cat <<'EOF'
Paste this block into that Bash session. Do not change the block.

execfail=/tmp/mithril-execfail-$RANDOM-$RANDOM
python3 - "$execfail" <<'PY'
from pathlib import Path
import sys

image = bytearray(Path("/bin/true").read_bytes())
for loader in (
    b"/lib64/ld-linux-x86-64.so.2\x00",
    b"/lib/ld-linux-aarch64.so.1\x00",
    b"/lib/ld-linux-armhf.so.3\x00",
    b"/lib/ld-linux-riscv64-lp64d.so.1\x00",
):
    offset = image.find(loader)
    if offset >= 0:
        image[offset + 1] = ord("z")
        Path(sys.argv[1]).write_bytes(image)
        break
else:
    raise SystemExit("/bin/true has no supported ELF loader path")
PY
chmod 700 "$execfail"
bash -c '
  read child_pid _ < /proc/self/stat
  kill -STOP "$child_pid"
  shopt -s execfail
  exec "$0"
  printf "%s\n" MITHRIL_EXECFAIL_RECOVERED
  kill -STOP "$child_pid"
  exec /bin/sleep 300
' "$execfail" &
wait "$!"
rm -f -- "$execfail"
printf '%s\n' MITHRIL_EXECFAIL_CLEANED
EOF
  echo "Enter that Bash session host PID, then its first stopped Bash child host PID."
  identity_read_host_pid "shell host PID: "
  parent_pid=$identity_read_pid
  identity_read_host_pid "stopped native child host PID: "
  child_pid=$identity_read_pid
  grep -q $'^State:\tT' "/proc/$child_pid/status" || {
    echo "native child is not stopped before the ELF loader failure" >&2
    exit 1
  }
  identity_inspect_task failed-exec-parent "$parent_pid"
  identity_inspect_task failed-exec-child-before "$child_pid"

  parent_cookie=$(jq -er '.task_cookie' "$identity_work/failed-exec-parent.json")
  child_cookie=$(jq -er '.task_cookie' "$identity_work/failed-exec-child-before.json")
  child_execution=$(jq -er '.active_execution_id' "$identity_work/failed-exec-child-before.json")
  child_image=$(jq -er '.image_provenance_id' "$identity_work/failed-exec-child-before.json")
  child_role=$(jq -er '.active_role_id' "$identity_work/failed-exec-child-before.json")
  identity_assert_external "$identity_work/failed-exec-parent.json"
  jq -e --argjson parent_cookie "$parent_cookie" \
    --argjson child_cookie "$child_cookie" \
    '.task_cookie == $child_cookie
     and .creator_task_cookie == $parent_cookie
     and .real_parent_task_cookie == $parent_cookie
     and .root_class == null
     and .installed_role_class == null
     and .process_execution_state == 2
     and .process_state_vector_state == 2
     and .exec_guard_state == 0' \
    "$identity_work/failed-exec-child-before.json" >/dev/null

  echo "In the other root terminal, run: kill -CONT $child_pid"
  read -r -p "Press Enter after that terminal prints MITHRIL_EXECFAIL_RECOVERED: " _
  grep -q $'^State:\tT' "/proc/$child_pid/status" || {
    echo "native child did not stop after the ELF loader failure" >&2
    exit 1
  }
  [[ $(tr -d '\n' </proc/$child_pid/comm 2>/dev/null || true) == bash ]] || {
    echo "native child did not return to Bash after the ELF loader failure" >&2
    exit 1
  }
  identity_inspect_task failed-exec-child-after-failure "$child_pid"
  jq -e --argjson parent_cookie "$parent_cookie" \
    --argjson child_cookie "$child_cookie" \
    --arg child_execution "$child_execution" \
    --arg child_image "$child_image" \
    --argjson child_role "$child_role" \
    '.task_cookie == $child_cookie
     and .creator_task_cookie == $parent_cookie
     and .real_parent_task_cookie == $parent_cookie
     and .active_execution_id == $child_execution
     and .image_provenance_id == $child_image
     and .active_role_id == $child_role
     and .root_class == null
     and .installed_role_class == null
     and .process_execution_state == 2
     and .process_state_vector_state == 2
     and .exec_guard_state == 0' \
    "$identity_work/failed-exec-child-after-failure.json" >/dev/null

  echo "In the other root terminal, run: kill -CONT $child_pid"
  for ((attempt = 0; attempt < 100; attempt++)); do
    [[ $(tr -d '\n' </proc/$child_pid/comm 2>/dev/null || true) == sleep ]] && break
    sleep 0.1
  done
  [[ $(tr -d '\n' </proc/$child_pid/comm 2>/dev/null || true) == sleep ]] || {
    echo "native child did not exec sleep after the pre-PONR failure" >&2
    exit 1
  }
  identity_inspect_task failed-exec-child-after-success "$child_pid"
  jq -e --argjson parent_cookie "$parent_cookie" \
    --argjson child_cookie "$child_cookie" \
    --arg child_execution "$child_execution" \
    --arg child_image "$child_image" \
    --argjson child_role "$child_role" \
    '.task_cookie == $child_cookie
     and .creator_task_cookie == $parent_cookie
     and .real_parent_task_cookie == $parent_cookie
     and .active_execution_id != $child_execution
     and .image_provenance_id != $child_image
     and .active_role_id == $child_role
     and .root_class == null
     and .installed_role_class == null
     and .process_execution_state == 2
     and .process_state_vector_state == 2
     and .exec_guard_state == 0' \
    "$identity_work/failed-exec-child-after-success.json" >/dev/null

  echo "In the other root terminal, run: kill -TERM $child_pid"
  read -r -p "Press Enter after that terminal prints MITHRIL_EXECFAIL_CLEANED: " _
  for ((attempt = 0; attempt < 50; attempt++)); do
    [[ ! -d /proc/$child_pid ]] && break
    sleep 0.1
  done
  [[ ! -d /proc/$child_pid ]] || {
    echo "native child did not exit after cleanup" >&2
    exit 1
  }
  identity_pass "PASS: a pre-PONR ELF loader failure kept the source identity and a later exec committed."
  exit 0
fi

if [[ $identity_case_mode == --namespace-init ]]; then
  identity_require_command unshare
  ready_name=.mithril-namespace-init-${identity_work##*.}.ready
  ready_host=$identity_k3s_shared_directory/$ready_name
  namespace_init_pids=()
  namespace_init_cleanup() {
    local pid
    for pid in "${namespace_init_pids[@]}"; do
      kill -KILL "$pid" 2>/dev/null || true
    done
  }
  identity_cleanup_functions+=(namespace_init_cleanup)
  /usr/bin/unshare --user --map-root-user --pid --fork python3 -c '
import os
import signal
import sys

ready = sys.argv[1]
os.kill(os.getpid(), signal.SIGSTOP)
middle = os.fork()
if middle == 0:
    child = os.fork()
    if child == 0:
        os.kill(os.getpid(), signal.SIGSTOP)
        os.execv("/bin/sleep", ["/bin/sleep", "300"])
    with open(ready, "w", encoding="ascii") as output:
        output.write(f"{os.getpid()} {child}\n")
os.waitpid(middle, 0)
with open(ready, encoding="ascii") as input_file:
    _middle, child = input_file.read().split()
os.waitpid(int(child), 0)
' "$ready_host" >"$identity_work/namespace-init-client.log" 2>&1 &
  namespace_init_outer_pid=$!
  namespace_init_pids+=("$namespace_init_outer_pid")
  for ((attempt = 0; attempt < 100; attempt++)); do
    namespace_init_pid=$(awk '{print $1}' "/proc/$namespace_init_outer_pid/task/$namespace_init_outer_pid/children" 2>/dev/null || true)
    [[ $namespace_init_pid =~ ^[1-9][0-9]*$ ]] && break
    sleep 0.1
  done
  [[ $namespace_init_pid =~ ^[1-9][0-9]*$ ]] || {
    echo "cannot find the stopped PID-namespace init" >&2
    exit 1
  }
  namespace_init_pids+=("$namespace_init_pid")
  [[ $(awk '/^NSpid:/ {print $NF}' "/proc/$namespace_init_pid/status") == 1 ]] || {
    echo "the stopped namespace init does not have PID 1" >&2
    exit 1
  }
  printf '%s\n' "$namespace_init_pid" >"$identity_cgroup_path/cgroup.procs"
  for ((attempt = 0; attempt < 100; attempt++)); do
    identity_inspect_task namespace-init-parent "$namespace_init_pid" >/dev/null 2>&1 && break
    sleep 0.1
  done
  identity_assert_external "$identity_work/namespace-init-parent.json"
  namespace_init_parent_cookie=$(jq -er '.task_cookie' "$identity_work/namespace-init-parent.json")
  namespace_init_role=$(jq -er '.active_role_id' "$identity_work/namespace-init-parent.json")
  namespace_init_host_tid=$(jq -er '.host_tid' "$identity_work/namespace-init-parent.json")
  namespace_init_host_tgid=$(jq -er '.host_tgid' "$identity_work/namespace-init-parent.json")
  kill -CONT "$namespace_init_pid"
  for ((attempt = 0; attempt < 100; attempt++)); do
    [[ -s $ready_host ]] && break
    sleep 0.1
  done
  [[ -s $ready_host ]] || {
    echo "the PID-namespace fixture did not become ready" >&2
    exit 1
  }
  read -r namespace_middle_pid namespace_child_pid <"$ready_host"
  [[ $namespace_middle_pid =~ ^[1-9][0-9]*$ \
    && $namespace_child_pid =~ ^[1-9][0-9]*$ ]] || {
    echo "the PID-namespace fixture did not report middle and child PIDs" >&2
    exit 1
  }
  namespace_middle_host_pid=
  namespace_child_host_pid=
  for candidate in $(<"$identity_cgroup_path/cgroup.procs"); do
    [[ -r /proc/$candidate/status ]] || continue
    mapped_pid=$(awk '/^NSpid:/ {print $NF}' "/proc/$candidate/status")
    case $mapped_pid in
      "$namespace_middle_pid") namespace_middle_host_pid=$candidate ;;
      "$namespace_child_pid") namespace_child_host_pid=$candidate ;;
    esac
  done
  [[ $namespace_middle_host_pid =~ ^[1-9][0-9]*$ \
    && $namespace_child_host_pid =~ ^[1-9][0-9]*$ ]] || {
    echo "cannot map the PID-namespace middle and child to host PIDs" >&2
    exit 1
  }
  namespace_init_pids+=("$namespace_middle_host_pid" "$namespace_child_host_pid")
  identity_task_pids+=("$namespace_init_pid" "$namespace_child_host_pid")
  grep -q $'^State:\tT' "/proc/$namespace_child_host_pid/status" || {
    echo "PID-namespace native child is not stopped before parent exit" >&2
    exit 1
  }
  identity_inspect_task namespace-init-parent "$namespace_init_pid" >/dev/null
  identity_inspect_task namespace-init-middle "$namespace_middle_host_pid" >/dev/null
  identity_inspect_task namespace-init-child-before "$namespace_child_host_pid" >/dev/null
  namespace_init_parent_cookie=$(jq -er '.task_cookie' "$identity_work/namespace-init-parent.json")
  namespace_middle_cookie=$(jq -er '.task_cookie' "$identity_work/namespace-init-middle.json")
  namespace_child_cookie=$(jq -er '.task_cookie' "$identity_work/namespace-init-child-before.json")
  namespace_child_interval=$(jq -er '.real_parent_interval_sequence' "$identity_work/namespace-init-child-before.json")
  namespace_child_process=$(jq -er '.process_state_id' "$identity_work/namespace-init-child-before.json")
  namespace_child_execution=$(jq -er '.active_execution_id' "$identity_work/namespace-init-child-before.json")
  namespace_child_image=$(jq -er '.image_provenance_id' "$identity_work/namespace-init-child-before.json")
  jq -e --argjson init_cookie "$namespace_init_parent_cookie" \
    --argjson init_tid "$namespace_init_host_tid" \
    --argjson init_tgid "$namespace_init_host_tgid" \
    --argjson init_role "$namespace_init_role" \
    '.creator_task_cookie == $init_cookie
     and .real_parent_task_cookie == $init_cookie
     and .real_parent_host_tid == $init_tid
     and .real_parent_host_tgid == $init_tgid
     and .root_class == null
     and .installed_role_class == null
     and .active_role_id == $init_role' \
    "$identity_work/namespace-init-middle.json" >/dev/null
  jq -e --argjson middle_cookie "$namespace_middle_cookie" \
    --argjson middle_tid "$(jq -er '.host_tid' "$identity_work/namespace-init-middle.json")" \
    --argjson middle_tgid "$(jq -er '.host_tgid' "$identity_work/namespace-init-middle.json")" \
    --argjson init_role "$namespace_init_role" \
    '.creator_task_cookie == $middle_cookie
     and .real_parent_task_cookie == $middle_cookie
     and .real_parent_host_tid == $middle_tid
     and .real_parent_host_tgid == $middle_tgid
     and .root_class == null
     and .installed_role_class == null
     and .active_role_id == $init_role
     and .coordinate_state == 3' \
    "$identity_work/namespace-init-child-before.json" >/dev/null

  kill -TERM "$namespace_middle_host_pid"
  for ((attempt = 0; attempt < 100; attempt++)); do
    [[ ! -d /proc/$namespace_middle_host_pid ]] && break
    sleep 0.1
  done
  [[ ! -d /proc/$namespace_middle_host_pid ]] || {
    echo "PID-namespace middle process did not exit" >&2
    exit 1
  }
  [[ $(awk '/^PPid:/ {print $2}' "/proc/$namespace_child_host_pid/status") == "$namespace_init_pid" ]] || {
    echo "PID-namespace init did not adopt the native child" >&2
    exit 1
  }
  kill -CONT "$namespace_child_host_pid"
  for ((attempt = 0; attempt < 100; attempt++)); do
    [[ $(tr -d '\n' <"/proc/$namespace_child_host_pid/comm" 2>/dev/null || true) == sleep ]] && break
    sleep 0.1
  done
  [[ $(tr -d '\n' <"/proc/$namespace_child_host_pid/comm" 2>/dev/null || true) == sleep ]] || {
    echo "PID-namespace native child did not exec sleep" >&2
    exit 1
  }
  identity_inspect_task namespace-init-child-after "$namespace_child_host_pid" >/dev/null
  if ! jq -e --argjson child_cookie "$namespace_child_cookie" \
    --argjson middle_cookie "$namespace_middle_cookie" \
    --argjson init_tid "$namespace_init_host_tid" \
    --argjson init_tgid "$namespace_init_host_tgid" \
    --argjson child_interval "$namespace_child_interval" \
    --arg child_process "$namespace_child_process" \
    --arg child_execution "$namespace_child_execution" \
    --arg child_image "$namespace_child_image" \
    --argjson init_role "$namespace_init_role" \
    '.task_cookie == $child_cookie
     and .creator_task_cookie == $middle_cookie
     and .real_parent_task_cookie == 0
     and .real_parent_host_tid == $init_tid
     and .real_parent_host_tgid == $init_tgid
     and .real_parent_interval_sequence > $child_interval
     and .process_state_id == $child_process
     and .active_execution_id != $child_execution
     and .image_provenance_id != $child_image
     and .active_role_id == $init_role
     and .root_class == null
     and .installed_role_class == null
     and .coordinate_state == 3
     and .process_execution_state == 2
     and .process_state_vector_state == 2
     and .exec_guard_state == 0' \
    "$identity_work/namespace-init-child-after.json" >/dev/null; then
    echo "PID-namespace child identity did not meet the required limit:" >&2
    cat "$identity_work/namespace-init-child-after.json" >&2
    exit 1
  fi
  identity_pass "PASS: PID-namespace init adoption kept native creator identity and restriction."
  exit 0
fi

if [[ $identity_case_mode == --subreaper ]]; then
  ready_name=.mithril-subreaper-${identity_work##*.}.ready
  ready_host=$identity_k3s_shared_directory/$ready_name
  ready_container=$identity_k3s_container_shared_directory/$ready_name
  release_host=$ready_host.release
  crictl --runtime-endpoint "$identity_runtime_endpoint" exec "$identity_container_id" \
    python3 -c '
import ctypes
import os
import signal
import sys
import time

ready = sys.argv[1]
release = f"{ready}.release"
libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(36, 1, 0, 0, 0) != 0:
    raise OSError(ctypes.get_errno(), "PR_SET_CHILD_SUBREAPER")
middle = os.fork()
if middle == 0:
    child = os.fork()
    if child == 0:
        os.kill(os.getpid(), signal.SIGSTOP)
        os.execv("/bin/sleep", ["/bin/sleep", "300"])
    with open(ready, "w", encoding="ascii") as output:
        output.write(f"{os.getppid()} {os.getpid()} {child}\n")
    while not os.path.exists(release):
        time.sleep(0.1)
    os._exit(0)
while not os.path.exists(ready):
    time.sleep(0.1)
os.waitpid(middle, 0)
with open(ready, encoding="ascii") as input_file:
    _root, _middle, child = input_file.read().split()
os.waitpid(int(child), 0)
' "$ready_container" >"$identity_work/subreaper-client.log" 2>&1 &
  for ((attempt = 0; attempt < 100; attempt++)); do
    [[ -s $ready_host ]] && break
    sleep 0.1
  done
  [[ -s $ready_host ]] || {
    echo "the K3s subreaper fixture did not become ready" >&2
    exit 1
  }
  read -r namespace_root namespace_middle namespace_child <"$ready_host"
  [[ $namespace_root =~ ^[1-9][0-9]*$ && $namespace_middle =~ ^[1-9][0-9]*$ \
    && $namespace_child =~ ^[1-9][0-9]*$ ]] || {
    echo "the K3s subreaper fixture wrote invalid namespace PIDs" >&2
    exit 1
  }
  subreaper_root_pid=
  subreaper_middle_pid=
  subreaper_child_pid=
  for candidate in $(<"$identity_cgroup_path/cgroup.procs"); do
    [[ -r /proc/$candidate/status ]] || continue
    mapped_pid=$(awk '/^NSpid:/ {print $NF}' "/proc/$candidate/status")
    case $mapped_pid in
      "$namespace_root") subreaper_root_pid=$candidate ;;
      "$namespace_middle") subreaper_middle_pid=$candidate ;;
      "$namespace_child") subreaper_child_pid=$candidate ;;
    esac
  done
  [[ $subreaper_root_pid =~ ^[1-9][0-9]*$ \
    && $subreaper_middle_pid =~ ^[1-9][0-9]*$ \
    && $subreaper_child_pid =~ ^[1-9][0-9]*$ ]] || {
    echo "cannot map the K3s subreaper processes to host PIDs" >&2
    exit 1
  }
  identity_task_pids+=("$subreaper_root_pid" "$subreaper_child_pid")
  grep -q $'^State:\tT' "/proc/$subreaper_child_pid/status" || {
    echo "subreaper native child is not stopped before parent exit" >&2
    exit 1
  }
  identity_inspect_task subreaper-root "$subreaper_root_pid" >/dev/null
  identity_inspect_task subreaper-middle "$subreaper_middle_pid" >/dev/null
  identity_inspect_task subreaper-child-before "$subreaper_child_pid" >/dev/null
  subreaper_root_cookie=$(jq -er '.task_cookie' "$identity_work/subreaper-root.json")
  subreaper_middle_cookie=$(jq -er '.task_cookie' "$identity_work/subreaper-middle.json")
  subreaper_child_cookie=$(jq -er '.task_cookie' "$identity_work/subreaper-child-before.json")
  subreaper_child_interval=$(jq -er '.real_parent_interval_sequence' "$identity_work/subreaper-child-before.json")
  subreaper_child_process=$(jq -er '.process_state_id' "$identity_work/subreaper-child-before.json")
  subreaper_child_execution=$(jq -er '.active_execution_id' "$identity_work/subreaper-child-before.json")
  subreaper_child_image=$(jq -er '.image_provenance_id' "$identity_work/subreaper-child-before.json")
  subreaper_root_role=$(jq -er '.active_role_id' "$identity_work/subreaper-root.json")
  subreaper_root_host_tid=$(jq -er '.host_tid' "$identity_work/subreaper-root.json")
  subreaper_root_host_tgid=$(jq -er '.host_tgid' "$identity_work/subreaper-root.json")
  identity_assert_external "$identity_work/subreaper-root.json"
  jq -e --argjson root_cookie "$subreaper_root_cookie" \
    --argjson middle_cookie "$subreaper_middle_cookie" \
    --argjson root_role "$subreaper_root_role" \
    '.creator_task_cookie == $root_cookie
     and .real_parent_task_cookie == $root_cookie
     and .root_class == null
     and .installed_role_class == null
     and .active_role_id == $root_role' \
    "$identity_work/subreaper-middle.json" >/dev/null
  jq -e --argjson middle_cookie "$subreaper_middle_cookie" \
    --argjson root_role "$subreaper_root_role" \
    '.creator_task_cookie == $middle_cookie
     and .real_parent_task_cookie == $middle_cookie
     and .root_class == null
     and .installed_role_class == null
     and .active_role_id == $root_role
     and .coordinate_state == 3' \
    "$identity_work/subreaper-child-before.json" >/dev/null

  : >"$release_host"
  for ((attempt = 0; attempt < 100; attempt++)); do
    [[ ! -d /proc/$subreaper_middle_pid ]] && break
    sleep 0.1
  done
  [[ ! -d /proc/$subreaper_middle_pid ]] || {
    echo "subreaper middle process did not exit" >&2
    exit 1
  }
  kill -CONT "$subreaper_child_pid"
  for ((attempt = 0; attempt < 100; attempt++)); do
    [[ $(tr -d '\n' <"/proc/$subreaper_child_pid/comm" 2>/dev/null || true) == sleep ]] && break
    sleep 0.1
  done
  [[ $(tr -d '\n' <"/proc/$subreaper_child_pid/comm" 2>/dev/null || true) == sleep ]] || {
    echo "subreaper native child did not exec sleep" >&2
    exit 1
  }
  identity_inspect_task subreaper-child-after "$subreaper_child_pid" >/dev/null
  if ! jq -e --argjson child_cookie "$subreaper_child_cookie" \
    --argjson middle_cookie "$subreaper_middle_cookie" \
    --argjson root_host_tid "$subreaper_root_host_tid" \
    --argjson root_host_tgid "$subreaper_root_host_tgid" \
    --argjson child_interval "$subreaper_child_interval" \
    --arg child_process "$subreaper_child_process" \
    --arg child_execution "$subreaper_child_execution" \
    --arg child_image "$subreaper_child_image" \
    --argjson root_role "$subreaper_root_role" \
    '.task_cookie == $child_cookie
     and .creator_task_cookie == $middle_cookie
     and .real_parent_task_cookie == 0
     and .real_parent_host_tid == $root_host_tid
     and .real_parent_host_tgid == $root_host_tgid
     and .real_parent_interval_sequence > $child_interval
     and .process_state_id == $child_process
     and .active_execution_id != $child_execution
     and .image_provenance_id != $child_image
     and .active_role_id == $root_role
     and .root_class == null
     and .installed_role_class == null
     and .coordinate_state == 3
     and .process_execution_state == 2
     and .process_state_vector_state == 2
     and .exec_guard_state == 0' \
    "$identity_work/subreaper-child-after.json" >/dev/null; then
    echo "subreaper child identity did not meet the required limit:" >&2
    cat "$identity_work/subreaper-child-after.json" >&2
    exit 1
  fi
  identity_pass "PASS: subreaper reparenting kept native creator identity and restriction."
  exit 0
fi

if [[ $identity_case_mode == --concurrent-thread-exec ]]; then
  ready_name=.mithril-concurrent-thread-exec-${identity_work##*.}.ready
  ready_host=$identity_k3s_shared_directory/$ready_name
  ready_container=$identity_k3s_container_shared_directory/$ready_name
  crictl --runtime-endpoint "$identity_runtime_endpoint" exec "$identity_container_id" \
    python3 -c '
import os
import signal
import sys
import threading

release = threading.Event()
started = threading.Barrier(3)
racing = threading.Barrier(2)
signal.signal(signal.SIGUSR1, lambda _signal, _frame: release.set())

def execute():
    started.wait()
    release.wait()
    racing.wait()
    os.execv("/bin/sleep", ["/bin/sleep", "300"])

first = threading.Thread(target=execute)
second = threading.Thread(target=execute)
first.start()
second.start()
started.wait()
with open(sys.argv[1], "w", encoding="ascii") as output:
    output.write(f"{os.getpid()}\n")
signal.pause()
first.join()
second.join()
' "$ready_container" >"$identity_work/concurrent-thread-exec-client.log" 2>&1 &
  for ((attempt = 0; attempt < 100; attempt++)); do
    [[ -s $ready_host ]] && break
    sleep 0.1
  done
  [[ -s $ready_host ]] || {
    echo "the K3s concurrent Python workers did not become ready" >&2
    exit 1
  }
  namespace_pid=$(<"$ready_host")
  [[ $namespace_pid =~ ^[1-9][0-9]*$ ]] || {
    echo "the K3s concurrent Python workers wrote an invalid namespace PID" >&2
    exit 1
  }
  root_pid=
  for candidate in $(<"$identity_cgroup_path/cgroup.procs"); do
    [[ -r /proc/$candidate/status ]] || continue
    mapped_pid=$(awk '/^NSpid:/ {print $NF}' "/proc/$candidate/status")
    if [[ $mapped_pid == "$namespace_pid" ]]; then
      root_pid=$candidate
      break
    fi
  done
  [[ $root_pid =~ ^[1-9][0-9]*$ ]] || {
    echo "cannot map the K3s concurrent Python root to a host PID" >&2
    exit 1
  }

  root_task_directory=/proc/$root_pid/task
  thread_paths=("$root_task_directory"/*)
  thread_pids=()
  for thread_path in "${thread_paths[@]}"; do
    candidate=${thread_path##*/}
    [[ $candidate == "$root_pid" ]] || thread_pids+=("$candidate")
  done
  [[ ${#thread_pids[@]} -eq 2 ]] || {
    echo "Python root does not have exactly two concurrent worker threads" >&2
    exit 1
  }
  first_thread_pid=${thread_pids[0]}
  second_thread_pid=${thread_pids[1]}
  [[ $first_thread_pid =~ ^[1-9][0-9]*$ && $second_thread_pid =~ ^[1-9][0-9]*$ \
    && -d /proc/$root_pid/task/$first_thread_pid && -d /proc/$root_pid/task/$second_thread_pid ]] || {
    echo "cannot identify the two concurrent Python worker threads" >&2
    exit 1
  }

  identity_inspect_task concurrent-thread-exec-root "$root_pid" >/dev/null
  root_cookie=$(jq -er '.task_cookie' "$identity_work/concurrent-thread-exec-root.json")
  root_process=$(jq -er '.process_state_id' "$identity_work/concurrent-thread-exec-root.json")
  root_execution=$(jq -er '.active_execution_id' "$identity_work/concurrent-thread-exec-root.json")
  root_image=$(jq -er '.image_provenance_id' "$identity_work/concurrent-thread-exec-root.json")
  root_role=$(jq -er '.active_role_id' "$identity_work/concurrent-thread-exec-root.json")
  identity_assert_external "$identity_work/concurrent-thread-exec-root.json"

  kill -USR1 "$root_pid"
  for ((attempt = 0; attempt < 100; attempt++)); do
    [[ $(tr -d '\n' </proc/$root_pid/comm 2>/dev/null || true) == sleep ]] && break
    sleep 0.1
  done
  [[ $(tr -d '\n' </proc/$root_pid/comm 2>/dev/null || true) == sleep ]] || {
    echo "neither concurrent Python worker exec became sleep" >&2
    exit 1
  }
  identity_inspect_task concurrent-thread-exec-after "$root_pid" >/dev/null
  jq -e --argjson root_cookie "$root_cookie" \
    --arg root_process "$root_process" \
    --arg root_execution "$root_execution" \
    --arg root_image "$root_image" \
    --argjson root_role "$root_role" \
    --argjson root_pid "$root_pid" \
    '.task_cookie != $root_cookie
     and .creator_task_cookie == $root_cookie
     and .process_state_id == $root_process
     and .active_execution_id != $root_execution
     and .image_provenance_id != $root_image
     and .active_role_id == $root_role
     and .root_class == null
     and .installed_role_class == null
     and .host_tid == $root_pid
     and .host_tgid == $root_pid
     and .coordinate_state == 3
     and .process_execution_state == 2
     and .process_state_vector_state == 2
     and .exec_guard_state == 0' \
    "$identity_work/concurrent-thread-exec-after.json" >/dev/null
  identity_pass "PASS: one concurrent Python worker exec kept the process identity and restricted role."
  exit 0
fi

if [[ $identity_case_mode == --thread-exec ]]; then
  if [[ $identity_case_k3s == true ]]; then
    ready_name=.mithril-thread-exec-${identity_work##*.}.ready
    ready_host=$identity_k3s_shared_directory/$ready_name
    ready_container=$identity_k3s_container_shared_directory/$ready_name
    crictl --runtime-endpoint "$identity_runtime_endpoint" exec "$identity_container_id" \
      python3 -c '
import os
import signal
import sys
import threading

release = threading.Event()
signal.signal(signal.SIGUSR1, lambda _signal, _frame: release.set())

def execute():
    with open(sys.argv[1], "w", encoding="ascii") as output:
        output.write(str(os.getpid()))
    release.wait()
    os.execv("/bin/sleep", ["/bin/sleep", "300"])

thread = threading.Thread(target=execute)
thread.start()
signal.pause()
thread.join()
' "$ready_container" >"$identity_work/thread-exec-client.log" 2>&1 &
    for ((attempt = 0; attempt < 100; attempt++)); do
      [[ -s $ready_host ]] && break
      sleep 0.1
    done
    [[ -s $ready_host ]] || {
      echo "the K3s Python worker did not become ready" >&2
      exit 1
    }
    namespace_pid=$(<"$ready_host")
    [[ $namespace_pid =~ ^[1-9][0-9]*$ ]] || {
      echo "the K3s Python worker wrote an invalid namespace PID" >&2
      exit 1
    }
    root_pid=
    for candidate in $(<"$identity_cgroup_path/cgroup.procs"); do
      [[ -r /proc/$candidate/status ]] || continue
      mapped_pid=$(awk '/^NSpid:/ {print $NF}' "/proc/$candidate/status")
      if [[ $mapped_pid == "$namespace_pid" ]]; then
        root_pid=$candidate
        break
      fi
    done
    [[ $root_pid =~ ^[1-9][0-9]*$ ]] || {
      echo "cannot map the K3s Python worker to a host PID" >&2
      exit 1
    }
  else
    echo "This check requires python3 and /bin/sleep in the workload."
    echo "Run in another root terminal:"
    if [[ $identity_mode == docker ]]; then
      printf '  docker exec -it %q sh\n' "$identity_container"
    else
      printf '  crictl --runtime-endpoint %q exec -i %q sh\n' \
        "$identity_runtime_endpoint" "$identity_container_id"
    fi
    cat <<'EOF'
Paste this block into that shell. Do not change the block.

python3 - <<'PY'
import os
import signal
import threading

release = threading.Event()
signal.signal(signal.SIGUSR1, lambda _signal, _frame: release.set())

def execute():
    print("MITHRIL_NONLEADER_READY", flush=True)
    release.wait()
    os.execv("/bin/sleep", ["/bin/sleep", "300"])

thread = threading.Thread(target=execute)
thread.start()
signal.pause()
thread.join()
PY
EOF
    printf 'When MITHRIL_NONLEADER_READY appears, find the Python host PID in %q/cgroup.procs.\n' \
      "$identity_cgroup_path"
    echo "Verify a candidate with: tr '\\0' ' ' </proc/PID/cmdline"
    identity_read_host_pid "Python root host PID: "
    root_pid=$identity_read_pid
  fi
  root_task_directory=/proc/$root_pid/task
  thread_paths=("$root_task_directory"/*)
  [[ ${#thread_paths[@]} -eq 2 ]] || {
    echo "Python root does not have exactly one non-leader thread" >&2
    exit 1
  }
  thread_pid=
  for thread_path in "${thread_paths[@]}"; do
    candidate=${thread_path##*/}
    if [[ $candidate != "$root_pid" ]]; then
      thread_pid=$candidate
      break
    fi
  done
  [[ $thread_pid =~ ^[1-9][0-9]*$ && -d /proc/$root_pid/task/$thread_pid ]] || {
    echo "cannot identify the non-leader Python thread" >&2
    exit 1
  }

  identity_inspect_task thread-exec-root "$root_pid" >/dev/null
  root_cookie=$(jq -er '.task_cookie' "$identity_work/thread-exec-root.json")
  root_process=$(jq -er '.process_state_id' "$identity_work/thread-exec-root.json")
  root_execution=$(jq -er '.active_execution_id' "$identity_work/thread-exec-root.json")
  root_image=$(jq -er '.image_provenance_id' "$identity_work/thread-exec-root.json")
  root_role=$(jq -er '.active_role_id' "$identity_work/thread-exec-root.json")
  identity_assert_external "$identity_work/thread-exec-root.json"

  kill -USR1 "$root_pid"
  for ((attempt = 0; attempt < 100; attempt++)); do
    [[ $(tr -d '\n' </proc/$root_pid/comm 2>/dev/null || true) == sleep ]] && break
    sleep 0.1
  done
  [[ $(tr -d '\n' </proc/$root_pid/comm 2>/dev/null || true) == sleep ]] || {
    echo "the non-leader Python thread did not exec sleep" >&2
    exit 1
  }
  identity_inspect_task thread-exec-after "$root_pid" >/dev/null
  jq -e --argjson root_cookie "$root_cookie" \
    --arg root_process "$root_process" \
    --arg root_execution "$root_execution" \
    --arg root_image "$root_image" \
    --argjson root_role "$root_role" \
    --argjson root_pid "$root_pid" \
    '.task_cookie != $root_cookie
     and .creator_task_cookie == $root_cookie
     and .process_state_id == $root_process
     and .active_execution_id != $root_execution
     and .image_provenance_id != $root_image
     and .active_role_id == $root_role
     and .root_class == null
     and .installed_role_class == null
     and .host_tid == $root_pid
     and .host_tgid == $root_pid
     and .coordinate_state == 3
     and .process_execution_state == 2
     and .process_state_vector_state == 2
     and .exec_guard_state == 0' \
    "$identity_work/thread-exec-after.json" >/dev/null
  identity_pass "PASS: a non-leader Python thread exec kept the process identity and role."
  exit 0
fi

if [[ ${3:-} == --orphan ]]; then
  echo "Run in another root terminal:"
  identity_print_runtime_exec '(read child_pid _ < /proc/self/stat; kill -STOP "$child_pid"; exec sleep 300) & wait'
  echo "Enter that shell's host PID, then its stopped child host PID."
  identity_read_host_pid "shell host PID: "
  parent_pid=$identity_read_pid
  identity_read_host_pid "stopped native child host PID: "
  child_pid=$identity_read_pid
  identity_inspect_task orphan-native-parent "$parent_pid"
  identity_inspect_task orphan-native-child-before "$child_pid"

  parent_cookie=$(jq -er '.task_cookie' "$identity_work/orphan-native-parent.json")
  parent_role=$(jq -er '.active_role_id' "$identity_work/orphan-native-parent.json")
  child_cookie=$(jq -er '.task_cookie' "$identity_work/orphan-native-child-before.json")
  child_creator=$(jq -er '.creator_task_cookie' "$identity_work/orphan-native-child-before.json")
  child_real_parent=$(jq -er '.real_parent_task_cookie' "$identity_work/orphan-native-child-before.json")
  child_interval=$(jq -er '.real_parent_interval_sequence' "$identity_work/orphan-native-child-before.json")
  [[ $parent_cookie == "$child_creator" && $parent_cookie == "$child_real_parent" ]] || {
    echo "native child does not name the exact live creator" >&2
    exit 1
  }

  echo "In another root terminal, run: kill -KILL $parent_pid"
  read -r -p "Press Enter after the creator has exited: " _
  for ((attempt = 0; attempt < 100; attempt++)); do
    [[ ! -d /proc/$parent_pid ]] && break
    sleep 0.1
  done
  [[ ! -d /proc/$parent_pid ]] || {
    echo "creator task is still live" >&2
    exit 1
  }
  kill -CONT "$child_pid"
  for ((attempt = 0; attempt < 100; attempt++)); do
    [[ $(tr -d '\n' </proc/$child_pid/comm 2>/dev/null || true) == sleep ]] && break
    sleep 0.1
  done
  [[ $(tr -d '\n' </proc/$child_pid/comm 2>/dev/null || true) == sleep ]] || {
    echo "native child did not exec sleep after the creator exited" >&2
    exit 1
  }
  identity_inspect_task orphan-native-child-after "$child_pid"
  jq -e --argjson parent_cookie "$parent_cookie" \
    --argjson parent_role "$parent_role" \
    --argjson child_cookie "$child_cookie" \
    --argjson child_interval "$child_interval" \
    '.task_cookie == $child_cookie
     and .creator_task_cookie == $parent_cookie
     and .real_parent_task_cookie != $parent_cookie
     and .real_parent_interval_sequence > $child_interval
     and .root_class == null
     and .installed_role_class == null
     and .active_role_id == $parent_role' \
    "$identity_work/orphan-native-child-after.json" >/dev/null
  identity_pass "PASS: creator identity stayed exact after parent exit and the real-parent interval changed."
  exit 0
fi

echo "Run in another root terminal:"
identity_print_runtime_exec 'sleep 300 & wait'
echo "Enter that shell's host PID, then its sleep child's host PID."
identity_read_host_pid "shell host PID: "
parent_pid=$identity_read_pid
identity_read_host_pid "native child host PID: "
child_pid=$identity_read_pid
identity_inspect_task native-parent "$parent_pid"
identity_inspect_task native-child "$child_pid"

parent_cookie=$(jq -er '.task_cookie' "$identity_work/native-parent.json")
child_creator=$(jq -er '.creator_task_cookie' "$identity_work/native-child.json")
[[ $parent_cookie == "$child_creator" ]] || {
  echo "native child creator edge does not name the actual parent" >&2
  exit 1
}
jq -e '.root_class == null and .installed_role_class == null' \
  "$identity_work/native-child.json" >/dev/null
identity_pass "PASS: native child names its actual creator and is not an external root"
