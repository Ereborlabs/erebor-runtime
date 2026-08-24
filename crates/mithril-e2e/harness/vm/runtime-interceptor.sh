#!/usr/bin/env bash

set -Eeuo pipefail

usage() {
  echo "usage: $0 {install-and-run STAGE PIN_ROOT RESULT KEEP_VM|probe}" >&2
}

require_root() {
  [[ $(id -u) -eq 0 ]] || {
    echo "Runtime Interceptor VM proof requires root" >&2
    exit 2
  }
}

require_command() {
  command -v "$1" >/dev/null || {
    echo "Runtime Interceptor VM proof requires command: $1" >&2
    exit 2
  }
}

install_and_run() {
  (($# == 4)) || { usage; exit 2; }
  local stage=$1
  local pin_root=$2
  local result=$3
  local keep_vm=$4
  require_root
  [[ $keep_vm == true || $keep_vm == false ]] || {
    echo "Runtime Interceptor VM retention mode is invalid: $keep_vm" >&2
    exit 2
  }
  [[ $stage =~ ^/var/tmp/(mithril-vm-[a-z0-9]+(-[a-z0-9]+)*)/runtime-interceptor$ ]] || {
    echo "Runtime Interceptor VM stage is invalid: $stage" >&2
    exit 2
  }
  local vm_name=${BASH_REMATCH[1]}
  [[ ! -L $stage && $(readlink -f -- "$stage") == "$stage" \
    && -d $stage/bin && -d $stage/scripts \
    && -f $stage/source-state && ! -L $stage/source-state \
    && $result == "$stage/runtime-interceptor-physical-proof.json" \
    && ! -e $result && ! -L $result \
    && $pin_root == "/sys/fs/bpf/$vm_name-runtime" ]] || {
    echo "Runtime Interceptor VM stage or pin root is invalid" >&2
    exit 2
  }

  install -D -m 0755 "$stage/bin/erebord" /usr/lib/erebor/erebord
  install -D -m 0755 "$stage/bin/erebor" /usr/local/bin/erebor
  install -D -m 0755 "$stage/bin/erebor-path-broker" \
    /usr/libexec/erebor/erebor-path-broker
  install -D -m 0755 "$stage/bin/erebor-linux-session-controller" \
    /usr/libexec/erebor/erebor-linux-session-controller
  install -D -m 0755 "$stage/bin/codex-v1-fixture" \
    /usr/lib/erebor/codex-v1-fixture
  install -D -m 0755 "$stage/bin/runtime-file-probe" \
    /usr/lib/erebor/runtime-file-probe
  install -D -m 0444 "$stage/source-state" \
    /usr/local/lib/erebor/runtime-interceptor-source-state
  install -D -m 0755 "$stage/scripts/daemon-systemd-control-plane.sh" \
    /usr/local/lib/erebor/daemon-systemd-control-plane.sh
  install -D -m 0755 "$stage/scripts/runtime-interceptor.sh" \
    /usr/local/lib/erebor/runtime-interceptor-vm.sh
  install -D -m 0644 "$stage/erebord.service" \
    /etc/systemd/system/erebord.service
  systemctl daemon-reload

  EREBOR_RUNTIME_INTERCEPTOR_PROBE=1 \
  EREBOR_RUNTIME_INTERCEPTOR_PIN_ROOT=$pin_root \
  EREBOR_RUNTIME_INTERCEPTOR_RESULT=$result \
  EREBOR_RUNTIME_INTERCEPTOR_KEEP_VM=$keep_vm \
    bash /usr/local/lib/erebor/daemon-systemd-control-plane.sh
  [[ -s $result ]] || {
    echo "Runtime Interceptor VM proof did not write its result" >&2
    exit 1
  }
}

as_user() {
  local user=$1
  shift
  runuser -u "$user" -- "$erebor" "$@"
}

await_daemon() {
  local last_error=
  for _ in $(seq 1 200); do
    if last_error=$("$erebor" daemon status 2>&1); then
      return
    fi
    if systemctl is-failed --quiet erebord.service; then
      break
    fi
    sleep 0.1
  done
  systemctl status erebord.service --no-pager >&2 || true
  journalctl -u erebord.service --no-pager >&2 || true
  echo "$last_error" >&2
  echo "Runtime Interceptor daemon did not become ready" >&2
  exit 1
}

await_restarted_daemon() {
  local previous_pid=$1
  local current_pid=
  for _ in $(seq 1 300); do
    current_pid=$(systemctl show --property=MainPID --value erebord.service)
    if [[ $current_pid =~ ^[1-9][0-9]*$ && $current_pid != "$previous_pid" ]] \
      && "$erebor" daemon status >/dev/null 2>&1; then
      return
    fi
    sleep 0.1
  done
  systemctl status erebord.service --no-pager >&2 || true
  journalctl -u erebord.service --no-pager >&2 || true
  echo "Runtime Interceptor daemon did not restart after SIGKILL" >&2
  exit 1
}

snapshot_sessions() {
  local destination=$1
  local root="/var/lib/erebor/users/$client_uid/sessions"
  if [[ -d $root ]]; then
    find "$root" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort >"$destination"
  else
    : >"$destination"
  fi
}

capture_new_session() {
  local before=$1
  local after=$lane_root/sessions-after
  local -a sessions=()
  for _ in $(seq 1 200); do
    snapshot_sessions "$after"
    mapfile -t sessions < <(comm -13 "$before" "$after")
    if ((${#sessions[@]} == 1)); then
      captured_session=${sessions[0]}
      return
    fi
    if ((${#sessions[@]} > 1)); then
      echo "Runtime Interceptor case created more than one session" >&2
      exit 1
    fi
    sleep 0.1
  done
  echo "Runtime Interceptor case did not create a session" >&2
  exit 1
}

session_record() {
  printf '/var/lib/erebor/users/%s/sessions/%s/session.json\n' \
    "$client_uid" "$1"
}

session_state() {
  python3 - "$(session_record "$1")" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    print(json.load(source)["state"])
PY
}

await_state() {
  local session=$1
  local expected=$2
  local state=
  for _ in $(seq 1 200); do
    state=$(session_state "$session" 2>/dev/null || true)
    if [[ ,$expected, == *,$state,* ]]; then
      return
    fi
    sleep 0.1
  done
  echo "session $session reached $state, expected $expected" >&2
  exit 1
}

binding_path() {
  python3 - "$1" <<'PY'
import glob
import json
import sys

session = sys.argv[1]
matches = []
for path in glob.glob("/var/lib/erebor/runtime-interceptor/bindings/*.json"):
    with open(path, encoding="utf-8") as source:
        if json.load(source)["session_id"] == session:
            matches.append(path)
if len(matches) != 1:
    raise SystemExit(f"session {session} has {len(matches)} Runtime Interceptor bindings")
print(matches[0])
PY
}

binding_value() {
  python3 - "$1" "$2" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    value = json.load(source)
for component in sys.argv[2].split("."):
    value = value[component]
if isinstance(value, bool):
    print(str(value).lower())
elif value is None:
    print("null")
else:
    print(value)
PY
}

await_binding_status() {
  local binding=$1
  local expected=$2
  local status=
  for _ in $(seq 1 200); do
    status=$(binding_value "$binding" status 2>/dev/null || true)
    [[ $status == "$expected" ]] && return
    sleep 0.1
  done
  echo "Runtime Interceptor binding reached $status, expected $expected" >&2
  exit 1
}

binding_count() {
  find /var/lib/erebor/runtime-interceptor/bindings -name '*.json' -type f 2>/dev/null \
    | wc -l | tr -d ' '
}

active_binding_count() {
  python3 - <<'PY'
import glob
import json

active = 0
for path in glob.glob("/var/lib/erebor/runtime-interceptor/bindings/*.json"):
    with open(path, encoding="utf-8") as source:
        active += json.load(source)["status"] == "active"
print(active)
PY
}

workload_absent() {
  local session=$1
  local environment=
  for environment in /proc/[0-9]*/environ; do
    if tr '\0' '\n' <"$environment" 2>/dev/null \
      | grep -Fxq "EREBOR_SESSION_ID=$session"; then
      return 1
    fi
  done
}

await_workload_absent() {
  local session=$1
  for _ in $(seq 1 200); do
    workload_absent "$session" && return
    sleep 0.1
  done
  echo "session $session retained a workload process" >&2
  exit 1
}

await_cgroup_population() {
  local cgroup=$1
  local destination=$2
  for _ in $(seq 1 200); do
    if [[ -r $cgroup/cgroup.procs ]]; then
      sort -n "$cgroup/cgroup.procs" >"$destination"
      if [[ $(wc -l <"$destination") -ge 2 ]]; then
        return
      fi
    fi
    sleep 0.1
  done
  echo "workload cgroup did not retain the fixture and its descendant" >&2
  exit 1
}

await_processes_absent() {
  local processes=$1
  local pid=
  for _ in $(seq 1 200); do
    local any=false
    while IFS= read -r pid; do
      [[ -n $pid && -e /proc/$pid ]] && any=true
    done <"$processes"
    [[ $any == false ]] && return
    sleep 0.1
  done
  echo "a workload descendant remained after session cleanup" >&2
  exit 1
}

initialize_frame() {
  printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize"}'
}

command_frame() {
  python3 - "$1" "$2" <<'PY'
import json
import sys

print(json.dumps({
    "jsonrpc": "2.0",
    "id": int(sys.argv[1]),
    "method": "fixture/command",
    "params": {"command": sys.argv[2]},
}, separators=(",", ":")))
PY
}

run_app_server_case() {
  local label=$1
  local policy=$2
  shift 2
  local before=$lane_root/$label-sessions-before
  local output=$lane_root/$label-output.jsonl
  local index=10
  snapshot_sessions "$before"
  {
    initialize_frame
    for command in "$@"; do
      command_frame "$index" "$command"
      index=$((index + 1))
    done
  } | timeout 60s runuser -u "$client_user" -- "$erebor" run \
    --policy "$policy" \
    --workspace "/home/$client_user" --app-server "$agent_name" \
    >"$output" 2>&1
  capture_new_session "$before"
  case_session=$captured_session
  await_state "$case_session" succeeded
  case_binding=$(binding_path "$case_session")
  await_binding_status "$case_binding" tombstoned
  local cgroup
  cgroup=$(binding_value "$case_binding" cgroup_path)
  [[ ! -e $cgroup ]]
  await_workload_absent "$case_session"
  fact "${label}_session" "$case_session"
  fact "${label}_binding" "$case_binding"
}

run_file_probe_denial_case() {
  local label=$1
  local policy=$2
  local agent=$3
  local input=$4
  local before=$lane_root/$label-sessions-before
  local output=$lane_root/$label-output.txt
  local command="stty rows 24 cols 80; exec $erebor run --policy $policy --workspace /home/$client_user $agent"
  snapshot_sessions "$before"
  if [[ -n $input ]]; then
    printf '%s' "$input" | timeout 30s runuser -u "$client_user" -- \
      script -qefc "$command" /dev/null >"$output" 2>&1 || true
  else
    timeout 30s runuser -u "$client_user" -- \
      script -qefc "$command" /dev/null </dev/null >"$output" 2>&1 || true
  fi
  capture_new_session "$before"
  case_session=$captured_session
  await_state "$case_session" failed
  case_binding=$(binding_path "$case_session")
  await_binding_status "$case_binding" tombstoned
  local cgroup
  cgroup=$(binding_value "$case_binding" cgroup_path)
  [[ ! -e $cgroup ]]
  await_workload_absent "$case_session"
  fact "${label}_session" "$case_session"
  fact "${label}_binding" "$case_binding"
}

start_long_session() {
  local label=$1
  local policy=$2
  local command=$3
  local before=$lane_root/$label-sessions-before
  long_fifo=$lane_root/$label-input.fifo
  long_output=$lane_root/$label-output.jsonl
  long_processes=$lane_root/$label-processes.txt
  snapshot_sessions "$before"
  mkfifo "$long_fifo"
  timeout 180s runuser -u "$client_user" -- "$erebor" run \
    --policy "$policy" --workspace "/home/$client_user" \
    --app-server "$agent_name" <"$long_fifo" >"$long_output" 2>&1 &
  long_client_pid=$!
  exec {long_writer}>"$long_fifo"
  initialize_frame >&"$long_writer"
  command_frame 10 "$command" >&"$long_writer"
  capture_new_session "$before"
  long_session=$captured_session
  await_state "$long_session" running
  long_binding=$(binding_path "$long_session")
  await_binding_status "$long_binding" active
  long_cgroup=$(binding_value "$long_binding" cgroup_path)
  await_cgroup_population "$long_cgroup" "$long_processes"
  fact "${label}_session" "$long_session"
  fact "${label}_binding" "$long_binding"
}

close_long_session_client() {
  exec {long_writer}>&-
  wait "$long_client_pid" || true
  rm -f -- "$long_fifo"
}

collect_evidence() {
  local label=$1
  local session=$2
  local destination=$lane_root/$label-evidence.txt
  local page=$lane_root/$label-evidence-page.txt
  local after_sequence=0
  local cursor=
  local record_count=
  local summary=
  : >"$destination"
  for _ in $(seq 1 64); do
    as_user "$client_user" audit evidence-trace "$session" \
      --after-sequence "$after_sequence" --maximum-records 256 >"$page"
    summary=$(python3 - "$page" "$session" "$after_sequence" <<'PY'
import re
import sys

path, session, after = sys.argv[1], sys.argv[2], int(sys.argv[3])
with open(path, encoding="utf-8") as source:
    lines = source.read().splitlines()
if not lines:
    raise SystemExit("evidence page is empty")
end = re.fullmatch(
    r"durable_cursor=([0-9]+) truncated_before_cursor=(true|false)",
    lines[-1],
)
if end is None or end.group(2) != "false":
    raise SystemExit("evidence page has an invalid or truncated cursor")
cursor = int(end.group(1))
expected = after + 1
for line in lines[:-1]:
    record = re.match(
        r"session_id=([^ ]+) sequence=([0-9]+) "
        r"timestamp_unix_ms=[0-9]+ source=[^ ]+ payload=",
        line,
    )
    if record is None or record.group(1) != session:
        raise SystemExit("evidence page has an invalid session record")
    sequence = int(record.group(2))
    if sequence != expected:
        raise SystemExit("evidence page has a missing or repeated sequence")
    expected += 1
records = len(lines) - 1
expected_cursor = after if records == 0 else expected - 1
if cursor != expected_cursor:
    raise SystemExit("evidence page cursor does not match its last record")
print(records, cursor)
PY
)
    read -r record_count cursor <<<"$summary"
    grep '^session_id=' "$page" >>"$destination" || true
    if ((record_count < 256)); then
      tail -n 1 "$page" >>"$destination"
      rm -f -- "$page"
      return
    fi
    [[ $cursor -gt $after_sequence ]]
    after_sequence=$cursor
  done
  echo "Runtime Interceptor evidence exceeded 64 pages" >&2
  exit 1
}

assert_normal_coverage() {
  python3 - "$1" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    record = json.load(source)
coverage = record["evidence_coverage"]
assert record["status"] == "tombstoned"
assert record["failure"] is None
assert coverage["recovery"] is False
assert coverage["complete"] is True
assert coverage["route"]["processed"] == coverage["route"]["persisted"]
assert coverage["route"]["parse_failures"] == 0
assert coverage["route"]["write_failures"] == 0
PY
}

assert_operation_decisions() {
  local binding=$1
  shift
  python3 - "$binding" "$@" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    record = json.load(source)
rows = record["operation_decisions"]
decisions = {
    (row["effect_family"], row["operation"]): row["deny"]
    for row in rows
}
expected = {
    1: {1, 9, 10},
    2: {2, 3, 4, 5, 7, 8, 10, 16, 17, 18, 25, 26, 39},
    3: {12, 13, 32, 33, 34, 35, 36, 37, 38},
    4: {6},
    5: {14, 15, 23, 24, 27, 28, 29, 30, 31},
    6: {11},
    7: {19, 20, 21, 22},
}
expected_pairs = {
    (family, operation)
    for family, operations in expected.items()
    for operation in operations
}
assert len(rows) == 40
assert len(decisions) == 40
assert decisions.keys() == expected_pairs
for expectation in sys.argv[2:]:
    key, denied = expectation.split("=", 1)
    family, operation = map(int, key.split(":", 1))
    assert decisions[(family, operation)] is (denied == "true")
PY
}

fact() {
  printf '%s=%s\n' "$1" "$2" >>"$facts"
}

record_artifact() {
  local name=$1
  local path=$2
  fact "${name}_sha256" "$(sha256sum "$path" | awk '{print $1}')"
}

report_probe_failure() {
  local status=$?
  local command=$BASH_COMMAND
  local line=${BASH_LINENO[0]}
  trap - ERR
  {
    printf 'status=%s\n' "$status"
    printf 'line=%s\n' "$line"
    printf 'command=%s\n' "$command"
  } >"$lane_root/failure.txt"
  echo "Runtime Interceptor probe failed at line $line: $command" >&2
}

copy_bounded_failure_file() {
  local source=$1
  local destination=$2
  local size
  [[ -f $source && ! -L $source ]] || return 0
  size=$(stat -c %s -- "$source") || return 0
  install -d -m 0700 "$(dirname -- "$destination")"
  if ((size <= 1048576)); then
    install -m 0600 "$source" "$destination"
  else
    head -c 1048576 -- "$source" >"$destination"
    chmod 0600 "$destination"
    printf 'source_bytes=%s captured_bytes=1048576\n' "$size" \
      >"$destination.truncated"
  fi
}

collect_failure_state() {
  local destination=$1
  local session_root=$2
  local binding_root=$3
  local count=0
  local name
  local path
  install -d -m 0700 "$destination/sessions" "$destination/bindings"
  if [[ -d $session_root && ! -L $session_root ]]; then
    while IFS= read -r path; do
      if ((count >= 32)); then
        printf '%s\n' 'Only the first 32 session directories were captured.' \
          >"$destination/sessions.limit"
        break
      fi
      name=${path##*/}
      copy_bounded_failure_file "$path/session.json" \
        "$destination/sessions/$name/session.json"
      copy_bounded_failure_file \
        "$path/output/linux-controller-diagnostics.log" \
        "$destination/sessions/$name/linux-controller-diagnostics.log"
      count=$((count + 1))
    done < <(find "$session_root" -mindepth 1 -maxdepth 1 -type d | sort)
  fi
  count=0
  if [[ -d $binding_root && ! -L $binding_root ]]; then
    while IFS= read -r path; do
      if ((count >= 32)); then
        printf '%s\n' 'Only the first 32 binding records were captured.' \
          >"$destination/bindings.limit"
        break
      fi
      name=${path##*/}
      copy_bounded_failure_file "$path" "$destination/bindings/$name"
      count=$((count + 1))
    done < <(find "$binding_root" -mindepth 1 -maxdepth 1 \
      -name '*.json' -type f | sort)
  fi
}

probe() {
  (($# == 0)) || { usage; exit 2; }
  require_root
  for command in cmp head python3 runuser script sha256sum stty systemctl tar; do
    require_command "$command"
  done
  erebor=/usr/local/bin/erebor
  fixture=/usr/lib/erebor/codex-v1-fixture
  runtime_file_probe=/usr/lib/erebor/runtime-file-probe
  source_state=/usr/local/lib/erebor/runtime-interceptor-source-state
  config_path=/etc/erebor/erebord.json
  trust_root=/usr/lib/erebor/codex-v1-fixture-trust
  client_user=${EREBOR_INSTALLED_SESSION_USER:?first session user is required}
  client_uid=$(id -u "$client_user")
  client_gid=$(id -g "$client_user")
  pin_root=${EREBOR_RUNTIME_INTERCEPTOR_PIN_ROOT:?pin root is required}
  result=${EREBOR_RUNTIME_INTERCEPTOR_RESULT:?result path is required}
  keep_vm=${EREBOR_RUNTIME_INTERCEPTOR_KEEP_VM:?VM retention mode is required}
  [[ $keep_vm == true || $keep_vm == false ]]
  [[ -x $runtime_file_probe && -r $source_state ]]
  [[ $result =~ ^/var/tmp/(mithril-vm-[a-z0-9]+(-[a-z0-9]+)*)/runtime-interceptor/runtime-interceptor-physical-proof.json$ ]] || {
    echo "Runtime Interceptor result path is invalid: $result" >&2
    exit 2
  }
  local vm_name=${BASH_REMATCH[1]}
  [[ $pin_root == "/sys/fs/bpf/$vm_name-runtime" ]] || {
    echo "Runtime Interceptor pin root does not match its VM: $pin_root" >&2
    exit 2
  }
  lane_root=$(dirname -- "$result")/runtime-interceptor-proof
  facts=$lane_root/facts.txt
  agent_name=runtime-codex
  socket_port=39183
  file_target=/tmp/erebor-runtime-interceptor-file-$client_uid
  install -d -m 0700 "$lane_root"
  : >"$facts"

  trap report_probe_failure ERR

  cleanup_probe() {
    local status=$?
    trap - EXIT ERR
    [[ -z ${socket_server_pid:-} ]] || kill "$socket_server_pid" >/dev/null 2>&1 || true
    rm -f -- "$file_target" "${runtime_file_open_target:-}" \
      "${runtime_file_read_target:-}" "${runtime_file_mutation_target:-}" \
      "${long_fifo:-}"
    if [[ $status -ne 0 ]]; then
      local failure_archive
      systemctl status erebord.service --no-pager \
        >"$lane_root/erebord-status.txt" 2>&1 || true
      journalctl -u erebord.service --no-pager \
        >"$lane_root/erebord-journal.txt" 2>&1 || true
      cat "$lane_root/erebord-status.txt" >&2 || true
      cat "$lane_root/erebord-journal.txt" >&2 || true
      collect_failure_state "$lane_root/durable-state" \
        "/var/lib/erebor/users/$client_uid/sessions" \
        /var/lib/erebor/runtime-interceptor/bindings || true
      failure_archive=$(dirname -- "$result")/runtime-interceptor-failure.tar.gz
      if tar -C "$lane_root" -czf "$failure_archive" .; then
        echo "Runtime Interceptor failure evidence: $failure_archive" >&2
      else
        echo "Runtime Interceptor failure evidence could not be archived" >&2
      fi
    fi
    exit "$status"
  }
  trap cleanup_probe EXIT

  local group_gid
  local fixture_output
  local package_name
  local runtime_file_open_package
  local runtime_file_read_package
  local runtime_file_mutation_package
  local runtime_file_open_target
  local runtime_file_read_target
  local runtime_file_mutation_target
  local runtime_policy_root
  group_gid=$(stat -c %g /run/erebor/daemon.sock)
  fixture_output=$("$fixture" configure \
    --config "$config_path" \
    --trust-root "$trust_root" \
    --socket-group-gid "$group_gid" \
    --linux-runner-containment systemd \
    --runtime-file-probe "$runtime_file_probe" \
    --owner-uid "$client_uid")
  package_name=$(sed -n 's/^package_name=//p' <<<"$fixture_output")
  runtime_policy_root=$(sed -n 's/^runtime_policy_root=//p' <<<"$fixture_output")
  runtime_file_open_package=$(sed -n 's/^runtime_file_open_package=//p' \
    <<<"$fixture_output")
  runtime_file_open_target=$(sed -n 's/^runtime_file_open_target=//p' \
    <<<"$fixture_output")
  runtime_file_read_package=$(sed -n 's/^runtime_file_read_package=//p' \
    <<<"$fixture_output")
  runtime_file_read_target=$(sed -n 's/^runtime_file_read_target=//p' \
    <<<"$fixture_output")
  runtime_file_mutation_package=$(sed -n \
    's/^runtime_file_mutation_package=//p' <<<"$fixture_output")
  runtime_file_mutation_target=$(sed -n \
    's/^runtime_file_mutation_target=//p' <<<"$fixture_output")
  [[ -n $package_name && -d $runtime_policy_root \
    && $runtime_file_open_package == runtime-file-open-probe \
    && $runtime_file_open_target == /tmp/erebor-runtime-file-open-target \
    && $runtime_file_read_package == runtime-file-read-probe \
    && $runtime_file_read_target == /tmp/erebor-runtime-file-read-target \
    && $runtime_file_mutation_package == runtime-file-mutation-probe \
    && $runtime_file_mutation_target == /tmp/erebor-runtime-file-mutation-target ]]
  python3 - "$config_path" "$pin_root" <<'PY'
import json
import sys

path, pin_root = sys.argv[1:]
with open(path, encoding="utf-8") as source:
    config = json.load(source)
config["linux_runner"]["interceptor"] = {
    "runtime_btf_path": "/sys/kernel/btf/vmlinux",
    "lease_path": "/var/lib/erebor/runtime-interceptor.owner.lock",
    "pin_root": pin_root,
}
with open(path, "w", encoding="utf-8") as destination:
    json.dump(config, destination, separators=(",", ":"))
    destination.write("\n")
PY
  chown root:root "$config_path"
  chmod 0640 "$config_path"
  systemctl restart erebord.service
  await_daemon
  [[ $(systemctl show --property=Delegate --value erebord.service) == yes ]]
  [[ -d $pin_root/maps && -d $pin_root/links ]]

  local user_fixture="/home/$client_user/codex-v1-fixture"
  local user_file_probe="/home/$client_user/runtime-file-probe"
  install -o "$client_user" -g "$client_gid" -m 0755 "$fixture" "$user_fixture"
  install -o "$client_user" -g "$client_gid" -m 0755 \
    "$runtime_file_probe" "$user_file_probe"
  as_user "$client_user" agent load "$package_name" --from "$user_fixture" \
    --adapter codex-v1 --name "$agent_name" | grep -q "agent=$agent_name"
  as_user "$client_user" agent load "$runtime_file_open_package" \
    --from "$user_file_probe" --adapter codex-v1 \
    --name "$runtime_file_open_package" \
    | grep -q "agent=$runtime_file_open_package"
  as_user "$client_user" agent load "$runtime_file_read_package" \
    --from "$user_file_probe" --adapter codex-v1 \
    --name "$runtime_file_read_package" \
    | grep -q "agent=$runtime_file_read_package"
  as_user "$client_user" agent load "$runtime_file_mutation_package" \
    --from "$user_file_probe" --adapter codex-v1 \
    --name "$runtime_file_mutation_package" \
    | grep -q "agent=$runtime_file_mutation_package"
  local policy
  for policy in \
    runtime-allow-all runtime-deny-exec runtime-deny-file-open \
    runtime-deny-file-read runtime-deny-file-mutation \
    runtime-deny-socket-connect runtime-dynamic-reject; do
    as_user "$client_user" policy package apply "$runtime_policy_root/$policy" \
      --name "$policy" --idempotency-key "runtime-physical-package-$policy" \
      | grep -q "policyPackage=$policy"
    as_user "$client_user" policyset create --name "$policy" --package "$policy" \
      --idempotency-key "runtime-physical-policyset-$policy" \
      | grep -q "policySet=$policy"
  done
  install -d -o "$client_user" -g "$client_gid" -m 0700 "/home/$client_user/.codex"
  printf '%s' fixture-private-state >"/home/$client_user/.codex/erebor-phase53-state-marker"
  chown "$client_user:$client_gid" \
    "/home/$client_user/.codex/erebor-phase53-state-marker"
  chmod 0600 "/home/$client_user/.codex/erebor-phase53-state-marker"

  python3 -m http.server "$socket_port" --bind 127.0.0.1 \
    >"$lane_root/socket-server.log" 2>&1 &
  socket_server_pid=$!
  for _ in $(seq 1 100); do
    python3 - "$socket_port" <<'PY' >/dev/null 2>&1 && break
import socket
import sys
with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=0.1):
    pass
PY
    sleep 0.1
  done
  kill -0 "$socket_server_pid"

  run_app_server_case allow_effects runtime-allow-all \
    "printf runtime-file > '$file_target' && test \"\$(cat '$file_target')\" = runtime-file && printf file-allowed" \
    "/bin/bash -c 'exec 3<>/dev/tcp/127.0.0.1/$socket_port' && printf socket-allowed"
  grep -q 'file-allowed' "$lane_root/allow_effects-output.jsonl"
  grep -q 'socket-allowed' "$lane_root/allow_effects-output.jsonl"
  collect_evidence allow_effects "$case_session"
  assert_normal_coverage "$case_binding"
  assert_operation_decisions "$case_binding" \
    1:1=false 1:9=false 1:10=false 2:4=false 2:5=false 2:10=false \
    2:39=false 3:12=false
  fact allow_static_five_classes true
  fact pipe_transport true

  start_long_session stop_descendants runtime-allow-all "sleep 300"
  local controller_cgroup
  local controller_id
  local workload_id
  controller_cgroup=$(dirname -- "$long_cgroup")
  controller_id=$(binding_value "$long_binding" controller_cgroup_id)
  workload_id=$(binding_value "$long_binding" cgroup_id)
  [[ $long_cgroup != "$controller_cgroup" \
    && $controller_id != "$workload_id" \
    && $(stat -Lc %i "$long_cgroup") == "$workload_id" \
    && $(stat -Lc %i "$controller_cgroup") == "$controller_id" ]]
  fact cgroup_separation true
  fact cgroup_path "$long_cgroup"
  fact controller_cgroup_path "$controller_cgroup"
  fact workload_cgroup_id "$workload_id"
  fact controller_cgroup_id "$controller_id"
  as_user "$client_user" session stop "$long_session" --grace-seconds 1 \
    --idempotency-key runtime-physical-stop >/dev/null
  close_long_session_client
  await_state "$long_session" succeeded,failed,interrupted
  await_binding_status "$long_binding" tombstoned
  [[ ! -e $long_cgroup ]]
  await_processes_absent "$long_processes"
  collect_evidence stop_descendants "$long_session"
  assert_normal_coverage "$long_binding"
  fact stop_descendants true

  start_long_session kill_descendants runtime-allow-all "sleep 300"
  as_user "$client_user" session kill "$long_session" --signal kill \
    --idempotency-key runtime-physical-kill >/dev/null
  close_long_session_client
  await_state "$long_session" succeeded,failed,interrupted
  await_binding_status "$long_binding" tombstoned
  [[ ! -e $long_cgroup ]]
  await_processes_absent "$long_processes"
  collect_evidence kill_descendants "$long_session"
  assert_normal_coverage "$long_binding"
  fact kill_descendants true

  local before=$lane_root/pty-sessions-before
  local pty_output=$lane_root/pty-output.txt
  snapshot_sessions "$before"
  as_user "$client_user" run --policy runtime-allow-all \
    --workspace "/home/$client_user" "$agent_name" -d \
    >"$lane_root/pty-create.txt" 2>&1
  capture_new_session "$before"
  local pty_session=$captured_session
  await_state "$pty_session" running
  printf 'exit\n' | timeout 30s runuser -u "$client_user" -- script -qefc \
    "$erebor session attach $pty_session --input --client-instance-id runtime-pty --idempotency-key runtime-pty-attach" \
    /dev/null >"$pty_output" 2>&1
  grep -q 'fixture-tty=ready' "$pty_output"
  grep -q 'fixture-tty-size=' "$pty_output"
  await_state "$pty_session" succeeded
  local pty_binding
  pty_binding=$(binding_path "$pty_session")
  await_binding_status "$pty_binding" tombstoned
  fact pty_session "$pty_session"
  fact pty_binding "$pty_binding"
  collect_evidence pty "$pty_session"
  assert_normal_coverage "$pty_binding"
  fact pty_transport true

  printf '%s' runtime-file-open-target >"$runtime_file_open_target"
  printf '%s' runtime-file-read-target >"$runtime_file_read_target"
  printf '%s' runtime-file-mutation-sentinel >"$runtime_file_mutation_target"
  chown "$client_user:$client_gid" \
    "$runtime_file_open_target" "$runtime_file_read_target" \
    "$runtime_file_mutation_target"
  chmod 0600 "$runtime_file_open_target" "$runtime_file_read_target" \
    "$runtime_file_mutation_target"

  run_file_probe_denial_case deny_file_open runtime-deny-file-open \
    "$runtime_file_open_package" ""
  ! grep -q 'runtime-file-open-succeeded' \
    "$lane_root/deny_file_open-output.txt"
  [[ $(<"$runtime_file_open_target") == runtime-file-open-target ]]
  fact file_open_success_marker_absent true
  collect_evidence deny_file_open "$case_session"
  assert_normal_coverage "$case_binding"
  assert_operation_decisions "$case_binding" \
    1:1=false 1:9=false 1:10=false 2:2=true 2:3=true 2:4=false \
    2:5=false 2:10=false 2:39=true 3:12=false

  run_file_probe_denial_case deny_file_read runtime-deny-file-read \
    "$runtime_file_read_package" $'r\n'
  ! grep -q 'runtime-file-read-succeeded' \
    "$lane_root/deny_file_read-output.txt"
  [[ $(<"$runtime_file_read_target") == runtime-file-read-target ]]
  fact file_read_success_marker_absent true
  collect_evidence deny_file_read "$case_session"
  assert_normal_coverage "$case_binding"
  assert_operation_decisions "$case_binding" \
    1:1=false 1:9=false 1:10=false 2:2=true 2:3=false 2:4=true \
    2:5=false 2:7=true 2:10=false 2:39=false 3:12=false

  run_file_probe_denial_case deny_file_mutation \
    runtime-deny-file-mutation "$runtime_file_mutation_package" ""
  ! grep -q 'runtime-file-mutation-succeeded' \
    "$lane_root/deny_file_mutation-output.txt"
  [[ $(<"$runtime_file_mutation_target") == runtime-file-mutation-sentinel ]]
  fact file_mutation_success_marker_absent true
  fact file_mutation_target_unchanged true
  collect_evidence deny_file_mutation "$case_session"
  assert_normal_coverage "$case_binding"
  assert_operation_decisions "$case_binding" \
    1:1=false 1:9=false 1:10=false 2:3=true 2:4=false 2:5=true \
    2:8=true 2:10=true 2:39=false 3:12=false

  run_app_server_case deny_socket runtime-deny-socket-connect \
    "if /bin/bash -c 'exec 3<>/dev/tcp/127.0.0.1/$socket_port'; then exit 74; else printf socket-denied; fi"
  grep -q 'socket-denied' "$lane_root/deny_socket-output.jsonl"
  collect_evidence deny_socket "$case_session"
  assert_normal_coverage "$case_binding"
  assert_operation_decisions "$case_binding" \
    1:1=false 1:9=false 1:10=false 2:4=false 2:5=false 2:10=false \
    2:39=false 3:12=true

  before=$lane_root/deny-exec-sessions-before
  snapshot_sessions "$before"
  as_user "$client_user" run --policy runtime-deny-exec \
    --workspace "/home/$client_user" --app-server "$agent_name" \
    </dev/null >"$lane_root/deny_exec-output.txt" 2>&1 || true
  capture_new_session "$before"
  local deny_exec_session=$captured_session
  await_state "$deny_exec_session" failed
  local deny_exec_binding
  deny_exec_binding=$(binding_path "$deny_exec_session")
  await_binding_status "$deny_exec_binding" tombstoned
  local deny_exec_cgroup
  deny_exec_cgroup=$(binding_value "$deny_exec_binding" cgroup_path)
  [[ ! -e $deny_exec_cgroup ]]
  await_workload_absent "$deny_exec_session"
  fact deny_exec_session "$deny_exec_session"
  fact deny_exec_binding "$deny_exec_binding"
  collect_evidence deny_exec "$deny_exec_session"
  assert_normal_coverage "$deny_exec_binding"
  assert_operation_decisions "$deny_exec_binding" \
    1:1=true 1:9=true 1:10=true 2:4=false 2:5=false 2:10=false \
    2:39=false 3:12=false
  fact no_first_exec true

  before=$lane_root/dynamic-sessions-before
  snapshot_sessions "$before"
  local bindings_before
  bindings_before=$(binding_count)
  local dynamic_status=0
  as_user "$client_user" run --policy runtime-dynamic-reject \
    --workspace "/home/$client_user" --app-server "$agent_name" \
    </dev/null >"$lane_root/dynamic-output.txt" 2>&1 || dynamic_status=$?
  [[ $dynamic_status -ne 0 ]]
  grep -q 'command_contains' "$lane_root/dynamic-output.txt"
  capture_new_session "$before"
  local dynamic_session=$captured_session
  await_state "$dynamic_session" failed
  [[ $(binding_count) == "$bindings_before" ]]
  ! systemctl is-active --quiet "erebor-session-$dynamic_session.scope"
  await_workload_absent "$dynamic_session"
  fact dynamic_session "$dynamic_session"
  fact activation_cancellation true

  start_long_session restart_fencing runtime-allow-all "sleep 300"
  local restart_session=$long_session
  local restart_binding=$long_binding
  local restart_cgroup=$long_cgroup
  local restart_processes=$long_processes
  local main_pid
  main_pid=$(systemctl show --property=MainPID --value erebord.service)
  [[ $main_pid =~ ^[1-9][0-9]*$ ]]
  snapshot_sessions "$lane_root/restart-sessions-before-kill"
  kill -KILL "$main_pid"
  await_restarted_daemon "$main_pid"
  close_long_session_client
  await_state "$restart_session" interrupted,failed
  await_binding_status "$restart_binding" tombstoned
  [[ ! -e $restart_cgroup ]]
  await_processes_absent "$restart_processes"
  await_workload_absent "$restart_session"
  [[ $(binding_value "$restart_binding" evidence_coverage.recovery) == true ]]
  [[ $(binding_value "$restart_binding" evidence_coverage.complete) == false ]]
  [[ $(binding_value "$restart_binding" failure) == \
    *"cannot prove continuous process-local evidence routing"* ]]
  snapshot_sessions "$lane_root/restart-sessions-after-recovery"
  cmp -s "$lane_root/restart-sessions-before-kill" \
    "$lane_root/restart-sessions-after-recovery"
  [[ $(active_binding_count) == 0 ]]
  fact restart_session "$restart_session"
  fact restart_binding "$restart_binding"
  fact restart_fencing true
  fact no_adoption true
  collect_evidence restart_fencing "$restart_session"

  fact pin_root "$pin_root"
  local source_commit
  local source_dirty
  source_commit=$(sed -n 's/^source_commit=//p' "$source_state")
  source_dirty=$(sed -n 's/^source_dirty=//p' "$source_state")
  [[ $source_commit =~ ^[0-9a-f]{40}$ \
    && ($source_dirty == true || $source_dirty == false) ]]
  fact source_commit "$source_commit"
  fact source_dirty "$source_dirty"
  fact keep_vm "$keep_vm"
  record_artifact erebor_cli "$erebor"
  record_artifact erebord /usr/lib/erebor/erebord
  record_artifact session_controller \
    /usr/libexec/erebor/erebor-linux-session-controller
  record_artifact path_broker /usr/libexec/erebor/erebor-path-broker
  record_artifact fixture "$fixture"
  record_artifact runtime_file_probe "$runtime_file_probe"
  record_artifact service_unit /etc/systemd/system/erebord.service
  record_artifact guest_probe /usr/local/lib/erebor/runtime-interceptor-vm.sh
  record_artifact control_plane \
    /usr/local/lib/erebor/daemon-systemd-control-plane.sh
  python3 - "$facts" "$lane_root" "$result" <<'PY'
import json
import pathlib
import sys

facts_path, lane_path, result_path = map(pathlib.Path, sys.argv[1:])
facts = {}
for line in facts_path.read_text(encoding="utf-8").splitlines():
    key, value = line.split("=", 1)
    facts[key] = value

def evidence(label):
    records = []
    for line in (lane_path / f"{label}-evidence.txt").read_text(encoding="utf-8").splitlines():
        marker = " payload="
        if marker in line:
            records.append(json.loads(line.split(marker, 1)[1]))
    return records

def has_effect(records, family, operation=None, physical=None):
    return any(
        record.get("schema") == "erebor.runtime.effect-observation"
        and record.get("effect_family") == family
        and (
            operation is None
            or record.get("operation") == operation
            or isinstance(operation, tuple) and record.get("operation") in operation
        )
        and (physical is None or record.get("physical_result") == physical)
        for record in records
    )

def coverage(records, recovery, complete):
    return any(
        record.get("schema") == "erebor.runtime.effect-coverage"
        and record.get("recovery") is recovery
        and record.get("complete") is complete
        for record in records
    )

allow = evidence("allow_effects")
deny_exec = evidence("deny_exec")
deny_file_open = evidence("deny_file_open")
deny_file_read = evidence("deny_file_read")
deny_file_mutation = evidence("deny_file_mutation")
deny_socket = evidence("deny_socket")
normal_labels = [
    "allow_effects",
    "stop_descendants",
    "kill_descendants",
    "pty",
    "deny_exec",
    "deny_file_open",
    "deny_file_read",
    "deny_file_mutation",
    "deny_socket",
]
checks = {
    "cgroup_separation": facts["cgroup_separation"] == "true",
    "allow_static_five_classes": facts["allow_static_five_classes"] == "true",
    "no_first_exec": facts["no_first_exec"] == "true" and has_effect(deny_exec, 1, 1, 1),
    "allow_exec": has_effect(allow, 1, 1, 0),
    "allow_file_read": has_effect(allow, 2, (2, 4, 7), 0),
    "allow_file_mutation": has_effect(allow, 2, (3, 5, 8, 10, 16, 17, 18, 25, 26), 0),
    "allow_socket_connect": has_effect(allow, 3, 12, 0),
    "deny_exec": has_effect(deny_exec, 1, 1, 1),
    "deny_file_open": (
        facts["file_open_success_marker_absent"] == "true"
        and has_effect(deny_file_open, 2, 2, 1)
        and not has_effect(deny_file_open, 2, 39)
    ),
    "deny_file_read": (
        facts["file_read_success_marker_absent"] == "true"
        and has_effect(deny_file_read, 2, 4, 1)
        and not has_effect(deny_file_read, 2, 2)
    ),
    "deny_file_mutation": (
        facts["file_mutation_success_marker_absent"] == "true"
        and facts["file_mutation_target_unchanged"] == "true"
        and has_effect(deny_file_mutation, 2, 3, 1)
        and not has_effect(deny_file_mutation, 2, (5, 8), 1)
    ),
    "deny_socket_connect": has_effect(deny_socket, 3, 12, 1),
    "pipe_transport": facts["pipe_transport"] == "true" and coverage(evidence("allow_effects"), False, True),
    "pty_transport": facts["pty_transport"] == "true" and coverage(evidence("pty"), False, True),
    "stop_descendants": facts["stop_descendants"] == "true" and coverage(evidence("stop_descendants"), False, True),
    "kill_descendants": facts["kill_descendants"] == "true" and coverage(evidence("kill_descendants"), False, True),
    "activation_cancellation": facts["activation_cancellation"] == "true",
    "restart_fencing": facts["restart_fencing"] == "true" and coverage(evidence("restart_fencing"), True, False),
    "no_adoption": facts["no_adoption"] == "true" and coverage(evidence("restart_fencing"), True, False),
    "evidence_coverage": all(coverage(evidence(label), False, True) for label in normal_labels),
}
failed = [name for name, passed in checks.items() if not passed]
if failed:
    raise SystemExit(f"Runtime Interceptor physical oracles failed: {', '.join(failed)}")

result = {
    "schema": "erebor.runtime.interceptor.physical-proof",
    "schema_version": 1,
    "qualified_platform": {
        "kernel_release": pathlib.Path("/proc/sys/kernel/osrelease").read_text().strip(),
        "architecture": __import__("platform").machine(),
        "init": "systemd",
        "containment": "delegated_systemd",
    },
    "artifacts": {
        "erebor_cli_sha256": facts["erebor_cli_sha256"],
        "erebord_sha256": facts["erebord_sha256"],
        "session_controller_sha256": facts["session_controller_sha256"],
        "path_broker_sha256": facts["path_broker_sha256"],
        "fixture_sha256": facts["fixture_sha256"],
        "runtime_file_probe_sha256": facts["runtime_file_probe_sha256"],
        "service_unit_sha256": facts["service_unit_sha256"],
        "guest_probe_sha256": facts["guest_probe_sha256"],
        "control_plane_sha256": facts["control_plane_sha256"],
        "pin_root": facts["pin_root"],
    },
    "source": {
        "commit": facts["source_commit"],
        "dirty": facts["source_dirty"] == "true",
    },
    "policies": {
        "allow_all": "runtime-allow-all",
        "deny_exec": "runtime-deny-exec",
        "deny_file_open": "runtime-deny-file-open",
        "deny_file_read": "runtime-deny-file-read",
        "deny_file_mutation": "runtime-deny-file-mutation",
        "deny_socket_connect": "runtime-deny-socket-connect",
        "dynamic_reject": "runtime-dynamic-reject",
    },
    "oracles": {name: {"passed": passed} for name, passed in checks.items()},
    "cgroups": {
        "controller_path": facts["controller_cgroup_path"],
        "controller_id": int(facts["controller_cgroup_id"]),
        "workload_path": facts["cgroup_path"],
        "workload_id": int(facts["workload_cgroup_id"]),
    },
    "sessions": {
        key.removesuffix("_session"): value
        for key, value in facts.items()
        if key.endswith("_session")
    },
    "guest_lifecycle": {
        "keep_vm": facts["keep_vm"] == "true",
        "expected_disposition": "retained" if facts["keep_vm"] == "true" else "destroyed_after_evidence_copy",
    },
    "limits": [
        "The lifecycle field records the requested harness disposition. This record does not prove later guest cleanup.",
        "The record qualifies only this guest and kernel build.",
    ],
}
result_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
  trap - EXIT
  kill "$socket_server_pid" >/dev/null 2>&1 || true
  socket_server_pid=
  rm -f -- "$file_target" "$runtime_file_open_target" \
    "$runtime_file_read_target" "$runtime_file_mutation_target"
}

if [[ ${BASH_SOURCE[0]} != "$0" ]]; then
  return 0
fi

case ${1:-} in
  install-and-run)
    shift
    install_and_run "$@"
    ;;
  probe)
    shift
    probe "$@"
    ;;
  --help|-h)
    usage
    ;;
  *)
    usage
    exit 2
    ;;
esac
