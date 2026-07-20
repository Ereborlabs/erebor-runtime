#!/usr/bin/env bash
set -euo pipefail

required=(EREBOR_PHASE1_EREBORD EREBOR_PHASE1_EREBOR)
for variable in "${required[@]}"; do
  if [[ -z "${!variable:-}" ]]; then
    echo "missing required environment variable: ${variable}" >&2
    exit 1
  fi
done

if [[ "$(id -u)" -ne 0 ]]; then
  echo "this temporary-path control-plane probe must run as root" >&2
  exit 1
fi
if [[ "$(uname -s)" != "Linux" ]]; then
  echo "this control-plane probe requires Linux Unix peer credentials" >&2
  exit 1
fi
if [[ ! -x "$EREBOR_PHASE1_EREBORD" || ! -x "$EREBOR_PHASE1_EREBOR" ]]; then
  echo "staged binaries are missing or not executable" >&2
  exit 1
fi

phase_root="$(mktemp -d /tmp/erebor-phase1.XXXXXX)"
config_dir="$phase_root/etc"
config_path="$config_dir/erebord.json"
runtime_dir="$phase_root/run"
log_dir="$phase_root/log"
state_dir="$phase_root/lib"
socket="$runtime_dir/daemon.sock"
lock_path="$runtime_dir/erebord.lock"
daemon_stderr="$phase_root/erebord.stderr"
test_group="erebor-phase1-test"
user_a="erebor-phase1-a"
user_b="erebor-phase1-b"
user_outside="erebor-phase1-outside"
daemon_pid=""
group_created=false
user_a_created=false
user_b_created=false
user_outside_created=false

cleanup() {
  if [[ -n "$daemon_pid" ]] && kill -0 "$daemon_pid" 2>/dev/null; then
    kill "$daemon_pid" >/dev/null 2>&1 || true
    wait "$daemon_pid" >/dev/null 2>&1 || true
  fi
  if [[ "$user_a_created" == true ]]; then
    userdel --remove "$user_a" >/dev/null 2>&1 || true
  fi
  if [[ "$user_b_created" == true ]]; then
    userdel --remove "$user_b" >/dev/null 2>&1 || true
  fi
  if [[ "$user_outside_created" == true ]]; then
    userdel --remove "$user_outside" >/dev/null 2>&1 || true
  fi
  if [[ "$group_created" == true ]]; then
    groupdel "$test_group" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$phase_root"
}
trap cleanup EXIT

for account in "$user_a" "$user_b" "$user_outside"; do
  if id "$account" >/dev/null 2>&1; then
    echo "refusing to modify pre-existing test user: $account" >&2
    exit 1
  fi
done
if getent group "$test_group" >/dev/null; then
  echo "refusing to modify pre-existing test group: $test_group" >&2
  exit 1
fi

await_daemon() {
  for _ in $(seq 1 100); do
    if "$EREBOR_PHASE1_EREBOR" daemon --socket "$socket" status >/dev/null 2>&1; then
      return
    fi
    if ! kill -0 "$daemon_pid" 2>/dev/null; then
      wait "$daemon_pid" || true
      cat "$daemon_stderr" >&2
      echo "erebord stopped before accepting control-plane requests" >&2
      exit 1
    fi
    sleep 0.1
  done
  cat "$daemon_stderr" >&2
  echo "timed out waiting for erebord at $socket" >&2
  exit 1
}

await_socket_removal() {
  for _ in $(seq 1 100); do
    if [[ ! -e "$socket" ]]; then
      return
    fi
    sleep 0.1
  done
  echo "erebord did not remove $socket during shutdown" >&2
  exit 1
}

start_daemon() {
  "$EREBOR_PHASE1_EREBORD" \
    --config "$config_path" \
    --runtime-dir "$runtime_dir" \
    --log-dir "$log_dir" \
    --state-dir "$state_dir" \
    >"$daemon_stderr" 2>&1 &
  daemon_pid=$!
  await_daemon
}

stop_daemon() {
  local idempotency_key="$1"
  "$EREBOR_PHASE1_EREBOR" daemon --socket "$socket" stop \
    --idempotency-key "$idempotency_key" | grep -q 'daemon stop accepted'
  await_socket_removal
  wait "$daemon_pid"
  daemon_pid=""
}

groupadd --system "$test_group"
group_created=true
useradd --create-home --groups "$test_group" "$user_a"
user_a_created=true
useradd --create-home --groups "$test_group" "$user_b"
user_b_created=true
useradd --create-home "$user_outside"
user_outside_created=true
group_gid="$(getent group "$test_group" | cut -d: -f3)"

chmod 0755 "$phase_root"
install -d -o root -g root -m 0750 "$config_dir"
printf '{"socket_group_gid":%s,"max_log_bytes":4096,"max_log_records":32,"max_idempotency_records":32}\n' "$group_gid" \
  >"$config_path"
chown root:root "$config_path"
chmod 0640 "$config_path"

start_daemon

[[ "$(stat -c '%U:%G:%a' "$socket")" == "root:$test_group:660" ]]
sudo -u "$user_a" "$EREBOR_PHASE1_EREBOR" daemon --socket "$socket" status | grep -q 'state=running'
sudo -u "$user_b" "$EREBOR_PHASE1_EREBOR" daemon --socket "$socket" status | grep -q 'state=running'
if sudo -u "$user_outside" "$EREBOR_PHASE1_EREBOR" daemon --socket "$socket" status \
  >/dev/null 2>&1; then
  echo "user outside the connection group reached the control socket" >&2
  exit 1
fi
if sudo -u "$user_a" "$EREBOR_PHASE1_EREBOR" daemon --socket "$socket" logs --maximum-records 1 \
  >/dev/null 2>&1; then
  echo "non-root caller read daemon logs" >&2
  exit 1
fi
if sudo -u "$user_a" "$EREBOR_PHASE1_EREBOR" daemon --socket "$socket" reload \
  --idempotency-key phase1-nonroot-reload >/dev/null 2>&1; then
  echo "non-root caller reloaded daemon configuration" >&2
  exit 1
fi
if sudo -u "$user_a" "$EREBOR_PHASE1_EREBOR" daemon --socket "$socket" stop \
  --idempotency-key phase1-nonroot-stop >/dev/null 2>&1; then
  echo "non-root caller stopped the daemon" >&2
  exit 1
fi

before_reload="$("$EREBOR_PHASE1_EREBOR" daemon --socket "$socket" status)"
[[ "$before_reload" != *"accepted daemon client"* ]]
"$EREBOR_PHASE1_EREBOR" daemon --socket "$socket" reload --idempotency-key phase1-reload \
  | grep -q 'configuration reloaded'
after_reload="$("$EREBOR_PHASE1_EREBOR" daemon --socket "$socket" status)"
[[ "$before_reload" != "$after_reload" ]]
printf '{"socket_group_gid":' >"$config_path"
if "$EREBOR_PHASE1_EREBOR" daemon --socket "$socket" reload \
  --idempotency-key phase1-invalid-reload >/dev/null 2>&1; then
  echo "invalid replacement configuration was accepted" >&2
  exit 1
fi
[[ "$after_reload" == "$("$EREBOR_PHASE1_EREBOR" daemon --socket "$socket" status)" ]]
printf '{"socket_group_gid":%s,"max_log_bytes":4096,"max_log_records":32,"max_idempotency_records":32}\n' "$group_gid" \
  >"$config_path"
chown root:root "$config_path"
chmod 0640 "$config_path"

socket_inode="$(stat -c '%i' "$socket")"
if "$EREBOR_PHASE1_EREBORD" \
  --config "$config_path" \
  --runtime-dir "$runtime_dir" \
  --log-dir "$log_dir" \
  --state-dir "$state_dir" \
  >/dev/null 2>&1; then
  echo "second daemon started despite the held lock" >&2
  exit 1
fi
[[ "$socket_inode" == "$(stat -c '%i' "$socket")" ]]

"$EREBOR_PHASE1_EREBOR" daemon --socket "$socket" logs --maximum-records 32 \
  | grep -q 'daemon control service started'
lock_inode="$(stat -c '%i' "$lock_path")"
stop_daemon phase1-stop
[[ ! -e "$socket" ]]
[[ "$lock_inode" == "$(stat -c '%i' "$lock_path")" ]]

python3 -c 'import socket, sys; sock=socket.socket(socket.AF_UNIX); sock.bind(sys.argv[1])' "$socket"
start_daemon
sudo -u "$user_a" "$EREBOR_PHASE1_EREBOR" daemon --socket "$socket" status | grep -q 'state=running'
[[ -S "$socket" ]]

kill -KILL "$daemon_pid"
if wait "$daemon_pid" 2>/dev/null; then
  echo "erebord unexpectedly exited cleanly after SIGKILL" >&2
  exit 1
fi
daemon_pid=""
start_daemon
sudo -u "$user_a" "$EREBOR_PHASE1_EREBOR" daemon --socket "$socket" status | grep -q 'state=running'
[[ "$lock_inode" == "$(stat -c '%i' "$lock_path")" ]]

"$EREBOR_PHASE1_EREBOR" daemon --socket "$socket" reload --idempotency-key phase1-reload \
  | grep -q 'configuration reloaded at generation 2'
stop_daemon phase1-stop
[[ ! -e "$socket" ]]
[[ "$lock_inode" == "$(stat -c '%i' "$lock_path")" ]]
