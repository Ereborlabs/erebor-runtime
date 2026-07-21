#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "$(id -u)" -ne 0 || "$(uname -s)" != "Linux" ]]; then
  echo "the installed session-runtime probe requires root on Linux" >&2
  exit 1
fi

erebor=/usr/local/bin/erebor
first_user="${EREBOR_INSTALLED_SESSION_USER:?first session user is required}"
second_user="${EREBOR_INSTALLED_SESSION_USER_TWO:?second session user is required}"
config_path=/etc/erebor/erebord.json

report_failure() {
  local status="$?"
  echo "installed session-runtime probe failed at line ${BASH_LINENO[0]}: $BASH_COMMAND" >&2
  exit "$status"
}
trap report_failure ERR

for binary in \
  "$erebor" \
  /usr/libexec/erebor/erebor-linux-session-controller \
  /usr/libexec/erebor/erebor-linux-process-guard \
  /usr/libexec/erebor/erebor-path-broker; do
  [[ -x "$binary" ]] || {
    echo "installed runtime binary is missing: $binary" >&2
    exit 1
  }
done

session_id_from() {
  sed -n 's/^session_id=\([^ ]*\).*/\1/p'
}

as_user() {
  local user="$1"
  shift
  runuser -u "$user" -- "$erebor" "$@"
}

child_pid_of() {
  local parent_pid="$1"
  local child_pid=""
  for _ in $(seq 1 150); do
    child_pid="$(tr ' ' '\n' <"/proc/$parent_pid/task/$parent_pid/children" | head -n 1)"
    [[ -n "$child_pid" ]] && {
      printf '%s\n' "$child_pid"
      return
    }
    sleep 0.1
  done
  echo "runuser process $parent_pid did not start an Erebor client" >&2
  return 1
}

await_daemon() {
  for _ in $(seq 1 150); do
    "$erebor" daemon status >/dev/null 2>&1 && return
    sleep 0.1
  done
  "$erebor" daemon status
}

await_terminal_state() {
  local user="$1"
  local session_id="$2"
  local output=""
  for _ in $(seq 1 150); do
    output="$(as_user "$user" session inspect "$session_id" 2>&1 || true)"
    if grep -Eq 'state=(succeeded|failed|interrupted)' <<<"$output"; then
      return
    fi
    sleep 0.1
  done
  echo "session $session_id did not reach a terminal state" >&2
  echo "$output" >&2
  exit 1
}

await_log() {
  local user="$1"
  local session_id="$2"
  local expected="$3"
  local output=""
  for _ in $(seq 1 150); do
    output="$(as_user "$user" session logs "$session_id" 2>&1 || true)"
    if grep -q "$expected" <<<"$output"; then
      return
    fi
    sleep 0.1
  done
  echo "session $session_id did not emit expected output: $expected" >&2
  echo "$output" >&2
  exit 1
}

write_config() {
  local group_gid
  group_gid="$(stat -c %g /run/erebor/daemon.sock)"
  printf '{"socket_group_gid":%s,"max_log_bytes":4096,"max_log_records":32,"max_idempotency_records":256,"max_session_output_bytes":67108864,"session_output_rotation_bytes":4194304,"max_daemon_loss_grace_seconds":2}\n' \
    "$group_gid" >"$config_path"
  chown root:root "$config_path"
  chmod 0640 "$config_path"
}

create_linux() {
  local user="$1"
  local label="$2"
  as_user "$user" session create \
    --runner linux-host \
    --workspace "/home/$user" \
    --loss-grace-seconds 1 \
    --idempotency-key "create-$label" \
    -- /usr/bin/dash -c \
      'test "$(id -u)" != 0; test "$(id -G)" = "$(id -g)"; test "$(umask)" = 0077; test ! -e /run/erebor/daemon.sock; printf "linux-ready-%s\n" "$0"; printf "linux-stderr-%s\n" "$0" >&2; while :; do sleep 1; done' \
    "$label"
}

create_tty_linux() {
  local user="$1"
  local label="$2"
  as_user "$user" session create \
    --runner linux-host \
    --workspace "/home/$user" \
    --loss-grace-seconds 1 \
    --idempotency-key "tty-create-$label" \
    -t \
    -- /usr/bin/dash -c \
      'IFS= read -r line; printf "tty-input-%s\n" "$line"; while :; do sleep 1; done' \
    "$label"
}

start_session() {
  local user="$1"
  local session_id="$2"
  local label="$3"
  as_user "$user" session start "$session_id" --idempotency-key "start-$label" \
    | grep -q 'state=running'
}

stop_and_remove() {
  local user="$1"
  local session_id="$2"
  local label="$3"
  as_user "$user" session stop "$session_id" \
    --idempotency-key "stop-$label" >/dev/null
  await_terminal_state "$user" "$session_id"
  as_user "$user" session rm "$session_id" --force \
    --idempotency-key "remove-$label" | grep -q 'state=removed'
}

write_config
await_daemon

as_user "$first_user" runner inspect linux-host | grep -q '"runner":"linux-host"'

marker="/home/$first_user/daemon-must-launch-nothing"
rm -f "$marker"
systemctl stop erebord.service
if as_user "$first_user" session run \
  --runner linux-host \
  --workspace "/home/$first_user" \
  --idempotency-key daemon-unavailable \
  -- /usr/bin/dash -c 'touch "$1"' dash "$marker"; then
  echo "generic run launched without erebord" >&2
  exit 1
fi
test ! -e "$marker"
systemctl start erebord.service
await_daemon

first_output="$(create_linux "$first_user" first)"
first_session="$(session_id_from <<<"$first_output")"
[[ -n "$first_session" ]]
start_session "$first_user" "$first_session" first
await_log "$first_user" "$first_session" 'linux-ready-first'
as_user "$first_user" session logs "$first_session" --stream stderr \
  | grep -q 'linux-stderr-first'
as_user "$first_user" audit tail "$first_session" | grep -q 'durable_cursor='
as_user "$first_user" session alias set primary "$first_session" \
  --idempotency-key alias-first | grep -q "session_id=$first_session"
as_user "$first_user" session inspect primary | grep -q "session_id=$first_session"
if as_user "$second_user" session inspect "$first_session" >/dev/null 2>&1; then
  echo "second user inspected the first user's session" >&2
  exit 1
fi
if as_user "$second_user" session inspect primary >/dev/null 2>&1; then
  echo "second user resolved the first user's alias" >&2
  exit 1
fi
stop_and_remove "$first_user" "$first_session" first
as_user "$first_user" session alias remove primary \
  --idempotency-key alias-remove-first | grep -q "session_id=$first_session"

tty_output="$(create_tty_linux "$first_user" first)"
tty_session="$(session_id_from <<<"$tty_output")"
[[ -n "$tty_session" ]]
start_session "$first_user" "$tty_session" tty-first
{
  sleep 1
  printf 'governed\n'
  sleep 1
  printf '\020\021'
} | runuser -u "$first_user" -- script -qefc \
  "$erebor session attach $tty_session --input --client-instance-id tty-first --idempotency-key tty-attach-first" \
  /dev/null >/dev/null
await_log "$first_user" "$tty_session" 'tty-input-governed'
as_user "$first_user" session inspect "$tty_session" | grep -q 'state=running'
stop_and_remove "$first_user" "$tty_session" tty-first

sigint_output="$(mktemp)"
runuser -u "$first_user" -- "$erebor" session run \
  --runner linux-host \
  --workspace "/home/$first_user" \
  --loss-grace-seconds 1 \
  --idempotency-key sigint-first \
  -- /usr/bin/dash -c 'while :; do sleep 1; done' \
  >"$sigint_output" 2>&1 &
sigint_client_pid="$!"
sigint_session=""
for _ in $(seq 1 150); do
  sigint_session="$(session_id_from <"$sigint_output")"
  [[ -n "$sigint_session" ]] && break
  sleep 0.1
done
[[ -n "$sigint_session" ]]
for _ in $(seq 1 150); do
  grep -q 'read_only=true' "$sigint_output" && break
  sleep 0.1
done
grep -q 'read_only=true' "$sigint_output"
sleep 1
sigint_erebor_pid="$(child_pid_of "$sigint_client_pid")"
kill -INT "$sigint_erebor_pid"
wait "$sigint_client_pid" || true
await_terminal_state "$first_user" "$sigint_session"
as_user "$first_user" session inspect "$sigint_session" | grep -q 'state=failed'
as_user "$first_user" session rm "$sigint_session" --force \
  --idempotency-key sigint-remove-first | grep -q 'state=removed'

transport_output="$(create_linux "$first_user" transport)"
transport_session="$(session_id_from <<<"$transport_output")"
[[ -n "$transport_session" ]]
start_session "$first_user" "$transport_session" transport
readonly_attach_output="$(mktemp)"
as_user "$first_user" session attach "$transport_session" \
  --idempotency-key readonly-attach-first >"$readonly_attach_output" 2>&1 &
readonly_attach_pid="$!"
sleep 1
readonly_attach_erebor_pid="$(child_pid_of "$readonly_attach_pid")"
kill -TERM "$readonly_attach_erebor_pid"
wait "$readonly_attach_pid" || true
as_user "$first_user" session inspect "$transport_session" | grep -q 'state=running'
stop_and_remove "$first_user" "$transport_session" transport

second_output="$(create_linux "$second_user" second)"
second_session="$(session_id_from <<<"$second_output")"
[[ -n "$second_session" ]]
start_session "$second_user" "$second_session" second
await_log "$second_user" "$second_session" 'linux-ready-second'
stop_and_remove "$second_user" "$second_session" second

if as_user "$first_user" session create \
  --runner docker \
  --workspace "/home/$first_user" \
  --idempotency-key docker-unavailable \
  -- /usr/bin/dash -c 'exit 0' >/dev/null 2>&1; then
  echo "Phase 3 admitted a Docker session" >&2
  exit 1
fi
