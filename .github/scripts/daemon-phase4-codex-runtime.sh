#!/usr/bin/env bash
set -Eeuo pipefail

# This privileged probe deliberately uses the deterministic codex-v1-fixture.
# It proves the daemon/client contract without a vendor binary, credentials,
# CODEX_HOME, OCI import, or a caller-owned state projection.

if [[ "$(id -u)" -ne 0 || "$(uname -s)" != "Linux" ]]; then
  echo "the Phase 4 Codex runtime probe requires root on Linux" >&2
  exit 1
fi

erebor=/usr/local/bin/erebor
fixture=/usr/lib/erebor/codex-v1-fixture
config_path=/etc/erebor/erebord.json
trust_root=/usr/lib/erebor/codex-v1-fixture-trust
first_user="${EREBOR_INSTALLED_SESSION_USER:?first session user is required}"
second_user="${EREBOR_INSTALLED_SESSION_USER_TWO:?second session user is required}"

report_failure() {
  local status="$?"
  echo "Phase 4 Codex runtime probe failed at line ${BASH_LINENO[0]}: $BASH_COMMAND" >&2
  systemctl status erebord.service --no-pager >&2 || true
  journalctl -u erebord.service --no-pager >&2 || true
  exit "$status"
}
trap report_failure ERR

for binary in "$erebor" "$fixture"; do
  [[ -x "$binary" ]] || {
    echo "installed Phase 4 binary is missing: $binary" >&2
    exit 1
  }
done

as_user() {
  local user="$1"
  shift
  runuser -u "$user" -- "$erebor" "$@"
}

await_daemon() {
  for _ in $(seq 1 150); do
    "$erebor" daemon status >/dev/null 2>&1 && return
    sleep 0.1
  done
  "$erebor" daemon status
}

session_ids() {
  local user="$1"
  as_user "$user" session ps | sed -n 's/^session_id=\([^ ]*\).*/\1/p'
}

running_session_id() {
  local user="$1"
  as_user "$user" session ps \
    | sed -n 's/^session_id=\([^ ]*\).*state=running.*/\1/p' \
    | head -n 1
}

await_terminal() {
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
  echo "Codex session $session_id did not become terminal" >&2
  echo "$output" >&2
  exit 1
}

remove_all_sessions() {
  local user="$1"
  local index=0
  local session_id=""
  while IFS= read -r session_id; do
    [[ -n "$session_id" ]] || continue
    index=$((index + 1))
    as_user "$user" session rm "$session_id" --force \
      --idempotency-key "phase4-codex-remove-$index" >/dev/null
  done < <(session_ids "$user")
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

configure_fixture() {
  local group_gid package_output
  group_gid="$(stat -c %g /run/erebor/daemon.sock)"
  package_output="$("$fixture" configure \
    --config "$config_path" \
    --trust-root "$trust_root" \
    --socket-group-gid "$group_gid" \
    --owner-uid "$(id -u "$first_user")" \
    --owner-uid "$(id -u "$second_user")")"
  package_reference="$(sed -n 's/^package_reference=//p' <<<"$package_output")"
  root_policy_digest="$(sed -n 's/^root_policy_digest=//p' <<<"$package_output")"
  [[ -n "$package_reference" && -n "$root_policy_digest" ]]
  chown root:root "$config_path"
  chmod 0640 "$config_path"
}

configure_policy() {
  local user="$1"
  local output policy_set_digest
  output="$(as_user "$user" policy set create \
    --root-minimum-digest "$root_policy_digest" \
    --idempotency-key "phase4-codex-policy-$user")"
  policy_set_digest="$(sed -n 's/^digest=//p' <<<"$output")"
  [[ -n "$policy_set_digest" ]]
  as_user "$user" policy set alias fixture "$policy_set_digest" \
    --idempotency-key "phase4-codex-policy-alias-$user" \
    | grep -q 'alias=fixture'
}

load_fixture() {
  local user="$1"
  local user_fixture="/home/$user/codex-v1-fixture"
  install -o "$user" -g "$user" -m 0755 "$fixture" "$user_fixture"
  if as_user "$user" agent load \
    "codex-v1-fixture@sha256:$(printf 'a%.0s' {1..64})" \
    --from "$user_fixture" >/dev/null 2>&1; then
    echo "agent load accepted an unknown root-curated package" >&2
    exit 1
  fi
  cp "$user_fixture" "/home/$user/codex-v1-fixture-mutated"
  chown "$user:$user" "/home/$user/codex-v1-fixture-mutated"
  printf 'x' >>"/home/$user/codex-v1-fixture-mutated"
  if as_user "$user" agent load "$package_reference" \
    --from "/home/$user/codex-v1-fixture-mutated" >/dev/null 2>&1; then
    echo "agent load accepted an executable with the wrong artifact digest" >&2
    exit 1
  fi
  as_user "$user" agent load "$package_reference" --from "$user_fixture" \
    | grep -q 'alias=codex-app-server'
}

run_app_server_frame() {
  local user="$1"
  local frame="$2"
  local output="$3"
  printf '%s\n' "$frame" | as_user "$user" run --policy fixture \
    --workspace "/home/$user" codex-app-server >"$output" 2>&1
}

start_waiting_app_server() {
  local user="$1"
  local fifo="$2"
  local output="$3"
  mkfifo "$fifo"
  runuser -u "$user" -- bash -c \
    'exec "$1" run --policy fixture --workspace "$2" codex-app-server <"$3"' \
    -- "$erebor" "/home/$user" "$fifo" >"$output" 2>&1 &
  wait_client_parent="$!"
  exec {wait_writer}>"$fifo"
  printf '%s\n' '{"jsonrpc":"2.0","id":90,"method":"fixture/wait"}' >&"$wait_writer"
  for _ in $(seq 1 150); do
    wait_session_id="$(running_session_id "$user")"
    [[ -n "$wait_session_id" ]] && return
    sleep 0.1
  done
  echo "waiting Codex App Server session did not start" >&2
  exit 1
}

close_waiting_app_server_input() {
  exec {wait_writer}>&-
  rm -f "$1"
}

configure_fixture
systemctl restart erebord.service
await_daemon

load_fixture "$first_user"
load_fixture "$second_user"
configure_policy "$first_user"
configure_policy "$second_user"

if as_user "$first_user" run --policy fixture --workspace "/home/$first_user" \
  codex -- --escape-daemon-entrypoint >/dev/null 2>&1; then
  echo "the Codex alias accepted raw argv" >&2
  exit 1
fi
if as_user "$first_user" run --policy fixture --workspace "/home/$first_user" \
  fixture-not-an-entrypoint >/dev/null 2>&1; then
  echo "the daemon admitted a non-certified Codex entrypoint" >&2
  exit 1
fi

tty_output="$(mktemp)"
printf 'governed\n' | runuser -u "$first_user" -- script -qefc \
  "$erebor run --policy fixture --workspace /home/$first_user codex" \
  /dev/null >"$tty_output"
grep -q 'fixture-tty=ready' "$tty_output"
grep -q 'fixture-daemon-socket=absent' "$tty_output"
grep -q 'fixture-hook=accepted' "$tty_output"
grep -q 'fixture-tty-input=governed' "$tty_output"
remove_all_sessions "$first_user"

app_server_output="$(mktemp)"
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize"}' \
  '{"jsonrpc":"2.0","id":2,"method":"fixture/hook"}' \
  '{"jsonrpc":"2.0","method":"$/cancelRequest","params":{"id":2}}' \
  | as_user "$first_user" run --policy fixture --workspace "/home/$first_user" \
      codex-app-server >"$app_server_output" 2>&1
grep -q '"fixture":"accepted"' "$app_server_output"
grep -q '"fixture":"cancelled"' "$app_server_output"
remove_all_sessions "$first_user"

for hook_case in hook-replay hook-wrong-peer hook-wrong-session; do
  hook_output="$(mktemp)"
  run_app_server_frame "$first_user" \
    "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"fixture/$hook_case\"}" \
    "$hook_output"
  grep -q "\"fixture\":\"${hook_case#hook-}-rejected\"" "$hook_output"
  remove_all_sessions "$first_user"
done

first_concurrent_output="$(mktemp)"
second_concurrent_output="$(mktemp)"
run_app_server_frame "$first_user" \
  '{"jsonrpc":"2.0","id":4,"method":"fixture/hook"}' \
  "$first_concurrent_output" &
first_concurrent_pid="$!"
run_app_server_frame "$second_user" \
  '{"jsonrpc":"2.0","id":5,"method":"fixture/hook"}' \
  "$second_concurrent_output" &
second_concurrent_pid="$!"
wait "$first_concurrent_pid"
wait "$second_concurrent_pid"
grep -q '"fixture":"accepted"' "$first_concurrent_output"
grep -q '"fixture":"accepted"' "$second_concurrent_output"
remove_all_sessions "$first_user"
remove_all_sessions "$second_user"

malformed_output="$(mktemp)"
if run_app_server_frame "$first_user" \
  '{"jsonrpc":"2.0","id":6,"method":"fixture/malformed-output"}' \
  "$malformed_output"; then
  echo "the malformed App Server stdout fixture unexpectedly completed cleanly" >&2
  exit 1
fi
malformed_session="$(session_ids "$first_user" | head -n 1)"
[[ -n "$malformed_session" ]]
await_terminal "$first_user" "$malformed_session"
as_user "$first_user" session inspect "$malformed_session" | grep -q 'state=failed'
remove_all_sessions "$first_user"

cancellation_fifo="$(mktemp -u)"
cancellation_output="$(mktemp)"
start_waiting_app_server "$first_user" "$cancellation_fifo" "$cancellation_output"
cancellation_client_pid="$(child_pid_of "$wait_client_parent")"
kill -INT "$cancellation_client_pid"
close_waiting_app_server_input "$cancellation_fifo"
wait "$wait_client_parent" || true
await_terminal "$first_user" "$wait_session_id"
remove_all_sessions "$first_user"

disconnect_fifo="$(mktemp -u)"
disconnect_output="$(mktemp)"
start_waiting_app_server "$first_user" "$disconnect_fifo" "$disconnect_output"
disconnect_client_pid="$(child_pid_of "$wait_client_parent")"
disconnect_session_id="$wait_session_id"
kill -TERM "$disconnect_client_pid"
close_waiting_app_server_input "$disconnect_fifo"
wait "$wait_client_parent" || true
as_user "$first_user" session inspect "$disconnect_session_id" | grep -q 'state=running'
as_user "$first_user" session stop "$disconnect_session_id" \
  --idempotency-key phase4-codex-disconnect-stop >/dev/null
await_terminal "$first_user" "$disconnect_session_id"
remove_all_sessions "$first_user"

recovery_fifo="$(mktemp -u)"
recovery_output="$(mktemp)"
start_waiting_app_server "$first_user" "$recovery_fifo" "$recovery_output"
recovery_client_pid="$(child_pid_of "$wait_client_parent")"
recovery_session_id="$wait_session_id"
kill -TERM "$recovery_client_pid"
close_waiting_app_server_input "$recovery_fifo"
wait "$wait_client_parent" || true
systemctl restart erebord.service
await_daemon
as_user "$first_user" session inspect "$recovery_session_id" | grep -q 'state=running'
as_user "$first_user" session stop "$recovery_session_id" \
  --idempotency-key phase4-codex-recovery-stop >/dev/null
await_terminal "$first_user" "$recovery_session_id"
remove_all_sessions "$first_user"

# Replacing an enrolled artifact after all successful workflows must prevent a
# later daemon admission; the daemon re-resolves its held descriptor identity.
printf 'x' >>"/home/$first_user/codex-v1-fixture"
if as_user "$first_user" run --policy fixture --workspace "/home/$first_user" \
  codex -d >/dev/null 2>&1; then
  echo "the daemon admitted a replaced enrolled Codex artifact" >&2
  exit 1
fi
