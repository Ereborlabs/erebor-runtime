#!/usr/bin/env bash
set -Eeuo pipefail

# This privileged probe deliberately uses the deterministic codex-v1-fixture.
# It proves the daemon/client contract without a vendor binary, credentials,
# CODEX_HOME, OCI import, or a caller-owned state projection.

if [[ "$(id -u)" -ne 0 || "$(uname -s)" != "Linux" ]]; then
  echo "the Codex runtime probe requires root on Linux" >&2
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
  echo "Codex runtime probe failed at line ${BASH_LINENO[0]}: $BASH_COMMAND" >&2
  systemctl status erebord.service --no-pager >&2 || true
  journalctl -u erebord.service --no-pager >&2 || true
  exit "$status"
}
trap report_failure ERR

for binary in "$erebor" "$fixture"; do
  [[ -x "$binary" ]] || {
    echo "installed Codex runtime binary is missing: $binary" >&2
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

running_session_ids() {
  local user="$1"
  as_user "$user" session ps \
    | sed -n 's/^session_id=\([^ ]*\).*state=running.*/\1/p'
}

await_running_session_count() {
  local user="$1"
  local expected="$2"
  local -a sessions=()
  for _ in $(seq 1 150); do
    mapfile -t sessions < <(running_session_ids "$user")
    if [[ "${#sessions[@]}" == "$expected" ]]; then
      printf '%s\n' "${sessions[@]}"
      return
    fi
    sleep 0.1
  done
  echo "expected $expected running Codex sessions" >&2
  as_user "$user" session ps >&2
  exit 1
}

await_running_session() {
  local user="$1"
  local session_id=""
  for _ in $(seq 1 150); do
    session_id="$(running_session_id "$user")"
    [[ -n "$session_id" ]] && {
      printf '%s\n' "$session_id"
      return
    }
    sleep 0.1
  done
  echo "Codex session did not become running" >&2
  as_user "$user" session ps >&2
  exit 1
}

await_session_stdout() {
  local user="$1"
  local session_id="$2"
  local expected="$3"
  local output=""
  for _ in $(seq 1 150); do
    output="$(as_user "$user" session logs "$session_id" 2>&1 || true)"
    grep -Fq "$expected" <<<"$output" && {
      printf '%s\n' "$output"
      return
    }
    sleep 0.1
  done
  echo "Codex session $session_id did not write expected stdout: $expected" >&2
  echo "$output" >&2
  exit 1
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
      --idempotency-key "codex-runtime-remove-$index" >/dev/null
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
    --linux-runner-containment systemd \
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
    --idempotency-key "codex-runtime-policy-$user")"
  policy_set_digest="$(sed -n 's/^digest=//p' <<<"$output")"
  [[ -n "$policy_set_digest" ]]
  as_user "$user" policy set alias fixture "$policy_set_digest" \
    --idempotency-key "codex-runtime-policy-alias-$user" \
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

send_fixture_tty_control() {
  local user="$1"
  local session_id="$2"
  local control="$3"
  local label="$4"
  local output="$5"
  {
    sleep 1
    printf '%s\n' "$control"
    sleep 1
    printf '\020\021'
  } | runuser -u "$user" -- script -qefc \
    "stty rows 24 cols 80; $erebor session attach $session_id --input --client-instance-id $label --idempotency-key $label" \
    /dev/null >"$output" 2>&1
}

record_field() {
  local record="$1"
  local field="$2"
  tr ' ' '\n' <<<"$record" | sed -n "s/^${field}=//p" | head -n 1
}

context_record_for_child() {
  local user="$1"
  local parent_session="$2"
  local child_session="$3"
  as_user "$user" session context inbox "$parent_session" \
    | grep -F "child_scope=refs/scopes/$child_session/root "
}

context_record_for_scope() {
  local user="$1"
  local parent_session="$2"
  local child_scope="$3"
  as_user "$user" session context inbox "$parent_session" \
    | grep -F "child_scope=$child_scope "
}

receive_context_delivery() {
  local user="$1"
  local parent_session="$2"
  local record="$3"
  local key="$4"
  as_user "$user" session context receive "$parent_session" \
    "$(record_field "$record" delivery_path)" \
    "$(record_field "$record" delivery_commit)" \
    --expected-parent-head "$(record_field "$record" expected_parent_head)" \
    --idempotency-key "$key"
}

reject_context_delivery() {
  local user="$1"
  local parent_session="$2"
  local record="$3"
  local key="$4"
  as_user "$user" session context reject "$parent_session" \
    "$(record_field "$record" delivery_path)" \
    "$(record_field "$record" delivery_commit)" \
    --expected-parent-head "$(record_field "$record" expected_parent_head)" \
    --reason "fixture parent rejected cancellation" \
    --idempotency-key "$key"
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
# A real interactive Codex client remains owned by the daemon after the user
# detaches.  Exercise that path instead of making this long-lived fixture exit
# during the controller's input acknowledgement.
printf 'governed\n\020\021' | timeout 20s runuser -u "$first_user" -- script -qefc \
  "stty rows 24 cols 80; $erebor run --policy fixture --workspace /home/$first_user codex" \
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

for delegation_params in \
  '"frozen_context_mode":"none","last_turns":0' \
  '"frozen_context_mode":"all","last_turns":0' \
  '"frozen_context_mode":"last_turns","last_turns":1'; do
  delegation_output="$(mktemp)"
  run_app_server_frame "$first_user" \
    $'{"jsonrpc":"2.0","id":6,"method":"turn/start","params":{"threadId":"fixture-thread"}}\n'"{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"fixture/delegate\",\"params\":{$delegation_params}}" \
    "$delegation_output"
  grep -q '"fixture":"delegated"' "$delegation_output"
  delegated_child="$(await_running_session "$first_user")"
  delegated_session_count="$(session_ids "$first_user" | wc -l | tr -d ' ')"
  [[ "$delegated_session_count" == 2 ]] || {
    echo "delegation did not retain exactly parent P and child B sessions" >&2
    as_user "$first_user" session ps >&2
    exit 1
  }
  as_user "$first_user" session inspect "$delegated_child" | grep -q 'state=running'
  delegated_logs="$(await_session_stdout "$first_user" "$delegated_child" 'fixture-hook=accepted')"
  if [[ "$delegation_params" == *'"none"'* ]]; then
    ! grep -q 'fixture-frozen-context=' <<<"$delegated_logs"
  else
    grep -q 'fixture-frozen-context={"schema_version":1,"source":"erebor_frozen_codex_prompt_projection"' <<<"$delegated_logs"
  fi
  remove_all_sessions "$first_user"
done

# Exercise the complete public parent/child delivery path. P admits sibling
# children B and C through the guarded bridge. B publishes a message, C
# publishes a cancellation fact, the parent explicitly decides both, then B
# binds its own authenticated terminal turn and admits D. D's result must be
# received by B before B's second result can be received by P.
dag_parent_output="$(mktemp)"
dag_parent_frame=$'{"jsonrpc":"2.0","id":100,"method":"turn/start","params":{"threadId":"fixture-thread"}}\n'
dag_parent_frame+=$'{"jsonrpc":"2.0","id":101,"method":"fixture/delegate","params":{"frozen_context_mode":"all","last_turns":0,"tool_use_id":"fixture-p-b"}}\n'
dag_parent_frame+=$'{"jsonrpc":"2.0","id":102,"method":"fixture/delegate","params":{"frozen_context_mode":"none","last_turns":0,"tool_use_id":"fixture-p-c"}}'
run_app_server_frame "$first_user" "$dag_parent_frame" "$dag_parent_output"
grep -c '"fixture":"delegated"' "$dag_parent_output" | grep -q '^2$'

mapfile -t dag_running < <(await_running_session_count "$first_user" 2)
mapfile -t dag_sessions < <(session_ids "$first_user")
[[ "${#dag_sessions[@]}" == 3 ]]
dag_b_session="${dag_running[0]}"
dag_c_session="${dag_running[1]}"
dag_parent_session=""
for session_id in "${dag_sessions[@]}"; do
  if [[ "$session_id" != "$dag_b_session" && "$session_id" != "$dag_c_session" ]]; then
    dag_parent_session="$session_id"
  fi
done
[[ -n "$dag_parent_session" ]]
await_session_stdout "$first_user" "$dag_b_session" 'fixture-hook=accepted' >/dev/null
await_session_stdout "$first_user" "$dag_c_session" 'fixture-hook=accepted' >/dev/null

dag_b_message_output="$(mktemp)"
send_fixture_tty_control "$first_user" "$dag_b_session" \
  $'fixture/turn\nfixture/command {"tool_use_id":"fixture-b-ls","command":"ls"}\nfixture/start-q\nfixture/deliver {"sequence":1,"kind":"message","mode":"queue","selected_text":"B queued message"}' \
  dag-b-message "$dag_b_message_output"
grep -q 'fixture-turn=accepted' "$dag_b_message_output"
grep -q 'fixture-command=completed' "$dag_b_message_output"
grep -q 'fixture-operation=q-started' "$dag_b_message_output"
grep -q 'fixture-delivery=accepted' "$dag_b_message_output"

dag_c_cancel_output="$(mktemp)"
send_fixture_tty_control "$first_user" "$dag_c_session" \
  'fixture/deliver {"sequence":1,"kind":"cancelled","mode":"queue","selected_text":"C cancelled"}' \
  dag-c-cancel "$dag_c_cancel_output"
grep -q 'fixture-delivery=accepted' "$dag_c_cancel_output"

dag_b_message_record="$(context_record_for_child "$first_user" "$dag_parent_session" "$dag_b_session")"
dag_c_cancel_record="$(context_record_for_child "$first_user" "$dag_parent_session" "$dag_c_session")"
[[ -n "$dag_b_message_record" && -n "$dag_c_cancel_record" ]]
dag_parent_after_b="$(receive_context_delivery "$first_user" "$dag_parent_session" "$dag_b_message_record" dag-parent-receive-b)"
dag_parent_after_b_head="$(record_field "$dag_parent_after_b" parent_head)"
dag_parent_b_receipt="$(record_field "$dag_parent_after_b" receipt_path)"
[[ -n "$dag_parent_after_b_head" && -n "$dag_parent_b_receipt" ]]
dag_c_cancel_record="$(context_record_for_child "$first_user" "$dag_parent_session" "$dag_c_session")"
dag_parent_after_c="$(reject_context_delivery "$first_user" "$dag_parent_session" "$dag_c_cancel_record" dag-parent-reject-c)"
dag_parent_after_c_head="$(record_field "$dag_parent_after_c" parent_head)"
dag_parent_c_receipt="$(record_field "$dag_parent_after_c" receipt_path)"
[[ -n "$dag_parent_after_c_head" && -n "$dag_parent_c_receipt" ]]

# q is a long-lived operation inside B, not another daemon session. Its
# delivery scope is admitted from B's exact command pin, so B alone must make
# two explicit receives while P's head remains unchanged.
await_session_stdout "$first_user" "$dag_b_session" 'fixture-operation=q-delivery-1' >/dev/null
dag_q_scope="refs/scopes/$dag_b_session/scope/codex-operation-$(printf 'fixture-q' | sha256sum | awk '{print substr($1, 1, 20)}')"
dag_q_partial_record="$(context_record_for_scope "$first_user" "$dag_b_session" "$dag_q_scope")"
dag_b_after_q_partial="$(receive_context_delivery "$first_user" "$dag_b_session" "$dag_q_partial_record" dag-b-receive-q-partial)"
dag_b_after_q_partial_head="$(record_field "$dag_b_after_q_partial" parent_head)"
[[ -n "$dag_b_after_q_partial_head" ]]
[[ "$(git --git-dir="/var/lib/erebor/users/$(id -u "$first_user")/sessions/$dag_parent_session/context" rev-parse "refs/scopes/$dag_parent_session/root")" == "$dag_parent_after_c_head" ]]
await_session_stdout "$first_user" "$dag_b_session" 'fixture-operation=q-delivery-2' >/dev/null
dag_q_final_record="$(context_record_for_scope "$first_user" "$dag_b_session" "$dag_q_scope")"
dag_b_after_q_final="$(receive_context_delivery "$first_user" "$dag_b_session" "$dag_q_final_record" dag-b-receive-q-final)"
dag_b_after_q_final_head="$(record_field "$dag_b_after_q_final" parent_head)"
[[ -n "$dag_b_after_q_final_head" ]]

as_user "$first_user" session stop "$dag_c_session" \
  --idempotency-key dag-parent-cancel-c >/dev/null
await_terminal "$first_user" "$dag_c_session"

dag_b_delegate_output="$(mktemp)"
send_fixture_tty_control "$first_user" "$dag_b_session" \
  $'fixture/turn\nfixture/delegate {"frozen_context_mode":"none","last_turns":0,"tool_use_id":"fixture-b-d"}' \
  dag-b-delegate "$dag_b_delegate_output"
grep -q 'fixture-turn=accepted' "$dag_b_delegate_output"
grep -q 'fixture-delegation=accepted' "$dag_b_delegate_output"
mapfile -t dag_running < <(await_running_session_count "$first_user" 2)
if [[ "${dag_running[0]}" == "$dag_b_session" ]]; then
  dag_d_session="${dag_running[1]}"
else
  dag_d_session="${dag_running[0]}"
fi
[[ "$dag_d_session" != "$dag_b_session" ]]
await_session_stdout "$first_user" "$dag_d_session" 'fixture-hook=accepted' >/dev/null

dag_d_result_output="$(mktemp)"
send_fixture_tty_control "$first_user" "$dag_d_session" \
  'fixture/deliver {"sequence":1,"kind":"result","mode":"queue","selected_text":"D result"}' \
  dag-d-result "$dag_d_result_output"
grep -q 'fixture-delivery=accepted' "$dag_d_result_output"
dag_d_result_record="$(context_record_for_child "$first_user" "$dag_b_session" "$dag_d_session")"
dag_b_before_d_head="$(record_field "$dag_d_result_record" expected_parent_head)"
dag_b_after_d="$(receive_context_delivery "$first_user" "$dag_b_session" "$dag_d_result_record" dag-b-receive-d)"
dag_b_after_d_head="$(record_field "$dag_b_after_d" parent_head)"
dag_b_d_receipt="$(record_field "$dag_b_after_d" receipt_path)"
[[ -n "$dag_b_before_d_head" && -n "$dag_b_after_d_head" && -n "$dag_b_d_receipt" ]]

dag_b_final_output="$(mktemp)"
send_fixture_tty_control "$first_user" "$dag_b_session" \
  'fixture/deliver {"sequence":2,"kind":"result","mode":"follow-up","selected_text":"B final after D"}' \
  dag-b-final "$dag_b_final_output"
grep -q 'fixture-delivery=accepted' "$dag_b_final_output"
dag_b_final_record="$(context_record_for_child "$first_user" "$dag_parent_session" "$dag_b_session")"
dag_b_final_commit="$(record_field "$dag_b_final_record" delivery_commit)"
dag_parent_after_final="$(receive_context_delivery "$first_user" "$dag_parent_session" "$dag_b_final_record" dag-parent-receive-b-final)"
dag_parent_after_final_head="$(record_field "$dag_parent_after_final" parent_head)"
dag_parent_b_final_receipt="$(record_field "$dag_parent_after_final" receipt_path)"
[[ -n "$dag_b_final_commit" && -n "$dag_parent_after_final_head" && -n "$dag_parent_b_final_receipt" ]]

# Inspect the real daemon-owned SHA-256 Git artifact. This is evidence only:
# all creates, deliveries, and decisions above used the public client.
context_git="/var/lib/erebor/users/$(id -u "$first_user")/sessions/$dag_parent_session/context"
[[ -d "$context_git" ]]
git --git-dir="$context_git" fsck --no-dangling --no-progress
[[ "$(git --git-dir="$context_git" rev-parse "refs/scopes/$dag_parent_session/root")" == "$dag_parent_after_final_head" ]]
mapfile -t dag_parent_merge_parents < <(git --git-dir="$context_git" cat-file -p "$dag_parent_after_final_head" | sed -n 's/^parent //p')
[[ "${dag_parent_merge_parents[0]}" == "$dag_parent_after_c_head" ]]
[[ "${dag_parent_merge_parents[1]}" == "$dag_b_final_commit" ]]
mapfile -t dag_b_merge_parents < <(git --git-dir="$context_git" cat-file -p "$dag_b_after_d_head" | sed -n 's/^parent //p')
[[ "${dag_b_merge_parents[0]}" == "$dag_b_before_d_head" ]]
[[ "${dag_b_merge_parents[1]}" == "$(record_field "$dag_d_result_record" delivery_commit)" ]]
for receipt in "$dag_parent_b_receipt" "$dag_parent_c_receipt" "$dag_parent_b_final_receipt"; do
  git --git-dir="$context_git" cat-file -e "$dag_parent_after_final_head:$receipt"
done
git --git-dir="$context_git" cat-file -e "$dag_b_after_d_head:$dag_b_d_receipt"
git --git-dir="$context_git" grep -F "\"child_scope\":\"refs/scopes/$dag_b_session/root\"" \
  "$dag_parent_after_final_head" -- erebor/context-dag/edges >/dev/null
git --git-dir="$context_git" grep -F "\"child_scope\":\"refs/scopes/$dag_c_session/root\"" \
  "$dag_parent_after_final_head" -- erebor/context-dag/edges >/dev/null
git --git-dir="$context_git" grep -F "\"child_scope\":\"refs/scopes/$dag_d_session/root\"" \
  "$dag_b_after_d_head" -- erebor/context-dag/edges >/dev/null
git --git-dir="$context_git" grep -F "\"child_scope\":\"$dag_q_scope\"" \
  "$dag_b_after_q_final_head" -- erebor/context-dag/edges >/dev/null
git --git-dir="$context_git" grep -F '"execution_binding":"native_logical"' \
  "$dag_b_after_q_final_head" -- erebor/context-dag/edges >/dev/null
mapfile -t dag_q_final_merge_parents < <(git --git-dir="$context_git" cat-file -p "$dag_b_after_q_final_head" | sed -n 's/^parent //p')
[[ "${dag_q_final_merge_parents[0]}" == "$dag_b_after_q_partial_head" ]]
[[ "${dag_q_final_merge_parents[1]}" == "$(record_field "$dag_q_final_record" delivery_commit)" ]]
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
  --idempotency-key codex-runtime-disconnect-stop >/dev/null
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
  --idempotency-key codex-runtime-recovery-stop >/dev/null
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
