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
terminal_lease_probe=/usr/lib/erebor/erebor-terminal-lease-probe
config_path=/etc/erebor/erebord.json
trust_root=/usr/lib/erebor/codex-v1-fixture-trust
codex_agent_name=fixture-codex
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

for binary in "$erebor" "$fixture" "$terminal_lease_probe"; do
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
  local session_root="/var/lib/erebor/users/$(id -u "$user")/sessions"
  local session_id=""
  local record=""
  [[ -d "$session_root" ]] || return
  while IFS= read -r session_id; do
    record="$(as_user "$user" session inspect "$session_id" 2>/dev/null || true)"
    grep -q 'removed' <<<"$record" || printf '%s\n' "$session_id"
  done < <(find "$session_root" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort)
}

running_session_id() {
  local user="$1"
  local session_id=""
  while IFS= read -r session_id; do
    as_user "$user" session inspect "$session_id" 2>/dev/null | grep -q 'running' && {
      printf '%s\n' "$session_id"
      return
    }
  done < <(session_ids "$user")
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

await_terminal() {
  local user="$1"
  local session_id="$2"
  local output=""
  for _ in $(seq 1 150); do
    output="$(as_user "$user" session inspect "$session_id" 2>&1 || true)"
    if grep -Eq '(succeeded|failed|interrupted)' <<<"$output"; then
      return
    fi
    sleep 0.1
  done
  echo "Codex session $session_id did not become terminal" >&2
  echo "$output" >&2
  exit 1
}

start_tty_attachment() {
  local user="$1"
  local session_id="$2"
  local output="$3"
  local client_instance_id="$4"
  local initial_rows="$5"
  local initial_columns="$6"
  local resize_rows="$7"
  local resize_columns="$8"
  local delayed_resize=""

  tty_attachment_fifo="$(mktemp -u)"
  mkfifo "$tty_attachment_fifo"
  if [[ "$resize_rows" != 0 ]]; then
    delayed_resize="( sleep 2; stty rows $resize_rows cols $resize_columns ) &"
  fi
  timeout 20s runuser -u "$user" -- script -qefc \
    "stty rows $initial_rows cols $initial_columns; $delayed_resize exec $erebor session attach $session_id --input --client-instance-id $client_instance_id --idempotency-key $client_instance_id" \
    /dev/null <"$tty_attachment_fifo" >"$output" 2>&1 &
  tty_attachment_pid="$!"
  exec {tty_attachment_writer}>"$tty_attachment_fifo"
}

await_tty_attachment_output() {
  local output="$1"
  local expected="$2"
  for _ in $(seq 1 150); do
    grep -Fq "$expected" "$output" && return
    sleep 0.1
  done
  echo "TTY attachment did not emit expected output: $expected" >&2
  cat "$output" >&2
  exit 1
}

detach_tty_attachment() {
  printf '\020\021' >&"$tty_attachment_writer"
  exec {tty_attachment_writer}>&-
  wait "$tty_attachment_pid"
  rm -f "$tty_attachment_fifo"
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
  package_name="$(sed -n 's/^package_name=//p' <<<"$package_output")"
  fixture_policy_path="$(sed -n 's/^fixture_policy_path=//p' <<<"$package_output")"
  [[ -n "$package_name" && -n "$fixture_policy_path" ]]
  chown root:root "$config_path"
  chmod 0640 "$config_path"
}

configure_policy() {
  local user="$1"
  as_user "$user" policy package apply "$fixture_policy_path" \
    --name fixture-baseline \
    --idempotency-key "codex-runtime-policy-package-$user" \
    | grep -q 'policyPackage=fixture-baseline'
  as_user "$user" policyset create \
    --name fixture \
    --package fixture-baseline \
    --idempotency-key "codex-runtime-policy-set-$user" \
    | grep -q 'policySet=fixture'
}

load_fixture() {
  local user="$1"
  local user_fixture="/home/$user/codex-v1-fixture"
  install -o "$user" -g "$user" -m 0755 "$fixture" "$user_fixture"
  if as_user "$user" agent load \
    unknown-codex-v1-fixture \
    --from "$user_fixture" --adapter codex-v1 --name rejected-codex >/dev/null 2>&1; then
    echo "agent load accepted an unknown root-curated package" >&2
    exit 1
  fi
  cp "$user_fixture" "/home/$user/codex-v1-fixture-mutated"
  chown "$user:$user" "/home/$user/codex-v1-fixture-mutated"
  printf 'x' >>"/home/$user/codex-v1-fixture-mutated"
  if as_user "$user" agent load "$package_name" \
    --from "/home/$user/codex-v1-fixture-mutated" \
    --adapter codex-v1 --name rejected-codex >/dev/null 2>&1; then
    echo "agent load accepted an executable with the wrong artifact digest" >&2
    exit 1
  fi
  as_user "$user" agent load "$package_name" --from "$user_fixture" \
    --adapter codex-v1 --name "$codex_agent_name" \
    | grep -q "agent=$codex_agent_name"
}

run_app_server_frame() {
  local user="$1"
  local frame="$2"
  local output="$3"
  printf '%s\n' "$frame" | as_user "$user" run --policy fixture \
    --workspace "/home/$user" --app-server "$codex_agent_name" >"$output" 2>&1
}

record_field() {
  local record="$1"
  local field="$2"
  sed -n "s/^${field}=//p" <<<"$record" | head -n 1
}

scope_for_operation() {
  local session_id="$1"
  local operation_key="$2"
  local digest
  digest="$(printf '%s' "$operation_key" | sha256sum | awk '{print substr($1, 1, 20)}')"
  printf 'refs/scopes/%s/scope/codex-operation-%s\n' "$session_id" "$digest"
}

scope_for_logical_thread() {
  local session_id="$1"
  local thread_id="$2"
  local turn_id="$3"
  local child_digest operation_key
  child_digest="$(printf '%s\0%s' "$thread_id" "$turn_id" | sha256sum | awk '{print substr($1, 1, 32)}')"
  operation_key="fork-$child_digest"
  scope_for_operation "$session_id" "$operation_key"
}

scope_for_app_server_thread() {
  local session_id="$1"
  local thread_id="$2"
  local thread_digest
  thread_digest="$(printf '%s' "$thread_id" | sha256sum | awk '{print substr($1, 1, 32)}')"
  scope_for_operation "$session_id" "app-server-thread-$thread_digest"
}

edge_path_for_scope() {
  local scope="$1"
  local digest
  digest="$(printf '%s' "$scope" | sha256sum | awk '{print $1}')"
  printf 'erebor/context-dag/edges/%s.json\n' "$digest"
}

require_context_record() {
  local record="$1"
  [[ -n "$(record_field "$record" delivery_path)" \
    && -n "$(record_field "$record" delivery_commit)" \
    && -n "$(record_field "$record" expected_parent_head)" ]] || {
    echo "expected pending context delivery was not present" >&2
    exit 1
  }
}

context_record_for_scope() {
  local user="$1"
  local parent_session="$2"
  local child_scope="$3"
  as_user "$user" session context inbox "$parent_session" | awk -F '┆' \
    -v child_scope="$child_scope" '
      /^│/ {
        for (field = 1; field <= NF; field += 1) {
          gsub(/^[[:space:]]+|[[:space:]]+$/, "", $field)
        }
        if ($2 == child_scope) {
          print "delivery_path=" $3
          print "delivery_commit=" $4
          print "expected_parent_head=" $5
          exit
        }
      }
    '
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
    'exec "$1" run --policy fixture --workspace "$2" --app-server "$3" <"$4"' \
    -- "$erebor" "/home/$user" "$codex_agent_name" "$fifo" >"$output" 2>&1 &
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

start_live_app_server() {
  local user="$1"
  local fifo="$2"
  local output="$3"
  mkfifo "$fifo"
  runuser -u "$user" -- bash -c \
    'exec "$1" run --policy fixture --workspace "$2" --app-server "$3" <"$4"' \
    -- "$erebor" "/home/$user" "$codex_agent_name" "$fifo" >"$output" 2>&1 &
  live_client_pid="$!"
  exec {live_writer}>"$fifo"
}

send_live_app_server_frame() {
  printf '%s\n' "$1" >&"$live_writer"
}

await_live_app_server_output() {
  local output="$1"
  local expected="$2"
  for _ in $(seq 1 150); do
    grep -Fq "$expected" "$output" && return
    sleep 0.1
  done
  echo "live Codex App Server did not write expected output: $expected" >&2
  cat "$output" >&2
  exit 1
}

close_live_app_server_input() {
  local fifo="$1"
  exec {live_writer}>&-
  rm -f "$fifo"
}

exercise_single_session_context_dag() {
  local user="$1"
  local dag_output dag_fifo dag_session context_git p_scope b_scope c_scope d_scope q_scope
  local b_message_record c_cancel_record q_partial_record q_final_record d_result_record
  local b_final_record p_after_b p_after_c p_after_final b_after_q_partial b_after_q_final b_after_d
  local p_after_b_head p_after_c_head p_after_follow_head p_after_final_head b_after_q_partial_head
  local b_after_q_final_head b_after_d_head b_before_d_head

  dag_fifo="$(mktemp -u)"
  dag_output="$(mktemp)"
  start_live_app_server "$user" "$dag_fifo" "$dag_output"

  # App Server owns P's prompt binding. The subsequent fixture operations are
  # native hook facts from the same daemon-owned process and session.
  send_live_app_server_frame \
    '{"jsonrpc":"2.0","id":100,"method":"turn/start","params":{"threadId":"fixture-thread"}}'
  await_live_app_server_output "$dag_output" '"fixture":"ok"'
  dag_session="$(await_running_session "$user")"
  [[ "$(session_ids "$user" | wc -l | tr -d ' ')" == 1 ]] || {
    echo "typed App Server start created more than one Erebor session" >&2
    as_user "$user" session ps >&2
    exit 1
  }
  context_git="/var/lib/erebor/users/$(id -u "$user")/sessions/$dag_session/context"
  [[ -d "$context_git" ]]
  p_scope="$(scope_for_app_server_thread "$dag_session" fixture-thread)"
  b_scope="$(scope_for_logical_thread "$dag_session" fixture-b turn-1)"
  c_scope="$(scope_for_logical_thread "$dag_session" fixture-c turn-1)"
  d_scope="$(scope_for_logical_thread "$dag_session" fixture-d turn-1)"
  q_scope="$(scope_for_operation "$dag_session" fixture-q)"

  send_live_app_server_frame \
    '{"jsonrpc":"2.0","id":101,"method":"fixture/delegate","params":{"child_thread_id":"fixture-b","child_turn_id":"turn-1","frozen_context_mode":"all","last_turns":0,"tool_use_id":"fixture-p-b"}}'
  await_live_app_server_output "$dag_output" '"id":101,"result":{"fixture":"delegated"'
  send_live_app_server_frame \
    '{"jsonrpc":"2.0","id":102,"method":"fixture/turn"}'
  await_live_app_server_output "$dag_output" '"id":102,"result":{"fixture":"ok"'
  send_live_app_server_frame \
    '{"jsonrpc":"2.0","id":103,"method":"fixture/command","params":{"tool_use_id":"fixture-b-ls","command":"ls"}}'
  await_live_app_server_output "$dag_output" '"id":103,"result":{"fixture":"command-completed"'
  send_live_app_server_frame \
    '{"jsonrpc":"2.0","id":104,"method":"fixture/start-q"}'
  await_live_app_server_output "$dag_output" '"id":104,"result":{"fixture":"operation-started"'

  # Switches are fixture scheduler operations only. Each subsequent hook still
  # names a daemon-bound native thread/turn and cannot create another session.
  send_live_app_server_frame \
    '{"jsonrpc":"2.0","id":105,"method":"fixture/switch","params":{"thread_id":"fixture-thread","turn_id":"fixture-turn"}}'
  await_live_app_server_output "$dag_output" '"id":105,"result":{"fixture":"switched"'
  send_live_app_server_frame \
    '{"jsonrpc":"2.0","id":106,"method":"fixture/delegate","params":{"child_thread_id":"fixture-c","child_turn_id":"turn-1","frozen_context_mode":"none","last_turns":0,"tool_use_id":"fixture-p-c"}}'
  await_live_app_server_output "$dag_output" '"id":106,"result":{"fixture":"delegated"'
  send_live_app_server_frame \
    '{"jsonrpc":"2.0","id":107,"method":"fixture/switch","params":{"thread_id":"fixture-thread","turn_id":"fixture-turn"}}'
  await_live_app_server_output "$dag_output" '"id":107,"result":{"fixture":"switched"'
  send_live_app_server_frame \
    '{"jsonrpc":"2.0","id":108,"method":"fixture/control","params":{"action":"list_agents","tool_use_id":"fixture-p-list"}}'
  await_live_app_server_output "$dag_output" '"id":108,"result":{"control":'
  grep -q '"action":"list_agents"' "$dag_output"
  grep -q '"thread_id":"fixture-b"' "$dag_output"
  grep -q '"thread_id":"fixture-c"' "$dag_output"
  send_live_app_server_frame \
    '{"jsonrpc":"2.0","id":109,"method":"fixture/control","params":{"action":"interrupt","target_thread_id":"fixture-c","target_turn_id":"turn-1","tool_use_id":"fixture-p-interrupt-c"}}'
  await_live_app_server_output "$dag_output" '"id":109,"result":{"control":'
  grep -q '"action":"interrupt"' "$dag_output"

  # C emits its cancellation fact only after P's authenticated interruption
  # succeeds. P decides its receipt before taking any later action, so the
  # public compare-and-set parent head remains exact.
  c_cancel_record="$(context_record_for_scope "$user" "$dag_session" "$c_scope")"
  require_context_record "$c_cancel_record"
  p_after_c="$(reject_context_delivery "$user" "$dag_session" "$c_cancel_record" dag-parent-reject-c)"
  p_after_c_head="$(record_field "$p_after_c" parent_head)"
  [[ -n "$p_after_c_head" ]]

  send_live_app_server_frame \
    '{"jsonrpc":"2.0","id":110,"method":"fixture/control","params":{"action":"follow_up","target_thread_id":"fixture-b","target_turn_id":"turn-1","follow_up_text":"continue B after C was cancelled","tool_use_id":"fixture-p-follow-b"}}'
  await_live_app_server_output "$dag_output" '"id":110,"result":{"control":'
  grep -q '"action":"follow_up"' "$dag_output"
  p_after_follow_head="$(git --git-dir="$context_git" rev-parse "$p_scope")"
  send_live_app_server_frame \
    '{"jsonrpc":"2.0","id":111,"method":"fixture/command","params":{"tool_use_id":"fixture-b-after-q","command":"ls"}}'
  await_live_app_server_output "$dag_output" '"id":111,"result":{"fixture":"command-completed"'
  send_live_app_server_frame \
    '{"jsonrpc":"2.0","id":112,"method":"fixture/deliver","params":{"sequence":1,"kind":"message","mode":"queue","selected_text":"B queued message"}}'
  await_live_app_server_output "$dag_output" '"id":112,"result":{"fixture":"delivered"'

  b_message_record="$(context_record_for_scope "$user" "$dag_session" "$b_scope")"
  require_context_record "$b_message_record"
  p_after_b="$(receive_context_delivery "$user" "$dag_session" "$b_message_record" dag-parent-receive-b)"
  p_after_b_head="$(record_field "$p_after_b" parent_head)"
  [[ -n "$p_after_b_head" ]]
  [[ "$p_after_b_head" != "$p_after_follow_head" ]]

  # q is an operation scope below B. Its stream facts do not advance B; each
  # selected result enters B only through a public daemon/client receive.
  await_live_app_server_output "$dag_output" 'fixture-operation=q-delivery-1'
  q_partial_record="$(context_record_for_scope "$user" "$dag_session" "$q_scope")"
  require_context_record "$q_partial_record"
  b_after_q_partial="$(receive_context_delivery "$user" "$dag_session" "$q_partial_record" dag-b-receive-q-partial)"
  b_after_q_partial_head="$(record_field "$b_after_q_partial" parent_head)"
  [[ -n "$b_after_q_partial_head" ]]
  [[ "$(git --git-dir="$context_git" rev-parse "$p_scope")" == "$p_after_b_head" ]]

  await_live_app_server_output "$dag_output" 'fixture-operation=q-delivery-2'
  q_final_record="$(context_record_for_scope "$user" "$dag_session" "$q_scope")"
  require_context_record "$q_final_record"
  b_after_q_final="$(receive_context_delivery "$user" "$dag_session" "$q_final_record" dag-b-receive-q-final)"
  b_after_q_final_head="$(record_field "$b_after_q_final" parent_head)"
  [[ -n "$b_after_q_final_head" ]]

  send_live_app_server_frame \
    '{"jsonrpc":"2.0","id":113,"method":"fixture/delegate","params":{"child_thread_id":"fixture-d","child_turn_id":"turn-1","frozen_context_mode":"last_turns","last_turns":1,"tool_use_id":"fixture-b-d"}}'
  await_live_app_server_output "$dag_output" '"id":113,"result":{"fixture":"delegated"'
  send_live_app_server_frame \
    '{"jsonrpc":"2.0","id":114,"method":"fixture/command","params":{"tool_use_id":"fixture-d-ls","command":"ls"}}'
  await_live_app_server_output "$dag_output" '"id":114,"result":{"fixture":"command-completed"'
  send_live_app_server_frame \
    '{"jsonrpc":"2.0","id":115,"method":"fixture/deliver","params":{"sequence":1,"kind":"result","mode":"queue","selected_text":"D result"}}'
  await_live_app_server_output "$dag_output" '"id":115,"result":{"fixture":"delivered"'

  d_result_record="$(context_record_for_scope "$user" "$dag_session" "$d_scope")"
  require_context_record "$d_result_record"
  b_before_d_head="$(record_field "$d_result_record" expected_parent_head)"
  b_after_d="$(receive_context_delivery "$user" "$dag_session" "$d_result_record" dag-b-receive-d)"
  b_after_d_head="$(record_field "$b_after_d" parent_head)"
  [[ -n "$b_before_d_head" && -n "$b_after_d_head" ]]

  send_live_app_server_frame \
    '{"jsonrpc":"2.0","id":116,"method":"fixture/switch","params":{"thread_id":"fixture-b","turn_id":"turn-1"}}'
  await_live_app_server_output "$dag_output" '"id":116,"result":{"fixture":"switched"'
  send_live_app_server_frame \
    '{"jsonrpc":"2.0","id":117,"method":"fixture/deliver","params":{"sequence":2,"kind":"result","mode":"follow-up","selected_text":"B final after D"}}'
  await_live_app_server_output "$dag_output" '"id":117,"result":{"fixture":"delivered"'

  b_final_record="$(context_record_for_scope "$user" "$dag_session" "$b_scope")"
  require_context_record "$b_final_record"
  p_after_final="$(receive_context_delivery "$user" "$dag_session" "$b_final_record" dag-parent-receive-b-final)"
  p_after_final_head="$(record_field "$p_after_final" parent_head)"
  [[ -n "$p_after_final_head" ]]

  # The only repository access in this probe is a post-action inspection of
  # daemon-owned Git facts. All admits, delivery decisions, and graph reads
  # above use public daemon/client paths.
  git --git-dir="$context_git" fsck --no-dangling --no-progress
  /usr/lib/erebor/codex-context-dag-inspector \
    --repository "$context_git" \
    --session-id "$dag_session" \
    --edge "$p_scope|$b_scope|$(edge_path_for_scope "$b_scope")" \
    --edge "$p_scope|$c_scope|$(edge_path_for_scope "$c_scope")" \
    --edge "$b_scope|$d_scope|$(edge_path_for_scope "$d_scope")" \
    --edge "$b_scope|$q_scope|$(edge_path_for_scope "$q_scope")" \
    | grep -q 'context_dag_scopes=6'
  [[ "$(git --git-dir="$context_git" for-each-ref --format='%(refname)' "refs/scopes/$dag_session" | wc -l | tr -d ' ')" == 6 ]]
  [[ "$(git --git-dir="$context_git" rev-parse "$p_scope")" == "$p_after_final_head" ]]
  git --git-dir="$context_git" grep -F "\"child_scope\":\"$b_scope\"" "$p_after_final_head" -- erebor/context-dag/edges >/dev/null
  git --git-dir="$context_git" grep -F "\"child_scope\":\"$c_scope\"" "$p_after_final_head" -- erebor/context-dag/edges >/dev/null
  git --git-dir="$context_git" grep -F "\"child_scope\":\"$d_scope\"" "$b_after_d_head" -- erebor/context-dag/edges >/dev/null
  git --git-dir="$context_git" grep -F "\"child_scope\":\"$q_scope\"" "$b_after_q_final_head" -- erebor/context-dag/edges >/dev/null
  git --git-dir="$context_git" grep -F '"execution_binding":"native_logical"' "$p_after_final_head" -- erebor/context-dag/edges >/dev/null
  git --git-dir="$context_git" ls-tree -r "$p_after_final_head" -- agents/codex/app-server/prompts | grep -q .
  git --git-dir="$context_git" ls-tree -r "$b_after_d_head" -- agents/codex/physical-effects | grep -q .
  git --git-dir="$context_git" ls-tree -r "$(git --git-dir="$context_git" rev-parse "$d_scope")" -- agents/codex/physical-effects | grep -q .
  git --git-dir="$context_git" ls-tree -r "$(git --git-dir="$context_git" rev-parse "$q_scope")" -- agents/codex/physical-effects | grep -q .

  mapfile -t dag_p_merge_parents < <(git --git-dir="$context_git" cat-file -p "$p_after_final_head" | sed -n 's/^parent //p')
  [[ "${dag_p_merge_parents[0]}" == "$p_after_b_head" ]]
  [[ "${dag_p_merge_parents[1]}" == "$(record_field "$b_final_record" delivery_commit)" ]]
  mapfile -t dag_b_merge_parents < <(git --git-dir="$context_git" cat-file -p "$b_after_d_head" | sed -n 's/^parent //p')
  [[ "${dag_b_merge_parents[0]}" == "$b_before_d_head" ]]
  [[ "${dag_b_merge_parents[1]}" == "$(record_field "$d_result_record" delivery_commit)" ]]
  mapfile -t dag_q_merge_parents < <(git --git-dir="$context_git" cat-file -p "$b_after_q_final_head" | sed -n 's/^parent //p')
  [[ "${dag_q_merge_parents[0]}" == "$b_after_q_partial_head" ]]
  [[ "${dag_q_merge_parents[1]}" == "$(record_field "$q_final_record" delivery_commit)" ]]

  dag_graph="$(as_user "$user" session context graph "$dag_session")"
  grep -q 'logical fork fixture-b/turn-1' <<<"$dag_graph"
  grep -q 'tool bash command="ls"' <<<"$dag_graph"
  grep -q 'exec /usr/bin/ls allowed pid=' <<<"$dag_graph"
  grep -q 'delivery result #1 queued' <<<"$dag_graph"
  grep -q 'agent control list_agents' <<<"$dag_graph"
  grep -q 'agent control follow_up fixture-b/turn-1' <<<"$dag_graph"
  grep -q 'agent control interrupt fixture-c/turn-1' <<<"$dag_graph"

  close_live_app_server_input "$dag_fifo"
  wait "$live_client_pid"
  await_terminal "$user" "$dag_session"
  remove_all_sessions "$user"
}

configure_fixture
systemctl restart erebord.service
await_daemon

load_fixture "$first_user"
load_fixture "$second_user"
configure_policy "$first_user"
configure_policy "$second_user"

# The fixture never receives this caller path. Its TTY output proves the
# daemon copied the marker into the fixed CODEX_HOME projection and hid the
# live caller state before the workload started.
install -d -o "$first_user" -g "$first_user" -m 0700 \
  "/home/$first_user/.codex"
printf 'fixture-private-state' >"/home/$first_user/.codex/erebor-phase53-state-marker"
chown "$first_user:$first_user" \
  "/home/$first_user/.codex/erebor-phase53-state-marker"
chmod 0600 "/home/$first_user/.codex/erebor-phase53-state-marker"

if as_user "$first_user" run --policy fixture --workspace "/home/$first_user" \
  "$codex_agent_name" -- --escape-daemon-entrypoint >/dev/null 2>&1; then
  echo "the named Codex Agent accepted raw argv" >&2
  exit 1
fi
if as_user "$first_user" run --policy fixture --workspace "/home/$first_user" \
  fixture-not-an-entrypoint >/dev/null 2>&1; then
  echo "the daemon admitted a non-certified Codex entrypoint" >&2
  exit 1
fi

# This is the complete privileged interactive contract: a real PTY starts at
# the requested geometry, controller resize reaches the workload as SIGWINCH,
# an observer cannot write or resize, and a later controller reattaches to the
# same workload rather than creating another session or PTY.
tty_create_output="$(mktemp)"
timeout 20s runuser -u "$first_user" -- script -qefc \
  "stty rows 24 cols 80; $erebor run --policy fixture --workspace /home/$first_user $codex_agent_name -d" \
  /dev/null >"$tty_create_output"
tty_session="$(await_running_session "$first_user")"
[[ "$(session_ids "$first_user" | wc -l | tr -d ' ')" == 1 ]]

tty_first_output="$(mktemp)"
start_tty_attachment "$first_user" "$tty_session" "$tty_first_output" \
  phase4-tty-controller-a 24 80 40 120
await_tty_attachment_output "$tty_first_output" 'fixture-tty=ready'
await_tty_attachment_output "$tty_first_output" \
  'fixture-private-state=projected caller-state=hidden'
await_tty_attachment_output "$tty_first_output" 'fixture-tty-size=rows=24 columns=80'
await_tty_attachment_output "$tty_first_output" 'fixture-daemon-socket=absent'
await_tty_attachment_output "$tty_first_output" 'fixture-hook=accepted'
observer_output="$(runuser -u "$first_user" -- "$terminal_lease_probe" "$tty_session")"
grep -q 'observer_input=denied observer_resize=denied' <<<"$observer_output"
sleep 3
printf 'terminal-size\n' >&"$tty_attachment_writer"
await_tty_attachment_output "$tty_first_output" 'fixture-tty-size=rows=40 columns=120'
await_tty_attachment_output "$tty_first_output" 'fixture-tty-sigwinch=received'
detach_tty_attachment
tty_before_reattach="$(as_user "$first_user" session inspect "$tty_session")"
grep -q 'running' <<<"$tty_before_reattach"
tty_workload_identity="$(grep -o '"workload_identity":"[^"]*"' <<<"$tty_before_reattach")"
[[ -n "$tty_workload_identity" ]]

tty_second_output="$(mktemp)"
start_tty_attachment "$first_user" "$tty_session" "$tty_second_output" \
  phase4-tty-controller-b 50 140 0 0
await_tty_attachment_output "$tty_second_output" 'read_only=false'
printf 'terminal-size\n' >&"$tty_attachment_writer"
await_tty_attachment_output "$tty_second_output" 'fixture-tty-size=rows=50 columns=140'
await_tty_attachment_output "$tty_second_output" 'fixture-tty-sigwinch=received'
detach_tty_attachment
tty_after_reattach="$(as_user "$first_user" session inspect "$tty_session")"
grep -q 'running' <<<"$tty_after_reattach"
[[ "$tty_workload_identity" == "$(grep -o '"workload_identity":"[^"]*"' <<<"$tty_after_reattach")" ]]
as_user "$first_user" session stop "$tty_session" \
  --idempotency-key phase4-tty-stop >/dev/null
await_terminal "$first_user" "$tty_session"
remove_all_sessions "$first_user"

app_server_output="$(mktemp)"
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize"}' \
  '{"jsonrpc":"2.0","id":2,"method":"fixture/hook"}' \
  '{"jsonrpc":"2.0","method":"$/cancelRequest","params":{"id":2}}' \
  | as_user "$first_user" run --policy fixture --workspace "/home/$first_user" \
      --app-server "$codex_agent_name" >"$app_server_output" 2>&1
grep -q '"fixture":"accepted"' "$app_server_output"
grep -q '"fixture":"cancelled"' "$app_server_output"
remove_all_sessions "$first_user"

for frozen_context_mode in none all last_turns; do
  mode_output="$(mktemp)"
  mode_thread="fixture-mode-$frozen_context_mode"
  mode_child="fixture-child-$frozen_context_mode"
  if [[ "$frozen_context_mode" == last_turns ]]; then
    mode_params='"frozen_context_mode":"last_turns","last_turns":1'
  else
    mode_params="\"frozen_context_mode\":\"$frozen_context_mode\",\"last_turns\":0"
  fi
  run_app_server_frame "$first_user" \
    $'{"jsonrpc":"2.0","id":6,"method":"turn/start","params":{"threadId":"'"$mode_thread"'"}}\n' \
    $'{"jsonrpc":"2.0","id":7,"method":"fixture/delegate","params":{"child_thread_id":"'"$mode_child"'","child_turn_id":"turn-1",'"$mode_params"$'}}' \
    "$mode_output"
  grep -q '"fixture":"delegated"' "$mode_output"
  mode_session="$(session_ids "$first_user" | head -n 1)"
  [[ -n "$mode_session" && "$(session_ids "$first_user" | wc -l | tr -d ' ')" == 1 ]]
  mode_context_git="/var/lib/erebor/users/$(id -u "$first_user")/sessions/$mode_session/context"
  mode_parent_scope="$(scope_for_app_server_thread "$mode_session" "$mode_thread")"
  mode_child_scope="$(scope_for_logical_thread "$mode_session" "$mode_child" turn-1)"
  mode_parent_head="$(git --git-dir="$mode_context_git" rev-parse "$mode_parent_scope")"
  mode_edge_path="$(edge_path_for_scope "$mode_child_scope")"
  mode_edge="$(git --git-dir="$mode_context_git" show "$mode_parent_head:$mode_edge_path")"
  grep -Fq "\"child_scope\":\"$mode_child_scope\"" <<<"$mode_edge"
  grep -Fq "\"frozen_context_mode\":\"$frozen_context_mode\"" \
    <(git --git-dir="$mode_context_git" grep -h 'frozen_context_mode' "$mode_parent_head" -- agents/codex/hooks)
  if [[ "$frozen_context_mode" == none ]]; then
    ! grep -q '"used_paths"' <<<"$mode_edge"
  else
    grep -Fq '"used_paths":["agents/codex/app-server/prompts/' <<<"$mode_edge"
  fi
  remove_all_sessions "$first_user"
done

exercise_single_session_context_dag "$first_user"
for hook_case in hook-replay hook-wrong-peer hook-wrong-session; do
  hook_output="$(mktemp)"
  run_app_server_frame "$first_user" \
    "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"fixture/$hook_case\"}" \
    "$hook_output"
  grep -q "\"fixture\":\"${hook_case#hook-}-rejected\"" "$hook_output"
  remove_all_sessions "$first_user"
done

# A shared hook listener must not route by UID alone. Keep B registered under
# the same UID while A's real managed hook claims B's session id. The hook wire
# format deliberately carries no ticket string: the adapter derives A's
# guard-issued authority from the kernel peer. B must reject that peer/session
# combination, then A must still succeed, proving the failed hello neither
# routed nor consumed A's authority.
same_uid_fifo="$(mktemp -u)"
same_uid_wait_output="$(mktemp)"
start_waiting_app_server "$first_user" "$same_uid_fifo" "$same_uid_wait_output"
same_uid_session_b="$wait_session_id"
same_uid_cross_output="$(mktemp)"
run_app_server_frame "$first_user" \
  "{\"jsonrpc\":\"2.0\",\"id\":31,\"method\":\"fixture/hook-cross-session\",\"params\":{\"target_session_id\":\"$same_uid_session_b\"}}" \
  "$same_uid_cross_output"
grep -q '"fixture":"cross-session-rejected"' "$same_uid_cross_output"
as_user "$first_user" session inspect "$same_uid_session_b" | grep -q 'running'
close_waiting_app_server_input "$same_uid_fifo"
wait "$wait_client_parent"
await_terminal "$first_user" "$same_uid_session_b"
remove_all_sessions "$first_user"

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
as_user "$first_user" session inspect "$malformed_session" | grep -q 'failed'
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
as_user "$first_user" session inspect "$disconnect_session_id" | grep -q 'running'
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
as_user "$first_user" session inspect "$recovery_session_id" | grep -q 'running'
as_user "$first_user" session stop "$recovery_session_id" \
  --idempotency-key codex-runtime-recovery-stop >/dev/null
await_terminal "$first_user" "$recovery_session_id"
remove_all_sessions "$first_user"

# Replacing an enrolled artifact after all successful workflows must prevent a
# later daemon admission; the daemon re-resolves its held descriptor identity.
printf 'x' >>"/home/$first_user/codex-v1-fixture"
if as_user "$first_user" run --policy fixture --workspace "/home/$first_user" \
  "$codex_agent_name" -d >/dev/null 2>&1; then
  echo "the daemon admitted a replaced enrolled Codex artifact" >&2
  exit 1
fi
