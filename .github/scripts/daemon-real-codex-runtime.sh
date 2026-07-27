#!/usr/bin/env bash
set -Eeuo pipefail

# This privileged acceptance uses the actual Codex TUI release mounted at the
# fixed test path. The loopback Responses server is only a deterministic model
# provider: the executable, managed hook, daemon admission, PTY, and guarded
# filesystem write are all the real production path.

if [[ "$(id -u)" -ne 0 || "$(uname -s)" != "Linux" ]]; then
  echo "the real Codex acceptance requires root on Linux" >&2
  exit 1
fi

erebor=/usr/local/bin/erebor
profile=/usr/lib/erebor/erebor-codex-real-profile
managed_hook=/usr/lib/erebor/erebor-codex-hook
terminal_lease_probe=/usr/lib/erebor/erebor-terminal-lease-probe
codex_release=/opt/erebor-real-codex-release
codex_source="$codex_release/bin/codex"
config_path=/etc/erebor/erebord.json
trust_root=/usr/lib/erebor/codex-real-profile-trust
policy_set=codex-runtime-guardrail-set
agent_name=local-codex
first_user="${EREBOR_INSTALLED_SESSION_USER:?first session user is required}"
second_user="${EREBOR_INSTALLED_SESSION_USER_TWO:?second session user is required}"
mock_server=/usr/local/lib/erebor/codex-real-tui-mock.py
mock_port=18080

report_failure() {
  local status="$?"
  echo "real Codex acceptance failed at line ${BASH_LINENO[0]}: $BASH_COMMAND" >&2
  systemctl status erebord.service --no-pager >&2 || true
  journalctl -u erebord.service --no-pager >&2 || true
  exit "$status"
}
trap report_failure ERR

for binary in "$erebor" "$profile" "$managed_hook" "$terminal_lease_probe" "$codex_source"; do
  [[ -x "$binary" ]] || {
    echo "required real Codex acceptance executable is missing: $binary" >&2
    exit 1
  }
done
[[ -f "$mock_server" ]] || {
  echo "real Codex mock provider is missing: $mock_server" >&2
  exit 1
}

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
  echo "real Codex session did not become running" >&2
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
  echo "real Codex session $session_id did not become terminal" >&2
  echo "$output" >&2
  exit 1
}

start_tty_attachment() {
  local user="$1"
  local session_id="$2"
  local output="$3"
  local client_instance_id="$4"
  local rows="$5"
  local columns="$6"
  tty_attachment_fifo="$(mktemp -u)"
  mkfifo "$tty_attachment_fifo"
  timeout 45s runuser -u "$user" -- script -qefc \
    "stty rows $rows cols $columns; exec $erebor session attach $session_id --input --client-instance-id $client_instance_id --idempotency-key $client_instance_id" \
    /dev/null <"$tty_attachment_fifo" >"$output" 2>&1 &
  tty_attachment_pid="$!"
  exec {tty_attachment_writer}>"$tty_attachment_fifo"
}

await_tty_output() {
  local output="$1"
  local expected="$2"
  for _ in $(seq 1 300); do
    grep -Fq "$expected" "$output" && return
    sleep 0.1
  done
  echo "real Codex TTY did not emit expected output: $expected" >&2
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
      --idempotency-key "real-codex-remove-$index" >/dev/null
  done < <(session_ids "$user")
}

write_private_config() {
  local user="$1"
  local home="/home/$user"
  # Keep the admitted workspace separate from the user's private Codex state.
  # A home-directory workspace would also expose ~/.codex as project-local
  # configuration, which Codex intentionally sanitizes differently from its
  # CODEX_HOME user configuration.
  install -d -o "$user" -g "$user" -m 0755 "$home/workspace"
  install -d -o "$user" -g "$user" -m 0700 "$home/.codex"
  cat >"$home/.codex/config.toml" <<EOF
model = "erebor-phase-5-local-mock"
model_provider = "erebor-phase-5"
approval_policy = "never"
sandbox_mode = "danger-full-access"

[features]
plugins = false

[model_providers.erebor-phase-5]
name = "Erebor Phase 5 local mock"
base_url = "http://127.0.0.1:$mock_port/v1"
wire_api = "responses"
request_max_retries = 0
stream_max_retries = 0
supports_websockets = false
requires_openai_auth = false
EOF
  printf 'real-codex-private-state\n' >"$home/.codex/erebor-phase55-state-marker"
  chown "$user:$user" "$home/.codex/config.toml" "$home/.codex/erebor-phase55-state-marker"
  chmod 0600 "$home/.codex/config.toml" "$home/.codex/erebor-phase55-state-marker"
}

configure_profile() {
  local group_gid package_output
  group_gid="$(stat -c %g /run/erebor/daemon.sock)"
  package_output="$("$profile" \
    --config "$config_path" \
    --trust-root "$trust_root" \
    --socket-group-gid "$group_gid" \
    --owner-uid "$(id -u "$first_user")" \
    --owner-uid "$(id -u "$second_user")" \
    --codex-executable "$codex_source" \
    --managed-hook "$managed_hook" \
    --linux-runner-containment systemd)"
  package_name="$(sed -n 's/^package_name=//p' <<<"$package_output")"
  policy_path="$(sed -n 's/^policy_path=//p' <<<"$package_output")"
  [[ "$package_name" == 'codex-cli-0-145-0' && -n "$policy_path" ]]
  chown root:root "$config_path"
  chmod 0640 "$config_path"
}

load_agent() {
  local user="$1"
  local user_codex="/home/$user/codex-cli-0-145-0"
  install -o "$user" -g "$user" -m 0755 "$codex_source" "$user_codex"
  as_user "$user" agent load "$package_name" --from "$user_codex" \
    --adapter codex-v1 --name "$agent_name" | grep -q "agent=$agent_name"
}

configure_policy() {
  local user="$1"
  as_user "$user" policy package apply "$policy_path" \
    --name codex-runtime-guardrail \
    --idempotency-key "real-codex-policy-package-$user" \
    | grep -q 'policyPackage=codex-runtime-guardrail'
  as_user "$user" policyset create --name "$policy_set" \
    --package codex-runtime-guardrail \
    --idempotency-key "real-codex-policy-set-$user" \
    | grep -q "policySet=$policy_set"
}

python3 "$mock_server" --port "$mock_port" &
mock_server_pid="$!"
trap 'kill "$mock_server_pid" >/dev/null 2>&1 || true' EXIT
sleep 0.2

write_private_config "$first_user"
first_config_digest="$(sha256sum "/home/$first_user/.codex/config.toml")"
first_marker_digest="$(sha256sum "/home/$first_user/.codex/erebor-phase55-state-marker")"
configure_profile
systemctl restart erebord.service
await_daemon

load_agent "$first_user"
load_agent "$second_user"
configure_policy "$first_user"

workspace="/home/$first_user/workspace"

if as_user "$first_user" run --policy "$policy_set" --workspace "$workspace" \
  "$agent_name" -- --unadmitted-raw-argument >/dev/null 2>&1; then
  echo "the real named Codex Agent accepted raw argv" >&2
  exit 1
fi

tty_create_output="$(mktemp)"
timeout 180s runuser -u "$first_user" -- script -qefc \
  "stty rows 24 cols 80; $erebor run --policy $policy_set --workspace $workspace $agent_name -d" \
  /dev/null >"$tty_create_output"
tty_session="$(await_running_session "$first_user")"
[[ "$(session_ids "$first_user" | wc -l | tr -d ' ')" == 1 ]]

tty_output="$(mktemp)"
start_tty_attachment "$first_user" "$tty_session" "$tty_output" \
  real-codex-controller-a 24 80
await_tty_output "$tty_output" 'Press enter to continue'
observer_output="$(runuser -u "$first_user" -- "$terminal_lease_probe" "$tty_session")"
grep -q 'observer_input=denied observer_resize=denied' <<<"$observer_output"
printf '\r' >&"$tty_attachment_writer"
# The hint above the composer is intentionally rotated by Codex. The provider
# and model status is the stable post-trust readiness marker for this pinned
# Codex release.
await_tty_output "$tty_output" 'erebor-phase-5-local-mock default'
printf 'Run the configured Erebor guardrail check.' >&"$tty_attachment_writer"
# The terminal broker forwards input as an ordered byte stream. Let Codex
# render the final character before sending Enter so the prompt is submitted,
# rather than racing its post-trust TUI transition.
sleep 0.2
printf '\r' >&"$tty_attachment_writer"
await_tty_output "$tty_output" 'Erebor guardrail test completed.'

[[ ! -e "$workspace/.erebor-denied" ]]
session_root="/var/lib/erebor/users/$(id -u "$first_user")/sessions/$tty_session"
[[ -d "$session_root/filesystem/repo" ]]
[[ -f "$session_root/filesystem/work/volumes/agent-state/lower-ro/erebor-phase55-state-marker" ]]
grep -Fxq 'real-codex-private-state' \
  "$session_root/filesystem/work/volumes/agent-state/lower-ro/erebor-phase55-state-marker"
# Filesystem policy decisions are retained beneath the Session output plan as
# the filesystem Surface's daemon-owned evidence, not as a legacy audit.jsonl.
filesystem_audit="$session_root/output/evidence/filesystem-decisions.jsonl"
grep -q 'deny-governed-marker-' "$filesystem_audit"
grep -q '"type":"deny"' "$filesystem_audit"
[[ "$first_config_digest" == "$(sha256sum "/home/$first_user/.codex/config.toml")" ]]
[[ "$first_marker_digest" == "$(sha256sum "/home/$first_user/.codex/erebor-phase55-state-marker")" ]]

tty_before_reattach="$(as_user "$first_user" session inspect "$tty_session")"
grep -q 'running' <<<"$tty_before_reattach"
grep -q 'local-codex' <<<"$tty_before_reattach"
grep -q 'codex-runtime-guardrail-set' <<<"$tty_before_reattach"
grep -q 'erebor.dev/v1' <<<"$tty_before_reattach"
detach_tty_attachment

tty_second_output="$(mktemp)"
start_tty_attachment "$first_user" "$tty_session" "$tty_second_output" \
  real-codex-controller-b 50 140
await_tty_output "$tty_second_output" 'read_only=false'
detach_tty_attachment
tty_after_reattach="$(as_user "$first_user" session inspect "$tty_session")"
grep -q 'running' <<<"$tty_after_reattach"

as_user "$first_user" session stop "$tty_session" \
  --idempotency-key real-codex-stop >/dev/null
await_terminal "$first_user" "$tty_session"
remove_all_sessions "$first_user"

printf 'real_codex_tui_governed_acceptance=passed\n'
