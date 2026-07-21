#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "this systemd service probe must run as root" >&2
  exit 1
fi
if [[ "$(uname -s)" != "Linux" ]]; then
  echo "this systemd service probe requires Linux" >&2
  exit 1
fi

erebord=/usr/lib/erebor/erebord
erebor=/usr/local/bin/erebor
service_group=erebor
service_user=erebor-daemon-service-client
service_user_two=erebor-daemon-service-client-two
outside_user=erebor-daemon-service-outsider
config_dir=/etc/erebor
config_path="$config_dir/erebord.json"
socket=/run/erebor/daemon.sock
lock_path=/run/erebor/erebord.lock

for command in systemctl groupadd useradd userdel groupdel getent runuser; do
  command -v "$command" >/dev/null || {
    echo "missing required command: $command" >&2
    exit 1
  }
done
if [[ ! -x "$erebord" || ! -x "$erebor" ]]; then
  echo "installed daemon or client binary is missing" >&2
  exit 1
fi
if getent group "$service_group" >/dev/null; then
  echo "refusing to modify pre-existing service group: $service_group" >&2
  exit 1
fi
for account in "$service_user" "$service_user_two" "$outside_user"; do
  if id "$account" >/dev/null 2>&1; then
    echo "refusing to modify pre-existing service user: $account" >&2
    exit 1
  fi
done

cleanup() {
  systemctl stop erebord.service >/dev/null 2>&1 || true
  userdel --remove "$service_user" >/dev/null 2>&1 || true
  userdel --remove "$service_user_two" >/dev/null 2>&1 || true
  userdel --remove "$outside_user" >/dev/null 2>&1 || true
  groupdel "$service_group" >/dev/null 2>&1 || true
}
trap cleanup EXIT

report_failure() {
  local status="$?"
  echo "systemd service probe failed at: $BASH_COMMAND" >&2
  systemctl status erebord.service --no-pager >&2 || true
  journalctl -u erebord.service --no-pager >&2 || true
  if [[ -f /var/log/erebor/daemon.jsonl ]]; then
    cat /var/log/erebor/daemon.jsonl >&2 || true
  fi
  while IFS= read -r diagnostics; do
    echo "runner controller diagnostics: $diagnostics" >&2
    cat "$diagnostics" >&2 || true
  done < <(find /var/lib/erebor/users -name '*-controller-diagnostics.log' -type f 2>/dev/null)
  exit "$status"
}
trap report_failure ERR

await_service() {
  local last_client_error=""
  for _ in $(seq 1 100); do
    if last_client_error="$("$erebor" daemon status 2>&1)"; then
      return
    fi
    if ! systemctl is-active --quiet erebord.service; then
      systemctl status erebord.service --no-pager >&2 || true
      journalctl -u erebord.service --no-pager >&2 || true
      echo "erebord.service stopped before accepting control-plane requests" >&2
      exit 1
    fi
    sleep 0.1
  done
  systemctl status erebord.service --no-pager >&2 || true
  journalctl -u erebord.service --no-pager >&2 || true
  if [[ -f /var/log/erebor/daemon.jsonl ]]; then
    cat /var/log/erebor/daemon.jsonl >&2 || true
  fi
  echo "$last_client_error" >&2
  echo "timed out waiting for erebord.service at $socket" >&2
  exit 1
}

groupadd --system "$service_group"
useradd --create-home --groups "$service_group" "$service_user"
useradd --create-home --groups "$service_group" "$service_user_two"
useradd --create-home "$outside_user"
group_gid="$(getent group "$service_group" | cut -d: -f3)"

install -d -o root -g root -m 0750 "$config_dir"
printf '{"socket_group_gid":%s,"max_log_bytes":4096,"max_log_records":32,"max_idempotency_records":256,"max_session_output_bytes":67108864,"session_output_rotation_bytes":4194304,"max_daemon_loss_grace_seconds":2}\n' "$group_gid" \
  >"$config_path"
chown root:root "$config_path"
chmod 0640 "$config_path"

systemctl daemon-reload
systemctl enable erebord.service
systemctl start erebord.service
systemctl is-enabled --quiet erebord.service
await_service

[[ "$(stat -c '%U:%G:%a' "$socket")" == "root:$service_group:660" ]]
runuser -u "$service_user" -- "$erebor" daemon status | grep -q 'state=running'
if runuser -u "$outside_user" -- "$erebor" daemon status >/dev/null 2>&1; then
  echo "user outside the connection group reached the installed control socket" >&2
  exit 1
fi
if runuser -u "$service_user" -- "$erebor" daemon logs --maximum-records 1 >/dev/null 2>&1; then
  echo "non-root caller read installed daemon logs" >&2
  exit 1
fi
if runuser -u "$service_user" -- "$erebor" daemon reload \
  --idempotency-key daemon-systemd-nonroot-reload >/dev/null 2>&1; then
  echo "non-root caller reloaded the installed daemon" >&2
  exit 1
fi
if runuser -u "$service_user" -- "$erebor" daemon stop \
  --idempotency-key daemon-systemd-nonroot-stop >/dev/null 2>&1; then
  echo "non-root caller stopped the installed daemon" >&2
  exit 1
fi

"$erebor" daemon logs --maximum-records 32 | grep -q 'daemon control service started'
"$erebor" daemon reload --idempotency-key daemon-systemd-reload \
  | grep -q 'configuration reloaded'
lock_inode="$(stat -c '%i' "$lock_path")"
systemctl restart erebord.service
await_service
[[ "$lock_inode" == "$(stat -c '%i' "$lock_path")" ]]

systemctl stop erebord.service
if systemctl is-active --quiet erebord.service; then
  echo "erebord.service remained active after systemctl stop" >&2
  exit 1
fi
[[ "$lock_inode" == "$(stat -c '%i' "$lock_path")" ]]
systemctl start erebord.service
await_service

EREBOR_INSTALLED_SESSION_USER="$service_user" \
EREBOR_INSTALLED_SESSION_USER_TWO="$service_user_two" \
bash /usr/local/lib/erebor/daemon-installed-session-runtime.sh

EREBOR_DAEMON_CONTROL_EREBORD="$erebord" \
EREBOR_DAEMON_CONTROL_EREBOR="$erebor" \
bash /usr/local/lib/erebor/daemon-control-plane.sh
