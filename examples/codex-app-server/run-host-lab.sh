#!/usr/bin/env bash
set -Eeuo pipefail

# Run the deterministic Phase 4 Codex fixture on the host, without systemd.
# The lab is deliberately retained. This script never runs rm, never has a
# deletion trap, and never operates on a repository directory.

if [[ "$(uname -s)" != "Linux" ]]; then
  printf '%s\n' 'the Codex host lab requires Linux' >&2
  exit 1
fi
if [[ "$(id -u)" -ne 0 || -z "${SUDO_USER:-}" || "$SUDO_USER" == root ]]; then
  printf '%s\n' 'run this as a non-root developer with: sudo ./examples/codex-app-server/run-host-lab.sh' >&2
  exit 1
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "$script_dir/../.." && pwd -P)"
caller="$SUDO_USER"
caller_uid="$(id -u "$caller")"
caller_gid="$(id -g "$caller")"
target_dir="$repo_root/target/debug"

for binary in \
  erebor \
  erebord \
  erebor-path-broker \
  erebor-linux-session-controller \
  erebor-linux-process-guard \
  codex-v1-fixture; do
  if [[ ! -x "$target_dir/$binary" ]]; then
    printf 'missing %s; first run ./examples/codex-app-server/build-host-lab.sh\n' "$target_dir/$binary" >&2
    exit 1
  fi
done

# mktemp creates a fresh directory. It is retained after both success and
# failure so the developer can inspect daemon logs, config, and state.
lab_root="$(mktemp -d -p /tmp "erebor-codex-app-server-${caller_uid}.XXXXXX")"
chmod 0711 "$lab_root"
install -d -o root -g root -m 0750 \
  "$lab_root/bin" \
  "$lab_root/etc" \
  "$lab_root/log" \
  "$lab_root/run" \
  "$lab_root/state" \
  "$lab_root/trust"
install -d -o "$caller_uid" -g "$caller_gid" -m 0750 "$lab_root/caller"

stage_root_binary() {
  local name="$1"
  install -o root -g root -m 0755 "$target_dir/$name" "$lab_root/bin/$name"
}

stage_root_binary erebor
stage_root_binary erebord
stage_root_binary erebor-path-broker
stage_root_binary erebor-linux-session-controller
stage_root_binary erebor-linux-process-guard
stage_root_binary codex-v1-fixture
install -o "$caller_uid" -g "$caller_gid" -m 0755 \
  "$target_dir/codex-v1-fixture" "$lab_root/caller/codex-v1-fixture"

fixture_output="$("$lab_root/bin/codex-v1-fixture" configure \
  --config "$lab_root/etc/erebord.json" \
  --trust-root "$lab_root/trust" \
  --socket-group-gid "$caller_gid" \
  --owner-uid "$caller_uid" \
  --linux-runner-containment direct \
  --linux-runner-controller "$lab_root/bin/erebor-linux-session-controller" \
  --linux-process-guard "$lab_root/bin/erebor-linux-process-guard" \
  --descriptor-broker "$lab_root/bin/erebor-path-broker")"
package_reference="$(sed -n 's/^package_reference=//p' <<<"$fixture_output")"
root_policy_digest="$(sed -n 's/^root_policy_digest=//p' <<<"$fixture_output")"
if [[ -z "$package_reference" || -z "$root_policy_digest" ]]; then
  printf '%s\n' "fixture did not produce package and root-policy identities; retained lab: $lab_root" >&2
  exit 1
fi
chown root:root "$lab_root/etc/erebord.json"
chmod 0640 "$lab_root/etc/erebord.json"

"$lab_root/bin/erebord" \
  --config "$lab_root/etc/erebord.json" \
  --runtime-dir "$lab_root/run" \
  --log-dir "$lab_root/log" \
  --state-dir "$lab_root/state" &
daemon_pid="$!"

stop_daemon() {
  if kill -0 "$daemon_pid" 2>/dev/null; then
    kill -TERM "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" 2>/dev/null || true
  fi
}
trap stop_daemon EXIT INT TERM

socket="$lab_root/run/daemon.sock"
as_caller() {
  runuser -u "$caller" -- "$lab_root/bin/erebor" --socket "$socket" "$@"
}

daemon_ready=false
for _ in $(seq 1 100); do
  if as_caller daemon status >/dev/null 2>&1; then
    daemon_ready=true
    break
  fi
  sleep 0.1
done
if [[ "$daemon_ready" != true ]]; then
  printf '%s\n' "foreground erebord did not become ready; retained lab: $lab_root" >&2
  exit 1
fi

policy_output="$(as_caller policy set create \
  --root-minimum-digest "$root_policy_digest" \
  --idempotency-key "host-lab-policy-$caller_uid")"
policy_set_digest="$(sed -n 's/^digest=//p' <<<"$policy_output")"
if [[ -z "$policy_set_digest" ]]; then
  printf '%s\n' "could not create the fixture policy set; retained lab: $lab_root" >&2
  exit 1
fi
as_caller policy set alias fixture "$policy_set_digest" \
  --idempotency-key "host-lab-policy-alias-$caller_uid" >/dev/null

printf '%s\n' "temporary erebord is ready at $socket; type exit in the lab shell to stop it"
printf '%s\n' "The retained lab is $lab_root"
runuser -u "$caller" -- env \
  EREBOR_BIN="$lab_root/bin/erebor" \
  EREBOR_SOCKET="$socket" \
  EREBOR_CODEX_PACKAGE="$package_reference" \
  EREBOR_CODEX_FIXTURE="$lab_root/caller/codex-v1-fixture" \
  EREBOR_WORKSPACE="$repo_root" \
  bash --noprofile --rcfile "$script_dir/host-lab-shell.bash" -i

printf '%s\n' "foreground erebord stopped; the lab was retained at $lab_root"
