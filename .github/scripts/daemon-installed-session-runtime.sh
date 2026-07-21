#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "$(id -u)" -ne 0 || "$(uname -s)" != "Linux" ]]; then
  echo "the installed session-runtime probe requires root on Linux" >&2
  exit 1
fi

report_failure() {
  local status="$?"
  echo "installed session-runtime probe failed at line ${BASH_LINENO[0]}: $BASH_COMMAND" >&2
  exit "$status"
}
trap report_failure ERR

driver=/usr/local/lib/erebor/erebor-daemon-session-driver
erebor=/usr/local/bin/erebor
first_user="${EREBOR_INSTALLED_SESSION_USER:?first session user is required}"
second_user="${EREBOR_INSTALLED_SESSION_USER_TWO:?second session user is required}"
fixture_tar=/usr/local/lib/erebor/docker-fixture-root.tar
config_path=/etc/erebor/erebord.json
policy_digest=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

for binary in \
  "$driver" \
  /usr/libexec/erebor/erebor-linux-session-controller \
  /usr/libexec/erebor/erebor-docker-session-controller \
  /usr/libexec/erebor/erebor-linux-process-guard \
  /usr/libexec/erebor/erebor-path-broker; do
  [[ -x "$binary" ]] || {
    echo "installed private runtime binary is missing: $binary" >&2
    exit 1
  }
done

session_id_from() {
  sed -n 's/^session_id=\([^ ]*\).*/\1/p'
}

runner_recovery_from() {
  sed -n 's/.* runner_recovery=\([^ ]*\).*/\1/p'
}

uid_of() {
  stat -c %u "/home/$1"
}

gid_of() {
  stat -c %g "/home/$1"
}

await_daemon() {
  for _ in $(seq 1 150); do
    "$erebor" daemon status >/dev/null 2>&1 && return
    sleep 0.1
  done
  "$erebor" daemon status
}

write_config() {
  local maximum_loss_grace="$1"
  local group_gid
  group_gid="$(stat -c %g /run/erebor/daemon.sock)"
  printf '{"socket_group_gid":%s,"max_log_bytes":4096,"max_log_records":32,"max_idempotency_records":256,"max_session_output_bytes":67108864,"session_output_rotation_bytes":4194304,"max_daemon_loss_grace_seconds":%s,"phase_two_validated_fixtures":[{"package_digest":"%s","installation_digest":"%s","adapter_digest":"%s","policy_input_digests":["%s"],"policy_set_digest":"%s"}]}\n' \
    "$group_gid" "$maximum_loss_grace" "$policy_digest" "$policy_digest" \
    "$policy_digest" "$policy_digest" "$policy_digest" >"$config_path"
  chown root:root "$config_path"
  chmod 0640 "$config_path"
}

marker_live() {
  local marker="$1"
  local command_line argument
  for command_line in /proc/[0-9]*/cmdline; do
    while IFS= read -r -d '' argument; do
      if [[ "$argument" == *"$marker"* ]]; then
        return 0
      fi
    done 2>/dev/null <"$command_line" || true
  done
  return 1
}

as_user() {
  local user="$1"
  shift
  runuser -u "$user" -- "$driver" "$@"
}

await_log() {
  local user="$1"
  local session_id="$2"
  local expected="$3"
  local output=""
  for _ in $(seq 1 100); do
    output="$(as_user "$user" logs "$session_id" 2>&1 || true)"
    if grep -q "$expected" <<<"$output"; then
      return
    fi
    sleep 0.1
  done
  echo "session $session_id did not emit expected output: $expected" >&2
  echo "$output" >&2
  exit 1
}

await_log_after() {
  local user="$1"
  local session_id="$2"
  local after="$3"
  local expected="$4"
  local output=""
  for _ in $(seq 1 100); do
    output="$(
      as_user "$user" logs "$session_id" --after "$after" 2>&1 || true
    )"
    if grep -q "$expected" <<<"$output"; then
      return
    fi
    sleep 0.1
  done
  echo "session $session_id did not resume output after cursor $after" >&2
  echo "$output" >&2
  exit 1
}

await_event_after() {
  local user="$1"
  local session_id="$2"
  local after="$3"
  local expected="$4"
  local output=""
  for _ in $(seq 1 100); do
    output="$(
      as_user "$user" events "$session_id" --after "$after" 2>&1 || true
    )"
    if grep -q "kind=$expected" <<<"$output"; then
      return
    fi
    sleep 0.1
  done
  echo "session $session_id did not resume events after cursor $after" >&2
  echo "$output" >&2
  exit 1
}

await_state() {
  local user="$1"
  local session_id="$2"
  local expected="$3"
  local output=""
  for _ in $(seq 1 150); do
    output="$(as_user "$user" inspect "$session_id" 2>&1 || true)"
    if grep -q "state=$expected" <<<"$output"; then
      return
    fi
    sleep 0.1
  done
  echo "session $session_id did not reach state $expected" >&2
  echo "$output" >&2
  exit 1
}

create_linux() {
  local user="$1"
  local mode="$2"
  local label="$3"
  local loss_grace="${4:-1}"
  as_user "$user" create \
    --runner linux-host \
    --workspace "/home/$user" \
    --failure-mode "$mode" \
    --loss-grace-seconds "$loss_grace" \
    --key "create-$label" \
    -- /usr/bin/dash -c \
    'test "$(id -u)" != 0; test "$(id -G)" = "$(id -g)"; test "$(umask)" = 0077; test "$(ulimit -n)" = 1024; test -z "${EREBOR_ROOT_SENTINEL+x}"; test ! -e /run/erebor/daemon.sock; test ! -e /proc/1/root/run/erebor/daemon.sock; test ! -r /var/lib/erebor; for fd in /proc/self/fd/*; do test "$(/usr/bin/readlink "$fd" 2>/dev/null || :)" != /run/erebor/daemon.sock; done; rm -f denied-marker; ! /usr/bin/dash -c "printf forbidden > denied-marker" erebor-phase-two-denied; test ! -e denied-marker; /usr/bin/setsid /usr/bin/dash -c "while :; do sleep 1; done" "erebor-child-$0" </dev/null >/dev/null 2>&1 & /usr/bin/dash -c "/usr/bin/dash -c \"while :; do sleep 1; done\" \"\$0\" </dev/null >/dev/null 2>&1 &" "erebor-grandchild-$0" & printf "identity %s %s\n" "$(id -u)" "$(id -g)"; printf "linux-ready-%s\n" "$0"; printf "linux-stderr-%s\n" "$0" >&2; while :; do printf "%s-tick\n" "$0"; sleep 1; done' \
    "$label"
}

create_docker() {
  local user="$1"
  local mode="$2"
  local label="$3"
  local loss_grace="${4:-1}"
  as_user "$user" create \
    --runner docker \
    --workspace "/home/$user" \
    --failure-mode "$mode" \
    --loss-grace-seconds "$loss_grace" \
    --image-digest "$docker_digest" \
    --key "create-$label" \
    -- /bin/sh -c \
    'test "$(id -u)" != 0; test "$(id -G)" = "$(id -g)"; test "$(umask)" = 0022; test "$(ulimit -n)" = 1024; test -z "${EREBOR_ROOT_SENTINEL+x}"; test ! -e /run/erebor/daemon.sock; test ! -e /proc/1/root/run/erebor/daemon.sock; test ! -e /var/lib/erebor; for fd in /proc/self/fd/*; do test "$(/bin/busybox readlink "$fd" 2>/dev/null || :)" != /run/erebor/daemon.sock; done; /bin/busybox setsid /bin/sh -c "while :; do sleep 1; done" "erebor-child-$0" </dev/null >/dev/null 2>&1 & /bin/sh -c "/bin/sh -c \"while :; do sleep 1; done\" \"\$0\" </dev/null >/dev/null 2>&1 &" "erebor-grandchild-$0" & printf "identity %s %s\n" "$(id -u)" "$(id -g)"; printf "docker-ready-%s\n" "$0"; printf "docker-stderr-%s\n" "$0" >&2; while :; do printf "%s-tick\n" "$0"; sleep 1; done' \
    "$label"
}

start_session() {
  local user="$1"
  local session_id="$2"
  local label="$3"
  local output
  if ! output="$(as_user "$user" start "$session_id" --key "start-$label" 2>&1)"; then
    echo "session $session_id start failed: $output" >&2
    return 1
  fi
  if ! grep -q 'state=running' <<<"$output"; then
    echo "session $session_id did not start in running state: $output" >&2
    as_user "$user" events "$session_id" >&2 || true
    as_user "$user" logs "$session_id" --stream stderr >&2 || true
    return 1
  fi
}

remove_session() {
  local user="$1"
  local session_id="$2"
  local label="$3"
  as_user "$user" remove "$session_id" --force --key "remove-$label" \
    | grep -q 'state=removed'
}

assert_scope() {
  local session_id="$1"
  local runner_recovery="$2"
  local scope="erebor-session-$session_id.scope"
  local session_slice="erebor-session-$session_id.slice"
  local controller_pid
  local container_id
  local session_cgroup
  controller_pid="$(sed -n 's/.*"controller_pid":\([0-9]*\).*/\1/p' <<<"$runner_recovery")"
  container_id="$(sed -n 's/.*"container_id":"\([^"]*\)".*/\1/p' <<<"$runner_recovery")"
  session_cgroup="$(
    systemctl show "$session_slice" --property=ControlGroup --value
  )"
  [[ -n "$controller_pid" ]]
  [[ -n "$session_cgroup" ]]
  if [[ -n "$container_id" ]]; then
    [[ "$(readlink "/proc/$controller_pid/exe")" == \
      /usr/libexec/erebor/erebor-docker-session-controller ]]
  else
    [[ "$(readlink "/proc/$controller_pid/exe")" == \
      /usr/libexec/erebor/erebor-linux-session-controller ]]
  fi
  [[ "$(systemctl show "$scope" --property=PartOf --value)" == "" ]]
  [[ "$(systemctl show "$scope" --property=BindsTo --value)" == "" ]]
  [[ "$(systemctl show "$scope" --property=ControlGroup --value)" != \
    "$(systemctl show erebord.service --property=ControlGroup --value)" ]]
  [[ "$(systemctl show "$scope" --property=ControlGroup --value)" == \
    "$session_cgroup/$scope" ]]
  if [[ -n "$container_id" ]]; then
    [[ "$(docker inspect --format '{{.HostConfig.CgroupParent}}' "$container_id")" == \
      "$session_slice" ]]
    [[ "$(systemctl show "docker-$container_id.scope" \
      --property=ControlGroup --value)" == \
      "$session_cgroup/docker-$container_id.scope" ]]
  fi
}

run_service_loss_case() {
  local action="$1"
  local prefix="$2"
  local linux_terminate_label="$prefix-linux-terminate"
  local linux_continue_label="$prefix-linux-continue"
  local docker_terminate_label="$prefix-docker-terminate"
  local docker_continue_label="$prefix-docker-continue"
  local linux_terminate linux_continue docker_terminate docker_continue

  linux_terminate="$(
    create_linux "$first_user" terminate "$linux_terminate_label" | session_id_from
  )"
  linux_continue="$(
    create_linux "$second_user" continue "$linux_continue_label" | session_id_from
  )"
  docker_terminate="$(
    create_docker "$first_user" terminate "$docker_terminate_label" | session_id_from
  )"
  docker_continue="$(
    create_docker "$second_user" continue "$docker_continue_label" | session_id_from
  )"
  start_session "$first_user" "$linux_terminate" "$linux_terminate_label"
  start_session "$second_user" "$linux_continue" "$linux_continue_label"
  start_session "$first_user" "$docker_terminate" "$docker_terminate_label"
  start_session "$second_user" "$docker_continue" "$docker_continue_label"
  await_log "$first_user" "$linux_terminate" "linux-ready-$linux_terminate_label"
  await_log "$second_user" "$linux_continue" "linux-ready-$linux_continue_label"
  await_log "$first_user" "$docker_terminate" "docker-ready-$docker_terminate_label"
  await_log "$second_user" "$docker_continue" "docker-ready-$docker_continue_label"

  marker_live "erebor-child-$linux_terminate_label"
  marker_live "erebor-child-$linux_continue_label"
  marker_live "erebor-child-$docker_terminate_label"
  marker_live "erebor-child-$docker_continue_label"
  marker_live "erebor-grandchild-$linux_terminate_label"
  marker_live "erebor-grandchild-$linux_continue_label"
  marker_live "erebor-grandchild-$docker_terminate_label"
  marker_live "erebor-grandchild-$docker_continue_label"

  if [[ "$action" == restart ]]; then
    systemctl reset-failed erebord.service
    systemctl restart erebord.service
  else
    systemctl stop erebord.service
    if "$erebor" daemon status >/dev/null 2>&1; then
      echo "daemon control remained available after systemctl stop" >&2
      exit 1
    fi
    for _ in $(seq 1 30); do
      if ! marker_live "erebor-child-$linux_terminate_label" &&
        ! marker_live "erebor-grandchild-$linux_terminate_label" &&
        ! marker_live "erebor-child-$docker_terminate_label" &&
        ! marker_live "erebor-grandchild-$docker_terminate_label"; then
        break
      fi
      sleep 0.1
    done
    marker_live "erebor-child-$linux_continue_label"
    marker_live "erebor-child-$docker_continue_label"
    marker_live "erebor-grandchild-$linux_continue_label"
    marker_live "erebor-grandchild-$docker_continue_label"
    systemctl reset-failed erebord.service
    systemctl start erebord.service
  fi
  await_daemon

  as_user "$first_user" wait "$linux_terminate" \
    | grep -Eq 'state=(failed|interrupted)'
  as_user "$first_user" wait "$docker_terminate" \
    | grep -Eq 'state=(failed|interrupted)'
  await_state "$second_user" "$linux_continue" running
  await_state "$second_user" "$docker_continue" running
  if marker_live "erebor-child-$linux_terminate_label" ||
    marker_live "erebor-grandchild-$linux_terminate_label" ||
    marker_live "erebor-child-$docker_terminate_label" ||
    marker_live "erebor-grandchild-$docker_terminate_label"; then
    echo "$action left a terminate-mode workload alive" >&2
    exit 1
  fi
  marker_live "erebor-child-$linux_continue_label"
  marker_live "erebor-child-$docker_continue_label"
  marker_live "erebor-grandchild-$linux_continue_label"
  marker_live "erebor-grandchild-$docker_continue_label"
  await_log "$second_user" "$linux_continue" "$linux_continue_label-tick"
  await_log "$second_user" "$docker_continue" "$docker_continue_label-tick"

  remove_session "$first_user" "$linux_terminate" "$linux_terminate_label"
  remove_session "$first_user" "$docker_terminate" "$docker_terminate_label"
  remove_session "$second_user" "$linux_continue" "$linux_continue_label"
  remove_session "$second_user" "$docker_continue" "$docker_continue_label"
  [[ -z "$(docker ps -aq --filter "label=dev.erebor.session_id=$docker_terminate")" ]]
  [[ -z "$(docker ps -aq --filter "label=dev.erebor.session_id=$docker_continue")" ]]
}

systemctl start docker.service
for _ in $(seq 1 100); do
  docker info >/dev/null 2>&1 && break
  sleep 0.1
done
docker info >/dev/null
docker_image="$(docker import "$fixture_tar" erebor-installed-fixture:local)"
[[ "$docker_image" =~ ^sha256:[0-9a-f]{64}$ ]]
docker_digest="${docker_image#sha256:}"

systemctl set-environment EREBOR_ROOT_SENTINEL=phase-two-root-secret
systemctl reset-failed erebord.service
systemctl restart erebord.service
await_daemon

created_only="$(create_linux "$first_user" terminate created-only | session_id_from)"
created_uid="$(uid_of "$first_user")"
[[ -n "$created_only" ]]
as_user "$first_user" inspect "$created_only" | grep -q 'state=created'
[[ ! -e "/run/erebor/sessions/$created_uid/$created_only" ]]
if systemctl is-active --quiet "erebor-session-$created_only.scope" ||
  systemctl is-active --quiet "erebor-session-$created_only.slice"; then
  echo "create-only session opened a systemd scope" >&2
  exit 1
fi
if marker_live erebor-child-created-only; then
  echo "create-only session launched a workload" >&2
  exit 1
fi
created_record="/var/lib/erebor/users/$created_uid/sessions/$created_only/session.json"
python3 -c '
import json, sys
record = json.load(open(sys.argv[1], encoding="utf-8"))
spec = record["spec"]
assert record["state"] == "created"
assert spec["schema_version"] == 3
assert spec["runner_capability"]["schema_version"] == 2
assert spec["runner_capability"]["runner"] == "linux-host"
assert spec["policy_set"]["sha256"] == sys.argv[2]
assert spec["package"]["sha256"] == sys.argv[2]
assert spec["installation"]["sha256"] == sys.argv[2]
assert spec["adapter"]["sha256"] == sys.argv[2]
assert spec["secret_references"] == ["phase-two-secret-provider://fixture"]
assert "phase-two-root-secret" not in json.dumps(record)
' "$created_record" "$policy_digest"
if as_user "$first_user" admin-set-retention-hold \
  --uid "$created_uid" "$created_only" --retention-hold true \
  --key non-root-retention-hold >/dev/null 2>&1; then
  echo "non-root caller used the retention-hold administration API" >&2
  exit 1
fi
"$driver" admin-set-retention-hold \
  --uid "$created_uid" "$created_only" --retention-hold true \
  --key root-retention-hold \
  | grep -q 'retention_hold=true'
"$erebor" daemon logs --maximum-records 32 \
  | grep -q 'root administration applied admin-session-set-retention-hold'
if as_user "$first_user" remove "$created_only" --key remove-held-created-only \
  >/dev/null 2>&1; then
  echo "retention-held session was removed" >&2
  exit 1
fi
"$driver" admin-set-retention-hold \
  --uid "$created_uid" "$created_only" --retention-hold false \
  --key root-release-retention-hold \
  | grep -q 'retention_hold=false'
as_user "$first_user" remove "$created_only" --key remove-created-only \
  | grep -q 'state=removed'

revalidation_session="$(
  create_linux "$first_user" terminate root-revalidation 5 | session_id_from
)"
write_config 1
"$erebor" daemon reload --idempotency-key phase-two-lower-root-limit \
  | grep -q 'configuration reloaded'
if as_user "$first_user" start "$revalidation_session" \
  --key start-root-revalidation >/dev/null 2>&1; then
  echo "start ignored a lowered active root constraint" >&2
  exit 1
fi
as_user "$first_user" inspect "$revalidation_session" | grep -q 'state=created'
write_config 300
"$erebor" daemon reload --idempotency-key phase-two-restore-root-limit \
  | grep -q 'configuration reloaded'
as_user "$first_user" remove "$revalidation_session" \
  --key remove-root-revalidation | grep -q 'state=removed'

symlink_workspace="/home/$first_user/phase-two-workspace-link"
ln -s "/home/$first_user" "$symlink_workspace"
if as_user "$first_user" create \
  --runner linux-host \
  --workspace "$symlink_workspace" \
  --failure-mode terminate \
  --key create-symlink-workspace \
  -- /usr/bin/true >/dev/null 2>&1; then
  echo "descriptor admission followed a workspace symlink" >&2
  exit 1
fi
rm "$symlink_workspace"

swapped_workspace="/home/$first_user/phase-two-swapped-workspace"
mkdir "$swapped_workspace"
chown "$(uid_of "$first_user"):$(gid_of "$first_user")" "$swapped_workspace"
workspace_swap_session="$(
  as_user "$first_user" create \
    --runner linux-host \
    --workspace "$swapped_workspace" \
    --failure-mode terminate \
    --key create-workspace-swap \
    -- /usr/bin/true | session_id_from
)"
mv "$swapped_workspace" "$swapped_workspace.old"
mkdir "$swapped_workspace"
chown "$(uid_of "$first_user"):$(gid_of "$first_user")" "$swapped_workspace"
if as_user "$first_user" start "$workspace_swap_session" \
  --key start-workspace-swap >/dev/null 2>&1; then
  echo "start accepted a changed workspace identity" >&2
  exit 1
fi
as_user "$first_user" inspect "$workspace_swap_session" | grep -q 'state=failed'
as_user "$first_user" remove "$workspace_swap_session" \
  --key remove-workspace-swap | grep -q 'state=removed'
rm -r "$swapped_workspace" "$swapped_workspace.old"

swapped_executable="/home/$first_user/phase-two-swapped-executable"
install -o "$(uid_of "$first_user")" -g "$(gid_of "$first_user")" \
  -m 0755 /usr/bin/dash "$swapped_executable"
executable_swap_session="$(
  as_user "$first_user" create \
    --runner linux-host \
    --workspace "/home/$first_user" \
    --failure-mode terminate \
    --key create-executable-swap \
    -- "$swapped_executable" -c true | session_id_from
)"
install -o "$(uid_of "$first_user")" -g "$(gid_of "$first_user")" \
  -m 0755 /usr/bin/true \
  "$swapped_executable.replacement"
mv "$swapped_executable.replacement" "$swapped_executable"
if as_user "$first_user" start "$executable_swap_session" \
  --key start-executable-swap >/dev/null 2>&1; then
  echo "start accepted a changed executable identity" >&2
  exit 1
fi
as_user "$first_user" remove "$executable_swap_session" \
  --key remove-executable-swap | grep -q 'state=removed'
rm "$swapped_executable"

missing_digest=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
if as_user "$first_user" create \
  --runner docker \
  --workspace "/home/$first_user" \
  --failure-mode terminate \
  --image-digest "$missing_digest" \
  --key create-missing-docker-image \
  -- /bin/true >/dev/null 2>&1; then
  echo "Docker admitted a non-local immutable image" >&2
  exit 1
fi
[[ -z "$(docker ps -aq --filter label=dev.erebor.session_id)" ]]

if create_linux "$first_user" continue_if_enforced rejected-mode >/dev/null 2>&1; then
  echo "Linux runner admitted unsupported continue_if_enforced mode" >&2
  exit 1
fi
if create_docker "$first_user" continue_if_enforced rejected-docker-mode >/dev/null 2>&1; then
  echo "Docker runner admitted unsupported continue_if_enforced mode" >&2
  exit 1
fi

fast_linux="$(
  as_user "$first_user" create \
    --runner linux-host \
    --workspace "/home/$first_user" \
    --failure-mode terminate \
    --key create-fast-linux \
    -- /usr/bin/dash -c \
    'printf "fast-linux-final\n"; printf "fast-linux-stderr\n" >&2' \
    | session_id_from
)"
fast_start="$(as_user "$first_user" start "$fast_linux" --key start-fast-linux)"
if grep -q 'state=running' <<<"$fast_start"; then
  as_user "$first_user" wait "$fast_linux" | grep -q 'state=succeeded'
else
  grep -q 'state=succeeded' <<<"$fast_start"
fi
await_log "$first_user" "$fast_linux" fast-linux-final
as_user "$first_user" logs "$fast_linux" --stream stderr \
  | grep -q fast-linux-stderr
remove_session "$first_user" "$fast_linux" fast-linux

fast_docker="$(
  as_user "$first_user" create \
    --runner docker \
    --workspace "/home/$first_user" \
    --failure-mode terminate \
    --image-digest "$docker_digest" \
    --key create-fast-docker \
    -- /bin/sh -c \
    'printf "fast-docker-final\n"; printf "fast-docker-stderr\n" >&2' \
    | session_id_from
)"
fast_start="$(as_user "$first_user" start "$fast_docker" --key start-fast-docker)"
if grep -q 'state=running' <<<"$fast_start"; then
  as_user "$first_user" wait "$fast_docker" | grep -q 'state=succeeded'
else
  grep -q 'state=succeeded' <<<"$fast_start"
fi
await_log "$first_user" "$fast_docker" fast-docker-final
as_user "$first_user" logs "$fast_docker" --stream stderr \
  | grep -q fast-docker-stderr
remove_session "$first_user" "$fast_docker" fast-docker

output_failure_label=output-sink-failure
output_failure_session="$(
  as_user "$first_user" create \
    --runner linux-host \
    --workspace "/home/$first_user" \
    --failure-mode terminate \
    --key create-output-sink-failure \
    -- /usr/bin/dash -c \
    'while :; do printf "%08000d\\n" 0; done' \
    "$output_failure_label" | session_id_from
)"
output_failure_root="/var/lib/erebor/users/$(uid_of "$first_user")/sessions/$output_failure_session/output"
install -d -m 0700 "$output_failure_root"
mount -t tmpfs -o size=64k tmpfs "$output_failure_root"
as_user "$first_user" start "$output_failure_session" \
  --key start-output-sink-failure >/dev/null 2>&1 || true
as_user "$first_user" wait "$output_failure_session" \
  | grep -Eq 'state=failed.*failure=.*output'
if marker_live "$output_failure_label"; then
  echo "required output sink failure left a workload alive" >&2
  exit 1
fi
umount "$output_failure_root"
remove_session "$first_user" "$output_failure_session" output-sink-failure

case "${EREBOR_SESSION_RUNTIME_PROBE:-full}" in
  output-contract)
    exit 0
    ;;
  full | shared-guard)
    ;;
  *)
    echo "unknown installed session-runtime probe mode" >&2
    exit 1
    ;;
esac

linux_terminate="$(create_linux "$first_user" terminate linux-terminate | session_id_from)"
linux_continue="$(create_linux "$second_user" continue linux-continue | session_id_from)"
docker_terminate="$(create_docker "$first_user" terminate docker-terminate | session_id_from)"
docker_continue="$(create_docker "$second_user" continue docker-continue | session_id_from)"
for value in "$linux_terminate" "$linux_continue" "$docker_terminate" "$docker_continue"; do
  [[ -n "$value" ]]
done

start_session "$first_user" "$linux_terminate" linux-terminate
start_session "$second_user" "$linux_continue" linux-continue
start_session "$first_user" "$docker_terminate" docker-terminate
start_session "$second_user" "$docker_continue" docker-continue
await_log "$first_user" "$linux_terminate" linux-ready-linux-terminate
await_log "$second_user" "$linux_continue" linux-ready-linux-continue
await_log "$first_user" "$docker_terminate" docker-ready-docker-terminate
await_log "$second_user" "$docker_continue" docker-ready-docker-continue
await_log "$first_user" "$linux_terminate" \
  "identity $(uid_of "$first_user") $(gid_of "$first_user")"
await_log "$second_user" "$linux_continue" \
  "identity $(uid_of "$second_user") $(gid_of "$second_user")"
await_log "$first_user" "$docker_terminate" \
  "identity $(uid_of "$first_user") $(gid_of "$first_user")"
await_log "$second_user" "$docker_continue" \
  "identity $(uid_of "$second_user") $(gid_of "$second_user")"
await_log "$first_user" "$linux_terminate" linux-terminate-tick
await_log "$second_user" "$docker_continue" docker-continue-tick
await_log "$first_user" "$linux_terminate" linux-ready-linux-terminate
as_user "$first_user" logs "$linux_terminate" --stream stderr \
  | grep -q linux-stderr-linux-terminate
as_user "$first_user" logs "$docker_terminate" --stream stderr \
  | grep -q docker-stderr-docker-terminate

linux_stable="$(
  as_user "$first_user" inspect "$linux_terminate" | runner_recovery_from
)"
docker_stable="$(
  as_user "$first_user" inspect "$docker_terminate" | runner_recovery_from
)"
[[ "$(
  as_user "$first_user" start "$linux_terminate" \
    --key start-linux-terminate | runner_recovery_from
)" == "$linux_stable" ]]
[[ "$(
  as_user "$first_user" start "$docker_terminate" \
    --key start-docker-terminate | runner_recovery_from
)" == "$docker_stable" ]]
if as_user "$first_user" start "$linux_terminate" \
  --key second-start-linux-terminate >/dev/null 2>&1; then
  echo "a second start with a new mutation key was accepted" >&2
  exit 1
fi
[[ "$(docker ps -aq --filter "label=dev.erebor.session_id=$docker_terminate" | wc -l)" -eq 1 ]]

conflict_session="$(
  create_linux "$first_user" terminate idempotency-conflict | session_id_from
)"
if as_user "$first_user" start "$conflict_session" \
  --key start-linux-terminate >/dev/null 2>&1; then
  echo "an idempotency key was rebound to different protobuf payload bytes" >&2
  exit 1
fi
as_user "$first_user" remove "$conflict_session" \
  --key remove-idempotency-conflict | grep -q 'state=removed'

linux_log_cursor="$(
  as_user "$second_user" logs "$linux_continue" \
    | sed -n 's/^durable_cursor=\([0-9]*\).*/\1/p'
)"
docker_log_cursor="$(
  as_user "$second_user" logs "$docker_continue" \
    | sed -n 's/^durable_cursor=\([0-9]*\).*/\1/p'
)"
linux_event_cursor="$(
  as_user "$second_user" events "$linux_continue" \
    | sed -n 's/^durable_cursor=\([0-9]*\).*/\1/p'
)"
docker_event_cursor="$(
  as_user "$second_user" events "$docker_continue" \
    | sed -n 's/^durable_cursor=\([0-9]*\).*/\1/p'
)"
for cursor in \
  "$linux_log_cursor" \
  "$docker_log_cursor" \
  "$linux_event_cursor" \
  "$docker_event_cursor"; do
  [[ "$cursor" =~ ^[0-9]+$ ]]
done

for session_id in \
  "$linux_terminate" \
  "$linux_continue" \
  "$docker_terminate" \
  "$docker_continue"; do
  owner="$first_user"
  if [[ "$session_id" == "$linux_continue" || "$session_id" == "$docker_continue" ]]; then
    owner="$second_user"
  fi
  runner_recovery="$(as_user "$owner" inspect "$session_id" | runner_recovery_from)"
  assert_scope "$session_id" "$runner_recovery"
done

shared_guard_socket=/run/erebor/sessions/runtime-interception.sock
[[ -S "$shared_guard_socket" ]]
[[ "$(stat -c '%U:%G:%a' "$shared_guard_socket")" == "root:root:666" ]]
[[ "$(find /run/erebor/sessions -type s -name runtime-interception.sock | wc -l)" -eq 1 ]]
for session_id in "$linux_terminate" "$linux_continue"; do
  owner_uid="$(uid_of "$first_user")"
  if [[ "$session_id" == "$linux_continue" ]]; then
    owner_uid="$(uid_of "$second_user")"
  fi
  [[ ! -e "/run/erebor/sessions/$owner_uid/$session_id/runtime-interception.sock" ]]
  python3 -c '
import json, sys
record = json.load(open(sys.argv[1], encoding="utf-8"))
assert record["spec"]["endpoint_projections"] == [{
    "service": "runtime-guard",
    "host_path": "/run/erebor/sessions/runtime-interception.sock",
    "workload_path": "/run/erebor/runtime-interception.sock",
}]
' "/var/lib/erebor/users/$owner_uid/sessions/$session_id/session.json"
done
for user in "$first_user" "$second_user"; do
  if runuser -u "$user" -- python3 -c '
import socket, sys
client = socket.socket(socket.AF_UNIX)
client.connect(sys.argv[1])
' "$shared_guard_socket" >/dev/null 2>&1; then
    echo "a host user reached the unprojected shared runtime guard socket" >&2
    exit 1
  fi
done
if as_user "$first_user" inspect "$linux_continue" >/dev/null 2>&1; then
  echo "one user inspected another user session by guessing its id" >&2
  exit 1
fi
if find /run/erebor -type s -name '*hook*' | grep -q .; then
  echo "erebord exposed a production Codex hook listener during Phase 2" >&2
  exit 1
fi

if [[ "${EREBOR_SESSION_RUNTIME_PROBE:-full}" == shared-guard ]]; then
  remove_session "$first_user" "$linux_terminate" linux-terminate
  remove_session "$first_user" "$docker_terminate" docker-terminate
  remove_session "$second_user" "$linux_continue" linux-continue
  remove_session "$second_user" "$docker_continue" docker-continue
  [[ -S "$shared_guard_socket" ]]
  [[ -z "$(docker ps -aq --filter "label=dev.erebor.session_id=$docker_terminate")" ]]
  [[ -z "$(docker ps -aq --filter "label=dev.erebor.session_id=$docker_continue")" ]]
  exit 0
fi

"$driver" admin-list --all-users | grep -q "session_id=$linux_terminate"
if "$driver" admin-list --uid 0 | grep -q 'session_id='; then
  echo "target uid 0 admin listing was incorrectly treated as all users" >&2
  exit 1
fi
if as_user "$first_user" admin-list --all-users >/dev/null 2>&1; then
  echo "non-root caller used the root administration API" >&2
  exit 1
fi
"$driver" admin-inspect --uid "$(uid_of "$first_user")" "$linux_terminate" \
  | grep -q "session_id=$linux_terminate"
if as_user "$first_user" attach "$linux_terminate" --input \
  --key noninteractive-input >/dev/null 2>&1; then
  echo "non-interactive session received an input lease" >&2
  exit 1
fi
as_user "$first_user" attach "$linux_terminate" --key read-only-attach \
  | grep -q 'read_only=true'
if "$erebor" daemon stop --idempotency-key unresolved-stop >/dev/null 2>&1; then
  echo "graceful daemon stop accepted unresolved sessions" >&2
  exit 1
fi

for marker in \
  erebor-child-linux-terminate \
  erebor-child-linux-continue \
  erebor-child-docker-terminate \
  erebor-child-docker-continue \
  erebor-grandchild-linux-terminate \
  erebor-grandchild-linux-continue \
  erebor-grandchild-docker-terminate \
  erebor-grandchild-docker-continue; do
  marker_live "$marker"
done

systemctl reset-failed erebord.service
systemctl kill --kill-who=main --signal=KILL erebord.service
await_daemon

as_user "$first_user" wait "$linux_terminate" | grep -Eq 'state=(failed|interrupted)'
as_user "$first_user" wait "$docker_terminate" | grep -Eq 'state=(failed|interrupted)'
await_state "$second_user" "$linux_continue" running
await_state "$second_user" "$docker_continue" running
if marker_live erebor-child-linux-terminate ||
  marker_live erebor-grandchild-linux-terminate ||
  marker_live erebor-child-docker-terminate ||
  marker_live erebor-grandchild-docker-terminate; then
  echo "terminate mode left a process tree or container alive" >&2
  exit 1
fi
marker_live erebor-child-linux-continue
marker_live erebor-child-docker-continue
marker_live erebor-grandchild-linux-continue
marker_live erebor-grandchild-docker-continue
await_log_after "$second_user" "$linux_continue" \
  "$linux_log_cursor" linux-continue-tick
await_log_after "$second_user" "$docker_continue" \
  "$docker_log_cursor" docker-continue-tick
await_event_after "$second_user" "$linux_continue" \
  "$linux_event_cursor" daemon_control_lost
await_event_after "$second_user" "$docker_continue" \
  "$docker_event_cursor" daemon_control_lost
[[ -S "$shared_guard_socket" ]]
[[ "$(find /run/erebor/sessions -type s -name runtime-interception.sock | wc -l)" -eq 1 ]]

remove_session "$first_user" "$linux_terminate" linux-terminate
remove_session "$first_user" "$docker_terminate" docker-terminate
remove_session "$second_user" "$linux_continue" linux-continue
remove_session "$second_user" "$docker_continue" docker-continue

[[ -z "$(docker ps -aq --filter "label=dev.erebor.session_id=$docker_terminate")" ]]
[[ -z "$(docker ps -aq --filter "label=dev.erebor.session_id=$docker_continue")" ]]

run_service_loss_case restart systemctl-restart
run_service_loss_case stop systemctl-stop

admin_stop_session="$(
  create_linux "$first_user" continue admin-stop | session_id_from
)"
start_session "$first_user" "$admin_stop_session" admin-stop
"$driver" admin-stop \
  --uid "$(uid_of "$first_user")" \
  "$admin_stop_session" \
  --key root-admin-stop | grep -Eq 'state=(failed|succeeded|interrupted)'
remove_session "$first_user" "$admin_stop_session" admin-stop

admin_kill_session="$(
  create_docker "$second_user" continue admin-kill | session_id_from
)"
start_session "$second_user" "$admin_kill_session" admin-kill
"$driver" admin-kill \
  --uid "$(uid_of "$second_user")" \
  "$admin_kill_session" \
  --key root-admin-kill | grep -Eq 'state=(failed|interrupted)'
remove_session "$second_user" "$admin_kill_session" admin-kill
"$erebor" daemon logs --maximum-records 32 \
  | grep -q 'root administration applied admin-session-stop'
"$erebor" daemon logs --maximum-records 32 \
  | grep -q 'root administration applied admin-session-kill'
"$driver" prune --before-unix-ms "$(date +%s%3N)" --maximum-sessions 100 \
  --key installed-session-prune | grep -q 'pruned='
systemctl unset-environment EREBOR_ROOT_SENTINEL
