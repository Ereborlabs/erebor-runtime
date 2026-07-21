# Codex App Server: Cumulative Hands-On Example

This is Erebor's maintained hands-on example. It grows with the daemon/client
architecture: after each approved phase, add the smallest real walkthrough
that lets a developer exercise that phase against its actual public or
explicitly documented test interface.

Do not make this example claim a future command exists. In particular, Phase 1
proves the installed daemon control plane only; it does **not** yet run Codex
through `erebord`.

## Phase 1: Daemon Control Plane

This is a manual two-terminal example. It starts a real root-owned `erebord`
from this checkout, then connects the matching `erebor` client to its explicit
local Unix socket. It creates no `/etc/erebor`, `/run/erebor`, `/var/log/erebor`,
or `/var/lib/erebor` data, and does not require systemd.

In Terminal 1, build the binaries and create a disposable local directory.
Copy the printed path; Terminal 2 uses the same path.

```sh
cd /path/to/erebor-runtime
cargo build -p erebor-runtime-cli --bin erebor
cargo build -p erebor-runtime-daemon --bin erebord

local_root="$(mktemp -d /tmp/erebor-phase1.XXXXXX)"
printf 'local root: %s\n' "$local_root"

sudo install -d -o root -g root -m 0755 "$local_root"
sudo install -d -o root -g root -m 0750 "$local_root/etc"
printf '{"socket_group_gid":%s,"max_log_bytes":4096,"max_log_records":32,"max_idempotency_records":32}\n' "$(id -g)" \
  | sudo tee "$local_root/etc/erebord.json" >/dev/null
sudo chown root:root "$local_root/etc/erebord.json"
sudo chmod 0640 "$local_root/etc/erebord.json"

sudo target/debug/erebord \
  --config "$local_root/etc/erebord.json" \
  --runtime-dir "$local_root/run" \
  --log-dir "$local_root/log" \
  --state-dir "$local_root/lib"
```

`erebord` now owns `$local_root/run/daemon.sock`. Keep it running. In
Terminal 2, use the printed local directory:

```sh
cd /path/to/erebor-runtime
local_root=/tmp/erebor-phase1.<copied-suffix>
socket="$local_root/run/daemon.sock"

target/debug/erebor daemon --socket "$socket" status
# expected: daemon_pid=... configuration_generation=1 state=running

target/debug/erebor daemon --socket "$socket" logs --maximum-records 1
# expected: denied, because this caller is not root

sudo target/debug/erebor daemon --socket "$socket" logs --maximum-records 10
# expected: sequence=... daemon-control telemetry records

key="manual-phase1-reload-$(date -u +%Y%m%dT%H%M%SZ)"
sudo target/debug/erebor daemon --socket "$socket" reload --idempotency-key "$key"
# expected: configuration reloaded at generation 2

sudo target/debug/erebor daemon --socket "$socket" reload --idempotency-key "$key"
# expected: the same stored result; generation does not increase again
```

This proves that the real client connects to the real daemon, and exercises
non-root status, root-only logs, transactional reload, and idempotent replay.
`erebord`'s path arguments are ordinary local path overrides: omitting each
one uses the installed system default. Likewise, omitting `erebor daemon
--socket` uses `/run/erebor/daemon.sock`. None of these options add a remote
endpoint, context, or daemon-selection model to the product.

To stop this daemon, run this in Terminal 2, then remove only the printed
disposable directory:

```sh
sudo target/debug/erebor daemon --socket "$socket" stop \
  --idempotency-key "manual-phase1-stop-$(date -u +%Y%m%dT%H%M%SZ)"
sudo rm -rf -- "$local_root"
```

For the installed systemd product path, use
[the daemon installation guide](../../docs/erebord-installation.md). The
manual example supplements, but does not replace, the local ignored privileged
Docker acceptance, which also creates a second in-group user and an outsider,
tests socket recovery, and tests graceful and abrupt daemon shutdown. That
acceptance is not run in CI.

## Phase 2: Daemon-Owned Generic Sessions

Phase 2 intentionally has no public `erebor run` command yet. This walkthrough
uses the explicitly documented internal driver, but every operation still
crosses the real authenticated daemon-control socket. It is a step-by-step
example, not a wrapper around the automated acceptance.

Prerequisites are Linux, Docker, and permission to run privileged containers.
First build the installed artifacts and disposable systemd image from the
repository root:

```sh
cargo build \
  -p erebor-runtime-cli --bin erebor \
  -p erebor-runtime-daemon --bins \
  -p erebor-runtime-session \
    --bin erebor-linux-process-guard \
    --bin erebor-linux-session-controller \
    --bin erebor-docker-session-controller \
  -p erebor-runtime-e2e --bin erebor-daemon-session-driver

docker build \
  --file .github/containers/daemon-systemd.Dockerfile \
  --tag erebor-daemon-systemd:local \
  .

phase2_box="$(
  docker run --detach --rm --privileged --cgroupns=private \
    --tmpfs /run --tmpfs /run/lock \
    erebor-daemon-systemd:local
)"
printf 'Phase 2 container: %s\n' "$phase2_box"
docker exec -it "$phase2_box" bash
```

The remaining commands run inside that container as root. Create one client
account, configure the root-curated local generic package records, and then
start the installed daemon. Phase 3 has no Docker/image admission path.

```sh
groupadd --system erebor
useradd --create-home --groups erebor erebor-demo
erebor_gid="$(getent group erebor | cut -d: -f3)"
demo_uid="$(id -u erebor-demo)"
adapter_digest=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
root_policy_digest=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
package_manifest="$(printf '{"format_version":1,"name":"generic-process","adapter_id":"generic-process-v1","minimum_daemon_version":"0.1.0","entrypoint":["<argv>"],"config_digest":"%s","support_layer_digests":[]}' "$adapter_digest")"
package_digest="$(printf '%s' "$package_manifest" | sha256sum | cut -d' ' -f1)"
installation_record="$(printf '{"format_version":1,"owner_uid":%s,"package_digest":"%s","installed_at_unix_ms":1}' "$demo_uid" "$package_digest")"
installation_digest="$(printf '%s' "$installation_record" | sha256sum | cut -d' ' -f1)"
policy_set_record="$(printf '{"format_version":1,"root_minimum_digest":"%s","package_minimum_digests":[],"local_override_digest":null}' "$root_policy_digest")"
policy_set_digest="$(printf '%s' "$policy_set_record" | sha256sum | cut -d' ' -f1)"

install -d -o root -g root -m 0750 /etc/erebor
printf '{"socket_group_gid":%s,"max_session_output_bytes":67108864,"session_output_rotation_bytes":4194304,"root_curated_admissions":[{"package":%s,"installation":%s,"policy_set":%s}]}\n' \
  "$erebor_gid" "$package_manifest" "$installation_record" "$policy_set_record" >/etc/erebor/erebord.json
chown root:root /etc/erebor/erebord.json
chmod 0640 /etc/erebor/erebord.json

systemctl daemon-reload
systemctl enable --now erebord.service
erebor daemon status
```

`erebor daemon status` should report `state=running`. The installed control
socket should also prove the intended owner and permissions:

```sh
stat -c '%U:%G:%a %n' /run/erebor/daemon.sock
# expected: root:erebor:660 /run/erebor/daemon.sock
```

Create a Linux-host generic session through the public daemon client. `create`
persists the immutable session but starts no process:

```sh
linux_created="$(
  runuser -u erebor-demo -- erebor session create \
    --runner linux-host \
    --workspace /home/erebor-demo \
    --package-digest "$package_digest" \
    --installation-digest "$installation_digest" \
    --adapter-digest "$adapter_digest" \
    --policy-set-digest "$policy_set_digest" \
    --failure-mode terminate \
    --idempotency-key example-linux-create \
    -- /usr/bin/dash -c \
      'printf "linux-output\n"; printf "linux-error\n" >&2; sleep 300'
)"
printf '%s\n' "$linux_created"
linux_session="$(sed -n 's/^session_id=\([^ ]*\).*/\1/p' <<<"$linux_created")"

runuser -u erebor-demo -- erebor session inspect "$linux_session"
# expected: state=created
test ! -e "/run/erebor/sessions/$(id -u erebor-demo)/$linux_session"
```

Now start it and inspect the active runner, its private runtime-guard
projection onto the shared service, output, lifecycle events, and systemd
ownership:

```sh
runuser -u erebor-demo -- erebor session start "$linux_session" \
  --idempotency-key example-linux-start
runuser -u erebor-demo -- erebor session inspect "$linux_session"
runuser -u erebor-demo -- erebor session logs "$linux_session"
runuser -u erebor-demo -- erebor session logs "$linux_session" --stream stderr
runuser -u erebor-demo -- erebor session events "$linux_session"

demo_uid="$(id -u erebor-demo)"
stat /run/erebor/sessions/runtime-interception.sock
systemctl status "erebor-session-$linux_session.slice" --no-pager
systemctl status "erebor-session-$linux_session.scope" --no-pager
```

The Phase 3 generic adapter has no interactive TTY contract yet. A normal
attach returns `read_only=true`; requesting input must fail:

```sh
runuser -u erebor-demo -- erebor session attach "$linux_session" \
  --idempotency-key example-linux-attach

if runuser -u erebor-demo -- erebor session attach "$linux_session" --input \
  --idempotency-key example-linux-input; then
  echo 'unexpected input lease' >&2
  exit 1
fi
```

Stop, wait for an honest terminal result, and remove the Linux session:

```sh
runuser -u erebor-demo -- erebor session stop "$linux_session" \
  --idempotency-key example-linux-stop
runuser -u erebor-demo -- erebor session wait "$linux_session"
runuser -u erebor-demo -- erebor session rm "$linux_session" --force \
  --idempotency-key example-linux-remove
```

`erebor session create --runner docker ...` fails explicitly because Docker
image admission and lifecycle support are deferred to Phase 6. It never pulls
an image or falls back to a direct launcher.

Exit the container shell, then remove only this disposable example container:

```sh
exit
docker rm --force "$phase2_box"
```

The broader automated supplement is explicit and local:

```sh
cargo test -p erebor-runtime-e2e --test daemon_control_plane \
  daemon_control_plane_runs_in_systemd_container -- --ignored --nocapture
```

It additionally covers two users, root administration, idempotent retry and
conflict, path-identity changes, process trees that fork/double-fork, output
cursors, daemon SIGKILL, systemd stop/restart, and Linux-host failure modes.
Docker lifecycle coverage is deferred to Phase 6. It is not CI and it does not
replace the manual walkthrough above.

## Current Direct Codex Baseline

The following is the existing direct foreground baseline. It is useful for
checking the current Codex integration, but it is **not** evidence that Codex
is daemon-owned yet. That migration belongs to Phase 4.

```sh
sudo env \
  EREBOR_SESSION_UID="$(id -u)" \
  EREBOR_SESSION_GID="$(id -g)" \
  CODEX_HOME="$HOME/.codex" \
  target/debug/erebor session run \
    --runner linux-host \
    --config examples/codex-app-server/runtime.json \
    /var/lib/erebor/codex-phase3/vscode-0.144.2/bin/codex \
    app-server --stdio
```

`runtime.json` and `policy.json` are the required current Erebor setup. They
enroll the root-managed profile at `/var/lib/erebor/codex-phase3/vscode-0.144.2`,
pin the binary, hook, requirements, sandbox launcher, and observed hook
schemas, and enable the Linux process/file interception path. The command
starts the real Codex App Server as an Erebor-governed child. There is no mock
model, helper client, or second App Server in this example.

`app-server --stdio` speaks the Codex App Server JSON-RPC protocol, so connect
your normal App Server client to its standard input/output. Keep `CODEX_HOME`
outside the governed workspace and authenticate Codex there before this run.

The explicit `sudo env` form is required: a simple `CODEX_HOME=... sudo ...`
does not preserve `CODEX_HOME` through `sudo`, so Codex falls back to
`/root/.codex`. The user/group variables tell Erebor which non-root identity
the governed child and its process guard will use.

## Extension Contract

Every future architecture phase extends this directory in the same change that
implements the phase:

| Phase | Add to this example |
| --- | --- |
| 2 | A documented daemon-session/runner-guard probe using the explicit Phase 2 test driver; do not invent a public run command before Phase 3. |
| 3 | A generic daemon-owned `erebor session create/run/ps/logs` walkthrough, including daemon-unavailable failure before process launch. |
| 4 | Replace the direct baseline above with the daemon-owned real Codex App Server walkthrough and its evidence checks. |
| 10 | Package pull/verify and local registry/Hub trust walkthrough. |
| 6 | Linux-host and Docker runner-parity plus ambient-surface walkthroughs. |
| 7–8 | Claude discovery/implementation walkthroughs only if the Phase 7 approval gate is passed. |
| 9 | Recovery, upgrade, and certification evidence walkthrough. |

Each addition must state its host prerequisites, exact commands, expected
observable result, cleanup, and whether it is a manual supplement or a
replacement for an automated test. Never put Codex credentials, prompts, hook
tickets, package tokens, or workload data in example output or committed
fixtures.
