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

target/debug/erebor --socket "$socket" daemon status
# expected: daemon_pid=... configuration_generation=1 state=running

target/debug/erebor --socket "$socket" daemon logs --maximum-records 1
# expected: denied, because this caller is not root

sudo target/debug/erebor --socket "$socket" daemon logs --maximum-records 10
# expected: sequence=... daemon-control telemetry records

key="manual-phase1-reload-$(date -u +%Y%m%dT%H%M%SZ)"
sudo target/debug/erebor --socket "$socket" daemon reload --idempotency-key "$key"
# expected: configuration reloaded at generation 2

sudo target/debug/erebor --socket "$socket" daemon reload --idempotency-key "$key"
# expected: the same stored result; generation does not increase again
```

This proves that the real client connects to the real daemon, and exercises
non-root status, root-only logs, transactional reload, and idempotent replay.
`erebord`'s path arguments are ordinary local path overrides: omitting each
one uses the installed system default. Likewise, omitting `erebor --socket`
uses `/run/erebor/daemon.sock`. None of these options add a remote
endpoint, context, or daemon-selection model to the product.

To stop this daemon, run this in Terminal 2, then remove only the printed
disposable directory:

```sh
sudo target/debug/erebor --socket "$socket" daemon stop \
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
    --bin erebor-session-helper \
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
account, configure the exact temporary Phase 2 validation fixture, start nested
Docker, import the local pinned image, and then start the installed daemon:

```sh
groupadd --system erebor
useradd --create-home --groups erebor erebor-demo
erebor_gid="$(getent group erebor | cut -d: -f3)"
fixture_digest=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

install -d -o root -g root -m 0750 /etc/erebor
printf '{"socket_group_gid":%s,"max_session_output_bytes":67108864,"session_output_rotation_bytes":4194304,"phase_two_validated_fixtures":[{"package_digest":"%s","installation_digest":"%s","adapter_digest":"%s","policy_input_digests":["%s"],"policy_set_digest":"%s"}]}\n' \
  "$erebor_gid" "$fixture_digest" "$fixture_digest" "$fixture_digest" \
  "$fixture_digest" "$fixture_digest" >/etc/erebor/erebord.json
chown root:root /etc/erebor/erebord.json
chmod 0640 /etc/erebor/erebord.json

systemctl start docker.service
docker_image="$(
  docker import \
    /usr/local/lib/erebor/docker-fixture-root.tar \
    erebor-phase2-example:local
)"
docker_digest="${docker_image#sha256:}"

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

Use a short alias for the internal client and create a Linux-host session.
`create` persists the immutable session but starts no process:

```sh
driver=/usr/local/lib/erebor/erebor-daemon-session-driver

linux_created="$(
  runuser -u erebor-demo -- "$driver" create \
    --runner linux-host \
    --workspace /home/erebor-demo \
    --failure-mode terminate \
    --key example-linux-create \
    -- /usr/bin/dash -c \
      'printf "linux-output\n"; printf "linux-error\n" >&2; sleep 300'
)"
printf '%s\n' "$linux_created"
linux_session="$(sed -n 's/^session_id=\([^ ]*\).*/\1/p' <<<"$linux_created")"

runuser -u erebor-demo -- "$driver" inspect "$linux_session"
# expected: state=created
test ! -e "/run/erebor/sessions/$(id -u erebor-demo)/$linux_session"
```

Now start it and inspect the active runner, its separate runtime-guard
endpoint, output, lifecycle events, and systemd ownership:

```sh
runuser -u erebor-demo -- "$driver" start "$linux_session" \
  --key example-linux-start
runuser -u erebor-demo -- "$driver" inspect "$linux_session"
runuser -u erebor-demo -- "$driver" logs "$linux_session"
runuser -u erebor-demo -- "$driver" logs "$linux_session" --stream stderr
runuser -u erebor-demo -- "$driver" events "$linux_session"

demo_uid="$(id -u erebor-demo)"
stat /run/erebor/sessions/runtime-interception.sock
systemctl status "erebor-session-$linux_session.slice" --no-pager
systemctl status "erebor-session-$linux_session.scope" --no-pager
```

Phase 2 attach is deliberately read-only because both initial runners report
`tty_supported=false`. A normal attach returns `read_only=true`; requesting
input must fail:

```sh
runuser -u erebor-demo -- "$driver" attach "$linux_session" \
  --key example-linux-attach

if runuser -u erebor-demo -- "$driver" attach "$linux_session" --input \
  --key example-linux-input; then
  echo 'unexpected input lease' >&2
  exit 1
fi
```

Stop, wait for an honest terminal result, and remove the Linux session:

```sh
runuser -u erebor-demo -- "$driver" stop "$linux_session" \
  --key example-linux-stop
runuser -u erebor-demo -- "$driver" wait "$linux_session"
runuser -u erebor-demo -- "$driver" remove "$linux_session" --force \
  --key example-linux-remove
```

Repeat the same lifecycle through the Docker runner. The request names the
exact already-local image digest; no tag or implicit pull reaches runner start:

```sh
docker_created="$(
  runuser -u erebor-demo -- "$driver" create \
    --runner docker \
    --workspace /home/erebor-demo \
    --failure-mode terminate \
    --image-digest "$docker_digest" \
    --key example-docker-create \
    -- /bin/sh -c \
      'printf "docker-output\n"; printf "docker-error\n" >&2; sleep 300'
)"
printf '%s\n' "$docker_created"
docker_session="$(sed -n 's/^session_id=\([^ ]*\).*/\1/p' <<<"$docker_created")"

runuser -u erebor-demo -- "$driver" start "$docker_session" \
  --key example-docker-start
runuser -u erebor-demo -- "$driver" inspect "$docker_session"
runuser -u erebor-demo -- "$driver" logs "$docker_session"
runuser -u erebor-demo -- "$driver" logs "$docker_session" --stream stderr
systemctl status "erebor-session-$docker_session.slice" --no-pager

runuser -u erebor-demo -- "$driver" kill "$docker_session" \
  --key example-docker-kill
runuser -u erebor-demo -- "$driver" wait "$docker_session"
runuser -u erebor-demo -- "$driver" remove "$docker_session" --force \
  --key example-docker-remove
```

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
cursors, daemon SIGKILL, systemd stop/restart, and `terminate`/`continue` for
both runners. It is not CI and it does not replace the manual walkthrough
above.

## Phase 4: Daemon-Owned Deterministic Codex Fixture

Phase 4 replaces the direct foreground Codex baseline. The supported recovery
walkthrough is the local host lab in
[`examples/codex-app-server`](../../examples/codex-app-server/README.md). It
uses a deterministic pinned fixture, not a vendor Codex installation or
credential, and starts a foreground daemon without systemd:

```sh
./examples/codex-app-server/build-host-lab.sh
sudo ./examples/codex-app-server/run-host-lab.sh
```

The lab shell's `erebor` function always uses its isolated absolute local
socket. It is equivalent to passing `erebor --socket "$EREBOR_SOCKET"` to each
daemon-backed command; omitting `--socket` outside the lab still selects the
installed `/run/erebor/daemon.sock`.

```sh
erebor agent load "$EREBOR_CODEX_PACKAGE" --from "$EREBOR_CODEX_FIXTURE"
erebor run --policy fixture --workspace "$PWD" codex

printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize"}' \
  | erebor run --policy fixture --workspace "$PWD" codex-app-server
```

The interactive command proves daemon-owned TTY and socket absence; the second
command proves the bounded typed JSONL path. Exiting the shell stops only the
foreground daemon and retains the `/tmp` lab directory for review. It never
uses `CODEX_HOME`, and real authenticated Codex remains Phase 5 work after the
generic filesystem-state projection exists.

## Extension Contract

Every future architecture phase extends this directory in the same change that
implements the phase:

| Phase | Add to this example |
| --- | --- |
| 2 | A documented daemon-session/runner-guard probe using the explicit Phase 2 test driver; do not invent a public run command before Phase 3. |
| 3 | A generic daemon-owned `erebor create/run/ps/logs` walkthrough, including daemon-unavailable failure before process launch. |
| 4 | Deterministic daemon-owned Codex TTY/App Server host lab and its evidence checks; real authenticated Codex remains out of scope. |
| 5 | Daemon-owned ambient surfaces and filesystem-state projection walkthrough. |
| 6 | Linux-host and Docker runner-parity walkthroughs. |
| 7–8 | Claude discovery/implementation walkthroughs only if the Phase 7 approval gate is passed. |
| 9 | Recovery, upgrade, and certification evidence walkthrough. |

Each addition must state its host prerequisites, exact commands, expected
observable result, cleanup, and whether it is a manual supplement or a
replacement for an automated test. Never put Codex credentials, prompts, hook
tickets, package tokens, or workload data in example output or committed
fixtures.
