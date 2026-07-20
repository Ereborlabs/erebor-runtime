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
manual example supplements, but does not replace, the privileged CI probe,
which also creates a second in-group user and an outsider, tests socket
recovery, and tests graceful and abrupt daemon shutdown.

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
| 3 | A generic daemon-owned `erebor create/run/ps/logs` walkthrough, including daemon-unavailable failure before process launch. |
| 4 | Replace the direct baseline above with the daemon-owned real Codex App Server walkthrough and its evidence checks. |
| 5 | Package pull/verify and local registry/Hub trust walkthrough. |
| 6 | Linux-host and Docker runner-parity plus ambient-surface walkthroughs. |
| 7–8 | Claude discovery/implementation walkthroughs only if the Phase 7 approval gate is passed. |
| 9 | Recovery, upgrade, and certification evidence walkthrough. |

Each addition must state its host prerequisites, exact commands, expected
observable result, cleanup, and whether it is a manual supplement or a
replacement for an automated test. Never put Codex credentials, prompts, hook
tickets, package tokens, or workload data in example output or committed
fixtures.
