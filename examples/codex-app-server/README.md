# Codex App Server Host Lab

This is the Phase 4 host example. It exercises the real local `erebord`,
`erebor`, Linux runner, process guard, descriptor broker, package admission,
TTY attachment, and typed App Server bridge. It does so with the deterministic
`codex-v1-fixture`, not your installed Codex, login, `HOME`, or `CODEX_HOME`.
Real authenticated Codex state belongs to Phase 5.

The daemon is not a systemd requirement. The lab starts one foreground root
`erebord` with isolated paths and uses Linux direct-controller containment.
Systemd scope is an explicit root configuration option for an installed host;
it is not the baseline used here.

## Run the lab

From the repository root, run these two commands:

```sh
./examples/codex-app-server/build-host-lab.sh
sudo ./examples/codex-app-server/run-host-lab.sh
```

The first command only builds local debug binaries. The second stages those
binaries into a new root-owned directory under `/tmp`, starts a foreground
daemon at `<lab>/run/daemon.sock`, creates the fixture policy alias, and opens
a shell as your normal user. It does not install a service, use the default
`/run/erebor/daemon.sock`, create a container, or delete anything.

Inside the printed `[erebor host lab]` shell, run:

```sh
erebor agent load "$EREBOR_CODEX_PACKAGE" --from "$EREBOR_CODEX_FIXTURE"
erebor run --policy fixture --workspace "$PWD" codex
```

The second command attaches to a daemon-owned TTY. The fixture prints
`fixture-tty=ready` and `fixture-daemon-socket=absent`; enter one line to let
the deterministic TTY session finish.

To exercise the daemon-owned typed App Server path instead:

```sh
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize"}' \
  | erebor run --policy fixture --workspace "$PWD" codex-app-server
```

Its standard output is JSONL protocol output only. Daemon/session diagnostics
stay on standard error.

Type `exit` when finished. The script stops only its foreground daemon; it
retains the printed lab directory, including its root-owned configuration,
logs, and daemon state, for inspection. It never performs automatic cleanup.

## Socket selection

In a normal installed deployment, omit `--socket` and the client uses
`/run/erebor/daemon.sock`. The lab shell defines an `erebor` function that
always invokes the staged client as:

```sh
"$EREBOR_BIN" --socket "$EREBOR_SOCKET" …
```

`--socket` is an absolute, process-local local-Unix-socket selector. It is not
a persisted context, remote endpoint, or multi-daemon feature. It applies to
the daemon-backed command families (`agent`, `run`, `session`, `policy`,
`runner`, `audit`, `approval`, and `daemon`).
