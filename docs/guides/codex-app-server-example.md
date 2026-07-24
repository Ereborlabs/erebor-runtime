# Codex App Server Host-Lab Guide

The current Phase 4 walkthrough is the deterministic local host lab in
[`examples/codex-app-server`](../../examples/codex-app-server/README.md). It
replaces the removed direct `runtime.json`/`sudo env` Codex launch path.

The lab uses the real daemon/client and Linux helper binaries, but a pinned
`codex-v1-fixture` rather than a vendor Codex installation, login, `HOME`, or
`CODEX_HOME`. Real authenticated Codex state is deferred to Phase 5's generic
filesystem projection.

```sh
./examples/codex-app-server/build-host-lab.sh
sudo ./examples/codex-app-server/run-host-lab.sh
```

The second command starts a foreground root daemon in a fresh retained `/tmp`
directory, without systemd, a container, an installed service, or the default
socket. It opens a shell as the original caller. There:

```sh
erebor agent load "$EREBOR_CODEX_PACKAGE" --from "$EREBOR_CODEX_FIXTURE"
erebor run --policy fixture --workspace "$PWD" codex

printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize"}' \
  | erebor run --policy fixture --workspace "$PWD" codex-app-server
```

The normal `codex` alias is an interactive daemon-owned TTY. After the fixture
reports ready, it prints the kernel geometry as
`fixture-tty-size=rows=<rows> columns=<columns>` and echoes each line as
`fixture-tty-input=<line>`; type `exit` to end it normally.
`codex-app-server` is a separate bounded JSON-RPC JSONL bridge, whose protocol
output alone is written to standard output.

For a live resize check, resize the terminal window and enter `terminal-size`.
The fixture prints its current kernel PTY geometry without starting another
workload.

The shell's `erebor` function passes `--socket "$EREBOR_SOCKET"` to each
daemon-backed command. Outside this lab, omit `--socket` to use the normal
`/run/erebor/daemon.sock`. This selector is process-local and local-Unix-only;
it does not introduce contexts, remote targets, or a multi-daemon model.

Exiting stops only the foreground daemon. The lab directory, configuration,
logs, and state are intentionally retained; the scripts never delete them.
