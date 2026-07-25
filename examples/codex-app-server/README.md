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
binaries into a new root-owned directory under `/tmp`, strips debug symbols
from its two fixture copies so repeated descriptor verification stays fast,
starts a foreground daemon at `<lab>/run/daemon.sock`, creates the fixture
policy alias, and opens a shell as your normal user. It does not install a
service, use the default `/run/erebor/daemon.sock`, create a container, or
delete anything. It requires the standard `strip` tool from your distribution's
`binutils` package.

Inside the printed `[erebor host lab]` shell, run:

```sh
erebor agent load "$EREBOR_CODEX_PACKAGE" --from "$EREBOR_CODEX_FIXTURE"
erebor run --policy fixture --workspace "$PWD" codex
```

The second command attaches to a daemon-owned TTY. The fixture prints
`fixture-tty=ready`, its kernel geometry as
`fixture-tty-size=rows=<rows> columns=<columns>`, and
`fixture-daemon-socket=absent`, then echoes each input line as
`fixture-tty-input=<line>`. To leave the TTY, press `Ctrl-P`, then `Ctrl-Q`.
That detaches the client while the daemon retains the same governed fixture
session. Inspect it with `erebor session ps`; when finished, stop it through
the daemon, for example:

```sh
erebor session stop <session-id> --idempotency-key manual-fixture-stop
```

The fixture's `exit` command is intentionally not part of this manual path:
the Phase 4 contract being demonstrated is a long-lived interactive agent that
the user detaches from and the daemon later stops.

To verify a live resize, resize your terminal window, then type
`terminal-size`. The fixture prints the current kernel PTY geometry again;
the session should remain the same running workload.

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

## Inspect from another terminal

Keep the host-lab shell open: exiting it stops its foreground daemon. In a
second terminal, substitute the retained lab path printed at startup and use
the staged client against that same socket:

```sh
lab=/tmp/erebor-codex-app-server-<uid>.<suffix>
erebor_lab() { "$lab/bin/erebor" --socket "$lab/run/daemon.sock" "$@"; }
erebor_lab daemon status
erebor_lab session ps
```

`session ps` uses compact, Docker-like 12-character IDs. The displayed short
ID is a unique prefix, so it can be pasted directly into every session command:

```sh
erebor_lab session inspect <short-id>
erebor_lab session logs <short-id>
erebor_lab session events <short-id>
```

For an admitted parent session, its pending direct-child contributions are
visible through the daemon-owned view:

```sh
erebor_lab session context inbox <parent-short-id>
```

This prints the child scope and immutable delivery pin that the parent may
receive or reject. Delivery and parent-pin values are deliberately full-length:
they are compare-and-set inputs, unlike the safely abbreviated session IDs.
An ordinary `erebor run … codex` fixture is a root session, so its inbox is
correctly empty until the fixture creates a logical child scope. A Codex
thread is such a scope inside this same session, never a second session or
TTY. In the first terminal, create B and run a real guarded descendant from B:

```text
fixture/turn
fixture/delegate {"child_thread_id":"fixture-b","child_turn_id":"turn-1","frozen_context_mode":"all","last_turns":0}
fixture/start-q
fixture/command {"command":"ls"}
fixture/deliver {"sequence":1,"selected_text":"B completed ls"}
```

`erebor_lab session ps` must still show exactly one session. The `ls` process
is physically governed by that one session's Linux guard and causally bound to
B's scope. `fixture/start-q` declares retained operation key `fixture-q` before
the shell starts; q is therefore a separate operation scope below B, while B
continues to run `ls`. It is not inferred later from an alive PID or from the
next command. Back in the second terminal, render the daemon-owned scope DAG:

```sh
erebor_lab session context graph <parent-short-id>
```

The graph is a compact Git-style tree of durable scopes and their retained,
authenticated activity. `HEAD` is each scope's current commit; `FROM` is the
exact immutable parent commit selected when that branch was admitted. The B
branch therefore shows `tool bash command="ls"`, one or more guard-observed
`exec … allowed pid=… via Bash <tool-use-id>` leaves, and its completion after
the fixture command above; its q child branch shows q's own physical `exec`
and delivery leaves, including q's shell descendants such as `sleep`. q owns
those process effects; a normal process does not create another context scope.
The execution leaves are retained Git facts bound to the same invocation lease,
not guesses from hook output or terminal text. It also shows whether the edge
is native-logical or daemon-physical and its authenticated source identity.
Inherited activity is not repeated on descendants. Scope and commit IDs are
safely abbreviated for display; the full values remain available in the
delivery inbox when a compare-and-set receive or reject needs them. The client
never opens the root-owned context repository or JSONL audit files.

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
