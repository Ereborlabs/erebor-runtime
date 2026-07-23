# Daemon-Owned Codex

This is the runnable Phase 4 developer walkthrough. It starts the privileged
`erebord` service, loads Erebor's deterministic `codex-v1` fixture, and uses
the public CLI for an interactive TTY and typed App Server JSONL session.

The fixture is deliberate: it proves the daemon/client contract without a
vendor login, a caller `HOME` or `CODEX_HOME`, or a real Codex state directory.
Your locally installed `codex-cli 0.145.0` is not used by this Phase 4 example.
Phase 5 owns the separately configured, state-projected real-vendor path.

## What you need

- Linux with systemd and `sudo`.
- Docker is not needed for this walkthrough.
- A fresh login after adding yourself to the `erebor` group. `id -nG` must
  include `erebor` before the unprivileged commands below can reach the daemon
  socket.

All root-owned service files are installed under `/usr/lib`, `/usr/libexec`,
and `/etc`; all caller-owned fixture files stay under `$HOME`.

## Build and install the development service

From the repository root, build the exact binaries used by the service:

```sh
rtk cargo build -p erebor-runtime-daemon --bin erebord --bin erebor-path-broker
rtk cargo build -p erebor-runtime-cli --bin erebor
rtk cargo build -p erebor-runtime-session --bin erebor-linux-session-controller
rtk cargo build -p erebor-runtime-session \
  --features editor-process-guard-target \
  --bin erebor-linux-process-guard
rtk cargo build -p erebor-runtime-e2e --bin codex-v1-fixture
```

Install those binaries and the repository-owned service unit. These are local
development installation commands; they do not download Codex or create a
package registry entry.

```sh
sudo install -d -m 0755 /usr/lib/erebor /usr/libexec/erebor
sudo install -m 0755 target/debug/erebord /usr/lib/erebor/erebord
sudo install -m 0755 target/debug/erebor-path-broker /usr/libexec/erebor/erebor-path-broker
sudo install -m 0755 target/debug/erebor-linux-session-controller \
  /usr/libexec/erebor/erebor-linux-session-controller
sudo install -m 0755 target/debug/erebor-linux-process-guard \
  /usr/libexec/erebor/erebor-linux-process-guard
sudo install -m 0755 target/debug/codex-v1-fixture /usr/lib/erebor/codex-v1-fixture
sudo install -m 0755 target/debug/erebor /usr/local/bin/erebor
sudo install -m 0644 packaging/systemd/erebord.service /etc/systemd/system/erebord.service
```

Create the socket-access group once, add your current user, then log out and
back in so the new group is in your process credentials:

```sh
getent group erebor >/dev/null || sudo groupadd --system erebor
sudo usermod -aG erebor "$(id -un)"
```

## Configure and start `erebord`

After logging in again, generate a root-owned daemon configuration for the
deterministic fixture. It pins the fixture executable and its managed artifacts
and seeds the fixture host-minimum policy for your current UID.

```sh
id -nG | tr ' ' '\n' | grep -x erebor

group_gid="$(getent group erebor | cut -d: -f3)"
owner_uid="$(id -u)"
fixture_config="$ (
  sudo /usr/lib/erebor/codex-v1-fixture configure \
    --config /etc/erebor/erebord.json \
    --trust-root /usr/lib/erebor/codex-v1-fixture-trust \
    --socket-group-gid "$group_gid" \
    --owner-uid "$owner_uid"
)"
```

Correct the command substitution's harmless whitespace if your shell does not
accept it: `fixture_config="$(sudo … configure …)"`. Then record the two
immutable values printed by the fixture:

```sh
package_ref="$(sed -n 's/^package_reference=//p' <<<"$fixture_config")"
root_policy_digest="$(sed -n 's/^root_policy_digest=//p' <<<"$fixture_config")"
test -n "$package_ref"
test -n "$root_policy_digest"

sudo systemctl daemon-reload
sudo systemctl enable --now erebord
erebor daemon status
```

`erebor daemon status` must report `state=running`. The socket is root-owned,
group `erebor`, and mode `0660`; ordinary group members can use sessions but
cannot reload, stop, or read global daemon logs.

If startup fails, inspect the root-owned service rather than bypassing the
daemon with a direct launch:

```sh
sudo systemctl status erebord --no-pager
sudo journalctl -u erebord --no-pager
```

## Load the deterministic Codex package

Copy the fixture to a caller-owned executable path, load the exact
root-curated package reference, and make a local policy-set alias:

```sh
fixture_bin="$HOME/.local/bin/codex-v1-fixture"
install -D -m 0755 /usr/lib/erebor/codex-v1-fixture "$fixture_bin"

erebor agent load "$package_ref" --from "$fixture_bin"

policy_set_digest="$(erebor policy set create \
  --root-minimum-digest "$root_policy_digest" \
  --idempotency-key codex-example-policy \
  | sed -n 's/^digest=//p')"
erebor policy set alias fixture "$policy_set_digest" \
  --idempotency-key codex-example-policy-alias
```

The load result must include `alias=codex` and `alias=codex-app-server`. The
daemon resolves and hashes `fixture_bin` through its descriptor broker; do not
replace it after loading it.

## Interactive TTY path

The public `codex` alias creates a daemon-owned PTY. Type one line and press
Enter; the deterministic fixture prints that line and exits.

```sh
erebor run --policy fixture --workspace "$PWD" codex
```

The output includes `fixture-daemon-socket=absent`, proving the workload cannot
reach the daemon control socket from its private namespace.

## Typed App Server JSONL path

`codex-app-server` uses a bounded JSON-RPC JSONL bridge, not generic session
input. The daemon owns the child pipes, validates each frame, handles EOF, and
validates child output before returning it to this command's stdout.

```sh
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize"}' \
  '{"jsonrpc":"2.0","id":2,"method":"fixture/hook"}' \
  | erebor run --policy fixture --workspace "$PWD" codex-app-server
```

The response contains `"turnId":"fixture-turn"` and
`"fixture":"accepted"`. EOF closes the fixture's standard input through the
daemon-owned structured-input lease.

## Your installed Codex binary

Your standalone executable resolves to:

```sh
readlink -f "$HOME/.local/bin/codex"
```

Do not substitute it for `fixture_bin` above yet. A real Codex enrollment needs
a separately approved root-curated release definition, root-owned managed-hook
artifacts, and a generic private state projection. That is the explicit Phase
5 boundary, not a missing `PATH` setting. Once Phase 5 supplies those facts,
the user-side enrollment shape remains:

```sh
erebor agent load REAL_CODEX_PACKAGE@sha256:... --from /absolute/path/to/codex
```

## Inspect and stop

```sh
erebor session ps
erebor session logs <session-id>
erebor audit tail <session-id>

sudo systemctl stop erebord
```

Stopping the daemon is a daemon-loss event; it is not a way to launch the
fixture directly. Start it again with `sudo systemctl start erebord` when you
want to continue.
