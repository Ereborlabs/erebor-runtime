# Real Codex TUI

This runs an installed Codex TUI through a root-owned `erebord` and the normal
`erebor` client under your UID. There is no lab and no profile generator.

The example owns the real daemon configuration, managed-hook requirements, and
`codex-runtime-guardrail` PolicyPackage under `config/` and `trust/`. It pins
the supported `0.145.0` standalone Codex release and the current managed hook
artifact. It is an intentionally exact host profile, not a template with
interpolation or a configuration-generating program.

## Build

From the repository root:

```sh
cargo build --package erebor-runtime-cli --bin erebor
cargo build --package erebor-runtime-daemon --bin erebord --bin erebor-path-broker
cargo build --package erebor-runtime-session --bin erebor-linux-session-controller \
  --bin erebor-codex-hook
```

## Install the checked-in configuration once

The host configuration uses group ID `1000`, matching this development host.
It accepts only the supported Codex release and managed hook byte-for-byte.
Fail rather than editing the configuration if either assertion does not hold.

```sh
export EREBOR_BIN="$(pwd)/target/debug"
export EREBOR_ROOT=/var/lib/erebor/codex-real
export EREBOR_RUNTIME=/run/erebor-codex-real
export EREBOR_CONFIG=/etc/erebor/codex-real.json
export EREBOR_SOCKET="$EREBOR_RUNTIME/daemon.sock"
export EREBOR_TRUST="$EREBOR_ROOT/trust"
export CODEX_RELEASE="$HOME/.codex/packages/standalone/releases/0.145.0-x86_64-unknown-linux-musl"

test "$(id -g)" = 1000
test "$(sha256sum "$CODEX_RELEASE/bin/codex" | cut -d' ' -f1)" = \
  a2a05dafaa1acb002a45eaec0a462de5b13694fcfcd7bc43305f14781ce7be14
test "$(sha256sum "$EREBOR_BIN/erebor-codex-hook" | cut -d' ' -f1)" = \
  d78c176c6e328c1fb1143e737ce1fdcacae6a3c1f5fffafa8468a43042f15ca6
test -f "$HOME/.bashrc"
test -d "$HOME/.codex"

sudo install -d -o root -g 1000 -m 0750 "$EREBOR_ROOT/bin" "$EREBOR_TRUST"
sudo install -o root -g root -m 0755 \
  "$EREBOR_BIN/erebor-linux-session-controller" \
  "$EREBOR_BIN/erebor-path-broker" \
  "$EREBOR_ROOT/bin/"
sudo install -o root -g root -m 0755 \
  "$EREBOR_BIN/erebor-codex-hook" \
  "$EREBOR_TRUST/erebor-codex-hook"
sudo install -o root -g root -m 0644 \
  examples/codex-real-tui/trust/requirements.toml \
  "$EREBOR_TRUST/requirements.toml"
sudo install -o root -g root -m 0755 \
  examples/codex-real-tui/trust/shell-startup \
  "$EREBOR_TRUST/shell-startup"

sudo install -d -o root -g 1000 -m 0750 \
  "$EREBOR_TRUST/codex-runtime-guardrail/rules" \
  "$EREBOR_TRUST/codex-runtime-guardrail/tests"
sudo install -o root -g 1000 -m 0640 \
  examples/codex-real-tui/trust/codex-runtime-guardrail/policy.toml \
  examples/codex-real-tui/trust/codex-runtime-guardrail/README.md \
  "$EREBOR_TRUST/codex-runtime-guardrail/"
sudo install -o root -g 1000 -m 0640 \
  examples/codex-real-tui/trust/codex-runtime-guardrail/rules/terminal.json \
  examples/codex-real-tui/trust/codex-runtime-guardrail/rules/filesystem.json \
  "$EREBOR_TRUST/codex-runtime-guardrail/rules/"
sudo install -o root -g 1000 -m 0640 \
  examples/codex-real-tui/trust/codex-runtime-guardrail/tests/terminal.json \
  examples/codex-real-tui/trust/codex-runtime-guardrail/tests/filesystem.json \
  "$EREBOR_TRUST/codex-runtime-guardrail/tests/"

sudo install -d -o root -g root -m 0750 /etc/erebor
sudo install -o root -g root -m 0640 \
  examples/codex-real-tui/config/erebord.host.json \
  "$EREBOR_CONFIG"
```

## Terminal 1: run the daemon

```sh
sudo "$EREBOR_BIN/erebord" \
  --config "$EREBOR_CONFIG" \
  --runtime-dir "$EREBOR_RUNTIME" \
  --log-dir "$EREBOR_ROOT/log" \
  --state-dir "$EREBOR_ROOT/state"
```

## Terminal 2: enroll and run Codex

Use the same exports from the installation section:

```sh
"$EREBOR_BIN/erebor" --socket "$EREBOR_SOCKET" daemon status

"$EREBOR_BIN/erebor" --socket "$EREBOR_SOCKET" agent load codex-cli-0-145-0 \
  --from "$CODEX_RELEASE/bin/codex" \
  --adapter codex-v1 \
  --name local-codex

"$EREBOR_BIN/erebor" --socket "$EREBOR_SOCKET" policy package apply \
  "$EREBOR_TRUST/codex-runtime-guardrail" \
  --name codex-runtime-guardrail \
  --idempotency-key real-codex-policy-package

"$EREBOR_BIN/erebor" --socket "$EREBOR_SOCKET" policyset create \
  --name codex-runtime-guardrail-set \
  --package codex-runtime-guardrail \
  --idempotency-key real-codex-policy-set
```

Choose a workspace below your home directory. The relative source declaration
is intentional: the daemon resolves it under the authenticated caller's home
and rejects undeclared or symlinked inputs.

```sh
export EREBOR_WORKSPACE="$HOME/go/src/github.com/Ereborlabs/erebor-runtime"
export EREBOR_WORKSPACE_SOURCE="${EREBOR_WORKSPACE#"$HOME"/}:directory:read_write"

"$EREBOR_BIN/erebor" --socket "$EREBOR_SOCKET" run \
  --caller-home-source .bashrc:file:read_only \
  --caller-home-source .codex:directory:read_write \
  --caller-home-source "$EREBOR_WORKSPACE_SOURCE" \
  --policy codex-runtime-guardrail-set \
  --workspace "$EREBOR_WORKSPACE" \
  local-codex
```

That command attaches the real interactive Codex TUI. Do not add `-d`. Codex
uses the existing state snapshot taken from `~/.codex`, with its configured
provider, authentication, model, and preferences.

## Files visible to the governed process

```text
caller ~/.bashrc       -> $HOME/.bashrc       read-only
caller ~/.codex/       -> $HOME/.codex/       read-write
caller <workspace>/    -> $HOME/<workspace>/  read-write
host system base       -> Bash and system tools for LinuxHostRunner
```

The daemon creates Codex's writable private state view at
`/run/erebor/state/codex` from a verified snapshot. The live
`~/.codex/ipc/` directory is masked: it is IDE authority, not a general
filesystem source. The policy package still supports daemon-owned policy
evaluation. This example does not provide syscall-level process or filesystem
denial.

See the [Phase 5.5 plan](../../docs/plans/daemon-client/phase-5-agent-policy-surface-model/phase-5-5-real-codex-tui-governed-acceptance.md)
for the complete resource and enforcement contract.
