# Governed OpenClaw Pilot Example

This example is the first runnable slice of the governed OpenClaw pilot:

```text
one Erebor session
one Docker/OCI session runner
one actor identity
one policy set
one JSONL audit stream
```

The current slice proves session-runner launch, config-owned TTY attachment,
session-owned browser CDP endpoint injection, and bounded shell/process
diagnostics through the Linux ptrace process guard mounted by Docker. It does not yet build or
select an OpenClaw container image automatically.

## Session Runner Smoke

Run a named safe read-only diagnostic through the guarded Docker session:

```bash
cargo run -p erebor-runtime-cli -- \
  session diagnose \
  --runner docker \
  --config examples/governed-openclaw-pilot/session-config.json \
  list-workspace
```

The diagnostic prints the session id, actor id, `EREBOR_BROWSER_CDP_URL`, and
`EREBOR_PROCESS_GUARD=linux-ptrace`. The browser URL is Erebor's governed endpoint,
not Chrome's private DevTools endpoint. The Linux process guard audits
`execve`/`execveat` attempts from the session process tree.

## TTY Runner Smoke

Run an interactive shell through the same Docker/OCI session runner:

```bash
cargo run -p erebor-runtime-cli -- \
  session run \
  --runner docker \
  --config examples/governed-openclaw-pilot/session-config.json \
  sh
```

`surfaces.terminal.tty=true` in `session-config.json` allocates Docker's
interactive TTY flags. With an OpenClaw-capable image in
`session-config.json`, the same path becomes:

```bash
cargo run -p erebor-runtime-cli -- \
  session run \
  --runner docker \
  --config examples/governed-openclaw-pilot/session-config.json \
  openclaw
```

The default example image is still `alpine:3.20`, so use `sh` for the runnable
smoke unless you have built or configured an OpenClaw image.

Inspect the audit stream:

```bash
cargo run -p erebor-runtime-cli -- \
  audit tail \
  --file examples/governed-openclaw-pilot/pilot-audit.jsonl
```

## Denied Shell Action

The Linux process guard denies a direct unmanaged Chrome launch attempt before
the child exec completes:

```bash
cargo run -p erebor-runtime-cli -- \
  session diagnose \
  --runner docker \
  --config examples/governed-openclaw-pilot/session-config.json \
  raw-cdp-browser-launch
```

Expected result:

```text
erebor linux process guard: denied exec: ... --remote-debugging-port=9222: unmanaged browser launch with raw CDP is denied
```

The denial is written to the same JSONL audit file with the same session id and
actor identity.

The guard also catches child-process launches below a shell prompt:

```bash
cargo run -p erebor-runtime-cli -- \
  session diagnose \
  --runner docker \
  --config examples/governed-openclaw-pilot/session-terminal-config.json \
  shell-spawned-raw-cdp-browser-launch
```

## OpenClaw Browser Profile

The later full pilot should write an attach-only OpenClaw browser profile like
[`openclaw-profile.example.json`](./openclaw-profile.example.json), replacing
`<session-governed-cdp-url>` with `EREBOR_BROWSER_CDP_URL` from the governed
session.

OpenClaw must never receive the private Chrome DevTools endpoint.

## Current Non-Claims

- This example does not yet run OpenClaw inside the container.
- This example starts an Erebor-owned browser side resource, but it does not yet
  prove OpenClaw connected to it.
- This example governs process creation attempts made by the Docker session
  process tree with a Linux ptrace guard. It has been smoke-tested against direct
  commands, shell-spawned children, and Python `subprocess` launches.
- This example does not claim host-wide bare-metal process governance or a
  production-hardened seccomp/eBPF/LSM backend.
- Docker/OCI is the first session runner, not the final Erebor product
  boundary.
