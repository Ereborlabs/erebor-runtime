# Governed OpenClaw Pilot Example

This example is the first runnable slice of the governed OpenClaw pilot:

```text
one Erebor session
one Docker/OCI session runtime
one actor identity
one policy set
one JSONL audit stream
```

The current slice proves session-runtime launch, named bounded diagnostics, and
root command governance. It does not yet start OpenClaw, launch the owned
browser, or inject the browser CDP profile automatically.

## Session Runtime Smoke

Run a named safe read-only diagnostic inside the Docker/OCI session runtime:

```bash
cargo run -p erebor-runtime-cli -- \
  session diagnose \
  --runtime docker \
  --config examples/governed-openclaw-pilot/session-config.json \
  list-workspace
```

Then inspect the audit stream:

```bash
cargo run -p erebor-runtime-cli -- \
  audit tail \
  --file examples/governed-openclaw-pilot/pilot-audit.jsonl
```

## Denied Shell Action

The policy denies a direct unmanaged Chrome launch attempt:

```bash
cargo run -p erebor-runtime-cli -- \
  session run \
  --runtime docker \
  --config examples/governed-openclaw-pilot/session-config.json \
  google-chrome --remote-debugging-port=9222
```

Expected result:

```text
session command denied: unmanaged browser launch with raw CDP is denied
```

The denial is written to the same JSONL audit file.

## OpenClaw Browser Profile

The later full pilot should inject an attach-only OpenClaw browser profile like
[`openclaw-profile.example.json`](./openclaw-profile.example.json), replacing
`<session-governed-cdp-url>` with the governed CDP endpoint created by the
session.

OpenClaw must never receive the private Chrome DevTools endpoint.

## Current Non-Claims

- This example does not yet run OpenClaw inside the container.
- This example does not yet launch the Erebor-owned browser from the session
  runtime.
- This example governs named diagnostics and the root command passed to
  `session run`; richer child-process interception belongs to a later
  Docker/OCI session-runtime slice.
- Docker/OCI is the first session runtime, not the final Erebor product
  boundary.
