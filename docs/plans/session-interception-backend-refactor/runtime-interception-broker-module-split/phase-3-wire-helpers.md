# Phase 3: Extract Wire Helpers

Status: Done.

## Purpose

Move IPC frame/token helper functions out of the root without changing broker
transport behavior.

## Scope

Create or update:

- `runtime_interception_broker/wire.rs`
- root `runtime_interception_broker.rs`

Move only:

- `hex_encode`
- `interception_token`
- `envelope_with_token`
- `read_frame_from_stream`
- `write_frame_to_stream`

## Non-Goals

- Do not move socket platform code.
- Do not move server state.
- Do not move client code.
- Do not change IPC envelope or frame format.
- Do not change token validation semantics.

## Implementation Rules

- Compare stale `wire.rs` against the root wire helper range before moving.
- Keep helper behavior byte-for-byte equivalent where possible.
- `wire.rs` may import `RuntimeInterceptionBrokerError` from the root while the
  error type still lives in the root.
- Later Phase 9 may update that import when the error type moves to `server.rs`.
- Preserve `INTERCEPTION_TOKEN_HEADER` usage through `constants.rs`.

## Checkpoint

```sh
cargo fmt
cargo check -p erebor-runtime-session --all-targets --all-features
cargo test -p erebor-runtime-session --lib
```

Then run the live governed-session lifecycle probe in `lifecycle-probe.md`.

## Required Evidence

- Stale `wire.rs` comparison result.
- Old root code range moved.
- Root and `wire.rs` line counts.
- Item inventory showing only wire helpers moved.
- Compile/check result.
- Test result.
- Live lifecycle probe result.

## Acceptance

- Broker hello and interception decision tests still pass.
- A real Linux-host governed session runs an allowed command.
- A real Linux-host governed session fails closed for the denied
  `remote-debugging-port` command and writes audit evidence.

## Stop Point

Stop after Phase 3 verification. Wait for approval for Phase 4.

## Phase 3 Result

State: Done.

Implemented:

- Compared stale `wire.rs` against the current root wire helper range.
- Confirmed the helper bodies matched root exactly after normalizing root
  helper visibility to `pub(super)` and comparing only the planned helper
  range.
- Added `mod wire;` to the root broker module.
- Imported the wire helpers back into the root module for existing call sites:
  - `hex_encode`
  - `interception_token`
  - `envelope_with_token`
  - `read_frame_from_stream`
  - `write_frame_to_stream`
- Removed the five root-local wire helper definitions.
- Kept `read_interception_token` in the root; it now calls the moved
  `hex_encode`.
- Removed root imports that became wire-only:
  - `Header`
  - `EreborIpcFrame`
  - `FRAME_VERSION`
  - `HEADER_LEN`
  - `MAGIC`
  - `MAX_PAYLOAD_LEN`
  - `INTERCEPTION_TOKEN_HEADER`
- Did not move socket platform code, server state, client code, mediation,
  handlers, browser code, or tests.

Old root code range moved:

- `runtime_interception_broker.rs` lines 799-877 before Phase 3.

Line counts:

- Root before Phase 3: 1997 lines.
- Root after Phase 3: 1922 lines.
- `wire.rs`: 88 lines.

Moved item inventory:

```text
hex_encode
interception_token
envelope_with_token
read_frame_from_stream
write_frame_to_stream
```

Verification:

- Done: `cargo fmt`
- Done: `cargo check -p erebor-runtime-session --all-targets --all-features`
- Done: `cargo test -p erebor-runtime-session --lib`
- Done: live governed-session lifecycle probe from `lifecycle-probe.md`
  - Re-run with escalated execution because ptrace/session execution is blocked
    by the sandbox without escalation.
  - Allowed Linux-host governed session printed `erebor-lifecycle-allowed`.
  - Denied Linux-host governed session exited non-zero with status `1`.
  - Audit evidence contained `"type":"deny"`.
  - Audit evidence contained `deny-raw-cdp`.
  - Probe workspace:
    `/tmp/erebor-broker-lifecycle.InlRHD`.
  - Host cgroup residual risk remained:
    `cgroup_failed=1 cgroup_reason=failed to create cgroup directory: Permission denied (os error 13)`.
- Done: `cargo test -p erebor-runtime-cdp --test runtime_e2e browser_cdp_runtime_exposes_governed_discovery_endpoints -- --nocapture`
  - This was run after the first full workspace test hit a transient
    `WouldBlock` failure in that CDP e2e.
  - The exact test passed on rerun.
- Done: `cargo test --workspace --all-targets --all-features`
  - The full workspace test passed on rerun after the transient CDP e2e pass.
- Done: `cargo clippy --workspace --all-targets --all-features -- -D warnings`

Behavior change:

- No behavior change intended. IPC envelope token handling and frame
  read/write logic are unchanged; only the helper location changed.
