# Phase 6: Extract Handlers And Router

Status: Done.

## Purpose

Move session handler/router logic after mediation and decision helpers are
already modular.

## Scope

Create or update:

- `runtime_interception_broker/handlers.rs`
- root `runtime_interception_broker.rs`
- `runtime_interception_broker/mediation.rs`, only if Phase 6 proves a narrow
  visibility adjustment is required

Move only:

- `SessionInterceptionHandler`
- `SessionInterceptionRouter`
- `impl fmt::Debug for SessionInterceptionRouter`
- `SessionInterceptionHandler::decision_for_request`
- `SessionRegistration`, if the server still stores that exact shape

## Non-Goals

- Do not move Browser CDP mediation.
- Do not move server lifecycle.
- Do not move platform transport.
- Do not redesign routing.

## Implementation Rules

- Compare stale `handlers.rs` against the root handler/router ranges before
  moving.
- Treat the root file as the source of truth.
- Phase 0 found that stale `handlers.rs` adds `SessionInterceptionHandler::id()`
  and `pub(super)` methods because server code cannot read private fields across
  modules. Apply only the minimal visibility/method changes needed to compile.
- Prefer methods over field visibility.
- Root should publicly re-export the same public handler/router types.

## Checkpoint

```sh
cargo fmt
cargo check -p erebor-runtime-session --all-targets --all-features
cargo test -p erebor-runtime-session --lib
```

Then run the live governed-session lifecycle probe in `lifecycle-probe.md`.

## Required Evidence

- Stale `handlers.rs` comparison result.
- Old root code ranges moved.
- Root and `handlers.rs` line counts.
- Item inventory showing moved handler/router items.
- Any visibility changes, with justification.
- Compile/check result.
- Test result.
- Live lifecycle probe result.

## Acceptance

- Direct process-exec requests still route through the registered surface
  handler.
- Unknown handlers still fail closed.
- A real Linux-host governed session runs an allowed command.
- A real Linux-host governed session fails closed for the denied
  `remote-debugging-port` command and writes audit evidence.

## Stop Point

Stop after Phase 6 verification. Wait for approval for Phase 7.

## Phase 6 Result

State: Done.

Implemented:

- Compared stale `handlers.rs` against the current root handler/router ranges.
- Confirmed the moved item bodies matched root after applying only the
  visibility/method normalization required by this phase:
  - `SessionRegistration` from private root struct to `pub(super)` module
    struct.
  - `SessionRegistration` fields from private to `pub(super)`.
  - added `SessionInterceptionHandler::id()`.
  - `SessionInterceptionRouter::decide_process_exec` from private to
    `pub(super)`.
  - `SessionInterceptionHandler::decision_for_request` from private to
    `pub(super)`.
- Added `mod handlers;` to the root broker module.
- Re-exported the public handler/router API from the root broker module:
  - `SessionInterceptionHandler`
  - `SessionInterceptionRouter`
- Imported internal `SessionRegistration` from `handlers.rs`.
- Replaced server registration's private field read with `handler.id()`.
- Adjusted test imports so process-exec test traits/types come directly from
  `erebor_runtime_core` instead of root-private imports.
- Did not move Browser CDP mediation.
- Did not move server lifecycle.
- Did not move platform transport.
- Did not redesign routing.

Old root code ranges moved:

- `runtime_interception_broker.rs` lines 50-155 before Phase 6.
- `runtime_interception_broker.rs` lines 772-836 before Phase 6.

Line counts:

- Root before Phase 6: 1677 lines.
- Root after Phase 6: 1507 lines.
- `handlers.rs`: 192 lines.

Moved item inventory:

```text
SessionRegistration
SessionInterceptionHandler
SessionInterceptionRouter
impl fmt::Debug for SessionInterceptionRouter
SessionInterceptionHandler::decision_for_request
```

Visibility changes:

- `SessionRegistration` is `pub(super)` and its fields are `pub(super)`.
  Justification: server lifecycle/state remains in the root module in this
  phase, and it still constructs registrations and reads registration fields
  while handling guard requests.
- `SessionInterceptionHandler::id()` was added as `pub(super)`.
  Justification: root server registration needs the handler id to build the
  handler map; a method avoids exposing the private `id` field.
- `SessionInterceptionRouter::decide_process_exec` is `pub(super)`.
  Justification: root request routing still calls into the router until server
  handling moves later.
- `SessionInterceptionHandler::decision_for_request` is `pub(super)`.
  Justification: root request routing still asks the selected handler for a
  decision until server handling moves later.

Verification:

- Done: `cargo fmt`
- Done: `cargo check -p erebor-runtime-session --all-targets --all-features`
- Done: `cargo test -p erebor-runtime-session --lib`
  - Included `broker_routes_process_exec_requests_without_handler_id`.
  - Included `broker_fails_closed_for_unknown_interception_handler`.
- Done: live governed-session lifecycle probe from `lifecycle-probe.md`
  - Re-run with escalated execution because ptrace/session execution is blocked
    by the sandbox without escalation.
  - Allowed Linux-host governed session printed `erebor-lifecycle-allowed`.
  - Denied Linux-host governed session exited non-zero with status `1`.
  - Audit evidence contained `"type":"deny"`.
  - Audit evidence contained `deny-raw-cdp`.
  - Probe workspace:
    `/tmp/erebor-broker-lifecycle.zBMxeH`.
  - Host cgroup residual risk remained:
    `cgroup_failed=1 cgroup_reason=failed to create cgroup directory: Permission denied (os error 13)`.
- Done: `cargo test --workspace --all-targets --all-features`
- Done: `cargo clippy --workspace --all-targets --all-features -- -D warnings`

Behavior change:

- No behavior change intended. Direct process-exec requests still route through
  the registered surface handler, unknown handlers still fail closed, and
  mediation/browser/server/platform behavior is unchanged.
