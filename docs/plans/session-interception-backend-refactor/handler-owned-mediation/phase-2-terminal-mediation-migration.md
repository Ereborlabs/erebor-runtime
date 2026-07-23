# Phase 2: Move Terminal Process Mediation Into Process-Exec Surface

Status: Done.

## Purpose

Move terminal process mediation config out of broker/session control-handler
registration and into the process-exec surface decision path.

## Scope

Create or update:

- `crates/erebor-runtime-terminal/src/lib.rs`
- `crates/erebor-runtime-session/src/surfaces/terminal.rs`
- `crates/erebor-runtime-session/src/surfaces/terminal/browser_cdp_process_mediation.rs`
- `crates/erebor-runtime-session/src/runtime_interception_broker/handlers.rs`
- `crates/erebor-runtime-session/src/runtime_interception_broker/server.rs`
- focused terminal and broker tests

## Required Behavior

- Empty `matched_handler_id` requests use ordinary terminal process policy.
- Non-empty `matched_handler_id` requests use terminal process-interception
  handler config.
- Terminal process handlers can return allow, deny, require approval, and
  mediate.
- Browser CDP fixed endpoint mediation is bound as a terminal process
  capability.
- Browser CDP lazy owned-surface mediation is bound as a terminal process
  capability.
- Missing Browser CDP capability fails closed in the terminal process surface.
- Unknown matched handler id fails closed in the terminal process surface.
- Broker dispatch routes all process-exec requests through the router.

## Backend Boundary

The Linux interception backend may prepare process guard mechanics, shims,
executable matching data, environment, and runner command options. It must not
produce allow, deny, approval, or mediate broker decision handlers from
terminal mediation config.

## APIs Removed

- `SessionMediationRegistry`
- `SessionInterceptionHandler`
- `SessionMediationIntent`
- `SurfaceMediationHandler`
- `SurfaceMediationOutcome`
- `RuntimeInterceptionBroker::register_session_with_mediators`
- `RuntimeInterceptionBroker::register_session_with_router_and_mediators`
- `SessionInterceptionBackendBundle::control_handlers()`
- `runtime_interception_broker/mediation.rs`

## Checkpoint

```sh
cargo fmt
cargo check -p erebor-runtime-core --all-targets --all-features
cargo check -p erebor-runtime-terminal --all-targets --all-features
cargo check -p erebor-runtime-session --all-targets --all-features
cargo test -p erebor-runtime-core --lib
cargo test -p erebor-runtime-terminal --lib
cargo test -p erebor-runtime-session --lib
cargo test -p erebor-runtime-session --test linux_host_runner
cargo test -p erebor-runtime-session --test linux_process_guard
git diff --check
```

Then run the live lifecycle probe in `lifecycle-probe.md`.

## Acceptance

- Terminal process mediation is owned by the process-exec surface handler.
- Browser CDP process mediation behavior is unchanged.
- Broker registration stores no session-level mediation registry.
- Broker request dispatch does not pass mediator state.
- The Linux interception backend is mechanics-only for this path.

## Phase 2 Result

Done. `TerminalProcessExecValidator` owns matched handler decisions and calls
`TerminalProcessMediationCapability` for mediated launches. Browser CDP process
mediation is bound into terminal as `BrowserCdpProcessMediationCapability`, and
broker request dispatch calls `SessionInterceptionRouter::route_interception`.
