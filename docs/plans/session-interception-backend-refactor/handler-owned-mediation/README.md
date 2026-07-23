# Handler-Owned Mediation Subplan

Status: Done. Phases 0 through 3 are complete.

Parent plan: `docs/plans/session-interception-backend-refactor/README.md`

## Goal

Move mediation ownership out of the runtime interception broker request path
and into each session's owning surface decision handler.

For process execution, terminal owns the allow, deny, approval, and mediate
decision. Browser CDP may provide the runtime capability that launches or
reuses a governed endpoint, but Browser CDP does not own terminal process
policy and the broker does not own mediation resolution.

## Non-Negotiables

- Do not reintroduce a session-level mediation registry.
- Do not make the broker server clone, pass, or resolve mediation state.
- Do not add a broker-owned handler map for matched process-interception
  handlers.
- Keep missing mediation capability fail-closed.
- Keep unknown `matched_handler_id` fail-closed.
- Keep Browser CDP fixed endpoint and lazy owned-browser mediation behavior.
- Keep the Linux interception backend mechanics-only: guard binary, shims,
  executable matching data, environment, and runner command options.
- Do not overload IPC `MediateDecision.endpoint` for replacement URLs or file
  paths.
- Do not change the one runtime-owned broker socket model.
- Do not change `GuardHello.session_id` binding semantics.

## Existing Problem

The original post-split broker path still encoded mediation as broker/session
state:

- `SessionRegistration` stored a session-level `SessionMediationRegistry`.
- Requests with `matched_handler_id` bypassed the process-exec surface router.
- The broker selected `SessionInterceptionHandler` values and passed mediator
  state into request handling.
- Terminal process mediation config was converted by the Linux backend into
  broker control handlers.
- The process-exec surface decision contract could not return mediation
  payloads directly.

That ownership was wrong. Mediation is a decision outcome for the surface that
owns the action. Broker state should bind and route, not decide or mediate.

## Current Target Shape

```text
process guard
  -> broker GuardHello binding
  -> SessionInterceptionRouter
  -> terminal process-exec surface handler
  -> SurfaceInterceptionDecision
  -> IPC InterceptionDecision
```

```text
session setup
  -> TerminalProcessSurface builds backend input
  -> TerminalProcessSurface builds process-exec router
  -> optional BrowserCdpProcessMediationCapability is bound into terminal
  -> SessionInterceptionSetup registers the router with the broker
  -> runner receives broker endpoint command options
```

## Current Module Ownership

`crates/erebor-runtime-core/src/interception.rs`

- `SurfaceInterceptionDecision`.
- `SurfaceMediationDecision`.
- `ProcessExecInterceptionRequest` with `matched_handler_id`.
- `ProcessExecSurfaceHandler`.

`crates/erebor-runtime-terminal/src/lib.rs`

- `TerminalProcessExecValidator`.
- Ordinary terminal process policy.
- Terminal process-interception handler policy.
- `TerminalProcessMediationCapability`.

`crates/erebor-runtime-session/src/surfaces/terminal.rs`

- `TerminalProcessSurface`.
- Process-exec interception backend input construction.
- Process-exec router construction.
- Browser CDP process mediation capability selection.

`crates/erebor-runtime-session/src/surfaces/terminal/browser_cdp_process_mediation.rs`

- `BrowserCdpProcessMediationCapability`.
- Fixed Browser CDP endpoint mediation.
- Lazy owned Browser CDP surface startup/reuse.
- Remote-debugging port validation.
- Private endpoint port selection helper.

`crates/erebor-runtime-session/src/runtime_interception_broker/handlers.rs`

- `SessionInterceptionRouter`.
- Internal `SessionRegistration` with token, broker id, and router only.
- Process-exec request conversion to the surface handler contract.

`crates/erebor-runtime-session/src/runtime_interception_broker/server.rs`

- `RuntimeInterceptionBroker`.
- `SessionInterceptionRegistration`.
- Runtime-owned broker server state.
- Guard hello binding.
- Session lookup and router dispatch.

`crates/erebor-runtime-session/src/runtime_interception_broker/decision.rs`

- Surface decision to IPC decision conversion.
- Fail-closed deny helper.
- No socket, session table, or mediation registry ownership.

`crates/erebor-runtime-session/src/interception_setup.rs`

- Broker session registration.
- Broker endpoint command-option wiring for Docker and Linux-host runners.

## Removed Ownership Artifacts

These names describe the old ownership boundary and should stay absent from
runtime source:

- `SessionMediationRegistry`
- `SessionInterceptionHandler`
- `SessionMediationIntent`
- `SurfaceMediationHandler`
- `SurfaceMediationOutcome`
- `RuntimeInterceptionBroker::register_session_with_mediators`
- `RuntimeInterceptionBroker::register_session_with_router_and_mediators`
- `SessionInterceptionBackendBundle::control_handlers()`
- `runtime_interception_broker/mediation.rs`
- `runtime_interception_broker/browser_cdp_mediation.rs`

## IPC Boundary

Current IPC mediation is endpoint-shaped:

- `kind`
- `replacement_surface`
- `endpoint`
- `lease_id`
- `print_line`
- `keepalive`

That shape covers Browser CDP process-launch mediation. It does not cover
browser website replacement or filesystem replacement. Those stories require a
future IPC extension or operation-specific mediation payload.

## Phase 0 Baseline Summary

Phase 0 documented the old broker-owned mediation path and the behavior that
had to survive the refactor:

- one runtime-owned broker socket
- `GuardHello.session_id` binding
- fixed Browser CDP mediation
- lazy Browser CDP mediation
- missing mediator/capability fail-closed behavior
- unknown handler fail-closed behavior
- process-exec audit attribution

The current baseline is that the old registry and matched-handler broker path
are gone, and the behavior above is owned by the surface path.

## Phase List

- [Phase 0: Inventory And Behavior Contract](./phase-0-inventory-and-behavior-contract.md)
- [Phase 1: Add Surface-Owned Process-Exec Mediation Contract](./phase-1-surface-decision-handlers-own-mediation.md)
- [Phase 2: Move Terminal Process Mediation Into Process-Exec Surface](./phase-2-clean-registration-boundaries.md)
- [Phase 3: Cleanup, IPC Gap Docs, And Full Verification](./phase-3-tests-docs-and-full-verification.md)
- [Live Lifecycle Probe](./lifecycle-probe.md)

## Verification

Required focused checkpoint:

```sh
cargo fmt
cargo check -p erebor-runtime-core --all-targets --all-features
cargo check -p erebor-runtime-terminal --all-targets --all-features
cargo check -p erebor-runtime-session --all-targets --all-features
cargo check -p erebor-runtime-ipc --all-targets --all-features
cargo test -p erebor-runtime-core --lib
cargo test -p erebor-runtime-terminal --lib
cargo test -p erebor-runtime-session --lib
cargo test -p erebor-runtime-ipc --all-targets
cargo test -p erebor-runtime-session --test linux_host_runner
cargo test -p erebor-runtime-session --test linux_process_guard
```

Required full checkpoint:

```sh
cargo test --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
git diff --check
```

Implementation phases also require the live governed-session lifecycle probe in
`lifecycle-probe.md`.

## Source Checks

Use these checks when changing this boundary:

```sh
rg -n "SessionMediationRegistry|SurfaceMediationHandler|SessionInterceptionHandler|SessionMediationIntent|SurfaceMediationOutcome|register_session_with_mediators|register_session_with_router_and_mediators|control_handlers\\(|runtime_interception_broker::mediation|browser_cdp_mediation" crates/erebor-runtime-session/src crates/erebor-runtime-terminal/src crates/erebor-runtime-core/src
rg -n "SurfaceMediationDecision|SurfaceInterceptionDecision|matched_handler_id|TerminalProcessExecValidator|TerminalProcessMediationCapability|BrowserCdpProcessMediationCapability|SessionInterceptionRouter|route_interception|RuntimeInterceptionBroker::register_session" crates/erebor-runtime-core/src crates/erebor-runtime-terminal/src crates/erebor-runtime-session/src
```

The obsolete-artifact scan should find no old broker mediator registry APIs.
Matches for `uses_managed_browser_cdp_mediation` are current terminal surface
helper names and are allowed.
