# Phase 0: Inventory And Behavior Contract

Status: Done. Production code not changed by this phase.

## Purpose

Record the mediation ownership baseline and define the behavior that later
phases must preserve while moving ownership into the surface path.

## Scope

Read and document:

- broker request dispatch
- broker session registration
- process-exec router behavior
- terminal process mediation config
- Browser CDP process mediation behavior
- IPC mediation payload limits
- tests that prove current behavior

Do not change production code in this phase.

## Current Baseline After Refactor

The current code now has the target ownership this phase led toward:

- `SessionRegistration` stores token, broker id, and
  `SessionInterceptionRouter`.
- `RuntimeInterceptionBrokerServer::interception_decision_for_request` binds,
  looks up the session, routes through the router, and converts the surface
  decision to IPC.
- `SessionInterceptionRouter::route_interception` sends process-exec requests
  with or without `matched_handler_id` to the process-exec surface handler.
- `TerminalProcessExecValidator` owns ordinary process policy and matched
  process-interception handler decisions.
- `BrowserCdpProcessMediationCapability` is a terminal process mediation
  capability, not broker state.

## Behavior Contract

Later phases must preserve:

- one runtime-owned broker socket
- `GuardHello.session_id` binding
- invalid token fail-closed behavior
- unknown session fail-closed behavior
- unrouted request fail-closed behavior
- unknown `matched_handler_id` fail-closed behavior
- missing Browser CDP mediation capability fail-closed behavior
- fixed Browser CDP endpoint mediation
- lazy Browser CDP owned-surface mediation
- process-exec audit attribution

## IPC Contract

Current `MediateDecision` is endpoint-shaped and valid for Browser CDP
process-launch mediation only. It is not a URL replacement or file replacement
payload.

## Inventory Commands

```sh
rg -n "SessionMediationRegistry|SessionRegistration|decision_for_request|register_session_with.*mediators|mediators|SessionInterceptionHandler::mediate" crates/erebor-runtime-session/src
rg -n "ProcessExecSurfaceHandler|SurfaceInterceptionDecision|SurfaceMediationDecision|TerminalProcessExecValidator|TerminalProcessMediationCapability" crates/erebor-runtime-core/src crates/erebor-runtime-terminal/src crates/erebor-runtime-session/src
rg -n "MediateDecision|replacement_surface|endpoint|lease_id|print_line|keepalive" crates/erebor-runtime-session/src crates/erebor-runtime-ipc/src crates/erebor-runtime-ipc/proto
```

## Checkpoint

```sh
cargo test -p erebor-runtime-session --lib
```

## Acceptance

- Current request-time mediation ownership is documented.
- Current registration-time ownership is documented.
- Browser CDP fixed and lazy behavior are documented.
- IPC representation gaps are documented.
- Later phases have a behavior contract to preserve.

## Phase 0 Result

Phase 0 found that the old mediated process-exec path used broker control
handlers plus a session-level mediator registry. That drove the later phase
order: first make surface decisions carry mediation payloads, then move
terminal process mediation into the surface handler, then remove stale broker
mediation ownership.
