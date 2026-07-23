# Phase 1: Add Surface-Owned Process-Exec Mediation Contract

Status: Done.

## Purpose

Make the process-exec surface decision contract able to return mediation
directly, without relying on broker mediator registry state.

## Scope

Create or update:

- `crates/erebor-runtime-core/src/interception.rs`
- `crates/erebor-runtime-session/src/runtime_interception_broker/decision.rs`
- `crates/erebor-runtime-session/src/runtime_interception_broker/handlers.rs`
- focused broker tests for surface-owned mediation

## Required Behavior

- `SurfaceInterceptionDecision` can represent allow, deny, require approval,
  and mediate.
- A mediate surface decision carries a resolved `SurfaceMediationDecision`.
- `ProcessExecInterceptionRequest` carries `matched_handler_id`.
- Broker decision conversion can turn a surface mediate decision into IPC
  `MediateDecision`.
- A mediate decision without mediation payload fails closed.

## Non-Goals

- Do not move terminal process mediation config yet.
- Do not change Browser CDP mediation behavior.
- Do not implement browser navigation or filesystem replacement mediation.
- Do not overload IPC `endpoint`.

## Checkpoint

```sh
cargo fmt
cargo check -p erebor-runtime-core --all-targets --all-features
cargo check -p erebor-runtime-session --all-targets --all-features
cargo test -p erebor-runtime-core --lib
cargo test -p erebor-runtime-session --lib
git diff --check
```

Then run the live lifecycle probe in `lifecycle-probe.md`.

## Acceptance

- The surface decision contract carries endpoint-style mediation payloads.
- Process-exec surface handlers receive `matched_handler_id`.
- Router-owned process-exec mediation works without a session-level mediator
  registry.
- Existing Browser CDP mediation behavior is preserved for the next phase to
  move.

## Phase 1 Result

Done. Core now has `SurfaceMediationDecision` and
`SurfaceInterceptionDecision::mediate`. `ProcessExecInterceptionRequest` carries
`matched_handler_id`, and broker IPC conversion accepts surface-owned mediate
decisions.
