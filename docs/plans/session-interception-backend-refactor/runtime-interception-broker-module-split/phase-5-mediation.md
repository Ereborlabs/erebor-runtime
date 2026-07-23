# Phase 5: Extract Mediation

Status: Done.

## Purpose

Move mediation primitives before moving handler/router logic that consumes them.

## Scope

Create or update:

- `runtime_interception_broker/mediation.rs`
- root `runtime_interception_broker.rs`

Move only:

- `SessionMediationIntent`
- `SurfaceMediationOutcome`
- `SurfaceMediationHandler`
- `SessionMediationRegistry`
- `impl fmt::Debug for SessionMediationRegistry`

## Non-Goals

- Do not move `SessionInterceptionHandler`.
- Do not move `SessionInterceptionRouter`.
- Do not move Browser CDP mediation.
- Do not move server lifecycle.

## Implementation Rules

- Compare stale `mediation.rs` against the root mediation range before moving.
- Treat the root file as the source of truth.
- Preserve public constructors and builders exactly.
- Preserve derives exactly unless the compiler proves a moved internal type
  requires a visibility-only adjustment.
- Phase 0 found that stale `mediation.rs` makes `SurfaceMediationOutcome` fields
  and `SessionMediationRegistry::mediate` `pub(super)`. Do not apply that
  blindly in this phase; first determine whether root code still needs private
  access while handlers remain in root.
- If visibility must change, document why in the phase handoff.

## Checkpoint

```sh
cargo fmt
cargo check -p erebor-runtime-session --all-targets --all-features
cargo test -p erebor-runtime-session --lib
```

Then run the live governed-session lifecycle probe in `lifecycle-probe.md`.

## Required Evidence

- Stale `mediation.rs` comparison result.
- Old root code range moved.
- Root and `mediation.rs` line counts.
- Item inventory showing moved mediation items.
- Any visibility changes, with justification.
- Compile/check result.
- Test result.
- Live lifecycle probe result.

## Acceptance

- Public mediation API remains available from the root broker module.
- Unregistered mediation surfaces still fail closed.
- A real Linux-host governed session runs an allowed command.
- A real Linux-host governed session fails closed for the denied
  `remote-debugging-port` command and writes audit evidence.

## Stop Point

Stop after Phase 5 verification. Wait for approval for Phase 6.

## Phase 5 Result

State: Done.

Implemented:

- Compared stale `mediation.rs` against the current root mediation range.
- Confirmed the moved item bodies matched root after applying only the
  visibility normalization required by this phase:
  - `SurfaceMediationOutcome` fields from private to `pub(super)`.
  - `SessionMediationRegistry::mediate` from private to `pub(super)`.
- Added `mod mediation;` to the root broker module.
- Re-exported the public mediation API from the root broker module:
  - `SessionMediationIntent`
  - `SessionMediationRegistry`
  - `SurfaceMediationHandler`
  - `SurfaceMediationOutcome`
- Removed the mediation primitive block from the root broker module.
- Removed the root import that became mediation-only:
  - `ProcessMediationPrivateEndpointConfig`
- Did not move `SessionInterceptionHandler`.
- Did not move `SessionInterceptionRouter`.
- Did not move Browser CDP mediation.
- Did not move server lifecycle.

Old root code range moved:

- `runtime_interception_broker.rs` lines 153-347 before Phase 5.

Line counts:

- Root before Phase 5: 1869 lines.
- Root after Phase 5: 1678 lines.
- `mediation.rs`: 200 lines.

Moved item inventory:

```text
SessionMediationIntent
SurfaceMediationOutcome
SurfaceMediationHandler
SessionMediationRegistry
impl fmt::Debug for SessionMediationRegistry
```

Visibility changes:

- `SurfaceMediationOutcome` fields are `pub(super)` in `mediation.rs`.
  Justification: `SessionInterceptionHandler::decision_for_request` still lives
  in the root module in this phase and must read the mediation outcome fields
  while constructing the IPC `MediateDecision`.
- `SessionMediationRegistry::mediate` is `pub(super)` in `mediation.rs`.
  Justification: `SessionInterceptionHandler::decision_for_request` still lives
  in the root module in this phase and must call registry mediation.
- `SessionMediationIntent` fields remained private.
- `SurfaceMediationHandler::mediate` remained part of the public trait API.

Verification:

- Done: `cargo fmt`
- Done: `cargo check -p erebor-runtime-session --all-targets --all-features`
- Done: `cargo test -p erebor-runtime-session --lib`
  - Included `broker_fails_closed_when_mediation_surface_is_not_registered`.
- Done: live governed-session lifecycle probe from `lifecycle-probe.md`
  - Re-run with escalated execution because ptrace/session execution is blocked
    by the sandbox without escalation.
  - Allowed Linux-host governed session printed `erebor-lifecycle-allowed`.
  - Denied Linux-host governed session exited non-zero with status `1`.
  - Audit evidence contained `"type":"deny"`.
  - Audit evidence contained `deny-raw-cdp`.
  - Probe workspace:
    `/tmp/erebor-broker-lifecycle.KGQfMq`.
  - Host cgroup residual risk remained:
    `cgroup_failed=1 cgroup_reason=failed to create cgroup directory: Permission denied (os error 13)`.
- Done: `cargo test --workspace --all-targets --all-features`
- Done: `cargo clippy --workspace --all-targets --all-features -- -D warnings`

Behavior change:

- No behavior change intended. Public mediation constructors/builders remain
  available from the root broker module, unregistered mediation surfaces still
  fail closed, and Browser CDP mediation stayed in the root for Phase 7.
