# Runtime Interception Broker Module Split Subplan

Status: Done. Phases 0 through 10 are complete and verified.

Parent plan: `docs/plans/session-interception-backend-refactor/README.md`

## Goal

Split `crates/erebor-runtime-session/src/runtime_interception_broker.rs` into
small, responsibility-owned modules without changing behavior.

This is a mechanical organization refactor. It is not an architecture redesign,
not a policy-routing redesign, and not permission to remove functionality.

## Non-Negotiables

- Do not implement this subplan until the user approves it.
- Implement only one approved phase at a time.
- Do not one-shot the full file split.
- Do not remove functionality.
- Do not collapse behavior into smaller "equivalent" code.
- Do not make architecture decisions during implementation. If a boundary is
  unclear, stop and provide analysis; the user decides.
- Keep public API compatibility unless a phase explicitly says otherwise.
- Keep line/item parity visible after each extraction.
- After Phase 0, every phase must leave the repository compiling, tested, and
  runnable as a real governed session.
- Cargo tests are not enough for implementation phases. Each implementation
  phase must also run the live lifecycle probe in
  `lifecycle-probe.md`: start a governed Linux-host session, run an allowed
  command, run a denied process-exec command, and verify audit evidence.
- Run the phase-specific checkpoint and the live lifecycle probe before
  starting the next phase.
- If a phase checkpoint fails, fix only that phase's boundary issue before
  continuing.
- If the live lifecycle probe cannot run because the host cannot support Linux
  ptrace/session execution, the phase is blocked. Do not substitute unit tests
  and call the phase done.
- Do not touch unrelated dirty files.
- Do not delete the stale untracked split directory as part of this plan. It is
  comparison/reference material.
- Do not blindly trust or wire the stale split files. For each phase, compare
  the relevant stale file against the current root implementation, identify the
  necessary import/visibility boundary changes, and move from the current root
  source of truth.

## Existing Problem

`runtime_interception_broker.rs` currently mixes several responsibilities in one
large module:

- public endpoint environment contract
- session registration and server lifecycle
- runtime-owned socket server state
- platform transport implementation
- broker client helper
- wire framing helpers
- session handler/router policy decision conversion
- mediation registry and mediation outcome types
- browser CDP mediation startup and endpoint validation
- test helpers and broker tests

This makes future broker changes risky because unrelated responsibilities share
imports, private fields, helper functions, and tests.

## Target Module Tree

Final target, subject to explicit phase approval:

```text
crates/erebor-runtime-session/src/runtime_interception_broker.rs
crates/erebor-runtime-session/src/runtime_interception_broker/
  browser_cdp_mediation.rs
  client.rs
  constants.rs
  decision.rs
  endpoint.rs
  handlers.rs
  mediation.rs
  platform.rs
  server.rs
  tests.rs
  wire.rs
```

The root file should become a thin module root only after all extracted modules
are compiling and tested. Until the final phase, it may temporarily contain some
remaining implementation.

## Phase 0 Baseline Summary

- Current tracked root broker file:
  `crates/erebor-runtime-session/src/runtime_interception_broker.rs`
- Root line count: 2083 lines.
- Root tracked diff at inventory time: empty.
- Stale untracked split directory exists:
  `crates/erebor-runtime-session/src/runtime_interception_broker/`
- Stale untracked split directory line count: 2144 lines across 11 files.
- Baseline `cargo test -p erebor-runtime-session --lib`: passed, 20 tests.

Phase 0 comparison result: the stale split directory contains candidate files
for all major root responsibilities, and no behavior-bearing root item is
obviously absent from the stale directory. However, those files are uncompiled
artifacts with module-boundary assumptions, import changes, and visibility
changes. They are reference material only; the current 2083-line root file is
the implementation source of truth.

## Module Ownership

`constants.rs`

- Runtime interception socket name.
- Runtime interception protocol string.
- Interception token header name.
- Default timeout.

`endpoint.rs`

- `RuntimeInterceptionEndpoint`.
- Endpoint environment variables.
- Endpoint path, directory, token, timeout helpers.

`wire.rs`

- IPC frame read/write helpers.
- Interception token envelope helper.
- Hex token encoding helper.
- No session routing decisions.

`decision.rs`

- Conversion from local surface decisions to IPC decisions.
- Fail-closed deny decision helpers.
- No socket, platform, or session table ownership.

`mediation.rs`

- `SessionMediationIntent`.
- `SurfaceMediationOutcome`.
- `SurfaceMediationHandler`.
- `SessionMediationRegistry`.

`handlers.rs`

- `SessionInterceptionHandler`.
- `SessionInterceptionRouter`.
- Internal `SessionRegistration` only if the server still stores that exact
  shape.
- Process-exec request conversion to the surface handler contract.

`browser_cdp_mediation.rs`

- `BrowserCdpMediationHandler`.
- Fixed endpoint and lazy Browser CDP mediation.
- Remote-debugging port parsing and validation.
- Private endpoint port selection helper.

`platform.rs`

- `RuntimeInterceptionBrokerPlatform`.
- `RuntimeInterceptionBrokerServerPlatform`.
- Unix socket transport implementation.
- Windows unsupported transport implementation.
- No session map or routing ownership.

`server.rs`

- `RuntimeInterceptionBroker`.
- `SessionInterceptionRegistration`.
- `RuntimeInterceptionBrokerError`.
- `RuntimeInterceptionBrokerServer`.
- Shared runtime-owned server singleton.
- Session map ownership.
- Guard hello binding.
- Runtime interception envelope dispatch.

`client.rs`

- `InterceptionBrokerClient`.
- Client calls delegated through the platform trait.

`tests.rs`

- Existing broker unit tests and test helpers, moved mechanically.

## Required Evidence Per Phase

Each phase handoff must include:

- exact files changed
- old code range moved, when practical
- stale artifact comparison for the moved responsibility, including missing or
  extra items
- item inventory before/after for moved items
- line-count delta for root file and new module files
- compile/test commands and results
- live lifecycle probe command and result for every implementation phase
- explicit statement of whether behavior was changed

## Approval Workflow

The user approves a single phase by name. Only that phase is implemented.

After each phase:

- stop
- report verification
- wait for the user's next approval

## Final Status

State: Done.

The broker module split is complete. The root broker file is now a thin module
root with declarations, public re-exports, and the test module declaration.
All old responsibilities have named modules under
`crates/erebor-runtime-session/src/runtime_interception_broker/`.

Final verification after Phase 10:

- Done: `cargo fmt`
- Done: `cargo check -p erebor-runtime-session --all-targets --all-features`
- Done: `cargo test -p erebor-runtime-session --lib`
- Done: `cargo test -p erebor-runtime-session --test linux_host_runner`
- Done: `cargo test -p erebor-runtime-session --test linux_process_guard`
- Done: `cargo test --workspace --all-targets --all-features`
- Done: `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- Done: `git diff --check`
- Done: live governed-session lifecycle probe at
  `/tmp/erebor-broker-lifecycle.9RGQzx`.

No behavior change is intended by this module split.

## Phase Index

- [Live Lifecycle Probe](./lifecycle-probe.md)
- [Phase 0: Inventory And Cleanup Gate](./phase-0-inventory-and-cleanup-gate.md)
- [Phase 1: Extract Constants](./phase-1-constants.md)
- [Phase 2: Extract Endpoint](./phase-2-endpoint.md)
- [Phase 3: Extract Wire Helpers](./phase-3-wire.md)
- [Phase 4: Extract Decision Helpers](./phase-4-decision-helpers.md)
- [Phase 5: Extract Mediation](./phase-5-mediation.md)
- [Phase 6: Extract Handlers And Router](./phase-6-handlers-and-router.md)
- [Phase 7: Extract Browser CDP Mediation](./phase-7-browser-cdp-mediation.md)
- [Phase 8: Extract Server And Platform Together](./phase-8-server-and-platform.md)
- [Phase 9: Extract Broker Client](./phase-9-client.md)
- [Phase 10: Move Tests And Final Root Cleanup](./phase-10-tests-root-cleanup-and-full-verification.md)
