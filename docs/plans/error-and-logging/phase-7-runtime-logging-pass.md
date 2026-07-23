# Phase 7: Runtime Logging Pass

Status: Done.

## Purpose

Apply the GreptimeDB-style telemetry wrappers to lifecycle-critical runtime
logging and remove noisy or duplicated direct error logs.

This phase is a logging behavior pass, not an error type migration.

## Scope

Review and update logging in:

```text
crates/erebor-runtime-core/src/runtime.rs
crates/erebor-runtime-core/src/session.rs
crates/erebor-runtime-core/src/session_registry.rs
crates/erebor-runtime-session/src
crates/erebor-runtime-cdp/src
crates/erebor-runtime-audit/src
crates/erebor-runtime-cli/src/main.rs
```

## Implementation Steps

1. Add `erebor-runtime-telemetry` dependencies to touched crates.
2. Replace direct `tracing` macro imports only where the telemetry wrapper adds
   value. Plain `tracing::instrument` can remain direct.
3. Use `error!(err; "...")` for true owning-boundary failures.
4. Use `warn!(err; "...")` for recoverable failures, cleanup failures, or audit
   sink failures that do not abort the main operation.
5. Use `info!` for lifecycle transitions:
   - runtime start
   - surface start
   - session start
   - broker start
   - broker connection bind
   - session registry write
6. Use `debug!` for high-frequency protocol details:
   - CDP method forwarding
   - broker wire frames
   - state recovery
7. Ensure these fields appear where relevant:
   - `session_id`
   - `runner`
   - `surface`
   - `handler_id`
   - `method`
   - `rule_id`
   - `workspace`
   - `listen`
   - `browser_url` only when it is already safe to log
8. Remove duplicate logs where a lower layer logs then returns the same error
   to a boundary that logs again.
9. Do not log policy denials as internal errors. Log denial decisions at info or
   debug level unless they represent a malfunction.
10. Add tests where practical:
   - compile tests for telemetry macro usage in each touched crate
   - unit tests for any helper that decides log severity from `StatusCode`
11. Manually inspect lifecycle probe stderr/stdout to ensure denial wording
   remains visible.

## Non-Goals

- Do not add log file rotation, OTLP, dynamic reload, or slow-query style
  logging.
- Do not change audit JSON schemas.
- Do not change policy decisions.
- Do not create log snapshot tests unless they are stable and cheap.

## Focused Checkpoint

```sh
cargo fmt
cargo test -p erebor-runtime-telemetry --all-targets --all-features
cargo test -p erebor-runtime-core --all-targets --all-features
cargo test -p erebor-runtime-audit --all-targets --all-features
cargo test -p erebor-runtime-session --all-targets --all-features
cargo test -p erebor-runtime-cdp --all-targets --all-features
cargo test -p erebor-runtime-cli --all-targets --all-features
cargo test --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
git diff --check
```

Then run `lifecycle-probe.md`.

## Required Evidence

- Summary of changed logging boundaries.
- Confirmation that duplicated error logs were removed.
- Confirmation that denials are not logged as internal runtime failures.
- Focused test results.
- Workspace/clippy results.
- Lifecycle probe result.

## Acceptance

- Lifecycle-critical logs use structured telemetry wrappers where useful.
- Errors are logged once at owning boundaries.
- Lifecycle probe passes.

## Current Status

State: Done as of 2026-07-04.

Changed logging boundaries:

- Added `erebor-runtime-telemetry` dependencies to
  `erebor-runtime-core`, `erebor-runtime-audit`, `erebor-runtime-session`, and
  `erebor-runtime-cdp`.
- Removed stale direct `tracing` dependencies from those migrated crates after
  their direct logging macro usage moved to telemetry wrappers.
- Replaced direct lifecycle/protocol `tracing::{debug, info, warn}` macro usage
  with `erebor_runtime_telemetry::{debug, info, warn}` in the scoped runtime
  crates.
- Left CLI tracing initialization in `crates/erebor-runtime-cli/src/logging.rs`
  as the CLI-specific adapter. The CLI command-failure boundary already used
  `erebor_runtime_telemetry::error!` from Phase 6.
- Added structured fields where useful:
  - `session_id` on session runner, session registry, audit append, CDP proxy,
    browser session, CDP forwarding, CDP observer, and CDP decision logs.
  - `runner` on session runner launch/adoption logs.
  - `surface`, `listen`, `browser_url`, and `method` where already present and
    safe.
  - `rule_id` on CDP block/approval and observed Fetch-failure logs when a
    policy decision record is available.

Duplicate/noisy error logs removed:

- Removed the lower-level `error!` log from
  `SessionSurfaceSupervisor::wait`; the failure is converted into
  `RuntimeError::SurfaceExited` and logged once by the CLI boundary.
- Removed the background browser-CDP surface `error!` log before forwarding the
  same failure through the surface failure channel. The CLI boundary logs the
  resulting command failure once.

Denial logging:

- CDP command blocks and observed Fetch request failures are logged at `info`
  with `session_id`, `method`, `reason`, and `rule_id`, not as internal runtime
  errors.
- Recoverable audit sink, CDP connection, and CDP observer failures remain
  `warn` logs with error context.

Verification:

- `cargo fmt` passed.
- `cargo test -p erebor-runtime-telemetry --all-targets --all-features` passed
  (`4 passed`).
- `cargo test -p erebor-runtime-core --all-targets --all-features` passed
  (`50 passed`).
- `cargo test -p erebor-runtime-audit --all-targets --all-features` passed
  (`19 passed`).
- `cargo test -p erebor-runtime-session --all-targets --all-features` passed
  (`25` library tests, `23` Linux process guard unit tests, `9`
  `linux_host_runner` tests, and `1` `linux_process_guard` test).
- `cargo test -p erebor-runtime-cdp --all-targets --all-features` passed
  (`42` unit tests; `proxy_e2e`: `3 passed`, `2 ignored`;
  `runtime_e2e`: `11 passed`, `2 ignored`).
- `cargo test -p erebor-runtime-cli --all-targets --all-features` passed
  (`42 passed`).
- `cargo test --workspace --all-targets --all-features` passed.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
  passed.
- `git diff --check` passed.

Verification note:

- During verification, the filesystem reached `100%` full and `rustc` failed
  with `No space left on device`. `cargo clean` was run to remove rebuildable
  Cargo artifacts, freeing `45.7GiB`, then the focused tests resumed and
  passed.

Lifecycle probe:

- The first sandboxed lifecycle probe was blocked by the host sandbox with
  `runtime interception broker I/O failed: Operation not permitted (os error 1)`.
- The same lifecycle probe passed with host process permissions:
  - allowed command printed `erebor-lifecycle-allowed`
  - denied command failed closed
  - denial wording remained visible:
    `erebor linux process guard: denied exec: ... raw CDP process launch is denied`
  - CLI boundary logged the command failure once
  - audit evidence contained `"type":"deny"`
  - audit evidence contained `deny-raw-cdp`
  - probe workspace:
    `/tmp/erebor-error-logging-lifecycle.9Aelw8`

## Stop Point

Stop after Phase 7 verification. Wait for user approval for Phase 8.
