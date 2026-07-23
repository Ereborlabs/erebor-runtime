# Phase 2: Common Telemetry Crate

Status: Done.

## Purpose

Add a small telemetry crate inspired by GreptimeDB's `common-telemetry`.

The first version should be intentionally small:

- logging macros
- tracing re-exports
- test logging helper
- optional CLI initialization helper only if it can replace existing CLI code
  cleanly

## Scope

Create:

```text
crates/erebor-runtime-telemetry/Cargo.toml
crates/erebor-runtime-telemetry/src/lib.rs
crates/erebor-runtime-telemetry/src/macros.rs
crates/erebor-runtime-telemetry/src/logging.rs
```

Update:

```text
Cargo.toml
Cargo.lock
```

## Implementation Steps

1. Add `crates/erebor-runtime-telemetry` to workspace members.
2. Dependencies:
   - `erebor-runtime-error`
   - `tracing`
   - `tracing-subscriber`
3. In `lib.rs`:
   - `pub use erebor_runtime_error as error;`
   - `pub use tracing;`
   - re-export `init_test_logging` and any shared initialization helper
   - expose macros from `macros.rs`
4. In `macros.rs`, implement these Greptime-style comma forms:

```rust
error!("message", field = %value);
error!(err; "message", field = %value);
error!(%err; "message", field = %value);
warn!("message", field = %value);
warn!(err; "message", field = %value);
info!("message", field = %value);
debug!("message", field = %value);
trace!("message", field = %value);
```

Do not add a second field syntax in this phase. One supported form is easier to
test and harder for later migrations to misuse.

5. Error macro behavior:
   - `error!(err; ...)` records `error = ?err`.
   - `error!(%err; ...)` records `error = %err`.
   - If `err` implements `ErrorExt` at call sites later, callers may add
     explicit `status_code = %err.status_code()`. Do not attempt type
     specialization in the macro.
6. In `logging.rs`, implement:
   - `init_test_logging()`
   - a small shared `LoggingOptions` only if it stays under 300 lines
   - no file rotation or OTLP in this phase
7. Add macro compile tests that call every supported form.
8. Add a unit test that calls `init_test_logging()` twice and proves it is
   idempotent.

## Non-Goals

- Do not migrate existing logging call sites yet.
- Do not add OTLP, reloadable filters, slow logs, or rolling files.
- Do not wrap every `tracing` feature.

## Focused Checkpoint

```sh
cargo fmt
cargo test -p erebor-runtime-telemetry --all-targets --all-features
cargo test --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
git diff --check
```

Then run `lifecycle-probe.md`.

## Required Evidence

- New crate file tree.
- Supported macro syntax.
- Macro test names and results.
- Workspace test result.
- Clippy result.
- Lifecycle probe result.

## Acceptance

- Telemetry crate builds and tests pass.
- Existing runtime behavior is unchanged.
- Lifecycle probe still passes.

## Stop Point

Stop after Phase 2 verification. Wait for user approval for Phase 3.

## Phase 2 Result

State: Done.

Implemented:

- Added workspace crate `crates/erebor-runtime-telemetry`.
- Added `erebor-runtime-telemetry` to workspace members and lockfile.
- Added dependencies on `erebor-runtime-error`, `tracing`, and
  `tracing-subscriber`.
- Re-exported `erebor_runtime_error` as `error`.
- Re-exported `tracing` and `tracing_subscriber`.
- Re-exported `init_test_logging`.
- Added Greptime-style logging macros:
  - `error!("message", field = %value);`
  - `error!(err; "message", field = %value);`
  - `error!(%err; "message", field = %value);`
  - `warn!("message", field = %value);`
  - `warn!(err; "message", field = %value);`
  - `info!("message", field = %value);`
  - `debug!("message", field = %value);`
  - `trace!("message", field = %value);`
- `error!(err; ...)` records `error = ?err`.
- `error!(%err; ...)` records `error = %err`.
- `warn!(err; ...)` records `error = ?err`.
- `init_test_logging()` is idempotent and uses test-writer tracing output.

New crate file tree:

```text
crates/erebor-runtime-telemetry/Cargo.toml
crates/erebor-runtime-telemetry/src/lib.rs
crates/erebor-runtime-telemetry/src/macros.rs
crates/erebor-runtime-telemetry/src/logging.rs
```

Tests added:

- `macros::tests::error_macro_supports_message_fields_and_error_fields`
- `macros::tests::warn_macro_supports_message_fields_and_error_fields`
- `macros::tests::level_macros_support_message_fields`
- `logging::tests::init_test_logging_is_idempotent`

Verification:

```text
cargo fmt
cargo test -p erebor-runtime-telemetry --all-targets --all-features
  result: passed, 4 passed
cargo test --workspace --all-targets --all-features
  result: passed
cargo clippy --workspace --all-targets --all-features -- -D warnings
  result: passed
git diff --check
  result: passed
```

Lifecycle probe:

- First sandboxed run was blocked by the host-process sandbox:
  `runtime interception broker I/O failed: Operation not permitted (os error 1)`.
- Rerun with host process permissions passed.
- Probe workspace: `/tmp/erebor-broker-lifecycle.N5DINw`.
- Allowed command printed `erebor-lifecycle-allowed`.
- Denied command failed closed with exit code `126`.
- Audit evidence contained `"type":"deny"`.
- Audit evidence contained `deny-raw-cdp`.

Not done in this phase:

- No existing logging call sites were migrated.
- No OTLP support was added.
- No reloadable filters were added.
- No slow logs or rolling file appenders were added.
- No `LoggingOptions` was added because the current phase only needed the test
  initializer.

Stop point reached. Phase 3 is not started.
