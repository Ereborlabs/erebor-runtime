# Phase 3: Leaf Crate Error Migration

Status: Done.

## Purpose

Migrate leaf crates to SNAFU errors and the shared `ErrorExt` taxonomy before
touching runtime orchestration.

Start with crates that have smaller error surfaces and fewer upstream callers.

## Scope

Migrate:

```text
crates/erebor-runtime-policy
crates/erebor-runtime-ipc
crates/erebor-runtime-terminal
crates/erebor-runtime-events
```

`erebor-runtime-events` may have no error type. If so, record that explicitly
and do not invent one.

## Implementation Steps

1. For each crate with errors, add dependency:
   - `erebor-runtime-error`
   - keep `snafu`
   - remove `thiserror`
2. Convert error enums to `#[derive(Debug, Snafu)]`.
3. Use `#[snafu(visibility(pub(crate)))]` by default.
4. Add `#[snafu(implicit)] location: Location` to public/domain variants.
5. Add a local `pub type Result<T> = std::result::Result<T, Error>;` where the
   crate has one primary error.
6. Implement `ErrorExt` for each public error type.
7. Map statuses:
   - policy syntax/rule problems -> `InvalidArguments` or `InvalidSyntax`
   - duplicated rule -> `AlreadyExists`
   - IPC malformed data -> `InvalidArguments`
   - unsupported protocol or command -> `Unsupported`
   - terminal policy read I/O -> `External`
   - terminal invalid config -> `InvalidArguments`
   - terminal policy denial as an error, if represented as an error ->
     `PolicyDenied`
8. Move `TerminalSurfaceError` out of
   `crates/erebor-runtime-terminal/src/lib.rs` into:

```text
crates/erebor-runtime-terminal/src/error.rs
```

9. Update `lib.rs` exports:

```rust
mod error;
pub use error::{Error as TerminalSurfaceError, Result as TerminalSurfaceResult};
```

If the crate can use `pub use error::{Error, Result};` without harming clarity,
prefer the shorter Greptime-style export and update all callers.

10. Replace manual constructors with SNAFU selectors where possible.
11. Delete old constructors once callers migrate.
12. Delete `thiserror` dependencies from migrated crates.

## Non-Goals

- Do not touch core/session/CDP/CLI errors in this phase except for compile
  fixes required by migrated leaf error names.
- Do not add compatibility type aliases unless a same-phase caller needs a
  temporary bridge; remove the bridge before completing the phase.
- Do not change policy or terminal behavior.

## Focused Checkpoint

```sh
cargo fmt
cargo test -p erebor-runtime-policy --all-targets --all-features
cargo test -p erebor-runtime-ipc --all-targets --all-features
cargo test -p erebor-runtime-terminal --all-targets --all-features
cargo test -p erebor-runtime-events --all-targets --all-features
cargo test -p erebor-runtime-session --all-targets --all-features
cargo test -p erebor-runtime-cli --all-targets --all-features
cargo test --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
git diff --check
```

Then run `lifecycle-probe.md`.

## Required Evidence

- Per-crate list of migrated errors.
- Per-crate status mapping summary.
- Confirmation that `TerminalSurfaceError` moved out of `lib.rs`.
- Confirmation that migrated crates no longer depend on `thiserror`.
- Focused test results.
- Workspace/clippy results.
- Lifecycle probe result.

## Acceptance

- Leaf crates use SNAFU errors and implement `ErrorExt`.
- No old `thiserror` dependency remains in migrated crates.
- Lifecycle probe passes.

## Stop Point

Stop after Phase 3 verification. Wait for user approval for Phase 4.

## Phase 3 Result

State: Done.

Migrated crates:

- `erebor-runtime-policy`
  - Migrated `PolicyError` from `thiserror` to `#[derive(Debug, Snafu)]`.
  - Added `erebor-runtime-error` dependency.
  - Kept `snafu` dependency.
  - Removed `thiserror` dependency.
  - Added `pub type Result<T> = std::result::Result<T, PolicyError>`.
  - Replaced manual constructors with SNAFU selectors in policy parsing and
    validation.
  - Implemented `ErrorExt`.
- `erebor-runtime-ipc`
  - Migrated `IpcProtocolError` from `thiserror` to
    `#[derive(Debug, Snafu)]`.
  - Added `erebor-runtime-error` and `snafu` dependencies.
  - Removed `thiserror` dependency.
  - Added `pub type Result<T> = std::result::Result<T, IpcProtocolError>`.
  - Replaced crate-local manual constructors with SNAFU selectors in frame and
    envelope helpers.
  - Implemented `ErrorExt`.
- `erebor-runtime-terminal`
  - Moved `TerminalSurfaceError` out of `src/lib.rs` into `src/error.rs`.
  - The crate now exports:

    ```rust
    mod error;
    pub use error::{Error as TerminalSurfaceError, Result as TerminalSurfaceResult};
    ```

  - Added `erebor-runtime-error` and `snafu` dependencies.
  - Removed `thiserror` dependency.
  - Replaced terminal policy read/parse/config constructors with SNAFU
    selectors.
  - Implemented `ErrorExt`.
- `erebor-runtime-events`
  - Confirmed there is no crate-owned runtime/domain error type.
  - No error module was invented.

Status mapping summary:

- `PolicyError::EmptyPolicy` -> `InvalidArguments`.
- `PolicyError::InvalidPolicySyntax` -> `InvalidSyntax`.
- `PolicyError::InvalidRule` -> `InvalidArguments`.
- `PolicyError::DuplicateRule` -> `AlreadyExists`.
- `IpcProtocolError::UnsupportedFrameVersion` -> `Unsupported`.
- `IpcProtocolError::EncodePayload` -> `Unexpected`.
- Other IPC malformed frame/envelope/decode errors -> `InvalidArguments`.
- `TerminalSurfaceError::ReadPolicy` -> `External`, with retry hint derived
  from the source `io::Error`.
- `TerminalSurfaceError::InvalidPolicy` -> source policy status/retry hint.
- `TerminalSurfaceError::PolicyJson` -> `InvalidSyntax`.
- `TerminalSurfaceError::InvalidGuardConfig` -> `InvalidArguments`.
- Terminal policy denial is not represented as an error in this crate, so no
  `PolicyDenied` mapping was added.

Caller fixes:

- `erebor-runtime-session/src/runtime_interception_broker/wire.rs` now fills
  SNAFU `Location` fields when constructing `IpcProtocolError` values while
  decoding partial frame headers. No session error type was migrated in this
  phase.

Dependency cleanup:

- `crates/erebor-runtime-policy/Cargo.toml` no longer depends on `thiserror`.
- `crates/erebor-runtime-ipc/Cargo.toml` no longer depends on `thiserror`.
- `crates/erebor-runtime-terminal/Cargo.toml` no longer depends on
  `thiserror`.
- `Cargo.lock` confirms those migrated packages no longer list `thiserror`.

Verification:

```text
cargo fmt
cargo test -p erebor-runtime-policy --all-targets --all-features
  result: passed, 8 passed
cargo test -p erebor-runtime-ipc --all-targets --all-features
  result: passed, 13 passed
cargo test -p erebor-runtime-terminal --all-targets --all-features
  result: passed, 4 passed
cargo test -p erebor-runtime-events --all-targets --all-features
  result: passed, 3 passed
cargo test -p erebor-runtime-session --all-targets --all-features
  result: passed
cargo test -p erebor-runtime-cli --all-targets --all-features
  result: passed, 39 passed
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
- Probe workspace: `/tmp/erebor-broker-lifecycle.LlQhNv`.
- Allowed command printed `erebor-lifecycle-allowed`.
- Denied command failed closed with exit code `126`.
- Audit evidence contained `"type":"deny"`.
- Audit evidence contained `deny-raw-cdp`.

Not done in this phase:

- Core/session/CDP/CLI error types were not migrated.
- Runtime orchestration error modules were not split.
- Logging call sites were not migrated.
- Terminal `lib.rs` remains larger than the target file-size rule from earlier
  code; this phase only moved the error type as scoped.

Stop point reached. Phase 4 is not started.
