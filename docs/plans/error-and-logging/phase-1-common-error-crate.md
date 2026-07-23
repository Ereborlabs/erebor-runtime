# Phase 1: Common Error Crate

Status: Done.

## Purpose

Add the shared Erebor error vocabulary inspired by GreptimeDB's
`common-error`.

This phase creates the foundation only. It does not migrate existing crates yet.

## Scope

Create:

```text
crates/erebor-runtime-error/Cargo.toml
crates/erebor-runtime-error/src/lib.rs
crates/erebor-runtime-error/src/status_code.rs
crates/erebor-runtime-error/src/ext.rs
```

Update:

```text
Cargo.toml
Cargo.lock
```

## Implementation Steps

1. Add `crates/erebor-runtime-error` to workspace members.
2. Keep dependencies minimal:
   - `serde` if serialization helpers are included
   - `snafu`
3. Define `StatusCode` in `status_code.rs`:
   - `Success = 0`
   - `Unknown = 1000`
   - `Unsupported = 1001`
   - `Unexpected = 1002`
   - `Internal = 1003`
   - `InvalidArguments = 1004`
   - `InvalidSyntax = 1005`
   - `NotFound = 1006`
   - `AlreadyExists = 1007`
   - `PolicyDenied = 1008`
   - `PermissionDenied = 1009`
   - `Cancelled = 1010`
   - `DeadlineExceeded = 1011`
   - `IllegalState = 1012`
   - `Unavailable = 1013`
   - `External = 1014`
4. Implement:
   - `StatusCode::is_success(code: u32) -> bool`
   - `StatusCode::from_u32(value: u32) -> Option<Self>`
   - `StatusCode::should_log_error(self) -> bool`
   - `Display` as variant name
5. Define `RetryHint` in `ext.rs`:
   - `Retryable`
   - `NonRetryable`
   - `is_retryable()`
   - `as_str()`
   - `from_io_error(&std::io::Error) -> Self`
6. Define `ErrorExt`:
   - requires `std::error::Error`
   - `status_code(&self) -> StatusCode`
   - `retry_hint(&self) -> RetryHint`
   - `is_retryable(&self) -> bool`
   - `as_any(&self) -> &dyn Any`
   - `output_msg(&self) -> String`
   - `root_cause(&self) -> Option<&dyn Error>`
7. Implement stable source-chain helpers without nightly-only features.
8. Add `BoxedError` only if needed by tests or upcoming phases. If added, it
   must preserve `StatusCode` and `RetryHint`.
9. Add unit tests for:
   - status round trip
   - success detection
   - display
   - retry hint from transient I/O errors
   - retry hint from non-transient I/O errors
   - output message masking for `Unknown` and `Internal`
   - output message preserving user-actionable statuses

## Non-Goals

- Do not migrate existing crate errors.
- Do not add transport-specific gRPC/HTTP mapping.
- Do not add a telemetry crate.
- Do not keep compatibility shims for `thiserror`.

## Focused Checkpoint

```sh
cargo fmt
cargo test -p erebor-runtime-error --all-targets --all-features
cargo test --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
git diff --check
```

Then run `lifecycle-probe.md`.

## Required Evidence

- New crate file tree.
- Unit test names and results.
- Workspace test result.
- Clippy result.
- Lifecycle probe result.
- Confirmation that no existing crate has been migrated yet.

## Acceptance

- `erebor-runtime-error` builds and tests pass.
- Existing behavior is unchanged.
- Lifecycle probe still passes.

## Stop Point

Stop after Phase 1 verification. Wait for user approval for Phase 2.

## Phase 1 Result

State: Done.

Implemented:

- Added `crates/erebor-runtime-error` to the workspace.
- Added the foundational shared error vocabulary:
  - `StatusCode`
  - `RetryHint`
  - `ErrorExt`
  - `root_source`
- Re-exported `snafu` from the new crate for future SNAFU-style migrations.
- Updated `Cargo.lock`.

New crate file tree:

```text
crates/erebor-runtime-error/Cargo.toml
crates/erebor-runtime-error/src/ext.rs
crates/erebor-runtime-error/src/lib.rs
crates/erebor-runtime-error/src/status_code.rs
```

Line counts:

```text
 12 crates/erebor-runtime-error/Cargo.toml
274 crates/erebor-runtime-error/src/ext.rs
  6 crates/erebor-runtime-error/src/lib.rs
156 crates/erebor-runtime-error/src/status_code.rs
448 total
```

All new code files are under the 300-line rule.

Dependencies:

- Added only `snafu.workspace = true` to `erebor-runtime-error`.
- Did not add `serde` because Phase 1 did not include serialization helpers.
- Did not add `BoxedError` because it was not needed for Phase 1 tests or
  current callers.

Existing crate migration:

- None. Existing runtime crates were not migrated in this phase.
- Verified no existing crate outside `erebor-runtime-error` imports
  `erebor-runtime-error`, `ErrorExt`, `RetryHint`, or `StatusCode`.

### Implemented API

`StatusCode` variants:

- `Success = 0`
- `Unknown = 1000`
- `Unsupported = 1001`
- `Unexpected = 1002`
- `Internal = 1003`
- `InvalidArguments = 1004`
- `InvalidSyntax = 1005`
- `NotFound = 1006`
- `AlreadyExists = 1007`
- `PolicyDenied = 1008`
- `PermissionDenied = 1009`
- `Cancelled = 1010`
- `DeadlineExceeded = 1011`
- `IllegalState = 1012`
- `Unavailable = 1013`
- `External = 1014`

`StatusCode` methods:

- `as_u32`
- `is_success`
- `from_u32`
- `should_log_error`
- `as_str`
- `Display`

`RetryHint` variants:

- `Retryable`
- `NonRetryable`

`RetryHint` methods:

- `is_retryable`
- `as_str`
- `from_io_error`
- `Display`
- `FromStr`

`ErrorExt` methods:

- `status_code`
- `retry_hint`
- `is_retryable`
- `as_any`
- `output_msg`
- `root_cause`

Stable source-chain helper:

- `root_source`

### Unit Tests

`cargo test -p erebor-runtime-error --all-targets --all-features` passed 11
tests:

```text
ext::tests::output_message_includes_root_cause_for_user_actionable_wrappers
ext::tests::output_message_masks_unknown_and_internal_errors
ext::tests::output_message_preserves_user_actionable_errors
ext::tests::retry_hint_marks_non_transient_io_errors_non_retryable
ext::tests::retry_hint_marks_transient_io_errors_retryable
ext::tests::retry_hint_round_trips_through_strings
ext::tests::root_source_returns_deepest_source_without_nightly_helpers
status_code::tests::expected_user_statuses_do_not_request_error_logs
status_code::tests::status_code_display_uses_variant_name
status_code::tests::status_code_round_trips_from_u32
status_code::tests::success_detection_uses_success_code_only
```

### Verification

Required commands:

```sh
cargo fmt
cargo test -p erebor-runtime-error --all-targets --all-features
cargo test --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
git diff --check
```

Results:

- `cargo fmt`: passed.
- `cargo test -p erebor-runtime-error --all-targets --all-features`: passed,
  11 tests.
- `cargo test --workspace --all-targets --all-features`: passed.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`:
  passed.
- `git diff --check`: passed.

### Live Lifecycle Probe

Required lifecycle probe run from `lifecycle-probe.md`.

First sandboxed attempt failed before the allowed command could complete:

```text
runtime interception broker I/O failed: Operation not permitted (os error 1)
```

The probe was rerun outside the sandbox because Linux ptrace/socket session
interception needs host process permissions. The escalated probe passed.

Probe workspace:

```text
/tmp/erebor-error-logging-lifecycle.mWcxOV
```

Allowed command result:

- Succeeded.
- Printed `erebor-lifecycle-allowed`.
- Session registry directory existed under the probe workspace.

Denied command result:

- Failed closed with non-zero exit.
- Output contained:

```text
erebor linux process guard: denied exec: /home/navid/.codex/tmp/arg0/codex-arg0yw2nQ7/sh sh --remote-debugging-port=9222: raw CDP process launch is denied
```

Audit evidence:

- Found `"type":"deny"` in:

```text
/tmp/erebor-error-logging-lifecycle.mWcxOV/.erebor/sessions/session-97298/audit.jsonl
```

- Found `deny-raw-cdp` in:

```text
/tmp/erebor-error-logging-lifecycle.mWcxOV/.erebor/sessions/session-97298/audit.jsonl
/tmp/erebor-error-logging-lifecycle.mWcxOV/.erebor/sessions/session-97298/policies/000-policy.json
/tmp/erebor-error-logging-lifecycle.mWcxOV/.erebor/sessions/session-97233/policies/000-policy.json
```

Host note:

- The process guard reported ptrace enabled and recursive attach complete.
- It also reported cgroup setup could not create the cgroup directory:

```text
cgroup_failed=1 cgroup_reason=failed to create cgroup directory: Permission denied (os error 13)
```

This did not block the Phase 1 lifecycle acceptance criteria.

### Phase 1 Acceptance

- `erebor-runtime-error` builds and tests pass.
- Existing runtime crate behavior is unchanged.
- No existing crate errors were migrated.
- Workspace tests pass.
- Clippy is clean with `-D warnings`.
- Live lifecycle probe passes after rerunning outside the sandbox.

Stop point reached. Phase 2 is not started.
