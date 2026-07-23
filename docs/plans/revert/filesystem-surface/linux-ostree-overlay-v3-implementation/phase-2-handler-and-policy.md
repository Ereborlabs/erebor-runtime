# Phase 2: Filesystem Handler And Policy Decisions

Status: Done.

## Purpose

Add the filesystem surface decision handler that owns allow, deny,
require-approval, and mediation decisions for file operations.

The broker may route file requests, but policy evaluation must live in the
filesystem surface.

## Scope

- Add `crates/erebor-runtime-session/src/surfaces/filesystem.rs` or a module
  root plus focused submodules.
- Implement a filesystem handler that implements
  `FileOperationSurfaceHandler`.
- Read filesystem policy paths from `FilesystemSurfaceConfig`, falling back to
  global policy paths where the existing surface policy pattern says so.
- Match file operation actions according to the Phase 1 event taxonomy:
  - `file_open`
  - `file_read`
  - `file_mutation`
- Use current policy matchers (`surface`, `action`, `target_contains`,
  `payload_contains`, `risk_at_least`) unless Phase 1 explicitly extends the
  policy language.
- Normalize request paths for policy matching without resolving through
  untrusted symlink traversal.
- Register the filesystem file-operation handler in
  `SessionInterceptionRouter` when the filesystem surface is enabled.
- Add synthetic broker/router tests for filesystem allow, deny,
  require-approval, and fail-closed missing handler cases.

## Non-Goals

- Do not trace real Linux file syscalls yet.
- Do not mount overlays.
- Do not create filesystem checkpoints.
- Do not implement rollback.

## Checkpoint

```sh
cargo fmt
cargo check -p erebor-runtime-session --all-targets --all-features
cargo test -p erebor-runtime-session --lib
cargo test -p erebor-runtime-session --test filesystem_surface_config
cargo test -p erebor-runtime-session --test filesystem_surface_lifecycle
```

Then run the Phase 2 assertions in `lifecycle-probe.md`.

## Required Evidence

- Files changed.
- Handler registration path.
- Policy actions supported.
- Unit and synthetic broker tests added.
- Lifecycle probe result for synthetic file-operation routing.

## Acceptance

- Filesystem file decisions are owned by the filesystem surface handler.
- Broker file-operation requests route to the filesystem handler.
- Path policy tests use `target_contains` or `payload_contains` unless a
  `path_contains` matcher has been deliberately added.
- Missing filesystem handler still fails closed.
- No terminal surface code evaluates filesystem file policy.

## Stop Point

Stop after Phase 2 verification. Wait for approval for Phase 3.

## Phase 2 Result

State: Done.

Implemented:

- Added `FilesystemFileOperationHandler` under
  `crates/erebor-runtime-session/src/surfaces/filesystem.rs`.
- Split focused helpers under
  `crates/erebor-runtime-session/src/surfaces/filesystem/`:
  - `path.rs` for lexical request-path normalization.
  - `mediation.rs` for filesystem-owned mediation metadata parsing.
  - `tests.rs` for handler unit coverage.
- Exposed the handler and `FilesystemSessionContext` from
  `erebor-runtime-session` so integration tests can register a synthetic
  filesystem handler with the runtime broker.
- Wired enabled `SessionSurfaceDefinition::Filesystem` entries in
  `crates/erebor-runtime-session/src/session_side_resources.rs` to:
  - read filesystem policy paths through `read_policy_set(config.policies())`
  - build a filesystem session context from the session plan
  - attach JSONL audit recording when a prepared session exists
  - register the handler on `SessionInterceptionRouter`
  - keep `EREBOR_FILESYSTEM_SURFACE=filesystem` in the session environment
- Added `erebor-runtime-audit` and `serde_json` dependencies to
  `erebor-runtime-session` for filesystem audit writes and event payloads.

Handler registration path:

```text
RuntimeConfig::surface_start_plan_for_session
  -> SessionSurfaceLaunchPlan::from_start_plan
  -> SessionSurfaceDefinition::Filesystem
  -> FilesystemFileOperationHandler::new
  -> SessionInterceptionRouter::with_file_operation_handler
  -> RuntimeInterceptionBroker session registration
```

Policy actions supported:

- `file_open`
- `file_read`
- `file_mutation`

Policy behavior:

- The filesystem handler owns policy evaluation for file operations.
- Policy matching uses existing matchers such as `surface`, `action`,
  `target_contains`, `payload_contains`, and `risk_at_least`.
- No `path_contains` matcher was added.
- Request paths are normalized lexically for event target/payload matching.
  The handler does not resolve symlinks or walk the host filesystem in this
  phase.
- Missing filesystem handler still fails closed in the broker.
- Terminal surface code does not evaluate filesystem file policy.

Tests added:

- `surfaces::filesystem::tests::filesystem_handler_allows_denies_and_requires_approval`
- `surfaces::filesystem::tests::filesystem_handler_mediates_from_policy_metadata`
- `surfaces::filesystem::tests::filesystem_handler_writes_audit_records`
- `surfaces::filesystem::tests::path_normalization_is_lexical`
- `synthetic_file_operations_route_to_filesystem_handler_and_audit`
- `synthetic_file_operation_fails_closed_without_filesystem_handler`

Lifecycle probe:

- Probe workspace: `/tmp/erebor-fs-phase2.mxCqrX`
- Synthetic filesystem routing/audit proof:
  `cargo test -p erebor-runtime-session --test filesystem_surface_lifecycle`
  passed with 2 tests.
- Existing terminal/process lifecycle carry-forward:
  `cargo run -p erebor-runtime-cli -- session diagnose --runner linux-host --config /tmp/erebor-fs-phase2.mxCqrX/config.json filesystem-phase2`
  passed outside the sandbox.
- Filesystem config/session setup: passed. The diagnostic asserted
  `EREBOR_FILESYSTEM_SURFACE=filesystem` and
  `EREBOR_TERMINAL_PROCESS_GUARD=linux_ptrace`.
- Host caveat: the guard reported `cgroup_failed=1` because this host denied
  creating `/sys/fs/cgroup/erebor/...`; this is a residual-risk report and did
  not fail the diagnostic.
- Initial sandboxed diagnostic attempt failed before session launch with
  `runtime interception broker I/O failed: Operation not permitted`; the
  passing probe was rerun outside the sandbox with approval.

Verification:

- Done: `cargo fmt`
- Done: `cargo check -p erebor-runtime-filesystem --all-targets --all-features`
- Done: `cargo check -p erebor-runtime-core --all-targets --all-features`
- Done: `cargo check -p erebor-runtime-session --all-targets --all-features`
- Done: `cargo test -p erebor-runtime-core --lib`
  - 56 passed, 0 failed.
- Done: `cargo test -p erebor-runtime-session --lib`
  - 33 passed, 0 failed.
- Done: `cargo test -p erebor-runtime-session --test linux_process_guard`
  - 1 passed, 0 failed.
- Done: `cargo test -p erebor-runtime-session --test filesystem_surface_config`
  - 1 passed, 0 failed.
- Done: `cargo test -p erebor-runtime-session --test filesystem_surface_lifecycle`
  - 2 passed, 0 failed.
- Done: `cargo test --workspace --all-targets --all-features`
  - Passed. Existing slow real-Chrome tests remained ignored.
- Done: `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- Done: `git diff --check`
- Done: Phase 2 touched-code file-size scan; all checked code files are under
  300 lines.

Stop point:

- Phase 3 is not started. Wait for user approval before implementing it.
