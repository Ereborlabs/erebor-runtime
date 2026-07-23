# Phase 3: Linux File Syscall Interception

Status: Done after corrective coverage.

## Purpose

Extend the Linux ptrace process guard so real file operations can be routed to
the filesystem surface.

This phase addresses the boundary explicitly: the Linux guard observes syscalls,
the runtime broker routes the request, and the filesystem surface decides.

## Scope

- Extend `SessionInterceptionBackendKind::supports_operation` for Linux ptrace
  file operations once the guard implementation exists.
- Extend guard-side IPC types in
  `crates/erebor-runtime-session/src/os/linux/process_guard/ipc.rs` to encode:
  - operation family
  - `FileOperationKind`
  - file path
  - resolved device/inode metadata when available
- Extend the generated IPC proto if Phase 1/3 keeps `(dev, ino)` on the wire
  instead of placing it only in filesystem-surface audit payloads.
- Extend guard tracing in `process_guard.rs` to observe at least:
  - `open`
  - `openat`
  - `openat2`, if available on the host/kernel contract
- Classify file operations into open/read/mutation using syscall flags.
- Resolve relative paths using the traced process cwd for request payloads.
- Include resolved Linux `(dev, ino)` metadata where it can be safely obtained
  for the opened target.
- Deny fail-closed by forcing the syscall result to `EPERM`.
- Write audit evidence for filesystem file decisions.
- Add process guard unit tests for file request encoding and syscall
  classification.
- Add real Linux-host integration tests where `cat secret.txt` is denied by
  filesystem read policy and shell redirection to `settings.json` is denied by
  filesystem mutation policy.

## Non-Goals

- Do not implement full path canonicalization through arbitrary traced process
  namespace state unless Phase 0 approves that scope.
- Do not add network/socket interception.
- Do not implement overlay or revert.

## Checkpoint

```sh
cargo fmt
cargo check -p erebor-runtime-session --all-targets --all-features
cargo test -p erebor-runtime-session --test linux_process_guard
cargo test -p erebor-runtime-session --test filesystem_surface_lifecycle
```

Then run the Phase 3 assertions in `lifecycle-probe.md`.

## Required Evidence

- Syscalls handled.
- Syscalls intentionally not handled yet.
- Guard IPC fields added.
- IPC proto compatibility decision for device/inode metadata.
- Deny mechanism used for file syscalls.
- Unit tests and real lifecycle deny result.

## Acceptance

- A real Linux-host command that opens a denied file fails before reading it.
- A real Linux-host command that opens a denied file for mutation fails before
  mutating it.
- Audit evidence contains filesystem surface, file action, path, rule id, and
  final decision.
- Audit and handler request payloads include resolved device/inode metadata
  where available.
- Terminal process-exec interception still passes the existing lifecycle probe.
- File operation policy is not evaluated in terminal code.

## Stop Point

Stop after Phase 3 verification. Wait for approval for Phase 4.

## Phase 3 Result

State: Done after corrective coverage.

Implemented:

- Added `crates/erebor-runtime-session/src/os/linux/process_guard/file_interception.rs`
  as the guard-owned Linux file syscall classifier and broker requester.
- Added `crates/erebor-runtime-session/src/os/linux/process_guard/ipc/file.rs`
  for guard-side file-operation IPC encoding.
- Extended the guard-side IPC mirror in
  `crates/erebor-runtime-session/src/os/linux/process_guard/ipc.rs` to encode:
  - `InterceptionSource`
  - `InterceptionOperation`
  - `FileOperationKind`
  - file path
  - optional resolved file identity
- Extended
  `crates/erebor-runtime-ipc/proto/erebor/runtime/ipc/v1/control.proto` with
  `FileIdentity` and `FileOperation.resolved_identity`.
- Extended `FileInterceptionRequest` with optional `FileResolvedIdentity` and
  routed IPC file identity through
  `SessionInterceptionRouter::route_file_operation`.
- Updated the filesystem surface audit payload to include
  `resolved_identity` when available.
- Updated Linux ptrace backend preparation so the backend can start for
  filesystem file operations, not only terminal `process_exec`.
- Added `EREBOR_GUARD_INTERCEPTION_OPERATIONS` so the guard only routes the
  operation families effective for the current session.
- Updated Linux ptrace backend capability reporting so file-open/read/mutation
  are backend-supported; they are only effective when the filesystem surface is
  enabled.

Syscalls handled:

- `open`
- `openat`
- `openat2` on x86_64 Linux syscall number `437`

Classification:

- `O_WRONLY`, `O_RDWR`, `O_CREAT`, `O_TRUNC`, `O_APPEND`, and `O_TMPFILE`
  classify as `file_mutation`.
- `O_PATH` classifies as `file_open`.
- Other read-only opens classify as `file_read`.
- Relative paths are resolved against traced process cwd for `open` and
  `openat(AT_FDCWD, ...)`.
- Relative `openat` paths with another directory fd are resolved through
  `/proc/<pid>/fd/<dirfd>` when available.

Syscalls intentionally not handled yet:

- `creat`
- `read`, `pread*`, `readv`
- `write`, `pwrite*`, `writev`
- `rename*`, `unlink*`, `mkdir*`, `rmdir`, `link*`, `symlink*`, `chmod*`,
  `chown*`, and metadata-only mutation families
- `stat*` and access-check families

These are outside Phase 3 because this phase gates pathname-bearing open
families. The corrective coverage pass added the missing real mutation-denial
proof for shell redirection, but lower-level `write*` syscall interception is
still intentionally not part of this phase.

IPC proto compatibility decision:

- Device/inode metadata is part of the typed IPC contract, not filesystem
  surface JSON only.
- The added wire shape is optional and backward-compatible for existing file
  requests:

```proto
message FileOperation {
  FileOperationKind kind = 1;
  string path = 2;
  FileIdentity resolved_identity = 3;
}

message FileIdentity {
  uint64 device = 1;
  uint64 inode = 2;
}
```

Deny mechanism:

- Denied file syscalls use the existing ptrace fail-closed mechanism:
  - on syscall entry, set `orig_rax = -1`
  - set `rax = -EPERM`
  - mark the pid state as denied pending
  - on syscall exit, force `rax = -EPERM` again

Tests added or updated:

- `file_interception::tests::classifies_open_flags_for_file_operations`
- `file_interception::tests::joins_relative_paths_without_canonicalizing`
- `file_interception::tests::resolves_at_fdcwd_relative_paths_against_cwd`
- `ipc::tests::file_interception_request_encodes_operation_and_identity`
- `surfaces::filesystem::tests::filesystem_handler_audits_resolved_identity`
- `linux_host::linux_host_cat_secret_is_denied_by_filesystem_policy`
- `linux_host::linux_host_settings_mutation_is_denied_by_filesystem_policy`
- Updated core capability tests so Linux ptrace file operations are
  backend-supported after this phase.
- Updated IPC contract tests to assert `FileIdentity` remains in the proto.

Lifecycle probe:

- Probe workspace: `/tmp/erebor-fs-phase3.WCvN0e`
- Command:
  `cargo run -p erebor-runtime-cli -- session diagnose --runner linux-host --config /tmp/erebor-fs-phase3.WCvN0e/config.json deny-secret`
- Result: passed as a deny probe. The diagnostic exited non-zero because
  `cat secret.txt` received `Operation not permitted`.
- Guard evidence:
  `erebor linux process guard: denied file_read: /tmp/erebor-fs-phase3.WCvN0e/workspace/secret.txt: secret file reads are denied`
- Audit path:
  `/tmp/erebor-fs-phase3.WCvN0e/workspace/.erebor/sessions/session-888592/audit.jsonl`
- Audit evidence: line 65 contains `surface = filesystem`, `action =
  file_read`, path `/tmp/erebor-fs-phase3.WCvN0e/workspace/secret.txt`, rule
  `deny-secret-read`, final decision `deny`, and
  `resolved_identity.device/resolved_identity.inode`.
- Host caveat: the guard still reported `cgroup_failed=1` because this host
  denied creating `/sys/fs/cgroup/erebor/...`; ptrace attach and file denial
  succeeded.

Corrective coverage added after Phase 4:

- Added a real Linux-host mutation denial lifecycle test:
  `linux_host::linux_host_settings_mutation_is_denied_by_filesystem_policy`.
- The diagnostic command is:

```sh
sh -lc 'printf changed > settings.json'
```

- The policy denies `surface = filesystem`, `action = file_mutation`, and
  `target_contains = settings.json`.
- The assertion proves:
  - the diagnostic fails through the governed linux-host path
  - the original host file still contains `original-settings`
  - audit contains `surface = filesystem`
  - audit contains `action = file_mutation`
  - audit contains rule `deny-settings-mutation`
  - audit contains resolved `device` and `inode` metadata where available
- The read-denial and mutation-denial tests no longer depend on OSTree or
  configured filesystem volumes. They exercise the Linux ptrace file syscall
  interception and filesystem policy path directly.

Verification:

- Done: `cargo fmt`
- Done: `cargo check -p erebor-runtime-core --all-targets --all-features`
- Done: `cargo check -p erebor-runtime-session --all-targets --all-features`
- Done: `cargo test -p erebor-runtime-ipc --all-targets --all-features`
  - 15 passed, 0 failed.
- Done: `cargo test -p erebor-runtime-core --lib`
  - 56 passed, 0 failed.
- Done: `cargo test -p erebor-runtime-session --lib`
  - 34 passed, 0 failed.
- Done: `cargo test -p erebor-runtime-session --test linux_process_guard`
  - 1 passed, 0 failed. The standalone guard unit suite inside it ran 27
    tests.
- Done: `cargo test -p erebor-runtime-session --test filesystem_surface_config`
  - 1 passed, 0 failed.
- Done after corrective coverage:
  `cargo test -p erebor-runtime-session --test filesystem_surface_lifecycle -- --test-threads=1 --nocapture`
  - 5 passed, 0 failed.
  - The Phase 4 storage-layout test reported that `ostree` was not in `PATH`
    in the sandbox and skipped only that OSTree-dependent assertion. The real
    read-denial and real mutation-denial tests ran and passed.
- Done: `cargo test --workspace --all-targets --all-features`
  - Passed. Existing slow real-Chrome tests remained ignored.
- Done: `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- Done: `git diff --check`
- Done: new-code file-size scan. New Phase 3 files are under 300 lines.
- Corrective note: the surrounding legacy Linux process guard files remain
  over the 300-line target. Do not add more behavior to `process_guard.rs`,
  `process_guard/ipc.rs`, or `process_guard/interception.rs` without first
  splitting the touched responsibility into focused modules.

Stop point:

- Phase 4 and Phase 4a are complete. Wait for user approval before
  implementing Phase 5.
