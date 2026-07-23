# Phase 5: Mount-Capable Overlay Session View

Status: Done.

## Purpose

Run a Linux-host session where the agent sees the OverlayFS merged view at the
configured path.

This is the phase that proves the runtime controls the filesystem path the
agent mutates.

## Scope

- Bind the host path read-only as the direct kernel OverlayFS lowerdir.
- Mount kernel `overlay` with per-volume `upperdir`, `workdir`, and `merged`.
- Run the session command in a mount namespace where `session_path` is bound to
  the merged path.
- Ensure the raw `host_path` is not exposed as a writable or mutable path inside
  the governed process. The agent must not be able to bypass the overlay by
  opening the original absolute host path.
- Use private mount propagation for session mounts so mount state does not
  leak back to the host or sibling sessions.
- Unmount in reverse order on session finish and on failure.
- Refuse to start if Linux namespace or OverlayFS mount prerequisites are
  missing.
- Prefer a rootless user namespace that preserves the current session uid
  (`unshare -U --map-current-user --keep-caps -m`) when the host supports it.
- If the runtime itself has mount capability as root, mount setup may run with
  that capability, but the governed session command must drop to a non-root
  target uid/gid before execution.
- Add host-supported tests behind explicit mount-lifecycle gating, and keep
  normal unit tests unprivileged.
- Update lifecycle probe to write, replace, and delete files through the
  session path while verifying the host path remains unchanged before
  promotion.
- Update lifecycle probe to attempt a raw-host-path write and prove it cannot
  bypass the overlay.

## Non-Goals

- Do not normalize or commit upperdir changes yet.
- Do not promote session changes to host.
- Do not implement rootless `fuse-overlayfs`.
- Do not implement Docker/OCI filesystem revert.
- Do not use Docker's `overlay2` storage-driver layout for this Linux-host
  backend.

## Checkpoint

```sh
cargo fmt
cargo check -p erebor-runtime-session --all-targets --all-features
cargo test -p erebor-runtime-session --lib
cargo test -p erebor-runtime-session --test filesystem_surface_lifecycle
```

Then run the Phase 5 assertions in `lifecycle-probe.md`.

## Required Evidence

- Mount commands or syscall wrappers used.
- Mount namespace ownership.
- Cleanup behavior on success and failure.
- Mount-capable lifecycle probe result.
- Evidence that the governed session command is not forced to run as root.

## Acceptance

- The agent process sees the overlay merged view at `session_path`.
- Writes through `session_path` appear in `upperdir`.
- Host files are unchanged before promotion.
- A write attempted through the raw `host_path` from inside the governed
  process either cannot resolve the raw host path or is denied/read-only; it
  must not mutate the host and must not bypass the overlay changed-set.
- Denied filesystem policy mutations do not create upperdir changes.
- Mounts are cleaned up after the session.
- The phase fails closed when mount prerequisites are unavailable.

## Stop Point

Stop after Phase 5 verification. Wait for approval for Phase 6.

## Phase 5 Result

State: Done.

Implemented:

- Added composable Linux-host command wrappers in
  `LinuxHostSessionCommandOptions` so the filesystem overlay wrapper can run
  outside the existing process guard wrapper.
- Added `LinuxOverlaySessionView` in `erebor-runtime-filesystem`, split across
  a module root, `plan.rs`, and `script.rs`.
- The overlay wrapper:
  - creates a private mount namespace;
  - prefers `unshare -U --map-current-user --keep-caps -m` so the governed
    command runs as the current session uid while still allowing kernel
    OverlayFS mounts on hosts that support that model;
  - falls back to plain `unshare -m` for runtimes that already have mount
    capability;
  - refuses to run the session command as root unless a non-root target uid/gid
    is available, and then uses `setpriv` before invoking the command;
  - bind-mounts `host_path` read-only as the lowerdir;
  - mounts kernel `overlay` with the prepared `upperdir`, `workdir`, and
    `merged`;
  - masks the raw `host_path` with a read-only empty bind mount inside the
    namespace;
  - bind-mounts `merged` over `session_path`;
  - unmounts `session_path`, masked `host_path`, `merged`, and `lower-ro` in
    reverse order through shell cleanup traps.
- Added fail-closed overlay plan validation for:
  - missing Linux commands;
  - non-Linux platforms;
  - host/session path overlap;
  - host/storage root overlap;
  - root paths;
  - non-directory or non-UTF-8/comma/newline paths.
- Added gated Phase 5 lifecycle tests, now housed in
  `crates/erebor-runtime-session/tests/filesystem_surface_lifecycle/linux_host/overlay_session_view.rs`.

Verification:

```sh
cargo fmt
cargo check -p erebor-runtime-session --all-targets --all-features
cargo test -p erebor-runtime-filesystem --lib
cargo test -p erebor-runtime-session --lib
cargo test -p erebor-runtime-session --test filesystem_surface_lifecycle -- --test-threads=1 --nocapture
PATH=/tmp/erebor-ostree-deb.JOW1pw/root/usr/bin:$PATH \
  EREBOR_REQUIRE_FILESYSTEM_LIFECYCLE=1 \
  EREBOR_RUN_FILESYSTEM_OVERLAY_LIFECYCLE=1 \
  cargo test -p erebor-runtime-session --test filesystem_surface_lifecycle linux_host::overlay_session_view -- --test-threads=1 --nocapture
cargo test --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
git diff --check
```

All commands passed. The gated lifecycle probe passed both Phase 5 tests:

- `linux_host_overlay_session_view_writes_through_upperdir_without_host_mutation`
- `linux_host_denied_overlay_mutation_does_not_create_upperdir_change`

Lifecycle evidence:

- The governed command observed uid != 0.
- The command read host lower content through `session_path`, replaced
  `settings.json`, deleted `old-cache.txt`, and created `generated/token.txt`.
- The replacement and creation appeared in `upperdir`.
- The host `settings.json`, `old-cache.txt`, and lack of `generated/token.txt`
  were unchanged before promotion.
- A raw `host_path/settings.json` write attempt from inside the governed
  command failed and did not mutate the host.
- A denied `file_mutation` wrote the expected filesystem denial audit record
  and did not create `settings.json` in `upperdir`.
- `findmnt --mountpoint` verified `session_path` and `host_path` were not
  leaked mountpoints after session finish.
