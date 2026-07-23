# Phase 13: Large File And CoW Preimages

Status: Done.

## Purpose

Avoid copying huge preimages into OSTree when the host filesystem can provide a
safe reflink copy-on-write mechanism, and block clearly when it cannot.

V3 is proportional to changed data plus rollback preimages. If an agent
replaces a large existing file, exact rollback is expensive unless a native
CoW backend is available.

## Recorded Decision

Reflink is sufficient for the first CoW preimage backend. Btrfs and ZFS
snapshot backends are deferred to later backend-expansion phases in this plan.

## Scope

- Add a preimage backend abstraction owned by `erebor-runtime-filesystem`.
- Keep the current OSTree byte preimage backend as the default.
- Detect and test Linux reflink support with `FICLONE` for regular files.
- Do not implement Btrfs/ZFS snapshot backends in this phase.
- Record preimage backend metadata in `erebor-preimage.json`.
- Roll back from reflink artifacts when selected.
- Preserve fail-closed behavior when:
  - the file exceeds `preimage_size_limit_bytes`;
  - reflink CoW is disabled or unsupported;
  - reflink setup fails;
  - backend artifact validation fails before rollback.
- Add tests for:
  - small-file OSTree byte preimages;
  - large-file block without CoW;
  - reflink-backed preimage when supported;
  - backend artifact loss or drift.

## Non-Goals

- Do not weaken exact rollback guarantees for large files.
- Do not store unbounded large preimages in OSTree by default.
- Do not implement Btrfs or ZFS snapshot backends in Phase 13.

## Lifecycle Probe Growth

Extend the live probe with a large-file case:

- configure a small `preimage_size_limit_bytes`;
- seed a host file larger than that limit;
- run a governed session that replaces the file;
- verify promotion blocks before host mutation when reflink CoW is disabled or
  unsupported;
- when reflink is supported and enabled, verify promotion succeeds without
  storing the full old bytes in OSTree and rollback restores the old bytes;
- record host filesystem capability output in the phase result.

## Checkpoint

```sh
cargo fmt
cargo check -p erebor-runtime-filesystem --all-targets --all-features
cargo test -p erebor-runtime-filesystem --lib large_file
cargo test -p erebor-runtime-session --test filesystem_surface_lifecycle large_file -- --test-threads=1 --nocapture
PATH=/tmp/erebor-ostree-deb.JOW1pw/root/usr/bin:$PATH \
  EREBOR_REQUIRE_FILESYSTEM_LIFECYCLE=1 \
  EREBOR_RUN_FILESYSTEM_OVERLAY_LIFECYCLE=1 \
  cargo test -p erebor-runtime-session --test filesystem_surface_lifecycle large_file -- --test-threads=1 --nocapture
cargo test --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
git diff --check
```

## Required Evidence

- Preimage backend manifest examples.
- Host filesystem capability detection output.
- Large-file block example.
- Reflink success example if supported by the test host.

## Acceptance

- Large replacements either use the reflink exact CoW backend or block before
  host mutation.
- The audit and error output explains why exact rollback is or is not available.
- Rollback verifies backend artifacts before restoring.

## Stop Point

Stop after Phase 13 verification. Retention/GC is separate.

## Phase 13 Result

State: Done.

Implemented on July 6, 2026.

What changed:

- Added `FilesystemPreimageBackendKind` with `ostree_bytes` as the default and
  `linux_reflink` as the first explicit CoW backend.
- Added `surfaces.filesystem.revert.preimage_backend` config and wired it from
  runtime config into session-end promotion.
- Added retained Linux reflink artifact storage under
  `work/cow-preimages/<promotion-id>/volumes/<volume-id>/...`, outside the
  mutable promotion workdir and outside the OSTree preimage tree.
- Extended `erebor-preimage.json` regular-file metadata with the selected
  preimage backend. Reflink entries record artifact path, size, mtime,
  device, and inode metadata for validation.
- Extended opaque-directory preimages with `external_files` so hidden large
  regular files can be represented as retained artifacts while normal small
  files remain in the OSTree preimage tree.
- Added pre-apply and pre-rollback artifact validation. Missing or drifted
  artifacts fail closed before host mutation.
- Kept `ostree_bytes` size-budget behavior unchanged: if a preimage exceeds
  `preimage_size_limit_bytes` and `linux_reflink` is not selected/supported,
  promotion blocks before applying the layer to the host.

Host capability result:

- The checked host stores `/tmp` and the workspace on `ext4`
  (`stat -f -c '%T %m' /tmp` reported `ext2/ext3 ?`, and `df -T` reported
  `ext4`).
- `cp --reflink=always` in `/tmp` failed with `Operation not supported`.
- The required lifecycle probe therefore proved the fail-closed large-file
  behavior and skipped the reflink success branch with explicit
  `reflink capability ... unsupported` output.
- Deterministic crate-local tests construct retained `linux_reflink` artifacts
  directly to cover rollback restore and artifact-loss failure on hosts without
  `FICLONE` support.

Ownership and file-size note:

- `promotion/preimage.rs`, `promotion/apply.rs`, and the focused large-file
  test modules are over the soft 300-line readability target after this phase.
  They remain cohesive owners/tests for capture, rollback, and Phase 13
  scenarios. The Linux-specific `FICLONE` and artifact-validation behavior was
  split into `promotion/preimage_artifact.rs`; further splitting capture or
  rollback in this phase would fragment the failure-before-mutation flow more
  than it would clarify it.

Verification:

```text
cargo fmt
```

Passed.

```text
cargo check -p erebor-runtime-filesystem --all-targets --all-features
```

Passed.

```text
cargo test -p erebor-runtime-filesystem large_file -- --nocapture
```

Passed: 6 tests.

```text
cargo test -p erebor-runtime-filesystem --lib -- --nocapture
```

Passed: 45 tests.

```text
cargo test -p erebor-runtime-core filesystem -- --nocapture
```

Passed: 7 tests.

```text
PATH=/tmp/erebor-ostree-deb.JOW1pw/root/usr/bin:$PATH \
EREBOR_REQUIRE_FILESYSTEM_LIFECYCLE=1 \
EREBOR_RUN_FILESYSTEM_OVERLAY_LIFECYCLE=1 \
cargo test -p erebor-runtime-session --test filesystem_surface_lifecycle large_file -- --test-threads=1 --nocapture
```

Passed: 3 tests. The reflink capability lines reported unsupported on this
host; the byte-backend large-file refusal path ran and passed.

```text
cargo test --workspace --all-targets --all-features
```

Passed.

```text
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Passed.

```text
git diff --check
```

Passed.
