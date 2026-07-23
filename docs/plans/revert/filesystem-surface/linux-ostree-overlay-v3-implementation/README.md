# Filesystem Surface Linux OSTree OverlayFS V3 Implementation Subplan

Status: Phase 16 implemented. Phase 17 is the next approval gate.

Parent design:

- [`../ostree-overlay-v3/README.md`](../ostree-overlay-v3/README.md)

Reference planning structure:

- [`docs/plans/session-interception-backend-refactor/runtime-interception-broker-module-split/`](../../../session-interception-backend-refactor/runtime-interception-broker-module-split/)

## Goal

Implement the Linux filesystem surface for reversible session filesystem
changes using the V3 design:

```text
host allowed path
  -> read-only lowerdir
  -> OverlayFS upperdir records changes
  -> merged path is mounted into the Linux-host session
  -> normalized upperdir layer is stored in OSTree
  -> promotion captures preimages before host mutation
  -> rollback restores from committed preimages
```

The implemented first backend is Linux-only and uses direct kernel OverlayFS. Mount
setup may use the current user's namespace capabilities or a mount-capable
runtime path, but the governed session command must not be forced to run as
root. Phase 16 records the backend-expansion gates for other Linux backends,
Docker/OCI integration, and non-Linux filesystem surfaces, but those later
phases do not start without explicit implementation approval.

## Current-Code Grounding

The current tree has these filesystem-surface pieces after Phase 15:

- `crates/erebor-runtime-core/src/interception/file.rs` defines
  `FileInterceptionRequest`, `FileInterceptionOperationKind`, and
  `FileOperationSurfaceHandler`.
- `crates/erebor-runtime-ipc/proto/erebor/runtime/ipc/v1/control.proto`
  already has `FileOperation`, `FileOperationKind`, and file operation families.
- `crates/erebor-runtime-session/src/runtime_interception_broker/handlers.rs`
  can route file-open/read/mutation requests to a registered file handler.
- `crates/erebor-runtime-filesystem` exists as the first filesystem domain
  crate.
- `surfaces.filesystem` config exists with backend, policies, volumes, and
  revert settings.
- `SessionSurfaceKind::Filesystem`,
  `SessionSurfaceDefinition::Filesystem`, and filesystem file action event
  contracts exist.
- `crates/erebor-runtime-session/src/surfaces/filesystem.rs` owns synthetic
  file-operation policy decisions and audit writes for the filesystem surface.
- The Linux process guard now routes `open`, `openat`, and `openat2`
  pathname-bearing syscalls to the runtime broker when file operation
  interception is enabled for the session.
- Real file-read denial through the filesystem surface is covered by
  `crates/erebor-runtime-session/tests/filesystem_surface_lifecycle.rs`.
- `erebor-runtime-filesystem` owns the session storage layout, filesystem
  volume storage requests, path/id validation, OSTree repo initialization,
  upperdir normalization, checkpoint commits, promotion, rollback, retained
  artifact inventory/pruning, and session-work transactions.
- Prepared sessions create filesystem storage under
  `.erebor/sessions/<session-id>/filesystem/` for configured filesystem
  volumes.
- Filesystem storage preparation uses
  `ostree --repo=<session-dir>/filesystem/repo init --mode=bare-user-only`
  and configures `core.min-free-space-percent=0` for Erebor-created repos.
- Successful sessions checkpoint all configured writable volumes.
- Sessions with `promote_on_session_finish = true` commit preimages before host
  mutation, promote all volumes, and leave committed refs for rollback.
- Sessions with promotion disabled can autocommit session work at the supported
  `session_finish` boundary when configured under
  `surfaces.filesystem.revert.autocommit`.
- `erebor_runtime_filesystem::rollback_promotion(...)` restores promoted
  volumes from committed preimage refs.
- The transaction catalog and rollback operator workflow can list/show/rename
  and roll back transactions/subtransactions.
- `filesystem transactions commit` creates explicit session-work transactions,
  and `work@{n}` handles list/show/rename/rollback unpromoted overlay-state
  transactions without mutating the host.
- Supported Linux metadata and safe xattrs are restored through shared
  metadata helpers.
- Opaque directories normalize to `opaque_replace`, capture hidden lower
  subtree preimages before mutation, promote by replacing the host subtree, and
  roll back through the captured preimage.

## Remaining Work Against The V3 Design

The first Linux direct OverlayFS implementation now executes the approved V3
Linux lifecycle through Phase 15. The remaining gaps are explicit backend
expansion phases:

- Phase 17: rootless `fuse-overlayfs` fallback backend;
- Phase 18: Docker/OCI filesystem revert integration;
- Phase 19: Btrfs snapshot backend;
- Phase 20: ZFS snapshot backend;
- Phase 21: extraction pointer to the dedicated
  [`macos-fskit-overlay-v1-implementation`](../macos-fskit-overlay-v1-implementation/)
  plan;
- Phase 22: Windows filesystem-surface equivalent.

Action-boundary, pre-approval, and pre-mediation autocommit triggers remain
unsupported until the runtime has implemented quiescent barriers for them.

## Phase 0 Historical Baseline Summary

Phase 0 inventory was run against the then-current tree and found these
historical baselines:

- V3 design source:
  `docs/plans/revert/filesystem-surface/ostree-overlay-v3/README.md`.
- New crate target:
  `crates/erebor-runtime-filesystem` does not exist yet.
- Phase 0 runtime surface module root:
  `crates/erebor-runtime-session/src/surfaces.rs` only exposes `terminal`.
- Phase 0 implemented session surface definitions:
  `browser_cdp` and `terminal`.
- Phase 0 generic file interception contract existed in
  `crates/erebor-runtime-core/src/interception/file.rs`.
- Phase 0 IPC proto had file operation families in
  `crates/erebor-runtime-ipc/proto/erebor/runtime/ipc/v1/control.proto`.
- Phase 0 runtime broker could route file operations to a registered
  `FileOperationSurfaceHandler`.
- Phase 0 Linux ptrace guard behavior was process-exec focused and only traced
  `execve`/`execveat`.
- Phase 0 guard-side IPC mirror did not encode operation family or
  `FileOperation` payloads.
- Phase 0 event contract had `ActionKind::FileRead` and
  `ActionKind::FileWrite`, but no `ExecutionSurface::Filesystem`,
  `ActionKind::FileOpen`, or `ActionKind::FileMutation`.
- Phase 0 policy matcher supported `surface`, `action`, `target_contains`,
  `payload_contains`, `command_contains`, and `risk_at_least`. It did not
  support `path_contains`.
- Phase 0 Linux-host runner options supported environment, wrapper program, and
  adopt pid only. They did not support a mount namespace or bind-mount plan.

Line-count snapshot from Phase 0:

```text
80    crates/erebor-runtime-core/src/interception/file.rs
161   crates/erebor-runtime-ipc/proto/erebor/runtime/ipc/v1/control.proto
236   crates/erebor-runtime-session/src/runtime_interception_broker/handlers.rs
1489  crates/erebor-runtime-session/src/os/linux/process_guard.rs
623   crates/erebor-runtime-session/src/os/linux/process_guard/ipc.rs
545   crates/erebor-runtime-session/src/os/linux/process_guard/interception.rs
4438  crates/erebor-runtime-core/src/config.rs
274   crates/erebor-runtime-core/src/runtime.rs
526   crates/erebor-runtime-core/src/session.rs
202   crates/erebor-runtime-session/src/session_side_resources.rs
```

Existing tests to extend or split:

- `crates/erebor-runtime-session/src/runtime_interception_broker/tests.rs`
  already has synthetic file-operation routing coverage.
- `crates/erebor-runtime-session/tests/linux_process_guard.rs` compiles and
  runs standalone process guard unit tests.
- `crates/erebor-runtime-session/tests/linux_host_runner.rs` has real
  Linux-host process guard lifecycle tests, but is already over 300 lines and
  should not receive the new filesystem lifecycle cases.

## Current Phase Status

Phase 1 made filesystem a configured surface and added the first
`erebor-runtime-filesystem` crate.

Phase 2 added the session filesystem file-operation handler and registered it
with the runtime interception broker when the filesystem surface is enabled.
The handler owns filesystem policy evaluation for synthetic `file_open`,
`file_read`, and `file_mutation` requests, writes filesystem audit records, and
keeps missing-handler file operations fail-closed.

Phase 3 added real Linux `open`/`openat`/`openat2` syscall routing to the
filesystem handler. The corrective coverage pass after Phase 4 now proves both
real `file_read` denial with `cat secret.txt` and real `file_mutation` denial
with shell redirection to `settings.json`. Both paths write filesystem audit
evidence with resolved device/inode identity when available.

Phase 4 added filesystem session storage and mount-plan paths under the
prepared session directory. The original Phase 4 probe initialized an empty
OSTree repo; after Phase 7, successful sessions now checkpoint on finish, so
the current carry-forward lifecycle assertion checks the expected checkpoint
refs, no `base` ref, and no copied host file in session storage.

Phase 5 added the Linux OverlayFS session view. The filesystem crate now
prepares a Linux overlay wrapper that runs the agent command in a private mount
namespace, exposes the overlay merged path at `session_path`, masks the raw
`host_path` inside the namespace, and keeps the governed command non-root. The
gated lifecycle probe proves writes land in `upperdir`, host files stay
unchanged before promotion, raw-host-path writes cannot bypass the overlay, and
denied mutations do not create upperdir changes.

Phase 6 added upperdir normalization and `erebor-layer.json`. Successful
sessions now normalize each configured volume after the governed runner exits
and before registry finish is reported as successful. The manifest records
create, replace, and delete operations discovered by walking `upperdir`, known
OverlayFS metadata sidecars, and fail-closed unsupported reasons. The gated
lifecycle probe proves real overlay replace/delete/create operations are
represented in the manifest without treating raw whiteout markers as content.

Phase 7 added OSTree checkpoint commits. Successful sessions now normalize the
upperdir, stage each volume layer, commit
`erebor/checkpoints/<session-id>/volumes/<volume-id>/layer`, and commit
`erebor/checkpoints/<session-id>/manifest` with `erebor-checkpoint.json`
referencing the layer refs. The lifecycle probe asserts the refs exist, no V3
`base` ref exists, the layer commit contains `erebor-layer.json`, and normalized
file content can be read from the layer commit.

Phase 8 added promotion preimages and rollback for the one-volume case.
Successful sessions now promote on finish when
`surfaces.filesystem.revert.promote_on_session_finish` is true. Promotion
commits preimage refs under `erebor/promotions/<session-id>/volumes/<volume-id>/preimage`,
commits a promotion manifest under `erebor/promotions/<session-id>/manifest`,
then applies the normalized layer to the host. Rollback is exposed as the
filesystem crate API `rollback_promotion(...)`; no transaction catalog or
operator rollback workflow exists yet. The lifecycle probe proves the host is
promoted and then restored for replace, delete, and create operations in the
one-volume case.

Phase 9 completed the first multi-volume Linux V3 implementation. The
promotion/checkpoint/rollback paths now have explicit crate-level coverage for
two writable volumes. The live lifecycle probe covers a governed Linux-host
session with:

- a denied filesystem mutation audited by the filesystem surface;
- allowed overlay mutations in `project` and `cache` volumes;
- checkpoint and promotion refs for both volumes;
- rollback restoring both host directories from committed preimage refs after
  local mutable promotion work is removed;
- a second multi-volume session where an unsupported preimage in `cache`
  blocks promotion before the already-captured `project` mutation reaches the
  host.

Phase 10 added the transaction/subtransaction catalog and rollback operator
workflow. Phase 11 hardened exact metadata and xattr restore semantics.
Phase 12 added safe opaque directory support by capturing hidden lower
subtrees before promotion.

Phase 13 added explicit preimage backend selection. The default
`ostree_bytes` backend preserves the existing bounded byte-copy behavior.
The `linux_reflink` backend uses Linux `FICLONE` for regular files whose
preimages would exceed the byte budget, stores retained CoW artifacts outside
the committed OSTree preimage tree, records artifact metadata in
`erebor-preimage.json`, and validates retained artifacts before apply and
rollback. If reflink is disabled, unsupported, or an artifact is lost/drifted,
the operation fails closed before mutating the host.

Phases 14, 15, and 16 are implemented. Phase 17 is the next follow-up gate:

- Phase 14 added retained artifact history plus explicit retention list/prune
  commands.
- Phase 15 added session-work transactions and config-driven `session_finish`
  autocommit.
- Phase 16 made backend expansion phases explicit before any `fuse-overlayfs`,
  Docker/OCI, Btrfs, ZFS, macOS, or Windows work starts.

## Target Ownership

Target code shape, subject to Phase 0 confirmation:

```text
crates/erebor-runtime-filesystem/
  Cargo.toml
  src/lib.rs
  src/config.rs
  src/handler.rs
  src/linux.rs
  src/linux/mounts.rs
  src/linux/runner.rs
  src/manifest.rs
  src/normalizer.rs
  src/ostree.rs
  src/promotion.rs
  src/storage.rs
  src/error.rs
  tests/

crates/erebor-runtime-core/src/config.rs
crates/erebor-runtime-core/src/config/filesystem_surface.rs
crates/erebor-runtime-core/src/interception/file.rs
crates/erebor-runtime-core/src/runtime.rs

crates/erebor-runtime-session/src/surfaces.rs
crates/erebor-runtime-session/src/surfaces/filesystem.rs
crates/erebor-runtime-session/src/surfaces/filesystem/
  tests.rs

crates/erebor-runtime-session/src/os/linux/process_guard.rs
crates/erebor-runtime-session/src/os/linux/process_guard/ipc.rs
crates/erebor-runtime-session/src/os/linux/process_guard/interception.rs

crates/erebor-runtime-session/tests/filesystem_surface_config.rs
crates/erebor-runtime-session/tests/filesystem_surface_lifecycle.rs
```

Keep code files under 300 lines. If a module wants to grow beyond that, split
it before adding behavior.

The filesystem domain implementation belongs in
`erebor-runtime-filesystem`. `erebor-runtime-session` should only wire session
lifecycle, broker registration, prepared session paths, and runner options to
that crate.

## Proposed Config Shape

The implemented config shape is:

```json
{
  "session": {
    "interception": {
      "enabled": true,
      "backend": "linux_ptrace",
      "operations": ["process_exec", "file_open", "file_read", "file_mutation"]
    }
  },
  "surfaces": {
    "terminal": { "enabled": true },
    "filesystem": {
      "enabled": true,
      "backend": { "kind": "linux_ostree_overlay" },
      "policies": [],
      "volumes": [
        {
          "id": "workspace",
          "host_path": "/tmp/erebor-fs-host/project",
          "session_path": "/tmp/erebor-session-workspace/project",
          "mode": "writable"
        }
      ],
      "revert": {
        "promote_on_session_finish": true,
        "retain_layers": true,
        "preimage_size_limit_bytes": 104857600
      }
    }
  }
}
```

The Linux-host runner must execute the agent inside a mount namespace where the
configured `session_path` sees the overlay `merged` path. The raw host path must
not be exposed as the mutable path inside the governed session. The session
registry path should stay outside governed volumes so `.erebor/sessions` is not
hidden by volume mounts or included in filesystem layer manifests.

## Non-Negotiables

- Do not implement this subplan until the user approves a phase.
- Implement only one approved phase at a time.
- Phase 0 is inventory and contract only. It may rewrite later phase files.
- After Phase 0, every phase must compile, pass tests, and run the lifecycle
  probe for the behavior implemented so far.
- Do not copy the whole allowed host tree into OSTree at session start.
- Do not discover changes by scanning the host tree.
- Do not discover changes by scanning the merged tree.
- Discover changed filesystem state only by walking OverlayFS `upperdir` after
  the agent is quiesced.
- Do not create an OSTree `base` ref for V3.
- Do not promote host changes unless rollback preimages have been captured and
  committed first.
- Do not claim exact rollback for paths whose preimage was not captured.
- Unsupported metadata, special files, unreadable preimages, or host drift must
  fail closed with audit evidence. Supported opaque OverlayFS markers must be
  represented as `opaque_replace`, not restored as host metadata.
- The terminal/ptrace backend may observe syscalls, but file policy decisions
  belong to the filesystem surface.
- Keep architecture decisions visible. If Phase 0 finds a better crate/module
  boundary, stop with analysis and let the user decide.

## Testing Contract

Each implementation phase must report:

- changed files
- exact behavior added
- unit tests added or updated
- crate-level integration tests added or updated
- lifecycle probe result from [`lifecycle-probe.md`](./lifecycle-probe.md)
- whether privileged Linux host requirements were met
- explicit `Done`, `Not done`, or `Blocked` state

Required automated checks before a phase is marked done:

```sh
cargo fmt
cargo check -p erebor-runtime-core --all-targets --all-features
cargo check -p erebor-runtime-session --all-targets --all-features
cargo test -p erebor-runtime-core --lib
cargo test -p erebor-runtime-session --lib
cargo test -p erebor-runtime-session --test linux_process_guard
cargo test -p erebor-runtime-session --test filesystem_surface_config
cargo test -p erebor-runtime-session --test filesystem_surface_lifecycle
EREBOR_REQUIRE_FILESYSTEM_LIFECYCLE=1 EREBOR_RUN_FILESYSTEM_OVERLAY_LIFECYCLE=1 cargo test -p erebor-runtime-session --test filesystem_surface_lifecycle linux_host::overlay_session_view -- --test-threads=1 --nocapture
EREBOR_REQUIRE_FILESYSTEM_LIFECYCLE=1 EREBOR_RUN_FILESYSTEM_OVERLAY_LIFECYCLE=1 cargo test -p erebor-runtime-session --test filesystem_surface_lifecycle linux_host::overlay_layer_manifest -- --test-threads=1 --nocapture
EREBOR_REQUIRE_FILESYSTEM_LIFECYCLE=1 EREBOR_RUN_FILESYSTEM_OVERLAY_LIFECYCLE=1 cargo test -p erebor-runtime-session --test filesystem_surface_lifecycle linux_host::overlay_promotion_rollback -- --test-threads=1 --nocapture
EREBOR_REQUIRE_FILESYSTEM_LIFECYCLE=1 EREBOR_RUN_FILESYSTEM_OVERLAY_LIFECYCLE=1 cargo test -p erebor-runtime-session --test filesystem_surface_lifecycle overlay_multivolume -- --test-threads=1 --nocapture
cargo test --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
git diff --check
```

If a test file does not exist yet for an early phase, the phase result must say
so directly instead of pretending it ran.

## Lifecycle Probe Contract

The lifecycle probe grows with the phases. It must eventually prove:

- a governed Linux-host session starts with terminal and filesystem surfaces
- file operation interception can deny a `cat`/`openat` path through the
  filesystem surface
- the agent writes through the overlay merged view
- the raw host path stays unchanged until promotion
- checkpoint layer refs exist in OSTree
- no V3 `base` ref exists
- promotion captures preimages before mutating host files
- rollback restores replaced, deleted, and created paths
- rollback uses committed promotion/preimage refs, not mutable local
  `work/promotions` files
- multi-volume promotion blocks before host mutation if any volume cannot
  capture a required preimage
- audit artifacts identify filesystem decisions and revert outcomes
- transactions/subtransactions can be listed, shown, renamed, and rolled back
  through the approved operator workflow
- supported metadata is restored exactly
- opaque directory promotion/rollback works or fails closed according to Phase
  12
- large-file promotion either uses the reflink CoW backend or blocks, once
  Phase 13 exists
- retention/prune operations preserve rollback refs
- session-work transactions and config-driven autocommit commits are quiesced
  and reversible according to Phase 15

## Phase Index

- [Live Lifecycle Probe](./lifecycle-probe.md)
- [Phase 0: Current-Code Inventory And Contract](./phase-0-current-code-inventory-and-contract.md)
- [Phase 1: Core Config And Surface Registration](./phase-1-core-config-and-surface-registration.md)
- [Phase 2: Filesystem Handler And Policy Decisions](./phase-2-filesystem-handler-and-policy-decisions.md)
- [Phase 3: Linux File Syscall Interception](./phase-3-linux-file-syscall-interception.md)
- [Phase 4: Linux Volume Storage And Mount Plan](./phase-4-linux-volume-storage-and-mount-plan.md)
- [Phase 4a: Corrective Coverage And Plan Hardening](./phase-4a-corrective-coverage-and-plan-hardening.md)
- [Phase 5: Mount-Capable Overlay Session View](./phase-5-rootful-overlay-session-view.md)
- [Phase 6: Upperdir Normalizer And Layer Manifest](./phase-6-upperdir-normalizer-and-layer-manifest.md)
- [Phase 7: OSTree Checkpoint Commits](./phase-7-ostree-checkpoint-commits.md)
- [Phase 8: Promotion Preimage And Rollback](./phase-8-promotion-preimage-and-rollback.md)
- [Phase 9: Multi-Volume Lifecycle And Full Verification](./phase-9-multivolume-lifecycle-and-full-verification.md)
- [Phase 10: Transaction Catalog And Rollback Operator Workflow](./phase-10-rollback-cli-and-operator-workflow.md)
- [Phase 11: Exact Metadata And Xattr Restore](./phase-11-exact-metadata-and-xattr-restore.md)
- [Phase 12: Opaque Directory Support](./phase-12-opaque-directory-support.md)
- [Phase 13: Large File And CoW Preimages](./phase-13-large-file-and-cow-preimages.md)
- [Phase 14: Retention History And Garbage Collection](./phase-14-retention-history-and-garbage-collection.md)
- [Phase 15: Session Work Transactions And Autocommit](./phase-15-session-work-transactions-and-autocommit.md)
- [Phase 16: Backend Expansion Decision Gates](./phase-16-backend-expansion-decision-gates.md)
- [Phase 17: Rootless Fuse-OverlayFS Backend](./phase-17-rootless-fuse-overlayfs-backend.md)
- [Phase 18: Docker And OCI Filesystem Revert](./phase-18-docker-oci-filesystem-revert.md)
- [Phase 19: Btrfs Snapshot Backend](./phase-19-btrfs-snapshot-backend.md)
- [Phase 20: ZFS Snapshot Backend](./phase-20-zfs-snapshot-backend.md)
- [Phase 21: macOS Filesystem Surface Extraction](./phase-21-macos-filesystem-surface.md)
- [Phase 22: Windows Filesystem Surface Equivalent](./phase-22-windows-filesystem-surface.md)

## Decisions Recorded Before Phase 0

- The implementation uses a new `erebor-runtime-filesystem` crate.
- File read/open/mutation decisions include resolved device/inode metadata
  where the Linux backend can safely obtain it. Path remains part of the
  request and audit payload, but policy and audit can also reason about the
  resolved `(dev, ino)` identity.
- The first Linux backend uses direct kernel OverlayFS owned by Erebor, not
  Docker's `overlay2` storage-driver layout.
- Opaque directories are supported as explicit `opaque_replace` layer
  operations. The hidden lower subtree is captured under the existing volume
  preimage ref before host mutation.
- Session-work transactions and autocommit are implemented for explicit
  CLI/API commits and the config-driven `session_finish` boundary. Timer-based
  or periodic transaction commits are not part of the approved direction.
- Rootless `fuse-overlayfs` is not required for this first implementation.
- Docker/OCI filesystem revert is not in this first implementation. Phase 0
  should record whether a later Docker backend uses Docker volume/storage-driver
  behavior or the same Erebor-owned overlay model inside/around containers.

## Decisions Recorded After Phase 10

- Phase 11 should support every Linux metadata class that the selected OSTree
  repo mode can faithfully commit and check out on the host. Erebor should not
  invent a narrower metadata whitelist when OSTree can preserve the class.
  Metadata that OSTree or the current process privileges cannot restore exactly
  must fail closed with an auditable reason.
- Phase 12 implements an explicit opaque directory manifest shape and bounded
  hidden-subtree preimage behavior. Opaque preimages are grouped under the
  existing volume preimage ref.
- Phase 13 uses reflink as the first CoW preimage backend. Btrfs/ZFS snapshot
  backends are not part of Phase 13.
- Phase 14 does not add retention policy defaults. Retention and pruning are
  operator actions exposed through CLI commands and, later, GUI operations.
- Phase 14 implemented explicit retention list/prune APIs and CLI commands.
  Safe prune refuses applied, partially restored, or corrupt targets and only
  allows restored transaction/subtransaction artifacts to be pruned.
- Phase 15 autocommit is configured in runtime config. Explicit commit,
  rollback, list, show, and rename operations follow the Phase 10 CLI/API
  style.
- Phase 16 originally kept backend expansion work in this plan. A subsequent
  user decision extracted the native macOS surface into the sibling
  `macos-fskit-overlay-v1-implementation` plan while retaining Phase 21 as a
  navigation and contract-reuse pointer.
- Phase 16 created backend-expansion phases for rootless `fuse-overlayfs`,
  Docker/OCI, Btrfs, ZFS, macOS, and Windows. Each remains disabled and
  unimplemented until its own phase is explicitly approved; macOS approval and
  implementation now follow the sibling plan's phases.

## Stop Point

Stop after Phase 16. Wait for explicit user approval before implementing
Phase 17 or any later backend-expansion follow-up.
