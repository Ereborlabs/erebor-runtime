# Phase 0: Signed Platform Feasibility And Deployment Gates

Status: Proposed. Pending explicit implementation approval.

## Purpose

Prove the native boundary on a signed real Mac before production architecture
depends on it. This is a go/no-go phase, not a paper inventory.

## Scope

- Record the current source-tree owners named in the root plan and update later
  phases if they have moved.
- Build a minimal signed containing app plus FSKit app extension using the
  latest stable Xcode and SDK selected for the test.
- Mount a path-backed test resource through supported FSKit APIs and prove
  ordinary POSIX tools can use it.
- Prove a custom two-tree lookup can return upper content before lower content;
  the spike need not implement the full union filesystem.
- Test both candidate topologies:
  - a mount over a non-empty workspace path after all users are quiesced;
  - a stable Erebor session mount path.
- Prove clean mount, synchronize, unmount, extension crash, host-process crash,
  app update, and reboot observations.
- Verify the extension can access only a signed/security-scoped session
  resource and cannot be tricked into opening an arbitrary backing path.
- Measure APFS same-volume clone behavior for representative directory trees
  and verify that source and clone diverge copy-on-write.
- Run the current `OstreeRepository` and checkpoint path on macOS. Test
  dependency packaging, repository initialization, commit/ref/read/checkout,
  crash consistency, and the full macOS metadata fixture; do not accept the
  presence of a developer-installed command as a distributable solution.
- Run open, read, write, create, delete, rename, symlink, hardlink, xattr, ACL,
  resource-fork, mmap, sparse-file, and preallocation probes to inventory the
  stable FSKit API surface and any semantic gaps.
- With the real Endpoint Security extension, subscribe to relevant AUTH and
  NOTIFY file events and prove:
  - events still arrive for I/O through the FSKit mount;
  - the message identifies the originating test process rather than only the
    FSKit extension;
  - decisions can distinguish merged-mount access from direct backing/original
    access;
  - cache invalidation and event deadlines are understood.
- Test documented activation and update paths on an unmanaged Mac and on the
  available MDM-managed profile. Record every user/admin interaction.
- Inventory only stable APIs. Record beta Handler/DataCache results separately
  and do not make them a V1 dependency.

## Required Decisions From Evidence

Phase 0 presents, but does not make, these product decisions:

- minimum supported macOS version and stable Xcode/SDK;
- exclusive path takeover, stable session path, or both;
- whether one-time File System Extension user enablement is acceptable;
- whether strict mode requires managed Endpoint Security deployment;
- XPC or authenticated local-socket control protocol between Rust and the
  signed native host;
- packaged OSTree, a macOS-native content-addressed store, or committed APFS
  clone artifacts as the checkpoint backend while preserving logical refs and
  transaction semantics;
- native project placement and build integration;
- whether FSKit's stable API is sufficient or V1 must wait for a beta API to
  become final.

## Hard Go/No-Go Gates

Do not start Phase 1 unless all required strict-profile gates pass:

- the supported stable SDK can implement the required file operations;
- the extension can mount and unmount reliably through documented APIs;
- the selected topology cannot expose the lower/upper/meta roots as aliases;
- Endpoint Security preserves usable originating-process attribution for I/O
  through the mount;
- direct original/backing access can be denied without denying FSKit's own
  legitimate backing I/O;
- crash and reboot behavior fails closed at runtime admission;
- activation requirements are acceptable for the selected deployment profile;
- APFS clone creation and divergence preserve every metadata class required by
  the proposed exactness contract, or unsupported classes are enumerated.
- one checkpoint backend has proven packaging, durability, metadata,
  crash-recovery, reference, retention, and prune semantics on macOS.

If a gate fails, stop with evidence and options. Do not substitute macFUSE,
NFS, File Provider, a full managed copy, or a VM without explicit user approval.

## Deliverables

- A retained production candidate or real e2e fixture, not an abandoned demo.
- `phase-0-result.md` evidence or a result section in this file containing:
  - Mac hardware and OS build;
  - Xcode and SDK versions;
  - Team ID/signing and entitlements used, without secrets;
  - activation steps and prompts;
  - mount table and filesystem identity evidence;
  - Endpoint Security event matrix;
  - FSKit operation/metadata matrix;
  - crash/update/reboot results;
  - clone correctness and timing;
  - OSTree/checkpoint-store portability and metadata results;
  - explicit pass/fail for every hard gate.
- Rewritten later phase files if the native boundary differs from this draft.

## Checkpoint

The exact scheme names are finalized by the phase. The minimum shape is:

```sh
xcodebuild -project integrations/macos/erebor-filesystem-host/EreborFilesystemHost.xcodeproj \
  -scheme EreborFilesystemHost test
cargo test -p erebor-runtime-filesystem --all-targets --all-features
cargo test -p erebor-runtime-e2e --test macos_filesystem_fskit_probe \
  -- --test-threads=1 --nocapture
cargo fmt
cargo clippy --workspace --all-targets --all-features -- -D warnings
git diff --check
```

The real-Mac e2e probe must be required by an environment gate and must fail,
not skip, when the release job declares that gate.

## Acceptance

- Every hard gate has real signed-Mac evidence.
- Unsupported and uncertain behaviors are explicit.
- The user has selected the supported OS/SDK, activation profile, control
  protocol, default mount topology, and checkpoint backend.
- No production implementation phase has started prematurely.

## Stop Point

Stop after presenting the evidence and decisions. Wait for explicit approval
before Phase 1.

## Phase 0 Result

State: Not started.
