# Phase 9: Real-Mac Compatibility Performance And Release Gate

Status: Proposed. Blocked on Phase 8 and explicit implementation approval.

## Purpose

Prove that the strict FSKit overlay is correct and usable for real developer
workloads before enabling it as a supported macOS backend.

## Scope

- Run the full lifecycle probe on the user-approved supported macOS versions,
  stable Xcode/SDK versions, and Apple Silicon hardware classes; include Intel
  only if it remains in the support policy.
- Cover case-insensitive and case-sensitive APFS and internal/external APFS
  volumes selected for support.
- Verify explicit failure on non-APFS, read-only, cloud-placeholder, network,
  removable/disconnected, and unsupported encrypted-volume cases not selected
  for V1.
- Exercise representative workloads:
  - Git status/diff/checkout/merge/rebase and large worktrees;
  - Rust `cargo check`, test, target-directory churn, and incremental builds;
  - Node/npm/pnpm/yarn install and rename-heavy package trees where supported;
  - shell tools, archives, compilers, language servers, and file watchers;
  - VS Code or the selected IDE launched by Erebor, including extension hosts;
  - a generic CLI agent and child process tree, without Codex-specific
    assumptions.
- Measure mount/start clone latency, lookup/stat/readdir latency, sequential and
  random I/O, small-file create/unlink, rename, copy-up, build duration, watcher
  behavior, memory, CPU, disk allocation, checkpoint, promotion, rollback, and
  recovery.
- Compare against direct APFS and record the user-approved budgets. Do not set a
  performance claim before collecting the baseline.
- Run concurrency, fault-injection, repeated mount/unmount, disk pressure,
  extension restart, guard restart, and long-running soak tests.
- Audit security posture: signing and entitlements, protocol authentication,
  backing permissions, path races, stale epochs, protected roots, log secrets,
  and failure defaults.
- Publish the exact compatibility matrix, known unsupported semantics,
  activation requirements, and operational recovery guide.
- Enable the backend as supported only for the proven matrix. Do not make it the
  universal default or enable unsupported fallback modes.

## Release Gates

- Full operation/metadata/bypass matrix passes without required-test skips.
- Full checkpoint/promotion/rollback and multi-volume lifecycle passes.
- Crash, reboot, upgrade, and retention matrix passes.
- No acknowledged mutation is lost across required synchronize/remount cases.
- Host is unchanged before promotion in every success case.
- Unsupported metadata and host drift block before mutation.
- No governed process accesses original/backing paths in bypass probes.
- Performance budgets are explicitly approved from measured data.
- Activation/install model is approved for every advertised deployment profile.
- Workspace tests and clippy are clean on Linux and macOS.

## Checkpoint

```sh
xcodebuild -project integrations/macos/erebor-filesystem-host/EreborFilesystemHost.xcodeproj \
  -scheme EreborFilesystemHost test
EREBOR_REQUIRE_FILESYSTEM_MACOS_LIFECYCLE=1 \
  cargo test -p erebor-runtime-e2e --test macos_filesystem_lifecycle \
  -- --test-threads=1 --nocapture
cargo fmt
cargo test --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
git diff --check
```

The release job must attach the lifecycle report, benchmark comparison,
mount/guard/extension versions, and test environment identity.

## Acceptance

- The backend is enabled only on the exact proven matrix.
- Real developer workloads behave correctly through the merged view.
- Performance and operational costs are measured and approved.
- Published limitations make no claim of transparent adoption for existing
  processes or unsupported filesystems.

## Stop Point

Stop after presenting the release evidence. Wait for explicit approval before
changing defaults, widening the OS/filesystem matrix, or starting a fallback
backend.

## Phase 9 Result

State: Not started.

