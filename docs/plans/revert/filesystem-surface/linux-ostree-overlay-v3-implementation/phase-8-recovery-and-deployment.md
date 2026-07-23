# Phase 8: Recovery Deployment Retention And Upgrade

Status: Proposed. Blocked on Phase 7 and explicit implementation approval.

## Purpose

Make installation, crash recovery, reboot, upgrade, retention, prune, and
uninstall operationally safe.

## Scope

- Add a documented install and activation workflow for the signed native app,
  FSKit extension, and Endpoint Security dependency selected in Phase 0.
- Expose activation/readiness state through the runtime without scraping
  private databases or invoking undocumented activation paths.
- Add native/Rust protocol compatibility negotiation and refuse incompatible
  major versions.
- Reconcile prepared, mounted, frozen, promoting, rolling-back, corrupt, and
  retained session journals after runtime crash or reboot.
- Verify mount table, extension version, session descriptor, backing roots,
  process-tree liveness, and promotion journal before choosing recovery.
- Never auto-resume governed execution after reboot. Require a healthy remount,
  new epoch, and explicit session recovery action.
- Define recover, abandon, force-unmount, and preserve-for-forensics operator
  actions in the filesystem domain API; CLI commands remain thin renderers.
- Drain and unmount active sessions before native extension upgrade or
  deactivation.
- Retain and prune APFS lower/preimage clones using existing transaction state,
  liveness, identity, and safe-prune rules.
- Refuse prune for active, applied, partially restored, corrupt, referenced, or
  unverified artifacts.
- Make partial install, user-disabled extension, revoked signing identity,
  lost entitlement, full disk, disconnected external volume, and missing
  backing store typed and auditable states.
- Provide a safe uninstall sequence that refuses to remove active extensions or
  required retained artifacts without an explicit destructive operator action.

## Recovery Rules

| Observed state | Required behavior |
| --- | --- |
| Clean mounted session and healthy journal | Report; do not duplicate mount or epoch. |
| Mount absent, prepared upper/meta clean | Offer explicit remount/recover after validation. |
| Mount absent after unclean writer loss | Seal as recoverable, run journal/fsck validation, do not promote automatically. |
| Promotion journal incomplete | Reuse existing promotion recovery state; never infer success from host content alone. |
| Backing identity missing or drifted | Mark blocked/corrupt and preserve evidence. |
| Extension/guard version mismatch | Deny admission and require drain/upgrade. |
| Reboot revealed original host path | Treat it as ungoverned host state; do not claim session overlay remains active. |

## Tests

- State-machine tests cover every recovery table row and idempotent retries.
- Real-Mac fault tests kill the governed process, Rust runtime, native host, and
  FSKit extension independently during prepare, mutation, freeze, checkpoint,
  promotion, and rollback.
- Reboot fixture verifies original-path visibility, no automatic session resume,
  journal reconciliation, explicit remount, and a new epoch.
- Upgrade tests cover compatible patch/minor versions, incompatible major
  versions, active-session drain, rollback to previous bundle, and user-disabled
  extension.
- Retention tests cover inventory, liveness, safe prune, lost clone, external
  volume removal, and disk-pressure errors.

## Checkpoint

```sh
cargo fmt
cargo test -p erebor-runtime-filesystem --all-targets --all-features
cargo test -p erebor-runtime-session --all-targets --all-features
xcodebuild -project integrations/macos/erebor-filesystem-host/EreborFilesystemHost.xcodeproj \
  -scheme EreborFilesystemHost test
EREBOR_REQUIRE_FILESYSTEM_MACOS_LIFECYCLE=1 \
  cargo test -p erebor-runtime-e2e --test macos_filesystem_lifecycle \
  recovery_and_retention -- --test-threads=1 --nocapture
cargo test --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
git diff --check
```

## Acceptance

- Every persistent state has an explicit recovery or fail-closed outcome.
- Reboot, crash, upgrade, and extension disablement cannot silently bypass
  admission.
- Retention and prune protect active or rollback-required artifacts.
- Install/activation requirements are honest and use documented mechanisms.

## Stop Point

Stop after recovery, upgrade, and retention verification. Wait for explicit
approval before Phase 9.

## Phase 8 Result

State: Not started.

