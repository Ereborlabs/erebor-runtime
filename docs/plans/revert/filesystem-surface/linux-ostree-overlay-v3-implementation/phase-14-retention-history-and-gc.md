# Phase 14: Retention History And Garbage Collection

Status: Complete. Implemented and verified.

## Purpose

Make retained filesystem layers and promotion history operationally manageable.

The config already has `retain_layers`, and Phase 9 leaves committed refs in
the per-session OSTree repo. This phase defines how users inspect, keep, and
prune those artifacts without breaking rollback guarantees.

## Recorded Decision

Phase 14 does not add retention policy defaults or automatic retention policy
configuration. Retention and pruning are explicit operator actions exposed
through CLI commands in this phase and later through GUI operations.

Prune commands may still enforce safety rules. They are not a policy engine;
they are guardrails that prevent deleting artifacts required for rollback or
audit unless a later approved design adds an explicit force shape.

## Scope

- Define retained artifact lifecycle for:
  - checkpoint layer refs
  - checkpoint manifests
  - promotion preimage refs
  - promotion manifests
  - rollback checkout work directories
  - local journals and locks
- Add inspection APIs and CLI commands to list filesystem retained artifacts
  for a session, including transactions, subtransactions, checkpoint refs,
  promotion/preimage refs, rollback state, and audit identifiers.
- Add explicit prune APIs and CLI commands where the operator selects the
  artifact or transaction/subtransaction handle to prune.
- Add safe prune operation that refuses to delete refs required for an
  unrolled-back applied promotion unless forced by an explicit approved shape.
- Run `ostree prune` only when it cannot remove still-required rollback refs.
- Add audit records for prune/list operations where applicable.
- Add tests for safe prune, protected refs, already-rolled-back refs, and
  missing/corrupt refs.

## Non-Goals

- Do not change promotion or rollback semantics.
- Do not implement cross-session shared OSTree repos.
- Do not add automatic pruning or retention defaults.
- Do not remove artifacts silently at session finish.

## Lifecycle Probe Growth

Extend the live probe with retention operations:

- run two promoted sessions in one workspace;
- list retained filesystem transactions, subtransactions, checkpoints, and
  promotions;
- prove both sessions' rollback refs exist;
- prune only explicitly selected artifacts that safety checks allow;
- verify protected rollback refs remain;
- run rollback after prune for a protected session;
- verify `ostree refs --list` and `ostree prune` output before/after.

## Checkpoint

```sh
cargo fmt
cargo check -p erebor-runtime-filesystem --all-targets --all-features
cargo check -p erebor-runtime-cli --all-targets --all-features
cargo test -p erebor-runtime-filesystem --lib retention
cargo test -p erebor-runtime-cli --all-targets --all-features retention
cargo test -p erebor-runtime-session --test filesystem_surface_lifecycle retention -- --test-threads=1 --nocapture
PATH=/tmp/erebor-ostree-deb.JOW1pw/root/usr/bin:$PATH \
  EREBOR_REQUIRE_FILESYSTEM_LIFECYCLE=1 \
  EREBOR_RUN_FILESYSTEM_OVERLAY_LIFECYCLE=1 \
  cargo test -p erebor-runtime-session --test filesystem_surface_lifecycle retention -- --test-threads=1 --nocapture
cargo test --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
git diff --check
```

## Required Evidence

- Approved list/prune command and crate API shape.
- Operator examples for listing retained artifacts and pruning one explicit
  transaction/subtransaction artifact.
- Ref protection rules.
- Before/after `ostree refs --list` examples.
- Prune audit examples.
- Lifecycle rollback-after-prune result.

## Acceptance

- Users can inspect retained filesystem revert artifacts.
- Users can explicitly prune selected retained artifacts.
- Safe prune cannot remove refs needed for an unapplied rollback.
- Rollback remains possible for protected promotions after pruning.

## Stop Point

Stop after Phase 14 verification. Session-work transactions and autocommit
remain separate.

## Phase 14 Result

State: Done.

Implemented:

- Added filesystem retention domain APIs:
  - `FilesystemRetentionInventory::load`
  - `FilesystemRetentionPrune::prune`
- Added explicit operator CLI commands:
  - `erebor filesystem retention list --registry <registry> --session <session> [--format text|json]`
  - `erebor filesystem retention prune --registry <registry> --session <session> <target> [--format text|json]`
- Text CLI output renders tables for transaction/subtransaction state,
  retained OSTree refs, local artifacts, and prune results. JSON remains
  available through `--format json` for GUI/API reuse.
- Retention inventory lists:
  - checkpoint manifest refs;
  - checkpoint layer refs;
  - promotion manifest refs;
  - promotion preimage refs;
  - promotion workdirs;
  - rollback checkout dirs;
  - CoW preimage artifact dirs;
  - local retention, transaction catalog, and promotion lock artifacts.
- Safe prune supports transaction handles, subtransaction handles, names, and
  raw retained `erebor/...` refs.
- Safe prune refuses applied, partially restored, or corrupt targets. Applied
  transaction refs are protected for rollback/audit. Restored transactions may
  prune all retained refs and prunable local workdirs. Restored
  subtransactions prune only their promotion preimage ref and local CoW artifact
  so remaining transaction catalog/history stays readable.
- Retention list/prune events are appended to
  `filesystem/retention/erebor-retention.jsonl`.
- The OSTree adapter now resolves refs to commit checksums before
  `checkout_at`, which avoids libostree binding panics and hardens existing
  promotion/catalog/rollback checkouts.
- The OSTree adapter now supports retained ref deletion and libostree prune.
- Follow-up ownership cleanup moved the changed filesystem CLI path onto
  explicit owners:
  - `FilesystemCommandOwner`, `TransactionCommandOwner`, and
    `RetentionCommandOwner` own command execution flow;
  - `FilesystemStorageOpener` owns registry/session filesystem storage
    loading;
  - `TransactionRenderer`, `RetentionRenderer`, and `RenderSupport` own CLI
    rendering behavior;
  - retention lifecycle/unit-test setup helpers were folded into scenario
    owners instead of loose helper functions.

Operator examples:

```sh
erebor filesystem retention list \
  --registry .erebor/sessions \
  --session session-filesystem-retention-protected

erebor filesystem retention prune \
  --registry .erebor/sessions \
  --session session-filesystem-retention-restored \
  tx@{0}

erebor filesystem retention prune \
  --registry .erebor/sessions \
  --session session-filesystem-retention-restored \
  tx@{0}.sub@{0}
```

Test coverage added:

- `promotion::tests::retention::retention_inventory_lists_refs_and_writes_audit_event`
- `promotion::tests::retention::retention_prune_refuses_applied_transaction`
- `promotion::tests::retention::retention_prunes_restored_transaction_refs_and_workdirs`
- `promotion::tests::retention::retention_prunes_restored_subtransaction_preimage_without_layer_ref`
- `promotion::tests::retention::retention_inventory_reports_missing_expected_ref`
- `promotion::tests::retention::retention_inventory_reports_corrupt_promotion_manifest`
- `cli::tests::accepts_filesystem_retention_commands`
- `linux_host::retention::linux_host_retention_cli_prunes_restored_session_without_breaking_protected_rollback`

Lifecycle evidence:

- The live retention probe runs two promoted sessions in one workspace.
- It lists retained refs through the new CLI.
- It proves both sessions' checkpoint and promotion refs exist with
  `ostree refs --list`.
- It verifies pruning the still-applied session is rejected as protected.
- It rolls back the first session, prunes that restored transaction, verifies
  the restored session's refs are removed, and records retention prune audit.
- It then rolls back the protected second session after the prune path has run.
- It executes `ostree prune --no-prune` before and after the safe prune check.

Verification run:

```sh
cargo fmt
cargo check -p erebor-runtime-filesystem --all-targets --all-features
cargo check -p erebor-runtime-cli --all-targets --all-features
cargo test -p erebor-runtime-filesystem --lib retention -- --nocapture
cargo test -p erebor-runtime-cli --all-targets --all-features retention -- --nocapture
cargo test -p erebor-runtime-session --test filesystem_surface_lifecycle retention -- --test-threads=1 --nocapture
PATH=/tmp/erebor-ostree-deb.JOW1pw/root/usr/bin:$PATH \
  EREBOR_REQUIRE_FILESYSTEM_LIFECYCLE=1 \
  EREBOR_RUN_FILESYSTEM_OVERLAY_LIFECYCLE=1 \
  cargo test -p erebor-runtime-session --test filesystem_surface_lifecycle retention -- --test-threads=1 --nocapture
cargo test --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
git diff --check
```

Verification notes:

- The first real lifecycle run inside the sandbox failed at broker startup with
  `Operation not permitted`; rerunning the same lifecycle outside the sandbox
  passed.
- The retention inventory loader remains above the soft 300-line guideline
  because it is a single cohesive owner for ref discovery, manifest checkout,
  missing/corrupt artifact classification, and local-artifact inventory. The
  pure model and CLI rendering were split into focused submodules to keep
  unrelated ownership out of larger files.
- After the ownership cleanup, the changed production filesystem CLI/retention
  modules have no loose top-level helper functions; behavior is on command,
  storage, render, inventory, prune, resolver, and journal owners.
