# Phase 7.5.1: Native Graph Storage

Store subjects, relationships, and findings as native rows so authorized reads
and joins do not decode every graph snapshot. Parent: [7.5](README.md).

## Intended end state

AnalysisStore keeps one authoritative graph representation. Existing snapshot
and export APIs reconstruct the same values, identities, and ordering. Historical
finding references and notification obligations remain valid.

## Implementation flow

```text
GraphAndFindingOwner submits a validated graph result
  -> AnalysisStore encodes its versioned rows outside the write transaction
  -> AnalysisStore commits rows, references, progress, revisions, and quota together
  -> an identical retry returns the original receipt
  -> a changed retry under the same operation key fails

Caller requests findings or a query input
  -> the reader authorizes the complete selected versions before row selection
  -> the reader selects native rows under cancellation and byte limits
  -> the reader closes durable handles before SQL evaluation

Store opens with retained snapshot bodies
  -> migration checks the format and available temporary storage
  -> migration converts every retained version and verifies reconstruction
  -> AnalysisStore retires old bodies only after the checked conversion commits
  -> a failed conversion preserves the original store
```

## Scope and owners

The [seven storage TODOs](README.md#native-graph-storage-improvement-todos)
are the complete change checklist. Keep them in that location. AnalysisStore
owns encoding, transactions, migration, quotas, and reconstruction.
`graph/read.rs` owns selected finding reads; query extraction and the existing
VTab expose detached rows. Share row encoding and reconstruction across these
paths. Preserve `GraphAndFindingOwner` validation and graph construction.

## Acceptance and verification

- Complete all seven linked TODOs with focused Rust tests. Include latest
  version per source window, latest finding across windows, and removal of
  findings omitted by a replacement window.
- Verify typed joins, whole-version authorization, sensitivity, exact retries,
  rollback, reopen, quota reconstruction, and backup/restore.
- Verify failed migration preserves originals and successful migration keeps
  every historical result reference and snapshot value.
- Run the existing `graph-notification` lightweight case before its paired
  physical case. Run the final shared Rust procedure after source changes.

## Exclusions and stop point

Add no graph database, custom DuckDB type, second snapshot body, or replacement
VTab. The retained graph conversion is the user-approved exception to the parent
plan's fresh-store rule. It does not authorize unrelated format migrations.
Stop before SDK implementation.

## Result

**Done.** All seven storage TODOs pass their required checks in the primary
checkout. SDK, package lifecycle, runtime,
and algorithm migration work remain outside this result.

Historical plan expansion record: the storage checklist is retained from the
existing plan. No new implementation or storage qualification is recorded by
that plan expansion.

The primary checkout contains the qualified storage implementation. The
[native row owner](../../../../../crates/araphor-data/src/analysis/graph_rows/mod.rs)
stores subjects, relationships, and findings. Existing graph APIs use native
reads and checked reconstruction. The
[migration owner](../../../../../crates/araphor-data/src/analysis/graph_migration.rs)
converts retained versions in one transaction. Current focused checks pass 32
native tests, one schema-permission test, and ten graph query tests. Read the
source record and logs in `/tmp/araphor-native-storage.j8wJmf`.
The existing dense notification case passes with 257 findings across 33 source
windows. Read `dense-split.log`. Earlier reads reached a deadline or failed
native allocation. The current reader separates key selection, version
validation, and bounded payload reads. The memory limit remains 64 MiB and the
deadline remains one second. The full lightweight case and Clippy pass on the
recorded source. Read `lightweight-qualified/result.json`,
`lightweight-qualified.log`, and `clippy-final.log` in the same evidence
directory. The earlier paired physical Rust case passes on Linux kernel
`6.8.0-142-generic` and Kubernetes `v1.35.5+k3s1`. The protected read returns
errno 13 and zero bytes. The benign read returns 558 bytes. Graph references,
replay, reopen, and notification transitions pass. Read `physical/result.json`,
`physical-test.log`, and the resource and VM cleanup receipts. The earlier shared
Rust procedure fails the existing
`control_graph_context_and_result_bounds_keep_required_progress` test with
`AnalysisReadDeadline`. It reports 378 passed, one failed, and three ignored
Araphor tests. Later workspace tests do not run. Read `rust-ci-qualified.log`.
The focused test also reproduces the failure. The unbounded finding read
measured an unused JSON output limit. It now skips that byte accounting. The
existing large-context test passes after the correction.

The corrected source record is `source-state-complete2.json` in the same
evidence directory. It covers 1,330 files with SHA-256
`ea747ca3d8ea338a09b5e515874aa6fffa9134ab29a68489d311dbb354b06479`.
The large-context test, three finding checks, and workspace Clippy pass.
Read `context-budget-fix.log`, `finding-budget-focused.log`, and
`clippy-budget-fix.log`. The full lightweight case also passes. Its result is
`lightweight-complete2/result.json`, with SHA-256
`000b84e17774832bb9a314b22c3731f85747b29eaea2efcd0e747f8af57e4862`.
The fresh physical pair passes on x86_64, Linux `6.8.0-142-generic`, and K3s
`v1.35.5+k3s1`. Its result is `physical-complete2/result.json`, with SHA-256
`608d890301bc5ee4cfa80eee62ade2d5b12f6787682559ee0ba7284bf581c1c7`.
The protected read returns errno 13 and zero bytes. The benign read returns
558 bytes. Replay, reopen, and notification contracts pass. The graph decision
is `COVERAGE_INSUFFICIENT`, equal to the lightweight `initial-health-missing`
case. It retains ancestry, policy, source-coverage, and activation limits.
One target obligation is acknowledged; 255 ambient obligations remain.
The owned resources and VM are removed. Read `physical-complete2-invocation.json`,
`physical-complete2-provenance.json`, `physical-complete2/resource-absence.json`,
and `physical-complete2/vm-cleanup.json` in the same evidence directory.
The final shared Rust procedure returns zero after the last source edit:

```sh
rtk proxy env RUST_TEST_THREADS=1 CARGO_BUILD_JOBS=2 bash .github/scripts/verify-rust-ci.sh
```

Formatting, workspace check, strict Clippy, and all workspace tests pass. The
Araphor Data suite reports 379 passed, zero failed, and three ignored. Read
`rust-ci-complete2.log`, with SHA-256
`3e24ef3f8341e606a48adf26ac9b23bc093c14574b8b59f37b3d5047ce802ee2`.
Read `rust-ci-complete2-receipt.json` for the command, exit code, and source check.
The final covered source matches `source-state-complete2.json`. Ignored tests
are not counted as passes; the physical case above ran separately.
This proof does not qualify the full incident, cross-node behavior, provider
effects, or performance.

## End scope and example

Complete when graph writes, selected reads, joins, snapshot reconstruction,
migration, and backup/restore use the native rows and pass the linked checklist.
Existing graph APIs and historical references retain their meaning. Package
authoring and execution are not added by this storage change.

Example at completion: source-window result `R1` contains finding `F1`; its
replacement `R2` omits `F1`. The current finding query excludes `F1`. An exact
historical read of `R1` still returns it, and a notification that references
`R1` remains readable after migration and restore.
