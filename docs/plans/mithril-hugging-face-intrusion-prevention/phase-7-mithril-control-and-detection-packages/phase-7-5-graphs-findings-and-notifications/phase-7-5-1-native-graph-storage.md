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

**Not done.** The storage checklist is retained from the existing plan. No new
implementation or storage qualification is recorded by this plan expansion.

## End scope and example

Complete when graph writes, selected reads, joins, snapshot reconstruction,
migration, and backup/restore use the native rows and pass the linked checklist.
Existing graph APIs and historical references retain their meaning. Package
authoring and execution are not added by this storage change.

Example at completion: source-window result `R1` contains finding `F1`; its
replacement `R2` omits `F1`. The current finding query excludes `F1`. An exact
historical read of `R1` still returns it, and a notification that references
`R1` remains readable after migration and restore.
