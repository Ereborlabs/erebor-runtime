# Phase 7.1: Contracts And DuckDB Proof

Freeze the data and investigation contracts before live storage changes.

## Intended end state

A recorded manifest produces deterministic atoms and an exact native preview.
The selected DuckDB binding passes durability, bounded extraction, cancellation
and isolated-query checks. The corpus and expected outcomes are executable.
Entry: Mithril 6.2 and 6.3 contracts. Status: **Not done** for this design.

## Implementation flow

```text
Engineer submits a bounded recorded manifest
  -> DiscoveryInputManifestV1 validates identity, bytes, context and coverage
  -> DiscoveryOwner::derive_recorded produces exact atoms and unresolved counts
  -> existing compiler/simulator checks the fixture-supplied candidate
  -> mithril-e2e compares canonical output with the frozen oracle

Engineer runs storage proof
  -> AnalysisStore commits evidence and receipt progress in one transaction
  -> process stops before or after commit
  -> reopen returns the complete old or new state
  -> isolated query worker receives only authorized bounded inputs
  -> forbidden SQL or worker failure returns a typed failure
```

## Changes in implementation order

1. Reuse Control `src/discovery/model.rs`, `recorded.rs`, `context.rs`,
   `investigation.rs` and current exact derivation. Freeze the records in
   engine-design.md: source key, kernel sequence, coverage revision, context,
   profiles, receipts, assessments, suggestions and publication references.
   Canonical digests exclude database positions, run IDs and model output.
2. Add `crates/araphor-data` as a library with the first concrete
   `AnalysisStore` module under `src/analysis/`. It must not depend on
   `mithril-control`. Control keeps source authentication and passes the exact
   validated source identity, framed records, and coverage to the data owner.
   The data owner computes the durable source key. Pin one DuckDB Rust binding/build
   in Cargo and record its version in the fixture manifest. Use one writer,
   explicit transactions and local filesystem checks. No storage trait or
   production SQLite/DuckDB switch is required.
3. Specify how existing `EvidenceIntakeOwner::receive_group` and
   `receive_coverage` map to one data transaction. Preserve authenticated
   identity, contiguous ACK, gap and retransmission rules. No generic public
   Ingest RPC or producer SDK is added. The input is the existing Node
   contract; only its durable destination changes in 7.2.
   After Control authenticates and validates a group, pass the exact
   `EvidenceIntakeIdentityV1` and `ValidatedEvidenceBatchV1` with CPU, cursor
   range, shared framed bytes, and frame ends to AnalysisStore. The store
   computes the source key and commits new records with its source receipt.
   `Accepted` means the submitted end cursor is contiguous and durable;
   `Pending` means a gap remains. Control issues only the durable contiguous
   ACK. For coverage, pass the validated encoded report, CPU and revision as
   `ValidatedCoverageV1`; commit it with the coverage receipt before ACK.
4. Freeze `StorePosition(commit_revision, ordinal)`, store UUID/recovery epoch,
   relation revisions, processor progress and retained floors. Keep source
   cursors distinct. Freeze query `append`, `replace`, checkpoint, health,
   terminal and error frame schemas. A trace terminal result remains separate
   from gRPC stream closure.
5. Qualify sqlparser-rs with DuckDbDialect and the closed binder. Pin the
   parser/engine pair; parsing alone is not semantic validation. Compare
   optimized extraction with full authorized-input evaluation in DuckDB.
   Test aliases, timestamp parameters, AND/OR, CTE reuse, joins, nested
   predicates, nulls and exact window endpoints. Prove untrusted SQL runs only
   in a no-network, no-credential, OS-limited worker with in-memory DuckDB.
   Use the isolation contract in engine-design.md, not a SELECT-prefix check.
6. Extend `crates/mithril-e2e/fixtures/discovery/manifest.json` and `pilot.json`.
   Pin source, context, policy, coverage, expected rows and proof kind.
   Include repeats, rare valid work, poisoned baseline, deployment drift,
   credential denial, missing provider evidence and malicious context text.
   Freeze workload/time train/validation/holdout splits before AI experiments.
7. Keep existing `offline-exact` and add `storage-contract` to
   `src/bin/mithril_discovery_test.rs`. Implement cases in the existing
   `src/discovery/` family. Call public owners; do not build private database
   transactions in the e2e harness.

## Unit tests and end-to-end proof

Unit tests beside the owners must check schema N/N+1 bounds, duplicate and
conflicting identity, count conservation, absent bindings, canonical ordering,
unknown runtime conditions, source continuity, transaction rollback and
forbidden SQL. Test crash after commit but before ACK in a separate process.

The `storage-contract` e2e case must commit through the production intake
adapter, reopen through AnalysisStore, and read the same identity, receipt,
coverage and counts. Kill the query worker; intake and policy state remain
valid. Record query plans, native RSS, temporary bytes, batch latency, ACK
latency and checkpoint time. No benchmark result follows from choosing DuckDB.

Commands after the new case is implemented:

```sh
cargo test -p araphor-data
cargo test -p mithril-control
cargo run -p mithril-e2e --bin mithril_discovery_test -- --case offline-exact --output-directory /tmp/araphor-offline
cargo run -p mithril-e2e --bin mithril_discovery_test -- --case storage-contract --output-directory /tmp/araphor-storage-contract
bash .github/scripts/verify-rust-ci.sh
```

## Completion gate

Pass DE-IDENTITY, DE-AGGREGATE, DE-REPLAY, DE-PREVIEW, DE-QUERY and DE-STORE
for this recorded slice with nonzero test counts and result digests. A binding
that fails durability or isolation blocks live integration. Do not substitute
another backend without approval. No production intake cutover, public API,
model runtime, or policy publication is part of this phase.

## Implementation result

**Not done.** The current code puts AnalysisStore and SQL admission in
`araphor-data`. Control re-exports the unchanged source identity and intake
limits. The store has atomic event, coverage and receipt commits, and a
separate-process post-commit crash test. The offline SQL proof covers admitted
read shapes, safe fixed lower bounds and a manually run isolated worker.
The durable position, progress and follow-frame fields are frozen in
engine-design.md. The pilot fixture freezes distinct workload IDs and
non-overlapping time windows for its train, tune, held-out and forbidden cases.
Control still uses its existing live evidence store; no Node ACK path changed.

At code revision `ce5f672`, the workspace gate passed 11 `araphor-data` tests
with 2 ignored. The tests reject schema versions 0 and 2 for the version-1
store and cancel a long-running in-memory DuckDB query. This proves binding
cancellation, not QueryOwner deadline wiring. The isolated worker test passed
with `--ignored`. The pilot corpus test passed with distinct workload/time
splits. The `offline-exact` e2e case passed at
`/tmp/araphor-corpus.2xySiD/offline-exact/result.json`; it reports zero live
lookups and no production authority. The repository Rust CI script passed
formatting, workspace check, strict lint and workspace all-targets tests on
that code revision.

The `storage-contract` e2e case, a production intake-path proof, bounded
extraction measurements and executable schema/stream contract checks are not
complete. Resolve whether that e2e case belongs before or with the live
intake cutover before changing the intake owner or the completion gate.
