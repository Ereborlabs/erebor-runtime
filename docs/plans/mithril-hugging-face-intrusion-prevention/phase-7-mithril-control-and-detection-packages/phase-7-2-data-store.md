# Phase 7.2: Shared Data Store, Intake, And Retention

Make DuckDB the durable home for retained data and analysis.

## Intended end state

Existing authenticated Node delivery commits directly through AnalysisStore.
ACK, replay, retention, backup and restart have one data transaction contract.
Policy/control state keeps its existing persistence. Discovery-disabled startup
still accepts data. Entry: 7.1. Status: **Not done** for this design.

## Implementation flow

```text
Control starts
  -> AnalysisStore obtains the exclusive data-directory lease
  -> DuckDB recovers its WAL and validates schema, receipts and references
  -> writer publishes committed relation revisions
  -> intake becomes ready independently of discovery algorithms

Node sends an authenticated batch
  -> EvidenceIntakeOwner validates source and reserves bounded capacity
  -> AnalysisStore commits events, context, coverage, receipt and revisions
  -> Control acknowledges the durable contiguous source position
  -> readers and configured processors can consume the committed input

Retention reaches an age or byte boundary
  -> EvidenceRetentionOwner checks required progress and witness references
  -> one transaction removes eligible rows and advances retained floors
  -> checkpoint attempts physical reclamation
  -> insufficient capacity rejects new diagnostics and backpressures intake

Store recovery fails
  -> data ACK and dependent operations stop with an explicit error
  -> Node retains unacknowledged input under its existing quota
  -> installed enforcement and independent policy/control owners continue
```

## Changes in implementation order

1. Complete `AnalysisStore::{open,commit_evidence,read_page,commit_result,
   retain,backup,restore}` in `crates/araphor-data/src/analysis/`.
   Names are proposed public owner methods. Use the schema, single-writer,
   batching and durability contract in engine-design.md. No new data service
   is required for embedded operation.
2. Adapt Control `evidence.rs`, `service.rs`, `server.rs`, `config.rs`
   and `main.rs` to pass the same store handle. Validate before queuing.
   Keep authentication and ACK meaning at EvidenceIntakeOwner. Preserve
   `receive_group`/coverage callers; do not move policy state into DuckDB.
3. Record tenant/source/session binding, source cursor, kernel sequence,
   intake time, original bytes and coverage. Insert context versions by
   exact identity/digest. Enforce uniqueness and bounded pending gaps.
   Keep AlreadyAcceptedExpired distinct from a verified retained duplicate.
4. Publish a Tokio watch revision only after commit. The transaction updates
   affected relation revisions, including coverage/context and retention.
   Expose fixed prepared bounded reads: 256 records or 1 MiB per page.
   Return explicit range expiry. Never hold a reader during client I/O.
5. Implement `EvidenceRetentionOwner` in `araphor-data` with the fixed
   optional/required classes in engine-design.md.
   Discovery progress does not pin raw data. Required security progress and
   bounded exact witness references constrain expiry. Lag is a health warning;
   backpressure starts at the protected age/byte or physical capacity bound.
   Commit result, references and progress together; compare expected progress.
   Return Conflict on a competing commit. Commit optional missing ranges before
   resuming from a newer retained floor. External readers cannot pin input.
   Required-package retirement is explicit and authorized.
6. Separate health for intake storage, each processor and trace capacity.
   Database corruption stops data ACK. Supervise analysis failures without
   exiting Control's policy service. Enforce per-tenant and global queue/disk
   quotas. Query-worker health and failure isolation belong to 7.3.
7. Implement checkpoint, backup and restore through the data owner. Measure
   physical disk reuse after DELETE. Reserve maintenance space before work.
   Stop writes when reclamation fails; never unlink the native WAL. Recovery
   after an older backup reports source ranges no longer retained on Node.
8. Activate the data owner in a clean development deployment. Control opens
   a private AnalysisStore with the current schema and selects it as the only
   evidence writer before Node intake starts. Reject an unsupported schema
   or a Control store that still has accepted evidence. Start each Node with
   a new source identity so an old ACK or cursor cannot enter the new store.
   There is no old-store import, schema migration, dual write, or rollback
   path. Backup and restore remain required for data written after activation.
9. Keep policy/trust/rollout state outside this conversion. Reconcile their
   committed versions into context with idempotent reads; unavailable context
   stays Pending or Unknown. Do not hold both stores' locks or claim a shared
   transaction. Remove the superseded event write path only after cutover
   tests prove every production caller uses AnalysisStore.

## Unit tests and end-to-end proof

Add `analysis_store_`, `control_retention_` and `analysis_startup_` tests:
commit/rollback, post-commit lost ACK, conflicting duplicates, out-of-order
batches, explicit gaps, checked overflow, cross-tenant references, required
processor stall, review pins, retirement, expiry, late context, WAL recovery,
disk full, unsupported schema and rejected old evidence state.

Add `data-store-recovery` to the discovery e2e binary. Through the production
mTLS service, submit data, lose ACK, resend, restart, process and expire input.
This is the production counterpart to the offline `storage-contract` case in
7.1. Reopen AnalysisStore and require the same source identity, receipt,
coverage and exact counts. Require unchanged policy state and explicit expired
reads. Stop after every transaction boundary. Record batch latency, durable
ACK latency, checkpoint time and actual database, WAL and temporary bytes. Run
backup/restore after raw expiry; retained findings/profile fixtures and
references must survive. A stale backup with already-purged Node input must
report Partial recovery.

Extend `data-store-recovery` with a controllable clock and 24-hour retention.
Disable optional discovery for eight hours, then two days. Require continued
intake and bounded AnalysisStore reads, exact retained replay, explicit expired
gaps and no double counts. A required detector stall raises health immediately.
One-hour lag alone does not pause intake. Reach its protected age/byte bound
and require backpressure without deleting protected input. Keep a review witness through
optional expiry; no source-wide pin is permitted.

Add `data-store-startup` with an empty development Control evidence state.
Require one selected writer, a fresh Node source, unchanged policy state,
and explicit refusal of old evidence receipts or an unsupported schema.
Do not require a live Kubernetes cluster for either case. Rerun both before
the physical storage/partition case in the existing mithril-e2e harness.

```sh
cargo test -p mithril-control
cargo test -p araphor-data
cargo run -p mithril-e2e --bin mithril_discovery_test -- --case data-store-recovery --output-directory /tmp/araphor-data-recovery
cargo run -p mithril-e2e --bin mithril_discovery_test -- --case data-store-startup --output-directory /tmp/araphor-data-startup
bash .github/scripts/verify-rust-ci.sh
```

## Completion gate

Pass DE-STORE, DE-INDEX, DE-RETENTION, DE-BOOT, DE-GAP, DE-TENANT and DE-LIMIT.
Record nonzero case counts, actual disk usage, source receipts, backup revision
and retained floors. No public SQL, discovery algorithm or remote transport is
required here. Stop before enabling a data path whose recovery case fails.

## Implementation result

**Not done.** AnalysisStore has a writer, bounded reads, exact context
versions, processor results and references, guarded raw expiry, backup and
restore. Source bindings and an explicit data-backed EvidenceIntakeOwner path
have component tests. `data-store-recovery` passed 19 checks through the
production mTLS service with an explicitly selected data owner. The case proves
lost-ACK replay, owner restart, exact frames and coverage, required-progress
protection, optional expiry, an exact witness, tenant-scoped result reads,
backup after expiry, and Partial recovery from a stale backup.
The result is `/tmp/araphor-live-store.M3z6hl/recovery/result.json`: cursor 3,
retained floor 2, one retained witness, and backup revision 8.
`cargo test -p araphor-data --lib` passed 19 tests with two ignored.
These tests include tenant and corrupt-body checks in
`analysis_store_result_progress`.
`bash .github/scripts/verify-rust-ci.sh` passed for commit `658c16c3`:
workspace formatting, compilation, strict Clippy, and workspace tests.
This result does not cover subsequent uncommitted startup changes.
Tests use temporary databases; no retention call ran on an existing deployment.
Default startup still selects the old writer. Fresh-store activation, bounded
admission, capacity and processor health, Control context projection, crash
injection, the startup case, and physical disk reuse remain open.
Do not enable the new default data path yet.
