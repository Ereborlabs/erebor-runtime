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
8. Implement a bounded offline upgrade under the exclusive lease. Pause
   intake and analysis; preserve a backup. Import accepted evidence and
   canonical referenced analysis/trace records by stable identity and digest.
   Do not treat unchecked index rows as evidence. Validate counts, references
   and receipt floors before selecting the new store. Persist an upgrade
   marker; retries resume or fail without dual writes. Preserve old input
   until validation and operator cleanup. After new ACKs, rollback requires
   recovery, not reopening a stale backup. Reject unsupported downgrades.
9. Keep policy/trust/rollout state outside this conversion. Reconcile their
   committed versions into context with idempotent reads; unavailable context
   stays Pending or Unknown. Do not hold both stores' locks or claim a shared
   transaction. Remove the superseded event write path only after cutover
   tests prove every production caller uses AnalysisStore.

## Unit tests and end-to-end proof

Add `analysis_store_`, `control_retention_` and `analysis_upgrade_` tests:
commit/rollback, post-commit lost ACK, conflicting duplicates, out-of-order
batches, explicit gaps, checked overflow, cross-tenant references, required
processor stall, review pins, retirement, expiry, late context, WAL recovery,
disk full, unsupported schema and interrupted upgrade.

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

Add `data-store-upgrade` using retained-format fixture bytes. Validate all
imported IDs/digests, preserve policy bytes, and restart at each upgrade step.
Do not require a live Kubernetes cluster for either case. Rerun both before
the physical storage/partition case in the existing mithril-e2e harness.

```sh
cargo test -p mithril-control
cargo test -p araphor-data
cargo run -p mithril-e2e --bin mithril_discovery_test -- --case data-store-recovery --output-directory /tmp/araphor-data-recovery
cargo run -p mithril-e2e --bin mithril_discovery_test -- --case data-store-upgrade --output-directory /tmp/araphor-data-upgrade
bash .github/scripts/verify-rust-ci.sh
```

## Completion gate

Pass DE-STORE, DE-INDEX, DE-RETENTION, DE-BOOT, DE-GAP, DE-TENANT and DE-LIMIT.
Record nonzero case counts, actual disk usage, source receipts, backup revision
and retained floors. No public SQL, discovery algorithm or remote transport is
required here. Stop before enabling a data path whose recovery case fails.

## Implementation result

**Not done.** The working tree contains an AnalysisStore writer, bounded reads,
exact context versions, processor results and references, guarded raw expiry,
optional gap records, backup, restore, and an analysis-schema upgrade. The retention owner
deletes only eligible raw rows. Required progress and live exact witnesses
protect rows. The tests use temporary databases. No retention call ran on an
existing deployment.

`cargo test -p araphor-data --lib` passed 19 tests with two ignored.
`RUST_TEST_THREADS=1 cargo test -p mithril-control --lib` passed 193 tests with
two ignored. Strict Clippy passed for `araphor-data` and `mithril-control` on all
targets. The repository Rust CI procedure passed before the offline import
change and must be rerun for the current source. The parallel run at that time
failed one existing 500 ms Control reconnect timing assertion. That test passed
alone and in the serialized run. The offline `storage-contract` case passed nine
assertions. That case
does not use production intake. The old Control store now exports bounded,
length- and checksum-checked original frame pages; its focused test passed.
An offline copy now moves accepted original frames and coverage into AnalysisStore.
Per-source markers preserve old retained floors, leave old intake time unknown,
and check exact digests after restart. A component test passed with an expired
old prefix, retained frame, coverage report, and unchanged Control commit index.
The current Control intake still writes its chunked store. A complete offline
upgrade, single-writer cutover, capacity admission,
context projection from Control, data-store recovery/upgrade cases, and physical disk reuse
remain unverified. Do not enable the new data path yet.
