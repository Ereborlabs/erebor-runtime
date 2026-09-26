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
   Read processor progress, accepted cursor, missing ranges and revision from
   one snapshot. Report lag separately from expired or lost input. Keep a
   missing-coverage flag after an optional processor resumes. Report physical
   storage capacity separately from retention health. A capacity sample does
   not promise admission for a later write or for a tenant's logical quota.
   Read exact recovery gaps in source-scoped pages of at most 256 ranges.
   These health reads must not advance receipts or processor progress.
   Charge each retained row 256 logical bytes plus its variable payload and
   key bytes. Use 8 GiB per store and 2 GiB per tenant by default. Ordinary
   writes leave one quarter of each limit for result and maintenance commits.
   At 90 percent of the ordinary limit, bounded retention removes eligible
   raw rows. Required progress and witness checks still apply. Limit each
   context, result, and coverage family to 1,024 revisions per tenant and
   4,096 per store. Charge unique pinned raw/context rows to a separate
   512-MiB tenant witness limit. Check these bounds before transaction commit.
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
have component tests. `data-store-recovery` passed 23 checks through the
production mTLS service with an explicitly selected data owner. The case proves
lost-ACK replay, owner restart, exact frames and coverage, required-progress
protection, optional expiry, an exact witness, tenant-scoped result reads,
backup after expiry, and Partial recovery from a stale backup.
The result is `/tmp/araphor-retention.NH24lk/recovery/result.json`: cursor 4,
retained floor 2, one retained witness plus one new event, and backup revision 9.
After checkpoint, the database uses 8,663,040 bytes and its native WAL is absent.
This small fixture does not qualify physical disk reuse.
`cargo test -p araphor-data --lib` passed 19 tests with two ignored.
These tests include tenant and corrupt-body checks in
`analysis_store_result_progress`.
`bash .github/scripts/verify-rust-ci.sh` passed for commit `658c16c3`:
workspace formatting, compilation, strict Clippy, and workspace tests.
This result does not cover subsequent startup or recovery-validation changes.
Tests use temporary databases; no retention call ran on an existing deployment.
Default startup now opens `evidence_directory/analysis` and shares its data
handle with intake. Policy/trust/rollout persistence stays in ControlStore.
Old accepted, pending, or coverage state prevents activation before data-store
creation. Data recovery failure leaves evidence and coverage unavailable;
the policy service keeps its durable owner. There is no old-writer fallback.
The default process no longer starts the superseded discovery projection or
accepts its configuration. Its replacement belongs to Phase 7.4.
The `data-store-startup` command passed 16 checks. Its result is
`/tmp/araphor-integrity.K3NdoS/startup/result.json`. The case checks fresh intake,
restart, exact frames, policy persistence, old-receipt refusal, and policy RPCs
under invalid receipt, unsupported schema, missing table, and corrupt file failures. All four
failures stop evidence and coverage ACK while Node retains its pending input.
The `data-store-recovery` command passed its 19 checks again at
`/tmp/araphor-integrity.K3NdoS/recovery/result.json`.
`analysis_startup_is_independent` passed. The workspace run for `5c86f3d`
failed in the old SQLite 50,000-atom replay test with `OperationInterrupted`
while decoding atom samples. The recovery-validation runs passed that test,
but failed the startup case during data-store reopen. Concurrent server cleanup
could still hold the data lease after the policy lease became available.
Restart rejects missing tables and columns without creating them. It also
checks source bindings, receipts, retained/expired range counts, coverage,
frame/result/context digests, processor progress, tenant-scoped references,
pending bounds, and relation revisions. Restore uses the same checks.
The data-owner suite passed 21 tests with two ignored, including 16 corruption
cases in `analysis_rejects_broken_state`.
Control now uses shared evidence/coverage admission: eight active or queued
groups per process and two per tenant. Tenant UUID bytes select the quota.
Idle streams hold no permit. A permit covers group assembly, blocking validation,
and commit. Control removes the separate 64-message stream queue. A group has
at most 4 MiB of framed data and 4,096 records. An incomplete group flushes after
50 ms; it does not wait indefinitely for a tail marker or stream closure.
Node uses the same group bounds. Component tests passed the 4,096/4,097-record
boundary and proved that rejection does not advance the receipt or revision.
Qualification restart now waits at most five seconds for the data lease.
Other open failures return immediately. AnalysisStore releases its lease only
after the database connection closes. Startup and recovery passed with that
wait. The four current data e2e tests passed, including the open-stream deadline
case and the lease/error case. The semaphore quota test passed. The final
workspace gate for `be877df` passed formatting, compilation, and strict Clippy.
It failed the unchanged SQLite 50,000-atom test with `OperationInterrupted`
during atom-sample decoding. The concurrent Mithril e2e suite passed 110 tests;
247 physical or explicit qualification tests remained ignored.
AnalysisStore now reads at most one batch of retained digests and uses the
pinned DuckDB appender for new rows. Appender flush, receipt progress, and
revision updates remain in one transaction. No per-record SQL insert or lookup
remains in this path. `analysis_store_bulk_rollback` checks a conflict at record
4,096, unchanged receipt/revision and notification state, retry, and reopen.
The 13 data-store tests passed. The existing 4,096-record Control test passed
in 0.52 seconds; the earlier per-record path took 31.46 seconds in this workspace.
These single runs are not a throughput qualification. The final workspace gate
passed for the appender change at `666d1c99`. Physical disk capacity remains unqualified.
Control now runs one retention task with its existing service and clock.
Each one-second pass checks at most 16 sources. Each source transaction removes
at most 256 eligible rows with one parameterized DELETE. Raw byte pressure uses
the tenant total, not a separate allowance for each source. Required progress
and exact witness checks remain in the transaction. A pass checkpoints after
deletion. A failed pass stops evidence and coverage intake until a later pass
and checkpoint succeed. Policy RPCs continue.
`data_retention` in Control configuration accepts `raw_max_age_ns` and
`raw_max_bytes`. Both values must be positive. Defaults are 86,400,000,000,000
nanoseconds and 2,147,483,648 bytes. The age limit applies to accepted required
input on the affected source. The byte reservation counts protected raw input
across that tenant's sources. This reservation is not a complete data-disk quota.
An over-budget batch rolls back and returns ResourceExhausted. Exact retries
remain valid at the bound. An old pending gap alone does not age-block gap repair.
The 16 `analysis_store_` tests passed, including paged sweeps, failure/recovery,
required-input limits, and tenant-scoped protected bytes. The mTLS startup and
recovery tests passed. Recovery now checks automatic expiry, required-age
backpressure, policy RPC availability, and retry after processor progress.
The startup command passed 16 checks at
`/tmp/araphor-retention.NH24lk/startup/result.json`. The sweep-failure test also
holds a native read transaction across deletion. Intake stays unavailable while
that transaction blocks checkpointing, including a retry with no rows to remove.
Intake recovers only after the read transaction ends and checkpoint succeeds.
The final workspace gate passed for retention at `f2c2db33`. It passed
formatting, compilation, strict Clippy, and workspace tests. The data crate
passed 25 tests with two ignored. The Mithril e2e suite passed 110 tests with
247 physical or explicit qualification tests ignored.
AnalysisStore now bounds all connection admission, including direct processor
and maintenance calls. One writer permits eight queued operations. Two private
readers permit 16 active or queued reads in total. Excess work returns
AnalysisBusy; Control maps that error to ResourceExhausted. Connection guards
release permits on return and error. Evidence pages and source-status reads use
one database snapshot for all of their statements. Fixed single-statement reads
also use the private readers. No database handle crosses the public data API.
Checkpoint and backup hold the writer and wait for read guards to close.
Readers can run during normal writes. No reader survives a public method return.
The current data crate passed 27 tests with two ignored, including the exact
16-read cap, writer queue saturation, and snapshot/maintenance checks. All four
data e2e tests passed. `data_backed_intake_acks_only_the_analysis_commit` passed.
The final workspace gate passed for `d806c2dd`: formatting, compilation,
strict Clippy, and all workspace tests.
Storage admission now checks the data directory and available filesystem bytes
under the writer lock. `data_storage` accepts `disk_max_bytes` (8 GiB by
default) and `policy_reserve_bytes` (256 MiB by default). Ordinary writes stop
256 MiB below the file budget. They also require the policy reserve, a 256-MiB
write allowance, and one quarter of the configured disk budget as free space.
The directory scan visits at most 4,096 entries. It counts each file's larger
logical or allocated size. Separate fields report allocated and available bytes.
The check includes native WAL and temporary files below the data directory.
Backups outside that directory have a separate destination-space check; they
are not charged to the directory total.
Retention, checkpoint, and processor catch-up retain access above the ordinary
file limit while the policy reserve and write allowance remain available.
Exact durable retries do not require ordinary write capacity. New evidence and
coverage do. Rejection returns ResourceExhausted without a new receipt or ACK.
DuckDB uses a 128-MiB memory target, two threads, a 64-MiB WAL checkpoint
threshold, and a 128-MiB temporary-directory limit. These are native settings,
not an operating-system memory cap or a measured recovery reserve.
The 20 `analysis_store_` tests passed. The capacity test checks exact admission
boundaries, a sparse temporary quota file, unchanged receipts on rejection,
checkpoint access, and retry after capacity returns. All five data e2e tests
passed. `data_capacity_retry` uses mTLS and an impossible free-space reserve;
Node keeps the rejected batch, policy RPCs work, and a restart with normal
limits permits the same batch. These tests use temporary stores, not an
existing deployment. The final workspace gate passed formatting, compilation,
strict Clippy, and all 29 enabled data-crate tests; two tests are ignored.
That workspace run failed at the capacity test's second startup assertion.
The concurrent rerun exposed a held data lease. A duplicated descriptor could
retain the lock after the owner closed its descriptor. AnalysisLease now
explicitly unlocks after native connection closure. The acquiring process ID
prevents a child guard from unlocking an active parent. This is the existing
ControlStore lease rule. The assertion retains the exact startup error.
Logical quotas now cover all twelve tenant-owned DuckDB relations. Each row
has a 256-byte charge plus its variable payload and key bytes. The native
aggregate runs in the same transaction as the mutation. No cached ledger or
schema migration is used. Physical file accounting remains separate.
`data_storage` also accepts `logical_max_bytes`, `tenant_max_bytes`, and
`witness_max_bytes`. Defaults are 8 GiB, 2 GiB, and 512 MiB. Omitted fields use
their defaults; unknown fields fail configuration validation.
Ordinary writes leave one quarter of the logical budgets for result commits
and maintenance. Native quota checks precede receipt/revision commit and ACK.
Context, result, and coverage families have separate 1,024-tenant and
4,096-store revision limits. Shared exact raw or context dependencies count
once toward the witness budget. Reference records still count toward the
overall logical budget. An unchanged retry does not add a charge.
Retention checks logical usage in its existing bounded pass. At 90 percent
of the ordinary logical limit, eligible raw data can expire before its age
limit. Required input and live witnesses remain protected. Retention does
not require spare logical space; each removed row releases at least its
replacement expiry-record charge. Native physical maintenance checks remain.
The 24 `analysis_store_` tests passed, including tenant/global limits,
unchanged commits after rejection, restart, exact revision boundaries,
shared raw/context witnesses, reserved processor space, and quota-driven
cleanup after witness expiry, and duplicate-descriptor lease release.
`data_capacity_retry` now checks both an
impossible physical reserve and a one-byte tenant quota through mTLS.
After the lease fix, the full concurrent Mithril e2e suite passed 111 tests;
247 physical or explicit qualification tests remained ignored.
The final workspace gate for `ae7d342c` passed formatting, compilation, strict
Clippy, and 33 data-crate tests with two ignored. It failed the unchanged
SQLite 50,000-atom test with `OperationInterrupted` during atom-sample decoding.
Control passed 194 tests, failed one, and ignored two.
Fixed health reads now return processor lag, expired input, recovery loss,
and historical missing coverage from one snapshot. Storage health separates
retention failure from sampled physical intake and maintenance capacity.
Neither capacity field checks a tenant's logical quota or reserves space.
Exact recovery-gap reads return at most 256 source-scoped ranges. A stale
restore retains those ranges across restart without creating a source receipt.
No read advances an ACK or processor progress. The Node protocol does not
provide an authenticated purge-floor report; this change adds no cursor skip.
The 26 `analysis_store_` tests and all five data e2e tests passed. The recovery
case now passes 26 checks, including required lag, optional missing coverage,
and recovery-gap restart. These runs use temporary stores and synthetic input.
The final workspace gate for the health changes is running. The aggregate
scan cost still needs load qualification; passing small fixtures does not
prove the declared intake budget. Physical capacity and trace reservation,
processor runtime-failure reporting, Control context projection, crash injection, removal of
the remaining old library writer, and physical disk reuse remain open.
Production enablement is not qualified.
