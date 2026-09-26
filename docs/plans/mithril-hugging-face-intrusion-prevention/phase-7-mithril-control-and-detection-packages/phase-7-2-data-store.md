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
   Limit the SQL cursor range to the first cursor plus 256, or the earlier
   accepted or expiry boundary. Use saturating addition. This range contains
   at most 256 returned records and one look-ahead record. Keep the look-ahead
   continuity check; a missing accepted cursor is an error, not end of input.
   Return explicit range expiry. Never hold a reader during client I/O.
   End a retained page before the next expired interval. Return that interval's
   first cursor as `next_cursor`; a read at that cursor returns explicit expiry.
   A later gap must not hide an earlier retained witness. An unexplained missing
   row still fails the read.
5. Implement `EvidenceRetentionOwner` in `araphor-data` with the fixed
   optional/required classes in engine-design.md.
   Discovery progress does not pin raw data. Required security progress and
   bounded exact witness references constrain expiry. Lag is a health warning;
   backpressure starts at the protected age/byte or physical capacity bound.
   Commit result, references and progress together; compare expected progress.
   Return Conflict on a competing commit. Commit optional missing ranges before
   resuming from a newer retained floor. External readers cannot pin input.
   Required-package retirement is explicit and authorized.
   Control applies at most 32 explicit `data_retirements` from its trusted
   startup configuration before it admits Node data. Each request names the
   exact processor, method version, tenant/source identity, change ID, reason,
   expected consumed cursor, and accepted cutoff. Require an allowed Node and
   tenant. Compare both cursors in the data transaction. Record the change,
   cutoff, and unprocessed range with the retired state. Keep consumed progress
   unchanged. A matching retry returns the original commit revision; a changed
   retry conflicts. A retired scope cannot restart by registration. A new
   method version needs its own registration. Never remove exact witness pins
   as part of retirement. A request conflict stops data startup, not the
   independent policy service. No public retirement RPC is added in this phase.
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
   Write managed backups only as `.duckdb` files directly in the private
   `AnalysisStore/backups` directory. Create that directory through the owner.
   Count complete and incomplete copies in the existing data-file budget.
   Before copying, reserve the database size, one quarter of that size, and
   4,096 manifest bytes against ordinary file and free-space admission. Reserve
   two file entries in the bounded directory scan. Reserve one more entry when
   the backup directory is absent. Keep all existing copies unchanged
   on rejection or failure. Do not add automatic backup deletion. Operators can
   copy a completed database and its manifest outside the managed directory;
   restore accepts that external copy. External operator copies are not managed
   data-store usage.
   Stop writes when reclamation fails; never unlink the native WAL. Recovery
   after an older backup reports source ranges no longer retained on Node.
   Add `NodeEvidence.ReportFloor` to the existing Node mTLS service. Each
   request carries the current session and one source's boot ID, source ID,
   source epoch, and durable acknowledged cursor. This cursor is the last
   record excluded from Node replay, not the first retained record. Node walks
   its ordered WAL sources at one report per second, including empty sources.
   Restart the walk on reconnect and after its last source. Advance the walk
   only after a successful report. Hold no WAL lock during network I/O.
   Control checks current mTLS, session, and trust, then resolves the source's
   original durable session. Use the existing shared intake admission limit.
   Commit missing ranges through `AnalysisStore::record_recovery_floor`.
   Retry is idempotent. The reply accepts the report; it is not an evidence
   ACK and cannot advance Node truncation, accepted receipts, or processors.
   A missing or corrupt data owner rejects the report without a fallback.
   Keep the data-directory lease throughout backup. Close readers before the
   writer. Attempt validated reopen after a copy error. If reopen fails, keep
   data access closed until restart; do not create an empty replacement store.
   Restore holds the destination lease before it checks that the directory is
   empty except for that lease file. Create and sync `restore.pending` before
   copying the backup. Before backup or restore copies bytes, check destination
   free space with one shared rule. Require the database size, one quarter of
   that size, the policy reserve, and the write allowance. Reject arithmetic
   overflow or insufficient space with a storage-capacity error. A rejected
   restore retains its pending marker and creates no database file. This check
   samples capacity; it does not reserve blocks against other writers.
   Normal startup rejects that marker before it opens the
   database. Keep the marker until validation and the new recovery-epoch commit
   succeed. Remove the marker and sync the directory before returning the
   restored owner. A copy with a pending marker remains unavailable. Retry from the
   unchanged backup into a new empty directory; do not remove the marker to
   enable the incomplete copy.
   Pin DuckDB core 1.5.5 through Rust binding 1.10505.0. Enable native
   `vacuum_rebuild_indexes` at open and reopen with the maximum unsigned
   64-bit threshold. Keep primary keys. Do not skip compaction because a
   table exceeds a separate row-count threshold. Existing logical quotas,
   native resource settings, and maintenance admission still apply. This
   native option is experimental and rebuilds affected indexes. Qualify its
   cost and recovery before production use. Check repeated file reuse with
   live exact witnesses; do not require each partial deletion to shrink a file.
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
   transaction. Control reads at most 16 entries per one-second tick. It cycles
   through configured tenants and the policy, trust, and rollout maps. Copy the
   source revision with its policy document, the trust generation, and the
   current rollout transition. Bound each serialized body to 32 KiB. Never
   truncate a body. Release the Control lock before each data commit. Retain
   the source generation, trust generation, or rollout transition number as
   the owner revision, including a rollout revision of zero. Use the source
   revision ID, trust digest, or candidate ID as the exact lifetime key.
   A projection has no claimed validity interval; store both bounds as null.
   The body retains any time reported by its authoritative owner. Do not infer
   activation or continuous coverage from a copied state. A missing exact key,
   including a transition that was replaced before projection, stays Unknown.
   Retry failed entries on the next pass. Continue other entries and keep
   policy RPCs active. Restart the worker after a panic; never restart Control
   to repair a projection failure. Remove the superseded event write path only
   after cutover
   tests prove every production caller uses AnalysisStore.

## Unit tests and end-to-end proof

Add `analysis_store_`, `control_retention_` and `analysis_startup_` tests:
commit/rollback, post-commit lost ACK, conflicting duplicates, out-of-order
batches, explicit gaps, checked overflow, cross-tenant references, required
processor stall, review pins, retirement, expiry, late context, WAL recovery,
disk full, unsupported schema and rejected old evidence state.

Use `analysis_store_input_crashes` for process exits immediately before and
after evidence, coverage, context, and recovery-gap commits. Reopen through the
production owner. Require the complete prior or new state, exact receipts and
relation revisions, tenant isolation, unchanged consumed progress, and an
idempotent retry. A duplicate retry must not publish a revision notification.
Reopen again after retry. Use temporary stores and test-only exit hooks.
These checks do not prove interruption inside native commit or hardware power
loss.

Use `analysis_store_processor_crashes` for exits before and after registration,
optional resume, and required retirement. Require atomic progress and missing
ranges, an exact retirement record, unchanged consumed cursors, retained
witnesses, tenant isolation, and retry without a second revision.
Use `analysis_store_restore_crashes` after the pending marker, before and after
the epoch commit, and after readiness publication. An incomplete copy must
reject repeated startup without changing the backup. A ready copy must retain
the new epoch across restart. Run the mTLS startup case with a pending-marker
fixture and require unavailable evidence/coverage, retained Node input, and
unchanged policy service and database bytes.

Use `data_control_crash` for a Control process exit after the data commit and
before the evidence ACK. Start the production mTLS server in a child process
from ControlConfig. Install its exit callback through the existing
`test-fixtures` feature. Reject an invalid batch without running the callback.
For valid input, require exit code 73 and no ACK. Reopen the Node WAL and data
store. Require the exact committed frame and receipt. Restart Control and replay
the same batch through mTLS. The replay must ACK without another record or
revision. Apply the ACK to Node, accept the next cursor, and reopen again.
Keep policy state unchanged. Use temporary directories and bounded child waits.

Use `data_commit_failure` for a native write error during evidence and result
commits. In a child process, open a temporary store before applying a zero-byte
or 64-byte file-size limit. Require the native commit to report `File too large`
for `analysis.duckdb.wal`. Do not accept an admission error as commit proof.
Require no revision notification, then exit without owner cleanup. Reopen and
check unchanged metadata, receipts, records, and processor progress, with no
new result. Retry without the limit. Require one revision, an unchanged duplicate
retry, and persistent state after another reopen. The result case must retain
its exact witness past raw expiry. These checks do not prove a torn write,
ENOSPC during commit, hardware power loss, or the mTLS failure response.

Use `data_intake_failure` to check the native write failure through mTLS.
Run the server and Node client in an isolated child process. Apply the file-size
limit only after startup and one accepted record. Require a native WAL commit
error instead of an ACK, unchanged data revision and receipt, and retained Node
input. Remove the limit. Require a policy RPC and exact replay without restarting
Control. Reopen the store and check the accepted frames and receipt. This case
does not qualify hardware power loss or an actual full filesystem during commit.

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

Use `data_capacity_recovery` and `data_full_disk` for paired capacity proof.
Both call the same production-owner scenario. The first uses a sparse file to
reach the data-file quota. The second requires an empty, task-owned 1-GiB tmpfs.
Allocate all free blocks and require an `ENOSPC` result. Through mTLS, require
ResourceExhausted, an unchanged receipt and revision, readable accepted data,
retained Node input, and a working policy RPC. Release only the test padding.
Reconnect the evidence stream without restarting Control. Require one commit,
an unchanged duplicate retry, and exact retained records after store reopen.
The harness is `crates/mithril-e2e/harness/discovery/disk-full.sh`. It accepts
the built Mithril e2e test binary and a new absolute output-log path. Run it
inside `unshare --user --map-root-user --mount`, or as root. The harness runs
the lightweight case first and removes its temporary mount at exit. This test
does not qualify hardware failure, native commit failure after admission,
reserve adequacy, or Kubernetes partition recovery.

Use `analysis_store_copy_limits` for exact copy-reserve boundaries and overflow.
The capacity scenario also makes a current-format managed backup, copies both
files outside the constrained filesystem, and restores that external copy.
In the full-tmpfs case, require the managed backup to fail its filesystem
reserve check and restore to fail its `copy reserve` check. A rejected backup creates neither
database nor manifest and leaves its source usable. A rejected restore creates
no database, retains its pending marker, and rejects normal startup. The same
backup must still restore into a new directory with sufficient space. This case
does not prove capacity that changes after the admission check.

Use `data-store-load` to measure the production data path without a cluster.
Submit 64 groups of 4,096 synthetic records through Node's bounded ingestion
queue, durable WAL, and the real mTLS intake. Use 1,024 records per Node worker
batch. Keep the production data quotas. Send a policy inventory RPC while each
group is in flight. Record Node generation time, time to observe the durable
ACK, policy RPC time, and sampled database, WAL, and aggregate file bytes.
The ACK measurement includes the intervening policy RPC. Retry each group and
require no new revision. Read every retained frame through bounded owner pages
and compare the ordered SHA-256 digest. Checkpoint, restart, and require unchanged
metadata, source receipt, and retained count. Record elapsed intake, read,
checkpoint, and restart times. Run `data_load_contract` with two groups in CI.
Run the CLI with `/usr/bin/time -v -o resources.log` on the qualification host
to record whole-process CPU time and peak RSS. This fixed single-source workload
does not prove multi-tenant contention, concurrent policy rollout, worst-case
payloads, disk-reserve adequacy, or full-quota throughput.

Use `data-store-tenants` for two authenticated tenants sharing one Control
and AnalysisStore. Give each Node a distinct certificate, tenant, and boot ID.
Wait for each tenant's exact initial trust-context record before measurement.
Send 32 groups of 4,096 records per Node through the production bounded worker.
Send both groups before waiting for either ACK. Run a policy inventory RPC
while the groups are in flight. After both commits, replay both groups and
require unchanged metadata. Check each Node's pending input, exact retained
frame digest, source receipt, and rejected foreign-tenant reads. Checkpoint and
reopen the shared store. Require unchanged metadata and both source states.
Record per-tenant ACK and policy RPC times, aggregate elapsed time, and sampled
database/WAL bytes. `data_tenant_load` uses two groups per Node in CI.
This case does not prove concurrent policy rollout, worst-case payloads, or
full-quota capacity.

```sh
cargo test -p mithril-control
cargo test -p araphor-data
cargo run -p mithril-e2e --bin mithril_discovery_test -- --case data-store-recovery --output-directory /tmp/araphor-data-recovery
cargo run -p mithril-e2e --bin mithril_discovery_test -- --case data-store-startup --output-directory /tmp/araphor-data-startup
cargo run -p mithril-e2e --bin mithril_discovery_test -- --case data-store-load --output-directory /tmp/araphor-data-load
cargo run -p mithril-e2e --bin mithril_discovery_test -- --case data-store-tenants --output-directory /tmp/araphor-data-tenants
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
Managed backups now stay inside that directory and count toward the total.
Restore can read an operator-owned external copy.
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
No read advances an ACK or processor progress. Authenticated Node floor reports
now use the protocol route described below; this route adds no cursor skip.
The 26 `analysis_store_` tests and all five data e2e tests passed. The recovery
case now passes 26 checks, including required lag, optional missing coverage,
and recovery-gap restart. These runs use temporary stores and synthetic input.
The final workspace gate passed for `4c9fca1f`: formatting, compilation,
strict Clippy, and workspace tests. The data crate passed 35 tests with two
ignored. Control passed 195 tests with two ignored, including the SQLite
50,000-atom case. The aggregate
scan cost still needs load qualification; passing small fixtures does not
prove the declared intake budget. Physical capacity and trace reservation,
processor runtime-failure reporting, crash injection, removal of
the remaining old library writer, and physical disk reuse remain open.
Production enablement is not qualified.

Backup now drains native access under the existing maintenance lock. It
checkpoints, closes both readers and the writer, copies and syncs the database
and manifest, then validates the original store before resuming. The directory
lease remains held. A copy or manifest error still attempts reopen. A reopen
failure leaves all native slots closed; data operations return an error.
Startup and reopen share the same native resource settings. Neither path adds
an importer, migration, fallback database, or additional persistence owner.
The 28 `analysis_store_` tests passed. `analysis_store_backup_window` checks
reader drain, unchanged revision, post-backup writes, and recovery after copy
and manifest errors. It also checks that a prior backup remains unchanged.
`analysis_store_closed_access` checks rejected reads, writes, and health after
connection closure, a held lease, rejected identity change, and restart.
All five data e2e tests passed with the post-backup mTLS replay assertion.
The recovery case now passes 27 checks. The same authenticated connection
retries the retained batch after backup; ACK and store revision stay unchanged.
The final workspace gate passed for `c2e4d3ed`: formatting, compilation, strict
Clippy, and all workspace tests. The data crate passed 37 tests with two ignored.
Control passed 195 tests with two ignored.

Explicit required-processor retirement now uses `data_retirements` in trusted
Control startup configuration. Control rejects more than 32 requests, duplicate
scopes, and requests outside an allowed Node and tenant. AnalysisStore compares
expected progress and accepted cutoff in one transaction. It records the change
ID, reason, cutoff, revision, and missing range before it releases the required
retention obligation. It does not advance consumed progress or remove witness
pins. A matching retry returns the original revision. Registration cannot
reactivate the retired processor version. The current development schema is 5;
older formats are rejected without migration.
The six data e2e tests passed. `data_retirement_startup` checks rejected foreign
and duplicate scopes, the request-count bound, policy RPCs during a stale-cutoff
conflict, Node retention of unacknowledged input, successful retirement, resumed
intake, and an unchanged retirement replay after restart.
The component test found a retained witness before an expired interval that
the old page read hid. The reader now stops before the next expired interval.
It returns the retained prefix and the gap's first cursor. A read at the gap
still returns explicit expiry. The existing witness test now checks readable
records on both sides of that gap. Retirement component checks include quota
rollback, unchanged consumed progress, retained witness protection, exact retry,
new-version registration, empty-input retirement, and corrupt retirement state.
The final workspace gate passed formatting, compilation, strict Clippy, and
39 data-crate tests with two ignored after the last witness assertion update.
All six data e2e tests passed again on those rebuilt binaries. The full gate
passed for `61b6ee89`, including 195 Control tests and 112 lightweight e2e tests.
The complete phase remains **Not done**.

Control context projection is implemented in `ControlContextOwner` and the
server's independent context task. The task reads committed authority records
and uses `AnalysisStore::commit_context`. It does not add a queue, outbox,
control transaction, or persistence owner. Schema 5 stores unknown context
validity as null and accepts exact zero-based owner revisions. Older schemas
are rejected; no migration is provided.
`control_context_bounded_replay` checks bounded pages, retry, restart, tenant
isolation, unchanged Control state, and an oversized trust body followed by a
valid body. `data_context_projection` exercises background policy and rollout
copies, source replacement, retained prior copies, restart, and a policy RPC.
Formatting, workspace checks, strict Clippy, and the data-crate tests passed.
All seven data e2e tests and the context component test passed on the final
rebuilt binaries. The startup test reads its restart baseline after server
shutdown drains blocking workers; independent context commits can occur before
that drain. The full workspace gate passed for `ee3568ec`, including 196 Control
tests with two ignored. Physical qualification and
the other open phase requirements remain **Not done**.

Native indexed-table compaction now uses DuckDB core 1.5.5 and Rust binding
1.10505.0. Startup and backup reopen enable the same native option. Primary
keys and transaction checks remain present. The shared `comfy-table` dependency
uses 7.1.4 because this DuckDB binding requires the 7.1 release line.
`analysis_store_physical_reuse` passed. It loads 40 MiB of deterministic,
poorly compressible payload in five cycles through the public data owner.
Production retention preserves one exact witness across the cycles. After two
initial cycles, each later peak file size stays within one 8-MiB load of the
initial maximum. Witness expiry releases native used blocks, and restart keeps
the accepted cursor and retained floor at 2,560. This component test uses
temporary stores and opaque data-owner input, not Node or kernel evidence.
It does not qualify full-disk behavior, large-store index cost, or the physical
storage/partition case.
The current data suite passed 40 tests with two ignored. All seven data mTLS
e2e tests passed. The first workspace build stopped during linking with
`No space left on device`. Removing only this worktree's generated incremental
cache restored build capacity; the same focused workspace command then passed.
The first final workspace CI run passed formatting and workspace checks. It
stopped on a strict-Clippy needless-borrow warning in the new native setting.
That borrow is removed. The final workspace procedure passed for `373474f`:
formatting, workspace checks, strict Clippy, and workspace tests. The data crate
passed 41 tests with two ignored. Control passed 196 tests with two ignored.
Mithril e2e passed 113 tests with 247 ignored. Node passed 255 tests with one
ignored. The phase remains **Not done** for its other open requirements.

`analysis_store_commit_crashes` passed twice. Four child processes exit without
Rust cleanup immediately before or after the production result and retention
commits. The hooks exist only under `cfg(test)` and match an exact temporary
store path. Reopen checks the prior or new commit revision, source receipt,
processor progress, result body, exact raw/context references, retained count,
and expiry range. Result retry has one effect. Retention retry preserves the
live witness and the accepted source cursor. A second reopen keeps that state.
The test calls production mutations; it does not reproduce their SQL writes.
This proof does not cover interruption inside the native commit, hardware power
loss, every other mutation boundary, or a Control process crash during mTLS.

The rebuilt qualification CLI passed `data-store-startup` (16 checks),
`data-store-recovery` (27 checks), `storage-contract` (nine checks), and
`offline-exact` for `373474f`. Results are in
`/tmp/araphor-data-qualification.MtrjRy/{startup,recovery,storage,offline}/result.json`.
Recovery records accepted cursor 4, retained floor 2, two retained events,
and backup revision 12. After checkpoint, the database uses 8,400,896 bytes
and the native WAL uses zero bytes. Measured batch commit, durable ACK, and
checkpoint times are 97,903, 45,958, and 13,232 microseconds. These single-run
fixture measurements do not establish throughput or reserve adequacy.
The explicit ignored SQL-worker isolation test also passed on this source.
No physical storage/partition qualification ran in this verification batch.

The paired `data_capacity_recovery` and `data_full_disk` checks now pass.
The committed-source harness log is
`/tmp/araphor-data-qualification.MtrjRy/disk-full-committed.log`.
It covers clean commit `db51fcea` and records the test-binary digest.
The platform is Linux 6.8.0-139-generic, x86_64. A private
1-GiB tmpfs reached zero free bytes with 1,070,059,520 allocated padding bytes.
The exact evidence stream received ResourceExhausted. The prior receipt and
revision remained unchanged; the pending Node batch survived. Accepted data
remained readable and a policy inventory RPC succeeded. After padding release,
a new stream obtained cursor 2 without a Control restart. Duplicate replay
did not add a commit. Reopen retained two records at commit revision 3.
The seven enabled data-store tests passed; the explicit full-filesystem test
also passed. The full workspace gate passed for `db51fcea`: formatting,
workspace checks, strict Clippy, and workspace tests. The data crate passed
41 tests with two ignored; Control passed 196 with two ignored; Mithril e2e
passed 114 with 248 ignored; Node passed 255 with one ignored.
Full-disk admission is qualified for this isolated fixture, not
for native failure during commit, hardware power loss, reserve sizing, or the
Kubernetes storage/partition case. The complete phase remains **Not done**.

Authenticated floor reporting is implemented through `NodeEvidence.ReportFloor`.
Node reads one ordered WAL source and its durable acknowledged cursor under
the WAL lock. It releases that lock before the RPC. Control uses current mTLS,
session and trust checks, shared intake admission, and the batch path's original
source-session lookup. The data owner records only recovery gaps. No source
receipt, processor progress, Node truncation, schema, or policy state changes.
The report reply is separate from `EvidenceAck`.
`wal_floor_replay` passed. It checks empty and nonempty sources, pending input,
rejected ACKs, ordered iteration, protocol conversion, and current-format
restart. All eight targeted data/mTLS tests passed. The raw mTLS intake test
checks rejected missing trust ACK, absent report/session, stale nonce, foreign
Node, changed boot, malformed source ID, and zero epoch. Valid reports record
the exact gap; retry has no second effect or cross-tenant visibility.
The rebuilt CLI passed startup (16 checks) and recovery (29 checks). Results
are in `/tmp/araphor-data-qualification.MtrjRy/floor-{startup,recovery}/result.json`.
Recovery now sends the actual Node floor through mTLS after stale restore.
It retries after restart and verifies the same missing range without creating
an accepted receipt. The full workspace gate passed for `a50c42d9`: formatting,
workspace checks, strict Clippy, and workspace tests. The data crate passed
41 tests with two ignored; Control passed 196 with two ignored; Mithril e2e
passed 114 with 248 ignored; Node passed 256 with one ignored.
Kubernetes scheduling of the new periodic report remains unqualified.
The complete phase remains **Not done**.

`analysis_store_input_crashes` passed all eight subprocess cases. Each case
calls the production mutation and exits without Rust cleanup at its selected
commit boundary. The test checks exact frames, coverage, context, recovery
ranges, receipts, relation revisions, notification state, tenant isolation,
and unchanged consumed progress. Retry and a second reopen preserve one effect.
The hooks compile only under `cfg(test)` and require an exact temporary path.
The first build stopped with `No space left on device`. Removing only this
worktree's ignored incremental build cache allowed the same command to pass.
The final `bash .github/scripts/verify-rust-ci.sh` run passed for `cb8417f8`:
formatting, workspace checks, strict Clippy, and workspace tests. The data crate
passed 42 tests with two ignored; Control passed 196 with two ignored; Mithril
e2e passed 114 with 248 ignored; Node passed 256 with one ignored. This run
includes the twelve result, retention, and input commit-crash cases. Processor
lifecycle and restore boundaries, a Control crash before ACK, and the remaining
capacity, load, and physical requirements are not proved by these cases.
The complete phase remains **Not done**.

Restore now holds the destination lease from the empty-directory check until
owner return. A synced pending marker blocks normal startup before native open.
The marker remains through copy, validation, and the recovery-epoch commit.
The same lease acquisition method serves normal startup and restore. No second
writer, migration, or public configuration option is added.
`analysis_store_processor_crashes` passed six before/after cases for
registration, optional resume, and required retirement. The cases check atomic
missing ranges and progress, exact retirement records, retained witnesses,
tenant isolation, and retry. `analysis_store_restore_crashes` passed four cases
at pending-marker creation, before and after the epoch commit, and after marker
removal. Incomplete copies reject repeated startup. Ready copies retain the new
epoch. The source store and backup remain unchanged, and a new destination can
restore from that backup.
All 44 enabled data tests and seven enabled data-store mTLS tests passed.
The rebuilt CLI passed startup (18 checks) and recovery (29 checks). Results
are in `/tmp/araphor-data-qualification.MtrjRy/restore-{startup,recovery}/result.json`.
The startup case uses a pending-marker fixture to prove rejected evidence and
coverage ACK, retained Node input, unchanged database bytes, and working policy
RPCs. The full `bash .github/scripts/verify-rust-ci.sh` gate passed for
`3121ea7d`: formatting, workspace checks, strict Clippy, and workspace tests.
The data crate passed 44 tests with two ignored; Control passed 196 with two
ignored; Mithril e2e passed 114 with 248 ignored; Node passed 256 with one ignored.
The tests use temporary stores and synthetic inputs. They do not prove a Control
process crash before ACK, hardware power loss, native commit failure after
admission, reserve adequacy, load limits, or physical Kubernetes behavior.
The complete phase remains **Not done**.

`data_control_crash` now passes through a real child Control process and mTLS.
Invalid input does not trigger the exit. Valid input commits before exit code
73, without an ACK. Reopened Node WAL returns the exact pending batch. Data
recovery returns its committed frame and receipt. Restarted Control ACKs replay
without a second record or revision. Applying that ACK clears Node pending
input. The next cursor commits once and survives another reopen. Policy state
remains unchanged, and the Control evidence cursor count remains zero.
All eight enabled `discovery::data_store::tests` cases passed; two are ignored
helpers or environment-specific cases. The full workspace gate passed for
`6ec1afed` with `CARGO_BUILD_JOBS=2 bash .github/scripts/verify-rust-ci.sh`:
formatting, workspace checks, strict Clippy, and workspace tests. The data crate
passed 44 tests with two ignored; Control passed 196 with two ignored; Mithril
e2e passed 115 with 249 ignored; Node passed 256 with one ignored.
These tests do not qualify hardware power loss, native commit failure after
admission, reserve adequacy, load, or Kubernetes behavior.
The complete phase remains **Not done**.

Backup and restore now share the checked destination-space rule. Restore checks
capacity after syncing its pending marker and before creating the database.
`analysis_store_copy_limits` passed exact boundaries and overflow checks. All
eight enabled data-store tests passed. The tmpfs harness passed both cases on
Linux 6.8.0-139-generic, x86_64. With zero available bytes, both copy entry points
return the copy-reserve error. No destination database is created. Restore
retains its marker and rejects startup. Backup reopens its source connections.
The unchanged backup restores into a fresh directory. The log is
`/tmp/araphor-copy-qualification.iqcH0TQ0/disk-full-committed.log` and records
clean commit `e7c771d2` and the binary digest. The full workspace gate passed for
that commit with `CARGO_BUILD_JOBS=2 bash .github/scripts/verify-rust-ci.sh`:
formatting, workspace checks, strict Clippy, and tests. The data crate passed
45 tests with two ignored; Control passed 196 with two ignored; Mithril e2e
passed 115 with 249 ignored; Node passed 256 with one ignored.
Concurrent space loss after admission, aggregate backup quotas, reserve sizing,
load limits, and Kubernetes qualification remain open. The phase is **Not done**.

`data_commit_failure` passed all four child cases. Evidence and result commits
each fail inside DuckDB with file-size limits of zero and 64 bytes. The native
error names the WAL file. No watch revision advances. After abrupt child exit,
reopen preserves prior metadata, receipt, exact records, and processor progress.
Retry commits once. A result witness prevents raw expiry, and another reopen
preserves the successful state. All nine enabled data-store tests passed; three
helpers or environment-specific cases remain ignored. The final workspace gate
passed for `c67d6588` with
`CARGO_BUILD_JOBS=2 bash .github/scripts/verify-rust-ci.sh`: formatting,
workspace checks, strict Clippy, and all workspace tests. The data crate passed
45 tests with two ignored; Control passed 196 with two ignored; Node passed
256 with one ignored. These cases do not prove torn writes, ENOSPC
during commit, hardware power loss, or Control's mTLS failure response. Other
capacity, load, old-writer removal, and physical requirements remain **Not done**.
The physical outage harness still uses `control_segment_manifest` and
`verify_control_segment_prefixes` in
`crates/mithril-e2e/harness/vm/two-node-outage-recovery.sh`. These checks inspect
`segments-v2`, not AnalysisStore. They do not qualify the new storage contract.

`data_load_contract` passed with 8,192 records. The CLI load case passed for
`769ddefb` with 262,144 records and 30,113,740 input bytes. Exact frame digests,
duplicate replay, Node ACK application, checkpoint, and restart checks passed.
The result is `/tmp/araphor-load-qualification.yOkYzh/load/result.json`.
Whole-process measurements are in the adjacent `resources.log`. The binary
SHA-256 is `820f459369ef5de5fd45c7a14309ef7eb9c5e6092b716e7a9d4fc7dcdd91525f`.
The host is Linux x86_64. This is a debug build and a single-source synthetic
run, not a production capacity limit. No kernel evidence was generated.
Intake, including generation and duplicate retries, took 35.462 seconds.
Observed ACK p95 was 302.475 ms, with a maximum of 366.727 ms. The maximum
policy inventory RPC time was 4.441 ms. Reading all bounded pages took
48.787 seconds. Checkpoint took 1.652 seconds; reopen took 1.101 seconds.
Sampled peak data files used 60,596,224 bytes. After checkpoint, the database
used 24,129,536 bytes and the WAL used zero bytes. The process used 131.39
user CPU seconds, 2.91 system CPU seconds, and 219,188 KiB peak RSS.
The run uses the production bounded batching worker and unchanged data quotas.
The final `CARGO_BUILD_JOBS=2 bash .github/scripts/verify-rust-ci.sh` gate passed
for `769ddefb`: formatting, workspace checks, strict Clippy, and workspace tests.
The data crate passed 45 tests with two ignored; Control passed 196 with two
ignored; Mithril e2e passed 117 with 250 ignored; Node passed 256 with one ignored.
Backup quota accounting, larger and
multi-tenant load, required reserve sizing, old-writer removal, and physical
qualification remain **Not done**.

The bounded evidence read now limits its SQL cursor range to one page and
one look-ahead record. It retains expiry, continuity, digest, row, and byte
checks. No index, cache, schema, or public API changes are added.
`analysis_store_bounded_read`, all 45 enabled data-owner tests, and all ten
enabled data-store mTLS tests passed. The full workspace gate passed for
`a604315a` with `CARGO_BUILD_JOBS=2 bash .github/scripts/verify-rust-ci.sh`:
formatting, workspace checks, strict Clippy, and workspace tests. Control
passed 196 tests with two ignored; Mithril e2e passed 117 with 250 ignored;
Node passed 256 with one ignored.
The repeated 262,144-record load passed with 30,113,740 input bytes, exact
frame digests, duplicate replay, ACK application, checkpoint, and restart.
Results are in `/tmp/araphor-read-qualification.Vslc6u5B/load/result.json` and
the adjacent `resources.log`. The measured binary SHA-256 is
`9d9989c6191c7f7da28f5fd8cc6371f4571e9d8b6c7d84de78e4920de97393a2`.
Reading took 32.024 seconds, compared with the earlier 48.787 seconds.
These two debug runs do not establish a production performance limit.
Intake took 32.199 seconds, checkpoint 1.519 seconds, and restart 0.985 seconds.
ACK p95 was 256.413 ms; the maximum policy inventory RPC time was 3.608 ms.
Sampled peak data files used 60,596,224 bytes. The checkpointed database used
23,605,248 bytes and its WAL used zero bytes. Whole-process wall time was
67.21 seconds, user CPU time 86.41 seconds, system CPU time 2.61 seconds,
and peak RSS 223,536 KiB. Capacity, remaining load, old-writer removal, and
physical qualification requirements remain **Not done**.

`data_intake_failure` now passes through production mTLS intake in an isolated
child process. The existing capacity-recovery scenario selects the native
commit fault without a production hook. Storage admission succeeds. DuckDB then
reports `File too large` for the WAL commit. Control returns Internal without
an ACK. The watch revision, metadata, source receipt, and accepted bytes remain
unchanged. Node retains the rejected batch. After the child restores its file
limit, a policy RPC and evidence replay succeed without a Control restart.
Duplicate replay has no second effect. Reopen retains two records at cursor 2.
All eleven enabled data-store tests passed; four helpers or environment-specific
cases remain ignored. The first run lacked the required filesystem reserve.
Removing only stale generated binaries allowed the unchanged test to pass.
The shared capacity pair passed in a private 1-GiB tmpfs. Its committed log is
`/tmp/araphor-intake-qualification.hEEgehKt/disk-full-committed.log`. The log
records clean commit `d2fce24f` and the binary digest. The full-filesystem case reached
zero free bytes, rejected intake and copy operations, retained Node input,
and recovered at cursor 2. The full workspace gate passed for `d2fce24f` with
`CARGO_BUILD_JOBS=2 bash .github/scripts/verify-rust-ci.sh`: formatting,
workspace checks, strict Clippy, and workspace tests. Control passed 196 tests
with two ignored; Mithril e2e passed 118 with 251 ignored; Node passed 256 with
one ignored. No Rust source changed after this gate.
Other phase requirements remain **Not done**.

The single-source and two-tenant load cases now share one runner. Each tenant
uses a distinct certificate and boot ID. The runner waits for the exact initial
trust context before checking duplicate metadata. Both original groups are
sent before either ACK wait. Exact retained digests, rejected foreign-tenant
reads, Node ACK application, checkpoint, and restart checks passed in both CLI
modes with 262,144 total records. The first measurements are in
`/tmp/araphor-tenant-qualification.7tmi4y0w/{single,tenants}/result.json`.
These measurements precede the final edit that restores Node generation time
in each sample. The measured binary SHA-256 is
`dcaf5428c954e2354a13bf3af8d6a9974e767ff90d29347810c2b0330f138868`.

| Measurement | One source | Two tenants |
| --- | ---: | ---: |
| Input bytes | 30,113,740 | 30,080,920 |
| Intake, seconds | 31.323 | 30.556 |
| Bounded reads, seconds | 30.540 | 26.647 |
| ACK p95, ms | 278.154 | 493.082 |
| Maximum policy RPC, ms | 4.002 | 5.414 |
| Checkpoint, seconds | 1.390 | 1.472 |
| Restart, seconds | 0.915 | 0.925 |
| Sampled peak files, bytes | 60,596,224 | 60,567,552 |
| Checkpointed database, bytes | 24,915,968 | 24,653,824 |
| Peak RSS, KiB | 221,192 | 242,796 |

Both checkpointed WAL files use zero bytes. Each tenant retains 131,072 records
at the same accepted cursor, with retained floor zero. The adjacent
`single-resources.log` and `tenant-resources.log` record CPU and wall time.
The debug binary ran on Linux x86_64 with a Ryzen 9 5900HX, 16 logical CPUs,
and 31,492 MiB memory. This host is not the declared 4-vCPU, 8-GiB pilot host.
One pair of runs does not prove variability, rollout performance, worst-case
payloads, full quotas, or reserve adequacy.

The final CLI passed for `c69dba4a` with 262,144 records. All 64 samples include
Node generation time. Each tenant retained 131,072 exact records at cursor
131,072, with retained floor zero. Reopen preserved commit revision 66 and
recovery epoch 1. The result is
`/tmp/araphor-tenant-qualification.7tmi4y0w/final-tenants/result.json`;
resource measurements are in the adjacent `final-resources.log`.
The final binary SHA-256 is
`26a1957c9993a6ace4b209753f8f19a5c2522c94793878d634fcd9f0ed1ce13c`.
This CLI ran during workspace tests. Its timings are not a clean performance
baseline. The final gate passed for the same source with
`CARGO_BUILD_JOBS=2 bash .github/scripts/verify-rust-ci.sh`: formatting,
workspace checks, strict Clippy, and workspace tests. The data crate passed
45 tests with two ignored; Control passed 196 with two ignored; Mithril e2e
passed 119 with 251 ignored; Node passed 256 with one ignored. No Rust source
changed after this gate. The complete phase remains **Not done**.

Managed backups now use the private `analysis/backups` directory and the
existing data-file budget. Admission checks projected copy and manifest bytes,
ordinary free-space reserves, and directory entries. Complete and incomplete
copies remain charged after restart. Restore still accepts an external copy.
No backup registry, deletion worker, or new configuration is added.
The 37 selected `analysis_store_` tests and all twelve enabled data-store mTLS
tests passed. The first backup run failed the filesystem-reserve check because
generated build files reduced host free space. Removing only the idle ignored
incremental cache restored capacity. The tests then passed without reducing
storage reserves. The final workspace gate and paired full-filesystem check
are pending. The complete phase remains **Not done**.
