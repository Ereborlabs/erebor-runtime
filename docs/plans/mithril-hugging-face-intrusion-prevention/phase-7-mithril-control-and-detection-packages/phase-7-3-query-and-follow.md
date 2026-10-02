# Phase 7.3: Trusted Query And Commit-Driven Follow

Provide the internal read engine for retained and live data.

## Intended end state

QueryOwner evaluates trusted internal read plans and returns one bounded stream.
Immutable event reads append rows. Aggregate and mutable-view reads replace
the complete bounded result. Entry: 7.2. Status: **Not done**.

The owner, record decoder, and query input types live in `araphor-data`.
They work without a Control process or Control crate dependency. Phase 7.9
packages these same owners as the optional remote data service.
Observability 3 adds client SQL admission, current caller grants, disclosure,
authenticated receipts/cursors, and the production isolated worker before
public SQL access. This phase must not expose arbitrary SQL through a service.

## Implementation flow

```text
Trusted code supplies a reviewed read plan, typed parameters and exact tenant/source scope
  -> QueryOwner validates the plan and its configured limits
  -> AnalysisStore captures source membership, metadata revision and committed segment ends
  -> shared decoder reads bounded segment records into temporary typed pages
  -> built-in DuckDB table function exposes those pages as logical relations
  -> QueryOwner evaluates its fixed SQL template against these pages in memory
  -> owner returns rows, coverage, read revision and checked internal checkpoint

A batch arrives before an earlier source range
  -> segment sync makes its rows visible at their original store positions
  -> coverage reports the missing source range
  -> contiguous ACK and ordered processor progress do not cross that range
  -> arrival of the missing range adds its rows and updates coverage

Follow is requested
  -> QueryOwner registers dependency notifications before the initial snapshot
  -> owner sends metadata, initial result and a checkpoint on one stream
  -> relevant commits mark one evaluation dirty
  -> append reads new committed positions; replace evaluates a complete snapshot
  -> supported time-window expiry also triggers replacement without new input
  -> owner closes all DB readers and evaluations before waiting

Reader is slow, cancelled or disconnected
  -> owner stops this bounded read; source intake continues
  -> retry checks the scope, epoch and last complete checkpoint
  -> a checkpoint below the tenant replay floor returns CursorExpired
  -> no retry silently starts at a newer position
```

## Changes in implementation order

1. Put the shared evidence protobuf messages and bounded record decoder in
   `araphor-data`. Generate each shared message once. Control's service code
   imports/re-exports those types; it keeps source authentication and policy
   validation. Keep the wire package, field numbers and segment format.
   Do not create a second observation model or a DuckDB row archive. Decode
   only selected records into temporary pages. Discovery reuses this decoder
   in 7.4. Follow the [representation contract](engine-design.md#portable-records-and-query-input).
2. Add a position-based read to AnalysisStore through its existing segment
   owner. Query reads include durable pending ranges above the contiguous ACK.
   Keep source cursor, store position and kernel sequence distinct. Preserve
   contiguous source reads for ordered processors. Capture source membership,
   coverage and metadata in the same snapshot. A coverage correction changes
   coverage, not an immutable event row or its store position.
3. Add `QueryOwner` under `crates/araphor-data/src/query/`. Accept only
   code-owned read plans with fixed SQL templates and checked parameters.
   Templates specify relations, columns, source selection, time bounds and
   append/replace behavior. No network request, client attachment, stored
   document or caller SQL string can construct a trusted plan. Reuse one
   evaluator when Observability 3 adds its isolated process entry point.
   Use a temporary in-memory connection, never the persistent metadata
   connection. Keep native external access and extension loading disabled.
   Implement the [built-in input adapter](engine-design.md#built-in-duckdb-input-adapter)
   with the existing DuckDB `VTab` trait. Register query-owned input and expose
   SQL views over it; do not insert raw records into DuckDB tables. Reuse the
   same adapter in the later isolated worker. No loadable plugin is required.
4. Implement typed rows and internal frames for `catalog`, `events`, `coverage`
   and `context_versions`. Document units, nulls, exact join keys and proof
   limits. `received_at` is Control intake time; source boot-relative time is
   separate. Metadata/results use their existing owner reads. Add later views
   only when their owners exist; unavailable capability is not an empty table.
   Register shared evidence and trace schemas without a second query owner.
5. For append, select positions after the last scanned position and through
   one captured end. Page the initial retained range and later commits without
   repeatedly extracting full history. Advance checkpoints across nonmatching
   records; a full frame stops before its next unreturned match. For replace,
   evaluate complete bounded input. Require the complete replacement
   to fit the configured output bound, initially 200 rows/1 MiB. Reject
   overflow; never calculate a partial aggregate.
   Register watch before snapshot capture. Use one evaluation and one dirty
   flag per stream; recheck dependency revisions before waiting.
6. Bind checkpoints to store UUID/epoch, plan/schema version, parameters and
   exact scope. Retention commits a per-tenant replay floor with deletion
   intent before unlink. The floor is the greatest deleted raw store position.
   Reject older append checkpoints conservatively, even if their filter could
   have excluded the deleted rows. Report that replay is unavailable, not that
   a particular matching row was lost. The floor survives restart and backup.
   Retained witnesses below it remain queryable. Replacement resume evaluates
   current state. Neither cursor type pins history.
7. Implement the existing moving intake-time window as a trusted template.
   Bind one evaluation instant to selection and SQL. Use a controllable clock
   and an expiry timer; quiet streams still lose expired rows. Report clock
   changes. Additional window semantics require user review before they enter
   this plan.
   Templates for exact match, counts, revision difference and qualified
   within-subject sequence retain their limitations; interpretation is 7.6.
8. Add validated `QueryLimits` in the data crate. The host supplies the same
   settings in embedded and remote mode. Use verification.md defaults for
   scan/input/output bytes, deadlines, evaluation concurrency and stream count.
   Reserve concurrent input and output capacity before extraction. Close all
   segment leases and metadata readers before evaluation or output waits.
   Cancel native evaluation, release buffers on every exit and enforce the
   output-stall timeout. Native memory settings are not an OS process cap.
   Observability 3 adds and qualifies the worker OS limits and public grants.

## Unit tests and end-to-end proof

Unit tests `query_input_`, `query_scope_`, `query_follow_` must cover decoding,
exact source selection, cross-tenant keys, snapshot consistency, input/output
N/N+1, cancellation and cleanup. Use small configured limits for boundary tests.
For the adapter, compare decoded values with query output, including nulls,
bytes, unknown enum values and timestamp precision. Scan one input twice and
through a self-join. Use drop counters to prove input release after success,
error, cancellation and repeated follow evaluations. No process-lifetime
input registry or persistent event table may remain.
Check every emitted append, replace, checkpoint, health, error and terminal
frame against its fields and ordering. A closed stream is not a trace terminal
result. Public SQL admission, authenticated tokens, grants, disclosure, sandbox
and wire-level gRPC tests belong to Observability 3. Compare each trusted
template with full scoped-input execution in the pinned DuckDB.

Add `query-follow` to `mithril_discovery_test`. Use actual AnalysisStore
commits and QueryOwner streams. Use deterministic commit barriers. Verify
initial snapshot/commit race, empty
filters, replay, coalesced notifications, unrelated commits, full batches,
late events, coverage correction, retention expiry, cancellation and restart.
Commit source cursors 11–20 before 1–10. Require the first query to return
11–20 with a gap and ACK zero. Follow must then return 1–10 once, with ACK 20
and corrected coverage. An exact retry emits no duplicate record.
Expire history after a checkpoint and test the persisted replay floor across
restart and restore. A retained witness remains readable below that floor.
For `SELECT operation, COUNT(*) ... GROUP BY operation`, verify each replace
equals a normal query at the same revision, never the sum of prior snapshots.
Use a tenant history larger than the extraction budget with a small matching
trusted time window. Require a correct count and bounded extraction, then add a
matching batch and require a complete replacement. Expire a moving-window row
with no new traffic. Prove reader cancellation leaves intake and policy work
active. Fail an evaluation and prove subsequent reads and intake still work.
Test a pin/delete race and concurrent segment rotation during snapshot capture.
Require counts to match a full authorized scan at that same revision. Confirm
no segment lease survives a cancelled read or a blocked client response.
Record the template, read revision, scanned bytes and extracted row/byte counts.
Check that no raw-event database table or persistent query copy is created.
Reject over-budget input before returning an aggregate. New performance tests,
workloads and pass limits require separate user approval; this plan is not that
approval. The accepted 1-GiB storage qualification is not an 8-GiB claim.

```sh
cargo test -p araphor-data
cargo test -p mithril-control
cargo run -p mithril-e2e --bin mithril_discovery_test -- --case query-follow --output-directory /tmp/araphor-query-follow
bash .github/scripts/verify-rust-ci.sh
```

## Completion gate

Pass the internal DE-QUERY, DE-FOLLOW, DE-TENANT and DE-LIMIT cases. Record
schema, operations, read revisions, coverage, checkpoints and configured limits.
Full public DE-QUERY and DE-DISCLOSE require Observability 3. This phase cannot
enable client SQL or claim OS worker isolation. A model, discovery profile,
public API or durable subscription registry is not required.
