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

1. Correct reader/rotation locking before adding QueryOwner. In
   `analysis/raw.rs`, keep the writer coordinator but release the raw-directory
   mutex before waiting for exclusive maintenance protection. Reacquire the
   mutex after obtaining protection, then rotate and commit. In
   `analysis/extraction.rs`, use `AnalysisReadControl::lock` for directory
   access in `selected_ranges` and `check_selected_source`. Preserve snapshot
   and durable ACK rules. Pass the deterministic regression case below before
   proceeding. Follow the [locking contract](engine-design.md#reader-and-rotation-locking).
2. Put the shared evidence protobuf messages and bounded record decoder in
   `araphor-data`. Generate each shared message once. Control's service code
   imports/re-exports those types; it keeps source authentication and policy
   validation. Keep the wire package, field numbers and segment format.
   Do not create a second observation model or a DuckDB row archive. Decode
   only selected records into temporary pages. Discovery reuses this decoder
   in 7.4. Follow the [representation contract](engine-design.md#portable-records-and-query-input).
3. Add a position-based read to AnalysisStore through its existing segment
   owner. Query reads include durable pending ranges above the contiguous ACK.
   Keep source cursor, store position and kernel sequence distinct. Preserve
   contiguous source reads for ordered processors. Capture source membership,
   coverage and metadata in the same snapshot. A coverage correction changes
   coverage, not an immutable event row or its store position.
4. Add `QueryOwner` under `crates/araphor-data/src/query/`. Accept only
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
5. Implement typed rows and internal frames for `catalog`, `events`, `coverage`
   and `context_versions`. Document units, nulls, exact join keys and proof
   limits. `received_at` is Control intake time; source boot-relative time is
   separate. Metadata/results use their existing owner reads. Add later views
   only when their owners exist; unavailable capability is not an empty table.
   Register shared evidence and trace schemas without a second query owner.
6. For append, select positions after the last scanned position and through
   one captured end. Page the initial retained range and later commits without
   repeatedly extracting full history. Advance checkpoints across nonmatching
   records; a full frame stops before its next unreturned match. For replace,
   evaluate complete bounded input. Require the complete replacement
   to fit the configured output bound, initially 200 rows/1 MiB. Reject
   overflow; never calculate a partial aggregate.
   Register watch before snapshot capture. Use one evaluation and one dirty
   flag per stream; recheck dependency revisions before waiting.
7. Bind checkpoints to store UUID/epoch, plan/schema version, parameters and
   exact scope. Retention commits a per-tenant replay floor with deletion
   intent before unlink. The floor is the greatest deleted raw store position.
   Reject older append checkpoints conservatively, even if their filter could
   have excluded the deleted rows. Report that replay is unavailable, not that
   a particular matching row was lost. The floor survives restart and backup.
   Retained witnesses below it remain queryable. Replacement resume evaluates
   current state. Neither cursor type pins history.
8. Implement moving intake-time windows and fixed buckets as trusted
   templates under the [window contract](engine-design.md#intake-time-windows).
   Bind one evaluation instant to moving selection and SQL. Use a controllable
   clock and an expiry timer; quiet streams still lose expired rows. Report
   clock changes. Fixed buckets use DuckDB `time_bucket`, UTC, an explicit
   origin and separate input bounds. Both return complete replacements.
   Preserve late evidence and label intake time separately from source time.
   Defer overlapping windows, sessions and event-time finality. Do not add
   persistent per-query state or a second raw representation.
   Templates for exact match, counts, revision difference and qualified
   within-subject sequence retain their limitations; interpretation is 7.6.
9. Add validated `QueryLimits` in the data crate. The host supplies the same
   settings in embedded and remote mode. Use verification.md defaults for
   scan/input/output bytes, deadlines, evaluation concurrency and stream count.
   Reserve concurrent input and output capacity before extraction. Close all
   segment leases and metadata readers before evaluation or output waits.
   Cancel native evaluation, release buffers on every exit and enforce the
   output-stall timeout. Native memory settings are not an OS process cap.
   Observability 3 adds and qualifies the worker OS limits and public grants.

## Unit tests and end-to-end proof

First add a component regression case for extraction and rotation. Use
barriers, not sleep-based scheduling. Pause a reader after it acquires segment
protection and releases the writer coordinator. Start a write that requires
rotation. Use a writer barrier immediately before its exclusive-protection
request, then let the reader request directory access. Require both to
finish, preserve the first read's snapshot and include the new commit in a
later read. Check cancellation/deadline handling at directory-lock waits.
This is a correctness check, not a performance benchmark.

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
matching batch and require a complete replacement. For records at 10:01,
10:04 and 10:07, require moving five-minute counts of 2 at 10:08 and 1 at
10:10 without new traffic. Require fixed five-minute bucket counts of 2 at
10:00 and 1 at 10:05 for the 10:00–10:10 input range. Add a record at exactly
10:05 and require it only in the second bucket. Compare each replacement
with a normal query at the same revision and evaluation time. Test configured
input/output overflow, clock changes and explicit retention gaps. A delayed
source record uses its intake bucket without losing its source timestamp.
Reuse these fixtures in component tests and the production-owner e2e case.
Prove reader cancellation leaves intake and policy work
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

## Implementation result

Status: **Not done**. Reader/rotation locking is **Done**. The writer keeps
its coordinator, releases the raw-directory mutex before the rotation wait,
and acquires that mutex again after segment protection. Directory waits in
extraction and reader coordination check cancellation and deadlines.

`analysis_extract_rotation` uses channel barriers and the production extractor.
It checks the original snapshot, rotation completion, and the later commit.
`analysis_extract_lock_waits` cancels after a blocked lock attempt. The lock
holder must retain the mutex until the reader returns. The test also checks
deadlines at all three directory-access sites and subsequent intake.

On base `ce0a9fd8` with this lock correction, the command below passed:
8 tests, zero failures, and one ignored release-history test. Formatting and
`git diff --check` passed. No performance case ran. The final workspace gate
remains required after the last implementation edit.

```sh
CARGO_TARGET_DIR=/home/navid/go/src/github.com/Ereborlabs/erebor-runtime/target CXXFLAGS='-O2 -g0' CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true RUST_TEST_THREADS=1 cargo test -p araphor-data analysis_extract_ -- --nocapture
```

Shared evidence definitions and bounded decoding are **Done**. `araphor-data`
generates the shared protobuf types. Control, Node and qualification callers
use those types. Control retains authentication and semantic validation.
The decoder checks frame length, CRC32C and protobuf bounds. Exact-frame
conversion rejects trailing bytes. Unknown protobuf values remain unchanged.

The focused data command below passed 7 tests. Four tests check decoding,
size boundaries, invalid frames and shared byte ownership. Three tests check
the position-reader work that follows this deliverable. The contract command
passed 3 tests, including exact protobuf fields and shared Rust type identity.
The contract build compiled data and Control production code. Node and e2e
compilation and caller library-test filters remain pending; their native
dependency build is in progress. No performance case ran.

Use the six environment settings from the locking command for these commands:

```sh
cargo test -p araphor-data query_input_ -- --nocapture
cargo test -p araphor-data -p mithril-control -p mithril-node -p mithril-e2e --all-features --test contract
```

The decoder deliverable is commit `ec96c32a`. The locking deliverable is
commit `61a20f82`.

Position reads are **Done**. The segment owner selects durable commit positions
across all selected sources, including ranges above the contiguous ACK. A
snapshot captures receipts, pending gaps, retention/recovery gaps, and the
coverage report. Existing ordered source reads retain their ACK boundary.
No SQL offset directory or second raw store was added.

The position tests passed: three `query_input_` tests plus one
`query_scope_position_pages` test. They check pending cursors 11–20 before
1–10, a commit during projection, exact retry, sparse duplicate spans,
cross-tenant exclusion, filtered-page progress, byte limits, and resume.
The extraction regression filter then passed 8 tests with one existing
release-history test ignored. All commands used the six settings above:

```sh
cargo test -p araphor-data query_scope_position_pages -- --nocapture
cargo test -p araphor-data analysis_extract_ -- --nocapture
```

The persisted replay floor is **Done**. Schema version 10 adds one floor per
tenant. Retention commits the greatest deleted raw position with `Deleting`
and the exact expired ranges, before file removal. The floor has one 256-byte
metadata charge. Validation rejects missing, invalid, or uncharged floors.
Restart and backup retain the floor. Restore changes the recovery epoch.
An older exact witness remains readable below the floor.

The integrated command below ran 38 data tests. The five
`query_follow_retention_` tests passed. They cover deletion ordering,
multi-span positions, tenant isolation, crash recovery, restart, restore,
quota validation, and a retained older witness. In total, 33 tests passed and
5 query-evaluator tests failed at connection configuration. Those failures
are not storage qualification failures. The correction and later results
are recorded below.
The command used the six environment settings above:

```sh
cargo test -p araphor-data -p mithril-control -p mithril-node -p mithril-e2e --all-features --lib query_ -- --nocapture
```

QueryOwner, typed input, internal follow, and intake windows are **Done** at
the focused component-test level. Raw events stay in segments. The temporary
VTab adapter owns no durable rows or process-wide registry. Catalog and
coverage SQL rows are generated only when the template needs those relations.
All native query connections disable external access, extension loading, and
temporary files. Temporary storage is configured before external access is
disabled, as required by the pinned DuckDB version.

Output frames share one charged coverage summary. Each frame reserves its
own fields before construction. The owner checks exact input/output bounds,
including row descriptors during transfer. A cancelled read that did not
start a native snapshot keeps its reader. A failed native reader is replaced
with a fresh connection to the same open database. Cancellation does not
require full-store recovery. The regression checks deadline-before-BEGIN,
failed BEGIN, failed rollback, and subsequent reads.

The integrated `query_` command above then passed 55 data tests, 2 Control
tests, and 2 e2e tests. One existing isolated-worker helper was ignored.
The data tests include full-input template comparisons, exact timestamps,
input/output N and N+1, shared output ownership, native cancellation,
initial-snapshot races, nonmatching append progress, coalesced replacements,
stalled output, reader release during backup/rotation, and pinned evidence
during deletion. Weak input references prove release after stream evaluations.
The e2e query-follow contract passed its six-case source version: pending
ranges, counts, windows, bounded input, retention/restart/restore, and policy
work after cancellation. Additional stream barriers remain under qualification.

Decoder caller checks also passed: 17 Control evidence tests, 49 Node
observation tests, 1 Node context-catalog test, and 1 e2e context-bound test.
The first command compiled all four libraries. The Node and context filters
ran their built test executables. No performance test ran.

Next: finish the end-to-end barriers and final acceptance review, then run
the complete workspace gate. Overall status remains **Not done**.

The data-owner deliverable is commit `6f055e92`. The expanded
`query_follow_contract` then passed with eight cases. The two added cases
force a commit between watch registration and the first snapshot, coalesce
commits behind blocked output, and prove output-timeout cleanup before the
client drains its queue. Retention and later intake succeed while that old
output remains queued. These cases call production owners and use small
temporary stores. They make no throughput or latency claim.

```sh
cargo test -p araphor-data -p mithril-control -p mithril-node -p mithril-e2e --all-features --lib query_follow_contract -- --nocapture
```

The command used the same six environment settings. Final acceptance review
and the full workspace procedure remain required. The CLI case has not yet run.
