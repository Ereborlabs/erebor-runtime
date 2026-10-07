# Phase 7.3: Trusted Query And Commit-Driven Follow

Provide the internal read engine for retained and live data.

## Intended end state

QueryOwner evaluates trusted internal read plans and returns one bounded stream.
Immutable event reads append rows. Aggregate and mutable-view reads replace
the complete bounded result. Entry: 7.2. Status: **Done** for trusted internal
query and follow. Read the [additional correctness checks](#additional-correctness-checks)
for the latest verification result.

The owner, record decoder, and query input types live in `araphor-data`.
They work without a Control process or Control crate dependency. Phase 7.9
packages these same owners as the optional remote data service.
Observability 3 adds client SQL admission, current caller grants, disclosure,
unsigned bookmark checks, and bounded Tokio execution before
public SQL access. This phase must not expose arbitrary SQL through a service.

## Implementation flow

```text
Trusted code supplies a reviewed read plan, typed parameters and exact tenant/source scope
  -> QueryOwner validates the plan and its configured limits
  -> AnalysisStore captures source membership, metadata revision and committed segment ends
  -> shared decoder decodes each selected event once when binding checks or projection require it
  -> query-owned projection expands SQL views through the store-owned byte limit
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
  -> owner returns one lazy QueryStream without starting SQL
  -> consumer polling produces metadata, initial result and a checkpoint
  -> relevant commits mark one evaluation dirty
  -> append reads new committed positions; replace evaluates a complete snapshot
  -> supported time-window expiry also triggers replacement without new input
  -> owner closes all DB readers and evaluations before waiting

Reader pauses
  -> owner starts no further evaluation
  -> bounded retained frames keep their reservations until consumption or drop

Reader cancels or disconnects
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
   Validate source, context, result, profile, trace and binding keys against
   one combined limit with checked subtraction. Keep Node keys under their
   separate limit. Preserve identity, tenant and uniqueness checks.
   Represent sources, contexts and traces with one Selection value each:
   All or Exact with a list. An empty Exact list selects nothing. Resolve All
   membership in the same bounded snapshot. Do not store separate all flags.
4. Add `QueryOwner` under `crates/araphor-data/src/query/`. Accept only
   code-owned read plans with fixed SQL templates and checked parameters.
   Templates specify relations, columns, source selection, time bounds and
   append/replace behavior. No network request, client attachment, stored
   document or caller SQL string can construct a trusted plan. Reuse one
   evaluator when Observability 3 adds its asynchronous client entry point.
   Use a temporary in-memory connection, never the persistent metadata
   connection. Keep native external access and extension loading disabled.
   Implement the [built-in input adapter](engine-design.md#built-in-duckdb-input-adapter)
   with the existing DuckDB `VTab` trait. Register query-owned input and expose
   SQL views over it; do not insert raw records into DuckDB tables. Reuse the
   same adapter for client execution. No loadable plugin is required.
   Keep target, context, profile and trace-measurement expansion in the query
   projection. AnalysisStore supplies retained inputs from one snapshot. It
   owns selection, segment leases, byte limits, cancellation and page progress.
   Binding checks and event rows use the same decoded event. Raw-only reads
   do not require decoding. Charge projection state and every emitted row.
   A page must not disclose part of one expanded raw record.
5. Implement typed rows and internal frames for `catalog`, `events`, `coverage`
   and `context_versions`. Document units, nulls, exact join keys and proof
   limits. `received_at` is Control intake time; source boot-relative time is
   separate. Metadata/results use their existing owner reads. Add later views
   only when their owners exist; unavailable capability is not an empty table.
   Register shared evidence and trace schemas without a second query owner.
   Column stores one name and data type. EvaluationResult and QueryResult
   share that type and one column vector. Client metadata adds units, owner
   and readiness at its existing boundary. Preserve row and cursor checks.
6. For append, select positions after the last scanned position and through
   one captured end. Page the initial retained range and later commits without
   repeatedly extracting full history. Advance checkpoints across nonmatching
   records; a full frame stops before its next unreturned match. For replace,
   evaluate complete bounded input. Require the complete replacement
   to fit the configured output bound, initially 200 rows/1 MiB. Reject
   overflow; never calculate a partial aggregate.
   Register watch before snapshot capture. Use one evaluation and one dirty
   flag per stream; recheck dependency revisions before waiting.
   QueryStream owns the plan, checkpoint, subscriptions and one pending
   next-frame future. One lifecycle value contains the Ready state, the
   Pending future, or Closed. Move the same state through each evaluation.
   Derive the append position from the last disclosed checkpoint. Closed
   cannot start another read. The stream implements Stream directly.
   Construction starts no SQL. Polling advances that future and returns one frame. Do not
   add a separate producer task, output channel or subscription driver.
   The same future waits for retained-read checks before it returns the frame.
   Cancellation and authority changes also wake this wait. Advance the
   checkpoint only when the authorized frame is returned.
   Construction needs no runtime. Poll with the Tokio timer enabled. Polling
   outside Tokio returns a typed QueryInvalid error.
   Drain the current metadata/data/checkpoint sequence before another
   evaluation. QueryYield holds each staged result and its checked checkpoint.
   Keep the last disclosed checkpoint separate until authorized yield.
   A paused consumer starts no further evaluation. An admitted
   native task can finish; retain its capacity until cleanup returns.
7. Check the checkpoint schema, store UUID/epoch, operation, read revision and
   position. The caller retains the exact plan, parameters and input selection.
   A checkpoint grants no access. Retention commits a per-tenant replay floor
   with deletion intent before unlink. The floor is the greatest deleted raw
   store position.
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
   Cancel native evaluation and release buffers on every exit. The client
   transport enforces the output-stall timeout. The transport checks the
   elapsed interval when it receives demand after a returned frame. A pending
   read that waits for a change is not a stalled client. A timeout closes
   the read, not trace execution. Do not add an idle driver to reclaim an
   unpolled stream. Native memory settings are not an OS process cap.
   Observability 3 adds client admission and current caller grants. Its
   asynchronous entry point uses bounded blocking tasks on the host's existing
   Tokio runtime. Do not add a query process or an OS-isolation requirement.

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
result. Public SQL admission, unsigned bookmark checks, current caller grants,
disclosure, bounded asynchronous execution and wire-level gRPC tests belong
to Observability 3. Compare each trusted template with full scoped-input
execution in the pinned DuckDB.
Check that construction performs no query work and that paused consumption
starts no further evaluation. Drop a pending stream and require cancellation
and capacity release. Revoke authority or invalidate retained trace reads
between staged frames; no denied frame can be returned. Test slow-client
deadlines at the client transport, not through a producer queue.

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

Status: **Done** for the approved internal scope, including the additional
checks below. The records describe each deliverable. Reader/rotation locking
is **Done**. The writer keeps
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
was still required after the last implementation edit.

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
The contract build compiled data and Control production code. At this point,
Node and e2e compilation and caller library-test filters were pending.
The later caller and final workspace results are recorded below.
No performance case ran.

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
The position-reader deliverable is commit `4c6e0900`.

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
The replay-floor deliverable is commit `34a12a8a`.

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
work after cancellation. The later eight-case result includes the additional
stream barriers.

Decoder caller checks also passed: 17 Control evidence tests, 49 Node
observation tests, 1 Node context-catalog test, and 1 e2e context-bound test.
The first command compiled all four libraries. The Node and context filters
ran their built test executables. No performance test ran.

At this point, the end-to-end barriers, final acceptance review, and complete
workspace gate remained open. Their results follow.

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

The command used the same six environment settings. Final acceptance review,
the workspace procedure, and the standalone CLI case had not yet run.

The end-to-end deliverable is commit `5c89ebcf`. The final Ponytail review
closed two proof gaps. All ten trusted templates now compare with complete
scoped input through the pinned DuckDB. The existing query-test filter passed
11 tests. `query_scope_pin_race` passed both forced commit orders. A pin that
commits first prevents deletion. Deletion that commits first rejects the pin
and leaves result/progress unchanged. A held query result stays unchanged in
both cases. The hooks exist only in test and test-fixture builds.

```sh
cargo test -p araphor-data -p mithril-control -p mithril-node -p mithril-e2e --all-features --lib query::tests:: -- --nocapture
cargo test -p araphor-data -p mithril-control -p mithril-node -p mithril-e2e --all-features --lib query_scope_pin_race -- --nocapture
```

Both commands used the six settings above. The three existing
`analysis_read_` tests also passed in the built data test executable.
The new review-guide links and `git diff --check` passed. This proof deliverable
is commit `038c3bd4`. The final workspace and CLI results follow.

### Final query qualification

Status: **Done, PASS** at source commit `68db8105`. The complete workspace
procedure and standalone production-owner case passed after the last code edit.
The later audit found three missing checks. The passing runs below do not
prove those paths; their current status is recorded below.

The first two workspace attempts found test-only Clippy errors: one unnecessary
borrow, five explicit panic branches, and one unchecked field lookup. Commit
`68db8105` removes the borrow and uses ordinary errors for test failures.
It changes no production behavior, expected test result, or lint setting.
The complete procedure then passed:

```sh
CARGO_TARGET_DIR=/home/navid/go/src/github.com/Ereborlabs/erebor-runtime/target CXXFLAGS='-O2 -g0' CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true RUST_TEST_THREADS=1 bash .github/scripts/verify-rust-ci.sh
CARGO_TARGET_DIR=/home/navid/go/src/github.com/Ereborlabs/erebor-runtime/target CXXFLAGS='-O2 -g0' CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true RUST_TEST_THREADS=1 cargo run -p mithril-e2e --bin mithril_discovery_test -- --case query-follow --output-directory /tmp/araphor-query-follow
```

Both commands exited with code 0. The procedure runs formatting, workspace
compilation, Clippy with warnings denied, and all-target/all-feature tests.
The affected library results were:

| Library | Passed | Failed | Ignored |
| --- | ---: | ---: | ---: |
| `araphor-data` | 139 | 0 | 5 |
| `mithril-control` | 176 | 0 | 2 |
| `mithril-node` | 266 | 0 | 1 |
| `mithril-e2e` | 124 | 0 | 406 |

Other enabled workspace tests also passed. The ignored cases keep their existing
physical-environment, release-only, or subprocess-helper requirements. This run
does not qualify those cases. `query_follow_contract` and
`query_follow_arguments_are_scoped` both passed.

The standalone receipt records **PASS** for all eight cases: pending replay and
scope; complete operation counts; moving and fixed windows; bounded input and
recovery; retention, restart, restore, and exact witnesses; cancellation with
continued policy work and intake; the initial-snapshot race and coalesced wake;
and blocked-output cleanup. It records schema 1, configured limits, coverage,
read revisions, checkpoints, and frame operations.

Evidence paths:

- Workspace log: `/tmp/araphor-query-final-ci-3.log`.
- Standalone command log: `/tmp/araphor-query-follow-cli.log`.
- Standalone receipt: `/tmp/araphor-query-follow/result.json`.

The final Ponytail review is complete. The owner uses the existing segment
reader, query-owned temporary input, one follow task, and one bounded output
queue. It adds no durable raw copy, input registry, or subscription service.
The [implementation review](implementation-review.md#trusted-query-and-follow-review)
links the source owners and their checks.

These are component and lightweight production-owner proofs. Forced pin/delete
orders and concurrent rotation are component proofs, not physical e2e proofs.
Public SQL, unsigned client bookmarks, caller grants and client transports
belong to Observability 3. Remote packaging and later discovery algorithms
remain outside this phase. Query execution does not claim process-level
crash containment. No new performance experiment or retired 8-GiB
qualification ran.

### Additional correctness checks

Status: **Done, PASS** at source `17d8262e`. The three focused checks, complete
workspace procedure, and standalone command passed after the last code edit.

1. Commit `8126f431` adds `query_follow_autonomous_expiry`. The clock captures
   the idle loop's old sample before a silent advance. The expiry timer returns
   count 0 after count 1, with unchanged storage and checkpoint revisions.
   The five-second deadline ends before the fifteen-second heartbeat. The
   clock supplies no change notifications. Cancellation releases the input.
2. Commit `1aa326ed` adds `query_scope_native_cancel`. A test-only barrier pauses
   the native scan after its first actual chunk. Cancellation must make native
   execution fail, not only the wrapper's final check. A release acknowledgement
   excludes a barrier timeout as the failure cause. Weak input references then
   expire, full capacity is available, and later intake and a count query pass.
3. Commit `17d8262e` extends the existing eight-case qualification. Its windows
   case checks timer-only expiry. Its bounded-window case consumes a complete
   replacement and checkpoint before each input/output overflow. Only Health
   frames may precede the typed error. The error keeps the previous checkpoint,
   no partial replacement is sent, and the stream closes. Later intake and
   bounded queries pass.

The changes reuse existing owners, clock interfaces, frames, and temporary
stores. The scan barrier and native-error flag compile only in data-crate test
builds. No production behavior or storage format changes. The final Ponytail
review found no blocker in these three checks.

Each command below passed one test, with zero failures. Use the six environment
settings from the final query qualification above:

```sh
cargo test -p araphor-data -p mithril-control -p mithril-node -p mithril-e2e --all-features --lib query_follow_autonomous_expiry -- --nocapture
cargo test -p araphor-data -p mithril-control -p mithril-node -p mithril-e2e --all-features --lib query_scope_native_cancel -- --nocapture
cargo test -p araphor-data -p mithril-control -p mithril-node -p mithril-e2e --all-features --lib query_follow_contract -- --nocapture
```

Logs: `/tmp/araphor-query-timer-proof.log`,
`/tmp/araphor-query-cancel-proof.log`, and
`/tmp/araphor-query-follow-proof-2.log`. The first E2E attempt failed because
the fixture did not create its parent directory. The correction creates that
temporary directory before opening its two stores. No production correction
was required. These are correctness checks, not performance measurements.

Final commands, with the same six environment settings shown above:

```sh
bash .github/scripts/verify-rust-ci.sh
cargo run -p mithril-e2e --bin mithril_discovery_test -- --case query-follow --output-directory /tmp/araphor-query-follow-correctness
```

Both commands exited with code 0. Formatting, workspace compilation, Clippy
with warnings denied, and all-target/all-feature tests passed. The affected
library results were:

| Library | Passed | Failed | Ignored |
| --- | ---: | ---: | ---: |
| `araphor-data` | 141 | 0 | 5 |
| `mithril-control` | 176 | 0 | 2 |
| `mithril-node` | 266 | 0 | 1 |
| `mithril-e2e` | 124 | 0 | 406 |

Other enabled workspace tests also passed. Existing ignored cases remain
unqualified. All eight standalone cases passed, including the added timer-only
expiry and established-stream overflow checks. The receipt records
`ResultTooLarge` and `InputTooLarge`, each with the last complete checkpoint
and a closed stream. The timer-only case records no clock notifications and
unchanged storage. The proof limits from the earlier qualification still apply.

Evidence paths:

- Workspace log: `/tmp/araphor-query-proof-ci.log`.
- Standalone command log: `/tmp/araphor-query-follow-correctness.log`.
- Standalone receipt: `/tmp/araphor-query-follow-correctness/result.json`.

### Consumer-driven follow correction

Implementation: `7b828c0a`. Final code corrections: `11b3a725`.
Qualification: **Done** for scoped correctness. The final workspace procedure
passed after the last code edit.
This correction replaces the task and queue from the earlier proof record.

One QueryStream owns the passive state and the next-frame future. Creation
does not start SQL or require a Tokio runtime. Consumer polling produces each
frame. A paused consumer starts no further evaluation. An admitted native read
can finish; its capacity remains charged until cleanup. Drop requests
cancellation. Checkpoints advance only after the authorized frame is returned.
Polling outside a Tokio runtime returns QueryInvalid. Timer support is required.

Cleanup proof must check both input destruction and reservation release. Input
tables can drop before the native work releases its lease. An expired Weak
reference alone does not prove that full query capacity is available.

Control checks the output deadline on the next request for a frame. It closes
only that read. A quiet read with a pending request remains valid. No separate
producer, output channel or idle cleanup task is required.

Focused checks pass: 131 data query tests, 14 Control gRPC tests and one E2E
test that calls all eight production-owner cases. The standalone `query-follow`
command also passes all eight cases. Its receipt is
`/tmp/araphor-profile-follow.tPl3zk/query-follow-final/result.json`.
The full procedure is `bash .github/scripts/verify-rust-ci.sh` at `11b3a725`.
Its log is `/tmp/araphor-profile-follow.tPl3zk/rust-ci-final-5.log`.
Formatting, workspace check, strict Clippy and all-target/all-feature tests
passed with exit code 0: 1,626 tests passed, zero failed and 544 were ignored.
The counts exclude nested recovery helpers. Ignored tests remain unqualified.
The six environment settings in the profile result apply to this run.
These checks do not add a performance or physical qualification claim.

The cleanup regression fails before the fixture correction and passes after
it. The five `query_follow_wait_` cases also pass. They preserve the original
timeouts and all cancellation and capacity assertions. Logs are
`/tmp/araphor-profile-follow.tPl3zk/query-cleanup-before.log`,
`query-cleanup-after.log` and `query-follow-wait-final.log` in that directory.

### Owner composition result

Source: `be7f411c`. Commit `a4f2cf56` uses one checked selection-key budget.
Commit `c62c5fd9` puts frame production and retained-read checks in one future.
The transport and CLI changes are recorded in the
[client result](../../araphor-observability/phase-3-cli-api-and-console.md#owner-composition-result).
Status: **Done** for scoped correctness.

On 2026-10-07, the affected library command passed with 513 tests, zero
failures and four existing ignored tests. It checked mixed selection bounds,
cancel/revoke/drop during a blocked native read, and capacity release after
native cleanup. The standalone follow command passed all eight cases.
Both standalone commands ran at `36c30113`. The later `be7f411c` correction
copies QueryHealth directly in one test. Its focused check passed. Production
code is unchanged.

Run from the primary checkout with these six settings. The commands use its
default target directory. TMPDIR keeps temporary Unix socket paths short.

```sh
export TMPDIR=/dev/shm CXXFLAGS='-O2 -g0' CARGO_BUILD_JOBS=2
export CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true RUST_TEST_THREADS=1

cargo test -p araphor-data -p mithril-control -p araphor-cli --all-features --lib
cargo build -p araphor-cli -p mithril-e2e --all-features --bin araphor --bin mithril-observability-test --bin mithril_discovery_test
target/debug/mithril_discovery_test --case query-follow --output-directory /tmp/araphor-owner-simplify.ht265y/query-follow
bash .github/scripts/verify-rust-ci.sh
```

Read `/tmp/araphor-owner-simplify.ht265y/focused.log`, `clients-build.log`,
`query-follow.log` and `query-follow/result.json`. These checks use production
owners, synthetic evidence and temporary stores. They do not qualify
performance or physical capture. Existing ignored cases remain unqualified.

The final procedure, `bash .github/scripts/verify-rust-ci.sh`, passed at
`be7f411c` after the last Rust edit. Formatting, workspace compilation, strict
Clippy and all-target/all-feature tests passed with exit code 0. The suite
passed 1,629 tests, with zero failures and 544 existing ignored tests. Counts
exclude nested subprocess helpers. Read
`/tmp/araphor-owner-simplify.ht265y/rust-ci-final.log`. The focused test-only
correction is recorded in `output-test.log` in that directory.

### Accepted simplification result

Source: `667209fe`. The staged-state change is commit `d55d7a75`.
Status: **Done** for implementation and scoped correctness.
QueryYield owns each staged result and checked checkpoint. The last disclosed
checkpoint remains separate. Authorization wakes and native cleanup do not change.

The `query_` filter passes 133 tests. `query_follow_staged_cancel` cancels after
metadata or data, before a checkpoint. It checks the absent checkpoint, fused
closure, input release and available output, evaluation and stream capacity.
The standalone `query-follow` case passes all eight cases. The built native
client case also passes. The six environment settings above apply.
Commands:

```sh
cargo test -p araphor-data --all-features --lib query_ -- --nocapture
cargo test -p mithril-control --all-features --lib client_grpc:: -- --nocapture
cargo test -p araphor-cli --all-features --lib
cargo build -p araphor-cli -p mithril-e2e --all-features --bin araphor --bin mithril-observability-test --bin mithril_discovery_test
target/debug/mithril_discovery_test --case query-follow --output-directory /tmp/araphor-five-cuts.Gor7fD/query-follow
target/debug/mithril-observability-test --case query-trace-client --output-directory /tmp/araphor-five-cuts.Gor7fD/native-client --client-executable /home/navid/go/src/github.com/Ereborlabs/erebor-runtime/target/debug/araphor
bash .github/scripts/verify-rust-ci.sh
```

Use new, empty receipt directories for another run.
Read `/tmp/araphor-five-cuts.Gor7fD/query.log`, `query-follow/result.json` and
`native-client/result.json`. These checks do not qualify performance or physical
capture.

The final procedure, `bash .github/scripts/verify-rust-ci.sh`, passes at
`667209fe` after the last Rust edit. Formatting, workspace compilation, strict
Clippy and all-target/all-feature tests return zero. Across 76 top-level suites,
1,630 tests pass, zero fail and 544 existing tests are ignored. Counts exclude
nested recovery helpers. The affected libraries pass 290 data tests, 166 Control
tests and 58 CLI tests. Ignored cases remain unqualified. Read
`/tmp/araphor-five-cuts.Gor7fD/rust-ci.log`.

### Structural ownership result

Source: `244ac567`. The shared scope is commit `782c80ce`; the follow lifecycle
is commit `be08d303`. Status: **Done** for implementation and scoped correctness.
QueryPlan and query sessions share one immutable client grant. Dependency
selection narrows a separate mutable copy. QueryRun owns Ready, Pending or
Closed. The append position comes from the last disclosed checkpoint.
Current authority checks, retained-read checks and native cleanup remain.

The focused `query_` run passes 135 tests. The final procedure,
`bash .github/scripts/verify-rust-ci.sh`, passes at `244ac567` with exit code 0.
Formatting, workspace compilation, strict Clippy and all-target/all-feature
tests pass. The 76 top-level suites pass 1,632 tests, with zero failures and
544 existing ignored tests. Counts exclude nested recovery helpers.
The data library passes 292 tests, Control passes 166, CLI passes 58 and
the end-to-end library passes 167. Ignored cases remain unqualified.

The standalone `query-follow` command passes all eight cases. `profile-restart`
passes with deterministic profiles qualified and physical profiles unqualified.
The native CLI `query-trace-client` case passes all ten receipt checks. Its
`table.stdout` contains the follow table. Cargo checks and builds use the six
environment settings above. Standalone commands use `TMPDIR=/dev/shm` and
new temporary stores:

```sh
target/debug/mithril_discovery_test --case query-follow --output-directory /tmp/araphor-structure.ZIXAR3/query-follow
target/debug/mithril_discovery_test --case profile-restart --output-directory /tmp/araphor-structure.ZIXAR3/profile-restart
target/debug/mithril-observability-test --case query-trace-client --output-directory /tmp/araphor-structure.ZIXAR3/native-client --client-executable /home/navid/go/src/github.com/Ereborlabs/erebor-runtime/target/debug/araphor
bash .github/scripts/verify-rust-ci.sh
```

Read `query-fixed.log`, `clients-build.log`, `rust-ci.log` and the three
`result.json` receipts in `/tmp/araphor-structure.ZIXAR3/`. Independent source
review finds no issues. No benchmark or physical-capture run is part of this
change. Performance and existing physical-proof limits remain unchanged.

### Field ownership result

Source: `5f885e2d`. The data contract is commit `4fd7b8fe`. Status: **Done**
for implementation and scoped correctness. Sources, contexts and traces each
use `Selection::All` or `Selection::Exact`. Empty Exact lists select no records.
Tenant snapshot resolution, combined key limits and byte limits remain.
Native evaluation and QueryResult use one `Vec<Column>`. Each Column contains
the name and data type. Client metadata keeps its existing annotations.
Private cursor removal, row checks and allocation checks remain.

The data library passes 294 tests with zero failures and three existing ignored
tests. The eight standalone `query-follow` cases pass. `profile-restart` passes
and qualifies deterministic profiles only. The built native CLI case passes
retry, expiry, cancellation and default table-follow checks. Actual table output
is in `native-client/table.stdout`. No benchmark or physical capture runs are
part of this change.

Logs and receipts are in `/tmp/araphor-fields.9ncVKeNY/`. The build and Cargo
checks use the six environment settings above. The standalone commands use
`TMPDIR=/dev/shm` and fresh temporary stores:

```sh
cargo test --offline -p araphor-data --all-features --lib
cargo test --offline -p araphor-observability -p mithril-node -p mithril-control --all-features --lib
cargo build --offline -p araphor-cli -p mithril-e2e --all-features --bin araphor --bin mithril_discovery_test --bin mithril-observability-test
target/debug/mithril_discovery_test --case query-follow --output-directory /tmp/araphor-fields.9ncVKeNY/query-follow
target/debug/mithril_discovery_test --case profile-restart --output-directory /tmp/araphor-fields.9ncVKeNY/profile-restart
target/debug/mithril-observability-test --case query-trace-client --output-directory /tmp/araphor-fields.9ncVKeNY/native-client --client-executable /home/navid/go/src/github.com/Ereborlabs/erebor-runtime/target/debug/araphor
bash .github/scripts/verify-rust-ci.sh
```

Read `data-tests.log`, `owners-tests.log`, `clients-build.log` and the three
`result.json` receipts. AnalysisStore schema 17 and discovery schema 3 require
a fresh store. Startup rejects unsupported formats without changes to stored
bytes. No migration is part of this change.

The final Rust procedure is **Done, PASS** at `5f885e2d` after the last Rust
edit. Formatting, workspace compilation, strict Clippy and all-target/all-feature
tests return zero. The 76 top-level suites pass 1,637 tests with zero failures
and 544 existing ignored tests. Counts exclude nested recovery helpers.
The end-to-end library passes 167 tests. Ignored cases remain unqualified.
Read `rust-ci.log`. Independent source review finds no required correction.
The existing review guide contains the updated owner flow and test links.

### Production simplification result

Source: `d3c2f276`. Status: **Done** for the four approved production changes
and their correctness checks. Data commit `bff24af9` puts SQL expansion in
InputProjection. AnalysisStore retains snapshot selection, segment reads,
leases, byte limits, cancellation and cursor progress. Binding checks and SQL
event rows use one decoded event. Raw-only reads do not require decoding.
Projection state and rows remain charged to the input limit.

Node commit `a1f76dbf` prepares shared tables once per generation. Each binding
checks its measurements and selected cells. Node finalizes counts and the table
digest once. Control commit `f5f7f5bc` derives role selectors and entry kinds
from completed assignments. Control commit `7a7a6cea` uses borrowed role and
base-rule maps. Validation checks and diagnostic order remain. Commit
`d3c2f276` corrects field shorthand and a local regression-test type. These
changes do not refactor qualification scenarios. Read the
[production review flow](implementation-review.md#production-simplification-review)
for owner lifetimes, invariants and regression links.

The final procedure passes formatting, workspace compilation, strict Clippy
and all-target, all-feature tests. The 76 top-level suites pass 1,646 tests
with zero failures and 544 existing ignored tests. Counts exclude nested
recovery helpers. The data library passes 295 tests. Control passes 168
library tests and 84 policy integration tests. Node passes 272 library tests.
The end-to-end library passes 167 tests. All nine new regressions pass.

The eight standalone `query-follow` cases pass. `profile-restart` passes and
qualifies deterministic profiles only. The built CLI case passes retry,
expiry, cancellation and default table output. Actual output is in
`native-client-final/table.stdout`. The checks use fresh temporary stores.
No store format, BPF or wire change is part of these simplifications. No
benchmark or physical-capture run is part of this change. Ignored cases remain
unqualified.

The build and Cargo checks use the six environment settings above. The
standalone commands use `TMPDIR=/dev/shm`. Logs and receipts are in
`/tmp/araphor-production.9oCkuTHM/`:

```sh
cargo test --offline -p araphor-data -p mithril-control -p mithril-node --all-features --lib
cargo test --offline -p mithril-control --all-features --test policy_compilation --test kubernetes_policy_api --test control_policy_reconciliation
cargo build --offline -p araphor-cli -p mithril-e2e --all-features --bin araphor --bin mithril_discovery_test --bin mithril-observability-test
target/debug/mithril_discovery_test --case query-follow --output-directory /tmp/araphor-production.9oCkuTHM/query-follow-final
target/debug/mithril_discovery_test --case profile-restart --output-directory /tmp/araphor-production.9oCkuTHM/profile-restart-final
target/debug/mithril-observability-test --case query-trace-client --output-directory /tmp/araphor-production.9oCkuTHM/native-client-final --client-executable /home/navid/go/src/github.com/Ereborlabs/erebor-runtime/target/debug/araphor
bash .github/scripts/verify-rust-ci.sh
```

Read `policy-tests.log`, `build-final.log`, `rust-ci-check.log` and the three
final `result.json` receipts. The first two workspace attempts stopped on
Clippy warnings. The final procedure runs after both corrections and returns
zero at the stated source. Independent source review finds no required change.
