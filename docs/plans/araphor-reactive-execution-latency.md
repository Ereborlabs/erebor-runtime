# Araphor reactive execution in milliseconds

Replace repeated source capture, saved-state reconstruction, and per-row
transactions with one retained DataFusion subscription and atomic writes of
changes. This plan records the measured costs and proposes the replacement.

**Measurement record: Done. Proposal 1: Approved; implementation in progress.
Proposals 2 through 6: Not approved; implementation Not done.** The user
approved retained execution state and change inputs, measurement with the
existing workload, and commits. This approval does not include the other
proposals or a storage engine change.

The parent designs are [component ownership](araphor-component-redesign.md),
[packages and jobs](araphor-package-jobs.md), and
[native Graph storage](araphor-graph-storage-reduction.md). The native Graph
storage record already proves its logical payload reduction. This plan
addresses execution and delivery latency.

## Intended end state

Data accepts source data
  -> Query wakes the affected subscription
  -> the retained native DataFusion plan reads one committed source cut
  -> the package receives changed Arrow rows and its committed state
  -> Data commits output changes, state, and progress together
  -> affected query and delivery subscriptions receive the committed changes

Use the native SQL parser, logical planner, optimizer, physical planner, and
execution path. Use the same SDK and publication contract for builtin and
installed packages. Keep Data as the only durable owner.

Proposed performance acceptance targets are:

| Work after the job is ready | Proposed target |
| --- | ---: |
| Data receives a normal source update through durable result commit and local notification handoff | p99 at or below 100 ms |
| Initial Graph build for the existing 1,592-event workload, after admission | At or below 500 ms |
| Prepare and complete the existing 130-row local notification update | At or below 50 ms |

These are proposed verification targets. They are not runtime limits,
quotas, timeouts, or reasons to discard work. They require approval before a
new performance test is added. Millisecond behavior is **Not done**.

Record latency from Data arrival and from the committed source signal.
Record kernel capture and network transit separately when physical tests
measure those boundaries. The current trace starts at the source signal.
A declared SQL window can delay execution until its boundary. Measure
execution latency from that boundary. Remote connector response time is
external to local queue handoff; record success, failure, and unresolved
delivery without claiming an external effect before it occurs.

Admission prepares package code and query plans before a job becomes ready.
Cold image installation and job startup have separate timings. A normal
source update must not compile a component or restore the whole job.

## Proposed event flow

Data commits new source rows or a relevant context change
  -> Data publishes the changed tables, sources, keys, and committed revision
  -> Query wakes subscriptions whose native plans use those inputs
  -> each subscription pins the committed source cut and state references
  -> DataFusion executes input SQL over changed Arrow batches
  -> package physical execution computes changed outputs and tentative state
  -> Data checks authority and the expected committed state at publication
  -> Data commits output changes, state, progress, and replay references once
  -> Query adopts the committed state and publishes the output changes

A declared window closes, or selected rows leave a window
  -> the existing Query window stream emits that semantic change
  -> the same physical execution receives inserted and removed rows
  -> the package changes only affected state and Graph membership
  -> Data uses the same atomic publication path

An invocation fails or its authority changes
  -> Query cancels the invocation and releases its pinned inputs
  -> Data rejects publication of an invalid or stale result
  -> tentative output and state do not become committed state
  -> a retry starts from the last committed cursor and package state

The process restarts
  -> Data opens and checks the committed store
  -> Query restores each active job's cursor and saved state once
  -> Query prepares its plan and runtime before it reports ready
  -> the subscription resumes from the durable change position

The notification query receives new findings or relevant route changes
  -> DataFusion selects routes from one authorized snapshot
  -> Data commits a batch of durable delivery obligations and attempt IDs
  -> the delivery stream sends those prepared attempts in the required order
  -> the live authority check applies immediately before each effect
  -> Data commits completed, failed, or unresolved results as a batch
  -> a restart resumes the same durable attempts under the existing retry rules

No polling loop, periodic discovery clock, artificial batching delay, memory
quota, or package-size cap is introduced. A batch consists of available
committed changes. A real window deadline remains a Query processing event.

## Measured baseline

The source was `2d7d4164b9c2`. The existing
`discovery::packages::required::incident::backlog::follows_wal_backlog` test
used 950 events from one source and 642 from another. It ran the three OCI
Wasm Graph packages through the current physical execution path.

One final instrumented run passed in **121.13 seconds** with
`RUST_LOG=warn`. Data, Query, and the SDK used the existing test profile's
optimization level 1. This is not a release benchmark. Native DuckDB C API
timers separated SELECT, writes, preparation, appends, and transaction
commands. These are wall times inside API calls, not separate CPU or disk
measurements. Rust time includes conversion, checks, allocation, scheduling,
and probe overhead. Child timings are included in their parent timings.

The diagnostic observation cap was 300 seconds. Observation completed in
84.48 seconds, within the original 90-second cap. The diagnostic cap and
all probes were removed. Forty files were restored from exact copies. A
calibration of 100,000 empty calls with four nested scopes took 307 ms.
No estimated overhead was subtracted. Earlier diagnostic runs must not be
combined with the final run.

### Cursor 950

Data published revision 81 at test time 60,873.318 ms. The prior Graph result
selected cursor 941. The invocation for the next result was
`12ef88f3-6d23-4944-985b-1befd85b6c36`.

| Boundary after Data's source signal | Elapsed time |
| --- | ---: |
| Next Graph evaluation starts | 5,603 ms |
| First package runtime starts | 10,608 ms |
| First Wasm function starts | 10,630 ms |
| Graph result commit completes | 13,746 ms |
| Client Follow receives the Graph result | 16,069 ms |

| Sequential work | Time | Measured cause |
| --- | ---: | --- |
| Finish the previous Graph run | 5,603 ms | The subscription is still executing the prior cut |
| Session and physical plan setup | 26 ms | Physical planning itself takes 1.3 ms |
| Capture source and saved calls | 3,663 ms | 1,952 ms writer wait, 1,059 ms DuckDB, about 652 ms other work |
| Register the attempt | 659 ms | 315 ms DuckDB, 325 ms writer wait, about 19 ms other work |
| Input SQL and Arrow work before the first runtime call | 658 ms | Native DataFusion input execution and argument preparation |
| Three package runtime calls | 255 ms | Runtime intervals overlap |
| Finish and convert output | 69 ms | Host processing |
| Final result commit | 2,815 ms | 2,048 ms DuckDB and 766 ms other work |

The direct Wasm calls took 49 ms, 63 ms, and 64 ms. Their complete runtime
calls took 97 ms, 113 ms, and 135 ms. The final Graph input projection took
150 ms within input preparation.

`coordinated_reader` takes the writer mutex before opening the snapshot.
The reader waited behind the other source's Graph commit. Pending raw
projection took less than 0.01 ms at that boundary. Inside source capture,
restoring three saved calls took 1,475 ms: 884 ms DuckDB and 590 ms Rust.
That nested operation executed 105 SELECT statements. The complete captured
read executed 134 SELECT statements.

### Final Graph commit

| Native operation | Count | Time |
| --- | ---: | ---: |
| SELECT execution | 97 | 688 ms |
| INSERT and UPDATE execution | 94 | 327 ms |
| Parse and prepare | 176 statements | 179 ms |
| Append operations, including 29 flushes | 53,080 C API calls | 233 ms |
| CREATE and DROP execution | 22 | 37 ms |
| Transaction commands | 3 | 549 ms |
| Bind, fetch, and other native operations | — | 35 ms |

COMMIT itself took 547 ms. Appender flushes took 134 ms within the append
total. Rust work outside native API calls took 766 ms. Thus the operation
called Graph publication does substantial reading and preparation as well as
writing. Each call's `apply_output` interns records from the complete Graph
input manifest again.

### Notification processing

One 130-row update took **41,091 ms**: **38,316 ms inside DuckDB** and
**2,774 ms outside it**.

| Operation | Count | Time |
| --- | ---: | ---: |
| SELECT execution | 3,529 | 14,943 ms |
| INSERT and UPDATE execution | 2,600 | 12,521 ms |
| Transaction commands | 6,642 | 8,885 ms |
| Parse and prepare | 803 statements | 877 ms |
| Fetch, bind, and other native operations | — | 1,091 ms |
| Rust work outside native calls | — | 2,774 ms |

This update made 650 durable metadata commits, five per selected row. COMMIT
calls took 5,208 ms. One row caused about 27 SELECT executions and 20 write
executions. The first nonempty 138-row update took another 14,342 ms:
7,791 ms DuckDB and 6,552 ms other work. These intervals overlap other
subscriptions and must not be added to total test time.

Across the complete test, the owners made 769 durable metadata commits,
1,459 subscription dependency checks, and 1,477 source captures. A metadata
commit broadcasts a revision to other subscriptions. The native Graph
function is not the largest measured cost.

| Whole-test milestone | Time from start |
| --- | ---: |
| Fixture, policy, and node setup ready | 12.978 s |
| Both initial source uploads complete | 32.795 s |
| Client subscriptions open | 32.813 s |
| Cursor 950 source signal | 60.873 s |
| Cursor 950 Graph result committed | 74.619 s |
| Cursor 950 Graph result received | 76.943 s |
| Complete incident result observed | 117.297 s |
| Owners stopped | 121.100 s |
| Test finished | 121.130 s |

## Expected effect of the six proposals

The earlier plan gave targets without estimating each saving. The table
below separates measured work from provisional replacement costs. Estimates
apply to the existing incident workload after job admission. They are
engineering assumptions, not measured speed gains or a validated p99.

| Proposal | Measured work addressed | Provisional cost after the full change | Estimated reduction in that work |
| --- | ---: | ---: | ---: |
| 1. Retain execution state and consume Arrow changes | 2,456 ms for saved-call restore, input preparation, package runtimes, and conversion | 10–80 ms | About 2.38–2.45 s |
| 2. Use one atomic change commit | 659 ms attempt registration plus 2,815 ms result commit | 10–50 ms combined | About 3.42–3.46 s |
| 3. Use a batch outbox | 41,091 ms for the 130-row update | 50–250 ms | About 40.84–41.04 s |
| 4. Use independent snapshots and selective change signals | 1,952 ms writer wait during capture | Remove that gate wait; at most 1 ms assumed for the replacement pin | About 1.95 s in this captured read |
| 5. Apply Graph changes through araphor-graph | 1,333 ms Graph row application inside the result commit | 5–20 ms | About 1.31–1.33 s, already included in proposal 2 |
| 6. Select the durable storage engine | 547 ms for the final Graph COMMIT call | 5–20 ms is a feasibility requirement; no engine has proved it | A conditional 527–542 ms, already included in proposal 2 |

Do not add these savings. Proposal 5 is inside proposal 2. Proposal 6 affects
the transactions in proposals 2 and 3. Shorter earlier executions also reduce
the measured 5,603 ms queue wait and some of the 2,323 ms commit-to-Follow
delay. Neither queue reduction has a separate measured saving yet.

Proposal 1 assumes that a normal invocation receives only changed query rows,
keeps checked state ready, and avoids encoding the full source for every
call. Fixed Wasm call and exchange costs are not yet isolated on the proposed
small input. Proposal 5 requires a new change application algorithm. Moving
code between crates without that algorithm has **zero established saving**.

Proposal 3 requires the complete read and write rewrite. It is not a claim
that transaction batching alone changes 41 seconds to 50 ms. The 650 COMMIT
calls used 5,208.487 ms. Two calls at the same observed average would use
16.026 ms. If all other work stayed unchanged, the update would still use
**35,898 ms**. The 3,529 reads, 2,600 writes, repeated read transactions,
and host work must also be replaced. The 50 ms target is at the aggressive
end of the provisional range and remains unproved.

Proposal 2 also depends on real commit latency. If the 547 ms COMMIT time
stayed unchanged, a 100 ms complete path would be impossible even if every
other step became free. This measured COMMIT is not proof of a fixed engine
or device minimum. Less written data and a different transaction model can
change it. The replacement must measure that result with full durability.

Removing the measured Graph queue, source capture, attempt registration,
and final commit would still leave **1,007 ms** of session, Arrow input,
package runtime, and result conversion work. Thus the Data and notification
changes alone do not establish a millisecond Graph path. Proposal 1 must
also reduce the work passed through the packages and their host exchange.

### What the 100 ms target requires

This is one allocation of the target. It states what must be proved; it is
not a prediction. The values are verification targets, not runtime caps.

| Required stage | Proposed maximum in the reference workload |
| --- | ---: |
| Data intake and durable source append | 10 ms |
| Wake and pin the committed source and state | 5 ms |
| DataFusion input SQL and Arrow arguments | 5 ms |
| Combined package execution and exchange on the critical path | 20 ms |
| Validate and durably commit Graph output, state, and progress | 15 ms |
| Route the changed findings and commit the outbox | 20 ms |
| Local handoff and durable delivery outcome | 20 ms |
| Remaining scheduling and handoff allowance | 5 ms |
| Total | 100 ms |

The joint end-to-end measurement must pass. Separate stage percentiles do
not establish the percentile of their sum. Current source-signal timing also
does not measure Data intake before the signal. Retain that distinction.

The first feasibility checks must prove the small durable transaction, the
small Arrow/Wasm input path, and the complete 130-row notification rewrite.
If these checks cannot meet the required stage costs, revise the design or
storage choice before completing the replacement. Do not claim success from
fewer statements or moved code alone.

### The 121-second test is a different interval

The complete test spends 32.81 seconds before client subscriptions open and
about 3.82 seconds after the complete result is observed. If those parts
stayed unchanged, even zero processing time between them would leave about
**36.64 seconds**. Some upload and setup work can also benefit from Data
changes, but its reduction has not been estimated separately.

The six estimates therefore do not justify **121.13 seconds to 100 ms** for
the whole test. The 100 ms proposal applies to a normal event through durable
result and local notification after the job is ready. The initial 1,592-event
Graph build has a separate 500 ms target, also without a validated estimate.
Keep setup, package preparation, source upload, initial Graph build, normal
event latency, and shutdown visible in every later report.

## Recommended replacement

### 1. Retain the execution state and consume changes

Query retains the admitted logical plan and reusable physical execution.
Data owns durable state. A running physical operator holds references to the
last committed state, source cut, package revision, and checked context. It
loads this state once at start or recovery. A normal source update supplies
inserted, removed, or changed Arrow rows and changed context references.

Retain an optimized plan and a physical template where DataFusion permits
reuse. Use its reset or plan creation APIs when an operator has consumed
mutable execution state. Each concurrent invocation has its own task context.
Do not reuse one consumed join or aggregate state across concurrent calls.

Change input means changes to the input query's result. New source rows alone
do not give a correct result for every SQL join, aggregate, or window. Preserve
native SQL semantics. Use existing DataFusion operators and accumulators;
do not add a second incremental SQL engine. Rewrite the builtin input queries
and package state contract to expose the required incremental work. A query
that requires its complete selection continues to execute that selection.

Remove whole prior-call reconstruction from normal `capture_managed` work.
Remove repeated progress-map expansion, copying, and whole-input hashing.
Use a durable input position and package state to identify completed input.
Keep indexed state for records still needed by a window or a future match.
An unwindowed job can retain required indexed state without scanning all of
its history on each event. A proof change or late input still changes every
affected contribution; it does not permit stale evidence.

The SDK must declare and validate change inputs and outputs for any package
that uses this mode. Data must not infer support by matching builtin package
IDs. Native and Wasm packages use the same input, state, and commit contract.
Native execution can borrow Arrow buffers. Wasm encodes the changed input at
the component boundary. Share immutable encoded input when several calls use
the same batch. Do not encode the complete 950-row source for each call.

**Removal:** repeated capture and reconstruction on every event, per-record
progress verification over unchanged input, and builtin-only resume paths.
**Required proof:** append, late input, proof change, window expiry, exact
replay, restart, and native/Wasm behavior remain correct.

#### Retained-state result

**Retained committed state: Done. Change-only package inputs: Not done.
Proposal 1: Not done.** This result covers the working tree based on
`80e0a0b`. The [source review guide](../guides/araphor-retained-execution-review.md)
links the owners and lifetime rules.

Each managed subscription owns one opaque `ManagedExecution`. Data retains
the last committed call inputs, output, checkpoint, and checked Graph
progress. Data checks the current instance, exact call heads, store identity,
recovery epoch, and current package bytes before reuse. A mismatch uses the
existing cold read. Data prepares the candidate in the publication
transaction and promotes the candidate only after COMMIT succeeds. Failed
publication leaves the last committed state unchanged.

The retained evaluation omits its previous checkpoint and previous outputs.
This rule prevents a chain of earlier evaluations. The retained state holds
no source snapshot, task context, database connection, or exchange permit.
Existing Arrow reservations retain their buffer charges. Analysis accounts
for retained metadata through its memory owner. Failure of an enabled
optional reservation drops the cache after a successful durable commit.

The existing incident workload ran twice with temporary probes and a
300-second diagnostic observation cap. The final run removed duplicate
package validation from retained candidate preparation. All 41 affected
source files were restored from exact copies after measurement.
The measurement precedes one mechanical change that groups the retention
argument in the existing `OutputMode`. The final Data tests and clippy cover
that grouping.

| Measurement | Earlier baseline | Final retained-state run |
| --- | ---: | ---: |
| Complete instrumented test | 121.13 s | 143.55 s |
| Observation interval | 84.48 s | 101.36 s |
| Cursor 950 signal to Graph commit | 13,746 ms | 13,661 ms |
| Restore three saved calls | 1,475 ms; 105 SELECT statements | About 300–475 ms on warm reads; 12 SELECT statements |
| Prepare retained candidate | Not present | At most 0.295 ms; no DuckDB calls |
| Graph computations | 3 | 5 |
| Guest calls | 9 | 15 |

The state read is faster. The complete test is slower. These separate runs
do not establish a causal speed factor. The final observation exceeds the
original 90-second cap. Thus this diagnostic run does not qualify the
unmodified incident acceptance test. Complete input selection, encoding,
Graph publication, and notification work remain. No overall speed gain or
millisecond execution is claimed.

Focused verification used these existing production-owner tests:

- Five Data tests passed with the `execution` filter. These tests cover
  failed commit, retry, current package bytes, changed heads, recovery epoch,
  reopen, and tentative-progress cleanup.
- Four serial Graph cases passed: failed-Graph reuse, restart frontier,
  version-flush rollback, and managed rechecks. The empty-history and
  conversion-failure cases also passed separately.
- Clippy passed for Data, Query, and Analysis tests with warnings denied.
- The exhaustive Graph corruption sweep was stopped before completion. Its
  cases remain unchanged. No complete corruption-sweep pass is claimed.
- Full workspace CI was not run. The user requested relevant tests only.

Two existing Graph fixtures required corrections. The conversion fixture
now uses the declared two-column `SubjectChange` schema and still requires
the same terminal failure and absent receipt. The failed-Graph fixture now
compares the produced Complete checkpoint with the saved Complete checkpoint.
It also checks that the resumed Progress checkpoint survives wire decoding.

Local measurement files are in `/tmp/araphor-retain-final-20261030/`:
`run.log`, `detail.txt`, `summary.txt`, `scopes.csv`, and `api.csv`.
The source contains no diagnostic probes or changed observation cap.

#### Declared change-input result

**Generic change inputs: Done. Builtin Graph migration: Not done. Proposal 1:
Not done.** This change follows `621665a6a`. The
[review guide](../guides/araphor-retained-execution-review.md#declared-change-inputs)
shows the SDK declaration, native plans, storage, and replay path.

An opted-in model names ordinary before, after, and reset ports. Query
prepares native row-number windows and anti joins at admission. Execution
reads each target once, binds immutable old and current Arrow batches, and
executes those prepared difference children. NULL rows and duplicate counts
remain correct. Snapshot models retain their complete input behavior.

Data retains the committed full target separately from the delivered input.
Data stores the exact delivered before, after, and reset batches for replay.
The historical base must equal the captured call head. A continuing result
has a complete input basis and a base. A reset has neither. A parameter or
support change resets all pairs and clears prior state. Output evidence
cannot cite historical before rows or the reset flag.

The input identity for a managed after port uses its exact invocation, call,
port, store cut, selected provenance, and window. This path avoids encoding
the full target to obtain its identity. Direct producer inputs retain the
producer revision. Metadata hashing in this input path uses the existing
MessagePack encoder. Unpaired support and Snapshot ports retain row-based
identity. No ABI layout, contract version, quota, or polling loop changes.

Focused verification passed:

- Six Analysis cases cover SQL, Wasm, and native execution; NULL duplicate
  insertion and removal; exact replay; restart; parameter reset; and
  concurrent captures of one plan. All six passed in 74.10 seconds.
- A seventh Analysis case first proves continuation with unchanged support.
  It then changes only support and checks a complete reset, empty before
  rows, cleared prior state, no saved base, and exact replay. This case
  passed separately in 3.97 seconds.
- Six Data cases cover retained-state guards and a changed base/input-basis
  mutation. All six passed in 9.06 seconds.
- Two SDK cases cover invalid declarations, reset rules, evidence rules,
  wire round trips, and state restoration.
- Clippy passed for SDK, Data, Query, Analysis, and the component fixture,
  including tests, with warnings denied.

The native case used the existing source-built component fixture on
`x86_64-unknown-linux-gnu`. Debug sections were removed from a copy of its
library. This reduced that qualification artifact from 178 MiB to 16 MiB.
The unstripped qualification run was stopped before completion. No native
performance factor is claimed from that change.

Native input SQL still selects the current complete target. Native windows
and joins then compute the row difference. Data still encodes the full
target for cold recovery, and Wasm still encodes saved checkpoint values.
These costs remain. The builtin Graph ports still use coupled record/fact
ordinals. Their migration requires stable, complete change units, current
support evidence, and retained contribution indexes. Independent differences
of the present ports would corrupt those references. This result does not
claim a Graph speed gain or completion of proposal 1.

The final instrumented incident run used the same 1,592 source events. The
builtin Graph jobs still use Snapshot inputs. Thus this run measures the
remaining Graph path, not the cost of executing Graph packages on changes.

| Measurement | Earlier baseline | Final change-input source |
| --- | ---: | ---: |
| Complete instrumented test | 121.13 s | 155.52 s |
| Observation interval | 84.48 s | 112.52 s |
| Cursor 950 source signal to Graph commit | 13,746 ms | 15,600 ms |
| Graph computations | 3 | 5 |
| Guest calls | 9 | 15 |
| Prepare retained candidate | Not present | At most 0.303 ms; no DuckDB calls |

The cursor 950 signal occurs at 75,084.871 ms. Its Graph commit completes
at 90,684.507 ms. That commit takes 2,891 ms: 1,824 ms inside DuckDB API
calls and 1,067 ms outside them. The last notification update selects 138
rows and takes 58,090 ms. It makes 690 durable metadata commits. These
notification and Graph intervals overlap; do not add them.

The complete test is slower. The different execution cuts and notification
selections do not establish the cause of that difference. No overall speed
gain is proved. The 112.52-second observation exceeds the original
90-second cap. The diagnostic run uses a temporary 300-second observation
cap and does not qualify the unmodified incident acceptance test. The
temporary cap and probes are removed. All 41 source paths match their exact
copies from before measurement. Scoped formatting and whitespace checks
pass after restoration.

Local measurement files are in `/tmp/araphor-changes-measure-20261030/`:
`run.log`, `detail.txt`, `summary.txt`, `scopes.csv`, and `api.csv`.

Local proof logs are `/tmp/araphor-change-integration-final.log`,
`/tmp/araphor-change-data.log`, `/tmp/araphor-change-sdk.log`, and
`/tmp/araphor-change-clippy.log`. The support proof is in
`/tmp/araphor-change-support.log`. Final Analysis clippy is in
`/tmp/araphor-change-analysis-clippy-final.log`. Full workspace CI was not
run. The user requested relevant tests only.

#### Choice for the remaining Graph work

**Broader design: Not approved. No implementation.** Proposal 1 can retain
package-owned contribution indexes and checkpoint state. A broader option
combines proposals 1 and 5: Graph packages remain pure functions, and Data
owns contribution membership through `araphor-graph`. The broader option
requires user approval. Proposal 5 is not an automatic prerequisite for
proposal 1.

The recommended broader flow is:

Native input SQL selects complete Graph change units
  -> each unit has a stable record key and canonically ordered support keys
  -> prepared native difference plans select affected units
  -> prepared current lookup queries select their support from the same cut
  -> the package computes Graph values for those units
  -> Data replaces each affected unit's contribution in its transaction
  -> shared members remain active while another unit still owns them
  -> Data commits Graph membership, input base, and progress together

For example, two events can own the same process subject. When one event
leaves a window, Data removes that event's ownership. The other event keeps
the subject active. A package output with no Graph values explicitly clears
that unit's contribution. An untouched unit keeps its contribution.

The present [GraphStage::apply](../../crates/araphor-data/src/analysis/graph_rows/stage.rs)
keys active members by producer scope and member identity. The member has
one anchor. That anchor does not identify all contributing units. A new
per-unit ownership index changes the storage algorithm and schema. The
change belongs to proposal 5 even when Data keeps the same transaction.

The proposed owners and changes are:

| Owner | Proposed change |
| --- | --- |
| Query and SDK | Declare current lookup ports and prepare their native SQL after the difference step. Store their delivered inputs for exact replay. Do not compare lookup results as complete support state for reset. Permit a change consumer without a guest checkpoint; Data still retains its committed target and base. |
| Builtin packages | Replace independently indexed record/fact inputs with stable units and current support. Compute only affected contributions. Remove whole-selection progress reconstruction after equivalent proof passes. |
| araphor-graph | Add contribution application keyed by the existing producer scope and stable unit key. Reuse native value identities and shared-member indexes. Do not open or commit a store. |
| Data | Validate the exact source cut, authority, and expected base. Supply its transaction to contribution application. Retain one authoritative versioned membership history. Treat counts as an index over that history. |

Scope each unit by the existing tenant, source, definition, and call pin.
Do not use a bare call number or row ordinal as the durable key. Preserve
current rejection of conflicting values or authority. Select a surviving
anchor from surviving owners without changing its provenance.

The credential input query must update affected old units on removal, late
input, window exit, and proof or context change. A query that selects support
only for new events is incomplete. Native SQL must determine the complete
current unit value before the difference step. Current lookup inputs must
retain the same captured cut and permission checks.

This option removes package-owned whole-Graph checkpoints and their normal
restore path. It must not add another snapshot normalizer or a second
membership history. The existing tests for shared subjects, historical
reads, late input, expiry, evidence, rollback, replay, and restart must pass.
The existing incident workload must measure the result. No saving is proved
for this option yet.

### 2. Replace attempt-first publication with one atomic change commit

An invocation prepares output in memory. Data performs one final authority
and expected-state check, then commits output changes, saved state, progress,
and replay references in one transaction. A crash before this transaction
leaves the prior cursor and state. A retry reuses the existing deterministic
invocation identity and committed input position.

Remove the durable pre-execution attempt write from the normal pure package
path. Keep job lifecycle and failure inspection at their existing owner.
Package computation does not make an external effect; notification delivery
uses the separate durable obligation described below.

Validate immutable package code and schemas at installation or admission.
Retain checked references in the invocation. At commit, check changed keys,
live authority, and expected state versions. An unrelated notification write
must not force a Graph invocation to restore or reject its full input cut.

Stage Arrow changes once and apply table changes in sets. Remove per-call
temporary DDL and repeated metadata SELECT statements. Prepare reusable
storage statements outside normal event execution. Store replay changes once
and refer to retained source segments; do not save another full input copy.

**Removal:** the extra attempt transaction, repeated metadata reads, temporary
tables per Graph step, and full-manifest interning for each call.
**Required proof:** atomic rollback, authority revocation, stale state,
corruption checks, exact replay, and crash recovery remain correct.

### 3. Replace per-row notification transactions with a durable outbox

Use native DataFusion SQL to select new notification obligations from finding
changes and the relevant route snapshot. Resolve the required finding,
policy, route, and destination metadata as a batch. Commit all prepared
obligations and their stable attempt IDs together before delivery.

The transport consumes the durable outbox as a stream. It preserves required
per-key order and performs the live authority check before each effect.
Commit completed, failed, and unresolved attempt results together. This
changes 650 commits for the measured 130-row update to **two notification
batch commits**. The Graph result has its own single atomic commit. These
counts are design targets, not a measured speed factor.

The two-commit target applies to the measured local sink, which returns
immediately. For slow external effects, persist available completed groups
without waiting for another destination. Do not add a timer to fill a batch.

A crash after an effect but before acknowledgement follows the existing
ambiguity and retry rules. Preserve the attempt identity and body. Do not
claim exactly-once external effects. Do not hold Data's writer while calling
a transport. A slow destination must not hold up Graph execution or unrelated
delivery streams. Use existing async streams and task ownership.

An optional later composition can include outbox preparation in the result
transaction when one native query already produces both outputs. Do not add
Graph-specific routing SQL inside Data's storage callbacks merely to save
that transaction.

**Removal:** per-row finding reads, repeated route reads, repeated durable
state transitions, and a synchronous delivery loop on the Graph work path.
**Required proof:** save before effect, cancellation at both existing points,
revocation, ordered delivery, retry, failure, and restart remain correct.

### 4. Open committed snapshots without the writer gate

Data publishes a consistent committed view that includes source positions,
metadata versions, and package state references. Query pins that view.
Opening a read must not take the writer mutex or project raw data into a
catalog before the read can start. Raw segments remain immutable and pinned
for the selected cut. Concurrent writes cannot alter the view's meaning.

Use the storage engine's snapshot support and existing immutable Arrow
ownership. Do not copy the entire catalog or Graph to publish a new view.
Check the source cut, state, evidence, and metadata together. A reader must
not combine old raw positions with new mutable metadata. Prove this before
removing the current coordination gate.

**Removal:** `coordinated_reader`'s writer acquisition and raw projection on
read. **Required proof:** simultaneous source commits, package calls,
retention, authority changes, and historical reads keep an exact snapshot.

#### Publish changes to actual query dependencies

Derive table and source interests from the native logical plan and registered
providers. A result acknowledgement wakes consumers of that result state;
it does not wake an unrelated event-to-Graph subscription. A Graph result
wakes queries that consume the changed Graph relations.

Use existing notification primitives and the durable change position.
Signals can coalesce, but a subscription must read every required change
since its committed cursor. Do not use a replaceable watch value as the only
copy of an input delta. Remove no-op commits and their revision broadcasts.
Keep declared window events in the same Query stream.

Replace separate Graph Evaluate and Expire jobs with the same subscription
execution and semantic window events. Analysis owns start, inspect, stop,
and recovery. It does not own a second Graph scheduler.

**Removal:** global revision rechecks for unrelated changes, metadata feedback
loops, empty expiry publication, and separate Graph lifecycle machinery.
**Required proof:** no lost change, source retirement, context update,
historical query, resume, and window behavior remain correct.

### 5. Apply Graph changes through araphor-graph

The crate currently owns native finding values and selected finding views.
Data still owns most subject, edge, producer, and version code. In the
replacement, araphor-graph owns stable Graph identities, typed node and edge
values, adjacency access, and version membership. It applies explicit changes
through a transaction borrowed from Data. It opens no store and commits no
transaction itself.

Retain the existing native shared values and historical results. Store only
changed facts and membership. Reuse the TerminusDB lesson of immutable facts
and versioned additions and removals. Do not rebuild, compare, or serialize a
complete Graph during publication. A public snapshot is assembled only when
selected. Do not add another parser, planner, aggregate implementation, or
query execution owner. Existing DataFusion providers expose current and
historical Graph relations.

**Removal:** split Graph storage rules, package identity switches in Data, and
complete contribution reconstruction. **Required proof:** selected historical
Graphs, traversal, stable finding identity, exact replay, and reopen remain
correct. This is an ownership and algorithm change; a file move alone does
not satisfy it.

### 6. Select the durable storage engine

Changing the engine alone leaves thousands of requests in place. First
define the replacement snapshot and atomic change transaction. Then compare
the same change transaction with durable settings on the candidate engines.
Do not weaken durability to meet the timing target.

| Candidate | Proposal | Required evidence |
| --- | --- | --- |
| DuckDB | Retain it only if set writes, retained metadata, and independent snapshots meet the latency target | Exact snapshots across raw and derived state; no writer gate for reads; one small durable commit in milliseconds |
| redb | Evaluate a direct Rust transactional store for canonical Data metadata, Graph, state, progress, and outbox | Snapshot reads during writes, atomic multi-table changes, durable reopen, indexed historical reads, and measured commit latency |

DuckDB documents MVCC and concurrent work within one process. Its support
does not justify our application-level writer gate for all reads. The trace
measures the cost of our requests; it does not establish an irreducible
engine cost. See [DuckDB concurrency](https://duckdb.org/docs/1.5/connect/concurrency).

redb documents a pure Rust store with copy-on-write B+trees and concurrent
read transactions during writes. It still has a single writer. Its APIs and
durability model are candidates, not proof of this workload's speed. See the
[redb design](https://github.com/cberner/redb/blob/master/docs/design.md),
[database API](https://docs.rs/redb/latest/redb/struct.Database.html), and
[durable transaction API](https://docs.rs/redb/latest/redb/struct.WriteTransaction.html).

An engine replacement moves every record that must commit atomically to the
chosen store. Do not split authoritative state and progress across DuckDB
and a key-value store. DataFusion remains the SQL engine. OCI artifacts and
raw segments can remain immutable files referenced by the transaction. Reuse
existing typed binary and Arrow formats; add no JSON storage, legacy decoder,
development version bump, or application compaction task as a latency fix.

## Ownership after the replacement

| Owner | Responsibility |
| --- | --- |
| araphor-query | Native SQL stages, retained physical execution, change inputs, windows, and result streams |
| araphor-package-runtime and SDK | One package contract, Arrow exchange, explicit saved state, native/Wasm adapters |
| araphor-graph | Native Graph values, adjacency, changes, and historical membership through Data's transaction |
| araphor-data | Source cuts, the only durable transaction, state, progress, outbox, and committed change publication |
| araphor-analysis | Job admission, lifecycle, subscription task collection, and transport wiring |
| Control and the existing authority owners | Admission and live effect authority; final commit and delivery checks |

## Work order and approval

1. Review the complete flow, transaction contents, SDK changes, and code to
   remove. Record every changed owner and the DataFusion or dependency API
   used. Resolve snapshot consistency and delivery recovery before code.
2. Propose the release qualification workload, runtime, and pass/fail values
   for approval. Use normal Rust tests and existing Mithril E2E owners.
3. Prove the small durable transaction, changed Arrow/package input path,
   and 130-row local notification path. Record their measured costs against
   the required stage values. Select one engine before production ownership
   is changed. Revise the design if these checks cannot support the target.
4. Replace source capture, package state exchange, and Graph publication with
   the retained plan and atomic change path. Include selective notifications.
5. Replace notification processing with the batch outbox path. Its measured
   41-second cost makes this the first user-visible result to qualify.
6. Remove each old path only after its replacement preserves the existing
   correctness tests. Record removed production code and remaining duplicates.
7. Run the original incident behavior checks and approved release timing
   qualification. Stop when the targets and feature preservation both pass.

Before each implementation deliverable, the implementer proposes its types,
owners, data flow, removed code, and reused native APIs to the change reviewer.
The reviewer must challenge unnecessary work and duplicate implementations.
Implementation starts after agreement and the user's required approval.
Agreement does not make the unapproved proposals in this file approved.

Arbitrary user SQL and arbitrary package code can require work proportional
to their selected data or output. Preserve those queries and report their
cost. The builtin incident jobs must use incremental inputs and indexed
state. Do not claim constant-time execution by dropping input, hiding backlog,
changing window behavior, or weakening tests.

## Evidence and current result

The durable measurement record is the baseline tables in this file. Local
trace and source probe artifacts are:

- `/tmp/araphor-measure-20261030-complete.log`
- `/tmp/araphor-measure-20261030-complete-detail.txt`
- `/tmp/araphor-measure-20261030/scopes.csv`
- `/tmp/araphor-measure-20261030/api.csv`
- `/tmp/araphor-measure-20261030/probes.patch`

The probe patch passed `git apply --check` after exact source restoration.
The current code does not contain the probes. No release result or measured
speed factor is claimed for the proposed replacement.

**Recorded measurements: Done. Retained committed state: Done. Proposal 1:
Approved and Not done. Millisecond execution: Not done. Proposals 2 through
6: Not approved and Not done.**
