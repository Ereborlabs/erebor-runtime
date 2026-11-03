# Araphor reactive execution in milliseconds

Replace repeated source capture, saved-state reconstruction, and per-row
transactions with one retained DataFusion subscription and atomic writes of
changes. This plan records the measured costs and proposes the replacement.

## Current approval on 2026-11-03

All six proposals and further component rewrites are approved when they
improve the existing live subscription test by 100 times. This approval
supersedes the earlier approval limits in this file. Preserve those older
records as history. The target is **Not done** until comparable completion
of the same workload proves the improvement.

The qualification owner is
`discovery::packages::required::incident::incremental::follows_incremental_sources`.
The workload has four sources, 4,096 initial events per source, and eight
later arrivals: 16,392 events in total. Run only this live test during the
performance work. Preserve its inputs, assertions, progress gates, native
finding identities, notification references, and source isolation.

Use the native DataFusion SQL parser, logical planner, optimizer, physical
planner, and execution. Keep subscriptions reactive. Use committed journal
positions for change detection. Compute and store changes incrementally.
Preserve authorization, attribution, atomic commits, and recovery. Remove
unnecessary hashes, serialization, repeated planning, and data copies from
this path. A crate replacement is permitted when this path requires it.

Record actual elapsed seconds for each measured section after each run.
State the source change and compare the same before and after boundaries.
Identify nested or concurrent intervals and any unmeasured time. Counts,
partial runs, and build times do not prove the 100-times target.

### Live physical planning measurement

**SQL dependency reduction: Done. First finding and 100-times target:
Not done.**

Both runs use the same live test and debug filters. The second run changes
only the Graph unit selection SQL. It joins grouped fact keys at the final
support aggregate. Credential support does not use those keys. The earlier
join caused native planning to repeat the unused fact subtree in each
credential support branch. The final join preserves the native record key,
left-join behavior, empty fact list, support values, and final ordering.

| Boundary | Before | After | Reduction |
| --- | ---: | ---: | ---: |
| External test process | 700.392 s | 568.844 s | 18.8% |
| Configuration | 276.179 s | 224.314 s | 18.8% |
| First large physical plan | 264.533 s | 213.609 s | 19.3% |
| First-event observation (failed) | 422.111 s | 342.397 s | 18.9% |
| Second large physical plan | 412.305 s | 333.745 s | 19.1% |
| Pipeline shutdown | 1.506 s | 1.525 s | 1.3% increase |

The internal total changes from 700.340 s to 568.792 s. Inclusive startup
changes from 276.721 s to 224.869 s. Listening changes from 0.240439 s to
0.240901 s; subscription setup, 0.067043 s to 0.067145 s; policy setup,
0.220392 s to 0.230873 s; and OIDC shutdown, 0.000213 s to 0.000218 s.
Startup includes configuration, listening, subscription setup, and policy
setup. The internal total includes all test sections.

The first physical plan is inside configuration. The second physical plan
is inside first-event observation. Do not add these nested values to the
process time. The two large physical plans do not overlap. Both runs fail
before the first Graph publication, finding, and notification. The bulk
events and eight later arrivals do not run. These results do not establish
completed-workload throughput or event latency.

The measured source includes the connected native record-identity changes.
The separate SQL commit applies the same join movement to its parent
record-row keys. It does not commit those unrelated identity changes.

The logs are `/tmp/araphor-live-baseline-20261103.log` and
`/tmp/araphor-live-fact-keys-20261103.log`. Their paired `-timing.txt` files
record external process time. The builds take 198.762 s and 242.366 s.
Build time is outside both test measurements.

A separate debugger run of the exact same test samples native physical
planning. The active Query thread computes join statistics inside native
`EnforceDistribution`. The stack contains 829 frames. DuckDB is idle in
that sample. This sample identifies active work; it does not measure the
whole duration of that work. The source and summary are in
`/tmp/araphor-live-fact-keys-gdb-exact-20261103.log` and
`/tmp/araphor-live-fact-keys-stack-summary-20261103.txt`.

### Retained join ordering measurement on 2026-11-03

`SourceJoin` no longer adds native output requirements to every retained
probe subtree. Real package arguments keep their `PackageExec` wrappers.
The native optimizer still enforces SQL and package ordering requirements.
The first join-orientation traversal remains.

The connected first-plan time falls from 253.668 s to 223.212 s. Setup takes
235.576 s, including configuration at 235.006 s and the first physical
plan. The attempt stops after 425.979 s during its second plan. No finding,
bulk result, or warm-arrival result is produced. The build takes 189.707 s.
The log is `/tmp/araphor-live-join-order-20261103.log`.

The paired completed setup stages are: configuration 265.085 s to
235.006 s; listening 0.254317 s to 0.254086 s; subscriptions 0.073497 s to
0.070954 s; and policy 0.238808 s to 0.229004 s. Inclusive startup falls
from 265.666 s to 235.576 s. The externally interrupted totals are
556.405 s and 425.979 s. These totals do not compare completed tests.
The second-plan, event-observation, and shutdown durations are unknown.

The measured source contains the recorded native optimizer and identity
work. The isolated commit preserves its parent's first traversal and removes
only the second traversal. This measurement does not qualify that isolated
commit alone. Completed-workload qualification and the 100-times target
remain **Not done**.
**Measurement record: Done. Proposals 1 and 5: Approved; implementation in
progress. Proposals 2, 3, 4, and 6: Not approved; implementation Not done.**
The user approves retained execution state, change inputs, contribution
ownership through `araphor-graph`, measurement with the existing workload,
and commits. Completion requires measured reductions in input/package work
and Graph application work. This approval does not include the other
proposals or a storage engine change.

The parent designs are [component ownership](araphor-component-redesign.md),
[packages and jobs](araphor-package-jobs.md), and
[native Graph storage](araphor-graph-storage-reduction.md). The native Graph
storage record already proves its logical payload reduction. This plan
addresses execution and delivery latency.

## Multi-source incremental qualification

**User request: Approved. Implementation and qualification: Not done.**

The user removes the old 1,592-event backlog test. Its Rust file and its
private backlog helpers are removed. The recorded results below remain
historical evidence. They do not qualify the replacement test.

The replacement is a normal Rust test in
`crates/mithril-e2e/src/discovery/packages/required/incident/incremental.rs`.
It uses four sources with 4,096 initial events per source. Each source first
receives one denied event. Its work is observed before the source grows.
Two later rounds append one denied file-read event to each source.
Most initial events have different process and task identities. A new event must not require the
complete source history as causal support.

Node appends an event to its WAL
  -> authenticated Control intake commits the event to the central journal
  -> Query notifies the subscriptions that depend on the changed data
  -> the subscription creates its task context for the committed source cut
  -> DataFusion executes the prepared native plan with that context
  -> native affected-key and support queries select the required rows
  -> the package computes the affected Graph contributions
  -> Data commits changed contributions, references, and progress together
  -> the Follow streams expose the Graph, finding, and notification

The test sends events through the real Node WAL and authenticated intake.
It receives event rows, small Graph header rows, finding rows, and notification
rows through public Follow subscriptions. It does not call a journal point
reader, a Graph getter, managed history, or the notification Router. Journal
reads belong to the running native subscription plan. The test compares the
ordered event stream with the exact uploaded bytes and journal positions.
It checks stable native finding value IDs and source isolation. It does not
subscribe to a complete serialized Graph payload.

A stored notification reference can remain at its original publication when
the finding value does not change. Each new finding must arrive through the
notification subscription with its actual publication reference.

The test checks the actual source and Graph input work. A small guest input
does not prove that Query avoided a complete source scan. Continuing calls
must use their exact prior result as the change base. An unrelated source
must keep its committed Graph head. Stored contributions for untouched units
must keep their existing membership intervals.

Use native DataFusion metrics and normal structured debug events for work
counts. Preserve the current trace dispatcher across existing task and
blocking boundaries. The test uses a local telemetry subscriber. Do not add
a host getter, a durable input or output copy, a second Graph state owner,
or timer polling. No new elapsed-time pass/fail limit is part of this
functional test.

The working replacement uses native logical children for affected records,
facts, and scalar window state. The old six-query capture and complete Graph
reconstruction are removed from that path. The obsolete whole-input
`GraphFacts::facts` callback is removed. The domain fact resolver remains.

The replacement is **Not done**. The frozen coverage merge must preserve
each required report and its qualification. Finding and notification reads
still expand complete provenance. The replacement must select the actual
finding's owning units. Native source read counts must be bounded. A small
returned batch does not prove bounded work.

The test waits for the exact Graph publication, its captured revision, the
completed source reads, and the completed subscription execution. It checks
changed package units and native membership writes. It also checks the
complete journal frame's record count and body bytes against the actual
single-event upload. The test does not accept an arbitrary multiple of the
cold work count.

Source checkpoint on 2026-11-01:

- `cargo check -p mithril-control --tests --message-format=short`: passed
  without warnings. This check covers Query, Data, Analysis, Control, and
  Control tests at that checkpoint. It does not cover the later source fixes
  or the Mithril end-to-end test.
- Data `historical_call_members_require_unit_anchors`: passed.
- Data `graph_reopen_`: both selected-call recovery and corruption rejection
  passed. The corruption case rejects incorrect native captured revisions.
- Control `managed_captures_control_proofs`: failed before execution because
  the coverage adapter tried to replace the protected `events` source. The
  working correction uses a private view and a native SQL CTE. Qualification
  of that correction is **Not done**.
- The four-source end-to-end test has not passed. No new latency or speed
  improvement is proven.

Source checkpoint on 2026-11-02:

- `cargo check -p araphor-analysis -p mithril-e2e --tests --message-format=short`
  passed without warnings before the later test and diagnostic edits. This
  result does not qualify the current four-source test.
- The focused Analysis run passed `native_projection_keeps_policy_values`.
  `keeps_frozen_coverage` failed during native SQL planning. The fixture now
  uses equivalent explicit join conditions. The retry passes that point, but
  fails at the source-port key schema check.
- The same retry built the Control test executable. Its direct
  `managed_captures_control_proofs` run also failed at the source-port key
  schema check. No Graph execution or coverage result is proven by these
  failed runs.
- The four-source subscription test remains **Not done**. Native coverage
  invalidation, frozen report reads, and the work bounds remain **Not done**.
  No new end-to-end latency, speed factor, or millisecond result is proven.

The next connected run built the selected Analysis, Control, and Mithril
end-to-end test executables in 3 minutes 3 seconds. The projection case passed.
Initial Graph preparation then used one CPU core for more than 12 minutes.
The run was stopped for diagnosis. The other selected cases did not run.

Two debugger samples of the same focused case identify repeated native-plan
work before package execution. One sample traverses native physical-plan
invariant checks. The other hashes nested `SourcePort` children while
`prepare_on` prepares `graph-settings`. The DuckDB worker is idle in the
physical-plan sample. The samples are in
`/tmp/araphor-frozen-child-stack-20261102.log` and
`/tmp/araphor-frozen-caller-20261102.log`. A working correction carries
resolved rows through coverage qualification and removes the second resolver
subtree and its identity join. Runtime qualification is **Not done**.

The native prepared-query probe now executes all five corrected point
queries. The finding queries required an equivalent derived join because
DuckDB rejected a correlated subquery in their outer join. Indexed member
candidates read the requested identity's history. Evidence, source-version,
and context-reference joins still read unrelated rows. This probe uses
synthetic native rows. It does not qualify Rust authority checks or complete
incremental execution. The exact SQL, plans, failures, and correction are
recorded in `/tmp/araphor-five-point-query-review.md`.

## Journal positions for change detection

**User request: Approved. Implementation and qualification: Not done.**

Change detection must use committed journal positions and explicit change
records. Do not hash input rows, output rows, or state to find changes. Do
not create object IDs from content hashes. Hashing is prohibited unless a
specific operation requires it.

Data appends records and commits the journal position
  -> Query receives the commit notification
  -> Query reads changes after the subscription's last committed position
  -> the saved native DataFusion plan consumes those changes
  -> the package returns changed contributions
  -> Data commits those contributions and the new progress position together

Execution or commit fails
  -> the subscription keeps its previous committed progress position
  -> retry reads the same journal range
  -> Data preserves the existing transaction and duplicate-call checks

Working changes remove Query result fingerprints, managed result hash IDs,
Graph member hash keys, and Graph input content revisions. The end-to-end
test compares exact bytes received through subscriptions. Source-key
lookups, generic input receipts, and native value interning still require
completion and focused qualification. No complete hash audit or new speed
improvement is proven at this checkpoint.


### Current change audit on 2026-11-02

Native Query output delivery no longer hashes result rows. Managed result
IDs use the committed publication and call positions. Discovery instance
identity uses its existing source key. Native Graph property and edge
values use exact native keys. Finding values use indexed candidates and
full typed equality. Package context keys use native package metadata.
The retained package-validation cache and its content fingerprints are
removed. These changes have focused owner checks. They do not qualify
complete incremental Graph execution.

The unused Node fixed-sequence window owner and its content-derived
observation and revision IDs are removed from the working source. Node
keeps kernel CPU and sequence coordinates. `EvidenceWal` allocates a
separate durable cursor. The historical ownership and current deletion
checks are in the
[dated evidence review update](mithril-hugging-face-intrusion-prevention/phase-6-implementation-review.md#journal-position-update-on-2026-11-02).

Remaining hash removals include Graph package state, public finding IDs,
Discovery definition revisions, and derived workload and source IDs. OCI
blob validation, signed policy and catalog integrity, and WAL corruption
checks have separate integrity requirements. An integrity check must not
be used as a change detector. The complete hash audit is **Not done**.

A 90-second diagnostic run of `keeps_frozen_coverage` records 135 native
Control-source compilations and 55 Status-source compilations during
initial preparation. The run ends at its diagnostic cutoff. Control header logical optimization takes 7.549 seconds
in total. Status header logical optimization takes 14.726 seconds. These
are observations from one partial run, not a work bound or event latency.
Nested physical-planning scopes overlap and must not be added together.
The trace is `/tmp/araphor-cdc-source-plan-profile-20261102.log`.
Complete Graph preparation and the four-source subscription test remain
**Not done**. No new end-to-end speed factor is proven.

## Intended end state

### Central journal references

The user requires removal of saved package input, output, selected-result,
and source-capture payloads. A call records its package revision and source
time. Source time identifies the committed data visible to the call. It does
not identify the call's complete input. SQL determines that input.

Data commits a source event
  -> the subscription receives the committed source position
  -> native DataFusion executes the admitted SQL at that source position
  -> the package consumes the query result
  -> Data commits the call reference and its canonical produced data
  -> the subscription advances after the commit succeeds

A caller requests replay or restart recovery
  -> Data checks the retained call, package, source, and authority references
  -> Query reads the referenced central journal and immutable context versions
  -> native DataFusion reconstructs the inputs at the recorded source time
  -> execution reconstructs required prior state through recorded calls
  -> replay returns data without publishing a second result

Required source data is no longer retained
  -> replay reports the missing or expired source range
  -> replay does not substitute current data

Remove `managed_arrow` and its payload writers, readers, source IPC records,
and payload accounting. Do not move those copies into another table or blob.
Preserve the existing canonical Graph, finding, notification, package, and
context owners. Their committed data can be referenced by a call.

**Journal-reference replacement: Done.** The user
authorizes this work after the checkpoint at `ef8024ed7`. The payload-based
replay and recovery results later in this document describe the old
implementation. They do not define the new storage requirement.

The checked metadata lookup is implemented by `AnalysisStore::managed_reference`.
It returns the recorded request, source cut, call ID, receipt, and historical
definition. The lookup does not read an Arrow payload or admit publication.
The lookup does not execute a package.

The source removes `managed_arrow`, saved evaluations, saved outputs,
selected payloads, source IPC records, and their accounting. Each call stores
one optional declared checkpoint as its canonical state. Each selected result
stores its receipt, row count, and dependencies. Its body is
empty. Temporary Arrow batches remain in live execution and Replay memory.
They do not persist after a process restart.

Remove the unused source metadata cache and the saved projection contract.
The native query derives its projection from the recorded grant. Keep the
source cut, row identity, schema, and authority checks. The change must remove
production Rust in total. Count production and test code separately. Exclude
blank lines. Use existing execution, restart, replay, and expiry tests. Do not
add a test that only calls a helper with an invented result reference.

Retire the unused host output aliases and local result wrapper. Their earlier
saved-output contract is superseded by reference-only Inspect and explicit
Replay. Remove the automatic producer-replay bridge added for those aliases.
Keep native SDK output dependencies and the local stream used by the context
owner. Keep real lifecycle, replay, source expiry, and permission checks.

Replay uses the original native query, package pins, source cut, invocation
time, and seed. Native source, processor, result-notice, and trace histories
provide administrative values at that cut. Current revocation checks still
apply. Retired event headers preserve acceptance and retention metadata. The
headers do not replace missing event bytes.

**Payload-removal qualification: Done.** Existing Data tests cover source
history, metadata, scope, atomic publication, checkpoints, and empty selected
bodies. Existing Query tests cover the original journal cut, source witnesses,
notification deadlines, and reactive windows. Existing Analysis tests cover
SQL, Wasm, native execution, previous outputs, restart, expiry, and revocation.
The Graph reset Replay case passes with the original input revisions and
coverage for all three detectors. The
[verification record](../guides/araphor-retained-execution-review.md#qualification)
states the source boundaries and exact results.

Final scoped formatting and Clippy pass for the nine affected crates. Clippy
denies warnings and includes their test targets. The full workspace procedure
is not run under the user's relevant-test instruction. No new event latency
or storage-size result is claimed. The Graph functional check takes
2,683.70 seconds; it does not prove millisecond execution.

The complete change from `3f9bbd3a4` removes 10 nonblank production Rust lines
and 607 nonblank test lines. These are separate totals. They include the
necessary history and replay code, the retired storage APIs, and the removed
host aliases. Blank lines do not contribute to either total.

The user approves reference-only Inspect operations. Inspect returns the call
and source references. Explicit replay uses Run permission and reconstructs
data from the journal. Inspect does not execute package code. Remove the
Inspect query operation that reads saved output rows. Keep one metadata read
owner for call and selected references. This approval does not permit current
administrative state to replace missing historical source state during replay.

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

## Current incremental requirement

**Query, execution, and Graph changes: Not done.** The user requires
incremental computation and storage throughout proposals 1 and 5. Reading
the complete current input and then computing its difference does not meet
this requirement. The complete-target flows and their results below record
earlier implementations. They do not define the required final behavior.

The local TerminusDB source supplies these concrete lessons:

- [Layer queries](../../terminusdb/src/rust/terminusdb-store-prolog/src/layer.rs)
  use stable value IDs and separate addition and removal iterators. Bound
  subject, predicate, or object keys select the corresponding index.
- [Layer builders](../../terminusdb/src/rust/terminusdb-store-prolog/src/builder.rs)
  apply additions and removals against a parent layer.
- [Query compilation](../../terminusdb/src/core/query/woql_compile.pl)
  compiles addition and removal queries to these change readers. It does
  not discover changes by comparing two complete query results.

Reuse these rules with Arrow, native DataFusion plans, and Data's existing
transaction. Do not add a second durable store or a second SQL engine.

Data receives changes after the last committed input cut C
  -> Data captures changed raw, context, proof, and coverage inputs through R
  -> Query prepares a candidate over the retained indexed view at C
  -> native SQL selects affected keys from old and new dependencies
  -> native SQL reads only the changed roots and required indexed support
  -> the same package executor receives exact before, after, and support rows
  -> Data commits typed changes, Graph membership, and input cut R together
  -> Query promotes the candidate view only after that commit is acknowledged

A window closes or removes selected rows
  -> the existing Query window stream supplies the affected keys
  -> the same candidate and publication path applies those changes

Publication fails or the process restarts
  -> failed publication leaves input cut C and its indexed view unchanged
  -> restart loads the committed base and typed change records once
  -> execution resumes with changes after the recovered committed input cut

The input cut differs from the output commit revision. Later arrivals stay
outside R. Concurrent captures must not combine different cuts. Do not
promote a source cursor or mutable input index before publication succeeds.
Retain row counts, reservations, and dependency indexes. A normal update must
not rebuild complete witness lists, input hashes, target Arrow payloads, or
Graph metadata. Preserve exact replay through typed base and change records.

Affected keys include prior dependents and new join candidates. Late input
can create a new match that no prior unit referenced. Use stable record and
context keys at the index boundary. Use local Arrow row indexes only within
the selected package input. A global proof or sensitivity change can affect
all units; an unrelated append does not justify reading all prior records.

Ordinary SQL subscriptions and package inputs must use the same source-change
machinery. Native joins, groups, outer joins, aggregates, and windows must
retain their SQL meaning. An unsupported incremental plan must remain an
explicit implementation gap. A complete-query fallback does not qualify as
incremental execution. Finite snapshot queries retain their native results
and output order.

The first implementation prerequisite is a managed read of the existing raw
change journal. This prerequisite does not complete the context and coverage
feed, indexed native execution, Graph integration, or either proposal. The
reviewer must approve the concrete next source contract and state lifetime
before implementation. Proposals 2, 3, 4, and 6 remain unapproved.

### Managed raw-change read result

**Managed raw-change read prerequisite: Done. Complete incremental Query and
Graph execution: Not done. Proposals 1 and 5: Not done.** This change follows
`516c1fdd`. The
[review route](../guides/araphor-retained-execution-review.md#committed-raw-changes)
links the current owners and tests.

Data accepts a managed `Changes` read after a complete committed input
position. The existing raw journal selects additions and retirement ranges
through the captured revision. The same transaction checks the instance,
grant, generation, lifecycle, call heads, and replay floor. The returned
capture keeps its exact source interests and witnesses. Reading does not
advance durable progress or execution state.

The read rejects relations and explicit input selections that its early
change return cannot supply. Current source metadata remains current
metadata. A dependency-only context request does not read context rows.
An unselected all-context scope is pruned before key resolution. Its original
source interest remains in the sealed capture. The read does not introduce a
new cursor, storage engine, quota, format version, or polling task.

Four new managed journal tests and ten existing raw-change, managed-owner,
and retained-state tests pass. The managed tests cover arrivals after a fixed
snapshot, late gap repair, idle reads, unsupported requests, stale owners,
cancellation, retirement, replay floors, and reopen. The context regression
uses the existing optional key configuration to prove that unrequested
context keys are not resolved. It adds no default limit or performance test.
The proof log is `/tmp/araphor-managed-journal-final-20261031.log`.
Data clippy passes with tests and warnings denied. Scoped formatting,
whitespace, and document-link checks pass. The clippy log is
`/tmp/araphor-managed-journal-clippy-20261031.log`. Full workspace CI was
not run. The user requires relevant checks only.

The Graph caller still uses complete captures. Context and coverage change
feeds, the shared explicit delta-source contract, indexed native execution,
commit-only candidate promotion, and changed Graph metadata remain open.
This prerequisite proves no reduction in incident latency. The recorded
243.94-second diagnostic remains the latest full incident measurement.

### Context-version change read result

**Context-version change read: Done. Complete incremental Query and Graph
execution: Not done. Proposals 1 and 5: Not done.** This change follows
`e80f918fd`. The
[review route](../guides/araphor-retained-execution-review.md#committed-context-changes)
links the reader and its tests.

Data receives a managed or ordinary change read after committed input cut C
  -> Data resolves source keys without expanding the context history
  -> the native revision index selects new context key headers through captured cut R
  -> Data checks tenant, owner, and exact-key scope before it reads a value
  -> the existing verified context reader fetches each selected value by its unique key
  -> Data checks the key, header revision, value revision, and package provenance
  -> Data returns every selected immutable version and its exact reference

The reader uses the same captured transaction for headers and values. Future
arrivals remain outside R. Versions with past or future validity remain in
the change feed. Native SQL can select the required validity later. Reading
does not advance durable progress. Failed reads and cancellation leave the
committed input cut unchanged.

The revision index is installed at store open. The value lookup reuses the
existing decoder and provenance owner. The change adds no storage format,
engine setting, input cap, cache, or timer. The configured key count includes
source, trace, and binding keys. Temporary decoded values release their
memory charge after Arrow and references retain their own allocations.

Seven context tests pass. The tests include both native index statements,
six selected keys in reverse exact-scope order, excluded invalid values,
fixed cuts, validity, corruption, cancellation, enabled limits, and reopen.
The index proof covers the tested source state. DuckDB retains its native
access-path choice. The proof log is
`/tmp/araphor-context-changes-final-20261101.log`.

Fourteen related raw-change, managed-owner, and retained-state tests pass.
Data clippy passes with tests and warnings denied. Its log is
`/tmp/araphor-context-clippy-20261101.log`. Scoped formatting, whitespace,
and 78 local document links pass. Full workspace CI was not run. The user
requires relevant checks only.

The Graph caller still reads complete inputs before it computes differences.
Coverage changes, the explicit delta-source contract, indexed native Query
execution, and Graph integration remain open. This reader alone proves no
incident latency improvement.

### Managed input-frontier result

**Exact binary input frontier: Done. Incremental source execution: Not done.
Proposals 1 and 5: Not done.** This change follows `ad4aad54b`.

A managed subscription captures input through transaction revision R
  -> Query stores input position `(R, u32::MAX)` in the offered frontier
  -> the existing Data publication can acknowledge output commit P
  -> Query emits input position R and publication revision P as separate fields
  -> a live or resumed subscription reads input progress from R

This rule applies to Graph and Selected destinations. The previous generic
managed path used P for consumed input. An arrival between R and P could
then appear to be consumed. The resume checks, runtime initialization, and
runtime progress now use the same input rule. Window acknowledgement keeps
its separate publication-revision check.

Cursor storage and source-scope fingerprints use MessagePack through the
existing workspace dependency. Decoding rejects trailing bytes, unknown
fields, invalid versions, invalid window identities, and inconsistent
positions. No JSON fallback or version change is added.

Twenty-six focused Query tests pass: four cursor tests, seventeen managed
capture tests, and five fixed-window tests. The publication test covers
Graph and Selected destinations in live execution and restart from both the
saved frontier and emitted cursor. A context commit after the last raw
arrival precedes R. Another arrival and a context commit occur during the
held publication. The returned input position remains R. The next execution
processes the pending arrival.

The logs are `/tmp/araphor-input-frontier-codec-final-20261101.log`,
`/tmp/araphor-input-frontier-managed-final-20261101.log`, and
`/tmp/araphor-input-frontier-windows-20261101.log`. Query clippy passes with
tests and warnings denied. Its log is
`/tmp/araphor-input-frontier-clippy-20261101.log`. Full workspace CI was not
run. The user requires relevant checks only.
Scoped formatting, whitespace, and 86 local document links pass.

This change supplies a correct input cut for the change reader. It does not
replace the complete Query or Graph capture and proves no latency gain.

### Coverage change read result

**Coverage change reader: Done. Incremental source execution: Not done.
Proposals 1 and 5: Not done.** This change follows `b2df26330`.

Data receives a coverage change read after complete input cut C
  -> the existing reader transaction fixes committed revision R
  -> the native revision index selects coverage headers after C
  -> Data checks tenant, node, and source scope before it reads a report
  -> a native equality lookup reads each selected immutable report through R
  -> Data returns the report bytes and exact source, revision, and position

Each accepted report has its own global commit revision and ordinal zero.
The existing writer inserts one report per transaction. A unique index on
that revision supplies both native access paths. The report decoder and
coverage writer remain unchanged. A standalone historical read checks the
exact reference and its captured revision. Reading does not advance managed
progress.

Five focused tests pass. They cover fixed cuts, later arrivals, scope checks
before report reads, invalid references and stored rows, cancellation,
idempotence, reopen, backup, restore, and native index use. The index test
uses the production statements and default engine settings. The test log is
`/tmp/araphor-coverage-changes-fixed-20261101.log`. Data clippy passes with
tests and warnings denied. Its log is
`/tmp/araphor-coverage-clippy-20261101.log`. Full workspace CI was not run.
The user requires relevant checks only.
Scoped formatting, task whitespace checks, and 94 local document links pass.

The shared source view and Graph runtime do not use this reader yet. Managed
execution still requests `Read::Snapshot`, executes complete target inputs,
and compares those targets. That path does not satisfy the incremental
requirement. No incident latency reduction is claimed for this reader.

### Native source-view replacement

**Concrete source-record and input-contract implementation: Not done.**
The change reviewer approves the source-record and model flow for
implementation. The approved flow has these requirements:

- Reuse one managed `Step` for the shared source basis. Link its parent to
  the prior selected result. Retain the source cut, projection, typed Arrow
  additions, removal ranges, and exact metadata references once per step.
  Reuse `managed_arrow` for payloads. Remove per-call complete target IPC.
- Data seals the actual read mode, prior selected result, lower input cut,
  and projection in the attempt contract. Initial capture requires no prior
  basis or an explicitly authorized rebuild. Continued capture names the
  exact committed basis. A source-parent edge retains history without
  turning old witnesses into current input dependencies.
- Store the first projected source basis once. Later steps store changes.
  Restart validates the same instance, generation, store, schema, and epoch,
  then restores the indexed view once. Parent result commits are strictly
  older. Equal source cuts remain valid for window transitions.
- Add an `affected` reference to each existing SDK change pair. The reference
  names a typed query input port. Existing native query ports supply before,
  after, and Lookup rows from invocation-local source views. The declaration
  does not introduce another SQL parser, join implementation, or guest ABI.
- Keep the committed index at C in Query. Each invocation reads a candidate
  through R. Promote the exact candidate after its own acknowledgement.
  Failure after COMMIT must adopt that candidate or invalidate the local
  index and restore the committed basis.
- Native DataFusion joins execute the queries. A transparent build-stream
  adapter can expose exact Arrow join keys to the indexed probe provider.
  The provider must not scan all retained keys to evaluate an opaque native
  hash filter. A key wait must not depend on its own probe. Reused and
  concurrent plans require fresh task-local key and filter state.
- Internal Graph facts use stable record and context identities. Local guest
  row ordinals are assigned only after selected support is known. Remove
  global row numbering and complete Graph reconstruction from normal updates.

The first complete slice must execute installed SQL, Wasm, and native
packages through real Selected publication. Its proof must cover changed
inputs, indexed support, failed publication, acknowledgement, and restart.
Coverage integration, Graph migration, ordinary incremental SQL plans, and
window transitions remain required parts of the full goal.

#### Source-record working state

**Shared source records: Partial. Native runtime integration: Partial.
Proposals 1 and 5: Not done.** The working tree follows `29d7a356b`.

Data seals the source read mode, exact committed parent, input position,
selection, and projection. The existing managed transaction stores source
Arrow payloads once on the selected `Step`. A separate source edge retains
the parent without changing ordinary input freshness. Each source metadata
change is an initial state or accepted ranges. Receipt replacement, new
gaps, and exact coverage references use the same captured revision.

Source frames share a proof cell. Data checks the cell before COMMIT and
fills the cell after COMMIT. Cold restoration reads the existing Step proof
and loads one payload frame at a time through a callback. Arrow frames do
not retain cumulative source membership. Data retains current membership in
the existing capture, attempt, and committed execution state.

Zero-batch table headers require zero rows. These headers store no Arrow
payload. Nonempty headers map to contiguous payload slots. Explicit empty
batches retain their payload and exact batch count.

The managed change path now supplies an initial or continued source read.
Query retains indexed Arrow blocks and stages each candidate without
changing the committed index. Native DataFusion joins select matching old
rows by hash key. The existing native join checks key equality. The SDK
change pair names its affected query port. Package execution binds each
input once in dependency order. Complete-target comparison and target IPC
storage are removed from the working code.

The source subscription test passes for three successive context changes.
Each execution delivers one new row. Source history contains three one-row
frames. A new runtime restores the committed frames before it reads the
next change. The selected-key Graph test checks missing current rows,
missing retired rows, duplicates, foreign streams, and cursor zero. These
two tests pass in `/tmp/araphor-native-source-subscription-4.log`.

The order test now reads Arrow rows directly. Its earlier assertion used
an existing helper that sorts values and could not qualify delivery order.
Native query planning retains the caller's query AST and outer scope.
Native physical output requirements preserve the probe input's sort.
The key provider accepts a native sort without a fetch limit. Native joins
still execute the restriction. No replacement parser or sort evaluator is
added. The SQL and Wasm tests restore a new runtime, consume only the two
new context rows, and deliver `[5, 4]`. These checks and the Graph selection
and direct-run checks pass in
`/tmp/araphor-native-source-subscription-9.log`.

The same counter case passes with the source-built native Rust library.
The log is `/tmp/araphor-native-source-native.log`. The complete native test
takes 102.49 seconds with a 171 MiB debug library. This test result does not
measure the latency of an admitted source update. The native test cost
still needs investigation. Multicolumn, outer CTE, inner CTE, explicit SQL
limit, and native duplicate-name checks pass in
`/tmp/araphor-native-source-cte-4.log`. CTE shadowing has the same rejection
as an equivalent query in a plain native DataFusion session.

Data now creates opaque row handles for captured Arrow blocks. Query records
only the old rows that an indexed read selects. Data adds their exact evidence
to the new call and Step. The source record stores compact origin references
and indices. Cold validation reads those named origin headers. It does not
scan their Arrow payloads. A focused SQL subscription check passes with one
new context row and one matching old context row per update. The saved proof
contains only those two context versions. The same check restores a new
runtime before the next update. This test took 3.11 seconds. This duration
covers the complete test, not one source update.

Sixteen focused Data checks pass after the evidence changes. They cover
source records, metadata, replay, and retention. The source evidence test
checks selected old rows, rejected publication, a frozen retry, exact evidence
expiry, invalid support indices, and reopen. These checks took 49.56 seconds.

Cold restoration now borrows IPC bytes and uses the existing SDK decoder.
A caller reserves the decode bound before allocation. Query transfers the
decoded buffers to its existing memory owner before indexing. A failed
restoration discards the partial local index. The final six Analysis checks
pass for SQL and Wasm source changes, indexed support with restart, input
order, native CTE behavior, and selected Graph roots. They took 6.64 seconds.
`cargo check -p araphor-analysis --tests`, formatting for the five changed
crates, and the staged whitespace check also pass. Partial-restoration failure
and incomplete-commit wake behavior still lack their required focused proof.
The full regression suite and incident workload were not run.

Complete Graph integration, general native incremental SQL, and semantic
window transitions remain Not done. The old source metadata loop also remains.
The focused source checks do not qualify complete Graph execution or windows.
There is no new incident latency result.

**Checkpoint and stop: Requested by the user.** The user requires a commit of
the current work and an architecture explanation before work stops. The
checkpoint includes unfinished code. It does not complete this slice or
proposals 1 and 5. The user has rejected the current complexity. The separate
block and table containers, repeated evidence and scope records, and custom
version leases require design review before further implementation.

Native wiring must also reserve the source proof before COMMIT. The proof
cell is empty when the current capture size is measured. The current cached
size does not include the proof vectors that publication adds later. This
memory accounting remains Not done.

Before the native runtime edits, six focused source-record tests passed.
They check shared payloads across two
calls, rejection before COMMIT, exact committed proof, fixed input cuts,
reopen, cancellation, malformed payloads, source order, and empty tables.
Seven existing managed-state tests also passed. Data clippy passed with tests
and warnings denied. The logs are
`/tmp/araphor-source-frames-final-20261101.log`,
`/tmp/araphor-source-basis-regressions-20261101.log`, and
`/tmp/araphor-source-basis-clippy-20261101.log`. These results cover the Data
source-record path before the native edits. They do not qualify the current
working tree, complete native Query integration, or incident
latency. Full workspace CI was not run. The user requires relevant checks.
The six source-record checks also pass after the native input edits in
`/tmp/araphor-source-frames-integrated.log`.

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
for a finite snapshot keeps its native complete selection. A managed
incremental query must consume changes. A complete-query fallback does not
meet the incremental requirement.

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

#### Native lookup and stateless result

**Prepared lookup inputs and stateless continuation: Done. Builtin Graph
migration: Not done. Proposals 1 and 5: Not done.** This result follows
`6a61cd89a` and the earlier generic change-input delivery.

The SDK's `InputSource::Lookup` declares native SQL that executes after the
input difference. Query prepares those children at admission and binds the
delivered before, after, reset, and earlier lookup rows during physical
execution. Raw dependencies use the same captured source cut. Admission
rejects caller overrides, cycles, and early queries that depend on late
inputs. Bound ports retain their actual input revisions and coverage.

Data stores actual lookup rows for replay. Lookup rows do not enter the
retained target or force a complete reset when their source changes. A
stateless consumer uses the committed target and exact historical base.
It needs no guest checkpoint. Stateful consumers keep their existing rules.
No ABI, version, timer, quota, or engine changes are added.

Eight Analysis change-input cases passed, including native and Wasm, in
100.32 seconds. Three SDK cases passed. The new lookup checks cover empty
main differences, raw-source updates, cold restart, exact replay, historical
before-row provenance, caller override rejection, and phase rejection.
The first phase-rejection assertion inspected only the outer error text.
That assertion failed. The corrected assertion checks the exact rejection
field in the error chain; the case passed in 3.17 seconds. No production
behavior was changed to satisfy that assertion.

Final SDK, Query, Data, and Analysis clippy passed with tests and warnings
denied in 37.60 seconds. Scoped formatting and whitespace checks passed.

Proof is in `/tmp/araphor-lookup-integration.log`,
`/tmp/araphor-lookup-sdk.log`, `/tmp/araphor-lookup-final.log`, and
`/tmp/araphor-lookup-phase.log`. The final clippy log is
`/tmp/araphor-lookup-clippy-final.log`. This result adds no speed claim. Final
Graph timing requires the builtin unit migration and old-path removal.

#### Choice for the remaining Graph work

**Combined design: Approved; implementation Not done.** The user approves
proposals 1 and 5 together. Graph packages remain pure functions. Data owns
contribution membership through `araphor-graph`. Do not add package-owned
whole-Graph checkpoints or a second membership history.

The approved flow is:

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

#### Membership owner result

**Membership mutation owner: Done. Builtin unit integration: Not done.
Proposals 1 and 5: Not done.** This result follows `b19b0c89a`.

`araphor_graph::Contributions::apply` changes the existing versioned member
history through Data's transaction. Each member names an interned event unit.
The history has no second contribution table. An empty replacement removes
one unit. An absent unit remains unchanged. Identical rows keep their open
intervals. Shared members remain present until the last owner is removed.
The owner checks conflicts across retained and replacement owners. Counts
change from presence transitions for touched keys.

Data's direct, metadata, and Snapshot adapters use this owner. Data retains
producer pins, expected bases, authority checks, and COMMIT. Recovery checks
unit-scoped intervals, historical conflicts, source ownership, and logical
counts. Historical results retain their existing exact producer cuts.

Fourteen focused Graph tests and eleven focused Data tests pass. The Data
checks include shared values, historical conflicts, unchanged intervals,
canonical anchors, metadata, branch order and duplicates, rollback, retry,
schema integrity, and reopen. Graph and Data clippy pass with warnings
denied. Scoped formatting and whitespace checks pass. Data proof is in
`/tmp/araphor-graph-membership-data.log`.

The transitional unit-zero adapter merges its full prior contribution.
Builtin event-unit publication must bypass this adapter before completion.
No timing reduction is claimed for this ownership change alone. Native
value ownership, builtin change inputs, and final measurements remain open.

#### Unit integration result

**Builtin unit inputs and native value ownership: Done. Combined timing
proof for proposals 1 and 5: Not done.**

Builtin packages now declare native SQL for their target units and lookup
inputs. Query computes the input differences with native DataFusion plans.
The package receives changed units and their current records and facts.
SQL, Wasm, native, and the custom Burst package use the same contract.
Data changes only the affected unit membership through `araphor-graph`.
Subject, relationship, finding, and state values have shared native owners.
Data keeps the transaction, authority checks, progress, and replay records.

The old Graph-call reconstruction, progress rows, sparse resume, and builtin
classification by artifact bytes are removed from production. Data still
checks the current installed package bytes. An empty change keeps the
state of active units. Cold recovery checks historical anchors against the
exact saved call and owning unit. It reuses the evaluation that recovery
already decodes. It does not reconstruct a complete prior Graph.

Standalone package query programs keep their native query roots through
SQL planning. Native DataFusion output requirements preserve their final
ordering. Araphor delivers the resulting batches without changing their
values, row order, or batch order. Simple event subscriptions preserve
committed arrival order across pages, resumed cursors, and combined wakes.

Verification includes 73 builtin and Burst checks, 62 Data Graph-row checks,
29 Graph-owner checks, 16 Query checks, exact-order and replay checks for
quoted exports, and 11 input-binding checks. The added historical-anchor
regression applies 27 mutations to existing closed rows. The original
managed corruption matrix, source backlog, state recovery, unchanged
notices, and final-authority denial checks pass. Scoped formatting and
six-crate clippy checks pass with warnings denied. These are correctness
results; their test runtimes are not event-processing measurements.

Complete target queries and source captures remain. The existing incident
workload must still measure input/package work and Graph application work
against the recorded baseline. No combined speed factor is claimed here.

#### Unit measurement result

**Diagnostic measurement: Done. Original observation deadline: Failed.
Proposals 1 and 5: Not done.**

The source was `209cb8297` with temporary probes. The existing 1,592-event
incident test completed in **243.94 seconds**, against the recorded
**121.13-second** baseline. No compilation ran during this measurement.
The fixture reached `policy_ready` at 104.977 seconds. Observation took
115.086 seconds. Observation exceeded the original 90-second deadline.
The diagnostic run used a temporary 300-second observation cap. This cap
does not change acceptance. All 43 probe paths were restored from exact
copies and checked with SHA-256.

The following rows compare the selected cursor-950 invocation with the
same baseline boundary. They are not totals for the complete test or
guaranteed execution times. Child scopes are included in parent scopes.

| Selected-cut boundary | Baseline | Unit implementation | Change |
| --- | ---: | ---: | --- |
| Saved-call capture | 1,474.773 ms | 215.101 ms | 85.4% lower |
| Attempt ready to first package worker | 657.889 ms | 18,272.531 ms | 27.8 times higher |
| Graph publication, `graph_result_rows` | 1,332.962 ms | 1,592.164 ms | 19.4% higher |
| DuckDB API time inside Graph publication | 930.511 ms | 1,446.965 ms | 55.5% higher |
| Time outside DuckDB APIs inside Graph publication | 402.451 ms | 145.199 ms | 63.9% lower |
| Complete Data result commit | 2,814.612 ms | 2,480.537 ms | 11.9% lower |

The selected invocation delivered 10 changed units and 10 lookup records
to each package. The Process package produced 31 subjects, 21 edges, and
one finding. The other two packages produced no Graph values. Each package
still retained a complete target of 950 rows and 275,424 Arrow memory
bytes. Changed guest input does not prove that target query work is
incremental.

The three package-worker intervals covered 130.473 ms. Their complete
span was 2,197.335 ms. The 2,066.862 ms between these intervals remains
part of execution latency. Do not omit this time from the comparison.
Input preparation before the first worker is the largest measured
regression. Current probes do not identify the exact input operator that
causes this cost. The startup interval also needs a separate source-level
measurement.

The retained state reduces saved-call capture. Graph publication spends
less time outside DuckDB APIs, but more time inside those APIs. The whole
test is slower. Both approved proposals remain incomplete until input
execution and Graph publication show measured reductions with the same
behavior checks. No millisecond or overall speed improvement is proved.

The diagnostic log is
`/tmp/araphor-unit-measure-20261031-quiet.log`. Selected-cut scopes, API
counts, and source-log hashes are in
`/tmp/araphor-unit-analysis-20261031/quiet/focus.json`. The selected commit
scope is 4478. Its invocation is
`f7aa2fbb-3f1a-4c9b-b5fc-fb98e4f4ca13`.

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

**Recorded measurements: Done. Retained committed state: Done. Proposals 1
and 5: Approved and Not done. Millisecond execution: Not done. Proposals 2,
3, 4, and 6: Not approved and Not done.**
