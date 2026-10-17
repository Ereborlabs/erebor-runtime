# Araphor Performance Simplification TODO

Implement the 17 audit items that the user approved on 2026-10-15. The source
basis is `aa390d9f647c304ef212396433824a6b9c560982`. Remove repeated production
work in all Araphor crates. Keep the existing durable and authorization owners.
The user approves the quota-unit change in item 17 with the other items.

This file extends the
[production data flow plan](araphor-production-dataflow-simplification.md).
Earlier source and verification records in that plan remain historical.

## Approved deletion work

The user requires at least 6,000 net deleted nonblank production Rust lines.
Tests and documents do not count toward this target. Report both `7b7b407a` and
`aa390d9f` as comparison points. Do not count blank-line removal, code movement,
or compressed formatting as simplification. Consolidated tests must retain
every distinct input, fault, boundary, and assertion.

| Owner | Required deletion |
| --- | --- |
| Query | One Arrow registration and SQL execution path. The approved component redesign removes the DuckDB query adapter and duplicate physical schemas. DuckDB retains durable storage. |
| Package | One input/freshness comparison. Remove optional admitted-bundle loading and per-export task handoff. Wait on changes and actual deadlines. |
| SDK and built-ins | One checked computation entry. Keep standalone, import, and host boundary checks. |
| Control context | The authoritative transaction application identifies changed keys. Remove the second transaction interpreter. |
| Capture | One retained execution entry owns dispatch, cursor, and optional worker. |
| Storage | One selected-set cleanup validates expiry, synchronizes removal, and commits quota changes. Remove per-segment global scans. |
| Documentation | One current source route per contract. Remove repeated implementation and verification prose. |

The benchmark remains on hold. The user requires relevant builds and tests
for each iteration. This instruction replaces the general full-workspace CI
rule for this work.

### Component redesign

The user accepts the deletion work and requires simpler complete components.
Documentation and test consolidation do not establish that result.

| Component | Required replacement | Result |
| --- | --- | --- |
| Control context | One ordered source index and one replay cursor replace separate change maps and domain cursors. Preserve distinct-source conflicts, bounded replay, and retry after a failed durable write. | Not done |
| Package transport | SDK wire types and codecs own datasets, inputs, reasons, outputs, and checkpoints. Data uses these codecs. Each boundary keeps its limits and error classes. | Done |
| Raw storage | The raw journal owns its physical segments, append decision, and recovery scan. Remove the generic segment owner and second frame decode. Keep acknowledgement before SQL publication, sealed length checks, leases, pins, quota, and recovery after database loss. | Done |
| Discovery and graph values | The existing built-ins crate owns shared pure values. Data retains source qualification and host output checks. Remove mirrored values and field conversion owners. Execute the selected installed artifact. | Done |
| Follow positions | SQL views expose position aliases from existing columns. Remove copied hidden values from each input row. Keep position type checks, repeat-call denial, bounds, and source cleanup. | Done |
| Native graph rows | Append from canonical graph values and decode native cells into those values. Remove buffered row DTOs and their byte formulas. Keep native schema, result-scoped charges, explicit flushes, rollback, bounds, and corruption checks. | Done |
| SQL admission | Use the production parser for the former offline proof cases. Remove the unused parser. Keep fixed-bound disjunction parity, source scope, parameter bounds, and moving-clock denial. | Done |
| Discovery page admission | Reuse the admitted snapshot and input-byte total. Remove the second detector execution, merge, and input-size pass for an accepted page. Keep candidate bounds, context references, progress, and commit authorization. | Done |
| Package result contract | Store `PackageCommitV1` as the canonical contract. Remove the cloned metadata DTO and duplicate dependency JSON column. Keep native index checks, full retry identity, authorization, dependency references, and exact charges. | Done |
| Query transport | Move owned values into transport output. Remove the scalar wrapper and text, binary, column, and context-key clones. Keep output leases through the next poll or drop. | Done |

Do not replace native pointer checks with IPC copies or remove the supported
graph traversal contract to obtain a line count. Reuse must remove an owner or
representation without moving the same duplicate implementation elsewhere.

## Intended end state

Owners check relevant changes and due deadlines before they load payloads.
One operation prepares common inputs once. Existing owners retain immutable
declarations, verified artifact identities, and cursor positions for their
actual lifetimes. Query input preparation uses the admitted relations and
columns. Storage charges current encoded bytes. Current-format recovery,
tenant isolation, evidence, exact revisions, deadlines, and cleanup remain.

The approved [component redesign](araphor-component-redesign.md) replaces the
in-memory query engine with DataFusion. DuckDB retains durable storage.
Arrow remains the canonical query data format. This work adds no service,
broker, provider framework, fallback backend, or older-format reader.

The user requests a study of local DataFusion and Mangroves before the next
component redesign. The [redesign proposal](araphor-component-redesign.md)
records the source findings, replacement owners, and required proof. The
study is complete. The user approves implementation of the redesign and
requires a commit for each deliverable. The 6,000-line production target
remains in force.
The [crate ownership correction](araphor-component-redesign.md#proposed-crate-ownership-correction)
defines separate Data, Query, and Analysis owners. The user explicitly
requires this design and a query engine written from the start with native
DataFusion APIs. Moving or adapting the old query tree does not satisfy the
request. Implementation and verification remain **Not done**.
The current count adds 404 nonblank production Rust lines from `537f9de3`
and removes 1,825 from `7b7b407a`. Another 4,175 must be removed for the
6,000-line target. The count record is
`/tmp/araphor-arrow-engine-count15.json`. Complete redesign: **Not done**.
The user approves native DataFusion SQL behavior and ordinary visible
`__row_index` table columns. The component redesign must remove the custom
SQL binder, wildcard expansion, name repair, and numeric compatibility owners.
This approval requires no DataFusion extension.
The latest correction registers a Subscribe logical extension for the Follow
request. Ordinary SQL parsing, optimization, physical planning, and operators
remain native. The physical subscription node owns the commit and receipt
contract that a native batch stream does not supply. The direct Processor,
standalone aggregate helper, SourceBatch bridge, and obsolete Data row-page
framework are deleted. The selected host checks pass 195 distinct cases.
The last count adds 1,008 production lines from `537f9de3` and removes 1,221
from `7b7b407a`. The record is `/tmp/araphor-native-rewrite-count7.json`.
The required 6,000-line reduction and the complete redesign are **Not done**.
Local input binding now uses native MemTables and a native logical transformation
before optimization. The custom LocalTable provider and its SessionConfig map
are deleted. Canonical source schemas are shared across reads. Four unused Data
input variants and synthetic trace dispatch are deleted. The selected Query,
Data extraction, and Analysis model checks pass 158 cases; one Data history case
is ignored. Strict Clippy passes for the six affected crates and test targets.
NativeExecution and its owner field are also deleted. NativeLibrary owns the
invocation. Its pinned-file validation replaces repeated runtime inspection
and system-library reads. All 27 selected native cases pass, including eight
opt-in package cases. The combined record covers 185 selected cases:
`/tmp/araphor-native-owners-qualification1.json`.
The slice removes 90 nonblank production Rust lines. The latest complete count
removes 1,311 from `7b7b407a` and adds 918 from `537f9de3`. Another 4,689 must be
removed for the 6,000-line target. The record is
`/tmp/araphor-native-rewrite-count9.json`. Complete redesign: **Not done**.
The Wasm prepared-input and optional-input wrappers are deleted. The package
dispatch calls the Store owner directly under the existing checked input and
reservations. All 36 selected Wasm and component cases pass, and strict Analysis
Clippy passes. The record is `/tmp/araphor-wasm-owner-qualification1.json`.
This change removes 49 nonblank production Rust lines. The verified count chain
removes 1,360 from `7b7b407a` and adds 869 from `537f9de3`:
`/tmp/araphor-wasm-owner-count2.json`. Another 4,640 must be removed for the
6,000-line target. Complete redesign: **Not done**.
CheckedEvaluation now owns input encoding and supplies the native Invocation
proof. The old raw encoder is deleted. Guest validation, raw wire output error
order, IPC checks, native ABI, and release callbacks remain. All 125 selected
SDK, fixture, Wasm, and native cases pass with fresh native fixtures. Strict
Clippy passes for the three affected crates and their test targets. The record
is `/tmp/araphor-checked-input-qualification1.json`. This change removes two
nonblank production Rust lines. The complete count removes 1,362 from
`7b7b407a` and adds 867 from `537f9de3`:
`/tmp/araphor-native-rewrite-count10.json`. Another 4,638 must be removed for the
6,000-line target. Complete redesign: **Not done**. These checks do not establish
a performance improvement. Full workspace CI is not run, as instructed.
Native subquery admission now accepts DataFusion's structural container while
it retains recursive policy checks. Follow selects Replace for subqueries
before optimization. All 100 Query, 35 Analysis model, and one E2E query-follow
case pass. Strict Query Clippy passes. The record is
`/tmp/araphor-native-subquery-qualification1.json`. This correctness change adds
14 nonblank production Rust lines. It is not a code-reduction result. The
verified complete count removes 1,348 from `7b7b407a` and adds 881 from
`537f9de3`: `/tmp/araphor-native-subquery-count2.json`. Another 4,652 must be
removed for the 6,000-line target. Complete redesign: **Not done**.
Native cast preflight now charges the target FixedSizeBinary width for null
rows. Both regressions fail on the old estimator; all 12 selected conversion,
schema, and model execution cases pass with the fix. Strict Analysis Clippy
passes. The record is `/tmp/araphor-fixed-binary-qualification1.json`. The fix
adds eight nonblank production Rust lines. The verified complete count removes
1,340 from `7b7b407a` and adds 889 from `537f9de3`:
`/tmp/araphor-fixed-binary-count2.json`. Another 4,660 must be removed for the
6,000-line target. Complete redesign: **Not done**.
The subscription physical plan now includes the actual JournalExec child.
The hidden Source factory is deleted. Native bounded source execution,
Inexact filters, complete receipts, and native optimizer checks remain.
The journal enforces Tokio's cooperative budget between signed messages.
All 102 Query cases and the E2E query-follow contract pass. Strict Query
Clippy and scoped formatting pass. The record is
`/tmp/araphor-journal-owner-qualification1.json`. This change adds 139 nonblank
production Rust lines. The complete count removes 1,201 from `7b7b407a` and
adds 1,028 from `537f9de3`: `/tmp/araphor-native-rewrite-count11.json`.
Another 4,799 must be removed for the 6,000-line target. General maintained
SQL, clock epochs, the append source replacement, and the complete redesign
remain **Not done**. Full workspace CI is not run, as instructed.
Physical Output now transfers its reservation to Update. Follow's repeated
output checks and claims are deleted. The native iterator retains metadata
without retaining the completed SQL permit. The old-code regression fails;
all 102 Query cases and strict Query Clippy pass with the change. The record is
`/tmp/araphor-output-owner-qualification1.json`. This change removes 23 nonblank
production Rust lines. The complete count removes 1,224 from `7b7b407a`:
`/tmp/araphor-output-owner-count2.json`. Another 4,776 must be removed for the
6,000-line target. Complete redesign: **Not done**.
Native DataSourceExec now carries immutable source descriptors. Capture reads
the optimized physical tree; both planning mutexes and SnapshotPartition are
deleted. Native MemoryStream reads each TaskContext's captured snapshot.
All 104 Query cases, 37 model cases, and the E2E query-follow contract pass.
Strict Query Clippy passes. The record is
`/tmp/araphor-source-descriptor-qualification1.json`. This change removes
25 nonblank production Rust lines. The corrected complete count removes 1,301
from `7b7b407a` and adds 928 from `537f9de3`:
`/tmp/araphor-native-rewrite-count12.json`. The correction excludes three
external test modules; it gives no implementation deletion credit. Another
4,699 must be removed for the 6,000-line target. Complete redesign: **Not done**.
Native physical append pages now replace the logical position rewrite and
Sort. Native filters carry the real position fields with their rows. The
physical output owns prefix limits, compaction, positions, and reservations.
Finite and page execution share the capture worker and retain the actual
native task context. One State.finish method updates completed cursor state.
The selected checks pass 112 Query cases, 37 model cases, and the E2E
query-follow contract. Strict Query Clippy and scoped formatting pass. One
new fixture needs an explicit native VARCHAR cast; its selected retry passes.
The record is `/tmp/araphor-physical-page-qualification1.json`. This slice adds
227 nonblank production Rust lines; moving the collector gives no deletion
credit. The complete count removes 1,074 from `7b7b407a` and adds 1,155 from
`537f9de3`: `/tmp/araphor-native-rewrite-count15.json`. Another 4,926 must be
removed for the 6,000-line target. General maintained SQL, clock epochs,
shared maintained-query ownership, and the complete redesign remain **Not done**.
Full workspace CI is not run, as instructed.
### Finite resolved inputs

The working tree now uses Query-owned
[Inputs](../../crates/araphor-query/src/inputs/mod.rs) and
[InputSet](../../crates/araphor-query/src/inputs/physical.rs) for resolved model
inputs. Native plans retain original provider origins and execute in dependency
order. All physical input children share one SourceSnapshot and TaskContext.
Data reads canonical sources, exact package outputs, and their reference ledger
in the same transaction. The SDK owns conversion preflight and normalization.
Each port receives one retained dataset-global row index. SQL ModelRun reuses
those indexed tables. Analysis's old per-port dispatcher, source readers,
package-output resolver, and post-capture reference reads are deleted.

Analysis prepare_model reads the admitted Inputs directly. Package lifecycle,
backend admission and execution, checkpoint selection, authority, and the
authorized Data compare-and-swap commit remain unchanged. A live InputOperation,
shared source watch, Busy retry retention, and commit-completion feedback are
**Not done**. Serve and supervision still decide when automatic work runs.

Selected host verification is **Done**. The earlier 124-case Query run
precedes the final metadata and read-control changes. The final affected
execution, input, and memory selection passes all 40 cases.

| Required record | Current result |
| --- | --- |
| Finite-input owner checks | 65 SDK, 61 Data, 129 distinct Query, and 57 distinct Analysis cases pass across the corrected checks. Analysis includes eight explicit native cases. One Data release-history case remains ignored. |
| Affected caller checks | The package E2E contract passes after the cold Wasm preparation deadline fix. Strict Clippy passes for the affected crate and caller test targets. Formatting and local document links pass. |
| Production source count at `b80e274b` | This change adds 1,188 nonblank production lines. At that commit, the complete redesign adds 114 from `7b7b407a`. Another 6,114 must be removed for the required target. |
| Complete redesign and 6,000-line reduction | Not done. |

The records are `/tmp/araphor-native-input-qualification1.json` and
`/tmp/araphor-native-rewrite-count18.json`. Query's total combines corrected
checks. Native qualification covers Linux x86_64 with the GNU target. Cold
Wasm preparation now uses the caller deadline before the unchanged evaluation
timeout starts. The deadline regression and package restart check pass.
Session registration reuses shared Arrow allocation claims; a new allocation
still fails when the pool is full. Full workspace CI and benchmarks are not run.

The [component record](araphor-component-redesign.md#finite-resolved-input-ownership)
and [review guide](../guides/araphor-sql-operation-review.md#current-table-and-query-input-flow)
give the source route and test owners. This change supplies no benchmark or
speed result.

### Complete source changes in physical execution

Implementation and selected host verification: **Done**. One private Change
carries the complete signed Arrow input and commit proof. The synthetic
Begin, Insert, Delete, and Commit queue and physical Inputs adapter are deleted.
Native input plans bind once for all before batches and once for all after
batches. SubscribeExec::compile owns COUNT eligibility; repeated kernel checks
are deleted. Exact frontiers, full witnesses, cumulative byte checks, shared
evaluation control, and actual worker permits remain.

All 18 affected Query cases and the E2E query-follow contract pass. The E2E
contract retains eight behavior cases. Strict Clippy passes for Query, Control,
E2E, and their test targets. Scoped formatting and local document links pass.
The records are `/tmp/araphor-committed-input-qualification1.json` and
`/tmp/araphor-committed-input-count1.json`.

This change removes 127 nonblank production Rust lines. The complete redesign
removes 13 from `7b7b407a` and adds 2,216 from `537f9de3`. Another 5,987 net
production deletions are required for the 6,000-line target. General maintained
SQL, Query-owned live detector scheduling, and the complete reduction remain
**Not done**. Full workspace CI and benchmarks are not run, as instructed.
No performance improvement is claimed.

### Native Arrow table reads

The [native Arrow table read](araphor-component-redesign.md#native-arrow-table-reads)
deletes the public Data row callback protocol, Query scalar scratch rows, and
the separate Arrow builder. The selected functional checks pass 209 distinct
cases. Strict Clippy passes for all five affected crates and their test targets.
The change removes 417 nonblank
production lines. The complete count removes 430 from `7b7b407a` and adds 723
from `aa390d9f`: `/tmp/araphor-native-tables-count1.json`. Another 5,570 net
production deletions are required. The complete redesign remains **Not done**.

### Shared physical output completion

The [shared physical completion](araphor-component-redesign.md#shared-physical-output-completion)
deletes Follow's duplicate collector and COUNT's retained comparison batches.
Both paths consume the native stream through the existing bounded Session
owner. The selected checks pass 173 distinct cases. Strict Clippy and scoped
formatting pass. The records are
`/tmp/araphor-output-completion-qualification1.json` and
`/tmp/araphor-output-completion-count1.json`. This slice removes 40 nonblank
production lines. The complete count removes 470 from `7b7b407a`; another
5,530 must be removed. The complete redesign remains **Not done**. Full
workspace CI and benchmarks are not run, as instructed.

### Live detector inputs

[Live input ownership](araphor-component-redesign.md#live-detector-input-ownership)
moves source, time, witness, pending-cut, and completion checks to Query.
Analysis retains lifecycle, authority, backend execution, and the Data commit.
Unchanged running activations skip admission. Busy waits use actual resources.
Implementation and selected host verification are **Done**. The affected
checks pass 267 distinct cases. Strict Clippy and formatting pass. The records
are `/tmp/araphor-live-input-qualification1.json` and
`/tmp/araphor-live-input-count1.json`. This delivery adds 1,637 nonblank
production Rust lines. The complete count adds 1,167 from 7b7b407a; another
7,167 net deletions are required. The complete redesign remains **Not done**.
General maintained SQL and the separate native execution pool review remain
open. Full workspace CI and benchmarks are not run, as instructed. No
performance improvement is claimed.

The obsolete Analysis automatic flag, branch, and input deadline calculation
are deleted. Manual retry and Inspect behavior remain. Selected verification
is **Done**: 13 Analysis cases and two explicit native checkpoint cases pass.
This follow-up removes 35 nonblank production Rust lines. The complete count
still adds 1,132 from 7b7b407a; another 7,132 net deletions are required.
The records are `/tmp/araphor-obsolete-run-qualification1.json` and
`/tmp/araphor-obsolete-run-count1.json`. The complete redesign remains **Not done**.

Query Session now supplies one indexed schema and batch builder for resolved
and supplied model data. The duplicate ModelSchema production owner and
Analysis indexing loop are deleted. Analysis retains stage visibility and
complete-input admission. Manual Run reuses its decoded activation context.
The count removes 22 nonblank production Rust lines from 97909397. The
complete redesign still adds 1,110 from 7b7b407a; another 7,110 net deletions
are required. The count is `/tmp/araphor-indexed-table-count1.json`.
Selected verification is **Done**: 73 distinct cases pass across Query,
Analysis, and explicit native execution. The qualification record is
`/tmp/araphor-indexed-table-qualification1.json`. The complete redesign
remains **Not done**.

Query and Data now use one original-source and physical-projection map.
The separate Data relation set, per-port request maps, capture request map,
and trace flag are deleted. The map distinguishes an original source with
no surviving scan from a real zero-column scan. Per-port evidence scopes and
event ranges remain. Cursor binding uses the original keys without another
allocation. Selected verification is **Done**: 287 distinct cases pass across
Query, Data, Analysis, and two E2E contracts. One existing Data history case
remains ignored. The Analysis alias-budget fixture also fails on b4d9c033.
The final single-case check passes with its original input limit and all
assertions retained. Strict Clippy passes for the affected crates and tests.
The qualification record is `/tmp/araphor-source-demand-qualification1.json`.
The count removes one nonblank production Rust line from b4d9c033. The
complete change adds 1,109 from 7b7b407a; another 7,109 net deletions remain.
The count is `/tmp/araphor-source-demand-count1.json`. The complete redesign
remains **Not done**.

The source coherence review records the connected callers and compatibility
work. The synchronous API boundary, resource behavior, compiled parity, and
net replacement count remain unproved.

### One native source field declaration

**Done** for the selected source and host checks. One table_row declaration
creates native Arrow fields and the Capture append method. The separate field
lists are deleted. Projection, complete-row admission, and metadata remain.
Nineteen fixed schema hashes and the native value cases preserve the contract.
The trace fixture also proves measurement-only fanout. The selected checks pass
289 cases; one existing Data history case is ignored. Strict scoped Clippy
passes. The change removes 237 nonblank production Rust lines. The complete
change adds 872 from 7b7b407a; another 6,872 net deletions remain. The records
are `/tmp/araphor-canonical-tables-qualification1.json` and
`/tmp/araphor-canonical-tables-count1.json`. Complete redesign: **Not done**.
Full workspace CI and benchmarks are not run, as instructed.

### Native catalogs define model table visibility

**Done** for the selected source and host checks. One explicit native provider
map replaces schema-overlay catalog construction. Model and dataset catalogs
contain only their declared native MemTables. The separate source-membership
walk is deleted. Native planning retains unused-CTE denial and qualified local
lookup. Client and input source provenance remain. The selected checks pass
235 cases. Strict scoped Clippy passes. The change removes 23 nonblank
production Rust lines. The complete change adds 849 from 7b7b407a; another
6,849 net deletions remain. The records are
`/tmp/araphor-closed-catalog-qualification1.json` and
`/tmp/araphor-closed-catalog-count1.json`. Complete redesign: **Not done**.
Full workspace CI and benchmarks are not run, as instructed.

## Implementation flow

An owner starts or recovers
  -> the existing store validates current durable state
  -> the owner reconstructs its immutable inputs and cursor state
  -> the owner registers existing change subscriptions and required deadlines

A relevant commit or due deadline occurs
  -> the owner checks current authorization and exact metadata
  -> the owner selects affected work
  -> the owner prepares required inputs once
  -> the existing execution owner computes the result
  -> the existing store validates and commits the result
  -> the owner publishes the committed change

An operation fails, expires, or loses authority
  -> the current control cancels active work
  -> the owner releases handles, inputs, and reservations
  -> the store retains only committed state
  -> recovery or retry checks current exact state

## Accepted items

`Not done` means that implementation or required verification remains.
Change an item to `Done` only after its source and functional checks pass.

| ID | Status | Change and owner | Required proof |
| --- | --- | --- | --- |
| 1 | Not done | Package owner groups reconciliation by installation, reuses immutable closures, and checks relevant dependency changes before source preparation. Remove repeated orphan scans and unconditional input reconstruction. | Upgrade orphan repair, activation changes, authority revocation, required clock ticks, exact dependency revisions, restart, and unchanged-input behavior. |
| 2 | Not done | Graph owner checks headers, notices, exact heads, and witness deadlines before it loads retained graph rows. | Notice changes, expiry without new data, overlap replacement, package changes, restart, and exact result parity. |
| 3 | Not done | Store owner maintains owned file and segment totals at file changes. Remove a full directory walk from each raw batch. Rebuild totals during recovery. | Capacity denial, disk reserve, rotation, deletion, database growth, restart, and ACK after durable commit. |
| 4 | Not done | Graph derivation prepares common records, facts, revision, coverage, and datasets once per window. | Native and Wasm parity, per-model bounds, original input revisions, evidence ordinals, and exact outputs. |
| 5 | Not done | Built-in graph computation indexes original facts by record once per evaluation. | Missing and conflicting facts, original ordering, exact evidence references, and detector parity. |
| 6 | Not done | Follow retains its checked store revision and dependency selection. Remove dependency history scans when both remain unchanged. | Append replay, moving-window expiry, coverage changes, quiet revocation, and unrelated commits. |
| 7 | Not done | Query owner constructs required event columns and applies supported simple predicates during extraction. Keep a complete fallback for complex statements. | Full row mapping, query parity, scope denial, evidence capture before pruning, empty append progress, and joins, ordering, and aggregate semantics. |
| 8 | Not done | Installed package owner retains verified identities with immutable bundles. Authority checks current trust membership without rebuilding OCI layouts. | Changed-content denial, trust revocation, exact installed exports, native closure identity, and commit authorization. |
| 9 | Not done | Retention uses the existing source index and removes a bounded eligible set per visit. Remove repeated global entry scans. | Current pin and required-progress checks, pressure, replay floors, recovery, and physical reuse. |
| 10 | Not done | Capture owner retains verified immutable dispatches after recovery or admission. Remove intent file reads from idle diagnostic polls. | Durable intent before spawn, duplicate rejection, lease expiry, retirement floors, and recovery without a second spawn. |
| 11 | Not done | Capture owner retains the verified spool cursor byte offset. Rebuild the offset once after reopen. | Replay, cursor changes, sequence denial, torn tails, and upload of the synced prefix only. |
| 12 | Not done | Operation owners observe authority changes through events and reuse deadline monitoring. Remove per-read thread creation and authority polling. | Direct synchronous calls, shorter stage deadlines, cancellation, closed authority channels, cleanup, and commit checks. |
| 13 | Not done | Query owner registers admitted built-in relations only. Store provenance methods return empty values for empty references after validation. | Hidden-source denial, alias provenance, cleanup, exact nonempty references, and empty input results. |
| 14 | Not done | Built-ins reuse immutable declarations and their ports. Remove schema generation during computation. | Canonical descriptor and schema metadata, wire round trips, and native and Wasm parity. |
| 15 | Not done | Guest invocation reuses validated inputs internally. Remove repeated contract passes inside one invocation. | Framing and FFI validation, checked standalone APIs, host output checks, evidence validation, cleanup, and error precedence. |
| 16 | Not done | Control context owner projects committed changes and serializes a new record once. Retain startup replay. | Exact retries, failed-write retry, bounded replay, current revisions, and restart. |
| 17 | Not done | Package store charges actual current encoded bytes. Remove decimal JSON size counting, its retained frame field, and obsolete quota bookkeeping. | Current format integrity, quota accounting, identical install retry, native dependencies, corruption, backup, restore, and recovery. |

## Verification and result

Use owner-local functional tests and build the affected callers for each
iteration. Qualify current source-built native packages and the installed native detector
through the existing proof route. Preserve all current format and ABI checks.

No new performance test or benchmark is approved. Do not infer speed gains
from changed test-suite durations. Record removed work from the final source.
Measure latency only after approval of a specific workload and its limits.

Result: **Not done**. The current DataFusion working tree adds 72 nonblank
production Rust lines from `7b7b407a` and 1,225 from `aa390d9f`.
The redesign adds 2,301 from the baseline `537f9de3`.
Another 6,072 must be removed to meet the target. The count record is
`/tmp/araphor-arrow-engine-count13.json`. It includes the new query modules
and excludes tests and documents. Engine functional qualification passes:
439 ordinary Data cases, 12 native Data cases, six Control cases, and three
E2E cases. The final affected build, strict Clippy, and formatting pass. The
result record is `/tmp/araphor-arrow-engine-qualification-final.json`. The
[engine plan result](araphor-component-redesign.md#qualification-and-acceptance)
records the corrected native test, exact source extension, and platform limits.
The following direct plan change removes 42 production lines from the engine
commit. It passes 256 query cases, four package cases, two native cases,
and strict Clippy for Data and its Control/E2E callers. The plan records the
host disk-reserve failure and the successful retry of its 88 affected cases.
The source scan change uses one optimized DataFusion plan for field selection
and execution. It adds 80 production lines from the direct plan commit and
passes 259 query cases, four package cases, and strict Clippy for Data and its
callers. The plan records its two test corrections and their focused retry.
Canonical Arrow fields replace 431 parallel InputField descriptors. Model
stages move one imported-table map. The change adds four production lines and
passes 260 query cases, six package cases, and strict Clippy for Data and its
callers. The plan records the stopped broad package selection separately.
SQL model execution consumes only the admitted program and checked SDK model.
Descriptor order replaces two retained statement maps. Checked indices bind
reason declarations. This change removes 17 production lines and passes 52
affected cases and strict Clippy. The plan records the new fixture correction
and test-only source extension. One ordered input program replaces retained
SQL-name lookup and per-run source-name lookup. Fresh slots preserve declared
input order. This change adds 54 production lines and passes 53 affected cases
and strict Clippy. The plan records the host disk-reserve failure and the
successful retry of only its 21 failed cases. The complete reduction remains open.
Continue component refactoring. Documentation and test deletion do not close
this result.

Before the engine integration, retained admission removed 2,036 nonblank
production Rust lines from `7b7b407a` and 883 from `aa390d9f`. The shared SDK
codec changes removed 92 from `1fb58d37`. These are historical counts.

The shared codec iteration passed the affected SDK, Data, Control, and
end-to-end test build in 45.44 seconds after cache cleanup. All 107 selected
functional cases passed: 74 SDK cases, 31 Data cases, and two Control cases.
These include wire bounds, native C layout, independent storage reason
budgets, aggregate execution budgets, checkpoints, OCI fixtures, source
cleanup, and package authorization. Strict Clippy passed for these four
crates and their test targets in 71.55 seconds. Formatting passed. Source and
test binary hashes stayed fixed. The records are `/tmp/araphor-codec-build3.json`,
`/tmp/araphor-codec-tests1.json`, and `/tmp/araphor-codec-clippy1.json`.

The final codec adjustment removes an unnecessary decoded-memory count from
storage encoding. Execution accounting and decoding do not change. The
affected test build passed in 88.23 seconds. All 74 SDK cases and the package
IPC limit case passed again. Strict Clippy passed in 32.42 seconds. The records
are `/tmp/araphor-codec-build4.json`, `/tmp/araphor-codec-branch-tests1.json`,
and `/tmp/araphor-codec-clippy2.json`. The source count record is
`/tmp/araphor-codec-syntax-counts2.json`.

The final source-built native libraries passed six selected Data cases and the
installed detector end-to-end case in 340.91 seconds. The latter ran with
`PATH` empty. Source, artifact, and test binary hashes stayed fixed. These
checks cover Linux, `x86_64-unknown-linux-gnu`, and glibc 2.39. The records are
`/tmp/araphor-codec-native-build3.json` and
`/tmp/araphor-codec-native-final-qualification.json`.

The package contract and transport iteration passed the affected Data,
Control, and end-to-end test build in 179.37 seconds. All 83 selected Data
tests passed. Of the 29 selected Control tests, 25 passed on the first run.
Four cases lost their 60-second fixture session during concurrent setup.
Those four cases passed unchanged in a sequential run. No assertion or
deadline was removed. All 112 selected functional cases have passing results.
Strict Clippy passed for these three crates and their test targets in 87.87
seconds. Formatting and `git diff --check` passed. Source and test binary
hashes stayed fixed. The records are `/tmp/araphor-contract-build3.json`,
`/tmp/araphor-contract-tests1.json`, `/tmp/araphor-contract-failed-tests1.json`,
and `/tmp/araphor-contract-clippy2.json`.

Six native libraries were built from the current locked source in 42.18
seconds. All 12 native Data cases and the installed native detector end-to-end
case passed. The latter ran with `PATH` empty. Source, artifact, and test binary
hashes stayed fixed. These checks cover Linux, `x86_64-unknown-linux-gnu`, and
glibc 2.39. They do not qualify other targets. The records are
`/tmp/araphor-deletion-native-build.json` and
`/tmp/araphor-deletion-native-qualification.json`. This qualification covers
the shared values, direct graph storage, and package contract changes.

The package contract count record is `/tmp/araphor-contract-syntax-counts2.json`.
The count also excludes code that is available only through the
`test-fixtures` or `test-support` features. Other feature code remains
production code. This correction changes the earlier `aa390d9f` comparison
from 963 to 966 deleted lines before this iteration. It does not change the
earlier 2,119-line comparison with `7b7b407a`.

The direct-storage iteration passed the affected test build in 353.74 seconds,
strict Clippy, and all 130 selected tests: 18 built-in cases, 95 Data cases,
and 17 SQL admission cases. The Data cases include native graph bytes,
borrowed-column faults, cancellation, quota isolation, backup, restore,
traversal, extraction bounds, page resume, Discovery limits, follow, and model
source cleanup. Source and test binary hashes stayed fixed. The records are
`/tmp/araphor-direct-build1.json`, `/tmp/araphor-direct-clippy1.json`,
`/tmp/araphor-direct-tests1.json`, and
`/tmp/araphor-direct-admission-tests1.json`.

The direct-storage count record is `/tmp/araphor-direct-syntax-counts2.json`. The
extraction change reduces stored pipeline and operation-closure symbols from
51 to five in the Data test binary. That compiled-code reduction does not
count toward the source target and does not measure production latency.
The records are `/tmp/araphor-extraction-symbols-before.json` and
`/tmp/araphor-extraction-symbols-after.json`.

The count uses Rust syntax spans to exclude test items, parameters, fields,
expressions, local bindings, and match arms. A test-only parameter does not
exclude its function body. Added shared type files are included, so code moves
cancel. The count records are `/tmp/araphor-components-syntax-counts1.json`
and `/tmp/araphor-components-syntax-head-counts.json`. These records replace
the earlier regular-expression counts.

The affected Data and built-ins test build passed in 386.61 seconds. All 18
built-in tests and 391 selected Data tests passed. The selected tests include
raw append, quota, recovery after database loss, truncation, backup, restore,
leases, graph and Discovery outputs, SQL positions, and source cleanup. Source
and test binary hashes stayed fixed during the test run. The records are
`/tmp/araphor-components-build2.json` and
`/tmp/araphor-components-tests1.json`.

Strict Clippy passed for the two affected libraries after two local lint fixes:
use `?` for an optional atom key, and import test-only names under `cfg(test)`.
The record is `/tmp/araphor-components-clippy3.json`. The native qualification
above uses rebuilt native and Wasm packages. Shared value changes require
these current artifacts; an older artifact is not current proof.
All 18 built-in tests passed again after the lint fixes. Their record is
`/tmp/araphor-components-builtins-tests2.json`. Formatting passed for both
affected crates.

Commit `238e3ff9` passed the workspace test build, strict Clippy, and all
170 selected functional cases. Its source did not change during these checks.
The records are `/tmp/araphor-deletion-build5.json`,
`/tmp/araphor-deletion-clippy2.json`, and
`/tmp/araphor-components-focused2.json`. The broader CI run was interrupted
at the user's request to use relevant checks per iteration. It is not a passing
CI receipt. The current native qualification is recorded above.

The previous check at `7b7b407a` ran on 2026-10-15. The source manifest contains 1,401 input
files. Its SHA-256 is:

`0f23272581240d3a2e1cb92ac9421ff10b4fec95136bca3f1d642f3a35a62612`

- `bash .github/scripts/verify-rust-ci.sh`: formatting, compilation, Clippy,
  and tests passed. All 90 test harnesses completed: 2,172 passed, zero failed,
  and 568 ignored. Araphor Data passed 653 tests with 19 ignored. Control
  passed 191 tests with two ignored. The end-to-end crate passed 191 tests
  with 528 ignored.
- Six native libraries were built from the current locked source. Their
  98 build inputs still matched the final checkout. All 12 native Data
  cases passed. These cases include parity with current source-built Wasm
  components. The installed native detector end-to-end case also passed
  with `PATH` empty, no host rebuild, exact evidence, and replay equality.
- Source, native libraries, and test binary hashes did not change during
  qualification. Native qualification covers Linux, `x86_64-unknown-linux-gnu`,
  and glibc 2.39. It does not qualify other native targets.

The local evidence records are
`/tmp/araphor-performance-final-ci4.json`,
`/tmp/araphor-performance-final-ci4-report.json`,
`/tmp/araphor-performance-native-build.json`, and
`/tmp/araphor-performance-native-qualification.json`.
The [review guide](../guides/araphor-performance-simplification-review.md)
links each changed owner to its functional checks.

No benchmark or physical Kubernetes qualification was run. The functional
results do not measure production latency or claim a speed increase.
