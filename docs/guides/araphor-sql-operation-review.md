# Araphor SQL Operation Review

The [approved plan](../plans/araphor-production-dataflow-simplification.md)
defines input ownership. The [current verification](../plans/araphor-performance-simplification-todo.md)
records the source and checks. The
[component redesign](../plans/araphor-component-redesign.md) defines the current
engine replacement. Earlier qualification does not cover later edits.

This guide covers the current working-tree DataFusion rewrite. The parser
returns a native statement. The planner returns a native logical plan through
the standard session catalog. The user approves native SQL behavior and
visible dataset row indices. Complete qualification is **Not done**. The
earlier receipts below apply only to their recorded source.

## Intended end state

One admitted logical plan reads authorized Arrow sources and produces native
Arrow batches. Each run owns its source batches, physical plan, stream,
control, and reservations. Control converts client results at the protocol
boundary. Analysis checks declared model outputs. Data remains the durable
result and progress owner. Current source tests define the required checks.

## Current table and query input flow

The SDK declares each input as `Table(TableRef)` or `Query(String)`.
`TableRef::Named` names a source table. `TableRef::Output` names an exact
package revision, export, and output. An input port supplies its local name
and Arrow schema. Separate ports remain separate datasets; the caller must
write SQL when it needs a join or union.

| Crate owner | State and behavior | Dependencies in this route |
| --- | --- | --- |
| [Data](../../crates/araphor-data/src/lib.rs) | Durable records, package formats, transactions, retention, source revisions, and read control. | SDK, shared built-in contracts, and DuckDB. No Query or Analysis dependency. |
| [Query](../../crates/araphor-query/src/lib.rs) | Native parsing, planning, catalogs, source capture, Arrow execution, reservations, follow, and subscription delivery. | Data, SDK, DataFusion, and Arrow. |
| [Analysis](../../crates/araphor-analysis/src/lib.rs) | Package lifecycle, admitted model programs, ModelRun, native/Wasm execution, and domain execution. | Query, Data, SDK, and existing execution backends. |

Control imports these owners directly. The dependency graph has no facade
crate. SDK owns declarations and native/Wasm application binary interfaces.

[AnalysisPackageOwner::prepare_at](../../crates/araphor-analysis/src/package/evaluation/preparation.rs) checks the installed context and selects the implementation
  -> [ModelRun::new](../../crates/araphor-analysis/src/model/operation.rs) creates one runtime operation from the existing Engine
  -> [ModelRun::prepare_inputs](../../crates/araphor-analysis/src/model/operation.rs) checks current authority and resolves declared Table inputs before Query inputs
  -> [ModelRun::output_table](../../crates/araphor-analysis/src/model/source/table.rs) reads exact committed package output through Engine.store and checks the retained grant
  -> [ModelRun::read_input](../../crates/araphor-analysis/src/model/source/read.rs) executes admitted source plans through the native Session
  -> [ModelInputs::add_snapshot](../../crates/araphor-analysis/src/model/source.rs) checks source references and combines original receipts with inherited input revisions
  -> [ModelInputs::finish](../../crates/araphor-analysis/src/model/source.rs) normalizes evidence after the run restores declared input order
  -> [AnalysisPackageOwner::execute_model](../../crates/araphor-analysis/src/package/execution.rs) selects SQL, native, or Wasm execution
  -> [AnalysisPackageOwner::prepare_model](../../crates/araphor-analysis/src/package/evaluation/preparation.rs) prepares one result contract
  -> [AnalysisStore::commit_package](../../crates/araphor-data/src/analysis/packages/commit.rs) checks the authorized durable transaction

```mermaid
sequenceDiagram
    participant Package as AnalysisPackageOwner
    participant Input as ModelRun
    participant Store as AnalysisStore
    participant Session as Native Query Session
    Package->>Input: Resolve admitted inputs with current grant
    Input->>Store: Read exact committed Table outputs
    opt Named source or Query input
        Input->>Session: Execute retained plan with one captured clock
        Session->>Session: Create native physical source descriptors
        Session->>Store: Capture requested rows and original source receipts
        Session->>Session: Read native Arrow stream
        Session-->>Input: Bounded Arrow inputs and source receipt
    end
    Input-->>Package: Ordered Arrow inputs and provenance
    alt SQL implementation
        Package->>Input: Evaluate with the retained Arrow tables
        Input->>Session: Execute local output, checkpoint, evidence, and reason plans
        Input-->>Package: Validated output and native reservations
    else Native or Wasm implementation
        Package->>Package: Release source Session and invoke selected backend
    end
    Package->>Store: Existing authorized result transaction
```

ModelRun derives all store access from its Engine. The package owner also
derives its retained store Arc from that Engine. The constructors accept no
independent store argument. Output-only input resolution takes no SQL
evaluation slot. The run creates its Session when the run first needs SQL.
The Session retains registered local MemTables. Each statement acquires its
evaluation permit for actual planning, capture, and stream consumption.

[ModelRun::table](../../crates/araphor-analysis/src/model/input.rs) adds one
dataset-global `__row_index` column across all batches. The column is an
ordinary visible table field. Native `SELECT *` includes the field. Canonical
Data tables keep their declared fields. Local registrations can replace a
canonical table name. Admission excludes those local bindings from the durable
source inventory. Table lookup applies no `__araphor_` prefix ban.

[AdmittedModel](../../crates/araphor-analysis/src/model.rs) stores raw native
logical plans for output and checkpoint queries in descriptor order. Each
reason plan retains checked output and reason indices. InstalledBundle retains
the exact descriptor, implementation, and admitted-program pairing. Public
transient calls perform their own admission. Known retained vectors and
declarations have native memory reservations; native plan allocation has no
complete upstream size measurement.

[AdmittedExport](../../crates/araphor-analysis/src/model.rs) retains an ordered
input program. The program selects admitted plans or exact committed outputs.
Each query keeps its original durable source names and declared input indices.
Native `SessionState::resolve_table_references` supplies the original table
references, including unused common table expressions (CTEs). The run restores
descriptor order after preparation. Exact names, current grants, freshness,
source capture, and resource limits remain checks for each run.

Each original Table input retains its evidence and exact dependency once.
A derived Query input combines inherited coverage and hashes the inherited
input revisions, including when SQL returns zero rows. Witness normalization
precedes duplicate removal, so a raw witness cannot hide expired retained
evidence. Freshness inspection uses this same input owner. Native and Wasm
execution release any SQL preparation slot before their runtime acquires one.
Analysis checks captured context and result references through the same
Engine.store before it retains model provenance. Data checks the exact
dependency revisions again at the durable commit boundary.

Native execution calls the actual
[NativeLibrary](../../crates/araphor-analysis/src/package/native/loading.rs)
owner. The stateless NativeExecution wrapper is deleted. The loader checks the
qualification against its pinned files. Execution does not repeat artifact
inspection and system-library reads before loading. Native admission remains
a separate trust boundary. The native options remain on AnalysisPackageOwner.
The library creates a fresh SDK Invocation and keeps all code and file pins
through output copying and producer release callbacks. The caller checks
cancellation after loading; the library checks it before and after the call.

The Wasm branch also calls its actual
[invoke owner](../../crates/araphor-analysis/src/package/wasm/execution.rs)
directly. The duplicate prepared-input and optional-input wrappers are deleted.
Package execution retains the checked evaluation and encoded input reservation
through invocation and output decoding. Invoke owns the VM permit, engine
identity check, Store, quotas, interruption, and code pin. The outer Query
evaluation permit remains held through SDK output validation and retention.

[CheckedEvaluation](../../crates/araphor-analysis-sdk/src/validation.rs)
retains the validated package, model, and input by borrow. Its
[encode](../../crates/araphor-analysis-sdk/src/wire/evaluation.rs) method
retains the IPC allocation checks. Native
[Invocation](../../crates/araphor-analysis-sdk/src/native/mod.rs) borrows the
same proof for input exchange and output validation. These paths do not repeat
the input contract checks. The foreign guest decoders still validate raw input.
The raw wire output decoder retains its error order. The wire bytes, WIT, native
ABI, and producer release callbacks do not change.

The Session checks retained local table bytes, including the dataset row
index, before registration. Earlier local tables remain charged. Source
capture and model-input results use the native input category. Client and
model-output batches use the native output category. Borrowed Arrow buffers
retain their charges after the producer closes.

Source declarations and datasets use canonical Arrow 58 schemas and batches.
The [canonical schemas](../../crates/araphor-query/src/sources/schema.rs)
supply source fields, catalog rows, and result metadata. Field metadata defines
owner, units, null meaning, join keys, readiness, and description. Native
projections preserve the selected Field metadata. One immutable schema map is
shared across engines and reads. Capture does not build another schema map.
The query engine is
DataFusion 53.1.0. Dataset-only SQL uses the existing validators and ModelRun.
It creates no synthetic package or evaluation. DuckDB remains the durable
storage engine. Client transport reads native Arrow values in Control; the
transport path opens no DuckDB query connection.

## Source access and failure

Analysis source queries follow the retained-plan route below.
[Engine::prepare](../../crates/araphor-query/src/execution/admission.rs) owns
native parsing, original table-reference resolution, and planning for client
and E2E preparation. [Engine::subscribe](../../crates/araphor-query/src/execution/admission.rs)
uses that route and creates the native Subscription. E2E keeps the prepared
native plan for independent snapshot comparisons. E2E retains its result,
paging, cursor, health, and cleanup assertions.

[Parser::parse](../../crates/araphor-query/src/parser/mod.rs) returns one bounded native DataFusion statement
  -> [Engine::catalog](../../crates/araphor-query/src/execution.rs) registers canonical and declared local providers in the standard memory catalog
  -> [AdmittedExport::admit](../../crates/araphor-analysis/src/model.rs) retains original durable source names from native table-reference resolution
  -> [Planner::build](../../crates/araphor-query/src/planner/mod.rs) calls SessionState.statement_to_plan and binds parameters once
  -> [Planner::check](../../crates/araphor-query/src/planner/mod.rs) checks projection, join, and window resource rules on the native logical plan
  -> [ModelRun::read_input](../../crates/araphor-analysis/src/model/source/read.rs) executes the retained plan with the current authorized selection

[Planner::build](../../crates/araphor-query/src/planner/mod.rs) rejects an invalid statement, parameter, or plan
  -> [Query Error](../../crates/araphor-query/src/error.rs) preserves the native or Data error source
  -> [Query::Failure](../../crates/araphor-query/src/error.rs) classifies the structured error cause
  -> [ClientGrpcOwner::query_failure](../../crates/mithril-control/src/client_grpc/query.rs) maps the failure to a redacted client status

Parser limits SQL to 16 KiB, one statement, and recursion depth 64. The native
parser uses an 8 MiB stack region through the existing stacker dependency.
Planner accepts a read query and at most 256 parameters with a 1 MiB bound.
The standard function registry contains the admitted native scalar, aggregate,
and window functions. Standard memory catalogs perform table lookup. No
custom ContextProvider, SQL scope walker, or second binder remains.

DataFusion owns names, types, CTE scope, aliases, wildcard expansion, and
numeric behavior. Araphor checks the resulting native plan before physical
optimization. An unused CTE remains in the original source inventory. Native
expressions supply follow clock facts. Physical scans supply requested source
columns and supported time intervals.

Native expression names and numeric types reach the result schema. Integer
division stays integer division. Floating literals use Float64. An unqualified
SQL TIMESTAMP uses nanoseconds; declared source timestamps keep their Arrow
units. Quoted names use exact lookup. Duplicate projections need distinct
aliases. Native CTE alias counts and HAVING resolution apply.

[ModelSchema](../../crates/araphor-analysis/src/model/schema.rs) supplies the
allowed Arrow schema map for each stage. Source SQL sees authorized built-in
sources and declared Table aliases. Output SQL sees model inputs, parameters,
and prior checkpoint tables. Checkpoint, evidence, and reason SQL also see
completed output tables. The declared catalog defines local visibility. The
authorized Data selection defines durable source scope.

[SourceProvider::scan](../../crates/araphor-query/src/sources/mod.rs) returns a
native DataSourceExec with an immutable SourceData descriptor. The descriptor
contains its source name, exact projected schema and indices, conservative
time interval, and fetch limit. Planning reads no SourceSnapshot and changes
no projection or interval registry. Capture collects those facts from the
optimized physical tree. A retained plan has no tenant snapshot or Arrow rows.

[SourceData::open](../../crates/araphor-query/src/sources/mod.rs) reads the
actual captured SourceSnapshot from TaskContext. Native MemoryStream supplies
cooperative batch execution and fetch handling. Native MemorySourceConfig
requires batches at plan construction, so it cannot supply this run binding.
The former SnapshotPartition and both planning mutexes are deleted.
SourceData keeps native logical projection and residual filters. Its required
physical projection hook returns None, so native ProjectionExec remains above
the source. This preserves the exact source and journal schema pair.

The current source change passes all 104 Query cases, 37 model cases, and the
E2E query-follow contract. Strict Query Clippy and scoped formatting pass.
The exact source record is `/tmp/araphor-source-descriptor-qualification1.json`.
The change removes 25 nonblank production Rust lines. The corrected complete
count is `/tmp/araphor-native-rewrite-count12.json`. Wider runtime suites and
full workspace CI are not repeated. No general physical-plan reuse is claimed.

Local admission uses empty native MemTables. Before native optimization,
Session uses the native logical transformation API to bind those scans to the
current run's MemTables. It checks the complete Arrow schema, including field
metadata and nullability. This transformation does not change the retained
logical plan or replace durable SourceProvider scans. The custom LocalTable
provider and its separate SessionConfig lookup are deleted.

[SourceSnapshot::read](../../crates/araphor-query/src/sources/rows.rs) captures
requested Arrow rows and all original source receipts in one Data snapshot.
Original sources removed by optimization still supply receipts, coverage,
context references, and result references. Data bounds keys, scanned bytes,
retained input, and graph traversal. Source selection keeps explicit profile,
notification, node, binding, and time bounds. Disabled source capabilities
return a structured unavailable error.

Data emits durable inputs only. Query expands a retained profile, context, or
trace frame into its Arrow tables. The unused Behavior, DiscoveryContext,
Target, and TraceMeasurement input variants are deleted. Trace measurement
mapping calls its real table adapter directly.

The event provider uses DataFusion interval analysis for supported physical
filters. The provider narrows the intake-time read conservatively and leaves
the SQL filter in the native plan. An unsupported filter keeps the full
authorized selection. Declared microsecond timestamps remain microseconds;
the separate exact nanosecond field retains its full range.

The private captured owner retains source batches for physical execution.
Public ArrowSnapshot retains Data facts and its metadata reservation. A
retained receipt therefore does not retain the entire source batch cache.
A failed source read does not execute the model or commit a result. Rust
ownership releases local state and permits. Borrowed buffers retain their
native allocation claims through their last consumer.

## Execution and verification

[Engine::new](../../crates/araphor-query/src/execution.rs) creates the owned
Tokio runtime and native SessionState. Native execution uses one target
partition, planning concurrency one, a batch size of 200, a 64 MiB operator
memory pool, and disabled spill storage. Engine supplies selected standard
scalar, aggregate, and window functions. The engine registers no private
numeric or time-bucket function. Fixed buckets use native `date_bin`.

[Session::start](../../crates/araphor-query/src/execution.rs) supplies the
run's local tables and captured execution time
  -> [Session::physical](../../crates/araphor-query/src/execution.rs) calls native SessionState.create_physical_plan
  -> [SourceProvider::scan](../../crates/araphor-query/src/sources/mod.rs) returns immutable native source descriptors
  -> [SourceSnapshot::capture](../../crates/araphor-query/src/sources/mod.rs) collects optimized projections and interval unions, then fixes all original source receipts and requested batches
  -> [Session::start_physical](../../crates/araphor-query/src/execution.rs) binds the captured snapshot to TaskContext and calls native execute_stream with the same physical plan
  -> [Session::bounded](../../crates/araphor-query/src/execution.rs) checks output rows and bytes before it emits each batch

Physical planning has a separate bounded stage. The extraction allowance
starts at the actual store read. Stream consumption has its own evaluation
stage within the full operation control. The synchronous API uses Engine's
runtime bridge. Async callers can use the native stream directly. Native
operators determine row order. Use `ORDER BY` when the result needs order.

[Planner::check](../../crates/araphor-query/src/planner/mod.rs) accepts the
native Subquery container and checks its inner plan through DataFusion's
visitor. Native decorrelation and planning implement scalar, EXISTS, and IN
subqueries. The explicit join check applies before optimization. It does not
constrain every join that native decorrelation creates.
[Subscribe::appendable](../../crates/araphor-query/src/planner/subscription.rs) selects
Replace for expression subqueries before optimization. An earlier row can
qualify after the subquery's source changes. The
[subquery regressions](../../crates/araphor-query/src/follow/tests.rs) check
both SQL and retained-plan entry points against a complete native snapshot.

[Session::execute_input](../../crates/araphor-query/src/execution.rs) retains
model-input results in the native input category. This route uses the same
physical stream path as client output. [Session::execute_local](../../crates/araphor-query/src/execution.rs)
executes model-local plans without a durable source binding or store read.
The `local_skips_store`, `local_output_bounds`, and `local_producer_cancel`
tests cover that correction. Qualification against the final shared delivery
source remains **Not done**. ModelRun uses the local route for outputs,
checkpoints, evidence, reasons, and dataset-only queries. The correction does
not add a second SQL executor.

[ModelSchema::normalize](../../crates/araphor-analysis/src/model/schema.rs)
checks declared result names and types at the SDK boundary. Native string
views can become declared Utf8 arrays at that boundary. ModelArrays checks
permitted conversions, nested nulls, and fixed binary widths. The boundary
preserves declared Arrow metadata. The native planner applies no output-name
repair or numeric-width emulation.

[ModelArrays](../../crates/araphor-analysis/src/model/arrays.rs) calls Arrow's
cast kernel for ordinary conversions. It rebuilds nested arrays only when the
native cast does not support the declared type. Before conversion, it checks
visible values for a declared Null type. Parent null masks and list slices
exclude hidden values. The native cast alone does not preserve that rule.
The same owner estimates new buffers before ModelRun reserves conversion
memory. Binary to FixedSizeBinary includes the target width for null rows.
The [model reservation regression](../../crates/araphor-analysis/src/model/execute.rs)
requires reservation failure before casting and checks capacity recovery.

[Memory](../../crates/araphor-query/src/memory.rs) uses native memory pools
and MemoryReservation values for retained input and output. The default
shared capacities are 128 MiB input and 16 MiB output. An Arrow allocation
claim retains its charge through cloned columns, slices, child arrays, and
validity buffers. The registry holds weak allocation references. A completed
or cancelled producer releases its evaluation permit independently of those
borrowed buffers. Known metadata retains separate reservations.

These limits do not account for every temporary Arrow allocation. Native
operators account for registered allocations through their execution pool.
The buffer claims account for retained allocations. Native plan allocation
also has no complete size API. This guide makes no complete heap-bound claim.

[Subscription](../../crates/araphor-query/src/follow/mod.rs) retains a raw
native plan, the original durable source names, authorized selection, clock,
and cursor binding. Append plans use bounded Data position pages. Replacement
plans use the maintained COUNT path below when that path supports the plan.
Other replacement plans compute the complete captured input for each update.
Native expressions define supported moving windows. Notification source facts
supply the next obligation deadline. Commit changes and due deadlines wake
the subscription. A metadata-only health update takes no SQL evaluation
permit and preserves the last SQL cursor and evaluation time. Notification
metadata can require decoding the retained obligation context.

### Native physical append pages

[Subscribe::appendable](../../crates/araphor-query/src/planner/subscription.rs) selects a projection with filters and aliases over one durable events or trace_output source
  -> [State::evaluate](../../crates/araphor-query/src/follow/mod.rs) acquires the evaluation permit before the clock read and physical planning
  -> [Session::subscribe](../../crates/araphor-query/src/execution.rs) registers the actual permit and run facts in the native task configuration
  -> [Subscribe::page](../../crates/araphor-query/src/planner/subscription.rs) retains the public native SQL schema
  -> DataFusion runs its default logical and physical optimizer rules
  -> the late registered [PageLineage](../../crates/araphor-query/src/planner/subscription.rs) extends the actual native physical child with its real source positions
  -> native SanityCheckPlan checks the completed physical tree
  -> [SubscribeExec::execute_committed](../../crates/araphor-query/src/stream/physical.rs) opens the planned page child through shared Session.start_physical
  -> [Output::page](../../crates/araphor-query/src/stream/physical/page.rs) selects and compacts the disclosed prefix
  -> [State::finish](../../crates/araphor-query/src/follow/mod.rs) checks the store binding and creates Update from the completed physical output

The public append result requires a raw position for each disclosed row. A
native SQL projection can discard those fields. RecordBatchStream supplies no
separate per-row position channel. PageLineage carries the real fields through
physical execution to preserve that existing result contract.

The logical SQL plan has no added position alias or Sort. The physical source
adds its real commit_revision and ordinal columns after its existing scan
columns. Native ProjectionExec keeps its bound expressions and carries those
positions. Native FilterExec applies its mask to the complete Arrow row. An
embedded native filter projection retains its original fields and both position
fields. SourceData capture reads the final descriptor, including those fields.
Output removes the two physical fields before disclosure. The public schema,
field metadata, aliases, and values remain the native SQL result.

PageLineage runs after all default rewrite rules and before the existing final
sanity check. The complete native rule order remains intact. No duplicate sanity
check is added. Ordinary and COUNT plans need only a root check for this rule.
No name-based projection or filter rewrite runs after this rule. Public aliases can therefore equal the
position field names. The final sanity check does not rewrite expressions.
The events provider keeps its Inexact filter promise. SQL predicates remain native;
the source adds no separate filter implementation or matched-position registry.

The admitted physical path has one canonical scan and native projection,
filter, cooperative, or single-partition coalescing operators. Data emits raw
positions in global revision and ordinal order. These operators preserve that
row order. An optimizer-eliminated empty scan stays empty. The original source
inventory still supplies receipts and page progress before SQL filtering.
This rule does not establish order for joins, unions, or multiple partitions.

The page collector retains the prior logical-byte, row, staging, scratch, and
actual Arrow allocation checks. Native interleave copies the selected prefix;
view garbage collection drops undisclosed variable buffers. An output limit
keeps the last disclosed raw position. At complete SQL EOF, the cursor uses
the raw scanned-through position. A first row that cannot fit fails without
a new checkpoint. Empty filtered pages can advance raw progress.

Finite sessions and physical pages share Session.start_physical. This method
keeps the actual native task identity, configuration, function maps, and runtime.
Only the captured SourceSnapshot extension changes. Its worker keeps the
operation permit until the blocking read exits. Cancellation retains
that rule. Page execution checks the current read before returning Output.
Follow consumes that completed output and its actual reservation. One shared
State.finish method updates the cursor and wake state for bounded, maintained,
and page results. The Query owner retains source watches and health handling.
The page physical stream is one bounded read; general maintained SQL remains
**Not done**.

Selected host verification is **Done** for 150 distinct Rust cases: 112 Query,
37 Analysis model, and the E2E query-follow contract. That E2E test retains eight
behavior cases. The final Query run passes all 112 cases in 12.46 seconds.
An earlier new view fixture needs an explicit native VARCHAR cast; the corrected
fixture passes without a production workaround. Strict Query Clippy and scoped
formatting pass. The exact source and binary
record is `/tmp/araphor-physical-page-qualification1.json`.

The new checks include real trace interleaving and resume between a data frame
and terminal frame in one commit. Other checks cover NULLs, parameters,
colliding aliases, zero-column output, byte-limited view compaction, an oversized
first undisclosed row, borrowed buffers, and native task-context preservation.
Full workspace CI is not run, as instructed. These functional checks do not
establish a performance improvement.

This slice adds 227 nonblank production Rust lines. Collector relocation gives
no deletion credit. The complete count adds 1,155 from `537f9de3` and removes
1,074 from `7b7b407a`: `/tmp/araphor-native-rewrite-count15.json`. The required
6,000-line reduction still needs 4,926 net deletions. The complete redesign
remains **Not done**.

The current maintained path supports ordinary global `COUNT` over one durable
`events` source. The input contains native scan, filter, projection, or alias
nodes. The output contains projection or alias nodes above the aggregate.
Native COUNT arguments, null behavior, and aggregate `FILTER` remain native.
Grouped or distinct counts, other aggregates, and clock expressions do not
use this path.

[State::evaluate](../../crates/araphor-query/src/follow/mod.rs) requests a subscription session
  -> [Session::subscribe](../../crates/araphor-query/src/execution.rs) wraps the admitted native SQL plan with [Subscribe](../../crates/araphor-query/src/planner/subscription.rs)
  -> native SessionState runs its logical optimizer and physical planner
  -> [SourceProvider::scan](../../crates/araphor-query/src/sources/mod.rs) supplies the native execution plan with its immutable projection and time bounds
  -> [SubscriptionPlanner](../../crates/araphor-query/src/planner/subscription.rs) creates JournalExec from the actual native scan
  -> the registered ExtensionPlanner returns [SubscribeExec](../../crates/araphor-query/src/stream/physical.rs) with the native SQL child and the journal child
  -> native physical optimizers process that plan and both children

SubscribeExec retains the native input and output execution plans. Its physical
execution binds Arrow change batches through native MemorySourceConfig and
`with_new_children`. Native FilterExec and ProjectionExec keep their compiled
expressions. No second SQL parser or expression compiler runs for a change.
The former Processor and standalone aggregate helper are deleted.

The native SQL child remains bounded. Its DataSourceExec and SourceData
supply the finite source schema. Native operators retain compiled expressions.
Native global AggregateExec finishes at end of input. The unbounded journal
therefore remains a separate physical child. The journal stores the exact
native projected schema, canonical indices, and capture request once. Each
execute_committed call creates its own watch, pending changes, live beforeimages,
and reservations from the actual TaskContext. The hidden Source factory and
its separate stream module are deleted.

[State::advance](../../crates/araphor-query/src/follow/mod.rs) consumes the next completed physical result
  -> [JournalExec::execute_committed](../../crates/araphor-query/src/sources/journal.rs) reads the initial snapshot or waits for a later committed revision
  -> [AnalysisStore::change_rows](../../crates/araphor-data/src/analysis/extraction.rs) reads raw inserts and retirements through one captured revision
  -> the physical input emits one evaluation stage, Arrow changes, and a complete commit frontier
  -> native input plans process the Arrow batches
  -> the private [physical kernel](../../crates/araphor-query/src/stream/physical/kernel.rs) calls native COUNT accumulators
  -> the kernel finishes the complete frontier before native output plans run
  -> the physical output retains its exact receipt, deadline, and evaluation permit
  -> State returns Update with the receipt and cursor

The change read uses the existing raw journal and
[expired_ranges](../../crates/araphor-data/src/analysis/extraction/changes.rs).
It requires a complete source frontier `(R, u32::MAX)`. It does not emit
context, result, or trace-state changes. No query journal is added to Data.

The physical source retains projected batches and raw identity, cursor, and
position keys before SQL filters. A retirement removes those contributions.
The physical kernel retracts their filtered values. Each result receipt keeps
witnesses for all retained input, including rows removed by SQL filters.
Native Arrow equality suppresses an unchanged COUNT result.

The event provider keeps its Inexact filter promise. Native residual filters
process both inserted rows and retired beforeimages. If native optimization
removes the scan, no journal child is created. The existing complete snapshot
route returns the native result with all original source receipts. The
`journal_keeps_residual_filter` and `empty_scan_keeps_receipts` tests cover
these cases.

JournalExec declares unbounded incremental output with finite live state.
Data admits raw evidence under finite byte quotas. Each raw record has a
positive encoded size. On reopen, the bound includes the initially retained
bytes if a new quota is lower. Exact retirements remove live keys and drop
empty chunks. The journal retains one pending capture and no history ledger.
This bound applies to the admitted events source. It is not a complete heap
size measurement or a bound for other maintained operators.

The native EnsureCooperative and SanityCheckPlan rules remain enabled.
Each journal stream step uses Tokio's cooperative future wrapper. The existing
`native_subscribe_execution` test checks both rules and the real physical
children. It exhausts the Tokio task budget before polling a queued Insert.
The poll yields, then returns that same Insert after the budget is renewed.
The wrapper does not preempt synchronous work inside a capture.

DataFusion RecordBatchStream carries Arrow batches and a schema. It does not
carry a commit frontier or Araphor read receipt. The actual planned SubscribeExec
therefore supplies `execute_committed` for Query cursors. Its standard native
`execute` delegates to the same execution and returns the Arrow batches.
JournalExec rejects unsigned execute with native NotImplemented. Signed
inserts and deletes require the committed route through SubscribeExec.
The registered planner delegates ordinary planning to DataFusion.

Physical Output now carries its actual native reservation into Update.
Follow's advance method does not repeat output size checks or buffer claims.
The native Arrow iterator keeps the output metadata reservation until EOF or
drop. It releases the completed SQL permit at the original boundary. The
`native_subscribe_execution` regression checks that separation and borrowed
buffer lifetime through a second commit and cancellation. All 102 Query cases
and strict Query Clippy pass. The exact source record is
`/tmp/araphor-output-owner-qualification1.json`. Wider runtime suites and full
workspace CI are not repeated for this private ownership change.

Each State currently owns one physical execution stream. A shared maintained
query owner is **Not done**. Other plans still use State::evaluate and its hash
of the complete result. Broader maintained operators and clock processing are
**Not done**. The selected host qualification passes 195 distinct cases. Wider qualification
is **Not done**.
The complete redesign is **Not done**.

The current journal ownership change passes all 102 Query cases and the
E2E query-follow contract. Strict Query Clippy and scoped formatting pass.
The exact source hashes and checks are in
`/tmp/araphor-journal-owner-qualification1.json`. This change adds 139 nonblank
production Rust lines. It removes a hidden source owner; it does not meet the
complete reduction target. Full workspace CI is not run, as instructed.

[ClientGrpcOwner::query_request](../../crates/mithril-control/src/client_grpc/query.rs) supplies QueryEncoder and the request duration
  -> [Delivery::new](../../crates/araphor-query/src/follow/delivery.rs) retains the native Subscription, adapter, control, deadlines, and conversion reservation

[ClientGrpcOwner::watch](../../crates/mithril-control/src/client_grpc/trace.rs) supplies TraceEncoder and the trace deadline
  -> [Delivery::new](../../crates/araphor-query/src/follow/delivery.rs) uses the same delivery owner for the trace route

[Delivery::poll_next](../../crates/araphor-query/src/follow/delivery.rs) accepts caller demand
  -> [Consumer::authorize](../../crates/araphor-query/src/follow/delivery.rs) checks current client authority
  -> [Subscription](../../crates/araphor-query/src/follow/mod.rs) supplies a native update when no disclosure is pending
  -> [Engine::check_read](../../crates/araphor-query/src/execution.rs) checks the receipt read scope
  -> [Consumer::encode](../../crates/araphor-query/src/follow/delivery.rs) converts one borrowed Action and Update into the adapter's protocol value
  -> [Consumer::authorize](../../crates/araphor-query/src/follow/delivery.rs) checks current authority again
  -> [Delivery::poll_next](../../crates/araphor-query/src/follow/delivery.rs) commits the cursor only for a completed checkpoint
  -> [Delivery::poll_next](../../crates/araphor-query/src/follow/delivery.rs) returns the encoded item

[QueryEncoder](../../crates/mithril-control/src/client_grpc/query.rs) and
[TraceEncoder](../../crates/mithril-control/src/client_grpc/trace.rs) implement
Consumer. Their authority methods use ClientAccess and supply authorization
changes and expiry. Query Delivery owns disclosure phases, pending rows, the
last completed cursor, read checks, duration, output wait, conversion
reservations, and cleanup. Control supplies protocol encoding, trace
terminal validation, and per-target result assembly. Query Delivery serves
both protocol routes.

Delivery retains the original native update through Metadata, rows, and
Checkpoint. A completed checkpoint releases the Arrow batches. The retained
receipt contains Data facts for later disclosure checks. A later failure
keeps the last completed cursor. A successful item keeps its conversion
reservation until the next poll or drop. A failed conversion releases its
reservation immediately. Output wait applies when the caller requests the
next item; waiting for a source change does not consume that allowance.

[Wire](../../crates/mithril-control/src/client_grpc/wire.rs) reads native Arrow
scalars and Field metadata. Timestamp parameters keep their declared units.
Native decimals keep their precision, scale, and unscaled value within
protocol limits. Native failures return typed, redacted errors. Query owns
no protocol frame type or DuckDB scalar conversion layer. The borrowed Action
is an encoding instruction, not a retained query or result wrapper.

The run retains control, reservations, and backend handles while work runs.
Output tables keep one dataset-global row index across batches. Checkpoint,
evidence, and reason plans reuse those tables. Native foreign output remains
validated and copied into host-owned storage before the library is released.
A completed model result becomes durable only after the existing authorized
Data transaction.

The current source reading route is:

- [Planner tests](../../crates/araphor-query/src/planner/tests.rs): native names, CTE scope, parameters, visible row indices, joins, windows, and rejection of writes.
- [Source tests](../../crates/araphor-query/src/sources/tests.rs): `unused_source_receipts`, `empty_filter_progress`, zero-column counts, native interval pruning, and timestamp precision.
- [Execution tests](../../crates/araphor-query/src/execution/tests.rs): repeated native plans, local bindings, runtime entry modes, cancellation, permits, and input/output category separation.
- [Native loader tests](../../crates/araphor-analysis/src/package/native/loading.rs) and [native package cases](../../crates/araphor-analysis/src/package/tests/native/mod.rs): pinned files, ABI and dependency errors, invalid paths, disabled options, cancellation, checkpoints, lifecycle, and host fault recovery.
- [Prepared Wasm tests](../../crates/araphor-analysis/src/package/wasm/tests/runtime/prepared.rs): engine identity, cancellation, code pins, and retained prepared execution after cache removal.
- [Memory tests](../../crates/araphor-query/src/memory.rs): shared buffers, nested children, borrowed aliases, capacity denial, and producer cancellation.
- [Native template tests](../../crates/araphor-query/src/stream/tests.rs) and [physical kernel tests](../../crates/araphor-query/src/stream/physical/kernel/tests.rs): native parameters, NULL filters, zero-column row counts, native COUNT updates and retractions, aliases, errors, exact metadata, borrowed arrays, and schema checks.
- [Raw change tests](../../crates/araphor-data/src/analysis/extraction/changes/tests.rs): existing-journal replay, retirement ranges, complete frontiers, scope, and resource bounds.
- [Follow tests](../../crates/araphor-query/src/follow/tests.rs): append positions, `health_keeps_cursor`, `count_consumes_committed_changes`, `moving_window_nanoseconds`, `notification_follow_deadline`, and cursor binding. The COUNT case checks later insert scans, full retained witnesses, retraction after retention, and released reservations.
- [Delivery tests](../../crates/araphor-query/src/follow/delivery/tests.rs): disclosure phases, conversion lifetime, immediate failure cleanup, renewed output demand, native waits, and authority changes during native waits or read checks.
- [Model operation tests](../../crates/araphor-analysis/src/model/operation/tests.rs): exact input order, revisions, original provenance, retained capacity, and local source scope.
- [Model tests](../../crates/araphor-analysis/src/model/tests.rs) and [package lifecycle tests](../../crates/araphor-analysis/src/package/tests/lifecycle.rs): checkpoints, parameters, evidence, source bounds, retries, and installed revisions.
- [Interruption tests](../../crates/araphor-analysis/src/package/tests/interruption.rs): authority change, cancellation, stop before commit, Busy, and preservation of committed state.
- [Control tests](../../crates/mithril-control/src/client_grpc/tests.rs) and [follow E2E cases](../../crates/mithril-e2e/src/discovery/query_follow.rs): actual protocol frames and native subscription behavior across owners.

The source state is the uncommitted rewrite on 2026-10-16. The recorded Query
library run passes 60 tests in 9.12 seconds. The Analysis library run reports
303 passed, 9 failed, and 16 ignored tests in 357.51 seconds; its build takes
52.46 seconds. Control and E2E test targets compile in 40.33 seconds. Their
runtime checks remain **Not done**. Fixes after these runs, including local
execution, need new qualification. Those runs do not qualify the later shared
Delivery, maintained COUNT, or current caller edits. Their qualification
remains **Not done**.
The complete production reduction remains **Not done**. No performance
improvement is claimed.

### Earlier qualification records

The [mixed package retry case](../../crates/araphor-analysis/src/package/tests/wasm/metadata.rs)
uses two valid native queries with different source text. The changed query
keeps the declared binary schema. The case checks revision conflict and the
unchanged retained revision after repeated encoding and reopen. Unsupported
`BLOB` syntax previously stopped admission before the conflict check. The
corrected case and 48 admission cases pass on the final Data build. Strict
Clippy and scoped formatting pass. The record is
`/tmp/araphor-native-sql-fixture-qualification1.json`. This result covers the
fixture correction and test imports only.

At engine commit `34a8199c`, the
affected build and strict Clippy pass. All 460 distinct selected cases pass: 439 ordinary Data cases,
12 native Data cases, six Control cases, and three E2E cases. The native
detector E2E case runs with PATH empty. Qualification covers Linux,
x86_64-unknown-linux-gnu, and glibc 2.39. Other targets remain unqualified.

The first native checkpoint replay correctly reports Busy while the test
retains a checkpoint alias from its prior output. The corrected test proves
that denial, then reloads checkpoint bytes through the standard wire codec
and proves replay. Production already uses stored checkpoint bytes. All
ordinary Data cases and eight caller cases pass before that test-only edit.
Production source and manifests stay identical. The final build covers the
corrected native case and native E2E. The result record is
`/tmp/araphor-arrow-engine-qualification-final.json`. The
[plan result](../plans/araphor-component-redesign.md#qualification-and-acceptance)
lists the source, test, artifact, and platform receipts.

The following direct plan change passes the affected Data build and 262
selected cases: 256 query cases, four package cases, and two explicit native
error/checkpoint cases. The first query run reaches the host filesystem
reserve. Only its 88 failed cases run again after obsolete generated binaries
are removed; all pass. Strict Clippy passes for Data, Control, and E2E test
targets. Their runtime integration cases are not repeated for this change.
The [plan result](../plans/araphor-component-redesign.md#qualification-and-acceptance)
lists those separate receipts and the current production count.

The source scan change prepares one optimized plan before extraction and
executes that same plan with admitted MemTables. All 263 selected cases pass:
259 query cases and four package cases. The final build and strict Clippy for
Data and its callers pass. Only two test files change after the first
258-query and three-package pass. Both corrected cases pass on the final
build. The count case checks retained real source buffers with a zero-column
scan. The budget cases keep both narrow-query success and wide-query denial
at unchanged limits. The unused-CTE case keeps full witnesses and the existing
content-based revision rule. The result record is
`/tmp/araphor-source-plan-qualification1.json`.

The canonical source-field and table-map changes pass the affected Data build,
260 query cases, six package cases, and strict Clippy for Data and its callers.
The metadata tests check exact dictionaries and shared Schema and Field
allocations. Operation and package cases preserve alias scope, source
provenance, capacity denial, and cleanup. A broad package selection is stopped
before the six affected cases run. The interrupted run is not counted as
qualification. Native and caller runtime cases are not repeated. The result
record is `/tmp/araphor-canonical-fields-qualification1.json`.

The admitted SQL model execution change passes 52 affected cases. The first
run passes 51 cases and rejects the new test's invalid reason namespace. Only
that test file then changes. The final test uses the required namespace and
a shorter name. It passes against the final affected build. Strict Clippy for
Data and its callers passes. Production and manifests remain unchanged.
The cases check descriptor order, independent admitted execution, reason
bindings, vector capacity, installed pairing, current grants, snapshot reuse,
invalid indices, and cleanup. Native and caller runtime cases are not repeated.
The result record is `/tmp/araphor-admitted-runtime-qualification1.json`.

The admitted input-program change passes the affected Data build and all 53
selected cases. The first run passes 32 cases and reaches the host filesystem
reserve in 21 cases. After two obsolete generated test binaries are removed,
only those 21 cases run again. All pass with unchanged production, limits,
and test binary. Strict Clippy for Data and its callers passes. The new case
checks declaration order, mixed-case aliases, unused CTE dependencies, exact
wire bytes, revisions, evidence, retained capacities, and cleanup. Native and
caller runtime cases are not repeated. The result record is
`/tmp/araphor-input-program-qualification1.json`. The change adds 54 production
lines. The complete reduction remains open.

The complete earlier receipts remain at
`7b7b407adf347d389984553a4d212bfce37b75b5:docs/guides/araphor-sql-operation-review.md`.
They include failed attempts, corrections, source hashes, and Linux x86_64 GNU
native qualification. They establish no causal SQL speed improvement. They
do not qualify the current DataFusion integration. The complete production reduction remains **Not done**.
A new performance workload is not part of this deletion work.
