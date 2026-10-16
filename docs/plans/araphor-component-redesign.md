# Araphor Component Redesign Proposal

Source study: **Done**. Implementation: **Not done**. The user approves
implementation of this redesign and requires a commit for each deliverable.
The source baseline is `537f9de3`. DataFusion and Mangroves supply the source
lessons below. The complete redesign must reduce real production Rust code.

This proposal supports the
[performance simplification TODO](araphor-performance-simplification-todo.md).

Before this redesign, the committed code removes 2,229 nonblank production
Rust lines from `7b7b407a`. The remaining target at that baseline is 3,771.
None of the source inventories below is a net reduction. Count the complete
replacement before a completion claim.

The working tree now routes queries through DataFusion. `QuerySql` retains a
shared immutable program with its logical plan. `PlannerContext` supplies CTE and derived-query scope. Arrow
batches supply client, model, and dataset inputs. Affected compilation and
functional qualification pass on the host below. The whole-code reduction is
**Not done**. Earlier retained-admission receipts do not qualify this route.

## Intended end state

Use one Arrow schema and one columnar query operation from authorized source
selection to SQL output. The existing package owner retains one immutable
admitted program per exact installed closure. Each run owns its mutable inputs,
checkpoint, control, and resource leases. The existing store remains the only
durable owner of evidence, progress, results, references, and quotas.

The user approves the SQL engine replacement through the implementation
request. This approval replaces the earlier DuckDB-only constraint for query
execution. The working tree selects DataFusion 53.1.0 and Arrow 58.4.0 in
Cargo.lock. Affected compilation and functional qualification pass.
DuckDB continues to own retained metadata and graph tables. This proposal
changes the private in-memory SQL engine only. The native and Wasm execution
backends do not change.

Coherence review: **Done for owner boundaries**. The review found missing
parser, SQL binding, caller, resource, and execution-boundary requirements.
The sections below record them. The source now includes the engine and
synchronous execution route. The affected execution, resource, and parity
cases pass on Linux x86_64 GNU. The complete production reduction remains
**Not done**. These checks do not qualify another platform or measure speed.

## Columnar query operation

A caller submits client SQL or a package input/output query
  -> QueryOwner checks the request grant and constructs its authorized source scope
  -> Binder checks SQL length, parameters, recursion, statements, and functions
  -> SqlToRel resolves names and types against canonical Arrow schemas
  -> QuerySql retains the logical plan and full-query source dependencies
  -> source scans capture exact revisions, witnesses, context references, and coverage
  -> source scans admit bounded Arrow batches before buffer growth
  -> one query operation executes input and output plans over those batches
  -> the caller receives the result with its retained resource leases

A row matches no SQL predicate
  -> provenance retains required source observations before predicate pruning
  -> append progress can advance across the empty output

One source record produces several rows
  -> source admission accepts or rejects that whole record
  -> the next cursor cannot omit part of its output

Authorization changes, a deadline expires, or execution fails
  -> the operation requests cancellation and drops its query streams
  -> running tasks retain input buffers, leases, and backend pins until they finish
  -> running native calls retain their guards until return and producer release
  -> cancellation observed at the final store check rejects the transaction

A transaction passes its final cancellation check
  -> the store can commit before a concurrent cancellation takes effect
  -> the committed result and checkpoint remain durable
  -> recovery and retry use the exact immutable commit identity

A returned batch outlives its run
  -> its transferred or shared leases cover owned and aliased input buffers
  -> the final consumer releases those leases with the batch

### Existing DataFusion composition

The working tree uses the standard `EmptyTable` and `MemTable` owners. It
adds no Araphor table-provider framework or physical operator.

A query needs admission
  -> Binder walks every original common table expression (CTE), derived query, and source relation
  -> SqlContext supplies schema-only EmptyTable sources
  -> PlannerContext retains bound CTE and derived-query plans
  -> SqlToRel resolves the SELECT clauses against those bound plans
  -> QuerySql retains the logical plan, dependencies, labels, and clock facts

A run prepares its fixed source selection
  -> QuerySql::bind_complete binds parameter values and the captured clock
  -> QueryEngine::prepare optimizes the logical plan once
  -> InputProjection selects canonical fields from the optimized TableScan projections
  -> the current extraction owner supplies qualified batches and full source provenance
  -> QueryEngine::bind_sources consumes that same plan and supplies admitted MemTables
  -> QueryEngine::stream creates the physical plan and its batch stream

EmptyTable has no data statistics. Treat a schema-only scan as an unknown
source during planning. Binder records base relations while it walks the full
original abstract syntax tree (AST), including unused CTEs. A constant-false predicate can remove a
scan during optimization. The retained source inventory therefore supplies
dependency and witness scope before pruning. The original AST also supplies
time bounds, source-column facts, and append cursor facts.
The transient planning AST does not replace those facts.

Field selection comes from standard optimized scans for all built-in tables.
The source no longer retains a separate event-field AST collector. Extraction
still uses every original admitted dependency, including unused CTEs and
sources removed by optimizer pruning. A source with no requested column keeps
one existing canonical field so its real buffer retains the source lease.
Its physical scan can still project zero columns. Finding inputs also retain
the keys required to select their latest revision before SQL filtering.

Binder stores each completed child plan in the standard PlannerContext.
SqlToRel plans the full SELECT directly. Binder uses the admitted child
schemas for wildcard, window, and compatibility checks. It checks the final
unoptimized joins before constant pruning. The source no longer creates a
synthetic FROM-only SELECT or a temporary FROM plan. The retained logical
plan contains real source scans and does not depend on the transient context.

After scan replacement, QueryEngine::stream calls
`query_planner().create_physical_plan`. It does not call
`SessionState::create_physical_plan`, which repeats logical optimization in
DataFusion 53.1.0. The public planner still performs physical planning and
physical optimization.

Physical execution uses execute_stream_partitioned and reads the final
output partitions in partition order. The optimizer retains Union instead
of replacing it with Interleave. This route preserves branch order for the
model fixture whose final plan is Union. Internal physical operators can
merge partitions. Use ORDER BY when result order is required. The route
uses standard stream composition and adds no physical operator.

A TableScan projection indexes its original source schema. QueryEngine::bind_sources
maps each requested field to the admitted MemTable by exact field name. It
checks the field type and builds a new TableScan with the mapped indices.
The scan keeps its filters and fetch bound. Replacing only the provider Arc
would leave incorrect indices when extraction supplies a reduced schema.

Each source declaration creates one canonical Arrow schema. Emission, SQL
binding, projection, catalog rows, and result metadata read its fields. The
source no longer stores a parallel InputField name, type, and unit descriptor.
InputSchema retains relation facts and ordered absence text. The Arrow field
metadata keeps the same four keys and values. A static schema owner preserves
borrowed field metadata and shared Schema and Field allocation identities.

ModelOperation owns one map of admitted Table aliases. Each source statement
moves that map into ModelExecution. The statement removes its temporary
built-in tables before it returns the map. Final model execution consumes the
same map. Failure drops the transferred map and operation lease handles.
Shared buffer reservations remain until their last owner drops. This route
removes registry copies between source and output stages.

### Owners to replace

| Before-redesign owner | Baseline production nonblank lines | Complete replacement responsibility |
| --- | ---: | --- |
| `query/admission.rs` | 1,564 | Keep SQL policy, parameter bounds, frozen time, append shape, source scope, and the compatibility checks below. Use engine name and type binding where it preserves those checks. |
| `query/input.rs` | 2,008 | Keep public relation names, column metadata, event decoding, coverage, catalog, recipes, and exact projection semantics. Produce canonical Arrow batches directly. |
| `query/adapter.rs` | 206 | Remove the scalar InputTable/InputColumn contract. DataFusion consumes canonical Arrow batches directly. |
| `query/model/schema.rs` and `arrays.rs` | 337 | Remove DuckDB physical-type copies and reverse normalization if SQL runs on canonical Arrow types. Keep output field and metadata validation. |
| `query/model/input.rs` | 144 | Remove temporary SQL table creation and Arrow append when the engine consumes registered Arrow sources directly. Keep row indices and input limits. |
| `query/analysis/rows.rs` | 154 | Remove the second scalar-to-Arrow conversion for graph inputs. Keep graph selection, traversal receipts, and pre-admission bounds. |
| `query/evaluation.rs`, `model/execute.rs`, and `model/operation.rs` | 625 | Compose one operation for client output, model inputs, datasets, checkpoint, evidence, and reasons. Keep each output contract and lease lifetime. |

These owners contain 5,038 nonblank production Rust lines in total, including
source comments. The current syntax counter excludes test-only spans. The
file-level count record is `/tmp/araphor-datafusion-owner-inventory.json`.
Most domain field mappings and policy checks still need code. This number
is the source scope, not a promised deletion. A design that only moves those
mappings does not meet the target. If all 5,038 lines are removed, with no
other deletions, the complete replacement can add at most 1,267 production
lines to meet the remaining 3,771-line target. This budget is not proved.

Check the complete replacement budget before routing callers to the new
engine. Include retained-program additions, SQL normalization, UDFs, runtime
execution, resource guards, source builders, extraction, and caller changes.
Include public result conversion. A component can grow when the complete
redesign removes more representations, repeated work, or ownership paths.
Apply the reduction target to the complete redesign, not to each file or
deliverable. Check coherence and correctness with that total.

The measured subset excludes these connected owners. Count their complete
changes in the replacement; do not treat the subset as the full migration:

| Connected owner | Required behavior |
| --- | --- |
| `query/mod.rs`, `query/plan.rs`, and `query/frame.rs` | Preserve client columns, values, timestamps, Decimal, and integer ranges at the public result boundary. These types currently depend on DuckDB values. |
| `mithril-control/src/client_grpc/wire.rs` | Preserve the existing wire values and column type names. Arrow `UInt32` does not by itself preserve the current `UInteger` metadata. |
| `analysis/read.rs` and `error.rs` | Keep storage interruption. Add query-stream cancellation to the existing operation control. Preserve cancellation, deadline, admission, limit, and execution error categories. |
| `analysis/extraction.rs` | Keep source selection, page admission, record fanout, and cursor advancement. Return the Arrow accumulator only when extraction succeeds. |
| `package/evaluation.rs`, `freshness.rs`, and installed callers | Use the same admitted package program for manual execution, freshness, supervision, and snapshots. |
| `query/model/datasets.rs` and `package/inspect.rs` | Preserve checked transient dataset SQL, including result inspection. This path has no installed package program to reuse. |

For example, a detector that reads `events` and an earlier package output
should obtain two Arrow sources in one operation. Its SQL input query returns
another batch in that same operation. The model output, checkpoint, and reason
queries read those sources without rebuilding DuckDB physical schemas or
copying the batches into temporary native tables.

Use the existing InputProjection to accumulate standard Arrow builders and
batches. Keep row admission in ProjectionSink before the builders change. If
the first row of a source record does not fit the remaining page, retain the
cursor before that record. If a later row from that record fails admission,
return the error and drop the operation's accumulated buffers. Do not return
partial output or add a rollback buffer.

Keep relation semantics before SQL predicate pushdown. The current `findings`
view selects the greatest commit revision for each tenant and finding. For
example, an old `high` finding followed by a current `low` finding must produce
no row for `WHERE severity = 'high'`. Registering all revisions as a bare
MemTable would change this result. Use the existing source owner or standard
engine composition for this selection.

Capture accepted row counts and the earliest selected event receipt time
before column pruning. Follow uses that time to schedule idle window expiry.
A zero-column Arrow batch must retain its row count for `COUNT(*)`.

### Statement scope and output rows

One operation does not grant every statement access to every relation. Keep
the current stage-specific relation sets from
[model schema construction](../../crates/araphor-data/src/query/model/schema.rs:13)
and [model evaluation](../../crates/araphor-data/src/query/model.rs:201):

| Statement | Allowed relations |
| --- | --- |
| Source SQL | Authorized built-in sources and declared Table aliases. A Query input is not a Table alias. |
| Model output SQL | Declared model inputs, `parameters`, and `prior_*` checkpoint relations. Other `output_*` relations are not available. |
| Checkpoint, evidence, and reason SQL | The model relations plus the completed `output_*` relations. |

The run executes a model output query
  -> the operation materializes that output once and fixes its batch order
  -> it assigns zero-based `__row_index` across the complete dataset
  -> it registers the same batches as the corresponding output relation
  -> checkpoint, evidence, and reason queries read those batches
  -> SDK row references select the same rows in every stage

Keep dataset-global ordinals across batch boundaries. A new batch must not
restart the row index. Preserve source cleanup between statements and denial
of undeclared sources. Do not re-execute a model output to serve a later query.

### Binding behavior that must remain

DuckDB's binder skips unused CTEs and removes duplicate derived column names.
Araphor's current tests reject an invalid unused CTE and duplicate aliases.
For example, this input must still fail before a source read:

```sql
WITH unused AS (SELECT missing_field FROM events)
SELECT operation FROM events
```

A replacement must preserve current checks across the full admitted query
closure. Engine dependency extraction alone is insufficient. Hidden columns,
external functions, tenant selection, and evidence capture before pruning
remain Araphor responsibilities.

DataFusion 53.1.0 rejects a nested CTE that uses an outer CTE's name. Current
Araphor permits that scope. For example, both definitions of `t` below are
valid in the current contract:

```sql
WITH t AS (SELECT operation FROM events)
SELECT operation FROM (
  WITH t AS (SELECT operation FROM events)
  SELECT operation FROM t
) x
```

The working tree resolves each child query with a cloned PlannerContext.
Binder inserts a completed CTE plan under that query's name. A nested context
can replace an inherited CTE name. The outer context keeps its own binding.
This route replaces the proposed AST CTE renaming pass. Exact Expr::Column
projections preserve partial column aliases and declared names. Keep the
existing shadowing and duplicate-alias tests.

DataFusion also leaves an unused named window unresolved. Current Araphor
rejects this query because `missing_field` does not exist:

```sql
SELECT operation FROM events
WINDOW unused AS (ORDER BY missing_field)
```

Binder keeps the full-AST checks for window names, shape, and functions. It
also calls SqlToRel::sql_to_expr for unused window partition and ordering
expressions against the bound FROM schema. Normal wildcard expansion uses
that same schema and removes the model row index before SELECT binding.
DataFusion TableSource has no hidden-column rule for this contract.
The affected compilation and functional checks pass in the receipts below.
Do not infer a stronger type-validation guarantee for every unused expression.

Preserve HAVING name precedence from `query_admission_having_aliases`: a
grouped source column takes precedence over an output alias; otherwise use
the alias. DataFusion can select an ungrouped base column instead. Preserve
unnamed duplicate expressions such as `SELECT 1, 1`; DataFusion rejects their
duplicate generated projection names. Resolve these cases in the same
admission path and count that code in the replacement.

## Local DataFusion source basis

The source study read `datafusion/` at commit `cdc2fc041`. The implementation
uses the local `53.1.0` tag as its API source. The table below names paths in
that tag:

| Source | Rule to apply |
| --- | --- |
| `datafusion/catalog/src/table.rs`, `TableProvider::schema` and `scan` | A source supplies one Arrow schema and a scan plan. Planning does not require scalar rows. |
| `datafusion/common/src/dfschema.rs`, `DFSchema` | Add qualifiers to the canonical Arrow schema. Do not maintain another field-type model. |
| `datafusion/physical-plan/src/execution_plan.rs`, `ExecutionPlan::execute` | Keep executable plan nodes separate from output streams. Create fresh execution state for each run. Do not assume a physical plan is immutable or reusable. |
| `datafusion/execution/src/stream.rs`, `RecordBatchStream` | Pass Arrow batches between execution stages with one schema, including an empty result. |
| `datafusion/execution/src/memory_pool/mod.rs`, `MemoryReservation` | A run owns reservations. Drop releases them. The pool does not account for all input and output batches. |
| `datafusion/physical-plan/src/windows/bounded_window_agg_exec.rs` | Window execution retains and removes bounded state. This owner does not replace durable replay or commit authorization. |

The study checkout declares DataFusion 55.1.0, Rust 1.95, and Arrow 60. That
checkout is not the selected engine dependency. Cargo.lock now selects
DataFusion 53.1.0, Arrow 58.4.0, and sqlparser 0.61.0. Admission imports the
parser through DataFusion. The separate workspace sqlparser 0.63.0 dependency
is removed. The crate enables `sql`, `unicode_expressions`, and
`recursive_protection`. Compilation and functional qualification remain
pending. Keep one Arrow version at the SDK and engine boundary.

### Execution and resource gates

The current `query_at`, `query_cancel`, `evaluate_model`, and `query_datasets`
APIs are synchronous. Ordinary Rust tests call them without a Tokio runtime.
Production result inspection also calls `query_datasets`. QueryOwner now
owns QueryEngine, which creates one Tokio execution runtime on first use.
ModelOperation creates SessionState and its query lease on first SQL use.
Client evaluation creates SessionState for that evaluation. The authority
watch retains its separate notification runtime.

DataFusion SQL-to-logical planning is synchronous. Physical planning and
stream consumption are asynchronous. Some physical
operators spawn Tokio tasks. A future executor alone does not prove that
these plans can run outside Tokio. `RuntimeEnv` configures engine resources;
it is not a Tokio executor.

QueryEngine::run dispatches physical planning and stream consumption to its
owned runtime. It returns the result through a synchronous channel. The
operation retains its control and leases while the dispatched work runs.
Qualify this boundary for all four synchronous APIs and their callers.
Preserve their supported contract. An API change requires an explicit decision. Require cases outside Tokio,
inside current-thread and multithread runtimes, and through the current
blocking-worker path. Exercise a plan that starts child work, cancellation,
and final lease release. Do not assume nested `block_on` calls work. Do not
add a per-query runtime or another runtime/pool framework to hide this gap.
This gate is **Not done**.

The current
[engine configuration](../../crates/araphor-data/src/query/engine.rs)
sets a 64 MiB memory pool, one execution partition, planning concurrency one,
and disabled spill storage. SqlContext exposes only admitted relations and
registered functions. DataFusion's defaults
use an unbounded memory pool, operating-system temporary storage, and
CPU-count concurrency. Those defaults do not preserve current behavior.

Configure bounded engine reservations, disabled spill storage, and execution
and planning parallelism in the existing operation. Keep external stores,
file reads, and unapproved functions unavailable. Preserve the current
resource policy; add no new user option or package cap. Keep QueryLease
charges for input, output, schema, and aliased buffers. The engine pool omits
some streamed allocations and cannot replace those charges. Prove that
exhaustion returns the existing structured failure, writes no spill files,
and releases reservations. The affected resource cases pass in the
qualification below. Other platforms remain unqualified.

Retain the original full buffer allocation charge through Arrow clones,
slices, nested children, and validity buffers. A result wrapper or TaskContext
alone does not own all these lifetimes. Test a small slice and cancelled child
work after their parent operation drops. Keep evaluation-slot release separate
from final input-buffer release. Extend QueryLease; add no second budget owner.

Also test a small aliased output under a tight existing output-byte limit.
SDK validation counts retained array allocations; a short slice can retain
a large input buffer. Shared input charges alone do not preserve that output
contract. Use standard Arrow compaction only where the contract requires it.

Keep canonical SDK field types at the result boundary. DataFusion 53.1.0
maps strings to `Utf8View` by default; the current SDK declares `Utf8`.
Configure the supported type or perform the minimum required normalization.
Preserve field names, metadata, nullability, and current wire type labels.
Add no engine-neutral value or cancellation framework. Count the required
boundary conversion and error mapping in the replacement.

## Mangroves source study

The source root is `/home/navid/go/src/github.com/mangrovesdb/mangroves`.
The checked commit is `abce2ac64b95e80ef18d7b330a0f91a0bf8ba063`.
The checkout has no tracked changes. Its lock file selects DataFusion 15.0.0,
Arrow 28.0.0, and sqlparser 0.27.0. Reuse the owner boundaries below. Use the
selected current APIs for implementation; do not port these old API calls.

### Reading route and plan changes

| Mangroves source | Observed behavior | Araphor plan change |
| --- | --- | --- |
| [SQL planner](/home/navid/go/src/github.com/mangrovesdb/mangroves/src/sql/src/plan/planner.rs:44) | Ordinary SQL goes to `SqlToRel`. Subscribe is a separate top-level operation over the resulting engine plan. | Use engine SQL planning directly. Keep package scheduling, follow checkpoints, and durable commits in their existing Araphor owners. Add no second logical-plan hierarchy. |
| [Chain table](/home/navid/go/src/github.com/mangrovesdb/mangroves/src/chain/src/table.rs:167) and [batch stream](/home/navid/go/src/github.com/mangrovesdb/mangroves/src/chain/src/datastream.rs:84) | A domain table supplies a schema and scan plan. Each execution produces Arrow batches. | Make Arrow the internal query data format. Use standard `EmptyTable` and `MemTable` for this implementation. Keep source admission in the existing extraction owner. |
| [Query execution](/home/navid/go/src/github.com/mangrovesdb/mangroves/src/sql/src/execution/query.rs:30) and [session creation](/home/navid/go/src/github.com/mangrovesdb/mangroves/src/sql/src/context.rs:223) | A query creates fresh session state and calls `execute_stream`. | Reuse immutable admitted programs. Create each run's admitted source map, value bindings, physical plan, streams, clock, and checkpoint state separately. Use public session builders. |
| [Source notification](/home/navid/go/src/github.com/mangrovesdb/mangroves/src/chain/src/schema.rs:117) and [subscription wait](/home/navid/go/src/github.com/mangrovesdb/mangroves/src/sql/src/execution/subscribe.rs:109) | The source reports progress and wakes a waiting query. | Use existing Data and authority revision subscriptions and recorded deadlines. Keep source progress separate from query output. A wake is a reason to check state; it is not a durable acknowledgement. |
| [Source wrapper](/home/navid/go/src/github.com/mangrovesdb/mangroves/src/sql/src/table_source.rs:13) and [physical planner](/home/navid/go/src/github.com/mangrovesdb/mangroves/src/sql/src/execution/planner.rs:394) | A custom logical source retains its schema provider. A local physical planner unwraps that source and implements standard engine operations. | Keep progress subscriptions beside the admitted dependency set. Use standard engine table sources and the standard planner. Add a public UDF or extension hook only for a required operation that standard composition cannot express. |
| [Plan adapters](/home/navid/go/src/github.com/mangrovesdb/mangroves/src/common/query/src/physical_plan.rs:39), [table adapters](/home/navid/go/src/github.com/mangrovesdb/mangroves/src/table/src/table/adapter.rs:52), and [batch adapters](/home/navid/go/src/github.com/mangrovesdb/mangroves/src/common/recordbatch/src/adapter.rs:59) | Separate domain and engine plan, table, schema, and batch types require adapters in both directions. | Retain canonical Arrow schemas, batches, and engine plans. Add no engine-neutral copies of DataFusion's traits. Keep Araphor metadata only where it supplies authority, evidence, progress, or resource ownership. |
| [Storage writer](/home/navid/go/src/github.com/mangrovesdb/mangroves/src/storage/src/region/writer.rs:354), [snapshot](/home/navid/go/src/github.com/mangrovesdb/mangroves/src/storage/src/snapshot.rs:29), and [flush](/home/navid/go/src/github.com/mangrovesdb/mangroves/src/storage/src/flush.rs:230) | Storage owns WAL ordering, visible sequence, snapshots, SST persistence, and manifest changes. | Keep AnalysisStore as the durable owner. Query execution consumes its qualified inputs. DataFusion does not receive commit, recovery, retention, or quota authority. Add no Mito, WAL, or manifest subsystem for this change. |

The active daemon wires `ChainCatalogFactory` into SQL in
[daemon startup](/home/navid/go/src/github.com/mangrovesdb/mangroves/src/daemon/src/lib.rs:45).
The storage/table adapter family is a separate source path with local tests.
Its existence does not prove that the daemon uses the full storage stack.
Mangroves captures Mito snapshots separately for each region. That does not
prove one atomic revision across all queried tables. Preserve Araphor
source-revision comparisons and dependency checks at commit.

### Source and stream behavior to preserve

An existing source revision changes or a recorded window deadline arrives
  -> the current owner checks affected dependencies and current authority
  -> it selects an exact snapshot or source range for this run
  -> query execution reads bounded Arrow batches from that fixed selection
  -> output preserves source progress, coverage, and evidence captured before pruning
  -> the existing store commits result and progress together where required

The selected range remains immutable during the run. Do not refresh a shared
catalog to change the inputs of a bound plan. A bound TableScan retains its
source Arc. The source schema alone does not establish a snapshot, grant,
retention floor, or memory reservation.

Mangroves' current `DataProviderTable::new` discards its supplied time bounds.
Its scan ignores filters and limits. Projection occurs after `provider.get`
returns a complete batch. Therefore this code supplies a useful source seam,
but it does not prove Araphor's bounds or source qualification. Keep admission
before buffer growth and keep record fanout atomic. Keep all required evidence
when SQL returns no rows. Repeated scans and self-joins need independent read
cursors over the same fixed source selection.

Do not reuse the subscription implementation unchanged. Its
[subscription execution](/home/navid/go/src/github.com/mangrovesdb/mangroves/src/sql/src/execution/subscribe.rs:185)
collects complete results, concatenates arrays, and converts execution errors
into empty output. Araphor must stream bounded batches and return errors.
Running child work retains its resource guards until it finishes. Cancellation
does not promise forced preemption of an in-process native call.

The [single-use scan test](/home/navid/go/src/github.com/mangrovesdb/mangroves/src/table/src/table/scan.rs:94)
executes a scan once and requires a second execution to fail. This is a reason
to retain an admitted program, not a live stream or mutable physical plan, in
InstalledBundle. Each invocation creates fresh execution state.

### Proof added to the proposed replacement

Require normal Rust tests beside the changed owners. Preserve current tests
and every distinct assertion when their implementation changes. Add proof for
these transferred lessons in the affected test groups:

- Bind schema-only tables without reading a source. Replace the actual bound
  scan sources before execution. Keep dependencies from unused CTEs.
- Preserve reordered and non-prefix column projections after replacing a scan
  source. Check column values, names, types, metadata, and output order.
- Preserve both witnesses in the existing
  [pruned source evidence case](../../crates/araphor-data/src/query/model/operation/tests.rs:278),
  including `operation = 7 AND false`.
- Keep a run's captured revision while new data arrives. Preserve independent
  cursors for repeated scans, joins, and a second invocation.
- Wake on relevant source or authority changes and due deadlines. Preserve
  idle window expiry, bounded source-page draining, and empty append progress.
- Propagate source and execution errors. Preserve cancellation and resource
  charges until child work and the final output consumer release ownership.
- Keep durable result, checkpoint, dependency, and source-progress checks in
  the existing store transactions. A completed query stream is not a commit.

No Mangroves build or test was run. The source tests above explain contracts;
they are not passing qualification results for the proposed Araphor change.
Mangroves' [log-store configuration](/home/navid/go/src/github.com/mangrovesdb/mangroves/src/log-store/src/config.rs:37)
defaults to `sync_write = false`. Its ordering code does not establish a
power-loss durability guarantee for Araphor. The root SQL golden tests import
`toydb`; they do not qualify the active DataFusion query path.

## Immutable installed package program

An exact OCI closure is loaded
  -> the existing InstalledBundle owner verifies its digest and descriptor
  -> it performs each export's policy and declaration admission once
  -> it retains admitted logical plans, scoped dependencies, relation contracts, and clock use
  -> it retains export indices and the exact artifact identity
  -> it charges the complete retained plan through the existing QueryLease

A caller selects an export
  -> the owner pairs the immutable plan with the exact activation and current grant
  -> a run owns inputs, parameters, checkpoint, context, control, and leases
  -> the run binds values and admitted Arrow sources, then creates its physical plan and streams
  -> the existing native, Wasm, or SQL execution owner performs the selected computation
  -> current authority is checked again at the existing commit boundary

Authority or trust membership changes
  -> the existing authority watch cancels affected runs
  -> immutable content does not make an old grant current

An activation changes
  -> selection and commit check exact generation, metadata, and checkpoint revision
  -> an old selection cannot commit after the activation changes
  -> this proposal does not claim an existing activation cancellation watch

The immutable program contains QuerySql values with retained LogicalPlan
objects and admitted declarations. Descriptor schemas and code-owned built-in
schemas define the relation contracts. Admission resolves engine names and
types once for each retained query. The logical plans retain schema-only
EmptyTable sources. They retain no input batches, MemTables, streams, or physical
plans. QuerySql clones share the complete admitted program, including its SQL,
parameters, labels, dependencies, and plan. The existing retained-byte charge
includes that program and its Arc allocation. Each run binds its parameter and clock values, optimizes a plan clone,
and substitutes its admitted Arrow sources. QueryPlan::new admits each
code-owned template once. QueryBinding shares its immutable plan through an
Arc. Each evaluation supplies fresh parameter and clock values. Parameter
substitution occurs once before logical optimization.

Each run supplies its own tenant, grant, source batches, clock, checkpoint,
bindings, and mutable execution state. A historical snapshot does not permit
a current-state commit.

Manual package execution, freshness checks, supervision, and installed
snapshots must consume this same admitted representation. Updating only
InstalledBundle would leave manual execution and freshness on raw bundles
with repeated admission. Keep the admitted representation within the current
bundle owner's lifetime. Add no lookup cache to cover callers that bypass it.
Public transient `evaluate_model` and `query_datasets` calls still need checked
admission. In particular, `query_datasets` derives its schemas from supplied
batches and must bind that call's schemas. Package result inspection uses
this transient path.

Retain this plan inside the existing owner. Add no plan cache service or
second executable cache. Keep the per-invocation native library owner and
Wasm code cache. A historical snapshot retains its exact closure and current
authority rules.

Keep backend handle lifetimes unchanged. Native libraries remain pinned for
one invocation. Strong Wasm component handles are not retained by every
package plan; that would change code-cache eviction. Release statements and
streams before releasing source data, code pins, and reservations. Returned
batches keep their leases through their final consumer, including buffers
that alias input arrays. Foreign native output remains validated and copied
into host-owned storage. Producer release callbacks finish while the native
library remains pinned. No native boundary check or output copy is removed.

The current representation already retains verified identities and shares
bundles. It also already prepares common graph inputs once. Do not claim these
as new savings. The remaining work is to remove repeated source/SQL admission
and derived metadata interpretation across callers.

## Qualification and acceptance

Qualify the engine replacement in this order. Retained package admission is
an independent deliverable and can precede the engine replacement.

1. Resolve one compatible engine, parser, and Arrow dependency set. Compile
   against the selected release, not the newer source-study checkout.
2. Prove the synchronous execution boundary and current resource behavior.
   Stop if either requires an unapproved API or ownership change.
3. Build a complete query slice from admitted sources through public values
   and the wire output. Include nested CTE scope, unused windows, stage
   namespaces, and dataset-global row references. Preserve every distinct
   existing assertion. Check the complete replacement budget before wider
   migration. Do not use a partial engine demo as parity or size proof.
4. Route every package caller through the retained admitted program. Preserve
   checked transient calls, current grants, and per-run value and source binding.
5. Verify that client, model, source, and dataset SQL use one DataFusion
   backend. Remove obsolete query adapters. Keep DuckDB for the existing
   durable storage owners. Add no fallback backend.
6. Count the actual complete production replacement after that deletion with
   the current syntax counter. Include resources, compatibility code, adapters,
   and callers. Exclude tests, documentation, blank lines, and code movement.
   Meet the net reduction target before declaring this redesign complete.

Run only affected builds and tests in each iteration, as the user requires.
After the final code edit, run the affected build, formatting, strict Clippy,
and functional cases. Run the applicable native and Wasm qualification for
that source. The implementation TODO records the scoped-check override.
Preserve the existing
SQL scope, CTE, alias, join, aggregate, window, time, and parameter cases.
Require exact numeric, timestamp, null, nested-array, output-name, and
`time_bucket` parity. Keep existing SQL function names and their semantics.
DataFusion date_bin uses a different default origin from DuckDB time_bucket.
A rename alone does not preserve behavior. Preserve case-insensitive SQL name lookup, including
quoted names, while keeping declared output names and metadata. Preserve
explicit `__row_index` access and its exclusion from wildcard expansion. Count
all required compatibility code in the replacement budget.
Preserve source cleanup, cancellation, empty append progress, record fanout,
input/output bounds, and source evidence captured before filtering. Preserve
native/Wasm parity, exact package revision, trust revocation, checkpoint retry,
stale dependencies, crash recovery, backup, and all durable commit checks.

Require exact `HUGEINT`, unsigned integer, and Decimal value parity. The
selected DataFusion version does not support every current DuckDB cast name.
Aggregate result widths and overflow behavior also differ. For example,
DataFusion's integer SUM types do not by themselves preserve DuckDB's wider
integer result. Test promotion and overflow as well as cast names. Count
each required rewrite and output conversion in the replacement.

Include function result types in that proof. DataFusion returns UInt64 for
`row_number`, `rank`, and `dense_rank`; the public SQL contract requires BIGINT.
For Utf8 input, DataFusion `length` returns Int32; the public SQL contract
requires BIGINT. Preserve values and public type labels. A final cast cannot repair an
aggregate that already overflowed during execution.
Select the engine features required by the admitted functions. For example,
`length` requires DataFusion's `unicode_expressions` feature. A SQL-only
dependency configuration does not qualify that function.

Keep the existing `operation_source_cleanup` and `operation_source_denial`
assertions. Add one multibatch output case whose checkpoint, evidence, and
reason queries use the same stable row references. Use the existing
`BeforeResultCommit` hook to prove a transaction that wins the cancellation
race. Separately prove rejection when cancellation is observed at the final
check. Preserve the existing authorization lock and activation comparison
at commit.

The query engine choice must pass parity before acceptance. The working tree
now has one query backend, no fallback path, and no older-format reader.
DuckDB value types remain at the public client boundary; QueryValues reads
Arrow arrays directly and does not open a DuckDB query connection. Functional timing is not a performance benchmark.
No performance result is claimed by this source study.

Keeping DuckDB for storage also keeps its build dependency. Adding DataFusion
does not establish a CI or runtime speed improvement. Measure only with an
approved workload after a complete, qualified implementation.

Retained admission: **Done**. InstalledBundle retains each export's admitted
input and model queries. Installed execution borrows them. Standalone model
and dataset calls retain their checked transient boundaries. Current grants,
activation comparisons, backend code lifetimes, and commit owners remain.

The retained-admission Data, Control, and E2E test build passed in 422.31
seconds. Strict Clippy passed in 72.60 seconds. All 57 final selected
functional cases passed.
These include the two corrected owner and capacity cases, long SQL literals,
program reuse, changed source revisions, provenance, clock classification,
current trust, six native Data cases, and the installed native detector E2E
case. The native E2E case runs with PATH empty. Rust source, test binaries,
native artifacts, and native build inputs remain fixed during qualification.
Formatting and whitespace checks pass. The records are
`/tmp/araphor-redesign-program-build2.json`,
`/tmp/araphor-redesign-program-clippy2.json`,
`/tmp/araphor-redesign-program-tests2.json`, and
`/tmp/araphor-redesign-reuse-tests.json`.

The first selection reported 184 passed, two failed, and 12 ignored. The final
checks above resolve those two failures. Ignored native cases are not counted
as passing cases; the named native qualification runs them explicitly.

The retained-admission deliverable added 193 nonblank production Rust lines
from `537f9de3`. Its total reduction from `7b7b407a` was 2,036 lines. Its
remaining target was 3,964 lines. The record is
`/tmp/araphor-redesign-program-count3.json`. This record does not count the
current engine integration.

Engine commit `34a8199c` adds 2,222 nonblank production Rust lines from
`537f9de3`. At that commit, the complete change removes 7 from `7b7b407a`
and adds 1,146 from `aa390d9f`. Another 5,993 must be removed at that point. The
record is `/tmp/araphor-arrow-engine-count8.json`. This count includes the new
query modules, buffer leases, and SQL compatibility code. It excludes tests
and documents. It does not establish a simpler complete redesign.

Engine execution: **Done** for the affected host checks. The Data, Control,
and E2E test build passes in 153.29 seconds. Strict Clippy passes in 12.40
seconds. Formatting passes for all 46 changed Rust files. All 174 local
document links resolve.

All 460 distinct selected cases pass: 439 ordinary Data cases, 12 native
Data cases, six Control cases, and three E2E cases. The ordinary Data run
selects 456 cases and reports 439 passed and 17 ignored. The separate native
checks run all 12 native cases. Four compiler-worker entry points and one
release-history case remain ignored. The native detector E2E case runs with
PATH empty. Native qualification covers Linux, x86_64-unknown-linux-gnu,
and glibc 2.39. It does not qualify other targets.

The first native run reports 11 passed and one failed. The failing test clones
a checkpoint that retains the prior output lease. The next full-capacity
reservation correctly returns Busy. The test now checks that exact denial,
reloads the checkpoint through the standard wire codec, and proves successful
replay. All prior parity assertions and limits remain. Production already
loads checkpoint bytes from storage. Only that test changes after the 439
ordinary Data cases and the first eight caller cases pass. Production source
and manifests remain identical. The corrected native case and native E2E
case pass against the final build. Source, native artifacts, and test binary
hashes remain fixed within each check.

The records are `/tmp/araphor-arrow-engine-qualification-final.json`,
`/tmp/araphor-arrow-engine-testbuild11.json`,
`/tmp/araphor-arrow-engine-clippy8.json`,
`/tmp/araphor-arrow-engine-final-data.json`,
`/tmp/araphor-arrow-engine-integration1-tests.json`,
`/tmp/araphor-engine-native-qualification1.json`,
`/tmp/araphor-engine-native-retry2.json`, and
`/tmp/araphor-arrow-engine-qualified-source-extension.json`.

Complete redesign result: **Not done**. The execution, resource, and parity
checks above do not close the production reduction target. The earlier
retained-admission receipts remain separate evidence. No performance result
is established. Continue removal of custom planning and source stages.

The next deliverable removes the synthetic FROM planning pass. Full SELECT
planning uses SqlToRel directly. Code-owned QueryPlan templates retain their
admitted plans and bind fresh values for each evaluation. Built-in source
tables use ordinary leased MemTables without an inaccessible model row index.
Dataset aliases retain their row indices. Model output validation reuses the
SDK CheckedEvaluation instead of checking the full input a second time.

Direct plan binding: **Done**. The affected Data test build passes in 229.46
seconds. Strict Clippy passes for Data, Control, and E2E test targets in 39.84
seconds. All 262 distinct selected cases pass: 256 query cases, four package
cases, and two explicit native error/checkpoint cases. The first query run
reports 168 passed and 88 failed because the host reaches its filesystem
reserve. After removal of obsolete generated test binaries, only those 88
cases run again and all pass. Production storage checks remain unchanged.
Source and test binary hashes remain fixed during each check. No Control or
E2E runtime test is repeated for this internal change. Their engine-commit
results remain separate evidence.

The records are `/tmp/araphor-df-plan-stage-build2.json`,
`/tmp/araphor-df-plan-stage-query1.json`,
`/tmp/araphor-df-plan-stage-query-failed2.json`,
`/tmp/araphor-df-plan-stage-packages1.json`,
`/tmp/araphor-df-plan-stage-native1.json`, and
`/tmp/araphor-df-plan-stage-callers1.json`.

Direct plan commit `dc2da897` removes 42 nonblank production Rust lines from
`34a8199c`. At that commit, the redesign adds 2,180 from `537f9de3`. The
complete change removes 49 from `7b7b407a` and adds 1,104 from `aa390d9f`.
Another 5,951 must be removed at that point. The records are
`/tmp/araphor-df-plan-stage-count1.json` and
`/tmp/araphor-arrow-engine-count9.json`. Complete redesign: **Not done**.

Source scan projection: **Done**. QueryEngine prepares the optimized logical
plan before extraction. InputProjection derives canonical source fields from
its TableScans. QueryEngine binds the admitted MemTables to that same plan.
Logical optimization still runs once. The source removes the event-field AST
collector and its separate projection rule. Original dependencies retain
authority and evidence scope before pruning.

The final affected Data build passes in 146.22 seconds. Strict Clippy passes
for Data, Control, and E2E test targets in 11.83 seconds. All 263 distinct
selected cases pass: 259 query cases and four package cases. The existing
32 KiB query case now returns all eight rows for a narrow ordered projection.
A query that requires its large catalog payload still rejects at that limit.
The count case proves a zero-column scan with a real canonical source buffer
that retains its charge. Source schema identity, latest finding keys, unused
CTE witnesses, and record fanout checks remain.

The first run reports 258 query cases and three package cases passed. Two
test expectations fail. An added unused-CTE case incorrectly expects a
different revision for identical input content. The corrected case requires
equal revisions and equal full witness vectors. Both original revision cases
remain. The old combined budget case now fits because COUNT(*) reads fewer
columns. The test retains that success at the same limit and adds a query
that needs the large description column. It checks the original exact denial,
public error category, three authorization calls, cleanup, and high-limit
parity. Production source and manifests do not change after that first run.
Only the two corrected cases run again; both pass in 40.77 seconds. Source and
test binary hashes remain fixed within each check. Native and caller runtime
qualification are not repeated for this internal source change.

The records are `/tmp/araphor-source-plan-qualification1.json`,
`/tmp/araphor-source-plan-build4.json`,
`/tmp/araphor-source-plan-clippy2.json`,
`/tmp/araphor-source-plan-query1.json`,
`/tmp/araphor-source-plan-packages1.json`, and
`/tmp/araphor-source-plan-failed2.json`.

This deliverable adds 80 nonblank production Rust lines from `dc2da897`.
The complete redesign adds 2,260 from `537f9de3`. The complete change adds
31 from `7b7b407a` and 1,184 from `aa390d9f`. Another 6,031 must be removed
to meet the required target. The records are
`/tmp/araphor-source-plan-count1.json` and
`/tmp/araphor-arrow-engine-count10.json`. Complete redesign: **Not done**.
The proposed native DataFusion result-name, numeric, and SQL scope changes
have no approval. The current SQL contract remains in effect.

Canonical source fields: **Done**. One Arrow schema replaces 431 parallel
InputField descriptors. Schema and Field allocation sharing remains intact.
Metadata tests check exact key sets, host types, encodings, nullability, and
absence text. Model stages move one imported-table map and remove temporary
built-in tables before the next stage.

The affected Data build passes in 189.42 seconds. All 266 selected cases pass:
260 query cases and six package cases. Strict Clippy passes for Data, Control,
and E2E test targets in 37.19 seconds. Source and test binary hashes remain
fixed. The first package selector starts 147 cases and is stopped. That
interrupted run is not a qualification result. The six affected cases then
pass. The records are `/tmp/araphor-canonical-fields-build1.json`,
`/tmp/araphor-canonical-fields-query1.json`,
`/tmp/araphor-canonical-fields-packages1.json`,
`/tmp/araphor-canonical-fields-packages2.json`,
`/tmp/araphor-canonical-fields-clippy1.json`, and
`/tmp/araphor-canonical-fields-qualification1.json`. Native and caller runtime
cases are not repeated for this change. No speed measurement is made.

This change adds four nonblank production Rust lines from `3fd07cac`. The
complete redesign adds 2,264 from `537f9de3`. The current tree adds 35 from
`7b7b407a`; another 6,035 must be removed to meet the production target. The
count record is `/tmp/araphor-arrow-engine-count11.json`. The count excludes
tests, documents, and blank lines. Complete redesign: **Not done**.
