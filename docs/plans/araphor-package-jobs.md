# Araphor Packages And Managed Jobs

Replace separate Discovery and package execution loops with managed Query
subscriptions. A package supplies callable computations. A job file binds
those computations to data. A running job owns its progress and saved state.

This file first recorded an unapproved draft on 2026-10-18. The user stopped
that implementation. The later instruction below authorizes work under the
native pipeline and simplification criteria. It does not approve every earlier
storage, controller, or SDK proposal in this draft.

This plan extends the [component redesign](araphor-component-redesign.md).
The parent retains the complete production Rust reduction target.

## Current goal and acceptance criteria

The user directs implementation under these criteria on 2026-10-18:

1. Simplification and a coherent design are the primary goal. The complete
   replacement must reduce real production Rust. Track additions and deletions
   against each delivery and the parent baseline. Do not count blank lines,
   tests, documentation, code moves, or discarded uncommitted drafts as the
   required reduction.
2. Every new execution path, including Discovery, uses native SQL parsing,
   native logical planning, native optimization, physical planning, and
   execution. SQL package calls and PRQL source use that same SQL route.
3. Move the existing Discovery owner and packages into the real
   `araphor-analysis_back` crate. Create `araphor-analysis` from scratch.
   The new crate consumes actual Query subscription output. It must not call
   the backup owner or retain `run_clock`, source sweeps, or the old reader.
   Keep the backup available for explicit legacy use and comparison.
4. Before each addition, check whether it fits this design, whether a simpler
   form works, whether it is required, and whether DataFusion or an existing
   dependency already supplies it. Reuse native implementation when it does.
5. Execution is reactive. Periodic polling is prohibited. A declared window
   boundary is a processing event; a timer that checks for changes is polling.
6. Keep new packages in their own crates. Do not move old code to a new crate
   and describe that move as a rewrite or reduction.

The user permits reuse of old Analysis code only when that code meets the
native pipeline and reactive subscription design. Keep the complete old crate
in `araphor-analysis_back`. The fresh `araphor-analysis` must not depend on the
backup or receive a clock. Query subscriptions supply pipeline events and SQL
window deadlines. Use a native stream collection that supports insertion and
removal on demand. Do not keep a permanent set of sources or a source sweep.
The replacement and complete production Rust reduction remain **Not done**.

The [subscription stream result](araphor-component-redesign.md#subscription-streams-and-shared-validation)
records the fresh owner, compatible reuse, selected checks, and remaining work.

### Backup removal and current ownership

The user authorizes continuation of the complete migration on 2026-10-19.
Use the [Analysis migration record](araphor-analysis-migration.md) for the
complete source and function map. Move compatible finite rules. Rewrite
other behavior through native plans and Query subscriptions. Keep the
reference source until replacements pass their required checks.

On 2026-10-19, the user requires compatible functionality to move before the
backup crate is deleted. The initial removal did not establish complete
coverage. That removal is withdrawn. At restoration, all 208 backup files
matched the local `6a25ba1b` commit. The 34 deleted Control and E2E reference
files were restored.
The backup is a reference; current execution must not call its old planners,
source sweeps, compiler process, or periodic tasks.

The native loader and Wasm evaluator are copied to Package Runtime. Finite
notification operations are copied to active Analysis. These moves do not
establish complete graph, Discovery, durable commit, permission, or replay
parity. A file and function inventory must identify each compatible rule,
its current owner and tests, or the work required to move it. Old caller
coupling alone does not justify deleting domain behavior.

Backup migration and removal: **Not done**. The withdrawn deletion had no
complete finite OCI qualification. Formatting, workspace compilation, and
strict Clippy passed before source restoration. Full workspace tests failed
to build because the host disk filled. They did not pass. The previous
11,664-line delivery reduction and 5,668-line complete reduction describe the
withdrawn deletion; they are not current results. No deletion commit or push
was made for that removal.

Current finite execution and managed-state checks pass as recorded in the
[migration result](araphor-analysis-migration.md#finite-managed-source-focused-qualification).
The historical full Rust gate `migration-final-ci42` covers the earlier 29
retired leaves. Four additional reference files, eight Wasm leaves, and 15
finite Graph, SQL, Discovery, test, and asset leaves are retired. Eight more
executor, component, atom, pager, and pure test leaves are removed after 50
focused replacement checks pass. Fifteen more retained-query, authority, Wasm,
and finite notification test leaves are removed after 89 checks pass.
Two more complete image/fixture leaves are removed after their replacements
pass. The complete error leaf then retires after exact replacement checks.
The limits leaf also retires after Runtime preserves its complete configuration
contract. The later snapshot-memory and stream-test replacement retires three
more whole files after 373 distinct connected cases pass. The native operation
replacement then retires one complete test leaf after all ten old test functions
have passing native assertions. There are now 87 retired files; 121 remain unchanged. The recovery archive retains all 208 originals.
The full Rust gate59 stops at a stale OCI fixture. The corrected fixture passes
all 15 Package cases. The complete final Rust gate remains **Not done**. These finite results do not establish
long-running lifecycle or automatic restart.

### First deliverable: definition files and running instances

The user requires this work before the earlier feature parity TODOs. Implement
the package, definition-file, and running-instance model first. The
[parity TODO](araphor-feature-parity-todo.md#first-priority-todos)
records three separate items: 14, the OCI package image; 15, the Discovery
definition file; and 16, running Discovery instances. Complete them in that
order. Items 1-13 remain later work. Reuse existing code needed
for this deliverable; this priority does not require the complete earlier
owner migration first.

Keep three separate objects: the OCI package contains reusable code; the
Discovery definition contains SQL or PRQL; the running instance owns the
subscription lifetime. Installing a package does not start a Discovery.

The previous native-call delivery replaces the separate package-call program
form with calls inside SQL or PRQL. It removes the JSON call, input bindings,
parameters, output
selector, and window fields. Native SQL supplies those operations. Use an
exact function name such as `"fixture"."r1".count(...)`: the parts identify
the image, revision, and export. Named subquery arguments supply input
relations. Named scalar arguments supply parameters. An optional first string
argument selects an output relation when the export has several outputs.
Filters and time windows belong in the SQL input query. PRQL uses its
existing SQL relation expressions; add no PRQL parser or extension language.

Query resolves image references from the native SQL syntax tree. It loads
each exact installed image once for the admission. Data and Control retain
the existing immutable snapshot, permission, and trust checks. Admission
starts no Discovery. This change does not implement the running-instance
lifecycle or the physical package-call executor.

### Finite OCI calls through native execution

The user authorizes this execution work on 2026-10-19. Managed instances
remain the next deliverable. This work does not approve the earlier draft
Jobs storage or root-packet proposals.

```text
A caller executes one prepared definition with invocation state
  -> Query fixes logical time for native optimization and physical planning
  -> native physical planning creates PackageExec for each admitted call
  -> Query captures the declared source view once
  -> PackageExec collects complete Arrow inputs and scalar parameters
  -> native SQL plans or the selected Wasm or native evaluator compute outputs
  -> the existing SDK validates all datasets, state, reasons, and evidence
  -> Query returns selected Arrow batches and complete proposed call results
  -> Data remains the only durable commit owner

A call fails or the operation is cancelled
  -> Query returns no complete definition result
  -> runtime cancellation wakes from an event and joins active guest work
  -> Data receives no automatic state, output, or progress write
```

Query owns the DataFusion extension operator and the captured call context.
`araphor-package-runtime` owns compatible native loader and Wasm evaluator
code reused from the restored reference backup. No current owner depends on
`araphor-analysis_back`. Runtime imports neither Query nor Analysis. This boundary prevents a crate dependency cycle. Runtime has
no scheduler, source reader, or durable writer.

SQL body plans remain native logical and physical children. Temporary input,
parameter, output, and prior-state tables use the existing source provider.
These tables share the captured source view and fixed execution clock. A
child call uses the existing operation permit. It does not enter the
synchronous Query bridge or acquire a second permit.

Each admitted call has a distinct identity. Readers of that call share its
complete result. Separate call sites have separate proposed state. A finite
caller can supply prior state by admitted call identity. The finite Instance
owner instead captures guarded prior state on the same source cut and retains
a versioned call manifest. Automatic restart remains in TODO 16.

Wasm interruption waits for cancellation, an exact configured deadline, or
completion. No recurring epoch timer runs. Compilation uses Wasmtime inside
the process. The new execution path does not use the backup compiler or
its polling timer. Runtime quotas default to disabled. Explicit image, model, caller,
and Query quotas retain their existing checks. The former compiler address
space quota returns Unsupported because the compiler no longer has a separate
process. Native cancellation remains cooperative. Active Wasmtime compilation
must finish before cancellation can join that worker. Explicit cancellation
through execute_definition joins logical and guest work before return. A
caller that drops the complete async future cannot wait for cleanup in Drop;
worker tokens still retain executable and operation resources through teardown.

Finite implementation and focused qualification: **Done**. Query executes
SQL, Wasm, and native OCI calls through the native pipeline. Analysis
`Instance::admit` starts no work. `Instance::run` registers an immutable attempt
after capture and before execution. Data atomically commits complete actual
call returns, guarded state, evidence references, and progress. Input revision,
coverage, parameters, schema, version, and rebuild checks prevent incompatible
prior-state reuse. Completed retries return the original receipt; pending
retries return Incomplete. Current authority protects capture, commit, and
receipt delivery. The [migration result](araphor-analysis-migration.md#finite-managed-source-focused-qualification)
records the focused checks and resource limits.

The complete final Rust gate remains **Not done**. Long-running
supervision, start/inspect/stop/update/removal, public history, automatic
restart, and complete migration remain **Not done**.

Native managed subscription checks now pass. `Instance::subscribe` requires
the exact running lifecycle and uses Query's existing native subscription.
Data commits the native cursor with complete results and saved state. An
unchanged resumed cut waits for Query source or window events. A stream cannot
use another stream's newer progress with an older cursor. All 27 selected
Analysis cases pass, including the source-built native cases. The later 83
connected checks pass for known terminal outcomes, original claim lifetime,
completed-attempt comparisons, and exact native failed-offer wait cuts.
Successful state and progress remain unchanged on failure. Read the
[terminal result](araphor-analysis-migration.md#known-terminal-outcomes-and-failed-offers).
Query and Instance now share admitted images and their native reservations.
Typed authority notices retain their origin; real source denial remains Denied.
The [image result](araphor-analysis-migration.md#shared-admitted-images-and-error-origins)
records focused checks and the remaining retained-metadata capacity gap.
The internal reactive host and component-slot wait now pass focused checks.
The host consumes Query subscriptions through one FuturesUnordered collection.
Held authority callbacks and guests preserve actual joins. Component admission
keeps the original capture, attempt, and frontier. The
[host result](araphor-analysis-migration.md#reactive-host-joined-delivery-and-component-admission)
records all 54 Instance cases and 130 selected Query cases across ordinary
and corrected native commands. Retained admission metadata, durable failure
status, fresh Inspect status, and finite known failure recording now pass
[focused checks](araphor-analysis-migration.md#retained-metadata-and-durable-failure-status).
Public lifecycle integration, projected host metadata, general pressure retry,
and the complete final Rust gate remain **Not done**.

### Approved YAML authoring design

The user requires YAML metadata for all three program forms: full SQL, PRQL,
and a structured package call. A SQL or PRQL source file is referenced from
the YAML definition. It is not a complete definition without metadata.
The YAML definition requires a name. Description and labels are optional.
The definition selects exactly one of `sql`, `prql`, or `call`.

```yaml
name: selected-events
description: Process selected event cursors.
labels:
  team: security
sql: |
  SELECT *
  FROM "fixture"."r1".count(
    source => (SELECT source_cursor AS value FROM events),
    increment => 2
  )
```

SQL and PRQL accept inline text or a source file:

```yaml
name: selected-events
prql:
  file: queries/selected-events.prql
```

A structured call selects an installed image and one export:

```yaml
name: selected-events
call:
  package: fixture
  revision: r1
  export: count
  inputs:
    source: |
      SELECT source_cursor AS value FROM events
  parameters:
    increment: 2
```

An input can use `{file: queries/input.sql}` instead of inline SQL. The
optional `output` field selects an output when the export has several
outputs. Omitted inputs use the image's declared defaults. The package
interface still determines required parameters and valid input schemas.
Parameter values are literals. Filters and time windows stay in input SQL.
The definition adds no separate window or scheduling language.

```text
An operator admits a YAML definition
  -> the file owner validates metadata and exactly one program
  -> the file owner captures each referenced source once
  -> the file owner converts a structured call to native SQL syntax
  -> Query parses SQL or the existing PRQL compiler's SQL output
  -> Query uses native logical planning and optimization
  -> Query validates physical plans that need no package-call executor
  -> Control checks current permission and every image pin at commit
  -> Data retains the immutable definition
  -> no Discovery starts

The YAML, query, image, permission, or commit check fails
  -> the request returns a typed error
  -> Data commits no new definition
  -> a retry checks current permission again
```

The file crate owns YAML parsing and call conversion. Reuse the workspace
YAML parser and DataFusion's pinned SQL parser. Construct identifiers and
literals through the native SQL syntax types. Do not substitute unescaped
text. The normalized request keeps the existing SQL and PRQL program types.
Query, Control, and Data need no third execution route or program variant.
SQL and PRQL retain captured source text. A structured call retains its
metadata and normalized SQL; it does not retain YAML formatting or source
paths. Native Query admission derives the exact image pins from that SQL.

Keep the existing JSON request and snapshot encoding. Reject duplicate
keys, unknown fields, missing programs, combined programs, and uncaptured
server-side paths. Add no mandatory file-size, depth, or alias-count quota.
Do not add package aliases, raw SQL/PRQL definition admission, a source
watcher, or a polling loop. Package-call physical execution and running
instances remain outside this authoring change.

Implementation and selected functional qualification: **Done**. All 60
distinct focused tests pass. They cover YAML forms, source capture, native
plans, literal values, current permission and trust, immutable storage,
recovery, request encoding, and the real TLS client. Admission starts no
Discovery. The source and command record is
`/tmp/araphor-yaml-verification1.json`. Formatting and affected-crate Clippy
with warnings denied pass.

This delivery adds 261 production Rust code lines from `d49e6bd5`: 282
additions and 21 deletions by file size. The complete redesign adds 6,180
from `7b7b407a`; another 12,180 must be removed for the 6,000-line reduction
target. Tests, comments, documents, blank lines, and moves do not count as
reduction. The record is `/tmp/araphor-yaml-count1.json`. Complete reduction:
**Not done**. Full workspace CI, benchmarks, and physical Kubernetes checks
did not run. No speed result is claimed.

### Native derived relations and crate removal

The user rejects the hardcoded Discovery function resolver, its call syntax,
and the complete `araphor-discovery-effects` crate. Remove the crate and all
workspace and dependency entries. Keep the required computations in the
existing built-in package and image owners. Do not add a replacement resolver
or a fixed schema bootstrap.

Native SQL declarations define the ordinary views. For example:

```sql
SELECT source_id, event_count FROM discovery.observed_effects;
```

Query obtains each view name and schema from the native declaration. Native
catalog and schema providers retain the native `ViewTable`. Query does not
match Discovery names. The existing generic relation planner remains for
actual package calls with relation inputs.

Collect source origins during native relation planning and from the expanded,
unoptimized native plan. The per-admission RelationPlanner observer returns
native plans without changes. It preserves source declarations in unused
query CTEs, which DataFusion omits from the returned plan. Keep these origins
for capture, permission, receipts, and source notices even when optimization
removes an empty branch. Query and package inputs use the same collection.
Trusted views retain DataFusion's stored-plan behavior; unused CTEs in a view
declaration are absent from that stored plan. User query admission rejects
DDL. Native view plans remain unoptimized until query execution, so clock
expressions use the execution time.

The complete recorded and merge computations remain SQL programs with named
input relations. A windowed program filters events before aggregation. An
outer filter on an aggregate view cannot replace that input window. Native
SQL CTE scopes replace the former AST table renamer during image assembly.
All existing result, coverage, evidence, context, and lifecycle assertions
remain required.

Crate removal and selected qualification: **Done**. All 354 distinct focused
tests pass on the final source:

| Owner | Passing tests |
| --- | ---: |
| Query library | 268 |
| Analysis library, including all 36 SQL cases | 41 |
| Definition format | 21 |
| Data definitions and request encoding | 9 |
| Control admission, finite queries, follow, and context | 11 |
| TLS admission | 1 |
| CLI definitions | 3 |

Scoped formatting and affected-crate Clippy with warnings denied pass. The
source and command record is `/tmp/araphor-native-views-verification1.json`.
The final record checks 53 Rust, SQL, Cargo, and lockfile paths against the
commit. All earlier SQL result, coverage, context, merge, and live-state
assertions remain. The idle-clock test uses a notification to enter its quiet
interval; its 650 ms no-read and no-clock-read assertions remain unchanged.

This change removes 157 production Rust code lines from `5c9e2fb7`: 494
additions and 651 deletions by file size. The count excludes tests, comments,
documents, blank lines, and moves. The record is
`/tmp/araphor-native-views-count6.json`. The complete redesign adds 5,996 from
`7b7b407a`; another 11,996 must be removed for the required 6,000-line reduction.
At this revision, the complete redesign, reduction target, physical OCI
package-call execution, and managed instances remained **Not done**. Full
workspace CI, benchmarks, and physical Kubernetes checks did not run. No speed
result is claimed. The finite execution result above records later work.

### Native admission simplification

The package planner now uses native DataFrame window operations for row
indices. It binds default input dependencies with native plan transformation
and schema recomputation. It does not generate index SQL or parse an input
query again after binding. One admission shares one catalog and source map.
The planner validates each distinct retained plan once. Existing configured
quotas and trust checks remain. YAML uses one shared field-presence check.

Calls use DataFusion's `RelationPlanner`, because package inputs are complete
relations. The native `TableFunctionImpl` accepts scalar expressions. The
package call is not a registered scalar UDF. The native logical extension
retains exact image identity and the typed execution contract. At this
revision, physical package execution and running instances remained **Not
done**. Read the
[definition review](../guides/araphor-discovery-definition-review.md).

Native admission simplification and selected qualification: **Done**. All
61 distinct focused tests pass. Formatting and affected-crate Clippy with
warnings denied pass. The source and command record is
`/tmp/araphor-native-simplify-verification1.json`. This change removes 27
production Rust code lines from `b637c05a`: 15 additions and 42 deletions
by file size. The complete redesign adds 6,153 from `7b7b407a`; another
12,153 must be removed for the 6,000-line reduction target. Tests, comments,
documents, blank lines, and moves do not count. The count record is
`/tmp/araphor-native-simplify-count1.json`. Complete reduction: **Not done**.
At this revision, the separate hardcoded Effects function resolver still
required consolidation. The crate-removal result above records its removal. Full workspace CI, benchmarks, and physical Kubernetes checks
did not run. No speed result is claimed.

The user authorizes the OCI image in a separate crate. The current delivery
uses `araphor-package` for image content and the existing Data store for
durable installation. Control and CLI image requests do not call a package
executor. Image content, installation, inspection, and focused qualification
are **Done**. Definition-file admission and inspection are implemented in
`araphor-discovery-definition`, Query, Data, Control, and CLI. Native finite
OCI execution and finite managed state are implemented and have focused
qualification. The running-instance lifecycle remains **Not done**. Read the
[image review](../guides/araphor-binary-package-storage-review.md#image-installation-without-execution)
for the source route and verification limits.

The [definition review](../guides/araphor-discovery-definition-review.md)
records the YAML file schema and admission route. Admission captures source
files once, binds exact installed images, validates native query plans, and
retains an immutable snapshot. Admission starts no Discovery. SQL and PRQL
reach native physical planning. A package call reaches a typed logical node
and the native PackageExec executor. The instance lifecycle remains open.
The complete running-instance acceptance criterion below remains **Not done**.

| Order | TODO | Result |
| --- | --- | --- |
| First | [14. OCI package image](araphor-feature-parity-todo.md#14-oci-package-image) | Reusable code with exact revisions and declared SDK contracts. Installation starts no Discovery. |
| Next | [15. Compose file](araphor-feature-parity-todo.md#15-discovery-definition-file-compose-file) | YAML metadata and one SQL, PRQL, or structured call form. Calls produce native SQL. |
| Then | [16. Running Discoveries](araphor-feature-parity-todo.md#16-running-discovery-instances) | Independent managed Query subscriptions with their own lifetime, progress, and saved state. |

A definition contains metadata and selects one program form:

| Program form | Definition input | Route to execution |
| --- | --- | --- |
| PRQL | PRQL source or a referenced PRQL file, with package calls when required. | Compile to SQL, then use native SQL admission. |
| SQL | SQL source or a referenced SQL file, with package calls when required. | Use native SQL admission directly. |
| YAML call | Exact image, export, input queries, and literal parameters. | Construct native SQL syntax, then use native SQL admission. |

All three forms use native SQL parsing, logical planning, optimization,
physical planning, and execution. Reuse the installed evaluator and Query
subscriptions. Add no separate execution engine or polling loop.

YAML metadata names and describes the definition and attaches labels. Call
bindings and parameters use SQL syntax or the structured YAML call form. SQL
defines query windows.
Execution permission comes from Control, not from metadata in the file.
Resolve referenced source paths relative to the definition. Read those files
when the definition is admitted; do not poll them for changes.

An instance runs without a default lifetime cutoff until it is stopped,
subject to current permission, cancellation, and execution failure. A client
disconnect does not stop it. Restart restores its admitted definition, exact
package revisions, and committed state and progress. Check current permission
again. Missing retained input produces an explicit incomplete or unavailable
result. Each instance has separate state; stopping one leaves the others
running. Query supplies all data and window events without polling.

```text
An operator installs an OCI package
  -> the package owner validates and retains its exact revision
  -> no Discovery instance starts

An operator starts a Discovery definition
  -> the definition owner reads the selected program and metadata
  -> SQL is admitted directly or PRQL compiles to SQL
  -> native relation planning resolves package calls in that SQL
  -> native DataFusion plans and executes the admitted program
  -> Query runs the managed subscription until it is stopped

An operator stops one instance
  -> Query stops that subscription and cancels its active work
  -> other instances that use the same package continue
```

Acceptance: load SQL and PRQL definitions with package calls and preserve
their metadata. Prove both forms reach native Query execution. Install a package
without starting a Discovery. Start two instances with different inputs or
parameters; stop one while the other continues. Preserve current permission,
cancellation, saved-state, and buffer lifetime checks.

This priority and the three separate TODOs are current user requirements.
The approved YAML design above supplies three authoring forms. The retained
program types remain SQL and PRQL.
They do not approve every controller, storage, checkpoint, or crate proposal
in the earlier draft. Implementation: **Not done**.

### Earlier native SQL delivery

Add one new observed-effects package. Use native SQL projection, filtering,
GROUP BY, COUNT, MIN, and MAX over the existing typed events source. Register
its callable relation through the native DataFusion relation-planning hook.
Expand its SQL body into native plans. This package requires no new logical
operator, physical executor, result cache, scheduler, or state store.

Qualify the actual SQL parser through execution and run that same plan through
Query subscription changes and window expiry. Preserve exact source identities,
NULL dimensions, original input cuts, and query receipts. This package reports
observed effects. It does not claim complete coverage or old profile parity.

The stopped package-runtime, Jobs loader, and Data jobs drafts have no production
consumer. Preserve their files outside the source tree and remove their unused
workspace wiring. They are not prerequisites for this package. Introduce a
further extension only after a required computation proves the native API gap.

Previous native SQL package and selected caller qualification: **Done**. At
that revision, the new crate was `araphor-discovery-effects`. The crate removal
above replaces that route. At that revision, Control registers its native relation planner
through `ControlPlane::analysis_packages`. The package has no separate source
reader, scheduler, logical operator, physical operator, or result cache.

The selected checks pass four package tests, five Query subscription tests,
and two Control query-RPC tests. Strict Clippy passes all targets in the three
affected crates. Scoped formatting and `git diff --check` pass. The source and
command record is `/tmp/araphor-native-discovery-verification1.json`.

Complete Discovery replacement: **Not done**. This SQL call is built in. OCI
admission, managed job persistence, old profile and coverage parity, remaining
quota defaults, and Data and Wasm polling still require work. The existing
Discovery packages and their callers remain available.

This delivery adds 133 nonblank production Rust lines and removes one, for a
net addition of 132. Tests, documents, and SQL files are excluded from that
Rust count. The complete worktree still adds 1,089 production Rust lines against
`7b7b407a`; the required 6,000-line reduction is **Not done**. The source count
record is `/tmp/araphor-native-discovery-count2.json`.

### Next semantic replacement

Use the existing typed events and coverage relations to qualify observed
cursor ranges. Both inputs must be explicit query arguments captured under
one source cut. Native joins, CASE, LAG, running SUM, and GROUP BY can supply
the computation. Native array functions can combine admitted coverage reason
tokens. A custom execution operator is not required.

Parity must preserve source identity, source epoch, CPU, original kernel
sequence bounds, temporal degradation, counter overflow checks, missing
reports, cursor holes, reason ordering, and batch independence. Durable cursors
are not kernel sequence numbers. This work does not yet replace pinned context
or full atom and profile derivation. Delete the old coverage interpreter only
after all callers use the qualified replacement. Result: **Not done**.

The raw range call is now implemented as discovery.coverage_ranges in the new
Discovery Effects crate. The shared native relation planner binds explicit
event and coverage queries. Native SQL performs range qualification and
coalescing. No custom executor or timer is added. All 11 package tests, seven
Query subscription tests, and three Control query-RPC tests pass. The cases
include receipt-only changes and exact window expiry without new intake.
Strict Clippy passes all targets in the five affected crates. The command and
source record is `/tmp/araphor-native-coverage-verification1.json`.

The existing qualifier remains for three Discovery and two graph callers.
Those callers must supply their original historical reports and intervals.
The new call does not perform the later builtin temporal degradation or final
profile merge. Full replacement remains **Not done**. This increment adds 20
nonblank production Rust lines. The complete redesign adds 1,144 against
`7b7b407a`. The count is `/tmp/araphor-native-coverage-count3.json`.

### Native recorded snapshot

Implementation and selected qualification: **Done**. The new SQL package
exports discovery.recorded_snapshot with explicit records, raw bindings,
ranges, exclusions, lifecycle, and metadata relations. Native SQL constructs
full atom keys and all snapshot outputs. The retained algorithm is the test
oracle. No new executor, source reader, scheduler, or state store is added.

All three native Discovery calls now plan each caller argument once, then bind
the resulting logical plan in a new native PlannerContext. DataFusion owns
package CTE planning. The AST substitution visitor is deleted. A borrowed
ContextProvider adapter only forwards the existing native catalog interface.

Query can reuse one admitted received-time window across these input plans.
Every events scan must have the same valid source bounds. The existing progress
owner handles intake and exact expiry. Physical planning and evaluation have
an optional timeout that defaults to None. Parent authorization and cancellation
remain active. Extraction deadlines and other quotas still require work.

The selected checks pass 68 distinct cases across Data, the SQL package, Query,
Analysis, and Control. The source and command record is
`/tmp/araphor-recorded-snapshot-verification1.json`. Strict Clippy passes all
targets in the six affected crates. Full workspace CI and benchmarks are not
run. This increment adds 166
production Rust code lines and 464 SQL lines. The complete redesign adds 937
production code lines against `7b7b407a`; the reduction target is **Not done**.

Old Discovery orchestration is retained until its replacement captures context
and interval state, pins the correct computation revision, and publishes the
profile atomically. This SQL result does not prove that cutover. Full managed
jobs, OCI callable identity, and old Discovery replacement remain **Not done**.

### SQL artifacts with provided inputs

Implementation and selected functional qualification: **Done**. Data no longer
rejects Provided SQL. Existing InstalledAnalysis and ModelRun execute supplied
Arrow inputs through admitted native plans. Installation does not execute that
model, and finite evaluation does not change its activation or checkpoint.
Declared-only SQL admission and the existing authority, schema, lease, and
target checks remain active. No new executor, reader, store, or timer is added.

The complete recorded SQL body includes validation and private column removal.
Native CAST rejects a prefixed error; a NULL error passes. The custom guard
function and host Filter construction are deleted. The exported
araphor_analysis_builtins::discovery::sql::RECORDED_SNAPSHOT_SQL can be stored in an OCI program. The
round-trip case executes that retained body in plain native DataFusion, with
no Discovery relation planner, and compares every Arrow array with the old
algorithm. A changed body changes the artifact digest.

Selected checks pass 59 cases across Discovery Effects, installed Analysis,
Data package storage, and Query subscriptions. Strict Clippy passes all targets
in Data, Discovery Effects, Query, Analysis, Control, and E2E. Scoped formatting, local document links, and whitespace
checks pass. The command and source record is
`/tmp/araphor-provided-sql-verification1.json`. Full workspace CI and benchmarks
are not run. This delivery removes 50 production Rust code lines and adds five
SQL lines. The complete redesign still adds 887 production code lines against
`7b7b407a`; the reduction target remains **Not done**.

Live producer installation, captured authoritative context and interval state,
new package pins, and atomic profile publication remain **Not done**. This
increment does not authorize or implement the earlier draft job controller.
The parent plan records the remaining context content gap.

### Atomic reactive context publication

Implementation and selected functional qualification: **Done**. The existing
Control context owner captures all changed facts under one lock. Data commits
the complete batch in one transaction with one revision for all new rows.
The former partial-copy cursor and one-second failure retry are deleted.
Relevant Control notices trigger work. After a failure, Data repair notices
can also trigger work without a new Control revision. No new source reader,
store, controller, or execution operator is added.

The shared transaction preserves exact retries, imported history, package
provenance, tenant scope, and rollback. The optional context body quota defaults
to None. The context page reader preserves rows above the former fixed byte
cutoff. This change prepares complete Query captures; authoritative proof
projection and live Discovery package execution remain **Not done**.

Selected checks pass 14 Data cases, eight Control cases, and one native Query
E2E case. The E2E case proves failure rollback and repair wake without a new
Control revision. The crash case proves two-row atomic recovery. Strict Clippy
passes all targets in the six affected crates. Scoped formatting, local links,
and whitespace checks pass. The source and command record is
`/tmp/araphor-context-cut-verification1.json`. Full workspace CI, benchmarks,
and physical Kubernetes qualification are not run.

The delivery removes 12 production Rust code lines. The complete redesign
still adds 875 against `7b7b407a`. The required reduction is **Not done**.

### Snapshot-qualified target context

Implementation and selected functional qualification: **Done**. The shared
TargetContextV1 retains each workload with its parent source, snapshot, and
signed-profile identities. Snapshot-qualified lifetime keys preserve identical
workloads from distinct signed snapshots. Native targets exposes all three
parent identities without replacing the workload's own source identity.
The existing publisher, Data transaction, table provider, and Query stream
supply the path. Authoritative binding resolution and live Discovery cutover
remain **Not done**.

The selected 16 Data cases, one Control case, and one Query follow case pass.
Strict Clippy passes all targets in the six affected crates. Scoped formatting,
local links, and whitespace checks pass. The source and command record is
`/tmp/araphor-target-proof-verification1.json`. Full workspace CI, benchmarks,
and physical Kubernetes qualification are not run. The delivery adds 21
production Rust code lines. The complete redesign adds 896 against `7b7b407a`;
the required reduction remains **Not done**.

### Native Discovery binding resolution

Implementation and selected functional qualification: **Done**.
The [component plan](araphor-component-redesign.md#native-discovery-binding-resolution)
records the shared catalog codec, native compiled-policy proof, and SQL binding
resolver. The resolver uses native joins, window functions, grouping, and
equality checks. No new compiler, scheduler, store, or physical operator is
added. Live Discovery package execution, cumulative state, exact replay inputs,
installation pins, and atomic profile cutover remain **Not done**. The parent
records 105 selected passing cases, strict Clippy in eight crates, and the exact
source receipt. This delivery adds 401 production Rust code lines. The complete
redesign and the required production Rust reduction remain **Not done**.

## Earlier design draft

The design and statuses below are historical. The finite execution result
above and the migration record state current implementation and qualification.

The sections below retain the earlier design for review. Their controller,
checkpoint, loader, and runtime crate proposals are not prerequisites for the
immediate native SQL package. Before any such addition, apply the current
acceptance criteria above and prove that existing native owners cannot supply
the required behavior. The current source does not contain these draft owners.

## Intended end state

An operator installs an OCI package and starts a job from a definition file.
The file contains SQL, refers to a SQL or PRQL file, or declares a direct
package call with input bindings and a window. All forms use the same native
DataFusion planning and execution route. PRQL compiles to SQL before admission.
A direct call must reach the native SQL parser before planning and execution.

An OCI package is like an image. A job definition is like a Compose file.
A managed job instance is like a running container. A function evaluation is
one finite call inside that instance. The package does not start a job when
it is installed.

Every Discovery is a managed job. It has no private source sweep, evidence
reader, clock loop, or seal scheduler. Query supplies actual Arrow input,
windows, source progress, and exact deadlines. A stored definition remains
registered until it is stopped. A client disconnect does not stop its job.
Restart restores the last committed state and input frontier.

## Implementation flow

```text
An operator submits a definition and an authorized instance request
  -> Jobs reads the definition and its source files once
  -> the package owner resolves aliases to immutable OCI revisions
  -> Jobs compiles PRQL or renders a direct call as SQL before native parsing
  -> native SQL admission checks sources, types, and current scope
  -> Data records the admitted definition, instance generation, and package pins
  -> Query starts the managed subscription without a default lifetime cutoff

A relevant input changes or a declared window boundary arrives
  -> Query starts one step for that instance
  -> Data captures declared inputs and the previous root checkpoint together
  -> Query records the captured revision, input positions, and logical time
  -> Data closes the read transaction before package computation
  -> native physical execution calls the admitted exports
  -> each call returns named outputs and proposed next state
  -> downstream calls read upstream output as a temporary Arrow relation
  -> domain validators check the complete step and its evidence
  -> Data checks the current grant, activation, instance generation, and root head
  -> one transaction commits outputs, all call states, evidence, and input progress
  -> Query publishes committed output and waits for the next relevant event

New input arrives while a step runs
  -> the running step retains its captured view
  -> later input remains pending for a subsequent step
  -> a later source head does not reject a valid captured step

A call fails or the step is cancelled
  -> Query cancels and joins the remaining step work
  -> Data commits no proposed state, output, or input progress
  -> the instance retains its last complete root checkpoint
  -> a retry uses the recorded input and state contract

The operator stops the instance or its authority changes
  -> Query stops new steps and cancels active work
  -> Data rejects a commit from the old generation or invalid authority
  -> Jobs joins active work before it reports a complete stop
  -> retained results and evidence remain readable under current authority

The process restarts
  -> Jobs loads active instance definitions and exact package pins from Data
  -> Query validates retained input positions against the current recovery epoch
  -> Query resumes from the last committed root checkpoint or rebuilds explicitly
  -> missing retained input produces an explicit incomplete result
```

## Contracts

### Package and call

The portable export declares named input schemas, parameters, named output
schemas, reasons, and an optional checkpoint schema. Input source bindings and
windows belong to a job or call site. They do not select another runtime path.
The existing SDK remains the single contract owner.

```text
export(inputs, previous_state, parameters, context)
  -> named_outputs, proposed_next_state
```

An input is a complete selected relation for one call. Arrow batch size and
physical partition count do not define the number of calls. A call result is
computed once and shared by its named output readers. DataFusion has one
schema per stream; the existing typed SDK result owns the complete return.
Named datasets retain their Arrow arrays and can use native tables downstream.

SQL exports use native relational plans. Native and Wasm exports use the
selected installed implementation. Native runs in Araphor's process. A call
does not write durable state or publish notifications during physical execution.

### Read view and state

Each named call in an instance owns private saved state. Partitioned calls
have separate state per declared key. Logical call identities must remain
stable when native physical optimization changes plan nodes.

A step has one captured Data view and one root checkpoint. Logical time,
capture revision, trigger notice, and execution time are separate values.
A window due at 12:01:00 can capture revision 417 at 12:01:02. This view is not
a promise of database contents at wall-clock 12:01:00.

Package SQL reads use the same captured catalog and fixed logical clock.
Admission includes the declared internal relations and columns in that capture.
An additional query must not open a new live-data session. Package-issued SQL
requires an explicit SDK capability; the current ABI does not supply one.
Reuse invocation resources for child execution. Do not acquire another tenant
evaluation permit or enter the synchronous Query bridge from its own runtime.

One immutable root packet contains all call checkpoints and the consumed
frontier. One instance head comparison protects the complete step. A failure
in B after A succeeds leaves both saved states unchanged. This replaces the
older per-export commit boundary for composed job execution.

Late input, retractions, and changed context require a valid earlier checkpoint
and replay or a complete rebuild. Do not merge a correction into the latest
accumulated state. Ordinary SQL operators retain their native state owner.

### Definition and instance

Use one definition format with exactly one program source. Keep instance ID,
tenant selection, current grant, active generation, progress, and checkpoints
outside the reusable definition. Resolve source paths relative to the definition.
Retain the admitted source bytes and package revisions. Runtime does not poll
or reread those files.

The file shape below illustrates a SQL job. Its exact parser contract is
qualified by the Jobs tests before acceptance.

```yaml
version: 1
packages:
  discovery: ./packages/discovery.oci
program:
  sql: ./profile.sql
```

SQL defines filters, joins, grouping, and windows. PRQL supplies another
authoring route to the same SQL admission. A direct call supplies input
bindings and a declared window, then reaches that same native SQL parser and plan. Add no
second operator graph or scheduling language to the file.

PRQL has no documented DataFusion target. Use the embedded Rust compiler with
CLI features disabled. Pass generated SQL text through native DataFusion
admission and qualify the actual supported forms. Do not share PRQL and
DataFusion parser AST types or claim complete dialect parity.

## Crate ownership

| Crate | Owns | Does not own |
| --- | --- | --- |
| `araphor-analysis-sdk` | One portable package, Arrow, state, validation, and ABI contract. | Store access, job source selection, scheduling. |
| `araphor-package-runtime` | Admitted callable code, invocation results, package-call integration, and executable lifetimes. | Managed job loops or durable commits. |
| `araphor-jobs` | Definition files, admitted instances, lifecycle, and root-step coordination through Query and Data. | A second SQL engine or source progress loop. |
| `araphor-query` | Native parser, planner, optimizer, physical execution, captured catalogs, windows, and subscriptions. | OCI installation or publisher trust. |
| `araphor-data` | Durable packages, job heads, root packets, retention, atomic transactions, and recovery. | Executable loading or query scheduling. |
| `araphor-analysis` | Profile, graph, and finding domain adapters and validation during migration. | The replacement package or job execution owner. |
| Algorithm crates | One implementation of each package computation and its native/Wasm builds. | Host authority, subscriptions, and storage. |

Keep package-runtime registration behind native DataFusion extension APIs.
Query must not import a higher owner that already depends on Query. The
composition root registers the package relation and physical planners.
Reuse the current SDK rather than adding a parallel contract crate. Existing
algorithm component crates must become real computation owners; do not retain
a common built-in crate as a second implementation after their migration.

## Delivery order and acceptance

### 1. Callable execution and definition entry

Status: **Not done**.

Create the package runtime and Jobs crates. Implement the finite package-call
operation through native logical and physical execution. Preserve all named
inputs, outputs, prior state, validation, and output-buffer lifetimes. Route a
real installed evaluation through it. Add definition loading and a production
inspection or admission entry. SQL, PRQL, and direct calls share the same
admission result; unsupported forms return structured errors.

Prove unequal input batch counts, empty input, two named outputs, one calculation
for multiple readers, failed computation, and returned buffer lifetimes. Prove
relative paths, invalid definitions, fixed loaded bytes, and generated PRQL SQL
against the actual native planner. A loader or test-only executor alone does
not complete this delivery.

### 2. Captured root state and atomic steps

Status: **Not done**.

Add one durable instance head and immutable root packet through existing Data
transactions. Capture root state in the same read transaction as inputs. Replace
per-export source freshness with recorded-cut validity for these steps. Retain
current authority, generation, retry, retained evidence, and root-head checks.
Include jobs in usage accounting, schema validation, artifact collection,
retention, backup, and recovery. Add no hidden fixed packet limit.

Prove A succeeds and B fails with no changes; successful two-call recovery;
independent state for two calls of one export; exact and changed retries;
new input after capture; overlapping generations; revocation; cancellation;
missing retained input; and configured optional quota denial.

### 3. Managed production instances

Status: **Not done**.

Start persisted instances from the Control composition root with or without
a client listener. Use one Query subscription lifetime and one step in flight
per instance. Replace per-export automatic supervision. OCI installation
installs code; a job instance supplies execution intent. Add start, inspect,
stop, and restart qualification through supported owner APIs.

Prove a client disconnect does not stop the job; idle execution has no periodic
source checks; capacity waits wake on release; exact window deadlines execute;
stop joins work; and restart restores the last committed root packet.

### 4. Discovery and algorithm migration

Status: **Not done**.

Express the existing Discovery work as job definitions and package calls.
Delete its source enumeration, direct raw-page reader, run_clock, separate
Control task, and private seal scheduler. Replace remaining host-prepared and
resolved-input execution loops with call bindings. Move algorithm ownership
to the respective package crates and remove replaced implementations.

Retain profile, graph, finding, context, coverage, evidence, native/Wasm, replay,
and notification assertions. Test finite refresh and replay through the same
plan with a selected captured cut. Keep historical qualification attached to
its original source; it does not qualify the replacement.

### 5. Closure

Status: **Not done**.

Reconcile the older redesign sections and package phase records with current
ownership. Preserve their historical results. Update the implementation review
guide with actual source paths and proof. Count real production Rust against
the parent baseline; exclude tests, documentation, blank lines, and code moves.
The required total reduction remains 6,000 nonblank production Rust lines
against `7b7b407adf347d389984553a4d212bfce37b75b5`.

## Verification and current source

Use crate-local Rust tests through production APIs. Run only the relevant
checks during implementation, as the user requires. Do not run the full
workspace procedure or a benchmark without a new instruction. No performance
claim follows from functional execution time.

Baseline commit: `1429920de28a6e2376ef10c6ee3513839eca4da4`. The initial worktree
contained unfinished Query deadline and partition edits, optional read-control
edits, and deletion of Discovery run/run_clock without caller migration.
These drafts are withdrawn from the current delivery. Their files remain
under `/tmp/araphor-stopped-drafts-20261018`. Existing entry points are restored.
These drafts are not a verified replacement or production reduction. Preserve unrelated
source trees and user files. Qualify each completed delivery after its final
relevant source edit and commit it separately, as previously instructed.

Current result: **Not done** for the complete replacement. The new native SQL
package and its production query-RPC path pass the selected checks above.
Existing algorithms remain available. No full workspace CI or benchmark is run,
as instructed.
