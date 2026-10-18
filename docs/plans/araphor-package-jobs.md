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
   execution. A direct call or PRQL source must reach that same SQL route.
3. Build new Discovery packages. Keep the existing package implementations
   available for reuse and comparison. Remove obsolete orchestration only when
   its replacement preserves the required behavior.
4. Before each addition, check whether it fits this design, whether a simpler
   form works, whether it is required, and whether DataFusion or an existing
   dependency already supplies it. Reuse native implementation when it does.
5. Execution is reactive. Periodic polling is prohibited. A declared window
   boundary is a processing event; a timer that checks for changes is polling.
6. Keep new packages in their own crates. Do not move old code to a new crate
   and describe that move as a rewrite or reduction.

### Immediate delivery order

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

Native SQL package and selected caller qualification: **Done**. The new crate
is `araphor-discovery-effects`. Control registers its native relation planner
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

## Earlier design draft

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
