# Araphor Query and Analysis Feature Parity TODO

Compare the accepted features with the new Query and Analysis design. Each
item states the previous behavior, the current behavior, the required result,
and the old code that can be reused.

The user requires three TODOs first: 14, the OCI package image; 15, the
Discovery definition file; and 16, running Discovery instances. Complete them
before items 1-13. Definitions contain SQL or PRQL with metadata. Package
calls belong inside those queries. The
[active package and job plan](araphor-package-jobs.md#first-deliverable-definition-files-and-running-instances)
records that priority. Items 1-13 remain recorded TODOs. Existing uncommitted
code from the stopped attempts is an unverified draft. The local backup is
`/tmp/araphor-stopped-drafts-image1`. The draft is not a completed item.

## Intended end state

Keep the accepted package, SDK, graph, detector, and notification behavior.
Run SQL through native DataFusion parsing, logical planning, optimization,
physical planning, and execution. Query subscriptions supply data changes and
window events. Keep the existing Data transactions. Do not use polling.

```text
A subscription receives a data change or a declared window event
  -> Query captures the permitted inputs and their exact revisions
  -> native DataFusion executes the plan
  -> the selected installed package consumes the inputs
  -> Analysis checks the result
  -> Data commits outputs, saved state, evidence references, and progress together

The call fails, loses permission, or is cancelled
  -> Data commits no incomplete result
  -> the operation releases temporary resources
  -> a relevant event or an explicit request can start another call
```

## What already works

The accepted work covers native graph storage, SDK contracts, package
operations, Wasm execution, and native execution. These features remain in
Data, Query, SDK, builtins, and the retained Analysis crate. Control still
uses the retained package, graph, and notification owners.

The new Query already supplies native SQL planning, canonical Arrow tables,
one shared input capture, snapshot queries, subscriptions, cursors,
cancellation, and buffer lifetime checks. These do not need another
implementation.

The new Analysis currently exports only DiscoveryOwner and a restricted SQL
Package adapter. Most of the remaining work connects existing behavior to
this new design. Some work below corrects specific regressions.

A profile is the saved behavior summary for one Discovery interval. Saved
state means the package checkpoint. Input evidence references identify the
retained data that supports a result.

## First-priority TODOs

Complete items 14, 15, and 16 in that order, before items 1-13. These are
separate deliverables. Reuse the compatible old code needed for each one.
The user authorized the OCI image as a separate crate, then the definition
file. Image content, installation, inspection, and definition admission are
**Done**. Running instances and package-call execution remain **Not done**.

### 14. OCI package image

- **Before:** A package contained reusable exports. Installation also activated
  supported exports.
- **Now:** `araphor-package` owns the existing OCI codec and static package
  contracts. The `image install` request retains an image without activation.
  Data owns the durable image root and its exact dependency closure. The old
  `package` commands still use the retained execution owner.
- **Required:** Keep the package as reusable, versioned code. Installing it
  must not start a Discovery. A definition and a running instance select how
  that code is used.
- **Reuse:** Existing Data OCI admission and storage, SDK contracts,
  InstalledAnalysis, and the compatible evaluators in
  [the retained package family](../../crates/araphor-analysis_back/src/package/mod.rs).
  Change the installation/activation connection; do not write another
  artifact format or package evaluator.

Recorded specifications:

- [x] Use OCI metadata and separate artifact layers. Retain exact content
  digests, package/export identities, locked dependencies, and fixtures.
- [x] Retain declared Arrow input/output schemas, multiple named datasets,
  parameters, typed reasons, evidence, and the optional saved-state contract.
  Keep these contracts in the existing SDK.
- [ ] Execute the declared SQL, Wasm, or native implementation. Native Rust
  calls run inside Araphor's process. Do not add fallback to another target
  or a separate package execution process.
- [ ] Keep input bindings, query windows, current grants, progress, and
  instance state at the call or running-instance boundary. Two instances can
  use the same image with different bindings and separate saved state.
- [ ] Pass the selected Arrow inputs, prior state, parameters, and captured
  evaluation context to the package. Validate returned datasets, proposed
  state, reasons, and evidence before Data commits them.
- [ ] Preserve the exact artifact revision used by each call. Installation,
  inspection, or a later image revision must not silently replace the code
  of an already admitted instance.
- [ ] Add no mandatory package-size cap. Resource quotas must be configurable
  and disabled by default. Preserve type, identity, format, and arithmetic
  checks.

Image content, installation, and inspection: **Done**. The affected checks
pass. Read the
[image review](../guides/araphor-binary-package-storage-review.md#image-installation-without-execution)
for the source route. The execution and instance requirements above remain
open. This delivery adds no execution engine, subscription, or timer.

The image delivery adds 615 production Rust lines from `41815177`. The count
excludes tests, comments, documents, and blank lines. Moved code adds zero to
the net count. The complete redesign adds 4,101 lines from `7b7b407a`; another
10,101 must be removed to meet the 6,000-line reduction target. Complete
redesign: **Not done**. The count record is `/tmp/araphor-image-count1.json`.

### 15. Discovery definition file (Compose file)

- **Before:** Control configuration enabled a fixed Discovery implementation.
  Packages also carried input declarations.
- **Now:** `araphor-discovery-definition` owns the JSON file, source capture,
  PRQL compilation, and admitted snapshot. Control admits and inspects that
  snapshot. The fixed live Discovery remains separate.
- **Required:** A reusable definition contains metadata and selects SQL or
  PRQL. Those queries can call installed packages. Starting a definition
  creates a separate running instance.
- **Reuse:** Existing OCI resolution, native Query admission, schemas, and
  compatible package validation. Use an existing PRQL compiler. Do not add
  another SQL parser, planner, or execution engine.

Recorded specifications:

- [x] Select exactly one program form: SQL or PRQL. Either form can use inline
  source or a referenced source file. Package calls belong in the query.
- [x] Include definition metadata such as name, description, and labels.
  Preserve that metadata when the definition is admitted and inspected.
- [x] A native SQL package function identifies the image, exact revision, and
  export. Native subquery arguments supply inputs. Native scalar arguments
  supply parameters. SQL supplies filters and windows.
- [ ] SQL defines its filters, joins, grouping, and windows. PRQL compiles to
  SQL. Package calls stay inside that SQL. Both forms reach native SQL
  parsing, logical planning, optimization, physical planning, and execution.
- [x] Use native DataFusion and existing dependencies wherever they supply
  the required operation. Qualify generated PRQL SQL with the actual native
  planner. Do not assume complete dialect compatibility.
- [x] Resolve relative source paths from the definition directory. Read the
  source files at admission and retain the admitted bytes and package
  revisions. Later file changes require an explicit update; do not poll files.
- [x] Keep running-instance identity, current permission, progress, and saved
  state outside the reusable definition. Metadata in the file grants no
  permission.
- [x] Keep the definition separate from image installation. One image can
  serve several definitions and instances with different inputs or parameters.
- [x] Add no second scheduling language. Query subscriptions supply data
  changes and declared SQL window events.

Definition admission: **Done**. The file selects one program with the `kind`
field. SQL and PRQL use either `source.inline` or `source.file`. The CLI
captures referenced files before the request. The server rejects uncaptured
file references. Data retains exact source text, generated SQL, image pins,
and metadata under an immutable content revision. An explicit admission of
changed content creates another revision. Admission starts no Discovery.

The user replaces the separate JSON package form with native SQL and PRQL
calls. The function name has three parts: image, exact revision, and export.
For example, `"fixture"."r1".count(source => (SELECT ...), increment => 2)`.
Use the first string argument to select an output when necessary. Remove
the JSON call, input binding, parameter, and window fields. Query owns
resolution of all exact image references in the native syntax tree. Keep
the existing Data transaction and final Control permission checks.
Native-call definition admission and selected qualification: **Done**.
All 50 distinct focused tests pass. They cover both source forms, native
arguments, nested calls, recursion, lexical scope, body optimization, exact
image pins, permission, immutable storage, request encoding, and TLS client
admission. Every SQL body plan uses native analysis and optimization.
Plans with no package-call node also use native physical planning.
Formatting and affected-crate Clippy with warnings denied pass. The source
and command record is `/tmp/araphor-sql-call-verification1.json`.
Full workspace CI, benchmarks, and physical Kubernetes checks did not run.

Complete package execution: **Not done**. SQL and PRQL reach native physical
planning during admission. Query binds package inputs, parameters, output,
and dependency contracts into a native `PackageCall` logical node. SQL
body plans with no package-call node also reach native physical planning.
The package-call node
has no physical executor. An execution attempt returns `Unsupported`; it
does not return empty output. The unchecked execution requirement above
remains open with running instances. Read the
[definition review](../guides/araphor-discovery-definition-review.md).

Previous qualification at `318a3259`: **Done**. All 73 distinct cases passed.
These cases cover the
definition format, PRQL, native planning, typed inputs and saved state,
immutable storage, request encoding, permission, CLI output, and the real TLS
client route. Empty schemas retain their row count and continuous row
indices. The existing duplicate-column and reserved-column checks remain.
Formatting and affected-crate Clippy with warnings denied passed. The exact
commands and log hashes are in `/tmp/araphor-definition-verification1.json`.
Full workspace CI, benchmarks, and physical Kubernetes checks did not run.

The previous delivery adds 1,653 production Rust code lines from `a03e5daa`. The
complete redesign adds 5,754 from `7b7b407a`. The 6,000-line reduction requires
another 11,754 net deletions. Tests, comments, documents, blank lines, and
moves do not count as reduction. The record is
`/tmp/araphor-definition-count1.json`. Complete redesign: **Not done**.

The native-call replacement adds 165 production Rust code lines from
`318a3259`: 327 additions and 162 deletions by file size. The complete
redesign adds 5,919 from `7b7b407a`; the required reduction still needs
11,919 net deletions. The simpler file interface is not a production code
reduction. The record is `/tmp/araphor-sql-call-count1.json`.

### 16. Running Discovery instances

- **Before:** Control ran fixed Discovery work. The retained package owner
  supervised scoped activations and saved their results and state.
- **Now:** Fresh Discovery uses reactive Query streams, but no general API
  starts and stops independent instances from definition files.
- **Required:** Create managed instances from admitted definitions. Each
  instance has its own lifetime, selected inputs, progress, and saved state.
- **Reuse:** Query subscriptions and their native stream collection, current
  permission checks, compatible installed evaluation, and Data commit/recovery
  operations. Replace fixed Control selection and old scheduling/input seams.
  Do not copy run_clock, source sweeps, or separate raw readers.

Recorded specifications:

- [ ] Start, inspect, and stop each instance independently. Keep its identity
  separate from the image and reusable definition. Support multiple instances
  that use the same image.
- [ ] Run until explicitly stopped, subject to current permission,
  cancellation, and execution failure. Add no default lifetime cutoff.
  A client disconnect must not stop the managed instance.
- [ ] Drive all execution from actual Query subscription batches and declared
  window events. Use the same native SQL pipeline for every program form.
  Add no polling in the owner or client and no private Discovery clock.
- [ ] Insert and remove subscription streams on demand through a native
  stream collection such as SelectAll/FuturesUnordered. Query owns window
  events and exact deadlines; a timer must not poll for changes.
- [ ] Give each instance separate progress and saved state. Execute a logical
  call against its complete selected inputs; Arrow batch boundaries must not
  change the call's meaning.
- [ ] Bind inputs and declared SQL reads to the captured Data view and
  evaluation time. New input remains pending while that call uses its
  captured view.
- [ ] Use the existing Data commit checks to keep outputs, proposed state,
  evidence references, and consumed progress consistent. Failed or cancelled
  work must not advance committed state or progress.
- [ ] Check current permission before execution and commit. Stopping an
  instance or revoking its grant must cancel work and reject stale completion.
  Release its streams, buffers, and runtime handles.
- [ ] Restore active instances after restart from their admitted definition,
  exact package revisions, committed state, and progress. Recheck current
  permission. Missing retained input must produce an explicit incomplete or
  unavailable result.
- [ ] Stopping one instance must leave other instances and referenced package
  history intact.

The analogy is: image = OCI package; Compose file = Discovery definition;
running container = Discovery instance. It does not require container
isolation or another process for native calls.

These TODOs record behavior. They do not approve the earlier draft's new
crate names, root-packet/head storage, all-call transaction model, or
partitioned-call state design. The definition review records the implemented
file schema and admission commands. A package-issued internal-query SDK
capability is not defined; the current ABI does not supply that capability.
Any such API must preserve the same captured view and requires a separate
concrete design.

## Earlier parity TODOs

### 1. Package operations and saved state

- **Before:** Install, inspect, test, run, update, roll back, and remove SQL,
  Wasm, and native packages. Pass parameters, dependencies, and saved state.
  Return named outputs, reasons, and evidence.
- **Now:** These operations still run through analysis_back. The new Analysis
  Package adapter accepts only a restricted SQL model.
- **Required:** Support the same operations through active Analysis. Preserve
  exact retries, failed-update rollback, permissions, restart, and atomic saved
  state. Separate package installation from Discovery start as described in
  items 14-16. Keep the complete backup available.
- **Reuse:** The compatible [package family](../../crates/araphor-analysis_back/src/package/mod.rs),
  [model execution](../../crates/araphor-analysis_back/src/model/execute.rs),
  and [output checks](../../crates/araphor-analysis_back/src/model/output.rs).
  Package supervision already uses Query Inputs::watch. Keep Data package
  storage and SDK contracts in their current crates.

### 2. Installed package calls in SQL

- **Before:** The package owner selected and called the installed SQL, Wasm,
  or native implementation.
- **Now:** The general evaluator still works in analysis_back. The new
  Discovery SQL path does not expose general installed exports as SQL calls.
- **Required:** Let a SQL query call an installed export and use its declared
  outputs. Use the same native planning and execution route. Preserve
  parameters, saved state, permissions, and the exact artifact revision.
- **Reuse:** [InstalledAnalysis](../../crates/araphor-analysis_back/src/package/installed.rs),
  [target dispatch](../../crates/araphor-analysis_back/src/package/execution.rs),
  and compatible native/Wasm runtime code. Connect these at the native Query
  execution boundary. Do not create another package lifecycle.

### 3. Graph history and SDK input metadata

- **Before:** A traversal could select an exact old graph version. SDK inputs
  included graph completeness, missing-data reasons, and traversal boundaries.
- **Now:** Native Query already supplies graph datasets. However, the request's
  result_ids are not applied to version selection. SDK completeness metadata
  does not include all selected-graph and traversal facts.
- **Required:** Return the requested permitted version. Report whether that
  graph input is complete, incomplete, or limited by the traversal. Keep all
  input datasets under the same captured source revision.
- **Reuse:** Keep the current Data graph extraction and Query Inputs. Reuse the
  old Query selection and completeness rules from
  d20ee0fd6:crates/araphor-data/src/query/analysis/projection.rs.
  Apply them at the existing [Data selection](../../crates/araphor-data/src/analysis/extraction/graph/traversal/versions.rs)
  and [Query receipt](../../crates/araphor-query/src/inputs/receipt.rs)
  boundaries. No old row codec or separate graph input owner is required.

### 4. Discovery window completion and evidence

- **Before:** Discovery closed an interval, saved its final profile, and
  retained the selected input evidence. Its host loop decided when to close.
- **Now:** Query supports rolling row expiry. The new Discovery publication
  always writes an open profile and an empty evidence-reference list.
- **Required:** Query must report the declared window's completion. Analysis
  must then save the final profile and its evidence. Later data must enter the
  next interval. No host clock loop is permitted.
- **Reuse:** The profile construction, evidence selection, and closing rules
  in [old Discovery live code](../../crates/araphor-analysis_back/src/discovery/live.rs).
  Reuse Data's existing profile commits. Replace the old scheduling and raw
  input reads with Query subscription input and window events.

### 5. Exact input and package versions for each profile

- **Before:** A profile recorded its input range, context facts, and installed
  package versions. A package change could start a new interval.
- **Now:** The new path keeps context references and a SQL package reference.
  It does not keep the complete recorded input description used by old replay
  or perform the same package-change interval decision.
- **Required:** Record the exact data, facts, and code used for each profile.
  A package change must not merge results from incompatible implementations
  into the same interval.
- **Reuse:** [Installed reference checks](../../crates/araphor-analysis_back/src/discovery/installed.rs)
  and source_context in
  [old Discovery live code](../../crates/araphor-analysis_back/src/discovery/live.rs).
  Adapt their recorded description to the selected SQL export. Keep context
  and result storage in Data.

### 6. Finite execution, refresh, profile reads, and replay

- **Before:** Callers could process available input, refresh a profile, read
  the profile, and reproduce it from its recorded data and code.
- **Now:** Those operations remain in analysis_back. The new Discovery owner
  exposes its continuous run path but not these equivalent operations.
- **Required:** Supply these operations through new Analysis. All execution
  and replay input must come from Query subscriptions. Missing historical
  input or code must produce an explicit unavailable result.
- **Reuse:** profile and refresh validation from
  [old live code](../../crates/araphor-analysis_back/src/discovery/live.rs),
  plus [replay validation and input capture](../../crates/araphor-analysis_back/src/discovery/replay.rs).
  The retained replay reader already uses a finite Query subscription.
  Do not bring back the old process loop.

### 7. Context selection, display groups, and baseline comparison

- **Before:** Callers could import and select permitted context, group behavior
  records for display, and compare current behavior with a reviewed baseline.
- **Now:** These operations still exist in analysis_back and builtins. They
  are not exposed through the new Analysis path.
- **Required:** Preserve their results and permission checks in new Analysis.
  Connect Control preview and the existing callers to that path.
- **Reuse:** [Context policy](../../crates/araphor-analysis_back/src/discovery/context.rs),
  [SDK context checks](../../crates/araphor-analysis_back/src/discovery/sdk/context.rs),
  [snapshot/group adapter](../../crates/araphor-analysis_back/src/discovery/sdk/snapshot.rs),
  and [comparison adapter](../../crates/araphor-analysis_back/src/discovery/sdk/compare.rs).
  Keep shared computations in their existing package crates. Use existing
  native SQL computation where it already supplies the operation.

### 8. Discovery after an expired data range

- **Before:** Optional Discovery could record an expired range and continue
  with later retained records.
- **Now:** The new path handles a saved position below the retained floor.
  It can fail when an interior range expires while an earlier range stays
  pinned and keeps the floor at zero.
- **Required:** Process each retained range and record each exact missing
  range. Preserve cumulative counts and completeness. Reject a stale resume.
- **Reuse:** Data's [optional processor resume transaction](../../crates/araphor-data/src/analysis/progress.rs)
  and captured coverage records. Select the next range in native SQL.
  Put the expected-position check inside Data's transaction. Do not reuse the
  old source sweep or add a second reader.

### 9. Graph and detector execution from Query events

- **Before:** Graph processing selected source windows, called installed
  detectors, checked proof, and committed graph and finding results.
- **Now:** This still works through analysis_back. Control starts it every
  second. The old owner scans sources and reads its input windows separately.
- **Required:** Query subscriptions must supply the selected event, context,
  coverage, package, and window changes. Preserve detector results, graph
  replacement, recovery, expiry, and operation with Discovery disabled.
- **Reuse:** Compatible [derivation](../../crates/araphor-analysis_back/src/graph/derive.rs),
  [installed selection](../../crates/araphor-analysis_back/src/graph/installed.rs),
  [commit checks](../../crates/araphor-analysis_back/src/graph/commit.rs),
  and graph proof/read code. Replace the scheduling in graph/live.rs and the
  input read in graph/input.rs. Keep Data graph storage and the three detector
  packages in their current crates.

### 10. Notification execution from Query events

- **Before:** The router created obligations, delivered notifications, retried
  failed delivery, escalated overdue work, and recorded acknowledgements.
- **Now:** The same state logic still works through analysis_back. Control
  calls it every second. Query already exposes notification rows and
  acknowledgement deadlines, but not every retry deadline.
- **Required:** Data, route, permission, retry, and acknowledgement events must
  trigger the existing operations. Preserve restart and disclosure checks.
- **Reuse:** The [notification family](../../crates/araphor-analysis_back/src/notification/mod.rs),
  including schedule, send, complete_attempt, and acknowledge. Replace the
  Control timer with Query events and exact deadlines. Keep delivery rules
  and durable notification records with their existing owners.

### 11. Runtime configuration through Control

- **Before:** Control passed configured Wasm and native options to the package
  runtime.
- **Now:** The option types still exist, but Control constructs the package
  owner with defaults. Explicit runtime options no longer reach it.
- **Required:** Pass the configured Analysis options at first construction.
  Check them when the runtime is reused. Omitted quotas must stay disabled.
- **Reuse:** [AnalysisLimits](../../crates/araphor-analysis_back/src/limits.rs)
  and new_with_limits in the
  [package owner](../../crates/araphor-analysis_back/src/package/owner.rs).
  Correct the [Control configuration route](../../crates/mithril-control/src/service/packages.rs).

### 12. Data and Wasm cancellation without periodic checks

- **Before:** Data used repeated lock and interruption checks. Wasm used a
  periodic epoch tick to interrupt execution.
- **Now:** Those waits remain, including the five-millisecond Wasm tick.
- **Required:** Wait for lock release, cancellation, completion, or an actual
  deadline. Preserve interruption and reject cancelled output. Do not poll.
- **Reuse:** Compatible Wasm admission, cache, execution, and cleanup code.
  Replace EpochTicker in
  [Wasm execution](../../crates/araphor-analysis_back/src/package/wasm/execution.rs)
  and the periodic waits in
  [Data read control](../../crates/araphor-data/src/analysis/read.rs).

### 13. Configurable quotas, disabled by default

- **Before:** Several limits were mandatory.
- **Now:** Wasm/native options, shared memory capacities, and storage limits
  already have disabled defaults. Query per-call limits, SDK limits,
  extraction limits, and compiler limits still include mandatory bounds.
- **Required:** Make the remaining quotas configurable and disabled by
  default. Keep identity, type, format, and arithmetic validation.
- **Reuse:** Existing option handling and configured-limit checks. Change
  their configuration and disabled path. Do not add another resource owner.
  This includes [Query limits](../../crates/araphor-query/src/execution.rs),
  [SDK limits](../../crates/araphor-analysis-sdk/src/model.rs),
  Data extraction limits, and the retained Wasm compiler limits.

## Checks for completion

Move the existing assertions with the compatible code. Use the current
production APIs. Do not weaken tests to make the new design pass.

| TODO | Required check |
| --- | --- |
| 14, first | Install and inspect an OCI image without starting Discovery. Execute its declared implementation through native Query and preserve typed input/output and state validation. |
| 15, next | Admit package-call, PRQL, and SQL definitions with metadata and relative source files. Prove native execution. A later file change must not change an admitted definition. |
| 16, then | Start two independent instances with different inputs or parameters. Stop one while the other continues. Check client disconnect, idle execution, restart, state/progress recovery, cancellation, and revoked or expired grants. |
| 1-2 | Install a dependency chain; pass parameters and saved state; update, roll back, restart, revoke, and remove it. Check SQL, Wasm, and native dispatch. A failed call changes no committed output or state. |
| 3 | Request old R1 after R2 replaces it. Check permitted and denied IDs, graph completeness, empty schemas, typed joins, cancellation, deadlines, buffer lifetime, and native Arrow offset bounds. Preserve all seven previous graph SDK scenarios and the installed-component round trip. |
| 4 | Close an idle window once at its exact boundary. Retain its selected evidence. Put later records in the next interval. |
| 5-6 | Change code and context after a profile is saved. Replay must still use its original versions. Late context repair must not double-count records. Missing input must report unavailable. |
| 7 | Preserve baseline results and each context cutoff, permission, conflict, omission, grouping, and comparison assertion. |
| 8 | Keep cursor 1 pinned, expire cursor 2, and retain cursor 3. Process 1 and 3 and record only gap 2. A stale resume changes no progress. |
| 9 | Preserve process, credential, and Kubernetes detector results. Refresh only affected work. Keep failure isolation and Discovery-disabled behavior. |
| 10 | Preserve delivery, exact retry, escalation, restart, acknowledgement, and current permission checks. |
| 11 | A configured Wasm limit takes effect. An unsupported native hard limit returns Unsupported. SQL and Wasm remain usable. |
| 12-13 | Idle work has no periodic wake. Cancellation and explicit quotas still work. Absent quotas impose no arbitrary cap. |

Use relevant builds and tests after implementation is approved. Do not run a
new benchmark or full workspace CI for this clarification.

## Audit basis and result

The source comparison covers the accepted
[parent plan](mithril-hugging-face-intrusion-prevention/phase-7-mithril-control-and-detection-packages/phase-7-5-graphs-findings-and-notifications/README.md),
the completed native baseline at 5e936454, the reduction baseline at
7b7b407a, the last Query implementation before replacement at d20ee0fd6,
and committed replacement code at 41815177.

Native DataFusion name, numeric, and wildcard behavior is an approved change.
Old QuerySql and QueryPlan types do not need to return. The user excluded
old-store compatibility. Python execution and upstream algorithm ports were
not completed baseline features. The previous Query plan deferred overlapping
windows, sessions, and event-time finality. These are not redesign regressions.

The production Rust reduction target remains 6,000 net code lines against
7b7b407a. At 41815177, the count adds 3,486 lines. Another 9,486 net deletions
are required. Moves, tests, documents, comments, and blank lines do not count.

Source comparison: **Done**. The user requires items 14-16 first, including
all three program forms. Other TODOs remain recorded work. Implementation and full feature
parity: **Not done**.

The previous delivery's selected runtime and Clippy results remain recorded in
the [subscription stream result](araphor-component-redesign.md#subscription-streams-and-shared-validation).
They do not qualify the frozen drafts or the proposed changes above.
