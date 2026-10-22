# Araphor Query and Analysis Feature Parity TODO

Compare the accepted features with the new Query and Analysis design. Each
item states the previous behavior, the current behavior, the required result,
and the old code that can be reused.

The user requires three TODOs first: 14, the OCI package image; 15, the
Discovery definition file; and 16, running Discovery instances. Complete them
before items 1-13. YAML definitions contain metadata and select SQL, PRQL, or
a structured package call. The call form produces native SQL. The
[active package and job plan](araphor-package-jobs.md#first-deliverable-definition-files-and-running-instances)
records that priority. Items 1-13 remain recorded TODOs. Existing uncommitted
code from the stopped attempts is an unverified draft. The local backup is
`/tmp/araphor-stopped-drafts-image1`. The draft is not a completed item.

## Intended end state

The user authorizes the complete reference migration on 2026-10-19. The
[Analysis migration record](araphor-analysis-migration.md) maps all 95
production source files, root exports, required rules, and test families.
It is the source checklist for retirement. Keep the reference unchanged
until replacements pass qualification. Complete migration: **Not done**.

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

The backup deletion is withdrawn after the user identifies missing compatible
functionality. All 208 backup files and 34 deleted Control and E2E reference
files are restored from `6a25ba1b`. The current production wiring does not
reconnect the old execution owners. Migration and removal remain **Not done**.
A complete file and function map must replace assumptions about compatibility.

The earlier finite retirement removed 29 duplicate reference leaves after
source comparison and focused qualification. At that point, 179 files remained
unchanged. The historical final Rust gate
`migration-final-ci42` covers those 29 leaves. Four additional reference files
were then retired. Eight more Wasm leaves and 15 finite Graph, SQL, Discovery,
test, and asset leaves are retired. Eight executor, component, atom, pager,
and pure test leaves are then removed after 50 focused replacement checks pass.
Fifteen more retained-query, authority, Wasm, and finite notification test
leaves are removed after 89 focused checks pass. Two image/fixture leaves then
retire after exact replacement tests pass. The complete error leaf then
retires after typed error and joined execution checks pass. There are now
103 retired files; 105 baseline files remain unchanged. The storage-window
retirement transfers the complete assertions after all 39 connected cases pass.
The later baseline retirement qualifies all 12 snapshots through 36 native calls
before the four old test/assets files are removed. Runtime now owns the
complete limits configuration and both original serialization tests.
The native operation replacement also retires one complete test leaf after
all ten old test functions have passing native assertions. This test-only
removal does not reduce production code. The native model replacement retires five more whole files after all 50
mapped cases pass. This removes 306 production lines. The later public receipt/output replacement retires three more files and 90
production lines after the full wire matrix and actual target checks pass.
Fresh Inspect status, successful receipt history, raw output and native SQL
reads now pass through Control and CLI. Per-input native windows pass 53
connected Query checks. Full per-window/latest history, installed clock,
supervision, and other old input-runner live rules remain open. The recovery archive
retains all 208 originals. Read the
[retirement record](araphor-analysis-migration.md#retired-finite-reference-files)
for the exact scope. The full Rust gate59 stops at a stale OCI fixture. The
corrected fixture passes all 15 Package cases. The complete final Rust gate
and migration remain **Not done**.
Before an attempt exists, the host waits on known reader and memory release events. Data
reader admission is configurable and disabled by default. Graph publication,
immutable retry, and notice acknowledgement require final authority checks.
Fresh Graph writes compare the exact prior window head. The connected checks
cover 106 distinct passing cases. No further reference file is retired by
these corrections. Complete producers, public lifecycle, native Data waits,
and the final Rust gate remain open.
The metadata-first resume passes focused checks with a real saved checkpoint
and full configured input pressure. Source changes and saved deadlines use the
same native Query Progress. Explicit rebuild still executes. Six more native
input cases pass. Actual Wasm and native checkpoint retry/reopen and native
overflow assertions pass. Two complete checkpoint test leaves retire. This
removes no production code. Retained dependency expiry, pressure retry,
general scalar clock events and the complete input executor remain open.
Read the [bounded result](araphor-analysis-migration.md#metadata-first-resume-and-checkpoint-retries).
The items below that describe removed paths refer to the stopped draft, not
a qualified replacement. No deletion commit or push was made.


Data retains native graph storage, history, traversal, atomic transactions,
and evidence validation. The SDK and builtins retain typed contracts and the
three detector computations. Compatible native and Wasm evaluators now belong
to Package Runtime. Active Analysis retains finite notification authorization,
state, delivery, and acknowledgement operations.

The user directs removal of `araphor-analysis_back` before completion of finite
OCI execution. That crate and its old activation API, duplicate model planner,
source sweeps, recorded preview bridge, and periodic graph and notification
tasks are disconnected in the draft. The reference files are restored. Current
functional qualification is incomplete. Automatic graph and notification production and the old activation
and replay workflows are not supplied by this deletion. Their TODOs remain
open. Historical source links below select the last committed backup.

The new Query already supplies native SQL planning, canonical Arrow tables,
one shared input capture, snapshot queries, subscriptions, cursors,
cancellation, and buffer lifetime checks. These do not need another
implementation.

Active Analysis exports the reactive Discovery owner, its SQL package adapter,
and finite notification operations. Native Query has the general OCI physical
call path. The finite Instance owner now connects exact definition admission,
immutable attempts, captured prior state, and atomic multi-call Data commits.
Focused finite checks pass. Managed subscriptions, lifecycle, automatic
restart, and full migration remain open. Some work below corrects specific
regressions. The [finite result](araphor-analysis-migration.md#finite-managed-source-focused-qualification)
records current owners and qualification.

A profile is the saved behavior summary for one Discovery interval. Saved
state means the package checkpoint. Input evidence references identify the
retained data that supports a result.

## First-priority TODOs

Complete items 14, 15, and 16 in that order, before items 1-13. These are
separate deliverables. Reuse the compatible old code needed for each one.
The user authorized the OCI image as a separate crate, then the definition
file. Image content, installation, inspection, and definition admission are
**Done**. Running instances remain **Not done**. Native finite package-call
execution is implemented. Its current qualification and remaining managed
requirements are in the [migration record](araphor-analysis-migration.md).

### 14. OCI package image

- **Before:** A package contained reusable exports. Installation also activated
  supported exports.
- **Now:** `araphor-package` owns the existing OCI codec and static package
  contracts. The `image install` request retains an image without activation.
  Data owns the durable image root and its exact dependency closure. The old
  activation-oriented `package` commands are removed.
- **Required:** Keep the package as reusable, versioned code. Installing it
  must not start a Discovery. A definition and a running instance select how
  that code is used.
- **Reuse:** Existing Data OCI admission and storage, SDK contracts,
  and the compatible evaluators reused from
  [the historical package family](https://github.com/Ereborlabs/erebor-runtime/blob/6a25ba1b34dbaa0a553b1883058938683ce7aaab/crates/araphor-analysis_back/src/package/mod.rs).
  Change the installation/activation connection; do not write another
  artifact format or package evaluator.

Recorded specifications:

- [x] Use OCI metadata and separate artifact layers. Retain exact content
  digests, package/export identities, locked dependencies, and fixtures.
- [x] Retain declared Arrow input/output schemas, multiple named datasets,
  parameters, typed reasons, evidence, and the optional saved-state contract.
  Keep these contracts in the existing SDK.
- [x] Execute the declared SQL, Wasm, or native implementation. Native Rust
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
for the source route. The image delivery added no execution engine,
subscription, or timer. The current native execution and its qualification
are in the [migration record](araphor-analysis-migration.md). Managed state
and instance requirements above remain open.

The image delivery adds 615 production Rust lines from `41815177`. The count
excludes tests, comments, documents, and blank lines. Moved code adds zero to
the net count. The complete redesign adds 4,101 lines from `7b7b407a`; another
10,101 must be removed to meet the 6,000-line reduction target. Complete
redesign: **Not done**. The count record is `/tmp/araphor-image-count1.json`.

### 15. Discovery definition file (Compose file)

- **Before:** Control configuration enabled a fixed Discovery implementation.
  Packages also carried input declarations.
- **Now:** `araphor-discovery-definition` owns the YAML file, source capture,
  PRQL compilation, and admitted snapshot. Control admits and inspects that
  snapshot. The fixed live Discovery remains separate.
- **Required:** A reusable YAML definition contains metadata and selects SQL,
  PRQL, or one package call. Calls use native SQL planning. Starting a
  definition creates a separate running instance.
- **Reuse:** Existing OCI resolution, native Query admission, schemas, and
  compatible package validation. Use an existing PRQL compiler. Do not add
  another SQL parser, planner, or execution engine.

Recorded specifications:

- [x] Select exactly one YAML form: `sql`, `prql`, or `call`. SQL and PRQL
  accept inline text or `{file: path}`. A structured call produces native
  SQL. Its inputs accept inline SQL or referenced files.
- [x] Include definition metadata such as name, description, and labels.
  Preserve that metadata when the definition is admitted and inspected.
- [x] A native SQL package function identifies the image, exact revision, and
  export. Native subquery arguments supply inputs. Native scalar arguments
  supply parameters. SQL supplies filters and windows.
- [x] SQL defines its filters, joins, grouping, and windows. PRQL compiles to
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

Definition admission: **Done**. Every form requires YAML `name` metadata and
accepts `description` and `labels`. A raw SQL or PRQL file is not a complete
definition. The CLI captures referenced files before the request. The server
rejects uncaptured file references. Data retains SQL or PRQL text, generated
SQL, image pins, and metadata under an immutable content revision. A YAML call
retains normalized SQL, not the original YAML mapping or input formatting.
An explicit admission of changed content creates another revision. Admission
starts no Discovery. The JSON request and snapshot formats do not change.

YAML implementation and selected functional qualification: **Done**. All 60
distinct focused tests pass. They cover metadata for all three forms, file
capture, strict maps, integer precision, native plans, exact image pins,
permission, immutable storage, recovery, CLI, and TLS admission. Formatting
and affected-crate Clippy with warnings denied pass. The source and command
record is `/tmp/araphor-yaml-verification1.json`. This authoring delivery adds
261 production Rust code lines from `d49e6bd5`: 282 additions and 21 deletions
by file size. The complete redesign adds 6,180 from `7b7b407a`; another 12,180
must be removed for the 6,000-line reduction target. Tests, comments,
documents, blank lines, and moves do not count as reduction. The record is
`/tmp/araphor-yaml-count1.json`. Complete reduction: **Not done**. Full
workspace CI, benchmarks, and physical Kubernetes checks did not run.
At that authoring revision, package-call physical execution and running
instances remained open.

The [native admission simplification](araphor-package-jobs.md#native-admission-simplification)
uses native DataFrame indexing and plan transformation. Default input SQL is
parsed once. The same traversal binds dependent inputs and updates schemas.
Configured quotas still apply. Package calls use the native `RelationPlanner`
for relation arguments; they are not scalar UDFs. At that admission revision,
physical package execution and running instances remained **Not done**.

Native admission simplification and selected qualification: **Done**. All
61 distinct focused tests pass. Formatting and affected-crate Clippy with
warnings denied pass. This change removes 27 production Rust code lines
from `b637c05a`. Read the linked design for the count and verification
records. At this revision, the separate Effects function resolver still
required consolidation. The later
[native derived relation change](araphor-package-jobs.md#native-derived-relations-and-crate-removal)
removes the complete Effects crate. Query registers native views from SQL
metadata. The required SQL computations and tests belong to the existing
built-in and Analysis package owners. Crate removal and selected qualification:
**Done**. All 354 distinct focused tests pass. Scoped formatting and
affected-crate Clippy with warnings denied pass. The source and command record
is `/tmp/araphor-native-views-verification1.json`. The change removes 157
production Rust code lines from `5c9e2fb7`. Read the linked result for the count
method and exclusions. At that revision, physical package-call execution,
managed instances, and the complete reduction remained **Not done**.

The previous delivery replaces the separate JSON package form with native SQL and PRQL
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

The preceding admission delivery had no PackageCall physical executor.
Execution returned `Unsupported`. Current Query uses the native PackageExec
extension for finite SQL, Wasm, and native calls. One source capture supplies
Arrow inputs, parameters, and prior state. SDK checks cover all returned
datasets, proposed state, reasons, and evidence. Admission checks precede
native optimization. Results have read-only accessors and private attribution.
The [migration record](araphor-analysis-migration.md) gives current tests and
remaining work. Finite Instance execution now registers the captured attempt
before execution and atomically publishes complete actual call returns,
guarded state, evidence references, and progress. Focused checks cover prior
reuse and reset, exact completed retries, current authority, and cancellation.
The complete final Rust gate remains **Not done**. Complete managed
execution and automatic restart remain **Not done**. Read the
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
- **Now:** Fresh Discovery uses reactive Query streams. The finite Instance
  owner admits an exact definition and call manifest, captures guarded prior
  state, registers immutable attempts, and commits multi-call results and
  progress atomically. Completed retries recover the original receipt. No
  general service API starts, stops, or restores independent running instances.
  The native Instance subscription now passes focused lifecycle, saved-cursor,
  state, cancellation, and progress checks. Known terminal outcomes, original
  claim lifetime, and failed-offer wait cuts also pass focused checks. The host
  remains open. Read the
  [subscription result](araphor-analysis-migration.md#native-managed-subscription-qualification).
  The [terminal result](araphor-analysis-migration.md#known-terminal-outcomes-and-failed-offers)
  records the later 83 passing cases and the remaining pressure-retry limit.
  Shared image ownership also passes focused checks. Query retains the
  admitted image and its reservation once; Instance borrows that image set.
  A typed Query authority notice stays distinct from a real source denial.
  Read the [image result](araphor-analysis-migration.md#shared-admitted-images-and-error-origins).
  Native input capture and projected membership also pass focused checks.
  SQL body inputs retain parent revision and coverage. The host reads small
  membership keys, joins old workers before replacement, and receives Stop
  notices during metadata pressure. Managed Run borrows admitted sources.
  Read the [capture result](araphor-analysis-migration.md#native-input-capture-and-projected-membership).
  General initial-admission pressure retry and public lifecycle remain open.
- **Required:** Create managed instances from admitted definitions. Each
  instance has its own lifetime, selected inputs, progress, and saved state.
- **Reuse:** Query subscriptions and their native stream collection, current
  permission checks, compatible installed evaluation, and Data commit/recovery
  operations. Replace fixed Control selection and old scheduling/input seams.
  Do not copy run_clock, source sweeps, or separate raw readers.

Recorded specifications:

The [finite result](araphor-analysis-migration.md#finite-managed-source-focused-qualification)
covers finite admission, capture, state, publication, authority, cancellation,
and receipt recovery. The requirements below also include running-service
lifetime and restart behavior. Keep them unchecked until that complete
behavior passes qualification. The current final Rust gate is pending.

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

## Historical qualification that still requires migration

The restored reference retains the old activation, model, source-sweep,
recorded-preview, and graph-production tests. Their assertions must be checked
for compatible domain rules before retirement. These tests are not current
replacement proof. Compatible backend loader, Wasm cache,
resource, cancellation, and notification state assertions move beside their
current owners. Current Data store, Query follow, image and definition TLS,
permission, immutable revision, and storage-recovery checks remain active.
The Data storage-contract case uses the frozen expected fixture count; it
no longer calls the removed host Discovery algorithm as its oracle.

The replacement still needs the old detector output and proof assembly,
authorized graph publication, recorded profile replay and refresh, complete
context and baseline adapter cases, automatic notification subscriptions,
retry event exposure, and managed state/progress recovery. TODOs 4-10 and 16
retain those requirements. The three detector computations and Data validation
contracts remain. Their presence does not qualify a complete producing path.

## Earlier parity TODOs

### 1. Package operations and saved state

- **Before:** Install, inspect, test, run, update, roll back, and remove SQL,
  Wasm, and native packages. Pass parameters, dependencies, and saved state.
  Return named outputs, reasons, and evidence.
- **Now:** Image and definition install/inspection use current owners. Finite
  native Query execution accepts Arrow input, parameters, and prior state.
  Finite Instance execution now preserves guarded state, atomic multi-call
  publication, immutable attempts, and original receipt recovery. The old
  activation, update, rollback, removal, and restart APIs are removed. Their
  managed lifecycle replacements remain unimplemented.
- **Required:** Support the same operations through active Analysis. Preserve
  exact retries, failed-update rollback, permissions, restart, and atomic saved
  state. Separate package installation from Discovery start as described in
  items 14-16. The backup source remains available in Git.
- **Reuse:** The compatible [package family](https://github.com/Ereborlabs/erebor-runtime/blob/6a25ba1b34dbaa0a553b1883058938683ce7aaab/crates/araphor-analysis_back/src/package/mod.rs),
  [model execution](https://github.com/Ereborlabs/erebor-runtime/blob/6a25ba1b34dbaa0a553b1883058938683ce7aaab/crates/araphor-analysis_back/src/model/execute.rs),
  and [output checks](https://github.com/Ereborlabs/erebor-runtime/blob/6a25ba1b34dbaa0a553b1883058938683ce7aaab/crates/araphor-analysis_back/src/model/output.rs).
  The old Query Inputs::watch supervision is historical reference only. Keep
  Data package storage and SDK contracts in their current crates. Do not
  restore the old model planner or activation supervisor.

### 2. Installed package calls in SQL

- **Before:** The package owner selected and called the installed SQL, Wasm,
  or native implementation.
- **Now:** Native Query admits exact installed export calls and has a physical
  extension for SQL, Wasm, and native execution. Focused finite qualification
  passes, including managed state and atomic publication. The current final
  Rust gate is pending. Automatic restart remains open.
- **Required:** Let a SQL query call an installed export and use its declared
  outputs. Use the same native planning and execution route. Preserve
  parameters, saved state, permissions, and the exact artifact revision.
- **Reuse:** [InstalledAnalysis](https://github.com/Ereborlabs/erebor-runtime/blob/6a25ba1b34dbaa0a553b1883058938683ce7aaab/crates/araphor-analysis_back/src/package/installed.rs),
  [target dispatch](https://github.com/Ereborlabs/erebor-runtime/blob/6a25ba1b34dbaa0a553b1883058938683ce7aaab/crates/araphor-analysis_back/src/package/execution.rs),
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
  in [old Discovery live code](https://github.com/Ereborlabs/erebor-runtime/blob/6a25ba1b34dbaa0a553b1883058938683ce7aaab/crates/araphor-analysis_back/src/discovery/live.rs).
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
- **Reuse:** [Installed reference checks](https://github.com/Ereborlabs/erebor-runtime/blob/6a25ba1b34dbaa0a553b1883058938683ce7aaab/crates/araphor-analysis_back/src/discovery/installed.rs)
  and source_context in
  [old Discovery live code](https://github.com/Ereborlabs/erebor-runtime/blob/6a25ba1b34dbaa0a553b1883058938683ce7aaab/crates/araphor-analysis_back/src/discovery/live.rs).
  Adapt their recorded description to the selected SQL export. Keep context
  and result storage in Data.

### 6. Finite execution, refresh, profile reads, and replay

- **Before:** Callers could process available input, refresh a profile, read
  the profile, and reproduce it from its recorded data and code.
- **Now:** Data retains profiles and native Query supplies finite execution.
  The old host replay and refresh adapters are removed. Equivalent current
  profile execution and replay operations remain unimplemented.
- **Required:** Supply these operations through new Analysis. All execution
  and replay input must come from Query subscriptions. Missing historical
  input or code must produce an explicit unavailable result.
- **Reuse:** profile and refresh validation from
  [old live code](https://github.com/Ereborlabs/erebor-runtime/blob/6a25ba1b34dbaa0a553b1883058938683ce7aaab/crates/araphor-analysis_back/src/discovery/live.rs),
  plus [replay validation and input capture](https://github.com/Ereborlabs/erebor-runtime/blob/6a25ba1b34dbaa0a553b1883058938683ce7aaab/crates/araphor-analysis_back/src/discovery/replay.rs).
  The historical replay reader used a finite Query subscription. Reuse that
  boundary, not the old process loop.

### 7. Context selection, display groups, and baseline comparison

- **Before:** Callers could import and select permitted context, group behavior
  records for display, and compare current behavior with a reviewed baseline.
- **Now:** Builtin computations and Data context contracts remain. The old
  Analysis adapters and Control recorded preview bridge are removed. Complete
  equivalent operations are not exposed through current Analysis.
- **Required:** Preserve their results and permission checks in new Analysis.
  Connect Control preview and the existing callers to that path.
- **Reuse:** [Context policy](https://github.com/Ereborlabs/erebor-runtime/blob/6a25ba1b34dbaa0a553b1883058938683ce7aaab/crates/araphor-analysis_back/src/discovery/context.rs),
  [SDK context checks](https://github.com/Ereborlabs/erebor-runtime/blob/6a25ba1b34dbaa0a553b1883058938683ce7aaab/crates/araphor-analysis_back/src/discovery/sdk/context.rs),
  [snapshot/group adapter](https://github.com/Ereborlabs/erebor-runtime/blob/6a25ba1b34dbaa0a553b1883058938683ce7aaab/crates/araphor-analysis_back/src/discovery/sdk/snapshot.rs),
  and [comparison adapter](https://github.com/Ereborlabs/erebor-runtime/blob/6a25ba1b34dbaa0a553b1883058938683ce7aaab/crates/araphor-analysis_back/src/discovery/sdk/compare.rs).
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
- **Now:** Data retains graph contracts, validation, commits, history, and
  traversal. Builtins retain the three detector computations. The old graph
  producer and Control timer are removed. Current Query subscriptions do not
  yet drive authorized graph assembly and publication.
- **Required:** Query subscriptions must supply the selected event, context,
  coverage, package, and window changes. Preserve detector results, graph
  replacement, recovery, expiry, and operation with Discovery disabled.
- **Reuse:** Compatible [derivation](https://github.com/Ereborlabs/erebor-runtime/blob/6a25ba1b34dbaa0a553b1883058938683ce7aaab/crates/araphor-analysis_back/src/graph/derive.rs),
  [installed selection](https://github.com/Ereborlabs/erebor-runtime/blob/6a25ba1b34dbaa0a553b1883058938683ce7aaab/crates/araphor-analysis_back/src/graph/installed.rs),
  [commit checks](https://github.com/Ereborlabs/erebor-runtime/blob/6a25ba1b34dbaa0a553b1883058938683ce7aaab/crates/araphor-analysis_back/src/graph/commit.rs),
  and graph proof/read code. Replace the scheduling in graph/live.rs and the
  input read in graph/input.rs. Keep Data graph storage and the three detector
  packages in their current crates.

### 10. Notification execution from Query events

- **Before:** The router created obligations, delivered notifications, retried
  failed delivery, escalated overdue work, and recorded acknowledgements.
- **Now:** Active Analysis retains authorization, obligation state, delivery,
  escalation, and acknowledgement operations and their domain tests. Control
  delegates finite operations to it. The old periodic router is removed.
  Query exposes notification rows and acknowledgement deadlines, but not every
  retry deadline. Automatic subscriptions remain unimplemented.
- **Required:** Data, route, permission, retry, and acknowledgement events must
  trigger the existing operations. Preserve restart and disclosure checks.
- **Reuse:** The [notification family](https://github.com/Ereborlabs/erebor-runtime/blob/6a25ba1b34dbaa0a553b1883058938683ce7aaab/crates/araphor-analysis_back/src/notification/mod.rs),
  including schedule, send, complete_attempt, and acknowledge. Replace the
  Control timer with Query events and exact deadlines. Keep delivery rules
  and durable notification records with their existing owners.

### 11. Runtime configuration through Control

- **Before:** Control passed configured Wasm and native options to the package
  runtime.
- **Now:** Query owns Package Runtime construction through its Limits value.
  Runtime Wasm and native quotas default to disabled. Control configuration
  must still be checked for complete propagation through this route.
- **Required:** Pass the configured Analysis options at first construction.
  Check them when the runtime is reused. Omitted quotas must stay disabled.
- **Reuse:** [AnalysisLimits](https://github.com/Ereborlabs/erebor-runtime/blob/6a25ba1b34dbaa0a553b1883058938683ce7aaab/crates/araphor-analysis_back/src/limits.rs)
  and new_with_limits in the
  [package owner](https://github.com/Ereborlabs/erebor-runtime/blob/6a25ba1b34dbaa0a553b1883058938683ce7aaab/crates/araphor-analysis_back/src/package/owner.rs).
  Correct the [Control configuration route](../../crates/mithril-control/src/service/packages.rs).

### 12. Data and Wasm cancellation without periodic checks

- **Before:** Data used repeated lock and interruption checks. Wasm used a
  periodic epoch tick to interrupt execution.
- **Now:** Package Runtime waits for cancellation, an exact deadline, or
  completion. The recurring Wasm epoch tick and compiler process are removed.
  Data lock and interruption waits still require their own audit.
- **Required:** Wait for lock release, cancellation, completion, or an actual
  deadline. Preserve interruption and reject cancelled output. Do not poll.
- **Reuse:** Compatible Wasm admission, cache, execution, and cleanup code.
  Replace EpochTicker in
  [Wasm execution](https://github.com/Ereborlabs/erebor-runtime/blob/6a25ba1b34dbaa0a553b1883058938683ce7aaab/crates/araphor-analysis_back/src/package/wasm/execution.rs)
  and the periodic waits in
  [Data read control](../../crates/araphor-data/src/analysis/read.rs).

### 13. Configurable quotas, disabled by default

- **Before:** Several limits were mandatory.
- **Now:** Wasm/native options, shared memory capacities, storage, Query bulk,
  SDK bulk and extraction limits have disabled defaults. Graph domain,
  retained-result and traversal resource defaults are now removed. All 159
  connected cases, formatting and strict Clippy pass. Evidence intake, coverage reports,
  Discovery batching, notification policy, legacy package literals and SDK
  descriptor boundaries still need their separate audit.
- **Required:** Make the remaining quotas configurable and disabled by
  default. Keep identity, type, format, and arithmetic validation.
- **Reuse:** Existing option handling and configured-limit checks. Change
  their configuration and disabled path. Do not add another resource owner.
  This includes [Query limits](../../crates/araphor-query/src/execution.rs),
  [SDK limits](../../crates/araphor-analysis-sdk/src/model.rs),
  Data extraction limits, and current runtime configured-limit checks. The
  former compiler address-space option returns Unsupported for in-process
  compilation.

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

## Native Graph adapter qualification

All 42 ordinary Graph cases and both explicit source-built native cases pass.
The six adapter cases use native Query preparation and execution. Wasm and
native calls run the actual detectors. SQL returns known complete values to
check transport and Graph validation. It does not implement the SQL detector.
The cases keep typed output, complete reasons and evidence, saved state,
configured pressure, exact replay and resource release assertions. Connected
test compilation, workspace formatting and strict connected Clippy pass.

No Back file retires. The old `graph/derive/adapter/mod.rs` also constructs
production Graph inputs and their source revision, window, time and coverage.
The current factories exist only in tests. Native transport does not replace
that responsibility. Keep the complete old file until a production owner and
its tests cover those rules. There are still 98 retired files and 110 unchanged
reference files. This delivery changes no production code. Read the
[qualification record](../../recovery/araphor-graph-adapter-qualification-20261020.json)
for exact source hashes, native artifacts and passing commands. The complete
migration and final Rust gate remain **Not done**.

## Extracted provenance count defaults

The native Data extraction owner no longer rejects more than 64 retained
results, 8192 witnesses or 256 contexts by default. Existing configured byte
and selected-key limits still apply. Exact revisions, tenant checks, origin
union and earliest witness expiry stay unchanged. The change removes 13
production lines and adds no owner. All 24 ordinary extraction cases and six
native Query input cases pass. The existing release history scan stays ignored.
Connected compilation, formatting and strict Clippy pass. Read the
[qualification record](../../recovery/araphor-extracted-provenance-20261020.json).

No Back file retires. All 110 remaining files match the baseline. The separate
legacy helper ceilings, complete migration and final Rust gate remain
**Not done**. The complete production count is +13,536 from the original
baseline. The required net reduction remains **Not done**.

## Public image fixture execution

`araphor image test PACKAGE --revision REVISION` tests all root-image fixtures.
Add `--fixture NAME` to test one fixture. Control checks current Test authority
and image trust. The existing Qualification owner executes the native Query
plan. Replies use the existing binary codec and preserve each fixture name and
pass result. Installation and testing start no Discovery. Testing changes no
managed output, state or progress.

The authority watch now spans reply encoding. A deterministic endpoint test
first returns success after late trust revocation. The corrected route returns
PermissionDenied. Both fixed five-minute request defaults are removed. Existing
configured Query timeouts, grant expiry and cancellation remain active.

All 53 distinct focused cases pass across the recorded runs. The cancellation
fixture first fails because its explicit 2 MiB input pool cannot hold the
current 2.04 MiB Wasm component. Its pool is now 4 MiB; all original assertions
stay unchanged and pass. The reader-exhaustion fixture now has an explicit
16-reader limit. Connected compilation, formatting and strict Clippy pass.
Read the [source and test record](../../recovery/araphor-public-fixture-execution-20261020.json).

This delivery adds 53 production lines and retires no Back file. All 110
remaining files match the baseline. Dependency-artifact fixture selection,
negative fixture time, complete migration and the final Rust gate remain
**Not done**.

## Native Graph baseline retirement

All 12 saved snapshots now pass through 36 actual native package calls and
production Graph validation. All three ordinary baseline cases also pass.
The complete golden files stay unchanged. The shared test normalizer changes
only the removed resource limits and checks the unchanged 300-second horizon.
Connected compilation, formatting and strict Clippy pass.

Only the old baseline test and three duplicate JSON files retire. This removes
no production code. There are now 102 retired files and 106 unchanged reference
files. The full archive retains all 208 originals. Read the
[retirement record](../../recovery/araphor-native-graph-baseline-retirement-20261020.json).
Keep the production adapter until its input and source-metadata replacement
passes qualification. Complete migration and the final Rust gate remain
**Not done**.

## Finite saved-output input replacement

Native definitions now read exact saved package datasets through registered
table aliases and the existing source capture. They keep source identity,
original evidence, trace checks and shared Arrow buffer charges. All 234
focused cases pass. The registration-order and narrowed-projection regressions
first fail, then pass after correction. Read the
[bounded result](araphor-analysis-migration.md#exact-saved-outputs-in-native-inputs).

No further reference file retires. There are still 102 retired files and 106
unchanged files. Managed alias publication, durable recovery, expired-input
Unknown coverage, model-wide expiry and witness deadlines remain open. The
production total is +14,333 from the original baseline. The required net
reduction and final Rust procedure remain **Not done**.

## Native image closure reuse

Four new native closure and current-authority cases and 27 mapped owner cases
pass. One complete old reuse test leaf retires. Explicit SQL declarations and
immutable OCI revisions replace its old active-root and mutable-version rules.
No managed Instance generation change is claimed. There are now 103 retired
files and 105 unchanged reference files. Production code does not decrease.
Read the [bounded result](araphor-analysis-migration.md#native-image-closure-reuse-retirement).
Freshness, installed snapshot, lifecycle and the complete migration remain
**Not done**. The final Rust procedure remains **Not done**.

## Saved input origin correction

A saved input keeps its original revision only when it has exactly one declared
origin. An unused CTE source still contributes to the derived input revision.
The actual regression first fails, then passes with all 45 focused cases.
Read the [bounded result](araphor-analysis-migration.md#saved-input-identity-includes-discarded-origins).
No reference file retires. The 105 remaining files and full archive are
unchanged. The complete migration and final Rust procedure remain **Not done**.


## Finite native Graph source status

The finite production Graph source and Discovery SDK bridge are qualified.
Five complete reference leaves retire; 108 files are retired and 100 unchanged
reference files remain. Read the
[bounded result](araphor-analysis-migration.md#finite-native-graph-source-retirement)
and [retirement record](../../recovery/araphor-native-graph-source-retirement-20261021.json).
This closes the prior test-only Graph input boundary for one finite refresh.
Automatic Graph advancement and recovery, Discovery live and replay ownership,
remaining quotas and polling, full migration, required net reduction, and the
final shared Rust procedure remain **Not done**.


## Finite Notification status

Read the [bounded Notification result](araphor-analysis-migration.md#finite-native-notification-retirement)
for the qualified five-leaf scope, exact qualification, custody, and counts.
Automatic Control consumption and failed-offer recovery, remaining limits,
complete migration, and the final shared Rust procedure remain **Not done**.

## Stopped authority renewal result

Explicit stopped-instance renewal is implemented at Data and Instance. Current
authority is separate from each attempt's captured grant. Native Graph plans
now receive fresh shared capture state for each execution. Finite Discovery
processing uses the existing Query subscription and joins before return.

The [review route](../guides/araphor-discovery-definition-review.md#stopped-authority-renewal-and-fresh-graph-execution)
and [checkpoint record](../../recovery/araphor-renewal-retirement-20261022.json)
state the exact behavior and focused proof. The complete old renewal/restart
test retires after its state, authority, receipt, and recovery rules pass.
Restart preserves state; an explicit rebuild reproduces the former fresh-state
case. There are 129 retired files and 79 unchanged reference files.

Result for this bounded change: **Done**. Update and rollback, saved-input
replay, automatic Graph publication, Discovery interval completion, complete
retirement, the required net reduction, and the final shared Rust procedure
remain **Not done**. Implementation continues within the current request.
