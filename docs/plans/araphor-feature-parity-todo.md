# Araphor Query and Analysis Feature Parity TODO

Compare the accepted features with the new Query and Analysis design. Each
item states the previous behavior, the current behavior, the required result,
and the old code that can be reused.

The user requires three TODOs first: 14, the OCI package image; 15, the
Discovery definition file; and 16, running Discovery instances. Complete them
before items 1-13. YAML definitions contain metadata and inline or referenced
SQL or PRQL. Package calls are expressions inside that program. The
[active package and job plan](araphor-package-jobs.md#first-deliverable-definition-files-and-running-instances)
records that priority. The current status table below applies to all 16 items.
The later implementation and retirement records replace the initial audit
status. Do not use the stopped drafts as completion evidence.

## Intended end state

The user authorizes the complete reference migration on 2026-10-19. The
[Analysis migration record](araphor-analysis-migration.md) maps all 95
production source files, root exports, required rules, and test families.
It is the source checklist for retirement. Keep the reference unchanged
until replacements pass qualification. Complete migration: **Not done**.
Reference removal: **Done**. All 208 original files are retired; zero remain.
Read the [final result](araphor-analysis-migration.md#complete-reference-retirement)
for the exact proof and archive custody. Earlier counts below describe their
original source states.

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

## Current status on 2026-10-24

The status audit checked `9243df7030e735fc3ae4ec48f94235406d7dfc8b`. Item 12
is complete in `98df70280`, with 33 passing focused checks. Its
[completion record](araphor-analysis-migration.md#scoped-native-interruption)
identifies the source and verification. Item 3 includes the history correction
in `8b8a119b7` and the metadata changes based on that commit, with 55 passing
focused checks. Its
[completion record](araphor-analysis-migration.md#graph-history-and-sdk-input-metadata)
identifies the owners and proof. Item 8 is complete in the changes based on
`a2f6cf800`, with 58 passing focused checks. Its
[completion record](araphor-analysis-migration.md#discovery-continuation-across-expired-input)
identifies the capture, native SQL and Data transaction owners. Item 7 is
complete in the changes based on `64f4a9d9c`, with 29 passing focused checks.
Its [completion record](araphor-analysis-migration.md#recorded-policy-preview-through-query)
identifies the Query result and Control policy owners. The other rows
retain the status audit.
`Done` means that the stated behavior has a current implementation and mapped
focused checks. It does not claim a new full-workspace CI result. `Not done`
identifies a specific remaining part of an otherwise implemented item.

| TODO | Result | Current behavior or remaining work |
| --- | --- | --- |
| 14. OCI package image | Done | Separate OCI owner, typed contracts, exact dependencies and saved-state contract. Installation starts no Discovery. Package size and SDK quotas are removed; the wider quota audit remains in item 13. |
| 15. Discovery definition file | Done | YAML metadata with SQL, PRQL, or a package call. Referenced files are captured at admission. All forms use native Query planning and execution. Admission starts no Discovery. |
| 16. Running Discovery instances | Done | Public lifecycle commands, independent instances, shared Query subscriptions, atomic state/progress, stop, current authority and restart recovery are implemented. |
| 1. Package operations and saved state | Done | Image and Instance owners provide install, inspect, qualification, execution, update, rollback, removal and retained replay. SQL, Wasm and native calls preserve state and exact retry rules. |
| 2. Installed package calls in SQL | Done | Native logical and physical package-call extensions execute SQL, Wasm and native exports with captured Arrow inputs, parameters and prior state. |
| 3. Graph history and SDK input metadata | Done | Traversal request `result_ids` select permitted historical versions. SDK inputs retain saved graph coverage, missing-data reasons and traversal boundaries from the same captured revision, including empty graphs. |
| 4. Discovery window completion and evidence | Done | Query window events seal profiles. Data retains the captured evidence. A later interval remains separate. |
| 5. Exact versions for each profile | Done | Retained profiles bind exact input, context, definition and package versions. A code change closes the old interval. |
| 6. Finite execution, refresh, reads and replay | Done | Current Analysis and Instance operations provide finite work, repair, authorized reads and replay from retained inputs. Missing frozen inputs or code return an explicit unavailable result. |
| 7. Context, groups and baseline comparison | Done | Native context, grouping and baseline operations remain in Analysis. Control consumes the validated installed Query call result for static policy preview. |
| 8. Discovery after an expired data range | Done | Native SQL processes captured retained records and exact expiry proofs. Data commits proven gaps, profile and progress together. Prefix, interior, multiple and expired-tail cases pass; unexplained holes and out-of-cut expiry cannot advance progress. |
| 9. Graph and detector execution from Query events | Done | Native source subscriptions use the shared Host for detector execution, graph publication, expiry and recovery. Control starts this path independently of Discovery. |
| 10. Notification execution from Query events | Done | Native subscriptions and the shared Host drive delivery, retries, ACK deadlines, restart and current permission checks. |
| 11. Runtime configuration through Control | Done | Control passes configured Query and package runtime limits at construction and rejects reuse with different limits. Runtime quotas default to disabled. |
| 12. Data and Wasm cancellation without periodic checks | Done | Wasm and Data lock waits use events and exact deadlines. Data sends one native interrupt at expiry and waits for an event. A native interrupt scope preserves cancellation across statement resets. |
| 13. Configurable quotas, disabled by default | Not done | Native capture removes the forced backend settings and unsupported map-capacity metadata. Node removes the diagnostic ACK ceiling through the existing validated upload path. All seven affected checks pass. The physical latency gate fails two pairs; performance qualification remains Not done. |

Result: **15 Done; 1 Not done**. The remaining item is **13**.
The separate 6,000-line production Rust reduction target remains unmet. The
[current retained-source audit](araphor-component-redesign.md#current-source-audit-on-2026-10-24)
adds 20,133 Araphor lines against the original baseline. Reference removal is
complete.

The status and `Now` text in each numbered item below describe this source.
Earlier qualification paragraphs retain their original source and result.
Historical `Reuse` links identify reference code; they do not authorize
restoration of removed execution owners.

## Historical implementation records

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
file. Image content, installation, inspection, definition admission, native
package-call execution and running instances are **Done** for their stated
contracts. The [migration record](araphor-analysis-migration.md) retains the
focused results and the separate work that remains.

### 14. OCI package image

**Status: Done.** The image and call contracts are implemented. The wider
operational quota audit remains in item 13.

- **Before:** A package contained reusable exports. Installation also activated
  supported exports.
- **Now:** `araphor-package` owns the existing OCI codec and static package
  contracts. The `image install` request retains an image without activation.
  Data owns the durable image root and its exact dependency closure. The old
  activation-oriented `package` commands are removed. Query executes the exact
  declared SQL, Wasm or native implementation. Instance owns bindings, grants,
  progress and saved state. The
  [final focused result](araphor-analysis-migration.md#complete-reference-retirement)
  includes image round trips, uncapped closures, native artifact checks and
  managed execution.
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
- [x] Keep input bindings, query windows, current grants, progress, and
  instance state at the call or running-instance boundary. Two instances can
  use the same image with different bindings and separate saved state.
- [x] Pass the selected Arrow inputs, prior state, parameters, and captured
  evaluation context to the package. Validate returned datasets, proposed
  state, reasons, and evidence before Data commits them.
- [x] Preserve the exact artifact revision used by each call. Installation,
  inspection, or a later image revision must not silently replace the code
  of an already admitted instance.
- [x] Add no mandatory package-size cap. SDK package quotas are removed.
  Separate engine quotas must be configurable and disabled by default, as
  recorded in item 13. Preserve type, identity, format and arithmetic checks.

Image content, installation, and inspection: **Done**. The affected checks
pass. Read the
[image review](../guides/araphor-binary-package-storage-review.md#image-installation-without-execution)
for the source route. The image delivery added no execution engine,
subscription, or timer. The current native execution and its qualification
are in the [migration record](araphor-analysis-migration.md). Managed state
and the instance requirements above are implemented through item 16.

The image delivery adds 615 production Rust lines from `41815177`. The count
excludes tests, comments, documents, and blank lines. Moved code adds zero to
the net count. The complete redesign adds 4,101 lines from `7b7b407a`; another
10,101 must be removed to meet the 6,000-line reduction target. Complete
redesign: **Not done**. The count record is `/tmp/araphor-image-count1.json`.

### 15. Discovery definition file (Compose file)

**Status: Done.**

- **Before:** Control configuration enabled a fixed Discovery implementation.
  Packages also carried input declarations.
- **Now:** `araphor-discovery-definition` owns the YAML file, source capture,
  PRQL compilation, and admitted snapshot. Control admits and inspects that
  snapshot. SQL, PRQL and package calls reach the native Query pipeline.
  [File capture](../../crates/araphor-discovery-definition/src/file.rs) reads a
  referenced file once at admission. Later file changes do not change the
  admitted definition. Starting work is a separate Instance operation.
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

**Status: Done.** The stated lifecycle, subscription and recovery contracts
have current implementations and mapped focused checks.

- **Before:** Control ran fixed Discovery work. The retained package owner
  supervised scoped activations and saved their results and state.
- **Now:** [Instance Host](../../crates/araphor-analysis/src/instance/host.rs)
  owns independent running instances and a native `FuturesUnordered`
  collection. Control and CLI expose admission, Start, Stop, Run, Renew,
  Update, Rollback, removal, inspection, history and retained reads.
  Execution consumes actual Query subscription captures and window events.
  Data commits complete outputs, guarded state, evidence and progress
  atomically. Stop and authority loss cancel and join workers. Restart uses
  retained definitions, exact image pins, saved state and native frontiers.
  [Host tests](../../crates/araphor-analysis/src/instance/host/tests.rs) check
  execution without an observer, independent members, authority and restore.
  [Control lifecycle tests](../../crates/mithril-control/src/client_grpc/tests/packages/lifecycle.rs)
  check the public operations. Read the
  [lifecycle result](araphor-analysis-migration.md#package-lifecycle-and-retained-output-test-retirement)
  and [final continuation result](araphor-analysis-migration.md#complete-reference-retirement).
- **Required:** Create managed instances from admitted definitions. Each
  instance has its own lifetime, selected inputs, progress, and saved state.
- **Reuse:** Query subscriptions and their native stream collection, current
  permission checks, compatible installed evaluation, and Data commit/recovery
  operations. Replace fixed Control selection and old scheduling/input seams.
  Do not copy run_clock, source sweeps, or separate raw readers.

Recorded specifications:

The recorded lifecycle and continuation checks cover the requirements below.
These checks use the current production owners. Complete migration, item 12's
Data interrupt loop and the overall reduction target remain separate work.
No new full-workspace CI result is claimed.

- [x] Start, inspect, and stop each instance independently. Keep its identity
  separate from the image and reusable definition. Support multiple instances
  that use the same image.
- [x] Run until explicitly stopped, subject to current permission,
  cancellation, and execution failure. Add no default lifetime cutoff.
  A client disconnect must not stop the managed instance.
- [x] Drive all execution from actual Query subscription batches and declared
  window events. Use the same native SQL pipeline for every program form.
  Add no polling in the owner or client and no private Discovery clock.
- [x] Insert and remove subscription streams on demand through a native
  stream collection such as SelectAll/FuturesUnordered. Query owns window
  events and exact deadlines; a timer must not poll for changes.
- [x] Give each instance separate progress and saved state. Execute a logical
  call against its complete selected inputs; Arrow batch boundaries must not
  change the call's meaning.
- [x] Bind inputs and declared SQL reads to the captured Data view and
  evaluation time. New input remains pending while that call uses its
  captured view.
- [x] Use the existing Data commit checks to keep outputs, proposed state,
  evidence references, and consumed progress consistent. Failed or cancelled
  work must not advance committed state or progress.
- [x] Check current permission before execution and commit. Stopping an
  instance or revoking its grant must cancel work and reject stale completion.
  Release its streams, buffers, and runtime handles.
- [x] Restore active instances after restart from their admitted definition,
  exact package revisions, committed state, and progress. Recheck current
  permission. Missing retained input must produce an explicit incomplete or
  unavailable result.
- [x] Stopping one instance must leave other instances and referenced package
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

## Historical qualification at the initial audit

The following two paragraphs describe the initial audit. Current status is
in the table above. Reference retirement is complete; the five specific open
items remain identified there.

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

**Status: Done.**

- **Before:** Install, inspect, test, run, update, roll back, and remove SQL,
  Wasm, and native packages. Pass parameters, dependencies, and saved state.
  Return named outputs, reasons, and evidence.
- **Now:** Image, qualification and Instance owners provide the operations.
  [Host request dispatch](../../crates/araphor-analysis/src/instance/host/request.rs)
  handles admission, Start, Run, Stop, Renew, Update, Rollback, removal and
  recreation. Native Query supplies Arrow inputs, parameters and prior state.
  Data preserves atomic publication and exact retry receipts.
  [Version tests](../../crates/araphor-analysis/src/instance/tests/version.rs)
  and [checkpoint tests](../../crates/araphor-analysis/src/instance/tests/checkpoint.rs)
  cover failed updates, rollback, state and reopen. Read the
  [recorded qualification](araphor-analysis-migration.md#package-lifecycle-and-retained-output-test-retirement).
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

**Status: Done.**

- **Before:** The package owner selected and called the installed SQL, Wasm,
  or native implementation.
- **Now:** Native Query admits exact installed export calls.
  [Package physical execution](../../crates/araphor-query/src/definition/physical.rs)
  runs SQL, Wasm and native implementations with captured inputs, parameters
  and prior state. Data commits complete validated returns and progress.
  [Execution tests](../../crates/araphor-query/src/definition/tests/execution.rs)
  cover the targets, separate call state, exact pins and boundary failures.
  Managed restart uses the same Host and retained call manifest as item 16.
- **Required:** Let a SQL query call an installed export and use its declared
  outputs. Use the same native planning and execution route. Preserve
  parameters, saved state, permissions, and the exact artifact revision.
- **Reuse:** [InstalledAnalysis](https://github.com/Ereborlabs/erebor-runtime/blob/6a25ba1b34dbaa0a553b1883058938683ce7aaab/crates/araphor-analysis_back/src/package/installed.rs),
  [target dispatch](https://github.com/Ereborlabs/erebor-runtime/blob/6a25ba1b34dbaa0a553b1883058938683ce7aaab/crates/araphor-analysis_back/src/package/execution.rs),
  and compatible native/Wasm runtime code. Connect these at the native Query
  execution boundary. Do not create another package lifecycle.

### 3. Graph history and SDK input metadata

**Status: Done.** Historical selection, request version pins, graph input
execution and SDK metadata pass 55 focused checks.

- **Before:** A traversal could select an exact old graph version. SDK inputs
  included graph completeness, missing-data reasons, and traversal boundaries.
- **Now:** Native Query supplies graph datasets and exact historical selection
  through `AnalysisSelectionV1.graphs`. Data's
  [selection resolver](../../crates/araphor-data/src/analysis/extraction.rs)
  applies nonempty request `result_ids` before it expands current graph heads.
  Explicit selections cannot widen. Existing tenant, source, binding and
  configured allocation checks remain. The
  [history test](../../crates/araphor-analysis/src/graph/tests/traversal/recovery.rs)
  now supplies the version IDs only in the request. The
  [SDK receipt](../../crates/araphor-query/src/inputs/receipt.rs) uses saved
  coverage for graph inputs and retains source and inherited package coverage
  for other inputs. A known graph gap remains `Gapped`. A traversal boundary
  adds `GRAPH_HOP_BOUNDARY` and makes otherwise complete coverage `Unknown`.
  Empty selected graphs retain their coverage and Arrow schemas. Native Query
  supplies all inputs from one captured revision. The
  [installed Wasm checks](../../crates/araphor-analysis/src/graph/tests/traversal/metadata.rs)
  compare the guest's rows, schemas, revisions and coverage with those inputs.
  Existing traversal, permission, history, buffer and allocation checks pass.
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

**Status: Done.**

- **Before:** Discovery closed an interval, saved its final profile, and
  retained the selected input evidence. Its host loop decided when to close.
- **Now:** [Managed publication](../../crates/araphor-analysis/src/discovery/publication/managed.rs)
  reads Query's completed-window events and seals the profile. Data's
  [profile transaction](../../crates/araphor-data/src/analysis/progress/profile.rs)
  retains captured witnesses, including closure without new input.
  `managed_window_frontier` in the
  [managed tests](../../crates/araphor-analysis/src/discovery/tests/managed.rs)
  checks the interval, seal, consumed cursor and cancellation. It passes in
  the [final focused result](araphor-analysis-migration.md#complete-reference-retirement).
- **Required:** Query must report the declared window's completion. Analysis
  must then save the final profile and its evidence. Later data must enter the
  next interval. No host clock loop is permitted.
- **Reuse:** The profile construction, evidence selection, and closing rules
  in [old Discovery live code](https://github.com/Ereborlabs/erebor-runtime/blob/6a25ba1b34dbaa0a553b1883058938683ce7aaab/crates/araphor-analysis_back/src/discovery/live.rs).
  Reuse Data's existing profile commits. Replace the old scheduling and raw
  input reads with Query subscription input and window events.

### 5. Exact input and package versions for each profile

**Status: Done.**

- **Before:** A profile recorded its input range, context facts, and installed
  package versions. A package change could start a new interval.
- **Now:** Managed publication retains the exact selected OCI bundle,
  captured source contexts and managed result. Data resolves the
  [retained profile association](../../crates/araphor-data/src/analysis/progress/profile/replay.rs)
  to its exact definition and call. A code change seals the current interval
  before the next interval starts. The
  [managed tests](../../crates/araphor-analysis/src/discovery/tests/managed.rs)
  check immutable versions, exact evidence and code changes. The
  [replay tests](../../crates/araphor-analysis/src/discovery/tests/replay.rs)
  check original time, seed, producer and captured inputs.
- **Required:** Record the exact data, facts, and code used for each profile.
  A package change must not merge results from incompatible implementations
  into the same interval.
- **Reuse:** [Installed reference checks](https://github.com/Ereborlabs/erebor-runtime/blob/6a25ba1b34dbaa0a553b1883058938683ce7aaab/crates/araphor-analysis_back/src/discovery/installed.rs)
  and source_context in
  [old Discovery live code](https://github.com/Ereborlabs/erebor-runtime/blob/6a25ba1b34dbaa0a553b1883058938683ce7aaab/crates/araphor-analysis_back/src/discovery/live.rs).
  Adapt their recorded description to the selected SQL export. Keep context
  and result storage in Data.

### 6. Finite execution, refresh, profile reads, and replay

**Status: Done.**

- **Before:** Callers could process available input, refresh a profile, read
  the profile, and reproduce it from its recorded data and code.
- **Now:** `DiscoveryOwner::profile` supplies authorized profile reads.
  Finite work uses the shared Instance operation. Historical repair uses
  captured SQL and managed publication. The
  [replay owner](../../crates/araphor-analysis/src/discovery/replay.rs) executes
  the exact retained inputs and code through the native Instance path.
  Missing frozen inputs or packages return an explicit unavailable result.
  Four [replay tests](../../crates/araphor-analysis/src/discovery/tests/replay.rs)
  and `sealed_repair_keeps_head` in the
  [managed tests](../../crates/araphor-analysis/src/discovery/tests/managed.rs)
  cover replay, repair, original heads, cancellation and reopen. The latter
  passes in the [final focused result](araphor-analysis-migration.md#complete-reference-retirement).
- **Required:** Supply these operations through new Analysis. All execution
  and replay input must come from Query subscriptions. Missing historical
  input or code must produce an explicit unavailable result.
- **Reuse:** profile and refresh validation from
  [old live code](https://github.com/Ereborlabs/erebor-runtime/blob/6a25ba1b34dbaa0a553b1883058938683ce7aaab/crates/araphor-analysis_back/src/discovery/live.rs),
  plus [replay validation and input capture](https://github.com/Ereborlabs/erebor-runtime/blob/6a25ba1b34dbaa0a553b1883058938683ce7aaab/crates/araphor-analysis_back/src/discovery/replay.rs).
  The historical replay reader used a finite Query subscription. Reuse that
  boundary, not the old process loop.

### 7. Context selection, display groups, and baseline comparison

**Status: Done.** Control consumes the current Query result through the
existing Analysis output adapter.

- **Before:** Callers could import and select permitted context, group behavior
  records for display, and compare current behavior with a reviewed baseline.
- **Now:** Active Analysis supplies authorized context import and native
  [context selection](../../crates/araphor-analysis/src/context/selection.rs).
  Native SQL and the [output adapter](../../crates/araphor-analysis/src/discovery/output.rs)
  supply grouping and reviewed-baseline comparison. Their finite assertions
  are retained. Control's public
  [recorded-preview constructor](../../crates/mithril-control/src/discovery/preview.rs)
  accepts the manifest, candidate policy, opaque package call and Query result.
  The existing Analysis adapter checks binding, tenant, source identity and
  typed output. Control retains its compiler and simulator. Preview supports
  exact File and Exec keys and rejects consuming exceptions. Every simulation
  reports `NotAttempted`. No new execution or service owner is added.
- **Required:** Preserve their results and permission checks in new Analysis.
  Connect Control preview and the existing callers to that path.
- **Reuse:** [Context policy](https://github.com/Ereborlabs/erebor-runtime/blob/6a25ba1b34dbaa0a553b1883058938683ce7aaab/crates/araphor-analysis_back/src/discovery/context.rs),
  [SDK context checks](https://github.com/Ereborlabs/erebor-runtime/blob/6a25ba1b34dbaa0a553b1883058938683ce7aaab/crates/araphor-analysis_back/src/discovery/sdk/context.rs),
  [snapshot/group adapter](https://github.com/Ereborlabs/erebor-runtime/blob/6a25ba1b34dbaa0a553b1883058938683ce7aaab/crates/araphor-analysis_back/src/discovery/sdk/snapshot.rs),
  and [comparison adapter](https://github.com/Ereborlabs/erebor-runtime/blob/6a25ba1b34dbaa0a553b1883058938683ce7aaab/crates/araphor-analysis_back/src/discovery/sdk/compare.rs).
  Keep shared computations in their existing package crates. Use existing
  native SQL computation where it already supplies the operation.

### 8. Discovery after an expired data range

**Status: Done.**

- **Before:** Optional Discovery could record an expired range and continue
  with later retained records.
- **Now:** Query captures selected rows, prior state and expiry metadata once.
  Native SQL matches and clips each expiry proof and processes all selected
  retained ranges in one evaluation. Data checks the expected position,
  current head, exact expiry tuples and retained-record count. Its existing
  transaction commits the profile, processor gaps and progress together.
  Cumulative counts, bytes, coverage, saved gaps and sealed intervals remain
  correct. A captured scope field permits expiry-only tail progress only for
  an unbounded input. Bounded cuts can account for expiry within the selected
  endpoint; rows beyond that endpoint remain unconsumed. An unexplained hole
  or retained row omitted within the claimed advance still fails. Stale
  captures and required processors cannot use this skip path. The
  [focused result](araphor-analysis-migration.md#discovery-continuation-across-expired-input)
  records 58 passing checks, including real retention and restart.
- **Required:** Process each retained range and record each exact missing
  range. Preserve cumulative counts and completeness. Reject a stale resume.
- **Reuse:** Data's [optional processor resume transaction](../../crates/araphor-data/src/analysis/progress.rs)
  and profile publication share the processor-gap insertion. The new path
  uses captured coverage, native SQL and the existing guarded profile
  transaction. It adds no source sweep, second reader or polling loop.

### 9. Graph and detector execution from Query events

**Status: Done.**

- **Before:** Graph processing selected source windows, called installed
  detectors, checked proof, and committed graph and finding results.
- **Now:** [Graph source subscriptions](../../crates/araphor-analysis/src/graph/feed.rs)
  use `FuturesUnordered` and the shared Host for Evaluate and Expire instances.
  [Control](../../crates/mithril-control/src/service/packages/graph.rs) prepares
  pinned detector calls in native SQL and starts Graph independently of
  Discovery. Managed checks cover notices, versions, expiry, restart,
  replacement, grants and failure isolation. The final source-recovery check
  passes in the [retirement result](araphor-analysis-migration.md#complete-reference-retirement).
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

**Status: Done.**

- **Before:** The router created obligations, delivered notifications, retried
  failed delivery, escalated overdue work, and recorded acknowledgements.
- **Now:** [Native Notification subscriptions](../../crates/araphor-analysis/src/instance/host/notification.rs)
  use the shared Host and DataFusion publication sink. Data supplies retry,
  ACK and grant-expiry events. Pending attempts retain the original subject
  and route across reopen. The
  [focused result](araphor-analysis-migration.md#shared-notification-execution-and-capacity-release)
  records nine Analysis and six Control passes for deadlines, cancellation,
  restart, permission, startup and disabled configuration. Notification uses
  the same Host source-recovery wait as package and Graph members.
- **Required:** Data, route, permission, retry, and acknowledgement events must
  trigger the existing operations. Preserve restart and disclosure checks.
- **Reuse:** The [notification family](https://github.com/Ereborlabs/erebor-runtime/blob/6a25ba1b34dbaa0a553b1883058938683ce7aaab/crates/araphor-analysis_back/src/notification/mod.rs),
  including schedule, send, complete_attempt, and acknowledge. Replace the
  Control timer with Query events and exact deadlines. Keep delivery rules
  and durable notification records with their existing owners.

### 11. Runtime configuration through Control

**Status: Done.**

- **Before:** Control passed configured Wasm and native options to the package
  runtime.
- **Now:** [Control configuration](../../crates/mithril-control/src/config.rs)
  passes Query limits, including package runtime options, to the first Engine
  construction. The [package owner](../../crates/mithril-control/src/service/packages.rs)
  rejects reuse with different limits. Query passes `limits.package` to
  Runtime. Focused tests cover disabled defaults, explicit Wasm fuel and
  unsupported native hard limits without disabling other targets.
- **Required:** Pass the configured Analysis options at first construction.
  Check them when the runtime is reused. Omitted quotas must stay disabled.
- **Reuse:** [AnalysisLimits](https://github.com/Ereborlabs/erebor-runtime/blob/6a25ba1b34dbaa0a553b1883058938683ce7aaab/crates/araphor-analysis_back/src/limits.rs)
  and new_with_limits in the
  [package owner](https://github.com/Ereborlabs/erebor-runtime/blob/6a25ba1b34dbaa0a553b1883058938683ce7aaab/crates/araphor-analysis_back/src/package/owner.rs).
  Correct the [Control configuration route](../../crates/mithril-control/src/service/packages.rs).

### 12. Data and Wasm cancellation without periodic checks

**Status: Done.** Wasm interruption, Data lock waits and native deadlines use
events. The native deadline worker sends one interrupt at expiry.

- **Before:** Data used repeated lock and interruption checks. Wasm used a
  periodic epoch tick to interrupt execution.
- **Now:** [Wasm execution](../../crates/araphor-package-runtime/src/wasm/execution.rs)
  waits for cancellation, an exact deadline or completion. Data lock waits
  register unlock and cancellation notifications and use an exact deadline.
  The [read monitor](../../crates/araphor-data/src/analysis/read.rs) reuses its
  worker, sends one interrupt at expiry and waits for a notification. A native
  [interrupt scope](../../vendor/README.md) keeps cancellation active across
  statement resets. Data releases both interrupt sources before it ends that
  scope and rolls back. All 21 Data, six Query and six Runtime focused checks
  pass. Cancellation, deadline enforcement and reader cleanup remain intact.
- **Required:** Wait for lock release, cancellation, completion, or an actual
  deadline. Preserve interruption and reject cancelled output. Do not poll.
- **Reuse:** Compatible Wasm admission, cache, execution, and cleanup code.
  Replace EpochTicker in
  [Wasm execution](https://github.com/Ereborlabs/erebor-runtime/blob/6a25ba1b34dbaa0a553b1883058938683ce7aaab/crates/araphor-analysis_back/src/package/wasm/execution.rs)
  and the periodic waits in
  [Data read control](../../crates/araphor-data/src/analysis/read.rs).

### 13. Configurable quotas, disabled by default

**Status: Not done.** Package quota removal is complete. Wider operational
quota defaults and resource boundaries still need changes or qualification.

- **Before:** Several limits were mandatory.
- **Now:** SDK package quotas are removed. Query, runtime, storage, extraction
  and shared-capacity options have disabled defaults. Graph and retained-result
  resource defaults are removed. The
  [package quota result](araphor-analysis-migration.md#package-quota-removal)
  retains the 143 passing focused checks. Control's
  [evidence admission](../../crates/mithril-control/src/config.rs) now defaults
  to no total or per-node gate. Configured positive counts use native Tokio
  semaphores. Known-node membership remains required when both gates are
  disabled. The [focused result](araphor-analysis-migration.md#optional-evidence-admission)
  records the completed admission change. The
  [native backend result](araphor-analysis-migration.md#native-backend-defaults)
  removes the forced native settings. Its latency qualification fails two
  pairs. The [Node acknowledgement result](araphor-analysis-migration.md#diagnostic-acknowledgement-sequences)
  removes the fixed 4,096-sequence ceiling through the existing upload method.
  All seven affected checks pass. Physical qualification remains open.
  Preserve identity, format, type and
  arithmetic validation; do not remove domain rules as quota cleanup.
- **Required:** Keep the package contract free of row, batch, byte, and
  checkpoint quotas. Only the time window can be set outside SQL. Keep
  separate engine quotas configurable and disabled by default. Keep identity,
  type, format, and arithmetic validation.
- **Reuse:** Existing option handling and configured-limit checks. Change
  their configuration and disabled path. Do not add another resource owner.
  This includes [Query limits](../../crates/araphor-query/src/execution.rs),
  [SDK schemas](../../crates/araphor-analysis-sdk/src/model.rs),
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


## Shared Host and retirement qualification

The shared Host is implemented for Control, Graph, and Discovery. Control cold
startup passes with both Graph sources. Image uninstall, instance removal,
explicit recreation, exact historical scope, and SQL/Wasm/native replay pass
focused checks. There are 132 retired reference files and 76 unchanged files.

The later [five-file retirement](araphor-analysis-migration.md#discovery-replay-and-package-commit-retirement)
replaces Discovery image lookup and replay, Graph chunk splitting, installed
image history, and the installed commit guard. All 65 distinct focused checks
pass on source state 290. The removal deletes 737 nonblank production Rust
lines. There are now 137 retired files and 71 unchanged files. Public lifecycle,
selected SQL/PRQL output reads, admission failure status, complete window
recovery, Notification supervision, and native interrupt cancellation remain
open. Complete retirement and final shared Rust CI are **Not done**.
The [migration record](araphor-analysis-migration.md#native-lifecycle-and-source-qualification)
retains exact passing and failing checks. These results do not close item 16.

The source audit finds missing public first admission, Start, finite Run, Stop,
Renew, Update, and Rollback routes. Existing native library APIs must own them.
Public reads must also support the selected root output of a SQL or PRQL job
with no package calls. Keep the old owner and Inspect leaves until these
replacement routes pass their checks. Automatic Notification supervision,
complete window recovery, remaining native polling, complete retirement,
required code reduction, and final Rust CI remain **Not done**.

### Saved SQL and PRQL result qualification

Result: **Done** for exact saved root-output reads and local queries. The
existing Data reader returns package-call results or selected SQL and PRQL
results. It checks saved call bindings, generation schema, and scope before
payload disclosure. Control uses the existing binary replies. All 133 focused
Data, Analysis, Query, and Control checks pass on source state 293.
The [qualification record](../../recovery/araphor-selected-output-qualification-20261022.json)
retains the commands, source hashes, and result hashes. No reference file
retires for this change alone. Public lifecycle, admission failures, complete
window recovery, Notification supervision, remaining native polling, and final
shared Rust CI remain **Not done**.

### Shared Notification continuation qualification

- **Before:** Control exposed finite routing and delivery. Automatic
  Notification supervision was not qualified.
- **Now:** Control uses the shared Instance Host and native SQL publication
  sink. Nine Analysis cases and six Control cases pass on source state 302.
  They cover pending-attempt reopen, exact retry and ACK deadlines, item-error
  isolation, cancellation, startup, disabled configuration, and count options.
- **Required:** Complete recovery after source capture fails. Preserve the
  unchanged failed cut until a relevant Query event permits another attempt.
- **Reuse:** Keep the finite Router, durable attempts, existing Query Progress,
  and shared Host. Do not add another clock, task collection, or status store.

The [bounded result](araphor-analysis-migration.md#shared-notification-execution-and-capacity-release)
also records capacity-release recovery. This work removes no further reference
file and does not close the running-instance item or final Rust CI.


### Native preparation and execution replacement

- **Before:** The old package owner prepared inputs, selected state, dispatched
  execution, and returned installed results through separate wrappers.
- **Now:** Query subscriptions and native physical package calls own execution.
  Data owns atomic state and result publication. Seven complete reference files
  retire after 61 focused checks. There are 159 retired files and 49 unchanged
  reference files. The net production reduction for this change is 532 lines.
- **Required:** Complete source-failure and durable window recovery, then qualify
  the remaining mixed product and lifecycle rules before their files retire.
- **Reuse:** Keep native Query subscriptions, physical package calls, Runtime,
  the shared Host, and Data transactions. Add no package clock or polling loop.

Read the [exact result and evidence](araphor-analysis-migration.md#native-preparation-and-installed-execution-retirement).
This result does not close the running-instance item or complete retirement.


### Package lifecycle and retained-output test retirement

- **Before:** Eleven reference test files checked the separate package owner.
- **Now:** Their assertions have passing checks at the shared Host, Query,
  Runtime, and Data owners. Exact source and archive records cover 83 selectors.
  There are 170 retired files and 38 unchanged reference files.
- **Required:** Complete pre-admission stale-source recovery, Graph feed
  qualification, and native Discovery SQL and managed-window qualification
  before removing those owners.
- **Reuse:** Keep the shared Host and native Query subscription. Cold renewal
  checks exact image bytes and saved state through the existing admission route.

Read the [result and evidence](araphor-analysis-migration.md#package-lifecycle-and-retained-output-test-retirement).
This removal deletes test duplication. It does not claim a production reduction
or complete retirement.


### Qualified reference leaf retirement

Nineteen more complete reference files retire. There are now 189 retired files
and 19 unchanged reference files. This batch removes 623 nonblank production
Rust lines and 2,255 nonblank test lines. The
[qualification record](../../recovery/araphor-qualified-leaves-retirement-20261023.json)
contains the archive hash and exact proof. No whole-migration net reduction is
claimed.

The old deadline tests begin with successful captures. A deadline after the
first failed capture is not an old parity gate. SourceRecovery keeps attached
Progress deadlines and scoped dependencies with 24 fewer production lines;
all five existing recovery checks pass on source state 350. The old
`admission_rejects_domain_execution` case checks inert installation, not
Discovery conversion. Read the [bounded result](araphor-analysis-migration.md#qualified-reference-leaf-retirement).
Pre-admission stale-source recovery, Graph feed qualification, native Discovery
SQL and managed-window qualification, complete retirement, and final Rust CI
remain **Not done**.


### Joined known-rollback cleanup

Finite Run and Follow now use the existing Data terminal owner after native
execution joins. The consolidation removes 19 net nonblank production Rust
lines. It adds no API. Four Analysis checks and three Data checks pass on source
state 359. These checks retain caller-cancelled pending claims, exact live-claim
authority, uncertain-commit recovery, saved receipts, and commit crash behavior.

The complete Discovery historical-repair case still fails later with `Elapsed`.
Graph failed-feed recovery still fails at cursor 258. No further reference file
retires: 189 are retired and 19 remain unchanged. Complete retirement and the
whole-migration reduction remain **Not done**. Read the
[bounded result and records](araphor-analysis-migration.md#joined-cleanup-after-known-rollback).


### Native continuation and Graph/package retirement

- **Before:** A committed managed Replace cut could request more work but
  wait for another source notice. The final Graph feed regression still failed.
- **Now:** Query uses the existing publication acknowledgement and `exhausted`
  state to continue through the same native subscription. All 15 managed Query
  checks and the actual Wasm Graph recovery check pass on source state 360.
  Ten complete reference files retire. There are 199 retired files and nine
  unchanged reference files.
- **Required:** Qualify the remaining Discovery historical-repair case before
  its complete owner and fixture files retire. Its current check still fails
  at the second wait, with an empty context selection in the fixture grant.
- **Reuse:** Keep Query capture and physical execution, the shared Instance
  Host, and Data atomic publication. Finite Run retains one subscription step.

Read the [bounded result](araphor-analysis-migration.md#native-publication-continuation-and-graphpackage-retirement)
and [retirement record](../../recovery/araphor-graph-package-retirement-20261023.json).
Complete retirement and the required overall production reduction remain
**Not done**. No whole-migration production total is claimed.


### Complete reference retirement

The final nine Discovery and facade files retire after the mapped native
checks and archive verification. All 208 original files are retired; zero
remain. The [final record](../../recovery/araphor-analysis-back-retirement-20261023.json) gives the
source identity, exact proof, original hashes and deletion check.

The committed source checkpoint already proves both Discovery managed checks
on source state 367. Its Graph group has five individual passes and one
same-frontier failure; these remain historical records. The exact current
Graph check passes in `graph-recovery369`. Read the
[owner route](../guides/araphor-discovery-definition-review.md#saved-native-continuation-and-current-proof)
and [retirement result](araphor-analysis-migration.md#complete-reference-retirement).
Complete migration, `DataReadMonitor` removal and the required 6,000-line net
production reduction remain **Not done**. No full-workspace pass or
whole-migration production total is claimed.


## Required native scope on 2026-10-25

Result: **Done** for the required native replacement. The five required baseline plans map
to the current SDK, Package, Query, Analysis, Runtime, and Data owners. Read the
[required native result](araphor-component-redesign.md#required-native-redesign-result)
and [Graph retirement proof](araphor-analysis-migration.md#one-managed-graph-execution-route).
The dated table above keeps its earlier source and qualification boundary.

Running-instance recovery includes interrupted current-generation native
attempts after exclusive store reopen. The duplicate direct Graph executor
is removed after its assertion transfer. All 21 final cases pass. The 17
prerequisite cases pass on their separately recorded source.

Quota configuration and disabled defaults are implemented. Item 13 retains
its separate failed physical latency qualification; diagnostics remain disabled.
General maintained SQL and later family features do not add a completion gate
for the five required baseline plans. The user's completion criterion is
coherent ownership and stable required behavior. The earlier standalone
6,000-line criterion is superseded; no whole-migration reduction is claimed.
