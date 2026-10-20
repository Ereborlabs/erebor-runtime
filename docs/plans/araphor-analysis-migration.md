# Araphor Analysis migration

Replace the reference Analysis implementation without loss of domain rules.
Move compatible finite code to its current owner. Rewrite execution and
lifecycle code through Query subscriptions and native DataFusion plans.

## Intended end state

Keep authorization, attribution, recovery, evidence, and atomic commit rules.
Every program uses native SQL parsing, logical planning, optimization,
physical planning, and execution. Data owns durable transactions. Query
subscriptions supply source and window events. Do not add polling.

The user authorizes this migration on 2026-10-19 after recovery of the
reference source. The reference crate remains unchanged until each replacement
has source coverage and passing tests. A source move does not prove coverage.
The complete migration and reference removal are **Not done**.

```text
An admitted instance receives a subscription update
  -> Query captures the permitted source cut and prior state
  -> native DataFusion executes the exact admitted image calls
  -> finite Analysis validators check domain output and attribution
  -> Data checks current authority, revisions, and instance generation
  -> Data commits all outputs, state, evidence, and progress in one transaction

Permission changes, execution fails, or the instance stops
  -> Query cancels execution and joins its workers
  -> Data commits no partial step
  -> a retry uses the immutable attempt identity and captured contract

Every replacement passes its required checks
  -> the migration record identifies the exact tests and source state
  -> the reference files for that replacement can be removed
```

## Current implementation and remaining work

| Work | Current implementation | Result |
| --- | --- | --- |
| Source recovery | All 208 reference files were recovered from local commit `6a25ba1b`. The archive retains the complete source and exact later prototype. The 175 remaining files still match the baseline. | Done |
| Complete source map | The tables below cover all 95 production source files and the root exports. Test families are listed with their rules. | Done |
| Native and Wasm runtime | Package Runtime passes all 46 current tests. Native calls remain in process. Wasm uses native compilation and exact cancellation events. Configured compiler memory limits are Unsupported. Installed lifecycle parity remains open. | Partial qualification |
| Finite OCI execution | PackageCall and PackageExec retain complete typed returns. All 8 focused SQL contract cases and 4 source-built native Query cases pass. Separate admissions cannot share cached calls. The current final Rust gate is pending. | Focused checks pass |
| Shared subscriptions | Query carries complete per-step package returns and stable admitted call IDs. Explicit stop and authority loss join active workers. The finite Instance state reuse/reset and captured execution checks pass. The current final Rust gate is pending. Long-running window completion remains unimplemented. No separate package polling task exists. | Partial qualification |
| Graph boundary | All 29 focused Graph tests pass. Graph validates canonical captured input and actual detector returns. These tests do not qualify the automatic producer. | Finite boundary qualified |
| Discovery boundary | All 4 Data provenance tests and 8 native output-adapter tests pass. Native SQL retains the computations. Live publication remains incomplete. | Finite boundary qualified |
| Context | All 17 focused Context tests pass. Active Analysis retains import authorization and native selection. Quotas are explicit options and disabled by default. | Finite boundary qualified |
| Fixture qualification | All 4 comparator cases and the corrected entered-guest cancellation/revocation case pass. Active Analysis uses native calls and current Test authority. Native accumulation and clock/seed cases pass. Negative saved fixture time returns Unsupported. | Partial qualification |
| Managed state and lifecycle | Finite Instance, Query capture, and Data managed checks pass for immutable attempts, guarded state, atomic multi-call publication, receipt recovery, authority, and cancellation. The native Instance case passes separately. The final Rust gate is pending. Long-running supervision, start/inspect/stop, public history, and automatic restart remain absent. | Finite checks pass; lifecycle Not done |
| Graph producer | Capture immutable ACK history, source proofs, graph heads and frozen coverage in the same view. Bind detector relations and consume subscriptions. Add the final authority callback and exact previous-head check to the existing Data graph transaction. | Not done |
| Discovery producer | The current adapter subscribes to an admitted PackageCall. Interval split, frozen facts, witnesses, seals, replay, and reviewed baselines remain required. The complete producer is not qualified. | Not done |
| Notification producer | Finite operations are moved. All 5 reactive tests pass. Native SQL selects route and delivery candidates. Data supplies exact retry and grant-expiry deadlines. Managed supervision is absent. | Not done |
| Public callers | Restore current managed operations through Control, CLI, and lightweight E2E. Reference test modules remain available but are not a substitute for native integration tests. | Not done |
| Data coordination waits | Analysis, Query, and Package Runtime use subscription events and exact deadlines. Data still retries contended read locks every 1 ms and repeats native interrupts after expiry in analysis/read.rs. Replace both loops with event-driven ownership without loss of cancellation or deadline guarantees. | Not done |
| Quotas | SDK bulk, Query bulk/count, Data extraction and DuckDB memory/temp defaults are disabled. Focused SDK, runtime, extraction and finite pressure checks pass. Explicit configured limits and buffer lifetime checks remain. The final Rust gate and remaining resource-boundary audit are pending. Keep identity, format, type, and checked arithmetic validation. | Not done |
| Final retirement | The earlier 29 leaves and four additional mapped finite leaves are removed. The 175 remaining files retain unqualified or mixed rules. The current final Rust gate is pending. Complete reference removal remains open. | Partial |

The earlier quota audit found default caps outside the moved owners. Current
SDK bulk defaults use numeric maxima. Query bulk defaults also use numeric
maxima; count and pool limits are optional. Data extraction key limits and
native memory/temp limits are optional. Focused checks pass, but the final
Rust gate and remaining boundary payload audit are pending. Resource bounds
must stay configurable with disabled defaults. Preserve identity, type,
format, and checked arithmetic validation. SDK limits remain shared with the
native ABI and WIT. Query Memory does not charge every Data writer allocation.
The complete quota audit is **Not done**.

Data also has a fixed 16-slot reader admission semaphore. This quota rejects
the seventeenth active or queued read. The two reusable reader connections
are a separate execution pool. Reader admission needs an optional limit in
StorageLimitsV1 with a disabled default. This correction does not remove
the contended-lock or native-interrupt polling described above.

The old Query input executor has no active production caller. Its historical
removal preview estimated 986 production code lines. That preview also removes
native clock inspection and must not be applied. Keep `Inputs::from_plans`,
`scan`, `clocked`, and the shared receipt guards. No current removal count is
claimed for that executor.

Finite managed tests now reject a wrong returned evaluation time and stale
checkpoint reuse after input revision or coverage changes. A completed stateful
SQL retry survives reopen while the full input pool and only evaluation permit
are occupied. These tests do not replace live offered-cut retry, inherited
witness expiry, per-port deadlines, or source-scope rules. Discarded local-port
origins and disjoint capture ranges remain open. The audit covers 19 finite
and 22 live tests. Keep every remaining assertion until a current Query or Data
owner proves it. Executor removal is **Not done**.

The required final command is `bash .github/scripts/verify-rust-ci.sh` after
the last covered edit. The earlier full run, `migration-final-ci11`, passes
formatting, workspace compilation, strict Clippy, and test compilation.
Analysis passes 122 tests with 2 ignored. Builtins passes 20. SDK passes 82.
The run stops at two stale CLI command tests. The corrected CLI passes all
69 tests in `migration-cli12.log`.

Focused checks correct the stale catalog, retention, graph, and quota
fixtures. Query now retains the initial SQL error receipt before delivery.
The corrected failures pass their focused reruns. The earlier full run is
`migration-final-ci19`. Formatting, workspace compilation, and strict Clippy
pass. Analysis passes 121 tests, fails one, and ignores two. The failing
`qualification::tests::sql::fixtures_compare_complete_return` uses a native
scalar-subquery parameter. DataFusion changes that child plan during parameter
binding after the old admission snapshot. PackageCall now seals the completed
logical plan after native parameter binding and before public plan access.
The failed fixture passes in `migration-fixture20.log`. All 56 ordinary
definition tests pass in `migration-definitions20.log`; four native cases
require the separate source-built fixture run. The final gate remains
**Not done**.
The later shutdown checks in `migration-blocking35.log` and
`migration-joins35.log` pass all six cases. A subsequent Discovery run passes
five cases and fails `native_run_stops` with an extraction deadline. The
failed case passes alone in `migration-owner35.log` with its original limits.
Native logical optimization now runs in the tracked blocking worker before
the native asynchronous physical planner. The new barrier test and the
Discovery cases must pass on this source state before the final Rust gate.
These later changes are still **Not done** for final qualification.

The replacement passes the later focused checks on unchanged active source:
`migration-execution40` passes all 43 execution tests, including the native
optimizer cancellation barrier. `migration-discovery40` passes all 6 Discovery
cases with their original limits. `migration-definitions40` passes 64 ordinary
cases and retains 4 separately qualified native cases. The Query, fixture, and
adapter native runs pass all 7 cases. Their source-built artifacts match all
93 recorded guest inputs. `migration-final-ci40` passes formatting and workspace checking, then stops
at one Clippy collapsible-if error. The equivalent admission correction passes
strict workspace Clippy in `migration-clippy41`. The complete Rust gate, `migration-final-ci41`, passes formatting, workspace
checking, strict Clippy, and test compilation. Analysis passes 132 cases,
fails one, and ignores three native cases. The failed Graph fixture reads
an outer host table from an isolated package body. The corrected fixture
uses the declared records and prior-state relations. All 29 Graph cases
pass in `migration-graph42`. All 46 Runtime cases and four Data provenance
cases pass in their focused runs. The final Rust gate on the retirement
source state, `migration-final-ci42`, passes formatting, workspace checking,
strict Clippy, and all active workspace tests in 1,789.793 seconds. The source
manifest confirms that no covered file changed during the command. Ignored
physical-environment tests are not qualified by this run.

No benchmark or complete-migration result is claimed. The final command uses
`RUST_TEST_THREADS=2` on this host. This standard Rust setting preserves all
assertions and timeout values.

### Finite managed source: focused qualification

The full Rust gate `migration-final-ci42` and commit `95e9bb4d` cover the earlier
finite migration and its 29 retired leaves. They do not qualify the later
managed source. Its build and focused checks now pass. The required final Rust
gate `migration-final-ci58` stopped during test compilation because the host disk was full. Formatting, workspace check, and strict Clippy passed. The later `migration-final-ci59` passes those checks, all 145 ordinary Analysis cases, and all 333 ordinary Data cases. It stops at the stale OCI identity fixture. The fixture inherited the changed SDK default limits. The fixture now supplies its original exact limits. All 15 Package cases pass in `migration-oci-package60`. The full result remains **Not done**.

[Instance::admit and run](../../crates/araphor-analysis/src/instance/mod.rs)
now connect an explicit Run grant, exact retained definition, versioned call
manifest, and finite attempt. Admission starts no work. The
[manifest](../../crates/araphor-analysis/src/instance/manifest.rs) retains exact
image, target, artifact, argument, and dependency identities without serializing
a logical plan. SQL-only instances still require current authority.

[Session::capture_managed](../../crates/araphor-query/src/definition.rs)
returns one native prepared execution with its source cut, prior state, permit,
and worker tokens. Analysis registers the immutable attempt before it consumes
that same handle. [PackageExec](../../crates/araphor-query/src/definition/physical.rs)
selects prior state after effective inputs and parameters are known. Revision,
coverage, parameter values/schema, checkpoint version, named state dataset
schemas, or rebuild prevent incompatible state reuse.

The [publication sink](../../crates/araphor-analysis/src/instance/sink.rs)
uses native TableProvider insertion and DataSinkExec. It wraps the admitted
SELECT with native INSERT and adds no parser or physical runner. Ordinary tables
remain TableProviders; only relation-valued package calls use RelationPlanner.
DataSinkExec invokes the sink and emits the native UInt64 count. Query checks
that measured count array against its row/byte bounds and reserves its buffer
before execution. Analysis drains the stream and retains selected Arrow rows
and actual complete call returns, then
[Data commits](../../crates/araphor-data/src/analysis/managed/commit.rs) outputs,
state, evidence, and progress atomically under the full current grant/image set.
Eliminated calls produce no invented return or state change.

Cancellation joins the captured workers. A final authority check also protects
the acknowledgement of an existing receipt. Completed retries return the
original receipt without execution; pending retries return Incomplete rather
than capture a newer view. [Recovery](../../crates/araphor-data/src/analysis/managed/schema.rs)
checks retained metadata, Arrow packets, heads, and references. Query Memory
retains prior, result, and selected Arrow buffers through use. Data writer IPC
serialization and transaction allocations are not all charged to Query Memory;
configured quotas do not bound all Rust heap allocation.

The [review guide](../guides/araphor-discovery-definition-review.md#finite-managed-execution)
gives the source order, guard details, and actual resource ownership. Query
`input_bytes` bounds complete input/parameter/prior allocations. The sink
checks selected rows/bytes under `output_rows` and `output_bytes`. Optional
pool limits retain Arrow buffers through the writer. SDK limits separately
bound complete output batches/rows/bytes and checkpoint bytes.

The focused records are under `/tmp/araphor-oci-execution/`. Each listed
command returns zero and records unchanged covered source during that command.

| Record | Result | Seconds |
| --- | --- | ---: |
| `migration-managed-build55` | Build passes | 171.176 |
| `migration-contract55` | All 8 SQL contract cases pass | 4.418 |
| `migration-native-query55` | All 4 source-built native Query cases pass | 22.062 |
| `migration-native-analysis55` | All 4 source-built native Analysis cases pass | 21.925 |
| `migration-native-query60` | All 4 source-built native Query cases pass after the clean build | 19.200 |
| `migration-native-analysis60` | All 4 source-built native Analysis cases pass after the clean build | 17.567 |
| `migration-oci-package60` | All 15 Package cases pass with the unchanged golden identity | 0.189 |
| `migration-managed-data55` | All 11 managed Data cases pass | 15.482 |
| `migration-managed-instance56` | 10 pass; 1 native case ignored here and passed separately | 17.380 |
| `migration-managed-captured57` | All 7 captured-execution cases pass | 33.417 |
| `migration-managed-graph57` | Both Graph contract cases pass | 0.057 |
| `migration-clippy57` | Strict workspace Clippy passes after test-only fixes | 97.088 |
| `migration-managed-sdk50` | All 87 SDK cases pass | 0.150 |
| `migration-runtime53` | All 46 Runtime cases pass | 162.755 |
| `migration-extract53` | 22 pass; 1 release-only case ignored | 11.757 |
| `migration-dependencies53` | All 3 dependency cases pass | 2.552 |

The native runs use six source-built artifacts from build54 with complete
recorded source provenance. The native57 cached refresh passes in 31.395
seconds: all 116 recorded artifact inputs are hashed, and the six artifacts match build54
byte for byte on `x86_64-unknown-linux-gnu`. No benchmark result is claimed.
The required full Rust gate58 is **Not done**. The host disk filled during test compilation. The user removed generated Cargo output. Gate59 repeats the complete procedure with `CARGO_INCREMENTAL=0` and debug information level 1 for dev and test builds. These settings do not remove test assertions. Gate59 stops at the OCI fixture after 4,076.415 seconds. Its source manifest remains unchanged. The test-only correction retains the exact byte count, golden digest, and round-trip assertions. The complete workspace test build passes in `migration-oci-build60` in 3.139 seconds. No complete final pass is claimed for this later source.

Long-running reactive supervision, per-port windows and window completion,
start/inspect/stop/update/removal, authorized history, CLI/Control managed
operations, historical replay, automatic restart, Data coordination polling,
and the remaining quota audit are **Not done**. Finite receipt recovery is not
a long-running recovery supervisor.

### Production code ledger

The current count60 follows the OCI fixture correction and the four-file retirement.
It excludes tests, comments, and blank lines. Moves cancel in the net result;
the retained Back source is included. No covered source changed during the
count.

| Baseline | Added production Rust | Removed production Rust | Net |
| --- | ---: | ---: | ---: |
| `6a25ba1b` | 12,965 | 5,136 | +7,829 |
| Original reduction baseline `7b7b407a` | 44,212 | 30,387 | +13,825 |

The finite managed deliverable adds 3,407 net production lines relative to
`95e9bb4d` (`13,825 - 10,418`). The required 6,000-line net reduction is
**Not done**. Another 19,825 net production lines must be removed relative to
the current count to meet that target. No simplification or speed result is
inferred from these counts.

The record is `/tmp/araphor-oci-execution-count60.json`. Its selected source
fingerprint is
`6774e44ebda654a827dab6fe4389dbbd4b8e7e5d2b97d9ab4ca6f45176d2be78`.
The earlier count58 has the same production totals. Its source fingerprint is
`a19423ab11a6da3d5d67fb22f1f65cc2eb3674740b9d074fe218e0da7eae4243`.
The test-only OCI correction changes no production count.

#### Historical count42

This is the historical count42 ledger at commit `95e9bb4d`, before the finite
managed deliverable. It is not a count of the current worktree. The syntax
count excludes tests, fixture helpers, comments, and blank lines. Moves cancel
in the net result. It includes the reference crate and new owners at that
source state. No source changed during that count.

| Baseline | Added production Rust | Removed production Rust | Net |
| --- | ---: | ---: | ---: |
| `6a25ba1b` | 9,384 | 4,962 | +4,422 |
| Original reduction baseline `7b7b407a` | 40,827 | 30,409 | +10,418 |

The required net reduction of 6,000 production lines is **Not done**. At that
historical source state, another 16,418 net lines were required relative to
the original baseline. These values do not measure the current deliverable.
The count record is `/tmp/araphor-oci-execution-count42.json`; the selected
source fingerprint is
`1d9c8e57c7c8dbc2d45ca1b11d5fe0022e5ca5827f8ad4c06bc73fb6bcce0f69`.
This count is not a performance result or proof of a simpler architecture.
The current owners retain one copy of the shared atoms test corpus. Two
byte-identical new copies are removed. Test fixture reduction receives no
credit against the production Rust target.

## Retired finite reference files

The earlier current owners and mapped assertions cover 29 complete reference
files. Those duplicate leaves were removed after the focused checks. No test rule is
removed from the current owners. Final Rust qualification of this source
state is **Done** in `migration-final-ci42`. The complete migration remains
**Not done**.

| Reference family | Files | Removed production lines | Current owner |
| --- | ---: | ---: | --- |
| Native admission and loading | 4 | 883 | Package Runtime |
| Wasm admission, bindings, and execution | 3 | 484 | Package Runtime and Query |
| Finite Graph domain rules | 7 | 774 | Analysis Graph |
| Finite notification operations | 6 | 1,047 | Analysis Notification and Data |
| Context import and selection | 2 | 393 | Analysis Context and Data |
| Discovery provenance validation | 6 | 507 | Data |
| Fixture comparison | 1 | 155 | Package |

The [retirement record](../../recovery/araphor-analysis-finite-retirement-20261019.json)
lists every path, source checksum, current owner, and required assertion.
The recovery archive checksum was verified before that removal. At that point,
179 reference files retained their original content. Mixed execution, capture,
publication, inspection, recovery, and producer files remained available.
The 4,243 removed lines are a gross duplicate count for that retirement. The
historical ledger above states its workspace net result.

The [additional retirement record](../../recovery/araphor-analysis-managed-retirement-20261019.json)
removes exactly these four complete files:
`graph/contract.rs`, `graph/contract/tests.rs`, `model/input.rs`, and
`model/operation.rs`. Current Graph contract tests preserve the descriptor
rules. Native SQL contract tests preserve typed inputs, parameters, prior-state
indices, conversion, and configured limits. Captured execution owns the cut,
control, memory leases, and operation permit. The extra source count is 178
production lines; the test-only file contributes zero. This is a gross
reference removal, not the current workspace net change.

There are now 33 retired files and 175 remaining baseline files. The recovery
archive retains all 208 originals. The current final Rust gate is pending;
complete migration and reference removal remain **Not done**.

## Root exports

The reference `src/lib.rs` exports execution owners, duplicated model output
wrappers, and local quota types. Active Analysis exports finite Graph,
Context, notification operations, the current reactive Discovery owner, and
the finite Instance owner with focused qualification. Package Runtime owns native and Wasm
limits. Query owns captured execution and receipts. Data owns managed attempts
and atomic result/state transactions. Do not recreate the old owner facade or
move its glob imports. Each current crate owns its structured error type. The
remaining long-running owner must use these current APIs.

## Recovery custody

The durable local archive is
`recovery/araphor-analysis-20261019-24zu3vty.tar.gz`. Its SHA256 is
`991f6bac9cf243523a415f308515b124a14c72eeb28da3be8ca5f32dcfcda420`.
It includes the complete reference source, current changes, exact recovered
tests, and independently checked reconstruction manifests. Do not remove it
during source retirement. This record does not claim a remote push.

Local commit `d9369555` retains the archive and its checksum. The archive
contains the complete recovered source. The 29 earlier leaves and four additional finite files are retired; the other
175 baseline files remain unchanged.

## Back package, model and notification inventory

Source baseline: `6a25ba1b34dbaa0a553b1883058938683ce7aaab`. The audit uses the complete recovered reference. The retirement record above identifies removed duplicates. This audit covers 55 production files: 37 package files, 7 model files, error and limits, and 9 notification files. Test-only `model/schema.rs`, `package/required/testing.rs`, `package/wasm/fixtures.rs` and their test trees are excluded from the production count. Their assertions remain migration inputs.

The table classifies rules, not whole features as obsolete. A current SDK validation call does not replace durable commit, current authority, capture identity or restart recovery. This is a source audit. It does not claim Cargo qualification.

| Back source | Functions or contracts | Current state | Current owner or required edit |
|---|---|---|---|
| `model.rs` | `AdmittedExport::{admit,compile,implementation}; AdmittedModel::{admit,outputs,relations,plan}; SqlModelOutputV1::retain` | Partial | Query definition/package.rs and PackageCall replace the old planner. CallResult retains Arrow buffers. Retained bundle and transfer scratch accounting still need proof. |
| `model/component.rs` | `component_limits; exchange_preflight` | Mapped | Query reserves SDK encoding scratch and guest transfer capacity before execution. The blocking worker retains the permit and memory lease. Wasmtime host-call fuel uses the acquired copy budget before it lifts guest output. Configured failure and lease-release tests pass. |
| `model/datasets.rs` | `SqlDatasetOutputV1::query` | Rewrite | Query committed output through native TableProviders or registered Arrow tables. Preserve declared schema, control, memory, and final authority. No separate ModelRun. |
| `model/execute.rs` | `ModelRun::{evaluate,evaluate_output,datasets,query,references,owned}` | Partial | PackageExec and physical/sql.rs execute native plans and validate full SDK output. Preserve pre-execution allocation accounting; remove Engine::wait and the second runner. |
| `model/input.rs` | `ModelRun::{register,table}` | Mapped | PackageExec binds SourceSnapshot ports, parameters, prior state and output relations. Keep zero-column batch row counts and native normalization tests. |
| `model/operation.rs` | `ModelRun::new` | Replace | Session, CallContext and the existing operation permit own execution. Keep child limits and memory lifetime; remove the old runner state. |
| `model/output.rs` | `ModelRun::{evidence,reasons,strings,indices}` | Mapped | Query definition/physical/sql.rs builds typed evidence and reason rows. SDK validates links, details and bounds. |
| `limits.rs` | `WasmLimits; AnalysisLimits` | Partial | Runtime optional limits and Query limits replace this owner. Preserve explicit quota failure and shared scratch accounting. Do not restore implicit caps. |
| `error.rs` | `missing_input; cause; is_busy; busy_resource; package_code; ErrorExt` | Partial | Query Failure and Runtime Error preserve backend codes and Busy. Managed readiness still needs missing input versus pressure, cancellation and permanent failure classification. |
| `package/mod.rs` | `AnalysisPackageOwner fields and exports` | Replace | Use current Query, Runtime, Data and the managed instance owner. Do not retain the old facade or lifecycle mutex. |
| `package/owner.rs` | `new_with_limits; execute; execute_sync; check; grant_control; operation; authorize_commit` | Missing rules | Current Package checks action, grant expiry, trust, and final single-use authority. Native subscriptions retain cleanup. Managed instances still need whole-call grant sets and durable lifecycle. Remove old dispatch, sync bridge, and service startup. |
| `package/evaluation.rs` | `run; evaluate_active; result_id; request` | Missing | Retain immutable request and result identity, exact scope and parameters, revision checks, original retry receipt, final current authority, and atomic Data commit. |
| `package/evaluation/preparation.rs` | `prepare_model` | Missing | Retain input revision plus coverage fingerprint, stale status, guarded checkpoint reuse/reset, target and artifact identity, and dependencies/source revisions/witnesses/context refs. Use one Query capture. |
| `package/execution.rs` | `evaluate_artifact; admit_artifact` | Partial qualification | Query PackageExec plus Runtime cover all three targets. Native fixture cases and full output checks pass. Shared transfer reservation is implemented. Cold preparation ordering remains under qualification. |
| `package/fixtures.rs` | `test_package` | Finite owner moved | Analysis Qualification uses exact image fixtures through native calls, saved Arrow input, parameters, checkpoint, clock, and seed. Test authority and trust precede and follow execution. Cancellation and revocation join the entered guest. Public Control and CLI callers remain open. |
| `package/fixtures/comparison.rs` | `output; datasets; batches; batch; reasons; array; number` | Moved | PackageFixtureV1::compare_output in araphor-package/src/fixture.rs owns this pure rule. All four focused comparison tests pass. |
| `package/freshness.rs` | `refresh_package` | Missing rule | Managed inspection must mark stale on changed source, coverage, clock, checkpoint or dependency; do not recompute during inspection. Use capture receipts and Data current checks. |
| `package/inspect.rs` | `activations; inspect; read_output; result_output; query_output; permits_selection` | Missing | Expose managed status, exact result reads and native queries. Retain captured selection disclosure checks and checkpoint reconstruction. Image inspection alone is not equivalent. |
| `package/installed.rs` | `InstalledAnalysis::{new,evaluate}; InstalledEvaluation` | Partial | Finite Query replaces compute and owns leases. Managed caller must add whole-tenant or exact-selection authority, trust before and after evaluation, effective parameters and stable result provenance. |
| `package/installed/commit.rs` | `InstalledAnalysis::authorize` | Missing | Preserve all dependency revisions, generation, exact metadata and current grants under commit_many. Data checks CAS in its transaction. No Data read API inside final writer-held callback. |
| `package/installed/control.rs` | `AuthorityWatch::{start,drop}` | Missing rule | Current Package composes changes_for with the native subscription. Authority loss cancels and joins workers before Denied. Managed grant sets and restart recovery remain open. Do not copy the per-operation thread. |
| `package/installed/history.rs` | `refs; pin_at` | Missing | Retain exact root, artifact revision, export, parameters, target and native identity. Historical evaluation must use current authority and cannot advance current state. |
| `package/installed/read.rs` | `snapshot; snapshot_reusing; descriptors; prepared_models; revisions; active` | Partial | Definition snapshots and immutable installed images replace bundle selection. Managed reads still need tenant, state and exact call pin checks. Remove active-export enumeration. |
| `package/installed/snapshot.rs` | `InstalledBundle::{new,admission,export_index,export_at,clock,identity}; InstalledSnapshot` | Partial | Query Packages and admitted calls retain image closure and implementation identity. Persist stable call pins for restart; do not copy old compiled model catalog. |
| `package/installed/snapshot/memory.rs` | `BundleMemory::{retained,bundle,snapshot,implementation,program,fixture,dataset,checkpoint,output}` | Partial | Native Arc ownership keeps binary and Arrow lifetimes. Explicit accounting for retained bundle metadata and transfer scratch must remain when configured. Remove handwritten duplicate size walks where existing owners measure it. |
| `package/lifecycle.rs` | `install; install_model; start_model; readiness; key` | Rewrite | Image retention stays inert. Managed create/start/update owns execution. Preserve prepare-before-switch, unsupported/missing input status and generation CAS. Remove hardcoded builtin adapter allowlist. |
| `package/lifecycle/activation.rs` | `model_activations; model_activation; check_parameters` | Missing rules | Preserve exact revision conflict, immutable parameters and selection, restart generation, and typed parameter validation. SQL source now contains parameters; instance pins its exact definition snapshot. |
| `package/lifecycle/revisions.rs` | `install_revision; load_bundle` | Mapped | Data install_package_image/package_image and pure PackageBundle validation retain exact closure, collisions and recovery. Remove old closure cap and activation coupling. |
| `package/output.rs` | `output_rows; encode_output; decode_output; decode_checkpoint; codec_result` | Partial | Reuse SDK wire codecs directly. Managed results need the full output and separate checkpoint; do not keep 16MiB encoding clamps or host JSON conversion as execution. |
| `package/removal.rs` | `remove; prune_package; prune_orphans; remove_closure; rehome_package` | Missing rules | Managed removal must protect shared dependencies, retain independent instances, release exclusive references and reconcile failed upgrades. Data owns collection; no source sweep. |
| `package/required.rs` | `required_bundles; ensure_required` | Partial | Builtin descriptors and components remain. Retain image factories for Discovery and all detectors. Remove implicit installation/activation and InstalledAnalysis construction. |
| `package/status.rs` | `receipt` | Missing caller | Managed receipt retains target/artifact identity, exact result and commit revision, input revisions, coverage and stale status. Current image response does not supply this. |
| `package/supervision.rs` | `supervise; registrations; admit_registrations; serve_activation; wait_inputs; wait_capacity; grant_expiry; evaluate_offer; failed` | Rewrite | Use on-demand native Query subscriptions. Retain stop-and-join, current permission/expiry, generation replacement, capacity events, retryable pressure, CAS conflict retry and durable failure status. Do not copy the registry scan or old input watcher. |
| `package/native/mod.rs` | `NativeLimits::validate` | Mapped | Runtime native/mod.rs preserves explicit unsupported in-process resource limits and native loader exports. |
| `package/native/artifact.rs` | `NativeAdmission::{validate,validate_files}; closure, target, ELF, symbol and path checks` | Mapped | Runtime native/artifact.rs retains this source; only public visibility differs. |
| `package/native/files.rs` | `FilePin::{package,system,link,path,check}; MappedFiles::{read,check}` | Mapped | Runtime native/files.rs is byte-identical. Sealed files and mapped-library identity remain pinned. |
| `package/native/loading.rs` | `NativeLibrary::{load,call}; failure; failure_at; open` | Mapped | Runtime native/loading.rs retains this source; only visibility differs. Load, call, copied output and release remain on one worker. |
| `package/wasm.rs` | `WasmExecution::{new,new_engine,admit,prepare,evaluate,wait_capacity,limits}` | Mapped with changes | Runtime wasm.rs uses lazy host construction, optional limits, current Wasmtime compilation and owned cache. Explicit compiler process memory limit is Unsupported. |
| `package/wasm/admission.rs` | `CompileBudget::{check_size,check,section,function,interface,resources,instance}` | Mapped | Runtime retains structure/interface validation. Resource/work bounds are configurable and disabled by default. |
| `package/wasm/bindings.rs` | `Wasmtime component bindings` | Mapped | Runtime file is byte-identical. |
| `package/wasm/cache.rs` | `CacheCharge; CodeCache::{get,reserve,insert}; cached; compiled` | Mapped | Runtime retains executable pin and charge/drop rules. Component::new replaces serialized compiler reply loading; cache limits remain explicit. |
| `package/wasm/execution.rs` | `GuestState; ResourceLimiter; Host::cancelled; EvaluationPermit; invoke; EpochTicker` | Mapped with replacement | Runtime retains host and output checks, fuel and limits. One-shot cancellation/deadline/completion replaces recurring epoch polling. Worker tracking joins explicit finite cancellation. |
| `package/wasm/compiler.rs` | `CompilerChild command/restrict/capture/run; WasmExecution::compile` | Replace | Remove child process startup, pipe management and polling. Wasmtime Component::new compiles validated source. Document unsupported compiler-process quotas and noninterruptible active compile. |
| `package/wasm/compiler/image.rs` | `CompilerImage::{write,read,reply,component_reserved}` | Remove obsolete protocol | No compiler pipe or serialized machine-code reply remains. Native Wasmtime compilation removes that transfer boundary and unsafe deserialize route. |
| `package/wasm/compiler/input.rs` | `CompilerInput::{write,read,request}` | Remove obsolete protocol | No subprocess request exists. Pure image bytes and native Wasmtime parsing remain the input boundary. |
| `package/wasm/compiler/worker.rs` | `run_worker_if_requested; run_compiler_worker; worker_limits; worker_image` | Remove obsolete hooks | Executable compiler entry hooks are absent from current execution. Preserve explicit quota support reporting rather than copying child-process limits. |
| `notification/mod.rs` | `NotificationRouter::{new,lock}; WorkCursors` | Mapped/partial | Finite Router and its lock moved to current Analysis. Native SQL and Query updates replace the old routing/delivery cursors. Managed supervision remains open. |
| `notification/routing.rs` | `configure; route; route_finding` | Partial | configure and route_finding moved with policy revision, authority and exact finding result check. Native SQL selects finding work. consume applies the finite route method. Managed supervision remains open. |
| `notification/obligation.rs` | `schedule; update_finding; update_route; escalation; obligation; insert` | Mapped | Current Analysis preserves first-seen deadline, monotonic priority/sensitivity, route revisions, revision-specific acknowledgement and related-obligation identity. |
| `notification/attempt.rs` | `send; prepare_attempt; retry_ready; append_attempt; attempt_result; complete_attempt` | Mapped | Current Analysis preserves pending attempt identity, retry delay/limit, captured revision, accepted delivery and sink health. Delivery is not human acknowledgement. |
| `notification/attempt_delivery.rs` | `captured_route; delivery_failure; captured_delivery` | Mapped | Current Analysis preserves captured subject/route, current grant and disclosure checks, unavailable finding failure and typed sink payload. Data graph reads replace thin Back wrappers. |
| `notification/concern.rs` | `refresh_concern; submit_concern` | Mapped | Current Analysis preserves approved agent concerns, current route, context sensitivity, immutable retry, original deadline and unconfirmed state. |
| `notification/delivery.rs` | `deliver; deliver_state` | Partial | deliver_state moved; deliver_obligation is finite. Native SQL selects notification work. consume preserves per-obligation error isolation. Managed supervision remains open. |
| `notification/operations.rs` | `obligations; obligations_page; health; acknowledge; record_agent; authorized_state` | Mapped | Current Analysis preserves filtered cursor advancement, tenant/route/sensitivity checks, human-only revision-bound acknowledgement and immutable agent receipt. |
| `notification/store.rs` | `routes; route_version; finding_version; state_page; related_states; state_key; save; persist` | Mapped | Current Analysis preserves versioned context storage, CAS, state validation and rollback of local revision on commit failure. State lookup is centralized. |

### Managed instance contract

The current source has no Data type named `PackageInvocation`. Query retains `Invocation {id, seed, inputs, checkpoints, limits}`, `DefinitionOutput {snapshot, batches, calls}`, and read-only `CallResult::{evaluation, output}` accessors. New Data managed types are `ManagedSpec`, `ManagedManifest`, `ManagedRead`, `ManagedRequest`, `ManagedAttempt`, `ManagedCommit`, and `ManagedReceipt`. The finite Instance path uses those types; the older `PackageActivationV1` and `PackageCommitV1` remain separate contracts.

1. Keep immutable image retention, immutable definition admission and managed lifetime separate. Installing an image or admitting a definition starts no work. A managed instance pins tenant, selection, exact definition snapshot/digest, exact image closures and grants.
2. Persist a stable call identity for each call site in that snapshot. A bare finite numeric call ID is not a restart contract. The new versioned manifest binds each ID to the exact definition, native arguments, and image pins. Two uses of the same export must have separate state. Do not put call IDs in separate scope strings: `package_dependency_current` requires the same scope for composed package dependencies.
3. Capture each attempt once. Its immutable identity includes instance generation, exact definition and call pins, fixed logical time/seed, selected input receipt, prior checkpoint revisions and the authorized selection. Persist an attempt before guest execution when retries must retain a capture across process failure. A retry returns the original receipt, or fails if its request differs. It must not silently select a newer view. A new view needs a new attempt identity.
4. Use the current native source capture. `ArrowSnapshot` already supplies the extraction identity, captured relation revision, exact result dependencies, context refs and witnesses. `CallResult` supplies effective evaluation parameters, complete input revision/coverage metadata and full validated output. Do not publish only the selected Arrow relation.
5. Choose guarded prior state after native child inputs are collected and before the target executes. Preserve Back `prepare_model`: reuse state only when prior input revisions AND coverage match, and no rebuild was requested. A changed snapshot resets state. Explicit finite caller-supplied state can keep its existing caller-owned contract.
6. Keep current authority outside Query compute: check Run and image trust before capture, subscribe to grant change/expiry events, cancel the operation and join its guests on loss, and recheck the entire image/grant set under `PackageAuthorization::commit_many` at the final commit. The callback must run once. Never read Data through a second reader while its writer transaction is held.
7. Extend the actual Data transaction owner for a composed step. Reuse `package_retry`, `package_commit_rows`, dependency/current-source checks, witness resolution, reference insertion and stale propagation. One transaction must publish all executed call outputs, checkpoint changes and instance progress, compare every expected generation/checkpoint and return one immutable receipt. Looping public `commit_package` would expose partial steps.
8. Retain Data recovery checks for image/descriptor digests, exact dependencies, result contracts and reference integrity. A commit that reached disk before a crash must return its existing receipt on retry. A crash before commit must leave state/progress unchanged; an admitted attempt must retain its capture or fail explicitly when that capture cannot be replayed.
9. A failed update must leave the old running revision and checkpoint usable. Prepare the new exact definition and its first proposed output before the Data CAS switch. Require an explicit reset/rebuild when state is incompatible. Removal must retain shared dependencies and independent instances, then release exclusive pins through Data collection.

`PackageKeyV1 {tenant, scope, package, export}` and the single-call public commit API need an actual managed call identity and atomic step edit. They cannot represent multiple stateful calls to the same export by renaming metadata alone. Retained within-step dependency edges also need admitted call metadata: current `DefinitionOutput.calls` contains evaluation/export and output, while package/image/target identity is on each admitted `PackageCall` in the native plan.

The new [managed capture](../../crates/araphor-data/src/analysis/managed/capture.rs)
extends the existing source read with exact managed prior state on the same
connection. Canonical TableProviders do not expose a separate checkpoint read.
PackageExec selects eligible prior state after native input collection and
executes the guest once. The finite connection is present but its qualification
is **Not done**. A stale dependency head and the call's own prior state have
different rules: prior state can be eligible when input revisions, coverage,
and parameters still match. Long-running subscription steps do not yet use
this managed transaction path.

### Public lifecycle

Keep image digest/install/inspect and image fixture qualification on the image. Keep definition admit/inspect on the immutable definition. Expose managed start, inspect/status, stop, resume or renew authority, update to an exact definition revision with expected generation, rollback to a retained exact revision, finite run with immutable attempt ID and explicit rebuild, exact result read/native result query, and removal. No image operation may imply activation. Parameters and windows remain in SQL/PRQL/YAML source; a managed instance pins that definition rather than adding a second parameter or window language.

Historical result replay must retain exact revisions, captured source/context/evidence and current authorization. It must not commit to current state. Unsupported host/output contracts must remain explicit status, not disappear from inspection.

### Notification continuation

All finite notification rules have current owners. Data reads replace the old graph wrappers. Native SQL selects finding and notification work. consume applies each Query update through the retained finite methods and preserves per-obligation error isolation. Managed supervision and recovery remain open.

Data `analysis/extraction/tables/notification.rs` supplies acknowledgement, retry, and grant-expiry deadlines as `next_change`. Query follow tests prove a deadline-only wake. No interval, tenant sweep, or second timer owner is added. Managed recovery must preserve the original first-seen deadline and pending attempt after restart and route changes.

### Focused proof required before Back removal

- SQL, Wasm and native calls in one definition; two calls to the same export keep independent checkpoints. Result reasons, evidence, every dataset and checkpoint survive publication.
- Same immutable attempt after reopen returns the original commit revision and rows. Changed definition, parameters, selection or captured input under the same attempt conflicts. Crash before commit leaves all heads and progress unchanged; crash after commit does not repeat execution.
- A concurrent state update or source/dependency/context change rejects the old proposed step atomically. Failure on the second call publishes neither call. Reuse Data crash and reference-contract tests.
- Grant revocation or expiry while a real guest is entered cancels and joins it; no result/state/progress is published. A current authority check is still required on an existing-result retry. Migrate `shared_root_checks_grants`, `domain_commit_fences_renewal`, `domain_commit_fences_suspension` and `package_stop_before_commit`.
- Changed input revision or coverage resets prior state; unchanged inputs retain it; explicit rebuild clears it. Pressure, cancellation and permanent error preserve the previous successful result. Migrate `package_busy_preserves_result`, `native_overflow_keeps_checkpoint`, `native_checkpoint_retry_and_restart` and `wasm_checkpoint_retry_reopens`.
- Failed update preserves the former revision. Removal keeps shared/explicit dependencies and releases only exclusive images. Migrate all five `package/removal/tests.rs` cases and historical pin tests without InstalledAnalysis.
- Image fixtures use saved Arrow input, parameters, checkpoint, time and seed through native calls for all targets. Compare row order, batch partition independence, nested numeric tolerance, typed reasons, evidence and checkpoint versions. `PackageFixtureV1::compare_output` now owns the pure comparison tests; native executor qualification is pending.
- A committed finding triggers routing without a scan; a due retry and acknowledgement deadline trigger delivery without new data or polling. A reopened pending attempt keeps its original identity and subject. Preserve the 16 current finite notification tests and add only the reactive continuation cases.

Query now reserves measured SDK encoding scratch and acquired guest output
capacity before the runtime call. The worker retains that lease through
output copy and release. Explicit quota failures and full pool recovery have
focused proof. The new SDK defaults and Query/Data bulk changes require the
separate qualification recorded above.

## Graph compatibility inventory

Reference: `6a25ba1b34dbaa0a553b1883058938683ce7aaab`.

Read all 22 production modules in `crates/araphor-analysis_back/src/graph`.
Keep each unqualified reference file until its replacement passes the required checks. A moved
function is not a code reduction. The later focused qualification table records the finite adapter result.
The reactive graph producer is not implemented.

### Current finite adapter contract

`araphor_analysis::Graph` owns one finite graph conversion. It has no store,
clock, reader, evaluator, activation state, or subscription scheduler.

```rust
Graph::new(&GraphReplayInputV1) -> araphor_data::Result<Graph>
Graph::supports(&sdk::Model) -> bool
Graph::apply(self, &PackageCall, &CallResult) -> araphor_data::Result<Graph>
Graph::finish(self) -> araphor_data::Result<GraphSnapshotV1>
Graph::expire(&GraphSnapshotV1, result_id, notice) -> araphor_data::Result<GraphSnapshotV1>
```

`new` checks the Data replay contract and its canonical manifest. The caller
uses the existing `GraphReplayInputV1::normalized` when it constructs the
captured input. `apply` consumes the accumulator, so a failed conversion cannot
leave a usable partial graph. It checks the call tenant, descriptor, export,
and graph port contract. It compares every effective input row with the
private expected projection before it resolves guest row references. Input
batch boundaries and dataset order do not change that comparison.

The detector wire remains the existing builtins `Rows` codec: one non-null
Binary `value` column, with its declared type and JSON schema metadata. The
private projection does not supply another execution input path. The native
query must supply the actual call relations. Query still owns full SDK output
validation, budgets, execution, cancellation, and the complete return lifetime.

### Production module map

Paths below the reference graph directory are relative to that directory.

| Reference module | Functions and required behavior | Current owner or required replacement |
|---|---|---|
| `mod.rs` | `GraphContextProvider::facts/revision`; `GraphAndFindingOwner::new/drop`; required graph registration | The old live callback, global source walk, mutex cursor, and InstalledAnalysis owner must not move. Keep the facts and revision semantics. Publish immutable graph proofs to Data before Query capture. Use Query source-registry updates for membership. Data already owns `enable_graph_owner`, `register_graph`, and required-processor registration. The reactive registration connection still needs implementation. |
| `contract.rs` | `supports_analysis`; `analysis_package` | Port and checkpoint qualification moved to `Graph::supports` in active `graph/mod.rs`. Detector descriptor lookup already exists at `araphor-analysis-builtins/src/graph/contract.rs::Detector::{from_id,descriptor}`. Do not move the duplicate lookup wrapper or require InstalledAnalysis. |
| `derive.rs` | `derive`, `derive_candidate`, `GraphDerivation::new`; deterministic detector merge | Input validation and finite merge moved to active `Graph::{new,apply,finish}`. Native `Engine::prepare_definition` and `Session::execute_definition` replace model dispatch and evaluation. The admitted definition must explicitly select its detector calls. Do not recreate discovery of active exports or a package-name execution switch. |
| `derive/adapter/mod.rs` | `evaluation/evaluation_for`, `evaluate`, `observation` | `observation` and the expected record/fact/manifest projection moved to active `graph/projection.rs`. They validate the actual effective inputs. The old evaluation constructor, 60-second timeout, InstalledAnalysis call, and synchronous execution bridge must not move. Native SQL/TableProvider relations must supply the real inputs. |
| `derive/adapter/facts.rs` | `algorithm_fact`: record row, duplicate identity, reviewed-policy qualification | Moved to active `graph/facts.rs`. It preserves exact record binding and does not infer review from an unqualified policy string. |
| `derive/adapter/edges.rs` | `selected_edge`, `native_selection`, `fact_selection`; native, parent, provider and Kubernetes subjects | Moved to active `graph/edges.rs`. It preserves native lifetime keys, object generation, request/provider identity, stage proofs, selected evidence, and cause spelling. |
| `derive/adapter/output.rs` | `apply_output`, `finding_evidence`, `finding_reasons`, `selected_record/fact/evidence/subject` | Domain mappings and checks moved to active `graph/output.rs`. Each finding must have the exact candidate evidence and reason. Reason details must equal the candidate, or retain their declared typed details. A context subject must refer to the same record. Query already validates generic SDK schemas, reference ranges, declared reasons, and checkpoint shape. The adapter does not duplicate that validation or maintain another fixed output-byte quota. |
| `derive/adapter/validation.rs` | `validate_edge`, `validate_finding`; prevent an authority upgrade | Moved to active `graph/validation.rs`. Direct native causes require exact identity. A direct parent needs a qualified local child match. Direct authority needs an authoritative operation, exact local identity, matching credential object, and the fact's evidence. Kubernetes evidence alone cannot become a direct cause. Confirmed findings require complete coverage for every evidence record. |
| `derive/identity.rs` | `subject`, `task`, `edge`; deterministic identities and conflict handling | Moved to active `graph/identity.rs`. A missing task gets an unresolved external subject. Conflicting non-contradicted edges fail. Contradicted edge conflicts remove result authority. |
| `derive/proof.rs` | `proof`, `effect`; temporal and physical authority | Moved to active `graph/proof.rs`. An overlapping gap or missing retained range prevents complete coverage. It preserves original kernel sequence, exact decision fields, nonzero identity coordinates, and the distinction between prevention, packet drop, queued termination, and unknown completion. |
| `derive/policy.rs` | `facts`, `policies`, `reviewed_policy`, `policy_conflict` | Moved to active `graph/policy.rs`. Match the observed generation. Suppress only a Missing chain that has its exact counterpart. Review requires one exact chain and no contradiction. Multiple exact chains remain a conflict. Data still validates the retained activation acknowledgement join. |
| `derive/finding.rs` | `finding`; IDs, evidence, policy provenance, sensitivity, reason and action | Moved to active `graph/finding.rs`. It preserves missing-ACK provenance, exact effect records, coverage intervals, UTC range, severity, action, HostRestricted propagation, contradiction precedence, and protection against a confirmed-to-unconfirmed downgrade in one conversion. |
| `derive/finish.rs` | `finish`; branch states, sorted output, package state and replay metadata; `WindowBytes::check` | Finite assembly moved to active `graph/finish.rs`. Data remains the GraphSnapshot and CanonicalGraph validation owner. The fixed sink-byte check was not copied. Query owns configured execution budgets. Existing graph schema limits remain in Data; this move does not claim that those limits are configurable. |
| `coverage.rs` | `coverage`; exact historical coverage reports and frozen coverage keys | Do not move the store reads. A captured native relation must retain the selected report revision and interval revision. Data already supplies `graph_coverage_versions`; Discovery coverage SQL supplies classification for its current contract. Graph's frozen historical-key behavior still needs a captured native projection and tests before replacing this module. Do not replace it with only the latest coverage report. |
| `input.rs` | `commit_chunk`, `replay_chunk`, `chunk_missing_ranges`, `read_window`, `window_context` | Replace the separate raw reader and live Control callback with Query's captured relations. Keep exact missing intervals, StorePosition values, frozen context keys, source identity, and immutable-body conflict checks. Data already normalizes and validates GraphReplayInput. Its canonical `context_versions` relation carries complete retained bodies. The captured graph input projection still needs implementation; no post-capture Control read is permitted. |
| `chunks.rs` | `commit_chunks`, `context_chunks`, `chunk_bounds`; work splitting and progress | Do not move recursive byte-driven splitting, source reads, or the fixed 255-context batching policy. A finite call consumes one declared relation. The native definition must declare the graph window and preserve the old boundary-join proof. Keep exact first/last cursor arithmetic and fail without advancing progress on a rejected result. |
| `window.rs` | `commit_window`, `window_heads`, `commit_retained_window`; replacement and retained-range selection | Replace source/header sweeps with a native graph-state input joined to the captured source cut. SQL must select current heads, frozen facts, overlap, retained-floor effects, and previous result identity. Data already owns `graph_window_headers`, `graph_window_page`, current/historical graph rows, and retention state. The reactive producer must use these semantics without a second reader. |
| `expiry.rs` | `expire_window_heads`, `window_deadline`, `expire_window`, `expiry_snapshot`, `expire_graph`, `expire_findings` | Pure graph/finding degradation moved to `Graph::expire` in active `graph/expiry.rs`. Native selection must detect expired or reclaimed heads, preserve the earliest existing deadline across overlapping evidence, and request a Query window event. The publisher must append the expiry result, retain its context/image proofs, use no expired evidence witnesses, leave consumed progress unchanged, and avoid duplicate expiry writes. These selection/publication parts still need implementation. |
| `installed.rs` | `installed_refs`, `analysis_refs`, `compatible_refs`, `installed_current`, `installed_snapshot`, `package_revisions`, `package_context` | Do not move active-export snapshots or cache invalidation. Query already pins immutable images and exact PackageCall metadata in PreparedDefinition. Graph publication must retain those actual image/export pins and current grant proofs as Data context references. It must preserve historical audit and deny publication after authority loss. That graph publication connection still needs implementation. |
| `commit.rs` | `commit_bounded_window`, `acknowledge_window`, `commit_snapshot`, `commit_contexts` | Do not move evaluation or adaptive splitting. Preserve semantic no-op detection, coverage/context acknowledgement, previous-result identity, exact positions, earliest witness deadline, current authority, and atomic result/progress publication. Data already owns CanonicalGraph, `commit_graph_snapshot`, witness equality and progress checks, and context commits. The native graph publisher must connect the captured result to that transaction and current authority guard. |
| `live.rs` | `process`, `process_source`, `refresh`, `refresh_source`, `scope`; registration, fairness, failure and recovery | Replace source enumeration and periodic refresh with keyed native Query subscription streams. Keep required registration before intake, accepted/consumed/resume floors, independent source progress, failure health, re-evaluation after relevant context/coverage/image changes, and explicit recovery. The current fresh Discovery stream collection is the reusable primitive; its profile publisher is not a graph publisher. A graph-specific consumer of the captured native rows still needs implementation. |
| `read.rs` | `snapshot`, `snapshot_result`, `findings`, `current_findings`, `next_current_findings`, `next_current_finding`, `current_finding`, `select_current_findings`, `finding_result`, `finding` | The durable behavior is already owned by Data: `graph_snapshot`, `graph_result`, `graph_findings`, `graph_finding`, and `graph_revision_finding`. Keep tenant/reference validation and bounded pagination at the public request boundary. Do not move a GraphAndFindingOwner reader facade or its execution mutex. |

### Existing owners that must remain

- `araphor-data/src/graph/input.rs::{normalized,manifest}` and
  `graph/model.rs::GraphReplayInputV1::validate` own canonical input identity,
  fact binding, and retained exact activation acknowledgement validation.
- `araphor-analysis-builtins/src/graph/{process,credential,kubernetes}` owns the
  detector algorithms. `graph/model/proof.rs` owns the shared proof predicates.
- `araphor-query/src/definition/{call.rs,physical.rs}` owns admitted call identity,
  exact image metadata, one complete return, state, reasons, evidence, and memory.
  `definition.rs::Session::execute_definition` owns capture and finite cleanup.
- `araphor-data/src/analysis/progress.rs::commit_graph_inner` checks exact evidence
  witnesses, witness deadlines, graph scope, and progress. `commit_progress`
  owns the transaction. `analysis/graph_rows` owns typed graph storage and its
  recovery checks. `analysis/graph/findings` owns current-finding selection.
- Traversal already works through `AnalysisSelectionV1::select_graphs`, Query
  captured source selection, Data `extraction/graph/traversal.rs`, native
  `analysis/graph/traversal/sql.rs`, and Control `client_grpc/query.rs` plus
  `client_grpc/wire.rs`. Keep this route. It does not need another graph engine.
- `mithril-control/src/store/graph.rs::graph_context` still contains the checked
  catalog, compiled-cell, exact workload, generation and acknowledgement-chain
  rules. The removed live trait bridge is not their replacement. Current
  ContextSource publication does not retain complete immutable ACK history.
  Publish that history through the existing context path and resolve it from
  the captured Data rows. Do not reduce it to the latest rollout row.

### Qualification transfer

The new finite family contains 28 tests. No Cargo check or test has been run by
this agent. Three existing JSON baselines were copied byte-for-byte.

| Behavior | Preserved test or required native adaptation |
|---|---|
| Host rejects valid-SDK but invalid-domain output | The seven old adapter tests now run under active `graph::tests`: exact reason, exact details, exact evidence, out-of-range candidate record, authority upgrade, missing coverage, declared details. |
| Policy and local cause authority | Active `tests/domain.rs`: retained ACK, exact generation history, exact local parent, same-operation contradiction, conflicting credential versions, contextual principal, mmap/read separation, missing lifetime, and HostRestricted findings. |
| Deterministic domain output | Active `tests/baseline.rs`: native, credential and all Kubernetes stage baselines. Active replay test preserves duplicate/reordered input normalization. |
| New input mapping boundary | Active `tests/binding.rs`: input batch splits and dataset order are accepted; changed record order, reviewed fact and missing dataset are rejected. Canonical input manifest is required. |
| Expiry transformation | Active `expiry_downgrades_all_proofs`: exact evidence/context manifest remains, edges become Superseded, all temporal proofs become Unknown, findings/packages lose confirmed state, deadlines stay unchanged, and the prior result remains unchanged. |
| Actual native execution and image identity | Adapt `derive/adapter/tests/native.rs`, `native/large.rs`, and `tests/installed/current/{descriptors,authority}.rs` to real PreparedDefinition/CallResult execution. Use SQL, Wasm and native images. Do not validate the producer only with direct detector calls. |
| Required intake, window joins, late evidence and source isolation | Adapt main `tests.rs::{required_registration_precedes_intake_without_discovery,new_source_registration_preserves_pending_other_source,window_boundary_preserves_credential_join}` and `tests/source_recovery.rs` to actual Query stream insertion/removal and Data required processors. |
| Relevant changes and no-op behavior | Adapt `tests/notices.rs`, `tests/notices/reuse.rs` and `tests/notice_storage.rs` to Query updates and native cut/revision equality. Preserve guest-call counts, no result mutation on no-op, and context checks before reuse. No periodic source sweep is permitted. |
| Expiry publication and recovery | Adapt `tests/{processing,window_expiry,evidence_recovery,installed}.rs` and main retry/restart/failure tests to native source/window events. Preserve earliest overlap deadlines, no progress advance on failure, exact historical result reads, recovery health, and idempotent expiry. |
| Storage and crash safety | Retain/adapt `tests/{native_storage,storage_contract,storage_windows,storage_recovery}.rs` and main result-crash tests against existing Data transactions. Preserve rollback, retry identity, mixed graph rows, package/context/witness references, backup/restore and corruption rejection. |
| Traversal and paging | Move or adapt `tests/traversal.rs`, its bindings/limits/recovery children, `tests/paging.rs`, and `read/tests.rs` to current Query/Data APIs. Preserve exact native lifetimes, directions, hop/fanout bounds, tenant/binding scope, cancellation/deadlines, current heads, historical replacement and restore. |

The Back crate cannot be removed on the finite adapter tests alone. The
captured graph input projection, authoritative ACK publication, native graph
subscription, guarded graph publication, and the listed native integration
tests are required replacement work.

## Discovery compatibility inventory

Source: the intact reference tree at `6a25ba1b34dbaa0a553b1883058938683ce7aaab`.
This inventory covers all 18 production modules under
`araphor-analysis_back/src/discovery`. `sdk/native.rs` is test-only.

| Reference module | Current equivalent and required action |
| --- | --- |
| `mod.rs` | Current Analysis registers and releases its Discovery owner. Do not move InstalledAnalysis, the context-provider reader, or the source cursor. Query subscriptions supply data. |
| `model.rs` | Data already owns require, same, checked addition, and InputByteLimit. Do not add another helper owner. |
| `context.rs` | Current Context owns import/review authorization and native SQL selection. It retains approver identity, tenant, subject, method, sensitivity, cutoff, conflict, and omission rules. Data validates documents and revision history. |
| `installed.rs` | Current immutable image pins and PackageBundleRef contexts replace installed export discovery. Replay still needs the exact retained closure and digest. Do not copy the old activation registry. |
| `replay.rs` | Keep source/CPU/cursor/interval checks, frozen fact identity, exact code selection, exact snapshot comparison, and explicit Unavailable results. Replace runtime.wait and the old replay reader with finite Query capture. |
| `live.rs` | Keep interval changes on code revision, monotonic time, contiguous progress, finalization, sampled witnesses and expiry, source-health provenance, frozen bindings, historical append, and final commit authorization. Current Publication preserves only part of these rules. Do not copy run_clock, source enumeration, raw read_page, or repeated cap-driven derivation. |
| `sdk/mod.rs` | Use current PackageCall and typed Query errors. Rows and InputRevision already supply codecs and revision hashes. Remove InstalledAnalysis dispatch and string-based error remapping. |
| `sdk/atoms.rs` | Native recorded_snapshot, observed_effects, and context_bindings SQL supply computation. Current Data validation checks independent returned-result provenance. |
| `sdk/snapshot.rs` | Native merge_snapshot SQL supplies merge computation. Builtins retains groups computation. Current Analysis output adapters and Data validators retain typed boundary conversion and validation. |
| `sdk/compare.rs` | Builtins retains comparison computation. Preserve reviewed-baseline validation, tenant checks, and comparison source-proof checks. |
| `sdk/context.rs` | Current Context codec and native selection retain deterministic packet revisions, subject/time windows, omission coverage, and exact metadata/payload agreement. Do not restore mandatory byte caps. |
| `sdk/pages.rs` | Do not move the fixed-size pager. Current PackageExec consumes complete relations. Preserve duplicate, sparse-range, orphan, lifecycle, empty-range, and batch-boundary test cases. |
| `sdk/validation.rs` | Current Data validation checks duplicate identity and conflicting values at the domain result boundary. |
| `sdk/validation/recorded.rs` | Current Data validation checks exact input accounting, source atom identity, context lifetime, physical result, disposition, and evidence. Snapshot self-validation is insufficient. |
| `sdk/validation/coverage.rs` | Native SQL supplies qualification. Current Data validation retains no-upgrade, retained-reason, and exact range-partition checks for returned results. |
| `sdk/validation/lifecycle.rs` | Current Data validation checks input-to-output lifecycle proof and recorded evidence membership. |
| `sdk/validation/merge.rs` | Current Data validation checks source identity, counts, atom evidence, dispositions, coverage, and lifecycle. |
| `sdk/validation/groups.rs` | Current Data validation checks exact group membership, counts, samples, and coverage proof. |

The current Publication writes `sealed: false` and an empty witness list.
Data stores and validates profiles, but storage does not replace the removed
finalization and provenance logic.

The original `recorded_rejects_host_changes` test constructs forged identity,
physical-result, and lifecycle values that pass BehaviorSnapshot::validate.
The result must still fail the input-to-output provenance validator.

### Test transfer

Keep context approval, cutoff, conflict, omission, subject-revision, import
history, SDK metadata, selector version, and baseline cases. Configure quota
cases explicitly; disabled limits remain the default.

Keep all four forged-output tests from `sdk/atoms/tests.rs`. Keep the atoms,
merge, comparison, and context JSON baselines. Keep corpus rare-export cases
through current native PackageCall execution.

Keep replay range, frozen-fact, missing-manifest, input-bound, retained-count,
and exact-revision cases. Use current Query capture and exact OCI pins.

Keep live transaction, crash, retention, boundary, finalization-without-intake,
deadline, capacity, stop/join, and notice cases through Query subscriptions.
Do not retain the old source-sweep fixture as the replacement.

### Current work

Data provenance validation is moved to `araphor-data/src/discovery/validation`.
The public boundaries are DiscoveryInputManifestV1::validate_result and
BehaviorSnapshotV1::{validate_merge, validate_groups, validate_comparison}.
The original four forged-output cases use immutable fixtures and no legacy
evaluator. All four cases pass. Eight native Query output-adapter cases also
pass, including unchanged corpora and rejection of forged attribution.

Active Analysis context work uses one finite Query document capture, native
MemTable inputs, native Planner, and Query Session execution. No second Engine,
SQL framework, legacy reader, or polling loop is required.

## Focused qualification and migration order

This section records the earlier finite source before the later managed
implementation. Its pending results and migration order are historical. Read
[Finite managed source](#finite-managed-source-focused-qualification) for the
current source and qualification.

The 2026-10-19 focused results below replace earlier pending notes for these
finite families. Logs are in `/tmp/araphor-oci-execution`.

| Scope | Evidence | Result |
| --- | --- | --- |
| Graph boundary | `migration-graph3.log`: 29 passed | Focused pass |
| Context | `migration-context3.log`: 17 passed | Focused pass |
| Data provenance | `migration-data-validation3.log`: 4 passed | Focused pass |
| Package comparator | `migration-fixtures3.log`: 4 passed | Focused pass |
| Query definition execution | `migration-definition16.log`: 53 passed and 2 view-fixture cases failed. The corrected view fixtures pass with both existing collision cases in `migration-collision17.log`. All 55 ordinary definition cases pass across these records; 4 native cases pass separately. | Focused pass; full gate pending |
| Guest preparation | Cold and cached deadline ordering, hidden native views, exact Runtime/image binding, and entered-worker cancellation/drop checks pass again in `migration-definition16.log`. | Focused pass |
| Admitted call identity | `migration-collision17.log`: all 4 cases pass. Changed inputs or SQL bodies fail before capture through every public execution entry and native views. CTE and multiple-output sharing remain valid. | Focused pass |
| Captured error receipt | `migration-failures14.log`: all 8 delivery cases pass. `migration-receipt14.log` passes the unchanged E2E error-frame and recovery assertions. | Focused pass |
| Disabled-default fixture setup | `migration-retention14.log`: all 5 extraction cases pass. Both Control graph and explicit-quota cases pass in `migration-control-graph14.log` and `migration-control-quota14.log`. | Focused pass |
| Immutable output attribution | The 6 unchanged Discovery adapter cases pass in `migration-output14.log`; both corrected forged-output cases pass in `migration-forged16.log`. Native SQL supplies altered test payloads without mutable attributed results. | Focused pass |
| Separate native Query run | `migration-native-query16.log`: 4 passed with the current source-built artifact | Focused pass |
| Discovery output adapters | `migration-output4.log`: 8 passed | Focused pass |
| Reactive notifications | `migration-reactive4.log`: 5 passed; `migration-deadline6.log` passes after removal of the Query source-name clock list | Focused pass |
| Fixture cancellation and authority | `migration-cancel6.log`: 1 passed; cancellation and revocation both join the entered guest and release capacity | Focused pass |
| Shared input capture | `migration-capacity6.log`: 1 passed with registered Arrow input, exact shared-pool pressure, retry, and full release | Focused pass |
| Admission identity | `migration-identity5.log`: 2 passed; foreign calls fail and valid multiple-output sharing remains | Focused pass |
| Package Runtime | `migration-runtime12.log`: 46 passed | Focused pass |
| Compiled image admission | `migration-admission10.log`: Wasmtime native bytes are rejected as a component binary, with exact Invalid classification | Focused pass |
| Native fixture qualification | `migration-native-qualification16.log`: accumulation and fixed clock/seed both pass | Focused pass |

The current full Rust gate is **Not done**. Its command record is
`migration-final-ci19.json` after completion. The command uses
`CARGO_BUILD_JOBS=2 CARGO_NET_OFFLINE=true RUST_TEST_THREADS=2` and the
repository-owned verification script. No reference
files are deleted. These results do not restore managed Control, CLI, or E2E
callers, or qualify an automatic Graph, Discovery, or notification producer.

Use this dependency order for the remaining Discovery replacement:

1. Qualify [Package's native call path](../../crates/araphor-analysis/src/package.rs).
   One cached admission replaces SQL body extraction and manual source/schema
   interpretation. Image installation remains separate. The adapter caches admission in
   memory and creates no definition or Data revision. Explicit durable
   definition admission retains exact source and image revisions. The profile publisher checks the actual
   admitted return and rejects auxiliary values that it cannot commit.
2. Record exact definition and image pins, source cut, ranges, immutable fact
   references, evaluation time, seed, and checkpoint lineage. Code changes
   must start a new interval. Preserve frozen successful attribution.
3. Apply finite domain validation before publication. Reuse PreparedProfile,
   guarded working-profile commits, and existing Data witness/context
   transactions. Add a final authority hook for sealed historical commits.
4. Extend the existing Query subscription execution to emit window completion
   once before row removal. Rolling row expiry and `clock_changed` do not
   prove interval completion. Seal and retain the selected evidence at that
   event; later input enters the next interval. Add no host scheduler.
5. Implement finite replay and refresh through the saved native definition.
   Require exact source, CPU, cursor, interval, fact, and code identity. Keep
   original framed bytes and explicit Unavailable results for missing input.
   Append sealed corrections without advancing current progress.

Durable checkpoint reuse/reset, atomic multi-call state publication, restart
recovery, and public managed operations remain **Not done**. Query prepares
cold Wasm under the parent request control before the execution budget starts.
Native views use the same preparation path. Configured compiler working-memory
limits and negative saved fixture times return Unsupported. The old compiler subprocess protocol has no active protocol
equivalent. Earlier Runtime tests do not qualify the old installed lifecycle,
committed-state recovery, or native revocation/expiry scenarios.

## Recovered prototype delta

This audit also checks the later uncommitted prototype. The baseline inventory
above remains unchanged. The recovered state has 30 changed paths: seven
modified tracked files, 21 deleted tracked files, and two added tests. The two
tests are part of the 30 paths. They are not two additional changes.

The preserved `pre-restore-reconstruction.json` records 208 baseline files:
180 unchanged, seven modified, and 21 deleted. The reconstructed tree has
189 files: the 180 unchanged files, seven modified files, and two added tests.
The 2026-10-19 audit recalculated all 30 entries against both independent
`runtime-first.json` and `definition-final.json` source manifests. Each check
matched all 30 entries. The 180 unchanged files also match the restored Back
tree. The [recovery archive](../../recovery/araphor-analysis-20261019-24zu3vty.tar.gz)
preserves the source bodies and verification records.

The recovered `package/tests/wasm/concurrency.rs` SHA256 is
`4ed0e627866f241189cc14742ca72e7c5b65936752015be4af76b17263a1edd2`.
The recovered `package/tests/wasm/preparation.rs` SHA256 is
`180adad4687c35f479c6b175eb79e1ea4acf845f63df21257c2384a417323d32`.
Both recovered files match their reconstructed copies and both independent
source manifests. These tests move existing baseline assertions to modules
that can use the extracted Runtime API. They add no new computation.

Paths in the first column are relative to `crates/araphor-analysis_back`.
An active equivalent identifies source ownership. A focused pass identifies
its test result. Managed lifecycle and integration remain removal gates.

| Recovered path and change | Classification | Current owner or remaining proof |
| --- | --- | --- |
| `Cargo.toml`: use Runtime and forward its fixture feature; remove direct backend dependencies | Active equivalent | [Query Cargo](../../crates/araphor-query/Cargo.toml) depends directly on Runtime. [Runtime Cargo](../../crates/araphor-package-runtime/Cargo.toml) owns Wasmtime, wasmparser, libloading, object, and native file support. The old Back dependency bridge is unnecessary. |
| `src/error.rs`: convert each Runtime error into the old error enum | Obsolete old architecture | [Query Failure](../../crates/araphor-query/src/error.rs) classifies typed Runtime causes through DataFusion external errors. [Analysis Error](../../crates/araphor-analysis/src/error.rs) retains Query and Data causes. Do not restore the old variant-copy adapter. |
| `src/lib.rs`: remove local backend Snafu selector exports | Active equivalent | [Runtime error.rs](../../crates/araphor-package-runtime/src/error.rs) owns the backend selectors. Active Analysis has no native or Wasm executor selectors. |
| `src/limits.rs`: reexport Runtime WasmLimits | Active equivalent | [Runtime limits.rs](../../crates/araphor-package-runtime/src/limits.rs) owns the optional limits. Query supplies Runtime configuration. No Back quota alias is required. |
| `src/package/native/mod.rs`: reexport NativeAdmission, NativeLibrary, and NativeLimits | Active equivalent | [Runtime native/mod.rs](../../crates/araphor-package-runtime/src/native/mod.rs) owns these types. [PackageExec::guest](../../crates/araphor-query/src/definition/physical/guest.rs) uses the current Runtime directly. The recovered Back reexport is unnecessary. |
| `src/package/wasm.rs`: reexport WasmExecution; add fixture preparation and observation wrappers | Active equivalent | [Runtime wasm.rs](../../crates/araphor-package-runtime/src/wasm.rs) and [fixtures.rs](../../crates/araphor-package-runtime/src/wasm/fixtures.rs) retain the runtime and fixture support. Query's guest-entry hook reaches the same runtime. The wrappers on AnalysisPackageOwner are obsolete. |
| `src/package/tests/wasm.rs`: declare the two recovered test modules | Obsolete old architecture | Active tests live at the current Query and Runtime owners. Keep the original declarations intact in the complete reference tree until removal gates close. |
| Delete `src/package/native/artifact.rs` | Active equivalent | [Runtime native/artifact.rs](../../crates/araphor-package-runtime/src/native/artifact.rs) retains target, CPU, ELF, dependency, symbol, and path validation. Only visibility differs. |
| Delete `src/package/native/files.rs` | Active equivalent | [Runtime native/files.rs](../../crates/araphor-package-runtime/src/native/files.rs) is byte-identical. Sealed file pins and mapped-file identity checks remain. |
| Delete `src/package/native/loading.rs` | Active equivalent | [Runtime native/loading.rs](../../crates/araphor-package-runtime/src/native/loading.rs) retains load, ABI validation, checked calls, release, cancellation, and typed errors. Only visibility differs. |
| Delete `src/package/wasm/admission.rs` | Active equivalent | [Runtime wasm/admission.rs](../../crates/araphor-package-runtime/src/wasm/admission.rs) retains source, interface, nesting, and resource validation. Policy bounds are explicit optional limits. |
| Delete `src/package/wasm/bindings.rs` | Active equivalent | [Runtime wasm/bindings.rs](../../crates/araphor-package-runtime/src/wasm/bindings.rs) retains the same host binding declaration. |
| Delete `src/package/wasm/cache.rs` | Active equivalent | [Runtime wasm/cache.rs](../../crates/araphor-package-runtime/src/wasm/cache.rs) retains digest identity, executable pins, cache charges, and release notices. Native Component::new replaces the old compiler transfer. |
| Delete `src/package/wasm/compiler.rs` | Obsolete old architecture | The user requires in-process Wasmtime compilation. The subprocess, fixed CPU/wall limits, and child reap owner are absent. Configured compiler working-memory limits remain explicitly Unsupported; synchronous active compilation is not interruptible. |
| Delete `src/package/wasm/compiler/image.rs` | Obsolete old architecture | No compiler reply pipe or supplied precompiled image is deserialized. Safe Component::new consumes checked component source. The private reply framing and digest protocol has no current boundary. |
| Delete `src/package/wasm/compiler/input.rs` | Obsolete old architecture | No compiler request pipe exists. CompileBudget and native Wasmtime source parsing own admission. Do not restore the private CBOR request codec. |
| Delete `src/package/wasm/compiler/input/tests.rs` | Obsolete old architecture | The three cases test the removed request framing, bounded transfer, and CBOR encoder. Configured source limits remain on CompileBudget; there is no replacement request wire format. |
| Delete `src/package/wasm/compiler/tests.rs` | Active equivalent with an unsupported boundary | Worker dispatch and reap cases refer to the removed subprocess. CompileBudget::check_size rejects supplied native images as component binaries. Runtime admission_rejects_native_images proves the exact Invalid result with real Wasmtime-produced bytes. Compiler memory limits remain Unsupported. |
| Delete `src/package/wasm/compiler/worker.rs` | Obsolete old architecture | Current binaries need no compiler-child startup hook. Native Runtime compilation supplies the implementation. Do not restore executable argument dispatch or a second compiler runner. |
| Delete `src/package/wasm/execution.rs` | Active equivalent | [Runtime wasm/execution.rs](../../crates/araphor-package-runtime/src/wasm/execution.rs) retains separate stores, host checks, configured fuel/resource limits, prepared-engine identity, and trap-code pins. Event-based EpochWatch replaces recurring epoch polling. |
| Delete `src/package/wasm/fixtures.rs` | Active equivalent | [Runtime wasm/fixtures.rs](../../crates/araphor-package-runtime/src/wasm/fixtures.rs) retains test component preparation, cache charges, and option separation. It adds no production Analysis owner. |
| Delete `src/package/wasm/fixtures/tests.rs` | Remaining test gap | Active Runtime retains both named tests. The option case uses image_bytes instead of the recovered compiler_bytes variant. It does not prove compiler working-memory enforcement. That configuration remains Unsupported. |
| Delete `src/package/wasm/tests.rs` | Active equivalent | [Runtime wasm/tests.rs](../../crates/araphor-package-runtime/src/wasm/tests.rs) retains the five admission, work-limit, evaluation-capacity, and event-based capacity-wait scenarios. |
| Delete `src/package/wasm/tests/runtime.rs` | Active equivalent | [Runtime wasm/tests/runtime.rs](../../crates/araphor-package-runtime/src/wasm/tests/runtime.rs) retains the six original runtime cases and adds explicit cancellation, dropped-future, and queued-deadline cleanup tests. |
| Delete `src/package/wasm/tests/runtime/batches.rs` | Active equivalent | [Runtime batches.rs](../../crates/araphor-package-runtime/src/wasm/tests/runtime/batches.rs) retains the original batch-preservation assertions. |
| Delete `src/package/wasm/tests/runtime/concurrency.rs` | Active equivalent, focused pass | [Query parity.rs](../../crates/araphor-query/src/definition/tests/parity.rs) restores nonempty two-tenant group, count, member, and evidence assertions through native registered Arrow inputs and PackageCall. The case passes in migration-query4.log. The Runtime overlap test also proves independent worker lifetimes. |
| Delete `src/package/wasm/tests/runtime/prepared.rs` | Active equivalent, focused pass | Runtime retains prepared-engine binding and trap-pin assertions. Query parity.rs proves cold preparation before evaluate_timeout, cached reuse, hidden native views, exact Runtime/image binding, cancellation, and complete permit/pool release. |
| Delete `src/package/wasm/tests/runtime/quotas.rs` | Active equivalent | [Runtime quotas.rs](../../crates/araphor-package-runtime/src/wasm/tests/runtime/quotas.rs) retains default-disabled execution, explicit fuel/timeout, and fixture option cases. |
| Add `src/package/tests/wasm/concurrency.rs` | Active equivalent, focused pass | This recovered test preserves the same nonempty assertions as the deleted runtime concurrency test through the temporary Back bridge. Query parity.rs supplies the native implementation and passes in migration-query4.log. Keep its result separate from earlier Runtime results. |
| Add `src/package/tests/wasm/preparation.rs` | Active equivalent, focused pass | Query preparation_precedes_evaluation_deadline puts a cold component in the cache before a one-nanosecond evaluation timeout. It checks cached reuse, caller control, evaluation permit, and full input/output pool release. The native physical planner owns preparation. |

No recovered change requires a second execution engine or a compatibility
facade on active Analysis. Native physical preparation uses the parent request
control before the execution budget starts. The focused deadline and cleanup
proofs pass. The recovery archive retains the complete reference. Each
unqualified reference file remains until its connected owner passes its
removal gates.
