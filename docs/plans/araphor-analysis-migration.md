# Araphor Analysis migration

Current saved-input ownership is in [Native saved-input retirement](#native-saved-input-retirement).

Current Query input ownership is in [Query input runner retirement](#query-input-runner-retirement).
That record supersedes the earlier instruction to keep Inputs::clocked and the old Query executor.

Replace the reference Analysis implementation without loss of domain rules.
Move compatible finite code to its current owner. Rewrite execution and
lifecycle code through Query subscriptions and native DataFusion plans.

## Intended end state

Keep authorization, attribution, recovery, evidence, and atomic commit rules.
Every program uses native SQL parsing, logical planning, optimization,
physical planning, and execution. Data owns durable transactions. Query
subscriptions supply source and window events. Do not add polling.
Running execution derives from these subscription streams. A replacement must
keep this ownership rule before its reference file can retire.

The user authorizes this migration on 2026-10-19 after recovery of the
reference source. The reference crate remains unchanged until each replacement
has source coverage and passing tests. A source move does not prove coverage.
The complete migration remains **Not done**. Reference removal is **Done**:
all 208 original files are retired; zero remain. The
[final retirement record](../../recovery/araphor-analysis-back-retirement-20261023.json) contains the
qualified source, checks and archive custody. Earlier counts and failed checks
below describe their original source states.

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
| Source recovery | All 208 reference files were recovered from local commit `6a25ba1b`. The archive retains the complete source and exact later prototype. The verified archive retains all 208 original files; no reference file remains. | Done |
| Complete source map | The tables below cover all 95 production source files and the root exports. Test families are listed with their rules. | Done |
| Native and Wasm runtime | Package Runtime passes all 46 current tests in migration-runtime61. The 15 relevant Query cases also pass. Native calls remain in process. Wasm uses native compilation and exact cancellation events. Configured compiler memory limits are Unsupported. Installed lifecycle parity remains open. | Partial qualification |
| Finite OCI execution | PackageCall and PackageExec retain complete typed returns. All 8 focused SQL contract cases and 4 source-built native Query cases pass. Separate admissions cannot share cached calls. The current final Rust gate is pending. | Focused checks pass |
| Shared subscriptions | Query carries complete per-step package returns and stable admitted call IDs. Native managed subscriptions use the captured view, saved cursor, SQL window events, and lifecycle checks. Explicit close and authority loss join workers. Selected progress and completed failure races pass focused checks. Known failed offers wait at their exact native cursor. The current final Rust gate and complete host supervision remain open. No separate package polling task exists. | Partial qualification |
| Graph boundary | All 31 focused Analysis Graph tests and 27 Data Graph tests pass. Data now owns request validation before native reads. Graph validates canonical captured input and actual detector returns. These tests do not qualify the automatic producer. | Finite boundary qualified |
| Discovery boundary | All 4 Data provenance tests, 12 output-adapter tests, and 11 complete native recorded SQL tests pass. Exact event projection, input revision, duplicate accounting, sparse coverage, and lifecycle checks pass. Live publication remains incomplete. | Finite boundary qualified |
| Context | All 17 focused Context tests pass. Active Analysis retains import authorization and native selection. Quotas are explicit options and disabled by default. | Finite boundary qualified |
| Fixture qualification | All 4 comparator cases and the corrected entered-guest cancellation/revocation case pass. Active Analysis uses native calls and current Test authority. Native accumulation and clock/seed cases pass. Negative saved fixture time returns Unsupported. | Partial qualification |
| Managed state and lifecycle | Finite and native subscription checks pass for immutable attempts, guarded state, atomic multi-call publication, saved frontiers, lifecycle comparisons, authority, cancellation, and known terminal outcomes. The internal reactive host admits retained running instances and drains actual workers before replacement. Original live claims cannot publish after clean reopen. Data admission starts no work. Public lifecycle and recovery integration remain open. | Focused checks pass; public integration Not done |
| Graph producer | Native source subscriptions admit Evaluate and Expire instances through the shared Host. Six feed cases pass, including source intake, stopped intent, retirement, denial isolation, stale grants, and caller abort. Control startup wiring and complete notice, expiry, and window qualification remain open. | Not done |
| Discovery producer | The native source feed uses the shared Host. Source membership, current authority, owner registration, and live Profile publication pass focused checks. Interval split, frozen facts, witnesses, seals, replay, and reviewed baselines remain required. The complete producer is not qualified. | Not done |
| Notification producer | Native SQL and the shared Host select and deliver candidates. All nine focused Analysis checks and six Control checks pass on source state 302. These checks include bounded capture, guarded pending attempts, clean reopen, retry and ACK deadlines, cancellation, startup, and disabled configuration. Complete source-failure recovery remains open. | Partial qualification |
| Public callers | Fresh Inspect status, original successful receipt history, complete output reads, and native retained queries pass through Control and CLI. Lightweight image and definition E2E cases pass with binary replies. Public start, stop, restart, and complete history selection remain open. | Partial qualification |
| Data coordination waits | Contended locks wait on unlock and cancellation notifications or an exact deadline. Native deadlines now send one interrupt and wait for an event. A native interrupt scope preserves cancellation across statement resets. All 21 Data, six Query and six Runtime focused checks pass. Read the scoped native interruption record below. | Done |
| Package quotas | SDK export, invocation, and retained-result quotas are removed. Non-time Graph window sizes are removed. External time windows remain. Native SQL selects rows. All 143 focused checks, strict Clippy, formatting, and workspace library test compilation pass. Versions stay unchanged. | Done for this removal |
| Retained result reads | Fresh Inspect authority, exact stored scope, native local SQL, original row indices and memory lifetime pass focused checks. Historical reads need no current Run permission or image execution trust. Public binary transport, CLI presentation, and current selected-result resolution pass focused checks. Full per-window heads remain open. | Focused checks pass |
| Final retirement | All 208 reference files are retired after mapped replacement checks and verified archive custody. The [final record](../../recovery/araphor-analysis-back-retirement-20261023.json) identifies the qualified source and confirms zero remaining files. Relevant checks cover this delivery; no full-workspace pass is claimed. | Done for reference removal |

On 2026-10-23, the user removes the package quota contract. The only package
window setting outside SQL is the time window. This instruction replaces the
earlier requirement to retain configurable SDK quotas with disabled defaults.
The current change removes all four SDK quota fields and their enforcement.
Identity, schema, Arrow validity, references, state, authority, and atomic
publication checks remain. Shared engine configuration remains separate.
Focused qualification passes. The record below identifies the exact source.

Data reader admission is now StorageLimitsV1.reader_admissions. Its default
is None, which creates no admission semaphore. Some(0) rejects reads with the
existing fixed quota error. Positive values use the native semaphore. The two
reader connections remain a separate execution pool. Focused checks pass.
The native-interrupt repetition is removed. Read the scoped native interruption
record below for current behavior and proof.

The old Query input executor has no active production caller. Its historical
removal preview estimated 986 production code lines. That preview also removes
native clock inspection and must not be applied. Keep `Inputs::from_plans`,
`scan`, `clocked`, and the shared receipt guards. No current removal count is
claimed for that executor.

Finite managed tests now reject a wrong returned evaluation time and stale
checkpoint reuse after input revision or coverage changes. A completed stateful
SQL retry survives reopen while the full input pool and only evaluation permit
are occupied. These tests do not replace live offered-cut retry, inherited
witness expiry, per-port deadlines, or source-scope rules. Native input qualification below now covers discarded local-port origins
and disjoint capture ranges. Mixed-window subscription expiry now passes the focused checks below. The audit covers 19 finite
and 22 live tests. Keep every remaining assertion until a current Query or Data
owner proves it. Executor removal is **Not done**.

The required final command is `bash .github/scripts/verify-rust-ci.sh` after
the last covered edit. The earlier full run, `migration-final-ci11`, passes
formatting, workspace compilation, strict Clippy, and test compilation.
Analysis passes 122 tests with 2 ignored. Builtins passes 20. SDK passes 82.
The run stops at two stale CLI command tests. The corrected CLI passes all
69 tests in `migration-cli12.log`.

The later complete run `migration-final-ci72` covers commit `098f66a7` without
source changes. Formatting, workspace check, and strict Clippy pass. Analysis
passes 151 cases, Data passes 337, Query passes 352, and Package Runtime passes
46. The run stops in Control: 27 cases encounter the same constructor rejection.
The constructor retains old 200-row and 1 MiB upper bounds while Query defaults
now disable those quotas. The narrow correction removes those upper bounds.
Native Query validation and delivery timeout validation remain. Both new
regression cases pass in `migration-control-limits74` in 2.843 seconds. All 30
gRPC cases then pass in `migration-control-grpc75` in 14.209 seconds. The
complete run takes 1,934.901 seconds and does not pass. Its failing group is
now corrected; the final complete procedure remains pending.

Retained-result Inspect and native local SQL pass focused checks in
`migration-retained-query76`, `migration-retained-analysis76`, and
`migration-retained-data76`. The replacement uses a fresh reader grant and
exact retained instance/result binding. The local native catalog contains only
the retained datasets. Data supplies retained descriptor limits without another
descriptor read. The writer's invocation limits do not set the later reader's
query limits. The exact retirement record below identifies the removed leaves.

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

### Native managed subscription qualification

The native stream slice is **Done** for the focused checks below. Complete
managed supervision is **Not done**. `Instance::subscribe` accepts the exact
running lifecycle and a separate control. Query owns source changes, SQL
windows, physical execution, and actual worker joins. Analysis receives no
clock. Data stores running intent separately from progress and the immutable
definition generation.

Query captures one physical source view. Data registers its exact attempt
before native child execution. The native Data sink commits complete package
returns, selected rows, saved state, and the native cursor in one transaction.
An unchanged recovered cut waits for source or window events. Unknown pending
work returns Incomplete instead of receiving a new identity or source cut.

Two streams assembled at the same initial progress exposed a real race. After
one stream commits two steps, the other stream could combine its old cursor
with new state and commit again. The new regression fails first on progress
12 instead of 10. The correction binds the selected progress to the stream
and advances this value only from its committed receipt. The same regression
then passes and preserves metadata, native frontier, output, and checkpoint.

| Record | Result | Seconds |
| --- | --- | ---: |
| `migration-managed-query80` | 97 captured, managed, local, follow, and physical stream cases pass. | 61.670 |
| `migration-managed-data80` | 24 managed and five image cases pass. The new large-image test fails on noncanonical expected artifact order. | 49.393 |
| `migration-image-data81` | All six image cases pass after canonical ordering. Exact byte and closure equality remain. | 24.078 |
| `migration-image-package81` | Saved fixture JSON, both times, maximum seed, and omitted-field defaults pass. | 0.083 |
| `migration-progress-red82` | The new progress regression fails on an actual duplicate commit before the fix. | 1.455 |
| `migration-progress-green-analysis83` | All 27 selected cases pass, including both source-built native cases and repeated saved SQL times. | 40.324 |
| `migration-managed-clippy84` | All targets and features in the 12 connected crates pass with warnings denied. | 74.062 |
| `migration-managed-build85` | The connected test build passes after six test-only lint corrections. | 72.130 |
| `migration-managed-data85` | All eight lifecycle cases pass after those corrections. | 7.965 |
| `migration-managed-fmt85` | Workspace formatting passes. | 4.383 |

The new guest fixture originally configured a 1 MiB output pool while its
explicit Wasm output and checkpoint budgets need an 8 MiB exchange for each
call. Its configured pool now holds both calls and native delivery. The full
pool-reclamation assertions remain. Production budgets are unchanged.

`/tmp/araphor-native-managed-provenance80.json` verifies all 116 native57 source
inputs and six artifact hashes against the current source. It qualifies
`x86_64-unknown-linux-gnu`. No benchmark or additional platform is claimed.

The later terminal and failed-offer source is described below. Idle suspension,
capacity retry, renewal, the host stream collection, public lifecycle operations,
and automatic recovery admission remain open. The mixed reference supervision
files remain. The complete final Rust procedure remains **Not done**.

### Known terminal outcomes and failed offers

Implementation and focused qualification are **Done**. The original
attempt remains held until Query joins its actual workers. Data then records
Cancelled or the exact package failure code. Failed work changes no successful
output, checkpoint, selected rows, or progress. A denied current lifecycle can
be suspended. An older lifecycle cannot suspend a newer start.

The fresh attempt holds a receiver from the existing store revision channel.
This receiver identifies the current open store without keeping the store or
its sender alive. A loaded pending attempt remains Incomplete. An original
pending attempt from an earlier open conflicts. Clean reopen keeps the durable
recovery epoch; the live channel comparison supplies this separate check.
Existing terminal retries remain idempotent and still check caller authority.

Data reads instance metadata, the native frontier, and the latest completion
revision in one snapshot. The completion revision replaces the stream's old
progress check. Capture, registration, and publication reject a newer completed
attempt even when successful progress stays unchanged. Schema 31 requires the
captured completion revision and validates this revision during recovery.

A known Invalid, Unsupported, Missing, or Conflict failure can resume at its
exact stored native frontier. Query waits there for a source or window event.
Cancelled work does not consume its offered cut. Unknown pending work and
ambiguous Incomplete or Limit failures remain explicitly unavailable. This
replacement adds no Query scheduler, Analysis clock, or polling task.

The first terminal checks, `migration-terminal-data88` and
`migration-terminal-analysis88`, find three defects: the live claim used only
a Boolean; finite validation rejected an exact retained native request before
the history lookup; and transparent error wrappers hid a permission notice.
The replacement uses the existing watch identity, moves finite-only validation
after history lookup, and inspects the actual transparent error variants.
The exact-expiry test also requires expiry at `expires_utc_ns <= now`.
All 83 connected behavior cases pass on unchanged covered source. Strict
Clippy passes for all targets and features in the 12 connected crates.

| Record | Result | Seconds |
| --- | --- | ---: |
| `migration-failure-build92` | Connected test build passes. | 20.059 |
| `migration-failure-data92` | All 35 managed Data cases pass. | 38.693 |
| `migration-failure-analysis92` | All 33 Instance cases pass, including both source-built native cases. | 73.906 |
| `migration-failure-query92` | All 15 native managed and error-category cases pass. | 6.596 |
| `migration-failure-clippy92` | All connected targets and features pass with warnings denied. | 103.852 |
| `migration-failure-fmt92` | Workspace formatting passes. | 4.702 |

The native source and artifact checks still match all 116 inputs and six
artifacts on `x86_64-unknown-linux-gnu`. The custody record
`/tmp/araphor-back-custody92.json` confirms that all 127 remaining reference
files match the recovered baseline and the archive checksum is unchanged.
No additional Back file is retired. Complete host supervision, pressure
retry, and the final complete Rust procedure remain **Not done**.

### Shared admitted images and error origins

Implementation and focused behavior checks are **Done**. Query retains one
sorted immutable image slice. Each admitted call borrows its descriptor from
that image. PreparedDefinition and its calls share the existing native memory
reservation. Instance no longer loads and retains a second image set. Data
still checks stored images and exact pins in its final transaction.

The image charge starts after Data decodes the image and before Query validates
and plans it. A cold preparation worker retains that charge until its result
is delivered or dropped. An entered guest retains the charge until it exits.
The charge covers defined payload and buffer capacities. This check does not
claim complete allocator or native planner accounting. Configured limits stay
optional and disabled by default. Retained instance spec and manifest capacity
contracts remain open; their mixed reference file is not retired.

Query now emits a typed AuthorityChanged notice. Only this notice can become
a cancelled offer after current authority checks. A real Data read denial
remains Denied. Runtime also delegates the SDK I/O retry hint. Interrupted and
WouldBlock remain retryable through native wrappers; PermissionDenied does not.

| Record | Result | Seconds |
| --- | --- | ---: |
| `migration-image-build97` | Connected test build passes. | 88.267 |
| `migration-image-query96` | 124 cases pass. Two fixture cases fail before correction. Four native cases are excluded from this command. | 187.090 |
| `migration-image-corrections97` | Both corrected fixture cases pass. The cold case reaches actual component compilation. The scratch case requires typed shared pressure before guest entry and complete pool release. | 7.989 |
| `migration-image-analysis96` | All 35 Instance cases pass, including both source-built native cases. | 66.990 |
| `migration-image-native-query96` | All four source-built native Query cases pass. | 12.634 |
| `migration-image-package96` | All four image capacity cases pass. | 0.121 |
| `migration-image-sdk96` | All seven SDK memory cases pass. | 0.104 |
| `migration-image-clippy97` | All connected targets and features pass with warnings denied. | 104.298 |
| `migration-image-fmt97` | Workspace formatting passes. | 5.212 |

The corrected tests change no production budget or accepted error class.
The earlier scratch fixture measured another image. The current fixture
measures its actual image and binding, then preserves exactly 64 KiB of
execution headroom. The incomplete Wasm header failed before compilation;
the current component has a parse-valid core function with an invalid result
type. Both tests keep their no-entry and full-release assertions.

Native artifact record `/tmp/araphor-oci-native-managed93.json` covers all
116 current source inputs and six artifacts on `x86_64-unknown-linux-gnu`.
Strict Clippy and formatting pass for this delivery. All 244 local document
links resolve. The complete final Rust procedure, host supervision, and capture-preserving pressure retry
remain **Not done**. All 127 remaining reference files stay unchanged.

### Reactive host, joined delivery, and component admission

Implementation and focused checks are **Done** for this bounded replacement.
The internal InstanceHost uses one FuturesUnordered collection as its member
registry. Data lifecycle notices supply membership changes. Query subscriptions
supply source and window events. The host has no polling clock. One store lease
remains held until all members and their actual workers exit.

A membership read starts after notice subscription. An older snapshot cannot
cancel a newer lifecycle. Replacement cancels the exact existing member and
waits for its drain before admission. A known failure affects that member.
An unknown pending attempt stays unavailable. Idle denial suspends only the
observed generation, lifecycle, and progress. Public lifecycle integration,
durable idle failure status, and retained metadata capacity remain **Not done**.

Initial and final authority callbacks use tracked blocking workers. A held
final callback does not stop healthy subscriptions. Stop and caller Drop keep
the instance, image reservations, and store lease until that callback exits.
Delivery preserves a Query error after a Data commit. Data retains the receipt
for an authorized retry. A real source denial remains Failed(Denied).

Configured component admission uses Tokio's semaphore. Managed work waits
asynchronously before exchange allocation and guest launch. The original
capture, attempt, time, and frontier remain unchanged. Default admission stays
unbounded. Finite calls retain typed Busy behavior. Actual worker exit releases
the slot. Native execution can retain an unfinished package future after its
stream is dropped. CallContext drains these exact shared futures before it
waits for workers. This correction adds no executor or source capture.

| Record | Result | Seconds |
| --- | --- | ---: |
| `migration-slot-build104` | Connected test build passes. | 231.635 |
| `migration-slot-analysis104` | Both previously failing slot and cancellation cases pass. | 20.014 |
| `migration-host-analysis104` | All 52 ordinary Instance cases pass. Two native cases lack the required directory variable. | 112.850 |
| `migration-host-native-analysis104` | Both exact native cases pass with the correct directory variable. | 17.803 |
| `migration-host-query104` | All 126 ordinary selected Query cases pass. Four native cases lack the required directory variable. | 190.503 |
| `migration-host-native-query104` | All four exact native cases pass with the correct directory variable. | 17.858 |
| `migration-host-data99` | All 38 managed Data cases pass on unchanged Data source. | 39.274 |
| `migration-native-runtime102` | All 48 Runtime cases pass on unchanged Runtime source. | 198.072 |
| `migration-host-clippy104` | All connected targets and features pass with warnings denied. | 101.025 |
| `migration-host-fmt104` | Workspace formatting passes. Retirement also requires a fresh successful formatting command. | 4.973 |

The first native commands supplied ARAPHOR_NATIVE_FIXTURE_DIR. The tests require
ARAPHOR_NATIVE_DIR. Their only failures report that missing variable. The six
corrected cases use the same source and native artifacts. All 116 native source
inputs and six artifact hashes still match native93.

The [error retirement record](../../recovery/araphor-analysis-error-retirement-20261020.json)
maps all 12 old variants, five helpers, conversions, and three embedded tests.
Current owners preserve typed codes, I/O retry hints, pressure, cancellation,
and actual denial. The complete 242-line production leaf is removed. No other
Back file changes. There are now **82 retired files and 126 unchanged files**.
The full archive remains intact. Complete migration, the production reduction
target, and the final Rust gate remain **Not done**.

### Retained metadata and durable failure status

Implementation and focused checks are **Done** for this bounded replacement.
PreparedDefinition shares resolved metadata, source requests, image handles,
and their reservation through one private Arc. Cloning that definition copies
no admitted metadata. Instance retains native extension nodes through their
existing Arc values. It charges its moved spec and manifest before admission.
Defined String and Vec capacities use checked arithmetic. Native planner and
allocator internals are outside this accounting claim. The later projected
membership result below completes retained host keys and source-request sharing.

Data retains one current failure fact on the instance row. Idle denial writes
that fact in the existing suspension transaction. A joined failed attempt writes
the fact in its terminal transaction only when the captured fences still match.
Stop and start preserve the fact. New successful progress makes the old failure
inactive. Recovery checks the failure, completion, and progress references.
Schema 32 adds this field without a compatibility loader.

Instance::read_status requires fresh Inspect authority and exact stored scope.
It reads no Arrow payload and admits no image. An expired writer grant does not
block a fresh reader. Current reader checks still protect final disclosure.

Finite execution records a known joined failure only before publication starts.
The existing Step records entry into the actual writer before final authority
and commit. Typed Busy, cancelled controls, uncertain publication, and process
loss stay pending. A committed lost acknowledgement keeps its original receipt.
No second classifier, history, or executor is added.

| Record | Result | Seconds |
| --- | --- | ---: |
| `migration-metadata-build109` | Connected test build passes after caller and fixture corrections. | 21.552 |
| `migration-metadata-new-data107` | All six new Data status and memory cases pass. | 12.246 |
| `migration-metadata-new-analysis107` | All eight new finite, Inspect, and memory cases pass. | 32.796 |
| `migration-metadata-new-query107` | Both new metadata ownership cases pass. | 1.130 |
| `migration-metadata-data107` | All 45 selected managed Data cases pass. | 61.420 |
| `migration-metadata-analysis107` | 59 cases pass. Two stale pending-outcome fixtures fail. | 144.763 |
| `migration-metadata-analysis-corrections109` | Both corrected cases pass. Actual publication failure stays pending. A known fixed row limit is Failed(Limit). | 1.241 |
| `migration-metadata-query107` | 138 cases pass. Two fixtures omit the retained admission charge. | 213.531 |
| `migration-metadata-query-corrections109` | Both corrected cases pass. Capture retains one byte of execution headroom; definition drop releases the complete pool. | 1.235 |
| `migration-limits-runtime108` | All 50 Runtime cases pass, including both transferred configuration cases. | 165.791 |
| `migration-metadata-clippy109` | Connected targets and features pass with warnings denied. | 19.686 |
| `migration-metadata-fmt109` | Workspace formatting passes. Retirement requires another fresh formatting command. | 4.659 |

The corrected fixtures keep all no-publication, no-child-entry, exact-attempt,
and full-release assertions. The earlier invalid SQL fixture returned a known
joined failure; it was not unknown pending work. The current host fixture reaches
the real BeforeResultCommit hook. The fixed row-limit test now requires an exact
terminal code and rejects replay of its terminated ID without another capture.

The [limits retirement record](../../recovery/araphor-analysis-limit-retirement-20261020.json)
maps all original fields, derived contracts, and both embedded tests to Runtime.
The complete 20-line production leaf is removed. Runtime retains the exact
disabled defaults, configured values, round trip, and unknown-field rejection.
Configured compiler memory and native resource limits remain explicitly
Unsupported; serialization does not prove enforcement. At that retirement,
there are **83 retired files and 125 unchanged files**. The recovery archive stays intact.
Complete migration, the reduction target, and the final Rust gate remain
**Not done**.

### Native input capture and projected membership

Implementation and focused checks are **Done** for this bounded replacement.
Native plans retain declared source origins through optimization. Each input
keeps its time envelope. Independent input windows use their exact range union.
An eliminated source scan still contributes its admitted receipt. Checked native
port identities prevent nested calls from binding another call's local slot.
These private identities do not change the persisted definition or plan hash.

SQL bodies pass inputs to nested calls through explicit relation arguments.
SourceSnapshot retains the parent SDK metadata beside its private bound rows.
The child input combines those revisions and coverage through the existing
receipt algorithm. The same capture supplies all rows, witnesses, and cuts.
Binding charges the defined SDK payload before cloning it. Arrow buffers keep
their existing shared claims. Opaque allocator headers are not estimated.

Data active membership returns only tenant, instance ID, generation, and
lifecycle. Each new member loads its full row once and checks those fences.
The host shares one charged key between its existing member and future. It
cancels stale members before it reserves new metadata. A capacity wait also
receives lifecycle notices, so Stop can release an old owner under pressure.
The old worker must join before a replacement admits. Managed Run borrows its
retained definition's source map instead of cloning that map.

| Record | Result | Seconds |
| --- | --- | ---: |
| `migration-input-host-build113` | Connected test build passes. | 22.985 |
| `migration-native-input-new112` | All 15 new native input cases pass. | 7.460 |
| `migration-host-projection-new112` | All four new host cases pass. | 10.345 |
| `migration-input-query112` | All 259 connected Query cases pass, including source-built native calls. | 236.384 |
| `migration-input-analysis112` | 64 Instance cases pass; the old full-spec metadata fault fixture times out. | 139.822 |
| `migration-input-analysis-corrections113` | The corrected projected-metadata fault and the added corrupt-member isolation case pass. There are 66 qualified Instance cases. | 1.676 |
| `migration-input-data113` | All 44 managed Data cases pass. | 44.689 |
| `migration-input-memory-package113` | All four image memory cases pass. | 0.095 |
| `migration-input-clippy113` | Connected targets and features pass with warnings denied. | 10.015 |
| `migration-fmt113` | Workspace formatting passes. Retirement repeats this check. | 4.535 |

The [memory retirement record](../../recovery/araphor-analysis-memory-retirement-20261020.json)
maps all 15 old helper methods, seven memory tests, and the native conversion
stream test. The complete three files are removed after these checks. This
removes 240 reference production lines and no test obligation. There are now
**86 retired files and 122 unchanged baseline files**. The archive remains
unchanged. Initial admission pressure retry, remaining operation assertions,
producer integration, public lifecycle, and the final Rust gate are **Not done**.

### Native operation assertions

Implementation and focused checks are **Done** for this test replacement.
The [native operation tests](../../crates/araphor-query/src/definition/tests/execution/contract/operation.rs)
cover complete inputs, qualified names, declared scope, exact revisions,
provenance, reused deadlines, and released capacity. The existing aggregate
output test now checks descriptor and invocation bounds independently. Its
volatile evidence expression remains unexecuted after a row-limit failure.

[PackageExec::collect](../../crates/araphor-query/src/definition/physical.rs)
now returns the existing SDK Limit error for an input bound. Shared pool
pressure remains Busy. Output bounds keep their existing classification.
Child, conversion, cancellation, and memory errors keep their original sources.

| Record | Result | Seconds |
| --- | --- | ---: |
| `migration-operation-build115` | Connected test build passes. | 262.684 |
| `migration-operation-new115` | All nine new or expanded operation cases pass. | 7.265 |
| `migration-operation-query115` | All 67 execution and guest cases pass, including source-built native calls. | 128.850 |
| `migration-operation-analysis115` | All seven finite failure and pressure cases pass. | 35.435 |
| `migration-operation-clippy115` | Connected targets and features pass with warnings denied. | 106.779 |
| `migration-operation-fmt115` | Workspace formatting passes. Retirement repeats this check. | 6.960 |

The [operation retirement record](../../recovery/araphor-analysis-operation-retirement-20261020.json)
maps all ten old test functions to passing native assertions. This removes
one complete test file and no production code. There are now **87 retired
files and 121 unchanged baseline files**. The archive remains unchanged.
Other model rules, initial admission pressure retry, producer integration,
public lifecycle, and the final Rust gate remain **Not done**.

### Reactive admission and guarded Graph publication

Implementation and focused checks are **Done** for this bounded correction.
Session preparation uses its existing memory scope. The host retries only
known reader or shared input/output pressure before an attempt exists. Failed
admission releases its retained image and metadata before the wait. Its own
release cannot wake that same scope. External capacity release, authority
changes, grant expiry, and stop remain events. Unknown pending work, Runtime
pressure, and fixed bounds do not enter this retry.

Data reader admission is optional and disabled by default. A configured zero
rejects reads without preventing a write. Configured positive values preserve
reader Busy and release notifications. The two native connections remain.

Graph writes keep the existing transaction. Changed publication and exact
immutable retry require a final caller check. Fresh publication compares the
exact tenant, processor, method, stream, and first-cursor head. Notice
acknowledgement also requires its final check. Generic commit_result rejects
Graph writes, so callers cannot bypass the guarded entry.

| Record | Result | Seconds |
| --- | --- | ---: |
| `migration-host-graph-build120` | Connected test build passes. | 21.434 |
| `migration-host-graph-data-new117` | All seven new reader and Graph guard cases pass. | 4.899 |
| `migration-host-graph-data-retained117` | All 16 retained Data cases pass. | 6.852 |
| `migration-host-all118` | All 25 host cases pass. | 36.778 |
| `migration-scope-all118` | All nine Query capacity cases pass. | 10.060 |
| `migration-graph-connected119` | All 39 connected Data Graph and native table cases pass. | 22.653 |
| `migration-graph-notification119` | 13 notification cases pass; eight replacement fixtures omit their prior head. | 25.017 |
| `migration-notification-corrected120` | All eight corrected notification cases pass with their original assertions. | 38.535 |
| `migration-host-graph-clippy120` | Connected targets and features pass with warnings denied. | 11.739 |
| `migration-host-graph-fmt120` | Workspace formatting passes. | 4.782 |

The [qualification record](../../recovery/araphor-analysis-host-graph-qualification-20261020.json)
identifies 106 distinct passing cases. It preserves the earlier compiler and
fixture failures and the exact corrections. Final formatting changes only
line wrapping in two test files. This delivery retires no Back file. All 121
remaining files and the recovery archive are unchanged. Complete producers,
public lifecycle, native Data waits, and the final Rust gate are **Not done**.

### Native model replacement

Implementation and focused checks are **Done** for this bounded replacement.
All 16 remaining model methods and 12 old tests have native assertion coverage.
The [model tests](../../crates/araphor-query/src/definition/tests/execution/contract/model.rs)
check complete output, prior and output checkpoint relations, evidence, reasons,
portable scalar boundaries, exact names, source revisions, retained buffers,
child deadlines, and native body time. Existing ordered-output assertions run
in current-thread, multithread, and blocking-worker contexts.

The [notification model test](../../crates/araphor-query/src/follow/tests/model.rs)
receives actual Query subscription deadlines. It adds no Analysis clock or
polling. The native pipeline, immutable admission seal, SDK validator, source
receipt, and existing Engine bridge remain the owners. No production code is
added. No old JSON parameter decoder or duplicate model executor is restored.

| Record | Result | Seconds |
| --- | --- | ---: |
| `migration-model-build122` | Connected test build passes. | 86.529 |
| `migration-model-new122` | All 13 new or expanded cases pass. | 9.039 |
| `migration-model-mapped122` | All 50 exact mapped cases pass. | 42.012 |
| `migration-model-clippy122` | Connected targets and features pass with warnings denied. | 24.014 |
| `migration-model-fmt122` | Workspace formatting passes. Retirement repeats this check. | 4.655 |

The [model retirement record](../../recovery/araphor-analysis-model-retirement-20261020.json)
maps every removed method and assertion. The five complete files are removed
only after these checks. This retires 306 production lines and no test duty.
There are now **92 retired files and 116 unchanged baseline files**. The archive
remains unchanged. Installed clock and supervision, mixed-window subscriptions,
other old input-runner rules, producers, public lifecycle, and the final Rust
gate remain **Not done**.

The separate old input-runner audit maps 28 functions, 19 finite tests, 22 live
tests, and 73 assertion groups. Its dedicated physical and live files contain
752 production lines. They are not ready for removal. Keep native plan binding,
clock inspection, and receipt guards. General scalar-clock events, per-port
expiry, raw lease renewal, retained witness expiry, unchanged restart, and
captured pressure retry still need exact native replacements.

### Public receipt reads and native input windows

Implementation and focused checks are **Done** for this bounded replacement.
Instance exposes fresh Inspect status, original successful receipt history,
complete package output, and native retained SQL queries through Control and
CLI. Data reads the instance, scope and receipt history in one controlled
transaction. Pending and failed attempts do not remove earlier successes.
History returns original receipts, not per-window heads or latest selection.
Selected SQL-only references can be listed; their public output reader remains
open. Public lifecycle and complete history parity remain **Not done**.

Data returns the original complete SDK wire Output after its existing retained
record validation. The read does not re-encode Arrow IPC or load a second
model descriptor. The public header retains exact image, export, target,
artifact, revisions, coverage and current status. It excludes the saved Run
grant and principal. Fresh Inspect authority protects initial and final
read disclosure. Control checks authority, expiry and client access again
after joined serialization. Historical reads need no current execution trust.

PackageResponseV1 is one exhaustive enum. The installed MessagePack codec
stores IPC and detail vectors as binary bytes and preserves fixed ID arrays.
The decoder rejects trailing bytes and invalid variants. The protobuf field
remains number 1 and is now named result. All current consumers use this
binary reply. CLI JSON is presentation. No compatibility decoder or mandatory
16 MiB clamp is added.

Each native PackageCall input retains its own admitted SQL window. SourceScan
collects actual ranges and row expiries for each input. One captured snapshot
supplies the next exact deadline to Progress. A metadata-only wake preserves
that deadline. Native SQL view planning already expands ViewTable plans.
The window validator accepts DataFusion's exact nanosecond-to-microsecond
bound coercion. Coarser casts and unsupported clocks remain rejected. This
replacement adds no Analysis clock, polling loop, or second physical executor.

The final focused records cover the same active source after the test-only
Clippy correction. The 53 connected Query cases pass. They cover independent,
dependent, nested and untimed inputs, outer-window isolation, native views,
precision, grant bounds, invalid clocks, metadata notices, and released buffers.
The SDK matrix retains every assertion in the old package_ipc_limits test.
Actual SQL, Wasm and source-built native calls compare retained target and
artifact with the admitted calls. Binary RPC and both CLI presentations retain
all outputs, checkpoint datasets, evidence and reasons.

| Record | Result | Seconds |
| --- | --- | ---: |
| `migration-inspection-build131` | Connected test build passes. | 434.950 |
| `migration-inspection-data131` | 16 cases pass. | 8.576 |
| `migration-inspection-analysis131` | 13 cases pass. | 18.227 |
| `migration-output-sdk131` | 14 cases pass. | 0.126 |
| `migration-history-data131` | 2 cases pass. | 3.018 |
| `migration-inspection-control131` | 7 cases pass. | 3.625 |
| `migration-inspection-cli131` | 8 cases pass. | 0.185 |
| `migration-output-native131` | 2 cases pass. | 11.919 |
| `migration-inspection-e2e131` | 2 cases pass. | 5.316 |
| `migration-window-connected131` | 53 cases pass. | 26.745 |
| `migration-inspection-clippy131` | Strict connected Clippy passes. | 115.270 |
| `migration-inspection-fmt131` | Workspace formatting passes. | 5.110 |

The initial failures were fixture and type errors. Corrections preserve the
assertions: use explicit UNION aliases, select the intended output dataset,
use a genuinely denied reader scope, keep supported scalar types, and use the
native Snafu source conversion. The SDK initializer correction removes only
a redundant struct update. Earlier failed command records remain available.

The [output retirement record](../../recovery/araphor-analysis-package-output-retirement-20261020.json)
maps six old methods and the full wire matrix. These checks qualify exactly
three whole files: package/status.rs, package/output.rs, and its wire test.
The retirement removes 90 reference production lines. There are now **95
retired files and 113 unchanged baseline files**. The full recovery archive
remains unchanged. The larger inspect.rs and input-runner files stay until
all their remaining rules pass replacement checks. Complete producers,
public lifecycle, recovery integration, and the final Rust gate are **Not done**.

### Metadata-first resume and checkpoint retries

Implementation and focused checks are **Done** for this bounded replacement.
Query probes an unchanged managed resume before native physical preparation.
Data checks the exact instance, pending work, selected completion, and source
revisions in one controlled transaction. The probe reads no source payload or
prior IPC. The same Query Progress receiver and saved deadline remain in use.
An idle probe finishes empty calls and releases its evaluation permit before
waiting. An actual worker retains that permit until the worker exits.

A source change or due deadline uses the existing native capture, immutable
attempt, physical execution and Data sink. Capture, registration and commit
keep their existing guards. An explicit rebuild bypasses both idle shortcuts.
The public ManagedPublication test executes again at the unchanged cursor.
No self-commit exception, polling loop, extra clock or second state owner is
added. Global relation notices can still force conservative capture for an
unrelated source. Exact suppression for that case remains **Not done**.

Six finite native tests now cover durable indices, foreign-tenant exclusion,
scoped revisions, captured time, catalog schema and bounds, buffer ownership,
generated input, and retained trace revocation. The real Instance test commits
checkpoint 1, joins, and resumes with every free input byte occupied. The
instance stays idle with its evaluation slot available and its exact receipt
and checkpoint unchanged. A later context event produces checkpoint 2 from
the same constant model input. Changed input still invalidates prior state.

Actual Wasm and source-built native tests retain the 3, 6, 9 checkpoint
sequence, completed retry before and after store reopen, exact artifact
identity, original complete output and context, and older-request retry after
newer state. Native overflow returns the typed SDK Limit. The successful head,
output and checkpoint remain unchanged. No selected output is published for
the failed attempt. All four explicitly configured operation slots release.

| Record | Result | Seconds |
| --- | --- | ---: |
| `migration-input-restart-build134` | Connected test build passes. | 22.685 |
| `migration-input-restart-fmt134` | Workspace formatting passes. | 4.592 |
| `migration-input-restart-clippy134` | Strict connected Clippy passes. | 123.035 |
| `migration-checkpoint-targets134` | 3 cases pass. | 24.169 |
| `migration-restart-query-connected134` | 62 cases pass. | 30.974 |
| `migration-restart-data-connected134` | 12 cases pass. | 7.305 |
| `migration-restart-analysis-connected134` | 7 cases pass. | 11.670 |

The first focused run finds three fixture assertions. The direct metadata
capture now checks the exact real context reference instead of using the
shared empty-fixture helper. The Query pressure tests require the full pool
while idle and zero retained input after the final definition owner closes.
The shared helper and production memory behavior do not change. Every failed
case then passes. The earlier command records remain available.

The [checkpoint retirement record](../../recovery/araphor-analysis-checkpoint-retry-retirement-20261020.json)
maps all 30 old assertion groups. Exactly two complete checkpoint test files
retire after these checks. This removes no production code. There are now
**97 retired files and 111 unchanged baseline files**. The archive remains
unchanged. The old input executor, mixed native restart and Wasm lifecycle
files remain. Retained dependency expiry, witness renewal, offered-cut pressure
retry, general scalar clock events, complete producers and lifecycle, and the
final Rust gate remain **Not done**.

### Graph and retained-result resource defaults

The replacement removes Graph record, fact, coverage, row, payload and variable
identifier ceilings. Shared result writes and reads also remove their fixed
body, metadata and reference-count ceilings. Recovery and copy paths accept the
same range. Existing SDK, Query and Data options still enforce explicit limits.
No additional resource owner is added. This change removes 122 production
lines and retires no Back file. All 111 remaining reference files and the full
archive remain unchanged.

The detector keeps its 300-second BOOTTIME join horizon. The default graph
traversal remains one outgoing hop. Subject and relationship failure limits
default to MAX. Native SQL uses NULL for an early-stop LIMIT only when its
value cannot fit BIGINT; actual configured count checks remain active. Stored
header counts and ordinals keep their existing u32 format and checked
conversions. Window reads use actual overlap without a 255-cursor assumption.

The 32 MiB read threshold remains batch and cache geometry. A large item uses
the existing single-item fallback. The threshold does not reject that item.
Data serialization/storage and Query array/exchange limits keep separate
owners. This change does not claim complete Rust heap accounting.

Implementation and focused qualification are **Done** for this bounded
correction. The first build finds a missing test import. The corrected source
passes the following checks without source changes during each command.

| Record | Result | Seconds |
| --- | --- | ---: |
| `migration-resource-build137` | Connected test build passes. | 90.554 |
| `migration-resource-fmt137` | Workspace formatting passes. | 4.970 |
| `migration-resource-clippy137` | Strict connected Clippy passes. | 98.094 |
| `migration-resource-data-connected137` | 94 cases pass. | 126.951 |
| `migration-resource-analysis137` | 56 cases pass. | 65.547 |
| `migration-resource-control137` | 3 cases pass. | 1.152 |
| `migration-resource-query137` | 6 cases pass. | 2.843 |

The [resource qualification record](../../recovery/araphor-graph-resource-defaults-20261020.json)
retains the exact source, commands, root test corrections and custody proof.
These 159 cases include large body/meta and actual witness persistence, exact
retry, reopen, backup/restore, native traversal and format checks, explicit
limits, cancellation, scopes and current authority. The domain tests use the
existing Builtins detector implementations. They do not qualify the automatic
native Graph producer. Evidence intake, encoded coverage reports,
Discovery batching, notification policy, legacy package literals and remaining
SDK descriptor boundaries still need their separate audit. Complete quota
qualification, producer replacement, Back removal and the final Rust gate
remain **Not done**.

### Storage window assertion transfer

Implementation and focused checks are **Done** for this exact test leaf. The
[current tests](../../crates/araphor-analysis/src/graph/tests/windows.rs)
preserve all three old test bodies, 35 test assertion sites and five helper
assertion sites. They retain header-only reads, strict continuation, exact
overlap, foreign scope, wide/short replacement, immutable history, unchanged
processor head, and corruption isolation. Only the former default range-ceiling
rejection is removed. The native Data overlap test instead requires a range
through cursor 1025 to pass. Zero and reversed ranges still fail.

The fixture uses supported Data registration, intake, coverage, commit and read
APIs. Existing Graph test derivation constructs expected domain snapshots. It
does not qualify the automatic producer. The existing workspace Prost package
is added only as a dev-dependency to encode the existing coverage input.

| Record | Result | Seconds |
| --- | --- | ---: |
| `migration-window-build138` | Connected test build passes. | 420.278 |
| `migration-window-fmt138` | Workspace formatting passes. | 5.173 |
| `migration-window-clippy138` | Strict connected Clippy passes. | 103.614 |
| `migration-window-analysis138` | 38 Graph cases pass. | 4.952 |
| `migration-window-data138` | Native wide-overlap case passes. | 1.556 |

The [retirement record](../../recovery/araphor-analysis-window-test-retirement-20261020.json)
identifies the exact source, original archived bytes and assertion map. Only
graph/tests/storage_windows.rs retires. This removes no production code.
There are now **98 retired files and 110 unchanged baseline files**. The full
archive remains unchanged. Producer, source advancement, lifetime, lifecycle,
recovery and the final full Rust gate remain **Not done**.

### Production code ledger

The current count147 includes the preceding native migration, extracted
provenance correction, public image fixtures and native baseline retirement. The storage-window transfer and native Graph
adapter qualification change no production code.
It excludes tests, comments, and blank lines. Moves cancel in the net result;
the retained Back source is included. No covered source changed during the
count.

| Baseline | Added production Rust | Removed production Rust | Net |
| --- | ---: | ---: | ---: |
| `6a25ba1b` | 16,585 | 8,990 | +7,595 |
| Original reduction baseline `7b7b407a` | 43,987 | 30,398 | +13,589 |

The finite managed deliverable at `7315cabd` adds 3,407 net production lines relative to
`95e9bb4d` (`13,825 - 10,418`). The required 6,000-line net reduction is
**Not done**. The later Wasm retirement removes 995 reference production lines.
Its Runtime correction adds one production line. This deliverable removes
994 net production lines. The next 15-file retirement removes 1,062 reference
production lines. Data request validation adds 19 production lines. This
deliverable removes 1,043 net production lines. The later eight-file retirement
removes 804 production lines and adds no production line. The retained-result
replacement adds 259 production lines and removes 149 reference production
lines. Its net change is +110. The separate Control correction removes four
production lines. Native managed subscriptions add 730 production lines.
The two image/fixture leaves remove 84 production lines. This delivery adds
646 net production lines. The mixed supervision files remain until their
complete replacements pass. This work restores missing behavior; it does not
yet reduce the complete production total. The later terminal and failed-offer
replacement adds 319 production lines and retires no additional reference
file. Shared image ownership and error-origin corrections add 251 production
lines and retire no reference file. The host, delivery, and component admission
replacement adds 505 production lines. Error retirement removes 242. This
delivery adds 263 net production lines. Retained metadata, failure status, and
finite failure recording add 396 production lines. Limits retirement removes
20. This delivery adds 376 net production lines. Native input capture and
projected membership add 420 production lines. Memory retirement removes 240.
This delivery adds 180 net production lines. The input-limit correction adds
seven production lines. Operation test retirement removes no production code.
Reactive admission and Graph guards add 207 production lines and retire no
reference file. Model retirement removes 306 production lines. The current
counter also excludes two test-only attribute/import lines in model/schema.rs
that the earlier counter incorrectly included. Public receipt/output reads,
original receipt enumeration and native input windows add 621 production
lines. The three retirements remove 90. This delivery adds 531 net production
lines. Metadata-first resume and explicit rebuild then add 109 production
lines. The checkpoint retirements remove test code only. The resource-default
correction removes 122 production lines. The extracted provenance correction
removes another 13. Public fixture execution adds 53. Another 19,589 net
production lines
must be removed relative to the
current count to meet the target. No
speed result is inferred from these counts.

The record is `/tmp/araphor-oci-execution-count147.json`. Its selected source
fingerprint is
`fbfc6d67d3f5ac370ba26047efdb0b04029db2d4e73e7e4e6b78f67a078c4d03`.
The earlier count145 has the same +13,589 production result. Its fingerprint is
`eb30b2103411f91a8e2528f63a9ab8ab3c0b1088bb97fc352f9d22971a4f7cdc`.
The earlier count142 records extracted provenance at +13,536. Its fingerprint is
`250c6bd51dc832117d8cb2881afb495f18911beee4a20bb86f581a60acbd6b9a`.
The earlier count138 has a +13,549 production result. Its fingerprint is
`d260ed09799d959fb6a1db0633efd5c07674b7d3a6dc39d03a9c4d363dd2ff40`.
The earlier count137 has the same +13,549 production result. Its fingerprint is
`13c415988c50cf51223c082f490b3f5adfa34f553d88a41635edc84de8dcd65c`.
The earlier count134 records metadata-first resume and checkpoint retirement
at +13,671 production lines from the original baseline. Its fingerprint is
`919f8aa8bfb6bb183e1c71497af61f886435f7cb5db762e2efe5c8ea89f4f113`.
The earlier count131 records public inspection, input windows and output
retirement at +13,562 production lines from the original baseline. Its
fingerprint is
`0bb41262738c88011c2f6c637e90316ea6f8a27c90bd7e11319dd9f1d7742561`.
The earlier count122 records model retirement at +13,031 production lines
from the original baseline. Its fingerprint is
`9c7ad010e35982feb615d921999936808d273ce077ee5d2875c9f7edb8ea12ee`.
The earlier count120 records admission and Graph guards at +13,339 production
lines from the original baseline. That result includes the two test-only lines
corrected above. Its fingerprint is
`ac385977f6fa6f4a1d5c7b1b692c54eaa4dd7ceec0d9c97737f37387e89f3290`.
The earlier count115 records the input-limit correction and operation test
retirement at +13,132 production lines from the original baseline. Its fingerprint is
`0f4f6cb8277d831edea72500719acb4256a49f9cc72173eb1f79d5a97ad2acb3`.
The earlier count113 records native input capture and projected membership at
+13,125 production lines from the original baseline. Its fingerprint is
`5bc47d095d98793e2d751cb46d86aaee7ae7ab118c0f1c16929f05100c689dbe`.
The earlier count109 records retained metadata, failure status, and limits
retirement at +12,945 production lines from the original baseline. Its
fingerprint is
`8432347cc06447b4605b1726616e9a9c5c78439cb915e1e76800ff02cfd75b4d`.
The earlier count104 records the reactive host and error retirement at +12,569
production lines from the original baseline. Its fingerprint is
`f613cab398713fef1b95dea59a3736d28efa6c43e1542e3fec052c4f6e6b6c41`.
The earlier count97 records shared images and error origins at +12,306
production lines from the original baseline. Its fingerprint is
`f0c2c62db1b093b1b4659822a42613a79741686508e81add70dfd90f0794f1b2`.
The earlier count92 records known terminal outcomes and failed-offer readiness
at +12,055 production lines from the original baseline. Its fingerprint is
`bc6aeb1e40ba4cf8ddda47288e8442f6019af00a194e89fb0a5cfd0ca9ec5ba2`.
The earlier count85 records native subscriptions and image/fixture retirement.
Its fingerprint is
`97942a8f09398ee44c94a2fe745013cbbda00d8b0f52d7edbdfea924dfff44af`.
The earlier count71 records the executor, component, atom, and pager retirement
at +10,984 production lines from the original baseline. Its fingerprint is
`ff4547f03bc8aa5701f8e0c1f063dab59a8fc208ec1738e9ace78bb28a5c3456`.
The earlier count67 records the finite Graph, SQL, and Discovery retirement at
+11,788 production lines from the original reduction baseline. Its fingerprint is
`a8065dc388d1182db14f530b2b088a5201cd801f709fc0610213cec6be0f6a27`.
The earlier count61 records the Wasm retirement at +12,831 production lines
from the original reduction baseline. Its source fingerprint is
`8b4cf5f003c2e3d08cf60d8117d74a584ff62da287fec5a96caec8a9ce27f264`.
The earlier count60 records the finite managed source before this retirement.
Its source fingerprint is
`6774e44ebda654a827dab6fe4389dbbd4b8e7e5d2b97d9ab4ca6f45176d2be78`.
Count58 has the same production totals as count60. Its source fingerprint is
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

After this four-file retirement, 33 files were retired and 175 baseline files
remained. The recovery archive retains all 208 originals.

The later [Wasm retirement record](../../recovery/araphor-analysis-wasm-retirement-20261020.json)
removes eight complete reference files. Runtime owns the engine and code cache.
Safe in-process `Component::new` replaces the compiler process, CBOR request
and reply protocols, pipes, PID checks, and fixed process CPU and wall limits.
The current compiler-memory option returns Unsupported. Synchronous compilation
cannot be preempted; cancellation joins the actual worker before acknowledgement.
Cache failure paths now drop compiled code before its retained byte charge.
Existing admission tests also check exact source bounds, failed admission
capacity, and both unsupported compiler-memory construction routes.

`migration-runtime61` passes all 46 Runtime cases in 151.295 seconds.
`migration-wasm-query61` passes 15 relevant Query cases in 57.470 seconds;
two native artifact cases are ignored in that Wasm-focused run. The separate
native60 runs cover those cases. The current owners and assertion map cover all
36 tests in the old Wasm family. Assertions for the removed process protocol
have no current execution boundary. The eight leaves remove 995 production
lines. The Runtime correction adds one production line.
Strict workspace Clippy passes after this retirement in
`migration-wasm-clippy62` in 83.945 seconds.

After the Wasm retirement, 41 files were retired and 167 baseline files remained.

The [Graph record](../../recovery/araphor-analysis-graph-retirement-20261020.json)
then removes four complete leaves: the old read facade and its pagination test
helper, output validation, and snapshot assembly. Data owns the request guards
and one native read snapshot. Current Graph owns the finite output transforms.
All 31 Analysis Graph, 27 Data Graph, and 21 notification caller tests pass.

The [output record](../../recovery/araphor-analysis-output-retirement-20261020.json)
removes one SQL output helper, three finite Discovery helpers, and seven pure
test or asset leaves. Native Query owns evidence and reason conversion.
Current Discovery adapters, native SQL, Builtins, and Data own snapshot,
grouping, comparison, and source-proof validation. The four baseline assets
remain byte-identical in their current owners.

| Check | Result | Seconds |
| --- | --- | ---: |
| `migration-graph-analysis65` | 31 passed | 0.710 |
| `migration-graph-data65` | 27 passed | 15.613 |
| `migration-graph-callers65` | 21 passed | 51.024 |
| `migration-discovery-analysis66` | 25 Context and Discovery cases passed | 75.585 |
| `migration-discovery-data66` | 4 provenance cases passed | 0.137 |
| `migration-discovery-builtins66` | 20 passed | 0.105 |
| `migration-discovery-finite-sql67` | 7 native merge and OCI cases passed | 10.849 |
| `migration-output-discovery-query67` | 10 native contract, admission, and tenant cases passed | 14.208 |

The first new ordering fixture failed because it had no configured capacities.
The correction uses explicit capacities and drops the retained result before
full pool checks. The final test preserves nonalphabetic output and checkpoint
order, reason program order, and exact admission rejection for an undeclared
reason output or code. The overbroad recorded-package selector was interrupted;
it is not a passed check. The exact finite merge selector passes separately.

There are now 56 retired files and 152 remaining baseline files. Every remaining
file still matches the baseline. The recovery archive is unchanged. Mixed
native, large-input, producer, replay, expiry, lifecycle, and recovery references
remain. The complete final Rust gate, migration, and reference removal are
**Not done**.

The later [native helper record](../../recovery/araphor-analysis-native-retirement-20261020.json)
removes eight more complete leaves. Query and Package Runtime replace the
component exchange helper. Native physical SQL execution replaces ModelRun.
Query captures complete relations. Native SQL, Builtins, and Data replace the
recorded atom adapter and pager. Four pure test leaves leave with those owners.
Every old function and assertion has a replacement map in the record.

| Check | Result | Seconds |
| --- | --- | ---: |
| `migration-native-source-build70` | Relevant test targets compile | 19.339 |
| `migration-native-helper-map70` | 17 executor and exchange cases passed | 31.987 |
| `migration-recorded-analysis70` | 23 output and native SQL cases passed | 79.312 |
| `migration-recorded-data70` | 4 provenance cases passed | 0.052 |
| `migration-recorded-query70` | 3 actual cancellation and join cases passed | 8.280 |
| `migration-recorded-builtins70` | Typed record proof passed | 0.051 |
| `migration-native-alias70` | Sliced arrays retain both pool charges | 0.048 |
| `migration-native-empty-schema70` | Empty IPC dataset retains its schema | 0.058 |

All 50 focused cases pass before removal. Ten new cases check the exact
remaining boundaries. These cases use actual native calls, source providers,
SQL execution, and Runtime exchange failures. They add no production owner.
The new cases keep sparse nested encoding, empty schema metadata, checkpoint
scratch, valid output conversion pressure, complete record projection, and
content-derived input revisions. They also keep duplicate counts, declared
coverage totals, empty ranges, and complete lifecycle references.

The old fixed page split and intermediate fragments have no native API.
Complete final semantics remain checked. No mixed Back root is edited to
repair historical module declarations. Back is not a workspace member.
There are now **64 retired files and 144 remaining baseline files**. All
remaining files and the complete recovery archive retain their exact bytes.
This deliverable removes 804 production lines and adds no production line.
Formatting passes after removal in `migration-native-format71` in 3.992 seconds.
Strict Clippy passes for all affected targets and features in
`migration-native-clippy71` in 89.972 seconds. All 193 local documentation
links resolve.
Complete migration, reference removal, and the final Rust gate remain
**Not done**.

The [retained-result record](../../recovery/araphor-analysis-retained-retirement-20261020.json)
then removes 15 complete leaves. The native local query replaces the old
ModelRun dataset helper. Native authority events and worker joins replace the
per-operation AuthorityWatch thread. Runtime and Query retain all 22 Wasm
fixture and execution assertions. Current NotificationRouter tests retain the
15 finite assertions from five removed test leaves. Notification production
and same-service tenant isolation remain open.

| Check | Result | Seconds |
| --- | --- | ---: |
| `migration-retained-build76` | Relevant targets compile | 80.114 |
| `migration-retained-query76` | 12 local SQL, indexing, and actual guest parity cases pass | 14.523 |
| `migration-retained-analysis76` | 37 Instance, authority, and notification cases pass; one native fixture case is ignored | 80.633 |
| `migration-retained-data76` | All 12 managed result and atomic commit cases pass | 18.497 |
| `migration-retirement-runtime76` | All 28 Wasm cases pass | 165.431 |
| `migration-retained-clippy76` | Strict checks pass for all affected targets and features | 102.147 |

The 89 focused cases pass before removal. The tests keep a complete historical
return after newer commits and writer revocation. They check current Inspect
denial, unchanged Data, original indices across Arrow batches, native interval
output, empty schema metadata, exact configured row/byte/batch limits, and
actual alias lifetime. Input arrays must be dropped before the full input pool
can be reserved again. The final test checks that lifetime directly.

The removed helper could override an explicit Engine row limit. A retained
SELECT now honors the native Session limit and retained descriptor limit.
The positive filtered-index case and explicit one-row rejection both pass.
Default quotas remain disabled. No source reader, parser, planner, executor,
clock, or polling task is added.

At that retirement, there are **79 retired files and 129 unchanged baseline files**. The
complete archive retains all 208 original files. The 149 removed production
lines are a gross reference count. The new authorized read and local query
code is included in the production ledger. Public result presentation,
codec parity, direct expired-writer proof, managed lifecycle, and complete
final Rust qualification remain **Not done**.

### Image and saved fixture reference retirement

The [image/fixture record](../../recovery/araphor-analysis-image-fixture-retirement-20261020.json)
maps every function and assertion in `package/lifecycle/revisions.rs` and
`package/fixtures/tests/clock.rs`. The current Data tests retain an exact
33 MiB payload, immutable retry, collision rejection, complete image closure,
reopen, and canonical OCI encoding. Fixture JSON retains both saved times,
seed, and complete expected output. Native SQL qualification runs both saved
times twice.

All six Data image cases, the Package context case, and the Analysis SQL cases
pass before removal. Current lifecycle checks and strict affected-target
Clippy also pass. There are now **81 retired files and 127 unchanged baseline
files**. The complete archive still retains all 208 originals. This retirement
removes 84 reference production lines. It does not qualify the remaining
mixed fixture, memory, lifecycle, output, or supervision files. Complete
retirement and the final Rust procedure remain **Not done**.

## Root exports

The reference `src/lib.rs` exports execution owners, duplicated model output
wrappers, and local quota types. Active Analysis exports finite Graph,
Context, notification operations, the current reactive Discovery owner, and
the Instance owner with focused finite and native subscription qualification. Package Runtime owns native and Wasm
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
contains the complete recovered source. The 29 earlier leaves, four additional
finite files, and eight Wasm leaves are retired at that earlier source state.
The latest custody record verifies all 106 remaining files against the baseline.
The complete 208-file source remains in the unchanged archive.

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
| `package/inspect.rs` | `activations; inspect; read_output; result_output; query_output; permits_selection` | Partial | Fresh Inspect status, successful receipt history, full output and native retained queries pass through Control and CLI. Full per-window heads, optional latest selection, readiness and installed lifecycle remain open. Keep the complete mixed file. |
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
| `package/output.rs` | `output_rows; encode_output; decode_output; decode_checkpoint; codec_result` | Retired | SDK codecs and typed errors, Data retained validation, and CLI native Arrow presentation preserve the mapped rules. All old wire assertions pass at the SDK owner. The mandatory 16 MiB clamps stay removed. |
| `package/removal.rs` | `remove; prune_package; prune_orphans; remove_closure; rehome_package` | Missing rules | Managed removal must protect shared dependencies, retain independent instances, release exclusive references and reconcile failed upgrades. Data owns collection; no source sweep. |
| `package/required.rs` | `required_bundles; ensure_required` | Partial | Builtin descriptors and components remain. Retain image factories for Discovery and all detectors. Remove implicit installation/activation and InstalledAnalysis construction. |
| `package/status.rs` | `receipt` | Retired | Data returns the original validated target, artifact, ID, revision, input revisions, coverage and current status. Actual SQL, Wasm and native target assertions pass. |
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

## Exact saved outputs in native inputs

A finite native definition can now read one exact saved package dataset.
`Session::register_retained` registers its table alias. Data creates the exact
result reference from stored metadata without loading Arrow IPC. The existing
native SourceProvider and source capture read that dataset in the same Data
transaction as the other inputs. Registration and reads change no output,
state or progress. The producer does not execute again.

Data checks the tenant, instance generation, call, result revision, producer
head, stored scope, source revisions, trace access, context heads and original
witness expiry. It bounds encoded and decoded input before bulk allocation.
Equal aliases share Arrow buffers. Each logical SDK input still contributes to
the configured model byte limit. The captured definition retains its metadata
reservation after the prepared definition is dropped.

Two native regressions first fail, then pass after correction. Registering the
same aliases in a different order must keep the same derived revision. A
changed result reference or changed rows must change that revision. A narrowed
or reordered projection must derive a new revision. Only the complete identity
projection can keep the original saved revision and coverage.

All 234 distinct focused cases pass, including four source-built native cases.
Connected compilation, workspace formatting and strict connected Clippy pass.
The reader-exhaustion test now sets an explicit 16-reader limit and uses a
bounded loop. Default reader admission remains disabled. Read the
[qualification record](../../recovery/araphor-retained-input-qualification-20261020.json)
for source hashes, failed regressions, passing commands and buffer-lifetime
proof.

No Back file retires. All 106 remaining reference files match the baseline.
The complete archive is unchanged. Managed publication, native follow, durable
alias recovery, readable expired inputs with Unknown coverage, model-wide
expiry downgrade and witness deadlines remain **Not done**. The separate Data
lock and native-interrupt polling paths remain open. This delivery adds 744
production lines. The total from the original baseline is +14,333. The required
net reduction and complete final Rust procedure remain **Not done**.

## Native image closure reuse retirement

Four new tests execute the exact native image closure and retained Instance
under current authority. They preserve clone and image ownership, complete
buffer release, engine and tenant isolation, and real dependency results.
The native definitions select one, two, one, then zero images. An installed
unused image starts no work and enters no closure. The older definition keeps
its immutable image while a new revision returns a changed dependency value.

Explicit SQL declarations replace the old active-root registry. An immutable
OCI revision rejects changed bytes at the same key and writes no partial
new dependency. A declared new revision returns the new value. This replaces
the old mutable same-version activation generation rule. These tests do not
prove a changed managed Instance generation. Lifecycle, removal and renewal
remain separate gates.

All four new tests and 27 mapped owner tests pass. Connected compilation,
formatting and strict Clippy pass after the reference deletion. The initial
test draft used an absent output-pool getter. The corrected tests reserve and
drop the complete configured output pool to prove release through the actual
owner API. No production getter or wrapper is added.

Only `package/installed/read/tests/retained/reusing.rs` retires. Its bytes match
the recovery baseline and complete archive before deletion. There are now
103 retired files and 105 unchanged reference files. This removes no production
code. Read the [retirement record](../../recovery/araphor-native-reuse-retirement-20261020.json).
The production total stays +14,333 from the original baseline. The complete
migration, net reduction and final shared Rust procedure remain **Not done**.

## Saved input identity includes discarded origins

The new regression first shows a saved input keeping its original revision
while an unused native CTE declares another source. The identity shortcut now
requires exactly that saved output as the declared origin. Otherwise the
existing native input hash includes the complete context and result references.
Changed context or a changed second saved result must change that hash even
when the selected rows stay equal. The direct input keeps its original revision.

All 45 focused cases, connected compilation, formatting and strict Clippy pass.
Read the [qualification record](../../recovery/araphor-retained-origin-qualification-20261020.json).
The correction adds two production lines and no owner. No reference file retires;
all 105 remaining files and the full archive are unchanged. The production total
is +14,335 from the original baseline. The complete migration, required net
reduction and final shared Rust procedure remain **Not done**.


## Finite native Graph source retirement

The production finite Graph source now replaces the earlier test-only adapter
limit. `GraphPublication` captures the declared native source children once,
binds the three complete detector inputs through Query `SourcePort`, and
executes the exact admitted OCI calls through `PackageExec`. Captured Control
facts use the original context rows and consulted candidate and ACK references.
The Graph sink validates all three actual returns and commits through the
existing guarded Data transaction. This route sets `advance = false`.

The following complete reference leaves retire after replacement qualification:

- `graph/derive.rs`, `graph/coverage.rs`, and `graph/derive/adapter/mod.rs`.
- `discovery/sdk/mod.rs` and `discovery/sdk/native.rs`.

The Discovery replacement uses declared native inputs, sealed `CallResult`
validation, and the existing Data provenance guards. Two actual Wasm/native
cases compare all four Discovery exports and their complete returned contracts.
Query owns invocation identity and evaluation time. The old private adapter
and its custom evaluation identity and time are not retained as public policy.

The selected qualification contains 255 distinct passing crate and test names,
including eight actual native cases. Final connected compilation and strict
Clippy pass. The last affected Data, Control, Analysis, and Query cases pass;
final formatting also passes. The record preserves earlier failures and their
later passing exact test names. Read the
[retirement record](../../recovery/araphor-native-graph-source-retirement-20261021.json)
for source hashes, native artifact provenance, commands, logs, and custody.
The [reading route](../guides/araphor-discovery-definition-review.md#finite-native-graph-source-and-publication)
explains the current production boundaries.

This removes 512 reference production lines. There are now 108 retired files
and 100 remaining files. Each remaining file matches the recovery baseline;
the complete archive is unchanged. The latest production count is +10,642
from the recovery baseline and +16,636 from the original baseline. The change
from the prior committed count is +2,301, including these reference deletions.
These figures do not meet the required net reduction.

Replacement and retirement of these five leaves are **Done**. Automatic Graph
advancement, producer recovery, Discovery live and replay ownership, remaining
resource and polling work, the complete migration, the required net reduction,
and the final shared Rust procedure remain **Not done**. This finite route
adds no public Graph recovery API for a lost acknowledgement.


## Finite native Notification retirement

Status: **Done** for these five finite leaves. This entry covers only the finite
Notification rules and native work discovery. The five retired leaves are
`notification/mod.rs`, `notification/routing.rs`, `notification/delivery.rs`,
`notification/tests.rs`, and `notification/tests/isolation.rs`.

Data exposes exact primary and escalation references and a Boolean for an ACK
of the current finding revision. Native SQL compares action with null-safe
equality and severity and sensitivity with their declared monotonic ranks.
Concern route refresh uses an authorized current primary and retained escalation
references. A current ACK suppresses concern refresh; a stale ACK does not.
The finite consumer preserves per-item errors and calls the retained Router and
send owners. Existing send owners preserve authority, attempt history, and original
deadlines. Query owns source notices and exact retry and grant deadlines.

Seven complete DISTINCT predicates now have parentheses. The pinned native
parser otherwise consumes a following AND or OR as part of the right operand.
The correction preserves the intended null-safe comparisons and all assertions.

StorageLimitsV1 owns optional notification_routes and notification_states
counts. Both default to None. Configured aggregate reads still reject excess rows.
Persistence uses the existing context_max_bytes owner instead of a separate
32 KiB Router ceiling. Identity, uniqueness, authorization, immutable attempts,
and original ACK deadlines remain enforced.

Qualification: 42 distinct passing tests cover Analysis 31, Data 7, Query 2, and Control 2. The final connected test build, strict Clippy, formatting, and corrected concern case pass. The record retains the exact source for each run.
Retirement record: [commands, hashes, and exact test names](../../recovery/araphor-native-notification-retirement-20261021.json).
Custody and archive verification: all 95 remaining files match the recovery baseline and complete archive. The archive is unchanged.
Remaining files and production counts: 113 files are retired. This change removes 323 reference production lines and has a net reduction of 288 production Rust lines. The totals remain +10,354 from the recovery baseline and +16,348 from the original baseline; the required overall reduction is not met.
The [reading route](../guides/araphor-discovery-definition-review.md#native-notification-eligibility-and-delivery)
explains the current owners.

Automatic Control subscription installation, failed-offer retry and shutdown
remain **Not done**. Control's 256-item configuration limits, policy package
and retry limits of 16, and the 48-attempt history ceiling remain outside this
change. Their remaining work, complete migration, required net reduction, and
the final shared Rust procedure remain **Not done**.


## Fixture comparator test retirement

Status: **Done** for `package/fixtures/tests.rs`. Five current comparator tests
and the actual public image fixture RPC pass. They preserve all three old test
bodies, including split batches, dataset and reference order, changed reason
details, nested floats, null values, and numeric tolerance. Invalid checkpoint
versions fail native SDK validation. Connected compilation and strict Clippy pass.
Read the [exact qualification and custody record](../../recovery/araphor-fixture-test-retirement-20261021.json).

There are now 114 retired files and 94 unchanged reference files. The complete
archive retains all 208 originals. This test-only deletion removes no production
code. The production totals remain +10,354 from the recovery baseline and
+16,348 from the original baseline. Production `package/fixtures.rs` stays:
negative fixture time and contained-artifact fixture selection remain open.
Complete migration, the required net reduction, and the final shared Rust
procedure remain **Not done**.


## Complete native Graph adapter test retirement

Status: **Done** for `graph/derive/adapter/tests.rs`, `tests/native.rs`, and
`tests/native/large.rs`. Fourteen distinct current tests pass. The actual native
and Wasm calls compare complete three-detector Graph snapshots for all six
selected and gapped inputs. Replay also matches the original trusted output.
The explicit output-pool test retains the exact shared-output error, checkpoint
alias lifetime, release and successful replay assertions. Connected compilation
and strict Clippy pass. Read the [exact assertion and qualification record](../../recovery/araphor-graph-adapter-test-retirement-20261021.json).

There are now 117 retired files and 91 unchanged reference files. The full
archive is unchanged. This test-only change adds and removes no production
code. Production totals stay +10,354 from the recovery baseline and +16,348
from the original baseline. Automatic Graph advancement, expiry and recovery,
complete migration, required net reduction, and the final shared Rust procedure
remain **Not done**.


## Native target build retirement

Status: **Done** for the old `build.rs`. The current Package Runtime build
script has identical bytes and supplies the compiler target to NativeAdmission.
Four current native admission tests pass. The preceding actual native Graph
checks also pass on the same current Runtime. Read the [retirement record](../../recovery/araphor-native-target-build-retirement-20261021.json).

There are now 118 retired files and 90 unchanged reference files. The full
archive is unchanged. This deletion removes eight production code lines. Totals
are +10,346 from the recovery baseline and +16,340 from the original baseline.
Complete migration, required net reduction, and the final shared Rust procedure
remain **Not done**.


## Native traversal test retirement

Status: **Done** for the five `graph/tests/traversal` reference leaves. Nine
current native Query tests pass. All 56 original literal assertions stay.
The cases preserve 16,385 unique subjects, 32,769 edges, exact directions and
lifetimes, configured limits, cancellation, historical bytes, and complete
receipts across reopen and backup/restore. Four real built-in image revisions
also survive restore. No production owner, execution layer or limit is added.
Connected compilation and strict Clippy pass. Read the [qualification record](../../recovery/araphor-native-traversal-test-retirement-20261021.json).

There are now 123 retired files and 85 unchanged reference files. The complete
archive is unchanged. This transfer changes no production code. Totals stay
+10,346 from the recovery baseline and +16,340 from the original baseline.
Complete migration, required net reduction, and the final shared Rust procedure
remain **Not done**.


## Native package composition and descriptor test retirement

Status: **Done** for `package/tests/admission/cycles.rs` and
`package/installed/read/tests/descriptors.rs`. Three current Query tests pass.
They preserve exact cycle rejection and no partial writes, internal composition,
the complete shared-artifact descriptor, actual Wasm execution, exact replay
metadata, and retained Arrow buffer pressure and release. Native SQL executes
the auxiliary. No production API or activation owner is added. Connected
compilation, strict Clippy and formatting pass. Read the [qualification record](../../recovery/araphor-package-test-leaf-retirement-20261021.json).

There are now 125 retired files and 83 unchanged reference files. The complete
archive is unchanged. Production totals stay +10,346 from the recovery baseline
and +16,340 from the original baseline. The mixed Wasm metadata/lifecycle file
stays. Complete migration, required net reduction, and the final shared Rust
procedure remain **Not done**.


## Native Graph storage contract test retirement

Status: **Done** for `graph/tests/storage_contract.rs`. Both current owner tests
pass after actual Wasm package execution through native GraphPublication. All
15 old assertion rules remain; 30 current assertions check complete native image
contexts, corrupt-row independence, exact rollback, retry, provenance and body
bytes. No production owner or API is added. Connected compilation and strict
Clippy pass. Read the [qualification record](../../recovery/araphor-native-graph-storage-test-retirement-20261021.json).

There are now 126 retired files and 82 unchanged reference files. The complete
archive is unchanged. Production totals stay +10,346 from the recovery baseline
and +16,340 from the original baseline. Complete migration, required net
reduction, and the final shared Rust procedure remain **Not done**.

The private package supervisor stays. Three exact replacement checks remain:

- Preserve safe capacity waits without repeating a guest or sink that has entered.
  Synchronous native DataFusion allocation failure has no qualified resume path.
- Save a known admission failure before an attempt exists, with the current
  generation, lifecycle and progress fences. Preserve unknown pending attempts.
- Test retained-image admission when stored bytes change during authorization.
  Keep the Data digest guard; do not add an unqualified cache or bypass.


## Wasm interruption test retirement

Status: **Done** for `package/tests/wasm/interruption.rs`. Nine current owner
tests pass. Actual Wasm calls preserve typed cancellation and denial, joined
worker capacity, no publication, and unchanged saved checkpoints. The exact
entered-guest barriers replace the old activation polling. No production code
is added. Read the [assertion and qualification record](../../recovery/araphor-wasm-interruption-test-retirement-20261021.json).

There are now 127 retired files and 81 unchanged reference files. The full
archive is unchanged. The shared interruption helper and native expiry tests
stay. Production totals stay +10,346 from the recovery baseline and +16,340
from the original baseline. Complete migration, required net reduction, and
the final shared Rust procedure remain **Not done**.

## Required package declaration retirement

Status: **Done** for `package/required.rs`. Nine exact current cases pass before
the whole reference file is removed. The existing OCI types and Data writer
retain the four original built-in descriptors, all exports and complete Wasm
bytes. Retry returns the original receipt without metadata or revision changes.
Installation starts no Discovery. Reopen and backup restore retain all four
image revisions. Actual native Query plans execute each built-in component.
Read the [declaration and qualification record](../../recovery/araphor-builtin-image-retirement-20261021.json)
and the [reading route](../guides/araphor-discovery-definition-review.md#built-in-image-installation-proof).

There are now 128 retired files and 80 unchanged reference files. The complete
archive retains all 208 originals. This leaf removes 86 production code lines.
The test fixture adds no production owner or registry. `required/testing.rs`
stays with its remaining reference callers. Historical image replay, grant
renewal and complete producer lifecycle remain **Not done**.

## Managed Wasm exchange lifetime

The complete run `ci205` passes formatting, workspace checking and strict
Clippy. Analysis then passes 288 cases, fails one and ignores 15. The failed
capacity-wait case reports a shared-output reservation error. The exact case
passes alone, but that result does not identify the cause.

The new Runtime assertion observes the sole slot inside worker lease
destruction. The assertion fails before the fix: the slot is already available.
EvaluationLease now retains slot lifetime through worker exchange cleanup and
Query output accounting. EvaluationPermit remains unique and cannot be cloned.
Both original Analysis capacity cases pass with the unchanged 8 MiB pool and
all assertions. All 16 exact focused cases pass. Read the
[failure, correction and source record](../../recovery/araphor-wasm-exchange-lifetime-20261021.json).

The lifetime correction adds 17 production code lines. The earlier immutable
retry correction adds three. The verified production deltas from `ced981a2`
therefore change the earlier totals by 20 added lines and 86 removed lines.
Totals are +10,280 from the recovery baseline and +16,274 from the original
baseline. This calculation uses the earlier syntax count and exact later
production changes. It is not a new complete syntax-counter run. Blank lines,
comments and test code do not contribute. The required net reduction remains
**Not done**.

The final shared Rust procedure `ci206` passes after the last covered edit.
Formatting, workspace checking, strict Clippy and all 95 workspace test targets
pass in 1,640.673 seconds. The tests pass 2,779 cases and ignore 564. Ignored
native artifact, release-only and physical-environment cases are not qualified.
No covered source changes during the command. The base is `cd843f23`; the
[final source, command and custody record](../../recovery/araphor-analysis-retirement-final-20261021.json)
identifies the exact working source. The final archive check and all 80 remaining
reference file checks also pass.

Status: **Done** for the named removals and final shared Rust procedure.
Complete migration and the required net reduction remain **Not done**. The next
identified lifecycle gap is renewal of a suspended instance under a new grant.
The replacement must retain original attempt attribution, successful output,
checkpoint history and generation fences. Keep the old lifecycle files until
their complete replacements pass.

## Stopped retirement checkpoint

Status: **Not done**. There are 129 retired reference files and 79 remaining
files. All remaining files and the complete recovery archive retain their
original bytes. No additional reference file was removed at this checkpoint.

The frozen source passes workspace checking in `check221`. `data223` passes
70 Managed and Profile cases. `query223` passes eight clock, fixed-window and
replay cases. `control225` passes the actual Host shutdown case. `analysis223`
passes two historical replay cases and the contained-artifact fixture case.
It fails four new domain admission cases. `preflight222` records compilation
before oversized input rejection. These results do not qualify the later
Profile provenance correction or the new finite-continuation regression.

Automatic approval review rejected shared Host wiring into Control startup,
client state and shutdown. The production patch was not applied. Specific
approval is required for the [proposed integration](../../recovery/araphor-control-host-proposal-20261022.md).
Implementation stopped at this boundary. The
[checkpoint record](../../recovery/araphor-retirement-stop-20261022.json)
contains exact commands, results and custody checks. The recorded work archive
retains all 805 current source files and the implementation drafts.

The final shared Rust procedure does not cover this source. Complete retirement,
native finite continuation, active lifecycle changes, source feeds, delayed
window recovery and the required production reduction remain **Not done**.


## Shared execution owner

The user approves the shared Host consolidation on 2026-10-22. Control and
Discovery now share one `InstanceHost`. Control uses its existing task slot to
start and join that Host and the source subscription feed. The feed admits,
starts, and stops membership. It owns no second package execution stream.
Image installation and definition admission start no work.

Status: **Not done**. The shared Host shutdown test and independent startup
configuration test pass in `control250`. Fourteen Host and restart checks pass
in `host249`. The finite Discovery publisher is removed. Finite calls and
subscriptions use the same native Query publication path. The prepared-instance
handoff now retains that prepared owner through the existing Host pause channel.
Its new immediate start, stop, restart, and recovery check is not yet qualified.

The corrected frozen Graph input and native clock expiry checks pass in
`graph253`. Eleven Profile and package subscription checks pass in
`discovery253`. The source-built native package subscription passes in
`native-package253`. These runs preserve exact returned-call identity,
auxiliary-output rejection, unchanged domain state on failure, retained context,
and current authority. The source-isolation test fails in `source253` before
revocation: it waits for a raw-row hook that a metadata subscription does not
call. Its replacement checks actual native stream admission. That replacement
and the public contained-artifact fixture selector are not yet qualified.

No reference file is removed by this consolidation. There are 129 retired
files and 79 unchanged reference files. The complete source checkpoint is
`recovery/araphor-consolidation-20261022T1501Z.tar.gz`, with SHA-256
`9a17da34f9e0b4d47b8aec1cba7206d329d0e3fe80776cba88ba0e35a07b76f6`.
The earlier approval rejection above is historical. The user has approved the
shared Host integration. No new approval is required for that integration.

Complete producer supervision, delayed-window recovery, removal and version
operations, source-isolation qualification, native Data coordination waits,
the required production code reduction, and the final shared Rust procedure
remain **Not done**. The final procedure must run after the last covered edit.


## Native input and fixture leaf retirement

Status: **Done** for the two reference leaves. Complete retirement remains
**Not done**. The [qualification record](../../recovery/araphor-input-fixture-retirement-20261022.json)
contains exact commands, source and binary hashes, passing selectors, source
coverage, and the proof archive. The source archive retains both original files.

The native events TableProvider and Graph projection replace Graph input
paging and assembly. Twenty-two input checks pass in `graph-input249`. The
corrected immutable-facts check passes in `graph253`. Both current mixed-origin
checks pass in `graph-origin255`. The production dependency audit permits the
22 unchanged checks to carry forward; the failed observer assertion does not
count as a pass. SQL defines the selected window. The remaining chunk and window
files retain the separate automatic scheduling duties. No complete producer
claim is made.

All 11 Qualification checks pass in `fixture-owner255`, including SQL, Wasm,
and actual source-built native fixtures. Control passes three fixture calls;
Data passes request encoding; the CLI passes six image command checks. The
public request can select an exact artifact inside its exact root OCI image.
Without that selector, it tests the root artifact. Testing starts no Discovery
and writes no package execution state.

The two removals delete 311 nonblank production lines. There are now 131
retired files and 77 unchanged reference files. This is a deletion count,
not the complete redesign reduction. The required overall production reduction
and the final shared Rust procedure remain **Not done**.

### Shared Host qualification and Discovery owner retirement

The shared Host owns the execution collection. Discovery and Graph source
subscriptions only admit instances and change running intent. Control supplies
the same Host to its public APIs and startup task. A prepared-instance handoff
uses the existing pause channel and waits for collection acceptance. Stop and
replacement join the actual worker before the Data lifecycle write. Caller
abort cancels a feed, but the feed retains its owner until admission workers
join.

The frozen source in `manifest268` passes compilation of workspace library
tests. `ownership270` passes all 12 selected lifecycle, slot-wait, source-denial,
and caller-abort cases. `joined270` passes the version case that captures the
joined worker's saved state. `discovery-owner272` passes six constructor,
context, membership, and finite-publication cases. `query-owner272` passes both
native clock cases. These are focused results, not the final shared Rust gate.

`live270` passes the existing live publication and shutdown case with its
128 MiB input pool, 16 MiB output pool, and original deadlines. A concurrent
metadata read previously reserved all free input memory. Profile conversion
then failed despite its small input. Metadata reads now retain their per-read
byte bound and charge their actual retained memory. Full Snapshot, Page, and
Changes reads retain their existing prepayment. The metadata boundary, memory
scope, remaining-capacity, local-capacity, and notification-deadline cases pass
in `query-metadata271`. Its catalog digest case fails because the native Graph
manifest has five new fields; the updated digest still requires qualification.
No speed benchmark or strict bound on all transient allocations is claimed.

`data-waits269` passes all 19 read and lock cases. `data-managed269` passes all
72 Managed and Profile cases. `data-graph269` passes the six Graph-interest
cases, the notice-dependency case, and 32 Graph storage cases. Six other Graph
storage cases fail because reopen fixtures retain the new lease or their local
schema omits the mutable notice fields. The source corrections are under
qualification. `graph-notices270` passes prefix drain and exact-source
invalidation. Three multi-head notice and expiry cases still need qualification.

The complete owner map permits removal of
`crates/araphor-analysis_back/src/discovery/mod.rs`. Its 52 nonblank lines
define the old owner, context contract, constructor, memory scope, operation
mutex, and registration lifetime. Native input plans and captured receipts
replace the callback contract. The shared Host replaces the execution owner
and operation mutex. Constructor and Drop checks preserve registration.
The separate live, replay, installed, corpus, and crash files remain.

The [retirement record](../../recovery/araphor-discovery-owner-retirement-20261022.json)
contains the exact method map, source hashes, commands, and passing test names.
The source archive is `recovery/araphor-consolidation-20261022T1855Z.tar.gz`,
SHA-256 `055fc924b4ea54c633867e9b676f1c93fba6b58691e7dd8070dd6b7a16c1c8fc`.
The original leaf in that archive and the current leaf matched baseline
`6a25ba1b` before removal.

This owner-leaf retirement is **Done**. There are 132 retired files and
76 unchanged reference files. Complete producer replacement, source removal,
the required overall production reduction, and the final Rust procedure are
**Not done**. Control Graph startup, removal and recreation, historical
Discovery replay, fixed-window recovery, and native interrupt cancellation
still require work.

### Graph integration qualification

Status: **Not done**. The frozen source in `manifest274` compiles all workspace
library tests. `data-reopen275` passes all ten selected Graph storage checks,
including the six failures recorded above. The reopen fixtures now release
their Graph lease before they reopen the store. The integrity fixture uses
the current notice fields. No production storage check is removed.

`graph-notices275` passes all five notice and expiry cases. These checks retain
all window heads, atomic rollback, exact source invalidation, and unchanged
state on a denied writer. The denied-writer hook returns Denied at the writer
boundary. It does not prove a reentrant authority change under a commit lock.
`catalog276` passes the complete catalog digest and Arrow lifetime check.
The earlier `catalog275` selector matched no tests and provides no proof.

`control-graph275` passes four checks: independent Graph configuration, inert
definitions, exact node scope, and startup when Data is unavailable. The fifth
check, `graph_sources_use_host`, times out before complete source processing.
Control now prepares the Graph source feed for its shared Host, but automatic
Graph processing is not qualified. No timeout or quota was increased. There
are still 132 retired files and 76 unchanged reference files. No additional
reference file can retire from these results alone.

`versions277` passes all eight ordinary version cases on the same frozen
source. `native-version278` passes the ninth case with source-built native
artifacts. These checks include failed replacement, current Run permission,
target image trust, worker cancellation, saved history, and joined saved state.

The diagnostic `control-stack276` finds native Wasmtime compilation still
active after 40 seconds. It is not a test pass or a benchmark. The source
audit finds one shared Runtime and a strong component cache. The new Control
test now uses the existing Discovery test's 90-second publication bound. It
checks that all three components are cold before execution and cached after
each source. Production deadlines, quotas, and cache options are unchanged.
The corrected test still requires qualification.

The checkpoint archive is
`recovery/araphor-consolidation-20261022T1918Z.tar.gz`, SHA-256
`9544843ac4258b74d913cf8ec22885f1467724571e7b0c6cfa7556b360ffd200`.
It retains the frozen source and the earlier build and Graph check records.
Package removal, image uninstall, and explicit recreation are now under
compilation. They have no passing result on this source yet. No backup file
was removed for those changes.


### Removal and replay qualification in progress

Status: **Not done**. `manifest281` compiles all workspace library tests.
`control-cold282` passes `graph_sources_use_host` in 77.891 seconds. The test
starts both Graph sources through the same Host. It checks cold compilation,
component reuse, exact node scope, durable publication, and joined shutdown.
The new test uses the 90-second publication bound described above. This result
does not qualify all Graph window, reuse, or failure-reporting behavior.

`data-removal281` passes 87 selected cases and fails two. The failed checks find
that actual capture accepts a Removed instance and that explicit rebuild
still decodes prior state. The shared capture validator now rejects Removed
instances. Rebuild retains the prior result identity for the commit comparison,
but does not decode or supply that prior state. These corrections require
qualification. The pending-attempt policy for finite capture is unchanged.

`analysis-removal281` passes 22 selected cases and fails one. All five Host
removal cases pass, including native worker join, recreation, retained history,
and Removed-instance recovery. The failed Discovery replay case reports a
missing definition image with a field name absent from the existing narrow
resource classification. That exact name is now included. Corrupt inputs and
authority denial keep their existing error classes. The correction requires
qualification.

The checkpoint archive is
`recovery/araphor-consolidation-20261022T1951Z.tar.gz`, SHA-256
`d1cbce497ce98962e93634e2400944c03e31dd6d07497bb2960a346f0210994c`.
It contains source state 281 and the complete build and focused test records,
including all failures. Later capture, freshness, and supplied-input changes
are outside this checkpoint. `manifest283` fails on a new Query test that
compares Dataset values without a PartialEq implementation. The test now
compares the dataset name and Arrow batches. Its assertions are retained.

There are still 132 retired files and 76 unchanged reference files. No
reference file is removed for an unqualified correction. Complete retirement,
the required overall production reduction, and final shared Rust CI are
**Not done**.


### Native lifecycle and source qualification

Status: **Not done**. `manifest284`, `manifest285`, `manifest286`, and
`manifest287` compile all workspace library tests. The Data capture corrections
pass all 90 selected cases in `data-removal284`. The eight selected Control
checks pass in `control-removal284`. The ten CLI removal and output checks pass
in `cli-removal286`. These are focused checks, not complete workspace CI.

`analysis-retained286` passes 32 cases and fails two new timed-output cases.
Its passing cases include all four Discovery replay cases, SQL and Wasm saved
state, source-built native replay, exact historical generations, current Inspect,
and the final combined authority check. The timed cases find that finite
managed calls do not retain package input expiry metadata. SourceScan now
retains that metadata for both Follow and managed finite execution. The
ordinary SQL plan and its captured time are unchanged.

`query-retirement286` passes 25 cases and fails two new lifetime checks.
The new tests still retain their own PackageCall clones and original input
buffers at their final capacity check. The corrected tests release those
owners before they require complete capacity release. No production lease or
quota changes. `query-corrections287` passes all eight selected cases, including
both failures, typed supplied inputs, exact retained pins, captured time,
state provenance, and managed window capture. `query-source287` passes five
source-frame, range, capacity, and deadline-only window cases.

`analysis-lifecycle287` passes 68 cases and fails four. The passing cases cover
native removal joins, separate instance state, stopped intent, SQL/Wasm/native
checkpoints, immutable retry, native finite publication, current authority,
and complete fixture returns. The failures are reader contention in a test
observer, admission under memory pressure, a pending request compared with the
uncaptured input request, and an empty-window fixture whose output requires
input evidence. Corrections retain the existing 30-second admission bounds,
the exact stored native frontier, and required output evidence. The new
window fixture supplies a native COUNT row when the event window is empty.
The corrections require qualification. No failure is treated as a pass.

The checkpoint is `recovery/araphor-consolidation-20261022T2042Z.tar.gz`,
SHA-256 `1df3ef1b8e41c65ce51d072b46ee6c1735af1f2dfcb4f3e835e0eb3024471a00`.
It retains source state 287, the two later test corrections, and all listed
build and test records. The later observer correction is outside that archive.
No reference file retires from these results alone. There are 132 retired
files and 76 unchanged reference files.

### Public Instance gaps found by the source audit

Status: **Not done**. The native library owners support first admission,
Start, finite Run, Stop, Update, Rollback, and stopped authority renewal. The
public Control request enum and CLI do not yet expose these operations.
Recreate requires an existing Removed instance and cannot create a first job.
Keep the old package owner until those public routes have a replacement.

A public execution operation has a fresh authenticated caller grant. The
running Instance has a separate stored execution grant and attribution.
The user permits a current authorized caller to operate an existing Instance
when its selection permits the saved scope. Ordinary Start, Stop, finite Run,
Update, and Rollback keep the saved execution grant and attribution. The
existing atomic commit_many seam must check both grants at the effect boundary.
Explicit Renew requires a stopped and joined Instance with the exact saved
selection. This operation replaces its execution grant.
Fresh renewal after reopen must prepare exact retained code under the new
grant without requiring the revoked or expired old grant.

Each added route or helper must replace an existing responsibility with a
simpler implementation. Do not add a sharing framework, permission model,
owner registry, or separate executor. Public lifecycle implementation and
qualification remain **Not done**. The statements above record the user's
decision; they do not record a test result.

A pure SQL or PRQL job can have no package calls. Its selected root output is
retained in the existing Managed store. The public result reader currently
accepts only package-call output. It must also read and query an exact selected
root result after fresh Inspect and captured-scope checks, before Arrow payload
hydration. This requires no second output store or fabricated package metadata.
Keep the old Inspect leaf until that route has a qualified replacement.

The configured input-before-cold-compilation contract, native interrupt loop,
Graph reuse and durable failure reporting, full window recovery, automatic
Notification supervision, complete source retirement, required overall code
reduction, and final shared Rust CI remain **Not done**.

### Native optimizer and admission corrections

Status: **Not done** for complete retirement. `manifest289` and `manifest290`
compile workspace library tests. These commands do not run full workspace CI.
Host restore now checks current Run authority before native preparation.
Previously, a denied instance could wait for memory before it found the denial.
All five selected admission and pending-request checks pass in
`host-admission289`, with the original capacity and deadline assertions.

`retirement-cases289` passes 26 checks and leaves one native version check
ignored. `query-parity289` passes nine input, scope, retained-image, and configured
limit checks. These records cover source state 289. They do not qualify the
later optimizer correction by themselves.

The existing Discovery code-change check found a native stack fault during
admission optimization. DataFusion tree recursion protection was active. An
Arrow constant cast used more stack than the native recursion checkpoint
reserved. Both Query optimizer calls now use the existing Parser stack guard.
The SQL, optimizer rules, stack constant, test deadlines, and fixtures stay
unchanged. The guard does not change native recursion segments or Arrow
checkpoints. Very deep native plans are not qualified by this correction.

On source state 290, `query-optimize290` passes all 14 selected checks, including
native optimizer errors and cancellation joins. `discovery-optimize290` passes
all six selected checks, including code change, window frontiers, conversion
failure, and the recorded-snapshot oracle. `native-replay290` passes all five
saved replay and native version checks. `query-native290` passes all four
source-built native execution and resource checks. No test stack setting,
timeout, or quota was increased.

The checkpoint is
`recovery/araphor-retirement-checkpoint-20261022T211945Z.tar.gz`, SHA-256
`e87544bb0bc41c893c85c47c86abfe12aa1e5882a297eaa81e0e2575f966da39`.
It retains the source, earlier completed records, current diagnostic maps,
and all six native artifacts. The later completed state-290 check records
require a new checkpoint before a reference file can retire.

The source audit also finds a remaining admission-status gap. The Host logs
non-denial restore errors before an attempt exists, but does not retain Failed
readiness. Keep the old supervision file until that behavior has a qualified
replacement. There are still 132 retired files and 76 reference files.

### Discovery replay and package commit retirement

Result: **Done** for five complete reference files. Native Query, Analysis,
Package, and Data owners now replace Discovery image lookup and replay, Graph
chunk splitting, installed image history, and the installed commit guard.
The method and assertion maps cover all removed methods and six old replay
tests. Current input, replay, authority, renewal, removal, atomic-publication,
and native execution checks retain their assertions. All 65 distinct checks
pass on source state 290, with no ignored case.

The current model uses one grant per Instance and its complete image set.
Independent grants have independent Instances. Exact saved images survive
uninstall while a definition retains them. Retained replay uses the exact
stored profile and saved inputs; it does not accept caller-edited profiles.
Raw-input expiry does not remove those saved managed inputs. These are explicit
contract changes from the old callback and global activation model.

The removal deletes 737 nonblank production Rust lines. It does not count test
code, comments, blank lines, or a complete net reduction. The original mixed
Graph and package caller tests stay. The public package owner, Inspect,
execution, supervision, and remaining window files stay for their recorded
gaps. There are now 137 retired files and 71 unchanged reference files.

The [retirement record](../../recovery/araphor-five-leaf-retirement-20261022.json)
contains every removed file hash, replacement map, test record hash, and native
artifact identity. The source and complete proof checkpoint is
`recovery/araphor-retirement-checkpoint-20261022T213330Z.tar.gz`, SHA-256
`dd167aaa3285b805370ba50668671e0e6808c495d8935d10346fd0a779742dc4`.
The checkpoint retains all five original files before removal. All remaining
reference files match baseline `6a25ba1b` after removal. Complete retirement,
the required net reduction, and final shared Rust CI remain **Not done**.

### Exact selected SQL and PRQL output qualification

Result: **Done** for exact saved output reads and queries. ManagedOutput now
distinguishes a package-call result from the selected root result in the
existing Data reader. The reader checks the captured scope before IPC loading.
It checks the saved generation schema and each receipt-to-call binding. The
public route uses the existing binary Output and Result replies. Local queries
use decoded datasets through native Query tables and release unused wire
buffers before execution. There is no second store or producer execution.

`manifest291` is interrupted because its narrower feature graph starts a new
bundled DuckDB build. It supplies no passing compilation result. `manifest292`
uses the existing workspace feature graph and fails on four field accesses in
one freshness test that still expects the old output type. The corrected test
matches the package-call variant and keeps all original assertions. Three
redundant field patterns are also corrected. `manifest293` compiles workspace
library tests without warnings.

On source state 293, `data-selected293` passes all 95 selected Data checks.
`analysis-selected293` passes all 22 selected history, disclosure, renewal, and
SQL/Wasm/native replay checks. `query-selected293` passes all nine local-table,
PRQL, retained-image, and typed-input checks. `control-selected293` passes all
seven selected binary RPC checks. No test is ignored. The call-swap regression
keeps the declared ID and dependency sets unchanged and requires Invalid before
and after IPC corruption.

The current retained manifest requires selected_schema from the native logical
plan. The field has no compatibility default. The
[review route](../guides/araphor-discovery-definition-review.md#saved-sql-and-prql-result-reads)
names the owners and checks. No reference file retires for this change alone.
There are still 137 retired files and 71 unchanged reference files. Public
lifecycle, admission failure status, complete window recovery, Notification
supervision, native interrupt replacement, required net reduction, and final
shared Rust CI remain **Not done**.

The [selected-output qualification record](../../recovery/araphor-selected-output-qualification-20261022.json)
retains all 133 focused results and their source hashes. The later checkpoint
`recovery/araphor-retirement-checkpoint-20261022T220327Z.tar.gz`, SHA-256
`f0b045f03138ca46c247a49b2d7067f7ea05f141991f0bcfee003266f1087f43`,
retains source state 293, its complete proof records, and the current drafts.

### Admission failure and Notification continuation checks

Status: **Not done** for complete supervision. Data now records an admission
failure when no managed attempt exists. The write checks the saved Instance,
completed revision, and lifecycle. It preserves running intent, output, saved
state, and progress. Denial uses the existing suspension rule. Busy and
cancellation do not create a Failed record. A later successful publication
clears the current failure and preserves its history.

`data-notification296` passes all 97 selected Data checks. The first admission
checks found two test errors: one corruption case retained its terminal row,
and one SQL fixture used a supported moving-window predicate. The corrected
cases keep the original validation rules. On source state 299, the opening
and capture failure cases pass. The retained-image case also passes after its
new corruption assertion uses the current OCI error type.

`manifest299` compiles all workspace library tests. It does not run the final
Rust CI procedure. The first Notification runtime group passes four cases and
fails five. One failure opens a pre-created test directory instead of a private
Data subdirectory. Four failures occur before delivery at the native sink
schema check. These failures require correction and another qualification run.
The Notification replacement is not qualified by compilation alone.

The source audit finds a remaining recovery path. A failed source capture
must retry when a relevant source changes. The current Host records the failure
but waits for a lifecycle change. Use Query subscriptions for this path. Do
not add a polling task or a second clock owner. A new Notification grant
revision does not renew a route's captured approval. The required route
configuration already emits a Data event. Current authority checks remain at
the actual effect. No additional grant watcher is required by that rule.
Keep the complete old supervision file until its
replacement passes the required checks. There are still 137 retired files and
71 reference files. Complete retirement, the required code reduction, and the
final shared Rust procedure remain **Not done**.

### Native package lifecycle and retained-image retirement

Result: **Done** for seven complete reference files. Native Instance admission,
Data image storage, native package-call planning, and Data publication replace
installation, activation, finite execution, removal, retained-image reads,
snapshot ownership, and saved-result freshness. The method maps cover all 36
removed methods. All 48 selected Analysis cases and 30 selected Query cases
pass on source state 300. Native checkpoint and version cases run with the
source-built artifacts; no selected case is ignored.

The earlier 97-case Data run remains applicable. All 207 Data source hashes,
its dependencies, and its exact test executable are unchanged. Later changes
belong to its consumers and their tests. The new target checks require typed
Unsupported errors for selected Python and unqualified Native code. An image
with ambiguous SQL and Wasm implementations is rejected before installation.
The existing OCI corruption checks preserve held-code execution, current
authority, complete auxiliary descriptors, and memory ownership.

This removal deletes 1,420 nonblank production Rust lines from the reference
files. It excludes their test declarations, comments, and blank lines. It is
not the complete net reduction. The remaining 64 reference files match the
original baseline. Keep installed execution for input-before-compilation
ordering, preparation and window files for complete window recovery, and
supervision for source and capacity recovery. Public lifecycle, Graph and
Discovery producer parity, Notification delivery, the required net reduction,
and final shared Rust CI remain **Not done**.

The [retirement record](../../recovery/araphor-seven-package-retirement-20261022.json)
contains the complete method and assertion maps, exact proof hashes, and all
seven removed file hashes. The checkpoint is
`recovery/araphor-retirement-checkpoint-20261022T233130Z.tar.gz`, SHA-256
`e5843149214c10feb03985f21d11e99cd850e3a86905755ff9bf3e7f5d5dba11`.
It retains all seven files before removal and records the independent
Notification failures. Those failures do not qualify Notification supervision.

### Shared Notification execution and capacity release

Result: **Done** for the bounded continuation checks on source state 302.
`analysis-notification302` passes all nine selected cases in 10.633 seconds.
`control-notification302` passes all six selected cases in 65.961 seconds.
`manifest302` compiles all workspace library tests. `format302` passes. These
commands do not replace the final shared Rust procedure.

The native sink accepts DataFusion's equivalent Utf8View fields and field
metadata. It still rejects changed column names, types, and counts. The
captured selection must have the admitted tenant. The exact canonical
definition, tenant-only grant, empty image set, and absence of package calls
are checked before admission and restore. The capture remains complete and
untruncated before the first effect.

The Host uses the same native subscription collection for Notification and
package instances. A Notification stores lifecycle and running intent; it
does not create package attempts, package receipts, or managed progress.
The actual effect checks current authority and lifecycle after the pending
attempt is durable. Cancellation preserves that pending attempt. A clean
reopen sends its exact original route and subject before the new candidate.
The retry and ACK tests add no input writes after startup. Query's existing
deadline events cause each delivery and escalation.

`host-capacity301` passes 48 selected Host and finite execution cases in
77.117 seconds. Its production source is unchanged in state 302. The only
source difference corrects a retained test Arc; the nine-case rerun covers
that corrected test. When initial stream capture reports shared output
pressure, the Host joins its workers and waits on the existing capacity
event. Releasing capacity resumes execution without a new input commit.
Cancellation while capacity is held joins without a partial publication.

The startup test restores a retained running Notification while Graph is
disabled. The disabled configuration creates no image, instance, source
registration, or subscription task. Grant and route count options default to
None. Explicit count limits remain atomic across startup and runtime updates.
Updating a grant does not renew a route's captured approval; route
configuration already emits the required Data event.

No additional reference file is removed by these checks. Complete source
failure recovery, the native interrupt loop, complete producer parity, the
required net reduction, and final shared Rust CI remain **Not done**.

### Prepared SQL test retirement

Status: **Done** for the complete reference test file
`package/installed/read/tests/prepared.rs`. Complete retirement remains
**Not done**. The [assertion and custody record](../../recovery/araphor-prepared-test-retirement-20261023.json)
maps all five old tests and their fixture helper to the current owners.

The OCI codec check passes on the current Package source. It checks exact
root, artifact, SQL and digest round trips, a valid Provided input, the
prepared predicate, and a digest change for an output-SQL-only change. Six
required Query checks pass within the seven-case `prepared-query309` run.
They check target rejection, exact input shapes, retained descriptors and
image identity, and SQL body scope. The separate `image309` run passes both
Data image checks for retained closure and atomic installation. These ten
checks qualify this test file. Installation remains inert; selected native
definition preparation validates the SQL body.

The wider Data run passes 105 checks and fails one old dependency-revision
expectation. The new Host recovery check fails when its initial status read
finds a pending attempt. The wider Host run passes 46 checks and fails one
admission-count assertion; an unchanged run of that exact case passes.
These results do not qualify recovery or supervision retirement.

The verified checkpoint is
`recovery/araphor-retirement-checkpoint-20261023T010642Z.tar.gz`, SHA-256
`24d0dd7c698c2364200616035cfac52fbc8fb372403e9b2a96a31df7cdb0c745`.
It preserves all 64 reference files before removal. There are now 145
retired files and 63 unchanged reference files. This removal contains no
production code and does not count toward the production reduction target.
Keep the `prepared` predicate: Data activation preflight still uses it.

### Native failure and interruption retirement

Status: **Done** for the complete reference test files
`package/tests/native/failures.rs` and `package/tests/native/interruption.rs`.
The [assertion and custody record](../../recovery/araphor-native-failure-interruption-retirement-20261023.json)
maps all five old tests to current checks. Native lifecycle and process-abort
recovery remain separate requirements; their reference files stay in place.

The fresh Native fixture build passes for `x86_64-unknown-linux-gnu`.
`native310` passes all six selected cases. Its Native failure case checks six
error modes before and after a clean store reopen. Each mode keeps its exact
error, failed status, saved request and terminal record. No result, checkpoint
or progress commits. All four evaluation slots return. Native checkpoint
overflow and a cap-rejected Native replacement preserve the complete prior
output, checkpoint, context, receipt and commit revision.

`host311` passes all 53 cases. Actual Native cancellation, revocation and
expiry retain a running guest until it joins. A socket event comes from
inside Native compute; no file polling is used. After guest release, one
five-second guard covers compute completion and the API join. Explicit Host
stop checks the exact saved Cancelled terminal. Already-expired admission
creates no instance or attempt. The connected Wasm, version and checkpoint
run passes eight cases. Query and Runtime each pass their two selected Native
checks. Formatting and strict workspace Clippy pass on source311.

Nonzero unsupported Native resource caps are checked only for selected Native
execution. SQL and Wasm remain usable. Zero caps remain Invalid configuration
at Runtime construction. No process isolation or fallback target is added.

The admitted-failure recovery case also passes in `host311`. It resumes from
the real saved frontier after an Incomplete or Limit result. Unrelated writes
do not trigger another call. A relevant source change or the query's saved
window deadline triggers one fresh evaluation. The same generation, running
intent, prior result and captured parameters remain intact. The correction
removes global relation revisions from this managed dependency read and uses
scoped dependencies. A real profile-change assertion and diagnostic retention
assertion pass in the eight-case `metadata310` run. Pre-attempt source failure
and typed Busy after an attempt remain **Not done**.

The verified checkpoint is
`recovery/araphor-retirement-checkpoint-20261023T013505Z.tar.gz`, SHA-256
`691b7c354309e03db9d8a4e6da9836bbc889c576033d1cb45c49628cbf2b3c6b`.
It preserves all 63 reference files before the two removals. There are now
147 retired files and 61 unchanged reference files. These two test removals
contain no production code. Complete retirement, the required production
reduction and the final shared Rust procedure remain **Not done**.

### Native lifecycle and restart retirement

Result: **Done** for the three complete Native reference files
`package/tests/native/lifecycle.rs`, `restart.rs`, and `mod.rs`.
The private helper has no caller outside these two test files. All remaining
reference files, including their parent module declarations, retain their
baseline bytes.

The current `InstanceHost` tests execute the installed Native image through
native DataFusion physical execution. The shared version test checks image
identity, Native output, Wasm update, exact receipt replay, rollback, two clean
store reopens, removal, retained history, and all four operation permits.
Image installation starts no instance. A completed finite run reports
`Inactive`.

The restart test calls public `InstanceHost::update` in each fault child.
The panic child checks the actual SDK panic result and preserves the current
instance. The abort child must exit with Linux `SIGABRT`. The parent reopens
the store after each child, compares complete saved output and state, and
replays prior receipts without a write. After abort, the current generation
executes successfully. The unfinished candidate generation remains blocked
by its exact pending attempt. The children provide fault injection for the
test. They add no production process owner.

| Check | Result | Seconds |
| --- | --- | --- |
| `manifest313` | Workspace library test targets compile | 40.428 |
| `lifecycle313` | SQL and Native version cases pass | 42.618 |
| `restart313` | Native panic, abort, and recovery case passes | 68.976 |
| `clippy313` | All workspace targets and features pass with warnings denied | 21.943 |
| `format313b` | Formatting passes | 4.550 |

The qualified Native artifact is `runtime.so`, SHA-256
`2c8bf062ac29642afff532ca1cd8f2ba2b9ed90352ae148136cc67c577b62cb8`,
for `x86_64-unknown-linux-gnu`. The exact assertion map, source hashes, test
commands, binary hashes, and removal record are in
`recovery/araphor-native-lifecycle-restart-retirement-20261023.json`.

The verified checkpoint is
`recovery/araphor-retirement-checkpoint-20261023T021945Z.tar.gz`, SHA-256
`08783763f490b0963d6808f325288ded3f128d43f1e96fb18cf1559b83dc8a05`.
It preserves all 61 reference files before this removal. The actual count is
150 retired files and 58 remaining files. These three removals contain no
production code. Complete retirement, the required production reduction, and
the final shared Rust procedure remain **Not done**.

### Admitted source or capacity recovery

Result: **Done** for live recovery after an admitted capacity failure.
The existing Host member select races its ordinary native Query subscription
with the original typed resource wait. Source changes and captured window
deadlines remain in Query. No new task, source watcher, clock, schema, or
durable state is added.

After a resource event, the Host cancels and joins the ordinary stream. A fresh
capture is allowed only when the exact failed completion is still latest and
newer than successful progress. A newer finite result prevents duplicate
execution. If the resource event cancels a new source attempt, Data retains
its newer completion and the actual prior receipt frontier. The normal native
dependency check can then execute that newer source cut.

The sink now uses the retained Session memory scope. The pool and configured
bounds stay the same. The member's own buffer release cannot trigger its
external capacity wait.

| Check | Result | Seconds |
| --- | --- | --- |
| `manifest318` | Workspace library test targets compile | 41.654 |
| `capacity318` | Release, source-first, finite-head, and cancellation cases pass | 5.135 |
| `host318` | All 54 connected Host, delivery, and joined-state cases pass | 97.236 |
| `memory317` | Scope and child release cases pass | 0.012 |
| `encoding315` | Canonical field metadata, raw SQL OCI metadata, and eight archive cycles pass | 0.050 |
| `clippy318` | All workspace targets and features pass with warnings denied | 80.768 |
| `format318` | Formatting passes | 4.865 |

The first build found a private existing test helper. The first runtime check
used an old handle after a lifecycle change. The corrected test uses public
`InstanceHost::start` and its returned handle. No production lifecycle fence
was weakened. The earlier failed records remain in the
[qualification record](../../recovery/araphor-reactive-capacity-recovery-20261023.json).

The three production files add 117 nonblank lines and remove 55. The four-case
test uses the existing native `JoinedInput` provider. These additions do not
qualify removal of the complete reference supervision implementation.
Pre-attempt capture recovery, compiler and cache forwarding, complete
retirement, the required production reduction, and the final shared Rust
procedure remain **Not done**.

### Supervision test retirement

Result: **Done** for the complete reference file
`package/supervision/tests.rs`. All three methods and all 14 assertion groups
have passing replacements. `host318` includes the exact healthy `COUNT` value
after another job expires. `cold-query318` checks the complete retained image
and auxiliary descriptor. `cold-analysis318` checks retained code, current
authority, and inert admission. These three runs pass all 57 selected cases.
The old file has no private helper definition or external helper caller.

The verified checkpoint is
`recovery/araphor-retirement-checkpoint-20261023T030259Z.tar.gz`, SHA-256
`2ba19fe5ce0f17c6febad665b7c52feb086ef6e679b794950ba534ddcb5af870`.
It contains all 58 reference files before the removal. The
[removal record](../../recovery/araphor-supervision-test-retirement-20261023.json)
contains the full assertion map, source identities, commands, and binary hashes.
The actual count is 151 retired files and 57 remaining files. All remaining
reference files keep their baseline bytes. The removed file contains 204
nonblank test lines and no production code.

The complete reference production supervision file remains. Pre-attempt
capture recovery is still required. Compiler and cache forwarding is under
qualification. Complete retirement, the required production reduction, and
the final shared Rust procedure remain **Not done**.


### Package inspection and latest-result retirement

Result: **Done** for the complete reference `package/inspect.rs` file.
Analysis retains fresh Inspect authorization and joins cancelled readers.
Data resolves an explicit result ID or the current generation's successful
selected result in one read transaction. Data checks scope and the exact
receipt before it decodes Arrow. Query executes the reader's local SQL with
native DataFusion. Control and CLI pass the optional result ID to these owners.
Installation and inspection start no Discovery.

The replacement qualifies all seven old methods and all 35 required exact
selectors: 12 Data, 18 Analysis, four Control, and one CLI. The SQL and Native
version cases retain output history through update, rollback, and removal.
A recreated instance has no current result until a successful step commits.
A later failed step does not hide the last successful result. Explicit result
IDs retain their original packet, schema, row indices, and descriptor limits.
The old unconditional 64-export cap is removed under the user's quota rule.

The source321 focused runs and source322 quality runs keep their exact source
identities in the
[removal record](../../recovery/araphor-inspect-retirement-20261023.json).
`manifest322` passes in 307.663 seconds. `format322` passes in 5.392 seconds.
Strict workspace `clippy322` passes in 141.518 seconds. These checks do not
replace the required final shared Rust procedure.

The verified checkpoint is
`recovery/araphor-retirement-checkpoint-20261023T034819Z.tar.gz`, SHA-256
`654743b5358b37e8b44c2e0ac3142c02074e1c7c0ccd6c6deb9fdb59ca688088`.
It preserves all 57 reference files before this removal. The actual count is
152 retired files and 56 remaining files. All remaining files retain their
baseline bytes. This removal deletes 266 nonblank production Rust lines.
Complete retirement and the required production reduction remain **Not done**.

### Scoped window clocks and native capacity waits

Result: **Done** for the qualified execution boundaries below. A retained
fixed input keeps its original SQL time and range after a late close. Other
input windows keep their own ranges. The call context and SDK evaluation time
retain the actual call time. DataFusion analyzes the execution clone once.
Its native expression simplifier folds each child at its scoped time. Its
native optimizer then runs once on the complete plan. No parser, aggregate,
clock task, or second source read is added.

All five fixed-window cases pass in `windows322` in 2.461 seconds. All six
connected clock cases pass in `clocks322` in 2.917 seconds. Durable window
recovery, older occupied intervals, and failed close recovery remain open.
The scalar-view rejection was a stale test contract. `scalar323` passes all
four view cases and both event-window guard cases. The scalar package matrix
first expected a repeated selected batch after equal output. The corrected
`scalar324` case checks native suppression of that batch and retains the new
call, input, SDK time, and auxiliary clock assertions. All four matrix rows
pass. `guard323` also preserves the typed Analysis admission rejection. These
changes add no production code. The failed records remain in the evidence.

Query also forwards the original typed Runtime capacity error. The shared
Host waits on the existing compiler or component-cache capacity notice.
Three Runtime cases and three Analysis cases pass on source321. The actual
cache pin, cancellation, release, source-first recovery, and finite progress
guards pass. These checks add no polling or new capacity owner. The immutable
six-case record is `maps/supervision-runtime318/qualification321-final.json`
in the checkpoint evidence. Pre-attempt source capture recovery remains open.
The complete supervision file and final shared Rust procedure remain
**Not done**.


### Current verification and preparation decision

Result: **Not done** for the complete retirement and final Rust procedure.
`manifest324` compiles the workspace library test targets. `scalar324` passes
the complete four-row scalar clock matrix. All 56 remaining reference files
still match the saved baseline. The three audit agents are idle.

The final command is `bash .github/scripts/verify-rust-ci.sh`, recorded as
`final-ci324`. Formatting, workspace checking, and strict Clippy pass. The root
agent interrupts the test stage after 549.925 seconds before the required
preparation contract decision. The exit code is `-2` and the source is unchanged.
The full test suite is incomplete. This result is not a passing final gate.
The interruption record lists only that command's own process IDs.

The focused `preflight324` run reproduces the unresolved contract. The cold
invalid component returns `InvalidQuery` before the engine checks the actual
input. That input has two rows and an explicit one-row limit. `input_preflight_precedes_compilation` fails because it
requires `InputTooLarge` before compilation. The separate
`preparation_precedes_evaluation_deadline` test passes and requires a cached
component before the one-nanosecond Query timeout rejects execution.

The proposed change checks actual inputs before that call's compilation and
counts compilation in the same configured Query execution timeout. Compilation
would run inside the existing physical execution stream. Nested inputs would
use the same native stream. No new runner or divided timeout is proposed.
This change is **not approved or implemented**. Keep the complete reference
preparation, installed execution, and mixed test files. The complete migration,
required production reduction, and final Rust gate remain **Not done**.


### Package quota removal

Result: **Done** for package quota removal.
The user requires removal before further reference retirement. Export metadata,
invocation context, native and Wasm interfaces, retained results, and callers
no longer carry SDK row, batch, byte, or checkpoint quotas. Native SQL owns row
selection. External time windows remain. Non-time Graph window sizes are
removed. Existing shared engine capacity and cancellation controls remain.

The historical source is the
[Analysis contract and SDK plan](mithril-hugging-face-intrusion-prevention/phase-7-mithril-control-and-detection-packages/phase-7-5-graphs-findings-and-notifications/phase-7-5-2-analysis-contract-and-sdk.md)
and the
[package lifecycle plan](mithril-hugging-face-intrusion-prevention/phase-7-mithril-control-and-detection-packages/phase-7-5-graphs-findings-and-notifications/phase-7-5-3-package-lifecycle.md).
Commit `c85be1d7` introduces the four fields. Commit `95e9bb4d` carries their
checks into native Query execution. Commit `7315cabd` disables their defaults
but retains the contract. These records explain the code origin. They do not
supply separate approval for retaining that contract in the new design.

The earlier input-first preparation proposal is withdrawn. Its one-row quota
test checks removed behavior. This removal does not change preparation timeout
policy. The user requires stable version identifiers during development.
The SDK contract stays at version 1. The native accessor and Wasm version
identifiers stay unchanged. Source-built fixtures require rebuild.
All 56 remaining reference files stay unchanged. No additional reference file
retires in this change.


The [qualification record](../../recovery/araphor-package-quota-removal-20261023.json)
records 143 passing focused checks. These checks cover the SDK contract,
SQL row selection, Wasm and native calls, retained results, replay corruption,
Graph fixtures, atomic state, CLI output, Control transport, and inert image
and definition admission. `clippy330` passes strict workspace Clippy in
144.084 seconds. `format330` passes. `manifest330` compiles workspace library
tests without execution in 44.933 seconds. The user requires focused tests;
the full workspace suite is not run for this removal.

The OCI identity test retains an exact archive length and manifest digest.
Its new values reflect removal of the quota metadata. Native and Wasm test
artifacts are rebuilt from current source. Native checks retain contract
version 1. A failed native setup run omitted `ARAPHOR_NATIVE_TARGET`; only its
two failed selectors run again after that environment value is supplied.
The earlier `runtime326` run used an old executable and is excluded from the
current qualification. All failed and excluded records remain in the evidence.

No reference file is removed in this change. All 56 remaining reference files
retain their baseline bytes. Complete retirement and the required production
reduction remain **Not done**.


### Native preparation and installed execution retirement

Result: **Done** for seven complete reference files. Complete retirement is
**Not done**. The [qualification and source record](../../recovery/araphor-preparation-execution-retirement-20261023.json)
identifies each old rule, its current owner, and the exact passing selectors.

The removed files are `package/evaluation/preparation.rs`, its test file,
`package/execution.rs`, `package/installed.rs`, and the Wasm `lifecycle.rs`,
`metadata.rs`, and `flow.rs` test files. Their replacements use the same route:
Analysis opens a Query subscription; native DataFusion executes the admitted
SQL and package calls; Data commits complete output, state, and progress.
Finite runs use that subscription route with one step. No package executor,
clock, or polling loop is added. Cold preparation keeps its existing position
in native physical planning and its existing timeout policy.

The restart regression keeps input capacity occupied when a relevant source
changes. An unchanged subscription stays idle. A changed source returns the
typed capacity error before publication. Saved output, checkpoint, progress,
and frontier remain unchanged. The subscription joins, capacity is released,
and a new subscription consumes the source change. Subscription admission
metadata remains charged until the subscription closes.

The Wasm and Native checks inspect the same saved result before another
execution. A source addition makes that result noncurrent. Inspection changes
no packet, history, progress, or stored revision. Existing tests retain image
closure, canonical metadata, update, rollback, state, and restart assertions.

Focused checks found that guest exchange reservation ignored the existing
Query output byte setting and took all available shared output capacity. The
physical executor now uses that setting for the reservation. Concurrent test
fixtures explicitly configure an operation budget below the shared capacity.
No package quota, new configuration field, or enabled default is added.
The fixed 64 KiB transfer expectation came from the removed descriptor quota.
Its replacement fills the configured shared pool and checks the typed capacity
error, no guest entry, unchanged Data, and released reservation.

All 61 distinct focused selectors have passing results. The record retains
failed runs and identifies each corrected selector. It reuses unchanged
assertions and records source differences explicitly. Only affected checks
run after corrections. Native checks use the current source-built artifact.
Formatting, strict workspace Clippy, and library test compilation pass. The
full workspace test suite is not run, as the user requires relevant tests only.

The verified archive preserves all 56 reference files before removal and the
qualified replacement source. After removal, 159 of 208 files are retired.
All 49 remaining files retain their baseline bytes. This change removes 540
nonblank reference production Rust lines and adds eight production lines.
The net production reduction is 532 lines. The required overall reduction is
not complete. Pre-attempt source recovery, durable window recovery, and the
remaining mixed product and lifecycle rules remain open.


### Package lifecycle and retained-output test retirement

Result: **Done** for eleven complete reference test files. Complete retirement
is **Not done**. The [qualification record](../../recovery/araphor-package-tests-retirement-20261023.json)
maps each old assertion to its current owner and passing check. It records 83
distinct selectors. Failed and interrupted runs remain in the verified archive.

The removed tests cover image admission, grant changes, lifecycle transitions,
retained output, removal, interruption, input relations, and Wasm failure. Their
current checks use the shared Instance Host, Query execution, Runtime, and Data
transactions. Ordinary control requests preserve the saved execution grant.
Explicit stopped renewal changes that grant. Cold renewal checks exact image
bytes and revisions, checkpoint continuation, prior output, and restart. It
does not require the allocation address from a separate prior owner.

The archive preserves each removed file before deletion. There are now 170
retired files and 38 unchanged reference files. This removal deletes 3,163
nonblank test lines and no production lines. No production reduction is claimed
for this removal. The full workspace suite is not run, as the user requires
relevant tests only.

Pre-admission stale-source recovery, Graph feed qualification, and native
Discovery SQL and managed-window qualification remain open. Their reference
owners remain in place.


### Qualified reference leaf retirement

Result: **Done** for nineteen complete reference files. Complete retirement is
**Not done**. The [qualification record](../../recovery/araphor-qualified-leaves-retirement-20261023.json)
records 189 retired files and 19 unchanged reference files. This batch removes
623 nonblank production Rust lines and 2,255 nonblank test lines. These counts
do not establish the whole-migration net reduction. The verified
[archive](../../recovery/araphor-retirement-checkpoint-20261023T161725Z.tar.gz)
has SHA-256 `360bdcd406d89cca11fbc8f1312d742bc72373b7cf7febcd96481b5c2cc9ca6f`.

The source comparison corrects the recovery gate. The old deadline tests first
capture successfully. Expiry after a first failed capture is not an old parity
requirement. SourceRecovery keeps attached Query Progress deadlines and scoped
Run.dependencies recovery. Removing the extra metadata read, saved bounds,
and forwarding method removes 24 net nonblank production lines. All five
existing recovery checks pass in `analysis-recovery-sql350` and
`query-recovery350`. The Analysis aggregate contains six failed native SQL
selectors; the record does not treat that aggregate as passing.

`admission_rejects_domain_execution` checks that installation is inert. It does
not test Discovery output conversion. Existing inert-admission and closure
checks qualify that leaf. Pre-admission stale-source recovery, Graph feed
qualification, and native Discovery SQL and managed-window qualification
remain **Not done**. Their reference owners remain in place.


### Joined cleanup after known rollback

Result: **Done** for known rollback cleanup after native execution joins. Finite
Run and Follow use the existing Data `finish_managed` owner. The consolidation
removes the `Step.publishing` flag and its writes. This change removes 19 net
nonblank production Rust lines. It adds no API or recovery owner. This bounded
count is not a whole-migration reduction.

A known failure before commit saves the terminal result for the original live
claim. The same Instance then accepts a new request. Caller cancellation keeps
the pending claim. A loaded claim cannot finish the original execution. An
uncertain database commit keeps writes closed until the existing Data recovery
check runs. A saved success receipt remains authoritative. Crash checks retain
all-or-none output and receipt state immediately before and after commit.

| Record | Result | Seconds |
| --- | --- | ---: |
| `compile359` | Six affected crates compile with all features; tests do not execute. | 102.96 |
| `rollback-core359` | Four exact finite, Follow, pending-claim, and receipt checks pass. | 4.03 |
| `rollback-data359` | Three exact uncertain-commit, claim, and crash checks pass. | 9.62 |
| `discovery-repair359` | Historical repair fails later with `Elapsed`. | 224.11 |

The [source and command record](../../recovery/araphor-analysis-consolidation-20261023.json)
retains the committed source hashes and exact commands.

The records are in `/tmp/araphor-retirement-resume-20261022/`. Each JSON record
contains its exact command, source hashes, and log hash. The test records also
contain the executable hash. The repair run no longer fails at the previous
`managed pending attempt` error. That result does not qualify the complete
historical repair route. Graph failed-feed recovery still fails at cursor 258
in `graph-feed358`. No remaining reference file retires. There are 189 retired
files and 19 unchanged reference files. Complete retirement and the required
overall reduction remain **Not done**.


### Native publication continuation and Graph/package retirement

Result: **Done** for native managed continuation and ten complete reference
files. Complete retirement remains **Not done**. The
[retirement record](../../recovery/araphor-graph-package-retirement-20261023.json)
contains the old assertion map, passing checks, and original source hashes.
There are now 199 retired files and nine unchanged reference files.

The publication sink already reports whether its Graph or Profile cut needs
another evaluation. A completed cut acknowledges its committed revision.
Query now uses that existing acknowledgement to set `exhausted`. A pending
Replace cut continues on the next subscription poll. The continuation uses the
existing native capture, admission, physical execution, and Data transaction.
Each physical result still creates its real cursor. Finite Run still consumes
one step and joins. Generic SQL keeps its existing completion rule. No new
runner, clock, polling loop, state field, or API is added.

| Record | Result | Seconds |
| --- | --- | ---: |
| `compile360` | Six affected crates compile with all features; tests do not execute. | 204.90 |
| `query-managed360` | All 15 managed native Query checks pass. | 19.52 |
| `graph-feed360` | The actual Wasm Graph source failure and recovery check passes. | 195.72 |
| `discovery-repair360` | Historical repair fails at its second subscription wait. | 239.75 |

The Query regression requires two pending frames, one completed frame, then
an idle stream on unchanged input. The Graph check preserves the failed head
and cursor, advances a sibling, recovers the same frontier, then consumes
cursor 258 with repaired context. The original Graph body remains readable.
Shutdown joins both shared tasks and releases input reservations. This passing
check closes the remaining Graph feed gate in the ten-file assertion map.

The removed files contain two Graph production owners, six Graph test leaves,
and the old package owner and supervision files. Their current owners are
Query subscriptions, the shared Instance Host, and Data atomic publication.
The verified [archive](../../recovery/araphor-graph-package-checkpoint-20261023T1801Z.tar.gz)
has SHA-256 `5ce261c65ea227b9a46f699e7e9a77859f08a80dc38b674d1cc5179b3f70176d`.
The archive preserves all nineteen pre-cut reference files and the passing
and failing records. The nine remaining files retain their baseline bytes.

Discovery historical repair remains **Not done**. The failing fixture grant
selects no context keys. The continuation result does not qualify that case
or its remaining reference owners. These are focused checks; the full
workspace test suite is not run for this delivery. Complete migration and the
required overall production reduction remain **Not done**. No whole-migration
production total is claimed.


### Complete reference retirement

Result: **Done** for removal of `araphor-analysis_back`. All 208 original files
are retired; zero remain. The
[final retirement record](../../recovery/araphor-analysis-back-retirement-20261023.json) binds the
old method and assertion maps to the exact qualified source and deletion cut.

The committed [source checkpoint](../../recovery/araphor-analysis-source-checkpoint-20261023.json)
is `4f0eae6a18a321331a0b2c73fc17ecc1dcddc813`. Its two Discovery managed checks
pass on source state 367. That Graph group has five individual passes and one
failure at the unchanged 30-second same-frontier observer. Its debugger sample
is diagnostic evidence. Those historical failures remain in the final archive.

The final affected proof records are `compile369, format369, package-layout369, data-context369, query-managed369, graph-recovery369, analysis-managed369, clippy369`. The exact Graph
recovery check passes in `graph-recovery369`. The final source manifest is
`proof/tmp/source369-final.json` with SHA-256 `294448db4d41e0c66c4dbeac314dae6eeb90537dd1d0297ef9eda339a5fbd5b0`.
The retirement record supplies commands, outcomes, binary hashes and log hashes.
Earlier checks are reused only with an exact source and assertion map.

The verified [archive](../../recovery/araphor-final-checkpoint-20261023.tar.gz) has SHA-256
`ae9f2569909707dd83ff529566f681f40581dd179b36dac9934b5820e9c2e289`. It contains all 208 original Git payloads, the qualified
selected replacement source, assertion maps, and positive and negative proof records.
It was verified before the final nine files were removed. The deletion check
confirms zero remaining files and no active Back dependency.

Read the [current owner route](../guides/araphor-discovery-definition-review.md#saved-native-continuation-and-current-proof).
Execution stays in native Query subscriptions, the shared Instance Host and
Data transactions. Complete migration, `DataReadMonitor` removal, and the
required 6,000-line net production reduction remain **Not done**. This result
closes reference removal; it claims no whole-migration production total.

## Scoped native interruption

Result: **Done** for TODO 12. This delivery covers the working-tree changes
based on `d596f463`. DataFusion retains native query planning and execution.
Data retains DuckDB transactions. Wasm retains its existing event-driven
Wasmtime interruption. No planner, executor or result decoder is added.

A Data read registers its native interrupt scope
  -> Data registers an exact deadline only when configured
  -> cancellation or expiry sends one native interrupt
  -> DuckDB preserves cancellation across statement resets
  -> Data removes both interrupt sources and ends the scope
  -> Data rolls back the read snapshot and rejects cancelled output

The deadline worker keeps the expired read reserved until cleanup. It then
waits for a notification instead of sending another interrupt every millisecond.
A default read starts no deadline worker. Existing Data lock and Wasm waits
already use notifications and exact deadlines; their implementations are
unchanged. This closes the periodic-interrupt gap named in earlier records.
The reusable native deadline worker remains; no polling remains in that worker.

The existing pinned Rust driver has no scoped interrupt API. The
[local dependency patch](../../vendor/README.md) adds this primitive at its
native interrupt owner. The copied 99 dependency files contain 8,179,916 bytes
before local changes. This copied source is separate from authored changes and
from production Rust reduction counts. Versions and the native source archive
remain unchanged. No external source checkout is modified.

All 33 focused checks pass: 17 Data read checks, four Data lock checks, six
Query execution checks and six Wasm Runtime checks. The Data cancellation
helpers now send one event. The checks retain active native interruption,
pre-start cancellation, expiry between statements, rollback, reader replacement,
worker cleanup and capacity release. The
[implementation review](../guides/araphor-discovery-definition-review.md#scoped-native-interruption)
gives the source route and exact selections. Formatting and strict Clippy pass
for the affected owners. All commands use `CARGO_INCREMENTAL=0`,
`CARGO_PROFILE_DEV_DEBUG=1` and `CARGO_PROFILE_TEST_DEBUG=1`.

```sh
cargo test --locked --offline -p araphor-data --lib analysis::read::tests:: -- --test-threads=4
cargo test --locked --offline -p araphor-data --lib analysis::read::locks:: -- --test-threads=4
cargo test --locked --offline -p araphor-query -p araphor-package-runtime --lib --no-run --message-format=short
cargo clippy --locked --offline -p araphor-data -p araphor-query -p araphor-package-runtime --lib --tests --message-format=short -- -D warnings
```

Qualification covers the bundled cc backend on this Linux host. CMake and
other platforms are not executed. No full-workspace CI or benchmark runs.
The remaining parity items are 3, 7, 8 and 13. Complete migration and the
6,000-line production Rust reduction target remain **Not done**.

## Graph history and SDK input metadata

Result: **Done** for TODO 3. The history correction is in `8b8a119b7`.
The metadata delivery covers the working-tree changes based on that commit.
Read the [source route and exact focused commands](../guides/araphor-discovery-definition-review.md#captured-graph-coverage-in-sdk-inputs).

Data resolves requested retained graph IDs before current-head expansion. It
keeps tenant, source, binding and explicit-selection checks in the captured
read. Data captures SDK coverage from the typed graph headers it already
loads, including empty selected graphs. Query builds each graph input receipt
from those captured references and the traversal receipt. Known gaps, missing
data reasons and hop boundaries reach the installed package. Other inputs
retain their existing coverage rules. The SDK coverage heap-size count replaces
two duplicate counts. There is no new parser, planner, executor, codec,
subscription owner, store read, polling loop or contract version.

All 55 distinct focused cases pass: 15 SDK checks, 21 Data checks, eight Query
checks and 11 Analysis traversal checks. The installed Wasm component returns
the same rows, schemas, revisions and coverage that native Query supplies.
The checks retain permission denial, exact history, empty graphs, buffer
lifetime, configured resource bounds and native Arrow offset overflow.
Scoped formatting and strict Clippy pass for all four affected owners,
including test targets. Full-workspace CI, other platforms and benchmarks do
not run for this bounded delivery.

The metadata change adds 174 and removes 29 nonblank production Rust lines,
excluding comments: net **+145**. The history correction adds 18. Complete
TODO 3 therefore adds **163** production lines. Tests, documents, blank lines
and copied code do not count toward production reduction. The remaining
parity items are **7, 8 and 13**. Complete migration and the 6,000-line
production Rust reduction target remain **Not done**.


## Discovery continuation across expired input

Result: **Done** for TODO 8. This delivery covers changes based on
`a2f6cf800`. The
[source route and focused commands](../guides/araphor-discovery-definition-review.md#discovery-continuation-across-expired-input)
identify each owner and its proof.

Query captures selected rows, saved state and expiry metadata in its existing
subscription read. Native DataFusion SQL matches the complete source and CPU
identity, clips expiry ranges to the selected interval and checks the cursor
advance. One evaluation processes all selected retained ranges. A captured
`input_unbounded` field permits an expiry-only endpoint only for a full time,
cursor and physical event-range scope. A bounded cut or empty window cannot
advance from expiry outside that cut. Unexplained holes and excluded retained
records still fail.

The existing Data transaction checks the expected position, current head,
exact expiry tuples and retained-record count. It publishes profile, gaps,
progress and managed receipt atomically. Automatic gaps keep the source expiry
revision; the later publication has its own revision. The standalone resume
API keeps its existing revision behavior. The two paths share gap insertion.
Required processors cannot skip. A failed final guard rolls back all changes.
No source reader, runner, clock, polling loop or contract version is added.
Native Arrow casts align SQL gap branches; the existing SDK normalization
still enforces the unchanged strict gap schema.

All 58 distinct focused checks pass: 39 Data and 19 Analysis checks. They cover
real prefix, interior, multiple and tail expiry; open and sealed profiles;
counts, coverage and bytes; exact gap tuples; bootstrap, reopen and later
subscription input; bounded cursor and time cuts; stale progress; wrong
proof; required processors; and atomic rollback. Existing saved-gap, repair,
missing-input and profile-version checks also pass. Scoped formatting and
strict Clippy pass for the affected owners and test targets. Full-workspace
CI, other platforms and benchmarks do not run for this bounded delivery.

This change adds 137 and removes 33 nonblank production Rust lines, excluding
comments: net **+104**. Builtin SQL adds 33 and removes 12 such lines: net
**+21**, counted separately. Tests and documents do not count toward production
Rust reduction. The remaining parity items are **7 and 13**. Complete migration
and the overall 6,000-line production Rust reduction target remain **Not done**.


## Recorded policy preview through Query

Result: **Done** for TODO 7 in the changes based on `64f4a9d9c`.
The [source route and focused commands](../guides/araphor-discovery-definition-review.md#recorded-policy-preview-through-query)
identify the public constructor and existing computation owners.

Control consumes the installed Query package call and result through
`DiscoveryOwner::recorded_result`. The existing adapter checks binding, tenant,
record source identity and typed output. Control retains the candidate policy
compiler, static simulation and unsupported-family checks. A consuming
exception cannot be proved from a recorded snapshot and is rejected. Every
simulation reports `NotAttempted`. The result type replaces the unused marker
owner. No runtime, snapshot reader, service or polling loop is added.

All 29 distinct focused checks pass: five installed-component preview checks
and 24 existing context and baseline checks. The preview cases execute the
installed Wasm component through native Query planning. The compatibility
cases retain cutoffs, permission, conflict, omission, grouping and baseline
results. The source-revision label in the counts adapter comes from the
manifest; independent rejection of that label is not claimed.

Scoped formatting, whitespace checks and strict Clippy pass for the affected
Control library and test targets. The linked guide records the exact command.
Production Rust adds 10 and removes six nonblank lines, excluding comments:
net **+4**. Moved and extended tests do not count as production reduction.
TODO 13, complete migration and the overall 6,000-line production Rust reduction
target remain **Not done**. Full-workspace CI, physical qualification and
benchmarks were not run for this delivery.


## Optional evidence admission

Result: **Done** for Control evidence admission under TODO 13. TODO 13 remains
**Not done** for its other resource boundaries.

`EvidenceAdmissionLimits` has optional total and per-node counts. Both default
to None. The existing admission owner creates a native Tokio semaphore only
for a configured count. It keeps the allowed-node map when a gate is disabled.
An unknown node remains denied. The owner waits for the node permit before
the total permit. Native permit drop releases capacity after cancellation.
Configured zero and counts above `Semaphore::MAX_PERMITS` are invalid.

The four configuration and admission checks pass. They cover omitted and null
values, native count bounds, disabled and mixed gates, known-node membership,
FIFO waiting, cancellation, release and runtime construction. Strict Clippy,
scoped formatting and whitespace checks pass. The
[source route and command](../guides/araphor-discovery-definition-review.md#optional-evidence-admission)
identify the existing owners. No resource manager, custom queue or polling
loop is added. Production Rust adds 33 and removes 26 nonblank lines, excluding
comments: net **+7**. Full-workspace CI, physical qualification and benchmarks
were not run for this delivery.


## Trace selection without hidden count quotas

Result: **Done** for retained trace counts and selection under TODO 13.
Other TODO 13 boundaries remain **Not done**.

Data removes the fixed trace-request admission, current-read and recovery
counts. The existing storage owner retains optional global and tenant
`diagnostic_sources` quotas. Tenant, identity, revocation and per-receipt
recovery checks remain. Selection reads every permitted request before node
and binding filters. The configured key quota counts the resolved selection,
including explicit binding IDs and selected trace IDs. Trace IDs are added
only after these filters. A request-row limit cannot replace this quota.

Two focused checks pass. The connected case accepts 1,025 requests through
public Data APIs, reopens the store and projects all 1,025 Arrow rows. It checks
a late node and binding match, configured key rejection, foreign and missing
identities, cancellation and revocation. The existing diagnostic-source case
retains configured storage-quota and reopen checks. The final connected run
takes 89.69 seconds. Strict Clippy, scoped formatting and whitespace checks
pass. The [source route](../guides/araphor-discovery-definition-review.md#trace-selection-without-hidden-count-quotas)
records the exact selection. Production Rust adds three and removes 13
nonblank lines, excluding comments: net **-10**. Full-workspace CI, physical
qualification and benchmarks were not run.


## Retained package quotas and collection

Result: **Done** for retained package and context quotas under TODO 13. The
other resource boundaries remain **Not done**.

Data removes fixed package, dependency, witness, context, metadata, result and
checkpoint size or count ceilings. Existing storage quotas still apply.
Identity, schema, digest, export, parameter, order, exact-retry and atomic-commit
checks remain in the writer, reader and recovery paths. Completed input reads
use one query with the original head, revision, scope and freshness fences.
The former size probe and second fetch are removed.

The global collector validates dependency records once and deletes complete
unreferenced layers in one transaction. Each layer uses every original image,
definition, activation, result, context and dependency pin predicate. Image
cleanup uses only the exact deleted keys. The collector publishes one revision
notice after a change and none after a no-op. Per-key collection keeps its
existing dependency traversal. No cache, temporary table or new owner is added.

Eleven distinct focused checks pass. They cover oversized contracts, more than
64 dependencies, 8,193 witnesses, 257 contexts, 1,025 package revisions, more
than 1 MiB of dependency JSON and 1,025 valid installed references. Actual
reads, rollback, exact retry, finite storage quotas, backup and reopen remain
covered. Retention checks keep image, definition, activation, dependency and
context pins. An unused two-artifact chain is deleted without a second notice
on a no-op sweep. The revised large closure check takes 431.82 seconds. This
ordinary test still needs runtime attribution before further simplification;
no performance improvement is claimed. The
[source route and checks](../guides/araphor-discovery-definition-review.md#retained-package-quotas-and-collection)
identify the owners. Strict Clippy, scoped formatting and whitespace checks
pass. Production Rust adds 177 and removes 219 nonblank lines, excluding
comments: net **-42**. Full-workspace CI, physical qualification and benchmarks
were not run.


## Native source and Discovery cardinality

Result: **Done** for CLI source size, selector count and Discovery cardinality
ceilings under TODO 13. The [source route](../guides/araphor-discovery-definition-review.md#native-source-and-discovery-cardinality)
identifies the unchanged parsing and computation owners.

`SourceInput` reads the complete file, standard input or inline value. It keeps
exclusive inputs, valid UTF-8, nonempty text and NUL rejection. CLI and Control
remove their duplicate selector length and node-count ceilings. Control keeps
locator grammar, valid unique Node IDs, current inventory and tenant checks.

Builtin Discovery removes the 50,000-atom and 64-lifecycle-record ceilings.
Native DataFusion live and merge SQL remove only the lifecycle count error.
Lifecycle state, identity, conflict, deduplication and checked counter rules
remain. Representative samples still contain at most eight records.

All 16 distinct focused checks pass: seven CLI, one Control locator, one guest
cardinality, three builtin invariants, two native SQL cardinality and two merge
conflict/overflow checks. The guest case takes 19.08 seconds; the three builtin
invariants take 0.10 seconds; merge conflict/overflow takes 7.34 seconds.
Strict affected-owner and separate CLI Clippy checks pass. Production Rust is
net **-20** lines; builtin SQL is net **-2**, counted separately. Tests and
documents are excluded. TODO 13, full migration and the 6,000-line reduction
goal remain **Not done**. Full-workspace CI and physical checks did not run.


## Notification policy counts and retained attempts

Result: **Done** for Notification count ceilings under TODO 13. The
[source route](../guides/araphor-discovery-definition-review.md#notification-policy-counts-and-retained-attempts)
identifies the existing policy, delivery and retained-context owners.

Policies accept more than 16 package IDs and a positive retry count through
the existing u16 type. Concerns accept more than 16 context keys. Runtime and
stored-obligation validation remove the duplicated 48-attempt ceiling.
Tenant, identity, ordering, duplicate, exact-context, sensitivity, approval,
retry-delay, acknowledgement and escalation checks remain. Attempt sequence
arithmetic stays checked. Each attempt uses the existing save transaction.

Both new connected checks pass. They retain 17 context keys and 50 failed
Finding attempts, reopen the store, deliver successfully and acknowledge the
same obligation without resetting its deadline. Invalid tenant, version and
duplicate context inputs change no stored state. The 17 compatibility checks
also pass in a separate selection that takes 229.73 seconds: 19 distinct passes.
Strict affected-owner Clippy, scoped formatting and whitespace checks pass.
Production Rust is net **-3** lines, excluding tests, comments and blank lines.
TODO 13, full migration and the 6,000-line reduction goal remain **Not done**.
Full-workspace CI, physical checks and benchmarks did not run for this change.


## Optional delivery and live input deadlines

Result: **Done** for output-idle and renewable input-stage defaults under
TODO 13. The [source route](../guides/araphor-discovery-definition-review.md#optional-delivery-and-live-input-deadlines)
identifies the existing Control, Query delivery and Data control owners.

Control output timeout is optional and defaults to None. A configured value
must be positive and fit the native clock. Query Delivery applies that value
only to consumer idle time after an item. Authority, cancellation and request
deadlines retain their existing paths. Native upstream waiting is not idle.

Live input stages use the grant deadline without the former 30-second cap.
A renewable `stage` replaces its local deadline and shares cancellation.
`within` still preserves the earlier enclosing deadline. An expired grant
is denied. Existing event and exact-deadline waits continue without a new poll.

All 37 distinct focused checks pass: 34 Query checks in 16.16 seconds, the
Data native-cancellation check in 0.04 seconds, and two Control timeout checks
in 1.11 seconds. Tokio's existing test-util feature supplies paused test time.
Strict affected-owner Clippy, scoped formatting and whitespace checks pass.
Production Rust is net **+11** lines after test instrumentation is excluded.
TODO 13, full migration and the 6,000-line reduction goal remain **Not done**.
Full-workspace CI, physical checks and benchmarks were not run.


## Evidence transport and diagnostic operational quotas

Result: **Done** for this bounded quota replacement and its 128 distinct
focused runtime checks. TODO 13 remains **Not done** at the native host
qualification gate. The [source route and checks](../guides/araphor-discovery-definition-review.md#evidence-transport-and-diagnostic-operational-quotas)
identify the current owners and reproduction selectors.

Evidence keeps the native frame, WAL, Control intake and Data journal without
fixed record, context, commit, pending-range or coverage-count ceilings. An
optional positive record quota applies on admission. Block enforces configured
retained-byte and retained-count gates; Retain bypasses those two gates.
Lowered quotas do not make valid retained data corrupt. New frames share one
native raw commit. Exact retries reuse the durable receipt. Large first items
pass batching and segment targets. Native widths, CRC, current authority,
contiguous ACK, atomic commit and recovery checks remain.

Diagnostic source, output, queue, preparation and local admission quotas default
to None. Allocation protects `Evidence.maximum_retained_bytes.unwrap_or(0)`,
including Retain, plus the optional extra reserve. Recovery validates the
complete output prefix, syncs that file, then writes its NodeRestarted terminal.
This does not prove which complete frames were synced before a crash. Signed
grant expiry, target lifetime, cancellation, joined child and exact terminal
identity remain required. Prost encodes directly into the shared final frame
buffer; an already allocated spool extent needs no allocation lock or statvfs.

All 128 focused cases pass: Data 36, Node 22, Control 11, Interceptor 23,
Observability 15, CLI seven and lightweight E2E 14. The final Data selection
takes 59.29 seconds. The four final changed E2E cases take 36.16 seconds and
include actual large-context WAL/TLS/ACK/reopen and large coverage transport.
The eight-library build passes in 3 minutes 08 seconds. Strict affected-owner
Clippy passes in 1 minute 39 seconds without warnings. The source guide states
which ignored child helpers run through parents and which physical case is unrun.

Production Rust adds 952 and removes 803 nonblank, noncomment lines: net **+149**.
Tests, E2E fixtures and cfg-only support are excluded. The first seven changes
are net -53: task cumulative **+96**. All five forced native environment values,
builtin source bytes/hashes, StaticResources and map metadata remain unchanged.
Full-workspace CI, physical qualification and benchmarks were not run. Native
policy, full migration and the 6,000-line reduction goal remain **Not done**.


## Native backend defaults

Result: **Done** for removal of five forced settings from both native capture
owners and the unsupported global recipe map-capacity claim. Native program
bytes and hashes stay unchanged. The exact ring checks now use the observed
262,144-byte native layout and reject the old layout. No option owner or
compatibility path is added. The
[source route](../guides/araphor-discovery-definition-review.md#native-backend-defaults)
identifies the unchanged native execution and Arrow metadata owners.

Thirty focused checks and two guest lightweight checks pass. Scoped formatting,
whitespace and strict affected-owner Clippy pass. Production Rust is net -8
nonblank, noncomment lines, excluding qualification and test code.
The [physical result](araphor-observability/phase-2-owned-capture.md#native-backend-defaults-on-2026-10-24)
retains all ten correctness and cleanup results. Two of five latency pairs fail
the unchanged gate. Performance qualification remains **Not done**; diagnostics
remain disabled. TODO 13 also retains the Node ACK ceiling above sequence 4,096.
Full migration, removal of polling and the reduction goal remain **Not done**.

## Diagnostic acknowledgement sequences

Result: **Done** for removal of the fixed Node acknowledgement ceiling.
Node accepts the durable sequence 4,097 after cursor 4,000 through its existing
production upload method. Execution identity, prefix and terminal checks stay
unchanged. The configured 4,096-frame capture limit remains effective. No new
configuration or execution owner is added. The
[source route](../guides/araphor-discovery-definition-review.md#diagnostic-acknowledgement-sequences)
identifies the owners and exact checks.

Seven affected checks pass: the actual Node upload regression, two existing
Node fixture cases, and four existing TLS cases. The TLS cases include the
Kubernetes service DNS certificate constructor. The Node regression checks
exact frames, durable acknowledgements, terminal rejection and both stores
after reopen. Strict ten-owner Clippy passes in 97 seconds. Scoped formatting
passes. The build contains separate managed-input work in the worktree; this
record does not claim full committed-tree CI.

Production Rust removes one nonblank, noncomment line. The certificate helper
move and test code do not count as production deletion. Native performance
qualification is not repeated. Its failed gate, diagnostic polling removal,
the remaining migration and the 6,000-line reduction remain **Not done**.


## Query input runner retirement

The working tree based on `6ded52863152b691c5948e890833afcf3cc09996` removes
Query's separate input admission, execution, and watch owners. InputSet and
InputOperation are removed. Native Session, PackageCall, PackageExec, and
subscription owners remain. Inputs retains native plans and receipts. Scope
retains isolated body tables. InputCapture retains admitted saved aliases and
memory ownership. Read the [current review flow](../guides/araphor-discovery-definition-review.md#query-input-runner-retirement).

Finite reads retain readable exact saved rows when only original evidence has
expired. Existing coverage folding adds the expiry reason within the affected call. Every
later context, dependency, authority, scope, and corruption check remains.
Managed status and publication still require current source proof. Finite Wasm
slot admission returns Busy; Managed execution awaits its existing permit.
Neither route renews an expired parent deadline.

Data's [package store and API](../../crates/araphor-data/src/analysis/packages/mod.rs),
[package-input codec](../../crates/araphor-data/src/analysis/extraction/package.rs),
and [old output tests](https://github.com/Ereborlabs/erebor-runtime/blob/6edd86f9c2864261abb72d5b108688008b9123b7/crates/araphor-data/src/analysis/packages/tests/output.rs)
remain unchanged by the Query retirement. Their native replacement proof is a
separate gate:

| Data case | Native assertion still required before Data removal |
| --- | --- |
| package_output_snapshot | One saved-alias read retains its original snapshot while another native result commits; later latest selection sees the new result. |
| package_output_current | Each stored-current corruption and restore case maps to a native assertion. Stopped finite reads keep their current native contract. |
| package_output_historical_scope | A narrower current grant does not replace the original saved scope. Recreation keeps historical reads scoped and fences old saved aliases. Foreign scope stays denied. |
| package_output_preflights_payload | A small byte bound rejects the retained input before corrupt payload decoding. |
| package_output_revocation | The native read hook preserves typed cancellation, no disclosure, cleanup, and authorized retry. |
| reference_origins_merge | Equal saved aliases and an explicit result retain the exact reference-origin union and earliest witness. |

Renewal preserves selection. A changed scope uses remove/recreate.

The selected proof passes across separate runs. Query passes 112 cases in
188.95 seconds, then the corrected catalog case in 2.90 seconds. Analysis
passes 15 retained-input and capacity cases in 40.26 seconds. Data passes
11 guard cases in 19.64 seconds, then the corrected schema case in 0.02 seconds.
These are 140 distinct cases. They are not one simultaneous final run. The two
last corrections change tests only.

The [catalog_content_contract](../../crates/araphor-query/src/sources/rows/tests.rs)
now checks every typed cell, field order, and readiness value against Data's
canonical schemas in all eight owner states. Shape, alias, admission, and
release assertions remain. The schema-reconstruction probes did not reproduce
the historical Rust Hash constants. No replacement opaque Query hashes are used.
The [schema_contract](../../crates/araphor-data/src/analysis/extraction/tables/tests.rs)
keeps its sorted-JSON schema digests. Exact native schema reconstruction
recovers the original recipe digest. Only the recipe expectation changes to
`1c1288af`; the other 23 schema digests remain unchanged.

Strict Clippy passes for the ten affected owners in 21.77 seconds after those
last test changes. Scoped formatting passes for 24 Rust files. Whitespace and
the retired-runner caller search pass. Full-workspace CI and benchmarks are
not repeated. No performance result is claimed.

Result: **Done** for the Query input runner retirement and native finite expiry
transfer. The [master count](araphor-component-redesign.md#query-input-runner-retirement)
retains its Araphor source scope. The Data replacement gate above and the
complete migration remain **Not done**.


## Native saved-input retirement

The working tree after `6edd86f9c2864261abb72d5b108688008b9123b7` removes the
old Package saved-input branch, SDK wire-dataset conversion, and its obsolete
context types. Query retains one canonical source slice. The earlier Data
saved-input gate has the native assertion owners below. Historical paragraphs
and the earlier Query result keep their recorded source state.

| Saved-input duty | Current native assertion owner |
| --- | --- |
| One read snapshot during concurrent native publication | [retained_snapshot](../../crates/araphor-data/src/analysis/managed/tests/input/reads.rs) keeps original raw rows, saved rows, references, witnesses, and metadata; a later explicit current reference reads the next result. |
| Current storage and retained-record binding | [current_reads_check_storage](../../crates/araphor-data/src/analysis/managed/tests/input/current.rs) checks Metadata and Complete binding/source guards and stopped finite reads. [retained_record_checks_identity](../../crates/araphor-data/src/analysis/managed/tests/input/current.rs) checks admission and full hydration identity. |
| Saved historical scope | [history_keeps_saved_scope](../../crates/araphor-data/src/analysis/managed/tests/input/scope.rs) checks narrow-scope rejection, foreign-tenant non-disclosure, original broad history, remove/recreate generation fences, reopen, and old alias rejection. |
| Header and payload preflight | [retained_payload_bound](../../crates/araphor-data/src/analysis/managed/tests/input/reads.rs) checks the byte limit before corrupt IPC decode; [retained_header_skips_ipc](../../crates/araphor-data/src/analysis/managed/tests/input.rs) keeps metadata reads separate from payload decode. |
| Read cancellation and retry | [retained_cancellation](../../crates/araphor-data/src/analysis/managed/tests/input/reads.rs) checks the actual read hook, typed cancellation, valid parent, released reader permits, and a valid new child. |
| Exact inherited reference origins | [retained_origins_merge_refs](../../crates/araphor-data/src/analysis/managed/tests/input/origins.rs) checks equal aliases, explicit result/context origins, exact revisions, and the earliest inherited witness. |

Renewal preserves selection. A changed scope uses remove/recreate. The native
read keeps the original authorized selection even when physical capture has a
narrower event or table selection. Query source slots and Data origin indices
remain separate.

The [current review flow](../guides/araphor-discovery-definition-review.md#native-saved-input-retirement)
shows the remaining source and memory owners. Only the old saved-input path
and its output-test module retire. Legacy activation, commit, status,
read/history, recovery, schema, and provenance APIs remain. This is not whole
Data retirement.

The final production-source selection passes 26 distinct cases across three
runs: 11 Data cases in 31.12 seconds, 13 Analysis retained-input cases in
20.98 seconds, and two Query metadata cases in 0.78 seconds. A later test-only
correction propagates errors from the snapshot fixture hook. Its operations
and assertions stay unchanged. Only retained_snapshot runs again after that
correction; the case passes in 1.58 seconds. These are 26 distinct cases, not
one simultaneous final rerun or an additional distinct snapshot case.

The final test build passes in 49.14 seconds. Strict Clippy passes for the ten
affected owners in 78 seconds after the last test edit. Scoped formatting
passes for 19 Rust files. Whitespace and the removed-source-symbol search
pass. Full-workspace CI and benchmarks are not repeated.

Result: **Done** for the saved-input decoder retirement and canonical capture
ownership. The [master count](araphor-component-redesign.md#native-saved-input-retirement)
retains its Araphor source scope. Whole legacy Data lifecycle, recovery, and
store removal, complete migration, and the required production reduction remain
**Not done**. No performance result is established.
