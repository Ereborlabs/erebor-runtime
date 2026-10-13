# Wasm Execution Review

This guide follows the installed component path for
[Wasm Execution](phase-7-5-4-wasm-execution.md). The package owner executes
compiled algorithms. Existing host owners retain permission, evidence,
storage, and notification control.

## Intended end state

An operator installs a built detector folder through the package API.
The detector returns validated findings without an Araphor rebuild.
Current discovery and HF detectors use the same installed execution path.
Restart and identical retry preserve the committed result.

## Implementation review flow

[PackageArtifactV1::implementation](../../../../../crates/araphor-data/src/package/bundle.rs) Package admission selects a component artifact
  -> [CompileBudget](../../../../../crates/araphor-data/src/package/wasm/admission.rs) the execution owner checks its contract version, imports, and declared features
  -> [WasmExecution::compiled](../../../../../crates/araphor-data/src/package/wasm/cache.rs) Wasmtime validates and prepares the component under compilation limits
  -> [AnalysisPackageOwner::install](../../../../../crates/araphor-data/src/package/lifecycle.rs) the package owner records target compatibility before activation

[AnalysisPackageOwner::evaluate_artifact](../../../../../crates/araphor-data/src/package/execution.rs) The scheduler invokes an admitted export
  -> [QueryOwner::evaluate_component](../../../../../crates/araphor-data/src/query/model/component.rs) the host reserves input and schema scratch before it encodes the input
  -> [WasmExecution::evaluate_encoded](../../../../../crates/araphor-data/src/package/wasm.rs) the execution owner receives the owned wire input
  -> [WasmExecution::invoke](../../../../../crates/araphor-data/src/package/wasm/execution.rs) the host creates an evaluation instance with explicit limits and authorized inputs
  -> [WasmExecution::invoke](../../../../../crates/araphor-data/src/package/wasm/execution.rs) generated WIT bindings transfer bounded batches and the prior checkpoint
  -> [WasmExecution::invoke](../../../../../crates/araphor-data/src/package/wasm/execution.rs) the component returns declared outputs, evidence references, and next checkpoint
  -> [Package::validate_output](../../../../../crates/araphor-analysis-sdk/src/validation.rs) host validation passes the complete result to the existing commit path
  -> [EvaluationPermit](../../../../../crates/araphor-data/src/package/wasm/execution.rs) the execution owner releases the instance and temporary buffers

[WasmExecution::invoke](../../../../../crates/araphor-data/src/package/wasm/execution.rs) The component traps, exceeds a limit, or receives cancellation
  -> [GuestState](../../../../../crates/araphor-data/src/package/wasm/execution.rs) the host interrupts execution and checks cancellation
  -> [InstalledAnalysis::evaluate](../../../../../crates/araphor-data/src/package/installed.rs) the host discards uncommitted output and releases resources

[AnalysisPackageOwner::reconcile](../../../../../crates/araphor-data/src/package/supervision.rs) The generic package scheduler receives the error
  -> [AnalysisPackageOwner::failed](../../../../../crates/araphor-data/src/package/supervision.rs) the package owner records typed failure and marks retained results stale without replacing output or checkpoint

[InstalledAnalysis::evaluate](../../../../../crates/araphor-data/src/package/installed.rs) A domain adapter receives the error
  -> [DiscoveryOwner::process](../../../../../crates/araphor-data/src/discovery/live.rs) and [GraphAndFindingOwner::process](../../../../../crates/araphor-data/src/graph/live.rs) the adapter returns the error to its existing owner failure and coverage path

The generic package scheduler uses the same evaluator. Its named source inputs
and dependency inputs come from
[AnalysisPackageOwner::inputs](../../../../../crates/araphor-data/src/package/inputs.rs).
The discovery and graph adapters prepare their authorized domain inputs.
These adapters do not run through the generic table scheduler.
[InstalledAnalysis::evaluate](../../../../../crates/araphor-data/src/package/installed.rs)
checks these domain inputs and invokes `evaluate_artifact`.
Host-prepared exports with Table outputs use this path after package admission.
Discovery and graph outputs still require their domain adapter checks.

[InstalledAnalysis::active](../../../../../crates/araphor-data/src/package/installed/read.rs)
selects the requested installed, active export under the shared lifecycle lock
for an unpinned call. Evaluation reads only its complete root dependency bundle
and checks the selected grant and trust before and after computation.
An unrelated package grant is not checked for this exact call. Explicit
snapshots still pin all supported active exports in the scope. Pinned and
historical calls keep their selected exports. An active export that cannot use
host-prepared inputs returns `Unsupported`.
The [exact selection test](../../../../../crates/araphor-data/src/package/installed/read/tests.rs)
checks complete dependency admission and both revocation cases.

## Build and installation

[ComponentBuilder](../../../../../crates/araphor-component-build/src/lib.rs)
packages an author-built core module as a component. The generated
[guest bindings](../../../../../crates/araphor-analysis-sdk/src/guest.rs)
and [host bindings](../../../../../crates/araphor-data/src/package/wasm/bindings.rs)
use the same versioned WebAssembly Interface Types
([WIT contract](../../../../../crates/araphor-analysis-sdk/src/bindings/analysis.wit)).
The [detector example](../../../../../crates/araphor-detector-example/README.md)
contains the author commands and a complete detector.
The runtime keeps Wasmtime and this WIT interface. Extism supplies the approved
resource-policy reference. The runtime adds no Extism dependency.

The [built-in build script](../../../../../crates/araphor-analysis-builtins/build.rs)
runs during a native Cargo build. It calls
[ComponentBuilder::workspace](../../../../../crates/araphor-component-build/src/workspace.rs)
to compile and pack all six repository components. The build uses the locked
source, release profile, and fixed seed. The guest Cargo cache defaults to
`target/analysis-guest`. `ARAPHOR_COMPONENT_TARGET` selects another build cache.
The script rejects a cache that contains the native Cargo output directory.
The Wasm target branch skips this step to prevent recursive builds.

The packed bytes remain in Cargo `OUT_DIR`.
[Generated component constants](../../../../../crates/araphor-analysis-builtins/src/components.rs)
supply the required packages and the Data and E2E component tests.
[CI](../../../../../.github/workflows/ci.yml) installs the
`wasm32-unknown-unknown` Rust target before the ordinary Cargo checks.
The [builder input inventory](../../../../../crates/araphor-component-build/src/workspace.rs)
supplies the source-change watches. Generated component files are not source
inputs. The [source-build proof](wasm-component-build-proof.json) records two
equal builds and matching ordinary Cargo outputs under `source_build_correction`.
Installed execution and final qualification remain required.

A built folder contains `package.json` and `detector.wasm`.
`package.json` embeds the component bytes and complete artifact closure.
Operators install this file or folder. Installation has no author compiler,
download, or hook. The host compiles admitted bytes in its bounded worker.
OCI distribution and native execution remain later work.

[PackageBundleV1::encode](../../../../../crates/araphor-data/src/package/bundle.rs)
uses canonical descriptor JSON for every artifact in a component bundle.
[Immutable revision writes](../../../../../crates/araphor-data/src/package/lifecycle/revisions.rs)
use canonical descriptor JSON for component revisions. SQL revisions keep
their checked original bytes.
Standalone SQL bundles retain their previous encoding and trust pins.
An identical SQL dependency retains its original stored bytes after a checked
descriptor, artifact, and dependency comparison.
Arrow metadata map order cannot change a component digest or an identical
installation record after decode or restart.

[ClientGrpcOwner](../../../../../crates/mithril-control/src/client_grpc/packages.rs)
checks the current permission before it decodes the operation.
Mutation requires the package grant and exact bundle trust pin.
The [public client](../../../../../crates/erebor-runtime-client/src/araphor/packages.rs)
uses the package message limit on this API.
The ordinary query API retains its existing limit.

## Execution owners

```mermaid
sequenceDiagram
    participant Control as ControlPackages
    participant Package as AnalysisPackageOwner
    participant Compiler as Compiler worker
    participant Guest as Wasm store
    participant Data as AnalysisStore
    Control->>Package: Current grant and exact artifact
    Package->>Data: Read authorized inputs
    Data-->>Package: Detached input and references
    Package->>Compiler: Bounded component bytes on a cold cache
    Compiler-->>Package: Checked compiled image
    Package->>Guest: Recorded time, seed, input, checkpoint
    Guest-->>Package: Typed output and evidence references
    Package->>Control: Hold current commit authority
    Package->>Data: Commit complete result and references
    Data-->>Package: Original or new immutable receipt
```

[ControlPackages](../../../../../crates/mithril-control/src/service/packages.rs)
holds one package owner and query owner for a Control plane.
The listener and domain tasks use this owner.
The internal Control grant accepts only required bundle digests for configured
tenants. External packages use the bound `ClientAuth` owner.
The listener binds this authority before it starts discovery processing.

[WasmExecution](../../../../../crates/araphor-data/src/package/wasm.rs)
owns the engine, generated linker, code cache, compiler permit, and evaluation
count. Each call creates a separate Wasmtime store.
One engine ticker advances interruption epochs. Store cancellation and mutable
state remain separate. The ticker stops when its last owner drops.

Read the [installed guest overlap test](../../../../../crates/araphor-data/src/package/wasm/tests/runtime/concurrency.rs)
before the test-only
[GuestEntry gate](../../../../../crates/araphor-data/src/package/wasm/execution.rs).
The gate signals entry from the actual WIT `cancelled` import.
The test waits for both entry signals before it releases either call.
The release wait uses the remaining guest deadline. The host then applies its
normal call-count and cancellation checks.
The [existing cancellation test](../../../../../crates/araphor-data/src/package/wasm/tests/runtime.rs)
sets `release: None` and keeps its cancellation assertion.

[CompilerChild](../../../../../crates/araphor-data/src/package/wasm/compiler.rs)
starts the current executable in compiler mode with a cleared environment.
The entry point runs before the application runtime.
The [CompilerInput request](../../../../../crates/araphor-data/src/package/wasm/compiler/input.rs)
carries a version, fuel mode, and component bytes through standard input.
The child uses the same fuel mode as the parent engine.
The reply contains a bounded image and its digest.
The parent accepts no installed native image or external precompiled image.
Cancellation or deadline kills and reaps the child.
The compiler permit remains held until the I/O threads finish.

The one unsafe image load is in
[CompilerImage::component_reserved](../../../../../crates/araphor-data/src/package/wasm/compiler/image.rs).
Its input comes from the fresh host compiler with the same engine configuration.
The compiler boundary rejects a malformed reply, incorrect digest, or oversized
image before this load. The cache reserves the exact source and image byte charge
before host deserialization. A failed load releases the reservation.

[WasmExecution::prepare](../../../../../crates/araphor-data/src/package/wasm.rs)
returns one handle that retains the charged code entry. The package execution
owner prepares this handle before the query evaluation deadline starts. The
owner passes the same handle to guest invocation. Invocation does not repeat
the source digest, cache lookup, or component resource check. The handle stays
live until output decoding ends. Invocation rejects a handle from another
engine and releases the evaluation permit.

## Input, output, and host authority

The WIT interface has one computation export and one host import: `cancelled`.
The descriptor selects a named algorithm export inside the computation call.
The host supplies recorded time and optional seed. The guest receives no
WebAssembly System Interface (WASI)
filesystem, network, environment, clock, or random import.

The SDK transfers standard Arrow IPC streams with exact declared schemas.
The [wire decoder](../../../../../crates/araphor-analysis-sdk/src/wire/codec.rs)
checks message sizes, schema structure, projected allocation, batches, and rows.
It rejects compressed IPC before decode.
[Dataset::owned_batch](../../../../../crates/araphor-analysis-sdk/src/wire/codec.rs)
checks all array and child buffer lengths against the remaining copy budget.
The check includes possible temporary child validity buffers for nullable
parents. The decoder validates each array and uses Arrow `MutableArrayData` to
copy the values into owned buffers. A batch with no columns keeps its row count.
The decoder checks the resulting allocated bytes before it retains the batch.
The [owned-buffer tests](../../../../../crates/araphor-analysis-sdk/src/wire/tests/buffers.rs)
check a large binary dataset at a tight byte limit, nested nulls, columnless
rows, and a sparse null child that exceeds the copy budget. A smaller encoded
byte limit returns the SDK `Limit` error.
The [SDK reference](../../../../../crates/araphor-analysis-sdk/README.md)
lists supported Arrow types. Encoding and decoding make bounded copies.
This implementation does not claim zero-copy exchange.

Each [wire evaluation](../../../../../crates/araphor-analysis-sdk/src/wire/evaluation.rs)
and [wire output](../../../../../crates/araphor-analysis-sdk/src/wire/output.rs)
operation uses one private
[contract validator](../../../../../crates/araphor-analysis-sdk/src/validation.rs).
The operation validates the immutable descriptor and selects its model once.
Encoding checks typed input and output before IPC serialization. Decoding checks
the descriptor and limits before IPC, then checks the decoded input and output.
The two entry paths preserve the original export and limit error order.
Independent host, guest, and algorithm calls retain their own validation.
The [codec boundary tests](../../../../../crates/araphor-analysis-sdk/src/tests/codec.rs)
check exact error codes, changed descriptors, malformed IPC, missing inputs,
and required output evidence. The
[detector descriptor](../../../../../crates/araphor-analysis-builtins/src/graph/contract.rs)
also reuses its Finding schema for reason details within one construction.
It does not regenerate the same schema for each reason.

[Package::allocated_bytes](../../../../../crates/araphor-analysis-sdk/src/memory.rs)
counts descriptor capacities, port schemas, reasons, and checkpoints.
`wire::Evaluation::allocated_bytes` counts retained IPC capacities and metadata.
Typed inputs and wire inputs share one revision and coverage calculation.
Schema charges include nested fields, Arc headers, and metadata capacity.
The [allocation tests](../../../../../crates/araphor-analysis-sdk/src/memory/tests.rs)
check unused capacity, nested metadata, all schema positions, and wire growth.
The SDK suite has 51 passes. The build proof records equal bytes from two
independent builds of all six components under `memory_accounting_correction`.
The current production owner qualification remains open.

[Rows](../../../../../crates/araphor-analysis-builtins/src/rows.rs) buffers JSON
with the standard Rust `BufWriter`. The buffer uses at most 8 KiB per row.
The checked row writer sends each complete fragment to the Arrow binary
builder. Each Arrow write checks the remaining byte budget first. The encoder
flushes after serialization, including a serializer error. The encoder checks
the result before Arrow completes a non-null row with an empty append.
No complete-row vector or complete-row copy is created. The
[writer test](../../../../../crates/araphor-analysis-builtins/src/rows/tests.rs)
checks empty writes, complete writes, and rejection without a partial write.
The large escaped-string test compares exact JSON bytes across flush
boundaries. The serializer-error test retains byte-limit error precedence
and checks a successful next call. The v25 shared suite has 14 passes.
The earlier build proof records six equal component pairs under
`direct_builder_correction` and `inline_writer_correction`.
The `buffered_writer_correction` record has 14 native passes and six equal
component pairs from two builds. At the v25 record, the original graph split
assertion and production fuel limit were unchanged. Installed runtime
qualification remained open.

[Computation::authorities](../../../../../crates/araphor-analysis-builtins/src/graph/credential/join.rs)
indexes each qualified fact identity by its position in one vector. The first
fact remains the representative. Duplicate matches update its direct-proof
flag with OR. Stable record sorting keeps equal-record encounter order. Every
channel evidence append remains in its original position. The
[credential test](../../../../../crates/araphor-analysis-builtins/src/graph/tests.rs)
checks repeated identities, direct-proof changes, tied records, contextual
fallback, and the exact raw evidence. The `authority_index_correction` build
record has six equal component pairs and 13 native test passes. The later
`direct_builder_correction` record applies the writer change. These proofs do
not replace installed execution at production limits.

[Computation::credential](../../../../../crates/araphor-analysis-builtins/src/graph/credential/mod.rs)
copies raw join evidence once into a separate edge prefix. The shared
canonicalization helper sorts this prefix and removes duplicates before the
matched-fact loop. Each loop step adds the same fact record to the raw finding
sequence and the edge prefix. Each relationship copies the separate edge
prefix. Raw authority matches and the finding sequence stay unchanged. Final
publication still canonicalizes every edge and finding. The dense case has
66 relationships.

[Computation::output](../../../../../crates/araphor-analysis-builtins/src/graph/contract.rs)
publishes sorted evidence sets for edges and findings. Raw joins finish before
publication. The method sorts and removes duplicate row references before it
encodes candidate rows, matching reason details, and SDK evidence links.
Authority representatives, edge order, fact references, proof, coverage, and
checkpoint state stay unchanged. The
[publication test](../../../../../crates/araphor-analysis-builtins/src/graph/tests.rs)
keeps the raw join assertions and checks canonical rows, exact reason details,
evidence links, and checkpoint state.

[QueryOwner::evaluate_component](../../../../../crates/araphor-data/src/query/model/component.rs)
reserves input, IPC, and schema-message scratch before encoding. It includes
declared schemas when an input has no batches. The owner encodes once, reduces
the charge to retained input and wire capacities, and moves the wire into
`WasmExecution::evaluate_prepared`. After invocation, it retains the input and
output charges until the domain adapter releases the result. SQL keeps its
existing reservation through `QueryOwner::evaluate_analysis`.
The shared evaluator checks its local query deadline after output validation.
An expired output cannot return as a retained result.
Extraction closes durable readers before computation.

[InstalledSnapshot](../../../../../crates/araphor-data/src/package/installed/snapshot.rs)
holds one validated bundle per root in shared Arc ownership. Bundle capacities
and snapshot pins hold retained-input leases. `InstalledEvaluation` also holds
a lease for its copied descriptor and revision. The last owner releases each
charge. Each evaluation checks its grant and current trust before and after
computation. Commit authorization checks current activation metadata,
generation, revision, and grants. Cached bundle bytes do not cache permission.
Native graph extraction and seeded traversal retain their existing byte limits
and whole-version permission checks.

[GraphAndFindingOwner::process](../../../../../crates/araphor-data/src/graph/live.rs)
retains a previous installed snapshot only during the current operation.
[InstalledAnalysis::snapshot_reusing](../../../../../crates/araphor-data/src/package/installed/read.rs)
reads fresh activations under the shared lifecycle lock for each live window.
Bundle reuse requires the same owner, scope, and tenant. A retained root must
have a current activation with the same key, generation, revision, and metadata.
The owner checks each current prepared-export grant and bundle trust.
Each reused Arc keeps the same immutable root and complete dependency closure.
The previous snapshot drops before new roots load. Unused bundle leases release
when their last owner drops. Explicit pinned and historical handles keep their
existing selection rules. The
[bundle reuse tests](../../../../../crates/araphor-data/src/package/installed/read/tests/retained/reusing.rs)
check current grants, active roots, scope, tenant, generation, and capacity
release before a new root loads. The corrected fixture retry has five passes.

[InstalledAnalysis::descriptors and prepared_models](../../../../../crates/araphor-data/src/package/installed/read.rs)
keep the complete immutable package descriptor. Dependency declarations can
refer to SQL exports. Snapshot pins select prepared models by package, revision,
and export. Graph derivation and retained-reference selection share this
iterator. The graph adapter keeps exact descriptor equality and SDK output
validation. The
[package regression](../../../../../crates/araphor-data/src/package/installed/read/tests/descriptors.rs)
checks the complete contract and direct and snapshot evaluation. The
[graph regression](../../../../../crates/araphor-data/src/graph/tests/installed/current/descriptors.rs)
checks mixed exports and complete graph equality. Both pass in
`/tmp/araphor-installed-descriptor-green-v41-retry.log`. Its SHA256 is
`235cd00d6beb8fde6c39832569687ba81f50cc52fedf8996f0d7dbf8b1116ddb`.
The [phase result](phase-7-5-4-wasm-execution.md#multi-export-descriptor-correction-todos)
records the defect reproduction, fixture lifetime correction, and source hashes.
Fresh production qualification and final workspace verification remain required.

[Adapter](../../../../../crates/araphor-data/src/discovery/sdk/mod.rs)
executes atoms, merge, groups, and compare through installed components.
The host checks exact keys, attribution, accounting, coverage, and prevention
claims against original records.
The shared context selector remains a host operation.

[GraphDerivation](../../../../../crates/araphor-data/src/graph/derive/adapter/mod.rs)
selects installed graph exports by their declared schemas.
It does not restrict package IDs to the current HF detectors.
[GraphReplayInputV1::normalized and manifest](../../../../../crates/araphor-data/src/graph/input.rs)
share input preparation between derivation and refresh. Normalization keeps the
existing full record and context conflict checks. It orders and removes duplicate
coverage ranges, keys, and gaps. It excludes the reserved package sidecar from
fact input. `manifest` constructs the same exact retained references.
[GraphAndFindingOwner::derive](../../../../../crates/araphor-data/src/graph/derive.rs)
pins and authorizes the tenant before normalization. `derive_selected` then
validates the input, checks required packages, and runs the selected installed
exports. The normal refresh path uses this same preparation.
[Graph validation](../../../../../crates/araphor-data/src/graph/derive/adapter/validation.rs)
checks exact subject identities, parent facts, direct cause, evidence, confirmed
findings, and qualified coverage.
A package cannot increase authority or proof through an output claim.

[GraphDerivation::apply_output](../../../../../crates/araphor-data/src/graph/derive/adapter/output.rs)
adds Arrow dataset and reason bytes across the selected packages.
The aggregate limit is 4 MiB.
[WindowBytes::check](../../../../../crates/araphor-data/src/graph/derive/finish.rs)
counts the serialized graph snapshot after host validation. The checked writer
creates no output buffer. It stops above the existing 4 MiB JSON limit and
returns `GraphInvalid` with field `graph output bytes`. Historical stored reads
do not use this derivation check.
[GraphAndFindingOwner::commit_bounded_window](../../../../../crates/araphor-data/src/graph/commit.rs)
selects the existing
[window split](../../../../../crates/araphor-data/src/graph/chunks.rs)
only for `GraphInvalid` with field `graph output bytes`.
The rejected window commits no output. Every other error returns to the caller.
The commit owner adds position metadata and keeps its final serialized-byte
check before commit.

[FindingReasonV1](../../../../../crates/araphor-data/src/graph/model.rs)
stores declared reason codes with their schema and IPC details.
The host maps the historical eleven reason codes to legacy JSON only when the
declared detail schema also matches. A new detector requires no host enum entry.
Existing notification routes and human deadlines remain host-owned.
Host graph assembly already sorts retained evidence and removes duplicates.
Canonical publication preserves that historical finding JSON.
Generic package `Run` results retain SDK candidate and reason-detail IPC through
[PackageOutputV1::encode](../../../../../crates/araphor-data/src/package/output.rs).
The candidate and reason-detail IPC bytes change when publication removes
duplicate references or changes their order. Generic results do not use the legacy graph
reason mapping. An identical saved
[Run retry](../../../../../crates/araphor-data/src/package/evaluation.rs)
returns its original receipt before it prepares a new computation.

## Commit and recovery

[InstalledAnalysis::authorize](../../../../../crates/araphor-data/src/package/installed/commit.rs)
compares activation generation, revision, and metadata before a domain commit.
`commit_many` holds current authority for the complete selected root set.
Exports with different grants retain separate authority entries even when their
root is the same. Package owners for the same store share the lifecycle lock.
An update, removal, grant renewal, or suspension cannot cross the activation
check and domain commit. Owner construction uses the same lock during admission
collection. A supervisor can change readiness metadata without this lock.
This status change does not change the grant or activation generation.
Permission and trust are checked after computation as well as before it.
An authority change cancels an active call.

Saved discovery and graph context retains exact exports, revisions, roots,
activation generations, and configured parameters.
[Context validation](../../../../../crates/araphor-data/src/analysis/context/provenance.rs)
checks tenant scope and retained dependency closure during writes, reads, reopen,
and restore. The previous discovery format can omit package references.
New graph context requires valid references.
Artifact collection retains these saved roots.

[InstalledAnalysis::pin_at](../../../../../crates/araphor-data/src/package/installed/history.rs)
replays retained code and parameters under current permission and trust.
It reads current activations even when the caller holds an old snapshot.
A historical handle cannot commit.
[GraphAndFindingOwner::installed_refs](../../../../../crates/araphor-data/src/graph/installed.rs)
reads the bounded native header to obtain the source identity.
It does not reconstruct graph rows for this reference read.
The graph commit retains and validates its exact package provenance sidecar.
The visible input manifest excludes only this sidecar key. The sidecar remains
in the atomic context references and artifact collection inputs.

[GraphAndFindingOwner::commit_window](../../../../../crates/araphor-data/src/graph/window.rs)
checks retained-input expiry before it reuses a completed graph check.
The provider notice and coverage revision must match the saved per-result
metadata. [installed_current](../../../../../crates/araphor-data/src/graph/installed.rs)
then compares all compatible installed references and checks current permission.
Update, removal, a new compatible export, or revocation cannot use this shortcut.

[commit_bounded_window](../../../../../crates/araphor-data/src/graph/commit.rs)
can also skip guest execution after a provider notice changes. This path applies
only to a normal refresh. The selected input must validate, and its normalized
manifest must match the retained result. The saved coverage revision must equal
the current source coverage revision. All compatible installed references must
match, including exports, roots, revisions, generations, and parameters.
[window_context](../../../../../crates/araphor-data/src/graph/input.rs)
checks complete immutable context values before this decision. A change to raw
body bytes, validity times, or sensitivity under the same key fails this check.
[acknowledge_window](../../../../../crates/araphor-data/src/graph/commit.rs)
holds current activation and commit authority through `authorize`, then calls
`mark_graph_notice` for the same immutable window head.

[WindowRun](../../../../../crates/araphor-data/src/graph/window.rs)
keeps advance and force flags through chunk processing. Both flags bypass the
pre-guest reuse check. Failed-source recovery uses force.
[Expiry](../../../../../crates/araphor-data/src/graph/expiry.rs) runs before reuse
and keeps its existing proof downgrade and original package references.
The [notice reuse tests](../../../../../crates/araphor-data/src/graph/tests/notices/reuse.rs)
observe the real guest import. They check a notice-only skip, a later fact
replacement, forced execution, raw-context rejection, and recovery. A newer
report for an unrelated interval runs the guest even when manifest coverage
keys stay empty. The six focused notice tests pass. Disabling the shortcut
makes the skip test fail because the guest enters. The existing activation and
revocation group has two passes. At the initial v39 focused record, a new normal
build, four fresh production cases, and final workspace verification remain
required.

When a changed notice produces the same graph,
[commit_bounded_window](../../../../../crates/araphor-data/src/graph/commit.rs)
checks current commit authority and saves the captured notice through
[mark_graph_notice](../../../../../crates/araphor-data/src/analysis/progress/notices.rs).
The guarded update applies only to the same retained window head and immutable
commit revision. It changes no result body, receipt, quota, progress, or deadline.
A provider change during the check remains pending for the next pass.
Discovery uses the same metadata update owner and keeps its monotone notice rule.
The [notice tests](../../../../../crates/araphor-data/src/graph/tests/notices.rs)
use the production graph owner and installed components.
The [authority tests](../../../../../crates/araphor-data/src/graph/tests/installed/current/authority.rs)
check both an unchanged notice and a changed notice without changed facts.
The [activation tests](../../../../../crates/araphor-data/src/graph/tests/installed/current.rs)
check updates, added compatible exports, removal, history, and exact health.
The [metadata tests](../../../../../crates/araphor-data/src/analysis/progress/notices/tests.rs)
check separate windows, old-head rejection, immutable metadata, and retry.

[GraphAndFindingOwner::refresh_source](../../../../../crates/araphor-data/src/graph/live.rs)
reads current window bounds through
[graph_window_bounds](../../../../../crates/araphor-data/src/analysis/graph/windows.rs).
The native query filters the tenant and source before it ranks window heads.
The bounds read validates the selected header without reconstructing its rows.
[window_heads](../../../../../crates/araphor-data/src/graph/window.rs) uses
`graph_window_page` to select possible overlapping ranges. The checked header
decides exact overlap before the owner reconstructs rows. A page retains its
continuation ID when the candidate does not overlap.
The [window read tests](../../../../../crates/araphor-data/src/analysis/graph/windows/tests.rs)
check selection, continuation, history, and corruption. Current-source
qualification remains pending.

[AnalysisReadControl::run and AnalysisStore::read_snapshot](../../../../../crates/araphor-data/src/analysis/read.rs)
carry the native caller location into the existing deadline error. This location
identifies the call to the read runner or snapshot wrapper. The location does
not identify a specific SQL statement inside its read closure. The one-second
default read deadline
and cleanup rules stay unchanged.

[Graph notice migration](../../../../../crates/araphor-data/src/analysis/graph_migration/notices.rs)
converts schema 19 to schema 20 in one transaction. It initializes each retained
graph notice from its checked native header. The schema 17 conversion uses the
same header field. Both paths retain immutable records and validate stored state.
The [schema owner](../../../../../crates/araphor-data/src/analysis/mod.rs)
selects the checked conversion for each supported version.
The [migration tests](../../../../../crates/araphor-data/src/analysis/graph_migration/tests/notices.rs)
check retained versions, package references, reopen, restore, quota, retry, and
unchanged originals after rejection. The focused notice checks and the exact
installed lifecycle check pass. The full current group and final shared Rust
procedure remain required. See the [correction record](phase-7-5-4-wasm-execution.md#completed-graph-check-reuse)
for source hashes and failed attempts.

The generic package commit retains result, checkpoint, input references,
progress, and quota together. Domain adapters use their existing graph or
discovery commit. Identical retries return the original receipt.
Changed retries fail. A current freshness check can mark a retained result
stale. This status does not change its result ID, commit revision, data, or
checkpoint bytes. Missing required coverage remains explicit.
Removal retains its tombstone and does not reinstall a required package on
restart. Expiry reduces retained proof without executing removed code.

The [package lifecycle test](../../../../../crates/araphor-data/src/package/tests/wasm/lifecycle.rs)
uses its test authority to observe the revision 2 receipt after the commit.
The test checks the Wasm target, output value 7, and immutable receipt fields.
The returned response can mark the saved result stale after a clock change.
The test keeps the clock, retry, reopen, rollback, and removal checks.

## Limits and proof

Compilation accepts at most 8 MiB of component source and a 32 MiB image.
The compiler has a 1 GiB address-space limit, 30-second CPU hard limit,
and 45-second wall deadline. Structural scan limits also apply.
Host domain calls have a finite 60-second outer deadline for a cold cache.
[QueryLimits](../../../../../crates/araphor-data/src/query/mod.rs) defaults to a
one-second evaluation timeout. The query owner uses its configured timeout.
This query deadline applies after compilation. A configured Wasm timeout can
shorten the inherited caller deadline.
Epoch interruption stops guest instructions. A synchronous
host call or canonical application binary interface (ABI) operation finishes
before the host checks the
control deadline again. An expired call cannot commit.

[WasmLimits](../../../../../crates/araphor-data/src/query/wasm.rs) contains six
optional quotas. Every field defaults to `None`. An omitted or `null` field
leaves that additional Wasm quota unset.

| Field | Configured quota |
| --- | --- |
| `fuel` | Instruction fuel units per evaluation |
| `memory_bytes` | Guest linear memory bytes, including initial memory |
| `data_bytes` | Additional SDK data-byte ceiling |
| `timeout` | Additional guest timeout, within the caller deadline |
| `allocation_bytes` | Approximate allocation fuel for canonical ABI copies |
| `host_calls` | Calls to the WIT `cancelled` import |

The parent and compiler engines enable instruction metering only when `fuel`
is set. Each call applies its configured fuel budget. The same configuration
path applies in production and tests. Resource-failure tests set the quotas
they check. The earlier 32 MiB data and 100 million fuel settings are historical
configurations. Current-source qualification remains pending.

Mandatory guards remain. Each store permits one memory, four tables,
16,384 elements per table, and 16 instances. The engine uses a 512 KiB Wasm
stack bound. The Wasm owner permits four active evaluations. SDK schema,
reference, batch, row, and byte checks remain. The component path caps batches
at 1,024, rows at one million, and checkpoint data at 16 MiB. Query input defaults
to 64 MiB. Shared query input capacity is 128 MiB; output capacity is 16 MiB.
Caller cancellation, the query deadline, authorization, and atomic commit checks
remain. The `allocation_bytes` quota does not measure total host resident memory.
When this quota is unset, value lifting has no additional Wasm allocation cap.
These settings do not bound total process resident memory.

The local package file has a 32 MiB bound.
Package JSON requests and replies allow an additional 64 KiB.
The package transport permits an additional 128 KiB for protocol framing.
The [code cache](../../../../../crates/araphor-data/src/package/wasm/cache.rs)
has an 80 MiB byte limit and a 16-entry limit.
On the earlier qualified Linux x86-64 build, the four required components charge
61,237,517 bytes in total. The SDK runtime fixture raises this total to
74,374,204 bytes. Each charge includes source bytes and mapped image bytes.
These figures predate the current SDK and graph schema corrections.
The cache index and prepared handles share each code entry. The byte and entry
charges stay live until the last reference drops. Cache eviction or clearing
cannot release the charge for retained code. Admission removes only entries
that have no other reference. Admission returns `AnalysisBusy` when live code
prevents a new reservation. The byte and entry limits do not change.
The [cache lifetime test](../../../../../crates/araphor-data/src/package/wasm/cache.rs)
checks both limits, cloned cache indexes, retained handles, and final release.
The [prepared execution test](../../../../../crates/araphor-data/src/package/wasm/tests/runtime/prepared.rs)
clears the index and holds the compiler permit. The saved handle still executes
the real component and returns value 42. A foreign engine rejects the handle.
The focused v44 runs pass 40 tests with zero failures. Four private compiler
workers remain ignored in the parent harness. The proof is
`/tmp/araphor-live-code-proof-v44.json`, with SHA-256
`bd1c71ec2f6a2fe747f938fb1b6e5554397a56e53b48d2f43bf742ad5cc08fad`.
The five current component charges total 66,333,163 bytes. The complete cases
and final workspace procedure remain required after the last Rust edit.
The [execution error](../../../../../crates/araphor-data/src/package/wasm/execution.rs)
also retains a charged handle. Wasmtime backtrace frames retain compiled modules.
The original error source drops before the handle. The host classifies the
original trap before it adds the handle. Display, the source chain, and the
exact root trap remain available. The retained-trap regression fails on the
original error path and passes after the correction. Cache clearing cannot
release the charge while the error is retained. Dropping the error releases
the last charge. The v45 focused runs pass 41 tests with zero failures and four
ignored private worker entries. The reviewed proof is
`/tmp/araphor-retained-trap-reviewed-proof-v45.json`, with SHA-256
`8a096e939a8fcf0e68581f4ac17a7775aa7384926c72d00c8f073116e4eb5799`.
Complete qualification and final workspace verification remain required.
The code charge excludes engine metadata, allocator overhead, and Arrow buffers.
Query accounting and evaluation limits bound input and output separately. The
code limit is not a total process memory limit.

The [native store](../../../../../crates/araphor-data/src/analysis/connection.rs)
has one 128 MiB buffer limit shared by its writer and two cloned readers.
[Backup validation](../../../../../crates/araphor-data/src/analysis/backup.rs)
uses the same constant. The graph window stays at 4 MiB. The separate SQL
evaluator keeps its 64 MiB target. These settings do not limit process RSS.
The [native limit test](../../../../../crates/araphor-data/src/analysis/capacity.rs)
checks the settings, rejects an allocation above the buffer limit, and confirms
that the failed insert stores no row. The
[restore test](../../../../../crates/araphor-data/src/graph/tests/traversal/recovery.rs)
compares all four saved component revisions before an owner can reinstall them.
The [supervisor](../../../../../crates/araphor-data/src/package/supervision.rs)
reuses each admitted bundle for the prepared-export check.

Review the committed Rust cases beside
[runtime isolation](../../../../../crates/araphor-data/src/package/wasm/tests/runtime.rs),
[compiler limits](../../../../../crates/araphor-data/src/package/wasm/compiler/tests.rs),
[package lifecycle](../../../../../crates/araphor-data/src/package/tests/wasm/lifecycle.rs),
[dependency replacement](../../../../../crates/araphor-data/src/package/tests/wasm/flow.rs),
[domain history](../../../../../crates/araphor-data/src/graph/tests/installed.rs),
and [context recovery](../../../../../crates/araphor-data/src/analysis/packages/tests/context/validation.rs).
The production [SDK detector case](../../../../../crates/mithril-e2e/src/discovery/packages/wasm.rs)
installs over TLS, reopens a new owner with an empty cache, replays, retries,
and revokes trust.

### Current algorithm proof route

| Algorithm | Installed execution proof | Host boundary |
| --- | --- | --- |
| AR-01: atoms and accounting | [Discovery captured results](../../../../../crates/araphor-data/src/discovery/derive/tests/baseline.rs) | Exact record identity, attribution, accounting, and coverage checks |
| AR-02: merge and display groups | [Discovery captured results](../../../../../crates/araphor-data/src/discovery/derive/tests/baseline.rs) | Host selection and retained profile identity |
| AR-03: baseline comparison | [Discovery captured results](../../../../../crates/araphor-data/src/discovery/derive/tests/baseline.rs) | Exact baseline and current profile revisions |
| AR-04: context integration | [Context round trip](../../../../../crates/mithril-e2e/src/discovery/roundtrip/context.rs) and [installed context component](../../../../../crates/mithril-e2e/src/discovery/roundtrip/context/component.rs) | Host permission, cutoff, selected records, and omissions |
| AR-05: HF-PROC-001 | [Graph captured results](../../../../../crates/araphor-data/src/graph/tests/baseline.rs) | Exact identities, parent facts, and native evidence |
| AR-06: HF-DW-001 | [Graph captured results](../../../../../crates/araphor-data/src/graph/tests/baseline.rs) | Credential identity, evidence, confirmation, and coverage |
| AR-07: HF-XNODE-001 | [Graph captured results](../../../../../crates/araphor-data/src/graph/tests/baseline.rs) | Cross-node causality remains unqualified; retain current Kubernetes proof limits |

The captured-result tests use installed components from the shared algorithm
source. AR-04 sends the host-selected packet through a real component. The
qualification case checks the returned rows, revision, coverage, cutoff, and
omissions. The component does not select or authorize context.

The [cached discovery fixture](../../../../../crates/araphor-data/src/discovery/derive.rs)
and [cached graph fixture](../../../../../crates/araphor-data/src/graph/tests.rs)
use a mutex. Each test or fixture operation holds one guard through its
component calls. Production query capacity stays unchanged.
The [metadata deadline test](../../../../../crates/araphor-data/src/analysis/read.rs)
includes the native graph snapshot read. It checks typed expiry, released read
slots, unchanged metadata, and a successful fresh read.

The [graph replay fixture](../../../../../crates/mithril-e2e/src/discovery/graph_notification/replay.rs)
retains one graph owner before intake accepts sources. The same owner processes
sources, reads snapshots, and refreshes context. Reopen paths drop the owner
before they close stores. The directory drops last. The
[owner lifetime tests](../../../../../crates/mithril-e2e/src/discovery/graph_notification/replay/lifetime.rs)
check required registration, cursor wrap, context replacement, historical
findings, and source isolation. The registration test fails on the original
fixture. Both corrected tests pass. Their proof is
`/tmp/araphor-graph-owner-proof-v44.json`, with SHA-256
`285008d9497bf605c6eea26b765288883bc4c505ee7bad5e01fdb44bec40e3c5`.
The complete CLI case has static DEBUG step timings and an INFO whole-case
duration. These diagnostics add no timing threshold. The four complete cases
and final workspace procedure remain required for the final source.

Review these boundary tests with the algorithm cases:

- [Focused graph boundary tests](../../../../../crates/mithril-e2e/src/discovery/graph_notification/replay/tests/transport.rs)
  check transport, output rejection, rollback, replay, routing, delivery, restart,
  agent limits, and human acknowledgement in eight ordinary Rust tests.
  The commit and notification modules are siblings of the transport module.
  Each test shows its production calls and assertions. Helpers prepare inputs
  and initial resources only. All eight tests pass on the v46 captured source.
  The proof is `/tmp/araphor-focused-graph-proof-v46.json`, with SHA-256
  `5099009ea6a0500a6d26aa1220ecc6a85cd5ab8302ef7c65e2d010fb619a70c2`.
  At the v46 record, the full CLI, large workloads, and aggregate are unchanged.
- [Focused host boundary tests](../../../../../crates/mithril-e2e/src/discovery/graph_notification/replay/tests/context.rs)
  retain all 12 cards, device denial, policy history, local input proof, node
  isolation, provider facts, and read scope in nine more ordinary Rust tests.
  The other modules are siblings of the context module. Each single-test file
  has fewer than 100 lines. All nine tests pass on the v48 captured source.
  The proof is `/tmp/araphor-focused-graph-host-proof-v48.json`, with SHA-256
  `0d7be6a3a8f3aab8bb4b17f525c4e40d5b92668fc732815fa6a6e1692e42f644`.
  Eighteen existing graph and query tests also pass on the corrected Data source.
  Their proof is `/tmp/araphor-focused-graph-reuse-proof-v47.json`, with SHA-256
  `dafc5c5865d6e56f4677f22e5ec8234f2e4b3f39c7dec679079978d79f120957`.
  Reuse these owner tests for read-result, contradiction, provenance, baseline,
  authorization, sensitivity, follow, and subject-join checks. The complete CLI
  retains combined-source checks, all read and send records, and large inputs.
  The aggregate Rust invocation is removed after the focused proofs pass.
  The existing-output test retains its rejection assertion. The supported CLI
  still runs the complete case. At v50, production source before the test
  module, density, both native windows, and large Data traversal were
  byte-identical.
  The library test build passes after removal. Standard test registration proof
  is `/tmp/araphor-graph-aggregate-retirement-proof-v50.json`, with SHA-256
  `8f3ad02fcefab1e40d0d113253cd6057e3c40cc5a0896cced6061ce78d78d8aa`.
  Four fresh complete cases and final workspace verification remain required.
- [Installed guest overlap](../../../../../crates/araphor-data/src/package/wasm/tests/runtime/concurrency.rs)
  uses the shipped Discovery `groups` component for two tenants. Both tenant
  snapshots retain the same installed owner. The test checks separate
  evaluation IDs, group keys, and sample identities. It checks member indexes
  `[0, 1]` and aggregate counts 5 and 18. Each output has no checkpoint,
  evidence, or reason. The focused overlap test and the existing cancellation
  test pass on the v12 source. Final qualification remains pending.
- [Multiple input batches](../../../../../crates/araphor-data/src/package/wasm/tests/runtime/batches.rs)
  includes an empty batch and verifies the computed total.
- [Checkpoint recovery](../../../../../crates/araphor-data/src/package/tests/wasm/checkpoint.rs)
  verifies prior state, restart, and an old retry after a later state commit.
- [Native graph component input](../../../../../crates/araphor-data/src/query/analysis/tests/component.rs)
  verifies bounded traversal rows and an empty replacement through a component.
- [Graph package references](../../../../../crates/araphor-data/src/analysis/graph_rows/tests/packages.rs)
  reject a wrong result key or corrupt sidecar before commit. A valid commit
  and retry retain the same visible graph and package references.
- [Graph output splitting](../../../../../crates/araphor-data/src/graph/tests/bounded.rs)
  uses installed components with 256 records and 67 facts. The test requires
  the exact whole-window aggregate byte error, unchanged metadata, and no
  partial finding commit. The test requires split processing to consume all
  256 records and retain 255 native findings and one contextual credential
  finding with exact evidence. Each stored result must stay within 4 MiB.
  The v23 run exhausts guest fuel before the aggregate error. Evidence recovery
  passes. Current production-limit graph splitting remains open.
- [Domain commit fences](../../../../../crates/araphor-data/src/package/installed/commit/tests/changes.rs)
  verify that Run renewal and supervisor suspension cannot change an activation
  during the commit callback.
- [Cache accounting](../../../../../crates/araphor-data/src/package/wasm/fixtures/tests.rs)
  checks each source and mapped image charge and retains all five components.
- [Output deadline](../../../../../crates/araphor-data/src/query/model/tests/clock.rs)
  rejects a result after the local deadline while the caller deadline remains
  valid. The next call can obtain the released memory lease.

## Production qualification

Build the normal qualification binary for the current source. Run all four
cases and the final shared Rust procedure after the last Rust edit.
Run all four cases before the final shared Rust procedure, as the phase
implementation checklist requires. Keep the source unchanged until both checks
finish. Run the graph case and CI separately to reduce simultaneous disk use.
Run each case in a separate output directory that does not yet exist. Use the
same binary for all four cases. Keep it unchanged while its compiler children
run.

```sh
CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo build --locked -p mithril-e2e --bin mithril_discovery_test
qualification_root=$(mktemp -d /tmp/araphor-qualification.XXXXXX)
cp target/debug/mithril_discovery_test "$qualification_root/mithril_discovery_test"
"$qualification_root/mithril_discovery_test" --case analysis-packages --output-directory "$qualification_root/analysis-packages"
"$qualification_root/mithril_discovery_test" --case context-roundtrip --output-directory "$qualification_root/context-roundtrip"
"$qualification_root/mithril_discovery_test" --case profile-restart --output-directory "$qualification_root/profile-restart"
"$qualification_root/mithril_discovery_test" --case graph-notification --output-directory "$qualification_root/graph-notification"
```

Require exit code 0 and a `result.json` with schema version 1, the exact case
name, and result `PASS`. Retain the source and binary hashes, logs, and output
files. These cases use the production configuration with optional Wasm quotas
unset. Configured resource-failure tests remain separate required checks.

| Case | Required proof |
| --- | --- |
| `analysis-packages` | Install the SDK detector over TLS from its built folder. Check restart, retry, trust revocation, threshold 3, four input records, three matching evidence records, reason `example-burst.THRESHOLD`, and no host rebuild. Check the package checkpoint counts 2, 2, and 1. |
| `context-roundtrip` | Check signed context, cursor 1, and the installed context component. The returned identity, revision, and coverage must match. Check one selected record, no excluded record, and one omission. |
| `profile-restart` | Check the context fields above, live profile, late context, deterministic profile, immutable sealed revision, and frozen replay without provider calls. Retain `profile.json` and `profile-unresolved.json`. |
| `graph-notification` | Check acknowledgements `[null, null, 2, 2]`, cursors `[0, 0, 2, 2]`, failed transaction, duplicate intake, and equal replay. Check the original notification deadline and human receipt. Check 12 incident cards, 257 findings and obligations, and native windows of 64 and 185 records with equal results after reopen. Retain `graph.json`. |

The commands above are required checks. They do not record a pass.

The [qualification server owner](../../../../../crates/mithril-e2e/src/discovery/graph_notification.rs)
awaits shutdown on success or failure and retains the original error.
Its expired-certificate test requires both stores to reopen after failure.
The [replay fixture](../../../../../crates/mithril-e2e/src/discovery/graph_notification/replay.rs)
closes owners before its temporary root and releases the completed incident
fixture before independent density and window checks. The
[command entry point](../../../../../crates/mithril-e2e/src/bin/mithril_discovery_test.rs)
returns an error after Tokio shutdown. Existing assertions and workloads remain.

## Verification record

**Not done.** This guide describes the implementation under qualification.
Later corrections retain live compiled-code charges in prepared handles and
returned trap errors. Their focused proof passes 41 tests. Seventeen focused
graph tests also pass before the shared-input correction. Eighteen existing
graph/query tests pass on the corrected Data source. The duplicate aggregate
Rust invocation is removed. The complete CLI and large workloads remain.
The [shared input owner](../../../../../crates/mithril-e2e/src/discovery/graph_notification/replay/inputs.rs)
now supplies card, read, and send inputs to both CLI and focused callers.
Its children prepare inputs only. Graph operations and assertions stay in the
callers. The normal test build passes. All 17 focused runtime checks pass for
this correction in 1,093.82 seconds, with zero failures and no ignored tests.
The change removes 187 Rust lines overall. Its reviewed proof is
`/tmp/araphor-shared-graph-inputs-proof-v52.json`, with SHA-256
`972a54ad508452cb7ab3020a15a379d534b39292978a66f2d0220c47ccbb0f09`.
The [final source record](phase-7-5-4-wasm-execution.md#final-source-qualification-record)
captures source `1f6b434` and its normal executable. The fresh v53 installed
package case exits zero and reports `PASS`. The real client installs the SDK
detector without a host rebuild. Restart, retry, and revocation checks pass.
The fresh context case also passes. Installed transport preserves identity,
revision, coverage, and the host-selected cutoff. The fresh profile restart
case also passes. Live profiles persist and late context resolves after reopen.
The complete graph case also passes with all 12 cards, 257 notification
obligations, and both native windows. Its recorded duration is 1,995.544 seconds.
All four fresh cases use the same captured source and executable. The final
workspace procedure stopped at the user's request with exit 130 after
formatting, workspace check, and strict Clippy passed. Workspace tests did not
complete. The user approved the
[revised completion goal](phase-7-5-4-wasm-execution.md#approved-completion-goal-and-remaining-todos)
on 2026-10-12. It requires current installed equivalence and preserves the
earlier dispatch-order error as history. Production cost isolation, any
confirmed corrections, and terminal final CI remain required.

The subsequent descriptor and codec correction passes 14 algorithm tests and
54 SDK tests. The SDK all-features command passes 55 tests, including generated
bindings. These counts overlap. They are not separate algorithm corpora.
The [correction proof](phase-7-5-4-wasm-execution.md#descriptor-and-codec-correction-proof)
records the commands and preserved validation order. These focused results do
not qualify the changed guest artifacts or establish a production speed
improvement. Affected production cases and final workspace CI remain required.

The following records retain their original source boundaries.
The isolation fixture now issues trace authority after service startup. Its
existing case passes in 88.81 seconds. The
[query fixture](../../../../../crates/mithril-e2e/src/observability/query.rs)
starts the public listener with the other services before capture. It connects
the same client and runs the unchanged 10-second query contract during capture.
One shutdown method closes the query service before Control reopen. Its existing
case passes in 69.70 seconds, including service startup. The 60-second active
case, 30-second capture, 120-second grant, and original assertions remain.
The [phase record](phase-7-5-4-wasm-execution.md#query-upload-diagnostic-correction-todos)
retains both red and green results. The corrected Rust source is committed
through `6cce92d1`. Its normal locked build passes without warnings. The
[capture](phase-7-5-4-wasm-execution.md#corrected-normal-qualification-capture)
records the frozen source and complete saved executable. All four fresh v43
cases pass with that executable. Ordered final workspace verification remains
required. The
[record](phase-7-5-4-wasm-execution.md#fresh-qualification-on-the-corrected-source)
retains the real client installation, custom reason, checkpoint, and lifecycle
proof. Fresh context and profile restart cases also pass with equal v41 result
bytes. The graph case exits zero and reports `PASS`. It retains all 12 incident
cards, 257 findings and obligations across 33 sources, and both native windows.
The phase record retains the immutable four-case completion snapshot. Final CI
starts after all four cases pass, then stops with a controlled SIGINT before
the user-requested performance and test-maintainability corrections. It exits
130. Formatting, workspace check, strict Clippy, and linking pass. The completed
targets have 135 passes and one ignored test. Workspace verification is
unfinished. The
[start record](phase-7-5-4-wasm-execution.md#ordered-final-verification-on-the-corrected-source)
retains its command, source checks, and interrupted result. After the last Rust
correction, all four fresh cases and final CI remain required. The historical
dispatch order remains unmet.

The retained multi-export correction is committed in `b14ffb2`. Its two focused
regressions and normal build pass. Its source has 1,590 files and source SHA256
`1807fd55302479664c33f129c2e487020e0f0b872fd24f06135e9ca74e192c0a`.
The saved executable is `/tmp/araphor-current-v41-bin/mithril_discovery_test`,
with SHA256 `8096891350c3022c5674df9974abb6ef390a5b48336f52d6dba7d4795623bcee`.
The [v41 capture](phase-7-5-4-wasm-execution.md#current-multi-export-production-capture)
records copy checks, component hashes, and checked cache recovery. The fresh
installed-package case passes with result SHA256
`30f956ac4e461befe7eb0e7ada5991dd18da041d52ca943c795eda51ed2738f6`.
The aggregate proof is
`/tmp/araphor-wasm-production-proof-v41.json`.
The fresh context round-trip case also passes, with result SHA256
`312cd19eaec497b7be967bb10f94ff74fe7f8f33a6a6cbd785a578c94906f587`.
The fresh profile restart case also passes, with result SHA256
`3e4dbc6f293c12a9911137d41285b1b18b4ec2c02df03c0a3cd2f265f6d996d5`.
The fresh v41 graph case also exits zero and reports `PASS`, with result SHA256
`912f2dbd7d8823190a861c72e09d4bfb5bc23fa4a0e9d6648b70036d0320dbe6`.
All four fresh cases pass with the same saved executable. The graph proof is
`/tmp/araphor-wasm-graph-proof-v41.json`, with SHA256
`ebb44bbfdff12e464b533796119faba58c9b48f95002351af5f88291cfbe67a9`.
The case retains all 12 incident cards, 257 findings and obligations across
33 sources, and the 64-record and 185-record native windows. The windows return
192 and 370 relationships. The larger window uses two SQL chunks. Reopen,
exact versions, subject joins, evidence, proof, coverage, original deadlines,
human receipt, intake acknowledgements, and transaction rollback checks pass.
The case remains lightweight recorded replay. Ordered final CI and closure
remain required.
The first v41 procedure starts after the last Rust edit, before the fresh graph
case. Formatting, workspace check, strict Clippy, and test linking pass. The
root stops this unfinished run with SIGINT to follow the phase's required order.
It exits 130. No test failure is reported. The SDK suite has 52 passes. The
large corpus, graph bounds, evidence recovery, mixed-export graph regression,
and large native traversal tests pass. Workspace verification is incomplete.
The log is `/tmp/araphor-wasm-rust-ci-final-v41.log`, with SHA256
`2cfcd512d1c13470b97bc251c39779d82753cad1c03faad80aa2b219ac1fb56d`.
The final procedure must run again after fresh graph qualification.

The ordered final procedure now starts after all four fresh cases pass.
All 1,590 source hashes, the saved executable hash, and all four result file
hashes match before the start. The command retains one Cargo build job and one
test thread. The log is `/tmp/araphor-wasm-rust-ci-ordered-v41.log`. The capture is
`/tmp/araphor-wasm-final-ci-ordered-capture-v41.json`, with SHA256
`ba2a5b58be2ce2659a49e22d2dafed33c6c9a7e3627a9b858e6568aca06b4d93`.
The procedure exits 101. Formatting, workspace check, strict Clippy, and test
linking pass. The 75 completed Cargo targets have 1,748 passes, two failures,
and 552 ignored tests. Data has 588 passes and seven ignored tests. The failing
e2e target has 171 passes, two failures, and 527 ignored tests. The failures are
the isolation trace-authority check and the query-upload timeout. Later targets
do not run. The log has SHA256
`fb8ccc87c6f8685051adf13f195c270a4528ea3c4c87d747cff443fcbab10d9c`.
The [phase record](phase-7-5-4-wasm-execution.md#ordered-final-workspace-verification)
links the immutable failed result and correction TODOs. No workspace pass is
claimed.

Independent guide review finds no additional source correction. All 157 local
links and anchors resolve. The review checks owners, quota defaults, generated
builds, operator installation, mixed exports, and lifecycle failures against
source. All 1,590 source hashes, 24 independent artifact hashes, and the saved
executable hash remain equal to their captured values. The review proof is
`/tmp/araphor-wasm-review-audit-v41.json`, with SHA256
`58f5e3d4fce119622894d7d93d900ce547dd7feaac424204c8b6fcd411e849b3`.
This proof retains the earlier partial CI snapshot. The later v41 graph proof
above closes fresh graph qualification. Ordered final CI and closure remain
required.

The retained v40 graph retry exits zero and reports `PASS`, with result SHA256
`125b6841f7e66aed953cfb060963147866908358481fc9554542c51044d17692`.
All four retained v39/v40 cases pass. The aggregate proof SHA256 is
`1eda662b77adc7a5e4dedc702935084b56fb158db84b015a5f55e3c2b3c74e26`.
The earlier failures remain recorded. These passes do not qualify the
multi-export correction. The records below retain their source boundaries.

The production repetition correction is committed in `82902cf4`. Its frozen
v39 source manifest has 1,588 files and source SHA256
`c1c5fcae09434446684c6cbe8fce4da61256a06271c119e469fa2b71a13921fa`.
The normal build exits zero without warnings. The saved executable is
`/tmp/araphor-current-v39-bin/mithril_discovery_test`, with SHA256
`2c6a05f5daefc9e85c921d31496a262e2ecac8ebe17df71d9561b4de90603e3f`.
The [phase result](phase-7-5-4-wasm-execution.md#corrected-production-source-and-final-verification)
records source, build, executable, and copy hashes. The new graph case and exact
final workspace procedure have started. Their terminal results and the other
three fresh cases remain required. The v38 proof below retains its older source
boundary.

The test-only lint correction in `b1339b57` changes no production input. The
v40 normal rebuild produces the same complete executable bytes as v39. The
identity proof is `/tmp/araphor-wasm-production-identity-v40.json`, with SHA256
`00816dde3e71d8d77f12a81ad53409391fc22085b31e81490324d3863a7660a6`.
Fresh installed-package, context transport, and profile restart cases exit zero
with the unchanged saved executable. Their records have separate commits and
cover the byte-identical v39/v40 normal executable. At that v40 record, the graph
case and exact v40 workspace procedure require retries. The graph case exits
1 at the filesystem reserve and produces no result file. The final procedure
passes formatting, workspace check, strict Clippy, and test linking, then exits
134 during workspace tests after the disk fills. No complete workspace pass is
recorded. The [storage failure record](phase-7-5-4-wasm-execution.md#current-storage-failure-and-recovery-todos)
preserves both log hashes and required retries. The aggregate proof is
`/tmp/araphor-wasm-production-proof-v39.json`.

The [phase result](phase-7-5-4-wasm-execution.md#result) will record final source
state, commands, counts, and evidence after the required checks pass.
The [build proof](wasm-component-build-proof.json) records independent component
build hashes. This work adds no new BPF program or ABI, physical-prevention
qualification, native target, OCI distribution, or performance result.

The retained v38 Rust source is committed through `20db87a9`. Its 1,586-file manifest
is `/tmp/araphor-wasm-source-manifest-production-v38.json`, with source SHA256
`e4681bec06f08de042c760c75fd0a76025b5fdfa945262e30e9377c1455a1a06`.
The saved normal executable is
`/tmp/araphor-current-v38-bin/mithril_discovery_test`, with SHA256
`b1d25154f255dbac2aefb7fc1fc063d38972628beba20f7fbcddef000173320f`.
Fresh `analysis-packages`, `context-roundtrip`, and `profile-restart` cases use
this unchanged executable. All three exit zero and produce schema version 1
`PASS` results. Their records have separate commits: `e4deb6cd`, `fdbd67c9`,
and `75c0e363`, respectively. The proof is
`/tmp/araphor-wasm-production-proof-v38.json`.
The fresh `graph-notification` case also exits zero and reports `PASS`. Its
result SHA256 is
`7e79955351206bd3ab153a803fac872d03509daf2e888b03906e029316c3644d`.
It preserves 12 incident cards, 257 findings and notification obligations,
33 source windows, and the 64-record and 185-record native windows. The latter
selects 370 relationships through two SQL chunks and reopens with equal output.
The aggregate proof SHA256 is
`3d9531eaed7693c662acf3379c3a0545cbc8f1f33c0220a24879b2385e3174f8`.
These four passes cover the retained v38 executable. Production repetition
corrections are under review. They require a new source capture, normal build,
four fresh production cases, and the final shared Rust procedure.

The retained v37 Rust source is committed through `6f6ac795`. All 1,586 files in
`/tmp/araphor-wasm-source-manifest-production-v37.json` matched source SHA256
`0df1d83246835e7158967cd7890a9cb8deda67f0061859b18e81191e628d6bb0`.
Two independent builds reproduced all six source-built components. The v37
runtime group had ten passes and one filesystem-reserve failure. After checked
cache recovery, the unchanged installed overlap test passed in 87.58 seconds.
The group and retry logs have SHA256 values
`7ac12dddedc80822246c50be7be6e82bf655285f45cbc36cf71e94caa0d6160a`
and `2f559b478f7ebf49bb9093fd2941fdfb4e104697f050a3addbd8ad5b5c510fee`.
The [phase record](phase-7-5-4-wasm-execution.md#current-native-build-failure)
contains the exact reserve, cache, loaded-section, and executable proof.
Four fresh normal production cases and the final shared Rust procedure remained
required on that source. The records below retain their historical source and
limits.

The retained v31 verification record follows `d8528992`. Its 1,576-file source
manifest is `/tmp/araphor-wasm-source-manifest-production-v31.json`, with SHA256
`12f6f8e821a5fe2aeb18fe727b3f6d9a65202492a75d7f9bb4a79237841823e7`.
Canonical evidence publication, the derived JSON byte check, and the common
edge prefix are implemented. The v27 graph group has five passes at production
limits. These are historical checks; final current-source CI remains required.

The earlier v30 production cases passed with the saved normal executable:
`analysis-packages`, `context-roundtrip`, and `profile-restart`.
The executable is `/tmp/araphor-current-v30-bin/mithril_discovery_test`, with
SHA256 `2bce7ffca52037ea28d6b974f38a9d16fad443ed76d63de2968568ba8f96eca2`.
Production source is unchanged between v30 and v31. The v31 normal build
produces the same executable bytes after test-only corrections.
The graph case exits one on the unchanged filesystem reserve and writes no
result. Its same-binary retry uses `/tmp/araphor-current-v31-graph-retry`.
The retry also exits one, with `AnalysisReadDeadline` at the final read cleanup
check. This earlier location does not identify the native read operation.
The proof is `/tmp/araphor-wasm-production-proof-v30.json`. Graph qualification
and the final shared Rust procedure remain required.

Current source also includes optional Wasm quotas, input reservation from
retained allocations, native window selection, and caller-location errors.
The combined source still requires complete algorithm and lifecycle checks,
the remaining graph production case with the saved executable, and the final
shared Rust procedure after the last Rust edit. Earlier source records do not
qualify these corrections. The dispatch ordering breach remains recorded.

The retained v23 graph group has one pass and one failure. Evidence recovery
passes. The split test exhausts guest fuel in graph output encoding. The log is
`/tmp/araphor-wasm-graph-recovery-and-split-production-v23.log`.
This run is historical evidence. It does not qualify the current changes.

The retained v26 graph group has one pass and one failure after 251.72
seconds. Evidence recovery passes. The split case exhausts guest fuel in
`quicksort<u64>` from `Computation::output`, before row encoding. The proof is
`/tmp/araphor-wasm-production-bounds-proof-v26.json`.
The later v27 graph checks pass. The current graph production case and final
workspace procedure remain required.

The focused correction run `v10` passed all six tests in 602.21 seconds.
The log is `/tmp/araphor-wasm-fixture-and-graph-tests-v10.log`.
The run includes `graph::tests::bounded::output_bytes_split` and
`package::tests::wasm::lifecycle::wasm_installed_lifecycle`.
The source manifest is `/tmp/araphor-wasm-source-manifest-correction-v10.json`.
Its SHA256 is `a0a0ee9405ef1963bc1e471f097c45df66dae7724074e299b11caa31d1aa5481`.
The run uses temporary unit test allowances. These allowances precede the
[approved resource policy](phase-7-5-4-wasm-execution.md#approved-resource-policy-correction)
and do not qualify current execution. The final shared Rust procedure and
production qualification remain incomplete.

Concurrency correction source `v12` adds
`package::wasm::tests::runtime::concurrency::installed_guests_overlap`
and the test-only release gate. Compilation and both focused tests pass.
The proof is `/tmp/araphor-wasm-concurrency-proof-v12.json`. The overlap and
cancellation logs have SHA256 values
`533d27f5c2c5a0fb8915195be8ae0b7f8691c1f5d6c0c4680c9f5d31a820c3a1`
and `813c5b0a6c375e4849aa883310bb4565e587e174da3f6407fc4c6950cfe6a59c`.
The source manifest is
`/tmp/araphor-wasm-source-manifest-concurrency-v12.json`.
Its SHA256 is `47d73bbfec0059251f6c8851a410d232f83bf2440c4edef7d10720064b33eb8b`.
The shared Rust run `v11` uses earlier source and cannot qualify this correction.
The final current-source run `v12` ended with exit code 101.
Formatting, workspace checking, and strict Clippy passed.
Linking the `mithril-control` test `contract` failed with a linker Bus error.
The filesystem had 342 MiB free at the final observation.
The cause of the linker error remains unconfirmed. Full workspace tests did
not start. The log is `/tmp/araphor-wasm-rust-ci-final-v12.log`.
Its SHA256 is `033debd8c043ebce29898229ebc7db73ca80801170b0ad3a8ca63730f774cbfc`.
The result is `/tmp/araphor-wasm-rust-ci-final-v12-result.json`.
The source SHA256 remains the `v12` value above.

Cleanup removed debug sections from 13 inactive generated executables.
The cleanup saved 17,862,496,480 bytes. Every loaded section stayed equal.
The cleanup proof and log paths are
`/tmp/araphor-strip-proof-20261011-ci-v12.json` and
`/tmp/araphor-strip-ci-v12.log`.
The retry uses the same v12 source. Its log and result paths are
`/tmp/araphor-wasm-rust-ci-final-v12-retry.log` and
`/tmp/araphor-wasm-rust-ci-final-v12-retry-result.json`.
The run receives a controlled SIGINT and exits 130 before the required
production-bound discovery correction starts. It is live when interrupted.
No timeout or terminal test failure causes the stop. No CI descendant remains
after the stop. The log SHA256 is
`5a870fce9d077ac6fe0c9f6ad04bbf4545720d2dc2ae5e7b688d3d1bfb1c15c4`.
Formatting, workspace checking, and strict Clippy pass on v12. Workspace tests
remain incomplete. The bounded-input correction is implemented and committed.
At this earlier bounded-input record, all four fresh production cases and a new
final shared Rust procedure remain required.

## Bounded discovery input correction

Read `discovery/sdk/pages.rs`, then `discovery/sdk/atoms.rs` and
`discovery/sdk/snapshot.rs`. `RecordedPages` keeps all deliveries of a full
record identity together. It rejects orphan context and exclusion rows before
projection. Coverage pieces have adjacent cursor bounds. Their expected
counts stay within each piece width and sum to the original count. Empty
ranges, explicit gaps, lifecycle references, and evidence samples remain.

`derive_recorded` uses 128 complete identities per internal page. The
129-identity fixture crosses this boundary and compares whole and paged output.
`derive_recorded` pins installed execution once and uses the original input
revision and one finite control. Each page and its rolling merge use installed
components. Page evaluation leases drop before the next call. The method
validates the final result against the complete input and commits no page.
The opaque record-comparison string uses the existing full-record digest.
Host validation still compares complete records for duplicate conflicts.

The v20 discovery group passes all 28 tests at production limits. It includes
all 21 normal and duplicate replay cases. The
[rare-case helper](../../../../../crates/araphor-data/src/discovery/derive/tests/corpus.rs)
checks exact groups and all eleven comparison fields against a 64-record
baseline. Its proof is `/tmp/araphor-wasm-production-bounds-proof-v20.json`.
Later component rebuilds require new qualification.

The earlier v13 production and tests use 32 MiB of data and 100 million fuel
units.
Source `v13` has SHA256
`8c34f38f69015fb184c8d8660e81e7882340ac0f9dbea0109ff58a15e389f42a`.
The ten planner tests and both real-component correction tests pass. Their
proof is `/tmp/araphor-wasm-production-bounds-proof-v13.json`. The complete
corpus fails at the shared 60-second deadline on `rare-forbidden normal`.
The graph evidence-recovery test fails with `PackageWasm::Limit` in
`/tmp/araphor-wasm-graph-recovery-production-v13.log`. Fresh production
qualification and final Rust CI remain required.

The graph correction changes `Computation::output` in
`araphor-analysis-builtins/src/graph/contract.rs`. It constructs one
reason-details port before the finding loop and reuses it. Finding values,
reason codes, evidence links, schemas, and checkpoint state stay equal.
The graph schema correction passed 13 shared tests. Two independent builds
produce equal bytes for all four required components. See `graph_schema_correction`
in [the build proof](wasm-component-build-proof.json). These checks do not
replace current production-limit graph recovery and output-byte qualification.
