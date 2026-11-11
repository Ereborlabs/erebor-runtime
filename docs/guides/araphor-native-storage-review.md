# Native Data storage review

Result: **Not done for the complete replacement**. This guide describes the
connected production replacement. Read the [current worklist](../research/araphor-fjall-integration.md#current-replacement-work-2026-11-10)
for qualification and remaining work. Earlier SQL review records are historical.

The five unused SQL storage files and five empty legacy package modules are
removed. The two `ResolvedInput` SQL files remain active DataFusion queries.
Historical package review links use the verified DuckDB control source revision.
The production Data library check passes after this removal. Existing warnings
remain. No new runtime or timing result follows from removal of unreachable files.

The connected release at `d429b0d08` passes two matched incident pairs.
Durable notification creation is 49.947–88.429 ms, a measured 6.70–7.30-fold
gain against DuckDB. Public receipt is 59.273–123.986 ms. Whole-test time is
2.12–2.23 seconds native and 5.10–5.13 seconds DuckDB. The 100-fold target
remains **Not done**. These short pairs do not establish a sustained latency
bound or a new gain from the journal/resume corrections alone.

Saved plans use native DataFusion operators. The default
[Causal bundle](../../crates/araphor-analysis/src/package/builtin.rs) contains
the Wasm Causal component. Its calls use
[WasmExecution](../../crates/araphor-package-runtime/src/wasm.rs).
Native shared-library loading is outside this incident path. Matched release
pairs show no incident gain from retaining native libraries. That experiment
is removed from production. Read the current worklist for its evidence.

## Reading order

1. [Public Data exports](../../crates/araphor-data/src/analysis/mod.rs) select the
   native owner. [NativeStore, DataView, and DataWrite](../../crates/araphor-data/src/analysis/native/mod.rs)
   own storage, captured reads, and the single commit boundary.
2. [Original raw intake](../../crates/araphor-data/src/analysis/native/source/raw.rs)
   appends event payloads once. [RawIndex](../../crates/araphor-data/src/analysis/raw/index.rs)
   indexes those original spans. A published DataView binds that raw prefix to
   one native snapshot. [Coverage reads](../../crates/araphor-data/src/analysis/native/source/coverage.rs)
   preserve the public API through one captured view and read cancellation.
3. [Input registration](../../crates/araphor-data/src/analysis/native/inputs/registration.rs)
   and [input checkpoints](../../crates/araphor-data/src/analysis/native/inputs/checkpoint.rs)
   retain subscription progress. [Query progress](../../crates/araphor-query/src/stream/progress.rs)
   consumes Data's matched log positions.
4. [Managed publication](../../crates/araphor-data/src/analysis/native/managed/commit.rs)
   commits package output and consumed progress. [Araphor Graph](../../crates/araphor-graph/src/native/mod.rs)
   supplies generic graph operations through Data's borrowed transaction.
5. [Source snapshots](../../crates/araphor-data/src/analysis/native/extraction/graph/snapshot.rs)
   and [indexed traversal](../../crates/araphor-data/src/analysis/native/extraction/graph/traversal.rs)
   serve retained results. [PublicationRead](../../crates/araphor-data/src/analysis/native/managed/graph/read/publication.rs)
   binds the selected publication to its exact writer cuts.
6. [Notification preparation](../../crates/araphor-data/src/analysis/notification/prepared/native.rs)
   reads one captured view. [NotificationCycle](../../crates/araphor-analysis/src/notification/cycle.rs)
   batches state writes. Pending attempts are durable before external delivery.

## Ownership and commit flow

Package definitions start subscriptions. SQL calls packages; package code owns
analysis. A package can use generic Graph facilities and stage the mutations it
chooses. It cannot commit Data's transaction. Graph has no package catalogue or
detector policy.

```mermaid
sequenceDiagram
    participant Intake as Collector intake
    participant Data as Data
    participant Query as Saved DataFusion plan
    participant Package as Package code
    participant Graph as Araphor Graph
    participant Notice as Notification router
    Intake->>Data: Validated event batch
    Data->>Data: Append and sync original raw commit
    Data-->>Query: Matching unconsumed log position
    Query->>Package: Incremental inputs and retained state
    Package->>Graph: Read indexes and stage mutations
    Graph-->>Data: Borrowed transaction changes
    Data->>Data: Commit Graph, findings, state, references, progress
    Data-->>Notice: Matching committed finding position
    Notice->>Data: Batch notification state and Pending attempts
    Data-->>Notice: Durable batch receipt
    Notice->>Notice: External delivery
```

Native commit failure stops publication. An uncertain engine write poisons the
owner. [Raw recovery](../../crates/araphor-data/src/analysis/native/recovery.rs)
must preserve every acknowledged raw commit. Changed native metadata or engine
poison requires reopen. A failed package attempt cannot advance consumed input.

The existing post-commit timing event divides transaction work into validation,
derived values, results, references, Graph staging, Source publication,
projection, and final state. Adjacent timers cover that interval exactly.
They change no operation order. The release incident diagnostic passes in
2.07 seconds. Its largest inner phase is Graph staging at 4.870 ms median.
Read the current worklist for the measured notification boundaries and limits.

Ordinary Graph table projections do not require package state. Explicit complete
snapshots require real package state. Traversal uses native node and adjacency
indexes. One depth map spans the requested retained versions. Identity reads do
not load property chunks. Selected properties retain the normal validation path.

## Package evaluation

[Runtime::evaluate_reserved](../../crates/araphor-package-runtime/src/lib.rs)
passes the current tracing subscriber into its blocking worker.
[WasmExecution](../../crates/araphor-package-runtime/src/wasm.rs) reports wire
intervals. [GuestState](../../crates/araphor-package-runtime/src/wasm/execution.rs)
counts Graph calls and sums callback and native service durations. One event
reports those totals after the component call and cleanup. No payload is logged.
The unchanged diagnostic incident passes. All 31 Wasm runtime cases pass
serially. An earlier parallel cancellation case times out before guest entry;
the exact unchanged rerun passes. Its cause remains unproved. Diagnostic timing
does not establish an end-to-end gain.

[Runtime::evaluate_reserved](../../crates/araphor-package-runtime/src/lib.rs) sends the owned evaluation and host service to its existing blocking worker.
  -> [Package::check_evaluation](../../crates/araphor-analysis-sdk/src/validation.rs) checks the immutable descriptor and current input once at the host boundary.
  -> [HostAccess::bind](../../crates/araphor-package-runtime/src/host.rs) obtains Graph capability from that checked model.
  -> [WasmExecution::evaluate_prepared](../../crates/araphor-package-runtime/src/wasm.rs) reuses the checked value for input encoding and output decoding.
  -> [Output::decode_checked](../../crates/araphor-analysis-sdk/src/wire/output.rs) checks wire framing, output schemas, evidence, reasons, checkpoints, and the configured copy bound.

The guest retains its own input checks across the Wasm boundary. Graph callbacks
retain schema checks and current transaction authority. Native calls bind the
same narrowed host after their checked input is constructed. A caller without
declared Graph capability receives the same typed denial before any callback.
Standalone output decoding keeps its existing error order. No ABI or durable
format changes.

The existing package event separates Graph binding, evaluation, output retention,
Graph freezing, and final row counts. Adjacent timers use one completion time.
Their sum equals the measured interval before microsecond truncation. Initial
qualification measures evaluation medians of 7.043 and 6.569 ms for the two Causal
calls. Binding is about 1.9 ms per call. Freezing is about 0.2 ms per call.
These values identify the measured owner; they do not establish a latency gain.

Ninety SDK cases and 31 Wasm runtime cases pass. The current ABI fixture uses
native request and API v2 names. C and Rust sizes, alignments, and existing
offsets remain checked. The additional host-pointer offset check passes.
The new runtime case checks exact capability denial, zero service callbacks,
an untouched invocation gate, and a successful ordinary retry. Read the current
worklist for the paired incident measurements and remaining work.

## Causal relation construction

[Causal::detect_model](../../crates/araphor-analysis-builtins/src/causal/descriptor.rs) constructs the one finding relation that the export declares.
  -> [FindingMember::port](../../crates/araphor-analysis-types/src/relations.rs) supplies the existing property schema.
  -> [CausalComponent](../../crates/araphor-analysis-builtins/components/causal/src/lib.rs) supplies the same package declaration inside each fresh guest.
  -> [Component::evaluate](../../crates/araphor-analysis-sdk/src/guest.rs) retains the existing guest input checks and Graph binding.

The prior factory constructs all four domain relations before it selects the
finding relation. Causal no longer constructs the three unused schemas. The
[descriptor case](../../crates/araphor-query/tests/native_execution/graph.rs)
compares the complete package and its JSON bytes with the prior factory.
The default definition, package exports, Graph operations, and component
isolation remain unchanged.

The focused Query target passes all three selected cases in 2.68 seconds.
It includes descriptor equality, real Wasm Graph publication with consumed
progress, and retained indexed versions.

Both matched unchanged incident pairs pass. Creation measures 44.157–82.437 ms
after this change and 49.254–86.804 ms immediately before it. Public receipt
measures 53.124–99.965 ms after this change. Whole-test time measures
2.26–2.30 seconds. The gain against the matched DuckDB control is 7.34–9.87 fold.
The 100-fold target remains **Not done**. Read the current worklist for build
hashes, the temporary diagnostic, and the exact verification commands.

## Scoped Graph reads

[Values::load](../../crates/araphor-data/src/analysis/native/managed/graph/projection.rs) receives an exact retained Graph property reference.
  -> [NativeStore::read_at](../../crates/araphor-data/src/analysis/native/mod.rs) selects its historical Data cut.
  -> [Graph::scoped_view](../../crates/araphor-graph/src/native/mod.rs) point-reads the selected relation and writer metadata.
  -> [View::member](../../crates/araphor-graph/src/native/view.rs) reads the existing dictionaries, membership, and typed property chunk.
  -> [Values::load](../../crates/araphor-data/src/analysis/native/managed/graph/projection.rs) checks the saved layer and complete member identity before it compares values.

The reader uses the same private metadata loaders as the full Graph view. It
does not enumerate other relations or writers. Its existing local cache uses
graph, revision, writer, and relation as the key. Full Graph enumeration remains
available to callers that need the complete view. Canonical selection still
compares every distinct retained candidate, including a value sequence A, B, A.
No durable format, index, or authority rule changes.

The [Graph member cases](../../crates/araphor-graph/src/native/tests.rs) compare
full and scoped node and edge reads. They check retained history after compaction,
memory leases after the view closes, selected metadata errors, and isolation
from unrelated metadata. All 14 cases pass with `native-store` enabled in
0.72 seconds. The native Data domain suite passes all 24 cases in 2.57 seconds.
Both matched incident pairs pass. Durable creation measures 49.130–91.787 ms;
public receipt measures 57.319–107.847 ms. Whole-test time is 2.26–2.32 seconds.
The pairs establish no end-to-end gain over the preceding native source.
Result: **Done for the scoped reader**. The complete replacement and 100-fold
performance proof remain **Not done**.

## Package-row replacement

The current replacement uses native format 10. It rejects format 9 before Data reads
package rows. This is a changed durable format; no automatic conversion is
provided. The cutover qualification below used format 9.

[PackageRecord](../../crates/araphor-data/src/analysis/native/packages/mod.rs)
stores immutable metadata in `P`. The original artifact bytes occur once under
`\0data/@package-body/` and the same dictionary ID. Routine managed contracts
read metadata only. Full package reads join the artifact through the same native
snapshot or transaction. Existing artifact and bundle authentication still runs
at its owning callers. No verifier cache is added by this change.

Staged Graph admission uses the same metadata-only path. The public regression
removes a package body after it creates both Graph journals. Publication must
reach its exact final rejection guard and leave Data and WAL unchanged. Full
artifact reads and reopen still reject the missing body. Three Graph checks
pass. Matched incident runs reduce the measured Graph phase but do not establish
an end-to-end notification gain. Read the current worklist for those results.

Installation retries compare both metadata and artifact bytes.
[Collection](../../crates/araphor-data/src/analysis/native/packages/collection.rs)
removes metadata, body fragments, and the compact GC catalogue atomically.
[Recovery](../../crates/araphor-data/src/analysis/native/packages/recovery.rs)
checks exact body ownership, length, and fragment membership before it
authenticates artifacts. Historical views retain their original bodies.

The focused checks pass: ten package lifecycle cases, twelve context-proof
cases, three Graph authority cases, and prior-format rejection. Two opposite-order
native pairs pass the unchanged incident. This change reduces durable creation
from 143.985–265.681 ms to 50.864–89.282 ms, a measured 2.78–3.48-fold gain.

Two matched release pairs against the saved successful DuckDB control also pass.
Native durable creation is 50.864–88.972 ms; the paired gain is 6.45–7.36 fold.
Public receipt is 58.730–104.749 ms. Whole-test time is 2.08–2.12 seconds native
and 5.03–5.09 seconds DuckDB. The measured creation target is met in these runs;
the 100-fold requirement is not met. These short pairs do not establish a
sustained latency guarantee. Read the current worklist for exact report paths.

## Package image reads

[NativeStore::package_revision_until](../../crates/araphor-data/src/analysis/native/packages/mod.rs) receives a tenant, exact package revision, and read control.
  -> [AnalysisReadControl::check](../../crates/araphor-data/src/analysis/read.rs) rejects cancellation.
  -> [DataView::package_revision](../../crates/araphor-data/src/analysis/native/packages/mod.rs) joins metadata and the original body from one captured cut.

The default `package_revision` call uses that same path. The public
`package_image` and `retained_package_image` calls use the same read control.
Captured DataView reads and staged DataWrite reads keep their existing lifetime.
The image closure reader authenticates artifacts and the saved bundle digest.

[PackageHeader::check](../../crates/araphor-data/src/analysis/native/packages/catalogue.rs)
sorts its two temporary dependency-ID vectors before comparison. Dependency order
has no semantic effect. Missing, extra, or duplicate IDs still fail comparison.
The check does not change stored metadata, descriptors, artifacts, or the format.

[Row tests](../../crates/araphor-data/tests/native_packages/catalogue/rows.rs)
preserve the nine malformed-row errors and their status and retry categories.
The positive ordering case reverses only retained metadata. Live image reads and
reopen succeed. The stored vector stays reversed and the image digest stays equal.
[Image tests](../../crates/araphor-data/tests/native_packages/catalogue/images.rs)
keep the 33 MiB unqualified Native artifact and its exact round trip without
execution. Point-read checks preserve cancellation, unchanged Data metadata,
and unchanged original journal position. Reader quotas are removed.
[Lifecycle tests](../../crates/araphor-data/tests/native_packages/catalogue/lifecycle.rs)
retain shared dependencies, explicit dependency images, foreign tenant images,
definition roots, guarded uninstall, and reinstall after reopen.

The no-execution assertion checks managed instances, versions, calls, attempts,
Graph records, managed results, processor results, and the Discovery enable flag.
The native activation subscription owns a database handle. The restart fixture
drops that handle before it reopens the store. All no-activation assertions remain.
Sixteen native cases replace the fifteen old SQL cases; the positive dependency
ordering case is separate from the malformed-row matrix. Read the current
worklist for verification results. Private verifier and witness ports remain open.

## Package context collection

[NativeStore::collect_package](../../crates/araphor-data/src/analysis/native/packages/collection.rs) receives one tenant and package revision.
  -> [DataWrite::package_roots](../../crates/araphor-data/src/analysis/native/packages/collection.rs) selects retained image, context, definition, and managed roots for that tenant.
  -> [DataWrite::context_owner_ids](../../crates/araphor-data/src/analysis/native/context/index.rs) reads the existing tenant/owner index before it loads context bodies.
  -> [DataWrite::collect_packages](../../crates/araphor-data/src/analysis/native/packages/collection.rs) counts dependencies within the selected tenant and stages eligible removals.
  -> [DataWrite::commit](../../crates/araphor-data/src/analysis/native/mod.rs) commits those removals and publishes one Data revision.

Targeted collection and image uninstall carry the same tenant scope. All retained
context versions, definition revisions, and managed generations remain roots.
Global admission collection checks all tenants. A malformed selected context
rejects the transaction. Repair permits retry. Neither rejection nor a no-op retry
changes Data revision or the original journal head. No new index or format is added.

The old target path decoded a foreign tenant's malformed context. The public
native regression fails on that path and passes after the scope correction.
[Package context tests](../../crates/araphor-data/tests/native_context/packages.rs)
preserve tenant roots, revision notices, exact retries, seven forged fields,
dependency export identity, and malformed or trailing binary input.
[The large closure test](../../crates/araphor-data/tests/native_context/packages/closure.rs)
keeps 1,025 artifacts, 1,024 dependencies, dependency metadata above one MiB,
1,025 dependency exports, and exact digest equality after backup and restore.
[Corruption tests](../../crates/araphor-data/tests/native_context/packages/corruption.rs)
check current context, descriptor, missing artifact, and changed body faults.
The body change preserves byte length. Point reads, head pages, and reopen reject
the faults. One test warms verification, removes a dependency in the same staged
transaction, and rejects exact retry before rollback.

These ten native checks replace the old SQL package-context family. The separate
private verifier tests still require a native port. These checks do not establish
a new incident speed gain. Read the current worklist for commands and results.

## Usage, retention, and maintenance

[Checkpoint](../../crates/araphor-data/src/analysis/native/backup/mod.rs) first
saves safe filtered input positions. It then holds the Data writer during raw
sealing, native flush, and [journal collection](../../crates/araphor-data/src/analysis/native/inputs/collection.rs).
The collection owner catches the shared reader through the published view under
the scan lock. The minimum of that reader, the published cut, and every durable
input generation protects the original cursor anchors. Fjall removes only
eligible sealed journals. The active journal and anchor journal remain.

All saved generations constrain this floor. Version selection can revive an
older generation after removal and recreation. Collection does not add an
incarnation limit or change that behavior. Retained native values survive old
journal removal. Native history and original-log retention have separate policies.

Fresh subscription capture uses the same scan lock. The coordinator remembers
its acknowledged cursor there. A cached old snapshot can still report a cursor,
so explicit registration behind that floor is rejected. Restart restores saved
consumers before a later checkpoint advances the engine acknowledgement again.
No extra synchronization is added to each package commit.

Ordinary Query resume uses `NativeStore::subscribe_inputs_since`. A cursor at
the end of Data revision R starts at R. A partial cursor starts at R minus one,
clamped at zero, and replays the original commit. Existing row positions and
filters select the unread portion. The captured read revision can be newer than
the last consumed row; it is not the replay start. Fresh subscriptions still
start at the current captured cut and perform the initial query capture.
Durable managed and notification consumers keep their saved-position path.

An absent or released native cursor returns `AnalysisInputExpired`, with the
requested position. Query reports `CursorExpired`. Decoder and I/O errors are
not converted to expiry. No context/result scan or extra journal is added.

The user removes Data storage quotas on 2026-11-10. The source has no
`StorageLimitsV1`, quota constructor, reader permit, or storage-quota error.
[StorageUsageV1](../../crates/araphor-data/src/analysis/capacity.rs) reports file
bytes, allocated bytes, and available filesystem bytes. It does not reject an
operation at a configured threshold. [RevisionCounts](../../crates/araphor-data/src/analysis/native/capacity.rs)
remain integrity metadata and are checked during recovery. Physical format 10
remains valid. Actual I/O errors still stop an uncertain owner.

[Trace authority](../../crates/araphor-data/src/analysis/native/admission.rs)
checks store readiness and current request state. [Query](../../crates/araphor-query/src/execution.rs)
awaits that check inside its blocking worker. The [native revocation case](../../crates/araphor-query/tests/native_execution/trace.rs)
reads a real trace through a package plan. Revocation rejects the saved receipt
and captured execution. Failed execution leaves Data revision unchanged.

[Required backlog](../../crates/araphor-data/src/analysis/raw/budget.rs) derives
active Required minima from committed processor state. Volatile counters use
original raw spans. Byte admission includes unconsumed out-of-order spans.
Age admission includes only the contiguous accepted prefix. Exact retries pass
before these checks. A cursor advance examines the spans it crosses; partial
spans use the original frame ends. Rollback does not change the counters.

[Retention](../../crates/araphor-data/src/analysis/native/retention/mod.rs)
reconciles committed processor changes before it removes raw segments. It uses
those same Required minima. Reopen rebuilds the counters from committed state
and original spans. No second durable backlog index is added.

## Backup and recovery

[DataWrite::profile_rows](../../crates/araphor-data/src/analysis/native/progress/profile.rs) receives a typed package profile and its managed attempt.
  -> [NativeStore::read_at](../../crates/araphor-data/src/analysis/native/mod.rs) selects the attempt's captured input cut.
  -> [DataView::progress_inputs](../../crates/araphor-data/src/analysis/native/progress/coverage.rs) walks only the requested original source spans.
  -> [DataWrite::progress_rows](../../crates/araphor-data/src/analysis/native/progress/commit.rs) stages proved gaps, resume progress, profile results, and references in the existing transaction.
  -> [NativeStore::commit_managed_projection](../../crates/araphor-data/src/analysis/native/managed/commit.rs) checks cancellation and the final guard after the test hook, then commits the managed result and consumed input together.

The span proof excludes input expired at the captured metadata cut. Each new
gap matches the exact expiry revision and clipped original commit/intake group.
Live records plus proved missing records cover the consumed interval. Only
Optional Discovery accepts those gaps. Witness and context authority remain
current at the DataWrite cut. Profile and interval IDs have no equality rule.

[Progress recovery](../../crates/araphor-data/src/analysis/native/progress/recovery.rs)
gets the producer capture from the existing qualified managed result. It checks
each advancing typed result at its publication cut. Accepted gaps are absent
before publication and present at publication. The existing exact gap-set check
rejects missing or changed current rows. Resume-only transitions keep their
existing rule. No new table, archive, or durable format is added.

Eight [native gap cases](../../crates/araphor-data/tests/native_managed/progress/profile/gaps.rs)
pass, including later expiry, exact head conflicts, cancellation, and stamped
corruption. The final native managed suite passes 108 cases in 2.34 seconds.
Six native lifecycle cases pass in 0.14 seconds. The four legacy SQL gap cases
are removed. Result: **Done for these gap contracts**. Ten other legacy profile
cases and the complete replacement remain **Not done**. Both current production
incident pairs pass. Durable creation measures 47.035–83.606 ms; public receipt
measures 55.053–99.452 ms. Whole-test time is 2.10–2.12 seconds. The paired gain
against DuckDB is 7.01–8.04 fold. This parity change establishes no latency gain
over the preceding native source. The 100-fold target remains **Not done**.

[Processor history](../../crates/araphor-data/tests/native_managed/progress/history.rs)
walks the same processor key backward through native snapshots. Each stored
revision selects the preceding cut. The test requires exactly four versions:
registration, two results, and retirement. It checks result bodies and context
watermarks before expiry, after two raw records expire, and after compaction
and reopen. Exact retries and a rejected commit preserve Data revision and the
original journal head. [Processor recovery](../../crates/araphor-data/tests/native_managed/progress.rs)
also rejects invalid history start, class, progress, retirement revision, and
declared revision. The former SQL history module is removed. All three focused
processor cases pass in 0.47 seconds with `test-fixtures` enabled.

[Backup](../../crates/araphor-data/src/analysis/native/backup/mod.rs) seals raw
segments and exports the protected engine cut. The checkpoint callback records
unique relative paths and expected file lengths. Data compares that inventory
with the exported files. Data also checks directory membership, checksums, raw
records, and trace obligation metadata. The callback applies no storage quota.

A destination I/O failure can leave source flushing completed. It preserves the
logical Data cut and source readiness. Fjall removes the incomplete checkpoint.
The outer staging directory is temporary. Raw payloads occur once in the backup.

[Restore](../../crates/araphor-data/src/analysis/native/backup/restore.rs)
validates the complete bundle before it creates the target. It uses an exclusive
lease and a durable pending marker during copy and validation. A failed copy can
leave partial files. The pending marker prevents open and repeated restore.
Restore verifies store identity, raw receipts, history, and the committed cut
before it clears that marker. It advances the recovery epoch. An existing
DuckDB directory is rejected; it is not opened as an empty native database.

[Native crash checks](../../crates/araphor-data/tests/native_crash.rs) terminate
a child process at four backup and four restore boundaries. Only the final
backup publication exposes a restorable target. An interrupted restore keeps
its pending marker and rejects repeated opens. A complete restore advances the
recovery epoch once. The checks compare exact raw pages, native contexts,
source metadata, and every file listed in the backup manifest. They also check
backup retry after later input. The three focused tests pass in 1.47 seconds.
The old SQL backup and restore crash tests are removed.

## Quota removal qualification

The source removes Data quotas and their Control configuration. The retired
protobuf field numbers and names remain reserved. The engine keeps its normal
cache and memtable settings. Query, package, and Required-input resource owners
remain separate from storage usage reporting.

[Native backup checks](../../crates/araphor-data/tests/native_backup.rs) pass
eight cases. The tests include incomplete traces, 17 MiB raw segments, writer
exclusion, held views, duplicate-stamp readiness failure, private bundle paths,
physical faults, and semantic restore faults. The old SQL backup family is
removed after these replacements pass. Six lifecycle and four indexed
notification cases also pass. The [native trace check](../../crates/araphor-query/tests/native_execution/trace.rs)
passes captured-read revocation through Query and package execution.
The process-isolated file-size cases pass raw append failure and checkpoint
export failure. Both cases preserve their distinct ACK and recovery boundaries.
The export fixture copies empty native directories and checks the real EFBIG
cause. The failed export destination remains unpublished.

Production checks pass for Data, Query, Analysis, Control, CLI, and the E2E
harness. Full CI remains excluded by user instruction. Existing obsolete Data
unit fixtures still prevent complete unit-target qualification. The new private
usage fixture has no execution result from that target. No new speed gain is
claimed from quota removal.

## Verification and limits

- Journal collection passes the slowest-consumer, rejected-publication,
  exhaustive-consumption, dormant-generation, removal/recreation, exact retry,
  physical journal removal, historical-read, and restart checks. Six storage
  lifecycle and sixteen managed input cases pass. Actual notification completion
  and restart after collection also pass. Read the current worklist for commands
  and logs. The later saved-cut correction passes all six native input and
  thirteen native Query cases. Ordinary resume, partial spans, filtered offline
  traffic, log expiry, and fresh initial capture have public Query proof.
- [Native coverage checks](../../crates/araphor-data/tests/native_raw.rs)
  preserve six-report bounded reads, exact report references and bytes,
  retry stability, conflicting-content rejection, and multi-report batches.
  The old SQL commit-revision uniqueness rule is removed. One native batch
  can contain several reports; each report retains its own source and revision.
- [Coverage parity cases](../../crates/araphor-data/tests/native_raw/coverage.rs)
  check arrival after capture, exact receipt history through expiry and reopen,
  backup and restore, source and tenant scope, damaged unselected bodies,
  reference corruption, cancellation, and unchanged progress. Four fixture
  cases pass in 0.21 seconds. Three default-feature cases pass in 0.43 seconds.
  The five replaced SQL cases are removed. The historical-corruption case
  still requires a native port.
- The focused native lifecycle suite passes six cases. It covers raw recovery,
  backup and restore, Required byte and age bounds, rollback, restart, retirement
  before expiry, witness expiry, and maintenance after Required retirement.
- The four indexed notification cases pass. Lookup returns all five retained
  states before and after reopen. The two quota-only preparation cases are
  removed. Prepared memory, cancellation, and current-view checks remain.
- The expanded Graph domain suite passed 24 cases before the final admission
  changes. It includes retained traversal and ordinary projections without state.
- Fjall checkpoint checks pass three cases. LSM metadata checks pass two cases.
  These cover exact output admission, refusal, source readiness, encoding parity,
  and retained branches, history, CDC, and compaction.

The format 9 cutover release build passed. The unchanged incident passed in
3.03 seconds, with durable creation delays of 147.276 to 268.944 ms.
That earlier unpaired run does not prove either performance target. SQL-only fixture
ports, finite-history collection, and complete production qualification remain
open. Full CI and physical device failure after manifest replacement have not
been run for this replacement.
