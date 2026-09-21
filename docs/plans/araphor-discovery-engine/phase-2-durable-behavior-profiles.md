# Phase 2: Durable Evidence, Profiles, And Context

Add continuous bounded derivation, transactional aggregates, and immutable profiles
through the existing Control persistence and evidence owners.

## Intended end state

Configured derivation survives restart, preserves gaps and unresolved identities,
and produces replayable profiles and scoped context. Discovery cannot block primary evidence intake
or advance another consumer's retention state.

## Implementation flow

```text
Control starts configured discovery
  -> DiscoveryOwner validates scope, supported sources, and quotas
  -> ControlStore opens the bounded derivation checkpoint
  -> bounded reader supplies committed evidence and pinned context
  -> ControlStore commits a durable exported-page reference
  -> one selected-DB transaction deduplicates input, updates counts, and advances progress
  -> derivation seals checked canonical atoms and their input manifest
  -> ControlStore commits the snapshot head
  -> query index exposes only the committed snapshot and matching digest
  -> context builder joins versioned owner documents and rule/runbook references
  -> packet preserves conflicts, missing facts, provenance, and disclosure classes

Source gap, binding conflict, or limit occurs
  -> derivation records affected intervals and exact incomplete counts
  -> derivation seals Partial or stops with a typed failure
  -> previous complete snapshots remain unchanged
  -> no overflow becomes a directory or wildcard rule

Control restarts or configured derivation is disabled
  -> recovery validates referenced artifacts before resuming
  -> enabled derivation resumes separate export and aggregation cursors
  -> missing query state is rebuilt from retained authoritative artifacts
  -> orphan cleanup removes only unreferenced artifacts within the store
  -> discovery expires only its own exported bundle references
  -> shared evidence consumption state remains unchanged
```

## Scope and owners

`DiscoveryOwner` owns derivation checkpoints and profile state. `ControlStore` owns persistence,
including the one embedded database selected in Phase 1. SQL is not policy authority.
`EvidenceRetentionOwner` owns source-evidence disposal. Node preserves bounded
decision context through the existing observation and WAL owners. The graph
owner is not duplicated or assumed to exist.

## Required changes

### Prerequisites and delivery boundary

Require Discovery 1 Done. Follow the [combined order](README.md#combined-implementation-order).
Development can overlap Mithril 6.2 closure, using the existing intake and
policy owners with discovery disabled by default. This phase has no dependency
on Mithril 7, graph findings, or public agent tools. It supplies the bounded
reader and shared derived store that Mithril 7 must reuse. After this phase,
complete Mithril 6.2 and 6.3 gates, then implement Mithril 7 before Discovery 3.
An evidence-contract change during closure requires the affected compatibility
and replay checks again.

Implement these changes in order. Paths below are relative to the named crate.

1. **Bounded reads — Control `src/store.rs`, `src/evidence.rs`,
   `src/evidence_segment.rs`.** Add `ControlStore::begin_evidence_read` and
   `read_evidence_page`. The existing `accepted_evidence_records` reads all
   retained records; do not use it behind HTTP pagination. Freeze stream
   identity, CPU, start/end durable cursors, retained floor, and coverage
   revision. Return at most 256 records and 1 MiB per page. Copy coverage
   intervals and counters for that revision. Preserve each accepted-record ID.
   The current intake drops batch CPU ID before persistence. Add an immutable
   per-stream CPU binding to the store image before the first new segment is
   accepted. Do not rewrite the store image for each later batch. Reject a
   changed CPU for the same stream. An old stream without a retained CPU fact
   stays unresolved. Perform the checked schema migration in step 6 before
   this new metadata is written; reuse it when discovery heads are added.
2. **Retention — same owners.** Open at most four immutable segment handles
   under the store lock; decode outside it. Reclamation before open returns
   `RetainedRangeExpired` and exact missing bounds. Reclamation after open must
   not invalidate that page. Discovery never calls
   `EvidenceRetentionOwner::acknowledge`: the current watermark has no consumer
   ID. Copy retained input into the interval bundle; missing input makes it Partial.
3. **Decision context — Node `src/policy.rs`, `src/observation.rs`,
   `src/observation/model.rs`, `src/observation/wal.rs`; Control
   `src/evidence/model.rs` and `proto/erebor/mithril/control/v1/control.proto`.**
   Add optional versioned context after the existing protobuf fields. Preserve
   the ABI's process/entry/binding IDs, role, state, entry rule, exact object
   key/handle, composite atom, and original kernel sequence. CPU already travels
   in `EvidenceBatch`; the durable cursor is not the original kernel sequence.
4. **Context join — `NodePolicyGenerationOwner::discovery_context`.** Use its
   generation role/state maps and measured signed-selector bindings. Pass a
   bounded immutable lookup snapshot to observation; no per-event filesystem
   resolution or Control call. Cap context at 16 KiB/event and lookup data at
   16 MiB/Node. Missing, stale, or oversized context keeps the base event with
   an unresolved reason. Reuse and pin Control `WorkloadTargetFactV1` for image,
   controller, and container facts. No reverse path lookup from an opaque ID.
5. **Compatibility — existing WAL and intake.** Keep old frames and checksums
   unchanged. Old records remain readable with missing-context/position states.
   Upgrade Control before Node. Test old/new records, reused generation handles,
   and a kernel sequence different from the WAL cursor. No new BPF collector.
6. **Derivation and persistence — Control `src/discovery/`, `src/store.rs`.** Add
   `DiscoveryOwner::{advance,seal_interval,read_snapshot,run}`. Commit
   bounded heads and immutable segments under the existing owner. No public
   start/cancel/resume job API. Close intervals at the fixed record/byte bound
   or configured checkpoint cadence; retain coverage limits. Reserve quota
   before work; sync artifacts before committing references. Add
   `src/discovery/index.rs` and the selected pinned database dependency in the
   workspace and Control manifests. Implement the initial tables, exact
   input uniqueness, checked UPSERT, separate progress fields, and sealing
   protocol in [engine-design.md](engine-design.md#embedded-database-and-query-contract).
   Use one writer and two bounded readers; verify engine-specific durability,
   checkpoint settings, schema version, and filesystem support. Batch only
   durably exported pages within the measured bound. Rebuild SQL from
   retained artifacts without changing authoritative snapshot IDs. Test quota,
   corruption, index lag, and interrupted rebuild. Migrate Control schema 4
   to the next version with crash-safe replacement and a checked recovery copy;
   preserve policy/trust/evidence state. An old binary must reject the new
   schema. Reconcile the version if main changes before implementation.
7. **Runtime — Control `src/config.rs`, `src/main.rs`, `src/lib.rs`.** Add
   disabled-by-default configuration and construct discovery with the existing
   store handle. Recover checkpoints at startup. Supervise derivation errors inside
   discovery; they must not exit Control's top-level `tokio::select!`. Shutdown
   stops admission and checkpoints bounded work. Expose bounded queue, byte,
   lag, and partial-reason counters without path or tenant metric labels.
8. **Context — Control `src/discovery/context.rs` (new).** Add
   `DiscoveryOwner::import_context` and private context-view construction. Accept bounded,
   tenant-scoped versioned documents; retain origin, validity, trust, sensitivity,
   and approver. Select exact workload/method/revision context before optional
   keyword matches. Pin policy/rollout facts, source health, and reviewed history
   available at the cutoff. Return typed evidence handles, selection counts,
   conflicting facts, and omissions. Recheck access on each read. No arbitrary
   URL fetch, vector database, external connector, or unbounded context dump.
   The same manifest and selector version produce the same packet digest.

9. **Revision feed — discovery index and immutable manifests.** Project accepted
   observations and committed context/profile/assessment changes as typed
   `events` rows. Persist original commit-index/ordinal positions and event IDs.
   Expose only durable referenced data. Deduplicate retries; late records and
   coverage corrections append new revisions. Rebuild preserves positions or
   changes the projection epoch explicitly. Do not add a second authoritative
   event log or per-client subscription state. The same projection later indexes
   finding, notification, assessment, policy, and response revisions from their
   owners. Use a complete committed prefix; do not skip a delayed owner artifact.

## Acceptance and verification

- Pass `DE-IDENTITY`, `DE-GAP`, `DE-REPLAY`, `DE-STORE`, `DE-RETENTION`,
  `DE-AGGREGATE`, `DE-INDEX`, `DE-TENANT`, `DE-CONTEXT`, `DE-BOOT`, and `DE-LIMIT` from
  [verification](verification.md).
- Crash at every artifact/head commit boundary yields a valid prior or new
  revision, not a referenced partial artifact.
- A slow console reader does not hold a write lock or block policy work.
- Run evidence intake and policy rollout with the live discovery owner enabled
  and disabled. Record repeat-run latency and completion. Investigate a
  reproducible regression above 5%. This integration gate completes the store
  selection proof; the offline database comparison does not replace it.
- Disablement or query cancellation does not erase evidence or alter active policy.
- Test budget values at the limit and one over the limit.
- Pass `DE-PACKET`: a changed owner document makes a new packet, expired facts
  do not become current, and another tenant's evidence is never retrieved.
- Pass the durable-position and rebuild cases of `DE-FOLLOW` before query exposure.
- Run focused Control/e2e tests and final full Rust verification. Record resource
  measurements separately from correctness results.

Add tests with prefixes `discovery_read_`, `discovery_context_`,
`discovery_derivation_`, `discovery_index_`, and `discovery_migration_`. Include reclamation before/after
open, frozen coverage, old-schema recovery, disabled startup, quota N/N+1,
disk full, repeated disablement, and continued intake/rollout during failure.
Kill the process after page-reference commit, SQL commit, snapshot-head commit,
and before index visibility. Retries must not double-count. Rebuild and page
the same 50,000-atom snapshot with stable cursors; verify measured plans use the
selected engine's qualified layout. No model or SQL row may widen a permission.
Add `context-roundtrip` and `profile-restart` to the lightweight binary. Use
the existing `MtlsFixture` and production owner APIs. Commands after addition:

```sh
cargo test -p mithril-control discovery_ -- --nocapture
cargo test -p mithril-node discovery_context_ -- --nocapture
cargo run -p mithril-e2e --bin mithril_discovery_test -- \
  --case profile-restart --output-directory /tmp/araphor-discovery-restart
```

Record nonzero test counts and `result.json` with cursor, context, checkpoint,
and recovered artifact digests. These commands describe new tests, not passes.

## Exclusions and stop point

No learned policy publication, classifier, external policy adapter, or
incident-graph implementation. Stop after durable profiles and their limits
are proven. Phase 3 requires approval.

## Result

**Not done.** The bounded reader and checked store migration are implemented.
The signed-context lookup and durable artifact store are implemented. The SQL
backend has committed-export replay and transactional counts. The live owner
exports bounded input and exact retention gaps. Profile sealing and bounded
snapshot reads are implemented. Disabled-by-default runtime supervision and
stream checkpoints pass the workspace checks.
Context import, revision feed, and live context roundtrip remain
to be implemented and verified.

### Bounded reader and source metadata

Read [intake](../../../crates/mithril-control/src/evidence.rs),
[store migration and CPU binding](../../../crates/mithril-control/src/store.rs),
[bounded reader](../../../crates/mithril-control/src/store/evidence_read.rs),
then [segment handles](../../../crates/mithril-control/src/evidence_segment.rs).
Intake commits one immutable CPU binding before new segment acceptance. Later
batches keep the segment-only write path. The binding has a first cursor. An
old retained prefix has no CPU proof, including pending old records.

The reader freezes accepted bounds, CPU metadata, and one coverage revision.
A page has at most 256 records, 1 MiB of framed bytes, and four file handles.
Coverage metadata has its separate existing 3-MiB payload limit. The store lock
protects handle selection, not decode. Open handles survive reclamation.
Reclamation before open returns `RetainedRangeExpired` with exact missing
bounds. Reads do not change the shared consumption watermark.

Schema 4 migration checks the state checksum, preserves a synced
`state-v4.bin` recovery copy, and atomically replaces the current image with
schema 5. A conflicting recovery copy, corrupt state, or future schema fails
without replacement. The schema 4 reader rejects schema 5. This is not an
automatic downgrade procedure.

Tests cover frozen coverage and bounds, retry, byte and handle limits, unknown
CPU, cross-store handles, changed frame checksums, CPU changes, mixed-CPU commit
groups, reclamation before and after open, and interrupted migration. The
storage test checks that 130 batches write CPU metadata once, preserve the
existing storage bound, and reopen within its existing one-second limit.

Verification: `bash .github/scripts/verify-rust-ci.sh` passed after the final
Rust edit. The Control library passed 147 tests; the Node library passed 243.
The e2e library passed 98 tests and ignored 160 physical or manual cases. These
ignored cases are not physical passes. The local document check passed 210
links across 27 documents. This result covers the reader and migration only.

### Kernel context transport

Field 21 of [EvidenceRecord](../../../crates/mithril-control/proto/erebor/mithril/control/v1/control.proto)
is optional `EvidenceDecisionContext`. Its first version preserves the original
kernel sequence, process/entry/binding IDs, generation, role/state/entry-rule
IDs, exact object key and handle, and composite atom. The
[Node canonicalizer](../../../crates/mithril-node/src/observation/model.rs)
fills these fields from the existing ABI event. It does not resolve a path or
read the filesystem. No BPF layout or collector changes are required.

The [shared evidence model](../../../crates/mithril-control/src/evidence/model.rs)
checks the context version, 16-KiB size limit, identity lengths, base generation,
composite atom, and exact-object digest. The Node and Control use the same
exact-object digest method. Missing IDs remain absent. These coordinates do not
claim that a signed selector or current workload fact was found; that join is
the next implementation step.

The [WAL check](../../../crates/mithril-node/src/observation/wal.rs) writes old
and new records together, reopens the WAL, and checks unchanged bytes and frame
checksums. Kernel sequences 101 and 202 use durable cursors 1 and 2. A legacy
record without context keeps its prior protobuf encoding. The
[intake check](../../../crates/mithril-control/src/evidence.rs) rejects changed
context coordinates, retains duplicate input once, restarts Control, and reads
the same context through the bounded reader. Upgrade Control before Node.

Verification: the focused context commands passed one Control test and two
Node tests. After the final Rust edit, `bash .github/scripts/verify-rust-ci.sh`
passed. The Node library passed 245 tests. The e2e library passed 98 tests and
ignored 163 physical or manual cases. An earlier gate stopped because the host
disk was full; it is not a pass. Scoped Cargo cleanup removed only generated
Mithril build output before the successful repeat. The document check passed
215 local links across 27 documents. Signed-catalog lookup and the live
context-roundtrip case remain open.

### Signed decision catalogue

Read the [policy catalogue](../../../crates/mithril-node/src/policy/discovery.rs),
then its construction in
[NodePolicyGenerationOwner](../../../crates/mithril-node/src/policy.rs),
publication in [NodeChassis](../../../crates/mithril-node/src/node.rs), and use in
[EffectObservationStore](../../../crates/mithril-node/src/observation.rs).
The existing policy owner verifies the signed artifact and measures selector
bindings before it constructs the immutable lookup. Startup, activation,
runtime reconciliation, OCI preparation, and retirement publish its snapshot.
The existing generation allocator rejects a handle with changed semantics.

The lookup requires equal boot, generation, binding, role, state, entry rule,
effect, operation, exact object, and composite atom. It copies the profile
identity, signed policy digest, and exact static key into optional context.
Conflicting static keys remain ambiguous. Unmeasured objects have no match.
Observation takes one shared snapshot per batch. It makes no filesystem or
Control request to resolve an event. The catalogue is limited to 16 MiB of
accounted allocation; the complete context is limited to 16 KiB. A limit or
missing match keeps the base event with an explicit unavailable reason.

The [Control evidence model](../../../crates/mithril-control/src/evidence/model.rs)
checks the catalogue digest and its coordinates against the base event. The
digest is an integrity check, not a new signature or policy authority. The
live derivation must still join the referenced policy and workload facts from
Control. WAL replay uses recorded catalogue bytes, not the current lookup.
The catalogue test covers equal input, conflicting input, changed content,
reused numeric handles on another boot, WAL restart, and both size limits.

Verification: the focused catalogue check passed one test. After the final
Rust edit, `bash .github/scripts/verify-rust-ci.sh` passed. The Node library
passed 246 tests. The e2e library passed 98 tests and ignored 163 physical or
manual cases. The document check passed 220 local links across 27 documents.
These checks do not close the live context-roundtrip acceptance case.

### Durable artifacts and bounded heads

This result covers the artifact store added after `2a07bf84`. It does not
include the live derivation or SQL index.

[ControlStore::put_discovery_artifact](../../../crates/mithril-control/src/store/discovery.rs)
accepts a bounded tenant artifact and its existing dependencies.
  -> [DiscoveryFiles::write](../../../crates/mithril-control/src/store/discovery.rs) checks the schema, dependency order, and tenant.
  -> [DiscoveryFiles::write](../../../crates/mithril-control/src/store/discovery.rs) reserves quota, syncs the file, and syncs its directory.
  -> [ControlStore::commit_discovery_head](../../../crates/mithril-control/src/store/discovery.rs) checks the artifact and expected head revision.
  -> [ControlStore](../../../crates/mithril-control/src/store.rs) commits the bounded head with the existing state transaction.
  -> Not implemented: derivation applies the exported page to the SQL index.

[ControlStore::recover_discovery_artifacts](../../../crates/mithril-control/src/store/discovery.rs)
runs before artifact admission.
  -> [DiscoveryFiles::read](../../../crates/mithril-control/src/store/discovery.rs) checks every referenced artifact and dependency.
  -> [ControlStore::recover_discovery_artifacts](../../../crates/mithril-control/src/store/discovery.rs) removes only unreferenced files in the owned artifact directory.
  -> Not implemented: the live owner resumes derivation and rebuilds the SQL index.

`ControlStore` creates the shared file owner at open. Artifact I/O uses its
separate mutex. Head commits use the existing low-priority store lock. File
reads and checksum work do not hold that store lock. No kernel or ABI change
is required. No public network API is added.

Each encoded segment is at most 16 MiB. Retained files are limited to 2 GiB per
tenant and 8 GiB per process. Recovery and admission also enforce a 131,072-file
bound. Heads are limited to 1,024 per tenant, 4,096 per process, and 8 MiB of
encoded metadata. Limit failures preserve the prior committed head. A retry
of the same artifact does not create another head revision. A changed artifact
requires the expected prior revision.

Schema 6 accepts checked migrations from schema 4 or 5. The migration preserves
the matching `state-v4.bin` or `state-v5.bin` recovery copy. Schema 5 CPU metadata
is preserved. Older binaries reject schema 6. Artifact corruption stops
discovery recovery; it does not stop primary Control from opening its state.

The tests `discovery_store_commits_only_synced_artifacts_and_recovers_orphans`
and `discovery_store_enforces_segment_quota_and_head_boundaries` check retries,
stale revisions, failed state replacement, restart, dependency retention,
orphan removal, tenant mismatch, corruption, and count and byte boundaries.
`discovery_migration_preserves_schema_five_cpu_metadata` checks the schema 5
recovery copy and CPU binding. Process-kill and live integration checks remain
open.

Verification: the two focused artifact tests and three migration tests passed.
After the final Rust edit, `bash .github/scripts/verify-rust-ci.sh` passed.
The Node library passed 246 tests. The e2e library passed 98 tests and ignored
163 physical or manual cases. The document check passed 228 local links across
27 documents. This result proves the storage owner, not the live engine.

### Control policy and workload context

[ControlStore::discovery_context](../../../crates/mithril-control/src/store/discovery_context.rs)
accepts one retained discovery record.
  -> [ObservationEnvelopeV1::validate](../../../crates/mithril-control/src/evidence/model.rs) checks the base event and catalogue coordinates.
  -> [ControlStore::discovery_context](../../../crates/mithril-control/src/store/discovery_context.rs) checks the stream identity and original kernel sequence.
  -> [ControlStore::discovery_context](../../../crates/mithril-control/src/store/discovery_context.rs) selects retained policy and workload facts for the exact tenant, Node, boot, label epoch, binding, and profile version.
  -> [DiscoveryPinnedContextV1](../../../crates/mithril-control/src/store/discovery_context.rs) retains the workload fact, policy and snapshot references, and Control read revision.
  -> Not implemented: the live owner commits this context with an exported page.

The selected static key must exist in the retained compiled policy. Its workload
selector, protected scope, and execution set must match the workload fact.
Conflicting facts return `AmbiguousWorkloadFact`. Missing catalogue, process
lifetime, or workload facts return separate unresolved states. Malformed
coordinates return an error. No missing fact becomes a guessed image or path.
Historical context uses the exact retained source, not the latest policy.

This join reads the existing bounded Control metadata under its low-priority
lock. It performs no filesystem or network lookup. The returned context belongs
to the caller until the caller stores it in an immutable export. A workload
without a matching retained `WorkloadTargetFactV1` remains unresolved. This
implementation does not add host inventory or claim a live roundtrip pass.

`discovery_context_pins_exact_policy_and_workload_facts` checks a signed policy
and committed target through the public store APIs. It checks restart stability,
cross-tenant input, another Node or boot, a changed label epoch, binding, profile
version, static selector, missing process or catalogue, changed operation, and
changed kernel sequence. A conflicting retained fact cannot select a context.

Verification: the focused join test passed. After the final Rust edit,
`bash .github/scripts/verify-rust-ci.sh` passed. The Control library passed
152 tests; the Node library passed 246. The e2e library passed 98 tests and
ignored 163 physical or manual cases. The document check passed 233 local
links across 27 documents. This result covers the join added after `3426e5f3`.

### Transactional export index

This result covers the SQLite backend added after `d5e30762`. The backend is
not connected to Control startup. It does not close the live engine gates.

[DiscoveryExportPageV1::artifact](../../../crates/mithril-control/src/discovery/index.rs)
checks one bounded page with its raw records, pinned context, and coverage.
  -> [ControlStore::put_discovery_artifact](../../../crates/mithril-control/src/store/discovery.rs) stores the immutable page and its previous-page dependency.
  -> [ControlStore::commit_discovery_head](../../../crates/mithril-control/src/store/discovery.rs) commits the export reference.
  -> [DiscoveryIndex::apply_export](../../../crates/mithril-control/src/discovery/index.rs) requires that exact committed head.
  -> [DiscoveryIndex::apply_committed](../../../crates/mithril-control/src/discovery/index.rs) deduplicates the page, updates exact counts, and advances progress in one SQLite transaction.
  -> Not implemented: derivation seals canonical atom segments and commits a snapshot head.

[DiscoveryIndex::replay_interval](../../../crates/mithril-control/src/discovery/index.rs)
reads the dependency chain from its committed tip.
  -> [DiscoveryIndex::export](../../../crates/mithril-control/src/discovery/index.rs) checks artifact hashes, tenant scope, revisions, and increasing commit positions.
  -> [DiscoveryIndex::apply_committed](../../../crates/mithril-control/src/discovery/index.rs) restores counts and original commit-index/ordinal pairs without duplicate input.
  -> Not implemented: runtime recovery replaces a corrupt index and exposes committed profiles.

`DiscoveryIndex` owns one writer, two readers, and an exclusive file lease.
Dropping the owner closes its connections and releases the lease. Admission
accepts at most one writer and eight pending calls. Both occupied readers
cause a typed limit failure. Fixed parameterized queries have a one-second
execution deadline. No caller can submit SQL. Index I/O does not hold the
primary Control lock or advance evidence consumption.

The backend reuses the qualified `rusqlite = 0.40.2` dependency and bundled
SQLite 3.53.2. It verifies WAL mode, full synchronous writes, 4-KiB pages,
foreign keys, query-only readers, and cache settings. Cache targets total
48 MiB. SQLite bounds rows at 8 MiB and disables attached databases.
Admission accepts Linux ext-family and tmpfs filesystem types. The ext-family
type does not distinguish ext2, ext3, and ext4. Other types are rejected.
Release qualification must name the actual filesystem and mount settings.
New database and lease files use mode 0600. An existing database with group
or other-user permissions is rejected.

Native primary keys, foreign keys, and checks protect exact input identity,
integer counts, the one-million-record bound, the 50,000-atom bound, and the
256-MiB input charge. New atoms past the bound remain unresolved; no wildcard
is added. Byte charges use a bounded serialized representation, not a measured
heap allocation. Process-memory qualification remains open.

An export contains at most 256 records, 1 MiB of wire records, and a separate
3-MiB coverage report. The encoded page is at most 8 MiB. Unknown CPU input
stays unresolved. Each previous-head reference retains its original Control
commit index. Eight-byte big-endian SQL positions preserve the full unsigned
cursor range and sort order. SQL state ahead of the requested committed tip
is rejected.

The database, WAL, and shared-memory files reserve half of the 2-GiB index
budget for a future replacement. The WAL has a 64-MiB bound. Admission
reserves 32 MiB before a transaction and attempts a bounded checkpoint when
needed. Shared tenant artifact/index accounting and measured worst-case growth
remain live-integration requirements.

Four `discovery_index_` tests passed. They check whole-transaction rollback,
retry, cross-tenant reads, restart, rebuild from committed artifacts, stable
event positions, writer and reader admission, and an index ahead of Control.
They also check native counter limits, a SQLite disk-full failure, a future
schema, and a corrupt header. The capacity test sets counters at their limits;
it does not claim a one-million-record workload measurement. Corrupt discovery
state does not stop the primary Control store from opening.

After the final Rust edit, `bash .github/scripts/verify-rust-ci.sh` passed.
The Control library passed 156 tests; the Node library passed 246. The e2e
library passed 98 tests and ignored 163 physical or manual cases. The document
check passed 241 local links across 27 documents. Profile paging, process-kill
tests, context import, runtime supervision, revision-feed visibility, and live
intake/rollout measurements remain open. **Not done.**

### Live export and bounded atom reads

This result covers the owner changes after `edb1f7b6`. Control startup does not
enable this owner yet. Runtime configuration and profile sealing remain open.

[DiscoveryOwner::open](../../../crates/mithril-control/src/discovery/live.rs)
obtains the index lease before artifact recovery.
  -> [DiscoveryOwner::advance](../../../crates/mithril-control/src/discovery/live.rs) derives the interval key from the exact stream lifetime and first cursor.
  -> [DiscoveryIndex](../../../crates/mithril-control/src/discovery/index.rs) resumes the committed export before reading more source input.
  -> [ControlStore::begin_evidence_read](../../../crates/mithril-control/src/store/evidence_read.rs) freezes the next retained range and coverage.
  -> [ControlStore::discovery_context](../../../crates/mithril-control/src/store/discovery_context.rs) pins context for each retained record with a known CPU.
  -> [DiscoveryOwner::advance](../../../crates/mithril-control/src/discovery/live.rs) commits the bounded export before SQL apply.
  -> [DiscoveryIndex::atoms](../../../crates/mithril-control/src/discovery/index.rs) reads an exact committed revision with stable digest cursors.
  -> Not implemented: the owner seals atom segments and publishes a snapshot head.

One live interval operation runs at a time. Admission fails when another
operation holds the owner lock. That lock is separate from the primary Control
lock. Each advance reads at most one bounded evidence page. It reserves the
remaining record and input-byte budget before the export head commit. A smaller
page leaves the next source cursor unchanged for the next call. An interval
that cannot accept another record returns `INTERVAL_SEAL_REQUIRED`.

A missing CPU stays unresolved. A pinned context is limited to 32 KiB of
serialized data. The context join checks the workload bound before cloning the
fact. An oversized pin keeps the base event with `CONTEXT_LIMIT`.
`RetainedRangeExpired` becomes an immutable gap page with its exact first and
last cursor. A gap page advances the cursor but adds no accepted record or atom.
The next page starts immediately after that gap. Export and replay do not
acknowledge the shared evidence watermark.

An atom page has at most 200 rows and 1 MiB. It uses a primary-key range read
and up to eight ordered evidence references per atom. The shared atom
constructor preserves the offline physical-result rules. An old head or a head
that SQL has not applied returns an error. Readers do not expose a mixed
revision or retain a transaction after the method returns.

`discovery_derivation_exports_retained_input_and_exact_gaps_then_rebuilds`
passed through the public intake, retention, and discovery APIs. It checks an
expired prefix, retained input, unresolved context, unchanged retention state,
owner admission, and rebuild after source reclamation.
`discovery_index_pages_fifty_thousand_atoms_and_rebuilds_the_same_cursors`
passed with 50,002 input records, 50,000 exact atoms, and one unresolved new
atom past the limit. A repeated existing atom still increments its count.
Both complete page sequences have equal digests after index rebuild. The test
checks the primary-key range plan and each result byte bound. Its focused run
took 299.19 seconds in the debug test build; this is not a production latency
or memory qualification result.

After the final Rust edit, `bash .github/scripts/verify-rust-ci.sh` passed.
The Control library passed 158 tests, including the large paging and rebuild
case; the Node library passed 246. The e2e library passed 98 tests and ignored
163 physical or manual cases. The document check passed 249 local links across
27 documents. An earlier full run stopped at the unchanged Runtime CLI test
`start_rejects_invalid_runtime_config`. That test passed in the same binary
on rerun and in the repeated full gate. The cause was not established; no
Runtime CLI code changed.

The 50,000-atom test proves working-index paging, not a sealed snapshot or a
live performance gate. Context roundtrip, sealing, runtime supervision, process-kill recovery,
context import, revision-feed visibility, and resource measurements remain
open. **Not done.**

### Immutable profiles and snapshot visibility

This result covers the snapshot implementation after `9c83eaaa`. The intended
end state is a checked, immutable profile that remains readable after restart
or loss of its SQL projection. This result does not enable runtime derivation.

[DiscoveryOwner::seal_interval](../../../crates/mithril-control/src/discovery/live.rs)
requires the committed export and matching aggregate progress.
  -> [DiscoveryIndex::export](../../../crates/mithril-control/src/discovery/index.rs) checks each retained page in the source chain.
  -> [DiscoveryOwner::seal_interval](../../../crates/mithril-control/src/discovery/live.rs) checks source bounds, coverage, accepted counts, unresolved counts, and exact atom counts.
  -> [DiscoveryLive::write_profile_artifact](../../../crates/mithril-control/src/discovery/live.rs) reserves encoded bytes before it writes each immutable segment and manifest.
  -> [ControlStore::commit_discovery_head](../../../crates/mithril-control/src/store/discovery.rs) commits the snapshot reference after the files are durable.
  -> [DiscoveryIndex::publish_snapshot](../../../crates/mithril-control/src/discovery/index.rs) exposes only the matching committed snapshot and artifact digest.
  -> [DiscoveryOwner::read_snapshot](../../../crates/mithril-control/src/discovery/live.rs) reads bounded atom pages from the checked immutable segments.

[DiscoveryOwner::seal_interval](../../../crates/mithril-control/src/discovery/live.rs)
receives the same export after a retry or projection loss.
  -> [DiscoveryOwner::profile](../../../crates/mithril-control/src/discovery/live.rs) checks the existing snapshot manifest and dependencies.
  -> [DiscoveryIndex::publish_snapshot](../../../crates/mithril-control/src/discovery/index.rs) repairs visibility without changing the snapshot head.
  -> Not implemented: runtime recovery starts this repair without a caller.

The existing live owner creates and closes these operations. The artifact store
owns all files. SQL stores only the committed visibility tuple for a sealed
snapshot. Snapshot reads do not depend on mutable aggregate rows. The index
schema changes from 1 to 2 in a native transaction; existing input and progress
rows remain unchanged. No policy, Node, kernel, or ABI owner changes.

Each snapshot has a canonical digest, transformation version, source export,
exact cursor bounds, accepted and included counts, unresolved and missing
counts, and ordered segment references. Complete means that the retained input
passed these checks. Its proof kind remains `RecordedInput`, not physical
qualification or proof that the workload requires this behavior. Missing source
coverage, incomplete observation coverage, retention gaps, unresolved input,
and empty input produce Partial with explicit reasons. A later snapshot cannot
change a prior snapshot.

The combined encoded manifest and atom segments are limited to 128 MiB. The
reservation measures the actual MessagePack wrapper, not estimated overhead.
A segment payload is at most 1 MiB. Each read returns at most 200 atoms and
1 MiB, including its metadata. Segment bounds skip prior pages before file I/O.
Counts and stable digest cursors survive projection loss. A missing visibility
tuple returns `SNAPSHOT_INDEX_UNAVAILABLE` until repair completes. Recovery
does not acknowledge the shared evidence-consumption watermark.

Focused checks pass for encoded-byte admission at the limit and one byte over,
schema upgrade, Complete and Partial snapshots, unchanged prior revisions,
tenant mismatch, source reclamation, and projection repair. These checks use
recorded fixtures; they do not prove the live signed-context roundtrip.
The 50,000-atom snapshot check passed with equal page digests after restart and
projection loss. Its focused debug run took 744.70 seconds. This is not a
production latency measurement. A workspace run passed for snapshot source
`68faeef8`: Control passed 160 tests, Node passed 246, and e2e passed 98 with
163 physical or manual cases ignored. That run precedes the runtime changes.
The document check passed 259 local links across 27 documents.
Process-kill checks, full runtime recovery, context import, revision feed, and live
resource measurements remain open. **Not done.**

### Runtime supervision and stream checkpoints

The intended end state is continuous derivation that does not stop primary
Control on a discovery failure. This result adds runtime wiring after
`68faeef8`. Corrupt-index replacement remains open.

[ControlConfig](../../../crates/mithril-control/src/config.rs) selects optional discovery configuration.
  -> [ControlRuntimeParts](../../../crates/mithril-control/src/config.rs) passes the existing store handle without opening discovery files.
  -> [Control main](../../../crates/mithril-control/src/main.rs) starts a separate supervised task only when discovery is configured.
  -> [DiscoveryOwner::run](../../../crates/mithril-control/src/discovery/runtime.rs) opens the owner and runs bounded work outside async worker threads.
  -> [ControlStore::discovery_sources](../../../crates/mithril-control/src/store/evidence_read.rs) reads at most 32 source identities by stable key.
  -> [DerivationRuntime](../../../crates/mithril-control/src/discovery/runtime.rs) admits at most four active intervals and 32 pending sources.
  -> [DiscoveryOwner::advance](../../../crates/mithril-control/src/discovery/live.rs) commits one bounded page before aggregation.
  -> [DerivationRuntime](../../../crates/mithril-control/src/discovery/runtime.rs) seals at the record or byte limit, or the configured cadence.
  -> [ControlStore::commit_discovery_head](../../../crates/mithril-control/src/store/discovery.rs) commits the next interval cursor with the completed snapshot reference.

The default is disabled. Set `"discovery": {"checkpoint_seconds": 60}` to
enable derivation. Omission or `null` disables the task without deleting stored
data. The cadence must be from 1 through 3,600 seconds. No public job API is
added. Each tenant has at most two active intervals and eight pending sources.
Excess sources remain in evidence storage for a later bounded scan. Source
reclamation remains an explicit gap, not an acknowledgement from discovery.

The runtime owns its bounded queues until shutdown. The existing store owns
all checkpoints. Restart resumes the committed export. A snapshot committed
before its stream checkpoint is completed before new input is admitted to the
next interval. A missing snapshot projection is repaired from that snapshot.
The next interval starts at the prior exact stopping cursor plus one. A changed
export after a failed SQL apply is read from Control before another seal attempt.

Startup and task failures remain inside discovery. Derivation failures retry
after five seconds. They cannot select a primary Control exit branch. Shutdown
stops admission, waits for the current bounded operation, then closes the owner.
An unfinished interval retains its exported input and aggregation checkpoint.
Structured logs expose active and pending counts, accounted queue bytes, input
bytes, source lag, failures, and bounded partial-reason counters. They do not
use path or tenant metric labels. These byte counters are not measured RSS.

Six focused `discovery_derivation_` tests passed before the final logging edit.
They cover configuration defaults, cadence boundaries, source pagination,
process and tenant admission limits, restart between snapshot and checkpoint,
projection loss, unchanged prior snapshots, disabled startup, and continued
intake during discovery startup failure. After the final runtime edit,
`bash .github/scripts/verify-rust-ci.sh` passed for source `8aeb2d4b`.
Control passed 164 tests; Node passed 246. The e2e library passed 98 tests and
ignored 163 physical or manual cases. The document check passed 268 local
links across 27 documents. This run does not cover the later coverage changes.
Process-kill checks, index replacement, context import, revision feed, and live
intake/rollout measurements remain open. **Not done.**

### Late coverage revisions

[EvidenceIntakeOwner::receive_coverage](../../../crates/mithril-control/src/evidence.rs)
accepts a later source report through the existing owner.
  -> [DerivationRuntime::admit](../../../crates/mithril-control/src/discovery/runtime.rs) checks coverage when it reopens the last stream checkpoint.
  -> [DiscoveryOwner::refresh_coverage](../../../crates/mithril-control/src/discovery/live.rs) commits a coverage-only page at the unchanged source cursor.
  -> [DiscoveryIndex](../../../crates/mithril-control/src/discovery/index.rs) applies that page without an input row or count increment.
  -> [DiscoveryOwner::seal_interval](../../../crates/mithril-control/src/discovery/live.rs) creates a new snapshot with its exact predecessor reference.
  -> [DerivationRuntime::commit_checkpoint](../../../crates/mithril-control/src/discovery/runtime.rs) records that revision without changing the next observation cursor.

Transformation version 2 checks the newest retained report for each matching
coverage interval. Other intervals keep their recorded source report. Closed
intervals require closing counters. Complete coverage requires matching source
epoch, CPU, sequence bounds, balanced counter snapshots, and no loss,
suppression, unresolved input, classifier miss, or counter regression. Missing
counter proof remains unknown. A later Healthy report cannot remove a recorded
gap. Each correction keeps its prior snapshot through an artifact dependency.
Version 1 snapshots remain readable with their original digest and proof class.

A correction does not admit new observations into a sealed interval. If an
earlier correction was committed but not sealed, recovery finishes that
revision before it accepts another correction. Retries preserve counts and
snapshot identities. The existing input-byte and artifact quotas also apply
to corrections. There is no separate event log or coverage consumer.

Seven derivation checks and the snapshot revision check passed. Clippy passed
with warnings denied. The checks cover unchanged counts, closed coverage,
counter gaps, incomplete counter proof, two corrections across restart,
unchanged prior snapshots, and retry without a new checkpoint. The full
workspace run is in progress. These changes do not complete context import, the revision feed, index replacement,
process-kill checks, or live resource qualification. **Not done.**

### Lightweight profile restart

This result adds the restart case after `dd01bb3b`. Its intended end state is
an unchanged profile after source reclamation and loss of the SQL projection.

[DiscoveryQualificationRunner::profile_restart](../../../crates/mithril-e2e/src/discovery/roundtrip.rs) starts the existing local mutual-TLS fixture.
  -> [EffectObservationStore](../../../crates/mithril-node/src/observation.rs) writes one synthetic kernel record to the Node WAL.
  -> [NodeControlConnection](../../../crates/mithril-node/src/control.rs) sends the batch to the production Control intake.
  -> [ControlStore::read_evidence_page](../../../crates/mithril-control/src/store/evidence_read.rs) returns the unchanged record at durable cursor 1.
  -> [DiscoveryOwner](../../../crates/mithril-control/src/discovery/live.rs) exports and seals a Partial profile with one unresolved record.
  -> [EvidenceRetentionOwner](../../../crates/mithril-control/src/evidence.rs) reclaims the source only after the test supplies a separate consumption acknowledgement.
  -> [DiscoveryQualificationRunner](../../../crates/mithril-e2e/src/discovery/roundtrip.rs) closes the owners and removes only the temporary SQLite projection.
  -> [DiscoveryOwner::seal_interval](../../../crates/mithril-control/src/discovery/live.rs) repairs visibility with the same snapshot head and content digest.

The runner owns temporary state and closes the local server before reopening
Control. It obtains the per-CPU source identity from the Node batch. The raw
kernel sequence remains 101; it is not the durable cursor. Discovery leaves
the shared consumption watermark unchanged. The separate test acknowledgement
advances the retained floor to 2. An existing output directory is rejected
without changing its proof files.

The focused test `discovery_derivation_profile_restart_uses_wal_and_mtls`
passed. The `mithril_discovery_test --case profile-restart` command also passed
and wrote `result.json`, `export.json`, and `snapshot.json` under
`/tmp/araphor-restart-proof.Nouz5k/proof`. The result records cursor, context,
checkpoint, snapshot, and recovered digests. Formatting passed. The final
workspace procedure is running for this source state.

This case uses production WAL, transport, intake, and discovery owners. Its
kernel input is synthetic. It does not load BPF, execute a physical action,
or resolve signed catalogue context. The signed-context roundtrip, process-kill
cases, context import, revision feed, and resource qualification remain open.
**Not done.**
