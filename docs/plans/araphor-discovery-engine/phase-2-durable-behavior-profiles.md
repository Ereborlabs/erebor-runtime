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

**Not done.** No derivation loop, SQL database, reader, metadata protocol, or durable profile was added
in this planning change.
