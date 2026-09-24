# Phase 7.4: Deterministic Profiles And Context

Implement continuous discovery over the shared retained data.

## Intended end state

DiscoveryOwner produces exact behavior profiles, lifecycle coverage, baseline
differences and scoped context. Counts survive replay and restart. Raw retention
does not erase retained profiles or their qualified witnesses.
Entry for derivation: 7.2. Query/view and end-to-end closure also require 7.3.
Status: **Not done** for this data contract.

## Implementation flow

```text
DiscoveryOwner receives a committed-data notification
  -> owner freezes a bounded source/context/coverage manifest
  -> exact identity checks assign each record to included, unresolved or excluded
  -> owner derives checked atoms and stable evidence samples
  -> one AnalysisStore transaction commits working counts and processor progress
  -> sealing commits canonical profile, context references and retained witnesses
  -> QueryOwner exposes the new revision when query is enabled

New context, source loss or workload revision arrives
  -> owner creates a new profile/context revision
  -> comparison separates behavior, outcome, identity and coverage changes
  -> no old review or baseline changes silently

Derivation fails or is disabled
  -> progress does not advance past uncommitted work
  -> storage, query, traces and installed enforcement continue
  -> optional discovery progress does not pin raw data
  -> resumption records any expired range before starting an incomplete interval
```

## Changes in implementation order

1. Reuse Control `src/discovery/recorded.rs`, `live.rs`, `runtime.rs`,
   `model.rs` and `context.rs`. Pass AnalysisStore into DiscoveryOwner.
   Keep storage startup outside `DiscoveryOwner::run`. No second database,
   copied raw-event archive or public derivation-job API is required.
   Register discovery as optional. Required graph packages read accepted data
   directly and must not depend on a live profile or context-enrichment task.
2. Preserve Node decision context through `policy.rs`,
   `observation/model.rs`, `observation/wal.rs`, Control `evidence/model.rs`
   and the existing protobuf fields. Bind roles, state, entry, selector,
   object and kernel sequence to the exact policy generation and lifetime.
   Use a bounded immutable Node lookup snapshot, not per-event filesystem
   resolution. Old records stay readable with explicit missing-context fields.
   Upgrade Control before Node. Keep Node WAL compatibility tests.
3. Apply the exact algorithm in engine-design.md. Deduplicate by accepted
   identity, not similarity. Keep source lifetime, cohort, role/state, operation,
   exact binding, source decision, physical result and proof kind in atom keys.
   Consume only the declared observation kinds. Derived profile/finding/trace
   revision notices are not new sensor actions. Use checked counts and stable
   record-ID sample selection. Included plus
   unresolved plus excluded equals unique input; duplicates are separate.
4. Commit atom changes and progress in one transaction. Freeze per-source end
   positions and coverage revisions. Seal at the record/byte bound or configured
   interval; late events/context create new revisions. Canonical digests do not
   depend on arrival, database row order or worker scheduling.
5. Build exact display groups with member references. Implement ordered set
   differences against an explicitly reviewed baseline. Keep image/config
   changes, new resources, changed results and lost coverage separate. Repeated
   activity is not a requirement; frequency cannot suppress a forbidden group.
6. Implement the lifecycle matrix: startup, steady work, probes, restart,
   rollout, shutdown, recovery, scheduled work and approved maintenance.
   Values are Recorded, Declared, Missing, NotApplicable with reason, or
   Unsupported. Time spent learning cannot fill a missing case.
7. Implement deterministic context selection in `context.rs`: exact subject,
   method/revision, valid overlap, stable document ID. Include source health,
   policy provenance, rule guide and reviewed history available at the cutoff.
   Preserve conflicts, omissions, sensitivity and source trust. Imported
   documents are bounded operator data, not executable instructions.
8. Retain exact context/witness dependencies with sealed outputs under the
   shared quota. Full replay requires the complete retained input manifest;
   a sample supports only the statements it actually proves. Expired raw input
   yields ReplayUnavailable for full reconstruction, not invented context.
9. Register `behaviors` and `context` views with QueryOwner after 7.3.
   Pin exact source-policy facts through their owner exports. Unavailable
   policy facts remain Unknown and cannot be repaired from today's cluster.

## Unit tests and end-to-end proof

Add `discovery_derivation_`, `discovery_context_` and
`discovery_comparison_` unit tests. Check repeated/reordered input, conflicting
keys, generation-handle reuse, denied/failed/unknown results, missing bindings,
integer overflow, source gaps, poisoned baseline, future review leakage and
quota N/N+1. Equal manifests must yield equal canonical digests.

Extend existing `context-roundtrip` and `profile-restart` cases in
`crates/mithril-e2e/src/discovery/roundtrip.rs` and `storage.rs`.
Use Node observation/WAL, actual mTLS intake, AnalysisStore and DiscoveryOwner.
Crash before/after count-progress and sealed-output commits. Require no double
count and exact context. Disable discovery past the raw retention period and prove intake/query/trace
still work. Resume at the retained floor with an explicit gap and incomplete
profile, not synthetic counts or an empty healthy interval.
Expire unpinned raw input; retained profile/context remains readable while
full replay correctly reports unavailable input.

```sh
cargo test -p mithril-control
cargo test -p mithril-node
cargo run -p mithril-e2e --bin mithril_discovery_test -- --case context-roundtrip --output-directory /tmp/araphor-context
cargo run -p mithril-e2e --bin mithril_discovery_test -- --case profile-restart --output-directory /tmp/araphor-profiles
bash .github/scripts/verify-rust-ci.sh
```

## Completion gate

Pass DE-IDENTITY, DE-CONTEXT, DE-AGGREGATE, DE-GAP, DE-NOISE, DE-POISON,
DE-PACKET, DE-REPLAY and DE-RETENTION. Measure 50,000-atom read and comparison
cost while intake runs. No classifier, causal graph, proposal publication or
model dependency is required for this phase.
