# Phase 7.4: Deterministic Profiles And Context

Implement continuous discovery over the shared retained data.

## Intended end state

DiscoveryOwner produces exact behavior profiles, lifecycle coverage, baseline
differences and scoped context. Counts survive replay and restart. Raw retention
does not erase retained profiles or their qualified witnesses.
Entry for derivation: 7.2. Query/view and end-to-end closure also require 7.3.
Status: **Done** for implementation and scoped correctness.
Implementation is committed at `0119e395`, with final corrections at
`11b3a725`. The final workspace procedure passed. Use the existing
AnalysisStore result, progress, context, and witness transaction. Do not add
a separate discovery database or a raw export archive.

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

1. Move the portable model, recorded derivation and context selection from
   Control `src/discovery/` into `crates/araphor-data/src/discovery/`.
   Reuse the shared record decoder from 7.3, not a Control-only decoder.
   Derivation can start after 7.2; decoder integration and closure need 7.3.
   Implement the live worker with bounded contiguous AnalysisStore source reads
   and one metadata transaction for result,
   references, and progress. Read raw evidence directly; no export artifact
   or staging table may contain another full copy before derivation.
   Control exports qualified policy facts; exact native preview stays in
   Control. Prove parity with the recorded derivation tests before live use.
   Queries can expose durable pending ranges before the contiguous ACK moves.
   Ordered discovery progress still waits for missing input or qualified loss;
   early query visibility does not authorize a processor to skip that input.
   Do not make `araphor-data` depend on Control.
   Keep storage startup outside `DiscoveryOwner::run`. No second database,
   copied raw-event archive or public derivation-job API is required.
   Register discovery as optional. Required graph packages read accepted data
   directly and must not depend on a live profile or context-enrichment task.
2. Preserve Node decision context through `policy.rs`,
   `observation/model.rs`, `observation/wal.rs`, Control `evidence/model.rs`
   and the existing protobuf fields. Bind roles, state, entry, selector,
   object and kernel sequence to the exact policy generation and lifetime.
   Use a bounded immutable Node lookup snapshot, not per-event filesystem
   resolution. Missing context in a supported record stays unresolved.
   Use matching Node and Control formats. Test the current Node WAL round trip
   and reject unsupported formats; do not add old-format readers.
3. Apply the exact algorithm in engine-design.md. Deduplicate by accepted
   identity, not similarity. Keep source lifetime, cohort, role/state, operation,
   exact binding, source decision, physical result and proof kind in atom keys.
   Consume only the declared observation kinds. Derived profile/finding/trace
   revision notices are not new sensor actions. Use checked counts and stable
   record-ID sample selection. Included plus
   unresolved plus excluded equals unique input; duplicates are separate.
4. Commit atom changes and progress in one transaction. Freeze per-source end
   positions and coverage revisions. Seal at the record/byte bound or configured
   interval; late events/context create new revisions. Canonical values do not
   depend on arrival, database row order or worker scheduling. Compare exact
   retained values. Do not calculate discovery hashes or bookkeeping digests.
   Use a small typed header in `analysis_results` for exact source, method,
   interval, profile revision, context notice, coverage notice and first cursor.
   Commit that header with the profile body. Do not enable DuckDB JSON extensions
   to select profiles. Check result-body and witness bounds before admission.
   Select the latest result per interval; keep older sealed results readable.
   Process at most 16 stale interval notices per source pass. If full input is
   unavailable, acknowledge only the scheduling notices. Do not change the
   frozen body, references, progress or query revision. Unavailable intervals
   must not prevent retained intervals from receiving late exact context.
   Late context admission preserves every frozen record and qualified binding.
   Admit only new bindings that fit the input, atom, result, reference, and
   witness bounds. Keep the other records unresolved. Check those bounds before
   storing new facts. A bound must not stop the optional worker. Source-health
   context records the committed processor cursor before the result transaction,
   not the candidate cursor.
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
   shared quota. Charge the full distinct witness segments under 7.2 rules.
   No private witness archive or discovery-specific compactor is permitted.
   Full replay requires the complete retained input manifest;
   a sample supports only the statements it actually proves. Expired raw input
   yields ReplayUnavailable for full reconstruction, not invented context.
9. Register `behaviors` and `context` views with QueryOwner after 7.3.
   Pin exact source-policy facts through their owner exports. Unavailable
   policy facts remain Unknown and cannot be repaired from today's cluster.
   Retained profiles and context remain readable when discovery is disabled.
   Catalogue readiness reports live owner presence, not worker health. It must
   not block a read of retained results.

## Unit tests and end-to-end proof

Add `discovery_derivation_`, `discovery_context_` and
`discovery_comparison_` unit tests. Check repeated/reordered input, conflicting
keys, generation-handle reuse, denied/failed/unknown results, missing bindings,
integer overflow, source gaps, poisoned baseline, future review leakage and
quota N/N+1. Equal manifests must yield equal canonical values.

Extend the existing `context-roundtrip` and `evidence-restart` storage cases
in `crates/mithril-e2e/src/discovery/roundtrip.rs`. Add `profile-restart`
for the live DiscoveryOwner. Use `storage.rs` for artifact parity checks.
Use Node observation/WAL, actual mTLS intake, AnalysisStore and DiscoveryOwner.
Crash before/after count-progress and sealed-output commits. Require no double
count and exact context. Disable discovery past the raw retention period and prove intake/query/trace
still work. Resume at the retained floor with an explicit gap and incomplete
profile, not synthetic counts or an empty healthy interval.
Check that profiles and progress survive restart without a raw export archive.
Expire unpinned segments; retained profile/context remains readable while
full replay correctly reports unavailable input.

```sh
cargo test -p mithril-control
cargo test -p araphor-data
cargo test -p mithril-node
cargo run -p mithril-e2e --bin mithril_discovery_test -- --case context-roundtrip --output-directory /tmp/araphor-context
cargo run -p mithril-e2e --bin mithril_discovery_test -- --case profile-restart --output-directory /tmp/araphor-profiles
bash .github/scripts/verify-rust-ci.sh
```

## Completion gate

Pass DE-IDENTITY, DE-CONTEXT, DE-AGGREGATE, DE-GAP, DE-NOISE, DE-POISON,
DE-PACKET, DE-REPLAY and DE-RETENTION. A 50,000-atom read and comparison
measurement while intake runs requires separate user approval. Do not add or
run a performance test under the implementation approval. Record performance
as unqualified until an approved measurement passes. No classifier, causal
graph, proposal publication or model dependency is required for this phase.

## Implementation result

Profile implementation: `0119e395`. The approved lazy query stream and its
qualification changes: `7b828c0a`. Final code corrections: `11b3a725`.
Result: **Done** for implementation and scoped correctness. The final workspace
procedure passed after the final code edit.

DiscoveryOwner now lives in `araphor-data`. It reads bounded, committed segment
pages from AnalysisStore. Control supplies exact retained policy facts through
DiscoveryContextProvider. Control retains authentication, native preview,
policy and physical-effect authority. Production Control has no discovery
SQLite dependency, copied raw archive or archive-head owner.

The shared database schema is 15. A fresh store is required. The result table
holds a typed discovery header; the processor row holds its current result ID.
No second result directory or JSON extension is required. Working result,
references and progress commit together. Sealed results are immutable. Late
qualified context creates a new revision of the same interval. Frozen replay
does not call the current context provider.

The implementation uses checked counts, exact atom keys, all nine lifecycle
cases, reviewed baseline differences and stable evidence samples. A missing
binding remains unresolved. Complete source coverage requires conserved
opening and closing counters and the declared sequence range. Missing counters
remain Unknown. Repetition does not change a baseline or grant authority.

Optional discovery progress does not protect raw data. Disabled or delayed
discovery permits intake, SQL, trace output and native policy operations.
Resume after expiry records the missing range and an incomplete interval.
Retained profiles remain readable. Full replay returns unavailable input when
the complete raw range has expired.

### Correctness proof

Focused checks passed before the final workspace procedure:

| Scope | Passed | Failed | Limits |
| --- | ---: | ---: | --- |
| Data `discovery_` | 37 | 0 | Includes six actual child-process crash boundaries for working and sealed result commits. |
| Control `discovery_`, `control_context_`, startup isolation | 12 | 0 | Eight discovery, three context and one startup test. |
| Node `discovery_` | 4 | 0 | Current catalogue/WAL format; no old-format import. |
| E2E discovery, retained context and CLI arguments | 15 | 0 | Nine discovery, one evidence-restart and five argument tests; four discovery tests remain ignored. |
| Data `query_` | 131 | 0 | Includes retained profile/context views and lazy stream lifecycle. |
| Data cleanup regression and `query_follow_wait_` | 6 | 0 | The new regression fails before the fixture correction and passes after it. Five admission/cancellation cases also pass. |
| Control `observability_grpc_` | 14 | 0 | Includes slow demand, quiet pending reads and independent trace execution. |
| E2E `query_follow_contract` | 1 | 0 | Calls the eight-case production-owner qualification. |

The deterministic proof maps to these gate requirements:

| Gate | Source proof |
| --- | --- |
| DE-IDENTITY, DE-CONTEXT | Exact lifetime, generation, object, decision and outcome keys; Node WAL and mTLS round trip; missing and unsupported context. |
| DE-AGGREGATE | Reordered/repeated input, conflicting identity, page overlap, checked overflow and exact disposition accounting. |
| DE-GAP | Qualified counter checks, Unknown coverage, expired optional progress and explicit incomplete resume. |
| DE-NOISE, DE-POISON | Exact display groups and immutable reviewed baselines. Repeated forbidden activity remains visible. Frequency supplies no authority. |
| DE-PACKET | Cutoff, exact subject/revision, conflicts, omissions, sensitivity, operator-text quotas and retained history. |
| DE-REPLAY | Result/progress crash recovery, frozen facts, replay after restart and explicit missing-input failure. |
| DE-RETENTION | Witness/reference transactions, retained counts after raw expiry, readable profiles without a live worker and independent intake/query/trace/policy. |

The six standalone correctness commands passed for `context-roundtrip`,
`profile-restart`, `owner-isolation`, `evidence-restart`, `offline-exact` and
`storage-contract`. Receipts are in
`/tmp/erebor-discovery-proof.pX3mLR/<case>/result.json`.
The final-source follow and profile commands also passed at `11b3a725`.
The first command builds the executable for the second command:

```sh
cargo run --offline -p mithril-e2e --all-features --bin mithril_discovery_test -- --case query-follow --output-directory /tmp/araphor-profile-follow.tPl3zk/query-follow-final
target/debug/mithril_discovery_test --case profile-restart --output-directory /tmp/araphor-profile-follow.tPl3zk/profile-restart-final
```

The follow receipt contains eight PASS cases. The profile receipt records
`deterministic_profiles_qualified: true`, `physical_profiles_qualified: false`,
durable cursor 1 and original kernel sequence 101. Temporary stores use tmpfs.
These synthetic-input checks do not qualify disk durability or physical
prevention. Earlier storage results retain their own source/platform limits.

The cleanup test waits for both expired input references and a full evaluation
reservation. Native work can release its input before it releases its lease.
The correction changes only the test completion condition. Limits, timeouts
and production cancellation remain unchanged. Read `query-cleanup-before.log`,
`query-cleanup-after.log` and `query-follow-wait-final.log` in
`/tmp/araphor-profile-follow.tPl3zk/`.

All commands use `TMPDIR=/dev/shm`, `CXXFLAGS='-O2 -g0'`,
`CARGO_BUILD_JOBS=2`, `CARGO_INCREMENTAL=0`, `CARGO_NET_OFFLINE=true` and
`RUST_TEST_THREADS=1`.

Final procedure: `bash .github/scripts/verify-rust-ci.sh` at `11b3a725`.
Its log is `/tmp/araphor-profile-follow.tPl3zk/rust-ci-final-5.log`.
Result: **PASS**, exit code 0. Formatting, workspace check, strict Clippy and
all-target/all-feature tests passed. The 76 top-level suites contain 1,626
passed tests, zero failures and 544 ignored tests. These counts exclude nested
recovery helpers. Ignored cases remain unqualified.

| Library | Passed | Failed | Ignored |
| --- | ---: | ---: | ---: |
| `araphor-data` | 288 | 0 | 3 |
| `araphor-observability` | 23 | 0 | 2 |
| `mithril-control` | 164 | 0 | 1 |
| `mithril-e2e` | 167 | 0 | 525 |
| `mithril-node` | 266 | 0 | 0 |

The source review and Ponytail review are complete. The owner uses shared
segment reads, one result/progress/reference transaction and exact value
comparison. It adds no private raw archive, subscription service or model
dependency. Read the [implementation review](implementation-review.md).

Performance, 50,000-atom concurrent-intake measurements, operator review time
and field noise reduction remain **UNQUALIFIED**. No new performance test or
benchmark ran. Physical qualification remains in 7.10. No later phase starts
with this result.
