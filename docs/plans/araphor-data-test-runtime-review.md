# Araphor Data Test Runtime Review

Review the changes in items 2–5 of the
[runtime reduction plan](araphor-data-test-runtime-reduction.md). The changes
remove repeated fixture preparation and descriptor work. They preserve the
existing test inputs, assertions, production owner calls, and deadlines.

## Intended end state

The complete Data suite runs faster with the same profile and test concurrency.
The complete suite still proves its original contracts. The current source
implements the changes below. Final qualification passed. The complete Data
duration decreased by 767.41 seconds, or 35.56 percent.

## Implementation review flow

[/tmp/araphor-data-diagnostic.json](/tmp/araphor-data-diagnostic.json) An engineer starts the approved diagnostic run
  -> [diagnostic record](/tmp/araphor-data-diagnostic.json) record the source, test binary, host, profile, and selected test names
  -> [cost report](/tmp/araphor-data-cost-report.json) distinguish lock wait from fixture setup and actual evaluation
  -> Partial [cost report](/tmp/araphor-data-cost-report.json) record parent and child costs without counting child time twice
  -> [cost report](/tmp/araphor-data-cost-report.json) rank repeated work by measured cost

[Discovery fixture](../../crates/araphor-data/src/discovery/derive.rs) An engineer changes one read-only fixture
  -> [InstalledAnalysis::snapshot](../../crates/araphor-data/src/package/installed/read.rs) reuse the existing installed snapshot and compiled code facilities
  -> [TraversalFixture](../../crates/araphor-data/src/graph/tests/traversal/fixtures.rs) retain each original computation, input variant, and assertion
  -> [package fixtures](../../crates/araphor-data/src/package/tests/fixture.rs) keep mutable lifecycle and cold-start cases on their original paths
  -> [focused record](/tmp/araphor-data-focused.json) run the affected existing cases before another full workspace run

[focused record](/tmp/araphor-data-focused.json) A fixture change passes focused verification
  -> [descriptor encoding](../../crates/araphor-data/src/package/bundle.rs) select the next correction from the measured cost report
  -> [InstalledSnapshot](../../crates/araphor-data/src/package/installed/snapshot.rs) retain separate authorization, memory accounting, and durable-state owners
  -> [scope boundary](araphor-data-test-runtime-reduction.md) stop if the correction requires a new ownership or trust-boundary design

[current changes](araphor-data-test-runtime-reduction.md) The approved implementation is ready for qualification
  -> [CI source record](/tmp/araphor-data-final-ci-source.json) run the repository Rust CI procedure after the last covered edit
  -> [CI log](/tmp/araphor-data-final-ci.log) obtain the new Data duration from that run
  -> [focused inventory record](/tmp/araphor-data-focused.json) compare the complete test inventory, results, and configuration
  -> [measured result](araphor-data-test-runtime-reduction.md#complete-data-qualification) record the measured improvement and any remaining slow cases

## Owners and lifecycle

The [Discovery fixture](../../crates/araphor-data/src/discovery/derive.rs) and
[graph fixture](../../crates/araphor-data/src/graph/tests.rs) create one pinned
installed snapshot for their immutable package stores. Both fixtures retain
their existing mutexes. The snapshot retains bundles and pins through charged
[query leases](../../crates/araphor-data/src/package/installed/snapshot.rs).
Clones share those leases. Normal evaluation still checks authority and control.
Package update, revocation, freshness, and lifecycle tests keep their separate
fixtures. The changes do not alter quotas or durable store ownership.

```mermaid
sequenceDiagram
    participant Fixture
    participant InstalledAnalysis
    participant QueryOwner
    Fixture->>InstalledAnalysis: snapshot(tenant)
    InstalledAnalysis->>QueryOwner: retain_analysis_input(bytes)
    QueryOwner-->>InstalledAnalysis: charged leases
    InstalledAnalysis-->>Fixture: pinned snapshot
    Fixture->>InstalledAnalysis: clone pinned snapshot
```

The corpus fixture decodes one seed per case, then clones the seed for every
original record. Per-record clocks, identities, variants, and encoding remain
in the loop. The traversal fixture reuses the graph snapshot that
[CommitFixture::new](../../crates/araphor-data/src/graph/tests/native_storage.rs)
already derives for window zero. Traversal still sets the window witness
deadline, replaces subjects and edges, creates the request, and commits every
window. Later windows still derive their distinct inputs.

[Package::descriptor_value](../../crates/araphor-analysis-sdk/src/descriptor.rs)
validates the descriptor and sorts its JSON objects. Both `inspect` and
[interfaces](../../crates/araphor-analysis-sdk/src/bindings.rs) use that value.
Runtime bundle encoding calls `inspect`; author interface generation still
produces WIT and native headers. Descriptor copies remain owned by callers.
Immutable builtin template reuse is not implemented in this slice.

[GraphRows::expected_shape](../../crates/araphor-data/src/analysis/graph_rows/schema.rs)
creates the expected schema with the existing SQL and DuckDB library. A
process-local `OnceLock` stores only successfully decoded immutable rows.
Initialization errors do not enter the cache. Concurrent first callers can
repeat construction. Temporary expected connections close after construction.
Every validation still reads the actual connection and compares its columns
and constraints. Actual store state and validation results are never cached.

## Existing proof route

| Change | Existing Rust tests |
| --- | --- |
| Pinned fixture and seed reuse | `discovery::derive::tests::discovery_derivation_corpus_parity`; the complete Discovery derivation family |
| First traversal window | `graph::tests::traversal::native_traversal_large_graph`; `graph::tests::traversal::recovery::native_traversal_replacement_history`; the traversal family |
| Descriptor encoding | `bindings::tests::declarations_share_descriptor`; `bindings::tests::descriptor_size_is_bounded` in the SDK; `package::tests::wasm::metadata::package_metadata_digest_stable` in Data |
| Expected schema cache | `analysis::graph_rows::tests::schema::native_schema_integrity`; `analysis::graph_rows::tests::schema::native_schema_reopen`; `analysis::graph_migration::tests::recovery::native_recovery_rejects_corruption` |

The integrity test validates a correct connection, rejects its later mutation,
then validates another correct connection. Reopen tests retain their checks
that rejection does not change corrupted database bytes. Final verification
uses [the repository procedure](../../.github/scripts/verify-rust-ci.sh).

## Source and evidence limits

This guide covers HEAD `404d0a78575558975359f6b1dbd886bf70baddeb` plus the
current ten changed Rust files shown in the linked source families. The
[diagnostic record](/tmp/araphor-data-diagnostic.json) covers the frozen
instrumented baseline, not the changed implementation. The
[cost report](/tmp/araphor-data-cost-report.json) has partial child attribution
because child output is captured. One split record retains its numeric fields,
but its thread label is corrupt. Fixture access combines shared initialization
wait and mutex wait when another thread performs initialization. Unmarked work
remains unattributed. Inclusive spans overlap and are not additive suite durations.
Temporary timing markers are removed. No measured savings are claimed.

**Done** for final qualification. The exact source state, complete inventory,
and final CI duration are recorded below.

The focused feature-unified debug run passed 63 SDK tests, six author builder
tests, and 26 Data tests. Data completed in 160.60 seconds. The complete Data
inventory and all 19 ignored classifications are unchanged. The record is
[/tmp/araphor-data-focused.json](/tmp/araphor-data-focused.json).
**Done** for focused qualification. Final repository CI subsequently passed.

The complete Data run passed 614 tests with 19 ignored in 1,390.41 seconds.
The complete inventory remains 633 tests. The baseline was 2,157.82 seconds
with the same debug profile and four test threads. The measured reduction is
767.41 seconds, or 35.56 percent. Host load was not controlled between runs.
The remaining workspace CI subsequently passed. The source recorder confirmed
that covered hashes matched at process exit.

## Final acceptance

The final repository procedure passed with exit 0 at
2026-10-14 17:52:03.212524 UTC. Formatting, workspace checking, strict clippy,
and full workspace tests passed. The 90 parent harnesses reported 2,112 passed,
0 failed, and 568 ignored. Elapsed procedure time was 2,450.85 seconds.
All 1,392 covered Rust, Cargo, and CI file hashes remained unchanged during
the run. The source state remains HEAD `404d0a78575558975359f6b1dbd886bf70baddeb`
plus the ten uncommitted Rust changes.

Read the [source record](/tmp/araphor-data-final-ci-source.json) and
[CI log](/tmp/araphor-data-final-ci.log) for the exact command, hashes, and
results. **Done** for approved changes 1 through 5. Diagnostic child-stage
attribution remains incomplete. No complete-suite speed claim depends on
those missing child records.

## Test profile correction

[Cargo test overrides](../../Cargo.toml) An engineer builds the Data tests
  -> [Data and SDK overrides](../../Cargo.toml) compile Data and SDK test code at optimization level 1
  -> [repository procedure](../../.github/scripts/verify-rust-ci.sh) retain the existing features, assertions, overflow checks, and test selection

The profile change does not change guest compiler settings. The matching
nine-case comparison covers the Data and SDK overrides. Both runs passed.
The recorded harness duration changed from 473.97 to 442.83 seconds.
There is no JSON or hashing dependency override. The temporary JSON override
started a new DuckDB C++ build and was removed before execution qualification.
A full filesystem blocked the first optimized build. The successful retry
reused completed artifacts.
Read [the implementation record](araphor-data-test-runtime-reduction.md#f1-test-build-profile)
for the exact measurements and limits. These temporary diagnostics are manual
evidence. They do not add committed timing tests.

## Admitted bundle inspection

[AnalysisPackageOwner::run](../../crates/araphor-data/src/package/evaluation.rs) Run completes the selected evaluations
  -> [AnalysisPackageOwner::inspect](../../crates/araphor-data/src/package/inspect.rs) inspect with the admitted bundle
  -> [AnalysisPackageOwner::refresh_package](../../crates/araphor-data/src/package/freshness.rs) read current activations and calculate freshness
  -> [artifact selection](../../crates/araphor-data/src/package/inspect.rs) use the matching root and revision or load current stored data

Run owns the borrowed bundle until inspection returns. Inspection does not
retain that borrow. Authority, activation, receipt, and scope checks remain in
their existing owners. Replacement can make the admitted root obsolete. The
existing fallback then reads the current artifact. This correction adds no
shared decoded package state or memory lease.

Read `package::lifecycle::tests::admitted_inspection_tracks_replacement` in
[the lifecycle tests](../../crates/araphor-data/src/package/lifecycle/tests.rs).
The test covers matching roots, replacement, fallback, scope, and authority.
Focused qualification passed in the 111-case Data run. The source record is
`/tmp/araphor-f-final-focused.json`. Final repository CI is pending.

## Bounded encoding sinks

[PackageBundleV1::encode](../../crates/araphor-data/src/package/bundle.rs) A caller requests bundle bytes
  -> [PackageBundleV1::encode_into](../../crates/araphor-data/src/package/bundle.rs) order artifacts and serialize the existing descriptor representation
  -> [BoundedBuffer](../../crates/araphor-analysis-sdk/src/wire/codec.rs) reject a write beyond the byte limit and forward accepted writes

[PackageBundleV1::validate](../../crates/araphor-data/src/package/admission.rs) Validation checks the encoded size
  -> [PackageBundleV1::check_encoding](../../crates/araphor-data/src/package/bundle.rs) use a bounded discard sink with the same serializer

[PackageBundleV1::digest](../../crates/araphor-data/src/package/bundle.rs) A caller requests the digest
  -> [PackageBundleV1::encode_into](../../crates/araphor-data/src/package/bundle.rs) write the same bytes to the bounded SHA-256 sink after the existing domain

Each call owns its temporary writer. Byte encoding returns the owned vector.
Size checking discards accepted bytes. Digest calculation retains only the hash
state. The SDK writer advances its count only after a successful write and uses
the sink's accepted byte count. The writer forwards flush errors. The writer
rejects arithmetic overflow and preserves the existing limit error text.

Read the new `wire::codec::buffer_tests` in
[the SDK codec](../../crates/araphor-analysis-sdk/src/wire/codec.rs) and
`package::bundle::encoding_tests` in
[the bundle owner](../../crates/araphor-data/src/package/bundle.rs).
The tests cover partial writes, write and flush errors, overflow, exact limits,
digest equality, and descriptor rejection. The existing
`package::tests::wasm::metadata::sql_bundle_encoding_unchanged` test checks the
compact SQL bytes. Focused qualification passed. The source record is
`/tmp/araphor-f-final-focused.json`. Final repository CI is pending.

## Installation retry encoding

[AnalysisPackageOwner::install_revision](../../crates/araphor-data/src/package/lifecycle/revisions.rs) Installation prepares one immutable revision
  -> [AnalysisPackageOwner::revision_encoding](../../crates/araphor-data/src/package/lifecycle/revisions.rs) construct the descriptor and sorted dependency fields
  -> [AnalysisStore::package_revision](../../crates/araphor-data/src/analysis/packages/read.rs) read the saved record and retain its result
  -> [ArtifactEncoding::check_encoding](../../crates/araphor-data/src/package/bundle.rs) check the candidate bound on a saved-record hit
  -> [semantic comparison](../../crates/araphor-data/src/package/lifecycle/revisions.rs) return the identical saved record or encode the candidate bytes
  -> [AnalysisStore::install_package](../../crates/araphor-data/src/analysis/packages/revisions.rs) retain the existing collision and transaction checks

The record lookup is read-only. Installation holds the existing lifecycle
lock. The owner does not return a saved lookup or decode error until candidate
serialization succeeds. A missing record or lookup error uses byte encoding
instead of size checking, so cold installation serializes once. A different
existing record can require both operations. Descriptor and artifact comparisons
retain the legacy semantic rules. No cache, durable identity, or transaction
owner changes.

Read `package::lifecycle::revisions::tests::revision_retry_and_collision` and
`revision_candidate_error_precedes_saved_decode` in
[the revision owner](../../crates/araphor-data/src/package/lifecycle/revisions.rs).
The tests cover identical retries, conflicting records, unchanged durable
state, and candidate-limit errors before malformed saved artifact decoding.
Focused qualification and final CI are pending.

The internal revision serializer and size check both use the existing 64 MiB
analysis record limit. Public bundle encoding and validation retain the 32 MiB
bundle limit. The test
`package::lifecycle::revisions::tests::revision_retry_preserves_encoding_bound`
checks an internal revision between those limits and an identical retry.
The candidate-limit precedence test retains rejection above the record limit.
Qualification is pending after this bound correction.

The earlier 111-case Data run passed retry collision and candidate-error
precedence checks. The limit correction and added regression require the
focused record `/tmp/araphor-f-retry-focused.json`. That run is in progress.
