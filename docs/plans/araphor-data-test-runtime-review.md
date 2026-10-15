# Araphor Data Test Runtime Review

The [runtime plan](araphor-data-test-runtime-reduction.md) owns approved changes,
comparisons, and their terminal receipts. The
[current performance review](../guides/araphor-performance-simplification-review.md)
owns later production changes. This guide owns the fixture source route.

## Intended end state

Tests use the standard Rust runner and supported production owner APIs. Reuse
immutable preparation; preserve every workload, input, fault, assertion,
deadline, authority boundary, and independent durable state.

## Implementation review flow

[Execution factory](../../crates/araphor-data/src/package/required/testing.rs)
creates a temporary store, query owner, authority, and installed packages
  -> [Wasm fixture](../../crates/araphor-data/src/package/wasm/fixtures.rs) shares immutable compiled code and keeps private running state
  -> [InstalledAnalysis::snapshot](../../crates/araphor-data/src/package/installed/read.rs) retains exact tenant references and charged leases
  -> [Graph fixture](../../crates/araphor-data/src/graph/tests/native_storage.rs) reuses that case's execution across its original windows
  -> [Traversal fixture](../../crates/araphor-data/src/graph/tests/traversal/fixtures.rs) reuses the first already-derived graph and commits every window

The [Discovery corpus](../../crates/araphor-data/src/discovery/derive/tests/corpus.rs)
decodes one seed per case and clones it for original records. Record clocks,
identities, variants, and encoding stay in the loop. Traversal retains witness
deadline changes, request construction, and distinct later-window derivations.
A snapshot clone shares leases; it does not create an independent query budget.
A pin does not bypass current authority. Update, expiry, history, replacement,
and revocation cases keep their unpinned owner paths.

[Discovery crash qualification](../../crates/araphor-data/src/analysis/crash.rs)
prepares durable packages in the parent, drops handles, and launches the child.
The child opens the store, checks exact package roots and revisions, and lazily
admits the Discovery component. It exits at the original crash point. The parent
checks recovery, retries, receipts, raw records, and a second reopen. All six
exit scenarios remain. Cold installation, compiler failure, eviction, and full
cache-capacity cases keep separate proof. The fixture constructor is gated by
test or test-fixtures; there is no additional production service.

## Descriptor and schema reuse

[Package::descriptor_value](../../crates/araphor-analysis-sdk/src/descriptor.rs)
validates and sorts the descriptor for runtime inspection. Author builds still
generate WIT and native headers through the SDK bindings. Copies remain owned
by callers. The later immutable builtin declaration cache uses the same
canonical descriptor contract.

[GraphRows::expected_shape](../../crates/araphor-data/src/analysis/graph_rows/schema.rs)
derives expected schema rows from the existing SQL and DuckDB version.
OnceLock retains only successful immutable results. A transient error is not
cached. Concurrent first callers can repeat construction. Every validation
reads actual columns and constraints again. Actual store data and a successful
store-validation result are never cached.

## Existing proof route

| Contract | Rust test route |
| --- | --- |
| Corpus and seed reuse | `discovery::derive::tests::discovery_derivation_corpus_parity` and the complete derivation family |
| Traversal windows | `graph::tests::traversal::native_traversal_large_graph` and `graph::tests::traversal::recovery::native_traversal_replacement_history` |
| Descriptor bytes | SDK `bindings::tests::declarations_share_descriptor` and `bindings::tests::descriptor_size_is_bounded`; Data `package::tests::wasm::metadata::package_metadata_digest_stable` |
| Actual schema integrity | `analysis::graph_rows::tests::schema::native_schema_integrity` and `native_schema_reopen`; `analysis::graph_rows::tests::recovery::native_recovery_rejects_corruption` |
| Crash boundaries | `analysis::crash::discovery_profile_commit_crashes`: two sealing modes, three points, six exits |
| Independent state | Graph and Discovery factory identity checks; original owner-specific concurrency, capacity, authority, and cleanup cases |

The integrity case accepts a correct connection, rejects its mutation, and
accepts another correct connection. Reopen checks preserve corrupt bytes.
Encoding sinks retain partial-write, error, flush, overflow, and exact-bound
checks. OCI and actual-byte storage now supersede the older JSON package
counting and cap-only tests; read the current production review for those paths.

## Source and verification limits

The full earlier diagnostics, failed attempts, source hashes, binary hashes,
and final receipts remain at
`7b7b407adf347d389984553a4d212bfce37b75b5:docs/plans/araphor-data-test-runtime-review.md`.
The final original qualification at `e31b033e` passes all 90 harnesses: 2,122
passed, zero failed, and 568 ignored. The Data inventory retains all 633 original
cases and seven regressions; the SDK adds three writer regressions.

Diagnostic child attribution is incomplete. Some fixture access spans combine
initialization and mutex wait. Inclusive spans overlap. Unmarked work remains
unattributed. Whole-suite runs have uncontrolled host load and filesystem
caches. They cannot establish a causal production speed change. Temporary
markers and comparison wrappers are removed; no timing infrastructure remains.
Use the [current TODO](araphor-performance-simplification-todo.md) for later
source verification and the required final Rust procedure.
