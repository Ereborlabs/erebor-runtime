# Araphor Data Test Runtime Reduction

Reduce the time to run the complete `araphor-data` test suite. Remove repeated
fixture and preparation work first. Preserve the production owner calls,
assertions, workloads, durability checks, and deadlines that establish correctness.

## Intended end state

The complete Data suite runs faster on the same host and with the same build
profile and test concurrency. A retained report identifies the cost of fixture
lock waits, package preparation, store creation, recovery, and evaluation.
Every existing test remains in the required inventory. Timing improvements do
not replace functional proof.

The initial request approved investigation and a plan. The user then explicitly
approved ordered changes 1 through 5 on 2026-10-14. This approval includes the
eight existing diagnostic cases, four test threads, and the 15-minute runtime
allowance stated below. Change 6 and later CI scheduling remain unapproved.
This plan does not change the completed native execution scope or approve its
later child phases.

## Implementation flow

An engineer starts the approved diagnostic run
  -> record the source, test binary, host, profile, and selected test names
  -> distinguish lock wait from fixture setup and actual evaluation
  -> record parent and child costs without counting child time twice
  -> rank repeated work by measured cost

An engineer changes one read-only fixture
  -> reuse the existing installed snapshot and compiled code facilities
  -> retain each original computation, input variant, and assertion
  -> keep mutable lifecycle and cold-start cases on their original paths
  -> run the affected existing cases before another full workspace run

A fixture change passes focused verification
  -> select the next correction from the measured cost report
  -> retain separate authorization, memory accounting, and durable-state owners
  -> stop if the correction requires a new ownership or trust-boundary design

The approved implementation is ready for qualification
  -> run the repository Rust CI procedure after the last covered edit
  -> obtain the new Data duration from that run
  -> compare the complete test inventory, results, and configuration
  -> record the measured improvement and any remaining slow cases

## Baseline and evidence limits

The last successful source is
`5e9364543093e3e18da03e4d51e6dd28cc057982`. The inspected checkout adds the
documentation commit `404d0a78`; the covered Rust source is unchanged.

| Item | Recorded value |
| --- | --- |
| Data suite | 2,157.82 seconds: 35 minutes 57.82 seconds |
| Inventory | 633 tests: 614 passed, 0 failed, 19 ignored |
| Test configuration | Four test threads; one Cargo build job; debug test profile |
| Log | `/tmp/araphor-native-rust-ci-joined-shutdown-final-20261014.log` |
| Source and terminal proof | `/tmp/araphor-native-final-ci-joined-shutdown-source-20261014.json`; session 25541; exit 0 |

The log identifies 29 distinct Data tests that ran for more than 60 seconds.
Eight are Discovery derivation tests; 12 are graph tests. The other nine concern
analysis, packages, and queries. These warnings include fixture lock wait. They
are not individual CPU measurements and cannot be added to obtain suite time.
The log has no per-test or per-stage duration within the Data harness.

The source facts below are verified. Their shares of the 2,157.82 seconds are
not measured. No reduction percentage or final duration is claimed.

## Why the suite can take this long

| Source fact | Cost and limit |
| --- | --- |
| [Discovery execution fixture](../../crates/araphor-data/src/discovery/derive.rs) and [graph execution fixture](../../crates/araphor-data/src/graph/tests.rs) return global mutex guards. | Discovery holds a guard across complete cases, including the 21-case corpus. Graph cases and traversal setup also use a shared guard. Waiting cases occupy test threads. More test threads do not remove these locks. |
| [Snapshot creation](../../crates/araphor-data/src/package/installed/read.rs) reloads bundles when the execution value is not pinned. [Discovery](../../crates/araphor-data/src/discovery/sdk/atoms.rs) and [graph derivation](../../crates/araphor-data/src/graph/derive.rs) create snapshots on entry. | A new unpinned call repeats activation reads, bundle loading, decoding, and artifact checks. An existing pinned snapshot returns a clone. Every evaluation still has authorization and control checks. |
| [Required test setup](../../crates/araphor-data/src/package/required/testing.rs) creates owners and installs four required bundles. [Package fixtures](../../crates/araphor-data/src/package/tests/fixture.rs) create or reopen a store. | The source has 85 `testing` call sites, three `testing_tenants` call sites, and 319 store-open call sites. These are static counts, not counts of executed operations. Loops and child processes add work. |
| [Graph schema validation](../../crates/araphor-data/src/analysis/graph_rows/schema.rs) creates a temporary DuckDB database and its three graph tables for each expected-schema comparison. | The expected schema is immutable for the build. The actual store schema must still be checked on every applicable open. |
| [Existing-store open](../../crates/araphor-data/src/analysis/mod.rs) validates state before recovery. [Recovery](../../crates/araphor-data/src/analysis/raw_catalog.rs) validates state again after projection. | The two checks protect different boundaries. Recovery also reads retained raw commits, restores receipts, checks the catalog, and calculates usage. Removing a check without proof can accept corrupt state. |
| [SQL evaluation](../../crates/araphor-data/src/query/evaluation.rs) creates a new in-memory DuckDB database for each run. | Engine setup and relation registration are repeated. The new database also isolates each evaluation. Connection pooling requires a separate design and is not the first correction. |
| [Artifact encoding](../../crates/araphor-data/src/package/bundle.rs) calls [SDK interface generation](../../crates/araphor-analysis-sdk/src/bindings.rs) for descriptor JSON. | The call also formats WIT and a native header that encoding does not use. Required bundle construction generates 47 typed port schemas and copies four artifact buffers. |
| [Crash qualification](../../crates/araphor-data/src/analysis/crash.rs) starts new processes. | The six Discovery profile crash children each initialize their own five-library Wasm fixture cache. Other crash cases also repeat cold store setup. Real process exits and crash boundaries are required proof. |

[Wasm fixture code](../../crates/araphor-data/src/package/wasm/fixtures.rs) is
already shared. Each process has two lazy caches for fuel configurations.
Each cache prepares five libraries when first used. Ordinary fixtures clone prepared code and keep
evaluation state separate. A second compilation cache would duplicate this
facility. Cross-process reuse needs a separate trust-boundary review.

## Ordered changes

Data owns the store, query, package, Discovery, graph, and local fixture changes.
The SDK and builtin crates own shared descriptors and interfaces. Changes there
must also verify their callers outside Data. CI scheduling belongs to the
existing workflow and verification script and requires separate approval.

| Order | Proposed change | Verification and stop point |
| --- | --- | --- |
| 1 | Measure the selected existing cases below. Separate lock wait, setup, bundle preparation, schema checks, recovery, SQL setup, and computation. | Obtain explicit approval for the diagnostic workload and runtime allowance. Produce a cost report before choosing larger changes. |
| 2 | Pin one installed snapshot when each read-only Discovery or graph fixture is initialized. Use the existing `InstalledAnalysis::snapshot` method. | Review every fixture caller. Exclude update, revocation, cache freshness, historical selection, and lifecycle cases. Preserve all evaluations and charged leases. Start with this small pilot. |
| 3 | Reuse the first graph snapshot already produced by `CommitFixture::new` when traversal builds window zero. Decode the corpus seed once per case and clone it for each record. | Preserve the traversal witness deadline adjustment, new request fields, and every commit. Static targets are nine redundant derivations, or 27 detector calls, and 10,312 redundant seed decodes. These counts are not time estimates. |
| 4 | Remove unused interface generation from runtime descriptor encoding. Reuse immutable builtin descriptor/schema templates where the measured report justifies it. | Preserve serialization bounds, canonical ordering, descriptor JSON bytes, artifact digests, validation errors, and owned copies for callers that modify descriptors. Author builds still generate complete WIT and headers. This reaches SDK and builtin owners and needs its own focused review. |
| 5 | Cache only successfully derived immutable expected graph schema data from the same SQL and DuckDB version. | Retain actual-schema comparison, column order/type/nullability, primary keys, unique constraints, corruption rejection, and failure behavior. Do not cache a transient initialization error, actual store validation result, or retained data. |
| 6 | Give independent cases separate execution owners and query budgets before narrowing or removing fixture mutexes. Reuse existing compiled code and eligible immutable package inputs. | Do not remove a mutex from a shared mutable owner or increase quotas to avoid Busy errors. Measure fresh-owner cost against lock wait. Preserve authority state, checkpoints, guest stores, and cleanup. |

Each correction is a separate reviewable slice. The user explicitly approved
rows 1 through 5. Row 6 requires a separate approval. Preserve focused failing-case
investigation and one authoritative final CI process for the approved changes.

Duplicate retained-state scans, crash bootstrap, and repeated graph input
normalization are secondary candidates. Change them only if the diagnostic
report places them on the critical path. Keep both pre-recovery rejection and
post-recovery consistency checks until a reviewed replacement proves both.

## Proposed diagnostic workload

Run these eight existing tests in the already unified workspace feature set:

1. `discovery::derive::tests::discovery_derivation_corpus_parity`
2. `graph::tests::traversal::native_traversal_large_graph`
3. `analysis::crash::discovery_profile_commit_crashes`
4. `query::client_tests::discovery_query_current_profiles`
5. `package::tests::wasm::metadata::wasm_metadata_install_retry`
6. `analysis::graph_migration::tests::recovery::native_recovery_rejects_corruption`
7. `discovery::derive::tests::discovery_comparison_reviewed_changes`
8. `graph::tests::traversal::recovery::native_traversal_replacement_history`

The two Discovery cases share one execution mutex. The two traversal cases use
the graph execution mutex. Run these pairs together to observe lock contention.
One case from each family alone cannot establish contention between tests.

Use four test threads, the debug profile, and the same original inputs. Propose
one diagnostic run with a 15-minute runtime allowance. If it exceeds the
allowance, record incomplete attribution; do not change a test or product
deadline. There is no proposed speed threshold for this diagnostic run.

Diagnostic completion requires all existing functional assertions to pass and
cost records for the selected stages. Record CPU availability, memory, filesystem,
source hash, binary hash, child processes, and fixture cache state. Separate
elapsed wall time from sums of overlapping worker times.

Use existing tools and temporary test-only timing markers. Add no benchmark
framework, dependency, product configuration, or new acceptance scenario.
Remove temporary markers before final functional qualification. The
[performance-test approval rule](../../.agents/verification.md#performance-test-approval)
requires explicit approval before adding performance tests or benchmarks.
The approved diagnostic completed. Its measured result is recorded below.

## Coverage and qualification

- Preserve every existing test name and its required or ignored classification.
  Additional focused regression tests can increase the inventory.
- Preserve all 21 corpus cases, 10,333 original records, reversed duplicate
  replay, and rare-event checks. Pages contain 128 unique record identities;
  duplicates stay together and can increase a page's record count.
  The existing normal/replay
  work includes 198 atom calls and 156 merge calls; do not remove these calls.
- Preserve the large traversal's 17 windows, 16,385 subjects, 32,769 edges,
  path depths, fanout limits, cancellation, historical selection, and restore.
- Preserve cold compilation, cache eviction, retained-trap release, compiler
  failure, authority changes, crash points, durable synchronization, and cleanup.
- Preserve current optional quota defaults and compiled-code accounting.
- Run focused checks after each correction. When the approved slice is ready,
  run `bash .github/scripts/verify-rust-ci.sh` after its final covered edit.
  Use that run's Data summary for the full-suite comparison; do not add a
  second complete Data run only to collect the same duration.

Set an approved runtime target after the diagnostic report establishes which
costs can be removed. A faster selected case does not establish a faster complete
suite. A timing result must use the same concurrency and comparable host load.

## Later CI scheduling option

The [Rust workflow](../../.github/workflows/ci.yml) currently has one Rust job.
The [verification script](../../.github/scripts/verify-rust-ci.sh) runs one
complete workspace test command. The workflow has no Cargo artifact cache or
test shards.

If source reductions leave unacceptable elapsed time, propose balanced test
shards on separate runners. Build the unified workspace test artifacts first.
Partition the complete inventory exactly once and preserve all targets and
helper dispatch. A `cargo test -p` split alone can change feature unification.
Keep child executables in their canonical paths and prevent relinking while
children run. Account for repeated Wasm warmup in each process.

Sharding reduces elapsed time by adding resources; it does not remove repeated
work. Runner resources, cost, and the changed verification procedure need
explicit approval. Cargo caching helps build time, not the recorded 36-minute
Data test execution. Neither is the first proposed Data correction.

## Result

**Done** for approved ordered changes 1 through 5, source review, focused
qualification, complete Data qualification, and final workspace CI.
The complete Data duration decreased by 767.41 seconds, or 35.56 percent.
**Partial** for diagnostic child-stage attribution. All temporary timing
markers are removed. Change 6 and CI scheduling require separate approval.

## Diagnostic record

The approved eight-case run completed on 2026-10-14. All eight tests passed.
The debug harness reported 487.49 seconds. Parent process wall time was
487.54 seconds. The run used four test threads and the original inputs.
The frozen instrumented binary has SHA-256
`05abdc8362cb545787bd6f3d23593cb93a14f9b0b47a464c72bac862260711b6`.

| Completed parent stage | Calls | Inclusive seconds | Exclusive seconds |
| --- | ---: | ---: | ---: |
| Installed snapshot creation | 184 | 548.37 | 360.03 |
| Bundle encoding | 523 | 213.33 | 211.19 |
| Graph fixture access | 30 | 227.76 | 174.06 |
| Discovery fixture access | 2 | 157.51 | 103.81 |
| Compiled fixture preparation or cache wait | 17 | 94.56 | 94.56 |
| Discovery derivation | 78 | 321.16 | 93.35 |
| Installed fixture setup | 15 | 125.61 | 23.10 |
| Recovery | 33 | 14.65 | 14.65 |
| Graph derivation | 30 | 14.62 | 14.62 |
| Store open | 41 | 30.03 | 13.04 |
| Descriptor encoding | 545 | 2.24 | 2.24 |
| Graph schema validation | 19 | 2.34 | 0.84 |
| SQL connection setup | 12 | 0.44 | 0.44 |
| SQL relation registration | 12 | 0.38 | 0.38 |
| Required builtin templates | 17 | 0.15 | 0.15 |

Inclusive spans contain nested spans. Exclusive spans subtract completed
children on the same thread. Worker times overlap. Neither column can be added
to obtain suite wall time. Fixture access includes shared initialization wait
and mutex wait. The report does not separate those two waits when another
thread performs initialization. Graph schema validation includes expected
database creation. Schema-row queries have separate nested spans.

The log contains six crash-child test starts. Each child captures its stage
output. The report therefore has no child-stage durations. An absent child
span does not mean zero cost. One split JSON record retains all numeric fields
across two log lines. Its corrupt thread label is excluded from per-test
attribution. Resource usage includes both build and test children. This usage
is not a test-only CPU measurement. Unmarked work remains unattributed.

The diagnostic record retains host, memory, filesystem, source hashes, the
feature-unified build command, exact test names, and start and end times.

- `/tmp/araphor-data-diagnostic.json`
- `/tmp/araphor-data-diagnostic.log`
- `/tmp/araphor-data-cost-report.json`
- `/tmp/araphor-data-before-inventory.txt`
- `/tmp/araphor-data-before-ignored.txt`

Snapshot cost supports the read-only fixture changes. Required builtin
templates used 0.15 seconds across 17 calls. This result does not justify
another builtin template cache. Runtime descriptor encoding uses the existing
SDK inspection API instead.

**Done** for the approved bounded diagnostic. **Partial** for child-stage
attribution. Source changes 2 through 5 are implemented. Functional
qualification passed in the final record below. Temporary timing markers
are removed. The complete-suite comparison is recorded below.

Read the [source review guide](araphor-data-test-runtime-review.md) to inspect
the changed owners and their proof route.

## Focused qualification

The feature-unified debug artifacts passed 63 SDK tests, six author builder
tests, and 26 selected Data tests. The Data harness reported 160.60 seconds.
The selected cases include corpus parity, every traversal case, schema
integrity and reopen, corruption recovery, descriptor bytes and digests,
legacy SQL encoding, and snapshot memory accounting.

The complete Data inventory remains 633 tests. The same 19 tests remain
ignored. The focused record is `/tmp/araphor-data-focused.json`. The selected
Data log is `/tmp/araphor-data-focused-araphor_data.log`.

**Done** for focused qualification. Final repository CI subsequently passed.

## Complete Data qualification

The complete Data harness passed in 1,390.41 seconds: 23 minutes 10.41 seconds.
The result is 614 passed, 0 failed, and 19 ignored. The inventory remains
633 tests. The run uses the same four test threads, one Cargo build job,
feature-unified workspace selection, and debug profile as the baseline.

Compared with 2,157.82 seconds, the recorded reduction is 767.41 seconds:
12 minutes 47.41 seconds, or 35.56 percent. This comparison uses two complete
Data harness results. It does not use the different focused workloads as a
speed comparison. Host load was not controlled between the two full runs.

The log is `/tmp/araphor-data-final-ci.log`. The source record is
`/tmp/araphor-data-final-ci-source.json`. The remaining workspace CI
subsequently passed. Source hashes matched at process exit.

**Done** for complete Data qualification and measured Data runtime reduction.
Final workspace CI acceptance is recorded below.

## Final workspace acceptance

The repository procedure completed with exit 0 on 2026-10-14 at
17:52:03.212524 UTC. The command was
`CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=4 bash .github/scripts/verify-rust-ci.sh`.
Elapsed procedure time was 2,450.85 seconds: 40 minutes 50.85 seconds.
Formatting, workspace checking, strict clippy, and full workspace tests passed.
The 90 parent harnesses reported 2,112 passed, 0 failed, and 568 ignored.
Child summaries are not added to these parent totals.

The source recorder covers 1,392 tracked Rust, Cargo, and CI files. Their
hashes remained unchanged from procedure start to exit. The source state is
HEAD `404d0a78575558975359f6b1dbd886bf70baddeb` plus the ten changed Rust
files listed in the record. The changes remain uncommitted.

- `/tmp/araphor-data-final-ci.log`
- `/tmp/araphor-data-final-ci-source.json`
- `/tmp/araphor-data-final-ci-summary.json`

**Done** for final workspace acceptance of approved changes 1 through 5.
Child-stage timing remains incomplete. The complete Data duration is measured.
Suggested commit message: `Reduce repeated Data test preparation`.

## Further reduction proposal

The user requested more analysis after the complete Data run reached
1,390.41 seconds. The user subsequently approved implementation of F1 through
F7 and a separate commit for each deliverable. The F1 comparison uses the
workload and runtime allowances below. The F7 concurrency comparison still
requires its concrete workload and runtime approval.

### Current evidence

The final Data log has 20 distinct tests with warnings above 60 seconds.
The earlier full run had 29. Remaining warnings include crash recovery,
corpus derivation, large traversal, mutable package history and freshness,
metadata installation retries, and current-profile queries. These warnings
include waits. They do not identify each test's CPU cost.

The eight-case diagnostic preceded the completed changes. Its 523 bundle
encodes and 211.19 exclusive worker-seconds show a repeated serialization
path. They do not establish that path's share of the remaining 23 minutes.
Child-stage attribution remains incomplete.

The existing build log confirms optimization level 0 for Data, the SDK,
`serde_json`, and `sha2`. Wasmtime and the main Cranelift crates already use
level 2. The host record reports 16 CPUs and affinity to all 16 CPUs. The
qualification run uses four Rust test threads. This CPU record alone does not
establish that higher concurrency is safe or faster.

### Proposed corrections

| ID | Change and concrete example | Boundary and proof |
| --- | --- | --- |
| F1 | Try optimization level 1 for test builds of Data and the SDK, then select serialization or hashing dependency overrides if the comparison supports them. | Keep debug assertions, overflow checks, all features, test names, and ignore status. Keep guest compiler settings unchanged. Measure build time separately from test execution. Generic serialization code can be generated in Data or the SDK, so a dependency override alone can miss the hot code. |
| F2 | Reuse the admitted bundle when [Run performs its final inspection](../../crates/araphor-data/src/package/evaluation.rs). The current call passes `None` although `bundle` remains available. | Use the existing [inspection argument](../../crates/araphor-data/src/package/inspect.rs) and [root/revision checks](../../crates/araphor-data/src/package/freshness.rs). Keep current activation reads, authority checks, freshness evaluation, dependency ordering, and fallback loading. Verify concurrent replacement and scope cases. Add no production cache. |
| F3 | Stream canonical encoding into bounded size and hash writers when the output bytes are discarded. [Validation](../../crates/araphor-data/src/package/admission.rs) currently allocates an encoded bundle to check its limit. [Digest creation](../../crates/araphor-data/src/package/bundle.rs) allocates the complete encoding again. | Use one canonical serializer. Preserve descriptor and bundle bytes, digest domain, bounds, error behavior, and ordering. Keep `encode` for callers that need the bytes. This removes buffers; it still serializes every artifact byte. |
| F4 | Avoid candidate serialization before an identical [installation retry](../../crates/araphor-data/src/package/lifecycle/revisions.rs) returns its existing revision. | Compare the saved descriptor, dependencies, and artifact through the existing semantic rules first. Preserve validation, collision rejection, legacy SQL equality, bounds, and all transaction decisions. Do not replace semantic equality with an unreviewed byte comparison. |
| F5 | Reduce unrelated preparation in the [Discovery crash case](../../crates/araphor-data/src/analysis/crash.rs). Its six children each prepare five libraries and install four required packages. Discovery processing uses the Discovery library. Prepare durable packages before launching the child, then let the child compile the library it uses. | Keep all six process exits, sealing modes, crash points, synchronization, cold reopen, and recovery assertions. Review the initial package revisions and transaction boundary. Dedicated cold installation, compiler failure, eviction, and five-library capacity tests keep their original coverage. Add no unsafe machine-code cache or fork after multithreaded runtime startup. |
| F6 | Pin packages in additional read-only cases that change evidence or query inputs. Start with eligible single-tenant [live](../../crates/araphor-data/src/discovery/live.rs) and [query](../../crates/araphor-data/src/query/client_tests.rs) cases. | Review each test. The live owner helper also serves a package activation test, so do not pin that helper for every caller. Keep update, authority, historical, expiry, and cache-freshness cases unpinned. Multi-tenant current-profile tests need separate tenant handling; one tenant pin cannot cover all tenants. |
| F7 | Give independent cases separate execution owners and budgets, then compare four and eight Rust test threads. Reuse the existing compiled code facility. | This is the earlier unapproved change 6. A clone of the pinned execution still shares its query budget, so do not remove the mutex from that clone. Keep stores, grants, authority state, guest stores, checkpoints, and cleanup separate. Do not raise quotas to avoid `Busy`. Measure extra package installation and store creation against reduced waiting. |

F1 is a small configuration experiment. F2 is the first production correction
to review. F3 and F4 address the large package payload path. F5 addresses cold
child setup. Apply F6 only to audited cases. Apply F7 after setup reuse is
available; otherwise new independent owners can add more installation work.
Every test continues to use the standard Rust test runner.

F3 keeps the existing conditional encoding. Component bundles use sorted,
pretty descriptor JSON. Legacy SQL-only bundles keep compact descriptor JSON.
F4 also preserves candidate serialization failures and error precedence before
returning a saved revision. Upstream validation alone does not prove those
revision-encoding guarantees. If the guarantees require the original work,
retain that work. F5 bypasses eager child fixture preparation; moving package
installation to the parent alone would still compile five libraries per child.

### Proposed measurement and acceptance

Use these nine existing cases to measure the residual paths:

1. `analysis::crash::discovery_profile_commit_crashes`
2. `package::tests::wasm::metadata::wasm_metadata_install_retry`
3. `package::tests::wasm::metadata::mixed_metadata_install_retry`
4. `query::client_tests::discovery_query_current_profiles`
5. `graph::tests::paging::control_graph_finding_pages`
6. `discovery::derive::tests::discovery_derivation_corpus_parity`
7. `discovery::derive::tests::discovery_derivation_distinct_keys`
8. `graph::tests::traversal::native_traversal_large_graph`
9. `graph::tests::traversal::recovery::native_traversal_replacement_history`

Propose one diagnostic run with four threads and a 15-minute runtime allowance.
Use temporary test-only markers. Write child records to separate process files
to retain completed stages before intentional process exit and avoid captured
or interleaved output. Record setup, compile, encode, decode, evaluation, and
fixture access separately. Keep overlapping worker time separate from wall
time. Preserve every existing functional assertion and product deadline.
If the allowance expires, record incomplete attribution.

F1 requires a second run of the same cases with the same four threads and a
15-minute allowance after the profile change. The proposed combined execution
allowance is 30 minutes, excluding build time. Functional assertions must pass;
there is no proposed speed pass/fail threshold. Compare both build cost and
execution cost. F7 requires a separate four-versus-eight comparison proposal
after owner separation. Neither comparison has started.

Require unchanged canonical bytes and digests, complete test inventory,
corruption rejection, authorization, memory charging, lifecycle checks, and
crash boundaries. Run focused correctness checks for approved corrections,
then one final repository CI run after the final covered edit. Use that run
for the complete Data comparison.

No new saving percentage or final duration is established. Database pooling,
cached actual-store validation, skipped durable synchronization, smaller
corpora, and a native replacement for Wasm qualification are not proposed.
The existing measurements do not justify prioritizing builtin descriptor
template caching or SQL connection pooling.

**Done** for further source analysis and this proposal. F1 through F7 are
approved for implementation. Implementation and final qualification are in
progress. The qualified baseline is commit `4d0758cf`.

## Implementation results

### F1: Test build profile

The matching nine-case comparison passed with four threads in both runs.
The baseline harness took 473.97 seconds. Data and SDK optimization level 1
took 442.83 seconds. The reduction is 31.14 seconds, or 6.57 percent.
All nine assertions passed. The complete 633-test inventories are identical.
Only `Cargo.toml` differs between the recorded original sources. Both test
executables and instrumented source hashes remained unchanged during execution.

Both runs retained debug assertions and overflow checks. Wasmtime and Cranelift
remain at their existing optimization levels. Guest compiler settings are
unchanged. Seven process files retain completed parent and child spans in each
run. Both runs recorded 35 library compilations. Encoding spans decreased from
131.40 to 95.91 elapsed worker-seconds. Exclusive bundle-load spans remained
166.04 seconds in the level-1 run. Spans overlap across workers. These spans
are not additive suite durations or CPU measurements. Dataset decode markers
had no completed calls in this workload. Bundle loading includes JSON decode
and durable reads; those costs are not separated by this diagnostic.

The final configuration has no serialization or hashing dependency override.
A temporary `serde_json` level-1 override invalidated DuckDB build dependencies
and started a new C++ build. That build was stopped before tests ran. The JSON
override was removed. The diagnostic does not separate JSON decode from other
load costs. The evidence does not justify this extra build cost. The measured
exclusive digest spans also do not justify another profile setting.

The baseline incremental build took 228.07 seconds. The first level-1 build
failed during `mithril-policy` linking because the filesystem was full.
The failed log interval is approximately 1,073 seconds. Cleanup removed only
old generated incremental caches. The successful retry took 48.42 seconds
with completed artifacts retained. These results do not establish a clean
build-cost comparison. The configuration change can increase build cost.

The records are `/tmp/araphor-f1-baseline.json`,
`/tmp/araphor-f1-opt1.json`, and their `-costs.json` reports. The failed build
log is `/tmp/araphor-f1-opt1-failed-build.log`. Temporary markers are removed.
No performance framework or timing test enters the repository.

**Done** for the matching Data and SDK comparison and profile implementation.
**Not done** for final configuration qualification until the focused and
repository checks below complete.

### F2 admitted bundle inspection

The Run owner passes its admitted bundle to final inspection. Inspection uses
that bundle only when the installed root matches. Artifact selection also
checks the installed revision. A changed root uses the existing store loading
path. Inspection still reads current activations, checks authority, calculates
freshness, and selects current receipts. No production cache is added.

The added test is
`package::lifecycle::tests::admitted_inspection_tracks_replacement`.
The test covers a matching root, replacement, old-root fallback, scope, and
rejected authority. Existing lifecycle and Wasm replacement tests retain their
original operations and assertions.

**Done** for implementation and focused qualification. The feature-unified
run passed 111 Data cases in 598.77 seconds and all 66 SDK tests. The record
is `/tmp/araphor-f-final-focused.json`. Covered source hashes remained
unchanged. **Not done** for final repository CI. No elapsed-time saving is established for this correction.
