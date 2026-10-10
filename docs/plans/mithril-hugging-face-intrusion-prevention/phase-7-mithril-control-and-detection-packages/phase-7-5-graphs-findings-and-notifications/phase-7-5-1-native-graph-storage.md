# Phase 7.5.1: Native Graph Storage And Traversal

Store subjects, relationships, and findings as native rows so authorized reads
and joins do not decode every graph snapshot. Add bounded large-graph access and
native DuckDB traversal. Parent: [7.5](README.md).

## Intended end state

AnalysisStore keeps one authoritative graph representation. Existing snapshot
and export APIs reconstruct the same values, identities, and ordering. Historical
finding references and notification obligations remain valid. An authorized
caller selects exact seeds and receives bounded native rows across source
windows. DuckDB executes traversal. Later algorithm and detector packages can
use this host data path.

## Implementation flow

```text
GraphAndFindingOwner submits a validated graph result
  -> AnalysisStore encodes its versioned rows outside the write transaction
  -> AnalysisStore commits rows, references, progress, revisions, and quota together
  -> an identical retry returns the original receipt
  -> a changed retry under the same operation key fails

Caller requests findings or a query input
  -> the reader authorizes the complete selected versions before row selection
  -> the reader selects native rows under cancellation and byte limits
  -> the reader closes durable handles before SQL evaluation

Store opens with retained snapshot bodies
  -> migration checks the format and available temporary storage
  -> migration converts every retained version and verifies reconstruction
  -> AnalysisStore retires old bodies only after the checked conversion commits
  -> a failed conversion preserves the original store

An authorized client submits exact seeds and traversal limits
  -> QueryOwner validates the request under the existing investigate grant
  -> AnalysisStore pins current source-window heads or exact retained results
  -> AnalysisStore checks each complete version before traversal
  -> DuckDB traverses narrow full subject keys through fixed recursive SQL
  -> AnalysisStore reads only selected subject and relationship payloads
  -> AnalysisStore closes the durable snapshot before client SQL runs
  -> the result records version references, row counts, and the hop boundary

Traversal exceeds a work, row, byte, or time limit
  -> the read fails with a structured error
  -> client SQL receives no truncated aggregate input
  -> the read owner closes handles and releases temporary state
  -> a retry captures a new read revision
```

## Scope and owners

The [seven storage TODOs](README.md#native-graph-storage-improvement-todos)
remain the storage checklist. The additional traversal TODOs below extend the
user-approved scope on 2026-10-10. Keep the original checklist in its location. AnalysisStore
owns encoding, transactions, migration, quotas, and reconstruction.
`graph/read.rs` owns selected finding reads; query extraction and the existing
VTab expose detached rows. Share row encoding and reconstruction across these
paths. Preserve `GraphAndFindingOwner` validation and graph construction.

### Native traversal and large-graph TODOs

- [x] Define a bounded graph input request and receipt under the graph model
  owner. Preserve complete seed authority and lifetime. Include direction,
  edge types, exact historical result IDs or current heads, hop, subject, and
  relationship limits. Use existing query byte, capacity, and deadline limits.
- [x] Check complete versions before traversal. Preserve tenant, source, Node,
  binding, and sensitivity rules. An excluded replacement cannot restore the
  old version. Keep one read revision for version selection and native reads.
- [x] Execute fixed parameterized recursive DuckDB SQL with `USING KEY`.
  Exclude visited keys and deduplicate candidates. Keep minimum hop depth.
  Bound narrow work inputs and output keys before selected proof payload reads.
- [x] Add direct native subject and relationship reads. Share row decoding with
  reconstruction. Add no complete Rust graph, second graph body, or custom
  graph engine. Use no index unless a query plan proves its use.
- [x] Connect graph input to QueryPlan, ClientGrpcOwner, and `araphor sql --graph`.
  Use one JSON file for the CLI input. Return a receipt with exact result IDs,
  counts, and hop-boundary state. Add no listener or permission.
- [x] Qualify at least 16,385 distinct subjects and 32,769 relationships across
  multiple current source windows. Keep existing per-version limits. Include
  disconnected records, chains, diamonds, cycles, high fanout, directions,
  type filters, exact seeds, and hop boundaries.
- [x] Verify row and byte limits, cancellation, deadlines, source replacements,
  historical versions, tenant and lifetime isolation, whole-version grants,
  retained proof, reopen, and backup/restore with focused Rust tests.
- [x] Extend the existing lightweight graph-notification case, then its paired
  physical Rust case. Include the captured 185-record window with 370
  relationships. Verify all relationships through bounded output queries under
  the existing 200-row cap. Retain the inner read error during diagnosis.
  Run the final shared Rust gate. Update the review guide and results. Commit
  each completed deliverable in the primary checkout.

Traversal SQL must read `graph_subjects` or `relationships`. It can join these
datasets and `catalog`. Use the ordinary catalog command for catalog-only
inspection. Follow, bookmarks, and other datasets are rejected for this request.
Existing queries retain their current behavior. Client recursion remains
outside the admitted SQL subset; the graph owner controls native recursion.
A zero-hop request reads exact seeds. Positive-hop reads retain filtered
relationships between reached subjects.

The pinned DuckDB 1.5.5 supports
[recursive USING KEY queries](https://duckdb.org/docs/current/sql/query_syntax/with).
This path adds no extension or dependency. Functional large-graph checks have
no throughput or latency threshold. Performance remains **UNQUALIFIED**; a
benchmark requires separate workload, runtime, and pass/fail approval.

## Acceptance and verification

- Complete all seven linked TODOs with focused Rust tests. Include latest
  version per source window, latest finding across windows, and removal of
  findings omitted by a replacement window.
- Verify typed joins, whole-version authorization, sensitivity, exact retries,
  rollback, reopen, quota reconstruction, and backup/restore.
- Verify failed migration preserves originals and successful migration keeps
  every historical result reference and snapshot value.
- Run the existing `graph-notification` lightweight case before its paired
  physical case. Run the final shared Rust procedure after source changes.

## Exclusions and stop point

Add no graph database, custom DuckDB type, second snapshot body, or replacement
VTab. The retained graph conversion is the user-approved exception to the parent
plan's fresh-store rule. It does not authorize unrelated format migrations.
Stop before SDK implementation.

## Result

**Done** for native storage, direct large-graph reads, and bounded native
DuckDB traversal. The storage baseline is `91afc657`. Native traversal and
large-graph access are committed as `88b3e8c`. Commit `763b7f1` shares the
filtered native edge relation and records an expired deadline's caller.
Commit `d20420c0` reuses full-source authorization. Commit `adf4d14b` encodes
shared projection metadata once per version. The existing raw-recovery test
uses a fresh control for each independent read in `bb49d538`.
The full lightweight and paired physical cases and the final shared Rust
procedure pass on the metadata source below. Read the
[native traversal review](native-traversal-review.md) for the implemented flow,
limits, caller examples, and proof. Read `/tmp/araphor-native-traversal.OC49oX`
for the source records and logs.

The scoped source record is `source-state-scoped.json`. It covers 1,348 files
with SHA-256
`0a5066e7016021d98c26afbfd1f0e36e8f08771d7c32565b520fc28f90c5002f`.
Commit `d20420c` skips binding-proof SQL filters for full-source grants after
whole-version authorization. Binding grants retain those filters. Nine native
checks pass after that change; read `native-scoped.log`. The full lightweight
case passes on this source. Its result is `lightweight-scoped/result.json`, with
SHA-256
`9bcb5d538e02c7653f3c90ee11eba68338c32562fc44b8711b4c847c03690b76`.
Read `lightweight-scoped-receipt.json`. All 1,348 source files match after the
run. The 64-record window selects five subjects and 192 relationships. The
selected density version has four subjects and three relationships. Both
queries return equal data after reopen. The paired physical run uses this source and lightweight input. Its failure is
recorded below. At that source, further qualification and the final Rust gate
remain pending.

The earlier source record is `source-state-shared2.json`. It covers 1,348 files
with SHA-256
`8fb48077944aa1211858ca7cb4484270d58051df80d3746e20358799a51b2a66`.
Read `native-shared.log`, `control-shared.log`, and `window-shared.log`.
The earlier lightweight result is `lightweight-shared/result.json`, with SHA-256
`061124b5a7068922f9e235d834eebb9d829b0b690acde7da408756d2cdf623a8`.
Read `lightweight-shared-receipt.json`. All 1,348 covered source files match
after the run. The 64-record query selects five subjects and 192 relationships.
The density query selects four subjects and three relationships from one exact
version. These selected lightweight snapshots contain no context facts or
manifest contexts. That run does not qualify physical context inputs.
The earlier full lightweight case passes on `source-state-qualified.json`,
which covers 1,347 files with SHA-256
`d4af099f0297dc8747f4c5fd262225f3afc5040ff0f699fdc926bd9ffbf45644`.
Its result is `lightweight-qualified/result.json`, with SHA-256
`6a49679120c9f37ba1aab92f17c67ac48c14681d9aec20d648cc3f9077beaaa5`.
That case selects one exact version through a fresh QueryOwner in a store with
257 findings across 33 source windows and returns equal data after reopen.
Read `lightweight-qualified-receipt.json`. The new source retains that condition
and adds a 64-record window with one task, mixed allowed and denied events,
missing initial health, and the same default-budget query after reopen.
The physical case now exports its graph, request, SQL, counts, limits, and
canonical replay before its first traversal.

The initial physical run failed on its first traversal with
`AnalysisReadDeadline`. Its owned resources and VM were removed. The dense
first-query condition now exists in the lightweight case. Traversal reuses
validated header bytes, revision, and sensitivity in the same pinned read.
The retained bytes and vector storage count toward the input limit. The first
shared Rust run failed one existing raw-recovery test. That test reused one
absolute deadline across independent reads, writes, and reopen. Commit
`bb49d538` gives each independent read a fresh control. Its focused check passes.
These changes keep the existing memory and deadline limits.

An earlier serial physical run also fails on its first traversal with
`AnalysisReadDeadline`. It does not reach reopen. Read
`physical-qualified-invocation.json` and `physical-qualified-test.log`.
The test lifecycle removed the original store before return. Only the decision
was exported before the failed query. Resource and VM cleanup pass; read
`physical-qualified/vm-cleanup.json`. The owned namespace, domain, work, and
active state are absent. The original ACL is restored. The other VM is unchanged.
This run supplies no physical traversal pass. The exact internal timeout stage
is not established by its log.

The next physical provision fails before VM creation. The test-only replay
export uses an internal type with no Serialize implementation. Read
`physical-shared-invocation.json`, `physical-shared-vm-start.log`, and
`replay-export-build-failed.log`. The export now uses the existing serializable
replay fields. The focused 64-record check passes; read `window-capture.log`.
No production serialization contract or deadline limit changes. Read
`physical-shared-pretest-cleanup.json` for cleanup and ACL restoration. This
attempt supplies no physical test result.

The scoped physical pair fails its first traversal with
`AnalysisReadDeadline`, observed at `analysis/read.rs:161`. It does not reach
reopen. The final check follows snapshot close and does not identify the inner
failure. The exported graph has 185 records, three subjects, 370 relationships,
one finding, and no context facts or manifest contexts. All relationships
originate at the selected seed. This condition was absent from the lightweight
case. Its one-row-per-relationship query also exceeds the existing 200-row
output cap. Read `physical-scoped/graph.json`,
`physical-scoped/observed-graph-input.json`, and `physical-scoped/replay.json`.
The graph has SHA-256
`bf77f290329f51e49df0f8870fb57f90938dae7ac2bc3a298d7c27018f06ec73`.
The replay has SHA-256
`1ff3ff15b846cde78521d4ff1619bd109e1c19b37d64c3095fbb865b614ae1d4`.
All 1,348 covered source files match after the test. Cleanup passes; read
`physical-scoped/vm-cleanup.json`, with SHA-256
`61b45d85f2e1f57ee1dac0a01ccf8f23d370db00d4e845bbf0041d4446a98107`.
The owned namespaces, VM, work and state roots are absent. The original ACL is
restored, and the other VM is unchanged. This run supplies no physical traversal
pass. At that source, the 185-record regression and its bounded output checks
were not yet present.

The new 185-record Rust fixture first stops at an intermediate 128-record
snapshot. It now calls the public process and snapshot APIs until the complete
window is present. The complete fixture reproduces `AnalysisReadDeadline`.
A temporary test-only diagnostic retains the inner error at
`ProjectionSink::check`, in `analysis/extraction.rs:443`. This observation does
not give a timing breakdown. Read `window-before2.log` and its receipt. That
source has SHA-256
`833c3ef8acc3252ec8574b6145e385d4646f0e045c4201c2f0d7c882f4dc12ee`.
Commit `adf4d14b` makes the shared graph projection encode its six metadata
columns once per version, on the first eligible row. The cache has an explicit heap charge.
Each output row still owns and charges its values. Permission checks and all
limits remain unchanged. The same 185-record fixture passes after this sole
production change, including all 370 relationship checks and reopen. Read
`window-after.log` and `window-after-receipt.json`. The temporary diagnostic is
removed. The final source record is `source-state-metadata.json`, with 1,348
files and SHA-256
`ecd499969fcfc73ccf162ee92f8f68934ba42dd5611fc5c155e0be7ca9114b40`.
Nine native and ten graph-query checks pass on this source. Read
`native-metadata.log` and `graph-query-metadata.log`. The fresh full lightweight
case passes on this source. Read `lightweight-metadata/result.json`, with
SHA-256
`a104a944a5895de35035aa3dc6e9ce701029ed08dbaca0475f750a3fcf786f6b`.
Its 185-record fixture has a 66,874-byte manifest and checks all 370
relationships through two output queries with the same complete native receipt.
The 64-record and density cases also pass. Read
`lightweight-metadata-receipt.json`; all 1,348 source files match after the run.
The fresh paired physical Rust case passes on the same source and lightweight
input. Read `physical-metadata/result.json`, with SHA-256
`31f718d784080127bb9177729939a6bb16600845a7cf1ebe75ccb0f3f00528a7`.
The recorded platform is Linux `6.8.0-142-generic` and Kubernetes
`v1.35.5+k3s1`. The selected physical window has 187 records, three subjects,
374 relationships, one finding, no context facts or manifest contexts, and a
60,376-byte manifest. Two SQL queries return all 374 relationships in chunks of
200 and 174 rows. The complete receipt and traversal value are equal after
reopen. Canonical replay also remains equal. Both stages keep their one-second
default and the SQL output cap remains 200 rows. The protected read returns
errno 13 and zero bytes. The benign read returns 558 bytes. Notification retries,
restart, overdue human acknowledgement, and final acknowledgement pass.
The finding remains `COVERAGE_INSUFFICIENT`; native ancestry, policy provenance,
and source coverage limits remain explicit. Read `physical-metadata-test.log`
and `physical-metadata-invocation.json`. The latter has SHA-256
`8286d603b7875830790d241e5b2621a39443960a2616c2bfb32991c9b65a99fe`.

Resource and VM cleanup pass. Read `physical-metadata/vm-cleanup.json`, with
SHA-256
`4420341fcb678aada147024abd471a22b311f8439c5eb219dba45ec80361bf23`.
Both owned namespaces, the owned domain, work directory, active state, and
metadata work and state roots are absent. The original ACL and mode are
restored. The other VM is unchanged. All 1,348 source files still match.
Earlier failure, setup, and regression records retain their hashes.
This proof covers one protected file-open denial and one benign read through
kernel, Node WAL, mTLS intake, Control, graph, and notification owners. The
query uses a fixed qualification grant. Full incident reproduction, remote
provider effects, physical cross-node causality, physical multiwindow traversal,
and performance remain **UNQUALIFIED**.

The final shared Rust procedure passes with exit code 0. Its command is
`env RUST_TEST_THREADS=1 CARGO_BUILD_JOBS=2 bash .github/scripts/verify-rust-ci.sh`.
It checks formatting, the workspace build, Clippy with warnings denied, and
all workspace targets and features. The data suite passes 391 tests with three
existing ignored qualifications. The Control suite passes 182 tests with one
ignored qualification. The Node library passes 282 tests with one ignored
qualification. The Mithril e2e suite passes 171 tests with 526 existing ignored
cases. Its dense, mixed-window, captured-window, and
complete graph-notification roundtrip checks pass. The paired physical case
passes separately as recorded above. No test suite fails.
Read `rust-ci-metadata.log`, with SHA-256
`6f6e2bfde05ad50d633a33bb54ea317c923835cf1a852c98f20f66c16e8b3a57`.
Read `rust-ci-metadata-receipt.json`, with SHA-256
`17557083614419ccecf1345208ae8e4ce8c9cbbb7e6216ef56d28762ec8a2b9b`.
The run starts at `2026-10-10T09:21:49Z` and finishes at
`2026-10-10T10:05:09Z`. All 1,348 covered source files match before and after
the procedure. SDK, package runtime, and algorithm migration remain outside
this completed scope.

The storage baseline is **Done**. All seven storage TODOs pass their required
checks in the primary checkout. Commit: `91afc657`. SDK, package lifecycle, runtime,
and algorithm migration work remain outside this result.

Historical plan expansion record: the storage checklist is retained from the
existing plan. No new implementation or storage qualification is recorded by
that plan expansion.

The primary checkout contains the qualified storage implementation. The
[native row owner](../../../../../crates/araphor-data/src/analysis/graph_rows/mod.rs)
stores subjects, relationships, and findings. Existing graph APIs use native
reads and checked reconstruction. The
[migration owner](../../../../../crates/araphor-data/src/analysis/graph_migration.rs)
converts retained versions in one transaction. Current focused checks pass 32
native tests, one schema-permission test, and ten graph query tests. Read the
source record and logs in `/tmp/araphor-native-storage.j8wJmf`.
The existing dense notification case passes with 257 findings across 33 source
windows. Read `dense-split.log`. Earlier reads reached a deadline or failed
native allocation. The current reader separates key selection, version
validation, and bounded payload reads. The memory limit remains 64 MiB and the
deadline remains one second. The full lightweight case and Clippy pass on the
recorded source. Read `lightweight-qualified/result.json`,
`lightweight-qualified.log`, and `clippy-final.log` in the same evidence
directory. The earlier paired physical Rust case passes on Linux kernel
`6.8.0-142-generic` and Kubernetes `v1.35.5+k3s1`. The protected read returns
errno 13 and zero bytes. The benign read returns 558 bytes. Graph references,
replay, reopen, and notification transitions pass. Read `physical/result.json`,
`physical-test.log`, and the resource and VM cleanup receipts. The earlier shared
Rust procedure fails the existing
`control_graph_context_and_result_bounds_keep_required_progress` test with
`AnalysisReadDeadline`. It reports 378 passed, one failed, and three ignored
Araphor tests. Later workspace tests do not run. Read `rust-ci-qualified.log`.
The focused test also reproduces the failure. The unbounded finding read
measured an unused JSON output limit. It now skips that byte accounting. The
existing large-context test passes after the correction.

The corrected source record is `source-state-complete2.json` in the same
evidence directory. It covers 1,330 files with SHA-256
`ea747ca3d8ea338a09b5e515874aa6fffa9134ab29a68489d311dbb354b06479`.
The large-context test, three finding checks, and workspace Clippy pass.
Read `context-budget-fix.log`, `finding-budget-focused.log`, and
`clippy-budget-fix.log`. The full lightweight case also passes. Its result is
`lightweight-complete2/result.json`, with SHA-256
`000b84e17774832bb9a314b22c3731f85747b29eaea2efcd0e747f8af57e4862`.
The fresh physical pair passes on x86_64, Linux `6.8.0-142-generic`, and K3s
`v1.35.5+k3s1`. Its result is `physical-complete2/result.json`, with SHA-256
`608d890301bc5ee4cfa80eee62ade2d5b12f6787682559ee0ba7284bf581c1c7`.
The protected read returns errno 13 and zero bytes. The benign read returns
558 bytes. Replay, reopen, and notification contracts pass. The graph decision
is `COVERAGE_INSUFFICIENT`, equal to the lightweight `initial-health-missing`
case. It retains ancestry, policy, source-coverage, and activation limits.
One target obligation is acknowledged; 255 ambient obligations remain.
The owned resources and VM are removed. Read `physical-complete2-invocation.json`,
`physical-complete2-provenance.json`, `physical-complete2/resource-absence.json`,
and `physical-complete2/vm-cleanup.json` in the same evidence directory.
The final shared Rust procedure returns zero after the last source edit:

```sh
rtk proxy env RUST_TEST_THREADS=1 CARGO_BUILD_JOBS=2 bash .github/scripts/verify-rust-ci.sh
```

Formatting, workspace check, strict Clippy, and all workspace tests pass. The
Araphor Data suite reports 379 passed, zero failed, and three ignored. Read
`rust-ci-complete2.log`, with SHA-256
`3e24ef3f8341e606a48adf26ac9b23bc093c14574b8b59f37b3d5047ce802ee2`.
Read `rust-ci-complete2-receipt.json` for the command, exit code, and source check.
The final covered source matches `source-state-complete2.json`. Ignored tests
are not counted as passes; the physical case above ran separately.
This proof does not qualify the full incident, cross-node behavior, provider
effects, or performance.

## End scope and example

Complete when graph writes, selected reads, joins, snapshot reconstruction,
migration, and backup/restore use native rows and the linked storage checklist
passes. Native traversal and the large-graph TODOs must also pass.
Existing graph APIs and historical references retain their meaning. Package
authoring and execution are not added by this storage change.

Example at completion: source-window result `R1` contains finding `F1`; its
replacement `R2` omits `F1`. The current finding query excludes `F1`. An exact
historical read of `R1` still returns it, and a notification that references
`R1` remains readable after migration and restore.

Traversal example at completion: exact seed `S1` occurs in several current
source windows. An outgoing two-hop request selects `S1`, `S2`, and `S3`, with
each relationship's result and evidence references. A disconnected retained
graph is not exported. The receipt reports a boundary if an unseen neighbor
exists beyond `S3`. A subject-limit overflow fails before SQL can aggregate
incomplete input. This result does not prove full-incident prevention, physical
cross-node causality, provider effects, performance, or unlimited graph size.
