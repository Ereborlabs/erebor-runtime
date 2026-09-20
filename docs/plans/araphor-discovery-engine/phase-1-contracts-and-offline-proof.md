# Phase 1: Contracts, Investigation Fixtures, And Storage Proof

Define the smallest qualified input and prove one recorded-input path before
adding continuous derivation, public SQL, or console mutation.

## Intended end state

A bounded accepted-evidence bundle produces deterministic behavior rows and
checks one recorded exact native file/execute candidate. Missing metadata
produces an explicit unsupported result. The production proposal builder is
owned by Phase 3; this phase proves its input and compiler seam. Context,
assessment, and suggestion schemas have executable fixture checks. A measured
SQLite/DuckDB comparison selects one embedded store and proves isolated query
execution before Phase 2.

## Implementation flow

Partial [run_discovery_offline](../../../crates/mithril-e2e/src/discovery.rs): Engineer selects a recorded workload case. Only the synthetic case exists.<br>
-> Partial [manifest](../../../crates/mithril-e2e/fixtures/discovery/manifest.json): Engineer pins source revision, target inputs, and permitted data scope. The inputs are fixture data.<br>
-> [DiscoveryInputManifestV1::validate](../../../crates/mithril-control/src/discovery/model.rs): Input adapter validates the existing envelope and coverage records.<br>
-> Partial [derive_recorded](../../../crates/mithril-control/src/discovery/recorded.rs): Adapter joins owner-supplied actor and resource bindings. Current joins use supplied fixture bindings.<br>
-> [DiscoveryOwner::derive_recorded](../../../crates/mithril-control/src/discovery/recorded.rs): Owner builds exact atoms and a sealed snapshot.<br>
-> [simulate_recorded](../../../crates/mithril-control/src/discovery/recorded.rs): Native compiler and PolicySimulator evaluate reconstructable keys.<br>
-> Partial [run_discovery_offline](../../../crates/mithril-e2e/src/discovery.rs): Output includes unknown cases and a replay manifest. It contains a fixture candidate preview, not a generated proposal.

[derive_recorded](../../../crates/mithril-control/src/discovery/recorded.rs): Required resource or role binding is absent.<br>
-> [derive_recorded](../../../crates/mithril-control/src/discovery/recorded.rs): Adapter preserves the observation as unresolved.<br>
-> Partial [simulate_recorded](../../../crates/mithril-control/src/discovery/recorded.rs): Preview omits invented resource or authority. The proposal builder is not implemented.<br>
-> Partial [source limits below](#source-and-proof-limits): Engineer records the exact owner/protocol change needed.<br>
-> Not implemented: Live implementation waits for the reviewed owner contract.

[derive_recorded](../../../crates/mithril-control/src/discovery/recorded.rs): Replay input or context conflicts at the same record ID.<br>
-> [derive_recorded](../../../crates/mithril-control/src/discovery/recorded.rs): Replay returns a typed mismatch.<br>
-> [DiscoveryOwner](../../../crates/mithril-control/src/discovery/recorded.rs): No live lookup repairs the recorded input.<br>
-> [DiscoveryDigestV1](../../../crates/mithril-control/src/discovery/model.rs): Corrected input creates a new bundle digest.

[storage_compare](../../../crates/mithril-e2e/harness/discovery/storage_compare.py): Engineer compares embedded stores on the same generated input.<br>
-> [measure](../../../crates/mithril-e2e/harness/discovery/storage_compare.py): Experiment measures deduplication, micro-batches, context queries, and recovery.<br>
-> Partial [measure](../../../crates/mithril-e2e/harness/discovery/storage_compare.py): Evaluator checks equal counts, canonical output, and measured resource use. Full resource qualification remains open.<br>
-> Partial [result below](#storage-experiment): Both candidates remain Reject for production selection. SQLite has fewer open feasibility issues in this experiment.<br>
-> Not implemented: Phase 2 waits until one candidate meets the complete contract.

## Scope and owners

- `mithril-control`: proposed discovery record types and `DiscoveryOwner`
  methods; existing policy validation and simulation. Private stateless
  helpers do not become another domain owner.
- Node/evidence owners: review the missing resource catalog contract. This
  phase does not change the Interceptor or add a collector.
- `mithril-e2e`: a lightweight entry point that calls supported owner APIs.
  No test-only reproduction of Control's internal operation sequence.
- Documentation: source dossier for both clones; no upstream code copy until
  applicable license and provenance are resolved.

## Required changes

### Prerequisites and delivery boundary

Start here in the [combined order](README.md#combined-implementation-order).
This offline work can proceed while Mithril 6.2 qualification finishes.
Reconcile current main and the implementation worktree first. Do not recreate
Control intake, policy delivery, approval reservation, or runtime recovery
because an older closure record calls them absent. Freeze graph, finding,
notification, and response references for later owners; do not implement those
owners here. Discovery 2 requires this phase's measured store selection and
contract tests. Console fixture work can start after these records are frozen.

1. Reconcile this worktree with current source and qualification records. Record
   exact revisions. Do not reuse a historical pass as a new result.
2. Specify canonical schemas from [engine-design.md](engine-design.md), including
   source epochs, proof kind, context reads, and unknown values.
3. Trace all current constructors/callers of the affected evidence and policy
   types before proposing an extension. Show producer, consumer, retention,
   migration, and compatibility consequences.
4. Allocate the bounded read/export contract to Phase 2. Discovery must not
   acknowledge the existing shared watermark. Use offline bundles here.
5. Implement exact aggregation and check a fixture-supplied candidate through
   native lowering, compilation, and simulation. Do not implement another
   proposal builder, wildcard generator, or inferred actor role.
6. Freeze the labeled pilot corpus and operator-task protocol before comparing
   ML methods. Include malicious activity in an otherwise normal learning run.
   Separate duplicate delivery, repeated legitimate work, rare valid work,
   changed releases, and poisoned baselines. Measure observations, exact atoms,
   review items, incorrect decisions, and task time independently.
7. Define `ContextPacket`, `DetectionAssessment`, `ClassificationAssessment`,
   `Suggestion`, `AssessmentReport`, `QueryReceipt`, and `DisclosurePolicyV1`.
   Freeze query/follow schemas, SQL/view contracts, and typed error examples.
   Require the same tenant, owner-qualified subject, evidence manifest, optional
   finding revision, and parent artifact references across reports and changes.
   Freeze notification, approval, activation, and response as separate owner
   facts in the shared read view; no duplicate case-complete state.
   Validate supporting/refuting references, missing facts, and draft actions
   separately from grouping. No model or provider is required for this proof.
8. Add incident-inspired credential-access, benign maintenance, deployment
   drift, and missing-provider-evidence tasks to the same corpus. Record exact
   expected evidence, alternative hypotheses, acceptable classifications, and
   useful next checks. Withhold future reviews from each historical context.
9. Add a bounded `storage_compare` experiment under the existing e2e harness.
   Use identical generated input up to the admitted million-record/256-MiB
   bound and 50,000 atoms. Compare SQLite and DuckDB batch ingestion, retry
   counts, context joins, evidence pivots, revision diffs, stable pages, restart,
   cancellation, native memory, spill, and rebuild. Use native engine layouts,
   not identical indexes by assumption. Record scripts, versions, plans,
   cold/warm runs, and results in this phase; do not add a storage review doc.
   Select one pinned binding only after correctness and budget gates pass.
10. Prototype query admission and isolation in the same experiment. Test a
    maintained parser/binder, approved views/functions, scope/redaction before
    evaluation, worker resource limits, and no file/network/extension access.
    Measure projection-copy, worker startup, and adversarial join costs. A
    SELECT prefix or read-only connection is not sufficient. If either engine
    cannot meet the security and latency gates, record Reject.
11. Map the master acceptance cases to existing/planned owner capabilities:
    HF-LOCAL-001, HF-NET-001, HF-SEM-001, HF-XNODE-001, HF-RESP-001/002,
    and HF-PROV-001. Freeze expected available/unsupported tool states.
    Policy-source response enums do not prove a response runtime exists.
12. Freeze one defender-loop fixture from accepted evidence through assessment,
    escalation, approval, action result, and late branch. Include model refusal,
    low suggested priority, absent human acknowledgement, and a restarted client.
    Define exact shared references and expected available/unsupported owner states.

### Changed files and contracts

- Add `src/discovery/mod.rs` and `src/discovery/model.rs` in `mithril-control`;
  export the owner from `src/lib.rs`. Add `DiscoveryOwner::derive_recorded`
  and `DiscoveryInputManifestV1::validate`. Use the record schemas in the
  engine design. Reject unknown schema versions and count/byte overflow.
- Add `crates/mithril-e2e/src/discovery.rs` and
  `src/bin/mithril_discovery_test.rs`. The binary calls the public owner API.
  It does not assemble private store transactions or compiler internals.
- Add `crates/mithril-e2e/fixtures/discovery/manifest.json` and its bounded
  inputs. Pin policy, target facts, context, accepted-record IDs, coverage,
  source revision, and expected rows. Mark supplied context as fixture proof,
  not as context that current Node transport already preserves.
- Freeze three distinct positions in the schema: accepted-record cursor,
  original kernel sequence when present, and coverage revision. Include CPU
  and source epoch. Never equate a WAL cursor with a kernel sequence.
- Record the supported static subset: existing source and declared roles;
  exact file/execute selectors with qualified bindings; no dynamic exceptions,
  unresolved mount semantics, source creation, or inferred lifecycle state.
- Add only experiment-scoped dependencies for the storage comparison. Do not
  introduce a production storage trait or ship both engines. Add the proposed
  `storage_compare` entry point in the same harness, with `--manifest`,
  `--engines sqlite,duckdb`, and `--output-directory`; require measurements and
  an explicit Select/Reject result, not a hand-written performance conclusion.

The offline entry points below now exist. Their current proof and remaining
limits are recorded in the result section:

```sh
cargo test -p mithril-control discovery:: -- --nocapture
cargo run -p mithril-e2e --bin mithril_discovery_test -- \
  --case offline-exact --output-directory /tmp/araphor-discovery-offline
```

The case writes `result.json`, `input-manifest.json`, and `snapshot.json`.
It fails on any expected-row mismatch, unexpected live lookup, or absent
assertion. Record the test count; a filter that runs zero tests is not proof.

## Acceptance and verification

- `DE-IDENTITY`, `DE-OUTCOME`, `DE-AGGREGATE`, `DE-REPLAY`, and `DE-WIDEN` from
  [verification.md](verification.md) pass on the offline slice.
- Equal input manifests produce equal deterministic output digests.
  Permute input and page boundaries; verify count conservation, stable evidence
  samples selected by record ID, and unchanged output when optional AI is absent.
- An absent path binding cannot produce a path rule; a denied read cannot
  silently enter required behavior.
- Synthetic and recorded-input results have different proof kinds.
- Pass offline `DE-PACKET`, `DE-DETECT`, `DE-ASSESS`, `DE-QUERY`, `DE-FOLLOW`,
  and `DE-PROTECTION` contract fixtures.
  Store selection must meet the query, recovery, and memory gates in
  verification.md. No unsupported absence claim or invented citation passes.
- Focused Control and e2e tests run. After Rust changes, run the repository's
  complete Rust verification command.
- Record the corpus manifest, exact commands, output paths, revision, and the
  unsupported source fields. A source study is not a runtime test.

## Exclusions and stop point

No live collection, durable multi-consumer registration, model deployment,
browser backend connection, or policy publication. Stop with the feasibility
result, frozen investigation tasks, and explicit metadata/ownership/storage
decisions before Phase 2. A benchmark not run is not a store-selection result.

## Result

**Not done.** The offline implementation and initial feasibility tests exist.
The complete corpus and storage qualification are not done. Phase 2 has not
started. No live collector, database binding, API, model, or policy mutation was
added.

### Source and proof limits

This result covers worktree HEAD
`e36d1cff21a07834c5db29076f1776c78931c7e1` plus the uncommitted changes in the
linked source files. The rebase includes main at
`d08517c9cd9a52fb3adad304370225c555f4300b`. Primary main advanced during this
work. Its later commits and working changes are not included in this result.

- `DiscoveryOwner` owns no durable state in this slice. The caller supplies an
  immutable manifest. The owner validates records, builds exact atoms, and
  returns a snapshot. It has no ControlStore handle or live lookup method.
- The manifest separates durable cursor, optional original kernel sequence,
  CPU, source epoch, coverage interval, and coverage revision. The export
  count is explicit. Interleaved CPU cursors do not imply missing records.
  A gapped or unknown observation lowers the snapshot coverage even when the
  supplied range says Healthy.
- Identical deliveries count once. Conflicting bytes at the same record ID
  fail. Independent repeated records increase the exact count. Evidence
  samples contain at most eight sorted record IDs per atom.
- Raw reason, decision, and kernel-result fields remain in the atom. The
  ABI decision field carries a physical-result code. A zero kernel result
  does not prove that the requested effect occurred. Native simulation
  returns NotAttempted; it does not prove physical enforcement.
- The synthetic manifest supplies process, entry, binding, role, state,
  catalog, image, and configuration facts. Current
  [Node normalization](../../../crates/mithril-node/src/observation/model.rs)
  does not retain that complete context. The
  [WAL adapter](../../../crates/mithril-node/src/observation/wal.rs) supplies
  a durable cursor to the envelope constructor. It does not recover an
  original kernel sequence. No protobuf, WAL, Interceptor, or retention
  watermark contract changed here.
- [Investigation contracts](../../../crates/mithril-control/src/discovery/investigation.rs)
  define the seven planned record families and query/follow shapes. Fixture
  checks reject foreign scope, stale revisions, fabricated record citations,
  invalid abstention, and unsupported negative results. This validation checks
  structure and supplied references. It does not prove that a citation supports
  a claim, resolve a live owner, redact an export, or grant execution.
- Query request validation checks shape only. SQL admission exists only in
  the experiment. Follow positions have no public token codec or live revision
  reader. Do not expose these methods as a qualified query API.
- Input parsing and derivation remain in memory. Count and serialized-byte
  limits are checked. The full 256-MiB process budget is not qualified for the
  Rust owner. A live implementation requires bounded pages and memory proof.
- The existing e2e `file_effect` module lacked its test-only compile guard.
  [effect.rs](../../../crates/mithril-e2e/src/effect.rs) now uses `cfg(test)`
  for that module, as its sibling platform tests do. No test was removed.
  The existing exception test now uses `contains` for cookie membership to
  satisfy the workspace clippy rule. This change preserves the predicate.

### Verification

Focused command:

```sh
cargo test --offline -p mithril-control -p mithril-e2e discovery -- --nocapture
```

Result: 17 tests passed. The
[Control tests](../../../crates/mithril-control/src/discovery/tests.rs)
cover exact counts, replay, input rejection, CPU interleaving, native Kubernetes
lowering, native compilation/simulation, assessment references, and follow
invalidation. The
[e2e test](../../../crates/mithril-e2e/src/discovery.rs) calls public owners
and checks that a repeated invocation does not overwrite an output directory.
These are synthetic tests, not physical HF acceptance.

The offline binary passed with the final schema and wrote
`/tmp/araphor-discovery-offline-3/result.json`, `input-manifest.json`, and
`snapshot.json`. Earlier output directories do not qualify the final source.

Full command: `bash .github/scripts/verify-rust-ci.sh`.
Result: **Passed**, exit status 0, after the final Rust edit. Formatting,
workspace compilation, all-target/all-feature clippy with warnings denied,
and the full workspace test command passed. The Mithril e2e library reported
94 passed and 152 ignored tests. The ignored platform cases were not run.
This result does not close Mithril 6.2 physical qualification.

The vendored libbpf build required write access to generated files in the
Cargo cache. The full procedure ran with that outer filesystem restriction
removed. The source-linked document check also passed: 27 files and 181 local
links, with no reported errors.

### Storage experiment

The experiment uses pinned Python bindings in
[requirements.txt](../../../crates/mithril-e2e/harness/discovery/requirements.txt).
It adds no production dependency. Reproduce the final full-size run from the
worktree root with a prepared environment and a new output directory:

```sh
uv venv /tmp/araphor-discovery-venv
uv pip install --python /tmp/araphor-discovery-venv/bin/python \
  -r crates/mithril-e2e/harness/discovery/requirements.txt
/tmp/araphor-discovery-venv/bin/python \
  crates/mithril-e2e/harness/discovery/storage_compare.py \
  --manifest crates/mithril-e2e/fixtures/discovery/manifest.json \
  --engines sqlite,duckdb \
  --output-directory /tmp/araphor-discovery-storage
```

This host required permission to start Bubblewrap outside the outer sandbox.
Workers have a separate network namespace, read-only runtime/package mounts,
no Control data mount, an empty environment except required runtime settings,
a 256-MiB address-space cap, and CPU and wall-clock limits. Only an authorized
two-column projection enters the worker. A maintained SQLGlot parser rejects
unapproved syntax, fields, tables, and functions before execution.

Final artifacts: `/tmp/araphor-discovery-storage-million-5/result.json` and
its per-engine directories. The experiment script SHA-256 is
`41aa0d2fd9292b4d2f65c172ec42b2de9df6441d1eb9086241db3daf494e943c`.
Host: x86-64 Linux `6.8.0-139-generic`, Python
3.12.3, CPU affinity 0–3. The host was not an isolated 4-vCPU/8-GiB machine.
Compilation and other work ran concurrently. These are development measurements.
The generated row input contains five 64-bit integers per record: 40,000,000
bytes at one million records. It is not a million full evidence envelopes or
a 256-MiB projected-input test.

| Measured result | SQLite 3.53.4 | DuckDB 1.5.5 |
| --- | --- | --- |
| One million records, 50,000 exact groups | Completed | Engine memory exhausted |
| Ingestion | 5.961 s | No complete result |
| Batch p95 / maximum | 30.966 / 37.816 ms | No complete result |
| Engine-process peak RSS | 105.2 MiB | 166.5 MiB at failure |
| Indexed 200-row page, warm p95 | 0.141 ms | No full-size result |
| Isolated 200-row count, including worker startup | 152.208 ms | No full-size result |
| WAL peak | 1.965 MiB | No complete result |
| Crash before / after commit and count recovery | Passed | No full-size result |
| Derived-table rebuild | 286.070 ms, equal rows | No full-size result |
| Engine page-limit failure | Committed head preserved | Not run |
| Adversarial join | Worker terminated in 1.030 s | No full-size result |

Both engines produced equal input, aggregate, and revision-diff digests in the
10,000-record run at `/tmp/araphor-discovery-storage-small-6/result.json`.
Both passed its before/after-commit recovery and rebuild checks. SQLite alone
ran the engine page-limit probe. Nine forbidden SQL cases were rejected before
worker execution. That case count does not cover the complete query threat matrix.
The small DuckDB adversarial-query worker exited with status 139 after
0.732 s. The worker remained isolated. This result is not a successful query
or a clean engine interruption.

DuckDB exhausted its 64-MiB engine target in both full-size configurations:
default insertion-order preservation and disabled insertion-order preservation.
One engine thread was used. The experiment retains each failure; it does not
replace a failed run with a timing from the smaller input. The
[DuckDB security guide](https://duckdb.org/docs/current/operations_manual/securing_duckdb/overview)
also states why engine settings alone are not an isolation boundary.

Store selection: **Reject both for production selection at this gate**.
SQLite remains the candidate for the next qualification pass. DuckDB failed
the current full-size memory target. SQLite has not passed the pinned Rust
binding, full projection, authorized-view binder, concurrent primary-owner,
and qualified-host repeat-run gates. Do not add a second database or raise a
memory limit silently. A SQLite engine page limit is not a physical disk-full
test.

### Remaining work before Phase 2

1. Freeze the complete labeled corpus, operator-task protocol, HF capability
   map, and defender-loop fixtures. Current tests cover the denied-read
   investigation and selected negative contracts, not that complete corpus.
2. Complete context freshness, provenance, disclosure, method, and known-owner
   reference checks. Test claim support separately from citation membership.
3. Finish SQL binding, full input/output limits, repeated isolated-query
   timings, restart/expiry follow cases, and the full adversarial matrix.
4. Qualify a pinned Rust SQLite binding on the declared host. Measure native
   memory, disk-full/spill, concurrent readers, and primary intake/rollout
   latency. Select an engine only after the complete gate passes.
5. Review the Node context extension and bounded ControlStore export contract.
   Preserve compatibility and the separate source-retention owner. Then rerun
   the complete Rust gate and record Done before starting Phase 2.

### Investigation contract correction

This correction starts from `25618bf4`, after the rebase onto main at
`e59aad20`. It does not change a live owner or grant execution authority.

Read [ContextPacket](../../../crates/mithril-control/src/discovery/investigation.rs)
before `AssessmentReport::validate_against` in the same file. The caller supplies
the sealed input to `validate_evidence`. That method checks the input digest,
tenant, proof kind, cited record membership, intake-time cutoff, and claimed
coverage. `validate_disclosure` compares the complete current disclosure policy,
not its revision alone. The caller must obtain that policy from its authority;
this offline method does not authenticate a client or redact data.

Report validation now rejects empty or unversioned methods, zero method and
receipt digests, contradictory citations in one claim, and unknown references
in suggestion targets, tests, proposals, and response plans. A reference must
occur in the packet's subject, finding, parents, or available owner facts.
An unsupported response stays unsupported. A draft never becomes an approval.

The [contract tests](../../../crates/mithril-control/src/discovery/tests.rs)
include a valid citation with an unsupported provider-use claim. Structural
validation accepts the citation; the fixture's provider-audit gap refutes the
claim of support. Do not treat structural validity as semantic verification.
Owner-document validity and provenance remain part of the context work below.

Focused verification: `cargo test --offline -p mithril-control discovery:: --
--nocapture` passed 19 tests. `bash .github/scripts/verify-rust-ci.sh` passed
after the last Rust edit. The e2e library passed 94 tests and did not run 156
physical tests. The Node library passed 243 tests. Result for this contract
correction: **Done**. The complete phase remains **Not done**.
