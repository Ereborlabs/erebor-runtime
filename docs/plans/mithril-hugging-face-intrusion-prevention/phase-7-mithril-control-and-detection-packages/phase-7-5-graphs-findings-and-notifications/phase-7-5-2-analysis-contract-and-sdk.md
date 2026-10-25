# Phase 7.5.2: Analysis Contract And SDK

Current command status, 2026-10-19: The old Analysis owner and its qualification
harness have been removed. The cases `profile-restart`, `context-roundtrip`, `graph-notification`
are no longer accepted by `mithril_discovery_test`. The commands and results
below remain historical proof for their recorded source. They do not qualify
the current replacement. Read the [current plan](../../../araphor-package-jobs.md)
for the supported path and remaining work.

Give authors one typed interface for reusable algorithms and detectors. Hide
execution bindings behind an SDK. Move current algorithms into shared SDK code
before package installation or Wasm execution. Parent: [7.5](README.md).
Require 7.5.1.

## Intended end state

An author defines inputs, parameters, outputs, and checkpoint types once. A
model can consume several datasets and return several datasets with different
row counts. Another model can use its named output. The same descriptor supplies
validation, package inspection, generated bindings, and agent descriptions.
Existing production owners call the same SDK-compatible computation through
ordinary Rust calls. Findings, evidence, coverage, checkpoints, and notifications
retain their current behavior. These calls use trusted built-in code.

## Implementation flow

```text
Author builds a Rust analysis package
  -> the SDK checks declared model interfaces and generates the descriptor
  -> the SDK generates versioned WIT and native interface declarations
  -> the local Rust fixture runner checks the portable computation contract

Author tests an export against fixtures
  -> the SDK supplies typed inputs, evaluation context, and prior checkpoint
  -> ordinary algorithm code returns datasets, evidence references, and next checkpoint
  -> shared contract validation checks the declared outputs and limits
  -> the test result identifies the export, implementation, and fixture revisions

An export returns an invalid schema, reference, or checkpoint
  -> validation rejects the complete result with a structured reason
  -> no durable result or progress is committed

An existing discovery or graph owner evaluates accepted input
  -> the owner authorizes and freezes the exact input revisions and context
  -> the shared adapter supplies bounded SDK datasets and closes durable readers
  -> the owner calls the shared built-in Rust algorithm through the SDK contract
  -> the owner validates output, identity, coverage, proof, and evidence references
  -> AnalysisStore commits through the existing production path
  -> NotificationRouter retains required routes and deadlines

The built-in evaluation fails or its input expires
  -> the owner discards uncommitted output and retains the last complete commit
  -> the existing owner records the failure or incomplete coverage
  -> retry uses the existing replay and commit rules
```

## Scope and owners

Use the `araphor-analysis-sdk` crate for portable authoring types, binding
generation, and fixture support. It must not depend on Control, DuckDB, or the
host store. `araphor-data` retains host validation. Share portable contract checks
without making SDK use a condition for accepting a valid implementation.

1. Define package identity, export name, contract version, dataset schemas,
   parameter schema, required evidence, output kinds, and checkpoint version.
   Add structured errors for incompatible, unauthorized, incomplete, and failed
   evaluations. Keep computations in code or SQL, not in descriptor fields.
2. Define bounded batch inputs, exact input revisions, source windows, evaluation
   time, coverage, and any random seed. Define integer and timestamp precision,
   missing values, ordering, and permitted numeric tolerance. Do not use the
   client SQL display limit to truncate internal inputs.
3. Use [WIT](https://component-model.bytecodealliance.org/design/wit.html) and
   generated bindings for the component boundary. Keep the native binary binding
   separate; both implement this analysis contract. Rust is the first SDK.
   Other languages can use the versioned interface without a new host contract.
4. Define descriptors for existing package IDs, namespaced reason codes, and
   typed details. Test their mapping to current findings. Change existing graph
   dispatch to call the shared SDK computation. Phase 7.5.3 connects descriptor
   validation to admission; 7.5.4 replaces built-in dispatch with installed
   component execution. Preserve host-owned identity, coverage, authority, and
   proof checks throughout.
5. Define build, inspect, and test operations. A directory can contain a generated
   descriptor, source, built artifacts, dependency lock, and fixtures. Operators
   need only built artifacts and the locked closure. No build runs during install.
6. Expand the [algorithm inventory](algorithm-coverage.md) into source algorithms,
   variants, and delegated operations before freezing the contract. Include
   existing discovery and detectors, recursive path aggregation,
   network and policy candidates, rule aggregates, time joins, correlation
   vectors, and threat-indicator matching. Identify each required input, output,
   state type, host check, and target constraint. Resolve contract gaps here;
   7.5.8 and 7.5.9 implement and verify the upstream algorithms later. Record the
   package exports that each later phase must deliver. A few examples cannot
   establish coverage of the requested algorithms.

Target artifact builds and execution adapters belong to 7.5.4 and 7.5.5. This
phase owns the production input/output adapters and direct Rust calls through
the portable interface. It does not activate installed packages.

The [SDK guide](../../../../../crates/araphor-analysis-sdk/README.md) specifies
the Arrow schemas, precision, ordering, evidence, checkpoint, and bound rules.
The [source review](analysis-contract-review.md) links each implemented owner
and identifies the runtime interfaces that remain declarations.

### Current algorithm migration

This follow-up uses the completed portable SDK. Complete it before 7.5.3.
The [source inventory](algorithm-coverage.md#current-araphor-algorithms) and
[contract records](current-contract-inventory.md) give each source entry point,
variant, export, and host boundary:

- [x] `AR-01`: exact behavior-atom derivation, counts, evidence samples, and
  unresolved, excluded, coverage, and lifecycle accounting.
- [x] `AR-02`: behavior snapshot merge and deterministic display grouping.
- [x] `AR-03`: reviewed-baseline comparison for added and removed behavior,
  count, outcome and identity changes, new resources, forbidden groups, coverage,
  and lifecycle changes.
- [x] `AR-04`: context selection and its cutoff, ordering, conflict, omission,
  and missing-fact behavior through the SDK input contract. Authorization and
  trusted context selection remain shared host operations.
- [x] `AR-05`: `HF-PROC-001` process and file findings, qualified relationships,
  effect interpretation, and contextual outside-authority, in-memory, and
  unobservable-payload classifications.
- [x] `AR-06`: `HF-DW-001` credential and local-channel correlation, including
  contextual-only results and missing-proof outcomes.
- [x] `AR-07`: the implemented `HF-XNODE-001` request, audit, object, scheduling,
  and remote-admission state handling. Preserve its unqualified cross-node
  causality result; migration adds no new physical proof.

Move reusable computation into focused package modules with one implementation
per algorithm. Existing production callers and SDK fixtures must call that same
code. Remove replaced computation after equivalence checks pass. Retain built-in
selection until 7.5.4 supplies installed component execution. Direct calls do not
load external code and do not implement the native plugin runtime from 7.5.5.

`DiscoveryOwner` and `GraphAndFindingOwner` retain input authorization, identity,
coverage and proof validation, graph assembly, and output checks. AnalysisStore
retains commits. AR-04 uses the shared authorized selector; packages cannot
replace that trust decision. Preserve historical reason codes, finding JSON,
evidence references, and notification behavior. Keep the SDK independent of
Control, DuckDB, and the host store.

Supply production adapters for authorized inputs, selected native graph rows,
domain outputs, and checkpoints. Reuse bounded extraction and row selection.
Preserve complete identities, exact versions, source windows, empty replacement
versions, traversal limits, and evidence row references across batches. Close
durable readers before computation. Share these adapters with later execution
targets; transport bindings must not contain another algorithm implementation.

## Acceptance and verification

Use Rust contract tests for multiple inputs, variable output counts, invalid
schemas, missing evidence, reason namespaces, checkpoint versions, and descriptor
generation. Build a small SDK fixture without host crates. Verify that inspection
does not load executable code into Control. Runtime builds and execution are
qualified in 7.5.4 and 7.5.5. Run the shared Rust procedure after source changes.

Test detector authoring with two named inputs, exact baseline membership,
findings, typed reasons, and event evidence. Include zero findings, evidence
across batches, incomplete baseline coverage, empty baseline revisions, and
input reordering. Test selected Arrow ranges and parent null masks. Selected
graph tests must compute from subjects, relationships, and the version manifest;
assertions must inspect the returned computation.

Capture expected results from the current algorithms before changing them.
Check every `AR-*` item and its inventory variants against those results. Include
negative, missing-input, duplicate, conflicting, late, expiry, and replay cases.
Check exact findings, reasons, evidence, coverage, revisions, and checkpoints.
Run `context-roundtrip`, `profile-restart`, and `graph-notification` through the
production owners that call the shared SDK computation. No migrated item can
retain a separate production implementation. AR-04 requires host selector
integration tests. Record per-item results and run the final shared Rust gate.
These checks prove computation and host integration. Installed execution and
isolation checks remain in 7.5.4 and 7.5.5.

## Exclusions and stop point

Add no new query language, compiler service, policy authority, or mandatory
Python dependency. The SDK does not enforce host permissions. Stop at a tested
contract, authoring interface, and current algorithms used by trusted production
Rust callers. Package installation and executable target loading remain later
work. Do not add a temporary plugin runtime to complete this migration.

## Result

**Done** for the complete phase. All seven current algorithm items use shared
SDK computation or the shared host context selector through production adapters.
The captured results, production qualification, and final shared Rust procedure
pass. The earlier portable SDK result remains **Done**. Read the
[migration result](#current-algorithm-migration-result) for source and proof.

### Portable SDK result

**Done** for the portable contract, Rust author SDK, interface declarations,
and local fixture tests. SDK commit `c85be1d7` adds the shared types, validation,
build, inspect, test, and `files.count` example. Host commit `412c001b` declares
the three current HF interfaces and preserves host validation during reason
conversion. Commit `ca8de3ae` brings test names within repository limits.
Existing detector dispatch remains operational.

The source requirements audit covers current discovery and HF algorithms,
Discovery Engine at `0b5b73425c5aec89b803e737b188b2a331d0e218`, and Security
Analytics at `e33c62506efcb15ae795847484357704b539bcf1`. Read the linked
[inventory](algorithm-coverage.md) for variants, delegated operations, state,
host checks, target constraints, and the required later exports. This audit
does not claim upstream algorithm execution or equivalence.

The initial shared Rust procedure passes on `ca8de3ae`, after its last Rust edit:

```sh
RUST_TEST_THREADS=4 bash .github/scripts/verify-rust-ci.sh
```

Qualified platform: Linux x86_64, Rust `1.97.1`. Formatting, workspace check,
strict Clippy, and the complete workspace test command return zero. The SDK
reports 21 passed, including WIT parsing and C header compilation. Araphor Data
reports 394 passed and three ignored; this includes the three host contract
tests. Mithril E2E reports 171 passed and 526 ignored. Ignored tests supply no
qualification. Read `/tmp/araphor-analysis-rust-ci-bounded.log`, with SHA-256
`30be5889b9ee299938b03581b6f4d471f04c184d463a27a7e93c6d652d448993`.

The earlier default-concurrency run fails `control_graph_overlap_expiry` with
`AnalysisReadDeadline` at `analysis/read.rs:161`. That existing case passes
alone and in the final four-thread run. The timeout cause is unproven. No test
assertion or production deadline changed. Read
`/tmp/araphor-analysis-rust-ci-final.log` for the earlier failure.

The standalone `files.count` example returns count `3`. Read
`/tmp/araphor-files-count-run.log`. Normal SDK dependencies contain no Control,
DuckDB, or host store. Selected graph relation fixtures retain full identities,
all selected versions, empty replacements, and traversal boundary state.

At that source, installation, production graph-to-SDK adapters, executable
target bindings, and current algorithm migration remained **Not done**.
Native/Wasm declaration syntax does not qualify execution, isolation, or ABI
behavior. Upstream ports,
physical incident prevention, and performance are not qualified here.

### Review corrections

| Item | Result and code |
| --- | --- |
| Selected Arrow values | **Done**, `cb936bd`. Finite checks apply list offsets and parent null masks. Physical Arrow validation and allocation bounds remain in place. Required `Null` fields fail recursive schema validation. Five Rust regressions cover these cases. |
| Graph computation fixture | **Done**, `d00fd54`. The computation consumes subjects, relationships, and the manifest. It joins endpoints within each graph version and returns counts. Assertions check output identities, exact versions, windows, empty replacements, and hop state. A lower row bound rejects before execution. |
| Detector author workflow | **Done**, `fadacd5`. The sensitive-access example returns findings, typed reasons, and event evidence against an exact baseline. Seven Rust tests cover matches, zero findings, evidence across batches, incomplete and empty baselines, and named input lookup. |

The author interface retains one descriptor, Arrow schemas, a Rust function,
and ordinary Rust tests. `Evaluation::input` selects inputs by name. Arrow
errors convert with `?` and retain their source. The examples share these
operations. This correction adds no dependency, rule language, or algorithm
trait. The native declaration now requires the return error code to equal
`response.error.code`; target execution is still outside this result.

Focused verification passes 33 SDK tests and three current host contract tests.
The standalone `sensitive_access` example returns two findings. The four-thread
workspace procedure on `2b9fe8c` passes formatting, workspace check, and strict
Clippy. The data suite reports 393 passed, one failed, and three ignored.
`native_traversal_large_graph` fails with `AnalysisReadDeadline` at
`analysis/read.rs:161`; the unchanged case then passes alone in 77.99 seconds.
The failing stage and the timeout cause remain unproven. Read
`/tmp/araphor-sdk-fixes-rust-ci-final.log` and
`/tmp/araphor-sdk-large-graph-isolated.log`.

The final complete workspace procedure **passes** on `2b9fe8c`:

```sh
RUST_TEST_THREADS=1 bash .github/scripts/verify-rust-ci.sh
```

Qualified platform: Linux x86_64, Rust `1.97.1`. Formatting, workspace check,
strict Clippy, and the complete test command return zero. The SDK reports 33
passed; Araphor Data reports 394 passed and three ignored. Mithril E2E reports
171 passed and 526 ignored. Node reports 282 passed and one ignored. Ignored
tests supply no qualification. Read `/tmp/araphor-sdk-fixes-rust-ci-serial.log`,
with SHA-256
`cfe4bc907b4db440dd490d2455d440a4fc417a10d526429e85477f47014cae1d`.

The serial rerun uses the same source as the four-thread run. No deadline or
assertion changed between those runs. Commit `2b9fe8c` replaces test unwraps and
explicit panics with propagated errors and an execution flag. The four-thread
deadline failure remains recorded above. This serial pass does not qualify
parallel timing or performance. All review corrections are **Done** within the
portable contract and authoring scope.

### Current algorithm migration result

**Done** for AR-01 through AR-07, production adapters, and equivalence through
trusted Rust calls. The final shared Rust procedure and all three required
production qualification cases pass on `53f7674`.

Baseline commit: `2e49839a` captures the original results before computation
changes. Seven Rust tests compare 24 outputs. The expected JSON files remain
unchanged. Computation commit: `2892f27`. Native graph adapter commit: `53f7674`.

The new `araphor-analysis-builtins` crate contains the shared discovery and HF
computations. It depends on the portable SDK and has no Control, DuckDB, or host
store dependency. Production owners call this code through validated SDK
evaluations. Portable fixtures call the same code. The replaced host computation
is removed. Host owners retain authorization, proof, identity construction,
domain result validation, graph assembly, atomic commits, and notifications.

| Item | Shared computation and production owner | Captured and semantic checks |
| --- | --- | --- |
| AR-01 | `discovery/atoms.rs` and `discovery/ranges.rs` in the shared crate. `DiscoveryOwner::derive_recorded` in `araphor-data/src/discovery/sdk/atoms.rs` supplies normalized rows and reconstructs the recorded result. | `discovery_atoms_baseline` checks the original and missing-context results. Existing replay, conflicting-input, distinct-key, missing-generation, disposition, lifecycle, and corpus tests remain in `discovery/derive.rs`. Portable `sdk_derivation_fixture`, `sdk_conflicting_record`, and `sdk_bounded_derivation` test the same computation. Host `duplicate_context_projection` and `discovery_exact_revision` check repeated records and content-bound revisions. |
| AR-02 | Shared `discovery/merge.rs`, `ranges.rs`, and `groups.rs`. `BehaviorSnapshotV1::merge` and `display_groups` in `discovery/sdk/snapshot.rs` retain domain ordering and exact references. | `discovery_merge_baseline` checks the merged snapshot and groups. `discovery_derivation_page_merge`, `discovery_derivation_lifecycle_schema`, and `discovery_derivation_corpus_parity` check page boundaries, lifecycle state, and corpus results. |
| AR-03 | Shared `discovery/compare.rs`. `BehaviorSnapshotV1::compare` in `discovery/sdk/compare.rs` retains reviewed-baseline validation and reconstructs comparison rows. | `discovery_compare_baseline` checks count, outcome, and identity changes. `discovery_comparison_reviewed_changes` and corpus parity check additions, removals, resources, forbidden groups, coverage, and lifecycle changes. |
| AR-04 | `DiscoveryOwner::select_context` remains the trusted host selector in `discovery/context.rs`. `context_input` in `discovery/sdk/context.rs` supplies its selected packet through the SDK input contract. | `discovery_context_baseline` checks initial, later, conflicting, missing, and denied context. Existing context tests cover cutoff, order, history, sensitivity, omissions, and quotas. `context_sdk_packet`, `context_sdk_metadata`, and `context_sdk_version` check conversion and reject inconsistent metadata or an unsupported selector version. The existing roundtrip calls the supported API through `mithril-e2e/src/discovery/roundtrip/context.rs`. |
| AR-05 | Shared `graph/process.rs`. `GraphAndFindingOwner::derive` in `araphor-data/src/graph/derive.rs` calls the SDK export. `graph/derive/adapter` supplies qualified input and assembles checked domain output. | `graph_native_baseline` checks protected, gapped, and missing-lifetime results. Existing `control_graph_denial_and_missing_lifetime`, `control_graph_accepted_physical_results_keep_stage_semantics`, and `control_graph_native_parent_is_exact_and_local` retain the host semantics. Portable `process_replay_checkpoint`, `process_context_classifications`, and `fact_reference_is_exact` check shared computation, state, and references. |
| AR-06 | Shared `graph/credential/mod.rs` and `graph/credential/join.rs`. Host `graph/derive/adapter/credential.rs` and `authority.rs` normalize retained source and qualified authority facts. | `graph_credential_baseline` checks direct, contextual, and missing-proof results. Existing read/channel/provider, same-operation contradiction, credential conflict, mmap, shared-principal, and window-boundary tests retain the identity and physical-stage distinctions. Portable `credential_exact_and_missing` checks the shared computation. |
| AR-07 | Shared `graph/kubernetes.rs`. Host `graph/derive/adapter/facts.rs` supplies qualified stage facts; the shared graph output adapter reconstructs results. | `graph_kubernetes_baseline` checks six request-to-admission stages. `control_graph_kubernetes_preserves_partial_stages` and portable `kubernetes_retains_missing_proof` retain incomplete stages and unqualified cross-node causality. |

Full source links and the variant inventory are in
[the current implementation map](current-contract-inventory.md#current-implementation-map).
The seven baseline tests are in `discovery/derive/tests/baseline.rs`,
`discovery/context/tests/baseline.rs`, and `graph/tests/baseline.rs` under
`araphor-data/src`. Portable tests are in the shared crate's
`discovery/tests.rs` and `graph/tests.rs`.

The graph output adapter requires one matching formal SDK reason per finding,
equal typed details, and equal evidence references. Its tests
`candidate_reason_matches_contract`, `candidate_requires_host_validation`,
`candidate_reason_is_exact`, and `candidate_evidence_is_exact` reject invalid
output before the owner accepts a result. Existing graph tests retain byte-identical replay,
late input, expiry, restart, failed commit, recovery, and checkpoint behavior.

`QueryOwner::graph_inputs` in `araphor-data/src/query/analysis.rs` supplies native
subjects, relationships, and one manifest row per selected graph version. It
uses the existing native traversal and whole-version checks. It retains empty
replacement versions, exact result identities, sensitivity, cancellation, scan
bounds, and the traversal receipt. Durable readers close before computation.
The returned owner holds the reservation while consumers use its Arrow buffers.
The five `graph_sdk_*` tests in `query/analysis/tests.rs` run the typed join in
`query/analysis/tests/computation.rs`. They check computation results, historical
access, empty replacements, authorization scope, sensitivity, bounds, and
cancellation. The SQL display limit does not truncate these inputs.

The context roundtrip calls `context_input` with its retained qualified record
and binding. It checks exact selected identities, method, cutoff, the SDK row,
and missing source-health evidence. A cutoff before receipt removes the record,
records its omission, changes the exact revision, and reports missing qualified
subject evidence. This is a supported host API integration; no existing live
context-selector caller was replaced.

### Migration verification

The focused checks below pass. The final shared Rust procedure covers all Rust
source, tests, and Cargo changes in `53f7674`.

| Check | Result and evidence |
| --- | --- |
| Discovery host regressions | **Done:** 42 passed, zero failed or ignored. Includes the four discovery/context baseline tests and the new context, duplicate, and revision tests. Log: `/tmp/araphor-sdk-migration-discovery.log`. |
| Graph host regressions | **Done:** 44 passed, zero failed or ignored. Includes the three graph baseline tests, recovery, replay, and native traversal regressions. Log: `/tmp/araphor-sdk-migration-graph.log`. This filter does not include `graph::derive::adapter::tests`. |
| Portable computations and output adapter tests | **Done:** 12 portable tests pass in `/tmp/araphor-builtins-final.log`; four output adapter tests pass in `/tmp/araphor-sdk-output-final.log`. |
| Native graph SDK inputs and SQL regressions | **Done:** 141 query tests pass, including all five `graph_sdk_*` tests. Log: `/tmp/araphor-sdk-migration-query.log`. |
| `context-roundtrip` | **Done:** `PASS`, lightweight qualification. Artifact: `/tmp/araphor-sdk-migration-context-final/result.json`. |
| `profile-restart` | **Done:** `PASS`, lightweight qualification. Artifact: `/tmp/araphor-sdk-migration-profile/result.json`. |
| `graph-notification` | **Done:** `PASS`, lightweight qualification. Artifact: `/tmp/araphor-sdk-migration-notification-final/result.json`. Canonical replay and transaction failure checks pass; cross-node causality remains unqualified. |
| Final shared Rust procedure | **Done:** formatting, workspace check, strict Clippy, and the complete workspace test command return zero on `53f7674`. Command: `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=1 bash .github/scripts/verify-rust-ci.sh`. Log: `/tmp/araphor-sdk-migration-rust-ci.log`. |

Qualified platform: Linux x86_64, Rust `1.97.1`. Final suite counts: shared
computation 12 passed; SDK 33 passed; Araphor Data 415 passed and three ignored;
Control 182 passed and one ignored; Mithril E2E 171 passed and 526 ignored; Node
282 passed and one ignored. There are no failed tests. Ignored tests supply no
qualification. Serial tests do not qualify parallel timing or performance.
The complete log SHA-256 is
`c975f1ec1cf29ec6b978a6346bf28fc5e414affefdc6922038fa690e6aaa172a`.

The three production cases use the executable built from `53f7674`:

```sh
cargo run -p mithril-e2e --bin mithril_discovery_test -- --case profile-restart --output-directory /tmp/araphor-sdk-migration-profile
target/debug/mithril_discovery_test --case context-roundtrip --output-directory /tmp/araphor-sdk-migration-context-final
target/debug/mithril_discovery_test --case graph-notification --output-directory /tmp/araphor-sdk-migration-notification-final
```

Result artifact SHA-256 values, in that order:

```text
de1610ad088e675e76d77fc2a23fd66f117b3f0bca3daeb55fbd1c53fc3a599d
2bce4ec8831d151a9f4bd2caa3cec501e771292b1224ee7db6adda5880aba0e9
81c920c590f8bb48a87e7166418c3f5b81d1374203e0489b4574a9eb05c9c983
```

The first workspace test build stopped with `No space left on device` after
formatting, workspace check, and strict Clippy passed. Its log is
`/tmp/araphor-sdk-migration-rust-ci-space.log`. The concurrent
`graph-notification` case stopped at the filesystem reserve check; its log is
`/tmp/araphor-sdk-migration-notification.log`. Old generated build artifacts
were removed. Both checks were restarted on the same source. No source, deadline,
or assertion changed for the retry.

These checks qualify trusted native computation and its host integration.
Installation, installed dispatch, Wasm execution, the external native runtime,
isolation, upstream algorithm ports, new physical incident prevention, and
performance remain outside this result. Existing cross-node causality remains
unqualified. The migration grants no response authority.

Discovery inputs retain exact cursor ranges in coverage rows. They can contain
several streams and have no single UTC source window. Their SDK window is absent,
evaluation time is zero, and aggregate coverage is Unknown. The computations use
the detailed coverage rows. The context packet separately retains its exact UTC
window and cutoff. Invocation revisions bind complete original inputs through
streamed hashing.

## End scope and example

Complete when the source inventory covers the contract requirements, the Rust
SDK generates consistent descriptors and interface declarations, and portable
fixture tests validate inputs, outputs, evidence, and state. Every `AR-01` through
`AR-07` migration item must also pass through the shared SDK computation and
existing production owners. Built-in dispatch selects that code until installed
Wasm execution is qualified in 7.5.4. Package installation comes in 7.5.3.

Example at completion: an author defines a Rust `files.count` export with typed
event input and subject/count output. Inspection reports those same types. A
local fixture with three distinct file events returns count `3`; input without
the required subject identity fails validation. This does not yet run a Wasm
component or install a detector into Control.

Detector example at completion: `access.detect` compares sensitive-read events
with an exact baseline. A new subject/resource pair produces a finding with an
`OUTSIDE_BASELINE` reason and evidence to the observed event. An incomplete
baseline returns `Incomplete`. The author uses one package descriptor, Arrow
types, a Rust function, and ordinary Rust tests. Installation and preventive
action remain outside this scope.

Migration example at completion: the existing protected-file replay calls the
shared `HF-PROC-001` Rust export through the production graph owner. It returns
the same finding, evidence, coverage limits, and notification behavior as the
captured result. Missing coverage retains the incomplete result. This check
requires no Wasm runtime or installed package.


## Native redesign review on 2026-10-25

Result: **Done** for the required native replacement.
Read the [current owner map](../../../araphor-component-redesign.md#required-native-redesign-result)
and [focused proof](../../../araphor-analysis-migration.md#one-managed-graph-execution-route).
Earlier commands, versions, results, and limits apply to their recorded source.
