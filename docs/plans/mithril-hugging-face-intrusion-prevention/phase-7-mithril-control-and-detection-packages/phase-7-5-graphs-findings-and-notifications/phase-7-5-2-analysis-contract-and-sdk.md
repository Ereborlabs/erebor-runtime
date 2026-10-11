# Phase 7.5.2: Analysis Contract And SDK

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

- [ ] `AR-01`: exact behavior-atom derivation, counts, evidence samples, and
  unresolved, excluded, coverage, and lifecycle accounting.
- [ ] `AR-02`: behavior snapshot merge and deterministic display grouping.
- [ ] `AR-03`: reviewed-baseline comparison for added and removed behavior,
  count, outcome and identity changes, new resources, forbidden groups, coverage,
  and lifecycle changes.
- [ ] `AR-04`: context selection and its cutoff, ordering, conflict, omission,
  and missing-fact behavior through the SDK input contract. Authorization and
  trusted context selection remain shared host operations.
- [ ] `AR-05`: `HF-PROC-001` process and file findings, qualified relationships,
  effect interpretation, and contextual outside-authority, in-memory, and
  unobservable-payload classifications.
- [ ] `AR-06`: `HF-DW-001` credential and local-channel correlation, including
  contextual-only results and missing-proof outcomes.
- [ ] `AR-07`: the implemented `HF-XNODE-001` request, audit, object, scheduling,
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

**Not done** for the extended phase. All seven algorithm migration items and
their production adapters and equivalence checks remain to be implemented.
The portable SDK result below remains **Done**. Its earlier checks do not prove
the added migration scope or satisfy the entry gate for 7.5.3.

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

Installation, production graph-to-SDK adapters, executable target bindings,
and current algorithm migration remain **Not done**. Native/Wasm declaration
syntax does not qualify execution, isolation, or ABI behavior. Upstream ports,
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
