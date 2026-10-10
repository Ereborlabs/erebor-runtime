# Phase 7.5.2: Analysis Contract And SDK

Give authors one typed interface for reusable algorithms and detectors. Hide
execution bindings behind an SDK. Parent: [7.5](README.md). Require 7.5.1.

## Intended end state

An author defines inputs, parameters, outputs, and checkpoint types once. A
model can consume several datasets and return several datasets with different
row counts. Another model can use its named output. The same descriptor supplies
validation, package inspection, generated bindings, and agent descriptions.

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
   typed details. Test their mapping to current findings. Keep existing graph
   dispatch operational. Phase 7.5.3 connects descriptor validation to admission;
   7.5.4 replaces detector dispatch when compiled packages can run. Preserve
   host-owned identity, coverage, authority, and proof checks throughout.
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
phase proves the portable interface and author tests without package activation.

The [SDK guide](../../../../../crates/araphor-analysis-sdk/README.md) specifies
the Arrow schemas, precision, ordering, evidence, checkpoint, and bound rules.
The [source review](analysis-contract-review.md) links each implemented owner
and identifies the runtime interfaces that remain declarations.

## Acceptance and verification

Use Rust contract tests for multiple inputs, variable output counts, invalid
schemas, missing evidence, reason namespaces, checkpoint versions, and descriptor
generation. Build a small SDK fixture without host crates. Verify that inspection
does not load executable code into Control. Runtime builds and execution are
qualified in 7.5.4 and 7.5.5. Run the shared Rust procedure after source changes.

## Exclusions and stop point

Add no new query language, compiler service, policy authority, or mandatory
Python dependency. The SDK does not enforce host permissions. Stop at a tested
contract and authoring interface before package activation.

## Result

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

The final shared Rust procedure passes on `ca8de3ae`, after the last Rust edit:

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

## End scope and example

Complete when the source inventory covers the contract requirements, the Rust
SDK generates consistent descriptors and interface declarations, and portable
fixture tests validate inputs, outputs, evidence, and state. Existing detectors
still run through their current dispatch. Package installation comes in 7.5.3.

Example at completion: an author defines a Rust `files.count` export with typed
event input and subject/count output. Inspection reports those same types. A
local fixture with three distinct file events returns count `3`; input without
the required subject identity fails validation. This does not yet run a Wasm
component or install a detector into Control.
