# Phase 7.5.4: Wasm Execution And Current Algorithm Migration

Run portable compiled algorithms in an embedded Wasmtime component host.
Parent: [7.5](README.md). Require 7.5.3.

## Intended end state

An operator installs a built component without a compiler, interpreter, or
separate service. Rust SDK packages use this target by default. The host applies
the same input, output, evidence, checkpoint, and retry rules as SQL models.

## Implementation flow

```text
Package admission selects a component artifact
  -> the execution owner checks its contract version, imports, and declared features
  -> Wasmtime validates and prepares the component under compilation limits
  -> the package owner records target compatibility before activation

The scheduler invokes an admitted export
  -> the host creates an evaluation instance with explicit limits and authorized inputs
  -> generated WIT bindings transfer bounded batches and the prior checkpoint
  -> the component returns declared outputs, evidence references, and next checkpoint
  -> host validation passes the complete result to the existing commit path
  -> the execution owner releases the instance and temporary buffers

The component traps, exceeds a limit, or receives cancellation
  -> the host interrupts execution and cancels pending host work
  -> the host discards uncommitted output and releases resources
  -> the package owner records incomplete coverage without changing committed state
```

## Scope and owners

Keep the Wasmtime adapter under the `araphor-data` package execution owner.
The SDK owns generated component bindings, not permissions or durable state.
Pin and qualify the Wasmtime, component, and binding versions together.
Complete the SDK component artifact build and generated bindings in this phase.
Connect the descriptors from 7.5.2 to the admission owner from 7.5.3. Replace
fixed graph package dispatch and its ID allowlist only after the built-in
packages pass migration checks. Existing host validation remains mandatory.
General package results must retain declared namespaced reason codes and typed
details. The current eleven-reason enum is a compatibility mapping for existing
HF findings. Do not require a new host enum variant for each installed detector.
Preserve historical finding JSON and all host evidence and authority checks.

- Permit only versioned analysis imports. Do not inherit ambient filesystem,
  network, environment, wall-clock, or random access. Supply recorded evaluation
  time and seed through the contract when the algorithm needs them.
- Use bounded typed batches, with Arrow IPC for table payloads and WIT for
  lifecycle and control values. Specify the supported Arrow types. Account for
  copies, decoding, input, output, and checkpoint memory; claim no zero-copy path.
- Bound compilation, linear memory, tables, CPU work, wall time, host calls,
  output, state, and concurrency. Wasmtime fuel and interruption do not replace
  limits on work performed by host imports.
- Cache compiled code by exact artifact and compatible host configuration under
  a bounded cache. Do not share mutable evaluation state across scopes. Treat
  precompiled artifacts as host-generated executable material with checked origin.
- Migrate the current discovery and detection algorithms listed below through
  the same contract without a second implementation. Preserve results, evidence,
  revisions, and notification behavior. Unsupported component features produce
  an explicit error.

### Current algorithm migration

This phase owns implementation of the complete Araphor migration. The
[source inventory](algorithm-coverage.md#current-araphor-algorithms) gives the
source entry points and boundaries for each item:

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

Package code owns reusable computation. `DiscoveryOwner` and
`GraphAndFindingOwner` retain input authorization, identity, coverage and proof
validation, graph assembly, and output checks. AnalysisStore retains commits.
Do not put these trust decisions under package control. Share the existing
computation code between SDK targets and remove the old production dispatch
after equivalence checks pass. Keep module and function boundaries focused.

## Acceptance and verification

Use real components in Rust tests for batch boundaries, multiple inputs, graph
traversal, recursion limits, variable output counts, checkpoints, and replay.
Reject undeclared imports, excessive memory/output, invalid evidence, and
incompatible interfaces. Exercise traps, CPU loops, host-call cancellation, and
scope isolation. Extend `analysis-packages` with a new Rust detector installed
without rebuilding Araphor. Run final shared Rust verification.

Capture expected results from the current algorithms before migration. Check
every `AR-*` item against those results, including negative, missing-input,
duplicate, conflicting, late, expiry, and replay cases. Run `context-roundtrip`,
`profile-restart`, and `graph-notification` through the migrated production path.
No item can remain on a hidden legacy execution path. Phase 7.5.5 adds native
target parity; 7.5.7 verifies the completed migration across owners.
AR-04 is complete when packages use the shared authorized context selector and
its integration tests pass. The selector remains a host operation; it is not
an omitted migration or a plugin-owned authorization decision.

## Exclusions and stop point

Do not require Python-to-Wasm or assume native Python wheels are compatible.
Do not adopt a gadget loader or run detector code on the kernel enforcement
path. Performance is unqualified; benchmark approval must name the workload,
runtime, and limits before a performance test is added. Stop before native work.

## Result

**Not done.** Wasmtime integration, all seven migration items, isolation tests,
and runtime compatibility remain to be implemented and verified.

## End scope and example

Complete when built Wasm packages run through the production lifecycle and
every `AR-01` through `AR-07` migration item passes. Existing discovery and HF
detectors use the package contract; the shared context and proof owners still
enforce their checks. Native execution follows in 7.5.5. Full upstream algorithm
development follows in 7.5.8 and 7.5.9.

Example at completion: replay the existing protected-file fixture through the
installed `HF-PROC-001` package. It returns the same finding, evidence references,
coverage limits, and notification behavior as the prior implementation. Remove
required coverage and the package retains the expected incomplete result. The
kernel policy causes the denial; package evaluation reports its evidence.
