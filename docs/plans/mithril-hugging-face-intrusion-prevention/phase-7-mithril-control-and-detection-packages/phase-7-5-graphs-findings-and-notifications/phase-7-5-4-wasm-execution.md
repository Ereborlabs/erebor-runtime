# Phase 7.5.4: Wasm Execution

Run portable compiled algorithms in an embedded Wasmtime component host.
Parent: [7.5](README.md). Require 7.5.3.
Current algorithms and production input/output adapters must already pass the
7.5.2 migration checks. This phase changes their execution target and dispatch.

## Intended end state

An operator installs a built component without a compiler, interpreter, or
separate service. Rust SDK packages use this target by default. The host applies
the same input, output, evidence, checkpoint, and retry rules as SQL models.
Current algorithms run as installed components from the shared source used by
the trusted Rust callers in 7.5.2.

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
packages pass installed-component equivalence checks. Reuse the production
input/output adapters from 7.5.2. Existing host validation remains mandatory.
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
- Build the current discovery and detection algorithms from the shared source
  delivered in 7.5.2. Preserve results, evidence, revisions, and notification
  behavior through installed execution. Unsupported component features produce
  an explicit error. Do not fall back silently to built-in execution.

### Current algorithm migration

The [7.5.2 migration checklist](phase-7-5-2-analysis-contract-and-sdk.md#current-algorithm-migration)
owns algorithm conversion, production adapters, and direct Rust equivalence for
`AR-01` through `AR-07`. This phase owns their installed Wasm execution and the
production dispatch change. Use the same source, contract, and captured results.
The [source inventory](algorithm-coverage.md#current-araphor-algorithms) retains
the algorithm variants and host boundaries. Record runtime proof for every item.

Package code owns reusable computation. `DiscoveryOwner` and
`GraphAndFindingOwner` retain input authorization, identity, coverage and proof
validation, graph assembly, and output checks. AnalysisStore retains commits.
Do not put these trust decisions under package control. Share the existing
computation code between SDK targets and remove the built-in production dispatch
after installed-component equivalence checks pass. Keep module and function
boundaries focused. Runtime migration adds no new physical or causal proof.

## Acceptance and verification

Use real components in Rust tests for batch boundaries, multiple inputs, graph
traversal, recursion limits, variable output counts, checkpoints, and replay.
Reject undeclared imports, excessive memory/output, invalid evidence, and
incompatible interfaces. Exercise traps, CPU loops, host-call cancellation, and
scope isolation. Extend `analysis-packages` with a new Rust detector installed
without rebuilding Araphor. Run final shared Rust verification.

Reuse the expected results and fixtures captured in 7.5.2. Check every `AR-*`
item through installed components, including negative, missing-input,
duplicate, conflicting, late, expiry, and replay cases. Run `context-roundtrip`,
`profile-restart`, and `graph-notification` through installed production execution.
No item can remain on a hidden built-in execution path. Phase 7.5.5 adds native
target parity; 7.5.7 verifies the completed migration across owners.
For AR-04, verify that installed execution uses the shared authorized context
selector and retains its integration results. The selector remains a host
operation.

## Exclusions and stop point

Do not require Python-to-Wasm or assume native Python wheels are compatible.
Do not adopt a gadget loader or run detector code on the kernel enforcement
path. Performance is unqualified; benchmark approval must name the workload,
runtime, and limits before a performance test is added. Stop before native work.

## Result

**Not done.** Wasmtime integration, installed execution of all seven current
algorithm items, the production dispatch change, isolation tests, and runtime
compatibility remain to be implemented and verified.

## End scope and example

Complete when built Wasm packages run through the production lifecycle and
every `AR-01` through `AR-07` item passes installed-component equivalence and
runtime checks. Existing discovery and HF detectors run from installed packages;
the shared context and proof owners still enforce their checks. Native execution
follows in 7.5.5. Full upstream algorithm development follows in 7.5.8 and 7.5.9.

Example at completion: replay the existing protected-file fixture through the
installed `HF-PROC-001` package. It returns the same finding, evidence references,
coverage limits, and notification behavior as the prior implementation. Remove
required coverage and the package retains the expected incomplete result. The
kernel policy causes the denial; package evaluation reports its evidence.
