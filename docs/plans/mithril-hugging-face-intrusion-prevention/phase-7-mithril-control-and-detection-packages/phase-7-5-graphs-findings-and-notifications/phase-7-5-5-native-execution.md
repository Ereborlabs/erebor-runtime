# Phase 7.5.5: Native Execution

Run compiled algorithms and native dependencies under the same package contract.
Parent: [7.5](README.md). Require 7.5.4. This target supports frequently used
algorithms without a Python dependency; speed claims require measurements.

## Intended end state

A package can carry both `algorithm.wasm` and a platform-specific native artifact
for one named export. The same source library, parameters, dataset schemas,
evidence rules, and state contract serve both targets. Selection is explicit,
compatible with the host, and recorded in each result.

## Implementation flow

```text
Admission evaluates a requested native target
  -> the package owner checks platform, CPU, system libraries, and ABI requirements
  -> the execution owner verifies that required worker isolation is available
  -> the package owner records the selected implementation before evaluation

The scheduler invokes the export
  -> the supervisor supplies a worker with its package and authorized batches
  -> the SDK adapter calls the compiled algorithm through the native interface
  -> the worker returns bounded outputs and its next checkpoint
  -> host validation submits the result through the existing atomic commit path

The worker crashes or ignores cancellation
  -> the supervisor terminates the worker and releases its resources
  -> the package owner records failure and retains the prior committed state
  -> retry uses the same declared implementation and operation identity
```

## Scope and owners

Reuse the package execution owner and the SDK contract. Use a versioned
C-compatible function table for native calls, with explicit ownership, release,
errors, and cancellation. Do not expose Rust trait objects as a binary ABI.
Panics and exceptions must not cross that boundary.
Complete native artifact builds and generated SDK adapters here. A native-only
dependency is permitted when the package declares that target requirement. Such
an export must pass its semantic fixtures; it cannot claim Wasm compatibility.
Cross-target parity is required for every export that advertises both targets.

- Use Arrow C Data/Stream interfaces inside the worker and bounded Arrow IPC
  across the process boundary. Process-local pointers cannot cross that boundary.
  Share exchange validation with the Wasm path where the contract is the same.
- Run outside Control's address space, without its credentials, database files,
  or network access. Enforce process, memory, CPU, output, and time limits through
  qualified OS isolation. A subprocess alone is not a sandbox. Reject the target
  if required isolation is unavailable; do not silently load it in Control.
- Reuse workers only within a compatible authorization scope, package revision,
  and dependency closure. Reset transient state between evaluations. Shared
  algorithm libraries contain computation; AnalysisStore owns durable state.
- Check output and checkpoint parity before switching between declared targets.
  Specify numeric and ordering behavior in fixtures. Incompatible state needs
  the checked conversion or rebuild path. Never switch targets after a trap,
  partial result, or timeout. Missing compatible artifacts return Unsupported.
- Prefer the default Wasm target unless a selected package requirement or an
  approved measurement justifies native selection. Keep all selection policy in
  the package owner; do not add a second native package system.

## Acceptance and verification

Build the same Rust algorithm for Wasm and native execution. Check findings,
datasets, evidence, state, and replay with identical fixtures. Test incompatible
platforms, unavailable isolation, invalid ABI values, buffer release, worker
crashes, stale completion, and cancellation. Run a migrated graph or discovery algorithm
with Python unavailable. Extend `analysis-packages`; run the final Rust gate.
Apply target parity to each native artifact selected from the current
[migration inventory](algorithm-coverage.md#current-araphor-algorithms). A
native target reuses the migrated source; it does not defer or repeat migration.

## Exclusions and stop point

Add no in-process third-party library loading, Python bridge, or copied native
algorithm. Native execution does not establish a throughput or latency gain.
Any benchmark needs separate approval with its workload, runtime, and limits.
Stop at a qualified native target; advertise only verified host platforms.

## Result

**Not done.** Native execution and target parity are unqualified.

## End scope and example

Complete when qualified native artifacts execute in isolated workers under the
same package contract, with explicit target selection and failure recovery.
Each export that advertises Wasm and native execution passes output and state
parity. This proves compatibility and isolation; it establishes no speed gain.

Example at completion: build the migrated behavior-aggregation algorithm once
for Wasm and once for the qualified native platform. The same input produces
the same counts, evidence, and checkpoint meaning; each receipt names its actual
target. A native crash commits no partial result and triggers no Wasm fallback.
