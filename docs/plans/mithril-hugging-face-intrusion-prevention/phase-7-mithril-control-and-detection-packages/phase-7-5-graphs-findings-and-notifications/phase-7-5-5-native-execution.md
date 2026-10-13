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
  or network access. Require qualified OS isolation and the existing host
  authorization, output accounting, and deadlines. Native memory and CPU limits
  are optional configuration settings and are disabled by default. Apply each
  native limit only when configured. A subprocess alone is not a sandbox.
  Reject the target if required isolation is unavailable; do not silently load
  it in Control.
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

### Design decision record

The [native decision proposal](native-execution-design.md) records source
`2b9384ec`, existing owner contracts, five unresolved decisions, mandatory
controls, configurable limits, and qualification requirements. D1 through D5
are **Not approved**. The user approved D6 native memory and CPU options with
disabled defaults. No cap values are required before native admission,
execution, or qualification. The host capability query reports Landlock ABI 4
and seccomp support. That query does not prove worker isolation.

### Ordered correction TODOs

Record a new concrete correction here before its implementation. Keep these
deliverables in order. Commit each implementation deliverable after its focused
checks pass; do not defer its commit until final qualification.

- [ ] **1. Resolve native design decisions.** Obtain approval for unresolved
  D1 through D5 in the decision record. Preserve the approved D6 optional limits
  and disabled defaults. Record the supported platform, native export inventory,
  ABI and dependency changes, artifact metadata, isolation and deployment
  requirements, and native resource defaults before dependent implementation.
- [ ] **2. Complete the native SDK and source builds.** Reuse the v1 C table,
  `Guest` computation, Arrow C Data/Stream, and SDK wire validation. Complete
  typed inputs, parameters, recorded time and seed, outputs, evidence, reasons,
  checkpoints, errors, cancellation, and owned release. Test failure and repeated
  release. Build the native artifact and locked dependency closure from source.
  Keep generated binaries out of commits.
- [ ] **3. Add isolated native execution to the package owner.** Apply every
  approved control before package loading or dependency initialization. Return
  typed Unsupported when a required control is unavailable. Preserve authority,
  expiry, revocation, concurrency, cleanup, and stale-completion rejection.
  Terminate and reap the complete owned worker scope.
- [ ] **4. Integrate compatibility, selection, and provenance.** Validate platform,
  CPU, system libraries, ABI, and dependency closure at admission. Add explicit
  selection through existing requests, CLI, and agent interfaces. Record actual
  artifact revisions. Preserve SQL/Wasm encoding, immutable history, and retry
  identity. Require compatible output and state contracts before switching.
  Never use failure fallback.
- [ ] **5. Prove export parity and host guarantees.** Qualify every approved export
  with identical fixtures. Reuse the migrated algorithms, authorized extraction,
  selected native reads, and traversal. Close durable readers before computation.
  Preserve host context, domain validation, atomic commits, notifications,
  missing coverage, and existing Wasm quota and compiled-code accounting.
- [ ] **6. Complete failure and lifecycle tests.** Keep production actions,
  transitions, assertions, and cleanup visible. Cover invalid ABI values,
  malformed transport and outputs, unavailable isolation, forbidden access, crashes,
  cancellation, expiry, revocation, stale completion, resource failures,
  restart, retry, upgrade, rollback, removal, and target switching. Include large
  selected graph transport without reducing workload or deadlines. Prove that
  failure preserves the prior output and checkpoint, releases resources, and
  produces no fallback. Test Wasm-to-native and native-to-Wasm switches.
- [ ] **7. Qualify installed production execution and final CI.** Extend
  `analysis-packages` with a real source-built SDK dual-target detector. Install
  and run it without rebuilding Araphor. Prove target parity and actual artifact
  identity in each result. Run a migrated algorithm with Python unavailable
  and affected existing production cases.
  Record exact source, artifacts, platform, configuration, commands, and terminal
  results. After the last covered source edit, run one final
  `bash .github/scripts/verify-rust-ci.sh` process to its terminal result.
- [ ] **8. Review connected source and close the records.** Review callers,
  duplication, ownership, and validation. Update the result and implementation
  review guide with completed deliverables, commits, exact proof, supported
  platforms, and limits. Keep the result Not done while required proof or a
  confirmed defect remains open.

### Preparation verification

At preparation commit `3764c005`, the documentation check passed for both changed
Markdown files, 13 local links, balanced code fences, six pending decisions,
and eight ordered TODOs. It confirmed that the original phase text was preserved
exactly. `git diff --check` passed.
Three Sol 6.1 reviews checked the SDK, owner, and qualification boundaries.
Their concrete corrections are in the proposal. No Rust source, Cargo file,
test, CI configuration, or verification script changed. No native build,
isolation qualification, production case, or performance test ran.

### Resource-default correction TODO

- [x] Correct the native resource decision records for the approved policy. Define
  `memory_bytes` and `cpu_seconds` as configuration options with disabled
  defaults. Remove the requirement to supply cap values before native admission,
  execution, or qualification. Keep mandatory isolation, authorization,
  transport validation, and existing owner deadlines. Record D6 as approved
  without changing the approval status of D1 through D5.

The corrected JSON configuration specifies disabled memory and CPU limits.
The documentation check passes for two Markdown files, 13 local links, code
fences, JSON defaults, approved D6, five pending decisions, and eight ordered
deliverables. `git diff --check` passes. These checks cover the records only;
native configuration code, execution, and qualification remain Not done.

## End scope and example

Complete when qualified native artifacts execute in isolated workers under the
same package contract, with explicit target selection and failure recovery.
Each export that advertises Wasm and native execution passes output and state
parity. This proves compatibility and isolation; it establishes no speed gain.

Example at completion: build the migrated behavior-aggregation algorithm once
for Wasm and once for the qualified native platform. The same input produces
the same counts, evidence, and checkpoint meaning; each receipt names its actual
target. A native crash commits no partial result and triggers no Wasm fallback.
