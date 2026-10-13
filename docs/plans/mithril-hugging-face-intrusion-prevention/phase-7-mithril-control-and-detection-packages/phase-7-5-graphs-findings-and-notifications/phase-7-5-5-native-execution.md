# Phase 7.5.5: Native Execution

Run compiled algorithms and native dependencies under the same package contract.
Parent: [7.5](README.md). Require 7.5.4. This target supports frequently used
algorithms without a Python dependency; speed claims require measurements.

## Intended end state

A package can carry both `algorithm.wasm` and a platform-specific native artifact
for one named export. The same source library, parameters, dataset schemas,
evidence rules, and state contract serve both targets. Selection is explicit,
compatible with the host, and recorded in each result.
The user selected Rust native calls in Araphor's process. This decision replaces
the earlier isolated-worker requirement. Reuse the current builtin execution
model and retain the existing package and data owners.

## Implementation flow

```text
Admission evaluates a requested native target
  -> the package owner checks platform, CPU, system libraries, and ABI requirements
  -> the package owner validates the admitted native library and its dependencies
  -> the package owner stages the requested implementation before evaluation

The scheduler invokes the export
  -> the package owner supplies authorized typed batches to the Rust native adapter
  -> the SDK adapter calls the compiled algorithm through the native interface
  -> the adapter returns bounded outputs and its next checkpoint
  -> host validation submits the result through the existing atomic commit path
  -> AnalysisStore commits the selected implementation, result, and checkpoint together

Native computation returns an error or finishes after cancellation
  -> the package owner rejects its output and releases evaluation resources
  -> AnalysisStore retains the prior selected target and committed state
  -> retry uses the same declared implementation and operation identity

A native fault terminates Araphor
  -> the process cannot perform worker recovery
  -> restart restores the prior complete durable commit
  -> the package owner does not select Wasm as a fallback
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

- Use Arrow C Data/Stream interfaces at the native library boundary inside
  Araphor's process. Native requires no process transport. Reuse SDK validation
  where its contract matches. Keep the library loaded until all producer-owned
  buffers and release callbacks are finished. Keep it loaded while package-created
  threads or tasks can execute its code.
- Run native code in Araphor's process, like the current builtins. Add no worker
  or isolation layer. Native shares Araphor's privileges and failure domain.
  Retain host authorization, input/output accounting, and stale-result checks.
  Native memory and CPU options remain disabled by default. Process-wide OS
  limits cannot represent per-evaluation native limits; resolve enabled semantics
  before implementing those options.
- Keep durable state in AnalysisStore. Do not retain borrowed request pointers
  or callbacks after evaluation. Hold the library and operation permit while
  native code is running. Cancellation is cooperative; reject a late completion
  but do not claim that a stalled native call can be forcibly terminated.
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
platforms, invalid ABI values, buffer release, returned errors, recoverable Rust
panics, fatal host faults and restart, stale completion, and cancellation.
Run a migrated graph or discovery algorithm
with Python unavailable. Extend `analysis-packages`; run the final Rust gate.
Apply target parity to each native artifact selected from the current
[migration inventory](algorithm-coverage.md#current-araphor-algorithms). A
native target reuses the migrated source; it does not defer or repeat migration.

## Exclusions and stop point

Add no separate native process, isolation layer, Python bridge, or copied
algorithm. Load admitted native Rust packages in Araphor's process.
Native execution does not establish a throughput or latency gain.
Any benchmark needs separate approval with its workload, runtime, and limits.
Qualify the applicable native targets; advertise only verified host platforms.
Native execution must work on every platform where Araphor can compile.
Derive that target set from source and build records. Do not impose a separate
Linux x86-64 product restriction or claim qualification from compilation alone.

## Result

**Not done.** Native execution and target parity are unqualified.

### Design decision record

The [native decision proposal](native-execution-design.md) records source
`2b9384ec`, existing owner contracts, current decisions, configurable limits,
and qualification requirements. D1 is resolved: native execution must work
wherever Araphor can compile. D2 is approved for all current portable exports.
D5 is approved for execution in Araphor's process without isolation. D3 uses Rust;
its binary interface and dependency details remain proposals. D4 needs approval
after its installation and target-switch examples. The user approved D6 options with
disabled defaults. No cap values are required before native admission,
execution, or qualification. The host capability query reports Landlock ABI 4
and seccomp support. The current direction does not use that isolation proposal.

### Ordered correction TODOs

Record a new concrete correction here before its implementation. Keep these
deliverables in order. Commit each implementation deliverable after its focused
checks pass; do not defer its commit until final qualification.

- [ ] **1. Resolve native design decisions.** Obtain approval for unresolved
  D3 and D4 details in the decision record. Resolve the enabled-resource semantics
  that D5 changes. Preserve D1, approved D2, in-process D5, and disabled D6 defaults.
  Record the applicable
  compilation targets, native export inventory,
  ABI and dependency changes, artifact metadata, library loading and deployment
  requirements, and native resource defaults before dependent implementation.
- [ ] **2. Complete the native SDK and source builds.** Reuse the v1 C table,
  `Guest` computation, Arrow C Data/Stream, and SDK wire validation. Complete
  typed inputs, parameters, recorded time and seed, outputs, evidence, reasons,
  checkpoints, errors, cancellation, and owned release. Test failure and repeated
  release. Build the native artifact and locked dependency closure from source.
  Keep generated binaries out of commits.
- [ ] **3. Add in-process native execution to the package owner.** Load the
  admitted Rust library and hold it through every array and release callback.
  Preserve authority, expiry, revocation, concurrency, returned-error cleanup,
  and stale-completion rejection. Support cooperative cancellation. Do not add
  a native worker or claim fault isolation or forced termination.
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
  malformed batches and outputs, returned errors, Rust panics, host faults,
  cancellation, expiry, revocation, stale completion, resource failures,
  restart, retry, upgrade, rollback, removal, and target switching. Include large
  selected graph inputs without reducing workload or deadlines. Prove that
  returned failure preserves the prior output and checkpoint, releases resources,
  and produces no fallback. Check restart after a fatal native host fault.
  Test Wasm-to-native and native-to-Wasm switches.
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

At resource-default correction commit `88c6c2c7`, the corrected JSON configuration
specified disabled memory and CPU limits. The documentation check passed for
two Markdown files, 13 local links, code
fences, JSON defaults, approved D6, five pending decisions, and eight ordered
deliverables. `git diff --check` passed. These checks covered the records only;
native configuration code, execution, and qualification remain Not done.

### Platform-contract correction TODO

- [x] Replace the proposed Linux x86-64 product restriction with the user's
  requirement: native execution must work on every platform where Araphor can
  compile. Derive the applicable package-owner targets from source and build
  records. Do not claim platform qualification from successful compilation.
  Keep artifact compatibility checks and required worker isolation. Mark the
  Linux isolation proposal as one platform implementation. Record D1 as resolved
  and explain the existing Rust computation and the missing installed native
  artifact execution. Do not repeat algorithm migration.

The documentation check passes for two Markdown files, 14 local links, code
fences, disabled JSON resource defaults, resolved D1, approved D6, four pending
decisions, and eight ordered deliverables. Source review confirms the installed
SQL/Wasm dispatch and missing native artifact execution. `git diff --check`
passes. No Rust source or configuration changed. No native build or additional
platform qualification ran.

### In-process execution correction TODO

- [x] Record all current portable exports as the approved native qualification
  inventory. Record Rust as the authoring language. Replace isolated workers
  with native library calls in Araphor's process, as the user requires. Remove
  worker, isolation, process-transport, and process-limit requirements from the
  active native scope. Retain host authorization, semantic validation, atomic
  commits, and explicit target selection. Explain D4 with installation, saved
  state, retry, and target-switch examples. State library lifetime, cooperative
  cancellation, shared-process failure, and configured-resource limits precisely.
  Do not claim that native faults are isolated or that a stalled call can be killed.

The documentation check passes for six Markdown files, 14 checked local links,
code fences, disabled JSON defaults, D2/D5 approval status, Rust authoring,
staged target selection, and library lifetime requirements. SDK and owner
reviews checked the same boundaries. `git diff --check` passes. The parent
native row, Python supervisor reference, and later qualification boundary are
updated without implementing those later phases. No Rust source, Cargo file,
test, CI configuration, or verification script changed. Native execution and
enabled-resource semantics remain Not done.

## End scope and example

Complete when qualified native Rust artifacts execute in Araphor's process under the
same package contract, with explicit target selection and failure recovery.
Each export that advertises Wasm and native execution passes output and state
parity. This proves package compatibility; it establishes no isolation or speed gain.

Example at completion: build the migrated behavior-aggregation algorithm once
for Wasm and once for the qualified native platform. The same input produces
the same counts, evidence, and checkpoint meaning; each receipt names its actual
target. A returned native error commits no partial result and triggers no Wasm
fallback. A fatal native fault can stop Araphor; restart restores its last
complete durable commit.
