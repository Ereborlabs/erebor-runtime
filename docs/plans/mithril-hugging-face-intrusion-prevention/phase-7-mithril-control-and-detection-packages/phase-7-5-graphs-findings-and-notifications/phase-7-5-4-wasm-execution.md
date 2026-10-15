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
  -> the host reserves input and schema scratch before it encodes the input
  -> the execution owner receives the owned wire input
  -> the host creates an evaluation instance with explicit limits and authorized inputs
  -> generated WIT bindings transfer bounded batches and the prior checkpoint
  -> the component returns declared outputs, evidence references, and next checkpoint
  -> host validation passes the complete result to the existing commit path
  -> the execution owner releases the instance and temporary buffers

The component traps, exceeds a limit, or receives cancellation
  -> the host interrupts execution and checks cancellation
  -> the host discards uncommitted output and releases resources

The generic package scheduler receives the error
  -> the package owner records typed failure and marks retained results stale without replacing output or checkpoint

A domain adapter receives the error
  -> the adapter returns the error to its existing owner failure and coverage path
```

## Scope and owners

Keep the Wasmtime adapter under the `araphor-data` package execution owner.
The SDK owns generated component bindings, not permissions or durable state.
Pin and qualify the Wasmtime, component, and binding versions together.
Complete the SDK component artifact build and generated bindings in this phase.
Connect the descriptors from 7.5.2 to the admission owner from 7.5.3. Require
installed-component equivalence for all current algorithms. The approved
completion goal below replaces the past dispatch-order requirement. Reuse the production
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
- Keep the six optional Wasm quotas disabled by default: fuel, guest memory,
  analysis data, execution time, allocation, and host calls. Explicit quotas
  must work. Preserve mandatory compiler, compiled-code cache, SDK transfer,
  shared query, concurrency, cancellation, and authority controls.
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
computation code between SDK targets. Require installed-component equivalence
and no silent built-in fallback. Keep module and function
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

**Done.** The approved eight-deliverable goal is complete on the source and
components recorded in the final qualification table below. An author can
build an SDK detector. An operator can install its built folder and run it
without rebuilding Araphor. The host retains authorization, evidence checks,
native graph reads, atomic commits, lifecycle state, and notifications.
All four final production cases and the final shared Rust procedure pass.
The final CI record is `/tmp/araphor-wasm-rust-ci-ordered-v59.json`; its log is
`/tmp/araphor-wasm-rust-ci-ordered-v59.log`. The procedure finishes in
9,147.416 seconds with 2,080 passed, zero failed, and 555 ignored tests.
Ignored tests do not supply qualification evidence. The final proof is
`/tmp/araphor-wasm-rust-ci-proof-v59.json`. It verifies all 1,613 captured source
files, the saved executable, and the six component hashes.

The six optional Wasm quotas default to `None`. Explicit quotas retain their
checks. Mandatory compiler, SDK transfer, shared query, concurrency,
cancellation, and authority controls remain. The compiled-code cache remains
80 MiB and 16 entries. Prepared, executing, cached, pinned, and error-retained
code remains charged until the last owner releases it.

The startup investigation identifies accumulated exhaustion of the shared
120-second deadline. The unchanged saved artifact passes the complete recheck
under the original limits. The cause of the historical CPU-cost variation
remains unknown. No correction is claimed to prevent that historical failure.
Performance evidence applies only to the measured workloads below. The graph
stages overlap, and an unrelated build prevents an isolated whole-case
comparison. No new physical-prevention or cross-node-causality claim is made.

### Final installed lifecycle qualification

The normal build passes on `c145e7b8` in 151.688 seconds. The captured source
digest is `51e4e7cea19881ef97db9f429314a2feb92118fb135fde380701bbfe63fb65a3`.
The executable digest is
`f92d0fdc50462fe2eb882e69957f14d5cfac615e7c81fdbe3d3cb8d21c8fe801`.
All six generated components match the v57 baseline. Debug sections remain.
The capture is `/tmp/araphor-wasm-production-capture-v59.json`.

All four fresh production cases pass with this executable:

| Case | Seconds | Proof |
| --- | ---: | --- |
| `analysis-packages` | 289.756 | `/tmp/araphor-wasm-analysis-packages-proof-v59.json` |
| `context-roundtrip` | 16.294 | `/tmp/araphor-wasm-context-roundtrip-proof-v59.json` |
| `profile-restart` | 215.500 | `/tmp/araphor-wasm-profile-restart-proof-v59.json` |
| `graph-notification` | 1,981.221 | `/tmp/araphor-wasm-graph-notification-proof-v59.json` |

The installed SDK detector retains its typed reason, evidence, checkpoint,
restart, retry, and trust-revocation checks. Context selection retains exact
identity and cutoff omissions. Restart retains the unresolved profile,
sealed revision change, and durable source state. All 1,613 captured source
files, the executable, and the six component hashes match. These results
make no physical-prevention claim. The final shared Rust procedure passes
on this source after the last Rust edit. Its duration is 9,147.416
seconds, with 2,080 passing tests. The terminal record and log
are `/tmp/araphor-wasm-rust-ci-ordered-v59.json` and
`/tmp/araphor-wasm-rust-ci-ordered-v59.log`. Documentation-only closure does not
change the qualified executable or components.

### Final complete graph qualification and cost comparison

The complete v59 graph case passes with the captured executable and all six
unchanged components. It retains all 12 incident cards, duplicate and reordered
replay, 257 findings and notification obligations, original human deadlines,
and native graph windows with 64 and 185 records and 192 and 370 relationships.
Reopen preserves the committed version. The proof is
`/tmp/araphor-wasm-graph-notification-proof-v59.json`. The stage record is
`/tmp/araphor-wasm-graph-costs-v59.json`.

| Measured operation | v57 seconds | v59 seconds |
| --- | ---: | ---: |
| Complete case | 2,272.799 | 1,981.221 |
| 35 fresh-state fixtures with compiled code available | 658.770 | 260.690 |
| Median of those fixtures | 18.990 | 7.332 |
| First fixture, including cold compilation | 69.776 | 51.962 |
| 36 replay derivations | 171.422 | 202.727 |
| 64 graph processing calls | 376.148 | 436.052 |
| 64 snapshot reads | 2.949 | 3.637 |

Both runs retain the same workload, assertions, normal unoptimized profile,
limits, and component bytes. Each fixture retains independent durable state.
Stages overlap; their durations cannot be added to produce the complete case
time. An unrelated Rust and C++ build started during v59. The observation is
`/tmp/araphor-v59-concurrent-build-observation.json`. These durations describe
the measured runs. They do not isolate the correction's effect on the complete
case or establish production-wide performance.

Fixture setup still includes package installation and durable writes. Replay
derivation and graph processing remain material costs. This change removes
repeated immutable bundle reads during the locked installation response. It
does not change graph validation, detector inputs, test isolation, or deadlines.
The focused installation comparison above provides the same-test measurement.

### Final eight-deliverable review

The review uses the user-approved eight-deliverable goal. The final source and
component hashes are in the qualification table and capture above. Each row
identifies the completed change and its proof. The final CI result covers the
last Rust edit; the earlier failed and interrupted runs remain below.

| Deliverable | Completed source and proof |
| --- | --- |
| 1. Pending production correction | `9f8f5da2` reuses descriptor validation within each wire operation and the Finding schema within each detector descriptor. The focused SDK and algorithm checks pass. `0c35e0ca` adds graph stage diagnostics. The complete v57 and v59 graph cases verify those diagnostics. Independent host and guest checks remain. |
| 2. Production costs and startup | `208e58cf` adds the stronger retry-response assertions used before and after `c145e7b8`. The four unchanged metadata tests take 215.82 seconds before and 169.09 seconds after the locked installation-response correction. The v58 unchanged-artifact startup recheck passes. The shared startup deadline explains the failure mechanism; the historical CPU-cost cause remains unknown. Graph comparisons retain the overlap and concurrent-build limits above. |
| 3. SDK, package, and runtime contracts | Generated WIT bindings, six source-built components, typed inputs and outputs, reasons, checkpoints, and the SDK detector example remain. The v59 package case installs and runs the built folder without a host rebuild. Optional quotas default to `None`; explicit quotas and mandatory controls remain. `ec31f7e` verifies an explicit execution timeout and runtime recovery. The 80 MiB, 16-entry cache charges all live code until its last owner releases it. |
| 4. Current algorithms and lifecycle | Current installed-component proof covers AR-01 through AR-07. AR-04 selection remains host-owned. The final context, profile, package, and graph cases retain identity, evidence, coverage, revisions, historical finding JSON, and notification behavior. `881bea5a` records the final lifecycle proof. The earlier dispatch-order failure remains historical. |
| 5. Test strength and maintenance | `208e58cf` preserves retry, changed-artifact rejection, stored-byte equality, and response checks. The complete graph case retains 12 incident cards, both native windows, 257 obligations, and original human deadlines. Focused tests retain visible production actions. No scenario migration, shared mutable fixture, new test framework, or increased limit is included. |
| 6. Final installed qualification | All four v59 production cases pass with the captured source and executable above. All 1,613 source files, the saved executable, and all six components match their captures. `2305e0f` records the complete graph proof. No generated Wasm binary is committed. |
| 7. Final repository verification | `bash .github/scripts/verify-rust-ci.sh` passes after the last Rust edit. Formatting, workspace check, strict Clippy, and the full workspace test suite reach a terminal result. Duration: 9,147.416 seconds. Passing tests: 2,080. Record: `/tmp/araphor-wasm-rust-ci-ordered-v59.json`. Log: `/tmp/araphor-wasm-rust-ci-ordered-v59.log`. |
| 8. Review and commits | The connected-code review and [review guide](wasm-execution-review.md) retain the existing package, validation, storage, and computation owners. The implementation is committed in independently reviewed changes listed above. This result records completion and preserves the earlier failed checks, source boundaries, and dispatch-order error. |

The optional installation telemetry proposal remains unapproved and unchecked.
It adds no completion requirement. Native and Python execution, OCI delivery,
upstream algorithm ports, and new physical-prevention claims remain excluded.

## Historical records

The deleted progress entries repeat completed work, superseded limits, failed
attempts, and the qualification above. The complete record remains at
`7b7b407adf347d389984553a4d212bfce37b75b5:docs/plans/mithril-hugging-face-intrusion-prevention/phase-7-mithril-control-and-detection-packages/phase-7-5-graphs-findings-and-notifications/phase-7-5-4-wasm-execution.md`.
Use that revision to inspect an earlier attempt. Its result applies only to its
captured source, executable, components, and limits. A later pass does not turn
an earlier failure or interrupted run into a pass.

The approved resource correction leaves fuel, guest memory, analysis data,
execution time, allocation, and host-call quotas unset by default. Mandatory
compiler, cache, SDK, query, concurrency, cancellation, and authority controls
remain. Extism is a design reference; it is not a dependency. Component bytes
are built from locked source and are not committed.

Preserve all 21 corpus cases, the 256-record window, all 12 incident cards,
257 findings across 33 sources, and the 64- and 185-record traversal windows.
The host reserves retained input, encoding buffers, and schema scratch before
encoding. Null and nested FixedSizeList encoding allocations are included.
A deadline must identify the caller and release all reader slots. Each fixture
keeps its own durable state and query controls.

The historical dispatch-order requirement was not met. The approved completion
goal replaced that requirement. Historical CPU-cost variation remains
unexplained. Provider issuance, physical prevention, and cross-node causality
remain unqualified. The current deletion work requires new verification in the
[approved TODO](../../../araphor-performance-simplification-todo.md).

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
