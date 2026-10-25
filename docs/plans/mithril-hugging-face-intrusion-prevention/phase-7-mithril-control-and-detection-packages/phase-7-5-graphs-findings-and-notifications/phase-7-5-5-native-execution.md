# Phase 7.5.5: Native Execution

Run compiled algorithms and native dependencies under the same package contract.
Parent: [7.5](README.md). Require 7.5.4. This target supports frequently used
algorithms without a Python dependency; speed claims require measurements.

## Intended end state

An author can build `algorithm.wasm` and a platform-specific native artifact
from one source. An installed export declares one supported execution type.
The same source library, parameters, dataset schemas,
evidence rules, and state contract serve both targets. Execution follows the
installed plugin type. Check host compatibility and record the actual artifact
in each result. Add no global target preference or operator target option.
The user selected Rust native calls in Araphor's process. This decision replaces
the earlier isolated-worker requirement. Reuse the current builtin execution
model and retain the existing package and data owners.

## Implementation flow

```text
Admission evaluates an installed native plugin
  -> the package owner checks platform, CPU, system libraries, and ABI requirements
  -> the package owner validates the admitted native library and its dependencies
  -> the package owner uses the plugin's declared native implementation

The scheduler invokes the export
  -> the package owner supplies authorized typed batches to the Rust native adapter
  -> the SDK adapter calls the compiled algorithm through the native interface
  -> the adapter returns bounded outputs and its next checkpoint
  -> host validation submits the result through the existing atomic commit path
  -> AnalysisStore commits the result and checkpoint together

Native computation returns an error or finishes after cancellation
  -> the package owner rejects its output and releases evaluation resources
  -> AnalysisStore retains the prior active revision and committed state
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
  limits cannot represent per-evaluation native limits. An enabled hard native
  cap returns Unsupported before native loading. SQL and Wasm remain usable.
- Keep durable state in AnalysisStore. Do not retain borrowed request pointers
  or callbacks after evaluation. Hold the library and operation permit while
  native code is running. Cancellation is cooperative; reject a late completion
  but do not claim that a stalled native call can be forcibly terminated.
- Check output and checkpoint parity for builds from the same computation.
  Specify numeric and ordering behavior in fixtures. Incompatible state needs
  the checked conversion or rebuild path. Never switch targets after a trap,
  partial result, or timeout. Missing compatible artifacts return Unsupported.
- Execute the installed plugin's declared type: native runs native; Wasm runs
  Wasm. Keep execution under the package owner. Add no global target preference,
  operator target option, or second native package system.

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

**Done** for the source cuts below on the Linux x86-64 GNU host with glibc 2.39. Native SDK,
source builds, declared-plugin execution, compatibility, provenance, export
parity, lifecycle, host-fault restart, and installed production proof pass.
Final CI session 25541 returns exit 0 for source
`5e9364543093e3e18da03e4d51e6dd28cc057982`. All 1,390 recorded source hashes
remain unchanged. The eight-deliverable acceptance record is below. This result does not qualify
the later working-tree simplification. Its verification remains in the
[approved TODO](../../../araphor-performance-simplification-todo.md).

Native executes in Araphor's shared process. Cancellation is cooperative, and
stalled calls can delay shutdown. Enabled hard native memory or CPU caps return
Unsupported; defaults remain disabled. Other platforms, speed gains, physical
Kubernetes actions, and cross-node causality are not qualified by this result.

### Design decision record

The [native decision proposal](native-execution-design.md) records source
`2b9384ec`, existing owner contracts, current decisions, configurable limits,
and qualification requirements. D1 is resolved: native execution must work
wherever Araphor can compile. D2 is approved for all current portable exports.
D5 is approved for execution in Araphor's process without isolation. D3 uses
Rust artifacts with the existing SDK binary interface. D4 is resolved:
execution follows the installed plugin type. Keep the existing package lifecycle.
The user approved D6 options with
disabled defaults. No cap values are required before native admission,
execution, or qualification. The host capability query reports Landlock ABI 4
and seccomp support. The current direction does not use that isolation proposal.

### Native SDK and source-build verification

SDK source `d65db26` and host-copy correction `09b354f` use the versioned v1
function table and the shared Rust computation. The native SDK cut returns
63 passed and 0 failed. Strict all-target clippy returns exit 0. Builder tests
return 6 passed and 0 failed. The locked release build exports the v1 accessor
from all six libraries. Generated libraries are not committed.

The final library directory is `/tmp/araphor-native-built-20261013-final`.
The build log is `/tmp/araphor-native-build-20261013-final.log`.
`/tmp/araphor-native-build-20261013-final-proof.json` records artifact digests,
build inputs, host, and command. The earlier builder source record is
`/tmp/araphor-native-builder-proof-20261013.json`.

```sh
cargo test --locked -p araphor-analysis-sdk --features native --lib
cargo clippy --locked -p araphor-analysis-sdk --features native --all-targets -- -D warnings
cargo test --locked -p araphor-component-build --lib
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo run --locked -p araphor-component-build --example workspace -- . target/analysis-native /tmp/araphor-native-built-20261013-final --native
```

The commands above define a new source-build check. They do not record a new
pass. Compilation alone does not qualify admission, installed execution, or parity.
The following records supply those checks for their exact source and artifacts.

### Native owner and parity verification

The final source-built libraries are in
`/tmp/araphor-native-built-20261013-final`. The locked release build returned
exit 0. Artifact digests, build inputs, host, and command are in
`/tmp/araphor-native-build-20261013-final-proof.json`.

The final focused owner command returned exit 0, with 33 passed and 0 failed:

```sh
ARAPHOR_NATIVE_DIR=/tmp/araphor-native-built-20261013-final cargo test --locked -p araphor-data --lib -- --include-ignored --nocapture --skip native_host_fault_restart package::native package::tests::native discovery::sdk::native graph::derive::adapter::tests::native package::evaluation::preparation::tests shared_dependency_parameter_comparison native_leases_keep_limits
```

The log is `/tmp/araphor-native-final-focused-20261013.log`. The source record is
`/tmp/araphor-native-final-source-20261013.json`. The cut includes 18 loader tests,
seven installed lifecycle tests, all seven migrated export parity checks, the
185-record Process input, two preparation tests, the shared dependency root,
and native host buffer accounting. The native and Wasm fixtures compare complete
data, evidence, reasons, context, coverage, checkpoint, and replay results.
Enabled native caps leave SQL and Wasm usable and reject native execution.

The separate `package::tests::native::restart::native_host_fault_restart`
command returned exit 0, with 1 passed and 0 failed in 169.55 seconds. The test
uses the same final native libraries. A real Rust panic returns through the SDK
and the child host then runs native again. A real abort returns SIGABRT. Restart
restores the exact prior activation, stored output, checkpoint, and metadata.
Retry and subsequent native execution pass. No target fallback occurs.

The [proof-route table](native-execution-review.md#proof-route-and-current-status)
names the loader, SDK, lifecycle, four Discovery exports, three graph exports,
and large native Arrow tests. The production receipts are below.

### Installed native production verification

The [retained production records](native-execution-review.md#retained-production-case-evidence)
record the initial native package, context, and profile checks.
The [owner-correction records](native-execution-review.md#production-proof-after-the-owner-correction)
record the final native package and complete graph cases at
`b50107eb3551e61c405b6b15f5b5cdb093b1c8f2`, with the binary digest,
configuration, result files, and proof paths.

Session 8227 proves actual native plugins with Python unavailable. Session
64467 proves the complete graph workload with its declared Wasm packages.
The graph traversal label `native` describes evidence storage. It does not
change the plugin type. Neither result qualifies a later binary or source cut.

## End scope and example

Complete when qualified native Rust artifacts execute in Araphor's process under the
same package contract, with execution by plugin type and failure recovery.
Each export that advertises Wasm and native execution passes output and state
parity. This proves package compatibility; it establishes no isolation or speed gain.

Example at completion: build the migrated behavior-aggregation algorithm once
for Wasm and once for the qualified native platform. The same input produces
the same counts, evidence, and checkpoint meaning; each receipt names its actual
target. A returned native error commits no partial result and triggers no Wasm
fallback. A fatal native fault can stop Araphor; restart restores its last
complete durable commit.

### Final Rust CI acceptance

Session 25541 returns terminal exit 0 at `2026-10-14T07:50:20.175975+00:00`.
The covered source is `5e9364543093e3e18da03e4d51e6dd28cc057982`.
The source guard verifies all 1,390 recorded source and configuration hashes
unchanged after the run. The proof records `PASS` at
`/tmp/araphor-native-final-ci-joined-shutdown-source-20261014.json`.
The log is `/tmp/araphor-native-rust-ci-joined-shutdown-final-20261014.log`.

The command is `CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=4 bash .github/scripts/verify-rust-ci.sh`.
Formatting passes. Workspace check passes in 13.22 seconds; strict workspace
all-target, all-feature clippy passes in 0.47 seconds. All workspace test stages
pass. The exact retained summaries are:

| Crate | Passed | Failed | Ignored | Seconds |
| --- | ---: | ---: | ---: | ---: |
| SDK | 63 | 0 | 0 | 0.34 |
| CLI | 62 | 0 | 1 | 0.04 |
| Component builder | 6 | 0 | 0 | 0.00 |
| Data | 614 | 0 | 19 | 2,157.82 |
| Control | 188 | 0 | 2 | 119.39 |
| End-to-end | 191 | 0 | 528 | 737.61 |
| Node | 282 | 0 | 1 | 2.62 |

The original SQL replacement and observability query upload cases both pass.
The separate native parity and real host-fault records supply their opt-in
qualification; ignored tests are not counted as executed workspace proof.
No test workload, assertion, bound, or product deadline was reduced.

### Final eight-deliverable acceptance

All eight deliverables are complete for the recorded Linux x86-64 GNU host with
glibc 2.39. The retained source cuts remain explicit. Native SDK, loader,
algorithms, and artifact bytes are unchanged by the final shutdown correction.
The `b50107eb` production and complete graph results remain their exact
historical cuts. Focused cleanup proof and final CI at `5e936454` qualify the
affected supervisor shutdown behavior; they do not claim a new native artifact
build or production binary.

| Deliverable | Verified source and proof |
| --- | --- |
| 1. Decisions | [Approved design](native-execution-design.md): D1–D6, Rust authoring, declared plugin type, shared process, and disabled cap defaults. |
| 2. SDK and build | `d65db26`, `09b354f`; [SDK and source-build proof](#native-sdk-and-source-build-verification), 63 SDK tests, six locked source-built libraries, owned release, and bounded Arrow C exchange. |
| 3. Execution owner | `a38dec4`, `b50107eb`, `5e936454`; [native owner proof](#native-owner-and-parity-verification) and [shutdown contract](native-execution-review.md#supervisor-preparation-and-cancellation): authorization, cooperative cancellation, retained library lifetime, and joined shutdown. |
| 4. Compatibility and provenance | `a38dec4`; [native review](native-execution-review.md): complete declared closure, typed ABI checks, legacy readability, actual artifact identity, immutable history, and no fallback. |
| 5. Parity and host guarantees | [Native owner and parity proof](#native-owner-and-parity-verification): four Discovery exports, three graph exports, BurstDetector, and the 185-record native Arrow case. Session 8227 proves installed native plugins; session 64467 proves the unchanged declared-Wasm graph and notification workload. |
| 6. Failures and lifecycle | [Native tests](../../../../../crates/araphor-data/src/package/tests/native/mod.rs), separate real panic/SIGABRT restart proof, and focused shutdown checks: preserved prior commits, retry, updates, rollback, removal, and Wasm/native package changes. |
| 7. Final qualification | `b50107eb` production sessions 8227 and 64467; `5e936454` [final CI](#final-rust-ci-acceptance), session 25541, exit 0, verified unchanged source. |
| 8. Review and records | [Implementation review](native-execution-review.md), connected source reviews, explicit proof cuts, corrected historical statuses, and this eight-deliverable acceptance record. |

Native shares Araphor's privileges and failure domain. Rust unwind panics are
caught at the SDK boundary; aborts and memory faults can terminate the host.
Cancellation cannot forcibly stop arbitrary native code. Enabled hard
per-library caps return Unsupported. This result qualifies no other platform,
speed gain, physical Kubernetes action, or cross-node causal claim. Python
execution, OCI distribution, and upstream algorithm ports remain outside this
completed scope.

## Historical records

Completed correction lists, superseded design requirements, diagnostics, failed
checks, and intermediate qualification remain at
`7b7b407adf347d389984553a4d212bfce37b75b5:docs/plans/mithril-hugging-face-intrusion-prevention/phase-7-mithril-control-and-detection-packages/phase-7-5-graphs-findings-and-notifications/phase-7-5-5-native-execution.md`.
Use that exact revision for an earlier receipt. Each receipt applies only to
its recorded source, binary, artifacts, configuration, and limits. A later pass
does not change an earlier failure or interrupted result.

The user-approved shared-process decision replaces the worker and isolation
proposal. The historical independent one-second package-read failure has no
confirmed cause. The later graph pass does not establish that cause.


## Native redesign review on 2026-10-25

Result: **Done** for the required native replacement.
Read the [current owner map](../../../araphor-component-redesign.md#required-native-redesign-result)
and [focused proof](../../../araphor-analysis-migration.md#one-managed-graph-execution-route).
Earlier commands, versions, results, and limits apply to their recorded source.
