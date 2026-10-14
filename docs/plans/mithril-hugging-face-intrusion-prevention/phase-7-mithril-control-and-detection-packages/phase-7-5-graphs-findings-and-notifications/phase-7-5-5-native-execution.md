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

**Not done.** Native SDK exchange, installed execution, export parity, lifecycle,
and host-fault restart checks pass on the recorded Linux x86-64 host. The complete
graph notification case failed at a package read deadline. Final workspace CI
failed at the existing SQL dependency refresh case. Both failures remain under
investigation; final qualification is incomplete.

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

### Ordered correction TODOs

Record a new concrete correction here before its implementation. Keep these
deliverables in order. Commit each implementation deliverable after its focused
checks pass; do not defer its commit until final qualification.

### Decision simplification and implementation corrections

The user selected Rust artifacts and native calls in Araphor's process.
The SDK supplies the existing versioned binary interface. Authors implement
Rust computation; they do not implement C adapters. D4 adds no separate state
workflow. Execute the installed plugin's declared type. Reuse
the existing package version, checkpoint, update, and rollback rules. Remove
the proposed public `rebuild` option.

- [x] Add the Rust native adapter and export macro beside the existing SDK
  guest adapter. Complete typed exchange, cancellation, panic handling, and
  release tests through the existing v1 table.
- [x] Extend source builds and the current guest crates to emit native libraries
  from the same computation. Record artifact and host requirements in the
  existing package manifest. Install no compiler, hook, or downloader.
- [x] Add native admission and loading under AnalysisPackageOwner. Keep library
  code loaded through all calls and release callbacks. Preserve host-owned
  output, authorization checks, and existing query accounting.
- [x] Execute the declared plugin type and record actual artifact identity in
  results and receipts. Remove the incomplete request target and stored target
  preference drafts. Preserve historical encodings, retries, and atomic commits.
- [x] Define disabled native memory and CPU settings. Reject an enabled hard
  per-library cap with Unsupported when the shared process cannot enforce it.
  Do not change process-wide limits or silently ignore an enabled setting.
- [ ] Qualify shared-source export parity, installed execution, failures, and
  lifecycle changes. Run the final Rust gate and update the review guide.

- [x] **1. Resolve native design decisions.** Use Rust artifacts and the existing
  SDK binary interface. Execute the declared plugin type and keep the existing state
  lifecycle. Reject enabled hard per-library caps with Unsupported in the shared
  process. Preserve D1, approved D2, in-process D5, and disabled D6 defaults.
  Record the applicable
  compilation targets, native export inventory,
  ABI and dependency changes, artifact metadata, library loading and deployment
  requirements, and native resource defaults before dependent implementation.
- [x] **2. Complete the native SDK and source builds.** Reuse the v1 C table,
  `Guest` computation, Arrow C Data/Stream, and SDK wire validation. Complete
  typed inputs, parameters, recorded time and seed, outputs, evidence, reasons,
  checkpoints, errors, cancellation, and owned release. Test failure and repeated
  release. Build the native artifact and locked dependency closure from source.
  Keep generated binaries out of commits.
- [x] **3. Add in-process native execution to the package owner.** Load the
  admitted Rust library and hold it through every array and release callback.
  Preserve authority, expiry, revocation, concurrency, returned-error cleanup,
  and stale-completion rejection. Support cooperative cancellation. Do not add
  a native worker or claim fault isolation or forced termination.
- [x] **4. Integrate compatibility and provenance.** Validate platform,
  CPU, system libraries, ABI, and dependency closure at admission. Execute the
  declared plugin type through the existing owner and interfaces. Record actual
  artifact revisions. Preserve SQL/Wasm encoding, immutable history, and retry
  identity. Require compatible output and state contracts before switching.
  Never use failure fallback.
- [x] **5. Prove export parity and host guarantees.** Qualify every approved export
  with identical fixtures. Reuse the migrated algorithms, authorized extraction,
  selected native reads, and traversal. Close durable readers before computation.
  Preserve host context, domain validation, atomic commits, notifications,
  missing coverage, and existing Wasm quota and compiled-code accounting.
- [x] **6. Complete failure and lifecycle tests.** Keep production actions,
  transitions, assertions, and cleanup visible. Cover invalid ABI values,
  malformed batches and outputs, returned errors, Rust panics, host faults,
  cancellation, expiry, revocation, stale completion, resource failures,
  restart, retry, upgrade, rollback, removal, and package type changes. Include large
  selected graph inputs without reducing workload or deadlines. Prove that
  returned failure preserves the prior output and checkpoint, releases resources,
  and produces no fallback. Check restart after a fatal native host fault.
  Test package updates between Wasm and native builds in both directions.
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

### Native SDK and source-build verification

The SDK and builder source commit is `d65db26`. The SDK host-copy correction
commit is `09b354f`. The added error-bound test returned 63 passed and 0 failed;
the strict all-target clippy command also returned exit 0. These checks cover
the same SDK production code as `09b354f` and the added test.

The SDK native adapter uses the existing `Guest` implementation and v1 function
table. It supplies typed Arrow streams, context, parameters, evidence, reasons,
checkpoints, cancellation, and bounded output. Tests check Rust unwind handling,
invalid ABI values, borrowed input ownership, error cleanup, and repeated release.
The builder emits native libraries from the same six guest crates as Wasm.
Generated libraries are not committed.

Focused commands passed on `x86_64-unknown-linux-gnu`:

```sh
cargo test --locked -p araphor-analysis-sdk --features native --lib
cargo clippy --locked -p araphor-analysis-sdk --features native --all-targets -- -D warnings
cargo test --locked -p araphor-component-build --lib
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo run --locked -p araphor-component-build --example workspace -- . target/analysis-native /tmp/araphor-native-built-20261013 --native
```

The SDK tests returned 61 passed and 0 failed. Clippy returned exit 0. Builder
tests returned 6 passed and 0 failed. The locked release build returned exit 0
and exported the v1 accessor from all six libraries. Its artifact record is
`/tmp/araphor-native-build-20261013-proof.json`; its log is
`/tmp/araphor-native-build-20261013.log`. Builder source digests are in
`/tmp/araphor-native-builder-proof-20261013.json`.
This proof covers the adapter and source build. It does not qualify package
admission, installed execution, export parity, production cases, or final CI.
The complete deliverable remains Not done until built-folder installation proof
also passes.

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

The first broad native cut returned 67 passed and 1 failed. The failed new graph
test retained output guards during a later reservation. The final focused cut
passes after those guards are released. Two direct preparation launches also
returned ENOENT during concurrent test-binary replacement. The final Cargo
launch passes both preparation tests and the shared dependency regression.

The installed SDK example, context round trip, and profile restart cases pass.
The complete graph notification case and final workspace CI remain Not done.
This result makes no platform or speed claim beyond the recorded Linux x86-64
host and semantic checks.

### Installed native production verification

The retained production binary is
`/tmp/araphor-native-qualified-bin-20261013/mithril_discovery_test`. Its SHA-256 is
`d47ab672fa750273eef03080f054cc9494fee561f44f07f750e93c6821b82c02`.
The source and binary record is `/tmp/araphor-native-production-source-20261013.json`.
It covers owner commit `a38dec4` and the native qualification source changes.
The later CLI help and builder test error-path edits do not change this runtime.

Each case uses `PATH=/tmp/araphor-no-python`,
`ARAPHOR_NATIVE_DIR=/tmp/araphor-native-built-20261013-final`, and
`ARAPHOR_NATIVE_TARGET=x86_64-unknown-linux-gnu`.
Run the retained binary with `--case CASE --output-directory DIRECTORY`.

| Case | Output directory under `/tmp` | Terminal result |
| --- | --- | --- |
| `analysis-packages-native` | `araphor-native-qualified-analysis-packages-20261013` | Session 43003, exit 0, PASS. |
| `context-roundtrip` | `araphor-native-qualified-context-20261013` | Session 33660, exit 0, PASS. |
| `profile-restart` | `araphor-native-qualified-profile-20261013` | Session 2806, exit 0, PASS. |
| `graph-notification` | `araphor-native-qualified-graph-20261013` | Session 76075, exit 1, AnalysisReadDeadline. |

Each passing output directory contains `result.json`. The graph case failed
before it created its output directory. The adjacent `.log` file retains each
case log. These cases use supported production owners with synthetic inputs.
They do not establish a physical Kubernetes result.

The native case retains the original SQL and Wasm checks. The real client installs
a source-built BurstDetector folder without a host rebuild. Native execution
returns three matching evidence records from four inputs, threshold 3, the
`example-burst.THRESHOLD` reason, and checkpoint `4`. The result records the native
artifact digest, dependency closure digest, and platform. Restart, retry, and
trust revocation checks pass. The three installed migrated graph exports return
the same findings, graph records, package state, and repeated replay result.
Python is unavailable on PATH. No performance claim or physical action occurs.

The first complete graph case returned exit 1 after 1,460.056 seconds. The error
is `AnalysisReadDeadline`, with caller `analysis/packages/read.rs:16`.
`AnalysisStore::package_revision` uses a fresh one-second default read control.
This is not an overall graph timeout. The graph case executes the unchanged
required Wasm packages. The store reader and original graph workload did not
change. The info log places the failure inside replay qualification but does
not identify its exact step or package. Concurrent build load is a hypothesis,
not a proven cause. Run the same retained binary after final CI finishes, with
the existing graph debug logs and a fresh output directory. Keep all deadlines
and inputs unchanged. Do not change source without a confirmed cause.

The builder test correction returns clock and file-read errors through the
existing error owner. All file and dependency assertions remain. Its final
focused tests returned 6 passed and 0 failed; strict all-target clippy returned
exit 0. Logs are `/tmp/araphor-native-builder-test-final-20261013.log` and
`/tmp/araphor-native-builder-clippy-final-20261013.log`.

### Bundle-read correction TODO

- [x] Reuse the already loaded immutable bundle during installation, explicit
  evaluation, and preparation. Reuse it only when its root matches the activation
  root. Load the activation's own root for an independently installed dependency.
  Preserve grant checks, authority admission, commit authorization, retry identity,
  and activation generation checks. Add no resident bundle cache. Run dependency
  authority tests and the native interruption qualification after this change.

### Package help correction TODO

- [ ] Replace the install help's SQL-only export description with the supported
  package export behavior. Keep request parsing and execution unchanged. Verify
  the CLI through the final Rust gate.

### Builder test error-path correction TODO

- [x] Return the two errors from the new native folder test instead of calling
  `unwrap`. The first final CI process passed formatting and workspace check,
  then returned exit 101 at strict clippy. Preserve the file and dependency
  assertions. Run focused builder tests and strict clippy, then restart the final
  repository CI procedure after this last test edit.

### Loader test assertion correction TODO

- [x] Replace two explicit panic branches in native loader tests with assertions
  on the native error owner and code. Final CI session 51562 passed formatting
  and workspace check, then returned exit 101 at strict clippy. Preserve the
  incompatible ABI, error-code, and source assertions. Run the focused loader
  tests and strict clippy, then restart final CI after the last test edit.

The correction returns a test error when the native error owner does not match.
It preserves the separate code, operation, and SDK source assertions. The
focused loader command returned 18 passed and 0 failed. Strict all-target,
all-feature clippy for `araphor-data` returned exit 0. Logs are
`/tmp/araphor-native-loader-test-final-20261013.log` and
`/tmp/araphor-native-loader-clippy-final-20261013.log`. No production statement
changed; the retained native artifacts and production binary remain applicable.

### Workspace graph qualification investigation

Final CI session 56085 reports a failure in
`graph::tests::control_graph_context_and_result_bounds_keep_required_progress`.
The process remains live. The test uses 256 records, three large context facts
per record, and checks complete progress, 256 findings, result byte bounds, and
context bounds. Its full failure detail is pending the terminal test output.
Keep the test inputs, assertions, byte bounds, and deadlines unchanged. Check
the exact failure and connected source before a correction or isolated rerun.

The terminal result is exit 101: 606 passed, 5 failed, and 19 ignored in the
data crate. The two graph errors are read deadlines. The other failures are
the retained metadata capacity check, the sealed sibling loader assertion,
and the Wasm failure fixture's empty export receipt. No later workspace crate
test ran in this cut.

### Final CI correction TODOs

- [x] Include actual retained target and artifact metadata in the lease test's
  expected byte count. Use the production metadata accounting contract. Keep
  the exact capacity boundary and drop-release assertions. Change production
  accounting only if its held bytes do not match its retained values.
- [x] Replace the Wasm failure fixture's two declared implementations with one
  declared Wasm implementation. Test ambiguous admission separately. Preserve
  all four fault modes, their exact error codes, empty committed results,
  restart, and failed retry checks. Keep the approved plugin-type rule and
  absence of execution fallback.
- [x] Reproduce the sealed sibling loader assertion with the full error value.
  Preserve the real sibling dependency and accessor call. Correct the assertion
  only after identifying whether its error owner, code, or control failed.
- [x] Run the two unchanged graph deadline cases without concurrent build or
  qualification load. Preserve 256 records, large traversal, every assertion,
  and the existing deadlines. Record the result before changing source.

The two unchanged graph cases pass in isolation: 2 passed and 0 failed in
390.33 seconds, session 86044, exit 0. The command used the original full-feature
test executable, `--test-threads=1`, and the two exact test filters. The log is
`/tmp/araphor-native-ci-graph-isolated-20261013.log`. The 256-record bounds and
large traversal inputs, assertions, byte limits, and deadlines are unchanged.
The sibling loader case also passes without concurrent load.

The first isolated attempt used a copied executable outside a `deps` directory.
The existing compiler dispatcher did not recognize that path as a test binary;
both graph cases failed before graph computation with compiler process exit 101.
The original executable fixes that launch error. It is not a native or graph
implementation change. The copied attempt is not qualification evidence.

The corrected full-feature focused command returns 21 passed and 0 failed in
109.28 seconds, session 19394, exit 0. It covers 18 loader checks, the exact
retained metadata boundary, ambiguous admission, and all four Wasm fault modes.
The log is `/tmp/araphor-native-ci-corrections-focused-20261013.log`.
The metadata test now counts owned revision, target, and artifact allocation.
Production already holds those allocations. The fault fixture uses one Wasm
declaration. A separate test checks exact ambiguity rejection before activation
or revision storage. The sibling test preserves the expected invalid null ABI
result and adds its full unexpected error to the assertion diagnostic.
These changes affect tests only. Native production code and retained production
artifacts remain unchanged.

Run the final repository CI procedure with `RUST_TEST_THREADS=4` to reduce host
contention. This changes test scheduling, not product limits or test coverage.
Keep internal concurrency checks, original deadlines, and all workloads. Run
the complete graph production case after that CI process reaches its terminal
result. Use its existing debug logs and a fresh output directory.

CI session 23876 was stopped with exit 143 before its workspace tests. The
loader diagnostic had first been added to the null-accessor test instead of the
sibling test. The correction gives both tests their exact diagnostic and keeps
both assertions unchanged. This source edit requires a new final CI run. The
stop was for that source correction, not a polling timeout. Its log remains
`/tmp/araphor-native-rust-ci-qualified-20261014.log`.

The corrected null and sibling diagnostics pass the full-feature loader cut:
18 passed and 0 failed, session 66984, exit 0. The log is
`/tmp/araphor-native-ci-loader-diagnostics-20261014.log`. The assertions and
one-second controls are unchanged.

### SQL dependency refresh qualification investigation

Final CI session 63882 returned exit 101 at source `913c73e4`. Its log is
`/tmp/araphor-native-rust-ci-qualified-final-20261014.log`. The source record is
`/tmp/araphor-native-final-ci-source-qualified-20261014.json`. Formatting,
workspace check, and strict all-target, all-feature clippy passed. The data
crate returned 612 passed, 0 failed, and 19 ignored in 2,314.95 seconds. All
five failures from session 56085 passed, with their original workloads and
deadlines. The Control crate returned 188 passed, 0 failed, and 2 ignored.

The `mithril-e2e` crate returned 190 passed, 1 failed, and 528 ignored in
862.16 seconds. `discovery::packages::tests::analysis_packages_contract`
failed at automatic source replacement. The upstream `count` result was fresh
at revision 31. The dependent `repeated` result remained stale at revision 24
through the existing 120-second wait. Later workspace tests did not run.
This CI command used `RUST_TEST_THREADS=4`; it did not change product limits,
test deadlines, assertions, or internal concurrency checks.

The retained passing native case includes the same SQL replacement checks.
That case committed fresh `repeated` revision 32 from upstream revision 31.
Source review found no native artifact identity work in SQL execution. The
worker remained active in the failed case. Existing diagnostics do not show
whether scheduling, a read, evaluation, or commit prevented the next result.
No cause is confirmed. Do not change the scheduler or test deadline from this
timeout alone.

- [x] Run the unchanged original `analysis-packages` case without a concurrent
  build or qualification job. Use the retained production binary, a fresh output
  directory, and existing debug logs. Record its terminal result before any
  source correction.
- [ ] Obtain a passing final repository CI result and a passing complete graph
  notification result. Keep every test, input, assertion, and product deadline.

The quiet original case returned exit 0, session 96577. Its log is
`/tmp/araphor-native-qualified-analysis-packages-20261014-retry.log`; its output
directory is `/tmp/araphor-native-qualified-analysis-packages-20261014-retry`.
It uses the same retained binary and native artifact environment as the other
production cases. `RUST_LOG=info,araphor_data::package=debug` selects existing
logs. The original SQL and Wasm checks pass. Fresh `repeated` revision 32 uses
upstream revision 31. The result and binary digests, source reference, command
configuration, and terminal status are in
`/tmp/araphor-native-qualified-analysis-packages-20261014-retry-proof.json`.
This original case does not execute the native detector. Its pass does not
prove the cause of the preceding CI timeout.

Final CI session 5646 ran the same covered source with `RUST_TEST_THREADS=1`.
Its log is `/tmp/araphor-native-rust-ci-serial-final-20261014.log`. The source
record is `/tmp/araphor-native-final-ci-source-serial-20261014.json` and includes
SHA-256 values for 1,392 tracked Rust, Cargo, toolchain, and CI files. The runner
uses one test worker. It retains all tests, internal concurrency, workloads,
assertions, and product deadlines. It returned exit 101. The data crate returned
612 passed, 0 failed, and 19 ignored in 5,031.11 seconds. Control returned
188 passed, 0 failed, and 2 ignored in 243.84 seconds. The end-to-end crate
returned 190 passed, 1 failed, and 528 ignored in 2,147.35 seconds. The same SQL
replacement case failed with fresh upstream revision 31 and stale dependent
revision 24. Later workspace tests did not run. Test parallelism alone does not
explain this repeated failure. Do not run another full workspace cut before
focused diagnosis and correction.

### SQL replacement diagnostic TODO

- [x] Temporarily return the automatic evaluation error that reconciliation
  currently discards. Run only the original current-thread SQL case. Keep its
  inputs, assertions, and deadlines. Record the error and remove the temporary
  behavior before final qualification. Add no dependency or product option.
- [x] Record automatic evaluation outcomes through the complete original wait.
  The first diagnostic returned `AnalysisBusy: query evaluation capacity` in
  263.13 seconds, session 86203, exit 101. Its log is
  `/tmp/araphor-sql-focused-diagnostic-20261014.log`. One returned Busy error does
  not prove sustained starvation. Preserve the original retry behavior while
  collecting bounded package, export, duration, and error-resource fields.
- The normal-retry diagnostic returned 1 passed and 0 failed in 305.50 seconds,
  session 40336, exit 0. The log is
  `/tmp/araphor-sql-focused-outcomes-20261014.log`. Eight outcome records show
  one upstream commit, three dependent capacity conflicts, three unchanged
  upstream evaluations, and one dependent commit. This pass does not explain
  the repeated full-CI failure.
- [x] Confirm whether synchronous admission on the runtime thread causes the
  failure. The test uses a current-thread runtime; the passing production CLI
  uses a multithread runtime. The supervisor reads and decodes bundles and checks
  admission before it dispatches evaluation to a blocking task. This path existed
  before native execution. The diagnostic measures its duration during failure.
  Temporarily measure bundle loading, admission, prepared-export skips, worker
  queue time, and the original Inspect wait. Use bounded fields and retain the
  original runtime, retries, inputs, assertions, limits, and deadlines. Remove
  the diagnostic before final qualification.
- The workspace-feature focused case returned exit 101 in 379.44 seconds,
  session 12126. Its log is
  `/tmp/araphor-sql-workspace-focused-timing-20261014.log`; bounded timing is in
  `/tmp/araphor-sql-preparation-timing-20261014.jsonl`. During the original
  replacement wait, preparation consumed 111,518 milliseconds. All nine
  dependent evaluations returned query evaluation capacity errors. Inspect
  completion was delayed by the synchronous preparation work. The final
  Inspect returned Unavailable after the unchanged 120-second window.
- [x] Move supervisor preparation into its existing blocking task. Keep the
  operation permit until that task exits. Establish cancellation and authority
  observation before dispatch. Check control after admission and before state
  changes. Preserve package admission, prepared-export skips, typed failures,
  grant expiry, revocation, and the existing 30-second operation deadline.
  Add a deterministic stop-during-admission test with the existing authority
  fixture. Assert event order and unchanged retained state. Add no benchmark,
  quota, dependency, or new scheduler. Remove all temporary timing code.
- [x] Pass the operation control to the shared failure-status commit check.
  A cancelled blocking task must not write failure metadata or stale result
  heads after it obtains the writer. Preserve error classification and the
  active-generation comparison. Update both callers of the failure owner.
- [x] Give the admission-stop fixture an explicit UInt64 SQL result. The first
  focused run returned two passed and one failed, session 8601, exit 101.
  The new fixture used an integer literal that did not match its UInt64 port.
  Preserve production schema validation and the event-order assertions.

The corrected interruption cut returned 3 passed and 0 failed in 46.53 seconds,
session 59051, exit 0. Its log is
`/tmp/araphor-supervisor-correction-focused-20261014-retry.log`. It checks
existing busy and running-stop behavior plus stop during admission. The latter
checks stop before admission release, retained operation capacity until task
exit, and unchanged activation and complete result records.
The unchanged original SQL case returned 1 passed and 0 failed in 296.44
seconds with workspace features, session 13933, exit 0. Its log is
`/tmp/araphor-sql-owner-correction-workspace-focused-20261014.log`; the source
record is
`/tmp/araphor-sql-owner-correction-workspace-focused-source-20261014.json`.
The source guard confirms all 1,390 recorded source and configuration hashes.
The affected native and Wasm cut returned 5 passed and 0 failed in 174.68
seconds, session 52507, exit 0. Its log is
`/tmp/araphor-supervisor-native-wasm-cancellation-focused-20261014.log`.
It includes the new cancelled-failure commit regression, real-library native
cancellation, revocation, expiry and typed failures, plus existing Wasm
cancellation and all four Wasm fault modes. The tests retain the original
assertions and deadlines. No temporary diagnostic code remains.
Formatting passes, session 29137, exit 0. Strict workspace all-target,
all-feature clippy passes with warnings denied in 65 seconds, session 81331,
exit 0. Its log is `/tmp/araphor-supervisor-correction-clippy-20261014.log`.
No new full CI process has started. Final qualification remains Not done.
- [x] Correct the confirmed cause in its owner, preserve the complete original
  case, and pass focused verification before another full workspace cut.

Three Sol 6.1 reviewers checked the connected SDK, native owner, and proof
records. No new source defect was found. Library handles remain held through
producer release and host output copies. Typed compatibility errors and actual
artifact provenance remain consistent with the installed plugin type. The
supporting inventory and design records distinguish the baseline from the
implemented native path. They retain the Linux x86-64 GNU proof boundary and
the pending workspace and complete graph gates. This review does not replace
those terminal results.

### Installed native production qualification TODO

- [ ] Extend the existing `analysis-packages` scenario with an explicit native
  qualification entry point. Require source-built artifacts. Use the existing
  builder to make a BurstDetector folder, then install and run it through the
  production package owner. Preserve the SQL and Wasm scenario and all detector
  checks. Qualify the migrated native graph exports with retained graph inputs in
  a separate store when their immutable revisions match the Wasm bootstrap.
  Run with Python absent from PATH. Run the affected context, profile restart,
  and complete graph notification cases without changing workloads or deadlines.
- [x] Return a typed scenario error when Python is available. Do not use
  `expect_err` in the qualification owner. Compare recorded native artifact and
  closure identities with the authored bytes. Apply Burst parameters only to its
  bundle. Compare the actual nested graph fields and label the native case in
  its result. Keep scenario actions on the existing qualification owner.
- [x] Qualify a 185-record selected graph input through the actual native Process
  library. Use the existing graph window size and graph input adapter. Give each
  record an exact cursor, task, and time identity. Compare the complete native,
  Wasm, and trusted outputs, evidence, reasons, and checkpoint. Keep the existing
  deadline and query limits. This is a functional transport test, not a benchmark.

### Native host-fault proof TODO

- [x] Add native-only panic and abort modes to the source-built SDK test guest.
  Prove that an unwind panic returns a typed failure through the loaded library.
  Use a child test host for a fatal native abort. Install and commit state before
  the fault, close the parent's store handles, then reopen after child exit.
  Check the prior complete output, checkpoint, activation, retry, and absence of
  Wasm fallback. The child is a test host; production native execution stays in
  Araphor's process. Reuse the fixture's store and owner setup for a retained path.
- [x] Supply the existing temporary directory to `Fixture::open`. The first
  host-fault test returned ENOENT before any native action because its new parent
  directory did not exist. Preserve all fault, state, and restart assertions.

### Native buffer-accounting correction TODO

- [x] Account for native host transport storage through the existing query
  budget. Reuse SDK array validation and owned-array copies. Keep the native
  data contract separate from optional Wasm quotas. Apply the existing host output
  capacity before host output copies. Bound native error fields before copying
  them with the existing 1,024-byte component error transport limit.

The SDK copy correction passed 62 native SDK tests and clippy with warnings denied.
It uses the shared owned-array copy and validates arrays before allocation. The
host supplies output limits through the Rust invocation API; the input context
keeps its declared limits. One byte budget covers output metadata, data, reasons,
and checkpoint copies. Native output no longer requires the two IPC round trips.
The oversized error test checks the length before dereference and checks release.
These focused SDK checks do not qualify the corrected loader or built libraries.

- [x] Release the new parity test's replay output guards after their assertions
  and before a separate graph derivation. The first consolidated run returned
  `AnalysisBusy: query output capacity` because the test retained the prior
  outputs during the next full reservation. Preserve every parity assertion and
  the production query capacity.

### Native file-identity correction TODO

- [x] Use the existing `rustix` file API to retain sealed root and package
  dependency files on Linux. Link these retained files into the private package
  directory so `$ORIGIN` resolves the same dependency bytes. Hold file and library
  handles through every release. Open each system file once for compatibility
  inspection. Check the device and inode of an already loaded system image before
  package initialization. Reject a changed loaded identity with Conflict.
  Validate the selected closure and file identities before the accessor call.
  Add tests for replacement and seals. Add no dependency, namespace, process,
  environment restriction, or isolation claim.
- [x] Check a declared package dependency's ELF SONAME when it is present.
  Require that name to match the declared dependency name. Reject aliases that
  can select the root or a system library. Preserve valid files without SONAME
  and the existing declaration schema.
- [x] Derive Linux system-library directory names from the exact build target,
  including i386, ARM ABI, little-endian PowerPC and MIPS, and x32 names. Retain
  standard library directory fallbacks. Check the artifact's pointer class as
  well as its format, architecture, and endianness. Add no platform allowlist.
- [x] Use a valid 52-byte ELF32 header without sections for the new synthetic
  pointer-class fixture. Its first run returned Invalid during parsing because
  its section table had no valid string-table index. Preserve the incompatible
  class assertion and production validation. Add no unnecessary section table.
- [x] Validate symbol availability against the root's reachable dependency
  closure. An extra declared file cannot supply an unreachable symbol. Check
  transitive system requirements before package initialization. Use the existing
  artifact parser and typed compatibility errors. Add a missing or unreachable
  dependency fixture; preserve valid declared closures.
- [x] Map native function-table validation errors through the native error owner.
  Preserve the SDK source and operation. An incompatible version returns
  Unsupported; malformed table values retain their typed code. Add a real
  wrong-version library fixture. Do not classify every ABI failure as Invalid.

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

### Plugin-type decision correction TODO

- [x] Record D4 as explicitly approved: a native plugin runs native;
  a Wasm plugin runs Wasm. Remove the proposed global Wasm default, operator
  target option, stored target preference, and runtime target-switch workflow.
  Keep shared-source builds, parity fixtures, artifact compatibility, actual
  artifact identity, and the existing package lifecycle. Correct the parent
  records. Preserve the incomplete source drafts. Resume work only after the
  user's explicit approval.

### Explicit approvals and resumed corrections

The user explicitly approved D4 with `D4 approved.`. Execution follows the
installed plugin type. The user then explicitly approved `libloading 0.9.0`,
direct use of the locked `object 0.40.0`, and the configured-cap behavior.
An enabled hard native memory or CPU cap returns Unsupported for native
execution. SQL and Wasm remain usable. Work resumes under these approvals.

- [x] Remove the draft Run target option and stored target preference. Dispatch
  the implementation declared by the plugin and record its actual artifact.
- [x] Keep native cap checks on native admission and execution. Do not reject
  package-owner construction or SQL/Wasm execution for an enabled native cap.
- [x] Remove the draft blanket rejection of loader environment variables.
  Validate the declared library files and use scoped loading.
- [x] Check dependency names, symbols, versions, and content throughout the
  native closure. Add the missing native loader and failure tests.
- [x] Reuse the existing SDK SensitiveAccess test fixture. Remove its duplicate
  module declaration and retain native exchange and release assertions.
- [x] Preserve native loader error codes in package readiness and Control
  package-operation details. Account for native qualification and dependency
  storage in retained package snapshots.
- [x] Map returned native SDK errors to the matching package error code and
  retain their source. Report a Failed computation as Incomplete, as the Wasm
  execution path does. Keep invalid output distinct from execution failure.
- [x] Check host cancellation and deadline after every native call, including
  a returned SDK error. Preserve the host cancellation or deadline error before
  reporting a late native completion.
- [x] Compile the new parity fixtures with the shared test error type and
  existing EvidenceRecord conversions. Preserve complete input and output
  comparisons.
- [x] Check cancellation after native compatibility inspection and before each
  library load or accessor call. Reject work outside the active control lifetime.
- [x] Select the graph parity fixture's credential fact by its typed value.
  Do not depend on its position in a sorted vector. Compare Gapped coverage
  with the same detector fixtures.
- [x] Correct the new running-expiry fixture. Its one-second grant expires
  during native package admission, before activation. Use a five-second test
  grant to reach native computation. Keep the existing five-second activation,
  task, and cleanup deadlines. Retain separate rejection proof for an already
  expired native grant.

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
