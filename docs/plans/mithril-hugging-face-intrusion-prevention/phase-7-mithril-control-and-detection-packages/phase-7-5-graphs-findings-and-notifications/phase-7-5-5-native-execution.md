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

**Done** on the qualified Linux x86-64 GNU host with glibc 2.39. Native SDK,
source builds, declared-plugin execution, compatibility, provenance, export
parity, lifecycle, host-fault restart, and installed production proof pass.
Final CI session 25541 returns exit 0 for source
`5e9364543093e3e18da03e4d51e6dd28cc057982`. All 1,390 recorded source hashes
remain unchanged. The eight-deliverable acceptance record is below.

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
- [x] Qualify shared-source export parity, installed execution, failures, and
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
- [x] **7. Qualify installed production execution and final CI.** Extend
  `analysis-packages` with a real source-built SDK dual-target detector. Install
  and run it without rebuilding Araphor. Prove target parity and actual artifact
  identity in each result. Run a migrated algorithm with Python unavailable
  and affected existing production cases.
  Record exact source, artifacts, platform, configuration, commands, and terminal
  results. After the last covered source edit, run one final
  `bash .github/scripts/verify-rust-ci.sh` process to its terminal result.
- [x] **8. Review connected source and close the records.** Review callers,
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
This initial proof covers the adapter and source build. It did not qualify
package admission, installed execution, export parity, production cases, or
final CI. Built-folder installation was pending at that cut. The later installed
production records below supply that proof. Final qualification closes in the
acceptance record below.

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
At that focused cut, the complete graph case and final CI remained Not done.
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
not a proven cause. The planned retry required the retained binary, existing
graph debug logs, a fresh output directory, and unchanged deadlines and inputs.
The later owner-correction case below passes with a new binary. That pass does
not prove the cause of this earlier package-read failure.

The builder test correction returns clock and file-read errors through the
existing error owner. All file and dependency assertions remain. Its final
focused tests returned 6 passed and 0 failed; strict all-target clippy returned
exit 0. Logs are `/tmp/araphor-native-builder-test-final-20261013.log` and
`/tmp/araphor-native-builder-clippy-final-20261013.log`.

### Installed production proof after the owner correction

Source `b50107eb3551e61c405b6b15f5b5cdb093b1c8f2` includes the supervisor and
failure-commit correction. Build session 4718 returned exit 0 in 45.89 seconds.
The retained binary is
`/tmp/araphor-native-qualified-bin-20261014-owner-correction/mithril_discovery_test`.
Its SHA-256 is
`2b441e15d843083dd6eb7c7ef25e98aad6634e1e4eb5055bb54bd0da1e0186a8`.
The source record is
`/tmp/araphor-native-production-owner-correction-source-20261014.json`.

Session 8227 returned exit 0 for `analysis-packages-native`. Its `result.json`
records `PASS` and `python_unavailable: true`. The real client installs the
BurstDetector native folder without a host rebuild. The result checks native
artifact and closure identity, four inputs, three evidence records, threshold 3,
reason `example-burst.THRESHOLD`, checkpoint `4`, restart, retry, and trust
revocation. The three migrated graph exports record equal findings,
relationships, checkpoint meaning, and replay. The original SQL and Wasm
assertions also pass. Fresh SQL dependent revision 32 uses upstream revision 31.

The result is
`/tmp/araphor-native-qualified-analysis-packages-20261014-owner-correction/result.json`.
The proof is
`/tmp/araphor-native-qualified-analysis-packages-20261014-owner-correction-proof.json`.
The log is
`/tmp/araphor-native-qualified-analysis-packages-20261014-owner-correction.log`.
The proof records the command, source, binary and result hashes, Linux x86-64
GNU host, and the unchanged source-built library directory
`/tmp/araphor-native-built-20261013-final`. This is lightweight qualification;
it makes no physical, performance, or additional platform claim.

The complete graph notification case returned exit 0 in session 64467.
Its `whole_case` log records 1,754,425 milliseconds. It uses the same source
`b50107eb3551e61c405b6b15f5b5cdb093b1c8f2` and retained binary with SHA-256
`2b441e15d843083dd6eb7c7ef25e98aad6634e1e4eb5055bb54bd0da1e0186a8`.
The result is
`/tmp/araphor-native-qualified-graph-20261014-owner-correction/result.json`.
The proof is
`/tmp/araphor-native-qualified-graph-20261014-owner-correction-proof.json`.
The log is `/tmp/araphor-native-qualified-graph-20261014-owner-correction.log`.

The command is `mithril_discovery_test --case graph-notification` with
`--output-directory /tmp/araphor-native-qualified-graph-20261014-owner-correction`.
It uses `PATH=/tmp/araphor-no-python`, the final native library directory,
`ARAPHOR_NATIVE_TARGET=x86_64-unknown-linux-gnu`, and
`RUST_LOG=info,mithril_e2e::discovery::graph_notification=debug`.
All 12 incident cards, replay contracts, density checks, 64-record and 185-record
windows, notification, restart, and notification resume pass. The original
workload, assertions, and deadlines are unchanged. The result records
`LIGHTWEIGHT`, canonical replay equality, and no physical action, performance,
provider issuance, or cross-node qualification.

The graph case runs its existing declared-Wasm packages. Its traversal label
`native` identifies native evidence and storage; it does not prove execution
of a native plugin. Session 8227 separately proves the actual native plugins.
This graph PASS does not prove that the owner correction resolved the earlier
independent one-second package-read failure.

Final CI session 80004 returns terminal exit 101. Its log is
`/tmp/araphor-native-rust-ci-owner-correction-final-20261014.log`; its source
record is `/tmp/araphor-native-final-ci-owner-correction-source-20261014.json`.
The source is `b50107eb3551e61c405b6b15f5b5cdb093b1c8f2`.
The command uses `CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=4` with
`bash .github/scripts/verify-rust-ci.sh`. Formatting, workspace check in
13.22 seconds, and strict clippy in 0.52 seconds pass. Data tests return
614 passed, 0 failed, and 19 ignored in 2,122.55 seconds. Control tests return
188 passed, 0 failed, and 2 ignored in 119.38 seconds. Session 80004 returns
terminal exit 101. The end-to-end crate returns 190 passed, 1 failed, and
528 ignored in 726.33 seconds. The original SQL replacement case passes.
`observability::query::tests::observability_query_upload` fails. Later workspace
tests did not run. Final CI and acceptance were open at that failed cut.

### Observability query upload investigation TODO

- [x] Read the terminal failure detail for
  `observability::query::tests::observability_query_upload` in session 80004.
  The unchanged test from the exact CI binary reproduces the failure in session
  86054: exit 101 in 45.30 seconds. Both failures report WouldBlock when
  AnalysisStore obtains its writer lock. The original workload, assertions,
  query bounds, and deadlines are unchanged.
- [x] Cancel and join supervisor work before `serve` returns. The supervisor
  stop path dropped reconciliation before this correction while its
  `spawn_blocking` task still retained the owner and store. ClientListener already
  awaited `serve`; store reopen could race that detached work. Keep cancellation observation prompt, then wait for
  dispatched blocking work to exit. Cover authority-change cancellation as well
  as shutdown. Add no scheduler, store, dependency, or product option.
- [x] Correct the new admission-stop regression to distinguish prompt stop
  observation from shutdown completion. Retain event order, the held operation
  permit until task exit, and unchanged activation and complete result records.
  Preserve all original scenario inputs, assertions, bounds, and deadlines.
- [x] Pass the affected Data checks, original SQL case, formatting, and strict
  clippy after the shutdown correction.
- [x] Pass final CI after the last source edit. Session 25541 returns exit 0.
  The source guard verifies all 1,390 recorded files unchanged.

The correction cancels and joins dispatched supervisor work for stop requests
and authority changes before `serve` returns. Activation-page reads and orphan
pruning also remain awaited. ClientListener can reopen the store after service
shutdown completes. Cancellation is prompt, but shutdown completion waits for
blocking work. A stalled native call can therefore delay shutdown.

The current admission-stop test polls the supervisor after stop. It checks
responsive cancellation, a pending shutdown join, three available operation
permits while admission is held, four permits after task exit, and unchanged
activation and complete result records. It does not require service return
before admission release.

The unchanged upload test passes with the workspace feature union: 1 passed,
0 failed, and 0 ignored in 48.70 seconds, session 1402, exit 0. Its build took
2 minutes 14 seconds. Its log is
`/tmp/araphor-observability-query-upload-corrected-20261014.log`.
The source capture is
`/tmp/araphor-native-supervisor-shutdown-source-20261014.json` with hashes for
1,390 files. It records base commit `b50107eb`, correction commit
`5e9364543093e3e18da03e4d51e6dd28cc057982`, focused results, and exact test binary
SHA-256 values. The correction changes three source files with 60 additions and
18 removals.

The affected owner cut returns 5 passed and 0 failed in 45 seconds, session
36210, exit 0. Its log is
`/tmp/araphor-supervisor-joined-shutdown-focused-20261014.log`.
The original SQL case returns 1 passed and 0 failed in 263.79 seconds, session
60496, exit 0. Its log is `/tmp/araphor-sql-joined-shutdown-focused-20261014.log`.
Formatting returns exit 0 in session 46958. Strict clippy returns exit 0 in
66 seconds, session 5111. Its log is
`/tmp/araphor-supervisor-joined-shutdown-clippy-20261014.log`.

Sole final CI session 25541 returns exit 0 for correction commit `5e936454`.
Its log is `/tmp/araphor-native-rust-ci-joined-shutdown-final-20261014.log`.
Its source record is `/tmp/araphor-native-final-ci-joined-shutdown-source-20261014.json`.
The command is `CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=4 bash .github/scripts/verify-rust-ci.sh`.
The final terminal counts and source guard are in the acceptance record below.
The reproduced writer-lock failure is separate from the earlier independent
package-read failure.

The SDK, loader, algorithms, and native artifacts are unchanged. Earlier
parity, host-fault, and current-library control checks remain retained evidence.
The native production PASS in session 8227 and complete graph PASS in session
64467 retain their exact `b50107eb` source and binary cuts. They are not new
qualification of the shutdown source. The upload, five owner checks, and original
SQL case prove the affected cleanup behavior at the correction source.

### Bundle-read correction TODO

- [x] Reuse the already loaded immutable bundle during installation, explicit
  evaluation, and preparation. Reuse it only when its root matches the activation
  root. Load the activation's own root for an independently installed dependency.
  Preserve grant checks, authority admission, commit authorization, retry identity,
  and activation generation checks. Add no resident bundle cache. Run dependency
  authority tests and the native interruption qualification after this change.

### Package help correction TODO

- [x] Replace the install help's SQL-only export description with the supported
  package export behavior. Keep request parsing and execution unchanged.
- [x] Verify the CLI through the passing final Rust gate. Session 25541 returns
  62 CLI tests passed, 0 failed, and 1 ignored.

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

Final CI session 56085 reported a failure in
`graph::tests::control_graph_context_and_result_bounds_keep_required_progress`.
The initial observation preceded its terminal output. The test uses 256 records,
three large context facts per record, and checks complete progress, 256 findings,
result byte bounds, and context bounds. The terminal result below supplies the
failure detail. The later isolated checks retain the inputs, assertions, byte
bounds, and deadlines.

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
- [x] Obtain a passing complete graph notification result. Session 64467 passes
  with every original input, assertion, and product deadline.
- [x] Obtain a passing final repository CI result. Keep every test, input,
  assertion, and product deadline.

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
existing busy and running-stop behavior plus stop during admission. At that
historical source cut, the admission test required service return before
admission release. It retained operation capacity until task exit and checked
unchanged activation and complete result records. The later shutdown correction
above preserves responsive stop but requires service return after the task join.
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
No new full CI process had started at that focused cut. Session 80004 later
returns exit 101, as recorded above. Qualification remained open at that cut;
the later joined-shutdown final CI passes.
- [x] Correct the confirmed cause in its owner, preserve the complete original
  case, and pass focused verification before another full workspace cut.

Three Sol 6.1 reviewers checked the connected SDK, native owner, and proof
records. No new source defect was found. Library handles remain held through
producer release and host output copies. Typed compatibility errors and actual
artifact provenance remain consistent with the installed plugin type. The
supporting inventory and design records distinguish the baseline from the
implemented native path. They retain the Linux x86-64 GNU proof boundary and
the workspace and acceptance gates that were pending at that review cut.
The complete graph case and final CI now pass. This review does not replace
those terminal results.

### Installed native production qualification TODO

- [x] Extend the existing `analysis-packages` scenario with an explicit native
  qualification entry point. Require source-built artifacts. Use the existing
  builder to make a BurstDetector folder, then install and run it through the
  production package owner. Preserve the SQL and Wasm scenario and all detector
  checks. Qualify the migrated native graph exports with retained graph inputs in
  a separate store when their immutable revisions match the Wasm bootstrap.
  Run with Python absent from PATH. Commit `d88f7280` implements this entry point.
  The owner-correction production cut above passes the same native case.
- [x] Run the context and profile restart cases. Retain their exact historical
  source and results above; do not treat them as proof of the later owner change.
- [x] Pass the complete graph notification case after the owner correction.
  Session 64467 retains its original workload, inputs, assertions, and deadlines.
  This result does not establish the cause of the earlier independent read error.
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

The preparation and decision records below describe earlier source cuts.
The later approved decisions and proof above replace their pending status and
worker requirements.

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
| 3. Execution owner | `a38dec4`, `b50107eb`, `5e936454`; [native owner proof](#native-owner-and-parity-verification) and [shutdown correction](#observability-query-upload-investigation-todo): authorization, cooperative cancellation, retained library lifetime, and joined shutdown. |
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
