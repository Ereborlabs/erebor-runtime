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

**Not done.** The component runtime, installed domain adapters, production
dispatch change, and Rust qualification cases are implemented. Full production
qualification and the final shared Rust procedure remain pending. The TODOs
below record the required corrections and proof.

### Goal deliverable review

The review uses all six approved goal deliverables. A source commit does not
close a verification gate. The phase remains **Not done**.

| Deliverable | Source and commit | Remaining proof |
| --- | --- | --- |
| 1. SDK component path | Generated bindings, component build, and detector example: `c77eeec2`. Typed runtime fixtures: `d1de114d`. Owned Arrow buffers and six rebuilt components: `f274e413`. | The current SDK suite has 45 passes. The shared computation suite has 13 passes. The build proof records equal component bytes from both builds. |
| 2. Production Wasmtime execution | Compiler worker, bounded cache, guest limits, restricted imports, shared query budget, native inputs, and installed execution: `a6f870a3`. | Final workspace tests are running. Production data and fuel limits differ from the corpus test limits. |
| 3. Installed domain outputs | Typed reason storage and historical JSON: `6ca5ed3c`. Domain adapters and retained package references: `d7aaf21a`. | A fresh production finding-to-notification case has no pass. |
| 4. Current algorithms | AR-01 through AR-03 and AR-05 through AR-07 use installed execution in `d7aaf21a`. AR-04 selection stays on the host. Its installed transport case is in `8f150fd4`. | Corpus output parity passes with test-only limits. Production parity and the fresh context transport case remain open. |
| 5. Lifecycle and recovery | Shared lifecycle fences are in `a6f870a3`. Checkpoint, retry, upgrade, rollback, removal, and retained-reference tests are in `fcd587ae`. | Focused lifecycle and overlap tests pass. The final workspace result and fresh production restart case remain open. |
| 6. Qualification and closure | The new detector installation and context transport cases are in `8f150fd4`. | Run all four fresh production cases, finish the final Rust procedure, and record the final review and result. |

The current Rust source is committed through `8f150fd4`. Its 1,558 source file
hashes remain equal to the v12 manifest after the commits. Formatting,
workspace check, strict Clippy, and test linking pass. Workspace tests have
no terminal result. The production cases `analysis-packages`,
`context-roundtrip`, `profile-restart`, and `graph-notification` still require
fresh results on this source.

The corpus test permits 64 MiB of data and 8 billion fuel units. Production
permits 32 MiB and 100 million fuel units. The test result does not prove that
the production limits support the same inputs. Automatic approval review
rejects the proposed production limit increase. Explicit user approval is
pending. Keep this gate open and remove the test-only allowances only after
the approved correction passes the same production and test checks.
The production dispatch has already changed. The required complete production
equivalence gate did not pass before that change. Source review and test-only
corpus parity do not close this requirement.

### Implementation TODOs

The approved goal starts from the completed local SQL lifecycle at `4b8b524b`.
The current source has these required changes:

- [x] Add generated guest and host WIT bindings, shared bounded Arrow IPC
  exchange, a reproducible component build, and a complete Rust detector example.
- [x] Add Wasmtime admission, execution, cancellation, resource accounting, and
  a bounded compiled-code cache under the existing package execution owner.
- [x] Extend SQL-only input selection, evaluation, fixture replay, and readiness
  to admitted components. Preserve the shared authority and atomic commit path.
- [x] Connect installed discovery, subject, relationship, and finding outputs
  to the existing host adapters. Support declared reason codes and typed details
  without a new host enum entry for each detector.
- [ ] Build the shared AR-01 through AR-07 computations as components. Prove
  installed equivalence before removing fixed production dispatch. Keep AR-04
  selection on the host and retain current HF-XNODE causality limits.
- [ ] Verify dependency evaluation, corrections, empty replacements, retries,
  checkpoints, restart, stale results, updates, rollback, removal, concurrent
  execution, cancellation, revocation, traps, limits, and scope isolation.
- [ ] Extend the production `analysis-packages` case with a new SDK detector.
  Run `context-roundtrip`, `profile-restart`, and `graph-notification` through
  installed execution. Run the final shared Rust procedure after the last edit.
- [ ] Review correctness, completeness, shared validation, and code size. Update
  the source review guide and result with exact proof. Commit each deliverable.
- [x] Keep revision encoding and retained-artifact reads in one lifecycle
  module. Keep metadata retry tests separate from runtime lifecycle tests.

Work in the supplied checkout. Add no worktree or complex shell test harness.
Reuse native graph storage and bounded traversal. Add no separate package store,
authorization owner, notification path, or algorithm implementation.

### Execution correction TODOs

- [ ] Recover filesystem space after the v12 test link failure. Remove debug
  sections only from inactive generated executables. Check every loaded
  section before and after cleanup. Keep source, native archives, component
  artifacts, logs, and proof files. Retry the final Rust procedure on the same
  source and record its result.
- [x] Prove two successful Wasm computations overlap through one installed
  owner. Use the shipped discovery `groups` component and two authorized
  tenants. Extend only the existing test guest-entry signal with a release
  channel bounded by the guest deadline. Require both guests to enter the
  real host import before release. Check separate keys, members, samples,
  and counts of 5 and 18. Keep production limits, control checks, WIT,
  artifacts, and the separate mutable-state proof unchanged.
- [x] Observe the fresh revision 2 Wasm receipt at the authorized upgrade
  commit in `wasm_installed_lifecycle`. Use the existing test authority and
  clear its observer after the update. Require value 7 and equal immutable
  receipt fields. Check a later stale flag against the saved evaluation clock.
  Keep production clock behavior, deadlines, and resource limits.
- [x] Give `analysis_extract_snapshot` an explicit finite 30-second read
  control. Its projection commits three writes inside the retained snapshot.
  Keep every snapshot, missing-input, and cleanup check. Keep the production
  default and the separate deadline tests unchanged.
- [x] Record the full Rust regression failure and the unchanged serial graph
  bound test result. Diagnose the remaining lifecycle and query fixture errors.
  The regression does not cover the later fixture corrections.
- [x] Serialize tests that share a cached installed analysis owner. The parallel
  discovery baseline tests return `AnalysisBusy` for query output capacity.
  Hold one fallible mutex guard per test or fixture helper. Keep every discovery
  and graph assertion, production budget, and production concurrency limit.
- [x] Add the native graph snapshot read to `analysis_metadata_read_deadlines`.
  Keep typed expiry, all 16 released read slots, unchanged metadata, and fresh
  read recovery.
- [ ] Set the new component runtime data limit to 64 MiB and fuel limit to
  8 billion after the full corpus diagnostic. The 42 normal and replay calls
  pass with at most 6,741,078,368 fuel units. The previous draft limits reject
  the retained large cases. Keep guest memory at 256 MiB, guest time at five
  seconds, lifting at 32 MiB, and all lower query and descriptor limits.
  Remove test-only allowances and diagnostic output. Verify the same limits
  in production and tests. This measurement is not a performance result.
- [ ] Map the pinned Wasmtime output lifting fuel error to `Limit`. The runtime
  error type is private. Match its exact root error text. Keep the 32 MiB
  lifting limit. Require the existing 40 MiB output test to reach this error,
  return `Limit`, and permit the next evaluation.
- [ ] Select the exact active package export for an unpinned evaluation under
  the shared lifecycle lock. Keep explicit snapshots and historical pins equal.
  Keep the selected grant, complete dependency bundle, and execution checks.
  Verify that an unrelated revoked package does not prevent this evaluation.
  Require selected revocation to fail and a non-prepared target to return the
  existing unsupported-target error.
- [ ] Diagnose the discovery activation interval failure in the full Rust
  procedure. Keep the saved-profile, new-interval, and historical replay checks.
  Correct the owner or test fixture from the reproduced error.
- [ ] Give discovery revision update and removal tests an explicit finite
  30-second operation control. The default read control expires after one
  second. Keep production deadlines and all revision and replay checks.
- [ ] Give graph installed-history update and removal tests an explicit finite
  30-second operation control. Keep the historical package, witness expiry,
  restart, and removal checks. Keep production deadlines.
- [ ] Check graph installed-history progress through cursor 3 with the existing
  bounded `process_to` test helper. `process` returns the count of changed
  source windows. Keep all three input records and all history and expiry checks.
- [ ] Diagnose the discovery corpus parity failure in the full Rust procedure.
  Preserve every corpus case and correct the reproduced failure.
- [ ] Add a temporary test diagnostic at the discovery adapter evaluation
  boundary. Measure dataset IPC bytes, array capacity, binary values, offsets,
  and schema bytes near the 32 MiB input limit. Keep all 21 corpus cases and
  both delivery counts. Record the cause, then remove the diagnostic.
- [x] Compact each newly encoded binary row array before the byte check.
  Release unused builder capacity with Arrow `shrink_to_fit`. Keep the row
  values, schema, and IPC format equal. Test a bounded string round trip and
  require smaller byte limits to fail.
- [x] Copy decoded IPC arrays into owned buffers with Arrow
  `MutableArrayData` before the decoded capacity check. Keep the framing,
  schema, row, batch, and byte checks. Preserve nested nulls and the row count
  of a batch with no columns. Bound buffer and validity storage before the
  copy. Test a large binary dataset at a tight byte limit and require smaller
  limits to fail.
- [ ] Diagnose duplicate context projection and host-change rejection failures
  in the full Rust procedure. Keep exact identity and evidence validation.
- [ ] Record the Wasm trap cause and remaining fuel in a focused test
  diagnostic. Remove the diagnostic before final Rust verification.
- [ ] Measure fuel in the existing duplicate, corpus, and graph recovery
  tests. Use a temporary test-only fuel allowance if a failed call cannot
  report its full fuel cost. Keep production fuel, guest deadline,
  cancellation, and memory limits unchanged. Remove the diagnostic before
  final Rust verification. Use the results to select a reviewed correction.
- [ ] Share component data, row, batch, and checkpoint limits under the Wasm
  execution owner. Measure the full corpus with a temporary test-only 64 MiB
  data limit. Keep the production data limit unchanged during the diagnostic.
  Keep the separate 32 MiB guest-to-host lifting limit, configured query input
  limit, memory reservations, guest deadline, and cancellation checks.
- [ ] Make the forged physical-result candidate structurally valid in the
  host-change test. Change its decision and kernel result to match the forged
  physical result. Require host validation to reject it against retained wire
  evidence. Keep the identity and lifecycle attack cases.
- [ ] State each execution failure path in the review flow. The generic package
  scheduler records typed readiness and stale results. Domain adapters return
  errors to their existing owner failure and coverage paths.
- [ ] Remove the unused error conversion in Control configuration. Run the
  final Clippy check with warnings denied.
- [ ] Recover filesystem capacity after workspace test linking fills the disk.
  Remove debug sections from inactive generated executables. Verify that all
  loaded sections stay equal. Preserve source, native archives, logs, proof
  data, and the production qualification executable. Rerun the shared Rust
  procedure and the affected restart and graph cases.
- [ ] Diagnose the graph qualification read deadline. Record the failed stage,
  read operation, and last completed source cursor. Keep all corpus cases,
  graph state assertions, production deadlines, and resource limits. Remove
  temporary diagnostics before the final qualification.
- [ ] Use a private Snafu context for the temporary qualification deadline
  diagnostic. Retain the original Data error as its source. Show only the
  operation, requested source ID, elapsed time, and original deadline location.
  Add no dependency. Remove the context after the cause is known.
- [x] Install the required discovery exports for both known tenants in the
  current-profile query test. The test adds a foreign tenant record, and the
  discovery worker processes all retained tenants. Keep the query grant on the
  primary source and preserve every profile and isolation assertion.
- [x] Split a graph window when valid component outputs exceed the aggregate
  graph byte limit. Match only `GraphInvalid` with field `graph output bytes`.
  Preserve every other error. Use the installed credential component with
  256 records and 67 facts to prove the exact whole-window error, unchanged
  metadata, complete cursor progress, bounded results, and exact finding evidence.
- [x] Move the complete Wasm lifecycle proof into `package/tests/wasm/lifecycle.rs`.
  Share the existing immutable receipt comparison with the checkpoint test.
  Keep the commit observation, value, clock, retry, reopen, rollback, and removal
  checks.
- [ ] Diagnose the SQL automatic replacement timeout after the installed
  detector case. Keep the original failure decision during the diagnostic.
  Fix the cause and rerun the production qualification.
- [ ] Reuse the admitted bundle in each supervisor iteration. Remove the second
  full artifact read. Keep the grant and admission checks. Set the qualification
  wait to 120 seconds after the diagnostic shows completion at approximately
  40 seconds. Keep the production scheduler and result assertions unchanged.
- [ ] Check the local query deadline after output validation. Reject an expired
  result and release its memory lease. Verify that the caller deadline can
  remain valid while the shorter query deadline rejects the result.
- [ ] Reject host input allocation above the query limit before an installed
  call clones input or starts compilation. Use one shared query input check.
- [ ] Preserve typed component and SDK limit errors in package readiness.
  Record interrupted evaluation as incomplete. Verify no result or fallback.
- [ ] Use canonical descriptor JSON for component package digests. Arrow metadata
  maps must produce the same digest after read, install, restart, and replay.
  Preserve the existing SQL package encoding and its trust pins.
  Share this encoding with immutable component revision writes. An identical
  installation must not fail because an Arrow metadata map changes key order.
- [ ] Canonicalize all descriptors in a mixed SQL/component bundle. Keep the
  previous standalone SQL encoding. Reuse an existing immutable SQL revision
  only when its decoded descriptor, artifact, and dependencies are unchanged.
  Verify mixed-bundle digest, installation retry, reopen, and changed code.
- [ ] Share one component across its declared exports. Raise the bounded package
  and transport limits to hold the compiled artifact. Use no install hook.
- [ ] Account for Arrow schema memory. Reject compressed IPC before decoding.
  Keep host input charges until the adapter releases its evaluation.
- [ ] Compile in a fresh host worker with OS memory and CPU limits. Kill and
  reap the worker on cancellation or deadline. Accept compiled code only from
  this worker. Keep the compiler permit until the worker exits.
- [ ] Measure the source and compiled image charges for each required component.
  Set a finite cache byte limit that retains all four required components.
  Keep tests for byte and entry eviction. Retain the runtime test component
  in the shared test cache only when all five charges fit this limit.
- [ ] Prove initial memory rejection with an instantiated core module. Require
  the resource limit error before the host checks the analysis exports.
- [ ] Retain package artifacts referenced by saved domain context. Replay with
  saved parameters and current permission. Reject historical commits.
- [ ] Pass the host-selected AR-04 context dataset through an installed
  component. Verify exact identities, cutoff, revision, coverage, and omissions
  in `context-roundtrip`. Keep selection and permission on the host.
- [ ] Transfer multiple input batches, including an empty batch, through a
  real component. Verify computation across all batches.
- [ ] Supply a prior checkpoint to a real stateful component. Verify next
  state, restart, and identical retry through the production package lifecycle.
- [ ] Supply bounded native graph input and traversal output to an installed
  component. Verify the selected versions and rows without snapshot conversion.
- [ ] Reject an invalid evidence row from a real guest. Preserve a guest SDK
  limit error in installed readiness. Verify that neither failure commits output.
- [ ] Use a finite 300-second service grant in the installed detector
  qualification. Its 60-second fixture grant expired during cold component
  compilation. Keep production grant expiry checks unchanged. Verify install,
  processing, cold reopen, retry, and trust removal with the new fixture grant.

### Compiled cache memory qualification

The cache charges source bytes plus mapped compiled image bytes. The four
required components total 61,237,517 bytes (58.40 MiB). They fit the previous
64 MiB limit. The runtime test component raises the total to 74,374,204 bytes
(70.93 MiB). Set the byte limit to 80 MiB and keep the 16-entry limit. This
finite limit holds the four required components and the common SDK runtime
component in one cache. Tests check retention, byte eviction, and entry eviction.

| Component | Source bytes | Mapped image bytes | Cache charge bytes |
| --- | ---: | ---: | ---: |
| Discovery | 2,613,639 | 13,144,688 | 15,758,327 |
| Process | 2,519,874 | 12,639,856 | 15,159,730 |
| Credentials | 2,519,874 | 12,639,856 | 15,159,730 |
| Kubernetes | 2,519,874 | 12,639,856 | 15,159,730 |
| SDK runtime | 2,156,767 | 10,979,920 | 13,136,687 |

The `fixture_cache_charges_fit` test recorded these figures for the current
artifacts on Linux x86-64. The test kept all five entries below the 80 MiB and
16-entry limits. These figures are memory accounting evidence, not a
performance result. The fixture helper rejects a seed set when any source
digest is absent after admission.

### Corpus correction proof

The existing corpus test passes all 21 cases in normal and duplicate replay.
The 42 installed calls use the unchanged case counts and expected snapshots.
The largest successful call consumes 6,741,078,368 fuel units. The diagnostic
uses test-only limits of 64 MiB data and 8 billion fuel units. Guest memory
stays at 256 MiB. Guest time stays at five seconds. Output lifting stays at
32 MiB. The real component failure and recovery test also passes.

The diagnostic log is `/tmp/araphor-wasm-full-corpus-calibration-v7.log`.
Its SHA-256 is
`a4904a24444a655ff05c5ce74a72ad4c32b2d2261ddf4573efe224d804fea3e4`.
The diagnostic proof is
`/tmp/araphor-wasm-full-corpus-calibration-v7-proof.json`.
These files are local evidence. This measurement is not a performance result.

Production still uses the draft limits of 32 MiB data and 100 million fuel
units. Automatic approval review rejects the proposed production limit change.
Explicit user approval is pending. The final shared Rust procedure and final
production qualification do not yet cover the proposed limits.

The cache, exact export, and installed history tests pass in
`/tmp/araphor-wasm-full-corpus-calibration-v6.log`.
The duplicate context and graph recovery tests pass in
`/tmp/araphor-wasm-corpus-and-recovery-calibration-v6.log`.
The latter run fails its corpus test at the smaller diagnostic fuel limit.
The subsequent full corpus run above corrects that diagnostic failure.

Formatting and workspace Clippy pass after diagnostic removal.
Clippy runs with all targets, all features, and warnings denied.
The log is `/tmp/araphor-wasm-cleanup-clippy-v7.log`.

### Cached fixture correction proof

The parallel discovery baseline diagnostic passed one test and failed two.
Both failures returned `AnalysisBusy` for query output capacity. The serial
baseline passed. The shared fixture now uses a mutex. All 31 callers hold one
guard through their component calls. Production query capacity does not change.

The corrected focused run passed all 19 tests with four test threads. It includes
all 12 discovery derivation tests, all three graph baselines, reason validation,
native storage encoding, traversal lifetimes, and metadata deadline recovery.
The discovery corpus retains all 21 cases and both delivery counts. The metadata
test includes the native graph snapshot read and checks reader recovery.

The log is `/tmp/araphor-wasm-fixture-correction-tests-v8.log`. Its SHA-256 is
`8fef40597f580a0da66822f04d77ea5d04b4ce5bee76e764adfdd1934de33d42`.
Strict workspace Clippy passed in
`/tmp/araphor-wasm-fixture-correction-clippy-v8-retry.log`.
The proof is `/tmp/araphor-wasm-fixture-correction-proof-v8.json`.
The source manifest is `/tmp/araphor-wasm-source-manifest-correction-v8.json`.
The source SHA-256 is
`fd8a9f4a294020bd78ebc48b5e00bb76fe318ec5974f37e92e5649501a0a599e`.

The focused tests use the temporary 64 MiB data and 8 billion fuel limits.
Production still uses 32 MiB and 100 million fuel. Approval for the production
change remains pending. This run is not final production qualification.
The full regression uses the previous source manifest and still has failures.
The final shared Rust procedure and production qualification remain pending.

### Full regression failure proof

`/tmp/araphor-wasm-rust-ci-regression-v7.log` records exit 101 from the shared
Rust procedure with four test threads. Formatting, workspace check, and strict
Clippy passed. The Data test run has 509 passed, 15 failed, and seven ignored.
The procedure stopped at that failure. It did not run the remaining checks.
The log SHA-256 is
`cd5d63595444cb6d9ff2d0fffa2f4f117290e3ee10a2283cd46eb180d8d29c0b`.
The source manifest and result are in
`/tmp/araphor-wasm-ci-source-manifest-regression-v7.json` and
`/tmp/araphor-wasm-rust-ci-regression-v7-result.json`.

Eleven failures use the shared discovery fixture. The later mutex correction
has the focused proof above. It is not part of this regression source. The
extraction snapshot and graph context bound tests return a read deadline.
Both tests pass when run alone. The graph test uses the unchanged 256 records,
768 facts, progress checks, and result bounds. Its serial log is
`/tmp/araphor-wasm-graph-context-bounds-diagnostic-v8.log`; its SHA-256 is
`eee022066b2feccfb0f676a992b0e7916963d10f7d52f2c7fef687296161cd7c`.
This result does not identify the failed read caller in the parallel run.

The other failures are the Wasm lifecycle result freshness check and the
current discovery profile query fixture. The later corrections have the
focused proof below. Production limits remain 32 MiB and 100 million fuel
units. The test allowances remain diagnostic limits. Full production
qualification and the final shared Rust procedure are still required.

### Graph and fixture correction proof

The focused run passed all six tests with one test thread in 602.21 seconds.
It checks the extraction snapshot, discovery profile query, Wasm lifecycle,
checkpoint retry after reopen, graph source recovery, and graph byte splitting.
The log is `/tmp/araphor-wasm-fixture-and-graph-tests-v10.log`. Its SHA-256 is
`b48f761c28aa82e16624b609584de0eb32268b32fc7acdb1de79317a96b2ffca`.
The proof is `/tmp/araphor-wasm-fixture-and-graph-proof-v10.json`.
The source manifest is `/tmp/araphor-wasm-source-manifest-correction-v10.json`.
The source SHA-256 is
`a0a0ee9405ef1963bc1e471f097c45df66dae7724074e299b11caa31d1aa5481`.

The graph test uses the existing installed credential component. The input has
256 records and 67 facts. The complete window returns the exact host graph
output byte error and changes no stored metadata. The production graph owner
then processes smaller windows through cursor 256. It stores 255 native denial
findings and one contextual credential finding. Each result stays within the
4 MiB window limit. Credential evidence matches its committed prefix. This
test makes no claim for causality across the complete unsplit window.

The lifecycle test observes the fresh revision 2 result at its authorized
commit. It requires value 7 and equal immutable receipt fields. A later stale
flag must match the saved evaluation clock. The query fixture installs the
required discovery exports for both retained tenants and keeps the primary
source grant and isolation checks. The extraction fixture uses an explicit
30-second read control for its snapshot and three committed projection writes.
Production clock behavior, deadlines, and query grants do not change.

Formatting and strict workspace Clippy pass for this source. Their logs are
`/tmp/araphor-wasm-fixture-correction-format-v10.log` and
`/tmp/araphor-wasm-graph-capacity-clippy-v10.log`. These tests use the temporary
64 MiB data and 8 billion fuel allowances. Production uses 32 MiB and
100 million fuel. This proof does not replace final shared Rust verification
or production qualification.

The temporary qualification deadline wrapper is removed from the source.
The retained v9 executable still has the bounded diagnostic used by its run.
The first shared Rust procedure uses one test thread after this last source
edit. Its command is
`CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=1 bash .github/scripts/verify-rust-ci.sh`.
Its log and result are `/tmp/araphor-wasm-rust-ci-v11.log` and
`/tmp/araphor-wasm-rust-ci-v11-result.json`. Its source manifest is
`/tmp/araphor-wasm-ci-source-manifest-v11.json`. The source SHA-256 is
`beea6a724bf3d235196034033067fe4340dde54e9696a4a8efc1168f50e497f5`.
This run exits 101 during test linking when the filesystem is full. Formatting,
workspace check, and strict Clippy pass. The test suite does not start. The log
SHA-256 is
`707e99121d997d81974df2013629d4e53ea68087f766fcd4916961388ad8f262`.

Checked removal of debug sections from 14 inactive generated executables
recovers 18,230,107,832 bytes. All loaded sections stay equal. Source, native
archives, logs, proof files, and the retained qualification executable stay
intact. The cleanup proof is
`/tmp/araphor-strip-proof-20261011-ci-v11.json`. The same Rust source is checked
again before the retry. The retry command is
`CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=1 bash .github/scripts/verify-rust-ci.sh`.
Its log and result are `/tmp/araphor-wasm-rust-ci-v11-retry.log` and
`/tmp/araphor-wasm-rust-ci-v11-retry-result.json`. Formatting, workspace check,
and strict Clippy pass. The root stops this older source run with SIGINT after
the concurrency source change. It exits 130. No test failure is reported before
the stop, but the workspace tests are incomplete. This run is not a final pass.
The log SHA-256 is
`ffbf7f09c36bfbf60f25a5598d8db65a597ad9052d3f59f323612ce9fa3a4d1f`.

During retry linking, the same checked cleanup recovers a further
12,992,279,576 bytes from ten inactive generated executables. All loaded
sections stay equal. Its proof is
`/tmp/araphor-strip-proof-20261011-ci-v11-retry.json`. The test suite starts
after linking. The interrupted run does not prove the full suite.

The later concurrency audit finds no focused proof of two overlapping,
successful Wasm calls through one owner. The correction adds
`package::wasm::tests::runtime::concurrency::installed_guests_overlap`.
It uses the shipped discovery `groups` component and two tenant snapshots
of one installed owner. Both guests must reach the real host import before
either release. Each result must contain only its tenant key, members,
samples, and aggregate count. Expected counts are 5 and 18. The release wait
uses the existing guest deadline. Production limits, controls, artifacts,
and WIT stay unchanged. The existing cancellation proof keeps its signal.

This later source change is not in the interrupted v11 regression. Its source
manifest is `/tmp/araphor-wasm-source-manifest-concurrency-v12.json`.
Its source SHA-256 is
`47d73bbfec0059251f6c8851a410d232f83bf2440c4edef7d10720064b33eb8b`.
Focused compilation passes. The overlap and cancellation tests each pass with
one test thread. Their times are 101.39 seconds and 9.19 seconds. Their logs are
`/tmp/araphor-wasm-overlap-test-v12.log` and
`/tmp/araphor-wasm-cancellation-test-v12.log`. Their SHA-256 values are
`533d27f5c2c5a0fb8915195be8ae0b7f8691c1f5d6c0c4680c9f5d31a820c3a1`
and `813c5b0a6c375e4849aa883310bb4565e587e174da3f6407fc4c6950cfe6a59c`.
The final shared Rust procedure remains required.
The current source passes `cargo fmt --all -- --check` and `git diff --check`.
Its focused proof is `/tmp/araphor-wasm-concurrency-proof-v12.json`.
Source review checks both real import arrivals, separate store gates, finite
failure cleanup, unchanged cancellation checks, existing query capacities,
and the expected shared computation. No source defect is found. This review
does not prove runtime success.

After the focused tests, checked removal of debug sections from one inactive
test executable recovers 1,039,090,176 bytes. All loaded sections stay equal.
Its proof is `/tmp/araphor-strip-proof-20261011-pre-ci-v12.json`.
The final shared Rust procedure then starts on this source. Its command is
`CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=1 bash .github/scripts/verify-rust-ci.sh`.
Its log and result are `/tmp/araphor-wasm-rust-ci-final-v12.log` and
`/tmp/araphor-wasm-rust-ci-final-v12-result.json`. It exits 101 during the link
of the `mithril-control` contract test. The linker reports a bus error.
The filesystem has 342 MiB free at the terminal check. Formatting, workspace
check, and strict Clippy pass. The workspace tests do not start. The log
SHA-256 is
`033debd8c043ebce29898229ebc7db73ca80801170b0ad3a8ca63730f774cbfc`.

Checked removal of debug sections from 13 inactive generated executables
recovers 17,862,496,480 bytes. All loaded sections stay equal. Source, native
archives, component artifacts, logs, and proof files stay intact. Its proof is
`/tmp/araphor-strip-proof-20261011-ci-v12.json`. The source check finds no change.
The same final Rust command starts again. Its log and result are
`/tmp/araphor-wasm-rust-ci-final-v12-retry.log` and
`/tmp/araphor-wasm-rust-ci-final-v12-retry-result.json`. No final pass is recorded
while it runs. Production limits remain 32 MiB data and 100 million fuel.

The retry passes formatting, workspace check, strict Clippy, and test linking.
The workspace tests start. Checked removal of debug sections from nine more
inactive generated executables recovers 10,809,909,456 bytes. All loaded sections
stay equal. Its proof is `/tmp/araphor-strip-proof-20261011-ci-v12-retry.json`.
The terminal result remains open while the suite runs.

The v9 graph diagnostic exits 1 when AnalysisStore reaches its filesystem
reserve. It does not identify the earlier read deadline. Its log is
`/tmp/araphor-e2e-graph-notification-diagnostic-v9.log`, with SHA-256
`bd78181bd02ff2edf00c93ad0431262aeb3e03144904162adcf47db745dd5a51`.
Its result is in
`/tmp/araphor-wasm-qualification-20261011-sol-v9/e2e-qualification-proof.json`.
The production limit change and final production qualification remain open.

### Data adapter correction TODOs

- [ ] Correct the native database memory budget for bounded component artifacts.
  A production package revision read fails at the previous 64 MiB cap. Keep a
  finite cap, verify its rejection boundary, and rerun graph and SQL lifecycle
  qualification. Check reader release and repeated bundle reads before a fix.
- [ ] Set the native database memory limit to 128 MiB. Use the same constant for
  backup validation. Keep the graph window limit at 4 MiB. Check the native
  settings and resource rejection. Verify installed package reads and restore.
  This setting limits native database buffers. It does not limit process RSS.
- [ ] Match the native allocation failure and its reported reason in the
  rejection test. The pinned DuckDB binding does not retain the native error
  type in `Connection::execute`. Do not compare its unused error-code variant.
  Pass the SQL repetition length as `BIGINT`.
- [ ] Permit trusted host-prepared exports with declared Table outputs through
  `InstalledAnalysis`. Keep graph and discovery output checks on their domain
  adapters. Verify typed native graph input and the AR-04 context packet.
- [ ] Keep the validated graph package provenance reference in the atomic
  result commit. Exclude this sidecar from the visible input manifest check.
  Verify a production graph commit and the bounded header reference read.
- [ ] Validate the installed package references in native context records before collection and during recovery. Check the typed reference fields, tenant scope, names, generation, export, revision, root, and retained dependency closure. Permit a source record without these references only for the previous discovery format. Reject malformed new references. Verify reopen and backup restore.
- [ ] Read graph package references from the bounded native header. Do not read graph rows to obtain the source key. Verify that the reference read does not reconstruct rows.
- [ ] Use a finite 60-second outer deadline for host component calls. Permit compilation after reopen with an empty code cache. Keep the compiler and guest execution limits separate. Verify replay with a new production package owner.
- [ ] Check each distinct saved grant at domain commit, including different grants for the same package root. Verify that removal of the second grant prevents the commit callback.
- [ ] Share the package lifecycle lock between owners that use the same store. Verify that a second owner cannot change an activation while a domain commit holds that lock.
- [ ] Hold the shared lifecycle lock during owner construction and package admission collection. Verify that a second owner cannot collect a package row before the first owner completes activation.
- [ ] Keep previous-schema graph fixtures free of package rows. Use an isolated installed execution handle for native storage tests. Install packages in the tested store when the test checks retained package context.
- [ ] Hold the shared lifecycle lock for Run grant renewal and supervisor
  suspension. Release this lock before guest execution. Verify that neither
  operation changes an activation during a domain commit. Use the normal
  30-second fixture control for these concurrency tests.

- [ ] Validate graph output with the saved effective package parameters.
- [ ] Retain exact installed exports, revisions, activation generations, and
  configured parameters in discovery and graph context. Use these references
  for historical replay. Do not combine different references in one profile.
- [ ] Keep causal proof, confirmation, and coverage validation on the host.
  Reject a package result that increases these claims without qualified input.
- [ ] Change former unsupported-Wasm fixture cases to the unsupported Native
  target. Use real components for Wasm execution tests.

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
