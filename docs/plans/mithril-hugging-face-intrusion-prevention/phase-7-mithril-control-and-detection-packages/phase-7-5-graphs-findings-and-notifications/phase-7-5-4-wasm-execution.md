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

The approved optional resource policy below supersedes earlier fixed data,
fuel, memory, and guest-time statements. Earlier proof retains its original
source and limits. It does not qualify the current source or generated build.

### Goal deliverable review

The review uses all six approved goal deliverables. A source commit does not
close a verification gate. The phase remains **Not done**.

| Deliverable | Source and commit | Remaining proof |
| --- | --- | --- |
| 1. SDK component path | Generated bindings, component build, and detector example: `c77eeec2`. Typed runtime fixtures: `d1de114d`. Owned Arrow buffers and six rebuilt components: `f274e413`. | The SDK suite has 51 passes. The v27 shared suite has 14 passes. Two independent builds reproduce all six current component artifacts. Final workspace verification remains required. |
| 2. Production Wasmtime execution | Compiler worker, bounded cache, guest limits, restricted imports, shared query budget, native inputs, and installed execution: `a6f870a3`. | Retained bundle, input, wire, schema, and result charges are committed in `2a89eefc`. The v16 focused groups have 51 passes. Current native graph qualification has five passes. Final workspace verification remains required. |
| 3. Installed domain outputs | Typed reason storage and historical JSON: `6ca5ed3c`. Domain adapters and retained package references: `d7aaf21a`. | The fresh installed-detector case passes. The fresh production finding-to-notification case remains required. |
| 4. Current algorithms | AR-01 through AR-03 and AR-05 through AR-07 use installed execution in `d7aaf21a`. AR-04 selection stays on the host. Its installed transport case is in `8f150fd4`. | The v20 corpus has 28 passes at production limits. The v27 graph group has five passes, including unchanged splitting and historical JSON baselines. Fresh installed context transport passes. Final CI must qualify the complete corpus with current artifacts. The dispatch ordering breach remains recorded. |
| 5. Lifecycle and recovery | Shared lifecycle fences are in `a6f870a3`. Checkpoint, retry, upgrade, rollback, removal, and retained-reference tests are in `fcd587ae`. | Focused lifecycle and overlap tests pass. Fresh installed-detector and profile-restart cases pass. Final workspace verification remains required. |
| 6. Qualification and closure | The new detector installation and context transport cases are in `8f150fd4`. | Three fresh production cases pass and have separate commits. Finish graph notification, the final Rust procedure, and the final review and result. |

The Rust source before the bounded-input correction is committed through
`8f150fd4`. Its 1,558 source file hashes equal the v12 manifest. Formatting,
workspace check, strict Clippy, and test linking pass on that source. The
workspace test run is interrupted with exit code 130 before the required
correction starts. No terminal test failure is recorded. The correction,
four fresh production cases, and a new final shared Rust procedure remain
required.

The retained corpus run used 64 MiB of data and 8 billion fuel units.
At that time, production permitted 32 MiB and 100 million fuel units. That test result does
not prove production equivalence. Automatic approval review rejects the
proposed production limit increase. The earlier correction kept production
limits unchanged and removed the larger unit-test allowances. Qualify the
bounded-input correction with the same limits in both paths. Keep this gate
open until the required checks pass.
The production dispatch has already changed. The required complete production
equivalence gate did not pass before that change. Source review and test-only
corpus parity do not close this requirement.

The bounded-input correction builds on source `v13`. Its 1,560-file manifest
has SHA256 `8c34f38f69015fb184c8d8660e81e7882340ac0f9dbea0109ff58a15e389f42a`.
The ten page-planner tests, the 1,024-delivery duplicate test, and the real
component page-equivalence test pass with production data and fuel limits.
The complete corpus exits 101. `rare-forbidden normal` reaches the shared
60-second deadline. The graph evidence-recovery test also exits 101 with
`PackageWasm::Limit`. These results do not close production equivalence.
The proof is `/tmp/araphor-wasm-production-bounds-proof-v13.json`.
The graph log is `/tmp/araphor-wasm-graph-recovery-production-v13.log`.

The graph schema correction is implemented. Shared computation tests have
13 passes. Two independent builds produce equal core and component bytes
for all four required components. The correction constructs the reason-details
port once per evaluation. It preserves the finding rows, reasons, evidence,
and checkpoint. The correction proof is in
`wasm-component-build-proof.json`, under `graph_schema_correction`.
Current production-limit graph qualification remains required.

The SDK allocation correction is implemented. Descriptor, schema, and wire
charges include reserved capacities and retained metadata. Typed inputs and
wire inputs use the same metadata calculation. Six new tests check allocation
charges; the complete SDK suite has 51 passes. Two independent builds produce
equal core and component bytes for all six guest artifacts. The proof is in
`wasm-component-build-proof.json`, under `memory_accounting_correction`.
Production owner memory qualification and the final Rust procedure remain
required.

### Retained-memory correction proof

The v16 focused tests have 51 passes and no failures. The allocation and
reader-free reuse group has 23 passes. The lifecycle, runtime, and native graph
group has 28 passes. Its four ignored entries are compiler subprocess helpers;
the parent OS-limit and child-cleanup tests pass. The source manifest has
SHA256 `4cd8e0a57edb9aca24e867f9eea35e826781ded9d2a042e584e4a961fb2c2c46`.
The proof is `/tmp/araphor-wasm-production-bounds-proof-v16.json`.

Pinned runs retain one validated immutable bundle per root. Query leases
charge bundle, pin, returned descriptor, revision, input, wire, and schema
scratch allocations. The owner encodes each component input once. Each call
still checks current permission and trust. Historical repinning reads the
current activation. Tests check update and removal through an old handle,
quota rejection, last-owner release, cancellation, failure, and guest overlap.
The shared query capacity and production component limits do not change.

The normal v16 qualification binary builds. It reports one warning for the
direct evaluation wrapper, which has only unit-test callers. The v17 source
adds `cfg(test)` to that wrapper. Strict Data Clippy passes with all targets
and features. Its log is `/tmp/araphor-wasm-data-correction-clippy-v17.log`.
The full corpus, graph recovery, four fresh production cases, and final shared
Rust procedure remain required. This focused proof does not close those gates.

The v16 graph evidence-recovery test passes. The output-byte split test fails
with `PackageWasm::Limit` while JSON encodes relationship evidence. The exact
core-module frames select `Rows::encode<Relationship>` and the default
`RowBuffer::write_all` retry loop. The run has one pass and one failure.
Its log is `/tmp/araphor-wasm-graph-recovery-and-split-production-v16.log`.
This result does not qualify graph splitting at production limits.

The v18 discovery run has 27 passes and one failure. The largest
`rare-forbidden normal` call still reaches its 60-second outer deadline.
Its source uses 64 identities per page. The original graph split test also
still returns `PackageWasm::Limit`; evidence recovery passes. The direct row
writer is not sufficient for either failed gate. The proof is
`/tmp/araphor-wasm-production-bounds-proof-v18.json`.
The follow-up moves the pure carried-proof scan after its eligibility checks
and uses 128 identities per discovery page. Guest limits and outer deadlines
stay unchanged. The current source still requires fresh qualification.

### Discovery production-bound proof

The v20 discovery group has 28 passes and no failures. All 21 corpus cases
pass in normal and duplicate replay. The rare case also passes exact display
groups and all eleven baseline comparison fields. The 129-identity boundary
test passes separately. Both paths use 128 complete identities per internal
page, 32 MiB data, 100 million fuel units, and one 60-second outer deadline.
The source manifest has SHA256
`98343fea9235304f135e9b9c22e02f4e4f5f6c260a59e92f92ab27c79a9f236e`.
The log is `/tmp/araphor-wasm-discovery-equivalence-production-v20-retry.log`.
Its SHA256 is
`419938338318c9a7d0dfa97f14e3088e3002933ce9043110cabe8c788c1dfd47`.
The proof is `/tmp/araphor-wasm-production-bounds-proof-v20.json`.

The first copied test executable had an incorrect path. Its compiler child
used the application argument and exited before computation. That run has
eleven passes and seventeen failures. The retry uses the required test path
and the same executable bytes. The proof retains both results. The later
graph index correction rebuilds all six components. Those artifacts require
new qualification. Graph splitting, four production cases, and final shared
Rust verification remain open.

### Shared graph encoding correction proof

The v23 shared computation tests have 13 passes. The credential identity index
preserves first representatives, direct-proof OR, equal-record order, and raw
evidence positions. The row encoder writes JSON directly to the existing
Arrow binary builder. The encoder retains the same byte checks and JSON.
Two independent builds produce equal core and component bytes for all six
artifacts. The build proof retains both corrections.

The original production-limit graph group has one pass and one failure.
Evidence recovery passes. The unchanged output split test exhausts guest fuel
during `Rows::encode<Relationship>`. The run takes 225.50 seconds and exits
101. The log is `/tmp/araphor-wasm-graph-recovery-and-split-production-v23.log`.
Its SHA256 is
`a07311c8e0c15dd8a3fadd7b6f6ab3858f24b7778b9c517296e71dd8e6847de3`.
The v23 source manifest has SHA256
`661b0e5e1e83d61c9bcba11a18bfe6818cbb7baf70420323318da35f26efbb4c`.
The normal production qualification binary builds without warnings.
The proof is `/tmp/araphor-wasm-production-bounds-proof-v23.json`.
Graph splitting remains open. This correction does not change production
limits or close the dispatch ordering breach.

The v24 writer annotations pass all 13 shared tests. Two independent builds
produce equal bytes for all six components. The normal qualification binary
builds without warnings. The original graph group has one pass and one failure
after 231.77 seconds. Evidence recovery passes. The split still exhausts fuel
during graph output encoding. The proof is
`/tmp/araphor-wasm-production-bounds-proof-v24.json`.
The source manifest has SHA256
`a061f6d599c9bc95d91f50806bea0ab843f65076e64af0f69c4ec79bd702064d`.
The checked writer bodies and production limits stay unchanged. Graph
splitting remains open.

The v25 encoder uses the standard Rust `BufWriter` with at most 8 KiB of
scratch per row. The shared suite has 14 passes. Exact-byte tests cross
multiple flush boundaries. A serializer error retains byte-limit precedence.
Two independent builds produce equal core and component bytes for all six
artifacts. The build proof records `buffered_writer_correction`.
The source manifest has SHA256
`291e3b98b1c73def6ab87891ee57152577299096f77e4215e85f0e76efae6033`.
Production limits and the original graph split test stay unchanged.
The original v25 graph group has one pass and one failure after 217.46
seconds. Evidence recovery passes. Graph output encoding still exhausts fuel.
The proof is `/tmp/araphor-wasm-production-bounds-proof-v25.json`.
Installed runtime qualification remains open.

### Canonical evidence publication proof

The v26 shared computation suite has 14 passes. Both independent builds
produce the same six component artifacts. Canonical candidate evidence,
matching reason details, evidence links, and checkpoints pass the shared tests.
Raw authority join assertions remain in the test. The host retains the same
sorted evidence sets. The derived graph checks its actual JSON byte count
without an output buffer. The final commit check remains after metadata.

The original graph group has one pass and one failure after 251.72 seconds.
Evidence recovery passes. The split case exhausts fuel in `quicksort<u64>`
from `Computation::output`, before row encoding. The core function names
identify frames 506, 505, 330, and 329. The failure remains open.
The log has SHA256 `d366e261b6820a39db707bf985471e587d8fd5a9008eb46916b8f39183b25e58`.
The source manifest has SHA256 `8d0970966cc612bd0c6d39f4d46c908a770220d384d658dba58c3838cd4f4e40`.
The proof is `/tmp/araphor-wasm-production-bounds-proof-v26.json`.
The build proof records all six artifacts under `canonical_evidence_correction`.
This result does not qualify graph splitting or the four production cases.

### Common credential prefix proof

The v27 shared computation suite has 14 passes. Both independent builds
produce the same six components. The shared publisher canonicalizes one
credential edge prefix before the relationship copies. Raw authority and
finding evidence sequences remain unchanged. The unit test checks exact raw
joins and independently constructs the prior edge evidence sets.

The current graph group has five passes and no failure in 401.27 seconds.
The native, credential, and Kubernetes baselines retain exact historical JSON.
Evidence recovery passes. The unchanged 256-record, 67-fact split test returns
`GraphInvalid` with field `graph output bytes`. Rejection changes no metadata.
The owner advances through cursor 256 and retains 255 native findings and one
contextual credential finding. Every stored body fits 4 MiB. The credential
finding retains its exact prefix evidence. Production data and fuel limits
remain 32 MiB and 100 million units.

The log has SHA256 `1cd18fdcefcbc4045e3f31abc441244647aa4ef29153a36d75e9d97937d44e66`.
The source manifest has SHA256 `0fca39d0a0edc293e0900c3b7ba4d1f699ac2ef208c1ac67b42d4287ef72899d`.
The proof is `/tmp/araphor-wasm-production-bounds-proof-v27.json`.
The build proof records all six components under `edge_prefix_correction`.
The four fresh production cases and final Rust procedure remain required.

### Installed detector production proof

The fresh v23 `analysis-packages` case exits zero and records `PASS`.
The operator installs the built Rust detector folder through the real TLS
client. No host rebuild occurs. The detector uses threshold 3 and four input
records. The detector retains three matching evidence records, reason
`example-burst.THRESHOLD`, and checkpoint 4. Restart and retry preserve the
result. Three trust-removal checks pass. SQL correction, empty replacement,
checkpoint recovery, failed upgrade, rollback, revocation, and removal also pass.

The result is `/tmp/araphor-current-v23-packages/result.json`.
Its SHA256 is
`99d3a173014da78bc6230eb5a15976940ebc62df6bb859927b895c1a1306332a`.
The v23 source manifest is recorded above. The normal executable has SHA256
`90ccc1432ad45155b3022ffec0c815d951bf54e58572d346076188622855ce87`.
The proof is `/tmp/araphor-wasm-production-bounds-proof-v23.json`.
The inline writer follow-up changes all six component artifacts. Repeat the
four production cases on those final artifacts before closure.

### Current installed detector qualification

The fresh v27 `analysis-packages` case exits zero and records `PASS`.
A real TLS client installs the built `example-burst` folder without a host
rebuild. The stored threshold is 3. Four inputs produce three matching evidence
records, typed reason `example-burst.THRESHOLD`, and checkpoint 4. Task groups
remain separate. Restart and retry retain the same result.

Current computation and historical replay both reject revoked trust. Retained
results remain readable. SQL correction and empty replacement pass. Checkpoint
runs retain values 2, 2, and 1. Failed upgrade, rollback, revocation, removal,
and historical reads pass.

The result is `/tmp/araphor-current-v27-packages/result.json`.
Its SHA256 is `6e47925e569f0f4ee169322afe61d43e8c900dcca505d0317afc101aa4e08453`.
The normal executable has SHA256 `c91c8a8082d0308751a32ae8d367061f6e1cf4a5913a7cb91c72da058822e668`.
The source manifest is the v27 manifest recorded above. The proof is
`/tmp/araphor-wasm-production-bounds-proof-v27.json`.
The context, profile restart, graph notification, and final Rust gates remain.

### Current installed context qualification

The fresh v27 `context-roundtrip` case exits zero and records `PASS`.
Signed context resolves at durable cursor 1. The installed component returns
exact selected identities, revision, and coverage. Cutoff 3000 selects one
record. Cutoff 1999 selects no record and retains one omission. Host selection
and authorization remain unchanged. Missing provenance and health coverage
remain explicit.

The result is `/tmp/araphor-current-v27-context/result.json`.
Its SHA256 is `312cd19eaec497b7be967bb10f94ff74fe7f8f33a6a6cbd785a578c94906f587`.
The case uses the same normal executable and v27 source manifest as the
package case. The proof is `/tmp/araphor-wasm-production-bounds-proof-v27.json`.
The profile restart, graph notification, and final Rust gates remain.

### Current graph notification failure

The fresh v27 `graph-notification` case exits one. Its terminal error is
`Analysis storage reached its filesystem reserve limit`. The case writes no
result artifact. The log is `/tmp/araphor-current-v27-graph.log`.
Its SHA256 is `bd78181bd02ff2edf00c93ad0431262aeb3e03144904162adcf47db745dd5a51`. The run uses the recorded v27 source
manifest and normal executable. This failure does not qualify graph
notification. The elapsed time does not identify the failing source or
operation. Source review finds a separate repeated-check defect: an unchanged
graph check does not save the provider notice. Production Control and the test
provider both use a global notice. The correction remains required.

### Filesystem recovery before the notice correction

The cleanup removes debug sections from 53 inactive generated executables
in the primary target and the component build target. The cleanup saves
11,073,656,576 bytes. Every loaded ELF section has the same type, flags,
address, size, and bytes before and after cleanup. The cleanup preserves
source, archives, component artifacts, logs, and proof. The proof is
`/tmp/araphor-strip-proof-20261011-notice-v28-prebuild.json`.
Its SHA256 is `6660adcef9647835192fadbf7803b03feaa3e2d345d470c82445804f726bf1c7`.
The v27 normal executable now has a different whole-file hash. Its loaded
sections remain equal. The completed v27 runs retain their original hashes.
Current source still requires a new build and all final qualification.

### Current profile restart qualification

The fresh v27 `profile-restart` case exits zero and records `PASS`.
The production owner persists the live profile and resolves late context.
Frozen replay remains deterministic after restart without the prior context
provider. The case retains `profile.json` and `profile-unresolved.json`.
This case makes no physical profile or prevention claim.

The result is `/tmp/araphor-current-v27-profile/result.json`.
Its SHA256 is `3e4dbc6f293c12a9911137d41285b1b18b4ec2c02df03c0a3cd2f265f6d996d5`.
The case uses the same normal executable and v27 source manifest as the
package case. The proof records both profile artifact hashes in
`/tmp/araphor-wasm-production-bounds-proof-v27.json`.
Graph notification and the final Rust procedure remain required.

### Completed graph check reuse

**Done for the production correction.** An unchanged graph check saves the
captured provider notice in existing per-result metadata. A repeated notice
does not execute the algorithms again. Current package references, activation,
permission, and trust are checked before reuse. Expiry and forced refresh keep
their existing paths. Update, a new compatible export, removal, and revocation
are observed without a provider notice change.

Schema 20 initializes new graph notices from the captured provider token.
The checked schema 19 migration converts all retained native graph headers in
one transaction. Schema 17 conversion initializes the same field. Result
bodies, rows, request metadata, evidence, receipts, quota, progress, history,
and notification deadlines stay unchanged. Discovery keeps its existing
monotone notice rule through the shared metadata update owner.

The v30 serial group has 13 passes and one failed new health expectation in
423.06 seconds. Its log is `/tmp/araphor-wasm-graph-notice-focused-v30.log`,
with SHA256 `f24808fb2f4b51c10f6790c63cc6f196afa043890eb55393a0376421f4999ae7`.
The corrected lifecycle test passes alone in 130.16 seconds on v31. Its log is
`/tmp/araphor-wasm-graph-notice-installed-v31.log`, with SHA256
`f05fdd67d33fc3c4842fd5833816575eb896010c7513a27671afef48e01872bf`.
The checks cover unchanged and later notices, relevant facts, expiry, separate
windows, commit denial, retry, reopen, migration, restore, and corrupt-header
rejection. The full current group has not been run. Final CI remains required.

Earlier attempts remain recorded. The v28 build fails on a missing test import.
Its retry builds successfully. The v29 group has 11 passes and three failed new
expectations. Restore must increment the recovery epoch. A non-advancing graph
refresh retains the progress result pointer. The v30 health expectation must
use the current read revision. The corrected tests compare every metadata and
health field exactly. They retain every existing workload and assertion.
Five test names are shortened with byte-identical bodies.

The final source manifest is
`/tmp/araphor-wasm-source-manifest-production-v31.json`, with SHA256
`12f6f8e821a5fe2aeb18fe727b3f6d9a65202492a75d7f9bb4a79237841823e7`.
The proof is `/tmp/araphor-wasm-graph-notice-qualification-proof-v31.json`.
The test-only change proof is `/tmp/araphor-wasm-graph-notice-name-proof-v31.json`.
Production source is byte-identical to v30. A normal build on v31 returns the
same executable bytes as the saved v30 execution copy. All four production
cases use that copy. Their proof is `/tmp/araphor-wasm-production-proof-v30.json`.

### Installed detector and package lifecycle qualification

The fresh v30 `analysis-packages` case exits zero and records `PASS`.
It installs `example-burst` from a built folder through the real TLS client.
The stored threshold is 3. Four input records produce three matching evidence
records, checkpoint 4, and reason `example-burst.THRESHOLD`. The case checks
restart, identical retry, trust revocation, and retained history. No host
rebuild occurs. The SQL dependency cases retain correction, empty replacement,
checkpoint counts 2, 2, and 1, upgrade failure, rollback, and removal checks.

The result is `/tmp/araphor-current-v30-packages/result.json`, with SHA256
`a65a9c74fa8943fd462e40a0de96294e3c9276582e113549aeaf25f709c3c3ac`.
The source manifest is `/tmp/araphor-wasm-source-manifest-production-v30.json`,
with SHA256 `0948f6c8fd457929958f62d7b4612d0f61af715a35a0eb918d81848c6fa1b40d`.
The normal executable is copied without a byte change to
`/tmp/araphor-current-v30-bin/mithril_discovery_test`. Both have SHA256
`2bce7ffca52037ea28d6b974f38a9d16fad443ed76d63de2968568ba8f96eca2`.
The build log is `/tmp/araphor-wasm-production-e2e-build-v30.log`, with SHA256
`c19a318df29ce4871608587ab87bc513106eba06da310791258790aca07fd4e4`.
The proof is `/tmp/araphor-wasm-production-proof-v30.json`.
The case adds no physical-prevention or performance result.
The final shared Rust procedure remains required.

### Installed context transport qualification

The fresh v30 `context-roundtrip` case exits zero and records `PASS`.
The Node WAL, TLS intake, retained frame, context, and data restart checks pass.
The installed context component returns the same identity, revision, and
coverage as the host selector. Cutoff 3000 selects one record. Cutoff 1999
selects no record and retains one explicit omission.

The result is `/tmp/araphor-current-v30-context/result.json`, with SHA256
`312cd19eaec497b7be967bb10f94ff74fe7f8f33a6a6cbd785a578c94906f587`.
The case uses the same normal executable and source manifest as the v30 package
case. The proof is `/tmp/araphor-wasm-production-proof-v30.json`.
This pass covers installed transport with host-owned selection. It does not
qualify a new selection algorithm or physical prevention. Profile restart,
graph notification, and the final shared Rust procedure remain required.

### Installed profile restart qualification

The fresh v30 `profile-restart` case exits zero and records `PASS`.
Signed context, live profile persistence, late context, deterministic profiles,
immutable sealed revision, and replay without provider calls pass.
The installed context packet retains the same identity, revision, coverage,
selected record, and explicit omission as the context case.

The result is `/tmp/araphor-current-v30-profile/result.json`, with SHA256
`3e4dbc6f293c12a9911137d41285b1b18b4ec2c02df03c0a3cd2f265f6d996d5`.
The profile artifacts are in the same directory. Their SHA256 values are
`fcd5aa9bd9c5d3139ae284b8fde8d4776f1f82f262505f9b27cd88d9e3de7be1`
for `profile.json` and
`e55d4994a36753377a65e1a04332948ef16605d11ec757deaec9921dc515a7e4`
for `profile-unresolved.json`. The case uses the same saved normal executable.
The v31 normal build produces identical executable bytes after test-only
corrections. The proof is `/tmp/araphor-wasm-production-proof-v30.json`.
Graph notification and the final shared Rust procedure remain required.

### Qualification cleanup correction

**Done for the cleanup correction.** The graph qualification closes its stores
before the temporary root. It releases the completed replay fixture before the
density and window cases. On failure, it awaits the Control server shutdown and
retains the original error. The command returns failure after Tokio shutdown.
The test workload, assertions, and execution limits stay unchanged.

The Rust test `discovery::graph_notification::tests::graph_error_releases_stores`
passes. It uses an expired Node certificate with the production Control path.
It requires the original transport or RPC error, reopens both stores, checks
that no output exists, and checks temporary root removal. The command is
`CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 RUST_TEST_THREADS=1 cargo test -p mithril-e2e --lib discovery::graph_notification::tests::graph_error_releases_stores -- --exact --nocapture`.
It exits zero with one pass in 67.84 seconds. Its log is
`/tmp/araphor-wasm-cleanup-test-v29.log`, with SHA256
`a96db716feb4d1155973265070aa09e35f0ab1361bc9a29070614d7493e9340a`.
The source manifest is `/tmp/araphor-wasm-source-manifest-production-v29.json`,
with SHA256 `b832e5e15328458d8fe8c4f9a1713785f906904f8a95528979875cf0c1d9c7f1`.

An independent source review retains all 737 previous assertion calls in the
changed tracked Rust files. The corpus, incident cards, finding workload, and
window sizes stay unchanged. This review and the cleanup test do not replace
the four fresh production cases or the final shared Rust procedure.

### Graph notification reserve failure after the correction

The fresh v30 `graph-notification` case exits one on the unchanged filesystem
reserve check. It writes no result artifact. The log is
`/tmp/araphor-current-v30-graph.log`, with SHA256
`2105e27206040a3ff3668509d7361c3d0d45ed9100424b42a8c742d7a27fdde9`.
The precise graph operation is not identified. The proof retains this failure
in `/tmp/araphor-wasm-production-proof-v30.json`. The run uses the same saved
executable as the three passed production cases and the v31 source record.
This result does not qualify graph notification.

After failure, no case process, compiler child, recent temporary store, or
open deleted case file remains. A separate concurrent Cargo build creates
16,650,489,856 allocated bytes before the failure. The count uses unique
inodes. This allocation is in another checkout on the same filesystem. No
file in that checkout is changed or removed for this goal.
The allocation proof is `/tmp/araphor-wasm-capacity-correlation-v31.json`, with
SHA256 `05da30409d5f2fb3368506b15c19172dbf537536e125639141c0f71ea1f55e67`.
It is a retained-file correlation. It is not a complete filesystem ledger and
does not identify the exact failing graph caller.

Checked removal of debug sections from three inactive generated executables
recovers 4,179,186,704 bytes. Every loaded ELF section stays equal. The proof is
`/tmp/araphor-strip-proof-20261011-pre-ci-v31.json`, with SHA256
`d75d18f2707e6eb3a8cfb3daf6fbece6ad63a1d83c3cb9dad0cb74e0cf69ccd6`.
The saved production execution copy stays byte-identical.

- [x] Remove only the unused primary `target/debug/incremental` cache after
  checking active processes, file handles, and mappings. Keep source,
  executables, components, logs, and proof.
- [ ] Run graph notification again with the same saved executable, workload,
  limits, and reserve in a fresh output directory. Then run the final shared
  Rust procedure on unchanged source.

The primary incremental cache has no symlinks or active process references.
Removal recovers 5,256,327,168 allocated bytes from 1,417 generated files.
The saved execution copy has the same SHA256 after removal. The proof is
`/tmp/araphor-incremental-cache-recovery-v31.json`, with SHA256
`60705e0e43d6f45303d4dc6fb2f6baf74d8d7f5fb52d1021e43706682b3d2c8b`.
All 1,576 current source hashes still match the v31 manifest. The retry uses
`/tmp/araphor-current-v31-graph-retry` as its fresh output directory.

The retry exits one with `AnalysisReadDeadline` at
`crates/araphor-data/src/analysis/read.rs:161`. It writes no result artifact.
Available filesystem space at exit is 10,058,031,104 bytes. The reserve remains
unchanged. The failure log is `/tmp/araphor-current-v31-graph-retry.log`, with
SHA256 `25de98ad83f4a6d2feb14fda10df58cecd27239b82a3bd2a1e8acacffba625fb`.
The existing proof retains this failure. The location is the final check after
read cleanup; it does not identify the failed read operation.

### Approved resource policy correction

The user approves the Extism resource policy as a design reference. Do not add
an Extism dependency or replace the WIT interface. Configurable plugin quotas
must be optional and unset by default. Keep host authorization, validation,
caller cancellation, and atomic commits. Present further design choices to the
user before implementation. The current source has optional unset runtime
quotas. Compiler, cache, SDK, shared query, and caller guards remain.

- [x] Remove the six generated `.wasm` files from version control. Build the
  four required components, detector example, and runtime fixture from their
  locked Rust source before host compilation. Use one Rust build owner for local
  builds and CI. Keep generated bytes out of source directories. Preserve
  reproducible artifact checks, offline built-folder installation, and the
  operator path without an author compiler or installation hooks.

- [x] Make plugin execution quotas optional through the existing host owners.
  Disable instruction fuel when no fuel budget is set. Keep compiler and parent
  engine configurations equal. Preserve the SDK, WIT interface, Arrow data, and
  installed package format. Use the same configuration path in production and
  tests. Test configured rejection and default execution separately.
- [x] Preserve every large workload and its assertions. Keep all 21 corpus
  cases, the 256-record window case, 257 findings across 33 sources, all 12
  incident cards, and the 64- and 185-record traversal cases.
- [x] Correct component input reservation when the runtime data quota is unset.
  A 64 MiB declared ceiling reserves more than the 128 MiB shared input pool
  even for a small input. Reserve the retained input, encoding buffers, and
  schema scratch before encoding. Keep shared pool capacity unchanged. Preserve
  lease, metadata, cancellation, and rejection checks. Add a default-ceiling
  input test and retain the rejection above the effective input limit.
- [x] Include Arrow encoding allocations that do not appear in retained array
  buffers. A valid million-row Struct array with a nullable Null child needs a
  new 125,000-byte validity bitmap. Nested FixedSizeList arrays can increase
  this allocation. Reserve this space before encoding through the shared owner.
  Add focused Rust tests for both shapes. Keep the dataset, shared capacity,
  existing limits, and one encoding pass.
- [x] Report the caller of the final read deadline through the existing error
  location. Add caller tracking to the read runner and snapshot wrapper. Extend
  the existing native deadline test without removing its 16 iterations,
  cleanup, metadata, or fresh-reader checks.
- [x] Remove repeated production graph reads and validation where the same
  owner has already checked the same immutable version. Keep corruption,
  authorization, expiry, historical replay, and transaction checks. Add focused
  Rust proof before changing each affected path. Do not copy owner sequences
  into qualification helpers.
- [ ] Run the complete current-algorithm and lifecycle cases. Build one normal
  executable and run all four fresh production cases with that executable.
  After the last Rust edit, run the final shared Rust procedure. Update the
  review guide and result with exact source and proof. Commit each deliverable.

The caller-location correction passes the existing native deadline test on
source v33. The test retains all 16 direct read iterations and adds one wrapped
snapshot deadline. Every error identifies the calling line. The test also checks
transaction cleanup, all 16 released reader slots, unchanged metadata, and a new
reader after checkpoint. The focused run has one pass in 2.44 seconds.
Its log is `/tmp/araphor-wasm-read-caller-v33.log`, with SHA256
`0aea2e57cae8bfd9f3ebbb6f5f7ba93a5c347e6fbfc7bfffd4d39ab673749958`.
The combined source manifest is `/tmp/araphor-wasm-source-manifest-production-v33.json`,
with SHA256 `3aafb4341b322cf553036e9e2454bc1158b0adf1e784158236a017173c1ae4d9`.
The production graph retry and final workspace procedure remain required.

The native window selection correction passes three focused tests on v33 in
123.68 seconds. Refresh reads checked window headers in first-cursor order.
Each window then reconstructs only current overlapping graphs. Current-head
selection occurs before overlap checks. A short replacement cannot expose an
older wide version. A skipped row still advances the result-ID page cursor.
Historical result reads retain their existing order and complete graph output.
The tests check source scope, invalid ranges, replacement, saved progress,
corrupt selected rows, and invalid headers. Readers keep the existing deadline
and close before computation. Existing large graph test inputs stay unchanged.
The log is `/tmp/araphor-wasm-native-windows-v33.log`.
Its SHA256 is `4a37da55a8e9f92a24d271453bfa9f71b71faaafcbe19a938e6b7256c7c5632e`.
Full graph, lifecycle, production, and workspace qualification remain required.

The optional quota and input reservation correction is implemented. The six
`WasmLimits` fields default to `None` through the existing query configuration.
Unset fuel disables instruction instrumentation. The bounded compiler request
keeps the child and parent engine fuel modes equal. Cached fixture code retains
the caller quotas and checks initial memory before use.
Configured failure cases keep their original workloads and error assertions.
The runtime group has ten passes and one failure in the new fuel assertion.
That assertion checked the outer error wrapper. The corrected test requires the
underlying typed `OutOfFuel` trap and passes in 10.39 seconds. Its log is
`/tmp/araphor-wasm-explicit-fuel-v34.log`, with SHA256
`6023310ef1b61f6e0006b5e604b8dec67e8066b81846cb421c7ae43966908c52`.

Two new nested-array tests fail before the encoding correction. They return
`QueryLimit` after encoding instead of the required capacity rejection before
encoding. The log is `/tmp/araphor-wasm-nested-reservation-before-v34-retry.log`,
with SHA256 `b48a0bb2e76ab35d6858bfc7343e7b734874d30c3101461aaf8f5dbde65231fb`.
One shared SDK visitor now preserves decode checks and counts additional
aligned validity-buffer space. Input, parameter, and checkpoint accounting use
this visitor. The host reserves retained data, this space, and schema buffers
before its single encoding pass. Shared capacity stays unchanged.
All seven reservation tests pass in 5.35 seconds. The log is
`/tmp/araphor-wasm-component-reservation-v35.log`, with SHA256
`f464958770595443ac2c85d42a55e375405c9a6bc10c8b11f62a5c26afc139cd`.
The SDK library suite has 51 passes in 0.58 seconds. It includes the original
sparse-null decode rejection and a million-row constant-Null round trip.
Its log is `/tmp/araphor-wasm-sdk-v35.log`, with SHA256
`d3fc2527726252632f836744bee8aad3c1fe4fc0e643ff1427a0e6e1101c10bc`.
The correction manifest is `/tmp/araphor-wasm-source-manifest-correction-v35.json`,
with SHA256 `368ac75c3f66fd1ecfedb773003f008fa620cd9a2f65685abf37fc912ff5ceec`.
Reproduce all six components from this SDK source, qualify installed execution,
and run final workspace verification before closure.

The generated-artifact correction is implemented. Host Cargo builds generate
all six components through `ComponentBuilder::workspace`. The existing built-in
crate owns the host artifact bytes in Cargo `OUT_DIR`. All 21 Data and e2e byte
callers use these bytes. Wasm builds skip host generation. The guest cache is
separate from the active native cache. A conflicting cache path is rejected.
The positional component encoder command stays unchanged. CI installs the
`wasm32-unknown-unknown` target. No generated Wasm file remains tracked.
Operator installation still consumes a built package and starts no source build.

Four builder tests pass. Two separate Cargo caches produce equal core and
component bytes for all six guests. Their core files have different inodes.
The ordinary host Cargo output also matches all six reproduced components.
The first and second source builds take 1 minute 33 seconds and 1 minute
8 seconds. These times are execution records, not performance results.
The proof is `/tmp/araphor-wasm-source-build-proof-v36.json`, with SHA256
`318e936fdd7865832b1a99061b43d2f4ab7438af91709afd91971069864fae94`.
The current build record is also in `wasm-component-build-proof.json`, under
`source_build_correction`. Earlier artifact records retain their original paths
and hashes. Installed execution and final workspace verification remain required.

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

- [x] Check installed package references and current authority before an
  unchanged graph notice returns a cache hit. A normal `process()` call must
  observe updates, removal, and revocation without a source revision change.
  Use the existing package lifecycle and graph health owners. Preserve
  historical results. Keep missing coverage and failures explicit. Add Rust
  checks for unchanged input, changed activation, removal, and revocation.
- [x] Close qualification stores before their temporary root. Drop the completed
  incident replay fixture before density and window checks. Await graph test
  server shutdown on failure and retain the original error. Return command
  failures through the synchronous entry point so Tokio can close. Keep every
  qualification assertion and the filesystem reserve check unchanged.
- [x] Save a successful unchanged graph check in existing per-result notice
  metadata. Use `facts_revision` for the provider notice, as Discovery does.
  Initialize new graph metadata from the captured provider notice. Convert
  every retained graph version through a checked schema migration. Validate
  prior native-format quota and backup records during conversion. Keep result
  bodies, native rows, request metadata, evidence references, IDs, receipts,
  processor progress, and notification deadlines unchanged. Save the notice
  inside the installed authorization fence. Check unrelated and relevant
  changes, multiple windows, revocation, retries, reopen, migration, and restore
  in Rust. Repeat current qualification after the last Rust edit.
- [x] Permit the existing graph unit test to call the raw authority join.
  Limit the method visibility to `crate::graph`. Keep its body and public API
  unchanged. Check the exact raw join before canonical edge publication.
- [x] Canonicalize the common credential edge evidence prefix once before
  relationship copies. The v26 core exhausts fuel in `quicksort<u64>` from
  `Computation::output`. Keep raw authority joins and finding evidence intact.
  Sort and remove duplicates from one separate edge prefix before the matched
  fact loop. Append each same fact record to both prefixes in the same order.
  Copy only the small edge prefix. Keep final publication checks, fact order,
  first representatives, direct-proof OR, branches, and checkpoints unchanged.
  Test raw joins, edge prefixes, final candidate rows, and retained finding JSON.
  Keep the original dense graph test and every production limit. Reproduce all
  six components before the original test and fresh production qualification.
- [x] Publish canonical evidence sets from the shared computation output.
  The host already sorts and removes duplicate evidence from every retained
  edge and finding. Keep the raw join, authority representatives, edge order,
  fact references, proof, coverage, and checkpoint unchanged. Sort and remove
  duplicates before candidate rows, matching reason details, and evidence links
  are encoded. Retain raw join assertions before publication. Test canonical
  rows and exact details. Add no type, schema, dependency, or alternate algorithm.
- [x] Check the derived graph JSON against the existing 4 MiB window limit.
  Use a checked byte-count writer without an output allocation. Stop counting
  at the limit and return the exact `graph output bytes` error. Keep historical
  stored reads unchanged. Keep the commit size check after position metadata
  is added. Canonical candidate evidence changes the earlier transport count;
  this check must bound the actual graph returned by derivation. Keep the
  original 256 records, 67 facts, split assertion, rollback, cursor progress,
  finding evidence, and all production component limits. Run that complete case.
Checked entries below record their correction scope. The v16 memory group
has 23 passes. The v16 lifecycle, runtime, and native graph group has 28
passes. These tests prove lifting error recovery, exact export selection,
input preflight, typed readiness, canonical and mixed-bundle digests,
compiler OS limits and cleanup, batch transfer, checkpoint retry, native
traversal inputs, and invalid evidence rejection. The committed owners are
`a6f870a3`, `fcd587ae`, and `2a89eefc`. The logs are
`/tmp/araphor-wasm-memory-and-reuse-v16.log` and
`/tmp/araphor-wasm-lifecycle-and-runtime-v16.log`.

The v20 discovery group proves all retained corpus cases and the corrected
context and forged-result cases. Earlier graph history and activation tests
pass in the interrupted v12 run. The retained diagnostic logs record the
IPC and fuel measurements. No temporary allowance remains in the runtime.
The v23 production package case proves the corrected replacement wait and
detector grant. These historical results do not close final-artifact or final
workspace qualification. The complete implementation gates remain open.

The v16 commit tests prove distinct grant checks, shared-store lifecycle
exclusion, construction exclusion, renewal, and suspension. The earlier
native graph tests prove the 128 MiB database limit, atomic package references,
header-only reference reads, context retention and closure, and backup restore.
The earlier adapter tests reject authority and coverage upgrades. The v23
installed detector case proves stored nondefault graph parameters. These
checked correction scopes remain subject to final workspace verification.

- [x] Inline the checked row writer methods with the standard Rust writer
  annotation. The v23 core retains one generic call for each JSON evidence
  number and comma. Keep both method bodies, byte checks, JSON, evidence,
  fixtures, and production limits unchanged. Run shared tests, reproduce all
  six components twice, and rerun the original production-limit split test.
- [x] Buffer JSON through the standard Rust `BufWriter` before the checked
  Arrow row writer. Use at most 8 KiB of scratch per row. Flush before the
  non-null row offset. Flush after a serializer error to retain byte-limit
  precedence. Keep schemas, typed fields, JSON bytes, evidence positions,
  partial-result rejection, and all production limits unchanged. Test large
  rows across flush boundaries and serializer failure with a byte limit.
  Reproduce all six components and rerun the unchanged graph split test.
- [x] Serialize JSON rows through the existing Arrow binary builder writer.
  The v22 graph split exhausts fuel during aggregate value-buffer growth.
  Remove the temporary row vector and its complete-row copy. Keep checked
  byte accounting before writes, empty-row completion, row order, JSON bytes,
  final array checks, and error behavior. Reuse Arrow `Write`. Test complete,
  empty, and rejected writes. Build all six components twice and rerun the
  original split assertion at production limits. Add no maximum-size reserve.
- [x] Index qualified credential authority identities during the existing scan.
  The v21 assertion proves exhausted guest fuel while relationship evidence is
  encoded. Remove repeated linear identity scans before encoding. Preserve the
  first fact representative, direct-proof OR, equal-record order, and every raw
  evidence value and position. Test duplicate identities, direct-proof changes,
  ties, and contextual fallback. Keep the original 256 records, 67 facts,
  4 MiB split assertion, and 100-million-fuel limit. Build components twice.
- [x] Include the deepest Wasmtime error in the unchanged graph split assertion.
  The v20 run still returns `PackageWasm::Limit` during relationship evidence
  encoding. Record the exact resource cause before the next correction. Keep
  production code, limits, records, facts, and the expected host error unchanged.
- [x] Reduce the number of installed calls for the largest discovery window.
  Use 128 complete identity groups per internal page. Keep the source window,
  duplicate groups, coverage, validation, 60-second outer deadline, and every
  guest limit unchanged. Move the page-equivalence fixture across the new
  boundary. Verify whole and paged output, then run all normal and replay cases.
- [x] Check direct-proof conditions before scanning carried channel facts.
  Evaluate the existing pure `carried` check last. Keep every direct result,
  evidence value and order, relationship, finding, and checkpoint unchanged.
  Use the existing exact and missing credential tests. Rebuild twice and run
  the unchanged graph split assertion with 100 million fuel units.
- [x] Implement `RowBuffer::write_all` with one call to its existing complete
  write operation. Preserve every JSON byte, checked byte charge, and error.
  Test complete writes and byte rejection. Build each component twice and
  compare bytes. Rerun the original graph split test at production limits.
- [x] Extend the existing `rare-forbidden` corpus case with installed group
  and comparison checks for normal and duplicate replay. Reuse its snapshots
  and a 64-record prefix baseline. Check exact counts, members, samples,
  coverage, denial, and forbidden groups. Add no second algorithm or larger
  limits. Run the complete corpus before closure.
- [x] Compile the direct Wasm evaluation wrapper only for unit tests. All
  production callers use the charged, encoded-input path. Check every caller
  and the normal build warning before this change. Run strict Clippy.
- [x] Reuse the validated immutable bundle during a pinned installed run.
  Charge retained bundle memory to the existing shared query budget. Keep
  tenant and version checks, fresh authority checks before and after each
  evaluation, cancellation, lifecycle fences, and the 60-second deadline.
  Rerun the largest normal and replay corpus cases.
- [x] Count retained descriptor, implementation, fixture, and input allocations.
  Share SDK schema accounting. Reserve component wire work before encoding.
  Encode each input once, then pass its owned bytes to Wasm execution. Reduce
  the reservation to actual input and wire allocations before invocation.
  Retain the charge until the result drops. Keep the shared 128 MiB input
  capacity, the 64 MiB input check, and SQL reservations unchanged. Verify
  reader-free reuse, root deduplication, last-clone release, historical replay,
  revocation, removal commit fences, and overlapping real guests.
- [x] Charge the descriptor and revision retained by `InstalledEvaluation`
  before cloning them. Use the existing retained-input lease. Release that
  charge when the result drops. Check quota rejection and result release.
- [x] Give the shared model evaluator a name that differs from the existing
  asynchronous query evaluator. Compile the current owner tests.
  Use workspace formatting for the new allocation modules.
- [x] Reserve Arrow schema-message scratch from descriptor capacities before
  encoding. Include inputs with no batches and large declared metadata. Check
  small allowances and retained lease release. Keep IPC and capacity unchanged.
- [x] Make historical repinning check the current activation and grant even
  when its caller holds an old snapshot. Test update and removal through that
  old handle. Keep historical computation read-only.
- [x] Construct the graph reason-details schema once per evaluation. Reuse it
  for every finding. Keep reason rows, evidence, output schemas, full source
  windows, SDK bindings, and production limits unchanged. Rebuild components
  twice and compare their bytes. Rerun graph evidence recovery and output-byte
  splitting at production limits.
- [x] Use the existing full-record digest for the opaque duplicate comparison
  string. Keep the original input revision and full-record conflict validation.
  Check the 1,024-delivery identity at the production fuel limit.
- [x] Bound internal discovery calls without changing the outer source window.
  Keep all deliveries of one identity together. Reject orphan context and
  exclusion rows. Partition coverage into adjacent pieces with the same total
  expected count and complete cursor bounds. Keep each expected count within
  its piece width. Preserve sparse-input gaps, lifecycle references, samples,
  and frozen replay. Pin installed execution once, use one finite outer
  control, and use installed computation for each part and its merge. Check
  the largest normal and replay cases, display groups, and comparison at the
  production limits. Commit no intermediate page result.
- Superseded correction: remove the larger unit-test data and fuel allowances.
  The source removed test-only overrides. The user now approves optional
  runtime quotas. Use the approved resource policy correction above; retain
  every large test and its assertions.
- [ ] Verify the complete current-algorithm corpus and resource failures with
  the same runtime configuration as production. Keep resource failures explicit and
  atomic. Run the four production cases before the final shared Rust procedure.
- [x] Recover filesystem space after the v12 test link failure. Remove debug
  sections only from inactive generated executables. Check every loaded
  section before and after cleanup. Keep source, native archives, component
  artifacts, logs, and proof files.
- [ ] Retry the final Rust procedure on the current source and record its result.
  The retained v12 retry exits 130. It is not a complete verification pass.
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
- Superseded proposal: set the component runtime data limit to 64 MiB and fuel limit to
  8 billion after the full corpus diagnostic. The 42 normal and replay calls
  pass with at most 6,741,078,368 fuel units. The previous draft limits reject
  the retained large cases. Keep guest memory at 256 MiB, guest time at five
  seconds, lifting at 32 MiB, and all lower query and descriptor limits.
  Remove test-only allowances and diagnostic output. Verify the same limits
  in production and tests. This measurement is not a performance result.
  Automatic approval review rejects this proposal. The current correction
  keeps 32 MiB and 100 million fuel units in production and tests.
- [x] Map the pinned Wasmtime output lifting fuel error to `Limit`. The runtime
  error type is private. Match its exact root error text. Keep the 32 MiB
  lifting limit. Require the existing 40 MiB output test to reach this error,
  return `Limit`, and permit the next evaluation.
- [x] Select the exact active package export for an unpinned evaluation under
  the shared lifecycle lock. Keep explicit snapshots and historical pins equal.
  Keep the selected grant, complete dependency bundle, and execution checks.
  Verify that an unrelated revoked package does not prevent this evaluation.
  Require selected revocation to fail and a non-prepared target to return the
  existing unsupported-target error.
- [x] Diagnose the discovery activation interval failure in the full Rust
  procedure. Keep the saved-profile, new-interval, and historical replay checks.
  Correct the owner or test fixture from the reproduced error.
- [x] Give discovery revision update and removal tests an explicit finite
  30-second operation control. The default read control expires after one
  second. Keep production deadlines and all revision and replay checks.
- [x] Give graph installed-history update and removal tests an explicit finite
  30-second operation control. Keep the historical package, witness expiry,
  restart, and removal checks. Keep production deadlines.
- [x] Check graph installed-history progress through cursor 3 with the existing
  bounded `process_to` test helper. `process` returns the count of changed
  source windows. Keep all three input records and all history and expiry checks.
- [x] Diagnose the discovery corpus parity failure in the full Rust procedure.
  Preserve every corpus case and correct the reproduced failure.
- [x] Add a temporary test diagnostic at the discovery adapter evaluation
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
- [x] Diagnose duplicate context projection and host-change rejection failures
  in the full Rust procedure. Keep exact identity and evidence validation.
- [x] Record the Wasm trap cause and remaining fuel in a focused test
  diagnostic. Remove the diagnostic before final Rust verification.
- [x] Measure fuel in the existing duplicate, corpus, and graph recovery
  tests. Use a temporary test-only fuel allowance if a failed call cannot
  report its full fuel cost. Keep production fuel, guest deadline,
  cancellation, and memory limits unchanged. Remove the diagnostic before
  final Rust verification. Use the results to select a reviewed correction.
- [x] Share component data, row, batch, and checkpoint limits under the Wasm
  execution owner. Measure the full corpus with a temporary test-only 64 MiB
  data limit. Keep the production data limit unchanged during the diagnostic.
  Keep the separate 32 MiB guest-to-host lifting limit, configured query input
  limit, memory reservations, guest deadline, and cancellation checks.
- [x] Make the forged physical-result candidate structurally valid in the
  host-change test. Change its decision and kernel result to match the forged
  physical result. Require host validation to reject it against retained wire
  evidence. Keep the identity and lifecycle attack cases.
- [x] State each execution failure path in the review flow. The generic package
  scheduler records typed readiness and stale results. Domain adapters return
  errors to their existing owner failure and coverage paths.
- [x] Remove the unused error conversion in Control configuration.
- [ ] Run the final Clippy check with warnings denied.
- [x] Recover filesystem capacity after workspace test linking fills the disk.
  Remove debug sections from inactive generated executables. Verify that all
  loaded sections stay equal. Preserve source, native archives, logs, proof
  data, and the production qualification executable.
- [ ] Rerun the shared Rust procedure and the affected restart and graph cases.
- [ ] Diagnose the graph qualification read deadline. Record the failed stage,
  read operation, and last completed source cursor. Keep all corpus cases,
  graph state assertions, production deadlines, and resource limits. Remove
  temporary diagnostics before the final qualification.
- **Superseded diagnostic:** Use a private Snafu context for the temporary qualification deadline
  diagnostic. Retain the original Data error as its source. Show only the
  operation, requested source ID, elapsed time, and original deadline location.
  Add no dependency. Remove the context after the cause is known.
  The context was added and then removed. The retained diagnostic does not
  identify the earlier deadline cause. Current qualification uses ordinary
  error propagation and retains every production assertion and limit.
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
- [x] Diagnose the SQL automatic replacement timeout after the installed
  detector case. Keep the original failure decision during the diagnostic.
  Fix the cause and rerun the production qualification.
- [x] Reuse the admitted bundle in each supervisor iteration. Remove the second
  full artifact read. Keep the grant and admission checks. Set the qualification
  wait to 120 seconds after the diagnostic shows completion at approximately
  40 seconds. Keep the production scheduler and result assertions unchanged.
- [x] Check the local query deadline after output validation. Reject an expired
  result and release its memory lease. Verify that the caller deadline can
  remain valid while the shorter query deadline rejects the result.
- [x] Reject host input allocation above the query limit before an installed
  call clones input or starts compilation. Use one shared query input check.
- [x] Preserve typed component and SDK limit errors in package readiness.
  Record interrupted evaluation as incomplete. Verify no result or fallback.
- [x] Use canonical descriptor JSON for component package digests. Arrow metadata
  maps must produce the same digest after read, install, restart, and replay.
  Preserve the existing SQL package encoding and its trust pins.
  Share this encoding with immutable component revision writes. An identical
  installation must not fail because an Arrow metadata map changes key order.
- [x] Canonicalize all descriptors in a mixed SQL/component bundle. Keep the
  previous standalone SQL encoding. Reuse an existing immutable SQL revision
  only when its decoded descriptor, artifact, and dependencies are unchanged.
  Verify mixed-bundle digest, installation retry, reopen, and changed code.
- [x] Share one component across its declared exports. Raise the bounded package
  and transport limits to hold the compiled artifact. Use no install hook.
- [x] Account for Arrow schema memory. Reject compressed IPC before decoding.
  Keep host input charges until the adapter releases its evaluation.
- [x] Compile in a fresh host worker with OS memory and CPU limits. Kill and
  reap the worker on cancellation or deadline. Accept compiled code only from
  this worker. Keep the compiler permit until the worker exits.
- [x] Measure the source and compiled image charges for each required component.
  Set a finite cache byte limit that retains all four required components.
  Keep tests for byte and entry eviction. Retain the runtime test component
  in the shared test cache only when all five charges fit this limit.
- [x] Prove initial memory rejection with an instantiated core module. Require
  the resource limit error before the host checks the analysis exports.
- [x] Retain package artifacts referenced by saved domain context. Replay with
  saved parameters and current permission. Reject historical commits.
- [x] Pass the host-selected AR-04 context dataset through an installed
  component. Verify exact identities, cutoff, revision, coverage, and omissions
  in `context-roundtrip`. Keep selection and permission on the host.
- [x] Transfer multiple input batches, including an empty batch, through a
  real component. Verify computation across all batches.
- [x] Supply a prior checkpoint to a real stateful component. Verify next
  state, restart, and identical retry through the production package lifecycle.
- [x] Supply bounded native graph input and traversal output to an installed
  component. Verify the selected versions and rows without snapshot conversion.
- [x] Reject an invalid evidence row from a real guest. Preserve a guest SDK
  limit error in installed readiness. Verify that neither failure commits output.
- [x] Use a finite 300-second service grant in the installed detector
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

The `fixture_cache_charges_fit` test recorded these figures for the earlier
artifacts on Linux x86-64. They predate the SDK and graph schema corrections.
The test kept all five entries below the 80 MiB and
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
The unchanged-limit correction supersedes this proposal. Production and tests
now use 32 MiB and 100 million fuel units. The final shared Rust procedure and
production qualification remain required at these limits.

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
`/tmp/araphor-wasm-rust-ci-final-v12-retry-result.json`. No final pass is recorded.
Production limits remain 32 MiB data and 100 million fuel.

The retry passes formatting, workspace check, strict Clippy, and test linking.
The workspace tests start. Checked removal of debug sections from nine more
inactive generated executables recovers 10,809,909,456 bytes. All loaded sections
stay equal. Its proof is `/tmp/araphor-strip-proof-20261011-ci-v12-retry.json`.
The live run receives a controlled SIGINT before the required production-bound
discovery correction starts. It exits 130 and leaves no CI descendant. No
timeout or terminal test failure causes the stop. Workspace tests remain
incomplete. The log SHA-256 is
`5a870fce9d077ac6fe0c9f6ad04bbf4545720d2dc2ae5e7b688d3d1bfb1c15c4`.
A new final procedure is required after the last correction.

The v9 graph diagnostic exits 1 when AnalysisStore reaches its filesystem
reserve. It does not identify the earlier read deadline. Its log is
`/tmp/araphor-e2e-graph-notification-diagnostic-v9.log`, with SHA-256
`bd78181bd02ff2edf00c93ad0431262aeb3e03144904162adcf47db745dd5a51`.
Its result is in
`/tmp/araphor-wasm-qualification-20261011-sol-v9/e2e-qualification-proof.json`.
At that time, the proposed production limit change and final production
qualification remained open. The later unchanged-limit correction supersedes
the proposed increase. Production limits remain 32 MiB and 100 million fuel
units. Current final qualification remains required.

### Data adapter correction TODOs

- [ ] Correct the native database memory budget for bounded component artifacts.
  A production package revision read fails at the previous 64 MiB cap. Keep a
  finite cap, verify its rejection boundary, and rerun graph and SQL lifecycle
  qualification. Check reader release and repeated bundle reads before a fix.
  The 128 MiB implementation and focused checks are complete in the next items.
  Current graph qualification and final workspace verification remain required.
- [x] Set the native database memory limit to 128 MiB. Use the same constant for
  backup validation. Keep the graph window limit at 4 MiB. Check the native
  settings and resource rejection. Verify installed package reads and restore.
  This setting limits native database buffers. It does not limit process RSS.
- [x] Match the native allocation failure and its reported reason in the
  rejection test. The pinned DuckDB binding does not retain the native error
  type in `Connection::execute`. Do not compare its unused error-code variant.
  Pass the SQL repetition length as `BIGINT`.
- [x] Permit trusted host-prepared exports with declared Table outputs through
  `InstalledAnalysis`. Keep graph and discovery output checks on their domain
  adapters. Verify typed native graph input and the AR-04 context packet.
- [x] Keep the validated graph package provenance reference in the atomic
  result commit. Exclude this sidecar from the visible input manifest check.
  Verify a production graph commit and the bounded header reference read.
- [x] Validate the installed package references in native context records before collection and during recovery. Check the typed reference fields, tenant scope, names, generation, export, revision, root, and retained dependency closure. Permit a source record without these references only for the previous discovery format. Reject malformed new references. Verify reopen and backup restore.
- [x] Read graph package references from the bounded native header. Do not read graph rows to obtain the source key. Verify that the reference read does not reconstruct rows.
- [x] Use a finite 60-second outer deadline for host component calls. Permit compilation after reopen with an empty code cache. Keep the compiler and guest execution limits separate. Verify replay with a new production package owner.
- [x] Check each distinct saved grant at domain commit, including different grants for the same package root. Verify that removal of the second grant prevents the commit callback.
- [x] Share the package lifecycle lock between owners that use the same store. Verify that a second owner cannot change an activation while a domain commit holds that lock.
- [x] Hold the shared lifecycle lock during owner construction and package admission collection. Verify that a second owner cannot collect a package row before the first owner completes activation.
- [x] Keep previous-schema graph fixtures free of package rows. Use an isolated installed execution handle for native storage tests. Install packages in the tested store when the test checks retained package context.
- [x] Hold the shared lifecycle lock for Run grant renewal and supervisor
  suspension. Release this lock before guest execution. Verify that neither
  operation changes an activation during a domain commit. Use the normal
  30-second fixture control for these concurrency tests.

- [x] Validate graph output with the saved effective package parameters.
- [x] Retain exact installed exports, revisions, activation generations, and
  configured parameters in discovery and graph context. Use these references
  for historical replay. Do not combine different references in one profile.
- [x] Keep causal proof, confirmation, and coverage validation on the host.
  Reject a package result that increases these claims without qualified input.
- [x] Change former unsupported-Wasm fixture cases to the unsupported Native
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
