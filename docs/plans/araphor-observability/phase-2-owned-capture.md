# Phase 2: Owned Diagnostic Capture

Connect qualified diagnostic execution to exact Araphor targets and existing
durable storage. Require [Phase 1](phase-1-contracts-and-backend.md) Done.
Complete shared recovery integration after Phase 7.2. Capture
belongs to Control and must not require discovery analysis to be enabled.

## Intended end state

One accepted request creates at most one execution per frozen target lifetime.
Output, uncertainty, and cleanup survive client and Control failures. Existing
enforcement and its evidence reserve remain independent.

### Shared implementation crate

Put the shared trace contracts, recipes, grant checks, request owner and local
capture owner in `araphor-observability`. Control and Node call this crate.
The crate does not depend on `mithril-control` or `mithril-node`.

Control authenticates callers and Nodes, resolves authorized target cohorts,
issues grants, signs dispatch and checks disclosure. Node resolves current
runtime bindings and supplies an exact target lease to the shared capture
owner. The shared owner retains bounded output and handles expiry, replay and
restart. Interceptor retains backend supervision and cleanup. AnalysisStore in
`araphor-data` remains the only retained-output store.

Move existing implementations and their tests. Do not add another service,
database, protocol or execution owner. Keep shared workload facts and digest
encoding in one lower-level definition. Keep the current executable and
protobuf names; a repository-wide rename is outside this change.

## Implementation flow

```text
TraceOwner accepts an authorized request
  -> target resolver freezes authorized workload/container/node lifetimes
  -> AnalysisStore commits source, grant, target snapshot, and dispatch identities
  -> authenticated node-control service sends the bounded execution grant
  -> Node records intent and revalidates each lifetime before attachment
  -> Interceptor runs the reviewed or separately privileged script
  -> Node appends output to its bounded diagnostic spool
  -> AnalysisStore syncs self-contained output commits and publishes its raw receipt
  -> Control returns an output ACK after the durable segment commit

Identity changes, the lease expires, or cancellation arrives
  -> Node stops that execution without following replacements
  -> Interceptor drains and verifies cleanup within the qualified limits
  -> Control records per-target result and remaining uncertainty

Control or Node restarts after dispatch
  -> owner recovers the original execution identity
  -> duplicate dispatch does not spawn again
  -> uncertain child state is reconciled or terminated, not rerun
```

## Scope, owners, and changes

1. Put `TraceOwner` in `araphor-observability`, called by Control and backed by
   `araphor-data` AnalysisStore owner methods. Commit immutable source and
   request records with revision-checked state. Control decides transitions;
   the data crate commits them durably. Store source once; do not place output in the main state
   image. New requests, read grants, execution grants, and approvals are distinct.
2. Extend the authenticated protocol in
   `crates/mithril-control/proto/erebor/mithril/control/v1/control.proto` with
   a diagnostic service family. Bind dispatch, output and cancellation to
   `NodeSessionContext`, node boot, and execution identity. Limit message sizes.
   Reuse existing trust/session verification; no agent-to-node endpoint.
3. Put the local capture owner in `araphor-observability`, called by Node.
   Keep the spool
   separate from enforcement WAL quotas. Start with at most two concurrent
   diagnostic children per node and 16 target instances per request. Reject
   excess work; do not add an unbounded queue. Reserve a terminal-status slot.
4. Reuse Control workload inventory and Node lifetime checks. Resolve human
   names once. Freeze controller membership. Record denied, disappeared,
   unsupported, and failed participants separately. An empty cohort fails.
   Missing identity for an unprotected workload is Unsupported, not a reason
   to guess from labels. Limit the first scoped recipes to cgroup-v2 contexts
   whose current-task attribution is qualified.
5. Add reviewed syscall-error and failed-open recipes to the existing fixture
   tree. Their immutable manifests define parameters, sensitivity, supported
   hooks, output schema and cost limits. No arbitrary path or memory argument
   is a safe parameter merely because its type is string. Prevent parameter
   values from broadening collection. Preserve raw source for inspection.
6. New source uses the separately granted host-diagnostic path described in
   the parent. Do not expose arbitrary source under a namespace-only grant.
   Pin complete approved inputs; reject stale approvals and changed source.
7. Add `traces`, `trace_output` and `trace_measurements` to AnalysisStore in
   `araphor-data`. Move the existing model, owner, dispatch and recipe code to
   `araphor-observability`.
   adapt `TraceOwner` to owner-qualified data commits and reads.
   Store raw output only in diagnostic segments. The durable segment commit
   contains the output sequence and replay metadata. Catalogue publication
   does not delay output ACK. Trace intent and lifecycle changes remain
   transactional derived-state operations.
   Reuse 7.2 snapshot leases, exact references, whole-segment retention charges,
   and complete-bundle backup. No duplicate raw trace table is permitted.
   Equal execution/source sequence and bytes is a retry; changed bytes reject.
   Typed measurements require reviewed schemas. Preserve cumulative/interval
   semantics, units, reset epoch, sampling and loss; do not sum snapshots.
8. Wire shared data recovery in `config.rs`, `main.rs` and `service.rs`.
   Trace admission uses AnalysisStore readiness, not `ControlConfig.discovery`
   or `discovery_recovered`. Prove capture with discovery disabled.
   Data-store failure returns no upload ACK; Node expiry and spool limits
   remain effective.
9. Define scoped trace relation schemas and bounded owner reads.
   Observability 3 registers them with the qualified QueryOwner and reuses its
   append reader for the output API. No trace-specific subscription queue or
   second database is required. Retention and read-grant checks belong to the
   shared data boundary. Reserve terminal-state capacity before spawn.

Use the committed Node spool cursor to skip reads with no new durable frames.
Run inactive-spool recovery at startup and after intent or worker changes,
not on every unchanged upload poll. Mark recovery pending before intent
creation, which can fail after its final rename. Keep recovery pending after
a failed write, worker join or directory sync. Clear recovery pending only
after successful recovery. Keep target, lease, cancellation, authorization,
quota, sync-before-ACK and cleanup checks unchanged. Do not change the
bpftrace source or collection settings to improve a measurement.

Status: **Not done** for complete capture qualification. The storage checks
below do not replace physical capture checks on the implementing revision.

### Storage bounds

AnalysisStore has one raw segment owner for evidence and diagnostic output.
Diagnostic records use typed frames and a terminal record. A terminal has its
own stored cursor; an upload ACK reports the last output-frame sequence.
CRC32C checks raw records. Source and grant digests retain their separate
authorization purpose. No raw-output hash catalogue or SQL batch-offset table
is required.

The diagnostic logical-byte partition is one eighth of each global and tenant
limit. Admission reserves 16 KiB and file-entry capacity for each execution's
terminal state. A terminal-only commit can use that reservation under ordinary
quota pressure. It must still preserve the policy reserve and pass physical
write and sync checks. New output frames do not get that exception.

There are at most 1,024 retained requests and executions globally and 256 of
each per tenant. These are retained-history limits, not active-execution limits.
Raw retention does not remove request identities or terminal receipts. At the
limit, new requests fail with capacity status. Exact retained retries still
work. Automatic metadata expiry is not implemented; it requires an explicit
rule for when an old request can no longer be retried. Do not describe these
bounds as unlimited continuous admission.

Diagnostic segment files have a separate 1,024-entry allowance. They do not
consume the ordinary 4,096-entry allowance. Actual file bytes remain subject
to the shared disk limit. Whole-segment witness charges and read leases apply
to both stream kinds.

### Verified implementation slices

Source `cdb3cbe7` moves portable source, frame, terminal, measurement and batch
types into `araphor-data`. Control re-exports these types. Control still owns
grants, target resolution, dispatch and reviewed recipe decoding. Wire fields
and existing validation stay unchanged. The focused `observability_` library
run passed 35 tests; four process or physical tests were not selected for
ordinary execution.

Source `692e4f16` adds immutable trace intent storage to AnalysisStore. One row
contains source bytes, exact execution bindings and a bounded Control record.
Cancellation and read revocation use revision checks. These changes use
maintenance capacity. Intent reads return at most 16 requests and do not
publish pending raw commits. Schema 11 rejects older databases; no migration
or automatic deletion is provided.

The five `observability_intent_` tests passed. They cover restart, exact retry,
changed-input rejection, monotone state, tenant separation, paging, corrupt
metadata, cancellation under pressure, and deferred raw publication. Run:

```sh
CARGO_TARGET_DIR=/home/navid/go/src/github.com/Ereborlabs/erebor-runtime/target \
CXXFLAGS='-O2 -g0' CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 \
CARGO_NET_OFFLINE=true RUST_TEST_THREADS=1 \
cargo test --locked -p araphor-data -p mithril-control -p mithril-node \
  -p mithril-e2e --all-features --lib observability_intent_ -- --nocapture
```

Use `observability_` instead of `observability_intent_` for the portable-type
check. Receipts are `portable-contract-2.log` and `trace-intent.log` under
`/tmp/araphor-capture-qualification.E0VU3eEo/`. These results do not prove the
raw-output migration, Control integration, diagnostic reservations, or physical
lifecycle gates. The later slices below record those results. No performance
experiment ran for this slice.

Source `13cc6076` adds a test-only exit hook after durable Node intent and
before backend execution. The child exits with code 73. Reopen preserves the
execution identity and reports `NodeRestarted`, incomplete output and unknown
cleanup. An exact duplicate dispatch does not reach the hook again. The Node
`observability` filter passed seven tests. Two tests remain excluded from
ordinary execution: the child helper and the physical disk-full case. The
parent test invokes the child helper explicitly. The receipt is
`node-intent.log` in the same evidence directory. This proves the pre-spawn
process boundary, not post-attachment cleanup or physical enforcement recovery.

Source `680dd2c2` connects Control trace methods to shared diagnostic segments.
The data owner stores frames once. It returns the raw receipt after sync, before
DuckDB publication. Schema 12 rejects older metadata. Control retains grants,
target checks and disclosure checks. It no longer writes trace artifacts or
projects trace rows through DiscoveryIndex. Capture does not start discovery.

The focused `observability` run passed 58 tests: data 18, Control 17, e2e 14,
CLI parsing 2, and Node 7. Five helper or physical cases were not selected for
ordinary execution. The e2e owner-upload case checks signed mTLS dispatch,
lost ACK, exact retry, conflicting output, a post-sync storage error, store
unreadiness, reopen and replay with discovery disabled. Its injected failure
is not a physical full-disk result. It does not yet run a Node capture worker.

The same compiled data test binary passed 109 `analysis::` regression tests;
five existing exclusions were not run. The exact
`query::input::tests::query_input_catalog_bounds` check also passed. Receipts
are `shared-capture-3.log`, `shared-analysis.log` and `catalogue-schema.log` in
the evidence directory above. Use the documented Cargo environment and the
`observability` filter without `--lib` to include the CLI parser tests.

Source `5b716fe6` preserves terminal capacity when an active segment is pinned.
The segment owner seals that file and writes the terminal to a reserved new
file. This does not increase the pinned file's charge. Backup capacity checks
also preserve diagnostic file slots and terminal bytes.

Six new checks passed in `capture-hardening-2.log`: pinned-terminal recovery,
read versus retention, segment rotation and lifetime totals, incomplete backup,
backup reservations, and process exits at six raw-commit boundaries. The crash
check uses both an output-plus-terminal batch and an empty terminal. Exact
replay produces one retained copy. This run passed 24 data checks and failed
the separate quota-pressure fixture; it is not a complete-suite pass.

Source `e4a332c1` adds tenant and global quota-pressure checks. New frames fail
under ordinary pressure. A terminal-only commit uses its reservation once;
retry and reopen preserve the receipt and quota totals. The initial fixture
failure came from a repeated result ID across tenants. The corrected check
passed without a production quota change.

The corrected `observability` run passed 68 checks: data 25, Control 20, e2e
14, CLI parsing 2, and Node 7. Seven helper or physical cases were excluded
from ordinary execution. The receipt is `capture-hardening-fixed.log`. This
run precedes the final nonempty-schema-zero rejection and combined failed-ACK
case described below.

Source `4ec3d360` rejects retired DiscoveryIndex schemas before a writable
connection or install rename can change them. The current schema is 6. Schema
zero is valid only for an empty database. A new index has no trace tables.
The owner does not migrate an old schema. Three `observability_index_` checks and the
exact `discovery::index::tests::discovery_index_sealing_reopen` check passed.
Receipts are `capture-index-final.log` and `capture-sealing-final.log`.

Source `1a5da4c0` extends `owned-capture` through the production Node owner and
Interceptor supervisor. Its external inputs are a process command, binding
readback and admission clock. Four cases check target replacement, cancellation,
Control partition and failed storage ACK. The storage fault occurs after real
segment sync while capture is active. Node keeps its output and ends at its
local lease. Store reopen recovers that exact prefix. Replay returns one copy
and a stable ACK; Node retires output only after that ACK. Each case launches
once. Cleanup remains unknown and kernel loss remains unspecified.

The final exact `observability::tests::observability_owned_upload` check passed
in 16.27 seconds. Its receipt is `owned-chain-final.log`. This result does not
prove Node polling/retry scheduling, physical BPF cleanup, or real disk-full
behavior. The lightweight lifecycle cases also passed after output-limit cases
received a separate collection budget. Deadline cases retain their original
deadline; no latency or throughput claim follows from these correctness tests.

Source `06e614e4` adds the Node-process restart harness. The final focused build
compiled it, and `bash -n` passed for `owned.sh`. No physical restart result is
claimed. Supply a qualified configuration as the fifth argument and
`restart-before` or `restart-after` as the sixth argument. The four-argument
form runs the interference experiment and requires separate approval. The
script rejects a successful test command that did not write its expected proof.

Source `6887a178` corrects the shared tenant-read test and removes prohibited
test unwraps. The failed workspace run had rejected the foreign read with
`AnalysisState: the raw source is absent`. Its assertion expected the old
evidence-only text and incorrectly reported that the read succeeded. The
corrected check still requires that exact typed absence. It reports other errors separately from a
successful read. No production read or authorization rule changed.

The exact `data_load_contract` check reproduced that failure, then passed.
The exact `data_tenant_load` check also passed. The Node `observability` filter
passed seven tests; two helper or physical cases were excluded from ordinary
execution. Receipts are `capture-data-load-red.log`,
`capture-data-load-green.log`, `capture-data-tenants-green.log` and
`capture-node-lint-green.log` in the same evidence directory. The e2e commands
used the documented Cargo environment and the full test names under
`discovery::data_store::tests::`, with `--exact --nocapture`.

The final workspace procedure passed at source `6887a178`, after the last code
edit. Formatting, workspace checking, Clippy with warnings denied, and all
selected workspace tests passed. The receipt is `capture-workspace-final-5.log`
in the same evidence directory. Run from `worktrees/mithril-ui`:

```sh
CARGO_TARGET_DIR=/home/navid/go/src/github.com/Ereborlabs/erebor-runtime/target \
CXXFLAGS='-O2 -g0' CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 \
CARGO_NET_OFFLINE=true RUST_TEST_THREADS=1 \
bash .github/scripts/verify-rust-ci.sh
```

Main library results were Data 166 passed (5 ignored), Interceptor 39 passed
(1 ignored), Control 185 passed (2 ignored), e2e 133 passed (409 ignored), and
Node 267 passed (2 ignored). The owned-capture chain and both corrected tenant
checks passed in this run. Ignored physical cases are not qualified by this
procedure. No performance or interference experiment ran.

Source `7dc26bd2` adds the owned physical capture harnesses. The exact
`observability::tests::observability_owned_upload` check passed in 17.33 seconds.
Its receipt is `capture-harness-focused-3.log` in the same evidence directory.
Use the documented Cargo environment and these arguments:

```sh
cargo test --locked -p araphor-data -p mithril-control -p mithril-node \
  -p mithril-e2e --all-features --lib \
  observability::tests::observability_owned_upload -- --exact --nocapture
```

The Node chain now has five cases. The new `BeforeAppend` case injects a
storage error before the raw write. That hook leaves the writer ready. The
case stops Control transport until local expiry, then reopens Control and data.
Reopen has no output and a zero-progress terminal reservation: sequence, bytes
and commit revision are zero; the terminal is absent. Replay stores one copy
and does not start another child. The existing `AfterSync` case still checks
an unready writer, no ACK, a recovered synced prefix and exact replay. Neither
injected error is a physical full-disk result.

Compilation includes the ignored Pod, restart and full-store entry points.
`bash -n` passed for `owned.sh`, `pods.sh` and `disk-full.sh`. No owned physical
case or performance experiment ran at this source.

The workspace procedure above passed at source `7dc26bd2`, after the final
code edit. Formatting, workspace checking, Clippy with warnings denied, and
all selected workspace tests passed. The receipt is
`capture-workspace-final-6.log` in the same evidence directory. Main library
results were Data 166 passed (5 ignored), Interceptor 39 passed (1 ignored),
Control 185 passed (2 ignored), e2e 133 passed (412 ignored), and Node 267
passed (2 ignored). The three new physical entry points were ignored, not
executed. This result does not qualify physical capture or interference.

Source `9d570500` moves shared trace contracts, recipes, grant checks,
TraceOwner, NodeTraceOwner and the exact target lease into
`araphor-observability`. Control and Node call the same implementations.
Control retains authentication, current inventory, grant issuance, signing and
transport. Node retains runtime binding resolution. Interceptor retains backend
supervision. AnalysisStore remains the only retained-output store.

Shared workload facts, container kind, digest and canonical encoding now have
one definition in `araphor-data`. The digest check preserves the existing
domain and exact bytes. The target lease checks the held descriptor, current
path and native binding lifetime. The shared crate does not depend on either
application crate. Existing executable and protobuf identifiers do not change.

The focused `observability` library run passed 66 tests: Data 25, shared
observability 21, Control 5, e2e 14 and Node 1. Ten physical or subprocess
entry points were ignored as standalone tests. The parent tests invoke their
subprocess helpers. The exact `target_rejects_replaced_lifetime` and
`digest_preserves_canonical_domain` checks also passed. Receipts are
`crate-focused-2.log`, `crate-target.log` and `crate-digest.log` in the evidence
directory above. Use the documented Cargo environment and run:

```sh
cargo test --locked -p araphor-observability -p araphor-data \
  -p mithril-control -p mithril-node -p mithril-e2e \
  --all-features --lib observability -- --nocapture
```

The physical experiment writes its qualified configuration only after the
measured pairs pass validation. These component results do not qualify physical
capture or interference.

Source `3248d2a0` keeps the Node error size bounded with a boxed shared error.
Workspace checking and Clippy with warnings denied passed. The final workspace
run in `crate-workspace-final-3.log` passed 167 Data tests and 22 shared
observability tests. That run then failed the Interceptor parent-death check
with `No such file or directory`. The shared `target` directory disappeared
during the run. The child test uses the current test executable, which was no
longer present. This is not a complete workspace pass.

The replacement workspace run uses
`CARGO_TARGET_DIR=/home/navid/go/src/github.com/Ereborlabs/erebor-runtime/worktrees/mithril-ui/target`.
It uses the same Cargo environment and verification script above. The run in
`crate-workspace-final-4.log` completed native compilation and workspace
checking. That run stopped before the full test suite to include the bundle
correction below. The final run uses the same worktree-local cache. Its receipt
is `crate-workspace-final-5.log`. The interference experiment has not run.

Source `c9e6b802` permits the literal `+` in native library names. The actual
bpftrace dependency is `libstdc++.so.6`. The bundle still rejects path
separators, shell metacharacters, whitespace, symlinks and replacement system
libraries. The exact `platform::kubernetes::observability_runtime_library_names`
check passed. Its receipt is `capture-bundle-names.log` in the evidence directory.

The backend bundle is prepared on the owned VM at
`/var/tmp/araphor-capture-inputs.VMoOpWq2/backend-runtime.olmFu3lr`.
All 20 checksum entries passed. Native loader checks resolve the 19 bundled
libraries and the new test executable. These checks do not execute a trace or
qualify capture.

The final workspace procedure passed at source `c9e6b802`, after the last Rust
edit. Formatting, workspace checking, Clippy with warnings denied and all
selected workspace tests passed. Main library results were Data 167 passed
(5 ignored), shared observability 22 passed (2 ignored), Interceptor 39 passed
(1 ignored), Control 170 passed (2 ignored), e2e 134 passed (412 ignored), and
Node 261 passed (none ignored). The owned-capture chain and bundle-name check
passed. Ignored physical cases remain unqualified.

Run from `worktrees/mithril-ui`. The receipt is `crate-workspace-final-5.log`
in the evidence directory above:

```sh
CARGO_TARGET_DIR=/home/navid/go/src/github.com/Ereborlabs/erebor-runtime/worktrees/mithril-ui/target \
CXXFLAGS='-O2 -g0' CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 \
CARGO_NET_OFFLINE=true RUST_TEST_THREADS=1 \
bash .github/scripts/verify-rust-ci.sh
```

The approved experiment at source `c9e6b802` stopped at Node configuration
validation. The fixture reserved 256 MiB. Its evidence WAL limit was also
256 MiB. Node requires 272 MiB to include 16 MiB for metadata. No measured pair,
trace output or qualified configuration was written. The launch returned 101.
The test log records 1.75 seconds. The receipt is
`capture-vm153-pairs-preflight.log` in the evidence directory above.

Source `2f87a2b3` sets the fixture reserve to 272 MiB. One configuration supplies
the active run and the saved measured qualification. The production check,
WAL limit, spool bounds and measurement limits do not change. The exact
`config::tests::observability_target_wal_reserve` check passed before the
fixture correction. It rejects 256 MiB and 272 MiB minus one byte; 272 MiB
passes. Its receipt is `capture-reserve-focused.log`.

The final workspace procedure passed at source `2f87a2b3`, after the fixture
correction. Formatting, workspace checking, strict Clippy and all selected
workspace tests passed. Main library results were Data 167 passed (5 ignored),
shared observability 22 passed (2 ignored), Interceptor 39 passed (1 ignored),
Control 170 passed (2 ignored), e2e 134 passed (412 ignored), and Node 262 passed
(none ignored). The receipt is `crate-workspace-final-6.log`. Use the same
worktree-local command above. The unchanged experiment uses the original
approval below. Read its physical result below. These workspace results do
not qualify the physical capture gates.

### Current production images and physical attempt

The production Dockerfile built both images from Rust source `2f87a2b3`.
The Node build resumed its existing process and returned zero. The Control
build reused the same release stage and returned zero. Native loader checks
passed for all five packaged binaries in read-only containers without network
access. These image checks do not qualify diagnostic execution.

| Image tag | Image ID |
| --- | --- |
| `mithril-node:araphor-owned-capture-20261002` | `sha256:5e2dc4f64bb3a9b5efadf9fdb95acf0199310a7a20bf62d64b3296024d917130` |
| `mithril-control:araphor-owned-capture-20261002` | `sha256:1135207618c4f2b9f45714127fdf0b2e3e66492300d19bb6bdae9b543f6627f8` |

Read `capture-node-image.log` and `capture-control-image.log` in the evidence
directory above. Existing image tags remain unchanged.

The approved physical attempt used the same workload and limits. It recorded
three individual runs, not five complete pairs. Each recorded run reports
1,000 EACCES denials and zero drop or write-error counters. The first complete
pair has p99 values of 308,718 ns without tracing and 354,362 ns with tracing.
The increase is 14.785%, which exceeds the approved 10% limit. The next
trace-off run has p99 of 323,644 ns. The first trace terminal records `Deadline`,
complete output and verified cleanup.

The test failed before the second trace-on run. Node readiness timed out with
`admission_ready=false`. Saved coverage contains `CLASSIFIER_MISS` and
`UNRESOLVED_EFFECT`. The fixture opens `/proc/self/environ`; its policy has no
file rules. Zero drop counters do not establish healthy evidence coverage.
The test reports 147.95 seconds. The launcher returns 1. No qualified
configuration was written. Do not use this partial receipt to enable capture.

Run command on the owned VM:

```sh
sudo -n timeout --signal=TERM --kill-after=10s 590s bash \
  /mnt/mithril-source/worktrees/mithril-ui/crates/mithril-e2e/harness/observability/owned.sh \
  /mnt/mithril-source/worktrees/mithril-ui/target/debug/deps/mithril_e2e-69abcc1defdc24e3 \
  /var/tmp/araphor-capture-inputs.VMoOpWq2/fixtures.tar.gz \
  /tmp/araphor-observability-153-pairs-fixed 1000
```

Receipts are `capture-vm153-pairs-fixed-test.log`,
`capture-vm153-pairs-fixed.json` and `capture-vm153-pairs-fixed-coverage.json`
in the evidence directory above. The workload and readiness failure require
review before another measured run. Keep the production readiness checks and
the approved limit unchanged. Status remains **Not done**.

Remaining work is execution of the physical lifecycle gates below.
Physical enablement requires a platform-matched interference receipt. The
user approved the experiment below. Keep the phase **Not done** and keep
deployment diagnostics disabled until the required physical checks pass.

### Approved interference experiment

The user approved this experiment on 2026-10-02. Run it only on the task-owned
VM `mithril-runtime-qualification-20261002163710`, UUID
`fb6a3ee1-b6b0-4f57-82e6-834bf8629d1c`. The VM has two virtual CPUs and 4 GiB
memory. Use the tested capture source after the shared crate extraction.

Run five trace-off/trace-on pairs. Each run attempts 1,000 policy-denied file
opens. Enforcement stays active in both runs. Stop the experiment after at
most ten minutes. Each pair must have at most 10% p99 latency increase, zero
enforcement-event loss, and unchanged denial decisions. Store the measured
results and the matching Node configuration. Do not substitute synthetic
measurements. A pass on this VM does not enable production diagnostics or
qualify another platform.

The user also approved a corrected workload, provided that the experiment is
not weakened. Use `policy_replace_policy.json` and its explicit `OpenRead`
denial for `/fixtures/policy_replace.py`. Keep the five pairs, 1,000 opens,
cadence, ten-minute bound and 10% limit unchanged. Require exact policy-deny
evidence for the measured actor. Reject new classification errors, unresolved
effects or coverage gaps. Keep production readiness checks unchanged. Run the
fixture consistency check before the physical experiment.

The corrected fixture uses the existing policy and target file. No production
owner or policy rule changes. `Host::qualify_diagnostics` requires a healthy
snapshot before the first attachment. It compares all later snapshots with
that snapshot. For each run, it requires 1,000 fresh, distinct `OpenRead`
events with `EXACT_POLICY_DENY`, `-EACCES` and the measured actor's admitted
identity. It checks these records after the actor publishes latency. It does
not add work inside the actor's timed opens.

`Host::capture_health` rejects changed boot, label or program identity, new
loss/error counters and new coverage gap reasons. It compares the latest
revision for each source and CPU. It does not add repeated cumulative counters
from interval history. A gap that later recovers still fails the experiment.
Node readiness remains required before and after each run.

Both exact component checks passed with the workspace feature set:

```sh
cargo test --workspace --all-targets --all-features \
  observability::tests::observability_target_latency_fixture_needs_no_protected_file_writes \
  -- --exact --nocapture
cargo test --workspace --all-targets --all-features \
  platform::host::capture_rejects_coverage_faults -- --exact --nocapture
```

Use the worktree-local Cargo environment above. Each command ran one selected
test. Receipts are `capture-classified-fixture-focused.log` and
`capture-coverage-guard-final.log` in the evidence directory above. The fixture
check mocks its clock; it is not a performance measurement. A temporary actor
reversion failed the same compiled fixture check. Restoring the corrected
actor passed. Read `capture-classified-fixture-red.log` and
`capture-classified-fixture-green.log`. The actor reversion is not retained.
The corrected physical experiment remains required.

The final workspace procedure passed at source `0a759cf6`, after the last Rust
edit. Formatting, workspace checking, strict Clippy and all selected workspace
tests passed. Main library results were Data 167 passed (5 ignored), shared
observability 22 passed (2 ignored), Interceptor 39 passed (1 ignored), Control
170 passed (2 ignored), e2e 135 passed (412 ignored), and Node 262 passed
(none ignored). Both corrected fixture checks passed in this run. The receipt
is `capture-classified-workspace-final.log`. Use the worktree-local command
above. Ignored physical cases remain unqualified.

The worktree-local `mithril-kube-exec` build also passed. Run the same Cargo
environment with `cargo build --workspace --all-features --bin mithril-kube-exec`.
The receipt is `capture-kube-helper.log`. No production runtime source changed
after the image builds above.

The corrected physical attempt at `0a759cf6` rejected setup before any timed
run. The timed actor started before Node and policy activation. Recovery gave
that actor admission-rule ID zero. The entry-rule check returned
`missing admission rule 0 in generation 1`. The test reports 69.86 seconds;
the launcher returns 101. No measured result or qualified configuration was
written. Read `capture-vm153-pairs-classified-test.log` in the evidence directory.

The subsequent fixture change starts that same actor after policy activation
and initial recovery. It uses the existing declared Python entry. Keep the
entry-rule check and all measurement checks. No actor source, cadence, policy
rule, production owner or experiment limit changes.

The two focused checks passed after that change. Each ran one selected test.
Read `capture-actor-order-focused.log` and `capture-actor-order-guard.log`.

The final workspace procedure passed at source `2da84412`, after the last Rust
edit. Formatting, workspace checking, strict Clippy and all selected workspace
tests passed. Main library results were Data 167 passed (5 ignored), shared
observability 22 passed (2 ignored), Interceptor 39 passed (1 ignored), Control
170 passed (2 ignored), e2e 135 passed (412 ignored), and Node 262 passed
(none ignored). Read `capture-actor-order-workspace-final.log` in the evidence
directory above. Use the worktree-local verification command above. This
workspace result does not change the failed physical latency result below.

### Corrected five-pair result

The owned VM ran all five pairs at source `2da84412`. All ten runs retained
1,000 fresh exact policy-deny records. The admission-rule ID was 1, the role ID
was 3 and the profile generation was 1. Each run had healthy coverage, zero
unresolved effects and zero enforcement-event loss. All five trace terminals
reported `Deadline`, complete output and `Verified` cleanup. Trace kernel-loss
counters remain unknown; this result does not convert them to zero.

| Pair | Trace-off p99, ns | Trace-on p99, ns | Change | 10% gate |
| --- | ---: | ---: | ---: | --- |
| 1 | 96,809 | 304,636 | +214.68% | Fail |
| 2 | 300,123 | 189,412 | -36.89% | Pass |
| 3 | 175,560 | 215,218 | +22.59% | Fail |
| 4 | 218,032 | 305,135 | +39.95% | Fail |
| 5 | 90,385 | 576,320 | +537.63% | Fail |

The test reports 291.05 seconds and returns 101. Configuration validation
rejects the failed pairs. No qualified configuration was written. Run the
same VM command above with output `/tmp/araphor-observability-153-pairs-admitted`
and archive `/var/tmp/araphor-capture-inputs.VMoOpWq2/fixtures-classified.tar.gz`.
Receipts are `capture-vm153-pairs-admitted.json` and
`capture-vm153-pairs-admitted-test.log` in the evidence directory above.

The fixture uses the unoptimized test binary and defaults to DEBUG logging.
Production images use release binaries and default to INFO logging. The
trace-off values also vary. These facts do not establish the cause of latency
changes. Do not report the largest measured change as an intrinsic bpftrace
cost. The approved latency gate failed. Diagnostics stay disabled.

The user approved a direct plain-bpftrace comparison with Araphor capture.
Use the existing VM, script, cgroup, DEBUG logging and protected workload.
Run five trace-off/trace-on pairs for each path. Each run has 1,000 denied
opens at 1 ms intervals. Limit each five-pair experiment to ten minutes.
Keep the 10% p99 limit, zero enforcement-event loss, exact denial evidence,
healthy coverage and cleanup checks. Plain bpftrace does not use the Araphor
diagnostic supervisor, upload or storage path. Its result cannot qualify an
Araphor deployment. An INFO-only experiment is not part of this approval.
Later physical gates still require a real qualified configuration. Do not
create that configuration from failed measurements.

The later Host failure, restart and storage cases now use the same declared
denied file. Start their actors after policy activation. Before each read,
read the current Task and its entry rule. Require a fresh `EXACT_POLICY_DENY`
event with that Task, role, rule, profile generation and `OpenRead` result.
Save the exact witness in the existing JSON receipt. EACCES alone does not
prove the policy decision. Keep `managed_proc_read_is_denied` unchanged; that
case tests `UNRESOLVED_OBJECT`.

Compare enforcement health across each same-lifetime fault window. Before
Node shutdown, save the boundary snapshot. After restart, wait at most 20
seconds for healthy current coverage. Reject new classification, loss, error
and delay gaps, including recovered history. Preserve the expected
`UNCLEAN_RESTART` and `READER_STOPPED` gaps. Do not count them as healthy
coverage. Save both boundary snapshots and verify the program digest.
The restart case checks its first denial after the initial Node-process
handoff, then checks the second denial after the deliberate process kill.
The admission RPC health response does not prove healthy event coverage.
Retirement reads the replacement Task and checks the changed target identity.

The two focused component checks passed. The old proc-file target fails the
explicit-target assertion; the corrected target passes. Read
`capture-lifecycle-fixture-red.log`, `capture-lifecycle-fixture-green.log` and
`capture-lifecycle-guard.log` in the evidence directory above. These checks
do not execute a trace or qualify a physical lifecycle case. All fault holds,
deadlines, quotas, replay checks and cleanup checks stay in place.
No later physical lifecycle gate passed. Status: **Not done**.

The final workspace procedure passed at source `0e81c4c6` after the lifecycle
fixture edit. Formatting, workspace checking, strict Clippy and all selected
workspace tests passed. Data passed 167 tests, shared observability 22,
Interceptor 39, Control 170, e2e 136 and Node 262. Read
`capture-lifecycle-workspace-final.log` in the evidence directory above.
Ignored physical cases remain unqualified. This result covers the lifecycle
fixture correction, not the subsequent plain-bpftrace comparison change.

### Plain and owned capture result

The user specifies plain bpftrace as the baseline for Araphor-added cost.
Both paths must use the same backend, script, probes, target filter and
collection settings. Do not attribute the native probe cost to Araphor.
The trace-off comparisons below measure total capture interference. They
do not measure Araphor-added cost against plain bpftrace.

Source `58a9a171` ran both approved experiments on the same owned VM. Both
used the same unoptimized test binary, DEBUG logging, fixture archive and
bpftrace executable. Each path ran five trace-off/trace-on pairs. Each run
attempted 1,000 denied opens at 1 ms intervals. Each capture used the reviewed
`FailedOpens` source, its resolved cgroup filter and a five-second collection
window after the actual attachment notification. Each experiment created
its own admitted actor and cgroup. The native command uses inline source;
the Araphor backend reads source from standard input. The source bytes and
backend environment match. Compiled BPF byte equality was not measured.

Run the existing owned harness with these inputs:

```sh
sudo -n env RUST_LOG=debug MITHRIL_TRACE_MODE=plain \
  timeout --signal=TERM --kill-after=10s 590s bash \
  /mnt/mithril-source/worktrees/mithril-ui/crates/mithril-e2e/harness/observability/owned.sh \
  /mnt/mithril-source/worktrees/mithril-ui/target/debug/deps/mithril_e2e-69abcc1defdc24e3 \
  /var/tmp/araphor-capture-inputs.VMoOpWq2/fixtures-classified.tar.gz \
  /tmp/araphor-observability-153-plain-20261003 1000
```

The second command changes `MITHRIL_TRACE_MODE` to `araphor` and uses the
fresh output path `/tmp/araphor-observability-153-araphor-20261003`. All other
inputs stay unchanged. The experiments ran in sequence, without a concurrent
Cargo build or workspace test run.

Each table row is a trace-off/trace-on pair inside its experiment. The two
experiments are not direct interleaved plain/Araphor pairs.

| Pair | Plain off p99, ns | Plain on p99, ns | Change | Araphor off p99, ns | Araphor on p99, ns | Change |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 200,637 | 200,832 | +0.10% | 181,217 | 255,642 | +41.07% |
| 2 | 203,656 | 176,584 | -13.29% | 382,265 | 313,917 | -17.88% |
| 3 | 180,821 | 207,631 | +14.83% | 111,090 | 142,793 | +28.54% |
| 4 | 245,231 | 173,544 | -29.23% | 213,667 | 117,336 | -45.08% |
| 5 | 194,396 | 191,167 | -1.66% | 143,171 | 127,466 | -10.97% |

With plain trace-on as the baseline, the median of five p99 values is
191,167 ns. The Araphor median is 142,793 ns. Native trace-on values range
from 173,544 to 207,631 ns. Araphor values range from 117,336 to 313,917 ns.
These separate samples do not prove equal performance or a stable
Araphor-added cost. Do not report the lower Araphor median as a proven speed
improvement. A direct paired comparison remains unmeasured.

All twenty runs retained 1,000 fresh exact policy-deny witnesses per run.
Each run reports healthy coverage, zero unresolved effects and zero
enforcement-event loss. All five native captures measured 1,000 EACCES opens,
exited with code zero, removed their observed diagnostic resources and kept
the enforcement resources. Native collection times were 5,003, 5,006, 5,003,
5,005 and 5,002 ms. All five Araphor terminals report `Deadline`, complete
output, exit code zero, no forced kill and `Verified` cleanup. Araphor output
also measures at least 1,000 EACCES opens. Trace kernel-loss counters remain
unknown; zero enforcement-event loss does not establish zero trace loss.

The native test reports 255.16 seconds. The Araphor test reports 293.65
seconds. Both launchers return 101 at final configuration validation. Native
pair 3 and Araphor pairs 1 and 3 exceed the existing 10% trace-off limit.
Neither run writes a qualified configuration. Read
`capture-vm153-plain-20261003.json`,
`capture-vm153-plain-20261003-test.log`,
`capture-vm153-araphor-20261003.json` and
`capture-vm153-araphor-20261003-test.log` in the evidence directory above.
Diagnostics stay disabled. Status: **Not done**.

The direct-command and attachment-marker component checks each passed one
test at this source. Read `capture-plain-component.log`. These checks do not
replace the physical results above. The final workspace procedure passed at
source `58a9a171`. Formatting, workspace checking, strict Clippy and the full
selected workspace suite passed. Data passed 167 tests, shared observability
22, Interceptor 39, Control 170, e2e 138 and Node 262. Read
`capture-plain-workspace-final.log`. This pass covers the comparison helper,
not the subsequent capture optimization.

The user approved a direct baseline experiment after optimization. Run five
alternating plain-bpftrace/Araphor pairs on the same VM and admitted cgroup.
Keep the binary, script, filters, backend environment, DEBUG logging and
five-second collection window identical. Each run attempts 1,000 denied
opens at 1 ms intervals. Limit the complete experiment to ten minutes.
Use plain capture as each pair's baseline. Araphor p99 must not exceed that
baseline. Keep the same capture behavior. The user did not approve a 5%
allowance. Every run must retain all exact denial witnesses,
healthy coverage, zero enforcement-event loss and verified cleanup.
Record each pair and each failure. This added-cost comparison does not
replace the deployment interference gate or create a qualified configuration.
For every comparison, report both measured values and their signed difference
in the measured units and as a percentage of the plain-bpftrace value.
Calculate the difference as Araphor minus plain bpftrace. A positive difference
is an increase; a negative difference means Araphor is faster. Report every
pair, including increases. No increase is allowed. Do not replace pair results
with an aggregate that hides an increase.

### Capture optimization and direct baseline result

Source `b4890649` implements both Node spool changes.
`recovery_pending` starts true and is set before intent creation and worker
joins. Recovery syncs each execution directory and the diagnostics parent
before it clears the flag. A failure leaves recovery pending. An unchanged
poll skips recovery work; retained dispatch and upload validation still run.
An active spool with no newer committed frames returns no frames without
reading its output file. Other reads keep the existing parser. No bpftrace
source, probe, target check, timer, quota, storage format or ACK rule changes.

The focused recovery selection passed 13 tests. The direct routing check
and lightweight owned-upload case each passed one test. Read
`capture-spool-recovery-focused.log`, `capture-compare-route-focused.log` and
`capture-spool-owned-focused.log` in the evidence directory above. Tests
cover actual temporary terminal-write failures, retry, retained prefixes,
duplicate admission and corrupt uncommitted output. Parent-sync and thread-
spawn failures were source-reviewed; these tests do not inject those faults.

The approved direct experiment used `MITHRIL_TRACE_MODE=compare`. It ran
the same owned harness command above with output
`/tmp/araphor-observability-153-compare-20261003` and limit argument `500`.
All other inputs stay unchanged. The 590-second timeout stays in place.
The experiment ran without a concurrent Cargo build or workspace test run.
The agent selected `500` basis points, or 5%, as a test setting. The user
approved the experiment, not that allowance. Keep this setting in the
execution record. Do not use it as the acceptance requirement. Plain
bpftrace is the baseline; Araphor must have the same behavior without an
added performance cost.

Every run has capture enabled. Each pair runs plain bpftrace first and
Araphor second. All ten runs use cgroup 38,231, Task cookie 14, role 3,
admission rule 1 and profile generation 1. The source and backend settings
stay unchanged. Compare mode cannot write a qualified configuration.

| Pair | Plain p99, ns | Araphor p99, ns | Difference, ns | Difference, % |
| --- | ---: | ---: | ---: | ---: |
| 1 | 139,006 | 291,406 | +152,400 | +109.64% |
| 2 | 298,993 | 253,795 | -45,198 | -15.12% |
| 3 | 246,367 | 105,536 | -140,831 | -57.16% |
| 4 | 127,748 | 272,899 | +145,151 | +113.62% |
| 5 | 101,912 | 306,880 | +204,968 | +201.12% |

Every run retains 1,000 fresh exact policy-deny witnesses. The complete
receipt has 10,000 distinct witness coordinates, healthy coverage, zero
unresolved effects and zero enforcement-event loss. Every capture measures
1,000 EACCES opens and passes cleanup. Native collection times are 5,006,
5,001, 5,006, 5,000 and 5,009 ms. All children exit with code zero without
a forced kill. Araphor terminals report `Deadline`, complete output and
`Verified` cleanup. Trace kernel-loss counters remain unknown.

The test reports 283.51 seconds and the launcher returns 101 at final
configuration validation against the agent-selected 5% setting. Araphor
is slower in pairs 1, 4 and 5. Read
`capture-vm153-compare-20261003.json` and
`capture-vm153-compare-20261003-test.log` in the evidence directory above.
Both paths have substantial run-to-run variation. These results do not
identify its cause, prove equal performance or prove an improvement from
the two code changes. The changes remove known repeated work. They do not
establish performance parity. Do not add an allowance or change
logging, source, safety checks or workload to report a pass.

The final workspace procedure passed on the code committed as `b4890649`.
Formatting, workspace checking, strict Clippy and all selected workspace
tests passed. Data passed 167 tests, shared observability 23, Interceptor
39, Control 170, e2e 139 and Node 262. Read
`capture-spool-workspace-final.log`. The e2e suite kept 412 physical and
environment-dependent tests ignored. This pass proves correctness for the
executed cases. It does not prove performance parity or physical lifecycle
qualification.
Diagnostics stay disabled. Physical lifecycle gates remain **Not done**.

### Direct comparison and spool checks

Source `1e1e3de7` separates direct comparison from deployment
validation. `Host::capture_parity` compares plain bpftrace with Araphor; both
paths have tracing enabled. It requires five pairs, positive p99 values, no
increase over plain bpftrace, zero enforcement-event loss and equal physical
decisions. The integer comparison decides acceptance. A rounded percentage
does not decide acceptance. Each completed pair prints both p99 values and
the signed difference in nanoseconds and percent, before the next pair runs.
No configured percentage allowance applies to direct comparison.
Deployment validation and its configuration publication stay unchanged.
Compare mode cannot publish a qualified deployment configuration.

`Host::capture_frames` reuses the existing storage-case reader for the
partition case. It reads at most 5 MiB and parses complete JSONL frames before
the unused NUL-filled tail. Terminal sequence and exact replay checks stay
unchanged. The new `observability_spool_tail` regression uses two valid frames
and real 68-MiB file allocation. It checks exact frame readback and unchanged
file length. This is a storage correctness test, not a performance test.

The final focused selection passed three tests and kept five physical or
subprocess entry points ignored. Run the worktree-local Cargo environment
above with `cargo test --workspace --all-features --lib
platform::host::observability_ -- --nocapture`. Read
`capture-parity-focused-final.log`. The parity test uses fixed values. No new
performance comparison or physical lifecycle run occurred.

The current lifecycle input archive is
`/tmp/araphor-lifecycle-inputs.T6sGiUzw/fixtures-current.tar.gz`, SHA-256
`e45a80566a94034b43e44f23272e59a93cc5c60d9d0c0886a5cf4331da733929`.
It contains the seven original member paths from the current worktree plus
`policy_replace_policy.json` and `policy_replace.py`. Its `proc_read.py` reads
the supplied target. `tar -dzf` against the worktree passed. The old archive
is unchanged. Archive preparation does not qualify a physical case.

The final workspace procedure passed on source `1e1e3de7`. Formatting,
workspace checking, strict Clippy and all selected workspace tests passed.
Data passed 167 tests, shared observability 23, Interceptor 39, Control 170,
e2e 141 and Node 262. Read `capture-parity-workspace-final.log`. The e2e suite
kept 412 physical and environment-dependent tests ignored.
Physical fault cases still require a matching qualified configuration.
The inspected receipts contain no such configuration. Do not fabricate one
from the failed measurements. Status: **Not done**.

### Approved test-only physical admission

The user approved an explicit test-only admission input for the remaining
physical fault cases. Use the comparison's existing test setup with the real
backend hash, kernel, architecture and CPU facts. Keep production validation
unchanged. Do not treat the setup's fixed pairs as measurements. A missing or
invalid qualified configuration must not select this input automatically.

Run the lightweight owner case before each paired physical case. Require the
same target, authorization, storage, expiry, enforcement and cleanup checks.
Mark each test-only result with `diagnostic_admission: synthetic-test-only`,
`performance_qualified: false` and `performance_claim: false`. Do not publish
the setup as a qualification receipt or a qualified configuration. Internal
task-owned Node configuration is input to the real restarted Node process.
Keep deployment diagnostics disabled and performance qualification **Not done**.
Source `4273cda8` implements this path in the existing
Host, Shared and Kubernetes test owners. Each fault harness accepts
`--test-admission` in its qualified-configuration argument position. The
selector is `MITHRIL_TRACE_TEST_ADMISSION=1`. Missing, invalid and conflicting
inputs fail. Shared builds the existing fixture configuration with the actual
backend hash and platform facts. The positive limit field is `1`, as required
by the unchanged validator. This field is test input, not a performance
allowance. Plain-bpftrace comparison still requires no Araphor p99 increase.

Use these existing entry points:

```text
owned.sh BIN ARCHIVE OUTPUT LIMIT --test-admission [restart-before|restart-after]
disk-full.sh BIN ARCHIVE OUTPUT --test-admission
pods.sh BIN --test-admission BUNDLE OUTPUT
```

The lightweight `observability_owned_upload` case passed one test.
`capture_admission_selection` passed one test. The Host regression selection
passed three tests and kept five physical cases ignored. All three shell
syntax checks passed. All three scripts reject missing arguments with exit
code 2. Read `owned-upload.log`, `admission-selection.log` and
`host-regressions.log` in `/tmp/araphor-fault-admission.rz3Qj3lL`.
The final workspace procedure passed on source `4273cda8`. Formatting,
workspace checking and strict Clippy passed. Data passed 167 tests, shared
observability 23, Interceptor 39, Control 170, e2e 142 and Node 262. The e2e
suite kept 412 physical and environment-dependent tests ignored. Read
`workspace-final.log` in that directory. This result is not physical fault
or performance qualification.

The user approved the nine-file test archive transfer, including the tracked
test signing key. The archive copy succeeded from
`/tmp/araphor-lifecycle-inputs.T6sGiUzw/fixtures-current.tar.gz` to
`192.168.122.153:/var/tmp/araphor-owned-fault-inputs.qiLXnxP9/fixtures-current.tar.gz`.
The guest hash is
`e45a80566a94034b43e44f23272e59a93cc5c60d9d0c0886a5cf4331da733929`.
No physical fault pass or qualification receipt is claimed. Status: **Not done**.

The user also approved repeated plain-bpftrace versus Araphor comparisons,
with optimization between runs. Reuse the approved workload, platform and
five alternating capture-enabled pairs. Use the time bound approved for each
workload. Report each pair's p99 values and signed nanosecond and
percentage differences. Require no Araphor increase. Keep capture, isolation,
loss, target, enforcement and cleanup checks unchanged. Do not run a comparison
while Cargo or workspace CI runs. A failed comparison is not qualification.

The physical harnesses require these checks. Their compiled source is not a
physical pass:

- `pods.sh` runs the lightweight owner chain before the ignored Kubernetes
  case. A finite Control child uses the existing Deployment, configuration,
  inventory, authorization and controllers. Pod deletion uses the exact UID.
  The replacement has the same name and new UID, CRI ID and cgroup lifetime.
  The case checks `TargetChanged`, physical denials, unchanged original output,
  and diagnostic resource cleanup. Task-owned read-only backend mounts use
  exact runtime recovery entries. Native `ldd` checks reject incompatible
  libraries. Mount and argument limits stay unchanged.
- `disk-full.sh` runs the same lightweight case, then puts AnalysisStore on a
  task-owned 1 GiB tmpfs. Node state and Control authority stay outside that
  filesystem. The case delays real dispatch, attaches the reviewed backend,
  and fills the filesystem immediately before the first diagnostic append.
  The hook returns success. The native segment write must fail with ENOSPC
  (no space left on device).
  Require no ACK or committed progress, local lease expiry, bounded output,
  physical denials, full owner reopen, and exact replay through current mTLS.
- `owned.sh` uses a real 25-second dispatch hold and a 30-second backend limit
  for partition. The case requires Node lease expiry before backend timeout,
  no terminal ACK before repair, and exact local-output replay after repair.
  Each induced failure has a physical denial check. Retirement checks a new
  admitted lifetime; it does not wait for recovery state.
- The Node-process restart harness requires a matching qualified configuration
  or the explicitly selected test-only input.
  Its before-attachment and after-attachment cases have not run on the current
  capture source. A prior backend result is not an owned-capture result.

## Acceptance and verification

### Repeated plain-bpftrace comparison

The first approved repeat covers source `4273cda8`. It uses the same owned
VM, backend, eight-file classified archive, debug logging and workload as the
direct comparison above. The owned harness has four arguments, output
`/tmp/araphor-observability-153-compare-20261003-current` and limit input `1`.
`MITHRIL_TRACE_MODE=compare` selects plain bpftrace and Araphor in alternating
capture-enabled runs. The positive fixture input is not an overhead allowance.
The integer gate requires no Araphor p99 increase. No Cargo or CI runs at
the same time. The 590-second timeout stays unchanged.

| Pair | Plain p99, ns | Araphor p99, ns | Difference, ns | Difference, % |
| --- | ---: | ---: | ---: | ---: |
| 1 | 200,863 | 371,215 | +170,352 | +84.810045% |
| 2 | 181,771 | 315,194 | +133,423 | +73.401698% |
| 3 | 281,799 | 288,571 | +6,772 | +2.403131% |
| 4 | 225,278 | 169,199 | -56,079 | -24.893243% |
| 5 | 191,161 | 278,525 | +87,364 | +45.701791% |

The test takes 287.52 seconds and returns 101. All ten runs retain 1,000
exact denial witnesses, with zero enforcement-event loss and unresolved
effects. Coverage permits negative claims in all ten runs. All five Araphor
terminals have `Deadline` and `Verified` cleanup. Trace kernel loss stays
unknown. Read `compare-current.json` and `compare-current-test.log` in
`/tmp/araphor-fault-admission.rz3Qj3lL`. Four pairs fail the no-increase gate.
No qualified configuration is published. Performance parity is **Not done**.

### Resource scan buffer

Source `3da357fa` gives each diagnostic supervisor one reusable read buffer.
The supervisor clears the buffer before each status or descriptor read.
Every read still opens the current file. The 10-ms scan cadence, 256-entry
limit, 16-KiB descriptor bound, peak memory observation, program/map ID collection
and cleanup checks stay unchanged. No descriptor cache or new owner is added.

The focused backend selection passed 29 tests: Data 2, Interceptor 17 and
e2e 10. Two subprocess helpers stayed ignored. The new
`observability_backend_resource_buffer` test uses real `/proc` descriptor
data and temporary filesystem inputs. It checks fresh reads, allocation
reuse, stale text removal, read-error recovery, invalid UTF-8 recovery and
the descriptor input bound. Read `resource-buffer-focused.log` in
`/tmp/araphor-fault-admission.rz3Qj3lL`. The final workspace procedure has not
run on this source. The next comparison uses output
`/tmp/araphor-observability-153-compare-20261003-buffer` with the unchanged
workload and strict no-increase gate. No latency improvement is claimed.

The buffer comparison takes 282.24 seconds and returns 101. All ten runs
retain 1,000 exact denial witnesses with zero enforcement-event loss and
unresolved effects. Native cleanup and unchanged enforcement resources pass
in all five runs. Araphor has `Deadline` and `Verified` cleanup in all five
runs. Trace kernel loss stays unknown.

| Pair | Plain p99, ns | Araphor p99, ns | Difference, ns | Difference, % |
| --- | ---: | ---: | ---: | ---: |
| 1 | 249,340 | 272,362 | +23,022 | +9.233176% |
| 2 | 243,434 | 92,794 | -150,640 | -61.881249% |
| 3 | 213,660 | 299,159 | +85,499 | +40.016381% |
| 4 | 248,106 | 208,108 | -39,998 | -16.121335% |
| 5 | 210,080 | 176,239 | -33,841 | -16.108625% |

Read `compare-buffer.json` and `compare-buffer-test.log` in the evidence
directory above. Two pairs fail. Do not infer a causal speedup from the
changed pair count. No qualified configuration is published. Performance
parity remains **Not done**.

### Approved larger-sample comparison

The user approved 10,000 denied opens in each run. Use five plain-bpftrace
and Araphor pairs, for 100,000 total operations. Keep the 1-ms delay between
operations. Both paths use 30-second collection limits. The outer timeout
is 20 minutes.
Pause further production optimization until this comparison completes.

Calculate p99 by nearest rank: sort 10,000 measured durations and select
rank 9,900, at zero-based index 9,899. There are 100 observations above this
rank. The previous 1,000-operation runs select rank 990, with about ten
observations above it. More samples reduce the effect of individual tail
observations. They do not prove equal scheduling conditions or confidence
in the difference between two runs.

Read retained evidence after each measured workload through the existing
bounded AnalysisStore pages. Require all 10,000 fresh exact denial witnesses,
unchanged coverage health and cleanup checks. Do not increase the recent-event
snapshot limit. Do not poll retained evidence during the timed workload.
Keep the same backend, source, target, environment and tracing configuration.
Report every pair's two p99 values and signed differences. The gate still
requires no Araphor p99 increase in every pair. No percentage allowance applies.
This approval is not a performance pass. Result: **Not done**.

The eight-file archive is
`/tmp/araphor-capture-10k.CTkeIuTc/fixtures-10k.tar.gz`. Its copy at
`192.168.122.153:/var/tmp/araphor-capture-inputs.VMoOpWq2/fixtures-10k-20261003.tar.gz`
has the same SHA-256:
`cc79eda7def7b90bd72d97d40e9a0ef52427c23a36b86998e0a29e63b9aaac6c`.
The archive matches the files at source `c32fa9a9`. The stock backend hash stays
`d2846f3400bb129b1a569aae64adf548de99ff41f247823ff8caf1fbde40ff1e`.

The harness changes are test-only. Host requires sample completion before a
30-second cutoff set before capture preparation. Native collection and Araphor
collection still start at their attachment markers. The accepted Araphor lease
stays collection plus 15 seconds. Do not claim identical observed attachment
windows. Both captures finish before retained-evidence extraction.
`Host::capture_denials` reads bounded source and record pages. It checks tenant,
node, boot, label, source and epoch identities. It checks task, profile, role,
entry rule, reason, operation and EACCES. It uses the original kernel sequence
for freshness and exact witness identity. The storage cursor only advances
page reads. Reused cursors prevent repeated historical reads between runs.

Eight focused tests passed: four Host tests, the fixture contract test and
three native-capture tests. Five physical Host cases stayed ignored.
The real-store regression checks 10,000 fresh witnesses across page boundaries,
foreign-source exclusion, changed task context, stale sequences, CRC failure,
cursor reuse and extra-denial rejection. The first run rejected invalid
foreign test identities that reused a source epoch with a different boot or
label. The corrected fixture uses independent source identities. No production
change was required. Read `host-focused-final.log`, `fixture-focused.log` and
`plain-focused.log` in `/tmp/araphor-capture-10k.CTkeIuTc`.
Formatting passes. Final workspace verification has not run on this source.

The approved comparison covers harness source `c32fa9a9`, with production
capture unchanged from `3da357fa`. It uses the worktree libtest binary
`mithril_e2e-1adb172a9b31c9af`, debug logging, compare mode, the archive above,
output `/tmp/araphor-observability-153-compare-20261003-10000`, and the approved
1,200-second timeout. The positive fixture limit is `1`, not an allowance.
No Cargo, CI or guest polling runs during measurement.

| Pair | Plain p99, ns | Araphor p99, ns | Difference, ns | Difference, % |
| --- | ---: | ---: | ---: | ---: |
| 1 | 129,404 | 265,619 | +136,215 | +105.263361% |
| 2 | 160,074 | 267,051 | +106,977 | +66.829716% |
| 3 | 211,620 | 239,574 | +27,954 | +13.209527% |
| 4 | 190,280 | 233,557 | +43,277 | +22.743851% |
| 5 | 191,761 | 241,125 | +49,364 | +25.742461% |

The test takes 583.72 seconds and returns 101. All ten runs retain exactly
10,000 denial witnesses, with zero enforcement-event loss and unresolved
effects. All ten permit negative claims. Native collection takes 30,000 to
30,009 ms; cleanup and unchanged enforcement resources pass. All five Araphor
terminals have `Deadline`, complete output and `Verified` cleanup. Trace kernel
loss remains unknown. Read `compare-10000.json` and `compare-10000-test.log`
in `/tmp/araphor-capture-10k.CTkeIuTc`. All five pairs fail. The previous apparent
speedups do not repeat. This result does not isolate a latency cause or prove
statistical confidence. No qualified configuration is published.

### Approved difference investigation

The user requests 5,000 operations per run and investigation of the difference.
Keep the five pairs, 1-ms pacing, 30-second collection limits, 20-minute outer
limit and no-increase gate. Calculate nearest-rank p99 at zero-based index
4,949. Keep exact witness, coverage, loss, output and cleanup checks. Report
all pair measurements in the user thread. Analyze the existing source and
receipts before a production change. Profiling must be separate from the
unprofiled comparison. Obtain approval for any additional performance workload.
The cause is not proven. Performance parity remains **Not done**.

The 5,000-operation harness passes eight focused tests and formatting. Read
`host-5000-focused.log`, `fixture-5000-focused.log` and `plain-5000-focused.log`
in the same evidence directory. The archive is `fixtures-5000.tar.gz`.
Its guest copy at
`/var/tmp/araphor-capture-inputs.VMoOpWq2/fixtures-5000-20261003.tar.gz` has SHA-256
`e03a6bd8b320a4ce4655b7dedba001f94e6050263d87997e358ad106941d05ba`.
Harness source `444283cc` completes the 5,000-operation comparison in 580.81
seconds and returns 101. It uses the same debug libtest binary, backend,
DEBUG logging and compare route as the 10,000-operation run. The output is
`/tmp/araphor-observability-153-compare-20261003-5000`. No Cargo, CI, profiling
or guest polling runs during measurement.

| Pair | Plain p99, ns | Araphor p99, ns | Difference, ns | Difference, % |
| --- | ---: | ---: | ---: | ---: |
| 1 | 162,497 | 248,633 | +86,136 | +53.007748% |
| 2 | 122,616 | 234,571 | +111,955 | +91.305376% |
| 3 | 216,900 | 220,529 | +3,629 | +1.673121% |
| 4 | 144,037 | 258,159 | +114,122 | +79.231031% |
| 5 | 215,677 | 290,707 | +75,030 | +34.788132% |

All ten runs retain exactly 5,000 denial witnesses. Enforcement-event loss
and unresolved effects are zero. All ten permit negative claims. Native
collection takes 30,001 to 30,008 ms; cleanup and unchanged enforcement
resources pass. All Araphor terminals have `Deadline`, complete output and
`Verified` cleanup. Trace kernel loss remains unknown. All five pairs fail.
Read `compare-5000.json` and `compare-5000-test.log` in
`/tmp/araphor-capture-10k.CTkeIuTc`. The results were also reported in the user
thread. The lower count does not remove the latency difference. No qualified
configuration is published.

The existing comparisons use unoptimized Rust libtest code and stock packaged
bpftrace. Both paths use that bpftrace binary, but only Araphor adds the Rust
supervision and capture loops. Build mode is a possible cause of excessive
wrapper cost. It is not isolated by these results. Release performance remains
unqualified. The user has been asked to select release comparison or debug
diagnosis, and to approve two process-usage snapshots outside timed operations.

Source review finds two 10-ms Araphor loops: backend resource inspection and
held target/map checks. Plain polling checks output sizes and child exit.
Araphor also syncs local frames and commits uploaded output through Data's
shared writer/raw locks. That raw path calls `syncfs` on its filesystem.
[Linux documents the filesystem-wide scope](https://man7.org/linux/man-pages/man2/sync.2.html).
Do not remove required checks or durable commit to make a measurement pass.
The earlier 10,000-operation log has ten evidence-production intervals.
Each interval has 10,000 records.
Health-sampling deferrals total 377 plain and 460 Araphor. Reader pending peaks
are 9 and 8. These counts show no queue exhaustion and do not isolate a cause.
Do not blame post-capture retained reads or full catalogue projection for
the measured difference. Those reads occur outside measurement; trace intent
reads use the existing raw coordinator.

Target validation opens the pinned binding map on each 10-ms turn. Backend
inspection opens current process status and file-descriptor records on its
own 10-ms turn. Diagnostic commits share the raw-store locks with enforcement
uploads. These facts identify possible extra work, not a measured cause.

The fixture measures each Python `os.open` call and its error handling. The
1-ms sleep follows the timed operation. The fixture sorts 5,000 durations
and publishes only p99 through the task name. It does not retain individual
durations or operation timestamps. Host does not record trigger or result
publication times. Native collection times do not measure the actor loop.
The current receipts cannot correlate a slow operation with a map read,
disk sync, lock wait or scheduling delay. Backend compilation and final
retained-data extraction occur outside the timed operations. A release
comparison with the same logging and safety checks would isolate build mode.
This comparison requires approval. No measured cause or fix is claimed.
The Node RPC wait continues runtime admission; do not claim admission stops
for the full diagnostic RPC. Plain always precedes Araphor within a pair.
Sampling starts after each path observes attachment; Araphor also waits for
durable output visibility. The experiment does not equalize scheduler phase.
Control scans retained intents every 500 ms. Later plain runs also have those
intents. Acknowledged Node output is truncated, and recovery is guarded;
do not claim continuous full-spool recovery. No production change follows
from these hypotheses alone.

The archived 5,000-operation actor matches the checked source. Native output
receipts repeat the same backend and script digests. Both code paths select
that executable and recipe; Araphor receipts do not repeat those digests.
Native uses `-e` and output files. Araphor uses the checked executable through
its held descriptor, stdin source and supervised pipes. These differences
do not change the approved script, but their costs are not isolated.

### Approved attribution profile

The user approves a separate profile with five plain/Araphor pairs, 5,000
denied opens per run, 1-ms pacing and 30-second captures. Expected run time
is approximately ten minutes. Keep the backend, source, target checks,
debug build and logging unchanged. The outer limit is twenty minutes.
Use a temporary fixture, not a production code change.

Record each operation's monotonic start, end and thread CPU time. The wall
interval includes two CPU-clock reads. Preserve ordered samples and record
that added cost. Retain each run before the fixture removes its work directory.
Sample CPU stacks at 49 Hz for the harness and its descendants. Record
scheduler transitions and sync/futex entry and exit separately, without
stack capture for unrelated processes. Use the monotonic clock in both files.
Each profile file has a 2-GiB limit and private file permissions.

Correlate slow operations with scheduler transitions. Treat runnable
preemption separately from blocked time. A syscall's elapsed time alone
does not prove storage or lock waiting. Report every pair and missing records.
Profiled results cannot qualify performance or change the no-increase gate.
Release performance remains unqualified. The CPU recorder's file-size limit
also applies to its workload children.

### Attribution profile result

The approved run completes in 582.09 seconds on source `d486e637`, VM
`192.168.122.153`, with `mithril_e2e-1adb172a9b31c9af`. The comparison returns
101 because each pair exceeds the unchanged no-increase gate. The collector
returns zero and saves all ten timing files. The scheduler recorder returns
130 after the runner sends its planned interrupt. No production code changes.

| Pair | Plain p99, ns | Araphor p99, ns | Difference, ns | Difference, % |
| --- | ---: | ---: | ---: | ---: |
| 1 | 284,129 | 341,250 | +57,121 | +20.103896% |
| 2 | 248,212 | 289,093 | +40,881 | +16.470195% |
| 3 | 245,616 | 251,616 | +6,000 | +2.442838% |
| 4 | 261,856 | 310,475 | +48,619 | +18.567075% |
| 5 | 247,894 | 280,155 | +32,261 | +13.014030% |

All ten runs retain exactly 5,000 denials, zero enforcement-event loss and
zero unresolved effects. Native cleanup and unchanged enforcement resources
pass. All Araphor terminals have complete output, `Deadline`, `Verified`
cleanup, exit code zero and no forced kill. Trace kernel loss stays unknown.
The native receipts repeat the same executable and source digests as the
unprofiled run. No qualified configuration is published.

For each run, join scheduler intervals to each operation's monotonic start
and end. Exclude the 1-ms sleeps. Of each run's slowest 50 operations, 49 or
50 have a scheduler switch. Runnable waiting accounts for 86.06 to 91.06%
of their summed wall time. These intervals have no observed blocked wait.
This percentage describes the measured tail, not the difference between
the two p99 values. Thread CPU p99 is 61,321 to 66,259 ns across all ten runs,
using the same nearest-rank rule as wall p99. The CPU p99 difference ranges
from -2.38 to +4.03% across pairs. Runnable waiting dominates the measured
tail wall time, not execution in the actor thread.

The Araphor supervisor occupies the CPU during some actor runnable waits.
For example, run 1 operation 4,251 takes 540,568 ns of wall time and 35,630 ns
of thread CPU time. It has 500,293 ns of runnable waiting. The supervisor
occupies that CPU throughout this interval. This is a scheduler observation,
not a measurement of task-exclusive CPU time. Interrupts and guest scheduling
can occur within a task's interval. Matching switch-out and switch-in CPUs
does not exclude an intermediate migration.

CPU reports select ten run windows, from the first operation's start to the
last operation's end. They include the intervals between operations. The
reports contain 680 plain samples and 748 Araphor samples. The supervisor has 48
samples; 39 include `SupervisedChild::record_resources` or `read_resource`.
Some stacks include enforcement BPF hooks during those file reads. The source
opens `/proc/<child>/status`, scans `/proc/<child>/fdinfo`, and reads up to
256 entries on every pipe-poll turn. The loop sleeps 10 ms after that work.
This is a concrete optimization target. It is not proof that this scan causes
the complete p99 difference. Common Node evidence, coverage and live-manifest
work also appears in both paths.

The corrected scheduler parser accepts signed PID and TID fields. It parses
all 4,986,744 records with no lost-record message or timestamp-order error.
An independent interval join confirms all ten tail totals. The CPU recording
reports 2,325 out-of-order events and zero lost samples. Initial stack decoding
stops at a symbol-resolution error. Decoding the measured windows with
`--no-inline` succeeds. Preserve that limit; do not claim complete symbol
resolution. Aggregate complete per-operation task counters before selecting
the leading tasks. Do not attribute migrated waits to one CPU's task list.

The profiles add clock reads, scheduler tracepoints, CPU samples and collector
work. They also write on the same filesystem used by raw-store `syncfs`.
These settings can change scheduling and sync cost. Sync/futex elapsed time
alone does not prove I/O or lock contention. The original unprofiled receipts
have no operation timestamps, so this profile cannot explain each earlier
percentage. Both paths have variable scheduler waits. A small paired p99
difference does not show that wrapper work disappeared.

The source review of [bpftrace v0.20.2](https://github.com/bpftrace/bpftrace/blob/v0.20.2/src/main.cpp#L836-L911)
finds one parser and compiler path after `-e` or stdin supplies the source.
Compilation occurs before the measured operations. No separate faster kernel
path is established for `-e`. The packaged binary's patches and generated
instruction equality are not checked by this profile.

Read `capture-pairs.json`, `test.log`, `analysis.json`, `analysis-detail.json`,
`cpu-analysis.json`, `diagnostic-stacks.json`, the actor timing files and
recorder logs in `/tmp/araphor-capture-profile.GplRU8Gs`. The guest profiles
are `cpu.data` and `scheduling.data` in
`/var/tmp/araphor-attribution.xFUECZc1`. The launch is:

```sh
sudo timeout 1200 bash /var/tmp/araphor-attribution.xFUECZc1/profile.sh \
  /var/tmp/araphor-attribution.xFUECZc1 \
  /tmp/araphor-attribution-20261003-5000 \
  /mnt/mithril-source/worktrees/mithril-ui/target/debug/deps/mithril_e2e-1adb172a9b31c9af \
  /var/tmp/araphor-attribution.xFUECZc1/fixtures-profile.tar.gz
```

The diagnostic experiment is **Done**. Performance parity remains **Not done**.
Optimize measured repeated work without removing target, resource-ownership,
durability, deadline or cleanup checks. A later unprofiled comparison must
still pass the unchanged no-increase gate. Diagnostics stay disabled.

### Approved handle reuse and comparison

The user approves a bounded resource-scan change and an unprofiled comparison.
Keep a fresh fdinfo directory open and resource inspection on each 10-ms
supervision turn. Record conservative peak memory when the child is reaped.
Retain at most 256 fdinfo file handles for the
current selected entries. Remove handles for absent entries before opening
new ones. Read current contents from offset zero, with the same 16-KiB
limit. Continue positive short reads at the next offset until EOF or the limit.
Do not reuse parsed text or resource IDs as current evidence.
Discard handles on directory or read failure, and on a limit-sized read.
Close all handles before child reap and on owner drop. Keep the recorded ID
unions and cleanup verification.

Linux 6.8 [fdinfo reads](https://github.com/torvalds/linux/blob/v6.8/fs/proc/fd.c)
look up the current child FD when the sequence is regenerated. The proc handle
does not retain that child FD. [Sequence reset](https://github.com/torvalds/linux/blob/v6.8/fs/seq_file.c)
permits a fresh read from offset zero. Require tests for current contents,
closed or reused FDs and bounded handle ownership before measurement.
Keep fresh directory authorization and read authorization. Reuse removes
repeated per-file open checks and open-time evidence; it does not execute
the same authorization hooks as reopening every file. Do not claim equivalence
for arbitrary policies that authorize only file opens. Target, grant, local
deadline, cancellation, output and independent BPF cleanup checks do not change.

Run five plain-bpftrace and Araphor pairs. Use 5,000 denied opens per run,
1-ms spacing and the existing 30-second collection limits. Use the unchanged
actor, stock backend, source, target and environment. Do not run a profiler,
Cargo, workspace CI or guest polling during measurement. The outer timeout
is 20 minutes. Calculate nearest-rank p99 at zero-based index 4,949. Report
both p99 values and the signed difference for every pair. Keep the requirement
for no Araphor p99 increase in every pair. Do not add a percentage allowance.
This approval is not a performance result or deployment qualification.

### Resource scan measurements and optimization

The user approves further measured optimization and test runs to meet the
plain-bpftrace baseline. Do not weaken authorization, target checks, evidence
durability, resource ownership, deadlines, output limits or cleanup. Keep the
no-increase requirement for every pair. Do not add a percentage allowance.

The handle-cache source `94bf4428` completes the unprofiled comparison in
581.19 seconds. The five pairs below use the unchanged 5,000-open fixture,
stock backend, source, environment and owned VM. No Cargo, CI, profiler or
guest polling runs during this comparison.

| Pair | Plain p99, ns | Araphor p99, ns | Difference, ns | Difference, % |
| --- | ---: | ---: | ---: | ---: |
| 1 | 143,808 | 221,803 | +77,995 | +54.24 |
| 2 | 246,326 | 182,055 | -64,271 | -26.09 |
| 3 | 156,994 | 417,242 | +260,248 | +165.77 |
| 4 | 310,050 | 166,551 | -143,499 | -46.28 |
| 5 | 109,956 | 243,701 | +133,745 | +121.64 |

All ten runs have 5,000 exact denials, zero effect loss and zero unresolved
effects. Independent cleanup passes; enforcement resources stay unchanged.
Trace kernel loss remains unknown. Three pairs fail the comparison gate.
Read `capture-pairs.json` and `test.log` in the guest output
`/tmp/araphor-observability-153-fdinfo-20261003-5000`.

The separate post-cache profile uses the same approved CPU and scheduler
recorders and instrumented fixture. Its guest directory is
`/var/tmp/araphor-attribution-fdinfo.TxsIsNAf`; local analysis is in
`/tmp/araphor-fdinfo-profile.bc4UoneF`. The scheduler export reports no lost
records or ordering violations. The CPU recorder reports 2,155 out-of-order
events. Of 43 supervisor CPU samples, 35 include resource inspection.
Recorded stacks include repeated path construction and file rewinds.
The profile does not prove a p99 improvement. Its pair differences are
-20.69%, -4.37%, +1.79%, +2.12% and +0.67%; three pairs still fail.

`SupervisedChild` now selects numeric FDs in a fixed 256-entry buffer. It
builds a path only when a cached handle is absent. One 16-KiB byte buffer
serves all fresh fdinfo reads. `FileExt::read_at` starts at zero and continues
short reads at increasing offsets. Retry interruption at the same offset.
Reject other errors and invalid UTF-8 before copying or parsing text. Keep
the fresh directory open, 10-ms turns, ID unions and eviction.
Linux [sequence reads](https://github.com/torvalds/linux/blob/v6.8/fs/seq_file.c)
reset at offset zero. [Positioned reads](https://github.com/torvalds/linux/blob/v6.8/fs/read_write.c)
still call the read permission check.

The offset regression fails before this change and passes after it. All 17
backend tests pass in 31.53 seconds. After the final reader type change, the
three resource tests pass in 0.04 seconds. They check interrupted and short
reads, errors after a prefix, current contents, unchanged file position,
invalid UTF-8, limits, closed and reused FDs, and bounded handle ownership.
Owned upload passes in 24.87 seconds. Read `resource-offset-red.log`,
`resource-offset-green.log`, `resource-partial-green.log` and
`resource-owned-green.log` in the local analysis directory. Independent
Ponytail review finds no unnecessary owner or dependency. The implementation
slice is **Done**. Its unprofiled comparison and final CI are **Not done**.
Performance parity remains **Not done**. Diagnostics stay disabled.

The next unprofiled comparison uses `e02924e4`, the same archive and binary
path, and guest output `/tmp/araphor-observability-153-offset-20261003-5000`.
The physical case completes in 582.41 seconds and returns 101 at the unchanged
comparison gate. No Cargo, CI, profiler or guest polling runs during it.

| Pair | Plain p99, ns | Araphor p99, ns | Difference, ns | Difference, % |
| --- | ---: | ---: | ---: | ---: |
| 1 | 160,723 | 227,352 | +66,629 | +41.46 |
| 2 | 211,004 | 236,202 | +25,198 | +11.94 |
| 3 | 167,357 | 230,584 | +63,227 | +37.78 |
| 4 | 160,598 | 257,495 | +96,897 | +60.34 |
| 5 | 137,204 | 208,597 | +71,393 | +52.03 |

All ten runs have 5,000 exact denials, zero effect loss, zero unresolved
effects and eligible negative claims. Plain capture has verified cleanup and
unchanged enforcement resources. Each Araphor terminal is `Deadline`, with
verified cleanup and complete output. Trace kernel loss remains unknown.
Read `offset-5000/capture-pairs.json` and `offset-5000/test.log` in
`/tmp/araphor-fdinfo-profile.bc4UoneF`. All five pairs fail. The code removes
measured repeated work, but these results do not prove a p99 improvement.
Performance parity and final CI for this code remain **Not done**.

The next profile uses a 199-Hz CPU recorder and the same scheduler recorder.
Of 131 supervisor CPU samples, 57 include fdinfo reads, 18 include directory
work and 16 include status reads. Of the sampled leaf functions, 97 are kernel
functions and 20 are Rust functions. These samples do not identify UTF-8
conversion or text copying as the active cost. Do not select a copy-removal
change from these samples.

| Pair | Plain p99, ns | Araphor p99, ns | Difference, ns | Difference, % |
| --- | ---: | ---: | ---: | ---: |
| 1 | 269,288 | 278,030 | +8,742 | +3.25 |
| 2 | 233,627 | 232,006 | -1,621 | -0.69 |
| 3 | 241,574 | 248,185 | +6,611 | +2.74 |
| 4 | 239,415 | 234,492 | -4,923 | -2.06 |
| 5 | 196,712 | 282,993 | +86,281 | +43.86 |

This profile does not qualify performance. Three pairs fail the comparison.
All five pairs have equal program types, names, tags, translated sizes, JIT
sizes and map layouts. Equal tags do not prove equal translated or JIT bytes.
Read `program-comparison.json`, `diagnostic-stacks.json` and the recorder
analysis in `/tmp/araphor-offset-profile.bxGhTwug`. Guest recorder files are
in `/var/tmp/araphor-attribution-offset.GygAmvw0`.

`SupervisedChild::reap` replaces repeated status reads with one `wait4` call
for the exact owned child. Retry interruption. Set the reaped state before
converting the result, so Drop does not signal a reused PID. The kernel memory
value includes the pre-exec address-space peak and waited descendants.
Report `peak_rss_kib` as a conservative child-lifetime observation, not the
backend's post-exec RSS. No live memory limit consumes this field. Keep the
resource inventory, 10-ms turns, target checks, output limits and cleanup.

All 19 backend tests pass; one privileged case is ignored. The memory test
checks that the reported peak includes memory used before an exec and that
the child is reaped after cancellation. Owned upload passes in 24.74 seconds.
Read `resource-reap-green.log` and `reap-owned-green.log` in the local profile
directory. The unprofiled comparison and final CI remain **Not done**.
Diagnostics stay disabled.

### Reap comparison and exact-rank attribution

The unprofiled comparison covers source `833e9606`. It completes in 581.79
seconds and returns 101. The workload, backend, script, environment and
five-pair no-increase gate do not change. No profiler, build, CI or guest
polling runs during the comparison.

| Pair | Plain p99, ns | Araphor p99, ns | Difference, ns | Difference, % |
| --- | ---: | ---: | ---: | ---: |
| 1 | 182,218 | 209,377 | +27,159 | +14.90 |
| 2 | 123,046 | 217,263 | +94,217 | +76.57 |
| 3 | 152,154 | 217,023 | +64,869 | +42.63 |
| 4 | 139,813 | 160,000 | +20,187 | +14.44 |
| 5 | 212,210 | 193,007 | -19,203 | -9.05 |

All ten runs have 5,000 exact denials, zero effect loss and zero unresolved
effects. Independent cleanup passes; enforcement resources stay unchanged.
Each Araphor terminal reports `Deadline`, verified cleanup and complete
output. Trace kernel loss remains unknown. Four pairs fail. Read
`reap-5000/capture-pairs.json` and `reap-5000/test.log` in
`/tmp/araphor-offset-profile.bxGhTwug`. Performance parity is **Not done**.

A separate control comparison runs plain bpftrace on both sides. This
temporary test variant changes only capture-path selection and labels.
Production source is restored before measurement. The comparison completes
in 549.12 seconds. Three pairs fail the unchanged no-increase predicate.

| Pair | First plain p99, ns | Second plain p99, ns | Difference, ns | Difference, % |
| --- | ---: | ---: | ---: | ---: |
| 1 | 312,829 | 213,119 | -99,710 | -31.87 |
| 2 | 239,029 | 242,151 | +3,122 | +1.31 |
| 3 | 162,515 | 123,900 | -38,615 | -23.76 |
| 4 | 241,783 | 249,993 | +8,210 | +3.40 |
| 5 | 181,405 | 215,511 | +34,106 | +18.80 |

All ten receipts identify plain capture. Denials, loss, unresolved effects,
cleanup and enforcement-resource checks pass. Read `plain-control` in the
same local directory. This result shows comparison variability. It does not
prove Araphor parity or permit a larger acceptance limit.

The next bounded profile covers one plain/Araphor pair on `833e9606` with
5,000 operations per run. It uses the approved instrumented fixture, a 199-Hz
CPU recorder and the scheduler recorder. It is not qualification. Plain p99
is 227,613 ns; Araphor p99 is 273,030 ns, an increase of 45,417 ns or 19.95%.
At the exact sorted index 4,949, plain waits 190,529 ns and Araphor waits
233,628 ns. The same shared Node worker occupies both runnable waits.
Neither exact operation overlaps supervisor execution.

At Araphor sorted rank p99+4, the supervisor occupies the complete 235,339-ns
runnable wait. Twenty-four resource reads occupy 77,804 ns of that interval.
Across the Araphor actor window, all 13,440 resource calls pair correctly:
6,720 positive reads and 6,720 EOF reads, with no errors. Their elapsed time
totals 51.05 ms, including 18.02 ms for EOF reads. This is wall time, not pure
CPU time. Resource inspection causes contention near the threshold. The
profile does not prove that inspection causes the whole p99 difference.
Positive short reads still require continuation through EOF.

The scheduler export has no lost, unordered or unparsed records. The CPU
export is ordered but retains the recorder's warning for 2,535 out-of-order
events. Read `analysis.json`, `cpu-analysis.json`, the actor timing files and
recorder logs in `/tmp/araphor-reap-attribution.qLHawK0o`. The guest recorder
directory is `/var/tmp/araphor-attribution-reap.WewrtzIH`.

### Approved static resource inventory

The user approves one narrow exception to continuous resource inspection.
Only the reviewed backend digest
`d2846f3400bb129b1a569aae64adf548de99ff41f247823ff8caf1fbde40ff1e`
and the exact canonical FailedOpens source qualify. The source digest is
`bfa0519ba10b4eba255961285b1d2b46e1ea3ddb55793ac2720ee43fa4308a6e`.
The existing fixed environment remains part of this qualification.

After the real stderr attachment marker, take a fresh complete inventory.
Do not use the historical ID union as the current inventory. Require both
expected program roles and all three map roles, with the reviewed types,
names, sizes, capacities and flags. Any directory, entry, read or metadata
error, truncation, missing role or extra role retains continuous inspection.
Compile mode, other scripts and other backend digests retain that path.
Require valid common fdinfo fields for every selected FD. A BPF-typed record
without its matching nonzero ID is incomplete. Take only one eligible
snapshot attempt. A failed attempt cannot later enable the static path.
Resume resource scans during shutdown.

| Role | Kernel type | Kernel name | Key/value bytes | Capacity |
| --- | --- | --- | --- | ---: |
| Open-exit probe | Tracepoint | `sys_exit_openat` | Not applicable | Not applicable |
| Print interval | Perf event | `1` | Not applicable | Not applicable |
| Error count | Per-CPU hash | `AT_errors` | 8/8 | 4096 |
| Output buffer | Ring buffer | `ringbuf` | 0/0 | 32768 |
| Output loss count | Array | `ringbuf_loss_co` | 4/8 | 1 |

Map flags are zero. Program names in this table are kernel names, not longer
names from debug information. A different supported backend can retain
continuous scanning; the static path is not required for capture correctness.
Use the name from `bpf_prog_info.name`. The reviewed backend removes the
prefix through the last colon before `bpf_prog_load`. The kernel name is
`sys_exit_openat`. The full BTF function name is not this field. Read
[the backend naming code](https://github.com/bpftrace/bpftrace/blob/v0.20.2/src/attached_probe.cpp#L679).

For a verified static inventory, remove repeated collection-time resource
reads. The reviewed script and backend create no later BPF resources.
Preserve historical IDs for independent cleanup. Do not retain BPF handles
that could keep resources alive. Keep the 10-ms supervision turn, current
target and grant checks, cancellation, deadlines, output bounds, durability
and cleanup. This exception changes resource-inspection cadence, not the
capture's authority or enforcement behavior.

`StaticResources::select`, `record` and `verify` implement this contract in
the existing Interceptor supervisor. The first post-marker attempt uses
fresh current ID sets. The owner consumes the profile for that attempt, so
failure keeps ordinary scanning for the rest of the capture. Successful
verification closes temporary BPF handles and cached proc handles. Closing
and natural exit resume inspection before cleanup.

The focused backend selection passes 23 tests in 31.84 seconds; one subprocess
fixture is ignored. Strict package Clippy passes with all targets and
features. Owned upload passes in 25.21 seconds. Read `backend-tests-final.log`,
`backend-clippy-final.log` and `owned-upload.log` in
`/tmp/araphor-static-inventory.GOQgpiAI`. Independent safety and Ponytail
review find no must-fix issue. This implementation slice is **Done**. Physical
activation and its unchanged unprofiled comparison remain **Not done**.
Final workspace CI passes at `af72dbeb`. The command
`bash .github/scripts/verify-rust-ci.sh` returns zero. Formatting, workspace
check, strict Clippy and workspace tests pass. Read `workspace-final.log`
in the same evidence directory. Performance parity is **Not done**.
Diagnostics stay disabled.

The first unprofiled comparison of `6005773e` starts at 19:45 UTC on
2026-10-03. It uses the unchanged full ten-run binary and archive. The SSH
command ends with status 255 after the VM stops responding. Libvirt reports
`paused (user)` and no block-device error. The host has 62 GB free. The guest
output is `/tmp/araphor-observability-153-static-20261003-5000`; the host launch
log is `comparison-launch.log` in the local test directory above.
This run is interrupted. No five-pair result is available, and no parity
result is claimed. The user approves VM resume and a fresh comparison.
Discard this interrupted run for timing qualification after recovery.

The fresh comparison of `6005773e` returns 101 in 591.81 seconds. No build
or profiler runs during this comparison. The normal ten-run binary, backend,
source, archive, target and 30-second collection limits are unchanged.
Each run uses 5,000 denied opens with 1-ms spacing.

| Pair | Plain p99, ns | Araphor p99, ns | Araphor minus plain, ns | Difference |
| --- | ---: | ---: | ---: | ---: |
| 1 | 171,174 | 151,543 | -19,631 | -11.468447% |
| 2 | 120,753 | 169,523 | +48,770 | +40.388231% |
| 3 | 104,714 | 122,446 | +17,732 | +16.933743% |
| 4 | 140,124 | 321,902 | +181,778 | +129.726528% |
| 5 | 166,231 | 223,511 | +57,280 | +34.458073% |

All ten runs retain 5,000 exact policy denials. Reported enforcement loss
and unresolved effects are zero. Cleanup is verified. Enforcement resources
remain unchanged. Four pairs exceed the zero-increase limit. Parity remains
**Not done**. The comparison does not prove activation of the static path.
Read `comparison-rerun/capture-pairs.json` and `comparison-rerun/test.log`
under `/tmp/araphor-static-inventory.GOQgpiAI`. The guest output is
`/tmp/araphor-observability-153-static-rerun-20261003-5000`.
Use the existing CPU and scheduler attribution before another change.

The next instrumented pair on `6005773e` records plain p99 321,849 ns and
Araphor p99 389,701 ns: +67,852 ns, or +21.081936%. Both runs retain 5,000
exact denials, zero reported enforcement loss and verified cleanup. These
timings do not qualify parity. The exact p99 calls include 280,292 ns and
321,543 ns of runnable wait. All 22 calls at p99 and five ranks on each side
have no same-CPU trace-supervisor or trace-worker overlap. Shared Node and
kernel work accounts for their wait. This does not exclude indirect trace
load. The supervisor still makes 13,536 matched preads in the Araphor actor
window, including zero-duration records. The static path does not activate.
Read `analysis.json`, `cpu-analysis.json` and retained actor records in
`/tmp/araphor-static-profile.IT3ct7mZ`. Retain the CPU recorder's 2,304-event
ordering warning and the 51 plain/two Araphor CPU-greater-than-wall records.

A native check of the exact backend and source finds kernel program names
`sys_exit_openat` and `1`. Both post-marker snapshots have valid records,
two unique programs and three maps with the required layouts. The child
exits zero; all five IDs disappear. Read `snapshot.json` in
`/tmp/araphor-native-fdinfo.PpH66zk2`. The native name corrects the private
role check and table above. The regression rejects both misleading BTF-name
forms. All 23 focused backend tests pass in 31.61 seconds. Owned upload passes
in 24.84 seconds. Independent review finds no must-fix issue. Physical
activation, the unchanged five-pair
comparison and final workspace CI after this correction remain **Not done**.

The instrumented pair on `f078ebc4` proves static-path activation. During the
Araphor actor window, supervisor pread and fdinfo-directory stat counts are
zero. Supervisor CPU samples fall from 33 to six; resource-inspection samples
fall from 28 to zero. Target validation retains 571 cycles, with three BPF
calls and two statx calls per cycle. Both runs retain 5,000 exact denials,
zero reported enforcement loss and verified cleanup.

Plain p99 is 178,299 ns; Araphor p99 is 243,557 ns. The difference is
+65,258 ns, or +36.600317%. The exact p99 waits are 137,824 ns and 198,625 ns.
All 22 nearby ranked calls have zero same-CPU supervisor or trace-worker
overlap. Shared workers account for their wait. No CPU sample occurs inside
those calls; full-window stacks do not identify an exact function there.
The CPU recorder reports 2,629 ordering events. Exported loss, ordering and
parser counts are zero. Scheduler exit 130 follows data finalization; both
exports return zero. These instrumented timings do not qualify parity.
Read the retained results in `/tmp/araphor-native-name-profile.QMUvAh09`.
Its `raw-recordings.tar.gz` contains byte-verified copies of both raw perf
files removed from the VM. Physical activation is **Done** at `f078ebc4`.

The first unprofiled run at this source stops before latency sampling.
Profiling files reduce VM free space below the existing filesystem reserve.
Control refuses intake, and target resolution times out. The reserve remains
unchanged. Removing the two archived temporary recordings frees 1.19 GiB;
the VM then has 3.2 GiB free. The unchanged five-pair rerun and final workspace
CI remain **Not done**. No parity result follows from the stopped setup.

The unprofiled rerun on `f078ebc4` uses the preserved full ten-run binary.
No build or profiler runs during the comparison. The exact backend, source,
archive, target and workload remain unchanged.

| Pair | Plain p99, ns | Araphor p99, ns | Araphor minus plain, ns | Difference |
| --- | ---: | ---: | ---: | ---: |
| 1 | 164,250 | 135,179 | -29,071 | -17.699239% |
| 2 | 208,894 | 127,911 | -80,983 | -38.767509% |
| 3 | 255,676 | 179,912 | -75,764 | -29.632817% |
| 4 | 198,012 | 244,094 | +46,082 | +23.272327% |
| 5 | 220,627 | 174,783 | -45,844 | -20.778962% |

All ten runs retain 5,000 exact denials, zero reported enforcement loss,
zero unresolved effects and verified cleanup. Negative-claim eligibility
remains true. Four pairs are faster, but pair 4 exceeds the unchanged
zero-increase limit. The command returns 101. Parity remains **Not done**.
Read `name-fix/comparison-rerun/{capture-pairs.json,test.log}` under
`/tmp/araphor-static-inventory.GOQgpiAI`. The guest output is
`/tmp/araphor-observability-153-native-name-rerun-20261003-5000`.

The final workspace gate passes at `f078ebc4` after the last Rust edit.
Run `.github/scripts/verify-rust-ci.sh` with the existing worktree target,
`CXXFLAGS='-O2 -g0'`, two build jobs, no incremental build, offline input and
one test thread. The command returns zero. Read
`name-fix/workspace-final.log` in the same evidence directory. Final Rust CI
is **Done**. Performance parity remains **Not done**.

The next diagnostic uses the same 5,000 operations and one plain/Araphor
pair. Temporary entry and return probes record five functions:
`verify_live_manifest`, `persist_snapshot`, `project_group`, `refresh_budget`
and `retain_raw`. The probes use the exact private test executable and
`nsecs(monotonic)`. Attach all probes before the test starts. Do not change
the recipe, workload, security checks or tracefs permissions. Keep scheduler
events; do not add CPU sampling. Match spans by process, thread and function.
Intersect each span with the same thread's on-CPU intervals during actor
runnable waits. Do not count nested spans twice or treat wall time as CPU
time. Report all-operation, tail-50 and p99-nearby results, loss and incomplete
boundaries. This diagnostic does not qualify performance.

Both function diagnostics cover `f078ebc4` and retain 5,000 exact denials per
run, zero reported enforcement loss and verified cleanup. The first pair
has plain p99 312,294 ns and Araphor p99 261,190 ns: -51,104 ns, or
-16.364067%. Executable hashing overlaps the plain actor window. Its thread
runs for 662.869 ms in that window and accounts for 6.293 ms of same-CPU
actor wait. This pair has unequal setup work. Do not use it to claim an
improvement. Read `/tmp/araphor-function-spans.nQE9ewSA`.

The repeat completes hashing before recording and moves process discovery
after the first actor window. No recorded hash, process-discovery, SSH,
readlink or stat thread overlaps either actor window. Plain p99 is 257,125
ns; Araphor p99 is 210,537 ns: -46,588 ns, or -18.118814%. Total call wall
time is 240.375 ms plain and 241.086 ms Araphor. The slowest 50 calls total
23.864 ms and 24.965 ms. The lower p99 is not a uniform speed increase.

Coverage persistence overlaps six plain and two Araphor calls among the
eleven ranks near p99. Its all-call same-CPU wait is 4.247 ms plain and
4.271 ms Araphor. Manifest verification contributes zero and 1.905 ms.
Neither wrapper thread overlaps the exact p99 or the Araphor tail-50 calls.
The Araphor p99 includes 76,622 ns behind a bpftrace thread whose profiler
ownership is not independently recorded. Probe overhead remains unknown.
All 9,861 function spans have entry and return records. Loss, ordering and
parser counts are zero. Retain two boundary syscall records and one
CPU-greater-than-wall operation per run. Read
`/tmp/araphor-function-clean.PpxG5PKs/function-analysis.json` and its detail
file. Both export commands return zero. Function and collector exits are
zero; scheduler exit 130 follows data finalization. The harness returns 101
because this diagnostic has one pair, not the required five. These results
support shared-work timing as a test target; they do not qualify parity.

### One fresh map metadata query

`KernelHost::verify_manifest_pins` previously opened each map through
`MapHandle::from_pinned_path`, then called `map.info()`. The locked
libbpf-rs constructor already reads map metadata. These calls read the same
immutable map metadata twice per verification. The new owner method opens
the current pin once and reads its metadata once. The method retains the
owned descriptor until validation completes. Every pass opens the pin again.
No descriptor or metadata cache persists between passes.

Keep map-name validation and the map ID, type, key size, value size and entry
limit checks. Keep lease, link and program checks. The native call uses the
same default options as the previous binding. Convert its negative errno
return to the existing typed error. Limit the unsafe-code exception to this
private method. Do not change the crate-wide rule.

The library command `cargo test -p erebor-interceptor --lib` passes 49 tests
in 31.73 seconds; two privileged or subprocess fixtures remain ignored.
On VM `192.168.122.153`, the same library binary passes
`host::tests::pinned_map_freshness --ignored --exact --nocapture` with
`EREBOR_TEST_BPFFS_ROOT=/sys/fs/bpf`. The test uses a private temporary pin
directory. It detects an unlinked pin while the old descriptor remains open,
rejects a same-layout replacement ID, rejects a changed layout, and verifies
release of all three map IDs. The command returns zero. Independent safety
and Ponytail review find no must-fix issue. Owned upload passes in 24.34
seconds. Read `manifest-tests-green.log` and `owned-upload.log` in
`/tmp/araphor-function-clean.PpxG5PKs`. The final
`bash .github/scripts/verify-rust-ci.sh` run returns zero after the last
Rust test change. Formatting, workspace check, strict Clippy and all
workspace tests pass. Read `workspace-recheck.log` in the same directory.

The unchanged five-pair comparison uses the private full ten-run binary
`target/araphor-map-query.3YbvWgy6/normal-pairs`, SHA-256
`ea9de8261399563b8187737537e5a120db94a959ffe7c8eeb718da21671437db`.
Its production map-validation code includes this change. The later test-only
assertion correction does not change production code. Keep the 5,000 denied
opens, 1-ms spacing, 30-second captures, backend and script unchanged.

The first attempt stops before sampling because free space crosses the
unchanged filesystem reserve. Archive the two earlier static-profile perf
files and verify both file hashes before removing their VM copies. The
archive remains in `old-static-raw.tar.gz` in the evidence directory above.
Free space increases to 3,949,543,424 bytes. The repeat runs without a build,
profiler or guest status query during sampling. Pause only the owned CI
process for this comparison; resume CI after capture completes.

| Pair | Plain p99, ns | Araphor p99, ns | Araphor minus plain, ns | Difference |
| --- | ---: | ---: | ---: | ---: |
| 1 | 254,501 | 200,005 | -54,496 | -21.412882% |
| 2 | 242,955 | 182,782 | -60,173 | -24.767138% |
| 3 | 243,173 | 156,816 | -86,357 | -35.512577% |
| 4 | 277,742 | 169,793 | -107,949 | -38.866646% |
| 5 | 158,586 | 174,914 | +16,328 | +10.295991% |

All ten runs retain 5,000 exact denials, zero loss, zero unresolved effects,
negative-claim eligibility and verified cleanup. The command returns 101 in
581.68 seconds. Pair 5 exceeds the zero-increase limit. Performance parity
remains **Not done**. Read `map-query-pairs.json` in the evidence directory
above and guest `test.log` in
`/tmp/araphor-observability-153-map-query-rerun-20261003-5000`. The smaller
Araphor range and faster plain result in pair 5 do not establish a cause.

The test logging owner defaults to DEBUG; production defaults to INFO.
The earlier ordinary log has 726,288 DEBUG lines. Earlier actor-window CPU
profiles contain logging-family stacks in 47 plain and 44 Araphor samples.
No p99-adjacent CPU sample attributes the regression to logging. A comparison
with production INFO logging on both routes awaits separate user approval.

Pass `OBS-TARGET`, `OBS-GRANT`, `OBS-REPLAY`, and `OBS-LOSS`. Cases include
foreign namespace/tenant, host source under pod grant, changed digest, new
container under the same pod name, reused PID/cgroup, control partition, Node
restart before spawn/after spawn, duplicate output, disk full, map exhaustion,
output truncation, partial fan-out, and late terminal output. A frozen target
does not widen after a retry. Revocation prevents further disclosure and
requests stop; partitioned execution ends at its local lease deadline.

Measure trace-on versus trace-off enforcement latency and evidence loss on
stated hardware with at least five paired runs. Before enablement, set the
deployment's allowed overhead and storage reserve, and reject configurations
that exceed them. No universal performance guarantee follows from a test host.
No induced trace failure may change the installed policy or its physical
decisions. If BPF-related overhead cannot be contained, keep that recipe off.

Add `observability_target_`, `observability_recovery_`, and
`observability_projection_` tests beside their owners. Run the lightweight
cases before the paired physical Kubernetes cases, then full Rust CI. Keep
source/target/approval digests, frame sequences, cleanup proof, and measurements
in the existing test output. Do not create a separate review-report family.

## Physical lifecycle gates

The current `observability::tests::observability_owned_upload` case passes
ten Node-owner cases in 24.18 seconds. Run
`cargo test -p mithril-e2e --all-features --lib observability::tests::observability_owned_upload -- --exact --nocapture`.
Read `owned-ten-cases-final.log` in `/tmp/araphor-owned-lifecycle.DlPg5O1y`.
The added cases cover revoked reads with terminal upload, a supplied 4096-key
map result, supervised output overflow, binding removal with a new lifetime,
and native segment creation failure before sync. The native case changes the
configured evidence-directory input. It gets `ENOTDIR`, no ACK and no sync.
Retry sees an unready writer. Reopen has zero progress and accepts exact replay.
The map fixture does not prove kernel saturation. Attach notifications are
simulated. These cases do not prove physical BPF cleanup or enforcement.

`Host::qualify_diagnostic_failures` now observes BPF program, map and link IDs
before dispatch and after attachment. Each case must restore that inventory
before Node shutdown. Baseline enforcement IDs must remain. The native
full-store case has the same independent cleanup check before Node shutdown.
Both use the existing `ResourceSnapshot` owner. No production owner changes.
The final `bash .github/scripts/verify-rust-ci.sh` run passes on `ee5f068d`.
Formatting, workspace check, strict Clippy and all workspace tests pass.
Data passes 167 tests, Observability 23, Interceptor 40, Control 170,
Mithril e2e 145 and Node 262. Read `workspace-fault-final.log` in
`/tmp/araphor-owned-lifecycle.DlPg5O1y`. Ignored physical tests are not passes.
Paired physical results and performance parity remain **Not done**.

The combined physical fault route on VM `192.168.122.153` returns 101 on
`ee5f068d` with `mithril_e2e-1adb172a9b31c9af`. Owned upload first passes in
24.88 seconds. The physical test fails after 110.43 seconds with
`partition: attachment absent: []`. Later fault cases are not reached.
The command is `owned.sh BIN ARCHIVE OUTPUT 1 --test-admission`; output is
`/tmp/araphor-owned-failures-20261003-ee5f068d` in the guest. Read the copied
logs in `/tmp/araphor-owned-lifecycle.DlPg5O1y/failures-current`.
Source review finds that the external TCP proxy discards TLS bytes while
blocked. Its endpoint has already acknowledged those bytes. Repair cannot
restore them on that connection. The new lightweight
`control_tls::observability_partition_tls_repair` case first fails both
active-session repair and ClientHello repair in 10.19 seconds. Each leg
has a five-second bound and a held-input notification. The corrected relay
holds its existing 16-KiB chunk, waits for repair, then forwards it before
the next read. Control-to-Node forwarding and shutdown do not change.
The exact regression then passes in 0.29 seconds. The existing outage and
predecessor-replacement test passes in 26.13 seconds with its old bound and
checks. Read `partition-tls-red.log`, `partition-tls-green.log` and
`partition-outage-focused.log` in the same evidence directory. The changes
affect only the external test fixture. Repeat the paired physical route
and final workspace CI before qualification. This proxy is not used by the
latency comparison. No performance cause is inferred.

The repeated combined route on `9e4f08dc` returns 101 after 141.36 seconds.
Its lightweight companion first passes in 24.92 seconds. The partial receipt
contains partition, revocation and bounded-map results. Each has one exact
physical denial and independent BPF cleanup before Node shutdown. The
partition expires at its signed deadline; revocation returns `Cancelled`;
the map case returns `Completed`. The next case fails at
`output-limit: attachment has no observed diagnostic BPF programs`.
Its inventory is read only after the retained notification arrives. This
does not establish whether the short capture ended before that read.
Retirement is not reached. The combined route remains **Not done**.
Read the copied logs and partial `capture-pairs.json` in
`/tmp/araphor-owned-lifecycle.DlPg5O1y/failures-relay`. The guest output is
`/tmp/araphor-owned-failures-20261003-9e4f08dc`.
Before a correction, add the exact immediate-output-overflow condition to
the lightweight case. Its current backend waits for prefix ACK before
overflow. Do not slow the physical source or remove the inventory check.
Final workspace CI passes on `9e4f08dc`. Formatting, workspace check, strict
Clippy and all workspace tests return zero. Data passes 167 tests,
Observability 23, Interceptor 40, Control 170, Mithril e2e 146 and Node 262.
Read `workspace-relay-final.log` in the same evidence directory. This source
includes the TLS repair regression. Ignored physical tests are not passes.
The next immediate-overflow and observer changes require new verification.

The lightweight `observability_owned_upload` case now has eleven cases.
`output-before-upload` emits 1,048,577 bytes after its simulated attach
notification, without waiting for a prefix ACK. The local owner reaches
`OutputLimit` before the first upload. Control has zero output progress and
no terminal. Reopen preserves the exact request, grant and bounded prefix.
Current mTLS upload and replay return the same ACK without another launch.
Cleanup stays unknown. This is not physical BPF proof.
The exact test passes in 24.70 seconds on `9427c92d` plus this test change.
Read `owned-eleven-focused.log` in the same evidence directory. Formatting
passes. Final workspace CI and the corrected physical observer remain due.

`Host::qualify_diagnostic_failures` now samples BPF resource IDs before
dispatch through local terminal state. The scoped thread uses the existing
20-ms interval and a 77-second bound from the case's current time limits.
Each sample checks baseline IDs. The observer joins before the final exact
inventory comparison. A real retained attach notification and nonempty new
program IDs remain required. A missed short lifetime fails qualification.
The source, output limits and production owners do not change.
The existing fault and full-disk harnesses now run the exact lightweight
TLS repair case before their physical case. The performance route does not
change. The final observer source passes the eleven-case owner test in
24.68 seconds and the TLS repair test. Read `observer-owner-focused.log` and
`observer-tls-focused.log` in the same evidence directory. Formatting and
both harness syntax checks pass. Final workspace CI and physical proof remain
due on `b9b01888` plus this observer and harness change.

Final workspace CI passes on `d486e637`. Formatting, workspace check,
strict Clippy and all workspace tests return zero. Data passes 167 tests,
Observability 23, Interceptor 40, Control 170, Mithril e2e 146 and Node 262.
Read `workspace-observer-final.log` in the same evidence directory.
Ignored physical tests are not passes.

The first observer run passes partition, revocation, map exhaustion and
output overflow. Retirement then fails because the launch omits
`MITHRIL_TEST_OCI_HOOK`. The input archive has no runtime executable.
The checked worktree binary exists and its `run --help` preflight passes.
No production or fixture source change follows from this missing input.
The repeated run sets
`MITHRIL_TEST_OCI_HOOK=/mnt/mithril-source/worktrees/mithril-ui/target/debug/mithril-oci-hook`.
It uses `owned.sh BIN ARCHIVE OUTPUT 1 --test-admission`, the same archive,
VM and libtest binary as the previous run. Its guest output is
`/tmp/araphor-owned-failures-20261003-d486e637-hook`.
Owned upload passes in 26.82 seconds and TLS repair in 0.74 seconds.
All five physical fault cases pass in 116.95 seconds. The command returns zero.

| Case | Terminal reason | Physical denials |
| --- | --- | ---: |
| Partition | `Deadline` | 1 |
| Revocation | `Cancelled` | 1 |
| Map exhaustion | `Completed` | 1 |
| Output overflow | `ConsumerSlow` | 1 |
| Runtime retirement | `TargetChanged` | 2 |

Each case retains nonempty diagnostic program IDs. Independent inventory
returns to baseline before Node shutdown. Enforcement resource IDs do not
change. Cleanup is verified; trace kernel loss remains unknown. Output is
incomplete except for the bounded-map case. Read `capture-pairs.json`,
`test.log`, `lightweight.log` and `lightweight-tls.log` in `failures-hook`
under the same evidence directory. The combined fault route is **Done** on
this source and platform. Pod replacement, native full-store proof and
performance parity remain **Not done**. Diagnostics stay disabled.

Native full-store qualification is **Done** on `d486e637` and the same VM.
Run `disk-full.sh BIN ARCHIVE OUTPUT --test-admission` with the verified
worktree hook input above. The harness creates a fresh 1-GiB tmpfs. Its guest
output is `/tmp/araphor-owned-storage-20261003-d486e637`. The command returns
zero. Owned upload first passes in 25.37 seconds and TLS repair in 0.72 seconds.
The physical case passes in 124.17 seconds.

The real segment write fails with `ENOSPC` before sync. Control sends no ACK;
raw output progress is zero before replay. Discovery stays disabled. Node
retains 27 frames with 1,214 bytes and reaches its signed local deadline.
Cleanup is verified before Node shutdown. Independent inventory removes
programs 2648 and 2649 and maps 1890 to 1892, with no links. Enforcement IDs
remain unchanged. Store and Node reopen preserve the exact accepted request,
frames and terminal. Current mTLS replay returns the same ACK at sequence 27.
Three exact physical policy denials pass. Output is incomplete and trace
kernel loss stays unknown. The harness removes only its temporary full-store
mount. Read `storage.json`, `test.log`, `lightweight.log` and
`lightweight-tls.log` in `storage-current` under the evidence directory above.
Pod replacement and performance parity remain **Not done**.

The first Pod route returns 101 on `d486e637`, with the same VM and libtest
binary. `pods.sh BIN --test-admission BUNDLE OUTPUT` uses the full worktree
as `MITHRIL_TEST_ROOT`, the prepared Node/Control images and the pinned actor.
Owned upload first passes in 25.52 seconds. The physical case fails in
80.61 seconds with `the task Node exceeds the production recovery mount or
argument bound`. Capture does not start. No Pod capture or cleanup pass follows
from this result. Read `lightweight.log` and `test.log` in `pods-first` under
`/tmp/araphor-owned-lifecycle.DlPg5O1y`.
Fixture teardown removes its workloads. The guarded VM helper then removes
the harness-owned K3s cluster. The service is inactive and its CRI socket is
absent. Images and result logs remain available. Production limits do not change.

### Pod fixture input correction

`Kubernetes::capture_installer` converts four repeated list options to the
CLI form `--option=value`: Node read-only mounts, Node read-write mounts,
runtime CLI arguments and runtime services. It keeps argument order and
repeated values. It leaves existing combined arguments unchanged. The
recovery identity options `--owner`, `--hook-host-directory`,
`--containerd-host-directory` and `--socket` retain separate values.
The Helm chart and production recovery owner do not change.

The representative K3s chart input has 60 command and argument entries.
Compaction reduces this count to 44. Two backend mounts and 18 library mounts
then fit exactly within 64 entries and 32 Node mounts. Reject a nineteenth
library mount, an extra argument at this boundary, a missing or empty list
value, and a combined argument that exceeds 4,096 bytes. Do not raise a limit.

The exact test `platform::kubernetes::observability_runtime_mount_args` first
fails with the same recovery-bound error before the implementation change.
After the change, this test and `observability_runtime_library_names` pass.
Use the documented worktree Cargo environment and run
`cargo test -p mithril-e2e --lib platform::kubernetes::observability_runtime_ -- --nocapture`.
Read `pod-args-red.log` and `pod-args-green.log` under
`/tmp/araphor-owned-lifecycle.DlPg5O1y`. Both tests take less than 0.01 seconds
after compilation. Ponytail review finds no new owner, parser or dependency.
The fixture correction is **Done**. Paired Pod qualification and final
workspace CI remain **Not done** until their new runs finish. Performance
parity remains **Not done**. Diagnostics stay disabled.

Workspace CI returns zero on `717363cb`. Formatting, workspace check, strict
Clippy and all workspace tests pass. Data passes 167 tests, Observability 23,
Interceptor 40, Control 170, Mithril e2e 147 and Node 262. The e2e suite has
413 ignored tests. Read `workspace-pod-args-final.log` in the same evidence
directory. This run does not cover later source edits.

The paired Pod rerun first passes owned upload in 25.57 seconds. The physical
case fails after 250.66 seconds. The installer now succeeds and Node becomes
ready. The initial capture and exact denial pass. Kubernetes confirms deletion
of the original Pod, but the local exec transport still has open stdin.
Waiting for that transport before closing stdin reaches the 120-second
`deleted Pod actor` timeout. Read `pods-args/lightweight.log` and
`pods-args/test.log` in the evidence directory. This result does not qualify
Pod replacement.

The earlier input-close regression passes in 0.02 seconds. Read
`pod-exit-red.log` and `pod-exit-green.log` in the evidence directory.
That regression does not include the Kubernetes actor-status check.

The paired run at `388c298a` passes owned upload in 25.57 seconds. The physical
case returns 101 after 242.84 seconds, with the same 120-second timeout.
The actor-status check returns no exit status when the deleted Pod is absent.
`ProcessFixture::try_wait` continues to use that check after it reaps the local
attach process. Closing input does not make that status check complete.
Read `pods-388c298a-failed/test.log` in the same evidence directory.

After exact Pod UID deletion completes, `Kubernetes::capture_exit` now calls
`ProcessFixture::stop`. The existing owner closes input, bounds graceful
cleanup, uses held process descriptors or the recorded cgroup for cleanup,
and reaps the local attach process. The owner can force-stop that local
process during fixture cleanup. No remote exit status is fabricated.
Exact UID deletion, target retirement, physical policy denials, retained
output checks and independent BPF cleanup remain unchanged.

`platform::kubernetes::observability_pod_exec_exit` now includes the absent-Pod
status check. The test requires a dead remote process and a live local
transport before cleanup. It requires the local transport to be absent after
cleanup. The old extra wait fails in 3.01 seconds. The reviewed correction
passes in 2.01 seconds. Read `pod-status-red.log`, `pod-status-green.log`
and `pod-status-reviewed.log`. The fixture correction is **Done**. Its new
paired physical result and final workspace CI remain **Not done**.

Workspace CI returns zero at `888df402`. Formatting, workspace check, strict
Clippy and all workspace tests pass after the final Rust edit. Data passes
167 tests, Observability 23, Interceptor 49, Control 170, Mithril e2e 148
and Node 262. The Rust and Cargo source fingerprint is unchanged between
start and completion. Read `workspace-pod-status-final.log` in the same
evidence directory.

The new paired Pod run passes owned upload in 26.00 seconds. It uses an
immutable libtest copy with SHA-256
`89006033c55271973f771ce1e138e8adce6a44b8dcd7b792c5b299c0af8c0dc2`.
The Node and Control images retain revision `388c298a`; the intervening Rust
change affects only the test fixture. The physical case passes transport
cleanup, then returns 101 after 308.72 seconds at the 180-second diagnostic
BPF cleanup wait. Read `pods-888df402-failed/test.log`.

The diagnostic repeat retains IDs before teardown. Programs 6596 and 6597
and maps 4447 to 4449 disappear during the failed wait. Global maps and links
match the baseline. Programs 6580, 6584, 6585, 6589 and 6592 disappear;
programs 6598 and 6602 appear. The live inventory identifies 6580 as
`sd_devices` and 6584 as a map-free `cgroup_device` program. The other changed
program types are not retained. Read `pods-inventory-failed/test.log` in
`/tmp/araphor-owned-lifecycle.DlPg5O1y`. Global equality is not diagnostic
cleanup proof.

The cleanup check now compares exact private pin paths, map IDs, link IDs,
link-to-program IDs and every program that uses a private enforcement map.
The program graph includes unattached helpers and recovered generations.
Program enumeration and metadata queries fail on incomplete results.
Diagnostic selection checks both reviewed program roles and all three map
layouts. Direct ID queries require every selected diagnostic object to be
absent. Two consecutive checks must pass. Unrelated global changes do not
fail this owned-resource check. Each Pod leg has its own baseline.

The four regressions cover unrelated changes, retained diagnostic objects,
changed pins or program graphs, incomplete metadata and ambiguous capture
selection. The old predicate fails the cleanup regression. The final focused
run passes 17 tests in 24.81 seconds. Read `pod-scope-red.log` and
`pod-scope-final.log`. Final workspace CI returns zero on `29696cc2` plus
these Rust changes. The source fingerprint stays unchanged. Read
`workspace-pod-scope-final-2.log` in the same evidence directory.

The scoped physical repeat passes owned upload in 25.60 seconds and the Pod
test body in 135.96 seconds. The full receipt check returns zero. Both exact
policy denials pass. Private enforcement resources remain equal. The command
still returns 1: publication of `finish.json` stops the finite Control child
before Node teardown calls the admission listener. Read `pods-scoped` in the
same evidence directory. The scoped verifier is **Done**. The complete Pod
route and performance parity remain **Not done**. Diagnostics stay disabled.

The paired lightweight restart case is
`observability::lifecycle::tests::observability_owned_restart`. It uses
production Control dispatch, NodeTraceOwner, the shared spool and current
mTLS transport. An external backend simulates attachment. The test kills
the Node owner process before execution and after two durable output frames.
Reopen preserves the accepted request and returns `NodeRestarted`, unknown
cleanup and incomplete output. Current-session replay returns the same ACK.
Retry does not start another backend. ACK removes local frame bytes; Control
still retains the exact prefix. Discovery analysis stays disabled.
The focused case passes in 0.97 seconds. `owned.sh` runs this exact case before
either physical restart route, after the existing owned-upload case.
The final `bash .github/scripts/verify-rust-ci.sh` run returns zero after the
last Rust and harness edits. Formatting, workspace check, strict Clippy and
all workspace tests pass. Data passes 167 tests, Observability 23,
Interceptor 40, Control 170, Mithril e2e 145 and Node 262. The e2e suite has
413 ignored tests; ignored physical cases are not passes. This run covers
`e078b77f` plus the restart test and harness changes. Read
`workspace-restart-final.log` in `/tmp/araphor-owned-lifecycle.DlPg5O1y`.
Ponytail review keeps the existing owners and external process seam. No
production owner or dependency is added. The test does not prove BPF cleanup,
enforcement recovery or performance.

The earlier physical before-execution run at `444283cc` returns zero.
Its physical test takes 59.06 seconds. The receipt has no frames or observed
diagnostic BPF resources, `NodeRestarted`, unknown cleanup and incomplete
output. Two physical policy denials and recovered enforcement health pass.
Read `restart-before.json` and the logs in
`/tmp/araphor-owned-lifecycle.DlPg5O1y`. That run precedes the exact paired
lightweight route above.

The current paired routes pass on source `af4b91fe`. They use VM
`mithril-runtime-qualification-20261002163710`, address `192.168.122.153`,
and libtest binary `mithril_e2e-69abcc1defdc24e3`. The command is
`owned.sh BIN ARCHIVE OUTPUT 1 --test-admission MODE`. The archive at
`/var/tmp/araphor-owned-fault-inputs.qiLXnxP9/fixtures-current.tar.gz` has
SHA-256 `e45a80566a94034b43e44f23272e59a93cc5c60d9d0c0886a5cf4331da733929`.
Both harness commands return zero. Both run owned upload and the exact
lightweight restart case before the physical case.

| Mode | Owned upload, s | Lightweight restart, s | Physical case, s | Retained output |
| --- | ---: | ---: | ---: | --- |
| `restart-before` | 17.99 | 1.25 | 61.12 | No frames |
| `restart-after` | 17.56 | 1.24 | 59.44 | Two frames, 85 bytes |

Both receipts retain `NodeRestarted`, unknown cleanup, incomplete output,
and unknown trace kernel loss. The after-attachment receipt records programs
2061 and 2062, maps 1433 to 1435, and no links. An independent inventory
requires these diagnostic resources to disappear after SIGKILL and before
fixture shutdown. The recovery checks preserve the accepted request and
retained prefix. The lightweight case returns the same ACK on replay.
The physical cases receive the recovered ACK and retain one original
attachment notification. Recovery does not start another backend.
Two exact physical policy denials pass in each case. Recovered enforcement
health is ready, with zero reported loss, unresolved effects, decoder errors,
evidence errors, queue drops, and WAL capacity failures. Restart gaps remain
in the recorded coverage history. These results do not prove continuous
coverage across Node death.

Read `restart.json`, `test.log`, `lightweight.log` and
`lightweight-restart.log` in the `restart-before-paired` and
`restart-after-paired` directories under
`/tmp/araphor-owned-lifecycle.DlPg5O1y`. Node restart qualification is **Done**
at `af4b91fe` on this platform. The combined capture-failure route and native
full-store qualification pass at `d486e637`, as recorded above. These earlier
results do not qualify later changes. Current performance parity and Pod
replacement remain **Not done**.

1. Start a reviewed capture against a protected Kubernetes Pod. Replace that
   Pod with the same name. Require the original execution to end with
   `TargetChanged`. Require no output from the replacement under the original
   execution ID. Resolve a new request to the new Pod UID, CRI ID, and cgroup
   lifetime. Check physical denial before and after replacement.
2. Run Node as a separate process. Kill it after durable intent but before
   backend execution, then after the backend attach notification. Restart with
   the same state directory. Require retained output, `NodeRestarted`, unknown
   cleanup until independently checked, no second backend execution, and
   acknowledgement through the current mTLS session. Check BPF cleanup and
   enforcement recovery separately.
3. Disable discovery analysis. Run trace admission, upload and restart through
   production owners. Make AnalysisStore unavailable. Require no ACK, bounded
   Node spooling, local expiry and explicit loss/uncertainty. Restore the store
   and verify duplicate replay creates no second output or execution.

### End-to-end deliverable

Add lightweight `owned-capture` selection to
`crates/mithril-e2e/src/bin/mithril_observability_test.rs`. Put its case in
`crates/mithril-e2e/src/observability.rs` or a focused child of that module.
Call production Control, Node and Interceptor owner APIs with only external
runtime/process/clock doubles. Include post-commit lost ACK, source conflict,
target replacement, duplicate dispatch, Control partition and full-store restart.
Exit between output append, segment sync, receipt publication and ACK; require
exact replay without a second output. Test pin/delete races, expired output,
and a partial backup bundle. Keep diagnostic quotas separate from enforcement.
Record accepted spec, target lifetime, source/commit positions, quota and
cleanup state in result.json. Use `harness/observability/{owned,pods,disk-full}.sh`
for the paired physical cases; extend them instead of creating another runner.

## Stop point

Keep diagnostics disabled in deployment until lifecycle, interference, and
shared recovery gates pass on the qualified source and platform. Public CLI/API
exposure requires Observability 3. The Trace CRD requires Observability 4.
