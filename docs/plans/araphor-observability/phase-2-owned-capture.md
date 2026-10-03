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
limit, 16-KiB descriptor bound, peak memory check, program/map ID collection
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
The log has ten evidence-production intervals, each with 10,000 records.
Health-sampling deferrals total 377 plain and 460 Araphor. Reader pending peaks
are 9 and 8. These counts show no queue exhaustion and do not isolate a cause.
Do not blame post-capture retained reads or full catalogue projection for
the measured difference. Those reads occur outside measurement; trace intent
reads use the existing raw coordinator.

Target validation opens the pinned binding map on each 10-ms turn. Backend
inspection opens current process status and file-descriptor records on its
own 10-ms turn. Diagnostic commits share the raw-store locks with enforcement
uploads. These facts identify possible extra work, not a measured cause.
The Node RPC wait continues runtime admission; do not claim admission stops
for the full diagnostic RPC. Plain always precedes Araphor within a pair.
Sampling starts after each path observes attachment; Araphor also waits for
durable output visibility. The experiment does not equalize scheduler phase.
Control scans retained intents every 500 ms. Later plain runs also have those
intents. Acknowledged Node output is truncated, and recovery is guarded;
do not claim continuous full-spool recovery. No production change follows
from these hypotheses alone.

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
lightweight route above. The current paired physical routes remain **Not done**.

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
