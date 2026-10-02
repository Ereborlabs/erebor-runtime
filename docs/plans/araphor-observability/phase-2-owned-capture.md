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

Status: **Not done** for this storage contract. Physical capture qualification
also requires the cases below on the implementing revision.

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
It uses the same Cargo environment and verification script above. Its receipt
is `crate-workspace-final-4.log`. The interference experiment has not run.

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
- The Node-process restart harness requires a matching qualified configuration.
  Its before-attachment and after-attachment cases have not run on the current
  capture source. A prior backend result is not an owned-capture result.

## Acceptance and verification

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
