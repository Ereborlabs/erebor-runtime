# Phase 2: Owned Diagnostic Capture

Connect qualified diagnostic execution to exact Araphor targets and existing
durable storage. Require [Phase 1](phase-1-contracts-and-backend.md) Done.
Complete shared recovery integration after Phase 7.2. Capture
belongs to Control and must not require discovery analysis to be enabled.

## Intended end state

One accepted request creates at most one execution per frozen target lifetime.
Output, uncertainty, and cleanup survive client and Control failures. Existing
enforcement and its evidence reserve remain independent.

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

1. Keep `TraceOwner` in `mithril-control/src/observability/`, backed by
   `araphor-data` AnalysisStore owner methods. Commit immutable source and
   request records with revision-checked state. Control decides transitions;
   the data crate commits them durably. Store source once; do not place output in the main state
   image. New requests, read grants, execution grants, and approvals are distinct.
2. Extend the authenticated protocol in
   `crates/mithril-control/proto/erebor/mithril/control/v1/control.proto` with
   a diagnostic service family. Bind dispatch, output and cancellation to
   `NodeSessionContext`, node boot, and execution identity. Limit message sizes.
   Reuse existing trust/session verification; no agent-to-node endpoint.
3. Add the Node owner in `mithril-node/src/observability.rs`. Keep the spool
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
   `araphor-data`. Reuse Control's `observability/{model,owner,dispatch,recipe}.rs`;
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
lifecycle gates. Those parts remain **Not done**. No performance experiment ran.

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

Remaining work includes diagnostic crash-stage, read-lease and incomplete-backup
proof, terminal reservations when a segment is pinned or copied for backup,
the lightweight Node/Interceptor capture path, physical lifecycle cases, and
final workspace CI. Physical enablement still requires a platform-matched
interference receipt. That experiment needs separate approval.

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
