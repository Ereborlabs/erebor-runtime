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
  -> Control commits deduplicated output, receipt and revisions in DuckDB before ACK

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
   Commit output, deduplication receipt, state and table revisions together.
   Equal execution/source sequence and bytes is a retry; changed bytes reject.
   Typed measurements require reviewed schemas. Preserve cumulative/interval
   semantics, units, reset epoch, sampling and loss; do not sum snapshots.
8. Wire shared data recovery in `config.rs`, `main.rs` and `service.rs`.
   Trace admission uses AnalysisStore readiness, not `ControlConfig.discovery`
   or `discovery_recovered`. Prove capture with discovery disabled.
   An isolated query-worker failure leaves upload available. Data-store failure
   returns no upload ACK; Node expiry and spool limits remain effective.
9. Define scoped trace relation schemas and bounded owner reads.
   Observability 3 registers them with the qualified QueryOwner and reuses its
   append reader for the output API. No trace-specific subscription queue or
   second database is required. Retention and read-grant checks belong to the
   shared data boundary. Reserve terminal-state capacity before spawn.

Status: **Not done** for this storage contract. Physical capture qualification
also requires the cases below on the implementing revision.

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
   production owners. Terminate the query worker and prove upload continues.
   Separately make AnalysisStore unavailable: require no ACK, bounded Node
   spooling, local expiry and explicit loss/uncertainty. Restore the store and
   verify duplicate replay creates no second output or execution.

### End-to-end deliverable

Add lightweight `owned-capture` selection to
`crates/mithril-e2e/src/bin/mithril_observability_test.rs`. Put its case in
`crates/mithril-e2e/src/observability.rs` or a focused child of that module.
Call production Control, Node and Interceptor owner APIs with only external
runtime/process/clock doubles. Include post-commit lost ACK, source conflict,
target replacement, duplicate dispatch, Control partition and database restart.
Record accepted spec, target lifetime, source/commit positions, quota and
cleanup state in result.json. Use `harness/observability/{owned,pods,disk-full}.sh`
for the paired physical cases; extend them instead of creating another runner.

## Stop point

Keep diagnostics disabled in deployment until lifecycle, interference, and
shared recovery gates pass on the qualified source and platform. Public CLI/API
exposure requires Observability 3. The Trace CRD requires Observability 4.
