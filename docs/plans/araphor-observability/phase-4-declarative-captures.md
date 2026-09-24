# Phase 4: Declarative Captures

Add an optional namespaced `Trace` CRD as an input adapter to TraceOwner.
Require Observability 3 Done. This phase does not block CLI/API delivery.

## Intended end state

An authorized Kubernetes user requests one time-limited reviewed capture.
Status points to the same execution and output as the CLI/console. Controller
restarts, repeated apply, and status retries cannot start another execution.

## Implementation flow

```text
User creates an immutable Trace spec
  -> Kubernetes validates the schema and namespace RBAC
  -> Control checks namespace UID, recipe digest, targets, and grant limits
  -> controller registers a cleanup finalizer before dispatch
  -> TraceOwner uses cluster UID and resource UID for submission idempotency
  -> controller writes execution ID and conditions through the status subresource

Controller observes the resource again
  -> controller reads the same owner result
  -> completed or expired request remains terminal
  -> no metadata/status update restarts collection

User deletes the resource
  -> controller requests cancellation from TraceOwner
  -> status retains cleanup uncertainty until the physical result is known
  -> finalizer is removed after the cleanup contract is satisfied
  -> forced finalizer removal cannot extend the Node execution lease
```

Status: **Not done**. This optional phase uses the same DuckDB trace records
and query/output API; it introduces no separate output store.

## Scope, owners, and changes

1. Add `mithril.erebor.dev_traces.yaml` under
   `packaging/mithril/helm/crds/`. Use a strict structural schema, status
   subresource, bounded spec, immutable capture fields, and useful printer
   columns. No raw output, SQL text, arbitrary script, controller credential,
   or approval claim is accepted in the spec.
2. Add a focused reconciler in `mithril-control/src/observability/kubernetes.rs`
   using the existing Kubernetes client/watch patterns. Do not put it in the
   policy compiler. Handle relist, watch expiry and deleted namespace identity.
   Node expiry is independent of a functioning Kubernetes controller.
3. Require configured Control grants for the cluster/namespace UID, recipe
   digest, target kinds, duration and fan-out ceilings. Recipe names resolve
   only if the exact digest is allowed. No broad controller identity can
   substitute for the namespace grant. Node or cross-namespace targets reject.
   Record controller principal and source UID; user annotations are not identity.
4. Use `creationTimestamp` and a configured initial 60-second start window to
   reject stale requests before dispatch. Spec updates reject. A new capture
   requires a new object UID. Complete records remain complete after repeated
   apply. Store the request identity in Control before any effect.
5. Status contains observedGeneration, accepted spec digest, trace ID,
   per-target summary and conditions for admission, collection and cleanup.
   Output stays in Araphor under independent evidence-read grants. Deleting
   the CR does not erase retained audit/output. Existing retention applies.
6. Add narrowly scoped optional Helm RBAC and feature configuration. Disabled
   mode must preserve existing charts and node behavior. CLI requests must
   still work without Kubernetes and must not create CRs implicitly.

## Acceptance and verification

Pass `OBS-CRD`: denied namespace, digest mismatch, foreign target, namespace
recreation, stale object, immutable-spec update, repeated apply, lost status
write, controller restart between intent/dispatch/status, deletion during
attach, forced deletion, unavailable node, and watch relist. Verify one
execution identity through API, CLI resume, console, and CR status.

Add owner-level `observability_crd_` tests and a paired physical Kubernetes
case under the existing e2e harness. Lightweight cases run first. Verify CRD
schema and RBAC with `bash packaging/mithril/helm/tests/verify.sh`, then run
the full Rust CI gate after source changes. Do not mark deletion complete
solely because an API accepted a cancellation request.

### End-to-end deliverable

Add `trace-crd` to `crates/mithril-e2e/src/bin/mithril_observability_test.rs`.
Implement the case in the existing `src/observability.rs` module family.
Use the production
reconciler and TraceOwner with a Kubernetes API double for lightweight proof.
Repeat create/watch/status/delete events, lose the dispatch reply, restart
the reconciler, then force deletion. Require one execution identity, independent
read grants and local expiry. Run the same sequence through the existing
physical harness with actual Kubernetes resources. The result must retain
resource UID, spec digest, trace ID, execution count and cleanup result.

## Stop point

No continuous tracing policy, SQL CRD, script CRD, scheduling controller, or general Job
platform is included. Persistent instrumentation needs its own later scope.
