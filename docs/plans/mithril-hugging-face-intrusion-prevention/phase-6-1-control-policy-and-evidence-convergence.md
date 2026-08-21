# Phase 6.1: Control Policy And Evidence Convergence

Status: Proposed; depends on Phase 6 `Done`.

Master: [Mithril Hugging Face Intrusion Prevention](./README.md)

Design: [Validated readable architecture](./policy-and-protection-algorithm-architecture-readable.md)

Manual acceptance: [Phase 6.1 runbook](./manual-testing/phase-6-1-manual-acceptance.md)

Environment setup: [shared setup guide](./manual-testing/environment-setup.md)

## Purpose

Make Kubernetes custom resources the production desired-state source for
Mithril policy. Make `mithril-control` reconcile that source into immutable
signed candidates, distribute each candidate to the selected nodes, and
durably accept Phase 6 evidence. Keep node activation and physical enforcement
inside `mithril-node`. Give Phase 7 one stable evidence and policy-provenance
foundation on which it can build the cross-node graph.

## Scope And Design Coverage

Chapters 5, 11-12, 22, 30, 32, and 34-37; Appendices A.8.1, A.11, and
A.15.1.

## Fixed Ownership And Data Flow

```text
WorkloadProtectionProfile CRD desired revision
  -> PolicyDesiredStateOwner in mithril-control
  -> closed PolicyDocumentV1
  -> PolicyCompiler validation, simulation, approval, and signature
  -> immutable rollout snapshot and signed node candidate
  -> mTLS Control-to-node delivery
  -> PolicyActivationOwner stage, readback, probes, and pointer CAS
  -> authenticated node acknowledgement and Control rollout inventory

Phase 6 node WAL and coverage
  -> mTLS evidence batch
  -> EvidenceIntakeOwner durable append and contiguous acknowledgement
  -> immutable accepted evidence for Phase 7 graph replay
```

The CRD stores desired state. It is not a signed node artifact, evidence
database, graph database, or activation acknowledgement store. A node does not
watch or parse the CRD. Control does not write BPF maps or change a node's
active-generation pointer.

## Deliverables

### D6.1.1 — Closed Kubernetes policy API

Add the namespaced `WorkloadProtectionProfile.mithril.erebor.dev` CRD with a
served `v1alpha1` version, a structural OpenAPI schema, size and count bounds,
and status and scale limits. The stored `.spec` is the production source in
Kubernetes mode. It maps exactly to the existing closed `PolicyDocumentV1`.
Use group `mithril.erebor.dev`, plural `workloadprotectionprofiles`, kind
`WorkloadProtectionProfile`, namespaced scope, and one declared storage
version.
Require strict API field validation on the supported write path. Unknown fields
must not reach stored state or a candidate. An API-server/client combination
that silently prunes unknown input is unsupported for the exact-source claim.
Duplicate semantic IDs, unsupported enums, invalid bounds, and lossy
conversions must reject before compilation.

Keep the restricted YAML source from Appendix A.11 for offline review, tests,
and import. Offline YAML cannot activate production Kubernetes policy. Add
goldens that prove one CRD `.spec` and its offline source normalize to the same
canonical `PolicyDocumentV1` bytes.

Record one immutable `PolicySourceRevisionV1` for each accepted desired
revision. It binds tenant and cluster identity, CRD UID, namespace, name,
generation, canonical spec digest, observed Kubernetes resource version, and
deletion state. Kubernetes `resourceVersion` is an opaque watch cursor. It is
not a policy version, signature sequence, or authority value. Derive tenant,
cluster, namespace UID, and object UID from authenticated Control configuration
and API-server records. A CRD field, label, annotation, or status cannot select
its own tenant.

Treat the CRD, source-revision, rollout, candidate, acknowledgement, evidence
batch, and intake-receipt types as an additive architecture amendment. Update
the exact-type closure and canonical goldens, and rerun the affected Phase 0
schema checks. Do not change the frozen BPF ABI or rewrite a historical phase
result. Phase 6.1 and later results bind the amended architecture digest.

### D6.1.2 — Desired-state reconciliation and signing

Add one `PolicyDesiredStateOwner` to `mithril-control`. It alone may accept a
CRD revision and change the desired policy revision. It must use list/watch,
recover from compaction by relisting, deduplicate repeated events, reject stale
UID or generation state, and reconstruct the same desired revision after a
Control restart.

Require one live CRD owner for each `(tenant, trust domain, profile ID)` and
one active `WorkloadProtectionProfile` for each exact workload binding in
Version 1. If two CRDs claim the same profile ID or select the same exact
workload, report a conflict and do not activate the conflicting revision. Do
not use namespace/name, creation time, YAML order, priority, or “deny wins” to
choose a profile. Keep the previous valid non-conflicting generation active.

Run every accepted revision through the existing `PolicyCompiler`. Preserve
closed-schema validation, capability checks, deterministic compilation,
legitimate-workload simulation, required approval, registry binding,
signature, anti-rollback, and rollback authorization. A successful Kubernetes
write is desired-state input. It is not proof that compilation, approval,
rollout, or activation succeeded.

The API server's accepted object under configured RBAC and any approval
required by `RolloutV1` are recorded separately. A watch event does not prove
which human made the change. Bind any required human approval to the exact
source revision through the existing authenticated approval record. The
Control signing key proves artifact authenticity. It does not invent a human
approval.

Operate the `TrustBundleOwner` for policy signer rotation, revocation,
node-cache distribution, issuer sequence, and anti-rollback state. A node must
receive and verify an applicable trust generation before it can accept a
candidate signed by a new key. Revocation and key rotation cannot make an old
or partially delivered candidate current. Keep the policy-issuer sequence and
the target-bound candidate-distribution sequence as separate replay domains.

### D6.1.3 — Immutable targeting and rollout ownership

Add one `PolicyRolloutOwner` to `mithril-control`. It alone may create the
immutable target snapshot, assign the desired signed candidate to a node, and
change the Control rollout inventory. Resolve selectors against exact cluster,
namespace, controller, Pod, container, image, and node facts. Bind the source
revision, policy digest, signed candidate digest, rollout snapshot digest, and
target identity.

There is no cluster-wide atomic BPF update. Each node activates independently.
Control reports `PENDING`, `DELIVERED`, `STAGED`, `ACTIVE`, `REJECTED`,
`STALE`, or `UNKNOWN` for each target and applies the signed rollout stop
conditions. A mixed-generation rollout is visible and limits policy and
finding claims. It never appears as globally active.

### D6.1.4 — Secure node policy protocol

Extend the Phase 1 mTLS protocol with bounded, versioned messages for candidate
delivery, inventory, acknowledgement, rejection, retirement, and reconnect.
Control sends immutable signed candidates together with the referenced signed
profile, registry, and static compilation artifacts. Use content-addressed,
bounded, resumable chunks when the complete bundle exceeds one message. A node
may reuse an already durable artifact only after exact digest readback. The
node verifies tenant, trust, signature, every artifact digest, source and
candidate digests, policy-issuer sequence, candidate-distribution sequence,
target, expiry, capabilities, and anti-rollback state before staging. Partial
transfer cannot create a stageable candidate.

Only `PolicyActivationOwner` may build the inactive node generation, read back
the complete state, run the controlled probes, and publish the active pointer
with one compare-and-swap. The acknowledgement binds node identity, boot and
label epochs, source revision, candidate digest, node-bound generation digest,
node-local profile-generation reference, activation state, readback digest,
and rejection reason. A delayed acknowledgement from an old boot, target
snapshot, or candidate cannot advance the current rollout.

### D6.1.5 — Durable Control evidence intake

Consume the final Phase 6 WAL/upload protocol as the node-side source
contract. If Phase 6 closes with an earlier negotiated wire version, add a
bounded compatibility adapter or version negotiation in Control. Do not
invalidate Phase 6 source identities, WAL records, or accepted test results.

Add one `EvidenceIntakeOwner` to `mithril-control`. It authenticates bounded
Phase 6 evidence batches and durably appends immutable
`ObservationEnvelopeV1` and `CoverageIntervalV1` records by tenant, node,
boot, label epoch, source, source epoch, and sequence. A source epoch cannot
cross a label-epoch change. It rejects conflicting duplicates, invalid digests,
wrong tenant or node identity, unsupported schemas, and impossible sequence
transitions.

Control returns a contiguous acknowledgement only after the accepted records
and source cursor are in one durable commit. Duplicate delivery is idempotent.
Out-of-order delivery remains pending within a bounded window. Backpressure or
storage failure withholds the acknowledgement. The node truncates its WAL only
through the durable contiguous acknowledgement.

The intake owner does not rewrite source observations, close an unknown
coverage interval as healthy, build graph edges, or create findings. Phase 7
consumes only the immutable accepted records and intake cursors. Retain every
acknowledged record until Phase 7 installs and proves its declared retention,
reference, and consumer-watermark rules. An intake acknowledgement cannot make
Control's sole durable copy immediately eligible for deletion.

### D6.1.6 — Deletion, restart, and outage behavior

CRD deletion enters `RETIRING`. It does not tell a node to erase its active
generation. Control produces a signed monotonic retirement candidate that
names the exact current candidate and its approved replacement or restrictive
terminal state. A node applies retirement through the normal stage, readback,
probe, and activation path. If no valid successor is available, the last valid
local generation stays active.

A finalizer may report Control-owned retirement progress. It is not node
authority. Removing the finalizer, deleting the namespace, losing the API
server, or losing Control cannot remove a node's active protection.

After a Control restart, relist, watch compaction, node reconnect, or network
partition, reconcile from the durable source, rollout, intake, and node
inventory records. Never trust watch delivery order or an in-memory cursor.
Use one versioned transactional Control store for source revisions, compiler
results, approvals, target snapshots, candidates, rollout transitions, node
acknowledgements, accepted evidence, and intake cursors. Use compare-and-swap
for mutable transitions. A failed or incompatible schema migration blocks the
affected writer and keeps local node policy unchanged.

The initial implementation has one logical writer for each new durable owner.
Phase 11 qualifies leader election, failover, backup, restore, and upgrade for
the advertised production mode.

### D6.1.7 — Status, tenancy, and operational limits

Write bounded CRD status with `observedGeneration`, source and candidate
digests, aggregate rollout counts, and `Accepted`, `Compiled`, `Progressing`,
`Available`, `Degraded`, and `Retiring` conditions. Status is an informational
projection of Control-owned durable state. A status value cannot authorize a
candidate or activation. Keep per-node inventory in the Control store instead
of expanding CRD status without a bound.

Use least-privilege RBAC for CRD list/watch, status and finalizer updates, and
read-only access to the namespace, workload, Pod, controller, and node fields
needed for target resolution. Limit the Control watch to configured tenant
namespaces. Separate the Control service account from operator write identities
and from node identities that receive policy. Reject cross-tenant selectors,
acknowledgements, evidence, and status updates. Expose queue, storage, watch,
compile, rollout, target, node, and evidence-cursor health without policy
source, evidence, or secret payloads in logs or metrics.

### D6.1.8 — End-to-end convergence proof

Create, update, roll back, delete, and recreate one profile while two selected
nodes disconnect, reconnect, restart, and reject selected candidates. Prove
that each accepted CRD revision has one canonical source digest, each active
node generation has an unbroken provenance chain, stale messages cannot win,
and an invalid or unavailable update leaves the previous valid generation
active.

Upload Phase 6 evidence through duplicate, delayed, out-of-order, restart,
backpressure, and storage-failure variants. Prove that a node deletes no WAL
record before a durable contiguous Control acknowledgement and that the
accepted record set is stable input for Phase 7 replay.

## Checkpoint

An operator changes one `WorkloadProtectionProfile`. Control deterministically
compiles and signs the desired revision, distributes it to the exact rollout
snapshot, and reports the real per-node activation state. Nodes keep sole
ownership of physical activation. Control durably accepts replayable Phase 6
evidence. No graph or finding is created in this phase.

## Required Tests

- CRD structural schema, strict field validation, silent-prune rejection,
  version, conversion, unknown-field, size, count, namespace, tenant, and RBAC
  tests.
- CRD-to-`PolicyDocumentV1` golden equality and deterministic compile/sign
  tests.
- Create, update, duplicate event, stale UID, delete/recreate, finalizer
  removal, duplicate profile ID, overlapping selector, watch close,
  compaction/relist, and Control restart tests.
- Compile, simulation, approval, signature, rollback, trust rotation, and
  invalid-update retention tests.
- Target snapshot drift, partial rollout, mixed generation, stop condition,
  partial artifact transfer/resume, stale acknowledgement, node reboot,
  reconnect, and capability rejection tests.
- Inactive generation, complete readback, controlled probes, one pointer CAS,
  retained-old-generation, and no-Control-to-BPF-write tests.
- Evidence duplicate, conflicting duplicate, gap, reordering, bounded window,
  label-epoch/source-epoch transition, backpressure, durable acknowledgement,
  restart, and WAL truncation tests.
- CRD status projection, bounded inventory, tenant isolation, secret
  filtering, and status-is-not-authority tests.
- Phase 6.1 owns no new Appendix C fixture ID. These named phase tests remain
  mandatory and Phase 11 must run them for each advertised Kubernetes mode.

## Acceptance

- The CRD is the sole production desired-state policy source in Kubernetes
  mode, and both supported source forms produce the same canonical policy.
- Control is the sole desired-state, rollout, and evidence-intake owner.
- A node is the sole owner of its active generation and BPF state.
- A failed, stale, partial, deleted, or unavailable update cannot silently
  remove the last valid protection.
- Durable intake acknowledgement is the only authority for node WAL
  truncation.
- Phase 7 receives immutable evidence and exact policy provenance without
  creating a second Kubernetes policy watcher or evidence writer.

## Excluded

Graph edges, findings, detection packages, notification routing, provider
leases, response actuation, and provider-specific evidence. Phase 7 owns the
graph and finding extension. Phase 8 adds Kubernetes audit, object, scheduler,
and runtime facts for distributed causality.

## Phase Result

```text
State: Not done.
Validated architecture revision/digest: not recorded.
Completed deliverable IDs: none.
Files and durable owners changed: none.
Upstream-adoption dossier IDs used: none.
Fixture cases and exact physical results: not run.
Commands and exact source state covered: none; this is a plan-only addition.
Platform/kernel/runtime manifests: none.
Performance/capacity results: none.
Unsupported/degraded paths: not yet measured.
Remaining work in this phase: all deliverables.
Next phase not authorized: yes.
```
