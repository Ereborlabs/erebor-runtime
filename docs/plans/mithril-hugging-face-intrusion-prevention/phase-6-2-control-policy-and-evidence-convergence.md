# Phase 6.2: Control Policy And Evidence Convergence

Status: Not done. Source implementation and automated acceptance for
D6.2.1-D6.2.12 passed on 2026-08-22 at code commit
`781ee425320ce75cd6b7bf786e06cb23f36b6b91`. The required physical Kubernetes
and stock-runtime acceptance has not run.

Master: [Mithril Hugging Face Intrusion Prevention](./README.md)

Design: [Validated readable architecture](./policy-and-protection-algorithm-architecture-readable.md)

Closure matrix: [Phase 6.2 closure matrix](./phase-6-2-closure-matrix.md)

Manual acceptance: [Phase 6.2 runbook](./manual-testing/phase-6-2-manual-acceptance.md)

Implementation review: [Phase 6.2 review guide](./phase-6-2-implementation-review.md)

Environment setup: [shared setup guide](./manual-testing/environment-setup.md)

## Purpose

Make Kubernetes custom resources the production desired-state source for
Mithril policy. Make `mithril-control` reconcile that source into immutable
signed candidates, distribute each candidate to the selected nodes, and move
the existing Phase 6 evidence intake into the production Control transaction.
Keep node activation and physical enforcement inside `mithril-node`. Give
Phase 7 one stable evidence and policy-provenance foundation on which it can
build the cross-node graph.

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
  -> typed mTLS NodePolicy delivery
  -> PolicyActivationOwner stage, readback, probes, and pointer CAS
  -> authenticated node acknowledgement and Control rollout inventory

Phase 6 node WAL and coverage
  -> typed mTLS NodeEvidence and NodeCoverage RPCs
  -> EvidenceIntakeOwner durable append and contiguous acknowledgement
  -> immutable accepted evidence for Phase 7 graph replay
```

The CRD stores desired state. It is not a signed node artifact, evidence
database, graph database, or activation acknowledgement store. A node does not
watch or parse the CRD. Control does not write BPF maps or change a node's
active-generation pointer.

## Intended Kubernetes Flow

```text
Operator configures where the mithril-node DaemonSet runs
  -> Control reads the live DaemonSet Pod template
  -> Control derives its node selector and required node affinity
  -> Control does not accept a separate Mithril node-pool selector

New or existing Node matches the derived DaemonSet constraints
  -> Node admission adds mithril.erebor.dev/not-ready:NoSchedule
  -> the mithril-node DaemonSet tolerates that quarantine taint
  -> mithril-node loads and verifies BPF state
  -> mithril-node registers its Kubernetes Node name over authenticated mTLS
  -> Control verifies the live Node, node session, boot, and readiness report
  -> Control adds the Mithril-ready label and removes the quarantine taint

Ready node loses its session, boot identity, BPF health, or DaemonSet eligibility
  -> Control removes the Mithril-ready label
  -> Control restores the quarantine taint
  -> the scheduler cannot place another protected Pod on that Node
  -> the last valid local generation continues to protect existing workloads

WorkloadProtectionProfile CREATE or UPDATE
  -> PolicyDesiredStateOwner reads the namespaced CRD
  -> Control validates, compiles, approves, and signs the policy revision
  -> Control records the immutable source revision
  -> no node receives a candidate until an exact scheduled workload selects it

Pod CREATE
  -> admission checks WorkloadProtectionProfiles in the Pod's namespace
  -> zero matching profiles leaves the Pod outside this protected scheduling flow
  -> more than one matching profile rejects the Pod as ambiguous
  -> one matching profile makes the Pod protected
  -> admission reads the current mithril-node DaemonSet constraints
  -> admission adds those constraints and the Mithril-ready label as required affinity
  -> admission does not select an exact Node
  -> admission rejects nodeName and quarantine-taint toleration bypasses
  -> the Kubernetes scheduler chooses one ready Node from the constrained set

Pod or ephemeral-container UPDATE
  -> validating admission preserves the admitted Mithril policy annotations
  -> an unprotected scheduled Pod cannot enter a protected profile through an update
  -> a protected Pod cannot leave or replace its admitted profile through an update
  -> a matching new container must keep the admitted selector and image-pin contract

Scheduler submits the Pod binding
  -> binding admission verifies the selected Node against the same live constraints
  -> binding admission verifies the current Mithril-ready node session and boot
  -> Kubernetes persists Pod UID plus spec.nodeName
  -> Control observes the persisted binding and immutable Pod identity facts
  -> PolicyRolloutOwner creates an exact target for that Pod and Node
  -> Control delivers the exact signed policy and binding material only to that Node
  -> the stock OCI prestart hook holds the exact initial container process
  -> mithril-node verifies the hook request against the scheduled Pod and runtime state
  -> mithril-node stages, reads back, probes, and activates the exact policy generation
  -> mithril-node publishes the exact cgroup binding while the initial process is held
  -> the runtime gate releases that process only after policy and binding activation

Pod changes Node, UID, container identity, or profile match
  -> the old target cannot authorize the changed workload
  -> Control creates a new immutable target and candidate when the new state is valid
  -> the runtime gate remains closed until the selected Node activates that target

Pod or container terminates
  -> mithril-node retires the exact cgroup binding after the runtime lifetime ends
  -> Control removes the exact target from the next rollout snapshot
  -> another Pod, container, Node, or boot cannot reuse the retired authority

WorkloadProtectionProfile deletion
  -> a Deleted event or a complete relist detects the missing object UID
  -> deletion uses the last accepted generation because Kubernetes does not increment generation
  -> Control enters RETIRING for every exact current target
  -> each selected Node receives a signed restrictive replacement
  -> removal completes through normal stage, readback, probe, and activation
  -> deletion or Control loss cannot erase the last valid local protection
```

The operator selects nodes only through the `mithril-node` DaemonSet Pod
template. The scheduler still selects the exact Node. Mithril adds requirements
that restrict the scheduler to the live, ready part of that derived set.

A `WorkloadProtectionProfile` match defines whether a Pod enters this protected
flow. Control does not use a separate protected-tenant or protected-namespace
scope setting. The configured tenant and cluster identities bind provenance;
they do not select Pods.

## Deliverables

### D6.2.1 — Closed Kubernetes policy API

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
result. Phase 6.2 and later results bind the amended architecture digest.

### D6.2.2 — Desired-state reconciliation and signing

Add one `PolicyDesiredStateOwner` to `mithril-control`. It alone may accept a
CRD revision and change the desired policy revision. It must use list/watch,
recover from compaction by relisting, deduplicate repeated events, reject stale
UID or generation state, and reconstruct the same desired revision after a
Control restart. A complete relist must retire each durable live source whose
object UID is absent from the API snapshot. A partial relist must not retire a
source.

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

### D6.2.3 — Immutable targeting and rollout ownership

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

### D6.2.4 — Secure node policy service

Add a `NodePolicy` service through the Phase 6.1 generated contract and
transport owner. Define bounded typed RPCs for candidate delivery, inventory,
acknowledgement, rejection, retirement, and reconnect.
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

### D6.2.5 — Durable Control evidence intake

Consume the final Phase 6 WAL/upload contract through the typed Phase 6.1
`NodeEvidence` and `NodeCoverage` services. Do not add an envelope, transport
version switch, or compatibility dispatcher. Do not invalidate Phase 6 source
identities, WAL records, or accepted test results.

Extend the one Phase 6 `EvidenceIntakeOwner` in `mithril-control`. Keep its
durable acknowledgement contract and move its accepted records and cursor
into the versioned transactional Control store. It authenticates bounded Phase
6 evidence batches and durably appends immutable
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

### D6.2.6 — Deletion, restart, and outage behavior

CRD deletion enters `RETIRING`. It does not tell a node to erase its active
generation. Control produces a signed monotonic retirement candidate that
names the exact current candidate and its approved replacement or restrictive
terminal state. A node applies retirement through the normal stage, readback,
probe, and activation path. If no valid successor is available, the last valid
local generation stays active.

Control does not require or update a CRD finalizer. Forced object deletion,
namespace deletion, API-server loss, or Control loss cannot remove a node's
active protection.

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

### D6.2.7 — Status, tenancy, and operational limits

Write bounded CRD status with `observedGeneration`, source and candidate
digests, aggregate rollout counts, and `Accepted`, `Compiled`, `Progressing`,
`Available`, `Degraded`, and `Retiring` conditions. Status is an informational
projection of Control-owned durable state. A status value cannot authorize a
candidate or activation. Keep per-node inventory in the Control store instead
of expanding CRD status without a bound.

Use least-privilege RBAC for cluster-wide CRD list/watch, status updates, the
exact `mithril-node` DaemonSet, and read-only namespace, Pod, ServiceAccount,
and Node facts. Grant Node patch because built-in RBAC cannot restrict a patch
to individual fields. The readiness owner changes only the Mithril readiness
projection and quarantine taint. Control has no policy-spec or finalizer write
authority. There is no configured protected-namespace list. Separate the
Control service account from operator write identities and from node identities
that receive policy. Reject cross-tenant acknowledgements and evidence. Expose
queue, storage, watch, compile, rollout, target, node, and evidence-cursor
health without policy source, evidence, or secret payloads in logs or metrics.

### D6.2.8 — End-to-end convergence proof

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

### D6.2.9 — DaemonSet-derived node eligibility and readiness

Extend the existing Control Kubernetes client. Read one configured
`mithril-node` DaemonSet identity and derive eligible-node constraints only
from its live Pod template. Copy no operator-owned selector into another
Mithril configuration field. Reject an unsupported DaemonSet constraint
instead of interpreting it approximately.

Add Node admission and reconciliation for the
`mithril.erebor.dev/not-ready:NoSchedule` quarantine taint. Only Nodes that
match the live DaemonSet constraints enter this flow. The DaemonSet tolerates
the taint. A matching node is not ready for protected scheduling until the
authenticated `mithril-node` session names that Kubernetes Node and proves the
current boot, BPF state, identity state, and policy-admission readiness.

Project this Control decision through a bounded Mithril-ready Node label and
taint removal. Remove the label and restore the taint after session expiry,
boot change, readiness loss, or DaemonSet constraint change. The label is a
scheduler projection. The authenticated Control session remains the
authority. Do not evict an existing protected Pod merely because a
`NoSchedule` taint is restored.

### D6.2.10 — Protected Pod and scheduler-binding admission

Serve Kubernetes admission from the existing `mithril-control` process. Do
not create another policy watcher or policy owner. On Pod create, resolve the
current namespaced `WorkloadProtectionProfile` selectors against the admitted
Pod. No match leaves the Pod outside this flow. More than one match is an
ambiguous authority error. Remove the configured namespace list as a
protection selector; watch the cluster for namespaced profiles, namespace
identity, and protected Pod lifecycle facts.

Reserve the Mithril profile and source annotations for admission. Reject a Pod
that supplies either annotation. Validate Pod and ephemeral-container updates
without changing the scheduler binding. An unprotected scheduled Pod cannot
enter a protected profile through an update. A protected Pod update must keep
the admitted annotations, selector match, and digest-pinned protected images.

For one match, add the live DaemonSet node selector, its required node
affinity, and the Mithril-ready label as scheduling requirements. Combine the
requirements with the Pod's existing constraints. Never write `spec.nodeName`
or choose a node. Reject direct `nodeName`, quarantine-taint toleration, and
selector or affinity forms that can bypass the derived requirements.

Validate the scheduler's `pods/binding` request against the current derived
node set, ready label, authenticated session, Node UID, and boot identity.
After Kubernetes persists `Pod.spec.nodeName`, watch the exact Pod UID and
container facts. Admission is not policy delivery and must not report a Pod as
protected before the node-local runtime gate completes.

### D6.2.11 — Binding-driven policy delivery and runtime-start gate

Replace registration-time static workload inventory as the Kubernetes
targeting authority. Store each persisted Pod binding as immutable desired
workload material. Bind cluster, namespace, controller, ServiceAccount, Pod,
container, image, selected Node, and current node-session identity. Reconcile
again when the bound workload inventory changes even if the policy source
revision did not change.

Include the exact desired workload material in the signed node candidate. The
node verifies it before it creates dynamic local binding configuration. A node
must reject material for another Node, boot, Pod, profile, or candidate. Keep
non-Kubernetes static workload bindings available for the existing host mode;
they cannot authorize a Kubernetes Pod that Control did not observe as bound.

Use the supported stock OCI prestart adapter as a stateless forwarding hook.
The adapter sends the exact container ID, held initial PID, OCI annotations,
and cgroup path to `mithril-node`. The node validates the root-owned endpoint,
live PID, cgroup membership, Pod UID, container name, image digest, selected
Node, candidate, and active generation. It then publishes the cgroup binding
and releases the runtime only after activation readback and probes succeed.
Timeout, mismatch, stale state, unavailable node service, or unavailable exact
candidate rejects the hook and keeps the runtime start fail-closed.

### D6.2.12 — Packaging and convergence proof

Package the admission Service, webhook configurations, TLS inputs, DaemonSet
taint toleration, Node identity input, Control permissions, health, and bounded
timeouts. RBAC can read the one DaemonSet and workload facts and can patch only
the Mithril-owned Node readiness projection. Node identities cannot modify
Kubernetes policy or Node readiness.

Prove DaemonSet selector and affinity derivation, selector change, new-node
quarantine, stale-session quarantine, Pod mutation, scheduler choice among two
eligible nodes, binding rejection, exact-node delivery, held prestart release,
timeout denial, restart recovery, Pod deletion, container restart, and policy
retirement. Use API-server admission review objects and deterministic runtime
gate tests in automated acceptance. Use the current stock Kubernetes and OCI
runtime path for the physical manual result.

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
- Create, update, duplicate event, stale UID, delete/recreate, forced object
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
- DaemonSet-derived selector and required-affinity tests, including an empty
  selector, unsupported affinity, selector change, node label change, and
  DaemonSet replacement.
- Node create mutation, quarantine reconciliation, readiness projection,
  authenticated node-name binding, boot change, stale session, and Control
  restart tests.
- Pod no-match, one-match, ambiguous-match, mutation composition, `nodeName`,
  toleration bypass, reserved annotation, bounded affinity, update and
  ephemeral-container bypass, scheduler binding, stale ready label, replaced
  Node UID, and wrong boot tests.
- Bound Pod inventory drift, same-policy new target, exact-node candidate,
  wrong-node rejection, Pod deletion, container restart, and name/UID reuse
  tests.
- OCI prestart valid release, missing candidate, invalid annotation, PID and
  cgroup mismatch, stale candidate, timeout, node restart, and fail-closed
  endpoint tests.
- Phase 6.2 owns no new Appendix C fixture ID. These named phase tests remain
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
- The live `mithril-node` DaemonSet is the sole node-pool definition. Mithril
  does not choose the scheduler's exact Node.
- A matching protected Pod cannot start its initial process until the selected
  node has activated its exact candidate and cgroup binding.

## Excluded

Graph edges, findings, detection packages, notification routing, provider
leases, response actuation, provider-specific evidence, privileged/unmatched
workload floors, and cross-node causal joins. Phase 7 owns the graph and
finding extension. Phase 8 consumes the Kubernetes object, scheduler, and
runtime facts established here for distributed causality and adds authenticated
audit history and the privileged/unmatched workload floor.

## Phase Result

```text
State: Not done. Source implementation and automated acceptance passed. The required physical Kubernetes and stock-runtime acceptance has not run.
Validated architecture revision/digest: 0c87aaf6c2d0347e06b53ce0ccb9f69577a9b248a4a90463082335d7865d77ae.
Completed deliverable IDs: D6.2.1-D6.2.12 are source-complete. D6.2.9-D6.2.12 do not have the required physical result.
Files and durable owners changed: WorkloadProtectionProfile CRD and Helm package; PolicyDesiredStateOwner; PolicyRolloutOwner; TrustBundleOwner; KubernetesNodeReadinessOwner; KubernetesAdmissionOwner; KubernetesWorkloadInventoryOwner; one append-only ControlStore for policy, trust, rollout, acknowledgement, evidence, coverage, and cursor transactions; generated NodePolicy and ControlHealth services; NodePolicyDeliveryOwner; RuntimeAdmissionClient; RuntimeAdmissionServer; ScheduledRuntimeBindingV1; the existing node activation and cgroup-binding paths; and the stateless OCI adapter. The BPF ABI and BPF programs did not change.
Upstream-adoption dossier IDs used: none.
Fixture cases and exact physical results: no new Appendix C fixture or physical result. The deterministic two-node Control tests passed. The physical two-node manual run was not run.
Commands and exact source state covered: `bash .github/scripts/verify-rust-ci.sh` passed the repository format, check, clippy, and full workspace test gate at code commit 781ee425320ce75cd6b7bf786e06cb23f36b6b91. The first review gate exposed test-only strict-Clippy failures. The test was corrected, and the complete gate passed. The final gate included 63 mithril-control unit tests, 5 Kubernetes API tests, 70 mithril-e2e unit tests, 129 mithril-node unit tests, 2 OCI adapter tests, and 5 mTLS integration tests. An earlier complete gate had one transient browser discovery test failure with `WouldBlock`; the isolated test and the next complete gate passed. `bash packaging/mithril/helm/tests/verify.sh` passed chart lint and the rendered packaging contract for the reviewed source.
Platform/kernel/runtime manifests: the Helm package contains the generated closed CRD, Control RBAC, the exact DaemonSet reader Role, the Control Deployment and Service, fail-closed admission webhooks, the node DaemonSet, and the OCI hook installation. No BPF program or kernel ABI changed. No live platform manifest was recorded.
Performance/capacity results: no new benchmark. Evidence gRPC messages are limited to 4 MiB. Policy gRPC messages are limited to 128 KiB. The pending evidence window is limited to 4,096 records. Health reports fixed counts and booleans only.
Unsupported/degraded paths: no live Kubernetes API-server, RBAC denial, watch-compaction, network-partition, storage-outage, stock-runtime ordering, or physical two-node result was recorded. Phase 7 graph and finding behavior is not present.
Remaining work in this phase: run the documented physical acceptance on the target Kubernetes and stock OCI runtime versions, retain its evidence, and record a `Pass` or `Fail` result. The prior optional physical D6.2.1-D6.2.8 run was not completed.
Next phase not authorized: yes.
```
