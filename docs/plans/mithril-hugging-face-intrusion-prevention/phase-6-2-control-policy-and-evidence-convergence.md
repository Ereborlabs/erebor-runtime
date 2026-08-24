# Phase 6.2: Control Policy And Evidence Convergence

Status: Not done. The branch implements the approved capability-grounded
`WorkloadProtectionPolicy` and separate `WorkloadProtectionException`, their
Control and node lifecycles, Helm package, automated fixture, and independent
manual example. The current source has not passed the complete physical
procedure. The earlier physical run used the superseded API and stopped after
stock `runc` used an anonymous file write and IPC access that have no typed
authority. The internal `RuntimeBootstrap` flow is approved below but is not
implemented yet.

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
WorkloadProtectionPolicy CRD base revision
  -> PolicyDesiredStateOwner in mithril-control
  -> capability-grounded validation and public-to-internal lowering
  -> internal closed PolicyDocumentV1
  -> PolicyCompiler validation, simulation, approval, and signature
  -> immutable rollout snapshot and signed node candidate
  -> typed mTLS NodePolicy delivery
  -> PolicyActivationOwner stage, readback, probes, and pointer CAS
  -> authenticated node acknowledgement and Control rollout inventory

WorkloadProtectionException CRD bounded request
  -> PolicyDesiredStateOwner validates the same-namespace base-policy grant and bounds
  -> PolicyRolloutOwner resolves the active base generation and exact target
  -> signed target-bound exception activation or revocation candidate
  -> ExceptionAuthorityOwner durable state and receipt recovery
  -> BPF effect gate atomic use consumption

Phase 6 node WAL and coverage
  -> typed mTLS NodeEvidence and NodeCoverage RPCs
  -> EvidenceIntakeOwner durable append and contiguous acknowledgement
  -> immutable accepted evidence for Phase 7 graph replay
```

The CRDs store desired state. They are not signed node artifacts, evidence
database, graph database, or activation acknowledgement store. A node does not
watch or parse the CRDs. Control does not write BPF maps or change a node's
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

Ready Node loses its session or BPF health
  -> Control removes the Mithril-ready label
  -> Control restores the quarantine taint
  -> the scheduler cannot place another protected Pod on that Node
  -> the last valid local generation continues to protect existing workloads

Node no longer matches the live DaemonSet constraints
  -> Control removes the Mithril-ready label
  -> Control removes the Mithril quarantine taint because the Node is outside the managed set
  -> admission no longer includes that Node in the derived protected scheduling set
  -> existing local authority is not erased by the selector change

Node becomes eligible again
  -> Control adds the quarantine taint before the node session becomes ready
  -> the DaemonSet starts mithril-node through its quarantine toleration
  -> the current exact node session must report complete readiness
  -> Control removes quarantine only after that report

Kubernetes replaces a Node object with the same name and a new UID
  -> Control clears the old readiness projection
  -> the new Node remains quarantined until Control binds its exact UID
  -> the physical policy chain keeps its live predecessor
  -> Control sends an exact REPLACE candidate that binds the new Node UID

Host reboots and its label epoch increases
  -> mithril-node opens the kernel owner before it registers
  -> mithril-node proves that old policy and exception authority is absent
  -> Control records the higher physical epoch and stales old-session rollouts
  -> old-epoch delivery and acknowledgements reject
  -> Control signs a higher-sequence root candidate for the new physical epoch

WorkloadProtectionPolicy CREATE or UPDATE
  -> PolicyDesiredStateOwner reads the namespaced CRD
  -> Control validates the Kubernetes-facing fields
  -> Control derives Kubernetes identity, capability, proof, and rollout facts
  -> Control lowers the resource to the internal closed policy document
  -> Control compiles, approves, and signs the base-policy revision
  -> Control records the immutable source revision
  -> no node receives a candidate until an exact scheduled workload selects it

Pod CREATE
  -> admission checks WorkloadProtectionPolicies in the Pod's namespace
  -> zero matching policies leaves the Pod outside this protected scheduling flow
  -> more than one matching policy rejects the Pod as ambiguous
  -> one matching policy makes the Pod protected
  -> admission reads the current mithril-node DaemonSet constraints
  -> admission adds those constraints and the Mithril-ready label as required affinity
  -> admission does not select an exact Node
  -> admission rejects nodeName and quarantine-taint toleration bypasses
  -> the Kubernetes scheduler chooses one ready Node from the constrained set

Pod or ephemeral-container UPDATE
  -> validating admission preserves the admitted Mithril policy annotations
  -> an unprotected scheduled Pod cannot enter a protected policy through an update
  -> a protected Pod cannot leave or replace its admitted policy through an update
  -> a matching new container must keep the admitted selector and image-pin contract

Scheduler submits the Pod binding
  -> binding admission verifies the selected Node against the same live constraints
  -> binding admission verifies the current Mithril-ready node session and boot
  -> Kubernetes persists Pod UID plus spec.nodeName
  -> Control observes the persisted binding and immutable Pod identity facts
  -> PolicyRolloutOwner creates an exact target for that Pod and Node
  -> Control delivers the exact signed policy and binding material only to that Node
  -> NRI injects Mithril createContainer and prestart hooks
  -> createContainer stages immutable container, cgroup, image, and Pod facts
  -> createContainer grants no runtime authority
  -> the stock OCI prestart hook holds the exact initial container process
  -> mithril-node verifies CRI Created state and the staged immutable facts
  -> mithril-node verifies the scheduled Pod binding and active signed policy
  -> mithril-node stages, reads back, probes, and activates the exact policy generation
  -> mithril-node publishes the exact cgroup binding and RuntimeBootstrap identity
  -> the runtime gate releases that process only after policy and binding readback
  -> BPF limits RuntimeBootstrap to the exact initial entry and owned anonymous objects
  -> BPF permits only the fixed stock-runtime bootstrap operation classes
  -> a fixed monotonic deadline closes unused bootstrap authority
  -> the first policy-approved application exec atomically consumes RuntimeBootstrap
  -> application effects use only normal policy and exception authority

WorkloadProtectionException CREATE for the running Pod
  -> the API server authenticates and authorizes an exception writer
  -> PolicyDesiredStateOwner validates the same-namespace policy and grant
  -> Control requires the exact live Pod UID and matching container name
  -> Control bounds duration and uses to the named file grant
  -> PolicyRolloutOwner resolves the exact role, cells, base generation, Node, and boot
  -> PolicyRolloutOwner signs a candidate only for the scheduler-selected node
  -> ExceptionAuthorityOwner activates it without migrating the base generation
  -> the BPF effect gate consumes uses atomically
  -> the node reports use, expiry, or revocation

Pod changes Node, UID, container identity, or policy match
  -> the old target cannot authorize the changed workload
  -> Control creates a new immutable target and candidate when the new state is valid
  -> the runtime gate remains closed until the selected Node activates that target

Pod or container terminates
  -> mithril-node retires the exact cgroup binding after the runtime lifetime ends
  -> Control removes the exact target from the next desired snapshot
  -> Control sends a restrictive terminal candidate to each removed node-profile target
  -> the node activates and acknowledges the exact terminal candidate
  -> Control authorizes cleanup only when no viable successor depends on the terminal
  -> the node durably records the authorization and removes the closed local chain
  -> another Pod, container, Node, or boot cannot reuse the retired authority

WorkloadProtectionException target disappears or the request deletes
  -> Control sends a signed revocation for the exact exception instance
  -> ExceptionAuthorityOwner closes it without changing the base generation
  -> target disappearance keeps the accepted source but makes it terminal
  -> no result can reset a consumed-use counter or widen the base policy

WorkloadProtectionException expires or consumes its uses
  -> the BPF effect gate applies the signed deadline and use bound
  -> ExceptionAuthorityOwner records the exact terminal result
  -> the node reports the terminal result without a new authority grant
  -> no result can reset a consumed-use counter or widen the base policy

WorkloadProtectionPolicy deletion
  -> a Deleted event or a complete relist detects the missing object UID
  -> deletion uses the last accepted generation because Kubernetes does not increment generation
  -> Control enters RETIRING for every exact current target
  -> each selected Node receives a signed restrictive replacement
  -> removal completes through normal stage, readback, probe, and activation
  -> terminal acknowledgement and dependency checks close the candidate chain
  -> a recreated policy UID starts with a higher-sequence root candidate
  -> deletion or Control loss cannot erase the last valid local protection
```

The operator selects nodes only through the `mithril-node` DaemonSet Pod
template. The scheduler still selects the exact Node. Mithril adds requirements
that restrict the scheduler to the live, ready part of that derived set.

A `WorkloadProtectionPolicy` match defines whether a Pod enters this protected
flow. Control does not use a separate protected-tenant or protected-namespace
scope setting. The configured tenant and cluster identities bind provenance;
they do not select Pods.

## Deliverables

### D6.2.1 — Closed Kubernetes policy APIs

Replace the flattened CRD with the namespaced
`WorkloadProtectionPolicy.mithril.erebor.dev` CRD. Use group
`mithril.erebor.dev`, plural `workloadprotectionpolicies`, kind
`WorkloadProtectionPolicy`, served version `v1alpha1`, namespaced scope, and
one declared storage version. Its structural `.spec` contains only:

- one standard `podSelector`;
- `mode: Observe | Protect`;
- container matches by name, kind, digest-pinned immutable image reference,
  initial role, and conservative external-runtime role;
- named roles with canonical-path file rules, execution rules, explicit-address
  network rules, process-control rules, and Unix-stream role relationships; and
- named bounded `exceptionGrants` that refer only to named file rules.

Every Pod container must match exactly one container entry. Reject an unmatched
or multiply matched container. Control derives cluster, namespace,
ServiceAccount, controller, Pod UID, container, selected Node, node UID, and
boot facts from Kubernetes. None of these derived facts is a user selector.

File and execution rules support non-recursive allow or deny and recursive
deny. Reject recursive allow until the legitimate Kubernetes runtime control
is physically qualified. The supported operations are `OpenRead`,
`OpenWrite`, `Read`, `Write`, `MmapRead`, `MmapWrite`, `Execute`,
`MmapExecute`, `Mprotect`, `Create`, `SetAttributes`, `Unlink`, `Link`, and
`Rename` in their applicable rule family.

Network rules support IPv4 and IPv6 prefixes, TCP and UDP, port ranges,
final-address enforcement, and the qualified socket operations. Separate
address-free socket controls from destination rules. Unix-stream rules express
one role-to-role relationship for connect, send, and receive. Unmatched
Unix-stream relationships deny. Process-control rules support exact signal
numbers, including signal zero, against one exact target role and exact ptrace
denial. Positive general ptrace authority is not part of the API.

Add the namespaced `WorkloadProtectionException.mithril.erebor.dev` CRD. Use
plural `workloadprotectionexceptions`, kind `WorkloadProtectionException`, and
the same served and storage version. Its immutable `.spec` contains one local
policy reference, one named exception grant, one exact Pod name and UID, one
container name, one requested duration, and one requested use count. The
requested duration and use count cannot exceed the base grant. The resource
cannot contain an approval proof, compiled key, policy digest, node target, or
authority delta.

Lower each public `exceptionGrants` entry to one closed internal
`FileExceptionGrantTemplateV1` in the signed base policy. It binds the named
denied file rules and maximum duration and uses, but no Pod, node, active
instance, approver, or compiled key. Binding-time compilation creates the
conditional cells and generation-local handle. A
`WorkloadProtectionException` creates the exact runtime instance separately.

Use standard Kubernetes conditions with `observedGeneration`. Keep policy
status to bounded `desired`, `active`, `updating`, and `failed` rollout counts.
Keep exception status to `Pending`, `Active`, `Consumed`, `Expired`,
`Revoked`, or `Failed`. Do not put source digests, candidate digests,
signatures, per-node maps, receipts, or approval material in CRD status.

Require strict API field validation on both write paths. Unknown fields must
not reach stored state or a candidate. Reject duplicate names, unsupported
enums, invalid bounds, lossy conversions, invalid cross-references, and any
field outside the capability-grounded API before compilation.

Keep a restricted YAML form of the `WorkloadProtectionPolicy.spec` schema for
offline review, tests, and import. Offline YAML cannot activate production
Kubernetes policy. Add goldens that prove the stored CRD spec and offline form
produce the same internal policy for the same semantic input. Do not expose or
accept `PolicyDocumentV1` as the Kubernetes or offline operator schema.

Record one immutable source revision for each accepted policy or exception
object generation. It binds source kind, tenant and cluster identity, CRD UID,
namespace, name, generation, canonical spec digest, observed Kubernetes
resource version, and deletion state. A policy source revision binds its
internal policy digest. An exception source revision binds one separately
signed activation or revocation record; it does not change the base policy
document. Kubernetes `resourceVersion` is an opaque watch cursor. It is not a
policy version, signature sequence, or authority value. Derive tenant, cluster,
namespace UID, and object UID from authenticated Control configuration and
API-server records. A CRD field, label, annotation, or status cannot select its
own tenant.

Treat both CRDs, source revisions, policy rollout, policy candidate, exception
candidate, acknowledgement, evidence batch, and intake-receipt types as an additive
architecture amendment. Update the exact-type closure and canonical goldens,
and rerun the affected Phase 0 schema checks. The separately approved
`RuntimeBootstrap` transition is the only BPF ABI amendment in this phase. Do
not rewrite a historical phase result. Phase 6.2 and later results bind the
amended architecture and ABI digest.

### D6.2.2 — Desired-state reconciliation and signing

Add one `PolicyDesiredStateOwner` to `mithril-control`. It alone may accept a
policy or exception CRD revision and change policy or exception desired state.
It must use list/watch, recover from compaction by relisting, deduplicate
repeated events, reject stale UID or generation state, and reconstruct the
same desired revision after a Control restart. A complete relist must retire
each durable live source whose object UID is absent from the API snapshot. A
partial relist must not retire a source.

Require no more than one matching `WorkloadProtectionPolicy` for a Pod. If two
policies select the same Pod, report a conflict and do not activate either
conflicting revision for that Pod. Do not use name, creation time, YAML order,
priority, or “deny wins” to choose a policy. Keep the previous valid
non-conflicting generation active for existing targets.

Reconcile an exception only when its authorized stored source, policy, grant,
Pod UID, container, role, named file rule, requested duration, and requested
uses all match. Use separate exception-writer RBAC from base-policy writers.
The persisted API object proves accepted desired state under that RBAC; it does
not prove which human made the request. The CRD request is not a compiled
exception. The bound base-policy generation already contains the eligible
grant cells in an inactive state. `PolicyDesiredStateOwner` accepts the bounded
request. `PolicyRolloutOwner` derives the exact instance and target and signs
the activation candidate. Reject overlapping live exception instances for the
same grant and exact container.

Lower every accepted base policy into the existing internal
`PolicyDocumentV1`, including inactive cells for its named exception grants,
then run that policy through the existing `PolicyCompiler`. Preserve
closed-schema validation, capability checks, deterministic compilation,
legitimate-workload simulation, required approval, registry binding,
signature, anti-rollback, and rollback authorization. A successful Kubernetes
write is desired-state input. It is not proof that compilation, approval,
rollout, or activation succeeded.

The API server's accepted object under configured RBAC and any approval
required by the internal rollout are recorded separately. A watch event does
not prove which human made the change. Bind any required base-policy approval
to the exact policy source revision and any required exception approval to the
exact exception source, base-policy generation, grant, and target. The Control
signing key proves artifact authenticity. It does not invent a human approval.

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
namespace, controller, Pod, container, image, and node facts. Bind the base
policy source revision, internal policy digest, signed candidate digest,
rollout snapshot digest, and target identity. An exception uses a separate
target-bound candidate and does not alter the policy rollout snapshot.
`PolicyRolloutOwner` binds the exception source, active base-policy generation,
grant cells, Pod UID, container, selected Node, boot, duration, uses,
predecessor, and distribution sequence.

There is no cluster-wide atomic BPF update. Each node activates independently.
Control reports `PENDING`, `DELIVERED`, `STAGED`, `ACTIVE`, `REJECTED`,
`STALE`, or `UNKNOWN` for each target and applies the signed rollout stop
conditions. A mixed-generation rollout is visible and limits policy and
finding claims. It never appears as globally active.

### D6.2.4 — Secure node policy service

Add a `NodePolicy` service through the Phase 6.1 generated contract and
transport owner. Define bounded typed RPCs for candidate delivery, inventory,
acknowledgement, rejection, retirement, bounded exception activation,
exception revocation, exception receipt synchronization, and reconnect.
Control sends immutable signed candidates together with the referenced signed
profile, registry, and static compilation artifacts. Use content-addressed,
bounded, resumable chunks when the complete bundle exceeds one message. A node
may reuse an already durable artifact only after exact digest readback. The
node verifies tenant, trust, signature, every artifact digest, policy source
revision and candidate digests, policy-issuer sequence,
candidate-distribution sequence, target, expiry, capabilities, and
anti-rollback state before staging. Partial transfer cannot create a stageable
candidate.

Only `PolicyActivationOwner` may build the inactive node generation, read back
the complete state, run the controlled probes, and publish the active pointer
with one compare-and-swap. The acknowledgement binds node identity, boot and
label epochs, policy source revision, candidate digest, node-bound generation
digest, node-local profile-generation reference, activation state, readback
digest, and rejection reason. A delayed acknowledgement from an old boot,
target snapshot, or candidate cannot advance the current rollout.

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

Policy deletion enters `RETIRING`. It does not tell a node to erase its active
generation. Control produces a signed restrictive-terminal candidate that
names the exact viable predecessor. A node applies retirement through the
normal stage, readback, probe, and activation path. Control can authorize
local chain cleanup only after the terminal is active and no viable successor
depends on it. Until then, the last valid local generation stays active.

Exception deletion, target disappearance, or explicit revocation closes the
exact runtime instance through a signed revocation candidate. Expiry and
exhaustion become terminal through the signed deadline and use bound already
installed on the node. Control and the node preserve the consumed-use record.
The base policy generation does not change. A stale exception event or
recreated object cannot restore the old instance.

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

Write bounded policy status with `observedGeneration`, standard conditions,
and aggregate `desired`, `active`, `updating`, and `failed` rollout counts.
Write bounded exception status with `observedGeneration`, standard conditions,
and its current bounded state. Status is an informational projection of
Control-owned durable state. A status value cannot authorize a candidate,
exception, or activation. Keep source and candidate digests, signatures,
receipts, counters, and per-node inventory in the Control store.

Use least-privilege RBAC for cluster-wide policy and exception list/watch,
status updates, the exact `mithril-node` DaemonSet, and read-only namespace,
Pod, ServiceAccount,
and Node facts. Grant Node patch because built-in RBAC cannot restrict a patch
to individual fields. The readiness owner changes only the Mithril readiness
projection and quarantine taint. Control has no policy-spec or finalizer write
authority. There is no configured protected-namespace list. Separate the
base-policy writer, exception writer, Control service account, and node
identities that receive policy. A base-policy writer does not receive exception
write access by default, and an exception writer does not receive base-policy
write access by default. Reject cross-tenant acknowledgements and evidence. Expose
queue, storage, watch, compile, rollout, target, node, and evidence-cursor
health without policy source, evidence, or secret payloads in logs or metrics.

### D6.2.8 — End-to-end convergence proof

Create, update, roll back, delete, and recreate one policy while two selected
nodes disconnect, reconnect, restart, and reject selected candidates. Create,
consume, expire, revoke, delete, and attempt to replay one file exception.
Prove that each accepted source, policy candidate, and exception candidate is
canonical,
each active node generation has an unbroken provenance chain, stale messages
cannot win, and an invalid or unavailable update leaves the previous valid
generation active.

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
boot change, or readiness loss. If a DaemonSet constraint change makes a Node
ineligible, remove both the ready label and the quarantine taint because the
Node is outside the managed set. Add the taint before a newly eligible Node can
be ready. The label is a scheduler projection. The authenticated Control
session remains the authority. Do not evict an existing protected Pod merely
because a `NoSchedule` taint is restored.

### D6.2.10 — Protected Pod and scheduler-binding admission

Serve Kubernetes admission from the existing `mithril-control` process. Do
not create another policy watcher or policy owner. On Pod create, resolve the
current namespaced `WorkloadProtectionPolicy` selectors against the admitted
Pod. No match leaves the Pod outside this flow. More than one match is an
ambiguous authority error. Remove the configured namespace list as a
protection selector; watch the cluster for namespaced policies, exceptions,
namespace identity, and protected Pod lifecycle facts.

Reserve the Mithril policy and source annotations for admission. Reject a Pod
that supplies either annotation. Validate Pod and ephemeral-container updates
without changing the scheduler binding. An unprotected scheduled Pod cannot
enter a protected policy through an update. A protected Pod update must keep
the admitted annotations, selector match, one container-entry match, and
digest-pinned protected images.

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

Use one stateless OCI adapter for the injected createContainer and prestart
hooks. The createContainer call sends immutable container, cgroup, image, and
Pod facts. The prestart call adds the exact held initial PID. The node validates
the root-owned endpoint, staged fact equality, live PID, cgroup membership,
Pod UID, container name, image digest, selected Node, candidate, and active
generation. It then publishes the cgroup binding and releases the runtime only
after activation and binding readback succeed. Timeout, mismatch, stale state,
unavailable node service, or unavailable exact candidate rejects the hook and
keeps the runtime start fail-closed.

### D6.2.12 — Packaging and convergence proof

Package both CRDs, the admission Service, webhook configurations, TLS inputs,
DaemonSet taint toleration, Node identity input, Control permissions, health,
and bounded timeouts. RBAC can read the one DaemonSet and workload facts and
can patch Nodes because Kubernetes RBAC cannot restrict a patch to individual
fields. The readiness owner changes only the Mithril projection. Control can
update the two status subresources but cannot write either spec. Node
identities cannot modify Kubernetes policy, exceptions, or Node readiness.

Prove both structural schemas, policy-to-internal lowering, exception bounding
and consumption, DaemonSet selector and affinity derivation, selector change,
new-node quarantine, stale-session quarantine, Pod mutation, scheduler choice
among two eligible nodes, binding rejection, exact-node delivery, held prestart release,
timeout denial, restart recovery, Pod deletion, container restart, and policy
retirement. Use API-server admission review objects and deterministic runtime
gate tests in automated acceptance. Use the current stock Kubernetes and OCI
runtime path for the physical manual result.

### D6.2.13 — Stock-runtime bootstrap authority

Extend the existing node binding owner. Do not add a policy watcher, public
CRD field, runtime-selected permission, or generic process exemption. The NRI
`CreateContainer` callback injects both Mithril OCI hooks. The createContainer
hook sends immutable container, cgroup, image, and Pod facts to the node. The
node keeps one bounded, expiring staged record and grants no authority at this
step.

At prestart, keep the exact initial task held. Require an exact staged-record
match, live PID and cgroup proof, CRI `Created` state, scheduler-selected Pod
binding, current node session, active signed candidate, and generation
readback. Publish the binding and one `RuntimeBootstrap` identity only after
all checks succeed. A failed publication or response delivery must remove the
new binding and bootstrap state before the runtime can retry.

Bind `RuntimeBootstrap` to the exact binding lifetime and initial entry
lineage. Use one non-evictable kernel transition with `UNARMED`, `ARMED`,
`HANDOFF_PENDING`, `CONSUMED`, `EXPIRED`, and fail-closed `CORRUPT` states and
one monotonic deadline. `HANDOFF_PENDING` reserves one task across the
multi-pass exec path and returns to `ARMED` only when that exec fails before
commit. Record each bootstrap anonymous object against that binding and entry
when BPF observes its creation. Permit only same-lineage read-only process inspection,
bootstrap-owned anonymous-file and pipe access, sealed bootstrap self-exec,
and the qualified initial namespace mount transitions. Do not grant path-backed
file, network, another binding, another entry, later external-root, or
post-handoff authority.

Keep sealed runtime self-exec in `RuntimeBootstrap`. When the exact application
executable matches the active signed policy, atomically consume the bootstrap
state and activate the normal workload execution identity. All bootstrap
object records become non-authoritative through that one transition. Expiry,
state mismatch, missing object ownership, map pressure, restart ambiguity, or
readback failure denies the effect and keeps node admission readiness closed
until recovery proves one exact state.

## Checkpoint

An operator changes one `WorkloadProtectionPolicy` or requests one bounded
`WorkloadProtectionException`. Control deterministically lowers, compiles, and
signs the base policy or creates a signed exception activation. It distributes
each artifact only to the exact target and reports the real state. Nodes keep
sole ownership of physical policy activation and exception consumption.
Control durably accepts replayable Phase 6 evidence. No graph or finding is
created in this phase.

## Required Tests

- Both CRD structural schemas, strict field validation, version, unknown-field,
  size, count, namespace, immutability, cross-reference, and RBAC behavior
  tests.
- Policy-spec-to-internal-policy golden equality and deterministic
  compile/sign tests. The public schema must contain no internal-only field.
- Policy create, update, duplicate event, stale UID, delete/recreate, forced
  removal, overlapping selector, watch close, compaction/relist, and Control
  restart tests.
- Container no-match and multiple-match rejection; image pinning; supported
  role, path, address, Unix-stream, signal, and ptrace lowering; and rejection
  of every deliberately absent field.
- Recursive deny behavior and recursive allow rejection until its Kubernetes
  runtime control passes physical qualification.
- Exception-writer RBAC, grant, exact Pod UID, container, duration, use bound,
  immutable spec, atomic consumption, expiry, revocation, deletion, stale
  event, overlap, replay, wrong base generation, wrong node or boot, and active
  task behavior without base-generation migration tests.
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
- Kubernetes condition projection, bounded rollout and exception status,
  tenant isolation, secret filtering, and status-is-not-authority tests.
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
- NRI createContainer staging, immutable stage mismatch, stage expiry and
  capacity, no-authority-before-prestart, exact initial-entry binding,
  bootstrap deadline, one-use application handoff, restart readback, and
  response-delivery rollback tests.
- Bootstrap anonymous-file, pipe, sealed self-exec, same-lineage inheritance,
  and initial namespace-transition positive tests. Path-backed file, network,
  unsealed exec, other-entry, other-container, external-root, expired,
  post-handoff, and map-pressure negative tests.
- Phase 6.2 owns no new Appendix C fixture ID. These named phase tests remain
  mandatory and Phase 11 must run them for each advertised Kubernetes mode.

## Acceptance

- The two CRDs are the sole production desired-state policy inputs in
  Kubernetes mode. The offline policy form produces the same internal policy
  as the stored policy spec and cannot activate it.
- The public schemas contain only qualified Kubernetes enforcement fields.
  Internal identity, proof, compiler, rollout, and finding fields do not appear.
- An exception can widen only one named file rule within its base grant,
  duration, use count, Pod UID, container, and authorized stored request.
- Control is the sole desired-state, rollout, and evidence-intake owner.
- A node is the sole owner of its active generation and BPF state.
- `ExceptionAuthorityOwner` and the BPF effect gate are the sole owners of
  exception instance state, receipts, recovery, and atomic use consumption.
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

Native roles or state transitions; process-state bits; maximum native depth;
device, capability, BPF, mount, or arbitrary privilege grants; semantic
projected-token, container-image, named-volume, immutable-artifact, or content
identity; Kubernetes Service, Pod-selector, DNS, TLS, HTTP, provider, CNI, or
service-mesh destinations; pipes, Unix datagrams, shared memory, SysV IPC, and
generic asynchronous IPC; positive general ptrace; arbitrary errno; user
capability IDs, proof predicates, or node selectors; and exceptions for
network, IPC, device, privilege, or mount rules.

Graph edges, findings, detection packages, severity and finding routes,
notification routing, response actions, provider leases, provider-specific
evidence, privileged or unmatched workload floors, and cross-node causal joins
also remain excluded. Phase 7 owns the graph and finding extension. Phase 8
consumes the Kubernetes object, scheduler, and runtime facts established here
for distributed causality and adds authenticated audit history and the
privileged or unmatched workload floor.

## Phase Result

```text
State: Not done. The corrected policy and exception implementation, package, automated fixture, and independent manual example are present. The current source has not passed the physical procedure. RuntimeBootstrap is approved but not implemented.
Implemented deliverable scope: D6.2.1 through D6.2.4 are implemented and automated. D6.2.5 has automated intake and WAL proof but lacks the physical failure variants. D6.2.6, D6.2.7, D6.2.9, D6.2.10, D6.2.11, and D6.2.12 have implemented owners and automated or rendered proof, but their required current physical results are not done. D6.2.8 is blocked at stock-runtime protected start. D6.2.13 is approved and not implemented.
Files and durable owners changed: the branch contains both namespaced CRDs and their Helm package; PolicyDesiredStateOwner; PolicyRolloutOwner; the exception desired-state path; TrustBundleOwner; KubernetesNodeReadinessOwner; KubernetesAdmissionOwner; KubernetesWorkloadInventoryOwner; one append-only ControlStore for policy, exception, node session, trust, rollout, acknowledgement, evidence, coverage, and cursor transactions; generated NodePolicy and ControlHealth services; NodePolicyDeliveryOwner; ExceptionAuthorityOwner; RuntimeAdmissionClient; RuntimeAdmissionServer; ScheduledRuntimeBindingV1; the node activation and cgroup-binding paths; the stateless OCI adapter; hook ownership and cleanup; the two-node fixture; and the independent manual example. The BPF ABI and BPF programs did not change.
Upstream-adoption dossier IDs used: none.
Fixture cases and exact physical results: the current physical two-node fixture and manual example are Not run. The prior old-API run passed node readiness, typed RBAC review, admission, scheduler selection, selected-node delivery, policy activation, runtime binding, Control acknowledgement, and durable evidence intake. Protected container start then failed when stock runc used an anonymous file write and IPC access. The application process did not start. The prior cleanup passed.
Automated verification: the repository Rust CI script passed format, workspace check, strict Clippy, and the full workspace test gate. The final gate included 89 Mithril Control library tests, 28 reconciliation tests, 6 Kubernetes policy API tests, 150 Mithril node library tests, 2 OCI adapter tests, and 5 node mTLS integration tests. Helm hook ownership, chart lint, and render verification passed. The VM harness behavior suite and independent manual example behavior suite passed. Diff hygiene passed.
Platform/kernel/runtime manifests: the Helm package contains both generated closed CRDs, separate writer and Control RBAC, the exact DaemonSet reader Role, the Control Deployment and Service, fail-closed admission webhooks, the node DaemonSet, atomic OCI hook ownership, and bounded uninstall cleanup. No BPF program or kernel ABI changed. No live current-source platform manifest was recorded.
Performance/capacity results: no new benchmark. Evidence gRPC messages are limited to 4 MiB. Policy gRPC messages are limited to 128 KiB. The pending evidence window is limited to 4,096 records. Health reports fixed counts and booleans only.
Unsupported/degraded paths: stock-runc bootstrap is unsupported until the approved internal RuntimeBootstrap authority is implemented. The current physical protected-start, lifecycle, evidence failure, watch-compaction, network-partition, and storage-outage cases are Not run. Phase 7 graph and finding behavior is not present.
Remaining work in this phase: implement the approved typed, bounded RuntimeBootstrap authority. Then run the current physical procedure through protected start, exact target, exception, runtime task, policy terminal cleanup, Node UID replacement, host epoch, watch, evidence failure, restart, uninstall, and cleanup cases.
Next phase not authorized: yes.
```
