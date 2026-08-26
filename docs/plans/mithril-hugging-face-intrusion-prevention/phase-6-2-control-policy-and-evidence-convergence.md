# Phase 6.2: Control Policy And Evidence Convergence

Status: Not done. The branch implements the approved capability-grounded
`WorkloadProtectionPolicy` and separate `WorkloadProtectionException`, their
Control and node lifecycles, Helm package, automated fixture, and independent
manual example. The current source has not passed the complete physical
procedure. The earlier physical run used the superseded API and stopped after
stock `runc` used an anonymous file write and IPC access that have no typed
authority. The approved correction uses a runtime-independent
`PreparedContainer` transition instead of a list of `runc` bootstrap effects.
The direct stock-`runc` application-start regression now passes with the
dynamic loader and libc absent from policy. The focused protected Kubernetes
application-start transaction also passes. The complete physical procedure
has not passed. The current public policy has an explicit `applicationEntry`,
a bounded set of `additionalEntries`, one `administrativeEntry`, and
`externalRole` as the fail-closed fallback. The stock-`runc` and complete
non-Kubernetes VM procedures now prove independent additional-entry roles and
reusable declarations. The Kubernetes procedure for these entries is not
complete.

Master: [Mithril Hugging Face Intrusion Prevention](./README.md)

Design: [Validated readable architecture](./policy-and-protection-algorithm-architecture-readable.md)

Closure matrix: [Phase 6.2 closure matrix](./phase-6-2-closure-matrix.md)

Manual acceptance: [Phase 6.2 runbook](./manual-testing/phase-6-2-manual-acceptance.md)

Implementation review: [Phase 6.2 review guide](./phase-6-2-implementation-review.md)

Environment setup: [shared setup guide](./manual-testing/environment-setup.md)

Policy example: [independent entry roles](./phase-6-2-entry-policy-example.yaml)

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
  -> NRI injects two ordered Mithril createRuntime hooks
  -> the first hook stages immutable container, cgroup, image, and Pod facts
  -> the first hook grants no runtime authority
  -> the second hook keeps the exact initial container process held
  -> mithril-node verifies CRI Created state and the staged immutable facts
  -> mithril-node verifies the scheduled Pod binding and active signed policy
  -> mithril-node stages, reads back, probes, and activates the exact policy generation
  -> mithril-node publishes the exact cgroup binding as PreparedContainer
  -> the runtime gate releases that process only after policy and binding readback
  -> BPF recognizes the exact prepared container binding
  -> every runtime action in that binding can complete implementation-specific setup
  -> runtime-created objects gain no independent or inherited workload authority
  -> PREPARED remains until application activation or exact binding retirement
  -> the first exec that matches applicationEntry.executionRule atomically changes PreparedContainer to Active
  -> the application entry installs only applicationEntry.role
  -> every later independent root starts with externalRole and no admitted-entry default
  -> an exec that matches exactly one declared additional entry installs only that entry's role
  -> an approved administrative exec consumes its one-use slot and installs only administrativeEntry.role
  -> an unmatched or multiply matched external exec remains fail-closed
  -> explicit matching Deny decisions run before the admitted-entry default
  -> an applicable exception can authorize an explicitly denied action
  -> actions with no matching decision are allowed only for the exact admitted entry lineage
  -> cgroup membership alone does not grant entry authority

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
- container matches by name, kind, and digest-pinned immutable image reference;
- one `applicationEntry` with one named execution-rule reference and one role;
- a bounded `additionalEntries` list with a unique name, closed entry kind,
  named execution-rule reference, and role for each entry;
- one `administrativeEntry` role and one conservative `externalRole`;
- named roles with canonical-path file rules, execution rules, explicit-address
  network rules, process-control rules, and Unix-stream role relationships; and
- named bounded `exceptionGrants` that refer only to named file rules.

The closed additional-entry kinds are `PostStart`, `PreStop`, `StartupProbe`,
`ReadinessProbe`, and `LivenessProbe`. Probe entry kinds apply only to an exec
probe. HTTP, TCP, gRPC, and lifecycle Sleep actions do not create an
in-container task. OCI prestart and the two qualified `createRuntime` calls are
runtime bootstrap activity under `PreparedContainer`. OCI poststop is runtime
cleanup and is not a workload entry.

Each `executionRule` field refers to one existing named rule in the referenced
role's unchanged `execution` list. The referenced rule must be a
non-recursive `Allow` rule that contains `Execute`. Only a rule referenced by
an entry can admit an independent root. Other execution rules remain effect
rules for an already admitted lineage. Reject a missing rule, a rule in
another role, a duplicate entry or rule reference, and a configuration in
which one exec matches more than one declared entry.

Each entry installs only its referenced role. Roles do not inherit, union, or
fall back to the application role. A native descendant keeps the role of its
creator entry. The external role is the pre-admission and unmatched-entry
role. It never receives the admitted-entry default, and its execution rules
cannot admit an external exec. Only a declared entry match or the approved
administrative slot can admit that exec. The administrative role is installed
only after the existing signed one-use administrative slot matches and is
consumed.

Stock CRI does not prove that a matching exec is a PostStart, PreStop, or
probe request. The closed `kind` records the policy declaration. Kernel
evidence keeps the observed purpose as `UNKNOWN` and records the matched entry
ID separately. An ordinary runtime exec that does not match a declared entry
remains denied. An ordinary runtime exec with the same observable match as a
declared entry cannot be distinguished on the no-patch path. Record this
residual ambiguity and do not claim a purpose-to-task join.

Every Pod container must match exactly one container policy match. Reject an
unmatched or multiply matched container. Control derives cluster, namespace,
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
candidate, acknowledgement, evidence batch, and intake-receipt types as an
additive architecture amendment. Update the exact-type closure and canonical
goldens, and rerun the affected Phase 0 schema checks. The separately approved
`PreparedContainer` transition and the per-entry admission state are the BPF
ABI amendments in this phase. Do not rewrite a historical phase result. Phase
6.2 and later results bind the amended architecture and ABI digest.

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

Use one stateless OCI adapter for two ordered `createRuntime` hook entries.
OCI requires deprecated `prestart` hooks to run before `createRuntime` and
requires `createContainer` hooks to run after `createRuntime`. Therefore,
those two hook stages cannot implement the required stage-then-gate order.
The first `createRuntime` call sends immutable container, cgroup, image, and
Pod facts without PID authority. The second call adds the exact held initial
PID. The node validates the root-owned endpoint, staged fact equality, live PID,
cgroup membership,
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
among two eligible nodes, binding rejection, exact-node delivery, held
initial-task release,
timeout denial, restart recovery, Pod deletion, container restart, and policy
retirement. Use API-server admission review objects and deterministic runtime
gate tests in automated acceptance. Use the current stock Kubernetes and OCI
runtime path for the physical manual result.

### D6.2.13 — Prepared-container runtime boundary

Extend the existing node binding owner. D6.2.1 owns the approved public entry
fields. Do not add a policy watcher, runtime-selected permission,
runtime-specific operation list, or generic process exemption. The NRI
`CreateContainer` callback injects both
ordered Mithril `createRuntime` hooks. The first hook sends immutable
container, cgroup, image, and Pod facts to the node. The node keeps one
bounded, expiring staged record and grants no workload authority at this step.

`CreateContainer` also installs all authority that later entries can use for
the exact binding and policy generation. This authority contains the
application entry, every additional-entry declaration and role, the
administrative role, and the external role. It does not contain future task
identities. A PostStart, PreStop, or probe process does not exist when this
hook runs.

In the second hook, keep the exact initial task held. Require an exact
staged-record match, live PID and cgroup proof, CRI `Created` state,
scheduler-selected Pod
binding, current node session, active signed candidate, and generation
readback. Publish the exact binding as `PreparedContainer` only after all
checks succeed. A failed publication or response delivery must remove the new
binding and prepared state before the runtime can retry.

Bind `PreparedContainer` to the exact container binding lifetime. Do not bind
it to one runtime binary, syscall set, operation set, thread group, or helper
process shape. The held PID proves the initial cgroup lifetime and owns the
canonical initial entry before the node returns allow. It does not define the
runtime implementation after that point.

Here, `entry` is the boot-scoped task entry identity. It is not an exact
executable file or inode identity.

During `PREPARED`, BPF allows every governed action from a task that resolves
to the exact binding ID and nonce, node boot and label epoch, execution set,
profile generation, and live cgroup binding. A task without an identity first
receives the existing restricted external-root identity for that exact
binding. The action then uses the same prepared-binding bypass. This rule lets
`runc`, `crun`, `youki`, or another qualified runtime change its threads,
helpers, anonymous objects, IPC, or setup operations without a Mithril update.

Use one non-evictable kernel transition with `UNARMED`, `PREPARED`,
`EXEC_PENDING`, `ACTIVE`, `EXPIRED`, and fail-closed `CORRUPT` states. State,
not elapsed time, owns this boundary. Treat every governed effect from the
exact prepared binding as trusted node runtime infrastructure until a
signed-policy-approved application exec commits or the exact binding retires.
Do not identify the runtime
by a `runc`, `crun`, or `youki` syscall or operation sequence. Do not record
anonymous files, pipes, Unix endpoints, root handles, network destinations, or
other runtime-created objects as independent authority.

`EXEC_PENDING` reserves one exact task across the application exec path and
returns to `PREPARED` only when that exec fails before commit. The existing
identity lifecycle owner also keeps bounded per-task pending state for a
declared additional entry and the approved administrative path. A
runtime-internal exec that does not satisfy an entry match remains in
`PREPARED`. It does not activate workload authority. A task outside the exact
binding, container lifetime, or node session cannot use the prepared state.
The binding state is a trust-boundary state. It is not a workload policy
permission, exception, or transferable object authority.

A later runtime-created process gets a new restricted external identity when
it becomes visible in the exact binding. If one runtime bootstrap exec crossed
the cgroup attachment boundary, BPF can let only that exact task finish that
in-flight exec. This completion does not install an entry role. The task stays
prepared. Its next exec must match a declaration that `CreateContainer`
already installed. A failed or unmatched next exec remains fail-closed. Do
not match a runtime binary, helper path, file descriptor path, process name,
or lifecycle kind in BPF.

When the executable's container-visible path satisfies
`applicationEntry.executionRule`, atomically reserve the transition from any
task in the exact binding and commit `ACTIVE` with the application entry's
role. This binding transition removes prepared authority from every task in
that binding. A failed exec restores only its own reservation.

A PostStart exec can occur before or after application activation. If it
matches one declared additional entry during `PREPARED`, record its exact
entry identity and independent role before exec commit. Prepared authority
still controls its effects until the binding becomes `ACTIVE`. If the task is
still live after activation, it uses only its declared role. A PreStop or exec
probe that starts after activation first receives `externalRole`. At the exec
boundary, an exact match to one additional entry can reserve the task. A
successful exec commits that entry and installs only its role. A failed exec
restores the restricted external state. No match or more than one match
denies. An additional-entry declaration stays installed and can authorize
multiple invocations. Each invocation gets a new task identity, process
identity, prepared association, and exec transaction.

The approved administrative path remains separate. The external root first
receives `externalRole`. Only the existing signed, bounded, one-use next-match
slot can reserve it as the administrative entry. Successful exec installs
`administrativeEntry.role`. An applicable compiled exception can authorize
the exact denied action. An ordinary `kubectl exec` or direct `crictl exec`
cannot install the administrative role.

After `ACTIVE`, every file, network, IPC, process, device, privilege, mount,
and exec effect checks explicit signed decisions first. An explicit matching
`DENY` blocks the action unless an applicable exception authorizes it. A
missing decision allows the action only when the actor has one committed
application, declared additional, or approved administrative entry identity.
The actor uses only that entry's installed role. A task that enters the cgroup
with no identity, an unmatched external identity, or an unresolved identity
remains fail-closed. Runtime-created objects have no residual prepared-state
grant.
Expiry, state mismatch, restart ambiguity, or readback failure denies the
effect and keeps node admission readiness closed until recovery proves one
exact state.

Use the same binary-match boundary as the checked Tetragon implementation.
Resolve the executable path from the current task root and match that signed
path. Do not require inode generation or an `EXACT` selector for workload
execution. Keep `EXACT` object identity for filesystem rules and the separate
administrative-exec approval path. After activation, resolve exact object
identity only when a signed selector explicitly requests `EXACT`.

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
- Application, additional-entry, administrative-entry, and external-role
  schema tests. Cover missing roles and rules, cross-role references,
  duplicate names and references, unsupported kinds, non-`Allow` entry rules,
  recursive entry rules, missing `Execute`, and multiply matched entries.
- Lowering tests must prove that each entry receives only its named role and
  that no role inherits or unions the application role. Native descendants
  must retain the role of their creator entry.
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
- OCI held-task valid release, missing candidate, invalid annotation, PID and
  cgroup mismatch, stale candidate, timeout, node restart, and fail-closed
  endpoint tests.
- Ordered createRuntime staging, immutable stage mismatch, stage expiry and
  capacity, no-authority-before-admission, exact initial-entry binding,
  prepared-state deadline, one-use application activation, restart readback, and
  response-delivery rollback tests.
- Runtime-independent prepared-entry tests for anonymous files, pipes, Unix
  endpoints, namespace setup, file access, network setup, and runtime-internal
  exec. Tests must show that another entry, container, external root, or
  expired state cannot use the prepared boundary. Tests must also show that
  the first signed-policy-approved exec activates normal enforcement and that
  no runtime-created object carries authority across that transition.
- PostStart-before-application, PostStart-after-application, PreStop, startup
  probe, readiness probe, and liveness probe exec tests. Each successful match
  must install only its declared role. Invoke at least one additional entry
  twice and prove that the declaration is reusable while both process
  identities and exec transactions are distinct. An unmatched ordinary
  `kubectl exec`, direct `crictl exec`, cgroup-entering task, failed exec, and
  ambiguous entry match must remain fail-closed.
- Approved administrative exec tests must prove one-use slot consumption,
  installation of only `administrativeEntry.role`, explicit Deny precedence,
  applicable exception authorization, and denial of an ordinary exec without
  the slot.
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
- The application entry, every declared additional entry, and the approved
  administrative entry install independent roles. No entry inherits or unions
  the application role.
- `externalRole` remains the role for an unmatched independent root and never
  receives the admitted-entry default.

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
State: Not done. The current policy and exception implementation, PreparedContainer boundary, independent entry roles, package, automated fixture, and independent manual example are present. The direct stock-runc and complete non-Kubernetes VM procedures passed. The approved independent-entry CRD and runtime amendment is implemented. The protected Kubernetes procedure for the new entry behavior is not complete.
Implemented deliverable scope: D6.2.1 through D6.2.4 implement and automate `applicationEntry`, `additionalEntries`, `administrativeEntry`, and `externalRole`. D6.2.5 has automated intake and WAL proof but lacks the physical failure variants. D6.2.6 through D6.2.13 have implemented owners and automated or rendered proof, but their required current Kubernetes physical results are not complete.
Files and durable owners changed: the branch contains both namespaced CRDs and their Helm package; PolicyDesiredStateOwner; PolicyRolloutOwner; the exception desired-state path; TrustBundleOwner; KubernetesNodeReadinessOwner; KubernetesAdmissionOwner; KubernetesWorkloadInventoryOwner; one append-only ControlStore for policy, exception, node session, trust, rollout, acknowledgement, evidence, coverage, and cursor transactions; generated NodePolicy and ControlHealth services; NodePolicyDeliveryOwner; ExceptionAuthorityOwner; RuntimeAdmissionClient; RuntimeAdmissionServer; ScheduledRuntimeBindingV1; bounded runtime-fact staging in WorkloadBindingOwner; the node activation and cgroup-binding paths; the stateless two-stage OCI adapter; the PreparedContainer binding ABI and BPF transition owner; hook ownership and cleanup; the two-node fixture; and the independent manual example.
Upstream-adoption dossier IDs used: none.
Fixture cases and exact physical results: the complete non-Kubernetes VM procedure passed with stock runc 1.3.4. It recorded PREPARED to ACTIVE, the declared application entry, five additional-entry roles, role-specific Deny decisions, and external-entry denial. It invoked the PostStart declaration twice. Both invocations used the same role and rule. They had distinct host PIDs, task cookies, process-state IDs, and execution IDs. The policy did not list libc or the ELF loader. Identity, observe-mode effect, protect-mode effect, kernel, and network probes also passed. The evidence is `/tmp/phase-6-2-full-vm-20260826-run1`.
Earlier fixture cases and exact physical results: the direct stock-runc application-start lane passed with runc 1.3.4. It recorded PREPARED to ACTIVE, the path-approved application entry, an application-default dependency read, no exact executable object, libc and the ELF loader absent from policy, successful exit, and owned-resource cleanup. The focused protected-start lane passed with Kubernetes v1.35.5+k3s1 and containerd 2.2.3-k3s1. It replaced Mithril and the protected Pod in the retained two-VM cluster. The policy contained `/bin/sh` as its sole execution selector. Fresh Pod UID `078ffde6-6ef9-4268-a7da-3a398e2f205e` ran as container `05bb1cc19d8b5bed04ae9058053cd907effcb18956ab65162f67f75e2daa707e` on `ubuntu-b1bfec97`. Policy revision `5c8ab1236e1d26a7bb8ec0b9bed7bda91bdabfebd669c41533c244da957afb5d` activated binding `0044aed1-8c6e-877a-a0e6-84fffdaf54c9`. The exact admitted entry reached ACTIVE. Later BusyBox applet execs received `APPLICATION_DEFAULT_ALLOW` without an exact object key or composite atom. The explicit matching file Deny blocked its target. A direct CRI exec into the same container cgroup failed with `UNSUPPORTED_OBJECT`, `DENIED_BEFORE_EFFECT`, and kernel result `-13`. It did not create its marker. The result is `/tmp/phase-6-2-shell-only-entry-20260825-run13/protected-start-result.json`. These results do not prove declared additional entries or the administrative entry. The remaining two-node fixture and manual example cases are Not run. The prior old-API Kubernetes run remains partial historical evidence.
Automated verification: PreparedContainer ABI, application-default ABI, compiled BPF object, independent entry roles, repeated entry admission, node observation, VM-harness behavior, diff checks, and the complete non-Kubernetes VM procedure passed for the current source.
Platform/kernel/runtime manifests: the Helm package contains both generated closed CRDs, separate writer and Control RBAC, the exact DaemonSet reader Role, the Control Deployment and Service, fail-closed admission webhooks, the node DaemonSet, two atomically owned `createRuntime` hook registrations, and bounded uninstall cleanup. The protected-start result records Kubernetes v1.35.5+k3s1, containerd 2.2.3-k3s1, the exact live Pod, container, node, policy, binding, task, state, and entry identities, the later application exec result, and the external-entry denial. The VMs and K3s cluster remain available. The successful run keeps its current Mithril release and Pod; the next reuse run replaces them.
Performance/capacity results: no new benchmark. Runtime stages are limited to 128 records and 30 seconds. PreparedContainer is designed for one exact binding and one application activation. Evidence gRPC messages are limited to 4 MiB. Policy gRPC messages are limited to 128 KiB. The pending evidence window is limited to 4,096 records. Health reports fixed counts and booleans only.
Unsupported/degraded paths: the new lifecycle and probe entry roles have no protected Kubernetes proof. The approved administrative role has no new physical proof. The remaining evidence failure, watch-compaction, network-partition, and storage-outage cases are Not run. Phase 7 graph and finding behavior is not present.
Remaining work in this phase: run the protected Kubernetes procedure through the additional-entry cases, administrative entry, exception authorization, policy terminal cleanup, Node UID replacement, host epoch, watch, evidence failure, restart, uninstall, and final cleanup cases.
Next phase not authorized: yes.
```
