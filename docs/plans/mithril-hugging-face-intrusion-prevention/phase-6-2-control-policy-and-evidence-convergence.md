# Phase 6.2: Control Policy And Evidence Convergence

Status: Not done. The branch implements the approved capability-grounded
`WorkloadProtectionPolicy` and separate `WorkloadProtectionException`, their
Control and node lifecycles, Helm package, automated fixture, and independent
manual example. The recorded complete automated two-node physical fixture
passed on the current changed source. It uses the runtime-independent
`PreparedContainer` transition and the current public policy schema. That
schema has an explicit
`applicationEntry`, a bounded set of `additionalEntries`, one
`administrativeEntry`, and `externalRole` as the fail-closed fallback. The
stock-`runc`, non-Kubernetes VM, and Kubernetes procedures prove independent
entry roles, reusable declarations, and guarded migration of a running process
to a replacement policy generation. The retained runtime gate also permits the
exact Control and Node recovery shapes without an executable digest. The
independent manual procedure passed on its recorded source. The physical
evidence-failure, watch-compaction, network-partition, storage-outage,
version-changed Kubernetes recovery, and authorized final-decommission cases
remain `Not run` or `Not done` on the current changed source.

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
build the cross-node graph. Keep node enforcement after Kubernetes package
deletion unless an independently signed node decommission authorization
completes. Reject the exact attacker-created privileged Pod at admission and
retain a BPF incident floor for an admission bypass.

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
  -> PolicyActivationOwner stage, readback, probes, and pointer publication
  -> authenticated node acknowledgement and Control rollout inventory

Linux capability authority
  -> Kubernetes or the OCI runtime puts a Linux capability in the process credentials
  -> the active Mithril role matches one exact named capability rule
  -> an Allow rule permits use of that existing capability
  -> a Deny rule rejects use of that capability
  -> Mithril does not add a capability that is absent from the process credentials
  -> the mount gate uses the exact SysAdmin decision and needs no second public mount rule

Known path-tree route
  -> Node holds the authenticated initial container mount snapshot
  -> Node records the compiled path prefix for each known mount-root source
  -> BPF uses the route when the target dentry or a source ancestor has one
  -> BPF does not compare mount ages for a routed path
  -> BPF uses the oldest unique mount only when no route exists
  -> an unresolved route and fallback deny under strict policy

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

Offline decommission signer
  -> minimal signed cluster, node, boot, expiry, and nonce authorization
  -> Control relays the artifact unchanged over the authenticated node session
  -> NodeDecommissionOwner verifies and durably consumes it
  -> Control removes scheduling readiness and quarantines the exact Node
  -> the node closes admission and removes owned hooks and pinned BPF state
  -> node readback and acknowledgement authorize projection cleanup
  -> Helm removal deletes only Kubernetes release objects

Unmatched privileged Pod CREATE
  -> KubernetesAdmissionOwner rejects dangerous fields before scheduling
  -> no Kubernetes metadata can act as an exception signature
  -> containerd's default CRI runtime invokes the retained Mithril OCI hook
  -> the hook rejects the exact hostile OCI shape before its initial process
  -> direct non-CRI starts bypass the CRI hook but not the retained BPF floor
  -> retained BPF state denies the hostile task's first covered effect

Mithril recovery after ordinary Helm deletion
  -> Helm installs the retained hook, OCI base spec, and containerd default-runtime configuration
  -> containerd, not an NRI service, owns hook invocation after installation
  -> the hook admits a version-changed Mithril installer with the retained installer command and host ownership shape
  -> the installer atomically replaces binaries, runtime configuration, and the exact recovery manifest
  -> Control and Node reopen their existing durable state and run only supported migrations
  -> Control continues the existing policy sequence and predecessor chain
  -> the hook permits only the exact Control and Node recovery commands and OCI shapes recorded by the new manifest
  -> neither recovery exception uses an executable digest
  -> Pod labels, annotations, namespaces, RuntimeClass, and Helm ownership grant no recovery authority
  -> the recovered node verifies retained BPF state and opens normal admission
```

The CRDs store desired state. They are not signed node artifacts, evidence
database, graph database, or activation acknowledgement store. A node does not
watch or parse the CRDs. Control does not write BPF maps or change a node's
active-generation pointer.

A base-policy update applies to running processes. Node first builds the new
immutable generation under an unreachable generation handle. Node reads back
all rows and runs the activation probes. Node then publishes the generation for
the live binding. At each running process's next protected effect, BPF acquires
that process's transition guard, applies the precompiled semantic role and
process-state translation, changes the active process generation, and evaluates
the effect with the new generation. Processes migrate independently. There is
no container-wide stop or workload-wide migration transaction.

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
  -> containerd's configured default CRI runtime invokes two ordered Mithril createRuntime hooks
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
  -> ExceptionAuthorityOwner activates it without creating another base generation
  -> the BPF effect gate consumes uses atomically
  -> the node reports use, expiry, or revocation

WorkloadProtectionPolicy UPDATE for a running Pod
  -> PolicyDesiredStateOwner validates and persists the new source revision
  -> Control compiles and signs one new immutable target-bound generation
  -> Node installs the generation under keys that no live binding can reach
  -> Node reads back every row and runs controlled allow and deny probes
  -> Node stages exact old-to-new role and process-state migration rows
  -> Node publishes the new generation for the live binding
  -> each BPF effect migrates its running process under the process transition guard
  -> that effect uses the new generation after the guarded migration completes
  -> another process can remain on the complete old generation until its next protected effect

Live process migration cannot complete
  -> BPF does not combine old and new policy rows
  -> BPF denies the current effect
  -> BPF leaves the process on its last complete generation or in a fail-closed guarded state
  -> a later protected effect retries after the conflicting exec or process transition ends

Pod changes Node, UID, container identity, or policy match
  -> the old target cannot authorize the changed workload
  -> Control creates a new immutable target and candidate when the new state is valid
  -> the runtime gate remains closed until the selected Node activates that target

Pod or container terminates
  -> Control removes the exact target from the next desired snapshot
  -> Control returns a complete authenticated desired-bundle inventory to the selected node session
  -> mithril-node keeps the last valid policy while runtime inventory still reports a matching container lifetime
  -> mithril-node retires the exact cgroup binding after runtime inventory proves that lifetime is absent
  -> mithril-node records the stale profile and removes each binding owned by the exact profile generation and node session after reference readback permits removal
  -> a node restart restores retained enforcement before it reconciles the complete desired inventory again
  -> cleanup uses the stored profile, generation, node boot, and label epoch; a changed runtime binding alias cannot hide an owned kernel row
  -> cleanup does not inspect a deleted container root
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
  -> Control removes the policy bundles from each complete desired node inventory
  -> Control sends no restrictive policy candidate and does not inspect a deleted container root
  -> each node keeps its last valid local policy while a matching runtime lifetime exists or Control is unavailable
  -> runtime inventory absence permits local binding and generation removal
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
- named roles with canonical-path file rules, execution rules, exact Linux
  capability rules, explicit-address network rules, process-control rules, and
  Unix-stream role relationships; and
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

Define entry ambiguity only with facts that enforcement can observe. Control
rejects ambiguity that is visible in the policy. Node rederives the admission
keys for the exact container and rejects ambiguity or a required proof that is
missing in that container. A failed update keeps the previous active
generation. A new binding stays `PREPARED`. Physical aliasing does not merge
different canonical request-path keys unless the policy requests exact-object
matching. When it does, an unresolved object or conflicting object binding
prevents activation. BPF receives one complete, collision-free entry table. It
does not select by order, merge roles, or resolve an ambiguous entry.

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

Capability rules use the same named, per-rule action model as the other role
rules:

```yaml
capabilities:
  - name: allow-sys-admin
    capabilities: [SysAdmin]
    action: Allow
```

Each rule contains one or more exact Linux capability names and one `Allow` or
`Deny` action. The runtime must put an allowed capability in the process
credentials. Mithril authorizes its use but does not add it. A successful
mount needs the role's exact `SysAdmin` authorization. It does not need a
second public mount rule. Keep generic capability authority denial-only.

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
after it verifies that the expected pointer did not change. The acknowledgement
binds node identity, boot and label epochs, policy source revision, candidate
digest, node-bound generation digest, node-local profile-generation reference,
activation state, readback digest, and rejection reason. A delayed
acknowledgement from an old boot, target snapshot, or candidate cannot advance
the current rollout.

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

Policy deletion removes the policy from Control's complete desired-bundle
inventory. It does not create or deliver a restrictive policy candidate. A
node keeps the last valid local generation while a matching runtime lifetime
exists or Control is unavailable. Runtime inventory proves when the concrete
container lifetime is absent. The node then removes kernel bindings that match
the stored profile, generation, node boot, and label epoch. It does not depend
on the mutable runtime binding alias. It does not rediscover an entry point or
inspect a deleted container root.

This lifecycle adapts the checked Tetragon pattern. Tetragon keeps pinned
enforcement during a daemon outage, rebuilds current desired policy, and
removes replaced pinned state only after the rebuild succeeds. Its Pod cleanup
uses stored Pod, container, and cgroup identities. Mithril uses its stored
profile-generation owner tuple to find equivalent pinned membership, including
rows whose runtime alias replaced the scheduled authority alias. Mithril keeps
its signed activation and anti-rollback checks for desired policy changes, but
it does not model local stale-membership removal as a new policy. See
[persistent enforcement](https://tetragon.io/docs/concepts/enforcement/persistent-enforcement/),
[persistent gRPC policies](https://tetragon.io/docs/concepts/enforcement/persistent-grpc-policies/),
and [policy-filter state cleanup](https://github.com/cilium/tetragon/blob/main/pkg/policyfilter/state.go).

Exception deletion, target disappearance, or explicit revocation closes the
exact runtime instance through a signed revocation candidate. Expiry and
exhaustion become terminal through the signed deadline and use bound already
installed on the node. Control and the node preserve the consumed-use record.
The base policy generation does not change. A stale exception event or
recreated object cannot restore the old instance.

Control does not require or update a CRD finalizer. Forced object deletion,
namespace deletion, API-server loss, or Control loss cannot remove a node's
active protection.

Helm deletion follows the same rule. The chart has no pre-delete host cleanup
hook. An ordinary uninstall removes Kubernetes objects but leaves owned host
runtime hooks, the owned OCI base spec, the owned containerd default-runtime
configuration, and pinned BPF state. Containerd invokes the retained hook
directly. It does not depend on a retained NRI process or a RuntimeClass. A
missing node admission socket denies a matching protected start. The hook also
rejects the exact unmatched privileged-Pod OCI shape before its initial
process. It permits the exact Control and Node recovery commands and
security-sensitive OCI shapes recorded by the current manifest. Neither
recovery exception uses an executable digest. Control recovery requires the
exact command, non-root user and supplementary group, no Linux capabilities,
read-only root filesystem, and the recorded configuration and durable-state
mount destinations. Dynamic
Kubernetes volume source paths do not grant authority. The hook also permits a
version-changed Mithril installer when the installer command, retained owner,
host paths, writable mounts, privileges, and socket match the installed
integration. The installer can replace the hook binary, runtime configuration,
and recovery manifest. It cannot reset Control or Node durable state.
Kubernetes names, labels, annotations, namespaces, and Helm ownership are not
recovery authority. Retained BPF state continues to protect existing bindings
and denies the incident's first covered effect if a caller bypasses the CRI
path.

A normal reinstall mounts the same Control PVC and the same Node state
directory on each host. Control and Node own their respective migrations. A
migration must be explicit, bounded, and crash-safe. The owner must complete it
before it serves policy or opens admission. A failed or unsupported migration
keeps the original state intact and keeps admission fail-closed. The installer
does not create fresh policy authority. After restart, Control sends the next
sequence and names the previously active candidate as its predecessor.

A fresh Control PVC and a retained Node state directory do not form an upgrade
baseline. The Node retains issuer and distribution high-water values and the
active candidate, but fresh Control starts without that transaction history.
Its first root candidate is therefore a replay or an invalid predecessor. This
combination proves anti-replay rejection only. It cannot prove upgrade
continuity. A storage contract that cannot use an explicitly supported
migration is outside this upgrade path.

`NodeDecommissionOwner` accepts only an independently signed
`NodeDecommissionAuthorizationV1`. Its payload contains the cluster UID, node
ID, current node boot ID, expiry in UTC nanoseconds, and one nonce. The
envelope contains the signer key ID, Ed25519 algorithm, canonical payload, and
signature. Control stores and relays these bytes. It cannot sign or change
them. The node verifies every field, rejects a used nonce, and rejects while a
protected runtime binding is live. It durably records acceptance before any
physical change.

Control removes readiness and quarantines the exact Node before cleanup. The
node then closes runtime admission. It removes only the marked containerd
configuration, OCI base spec, hook documents, and hook binary that it owns. It
restarts containerd, reads back that the default runtime no longer invokes the
hook, removes its pinned BPF links and maps, and reads back absence. It durably
records completion and acknowledges the authorization. Only that
acknowledgement lets Control remove its Node label, identity annotations, and
quarantine taint. The operator removes Helm last. If Helm is removed first,
the host state stays active until the same owner or host entry point consumes
a valid authorization.

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

When the node receives the exact held initial PID, it snapshots the complete
initial container mount view. For each known mount-root source, it records the
binding, profile generation, topology generation, mount namespace, filesystem
device, root inode, and compiled path prefix. This record tells BPF which path
to use. It does not use the mount's creation order as policy authority.

The path graph is immutable generation content before this snapshot starts.
The existing held-initial-PID inode stage resolves each represented source
path to a state in that graph. It then publishes only dynamic, binding-scoped
inode routes. It does not rebuild the graph, change the generation digest, or
activate a second policy generation. The provisional entry-measurement pass
and the completed exact-object pass use the same generation handle. A new
generation is reserved only for a new signed candidate.

The exact held PID is at the `createRuntime` stage. Its process root is still
the pre-container root. Node must open the configured OCI bundle root through
the held mount namespace. It rebases each bundle mountpoint to its container
path before it resolves graph states. It publishes these entry-time routes and
must not use `/proc/<pid>/root` for this admission snapshot. Node does not
rebuild the route rows after the task starts.

BPF owns topology reconstruction after admission. The mount hooks update a
global mutation epoch and pending count before a namespace-visible change.
For each file or executable decision, BPF snapshots that guard, reads the live
namespace event, scans the live mount tree, resolves the path, and rechecks the
guard. A concurrent, missing, or unresolved topology denies under strict
policy. Ring-buffer delivery supplies evidence only. It does not complete the
authorization decision or trigger Node route publication.

For an initial Kubernetes submount, Node follows the source dentry ancestry
and records the inherited source path. For example, if the source root is
mounted at `/home/secret` and `source/models` is also mounted at
`/home/kubelet-attack`, the recorded route for the submount is
`/home/secret/models`. On access to `/home/kubelet-attack/secret`, BPF checks
`/home/secret/models/secret`.

A route stores up to 16 deduplicated state IDs from the compiled graph. It
does not store a new combined graph state. BPF advances all stored states,
combines their role-specific denial masks, and applies any denial. These
states keep `*` and `**` transitions active for later components and therefore
cover future descendants. Node refuses binding activation if one source needs
more than 16 states. If no route exists on the source dentry ancestry, BPF
selects the oldest unique mount as the canonical fallback. A later
in-container bind mount does not install a new policy route. A concurrent,
missing, or unresolved path denies under strict policy.

Helm installs the Mithril hook through containerd's default CRI runtime. The
installation owns one marked OCI base spec and one marked containerd
configuration fragment. It does not install a persistent NRI service, and it
does not require a Pod to select a RuntimeClass. Containerd therefore retains
the start gate when the Helm release and Mithril Pods are absent.

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

The same adapter owns the retained incident gate. It reads the OCI bundle and
rejects the exact Phase 6.2 unmatched privileged-Pod shape before the initial
process. If the node socket is absent, it permits the exact Node recovery whose
command and security-sensitive OCI fields equal the retained Mithril recovery
manifest. It also permits the exact Control recovery whose command, non-root
user and supplementary group, empty capability sets, read-only root, and
required mount destinations equal the manifest. Neither exception uses an
executable digest. The Control
exception does not accept identity from a Pod name, namespace, label,
annotation, image name, or dynamic Kubernetes volume source path. The gate
also admits a version-changed installer whose command and host ownership shape
match the retained installation. The installer replaces the integration and
writes a new exact recovery manifest. The new Control and Node processes must
reopen their existing state and continue the policy chain. A caller cannot
create this authority with Kubernetes metadata. A direct containerd or OCI
caller can bypass the CRI base spec, so retained BPF enforcement remains the
final incident floor.

### D6.2.12 — Packaging and convergence proof

Package both CRDs, the admission Service, webhook configurations, TLS inputs,
DaemonSet taint toleration, Node identity input, Control permissions, health,
and bounded timeouts. RBAC can read the one DaemonSet and workload facts and
can patch Nodes because Kubernetes RBAC cannot restrict a patch to individual
fields. The readiness owner changes only the Mithril projection. Control can
update the two status subresources but cannot write either spec. Node
identities cannot modify Kubernetes policy, exceptions, or Node readiness.

Do not package a pre-delete cleanup DaemonSet or Job. Ordinary Helm deletion
is not decommission authority. Package the independent decommission public
key as host-provisioned node input. Control receives only signed artifacts and
relays them unchanged. Package an idempotent host integration owner that
installs and reads back the default-runtime containerd fragment, OCI base spec,
hook binary, and recovery manifest. The owner must retain these files during
ordinary uninstall. The node owns durable nonce consumption, exact owned-file
cleanup, containerd restart and readback, pin removal, and BPF absence readback.

For every Pod CREATE that has no matching policy, reject privileged mode,
host PID, host IPC, host networking, `CAP_SYS_ADMIN`, `CAP_BPF`,
`CAP_SYS_MODULE`, hostPath, host devices, and unsafe unconfined security
settings. This is the exact incident admission floor. Retained BPF state must
also deny the hostile unmatched task's first covered host-secret, mount,
device, privilege, process-control, or network effect when the API path is
bypassed. Phase 8 owns signed privileged exceptions and the complete runtime
field matrix.

Prove both structural schemas, policy-to-internal lowering, exception bounding
and consumption, DaemonSet selector and affinity derivation, selector change,
new-node quarantine, stale-session quarantine, Pod mutation, scheduler choice
among two eligible nodes, binding rejection, exact-node delivery, held
initial-task release,
timeout denial, restart recovery, Pod deletion, container restart, and policy
retirement. Prove that ordinary Helm deletion retains hooks and pins, that a
matching start and the exact hostile unmatched start fail closed without the
node process, and that a version-changed installer with the retained ownership
shape succeeds. Prove that the installer replaces the recovery manifest, that
the exact new Node starts, and that Control and Node reopen the same durable
state. The next candidate must continue the retained sequence and name the
retained active candidate as its predecessor. Prove that a changed ordinary
Node recovery OCI shape and a forged installer shape fail. Prove that an
unsupported state migration fails closed without a fresh root or state
deletion. Prove
that only a valid exact decommission artifact removes the retained
integration. Prove rejection for wrong key,
cluster, node, boot, expiry, reused nonce, live protected binding, forged
acknowledgement, and partial cleanup restart. Prove the exact hostile Pod
rejection and the retained BPF fallback before the two-node physical case.
Use API-server admission review objects and deterministic direct-runc runtime
gate tests in automated acceptance. Run those lightweight tests before the
current stock Kubernetes and containerd path on the retained two-node cluster.
If the physical path exposes a different result, reproduce that exact result
in the lightweight test before changing the implementation.

### D6.2.13 — Prepared-container runtime boundary

Extend the existing node binding owner. D6.2.1 owns the approved public entry
fields. Do not add a policy watcher, runtime-selected permission,
runtime-specific operation list, or generic process exemption. Containerd's
default CRI runtime invokes both ordered Mithril `createRuntime` hooks. The
first hook sends immutable
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

Match a declared entry with two facts from the same kernel exec request. At
exec syscall entry, copy bounded `argv[0]` into task-local pending request
state before a cgroup membership check. Retain it across an in-flight cgroup
attachment, and remove it when that exec commits or fails. Use this value as
the logical invocation path. Use the opened `linux_binprm.file` as the
executable backing object. Accept only a canonical absolute invocation path,
and walk only exact signed path transitions for entry admission. Run the
normal opened-file policy gate first. This split lets `/bin/sh` and another
BusyBox applet select different declared roles even when both paths resolve to
the same backing executable. Do not add `/bin/busybox` to the policy for this
case. A relative, noncanonical, or unmatched invocation path cannot install a
declared role. Keep the container-visible opened-file match for the initial
application start because a runtime can use an internal file-descriptor path
for its held initial task.

After activation, the runtime can inspect and then signal the exact initial
task to stop the container. A permitted read-only inspection prepares one
runtime-controller lineage for the exact binding and initial entry. Only that
lineage can signal that exact task. This authority does not install a role,
permit an exec, or supply admitted-entry default allow. It ends with the
runtime-controller lineage and cannot move to another binding or entry.

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
- Path-tree route tests must use both initial Kubernetes mount orders. They
  must cover a direct protected mount, a Kubernetes submount alias, a later
  in-container bind alias, `/home/*/secrets`, and `/srv/**/secrets`. The later
  bind must complete before its alias read returns `EACCES`. The lightweight
  test must reproduce each mount and result before the two-node Kubernetes
  test runs.
- Exception-writer RBAC, grant, exact Pod UID, container, duration, use bound,
  immutable spec, atomic consumption, expiry, revocation, deletion, stale
  event, overlap, replay, wrong base generation, wrong node or boot, and active
  task behavior after live base-generation migration tests.
- Compile, simulation, approval, signature, rollback, trust rotation, and
  invalid-update retention tests.
- Target snapshot drift, partial rollout, mixed generation, stop condition,
  partial artifact transfer/resume, stale acknowledgement, node reboot,
  reconnect, and capability rejection tests.
- Inactive generation, complete readback, controlled probes, one pointer
  publication, guarded per-process migration, retained birth and long-lived
  object generation, and no-Control-to-BPF-write tests.
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
- Decommission tests must prove signature and target validation, durable
  one-use nonce consumption, live-binding refusal, restart recovery, owned-path
  cleanup, containerd restart and configuration readback, BPF absence readback,
  projection cleanup only after an exact node acknowledgement, and ordinary
  Helm deletion with retained enforcement.
- The hostile privileged-Pod test must include `privileged`, `hostPID`, a host
  `/` mount at `/host`, `CAP_SYS_ADMIN`, and a read of
  `/host/etc/shadow`. The lightweight admission test must reject the same
  PodSpec. The direct-runc test must prove that the retained default-runtime
  hook rejects the equivalent OCI shape before the process creates a marker.
  It must also prove admission of a version-changed installer with the retained
  ownership shape, exact recovery after manifest replacement, and rejection of
  a changed ordinary recovery or forged installer shape. The lightweight
  policy test must prove retained-sequence continuation and rejection of a
  fresh Control root against retained Node state. The lightweight BPF test must
  deny the same physical fallback effect. All lightweight cases must pass
  before the two-node Kubernetes test runs.
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
- A known mount-root route controls path-tree evaluation without mount-age
  selection. The oldest unique mount controls only the fallback when no route
  exists. Both Kubernetes baseline mount orders and a later in-container bind
  must preserve the same denial.
- The application entry, every declared additional entry, and the approved
  administrative entry install independent roles. No entry inherits or unions
  the application role.
- `externalRole` remains the role for an unmatched independent root and never
  receives the admitted-entry default.
- Helm deletion cannot remove host enforcement. Only a valid, exact,
  independently signed decommission authorization can do that.
- The exact hostile unmatched privileged Pod rejects at Kubernetes admission
  and at the retained containerd default-runtime gate. A version-changed
  Mithril installer with the retained ownership shape can replace the host
  integration. The exact new Node recovery reopens the existing durable state
  and continues the policy chain without another host service. A direct
  non-CRI bypass hits the retained BPF incident floor.

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
evidence, the complete privileged-exception and typed unmatched-workload
matrix, and cross-node causal joins also remain excluded. Phase 7 owns the
graph and finding extension. Phase 8 consumes the Kubernetes object,
scheduler, runtime, and incident-floor facts established here for distributed
causality and adds authenticated audit history, signed privileged exceptions,
and the complete unmatched-workload floor.

## Phase Result

```text
State: Not done. The current policy and exception implementation, PreparedContainer boundary, independent entry roles, package, automated fixture, and independent manual example are present. The current direct-runc and complete automated two-node Kubernetes procedures pass. They prove guarded live-process migration to a replacement base-policy generation. The current direct-runc retained-gate probe proves exact Control and Node recovery shapes without an executable digest. The physical evidence-failure variants, watch-compaction, network-partition, storage-outage, version-changed Kubernetes recovery, and authorized final decommission remain Not run.
Implemented deliverable scope: D6.2.1 through D6.2.4 implement and automate `applicationEntry`, `additionalEntries`, `administrativeEntry`, and `externalRole`; the recorded Kubernetes fixture exercised them physically. D6.2.5 has automated intake, WAL, and capacity proof plus one healthy physical stream, but lacks the physical failure variants. D6.2.6 through D6.2.10 and D6.2.13 passed their recorded automated Kubernetes physical cases. D6.2.11 includes the passing paired lightweight and Kubernetes known-route path walk. It is partial until the retained containerd gate, exact incident denial, measured recovery, and direct non-CRI fallback pass. D6.2.12 is partial until retained installation and authorized decommission pass.
Files and durable owners changed: the branch contains both namespaced CRDs and their Helm package; PolicyDesiredStateOwner; PolicyRolloutOwner; the exception desired-state path; TrustBundleOwner; KubernetesNodeReadinessOwner; KubernetesAdmissionOwner; KubernetesWorkloadInventoryOwner; one append-only ControlStore for policy, exception, node session, trust, rollout, acknowledgement, evidence, coverage, and cursor transactions; generated NodePolicy and ControlHealth services; NodePolicyDeliveryOwner; ExceptionAuthorityOwner; RuntimeAdmissionClient; RuntimeAdmissionServer; ScheduledRuntimeBindingV1; bounded runtime-fact staging in WorkloadBindingOwner; the node activation and cgroup-binding paths; the stateless two-stage OCI adapter; the PreparedContainer binding ABI and BPF transition owner; current hook ownership; the two-node fixture; and the independent manual example. The retained containerd integration owner and measured recovery gate are not implemented.
Upstream-adoption dossier IDs used: none.
Fixture cases and exact physical results: the complete non-Kubernetes VM procedure passed with runc 1.3.4. It recorded PREPARED to ACTIVE, the declared application entry, five additional-entry roles, role-specific Deny decisions, and external-entry denial. It invoked the PostStart declaration twice. Both invocations used the same role and rule. They had distinct host PIDs, task cookies, process-state IDs, and execution IDs. The policy did not list libc or the ELF loader. Identity, observe-mode effect, protect-mode effect, kernel, and network probes also passed. The current direct-runc run used the same running application across a base-policy replacement. Its next protected effect migrated that process to the complete replacement generation. A later child exec used the replacement generation and retained the application role and entry rule. The run also passed Node-owner restart, inactive-generation retirement after holder exit, pinned-program upgrade, and owned-resource cleanup. Its evidence is `/var/tmp/mithril-runtime-qualification-3504827/generation-migration-runc-repro-run9-20260902/evidence/runc-entry-role-runtime-probe.json`. The focused replacement-exception run also passed under the replacement generation. Its evidence is `target/mithril-replacement-generation-lightweight-20260902-r12/replacement-generation-exception-probe.json`. The current complete two-node Kubernetes fixture passed with Kubernetes v1.35.5+k3s1 and containerd v2.2.3-k3s1. It updated the policy of one running Pod, observed the same application process use the replacement policy at its next protected effect, and allowed a later child exec under the replacement generation. The Pod stayed Ready with zero restarts during that migration. The same run proved scheduler-selected exact delivery, runtime and Pod lifetime replacement, bounded exception use and retirement, Control and Node restart recovery, host boot and label-epoch advance, desired-inventory cleanup, and fresh root activation. The run first removed the prior Helm release while it retained the host runtime integration. It then recovered the current Control and Node shapes through that retained gate. Its direct-runc gate probe allowed version-changed Control and Node binaries with the same exact shapes. It rejected changed recovery shapes before process start. The Kubernetes evidence is `target/mithril-generation-migration-kubernetes-20260902-d`. The direct-runc gate result is `target/mithril-generation-migration-kubernetes-20260902-d/runc-retained-runtime-gate-probe.json`.
Earlier fixture cases and exact physical results: the direct-runc application-start lane passed with runc 1.3.4. It recorded PREPARED to ACTIVE, the path-approved application entry, an application-default dependency read, no exact executable object, libc and the ELF loader absent from policy, successful exit, and owned-resource cleanup. The focused protected-start lane passed with Kubernetes v1.35.5+k3s1 and containerd 2.2.3-k3s1. It replaced Mithril and the protected Pod in the retained two-VM cluster. The policy contained `/bin/sh` as its sole execution selector. Fresh Pod UID `078ffde6-6ef9-4268-a7da-3a398e2f205e` ran as container `05bb1cc19d8b5bed04ae9058053cd907effcb18956ab65162f67f75e2daa707e` on `ubuntu-b1bfec97`. Policy revision `5c8ab1236e1d26a7bb8ec0b9bed7bda91bdabfebd669c41533c244da957afb5d` activated binding `0044aed1-8c6e-877a-a0e6-84fffdaf54c9`. The exact admitted entry reached ACTIVE. Later BusyBox applet execs received `APPLICATION_DEFAULT_ALLOW` without an exact object key or composite atom. The explicit matching Deny blocked its target. A direct CRI exec into the same container cgroup failed with `UNSUPPORTED_OBJECT`, `DENIED_BEFORE_EFFECT`, and kernel result `-13`. It did not create its marker. The result is `/tmp/phase-6-2-shell-only-entry-20260825-run13/protected-start-result.json`. These earlier results do not prove declared additional entries or the administrative entry. The complete current fixture and independent manual case now prove them. The prior old-API Kubernetes run remains partial historical evidence.
Automated verification: PreparedContainer ABI, application-default ABI, compiled BPF object, independent entry roles, repeated entry admission, complete desired-inventory validation, live-runtime retention, terminal pending-exec retirement, crash-safe stale-profile cleanup, node observation, binary WAL migration, capacity policy, Control connection reuse, VM-harness behavior, diff checks, and the complete non-Kubernetes VM procedure passed for the current source. The lightweight suites execute the Rust owners and fixture command paths. They do not read source text as a capability oracle. The repository Rust CI script passed format, workspace check, strict Clippy, and the full workspace test gate.
Platform/kernel/runtime manifests: the Helm package contains both generated closed CRDs, separate writer and Control RBAC, the exact DaemonSet reader Role, the Control Deployment and Service, fail-closed admission webhooks, the node DaemonSet, and two atomically owned `createRuntime` hook registrations. It does not yet install the approved retained containerd default-runtime integration. The complete result records Kubernetes v1.35.5+k3s1, containerd v2.2.3-k3s1, the two eligible Nodes, and the scheduler-selected Node. The scenario removed its workload namespace, policy, exception, Pods, and marker state. The VMs, K3s cluster, and current Mithril release remain available for the next physical variant.
Performance/capacity results: no new benchmark. Runtime stages are limited to 128 records and 30 seconds. PreparedContainer is designed for one exact binding and one application activation. Evidence gRPC messages are limited to 4 MiB. Policy gRPC messages are limited to 128 KiB. The Control pending evidence window is limited to 4,096 records. The node reader queue retains 65,535 records by default. The binary node WAL retains 10,000 records by default. Both node bounds are configurable. WAL capacity policy is configurable as `BLOCK` or `REWRITE`. Queue loss, capacity blocks, rewritten records, and rewritten bytes have explicit health metrics and durable coverage gaps. Health reports fixed counts and booleans only.
Unsupported/degraded paths: the physical evidence-failure, watch-compaction, network-partition, storage-outage, version-changed Kubernetes recovery, and authorized final-decommission cases are Not run on the current changed source. Phase 7 graph and finding behavior is not present.
Remaining work in this phase: run the physical evidence-failure and outage matrix. Run a Kubernetes recovery with version-changed Control and Node images. Run the authorized final-decommission case.
Next phase not authorized: yes.
```
