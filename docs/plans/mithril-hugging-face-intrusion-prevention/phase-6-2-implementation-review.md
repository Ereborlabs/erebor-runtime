# Phase 6.2 Implementation Review Guide

Status: Current implementation guide. The source implements the separate
`WorkloadProtectionPolicy` and `WorkloadProtectionException` APIs. Automated
tests cover their closed schemas, lowering, reconciliation, delivery,
retirement, restart, and node-session boundaries. The current source has not
passed the complete physical procedure. The last physical run used the old API
and stopped when stock `runc` used an anonymous file write and interprocess
communication (IPC) access that have no typed authority.

Plan: [Control Policy And Evidence Convergence](./phase-6-2-control-policy-and-evidence-convergence.md)

Design: [Validated readable architecture](./policy-and-protection-algorithm-architecture-readable.md)

## Review Goal

Verify that Kubernetes desired state has one Control owner. Verify that the
live `mithril-node` DaemonSet defines the eligible node set. Verify that the
Kubernetes scheduler selects the exact node. Verify that Control sends signed
workload material only to that node. Verify that the node holds the initial
container process until policy and cgroup-binding activation. Verify that one
durable Control transaction owns policy provenance, rollout state, trust state,
accepted evidence, and intake cursors. Verify that each node still owns its
physical generation and Berkeley Packet Filter (BPF) state.

Do not treat the deterministic two-node Control test as a physical two-node
kernel result. Do not claim that this work creates a Phase 7 graph or finding.
The BPF ABI and BPF programs did not change.

## Recommended Reading Order

1. Read the [Helm package contract](../../../packaging/mithril/helm/README.md),
   [DaemonSet](../../../packaging/mithril/helm/templates/daemonset.yaml),
   [webhook registrations](../../../packaging/mithril/helm/templates/admission-webhooks.yaml),
   and [Control RBAC](../../../packaging/mithril/helm/templates/control-rbac.yaml).
2. Read the [Kubernetes policy API](../../../crates/mithril-control/src/policy/kubernetes.rs),
   the [policy CRD](../../../packaging/mithril/helm/crds/mithril.erebor.dev_workloadprotectionpolicies.yaml),
   the [exception CRD](../../../packaging/mithril/helm/crds/mithril.erebor.dev_workloadprotectionexceptions.yaml),
   and the [API contract tests](../../../crates/mithril-control/tests/kubernetes_policy_api.rs).
3. Read the [Control configuration](../../../crates/mithril-control/src/config.rs)
   and [Control startup](../../../crates/mithril-control/src/main.rs).
4. Read the [DaemonSet node owner](../../../crates/mithril-control/src/policy/kubernetes_nodes.rs)
   and [Kubernetes workload admission](../../../crates/mithril-control/src/policy/kubernetes_workloads.rs).
5. Read the [policy desired-state and rollout owners](../../../crates/mithril-control/src/policy/reconciliation.rs)
   and the [exception desired-state owner](../../../crates/mithril-control/src/policy/kubernetes_exceptions.rs).
6. Read the [policy compiler](../../../crates/mithril-control/src/policy/compiler.rs),
   [signature types](../../../crates/mithril-control/src/policy/signature.rs), and
   [closed source types](../../../crates/mithril-control/src/policy/source.rs).
7. Read the [durable Control store](../../../crates/mithril-control/src/store.rs)
   and the [trust owner](../../../crates/mithril-control/src/trust.rs).
8. Read the [generated Control contract](../../../crates/mithril-control/proto/erebor/mithril/control/v1/control.proto),
   [service adapters](../../../crates/mithril-control/src/service.rs), and
   [server assembly](../../../crates/mithril-control/src/server.rs).
9. Read the [node configuration binding](../../../crates/mithril-node/src/config.rs),
   [node Control client](../../../crates/mithril-node/src/control.rs),
   [node policy delivery owner](../../../crates/mithril-node/src/policy_delivery.rs),
   [node event loop](../../../crates/mithril-node/src/node.rs), and
   [node generation owner](../../../crates/mithril-node/src/policy.rs).
10. Read the [OCI adapter](../../../crates/mithril-node/src/bin/mithril_oci_hook.rs),
    [runtime admission socket](../../../crates/mithril-node/src/runtime_admission.rs),
    [CRI identity verification](../../../crates/mithril-node/src/identity/runtime.rs),
    and [cgroup binding owner](../../../crates/mithril-node/src/identity/binding.rs).
11. Read the [Control evidence intake](../../../crates/mithril-control/src/evidence.rs)
   and [node observation WAL](../../../crates/mithril-node/src/observation/wal.rs).
12. Finish with the [Kubernetes API tests](../../../crates/mithril-control/tests/kubernetes_policy_api.rs),
   [reconciliation tests](../../../crates/mithril-control/tests/control_policy_reconciliation.rs),
   [contract test](../../../crates/mithril-control/tests/contract.rs), and
   [mutual Transport Layer Security tests](../../../crates/mithril-node/tests/control_tls.rs).

## Ownership Map

| State or effect | Creator | Only mutator | Durable location or effect boundary | Main proof |
| --- | --- | --- | --- | --- |
| Accepted policy source revision | `PolicyDesiredStateOwner` | `ControlStore` transaction | Append-only Control commit | Canonical CRD and offline source equality; stale UID and generation tests |
| Accepted exception and retirement revision | `PolicyDesiredStateOwner` | `ControlStore` transaction | Append-only Control commit | Bounded request, exact-target disappearance, replay, and tamper tests |
| Compiled and signed artifact | `PolicyDesiredStateOwner` | `ControlStore` transaction | Source-revision keyed artifact | Deterministic compile, signature, and issuer anti-rollback tests |
| Eligible node constraints | Kubernetes operator | Live `mithril-node` DaemonSet Pod template | Kubernetes DaemonSet | Empty, selector, affinity, and selector-change tests |
| Node readiness projection | `KubernetesNodeReadinessOwner` | `KubernetesNodeReadinessOwner` | Mithril Node label, annotations, and quarantine taint | No-session, ready-session, and selector-change tests |
| Protected Pod mutation and update validation | `KubernetesAdmissionOwner` | Kubernetes admission transaction | Persisted Pod affinity and Mithril annotations | Profile match, composition, reserved annotation, update bypass, and admission-patch tests |
| Exact scheduler binding | Kubernetes scheduler | Kubernetes API server | Pod UID and `spec.nodeName` | Binding validation code and physical manual oracle |
| Bound workload inventory | `KubernetesWorkloadInventoryOwner` | `ControlPlane` API-only inventory | Exact Pod, container, image, Node, and node-session facts | API-only authority and inventory drift tests |
| Target snapshot and node candidate | `PolicyRolloutOwner` | `ControlStore` transaction | Immutable snapshot, bundle, and rollout records | Target conflict, exact-node, mixed rollout, restart, and stale acknowledgement tests |
| Trust generation and acknowledgement | `TrustBundleOwner` | `ControlStore` transaction | Trust generation and boot-bound acknowledgement records | Rotation, revocation, restart, and current-trust gating tests |
| Node policy, exception, transfer, and cleanup state | `NodePolicyDeliveryOwner` | `NodePolicyDeliveryOwner` | Node state directory | Incremental transfer, exact readback, restart, session retirement, and terminal cleanup tests |
| Active node generation and BPF maps | `NodePolicyGenerationOwner` and existing activation path | `mithril-node` | Node-local inactive generation and active-pointer compare-and-swap | Readback, probe, pointer, and retained-generation tests |
| Runtime admission request | `mithril-oci-hook` and `RuntimeAdmissionClient` | `RuntimeAdmissionServer` | Root-owned mode-0600 Unix socket | Stock-state parser, active-owner, unavailable endpoint, convergence hold, and timeout tests |
| Runtime container binding | `ScheduledRuntimeBindingV1` and node binding owner | Node binding owner | BPF cgroup and task maps plus node delivery state | Exact signed target, policy identity, CRI match, distinct lifetime, and reuse-rejection tests |
| Accepted evidence and coverage | `EvidenceIntakeOwner` | `ControlStore` transaction | Immutable records, coverage reports, and contiguous cursors | Duplicate, gap, reorder, backpressure, storage-failure, and restart tests |
| Node WAL truncation | Node WAL owner | Node WAL owner after durable Control acknowledgement | Node WAL | Durable contiguous acknowledgement and replay tests |
| Operational health | `ControlPlane` projection | Existing owners supply counts | Authenticated `ControlHealth.Get` response | Generated contract and bounded health snapshot tests |

The custom resource definition (CRD) stores desired state. It does not store a
signed node candidate or an activation acknowledgement. Control does not write
node BPF maps. A node does not watch the CRD. The scheduler selects the exact
node. Mithril admission only restricts the eligible set.

## Simplicity Review Decisions

The review assigned the admission listener and request dispatch to
`KubernetesAdmissionOwner`. It assigned the cluster inventory loop and exact
target construction to `KubernetesWorkloadInventoryOwner`. It assigned the
runtime socket lifecycle and request dispatch to `RuntimeAdmissionServer`,
client framing to `RuntimeAdmissionClient`, and signed target resolution to
`ScheduledRuntimeBindingV1`. These changes remove lifecycle free functions
from the reviewed paths.

`PolicyDesiredStateOwner` and `PolicyRolloutOwner` remain separate. The first
owner accepts and compiles durable source authority. The second owner derives
exact workload targets and advances node rollout state. A merge would combine
two authority and recovery boundaries in one large owner.

`RuntimeAdmissionServer` and `RuntimeAdmissionReceiver` also remain separate.
The server owns the socket and concurrent request tasks. The receiver gives
the node event loop one bounded request stream. A merge would couple socket
I/O to policy convergence without removing state or a handoff.

The implementation already uses `schemars` and `kube` derives for the CRD,
`json-patch` for admission patches, and `serde` for closed protocol and state
types. The remaining private helpers implement bounded Kubernetes, cgroup, or
canonical-identity rules. A general-purpose replacement would not preserve
those fail-closed contracts. The review added no new abstraction package.

Comments identify non-obvious ownership, ordering, scheduler, replay, and
fail-closed decisions. Direct matches, validation expressions, and wiring do
not have comments that repeat the code.

## Policy Convergence Flow

```mermaid
sequenceDiagram
    participant API as Kubernetes API
    participant Admission as Control admission
    participant Scheduler as Scheduler
    participant Desired as Policy owner
    participant Rollout as Rollout owner
    participant Node as Selected node
    participant Runtime as OCI runtime
    participant Kernel as BPF state
    API->>Desired: WorkloadProtectionPolicy revision
    Desired->>Desired: Validate, compile, approve, and sign
    API->>Admission: Protected Pod create
    Admission->>API: DaemonSet constraints and ready label
    API->>Scheduler: Persist admitted Pod
    Scheduler->>Admission: Proposed Pod binding
    Admission->>Scheduler: Current selected-node validation
    Scheduler->>API: Pod UID and spec.nodeName
    Desired->>Rollout: Exact persisted workload facts
    Rollout->>Node: Target-bound signed candidate
    Node->>Kernel: Stage, read back, probe, and activate
    Runtime->>Node: Held initial PID and OCI state
    Node->>Node: Verify CRI and signed target identity
    Node->>Kernel: Publish exact cgroup and task binding
    Node-->>Runtime: Allow after active readback
    Node-->>Rollout: Boot-bound acknowledgement
```

The admission owner reads the live DaemonSet for each Node, Pod, and binding
decision. The Pod mutation combines the DaemonSet selector and required
affinity with the Pod's existing requirements. It adds the Control-owned ready
label. It rejects `spec.nodeName`, the quarantine toleration, and conflicting
selectors. It bounds the combined required-affinity terms. It reserves the
Mithril profile and source annotations. It does not choose one node.

The mutating Pod webhook runs only on CREATE. A validating webhook checks Pod
and ephemeral-container updates. An unprotected scheduled Pod cannot enter a
protected profile through an update. A protected Pod must keep its admitted
profile, source revision, selector match, and image-pin contract.

`KubernetesWorkloadInventoryOwner` lists all Pods, Nodes, Namespaces, and
Service Accounts. It accepts only persisted protected Pods with
`spec.nodeName`. It creates exact target facts for each matching container.
The facts bind the Pod UID, controller UID, ServiceAccount UID, digest-pinned
image, Node name, Node UID, node ID, boot ID, and label epoch. An inventory
change creates a new target snapshot without a policy source change.

`NodePolicy` uses resumable content-addressed chunks. A complete bundle is at
most the declared protocol bound. A partial transfer is not stageable. The node
reads each durable object by its exact digest before reuse. A node rejects
signed workload material for another node, boot, label epoch, profile, source
revision, or candidate.

The node checks the tenant, trust generation, signature, source digest,
candidate digest, artifact digests, issuer sequence, distribution sequence,
target, expiry, capabilities, and predecessor. A delayed acknowledgement
cannot change a newer candidate or a different boot session.

## Exception Convergence Flow

```mermaid
sequenceDiagram
    participant API as Kubernetes API
    participant Desired as Policy owner
    participant Store as Control store
    participant Node as Selected node
    participant Kernel as BPF state
    API->>Desired: WorkloadProtectionException
    Desired->>Desired: Resolve policy grant and exact Pod
    Desired->>Store: Commit signed activation
    Store-->>Node: Deliver activation in chain order
    Node->>Kernel: Publish bounded runtime authority
    Node-->>Store: Report active, used, or expired state
    API->>Desired: Target disappears or request deletes
    Desired->>Store: Commit exact signed revocation
    Store-->>Node: Deliver revocation after activation
    Node->>Kernel: Remove exact runtime authority
    Node-->>Store: Report terminal state
```

The exception owner accepts one namespaced request for one named base-policy
file grant. The request names one Pod UID and one container. Control derives
the selected node, boot, label epoch, active base generation, compiled cells,
deadline, and remaining use bound. The request cannot contain compiled keys,
digests, signatures, or node authority.

The accepted source stays accepted when its exact Pod target disappears.
Control commits a target-retirement transaction and signs a `REVOKE`
candidate for the original target. The store requires the latest complete
workload snapshot to prove that the target is absent. A partial inventory
cannot retire the target. A pending activation stays ahead of its revocation.
Reappearance does not activate the same exception object again. The operator
must create a new object UID.

## Node Eligibility Flow

Control reads `spec.template.spec.nodeSelector` and required node affinity from
the live `mithril-node` DaemonSet. Control rejects a DaemonSet that sets
`spec.nodeName` or uses an unsupported required-affinity operator. An empty
selector includes all nodes. There is no Control node-pool selector.

Node admission removes forged Mithril readiness and adds
`mithril.erebor.dev/not-ready:NoSchedule` to an eligible Node without a current
session. The DaemonSet tolerates this taint. The node supplies its Kubernetes
Node name through the downward API and authenticates with its unique mutual
Transport Layer Security identity. Control binds the node name and Node UID to
that session. Control adds readiness and removes quarantine only after the
current session reports kernel, identity, Control, and admission readiness.
The readiness projection requires the exact Node name and Node UID. A new Node
cannot inherit an old session through name reuse.

A session expiry removes readiness and restores quarantine. A same-name Node
UID replacement clears readiness, but it does not reset the physical policy
chain. Control creates an exact `REPLACE` candidate that names the live
predecessor and binds the new UID.

A higher label epoch is the physical reset boundary. The node opens the kernel
owner first and proves that old policy and exception authority is absent. The
node includes the canonical absence digest in its authenticated registration.
Control records the session advance, rejects old-epoch delivery and
acknowledgement messages, settles old exception state conservatively, and
permits a higher-sequence root activation. A lower label epoch or a different
boot ID at the same label epoch rejects. A normal reconnect keeps the same boot
ID and label epoch.

A DaemonSet selector change removes the Mithril projection from nodes that are
no longer eligible. The readiness owner removes both the ready label and the
Mithril quarantine taint because the node is outside the managed set. If the
node becomes eligible again, Control adds the quarantine taint before a new
ready session can remove it. A `NoSchedule` taint stops new scheduling. It does
not evict a running Pod or remove its last active local policy.

## Runtime Admission Flow

The chart installs a stateless Open Container Initiative (OCI) prestart adapter
and a protected-Pod annotation filter. The adapter reads one bounded stock OCI
state object from standard input. It derives the live cgroup from
`/proc/<pid>/cgroup`. It sends the container ID, initial PID, cgroup, and OCI
annotations to the node socket. The adapter has a client deadline. The OCI
hook entry has a larger runtime deadline.

The node socket accepts only root peers. The socket parent is root-owned and
not group-writable or world-writable. The socket has mode `0600`.
`RuntimeAdmissionServer` rejects a second live owner and removes only a stale
socket. The server bounds the request size, queue, response size, and request
time.

One early valid hook call stays pending while Control observes the binding and
the node polls for the candidate. The node event loop continues policy delivery
during this hold. The node returns `POLICY_CONVERGENCE_PENDING` only to its
local socket owner. The socket owner retries the same immutable request until
the candidate becomes active or the request deadline expires.

After convergence, the node verifies the stock Container Runtime Interface
(CRI) record. It requires the `Created` state, full container ID, sandbox ID,
namespace, Pod UID, container name, profile ID, image digest, and cgroup. It
also validates the source-revision annotation shape. It then publishes the
held PID as the sole initial root for the exact cgroup. It records the runtime
binding in durable policy-delivery state before it allows the runtime. A
container restart derives a new binding ID from the signed scheduling
authority and the new runtime container ID. It retires the previous binding.

The runtime gate rejects malformed input and an already-used runtime identity
without a convergence retry. A canonical request that has no exact local
target stays pending only until the bounded deadline. This rule also keeps an
unknown but canonical identity fail-closed. An unavailable socket, silent
owner, identity mismatch, CRI mismatch, publication failure, or persistence
failure returns a nonzero hook result. No source test replaces the physical
stock-runtime ordering oracle.

The socket owner gives each request one absolute deadline and one cancellation
signal. The node checks cancellation before and after every awaited CRI step,
before and after kernel publication, after durable publication, and before it
returns the response. A late cancellation removes the new kernel binding and
restores the prior durable delivery state. The node marks itself unhealthy if
that rollback fails.

The node splits policy transfer, coverage, and acknowledgement work into
bounded steps. Each unary Control call has a local one-second deadline. While
the node waits for a unary reply, the event loop continues to answer runtime
admission. Trust and administrative streams keep their stream lifetime. They
do not use the unary deadline.

## Evidence Transaction Flow

```mermaid
sequenceDiagram
    participant WAL as Node observation WAL
    participant RPC as mTLS evidence RPC
    participant Intake as EvidenceIntakeOwner
    participant Store as ControlStore
    participant Next as Phase 7 reader
    WAL->>RPC: Bounded evidence or coverage batch
    RPC->>Intake: Authenticated tenant, node, boot, label, source, and epoch
    Intake->>Intake: Check digests, cursors, duplicates, and pending-window bound
    Intake->>Store: Commit records and cursor together
    Store-->>Intake: Durable commit index
    Intake-->>RPC: Contiguous acknowledgement
    RPC-->>WAL: Exact acknowledged range
    WAL->>WAL: Truncate only the acknowledged contiguous range
    Next->>Store: Read immutable accepted records and provenance
```

The pending window contains at most 4,096 evidence records for one identity.
An out-of-order batch can become durable without advancing the contiguous
acknowledgement. A storage error withholds the acknowledgement. A conflicting
duplicate rejects. The intake owner does not close unknown coverage as healthy
and does not create graph edges or findings.

## Trust, Restart, And Deletion Flow

Trust generations and acknowledgements use the same store as policy and
evidence. A trust acknowledgement binds the node, generation, boot identity,
and label epoch. A revoked key cannot become current again. Policy and evidence
RPCs require the current trust generation for that node session.

Control rebuilds source, artifact, target, bundle, rollout, trust, evidence,
coverage, and cursor state by replaying the append-only commit chain. Each
commit binds its index, predecessor digest, transaction, and digest. Control
writes the file, calls `fsync`, renames it, and calls `fsync` on the parent
directory. A corrupt chain or incompatible record blocks store open.

CRD deletion and exact-target disappearance create signed restrictive-terminal
candidates. Each terminal candidate names the exact viable predecessor and
uses the normal node stage, readback, probe, and pointer path. Deletion alone
does not erase a node generation. Kubernetes deletion can keep the same object
generation. The store accepts only the exact accepted-to-deleting transition
at that generation. A complete relist retires a durable live source that is
absent from the API snapshot. A partial relist does not retire a source.

An active terminal acknowledgement can authorize chain cleanup only when no
later viable candidate depends on that terminal. Control stores this decision
in the acknowledgement transaction. The node stores the authorization before
it removes the terminal bundle, transfer state, active pointer, and generation.
Control then suppresses the closed chain from later inventory. A recreated
policy object receives a higher issuer sequence and a new root `ACTIVATE`.
If a successor already depends on the terminal, cleanup stays denied and the
node continues that predecessor chain. Rejected and stale descendants do not
become viable heads.

## Kubernetes And Tenancy Boundary

The CRD is namespaced, has one served storage version, and has a closed
structural schema with string, list, and object bounds. The supported write
path uses strict field validation and supplies the canonical submitted-spec
digest. Control rejects a stored spec that differs from that submitted digest.

Control derives tenant, cluster, and namespace identity from configuration and
API records. A policy field, annotation, label, or status cannot select its own
tenant. A matching policy in the Pod namespace selects protection. There is no
separate protected-tenant or protected-namespace configuration.

The Helm ClusterRole can read policies, exceptions, Namespaces, Pods,
ServiceAccounts, and Nodes across the cluster. It can patch policy and
exception status. It cannot create, update, patch, or delete desired state.
Separate writer roles own policy and exception input. The namespaced Role
restricts DaemonSet access to `mithril-node`. Control has Node patch permission
because built-in RBAC cannot grant field-level patch permission. The readiness
owner patches only the Mithril label, four identity annotations, and the
quarantine taint. The node service account has no token and no Kubernetes
permissions.

Status is a bounded projection. Policy status has the observed generation,
aggregate desired, active, updating, and failed counts, and standard
conditions. Exception status has the observed generation, one bounded state,
and standard conditions. Status has no digest, signature, receipt, compiled
cell, or per-node array. A status change cannot sign, distribute, activate, or
consume authority.

## Operational Health Boundary

`ControlHealth.Get` uses the existing mTLS listener. The caller needs an
enrolled, registered node session with the current trust generation. The reply
contains only fixed counters and booleans. It reports reconciliation work,
Control commit state, watch and relist state, compile results, target and
rollout counts, node session counts, and evidence cursor and pending counts.

The desired-state owner processes one cluster-wide CRD watch. It relists after
a watch closure or compaction. `KubernetesWorkloadInventoryOwner` uses one
bounded cluster inventory loop. The Node readiness owner reads every page of
the Node snapshot before it starts a watch. `watch_healthy` is true only when
the cluster watch is active after a successful relist.

## Packaging Boundary

The chart mounts one host-provisioned node configuration and mTLS identity on
each selected host. The downward API overrides the Kubernetes Node name. In
Kubernetes mode, the node reads `/proc/self/cgroup` and binds the
effect-controller cgroup to its actual DaemonSet Pod lifetime. One static Pod
cgroup path is not accepted as scheduling authority.

The Control Deployment mounts its configuration, durable volume, and separate
admission TLS Secret. The admission certificate authenticates
`mithril-control.<namespace>.svc`. The chart requires the CA bundle and registers
fail-closed Node mutation, Pod CREATE mutation, Pod UPDATE validation, and
Pod-binding validation webhooks. Kubernetes and server request timeouts are
bounded. The chart rejects an OCI client timeout that has no outer runtime
margin. The HTTPS `/healthz` route contains no policy payload.

The node image contains `mithril-node` and `mithril-oci-hook`. A chart-owned
host installer publishes the hook configuration before the binary by atomic
same-directory rename. Adjacent ownership markers bind both exact paths to the
Helm release. Disable and uninstall hooks remove only matching owned paths. A
bounded pre-delete cleanup Job waits for selected-node cleanup before it
deletes the cleanup DaemonSet. Foreign or unmarked files fail closed and stay
in place.

CRI-O can consume the standard hook directory. Containerd needs the stock Node
Resource Interface hook-injector. The chart does not patch the container
runtime and does not install a custom runtime binary.

## BPF Boundary

This phase does not change a BPF program or frozen BPF application binary
interface (ABI). The userspace owners install and remove rows through the
existing [`KernelHost`](../../../crates/erebor-interceptor/src/host.rs). The
effect programs remain in the
[`identity` BPF object](../../../bpf/erebor-interceptor/programs/identity.bpf.c).

```mermaid
flowchart LR
    Node[mithril-node] --> Host[KernelHost]
    Host --> Object[identity BPF object]
    Object --> Programs[LSM, cgroup, tracepoint, and task programs]
    Node --> Maps[Pinned policy and binding maps]
    Programs --> Maps
    Programs --> Evidence[Effect evidence]
    Evidence --> WAL[Node observation WAL]
```

| Map | Key and value ABI | Userspace writer | BPF writer | Readers | Lifetime |
| --- | --- | --- | --- | --- | --- |
| `active_profile_generations` | `Id128V1 -> u64` | Node policy generation owner | None | Node binding owner and effect gates | Pinned for the current kernel owner; terminal cleanup removes the exact profile pointer |
| `profile_generation_descriptors` | `u64 -> ProfileGenerationDescriptorV1` | Node policy generation owner | None | Node recovery, binding owner, and effect gates | Pinned until generation retirement and reference readback permit removal |
| `execution_set_bindings` | `u64 cgroup ID -> ExecutionSetBindingStateV1` | Node binding owner | Task lifecycle programs can update lifecycle state | Node recovery and effect gates | Pinned for the exact runtime cgroup lifetime |
| `binding_activation_targets` | `BindingActivationTargetKeyV1 -> ExecutionSetBindingStateV1` | Node binding owner | None | Node recovery and runtime gate | Pinned until the exact binding and generation retire |
| `exception_runtime_states` | `ExceptionRuntimeStateKeyV1 -> ExceptionRuntimeStateV1` | Node exception owner | Effect gate consumes uses under the map value lock | Node recovery and exception gate | Pinned until the instance is terminal and durable receipts permit cleanup |
| `exception_handle_bindings` | `ExceptionHandleBindingKeyV1 -> ExceptionHandleBindingV1` | Node policy and exception owners | None | Exception gate and recovery | Pinned for the exact compiled handle and active instance |
| `exception_use_receipts` | Receipt identity -> bounded use receipt | Node exception receipt owner | Effect gate emits use receipts | Node receipt recovery | Pinned until the durable exception WAL records the receipt |

A bpffs pin keeps a map or link alive after the loader process exits. A
process restart does not remove a pin. `KernelHost` validates and reuses the
owned pin set. The node delivery and generation owners remove only exact rows
after readback proves that their authority is terminal. A boot loses the bpffs
objects. Startup then requires the old-session absence proof before Control can
open a new root chain.

The ABI readers use `FromBytes::read_from_bytes` for all-bit-valid exact-size
values such as `u64`. They use `TryFromBytes::try_read_from_bytes` for types
that contain checked enum states. Both methods reject the wrong byte size. A
rejected value becomes a typed node identity or policy error before a map
change. Review the exact map declarations and effect-gate lookups in
[`identity_maps.h`](../../../bpf/erebor-interceptor/programs/identity_maps.h).

## ABI And Protocol Boundary

This implementation adds the Kubernetes source types, Control store records,
policy delivery messages, and one authenticated health method. It uses the
generated `erebor.mithril.control.v1` contract. It does not add a generic
envelope, frame protocol, or compatibility dispatcher.

No BPF map, BPF program, kernel hook, or frozen ABI type changed. The node uses
the existing generation-building and active-pointer path. The evidence record
and coverage messages remain the Phase 6 types.

## Failure Boundaries

| Input or failure | Required behavior |
| --- | --- |
| Missing or invalid live DaemonSet constraints | Node, Pod, or binding admission rejects; stale readiness cannot authorize a new protected Pod |
| Node without an exact current name-and-UID session | Control removes readiness and adds the quarantine taint |
| Protected Pod with `spec.nodeName`, quarantine toleration, reserved annotation, or excessive affinity product | Pod admission rejects before persistence |
| Pod or ephemeral-container update changes protection state | Validating admission rejects the update and keeps scheduling unchanged |
| Scheduler selects an ineligible or stale Node | Binding admission rejects before the binding persists |
| Unknown or silently pruned CRD field | Strict decode or submitted-spec digest rejects before compilation |
| Stale UID, generation, historical replay, or watch event | Durable source ordering rejects; the prior valid rollout remains |
| Duplicate policy match or exact workload claim | Conflict rejects; no precedence rule selects a winner |
| Compile or signature failure | No candidate or rollout is created for that source revision |
| Partial or corrupt bundle | Node does not create a stageable pending activation |
| Wrong tenant, target, boot, label, trust, or sequence | Service or node rejects before rollout advancement |
| Early valid OCI prestart request | The socket holds the request while the exact candidate converges, within the configured deadline |
| Missing candidate, silent node owner, or second socket owner | The bounded socket or OCI deadline returns denial; the runtime does not receive an allow result |
| Malformed, mismatched, or reused runtime identity | The node rejects without publishing or reusing a binding |
| Mixed rollout | Status reports exact per-state counts; it does not claim global activation |
| Exact target disappears while an exception is active | Control keeps the source accepted and sends an exact signed revocation; it does not refund uses or retarget the request |
| Runtime admission caller cancels after publication starts | The node removes the exact new binding and restores the prior durable state; an incomplete rollback closes readiness |
| Node disconnect or Control outage | The last valid node generation stays active |
| Same-name Node gets a new UID | Readiness closes until the new API object binds; the next policy candidate names the live physical predecessor |
| Higher label epoch after proved map loss | Control stales the old session and permits a higher-sequence root; old-epoch delivery and acknowledgements reject |
| Watch closure or compaction | Control completes every list page, retires absent durable sources, and starts a new watch. A partial relist retires nothing |
| Control restart | The store replays the commit chain; in-memory watch state is rebuilt |
| CRD deletion or forced object removal | A Deleted event or complete relist creates retirement. No direct BPF removal occurs; only a valid signed retirement can change node policy |
| Active terminal has no viable successor | The acknowledgement authorizes durable node cleanup and Control suppresses the closed chain from inventory |
| Evidence gap within the bound | Batch stays pending; the contiguous acknowledgement does not advance |
| Evidence storage failure | No acknowledgement returns; the node keeps its WAL records |
| Conflicting evidence duplicate | Intake rejects and preserves the first immutable record |
| Health request from an untrusted session | mTLS, registration, or current-trust checks reject |

## Verification Map

| Proof | Source |
| --- | --- |
| Closed CRD, generated manifest equality, canonical source equality, silent-prune rejection, and status bound | [Kubernetes policy API tests](../../../crates/mithril-control/tests/kubernetes_policy_api.rs) |
| DaemonSet derivation, complete Node snapshot, scheduler choice, quarantine, exact Node UID readiness, empty constraints, and selector change | [Kubernetes node tests](../../../crates/mithril-control/src/policy/kubernetes_nodes.rs) |
| Policy match, additive and bounded Pod constraints, reserved annotations, Pod update bypass rejection, selector-consistent image pinning, admission patch, and health | [Kubernetes workload tests](../../../crates/mithril-control/src/policy/kubernetes_workloads.rs) |
| Policy and exception create, update, conflict, stale state, target disappearance, chain order, node UID rebind, physical epoch reset, terminal cleanup, restart, and tamper rejection | [Control reconciliation tests](../../../crates/mithril-control/tests/control_policy_reconciliation.rs) |
| Exact generated gRPC inventory, including `ControlHealth.Get` | [Control contract test](../../../crates/mithril-control/tests/contract.rs) |
| Commit chain, compare-and-swap transitions, evidence atomicity, pending bounds, restart replay, and trust persistence | [Control store tests](../../../crates/mithril-control/src/store.rs) |
| Evidence identity, duplicate, reorder, cursor, coverage, and stable Phase 7 query | [Evidence intake tests](../../../crates/mithril-control/src/evidence.rs) |
| Trust install, acknowledgement, revocation, anti-rollback, and restart | [Trust owner tests](../../../crates/mithril-control/src/trust.rs) |
| mTLS identity, boot session, trust gate, policy chunk, acknowledgement, evidence, and service isolation | [Control TLS tests](../../../crates/mithril-node/tests/control_tls.rs) |
| Incremental chunk assembly, signature and digest checks, pending recovery, old-session cleanup, terminal cleanup, exact target inspection, and acknowledgement replay | [Node policy delivery tests](../../../crates/mithril-node/src/policy_delivery.rs) |
| Existing inactive generation, readback, probes, and pointer activation | [Node policy tests](../../../crates/mithril-node/src/policy.rs) |
| Signed scheduling authority, exact policy and runtime identity, distinct container lifetime, active socket ownership, convergence hold, unavailable endpoint, and timeout denial | [Runtime admission tests](../../../crates/mithril-node/src/runtime_admission.rs) |
| OCI state parsing and cgroup-v2 path parsing | [OCI adapter tests](../../../crates/mithril-node/src/bin/mithril_oci_hook.rs) |
| Webhook TLS, rules, deadlines, health probes, DaemonSet identity and hook inputs, and least-privilege RBAC | [Helm render test](../../../packaging/mithril/helm/tests/verify.sh) |
| Exact two-node target, task lifetime, Node UID replacement, host epoch, selector lifecycle, exception target retirement, terminal cleanup, and no-root replay | [Physical fixture](../../../crates/mithril-e2e/harness/vm/two-node-convergence.sh) |
| Independent operator flow for exact target, runtime lifetime, exception target retirement, terminal cleanup, restart, and fresh root | [Manual example](../../../examples/mithril-kubernetes-convergence-manual/run.sh) |

Current automated closure checks passed:

```text
rtk bash .github/scripts/verify-rust-ci.sh
Passed format, workspace check, strict Clippy, and the full workspace test gate.

Mithril Control library
89 passed

Mithril Control reconciliation
28 passed

Kubernetes policy API
6 passed

Mithril node library
150 passed

Mithril OCI adapter
2 passed

Mithril node mTLS integration
5 passed

rtk bash packaging/mithril/helm/tests/verify.sh
Hook ownership checks passed. One chart linted. The render contract passed.

rtk bash crates/mithril-e2e/harness/vm/test.sh
VM harness behavior checks passed.

rtk bash examples/mithril-kubernetes-convergence-manual/test.sh
Manual example behavior checks passed.
```

These checks execute production owners and fixture command paths. The shell
behavior suites do not parse Rust or shell source as a capability oracle. They
do not replace the physical fixture or manual run.

## Verification Limits

The current source has not passed the physical two-node fixture or the
independent manual example. Both flows now contain exact target, runtime task,
exception target-retirement, terminal cleanup, restart, and fresh-root
oracles. The automated fixture also contains same-name Node UID replacement,
DaemonSet exclusion and re-entry, and a host boot and label-epoch change.
Those scripted cases remain `Not run` until one physical execution records a
result.

The last physical two-node run used the superseded flattened API. It passed
readiness, typed RBAC review, admission mutation and bypass rejection,
scheduler selection, selected-node delivery, policy activation, runtime
binding, Control acknowledgement, and durable evidence intake. Stock `runc`
then used an anonymous file write and IPC access that have no typed authority.
BPF denied both operations. The runtime reported start failure. The application
did not run.

The stock-runtime failure remains a product blocker. It is not test noise.
Do not add a broad runtime, pipe, socket, or process exemption. Completion
requires approval for a signed, typed, bounded runtime-bootstrap authority
with an exact helper identity and bounded helper-to-target handoff. The
watch-compaction, network-partition, storage-outage, and physical evidence
failure variants also remain `Not run`. There is no new performance result.

This work adds no Appendix C fixture ID. Phase 7 graph and finding behavior is
not present.

## Reviewer Checklist

- [ ] Compare the generated CRD with the committed Helm CRD.
- [ ] Change the DaemonSet selector and trace the readiness projection change.
- [ ] Replace a Node UID under the same name and verify that readiness does not transfer.
- [ ] Verify that Pod admission composes constraints and does not set `spec.nodeName`.
- [ ] Verify that Pod and ephemeral-container updates cannot add, remove, or replace protection.
- [ ] Trace the scheduler-selected Pod binding through current-session validation.
- [ ] Trace one CRD generation into one immutable source revision.
- [ ] Trace one persisted Pod UID and selected Node into one target snapshot.
- [ ] Trace one source revision through compilation, signature, and exact-node delivery.
- [ ] Verify that a duplicate profile or workload claim creates no candidate.
- [ ] Trace one candidate through bounded chunks and exact node digest readback.
- [ ] Trace node activation through inactive state, probes, and one pointer compare-and-swap.
- [ ] Trace one held OCI PID through CRI verification and exact cgroup publication.
- [ ] Verify that a missing candidate stays pending only until the runtime deadline.
- [ ] Verify that a second runtime socket owner cannot replace the live node owner.
- [ ] Verify that container restart retires the old runtime binding.
- [ ] Verify that Control changes rollout state only after the exact authenticated acknowledgement.
- [ ] Trace one evidence retry from the node WAL to a durable contiguous acknowledgement.
- [ ] Verify that an out-of-order evidence batch does not advance the acknowledgement.
- [ ] Restart Control and compare the rebuilt source, rollout, trust, evidence, and cursor state.
- [ ] Trace terminal acknowledgement, cleanup authorization, empty inventory,
      restart, no closed-root replay, and fresh-root recreation.
- [ ] Remove an exception target and verify exact revocation without use refund.
- [ ] Verify that a complete relist retires a missing source and a partial relist does not.
- [ ] Inspect the health reply and confirm that it contains no policy, evidence, or secret payload.
- [ ] Confirm that no Control path writes BPF maps or the node active pointer.
- [ ] Confirm that the node service account has no token or Kubernetes RBAC.
- [ ] Run the final repository gate after any Rust change.

## Source State

This guide covers the current phase branch after the policy API, exception,
rollout, node-session, node cleanup, Helm hook, automated fixture, and manual
example deliverables. Reviewers must compare the guide with the checked-out
source. The physical verification limits above remain part of the result.

Completion of this work does not authorize the next phase.
