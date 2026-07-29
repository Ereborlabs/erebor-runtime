# Hugging Face Agent Intrusion: Erebor Defender Implementation Analysis

Status: source-backed, implementation-level design proposal. This document
approves no implementation, deployment, dependency, privilege, or automatic
response. Concrete manifests and interfaces are included so an engineer can
implement them or object to a named assumption.

Related source record: [Published Live Action
Stream](hugging-face-agent-intrusion-live-action-stream.md).

## What this document must make implementable

The useful Defender question is not “which tools might help?” It is:

> For each published attacker action, which component receives which event,
> which stable identifiers connect the event to the compromised workload,
> which deterministic predicate changes state, which actuator may respond,
> and which postcondition proves the result?

This document answers that question for one reference asset class:

```text
asset class: Kubernetes dataset-conversion worker
input trust: attacker-controlled dataset revision
cloud: AWS/EKS-like node and workload identity
network: Defender cgroup/socket/packet enforcement plus optional CNI flow source
kernel source: Defender-owned CO-RE eBPF lifecycle, BPF LSM, and cgroup programs
control-plane source: raw Kubernetes audit events
external sources: cloud, mesh-network, connector, and GitHub audit/API
```

No third-party sensor is an architectural prerequisite. Existing products can
be adapters or independent corroboration. The kernel hooks, event fields,
joins, failure states, response scope, and verification requirements are the
contract.

## Scope: which side Erebor Defender can control

This analysis is entirely about a Defender deployment. The Defender node
plane owns the Linux sensor/enforcer and native task/process identity.
Defender's service owns evidence, correlation, authorization, and defensive
response. It neither requires nor reuses Erebor Runtime Sessions, Runtime
surface policy, or Runtime action leases. In this document, **container
runtime** means the OCI/CRI infrastructure that creates container processes.

### Deployment preservation is the first constraint

The baseline Defender product must work against the deployment that exists. It
may install Defender-owned node/runtime integration, evidence collectors,
correlation services, and approved enforcement programs. It must not require
the protected system to change:

- application code, parser, framework, or agent harness;
- one job per Pod/process, a new supervisor, sidecar, broker, or application
  event;
- controller topology, Pod template, mounted credentials, ServiceAccount,
  RBAC, IAM, network route, or provider identity; or
- how existing controllers authenticate to and use the Kubernetes API.

This document therefore uses three classes:

| Class | Meaning | Defender behavior |
| --- | --- | --- |
| **D — deployment-preserving Defender capability** | observation, attribution, detection, or effect enforcement applied by Defender to existing processes, cgroups, sockets, credentials, API audit, and provider identities | may be a Defender implementation requirement; enforcement still rolls out monitor-first and requires an approved policy |
| **H — operator hardening recommendation** | manifest, ServiceAccount, RBAC, IAM, admission, network, launch-template, or secret-distribution change | inventory, simulate, explain, and verify if the operator adopts it; never make it a prerequisite or claim it was applied |
| **R — application or deployment redesign** | parser change, admission scanner, new broker/capability service, split principal, new work-item protocol, or changed scheduling model | report as remediation/design advice only; never represent it as a Defender capability |

Defender returns H/R advice as a typed proposal, not as a fake control result:

```text
DeploymentRiskFinding {
  current_state_evidence[]
  exposed_principal_resource_or_path
  effective_authority_and_observed_use
  attack_path_enabled
  deployment_preserving_protections_active[]
  residual_limit
}

HardeningProposal {
  proposal_id
  class: H | R
  finding_id
  owner: application | platform | cluster | identity | provider
  proposed_change
  expected_risk_reduction
  compatibility_and_availability_risks[]
  affected_workloads_and_principals[]
  simulation_or_review_steps[]
  verification_if_adopted[]
  state: proposed | accepted_externally | observed_applied | rejected | stale
}
```

`proposed` is not `executed`. Defender may observe and verify a later external
change, but it cannot move the proposal to `observed_applied` without
authoritative deployment evidence.

The no-change baseline is an acceptance target, not a temporary migration
state. Every finding and response must still say what becomes fundamentally
ambiguous in the existing deployment. For example, if legitimate controller
code and injected code use the same process, Kubernetes client, TLS
connection, and ServiceAccount, Linux cannot distinguish the two API
operations. Defender must use API-server audit for semantics and may only
contain at the proven process/socket/cgroup or identity boundary.

Events `HF-001` through `HF-007` happened in an external evaluation sandbox.
A Defender deployed by Hugging Face cannot observe or control that sandbox.
What protected or failed to protect that external sandbox belongs to its
operator and is outside this Defender deployment's authority boundary.

Hugging Face-side prevention and response begin at `HF-008`, when an
attacker-controlled dataset enters Hugging Face infrastructure:

```text
OpenAI-operated external sandbox             Hugging Face-operated estate
HF-001..HF-007                               HF-008..HF-021
        │                                           │
        │ dataset/API requests over public boundary │
        └───────────────────────────────────────────►

HF Defender may:
  - report a malicious revision and request quarantine when an existing
    authenticated platform connector identifies that exact revision;
  - quarantine a revision only when application or platform evidence identifies
    that exact revision;
  - constrain the conversion worker;
  - observe and contain Hugging Face workloads and identities;
  - revoke Hugging Face-owned provider capabilities.

HF Defender may not:
  - require a new dataset scanner, broker, ServiceAccount, RBAC model, or
    workload topology as a condition of protection;
  - terminate the external sandbox;
  - inspect its local kernel;
  - claim control over the agent that originated the requests.
```

## What the public timeline establishes

The published chain contains two distinct application failures:

1. HDF5 external raw storage caused a local-file disclosure without code
   execution.
2. A data-derived Jinja2 expression caused Python execution inside an existing
   conversion worker.

The expansion then crossed these boundaries:

```text
dataset revision
  → conversion job
  → long-running Python worker
  → projected Kubernetes token and process environment
  → Kubernetes API and EC2 instance metadata
  → node and CSI identities
  → privileged host-mounted Pods
  → node root and cluster Secrets
  → static database, mesh, and connector credentials
  → other clusters, AWS, and GitHub
```

The article also says several security layers emitted signals and an AI-based
system correlated them, but the result did not receive the criticality and
on-call escalation needed for a fast response. Therefore the required product
is not another severity label. It is a deterministic path from attributable
evidence to a narrowly authorized physical response.

## Reference deployment

The minimum buildable Defender addition preserves the existing dataset worker,
its controller, credentials, RBAC, network, and job model:

```text
0. Existing protected deployment
   unchanged worker/controller manifests and application architecture
   existing ServiceAccounts, credentials, RBAC, IAM, and network access
   one or many concurrent jobs in one Pod and one or many processes

1. Defender node lineage and enforcement plane
   task creation/exec/exit + inherited in-kernel task labels
   synchronous exec/file/socket/device/security decisions
   loss, attachment, policy-version, and capability evidence

2. Defender network plane
   process-context socket controls + cgroup/packet policy
   flow verdicts + socket/cgroup/endpoint/IP identity history

3. Existing Kubernetes control-plane evidence
   raw audit events when enabled
   object UID/resource-version/owner-reference/binding history
   effective RBAC inventory; missing audit is a coverage gap, not a mandate to
   change the workload

4. Defender provider adapters
   AWS + mesh + connector + queue + artifact + GitHub audit
   narrowly scoped response APIs

5. Erebor Defender service
   raw intake → node-local task/exec graphs → effect attribution
              → typed distributed causal lineage + expected-graph diff
              → finding → authorized local/distributed response
```

Existing products may supply parts of these contracts, but the architecture is
defined in terms of Linux and control-plane mechanisms. Defender implements any
missing sensor or actuator itself. Optional application/platform audit can add
existing work-item, dataset-revision, and scheduler facts; it is useful
enrichment, never a prerequisite for Linux workload defense.

An admission scanner, parser fix, Pod Security policy, RBAC reduction,
workload identity migration, per-operation credential broker, or provider
principal split can improve the outcome. Those are H/R recommendations. They
are not part of the minimum Defender deployment and cannot appear in its
baseline acceptance criteria.

## Operating constraint: Defender must fit the deployed worker

Defender must not require one conversion job per Pod, one cgroup per job, a new
supervisor protocol, or a Defender-specific job event. A production Pod may
handle many jobs concurrently. Some jobs may create subprocesses; others may
run entirely inside the same Python interpreter. Defender observes that
reality and states the attribution it can actually prove.

The same rule applies to authority. A Kubernetes controller may legitimately
need its projected ServiceAccount token and API connection. A cloud or storage
worker may legitimately need its existing role. Defender profiles and protects
those existing subjects; it does not define “secure” as removing everything
the workload needs and then mark the original deployment unsupported.

The central Linux enforcement question is:

> Does this live task belong to the actual Pod task tree; does its exec edge
> belong to the approved process graph for this immutable workload; and do its
> file, network, privilege, and control-plane effects belong to the approved
> effect set for its role?

This produces three distinct findings that the previous design incorrectly
collapsed:

```text
actual task exists, but its parent/exec edge is not approved
  → unexpected process-graph deviation

known and approved process performs a prohibited file/socket/security effect
  → unexpected process-effect deviation

an effect refers to no reconstructable live task/exec node
  → orphan effect or lineage coverage gap; investigate, but do not pretend
    the missing edge proves compromise
```

Process lineage is the native execution spine. It is not the complete semantic
truth.
An in-process `exec()` in Python creates no Linux exec event. An HTTP request
inside an existing connection may create no new connect event. Provider and
Kubernetes audit remain necessary for those effects.

## Actual task and execution graph

Linux has three related identities that Defender must not conflate:

- a **task instance** is one kernel task/thread created by `fork`, `vfork`,
  `clone`, or `clone3`;
- a **process instance** is one thread group and the stable policy/response
  scope assigned when that group is created; its tasks normally share an
  address space and other resources, but the model does not assume every
  resource remains shared after `unshare` or descriptor passing; and
- an **execution instance** is one executable image installed into that process
  by `execve` or `execveat`.

A task can create a new thread in its existing process or a child process that
never execs. A process can exec a new image without changing its TGID. Therefore
the graph stores all three:

```text
TaskInstance {
  task_instance_id: SHA256(
    tenant_id, cluster_uid, node_boot_id, label_epoch, task_cookie)
  label_epoch: UUID
  task_cookie: u64
  process_instance_id: ID
  cluster_uid: UUID
  node_name: String
  node_boot_id: UUID
  pod_uid: UUID
  container_id: String
  cgroup_path: String
  cgroup_id: u64
  host_tid: u32
  host_tgid: u32
  namespace_tid: u32?
  namespace_tgid: u32?
  task_start_boottime_ns: u64
  native_coordinate_history: [NativeTaskCoordinateInterval]
  parent_task_instance_id: ID?
  created_at: Timestamp
  exited_at: Timestamp?
  lineage_state: complete | bootstrapped | missing_parent | source_gap
}

NativeTaskCoordinateInterval {
  host_tid: u32
  host_tgid: u32
  namespace_tid: u32?
  namespace_tgid: u32?
  task_start_boottime_ns: u64
  observed_from: Timestamp
  observed_until: Timestamp?
  change_reason: created | namespace_change | de_thread_exec | bootstrap
}

ProcessInstance {
  process_instance_id: SHA256(
    tenant_id, cluster_uid, node_boot_id, label_epoch, process_lineage_id)
  label_epoch: UUID
  current_leader_task_instance_id: ID
  leader_task_instance_history: [ID]
  parent_process_instance_id: ID?
  process_lineage_id: u64
  ancestor_process_lineage_ids: [u64]
  created_at: Timestamp
  exited_at: Timestamp?
}

ExecutionInstance {
  execution_instance_id: ID
  process_instance_id: ID
  exec_task_instance_id: ID
  source_exec_ids: Map<SourceKind, String>
  origin: container_root | inherited_on_fork | execve | execveat
  inherited_from_execution_instance_id: ID?
  previous_execution_instance_id: ID?
  binary_path: String
  binary_identity: BinaryIdentity
  argv: RedactedArgv
  cwd: String
  uid_gid_capabilities: Struct
  namespaces: Struct
  image_digest: Digest
  started_at: Timestamp
  ended_at: Timestamp?
  source_observation_ids: [ID]
}
```

The primary identity is not a PID tuple. At label-generation startup, the node
creates a fresh `label_epoch`. A pinned atomic counter allocates one
never-reused `task_cookie` at task creation and one
`process_lineage_id` whenever creation makes a new thread group. Threads
inherit the latter. An `exec` retains both cookies.

This distinction matters for a non-leader thread that calls `execve`: Linux
de-threads the group, terminates the old leader, and changes the calling
task's visible TID to the TGID. A task ID derived from TID would change in the
middle of its lifetime. Defender instead records TID, TGID, start-boottime, and
namespace IDs as time-bounded native coordinates used for lookup and
revalidation; the task cookie remains its graph identity. The label epoch
prevents cookie collisions if pinned state must be rebuilt. A loader restart
must reuse the pinned epoch and counter. Loss of that state while labeled
tasks survive is a coverage and enforcement transition requiring a new
bootstrap transaction, never a silent counter reset.

Source-native IDs such as Tetragon `exec_id` are retained only as adapter join
keys. The full container ID comes from the OCI/CRI container runtime; a shortened ID
is not accepted as the sole actuator target.

### Node mechanism: race-free lineage and synchronous enforcement

The reference node plane is a Defender-owned CO-RE eBPF sensor/enforcer. It does
not wait for a userspace process-tree database before deciding whether a child
may execute or a process may cross a sensitive boundary.

| Need | Linux mechanism | Defender behavior |
| --- | --- | --- |
| label a child before it runs | BPF LSM `task_alloc` | for `CLONE_THREAD`, inherit the same process identity/role; otherwise allocate a child process lineage and copy its ancestor vector before it can run |
| record every fork/clone/vfork | `sched_process_fork` BTF tracepoint | emit parent and child native task keys, including children that never exec |
| authorize executable transition | BPF LSM `bprm_check_security` | look up the current role and candidate file identity; deny an absent edge before the new image runs |
| commit execution identity | `sched_process_exec` and a version-tested post-exec hook | close the prior image, assign the approved resulting role, and emit the `ExecInstance` |
| close task lifetime | `sched_process_exit` | emit exit and let task-local storage be freed with the task |
| recover tasks present at attachment | BPF task iterator plus `/proc` and container-runtime inventory | create explicitly `bootstrapped` nodes and refuse to claim their missing creation edges were observed |

The task-local label is conceptually:

```text
TaskLabel {
  workload_instance_id
  label_epoch
  task_cookie
  process_profile_id
  process_profile_version
  role_id
  process_lineage_id
  lineage_depth
  ancestor_process_lineage_ids[MAX_PROFILE_DEPTH]
  response_state: normal | restrict_effects | freeze_pending
}
```

`BPF_MAP_TYPE_TASK_STORAGE` is the preferred implementation because the label
is attached to the kernel task and is cleaned up with it. The target-kernel
prototype must prove that the verifier permits the required storage operations
at each selected hook. If a supported kernel lacks that combination, Defender
uses an in-kernel map addressed by current native task coordinates, retains the
stable cookie in its value, and atomically rekeys the entry when a non-leader
exec changes the visible TID. It still requires an equally early fork hook. A
fallback is enforcement-capable only after stress tests prove both that a
child cannot run a protected effect before receiving its inherited label and
that de-threading cannot expose an unlabeled interval. Otherwise that node
class is observation-only, not silently weaker enforcement.

The bounded ancestor vector makes later subtree restriction synchronous. At
`task_alloc`, a new thread inherits the same process lineage; a new process
copies the parent's vector and appends the parent process-lineage ID before it
can run. Every protected LSM hook checks the current process-lineage ID and
ancestor vector against `response_roots`. Inserting one process root therefore
restricts all its existing and future descendant processes on their next
protected effect without waiting for userspace enumeration. Each profile
declares a maximum process depth no larger than the compiled bound; attempting
to exceed it is denied or moves the response guarantee to the cgroup scope.

The container's initial task is created by the OCI container runtime rather
than by an already managed worker parent. Defender does not create the
namespaces, mounts, cgroup, or container-init process. In explicitly approved
enforce-from-start mode, root admission is a coordinated handoff with explicit
ownership:

| Order | Owner | Required operation |
| --- | --- | --- |
| 1 | CRI/OCI implementation | create or join the configured namespaces, prepare mounts and the container cgroup, create the container-init task, place it in the intended cgroup, and keep the container in the OCI `created` state so the user-specified program has not executed |
| 2 | CRI shim/runtime integration | provide authenticated CRI and runtime identity to the Defender binder: cluster/Pod UID, sandbox and full container ID, immutable image digest, cgroup FD/ID, container-init PID/pidfd, and the runtime lifecycle generation |
| 3 | Defender binder | re-resolve those live objects, select the approved profile generation, and install the exact cgroup-to-profile binding and required BPF links/maps |
| 4 | Defender binder and node enforcer | initialize the root task/process label on the runtime-held init task through a target-kernel-proven pidfd-addressed task-storage update or iterator path, then read it back and verify the cgroup, Pod, container, node boot, label epoch, task cookie, and process-lineage binding |
| 5 | Defender verifier | run the generation-specific link/map checks and controlled allow/deny probes, then return a single-use admission acknowledgement bound to the runtime/container/generation transaction |
| 6 | CRI/OCI implementation | accept only the matching acknowledgement, complete the deployment's existing configured child-side security setup, apply any separately approved H-class seccomp/Landlock floor if present, and execute the user-specified program |

The OCI lifecycle already separates `create` from `start`: in the `created`
state, the container process has not executed the configured program.
Defender uses that runtime-owned gate; it does not invent a second namespace or
container lifecycle.

A generic external hook is not automatically equivalent to this integration.
OCI `startContainer` hooks run before the user-specified process and can serve
as a fail-closed acknowledgement gate, but the standard hook contract does not
itself supply authenticated CRI identity or impose Landlock on a different
future process. The implementation therefore belongs in the CRI shim/OCI
runtime path, or in a runtime extension with an equivalent proved handshake.

If the runtime can execute the user-specified program without waiting for the
matching Defender acknowledgement, that node class cannot provide
enforced-from-start semantics. The root `ProcessInstance` has no native
workload parent: its causal predecessor is the typed
`container_started_for_pod` edge, while the runtime/shim remains infrastructure
evidence rather than part of the workload process tree.

Observe mode does not block an existing deployment on Defender availability.
The runtime/shim emits the binding and continues its normal lifecycle; a
missing or late binding creates a coverage gap and the task may be
`bootstrapped`. Only an operator-approved enforce mode turns the acknowledgement
into a start prerequisite.

The synchronous effect layer reads the same label:

| Effect family | Primary pre-effect hook | Complementary mechanism |
| --- | --- | --- |
| execute | BPF LSM `bprm_check_security` | seccomp denies unused exec variants and risky syscall classes |
| file open/read/write and code mapping | BPF LSM `file_open`, `file_permission`, `mmap_file`, and selected inode/path hooks | existing mount policy is context; H-class mount/Landlock floors may be added separately |
| socket creation/connect/send | BPF LSM `socket_create`, `socket_connect`, and `socket_sendmsg` | cgroup `connect4/6`, `sendmsg4/6`, socket storage, and cgroup/TC packet policy |
| devices | cgroup v2 `BPF_PROG_TYPE_CGROUP_DEVICE` plus BPF LSM `file_open`/`file_ioctl` | existing `/dev` and seccomp are context; changing them is H |
| privilege/escape operations | BPF LSM capability, credential, ptrace, mount, namespace, BPF, perf, and module hooks available on the supported kernel | existing seccomp/admission are context; new floors are H |

Tracepoints and ring-buffer events construct evidence; LSM, cgroup, and
seccomp return values prevent effects. The decision path is in kernel and does
not depend on event delivery latency. A sequence gap or ring-buffer loss
degrades evidence continuity but does not turn a loaded deny program into
monitor mode.

Pinned policy maps contain only approved, signed profile versions. The node
agent loads a new generation, reads back its maps and links, runs a
version-specific probe, atomically switches the active generation, and retains
the prior generation until no task label refers to it. Agent restart
reconciles pinned state before accepting new policy work.

Existing products remain optional adapters:

- a Tetragon `ProcessExec`, `ProcessExit`, LSM, or kprobe event can populate the
  same source contracts;
- a Falco alert can independently detect a syscall pattern; and
- CNI flow telemetry can add workload-level network verdicts.

Their limitations do not define Defender's design. If imported Tetragon lineage
contains `taskWalk`, `miss`, `unknown`, `procFS`, or truncation flags, only that
source edge is downgraded. The Defender fork sensor can still provide the native
task edge. If an imported product cannot synchronously enforce a required hook,
the Defender enforcer owns it.

Required loss handling:

- sequence gaps, ring-buffer loss, restart, or unresolved parent close the
  healthy lineage `CoverageInterval`;
- every later effect from the affected task is retained as an
  `orphan_effect` or `lineage_incomplete`, not discarded;
- enforcement continues from pinned in-kernel policy while evidence health is
  reported separately;
- startup reconstruction is marked `bootstrapped`, never treated as equivalent
  to observing task creation and exec.

### Graph construction algorithm

For each event, the graph owner performs these steps transactionally:

1. Resolve `(tenant, cluster, node, node_boot_id)` from the authenticated
   collector, never from an untrusted payload field alone.
2. Resolve full container ID and exact Pod UID at the event time.
3. For `clone` with `CLONE_THREAD`, create a child `TaskInstance` in the same
   `ProcessInstance`; otherwise create both a child task and child process with
   direct task/process-parent edges and an `inherited_on_fork` execution that
   identifies the copied executable image even when the child never execs.
4. For a successful exec, resolve its task and process, close the prior
   execution, create an `ExecutionInstance`, and add the canonical exec
   transition. Optional source IDs attach to that node.
5. For process or task exit, close the matching live interval; a missing
   node produces a coverage defect.
6. For a file, socket, namespace, capability, or security-hook event, attach it
   to the exact execution and task. If that lookup is not unique, emit an
   `OrphanEffect` with the failed join keys.
7. Reject cross-Pod parent edges unless the event explicitly represents a
   host-namespace entry such as `nsenter`; surface that as an escape-relevant
   deviation.

The following are never graph keys by themselves: Pod name, workload name,
image tag, PID, process name, IP address, service-account name, or timestamp.

## Distributed causal lineage across nodes

Native process lineage ends at a node boundary. A process on node B is never a
child `ProcessInstance` of a process on node A, even when the first process
caused the second to exist. Defender represents the two facts separately:

1. each node proves its own fork/clone/exec ancestry from kernel events; and
2. the correlator connects node-local subjects through typed, evidence-backed
   causal edges.

This distinction is required for honest attribution and safe response. Kernel
ancestry answers “which task created this task?” Distributed causal lineage
answers “which earlier subject, request, resource, controller, credential,
message, connector, or artifact caused this execution or effect?”

### Durable graph objects

Raw observations and causal edges are immutable. A
`DistributedLineageView` is a versioned derivation over those records:

```text
SubjectRef =
    LinuxExecution {
      tenant_id, cluster_uid, node_id, node_boot_id, label_epoch,
      process_lineage_id, task_cookie?, execution_instance_id?
    }
  | KubernetesObject {
      tenant_id, cluster_uid, api_group, kind, namespace?, object_uid
    }
  | ApiRequest {
      tenant_id, authority_id, audit_id_or_request_id, principal_id?
    }
  | ControllerReconcile {
      tenant_id, cluster_uid, controller_object_uid,
      controller_instance_id?, reconcile_id?
    }
  | CredentialLease {
      tenant_id, issuer_id, lease_or_access_key_id
    }
  | ConnectorInvocation {
      tenant_id, connector_id, source_request_id, destination_request_id?
    }
  | ProviderResource {
      tenant_id, provider_account_id, provider_resource_id
    }
  | QueueMessage {
      tenant_id, broker_id, topic_or_queue_id, message_id_or_partition_offset
    }
  | ArtifactVersion {
      tenant_id, repository_id?, immutable_digest_or_revision
    }

CausalEdge {
  edge_id: SHA256(
    edge_type + canonical_source_ref + canonical_target_ref
    + sorted(evidence_observation_ids)
  )
  edge_type:
      process_issued_api_request
    | api_request_created_or_mutated_resource
    | object_triggered_controller_reconcile
    | controller_reconcile_changed_resource
    | controller_owns_resource
    | pod_bound_to_node
    | container_started_for_pod
    | credential_obtained_by
    | credential_used_for_request
    | connector_forwarded_request
    | remote_command_started_execution
    | message_published
    | message_consumed
    | artifact_produced
    | artifact_loaded
    | network_communication
  source_ref: SubjectRef
  target_ref: SubjectRef
  occurred_from, occurred_until
  proof: direct | derived | contextual | contradicted
  evidence_observation_ids[]
  coverage_interval_refs[]
  joining_fields[]
  missing_proof[]
}

DistributedLineageView {
  distributed_lineage_id: UUID
  version: UInt64
  tenant_id: UUID
  root_subject_ref: SubjectRef
  member_subject_refs[]
  causal_edge_ids[]
  open_branches[]
  contradicted_edge_ids[]
  required_coverage_refs[]
  merged_from_lineage_ids[]
  supersedes_version?
  state: open | contained | partial | unknown
}
```

`edge_id` deduplicates the same proven transition on replay. It does not imply
that two different evidence sets are the same assertion: additional evidence
creates another immutable edge or a new view referencing both. Late evidence
may merge two earlier views or split a contextual path from a direct path; it
creates `version + 1` and preserves every earlier view.

`distributed_lineage_id` is a correlation identity, not kernel authority. It
is never copied into BPF task storage or used as a node response target. Each
Linux member remains targetable only through its authenticated cluster, node
boot, label epoch, task/process cookie, cgroup, container, and Pod coordinates.

### Exact Kubernetes cross-node construction

The common Kubernetes propagation path is:

```text
Process A on node 1
  → authenticated socket/request observation
  → Kubernetes audit request with auditID X
  → resource object UID Y
  → controller reconciliation and owner-reference UID chain
  → Pod UID Z
  → scheduler binding / spec.nodeName
  → node 2
  → OCI/CRI container ID
  → root TaskInstance and ProcessInstance B on node 2
```

The correlator constructs that path using these rules:

1. **Process to API request.** `process_issued_api_request` is direct only when
   a unique task/socket/source-port interval and authenticated API-server
   observation, an exact credential lease/access-key ID, or an end-to-end
   request ID binds the process to the audit event. A Pod address and time
   window can provide contextual workload evidence, but source IP alone is not
   a process edge and must account for NAT, proxies, and reuse.
2. **Request to object.** Kubernetes audit supplies the audit ID, stage,
   authenticated user, source IPs, verb, request URI, object reference, and
   result. A successful create/mutate edge resolves the returned object UID;
   namespace, kind, and name alone are insufficient because deletion and
   recreation reuse names.
3. **Object to controller action.** The controller is retained as a causal
   mediator. With a controller-native reconcile ID, the path is owner object →
   `ControllerReconcile` → changed child object. Without one, controller audit
   plus the child's `ownerReferences[].uid` and `controller=true` may derive a
   direct owner-object → child-object transition. The owner reference by itself
   establishes `controller_owns_resource`, not which reconcile attempt created
   the child. Matching labels or selectors alone are contextual because a
   controller such as a ReplicaSet can acquire an existing matching Pod.
4. **Controller fan-out.** A Deployment, DaemonSet, StatefulSet, Job, or custom
   controller may create many resources on many nodes. Every object UID and Pod
   UID is a separate branch. A retry or duplicate delivery deduplicates by
   audit/request/object identity; it does not create a second causal event.
5. **Pod to node.** A scheduler binding or authoritative Pod record establishes
   the Pod UID's node assignment. A later reschedule is a different Pod UID;
   `spec.nodeName` without the matching object version and live interval cannot
   retarget an old branch.
6. **Pod to native root.** The authenticated node collector resolves Pod UID,
   full container ID, sandbox ID, cgroup, image digest, and container start to
   the initial task transaction described above. Only then does
   `container_started_for_pod` reach node 2's native tree.
7. **Missing transition.** If audit, object UID, owner reference, binding, CRI,
   or node-root evidence is absent, the view records the exact open branch and
   relevant coverage interval. It does not shortcut from “process A contacted
   Kubernetes” to “process A spawned process B.”

Controllers continuously reconcile desired state, so containment must preserve
the controller/resource branch. Killing or deleting only a descendant Pod can
cause the same controller to create a replacement on another node.

### Non-Kubernetes bridges and proof rules

The same graph supports other propagation without weakening proof:

- An exact credential lease, cloud access-key ID, or safely captured token
  fingerprint can directly connect acquisition and later provider use. A role
  name, service-account name, or principal class alone is contextual.
- A connector produces a direct forwarding edge only when its authenticated
  audit preserves both source and destination request IDs. A shared connector
  principal plus timing is contextual.
- A queue edge requires a broker-native message ID or stable
  partition/offset plus authenticated producer and consumer records. Topic
  name and time alone do not identify a message.
- An exact artifact digest or immutable revision can connect producer and
  loader. A mutable tag, filename, package name, or repository name cannot.
- A network flow proves communication between endpoints. It proves remote
  execution only when receiver-side request, workload, provider, connector, or
  application evidence establishes the invoked operation and resulting
  subject.
- A remote-execution service must emit a request identity that both its
  accepted command record and the resulting local execution record carry.
  Otherwise Defender reports communication plus a later execution, not
  `remote_command_started_execution`.
- A cross-cluster path needs independently authenticated cluster identities
  and an end-to-end connector, request, credential, message, or artifact key.
  Equal Pod names, service-account names, IPs, or timestamps never join
  clusters.

Proof is monotonic with respect to raw evidence, not confidence labels. A later
contradiction—such as provider audit proving that a different principal made
the request—adds a `contradicted` edge and a new lineage view; it never deletes
the earlier hypothesis or raw facts.

## Expected process graph and effect profile

The actual graph records what happened. Detection requires a separately
versioned statement of what is allowed:

```text
WorkloadProcessProfile {
  profile_id
  profile_version
  selector {
    cluster_or_asset_class
    namespace
    pod_labels
    container_name
    immutable_image_digest
  }
  roots: [RootRule]
  fork_rules: [ForkRule]
  exec_edges: [ExecEdgeRule]
  role_effects: Map<Role, EffectPolicy>
  critical_invariants: [Invariant]
  mode: observe | alert | enforce
  approval { approver, approved_at, artifact_digest }
}

ForkRule {
  parent_role
  child_role_before_exec
  clone_class: thread | process
  allowed_clone_flags
  maximum_depth_and_count
}

ExecEdgeRule {
  source_role
  resulting_role
  executable_identity
  argv_class?
  allowed_uid_gid_capability_transition
  allowed_namespace_transition
}

EffectPolicy {
  file_read_classes
  file_write_classes
  connect_destination_classes
  listen_classes
  executable_result_roles
  allowed_capability_and_namespace_changes
  prohibited_control_plane_classes
}
```

Profiles are scoped to immutable image digest, not image tag. OCI
entrypoint/command, packaged executable digests, reviewed workload
configuration, and SBOM data seed a candidate. Monitor-mode observations can
propose additional edges and effects, but never approve themselves. A human
reviews and signs the candidate; an image change requires a new version.

`executable_identity` cannot be only a path. The node image resolver maps the
approved OCI digest to a file identity such as:

```text
mount identity
+ device and inode
+ inode generation/version
+ IMA or fs-verity digest when supported
+ expected image-layer digest
```

The target filesystem determines which tuple is stable. Overlay copy-up,
writable executables, bind mounts, hard links, deleted-but-open binaries,
`memfd_create`/`fexecve`, and dynamically mapped executable code each receive
an explicit allow or deny test. A path that still says `/usr/bin/curl` after
its inode or content changed is `UnexpectedBinaryIdentity`, not an allowed
edge.

`bprm_check_security` may be called more than once while the kernel resolves a
script and its interpreter. The implementation records the complete
script/interpreter chain and authorizes every executable file involved.
Interpreters also load code as data: `python payload.py`, `python -c`, JIT
code, and `dlopen` cannot be governed by an exec edge alone. Defender's
file/mmap and role-effect policy therefore remains mandatory. Existing seccomp
state is useful evidence; a new static seccomp floor is optional H-class
hardening and is not required for the deployment-preserving baseline.

Dynamic language interpreters require effect policy as well as exec policy:

- `python → sh → curl` is an unexpected exec path if those edges are absent;
- a Python role that does not normally read a projected token produces an
  unexpected file effect; a controller role that requires the token does not;
- a Python role that does not use IMDS produces an unexpected network effect;
  a controller or node component with existing IMDS behavior keeps that
  access, and provider audit supplies operation semantics;
- a Jinja/Python payload executing inside the interpreter creates no exec edge,
  so the first observable prohibited effect is what detects it;
- a shell builtin or library HTTP call is not a new process and must not be
  described as one.

The diff engine emits named, independently testable deviations:

```text
UnexpectedRoot
UnexpectedTaskParent
UnexpectedExecEdge
UnexpectedBinaryIdentity
UnexpectedPrivilegeTransition
UnexpectedNamespaceTransition
UnexpectedFileEffect
UnexpectedNetworkEffect
UnexpectedDeviceEffect
UnexpectedControlPlaneEffect
OrphanEffect
LineageCoverageGap
```

`OrphanEffect` means Defender could not attach an event to the actual graph.
`Unexpected*` means it attached the event successfully and the approved profile
does not permit it. Those are operationally different and must never share a
generic “anomalous process” reason.

The pre-effect decision matrix is:

```text
task has no valid inherited label
  → deny protected exec/file/socket/device/security effects
  → emit OrphanEffect + enforcement result

task label exists; requested exec edge absent
  → return -EACCES before image installation
  → emit UnexpectedExecEdge

task and role are valid; requested effect absent
  → return the hook-specific denial
  → emit the corresponding Unexpected*Effect

effect allowed
  → permit; emit only when policy requests audit or correlation needs the fact
```

This fail-closed behavior applies to explicitly protected workloads. The node
must not accidentally apply a partial profile to unrelated host tasks.

## Multi-job Pods and the hard attribution limit

A Pod may run thousands of concurrent conversions. This design does not change
that.

- If one work item naturally causes a distinct child subtree, Defender can
  contain and explain that subtree. It still calls it a process subtree unless
  existing application evidence binds it to a work item.
- If many work items execute concurrently inside one interpreter, Linux cannot
  determine which dataset revision caused a file read or socket operation.
  The exact Linux subject is the task/execution, not the job.
- Existing scheduler, queue, trace, or application audit may add a
  `WorkItemContext` edge. It is optional and carries its own provenance and
  ambiguity.
- A timestamp-only “job started/job ended” interval on a concurrent
  interpreter is contextual. It cannot authorize revision quarantine.
- Revision quarantine is eligible only when an authenticated platform event,
  content digest, or equivalent application fact binds the exact revision to
  the malicious effect. Otherwise Defender contains at process, container, or
  Pod scope and says the revision is unknown.

This is an information boundary, not an implementation inconvenience. Defender
must not claim to solve it with a Pod label, cgroup, or time window.

## Enforcement stack and deployment classification

No one Linux mechanism has every decision context. The D-class baseline uses
mechanisms Defender can attach to the existing tasks/cgroups and treats current
deployment policy as evidence. Launch-time or control-plane changes remain
optional H work:

| Mechanism | Class in the baseline | Unique contribution and limit |
| --- | --- | --- |
| mount namespace and read-only/idmapped mounts | existing state is evidence; changing it is H | removes objects from view, but cannot distinguish processes and requires container recreation/configuration |
| Landlock before worker exec | H | monotonic inherited filesystem floor; cannot be retrofitted to an arbitrary live task |
| seccomp-BPF at container launch | existing state is evidence; changing it is H | cheap syscall floor, but syscall numbers lack resolved object/application semantics |
| BPF LSM | D | synchronous dynamic decisions with current task, credential, file/socket/kernel object, and Defender role; cannot infer logical job or encrypted operation |
| cgroup BPF | D | connect/send/packet/device policy and emergency whole-cgroup response; a shared cgroup affects all members |
| task and socket local BPF storage | D | stable role/lineage and socket origin without PID-only maps; shared descriptors still require use-time checks |
| fs-verity/IMA plus immutable runtime-resolved digest | digest inventory is D; enabling new integrity policy is H | executable/artifact identity; identity alone does not authorize behavior |
| Kubernetes admission/RBAC and provider IAM | existing state and audit are D inputs; changing them is H | authoritative server decision, but no local exploit path without node evidence; admission cannot block reads |

The OCI container runtime can apply mount and seccomp policy while creating
the existing Pod's container. Landlock is self-restriction: an unrelated node
process or ordinary external OCI hook cannot impose it retroactively on the
target. Defender therefore needs a container-runtime child setup path that calls
`landlock_restrict_self()` after namespace setup and before the worker exec
only if the operator adopts that floor. This changes launch-time enforcement
behavior and is therefore optional H work even though it does not change the
application binary, harness, or job model. The live-workload D baseline
remains BPF LSM/cgroup enforcement.

### Files

1. D baseline: BPF LSM applies role-specific file, mmap, exec, receive-FD, and
   ioctl rules to the existing process and credential objects.
2. D baseline: executable identity is resolved from the actual runtime image
   and file object; the manifest need not switch from tag to digest.
3. Optional H: mount/read-only policy removes unused roots and devices.
4. Optional H: Landlock provides a monotonic filesystem allow set.
5. Optional H: seccomp denies unused bypass syscall families.

Mount namespaces and Landlock are not redundant with BPF LSM. The namespace
removes objects entirely, Landlock gives an inherited restriction independent
of Defender's policy daemon, and BPF LSM supplies dynamic per-task role and
object context. Each covers failure or compromise of another owner.

### Network

1. D baseline: cgroup `connect4/6` and UDP `sendmsg4/6` hooks enforce
   destinations that are absent from the existing role;
2. D baseline: BPF LSM checks the current task's role and passed/inherited
   sockets while preserving required controller/API paths;
3. D baseline: socket storage labels the socket for later flow correlation;
4. D response: cgroup-skb or TC fences established packet flows;
5. D evidence: provider/API audit distinguishes application operations opaque
   inside TLS;
6. Optional H: network namespace, routes, CNI, IAM, or credential changes
   remove or narrow paths.

The supported profile explicitly covers or denies connected writes,
`sendmsg`, unconnected UDP, `sendfile`, `splice`, `io_uring`, raw/packet
sockets, TUN/TAP, AF_XDP, and BPF-based redirection. If the worker does not
need one of those paths, Defender's socket/device policy denies it; an adopted
H-class seccomp floor may independently remove the syscall route. If the
worker does need it, the target-kernel suite must prove equivalent
process/socket labeling and packet enforcement rather than assuming
`socket_connect` covers all egress.

### Devices

1. D baseline: cgroup-device BPF denies unapproved read, write, and `mknod` by
   device type/major/minor.
2. D baseline: BPF LSM file/ioctl hooks apply role-specific checks to the
   existing device set.
3. Optional H: narrow `/dev` mounts and seccomp remove unused interfaces.
4. GPU, accelerator, or other multiplexed-device semantics require a
   vendor/device-plugin boundary when major/minor and ioctl policy are too
   coarse.

### Commands and in-process code

An external command is an executable transition and is governed by the
approved source-role → executable → resulting-role edge. Shell builtins, Python
evaluation, JIT code, and library calls are not external commands. They remain
inside the same role and are governed by their effects.

This is how Defender can deny `python → sh → git`, yet also handle Python
implementing the same network request itself. Process policy catches the first;
file/socket/credential/provider policy catches the second. If `git clone` and
`git push` use the same TLS endpoint and same write-capable token, the kernel
cannot distinguish them. Defender uses provider audit to detect the operation
and can deny the whole channel only with approved blast radius. A read-only
capability, provider-side policy, or separate service boundary is an H/R
proposal; TLS interception is not required.

### Why seccomp-filtered ptrace is not the primary path

`SECCOMP_RET_TRACE` can cause ptrace stops only for selected syscalls instead
of tracing every syscall. That is materially cheaper than full ptrace and can
be useful on a compatibility kernel or in a diagnostic fixture. It still adds
userspace context switches on the selected hot path, depends on a continuously
healthy tracer, and sees syscall arguments rather than the fully resolved
kernel objects available at LSM hooks.

`SECCOMP_RET_USER_NOTIF` can delegate selected decisions to a broker without
ptrace, but safely approving operations that contain userspace pointers has
TOCTOU constraints; continuing the original syscall is not a general
security-policy primitive. Defender may offer either mechanism as a declared
compatibility tier applied by the container runtime. Neither is reported as
equivalent to in-kernel BPF LSM/cgroup enforcement without operation-specific
race and failure tests.

### The workload and network binding must survive reuse

The canonical Defender Linux subject adds all available exact identities:

```text
tenant_id
+ cluster_uid
+ pod_uid
+ full container_id
+ node_boot_id
+ task_instance_id
+ process_instance_id
+ execution_instance_id
+ cgroup_id and cgroup path
```

The canonical network identity adds a time-bounded address lease:

```text
IpLease {
  cluster_uid
  pod_uid
  cilium_endpoint_id
  network_namespace_id
  ip
  valid_from
  valid_until
}
```

A flow is assigned to a Pod only when its timestamp falls inside one unique
lease interval. If two Pod histories match the same address and time, the
network edge is ambiguous and cannot authorize automatic response.

Defender obtains process context at `socket_create`, `socket_connect`, and
`socket_sendmsg`, stores the originating task/profile/role in
`BPF_MAP_TYPE_SK_STORAGE`, and carries a socket cookie into flow evidence.
Packet-path cgroup/TC programs can then enforce the socket or workload label
without waiting for userspace.

Socket ownership has a real Linux complication: a socket can be inherited
across `fork()` or transferred with `SCM_RIGHTS`. Therefore the model records
both the socket creator and each process-context operation observed on it.
`file_receive` policy can deny receiving an unauthorized socket descriptor;
`socket_sendmsg` policy can deny a restricted recipient from using an allowed
socket. A packet seen later without current-task context remains attributed to
the socket and cgroup, not falsely to whichever task most recently appeared
near it in time.

## Evidence contracts

### Raw source envelope

Every adapter writes the exact received bytes before parsing them:

```text
SourceEnvelope {
  envelope_id: UUIDv7
  tenant_id: UUID
  asset_id: UUID
  source_kind: Enum
  source_instance_id: String
  source_boot_id: String?
  collector_instance_id: UUID
  collector_boot_id: UUID
  collector_sequence: u64
  source_event_id: String?
  source_cursor: String?
  occurred_at: Timestamp?
  received_at: Timestamp
  payload_sha256: [u8; 32]
  raw_object_uri: String
  media_type: String
  authenticated_principal: String
  parser_name: String
  parser_version: SemVer
}
```

Required invariants:

- `(tenant_id, collector_instance_id, collector_boot_id,
  collector_sequence)` is the delivery deduplication key;
- `(tenant_id, source_kind, source_instance_id, source_event_id)` is unique
  when the source provides an event ID;
- `payload_sha256` is calculated before parsing.
- adapters never replace raw source fields with enriched values;
- `occurred_at` and `received_at` remain separate;
- duplicate delivery returns the existing `envelope_id`;
- an event with an unbound sender is rejected before normalization.

### Normalized observation

The correlator consumes a small set of typed observations:

```text
Observation {
  observation_id: UUIDv7
  envelope_id: UUID
  occurred_at: Timestamp
  observed_result: allowed | denied | succeeded | failed | unknown
  observation_type:
    task_fork
    | process_exec_attempt
    | process_exec_committed
    | task_exit
    | process_ended
    | file_access
    | socket_connect
    | socket_send
    | device_access
    | privilege_transition
    | namespace_or_mount_transition
    | network_flow
    | kubernetes_request
    | kubernetes_object_changed
    | controller_reconcile
    | pod_bound
    | container_started
    | credential_issued
    | credential_used
    | cloud_request
    | mesh_device_enrolled
    | connector_request
    | connector_forwarded
    | queue_message_published
    | queue_message_consumed
    | artifact_produced
    | artifact_loaded
    | remote_execution_accepted
    | remote_execution_started
    | source_control_effect
    | policy_health
  subject:
    cluster_uid: UUID?
    node_id: String?
    pod_uid: UUID?
    container_id: String?
    node_boot_id: UUID?
    task_instance_id: String?
    process_instance_id: String?
    execution_instance_id: String?
    source_process_exec_id: String?
    cgroup_id: u64?
    process_profile_id: String?
    process_profile_version: u64?
    role_id: String?
    principal_id: String?
  object:
    kind: String
    canonical_id: String
    attributes: Map<String, Scalar>
  causal_keys:
    authority_id: String?
    request_id: String?
    destination_request_id: String?
    kubernetes_audit_id: UUID?
    kubernetes_object_uid: UUID?
    kubernetes_owner_object_uid: UUID?
    kubernetes_controller_object_uid: UUID?
    kubernetes_resource_version: String?
    bound_node_id: String?
    credential_lease_or_access_key_id: String?
    broker_id: String?
    queue_or_topic_id: String?
    message_id_or_partition_offset: String?
    immutable_artifact_digest_or_revision: String?
  action: String
  enforcement:
    mechanism: String?
    policy_generation: u64?
    decision: allowed | denied | audited | not_applicable
    kernel_errno: i32?
  source_strength: direct | derived | contextual
  coverage_interval_id: UUID
}
```

An `Observation` states only what its source can prove. For example:

- a Defender BPF LSM event with `decision=denied`, the active policy generation,
  and returned `-EACCES` proves that hook denied that operation. It does not
  prove the process had no other copy of the data;
- a datapath `DROPPED` verdict proves that packet or flow was dropped at the
  named hook. It does not reveal an encrypted HTTPS request body;
- Kubernetes audit proves that the API server handled a request as the recorded
  principal. A shared service-account name does not identify one Pod.
- a GitHub audit event can prove an installation or repository effect. A
  socket connection to `github.com:443` cannot distinguish clone from push.

### Coverage interval

Negative conclusions and automatic response require a continuous coverage
record:

```text
CoverageInterval {
  coverage_interval_id: UUID
  tenant_id: UUID
  asset_id: UUID
  source_kind: Enum
  policy_or_feed_id: String
  policy_or_feed_version: String
  valid_from: Timestamp
  valid_until: Timestamp?
  state: observing | enforcing_no_observation | degraded | uncovered
  drop_count_start: u64?
  drop_count_end: u64?
  clock_error_bound_ms: u32
  capability_hash: [u8; 32]
  reason: String?
}
```

The collector closes the current interval and opens `degraded` when the source
reports drops, restarts, loses its policy, loses Pod metadata, or exceeds its
delivery-latency budget. A DaemonSet being `Ready` is not sufficient.

## Mechanism and source normalization

### Defender node sensor and enforcer

The node agent authenticates its node and boot identity, pins its BPF links and
maps, and writes ring-buffer records to a local WAL before forwarding. Every
record includes:

```text
node_boot_id
per-CPU sequence and global reorder metadata
kernel monotonic timestamp
native task key
parent native task key when applicable
cgroup ID
policy/profile generation
hook ID
decision and errno
object fields available at that hook
```

Userspace resolves Pod/container/image metadata from the cgroup and OCI/CRI
container runtime at the event time. Kernel records never trust Pod labels as authority;
the authenticated node resolver supplies them as versioned enrichment.

The node publishes separate health for:

- each required BPF link and its kernel BTF attach target;
- active policy/profile map generation and digest;
- ring-buffer reserve failures and per-CPU sequence gaps;
- task-label allocation/lookup failures;
- container-runtime and cgroup metadata resolution;
- target-kernel enforcement probes; and
- WAL durability and forward progress.

A ring-buffer failure degrades observation. A missing link, policy-map mismatch,
task-label failure, or failed denial probe degrades enforcement.

### Optional Tetragon adapter

The collector uses Tetragon's `GetEvents` gRPC stream and retains the protobuf
envelope. It assigns a collector boot/sequence and commits the protobuf to its
local WAL before forwarding it. `GetEvents` is not a durable replay log, so a
collector disconnect can still create an unrecoverable interval; stream
restarts and Tetragon drop/health metrics close healthy coverage.

For a `ProcessLsm` or `ProcessKprobe` event it maps:

| Tetragon field | Defender field |
| --- | --- |
| response `cluster_name` | subject `cluster_uid`, after configured-name lookup |
| response `node_name` plus node boot inventory | subject `node_boot_id` |
| response `time` | `occurred_at` |
| `process.exec_id` | subject `source_process_exec_id`; join to a Defender `ExecutionInstance` when native task keys agree |
| `process.pod.uid` | subject `pod_uid` |
| `process.docker` plus node container-runtime inventory | subject full `container_id`; Tetragon's truncated value is not sufficient alone |
| `process.parent_exec_id` | a direct process-lineage edge |
| `policy_name`, `function_name`, `args` | object and action |
| `action` | `observed_result` plus enforcement mechanism |
| policy tags | content provenance, never authorization |

The adapter fails normalization if `process.pod.uid` is absent for a policy
whose package scope requires a Kubernetes Pod. It does not fall back to Pod
name for automatic response.

Imported socket attribution becomes `contextual`, not `direct`, when its
source reports tracking overflow or cannot prove the socket owner. Defender's
own process-context and socket-storage evidence remains independent.

### Network-flow source

A Defender datapath exporter, Hubble, or another CNI adapter needs, at minimum:

```text
flow UUID
event timestamp
source endpoint identity and labels
source IP
destination IP
destination port and protocol
verdict
drop reason or policy name
DNS query/answer reference, when available
node and cluster identity
```

It maps source endpoint/IP to `pod_uid` through `IpLease`. Destination classes
are data, not strings in a rule:

```text
169.254.169.254/32  → aws_imds
fd00:ec2::254/128   → aws_imds_ipv6
configured API VIPs → kubernetes_api
configured RFC1918 service ranges → private_service
configured mesh control addresses → mesh_control
```

DNS context can explain a destination. It is not authoritative when the
process pins an IP or rewrites resolution, as happened in the incident.

### Kubernetes audit

Defender ingests raw audit events. A rule-engine alert over those events may be
useful detection content but is not a replacement for the raw API record.

The minimum audit policy is:

```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
omitStages:
  - RequestReceived
rules:
  # Retain Pod bodies so admission and privileged/hostPath intent can be tested.
  - level: Request
    verbs: ["create", "update", "patch"]
    resources:
      - group: ""
        resources: ["pods", "pods/ephemeralcontainers"]

  # Retain TokenRequest input, but never its response token.
  - level: Request
    verbs: ["create"]
    resources:
      - group: ""
        resources: ["serviceaccounts/token"]

  # Record secret access metadata without logging secret bodies.
  - level: Metadata
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
    resources:
      - group: ""
        resources: ["secrets", "serviceaccounts"]

  - level: Request
    resources:
      - group: "authorization.k8s.io"
        resources:
          - "selfsubjectrulesreviews"
          - "selfsubjectaccessreviews"
          - "subjectaccessreviews"

  - level: Metadata
```

`RequestResponse` is intentionally not used for `secrets` or
`serviceaccounts/token`, because it would copy secret material or returned
tokens into the audit system.

The adapter retains at least:

```text
auditID, stage, requestReceivedTimestamp, stageTimestamp,
verb, requestURI, user.username, user.groups, impersonatedUser,
sourceIPs, objectRef, responseStatus, requestObject, annotations
```

Identity strength is:

1. exact when a unique bound credential ID or verified Pod-bound identity is
   available;
2. strong when `sourceIPs` maps to one Pod address lease and the service account
   matches that Pod;
3. contextual when only
   `system:serviceaccount:<namespace>:<service-account>` matches;
4. ambiguous when that service account is shared by concurrent Pods or the
   source address was node-SNATed.

Only levels 1 and 2 may extend an automatic Pod-containment path.

### Kubernetes object history and container binding

Audit alone is not a complete distributed-lineage source. Defender also runs a
least-privilege list/watch collector for the workload kinds it protects. It
persists only the control-plane metadata needed for identity and reconciliation:

```text
cluster UID and API authority
API group/version/kind
namespace, name, and immutable object UID
resourceVersion, generation, creation/deletion timestamps
ownerReferences { apiVersion, kind, name, uid, controller }
Pod spec.nodeName and scheduler binding observation
controller desired/observed state needed for response simulation
source watch cursor and CoverageInterval
```

It does not collect Secret data, ConfigMap data, projected tokens, or arbitrary
Pod environment values as part of this graph. The watch credential is read
only and namespace/resource scoped where the protected asset inventory allows
that.

The audit-to-object proof is classified as follows:

1. `direct` when the completed audit event contains the exact `objectRef.uid`
   or an authenticated admission/control-plane request ID is preserved on the
   resulting object event;
2. `derived` when a unique successful request and subsequent object-history
   record agree on authority, group, resource, namespace/name, actor, and a
   non-overlapping creation interval, but no end-to-end ID survived; and
3. `contextual` when only name, labels, selector, principal class, or timing
   agrees.

An owner-reference UID proves the ownership relation represented by that
object version. When controller audit also shows the controller principal
created or mutated the child, Defender can derive the corresponding controller
transition. Without controller audit or a controller-native reconcile ID, it
must not claim which individual reconcile loop created the child.

On each node, the container binder emits an authenticated, ordered record:

```text
ContainerRootBinding {
  cluster_uid, node_id, node_boot_id
  pod_uid, pod_sandbox_id
  full_container_id, immutable_image_digest
  cgroup_id, cgroup_path
  label_epoch, root_task_cookie, root_process_lineage_id
  container_created_at, admission_acknowledged_at, user_program_exec_at?
  container_runtime_event_id
  source_sequence, coverage_interval_id
}
```

In approved enforce-from-start mode, the binder records this before returning
the acknowledgement that permits the runtime to start the configured process,
as required by the root-admission handoff. Observe mode records the binding
without turning acknowledgement into a start dependency. A later collector
relist may reconstruct a
`bootstrapped` binding but cannot claim it observed container creation. Watch
cursor loss, compaction requiring relist, missing audit stages, CRI event loss,
or binder sequence gaps close the corresponding healthy coverage interval.

### AWS, mesh, connector, and GitHub

Each provider adapter must retain the provider event/request ID and the
provider's immutable resource IDs:

| Source | Required correlation fields |
| --- | --- |
| AWS CloudTrail | account, region, event ID, event time, access-key ID, principal ARN, role session, source IP, event source/name, resources, error |
| mesh provider | tailnet/tenant ID, auth-key ID if available, device ID, node key, tags, source address, created time |
| internal connector | connector principal ID, credential fingerprint, source workload/IP, destination cluster UID, request ID, outcome |
| GitHub | enterprise/org, App ID, installation ID, token fingerprint when available, actor, repository ID, audit event ID, operation, result |

Provider display names are context. They are not graph keys.

## Defender baseline and complementary recommendations

The Defender node plane must assume that hostile input can already execute inside
the unchanged worker and must deny that process role's prohibited effects. It
does not depend on the application emitting a job event, moving jobs into new
Pods/processes, or fixing the initial parser/template vulnerability.

The controls below are not one implementation checklist:

- P1 and P2 are **R-class application/deployment remediation**. Defender can
  identify the affected behavior and produce the recommendation, but cannot
  add a scanner or rewrite a parser without changing the protected product.
- P3 and P4 define the **D-class behavior for credentials and network access
  that already exist**, followed by optional H/R improvements.
- P5 through P7 begin with **D-class inventory, audit detection, correlation,
  and containment**. Their admission, RBAC, IAM, and launch-template changes
  are H-class controls that an operator may approve separately.

The baseline acceptance suite deliberately leaves the original credentials,
ServiceAccounts, RBAC, IAM, controller manifests, and allowed network paths in
place. Optional hardening has separate tests and never upgrades Defender's
coverage claim unless deployment evidence proves it is active.

There is one unavoidable distinction: Linux can deny the in-process payload's
file, socket, exec, device, and privilege effects, but cannot deny “malicious
Python computation” as a semantic operation when it uses the same interpreter
and allowed CPU/memory operations as legitimate work. Removing the Jinja
evaluation itself therefore remains an application fix; containing its
consequences does not.

### Recommendation P1 (R): reject HDF5 external storage before conversion

This is an application admission change, not a Defender requirement. Defender
may emit it as remediation and may consume its signed result if the application
owner implements it. Without that integration, Defender begins at the existing
worker's first observable file, process, or network effect.

The admission scanner opens the HDF5 file in an isolated scanner and walks
every dataset. It rejects the revision when the dataset creation property list
reports external raw storage:

```text
for every HDF5 dataset:
    dcpl = H5Dget_create_plist(dataset)
    external_count = H5Pget_external_count(dcpl)
    if external_count < 0:
        scan = error
    if external_count > 0:
        verdict = reject("external raw storage is forbidden")
```

The same scanner should reject external links and virtual-dataset mappings
unless the product has an explicit, separately sandboxed use case for them.
The scanner records:

```text
input revision
scanner image digest
HDF5 library version
file digest
dataset path
external_count
verdict
```

The scanner itself processes hostile HDF5 bytes. Run it without secrets,
Kubernetes credentials, instance metadata, private network, or write authority.
A parser crash is a rejected scan, not an automatic accept.

Acceptance only if the application owner adopts this recommendation:

- a normal self-contained HDF5 dataset is accepted;
- an HDF5 dataset with one external segment is rejected before a worker job is
  scheduled;
- malformed HDF5 produces `scan_error` and is rejected;
- a virtual or external link follows the explicit product rule;
- no scanner process can reach IMDS, the Kubernetes API, or production storage.

### Recommendation P2 (R): remove data-derived Jinja evaluation

This requires an application code change. Defender reports and validates it
only when the application owner chooses to implement it; the baseline
Defender path assumes the vulnerable evaluation can still occur.

The vulnerable offset field must be parsed as a strict integer before it
reaches any renderer:

```text
accepted: JSON number that fits the documented integer range
rejected: string, template expression, float, object, array, null
```

The application must not call `Template`, `Environment.from_string`, or an
equivalent evaluator on attacker-provided offsets. Jinja's
`SandboxedEnvironment` is defense in depth only; Jinja's own documentation
does not present it as a complete resource or side-effect boundary.

Acceptance only if the application owner adopts this recommendation:

- the smallest and largest allowed integer offsets pass;
- a numeric string fails;
- a string containing template syntax fails before Jinja is imported or called;
- a renderer exception does not include environment variables or credentials;
- the existing single-process and multi-process worker modes both pass without
  a Defender-specific job event.

No kernel policy can identify Python's in-process `exec()` as a Linux process
transition. There may be no new task or unique syscall. Defender instead denies
the later prohibited file, socket, device, credential, or control-plane
effect. A CPython uprobe may enrich an investigation but is not a production
prevention boundary.

### Control P3 (D): protect and detect use of existing credentials

Defender must assume that the existing Pod can legitimately contain a
projected ServiceAccount token, environment credentials, Secret volumes, or
provider credentials. Kubernetes controllers commonly need their
ServiceAccount token to perform their normal work. The presence or ordinary
use of that token is not itself malicious.

At workload discovery, Defender creates a non-secret inventory:

```text
ExistingCredentialBinding {
  tenant, cluster_uid, pod_uid, container_id
  source:
      projected_service_account_volume
    | secret_volume
    | environment
    | workload_identity
    | node_metadata
    | other
  principal_or_service_account
  audience_and_bound_object_uid_when_known
  mount_id, filesystem_id, inode_and_generation?  // for file-backed material
  configured_path_aliases[]
  expected_process_roles[]
  observed_api_or_provider_behavior_profile
  source_observation_ids[]
}
```

The inventory retains identity and placement, not secret values. Defender then
provides two distinct protections.

**Process-bound credential protection**

- BPF LSM file and mmap policy allows a projected-token or Secret object only
  to signed process roles that already need it. An unexpected child shell,
  interpreter, debugger, or helper receives a denial even though it is inside
  the same Pod.
- Checks run on use by the current task, including reads through inherited or
  passed file descriptors where the selected hooks provide that context.
  Path-only matching is insufficient.
- Ptrace, `process_vm_readv`, `/proc/<pid>/mem`, cross-process environment
  reads, and unapproved descriptor passing are separately denied by the
  process-role policy.
- A read by the expected controller process is retained as ordinary evidence,
  not automatically promoted to an incident.

These controls protect an access boundary, not a credential already copied.
If the legitimate controller has already read a token into memory, malicious
code in that process can use it. A fork can inherit copied memory before any
exec, and an environment credential may already be present in every child.
Defender may deny an unapproved fork/exec edge, ptrace, or later socket/API
effect, but it must not claim that a later file denial revoked existing bytes.

**Authority-use detection**

Defender builds a signed, monitor-first behavior profile for the *existing*
principal:

```text
KubernetesAuthorityBehaviorProfile {
  principal
  workload_and_process_roles
  observed_or_approved {
    verbs[]
    api_groups_resources_subresources[]
    namespaces_and_object_scopes[]
    expected_request_rate_and_controller_fanout[]
  }
  high_risk_predicates {
    Secret_get_list_watch
    TokenRequest
    Pod_exec_attach_or_ephemeral_container
    privileged_or_host_mounted_workload_create
    RBAC_bind_escalate_or_impersonate
    admission_or_webhook_change
    node_proxy_CSR_or_workload_identity_change
  }
  mode: observe | alert | approved_server_enforce
  version_and_approval
}
```

Kubernetes audit supplies the verb, resource, namespace/object, authenticated
principal, result, and request identity. A deviation is useful even when the
request was allowed by existing RBAC. The finding distinguishes:

```text
unexpected process role opened credential object
  → direct local credential-access deviation; may be denied synchronously

expected controller process made an unexpected API request
  → server-side authority-use deviation; request may already have succeeded

same controller process used its existing client/connection
  → no honest local semantic distinction; API audit is the first semantic fact
```

Kubernetes admission can optionally prevent reviewed write/create/update
patterns, but it cannot block `get`, `list`, or `watch`; reads bypass admission.
Preventing an allowed Secret read requires RBAC/authorization change, which is
H-class, or earlier process/network containment. Without either, Defender
detects the completed read from audit and must not claim it prevented it.

If malicious code executes inside the same legitimate controller process, it
already has that process's memory, client library, open descriptors, and
allowed token access. BPF cannot label one Python function “attacker” and
another “controller.” Defender detects the subsequent API/provider behavior,
then can restrict the proven process lineage, fence its sockets/cgroup, and
propose a disruptive identity or Pod response with explicit approval.

#### Optional hardening when the credential is unnecessary

If observation proves that a workload does not use the Kubernetes API, Defender
may recommend the following H-class manifest change. It is not valid for a
controller that needs its token and is not a baseline acceptance condition:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: dataset-worker
  namespace: dataset-conversion
automountServiceAccountToken: false
---
# Merge under the existing controller's .spec.template:
metadata:
  labels:
    erebor.io/trust-tier: untrusted-input
spec:
  serviceAccountName: dataset-worker
  automountServiceAccountToken: false
  containers:
    - name: worker
      image: registry.example/worker@sha256:PINNED_DIGEST
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop: ["ALL"]
        readOnlyRootFilesystem: true
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
```

`RuntimeDefault` above is Kubernetes' literal seccomp profile name. It does not
refer to the Erebor Runtime product.

Moving static database, cloud, mesh, connector, GitHub, or signing keys out of
`env`, `envFrom`, Secret volumes, or the image is also H-class. Introducing a
broker that issues a short-lived, resource/operation-specific capability is an
R-class deployment redesign. Defender may recommend and later verify either,
but cannot require or claim to implement them.

Blocking `/proc/self/environ` is not a substitute. After Python execution,
`os.environ` can return the process environment without reopening that procfs
file. A compromised process can use credentials already present in its own
memory; Defender controls the next distinguishable file, socket, process,
API-server, or provider effect.

### Control P4 (D): protect existing metadata and control-plane access

The primary node mechanism is attached to the existing worker cgroup by the
container-runtime/cgroup resolver. It does not globally deny the Kubernetes API
or IMDS. Policy is per existing process role and destination:

```text
DestinationAuthorityRule {
  process_profile_version
  process_role
  destination_class: kubernetes_api | instance_metadata | provider | other
  destination_addresses_and_live_intervals
  new_connection: allow | deny | observe
  established_packet_response: fence_only | approved_always_deny
  semantic_evidence_source: kubernetes_audit | cloud_audit | none
}

cgroup/connect4 + cgroup/connect6:
  apply the cgroup-wide floor for destinations no process in this workload uses
  do not apply a blanket API/IMDS deny to a controller that requires it

cgroup/sendmsg4 + cgroup/sendmsg6:
  apply the same rule to unconnected UDP send

BPF LSM socket_create/socket_connect/socket_sendmsg:
  enforce the current process role
  allow the existing controller role's approved destination
  deny an unexpected child/helper role even inside the same Pod/cgroup
  emit task, role, socket cookie, address, decision, and policy generation

cgroup_skb/egress or TC:
  enforce packet policy for established sockets and protocols whose later
  packets no longer execute in useful process context
```

The destination map is generated from cluster configuration and service
discovery and is keyed by workload/profile generation. It includes the
in-cluster Service IP, every private/public API endpoint, IPv4 and IPv6
metadata addresses, node-local proxies, secondary interfaces, and approved
conversion destinations. DNS is evidence, not authority: policy evaluates the
actual destination address.

A workload with no legitimate API or IMDS behavior can receive a synchronous
deny without changing its manifest. A controller that already uses the API
keeps that access. Defender can still deny a newly spawned `sh`, `curl`, or
unexpected interpreter role from opening or using an API socket and can
correlate allowed controller-role traffic with API audit.

If injected code runs in the already approved controller process and reuses its
existing Kubernetes client or TLS connection, the kernel sees the same task,
socket, destination, and credential as legitimate work. Network policy cannot
classify the verb or object. The earliest semantic distinction is the API audit
event and its comparison with `KubernetesAuthorityBehaviorProfile`.

A CNI policy may duplicate a deny that the operator has approved and provide
flow verdicts. Introducing or changing that CNI policy is H-class, not a
Defender baseline requirement.

Required tests:

- for a profile with no legitimate metadata or Kubernetes API use, IPv4/IPv6
  and every discovered API endpoint receive a synchronous denial;
- an unchanged controller with a mounted token and approved API behavior
  continues working in observe and enforce modes;
- an unexpected child/helper role in that controller's Pod cannot create or use
  an API/IMDS socket, while ordinary access by the signed controller role is
  retained as evidence rather than labeled malicious;
- an unexpected same-process API verb/resource is detected from Kubernetes
  audit without claiming the network layer decoded TLS;
- DNS replacement and hard-coded destination IPs do not bypass the CIDR rule;
- inherited and `SCM_RIGHTS`-transferred sockets cannot bypass the receiving
  task's `socket_sendmsg` policy;
- already established connections are cut by the packet-level incident fence;
- alternate Multus or secondary interfaces are either covered or the asset is
  marked `uncovered`;
- approved conversion traffic still works.

Without TLS interception, kernel networking cannot distinguish two HTTPS
operations sent to the same endpoint with the same credential—for example a
safe read and an unsafe write. That is a fundamental information boundary.
Defender obtains server/provider audit and may deny the entire ambiguous channel
only when the operator approves that blast radius. Separate destinations or
capabilities are H/R recommendations, not Defender prerequisites. It must not
claim the packet layer understands the encrypted request.

### Control P5 (D/H): detect dangerous workload creation; optionally deny it

The deployment-preserving capability consumes Kubernetes audit and object
history. It emits a high-confidence finding when an existing principal
attempts or succeeds in creating or updating:

- privileged containers or privilege escalation;
- `hostPath`, host PID/IPC/network, or dangerous device access;
- a DaemonSet or static-like workload that expands to nodes;
- ephemeral containers, `exec`, or `attach` outside the signed behavior
  profile; or
- a workload whose ServiceAccount, image, node placement, or owner lineage is
  unexpected.

The finding records whether the API server denied or persisted the object. If
it persisted, Defender correlates its UID through scheduling and remote native
roots, contains those exact branches, and reports that detection was not
prevention.

#### Optional H-class admission enforcement

If the cluster operator approves a preventive control-plane policy, apply Pod
Security Admission `restricted` to the selected namespace and pin the version
validated by the deployment:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: dataset-conversion
  labels:
    erebor.io/trust-tier: untrusted-input
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

For an explicit, independently reviewable boundary, bind this
`ValidatingAdmissionPolicy` to the untrusted namespace label:

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: erebor-untrusted-pod-boundary
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["pods", "pods/ephemeralcontainers"]
  validations:
    - expression: >-
        object.spec.containers.all(c,
          !has(c.securityContext) ||
          !has(c.securityContext.privileged) ||
          c.securityContext.privileged == false)
      message: "privileged containers are forbidden"
    - expression: >-
        object.spec.initContainers.all(c,
          !has(c.securityContext) ||
          !has(c.securityContext.privileged) ||
          c.securityContext.privileged == false)
      message: "privileged init containers are forbidden"
    - expression: >-
        object.spec.ephemeralContainers.all(c,
          !has(c.securityContext) ||
          !has(c.securityContext.privileged) ||
          c.securityContext.privileged == false)
      message: "privileged ephemeral containers are forbidden"
    - expression: "object.spec.volumes.all(v, !has(v.hostPath))"
      message: "hostPath volumes are forbidden"
    - expression: >-
        (!has(object.spec.hostNetwork) || object.spec.hostNetwork == false) &&
        (!has(object.spec.hostPID) || object.spec.hostPID == false) &&
        (!has(object.spec.hostIPC) || object.spec.hostIPC == false)
      message: "host namespaces are forbidden"
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: erebor-untrusted-pod-boundary
spec:
  policyName: erebor-untrusted-pod-boundary
  validationActions: [Deny, Audit]
  matchResources:
    namespaceSelector:
      matchLabels:
        erebor.io/trust-tier: untrusted-input
```

Validate the CEL against the exact Kubernetes minor before rollout. Keep Pod
Security Admission active even when this policy exists. The two controls fail
through different configuration paths. Defender records the policy UID,
generation, bindings, audit coverage, and a controlled allow/deny probe. Until
those verify, findings say `observed_allowed` or `observed_denied` from the API
result rather than assuming prevention.

### Control P6 (D/H): inventory effective RBAC and detect dangerous use

The incident depended on a node/CSI permission path that could create Pods and
mint broader service-account tokens. Defender does not require those existing
permissions to be removed. It inventories the effective result and emits an
`ExistingAuthorityExposure` for dangerous grants:

```text
for every node identity, CSI service account, and worker service account:
  can create/update privileged or host-mounted workloads?
  can create serviceaccounts/token, and for which names/audiences?
  can get/list/watch Secrets, and in which namespaces?
  can exec/attach or add ephemeral containers?
  can impersonate, bind, escalate, change RBAC or admission?
  can reach node/proxy, CSR approval, webhook, or other escalation surfaces?

record:
  allowed | denied | evaluation_error
  exact principal, groups, scope, and review timestamp
  Role/ClusterRole and binding evidence when resolvable
  whether observed production behavior actually used the grant
```

Run `SelfSubjectAccessReview` from a principal when available and
`SubjectAccessReview` from the authorized Defender collector. A role-name
review is insufficient because aggregated ClusterRoles and bindings can change
the effective result. A failed or unauthorized review is a coverage gap, not
`denied`.

For an offline controller test, submit a `SubjectAccessReview` for each
principal/action tuple. For example:

```yaml
apiVersion: authorization.k8s.io/v1
kind: SubjectAccessReview
spec:
  user: system:serviceaccount:kube-system:example-csi-controller
  groups:
    - system:serviceaccounts
    - system:serviceaccounts:kube-system
    - system:authenticated
  resourceAttributes:
    group: ""
    resource: pods
    verb: create
    namespace: dataset-conversion
```

The D-class inventory records the returned result without changing it. Repeat with
`resource=serviceaccounts`, `subresource=token`, `verb=create`; with
`resource=secrets`, `verb=get/list`; and with the RBAC `bind`, `escalate`, and
impersonation checks appropriate to the identity. Run the same matrix for
`system:node:<node-name>` with its real groups. The test service account needs
permission to create `subjectaccessreviews`; production workers do not.

Actual use is a separate finding. Kubernetes audit proves that the principal
attempted or completed one of those operations. Defender joins that request to
the native process/workload when evidence permits, then restricts or fences the
source. A broad permission that has never been exercised is exposure, not an
invented attack edge.

An operator may ask Defender to generate a least-privilege RBAC diff and rerun
the matrix in simulation. Applying that diff is H-class and remains a separate
change/approval owned by the cluster operator. When adopted, the operator's
expected result for prohibited tuples is `status.allowed=false`; that is an
optional hardening test, not Defender's baseline gate.

Admission cannot prevent Secret `get/list/watch`. If existing RBAC allows the
read, Defender can detect it from audit and contain the source afterward; only
authorization change or prior source isolation can prevent it.

### Control P7 (D/H): observe and contain node-role use

Defender first preserves the existing node role and metadata configuration. It
discovers every IPv4/IPv6 metadata route and builds a role-specific rule:

- deny an API/IMDS connection synchronously when the current process role has
  no observed or approved need for it;
- allow and record it when the existing controller or node component needs it;
- flag a first-seen role, unexpected native descendant, request burst, token
  retrieval sequence, or use outside the workload's live interval; and
- join later CloudTrail events through access-key/role-session/source evidence,
  compare them with the signed provider behavior profile, and contain the
  proven source process/socket/cgroup.

If injected code uses IMDS from the same process that legitimately uses IMDS,
the endpoint connection alone is not malicious proof. The cloud operation and
resource in provider audit are the semantic evidence. Revoking every session
for a shared node role is a separate high-blast-radius response.

#### Optional H-class identity hardening

For EKS-like nodes:

- require IMDSv2;
- set the metadata response hop limit to `1` where compatible;
- use one workload role per application through EKS Pod Identity or IRSA;
- keep the node instance role unable to enumerate or mutate the wider estate;
- deny Pod-to-IMDS traffic independently at the CNI or cgroup layer.

The launch-template setting is:

```text
http_endpoint = enabled
http_tokens = required
http_put_response_hop_limit = 1
```

This needs a workload compatibility test. Components that legitimately require
IMDS must not be broken to satisfy a Defender baseline. Migrating them to
workload identity, changing the launch template, narrowing the node role, or
adding a CNI deny is operator-owned hardening whose deployed state Defender can
verify.

## Detection packages

Defender node prevention and later cross-source correlation are separate
packages. The first denies one prohibited edge or effect. The second
reconstructs the credential pivot even when the vulnerable Python process
never spawned a child.

### HF-PROC-001: unexpected process or effect

```yaml
id: HF-PROC-001
version: 1
scope:
  processProfile: hf-dataset-worker
requiredEnforcement:
  - task-label-inheritance
  - exec-lsm
  - file-lsm
  - socket-lsm-and-cgroup
emitWhen:
  anyDeviation:
    - UnexpectedRoot
    - UnexpectedTaskParent
    - UnexpectedExecEdge
    - UnexpectedBinaryIdentity
    - UnexpectedPrivilegeTransition
    - UnexpectedNamespaceTransition
    - UnexpectedFileEffect
    - UnexpectedNetworkEffect
    - UnexpectedDeviceEffect
    - OrphanEffect
responseSuggestion:
  type: linux.restrict-process-tree.v1
```

An attempted `python → sh`, `sh → curl`, or `python → tailscale` transition is
denied at the exec hook if that edge is absent. A direct token read or
API/IMDS connection is denied only when it is absent from that existing
process role's signed profile. An expected controller role may legitimately do
both; its later API/provider behavior is evaluated from authoritative audit.
No case requires an application job ID.

### Reference BPF LSM file decision

The executable implementation is CO-RE C with versioned maps; this pseudocode
shows the decision boundary:

```c
SEC("lsm/file_open")
int BPF_PROG(erebor_file_open, struct file *file, int prior_ret)
{
    struct task_struct *task;
    struct task_label *label;
    struct file_key key;
    struct effect_decision decision;

    if (prior_ret != 0)
        return prior_ret;              /* preserve an earlier LSM denial */

    task = bpf_get_current_task_btf();
    label = bpf_task_storage_get(&task_labels, task, 0, 0);

    if (!erebor_protected_current_cgroup())
        return 0;
    if (!label) {
        emit_or_count_denial(ORPHAN_EFFECT, file);
        return -EACCES;
    }

    key = classify_file(file);         /* mount/inode/object class, not suffix */
    decision = lookup_file_rule(label->profile_id,
                                label->profile_version,
                                label->role_id,
                                key,
                                requested_access(file));
    if (!decision.allow) {
        emit_or_count_denial(UNEXPECTED_FILE_EFFECT, file);
        return -EACCES;
    }
    return 0;
}
```

The real implementation must:

- preserve prior LSM return values and use the normal BPF LSM MAC return
  convention; cgroup-attached LSM programs have different return semantics;
- classify procfs environment files, projected-volume symlink targets, inode
  aliases, mounts, and deleted files by tested kernel object identity;
- enforce both open-time access and later read/write/mmap operations needed to
  cover already-open descriptors;
- increment a loss counter when evidence emission fails while keeping the
  denial decision intact; and
- include task key, role, file key, policy generation, decision, and errno in
  the event.

Equivalent pre-effect programs own exec, socket, device, capability, namespace,
mount, ptrace, BPF, perf, and module boundaries. A post-syscall tracepoint is
not an enforcement substitute.

### BPF LSM platform requirement

This design does not inherit a third-party tool limitation, but it still
depends on an actual kernel hook. A BPF LSM node class requires:

1. `CONFIG_BPF_LSM=y`;
2. `bpf` present in the active LSM list, commonly selected at boot;
3. BTF and the BPF helpers/map types used by the compiled CO-RE object;
4. sufficient privilege for the trusted node loader; and
5. a target-kernel probe for every hook and denial return path.

BPF LSM is a kernel feature, not an out-of-tree module Defender can load into an
arbitrary running kernel. Mainline support began in the Linux 5.7 era, but
version numbers alone do not prove hook, helper, distribution, lockdown, or
verifier behavior.

Production choices are explicit:

- use a Defender-supported node image with the required kernel capabilities;
- generate equivalent SELinux/AppArmor, seccomp, cgroup, and network controls
  for a reduced capability tier and report which per-task decisions are not
  equivalent; or
- build and boot a separately maintained kernel/LSM integration.

The last option is not disguised as a normal loadable kernel module. If the
required synchronous hook is absent, Defender cannot deny that effect on that
running kernel and reports the node as enforcement-incomplete.

### Engineering gaps versus fundamental limits

The implementation must not turn a reusable product's missing feature into a
product limitation:

| Gap | Classification | Defender answer |
| --- | --- | --- |
| imported sensor lacks exact fork-without-exec nodes | engineering | own `task_alloc` plus `sched_process_fork` sensor and native task/process graph |
| imported policy cannot express role-specific edge/effect rules | engineering | own signed profile compiler, BPF maps, and LSM/cgroup programs |
| imported network event is only Pod-attributed | engineering where process context exists | own socket hooks/storage/cookies; retain Pod-only packet evidence when current-task context truly is absent |
| userspace descendant enumeration races new children | engineering for protected effects | precomputed bounded process-ancestor vector plus one response-root map lookup at every protected hook |
| node's running kernel has no required synchronous hook | platform capability | replace/boot a supported kernel, use a proved built-in LSM equivalent, or state reduced enforcement; software cannot invoke a hook absent from that kernel |
| concurrent logical jobs are indistinguishable inside one process | fundamental information limit | enforce process effects; do not name a job without independent application/platform evidence |
| two operations share one TLS endpoint and credential | fundamental information limit without decryption or server evidence | use provider/API audit; recommend separate capability/destination as H/R; deny the whole channel only when the operator accepts its blast radius |
| arbitrary process subtree shares a cgroup with unrelated processes | fundamental atomic-stop granularity in stock Linux | lineage policy atomically restricts covered future effects; cgroup freeze gives atomic broader computation stop |
| effect already completed, memory already read/mapped, packet already delivered, or credential already copied | fundamental temporal limit | prevent earlier, contain future effects, revoke authority, and investigate/rotate; never claim rollback |

### HF-DW-001: credential-boundary pivot

```yaml
id: HF-DW-001
version: 3
title: Workload deviated from existing credential or authority behavior
stateKey: [tenant_id, cluster_uid, pod_uid]
requiredCoverage:
  - node:file-effect
  - node:socket-effect
  - kubernetes-or-provider:audit
allowedLateness: 5m
correlationWindow: 2m
facts:
  credential_access:
    observationType: file_access
    objectClass: [process_environment, kubernetes_projected_token]
    evaluateAgainst: WorkloadProcessProfile
  authority_channel:
    observationType: [socket_connect, socket_send, network_flow]
    destinationClass: [aws_imds, aws_imds_ipv6, kubernetes_api]
    evaluateAgainst: DestinationAuthorityRule
  authority_use:
    observationType: [kubernetes_request, cloud_request]
    evaluateAgainst:
      [KubernetesAuthorityBehaviorProfile, ProviderAuthorityBehaviorProfile]
joinPreference:
  - sameTaskInstance
  - sameProcessInstance
  - directDescendantProcessOfSensitiveReader
  - sameSocketLineage
  - sameExactPodUidAsContextOnly
```

The correlator keeps independent state per exact process/task and a bounded
Pod index:

```text
on credential_access(A):
  if A matches the signed process-role rule:
      retain A as expected credential context; do not emit a finding
  else:
      store credential-access deviation by process/task/Pod
      emit denied-or-observed local deviation according to enforcement result

on authority_channel(B):
  if B matches the signed process-role/destination rule:
      retain B as expected channel context; do not call the API operation safe
  else:
      store unexpected channel deviation
      join to A by same task/process/descendant/socket when possible
      Pod-only match remains contextual

on Kubernetes/provider audit(C):
  compare C with the signed authority behavior profile
  if C is expected:
      retain it as context; do not emit HF-DW-001
  else:
      emit authority-use deviation
      attach local A/B as direct only through a unique credential lease,
      request ID, socket/source binding, or uniquely resolved Pod interval
      otherwise attach them as contextual evidence
      state whether C succeeded, failed, or was denied

on late stronger evidence:
  emit Finding V(n+1) superseding the earlier version
```

Receive order does not matter. Finding identity is deterministic over package
version and sorted evidence IDs. Denied attempts still produce findings and
record `effect_prevented=true`. Late evidence creates a new finding version
and never edits raw evidence.

This package does not equate “controller read its token and contacted the API”
with compromise. It needs a process-role deviation, a destination-rule
deviation, or an API/provider behavior deviation. When the same approved
process performs an unexpected request, the authoritative audit deviation can
stand alone even if the local token read and connection are ordinary.

### HF-XNODE-001: distributed compromise expansion

This package expands a proven local compromise into a multi-node lineage
without treating time-adjacent workloads as descendants:

```yaml
id: HF-XNODE-001
version: 1
title: Compromised subject caused execution or authority on another asset
stateKey: [tenant_id, distributed_lineage_id]
seedFindings:
  - HF-PROC-001
  - HF-DW-001
requiredCoverageByEdge:
  process_issued_api_request: [node:socket-effect, kubernetes:audit]
  api_request_created_or_mutated_resource: [kubernetes:audit]
  controller_reconcile_changed_resource:
    [kubernetes:audit, kubernetes:object-watch]
  pod_bound_to_node: [kubernetes:object-watch]
  container_started_for_pod: [node:container-binding, node:task-lineage]
allowedLateness: 15m
lineageWatchAfterContainment: 10m
directJoinKeys:
  - kubernetes_audit_id
  - kubernetes_object_uid
  - kubernetes_owner_reference_uid
  - pod_uid_and_object_version
  - full_container_id
  - credential_lease_or_access_key_id
  - connector_source_and_destination_request_id
  - queue_message_id_or_partition_offset
  - immutable_artifact_digest
contextOnlyKeys:
  - source_ip_without_unique_socket_binding
  - service_account_or_role_name
  - object_name_or_label_selector
  - image_tag_or_artifact_name
  - destination_and_time_window
```

Its state machine is deterministic:

```text
on qualifying local Finding S:
  create or reopen lineage rooted at S.linux_execution_subject
  enqueue bounded expansion from S's direct identity/effect edges

on authoritative transition T touching a member subject:
  validate tenant/authority binding and transition-specific join keys
  append one immutable CausalEdge
  add T.target as a member and enqueue it for bounded expansion
  emit Finding V(n+1) with the new complete and open branches

on contextual observation C:
  attach C as contextual evidence
  do not make its target response-eligible

on conflicting observation K:
  append contradicted edge
  emit Finding V(n+1); remove no raw record

on lateness/watch expiry:
  close only branches whose required source coverage was healthy
  retain uncovered branches as unknown
```

Expansion is bounded by tenant, approved authorities, edge count, graph depth,
and event-time windows declared per edge type. It never runs an unrestricted
recursive graph query. A controller fan-out creates one response candidate per
exact child subject; it does not collapse a Deployment, its ReplicaSet, its
Pods, and their processes into one target.

The finding carries:

```text
linux_execution_subject {
  task_instance_id?
  process_instance_id?
  execution_instance_id?
  descendant_process_instance_ids[]
  pod_uid
  container_id
  native_cgroup_target
}
distributed_lineage {
  distributed_lineage_id
  lineage_version
  causal_edge_ids[]
  remote_descendant_subject_refs[]
  open_branches[]
  contradicted_edge_ids[]
  outside_authority_subject_refs[]
}
profile_and_role
observed_actual_path[]
expected_rule_or_missing_rule
file_effect
network_effect
control_plane_effect
direct_edges[]
contextual_edges[]
coverage_intervals[]
work_item_context?             // optional, source-attributed, never assumed
eligible_response_scopes[]
ineligible_response_reasons[]
```

## Immediate containment implementation

Containment starts from the smallest safe kernel identity that is actually
proven. An individual thread is evidence context, but Python threads share
address space, files, credentials, and process role. The default containment
root is therefore the exact `ProcessInstance`/thread group.
It never places `job_id` or `input_revision` in a required Linux response
target.

### Default request: restrict the exact process and descendants

```json
{
  "type": "linux.restrict-process-tree.v1",
  "finding_id": "finding-uuid",
  "target": {
    "cluster_uid": "cluster-uuid",
    "pod_uid": "pod-uuid",
    "container_id": "container-id",
    "node_boot_id": "boot-uuid",
    "label_epoch": "label-epoch-uuid",
    "host_tid_that_emitted_finding": 4317,
    "host_tgid": 4312,
    "task_cookie_that_emitted_finding": 77102,
    "task_instance_id_that_emitted_finding": "task-id",
    "process_instance_id": "process-id",
    "process_lineage_id": 99117,
    "process_profile_id": "hf-dataset-worker",
    "process_profile_version": 7
  },
  "requested_effects": [
    "deny_new_sensitive_effects",
    "stop_exact_process",
    "stop_observed_descendant_processes"
  ],
  "optional_broader_effects": [
    "fence_container_cgroup_egress",
    "freeze_container_cgroup",
    "delete_pod_with_uid_precondition"
  ],
  "expires_at": "timestamp",
  "idempotency_key": "sha256(response-class + finding + native-process-key)"
}
```

Authorization resolves the emitting task by label epoch and task cookie,
resolves the process by label epoch and process-lineage ID, then verifies its
current PID/TID coordinates through a pidfd and start-time check. It rejects a
cookie/native-coordinate mismatch, PID/TID reuse, a changed
Pod/container/cgroup binding, an expired request, a policy-version mismatch,
or a target outside the caller's tenant and response scope.

### R1: deny future sensitive effects for the exact process tree

The node inserts the target's `process_lineage_id` into the preloaded
`response_roots` map. Every thread in the root process has that same process
lineage ID. Every pre-effect program checks the current process ID and bounded
ancestor vector, then denies:

- all new exec transitions except an explicitly approved shutdown helper;
- new sensitive file opens and later reads/writes covered by the file hooks;
- socket create/connect/send and receipt of passed socket descriptors;
- device opens/ioctls;
- credential, capability, namespace, mount, ptrace, BPF, perf, and module
  transitions.

A later child process inherits the target lineage in `task_alloc` before it
runs. A later thread inherits the same process identity. Already-existing
descendant processes already carry that ancestor ID, so their next protected
effect is denied immediately after the single response-map generation becomes
active. Userspace still performs reconciliation for proof:

1. resolves every descendant process to `(pidfd, current leader task cookie,
   process-lineage ID, cgroup, Pod UID)` through the task labels rather than
   trusting a PID lookup;
2. reads each still-live task label through a version-tested iterator;
3. proves that the response root occurs in its bounded ancestry; and
4. reports every exited, reparented, overflowed, or unverifiable branch.

The postcondition is not “map update succeeded.” The node class's controlled
response-root probe must be denied by the active generation, every live thread
in the root process must carry the root ID, and every live known descendant
process must prove that it will match the same response root.
With complete pre-observed ancestry inside the declared depth bound, protected
effect restriction is race-free even though signal delivery is not.

Linux still has no atomic “stop this arbitrary process and all descendants”
primitive when unrelated work shares the cgroup. `SIGSTOP` enumeration can
race ordinary computation. If stopping computation itself must be atomic, the
actuator uses `cgroup.freeze`, openly accepting the wider scope.

### R2: stop execution without confusing it with policy denial

After installing the restrictions, the node opens a pidfd for each revalidated
thread-group leader and sends `SIGSTOP` with `pidfd_send_signal`. A
stopped-process
postcondition checks `/proc/<pid>/status`, the native start time, and task
state. `SIGKILL` is a separate irreversible effect because it destroys memory
evidence and cannot prove that a prior effect did not complete.

Signals are post-decision containment. They are not equivalent to BPF LSM
returning `-EACCES` before a file, exec, or socket operation.

### R3: fence attributable sockets before widening to the cgroup

At `socket_create`, `socket_connect`, descriptor receipt, and
`socket_sendmsg`, Defender records the socket cookie, socket-local storage,
creator lineage, current-user lineage, destination, and policy generation. A
packet-path program checks `fenced_socket_cookies` before allowing egress.

For a response with complete socket evidence, the node inserts every socket
owned or used by the restricted subtree into that map. This can stop already
queued and later packets without fencing unrelated sockets in the container.
The postcondition reads back the cookie set and sends a controlled packet
through a response fixture with the same map path.

A socket may be inherited or passed to another process. Fencing that socket
then affects every user of the shared socket, which is wider than one process
but still
narrower than the cgroup. If socket cookies or sharing history are incomplete,
Defender cannot claim a complete process-only packet fence and offers the
cgroup response instead.

### R4: use the cgroup when a race-free broad boundary is required

When the response policy requires guaranteed containment and accepts affecting
all jobs in the target container/Pod, the node resolves an open cgroup
directory file descriptor and:

1. attaches or activates a preloaded deny-all `cgroup_skb/egress` program at
   that cgroup to drop new and established egress packets;
2. sets `cgroup.freeze=1` on cgroup v2 when execution must stop;
3. verifies the cgroup inode/ID, BPF link/program ID, frozen state, and current
   membership; and
4. holds the cgroup file descriptor until response completion so deletion and
   ID reuse cannot retarget the action.

The attachment affects the target cgroup subtree. The container runtime's
cgroup layout decides whether that means one container or every container in
the Pod; the simulation must enumerate actual affected tasks before
authorization. A connect-only BPF hook is insufficient for established
connections.

This is the strict containment fallback for a shared interpreter. It may
interrupt every logical job in that process or cgroup. Defender states that
blast radius rather than pretending it isolated one conversion.

### R5: revision quarantine is an independent optional response

`artifact.quarantine-revision.v1` is eligible only when an authenticated
application/platform record independently identifies an immutable revision or
content digest. It is not a sub-effect of process containment and is never
authorized from Pod UID, process ancestry, or timing alone.

Its narrow request and postcondition are:

```text
QuarantineInputRevision {
  immutable_revision_or_digest
  evidence_observation_id
  expected_current_state
  reason_finding_id
}

verified when:
  exact revision is unschedulable
  + queued occurrences are held or cancelled
  + identical digest follows the declared resubmission policy
```

If that evidence does not exist, the finding says `input_revision=unknown` and
the connector is not called.

### R6: preserve evidence honestly

Before a destructive response, the node snapshots within a bounded time budget:

```text
Pod object and UID
container ID and image digest
actual task and exec graph with native keys
open file and socket metadata
cgroup and namespace IDs
mounted-volume inventory
active BPF links, maps, policy generations, and capability state
raw node, flow, Kubernetes, and provider evidence references
```

It does not promise process memory, packet payload, or volume preservation
unless the corresponding acquisition completed. A network fence precedes a
slow snapshot when exfiltration risk is active.

### R7: coordinate containment across the distributed lineage

`defender.contain-distributed-lineage.v1` is an orchestration response. It
does not introduce a global kernel target and it is not a recursive “kill
everything related” command. It freezes one versioned causal view into a
reviewable plan of independently authorized physical actions:

```text
DistributedResponsePlan {
  response_request_id
  tenant_id
  distributed_lineage_id
  lineage_version
  seed_finding_id
  watch_until
  targets[] {
    subject_ref
    response_class
    requested_effects[]
    expected_native_or_provider_preconditions
    dependency_target_ids[]
    authorization_scope
    required: Boolean
  }
  outside_authority_subject_refs[]
  open_branches[]
  required_coverage_refs[]
  idempotency_key
}
```

Simulation shows every target, edge that made it eligible, physical connector,
dependency, blast radius, approval, and missing proof. Authorization is against
that snapshot. A newly discovered target receives its own append-only plan
version and authorization; it is never smuggled into an earlier approval.

The coordinator executes the following order:

1. **Open a containment watch.** Persist the authorized lineage version and
   `watch_until`. Continue consuming late Kubernetes, node, connector,
   credential, queue, artifact, and provider evidence for that lineage.
2. **Fence the seed locally.** Run R1 and R3, or the approved R4 scope, against
   the exact native process on the seed node before waiting for remote
   correlation. This closes the fastest known propagation path.
3. **Revoke the propagation capability.** Revoke or constrain the exact
   credential lease, access key, connector route, queue publisher, or provider
   capability when the causal edge proves it and the request has the required
   approval. A shared role or connector remains a separately disclosed,
   high-blast-radius target.
4. **Contain every proven remote Linux member.** Resolve each
   `LinuxExecution` to the currently authenticated node collector. That node
   revalidates cluster UID, node boot, label epoch, Pod/container/cgroup
   binding, process-lineage ID, task cookie, and pidfd coordinates, then runs
   its own R1–R4 response. The coordinator never sends a remote PID or
   `distributed_lineage_id` to BPF as authority.
5. **Stop reconciliation from recreating work.** Contain the exact owning
   Kubernetes object/controller using UID and `resourceVersion`
   preconditions. The kind-specific connector may suspend a supported Job or
   custom workload, scale a scalable controller, install a narrow admission
   block for that object lineage, or foreground-delete the approved object
   after evidence capture. Merely deleting one Pod is insufficient because a
   controller can replace it on another node.
6. **Admit late descendants.** During the watch interval, HF-XNODE-001 may
   produce a later lineage version. Newly proven branches are simulated,
   authorized under the declared automatic-response policy or escalated for
   approval, and independently contained. Already completed target actions
   remain idempotent.
7. **Verify every branch.** Read each node/provider postcondition, confirm that
   the controller has not created another descendant, and check required
   coverage through `watch_until`.

The coordinator may report:

```text
verified:
  every required known in-authority branch has a verified physical response
  + no required branch remains open
  + required coverage stayed healthy through the watch interval
  + no replacement descendant appeared

partial:
  at least one physical restriction succeeded
  + another branch is outside authority, offline, uncovered, awaiting approval,
    wider than approved, or failed verification

unknown:
  evidence or coverage cannot establish whether the distributed effect
  continues

failed:
  no requested containment postcondition was achieved, or an explicit
  connector failure left all intended targets active
```

An external cluster, provider account, device, or workload outside the
defending organization's authenticated inventory remains evidence in
`outside_authority_subject_refs`; it is never silently turned into an actuator
target. A node that is offline or lacks required enforcement capability makes
the distributed result `partial` or `unknown`, even if all reachable nodes were
successfully fenced.

### Response state and proof

```text
proposed → authorized → executing → verifying
                                  → verified | partial | failed | unknown
```

`verified` requires every requested effect's postcondition. `partial` is
mandatory when ancestry proof is incomplete or exceeds the profile depth,
signal delivery cannot stop every exact process, socket history is incomplete,
only a wider cgroup fence succeeded, a target exited before verification, or
evidence acquisition did not finish. HTTP `200`, a signal syscall returning
success, a map write, or `kubectl apply` is not by itself a verified response.

## Identity and provider containment

### Kubernetes service-account tokens

For a default Pod-bound projected token, deleting the bound Pod invalidates the
token when the API server verifies the bound object no longer exists. Verify
with `TokenReview` if the response service is authorized and possesses the
token fingerprint/value through a safe evidence path.

If the attacker minted an unbound token or a token for a shared CSI service
account, there is no exact Pod-only revocation:

- remove the harmful RoleBinding/ClusterRoleBinding;
- delete or replace the affected service account if its blast radius is known;
- block the compromised principal at admission/RBAC;
- rotate signing keys only when a signing key, rather than one token, escaped.

These are wider responses and require explicit approval. Defender must not call
them “revoke this workload lease.”

### AWS node-role credentials

AWS role-session revocation based on `aws:TokenIssueTime` denies every session
for that role issued before the cutoff. It is not single-token revocation and
can disrupt legitimate workloads.

The connector therefore exposes:

```text
RevokeAwsRoleSessionsBefore {
  account_id
  role_arn
  cutoff
  expected_impacted_principals
  approval_id
}
```

It requires `iam:PutRolePolicy` on an allowlisted role and verifies the
`AWSRevokeOlderSessions`-equivalent deny policy. The workload/node is isolated
first so it cannot immediately obtain new credentials after the cutoff.

### Mesh enrollment

Revoking an auth key prevents new enrollment. It does not remove devices that
already enrolled with the key. A complete Tailscale-like response is:

1. `DELETE /api/v2/tailnet/{tailnet}/keys/{keyID}`;
2. enumerate devices created in the incident interval with the implicated tags
   or key attribution;
3. `DELETE /api/v2/device/{deviceID}` for each approved device;
4. verify the key is absent and each device lookup is absent;
5. search network/configuration logs for continued use.

The Defender credential should have only `auth_keys` and the constrained
`devices:core` scope for the allowed tags, not full tailnet administration.

### Internal connector

The published shared connector identity was bound to `system:masters` across
clusters. There is no narrow containment for that design. The correct response
is to disable the broker or shared credential and rotate/rebuild it, which is a
high-blast-radius action.

The replacement design gives each tuple a distinct principal:

```text
source application
+ destination cluster UID
+ operation class
= connector principal and credential
```

Then Defender can disable one principal and verify authorization failure only
for that destination and operation.

### GitHub App installation tokens

If Defender safely possesses the exact installation token value, GitHub allows
that token to revoke itself through `DELETE /installation/token`. If the value
is unavailable, an organization cannot revoke one unknown installation token
by fingerprint. Suspending or uninstalling the App installation invalidates
the wider installation and requires approval.

The response connector supports two different actions:

```text
RevokeKnownGitHubInstallationToken { installation_id, secret_ref }
SuspendGitHubAppInstallation { installation_id, approval_id }
```

Verification includes:

- exact token authentication fails after revocation, when safe to probe;
- or the installation reports `suspended_at`;
- repository audit shows no later unauthorized branch, commit, workflow, or
  token-minting effect;
- protected CI policy still denies unapproved workflow/build changes.

A network control cannot distinguish `git clone`, `git push`, and GitHub REST
calls over direct TLS to the same provider endpoint.

## Published action-by-action control map

This table references the stable event IDs in the live-action record and keeps
deployment-preserving Defender behavior separate from changes an operator or
application owner may later adopt.

| Event | Deployment-preserving Defender capability (D) | Optional hardening or redesign (H/R) |
| --- | --- | --- |
| `HF-001`–`HF-007` external sandbox | no Hugging Face-owned node evidence or containment authority; record only public-boundary evidence that reaches the protected estate | external sandbox operator controls are outside Defender's authority |
| `HF-008` hostile HDF5 revision | ingest an existing platform submission/revision identity when available; otherwise begin at the worker's first attributable effect and make revision quarantine ineligible | P1 scanner and pre-scheduling rejection are R-class; an existing quarantine API can be an optional connector |
| `HF-009` environment disclosure | when the Python role does not need the target object, BPF LSM can deny and record the exact task/file; if the expected process already owns the environment value, Defender controls only later distinguishable effects | parser fix, secret removal, or changed mounts are R/H |
| `HF-010` in-process Jinja execution | do not invent a process edge; detect or deny the first prohibited exec/file/socket/device/API effect under the existing role | strict schema and removal of data-derived evaluation are P2 R-class |
| `HF-011` projected-token read | allow ordinary access by a controller role; deny an unexpected child/helper role; correlate same-process abuse through API audit rather than declaring every token read malicious | `automountServiceAccountToken: false` is H-class only when the workload does not need Kubernetes; a credential broker is R-class |
| `HF-012` API/IMDS access | deny by process role when the existing role does not need the destination; preserve required controller/node access; compare Kubernetes/cloud audit with the signed authority behavior profile; fence the proven source on deviation | CNI deny, workload-identity migration, or removal of IMDS/API use is H-class |
| `HF-013` dataset dead-drop | direct TLS flow proves communication only; existing platform/provider audit must prove repository, operation, actor, and result; quarantine requires an exact existing revision/digest identity | operation-specific capability or separate endpoint is R/H |
| node-role replay | correlate metadata access with CloudTrail access-key/role-session use and provider behavior deviation; isolate the source; disclose that role-session cutoff is shared | narrower node role, workload identity, and launch-template changes are H-class |
| privileged Pod/node root | Kubernetes audit proves attempt/result; follow object UID → owner/binding → remote roots; contain proven branches and controller; say explicitly when creation already succeeded | Pod Security/ValidatingAdmissionPolicy and RBAC denial are optional H-class prevention |
| broad Secret read | audit proves principal, verb, scope, result, and objects when recorded; admission cannot block reads; contain source and enumerate exposed capabilities | RBAC reduction is the H-class preventive control |
| `HF-014`–`HF-016` mesh/connector | provider audit identifies key/device/connector use; revoke exact known keys/devices or disable the shared broker only with disclosed blast radius | one-use tags and per-destination/operation principals are H/R |
| `HF-017` AWS validation/exfil | cloud audit plus socket/flow evidence identifies existing authority use; provider behavior deviation and role-wide response remain explicit | workload-scoped roles are H-class |
| `HF-018` GitHub token/CI | repository/provider audit distinguishes clone, push, workflow, token, and package effects; revoke an exact known token or suspend the wider installation with approval | permission reduction, protected workflows, and separate read/write capability are H/R |
| `HF-019` remote loader | deny an unapproved local exec/mmap/code-source effect; use exact request/message/artifact identity to connect remote native trees; contain each proven branch | changing loader or platform scheduling design is R-class |
| `HF-020`–`HF-021` continued activity | keep verified process/socket/cgroup/provider fences active, watch late branches and controller replacements, and close only with complete postconditions/coverage | longer-term identity, topology, and application remediation remain separate changes |

## Optional third-party evidence

Tetragon, Falco, CNI flow systems, and cloud/security rule engines can add
independent observations and mature operational integrations. Their structured
events retain source version, rule/policy artifact digest, native IDs, health,
and raw envelope. They do not define the process graph, replace Defender's
required synchronous hook, turn two alerts into a causal path, or authorize a
response.

## Acceptance suite

An implementation is not ready until these tests pass against every supported
kernel, container runtime, filesystem, Kubernetes, and provider class.

### Deployment-preservation baseline

1. Defender observes and protects the original workload binary, controller
   topology, Pod template, mounted ServiceAccount token, environment/Secret
   credentials, RBAC, IAM, and network paths without requiring any of them to
   change.
2. the existing worker architecture handles many concurrent jobs in one Python
   process with no Defender job event and no false process deviation.
3. an unchanged controller can read its projected token and perform its signed
   expected API behavior without a credential or authority-use finding.
4. an unexpected child/helper process that opens or uses the controller's token
   receives the configured deny/alert with exact native and file-object
   identity; an allowed read by the legitimate controller role is ordinary
   evidence.
5. injected code using the same legitimate controller process, Kubernetes
   client, TLS connection, and token is not falsely distinguished at the
   kernel layer; an unexpected verb/resource/scope/result from Kubernetes
   audit produces the authority-use finding.
6. existing dangerous RBAC, node-role, admission, or credential distribution
   produces exposure findings and optional H/R recommendations without
   Defender claiming to have changed or removed it.
7. a dangerous workload write and a Secret read are both detected from API
   audit with their actual result; optional admission can prove denial of the
   write, while the Secret read is never claimed prevented by admission.

### Task and exec graph

8. `fork`, `vfork`, `clone`, and `clone3` create exact parent/child
   `TaskInstance` edges before child effects.
9. a forked child that never execs remains a distinct task and inherits the
   correct role/restriction.
10. fork-then-exec and exec-without-fork create correct task and execution
    histories; when a non-leader thread execs and assumes the TGID, its stable
    task/process cookies remain unchanged while its native-coordinate history
    records the de-thread transition.
11. PID/TID reuse, node reboot, loader restart with pinned state, and a forced
    label-epoch rebuild do not merge task or process identities.
12. multiple threads and concurrent jobs inside one interpreter remain one
    process role without fabricated work-item attribution.
13. in approved enforce-from-start mode, a new container remains in OCI
    `created` state while Defender binds the runtime-owned cgroup and init task;
    the exact transaction acknowledgement permits start, while a missing,
    stale, wrong-container, wrong-cgroup, or wrong-profile acknowledgement
    fails closed. In observe mode, the same missing acknowledgement does not
    block the workload and instead opens a coverage gap. The resulting root
    `ProcessInstance` has no fabricated native workload parent and receives a
    typed `container_started_for_pod` causal edge. Tasks first seen after start
    are `bootstrapped`; an unresolved parent produces `LineageCoverageGap`, not
    an observed attack edge.
14. an effect whose native task cannot be resolved produces `OrphanEffect` and
    invokes the protected-workload fail-closed rule.
15. ring-buffer loss degrades observation while a pinned denial remains active.

### Synchronous kernel enforcement

16. child task policy is present before a fork bomb child can execute a
    protected action.
17. `python → sh` and `python → curl` absent from the profile return `EACCES`
    before the child image runs.
18. an approved exec edge succeeds and receives the declared resulting role.
19. a path-matching binary with changed inode/content identity is denied.
20. `execveat`, `fexecve`/`memfd`, scripts/interpreters, overlay copy-up, bind
    mounts, and deleted executables follow explicit tests.
21. opening each prohibited environment/token alias returns `EACCES` with the
    native task, role, object key, policy generation, and denial result.
22. already-open descriptors, mmap, shared memory, and passed file descriptors
    are tested against the claimed file coverage; uncovered cases are named.
23. for a process role with no existing IMDS/API need, in-process Python TCP
    and UDP attempts to every discovered IMDS/API address are denied without
    any new process; for a controller role that requires the destination, the
    connection remains allowed and an out-of-profile API/provider operation
    produces an authority-use finding from authoritative audit.
24. hard-coded IPs, changed DNS, IPv6, public/private API endpoints, and
    secondary interfaces do not bypass the role-specific destination policy or
    erase the distinction between an allowed destination and an unexpected
    server-side operation.
25. socket `write`/`sendmsg`, unconnected UDP, `sendfile`, `splice`, `io_uring`,
    raw/packet sockets, TUN/TAP, AF_XDP, and BPF redirection are either denied
    by the profile or pass an equivalent attribution/enforcement test.
26. inherited and `SCM_RIGHTS`-passed sockets cannot bypass the sender or
    receiver role.
27. cgroup-device policy denies unapproved major/minor read, write, and mknod;
    file/ioctl/seccomp tests cover the approved device API.
28. capability, credential, namespace, mount, ptrace, BPF, perf, and module
    transitions follow the role policy.
29. a node missing BPF LSM, a required helper, a BPF link, a denial probe, or a
    runtime start gate that requires the matching root-admission
    acknowledgement is enforcement-incomplete and cannot advertise equivalent
    protection.

### Correlation

30. credential-access/channel/authority deviations delivered in any order emit
    the same idempotent package result after lateness closes; expected
    controller token and API use emits none.
31. same-task, same-process/different-thread, direct descendant-process,
    socket-lineage, and Pod-only joins are represented with different edge
    strength.
32. duplicate delivery does not create another finding or response.
33. a five-minute-late Kubernetes audit event creates Finding V2 and preserves
    V1.
34. two concurrent Pods sharing a service account do not receive an exact edge
    from service-account name alone.
35. concurrent logical jobs inside one interpreter never cause kernel evidence
    to name a revision; revision quarantine stays ineligible without an exact
    platform observation.
36. IP and cgroup reuse outside recorded live intervals do not link the wrong
    Pod or task.
37. benign conversion files, allowed child edges, approved egress, expected
    credential reads, and signed API/provider behavior do not satisfy either
    package.

### Distributed causal lineage

38. equal PID, task-cookie, process-lineage, cgroup, container-name, or Pod-name
    values on different node boot or cluster identities never merge native
    subjects.
39. the graph API rejects a cross-node or cross-Pod `parent_process` edge; the
    same evidence may create only an explicitly typed causal edge with its
    proof and missing fields.
40. an integration fixture proves the full path
    process A on node 1 → socket/request → Kubernetes audit ID → created object
    UID → controller/owner-reference UID → Pod UID → binding → node 2 →
    full container ID → root process B, retaining every evidence ID.
41. Deployment, DaemonSet, Job, and custom-controller fan-out creates one
    causal branch per exact object/Pod/process identity across nodes; controller
    retry and duplicate audit delivery remain idempotent.
42. deletion and recreation under the same namespace/name produces a new object
    UID and never inherits the old resource's lineage.
43. a ReplicaSet acquiring a label-matching Pod produces contextual evidence
    until owner-reference/controller audit proves the relationship; labels and
    selectors alone never create a direct edge.
44. removing, one at a time, the audit, object UID, owner-reference, binding,
    CRI/container-start, or node-root observation creates the named open branch
    and prevents a complete direct path.
45. an exact credential lease or cloud access-key ID joins acquisition to use;
    the same role or service-account name used concurrently by two workloads
    remains contextual.
46. a connector carrying authenticated source and destination request IDs
    creates a direct forwarding edge; a shared connector principal and timing
    alone do not.
47. a broker message ID or partition/offset joins publisher to consumer; queue
    name plus time does not.
48. an exact immutable artifact digest joins producer to loader across nodes;
    mutable image tags, filenames, package names, or repository names do not.
49. a network flow alone creates `network_communication`, never
    `remote_command_started_execution`; receiver request/execution evidence is
    required for the latter.
50. evidence delivered after the lateness window creates a new lineage/finding
    version, preserves the prior version and raw records, and deterministically
    merges or contradicts the affected branch.
51. a cross-cluster join fails without authenticated cluster identities and an
    end-to-end request, credential, connector, message, or artifact key.

### Containment

52. exact-process restriction denies a fresh file, exec, socket, and device
    probe from every thread; a child process created afterward inherits the
    restriction before running.
53. every existing descendant's pre-populated ancestor vector matches the
    response root immediately; iterator/pidfd reconciliation proves it or
    reports the branch missing.
54. profile-depth overflow, bootstrapped/incomplete ancestry, and a missing
    task label make exact subtree restriction ineligible instead of creating a
    userspace labeling race.
55. `SIGSTOP` is verified separately from LSM denial; `SIGKILL` requires its
    distinct irreversible authorization.
56. the cgroup egress fence drops packets on an established connection and
    `cgroup.freeze` stops the enumerated cgroup membership.
57. response simulation lists every known task/container affected by the actual
    cgroup boundary and states that logical job count/identity is unknown when
    the application does not expose it.
58. stale node boot ID, label epoch, task cookie, process-lineage ID, native
    PID/TID coordinate, or cgroup ID; wrong Pod UID; and expired TTL are
    rejected.
59. a shared interpreter response states that all in-process jobs may be
    interrupted.
60. independently proven revision quarantine prevents rescheduling that exact
    immutable input; absent revision evidence makes the action ineligible.
61. a two-node distributed plan fences the seed immediately, independently
    re-resolves and contains the remote native process, constrains the owning
    controller with UID/resource-version preconditions, and contains a new
    branch discovered during the watch interval.
62. a distributed response is `verified` only when every required branch and
    postcondition verifies under healthy required coverage through the watch
    interval; an offline node, outside-authority target, unresolved branch, or
    replacement workload forces `partial` or `unknown`.
63. each local and distributed response is idempotent and ends in `verified`,
    `partial`, `failed`, or `unknown`.

### Provider recovery

64. deleting a mesh auth key prevents new enrollments; already enrolled devices
    remain until explicitly deleted.
65. AWS role-session revocation reports every expected affected principal and
    requires high-blast-radius approval.
66. known GitHub installation-token revocation and installation suspension are
    tested as different actions.
67. repository commits, branches, workflows, releases, packages, and image
    digests are checked after source-control access.
68. direct TLS network evidence never claims whether the operation was clone,
    push, token minting, email send, or another provider API call.

## Build order

The first useful vertical slice is:

1. run the existing, unchanged multi-job worker under an observe-only
   `WorkloadProcessProfile`; require no job event and identify its real
   task/process/exec/effect graph;
2. prototype the Defender node hooks on every supported kernel class:
   `task_alloc`, fork/exec/exit, task storage, exec/file/socket/device/security
   denial, ring-buffer loss, pinned maps, and BPF-link recovery;
3. build the native task/exec/effect graph and make PID reuse, bootstrap,
   fork-without-exec, and orphan behavior pass;
4. implement the image/profile resolver and signed
   `WorkloadProcessProfile` compiler in monitor mode;
5. build P3/P4 against the original mounted credentials and required API/IMDS
   access: learn signed process/destination/authority behavior, allow the
   existing controller, and detect an unexpected child or API/provider effect;
6. build P5–P7 inventory and audit findings against the original admission,
   RBAC, IAM, node role, and launch-template state; produce recommendations but
   mutate none of them;
7. enable HF-PROC-001 denial only for reviewed exec/file/socket/device effects
   absent from the existing process role, and prove the unchanged legitimate
   workload still works;
8. offer mount/Landlock/seccomp launch floors and P1/P2/P5–P7 hardening as
   separately simulated H/R work; never make their adoption a Defender
   prerequisite;
9. ingest raw node, network-flow, Kubernetes audit, and source-health evidence
   into `SourceEnvelope`, `Observation`, and `CoverageInterval`;
10. replay HF-DW-001 and prove same-task, same-process, descendant-process,
    socket, and contextual joins;
11. implement `SubjectRef`, immutable `CausalEdge`, and versioned
    `DistributedLineageView`; replay HF-XNODE-001 through audit ID, object UID,
    owner reference, binding, CRI/container root, credential, connector,
    message, and artifact transitions across two real nodes;
12. implement exact-process-tree restriction, then separately implement and
    approve the broader cgroup fence/freeze;
13. implement distributed containment as coordination over independently
    authorized node/controller/provider actions; verify watch-window,
    late-branch, offline-node, outside-authority, and controller-replacement
    behavior;
14. add cloud, mesh, connector, source-control, and optional third-party
    adapters one at a time with independent response approvals and tests.

Do not begin with a universal graph query language or a model-operated shell.
The first product proof is that an unchanged multi-job worker receives a
signed process/effect profile, an in-process prohibited file/socket action is
denied synchronously, the exact task and containing process are shown in the
causal graph, and the smallest honest containment scope is physically verified.

## Decisions an implementer may object to

This analysis makes the following explicit defaults:

| Decision | Default in this document | What changes if rejected |
| --- | --- | --- |
| protected deployment | baseline leaves application code, controller/Pod/process topology, mounted credentials, ServiceAccounts, RBAC, IAM, admission, routes, and provider identities unchanged | an adopted H/R change is separately approved and verified; Defender cannot depend on it for baseline protection |
| workload architecture | no job-per-Pod/process and no required application event | a deployment-specific integration may add stronger optional work-item context but cannot become a Defender enforcement prerequisite |
| native execution identity | native task tree + exec history + effects, keyed against PID reuse | replacement must cover fork-without-exec, exec-without-fork, threads, bootstrap, loss, and native actuator targeting |
| distributed lineage | immutable typed causal edges connect independently proven node-local trees through authoritative request/resource/controller/binding/container/credential/connector/message/artifact identities | replacement must never encode a remote process as a kernel child, must preserve fan-out and gaps, and must version late or contradictory evidence |
| node owner | Defender-owned CO-RE eBPF sensor/enforcer; third-party sources are adapters | replacement must prove equivalent pre-effect hooks, task inheritance, event health, policy generation, and postconditions |
| kernel baseline | supported image with BPF LSM, BTF, task/socket storage or a proved fallback, and cgroup v2/BPF; inventory existing seccomp but do not require a new filter | a reduced tier must enumerate missing prevention claims; a custom kernel integration has its own lifecycle; an adopted H-class seccomp floor has separate compatibility and verification |
| executable identity | immutable image/profile plus mount/inode/content identity | path-only policy accepts rename/alias/mutation risk and is not enforcement-equivalent |
| strict containment | root-map lookup gives synchronous protected-effect denial for a proven subtree; socket fence is next; cgroup fence/freeze is used for incomplete socket evidence or atomic computation stop | a different scheme must prove existing and future descendants cannot cross protected hooks after authorization |
| distributed containment | orchestrate exact local and provider actuators over one versioned lineage view; keep a watch open and contain the owning reconciler as well as current Pods | replacement must prove every known branch, replacement workload, coverage interval, authority boundary, and physical postcondition before claiming `verified` |
| revision response | optional and authorized only from exact application/platform evidence | without such evidence, revision stays unknown |
| primary store | immutable raw object plus transactional normalized records | alternative must preserve dedupe, replay, versioning, and audit |
| TLS | no interception | application semantics come from server/provider audit; separate capabilities are H/R, and an ambiguous channel is denied as a whole only with explicit blast-radius approval |

These are design proposals, not hidden assumptions. A future implementation
plan must adopt each one or name the replacement and its acceptance proof.

## Source boundaries

The incident actions are Hugging Face's published reconstruction, with
redactions and genericized indicators. The policies, schemas, response APIs,
and tests above are Defender design analysis. They do not claim that Hugging Face
ran these products or that any one control would have reconstructed the whole
incident.

## Technical sources

- [Hugging Face: technical incident timeline](https://huggingface.co/blog/agent-intrusion-technical-timeline)
- [HDF5 dataset creation properties and external-file APIs](https://support.hdfgroup.org/documentation/hdf5/latest/group___d_c_p_l.html)
- [Jinja sandbox and security considerations](https://jinja.palletsprojects.com/en/stable/sandbox/)
- [Linux kernel: LSM BPF programs](https://docs.kernel.org/bpf/prog_lsm.html)
- [Linux kernel: LSM hook development reference](https://docs.kernel.org/security/lsm-development.html)
- [Linux kernel source: current LSM hook definitions](https://github.com/torvalds/linux/blob/master/include/linux/lsm_hook_defs.h)
- [Linux kernel: BPF program and attach types](https://docs.kernel.org/bpf/libbpf/program_types.html)
- [Linux kernel: cgroup v2, freezing, hierarchy, and BPF device control](https://docs.kernel.org/admin-guide/cgroup-v2.html)
- [Linux kernel: socket-local BPF storage](https://docs.kernel.org/bpf/map_sk_storage.html)
- [Linux kernel source: task-local BPF storage implementation](https://github.com/torvalds/linux/blob/master/kernel/bpf/bpf_task_storage.c)
- [Linux kernel source: exec de-threading and task identity transition](https://github.com/torvalds/linux/blob/master/fs/exec.c)
- [Linux kernel: Landlock userspace API](https://docs.kernel.org/userspace-api/landlock.html)
- [Linux kernel: seccomp filter userspace API](https://docs.kernel.org/userspace-api/seccomp_filter.html)
- [OCI runtime spec: create/start lifecycle and container states](https://specs.opencontainers.org/runtime-spec/runtime/)
- [OCI runtime spec: pre-exec hook ordering](https://specs.opencontainers.org/runtime-spec/config/)
- [Kubernetes auditing](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
- [Kubernetes audit event schema](https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/)
- [Kubernetes owners and dependents](https://kubernetes.io/docs/concepts/overview/working-with-objects/owners-dependents/)
- [Kubernetes OwnerReference schema](https://kubernetes.io/docs/reference/kubernetes-api/definitions/owner-reference-v1-meta/)
- [Kubernetes ReplicaSet ownership and selector behavior](https://kubernetes.io/docs/concepts/workloads/controllers/replicaset/)
- [Kubernetes controller reconciliation](https://kubernetes.io/docs/concepts/architecture/controller/)
- [Kubernetes scheduling framework and Bind phase](https://kubernetes.io/docs/concepts/scheduling-eviction/scheduling-framework/#bind)
- [Kubernetes ValidatingAdmissionPolicy](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
- [Kubernetes admission-controller boundary, including reads bypassing admission](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/)
- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Kubernetes service accounts](https://kubernetes.io/docs/concepts/security/service-accounts/)
- [Kubernetes RBAC good practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/)
- [AWS EKS identity and IMDS guidance](https://docs.aws.amazon.com/eks/latest/best-practices/identity-and-access-management.html)
- [AWS IAM role-session revocation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html)
- [Tailscale trust-credential scopes](https://tailscale.com/docs/reference/trust-credentials)
- [GitHub App installation APIs](https://docs.github.com/en/rest/apps/installations)
- [Tetragon process lifecycle API, optional adapter](https://tetragon.io/docs/reference/grpc-api/)
- [Falco supported process fields, optional adapter](https://falco.org/docs/reference/rules/supported-fields/)
- [Cilium Layer 3 policy, optional network implementation](https://docs.cilium.io/en/stable/security/policy/layer3/)
