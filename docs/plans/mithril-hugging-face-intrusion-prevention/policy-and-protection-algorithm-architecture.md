# Mithril Policy And Protection Algorithm Architecture

Status: Proposed architecture companion. This document does not authorize an
implementation phase. An approved phase may implement only the part assigned
to it by the
[Mithril Hugging Face Intrusion Prevention Master Plan](./README.md).

Normative acceptance:

- [Hugging Face Adversarial Acceptance](./hugging-face-adversarial-acceptance.md)
- [Live Two-Node Lifecycle Probe](./live-two-node-lifecycle-probe.md)

Research inputs:

- [Erebor Defender: Linux Enforcement, Correlation, and Response Engineering](../../research/erebor-defender-learning-from-tetragon-and-falco.md)
- [Mithril Single-Gatherer Architecture and Upstream Adoption Plan](../../research/erebor-warden-single-gatherer-architecture-plan.md)
- [Hugging Face Agent Intrusion: Erebor Defender Implementation Analysis](../../research/hugging-face-agent-intrusion-analysis.md)
- [Hugging Face Agent Intrusion: Published Live Action Stream](../../research/hugging-face-agent-intrusion-live-action-stream.md)

## Purpose

The phase files say when Mithril builds each capability. This document says
what the finished policy system means and which algorithm handles each
Hugging Face incident situation.

It is deliberately more specific than a product description. An implementer
should be able to derive Rust owners, BPF maps and hooks, policy schemas,
decision order, failure behavior, and adversarial tests from it. A reviewer
should be able to object to an explicit decision rather than infer one from a
phrase such as “anomalous process.”

The target is an unchanged application deployment. Mithril may install node
security integration, BPF programs, a runtime admission transport, and audit
collectors, but the baseline cannot require one job per Pod, one job per
process, application instrumentation, a different ServiceAccount, narrower
RBAC/IAM, a sidecar, a TLS proxy, or a modified agent harness.

## Decision Summary

The proposed architecture makes these decisions:

1. A container is a **container execution set**, not necessarily one native
   tree. Its ordinary entrypoint, kubelet-created exec probes and lifecycle
   commands, administrative exec sessions, and other runtime-created tasks can
   be distinct native roots inside the same container.
2. Every root enters through an authenticated, one-use **entry admission**.
   Native descendants receive their label in kernel before they can perform a
   protected effect.
3. A task is authorized by its exact task/process identity and current role,
   not by its comm, path, PID, Pod name, namespace numbers, or cgroup alone.
4. Policy controls physical effects: executable transitions, file and code
   objects, sockets and packets, devices and ioctls, privileges, kernel
   interfaces, and control-plane operations. It does not pretend to recognize
   malicious intent inside Python.
5. Local decisions are deterministic and synchronous in kernel. Central
   correlation is asynchronous and never sits in a syscall decision loop.
6. Direct TLS is preserved. Operations inside the same allowed TLS channel are
   distinguished only by authoritative server/provider evidence; if that
   evidence arrives after completion, the result is detection and containment,
   not prevention.
7. Prevention continuity and evidence continuity are separate. A full
   ring-buffer or disconnected control plane cannot turn a loaded deny into an
   allow. Missing evidence prevents a negative conclusion.
8. The policy model is extensible. The Hugging Face package is the first set of
   roles, effects, causal predicates, and responses, not a special-purpose
   command signature engine.

These are proposed defaults. The final section lists the decisions that need
explicit approval or a replacement with equivalent proof.

## Claim Boundary

Mithril can protect a Linux or Kubernetes estate on which it is installed. It
cannot retroactively control `HF-001` through `HF-007` in OpenAI's external
evaluation environment, and it cannot claim to reject the uploaded HDF5 or the
Jinja expression itself without an application-owned content gate.

For `HF-008` through `HF-021`, the baseline claim is:

```text
hostile content may reach an existing interpreter
  -> Mithril denies the first distinguishable out-of-profile physical effect
  -> the denial is attached to an exact native execution and policy generation
  -> allowed or already-completed effects are correlated through exact
     Kubernetes/provider identities
  -> the smallest authorized local and remote scopes are contained
  -> postconditions and unresolved branches are reported
```

The following examples define the boundary:

- `os.environ` reading environment already resident in the same Python address
  space has no file syscall for Mithril to deny. Opening
  `/proc/self/environ`, a projected token, or another file does.
- Evaluating attacker-controlled Python inside an existing interpreter may
  create no exec event. `python -> sh`, `python -> curl`, an executable mapping,
  a protected file read, or a socket effect does.
- A new connection to IMDS can be denied by process role and destination. A
  forbidden Kubernetes verb inside a connection that the same role already
  needs is known from Kubernetes audit, not from encrypted packet bytes.
- Git clone and Git push can share a host, port, credential, and TLS
  connection. With no TLS interception and no attenuated provider capability,
  the node cannot honestly distinguish them. Provider audit can detect the
  server-side write and trigger a whole-channel or principal response.

## Source-Derived Mechanism Decisions

KubeArmor and Tetragon are implementation studies, not product chassis. Phase
0 still owns the per-file license and provenance decision. Nothing in this
document authorizes copying source.

### What to learn from KubeArmor

| Source mechanism | Useful lesson | Mithril adaptation | What Mithril must not inherit |
| --- | --- | --- | --- |
| [`enforcer.bpf.c`](../../../KubeArmor/KubeArmor/BPF/enforcer.bpf.c) attaches BPF LSM programs at exec, file, socket, and capability decision points | Select semantic pre-effect LSM hooks and return a denial before completion | Organize owned CO-RE programs by effect family and preserve the earlier LSM return value | A missing protected-container map, scratch map, or path must not silently return allow |
| [`rulesHandling.go`](../../../KubeArmor/KubeArmor/enforcer/bpflsm/rulesHandling.go) compiles higher-level process/file/network/capability rules into bounded map keys and bit masks | Keep policy parsing and conflict resolution in userspace; keep the kernel tuple compact | The Rust compiler produces reviewed immutable generations and finite role/effect keys | Paths and “from source path” are not durable process roles or executable identity |
| [`shared.h`](../../../KubeArmor/KubeArmor/BPF/shared.h) and [`mapHelpers.go`](../../../KubeArmor/KubeArmor/enforcer/bpflsm/mapHelpers.go) use a map-of-maps for per-container generations | Map indirection is a practical atomic policy-generation technique | Bind a stable workload/profile generation to a cgroup identity, then switch one active-generation pointer | PID and mount namespace numbers are reusable context, not the workload key |
| The main exec enforcer retains its decision when ring-buffer reservation fails | Enforcement and alert transport must be independent | Compute and commit the return value before best-effort evidence emission; increment loss counters on failure | Some presets, including [`protectenv.bpf.c`](../../../KubeArmor/KubeArmor/BPF/protectenv.bpf.c), [`filelessexec.bpf.c`](../../../KubeArmor/KubeArmor/BPF/filelessexec.bpf.c), and [`anonmapexec.bpf.c`](../../../KubeArmor/KubeArmor/BPF/anonmapexec.bpf.c), return allow when event reservation fails; that ordering is forbidden |
| Fileless exec, anonymous executable mapping, `/proc/*/environ`, and process inspection presets choose concrete kernel hooks | These are useful object classifiers and acceptance cases | Make them ordinary role-aware effect classes with explicit policy and coverage | A global preset keyed only by container namespace cannot decide which process role legitimately needs the effect |
| [`nriHandler.go`](../../../KubeArmor/KubeArmor/core/nriHandler.go) explicitly records that `StartContainer` occurs after start, namespace IDs can be reused, and enforcement is removed before shutdown | Runtime callback timing and teardown order are security properties | Full protection requires a pre-exec gate, exact lifetime identity, and policy retained through `preStop` and termination | Post-start binding cannot be advertised as enforce-from-first-exec; stop notification cannot remove policy before the last task exits |
| [`processTree.go`](../../../KubeArmor/KubeArmor/monitor/processTree.go) enriches a userspace PID tree and falls back to procfs | Procfs recovery is useful for explicit bootstrap and display | Reconstruct existing tasks as `bootstrapped` and retain the gap | A userspace PID cache is not race-free lineage or actuator identity |

One additional stacking rule is mandatory. BPF LSM programs receive the return
value from an earlier LSM/BPF program. Mithril never turns an earlier denial
back into success:

```text
if prior_ret != 0:
    record prior denial if possible
    return prior_ret
```

Mithril's policy can make a result stricter. It cannot weaken SELinux,
AppArmor, Landlock, another BPF LSM program, or an earlier Mithril program.

### What to learn from Tetragon

| Source mechanism | Useful lesson | Mithril adaptation | What Mithril must not inherit |
| --- | --- | --- | --- |
| [`bpf_fork.c`](../../../tetragon/bpf/process/bpf_fork.c) observes `wake_up_new_task`, inherits parent execution state, and tests fork-without-exec | Fork, clone, thread creation, exec, de-threading, and exit need separate state transitions | Allocate exact task and process identities before a child can perform a protected effect; test every Linux creation variant | Tetragon skips the child when no parent exists in `execve_map`; a protected unknown child must instead fail closed and open a coverage defect |
| [`process.h`](../../../tetragon/bpf/lib/process.h) stores `(pid, ktime)`, parent keys, clone flags, namespace/capability state, and explicit miss/error flags | Native coordinates need time bounds and source quality flags | Retain host TID/TGID/start time as coordinates while using non-reused task/process cookies as durable identity | TGID-keyed execution state is not enough for per-thread identity, non-leader exec, PID reuse, or response authority |
| [`bpf_execve_event.c`](../../../tetragon/bpf/process/bpf_execve_event.c) and [`bpf_execve_map_update.c`](../../../tetragon/bpf/process/bpf_execve_map_update.c) stage exec collection across hooks and tail calls | Complex argument/object collection should be staged and verifier-bounded | Use a small pre-effect decision record and richer post-decision observation record | Rich event construction cannot be allowed to delay or determine the physical deny |
| [`policy_filter.h`](../../../tetragon/bpf/process/policy_filter.h) and [`policyfilter/state.go`](../../../tetragon/pkg/policyfilter/state.go) compile Kubernetes selection into policy-ID/cgroup maps | Filter and select in kernel using a node-resolved cgroup binding | Resolve exact Pod UID/container/image/profile in userspace, then install a generation-bound cgroup key | Labels, image tags, and a cgroup ID without its live interval are not durable identity |
| [`rthooks.go`](../../../tetragon/pkg/policyfilter/rthooks/rthooks.go) and the [`OCI hook`](../../../tetragon/contrib/tetragon-rthooks/cmd/oci-hook/main.go) obtain Pod, image, mount, and cgroup context before normal execution | Runtime metadata closes attribution gaps that the kernel cannot infer | Use authenticated runtime handoff plus live cgroup/task re-resolution | A create-container notification alone does not admit later `ExecSync`/streaming exec roots |
| [`cache.go`](../../../tetragon/pkg/process/cache.go) handles out-of-order events and garbage collection | The central graph must accept replay, duplicates, and late events | Immutable observations build versioned views; local WAL sequence exposes gaps | A userspace LRU record cannot authorize a syscall or irreversible response |
| [`fork_test.go`](../../../tetragon/pkg/sensors/exec/fork_test.go) exercises fork-without-exec | Kernel edge cases deserve real executable fixtures | Carry these cases into Phase 2 and the standing incident suite | A happy-path `fork -> exec -> exit` test is not sufficient identity proof |

The intended synthesis is narrow: KubeArmor demonstrates useful BPF LSM
decision points and policy lowering; Tetragon demonstrates useful kernel
lineage, cgroup filtering, lifecycle metadata, miss flags, and test patterns.
Mithril replaces their container/path/PID authority with its own exact task,
entry, role, coverage, and response contracts.

## Protection Invariants

These invariants apply across all phases once the owning capability is enabled:

| ID | Invariant |
| --- | --- |
| `INV-ENTRY-001` | Every task performing a protected effect has either a verified native-parent label or a verified external-entry admission. |
| `INV-ENTRY-002` | An unlabeled task in a protected cgroup is denied at its first protected hook unless it atomically claims a matching one-use entry intent. |
| `INV-ENTRY-003` | Reparenting, PID reuse, namespace reuse, cgroup reuse, runtime restart, or kubelet restart cannot change a task's birth lineage. |
| `INV-ROLE-001` | A role is assigned by an admitted entry or approved transition; executable path and process name alone never assign authority. |
| `INV-ROLE-002` | Fork without exec receives a restrictive inherited child role and remains enforceable. Exec without fork retains process identity and creates a new execution identity. |
| `INV-EFFECT-001` | The most specific deny wins. Missing protected identity, generation, object classification required by policy, or response state fails closed. |
| `INV-EFFECT-002` | Event construction, rate limiting, ring-buffer pressure, WAL pressure, or control-plane availability cannot change a computed local denial into allow. |
| `INV-POLICY-001` | Only a signed, validated, locally compiled generation can enter enforcement maps. Observation never self-authorizes. |
| `INV-POLICY-002` | A policy update is atomic for new decisions; old generations remain until no live task or socket refers to them. |
| `INV-K8S-001` | Container start, runtime exec, exec probe, lifecycle exec, interactive exec, init container, sidecar, and ephemeral container are distinct entry classes even when they use the same binary. |
| `INV-K8S-002` | `preStop` and shutdown tasks remain protected. Termination is not an implicit policy bypass. |
| `INV-GRAPH-001` | Native parent edges never cross a node. Remote expansion uses typed causal edges with named proof. |
| `INV-RESPONSE-001` | A response re-resolves the live kernel/provider target and verifies a physical postcondition; a stale graph identifier is never an actuator handle. |
| `INV-COVERAGE-001` | A missing hook, sequence gap, bootstrap edge, ambiguous entry, or unavailable provider feed narrows the claim instead of being interpreted as benign. |

## Identity And Execution Model

### Why a container can have several roots

The container's configured entrypoint is created by the runtime and has no
native parent inside the workload. Later, kubelet or an administrator can ask
the runtime to execute another command in the same container. That new task
can be created by a host runtime/shim and placed into the container's cgroup
and namespaces; it need not be a descendant of container PID 1.

Therefore this graph is wrong:

```text
container PID 1
  -> every legitimate task in the container
```

The required graph is:

```text
ContainerExecutionSet
  +-- ContainerStartEntry -----------------> native tree A
  +-- KubeletPostStartEntry ---------------> native tree B
  +-- KubeletExecProbeEntry #1 ------------> native tree C
  +-- KubeletExecProbeEntry #2 ------------> native tree D
  +-- KubeletPreStopEntry -----------------> native tree E
  +-- AdministrativeExecEntry -------------> native tree F
  +-- other admitted runtime entries ------> native tree ...
```

The edge from an entry to its root process is `entry_started_execution`, not a
fabricated Linux parent edge. Ordinary fork/clone/exec edges below each root
remain native.

### Durable identity objects

```text
ContainerExecutionSet {
  execution_set_id
  tenant_id
  cluster_uid
  node_boot_id
  pod_uid
  pod_resource_version
  sandbox_id
  full_container_id
  container_kind: init | sidecar | application | ephemeral
  image_digest
  cgroup_binding_id
  cgroup_live_interval
  profile_id
  active_profile_generation
  lifecycle_generation
}

EntryInstance {
  entry_instance_id
  execution_set_id
  entry_nonce
  entry_kind
  request_transport
  request_provenance
  classification: exact | conservative | ambiguous | unknown
  pod_spec_digest
  command_digest
  candidate_binary_identity
  requested_at
  claim_deadline
  claimed_task_cookie?
  target_role_id
  state: pending | claimed | expired | denied | completed
}

TaskLabel {
  node_boot_id
  label_epoch
  task_cookie
  process_lineage_id
  process_instance_id
  entry_instance_id
  execution_set_id
  profile_generation
  role_id
  execution_id
  lineage_depth
  ancestor_process_lineage_ids[MAX_DEPTH]
  dynamic_state_bits
  response_state
}
```

`task_cookie` and `process_lineage_id` are allocated by Mithril for the node
boot/label epoch. TID, TGID, namespace IDs, cgroup ID, start boottime, and pidfd
are live coordinates and revalidation material. They are not durable identity
alone.

### Native inheritance algorithm

At the earliest target-kernel-proven task allocation hook:

```text
on_task_create(parent, child, clone_flags):
    parent_label = task_storage[parent]

    if parent is outside every protected binding:
        do not invent a protected label
        return

    if parent_label is missing:
        mark protected binding identity_incomplete
        install fail_closed_unknown label on child if the hook permits
        return

    child.task_cookie = allocate_monotonic_cookie()
    child.entry_instance_id = parent.entry_instance_id
    child.execution_set_id = parent.execution_set_id
    child.profile_generation = parent.profile_generation

    if clone_flags contains CLONE_THREAD:
        child.process_lineage_id = parent.process_lineage_id
        child.process_instance_id = parent.process_instance_id
        child.role_id = parent.thread_child_role or parent.role_id
    else:
        child.process_lineage_id = allocate_monotonic_process_id()
        child.process_instance_id = derive_process_instance_id(...)
        child.ancestors = parent.ancestors + parent.process_lineage_id
        child.role_id = transition(parent.role_id, FORK_WITHOUT_EXEC)

    if ancestor bound would overflow:
        apply profile overflow action: deny creation or cgroup-scope response

    atomically attach label before child can perform a protected effect
```

The observation hook then emits the exact parent/child coordinates. If event
delivery fails, the label still exists. If the selected kernel cannot prove
pre-run inheritance, that kernel tier is observation-only until an equivalent
fallback passes the hostile identity matrix.

### Exec transition algorithm

At `bprm_check_security`:

```text
on_exec(current_task, candidate_file, argv):
    preserve any earlier LSM denial
    binding = resolve_live_protected_cgroup(current_task)
    label = task_storage[current_task]

    if binding is protected and label is missing:
        label = claim_external_entry_or_deny(binding, candidate_file, argv)

    source_role = label.role_id
    binary_key = classify_executable_object(candidate_file, binding.mount_view)
    interpreter_chain = classify_script_or_interpreter(candidate_file)
    edge = lookup_exec_edge(profile_generation, source_role,
                            binary_key, interpreter_chain)

    if response policy, hard invariant, or edge says deny:
        return -EACCES

    stage PendingExecCommit(task_cookie, edge.result_role,
                            binary_key, policy_generation)
    return prior_ret
```

At the post-exec observation point, Mithril verifies that the staged candidate
became the execution image, closes the prior `ExecutionInstance`, assigns the
resulting role, and emits the new instance. A failed or mismatched commit is a
coverage defect and leaves the task in a restrictive fail-closed role.

Non-leader thread exec and Linux de-threading must retain the task cookie and
process-lineage ID while updating native TID/TGID coordinates.

## Kubernetes And Runtime-Created Entry Architecture

### Current Kubernetes facts the classifier must respect

Current Kubernetes behavior creates several materially different cases:

- `PostStart` begins concurrently with the container entrypoint; it is not
  ordered strictly before or after the main process.
- An exec lifecycle handler runs inside the container's cgroups and
  namespaces. HTTP and sleep handlers run from kubelet; they do not create a
  new task in the container.
- Exec probes create commands inside the container. HTTP, TCP, and gRPC probes
  are node-originated network operations and create no probe command in the
  container.
- Lifecycle hooks are at-least-once and can be repeated after kubelet failure.
- `PreStop` finishes before the normal termination signal, but its time is
  charged to the termination grace period.
- Init, sidecar, application, and ephemeral containers are separate container
  roots even when they share Pod namespaces or volumes.

The stock CRI `ExecSyncRequest` carries `container_id`, `cmd`, and `timeout`.
It does **not** state whether kubelet is running startup/readiness/liveness,
`PostStart`, or `PreStop`. This is an information limitation in the interface,
not a KubeArmor/Tetragon limitation. Exact semantic classification requires an
authenticated kubelet-side reason or a conservative policy when declarations
are indistinguishable.

Primary references are the Kubernetes
[lifecycle-hook documentation](https://kubernetes.io/docs/concepts/containers/container-lifecycle-hooks/),
[probe documentation](https://kubernetes.io/docs/concepts/workloads/pods/probes/),
[`handlerRunner`](https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/lifecycle/handlers.go),
[`prober`](https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/prober/prober.go),
and the [CRI runtime API](https://github.com/kubernetes/cri-api/blob/master/pkg/apis/runtime/v1/api.proto).

### Entry-class matrix

| Kubernetes/runtime situation | Native shape | Required entry treatment | Default role and decision |
| --- | --- | --- | --- |
| Initial application entrypoint | Runtime-created root in new container cgroup | Pre-start `ContainerStartEntry` bound to full container/image/Pod/profile generation | Exact `application-root`; deny start if strict admission cannot complete |
| Regular fork/thread from labeled workload | Native descendant | Kernel inheritance; no runtime admission | Profile transition or restrictive inherited role |
| Exec `PostStart` | Possible secondary root, concurrent with entrypoint | One-use `KubeletPostStartEntry`, matched against exact PodSpec generation | Narrow `kubelet-poststart`; no inheritance of all application authority |
| Exec `PreStop` | Possible secondary root during termination | One-use `KubeletPreStopEntry`; policy stays installed through exit | Narrow `kubelet-prestop`; no universal containment bypass |
| Exec startup/liveness/readiness probe | Repeated secondary roots | Bounded, repeatable `KubeletExecProbeEntry` matched to effective PodSpec command | `kubelet-exec-probe`; strict file/socket/exec budget |
| HTTP lifecycle handler | Kubelet-originated connection to Pod endpoint | No workload entry; retain node-flow and declared-hook context | Do not invent a workload process or parent edge |
| HTTP/TCP/gRPC probe | Kubelet-originated connection | No workload entry; optional inbound-probe observation | Do not treat application receiver thread as a probe-created root |
| Sleep lifecycle handler | Sleep in kubelet | No workload task or entry | No workload decision |
| `kubectl exec` / streaming exec | Runtime-created secondary root plus Kubernetes `pods/exec` audit | `AdministrativeExecEntry`, correlated to audit principal when possible | Default deny or explicit approval; limited break-glass role |
| `kubectl cp` | Usually a streaming exec that runs archive tooling | Same as administrative exec; never infer benignity from `tar` | Default deny or explicit scoped file-transfer role |
| Direct `crictl exec` or runtime API exec | Runtime-created secondary root without Kubernetes user audit | `HostAdministrativeExecEntry` with runtime peer evidence | Deny on protected workloads unless host break-glass policy allows |
| Ephemeral container | Separate container creation, optionally targeting another PID namespace | Normal container-root admission with `container_kind=ephemeral` and API audit | Default deny for protected workloads or isolated diagnostic profile |
| Init container | Separate ordered container root | Its own execution set and image/profile | Init-specific role; never app-role inheritance |
| Native sidecar | Separate independently restarted container root | Its own execution set and image/profile | Sidecar-specific role; shared Pod network does not merge lineage |
| OCI runtime hook process | Infrastructure process, often outside workload cgroup | Infrastructure observation only | Never assign workload authority from shared namespaces alone |
| `nsenter` or task moved into protected cgroup | Unlabeled external task | No pending authenticated entry means deny first protected effect | `unknown-external-entry` finding; fail closed |
| Container restart in same Pod | New full container ID, cgroup live interval, root and lifecycle generation | New execution set and root admission | Never reuse the prior root label or response target implicitly |

### One-gatherer runtime integration

The only Mithril event and policy owner remains the one `mithril-node` process.
Runtime integration is an admission transport, not another gatherer:

```text
kubelet / CRI caller
    -> runtime execution path
       -> lightweight hook, in-runtime adapter, or CRI admission proxy
          -> authenticated local RuntimeEntryIntent to mithril-node
             -> task/entry label installed and verified
          <- one-use acknowledgement
       -> runtime permits candidate executable transition
```

Preferred mechanisms, in descending order of guarantee:

1. A runtime/shim integration holds the exact new task before user executable
   installation, passes a pidfd plus full runtime identity, and resumes only
   after Mithril installs and reads back the task label.
2. The `mithril-node` process provides a local CRI admission proxy and writes a
   one-use pending intent before forwarding `ExecSync`/`Exec`; an unlabeled
   task may claim that intent only at `bprm_check_security` in the exact bound
   cgroup and for the exact candidate executable class.
3. An OCI pre-start hook, delivered as a short-lived mode of the same product
   binary, provides initial-container admission. This does not solve later
   runtime exec by itself.
4. Observe-only runtime callbacks may enrich a task after start, but they must
   report a start gap and cannot claim enforce-from-first-exec.

An NRI `StartContainer` callback alone is insufficient for full protection;
the local KubeArmor implementation documents precisely that post-start gap.
No permanently resident second collector is introduced. A short-lived hook or
code executing inside the runtime is not allowed to own policy maps, lineage,
WAL, or an independent event stream.

### `RuntimeEntryIntent`

```text
RuntimeEntryIntent {
  nonce: 128-bit random
  caller_transport: oci_hook | cri_execsync | cri_exec | runtime_shim
  caller_peer: authenticated local identity
  request_sequence
  cluster_uid
  node_boot_id
  pod_uid
  pod_resource_version
  full_container_id
  cgroup_binding_id
  runtime_lifecycle_generation
  operation: container_start | exec_sync | streaming_exec | ephemeral_start
  command: redacted argv plus canonical digest
  candidate_binary_hint
  tty, stdin, stdout, stderr
  requested_at
  deadline
}
```

The userspace classifier joins the request to the effective PodSpec and emits
an `EntryInstance`. It never trusts container annotations alone; it re-resolves
the full container, cgroup live interval, Pod UID, image digest, and policy
generation.

### ExecSync classification algorithm

```text
classify_exec_sync(intent, pod_spec, container_state):
    candidates = []

    for each declared exec startup/liveness/readiness probe:
        if canonical_command matches intent.command:
            add candidate(kind=probe type,
                          allowed_state=running and probe schedule eligible)

    for postStart exec:
        if command matches and lifecycle generation is starting:
            add candidate(kind=postStart)

    for preStop exec:
        if command matches and lifecycle generation is terminating:
            add candidate(kind=preStop)

    discard candidates with wrong Pod resource version, container ID,
    lifecycle generation, command, deadline, or multiplicity budget

    if authenticated kubelet reason exists and exactly matches a candidate:
        classification = exact
    else if all remaining candidates compile to the same target role and
            identical effect budget:
        classification = conservative
    else if no candidate remains:
        deny as undeclared runtime exec
    else:
        classification = ambiguous
        apply profile's ambiguity action, default deny in protect mode
```

Timing is supporting evidence, never the sole proof. A command that happens to
run every ten seconds does not become a liveness probe. Matching a declared
command does not authorize a different caller. Kubelet restarts and the
at-least-once hook contract are handled with idempotency keys and bounded
multiplicity, not a single expected timestamp.

When unmodified CRI cannot distinguish two declarations and their effect
budgets differ, only three honest choices exist:

- deny the ambiguous entry;
- compile the explicitly approved union of both budgets and mark the entry
  `conservative`; or
- install an authenticated kubelet/runtime reason extension.

Mithril must not pop an arbitrary pending intent and label the task with a more
powerful role.

### Pending-intent claim algorithm

The pidfd handshake is preferred. The fallback for a runtime that cannot
provide the task before exec is an atomic claim at `bprm_check_security`:

```text
claim_external_entry_or_deny(binding, candidate_file, argv):
    assert current task has no label
    assert binding is protected and live

    candidate_key = bounded_exec_classifier(candidate_file, argv)
    pending_key = (binding.id, binding.lifecycle_generation, candidate_key)
    intents = pending_entry_map[pending_key]

    choose only an unexpired intent whose role/effect budget is unique
    atomically change PENDING -> CLAIMED with current task cookie
    reject stale generation, duplicate claim, exhausted multiplicity,
           wrong binary object, or ambiguous target role

    install external-root TaskLabel before continuing exec evaluation
    emit entry_started_execution separately
```

An attacker-created native child cannot claim an external intent because it
already carries its inherited task label. An unlabeled task manually moved
into the cgroup cannot claim without a live authenticated intent. A host-root
attacker who can modify the runtime, BPF maps, or Mithril process is outside
this node trust boundary and must be handled by host integrity controls.

The prototype must prove that the selected BPF hooks can safely parse the
bounded executable/argv material and create task storage. If not, the fallback
is not promoted; full support requires the runtime-held pidfd path.

### Shutdown and containment interaction

Policy is retained until the runtime confirms exit and a BPF task/cgroup
reconciliation proves no live member remains. `StopContainer` and Pod deletion
change lifecycle state; they do not delete enforcement maps.

When a lineage is contained:

- new ordinary external entries are denied;
- declared `preStop` is not automatically allowed;
- a profile may authorize a narrow shutdown role with exact file/socket
  effects and a deadline;
- if that cleanup role could re-open the attack path, containment wins and the
  hook fails;
- cgroup freeze or kill is a separate typed response with its own approval;
- kubelet/controller replacement is watched and constrained separately.

## Policy Package And Compiler

### Source policy object

```text
WorkloadProtectionProfile {
  profile_id
  version
  schema_version
  issuer
  signature
  valid_from, valid_until?
  selectors
  required_capabilities
  default_postures
  entry_rules[]
  roles[]
  transition_rules[]
  effect_rules[]
  dynamic_state_rules[]
  authority_behavior_rules[]
  correlation_packages[]
  response_rules[]
  coverage_requirements[]
  rollout
}
```

Selectors find candidate workloads in userspace. They do not become kernel
authority. The binder resolves a selector to an exact Pod UID, full container
ID, immutable image digest, cgroup live interval, and profile generation.

### Entry rules

```text
EntryRule {
  entry_kind
  container_kind
  command_match: exact digest | executable object | none
  pod_spec_field_proof
  permitted_lifecycle_states
  caller_proof
  concurrency_limit
  rate_budget
  claim_ttl
  target_role_id
  ambiguity_action
  default_action
}
```

Arguments may help classify a declared kubelet action, but arguments are not a
substitute for physical effect policy. Shell quoting, interpreter flags, file
descriptors, environment, and in-process code make an argv allowlist
insufficient.

### Roles and transitions

```text
Role {
  role_id
  description
  entry_origins[]
  thread_creation
  fork_without_exec_target_role
  max_native_depth
  allowed_exec_edges[]
  effect_policy_id
  dynamic_state_machine_id
}

TransitionRule {
  source_role_id
  operation: fork | clone_thread | exec | privilege_transition
  candidate_object_key?
  interpreter_chain?
  required_state_bits
  resulting_role_id
  decision: allow | audit | deny
}
```

Recommended initial roles for the incident fixture are:

| Role | Purpose | Default dangerous effects |
| --- | --- | --- |
| `conversion-worker-root` | Existing unchanged interpreter/worker | deny undeclared exec, credential objects, API/IMDS, device/privilege escape |
| `conversion-worker-child` | Forked child that has not execed | narrower than root; cannot claim runtime entry |
| `declared-tool` | Exact approved worker child executable | only tool-specific files and destinations |
| `kubelet-exec-probe` | Declared startup/readiness/liveness command | no child exec, credential read, public egress, API/IMDS, device, or privilege effects by default |
| `kubelet-poststart` | Declared setup command | only reviewed setup objects/effects; bounded lifetime |
| `kubelet-prestop` | Declared cleanup command | reviewed cleanup effects and deadline; no containment bypass |
| `administrative-exec` | Approved interactive session | explicit break-glass policy, actor, TTL, recording/coverage requirements |
| `ephemeral-diagnostic` | Approved ephemeral container | separate container profile and restricted cross-container process/file access |
| `unknown-protected-task` | Identity or entry failure | deny every protected effect and emit high-severity coverage finding |
| `restricted-lineage` | Active response state | deny new exec/file/socket/device/privilege effects according to response policy |

### Effect rules

```text
EffectRule {
  role_id
  effect_family
  operation
  object_class
  object_key_match
  required_dynamic_state
  lifecycle_states
  decision: allow | audit | deny
  errno
  set_state_bits[]
  clear_state_bits[]
  evidence_level
}
```

An object class is a policy concept such as `dataset-input`,
`projected-service-account-token`, `worker-environment-procfile`,
`kubernetes-api`, `cloud-imds`, `mesh-control`, `tun-device`, or
`anonymous-executable-memory`. The kernel uses compact compiled keys; the
evidence record retains the resolved semantic class and provenance.

### Authority behavior rules

Linux can decide that a process may connect to the Kubernetes API. It cannot
parse an already-encrypted request and decide that `list pods` is expected but
`create rolebinding` is not. That second decision belongs to an asynchronous
authority behavior policy:

```text
AuthorityBehaviorRule {
  principal_selector
  source_workload_selector
  authority: kubernetes | aws | github | mesh | connector | artifact_repo
  allowed_operations[]
  allowed_resource_selectors[]
  allowed_credential_lease_types[]
  time/rate/concurrency budgets
  required_request_proof
  finding_on_deviation
  response_playbook
}
```

This rule consumes Kubernetes/provider audit. It never claims that the kernel
prevented a server operation that had already succeeded.

### Compilation pipeline

```text
signed source profile
  -> schema and signature validation
  -> selector resolution and immutable workload snapshot
  -> conflict and reachability analysis
  -> entry/role state-machine compilation
  -> object classifier compilation
  -> compact effect decision tables
  -> response and coverage requirement compilation
  -> userspace simulation against observed workload baseline
  -> human approval
  -> inactive BPF map generation
  -> read-back + controlled allow/deny probes
  -> atomic active-generation switch
```

Compiler rejection conditions include:

- an entry maps ambiguously to roles with unequal budgets without an explicit
  ambiguity action;
- a role is unreachable or can escalate through a transition cycle;
- a deny depends on an unsupported hook or object key;
- a path-only executable is marked immutable;
- a rule claims a TLS/server verb from network-only evidence;
- a response target lacks a revalidation key and physical postcondition;
- an allow would override a hard invariant or active response state;
- a required object classifier can return unknown with fail-open behavior; or
- the generation exceeds verified BPF map, stack, instruction, depth, or
  latency bounds.

Observation generates a **candidate** role/effect profile. It never writes an
allow directly into the active generation. Candidate promotion requires
review, simulation, signature, controlled probes, and rollout health.

### Policy precedence

Every protected hook evaluates in this order:

1. Preserve a nonzero prior LSM result.
2. Resolve the live protected cgroup/profile binding.
3. Resolve or admit the exact current task label.
4. Apply response-root and emergency hard-deny state.
5. Apply immutable product invariants.
6. Apply exact entry/role transition or effect rule.
7. Apply role and profile default posture.
8. Commit dynamic state changes associated with an allowed/audited effect.
9. Emit decision evidence independently.

No later step can change an earlier deny into allow.

## Node Decision Architecture

### Compiled map model

The exact layout is Phase 0 ABI work, but the architecture requires the
following logical maps:

```text
protected_cgroup_bindings:
  live cgroup key -> execution set, profile generation, lifecycle, mode

task_labels:
  BPF task storage -> TaskLabel

pending_entries:
  binding + lifecycle generation + candidate class -> one-use entry slots

active_profile_generations:
  profile ID -> active generation pointer

role_transition_tables[generation]:
  source role + transition + object key -> decision + target role

effect_tables[generation]:
  role + effect + operation + object class/key + state -> decision

response_roots:
  node boot + label epoch + process lineage -> restrictions + TTL

socket_labels:
  socket storage -> creator/current process, role, generation, destination,
                    flow identity, response state

coverage_counters:
  per CPU/hook/generation sequence, drop, classifier miss, map failure
```

The cgroup key must survive ancestor placement and cgroup v2 layout variation.
The node binder records the kernel cgroup ID, a generation/live interval, a
tracker for descendants where needed, the full cgroup path for evidence, and
the container/Pod binding. A bare cgroup ID recovered after deletion is not
enough to revive a binding.

Policy maps are bounded and preallocated where the selected hook cannot safely
allocate. Map exhaustion is a health transition. In protect mode, exhaustion
that prevents identity or a required lookup fails closed for the affected
protected binding; it does not silently evict a live label or rule.

### Generic pre-effect algorithm

```text
decide(effect_context):
    if effect_context.prior_lsm_result != 0:
        best_effort_emit(STACKED_DENIAL)
        return prior_lsm_result

    binding = protected_cgroup_bindings.lookup_current_ancestor()
    if binding is absent:
        return evaluate_explicit_host_policy_or_allow()

    if binding is expired, tombstoned, or outside its live interval:
        return deny(IDENTITY_STALE)

    label = task_storage.current()
    if label is absent:
        if effect is executable transition:
            label = atomically_claim_pending_entry()
        if label is still absent:
            return deny(PROTECTED_TASK_UNLABELED)

    if label.execution_set_id, generation, epoch, or node boot disagrees
       with binding:
        return deny(IDENTITY_BINDING_MISMATCH)

    if response_roots matches label.process or any bounded ancestor:
        return evaluate_response_restriction(effect)

    object = classify_effect_object(effect_context)
    if object is unknown and profile requires exact classification:
        return deny(REQUIRED_OBJECT_UNKNOWN)

    rule = exact_effect_lookup(label.role, effect, object,
                               label.dynamic_state, binding.lifecycle)
    decision = rule or profile.default_for(effect)

    if decision allows/audits:
        apply atomic dynamic-state transition

    best_effort_emit(decision, exact identity, object, generation,
                     classifier quality, coverage counters)
    return decision.errno_or_prior_result
```

`best_effort_emit` reserves a ring record only after the decision is fixed.
Failure increments a per-CPU loss counter visible to the collector. The
decision path never waits for Rust, the central service, DNS, Kubernetes, an
LLM, or provider audit.

## Effect-Family Algorithms

### Executable images and commands

Mithril governs executable transitions, not command strings alone.

The executable object key should contain the strongest target-kernel evidence
available:

```text
ExecutableObjectKey {
  mount_view_generation
  mount_id
  superblock/device identity
  inode number
  inode generation/version where available
  file type and executable mode
  immutable image-layer/file-manifest identity if pre-resolved
  IMA/fs-verity/content digest if available without a decision-path race
  overlay origin/copy-up state
  deleted_or_unlinked
  memfd/anonymous class
}
```

Userspace resolves immutable image files into object keys when binding the
profile. The BPF decision compares the live candidate file object to the
compiled key. It does not synchronously hash an arbitrary executable in every
exec hook. Mutable executable objects require an explicit mutable-code rule or
an integrity mechanism such as fs-verity/IMA; matching a pathname is not
equivalent.

Required cases:

- `execve`, `execveat`, `fexecve`, scripts and shebang interpreters;
- dynamic linker and interpreter transitions;
- memfd, deleted file, `/dev/shm`, `/run/shm`, and unlinked executable images;
- overlay copy-up and mount replacement;
- a renamed or bind-mounted approved binary;
- an approved pathname whose inode/content changed;
- non-leader thread exec and de-threading; and
- forked code that performs effects without exec.

`python -> sh` and `python -> curl` are denied at the executable edge when the
role lacks those target object keys. Python importing a module or evaluating a
template in-process creates no executable transition; file/code mapping and
later effects remain the control points.

### File and credential objects

File policy is role, operation, and object based:

```text
FileEffectKey = (
  role_id,
  operation: open_read | open_write | permission | mmap_exec |
             truncate | create | rename | link | unlink | ioctl,
  object_class,
  live_file_object_key,
  lifecycle_state,
  dynamic_state
)
```

Primary hooks include BPF LSM `file_open`, `file_permission`, `mmap_file`, and
selected inode/path hooks required to cover creation, rename, link, unlink,
and mount-view changes. The compiler must state which operation is actually
prevented by which hook; a later close/write tracepoint is evidence only.

Initial Hugging Face object classes include:

| Object class | Representative resolver | Default conversion-worker rule |
| --- | --- | --- |
| `dataset-input` | admitted job mount/root plus immutable revision when known | read; no execute; write only to declared output |
| `worker-runtime` | immutable image/runtime libraries | read/map according to executable profile |
| `worker-scratch` | exact scratch mount and lifetime | bounded read/write/create; no execute by default |
| `worker-environment-procfile` | `/proc/<pid>/environ` resolved to target task | deny cross-task; self-read requires explicit rule |
| `projected-service-account-token` | Kubernetes projected volume provenance plus Pod/container binding and rotating file identity | deny for conversion role; allow only controller role that demonstrably needs it |
| `cloud-credential-file` | mounted credential volume/provider path provenance | deny unless exact role requires it |
| `other-proc-task` | target task cookie/process plus proc inode/path class | deny inspection absent declared diagnostics |
| `host-filesystem` | mount provenance outside admitted container view | deny |
| `socket-or-device-file` | inode type plus device identity | dispatch to socket/device policy |
| `anonymous-executable-memory` | executable anonymous mapping | deny unless reviewed JIT role |

Projected tokens rotate, so policy cannot pin only one inode forever. The
binder classifies the mounted projected volume and its path/object lifetime;
rotation updates the exact live object set without broadening the directory to
arbitrary files.

Opening `/proc/self/environ` is enforceable. Reading the process's already
resident environment with a language API is not. If the role legitimately
holds secrets in memory, file policy alone cannot prevent in-process access;
Mithril must stop the next exfiltration or authority effect and report that
the memory read itself was unobservable.

Already-open descriptors, inherited descriptors, descriptor passing,
`mmap`, `sendfile`, `splice`, shared memory, and `io_uring` are separate
coverage cases. A file-open denial claim cannot be generalized to data already
present in process memory or a descriptor obtained before policy attachment.

### Coarse sensitive-read state

Mithril may maintain a deterministic process state bit after an observable
sensitive read:

```text
on allowed/audited read of credential or protected secret object:
    process.dynamic_state |= OBSERVED_SENSITIVE_READ

on later socket/write/exec effect:
    use the stricter effect table for OBSERVED_SENSITIVE_READ
```

This is coarse information-flow control, not byte-level taint. It is useful for
roles that may read one sensitive file but must not subsequently contact public
destinations or create artifacts. It cannot prove that bytes sent came from
that file, and it cannot see secrets read from existing memory. Profiles must
opt in after baseline simulation because the state can intentionally tighten
all later effects of the process.

### Network, sockets, and packets

Network policy has two distinct jobs:

1. pre-effect authorization for socket creation, connection, bind/listen,
   send, and packet transmission; and
2. response fencing for existing and future flows.

The socket label is created in socket storage and carries the creating
task/process/role/profile generation. On inheritance or descriptor passing,
the effect is evaluated against the **current sender** and the socket label;
the receiver does not automatically acquire the creator's network authority.

```text
NetworkEffectKey = (
  current_role,
  socket_creator_role,
  operation,
  family/type/protocol,
  network_namespace_generation,
  destination_class,
  address/prefix,
  port,
  DNS/provenance quality,
  dynamic_state,
  response_state
)
```

Required mechanisms include:

- BPF LSM `socket_create`, `socket_connect`, and `socket_sendmsg` where
  available and target-kernel-proven;
- cgroup `connect4/6` and `sendmsg4/6` for address decisions;
- socket storage for process/role attribution;
- cgroup/TC packet policy for established-flow and packet-level fences; and
- explicit coverage for UDP, IPv6, raw/packet sockets, TUN/TAP, AF_XDP,
  `io_uring`, BPF redirects, inherited descriptors, `SCM_RIGHTS`,
  `sendfile`, and `splice`.

Initial destination classes include `kubernetes-api`, `cloud-imds`,
`cloud-api`, `public-internet`, `approved-dataset-service`, `artifact-store`,
`mesh-control`, `mesh-peer`, `connector`, and `unknown`.

DNS is evidence, not destination identity by itself. The node records query,
answer, TTL, network namespace, and socket timing, then enforces the actual
address/prefix/service identity. Hard-coded IPs, stale DNS, CNAMEs, IPv6,
private endpoints, and alternate interfaces must not bypass the class.

A conversion role that never needs the Kubernetes API or IMDS is denied at
connect/send. A controller role that needs the Kubernetes API may connect; its
verbs and resources are evaluated later from Kubernetes audit. Direct TLS
remains opaque.

### Devices and ioctl APIs

Device admission uses cgroup v2 device BPF for major/minor/access plus file and
ioctl policy for the API exposed by the device:

```text
DeviceEffectKey = (
  role_id,
  device_type,
  major,
  minor or range,
  access: read | write | mknod,
  ioctl_command_class,
  lifecycle_state
)
```

`/dev/net/tun` is a key Hugging Face control. Denying the file or cgroup-device
access prevents an unapproved process from creating a TUN interface even if a
mesh client binary is present. Raw block devices, GPUs, accelerators, FUSE,
KVM, and terminal devices require separate policy classes; “device allowed”
does not mean every ioctl is allowed.

### Privilege and kernel escape effects

The security effect family covers:

- capability checks and credential transitions;
- setuid/setgid/file-capability executable transitions;
- ptrace and cross-process access;
- namespace create/join and `setns`;
- mount, pivot-root, filesystem context, and propagation changes;
- BPF program/map operations;
- perf events and kernel tracing interfaces;
- kernel module loading;
- keyring operations;
- dangerous sysctls and `/proc` control files; and
- seccomp changes that weaken an existing floor.

The selected LSM/cgroup/seccomp hooks vary by kernel. Phase 0 produces a
capability matrix and controlled deny probe per claimed operation. A missing
hook is a reduced protection tier, not a best-effort equivalent.

Seccomp is complementary: it cheaply removes syscall classes a role never
needs, but ordinary seccomp cannot decide rich file objects, cgroup-bound
roles, Kubernetes identities, or provider operations. Landlock and mount
namespaces can provide optional process-local/filesystem floors, but Mithril's
node BPF LSM remains necessary for exact cross-process roles, runtime-created
entries, dynamic response, network/device/security effects, and evidence.

## Deterministic Detection And Correlation Algorithms

Local prevention is not enough when an effect was allowed, happened before
attachment, used an existing encrypted channel, or originated outside the
node. Mithril Control runs versioned packages over immutable observations.

### Evidence prerequisites

Every package declares:

```text
PackagePrerequisite {
  required_sources[]
  required_coverage_intervals[]
  maximum_lateness_by_source
  exact_join_fields[]
  permitted_contextual_fields[]
  suppression_requirements[]
}
```

An unavailable audit feed produces `insufficient_coverage`, not “no malicious
operation.” Events can arrive in any order. Package state is keyed by exact
subjects and recomputed when late evidence arrives; duplicates are idempotent.

### `HF-PROC-001`: unexpected native effect

This package explains a local deny or audited deviation:

```text
input: exact TaskLabel + EntryInstance + role + EffectObservation

if task/entry identity incomplete:
    emit LineageCoverageGap, not a proven malicious edge
else if effect decision is deny:
    emit UnexpectedEffect with prevention point and physical errno
else if effect is allowed but outside reviewed role baseline:
    emit AuditedRoleDeviation

attach:
  native ancestors, entry class, binary object identity, cgroup/Pod/container,
  policy generation, dynamic state, hook, decision, loss counters
```

The finding does not rely on a process name such as `curl`. The same binary can
be allowed from a declared tool role and denied from an exec-probe or worker
role.

### `HF-DW-001`: credential-to-authority pivot

This package correlates an observable credential access or credential-bearing
channel with later authority use:

```text
state key = exact credential object/lease when available,
            otherwise exact process/socket/workload scope with weaker proof

facts:
  A = protected credential object read or credential lease obtained
  B = socket/channel to authority or credential used in provider audit
  C = server-side operation outside AuthorityBehaviorRule

if A and B share exact task/process/socket/lease proof and C is authoritative:
    emit direct credential_pivot path
else if only workload + principal + bounded time match:
    emit contextual hypothesis; do not authorize credential-specific response
```

Expected controller token reads and expected API verbs are negative controls.
Two Pods sharing a ServiceAccount name never receive an exact credential edge
from that name alone.

### `HF-XNODE-001`: distributed Kubernetes expansion

```text
LinuxExecution A on node 1
  -> process_issued_api_request (exact socket/request or credential proof)
  -> Kubernetes AuditEvent auditID
  -> api_request_created_or_mutated_resource object UID/resourceVersion
  -> owner-reference/controller reconcile chain
  -> Pod UID
  -> scheduler binding/spec.nodeName
  -> container full ID/cgroup on node 2
  -> ContainerStartEntry
  -> LinuxExecution B on node 2
```

Each arrow is a typed immutable edge with evidence IDs, proof strength,
coverage references, and missing fields. Time adjacency, an IP address, a
label selector, a ServiceAccount name, or the same process name cannot create
the direct path alone. Fan-out creates one branch per exact object/Pod/root.

### Provider and connector expansion

AWS, mesh, connector, GitHub, artifact, and message systems use the same rule:

- exact request IDs, credential lease/access-key IDs, installation IDs,
  connector invocation IDs, message IDs/offsets, and immutable artifact
  digests can create direct edges;
- principal name, repository name, IP, mutable tag, and time can create only
  contextual evidence;
- a network flow proves communication, not a remote command or API verb; and
- late provider evidence creates a new finding/lineage version without
  rewriting the earlier view.

## Response Algorithms

### Exact local restriction

An authorized local response inserts this key:

```text
ResponseRootKey = (node_boot_id, label_epoch, process_lineage_id)

ResponseRestriction {
  request_id
  target_process_instance_id
  permitted_emergency_effects
  deny_effect_families
  socket_fence
  expires_at
  policy_generation
}
```

Every protected hook checks the current process-lineage ID and bounded ancestor
vector. Existing and future descendants therefore match without waiting for a
userspace tree walk. A task iterator/pidfd reconciliation verifies that the
enumerated subtree agrees and reports missing/overflow branches.

The algorithm is:

1. Re-resolve node boot, label epoch, task/process cookie, native coordinates,
   cgroup, Pod UID, and container live interval.
2. Reject stale, ambiguous, bootstrapped-incomplete, or depth-overflow targets
   for exact-subtree response.
3. Insert the response root with TTL and read it back.
4. Run a fresh denied file, exec, socket, and device probe from the target
   scope where safe.
5. Fence existing sockets/packets if requested; an LSM connect deny alone does
   not stop an established connection.
6. Optionally freeze or signal only through separately authorized operations.
7. Watch for future descendants until the response closes.
8. Record `verified`, `partial`, `failed`, or `unknown` from physical
   postconditions.

### Cgroup and workload response

If exact lineage is incomplete, the product may propose a broader cgroup
egress fence or freeze. Before authorization it must show every known task and
container affected. In a shared interpreter, it explicitly states that all
in-process jobs may be interrupted and that no kernel evidence identifies one
logical job.

Kubelet can restart a container and a controller can replace a Pod. Therefore
process kill alone is not distributed containment. The coordinator separately
tracks:

- current local process/socket branches;
- container restart under the same Pod;
- replacement Pod UIDs created by the owning controller;
- remote node branches;
- credential/provider sessions; and
- artifact, mesh, connector, or source-control branches.

### Distributed response

```text
plan(distributed_lineage_version):
    fence proven seed process/socket immediately when locally authorized
    enumerate exact open branches and their authority owners
    produce one typed action per node/controller/provider target
    require target-specific approval and revalidation
    execute idempotently
    keep a watch open for replacement or late branches
    verify each physical postcondition

result = verified only if every required branch verifies under healthy
         required coverage through the watch interval
```

An offline node, an outside-authority environment, a contextual-only branch,
or unavailable provider verification forces `partial` or `unknown`.

## Per-Incident Protection Design

This section answers “what should Mithril do?” for every published stage. The
event IDs refer to the normalized
[live action stream](../../research/hugging-face-agent-intrusion-live-action-stream.md).

### `HF-001` through `HF-007`: external evaluation foothold and staging

**Situation.** The recovered root shell, environment discovery, public exfil,
remote staging, packing, and reconnaissance occurred in an external evaluation
environment outside the protected Hugging Face estate.

**Mithril action.** A Hugging Face deployment records these as outside-authority
subjects if provider or shared-artifact evidence later refers to them. It does
not claim local prevention. If Mithril is independently installed in an
evaluation estate, the ordinary policies apply: unexpected exec edges,
protected environment/credential access, public C2 destinations, anonymous
executable mappings, and remote loaders are denied by that estate's profile.

**Correlation.** Later exact artifact digests, credential IDs, connector
request IDs, or mesh enrollment IDs may connect the outside subject to a
protected branch. Similar commands or close timestamps do not.

**Acceptance.** The report must say `outside_authority` for the external
actions and must not turn them into fictitious ancestors of a Hugging Face
process.

### `HF-008`: hostile HDF5 external-file reference reaches conversion

**Situation.** An admitted dataset causes the unchanged conversion worker to
ask HDF5 to open a filesystem object selected by hostile metadata.

**Local policy.** The `conversion-worker-root` role may read only
`dataset-input`, reviewed runtime/library objects, and declared scratch/output
objects. An HDF5 external-file target resolved to
`worker-environment-procfile`, a projected credential, another Pod/process,
host filesystem, device, or an object outside the admitted dataset view is
denied at `file_open` before bytes are returned.

**Algorithm.** The file classifier uses the live mount namespace, mount ID,
inode/superblock identity, resolved proc target where applicable, and admitted
dataset mount provenance. It does not permit `../`, symlink, bind-mount, or
`/proc/<pid>/fd/<n>` aliases merely because the original string resembles the
dataset directory. The decision is attached to the exact interpreter task and
entry instance even though no child process exists.

**Central evidence.** The dataset/revision is connected to the worker only if
the platform supplies an exact immutable revision or dispatch identifier. If
the application supplies no job/revision event, Mithril reports the exact
process and file object but does not guess which concurrent logical job caused
it.

**Response.** Restrict the exact process lineage or, if the interpreter is
shared and continued execution is unsafe, propose a cgroup fence/freeze with
the explicit multi-job blast radius. Quarantine of one dataset revision is
eligible only with exact platform evidence.

**Required test.** A non-weaponized HDF5 fixture attempts an external read of
an allowed dataset sidecar file and of each protected object alias. The allowed
case completes; every protected case returns `EACCES`; no protected bytes enter
the converted output; `HF-LOCAL-001` contains the exact task, object key,
policy generation, and denial hook.

**Limit.** Mithril does not claim to reject the HDF5 structure at upload. That
would be an optional artifact scanner/admission control. The baseline prevents
the worker-side prohibited file effect.

### `HF-009`: worker environment and secrets are disclosed

**Situation.** Hostile processing obtains worker context or secrets and
publishes them through a dataset/result or network channel.

**Local policy, observable file path.** Opening `/proc/self/environ`, another
task's environ, a projected secret, token, cloud credential file, or host
configuration is evaluated by object class. If the conversion role has no
declared need, the read is denied before completion. An allowed but sensitive
read can set `OBSERVED_SENSITIVE_READ`, causing stricter later artifact and
egress decisions.

**Local policy, in-memory path.** If Python reads its own already resident
environment, the read has no distinguishable kernel file effect. Mithril
therefore evaluates the next action:

- a new/public socket or unapproved destination is denied;
- an output file/repository object outside the role is denied;
- an unexpected helper exec is denied; and
- an operation inside the same required encrypted publication channel is
  detected from service/provider audit when available.

**Correlation.** `HF-DW-001` joins an observable protected-object read to the
later socket/artifact/provider operation by exact task/process/socket or
credential lease. If only the same Pod and time are known, the edge remains
contextual.

**Response.** Restrict the exact lineage and fence its sockets. If authoritative
audit proves a result/dataset revision was written, mark that immutable
revision for review or quarantine through a separately authorized repository
action. Rotate/revoke a credential only when its exact identity and blast
radius are known.

**Required test.** The fixture has four branches: `/proc/self/environ`,
projected-token file, `os.environ` with public egress, and `os.environ` with an
already allowed TLS destination. The first two prove file denial, the third
proves network denial, and the fourth proves an honest
`semantic_effect_completed`/provider-audit result rather than a kernel
prevention claim.

### `HF-010`: template-based Python execution in the worker

**Situation.** Hostile template evaluation runs inside the already approved
Python interpreter.

**Local policy.** Mithril does not attempt to classify Python bytecode or
template intent. It denies the first prohibited physical effect:

- `python -> sh/curl/tailscale` at `bprm_check_security`;
- a module/plugin file outside the allowed code objects at file open/map;
- memfd or anonymous executable memory for a non-JIT role at exec/mmap;
- projected token, proc, host, or device access at file/device hooks;
- API/IMDS/C2 at socket hooks; or
- ptrace, namespace, mount, BPF, perf, capability, or module effects at the
  corresponding security hook.

**Algorithm.** This is an effect-state machine on the existing task label.
There is no prerequisite child process and no command-line signature.

**Response.** The exact interpreter process is the smallest native target. If
it hosts several logical jobs, Mithril states that containing it affects all
of them. It does not invent a job-specific response.

**Required test.** The malicious behavior driver performs prohibited file and
socket actions directly from Python without `subprocess`, then repeats them
through a helper child. Both in-process and exec-edge paths must be denied at
their respective pre-effect hooks. A pure arithmetic/template operation with
no effect must remain intentionally unclassified.

### `HF-011`: projected Kubernetes ServiceAccount token read

**Situation.** The compromised worker opens its projected ServiceAccount
token, or obtains equivalent credentials already loaded by legitimate code.

**Local policy.** The binder classifies the projected volume and rotating token
objects for the exact Pod/container. `conversion-worker-root` denies reads if
the worker does not need them. A controller role that legitimately reads the
same mounted token receives a reviewed token-read rule and a narrower
authority behavior rule; the entire Pod is not globally allowed.

**Algorithm.** A successful audited token read records the exact task,
process, file object, projected-volume provenance, ServiceAccount/Pod binding,
and profile generation, then optionally sets the sensitive-read state. Token
contents are never stored in evidence.

**Already-held credential.** If the token was read before attachment or is
already in memory, file denial is no longer prevention. Socket and Kubernetes
audit decisions remain active. Coverage reports the pre-attachment gap.

**Response.** Restrict the process/socket first. Deleting the Pod or revoking
broad ServiceAccount authority is not automatic. A projected token naturally
rotating does not prove every external bearer copy is invalid; provider-side
recovery follows Kubernetes' actual token type and issuer semantics.

**Required test.** Token rotation replaces the inode while the same projected
object class remains protected. A legitimate controller in the same Pod or on
the same node continues its declared read/API behavior; the conversion role
gets `EACCES`. Secret/token bytes never appear in WAL or findings.

### `HF-012`: Kubernetes API and cloud metadata probing

**Situation.** The foothold probes Kubernetes control-plane addresses and
cloud IMDS to enumerate or obtain authority.

**Local policy.** The node maintains destination classes for every discovered
API and metadata address: service IP, endpoint IPs, public/private API names,
IPv4/IPv6 link-local metadata, secondary interfaces, and provider-specific
paths. A conversion role with no need is denied on in-process connect/send;
no helper exec is required.

For a role that legitimately needs an API destination, network access remains
allowed. Kubernetes/provider audit then evaluates the exact principal, verb,
resource, namespace/account, result, and request ID against its
`AuthorityBehaviorRule`.

**Algorithm.** DNS observation updates provenance but the actual address and
network namespace drive the kernel decision. Existing socket storage retains
creator/current role. An established allowed connection is not reclassified
by TLS bytes; response uses the packet fence.

**Response.** Denied probes require no broad network change. A completed
forbidden API operation triggers exact process/socket restriction and a typed
Kubernetes/provider response against the resulting object or credential, with
resource UID/version preconditions.

**Required test.** `HF-NET-001` tries hard-coded IP, DNS, IPv6, alternate API
endpoint, and IMDS paths directly from Python. Negative controls exercise a
legitimate controller's expected API operation. A forbidden verb over its
allowed connection is detected from audit and is not mislabeled as a connect
denial.

### `HF-013`: dataset repository used as a dead-drop

**Situation.** A leaked write-capable token is used to publish an artifact or
dataset revision that becomes staging, C2, or a handoff point.

**Local prevention.** If the acting role does not need the repository
destination, connect/send is denied. If it has read-only network use but a
different endpoint or credential identity exists for writes, the profile can
deny the write channel. If read and write share the same process, endpoint,
credential, and TLS connection, the kernel cannot distinguish them.

**Authority behavior.** Repository audit must identify repository, actor/token
or principal, operation, immutable revision/commit/artifact ID, request ID,
and result. An unexpected create/update is a server-side deviation even when
the local channel was allowed.

**Correlation.** The exact written artifact digest/revision connects the
writer to later consumers. Repository name, filename, mutable branch/tag, or
time alone is contextual.

**Response.** Fence the source process/channel; revoke the exact token or
session when supported; quarantine or remove the exact immutable malicious
revision; enumerate downstream loads. Deleting an entire repository is not
the default.

**Required test.** A fixture permits a legitimate read and attempts a write on
the same TLS destination. The node reports network ambiguity; provider audit
produces the write finding. A separately identifiable write endpoint/token is
denied pre-effect. No test claims packet inspection recognized a repository
verb.

### `HF-014`: compromised node reaches mesh control

**Situation.** Code on the protected estate invokes or contacts mesh tooling
and its control service.

**Earliest prevention chain.** Any one of these independent policy gates can
stop the branch when absent from the conversion role:

1. deny `python -> tailscale` or another unapproved mesh executable object;
2. deny `/dev/net/tun` and its ioctls;
3. deny network/namespace/capability effects needed to establish the mesh;
4. deny the mesh-control destination; or
5. detect a forbidden mesh enrollment/control operation from provider audit.

The finding records which gate actually prevented the physical effect. It
does not claim all later gates fired after an earlier denial.

**Response.** Restrict the local lineage, fence existing mesh sockets, and use
a typed mesh action for the exact device/node/auth key. Revoking an enrollment
key and deleting an already enrolled device are different postconditions.

**Required test.** The fixture independently attempts unexpected mesh exec,
TUN open/ioctl, raw socket/capability, control connection, and use of an
already established mesh flow. Each advertised gate and the packet fence have
their own physical assertion.

### `HF-015`: attacker environment enrolls into the mesh

**Situation.** An external environment joins the organization's mesh. The
joining process may be outside every Mithril node.

**Mithril action.** Mesh audit creates an external subject keyed by exact
device/node/enrollment/auth-key identifiers. Credential acquisition/use and
the enrollment result form typed provider edges. A local node is connected to
that branch only with exact shared credential, request, or connector evidence.

**Prevention boundary.** Without a mesh admission integration, the enrollment
may complete before audit arrives. Mithril calls this detection/containment.
An optional provider-side pre-admission policy can deny unknown device posture
or unapproved enrollment, but it is not kernel prevention.

**Response.** Expire/revoke the exact enrollment credential to stop new joins,
delete or disable the enrolled device to stop the existing member, and verify
both separately. Search for other devices enrolled with the same credential.

**Required test.** The response test proves that key revocation alone does not
remove an existing device, then verifies the distinct device-removal action.
An outside-authority origin keeps the distributed result `partial` until the
provider branch is contained.

### `HF-016`: mesh access reaches an internal connector catalog

**Situation.** An enrolled mesh client reaches a connector or catalog that can
expose cluster/cloud/source-control context.

**Local policy.** On managed connector hosts, Mithril applies a connector
service role: declared listeners and upstreams are allowed, but unexpected
child exec, credential objects, destinations, devices, and privilege effects
are denied. A network flow from a mesh peer proves communication only.

**Authority behavior.** Connector-native audit should carry authenticated
source device/principal, connector ID, catalog/resource, source request ID,
destination request ID when forwarded, operation, and result. These fields
support `connector_forwarded_request`; a shared connector principal plus time
does not.

**Response.** Fence the compromised mesh device/channel, restrict the exact
connector process if it deviated, disable only affected connector grants or
sessions, and preserve service for unaffected principals where the provider
supports that scope.

**Required test.** A legitimate catalog request and an unexpected request use
the same connector service. Provider/request IDs distinguish them. Removing
those IDs downgrades the edge to contextual and makes connector-specific
automatic response ineligible.

### `HF-017`: harvested AWS credentials are used externally

**Situation.** A credential obtained from the protected estate is used from an
external origin to call AWS.

**Earlier prevention.** Deny the credential file/IMDS effect or the local
exfiltration channel when distinguishable. If the credential has escaped,
node enforcement cannot stop an external AWS request.

**Correlation.** Cloud audit resolves access-key ID, assumed-role session,
principal ARN, account, request/event ID, source, API operation, resource, and
result. An exact access-key/session ID can connect credential acquisition to
use. The same IAM role name used concurrently by several workloads is not an
exact edge.

**Authority behavior.** Expected role operations remain quiet. A new source,
operation, resource, region, or session behavior outside the signed rule emits
a versioned finding. Behavioral novelty supports detection but does not replace
the exact provider identity.

**Response.** Revoke/disable the exact access key or role session where
possible, apply a narrowly scoped deny/quarantine, enumerate resources changed
by that session, and verify provider state. Broad role-session revocation has
an explicit blast radius and approval.

**Required test.** Two workloads concurrently use the same role name with
different sessions. Only the exact compromised session is joined and targeted.
A shared-name-only case remains contextual. Resource postconditions are
verified after revocation.

### `HF-018`: source-control installation token is minted

**Situation.** A connector or compromised authority asks GitHub to mint a
GitHub App installation token and may then modify source or CI state.

**Local policy.** If the connector process/destination is unexpected, node
policy denies it. If the connector legitimately talks to GitHub over direct
TLS, the kernel cannot determine whether the HTTPS request is token creation,
clone, push, email-like notification, or another API operation.

**Authority behavior.** Connector audit and GitHub audit/API state identify the
App, installation, actor, token request where exposed, repositories,
permissions, operation, request/delivery IDs, and result. The signed behavior
rule permits expected installation operations and flags token minting or
write-capable repository effects outside them.

**Optional prevention.** A GitHub/connector-side policy integration at the
semantic API boundary may reject token minting before the provider call. This
does not require TLS interception because the connector itself supplies typed
operation metadata. Without that integration, detection follows authoritative
audit.

**Response.** Revoke a known token where supported, suspend the exact
installation if necessary, rotate App credentials with appropriate approval,
and enumerate commits, branches, workflows, releases, packages, and image
digests changed during the exposure. Token revocation and installation
suspension are distinct actions.

**Required test.** Read and write operations share a GitHub TLS destination.
The node does not claim verb visibility. Provider/connector evidence detects
the token/write effect, and the response verifies repository and installation
state rather than merely receiving HTTP success.

### `HF-019`: public remote loader re-arms fresh sandboxes

**Situation.** New external sandboxes retrieve and execute a public loader,
allowing persistence across ephemeral environments.

**Managed-node prevention.** On any protected node, deny the unapproved loader
destination, artifact write/code mapping, executable edge, memfd/deleted image,
or anonymous executable memory according to role. Artifact digest joins the
download to execution even if its filename changes.

**Outside authority.** If the sandboxes are not managed by Mithril, record them
as external subjects and act on shared provider/artifact/C2 infrastructure
within authority. Do not claim a Hugging Face node stopped their execution.

**Response.** Remove/quarantine the exact artifact or endpoint where
authorized, revoke the credential or dispatch mechanism that causes reload,
and enumerate every consumer by immutable digest/request ID. URL or filename
alone is insufficient for exact consumer lineage.

**Required test.** Execute the same bytes by ordinary file, renamed file,
memfd, deleted file, and anonymous mapping on a protected fixture. Each claimed
execution path is denied. An unprotected external fixture remains explicitly
outside authority.

### `HF-020`: staged binary and host state inspection

**Situation.** The foothold examines staged code and host/process state late in
the campaign.

**Local policy.** The current role is evaluated for procfs/sysfs/debugfs reads,
other-process memory/fds/maps, ptrace, perf, BPF, device access, mount/namespace
operations, host filesystem objects, and executable staging. Normal worker
diagnostics can be declared as exact read-only object classes without granting
general host inspection.

**Correlation.** A series of audited reconnaissance effects from the same
execution can raise finding priority, but every event remains independently
attributed and covered. A process name such as `readelf` is neither necessary
nor sufficient.

**Response.** Restrict the exact lineage and preserve relevant files,
descriptors, memory metadata, and WAL evidence before irreversible kill when
authorized. Evidence preservation cannot silently delay an already authorized
socket fence.

**Required test.** The profile allows one declared diagnostic file and denies
cross-task proc, ptrace, perf, BPF, debugfs, host mount, and staged executable
cases. Ring-buffer loss during a denial does not permit the operation.

### `HF-021`: access cut and end of recovered activity

**Situation.** Defenders sever access and activity ends. The architectural
question is how Mithril proves containment rather than infers it from silence.

**Response plan.** Mithril:

1. fences the proven local seed process and established flows;
2. follows the exact versioned distributed lineage across current nodes,
   controllers, mesh, connectors, cloud, repositories, and credentials;
3. re-resolves and authorizes one typed action per target;
4. watches kubelet/container restarts and controller-created replacement Pods;
5. watches provider feeds for credential reuse, late artifacts, and new
   branches;
6. verifies every physical postcondition; and
7. reports unresolved, outside-authority, or coverage-deficient branches.

**No-silence rule.** “No more alerts” is not a postcondition. Required source
coverage must remain healthy for the declared watch interval. An offline node
or provider-feed gap prevents `verified` containment.

**Required test.** `HF-RESP-002` contains a two-node branch, lets the controller
attempt replacement, delivers one provider event late, and makes one optional
source unavailable. The expected result is deterministic: every required
branch must verify for `verified`; otherwise the result is `partial` or
`unknown` with exact reasons.

## Situation-To-Control Summary

| Stage | Earliest local prevention when available | Required semantic/correlation control | Narrow response |
| --- | --- | --- | --- |
| `HF-008` | role/object file-open denial | exact dataset dispatch/revision if available | process/cgroup plus exact revision only when proven |
| `HF-009` | environ/credential file, artifact, or egress denial | sensitive-read and provider publication evidence | process/socket; exact leaked object/credential |
| `HF-010` | first exec/file/socket/device/security effect | same-process limitation retained | exact interpreter lineage, honest multi-job blast radius |
| `HF-011` | projected-token object denial | exact credential object/lease to authority use | process/socket; token/session-specific recovery |
| `HF-012` | API/IMDS destination denial | Kubernetes/cloud verb and resource audit | exact process/socket and mutated resource/session |
| `HF-013` | repository channel if distinguishable | repository operation and immutable revision | token/session plus exact artifact/revision |
| `HF-014` | mesh exec, TUN, capability, or control destination | mesh operation/device audit | local lineage/socket plus exact mesh device/key |
| `HF-015` | provider admission only; external node may be outside authority | exact enrollment/device/key | revoke new-enrollment key and remove existing device separately |
| `HF-016` | managed connector role/effect policy | exact connector source/destination request IDs | device/channel and affected connector grant/session |
| `HF-017` | earlier credential/IMDS/exfil gate | exact AWS key/session and API audit | exact session/key, then changed resources |
| `HF-018` | unexpected connector/GitHub channel; semantic connector gate if installed | GitHub App/installation/token/repository audit | token or installation plus repository integrity review |
| `HF-019` | destination/artifact/exec/memfd/mmap denial on managed nodes | immutable artifact consumer graph | artifact/dispatch/C2 within authority |
| `HF-020` | proc/ptrace/perf/BPF/device/host-object denial | exact reconnaissance sequence | lineage restriction and evidence preservation |
| `HF-021` | response-root and packet fences | versioned distributed branch watch | independently verified node/controller/provider actions |

## Worked Policy Example

This pseudo-configuration is illustrative, not an approved serialization
format. It shows how an unchanged worker and a kubelet-created probe receive
different authority in the same container.

```yaml
profile: hf-conversion-worker
version: 7
selector:
  namespace: datasets
  labels:
    app: conversion-worker

defaults:
  exec: deny
  file: deny
  network: deny
  device: deny
  security: deny

entries:
  - kind: container-start
    container: application
    imageDigest: sha256:approved-worker-image
    role: conversion-worker-root
    onMissingAdmission: deny-start

  - kind: kubelet-exec-probe
    declaredField: readinessProbe.exec
    commandDigest: sha256:canonical-health-command
    role: kubelet-exec-probe
    maxConcurrent: 2
    ambiguity: deny

  - kind: kubelet-prestop
    declaredField: lifecycle.preStop.exec
    commandDigest: sha256:canonical-cleanup-command
    role: kubelet-prestop
    claimTtl: 2s
    ambiguity: deny

roles:
  conversion-worker-root:
    forkWithoutExec: conversion-worker-child
    maxDepth: 8
    exec:
      - targetObject: approved-converter-helper
        resultRole: declared-converter-helper
    files:
      - allow: [read]
        class: dataset-input
      - allow: [read, mmap]
        class: worker-runtime
      - allow: [read, write, create]
        class: worker-scratch
      - deny: [read]
        class: projected-service-account-token
        setFinding: HF-PROC-001
      - deny: [read]
        class: worker-environment-procfile
    network:
      - allow: [connect, send]
        destination: approved-dataset-service
      - deny: [connect, send]
        destination: [kubernetes-api, cloud-imds, mesh-control, public-internet]
    devices: []
    security: []

  kubelet-exec-probe:
    lifetime: 3s
    childProcesses: deny
    files:
      - allow: [read]
        class: probe-health-file
    network: []
    devices: []
    security: []

  kubelet-prestop:
    lifetime: 20s
    childProcesses: deny
    files:
      - allow: [write]
        class: declared-cleanup-state
    network:
      - allow: [send]
        destination: declared-drain-endpoint
    onActiveContainment: deny

authorityBehavior:
  - principal: conversion-worker-service-account
    sourceRole: conversion-worker-root
    kubernetes:
      allowedOperations: []
    onDeviation: HF-DW-001
```

Consequences:

- the readiness process is legitimate even though the host runtime, not PID 1,
  created it;
- it cannot read the mounted token merely because it shares the container;
- an attacker running the health binary as a native worker child keeps the
  worker-child transition, not the kubelet-probe role;
- a direct unadmitted runtime exec cannot borrow the probe role;
- the worker can process multiple logical jobs without Mithril naming or
  changing them; and
- `preStop` remains subject to active containment policy.

## Kubernetes External-Entry Acceptance Matrix

The following tests are mandatory before a runtime/kernel combination can
claim full protected-entry support.

| Test | Setup and adversarial variation | Expected proof |
| --- | --- | --- |
| `ENTRY-START-001` | Hold a new container in runtime-created state; delay/wrong-profile/drop admission ack | Configured executable never begins without exact ack in strict mode; observe mode records the gap and continues |
| `ENTRY-POSTSTART-001` | PostStart races entrypoint in both observed orders | Two independent admitted roots, no fabricated parent, correct roles regardless of ordering |
| `ENTRY-POSTSTART-002` | Kubelet restart causes duplicate PostStart delivery | Separate idempotent/repeated entry instances within policy budget; no stale nonce reuse |
| `ENTRY-PRESTOP-001` | Trigger deletion while policy and an active response root exist | Enforcement remains installed; configured containment-vs-cleanup rule wins; termination alone grants nothing |
| `ENTRY-PROBE-001` | Run startup, readiness, and liveness exec probes concurrently with identical and different commands | Exact reason when extension exists; otherwise only same-budget conservative classification; unequal ambiguity denies |
| `ENTRY-PROBE-002` | Application child executes the exact probe binary/argv at the expected cadence | It retains native child lineage/role and cannot claim external probe intent |
| `ENTRY-NETPROBE-001` | HTTP, TCP, and gRPC probes hit the Pod | No synthetic in-container probe task; host flow and application receive remain correctly scoped |
| `ENTRY-SLEEP-001` | PostStart/PreStop sleep action | No in-container task appears; kubelet lifecycle evidence only |
| `ENTRY-EXEC-001` | `kubectl exec`, TTY/non-TTY, and `kubectl cp` | Administrative entry role and `pods/exec` audit correlation; default deny/approval honored |
| `ENTRY-EXEC-002` | Direct `crictl exec` with the same command as a probe | Host-admin/unknown runtime entry, never exact kubelet-probe role |
| `ENTRY-EPHEMERAL-001` | Add ephemeral container targeting app PID namespace | New container execution set, API actor evidence, separate profile; shared PID namespace does not merge native trees |
| `ENTRY-CONTAINERS-001` | Init, native sidecar, and app containers share Pod network and volume | Independent roots/profiles and correct shared-resource evidence |
| `ENTRY-MIGRATE-001` | Move an unlabeled task into protected cgroup or use `nsenter` | First protected effect denied without valid pending intent |
| `ENTRY-REUSE-001` | Reuse PID, namespace number, cgroup ID/path, container name, and Pod name over time | Live interval/full IDs prevent the old profile/response from attaching to the new subject |
| `ENTRY-RESTART-001` | Restart kubelet, runtime, and `mithril-node` at every admission state | Pending intents reconcile or expire; no task executes with a stale/duplicate role; exact coverage transition recorded |
| `ENTRY-LOSS-001` | Drop runtime-intent message or BPF entry event independently | Strict task denied or container held; event loss cannot relax enforcement; loss counter closes coverage |

For every case the test captures:

- runtime/containerd or CRI-O version;
- kernel, BTF, LSM ordering, helper, and hook capability record;
- Pod UID/resourceVersion, full container ID, cgroup live interval, image digest;
- entry nonce/classification/role/claim result;
- task/process/exec cookies and native coordinate history;
- physical syscall/runtime result; and
- coverage and loss state.

## Effect And Bypass Acceptance Matrix

| Family | Required bypass cases | Required physical assertion |
| --- | --- | --- |
| Exec | execveat, fexecve, memfd, deleted file, scripts, dynamic linker, renamed/bind-mounted binary, overlay copy-up, non-leader exec | prohibited image never begins; allowed immutable image receives exact result role |
| File | symlink, hardlink, rename, bind mount, proc-fd alias, projected token rotation, inherited/passed fd, mmap, `io_uring` | claimed operation returns denial before data/effect; uncovered pre-opened-memory cases named |
| Network | DNS/hard-coded IP, IPv4/IPv6, UDP, raw/packet, inherited/passed socket, established TLS, sendfile/splice, TUN/AF_XDP/BPF redirect | prohibited connect/send/packet is physically absent; established-flow fence separately proven |
| Device | mknod, open, major/minor aliases, TUN, GPU/FUSE/KVM, approved vs unapproved ioctl | cgroup device/file/ioctl result matches exact role rule |
| Security | setuid/file caps, credential change, ptrace, setns/unshare, mount, BPF, perf, module, keyring, seccomp weakening | selected pre-effect hook returns deny; unsupported operation downgrades tier |
| Identity | fork without exec, clone thread, vfork, non-leader exec, reparent, parent exit, PID/cgroup reuse, bootstrap | exact stable cookie/role or explicit gap; no userspace labeling window |
| Evidence | ring full, CPU sequence gap, WAL full, node/control outage, generation switch, BPF-link loss | enforcement result unchanged; negative conclusions prohibited across gap |

These are code-backed fixtures. A shell transcript or alert text is supporting
evidence, not the pass condition.

## Failure-State Architecture

| Failure | Observe mode | Protect mode | Claim effect |
| --- | --- | --- | --- |
| No BPF LSM or required helper/hook | Record unsupported capability and continue observation available from weaker hooks | Do not bind profile requiring the missing prevention; optionally deny workload start if operator selected strict tier | Cannot advertise equivalent prevention |
| Runtime start gate unavailable | Bind after start as `bootstrapped` with gap | Reject strict admission or use a separately proved fallback | No enforce-from-first-exec claim |
| Unlabeled task in protected cgroup | Record orphan/identity defect | Deny first protected effect | No exact lineage conclusion until recovered |
| Missing parent label at fork | Mark child lineage incomplete | Install restrictive unknown label or deny creation/effect | Never skip silently as benign |
| Pending entry ambiguous | Record all candidates and classification gap | Deny unless all candidates have explicitly identical approved budget | No exact lifecycle/probe claim |
| Ring-buffer reservation fails | Increment loss counter and close evidence interval | Same, while returning already computed deny/allow | Enforcement may remain healthy; evidence is incomplete |
| Rust process/control connection lost | Continue from pinned policy, spool health/evidence if possible | Continue in-kernel policy; reject new admissions that require userspace | Central response/new policy unavailable; existing deny not relaxed |
| BPF link/map lost or verifier probe fails | Mark affected hook unavailable | Deny new strict admissions and apply approved safe state to existing bindings | Required prevention coverage unhealthy |
| Policy generation compile/probe fails | Keep prior generation | Keep prior generation; reject update | No partial generation activation |
| Local WAL full | Apply retention/backpressure policy and expose gap before destructive overwrite | Local enforcement continues; strict evidence-dependent claims stop | No “safe”/“contained” conclusion across lost interval |
| Kubernetes/provider audit unavailable | Local effects continue | Same | Same-channel semantic deviations and distributed edges become unknown/contextual |
| Runtime/kubelet restart | Reconcile live containers/tasks and pending entries with explicit gaps | Preserve pinned bindings; expire/revalidate intents before new exec | No stale entry nonce or lifecycle classification |
| Node reboot | New node boot and label epoch; prior subjects close | New admission required | Old response keys cannot target new tasks |

## Performance And Boundedness

The architecture is intended to replace ptrace-heavy steady-state mediation.
That does not make every BPF design cheap. Each hot hook must have bounded map
lookups and no central round trip.

The expected fast path is:

```text
current cgroup binding lookup
  + task-storage lookup
  + response-root lookup
  + one compact role/effect decision lookup
  + optional socket/object lookup
  + best-effort fixed-size ring record only when policy requests evidence
```

The compiler resolves path trees, selectors, PodSpec interpretation, image
metadata, DNS/service inventory, provider rules, and conflicts outside the hot
path. BPF path/object extraction is performed only for hooks whose rule table
requires it. In-kernel filtering suppresses unneeded allowed events while
coverage counters remain observable.

Phase 0 sets numerical budgets for:

- median and tail overhead on exec, open, connect/send, and fork;
- maximum policy map memory per node/container/profile generation;
- task/socket storage capacity and exhaustion behavior;
- maximum role depth, ancestor vector, argv/path extraction, and tail calls;
- ring/WAL throughput and intentional stress loss;
- runtime admission latency for container start and repeated exec probes; and
- baseline application success, probe timing, Pod startup, and shutdown.

No phase can solve a performance failure by removing a required identity,
effect, evidence, or postcondition guarantee. It must optimize the mechanism,
reduce advertised scope, or propose a reviewed design change.

## Implementation Ownership

The final module names are Phase 0 decisions, but responsibilities must remain
cohesive:

| Owner | Responsibility | Must not own |
| --- | --- | --- |
| Rust runtime-entry owner in `mithril-node` | authenticate intents, resolve Pod/runtime identity, classify entry, issue one-use admission | BPF raw event parsing or central graph conclusions |
| Native identity owner | task/process/exec cookies, inheritance, bootstrap, coordinate history | Kubernetes/provider causal edges |
| Object classifier owner | executable/file/socket/device/security object resolution and quality | policy approval or response authorization |
| Policy compiler/activation owner | validate, simulate, compile, probe, atomically activate generations | model-generated direct allows |
| Kernel host owner | one loader, link/map lifecycle, ABI, capability probes, raw sequence | business detection packages |
| Local evidence owner | normalize raw events, coverage intervals, WAL, authenticated upload | mutation of kernel decisions after the fact |
| Control graph owner | immutable observations, typed causal edges, versioned lineage | native parent fabrication or live PID actuation |
| Detection-package owner | deterministic package state, lateness, findings | arbitrary response commands |
| Response coordinator | authorization, target re-resolution, typed execution, postconditions | raw shell or stale graph target |

The same node gatherer can expose a cgroup-scoped read-only observation stream
to Erebor Runtime. Runtime cannot install overlapping BPF links/maps, assign
Mithril roles, or invoke Mithril response through that subscription.

## Phase Allocation

| Architecture slice | Owning master-plan phases |
| --- | --- |
| ABI, license/provenance, capability/performance contracts, fixture vocabulary | Phase 0 |
| One Rust node process, one loader, base cgroup/runtime inventory | Phase 1 |
| task/process/exec identity, native inheritance, bootstrap, entry-independent tree | Phase 2 |
| effect observation, object classifiers, candidate profile simulation | Phase 3 |
| signed exec/file/device/security policy and generic decision precedence | Phase 4 |
| role-aware socket storage, destination policy, packet/established-flow fence | Phase 5 |
| sequence/WAL/coverage/generation restart and recovery truth | Phase 6 |
| `HF-PROC-001`, `HF-DW-001`, authority behavior and deterministic replay | Phase 7 |
| Kubernetes audit/object/runtime joins and multi-node causal graph | Phase 8 |
| response roots, cgroup/socket actions, controller replacement watch | Phase 9 |
| mesh/AWS/connector/artifact/GitHub packages and typed recovery | Phase 10 |
| runtime-specific full entry admission, packaging, scale, upgrades, complete conformance | Phase 11, with earlier prototypes in Phases 0-4 |
| optional upstream/EDR evidence adapters | Phase 12 |

Runtime-created entry handling crosses phases and cannot be postponed as a
late integration detail:

- Phase 0 must select the target runtime gate and prove its ordering;
- Phase 1 must carry authenticated runtime metadata;
- Phase 2 must model multiple roots and pending/claimed entries;
- Phase 4 must fail closed for missing protected labels; and
- Phase 11 must qualify each advertised containerd/CRI-O/Kubernetes version.

## Approval Decisions And Honest Alternatives

| Decision | Proposed default | Honest alternative and required proof |
| --- | --- | --- |
| Container model | Multiple admitted entry roots per container | A single-root model must prove kubelet/runtime exec tasks are always native descendants on every supported runtime; current Kubernetes behavior makes that unlikely |
| Strict initial start | Runtime-held pre-exec admission | Post-start observation is allowed only as a reduced tier with an explicit start gap |
| Strict runtime exec | pidfd/runtime-shim gate; pending-intent BPF claim only after target-kernel proof | Without either, unknown external roots must be denied or the tier is observe-only |
| ExecSync reason | authenticated reason extension when budgets differ; otherwise same-budget conservative class or deny | Timing/command-only exact classification is rejected |
| Administrative exec | default deny/approval on protected workloads | Always allow requires a separately bounded administrative role and accepts that compromised admin authority can introduce a root |
| PreStop under containment | containment wins unless an exact safe cleanup role is approved | Universal preStop bypass is rejected; disabling all preStop is possible with availability cost |
| Missing protected identity | fail closed at first protected effect | Fail open is an observation tier and cannot carry prevention claims |
| Executable identity | immutable object/image identity | Path-only policy is a reduced integrity tier |
| Same TLS destination | provider audit or semantic connector integration; no MITM | Whole-channel deny can prevent both allowed and forbidden operations with explicit blast radius |
| Multi-job process | exact native process scope; logical job remains unknown absent platform proof | Application instrumentation may add optional job identity but cannot become baseline |
| Policy learning | observation creates review-only candidates | Auto-authorizing observed behavior is rejected because compromise can train the allowlist |
| Upstream code | study/adapt mechanisms after Phase 0 license gate; own architecture and Rust userspace | Forking a daemon would add another chassis/owner and must replace, not duplicate, the single-gatherer design |

## Completion Standard For This Architecture

This document is implemented only when all of the following are true on every
advertised full-support kernel/runtime combination:

1. The unchanged concurrent worker, declared lifecycle handlers, exec probes,
   init/sidecars, and legitimate controller behavior pass.
2. Every container/runtime-created root has exact or explicitly conservative
   entry evidence before its first protected effect.
3. A native child cannot impersonate a kubelet/runtime entry by matching its
   command, binary, timing, cgroup, or namespace.
4. The first distinguishable prohibited `HF-008`-through-`HF-020` effect is
   physically denied where the matrix claims prevention.
5. Same-process and same-TLS cases produce the documented semantic detection
   result, never a fabricated kernel claim.
6. Native and distributed lineage survive concurrency, restart, reuse, fan-out,
   loss, late evidence, and contradictory evidence.
7. Local and provider responses re-resolve their target and verify physical
   postconditions through a healthy watch interval.
8. A missing hook, admission, map, event, WAL interval, audit source, or
   provider proof narrows the result mechanically.

Until then, the phase result must state which invariant, event stage, runtime
entry class, effect family, or response postcondition remains unproved.

## Primary Technical References

Local studies:

- [KubeArmor BPF LSM enforcer](../../../KubeArmor/KubeArmor/BPF/enforcer.bpf.c)
- [KubeArmor policy lowering](../../../KubeArmor/KubeArmor/enforcer/bpflsm/rulesHandling.go)
- [KubeArmor container-map identity](../../../KubeArmor/KubeArmor/enforcer/bpflsm/mapHelpers.go)
- [KubeArmor NRI timing and teardown](../../../KubeArmor/KubeArmor/core/nriHandler.go)
- [Tetragon fork tracking](../../../tetragon/bpf/process/bpf_fork.c)
- [Tetragon process state](../../../tetragon/bpf/lib/process.h)
- [Tetragon cgroup policy filter](../../../tetragon/bpf/process/policy_filter.h)
- [Tetragon runtime-hook policy binding](../../../tetragon/pkg/policyfilter/rthooks/rthooks.go)
- [Tetragon OCI hook](../../../tetragon/contrib/tetragon-rthooks/cmd/oci-hook/main.go)

Kernel and platform contracts:

- [Linux BPF LSM programs](https://docs.kernel.org/bpf/prog_lsm.html)
- [Linux LSM hook reference](https://docs.kernel.org/security/lsm-development.html)
- [Linux cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html)
- [Linux task-local BPF storage implementation](https://github.com/torvalds/linux/blob/master/kernel/bpf/bpf_task_storage.c)
- [OCI runtime lifecycle](https://specs.opencontainers.org/runtime-spec/runtime/)
- [OCI hook ordering](https://specs.opencontainers.org/runtime-spec/config/)
- [Kubernetes lifecycle hooks](https://kubernetes.io/docs/concepts/containers/container-lifecycle-hooks/)
- [Kubernetes probes](https://kubernetes.io/docs/concepts/workloads/pods/probes/)
- [Kubernetes init containers](https://kubernetes.io/docs/concepts/workloads/pods/init-containers/)
- [Kubernetes sidecar containers](https://kubernetes.io/docs/concepts/workloads/pods/sidecar-containers/)
- [Kubernetes ephemeral containers](https://kubernetes.io/docs/concepts/workloads/pods/ephemeral-containers/)
- [Kubernetes auditing](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
- [CRI runtime API](https://github.com/kubernetes/cri-api/blob/master/pkg/apis/runtime/v1/api.proto)

