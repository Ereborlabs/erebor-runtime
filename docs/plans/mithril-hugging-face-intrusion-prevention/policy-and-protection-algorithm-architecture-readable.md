# Mithril: Linux-Native Prevention, Evidence, And Verified Response

Status: proposed architecture. This document does not authorize an
implementation phase. The
[master plan](./README.md) controls what may be built.

This is a complete, plain-language rewrite of the
[original architecture](./policy-and-protection-algorithm-architecture.md).
The original remains unchanged and is used as a completeness checklist. This
file reorganizes the same design around the product, the exact Linux actor,
the physical effect, and the proof of the result. It does not preserve the
original section order.

The acceptance documents are:

- [Hugging Face adversarial acceptance](./hugging-face-adversarial-acceptance.md)
- [Live two-node lifecycle probe](./live-two-node-lifecycle-probe.md)

The incident facts come from:

- [Detailed incident analysis](../../research/hugging-face-agent-intrusion-analysis.md)
- [Normalized 21-event action stream](../../research/hugging-face-agent-intrusion-live-action-stream.md)

## How this document is organized

The topics in this architecture overlap in the real system. The organization
below deliberately combines them instead of repeating them:

- Part I defines Mithril, the missing security contract, and the trust
  boundaries of the complete system.
- Part II follows one Linux actor from runtime admission through fork, thread,
  exec, exit, and response.
- Part III defines one source policy, its compiler, immutable activation, and
  the kernel decision record used by every effect.
- Part IV explains how that one decision model controls each physical Linux
  surface, including shared objects and ways one process can lend authority to
  another.
- Part V defines evidence, local and multi-node causality, authorized response,
  and physical verification.
- Part VI applies the design to every published Hugging Face incident action
  and to normal CI/CD execution.
- Part VII records lessons from checked KubeArmor and Tetragon source, then
  defines acceptance, failure, recovery, performance, and boundedness.
- Part VIII assigns each state change to one durable owner, allocates delivery
  phases, identifies unallocated work, records approval choices, and defines
  completion.
- The appendices hold exact schemas, rejected designs, fixture IDs, and sources
  after the behavior has been explained.

A reader should be able to implement a chapter without guessing what words
such as “actor,” “deny,” “exact,” or “verified” mean. When the design still
depends on a product decision or unallocated phase, the text says so.

## Part I — Product, Gap, And Trust Boundaries

### 1. What Mithril Is

Mithril is a Linux-native system that prevents, proves, connects, and responds
to harmful actions made by workloads that an organization already chose to
run.

It is designed for the hard case: attacker-controlled code is running inside a
legitimate process, with the same Pod, image, Unix user, cgroup, mounted
credentials, and network namespace as legitimate code. Mithril does not assume
that a new shell, a new container, or an obviously malicious binary appears.

For every protected Linux effect, Mithril answers four questions:

```text
1. Who is acting?
   Exact task -> process -> execution -> independent container entry ->
   authority domain -> workload -> node.

2. What may that actor do now?
   Immutable policy generation + current process role + current response state.

3. Did the requested physical effect happen?
   Synchronous kernel result or the real external authority's result, with
   coverage health for the relevant time interval.

4. If response is required, what exact live object is still the target?
   Re-resolve it, apply the narrowest authorized actuator, and verify the
   postcondition through a healthy watch interval.
```

On each protected node, one Rust binary, `mithril-node`, owns the BPF programs,
runtime-entry protocol, local policy state, evidence sequence, and local
response actuators. A control plane receives normalized evidence, builds the
cross-node and provider graph, authorizes broader response, and tracks whether
the physical result was verified.

Mithril and Erebor Runtime may use the same node gatherer and BPF ABI. Their
purposes are different:

- Erebor Runtime watches or governs actions made by a known agent session.
- Mithril protects the wider estate, including processes that are not agents,
  runtime-created entries, stolen workload authority, new workloads, and
  actions that continue across nodes and providers.

The gatherer is shared code and one running owner, not two node agents.

### 2. The Security Gap Mithril Fills

Most Linux and Kubernetes products start with one useful but incomplete unit:
the container, cgroup, executable, syscall, connection, event, or workload
identity. The attack does not have to respect that unit.

#### 2.1 Legitimate workload does not mean legitimate action

A conversion worker may legitimately run Python, read input data, write output,
and make one internal request. Hostile input can make the already running
interpreter read a mounted token and call the Kubernetes API. There may be no
new command to block.

Mithril keeps a current role for the exact process and checks the requested
object or destination before the effect. “Python is allowed in this Pod” is not
the final decision.

#### 2.2 A container can have several unrelated process roots

The image entrypoint, a readiness probe, a lifecycle hook, `kubectl exec`, and
a host runtime exec can all start independent process trees in the same
container. They can have the same cgroup, namespaces, binary, arguments, and
Unix identity.

Mithril admits each root with a signed, authenticated, one-use intent and binds
that intent to the exact held task before it runs. “Kubelet created it” is
transport evidence, not permission.

#### 2.3 The process that reads authority may not be the process that uses it

One process can read a token and place it in a shared file, shared memory,
inherited file descriptor, Unix socket, loopback service, or environment for
another process. The second process can then make the network request.

Mithril records those physical transfers and places processes that share
sensitive authority into an authority domain. The domain prevents a narrow
process from laundering a broader process's permission.

#### 2.4 One attack crosses nodes and external systems

A local process can use a ServiceAccount to create a Pod on another node. That
Pod can enroll into a mesh, query a connector, obtain AWS credentials, and mint
a GitHub installation token. Linux parent/child relationships stop at the
node. IP address and time proximity are not a remote parent edge.

Mithril joins the graph only with proof owned by the boundary being crossed:
Kubernetes request UID and Pod UID, a one-use workload/runtime admission token,
mesh enrollment ID, connector request ID, cloud session ID, or provider token
issuance ID. Weak hints remain `contextual`; missing proof remains `unknown`.

#### 2.5 A finding is not containment

Killing PID 1234 is not enough if PID 1234 exited and the PID was reused, if a
sibling inherited the socket, if Kubernetes recreates the Pod, or if a stolen
cloud credential remains valid.

Mithril re-resolves the target, applies a named actuator, states its real blast
radius, and watches the required postconditions. It cannot call the result
`verified` while the required evidence source is unhealthy or behind its
watermark.

#### 2.6 Coverage is part of the result

A node agent may be down while pinned BPF still denies effects. That interval
is “enforcing without complete event delivery,” not “unprotected” and not
“fully observed.” Conversely, a running event collector does not prove that a
required deny hook is attached.

Mithril records enforcement, attribution, observation, admission, correlation,
and response coverage separately. It never replaces those axes with one green
health light.

### 3. Why Existing Products Do Not Individually Fill The Gap

Mithril should reuse proven mechanisms and source-code lessons. Its reason to
exist is the combined end-to-end contract, not a claim that other products do
nothing useful.

| Product or control | What it already does well | What remains outside that product by itself |
| --- | --- | --- |
| KubeArmor | Enforces file, process, network, and capability-oriented policy with Linux security mechanisms, including BPF LSM; integrates Kubernetes identity and policy. | The checked implementation does not provide Mithril's authenticated one-use identity for every independent runtime entry, immutable per-task/process authority lifecycle, complete multi-node/provider causal graph, coverage vector, or re-resolved and physically verified response contract. |
| Tetragon | Observes kernel process and syscall activity, tracks fork/exec state, filters by cgroup and workload, supports runtime-hook integration, and has real enforcement paths including Generic LSM override and a separate enforcer. | Its event/process model is not by itself Mithril's permission-bearing task/process/entry/authority-domain state; runtime metadata is not the signed one-use held-task proof; and it does not alone provide the complete policy-generation, provider-correlation, and verified-response contract. |
| Falco | Mature event ingestion, rule evaluation, enrichment, plugin model, and operational detection workflow. | Detection after an event is not synchronous prevention of every physical effect. Falco alone does not authenticate runtime entry roots, install per-task authority before first effect, or prove a response postcondition. |
| Cilium | Strong cgroup/workload network identity, eBPF datapath, service-aware policy, and Kubernetes networking. | A network identity does not distinguish two processes in one Pod, decide a local file or device operation, authenticate a runtime exec root, or prove which in-process code caused a provider action inside TLS. |
| Ordinary EDR | Broad telemetry, analytics, investigation, and response integrations; often valuable for detecting known behavior and fleet operations. | A product that observes after the syscall cannot claim the protected bytes were not read. Process reputation or behavioral scoring is not exact pre-effect authorization. Exact capabilities vary and must be measured rather than dismissed. |
| Seccomp, AppArmor, SELinux, or Landlock alone | Mature local isolation at their supported hooks and policy units. | No one mechanism supplies runtime intent, per-entry identity, object and socket provenance, provider edges, multi-node causality, or verified response. Mithril may compile part of a policy into them where they provide the best physical boundary. |
| Kubernetes admission or network policy alone | Rejects dangerous workload specifications or blocks workload-level flows. | It does not see hostile code already running inside a legitimate process, distinguish same-Pod actors, or govern local files, memory sharing, device ioctls, and inherited descriptors. |

This table states an architectural boundary, not a marketing insult. The later
source-review chapter names the exact checked KubeArmor and Tetragon paths,
what Mithril adopts, and what the tests show is missing for Mithril's stronger
claim. Features added upstream after the pinned revisions require a new source
review.

#### Practical comparison: hostile Python in a conversion worker

Assume `/usr/bin/python` is the approved worker process. The Pod legitimately
has a projected ServiceAccount token because an unchanged controller
deployment expects it.

```text
hostile template executes inside existing Python
  -> Python opens the projected token
  -> Python connects to the Kubernetes API
  -> Kubernetes creates a privileged Pod
```

- An exec-only rule sees no new command before the token read.
- A Pod-level allow for Kubernetes API permits both legitimate controller use
  and the hostile worker use.
- A network-only tool cannot prove which process read or transferred the token.
- An audit-only tool sees the successful API request after completion.
- A runtime admission control that protects only known profiles can be bypassed
  by creating an unmatched privileged Pod.

Mithril's combined contract is:

```text
exact worker process role
  -> projected-token object is denied before bytes are returned
  -> Kubernetes API destination is denied for that process/domain
  -> unmatched privileged runtime request is rejected by the node floor
  -> any completed remote action is joined with authority-owned IDs
  -> response re-resolves every live branch and verifies it stayed fenced
```

Any one of those barriers may stop this branch. The complete product keeps the
later barriers even when the earliest one is expected to succeed.

### 4. Mithril's Unique Contract

The product is the following chain of guarantees. Removing one item changes
the claim, even if installation becomes simpler.

1. **Unchanged workload.** Protection does not require a sidecar, application
   SDK, one-job-per-Pod deployment, different credentials, TLS interception,
   or a rewritten agent harness.
2. **One node gatherer.** One Rust process owns all Mithril BPF programs,
   runtime admission, local evidence, and local response. Several BPF programs
   are implementation details of that one owner.
3. **Exact actor before effect.** Every protected task has immutable task
   identity that resolves to mutable process and authority-domain state before
   it can perform a protected effect.
4. **Every independent root is admitted.** Initial entry, probe, lifecycle
   hook, administrative exec, runtime exec, restore, and unknown runtime entry
   do not silently inherit the container entrypoint's permission.
5. **One readable source policy.** Operators describe entries, roles,
   transitions, effects, shared authority, dispositions, responses, and
   exceptions in one signed package. A compiler rejects ambiguity and lowers
   it into bounded local records.
6. **Local decisions stay local.** A qualified kernel or runtime hook denies
   the physical effect synchronously. Central services never sit in a syscall
   path.
7. **Immutable activation.** Existing actors stay pinned to the generation
   they were admitted under unless a signed transition says otherwise. A
   partially written generation never becomes active.
8. **No authority laundering.** Shared files, memory, descriptors, sockets,
   loopback services, and token use cannot silently let a narrow actor borrow a
   broad actor's permission.
9. **Typed causality across boundaries.** There is no invented remote process
   parent. Kubernetes, mesh, connector, cloud, repository, and CI edges use
   the stable identifiers owned by those systems and carry proof quality.
10. **Coverage truth.** Enforcement, identity, observation, admission,
    correlation, and response health are separate time intervals.
11. **Narrowly authorized response.** The response engine re-resolves a live
    target, refuses stale or ambiguous identity, reports the actuator's actual
    blast radius, and checks physical postconditions.
12. **Claim by fixture, not intention.** Every advertised kernel, runtime,
    Kubernetes, and provider combination is backed by a named fixture and
    failure, bypass, event-loss, race, and performance evidence.

#### Claim boundary

Mithril must say where its authority ends:

- BPF cannot decide whether an in-memory Python expression is malicious. It
  decides the expression's later physical effects.
- Reading `os.environ` may use bytes already in memory and cause no new file
  hook. Later publication, file, socket, exec, device, or privilege effects are
  still controllable.
- `git clone` and `git push` may use the same process, host, port, credential,
  and TLS connection. Without TLS interception or a provider-issued distinct
  capability, Linux cannot allow clone and deny push. Mithril does not perform
  node-side TLS interception.
- Normal provider audit arrives after the provider action. It can prove
  completion and start response; it cannot turn a completed action into a
  prevented action.
- An exact causal finding does not create an exact actuator. AWS or GitHub may
  expose only a wider revoke or suspend operation. Mithril must disclose that
  scope before approval.
- If an attacker can replace the kernel, BPF links/maps, runtime gate, or policy
  owner, local prevention becomes unknown unless an independent boundary proves
  those components remain intact.
- `HF-001` through `HF-007` occurred outside the defended Hugging Face
  production boundary. A Hugging Face deployment cannot claim it prevented
  those external actions; it can import them as context.

#### Required result vocabulary

These words are not interchangeable:

| Word | Exact meaning | Concrete example |
| --- | --- | --- |
| `observed` | A trusted source saw an attempt or state. Completion is not proved. | A BPF hook saw `file_open`, but a later filesystem check may still fail. |
| `completed` | A return value or authority-owned result proves completion at the named boundary. | Kubernetes audit records a successful Secret read for the exact request UID. |
| `prevented` | A synchronous decision denied the action and a physical test proves the protected effect did not happen. | Read returned `EACCES`; no token byte reached the caller buffer. |
| `rejected` | A higher-level request was refused before its task, lease, or provider operation was admitted. | The runtime did not create the requested exec process. |
| `contained` | Every branch named by the response plan has an applied restriction; unresolved branches remain visible. | Known local tasks and sockets are fenced while a remote credential is still `UNRESOLVED`. |
| `verified` | Required postconditions stayed true through a healthy interval that includes source delay and watermark. | No replacement Pod appeared before the Kubernetes watch watermark passed the verification end. |

Relations use four proof levels:

| Relation | Required proof | Concrete example |
| --- | --- | --- |
| `exact` | Stable IDs from the authority owning both ends, or authenticated one-use proof claimed by the exact live task | Runtime request nonce + held pidfd/task cookie + successful one-use claim |
| `conservative` | Several candidates remain, but every candidate receives the same or less authority | Readiness and liveness are indistinguishable but both use the same deny-network role |
| `contextual` | Time, IP, name, label, or shared identity suggests a relation but cannot prove cause | A Pod flow and API audit share a ServiceAccount and ten-second window |
| `unknown` | Evidence is missing, contradictory, outside authority, or crosses unhealthy coverage | GitHub audit source was unavailable during the alleged write |

`exact` proves identity or relation, not maliciousness. A benign request can be
exact. A model can be highly confident and still provide only contextual
causality.

### 5. Node Architecture And Trust Boundaries

#### One userspace owner

One protected Linux node has one Mithril userspace process:

```text
mithril-node (Rust)
  ├── loads and owns all Mithril BPF programs, links, maps, and pin paths
  ├── accepts authenticated runtime-entry requests
  ├── binds Pods, containers, cgroups, tasks, images, and policy generations
  ├── resolves rich policy into bounded kernel records
  ├── owns the node evidence sequence and local WAL
  ├── reports coverage gaps and normalized observations
  └── applies approved local response actions
```

One gatherer does not mean one BPF program. File, exec, process, socket,
device, privilege, lifecycle, and evidence programs can be separate. The one
Rust process owns their lifecycle and health.

The same Linux sensor and ABI can be used by Erebor Runtime. Runtime observes
an agent's actions. Mithril applies estate defense. This reuse does not create
a second gatherer on the node.

#### The workload stays unchanged

The baseline design must work without requiring:

- one job per Pod or one job per process;
- application instrumentation or an application event for every job;
- a sidecar;
- a different ServiceAccount;
- narrower RBAC or IAM;
- a TLS proxy;
- a changed agent harness; or
- removal of legitimate mounted credentials.

Mithril may add node-level BPF, runtime admission, audit adapters, and control
components. Those are defense infrastructure, not application rewrites.

**Example.** A controller and conversion worker may both see the same mounted
ServiceAccount token. The controller's process role may read the token and make
specific Kubernetes calls. The conversion process is denied. The Pod and
credential mount do not need to change.

If the same process legitimately needs a credential and hostile code executes
inside that process, Mithril cannot separate two invisible Python intentions.
It must control the later file, network, provider, and publication effects and
state the remaining ambiguity.

#### Where each decision belongs

Do not put every decision in BPF:

| Decision | Correct owner | Why |
| --- | --- | --- |
| Local file, exec, socket, device, process-control, mount, namespace, capability, or kernel effect | Synchronous BPF LSM, cgroup BPF, seccomp, or another tested local hook | The hook still controls the physical effect and must not wait for a central service |
| Initial container or later runtime-created process | Local authenticated Rust admission, with a held task/request and a kernel claim | Runtime intent, signatures, replay state, and workload metadata are not available in one BPF hook |
| Kubernetes, repository, connector, CI, or provider request before execution | The real authorizer, admission service, broker, or connector | That component understands the semantic request and can reject it before completion |
| Provider audit after completion | Mithril correlation and response | The action already happened; only detection and response remain |
| Multi-node causal graph and investigation | Mithril control plane | It can wait for multiple sources; it must never sit in a syscall path |

BPF is not a YAML parser, OIDC verifier, Kubernetes authorizer, or human
approval engine. Rust is not allowed to approve a syscall after the fact.

#### No TLS interception

Mithril preserves direct TLS. It does not install a man-in-the-middle proxy.

Consequences:

- Network policy can allow or deny a destination or whole channel.
- Linux can distinguish separate processes, sockets, IPs, ports, network
  namespaces, and sometimes separately issued credentials or endpoints.
- Linux cannot read `git clone`, `git push`, an email-send operation, or an AWS
  API verb inside one allowed TLS connection.
- Server/provider evidence can identify the completed semantic operation.
- A synchronous provider/broker/connector integration can reject a semantic
  operation before completion without node-side TLS interception.
- If no separate capability exists, policy may deny the whole channel or allow
  it and detect later. Mithril must show that trade-off.

GitHub does not generally turn an arbitrary existing write-capable bearer token
into a new read-only token. A GitHub App can request an installation token with
narrower permissions only within the installation's granted authority and the
provider's supported rules. That is a provider-issued capability, not token
derivation performed by Mithril.

#### Boot order is an unresolved product choice

A DaemonSet alone cannot promise protection before the first workload on a new
node. Kubelet must already run to start the DaemonSet. Other workloads may run
before every required BPF link and map is loaded and checked.

| Deployment | Components | Honest claim |
| --- | --- | --- |
| Simple | One `mithril-node` DaemonSet Pod | Easy install, but a measured `START_GAP`; no first-exec claim during boot |
| Strict host | The same single `mithril-node` binary starts as a host service before kubelet | Still one gatherer; can gate node/workload readiness after enforcement verification; harder packaging/upgrades |
| Strict split gate | One DaemonSet gatherer plus a small persistent runtime/shim gate that gathers no events | Can hold starts while the gatherer restarts; adds another enforcement component even though there is still one gatherer |

This document does not silently choose one. The release manifest must expose
the selected mode. Full boot protection requires an approved strict design.

#### Node capability is measured, not guessed from kernel version

Before policy binds, the node records:

```text
KernelCapabilityRecordV1 {
  node_boot_id
  architecture
  kernel_release_and_build_id
  kernel_config_digest
  vmlinux_btf_digest
  core_relocation_probe_results[]
  active_lsm_order[]
  bpf_lsm_configured_and_active
  cgroup_v2_mount_and_config
  lockdown_and_privilege_state
  supported_program_and_attach_types[]
  supported_map_and_storage_types[]
  hook_results[] { hook, attach, ordering, return_semantics, test_id }
  helper_and_kfunc_results[] { program_type, symbol, result }
  link_and_map_ids_digests_and_pin_readback[]
  controlled_allow_deny_probe_results[]
  record_digest
}
```

Support requires the running node to prove:

- BPF LSM was built and `bpf` is active in the LSM list;
- BTF and CO-RE work for the exact build;
- cgroup v2 and required cgroup BPF paths work;
- every required hook, helper, kfunc, program type, map, and storage type works;
- lockdown and privilege settings permit the loader operation;
- every required link and map can be read back; and
- controlled allow and deny probes produce the expected result.

The same release string may behave differently on two distributions. One may
backport a helper. Another may disable BPF LSM. The probe result, not the
version number, controls the claim.

BPF LSM object files must use a GPL-compatible BPF program license where the
kernel requires it. This applies to the loaded BPF object. It does not by
itself relicense the independently linked Rust userspace or the complete
product. Phase 0 records source and license for every copied or derived BPF
file.

**Test.** Three nodes report the same kernel release. Node A lacks `bpf` in the
active LSM list. Node B blocks a required helper under lockdown. Both fail the
capability. Node C passes attach, readback, and physical deny probes. Its exact
build, BTF, BPF program, map, and runtime digests enter the support manifest.

#### Trust after node-root compromise

Root UID alone does not automatically mean local enforcement is lost. Kernel
lockdown, capability removal, read-only bpffs, runtime integrity, and external
attestation may still prevent tampering.

Mithril measures the actual boundary:

```text
required links and maps intact?
runtime/shim and admission socket intact?
policy signer and loaded generation intact?
packet hooks intact?
mithril-node healthy or pinned enforcement still active?
external measurement healthy?
```

If a required component is altered or cannot be measured, the affected
coverage interval becomes `ENFORCER_TAMPERED_OR_UNKNOWN`. Provider admission,
upstream network controls, and remote credential/device response remain
separate trust boundaries.

## Part II — Actor Identity And Runtime Admission

### 6. Who Is Acting?

Mithril makes a permission decision for an exact live Linux task. It must also
know which process owns the task, which independent container entry created
that process tree, and which policy generation is still valid for it.

#### A container is not one process tree

The runtime creates the configured entrypoint. Later, kubelet, an administrator,
or a host runtime can create another process directly inside the same
container. That new process may have no Linux parent inside the workload.

```text
ContainerExecutionSet
  +-- initial container entry -----------> native tree A
  +-- PostStart exec --------------------> native tree B
  +-- readiness probe #1 ----------------> native tree C
  +-- readiness probe #2 ----------------> native tree D
  +-- PreStop exec ----------------------> native tree E
  +-- kubectl exec ----------------------> native tree F
  +-- another admitted runtime entry ----> native tree ...
```

The edge from an entry request to its root means
`entry_started_execution`. It is not a fake fork edge. Real fork, clone, and
exec edges continue below each root.

#### “Kubelet created it” is not permission

Kubelet can carry:

- a legitimate probe;
- a legitimate lifecycle hook;
- an administrator's `pods/exec` request;
- an attacker's `pods/exec` request; or
- a malicious hook placed in a changed Pod template.

Mithril uses three facts together:

```text
runtime/kubelet transport
  + authenticated one-use intent
  + exact reviewed workload definition
  -> assign a narrow role or reject
```

The command does not decide the role.

```text
real readiness probe -> /app/healthcheck -> probe role
attacker kubectl exec -> /app/healthcheck -> admin role or rejection
```

The binary, arguments, cgroup, and namespaces can be identical. The one-use
request, actor, entry kind, and live task are different.

#### Four ways attacker code can appear

##### Existing process

The Jinja foothold ran in the existing conversion worker. There is no new
entry and may be no new task. The existing process role reaches every later
file, socket, device, or privilege decision.

##### Native child or exec

If the worker forks, the child receives inherited or narrower authority before
it can run. If it execs, the complete executable/interpreter/loader chain must
pass an exec transition before the new image receives user time.

##### Kubernetes exec

A normal `kubectl exec` uses Kubernetes, kubelet, and the runtime. It becomes
`AdministrativeExecEntry`, is joined to the Kubernetes request and principal
when exact proof exists, and is default-rejected or given an explicitly
approved break-glass role.

##### Node/runtime bypass

`crictl exec`, direct runtime APIs, shim manipulation, `nsenter`, or moving a
host task can bypass Kubernetes. They need a separately authenticated host
administrative entry and are denied by default. Appearing in a protected
cgroup does not create permission.

#### Kubernetes cases that must stay distinct

| Situation | What Linux/runtime actually creates | Mithril treatment |
| --- | --- | --- |
| Initial application process | Runtime-created root in a new container cgroup | Hold and admit `ContainerStartEntry`; bind exact Pod, container, image, cgroup lifetime, root task, and policy |
| Fork or thread | Native child | Kernel inheritance; no runtime ticket |
| Exec `PostStart` | Possible second root, concurrent with application start | One-use `KubeletPostStartEntry`; exact PodSpec generation; narrow role |
| Exec `PreStop` | Possible second root during termination | One-use `KubeletPreStopEntry`; keep enforcement until every task/socket exits; containment normally wins |
| Exec startup/readiness/liveness probe | Repeated secondary roots | Repeatable but bounded one-use `KubeletExecProbeEntry`; exact reviewed declaration; strict file/network/exec/lifetime budget |
| HTTP lifecycle hook | Connection made by kubelet | No workload root; record node flow and declared-hook context |
| HTTP, TCP, or gRPC probe | Connection made by kubelet | No workload root; application receiver thread does not become a probe process |
| Sleep lifecycle hook | Sleep inside kubelet | No workload task |
| `kubectl exec` | Runtime-created root and Kubernetes stream/audit | `AdministrativeExecEntry`; default reject or approved break-glass |
| `kubectl cp` | Usually exec of archive tooling | Same as admin exec plus scoped stream/file permission; `tar` is not proof of benign use |
| Direct runtime exec | Runtime-created root without Kubernetes user audit | `HostAdministrativeExecEntry`; default deny on protected workload |
| Restore/migration | May recreate tasks, memory, fds, sockets, mappings, devices, and namespaces without normal exec | Default reject; full support requires holding and reconciling the entire target set before any restored user task runs |
| `attach` | Streams attach to an existing process | Stream authority; no new root or role |
| `port-forward` | API/kubelet stream forwards traffic | Stream/flow authority; no new process edge |
| Ephemeral container | Separate container root, possibly sharing PID namespace | Separate execution set and admission; default deny or diagnostic profile |
| Init container | Separate ordered container root | Separate execution set, image, and init role |
| Native sidecar | Separate independently restarted root | Separate execution set and sidecar role; shared Pod network does not merge process lineage |
| OCI hook process | Runtime infrastructure, often outside workload cgroup | Infrastructure observation only; shared namespaces never grant workload role |
| `nsenter` or moved host task | Unlabeled external task | No ticket means deny first protected effect and report `unknown-external-entry` |
| Restarted container in same Pod | New full container ID, cgroup lifetime, root, and lifecycle generation | New execution set and admission; never reuse old root identity or response target |

Kubernetes details that affect policy:

- `PostStart` can run concurrently with the application entrypoint.
- Exec lifecycle handlers run in container cgroups/namespaces. HTTP and sleep
  handlers do not create a container task.
- Exec probes create container processes. HTTP, TCP, and gRPC probes do not.
- Lifecycle hooks are at-least-once and can repeat after kubelet failure.
- `PreStop` completes before the normal termination signal, but uses the same
  termination grace period.
- Init, sidecar, application, and ephemeral containers are separate roots even
  when they share Pod resources.

Stock CRI `ExecSyncRequest` carries container ID, command, and timeout. It does
not authenticate whether the reason is readiness, liveness, startup,
`PostStart`, or `PreStop`. This is a CRI information limit, not a KubeArmor or
Tetragon limit.

If several declarations are indistinguishable:

1. Give them one shared budget only when every candidate receives the same or
   less permission.
2. Otherwise reject.
3. Exact different roles require a kubelet-side authenticated reason/nonce
   carried to the exact task.
4. Never union unequal permissions and call that conservative.

#### Identity records

The main records and their purpose are:

| Record | What it identifies | Important rule |
| --- | --- | --- |
| `ContainerExecutionSet` | One exact live container, Pod, image, cgroup lifetime, and active policy binding | Same Pod name or image tag after restart is a new execution set |
| `EntryInstance` / `EntrySecurityStateV1` | Why one independent process tree exists and whether its one-use admission committed | A denied file effect does not end the entry; entry ends after the final task reference and reconciliation |
| `TaskLabelV1` | Immutable identity of one Linux task | Contains a reference to current process state; never caches a final allow |
| `TaskInstanceV1` | One task's live TID/start/namespace coordinate interval | TID is revalidated; it is not durable identity |
| `ProcessSecurityStateV1` | Current execution, role, policy generation, authority domain, response set, and exec state shared by all threads | This is the sole current process authority |
| `ProcessInstanceV1` | One exact live process interval | Used for live response after revalidation |
| `process_lineage_id` | Durable process identity through exec/reparent/PID coordinate changes | Used by the causal graph |
| `ImageProvenance` | Immutable executable, script/binfmt chain, ELF loaders, and source exec event | Several processes may share provenance after fork |
| `ProcessExecutionInstance` | One process using one image during one time interval | Fork creates a new process execution; exec creates another in the same lineage |
| `AuthorityDomainStateV1` | Restrictions shared across processes that can pass data or authority | Dynamic sensitive and response state belongs here, not in each task label |

The exact layouts appear in Appendix A. The hot-path read order is always:

```text
task label
  -> current process state
  -> authority domain named by current process state
  -> live execution-set binding and retained policy generation
  -> response, object/socket, and policy decision
```

Task identity comes first. A labeled worker moved into a host cgroup does not
become an unprotected host process. Missing, corrupt, wrong-epoch, or inactive
state denies the protected effect and opens a health finding.

#### Task, process, thread, entry, and exec are different

```text
entry
  -> owns one independent native tree
     -> process lineage
        -> one or more tasks/threads
        -> one process execution at a time
        -> exec changes execution but keeps lineage and entry
```

**Fork example.** Parent `T1/P1/X1/image I1/entry E1` forks:

```text
child T2/P2/X2/image I1/entry E1
```

The child has new task, process, and process-execution IDs, but keeps the same
entry and immutable image provenance. It execs a shell:

```text
child T2/P2/X3/image I2/entry E1
```

A thread clone gets a new task but shares `P1/X1/I1` and the same current
process role.

#### Native child creation

Permission inheritance follows the task that called clone, not whatever Linux
later reports as `PPid`.

Mithril stores:

- immutable `CREATED_BY`: creator task/process and child task/process;
- changing `KERNEL_REAL_PARENT` intervals: birth, `CLONE_PARENT`, parent exit,
  subreaper, namespace init, ptrace, or unknown change.

Double fork, daemonization, reparenting, and PID reuse cannot erase the
creator-derived restriction. `ID-CREATOR-PARENT-007` proves this.

Creation order:

```text
1. Read creator TaskLabelV1.
2. If present, read current process state and execution-set binding.
3. Require live binding, retained generation, and expected placement.
4. A placement mismatch denies creation or installs fail-closed child state.
5. Never send a labeled creator to host policy.
6. If no label exists, completely resolve protected placement.
7. Protected-but-unlabeled means identity failure; completely outside means
   explicit host policy; incomplete lookup follows fail-closed coverage policy.
```

##### Thread branch

```text
increment entry.live_task_refs
increment existing process.live_thread_refs
install a new task label pointing to the same process state
do not create a separate role
do not increment domain.live_process_refs
```

##### New-process branch

```text
increment entry.live_task_refs
create ALLOCATING process state with one live thread
increment domain.live_process_refs once
apply the one compiled FORK_WITHOUT_EXEC transition
install child label pointing to the new process state
```

At final thread exit, domain live-process count decrements once. Failed clone
and duplicate cleanup cannot decrement twice because every acquired reference
has an owned bit and tombstone.

The ideas `thread_child_role` and per-thread domain-process references are
rejected. Threads share memory and often files. A broader sibling role or
double-counted domain reference is unsafe.

#### Task creation hook and PID finalization

BPF LSM `task_alloc` is preferred because it receives the child and clone
flags and can reject. A platform must prove task storage can be installed there
and read at the child's first hostile effect.

If that is impossible, a target-specific pre-wake fentry/kprobe is protection
only when tests prove it runs before the child. A scheduling event after the
child ran is observation only.

| Failure | Result |
| --- | --- |
| Protected parent lacks identity | Deny creation if returning hook supports it; otherwise install fail-closed child and deny first protected effect |
| Role/ancestor bound overflows | Deny creation, or install overflow restriction and deny every protected effect while reporting availability failure |
| Task storage is full | Return configured creation errno when possible; never create an unlabeled child and call it protected |
| Later clone setup fails | Roll back every preallocated identity/reference exactly once; never report a runnable child |

`task_alloc` occurs before PID/TGID/start-time/pidfd coordinates exist. It
allocates opaque IDs and preallocated state only. A tested pre-wake point fills
the existing coordinate slots after PID assignment. It allocates nothing and
grants no permission. After visibility, Rust may append pidfd revalidation.

If coordinate finalization fails, the label points to
`FAIL_CLOSED_UNKNOWN`. The child cannot perform a protected effect.

`ID-TASK-COORD-FINALIZE-006` pauses before and after PID assignment, forces
map failure, covers leader-first exit, TID reuse, missing `PIDFD_THREAD`, and
non-leader exec, and proves no incomplete child reads or sends one marker byte.

A wake-only fallback is not sufficient when
`clone3(CLONE_INTO_CGROUP)` can place a child directly in a host cgroup and
label allocation can fail. `ID-CLONE-CGROUP-FAIL-003` must prove creation or
first effect is denied. Otherwise strict task identity is `UNSUPPORTED`.

#### Exec transition

Exec is one transaction that can include a script, `binfmt_misc` handler,
interpreter, main executable, and dynamic ELF loader.

Mithril:

1. Reads task identity first, then current process and binding.
2. Rejects placement mismatch; never falls back to host policy.
3. Creates one `PendingExecV1` attempt before the first `bprm` check.
4. Allows only one sibling exec attempt at a time.
5. Appends every script/interpreter/binfmt candidate to one bounded ordered
   chain.
6. Records the dynamic ELF loader through exact file/mapping allowance, because
   `PT_INTERP` is not another `bprm` pass.
7. Replaces pending permission with an equal or stricter intersection of
   source role, every candidate, target role, loader budget, and response.
8. Before Linux's point of no return, installs a restrictive
   `EXEC_COMMIT_PENDING` floor.
9. At a tested successful-exec point before user mode, performs only an
   in-place non-allocating role/execution switch.
10. Emits rich evidence later; event loss cannot restore broad permission.

While exec is preparing, committing, or uncertain, every non-loader protected
effect and every task creation is denied.

##### Failed exec

Before the point of no return, failure keeps the old image and old role. After
that point, the old image cannot return; the task usually dies. Mithril must
not restore old authority after a fatal late failure.

```text
EXEC_PREPARING
  -> PRE_PONR_FAILURE: clear pending; old image remains
  -> POST_PONR_FATAL: retain restriction until task_free; old image never returns
  -> SUCCESS: install target execution/role before user mode
```

If the platform cannot distinguish the outcomes, it keeps
`EXEC_OUTCOME_UNKNOWN` until exit/reconciliation and cannot claim exact exec
lifecycle coverage.

`execveat(..., AT_EXECVE_CHECK)` checks permission but does not install an
image. It must not consume a ticket, create a pending exec, or change role.
Unknown exec flags are denied under a full profile or reported unsupported.

`EXEC-CONCURRENT-002` races two thread execs and exec against fork/vfork/thread
creation. Exactly one stages. No child is born during the guard. A forced
commit-state failure leaves no source or target non-loader permission.

### 7. Runtime-Created Process Admission

Every independent root uses a one-use transaction:

```text
authenticate caller and signed intent
  -> create one pending claim slot
  -> hold the exact runtime task or prepare an exact kernel claim
  -> install immutable task identity and current process/entry state
  -> read back task, binding, policy, maps, and required hooks
  -> commit entry at the successful user exec boundary
  -> release exactly once
```

The issuer cannot choose fail-open. Signed local policy chooses behavior for
missing, expired, ambiguous, replayed, or unhealthy intent.

#### Strict initial container start needs two barriers

A generic OCI callback is not enough. Runtime init may perform namespace,
mount, rootfs, credential-state, and capability setup before the user image.
Mithril must permit only the exact setup work without granting ordinary
workload authority.

Initial state:

```text
UNBOUND
  -> PREPARING(exact request and container)
  -> ADMITTING(held runtime-init task, runtime-setup role)
  -> USER_EXEC_PREPARING(entry-provisional role)
  -> BOUND_USER(final role)
  -> TERMINATING
  -> TOMBSTONED

any pre-user state -> REJECTED | SETUP_FAILED
```

##### Barrier 1 — label the setup task

Preferred hold:

1. Measured runtime supervisor creates init child with `clone3(CLONE_PIDFD)`.
2. Child reaches a mandatory barrier before setup.
3. Supervisor sends pidfd and sealed one-use setup ticket over a root-only
   authenticated socket.
4. `mithril-node` re-resolves pidfd, start time, cgroup root/binding nonce,
   request, runtime measurement, and ticket.
5. It creates and reads back task storage through the same pidfd and a BPF task
   iterator.
6. Supervisor releases only after exact readback.
7. Every setup action consumes an ordered `RuntimeSetupBudgetV1` step.

A pidfd identifies a task; it does not stop it. A valid barrier is one of:

- exclusive ptrace stop proved with `waitid(P_PIDFD)` and released only by the
  measured supervisor;
- measured bootstrap blocked on a private, signal-safe, one-use MAC-bound
  pipe/eventfd/futex protocol; or
- exact empty target cgroup with `cgroup.freeze`, `frozen=1` readback, and exact
  member-set proof.

Plain `SIGSTOP`, unobserved stop, leaked release fd, ordinary `SIGCONT`
susceptibility, pidfd possession, or an OCI hook after setup is not a hold.
`BarrierEvidenceV1` records which variant proved the hold; fields from one
variant cannot prove another.

`ENTRY-HOLD-ATTACK-002` tries hostile `SIGCONT`, `SIGKILL`, ptrace, spurious
signals/wakes, parent death, leaked fd, and early resume. No setup or user
marker may run. Only the measured supervisor with the matching one-use
acknowledgement advances the positive control.

##### Runtime setup budget

`runtime-setup` is a signed, runtime-version-specific ordered list of exact
operations, objects, flags, counts, predecessors, and required results. It may
perform only the namespace, mount, rootfs, final UID/GID/groups, capability
drop, securebits, `no_new_privs`, and loader steps proven necessary for that
runtime build.

Mounting a projected credential volume as an opaque declared mount may be
allowed. Opening, reading, mapping, copying, or sending its token is not.
Unknown action, wrong order, wrong object/flags, or too many repetitions causes
`RUNTIME_SETUP_BUDGET_VIOLATION` and fails the start.

Qualification is exact for runtime name, version/config, OCI implementation,
kernel, and hook phase. A broad “runtime can do anything” exception is
forbidden.

##### Barrier 2 — bind the final rootfs and objects

The first barrier runs before rootfs/projected-volume objects exist. Allowing
the user image immediately after setup would race object classification.

```text
SETUP_LABELED
  -> SETUP_RUNNING_UNDER_BUDGET
  -> ROOTFS_READY_HELD
  -> TOPOLOGY_RECONCILED
  -> OBJECT_TABLES_INSTALLED_AND_READ_BACK
  -> ONE_USE_FINAL_EXEC_ARMED
  -> USER_EXEC_COMMIT
```

Immediately before user exec, the measured runtime stops at a second private
barrier and sends `RootfsReadyV1`: exact task, mount namespace fd/identity,
cgroup binding, rootfs/overlay identity, OCI config, image digest, declared
mounts/devices/projected volumes, and final argv/environment metadata digest.

`mithril-node`:

1. Holds the namespace fd.
2. Reconciles mount topology to `CLEAN`.
3. Resolves executable, loader, file, device, and projected-volume keys.
4. Installs them into inactive/entry tables.
5. Reads every required key and task expectation back.
6. Arms one final-exec claim.
7. Sends the one-use resume acknowledgement.

Any later mount/topology change marks the namespace `DIRTY` before the change
can make a protected decision. Final exec/file actions deny until a new full
reconciliation.

`ENTRY-ROOTFS-BARRIER-001` delays the binder, performs overlay copy-up, rotates
a token, mounts after acknowledgement, and resumes before readback. The user
marker runs only in the exact clean/read-back positive case.

#### Streaming exec is a two-stage request

CRI streaming `Exec` first prepares an endpoint and returns a URL. The runtime
usually creates the process only after the client connects. Observing the first
RPC does not bind a task.

```text
PREPARE_RECEIVED
  -> TICKET_ISSUED
  -> STREAM_AUTHENTICATED
  -> TASK_HELD_OR_PENDING_CLAIM
  -> TASK_BOUND
  -> RUNNING
  -> EXITED

before stream auth -> REJECTED | EXPIRED | CANCELLED
after stream auth but before bind -> BIND_FAILED and command never runs
```

Strict support uses either:

1. Mithril owns both the prepare endpoint and later stream URL, authenticates
   the later peer, consumes one opaque ticket, and only then opens the upstream
   runtime stream; or
2. Runtime/shim accepts a prevalidated ticket, creates the child held, passes
   pidfd and immutable runtime identity to `mithril-node`, and resumes after
   label readback.

A proxy that forwards the original runtime URL does not own stage two and is
observation-only unless a separate pending-claim mechanism passes qualification.

Ticket transitions are compare-and-swap. `ISSUED -> CLAIMING` occurs after
stream authentication. `CLAIMING -> CONSUMED` occurs after task-label readback.
Disconnect before consumption cancels. Reconnect never revives. A second
consumer receives a replay error.

**Test.** Client A obtains ticket Q and disconnects. Client B steals the URL
and connects after expiry. No task starts. Another test opens two connections
with Q; exactly one claims and the loser receives
`ENTRY_TICKET_ALREADY_CLAIMED`.

`ExecSync` is synchronous to the caller but still creates a process inside the
runtime. Strict support needs the same hold-and-bind seam or a qualified
pre-exec claim. Waiting for `ExecSync` to return is post-execution evidence.

#### Attacker-created unmatched workloads

Protecting only known Pod selectors leaves a simple escape: stolen broad
Kubernetes authority creates a brand-new privileged Pod that has no Mithril
profile, mounts `/`, and becomes node root.

Every sandbox, container create/start, and runtime exec on an enrolled protect
node therefore passes a signed node admission floor before dangerous setup.
If no workload profile matches, policy chooses exactly one:

```text
REJECT_UNMATCHED
BASELINE_HARD_FLOOR(exact floor profile)
OBSERVE_ONLY_WITH_START_GAP
```

The attacker cannot choose this posture through Pod fields. It comes from
separately signed node policy.

The baseline floor rejects unless an independently signed exact exception
allows the request:

- privileged mode;
- host PID, network, or IPC namespaces;
- dangerous capabilities such as `CAP_SYS_ADMIN`, `CAP_BPF`, or
  `CAP_SYS_MODULE`;
- hostPath, host devices, writable runtime/kernel paths, and similar node
  control;
- unsafe seccomp/AppArmor/SELinux settings;
- unexpected user, groups, securebits, or `no_new_privs` posture; and
- other exact runtime security fields in `NodeAdmissionRequestV1`.

Kubernetes metadata alone cannot authenticate an exception. A
`system:masters` attacker can copy namespace, labels, ServiceAccount, image,
CSI metadata, and controller shape. An exception also binds exact signed
workload definition, image digest, allowed node set, rollout/multiplicity,
expiry, uses, and independent signer.

**Incident test.** Attacker creates a new Pod with `privileged`, `hostPID`,
host `/` mounted at `/host`, `CAP_SYS_ADMIN`, and a command reading
`/host/etc/shadow`. Race creation ahead of audit delivery. `REJECT_UNMATCHED`
rejects container creation. The hard floor rejects the first forbidden field
before host mount setup. A reviewed CSI DaemonSet with exact non-expired
exception remains the legitimate control.

The full original plan currently marks this floor
`UNALLOCATED_REQUIRED_FOR_FULL_HF_CLAIM`. It must be assigned to approved
phases before a release claims prevention of the privileged-Pod branch.

#### Checkpoint creation and restore

Restore can resume processes, threads, memory mappings, open files, devices,
sockets, namespaces, and shared state without normal user exec. Version 1
therefore rejects restore by default.

Full restore support needs:

1. Signed one-use `CheckpointRestoreIntentV1` binding checkpoint and manifest
   digests, source identity/generation, target node/execution set/current
   generation, exact runtime/restore-engine build, counts/manifests for tasks,
   processes, memory classes, fds, sockets, VMAs, devices, namespaces, and
   authority domains, approval, and deadlines.
2. A measured restore coordinator in a narrow `RESTORE_SETUP` cgroup. It may
   perform only the exact versioned setup steps and has no ordinary credential,
   public/control network, arbitrary exec, host, or export permission.
3. One preallocated `RestoreTargetBirthSlotV1` for each expected target. At
   `task_alloc`, only the exact coordinator may claim the correct next slot.
   Target receives its own immutable identity and
   `RESTORE_TARGET_PREPARING` state at birth; it never inherits helper
   authority.
4. Every restored user task reaches an authenticated final held/stopped
   barrier. The coordinator may run; restored user code may not.
5. Mithril binds the exact final cgroup and installs current target policy,
   process/domain state, generation/response state, and every object record.
6. Complete task/object/reference/manifest readback. Missing/extra/reordered
   task/object, early wake, changed checkpoint, engine mismatch, or partial
   commit fails and reaps/fences the target set.
7. One common domain activation, then each target releases exactly once. Atomic
   resume means no restored user instruction runs before global commit; it does
   not mean the scheduler runs all targets simultaneously.

The old idea “freeze the entire restore cgroup while CRIU runs” is rejected.
The helper must run to restore. Helper stays in a separate setup cgroup; only
target tasks are held. A final barrier may be authenticated stopped tasks,
private bootstrap, or qualified target-cgroup freeze.

Checkpoint **creation** is a separate memory-export operation. A process may
hold secrets only in memory. Kubernetes/CRI checkpoint can archive those bytes
without a worker file read. Protected workloads default-reject creation.

A forensic exception binds exact actor/approval, container, current response
state, destination, overwrite precondition, encryption key, maximum bytes,
retention, included memory/fd/socket classes, request digest, and deadline.
`STORED` requires encrypted archive digest, size, store revision, key ID,
retention readback, and runtime result. “Capture started” proves only
`CAPTURING`.

`ENTRY-RESTORE-001` and `CHECKPOINT-CREATE-001` include secret-only-in-memory,
preopened token/device/socket, executable maps, changed node/generation,
missing/extra task or fd, early resume, path traversal/overwrite, contained
target, and lost audit cases.

Checkpoint support remains `UNALLOCATED_OPTIONAL` until the master and phase
plans assign its owner and tests.

#### Attach and port-forward

Neither operation creates a workload process. `StreamAuthorityOwner` binds:

- actor and request UID;
- Pod/container and, for attach, exact target process when runtime proves it;
- stream ticket and transport digest;
- TTY/stdin/stdout/stderr or ports;
- direction, maximum bytes, channels, and time;
- required audit proof; and
- stream state from prepared through active, fenced, completed, rejected,
  expired, disconnected, or unknown.

Attach never creates a role. Port-forward never creates a parent edge. The
owner authenticates the one-use runtime ticket, reads back target/ports and
transport, then meters both directions. Overflow or expiry closes/fences by
signed policy.

`ENTRY-STREAM-001` covers stolen URL, audit mismatch, wrong Pod/container,
extra port, reverse direction, byte/channel/time overflow, replay, disconnect,
and identical `pods/exec`. Only exec creates an entry.

Attach/port-forward authority remains `UNALLOCATED_OPTIONAL` until an approved
phase owns the stream gate, adapters, budgets, and test.

### 8. Proving Why An Entry Or Authority Exists

Process identity answers “which live Linux task is this?” It does not answer
“why was this task or credential requested?” Mithril learns purpose through a
separate, authenticated intent proof and binds that proof to the exact physical
task or authority acquisition.

This distinction prevents a common mistake:

```text
wrong:
  command == /app/healthcheck
  therefore this is a readiness probe

correct:
  measured kubelet requested this exact readiness probe
  + signed one-use ticket Q
  + runtime created and held task T for Q
  + task T claimed Q before user execution
  therefore task T receives the readiness-probe role
```

An attacker may go through kubelet and use exactly the same command. The
transport, command, cgroup, and namespaces can all match. The authenticated
request actor, immutable Pod definition, entry reason, one-use slot, and held
task make the legitimate case different.

#### The common signed intent

All intent producers use one canonical `SignedIntentV1` envelope. They do not
invent per-adapter JSON signing rules. Its payload contains:

- version, proof ID, tenant, trust domain, issuer, signing key, and algorithm;
- issuer sequence epoch and sequence;
- issue, not-before, and expiry times;
- one or more explicit, unique, sorted one-use claim-slot IDs;
- exactly one closed intent body;
- optional parent proof and trigger proof IDs.

Supported bodies are:

| Intent | What it proves | Where it is consumed |
| --- | --- | --- |
| `RUNTIME_ENTRY` | A specific container start, probe, lifecycle hook, administrative exec, ephemeral container, CI container action, or restore was requested for an exact target and role | Held runtime task or qualified pre-exec claim |
| `NATIVE_TRANSITION` | An already labeled lineage may perform one exact fork, exec, or privilege transition | Native transition hook for that lineage |
| `AUTHORITY_LEASE` | An exact process or CI subject may request a provider credential with a bounded audience, permissions, resources, and TTL | Credential broker before exchange; provider issuance completes it |
| `ARTIFACT_HANDOFF` | Exact bytes from one producer may be read, verified, loaded, executed, or deployed by one consumer | Object/loader/deploy gate for that digest and operation |
| `PROVIDER_OPERATION` | A trusted semantic gate may perform one provider operation on named resources | Provider or connector gate, never ordinary after-the-fact audit |
| `DEPLOYMENT_ADMISSION` | A signed workload definition, image, security fields, multiplicity, nodes, and profile generation may be admitted | Kubernetes/runtime node-admission path |
| `CI_STEP` | A coordinator assigned one immutable step to one runner/job and requested one role | Native transition, runtime root, or coordinator-only provider action according to execution shape |

The exact integer-keyed deterministic-CBOR schema, bounds, tags, and Ed25519
golden vector belong in Appendix A. Security IDs are fixed-size bytes, not
display strings. Unknown fields, duplicate fields, indefinite encodings,
non-canonical bytes, unregistered numeric tags, wrong variant fields, and a
decode/re-encode mismatch are parser errors.

The issuer cannot select fail-open behavior. The signed payload does not carry
`disposition_on_mismatch` or `disposition_on_expiry`; locally signed policy
does. It also cannot send a reusable count. It sends explicit one-use slots.

**Example.** Kubelet legitimately needs three identical readiness checks. The
proof contains slots A, B, and C. Each exact task atomically claims one slot. A
fourth task is rejected. Restarting `mithril-node` and replaying A is still a
replay, not a new check.

#### Trust, time, and replay

The trust bundle limits each issuer to named intent kinds, subject scopes,
algorithm, key, sequence epoch, and validity interval. Maximum accepted clock
skew is configurable from zero to five minutes; a larger value is invalid.

Receipt uses wall-clock validity including measured uncertainty, then derives
a monotonic boot-time deadline. An NTP step cannot revive an expired proof.

Replay state is keyed by trust domain, issuer, key, and sequence epoch. It
contains a bounded 4,096-sequence out-of-order window plus proof and slot
tombstones. Accepting a proof is one ordered transaction:

```text
1. Parse bounded canonical bytes.
2. Verify signature, trust scope, target, times, and local policy subset.
3. Prove sequence, proof ID, and every slot are new.
4. Append acceptance durably to the local WAL.
5. Expose prepared claim slots to the runtime/kernel.
6. Record every later claim transition in the WAL and pinned claim journal.
```

A BPF hook never waits for disk. Userspace durably prepares the slot before
exposure. The kernel then updates a preallocated pinned tombstone before it
installs authority. After a crash, `mithril-node` replays WAL and reconciles
the pinned tombstone before reopening admission.

The full claim state is:

```text
PENDING
  -> CLAIMING
  -> CLAIM_BOUND_PROVISIONAL
  -> EXEC_COMMITTED

or terminal:
  EXEC_FAILED | EXPIRED | CANCELLED | TASK_EXITED
```

`CLAIM_BOUND_PROVISIONAL` is not permission to run normal workload effects.
It permits only the bounded loader/interpreter work required to finish the
staged exec. Only the qualified successful-exec point installs the target role.

**Crash test.** Kill `mithril-node` after the kernel claim CAS but before ring
event delivery. On restart, the pinned record reconstructs the transition, the
same slot cannot be used again, and no provisional task gains its target role.

#### Exact kubelet probe and lifecycle intent

Stock CRI `ExecSync` does not carry “readiness,” “liveness,” `PostStart`, or
`PreStop`. Matching argv and timing cannot distinguish concurrent identical
requests.

Version 1 full support uses a small maintained kubelet call-site integration
and a ticket-aware runtime/shim:

```text
1. At kubelet's probe/hook call site, send Pod UID and resource version,
   full container ID, container-spec digest, lifecycle generation, exact
   reason, PodSpec field path, argv digest, timeout, and monotonic sequence.
2. mithril-node authenticates kubelet, re-resolves the live definition, and
   returns one signed ticket.
3. Kubelet passes that ticket through RunInContainerWithMithrilTicket.
4. Runtime creates the exact child behind the held-task barrier and sends its
   pidfd plus ticket nonce.
5. mithril-node installs and reads back identity, consumes the ticket, and
   acknowledges resume.
6. Result and timeout return with the same ticket ID.
```

This changes node control-plane components, not the PodSpec, image,
ServiceAccount, or application architecture.

| Installation | Honest result |
| --- | --- |
| Stock kubelet and stock runtime | No exact reason. Equal compiled budgets may use `SAME_BUDGET_AMBIGUOUS`; unequal budgets reject. |
| Patched kubelet, stock runtime | Authenticated reason exists but cannot select one of concurrent identical children. |
| Stock kubelet, patched runtime | Exact task is held, but probe versus lifecycle purpose is missing. |
| Ticket-aware kubelet and runtime | `EXACT_INTENT_AND_TASK` after task-label readback. |
| Direct `crictl ExecSync` | Administrative entry or rejection; never a probe/hook role. |

**Concrete ambiguity.** `/app/check` is both a readiness probe that may read
`/run/healthy` and a `PreStop` hook that may call `/drain`. Giving an unknown
request the union is unsafe: every readiness check would gain drain authority.
The default is rejection. A configured intersection is allowed only if
simulation proves the real operation still works. An explicitly approved union
is a broad exception, not “conservative” and not part of the exact claim.

`ENTRY-KUBELET-TICKET-001` starts readiness, liveness, `PostStart`, `PreStop`,
and direct `crictl ExecSync` with identical argv, reverses task creation order,
and tests swapped, duplicate, expired, dropped, and restart-replayed tickets.

#### AWS and Google login are authority leases, not entry kinds

Running `aws sso login`, `gcloud auth login`, or `gsutil` does not create a
special Mithril entry kind. The CLI follows its real native process lineage.
The separately approved provider authority becomes an
`AuthorityLeaseIntentV1`, then—only after compatible provider issuance—a
`CredentialLeaseV1`.

AWS example:

```text
approved CI or human proof
  -> expected AWS account, role/permission set, audience, TTL, source identity
  -> exact labeled process claims the lease request nonce
  -> broker/provider returns a compatible public session/access-key identifier
  -> CredentialLease binds provider session to the local owner at a stated
     proof quality
  -> CloudTrail actions join by authority-owned session fields
```

Policy separately controls the CLI executable, its cache/config objects, the
identity and API destinations, requested role and TTL, which descendants may
use the lease, and allowed provider operations. A shared AWS SSO cache is not
an exact task-to-session proof. Exact binding needs a nonce-carrying broker or
provider fields cryptographically tied to the approved identity; otherwise the
join is conservative or contextual.

Google workload-identity example:

```text
CI coordinator OIDC claim
  -> AuthorityLeaseIntent with issuer, audience, immutable job identity,
     target project/service account, scopes, and TTL
  -> Google STS exchange and optional service-account impersonation
  -> downstream audit identifies the fields that service actually preserves
```

Google audit does not universally preserve the source OIDC `jti`. A deployment
may map an immutable job identifier into `google.subject` and qualify each
service's audit fields. If downstream audit exposes only a shared service
account, the operation is exact for that account but only contextual for one
local job; job-exact automatic response is ineligible.

Secret material never enters evidence, the graph, logs, or WAL. A broker that
must revoke the exact bearer token may keep a short-lived encrypted or
non-exportable `ProtectedCredentialHandleV1` in a separate vault boundary,
authorized only for `REVOKE_SELF`. Evidence carries the opaque handle ID. If
the handle does not exist, response must use a wider provider action or wait
for expiry.

#### Artifact handoff is neither process parenthood nor permission to execute

A CI artifact, cache entry, image, manifest, queue message, or shared file
crosses a boundary without a Linux parent edge. Mithril records an immutable
artifact instance and one independent consumer slot per consumer.

`READ_AS_DATA`, `VERIFY`, `LOAD`, `EXECUTE`, and `DEPLOY` are different
operations. Restoring cache digest D for data does not authorize `dlopen(D)`.
A valid attestation proves the signer made a statement; policy must also trust
the builder, materials, subject digest, and predicate.

From verification to load/execute/deploy, the bytes must remain the same. Use
fs-verity, IMA, sealed immutable storage, or an exact held fd plus digest and
version revalidation. Copying verified bytes into a mutable workspace loses
that continuity.

#### Fallback pre-exec claim

When a runtime cannot pass a held task, an unlabeled root may claim one
preallocated slot at a qualified `bprm_check_security` point. The key includes
the live cgroup binding and lifecycle generation plus a bounded executable and
argv classifier.

The complete transaction—not just a map CAS—must:

1. validate boot, binding nonce, generation, executable, attempt, prepared
   digest, sole-thread shape, active authority domain, and exposed slot;
2. atomically win the slot and allocate a non-reused task cookie;
3. install task identity pointing to a prebuilt `ENTRY_PROVISIONAL` process;
4. write and read back the pinned claim tombstone;
5. acquire entry, generation, process, and authority-domain references with
   owned bits for exact rollback;
6. activate the prebuilt process state with only the provisional budget;
7. read back every label, state, binding, generation, and reference; and
8. allow only the exact loader/interpreter work until exec commit.

Failure before labeling leaves a protected unlabeled task, which is
fail-closed. Failure after labeling leaves the provisional deny floor. Partial
failure never restores a broad role. The runtime reaps the stub and cleanup
releases only references whose owned bits prove they were acquired.

Two identical pending candidates cannot provide exact request-to-task
attribution. If their budgets differ, reject. If budgets are byte-for-byte
identical, the effect can be admitted as `SAME_BUDGET_AMBIGUOUS`, but all
candidate actor/request IDs remain and no exact actor edge is invented.

This fallback is supported only when a runtime-specific trace proves the task
is already in the bound cgroup before first `bprm` and performs no protected
effect between placement and claim. Otherwise the held-task integration is
required.

### 9. Exit, Shutdown, And Identity Retention

Identity and policy stay installed until runtime exit is confirmed and BPF
task/cgroup reconciliation proves that no live member remains. `StopContainer`
or Pod deletion changes lifecycle state; it does not delete enforcement maps.

For a contained lineage:

- ordinary new entries are denied;
- `PreStop` is not automatically trusted merely because kubelet requested it;
- policy may allow a narrow shutdown role with exact files, destinations, and
  deadline;
- if cleanup could reopen the attack path, containment wins and the hook fails;
- freeze and kill remain separate typed responses with separate approval; and
- controller replacement Pods are watched and constrained as new branches.

Reference ownership is explicit. Every task, process, entry, authority domain,
and policy generation reference has an owned bit and tombstone. Failed clone,
failed exec, duplicate exit, daemon restart, thread-leader exit, reparenting,
and PID reuse cannot decrement a reference twice or retire live policy.

**Shutdown example.** A compromised worker has a declared `PreStop` script
that normally uploads a final report. During containment, the cleanup role may
write one local status file but cannot use the public upload socket or read the
projected token. Kubelet still receives the hook failure; Mithril does not let
shutdown become the last exfiltration path.

## Part III — One Policy From Source To Kernel Decision

### 10. Protection Invariants

These rules are true whenever their named capability is enabled. They are not
alert ideas. Each one has a hostile fixture, a physical oracle, required
coverage, and one of four results: `PASS`, `FAIL`, `UNSUPPORTED`, or
`INSUFFICIENT_COVERAGE`.

| ID | Rule | Concrete proof |
| --- | --- | --- |
| `INV-ENTRY-001` | Every task performing a protected effect has a verified native creator or an admitted external root. | A forked worker child and a separate `kubectl exec` root in the same container receive different kernel identity before either reads a file. |
| `INV-ENTRY-002` | An unlabeled task inside protected placement is denied unless it atomically claims an exact one-use entry. | A host process enters the namespaces/cgroup and opens the projected token; the hook returns `EACCES` and no byte is read. |
| `INV-ENTRY-003` | Reparenting and PID, namespace, cgroup, runtime, or kubelet reuse cannot change birth lineage. | A replacement process with the same visible PID/path cannot resolve the old task cookie, live interval, nonce, boot epoch, or entry. |
| `INV-ROLE-001` | Only an admitted entry or approved transition assigns a role. A path/name never assigns authority. | Approved updater and compromised worker both execute `curl`; each keeps the authority of its own entry/transition. |
| `INV-ROLE-002` | Fork without exec is restricted immediately; exec keeps lineage but creates a new execution and reviewed role transition. | A forked Python child cannot read a credential before exec; non-leader exec cannot escape during de-threading. |
| `INV-EFFECT-001` | Rules are expanded to exact keys; different physical results need a signed override or compilation fails. Missing required identity, generation, classifier, table, or response state denies. | An output path symlinked to a token resolves to the token object; conflicting allow/deny does not depend on “specificity” or file order. |
| `INV-EFFECT-002` | Telemetry, WAL, ring, rate-limit, or central-service pressure cannot turn a computed local denial into allow. | Fill the event ring while repeating token reads; every read still fails and loss counters increase. |
| `INV-POLICY-001` | Only a signed, validated, compiled, read-back generation can authorize. Learning never self-authorizes. | Observed malicious Kubernetes API use becomes a review candidate, not a new allow row. |
| `INV-POLICY-002` | Activation is atomic; old generations stay until every typed holder has ended. | Generation 42 tasks and sockets remain valid under 42 while new entry N receives 43; 42 is removed only after task/socket/object/response refs reach verified zero. |
| `INV-K8S-001` | Initial entry, probe, lifecycle hook, interactive exec, init/sidecar, and ephemeral container stay distinct even with identical bytes. | Three `/app/healthcheck` roots receive probe, application-descendant, and administrative roles from their exact origin. |
| `INV-K8S-002` | Shutdown is not a bypass. | A contained `PreStop` cannot read a Secret or send to the public Internet. |
| `INV-GRAPH-001` | Native parent edges never cross a node. | A node-A API request and node-B Pod root join through Kubernetes/runtime IDs, not a false process-parent edge. |
| `INV-RESPONSE-001` | Response re-resolves the live physical target and verifies the postcondition. | PID reuse makes a queued PID-only kill fail safely; a pidfd/task-cookie/cgroup match is required. |
| `INV-COVERAGE-001` | Missing hooks, sequence gaps, start gaps, ambiguous entries, and unavailable provider feeds narrow the claim. | A GitHub feed outage yields an explicit unknown interval, never “no write occurred.” |

The original phrase “most specific deny wins” is an abandoned design. There is
no total order between, for example, a role-exact/object-wildcard allow and a
role-wildcard/token-exact deny. Both expand to the same exact decision cell;
without a signed override edge, the compiler rejects the profile.

Each release record is executable:

```text
InvariantQualificationV1 {
  invariant_id
  capability_record_digest
  upstream_source_evidence_ids[]
  profile_generation_ref_id
  protected_scope_id
  preconditions[]
  stimulus_fixture_id
  expected_decision_point
  expected_physical_result
  required_coverage[]
  observed_artifact_digests[]
  status: PASS | FAIL | UNSUPPORTED | INSUFFICIENT_COVERAGE
}
```

“First protected hook” is not “first instruction.” CPU-only code may run before
a file, socket, exec, device, or privilege hook. Preventing process creation or
CPU use requires a qualified task-creation hook, seccomp clone floor, runtime
admission, `pids.max`, or CPU controller. A file hook cannot claim that result.

### 11. The Operator Writes One Policy Model

The human source object is one `WorkloadProtectionProfile`. It contains:

```text
identity and signature
selectors and required platform capabilities
default postures and failure posture
entry rules
roles and native transitions
local effect rules
dynamic/authority-domain state rules
provider/authority behavior rules
correlation packages
notification and response rules
coverage requirements
rollout and exact exceptions
```

Selectors find candidate workloads in userspace. They never become kernel
authority. Binding resolves a selector to exact Pod UID, full container ID,
image digest, cgroup live interval and nonce, mount/network namespace
generation, and profile-generation handle.

#### A complete readable example

This YAML is a design-level source example; the exact Version 1 serialization
is the closed deterministic-CBOR schema in Appendix A.

```yaml
profile: hf-conversion-worker
version: 8
mode: protect

selector:
  namespace: datasets
  labels: {app: conversion-worker}

defaults:
  entry: reject
  transition: deny
  file: deny
  network: deny
  device: deny
  privilege: deny

failurePosture:
  missingTaskIdentity: deny
  requiredClassifierUnknown: deny
  intentChannelUnavailable: reject
  providerFeedUnavailable: alert
  notificationUnavailable: keep-enforcement-and-buffer

entries:
  - id: initial-worker
    kind: container-start
    imageDigest: sha256:approved-worker-image
    role: conversion-worker
    onMismatch: reject

  - id: readiness
    kind: kubelet-exec-probe
    declaredField: readinessProbe.exec
    commandDigest: sha256:canonical-health-command
    role: readiness-probe
    maxConcurrent: 2
    claimTtl: 5s
    ambiguity: same-budget-only

  - id: cleanup
    kind: kubelet-prestop
    declaredField: lifecycle.preStop.exec
    commandDigest: sha256:canonical-cleanup-command
    role: prestop-cleanup
    claimTtl: 2s
    ambiguity: reject

roles:
  conversion-worker:
    forkWithoutExec: conversion-child
    maxNativeDepth: 8
    exec:
      - object: approved-converter-helper
        targetRole: converter-helper
    files:
      - {operation: read, class: dataset-input, disposition: allow}
      - {operation: read, class: worker-runtime, disposition: allow}
      - {operation: write, class: worker-scratch, disposition: allow}
      - id: deny-worker-token
        operation: read
        class: projected-service-account-token
        disposition: deny
        errno: EACCES
        finding: HF-PROC-001
    network:
      - {operation: connect, destination: approved-result-service, disposition: allow}
      - {operation: connect, destination: kubernetes-api, disposition: deny}
      - {operation: connect, destination: cloud-imds, disposition: deny}
      - {operation: connect, destination: public-internet, disposition: deny}
    devices: []
    privilege: []

  readiness-probe:
    maximumLifetime: 3s
    childProcesses: deny
    files:
      - {operation: read, class: probe-health-file, disposition: allow}
    network: []
    devices: []
    privilege: []

  prestop-cleanup:
    maximumLifetime: 20s
    childProcesses: deny
    files:
      - {operation: write, class: declared-cleanup-state, disposition: allow}
    network:
      - {operation: send, destination: declared-drain-endpoint, disposition: allow}
    onActiveContainment: deny

authorityBehavior:
  - principal: conversion-worker-service-account
    sourceRole: conversion-worker
    stage: post-effect
    authority: kubernetes
    allowedOperations: []
    onDeviation: alert
    response: restrict-compromised-worker
```

This allows many logical conversion jobs in one Pod. Mithril protects process
trees and effects; it does not require one Pod or one process per job. The
readiness root is legitimate but cannot read the same mounted token. Running
the health binary as a native worker child does not produce the probe role.

#### Entries, roles, transitions, and effects

An entry rule names the exact entry kind, container kind, optional executable
object or canonical argv digest, PodSpec field proof, lifecycle states, caller
proof, concurrency and rate budget, claim TTL, target role, ambiguity action,
and default admission result.

Canonical argv is length-delimited raw bytes:

```text
u32_be(argument_count) || for each argument:
  u32_be(byte_length) || raw_argument_bytes
```

There is no shell re-tokenization, whitespace folding, Unicode normalization,
or comparison against redacted display text. Argv helps classify one declared
request; it never replaces physical file/network/device policy.

A role names its entry origins and one effect-policy state. A transition rule
is the only authority for fork, thread, exec, and privilege transitions. Role
fields such as `forkWithoutExec` are shorthand that the compiler expands into
that same table. If shorthand and an explicit transition disagree, compilation
fails; no hook chooses a different authority.

An effect rule names:

```text
role + effect family + operation + composite object class + exact key if needed
+ process/domain state + workload lifecycle
-> allow, audit-allow, or errno denial
+ optional monotonic state transition and evidence requirement
```

An object has several axes at once. A projected token is not reduced to one
label:

```text
credential=service_account_token
backing=projected_volume
mutability=provider_rotated
persistence=pod_lifetime
```

The compiler enumerates the bounded cross-product into one composite atom. A
missing required axis or unknown atom denies. Likewise, Kubernetes API over a
private TLS address remains both `cluster_control_plane` and `private`; the
private address cannot erase the control-plane rule.

#### Local effects and provider behavior are different stages

Linux may deny a process connecting to the Kubernetes API. It cannot see the
verb and object inside direct TLS. A provider/authority behavior rule names a
versioned vocabulary, typed resource selector, principal/session fields,
result class, proof, and either:

- `REMOTE_PRE_ADMISSION`: a real synchronous Kubernetes admission, broker, or
  connector may forward, alert-forward, or reject; or
- `POST_EFFECT`: authoritative audit may record or alert after success, denial
  by provider, failure, or unknown result.

At `POST_EFFECT`, “allow” means “record without a deviation finding.” It does
not mean the already completed action was allowed by Mithril. Free-form
operation strings are invalid; provider adapters own checked numeric
vocabularies and schemas.

#### The four operator dispositions

| Disposition | Physical result | Legal stage |
| --- | --- | --- |
| `allow` | Admit/forward/let the local effect proceed; emit only required evidence | Any stage, with post-effect meaning record-only |
| `alert` | Proceed or record completion, then create and route a finding | Any observable stage |
| `deny` | Return the qualified negative errno before a local transition/effect completes | `NATIVE_TRANSITION` or `LOCAL_PRE_EFFECT` only |
| `reject` | Refuse the higher-level entry, lease, CI, deployment, or provider request before admission | `ENTRY_ADMISSION` or `REMOTE_PRE_ADMISSION` only |

Therefore a token `open(2)` can be `deny + finding`; an invalid runtime root is
`reject`; and a provider audit record can only `alert + optional response`.
Choosing `deny` in YAML cannot change a completed AWS or GitHub action into a
prevented action.

Every rule separately controls physical result, evidence level, finding,
notification routes, optional response, proof requirement, fallbacks, rate /
concurrency / lifetime budgets, validity, approval, and exact exceptions.
Notification schemas allowlist fields by sensitivity:

```text
PUBLIC < INTERNAL < SENSITIVE_IDENTIFIER < SECRET
```

`SECRET` never leaves through a notification. Forensic evidence may retain
specific bounded raw fields encrypted locally, but notification redaction does
not weaken.

#### Exceptions are bounded authority changes

An exception names the rule it changes, exact protected scopes/workloads,
entries, roles, immutable definitions, exact compiled key digests, authority
delta, approver and proof, start/end, maximum uses, and maximum lifetime.

It cannot target `*`, never expire, override a product hard invariant, or use
free-form reason text as authority. `BOUNDED_BROADENING` is visible in the
activation explanation and full-claim exclusions.

### 12. Compiler, Signature, And Atomic Activation

Human YAML is normalized into closed `PolicyDocumentV1` bytes. The signed
profile uses deterministic CBOR and Ed25519 with domain separator
`MITHRIL-PROFILE-V1`. The signature header binds the policy digest and the
numeric registries for providers, capabilities, selectors, object classifiers,
reason codes, correlation packages, and provider vocabularies.

Unknown keys, duplicate fields, unknown enums, non-canonical encodings,
invalid durations, integer overflow, unsupported algorithms, revoked keys,
unregistered IDs, and digest/header mismatches are rejected. Version 1 has no
generic metadata extension map.

#### Anti-rollback

Before activation, Mithril durably stores the greatest accepted issuer
sequence and profile version for each trust-domain/issuer/profile. A lower
signed version is still a rollback and is rejected.

An intentional rollback needs a separate signed, one-use authorization that
names:

- exact current digest and version;
- exact older target digest and version;
- platform scope;
- approver, closed reason, issue time, and expiry.

Re-signing version 7 after activating 8 is not authorization. Wrong current,
wrong target, wrong platform, expired, or replayed rollback proof fails.

#### Compilation pipeline

```text
signed source
  -> bounded schema/signature/anti-rollback validation
  -> selectors resolved to immutable workload snapshots
  -> entries, roles, states, transitions, and effects checked for reachability
  -> all selectors expanded to a finite exact decision universe
  -> conflicts require signed override/exception edges
  -> objects, composite atoms, responses, coverage, and provider vocabularies lowered
  -> simulate against a recorded legitimate-workload baseline
  -> human approval
  -> write a completely inactive generation
  -> read back every descriptor, row, default, membership, and digest
  -> run controlled allow and deny probes
  -> atomically publish the active-generation handle for new admissions
```

Compilation rejects ambiguous unequal-budget entries, escalation cycles,
unreachable roles, unsupported deny hooks, path-only objects marked immutable,
TLS verbs claimed from network-only evidence, response without a revalidation
key/postcondition, fail-open required classifiers, hard-invariant overrides,
and artifacts beyond verified BPF map/stack/instruction/depth/latency bounds.

Observation produces a candidate. It never writes active allow rows. Promotion
requires review, simulation, signature, probes, and rollout health.

#### Exact conflict rule

Rules are first separated by physical stage. Wildcards are expanded against
the closed generation universe. Identical physical decisions for one exact key
may merge compatible evidence and routing. Different physical results need a
signed `overrides` or exception edge naming the other rule and exact key delta.
Without that edge, compilation fails.

Priority controls display/notification order only. YAML order, wildcard count,
severity, “more specific,” and “deny is safer” never choose authority.

#### Generation activation and retirement

Generation handles are nonzero, monotonically allocated, and never reused
within `(node_boot_id, label_epoch)`. Every descriptor repeats that epoch.
Losing the allocator state while protected objects survive is fatal and holds
the workload fail-closed.

New external roots pin the active generation. Existing tasks, their native
forks and execs, sockets, files/shared objects, authority domains, VMAs,
checkpoint state, pending entries/execs, derived kernel capabilities, and
response plans keep their own typed generation reference.

```text
PREPARING: no holder may use or acquire
ACTIVE: existing holders may use; new holders may acquire with readback
RETIRING: existing proved holders may use; new references are denied
missing or unknown: deny and report corruption
```

Retirement requires all typed counters at zero, no owned reference tombstone
in complete iterator/WAL reconciliation, and the BPF grace period. Table rows
cannot disappear while a retained holder exists.

Version 1 does not migrate live processes to a new generation. That abandoned
design lacks a safe transaction across old/new generation refs, threads,
process/domain state, sockets, and concurrent retirement. Existing processes
stay pinned; only new external roots select the new generation. A future
quiesced old-intersect-new migration is a separately approved capability with
fault injection after every state/reference write.

**Generation test.** Task T and socket S start on generation 42. Activate 43.
T continues through 42; S follows its declared 42 lifetime; a new root N gets
43. Only after T exits, S closes, all typed references reconcile to zero, and
the grace period completes may 42 be removed.

### 13. The One Local Pre-Effect Decision

Every protected Linux surface uses the same ordering. The surface-specific
hook supplies the effect, operation, object/channel identity, and arguments;
the identity and policy machinery is shared.

```text
1. Preserve any nonzero prior BPF-LSM result.
2. Read current task storage first.
3. If labeled, resolve that task's exact process, entry, authority domain,
   binding, placement, pinned generation, and reference state.
4. If unlabeled, completely resolve protected cgroup placement. Outside all
   protected roots uses explicit host policy. Protected or uncertain placement
   attempts one exact eligible external-root claim, then denies if still unlabeled.
5. Intersect active emergency/response restrictions and hard invariants.
6. Classify every required object axis and exact lifetime identity.
7. Read the exact base rule/default from the actor's pinned generation.
8. Intersect authority-domain restriction, process response, domain response,
   object floor, socket/channel floor, pending-exec floor, and binding-lifetime floor.
9. If the allowed/audited effect has a monotonic state transition, atomically
   install its precompiled next state.
10. Fix the physical return value. Best-effort evidence comes afterward and
    can never change it.
```

#### Task first, never cgroup first

If a labeled worker is moved to `/system.slice`, its label still resolves the
protected execution set. Placement mismatch denies. The code never says
“current cgroup is host, therefore allow.”

Only an unlabeled task with a complete, qualified walk proving it is outside
every protected root may reach host policy. Ancestor-depth overflow, stale
index, or incomplete traversal is unknown, not outside.

Cgroup identity is:

```text
node boot ID
+ full u64 BPF cgroup ID
+ opened live interval
+ random binding nonce
+ opened cgroup-fd / cgroupfs mount identity
+ live BPF_MAP_TYPE_CGRP_STORAGE when qualified
```

Paths are explanation only. Recreating the same path does not restore old
storage/nonce. A test recreates the path and separately injects stale mapping /
nonce mismatch; requiring a naturally repeated full 64-bit ID is abandoned as
an impractical release gate.

#### One base permission plus only stricter floors

The actor's base row may allow, audit-allow, or deny. Every other set is
negative: it may preserve or narrow the base, never create authority.

```text
result = intersect(
  base role/effect row or explicit default,
  authority-domain restriction,
  process response,
  authority-domain response,
  exact object lifetime floor,
  exact socket/channel lifetime floor,
  pending-exec floor,
  binding lifecycle floor,
  prior security-module result)
```

Any deny wins in this physical intersection because these are already compiled
results, not conflicting source rules. If all permit and one asks for audit,
the result is audit-allow.

Every reachable non-exact cell has a real default row. Missing descriptor,
default, generation membership, composite atom, required dynamic floor, exact
object, unknown enum, or map-capacity state denies with a typed health counter.
Authoritative maps are preallocated and non-LRU.

Static policy cannot enumerate future sockets, pipes, received fds, or copied
files. For effects requiring a lifetime floor, the compiler emits either
`EXPLICIT_NEUTRAL` or `DYNAMIC_REQUIRED(template)`. At creation/acquisition,
the hook copies the template into an exact object-generation record, acquires
references, reads it back, and only then publishes the usable object. First use
before activation, capacity N+1, object reuse, or unclassified fd reception
denies.

#### Atomic dynamic state

State changes are precompiled. BPF looks up the transition before taking the
single owning value lock, rechecks current IDs/version under the lock, writes
the complete next tuple, and increments its transition version. It performs no
map/helper lookup while holding the lock and never nests process/domain/object
locks.

Version 1 permits one effect to change either process state or sensitive
authority-domain state, not both. An effect that must stop sibling publication
uses the domain transition as the authority. Process-local evidence can follow
without becoming a second independent security decision.

After one full snapshot retry, continuing contention denies. Race fixtures
pause writers between fields and prove readers see a complete old or new tuple,
never a mixed role/state/reference set.

#### Observe mode is not fail-open for broken identity

In `PROTECT`, a policy denial returns its errno. In `OBSERVE`, only a row marked
`SIMULATABLE_POLICY_DENY` returns allow and emits `WOULD_DENY`; state/response
transitions are not applied.

A prior LSM denial, stale binding nonce, missing protected task identity,
corrupt set, terminating lifetime floor, or installed emergency response is a
hard safety denial in both modes.

#### Stacked LSM result

Mithril preserves a nonzero prior BPF-LSM result. Depending on kernel LSM order,
its hook may not execute after a traditional SELinux/AppArmor denial. That
denial may still physically happen while Mithril has no local event. Platform
qualification records hook order and ingests the traditional LSM's audit when
available; otherwise evidence says the interval is incomplete.

The hot path never waits for Rust, disk, DNS, Kubernetes, a central service, an
LLM, or provider audit. Ring reservation happens only after the result is fixed.
Reservation failure increments a per-CPU loss counter and cannot restore an
allow.

## Part IV — Physical Linux Enforcement And Shared Authority

### 14. Why Mithril Uses Several Linux Mechanisms

No Linux mechanism covers the whole contract. Mithril compiles one source
policy into the mechanisms that own each physical boundary.

| Mechanism | Unique job | What it does not solve |
| --- | --- | --- |
| Mount namespace | Changes the filesystem view: hide host paths, present a selected rootfs/mount set, and apply `ro`, `noexec`, `nosuid`, and `nodev` kernel floors. | Any object still visible may be used by every process with ordinary Unix permission. It does not distinguish worker versus probe in one container, authenticate runtime entries, change dynamically for response, or govern network/provider actions. |
| Landlock | A monotonic restriction a process installs on itself and descendants. Depending on measured ABI, it can restrict filesystem, device ioctl, TCP/UDP bind/connect, pathname Unix sockets, signals, and abstract Unix sockets. | It needs a pre-run installation seam, cannot be centrally loosened or dynamically rewritten, may miss existing sibling threads on older ABIs, and does not supply Kubernetes entry intent, multi-node causality, or response orchestration. |
| Seccomp | Cheaply removes whole syscall classes or scalar-argument shapes a role never needs. Once installed, filters are inherited and can only become stricter. | It cannot safely resolve pathname pointers, file objects, target PIDs, Kubernetes roles, or TLS/provider semantics. It cannot be injected retroactively into an arbitrary running process. |
| BPF LSM | Makes dynamic task-aware decisions at Linux security hooks for files, exec, sockets, process control, devices, capabilities, mount, BPF, perf, and other qualified operations. It can use Mithril's task/process/domain state before effect. | It must be built and active as an LSM; helper/hook support varies by exact kernel. It cannot parse arbitrary TLS application intent or wait for a central service. GPL-compatible license is required for BPF LSM object programs that use the kernel's GPL-only interface. This does not automatically relicense the separate Rust program. |
| Cgroup BPF | Enforces workload/device floors, connect/send address policy, packet fences, and some socket operations at cgroup boundaries. | Cgroup membership alone is not per-process intent. Packet hooks may lack a meaningful current task. |
| TC/XDP/cgroup-skb | Drops actual packets, including established flows, after a response or final destination rewrite. | A packet does not reliably identify which of several sharing processes queued the bytes. Whole-socket/cgroup blast radius may be necessary. |
| Traditional SELinux/AppArmor | Adds mature distribution-owned mandatory policy and stacking defense. | Mithril cannot assume its hook observes every earlier denial; ordering and audit coverage are measured. |
| Runtime admission | Holds and labels a new root before user execution and rejects unsafe workload setup. | It does not control hostile code already executing inside an admitted process. |

The strongest ordinary worker can therefore receive all four local floors:

```text
mount namespace: host files absent; exact mounts and immutable flags
Landlock: monotonic dataset/scratch and selected network floor
seccomp: unused syscall families removed
BPF LSM/cgroup: exact current task, runtime entry, object, domain state,
                dynamic response, device/network/privilege enforcement
```

These layers intersect. None can turn another layer's denial into allow.
Missing Landlock or seccomp may produce a supported reduced tier if BPF owns
the claimed effect. Missing a required BPF LSM hook may make that particular
claim unsupported even when the namespace still hides many objects.

#### Pairwise examples: what each two-layer combination adds

Use one unchanged conversion worker as the example. It needs
`/dataset/input`, `/work/output`, its Python runtime, DNS, and one result
service. It must not read the ServiceAccount token, inspect the host, create a
TUN device, or reach Kubernetes.

| Pair | Concrete result | What is still missing |
| --- | --- | --- |
| Mount namespace + Landlock | Host `/etc`, `/proc`, runtime sockets, and devices are not mounted into the worker; Landlock still denies undeclared opens under the visible dataset/work tree if a bind/symlink/layout mistake exposes them. | Both are installed before run and mostly monotonic. They do not know that a new probe root and the application root need different authority, or dynamically fence an already-running compromised lineage. |
| Mount namespace + seccomp | Host objects are structurally absent; `mount`, `ptrace`, `bpf`, `perf_event_open`, module, keyring, and unused namespace/syscall families can be removed cheaply. | A visible token and an allowed `connect` syscall still need object/destination/actor policy. Seccomp cannot follow a pathname or distinguish two roles that need the same syscall. |
| Mount namespace + BPF LSM | Namespace removes whole host regions; BPF LSM distinguishes converter, probe, lifecycle, and admin tasks on every remaining exact file/exec/device/privilege object and can add a response restriction at runtime. | Whole unused syscall classes may still reach deeper kernel parsing unless seccomp removes them. A pre-run monotonic Landlock floor is absent if Mithril's own dynamic maps/links later become unhealthy. |
| Landlock + seccomp | Landlock limits visible filesystem/network/IPC rights inherited by descendants; seccomp removes syscall families that should never be attempted. This is a useful defense if the node BPF component is unavailable. | It needs a trustworthy pre-run installer. It does not authenticate later runtime roots, express Mithril's changing process/domain state, join multi-node actions, or centrally update response. The host view remains present even when access is denied. |
| Landlock + BPF LSM | Landlock supplies a monotonic least-authority floor that a later BPF policy bug cannot loosen; BPF LSM supplies exact task/entry/domain identity, dynamic object policy, and response. | The worker still sees every mounted pathname and may learn metadata through allowed operations. Unused syscall families still need seccomp, and host objects should still be removed by the namespace. |
| Seccomp + BPF LSM | Seccomp cheaply deletes broad attack surfaces; BPF LSM resolves the allowed syscall's real task, target object, and current restrictions. For example, seccomp permits `openat` generally while BPF LSM denies the token object only for the converter. | The filesystem view remains broad without the mount namespace; there is no independent monotonic pathname/network floor without Landlock. |

With all four, a runtime mistake must cross several different facts: the host
object first has to be visible, the syscall family has to exist, the monotonic
Landlock floor must permit it, and Mithril's current task/object/domain decision
must permit it. This is defense in depth, not four copies of the same rule.
Mithril still needs cgroup/packet controls for established traffic and provider
controls for TLS-hidden operations.

### 15. Mount Views And Exact Object Identity

A pathname is not a security identity. The same text can resolve through a
different mount namespace, bind mount, idmapped mount, overlay layer, symlink,
`dirfd`, or object replacement.

#### Mount and network namespace records

```text
MountViewIdentityV1:
  node boot + mount namespace inum + random namespace binding nonce
  + namespace live interval + topology epoch

LiveMountObjectV1:
  mount view + unique mount ID where qualified + superblock/filesystem
  + mount live interval + root/subtree + idmap user namespace
  + ro/noexec/nosuid/nodev + propagation + overlay lower/upper/work identity

NetworkNamespaceIdentityV1:
  node boot + netns cookie + live interval + capture mechanism
```

The same inode through an idmapped mount can have different ownership and file
capability behavior. Remount, `mount_setattr`, propagation, overlay copy-up,
move, pivot, or replacement advances topology even when inode/superblock
numbers look unchanged.

Userspace holds namespace/root fds while binding. Strong targets use
`STATX_MNT_ID_UNIQUE` and `listmount`/`statmount`; a held and verified complete
`mountinfo` snapshot is a lower tier. Bare mount IDs, namespace display
numbers, and paths are contextual and reusable.

#### No asynchronous topology race

Watching a successful mount and updating policy later is too late. Before any
covered mount, unmount, `move_mount`, `open_tree`, `pivot_root`, `fsconfig`, or
other topology change can take effect, the qualified hook performs:

```text
allocate bounded mutation ID
increment topology epoch and pending count
mark the target namespace DIRTY
```

Strict file/exec decisions in a non-`CLEAN` namespace deny. A qualified return
path marks that exact mutation complete even if event delivery fails. Rust
reconciles only at `(epoch E, pending 0, DIRTY)`, snapshots and resolves the
whole topology, installs and reads back new object tables, then compare-and-
swaps exactly `(E, 0, DIRTY) -> (E, 0, CLEAN, snapshot digest)`. A concurrent
mutation changes E and defeats the CAS.

A failed mount may leave a newer clean epoch after reconciliation. Correctness
does not depend on rolling the number back. Daemon death, lost completion, map
capacity failure, truncated snapshot, or disappearing namespace leaves it
DIRTY until a signed quiescent recovery.

Shared/slave propagation, automount, and NFS referrals can change another
namespace without a direct syscall there. Version 1's full baseline requires
private protected mount trees and no unqualified automount/referral points at
the held rootfs barrier. An extended tier must dirty every affected namespace
before visibility; bounded-fanout overflow sets a common fail-closed state.

**Race fixture.** A host task joins the worker mount namespace and mounts a
different object over an allowed path while the worker loops on open. Opens
before DIRTY see the old exact object; every open after DIRTY denies until the
new snapshot commits. The fixture repeats with two concurrent changes, failed
mount, propagation, overlay copy-up, and a process dying during snapshot.

### 16. Commands, Executable Images, And Executable Memory

Mithril governs a kernel executable transition, not a command string.

An executable object contains exact mount view and live mount, filesystem and
superblock live interval, inode, qualified incarnation/integrity, overlay
origin/upper/copy-up state, type/mode, deleted state, and a quality:

```text
IMMUTABLE_VERIFIED | LIVE_EXACT | REUSABLE_CONTEXTUAL | UNKNOWN
```

Authority for immutable code requires one of:

- immutable image-layer object with current overlay proof;
- fs-verity or IMA appraisal;
- correctly sealed memfd, including no earlier writable mapping;
- exclusive integrity lease that synchronously invalidates on every write,
  truncate, writable mmap, direct I/O, replacement, or copy-up.

Holding an fd proves object lifetime, not immutable bytes. Another fd can
modify the object. A path/inode without qualified incarnation is reusable
context and cannot authorize mutable code.

The exec transaction covers `execve`, `execveat`, `fexecve`, scripts, shebang
interpreters, `binfmt_misc`, the dynamic loader, memfd, deleted/unlinked files,
`/dev/shm`, overlay transitions, and non-leader exec. A compiled edge may deny
`python -> sh` or `python -> curl`. Python importing a module or evaluating a
template in-process has no exec edge; file mapping and later effects remain the
control points.

#### Memory that later becomes executable

File mappings have separate `MMAP_READ`, `MMAP_WRITE`, and `MMAP_EXEC`
decisions. `file_mprotect` and qualified `pkey_mprotect` variants recheck any
transition that adds write or execute, including `RW -> RX`, `R -> RX`, and
`RX -> RWX`. A no-JIT role denies executable anonymous, memfd, and deleted-file
memory. A JIT role receives a bounded signed image/memory budget.

ELF `PT_GNU_STACK`, `READ_IMPLIES_EXEC`, and architecture personality can make
memory executable without a later `mprotect`. At the held rootfs barrier, Rust
parses bounded immutable ELF metadata and binds executable-stack, interpreter,
architecture, static/dynamic, and personality meaning to the exact immutable
object. The BPF exec hook performs a bounded lookup; it does not parse mutable
ELF bytes in the hook.

Kernel-created executable mappings such as vDSO/vvar, legacy vsyscall, and
architecture signal gates are fixed measured classes bound to exact kernel
build/architecture/personality. They never become “allow all anonymous RX.”

Preexisting mappings cannot be retroactively prevented. A held full task/VMA
reconciliation may record them, freeze/kill/restart the lineage, and deny later
effects. It must report the acquisition interval unknown.

Full negative VMA snapshots use pidfds, task iteration, held/quiescent targets,
and `kcmp(KCMP_VM)` to form exact shared-address-space equality classes without
exporting raw kernel pointers. One serialized task-VMA iterator runs per class;
versioned binary frames must reach validated EOF, then tasks, pidfds, start
times, sharers, and every equality comparison are repeated before commit.
`/proc/<pid>/maps` may prove a positive observed mapping but cannot prove a
concurrent negative snapshot.

**Physical fixtures.** Replace an executable between bind and exec; write and
truncate through a second fd; force overlay copy-up; run sealed versus unsealed
memfd; create anonymous RW, change to RX, and jump to a marker; run executable
and non-executable stacks. Forbidden markers remain absent. Incomplete VMA
snapshot returns `VMA_SNAPSHOT_INCOMPLETE`, never “no mapping.”

### 17. Files, Credentials, And Delegated I/O

File operations use exact operation shapes. A rule for `open_read` does not
automatically govern namespace mutation or already-open descriptors.

#### Existing and not-yet-existing objects

```text
create: actor + mount view + parent object + bounded raw name + type/mode/flags
link: actor + source object + destination parent/name/flags
rename: actor + source parent/object + destination parent/existing object/name/flags
unlink: actor + parent + victim + file-or-directory
setattr: actor + object + truncate/mode/uid/gid/xattr/file-capability change
```

Resolved parent, mount, and object identities authorize. Path bytes are bounded
evidence/selector input. Unknown flags, over-bound names, hash collision,
unresolved parent, or unsupported hook fail according to required classifier
posture—strict profiles deny.

Fixtures cover `openat/openat2(O_CREAT)` with changed dirfds, symlink, hard
link, `O_TMPFILE` plus `linkat`, every rename mode, cross-mount, overlay,
unlink-while-open, chmod/chown/truncate, xattr/file capabilities, and over-bound
names. The oracle is the forbidden object remains absent or unchanged.

#### Projected credentials and `/proc`

Projected Kubernetes tokens rotate through AtomicWriter symlink/data-directory
swaps. An asynchronous inode list has a read race and is abandoned. The
pre-effect classifier uses projected-volume mount provenance plus a bounded
relative semantic item such as `token`, `namespace`, or `ca.crt`. Inode/live
object identity enriches the result but is not sole authority. If exact item
resolution is unavailable, a role that must not read credentials denies the
whole projected volume.

`/proc/<pid>/environ`, `mem`, `maps`, `map_files`, `fd`, `ns`, and similar
objects require exact PID-namespace target resolution to a live task cookie.
A textual PID is insufficient. Without that resolver, policy may deny the
whole class but cannot claim self-versus-other distinction.

Opening `/proc/self/environ` is controllable. Reading environment bytes already
present in the process through `os.environ` is not a new file effect. Mithril
must govern the next publication, provider, file, network, exec, device, or
privilege effect and state that the memory access was unobserved.

#### Opened-file provenance follows the file

A host task can open a host credential and pass the fd into a container. Later
classification cannot use only the container's current mount view.

Each protected file instance retains exact `file->f_path` object/mount,
acquiring actor role/generation/domain, open flags, transfer edges, response,
and live interval. Every later read/write/mmap uses the current actor's
permission intersected with that immutable file-instance floor.

Fork, dup, `SCM_RIGHTS`, `pidfd_getfd`, lazy-unmounted mount, bind alias, fd
number reuse, and creator exit do not produce a clean file. Final security
state ends only at a qualified file/object lifetime point or complete held
reconciliation, not one fd close.

#### Remote files and local proxies are delegated egress

Writing NFS, 9p, CIFS, FUSE, CSI, object-store mounts, or a local proxy can
cause another kernel client/process/sidecar to send the packet. Mithril records
a typed `DelegatedIoEdgeV1` from the initiating file/local-socket effect to the
delegate and then to the remote flow/provider action at its real proof quality.
It never fabricates a worker network-send edge.

A strict no-egress profile must either deny the writable relay object, govern
the delegate and join an exact request ID, or declare the semantic/contextual
gap. Packet capture in `FILE-DELEGATED-EGRESS-001` proves which component
actually emitted the packet.

### 18. Shared Authority, Memory, Files, Sockets, And Publication Races

Per-process policy alone is insufficient when processes share bytes or
capabilities. Mithril uses a bounded `AuthorityDomainStateV1`. Each process
keeps its own positive role. The domain shares only negative restrictions,
sensitive-state bits, response floors, and retained-generation constraints.
It never gives a converter the uploader's allow.

The domain is referenced by:

- execution-set/sandbox/volume bindings;
- live processes;
- live channels and shared objects;
- pending entries and joins;
- response plans;
- recovery/reconciliation holds; and
- publication reservations and persistent publication capabilities.

It can be reclaimed only after every typed reference is zero, inline
publication state is empty, complete iterators find no holder, and the grace
period passes. A Pod sidecar restart or zero-process interval does not reset a
shared `emptyDir`, network namespace, persistent socket, or volume domain.

#### Native descendants

Threads share one process state and domain. Version 1 also keeps every ordinary
fork descendant in the same monotonic authority domain, because ordinary fork
inherits open file descriptions, sockets, pipes, memfd, and shared mappings
even without `CLONE_VM|CLONE_FILES|CLONE_FS`.

Exec, `unshare`, fd close, or one member exit does not split/relax the domain;
copied secret memory or descriptors may survive. A future split requires
quiescing all members, enumerating/closing/relabeling every shared object,
installing new domains everywhere, complete readback, and atomic resume.

This baseline can over-restrict independent work. An operator may disable the
coarse information-flow claim, but may not claim equivalent prevention.

#### Independent container entries in one Pod

Initial app, sidecar, probe, lifecycle, and administrative entries may share
`emptyDir`, `/dev/shm`, IPC namespace, Unix sockets, and the Pod network while
having no native parent relation.

Before releasing the first user root, Mithril precomputes a communication
domain from exact Pod sandbox, volumes, mount backing objects, network/IPC
namespace, declared entries, and expected future entry slots. Every later exact
entry joins the existing domain at its held barrier. The durable scope spans
several execution sets and may outlive any one container.

Each channel chooses one prevention mode:

1. `DENY`: block creation/open/connect/attach/first operation.
2. `PRE_USE_CONSERVATIVE_DOMAIN_MERGE`: merge common negative restrictions
   before either participant can use the channel.
3. `SERIALIZED_TRANSFER_GATE`: only for a qualified boundary that owns every
   enqueue/dequeue and commits receiver restriction before bytes are delivered.

Object taint remains evidence unless every transfer race is closed. It cannot
be the Version 1 prevention baseline.

**Why object taint is insufficient.** A clean sidecar enters a blocking read
while a shared file/socket is clean. The converter marks it sensitive and
writes. The already-admitted read returns bytes without another pre-hook, and a
second sidecar thread sends before post-read taint. A faster BPF map does not
fix this. Prevention requires premerge or denying the channel.

**Unchanged Pod example.** Converter and uploader share `/work`. Their
positive roles remain different. Before either starts, the shared mount joins
their negative domain. Clean output can still be uploaded by the uploader's
own allow. When the converter is permitted/attempts a sensitive credential
access, the common domain atomically gains
`NO_PUBLICATION_AFTER_SENSITIVE_ACCESS`; the uploader's next public send
denies. If that blast radius is unacceptable, policy must deny the shared
surface or state prevention unsupported.

#### Local IPv4/IPv6 is also a shared channel

Containers sharing the Pod network can launder data over `127.0.0.1`, `::1`,
the Pod IP, wildcard listeners, UDP, reuseport, or redirected local services.
Version 1 premerges all admitted and expected execution sets sharing the Pod
network namespace before first release. A later sender's restriction applies
to another entry's external send without giving it the other entry's positive
destination allows.

Pre-resolving application listeners before roots run is impossible as a
general baseline and is abandoned. A future finer recipient tier must cover
bind/listen/accept/close, wildcard and reuseport membership, UDP recipient
sets, multicast/broadcast, NAT/hairpin, BPF redirect, io_uring/SQPOLL, and
recipient selection before enqueue. Until qualified, an unmerged dynamic local
channel denies its current operation; a crash-safe quiescent join can occur out
of band and the application retries.

#### Process memory, descriptor extraction, and signals

Cross-domain `process_vm_readv/writev`, ptrace, `/proc/<pid>/mem`,
`pidfd_getfd`, signals, and ptrace resume/control are data or authority
channels. Version 1 denies them unless a pre-use domain merge or exact declared
controller-target relation completes before effect. Target identity includes
task cookie, process-state ID/version, pidfd/start coordinates, boot, and label
epoch; PID alone is invalid.

A return hook cannot undo bytes already read or memory/registers already
changed. If the target cannot be pinned through the exact pre-effect operation,
strict policy denies or reports unsupported. Needed joins happen out of band
and require a new syscall.

A defender memory-read exception is a signed
`DEFENDER_READ_DECLASSIFICATION`: exact target, case/finding, read-only
operations, byte bound, evidence sink, approver, and expiry. A short-lived
measured inspector receives only an owner-opened classified target fd and one
fixed evidence-sink fd. Seccomp confines syscalls/fds; BPF LSM checks exact
target/case/budget on every read. No memory write, ptrace control, signal, fd
extraction, general socket, or arbitrary output is allowed.

#### Sensitive access changes the domain before allow

An LSM open/permission allow proves access was permitted, not that bytes were
returned. The safe bit is
`SENSITIVE_ACCESS_PERMITTED_OR_ATTEMPTED`, committed to the one domain value
before the sensitive hook returns allow. `SENSITIVE_BYTES_CONFIRMED` requires
complete positive-result coverage of every read/mmap/splice/io_uring path and
is not the baseline.

Sensitive bits and their restriction-set reference change together under the
domain lock and are monotonic for the complete domain lifetime. There is no
`clear_bits` operation. Missing transition row, set reference, or lock-stable
snapshot denies.

Secrets already in environment, restored memory, inherited fds, or existing
mappings may have no later read hook. Before releasing a domain, the binder
classifies declared secret/env delivery, mounts, inherited fds, restore state,
and mappings and presets `POTENTIAL_SENSITIVE_IN_MEMORY` when possession exists
or cannot be disproved. The honest choices are common restriction, denying the
secret/shared channel, a semantic transfer gate, or an unsupported claim.

#### Publication in flight must block new sensitive authority

A clean send decision alone does not prove clean bytes. After its pre-hook, a
send can block while a sibling reads a token and mutates the userspace buffer.
io_uring/SQPOLL can submit while clean and execute later.

Version 1 keeps bounded publication slots inline in the same locked authority
domain value:

```text
publication begin:
  build/read back exact immutable descriptor: actor, operation, request,
  bounded source plan, sink/flow, mutability proof, completion kind
  lock domain
  require no sensitive/publication-denying state and a free slot
  reserve unique instance, increment inflight count/ref and epoch
  unlock, read back ownership, then allow

sensitive access begin:
  lock same domain
  require inflight == 0 and no persistent writable publication capability
  install sensitive bits and stricter restriction set
  otherwise deny access with configured EAGAIN/EACCES

publication completion:
  match exact syscall/AIO/io_uring/zero-copy completion
  move slot INFLIGHT -> COMPLETING -> RELEASED_PENDING_ACK
  decrement once, acknowledge external lifetime, then make slot FREE
  duplicate/missing completion never decrements
```

Sources are closed variants: user buffer/iovecs/message batch, exact file
range, pipe buffer, or socket receive queue. Sinks are exact file, network
flow/final destination, or IPC object. `SCM_RIGHTS` and credentials are
separate authority transfers. Pointer/length wrap, N+1 iovec/message, mutable
unjoined file, missing source, incompatible operation/completion, or unknown
zero-copy lifetime denies.

For mutable sources, every writer is already in the same domain or a pre-use
join completed. A sealed memfd needs `F_SEAL_WRITE|F_SEAL_SEAL` and proof no
writable mapping predates sealing; `F_SEAL_FUTURE_WRITE` alone is insufficient.

Writable `MAP_SHARED` to output, shared/host/remote storage is a persistent
publication capability reserved before mmap returns. It remains until a held
full-domain VMA/object/writeback reconciliation proves all matching mappings,
faults, writeback, forked holders, and async work are gone. `munmap`, `msync`,
exec, exit, or origin-task death alone cannot clear it.

Every supported path—`writev`, `sendmmsg`, `sendfile`, `splice`, `tee`,
`vmsplice`, `copy_file_range`, AIO, io_uring, registered buffers/files,
SQPOLL, and zero-copy—needs a paired exact lifetime. Missing completion safely
leaks a restriction and degrades availability; it never guesses publication
ended. Unsupported setup/opcodes are denied for the full claim.

#### Persistent files and volumes

A linked regular file outlives fds and inode cache. Persistent file state is
owned by stable backing-volume/filesystem object generation. Rename/hardlink
preserves it; overlay copy-up and clone/copy attach restriction before the new
object becomes visible; unlink releases only after link count, open/VMA/async
I/O/writeback, and volume lifetime are all proven ended.

Cross-node RWX storage cannot rely on a reactive node-local taint. Node A can
crash before uploading its event while node B publishes. Version 1 uses a
signed, centrally committed `PersistentVolumeAuthorityV1` with portable
semantic restriction, storage generation, access mode, participant set, and
commit index. Every mount/root stays held until the node fetches the latest
non-rollback record, compiles the semantic restriction into a fresh local set,
joins the execution set, and reads the artifact/ref back.

Before any RWO/RWOP/RWX participant runs, a writable volume is marked
potential-sensitive when any participant could obtain protected material.
Every RWX node installs the common restriction before release. If an operator
rejects that scope, deny the mount or report cross-node publication prevention
unsupported.

Copy, reflink, `sendfile`/`splice` file copy, overlay copy-up, CSI
snapshot/clone, and backup/restore must propagate source authority before
destination visibility or be denied. Provider audit after restore is detection,
not prevention.

#### Joining two live domains is an out-of-band transaction

BPF cannot atomically merge several process/object maps. The triggering
channel operation is denied first and a persistent gate remains `DENYING`.
Rust builds a `PREPARING` combined domain with unioned negative state, then:

1. records per-old-root progress and installs combined-or-stricter floors one
   root at a time;
2. gates new channels, entries, async submission, and publication;
3. cancels/drains io_uring, SQPOLL, AIO, registered resources, and in-flight
   publication; freezes complete target sets and runs before/after iterators;
4. for every process, object, socket, pending entry, binding, response,
   persistent file/volume, and derived capability: acquire destination ref,
   CAS pointer, then release source ref, with owned bits for restart;
5. read back every root/target/ref; activate the combined domain; and
6. change the gate to `RETRY_ALLOWED`. A new operation re-resolves both ends.

A crash may leave one old root unchanged and another narrower. Safety does not
pretend the writes were atomic: the join gate remains denied and any member on
a non-active/new or draining root is fail-closed. Recovery resumes each exact
progress row; it never reopens the old authority.

### 19. Network, Sockets, DNS, And Encrypted Protocols

Network policy has two jobs: authorize socket/flow effects before they happen,
and fence existing/future packets during response.

#### Current actor and socket provenance both matter

A socket retains creator role/generation, accepted/creation provenance,
network namespace cookie/live interval, family/type/protocol, destination/flow
generation, response, and generation reference. Fork, fd passing, `setns`, or
`pidfd_getfd` does not move it to the current actor's network namespace or
transfer creator authority.

Each use evaluates:

```text
current actor role/process/domain and actor netns
intersect
socket creator/lifetime generation and socket netns/routing context
intersect
actual destination/flow and dynamic response floors
```

If a generation-42 socket is passed to a generation-43 role that denies its
destination, the send denies. Closing one fd does not end the socket; final
qualified kernel socket destruction or complete conservative reconciliation
releases the generation reference.

#### Every path has its own claim

| Path | Physical boundary | Honest result |
| --- | --- | --- |
| New TCP connect | BPF LSM `socket_connect` and/or cgroup connect4/6 after qualified rewrite ordering | Connection attempt denied |
| UDP connected/unconnected send | sender-time LSM plus cgroup sendmsg4/6 with actual peer | Datagram send denied |
| Established TCP send | sender-time LSM where qualified; packet fence for response | Send call denied or later packets dropped—stated separately |
| Inherited/passed/preconnected socket | sender-time current actor plus socket storage | Unauthorized current use denied |
| Existing contained flow | TC/cgroup-skb/socket destroy as qualified | Subsequent packets fenced; connection may have existed |
| Receive | `socket_recvmsg` or protocol-specific qualified pre-copy point | Caller receives errno and zero marker bytes; packet may remain queued |
| Raw/packet/TUN/AF_XDP/RDMA/vsock/netlink/SCTP/MPTCP | deny creation or qualify every secondary path | Only named tested path |

Connect hooks do not fence an established flow. Cgroup UDP send hooks are not a
general TCP-send hook. Packet hooks may not have a meaningful current task and
therefore use socket/cgroup response state installed earlier.

`socket_create` can decide family/type/protocol before the socket exists but
cannot label the completed object. A qualified post-create/first-object hook
must install socket storage before bind/connect/send. Accept needs a
protocol-specific post-clone/graft label before the accepted child can be used;
pre-return `security_socket_accept` alone is insufficient. Socketpair labels
both ends. Missing identity denies first protected use.

Socket controls such as `SO_MARK`, `SO_BINDTODEVICE`, transparent/freebind,
attached BPF, reuseport/fanout, MPTCP/TCP ULP, routing netlink, ioctl, and
compat variants are separate effects. Pointer-valued options are not
dereferenced from mutable userspace for authorization; fixed semantic value
classes need target-specific post-copy hooks, otherwise deny the option.

Full “no undeclared egress” support denies every unneeded family at create or
qualifies its entire path, including subflows/multihoming, tunnels, redirection,
io_uring and SQPOLL. One TCP connect and UDP send test is not full coverage.

#### Shared socket response

Two lineages may share one TLS socket. Sender-time checks can deny new calls
from one lineage, but queued bytes/retransmissions cannot reliably be separated
at packet hooks. Response must fence/destroy the whole socket/flow and disclose
impact to every sharing lineage, or report per-lineage packet containment
partial/unsupported. It never attributes a retransmitted packet to one process
from packet-hook `current`.

#### Destination identity and rewrite order

DNS name is evidence, not destination identity. Policy records query/answer,
TTL, CNAME, netns, and socket time, then enforces actual address/prefix/service
identity. Literal IP, stale DNS, IPv6, private endpoint, and alternate
interface cannot bypass.

Cgroup/CNI/mesh BPF, NAT, transparent proxy, or redirect may rewrite the
original destination. Mithril inventories and reads back program/link digest,
attach mode, and order. A broad claim requires exclusive ordered chain, a
post-rewrite deny point, or a final packet fence on actual destination. Unknown
or changed order closes coverage before strict admission.

`NET-REWRITE-001` starts with an allowed address and rewrites it to IMDS or a
denied public address before/after Mithril. The final packet must be absent;
checking only the original sockaddr fails.

#### DNS can exfiltrate

Allowing port 53 to the cluster resolver still lets a secret be encoded in
query names. A role selects:

```text
NO_RUNTIME_DNS_SIGNED_SERVICE_ADDRESSES
SEMANTIC_RESOLVER_GATE
DESTINATION_ONLY_WITH_PAYLOAD_GAP
```

The semantic gate is an owned resolver boundary, not TLS interception. It can
limit tenant, exact/suffix qname, type, response/CNAME, size, rate, cardinality,
and request ID while denying direct alternative resolvers. Destination-only
mode must state `DNS_PAYLOAD_SEMANTICS_UNENFORCED`.

DoH, DoT, and HTTP CONNECT inside an otherwise allowed TLS service remain
opaque unless their endpoints are denied or the service exposes typed
admission/audit.

#### No TLS interception and semantic limits

Mithril does not terminate direct TLS. Linux can allow an email endpoint and
deny GitHub, or allow separately issued credentials/endpoints/processes. It
cannot distinguish email send from another API verb on the same allowed TLS
channel, or `git clone` from `git push` when process, host, port, connection,
and bearer token are identical.

For verb-level prevention, use the real provider's capability or synchronous
semantic gate: for example a GitHub App installation token with provider-
supported read permissions. An arbitrary write-capable bearer token cannot in
general be locally transformed into a narrower token. Without a distinct
capability/gate, policy must deny the channel or allow it and use provider audit
for later detection/response.

### 20. Devices, Ioctls, And Derived Kernel Capabilities

Device policy is three intersecting decisions:

```text
cgroup-device floor: type + major/minor + mknod/read/write
file/device object: current role + exact device + open/read/write/mmap/poll/async
ioctl/control: current role + exact device + native/compat ABI + command
```

Cgroup-device BPF governs creation/access to the device node. It does not
re-authorize operations on an already-open or passed fd. BPF LSM file/ioctl and
target-specific hooks cover use by the current actor. Pointer-valued ioctl
arguments are not safely dereferenced as mutable user memory; command-level
allow/deny or a qualified kernel semantic hook is required.

Preopened, inherited, duped, `SCM_RIGHTS`, and `pidfd_getfd` device fds retain
exact object/acquisition provenance. Read/write, mmap data/exec, poll, async
submit, io_uring/SQPOLL, and descriptor receipt are separate coverage rows. If
poll lacks a physical decision point, strict policy must deny fd acquisition
or the syscall via a launcher floor, or report use coverage unsupported.

Some ioctls mint new anonymous capability fds: KVM VM/vCPU, DRM/GPU contexts,
perf, io_uring, FUSE, and similar. A target-qualified post-return/driver point
must label the returned object before another task can use it, recording parent
device/capability, creator role/generation, command/result, class, live
interval, retained generation, and response state. Otherwise Mithril may allow
or deny minting as a whole but cannot claim granular post-mint control.

**Examples.** Denying `/dev/net/tun` open or its TUN command prevents an
unapproved mesh interface even if the binary is present. A GPU sidecar passing
`/dev/nvidia0` to the worker does not give all ioctls; the receiver's role may
use only qualified inference commands. A passed KVM vCPU fd remains a derived
KVM object after creator exit and fd-number reuse.

### 21. Privilege, Kernel Escape, And Self-Protection

“Deny privilege” is not one hook. The platform manifest has one row and
physical fixture per operation family:

- UID/GID/groups, fsuid, capabilities, ambient/bounding/securebits,
  `no_new_privs`, setuid/file-capability exec;
- ptrace, process-vm, proc-memory, signals, pidfd control, process release;
- clone namespace flags, `unshare`, `setns`;
- chroot, pivot, mount/remount/bind/propagation, old and new mount APIs,
  idmapped/recursive `mount_setattr`;
- BPF map/program/link/token/fd-by-ID and bpffs pin/update/detach;
- perf, tracing, debugfs/tracefs/securityfs;
- kernel/module/firmware load, reboot, kexec, crash paths;
- keyrings;
- io_uring setup/register, SQPOLL, override credentials and uring commands;
- cgroup controller files, task moves, freeze, kill, subtree control;
- sysctl and `/proc/sys`, sysrq, kcore, kallsyms, proc task-control objects;
- hostname/domain/time namespaces and clocks;
- dumpability, ptracer, core pattern and coredump helpers;
- fanotify, userfaultfd, delegated perf/BPF/io_uring fds; and
- replacement/mount-over of `mithril-node`, runtime/shim, config, unit,
  admission socket, BPF links/maps, and bpffs roots.

Each row names all syscall/API/compat variants, a qualified pre-effect hook or
seccomp/capability/lockdown floor, and a physical oracle. A new or unmapped
variant is denied/unsupported, never assumed covered by a similar older call.

Runtime setup is the legitimate negative control. Its signed ordered budget
may perform the exact UID/GID/group changes, capability drops, securebits,
`no_new_privs`, namespaces and mounts required by that runtime build. Changing
one UID, adding one group, reordering beyond allowed variants, reading a
mounted token, or adding a device/network effect fails start.

#### Seccomp facts

Ordinary installed seccomp cannot be weakened or detached by the task; the old
idea “detect a task weakening its filter” is factually wrong and abandoned.
Mithril instead verifies pre-run installation and governs dangerous new user-
notification or ptrace/TRACE supervisor relationships.

`/proc/<pid>/status` shows mode/count, not arbitrary filter bytecode. Proof is:

```text
INSTALLER_ATTESTED: held trusted launcher hashed and installed exact bytes,
                    then mode/count/TSYNC scope were read back
KERNEL_OBSERVED: qualified kernel path proves exact installed identity/content
PRESENCE_ONLY: some filter exists; digest is not proved
ABSENT: no floor claimed
```

Correct and wrong filters can have the same mode/count. Only the first two may
prove exact rules. Partial TSYNC, wrong bytecode, install failure,
`NEW_LISTENER`, USER_NOTIF, and TRACE are fixtures.

Seccomp cannot authorize `/proc/<target>/mem` by pathname: it cannot safely
dereference and authenticate the userspace pointer. The defender inspector
uses an owner-opened fd plus seccomp fd/syscall confinement and BPF exact target
checks as described above.

#### Landlock facts

Landlock ABI and handled rights are measured on the actual node. Filesystem,
device ioctl, TCP/UDP, pathname/abstract Unix socket, and signal rights vary by
ABI. A held runtime launcher may install a monotonic floor before exec. If the
seam is absent or ABI lacks a right, Mithril records that layer absent and
evaluates BPF coverage independently.

Landlock does not replace BPF LSM for multiple independently admitted roots,
same-container role differences, cross-process domains, dynamic response,
exact cgroup/runtime identity, devices/privilege families outside its ABI, and
correlated evidence.

#### Self-protection and root compromise

`SELF-PROTECT-001` attacks `mithril-node`, kubelet, runtime/shim, admission
socket, cgroups, BPF links/maps/pins, binaries/config, mount points, reboot and
kexec from a privileged/hostPID task. Each hard floor has its own errno and
readback oracle.

If only userspace dies, pinned BPF may keep enforcing its proven local tables
while new userspace-dependent admission fails closed; evidence/WAL coverage is
degraded. If a required BPF link/map/runtime boundary is altered, that axis
becomes tampered/unknown before any later claim. Provider controls and remote
response remain separate boundaries; root UID alone is not assumed either
harmless or omnipotent without measuring actual lockdown/capability/integrity.

## Part V — Evidence, Multi-Node Causality, And Verified Response

### 22. What One Observation Proves

Prevention is not enough. An action may have been allowed, predate attachment,
use an existing encrypted channel, happen at a provider, or start outside the
node. Mithril normalizes every source into one versioned envelope:

```text
ObservationEnvelopeV1 {
  tenant and deterministic observation ID
  source ID, epoch, sequence, and stable provider event ID if available
  optional node boot/CPU
  hook or adapter and ABI/schema version
  optional pinned policy generation
  boot time and projected UTC with uncertainty
  ingestion time
  bounded typed payload
  ProofQualityV1
  coverage interval ID
  transport/signature/batch integrity
}
```

The observation ID is a digest of canonical tenant/source/sequence/schema /
payload data. Stable provider IDs deduplicate redelivery. Ad hoc unwrapped
events are not package inputs.

#### Coverage is recorded as time intervals

Kernel sources keep per-CPU, per-hook counters:

```text
attempted = suppressed + requested
requested = emitted + lost
```

`attempted` increments before deciding whether rich evidence is requested.
`suppressed` is intentional policy sampling; it is not loss. Classifier misses
have their own counter.

First loss, counter inconsistency, detach, clock reset, source-epoch change, or
unknown link/map health closes the healthy interval and opens `GAPPED` or
`UNKNOWN`. Recovery reads back mechanisms and runs an isolated controlled
probe, then opens a new healthy interval. It never rewrites history.

The local WAL tracks a contiguous acknowledged range per source epoch. Data is
truncated only below a durable contiguous acknowledgment. If restart cannot
prove prior sequence/interval state, it starts a new epoch with an explicit
gap.

Coverage is a vector, not one boolean:

```text
enforcement: required hook/map physically active?
identity: task/process/entry/object attribution complete?
observation: required event sequence complete?
admission: runtime/semantic gates healthy?
correlation: required remote source and watermark healthy?
response: actuator and postcondition source healthy?
```

Pinned BPF can therefore be `ENFORCING` while userspace event/WAL coverage is
gapped. A healthy collector can be `OBSERVING` while a deny hook is absent.

**Loss fixture.** Force requested sequence 901 to fail ring reservation between
900 and 902. The token open remains physically denied; observation coverage
across 901 is gapped; restart preserves that gap. A package requiring the event
returns `COVERAGE_INSUFFICIENT`, not “no credential access.”

#### Proof quality has independent axes

```text
ProofQualityV1 {
  source_authority:
    KERNEL_DECISION | SIGNED_COORDINATOR | AUTHORITATIVE_PROVIDER |
    AUTHENTICATED_MEASUREMENT | UNAUTHENTICATED
  local_subject_binding:
    EXACT_TASK | EXACT_PROCESS | EXACT_EXECUTION_SET | CONTEXTUAL | NONE
  remote_subject_binding:
    EXACT_REQUEST | EXACT_SESSION | EXACT_OBJECT | PRINCIPAL_ONLY |
    CONTEXTUAL | NONE
  operation_result_authority:
    PRE_EFFECT_DECISION | AUTHORITATIVE_SUCCEEDED | AUTHORITATIVE_DENIED |
    OBSERVED_ATTEMPT | CONTEXTUAL | UNKNOWN
  temporal_coverage: COMPLETE | GAPPED | UNKNOWN
  integrity: SIGNED | AUTHENTICATED_CHANNEL | LOCAL_ATTESTED | UNVERIFIED
}
```

There is no global `sourceQualityAtLeast`. CloudTrail can be authoritative
about a successful AWS operation and exact assumed-role session while two
local processes share the session. That permits session-scoped response; local
task binding remains contextual.

The short labels `exact`, `conservative`, `contextual`, and `unknown` remain
human summaries. Policy matches explicit axes. Intent classification is a
separate value: `EXACT_TARGET`, `SAME_BUDGET_AMBIGUOUS`, `AMBIGUOUS`, or
`UNKNOWN`.

#### Deterministic windows and findings

Each correlation package declares required sources/coverage, maximum lateness,
retention, time-uncertainty limit, exact and contextual join fields,
suppression, and late-event behavior.

Events can arrive in any order. Source watermarks use projected-time
uncertainty and maximum lateness; time never creates an exact edge. Package
state is keyed by canonical subjects. Duplicate observations are idempotent.

Findings are immutable revisions:

```text
FindingV1 {
  deterministic finding ID(package, version, subject, window)
  revision
  PROVISIONAL | CONFIRMED | SUPERSEDED | RETRACTED |
    COVERAGE_INSUFFICIENT
  window and graph version
  sorted evidence and required coverage IDs
  superseded revision and closed reason code
}
```

Late evidence appends a revision; it never edits old evidence. Replaying the
same observations in every delivery order must produce byte-identical terminal
revisions. “Outside baseline” means outside a named signed baseline digest,
not merely rare.

### 23. How Causality Crosses Nodes And Providers

The local graph has real native creator/fork/exec edges. A remote task never
becomes a Linux child of a task on another node.

#### Three core detection packages

`HF-PROC-001` explains a local denial or audited role deviation. It requires
complete task/entry identity and attaches native ancestors, entry, executable
object, workload/cgroup, generation, state, hook, decision, physical errno,
and coverage counters. If identity is incomplete it emits a lineage coverage
gap, not a proven malicious edge.

`HF-DW-001` connects credential access/lease to authority use. An exact path
needs the same task/process/socket/lease proof plus authoritative remote result.
Workload, ServiceAccount, IP, principal, and time alone produce a contextual
hypothesis and cannot authorize credential-specific narrow response.

`HF-XNODE-001` expands Kubernetes actions:

```text
node-A task/socket/credential
  -> Kubernetes request (only exact with carried request/lease proof)
  -> audit ID and authoritative API result
  -> object UID/resourceVersion
  -> controller/owner/scheduler chain
  -> Pod UID and node binding
  -> node-B runtime admission with Pod UID/full container ID
  -> node-B entry and Linux execution
```

Stock Kubernetes audit ID belongs to the API server; it does not identify a
Linux task. Two local processes sharing one ServiceAccount can create two Pods
concurrently. Without a unique carried nonce/lease, both task-to-request joins
stay contextual. Policy may authorize containment of the whole credential or
workload scope, but not an invented exact task.

#### Canonical graph

A subject ID is a digest of tenant, kind, authority, and immutable identity.
Subjects include task, process, execution set, socket, request, lease,
Kubernetes object, provider object, artifact, CI run/job/step, and others.

An edge contains exact endpoint IDs, registered edge type, package/version,
sorted evidence, proof vector, required coverage, and
`DIRECT|CONTEXTUAL|CONTRADICTED|SUPERSEDED`. Edge ID is deterministic.
Stronger evidence appends a direct edge superseding a contextual one;
contradictory authority evidence appends a contradiction and recomputes
dependent findings.

The graph may contain cycles from retries, ownership, sessions, and artifact
reuse. Traversal is bounded by tenant, allowed edge types, time/validity,
package depth, and visited subjects.

Each incident branch is independently:

```text
OPEN | TERMINAL_VERIFIED | CONTEXTUAL_ONLY |
OUTSIDE_AUTHORITY | COVERAGE_UNKNOWN
```

One offline node stays `COVERAGE_UNKNOWN` while other branches continue. A
controller retry creating three Pod UIDs creates three runtime-root branches,
not one name-based branch.

#### Direct provider edges require a registered contract

An identifier is exact only between the endpoint kinds for which its authority
guarantees uniqueness. Every provider edge registers source kind, endpoint
kinds, equal fields, uniqueness scope, request/result fields, coverage, proof
vector, missing-field behavior, and a shared-identity negative fixture.

Examples:

| Edge | Direct proof | Limit |
| --- | --- | --- |
| AWS lease -> operation | Same account/partition and access-key or assumed-role session ID plus provider event/request ID and authoritative result | Does not name one Linux task if the key/session was shared. |
| Kubernetes request -> object version | Cluster, audit/request UID, verb/resource/object UID/resourceVersion and authoritative result | Does not name the local process without carried proof. |
| Local lease -> Kubernetes request | Unique token `jti`/fingerprint exposed by both sides or broker-forwarded request nonce | Shared ServiceAccount name is insufficient. |
| GitHub lease -> operation | Installation/App/repository scope plus documented attribution and operation/delivery ID | No undocumented token-mint audit event is invented; shared token does not name local requester. |
| Connector invocation -> provider request | Connector owns invocation ID and forwarded destination request ID; provider confirms result | Shared connector principal/time is contextual. |
| Artifact -> consumer slot | Provider artifact version, immutable digest, exact one-use consumer slot | Name/cache key/tag/URL is insufficient. |
| Message publication -> consumption | Broker/cluster/topic/partition and immutable message ID/offset plus digest where supplied | Shared producer credential does not identify one task. |

Each fixture runs concurrent clients with a shared principal while only one
has the unique request/lease/message join. Only that branch becomes direct.

### 24. Response Is An Authorized Physical Transaction

A graph subject is not an actuator handle. Before doing anything, response
freezes one graph version and branch set, obtains authorization, and re-resolves
the exact live target at the authority that owns it.

#### Local lineage response

The response target includes node boot, label epoch, process lineage and
instance, task cookie/pidfd/start coordinates, execution set, cgroup binding,
Pod/container live interval, requested effect restrictions, socket fence,
expiry, and authorization.

Each process points to an immutable effective response set. An allowed fork
inherits it at task allocation in O(1); response is not limited by walking a
bounded ancestor list. Existing descendants are initially matched by verified
ancestry, then a complete task iterator upgrades each process. If an existing
branch exceeds qualified ancestry and cannot be enumerated, exact-subtree
response is unavailable; propose an approved broader cgroup fence/freeze or
report unknown. Response-set capacity exhaustion fails closed; it never drops
an older restriction.

Response restrictions are independent of workload-policy generations. A
policy update cannot make containment disappear.

#### Production verification does not inject hostile probes

Controlled file/exec/socket/device probes run in isolated qualification
fixtures, never an arbitrary compromised production process.

Production checks are non-invasive:

| Action | Physical postcondition |
| --- | --- |
| Lineage restriction | Response set and exact target map state read back; every current descendant reconciled or a named broader fence verified; hooks/maps healthy. A later real attempt may add errno evidence. |
| Socket/packet fence | Exact socket/cgroup keys and program generation read back; preexisting sockets enumerated; packet-drop/socket-destroy counters tied to fence. |
| Cgroup freeze | Exact live cgroup reports `frozen=1`; task membership reconciles. Silence alone is not execution proof. |
| Kill/signal | pidfd target revalidated and exact process exit confirmed; restart/replacement branches remain open. |
| Provider response | Authoritative provider readback or a separately authorized benign canary; audit silence is only quiet-window evidence. |

#### Durable response lifecycle

```text
PROPOSED -> AUTHORIZED -> REVALIDATING -> APPLYING -> VERIFYING -> WATCHING
  -> VERIFIED | PARTIAL | FAILED | UNKNOWN | EXPIRED | CANCELLED
```

Every compare-and-swap transition stores prior revision, actor, UTC,
node-boottime/deadline where applicable, reason, and per-action idempotency key.
Cancellation stops future transitions but does not erase already applied
actions.

- `VERIFIED`: every requested action in this revision passed its physical
  postcondition and required coverage stayed healthy through the watch.
- `PARTIAL`: at least one verified and another failed, expired, outside
  authority, or unverifiable.
- `FAILED`: authority postconditions prove none achieved the intended state.
- `UNKNOWN`: evidence/coverage/authority cannot establish the result.
- `EXPIRED`: approval or monotonic deadline elapsed before the next irreversible
  step; completed effects remain recorded.
- `CANCELLED`: an authorized actor cancelled future work; applied effects remain.

A replacement Pod or late remote branch produces a new plan revision. The old
revision may remain verified for its frozen scope; the incident returns to
watching/partial until the new branch resolves.

#### Blast radius is part of authorization

Killing a shared interpreter can interrupt many logical jobs. Freezing a Pod
affects every container. Revoking a shared credential affects all holders.
Fencing a shared TLS socket affects every process using it. A common authority-
domain response affects converter, uploader, later lifecycle/admin roots, and
shared objects in that domain.

Before approval, Mithril re-resolves and enumerates all known affected
participants and exact lost effects. If an existing socket needs a separate
packet fence, it is a separate action. The result is named
`SHARED_AUTHORITY_DOMAIN_RESTRICTION`, not process-only. If the operator does
not authorize that scope, Mithril may apply a separately proven narrower
object/socket action or report partial; it cannot silently use the broad one.

#### Distributed response

```text
fence the locally proven seed when preauthorized
enumerate every open branch and the authority that owns it
create one typed action per node/controller/provider/object
obtain target-specific approval and revalidate
apply idempotently
watch replacements and late evidence
verify every physical postcondition under healthy coverage
```

Process kill alone is not containment when kubelet restarts the container, a
controller replaces the Pod, a remote node remains active, a credential still
works, or an artifact/mesh/connector/source-control branch exists. Offline,
outside-authority, contextual-only, or unverified branches force `PARTIAL` or
`UNKNOWN`.

## Part VI — The First Complete Proof Package: Hugging Face And CI/CD

### 25. Every Published Hugging Face Incident Step

The incident is the first full product acceptance package, not Mithril's
definition. The source facts are the
[detailed incident analysis](../../research/hugging-face-agent-intrusion-analysis.md)
and the
[normalized 21-event stream](../../research/hugging-face-agent-intrusion-live-action-stream.md).
The 21 events summarize a much larger action record; granular fixtures below
cover important actions published outside that summary.

The algorithm names used here are:

| Name | Exact owner |
| --- | --- |
| `ALG-INTENT` | Signed intent, replay protection, and exact one-use claim |
| `ALG-ENTRY` | Held runtime/root admission and role assignment |
| `ALG-LINEAGE` | Fork/thread/exec identity and transition |
| `ALG-FILE` | Mount-aware object and file/mapping decision |
| `ALG-NET` | Current actor + socket provenance + destination/flow decision |
| `ALG-DEVICE` | Device, ioctl, capability, namespace, mount, BPF, perf, ptrace, and other privilege effects |
| `ALG-AUTHORITY` | Kubernetes/cloud/mesh/connector/source-control semantic gate or authoritative audit package |
| `ALG-ARTIFACT` | Immutable producer, bytes, trust, handoff, load, execute, and deploy edges |
| `ALG-XNODE` | Typed cross-node/provider graph; never remote process parenthood |
| `ALG-RESPONSE` | Target re-resolution, authorized actuator, readback, physical postcondition, and watch |

#### Complete operator and implementation map

| Event | Published action | Strict Mithril result | Exact implementation and honest limit |
| --- | --- | --- | --- |
| `HF-001` | Root shell in an external evaluation sandbox | Hugging Face estate records `OUTSIDE_AUTHORITY`; it cannot locally deny. A separately Mithril-protected evaluation estate may reject the root or deny shell exec. | `ALG-ENTRY/LINEAGE` runs only where installed. The graph creates an external subject with no fake native parent or `prevented` result. |
| `HF-002` | Identity, environment, mount, cgroup, filesystem, and process reconnaissance | External branch remains context. On a managed task, deny undeclared diagnostic exec and exact proc/host/credential objects. | `ALG-LINEAGE` decides the helper; `ALG-FILE` resolves exact proc target/mount. Already resident environment has no new file effect; the next publication is the control. |
| `HF-003` | Bundled/fallback `curl`, `nc`, `ip`, or other tools | Deny executable objects absent from the role; an approved diagnostic tool remains destination- and effect-restricted. | Immutable executable identity, not `$PATH`, basename, copy, or rename. `ALG-NET` still governs the tool's socket. |
| `HF-004` | Publish environment/secrets to public capture endpoints | Managed unapproved destination: deny connect/send and prove no packet. Required/opaque channel: alert only what source/result proves. | `ALG-NET`; sensitive domain state can narrow later egress. An allowed TLS event without content oracle is `PAYLOAD_UNOBSERVABLE`, not confirmed secret exfiltration. |
| `HF-005` | Execute staged Python disguised as a source file | Deny only when exact object/content provenance already classifies the bytes as untrusted code, or deny its next prohibited effect. | Filename `.c` is no proof. `ALG-ARTIFACT` binds download/CAS/IMA/fs-verity/held-content identity; in-process Python interpretation has no exec hook. |
| `HF-006` | gzip/base64/chunk payloads in memory | Pure CPU computation proceeds; first prohibited file/code-map/exec/send/provider boundary is controlled. | No algorithm invents a packing syscall. Heuristic observation may raise finding priority but cannot claim prevention. |
| `HF-007` | Search public code/platform APIs for infrastructure names | External evidence is contextual/provider evidence. Managed undeclared destination is denied; documented service query may alert. | `ALG-NET` owns destination; `ALG-AUTHORITY` owns a real audited query. Similar text/time is not causal identity. |
| `HF-008` | Hostile HDF5 external-file reference reaches the conversion worker | Deny any target outside admitted dataset/runtime/scratch/output objects before bytes reach HDF5. Optional upload scanner may separately reject the artifact. | `ALG-FILE` on the existing Python task; actual mount/inode/proc object defeats `../`, symlink, bind, and `/proc/*/fd` aliases. No new process is required. |
| `HF-009` | Worker environment/secrets/source/context disclosed through result or network | Deny observable proc/token/source reads and undeclared publication. In-memory environment read is unobservable; next file/socket/provider effect is decided. | Separate file results from publication results. Without a content oracle, normal and secret-shaped payloads over the same allowed TLS schema stay indistinguishable. |
| `HF-010` | Jinja expression executes Python in the existing worker | Do not claim “Jinja denied.” Deny the first prohibited exec/file/network/device/privilege effect of that already labeled process. | `ALG-LINEAGE` sees no new task. `ALG-FILE/NET/DEVICE` receive exact worker identity. Pure arithmetic is intentionally unclassified. |
| `HF-011` | Projected ServiceAccount token and namespace files opened/read | Conversion role gets `EACCES`; exact controller role may read and acquires a common sensitive restriction. Token bytes never enter evidence. | `ALG-FILE` uses rotating projected-volume semantic item. Open attempt, fd opened, positive bytes read, and provider credential used are separate results. A preloaded token shifts control to later effects. |
| `HF-012` | Probe Kubernetes API, DNS/EKS endpoints, and cloud IMDS using DNS and hard-coded IPv4/IPv6 | Conversion role denies every API/IMDS destination at connect/send. Legitimate controller channel is allowed; forbidden verbs/resources alert or reject at the real semantic boundary. | `ALG-NET` uses actual final address/netns; `ALG-AUTHORITY` uses Kubernetes/AWS result. TLS verb is never inferred from packets. |
| `HF-013` | Use a dataset repository and leaked write token as dead-drop | Distinct write endpoint/lease/process: deny or semantic reject. Same endpoint/credential/TLS as required read: provider-confirmed write alerts and exact immutable revision is quarantined. | `ALG-NET` cannot distinguish clone from push. `ALG-AUTHORITY/ARTIFACT` use repository operation/result and digest/revision. No bearer token inside TLS becomes a kernel selector. |
| `HF-014` | Reach mesh control and establish mesh capability from a compromised node | Before trust loss: deny mesh executable, TUN/ioctl, namespace/capability, or control destination independently. Audit after enrollment is detection. | `ALG-LINEAGE/DEVICE/NET`. If root tampers with required runtime/BPF/CNI and integrity cannot prove them intact, local coverage becomes `ENFORCER_TAMPERED_OR_UNKNOWN`; rely on independent mesh/upstream response. |
| `HF-015` | External sandbox devices enroll into corporate mesh with stolen key | Mesh semantic admission may reject. Audit-only: alert; revoke key for future joins and remove each existing device separately. | `ALG-AUTHORITY/RESPONSE`; local BPF cannot control external hosts. Exact device/key/session subjects remain outside node authority. |
| `HF-016` | Worker reaches internal connector catalog and obtains cluster context | Worker-to-connector destination denied; typed connector gate may reject catalog request; audit-only alerts exact request/result. | The published connector request was direct inside the cluster, not through mesh. `ALG-XNODE` keeps direct connector and mesh branches separate. Shared `system:masters` creates explicit cluster-A and cluster-B authority branches. |
| `HF-017` | Harvested AWS credentials used externally and from the worker | External replay: provider detection/response only. Worker-local STS/database/raw-exfil destinations: local deny where distinguishable. | `ALG-AUTHORITY` binds exact access-key/session operation but not one Linux reader of a shared key. `ALG-NET` separately controls worker sockets. Provider timeout is not Mithril prevention. |
| `HF-018` | Connector/GitHub mints write-capable App tokens, enumerates repos, attempts CI-triggering PR | Typed broker/provider gate may reject. Audit-only alerts supported downstream operations; protected token handle can self-revoke, otherwise broader repo/installation response or expiry watch. | `ALG-AUTHORITY/ARTIFACT`. Standard GitHub audit must not invent a token-mint event. Token hash/fingerprint is correlation, not the bearer secret needed to revoke itself. |
| `HF-019` | Fresh external sandboxes re-fetch and execute public loader | Managed node denies loader destination, code load/map, exec, memfd/deleted image, or anonymous executable memory. External sandboxes remain outside authority. | `ALG-NET/FILE/LINEAGE`; same-byte edge needs trusted content oracle. URL/name alone is contextual. |
| `HF-020` | Staged binary and host/process state inspected | Managed exact lineage: deny proc/sys/debugfs/host, ptrace/perf/BPF/device/mount/namespace and unapproved staging. External exact: outside authority. Missing location: unresolved. | `ALG-FILE/DEVICE`; `readelf`/hostname text and time cannot choose a location. Only managed exact case receives local errno or kill eligibility. |
| `HF-021` | Defenders cut access and recovered activity stops | Run typed local, controller, mesh, connector, credential, cloud, repository, artifact, and provider response; watch replacement/late branches. Silence never means contained. | `ALG-RESPONSE` requires postconditions and healthy source watermarks. Any outside, offline, contextual, or coverage-gap branch keeps result partial/unknown. |

#### The earliest production block: `HF-008`

The conversion worker may read only exact admitted dataset files, reviewed
runtime/library objects, and declared scratch/output. Hostile HDF5 metadata
resolving to proc environment, projected token, another process/Pod, host file,
device, or outside mount produces:

```text
actor: exact existing conversion process and entry
effect: OPEN_READ
object: fully resolved live mount/file/proc target
decision point: qualified BPF LSM file hook
result: -EACCES
oracle: no fd/protected byte and no protected bytes in conversion output
```

The dataset-to-worker edge is exact only if the service provides immutable
revision/dispatch identity. With many jobs in one process and no application
job event, Mithril reports the exact process/object but does not guess which
logical job caused it. Response may restrict the interpreter and must disclose
the multi-job impact. Quarantining one revision needs exact repository proof.

#### `HF-009` and `HF-011`: use exact result words

File access and publication are different actions:

| Result | Required oracle |
| --- | --- |
| `FILE_OPEN_PREVENTED` | Pre-effect deny plus matching syscall result/no fd |
| `FILE_ACCESS_ATTEMPT_ALLOWED` | Exact pre-effect allow; no claim that fd/bytes followed |
| `FILE_DESCRIPTOR_OPENED` | Same open attempt completed with nonnegative new fd and fd->object readback |
| `SENSITIVE_BYTES_READ` | Exact qualified positive-byte completion for that task/fd/path; mmap has its own path |
| `PROVIDER_CREDENTIAL_USED` | Authenticator/provider proves exact credential lease/fingerprint/request operation |
| `SEND_ATTEMPT_ALLOWED` | Exact local send admission; packet/result not implied |
| `PACKET_EMITTED` | Packet boundary proves transmission |
| `PUBLICATION_OBSERVED` | Authoritative repository/service result |
| `SUSPECTED_SENSITIVE_PUBLICATION` | Publication follows exact observable sensitive access in causal order; bytes not matched |
| `CONFIRMED_EXFIL` | Authorized content/provenance oracle matches protected and published bytes without storing secret |
| `PAYLOAD_UNOBSERVABLE` | Channel/result is known, but encrypted/in-memory content meaning is not |

`HF-011-READ-RESULT-001` covers zero-byte read, EOF, `EIO`, partial positive
read, mmap, inherited fd, io_uring, token already in memory, failed send,
emitted packet, and provider-confirmed publication. No boundary borrows the
result word of another.

#### `HF-012` through `HF-018`: remote authority stays separate

For every remote action, record:

```text
local Linux action if one exists
provider/connector request and result
join proof between them
coverage for both sides
```

A local socket deny can prevent a Kubernetes or IMDS request. An allowed TLS
connection cannot prove its verb. Provider audit can prove a successful verb
but may not name the local task. Only a carried nonce, unique lease, broker
request, connector forward ID, or another registered edge makes that join
direct.

The connector branch is specifically:

```text
worker -> direct internal connector request
       -> connector returns cluster A and B identities/shared authority
       -> each cluster records its own credential use
```

It is not:

```text
worker -> mesh device -> connector
```

unless mesh/connector request evidence proves that separate branch. Catalog
exposure, credential validity, credential use, and local-request cause are four
different edges. With no forwarded ID, cluster actions remain authoritative
but local cause is `CONTEXTUAL_SHARED_AUTHORITY`.

For AWS, external replay and worker-local STS/database/raw exfil are also two
branches. A `DryRun=True` response is
`ATTEMPTED_AUTHORIZATION_CHECK`, not completed mutation. Exact final provider
resource state is the oracle.

For GitHub, a broker mint record may include App, installation, repositories,
permissions, result, lease, and protected token handle. Standard audit-only
mode marks mint detection unsupported unless the configured schema documents
it. A token hash cannot call “revoke current token”; the raw protected handle
can. Installation suspension is wider and must say so.

#### Granular hostile acceptance fixtures

The published technical timeline includes actions more specific than the 21
summary events. These are mandatory cards, not optional examples:

| Fixture | Concrete attack | Required result |
| --- | --- | --- |
| `HF-GRAN-DEAD-DROP-001` | Return command output through normal result/dataset API | Sensitive-domain send denies before marker when channel can be restricted; same required opaque channel reports payload unobservable/provider result. Clean conversion output succeeds. |
| `HF-GRAN-HOSTPATH-001` | New privileged/hostPID Pod mounts host `/` with dangerous capabilities | `REJECT_UNMATCHED` or hard-floor runtime rejection before host mount/user marker. Exact signed CSI/host agent exception is positive control. |
| `HF-GRAN-RESPAWN-001` | Self-respawning Pods fan out across eleven nodes | Semantic admission rejects before persistence, or every node runtime gate holds/rejects roots; already-running roots receive verified fences; no replacement marker during watch. |
| `HF-GRAN-CONNECTOR-DIRECT-001` | Worker reaches connector without mesh | Local destination errno/no request, semantic connector rejection, or explicit audit-only semantic gap. Legitimate connector service succeeds. |
| `HF-GRAN-CLUSTER-SHARED-001` | One shared credential is valid in two clusters | Cluster operations stay authoritative; local cause remains contextual without per-request IDs; supplying distinct IDs upgrades only correct edges. |
| `HF-GRAN-MESH-ROOT-001` | Rooted managed node attacks Mithril and starts mesh | Intact mechanisms may deny. Successful required-link/runtime tamper closes local coverage before mesh attempt; no self-containment claim. |
| `HF-GRAN-MESH-SOCKS-001` | External userspace SOCKS mesh uses no TUN | Provider response on external subject; device policy explicitly inapplicable. A managed equivalent still has exec/listen/control-socket gates. |
| `HF-GRAN-MESH-ENUM-001` | 181 devices enroll and enumerate nodes/routes/CI subnets | Rate/cardinality finding; separately revoke enrollment key and remove exact devices; verify both. Approved automation within signed count/window succeeds. |
| `HF-GRAN-AWS-SPLIT-001` | Same key used externally and by worker for STS, MongoDB, raw exfil | External provider result and local socket decisions remain separate. Worker calls get errno/no packet; provider timeout is not prevention. |
| `HF-GRAN-AWS-DRYRUN-001` | Cloud mutation requested with `DryRun=True` | Provider result classified as auth check; resource unchanged. Semantic gate may reject, audit-only alerts. |
| `HF-GRAN-GITHUB-MINT-001` | Connector mints write-capable installation token | Broker reject/no token, or exact lease. Audit-only unsupported for undocumented mint. Possessed handle self-revokes; hash does not. |
| `HF-GRAN-GITHUB-TREE-PR-001` | Enumerate repo tree and create CI-triggering PR | Exact PR/commit/workflow state; code stays `untrusted_change`; privileged CI leases absent/rejected. Normal bot/dependency PR is control. |
| `HF-GRAN-GITHUB-REARM-001` | Repeated fresh tokens fetch payload into new external sandboxes | One lease/fingerprint/consumer branch each; managed executions denied; outside consumers keep response partial. |
| `HF-GRAN-TOKEN-FORGE-001` | Valid EdDSA token absent from issuer ledger | Only complete issuance coverage plus matching `kid+jti`/fingerprint permits `VALID_TOKEN_ABSENT_FROM_ISSUANCE_LEDGER`; otherwise forgery unobservable. |
| `HF-GRAN-CAPTURE-001` | 100+ single-use endpoints/raw sockets collect output | Managed sends deny/no packet; provider/network actuator disables exact endpoints and watch proves no reuse. Source IP/time joins remain contextual. |
| `HF-GRAN-CI-BUILDRS-001` | Malicious `build.rs` uses CI credential | Result depends on delivery: projected file deny, broker lease reject, read-only provider scope, or environment/same-TLS semantic gap and provider alert. |
| `HF-GRAN-OUTSIDE-001` | `HF-001`–`HF-007` preparation outside estate | External subjects only; no local task, errno, or response target invented. Managed replay tests the first real local hook. |
| `HF-GRAN-HOST-LOC-001` | Same host-inspection text from managed, external, and unresolved sources | Only managed exact branch gets local deny/response; external is outside authority; missing location stays unresolved. |

Every card stores syscall result, buffer/file before/after state, packet
capture/drop counter, provider request/result and resource state, coverage
intervals, generation, and graph/finding digest. An alert screenshot is not a
fixture result. Missing required hook/adapter must produce the card's degraded
status and disable that product claim.

#### End-to-end production branch

1. Runtime admits the reviewed conversion image and binds the first process as
   `conversion-worker` before user execution.
2. HDF5 resolves a hostile reference. A strict file rule denies it; an
   alert-only deployment permits the exact file action and a separate later
   publication decision still occurs.
3. Jinja runs inside Python; no fake task/exec is created. Projected-token open
   reaches the same process identity and normally denies.
4. Kubernetes/IMDS connect normally denies for the worker. An allowed controller
   channel proceeds to provider behavior rules; audit after success alerts but
   cannot retroactively deny.
5. A semantic Kubernetes admission gate may reject the privileged Pod before
   persistence. Audit-only success instead creates object/controller/runtime
   branches and triggers containment.
6. Each new Pod root on every node is separately admitted. Cross-node graph
   uses request, object, Pod UID, scheduling, and runtime evidence—never PID.
7. Mesh, AWS, connector, GitHub, repository, and external sandbox actions use
   their authority-owned subjects and edges. Pre-admission can reject only when
   the real synchronous boundary exists.
8. A malicious source change entering CI retains untrusted artifact/source
   provenance. It receives untrusted build authority and no silently borrowed
   release/deploy permission.
9. The incident is partial until every local lineage, controller/replacement,
   credential, device, connector, repository/artifact, and provider branch has
   a verified postcondition under healthy watch coverage.

### 26. CI/CD Uses The Same Identity And Authority Model

CI is not one process tree. Jobs fan out across nodes; shell/JavaScript steps
are native descendants; job, action, service, and Docker-in-Docker containers
are independent roots; caches/artifacts cross time; credentials may be job-
scoped; cleanup runs after failure; deploy operations create remote roots.

The coordinator-neutral model covers GitHub Actions, GitLab, Tekton, Jenkins,
and equivalent shapes. Vendor adapters provide authenticated assignments and
immutable IDs; they do not become extra node gatherers.

#### Honest assurance tiers

| Tier | Proof and enforcement | Cannot claim |
| --- | --- | --- |
| `CI0_JOB` | Exact coordinator job and its admitted roots; job-wide local policy | Exact step or separation of a job credential among steps |
| `CI1_STEP_PROCESS` | Held native child/runtime root plus authenticated job assignment and trusted runner step launch | Clone versus push inside one same-credential TLS channel; removal of credential already in job memory |
| `CI2_STEP_AUTHORITY` | CI1 plus provider/broker lease uniquely scoped and delivered to that step | Semantics the provider permission model itself does not separate |
| `CI3_PROVIDER_ADMISSION` | Exact request reaches a provider-native permission/admission gate | Operations with no synchronous provider boundary |

GitHub `GITHUB_TOKEN` and OIDC permission are job/workflow scoped; documented
OIDC claims do not prove one shell step. Mithril cannot derive a read-only token
from an arbitrary installed write bearer token. GitHub App installation tokens
can request provider-supported narrower permissions using App authority; that
is new provider issuance, not local attenuation.

**Clone/push example.** Checkout and hostile code both use `github.com:443` and
the job token. CI1 can identify each process but not encrypted smart-HTTP verb.
It can deny the whole endpoint to hostile code. CI2 gives checkout a provider-
issued read-only lease unavailable to hostile code. CI3 uses an actual provider
permission/admission boundary. Without either, write prevention is unavailable;
provider audit may detect push. Mithril does not terminate Git TLS.

#### Exact step identity needs a trusted child-creation seam

GitHub preview container hooks describe execution but are not an unforgeable
provider-signed step identity and do not cover ordinary native host jobs.
Full CI1 on self-hosted GitHub uses a maintained runner integration at child
creation:

```text
provider-authenticated job assignment (job/check-run ID, attempt, runner)
  + trusted runner-control task materializes one step
  + node-signed step launch attestation binds immutable definition,
    actual interpreter/image/script bytes, argv, cwd, public environment,
    input artifacts, node/binding, and held pidfd/runtime task
  + exact task/root claims one SignedIntent slot before resume
```

The node signing key is unavailable to job cgroups. Same UID or access to a
callback socket is insufficient; the peer must be the live labeled
`ci-runner-control` task. Job code that copies environment fields and asks for
a deploy intent is rejected.

GitHub `check_run_id` can identify a job, not a step. The patched runner's
internal step ID plus materialized bytes supplies step identity. Two jobs in
one `run_id` have different check-run/job epochs. Unpatched runner/hooks remain
CI0. GitLab uses a maintained runner custom executor/creation seam; Tekton can
bind TaskRun UID and per-step container root; Jenkins needs a launcher/plugin
held-child seam. GitHub-hosted runners are outside node authority absent a
provider integration.

Generated scripts are copied to a sealed memfd or equivalently held under an
exclusive integrity lease before hashing and execution. Workflow digest alone
does not prove actual temp-file bytes. Symlink swap, changed local action,
moved action tag, two identical bash commands, wrong attempt/runner, and script
mutation must reject or run only the exact held bytes.

#### Physical CI shapes

| CI action | Mithril identity and control |
| --- | --- |
| Host job/shell | Runner-control task admits one job/native transition; every child remains native and step intent changes role only at a held transition. |
| Job container | Independent runtime root admitted with exact image/job/workspace/credential audiences. |
| Script/JS/composite action | Native step transition; nested invocations have nested intents and immutable package/full commit digest. |
| Container action/service | Independent runtime entry and causal coordinator edge; shared workspace/network causes pre-use authority domain. |
| Matrix/parallel job | Separate job and node-local trees; coordinator edge only. |
| Reusable workflow/downstream pipeline | Typed call edge with caller/callee digests and effective permission; no implicit authority increase. |
| Cache/artifact | Immutable artifact and consumer slot; read-as-data does not grant execute/deploy. |
| OIDC/cloud login | Authority lease with exact job/step binding at the advertised tier, audience, account/project, resources, permissions and TTL. |
| Deploy (`kubectl`, Helm, Terraform, cloud CLI) | Local process effects plus semantic provider request/audit and remote object/runtime branches. |
| Post/finally/cleanup | Separate narrow role under terminal job lifecycle; active containment still wins. |
| Interactive debug terminal | Administrative entry with actor, approval, TTL and coverage; never build role. |
| Docker socket/DinD | Daemon socket/device effect plus every subordinate runtime root; if visibility/binding is absent, strict untrusted build denies daemon access. |

#### Untrusted source and indirect execution

A trusted `pull_request_target` workflow can download untrusted PR code and
execute it with powerful job authority. Mithril follows bytes, not the workflow
display name:

1. Coordinator proof says the definition is trusted but trigger/source is an
   untrusted change.
2. Checkout/artifact restore creates an immutable artifact instance with
   producer trust, source revision, digest, and verification result.
3. Writing to workspace does not authorize execution.
4. `make`, `npm install`, `cargo test`, `build.rs`, Python import, test
   discovery, plugin, shell sourcing, or container build consumes those bytes.
5. The resulting process receives `ci-untrusted-build`: no repository write,
   cloud identity endpoint/lease, Kubernetes deploy, runner-control socket,
   protected environment, or host credential unless an exact reviewed rule
   says otherwise.
6. Publish/deploy consumes only an exact promoted digest with valid policy-
   matched attestation and one-use consumer slot.

A boolean `attestation: verified` is insufficient. The verifier checks trust
chain/revocation, predicate version, builder, exact subject digest, source
revision, materials, transparency, freshness, producer trust, and policy
version at consumption.

#### State handoff and runner reuse

`GITHUB_ENV`, `GITHUB_PATH`, outputs/state files, workspace, cache, artifacts,
service sockets, background processes, `PYTHONPATH`, `NODE_OPTIONS`, compiler
plugins, and shell startup files are typed handoffs. A path inserted by an
untrusted step remains untrusted when a later publish step loads it.

Every job has a fresh job epoch, cgroup binding nonce, workspace/temp object
set, runner assignment, and start time. Before reuse, cleanup fences/kills old
descendants as authorized, proves no tasks/labeled sockets/services remain,
applies workspace/temp policy, tombstones the epoch, then starts the next job.
A daemonized child cannot survive into runner-control or the next job role.

#### Semantic CI rules require physical lowering

| Desired rule | Valid preventive lowering | Honest fallback |
| --- | --- | --- |
| deny repository write | Read-only provider token, synchronous provider/Git gate, or whole endpoint deny | Provider alert after write; never claim BPF saw clone/push |
| deny cloud identity | Deny every exact OIDC/STS/metadata endpoint or reject broker exchange | Cannot remove request token already in memory |
| deny Kubernetes API | Deny all resolved API destinations; semantic gate for allowed controller jobs | Audit verb after allowed TLS |
| deny runner-control | Exact Unix socket object + current task/peer role | Path/UID alone invalid |
| deny new cloud lease | Reject at broker or deny all identity endpoints | Provider issuance alert |
| declared artifact upload | Exact store/connector digest intent or destination deny | Filename/time is contextual |
| cleanup own resources | Exact lease, owner UID/tag, resource selector, delete operation at provider boundary | Cleanup role name never grants broad delete |

Each source semantic rule compiles an `EffectLoweringRecord` naming assurance
tier, stage, mechanism, capability IDs, proof axes, prevention result, blast
radius, and fixtures. If there is no valid lowering, protect compilation fails
or the operator explicitly selects alert-only degradation.

#### CI credential delivery determines the earliest control

| Delivery | Earliest honest control |
| --- | --- |
| Environment/context already in process memory | No file-read deny; govern broker/OIDC/provider operation, endpoint/egress, and payload-unobservable exposure |
| Unopened projected/mounted file | Exact file open/read denial |
| Inherited/preopened/passed fd | Sender/receive/read and later effects; open denial alone is insufficient |
| Brokered step lease | Reject issuance/use and deny lease object to other roles |
| Read-only provider token | Provider denies write over same TLS; verify permissions |
| Write-capable job token on required TLS endpoint | Whole channel deny or provider/semantic gate; otherwise post-effect detection |

#### Required CI fixtures

- `CI-NATIVE-001`: identical `curl` from two steps; only signed publish step
  receives publish role at CI1.
- `CI-CONTAINER-001`: job, service, and container action share workspace/network
  but have three entries/budgets and shared negative domain.
- `CI-PR-001`: trusted workflow executes untrusted PR artifact; every credential
  delivery branch produces the exact result in the table above.
- `CI-CACHE-001`: poisoned cache retains producer/digest trust; privileged load
  rejects.
- `CI-OIDC-001`: unapproved step cannot turn job OIDC claims into step lease.
- `CI-DIND-001`: every Docker-created root is bound or daemon access denies.
- `CI-POST-001`: cancelled/contained cleanup cannot regain egress/lease.
- `CI-FANOUT-001`: three-node jobs use coordinator/artifact edges, never remote
  process parents.
- `CI-RETRY-001`: run attempt 2 cannot replay attempt-1 nonce/lease; only
  explicitly reusable exact artifacts cross.
- `CI-DEBUG-001`: web terminal is administrative entry, never build step.
- `CI-STATE-001`: malicious PATH/PYTHONPATH handoff retains untrusted producer.
- `CI-RUNNER-REUSE-001`: daemon/socket cannot cross verified job epoch cleanup.
- `CI-ATTEST-001`: wrong subject/source/material/builder/revoked signer/stale /
  missing transparency all reject.
- `CI-GITHUB-TOKEN-001`: a shared write-capable job token cannot become read-only
  without provider-scoped issuance or a semantic gate.

CI1/2/3 contracts remain dormant architecture until their named adapters,
closed signed CI policy schema, phase allocation, and fixtures are approved.
Operator-facing `coordinators:`/`ciRules:` sketch fields are not silently valid
Version 1 `PolicyDocumentV1` fields; the parser must reject unknown top-level
keys until that schema is allocated.

## Part VII — Checked Upstream Lessons And Product Qualification

### 27. How To Read The Upstream Source Evidence

Mithril does not run KubeArmor, Tetragon, Falco, or Cilium beside its own node
agent. It also does not copy one of those products and add a second policy
engine. It studies the mechanisms that their source proves, keeps the useful
ideas, and builds one Mithril-owned implementation around Mithril's identity,
policy, evidence, and response contracts.

The checked baselines are:

- KubeArmor commit `e46f112e8bd4d3c8c8a73c23bfe438ff40eeea1a`;
- Tetragon commit `dbb59576f9ce504c044f8d9a0cd7a0f91c71ae2c`.

Every statement in this part is about those exact snapshots. It is not a claim
about the maintainers' intent, every release, or every possible configuration.
Phase 0 must re-check each line range before code or a product claim depends on
it.

Each source observation has two separate labels:

1. **What kind of boundary is it?** An implementation choice can be changed by
   writing different code. A Linux or protocol boundary needs a different
   control point. For example, a mutable policy map is an implementation
   choice; TLS hiding `git-upload-pack` from the kernel is a protocol boundary.
2. **How may Mithril use the observation?** `ADOPT` means keep the useful idea.
   `HARDEN` means keep it with a stronger contract. `HOSTILE_TEST` means turn a
   weakness or edge case into a permanent test. `DO_NOT_INHERIT` means the
   behavior is incompatible with Mithril's claim.

The future machine record is `SourceEvidenceClaimV1`. It stores repository,
commit, path, exact line range, blob digest, observation, boundary kind,
relationship to Mithril, reviewer, and the fixture IDs that depend on it. A
display table is never the source of truth.

#### Code reuse and license gate

“Learn from” and “copy code” are different decisions.

- Both checked repositories have an Apache-2.0 top-level `LICENSE`.
- The checked KubeArmor `KubeArmor/BPF/enforcer.bpf.c` has an
  `SPDX-License-Identifier: GPL-2.0` header. The BPF file's own SPDX notice is
  more specific than assuming every file has the repository-level license.
- Checked Tetragon headers under `bpf/lib`, including `process.h`, use
  `GPL-2.0-only OR BSD-2-Clause`; checked BPF program files such as
  `bpf_fork.c` publish `Dual BSD/GPL` to the kernel.
- `tetragon/bpf/lib` is a directory of headers/helpers compiled into Tetragon's
  BPF programs. It is not the upstream `libbpf` userspace library and not a
  stable separately linked API that Mithril can import by directory name.
- A BPF program's kernel `license` section controls access to GPL-only kernel
  helpers. It is not a substitute for obeying the source file's copyright and
  SPDX terms.

Phase 0 therefore records file-level SPDX, copyright, source commit, copied or
derived ranges, modifications, notices, chosen compatible license, generated
object digest, and Rust/BPF linkage/package boundaries. Rust userspace remains
an independently built program, but that fact does not erase obligations for
copied BPF code. Product counsel must approve the final distribution plan;
this architecture is technical provenance, not legal advice.

Default engineering choice: implement Mithril's BPF programs from its own
specification and tests, then selectively reuse a small upstream helper only
when its license and maintenance value beat an owned implementation. Do not
fork an upstream daemon merely to obtain its BPF loader or userspace process
model; the loader and state owners are Rust modules inside `mithril-node`.

### 28. What KubeArmor Teaches Mithril

KubeArmor proves that a relatively small BPF LSM program can make useful
pre-effect file, execution, network-family, and privilege decisions. Its
userspace compiler turns Kubernetes policy into bounded kernel maps. Those are
important lessons. Its checked snapshot does not provide Mithril's signed
entry intent, task-first process identity, immutable generation transaction,
cross-node authority graph, coverage proof, or verified response lifecycle.

#### 28.1 Adopt BPF LSM pre-effect decisions, but fail required identity misses closed

The checked main enforcer has paths that return allow when the container,
scratch, or path lookup is missing (`KA-CODE-001`,
`KubeArmor/BPF/enforcer.bpf.c:10-68`). That is a reasonable availability
choice for a general policy product. It is not valid for a Mithril task that is
already inside a protected binding.

**Example.** A converter is labeled `dataset-converter`. Its
`ProcessSecurityStateV1` entry disappears because a map is exhausted. It then
opens the projected ServiceAccount token. Mithril must return the configured
deny for “protected actor with missing authority state,” record the exact map
miss counter, and mark identity coverage unhealthy. Treating the missing row
as “unconfined” would turn memory pressure into privilege.

#### 28.2 Keep the physical deny independent from event delivery

KubeArmor's main exec path keeps the computed denial when ring reservation
fails (`KA-CODE-002`, `enforcer.bpf.c:346-412`). Mithril adopts this property.
Some checked preset programs instead allow when event allocation fails
(`KA-CODE-003`, `protectenv.bpf.c:78-81`, `filelessexec.bpf.c:91-95`,
`anonmapexec.bpf.c:97-100`, `protectproc.bpf.c:86-89`, and
`exec.bpf.c:117-120`). Mithril does not inherit that coupling.

**Example.** The ring buffer is full while hostile Python calls
`execve("/bin/sh")`. The BPF program first fixes the result as `-EACCES`, then
tries to emit evidence. If emission fails, the shell still does not start. A
pinned loss counter closes the evidence interval, so control cannot claim a
complete negative history.

#### 28.3 Compile outside the kernel, then publish one immutable generation

KubeArmor demonstrates useful userspace lowering into compact maps. In the
checked code, individual entries of per-container inner maps are mutated over
time (`KA-CODE-007` and `KA-CODE-019`; `shared.h:250-259`,
`mapHelpers.go:47-73`, `rulesHandling.go:414-638`). A logged update error can
therefore leave an installed map different from the desired policy.

Mithril hardens this into a transaction:

1. compile every rule and negative set into fresh inactive maps;
2. verify counts, bounds, digests, and all expected lookups;
3. run allow, deny, map-miss, and capacity probes;
4. publish one generation pointer with compare-and-swap;
5. keep old maps until every task, socket, domain, pending intent, and response
   generation reference is released.

**Example.** A profile has 400 file rules and rule 317 cannot be inserted. The
old generation remains active. No task sees rules 1 through 316 from the new
profile and rules 317 through 400 from the old one.

#### 28.4 Bind before first user effect, not after the container is already running

The checked NRI path associates policy after start and removes association at
stop (`KA-CODE-004` and `KA-CODE-017`, `core/nriHandler.go:120-240`). This
proves a useful runtime integration point, but it does not prove a first-exec
barrier or the exact ordering of every Kubernetes `PreStop` action.

Mithril uses the two admission barriers in Chapter 7. A runtime-held setup task
gets only setup authority. User execution waits until the root filesystem,
mount topology, cgroup binding, signed profile, and one-use entry claim are
read back.

**Example.** A new privileged Pod contains a malicious entrypoint that reads a
hostPath token in its first instruction. A post-start association is too late.
The node floor and rootfs-ready barrier must reject the root before that
instruction begins.

#### 28.5 Copy the idea of early fork context, not an unchecked key-width mismatch

The checked system monitor tries to propagate parent context during fork
(`KA-CODE-005` and `KA-CODE-010`, `BPF/system_monitor.c:1362-1376`). The map is
defined with a 64-bit key while the shown fork code uses a 32-bit key at
`1368-1373`; consumers use 64-bit values. Mithril treats this as a hostile ABI
test, not code to copy.

**Example.** Parent PID `41` forks child PID `70000`. A truncated or differently
sized key must not accidentally find another task. Rust and BPF compile the
same C-compatible structs, compare golden bytes, and reject an ABI whose size,
alignment, or endianness differs.

#### 28.6 Keep network-family hooks, but do not call protocol or endpoint context process authority

The checked KubeArmor BPF network rules mainly decide socket type and protocol
(`KA-CODE-006` and `KA-CODE-013`, `enforcer.bpf.c:415-648`). Its NFLOG path
adds endpoint/container context in userspace
(`networkPolicyEnforcer.go:267-303,733-824`; `types.go:722-767`). This is useful
network evidence. It is not a current task role, immutable socket provenance,
or same-process TLS verb decision.

**Example.** A broad uploader opens a TCP socket and passes it to a restricted
converter. Endpoint-only attribution could still call the flow “the Pod's
traffic.” Mithril intersects the socket creator's restrictions, the current
sender's authority domain, live response state, final route, and packet fence.
The passed socket cannot restore uploader permission.

#### 28.7 Treat action words as source syntax, not proof of the result

KubeArmor normalizes `Allow`, `Audit`, and `Block` in the checked control code
(`KA-CODE-009` and `KA-CODE-014`, `core/kubeUpdate.go:1405-1414`). Mithril
adopts a small readable vocabulary but gives each word one physical stage as
defined in Chapter 11. An audit event cannot prove a rejected request. An
observe-mode `would_deny` cannot prove the effect was absent.

#### 28.8 Preserve an earlier LSM denial at every hook that supports it

The checked programs show hook-specific handling of a prior BPF result and
partial attachment behavior (`KA-CODE-011`, `KA-CODE-020`, `KA-CODE-021`, and
`KA-CODE-022`). The details are not uniform enough to make one global claim.
Mithril records the exact signature and return-composition rule per hook.

**Example.** SELinux has already returned `-EACCES` for an open. Mithril's BPF
LSM program may add evidence, but it must not turn that into allow. A fixture
loads another denying LSM/BPF program before Mithril and checks the final
errno for every advertised hook.

#### 28.9 Use DNS parsing as context; keep an IP and packet floor

The checked DNS code (`KA-CODE-012`, `KA-CODE-015`, and `KA-CODE-025`,
`enforcer.bpf.c:1025-1075` and the decoder in `shared.h`) assumes particular
port-53, first-buffer, QNAME, size, and framing shapes. Missing state, malformed
input, long input, TCP DNS, split iovecs, DoT, and DoH cannot all be made safe by
that parser.

**Example.** Policy denies the Kubernetes API destination. The attacker sends
the IP literal, a compressed DNS name, TCP DNS, and DoH. DNS observations can
add names to evidence, but every case still reaches the exact final-address and
packet decision. Parser failure never creates network permission.

#### 28.10 Distinguish open from later access

The checked file programs provide valuable hook examples, but the pinned
`file_permission` path covers write/append rather than every possible read of
an already-open descriptor (`KA-CODE-016`). Mithril's result states whether it
denied open, denied a later operation, observed positive bytes, or could not
see bytes already in memory.

**Example.** The ServiceAccount token descriptor was inherited before policy
activation. A later `read` cannot be reported as “open denied.” Mithril governs
descriptor receipt/use and subsequent network/provider effects, and reports
the file boundary honestly if byte completion is not observable.

#### 28.11 Turn presets into classifier seeds, not complete security families

KubeArmor's checked environment, fileless-exec, anonymous-map-exec, and proc
presets are narrow and useful (`KA-CODE-018`). Its checked exec context also
carries namespace, TTY, and inherited context (`KA-CODE-008`,
`KubeArmor/BPF/exec.bpf.c:22-53`). Mithril uses these ideas to seed tests for
environment access, memfd execution, executable anonymous memory, proc
inspection, and contextual evidence. A TTY is never authenticated
administrative intent. Each preset expands into the full object, operation,
bypass, and physical-oracle matrix in Chapters 16, 17, and 21.

#### 28.12 Measure every reader, map, and bound

The checked monitor and preset readers can warn, continue, stop, or discard
lost samples depending on the path (`KA-CODE-023` and `KA-CODE-028`). Paths and
event fields are bounded (`KA-CODE-024`). Exec context and policy state use
bounded or LRU maps (`KA-CODE-026` and `KA-CODE-027`). Mithril keeps those
constraints visible:

- readiness means every required program, link, map, reader, sequence, WAL,
  and controlled probe is healthy;
- strings are evidence fields, while security identity uses exact kernel
  objects and digests;
- every authoritative map has a capacity budget and N/N+1 test;
- state required to grant authority is non-evictable; exhaustion denies the
  protected effect or admission instead of inventing an allow.

### 29. What Tetragon Teaches Mithril

Tetragon proves several mechanisms Mithril should keep: one userspace process
can own many BPF sensors; fork and exec can be staged across kernel hooks; a
Kubernetes selector can be resolved to exact cgroups; runtime metadata can
arrive before initial container execution; and a userspace process cache can
repair out-of-order evidence. The checked snapshot does not turn those pieces
into Mithril's signed, one-use authority admission or its exact prevention and
response proof.

#### 29.1 Label a child before fork-without-exec effects

The checked fork program does not create child state when parent state is
missing (`TG-CODE-001`, `bpf/process/bpf_fork.c:24-104`). Mithril keeps the
early child labeling point but treats a missing protected parent as a defect.

**Example.** Compromised Python calls `fork`; the child reads a token without
calling `exec`. If the parent's state is missing, protect mode installs the
restrictive unknown label or denies the child's first protected effect. It
does not wait for an exec event that may never happen.

#### 29.2 Preserve Tetragon's non-leader-exec lesson

The checked Tetragon source and tests explicitly handle exec by a non-leader
thread (`TG-CODE-002`, `bpf_execve_event.c`, `process.h`, and
`pkg/sensors/exec/exit_test.go`). Saying it simply misses this case would be
wrong. The checked staging spans commit-credentials, map-update, and event
programs rather than one magical hook (`TG-CODE-014`). Mithril adopts the case
as a permanent fixture and extends it with process-shared authority state and
generation references.

**Example.** Thread 7 of a Python process calls `execve`. Linux removes the
other threads and changes the task-group shape. Mithril commits one new
execution identity, preserves monotonic restrictions, closes obsolete task
coordinates, and never creates a second independent process merely because
the caller was not the leader.

#### 29.3 Resolve Kubernetes selection to cgroups, then add signed lifetime identity

Tetragon's cgroup policy filter is useful (`TG-CODE-003`). The checked
userspace conflict path can warn and retain overlapping policy IDs. Cgroup
membership by itself does not prove why a later root exists, which one-use
intent it claimed, or whether the identifier was reused.

Mithril adopts selector-to-cgroup resolution, then binds full container ID,
Pod UID, cgroup live interval, binding nonce, image digest, profile generation,
and exact entry identity. Conflicts are compiler errors or explicit closed
intersections, never logged ambiguity.

#### 29.4 Use runtime creation as an admission opportunity, not as automatic proof

The checked OCI path has a `createRuntime` opportunity that can fail before
user code, while another create path is a no-op; policy-map failures can log
and continue (`TG-CODE-004` and `TG-CODE-021`). This teaches where a barrier can
live. It does not prove the full Mithril transaction.

**Example.** The OCI hook reports Pod metadata but the cgroup binding nonce
does not match the held task. Mithril rejects the claim and keeps the task
held. A successful callback or matching container name alone never releases
it.

#### 29.5 Keep stable process coordinates separate from authority identity

Tetragon builds cluster-oriented execution IDs and repairs process cache
ordering (`TG-CODE-005`). The cache is useful for evidence, but host/node names,
PIDs, timestamps, and an LRU entry are not durable authorization objects.
Mithril uses random boot-scoped task/process/exec cookies plus exact live
intervals for authority. Display coordinates remain evidence.

#### 29.6 Keep fork-without-exec and test ownership exact

Tetragon has a fork-without-exec test (`TG-CODE-006` and `TG-CODE-020`). The
test file proves the behavior; the BPF source file does not “contain a test.”
Mithril's source evidence record names the mechanism file and the executable
fixture separately.

#### 29.7 Distinguish Generic LSM actions from the separate enforcer

Tetragon is not observation-only. Its checked Generic LSM path supports
override/signal actions, and its staged `bpf_enforcer` is another mechanism
(`TG-CODE-007` and `TG-CODE-019`). Its checked action vocabulary and mode split
are also useful patterns (`TG-CODE-013`). Mithril adopts the separation between
a hook-local result and event output. It does not flatten every Tetragon action
into the same assurance claim.

The exact hook signature, selector argument limits, process-state miss
behavior, and previous-return position must be qualified per program
(`TG-CODE-010`). The checked socket example is a kprobe example, not proof that
every socket control uses Generic LSM (`TG-CODE-015`).

#### 29.8 Turn loss counters into source epochs and closed coverage intervals

Tetragon exposes loss metrics (`TG-CODE-008`). Mithril adds a source epoch,
per-CPU or per-source sequence, gap intervals, WAL acknowledgement, and
watermarks. A counter says that something was lost; a coverage interval says
which negative conclusions are forbidden.

#### 29.9 Initial runtime metadata is not later exec intent

The checked runtime integration focuses on initial `CreateContainer`
(`TG-CODE-009`). Its local transport carries useful metadata but does not
provide Mithril's signature, expiry, nonce, one-use slot, target digest, or
held-task relation (`TG-CODE-023`). Later `exec`, probes, lifecycle hooks,
checkpoint restore, and administrative streams therefore need their own
admission paths.

#### 29.10 Make concurrency state authoritative and fail closed

The checked enforcer's `override_tasks` map has a small default capacity and an
ignored insert-failure path in the reviewed code (`TG-CODE-011`). This is an
audited concurrency hazard in that snapshot, not a public vulnerability
claim. Mithril's equivalent state is sized from declared workload capacity,
preflighted, non-evictable while authoritative, and has an N/N+1 fail-closed
test.

#### 29.11 Use one binary and fresh inner maps, then make reverse state transactional

Tetragon demonstrates one node binary with many sensors (`TG-CODE-012`) and a
useful fresh-inner-map publication pattern (`TG-CODE-016` and `TG-CODE-022`).
Mithril adopts both. Reverse-index and generation-retention updates become one
recoverable transaction; an update cannot publish only half of the relation.

#### 29.12 Keep runtime and TTY context as evidence, not authenticated intent

The checked source carries runtime and TTY context (`TG-CODE-017`). TGID and
one-event-per-thread-group suppression are useful coordinates and volume
controls, not per-task permission (`TG-CODE-018`). A TTY, familiar argv, or
runtime label cannot turn attacker activity into an administrative or probe
role.

#### 29.13 Preserve generic enforcement on an unknown process, but never invent a role

The checked Generic LSM selector can keep selector-independent enforcement
when process state is unknown (`TG-CODE-024`). Mithril does the same for a
node-wide hard floor. It differs where a rule needs role authority: a missing
role cannot be guessed from the cgroup, path, or command.

**Example.** An unlabeled task calls `bpf(BPF_PROG_LOAD)`. The node hard floor
can deny that operation without knowing the task's role. The same task cannot
be allowed to read a deployment credential merely because the Pod selector
normally maps to a deployment role.

### 30. The Combined Mithril Pipeline

The useful upstream ideas fit one pipeline. They are not two daemons and not
two independent sources of authority.

```text
runtime or coordinator creation seam
  -> authenticate one intent and hold the exact task/root
  -> install task/process/entry identity before release
  -> inherit identity on every fork/thread before child effects
  -> commit exec transitions around the real Linux exec hooks
  -> evaluate file/exec/network/device/privilege effects at pre-effect hooks
  -> update shared authority state before releasing a channel or publication
  -> fix the physical result
  -> emit bounded evidence with source sequence and coverage
  -> build typed local/multi-node/provider edges in control
  -> authorize, apply, read back, and watch any response
```

KubeArmor most directly teaches compact pre-effect LSM policy. Tetragon most
directly teaches staged process observation, cgroup selection, one-process
sensor ownership, and runtime integration points. Mithril adds the missing
contract between those mechanisms: signed reason, task-first identity,
immutable activation, shared-authority state, cross-node graph proof, coverage
truth, and verified response.

#### Example A: the attacker never starts a suspicious command

1. The normal converter is admitted as `dataset-converter`.
2. Hostile HDF5 data causes already-running Python to evaluate a template.
3. No exec event exists. File, memory, and network hooks still see the exact
   current task and process state.
4. Python opens the projected ServiceAccount token. File policy denies the
   exact token object before open if that is the configured boundary.
5. If the token was already in memory, file policy cannot undo that. The same
   process retains `sensitive:kubernetes-token`, and network/provider rules
   deny or reject Kubernetes authority use.
6. Python forks without exec. Early child labeling carries the restriction.
7. The child later execs `/bin/sh`; exec staging changes image identity but
   cannot clear the sensitive restriction.

This example needs both upstream lessons and Mithril's added state. A command
allowlist alone misses step 2. A post-hoc process tree alone misses the first
effect and cannot prevent it.

#### Example B: probe and attacker execute identical bytes

1. Kubelet signs a one-use readiness intent for held task A.
2. The application forks task B and runs the exact same `/app/healthcheck`
   binary with the same argv and timing.
3. Task A claims the kubelet ticket and receives `readiness-probe` role.
4. Task B has a native parent edge, no ticket, and remains
   `application-child`.
5. If task B races the claim first, target binding fails. Command equality,
   cgroup equality, and TTY state cannot claim the slot.

#### Release-gating implementation cards

Three small cards keep the first hard cases implementable:

| Card | Starting state | Stimulus | Required result and oracle |
| --- | --- | --- | --- |
| `CARD-FILE-SA-TOKEN-OPEN-001` | Bound converter; exact projected-token object in negative set | Existing Python opens token; variants use symlink, proc-fd alias, rotated projection, inherited fd, mmap | Open/read result uses exact file object and stage. A denied open returns errno and produces no positive-byte oracle. Already-open/memory branches report their real weaker boundary. |
| `CARD-ENTRY-PROBE-IMPERSONATION-001` | One signed probe ticket and one application process in same container | Both execute identical healthcheck bytes concurrently | Only exact held task claims the ticket. Native child never receives probe role. Replay, wrong task, wrong generation, expiry, and restart reject. The executable fixture ID is `ENTRY-PROBE-IMPERSONATION-003`. |
| `CARD-XNODE-PRIVILEGED-POD-001` | Worker authority domain has Kubernetes credential/use evidence; node floor active on another node | Credential creates privileged Pod and runtime root remotely | Typed Kubernetes audit/object/binding edges connect nodes. Remote pre-admission or node floor rejects the root where supported; otherwise report exact observation and response, never local syscall prevention. Fixture: `XNODE-PRIVILEGED-POD-001`. |

### 31. Acceptance: What Must Work Before Mithril Makes A Claim

Passing unit tests for map lookups is not enough. Each advertised kernel,
runtime, and Kubernetes combination must pass real hostile workloads and
legitimate controls. The oracle is the physical syscall, packet, provider
object, or verified response result, not an alert string.

#### 31.1 Kubernetes and runtime entry matrix

| Fixture | Real setup | Required result |
| --- | --- | --- |
| `ENTRY-START-001` | Delay, drop, or mismatch admission ack while initial task is held | User executable never starts in strict mode; observe mode records the exact gap. |
| `ENTRY-POSTSTART-001` | Race `PostStart` and entrypoint in both orders | Two admitted roots; neither is fabricated as the other's child. |
| `ENTRY-POSTSTART-002` | Kubelet restart repeats `PostStart` | Budgeted new/idempotent entry instance; stale nonce never works. |
| `ENTRY-PRESTOP-001` | Delete Pod during an active response | Containment versus cleanup policy wins explicitly; termination grants no bypass. |
| `ENTRY-PROBE-001` | Concurrent startup/readiness/liveness exec probes | Exact signed reason where supported; equal-budget conservative class otherwise; unequal ambiguity denies. |
| `ENTRY-PROBE-002` | Application child runs identical probe binary/argv/cadence | Native lineage remains; no probe role. |
| `ENTRY-NETPROBE-001` | HTTP, TCP, and gRPC probes | No fake in-container process root; host flow and application receive are scoped separately. |
| `ENTRY-SLEEP-001` | Lifecycle `sleep` action | Kubelet lifecycle evidence only; no invented task. |
| `ENTRY-EXEC-001` | `kubectl exec`, TTY/non-TTY, and `kubectl cp` | Administrative entry plus audit actor; configured approval/default deny applies. |
| `ENTRY-EXEC-002` | `crictl exec` runs same command as probe | Host-admin/unknown-runtime entry, never kubelet-probe. |
| `ENTRY-EPHEMERAL-001` | Add ephemeral container sharing target PID namespace | Independent container execution set and profile; shared PID namespace does not merge trees. |
| `ENTRY-CONTAINERS-001` | Init, native sidecar, and app containers share Pod network/volume | Independent roots plus exact shared-resource edges. |
| `ENTRY-MIGRATE-001` | Move unlabeled task into protected cgroup or use `nsenter` | First protected effect denies without a valid staged claim. |
| `ENTRY-REUSE-001` | Reuse PID, namespace number, cgroup path/ID, Pod/container name | Full IDs and live intervals prevent old policy/response attachment. |
| `ENTRY-RESTART-001` | Restart kubelet, runtime, and node agent at every admission state | Claims reconcile or expire; no stale/duplicate role; coverage transition is explicit. |
| `ENTRY-LOSS-001` | Drop intent and BPF entry evidence independently | Strict task denies or remains held; loss cannot relax enforcement. |

Every case records the exact runtime/CRI version; kernel/BTF/LSM order and
capabilities; Pod UID and resource version; full container/image/cgroup live
identity; entry nonce and claim result; task/process/exec cookies; syscall or
runtime outcome; and coverage/loss state.

#### 31.2 Physical effect and bypass matrix

| Family | Bypasses that must be tried | What the oracle proves |
| --- | --- | --- |
| Execution | `execveat`, `fexecve`, memfd, deleted file, script/interpreter, dynamic linker, rename/bind mount, overlay copy-up, non-leader exec, writable-to-executable `mprotect` | Forbidden image or executable memory never begins; allowed immutable image gets exact role. |
| File | symlink, hardlink, rename, bind mount, proc-fd alias, token rotation, inherited/passed fd, mmap, `io_uring`, writable `MAP_SHARED` publication | Claimed operation returns denial before the named effect; already-open/in-memory gaps remain explicit. |
| Network | DNS and IP literal, IPv4/IPv6, TCP/UDP/raw/packet, passed socket, established TLS, sendfile/splice, TUN/AF_XDP/BPF redirect, destination rewrite, receive queue | Forbidden connect/send/packet is physically absent; established-flow and shared-socket blast radius are proved separately. |
| Device | `mknod`, aliases, open, TUN, GPU, FUSE, KVM, approved/unapproved ioctl, passed device fd | Device tuple, actor, operation, and derived object all match the exact rule. |
| Privilege | setuid/caps, credential changes, ptrace, process-vm, pidfd controls, `setns`/`unshare`, mount, BPF, perf, module, keyring, proc/sysctl, seccomp user notification | Chosen pre-effect hook denies; unsupported operation lowers the claim. |
| Identity | fork without exec, thread/`vfork`, non-leader exec, reparent, parent exit, task/cgroup/PID reuse, moved tasks, bootstrap | Stable identity or typed gap exists before effect; no userspace-labeling window. |
| Evidence | ring pressure, reader death, source gap, WAL full, generation switch, link/pin/map loss, control outage | Physical deny is independent from transport where mechanism is live; negative claims stop across gaps. |

The old phrase “seccomp weakening hook” is not a valid Linux test. Seccomp
filters are monotonic once installed. The real tests prove that the required
floor existed before user mode, could not be silently omitted, and that
unapproved ptrace or seccomp-user-notification supervisors were denied.

#### 31.3 Pinned-source tests that cannot be waived

| Source observation | Mandatory hostile fixture | Release consequence |
| --- | --- | --- |
| `KA-CODE-025` DNS parser bounds | `NET-DNS-EXFIL-001`: short/malformed/compressed/multi-question/long/split-iovec/TCP/non-53/DoT/DoH/IP-literal | Unknown parse still hits destination/IP floor; failure blocks a complete DNS/network claim. |
| `KA-CODE-026`, `KA-CODE-027`, `TG-CODE-024` bounded or missing process/policy state | `SOURCE-KA-CAPACITY-005`, `SOURCE-TG-EXEC-MAP-007`, `DECISION-SET-GOLDEN-001`, and N/N+1 capacity cases | Missing state never grants role and a partial generation never activates. |
| `KA-CODE-028` reader loss behavior | `SOURCE-KA-READER-LOSS-003`, sole-reader death, nil/closed reader, lost samples, WAL gap | One daemon-ready bit cannot support a healthy negative interval. |
| `TG-CODE-023` unauthenticated local runtime metadata shape | `SOURCE-TG-RUNTIME-JOIN-006`, `ENTRY-CLAIM-TRANSACTION-004`, `ENTRY-PROBE-IMPERSONATION-003` | Metadata is authenticated and joined to held live target before release. |

A failure becomes `UNSUPPORTED` or `INSUFFICIENT_COVERAGE`. A similarly named
upstream feature cannot waive it.

### 32. Failure And Recovery Are Part Of The Security Result

Mithril tracks health separately for entry admission, task identity, process
state, authority domains, cross-entry topology, VMA snapshots, exec, file,
network LSM, packet fence, device, privilege, and evidence. “The daemon is
ready” is not enough.

| Failure | Observe mode | Protect mode | What may still be claimed |
| --- | --- | --- | --- |
| Required BPF LSM hook/helper is absent | Record exact unsupported capability; use weaker observations if present | Refuse a profile that requires that prevention; optionally reject workload under strict tier | Only the weaker measured stage, never equivalent prevention |
| Initial runtime hold is absent | Bootstrap after start and record the gap | Reject strict start or use a separately qualified barrier | No first-exec protection claim |
| Protected cgroup contains unlabeled task | Record orphan and identity defect | Deny its first protected effect | No exact lineage until reconciled |
| Parent state missing at fork | Child lineage becomes incomplete | Install restrictive unknown child or deny creation/effect | Never silently benign |
| Entry intent has several candidates | Keep candidates and report ambiguity | Allow only if every candidate has the same explicitly approved budget; otherwise deny | No exact probe/lifecycle reason |
| Ring reservation fails | Increment pinned loss counter and close interval | Same; already fixed physical result remains | Enforcement may be healthy; evidence is incomplete |
| Sole Rust process or control link dies | No disk WAL writer exists; bounded ring records remain until full | Pinned programs/maps keep existing decisions; userspace-dependent new admission rejects | No central response/new profile; later negative history is incomplete |
| bpffs pathname disappears but live references remain | Mark recovery/pin health bad | Existing objects may continue; reject restart-sensitive new admission | Only exact live-link readback, not healthy recoverability |
| Enforcement link detaches | Mark that family unavailable | Family becomes `PROTECTION_UNKNOWN`; separately healthy actuator may freeze/fence | Never claim the absent hook denied anything |
| Required map entry is missing while program remains | Record map miss and coverage defect | Use that program's qualified fail-closed miss result | Only if exact path was tested |
| Required map is replaced/lost | Mark link/map integrity failed | Reject strict new admission; independently freeze/fence if authorized | Affected prevention family unknown |
| New policy fails compile/readback/probe | Keep previous generation | Reject update; keep previous generation | No partial activation |
| WAL fills | Apply configured retention/backpressure before overwrite and expose gap | Local enforcement continues; evidence-dependent conclusions stop | No safe/contained claim across loss |
| Kubernetes/provider audit is absent | Local evidence continues | Local controls continue | Provider verb and distributed edge are unknown/contextual |
| Runtime/kubelet restarts | Reconcile live tasks and pending entries; open gap | Preserve pinned bindings; expire/revalidate before new exec | No stale nonce/lifecycle claim |
| Node reboots | Close old boot subjects and start new source epoch | Every workload is admitted again | Old response keys cannot target new tasks |
| Process/domain map corrupt, mismatched, or full | Mark exact task/domain interval incomplete | Deny affected effects and strict joins; authorized independent freeze may hold | No role/taint/domain claim from missing state |
| Authority-domain join crashes halfway | Keep subjects separate and report channel unproved | Keep held tasks held, deny dynamic channel, preserve every committed restriction | No laundering-prevention claim until recovered |
| VMA snapshot is partial or task sharing changes during snapshot | Keep positive mappings, mark absence unproved | Never relax from partial snapshot; retain restrictions or reject exact action | `VMA_SNAPSHOT_INCOMPLETE` |

A missing enforcement mechanism cannot apply its own “safe state.” If the file
LSM link detaches, that link cannot freeze a cgroup or deny a file. A separate,
still-healthy runtime gate can reject new roots. A separate packet program can
fence egress. A separately qualified cgroup freezer can hold existing tasks.
Each action has its own authorization and readback.

**Recovery example.** Detach only the file-LSM link while TC remains attached.
Mithril marks file protection `UNKNOWN`. If policy authorizes it, TC fences the
authority domain and verifies the fence. A token open during this interval is
not reported prevented. Recovery reattaches the exact expected program/maps,
checks digests, runs an isolated file-deny probe, reconciles live tasks and
file state, and opens a new healthy interval before strict admission resumes.

When the sole `mithril-node` process dies, no hidden second gatherer writes to
disk. Existing pinned decisions continue only while their links/maps remain.
The ring eventually fills; emission drops; pinned counters and claim
tombstones show the gap and stop replay. Runtime clients whose admission needs
userspace fail closed because the local socket is gone. On restart, the process
verifies object identity, reconciles tasks/claims/counters to WAL, drains what
remains, and only then reopens admission.

### 33. Performance And Boundedness

The steady state replaces ptrace stops with bounded BPF decisions. That makes
Mithril suitable for production only if the hot path remains both fast and
correct. A lower latency number does not excuse skipping identity, a shared
restriction, a prior LSM denial, or coverage accounting.

#### 33.1 Exact labeled-task hot path

```text
1. Preserve any nonzero previous BPF-LSM return.
2. Read immutable TaskLabelV1 from task storage.
3. Read ProcessSecurityStateV1 using label.process_state_id.
4. Read AuthorityDomainStateV1 using process.authority_domain_id.
5. Verify the expected protected-root cgroup binding nonce and current task
   placement. A moved labeled task never becomes an unprotected host task.
6. Read effective response set and only the object/socket/device state required
   by this hook.
7. Read one exact role + effect + object + state decision from the task's
   retained immutable profile generation.
8. Intersect it with domain restrictions, response restrictions, object/socket
   lifetime, and previous LSM result.
9. Commit any monotonic state change before returning allow. Required CAS or
   state allocation failure denies the effect.
10. After the result is fixed, optionally emit one bounded record.
```

The earlier cgroup-first sketch is abandoned. A labeled task moved out of its
expected cgroup must still be found through task storage and denied. Only an
unlabeled task begins with bounded protected-root/ancestor lookup, then claims
an exact staged entry or fails closed.

The Rust compiler handles paths, selectors, PodSpec meaning, DNS/service
inventory, provider rules, and conflicts outside the hook. BPF extracts a path
or object only when that hook's decision set needs it. Allowed-event emission
can be suppressed, but coverage counters remain.

#### 33.2 What Phase 0 must budget

- p50, p95, p99, and maximum added latency for fork, exec, open, connect, UDP
  send, established TCP send, packet fence, and each entry-admission path;
- CPU, resident memory, map memory, and event/WAL throughput;
- task, process, domain, socket, response, topology, VMA, mm-cookie,
  publication, and pending-intent capacity, including the exact N+1 result;
- reference churn, concurrent compare-and-swap contention, maximum ancestor
  vector, path/argv extraction, tail-call depth, and cold/warm behavior;
- signature verification, replay lookup, intent staging, repeated probe, Pod
  start, shutdown, CI fan-out, artifact handoff, and provider-event throughput;
- normal application success and probe deadlines under protection;
- overload and outage behavior without converting missing proof to allow.

Each benchmark pins the CPU/microcode, NUMA layout, kernel/BTF/boot arguments,
LSM order, BPF object digests, runtime/Kubernetes versions, workload, policy,
evidence mode, concurrency, warmup count, and raw samples. It alternates
baseline and protected trials. Averages alone do not pass.

The release records use closed types:

```text
LatencyDistributionV1 {
  unit: NANOSECONDS
  sample_count: u64
  p50, p95, p99, maximum: u64
  histogram_artifact_digest: DigestV1
}

OperationPerformanceRecordV1 {
  operation_id: FORK | EXEC | OPEN | CONNECT | UDP_SEND |
                ESTABLISHED_TCP_SEND | PACKET_FENCE | ENTRY_ADMISSION |
                INTENT_VERIFY | OTHER_REGISTERED
  operation_registry_id?: u32
  concurrency: nonzero u32
  evidence_mode_id
  state_transition_mode: READ_ONLY | MONOTONIC_TRANSITION | CONTENDED_CAS
  warmup_iterations, measured_iterations: u64
  baseline, protected, added: LatencyDistributionV1
  cpu_time_ns, peak_resident_bytes: u64
  requested_events, emitted_events, lost_events: u64
  threshold_record_id
  result: PASS | FAIL | INSUFFICIENT_SAMPLES
}

CapacityPerformanceRecordV1 {
  resource_kind: BPF_MAP | RING | WAL | PENDING_INTENT |
                 AUTHORITY_DOMAIN | PUBLICATION_SLOT | OTHER_REGISTERED
  resource_registry_id?: u32
  configured_capacity, largest_successful_cardinality,
    first_failed_cardinality, peak_bytes: u64
  expected_exhaustion_result
  observed_exhaustion_result
  health_transition_result
  result: PASS | FAIL | INSUFFICIENT_SAMPLES
}

PerformanceQualificationRecordV1 {
  qualification_record_id
  platform_support_manifest_digest, product_build_digest: DigestV1
  cpu_microcode_memory_numa_digest: DigestV1
  kernel_btf_boot_lsm_digest: DigestV1
  runtime_kubernetes_digest, bpf_object_set_digest: DigestV1
  workload_fixture_digest, policy_fixture_digest: DigestV1
  signed_threshold_set_digest, raw_sample_bundle_digest: DigestV1
  operation_records[]
  capacity_records[]
  aggregate_result: PASS | FAIL | INSUFFICIENT_SAMPLES
}

PerformanceQualificationBundleV1 {
  bundle_version: exactly 1
  architecture_revision_digest, product_build_digest: DigestV1
  platform_support_manifest_digest: DigestV1
  records[]: sorted unique PerformanceQualificationRecordV1
  canonical_payload_digest: DigestV1
  signer_key_id
  signature
}
```

Capability probes use `CapabilityRecordV1` and `CapabilityBundleV1` from
Appendix A. Both capability and performance bundles use deterministic CBOR,
SHA-256, and Ed25519 with distinct domain strings. `PASS` requires every
mandatory row, threshold, digest, build, and platform to agree.

**Concrete benchmark.** Measure one million protected and unprotected opens
after 100,000 warmups at concurrency 1 and 32. Record the full distributions.
Then fill the authoritative file-state map to N and attempt N+1. The expected
errno and health transition must match. A run that looks faster because it
dropped requested evidence is a correctness failure.

## Part VIII — Ownership, Delivery, And Approval

### 34. One Durable Owner For Every State Change

`mithril-node` is one Rust process per protected Linux node. “One process” does
not mean one giant module. It means there is one loader, one copy of each
authoritative map, one runtime-admission service, one local evidence sequence,
and no competing daemon that can assign security identity.

| Durable owner | Runs in | It alone may change | It must not do |
| --- | --- | --- | --- |
| `TrustBundleOwner` | Control, verified cache on node | Issuer keys, trust generation, rotation/revocation, anti-rollback floor | Stage a task claim |
| `IntentAdmissionOwner` | `mithril-node` | Canonical proof validation, replay WAL, target validation, pending claim state; its BPF ABI performs synchronous claim transitions | Infer intent from argv/timing or let an adapter stage claims |
| `WorkloadBindingOwner` | `mithril-node` | Container execution sets, cgroup binding nonce/storage, initial-entry lifecycle, node-floor binding | Create namespaces or perform the OCI runtime's normal job |
| `NativeSecurityStateOwner` | `mithril-node` plus owned BPF transitions | Task/process/domain/mm/publication state, inherited restrictions, joins, local response refs | Build provider graph conclusions |
| `PolicyCompiler` | Control | Validate/lower source policy and sign immutable artifact | Change a node's active pointer |
| `PolicyActivationOwner` | `mithril-node` | Stage/read back/probe generation, pointer CAS, generation-retention counts, retirement/rollback | Own domain membership, pending intent, or response semantics |
| `KernelHostOwner` | `mithril-node` | One loader, link/map object lifecycle, ABI, capability state | Invent roles or semantic transitions |
| `ObjectAndSocketStateOwner` | `mithril-node` effect modules | Exact object/socket identity, lifetime, classification | Directly mutate domain membership; it requests an owned join |
| `CoverageHealthOwner` | Node source plus merged control view | Source epochs, sequences, intervals, gaps, negative-claim eligibility | Change physical decisions |
| `LocalEvidenceOwner` | `mithril-node` | Canonical local observations, WAL, upload acknowledgement | Repair a deny after the fact |
| `GraphAndFindingOwner` | Control | Immutable graph/finding revisions and deterministic replay | Fabricate native parents or actuate PIDs |
| `NotificationRouter` | Control | Sensitivity-checked delivery, retry, dedupe, route health | Mutate findings or response plans |
| `ResponseCoordinator` | Control | Response authorization, plan revisions, target dispatch | Issue raw shell commands or use stale graph coordinates |
| `ProviderResponseActuator[provider, capability]` | Typed control adapter | One provider operation and authoritative readback | Perform arbitrary provider calls |
| `AuthorityLeaseOwner` | Node/control adapter boundary | Approved credential request to issued lease and audit identity binding | Store the secret or treat a CLI name as intent |
| `CheckpointAuthorityOwner` | Proposed node/runtime/store module | Create/restore transaction | Exist as authority before its optional phase is approved |
| `StreamAuthorityOwner` | Proposed authenticated stream gate | Attach/port-forward ticket, peer/target/port, meter/fence/result | Create process lineage |
| `QualificationOwner` | Offline release tooling | Registry validation, oracle comparison, ledger, signed envelope | Rewrite detector results or turn degraded into pass |

Adapters authenticate their vendor transport and normalize a candidate payload.
Only `IntentAdmissionOwner` can validate canonical meaning and change
`PENDING -> CLAIMING -> CLAIM_BOUND_PROVISIONAL -> EXEC_COMMITTED` or
`EXEC_FAILED`. Only `NativeSecurityStateOwner` installs the matching task,
process, and domain state. `PolicyActivationOwner` changes only the generation
reference those objects hold.

The same gatherer may expose a cgroup-scoped, read-only observation stream to
Erebor Runtime. Runtime cannot load overlapping BPF programs/maps, assign a
Mithril role, mutate a response, or become another durable owner.

### 35. Delivery Phases

Architecture prose does not authorize implementation. The master plan and the
exact phase file must allocate the work, its tests, and its exit result.

| Phase | Product slice and required exit |
| --- | --- |
| 0 | Freeze license/provenance, Rust/BPF ABI, source and compiled schemas, capability/performance records, source-evidence registry, fixture registry, result words, and golden bytes. Select and prove runtime ordering. |
| 1 | Ship one Rust node process, one loader/pin lease, capability probes, base cgroup/runtime inventory, authenticated local transport, and boot readiness. A second loader cannot own the pin root. |
| 2 | Implement task/process/exec cookies, task-first fork/thread/vfork/non-leader-exec transitions, process/domain state, bootstrap, multiple roots, pending claim identity, and restart reconciliation. |
| 3 | Observe/classify every exec/file/mm/socket/device/privilege/shared-channel operation; run candidate policy simulation and complete bypass/hook inventory. No prevention claim from an unpaired hook. |
| 4 | Enforce signed immutable exec/file/device/privilege policy, entry miss behavior, exact decision precedence, domain joins/publication, and local deny/reject semantics. |
| 5 | Enforce role-aware socket lifecycle, local-inet joins, final destination, DNS/IP floor, packet and established-flow fence, shared-socket blast radius. |
| 6 | Complete source sequences, WAL, coverage intervals, immutable generation recovery, link/map/pin health, restart/reuse truth, and sole-gatherer failure. |
| 7 | Implement `HF-PROC-001`, `HF-DW-001`, authority behavior, deterministic package replay, notification routing, and provider-neutral leases. |
| 8 | Join Kubernetes audit/object/runtime evidence, build typed multi-node graph, and prove fan-out/reuse/contradiction behavior. |
| 9 | Implement response roots, cgroup/socket actions, shared-domain widening, replacement-controller watch, readback, and verified postconditions. |
| 10 | Add separately qualified mesh, AWS, connector, artifact, GitHub evidence/lease/response packages. Each adapter proves identity limits and one typed actuator. |
| 11 | Qualify complete entry admission for each advertised containerd/CRI-O/Kubernetes platform; package, upgrade, scale, performance, and full conformance; sign release claim. |
| 12 | Optional upstream/EDR evidence adapters. They feed the same graph and do not add a second gatherer or authorize named CI adapters. |

#### Contract-to-code route

These are proposed monorepo module families, not final crate names. Phase 0 may
rename them, but it cannot split one durable owner across daemons or omit the
listed proof.

| Contract | First schema / physical phase | Proposed owner and code family | Concrete exit proof |
| --- | --- | --- | --- |
| Shared Rust/BPF ABI, closed enums, map/link manifest, capability and source registries, golden bytes | 0 / 1 | `erebor-linux-sensor-abi`; generated C header + Rust types; `erebor-linux-sensor-host::KernelHostOwner` | Rust/C byte equality; second loader cannot acquire pin-root lease; failed attach is `UNSUPPORTED`. |
| Policy/config YAML, signed compiled artifact, rollback, dispositions | 0 / 4 | `mithril-control::policy_schema`, `PolicyCompiler`; node `PolicyActivationOwner` | `CFG-V1-GOLDEN-002`, duplicate/unknown rejection, rollback/replay, inactive readback, allow/deny probes, one pointer CAS. |
| Fixture/family/claim/qualification schemas | 0 / 11 | `mithril-e2e::qualification_schema` and `QualificationOwner` | `FIXTURE-REGISTRY-COMPLETE-001`; digest splice, missing negative control, degraded-PASS, and wrong platform all reject. |
| Task/process/exec identity and native inheritance | 0 / 2 | `mithril-node::identity::NativeSecurityStateOwner`; owned `lifecycle.bpf.c`, `exec.bpf.c` | Fork-without-exec label before token open; moved-task/non-leader exec/PID reuse/ref cleanup pass. |
| Process/domain/set/mm/publication state | 0 / 2-4 | Same `NativeSecurityStateOwner`; kernel maps hold semantic state, while `KernelHostOwner` only owns their lifecycle | Thread races cannot recover authority; map N+1 fails closed; Rust/BPF decision bytes agree; partial VMA snapshot never relaxes. |
| Runtime entry, held task/root, replay and cgroup binding | 0 / 1-4; platform claim 11 | `mithril-node::admission::IntentAdmissionOwner`, `WorkloadBindingOwner`; runtime adapter only holds/transports | Identical probe/admin/native commands: only exact carried ticket receives role; root cannot run before rootfs binding. |
| File, descriptor, mapping, IPC, process-control and persistent object classification | 0 / observe 3, deny 4 | `mithril-node::effect`; domain transition requested from `NativeSecurityStateOwner` | Symlink/bind/proc-fd/rotation/mmap/fd-pass/io_uring/persistent volume either deny, pre-use join, or return exact unsupported. |
| Socket identity, local-inet domain join, destination, packet fence | 0 / observe 3, deny 5 | `mithril-node::effect::network` | Broad-created socket passed to narrow actor cannot restore egress; loopback/Pod-IP channels join before delivery; established-flow oracle states blast radius. |
| Source sequence, coverage, WAL, restart reconstruction | 0 / 6 | `mithril-node::evidence::{CoverageHealthOwner,LocalEvidenceOwner}`; control `mithril-control::intake` | Ring pressure preserves deny but gaps absence claim; restart changes epoch and reconciles live tasks/sockets/claims before admission. |
| Local and distributed detection graph | 0 / 7-8, provider 10 | `mithril-control::graph`, `mithril-control::detections` | Node-A process to node-B root uses audit/object/binding edges; shared credential plus time remains contextual. |
| Notification delivery | 0 / 7 | `mithril-control::notifications::NotificationRouter` | Secret fields reject; retry/dedupe do not duplicate finding or response; sink outage never relaxes enforcement. |
| Local/Kubernetes/provider response | 0 / 9-10 | `mithril-control::response::ResponseCoordinator`; authenticated node actuator; one provider actuator per capability | Stale PID/object UID denies; shared-domain action widens or returns partial; readback plus healthy watch required for verified. |
| Provider lease/operation/artifact joins | 0 / 7 neutral, 10 exact | `mithril-control::authority`, provider adapter, `AuthorityLeaseOwner` | CLI name grants nothing; exact issuance/session/audit join or weaker branch; secret never enters evidence. |
| Checkpoint and stream authority | 0 logical contract / unallocated physical | Proposed `CheckpointAuthorityOwner`, `StreamAuthorityOwner` | No product claim until master-plan amendment and dormant fixtures activate. |

An adapter milestone is not complete when it receives an event. It must prove
issuer authentication, replay resistance, exact target binding, failure
behavior, and the physical result of every advertised disposition.

The schema phase fixes owner, transitions, failure result, and fixture. It does
not authorize the final mechanism early. A capability advances only through:

```text
SCHEMA_ONLY
  -> FIXTURE_PROTOTYPE
  -> PLATFORM_QUALIFIED
  -> PRODUCT_CLAIM
```

- `SCHEMA_ONLY`: types and compiler behavior exist.
- `FIXTURE_PROTOTYPE`: named hostile fixture passes on a development target.
- `PLATFORM_QUALIFIED`: failure, recovery, performance, and coverage suites pass
  for one exact platform manifest.
- `PRODUCT_CLAIM`: signed release metadata exposes the exact platform, tier,
  limitations, and required configuration.

**Example.** File denial passes on kernel K in Phase 4, but containerd R has not
passed the held-start ordering suite. The product may advertise file denial
for already-bound tasks. It must say strict initial entry on R is unsupported.
The UI cannot combine those facts into “fully protected from first exec.”

#### 35.1 Work that is still unallocated

| Surface | Status now | Honest product result | Required amendment |
| --- | --- | --- | --- |
| Checkpoint create/restore | `UNALLOCATED_OPTIONAL` | `UNSUPPORTED`; dormant fixtures do not block unrelated core release | Add checkpoint owner, runtime/restore matrix, held restore, store actuator, `CHECKPOINT-CREATE-001`, `ENTRY-RESTORE-001`. |
| Attach/port-forward stream | `UNALLOCATED_OPTIONAL` | No authorization/metering claim; ordinary network evidence can remain contextual | Add stream-gate placement, owner, audit/runtime adapters, meter/fence, `ENTRY-STREAM-001`. |
| Named GitHub/GitLab/Jenkins/Tekton adapters and compilable CI policy | `UNALLOCATED_OPTIONAL` | CI contracts remain dormant; no CI1/2/3 claim | Add coordinator roots, runner seam, held task/root transport, closed schema, adapter suite, exact `CI-*` subset. |
| Unmatched-workload hard floor and signed privileged exceptions | `UNALLOCATED_REQUIRED_FOR_FULL_HF_CLAIM` | Full prevention of attacker-created privileged Pod and full HF claim are blocked | Amend Phase 0, chosen runtime phase, and Phase 11 with node-floor schema, pre-setup oracle, `XNODE-PRIVILEGED-POD-001`, `NODE-FLOOR-EXCEPTION-002`. |

Runtime entry cannot be postponed to a late integration task. Phase 0 chooses
and proves the gate; Phase 1 transports authenticated metadata; Phase 2 models
and claims roots; Phase 4 denies missing protected identity; Phase 11 qualifies
each advertised version.

**Stop points.** Stop after each phase's committed code-backed acceptance and
phase-result update. The user approves the next phase. Stop immediately before
implementing any `UNALLOCATED_*` surface, changing one durable owner, adding a
second node process/loader, weakening an invariant/failure result, changing the
policy or signed wire, terminating workload TLS, or widening a response
actuator. Those changes require an explicit master-plan and owning-phase
amendment.

### 36. Defaults That Need Explicit Approval

| Decision | Proposed default | Honest alternative |
| --- | --- | --- |
| Container identity | Several admitted roots per container | One root only after proving every later runtime/kubelet task is its native descendant on every platform. |
| Initial start | Runtime-held, pre-user-exec admission | Post-start is a reduced tier with an explicit gap. |
| Later exec | Held runtime/pidfd gate plus one-use task claim | Unknown external roots deny or observe-only. |
| ExecSync reason | Authenticated reason when budgets differ; otherwise exact equal-budget conservative class or deny | Timing/argv exact classification is rejected. |
| Administrative exec | Default deny or approval on protected workload | Always allow only through separately bounded admin role. |
| `PreStop` during containment | Containment wins unless exact safe cleanup role is approved | Universal bypass is rejected; disable all cleanup with availability cost. |
| Missing protected identity | Fail closed at first protected effect | Fail open is observation-only. |
| Executable identity | Immutable object/image identity | Path-only is a reduced integrity tier. |
| Same TLS endpoint | Provider/semantic gate or honest audit; no MITM | Whole-channel deny blocks both allowed and forbidden verbs. |
| Several logical jobs in one process | Exact native process only; logical job unknown without trusted platform seam | Optional application instrumentation may add identity but is not baseline. |
| Learning | Observations create review-only candidates | Auto-authorizing observed behavior is rejected because compromise trains it. |
| Upstream code | Reuse ideas/code only after Phase 0 license/provenance review; keep Mithril Rust chassis | A fork must replace, not duplicate, the single owner. |
| Intent | One authenticated envelope, issuer adapters, exact live-task claim | Callback is context only unless authenticated, replay-safe, target-bound, expiring, and claimed. |
| `aws`/`gcloud`/`gsutil` | Normal native processes; login is separate authority lease | CLI-specific entry kinds are rejected. |
| Dispositions | Physical `allow`/`deny`/`reject` separate from alert/notification/response | Any unified enum must preserve stage legality and exact meanings. |
| CI | Model real job/step/native/container/service roots and artifact edges | One workflow/Pod tree loses remote jobs, service containers, and artifact causality. |

### 37. When The Architecture Is Actually Complete

Completion is not “the daemon stayed alive” and not “an alert was emitted.” It
requires these eleven results on every advertised platform:

1. Unchanged concurrent workers, lifecycle hooks, probes, init/sidecars, and
   legitimate controllers still work.
2. Every runtime-created root has exact or explicitly conservative evidence
   before its first protected effect.
3. A native child cannot impersonate an external probe/admin/lifecycle root by
   matching bytes, argv, timing, cgroup, namespace, or TTY.
4. The first distinguishable forbidden effect for each advertised
   `HF-008` through `HF-020` branch is physically denied at the claimed stage.
5. In-process, already-open, delegated, shared-channel, and same-TLS cases get
   their honest result; no fabricated file/kernel claim.
6. Identity and distributed causality survive concurrency, restart, reuse,
   fan-out, gaps, late events, duplicates, and contradictions.
7. Local and provider responses re-resolve the target and verify postconditions
   through named healthy coverage intervals.
8. A missing hook, map, reader, WAL interval, audit source, or provider proof
   mechanically narrows the claim.
9. Every policy disposition compiles only to a boundary that can produce that
   physical result. Observe mode says `would_deny` or `would_reject`.
10. Every intent issuer proves authentication, target binding, expiry, replay,
    mismatch, concurrent claim, restart, and live-task consumption. CLI names
    never substitute.
11. Every advertised CI integration passes native/container/service/fan-out,
    artifact/cache/OIDC/credential/deploy/cleanup/cancel/retry/debug/reuse.

The release is decided from a digest-bound artifact set, not from two loose
files: platform manifest, capability bundle, fixture registry, case-level
result bundle, performance bundle, completion ledger, qualification envelope,
and exact signed release claims. Appendix A defines those records. Appendix C
defines the closed fixture set and criterion mapping.

## Appendix A — Exact Record And Release Contracts

This appendix collects the records needed to implement or review the plan.
Chapter text owns behavior; these shapes prevent Rust, C, control, and release
tooling from silently choosing different meanings.

### A.1 Common field rules

| Field | Required representation |
| --- | --- |
| Durable Mithril ID | Opaque 128 bits; equality only; never reused within its declared tenant/node-boot/label-epoch scope |
| Kernel coordinate | Unsigned 64-bit value plus namespace, boot, and live interval; never durable alone |
| Generation/counter | Nonzero unsigned 64-bit value; owner allocates monotonically; overflow opens a new epoch and coverage break |
| Digest | Closed algorithm enum plus fixed-length bytes; no free-form kernel string |
| Node time | Unsigned 64-bit monotonic boottime nanoseconds |
| Remote time | Signed UTC nanoseconds plus uncertainty and source clock information |
| Optional ID | Explicit presence plus value; all-zero bytes never mean absent |
| Enum | Fixed integer width, `UNKNOWN=0`; decoder retains unknown numeric value but enforcement rejects it |
| Collections | Declared maximum, unique/sorted when order is not semantic, rejected on duplicate/overflow |
| Serialization | Restricted duplicate-free source YAML; deterministic CBOR for signed or hashed records |
| Digest/signature | SHA-256 and Ed25519 in Version 1; each record family has a distinct ASCII domain separator |

Phase 0 generates Rust and C layout assertions for every shared BPF ABI type:
size, alignment, field offset, integer width, byte order, enum value, maximum,
and golden bytes. Logical records in this document are not permission to
choose separate convenient layouts.

```text
PortableProfileGenerationV1 {
  profile_id: Id128
  owner_generation: nonzero u64
  compiled_artifact_digest: DigestV1
}

ProfileGenerationRefV1 {
  node_boot_id: Id128
  label_epoch: u64
  generation_ref_id: nonzero u64
  portable_generation_digest: DigestV1
}

ExactObjectGenerationV1 {
  object_kind: REGULAR_FILE | DIRECTORY | PIPE | UNIX_SOCKET |
               INET_SOCKET | MEMFD | SHARED_MEMORY | DEVICE |
               KERNEL_SECURITY_OBJECT | OTHER_QUALIFIED
  authority_scope_id: Id128
  live_object_id: Id128
  object_generation: nonzero u64
  backing_identity_digest: DigestV1
  opened_boottime_ns: u64
  tombstoned_boottime_ns?: u64
}
```

The portable profile identifies a signed artifact across nodes. The node-local
reference is the bounded hot-path handle. Two profiles whose human versions
are both `42` never share a node-local handle.

### A.2 Contract index

| Contract family | Defined behavior and fields |
| --- | --- |
| `KernelCapabilityRecordV1` | Chapter 5: active LSM order, exact hooks/helpers/map types, runtime gate, BTF, program/map/link digests, controlled probe results |
| `ContainerExecutionSet`, `EntrySecurityStateV1`, `TaskLabelV1`, `TaskInstanceV1`, `ProcessSecurityStateV1`, `ProcessInstanceV1`, `AuthorityDomainStateV1`, `ImageProvenance`, `ProcessExecutionInstance` | Chapter 6: exact identity, references, state ownership, live intervals, native relationships |
| `BarrierEvidenceV1`, `RuntimeSetupBudgetV1`, binding/topology snapshot | Chapter 7: exact hold variant, setup sequence, rootfs-ready barrier, object readback |
| `IntentProofEnvelopeV1`, signed body union, trust generation, pending/claim/tombstone records | Chapter 8: canonical signed bytes, target, expiry, sequence/nonce, one-use slot, issuer-independent failure behavior |
| `InvariantQualificationV1` | Chapter 10: one invariant, capability/source proof, stimulus, decision point, physical result, coverage, artifacts, status |
| `PolicyDocumentV1`, signed compiled profile, rollback authorization, `EffectDecisionKeyV1`, generation descriptors | Chapters 11-13: closed source, deterministic compilation, exact conflict rule, activation and retirement |
| Mount/file/VMA/socket/device/publication/process-control records | Chapters 15-21: exact object generation, topology, lifetime, current actor, domain state, begin/end reservations, derived capabilities |
| `ObservationEnvelopeV1`, `CoverageIntervalV1`, `ProofQualityV1`, `FindingV1`, graph nodes/edges | Chapters 22-23: immutable source evidence, gaps, proof axes, finding revisions, causal strength |
| Response plan/target/application/postcondition records | Chapter 24: approval, re-resolution, actuator, readback, watch interval, partial/widened result |
| CI run/job/step/artifact/lease/attestation records | Chapter 26: assurance tier, physical root, trusted materialization seam, typed handoff, exact consumer |

All implementers must use this index. A field needed for a security decision
but absent from the closed record is a schema change, not an undocumented
side map or display annotation.

### A.3 Source evidence

```text
SourceEvidenceClaimV1 {
  evidence_id
  project: KUBEARMOR | TETRAGON | LINUX | OCI | KUBERNETES | PROVIDER
  repository_url
  commit_or_version
  path
  first_line, last_line: nonzero u32
  blob_digest: DigestV1
  observation
  boundary_nature: IMPLEMENTATION_CHOICE | PLATFORM_CONTRACT |
                   PROTOCOL_BOUNDARY | CONFIGURATION_BOUNDARY
  assertion_mode: SOURCE_PROVES | SOURCE_SUPPORTS | INFERENCE | HOSTILE_HYPOTHESIS
  relationship: ADOPT | HARDEN | HOSTILE_TEST | DO_NOT_INHERIT | CONTEXT_ONLY
  dependent_fixture_ids[]
  reviewed_by
  reviewed_at_utc_ns
  claim_digest: DigestV1
}
```

`boundary_nature` and `relationship` are separate. For example, a mutable map
update is an implementation choice and `HARDEN`; TLS payload opacity is a
protocol boundary and may be `CONTEXT_ONLY` plus a provider-gate requirement.
The display table cannot infer either field from a generic “kind.”

### A.4 Capability and performance bundles

```text
CapabilityRecordV1 {
  capability_id
  capability_schema_version: u32
  platform_support_manifest_digest, product_build_digest: DigestV1
  node_or_fixture_platform_id
  probe_input_digest, observed_kernel_runtime_result_digest: DigestV1
  state: SUPPORTED | UNSUPPORTED | DEGRADED | UNHEALTHY
  reason_code
  measured_at_utc_ns: i64
}

CapabilityBundleV1 {
  bundle_version: exactly 1
  architecture_revision_digest, product_build_digest: DigestV1
  platform_support_manifest_digest: DigestV1
  capability_records[]: sorted unique by capability_id
  canonical_payload_digest: DigestV1
  signer_key_id
  signature
}
```

The closed performance records are in Chapter 33. Their unsigned bundle is
signed over:

```text
ASCII("MITHRIL-PERFORMANCE-BUNDLE-V1") || 0x00 ||
SHA-256(canonical_unsigned_bundle)
```

The capability bundle uses `MITHRIL-CAPABILITY-BUNDLE-V1`. The unsigned view
omits payload digest, key ID, and signature; the stored digest is recomputed.
Unknown operation/resource IDs require a checked-in registry update.

### A.5 Closed platform assurance and exact claims

Every field below exists even when unsupported. An implementation cannot hide
a family by omitting it.

```text
AssuranceAxesV1 {
  boot_and_admission_availability
  initial_runtime_entry
  later_runtime_entry_and_streaming
  checkpoint_restore_and_attach
  native_task_process_exec_identity
  policy_generation_and_cgroup_binding
  mount_topology_and_namespace
  file_object_namespace_and_io
  vma_and_executable_memory
  process_and_authority_domain_state
  cross_entry_shared_resource_flow
  socket_network_and_dns
  device_and_derived_kernel_objects
  privilege_kernel_escape_and_self_protection
  seccomp_floor
  landlock_floor
  local_evidence_and_coverage_truth
  multi_node_and_provider_graph
  kubernetes_and_provider_semantic_authority
  artifact_provenance_and_trust
  local_and_distributed_response
  ci_execution_and_artifact_identity
  performance_and_capacity
}

AssuranceAxisRecordV1 {
  capability_record_ids[]
  supported_stages: subset of ENTRY_ADMISSION | NATIVE_TRANSITION |
                    LOCAL_PRE_EFFECT | REMOTE_PRE_ADMISSION |
                    POST_EFFECT | RESPONSE
  claim_vector_ids[]
  required_fixture_ids[]
  passed_result_ids[]
  unsupported_or_degraded_paths[]
}

PlatformSupportManifestV1 {
  schema_version: exactly 1
  manifest_id: Id128
  architecture_revision_digest, product_build_digest: DigestV1
  architecture: X86_64 | AARCH64
  kernel_release_build_id_and_btf_digest: DigestV1
  boot_config_and_lsm_order_digest: DigestV1
  landlock_capability_record_id?: Id128
  seccomp_capability_record_id?: Id128
  container_runtime_name_version_config_digest: DigestV1
  kubernetes_version_and_streaming_shape_digest?: DigestV1
  bpf_program_link_map_manifest_digest, capability_bundle_digest: DigestV1
  assurance_axes: AssuranceAxesV1
  unsupported_paths[]: sorted unique UnsupportedPathV1
  claim_vector_ids[]: sorted unique Id128
  performance_qualification_record_ids[]: sorted unique Id128
  canonical_payload_digest: DigestV1
  signer_key_id
  signature
}

ClaimVectorV1 {
  claim_vector_id
  assurance_axis: closed member of AssuranceAxesV1
  object_family
  operation
  evaluation_stage
  authority_boundary
  result: CONTEXTUAL_OBSERVATION | EXACT_OBSERVATION | PRE_EFFECT_DENIAL |
          SEMANTIC_REJECTION | VERIFIED_RESPONSE | UNSUPPORTED
  proof_quality: ProofQualityV1
  capability_record_ids[]
  required_fixture_ids[]
  passed_fixture_result_ids[]
  required_coverage_predicates[]
  unsupported_path?: UnsupportedPathV1
  performance_qualification_id?
}

UnsupportedPathV1 {
  object_family, operation, stage
  missing_capability_or_evidence
  degraded_result
  prohibited_product_statements[]
}
```

An assurance axis is only an index. It never grants policy authority or a
marketing statement. For example, the network axis may simultaneously contain
TCP connect denial, packet observation, and unsupported same-TLS provider verb.
Only an exact `ClaimVectorV1` can back a release statement.

### A.6 Fixture registry and case results

One fixture may have several branches. Each branch owns its own stimulus,
stage, result, coverage, and oracle.

```text
FixtureAllocationConditionV1 =
  ALWAYS | WHEN_CLAIM_VECTOR_REFERENCES |
  WHEN_SURFACE_ALLOCATED_AND_ADVERTISED

FixtureCaseV1 {
  case_id: stable unique lowercase ASCII within fixture
  allocation_condition: FixtureAllocationConditionV1
  topology_digest, starting_state_digest, stimulus_digest: DigestV1
  expected_stage: ENTRY_ADMISSION | NATIVE_TRANSITION | LOCAL_PRE_EFFECT |
                  REMOTE_PRE_ADMISSION | POST_EFFECT | RESPONSE
  expected_disposition: ADMIT | AUDIT_ADMIT | REJECT_REQUEST |
                        ALLOW_EFFECT | AUDIT_ALLOW_EFFECT | DENY_ERRNO |
                        RECORD_ONLY | FINDING | RESPONSE_PROPOSAL |
                        VERIFIED_RESPONSE | UNSUPPORTED
  expected_result: closed result enum or registered result ID
  required_coverage_predicates[]
  oracle_schema
  oracle_validator_id
  oracle_artifact_expectation_digest: DigestV1
  negative_control_case_ids[]
  degraded_result: UNSUPPORTED | INSUFFICIENT_COVERAGE |
                   OBSERVATION_ONLY | NOT_APPLICABLE
}

NormativeFixtureRegistryV1 {
  architecture_revision_digest: DigestV1
  fixtures[] {
    fixture_id
    id_kind: FIXTURE | META_TEST
    source_section_id
    owning_phase_and_crate
    criterion_numbers[]
    assurance_axes[]
    prerequisite_capability_ids[]
    upstream_source_evidence_ids[]
    cases[1..256]: FixtureCaseV1
  }
}

FixtureCaseResultV1 {
  fixture_id, case_id
  starting_state_digest, stimulus_digest: DigestV1
  observed_stage, observed_disposition, observed_result
  observed_coverage_interval_ids[]
  oracle_artifact_ids[]
  canonical_oracle_digest: DigestV1
  negative_control_case_result_ids[]
  result: PASS | FAIL | UNSUPPORTED | INSUFFICIENT_COVERAGE
}

FixtureAggregateResultV1 {
  fixture_id
  active_case_ids[], dormant_case_ids[]
  case_results[]: FixtureCaseResultV1
  aggregate_result: PASS | FAIL | UNSUPPORTED | INSUFFICIENT_COVERAGE
}

FixtureResultBundleV1 {
  result_bundle_id
  product_build_digest, platform_support_manifest_digest: DigestV1
  fixture_registry_digest: DigestV1
  fixture_results[]: sorted unique by fixture_id
  canonical_payload_digest: DigestV1
  signer_key_id
  signature
}
```

A fixture passes only if every active case, exact negative control, coverage
predicate, and oracle passes. Dormant optional cases cannot satisfy a claim but
do not block an unrelated core release. Wildcards, prose families, card IDs,
and source-evidence IDs are invalid where a fixture ID is required.

The checked-in sources of truth will be
`spec/qualification/v1/fixtures.yaml` and
`spec/qualification/v1/families.yaml` in the future monorepo. Both use
restricted YAML and deterministic CBOR. Generated result bundles never edit
them.

### A.7 Canonical comparison, ledger, and signed release

Random IDs, boot IDs, timestamps, and delivery order prevent raw byte-for-byte
comparison. The comparator normalizes only declared display variability:

```text
CanonicalOracleComparatorV1 {
  schema_version: exactly 1
  fixture_alias_bindings: authoritative actual IDs -> fixture logical slots
  time_normalization: absolute time -> signed offset/interval from stimulus
  sequence_normalization: preserve per-source order and explicit gaps
  collection_rules: ordered_list | key_sorted_set | counted_multiset
  ignored_display_fields[]: closed registry; never proof/result/security fields
  exact_fields[]
  interval_predicates[]
  expected_canonical_digest: DigestV1
}

CompletionLedgerV1 {
  ledger_id
  architecture_revision_digest, product_build_digest: DigestV1
  platform_support_manifest_digest, capability_bundle_digest: DigestV1
  fixture_registry_digest, fixture_result_bundle_digest: DigestV1
  performance_qualification_bundle_digest: DigestV1
  criteria[] {
    criterion_number: 1..11
    claim_vector_ids[]
    prerequisite_capability_ids[]
    acceptance_fixture_ids[]
    accepted_result: PASS
    result_artifact_ids[]
    status: PASS | FAIL | UNSUPPORTED | INSUFFICIENT_COVERAGE
  }
}

QualificationEnvelopeV1 {
  qualification_id
  architecture_revision_digest, product_build_digest: DigestV1
  platform_support_manifest_digest, capability_bundle_digest: DigestV1
  fixture_registry_digest, fixture_result_bundle_digest: DigestV1
  completion_ledger_digest, performance_qualification_bundle_digest: DigestV1
  generated_at_utc
  release_qualifier_identity
  signature_key_id
  canonical_payload_digest: DigestV1
  signature
}

ReleaseClaimV1 {
  claim_id
  qualification_envelope_digest: DigestV1
  claim_vector_ids[]
  human_statement
  valid_for_exact_platform_manifest_digest: DigestV1
  signature
}
```

The qualifier checks every signature and digest, exact fixture-set equality,
platform/build equality, coverage predicate, negative control, oracle, and
performance threshold. Data from another node, kernel, build, or registry
cannot be spliced in. A required non-`PASS` case makes every dependent claim
ineligible.

### A.8 Complete Version 1 type-ownership catalog

The original architecture named every type below. This catalog retains those
names, gives each one a single job, and connects it to the simpler chapter
model. It is not permission to implement one Rust struct per row when several
are naturally a closed enum body or generated ABI view. It is permission to
reject an implementation that silently drops the information.

#### A.8.1 Policy source, registries, and compilation

| Type | One job |
| --- | --- |
| `PolicyLocalIdV1` | Bounded ID that is meaningful only inside one signed profile; never a global object identity |
| `RegistrySymbolV1` | Numeric registry ID plus digest-bound human symbol for explanation |
| `ObjectClassIdV1` | Closed composite object-class atom selected by the compiler |
| `ReasonCodeIdV1` | Closed machine reason; free-form text cannot drive authority |
| `ResultCodeIdV1` | Closed physical/semantic result identity |
| `ProviderV1` | Registered provider and vocabulary generation |
| `PackageIdV1` | Registered deterministic detection/correlation package |
| `CanonicalArgvV1` | Length-delimited raw argument bytes; no shell parsing or Unicode/whitespace folding |
| `WorkloadSelectorV1` | Userspace candidate selector; never kernel authority |
| `ObjectClassifierSelectorV1` | Source selector for one classifier binding |
| `ObjectClassifierBindingV1` | Signed mapping from selector/axis input to classifier registry generation |
| `ObjectClassifierRegistryV1` | Closed classifier IDs, axes, versions, and capability requirements |
| `ClassifierAxisValueV1` | One typed value in a composite object atom |
| `ResolvedObjectClassBindingV1` | Exact bound workload/object snapshot and classifier generation |
| `CompositeDecisionAtomV1` | Finite cross-product of all required object axes; missing axis is not wildcard |
| `ExactObjectKindV1` | Closed regular-file/directory/pipe/socket/memfd/shared-memory/device/kernel-object kind |
| `ResourceSelectorV1` | Typed provider/Kubernetes/artifact resource selector with closed fields and bounds |
| `DefaultPosturesV1` | Explicit defaults for entry, transition, each effect family, and failures |
| `DefaultPostureActionV1` | Closed default physical result at one legal stage |
| `EffectFamilyDefaultV1` | One explicit reachable default decision per effect family |
| `AuthorityBehaviorRuleV1` | Provider/authority semantic rule at remote pre-admission or post-effect |
| `DomainSensitiveStateRuleV1` | Monotonic rule that adds or checks domain-sensitive state |
| `DetectionDispositionRuleV1` | Human allow/alert/deny/reject plus finding/notification/response bindings |
| `FallbackV1` | Explicit degraded result for a named missing capability/source; never issuer-selected fail-open |
| `BudgetSetV1` | Bounded counts, rates, lifetimes, concurrency, and depth |
| `ExceptionV1` | Signed, expiring, scoped authority delta with uses and approver |
| `ExactExceptionSubjectSelectorV1` | Immutable exact workload/entry/role/key subject of an exception; no `*` |
| `PermittedAuthorityDeltaV1` | Machine-readable permission widening or narrowing that an exception requests |
| `RolloutV1` | Immutable rollout population, time window, stop conditions, and health denominator |
| `NotificationRouteV1` | Approved sink, sensitivity allowlist, dedupe/retry, and failure posture |
| `ProvisionedNotificationSinkBindingV1` | Exact live sink instance and secret-free delivery handle |
| `FindingSpecV1` | Finding code, grouping, proof/coverage predicates, severity, and revision behavior |
| `FindingGroupingFieldV1` | Closed grouping field; unavailable fields cannot collapse unrelated findings |
| `CorrelationPackageBindingV1` | Profile binding to exact signed correlation package/version |
| `SignedCorrelationPackageRegistryV1` | Trusted deterministic package code/schema/digest registry |
| `StaticExpandedProfileV1` | Fully expanded finite policy before kernel lowering |
| `NormalizedDecisionCellV1` | One exact conflict-checked stage/actor/effect/object/state result |
| `CompiledActionPlanV1` | Legal physical decision plus evidence, finding, notification, response, and degradation |
| `SignedWorkloadProtectionProfileV1` | Canonical profile bytes, registry/header digests, issuer sequence, signature |
| `ProfileSignatureHeaderV1` | Domain/version/algorithm and all registry digests bound by profile signature |
| `RollbackAuthorizationPayloadV1` | Current and target profile digests/versions, platform, reason, expiry, nonce |
| `SignedRollbackAuthorizationV1` | One-use signed wrapper around rollback payload |
| `RollbackAuthorizationV1` | Verified, replay-checked rollback decision used by activation |
| `SupersessionRegistryV1` | Retained statement -> controlling statement relation with reason and proof |
| `SupersessionHeadingSetV1` | Docs-lint set of abandoned/corrected headings that must have markers |

#### A.8.2 Entries, tasks, processes, and intent

| Type | One job |
| --- | --- |
| `EntryKindV1` | Closed external-root reason: initial, probe, lifecycle, admin, host-runtime, CI, restore, and registered variants |
| `EntryClassificationV1` | Exact or conservative classification, candidate set, proof, and ambiguity result |
| `EntryRoleAssignmentV1` | Entry claim -> initial process role and retained profile generation |
| `EntryAdmissionMatchV1` | Bound policy predicate for one external entry request |
| `PreparedExternalRootStateV1` | Held root's task/cgroup/intent/binding state before final user exec |
| `ExecutionSetBindingStateV1` | Container execution-set lifecycle and exact cgroup binding |
| `BindingLifecycleStateV1` | PREPARING/BOUND/TERMINATING/TOMBSTONED floor applied to task/object decisions |
| `WorkloadBindingActivationStateV1` | Node transaction from prepared binding through active/terminating/tombstoned |
| `WorkloadBindingArtifactV1` | Signed/hashed Pod-container-image-cgroup-profile binding proof |
| `NodeAdmissionFieldKeyV1` / `NodeAdmissionFieldV1` | Closed node-floor request field and typed value |
| `NodeHardFloorDecisionV1` | Pre-setup allow/reject for unmatched workload plus exact exception proof |
| `TaskPlacementExpectationV1` | Expected protected-root binding nonce and allowed placement during a transition |
| `TaskCoordinateHistoryV1` | Append-only TID/TGID/PID namespace/start/pidfd live intervals |
| `CreatedByEdgeV1` | Immutable creator task/process -> child task/process relationship |
| `KernelRealParentIntervalV1` | Changing Linux real-parent coordinate with reason and time interval |
| `TaskLifetimeOwnershipV1` | Exactly-once owned task/entry/process/domain reference bits and tombstone |
| `ProcessLifetimeOwnershipV1` | Exactly-once thread, entry, domain, and execution lifetime references |
| `TaskReferenceTombstoneV1` | Durable proof that a task-owned reference was released once |
| `TaskEffectAttemptStateV1` | Bounded in-flight state for clone/exec/effect commit and failure cleanup |
| `ProcessStateVectorV1` | Current role, exec state, sensitive bits, response set, domain, generation refs |
| `ProcessStateBitV1` | One registered monotonic process restriction/state bit |
| `ProcessStateDefinitionV1` | Allowed state-vector shape and transitions for one profile |
| `RoleDefinitionV1` | Entry origins, base effects, budgets, transitions, and authority behavior for one role |
| `TransitionKindV1` / `NativeOperationV1` | Closed fork/thread/vfork/exec/credential native operation |
| `RuntimeOperationV1` | Closed setup/rootfs/exec/restore/stream operation used by runtime admission budgets |
| `NativeRoleTransitionRuleV1` | Source role + native operation + target -> one target role/restriction |
| `NativeTransitionMatchV1` | Exact current state and operation selector |
| `TransitionDescriptorV1` | Compiled transition result, reference effects, and evidence rule |
| `ProcessTransitionKeyV1` / `ProcessTransitionValueV1` | Kernel exact-key and result for native transition |
| `TransitionIntentV1` | Signed high-level intent to perform an otherwise external/native transition |
| `NativeTransitionBodyV1` | Closed signed-intent body for a native transition |
| `IntentKindV1` | Closed body union tag; CI is value `7` in this architecture |
| `IntentBodyV1` / `IntentPayloadV1` | Canonical target-bound signed body union and common claims |
| `RuntimeEntryBodyV1` | Runtime-created root body: entry kind, Pod/container, task/hold, command/definition, budgets |
| `KubeletExecutionRequestV1` | Kubelet-signed probe/lifecycle request and exact declaration generation |
| `ExactRequestIdentityV1` | Stable request/attempt/issuer identity used for replay and graph joins |
| `KernelClaimTombstoneV1` | Pinned consumed/rejected claim fact that survives userspace restart |
| `TokenConsumptionObservationV1` | Exact claim/lease/token-handle consumption attempt and result, not secret bytes |
| `RuntimeEntryIntentV1` | **Abandoned name** replaced by `IntentPayloadV1(kind=RUNTIME_ENTRY)` plus `RuntimeEntryBodyV1` |

#### A.8.3 Compiled generation and decision ABI

| Type | One job |
| --- | --- |
| `NodeBoundProfileGenerationV1` | Portable signed generation bound to one node-local nonreused handle |
| `BindingGenerationStateV1` | Active/retiring generation and typed holder counts for one workload binding |
| `GenerationReferenceClassV1` | Closed holder type: task, socket, domain, pending claim, response, and registered object |
| `GenerationReferenceTombstoneV1` | Durable exactly-once release of a generation reference |
| `BindingRetainedGenerationKeyV1` / `BindingRetainedGenerationValueV1` | Binding + generation-class counter and state |
| `GenerationMembershipKeyV1` / `GenerationMembershipValueV1` | Exact object belongs to one installed generation descriptor |
| `GenerationSetDescriptorV1` | Bounds/digest/membership for installed generation set |
| `DecisionSetDescriptorV1` | Bounds/digest/default/capability data for one exact decision set |
| `RestrictionSetDescriptorV1` | Bounds/digest for a negative restriction set |
| `ResponseSetDescriptorV1` | Bounds/digest for effective response restrictions |
| `SetKindV1` | Closed decision/restriction/response/generation set family |
| `SetRefV1` | Typed nonzero installed set handle plus generation/epoch |
| `SetReferenceClassV1` / `SetReferenceTombstoneV1` | Typed exactly-once holder and release proof for a set |
| `RestrictionDefaultKeyV1` | Explicit default cell for one restriction family |
| `EffectDefaultKeyV1` | Explicit default cell for a local effect family |
| `ResponseDefaultKeyV1` | Explicit default cell for response restrictions |
| `BindingLifetimeFloorKeyV1` | Binding lifecycle restriction cell |
| `ExactObjectFloorKeyV1` | Exact object-generation lifetime floor |
| `ExactSocketOrChannelFloorKeyV1` | Exact socket/channel-generation lifetime floor |
| `FloorRequirementKeyV1` / `FloorRequirementValueV1` | Whether a cell needs explicit-neutral or dynamic-required floor template |
| `DynamicFloorTemplateV1` | Precompiled state installed at object/channel creation/acquisition |
| `DynamicFloorStateV1` | Exact live installed floor and references |
| `RestrictionDecisionKeyV1` / `RestrictionDecisionV1` | Exact actor/state/object negative restriction result |
| `RestrictionFloorV1` | One monotonic allow-preserving or authority-narrowing floor |
| `CachedDecisionKeyV1` | **Rejected as authority**; may cache explanation only, never final allow |
| `LabelRequirementV1` | Required task/process/domain/binding state for a decision cell |
| `LookupStepV1` | Closed ordered lookup description used by Rust/BPF golden tests |
| `PhysicalDecisionV1` | Allow, audit-allow, or exact errno with stage and state transition |
| `EffectDecisionKeyV1` | Role/effect/operation/composite object/process-domain-lifecycle exact key |
| `MonotonicSetTransitionKeyV1` / `MonotonicSetTransitionValueV1` | Precompiled atomic old-set -> stricter-new-set transition |
| `DomainSensitiveTransitionKeyV1` / `DomainSensitiveTransitionValueV1` | Atomic old-domain-sensitive state -> stricter state transition |

#### A.8.4 Mounts, files, memory, publication, and shared authority

| Type | One job |
| --- | --- |
| `MountNamespaceStateV1` | Mount namespace identity, topology generation, CLEAN/DIRTY state, snapshot digest, live interval |
| `MountSecurityViewV1` | Actor-visible mount/root/propagation/read-only/security view used for object resolution |
| `MountSourceClassRecordV1` | Exact declared/image/projected/host/device/remote mount source classification |
| `VolumeMountBarrierV1` | Rootfs-ready held transaction that binds every required mounted object before release |
| `FileObjectIdentityV1` | Mount namespace generation + mount/fs/inode/version/live identity and object kind |
| `FileInstanceProvenanceV1` | Open-time file identity, source object, opener, generation, fd transfer/mapping provenance |
| `CreateKeyV1`, `SetattrKeyV1`, `RenameKeyV1`, `LinkKeyV1`, `UnlinkKeyV1` | Exact filesystem namespace mutation keys; no path-only authority |
| `SourceMutabilityProofV1` | Seals/verity/IMA/content lease and time at which source bytes were immutable |
| `KernelExecutableMappingClassV1` | File/anonymous/memfd/JIT mapping, write/execute history, loader purpose |
| `MmSnapshotIdentityV1` | Exact mm cookie, sharing generation, snapshot version, begin/end state |
| `VmaIteratorSessionIdentityV1` | Node/boot/mm/snapshot/session identity for one iterator run |
| `VmaIteratorSessionV1` | BEGIN/RECORD/END lifecycle, expected sharers, counters, gaps, outcome |
| `VmaIteratorFrameV1` | One exact VMA range, backing, permissions, provenance, and sequence |
| `VmaSnapshotV1` | Canonical complete or typed-partial set of frames and sharers |
| `CommunicationAuthorityDomainV1` | Logical set of processes/resources that can pass protected authority |
| `DomainSensitiveBitV1` | Registered monotonic shared restriction such as token-read or untrusted-artifact |
| `SharedResourceStateV1` | Exact pipe/socket/file/mm/device/shared object plus domain refs and restrictions |
| `CrossEntryTransferControlV1` | Pre-use allow/deny/join decision for authority crossing entry roots |
| `IpcCapabilityTransferV1` | Sender, receiver, exact fd/object/capability, domain result, completion |
| `AuthorityDomainJoinTransactionV1` | Crash-recoverable prepare/freeze-or-hold/redirect/commit/drain join |
| `DomainJoinQuiescenceV1` | Proof that required members/channels cannot act during a join step |
| `DomainJoinRootProgressV1` | Per-old-domain preparation/redirect/reference-drain progress |
| `DomainJoinTargetProgressV1` | New intersection-domain creation, state union, activation progress |
| `LocalInetChannelIdentityV1` | Netns/protocol/address/port/listener/socket generation and local peer set |
| `PublicationIdAllocatorV1` | Nonreused publication IDs per node boot/epoch with fatal rollback behavior |
| `PublicationSlotV1` | Reserved bounded publication attempt before source becomes visible to sink |
| `PublicationLeaseStateV1` | FREE/PREPARED/ACTIVE/COMPLETED/FAILED/TOMBSTONED state and owner |
| `PublicationDescriptorV1` | Exact source segments, sink, operation, actor/domain, policy, oracle, budgets |
| `PublicationDescriptorLifetimeV1` | Reference/tombstone state until copy/send/provider completion is known |
| `PublicationTransferPlanV1` | Bounded ordered transfer operations and required completion observations |
| `PublicationPayloadSourceV1` | Exact user buffer/file/map/pipe/splice source and provenance |
| `UserBufferSegmentV1` | User address range, mm identity, mutability lease, length, digest if proved |
| `PublicationInstanceV1` | One attempted/permitted/completed publication result and byte/packet/provider counts |
| `AuthorityDomainPublicationStateV1` | Shared pending/active publication restrictions and counters for a domain |
| `PersistentPublicationCapabilityV1` | Authority retained by a persistent file/volume/socket/artifact after processes exit |
| `PersistentFileSecurityStateV1` | Persistent object restrictions, producer domain, generation refs, consumer joins |
| `ExactPublicationSinkV1` | Exact fd/socket/file/provider destination generation and result boundary |
| `LocalObjectSelectorV1` | Compiler-owned exact local object selection input; paths remain explanation |

#### A.8.5 Network, devices, and privilege

| Type | One job |
| --- | --- |
| `NetworkEffectKeyV1` | Current actor/domain + socket/netns + operation + final destination/protocol exact key |
| `SocketProvenanceV1` | Immutable creator identity/domain/generation and later owner/pass/accept history |
| `ResolvedSocketOrChannelGenerationV1` | Exact socket/channel lifetime after bind/connect/accept/redirect resolution |
| `SocketControlEffectKeyV1` | `setsockopt`, bind/listen/accept/shutdown and other socket-control operation key |
| `DestinationPolicyRecordV1` | Versioned address/service/port/protocol class, final-route proof, packet requirement |
| `DeviceClassRecordV1` | Device type, major/minor, path-independent class, approved operation/ioctl registry |
| `DeviceFileEffectKeyV1` | Current actor + exact device fd/generation + open/read/write/ioctl/mmap key |
| `DerivedKernelCapabilityObjectV1` | TUN, io_uring, BPF link/map, perf, KVM/GPU context, keyring, pidfd, or similar authority-bearing object |
| `SecurityObjectRecordV1` | Exact process/kernel security target for ptrace, credentials, namespaces, module, BPF, perf, keyring, proc/sysctl |
| `SeccompFloorProofV1` | Required filter installed before user mode, TSYNC/result, no-new-privs, listener/supervisor policy, readback |

#### A.8.6 Evidence, graph, findings, and response

| Type | One job |
| --- | --- |
| `EvidenceBoundaryNatureV1` | Implementation, platform, protocol, or configuration boundary |
| `EvidenceAssertionModeV1` | Source proves/supports, inference, or hostile hypothesis |
| `EvidenceRelationshipV1` | Adopt, harden, hostile-test, do-not-inherit, or context-only |
| `SourceRangeV1` | Repository/commit/path/line/blob identity for one atomic source claim |
| `EvidenceFieldV1` | Typed canonical observation field with sensitivity, presence, provenance, and proof |
| `SourceCoverageHealthRuleV1` | Links source capabilities/gaps to allowed negative and result claims |
| `ProofQualityPredicateV1` | Per-axis minimum and missing-axis behavior for a package/claim |
| `ProviderResultBoundaryV1` | Request accepted/rejected/succeeded/failed/unknown and whether pre- or post-effect |
| `ProviderPrincipalV1` | Provider-native account/session/installation/service identity and proof |
| `LocalAuthoritySubjectV1` | Exact node/task/process/entry/domain/workload subject |
| `CommonSubjectMatchV1` | Bounded identity/time/request join predicate shared by two evidence sources |
| `GraphSubjectV1` | Versioned node in causal graph with exact/contextual/contradicted identity state |
| `CausalSubjectV1` | Normalized local, workload, provider, human, artifact, or external subject union |
| `GraphEdgeV1` | Typed direction, cause strength, join fields, time uncertainty, source IDs, version |
| `GraphVersionV1` | Immutable graph revision, input watermark, package versions, parent revision digest |
| `HfRepresentativeActionCaseV1` | One of the 21 normalized incident actions, branches, controls, result, proof |
| `HfGranularAcceptanceV1` | Smaller published incident action branch with exact fixture/oracle/source links |
| `ResponseActionSpecV1` | Typed local/provider action, required approval, blast radius, target, postcondition |
| `ResponseBindingV1` | Finding/package/result -> allowed response spec and policy version |
| `ResponsePlanV1` | Authorized immutable set of actions, target revisions, ordering, rollback/expiry |
| `ResponseDecisionKeyV1` / `ResponseDecisionV1` | Exact local response restriction lookup and result |
| `TargetRevalidationV1` | Re-resolved live pidfd/cgroup/socket/object/provider target before actuation |
| `BlastRadiusLimitV1` | Maximum tasks/domains/workloads/sockets/resources that approval permits |
| `PhysicalPostconditionV1` | Exact readback and healthy watch predicate that makes response verified |

#### A.8.7 Provider, deployment, artifact, and CI intent

| Type | One job |
| --- | --- |
| `AuthorityLeaseBodyV1` | Signed request for a narrowly scoped provider lease tied to exact task/job and TTL |
| `TokenIssuanceLedgerV1` | Provider issuance result, handle/fingerprint, scope, subject, expiry, revocation capability |
| `ProviderOperationBodyV1` | Closed provider vocabulary operation/resource/principal/result body |
| `RemoteAdmissionMatchV1` | Synchronous provider/admission rule key and exact request subject |
| `PostEffectMatchV1` | Authoritative completed provider/audit operation match |
| `DeploymentAdmissionBodyV1` | Deployment object/digest/environment/approval/actor pre-admission request |
| `DeploymentAdmissionIntentV1` | **Abandoned wrapper name**; represented by common intent plus `DeploymentAdmissionBodyV1` |
| `CheckpointCreationRequestV1` | Optional exact checkpoint-export target set, storage sink, authority, and result; unallocated |
| `StreamAuthorityV1` | Optional attach/port-forward peer, target, port, direction, meter/fence, and result; unallocated |
| `ArtifactKindV1` / `ArtifactOperationV1` | Closed source/package/cache/image/checkpoint/artifact kind and create/read/execute/promote/quarantine operation |
| `ArtifactInstanceV1` | Digest, producer, source revision, trust, mutability, attestation, storage and live interval |
| `ArtifactConsumerSlotV1` | One-use exact consumer/purpose/policy binding |
| `ArtifactHandoffBodyV1` | Signed producer-to-consumer artifact/cache/workspace handoff body |
| `ArtifactHandoffIntentV1` | **Abandoned wrapper name**; common intent plus `ArtifactHandoffBodyV1` |
| `AttestationVerificationV1` | Trust chain/revocation, predicate, builder, subject, source, materials, transparency, freshness, result |
| `CiExecutionShapeV1` | Native step, job container, container action, service, matrix, remote workflow, deploy, post, debug, DinD |
| `CiTriggerTrustClassV1` | Trusted branch, untrusted PR, scheduled, manual, dependency/reusable source trust |
| `ProducerTrustClassV1` | Trust assigned to exact bytes/artifact producer, never workflow display name |
| `CiProviderJobAssignmentEvidenceV1` | Provider-authenticated run/job/check attempt and assigned runner identity |
| `StepDefinitionIdentityV1` | Workflow step/action definition plus immutable referenced revision and declared inputs |
| `MaterializedStepInvocationV1` | Actual sealed script/interpreter/image/argv/cwd/public env/input digests and held child |
| `CiTrustedRunnerStepLaunchAttestationV1` | Node-signed proof that trusted runner control materialized and holds exact step task/root |
| `CiStepIntentBodyV1` | Common intent kind 7 body for exact run/job/attempt/step/runner/materialization |
| `CiStepAdmissionJoinV1` | Provider job assignment + runner attestation + node held task/root join result |
| `CiExecutionBindingV1` | Active step/job role, cgroup/root/native tree, policy, workspace, credential audiences |
| `JobExecutionEpochV1` | Nonreused run/job/attempt/runner reuse boundary and cleanup tombstone |
| `CiStateArtifactV1` | `GITHUB_ENV`, PATH, outputs, workspace, cache, socket, background process, or startup-file handoff with producer trust |
| `CiCoordinatorV1` | Registered coordinator adapter trust/version/capabilities; remains unallocated for named products |
| `CiPolicyV1` | Closed future CI policy surface; parser rejects it until allocated |

#### A.8.8 Qualification-only and deprecated record names

| Type | Status and meaning |
| --- | --- |
| `ImplementationCardV1` | Human implementation card that must map to a distinct executable fixture ID |
| `FixtureFamilyV1` | Explicit nonempty sorted fixture membership; wildcards forbidden |
| `NormativeFixtureSetV1` | Exact fixture-ID set printed in Appendix C.1 |
| `CriterionFixtureRequirementV1` | Criterion 1..11 + allocation condition + exact fixture IDs from Appendix C.2 |
| `ExactCompletionIdentityV1` | Exact architecture/build/platform/registry/result/performance digest tuple under qualification |
| `PerformanceQualificationV1` | **Abandoned untyped sketch** replaced by the typed Chapter 33 records |

Types such as `LocalEffectMatchV1`, `DeviceFileEffectKeyV1`,
`SocketControlEffectKeyV1`, and `EntryAdmissionMatchV1` are compiler inputs to
one normalized decision cell. They do not create parallel policy engines.
Types such as `RuntimeEntryIntentV1`, `DeploymentAdmissionIntentV1`, and
`ArtifactHandoffIntentV1` remain only to document old names; the wire uses the
single signed intent envelope and a closed body union.

## Appendix B — Rejected Designs And Their Replacements

The original architecture kept its mistakes visible. This rewrite does the
same in one index so an implementer does not accidentally revive them.

### B.1 Product, evidence, and upstream lessons

| Rejected or corrected idea | Why it is wrong | Replacement in this document |
| --- | --- | --- |
| Put every local decision in BPF | Policy compilation, signatures, provider meaning, graph correlation, and approval do not belong in a bounded hook | Rust/control prepares authority; BPF makes only bounded local pre-effect decisions (Chapters 5, 12-13) |
| Exact attribution implies narrow actuation | A precise task may share a socket/domain/cgroup with others | Response reports and verifies actual blast radius (Chapters 18-19, 24) |
| Infer machine evidence behavior from a display `Kind` | Boundary nature and Mithril relationship are independent fields | `SourceEvidenceClaimV1` stores both (Appendix A.3) |
| KubeArmor map-of-maps already equals immutable policy generations | Checked updates mutate rows over time and may partially diverge | Build/readback/probe a fresh generation, then one pointer CAS (Chapter 12, §28.3) |
| Treat a static LSM denial as a BPF `prior_ret` value | Hook signatures and LSM stacking differ; some programs never run after another LSM denies | Qualify exact hook order/signature/result composition per platform (§13, §28.8) |
| Express `INV-EFFECT-001` with prose specificity | “More specific” is not a deterministic authority order | Closed exact decision keys and explicit override edges (Chapters 10-13) |

### B.2 Identity and admission

| Rejected or corrected idea | Why it is wrong | Replacement |
| --- | --- | --- |
| Active authority lives in immutable `TaskLabelV1` | Role, exec, domain restrictions, and response change; cached allow goes stale | Label points to authoritative process/domain state (§6) |
| Direct `PENDING -> CLAIMED` entry | It hides winner CAS, provisional state, exec commit, crash recovery | Full pending/claim/provisional/commit/tombstone transaction (§7-9) |
| `parent.thread_child_role` or separate thread-child role | Threads share a process, memory, often files; sibling role can launder authority | Threads share one process state; transitions are process-owned (§6) |
| Classify creator/exec actor by current cgroup before task label | A protected labeled task can be moved to host cgroup | Task storage first; cgroup verifies expected placement (§6, §13, §33) |
| Wake-path labeling without cross-cgroup failure proof | Child may run or land elsewhere before label; allocation may fail | Returning pre-effect creation hook or proved pre-wake finalizer plus fail-closed first effect (§6) |
| Userspace/asynchronous role assignment after exec | New image may act before update | Stage before point of no return; non-allocating commit before user mode (§6) |
| Every failed exec resumes old image | A failure after point of no return usually kills task; restoring authority is unsafe | Separate pre-PONR failure, post-PONR fatal/unknown, and success (§6) |
| Freeze entire restore cgroup while CRIU helper runs | Freezing the helper can deadlock restoration and does not prove all future tasks | Hold a dedicated setup/helper execution set; intercept and label each restored task before runnable (§7) |
| Kubernetes metadata alone authenticates privileged exception | Metadata can be stale, reused, spoofed by another path, or lack human approval | Signed target-bound one-use exception plus node pre-setup enforcement (§7-9, §35.1) |
| Generic OCI pre-start hook is strict admission | Hook timing varies and may run after security-relevant setup; callback success is not a held target | Measured runtime hold plus rootfs-ready barrier (§7) |
| Streaming `Exec` is one synchronous request | Prepare and later stream/run are separate; task may start after request returns | Opaque one-use stream ticket bound to exact peer, target, task, and expiry (§7) |
| BPF claim hook performs synchronous disk I/O | BPF cannot write WAL and must remain bounded | Pinned claim/tombstone transition in kernel; Rust persists/reconciles outside hook (§8-9) |
| Issuer chooses fail-open or emits reusable claims | Compromised issuer could widen local safety and replay authority | Local signed profile chooses failure; every claim is one-use (§8) |
| `Strong` is one scalar proof class | Signature, target, time, replay, task binding, and coverage can differ independently | Proof-quality vector (§8, §23) |
| Signed side-channel timing alone proves kubelet intent | Another identical task can race the window | Carried nonce/ticket claimed by exact held task (§8-9) |
| Google audit always contains original OIDC `jti` | Provider fields vary and may not preserve source claim | Explicit lease join fields; otherwise contextual edge (§8, §23) |
| Union of unequal candidate budgets is conservative | Union grants each candidate the other's authority | Exact proof, identical budget intersection, or reject (§6, §9) |
| Three-state claim promotion or identical pending key proves exact task | Concurrency needs winner ownership, provisional refs, exec result, and crash states | Full one-winner state machine and live-task binding (§9) |

### B.3 Policy, identity lookup, objects, and shared authority

| Rejected or corrected idea | Why it is wrong | Replacement |
| --- | --- | --- |
| Version 1 generic metadata extensions | Unknown signed fields create divergent interpretations | Closed schema; unknown/duplicate key rejects (§12) |
| Two independent transition authorities | Role shorthand and explicit transition could disagree | Compiler lowers both to one table and rejects conflicts (§11-12) |
| Cgroup lookup before existing task label | Moving a task can escape policy | Task-first lookup everywhere (§13) |
| Prose specificity, YAML order, priority, or “deny wins” resolves source conflict | These rules are ambiguous before exact lowering | Expand exact cell; identical physical results merge; differing results need explicit signed override (§12) |
| Owner-local generation number, digest-only defaults, or cached final allow | Generation `42` can collide across profiles; digest/default without owner and state is incomplete; response can change | Portable generation plus node ref; every cell has explicit default; label never stores final allow (§12, Appendix A.1) |
| Mutable active generation or “current socket owner” shorthand | Partial policy and passed/shared sockets break authority | Immutable generation and creator/current-actor/domain intersection (§12, §19) |
| Migrate live processes to new generation in V1 | Cross-thread/socket/domain/reference transaction is not proved | Existing holders stay pinned; new roots use new generation (§12) |
| Label generation must equal active generation | Existing protected objects intentionally retain older valid generation | Validate retained typed generation reference, not current pointer (§12) |
| Ad-hoc state/default lookup in generic hook | Missing cells can accidentally inherit allow | Exact decision key plus explicit default and required dynamic floors (§13) |
| Reusable inode or undefined mount generation identifies a file | Inode is reused and namespace/mount topology changes object meaning | Mount namespace generation + mount/fs/inode/version/live identity (§15, §17) |
| Projected-token rotation can wait for asynchronous userspace update | New object may be readable before classifier catches up | Pre-publication mount/object transaction or deny until exact binding (§17) |
| Process-local sensitive bit controls publication | Sibling process sharing memory/fd/socket can publish | Authority-domain monotonic restriction and pre-use joins (§18) |
| Old process-shared ABI sketch or task-label role cache is authoritative | Duplicated mutable authority diverges | One `ProcessSecurityStateV1` and one domain state; label stores reference only (§6, §18) |
| Load authority domain directly from task label | Process may move to a stricter/current domain; label is immutable | Label -> current process -> current domain (§6, §13) |
| Unbounded domain members and eager split | BPF cannot scan unbounded sets; split during active sharing can drop restriction | Bounded references, negative shared state, no unsafe split (§18) |
| Join only on explicit `CLONE_VM/FILES/FS` | UNIX/INET sockets, fd pass, shared file/mm, ptrace, process-vm, pidfd, devices also carry authority | Operation-specific pre-use join/deny matrix (§18) |
| Object pre-hook taint alone prevents concurrent transfer | Another task may use the object between observation and update | Hold/reservation, object lifetime floor, atomic join before publication/use (§18) |
| Pre-resolve every listener before application code | Dynamic bind/reuse/redirect makes startup inventory incomplete | Resolve listener/recipient at connect/accept/delivery; deny unknown strict channel (§18-19) |
| Returning hook can undo process-memory effects | `process_vm_writev`, ptrace, or kernel copy may have occurred before a late return point | Use proven pre-copy hook or deny earlier actuator acquisition; otherwise observation only (§18, §21) |
| Seccomp authorizes `/proc/<target>/mem` by pathname | Seccomp does not resolve filesystem target identity | BPF/traditional LSM exact file/target plus seccomp syscall floor (§17, §21) |
| Reuse current bounded domain for every cross-entry state | Domain may need pre-use union and durable resources beyond current processes | Versioned authority-domain join transaction and persistent object refs (§18) |
| Reclaim domain when last process exits | Persistent file/socket/mapping/publication capability may survive | Tombstone only after every process and persistent semantic reference ends (§18) |
| Narrow old roots before redirecting domain members | Partial update can leave inconsistent authority or broaden on crash | Prepare new intersection, atomically redirect/commit, preserve old restrictions until refs drain (§18) |
| Merge positive role grants across domains | Join could give each side the other's permissions | Keep base role local; union only negative restrictions/response state (§18) |
| `OBJECT_TAINT` after writing prevents `emptyDir` laundering | Consumer can read before post-write taint; inode taint is too late | Publication reservation/lease before first byte plus consumer join (§18) |
| Publication admission proves bytes were published | Admission precedes copy/send completion | Distinguish admitted, attempted, permitted, completed bytes, packet, and provider confirmation (§18, §25) |
| Publication authority split across two map values | Crash can update reservation without restriction or vice versa | One owning transaction/version and recoverable journal (§18) |
| Detect a task weakening its installed seccomp floor | Installed seccomp filters are monotonic; there is no removal syscall | Prove floor installed before user mode and govern ptrace/user notification (§21, §31) |

### B.4 Evidence, graph, response, and incident statements

| Rejected or corrected idea | Why it is wrong | Replacement |
| --- | --- | --- |
| Scalar `sourceQualityAtLeast` | Identity, time, result, coverage, and causal proof fail independently | `ProofQualityV1` vector and package predicates (§22-23) |
| Always connect a process directly to Kubernetes audit | Shared credential/time does not prove which process sent TLS request | Typed exact, shared-authority, temporal-context, or contradiction edges (§23) |
| Matching identifier creates any direct edge | IDs can be shared/reused and need provider-specific semantics | `ProviderEdgeContractV1` with join fields, direction, cardinality, time, and degradation (§23) |
| Bounded ancestor list alone controls future descendants | New child can appear after list is built | Response root/reference inherited at task creation plus reconciliation (§24) |
| Active hostile probes inside compromised production target | Probe may execute attacker-controlled code or change evidence | Readback and passive healthy watch; hostile probes run in isolated qualification fixtures (§24) |
| Publication success proves secret exfiltration | A write/send/provider object does not prove which bytes or source | Separate file-read, publication, packet, and provider results (§18, §25) |
| Bearer token identity inside TLS selects a kernel rule | Kernel sees destination/flow, not HTTP authorization token or verb | Whole-channel rule or provider/semantic gate; audit otherwise (§19, §25) |
| Provider audit is a prevention gate | Audit normally arrives after the provider decision | `POST_EFFECT` exact observation/alert plus optional response (§11, §25) |
| Connector catalog definitely reached through mesh | Published evidence may show separate or uncertain paths | Preserve alternate graph branches and proof quality (§23, §25) |
| Shared credential proves exact end-to-end cluster cause | Many actors can use the same credential | Shared-authority edge unless stronger request/session binding exists (§23, §25) |
| AWS access-key ID proves the Linux reader | Key IDs are shared and may be used elsewhere | Lease/session/request/source proof or contextual branch (§23, §25) |
| All AWS activity was external | Timeline can contain internal and external origins | Separate origin branches and do not merge without evidence (§25) |
| GitHub audit token identity is a revocation handle | Audit identity/hash may not be accepted by revocation API | Resolve exact installation/session through provider actuator or report no handle (§24-25) |
| Every memfd/anonymous execution has trusted digest | Writable backing may change or lack stable immutable bytes | Seal/hash/prove immutable backing or classify untrusted executable memory (§16, §25) |
| HF-020 definitely belongs to one protected lineage | Public timeline can leave attribution uncertain | Keep competing branches and claim only proven edge (§23, §25) |
| Configuration specificity plus restrictive action wins | It hides contradictory author intent and stages | Exact conflict and legal-stage compiler (§11-12) |
| Circular admission, reversed GitHub intent, generic AWS revocation | Admission cannot rely on an event emitted after release; GitHub read/write intent was reversed; AWS credentials need typed handle | Held pre-effect transaction, corrected provider intent, exact actuator (§8-12, §24-26) |
| Retained “complete valid” YAML plus a combined key is the golden wire | Prose substitutions, stale standalone vectors, duplicate fields, and open keys are ambiguous | One checked canonical source and generated deterministic CBOR/signature vector in Phase 0 (§12) |
| Broad rollout selector or unstable metric denominator | Selector drift changes authority/health math | Immutable rollout snapshot and named numerator/denominator population (§11-12) |
| Erebor terminates Git/TLS | User explicitly rejects MITM and it expands trust/secrets | Provider-scoped token/gate, whole-channel deny, or honest audit (§19, §26) |
| Workflow digest proves the bytes executed | Generated temp script/local action/dependency can differ | Held/sealed materialized bytes and full immutable artifact chain (§26) |
| Runner callback signature alone proves a step | Job code may call socket or copy fields; callback may not bind held child | Measured runner-control task plus one-use exact child/root attestation (§26) |
| Design-level CI YAML is valid `PolicyDocumentV1` | CI adapters/schema remain unallocated | Parser rejects `coordinators`/`ciRules` until approved closed schema (§26, §35.1) |
| Boolean `attestation: verified` | It omits subject, source, materials, builder, trust, revocation, transparency, freshness | Exact attestation predicate and consumer check (§26) |
| Behavior reliably detects a valid forged token | Valid token can look normal; behavior is not cryptographic provenance | Prevention at issuance/use when possible, typed audit, anomaly as context (§25) |
| Every malicious CI credential read is locally denyable | Secret may already be environment memory or inherited fd | Control earliest visible delivery/use/provider boundary and report limits (§26) |
| File read equals publication result, or file read is never publication-related | Read and publication are distinct but causally related results | Report both exact stages and typed edge (§17-18, §25) |

### B.5 Failure, performance, ownership, and qualification

| Rejected or corrected idea | Why it is wrong | Replacement |
| --- | --- | --- |
| Lost enforcement family applies its own safe state | Detached/missing mechanism cannot enforce anything | Mark unknown; use only independently healthy actuator (§32) |
| Sole gatherer keeps disk-spooling while dead | No process drains ring or writes WAL | Bounded ring, loss counters/tombstones, fail-closed new admission, restart reconciliation (§32) |
| Cgroup-first fast path | Moved labeled task escapes | Task-first measured path (§33) |
| Untyped performance composite fields | Different tools serialize/interpret them differently | Closed operation/capacity/bundle records (§33, Appendix A.4) |
| Adapter and admission owner both authenticate and stage | Competing claims and inconsistent target validation appear | Adapter normalizes; only `IntentAdmissionOwner` stages (§34) |
| Completion from two artifacts | Missing fixture registry, case results, capability/performance, digest binding | Full bound artifact set (§37, Appendix A) |
| Assurance-axis aggregate carries authority | Mixed results get averaged into “full support” | Exact `ClaimVectorV1`; axis is only index (Appendix A.5) |
| One expected result per multi-branch fixture | File, network, credential, and CI branches have different stages/oracles | `FixtureCaseV1` and aggregate rules (Appendix A.6) |
| Two unbound qualification artifacts | Results from different build/platform can be spliced | Digest-bound manifest/bundles/ledger/envelope/claim (Appendix A.7) |
| Wildcard criterion expansion | `ENTRY-*` cannot prove registry membership; optional surfaces wrongly block core | Exact fixture IDs plus allocation condition (Appendix C) |

### B.6 Exact supersession records retained from the original

The original used explicit statement markers so a retained teaching sketch
could not override its later correction. That mechanism remains a Phase 0
docs-lint requirement:

```html
<!-- mithril-statement-v1: STMT-CGROUP-FIRST-RETAINED-001 RETAINED -->
<!-- mithril-statement-v1: STMT-CGROUP-FIRST-CONTROL-002 CONTROLLING -->
<!-- mithril-supersession-v1: SUP-TASK-CGROUP-FIRST-001 -->
```

The supersession row connects both statement IDs, gives the reason, names the
controlling invariant and fixtures, and fails lint if either statement moves
without its marker. In this example, the controlling rule is task-first
identity; the cgroup-first text remains only as an abandoned cost sketch.

`CFG-V1-GOLDEN-001` is likewise retained only as the stale standalone policy
golden vector. It predates required selectors, classifier bindings, roles,
entries, process states, defaults, authority/correlation/coverage lists, and
structured records. `CFG-V1-GOLDEN-002` replaces it. Phase 0 generates the new
restricted-YAML, deterministic-CBOR, header, digest, signature, compiler, and
round-trip vectors from one checked source; prose substitutions never produce
golden bytes.

`SOURCE-BOUNDARY-001` is the shared non-implementation boundary: ordinary
Linux LSM/socket/packet evidence cannot distinguish Git clone from push or a
specific Kubernetes/cloud verb inside encrypted same-destination TLS, and a
Linux hook cannot revoke an already issued remote IAM session. Target-specific
uprobes or instrumentation may add observation when explicitly qualified, but
the baseline solutions remain a provider/semantic gate, provider audit and
response, or denial of the entire channel.

## Appendix C — Closed Fixture Registry And Completion Mapping

Fixture IDs are security contract, not prose. The future docs linter requires
an adjacent marker of the form:

```html
<!-- mithril-fixture-v1: FILE-MMAP-001 -->
```

Fixture IDs match `^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+-[0-9]{3}$`. Cards use
`mithril-card-v1`, source observations use `mithril-source-evidence-v1`, and
invariants use `mithril-invariant-v1`; those IDs cannot satisfy a fixture
requirement.

### C.1 Exact fixture set for this architecture revision

```text
BOOT-ADMISSION-001
CFG-ROLLBACK-GOLDEN-002
CFG-V1-GOLDEN-002
CHECKPOINT-CREATE-001
CI-ATTEST-001
CI-CACHE-001
CI-CONTAINER-001
CI-DEBUG-001
CI-DIND-001
CI-FANOUT-001
CI-GITHUB-TOKEN-001
CI-NATIVE-001
CI-OIDC-001
CI-OUTPUT-001
CI-POST-001
CI-PR-001
CI-RETRY-001
CI-RUNNER-REUSE-001
CI-STATE-001
DECISION-SET-GOLDEN-001
DEVICE-DERIVED-001
DOMAIN-JOIN-CRASH-002
DOMAIN-REF-LIFETIME-001
EDGE-ARTIFACT-CONSUMER-005
EDGE-AWS-SHARED-001
EDGE-CONNECTOR-FORWARD-004
EDGE-GITHUB-SHARED-003
EDGE-K8S-SHARED-002
EDGE-MESSAGE-CONSUMER-006
ENTRY-CLAIM-TRANSACTION-004
ENTRY-CONTAINERS-001
ENTRY-EPHEMERAL-001
ENTRY-EXEC-001
ENTRY-EXEC-002
ENTRY-HOLD-ATTACK-002
ENTRY-KUBELET-TICKET-001
ENTRY-LOSS-001
ENTRY-MIGRATE-001
ENTRY-NETPROBE-001
ENTRY-POSTSTART-001
ENTRY-POSTSTART-002
ENTRY-PRESTOP-001
ENTRY-PROBE-001
ENTRY-PROBE-002
ENTRY-PROBE-IMPERSONATION-003
ENTRY-RESTART-001
ENTRY-RESTORE-001
ENTRY-REUSE-001
ENTRY-ROOTFS-BARRIER-001
ENTRY-SLEEP-001
ENTRY-START-001
ENTRY-STREAM-001
EXEC-COMMIT-STATE-001
EXEC-CONCURRENT-002
FILE-CONTENT-RACE-002
FILE-DELEGATED-EGRESS-001
FILE-FD-PASS-001
FILE-IDENTITY-001
FILE-MMAP-001
FILE-NAMESPACE-001
FILE-SA-TOKEN-OPEN-001
FILE-VMA-SNAPSHOT-001
FIXTURE-REGISTRY-COMPLETE-001
HF-004-RESULT-001
HF-011-READ-RESULT-001
HF-GRAN-AWS-DRYRUN-001
HF-GRAN-AWS-SPLIT-001
HF-GRAN-CAPTURE-001
HF-GRAN-CI-BUILDRS-001
HF-GRAN-CLUSTER-SHARED-001
HF-GRAN-CONNECTOR-DIRECT-001
HF-GRAN-DEAD-DROP-001
HF-GRAN-GITHUB-MINT-001
HF-GRAN-GITHUB-REARM-001
HF-GRAN-GITHUB-REVOKE-001
HF-GRAN-GITHUB-TREE-PR-001
HF-GRAN-HOST-LOC-001
HF-GRAN-HOSTPATH-001
HF-GRAN-MESH-ENUM-001
HF-GRAN-MESH-ROOT-001
HF-GRAN-MESH-SOCKS-001
HF-GRAN-OUTSIDE-001
HF-GRAN-RESPAWN-001
HF-GRAN-TOKEN-FORGE-001
HF-LOCAL-001
HF-NET-001
HF-RESP-002
HF-RESP-SHARED-DOMAIN-003
ID-CGROUP-ESCAPE-001
ID-CLONE-CGROUP-002
ID-CLONE-CGROUP-FAIL-003
ID-CREATOR-PARENT-007
ID-MOVED-PARENT-FORK-004
ID-MOVED-TASK-EXEC-005
ID-TASK-COORD-FINALIZE-006
LSM-DENY-SATURATION-001
MEM-EXEC-001
MEM-KERNEL-MAP-002
MOUNT-ATTR-001
MOUNT-CAS-002
MOUNT-PROPAGATION-003
MOUNT-SNAPSHOT-004
NET-ACCEPT-PASS-001
NET-DNS-EXFIL-001
NET-NS-PASS-001
NET-RECV-001
NET-REWRITE-001
NET-SHARED-RESPONSE-002
NET-SOCKCTL-001
NET-SOCKET-LIFE-001
NODE-FLOOR-EXCEPTION-002
SECCOMP-QUAL-001
SELF-PROTECT-001
SOURCE-KA-BOUNDS-004
SOURCE-KA-CAPACITY-005
SOURCE-KA-PARTIAL-ATTACH-001
SOURCE-KA-READER-LOSS-003
SOURCE-KA-STACK-PER-HOOK-002
SOURCE-TG-EXEC-MAP-007
SOURCE-TG-PATH-RENAME-008
SOURCE-TG-RUNTIME-JOIN-006
STATE-CROSS-ENTRY-003
STATE-CROSS-ENTRY-PREPOSSESSED-005
STATE-CROSS-ENTRY-RACE-004
STATE-CROSS-EXECSET-PERSIST-006
STATE-FORK-IPC-002
STATE-LOCAL-INET-LAUNDER-008
STATE-MMAP-PUBLICATION-011
STATE-PERSISTENT-FILE-LIFETIME-007
STATE-PROCESS-CHANNEL-009
STATE-PUBLICATION-LEASE-010
STATE-THREAD-RACE-001
XNODE-PRIVILEGED-POD-001
```

The documentation marker set, `fixtures.yaml`, executable tests, criterion
mapping, and result bundle must contain exactly the same active IDs.
`FIXTURE-REGISTRY-COMPLETE-001` performs that equality check. Adding a fixture
changes all owning artifacts in one review.

### C.2 Exact criterion allocation

`ALWAYS` means core qualification. `WHEN_CLAIM_VECTOR_REFERENCES` activates
only when a release claims that surface. `WHEN_SURFACE_ALLOCATED_AND_ADVERTISED`
activates only after the optional surface has an approved phase and product
claim.

| Criterion | Condition | Exact fixture IDs |
| ---: | --- | --- |
| 1 | `ALWAYS` | `BOOT-ADMISSION-001` |
| 1 | `WHEN_CLAIM_VECTOR_REFERENCES` | `NODE-FLOOR-EXCEPTION-002`, `XNODE-PRIVILEGED-POD-001` |
| 2 | `ALWAYS` | `ENTRY-CLAIM-TRANSACTION-004`, `ENTRY-CONTAINERS-001`, `ENTRY-EPHEMERAL-001`, `ENTRY-EXEC-001`, `ENTRY-EXEC-002`, `ENTRY-HOLD-ATTACK-002`, `ENTRY-KUBELET-TICKET-001`, `ENTRY-LOSS-001`, `ENTRY-MIGRATE-001`, `ENTRY-NETPROBE-001`, `ENTRY-POSTSTART-001`, `ENTRY-POSTSTART-002`, `ENTRY-PRESTOP-001`, `ENTRY-PROBE-001`, `ENTRY-PROBE-002`, `ENTRY-PROBE-IMPERSONATION-003`, `ENTRY-RESTART-001`, `ENTRY-REUSE-001`, `ENTRY-ROOTFS-BARRIER-001`, `ENTRY-SLEEP-001`, `ENTRY-START-001` |
| 2 | `WHEN_SURFACE_ALLOCATED_AND_ADVERTISED` | `CHECKPOINT-CREATE-001`, `ENTRY-RESTORE-001`, `ENTRY-STREAM-001` |
| 3 | `ALWAYS` | `DOMAIN-JOIN-CRASH-002`, `DOMAIN-REF-LIFETIME-001`, `EXEC-COMMIT-STATE-001`, `EXEC-CONCURRENT-002`, `ID-CGROUP-ESCAPE-001`, `ID-CLONE-CGROUP-002`, `ID-CLONE-CGROUP-FAIL-003`, `ID-CREATOR-PARENT-007`, `ID-MOVED-PARENT-FORK-004`, `ID-MOVED-TASK-EXEC-005`, `ID-TASK-COORD-FINALIZE-006`, `STATE-CROSS-ENTRY-003`, `STATE-CROSS-ENTRY-PREPOSSESSED-005`, `STATE-CROSS-ENTRY-RACE-004`, `STATE-CROSS-EXECSET-PERSIST-006`, `STATE-FORK-IPC-002`, `STATE-THREAD-RACE-001` |
| 4 | `ALWAYS` | `DEVICE-DERIVED-001`, `FILE-CONTENT-RACE-002`, `FILE-IDENTITY-001`, `FILE-MMAP-001`, `FILE-NAMESPACE-001`, `FILE-SA-TOKEN-OPEN-001`, `FILE-VMA-SNAPSHOT-001`, `HF-LOCAL-001`, `HF-NET-001`, `MEM-EXEC-001`, `MEM-KERNEL-MAP-002`, `MOUNT-ATTR-001`, `MOUNT-CAS-002`, `MOUNT-PROPAGATION-003`, `MOUNT-SNAPSHOT-004`, `NET-ACCEPT-PASS-001`, `NET-DNS-EXFIL-001`, `NET-NS-PASS-001`, `NET-RECV-001`, `NET-REWRITE-001`, `NET-SOCKCTL-001`, `NET-SOCKET-LIFE-001`, `SECCOMP-QUAL-001`, `STATE-LOCAL-INET-LAUNDER-008`, `STATE-MMAP-PUBLICATION-011`, `STATE-PERSISTENT-FILE-LIFETIME-007`, `STATE-PROCESS-CHANNEL-009`, `STATE-PUBLICATION-LEASE-010` |
| 4 | `WHEN_CLAIM_VECTOR_REFERENCES` | `HF-GRAN-CONNECTOR-DIRECT-001`, `HF-GRAN-DEAD-DROP-001`, `HF-GRAN-HOSTPATH-001`, `HF-GRAN-MESH-ROOT-001` |
| 5 | `ALWAYS` | `FILE-DELEGATED-EGRESS-001`, `FILE-FD-PASS-001`, `HF-004-RESULT-001`, `HF-011-READ-RESULT-001`, `NET-SHARED-RESPONSE-002` |
| 5 | `WHEN_CLAIM_VECTOR_REFERENCES` | `HF-GRAN-CI-BUILDRS-001`, `HF-GRAN-HOST-LOC-001`, `HF-GRAN-OUTSIDE-001` |
| 6 | `ALWAYS` | `EDGE-ARTIFACT-CONSUMER-005`, `EDGE-AWS-SHARED-001`, `EDGE-CONNECTOR-FORWARD-004`, `EDGE-GITHUB-SHARED-003`, `EDGE-K8S-SHARED-002`, `EDGE-MESSAGE-CONSUMER-006` |
| 6 | `WHEN_CLAIM_VECTOR_REFERENCES` | `HF-GRAN-AWS-SPLIT-001`, `HF-GRAN-CLUSTER-SHARED-001`, `HF-GRAN-GITHUB-TREE-PR-001`, `HF-GRAN-MESH-SOCKS-001` |
| 7 | `ALWAYS` | `HF-RESP-002`, `HF-RESP-SHARED-DOMAIN-003` |
| 7 | `WHEN_CLAIM_VECTOR_REFERENCES` | `HF-GRAN-CAPTURE-001`, `HF-GRAN-GITHUB-REARM-001`, `HF-GRAN-GITHUB-REVOKE-001`, `HF-GRAN-MESH-ENUM-001`, `HF-GRAN-RESPAWN-001` |
| 8 | `ALWAYS` | `LSM-DENY-SATURATION-001`, `SELF-PROTECT-001`, `SOURCE-KA-BOUNDS-004`, `SOURCE-KA-CAPACITY-005`, `SOURCE-KA-PARTIAL-ATTACH-001`, `SOURCE-KA-READER-LOSS-003`, `SOURCE-KA-STACK-PER-HOOK-002`, `SOURCE-TG-EXEC-MAP-007`, `SOURCE-TG-PATH-RENAME-008`, `SOURCE-TG-RUNTIME-JOIN-006` |
| 9 | `ALWAYS` | `CFG-ROLLBACK-GOLDEN-002`, `CFG-V1-GOLDEN-002`, `DECISION-SET-GOLDEN-001`, `FIXTURE-REGISTRY-COMPLETE-001` |
| 10 | `ALWAYS` | `ENTRY-CLAIM-TRANSACTION-004`, `ENTRY-KUBELET-TICKET-001`, `ENTRY-PROBE-IMPERSONATION-003` |
| 10 | `WHEN_CLAIM_VECTOR_REFERENCES` | `HF-GRAN-AWS-DRYRUN-001`, `HF-GRAN-GITHUB-MINT-001`, `HF-GRAN-TOKEN-FORGE-001` |
| 11 | `WHEN_SURFACE_ALLOCATED_AND_ADVERTISED` | `CI-ATTEST-001`, `CI-CACHE-001`, `CI-CONTAINER-001`, `CI-DEBUG-001`, `CI-DIND-001`, `CI-FANOUT-001`, `CI-GITHUB-TOKEN-001`, `CI-NATIVE-001`, `CI-OIDC-001`, `CI-OUTPUT-001`, `CI-POST-001`, `CI-PR-001`, `CI-RETRY-001`, `CI-RUNNER-REUSE-001`, `CI-STATE-001` |

`CARD-ENTRY-PROBE-IMPERSONATION-001` must never appear in this table. Its
executable fixture is `ENTRY-PROBE-IMPERSONATION-003`. `HF-021` is a response
and recovery outcome under criterion 7; it is not another local pre-effect
family under criterion 4.

## Appendix D — Technical And Incident Sources

### D.1 Local checked source snapshots

KubeArmor:

- [top-level license](../../../KubeArmor/LICENSE)
- [BPF LSM enforcer](../../../KubeArmor/KubeArmor/BPF/enforcer.bpf.c)
- [BPF shared ABI/helpers](../../../KubeArmor/KubeArmor/BPF/shared.h)
- [policy lowering](../../../KubeArmor/KubeArmor/enforcer/bpflsm/rulesHandling.go)
- [map handling](../../../KubeArmor/KubeArmor/enforcer/bpflsm/mapHelpers.go)
- [loader/attachment](../../../KubeArmor/KubeArmor/enforcer/bpflsm/enforcer.go)
- [system monitor BPF](../../../KubeArmor/KubeArmor/BPF/system_monitor.c)
- [exec observation BPF](../../../KubeArmor/KubeArmor/BPF/exec.bpf.c)
- [NRI lifecycle](../../../KubeArmor/KubeArmor/core/nriHandler.go)
- [network userspace enforcement/enrichment](../../../KubeArmor/KubeArmor/networkPolicyEnforcer/networkPolicyEnforcer.go)
- [preset programs](../../../KubeArmor/KubeArmor/BPF/filelessexec.bpf.c)

Tetragon:

- [top-level license](../../../tetragon/LICENSE)
- [fork tracking](../../../tetragon/bpf/process/bpf_fork.c)
- [process state](../../../tetragon/bpf/lib/process.h)
- [exec staging](../../../tetragon/bpf/process/bpf_execve_event.c)
- [cgroup policy filter](../../../tetragon/bpf/process/policy_filter.h)
- [Generic LSM core](../../../tetragon/bpf/process/bpf_generic_lsm_core.c)
- [separate BPF enforcer](../../../tetragon/bpf/process/bpf_enforcer.c)
- [runtime hook service](../../../tetragon/pkg/policyfilter/rthooks/rthooks.go)
- [runtime hook arguments](../../../tetragon/pkg/rthooks/args.go)
- [OCI hook](../../../tetragon/contrib/tetragon-rthooks/cmd/oci-hook/main.go)
- [process cache](../../../tetragon/pkg/process/cache.go)
- [observer/loss path](../../../tetragon/pkg/observer/observer_linux.go)

The review crosswalk is:

| Source family | Checked evidence IDs |
| --- | --- |
| KubeArmor LSM decisions, paired path programs, DNS, stacking, rendering and lookup misses: `enforcer.bpf.c`, `enforcer_path.bpf.c`, `shared.h` | `KA-CODE-001`, `002`, `006`, `011`, `012`, `015`, `016`, `020`, `021`, `022`, `024`, `025` |
| KubeArmor policy lowering, map publication, loader/capacity/action vocabulary: `rulesHandling.go`, `mapHelpers.go`, `enforcer.go`, `kubeUpdate.go`, `types.go` | `KA-CODE-002`, `006`, `007`, `009`, `011`, `014`, `019`, `020`, `027` |
| KubeArmor early identity, exec state, monitor/readers and reconciliation: `system_monitor.c`, `exec.bpf.c`, `systemMonitor.go`, `processTree.go` | `KA-CODE-005`, `008`, `010`, `023`, `026`, `028` and the KubeArmor side of `TG-CODE-012` |
| KubeArmor NRI lifetime: `core/nriHandler.go` | `KA-CODE-004`, `017` |
| KubeArmor network lowering/NFLOG/DNS: `networkPolicyEnforcer.go`, network `types.go`, `enforcer.bpf.c`, `shared.h` | `KA-CODE-006`, `012`, `013`, `015`, `025` |
| KubeArmor presets and readers: `protectenv.bpf.c`, `filelessexec.bpf.c`, `anonmapexec.bpf.c`, `protectproc.bpf.c`, `exec.bpf.c`, fileless preset reader | `KA-CODE-003`, `008`, `018`, `022`, `026` and the preset-reader side of `TG-CODE-012` |
| Tetragon fork/exec/non-leader/per-task state and tests: `bpf_fork.c`, `process.h`, exec staging programs, `base.go`, fork/exec/exit/thread tests | `TG-CODE-001`, `002`, `006`, `014`, `017`, `018`, `020`, `024` |
| Tetragon Generic LSM and separate enforcer: `genericlsm.go`, `generic_calls.h`, Generic LSM core/output/maps/types, `bpf_enforcer.*`, metrics, socket kprobe example | `TG-CODE-007`, `010`, `011`, `013`, `015`, `019` |
| Tetragon cgroup filter and runtime metadata: `policy_filter.h`, policy-filter map/state, runtime hooks/args/server/protobuf, node main, OCI hook | `TG-CODE-003`, `004`, `009`, `016`, `021`, `022`, `023` |
| Tetragon node/process IDs, cache, event schema and loss: `node.go`, `process_id_linux.go`, `process.go`, `cache.go`, `events.proto`, observer/metrics | `TG-CODE-002`, `005`, `008`, `018` |
| Tetragon one-process sensor/runtime chassis: node `main.go`, hook `runner.go`/`args.go`/server/protobuf/OCI hook | `TG-CODE-005`, `009`, `012`, `017`, `021`, `023` |

Phase 0 verifies every recorded line range and blob digest against the pinned
commits. Moving a clone or finding the same filename at a new commit does not
refresh an evidence claim. A human reviews the changed mechanism and its
hostile fixture.

### D.2 Linux, OCI, and Kubernetes contracts

- [Linux BPF LSM](https://docs.kernel.org/bpf/prog_lsm.html)
- [Linux BPF iterators](https://docs.kernel.org/bpf/bpf_iterators.html)
- [Linux LSM hooks](https://docs.kernel.org/security/lsm-development.html)
- [Linux cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html)
- [BPF cgroup-local storage](https://docs.kernel.org/6.17/bpf/map_cgrp_storage.html)
- [Linux task-local BPF storage](https://github.com/torvalds/linux/blob/master/kernel/bpf/bpf_task_storage.c)
- [Linux `kcmp` implementation](https://github.com/torvalds/linux/blob/master/kernel/kcmp.c)
- [Linux `kcmp(2)` contract](https://man7.org/linux/man-pages/man2/kcmp.2.html)
- [Linux seccomp filter](https://docs.kernel.org/userspace-api/seccomp_filter.html)
- [Linux Landlock](https://docs.kernel.org/userspace-api/landlock.html)
- [OCI runtime lifecycle](https://specs.opencontainers.org/runtime-spec/runtime/)
- [OCI hook ordering](https://specs.opencontainers.org/runtime-spec/config/)
- [Kubernetes lifecycle hooks](https://kubernetes.io/docs/concepts/containers/container-lifecycle-hooks/)
- [Kubernetes probes](https://kubernetes.io/docs/concepts/workloads/pods/probes/)
- [Kubernetes init containers](https://kubernetes.io/docs/concepts/workloads/pods/init-containers/)
- [Kubernetes sidecars](https://kubernetes.io/docs/concepts/workloads/pods/sidecar-containers/)
- [Kubernetes ephemeral containers](https://kubernetes.io/docs/concepts/workloads/pods/ephemeral-containers/)
- [Kubernetes auditing](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
- [Kubelet Checkpoint API](https://kubernetes.io/docs/reference/node/kubelet-checkpoint-api/)
- [CRI runtime API](https://github.com/kubernetes/cri-api/blob/master/pkg/apis/runtime/v1/api.proto)

### D.3 CI, identity, and provider contracts

- [GitHub Actions execution model](https://docs.github.com/en/actions/get-started/understand-github-actions)
- [GitHub job and sibling containers](https://docs.github.com/en/actions/how-tos/write-workflows/choose-where-workflows-run/run-jobs-in-a-container)
- [GitHub OIDC claims](https://docs.github.com/en/actions/reference/security/oidc)
- [GitHub job-scoped token](https://docs.github.com/en/actions/concepts/security/github_token)
- [Secure `pull_request_target` use](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target)
- [GitHub deployment environments](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments)
- [GitHub artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations)
- [GitHub App token revocation](https://docs.github.com/en/rest/apps/installations#revoke-an-installation-access-token)
- [GitHub audit token attribution](https://docs.github.com/en/enterprise-cloud@latest/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/identifying-audit-log-events-performed-by-an-access-token)
- [GitLab Docker executor](https://docs.gitlab.com/runner/executors/docker/)
- [GitLab Kubernetes executor](https://docs.gitlab.com/runner/executors/kubernetes/)
- [GitLab OIDC ID tokens](https://docs.gitlab.com/ci/secrets/id_token_authentication/)
- [Tekton Task model](https://tekton.dev/docs/pipelines/tasks/)
- [Jenkins Pipeline model](https://www.jenkins.io/doc/book/pipeline/syntax/)
- [Google workload identity for deployment pipelines](https://cloud.google.com/iam/docs/workload-identity-federation-with-deployment-pipelines)
- [AWS IAM source identity and session tags](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_session-tags.html)

### D.4 Incident sources

- [Hugging Face technical timeline](https://huggingface.co/blog/agent-intrusion-technical-timeline)
- [Detailed local analysis](../../research/hugging-face-agent-intrusion-analysis.md)
- [Normalized live action stream](../../research/hugging-face-agent-intrusion-live-action-stream.md)

## Appendix E — Completeness Map From The Original Architecture

This table is the review trail for the rewrite. It maps every original topic
family to its new home. Appendix B separately maps every original abandoned or
corrected design. Appendix C carries the exact fixture set. If a future edit
adds a normative topic to the original, this map and the fixture registry must
be updated before this rewrite may still call itself complete.

### E.1 Original navigation, scope, and design basis

| Original topic | New location |
| --- | --- |
| Document navigation, dependency hierarchy, implementer path, question/route index, heading semantics | Opening organization, Chapters 1-5, and this appendix |
| Security/execution terms; evidence/result terms; IDs/time/units | Chapters 1, 4, 6, 22-24; Appendix A.1 |
| Normative/supersession ownership and marker correction | Appendices B, C, and E; Phase 0 registry/lint in Chapter 35 |
| Decision summary and corrected local-kernel reading | Chapters 1, 4-5, 13-14 |
| Claim boundary, containment correction, platform eligibility | Chapters 4-5, 24, 31-33; Appendix A.5 |
| Pinned source baseline, evidence vocabulary, machine evidence ledger | Chapters 27-30; Appendix A.3; Appendix D.1 |
| Scenario boundary index | Chapters 2-4, 27-30 |
| KubeArmor lessons and practical examples | Chapter 28 |
| Tetragon lessons and practical examples | Chapter 29 |
| Combined upstream pipeline and source-to-implementation traceability | Chapter 30, §31.3, Appendix A.3 |
| Combined compromised-converter and identical-probe examples | §30 Example A/B |
| Release implementation cards | §30 release-gating cards |
| Protection invariants, examples, executable invariant record | Chapter 10 and `InvariantQualificationV1` in Chapter 10/Appendix A.2 |

### E.2 Original identity and runtime admission

| Original topic | New location |
| --- | --- |
| Why a container has several roots | Chapter 6 |
| Existing-process, kubelet exec, malicious hook, and node/runtime bypass paths | Chapter 6 |
| Stock CRI facts and limits | Chapters 6-7 |
| Durable identity objects and concrete field contract | Chapter 6; Appendix A.1-A.2 |
| Task/process/thread/entry/exec distinctions and state machines | Chapter 6 |
| Entry lifetimes and reference accounting | Chapters 6 and 9 |
| Creator parent versus changing kernel parent | Chapter 6 |
| Native fork/thread/vfork inheritance | Chapter 6 |
| Hook selection, PID finalization, clone-into-cgroup failures | Chapter 6 |
| Exec staging, interpreter/loader chain, non-leader exec, failed exec | Chapter 6 |
| Kubernetes external-entry facts and matrix | Chapters 6-7; §31.1 |
| Checkpoint creation/restore and full task-set hold | Chapter 7; unallocated status §35.1 |
| Attach and port-forward authority | Chapter 7; unallocated status §35.1 |
| Node-wide floor for attacker-created workloads and exceptions | Chapters 5 and 7; §35.1 |
| One-gatherer runtime integration and cold-boot circularity | Chapters 5 and 7 |
| Runtime setup hold and rootfs-ready barrier | Chapter 7 |
| Streaming exec two-stage model | Chapter 7 |
| Runtime intent, signed wire, trust, replay, failure posture | Chapter 8; Appendix A.2 |
| Claim consumption variants and state machines | Chapters 8-9 |
| Credential bytes versus protected actuator handle | Chapter 8 |
| Proof vector and use matrix | Chapters 8 and 23 |
| Kubelet-to-task proof and selected probe design | Chapters 8-9; §30 Example B |
| AWS and Google authority-lease proof, audit limitation | Chapter 8; Chapters 23, 25-26 |
| ExecSync classification and pending claim algorithm | Chapter 9 |
| Provisional root promotion, shutdown, and containment | Chapter 9 |

### E.3 Original policy, compiled state, and local Linux effects

| Original topic | New location |
| --- | --- |
| Source policy and signed anti-rollback profile | Chapters 11-12 |
| Entry rules | Chapter 11 |
| Roles and one transition authority | Chapters 11-12 |
| Effect rules and authority-behavior rules | Chapter 11 |
| Compiler pipeline, conflicts, and precedence | Chapter 12 |
| Compiled map/decision ABI and lookup semantics | Chapters 12-13; Appendix A.1-A.2 |
| Generation activation, retention, retirement, rollback | Chapter 12 |
| Cgroup binding identity/reuse and task placement | Chapters 5-7, 13 |
| Generic pre-effect order and stacked LSM semantics | Chapter 13 |
| Mount and network-namespace identity | Chapter 15 |
| Synchronous topology invalidation, CAS reconciliation, propagation/automount/referrals | Chapter 15 |
| Executable images, scripts, ELF loader, memfd/anonymous memory, `mprotect`, executable stack/personality | Chapter 16 |
| File and credential objects, namespace mutation, mmap/preexisting mapping, projected-token rotation | Chapter 17 |
| Open-fd provenance and delegated filesystem/local-proxy egress | Chapter 17 |
| Process-shared security state and exact current role | Chapter 18 |
| Threads/forks/cross-entry shared channels and bounded authority domains | Chapter 18 |
| Shared memory/files/IPC/local-inet/process control and persistent resources | Chapter 18 |
| Attempted versus permitted versus completed byte access/publication | Chapters 17-18 |
| Network actor/socket namespace, socket lifetime, shared-socket blast radius, receive queue | Chapter 19 |
| Destination rewriting, DNS, final packet floor, TLS limitation | Chapter 19 |
| Device open/ioctl/fd lifetime and derived capabilities | Chapter 20 |
| Credential, proc/sysctl, BPF/perf/module/keyring/namespace/mount privilege effects | Chapter 21 |
| Seccomp floor proof and Landlock scope | Chapters 14 and 21 |
| Self-protection | Chapters 5 and 21; `SELF-PROTECT-001` in Appendix C |

### E.4 Original evidence, graph, response, incident, and CI

| Original topic | New location |
| --- | --- |
| Observation and coverage records | Chapter 22; Appendix A.2 |
| Proof quality vector | Chapters 22-23 |
| Package windows, watermarks, finding lifecycle | Chapter 22 |
| `HF-PROC-001`, `HF-DW-001`, `HF-XNODE-001` | Chapter 23 |
| Canonical multi-node graph and provider expansion contracts | Chapter 23 |
| Local lineage restriction and target re-resolution | Chapter 24 |
| Response application, physical verification, durable result vocabulary | Chapter 24 |
| Cgroup/workload, shared-domain, and distributed response | Chapter 24 |
| `HF-001` through `HF-021` control design | Chapter 25 |
| Situation-to-control summary and full configured walkthrough | Chapter 25 |
| File/open/read/publication/provider-result corrections | Chapters 17-19 and 25 |
| Worked policy, exact dispositions, legal stages, configuration objects | Chapter 11 and Chapter 25 configuration references |
| Impossible configuration, precedence, exact conflicts | Chapters 11-12 |
| Rollout, exceptions, metric denominators | Chapters 11-12 |
| CI execution practices and assurance tiers | Chapter 26 |
| No Git/TLS termination and GitHub token limit | Chapters 19 and 26 |
| GitHub/GitLab/Tekton/Jenkins physical seams and support matrix | Chapter 26 |
| CI identity, intent body, coordinator-to-task binding | Chapter 26 |
| Native/container/service/matrix/reusable/artifact/OIDC/deploy/post/debug/DinD shapes | Chapter 26 |
| Untrusted PR, artifact/cache trust, indirect execution | Chapter 26 |
| Cross-step state and runner reuse | Chapter 26 |
| CI semantic lowering, credential-delivery boundaries, fixtures | Chapter 26 and Appendix C |
| Detailed representative and granular Hugging Face action acceptance | Chapter 25 and Appendix C |

### E.5 Original qualification, ownership, delivery, and approval

| Original topic | New location |
| --- | --- |
| Kubernetes external-entry acceptance | §31.1 |
| Effect/bypass acceptance | §31.2 |
| Pinned-source qualification consequences | §31.3 |
| Failure-state matrix and independent link/map/pin/ring/daemon faults | Chapter 32 |
| Sole-gatherer death correction | Chapter 32 |
| Task-first fast path and bounded cost model | Chapter 33 |
| Performance budgets, methodology, typed artifacts, N/N+1 | Chapter 33; Appendix A.4 |
| Cohesive owner table and durable-owner correction | Chapter 34 |
| Runtime read-only sharing with Erebor Runtime | Chapter 34 |
| Phase allocation and contract-to-code route | Chapter 35 |
| Unallocated checkpoint, stream, CI adapters, node floor | §35.1 |
| Phase state versus product claim | Chapter 35 |
| Approval choices and honest alternatives | Chapter 36 |
| Closed assurance axes and exact claim vectors | Appendix A.5 |
| Multi-case fixture registry and result bundle | Appendix A.6; Appendix C |
| Canonical oracle, ledger, envelope, release claim | Appendix A.7 |
| Exact completion criteria and fixture allocation | Chapter 37; Appendix C.2 |
| Primary technical and incident references | Appendix D |

### E.6 Final review question

For every product claim, the reviewer must be able to follow this chain without
an implied step:

```text
human source rule
  -> closed signed policy bytes
  -> exact compiled decision or provider contract
  -> exact live actor and object/channel identity
  -> qualified decision point
  -> physical or semantic result
  -> coverage and proof vector
  -> immutable observation/finding revision
  -> authorized response target and postcondition, if any
  -> fixture case and oracle
  -> exact claim vector in one signed platform qualification
```

If any arrow is missing, Mithril may still report the facts it has, but it must
lower the claim. It may not fill the gap with a Pod label, command name,
timestamp, shared credential, model inference, alert text, or product phase
number.
