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

The image entrypoint, an exec readiness probe, an exec lifecycle hook,
`kubectl exec`, and a direct runtime exec can all start independent process
trees in the same container. They can have the same cgroup, namespaces,
binary, arguments, and Unix identity.

Stock kubelet and CRI do not tell a node security product why every such
process was created. In particular, stock `ExecSyncRequest` does not say
whether it came from readiness, liveness, `PostStart`, or `PreStop`. Mithril
therefore does not invent a signed kubelet intent. It proves that the task is
an independent root, identifies its container, and applies a restricted
external-root role. A configured, supported hook may add only the facts that
its real interface provides.

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
| KubeArmor | Enforces file, process, network, and capability-oriented policy with Linux security mechanisms, including BPF LSM; integrates Kubernetes identity and policy. | The checked implementation does not provide Mithril's immutable per-task/process authority lifecycle, complete multi-node/provider causal graph, coverage vector, or re-resolved and physically verified response contract. Neither product can recover a kubelet purpose that stock CRI never exposes. |
| Tetragon | Observes kernel process and syscall activity, tracks fork/exec state, filters by cgroup and workload, supports runtime-hook integration, and has real enforcement paths including Generic LSM override and a separate enforcer. | Its event/process model is not by itself Mithril's permission-bearing task/process/entry/authority-domain state, and it does not alone provide the complete policy-generation, provider-correlation, and verified-response contract. Its runtime metadata is useful fact, but it does not prove an unexposed probe or lifecycle purpose. |
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
  -> a new or unknown process tree receives no application authority
  -> its first governed file/network/device/privilege effect is denied
  -> any completed remote action is joined with authority-owned IDs
  -> response re-resolves every live branch and verifies it stayed fenced
```

Any one of those barriers may stop this branch. The complete product keeps the
later barriers even when the earliest one is expected to succeed.

### 4. Mithril's Unique Contract

The product is the following chain of guarantees. Removing one item changes
the claim, even if installation becomes simpler.

1. **No changes to workloads or platform source code.** Installing Mithril
   adds one `mithril-node` owner per node and the Mithril control service.
   Operators may configure documented extension points that already exist,
   such as OCI hooks, NRI, runtime plugins, Kubernetes audit/API integrations,
   CI provider integrations, and hook verification. Mithril does not patch,
   fork, rebuild, or replace kubelet, containerd, runc, CNI, or a CI runner.
   It does not change Pod manifests, images, application code, process layout,
   probes, lifecycle hooks, workload credentials, traffic paths, TLS, or the
   agent harness.
2. **One node gatherer.** One Rust process owns all Mithril BPF programs,
   runtime admission, local evidence, and local response. Several BPF programs
   are implementation details of that one owner.
3. **Exact actor before effect.** Every protected task has immutable task
   identity that resolves to mutable process and authority-domain state before
   it can perform a protected effect.
4. **Independent roots never inherit application authority.** Mithril learns
   native parent/child relationships from the kernel. A task created outside
   the application tree but placed in the same container is a separate
   external root. Stock Linux and CRI often cannot prove whether that root is
   a probe, hook, administrator, or attacker, so the baseline gives it one
   conservative external-root policy or denies it. It never guesses purpose
   from command text or timing.
5. **One readable source policy.** Operators describe entries, roles,
   transitions, effects, shared authority, dispositions, responses, and
   exceptions in one signed package. A compiler rejects ambiguity and lowers
   it into bounded local records.
6. **Local decisions stay local.** A qualified BPF LSM or cgroup BPF hook
   denies the physical effect synchronously. Central services and existing
   runtime components never sit in a syscall path.
7. **Immutable activation.** Existing actors stay pinned to the generation
   they began under. Their fork/exec/privilege changes follow transitions
   already compiled into that signed policy generation. A partially written
   generation never becomes active.
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
12. **Claim by fixture, not intention.** Every advertised kernel, Kubernetes,
    and provider combination is backed by a named fixture and
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
- If an attacker can replace the kernel, BPF links/maps, configured stock
  runtime integration, or policy owner, local prevention becomes unknown unless
  an independent boundary proves those components remain intact.
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
| `rejected` | A higher-level request was refused by an existing authority before completion. Mithril uses this word only when that authority already exposes a supported rejection API. | Kubernetes admission or a provider API rejects a request; the unchanged-node baseline does not call a locally denied process effect “runtime rejection.” |
| `contained` | Every branch named by the response plan has an applied restriction; unresolved branches remain visible. | Known local tasks and sockets are fenced while a remote credential is still `UNRESOLVED`. |
| `verified` | Required postconditions stayed true through a healthy interval that includes source delay and watermark. | No replacement Pod appeared before the Kubernetes watch watermark passed the verification end. |

Relations use four proof levels:

| Relation | Required proof | Concrete example |
| --- | --- | --- |
| `exact` | Stable IDs from the authority owning both ends, or a complete kernel identity chain | Task cookie + process lineage + cgroup live interval for one observed Linux effect |
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
  ├── reads existing Kubernetes, containerd, procfs, cgroupfs, and kernel state
  ├── binds observed Pods, containers, cgroups, tasks, images, and policies
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

#### The protected workload and platform binaries stay unchanged

The rule is simple: installation and supported integration are allowed;
redesigning the protected system is not.

```text
allowed additions:
  one mithril-node DaemonSet Pod or equivalent host package per node
  Mithril's control service
  configuration of documented OCI, NRI, runtime, Kubernetes audit/API,
    CI provider, and verification extension points
  small stateless hook adapters that forward to mithril-node when the
    extension point requires a hook executable
  Mithril-owned read-only audit credentials and separately approved
    response credentials
  Mithril BPF programs, maps, links, local WAL, and control connection

not allowed:
  patches, forks, or rebuilt kubelet, containerd, runc, CRI, CNI, or CI runner
  replacement of those components with a Mithril-specific build
  changes to applications, PodSpecs, images, process layout, probes,
    lifecycle hooks, workload credentials, or the agent harness
  traffic redirection, DNS replacement, TLS interception, or a mandatory
    provider proxy
```

In particular, the baseline does not require:

- one job per Pod or one job per process;
- application instrumentation or an application event for every job;
- a sidecar;
- a different ServiceAccount;
- narrower RBAC or IAM;
- a TLS proxy;
- a changed agent harness; or
- removal of legitimate mounted credentials.

Mithril may read APIs and files the existing system already exposes. It may
also be registered through an official hook or plugin interface. That
registration does not let Mithril claim facts the interface does not carry.
For example, an OCI hook can report an exact container and lifecycle point; it
does not thereby reveal that a later `ExecSync` was a readiness probe.

A required adapter remains part of the one gatherer design when it is small
and stateless: it forwards one hook call to `mithril-node`, has no policy
engine, durable database, event sequence, or independent recovery state, and
fails exactly as the configured extension-point contract specifies.

The same rule applies outside Kubernetes:

| Existing system | Allowed Mithril integration | Forbidden dependency |
| --- | --- | --- |
| Kubernetes/container runtime | Configure existing audit, validating-admission, OCI, NRI, or runtime interfaces; read stock APIs; verify their fields, order, timeout, and failure result | Patched kubelet/containerd/runc, new CRI methods, changed Pod manifests/images/commands, or a ticket added to probes/hooks |
| Kafka or another message system | Read existing broker audit/authorization records and stable topic/partition/offset/message IDs; call an existing response API when authorized | Changed producers/consumers, a required new message header, a Mithril broker, or a patched Kafka build |
| CI/CD | Read existing provider job/audit APIs and configure an official plugin/hook when available | Patched runner, changed workflow/job code, wrapper command, replaced credential, or trusted callback invoked by job code |
| Database | Read existing database audit/session records and use existing authorization/kill-session APIs | Database proxy, TLS termination, client instrumentation, query rewriting, schema change, extension, or patched server |
| Cloud/source-control/SaaS | Read existing issuance/audit/resource APIs and use existing provider permissions/response APIs | Replacing the workload's token, changing its client, inserting a connector, or claiming an audit event prevented an action |

**Kafka example.** A producer process on node A publishes a record. If existing
Kafka evidence exposes topic, partition, offset, producer identity, and record
ID, Mithril can join those facts at the documented proof quality. If the
application never puts a unique ID in the record and Kafka exposes only a
shared principal, Mithril reports a shared-principal or contextual edge. It
does not ask the application to add a header and then call that the baseline.

**Database example.** Hostile Python and a legitimate controller use the same
database account over TLS. Mithril can distinguish their local processes and
can deny the whole database destination for Python. Database audit can later
show the completed query under the shared account, but may not identify which
local process sent it. Unless the existing database exposes a suitable
authorization API or distinct session identity, Mithril does not claim
query-level prevention or exact process-to-query causality.

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
| Local file, exec, socket, device, process-control, mount, namespace, capability, or kernel effect | Synchronous BPF LSM or cgroup BPF hook installed by Mithril | The hook controls the physical effect and does not wait for a central service |
| Initial container or later runtime-created process | Kernel process/cgroup tracking, read-only Kubernetes/containerd/procfs discovery, and optionally a configured stock OCI/NRI/runtime hook | A hook may improve timing and exact container/task binding only if its documented interface provides those facts. Stock CRI still does not expose probe/hook purpose. Unknown external roots receive a restricted role. |
| Kubernetes, repository, connector, CI, or provider request | Existing audit/result APIs and supported authorization or admission extension points that the operator explicitly configures | Mithril may reject only through a real existing API. It does not patch a client or insert TLS interception. |
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
- If an existing provider already exposes a policy or rejection API, an
  operator may separately authorize Mithril to use it. The baseline never
  inserts a broker or connector into the workload's request path.
- Otherwise policy may deny the whole destination/channel or allow it and
  detect the provider operation later. Mithril must show that trade-off.

GitHub does not generally turn an arbitrary existing write-capable bearer token
into a new read-only token. A GitHub App can request an installation token with
narrower permissions only within the installation's granted authority and the
provider's supported rules. That is a provider-issued capability, not token
derivation performed by Mithril.

#### Boot order and installation choices

A DaemonSet alone cannot promise protection before the first workload on a new
node. Kubelet must already run to start the DaemonSet. Other workloads may run
before every required BPF link and map is loaded and checked.

A simple DaemonSet installation records a measured `START_GAP` from node boot
until every required program, map, binding, and readback is healthy. It makes
no first-exec or boot-complete protection claim during that interval.

An operator may instead configure an existing node startup mechanism and
supported OCI/NRI/runtime hook so `mithril-node` is ready before protected
workloads. This is an allowed Mithril integration, not a workload architecture
change. The release must test the exact extension point and state what it can
block. It may not require patched or rebuilt runtime binaries.

On a node where BPF LSM is not available and active, the affected prevention
claim is `UNSUPPORTED`. Mithril must state the required host setup openly; it
must not describe a reboot or LSM boot-configuration change as zero-touch.

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

Mithril uses the facts that really exist:

```text
kernel creator and cgroup placement
  + exact container identity and reviewed workload definition
  + any authoritative purpose exposed by an existing supported interface
  -> initial/native/external classification
  -> narrow policy; missing purpose never grants more permission
```

The command does not decide the role.

```text
application child -> /app/healthcheck -> keeps application lineage
readiness probe -> /app/healthcheck -> restricted external-root role
attacker kubectl exec -> /app/healthcheck -> restricted external-root role
```

The binary, arguments, cgroup, and namespaces can be identical. The kernel can
still distinguish the labeled native child from a new external root. Stock
CRI usually cannot distinguish the purpose of two external roots, so Mithril
does not pretend otherwise.

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

A normal `kubectl exec` uses Kubernetes, kubelet, and the runtime. The Linux
task is a restricted external root. Kubernetes audit separately records the
API request and principal. A cluster may deliberately allow a stronger
administrative role through Mithril's short-lived, one-use next-match rule.
That rule does not prove an exact request-to-task join. The approving
administrator explicitly accepts the rare risk that another otherwise
identical runtime-created root could win the short race and consume the slot.

###### Approved administrative exec: from the browser to the next exact matching Linux entry

The restricted external-root rule is the safe baseline. A configured cluster
may offer a stronger administrative-exec role, but only through the complete
flow below. Installing only the client plugin or only the admission webhook is
not enough.

The administrator runs one command:

```text
$ kubectl mithril exec -it -n production api-7d9c -c api -- bash

Approval required for:
  cluster:   production
  pod:       production/api-7d9c
  container: api
  command:   bash
  tty:       yes

Opening https://mithril.example/activate
Code: JQTM-HVPK

Waiting for approval...
Approved by alice@example.com
Connecting...
```

The `kubectl-mithril` process waits while the browser interaction happens. It
does **not** send `pods/exec` and make a Kubernetes webhook wait for a human.
Admission webhooks have short bounded timeouts. After approval, the plugin
sends one ordinary Kubernetes `CONNECT pods/exec` request and attaches the
terminal streams. Stock kubectl plugins cannot replace the built-in
`kubectl exec`, so the explicit command is `kubectl mithril exec`.

The browser uses the organization's normal identity provider and displays the
exact cluster, Pod UID, container, argv, TTY/stdin settings, requested Mithril
role, expiry, and approver. A workstation may use browser OIDC with PKCE. A
headless or SSH client may show a short device code and poll. Entering a code
identifies the pending request; it does not itself approve the request. Policy
decides whether the requester may self-approve or needs a second person.

The requested operation is exact and one use. Its later Linux-task binding is
intentionally a bounded next-match association rather than an exact propagated
request ID:

```text
ApprovedAdministrativeExecV1 {
  approval_id
  authenticated_requester
  authenticated_approver
  cluster_id
  namespace
  pod_uid
  full_container_id
  container_generation
  canonical_argv_digest
  stdin_stdout_stderr_tty_flags
  approved_role_id
  policy_generation
  target_node_id
  issued_at
  expires_at
  one_use = true
  task_binding = NEXT_MATCHING_RUNTIME_EXTERNAL_ROOT
  requester_accepted_rare_binding_race = true
}
```

This is a Mithril authorization, not a statement supposedly signed by kubelet.
The plugin receives a short-lived, memory-only Kubernetes exec credential. A
configured stock Kubernetes authentication integration validates it and places
the non-secret approval ID in `AdmissionReview.userInfo.extra`. The credential
uses a dedicated identity or group that has authority only for the protected
`pods/exec` path; it must not reproduce the requester's general Kubernetes
permissions. The validating admission webhook remains the enforcement
boundary, so ordinary `kubectl exec`, curl, a modified plugin, and replay all
fail without a live approval.

The validating admission webhook then performs this transaction:

```text
receive CONNECT pods/exec
  -> authenticate approval ID from userInfo.extra
  -> parse the real PodExecOptions
  -> resolve Pod name to current Pod UID, container ID, and node
  -> verify requester, argv, streams, role, policy generation, and expiry
  -> ask the target mithril-node to prepare one BPF admission slot
  -> require successful map/link health and slot readback
  -> atomically commit the approval to that slot
  -> return allowed=true
```

If the target node is offline, the container changed, the node cannot install
the slot, or any value differs, the webhook rejects the API request. The human
wait occurred before this transaction, so this node round trip must fit the
ordinary short webhook deadline.

`mithril-node` is still the only node gatherer, BPF loader, and kernel-policy
owner. The central control service routes the prepare request over the node's
existing authenticated control stream; this does not add a sidecar or a second
node daemon. Control's `AdministrativeApprovalOwner` owns the browser challenge
and human decision. The target node's `AuthorizationProofOwner` validates and
consumes the signed node authorization. Its `WorkloadBindingOwner` owns the BPF
slot and exact task-role assignment. The node then installs a bounded one-use
value such as:

```text
ApprovedExecSlotV1 {
  approval_id
  pod_uid
  full_container_id
  container_generation
  cgroup_binding_id
  expected_argv_digest
  expected_stream_flags
  approved_role_id
  policy_generation
  expected_entry_class = RUNTIME_EXTERNAL_ROOT
  monotonic_deadline
  accepted_binding_risk = NEXT_EXACT_MATCH_MAY_RACE
  state = ARMED
}
```

BPF does not parse OAuth, JWT, CBOR, Kubernetes objects, or signatures. Rust
does that work and writes the already verified bounded slot. BPF performs only
kernel identity checks, bounded map lookups, and an atomic one-use transition.

Stock Kubernetes does not carry the admission approval ID into the Linux task.
Mithril deliberately accepts that limitation for this administrator-approved
feature. Immediately before the webhook returns `allowed=true`, the node arms
one short-lived slot. The next previously unlabeled runtime-created external
root that matches the exact Pod UID, full container ID and generation, cgroup
binding, argv digest, stream flags, policy generation, and deadline may consume
it. The operation is an atomic `ARMED -> CONSUMED` transition, so at most one
task receives the role.

This is not command recognition. An application child already carries Mithril
task identity and is ineligible before argv is considered. A different Pod,
container generation, cgroup, command, or stream shape cannot match. The
remaining risk is narrow but real: two new runtime-created external roots with
the same complete match can race, and the first one reaching the BPF decision
wins. The approval screen states this risk, cluster configuration must enable
it, and the administrator accepts it for that invocation.

Containerd runtime exec IDs and lifecycle events remain useful evidence. A
qualified runtime-specific adapter may correlate them and make the association
stronger, but the approved feature does not require unstable tracing of Go
function offsets or argument layouts. An adapter failure never broadens which
task can match the bounded slot.

At task creation and `bprm_check_security`, the BPF program applies this rule:

```text
if task already has a Mithril identity:
  use its existing native lineage policy
  never let it inspect or consume an administrative-exec slot

else if one ARMED administrative slot exactly matches this new
        runtime-created external root:
  verify Pod UID, full container ID, cgroup, container generation,
         executable/argv, stream flags, role, policy generation, and deadline
  atomically change ARMED -> CONSUMED
  install APPROVED_ADMINISTRATIVE_EXEC in BPF task storage
  evaluate the initial executable under that role

else:
  assign RUNTIME_EXTERNAL_RESTRICTED or deny, as configured
```

Descendants of the approved task inherit that bounded administrative lineage.
Every later exec, file, mapping, socket, device, process-control, and privilege
effect still passes the normal policy. Approval does not disable Mithril. A
typical diagnostic role may allow a shell, logs, and named internal health
endpoints while still denying ServiceAccount-token reads, runtime sockets,
mount, BPF, ptrace, host devices, persistence, and arbitrary Internet egress.

The accepted race is bounded as follows:

- an application process already has identity and cannot consume a slot;
- the slot exists only after admission approval and for a short configured
  monotonic-time window;
- Pod UID, full container ID and generation, cgroup binding, argv, streams,
  role, and policy generation must all match;
- only one matching slot may be armed for a container, and its state change is
  atomic;
- BPF protects the runtime socket from ordinary workloads, reducing who can
  deliberately create a competing runtime root;
- a probe, lifecycle hook, direct runtime caller, or second approved session
  with the same complete match can still win the race; this is the precise
  residual risk accepted by cluster policy and the approving administrator;
- Pod replacement, container restart, node restart, expiry, map loss, or sensor
  loss invalidates the slot; and
- a second use of the approval or slot fails the atomic state transition.

The durable evidence chain is:

```text
requester and approver
  -> one-use approval ID
  -> Kubernetes AdmissionReview UID and PodExecOptions
  -> Pod UID, container generation, and target node
  -> node BPF slot
  -> recorded next-match rule and accepted race
  -> consuming Linux task/process/lineage identity
  -> optional containerd runtime exec ID correlation
  -> every governed effect and final result
```

`ADMIN-EXEC-APPROVAL-001` races an application child, readiness `ExecSync`,
direct runtime caller, two identical approved sessions, Pod replacement, node
restart, and an expired approval. The application child can never consume the
slot. At most one complete matching external root may consume it. The test
records whether a deliberately injected identical runtime root won the race;
that outcome is an accepted-risk result, not a false claim of exact binding.
Every non-winner receives the restricted external role. If the cluster or
administrator has not accepted this binding mode, the stronger role is
unavailable and the restricted external role remains the baseline.

##### Node/runtime bypass

`crictl exec`, direct runtime APIs, shim manipulation, `nsenter`, or moving a
host task can bypass Kubernetes. They receive no application authority.
Appearing in a protected cgroup creates a restricted external or unresolved
root, not permission.

#### Kubernetes cases that must stay distinct

| Situation | What Linux/runtime actually creates | Mithril treatment |
| --- | --- | --- |
| Initial application process | Runtime-created root in a new container cgroup | Bind exact Pod, container, image, cgroup lifetime, initial root task, and policy from runtime inventory or a configured stock start hook |
| Fork or thread | Native child | Kernel inheritance from the labeled creator; no runtime ticket |
| Exec `PostStart` | Possible second root, concurrent with application start | Restricted external root; declaration is context, not exact purpose, unless an existing supported interface supplies a unique join |
| Exec `PreStop` | Possible second root during termination | Restricted external root; keep enforcement until every task/socket exits; containment wins over the ordinary external budget |
| Exec startup/readiness/liveness probe | Repeated secondary roots | Restricted external root with a common intersection budget; no probe role from argv or timing |
| HTTP lifecycle hook | Connection made by kubelet | No workload root; record node flow and declared-hook context |
| HTTP, TCP, or gRPC probe | Connection made by kubelet | No workload root; application receiver thread does not become a probe process |
| Sleep lifecycle hook | Sleep inside kubelet | No workload task |
| `kubectl exec` | Runtime-created root and Kubernetes stream/audit | Restricted external root by default. A stronger approved role requires `kubectl-mithril`, validating admission, node slot preparation, explicit acceptance of the rare race, and atomic consumption by the next complete matching runtime-created external root. |
| `kubectl cp` | Usually exec of archive tooling | Restricted external root; `tar` is not proof of benign use; stream/file effects need explicit permission |
| Direct runtime exec | Runtime-created root without Kubernetes user audit | Restricted external root; default deny for protected effects outside its common budget |
| Restore/migration | May recreate tasks, memory, fds, sockets, mappings, devices, and namespaces without normal exec | Reject through an existing qualified authorization hook, otherwise restrictive BPF treatment plus `UNSUPPORTED` for exact restore history |
| `attach` | Streams attach to an existing process | Stream authority; no new root or role |
| `port-forward` | API/kubelet stream forwards traffic | Stream/flow authority; no new process edge |
| Ephemeral container | Separate container root, possibly sharing PID namespace | Separate execution set found from its real container identity; default deny or configured diagnostic profile |
| Init container | Separate ordered container root | Separate execution set, image, and init role from existing Pod/container metadata |
| Native sidecar | Separate independently restarted root | Separate execution set and sidecar role from existing Pod/container metadata; shared Pod network does not merge process lineage |
| OCI hook process | Runtime infrastructure, often outside workload cgroup | Infrastructure observation only; shared namespaces never grant workload role |
| `nsenter` or moved host task | Unlabeled external task | Deny first protected effect and report `unknown-external-entry` |
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
3. Exact different roles are available only if an existing supported interface
   already supplies authoritative purpose and a unique request-to-task join.
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

The OCI runtime—not Mithril—creates namespaces, mounts the root filesystem,
places the task in a cgroup, and starts the configured process. Mithril does
not reproduce that work and does not require a special runtime build.

Mithril's job is narrower:

```text
observe the real task and its real kernel parent
  -> decide whether it is a native descendant or a new independent root
  -> bind it to the already discovered container and policy
  -> apply the correct kernel permission before each covered effect
```

#### What “child of containerd” does and does not mean

At the host level, a runtime shim or runtime helper commonly creates the
container's first task and later exec tasks. Inside a PID namespace, those
relationships can look different. Reparenting can also change the parent PID.
Mithril therefore never uses the display value `PPid` or “containerd is an
ancestor” as permission.

It records the creator at the kernel task-creation hook and separately records
the task's cgroup, PID namespace, mount namespace, container ID, and lifetime.
An application fork is a native descendant because its creator already has a
Mithril task label. A task created by a runtime helper and placed into the same
container is an independent root because its creator is not part of the
application tree.

**Example.** The application process forks `/app/healthcheck`. That child
keeps the application's role, even if its command matches the Pod readiness
probe. Later kubelet asks the runtime to execute the same path. The second task
has a runtime/helper creator, so it receives the external-root role. Command
text never changes either classification.

#### The stock-system admission algorithm

Every task in or entering a protected container is in one of these states:

```text
NATIVE_DESCENDANT       creator already had a Mithril label
INITIAL_CONTAINER_ROOT  exact initial task of a discovered container
EXTERNAL_RUNTIME_ROOT   new root in that container; exact purpose unavailable
UNRESOLVED_PROTECTED    protected placement is known but identity is incomplete
OUTSIDE                 proved outside Mithril's protected scope
```

The implementation performs these steps:

1. `mithril-node` watches Kubernetes and the container runtime's supported
   read-only APIs. It builds a binding from full container ID and cgroup
   lifetime to Pod UID, container name, image digest, and policy generation.
2. If a configured stock OCI, NRI, or runtime hook reports an earlier or more
   precise lifecycle fact, the node verifies that fact against kernel and
   runtime state and adds it to the same binding. The hook is not a second
   policy owner.
3. At task creation, BPF copies authority only when the creator already has a
   valid task label. This is the native-child path.
4. A task whose creator has no protected label does not inherit application
   authority merely because it enters the container cgroup. It is an initial
   root, external runtime root, unresolved protected task, or outside task.
5. The known initial root receives the configured container-entry role. A
   later independent root receives `RUNTIME_EXTERNAL_RESTRICTED` unless it
   atomically consumes the complete approved-administrative-exec slot from
   Chapter 6 as the next complete matching runtime-created external root. This
   exception carries the recorded administrator-accepted race. An unresolved
   protected task receives the local fail-closed floor.
6. Every file, exec, socket, device, privilege, and process-control hook reads
   the task result before making its decision. Event delivery is not on this
   decision path.
7. Userspace later enriches the evidence with Kubernetes audit or runtime
   events. Later enrichment may improve attribution, but it cannot rewrite a
   past allow or pretend that unknown purpose was known before the effect.

The cgroup binding and restrictive defaults must exist before Mithril claims
prevention for a container. If a process runs before the binding exists, the
honest result is either a denied protected effect or a recorded start gap. It
is never “exactly admitted before first user instruction” unless a particular
supported integration really proves that ordering.

#### What a supported hook may add

A supported hook is useful, but each claim is limited to its actual contract:

| Hook fact actually provided | What Mithril may conclude | What it may not conclude |
| --- | --- | --- |
| Container ID, bundle, cgroup, and lifecycle point | This exact container is being created or started; prepare or verify its binding | Why a later exec task exists |
| Exact PID or pidfd for a newly created task | This exact live task belongs to the reported operation, after kernel revalidation | That the operation is readiness, liveness, lifecycle, or administrator activity when the interface omits the reason |
| A synchronous documented failure result | The extension point rejected that request when Mithril returned failure | That the workload executed no instruction unless the hook ordering proves it |
| An event delivered after start | The event provides observation/enrichment from that time | Pre-start admission or prevention |

For every supported platform, qualification records the precise hook name,
ordering, request fields, failure behavior, timeout behavior, and a test using
the stock released binaries. Product documentation must not generalize one
runtime's result to another runtime.

#### Probes, lifecycle hooks, and administrative exec

Stock `ExecSyncRequest` carries container ID, command, and timeout. It does not
carry the caller's reason. Therefore the no-patch baseline deliberately uses
one external-root role for exec probes, exec lifecycle hooks, `kubectl exec`,
and direct `crictl exec` when they cannot be distinguished by stronger existing
evidence.

This role is configured by permission intersection, not permission union:

```text
external-root role may execute /app/healthcheck
external-root role may read /run/healthy
external-root role may not read the ServiceAccount token
external-root role may not open an external network connection
external-root role may not execute /bin/sh or /usr/bin/curl
```

If readiness and `PreStop` both use `/app/check`, but `PreStop` needs a network
call that readiness does not, Mithril cannot safely give only `PreStop` that
permission from stock CRI evidence. The operator has three honest choices:

1. allow the common intersection and accept that `PreStop` may fail;
2. explicitly grant the wider permission to every indistinguishable external
   root and see the larger risk in policy review; or
3. deny all such external roots.

A configured qualified integration may assign separate roles when it supplies
an authoritative purpose and a unique task/request join. The approved
administrative path in Chapter 6 is the deliberately narrower exception: the
plugin and admission webhook authorize one operation, then a BPF slot grants
the role to the next complete matching runtime-created external root. The
administrator accepts the rare ambiguous-match race. A local Mithril signature
over an observation proves that Mithril recorded the observation; it does not
turn missing kubelet purpose into a general fact.

#### Initial processes and processes already present on the node

For a new container, a configured supported hook can let Mithril prepare the
cgroup binding before the runtime starts the process. If no such hook is
configured, the BPF program applies the protected-but-unresolved floor until
userspace completes the binding.

When Mithril starts on a node that already has workloads, it binds each
protected container cgroup to policy. BPF then checks the next covered action
from every task in that cgroup. Mithril does not reconstruct the task's past,
retrofit start-time controls, or claim that actions before the binding were
covered.

#### Streaming exec, attach, and port-forward

Kubernetes streaming exec has a prepare request and a later stream connection.
Stock interfaces may expose an audit request without exposing a unique
request-to-task identifier all the way into the created Linux process.
Mithril therefore treats the resulting independent task as
`RUNTIME_EXTERNAL_RESTRICTED` by default; it does not insert a stream proxy or
replace the runtime URL. The configured approved-administrative-exec path in
Chapter 6 may assign a stronger role only after its plugin, admission, node
slot, exact match, and atomic one-use BPF consumption succeed. Runtime exec ID
correlation is optional evidence, not a prerequisite or an exactness claim.

`attach` and `port-forward` do not create a workload process. Kubernetes audit
and network evidence may record and correlate them. A configured Kubernetes
authorization extension may reject a request if its official API and ordering
support that result. Without such an extension, audit is detection after the
request, not prevention.

**Test.** Run a readiness probe, `kubectl exec`, and direct `crictl exec` with
identical argv and reverse their creation order. All three external roots get
the same restricted budget. A native application child with the same argv
keeps the application lineage. No case receives a more powerful role because
of timing or command text.

#### Attacker-created unmatched workloads

Protecting only known Pod selectors leaves a simple escape: stolen broad
Kubernetes authority creates a brand-new privileged Pod that has no Mithril
profile, mounts `/`, and becomes node root.

Mithril needs two layers because one installation mode cannot make both
claims:

1. A configured Kubernetes validating-admission integration can reject a
   dangerous Pod specification before scheduling. This is an existing
   Kubernetes extension point; it does not require a patched kubelet, changed
   workload manifest, or custom runtime.
2. BPF LSM and cgroup BPF apply a node hard floor to the new tasks' covered
   file, network, device, process-control, and privilege effects even if audit
   is late or an API path bypasses admission.

A supported NRI/runtime integration may also reject a create/start request if
its documented stock callback has that authority and ordering. Mithril must
qualify the exact runtime; an after-start notification is not admission.

If no workload profile matches, signed Mithril policy chooses exactly one:

```text
REJECT_UNMATCHED
BASELINE_HARD_FLOOR(exact floor profile)
OBSERVE_ONLY_WITH_START_GAP
```

The attacker cannot choose this posture through Pod fields. It comes from
separately signed node policy.

The validating-admission layer rejects unless an independently approved exact
exception allows the following Pod fields. The BPF hard floor separately
denies the later covered physical effects:

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
`/host/etc/shadow`.

- With the configured validating-admission integration, the Kubernetes API
  rejects the Pod before scheduling.
- If the attacker bypasses that API path, the node floor denies the first
  covered read, device, mount, process-control, or network effect. Mithril does
  not falsely claim the host mount setup itself was prevented unless a
  qualified runtime hook actually rejected it before setup.
- With sensor-only installation and a start gap, the result is only what the
  measured BPF hooks prove.

A reviewed CSI DaemonSet with an exact non-expired exception remains the
legitimate control.

The full original plan currently marks this floor
`UNALLOCATED_REQUIRED_FOR_FULL_HF_CLAIM`. It must be assigned to approved
phases before a release claims prevention of the privileged-Pod branch.

#### Checkpoint creation and restore

Restore can recreate processes, memory, open files, devices, sockets, and
namespaces without a normal exec. Kernel ancestry observed after restore is not
enough to reconstruct all earlier authority.

The no-patch baseline therefore does not claim transparent exact restore
admission. It can:

- reject a checkpoint/restore request through a configured existing
  Kubernetes or runtime authorization hook when that hook supports rejection;
- identify restored tasks as new or unresolved roots and apply the restrictive
  BPF floor to their next covered effects; and
- report that memory, open-descriptor, and earlier ancestry reconstruction is
  incomplete.

Exact resume-before-user-code support would require a stock runtime extension
that holds and enumerates every restored task and object. If the deployed
runtime does not provide that contract, the capability is `UNSUPPORTED`; the
plan may not solve it by patching CRIU or the runtime.

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
target, and lost audit cases. The expected result is rejection through a
qualified existing hook, restrictive BPF treatment, or honest `UNSUPPORTED`—
never an invented held-task guarantee.

Checkpoint support remains `UNALLOCATED_OPTIONAL` until the master and phase
plans assign its owner and tests.

#### Attach and port-forward

Neither operation creates a workload process. Attach connects to an existing
process; port-forward creates a stream to a Pod endpoint. Mithril records the
Kubernetes request UID, actor, target, ports/channels, audit result, and the
network/process evidence the stock interfaces expose. It does not invent a
task role or a remote parent edge.

An existing Kubernetes authorization integration may reject the request. If
only audit is configured, Mithril can detect and respond after the request but
cannot claim it prevented the stream. Inserting a Mithril stream proxy or
replacing the runtime URL is outside the no-change contract.

`ENTRY-STREAM-001` covers audit mismatch, wrong Pod/container, extra port,
reverse direction, disconnect, and identical `pods/exec`. Each case states
whether the configured interface proves rejection, observation, completion,
or only an unknown result.

### 8. Proving Why An Entry Or Authority Exists

Process identity answers “which live Linux task is this?” It does not answer
“why was this task or credential requested?” Sometimes the existing system
provides that second fact. Sometimes it does not. Mithril must preserve the
difference.

This distinction prevents a common mistake:

```text
wrong:
  command == /app/healthcheck
  therefore this is a readiness probe

correct on stock Kubernetes:
  task T was created by an unlabeled runtime-side creator
  + task T appeared in protected container C
  + stock CRI supplied no probe/hook/admin reason
  therefore T is an exact external root with unknown purpose
  therefore T receives the restricted external-root role
```

If the already-running application executes the same path, its existing task
and process identity survives exec and follows the native-exec policy. If an
attacker uses `kubectl exec` with the same path, that new task is an external
root. The command does not consume a ticket and does not decide the role.

Kubernetes audit may later prove that a named user requested `pods/exec` for
the container. Unless the deployed stock interfaces carry a unique identifier
from that request to the Linux task, the relation between that request and one
of several concurrent identical roots is only conservative or contextual.

#### Three kinds of proof

Mithril keeps these records separate:

| Proof | Real example | What it proves |
| --- | --- | --- |
| Kernel fact | Task cookie, creator edge, cgroup lifetime, executable object | What the Linux task did and where it ran |
| Existing-system fact | Kubernetes audit request UID, containerd container ID, GitHub audit ID | What that system recorded at its own boundary |
| Authorized intent | A Mithril response approval or a provider-issued signed claim | What the real signer authorized, limited to fields it actually owns |

Signing a normalized event does not upgrade it. If `mithril-node` signs “I saw
an external task run `/app/check`,” the signature protects that statement from
tampering. It does not prove kubelet's missing reason.

#### The common signed intent, where a real intent exists

When Mithril itself owns an authorization, or an existing integration really
provides a signed authorization, Mithril uses one canonical `SignedIntentV1`
envelope. It does not use this type for ordinary stock kubelet events. Its
payload contains:

- version, proof ID, tenant, trust domain, issuer, signing key, and algorithm;
- issuer sequence epoch and sequence;
- issue, not-before, and expiry times;
- one or more explicit, unique, sorted one-use claim-slot IDs;
- exactly one closed intent body;
- optional parent proof and trigger proof IDs.

Supported bodies are:

| Intent | What it proves | Where it is consumed |
| --- | --- | --- |
| `RUNTIME_ENTRY` | A supported existing integration authorized a specific runtime operation and supplied an exact request-to-task join | That integration's documented admission point; unavailable for ordinary stock CRI probe/hook purpose |
| `NATIVE_TRANSITION` | Reserved for an exceptional Mithril-owned one-use authorization; routine fork/exec/privilege decisions use the actor's compiled policy | Qualified native transition hook only when a feature explicitly allocates this intent kind |
| `AUTHORITY_LEASE` | An operator approved use of an existing provider capability with bounded audience, permissions, resources, and TTL | Existing provider authorization/issuance API when it exposes the required fields; never a mandatory traffic proxy |
| `ARTIFACT_HANDOFF` | Exact bytes from one producer may be read, verified, loaded, executed, or deployed by one consumer | Object/loader/deploy gate for that digest and operation |
| `PROVIDER_OPERATION` | An existing provider authorization API approved one operation on named resources | That provider API; ordinary audit remains after-the-fact evidence |
| `DEPLOYMENT_ADMISSION` | Mithril policy approved a workload definition, image, security fields, multiplicity, nodes, and profile generation | Configured stock Kubernetes admission or supported runtime admission extension |
| `CI_STEP` | An existing CI API or official plugin interface supplied an immutable job/step assignment | Correlation and any action that the existing interface can actually reject; never a patched runner claim |

The exact integer-keyed deterministic-CBOR schema, bounds, tags, and Ed25519
golden vector belong in Appendix A. They define Mithril's own signed records;
they do **not** require kubelet, containerd, runc, a CI runner, or a workload to
implement CBOR or Ed25519. Existing integrations keep their native protocol,
and `mithril-node` records the source and proof quality of the received facts.
Security IDs are fixed-size bytes, not display strings. Unknown fields,
duplicate fields, indefinite encodings, non-canonical bytes, unregistered
numeric tags, wrong variant fields, and a decode/re-encode mismatch are parser
errors for a real `SignedIntentV1`.

The issuer cannot select fail-open behavior. The signed payload does not carry
`disposition_on_mismatch` or `disposition_on_expiry`; locally signed policy
does. It also cannot send a reusable count. It sends explicit one-use slots.

**Example.** An operator approves one Mithril response that revokes cloud
session S. The signed record contains one use slot. A second use is rejected
as replay. By contrast, three stock kubelet readiness checks produce no
Mithril intent slots; they are three external roots under the same restrictive
budget.

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
5. Expose each slot only to the Mithril owner of the authorized action.
6. Record every later consumption transition in that owner's state and WAL.
```

A BPF hook never waits for disk. If the authorized action is a local kernel
transition, userspace prepares all bounded state before the hook can consume
it. Provider and response actions use their own durable owner. After a crash,
the owner replays the WAL and reconciles its action state before accepting a
new use.

The common authorization state is:

```text
ACCEPTED
  -> CLAIMING
  -> CONSUMED

or terminal:
  ACTION_FAILED | EXPIRED | CANCELLED
```

**Crash test.** Kill `mithril-node` after the response owner wins the slot CAS
but before it records the provider result. On restart, the same slot cannot be
used for a second action. The first action remains `UNKNOWN` until provider
readback resolves it; Mithril does not blindly retry a non-idempotent action.

#### Stock kubelet probe and lifecycle limitation

Stock CRI `ExecSync` does not carry “readiness,” “liveness,” `PostStart`, or
`PreStop`. Matching argv and timing cannot distinguish concurrent identical
requests.

Mithril does not add a kubelet call site, a new CRI method, or a ticket-aware
runtime. Those designs require patched platform binaries and are outside the
product contract.

| Available stock evidence | Honest result |
| --- | --- |
| Kernel creator/cgroup facts only | Exact external root and container; purpose `UNKNOWN` |
| Existing OCI/NRI/runtime hook supplies container and lifecycle event | Earlier or stronger container binding; later exec purpose still `UNKNOWN` unless the interface explicitly carries it |
| Kubernetes audit proves `pods/exec` actor and request UID but no task join | Exact API request, exact Linux task, contextual or conservative relation between them |
| Existing supported interface supplies authoritative reason plus unique request-to-task ID | Exact purpose is permitted only after the interface, ordering, and join pass qualification |
| Direct `crictl ExecSync` | External runtime root; it never receives a probe/hook role from command matching |

**Concrete ambiguity.** `/app/check` is both a readiness probe that may read
`/run/healthy` and a `PreStop` hook that may call `/drain`. Giving an unknown
request the union is unsafe: every readiness check would gain drain authority.
The default is rejection. A configured intersection is allowed only if
simulation proves the real operation still works. An explicitly approved union
is a broad exception, not “conservative” and not part of the exact claim.

`ENTRY-EXTERNAL-AMBIGUITY-001` starts readiness, liveness, `PostStart`,
`PreStop`, `kubectl exec`, and direct `crictl ExecSync` with identical argv and
reverses task creation order. Every indistinguishable external root receives
the same compiled restriction. The test fails if any role is inferred from
argv, timing, PodSpec resemblance, or an unsigned local event.

#### AWS and Google login create provider authority, not a process-entry kind

Running `aws sso login`, `gcloud auth login`, or `gsutil` does not create a
special Mithril entry kind. The CLI follows its real native process lineage.
Mithril does not replace the CLI login flow or credential. It records local
process/file/network effects and the provider issuance/audit facts that the
existing provider APIs expose. `AuthorityLeaseIntentV1` is used only when
Mithril itself is authorized to request a provider capability through an
existing provider API.

AWS example:

```text
exact labeled aws process
  -> local policy allows or denies its cache files and AWS destinations
  -> existing AWS login/STS flow runs unchanged when allowed
  -> CloudTrail records the session/account/role fields AWS preserves
  -> Mithril joins local process and provider session only at the proof quality
     supported by shared IDs, network facts, time bounds, and coverage
```

Policy separately controls the CLI executable, its cache/config objects, the
identity and API destinations, and which descendants may use already visible
cache files. A shared AWS SSO cache is not an exact task-to-session proof. If
the unchanged flow exposes no unique identifier from the local request through
CloudTrail, the join is conservative or contextual; Mithril does not insert a
broker to improve it.

Google workload-identity example:

```text
existing CI OIDC claim
  -> unchanged Google STS exchange and optional service-account impersonation
  -> downstream audit identifies the fields that service actually preserves
```

Google audit does not universally preserve the source OIDC `jti`. If the
existing deployment already maps an immutable job identifier into
`google.subject`, Mithril may use and qualify that field; it does not require
the deployment to add it. If downstream audit exposes only a shared service
account, the operation is exact for that account but only contextual for one
local job; job-exact automatic response is ineligible.

Secret material never enters evidence, the graph, logs, or WAL. If an existing
provider API gives Mithril a non-secret revocation handle, it may store that
opaque handle as `ProtectedCredentialHandleV1` and authorize only
`REVOKE_SELF`. Mithril does not copy a workload's bearer credential into a new
vault merely to create a handle. Without a provider handle, response must use a
wider existing provider action or wait for expiry.

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

#### No command-based pre-exec claim

An earlier design allowed an unlabeled task to claim a prepared role by
matching its cgroup, executable, arguments, and timing. That design is wrong
for the no-patch product. Two concurrent requests can have identical values,
and attacker code can deliberately copy them.

The replacement is simpler:

```text
labeled native task -> native exec transition
known initial container task -> configured container-entry role
any later independent root with missing purpose -> restricted external role
unresolved protected task -> deny protected effects until resolved
```

No task claims a kubelet ticket. No argv classifier turns an external root into
a probe, lifecycle, CI-step, or administrator role. Appendix B retains the old
ticket design only as rejected history so it is not accidentally reintroduced.

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
| `INV-ENTRY-002` | An unlabeled task inside protected placement receives no application authority. It is resolved as an initial root, a restricted external root, or a fail-closed unknown. | A host process enters the namespaces/cgroup and opens the projected token; the hook returns `EACCES` and no byte is read. |
| `INV-ENTRY-003` | Reparenting and PID, namespace, cgroup, runtime, or kubelet reuse cannot change birth lineage. | A replacement process with the same visible PID/path cannot resolve the old task cookie, live interval, nonce, boot epoch, or entry. |
| `INV-ROLE-001` | Only an admitted entry or approved transition assigns a role. A path/name never assigns authority. | Approved updater and compromised worker both execute `curl`; each keeps the authority of its own entry/transition. |
| `INV-ROLE-002` | Fork without exec is restricted immediately; exec keeps lineage but creates a new execution and reviewed role transition. | A forked Python child cannot read a credential before exec; non-leader exec cannot escape during de-threading. |
| `INV-EFFECT-001` | Rules are expanded to exact keys; different physical results need a signed override or compilation fails. Missing required identity, generation, classifier, table, or response state denies. | An output path symlinked to a token resolves to the token object; conflicting allow/deny does not depend on “specificity” or file order. |
| `INV-EFFECT-002` | Telemetry, WAL, ring, rate-limit, or central-service pressure cannot turn a computed local denial into allow. | Fill the event ring while repeating token reads; every read still fails and loss counters increase. |
| `INV-POLICY-001` | Only a signed, validated, compiled, read-back generation can authorize. Learning never self-authorizes. | Observed malicious Kubernetes API use becomes a review candidate, not a new allow row. |
| `INV-POLICY-002` | Activation is atomic; old generations stay until every typed holder has ended. | Generation 42 tasks and sockets remain valid under 42 while new entry N receives 43; 42 is removed only after task/socket/object/response refs reach verified zero. |
| `INV-K8S-001` | Initial container roots, native descendants, separate init/sidecar/ephemeral containers, and later external roots stay distinct. Indistinguishable external purposes never receive invented roles. | An application child running `/app/healthcheck` keeps application lineage. Readiness and `kubectl exec` roots running the same bytes both receive the restricted external role unless an existing qualified interface proves more. |
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
CPU use requires a qualified task-creation hook, a Seccomp floor that Mithril
successfully installed on that process at start, a supported runtime admission
hook, `pids.max`, or a CPU controller. A file hook cannot claim that result.

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
  entry: restrict-external
  admissionRequest: reject-when-configured-interface-supports-it
  transition: deny
  file: deny
  network: deny
  device: deny
  privilege: deny

failurePosture:
  missingTaskIdentity: deny
  requiredClassifierUnknown: deny
  runtimeMetadataUnavailable: restrict-external-or-deny-effect
  providerFeedUnavailable: alert
  notificationUnavailable: keep-enforcement-and-buffer

entries:
  - id: initial-worker
    kind: container-start
    imageDigest: sha256:approved-worker-image
    role: conversion-worker
    onMismatch: unresolved-fail-closed

  - id: stock-runtime-external
    kind: external-runtime-unknown
    creator: outside-labeled-application-tree
    role: runtime-external-restricted
    purpose: unknown

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

  runtime-external-restricted:
    # Stock CRI cannot distinguish readiness, PreStop, kubectl exec, or
    # direct runtime exec. This is the common safe budget for all of them.
    files:
      - {operation: read, class: probe-health-file, disposition: allow}
      - {operation: write, class: declared-cleanup-state, disposition: allow}
    network:
      - {operation: send, destination: declared-drain-endpoint, disposition: allow}
    onActiveContainment: deny
    childProcesses: deny
    devices: []
    privilege: []

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
trees and effects; it does not require one Pod or one process per job. A
readiness task, `PreStop`, `kubectl exec`, and direct runtime exec all receive
the same external budget because stock CRI does not expose their purpose. That
budget can read the health file, update the declared cleanup file, and contact
only the drain endpoint; it cannot read the mounted token or use the public
Internet. An attacker who enters through `kubectl exec` receives those same
limited permissions, not application authority.

This example deliberately does not enable the approved administrative-exec
feature. A deployment that enables it adds the explicit approved role and the
plugin, admission, node-slot, runtime-join, and failure settings from Chapter
6. Merely adding a wider role to this YAML cannot make stock `kubectl exec`
eligible for it.

If the drain permission is too broad, the operator may remove it and accept
that `PreStop` fails, or deny external roots entirely. Giving only `PreStop`
the drain permission requires a qualified existing interface that supplies an
authoritative purpose and unique task join. No policy field can manufacture
that missing fact.

#### Entries, roles, transitions, and effects

An entry rule names the proven root class, container kind, evidence source and
proof quality, lifecycle states, target role, and default result. Initial
container identity can come from existing Kubernetes/runtime metadata. A
later stock runtime exec normally has `purpose=UNKNOWN` and receives the
external role.

Canonical argv is length-delimited raw bytes:

```text
u32_be(argument_count) || for each argument:
  u32_be(byte_length) || raw_argument_bytes
```

There is no shell re-tokenization, whitespace folding, Unicode normalization,
or comparison against redacted display text. Argv may be checked as an effect
allowed to an already assigned role. It never assigns the role, proves probe
or lifecycle purpose, or replaces physical file/network/device policy.

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

- `REMOTE_PRE_ADMISSION`: an existing configured synchronous Kubernetes,
  provider, or connector authorization API may allow, alert-and-allow, or
  reject without changing that product's code or traffic path; or
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

Therefore a token `open(2)` can be `deny + finding`. A runtime start is
`reject` only when a configured stock admission hook actually returned the
rejection; otherwise the root's protected effects are denied. A provider audit
record can only `alert + optional response`.
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
   is classified as initial, restricted external, restored/unknown, or
   fail-closed unresolved; it never claims a command-based entry ticket.
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
| Existing mount namespace | The workload's existing namespace changes the filesystem view: host paths may be absent and mounts may already carry `ro`, `noexec`, `nosuid`, and `nodev`. Mithril measures that view and uses it when identifying objects. | Mithril does not change the Pod manifest or rebuild the mount view. Any object still visible needs another control. A mount namespace does not distinguish a native child from an external root or govern network/provider actions. |
| Landlock | When a supported start path lets Mithril install it in a new process, Landlock adds a monotonic restriction inherited by descendants. Available filesystem, network, Unix-socket, signal, and device-ioctl rights depend on the measured ABI. | Landlock is a start-time floor. It cannot be centrally loosened or dynamically rewritten, and it does not supply Kubernetes purpose, multi-node causality, or response orchestration. |
| Seccomp | When a supported start path lets Mithril install it in a new process, Seccomp cheaply removes whole syscall classes or scalar-argument shapes a role never needs. Installed filters are inherited and can only become stricter. | Seccomp is a start-time floor. It cannot safely resolve pathname pointers, file objects, target PIDs, Kubernetes roles, or TLS/provider semantics. |
| BPF LSM | Makes dynamic task-aware decisions at Linux security hooks for files, exec, sockets, process control, devices, capabilities, mount, BPF, perf, and other qualified operations. It can use Mithril's task/process/domain state before effect. | It must be built and active as an LSM; helper/hook support varies by exact kernel. It cannot parse arbitrary TLS application intent or wait for a central service. GPL-compatible license is required for BPF LSM object programs that use the kernel's GPL-only interface. This does not automatically relicense the separate Rust program. |
| Cgroup BPF | Enforces workload/device floors, connect/send address policy, packet fences, and some socket operations at cgroup boundaries. | Cgroup membership alone is not per-process intent. Packet hooks may lack a meaningful current task. |
| TC/XDP/cgroup-skb | Drops actual packets, including established flows, after a response or final destination rewrite. | A packet does not reliably identify which of several sharing processes queued the bytes. Whole-socket/cgroup blast radius may be necessary. |
| Traditional SELinux/AppArmor | Adds mature distribution-owned mandatory policy and stacking defense. | Mithril cannot assume its hook observes every earlier denial; ordering and audit coverage are measured. |
| Supported runtime/admission extension | Lets Mithril prepare identity or reject a start at the exact point the stock interface documents. Some launch interfaces may also install Seccomp/Landlock in the new target. | A callback cannot claim fields, ordering, target-context execution, or rejection behavior that its interface does not provide. It does not control hostile code already executing inside an admitted process. |

Where the existing mount view and supported start path permit it, the
strongest ordinary worker can therefore receive all four local floors without
changing its manifest, image, code, or command:

```text
existing mount namespace: host files absent; exact mounts and immutable flags
Landlock installed by Mithril at supported start: monotonic local floor
Seccomp installed by Mithril at supported start: unused syscall families removed
BPF LSM/cgroup: exact current task, runtime entry, object, domain state,
                dynamic response, device/network/privilege enforcement
```

These layers intersect. None can turn another layer's denial into allow.
Seccomp and Landlock are used only when Mithril can install them during a
supported new-process start. Otherwise Mithril relies on BPF for the effects
BPF can cover. Missing a required BPF LSM hook makes that particular claim
unsupported even when the namespace still hides many objects.

#### Pairwise examples: what each two-layer combination adds

Use one unchanged conversion worker as the example. It needs
`/dataset/input`, `/work/output`, its Python runtime, DNS, and one result
service. It must not read the ServiceAccount token, inspect the host, create a
TUN device, or reach Kubernetes.

| Pair | Concrete result | What is still missing |
| --- | --- | --- |
| Mount namespace + Landlock | Host `/etc`, `/proc`, runtime sockets, and devices are not mounted into the worker; Landlock still denies undeclared opens under the visible dataset/work tree if a bind/symlink/layout mistake exposes them. | Both are installed before run and mostly monotonic. They do not know that a new probe root and the application root need different authority, or dynamically fence an already-running compromised lineage. |
| Mount namespace + seccomp | Host objects are structurally absent; `mount`, `ptrace`, `bpf`, `perf_event_open`, module, keyring, and unused namespace/syscall families can be removed cheaply. | A visible token and an allowed `connect` syscall still need object/destination/actor policy. Seccomp cannot follow a pathname or distinguish two roles that need the same syscall. |
| Mount namespace + BPF LSM | Namespace removes whole host regions; BPF LSM distinguishes the converter's native lineage from later external roots on every remaining exact file/exec/device/privilege object and can add a response restriction at runtime. | Stock CRI still does not distinguish probe, lifecycle, and admin purpose among identical external roots. Whole unused syscall classes may still reach deeper kernel parsing unless Seccomp removes them. |
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
namespace without a direct syscall there. Mithril does not change the
workload's mount propagation or automount configuration. It measures the real
topology and must mark every affected namespace `DIRTY` before relying on a new
object decision. If a platform cannot provide that ordering, the exact
file-object claim is `UNSUPPORTED` for the affected mount and strict policy
denies the unresolved object. Bounded-fanout overflow sets a common fail-closed
state.

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
memory executable without a later `mprotect`. Rust parses bounded immutable
ELF metadata during image/object discovery and binds executable-stack,
interpreter, architecture, static/dynamic, and personality meaning to the
exact immutable object. The BPF exec hook performs a bounded lookup; it does
not parse mutable ELF bytes or wait for Rust. An executable not yet classified
is denied under a strict profile.

Kernel-created executable mappings such as vDSO/vvar, legacy vsyscall, and
architecture signal gates are fixed measured classes bound to exact kernel
build/architecture/personality. They never become “allow all anonymous RX.”

Mithril does not try to reconstruct mappings created before it began covering
a task. BPF governs later covered effects. A claim that requires control from
process start is available only for a process started under that control.

VMA snapshots use pidfds, task iteration, version counters, and
`kcmp(KCMP_VM)` to form exact shared-address-space equality classes without
exporting raw kernel pointers. One serialized task-VMA iterator runs per class;
versioned binary frames must reach validated EOF, then tasks, pidfds, start
times, sharers, and every equality comparison are repeated. A concurrent
change makes the negative snapshot incomplete and triggers retry or a
conservative result. `/proc/<pid>/maps` may prove a positive observed mapping
but cannot prove a concurrent negative snapshot.

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

Initial application, sidecar, init, ephemeral-container, and later external
roots may share `emptyDir`, `/dev/shm`, IPC namespace, Unix sockets, and the Pod
network while having no native parent relation. Stock CRI may not reveal
whether a later external root is a probe, lifecycle hook, or administrator;
shared-resource protection does not depend on knowing that purpose.

Mithril builds the communication-domain candidate from existing Pod/container
metadata plus the real volume backing objects, mount views, and network/IPC
namespaces it observes. Before a task may use a protected shared channel, the
BPF decision requires one of three results: the participants are already in a
common restrictive domain, an atomic pre-use join succeeds, or the operation
is denied. A later external root enters with its restrictive role and cannot
use the channel while the join is unresolved. No held runtime barrier or
future-entry ticket is required. The durable domain may span several execution
sets and outlive any one container.

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
mappings may have no later read hook. When Mithril binds a protected workload,
it uses the metadata and kernel state that already exist to find these cases.
If possession cannot be disproved, the domain starts with
`POTENTIAL_SENSITIVE_IN_MEMORY`. The honest choices are to apply the common
restriction, deny the shared channel, or report that prevention is unsupported.

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
commit index. On every protected participant, BPF denies access to the volume
until `mithril-node` has fetched the latest non-rollback record, installed the
local restriction, and read it back. Mithril does not hold the mount, change
CSI, or change the workload.

Before Mithril permits a covered file effect on an RWO/RWOP/RWX participant, a
writable volume is marked potential-sensitive when any participant could
obtain protected material. Every protected RWX node installs the common
restriction before allowing that effect. If an operator rejects that scope,
deny protected access to the volume or report cross-node publication
prevention unsupported.

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
DENY_DNS_AND_USE_POLICY_RESOLVED_ADDRESSES
PLAINTEXT_DNS_PACKET_POLICY
DESTINATION_ONLY_WITH_PAYLOAD_GAP
```

Mithril's plaintext DNS packet policy parses and bounds ordinary UDP/TCP DNS at
the node's BPF network hooks. It can limit exact/suffix qname, type,
response/CNAME, size, rate, and cardinality while denying alternative resolver
destinations. It does not replace or modify the cluster resolver. Fragmented,
malformed, unsupported, or encrypted DNS follows the configured deny or
destination-only result. Destination-only mode must state
`DNS_PAYLOAD_SEMANTICS_UNENFORCED`.

DoH, DoT, and HTTP CONNECT inside an otherwise allowed TLS service remain
opaque unless their endpoints are denied or the service exposes typed
admission/audit.

#### No TLS interception and semantic limits

Mithril does not terminate direct TLS. Linux can allow an email endpoint and
deny GitHub, or allow separately issued credentials/endpoints/processes. It
cannot distinguish email send from another API verb on the same allowed TLS
channel, or `git clone` from `git push` when process, host, port, connection,
and bearer token are identical.

For verb-level prevention, use a capability or authorization feature that the
real provider already exposes: for example a GitHub App installation token
with provider-supported read permissions. Mithril may configure or call that
existing API when authorized; it does not modify the provider, application, or
traffic path. An arbitrary write-capable bearer token cannot in general be
locally transformed into a narrower token. Without a distinct provider
capability, policy must deny the channel or allow it and use provider audit for
later detection/response.

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

The OCI runtime remains responsible for normal setup such as namespaces,
mounts, UID/GID, capabilities, securebits, and `no_new_privs`. Mithril does not
reimplement those operations. A configured stock admission hook may inspect
the requested security settings and reject them only if its documented timing
and return contract permit that result. BPF separately controls the later
covered operations performed by runtime helpers and workload tasks.

#### Seccomp facts

Ordinary installed seccomp cannot be weakened or detached by the task; the old
idea “detect a task weakening its filter” is factually wrong and abandoned.
Mithril instead verifies installation when a supported start path installs the
filter, and governs dangerous new user-notification or ptrace/TRACE supervisor
relationships.

`/proc/<pid>/status` shows mode/count, not arbitrary filter bytecode. Proof is:

```text
INSTALLER_ATTESTED: qualified Mithril start integration installed exact bytes
                    in the new target before its user code, then verified
                    mode/count/TSYNC scope
KERNEL_OBSERVED: qualified kernel path proves exact installed identity/content
PRESENCE_ONLY: some filter exists; digest is not proved
ABSENT: no floor claimed
```

Correct and wrong filters can have the same mode/count. Only the first two may
prove exact rules. Partial TSYNC, wrong bytecode, install failure,
`NEW_LISTENER`, USER_NOTIF, and TRACE are fixtures. If the supported start
interface cannot execute the install in the new target before user code,
Seccomp is `ABSENT`; a generic external OCI callback is not silently treated
as an installer.

Seccomp cannot authorize `/proc/<target>/mem` by pathname: it cannot safely
dereference and authenticate the userspace pointer. The defender inspector
uses an owner-opened fd plus seccomp fd/syscall confinement and BPF exact target
checks as described above.

#### Landlock facts

Landlock ABI and handled rights are measured on the actual node. Filesystem,
device ioctl, TCP/UDP, pathname/abstract Unix socket, and signal rights vary by
ABI. A supported Mithril start integration may install a monotonic floor in a
new target before user code. If that target-context start capability is absent
or the ABI lacks a right, Mithril records the layer absent and evaluates BPF
coverage independently. It does not require a wrapper in the image or a
changed workload command.

Landlock does not replace BPF LSM for multiple independent roots,
same-container role differences, cross-process domains, dynamic response,
exact cgroup/runtime identity, devices/privilege families outside its ABI, and
correlated evidence.

The installation rule is explicit:

| Process situation | Seccomp/Landlock result |
| --- | --- |
| Mithril directly launches the process, such as an Erebor-governed agent/tool process | Mithril's child setup installs the compiled floors before the final program. This changes neither the program image nor its code. |
| Existing supported launcher/runtime interface offers target-context pre-user-code installation | Mithril configures that interface, installs both floors, reads back what the kernel exposes, and qualifies the exact version. |
| Generic external OCI/NRI callback supplies metadata but cannot execute in the target context | It cannot install Seccomp/Landlock merely by being a hook. Mithril uses BPF and reports these floors absent. |

There is no retrofit path. If Mithril did not install the floor during process
start, Mithril does not depend on that floor for its protection claim.

This is a Mithril capability, not a requirement to modify Kubernetes, a
container image, a CI runner, an application command, or application code.

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
node. Mithril normalizes every source into one versioned envelope. This is the
readable field guide; Appendix A.15.1 is the one authoritative
`ObservationEnvelopeV1` definition:

```text
readable observation envelope {
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
readable proof-quality axes {       // exact ProofQualityV1: Appendix A.15.2
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

Findings are immutable revisions. This is the readable lifecycle view;
Appendix A.15.2 defines exact `FindingV1` fields:

```text
readable finding revision {
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
| Local authority -> Kubernetes request | Unique `jti`/fingerprint/request ID already exposed by both sides or by an existing service | Shared ServiceAccount name is insufficient. Mithril does not modify the client or API server to add an ID. |
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
| `ALG-INTENT` | Mithril-owned approval or a real existing signed authorization; never invented kubelet/runner intent |
| `ALG-ENTRY` | Kernel creator tracking, container/cgroup binding, initial/native/external root classification, and restricted unknown handling |
| `ALG-LINEAGE` | Fork/thread/exec identity and transition |
| `ALG-FILE` | Mount-aware object and file/mapping decision |
| `ALG-NET` | Current actor + socket provenance + destination/flow decision |
| `ALG-DEVICE` | Device, ioctl, capability, namespace, mount, BPF, perf, ptrace, and other privilege effects |
| `ALG-AUTHORITY` | Existing Kubernetes/cloud/mesh/connector/source-control authorization API or authoritative audit package; no required product modification or traffic proxy |
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
| `HF-016` | Worker reaches internal connector catalog and obtains cluster context | Worker-to-connector destination denied. An existing connector authorization API may reject the catalog request when configured; audit-only mode alerts the exact request/result. | The published connector request was direct inside the cluster, not through mesh. `ALG-XNODE` keeps direct connector and mesh branches separate. Shared `system:masters` creates explicit cluster-A and cluster-B authority branches. Mithril does not require connector code changes. |
| `HF-017` | Harvested AWS credentials used externally and from the worker | External replay: provider detection/response only. Worker-local STS/database/raw-exfil destinations: local deny where distinguishable. | `ALG-AUTHORITY` binds exact access-key/session operation but not one Linux reader of a shared key. `ALG-NET` separately controls worker sockets. Provider timeout is not Mithril prevention. |
| `HF-018` | Connector/GitHub mints write-capable App tokens, enumerates repos, attempts CI-triggering PR | Existing GitHub App permissions or authorization APIs may reject. Audit-only mode alerts supported downstream operations; otherwise response uses the narrowest provider action the existing API exposes. | `ALG-AUTHORITY/ARTIFACT`. Standard GitHub audit must not invent a token-mint event. Token hash/fingerprint is correlation, not the bearer secret needed to revoke itself. Mithril does not replace the connector or proxy GitHub TLS. |
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
but may not name the local task. Only a unique ID already carried and exposed
by the existing systems, a unique provider lease, or another registered edge
makes that join direct.

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

For GitHub, an existing connector/provider issuance record may include App,
installation, repositories,
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
| `HF-GRAN-HOSTPATH-001` | New privileged/hostPID Pod mounts host `/` with dangerous capabilities | Configured stock Kubernetes validating admission rejects the Pod, or a qualified stock runtime hook rejects the start. If neither exists, the BPF node floor denies covered host effects and the result must not claim the mount setup itself was prevented. Exact CSI/host-agent policy exception is the positive control. |
| `HF-GRAN-RESPAWN-001` | Self-respawning Pods fan out across eleven nodes | Existing Kubernetes admission rejects before persistence when configured; otherwise every node applies the restrictive unmatched-workload floor and response fences known roots/controllers. No replacement marker during the healthy watch. |
| `HF-GRAN-CONNECTOR-DIRECT-001` | Worker reaches connector without mesh | Local destination errno/no request, semantic connector rejection, or explicit audit-only semantic gap. Legitimate connector service succeeds. |
| `HF-GRAN-CLUSTER-SHARED-001` | One shared credential is valid in two clusters | Cluster operations stay authoritative; local cause remains contextual without per-request IDs; supplying distinct IDs upgrades only correct edges. |
| `HF-GRAN-MESH-ROOT-001` | Rooted managed node attacks Mithril and starts mesh | Intact mechanisms may deny. Successful required-link/runtime tamper closes local coverage before mesh attempt; no self-containment claim. |
| `HF-GRAN-MESH-SOCKS-001` | External userspace SOCKS mesh uses no TUN | Provider response on external subject; device policy explicitly inapplicable. A managed equivalent still has exec/listen/control-socket gates. |
| `HF-GRAN-MESH-ENUM-001` | 181 devices enroll and enumerate nodes/routes/CI subnets | Rate/cardinality finding; separately revoke enrollment key and remove exact devices; verify both. Approved automation within signed count/window succeeds. |
| `HF-GRAN-AWS-SPLIT-001` | Same key used externally and by worker for STS, MongoDB, raw exfil | External provider result and local socket decisions remain separate. Worker calls get errno/no packet; provider timeout is not prevention. |
| `HF-GRAN-AWS-DRYRUN-001` | Cloud mutation requested with `DryRun=True` | Provider result classified as auth check; resource unchanged. An existing AWS authorization boundary may reject; audit-only mode alerts. |
| `HF-GRAN-GITHUB-MINT-001` | Connector mints write-capable installation token | Existing connector/GitHub authorization may reject; otherwise record exact issuance evidence when exposed. Audit-only mode is unsupported for undocumented mint. A possessed protected handle can self-revoke; a hash cannot. |
| `HF-GRAN-GITHUB-TREE-PR-001` | Enumerate repo tree and create CI-triggering PR | Exact PR/commit/workflow state; code stays `untrusted_change`; privileged CI leases absent/rejected. Normal bot/dependency PR is control. |
| `HF-GRAN-GITHUB-REARM-001` | Repeated fresh tokens fetch payload into new external sandboxes | One lease/fingerprint/consumer branch each; managed executions denied; outside consumers keep response partial. |
| `HF-GRAN-TOKEN-FORGE-001` | Valid EdDSA token absent from issuer ledger | Only complete issuance coverage plus matching `kid+jti`/fingerprint permits `VALID_TOKEN_ABSENT_FROM_ISSUANCE_LEDGER`; otherwise forgery unobservable. |
| `HF-GRAN-CAPTURE-001` | 100+ single-use endpoints/raw sockets collect output | Managed sends deny/no packet; provider/network actuator disables exact endpoints and watch proves no reuse. Source IP/time joins remain contextual. |
| `HF-GRAN-CI-BUILDRS-001` | Malicious `build.rs` uses CI credential | Result depends on existing delivery: projected file deny, identity-endpoint deny, existing read-only provider scope, or environment/same-TLS semantic gap and provider alert. Mithril does not replace the credential. |
| `HF-GRAN-OUTSIDE-001` | `HF-001`–`HF-007` preparation outside estate | External subjects only; no local task, errno, or response target invented. Managed replay tests the first real local hook. |
| `HF-GRAN-HOST-LOC-001` | Same host-inspection text from managed, external, and unresolved sources | Only managed exact branch gets local deny/response; external is outside authority; missing location stays unresolved. |

Every card stores syscall result, buffer/file before/after state, packet
capture/drop counter, provider request/result and resource state, coverage
intervals, generation, and graph/finding digest. An alert screenshot is not a
fixture result. Missing required hook/adapter must produce the card's degraded
status and disable that product claim.

#### End-to-end production branch

1. Mithril discovers the reviewed conversion image and binds the initial task
   as `conversion-worker`. A configured qualified stock start hook can prepare
   that binding early; otherwise protected effects deny until binding and the
   measured start gap remains explicit.
2. HDF5 resolves a hostile reference. A strict file rule denies it; an
   alert-only deployment permits the exact file action and a separate later
   publication decision still occurs.
3. Jinja runs inside Python; no fake task/exec is created. Projected-token open
   reaches the same process identity and normally denies.
4. Kubernetes/IMDS connect normally denies for the worker. An allowed controller
   channel proceeds to provider behavior rules; audit after success alerts but
   cannot retroactively deny.
5. A configured stock Kubernetes validating-admission integration may reject
   the privileged Pod before persistence. Audit-only success instead creates
   object/controller/runtime branches and triggers containment.
6. Each new Pod root on every node is separately classified and restricted.
   Cross-node graph
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

#### Exact incident action-card contract

The human tables above explain the incident. They do not by themselves tell a
test runner which source fields, lookup key, degraded result, or oracle to use.
Every branch is also stored as this closed record:

```text
HfRepresentativeActionCaseV1 {
  event_id: HF-001 .. HF-021
  case_id: bounded unique ID inside the event
  published_fact_ref: exact live-stream or technical-timeline anchor
  fixture_id: exact member of NormativeFixtureSetV1
  authority_scope: MANAGED_EXACT | EXTERNAL_EXACT |
                   OUTSIDE_AUTHORITY | LOCATION_UNRESOLVED
  required_capability_ids[]
  required_observations[] {
    source_id
    payload_schema_id
    exact_required_fields[]
    coverage_interval_id
    minimum_proof: ProofQualityV1
  }
  ordered_lookup_plan[]: LookupStepV1
  compiled_control {
    profile_generation_ref_id
    evaluation_stage
    exact_key_type
    exact_key_fields
    expected_disposition
    expected_errno?
    expected_finding_reason?
    response_binding_ids[]
  }
  expected_result {
    physical_result
    oracle
    expected_proof: ProofQualityV1
  }
  degraded_cases[] {
    missing_capability_or_proof
    result
    prohibited_claim
  }
  legitimate_control_case
  upstream_source_evidence_ids[]
}

HfGranularAcceptanceV1 {
  test_id
  published_fact_ref
  upstream_source_evidence_ids[]
  fixture_topology_and_starting_authority
  input_observation_ids_and_exact_fields
  required_coverage_intervals
  minimum_proof_vector: ProofQualityV1
  algorithm_and_policy_generation
  compiled_decision_key_or_package_key
  expected_decision_stage
  expected_disposition
  physical_or_provider_oracle
  legitimate_negative_control
  degraded_or_unsupported_result
  expected_finding_reason_and_proof_vector
}
```

The branch set is fixed even when several branches share one event:

| Event | Required branches that must not be collapsed |
| --- | --- |
| `HF-001` | External root; separately protected managed replay |
| `HF-002` | External reconnaissance; managed helper; already resident environment |
| `HF-003` | External tools; managed copied/renamed executable |
| `HF-004` | External publication; managed connect; allowed send result; provider-confirmed publication |
| `HF-005` | External staged file; managed object with trusted provenance; ordinary source file |
| `HF-006` | Pure in-memory packing; later boundary-crossing effect |
| `HF-007` | External search; managed destination; documented service-semantic query |
| `HF-008` | Worker-local forbidden object; optional synchronous upload gate |
| `HF-009` | Protected read; resident environment; result publication; same allowed TLS channel |
| `HF-010` | Pure in-process expression; later helper or physical effect |
| `HF-011` | Open attempt; positive-byte read; inherited/passed fd; already resident memory |
| `HF-012` | New connection; destination rewrite; existing socket; allowed controller verb |
| `HF-013` | Distinct channel; existing provider read-only capability; same-TLS write |
| `HF-014` | Intact managed enforcement; tampered/unknown enforcement; independent mesh/provider source |
| `HF-015` | Synchronous mesh admission; audit-only removal of already enrolled devices |
| `HF-016` | Direct worker-to-connector; catalog-to-cluster operation; shared-credential ambiguity |
| `HF-017` | External AWS use; same-worker AWS use; credential acquisition-to-use join |
| `HF-018` | Existing connector/provider issuance; standard audit capability; repository/PR operation; revocation or broader response |
| `HF-019` | External loader; managed generic exec/map/connect; trusted same-digest correlation |
| `HF-020` | Managed exact; external exact; location unresolved |
| `HF-021` | Verified physical response; silence-only non-proof |

**Complete `HF-008` example.** The published fact is the hostile HDF5
external-file reference. The managed case requires the exact existing worker
task/process/domain, current mount view, final resolved mount/filesystem/object
generation, healthy file-open hook and identity coverage, and the compiled
worker role. Its local lookup is the ordinary task-first `LOCAL_EFFECT_V1`
sequence for `FILE/OPEN_READ`. The expected result is `DENY/EACCES`; the
syscall obtains no fd, no protected byte reaches HDF5, and no marker appears in
the conversion result. The legitimate control is a declared dataset chunk in
the admitted read-only dataset view. Missing mount-generation or exact-object
classification produces classifier-unknown denial or an explicit unsupported
claim—not a basename/path guess.

The optional upload-scanner case is a different card at
`REMOTE_PRE_ADMISSION`. It may reject before scheduling only when an actual
synchronous gate capability is installed. Its absence does not weaken the
worker-local file denial, and a later scanner/audit event must not be reported
as local prevention.

For `LOCAL_PRE_EFFECT`, `ordered_lookup_plan` expands to the exact sequence in
Appendix A.12. For remote admission, it names the authenticated gate and typed
request. For post-effect provider evidence, it names the documented request,
result, resource revision, and coverage but never a retrospective rejection.
For outside-authority cases, local task/cgroup/map fields must be absent rather
than zero-filled.

Every card stores the syscall/provider result, relevant before/after object or
buffer state, packet/drop evidence where applicable, provider resource state,
coverage interval, policy generation, graph/finding digest, and negative-
control result. An alert screenshot, command text, or final quiet period is not
an oracle.

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
| `CI0_JOB` | Existing CI API proves the job/runner assignment; kernel facts identify the job's local roots and descendants; policy is job-wide | Exact step purpose or separation of a credential already shared by all steps |
| `CI1_PROCESS_LINEAGE` | CI0 plus exact local process/file/socket ancestry and untrusted-input propagation | That one process corresponds to a named YAML step when the stock runner exposes no unique join |
| `CI2_OFFICIAL_STEP` | An existing supported runner/plugin API supplies immutable step identity and a unique join to the actual task/root; no patched runner | Clone versus push inside one same-credential TLS channel; any field absent from the official API |
| `CI3_PROVIDER_AUTHORITY` | Existing provider permissions or authorization API prevents the named provider operation | Operations that the provider exposes only through after-the-fact audit |

GitHub `GITHUB_TOKEN` and OIDC permission are job/workflow scoped; documented
OIDC claims do not prove one shell step. Mithril cannot derive a read-only token
from an arbitrary installed write bearer token. GitHub App installation tokens
can request provider-supported narrower permissions using App authority; that
is new provider issuance, not local attenuation.

**Clone/push example.** Checkout and hostile code both use `github.com:443` and
the same job token. Mithril can identify each process but cannot read the
encrypted smart-HTTP verb. It can deny the whole GitHub channel to one process.
If the unchanged CI job must use the same write-capable token from both
processes, Mithril cannot allow clone and deny push locally. Existing provider
permissions may prevent the write; otherwise provider audit detects it after
the request. Mithril neither replaces the token nor terminates Git TLS.

#### What stock CI can and cannot prove about a step

GitHub preview container hooks describe execution but are not an unforgeable
provider-signed step identity and do not cover ordinary native host jobs.
Mithril does not patch GitHub Runner, GitLab Runner, Jenkins, Tekton, or any
other runner. It uses only these existing facts:

```text
CI API: workflow/pipeline, job, attempt, runner, commit, and provider IDs
Linux: exact process creator, exec chain, cgroup, files, sockets, and lifetime
artifacts: source revision, digest, producer, verification, and later use
optional official plugin: only the step/task join its documented API supplies
```

GitHub `check_run_id` can identify a job, not an individual shell step. If two
steps both run `/usr/bin/bash` under the same runner process and no official
interface supplies a unique task join, Mithril records exact job identity and
exact process lineage but `step_purpose=UNKNOWN`. It never signs its own guess
and calls that exact.

Tekton often gives each step a separate declared container, so existing Pod
and container identity can distinguish those roots without runner changes.
GitLab custom executors or Jenkins plugins may expose more, but only an
official supported configuration is allowed. If enabling it changes job code,
images, commands, or the runner binary, it is outside this architecture.

Generated temporary scripts are still tracked as real executable objects.
Mithril hashes the bytes it observes at execution and retains file-generation
provenance. Workflow digest alone does not prove those bytes. If exclusive
integrity cannot be proved because the file remains mutable, the result says
so; Mithril does not rewrite the runner to use sealed files.

#### Physical CI shapes

| CI action | Mithril identity and control |
| --- | --- |
| Host job/shell | Existing runner/job root plus exact native process tree. Named step stays unknown unless an official supported interface joins it. |
| Job container | Independent container root joined to the CI job with existing provider and container IDs; credential scope is what the real job already has. |
| Script/JS/composite action | Exact native exec and executable/data provenance; no invented step transition or nested intent. |
| Container action/service | Independent container root and contextual/exact coordinator edge according to available IDs; shared workspace/network causes pre-use authority-domain checks. |
| Matrix/parallel job | Separate job and node-local trees; coordinator edge only. |
| Reusable workflow/downstream pipeline | Typed call edge with caller/callee digests and effective permission; no implicit authority increase. |
| Cache/artifact | Immutable artifact and consumer slot; read-as-data does not grant execute/deploy. |
| OIDC/cloud login | Observe the exact local requester and existing OIDC/provider issuance/audit fields; claim job/step binding only at the tier those fields support. |
| Deploy (`kubectl`, Helm, Terraform, cloud CLI) | Local process effects plus semantic provider request/audit and remote object/runtime branches. |
| Post/finally/cleanup | Separate narrow role under terminal job lifecycle; active containment still wins. |
| Interactive debug terminal | Restricted external root plus CI/provider audit actor and approval when available; never a build role by command matching. |
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
5. The resulting process/domain receives `ci-untrusted-build`: no repository
   endpoint, cloud identity endpoint, Kubernetes API, protected environment,
   host credential, or deployment destination unless an exact reviewed rule
   says otherwise. If the same process mixes trusted runner work and untrusted
   code, the process takes the stricter untrusted restriction.
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
A daemonized child cannot silently become part of the next job. If Mithril can
prove the old and new job cgroup/lifetime boundary, the old child remains bound
to the old restricted epoch and can be fenced. If the unchanged runner reuses
one process and cgroup without an observable boundary, exact job separation is
`UNSUPPORTED`; Mithril does not patch the runner to create one.

#### Semantic CI rules require physical lowering

| Desired rule | Valid preventive lowering | Honest fallback |
| --- | --- | --- |
| deny repository write | Existing provider read-only permission/authorization, or whole endpoint deny | Provider alert after write; never claim BPF saw clone/push |
| deny cloud identity | Deny every exact OIDC/STS/metadata endpoint or use an existing provider authorization API | Cannot remove request token already in memory |
| deny Kubernetes API | Deny all resolved API destinations; use existing Kubernetes authorization/admission for allowed controller jobs | Audit verb after allowed TLS |
| deny runner/plugin control | Exact existing Unix socket/object + current task/peer role | If no such official interface exists, there is no control socket to invent |
| deny new cloud lease | Deny all identity endpoints or use an existing provider authorization API | Provider issuance alert |
| declared artifact upload | Exact store/connector digest intent or destination deny | Filename/time is contextual |
| cleanup own resources | Exact lease, owner UID/tag, resource selector, delete operation at provider boundary | Cleanup role name never grants broad delete |

Each source semantic rule compiles an `EffectLoweringRecord` naming assurance
tier, stage, mechanism, capability IDs, proof axes, prevention result, blast
radius, and fixtures. If there is no valid lowering, protect compilation fails
or the operator explicitly selects alert-only degradation.

#### CI credential delivery determines the earliest control

| Delivery | Earliest honest control |
| --- | --- |
| Environment/context already in process memory | No file-read deny; govern OIDC/provider endpoints, existing provider authorization, egress, and payload-unobservable exposure |
| Unopened projected/mounted file | Exact file open/read denial |
| Inherited/preopened/passed fd | Sender/receive/read and later effects; open denial alone is insufficient |
| Existing provider-issued step lease | Use provider permissions and deny the lease object to other local roles where exact ownership is visible |
| Read-only provider token | Provider denies write over same TLS; verify permissions |
| Write-capable job token on required TLS endpoint | Whole channel deny or existing provider authorization; otherwise post-effect detection |

#### Required CI fixtures

- `CI-NATIVE-001`: identical `curl` from two shell processes. Kernel identity
  remains exact; named step is `UNKNOWN` unless an official stock integration
  provides the join. Neither process receives a publish role from argv.
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
  without provider-scoped issuance or an existing provider authorization API.

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

Mithril does not replace that gap with a made-up two-barrier runtime protocol.
It prebuilds the container/cgroup binding through a configured stock hook when
that hook runs early enough, and applies the fail-closed BPF floor to unresolved
protected tasks. A validating-admission or stock runtime hook may reject the
start only when its documented contract provides that control.

**Example.** A new privileged Pod contains a malicious entrypoint that reads a
hostPath token immediately. A configured Kubernetes validating-admission
integration can reject the Pod before scheduling. If it is bypassed, a
qualified BPF file hook can deny the token read. Mithril does not claim the
first CPU instruction was stopped unless the configured stock start hook's
ordering actually proves that result.

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

#### 29.3 Resolve Kubernetes selection to cgroups, then add exact lifetime identity

Tetragon's cgroup policy filter is useful (`TG-CODE-003`). The checked
userspace conflict path can warn and retain overlapping policy IDs. Cgroup
membership by itself does not prove why a later root exists or whether the
identifier was reused.

Mithril adopts selector-to-cgroup resolution, then binds full container ID,
Pod UID, cgroup live interval, binding nonce, image digest, profile generation,
and exact entry identity. Conflicts are compiler errors or explicit closed
intersections, never logged ambiguity.

#### 29.4 Use a stock runtime creation hook for what it really proves

The checked OCI path has a `createRuntime` opportunity that can fail before
user code, while another create path is a no-op; policy-map failures can log
and continue (`TG-CODE-004` and `TG-CODE-021`). This teaches where an existing
integration can report metadata or reject a create request. It does not prove
a held task, later exec purpose, or first-user-instruction barrier.

**Example.** The OCI hook reports Pod metadata, but kernel/runtime readback
finds a different full container ID or cgroup lifetime. Mithril rejects the
metadata and leaves the placement under its unresolved BPF floor. Whether the
container start itself fails depends only on the stock hook's documented
failure semantics; Mithril does not claim it held a task.

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
kernel task creation + runtime/Kubernetes inventory + optional stock hooks
  -> classify labeled native child, known initial root, external root, or unknown
  -> install or retain restrictive task/process identity before covered effects
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
contract between those mechanisms: honest missing-purpose handling, task-first identity,
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

1. The application forks task B and runs `/app/healthcheck`.
2. B has a labeled native creator, so it remains an application descendant.
3. Kubelet asks stock CRI to run the same path for readiness. Runtime-created
   task A has no labeled application creator, so it is an external root.
4. Stock CRI does not expose the readiness reason. A receives the restricted
   external-root role, not a made-up probe role.
5. An attacker then uses ordinary unapproved `kubectl exec` with the same argv.
   Admission rejects it when the approved-exec feature is enabled. In baseline
   mode, task C is a restricted external root. Kubernetes audit may identify
   the API actor, but command equality, cgroup equality, timing, and TTY state
   never grant C more permission.

#### Release-gating implementation cards

Three small cards keep the first hard cases implementable:

| Card | Starting state | Stimulus | Required result and oracle |
| --- | --- | --- | --- |
| `CARD-FILE-SA-TOKEN-OPEN-001` | Bound converter; exact projected-token object in negative set | Existing Python opens token; variants use symlink, proc-fd alias, rotated projection, inherited fd, mmap | Open/read result uses exact file object and stage. A denied open returns errno and produces no positive-byte oracle. Already-open/memory branches report their real weaker boundary. |
| `CARD-ENTRY-PROBE-IMPERSONATION-001` | One application process and stock kubelet/runtime in the same container | Native child, readiness probe, `kubectl exec`, and `crictl exec` execute identical healthcheck bytes concurrently | The native child keeps application lineage. Every later independent task receives the same restricted external role unless a qualified existing interface supplies stronger evidence. No task receives a role from argv, timing, TTY, or a Mithril-signed observation. Fixture: `ENTRY-PROBE-IMPERSONATION-003`. |
| `CARD-XNODE-PRIVILEGED-POD-001` | Worker authority domain has Kubernetes credential/use evidence; node floor active on another node | Credential creates privileged Pod and runtime root remotely | Typed Kubernetes audit/object/binding edges connect nodes. Remote pre-admission or node floor rejects the root where supported; otherwise report exact observation and response, never local syscall prevention. Fixture: `XNODE-PRIVILEGED-POD-001`. |

### 31. Acceptance: What Must Work Before Mithril Makes A Claim

Passing unit tests for map lookups is not enough. Each advertised kernel,
runtime, and Kubernetes combination must pass real hostile workloads and
legitimate controls. The oracle is the physical syscall, packet, provider
object, or verified response result, not an alert string.

#### 31.1 Kubernetes and runtime entry matrix

| Fixture | Real setup | Required result |
| --- | --- | --- |
| `ENTRY-START-001` | Delay or drop runtime discovery/hook metadata for an initial root | Protected-but-unresolved effects deny; if the task ran before BPF/binding coverage, the exact start gap is recorded. No first-instruction claim. |
| `ENTRY-POSTSTART-001` | Race `PostStart` and entrypoint in both orders | Initial root and external root remain distinct; neither is fabricated as the other's child. |
| `ENTRY-POSTSTART-002` | Kubelet restart repeats `PostStart` | Each observed external task gets a fresh task/lifetime identity and the same restricted budget; no stale identity is reused. |
| `ENTRY-PRESTOP-001` | Delete Pod during an active response | Containment versus cleanup policy wins explicitly; termination grants no bypass. |
| `ENTRY-PROBE-001` | Concurrent startup/readiness/liveness exec probes | Stock path gives one restricted external class. Exact different purpose is claimed only for a qualified existing interface that actually carries it. |
| `ENTRY-PROBE-002` | Application child runs identical probe binary/argv/cadence | Native lineage remains; no probe role. |
| `ENTRY-NETPROBE-001` | HTTP, TCP, and gRPC probes | No fake in-container process root; host flow and application receive are scoped separately. |
| `ENTRY-SLEEP-001` | Lifecycle `sleep` action | Kubelet lifecycle evidence only; no invented task. |
| `ENTRY-EXEC-001` | `kubectl exec`, TTY/non-TTY, and `kubectl cp` | Restricted external roots plus separate Kubernetes audit facts. The configured approved path must also pass `ADMIN-EXEC-APPROVAL-001` before assigning a stronger task role. |
| `ENTRY-EXEC-002` | `crictl exec` runs same command as probe | Restricted external root, never a kubelet-probe role. |
| `ENTRY-EPHEMERAL-001` | Add ephemeral container sharing target PID namespace | Independent container execution set and profile; shared PID namespace does not merge trees. |
| `ENTRY-CONTAINERS-001` | Init, native sidecar, and app containers share Pod network/volume | Independent roots plus exact shared-resource edges. |
| `ENTRY-MIGRATE-001` | Move unlabeled task into protected cgroup or use `nsenter` | First protected effect denies because no application authority is inherited. |
| `ENTRY-REUSE-001` | Reuse PID, namespace number, cgroup path/ID, Pod/container name | Full IDs and live intervals prevent old policy/response attachment. |
| `ENTRY-RESTART-001` | Restart kubelet, runtime, and node agent during discovery and binding | Live tasks are re-enumerated; no stale role is reused; incomplete history and coverage transition are explicit. |
| `ENTRY-LOSS-001` | Drop runtime/audit metadata and BPF entry evidence independently | Protected unknown/external task stays restricted; loss cannot relax enforcement. |

Every case records the exact runtime/CRI version; kernel/BTF/LSM order and
capabilities; Pod UID and resource version; full container/image/cgroup live
identity; entry classification and proof quality; task/process/exec cookies;
syscall or runtime outcome; and coverage/loss state.

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
filters are monotonic once installed. When a supported start path advertises
Mithril-installed Seccomp, the real tests prove that the floor existed before
that target's user code and could not be silently omitted. Mithril makes no
Seccomp claim for a process where it did not install that floor. Unapproved
ptrace or Seccomp user-notification supervisors are separate controls.

#### 31.3 Pinned-source tests that cannot be waived

| Source observation | Mandatory hostile fixture | Release consequence |
| --- | --- | --- |
| `KA-CODE-025` DNS parser bounds | `NET-DNS-EXFIL-001`: short/malformed/compressed/multi-question/long/split-iovec/TCP/non-53/DoT/DoH/IP-literal | Unknown parse still hits destination/IP floor; failure blocks a complete DNS/network claim. |
| `KA-CODE-026`, `KA-CODE-027`, `TG-CODE-024` bounded or missing process/policy state | `SOURCE-KA-CAPACITY-005`, `SOURCE-TG-EXEC-MAP-007`, `DECISION-SET-GOLDEN-001`, and N/N+1 capacity cases | Missing state never grants role and a partial generation never activates. |
| `KA-CODE-028` reader loss behavior | `SOURCE-KA-READER-LOSS-003`, sole-reader death, nil/closed reader, lost samples, WAL gap | One daemon-ready bit cannot support a healthy negative interval. |
| `TG-CODE-023` unauthenticated local runtime metadata shape | `SOURCE-TG-RUNTIME-JOIN-006`, `ENTRY-STOCK-HOOK-FAILURE-002`, `ENTRY-PROBE-IMPERSONATION-003` | Authenticate the source and compare its documented fields with the live kernel/runtime binding. Missing purpose remains `UNKNOWN`; Mithril does not invent a held-task transaction. |

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
| Qualified stock start hook is absent | Discover after start and record the gap | Deny unresolved protected effects; configured Kubernetes admission may separately reject unsafe specifications | No first-instruction or start-rejection claim |
| Protected cgroup contains unlabeled task | Record orphan and identity defect | Deny its first protected effect | No exact lineage until reconciled |
| Parent state missing at fork | Child lineage becomes incomplete | Install restrictive unknown child or deny creation/effect | Never silently benign |
| External-root purpose has several candidates | Keep candidates and report ambiguity | Apply one permission intersection to all indistinguishable roots or deny | No exact probe/lifecycle/admin reason |
| Ring reservation fails | Increment pinned loss counter and close interval | Same; already fixed physical result remains | Enforcement may be healthy; evidence is incomplete |
| Sole Rust process or control link dies | No disk WAL writer exists; bounded ring records remain until full | Pinned programs/maps keep existing decisions; userspace-dependent new admission rejects | No central response/new profile; later negative history is incomplete |
| bpffs pathname disappears but live references remain | Mark recovery/pin health bad | Existing objects may continue; reject restart-sensitive new admission | Only exact live-link readback, not healthy recoverability |
| Enforcement link detaches | Mark that family unavailable | Family becomes `PROTECTION_UNKNOWN`; separately healthy actuator may freeze/fence | Never claim the absent hook denied anything |
| Required map entry is missing while program remains | Record map miss and coverage defect | Use that program's qualified fail-closed miss result | Only if exact path was tested |
| Required map is replaced/lost | Mark link/map integrity failed | Reject strict new admission; independently freeze/fence if authorized | Affected prevention family unknown |
| New policy fails compile/readback/probe | Keep previous generation | Reject update; keep previous generation | No partial activation |
| WAL fills | Apply configured retention/backpressure before overwrite and expose gap | Local enforcement continues; evidence-dependent conclusions stop | No safe/contained claim across loss |
| Kubernetes/provider audit is absent | Local evidence continues | Local controls continue | Provider verb and distributed edge are unknown/contextual |
| Runtime/kubelet restarts | Reconcile live tasks and external/initial classifications; open a gap where history is missing | Preserve pinned bindings; unknown new roots stay restricted | No stale purpose or lifecycle claim |
| Node reboots | Close old boot subjects and start new source epoch | Every workload is admitted again | Old response keys cannot target new tasks |
| Process/domain map corrupt, mismatched, or full | Mark exact task/domain interval incomplete | Deny affected effects and strict joins; authorized independent freeze may hold | No role/taint/domain claim from missing state |
| Authority-domain join crashes halfway | Keep subjects separate and report channel unproved | Deny the new dynamic channel, preserve every committed restriction, and fence separately if authorized | No laundering-prevention claim until recovered |
| VMA snapshot is partial or task sharing changes during snapshot | Keep positive mappings, mark absence unproved | Never relax from partial snapshot; retain restrictions or reject exact action | `VMA_SNAPSHOT_INCOMPLETE` |

A missing enforcement mechanism cannot apply its own “safe state.” If the file
LSM link detaches, that link cannot freeze a cgroup or deny a file. A separate,
still-healthy configured stock runtime hook can reject new roots. A separate packet program can
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
| `AdministrativeApprovalOwner` | Control | Browser/device challenge, authenticated human decision, one-use Kubernetes exec credential, and signed node authorization | Assign a Linux task role or treat approval as a runtime-task join |
| `AuthorizationProofOwner` | `mithril-node` | Validate real Mithril/operator/provider authorizations, replay protection, and target scope | Invent kubelet/runner purpose, infer intent from argv/timing, or let an adapter grant a role |
| `WorkloadBindingOwner` | `mithril-node` | Container execution sets, cgroup lifetime/storage, initial/native/external classification, node-floor binding | Create namespaces, perform the OCI runtime's normal job, or claim a hook field that stock runtime did not send |
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
| `StreamEvidenceOwner` | Proposed Kubernetes audit/API adapter | Attach/port-forward request, actor, target, ports/channels, result, and proof quality | Insert a stream proxy, invent a task, or claim rejection from audit-only evidence |
| `QualificationOwner` | Offline release tooling | Registry validation, oracle comparison, ledger, signed envelope | Rewrite detector results or turn degraded into pass |

Adapters authenticate their vendor transport and normalize only fields that
the vendor interface actually supplies. `AuthorizationProofOwner` validates a
real signed authorization; it does not authorize ordinary external roots.
`WorkloadBindingOwner` classifies initial, native, external, and unresolved
tasks. Only `NativeSecurityStateOwner` installs matching task, process, and
domain state. `PolicyActivationOwner` changes only the generation reference
those objects hold.

The same gatherer may expose a cgroup-scoped, read-only observation stream to
Erebor Runtime. Runtime cannot load overlapping BPF programs/maps, assign a
Mithril role, mutate a response, or become another durable owner.

### 35. Delivery Phases

Architecture prose does not authorize implementation. The master plan and the
exact phase file must allocate the work, its tests, and its exit result.

| Phase | Product slice and required exit |
| --- | --- |
| 0 | Freeze license/provenance, Rust/BPF ABI, source and compiled schemas, capability/performance records, source-evidence registry, fixture registry, result words, and golden bytes. Record the allowed installation boundary and qualify each selected stock hook's real fields, ordering, and failure behavior. |
| 1 | Ship one Rust node process, one loader/pin lease, capability probes, base cgroup/runtime inventory, authenticated local transport, and boot readiness. A second loader cannot own the pin root. |
| 2 | Implement task/process/exec cookies, task-first fork/thread/vfork/non-leader-exec transitions, process/domain state, bootstrap, initial/native/external/unresolved roots, and restart reconciliation. |
| 3 | Observe/classify every exec/file/mm/socket/device/privilege/shared-channel operation; run candidate policy simulation and complete bypass/hook inventory. No prevention claim from an unpaired hook. |
| 4 | Enforce signed immutable exec/file/device/privilege policy, entry miss behavior, exact decision precedence, domain joins/publication, and local deny/reject semantics. |
| 5 | Enforce role-aware socket lifecycle, local-inet joins, final destination, DNS/IP floor, packet and established-flow fence, shared-socket blast radius. |
| 6 | Complete source sequences, WAL, coverage intervals, immutable generation recovery, link/map/pin health, restart/reuse truth, and sole-gatherer failure. |
| 7 | Implement `HF-PROC-001`, `HF-DW-001`, authority behavior, deterministic package replay, notification routing, and provider-neutral leases. |
| 8 | Join Kubernetes audit/object/runtime evidence, build typed multi-node graph, and prove fan-out/reuse/contradiction behavior. |
| 9 | Implement response roots, cgroup/socket actions, shared-domain widening, replacement-controller watch, readback, and verified postconditions. |
| 10 | Add separately qualified mesh, AWS, connector, artifact, GitHub evidence/lease/response packages. Each adapter proves identity limits and one typed actuator. |
| 11 | Qualify exact root classification and every configured stock OCI/NRI/runtime/Kubernetes integration for each advertised platform; package, upgrade, scale, performance, and full conformance; sign the limited release claim. |
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
| Runtime roots and cgroup binding | 0 / 1-4; platform claim 11 | `mithril-node::identity::WorkloadBindingOwner`; configured stock adapter only forwards documented facts | Identical application-child/probe/admin/direct-runtime commands: native child keeps lineage; indistinguishable external roots get the same restricted role. The approved administrative exception is stronger only through the configured short-lived one-use next-match slot, with the rare race explicitly accepted. Unresolved protected effects deny. No general command-based purpose. |
| File, descriptor, mapping, IPC, process-control and persistent object classification | 0 / observe 3, deny 4 | `mithril-node::effect`; domain transition requested from `NativeSecurityStateOwner` | Symlink/bind/proc-fd/rotation/mmap/fd-pass/io_uring/persistent volume either deny, pre-use join, or return exact unsupported. |
| Socket identity, local-inet domain join, destination, packet fence | 0 / observe 3, deny 5 | `mithril-node::effect::network` | Broad-created socket passed to narrow actor cannot restore egress; loopback/Pod-IP channels join before delivery; established-flow oracle states blast radius. |
| Source sequence, coverage, WAL, restart reconstruction | 0 / 6 | `mithril-node::evidence::{CoverageHealthOwner,LocalEvidenceOwner}`; control `mithril-control::intake` | Ring pressure preserves deny but gaps absence claim; restart changes epoch and reconciles live tasks/sockets/claims before admission. |
| Local and distributed detection graph | 0 / 7-8, provider 10 | `mithril-control::graph`, `mithril-control::detections` | Node-A process to node-B root uses audit/object/binding edges; shared credential plus time remains contextual. |
| Notification delivery | 0 / 7 | `mithril-control::notifications::NotificationRouter` | Secret fields reject; retry/dedupe do not duplicate finding or response; sink outage never relaxes enforcement. |
| Local/Kubernetes/provider response | 0 / 9-10 | `mithril-control::response::ResponseCoordinator`; authenticated node actuator; one provider actuator per capability | Stale PID/object UID denies; shared-domain action widens or returns partial; readback plus healthy watch required for verified. |
| Provider lease/operation/artifact joins | 0 / 7 neutral, 10 exact | `mithril-control::authority`, provider adapter, `AuthorityLeaseOwner` | CLI name grants nothing; exact issuance/session/audit join or weaker branch; secret never enters evidence. |
| Checkpoint and stream evidence/authorization | 0 logical contract / unallocated physical | Proposed `CheckpointAuthorityOwner`, `StreamEvidenceOwner` | No rejection claim until an existing supported API/hook and dormant fixtures are allocated and qualified. |

An adapter milestone is not complete when it receives an event. It must prove
source authentication, exact fields and target binding actually exposed,
failure behavior, and the physical result of every advertised disposition.

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
passed its configured start-hook ordering suite. The product may advertise
file denial for already-bound tasks. It must report the measured start gap and
must not claim protection before the first user instruction. The UI cannot
combine those facts into “fully protected from first exec.”

#### 35.1 Work that is still unallocated

| Surface | Status now | Honest product result | Required amendment |
| --- | --- | --- | --- |
| Checkpoint create/restore | `UNALLOCATED_OPTIONAL` | `UNSUPPORTED`; dormant fixtures do not block unrelated core release | Add checkpoint owner and stock authorization/runtime-hook matrix, store actuator, `CHECKPOINT-CREATE-001`, `ENTRY-RESTORE-001`; no patched runtime. |
| Attach/port-forward stream | `UNALLOCATED_OPTIONAL` | Audit/API evidence only at the configured tier; no proxy/metering claim | Add Kubernetes audit/authorization API owner, proof-quality rules, and `ENTRY-STREAM-001`; do not insert a stream gate. |
| Named GitHub/GitLab/Jenkins/Tekton adapters and compilable CI policy | `UNALLOCATED_OPTIONAL` | CI contracts remain dormant; no named tier claim | Add provider API roots, official supported plugin fields where available, closed schema, adapter suite, and exact `CI-*` subset; no runner patch or held-task transport. |
| Unmatched-workload hard floor and privileged exceptions | `UNALLOCATED_REQUIRED_FOR_FULL_HF_CLAIM` | Full prevention of attacker-created privileged Pod and full HF claim are blocked | Amend Phase 0, Kubernetes validating-admission integration, chosen stock runtime hook if used, BPF node-floor schema, and `XNODE-PRIVILEGED-POD-001`/`NODE-FLOOR-EXCEPTION-002`; no component rebuild. |

Runtime-root handling cannot be postponed to a late integration task. Phase 0
records stock evidence and limits; Phase 1 transports verified metadata;
Phase 2 models roots; Phase 4 denies missing protected identity; Phase 11
qualifies each advertised version and configuration.

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
| Container identity | Several independent roots per container | One root only after proving every later runtime/kubelet task is its native descendant on every platform. |
| Initial start | Prepare binding through a configured stock start hook when its ordering is qualified; otherwise protected effects deny until binding and the start gap is explicit | Never require a patched runtime or claim first-instruction control from a later callback. |
| Later exec | Restricted external root unless an existing qualified interface proves more | Application authority inheritance and command-based purpose are rejected. |
| ExecSync reason | Unknown on stock CRI; use one permission intersection for indistinguishable external roots or deny them | Timing/argv classification and Mithril-created kubelet intent are rejected. |
| Administrative exec | Default deny or the complete plugin + admission + node-slot path. The next complete matching runtime-created external root may atomically consume the short-lived slot only after cluster policy and the administrator accept the rare race. | Always allow, reusable slots, application descendants consuming slots, hidden race acceptance, and a broadly reusable admin role are rejected. |
| `PreStop` during containment | Containment wins unless exact safe cleanup role is approved | Universal bypass is rejected; disable all cleanup with availability cost. |
| Missing protected identity | Fail closed at first protected effect | Fail open is observation-only. |
| Executable identity | Immutable object/image identity | Path-only is a reduced integrity tier. |
| Same TLS endpoint | Existing provider permission/authorization or honest audit; no MITM | Whole-channel deny blocks both allowed and forbidden verbs. |
| Several logical jobs in one process | Exact native process only; logical job remains unknown when the existing platform exposes no boundary | Apply process-wide policy and disclose the blast radius; Mithril does not require application instrumentation. |
| Learning | Observations create review-only candidates | Auto-authorizing observed behavior is rejected because compromise trains it. |
| Upstream code | Reuse ideas/code only after Phase 0 license/provenance review; keep Mithril Rust chassis | A fork must replace, not duplicate, the single owner. |
| Intent | Signed envelopes only for real Mithril/operator/provider authorization | Stock kubelet/runner events remain facts with their actual proof quality; signing a normalized observation does not create missing purpose. |
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
10. Every real authorization issuer proves authentication, target binding,
    expiry, replay, mismatch, and restart behavior. Stock platform observations
    keep their actual proof quality; CLI names and local signatures never
    substitute for missing purpose.
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
`ProfileGenerationRefV1` is defined once in Appendix A.12.1. It binds the
portable profile ID, owner generation, and compiled digest to node boot, label
epoch, and one non-reused local handle. Two profiles whose human versions are
both `42` never share a node-local handle.

### A.2 Contract index

| Contract family | Defined behavior and fields |
| --- | --- |
| `KernelCapabilityRecordV1` | Chapter 5: active LSM order, exact hooks/helpers/map types, configured stock runtime/admission integrations, BTF, program/map/link digests, controlled probe results |
| `ContainerExecutionSet`, `EntrySecurityStateV1`, `TaskLabelV1`, `TaskInstanceV1`, `ProcessSecurityStateV1`, `ProcessInstanceV1`, `AuthorityDomainStateV1`, `ImageProvenance`, `ProcessExecutionInstance` | Chapter 6 explains the model; Appendix A.9 fixes identity, reference, coordinate, fork, exec, and lifetime fields |
| Root classification, runtime/container facts, binding/topology snapshot | Chapter 7 defines the stock-system algorithm; Appendix A.9 fixes task/container identity. Historical held-task records in A.9.7 are rejected, not implementation requirements. |
| `IntentProofEnvelopeV1`, signed body union, trust generation, replay records | Chapter 8 limits these records to real Mithril/operator/provider authorization; Appendix A.10 defines canonical CBOR, tags, bounds, trust, and replay. It never requires kubelet or a CI runner to sign. |
| `InvariantQualificationV1` | Chapter 10: one invariant, capability/source proof, stimulus, decision point, physical result, coverage, artifacts, status |
| `PolicyDocumentV1`, signed compiled profile, rollback authorization, `EffectDecisionKeyV1`, generation descriptors | Chapters 11-13 explain behavior; Appendices A.11-A.12 fix parser/signature/activation and Rust/BPF map semantics |
| Mount/file/VMA/socket/device/publication/process-control records | Chapters 15-21 explain behavior; Appendices A.13-A.14 fix object, hook-family, lifetime, domain, join, and publication contracts |
| `ObservationEnvelopeV1`, `CoverageIntervalV1`, `ProofQualityV1`, `FindingV1`, graph nodes/edges | Chapters 22-23 explain proof; Appendix A.15 fixes fields, intervals, direct-edge requirements, and determinism |
| Response plan/target/application/postcondition records | Chapter 24 explains response; Appendix A.15.4-A.15.6 fixes authorization, re-resolution, state, readback, and watch |
| CI run/job/process/artifact/lease/evidence records | Chapter 26 explains stock facts and limits; Appendix A.16 separates job/process evidence from optional official step joins and rejected patched-runner records |

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
| `EntryKindV1` | Closed root class: initial, native, external-unknown, restore-unknown, and qualified registered purpose. Probe/lifecycle/admin is legal only when an existing interface proves it. |
| `EntryClassificationV1` | Exact or conservative classification, candidate set, proof, and ambiguity result |
| `EntryRoleAssignmentV1` | Proven root classification -> initial process role and retained profile generation |
| `EntryAdmissionMatchV1` | Bound policy predicate for an initial, external, or unresolved root; never an argv ticket match |
| `PreparedExternalRootStateV1` | **Rejected no-patch design.** It described a held runtime root that stock interfaces do not provide. |
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
| `RuntimeOperationV1` | Closed operation name used only for facts or controls a qualified stock runtime integration actually exposes |
| `NativeRoleTransitionRuleV1` | Source role + native operation + target -> one target role/restriction |
| `NativeTransitionMatchV1` | Exact current state and operation selector |
| `TransitionDescriptorV1` | Compiled transition result, reference effects, and evidence rule |
| `ProcessTransitionKeyV1` / `ProcessTransitionValueV1` | Kernel exact-key and result for native transition |
| `TransitionIntentV1` | Optional signed Mithril authorization for a transition Mithril actually controls; never created from an ordinary kubelet event |
| `NativeTransitionBodyV1` | Closed signed-intent body for a native transition |
| `IntentKindV1` | Closed body union tag; CI is value `7` in this architecture |
| `IntentBodyV1` / `IntentPayloadV1` | Canonical target-bound signed body union and common claims |
| `RuntimeEntryBodyV1` | Optional body for a qualified existing integration that supplies a real authorization and unique request/task identity; unused for ordinary stock roots |
| `KubeletExecutionRequestV1` | **Rejected no-patch design.** Stock kubelet/CRI supplies no such signed probe/lifecycle request. |
| `ExactRequestIdentityV1` | Stable request/attempt/issuer identity used for replay and graph joins |
| `KernelClaimTombstoneV1` | Pinned consumed/rejected fact only for a real Mithril-owned one-use authorization; not required for stock external-root classification |
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
| `DecisionSetDescriptorV1` | **Rejected as Version 1 authority** with the final-decision cache; authoritative base/restriction/response rows use their active generation/set descriptors in Appendix A.12 |
| `RestrictionSetDescriptorV1` | Bounds/digest for a negative restriction set |
| `ResponseSetDescriptorV1` | Bounds/digest for effective response restrictions |
| `SetKindV1` | Closed restriction/response/retained-generation family; base authority belongs to the immutable profile generation, not a mutable decision-set cache |
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
| `MonotonicSetTransitionKeyV1` / `MonotonicSetTransitionValueV1` | **Superseded collapsed names**; Appendix A.12.5 separates process transitions from authority-domain sensitive transitions because one BPF hook cannot atomically mutate both map values |
| `DomainSensitiveTransitionKeyV1` / `DomainSensitiveTransitionValueV1` | Atomic old-domain-sensitive state -> stricter state transition |

#### A.8.4 Mounts, files, memory, publication, and shared authority

| Type | One job |
| --- | --- |
| `MountNamespaceStateV1` | Mount namespace identity, topology generation, CLEAN/DIRTY state, snapshot digest, live interval |
| `MountSecurityViewV1` | Actor-visible mount/root/propagation/read-only/security view used for object resolution |
| `MountSourceClassRecordV1` | Exact declared/image/projected/host/device/remote mount source classification |
| `VolumeMountBarrierV1` | **Rejected design.** Mithril never owns, holds, or releases a mount or root filesystem. |
| `VolumeAccessReadinessV1` | Active per-node record proving that the current persistent-volume authority was installed and read back before BPF allows a covered file effect. This is an access gate, not a mount or task hold. |
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
| `SeccompFloorProofV1` | Exact filter proof when Mithril installed it through a qualified new-process start path, or measured proof level for a filter that already existed; never a retroactive arbitrary-PID claim |

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
| `MaterializedStepInvocationV1` | Observed actual script/interpreter/image/argv/cwd/public-environment/input digests and mutability proof; named-step join may be absent |
| `CiTrustedRunnerStepLaunchAttestationV1` | **Rejected no-patch design.** It required trusted runner-control code to hold and attest a child. |
| `CiStepIntentBodyV1` | Optional body only when an existing official CI interface supplies a real signed/authorized immutable step assignment |
| `CiStepAdmissionJoinV1` | Optional join of provider job/step evidence to a Linux task when the existing interface supplies a unique join; otherwise job and process remain separate facts |
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

### A.9 Exact Actor, Entry, And Runtime-Admission Contract

This section makes Chapters 6-9 implementable. It deliberately starts with a
real action rather than a struct.

**Problem.** The conversion worker's Python process may fork a child, kubelet
may start a readiness probe, an administrator may use `kubectl exec`, and the
runtime may restore a checkpoint. All four processes can live in the same Pod
and cgroup. They are not the same actor and they must not receive the same
authority merely because Kubernetes placed them together.

**Required result.** Before any protected effect, Mithril can answer:

```text
which exact Linux task is acting?
which process and entry does it belong to?
why does that entry exist?
which executable image and role are current now?
which immutable policy generation does it retain?
which shared restriction and response state applies?
is it still in the cgroup binding to which it was admitted?
```

The answer comes from one immutable task label followed by mutable state owned
by the process, entry, binding, and authority domain. A task label is never a
cached final decision.

#### A.9.1 Exact identity records

```text
ContainerExecutionSet {
  execution_set_id: Id128
  tenant_id: Id128
  cluster_uid: Id128
  node_boot_id: Id128
  pod_uid: bounded bytes
  pod_resource_version_digest: DigestV1
  sandbox_id: bounded bytes
  full_container_id: bounded bytes
  container_kind: INIT | SIDECAR | APPLICATION | EPHEMERAL
  image_digest: DigestV1
  cgroup_binding_id: Id128
  cgroup_live_interval_id: Id128
  profile_id: Id128
  active_profile_generation_ref_id: nonzero u64
  lifecycle_generation: nonzero u64
}

TaskLabelV1 {                       // immutable after successful installation
  node_boot_id: Id128
  label_epoch: u64
  task_cookie: nonzero u64
  process_lineage_id: Id128
  process_instance_id: Id128
  process_state_id: Id128
  entry_instance_id: Id128
  execution_set_id: Id128
  birth_profile_generation_ref_id: nonzero u64
  birth_execution_id: Id128
  birth_authority_domain_id: Id128
  lineage_depth: u16
  ancestor_process_lineage_ids[MAX_DEPTH]: Id128
  task_placement_expectation: TaskPlacementExpectationV1
}

ProcessSecurityStateV1 {            // sole current process authority
  process_state_id: Id128
  node_boot_id: Id128
  label_epoch: u64
  process_lock: bpf_spin_lock
  process_lineage_id: Id128
  process_instance_id: Id128
  entry_instance_id: Id128
  entry_root_process_state_id: Id128
  active_execution_id: Id128
  active_role_id: u32
  active_profile_generation_ref_id: nonzero u64
  authority_domain_id: Id128
  process_state_vector_id: nonzero u32
  effective_response_set_ref_id: nonzero u64
  exec_guard_state: NONE | EXEC_PREPARING | EXEC_COMMIT_PENDING |
                    EXEC_OUTCOME_UNKNOWN
  pending_exec_id?: Id128
  pending_target_execution_id?: Id128
  pending_target_role_id?: u32
  pending_exec_response_set_ref_id?: nonzero u64
  transition_version: u64
  live_thread_refs: u64
  state: ALLOCATING | ACTIVE | EXITING | RECLAIMABLE |
         FAIL_CLOSED_OVERFLOW | CORRUPT
}

ProcessStateVectorV1 {
  process_state_vector_id: nonzero u32
  node_boot_id: Id128
  label_epoch: u64
  state_bits: u64
  profile_generation_ref_id: nonzero u64
  state: PREPARING | ACTIVE | RETIRING
}

EntrySecurityStateV1 {
  entry_instance_id: Id128
  node_boot_id: Id128
  label_epoch: u64
  entry_lock: bpf_spin_lock
  execution_set_id: Id128
  entry_kind: EntryKindV1
  claim_slot_id: Id128
  root_task_cookie: nonzero u64
  root_process_state_id: Id128
  committed_execution_id: Id128
  live_task_refs: u64
  admission_state: PREPARING | CLAIM_BOUND_PROVISIONAL | COMMITTED |
                   TERMINAL_FAILED
  lifetime_state: OPEN | DRAINING | COMPLETE
  transition_version: u64
}

ImageProvenance {
  image_provenance_id:Id128
  executable_object:ExactObjectGenerationV1
  script_or_binfmt_chain[]:ExactObjectGenerationV1
  elf_loader_objects[]:ExactObjectGenerationV1
  source_exec_event_id:DigestV1
}

ProcessExecutionInstance {
  process_execution_instance_id, process_lineage_id,
    image_provenance_id:Id128
  started_by:PROCESS_BIRTH | EXEC_COMMIT
  start_boottime_ns:u64
  end_boottime_ns?:u64
}
```

Fork creates a new per-process execution instance that points to the same
immutable image provenance. Exec creates another execution instance and new
image provenance in the same process lineage. A thread shares both. This is why
one child exit must not close the parent's image/execution record.

The process lock protects every mutable authority field in the process record.
BPF resolves the prospective next values before taking the lock, takes no map
lookup or helper call while holding it, verifies the old tuple and transition
version, writes the entire next tuple, increments the version, and unlocks.
Readers copy one complete tuple under the lock and revalidate it before use.

`TaskLabelV1.birth_*` fields explain origin. They do not select current policy,
role, execution, or domain. Every decision follows:

```text
TaskLabelV1
  -> ProcessSecurityStateV1
  -> current AuthorityDomainStateV1
  -> EntrySecurityStateV1 and ExecutionSetBindingStateV1
  -> retained policy, response, object, and channel state
```

Going directly from the task label to the birth domain, role, or generation is
an implementation error.

#### A.9.2 Task and process coordinates

Mithril IDs remain stable while Linux coordinates can change or be reused.

```text
ProcessInstanceV1 {
  process_instance_id, process_lineage_id, process_state_id: Id128
  state: ALLOCATING | COORDINATES_FINALIZED | RUNNABLE |
         EXITED | FAILED | FAIL_CLOSED_UNKNOWN
  host_tgid?: u64
  host_leader_tid?: u64
  pid_namespace_inode_and_generation?: Id128
  namespace_pid_chain[]: bounded u64
  start_boottime_ns?: u64
  pidfd_identity?: bounded bytes
  coordinate_finalization_hook_id?: u32
  owned_reference_bits: u64
}

TaskInstanceV1 {
  task_cookie: nonzero u64
  process_instance_id, process_state_id: Id128
  state: ALLOCATING | COORDINATES_FINALIZED | RUNNABLE |
         EXITED | FAILED | FAIL_CLOSED_UNKNOWN
  host_tid?: u64
  pid_namespace_inode_and_generation?: Id128
  namespace_tid_chain[]: bounded u64
  task_start_boottime_ns?: u64
  finalized_boottime_ns?: u64
  exited_boottime_ns?: u64
  thread_pidfd_identity?: bounded bytes
  coordinate_finalization_hook_id?: u32
  owned_reference_bits: u64
  coordinate_history_head_id?: Id128
}

TaskCoordinateHistoryV1 {
  history_id: Id128
  task_cookie: nonzero u64
  transition: BIRTH_FINALIZED | NONLEADER_EXEC_DETHREAD |
              LEADER_EXITED | PID_NAMESPACE_CHANGE_OBSERVED | EXIT
  old_and_new_tid_tgid_coordinates
  process_instance_id: Id128
  source_hook_id: u32
  boottime_ns: u64
}
```

`task_alloc` may allocate opaque IDs and fixed state, but PID, TGID, start time,
and pidfd do not yet exist there. A qualified pre-wake hook fills the already
allocated coordinate slots after PID assignment. It performs no allocation and
grants no authority. Rust may add a pidfd only after the task becomes visible.

If coordinate finalization fails, the installed label still points to
`FAIL_CLOSED_UNKNOWN`. The task cannot read, execute, connect, use a device, or
change privilege merely because its PID details are incomplete.

#### A.9.3 Who created whom

Linux's reported parent can change. Authority inheritance uses the task that
actually requested creation.

```text
CreatedByEdgeV1 {
  child_task_cookie, creator_task_cookie: u64
  child_process_lineage_id, creator_process_lineage_id: Id128
  clone_attempt_id: Id128
  clone_flags_digest: DigestV1
  task_alloc_hook_id: u32
}

KernelRealParentIntervalV1 {
  child_task_cookie: u64
  real_parent_task_cookie_or_coordinates
  interval_start_boottime_ns: u64
  interval_end_boottime_ns?: u64
  change_reason: BIRTH | CLONE_PARENT | PARENT_EXIT | SUBREAPER |
                 NAMESPACE_INIT_REPARENT | PTRACE_REPARENT | UNKNOWN
  proof_quality: ProofQualityV1
}
```

Double fork, daemonization, subreapers, namespace init, ptrace reparenting, and
PID reuse may change `KernelRealParentIntervalV1`. None changes the immutable
`CreatedByEdgeV1` or the child's inherited restriction.

#### A.9.4 References and entry lifetime

An entry is complete when its last task is gone and a complete task iterator
agrees. A denied effect is an observation; it does not end the entry.

```text
Entry admission:
  PENDING -> CLAIMING -> COMMITTED
  PENDING | CLAIMING -> REJECTED | EXPIRED | CANCELLED | CLAIM_FAILED

Entry lifetime:
  INACTIVE -> ACTIVE -> DRAINING -> COMPLETE

COMPLETE requires:
  admission == COMMITTED
  live_task_refs == 0
  complete task iterator finds no live TaskLabelV1 for the entry
```

One task reference is counted for every Linux task, including threads.
Authority-domain `live_process_refs` counts processes, not threads.

```text
TaskLifetimeOwnershipV1 {
  task_cookie: u64
  birth_transaction_id: Id128
  birth_transition_version: u64
  entry_instance_id, process_state_id, authority_domain_id: Id128
  profile_generation_ref_id: u64
  owns_entry_task_ref: bool
  owns_process_thread_ref: bool
  owns_profile_generation_task_ref: bool
  state: PREPARING | OWNED | RELEASED | RECONCILIATION_REQUIRED
}

ProcessLifetimeOwnershipV1 {
  process_state_id, authority_domain_id: Id128
  authority_domain_ref_owned: bool
  acquisition_transition_version: u64
  release_transition_version?: u64
  state: OWNED | DOMAIN_JOIN_PREPARING | RELEASED |
         RECONCILIATION_REQUIRED
}

TaskReferenceTombstoneV1 {
  task_cookie: u64
  birth_transaction_id: Id128
  birth_transition_version: u64
  entry_instance_id, process_state_id, authority_domain_id_at_birth: Id128
  profile_generation_ref_id: u64
  acquired_bits, released_bits: u64
  task_free_observed, wal_acknowledged: bool
  transition_version: u64
  state: PREPARING | OWNED | RELEASED | RECLAIMABLE
}
```

Birth creates and reads back the tombstone, acquires each typed reference, sets
its owned bit, and changes the task owner to `OWNED` before the child can run.
`task_free` changes each bit from owned to released before decrementing exactly
one counter. Duplicate cleanup sees the released bit and does nothing. A crash
or map error may leak a restriction until reconciliation; it may not guess that
a reference was absent.

#### A.9.5 Native fork and thread algorithm

```text
1. Read the creator's TaskLabelV1 first.
2. If it exists, load current process and expected binding.
3. Reject a stale binding or moved task; never reclassify it as a host task.
4. If no label exists, completely resolve protected-root membership.
5. Protected but unlabeled means identity failure; unknown placement follows
   the signed fail-closed posture; only proved outside placement uses host policy.
6. Allocate child IDs, fixed state, tombstone, and rollback bits.
7. For CLONE_THREAD, point the child to the same process state and increment
   entry task refs plus process thread refs. Do not add a domain process ref.
8. For a new process, create an ALLOCATING process state, apply the one compiled
   FORK_WITHOUT_EXEC transition, and add exactly one domain process ref.
9. Install and read back the child label and every owned reference before run.
```

If a returning `task_alloc` hook is unavailable, a pre-wake path qualifies only
when tests prove it labels every child before execution, including
`clone3(CLONE_INTO_CGROUP)`, and an independent floor handles allocation
failure. Otherwise Mithril may claim first-protected-effect prevention, not
child-creation denial.

#### A.9.6 Exact exec transaction

Exec can involve a script, a `binfmt_misc` handler, the chosen executable, and
an ELF dynamic loader. They are one attempt.

```text
PendingExecV1 {
  pending_exec_id: Id128
  task_cookie: u64
  process_state_id: Id128
  exec_attempt_sequence: u64
  syscall_entry_coordinate
  state: PREPARING | COMMIT_PENDING | PRE_PONR_FAILED |
         POST_PONR_FATAL | SUCCESS | OUTCOME_UNKNOWN
  ordered_candidate_object_digests[MAX_BPRM_CHAIN]: DigestV1
  source_execution_id: Id128
  source_role_id: u32
  source_profile_generation_ref_id: u64
  pending_exec_response_set_ref_id: u64
  final_chain_digest?: DigestV1
}
```

The process CASes its exec guard from `NONE` to `EXEC_PREPARING`. A concurrent
exec or task creation loses and is denied. Every `bprm_check_security` pass
adds one bounded candidate and can only make the pending budget stricter. The
ELF `PT_INTERP` loader is recorded through its file/mapping allowance; it is
not assumed to cause another bprm pass.

Before Linux crosses the point where the old image cannot return, Mithril
prepares the target IDs and installs `EXEC_COMMIT_PENDING`. While any exec
guard exists, only the exact loader budget is usable; ordinary file, network,
device, IPC, privilege, and task-creation effects deny.

At a qualified successful-exec point before user mode, BPF performs an
in-place non-allocating switch to the target execution and role. A proven
failure before the point of no return restores the old execution. A later
fatal failure never restores old authority. If the platform cannot distinguish
those outcomes, the process remains `EXEC_OUTCOME_UNKNOWN` and fail-closed
until exit or reconciliation.

The valid guard pairs are closed:

| Process guard | Pending state | Usable authority |
| --- | --- | --- |
| `NONE` | no live pending attempt | Normal decision path |
| `EXEC_PREPARING` | `PREPARING` | Loader budget only |
| `EXEC_COMMIT_PENDING` | `COMMIT_PENDING` | Loader budget only |
| `EXEC_OUTCOME_UNKNOWN` | `COMMIT_PENDING`, `POST_PONR_FATAL`, or `OUTCOME_UNKNOWN` | Pending fail-closed floor only |

Any other pair denies as state corruption. `execveat(AT_EXECVE_CHECK)` checks
permission but does not consume an entry claim or change the active image.

#### A.9.7 Current stock-runtime root contract and rejected two-barrier history

The active no-patch contract is:

```text
ExternalRootClassificationV1 {
  node_boot_id, label_epoch
  task_cookie, process_state_id, entry_instance_id
  execution_set_id, cgroup_binding_id, cgroup_lifetime_id
  full_container_id, pod_uid, container_name
  creator_task_cookie?: u64
  root_class: INITIAL_CONTAINER_ROOT | EXTERNAL_RUNTIME_ROOT |
              RESTORED_OR_UNKNOWN_ROOT | UNRESOLVED_PROTECTED
  purpose: UNKNOWN | QUALIFIED_REGISTERED_PURPOSE
  purpose_source_id?
  purpose_to_task_join_proof?
  proof_quality
  profile_generation_ref_id
  installed_role: INITIAL_ROLE | RUNTIME_EXTERNAL_RESTRICTED |
                  FAIL_CLOSED_UNKNOWN | QUALIFIED_REGISTERED_ROLE
  classified_boottime_ns
}
```

`QUALIFIED_REGISTERED_PURPOSE` is legal only when an existing supported
interface supplies both the purpose and a unique request-to-task join. Stock
CRI probe/hook exec uses `purpose=UNKNOWN`. The BPF path never uses command,
arguments, timing, TTY, PodSpec resemblance, or a locally signed observation
to upgrade that value. Approved administrative exec is one explicit exception:
it uses `QUALIFIED_ADMINISTRATIVE_EXEC` plus a separate risk-accepted,
short-lived, one-use next-match slot. It must not be represented as a unique
request-to-task proof.

The active transaction is:

```text
prebuild container/cgroup binding from runtime inventory or a stock hook
  -> observe creator and placement at kernel task hooks
  -> native labeled creator: inherit native lineage
  -> known initial task: install initial role
  -> later independent root: install RUNTIME_EXTERNAL_RESTRICTED
  -> incomplete protected placement: install FAIL_CLOSED_UNKNOWN
  -> read back identity and binding
  -> allow or deny each covered effect through the normal task-first lookup
```

No active record requires a held task, a setup ticket, a rootfs-ready ticket,
a kubelet signature, a new CRI method, or a command-based pending claim.

**Rejected historical design begins here.** The remainder of this subsection
is retained so reviewers can see exactly what was abandoned. It is
non-normative and must not be implemented: it requires runtime/kubelet behavior
that stock interfaces do not provide and violates the no-patch product rule.

The OCI runtime still creates namespaces, cgroups, mounts, and the setup task.
The rejected design assumed that Mithril could prevent the runtime from
releasing the user process until identity and security state were installed.
Stock interfaces do not provide that general hold. This assumption is one
reason the design below is non-normative.

```text
RuntimeSetupBudgetV1 {
  budget_id
  runtime_binary_measurement
  runtime_name_version_config_digest
  kernel_capability_manifest_digest
  ordered_variants[] {
    variant_id
    steps[] {
      step_id
      permitted_predecessor_step_mask
      decision_point: exact LSM/fentry/seccomp hook ID
      syscall_or_kernel_operation_variant
      object_selector_or_namespace_type
      argument_mask_and_required_values
      minimum_count
      maximum_count
      result_requirement
    }
  }
  final_uid_gid_groups_capabilities_securebits
  final_namespace_and_rootfs_identity
  final_seccomp_proof_requirement?
}

BarrierEvidenceV1 =
  PTRACE_STOPPED {
    held_pidfd_identity, task_cookie, start_boottime_ns,
    waitid_p_pidfd_result_digest, wstopped_observed: true,
    exclusive_tracer_process_identity, ptrace_relationship_digest,
    stop_boottime_ns
  }
  | PRIVATE_BOOTSTRAP_BLOCKED {
      held_pidfd_identity, task_cookie, start_boottime_ns,
      measured_bootstrap_digest, ready_transcript_digest,
      private_release_handle_identity, release_nonce,
      ack_mac_key_id, expected_ack_payload_digest,
      wstopped_observed: false
    }
  | CGROUP_FROZEN {
      cgroup_fd_identity, cgroup_binding_nonce,
      cgroup_events_frozen_value: 1,
      exact_member_task_set_digest, member_count,
      freeze_generation, readback_boottime_ns
    }
```

A pidfd identifies the task. It does not stop the task. `PTRACE_STOPPED` is
valid only after `waitid(P_PIDFD)` reports the stop and Mithril verifies the
exclusive tracer. A private bootstrap is running but blocked, so it must say
`wstopped_observed=false`. A cgroup hold is valid only when `cgroup.events`
reads `frozen=1` and the complete member set equals the proposed setup set.
`SIGSTOP` without observed ownership, a pidfd by itself, a leaked release fd,
or an OCI hook that runs after setup is not a barrier.

The release acknowledgement covers the barrier variant, exact held target or
set, one-use setup ticket, every installed-state readback digest, and the
release nonce. It is accepted once. Hostile `SIGCONT`, `SIGKILL`, ptrace
attach, spurious wakeups, parent death, and a replayed acknowledgement must not
advance the held task.

Barrier 1 holds the measured setup task and gives it only the setup budget.
After the runtime constructs the final rootfs and namespaces, Barrier 2 binds
the final mount topology, projected credentials, inherited descriptors,
network namespace, devices, executable chain, cgroup nonce, policy generation,
entry, process, and domain state. Every required map/link/value is read back.
Only then may the runtime resume the target.

The setup budget is not general runtime trust. For example, a step may permit
mounting the PodSpec-declared projected credential volume as an opaque mount
object. It does not permit opening or reading the `token` file. Every operation,
object, flag, result, count, and predecessor step must match one signed ordered
variant. An extra mount, an early credential read, a repeated step beyond its
maximum, or the right step in the wrong order fails setup.

The two barriers have distinct jobs:

```text
held setup task
  -> SETUP_LABELED
  -> SETUP_RUNNING_UNDER_BUDGET
  -> ROOTFS_READY_HELD
  -> TOPOLOGY_RECONCILED
  -> OBJECT_TABLES_INSTALLED_AND_READ_BACK
  -> ONE_USE_FINAL_EXEC_ARMED
  -> USER_EXEC_COMMIT
```

Barrier 1 prevents unlabeled setup work. Barrier 2 prevents the final user
image from racing the mount and object classifier. At Barrier 2 the trusted
runtime supplies `RootfsReadyV1`: held task identity, mount-namespace fd and
generation, cgroup binding and nonce, rootfs/overlay identity, OCI and image
digests, declared mounts/devices/projected volumes, and final
argv/environment metadata digest. Mithril holds the namespace fd, resolves all
objects, installs the inactive tables, reads them back, and arms one final-exec
claim. A topology change marks the namespace `DIRTY`; final exec denies until
another complete reconciliation succeeds.

For streaming exec, preparation and the later stream/task are different
events. `RuntimeStreamTicket` is opaque, one-use, peer-bound, target-bound,
and expiring. The workload never receives it. `mithril-node` consumes it only
after the authenticated runtime binds it to the exact later held task and the
required state reads back. Preparing an exec URL does not identify a Linux
task.

External-entry ticket lookup is never available to an already labeled task:

```text
if current task has TaskLabelV1:
  evaluate only the native fork/exec/privilege-transition path
  do not inspect or claim runtime/kubelet external-entry tickets

else if placement resolves to a protected binding or remains unknown:
  require an exact held-task claim
  or the separately qualified fail-closed pending-claim fallback

else:
  evaluate explicit host policy
```

`execve()` does not remove BPF task storage. The application entrypoint and
all of its labeled forks therefore cannot steal a probe or lifecycle ticket by
executing the same command while that ticket is pending.

Kubelet purpose needs a carried ticket as well. Stock `ExecSyncRequest` does
not say whether the command is readiness, liveness, startup, `PostStart`, or
`PreStop`. The exact optional integration sends this record before kubelet
calls the runtime:

```text
KubeletExecutionRequestV1 {
  kubelet_instance_id
  kubelet_build_and_config_digest
  pod_uid
  pod_resource_version
  full_container_id
  container_spec_digest
  lifecycle_generation
  reason: STARTUP_PROBE | READINESS_PROBE | LIVENESS_PROBE |
          POST_START_EXEC | PRE_STOP_EXEC
  podspec_field_path
  canonical_argv_digest
  timeout_ns
  kubelet_monotonic_sequence
}
```

Mithril authenticates the local kubelet peer, re-resolves the Pod/container,
and returns a signed one-use ticket. A ticket-aware runtime carries the ticket
to one exact child-creation request, holds that child, and gives `mithril-node`
the ticket plus the child's pidfd/task, container, binding, lifecycle, and
runtime-request identity. `mithril-node` binds the ticket to that child,
installs and reads back its provisional entry/process state, atomically marks
the ticket consumed, and only then acknowledges release. The child does not
present the ticket from inside the workload.

Two identical commands running concurrently are separated by ticket and held
task identity—not by timestamps. An existing labeled application task always
takes the native-exec path, so it is not one of the ticket candidates. Without
the carried ticket and exact held-task binding, Mithril may use one same-budget
class for every ambiguous external root or reject; it must not claim an exact
probe/hook reason. A direct `crictl ExecSync` has no kubelet ticket and is an
administrative entry or is rejected.

The pending-claim fallback is allowed only for a qualified runtime that cannot
provide a held task. Userspace prebuilds the whole claim, not just a role:

```text
PreparedExternalRootStateV1 {
  claim_slot_id
  immutable_task_label_template
  process_state_id                 // PREPARING; provisional deny set
  authority_domain_id              // already ACTIVE
  entry_instance_id
  active_profile_generation_ref_id
  generation_ref_slot
  entry_task_ref_slot
  domain_pending_ref_slot
  kernel_claim_tombstone_slot
  expected_binding/candidate/attempt digests
  prepared_immutable_fields_digest
  expected_claim_bound_state_digest
  state: PREPARING | EXPOSED | CLAIMING | CLAIM_BOUND_PROVISIONAL |
         EXEC_COMMITTED | TERMINAL_FAILED | RECONCILING
}
```

At `bprm_check_security`, one unlabeled sole-task stub can atomically claim the
slot. The hook validates the binding and candidate, wins `PENDING -> CLAIMING`,
installs `ENTRY_PROVISIONAL`, writes the kernel tombstone, acquires each
preallocated typed reference, activates the provisional process state, reads
everything back, and only then permits bounded loader/interpreter work. The
successful exec observer commits the final role. Failure after any step denies
and terminalizes the slot. The provisional role cannot read ordinary files,
use the network, create children, or obtain privilege. Multi-threaded or
unqualified runtime stubs require the held-task path.

#### A.9.8 Current root-classification failures and required tests

| Failure | Required physical result |
| --- | --- |
| Protected parent or root has no label | Resolve it as initial, restricted external, restored/unknown, or fail-closed unresolved; never inherit application authority |
| Task, process, or binding map is full | Deny the returning task/effect hook where supported and install/retain the fail-closed floor; never call an unlabeled actor protected |
| PID-coordinate finalization fails | Keep `FAIL_CLOSED_UNKNOWN`; no protected effect succeeds |
| Rootfs/mount/object binding is incomplete | Keep the binding `DIRTY` or unresolved and deny affected protected effects; claim start rejection only if the configured stock hook returned it |
| Runtime/hook source authentication fails | Discard its metadata; kernel placement remains restricted and source coverage becomes unhealthy |
| Concurrent exec loses the guard CAS | Deny that attempt before staging |
| Exec success observer cannot update | Retain the already installed pending deny floor |
| `task_free` update fails | Leak the restriction and require reconciliation; never decrement by guess |
| Daemon restarts with labeled or unresolved tasks | Preserve pinned restrictions; re-enumerate runtime/cgroups/tasks and reconcile labels, references, and WAL before opening a healthy interval |

Mandatory tests include leader-exits-first threads, failed fork rollback,
double cleanup, PID/TID reuse, moved labeled parent, moved exec task,
`CLONE_INTO_CGROUP` with allocation failure, concurrent exec, non-leader exec,
shebang, `binfmt_misc`, approved and substituted ELF loaders, pre/post-point-of-
no-return failure, direct `crictl` exec, identical probe/hook/admin commands,
runtime restart, discovery delay, missing hook fields, forged hook metadata,
and every supported stock hook failure/timeout result.

#### A.9.9 Checkpoint, attach, port-forward, and node-floor contracts

Checkpoint restore and stream records below are retained historical design
inputs, not active no-patch contracts. The active product may reject through a
configured existing authorization hook or apply restrictive BPF treatment and
report `UNSUPPORTED`. It may not add held-task support to CRIU/runtime or
insert a stream proxy. The node-floor request/decision remains active only at
a configured stock Kubernetes admission or runtime extension point.

```text
CheckpointRestoreIntentV1 {
  restore_intent_id, proof_id, claim_slot_id: Id128
  node_boot_id, execution_set_id, cgroup_binding_id,
    cgroup_binding_nonce: Id128
  checkpoint_artifact_digest, checkpoint_manifest_digest: DigestV1
  source_node_boot_id?: Id128
  source_profile_portable_generation: PortableProfileGenerationV1
  target_profile_generation_ref_id: u64
  expected_task_count: u32
  expected_process_count: u32
  target_role_and_domain_manifest_digest: DigestV1
  held_helper_execution_set_id: Id128
  deadline_boottime_ns: u64
  state: PREPARING | HELPER_HELD | RESTORING | TARGETS_BOUND |
         VERIFIED | REJECTED | FAILED_CLOSED
}

RestoreTargetBirthSlotV1 {
  slot_id, restore_intent_id: Id128
  checkpoint_task_identity_digest: DigestV1
  expected_process_and_thread_relation_digest: DigestV1
  prepared_task_cookie: u64
  prepared_process_state_id, prepared_entry_instance_id: Id128
  state: PENDING | CLAIMING | LABELED_HELD | VERIFIED |
         RELEASED | FAILED_CLOSED
}

CheckpointCreationRequestV1 {
  request_id: Id128
  exact_target_execution_set_and_task_set_digest: DigestV1
  target_profile_generation_refs[]: u64
  target_authority_domain_ids[]: Id128
  included_memory_file_socket_device_state_digest: DigestV1
  encrypted_storage_sink: ResourceSelectorV1
  export_authority_id: Id128
  maximum_bytes: u64
  deadline_boottime_ns: u64
  result: PENDING | DENIED | EXPORTED | FAILED | UNKNOWN
}

StreamAuthorityV1 {
  stream_authority_id, proof_id, claim_slot_id: Id128
  kind: ATTACH | PORT_FORWARD
  peer_identity_digest: DigestV1
  target_execution_set_id, target_process_or_entry_id: Id128
  permitted_ports[]: u16
  permitted_directions
  byte_and_time_budget
  meter_and_fence_capability_ids[]
  deadline_boottime_ns: u64
  state: PENDING | ACTIVE | FENCED | COMPLETE | FAILED | EXPIRED
}
```

**Rejected restore detail.** The earlier design uses a separate held helper
execution set; freezing the helper's own
cgroup may deadlock CRIU and does not prove future restored tasks. Each target
is intercepted before runnable, consumes one prepared slot, receives complete
task/process/entry/domain/generation state, and remains held until a complete
iterator equals the signed manifest. Memory, inherited fds, sockets, mappings,
credential possession, and sensitive/domain state restore with the target; a
checkpoint cannot erase them.

Checkpoint creation is a memory/file/socket/device export effect. It needs
complete target enumeration, shared-state preservation, encrypted sink, exact
byte/result oracle, and denial of an unapproved export. Attach and port-forward
are not process identity. Attach does not create a child; port-forward does not
become ordinary process egress. The active baseline records actor, request UID,
target, ports/channels, result, and proof quality from existing Kubernetes
APIs. Metering fields above stay inactive unless a future existing supported
interface supplies them without a proxy.

The node hard floor protects unchanged deployments before setup:

```text
NodeAdmissionRequestV1 {
  request_id: Id128
  node_boot_id: Id128
  effective_podspec_and_cri_security_digest: DigestV1
  image_digest, canonical_argv_digest: DigestV1
  working_directory_bytes: bounded bytes
  environment_config_secret_mount_device_security_manifests[]: DigestV1
  pod_uid?, controller_uid?: Id128
  immutable_controller_revision_digest?: DigestV1
  runtime_normalization_digest: DigestV1
}

NodeHardFloorDecisionV1 {
  request_id: Id128
  matched_baseline_or_exception_id?: Id128
  result: ALLOW_MATCHED | REJECT_UNMATCHED | REJECT_HARD_FLOOR |
          ADMIT_UNKNOWN_RESTRICTED_AND_ALERT
  exact_rejected_field_ids[]
  required_profile_generation_ref_id?: u64
  decision_interface_capability_id: Id128
  decision_digest: DigestV1
}
```

The floor can reject a never-seen privileged/hostPID/host-root/capability
workload before scheduling when a stock Kubernetes validating-admission
integration is configured. A stock runtime extension may reject before setup
only when its qualified ordering proves that result. Otherwise the BPF hard
floor controls later covered effects and must not claim the mount setup was
prevented. A privileged CSI/node agent requires an exact signed, expiring
exception naming immutable image, controller, fields, scope, approver, and
maximum instances. Kubernetes labels alone do not authenticate it.

Qualification must cover complete restore, partial target set, helper/target
mix-up, changed profile, inherited sensitive memory/fds, task-count mismatch,
restore crash after every slot transition, checkpoint export denial, attach
peer swap, port-forward existing stream/fence, unmatched privileged Pod, and
valid narrow node-agent exception. Until allocated phases implement these
records and tests, claims remain `UNSUPPORTED`, not approximated by ordinary
container-start or socket observation.

Mithril must never claim that a Pod, cgroup, command string, TTY, PID, runtime
callback, or post-run event alone proves why a process exists.

### A.10 Exact Signed-Intent, Trust, And Replay Contract

Chapter 8 explains why authorization is separate from process identity. This
section defines Mithril's canonical bytes only for a source that truly issues
an authorization. It does not require kubelet, containerd, runc, a CI runner,
or a workload to produce this format.

**Example.** An operator approves one cloud-session revocation. Its signed
proof has one slot. The response owner consumes that slot once; restart does
not make it new. Stock kubelet readiness probes have no such proof and are
classified as external roots with unknown purpose.

#### A.10.1 Signed envelope and common payload

Version 1 uses deterministic CBOR and integer map keys. `Id128` is exactly 16
bytes. `DigestV1` is `{0: 1, 1: <32 SHA-256 bytes>}`. Unknown, duplicate, or
non-canonical fields reject the whole object.

```text
SignedIntentV1 = {
  0: 1,                       // wire version
  1: bstr(1..128),            // key ID
  2: 1,                       // Ed25519
  3: bstr(1..32768),          // exact canonical IntentPayloadV1 bytes
  4: bstr(64)                 // signature
}

signature_input =
  ASCII("MITHRIL-INTENT-V1") || 0x00 || SHA-256(canonical_payload)

IntentPayloadV1 = {
  0: 1,                       // payload version
  1: IntentKindV1,
  2: Id128 proof_id,
  3: Id128 tenant_id,
  4: Id128 trust_domain_id,
  5: Id128 issuer_id,
  6: nonzero u64 sequence_epoch,
  7: nonzero u64 sequence,
  8: i64 issued_at_utc_ns,
  9: i64 not_before_utc_ns,
  10: i64 expires_at_utc_ns,
  11: [Id128; 1..64] sorted unique claim_slot_ids,
  12: IntentBodyV1,
  13?: Id128 parent_proof_id,
  14?: [Id128; 1..16] sorted unique trigger_proof_ids
}

IntentKindV1 =
  1 RUNTIME_ENTRY | 2 NATIVE_TRANSITION | 3 AUTHORITY_LEASE |
  4 ARTIFACT_HANDOFF | 5 PROVIDER_OPERATION | 6 DEPLOYMENT_ADMISSION |
  7 CI_STEP
```

`RUNTIME_ENTRY` and `CI_STEP` are reserved capability-gated variants. The
decoder rejects them unless the platform manifest names a qualified existing
issuer and exact join contract. They are not enabled for stock kubelet/CRI or
an unmodified runner merely because the enum value exists.

The issuer does not choose mismatch, expiry, or fail-open behavior. Those
fields are absent. Local signed policy owns the result. Multiplicity is the
explicit slot array, never a reusable count.

#### A.10.2 Closed body variants

```text
RuntimeEntryBodyV1 = {
  0: Id128 cluster_uid,
  1: Id128 node_boot_id,
  2: bstr(1..64) pod_uid,
  3: bstr(32..128) full_container_id,
  4: Id128 execution_set_id,
  5: Id128 cgroup_binding_id,
  6: Id128 cgroup_binding_nonce,
  7: nonzero u64 lifecycle_generation,
  8: RuntimeOperationV1,
  9: EntryKindV1,
  10: DigestV1 immutable_definition_or_podspec_digest,
  11?: DigestV1 canonical_command_digest,
  12: Id128 target_role_id,
  13: DigestV1 runtime_request_digest,
  14?: DigestV1 exact_request_to_task_join_digest
}

NativeTransitionBodyV1 = {
  0: Id128 node_boot_id,
  1: Id128 execution_set_id,
  2: Id128 process_lineage_id,
  3: Id128 source_execution_id,
  4: NativeOperationV1,
  5: DigestV1 candidate_executable_or_action_digest,
  6: Id128 source_role_id,
  7: Id128 target_role_id
}

AuthorityLeaseBodyV1 = {
  0: LocalAuthoritySubjectV1,
  1: ProviderV1,
  2: bstr(1..256) provider_account_or_project,
  3: bstr(1..512) audience,
  4: [u32; 1..128] requested_permission_ids,
  5: [ResourceSelectorV1; 1..128] requested_resources,
  6: u64 maximum_ttl_ns,
  7: bstr(1..256) issuer_subject,
  8: Id128 provider_request_nonce
}

ArtifactHandoffBodyV1 = {
  0: CausalSubjectV1 producer,
  1: CausalSubjectV1 consumer,
  2: ArtifactKindV1,
  3: DigestV1 immutable_artifact_digest,
  4: ProducerTrustClassV1,
  5: ArtifactOperationV1,
  6: [DigestV1; 0..32] required_attestation_digests
}

ProviderOperationBodyV1 = {
  0: ProviderV1,
  1: bstr(1..256) provider_account_or_tenant,
  2: ProviderPrincipalV1,
  3: u32 canonical_operation_id,
  4: [ResourceSelectorV1; 1..128] resources,
  5: Id128 request_nonce,
  6: ProviderResultBoundaryV1,
  7: u64 maximum_ttl_ns
}

DeploymentAdmissionBodyV1 = {
  0: Id128 approver_principal_id,
  1: DigestV1 effective_podspec_and_cri_security_digest,
  2: DigestV1 image_digest,
  3: DigestV1 canonical_argv_digest,
  4: bstr(0..4096) working_directory_bytes,
  5: DigestV1 environment_reference_manifest_digest,
  6: DigestV1 config_reference_manifest_digest,
  7: DigestV1 secret_reference_manifest_digest,
  8: DigestV1 mount_manifest_digest,
  9: DigestV1 device_manifest_digest,
  10: DigestV1 security_field_manifest_digest,
  11: Id128 controller_uid,
  12: DigestV1 immutable_controller_revision_digest,
  13: [Id128; 1..256] permitted_namespace_uids,
  14: [Id128; 1..4096] permitted_node_uids,
  15: u32 maximum_instance_count,
  16: [u32; 0..128] runtime_normalization_rule_ids,
  17: bool require_instance_binding,
  18?: Id128 admission_issued_pod_uid_nonce,
  19: u64 target_profile_generation
}
```

CI has three evidence bindings rather than dummy zero fields. The first two
are legal only when an existing official interface supplies a unique join;
ordinary host jobs use job evidence plus separate Linux process evidence and
do not create a `CiStepIntentBodyV1`:

```text
CiExecutionBindingV1 =
  {0: 1, 1: Id128 node_boot_id, 2: Id128 execution_set_id,
   3: Id128 cgroup_binding_id, 4: Id128 cgroup_binding_nonce,
   5: DigestV1 official_step_to_task_join_digest}              // local native
  | {0: 2, 1: Id128 node_boot_id, 2: Id128 execution_set_id,
     3: Id128 cgroup_binding_id, 4: Id128 cgroup_binding_nonce,
     5: DigestV1 official_step_to_container_join_digest}       // runtime root
  | {0: 3, 1: Id128 provider_operation_request_id}             // no local task

CiStepIntentBodyV1 = {
  0: CiCoordinatorV1,
  1: bstr(1..256) tenant_id,
  2: bstr(1..256) repository_or_project_id,
  3: bstr(1..256) pipeline_run_id,
  4: bstr(1..256) pipeline_job_id,
  5: bstr(1..256) pipeline_step_id,
  6: nonzero u32 run_attempt,
  7: DigestV1 immutable_pipeline_definition_digest,
  8: DigestV1 step_definition_identity_digest,
  9: DigestV1 materialized_step_invocation_digest,
  10: CiTriggerTrustClassV1,
  11: CiExecutionShapeV1,
  12: bstr(1..256) exact_runner_assignment_id,
  13: CiExecutionBindingV1,
  14: Id128 requested_role_id,
  15: [DigestV1; 0..128] input_artifact_digests,
  16: [Id128; 0..32] requested_authority_lease_proof_ids,
  17?: Id128 parent_step_proof_id,
  18: DigestV1 provider_job_assignment_evidence_digest,
  19?: DigestV1 official_step_task_join_evidence_digest
}
```

Shape `COORDINATOR_BUILTIN_NO_LOCAL_TASK` must use the coordinator-only
binding. A local shape may use a local binding only when the qualified official
interface provides it. Missing, extra, zero-filled, or wrong-shape fields are
parser errors. Mithril's own signature over separately observed job and task
records is not an official step-to-task join.

The closed base registries are:

```text
RuntimeOperationV1 = 1 CONTAINER_START | 2 EXEC_SYNC |
  3 STREAMING_EXEC | 4 LIFECYCLE_EXEC | 5 EPHEMERAL_CONTAINER |
  6 CHECKPOINT_RESTORE

NativeOperationV1 = 1 FORK | 2 EXEC | 3 PRIVILEGE_TRANSITION

ArtifactOperationV1 = 1 READ_AS_DATA | 2 VERIFY | 3 LOAD |
  4 EXECUTE | 5 DEPLOY

ProviderV1 = 1 KUBERNETES | 2 AWS | 3 GCP | 4 GITHUB |
  5 INTERNAL_CONNECTOR | 6 OCI_REGISTRY

EntryKindV1 = 1 CONTAINER_START | 2 QUALIFIED_EXEC_PROBE |
  3 QUALIFIED_LIFECYCLE_POSTSTART | 4 QUALIFIED_LIFECYCLE_PRESTOP |
  5 QUALIFIED_ADMINISTRATIVE_EXEC | 6 EPHEMERAL_CONTAINER |
  7 QUALIFIED_CI_CONTAINER_ACTION | 8 CHECKPOINT_RESTORE_UNKNOWN |
  9 UNKNOWN_EXTERNAL

ArtifactKindV1 = 1 FILE | 2 DIRECTORY_TREE | 3 OCI_IMAGE |
  4 CI_ARTIFACT | 5 CACHE_ENTRY | 6 QUEUE_MESSAGE |
  7 DEPLOYMENT_MANIFEST

ProducerTrustClassV1 = 1 UNTRUSTED_INPUT | 2 PROTECTED_BUILD |
  3 APPROVED_RELEASE | 4 EXTERNAL_UNVERIFIED

ProviderResultBoundaryV1 = 1 SYNCHRONOUS_GATE_RESULT |
  2 AUTHORITATIVE_API_RESULT

LocalAuthoritySubjectV1 =
  {0:1, 1:Id128 node_boot_id, 2:Id128 execution_set_id,
   3:Id128 process_lineage_id}
  | {0:2, 1:ProviderV1 coordinator, 2:bstr(1..256) run_id,
     3:bstr(1..256) job_id, 4?:bstr(1..256) step_id}

CausalSubjectV1 =
  {0:1, 1:Id128 node_boot_id, 2:Id128 process_lineage_id,
   3?:Id128 execution_id}
  | {0:2, 1:ProviderV1 coordinator, 2:bstr(1..256) run_id,
     3:bstr(1..256) job_id}
  | {0:3, 1:ProviderV1, 2:bstr(1..512) stable_subject_id}

ResourceSelectorV1 = {
  0:u16 resource_kind_id,
  1:bstr(1..1024) provider_canonical_resource_bytes,
  2?:DigestV1 immutable_revision_digest
}

ProviderPrincipalV1 = {
  0:u16 principal_kind_id,
  1:bstr(1..512) provider_stable_principal_id,
  2?:bstr(1..512) public_session_or_lease_id
}
```

Provider-specific operation, permission, principal, and resource IDs live in a
signed versioned registry. An unregistered number rejects. Display strings do
not replace numeric authority.

#### A.10.3 Bounds, trust, and replay

Before signature verification may allocate body state, the decoder enforces:

```text
payload <= 32 KiB
aggregate byte strings <= 24 KiB
nesting depth <= 8
aggregate array members <= 512
claim slots <= 64
trigger IDs <= 16
exactly one body variant
definite CBOR lengths and shortest integer forms
bytewise sorting and uniqueness where required
expiry no more than 24 hours after issue, with a smaller local limit allowed
```

```text
TrustBundle {
  trust_domain_id: Id128
  bundle_generation: u64
  issuers[] {
    issuer_id: Id128
    issuer_kind
    key_id: bounded bytes
    public_key: 32 bytes
    allowed_algorithm: ED25519
    sequence_epoch: u64
    valid_from_utc_ns, valid_until_utc_ns: i64
    revoked_at_utc_ns?: i64
    allowed_intent_kinds[]
    allowed_subject_scopes[]
  }
  maximum_clock_skew: 0s..5m
  replay_window_size: exactly 4096
}
```

The receiver checks wall-clock validity including measured uncertainty, then
derives a boot-time deadline. Clock adjustment cannot revive a proof. Replay
state is keyed by trust domain, issuer, key, and sequence epoch and keeps the
highest sequence, a 4,096-bit out-of-order window, and proof/slot tombstones.

Acceptance order is fixed:

```text
parse bounded canonical bytes
verify signature, issuer scope, target, time, and local policy subset
prove sequence, proof ID, and every slot are unused
append acceptance durably to the WAL
only then expose a prepared slot to the Mithril owner of that authorized action
record later consumption transitions in the owner's state and WAL
```

Key rotation needs an authorized new sequence epoch; changing only `key_id`
does not reset replay state. Admission remains closed during restart replay and
pinned-map reconciliation.

#### A.10.4 Claim journal and consumption

```text
KernelClaimTombstoneV1 {
  node_boot_id: Id128
  label_epoch: u64
  claim_slot_id, proof_id: Id128
  task_cookie: u64
  process_state_id, entry_instance_id, exec_attempt_id: Id128
  claimed_boottime_ns: u64
  transition_sequence: u64
  state: CLAIMING | CLAIM_BOUND_PROVISIONAL | EXEC_COMMITTED |
         EXEC_FAILED | EXPIRED | CANCELLED | TASK_EXITED
  owned_ref_bits: u64
  wal_acknowledged_through_sequence: u64
}
```

The kernel claim transition updates this preallocated pinned record before
installing provisional authority. Capacity failure denies. Event delivery is
best effort. Recovery releases only references whose owned bits say they were
acquired. The tombstone remains at least through replay expiry and entry
lifetime completion.

Four separate objects may consume real authorization. The runtime and native
rows are capability-gated and are not used to classify ordinary stock external
roots or routine forks/execs:

| Action | Object | State progression |
| --- | --- | --- |
| Runtime-created root under a qualified existing authorization interface | Entry and claim slot | pending -> provisional -> exec committed or terminal failure |
| Exceptional Mithril-authorized native fork/exec/privilege transition | `TransitionIntentV1` | pending -> claiming -> committed/denied/expired/cancelled |
| Credential acquisition | `AuthorityLeaseIntentV1`, then `CredentialLeaseV1` | request becomes issued only after compatible provider result |
| Artifact transfer | `ArtifactInstanceV1` plus one `ArtifactConsumerSlotV1` per consumer | published -> independently claimed -> verified/rejected/expired |

The native transition object is:

```text
TransitionIntentV1 {
  transition_intent_id, proof_id, claim_slot_id:Id128
  node_boot_id, execution_set_id:Id128
  source_process_lineage_id, source_execution_id:Id128
  operation:FORK | EXEC | PRIVILEGE_TRANSITION
  candidate_executable_object?:ExactObjectGenerationV1
  canonical_argv_digest?:DigestV1
  requested_target_role:Id128
  deadline_boottime_ns:u64
  state:PENDING | CLAIMING | COMMITTED | DENIED | EXPIRED | CANCELLED
}
```

Routine fork, exec, and privilege transitions do not need a signed intent; they
use the exact current process state, target object, and compiled transition
policy. If a future feature allocates an exceptional one-use
`TransitionIntentV1`, an exec authorization cannot authorize a fork, a
successful claim cannot be replayed, and expiry cannot be revived by restart.
The optional authorization is additional purpose, not a replacement for actor
identity.

A provider response with a different account, audience, role, scope, nonce, or
TTL does not create a credential lease. A `READ_AS_DATA` artifact slot does not
authorize `LOAD`, `EXECUTE`, or `DEPLOY`.

Bearer credentials never enter observations, graphs, logs, or the WAL. When a
provider requires possession for narrow self-revocation, a separate vault may
retain a short-lived `ProtectedCredentialHandleV1` authorized only for
`REVOKE_SELF`. Its opaque ID may appear in evidence; the secret cannot.

#### A.10.5 Conformance tests and forbidden claims

Phase 0 checks in canonical payload, signature input, signature, envelope, and
negative vectors. Rust must encode and decode the exact same bytes. Tests alter
one integer tag, duplicate a field, use an indefinite array, reorder a
supposedly sorted ID list, cross body variants, exceed every bound, replay a
slot across restart, rotate a key without an epoch, race four authorized action
consumers for three slots, and kill the daemon between owner-state CAS, event
delivery, and WAL acknowledgment.

Mithril must never call JSON/YAML bytes the signed wire, let an issuer select
fail-open, accept a reusable count instead of slots, infer a slot from time and
argv, store provider secrets as evidence, or call provider audit a synchronous
pre-effect intent proof. It must also never treat stock kubelet/CRI, runtime,
or runner observations as signed intent merely because Mithril normalized and
signed its own copy.

### A.11 Exact Policy, Parser, Signature, And Activation Contract

Chapters 11-12 describe one policy model. This section closes the places where
two implementations might otherwise make different choices.

**Problem.** An operator writes one rule denying the conversion worker access
to a projected ServiceAccount token. Rust, BPF, the policy-review UI, and the
qualification runner must all agree on the same actor, object, operation,
failure result, and bytes. YAML order or a library's permissive defaults cannot
change that decision.

#### A.11.1 Source-file rules

The source is UTF-8 YAML 1.2 restricted to the JSON data model. The decoder
rejects duplicate keys, anchors, aliases, merge keys, custom tags, non-string
map keys, implicit timestamps, NaN/infinity, integers outside the declared
type, unknown fields, unknown enums, and input beyond the signed size, depth,
and count limits. Enum source values are uppercase ASCII. Durations match
`^[0-9]+(ns|us|ms|s|m|h)$`; zero is legal only where the field says so.

Comments and YAML key order carry no authority. After parsing closed types,
the document is encoded as deterministic CBOR. Version 1 has no generic
extension or metadata bag.

```text
PolicyDocumentV1 {
  api_version: exactly "mithril.erebor.dev/v1"
  kind: exactly "ProtectionPolicy"
  metadata {
    profile_id: Id128
    profile_version: nonzero u64
    trust_domain_id: Id128
    valid_from_utc: RFC3339 UTC normalized to i64 nanoseconds
    valid_until_utc?: RFC3339 UTC normalized to i64 nanoseconds
  }
  required_capability_ids[]
  protected_universe {
    workload_selector_ids[]
    protected_scope_ids[]
    execution_set_ids[]
    role_ids[]
    entry_kind_ids[]
    object_class_ids[]
    provider_account_ids[]
  }
  workload_selectors[]: WorkloadSelectorV1
  classifier_bindings[]: ObjectClassifierBindingV1
  roles[]: RoleDefinitionV1
  entry_role_assignments[]: EntryRoleAssignmentV1
  native_transition_rules[]: NativeRoleTransitionRuleV1
  process_state_definitions[]: ProcessStateDefinitionV1
  domain_sensitive_state_rules[]: DomainSensitiveStateRuleV1
  effect_family_defaults[]: EffectFamilyDefaultV1
  authority_behavior_rules[]: AuthorityBehaviorRuleV1
  correlation_package_bindings[]: CorrelationPackageBindingV1
  default_postures: DefaultPosturesV1
  notification_routes[]: NotificationRouteV1
  response_bindings[]: ResponseBindingV1
  exceptions[]: ExceptionV1
  rules[]: DetectionDispositionRuleV1
  source_coverage_health_rules[]: SourceCoverageHealthRuleV1
  rollout: RolloutV1
}

PolicyLocalIdV1 = UTF-8 matching ^[a-z][a-z0-9.-]{0,127}$
RegistrySymbolV1 = ASCII matching ^[A-Z][A-Z0-9_]{0,127}$
PackageIdV1 = ASCII matching ^[A-Z][A-Z0-9-]{0,126}[0-9]$
```

#### A.11.2 Selectors classify candidates; bindings create authority

```text
ReasonCodeIdV1 = RegistrySymbolV1
ObjectClassIdV1 = RegistrySymbolV1
ResultCodeIdV1 = RegistrySymbolV1

LabelRequirementV1 {
  key:UTF-8 Kubernetes qualified name, 1..253 bytes
  operator:IN | NOT_IN | EXISTS | DOES_NOT_EXIST
  values[0..64]:UTF-8 Kubernetes label values, sorted unique
}

WorkloadSelectorV1 {
  workload_selector_id: PolicyLocalIdV1
  cluster_uids[1..16]: Id128
  namespace_uids[1..64]: Id128
  controller_uids[0..256]: Id128
  service_account_uids[0..64]: Id128
  pod_label_requirements[0..64]: LabelRequirementV1
  container_names[0..64]: bounded UTF-8
  container_kinds[1..4]: INIT | SIDECAR | APPLICATION | EPHEMERAL
  image_digests[0..256]: DigestV1
}

ObjectClassifierBindingV1 {
  classifier_binding_id: PolicyLocalIdV1
  object_class_id: ObjectClassIdV1
  selector: PROJECTED_SERVICE_ACCOUNT_TOKEN | FILESYSTEM_OBJECT |
            IMMUTABLE_ARTIFACT | DESTINATION | DEVICE |
            KERNEL_SECURITY_OBJECT
  required_capability_ids[1..64]
  unknown_result: DENY | ALERT
}

ResolvedObjectClassBindingV1 {
  classifier_binding_id, object_class_id: PolicyLocalIdV1
  exact_object: ExactObjectGenerationV1
  classifier_axis_id: u16
  classifier_axis_value_id: u32
  source_object_revision_digest: DigestV1
}

WorkloadBindingArtifactV1 {          // immutable signed payload
  binding_generation_id: Id128
  policy_document_digest, selector_registry_digest,
    classifier_registry_digest: DigestV1
  cluster_uid, node_boot_id: Id128
  workload_selector_id: PolicyLocalIdV1
  pod_uid: Id128
  pod_resource_version_digest, full_container_id_digest,
    image_digest: DigestV1
  execution_set_id, protected_scope_id: Id128
  cgroup_binding_identity_digest: DigestV1
  resolved_object_class_bindings[]: sorted unique
  binding_generation: nonzero u64
  valid_from_boottime_ns: u64
  canonical_payload_digest: DigestV1
  signer_key_id
  signature
}

WorkloadBindingActivationStateV1 {   // mutable node-local state
  binding_generation_id: Id128
  artifact_digest: DigestV1
  state: PREPARING | ACTIVE | RETIRING | TOMBSTONED
  transition_version: u64
  last_complete_readback_digest: DigestV1
}
```

The immutable signed artifact never contains a mutable `ACTIVE` byte. The
node-local activation record changes only after every installed row and object
binding reads back. A new Pod or rotated projected token creates new exact
bindings; a hook never lazily chooses the first matching selector.

The classifier registry is also closed and signed:

```text
DestinationPolicyRecordV1 {
  destination_policy_id: PolicyLocalIdV1
  protocols[1..3]: TCP | UDP | SCTP
  ipv4_prefixes[0..256], ipv6_prefixes[0..256]: canonical CIDR
  port_ranges[1..64] { first:u16, last:u16 >= first }
  required_network_namespace_ids[0..64]: Id128
  service_identities[0..64] {
    provider: KUBERNETES | AWS | GITHUB | MESH | CONNECTOR | OTHER
    stable_service_id: PolicyLocalIdV1
    endpoint_registry_generation: nonzero u64
  }
  final_address_required: bool
}

DeviceClassRecordV1 {
  device_class_id: PolicyLocalIdV1
  device_type: CHAR | BLOCK
  major_ranges[1..64], minor_ranges[1..64] { first:u32, last:u32 }
  driver_name_digests[0..64]: DigestV1
  allowed_ioctl_command_ids[0..256]: u32
}

SecurityObjectRecordV1 {
  security_object_id: PolicyLocalIdV1
  family: PTRACE | PROCESS_VM | PIDFD | BPF | PERF | KEYRING |
          CAPABILITY | NAMESPACE | MOUNT | MODULE | IO_URING_CONTROL
  operation_ids[1..256]: RegistrySymbolV1
  target_selector_ids[0..64]: PolicyLocalIdV1
}

MountSourceClassRecordV1 {
  mount_source_class_id: PolicyLocalIdV1
  source_kind: ROOTFS | BIND | TMPFS | PROJECTED | SECRET |
               CONFIGMAP | EMPTYDIR | HOSTPATH | CSI | NFS | FUSE | OTHER
  filesystem_type_ids[1..64]: PolicyLocalIdV1
  backing_object_or_volume_ids[0..64]: Id128
  required_mount_flags[0..32]: READ_ONLY | NOSUID | NODEV | NOEXEC
}

ObjectClassifierRegistryV1 {
  registry_version: nonzero u64
  destination_policies[]: DestinationPolicyRecordV1
  device_classes[]: DeviceClassRecordV1
  security_objects[]: SecurityObjectRecordV1
  mount_source_classes[]: MountSourceClassRecordV1
  filesystem_types[] { id, numeric_magic:u64, bounded_name }
  canonical_payload_digest: DigestV1
}
```

Overlapping registry entries that assign different classes, a missing required
axis, stale endpoint generation, unknown filesystem/device/security type, or a
registry digest mismatch keeps the binding `PREPARING` and prevents activation.

#### A.11.3 Roles, entries, transitions, and effects

```text
ProcessStateDefinitionV1 {
  process_state_id:PolicyLocalIdV1
  state_bits[0..64]:sorted unique closed ProcessStateBitV1
}

DomainSensitiveStateRuleV1 {
  state_rule_id:PolicyLocalIdV1
  triggering_object_class_ids[1..256]:ObjectClassIdV1
  triggering_operations[1..64]:RegistrySymbolV1
  set_sensitive_bits[1..64]:closed DomainSensitiveBitV1
  resulting_restriction_semantic_ids[1..64]:PolicyLocalIdV1
  monotonic:exactly true
}

RoleDefinitionV1 {
  role_id: PolicyLocalIdV1
  maximum_native_depth: u16
  default_process_state_id: PolicyLocalIdV1
  permitted_entry_kinds[1..16]: EntryKindV1
  description_artifact_digest?: DigestV1
}

EntryRoleAssignmentV1 {
  assignment_id: PolicyLocalIdV1
  workload_selector_ids[1..32]
  entry_kinds[1..16]: EntryKindV1
  container_kinds[1..4]
  immutable_definition_digests[0..64]: DigestV1
  accepted_classifications[1..3]: EXACT_INITIAL |
    CONSERVATIVE_EXTERNAL_UNKNOWN | QUALIFIED_REGISTERED_PURPOSE
  required_purpose_source_capability_id?: Id128
  resulting_role_id: PolicyLocalIdV1
  on_missing_or_unequal_ambiguity: RESTRICT_EXTERNAL |
    DENY_PROTECTED_EFFECTS | REJECT_WHEN_STOCK_INTERFACE_SUPPORTS
  unknown_restricted_role_id?: PolicyLocalIdV1
}

NativeRoleTransitionRuleV1 {
  transition_rule_id: PolicyLocalIdV1
  source_role_ids[1..32]
  operation: FORK | THREAD_CREATE | EXEC | PRIVILEGE_TRANSITION
  executable_object_ids[0..256]
  required_process_state_ids[1..64]
  resulting_role_id, resulting_process_state_id: PolicyLocalIdV1
  requested_disposition: ALLOW | ALERT | DENY
  errno?: EACCES | EPERM | EAGAIN
}

EffectFamilyDefaultV1 {
  role_ids[1..32]
  effect_family: EXEC | FILE | NETWORK | DEVICE | PRIVILEGE | IPC | MOUNT
  operations[1..256]
  requested_disposition: ALLOW | ALERT | DENY
  errno?: EACCES | EPERM | EAGAIN | ECONNREFUSED
  finding?: FindingSpecV1
}
```

An authority rule is one of two distinct stages:

```text
AuthorityBehaviorRuleV1 =
  REMOTE_ADMISSION {
    rule_id, authorization_interface_capability_id, provider, provider_accounts,
    principal_or_lease_selectors, operations, resources,
    required_proof, requested_disposition: ALLOW | ALERT | REJECT,
    finding?, responses[], budgets
  }
  | POST_EFFECT_RESULT {
      rule_id, provider, provider_accounts, principal_or_lease_selectors,
      operations, resources, authoritative_results,
      required_proof, requested_disposition: ALLOW | ALERT,
      finding?, responses[], budgets
    }
```

A completed provider result can alert or propose response. It cannot reject an
operation that already happened. A synchronous authorization interface that
the existing provider already exposes may reject before the operation when
configured. Mithril does not add that interface to the provider. Free-form
provider verbs are invalid; the adapter's signed vocabulary owns numeric
operation and resource IDs.

```text
CorrelationPackageBindingV1 {
  binding_id: PolicyLocalIdV1
  package_id: PackageIdV1
  package_version: nonzero u32
  required_source_ids[1..64]: PolicyLocalIdV1
  parameter_digest: DigestV1
  finding: FindingSpecV1
}

FindingSpecV1 {
  reason_code: ReasonCodeIdV1
  severity: INFO | LOW | MEDIUM | HIGH | CRITICAL
  route_ids[0..32]: PolicyLocalIdV1
  evidence_level: MINIMAL | STANDARD | FORENSIC
  title_template_id?: PolicyLocalIdV1
}

SignedCorrelationPackageRegistryV1 {
  registry_version: nonzero u64
  packages[] {
    package_id: PackageIdV1
    package_version: nonzero u32
    implementation_digest, parameter_schema_digest: DigestV1
    required_source_schema_ids[1..64]: PolicyLocalIdV1
  }
  canonical_payload_digest: DigestV1
  signer_key_id
  signature
}
```

Package code and parameter schema are immutable inputs to deterministic replay.
A finding title is display only; reason code, subjects, proof, coverage, and
package version own machine behavior.

#### A.11.4 One disposition rule and legal stages

```text
DetectionDispositionRuleV1 {
  schema_version: exactly 1
  rule_id: PolicyLocalIdV1
  enabled: bool
  priority: i32                 // display order only
  evaluation_stage: ENTRY_ADMISSION | NATIVE_TRANSITION |
                    LOCAL_PRE_EFFECT | REMOTE_PRE_ADMISSION | POST_EFFECT
  match: EntryAdmissionMatchV1 | NativeTransitionMatchV1 |
         LocalEffectMatchV1 | RemoteAdmissionMatchV1 | PostEffectMatchV1
  requested_disposition: ALLOW | ALERT | DENY | REJECT
  errno?: EACCES | EPERM | EAGAIN | ECONNREFUSED
  finding?: FindingSpecV1
  response_binding_ids[]
  fallback_by_condition[]: FallbackV1
  budgets: BudgetSetV1
  overrides_rule_ids[]
  exception_ids[]
  valid_from_utc_ns?: i64
  valid_until_utc_ns?: i64
}
```

| Stage | Legal physical dispositions |
| --- | --- |
| `ENTRY_ADMISSION` | allow, alert-admit, reject |
| `NATIVE_TRANSITION` | allow, alert-allow, deny with errno |
| `LOCAL_PRE_EFFECT` | allow, alert-allow, deny with errno |
| `REMOTE_PRE_ADMISSION` | allow-forward, alert-forward, reject |
| `POST_EFFECT` | record or alert; never retrospective deny/reject |

```text
BudgetSetV1 {
  rate_limits:exactly []
  concurrency_limits:exactly []
  maximum_lifetime:absent
  automatic_response_limit:absent
}
```

`BudgetSetV1` is empty in the approved Version 1 phases. Rate, concurrency,
lifetime, and automatic-response budgets remain unallocated until they have
exact counter keys, clocks, restart behavior, release tombstones, and expiry
actions. A nonempty draft returns `CFG_BUDGET_EXECUTION_UNALLOCATED`; it never
becomes an approximate limit.

Default posture is closed:

```text
DefaultPosturesV1 {
  missing_task_identity: DefaultPostureActionV1
  required_classifier_unknown: DefaultPostureActionV1
  unresolved_or_external_root: DefaultPostureActionV1
}

DefaultPostureActionV1 {
  requested_disposition: ALERT | DENY | REJECT
  finding: FindingSpecV1
  unknown_restricted_role_id?: PolicyLocalIdV1
}
```

An alert for missing identity/classification is legal only when an already
installed unknown-restricted role or exact safe floor prevents accidental
authority. An alert is not a hidden allow.

##### A.11.4.1 Exact match inputs

The rule above refers to five match types. Their fields are closed here so an
implementation cannot silently use process names, timestamps, or unspecified
metadata.

**Example.** A rule for “the converter reads the projected token” matches a
committed converter process, `LOCAL_PRE_EFFECT`, `FILE`, `OPEN_READ`, and the
exact projected-token object class. It does not match every Python process or
every file named `token`.

```text
CommonSubjectMatchV1 {
  workload_selector_ids[0..32]: PolicyLocalIdV1
  protected_scope_ids[0..32]: Id128
  execution_set_ids[0..32]: Id128
  entry_kind_ids[0..16]: EntryKindV1
  role_ids[0..32]: PolicyLocalIdV1
  required_process_state_ids[0..32]: PolicyLocalIdV1
  forbidden_process_state_ids[0..32]: PolicyLocalIdV1
}

EntryAdmissionMatchV1 {
  kind: exactly ENTRY_ADMISSION
  subject: CommonSubjectMatchV1
  runtime_operations[1..16]
  root_classifications[1..4]: EXACT_INITIAL |
    CONSERVATIVE_EXTERNAL_UNKNOWN | QUALIFIED_REGISTERED_PURPOSE |
    UNRESOLVED_PROTECTED
  source_proof_qualities[0..8]: ProofQualityV1
  required_purpose_source_capability_ids[0..8]: Id128
  immutable_definition_digests[0..64]: DigestV1
}

NativeTransitionMatchV1 {
  kind: exactly NATIVE_TRANSITION
  subject: CommonSubjectMatchV1
  operations[1..4]: FORK | THREAD_CREATE | EXEC | PRIVILEGE_TRANSITION
  executable_object_ids[0..256]: nonzero u64
  source_role_ids[0..32], target_role_ids[0..32]: PolicyLocalIdV1
}

LocalEffectMatchV1 {
  kind: exactly LOCAL_PRE_EFFECT
  subject: CommonSubjectMatchV1
  effect_families[1..8]: EXEC | FILE | NETWORK | DEVICE |
                         PRIVILEGE | IPC | MOUNT
  operation_ids[1..256]: RegistrySymbolV1
  object: LocalObjectSelectorV1
  binding_lifecycle_states[0..5]
  required_proof: ProofQualityPredicateV1
}

LocalObjectSelectorV1 =
  EXACT_OBJECT_KEYS { exact_object_key_ids[1..256]: nonzero u64 }
  | OBJECT_CLASSES { object_class_ids[1..256]: ObjectClassIdV1 }
  | DESTINATIONS { destination_policy_ids[1..64]: PolicyLocalIdV1 }
  | DEVICES { device_class_ids[1..64]: PolicyLocalIdV1,
              ioctl_command_ids[0..256]: u32 }
  | SECURITY_OBJECTS { security_object_ids[1..64]: PolicyLocalIdV1,
                       target_selector_ids[0..64]: PolicyLocalIdV1 }

RemoteAdmissionMatchV1 {
  kind: exactly REMOTE_PRE_ADMISSION
  subject: CommonSubjectMatchV1
  gate_capability_ids[1..32]: PolicyLocalIdV1
  providers[1..16]: ProviderV1
  provider_account_ids[0..64]: bounded bytes
  operation_ids[1..256]: u32
  resources[0..256]: ResourceSelectorV1
  required_lease_permission_ids[0..256]: u32
  required_proof: ProofQualityPredicateV1
}

PostEffectMatchV1 =
  LOCAL_COMPLETION {
    subject: CommonSubjectMatchV1,
    effect_families[1..8], operation_ids[1..256],
    authoritative_results[1..8], required_proof
  }
  | PROVIDER_RESULT {
      providers[1..16], provider_account_ids[0..64],
      operation_ids[1..256], resources[0..256],
      authoritative_results[1..8], required_proof
    }
  | CORRELATION_FINDING {
      package_ids[1..64], reason_codes[0..64], finding_states[1..6],
      required_proof
    }
```

`ProofQualityPredicateV1` supplies a minimum or exact accepted set on all six
proof axes from A.15.2: source authority, local subject binding, remote subject
binding, operation result authority, temporal coverage, and integrity. An
omitted axis accepts the whole finite signed axis. An unknown enum never
passes.

```text
ProofQualityPredicateV1 {
  source_authority[]:values from ProofQualityV1.source_authority
  local_subject_binding[]:values from ProofQualityV1.local_subject_binding
  remote_subject_binding[]:values from ProofQualityV1.remote_subject_binding
  operation_result_authority[]:
    values from ProofQualityV1.operation_result_authority
  temporal_coverage[]:COMPLETE | GAPPED | UNKNOWN
  integrity[]:SIGNED | AUTHENTICATED_CHANNEL | LOCAL_ATTESTED | UNVERIFIED
}
```

Fallback is also explicit:

```text
FallbackV1 {
  condition: SOURCE_GAPPED | CLASSIFIER_UNKNOWN | INTENT_MISSING |
             INTENT_AMBIGUOUS | PROOF_BELOW_REQUIRED | MAP_CAPACITY |
             ADAPTER_UNAVAILABLE | RESPONSE_UNVERIFIED
  requested_disposition: ALERT | DENY | REJECT
  errno?: EACCES | EPERM | EAGAIN | ECONNREFUSED
  finding: FindingSpecV1
  unknown_restricted_role_id?: PolicyLocalIdV1
}
```

The compiler rejects a fallback that is impossible at its stage—for example,
`REJECT` after an operation completed—or one that asks to alert-and-continue
without a preinstalled safe floor. Tests build one positive and one near-miss
vector for every field: wrong Pod UID, wrong role, wrong operation, same path
but wrong object generation, contextual instead of exact proof, and provider
result arriving after the pre-admission deadline.

#### A.11.5 Exact conflict and expansion rule

The compiler expands every wildcard against the finite signed universe. An
omitted optional selector dimension means the whole finite dimension. A
present empty required selector is an error; it never means `*`.

```text
NormalizedDecisionCellV1 {
  cell_id: PolicyLocalIdV1
  exact_compiled_key
  physical_result
  complete_transition_descriptor?
  finding_specs[]
  response_binding_ids[]
  budget_semantics
  source_rule_ids[]
}
```

Two cells merge only when the physical result, errno, complete transition,
findings, responses, and budget semantics are identical. Different results
need an explicit signed override or exception naming the exact replaced rule
and authority delta. Otherwise compilation fails. Priority, YAML order,
wildcard count, severity, “more specific,” and “deny wins” never select
authority.

Each operation becomes its own compiled key. `OPEN_READ` and later `READ` are
not one bit of authority. A file-open capability cannot satisfy a claim that
passed or inherited descriptors are controlled at use time.

##### A.11.5.1 Exceptions, notifications, responses, coverage, and rollout

An exception is a signed bounded authority change, not a free-form annotation:

```text
ExceptionV1 {
  exception_id: PolicyLocalIdV1
  changed_rule_ids[1..64]: PolicyLocalIdV1
  exact_subject: ExactExceptionSubjectSelectorV1
  authority_delta: PermittedAuthorityDeltaV1
  approver_principal_id: Id128
  approval_proof_digest: DigestV1
  closed_reason_code: u32
  valid_from_utc_ns, valid_until_utc_ns: i64
  maximum_uses: nonzero u32
  maximum_lifetime_ns: nonzero u64
}

ExactExceptionSubjectSelectorV1 {
  protected_scope_ids[1..64]: Id128
  execution_set_ids[0..256]: Id128
  entry_kind_ids[0..16]: EntryKindV1
  role_ids[0..64]: PolicyLocalIdV1
  immutable_definition_digests[0..64]: DigestV1
  exact_compiled_key_digests[1..256]: DigestV1
}

PermittedAuthorityDeltaV1 {
  from_physical_result
  to_physical_result
  added_or_removed_operation_cells[]: DigestV1
  added_or_removed_transition_cells[]: DigestV1
  maximum_blast_radius: BlastRadiusLimitV1
}
```

Wildcards, no expiry, missing approver, unlimited use, and hard-invariant
changes reject. The compiler shows the exact broadened/narrowed cells in the
activation explanation and claim exclusions.

```text
NotificationRouteV1 {
  route_id: PolicyLocalIdV1
  sink: PAGER | CHAT | EMAIL | SIEM | WEBHOOK | TICKET
  sink_binding_id: PolicyLocalIdV1
  minimum_severity: INFO | LOW | MEDIUM | HIGH | CRITICAL
  grouping_fields[1..16]: FindingGroupingFieldV1
  dedupe_window: duration
  allowed_evidence_fields[1..64]: EvidenceFieldV1
  maximum_sensitivity: PUBLIC | INTERNAL | SENSITIVE_IDENTIFIER
  delivery_failure_action: RECORD_ROUTE_FAILURE | ALERT_LOCAL_ONLY
}

ProvisionedNotificationSinkBindingV1 {
  sink_binding_id: PolicyLocalIdV1
  sink_kind
  endpoint_or_tenant_digest: DigestV1
  protected_credential_handle_id: Id128
  delivery_capability_id: PolicyLocalIdV1
  allowed_maximum_sensitivity
  health_record_id: Id128
  config_generation: u64
  canonical_payload_digest: DigestV1
  signer_key_id
  signature
}
```

Secret fields are never routable. Route delivery failure cannot change a deny,
finding revision, or response authorization.

```text
ResponseBindingV1 {
  binding_id: PolicyLocalIdV1
  action_spec: ResponseActionSpecV1
  approval: AUTOMATIC | PREAPPROVED | HUMAN
  required_proof: ProofQualityPredicateV1
  maximum_blast_radius: BlastRadiusLimitV1
  target_revalidation: TargetRevalidationV1
  physical_postcondition: PhysicalPostconditionV1
  watch_interval: duration
}

ResponseActionSpecV1 =
  LOCAL { RESTRICT_LINEAGE | FENCE_SOCKETS | FREEZE_CGROUP }
  | KUBERNETES { REJECT_REPLACEMENT, admission_capability_id }
  | CREDENTIAL { REVOKE_CREDENTIAL, provider, credential_kind,
                 actuator_capability_id, typed_request_schema_digest }
  | MESH { DISABLE_MESH_DEVICE, provider, actuator_capability_id,
           typed_request_schema_digest }
  | ARTIFACT { QUARANTINE_ARTIFACT, store_capability_id,
               typed_request_schema_digest }
  | SOURCE_CONTROL { SUSPEND_INSTALLATION, provider,
                     actuator_capability_id, typed_request_schema_digest }
  | PROVIDER_SPECIFIC { provider, canonical_action_id,
                        actuator_capability_id, typed_request_schema_digest }
```

The compiler uses a closed compatibility table between action, target
revalidation, postcondition, proof, and blast-radius variant. A GitHub audit
fingerprint cannot select a possessed-token revoke action; a process target
cannot use a Kubernetes-object postcondition.

```text
SourceCoverageHealthRuleV1 {
  health_rule_id: PolicyLocalIdV1
  required_source_id: PolicyLocalIdV1
  protected_scope_ids[1..64]: Id128
  maximum_gap: duration
  on_gap: ALERT | REJECT_NEW_ADMISSION | INSTALL_INDEPENDENT_FENCE
  finding: FindingSpecV1
  independent_admission_interface_binding_id?: PolicyLocalIdV1
  independent_admission_capability_id?: PolicyLocalIdV1
  independent_response_binding_ids[]: PolicyLocalIdV1
}
```

The fallback must be independent from the missing source. Loss of Kubernetes
audit may cause a separately healthy configured Kubernetes admission or stock
runtime hook to reject new privileged roots. It cannot reconstruct the missing
audit event. The compiler rejects an
“independent” response whose actuator or verification source depends on the
failed feed.

```text
RolloutV1 {
  rollout_generation: nonzero u64
  desired_profile_mode: OBSERVE | PROTECT
  cohort_selection: ALL_BOUND_EXECUTION_SETS |
                    EXPLICIT_EXECUTION_SETS |
                    HASHED_EXECUTION_SET_BINDING
  explicit_execution_set_ids[]: Id128
  selector_hash_modulus: nonzero u32
  selected_bucket_ids[]: sorted unique u32 < modulus
}
```

The rollout population is immutable for one generation. Health metrics name
their exact numerator and denominator population. Selector drift cannot
silently change authority or make a failed cohort look healthy.

#### A.11.6 Signed profile and rollback wire

```text
ProfileSignatureHeaderV1 = {
  0: 1,
  1: Id128 issuer_id,
  2: nonzero u64 sequence_epoch,
  3: nonzero u64 issuer_sequence,
  4: Id128 trust_domain_id,
  5: Id128 profile_id,
  6: nonzero u64 profile_version,
  7: i64 valid_from_utc_ns,
  8?: i64 valid_until_utc_ns,
  9?: Id128 rollback_authorization_id,
  10: DigestV1 policy_document_digest,
  11: DigestV1 provider_numeric_registry_bundle_digest,
  12: DigestV1 required_capability_schema_digest,
  13: DigestV1 source_selector_registry_digest,
  14: DigestV1 object_classifier_registry_digest,
  15: DigestV1 reason_code_registry_digest,
  16: DigestV1 correlation_package_registry_digest,
  17: DigestV1 provider_vocabulary_registry_digest
}

SignedWorkloadProtectionProfileV1 = {
  0: 1,
  1: bstr(1..128) key_id,
  2: 1,                       // Ed25519
  3: bstr(1..4096) canonical header,
  4: bstr(1..1048576) canonical PolicyDocumentV1,
  5: bstr(64) signature
}

profile_signature_input =
  ASCII("MITHRIL-PROFILE-V1") || 0x00 ||
  SHA-256(canonical_header) || SHA-256(canonical_policy)

RollbackAuthorizationPayloadV1 = {
  0: 1,
  1: Id128 authorization_id,
  2: Id128 trust_domain_id,
  3: Id128 issuer_id,
  4: Id128 approver_principal_id,
  5: nonzero u64 sequence_epoch,
  6: nonzero u64 issuer_sequence,
  7: Id128 profile_id,
  8: DigestV1 current_digest,
  9: nonzero u64 current_version,
  10: DigestV1 exact_older_target_digest,
  11: nonzero u64 exact_older_target_version,
  12: u32 closed_reason_code,
  13?: DigestV1 human_reason_artifact_digest,
  14: DigestV1 exact_platform_scope_digest,
  15: i64 issued_at_utc_ns,
  16: i64 expires_at_utc_ns
}
```

Rollback uses its own Ed25519 envelope and domain separator
`MITHRIL-ROLLBACK-V1`. It is one-use and must name the exact current digest,
exact older target, platform, approver, and expiry. Re-signing an older version
is not rollback authority.

The activation owner durably records the greatest accepted issuer sequence and
profile version before publishing a generation. Lower signed values reject
unless the exact rollback authorization is valid and unused.

#### A.11.7 Build, read back, probe, activate, and retire

```text
parse and validate closed source
verify signature, registries, validity, replay, and anti-rollback
resolve selectors into immutable workload/object snapshots
validate the role/transition graph and required capabilities
expand every exact decision cell and reject conflicts/capacity overflow
simulate against a recorded legitimate-workload baseline
obtain human approval
build a completely inactive generation
read back every descriptor, row, default, membership, and digest
run isolated allow and deny probes
publish one active-generation handle for new admissions
```

Expansion happens in two immutable stages:

```text
StaticExpandedProfileV1 {
  profile_id:Id128
  profile_version:u64
  source_policy_digest:DigestV1
  statically_expanded_workload_selector_ids[]:PolicyLocalIdV1
  statically_expanded_protected_scope_ids[]:Id128
  statically_expanded_role_ids[]:PolicyLocalIdV1
  statically_expanded_entry_kind_ids[]:EntryKindV1
  statically_expanded_object_class_ids[]:ObjectClassIdV1
  statically_expanded_provider_account_ids[]:bounded bytes
  unresolved_binding_selectors[]     // only live scope/execution-set selectors
  compiled_rule_cell_digests[]:DigestV1
  rollout:RolloutV1
}

NodeBoundProfileGenerationV1 {
  static_profile_digest:DigestV1
  signed_workload_binding_generation:DigestV1
  node_boot_id:Id128
  label_epoch:u64
  exact_protected_scope_ids[], exact_execution_set_ids[]:Id128
  exact_rollout_membership[]
  exact_compiled_kernel_cell_digests[]:DigestV1
  node_binding_digest:DigestV1
  state:PREPARING | READ_BACK | ACTIVE | REJECTED
}
```

The static compiler expands only against the signed finite universe. Live Pod
and execution-set IDs may not exist yet, so the node binder resolves only
those selectors against one signed workload-binding generation. A later Pod
creates a new node-bound generation; it never edits the active key set in
place. Hashed rollout uses the exact profile ID/version, rollout generation,
execution-set ID, and workload-binding digest. Tests publish two otherwise
identical Pods with different UIDs and prove that one Pod's node-bound rows
cannot authorize the other.

Existing tasks, sockets, files, mappings, domains, pending entries, and
responses retain typed references to their old immutable generation. New roots
use the active generation. Version 1 does not migrate live processes. A
retiring generation is deleted only after every typed reference is zero,
iterator/WAL reconciliation agrees, and the BPF grace period passes.

#### A.11.8 Required goldens and stable failures

`CFG-V1-GOLDEN-002` must be generated from one complete checked-in source after
the final schema exists. It includes restricted YAML, deterministic policy
CBOR, every registry payload/digest, header, signature, envelope, compiler
cells, and round trip. Prose substitutions and the retained stale
`CFG-V1-GOLDEN-001` bytes are not conformance data.

`CFG-ROLLBACK-GOLDEN-002` covers exact current-to-older success and wrong
current, wrong target, wrong platform, expired, replayed, and signed-without-
authorization failures.

Stable parser/compiler failures include duplicate key, unknown field, forbidden
YAML feature, unknown enum, missing required field, stage/disposition mismatch,
circular admission dependency, unsupported source/capability, exact-key
conflict, invalid exception, forbidden notification field, unsafe alert default,
unallocated budget, and map-capacity overflow. Every failure asserts that no
generation, entry slot, response binding, or partial map becomes active.

Mithril must never call the design-level YAML in Chapter 11 a valid wire file,
interpret an empty selector as wildcard, combine several operations into one
authority key, activate a partial map, let a finding decide the entry that must
exist before the finding, or claim rollback from a signature alone.

### A.12 Exact Kernel Decision ABI And Lookup

Chapter 13 explains the one local decision. This section fixes the map keys,
value meanings, lookup order, and failure behavior.

**Example.** Python opens the projected token. The role's base table denies it.
Even if the base table allowed it, an authority-domain restriction, active
response, terminating binding, stale object generation, or earlier LSM denial
could still deny. None of those negative layers can grant a base permission.

#### A.12.1 Non-reused handles and retained state

Every node-local handle is a nonzero `u64`, allocated monotonically within
`(node_boot_id, label_epoch)` and never reused. Losing the allocator epoch while
protected holders survive is fatal; the node does not wrap.

```text
ProfileGenerationRefV1 {
  profile_generation_ref_id: nonzero u64
  node_boot_id: Id128
  label_epoch: u64
  profile_id: Id128
  owner_generation: nonzero u64
  compiled_artifact_digest_id: nonzero u64
  state: PREPARING | ACTIVE | RETIRING
}

SetKindV1 = RESTRICTION | RESPONSE | RETAINED_GENERATION

SetRefV1 {
  set_lock: bpf_spin_lock
  set_ref_id: nonzero u64
  node_boot_id: Id128
  label_epoch: u64
  set_kind: SetKindV1
  owner_set_epoch: u64
  artifact_digest_id: nonzero u64
  refs_by_class[SetReferenceClassV1]: u64
  state: PREPARING | ACTIVE | RETIRING
  transition_version: u64
}
```

`ACTIVE` accepts existing and new holders. `RETIRING` serves only already
proved holders; it creates no new reference. `PREPARING`, missing, unknown, or
wrong-epoch state denies. Deletion needs zero counters, no owned tombstone,
complete iterator/WAL reconciliation, and a grace period.

Every labeled task and socket also pins where it is allowed to live:

```text
TaskPlacementExpectationV1 {
  protected_root_binding_id: Id128
  protected_root_binding_nonce: Id128
  allowed_descendant_policy_id: u32
}
```

The hook resolves the current live protected cgroup root, then requires its
`BPF_MAP_TYPE_CGRP_STORAGE` value to match this binding and nonce. A task moved
to another cgroup, a cgroup recreated at the same path, a stale descendant
index, or a socket left after binding tombstone cannot inherit the old allow.
The fallback identity is `(node_boot_id, full_u64_cgroup_id, live_interval)`;
a path or bare cgroup number is never enough.

Generation ownership is typed rather than one unexplainable object counter:

```text
BindingGenerationStateV1 {
  active_profile_generation_ref_id: u64
  retained[] {
    profile_generation_ref_id: u64
    task_refs, socket_refs, file_and_shared_object_refs: u64
    authority_domain_refs, derived_kernel_capability_refs: u64
    vma_and_publication_refs, checkpoint_restore_refs: u64
    pending_entry_and_exec_refs, response_plan_refs: u64
    state: ACTIVE | RETIRING
  }
}

GenerationReferenceClassV1 = TASK | SOCKET | FILE_OR_SHARED_OBJECT |
  AUTHORITY_DOMAIN | DERIVED_KERNEL_CAPABILITY | VMA_OR_PUBLICATION |
  CHECKPOINT_RESTORE | PENDING_ENTRY_OR_EXEC | RESPONSE_PLAN

GenerationReferenceTombstoneV1 {
  reference_owner_id: Id128
  reference_owner_generation: u64
  profile_generation_ref_id: u64
  reference_class: GenerationReferenceClassV1
  owned: bool
  acquisition_transition_version: u64
  release_transition_version?: u64
}
```

An owner acquires its typed reference before publication or use and releases
it once through `owned=true -> false`. Retirement requires every class counter
to be zero, no owned tombstone in the complete iterator/WAL reconciliation,
and the grace period. Existing processes do not migrate in Version 1: a new
root takes the active generation; an old root, its forks and execs keep the
generation they already own.

#### A.12.2 Binding and composite object identity

```text
ExecutionSetBindingStateV1 {
  binding_lock: bpf_spin_lock
  binding_id, binding_nonce, node_boot_id, execution_set_id,
    protected_scope_id, profile_id: Id128
  label_epoch: u64
  active_profile_generation_ref_id: u64
  root_cgroup_id: u64
  root_cgroup_live_interval_id: Id128
  mount_view_generation_id: Id128
  network_namespace_generation_id: Id128
  lifecycle_state: PREPARING | ACTIVE | DRAINING | TERMINATING | TOMBSTONED
  lifecycle_generation: u64
  mode: OBSERVE | PROTECT
  transition_version: u64
}

BindingRetainedGenerationKeyV1 {
  binding_id: Id128
  profile_generation_ref_id: u64
}

BindingRetainedGenerationValueV1 {
  binding_nonce: Id128
  lifecycle_generation: u64
  membership_state: ACTIVE | RETIRING
}

ClassifierAxisValueV1 { axis_id: u16, value_id: u32 }

CompositeDecisionAtomV1 {
  atom_id: nonzero u64
  effect_family: u16
  sorted_unique_axis_values[1..MAX_CLASSIFIER_AXES]
  canonical_axis_digest_id: nonzero u64
}
```

The token example is one composite atom such as credential=service-account,
backing=projected-volume, mutability=provider-rotated, and persistence=Pod-
lifetime. Selecting only “file” or only “token” is invalid. Missing/duplicate/
unknown required axes deny.

#### A.12.3 Base, restriction, response, and default keys

```text
EffectDecisionKeyV1 {
  profile_generation_ref_id: u64
  active_role_id: u32
  entry_kind: u16
  effect_family: u16
  operation: u16
  composite_atom_id: u64
  exact_object_key_id: nonzero u64
  process_state_vector_id: u32
  binding_lifecycle_state: u8
}

EffectDefaultKeyV1 {
  profile_generation_ref_id: u64
  active_role_id: u32
  entry_kind: u16
  effect_family: u16
  operation: u16
  composite_atom_id: u64
  process_state_vector_id: u32
  binding_lifecycle_state: u8
}

PhysicalDecisionV1 {
  decision: ALLOW | AUDIT_ALLOW | DENY
  errno: i16
  evidence_class_id: u32
  transition_id: u32              // zero means no state change
}

RestrictionDecisionKeyV1 {
  restriction_set_ref_id, profile_generation_ref_id: u64
  effect_family, operation: u16
  composite_atom_id, exact_object_key_id: u64
}

RestrictionDefaultKeyV1 {
  restriction_set_ref_id, profile_generation_ref_id: u64
  effect_family, operation: u16
  composite_atom_id: u64
}

RestrictionDecisionV1 {
  result: NO_ADDITIONAL_RESTRICTION | DENY
  errno: i16
  restriction_reason_bits: u64
}

ResponseDecisionKeyV1 {
  response_set_ref_id, profile_generation_ref_id: u64
  effect_family, operation: u16
  composite_atom_id, exact_object_key_id: u64
}

ResponseDefaultKeyV1 {
  response_set_ref_id, profile_generation_ref_id: u64
  effect_family, operation: u16
  composite_atom_id: u64
}

ResponseDecisionV1 {
  result: NO_ADDITIONAL_RESTRICTION | AUDIT_ALLOW | DENY
  errno: i16
  response_plan_set_digest_id: u64
}
```

Every negative set and retained-generation set has an active descriptor. A
table row without its descriptor has no meaning.

```text
RestrictionSetDescriptorV1 {
  restriction_set_ref_id, set_epoch, covered_generation_set_ref_id: u64
  row_count: u32
  table_digest_id, declared_default_digest_id: u64
  state: PREPARING | ACTIVE | RETIRING
}

ResponseSetDescriptorV1 {
  response_set_ref_id, set_epoch, covered_generation_set_ref_id: u64
  row_count: u32
  table_digest_id, declared_default_digest_id: u64
  response_plan_set_digest_id: u64
  state: PREPARING | ACTIVE | RETIRING
}

GenerationSetDescriptorV1 {
  retained_generation_set_ref_id: u64
  membership_count: u32
  membership_digest_id: u64
  state: PREPARING | ACTIVE | RETIRING
}

GenerationMembershipKeyV1 {
  retained_generation_set_ref_id, profile_generation_ref_id: u64
}

GenerationMembershipValueV1 {
  state: ACTIVE | RETIRING
  generation_artifact_digest_id: u64
}
```

Rust populates descriptor, membership, rows, and defaults under `PREPARING`,
reads back their counts and digests, then activates them. The BPF hook checks
identity, epoch, state, and exact generation membership; it does not calculate
a digest in the hot path. Missing descriptor or membership denies even if a
stale row remains in a map.

Activation installs exactly one default for every reachable non-exact key.
Missing exact rows may use only that fully initialized default. Missing
default, descriptor, atom, or generation membership denies. Zero never means
an object wildcard.

#### A.12.4 Exact lifetime floors

Static policy cannot enumerate future sockets, pipes, accepted connections,
created files, or received descriptors. The compiler emits either an explicit
neutral floor or a required dynamic template for each reachable cell.

```text
FloorRequirementKeyV1 {
  profile_generation_ref_id: u64
  active_role_id: u32
  entry_kind, effect_family, operation: u16
  composite_atom_id: u64
  process_state_vector_id: u32
  binding_lifecycle_state: u8
}

DynamicFloorTemplateV1 {
  template_id, profile_generation_ref_id: u64
  owner_lifetime_kind: SOCKET | CHANNEL | FILE | VMA | DERIVED_CAPABILITY |
                       PENDING_EXEC | BINDING
  required_provenance_bits, required_reference_classes: u64
  initial_floor: RestrictionFloorV1
  permitted_narrowing_transition_ids[]: u32
  artifact_digest_id: u64
  state: PREPARING | ACTIVE | RETIRING
}

RestrictionFloorV1 {
  result: NO_ADDITIONAL_RESTRICTION | DENY
  errno: i16
  reason_bits: u64
}

FloorRequirementValueV1 =
  EXPLICIT_NEUTRAL
  | DYNAMIC_REQUIRED {
      template_id: u64,
      required_provenance_bits: u64,
      required_reference_classes: u64
    }

DynamicFloorStateV1 {
  exact_lifetime_identity_digest: DigestV1
  source_template_id, source_profile_generation_ref_id: u64
  restriction_set_ref_id?: u64
  generation_reference_owned, set_reference_owned: bool
  floor: RestrictionFloorV1
  state: PREPARING | ACTIVE | TOMBSTONED | RECONCILIATION_REQUIRED
  transition_version: u64
}

ExactObjectFloorKeyV1 {
  exact_object_key_id, exact_object_generation: u64
  effect_family, operation: u16
}

ExactSocketOrChannelFloorKeyV1 {
  exact_socket_or_channel_key_id, exact_socket_or_channel_generation: u64
  current_actor_authority_domain_id: Id128
  effect_family, operation: u16
}

BindingLifetimeFloorKeyV1 {
  binding_id, binding_nonce: Id128
  lifecycle_state: u8
  effect_family, operation: u16
}
```

Creation/acquisition installs and reads back a dynamic floor before the object
or channel becomes usable. First use before `ACTIVE`, capacity N+1, object
reuse, missing provenance, or an unclassified received fd denies.

#### A.12.5 Atomic transitions

```text
TransitionDescriptorV1 {
  transition_id: u32
  node_boot_id: Id128
  label_epoch: u64
  transition_kind: NONE | PROCESS_ONLY | DOMAIN_SENSITIVE_ONLY
  profile_generation_ref_id: u64
  transition_artifact_digest_id: u64
  state: PREPARING | ACTIVE | RETIRING
}

ProcessTransitionKeyV1 {
  profile_generation_ref_id: u64
  transition_id, current_role_id, current_process_state_vector_id: u32
  current_process_response_set_ref_id: u64
}

ProcessTransitionValueV1 {
  next_role_id, next_process_state_vector_id: u32
  next_process_response_set_ref_id: u64
}

DomainSensitiveTransitionKeyV1 {
  profile_generation_ref_id: u64
  transition_id: u32
  current_potential_sensitive_bits, current_observed_sensitive_bits: u64
  current_restriction_set_ref_id, current_domain_response_set_ref_id: u64
}

DomainSensitiveTransitionValueV1 {
  next_potential_sensitive_bits, next_observed_sensitive_bits: u64
  next_restriction_set_ref_id, next_domain_response_set_ref_id: u64
}
```

BPF resolves the descriptor and prospective row before locking the owning
state. Under the one lock it rechecks the complete old tuple/version and writes
the complete next tuple. Version 1 rejects a rule that requires one syscall to
atomically mutate both process and domain map values. A publication-sensitive
read uses the domain transition as its authority.

#### A.12.6 Canonical lookup order

```text
1. If an earlier stacked LSM result is nonzero, preserve it and return it.
2. Read TaskLabelV1. If absent, completely resolve protected placement:
   proved outside -> explicit host policy;
   protected or unknown -> deny missing protected identity.
3. Validate expected live cgroup object, binding ID, nonce, live interval,
   descendant rule, lifecycle generation, and current placement.
4. Copy process, authority domain, entry, and binding tuples under their own
   locks. Never nest locks. Revalidate each version; retry one complete snapshot
   once, then deny on continuing contention.
5. Require committed/open entry, active process, compatible epochs, exact
   identity links, retained profile generation, binding membership, and domain
   generation membership.
6. Classify every required object axis and exact live object/channel generation.
7. Load exact base row or its exact default.
8. Load domain restriction, process response, and domain response rows/defaults.
9. Load required exact object, socket/channel, pending-exec, and binding floors.
10. Validate every SetRef kind, epoch, state, and existing-holder reference.
11. Intersect all results. Any deny wins; otherwise any audit requirement gives
    AUDIT_ALLOW; otherwise ALLOW.
12. Commit the one declared monotonic transition before returning allow.
13. Fix the physical return value, then best-effort emit bounded evidence.
```

An absent negative row is neutral only after its active descriptor and explicit
default have been found. Negative restriction/response sets can narrow a base
allow but cannot turn a base deny into allow.

In `OBSERVE`, only a row explicitly marked as a simulatable policy denial may
return allow plus `WOULD_DENY`. Earlier LSM denial, missing identity, stale
binding, corrupt state, terminating lifetime floor, and installed emergency
response remain hard denies in every mode.

Decision caching is disabled in Version 1. No task/process/domain value may
store a cached final allow. A loaded authority cache or nonzero cache ID makes
strict activation fail as `DECISION_CACHE_UNQUALIFIED`.

#### A.12.7 Golden and hostile cases

`DECISION-SET-GOLDEN-001` must compare Rust and BPF bytes, field offsets, enum
values, default rows, map key construction, lookup trace, transition result,
and physical errno. It includes two profiles whose owner generation is both
42 but whose node refs differ, a multi-axis projected-token atom, both process
and domain response sets, active/retiring holders, and exact object/channel
floors.

Hostile cases remove or corrupt each lookup in turn, exhaust every map at N+1,
move a labeled task, reuse cgroup/object/socket coordinates, retire a still-
referenced generation, race process/domain/binding transitions, lose evidence,
and inject an earlier LSM denial. Every missing authority state denies; event
loss cannot change the already fixed physical result.

Mithril must never use cgroup-first lookup for a labeled task, bare generation
42, digest-only defaults, zero as wildcard, mutable active rows, a cached final
allow, `CLEANUP_ONLY` as a kernel result, or telemetry success as proof of
enforcement.

### A.13 Exact Linux Effect-Surface Contract

Chapters 14-21 explain why Mithril combines several Linux mechanisms. This
section says what “complete coverage” means for each surface.

**Problem.** Blocking `/bin/curl` is not network control: Python can open a
socket directly. Blocking `open("token")` is not file-use control: the process
may inherit an already open descriptor. Blocking a TUN device is not complete
network containment: userspace TCP or an existing socket may remain. A product
claim therefore names an operation and its exact decision point, not a tool
name.

#### A.13.1 Mount topology and file identity

```text
MountViewIdentityV1 {
  node_boot_id:Id128
  mount_namespace_inum:u64
  mount_namespace_binding_nonce:Id128
  mount_namespace_live_interval:Id128
  topology_epoch:u64
}

LiveMountObjectV1 {
  mount_view_identity:MountViewIdentityV1
  unique_mount_id_when_qualified:u64
  legacy_mount_id?:u64
  superblock_and_filesystem_identity:Id128
  mount_live_interval:Id128
}

NetworkNamespaceIdentityV1 {
  node_boot_id:Id128
  netns_cookie:u64
  netns_live_interval:Id128
  capture_mechanism:u32
}

MountNamespaceStateV1 {
  mount_namespace_id: Id128
  node_boot_id: Id128
  namespace_inode: u64
  namespace_generation: u64
  topology_generation: u64
  root_mount_id: u64
  snapshot_digest: DigestV1
  state: CLEAN | DIRTY_RECONCILING | FAIL_CLOSED_UNKNOWN | TOMBSTONED
  live_interval_id: Id128
  transition_version: u64
}

MountSecurityViewV1 {
  mount_namespace_id: Id128
  topology_generation: u64
  task_root_identity: ExactObjectGenerationV1
  visible_mount_snapshot_digest: DigestV1
  propagation_and_peer_group_digest: DigestV1
  read_only_noexec_nosuid_nodev_digest: DigestV1
  state: ACTIVE | STALE | RETIRING
}

FileObjectIdentityV1 {
  mount_namespace_id: Id128
  mount_topology_generation: u64
  mount_id: u64
  filesystem_instance_id: Id128
  inode_number: u64
  inode_generation_or_version: u64
  exact_live_object_id: Id128
  object_kind: REGULAR_FILE | DIRECTORY | SYMLINK | DEVICE |
               PROC_OBJECT | OTHER_QUALIFIED
  backing_object_or_volume_identity: Id128
  live_interval_id: Id128
}

FileInstanceProvenanceV1 {
  file_instance_id: Id128
  exact_file_object: FileObjectIdentityV1
  opener_task_cookie: u64
  opener_process_state_id, opener_authority_domain_id: Id128
  profile_generation_ref_id: u64
  open_flags_and_mode: u64
  source_mount_view_digest: DigestV1
  acquisition_operation
  inherited_or_transferred_from?: Id128
  dynamic_floor_state_id: Id128
  state: PREPARING | ACTIVE | TOMBSTONED | RECONCILIATION_REQUIRED
}
```

Paths are display and policy-authoring inputs. The physical decision uses the
resolved mount, filesystem, object, and generation. Rename and bind aliases do
not change object authority. Inode-number reuse creates a new generation.

Mount, unmount, move, propagation, pivot-root, chroot, automount, overlay copy-
up, and network-filesystem referral synchronously mark the affected namespace
`DIRTY_RECONCILING` before exposing the new topology. Rust builds a new bounded
snapshot, reads it back, then atomically advances the topology generation. A
file decision during a required dirty interval denies or uses an explicitly
compiled safe floor; it never resolves against the old snapshot.

#### A.13.2 File-operation coverage

| Operation family | Exact object that must be known before allow | Required decision/result distinction |
| --- | --- | --- |
| Open/read acquisition | Final resolved object after namespace lookup | attempted open, returned fd, later positive bytes, mmap, and provider use are different results |
| Existing/passed/inherited fd use | `FileInstanceProvenanceV1` plus current actor | current actor policy intersects immutable acquisition floor; opener authority does not transfer |
| Create/mkdir/mknod/symlink | parent directory object, new name bytes, mount generation, proposed object kind | reserve/classify before visibility; attach new-object floor before first use |
| Rename/link | exact source object plus old/new parent objects and names | both sides must be checked; paired hooks cannot lose an earlier LSM denial |
| Unlink/rmdir | exact object and parent/name relation | namespace removal does not erase open/VMA/persistent state |
| chmod/chown/truncate/setattr | exact object, requested attributes, current file provenance | mutation uses a dedicated key; open permission is insufficient |
| read/write/splice/sendfile/copy-file-range | current actor, exact source and sink, offsets/lengths, async request identity | admission and positive completed bytes are recorded separately |
| mmap/mprotect/pkey_mprotect | exact mm, VMA range, backing object, old/new permissions and write/execute history | executable or writable-shared capability exists for VMA lifetime, not syscall lifetime |
| io_uring/AIO | submitting actor/domain, ring generation, registered files/buffers, opcode, later executor/completion | SQPOLL never borrows the kernel thread's role; unsupported opcode/setup denies full claim |

Projected ServiceAccount token rotation must install the new exact object
binding before AtomicWriter publishes the new revision. An asynchronous
userspace inode update after visibility is too late. If the platform cannot
hold publication, the strict role denies the projected mount or reports that
rotation-safe classification is unsupported.

`/proc/<pid>` and `/sys` objects are classified by the resolved target process
or kernel object, not path text. `/proc/self`, `/proc/<pid>/fd`, bind mounts,
hardlinks, symlinks, and namespace aliases cannot turn a protected target into
an ordinary file.

#### A.13.3 Executable images and memory

The executable object is the immutable file/object generation plus ordered
script or `binfmt_misc` chain and ELF loader objects. Basename, `$PATH`, argv,
file extension, and a copied filename are not authority.

The complete executable-memory family includes:

```text
execve and execveat image install
shebang and binfmt interpreter passes
ELF PT_INTERP loader open/map
memfd and deleted executable images
anonymous PROT_EXEC mapping
writable then executable file/VMA transition
mprotect and pkey_mprotect adding execute
executable stack requested by ELF metadata
personality/READ_IMPLIES_EXEC changes
JIT profiles with exact mm/VMA/write-seal discipline
```

```text
MmSnapshotIdentityV1 {
  node_boot_id: Id128
  label_epoch: u64
  mm_cookie: nonzero u64
  mm_generation: u64
  snapshot_version: u64
  expected_sharer_count: u32
}

VmaIteratorSessionV1 {
  session_identity: VmaIteratorSessionIdentityV1
  expected_mm_snapshot: MmSnapshotIdentityV1
  state: PREPARING | BEGUN | RECORDING | ENDED_COMPLETE |
         ENDED_PARTIAL | FAILED
  first_sequence, last_sequence: u64
  expected_records, observed_records, gap_count: u64
  canonical_snapshot_digest?: DigestV1
}
```

An `mm_struct *` pointer is not durable identity. BPF/Rust use a non-reused mm
cookie, generation, live interval, expected sharers, and begin/record/end
iterator protocol. An incomplete snapshot is typed partial and cannot prove
that no executable or writable-shared mapping exists.

In-process Python/Jinja interpretation may create no exec or executable-memory
transition. Mithril controls its next file, socket, device, privilege, or
publication effect and must not report “Python execution denied” when only a
later effect was denied.

#### A.13.4 Network and socket lifetime

```text
NetworkEffectKeyV1 {
  current_process_state_id, current_authority_domain_id: Id128
  current_profile_generation_ref_id: u64
  operation: SOCKET_CREATE | BIND | LISTEN | ACCEPT | CONNECT |
             SEND | RECEIVE | SHUTDOWN | SETSOCKOPT | GETSOCKOPT
  socket_key_id, socket_generation: u64
  network_namespace_generation_id: Id128
  protocol: u16
  final_destination_policy_id: u64
  final_address_and_port_digest: DigestV1
}

SocketProvenanceV1 {
  socket_key_id, socket_generation: u64
  backing_identity: ExactObjectGenerationV1
  creator_task_cookie: u64
  creator_process_state_id, creator_authority_domain_id: Id128
  creator_profile_generation_ref_id: u64
  network_namespace_generation_id: Id128
  bind_connect_accept_history_digest: DigestV1
  current_flow_generation: u64
  dynamic_floor_state_id: Id128
  state: PREPARING | ACTIVE | SHUTTING_DOWN | TOMBSTONED |
         RECONCILIATION_REQUIRED
}
```

Every use intersects current actor/domain policy with immutable socket
provenance and the exact live socket floor. A passed, inherited, accepted, or
preexisting socket does not transfer its creator's positive allow. Shared use
may force a common authority domain or separately authorized whole-socket
fence; the response reports that blast radius.

Coverage is path-specific:

| Path | Required control |
| --- | --- |
| New TCP | final destination after route/rewrite plus connect result and packet floor |
| Established TCP | send/write/sendmsg/splice/sendfile/io_uring path plus packet or flow floor; connect-only is insufficient |
| UDP | per-message `msg_name` final destination, connected and unconnected forms, IPv4 and IPv6 |
| Accept | listener identity plus new accepted-socket generation and peer; floor installed before release |
| Receive | admission and positive bytes/queued-data provenance are separate; already queued data may survive a later peer fence |
| Local channels | loopback, Pod IP, wildcard listener, reuseport, UDP, Unix socket, NAT/hairpin, and BPF redirect are shared channels, not automatically safe |
| Namespace transfer | current network namespace and socket's namespace provenance both remain part of the key |

Destination classification uses the final address after service resolution,
NAT, transparent proxying, cgroup/socket rewrite, and routing. A pre-rewrite
allow cannot authorize a different final endpoint. Missing rewrite or final-
address coverage denies under a full claim.

DNS names are context, not a bypass around destination control. Full DNS
claims separately qualify UDP/TCP framing, every iovec, `msg_name`, malformed
and compressed names, size bounds, multi-question behavior, non-53 resolvers,
literal IP, DoT, and DoH. Unknown/malformed/encrypted DNS follows the IP and
destination floor. Mithril never infers an HTTP, Git, Kubernetes, or cloud verb
from same-destination TLS.

#### A.13.5 Devices and derived kernel authority

```text
DeviceFileEffectKeyV1 {
  current_process_state_id, current_authority_domain_id: Id128
  device_file_instance_id: Id128
  exact_device_generation: u64
  operation: OPEN | READ | WRITE | MMAP | IOCTL | POLL | ASYNC_SUBMIT
  ioctl_command_id?: u32
  argument_shape_id?: u32
}

DerivedKernelCapabilityObjectV1 {
  capability_object_id: Id128
  kind: TUN_TAP | IO_URING | BPF_MAP | BPF_PROGRAM | BPF_LINK |
        PERF_EVENT | KVM_CONTEXT | GPU_CONTEXT | KEYRING |
        PIDFD | NAMESPACE_FD | MOUNT_FD | OTHER_REGISTERED
  exact_backing_object: ExactObjectGenerationV1
  creator_process_state_id, creator_authority_domain_id: Id128
  profile_generation_ref_id: u64
  creation_operation_and_parameters_digest: DigestV1
  dynamic_floor_state_id: Id128
  state: PREPARING | ACTIVE | REVOKING | TOMBSTONED |
         RECONCILIATION_REQUIRED
}
```

Device authority is path-independent: type, major/minor generation, driver
identity where available, operation, ioctl command, argument shape, current
actor, and file provenance. Opening `/dev/net/tun` is only one stage; later
ioctls and derived TUN/network state remain controlled. The same applies to
BPF, perf, io_uring, KVM, GPU, pidfds, keyrings, namespace fds, and mount fds.

#### A.13.6 Privilege, process control, Seccomp, and Landlock

The privilege family includes credential changes, setuid/setgid/capset,
`no_new_privs`, namespace creation/join, mounts and pivot-root, ptrace,
process-vm, pidfd operations, signal/control, BPF, perf, modules, keyrings,
proc/sysctl security objects, io_uring setup, and device-derived authority.
Each needs a named target and operation; a generic “capability event” is not
complete coverage.

```text
SeccompFloorProofV1 {
  proof_id: Id128
  task_or_process_state_id: Id128
  source: MITHRIL_QUALIFIED_NEW_PROCESS_START
  filter_program_digest?: DigestV1
  installed_before_target_user_code: PROVED | NOT_PROVED | NOT_APPLICABLE
  no_new_privs_state: bool
  tsync_requested_and_result
  listener_or_supervisor_identity?: Id128
  listener_policy_digest?: DigestV1
  readback_method_and_result
  permitted_syscall_argument_constraints_digest: DigestV1
  state: VERIFIED | PARTIAL | FAILED | UNKNOWN
}
```

Seccomp filters only become stricter; there is no syscall that removes an
installed filter. For a new process on a qualified start path, Mithril proves
that it installed the required floor before that target's user code and that
all required threads received it. Mithril makes no Seccomp-floor claim when it
did not perform that installation. A user-notification listener cannot widen
authority, and ptrace/supervisor relationships need separate control.
Seccomp can match syscall numbers and scalar arguments. It cannot authenticate
the pathname behind a userspace pointer, so it cannot by itself authorize
`/proc/<target>/mem`.

Landlock is an additional process-installed floor. Its available rights depend
on the running ABI and may include filesystem, network-port, Unix-socket,
signal, and device-ioctl controls. Mithril installs it only for a new process
through a qualified target-context start path. If Mithril did not install it,
Mithril does not make a Landlock-floor claim. Landlock does not replace
dynamic BPF policy, task identity, shared-domain propagation, devices and
privilege outside its ABI, provider semantics, or response.

For a defender's approved memory read, the trusted owner opens the exact target
while held, passes only that read-only target fd and one evidence-sink fd to a
short-lived measured inspector, installs/readbacks a seccomp fd/syscall floor,
and checks the exact case, target, byte budget, deadline, and sink again in BPF
LSM. Memory write, ptrace control, fd extraction, signal, and general network
remain forbidden.

#### A.13.7 Surface qualification

Every advertised operation has:

```text
exact hook/program and signature
whether it can deny before effect
prior-LSM result behavior
actor/object/channel fields available there
creation/acquisition and final-lifetime paths
missing-state and capacity result
completion oracle when completion is claimed
negative control and bypass fixture
platform capability record and unsupported result
```

Mandatory bypass cases include deep/long paths, bind/hardlink/symlink aliases,
projected-token rotation, inherited/passed fd, mmap and preexisting mappings,
`mprotect`, memfd/deleted exec, dynamic loader substitution, every namespace
mutation, IPv4/IPv6, established TCP, per-message UDP, local laundering,
rewrite, DNS framing variants, shared sockets, device fd pass, ioctl families,
io_uring/SQPOLL, ptrace/process-vm/pidfd, BPF/perf/module/keyring, and prior-LSM
denial on each enabled program.

Mithril must never promote a pathname, PID, namespace number, socket owner,
DNS string, device path, event after completion, or one successful hook probe
into a broader physical claim.

### A.14 Exact Shared-Authority And Publication Contract

Chapter 18 explains the race: one process can obtain sensitive authority while
another process publishes through a shared file, mapping, pipe, socket, or
userspace buffer. This section fixes the shared state and transaction.

**Example.** The converter and uploader sidecar share `/work`. The converter
reads a token while the uploader already has a blocked send using a mutable
buffer. Marking the file or process sensitive after the read is too late. The
send reservation and sensitive transition must serialize on the same domain
state before either effect is allowed.

#### A.14.1 Authority domain and durable resources

```text
AuthorityDomainStateV1 {
  authority_domain_id, node_boot_id: Id128
  label_epoch, domain_epoch: u64
  domain_lock: bpf_spin_lock
  execution_set_binding_refs: u64
  live_process_refs: u64
  live_channel_and_shared_object_refs: u64
  pending_entry_and_join_refs: u64
  response_plan_refs: u64
  reconciliation_hold_refs: u64
  publication_reservation_and_capability_refs: u64
  shared_resource_kind_bits: u64
  potential_sensitive_bits, observed_sensitive_bits: u64
  effective_restriction_set_ref_id: u64
  effective_response_set_ref_id: u64
  retained_generation_set_ref_id: u64
  publication: AuthorityDomainPublicationStateV1
  transition_version: u64
  state: PREPARING | ACTIVE | DRAINING | RECLAIMABLE |
         FAIL_CLOSED_OVERFLOW | CORRUPT
}

SharedResourceStateV1 {
  shared_resource_state_id: Id128
  exact_live_object_identity_and_generation: ExactObjectGenerationV1
  authority_domain_id: Id128
  reference_owned: bool
  participant_topology_plan_digest: DigestV1
  potential_sensitive_bits, observed_sensitive_bits: u64
  effective_response_set_ref_id: u64
  transition_version: u64
  state: PREPARING | ACTIVE | DRAINING | TOMBSTONED | CORRUPT
}

PersistentFileSecurityStateV1 {
  persistent_state_id: Id128
  backing_volume_live_identity, filesystem_instance_identity: Id128
  stable_filesystem_object_identity_and_generation: Id128
  known_namespace_alias_digest: DigestV1
  link_count_observation: u64
  open_file_refs, vma_refs, async_io_and_writeback_refs: u64
  authority_domain_id: Id128
  potential_sensitive_bits, observed_sensitive_bits: u64
  transition_version: u64
  state: PREPARING | ACTIVE | UNLINKED_REFERENCED | RETIRING |
         TOMBSTONED | CORRUPT
}
```

Threads share one process and domain. Ordinary fork descendants remain in the
same monotonic domain because they inherit memory and descriptors even without
explicit `CLONE_VM|CLONE_FILES|CLONE_FS`. Independent roots join before using
a shared mount, memory area, pipe, Unix/loopback socket, passed fd, or other
declared channel.

Positive role grants never merge. The domain carries only common negative
restrictions, sensitive bits, response floors, and retained generations. A
converter never gains the uploader's destination allow.

A domain cannot be reclaimed merely because the last process exits. Bindings,
objects, sockets, mappings, pending entries/joins, response plans, publication
slots, persistent files/volumes, and recovery holds can keep it alive. All
typed refs, iterator state, publication state, WAL, and grace period must agree.

#### A.14.2 Prevention modes for a shared channel

| Mode | Meaning |
| --- | --- |
| `DENY` | The channel cannot be created, opened, connected, attached, or first used by these participants. |
| `PRE_USE_CONSERVATIVE_DOMAIN_MERGE` | Participants receive the common negative domain before either may use the channel. This is the unchanged-deployment baseline. |
| `SERIALIZED_TRANSFER_GATE` | A separately qualified boundary owns every enqueue/dequeue and updates the receiver before bytes or capability become usable. |
| Observation-only taint | May explain completed flow or trigger later restriction; never claims first-transfer prevention. |

The configured record keeps prevention and observation separate:

```text
CrossEntryTransferControlV1 {
  prevention_mode:DENY | PRE_USE_CONSERVATIVE_DOMAIN_MERGE |
                  SERIALIZED_TRANSFER_GATE
  observation_mode:NONE | OBJECT_TAINT_BEST_EFFORT |
                   COMPLETE_POST_TRANSFER_TAINT
}

LocalInetChannelIdentityV1 {
  network_namespace_identity:NetworkNamespaceIdentityV1
  family:AF_INET | AF_INET6
  transport:TCP | UDP
  local_address_and_port
  peer_address_and_port
  socket_cookie_and_birth_generation
  listener_socket_cookie_and_generation?
  accepted_child_socket_cookie_and_generation?
  endpoint_selection:EXACT_ONE | EXACT_REUSEPORT_SET |
                     WILDCARD_LISTENER_SET | UNKNOWN
  participant_authority_domain_ids[]:Id128
  topology_version:u64
}
```

“Local” is resolved in the exact live network namespace. It includes loopback,
Pod IP, wildcard listeners, local redirection, and qualified hairpin delivery;
it is not determined by the spelling of an address. `UNKNOWN` cannot establish
a safe receiver and follows the configured deny or conservative merge.

A clean receiver may already be blocked in `read` before a sensitive writer
updates an object. Therefore object-taint-after-write is not the baseline.
Local IPv4/IPv6, wildcard/reuseport listeners, shared Pod networking, pipes,
shared memory, regular files, `emptyDir`, passed fds, and process-memory access
all follow the same rule.

#### A.14.3 Domain join transaction

BPF cannot atomically rewrite several maps and objects. The triggering channel
operation first denies and leaves a persistent gate in `DENYING`. Rust then
runs a crash-recoverable join.

```text
AuthorityDomainJoinTransactionV1 {
  join_transaction_id: Id128
  source_domain_ids[2..MAX_JOIN_DOMAINS]: Id128
  target_domain_id: Id128
  expected_source_transition_versions[]: u64
  unioned_negative_state_digest: DigestV1
  root_progress_ids[], target_progress_ids[]: Id128
  quiescence_proof_id: Id128
  gate_state: DENYING | RETRY_ALLOWED
  state: PREPARING | QUIESCING | REDIRECTING | VERIFYING |
         COMMITTED | DRAINING_OLD | COMPLETE |
         RECOVERY_REQUIRED | FAILED_CLOSED
}

DomainJoinRootProgressV1 {
  old_domain_id: Id128
  expected_transition_version: u64
  restrictive_floor_installed: bool
  members_enumerated: bool
  pointers_redirected: u64
  references_transferred: u64
  readback_digest: DigestV1
  state: PENDING | IN_PROGRESS | VERIFIED | DRAINING | COMPLETE
}

DomainJoinTargetProgressV1 {
  target_domain_id: Id128
  unioned_state_and_set_digest: DigestV1
  acquired_reference_counts_by_class[]
  installed_and_readback: bool
  state: PREPARING | ACTIVE | CORRUPT
}

DomainJoinQuiescenceV1 {
  new_channel_and_entry_gate: CLOSED
  new_async_submission_gate: CLOSED
  io_uring_instances[]: CANCELLED | DRAINED | UNRESOLVED
  sqpoll_workers[]: STOPPED_AND_DRAINED | UNRESOLVED
  registered_file_and_buffer_sets[]: SNAPSHOTTED | UNRESOLVED
  aio_and_kernel_worker_requests[]: CANCELLED | DRAINED | UNRESOLVED
  inflight_publications: exactly 0
  persistent_publication_present: exactly false
  frozen_process_set_digest: DigestV1
  task_object_socket_iterator_digests[]: DigestV1
  state: NOT_STARTED | GATED | DRAINED | FROZEN | VERIFIED | INCOMPLETE
}
```

Join order is fixed:

```text
deny the triggering operation and all new participant/publication paths
build a PREPARING target containing the union of negative state
freeze/hold the complete target set and drain async publication work
for every process/object/socket/binding/pending entry/response/persistent item:
  acquire target reference
  CAS the owner pointer
  release the source reference using an owned bit
read back every root, target, pointer, and reference
activate target and change the gate to RETRY_ALLOWED
retry the original operation from a fresh lookup
drain old domains only after zero references and reconciliation
```

A crash may leave some actors stricter than others. The gate stays denied and
recovery resumes exact progress rows. It never reopens old broad authority.

#### A.14.4 Publication reservation

```text
AuthorityDomainPublicationStateV1 {
  publication_epoch: u64
  inflight_publications: u32
  persistent_publication_present: bool
  state: ACTIVE | CAPACITY_FAIL_CLOSED | STUCK_FAIL_CLOSED |
         RECONCILIATION_REQUIRED
  slots[MAX_DOMAIN_PUBLICATIONS]: PublicationSlotV1
}

PublicationSlotV1 {
  publication_instance_id: Id128      // zero only when FREE
  descriptor_id: nonzero u64
  release_epoch: u64                  // zero before domain-side release
  state: FREE | INFLIGHT | COMPLETING | RELEASED_PENDING_ACK
}

PublicationDescriptorV1 {
  descriptor_id: nonzero u64
  publication_instance_id: Id128
  actor_task_cookie: u64
  actor_process_state_id, actor_authority_domain_id: Id128
  profile_generation_ref_id: u64
  operation
  exact_request_identity: ExactRequestIdentityV1
  transfer_plan: PublicationTransferPlanV1
  source_mutability_proof_ids[]: Id128
  completion_kind
  maximum_bytes: u64
  descriptor_digest: DigestV1
  state: PREPARING | ACTIVE | COMPLETING | TOMBSTONED
}
```

The types referenced by that descriptor are exact. They are placed here,
after the algorithm, so the reader sees the race before the wire shapes.

```text
UserBufferSegmentV1 { address:u64, length:u64 > 0 }

PublicationPayloadSourceV1 =
  USER_BUFFER { segment:UserBufferSegmentV1 }
  | FILE_RANGE {
      object:ExactObjectGenerationV1, offset:u64, length:u64 > 0
    }
  | PIPE_BUFFER {
      pipe:ExactObjectGenerationV1, pipe_generation:u64, length:u64 > 0
    }
  | SOCKET_RECEIVE_QUEUE {
      socket:ExactObjectGenerationV1, receive_generation:u64, length:u64 > 0
    }

ExactPublicationSinkV1 =
  FILE_OBJECT { object:ExactObjectGenerationV1, offset:u64, length:u64 }
  | NETWORK_FLOW {
      socket:ExactObjectGenerationV1, flow_generation:u64,
      final_destination_identity_digest:DigestV1
    }
  | PIPE_OR_IPC {
      object:ExactObjectGenerationV1, queue_generation:u64
    }

PublicationTransferPlanV1 =
  SINGLE {
    source:PublicationPayloadSourceV1, sink:ExactPublicationSinkV1
  }
  | USER_IOVEC {
      segments[1..MAX_IOV]:UserBufferSegmentV1,
      sink:ExactPublicationSinkV1
    }
  | MESSAGE_BATCH {
      messages[1..MAX_MMSG] {
        message_index:u32,
        segments[0..MAX_IOV]:UserBufferSegmentV1,
        sink:ExactPublicationSinkV1,
        capability_transfer_ids[0..MAX_SCM_TRANSFERS]:Id128
      }
    }

IpcCapabilityTransferV1 {
  transfer_id:Id128
  kind:SCM_RIGHTS | SCM_CREDENTIALS
  exact_transferred_object?:ExactObjectGenerationV1
  sender_task_cookie:u64
  sender_authority_domain_id:Id128
  receiver_channel:ExactObjectGenerationV1
  required_result:DENY | PRE_USE_DOMAIN_JOIN | DECLARED_SAME_DOMAIN
}

SourceMutabilityProofV1 {
  proof_id:Id128
  proof_generation:u64 > 0
  covered_source_identity_digest:DigestV1
  proof:SAME_AUTHORITY_DOMAIN { authority_domain_id:Id128 }
      | PREMERGED_AUTHORITY_DOMAIN { join_transaction_id:Id128 }
      | SEALED_MEMFD {
          object:ExactObjectGenerationV1,
          required_seals:F_SEAL_WRITE|F_SEAL_SEAL,
          no_preexisting_writable_mapping_proof_id:Id128
        }
      | IMMUTABLE_CAS_OR_IMAGE_OBJECT {
          object:ExactObjectGenerationV1, content_digest:DigestV1,
          read_only_backing_proof_id:Id128
        }
      | HELD_WRITER_RECONCILIATION {
          object:ExactObjectGenerationV1, reconciliation_id:Id128,
          writer_and_vma_snapshot_id:Id128
        }
  valid_from_transition_version:u64
  state:ACTIVE | INVALIDATED | CONSUMED
}

ExactRequestIdentityV1 =
  SYNC_SYSCALL {
    task_cookie:u64, process_state_id:Id128,
    syscall_entry_sequence:u64, effect_attempt_sequence:u64,
    effect_family:u16, operation:u16
  }
  | AIO_REQUEST {
      aio_context_id:Id128, request_id:Id128, submission_sequence:u64
    }
  | IO_URING_REQUEST {
      ring_id:Id128, ring_generation:u64, submission_sequence:u64,
      sqe_index:u32, user_data:u64, opcode:u16
    }
  | MMAP_ATTEMPT {
      task_cookie:u64, process_state_id:Id128,
      authority_domain_id:Id128, attempt_sequence:u64
    }

ExactCompletionIdentityV1 =
  SYNC_RETURN {
    task_cookie:u64, syscall_entry_sequence:u64,
    effect_attempt_sequence:u64
  }
  | AIO_COMPLETION { aio_context_id:Id128, request_id:Id128 }
  | IO_URING_CQE {
      ring_id:Id128, ring_generation:u64, submission_sequence:u64,
      user_data:u64
    }
  | ZEROCOPY_NOTIFICATION {
      socket:ExactObjectGenerationV1, notification_generation:u64,
      first_id:u32, last_id:u32
    }
  | HELD_WRITEBACK_RECONCILIATION { reconciliation_id:Id128 }
```

The source proof answers “can some actor change these bytes after admission?”
The request identity answers “which one syscall or asynchronous request owns
this reservation?” The completion identity answers “which exact completion may
release it?” A digest, address, fd, `user_data`, or time alone answers none of
those questions.

Task-local nesting and descriptor lifetime prevent an inner LSM pass or a
duplicate completion from releasing the wrong reservation:

```text
TaskEffectAttemptStateV1 {
  task_cookie, syscall_entry_sequence, next_effect_attempt_sequence:u64
  frames[MAX_NESTED_EFFECT_ATTEMPTS] {
    effect_attempt_sequence:u64
    effect_family, operation, hook_discriminator, repeated_lsm_pass_count:u16
    publication_instance_id?:Id128
    state:ACTIVE | RETURNED | CANCELLED
  }
  depth:u16
  state:ACTIVE | OVERFLOW_FAIL_CLOSED | TASK_EXITED
}

PublicationDescriptorLifetimeV1 {
  descriptor_id:u64
  publication_instance_id, authority_domain_id:Id128
  slot_reference_owned:bool
  prepared_boottime_ns:u64
  completion_identity_digest?:DigestV1
  completion_boottime_ns?, domain_release_epoch?:u64
  transition_version:u64
  state:PREPARED | OWNED | COMPLETING | COMPLETED | CANCELLED |
        RECLAIMABLE | CORRUPT
}

PublicationIdAllocatorV1 {
  allocator_lock:bpf_spin_lock
  node_boot_id:Id128
  label_epoch:u64
  next_instance_counter, next_descriptor_counter:u64  // start at 1
  state:ACTIVE | EXHAUSTED | LOST_EPOCH_FAIL_CLOSED
}
```

The deciding BPF program allocates non-reused IDs, inserts the immutable
descriptor and lifetime with `BPF_NOEXIST`, reads them back, and only then takes
the domain lock to reserve a slot. Counter wrap, allocator loss, map-full,
unexpected existing key, nested-frame overflow, or descriptor mutation holds
the domain fail-closed. The IDs are never recycled.

Transfer sources are closed: user buffer/iovec/message batch, exact file range,
pipe generation, or socket receive queue. Sinks are exact file range, network
flow/final destination, or IPC queue. `SCM_RIGHTS` and credentials are
capability transfers, not payload bytes. AIO and io_uring requests include
their ring/context generation, submission sequence, opcode, and completion
identity.

The linearization is:

```text
publication begin:
  build and read back immutable descriptor
  lock domain
  require no publication-denying sensitive state and a free slot
  reserve slot and increment inflight/ref/epoch
  unlock and read back ownership
  allow the effect

sensitive authority begin:
  lock the same domain value
  require inflight == 0 and no persistent writable publication capability
  install sensitive bits and stricter set in the same locked transition
  otherwise deny with the configured EAGAIN/EACCES

publication completion:
  match the exact syscall/AIO/io_uring/zero-copy completion
  move INFLIGHT -> COMPLETING -> RELEASED_PENDING_ACK
  decrement once using owned state
  acknowledge external lifetime, then free slot
```

Pointer/length overflow, N+1 iovec/message, mutable writer outside the domain,
missing source, incompatible completion, unknown zero-copy lifetime, or slot
capacity denies. A missing completion safely leaves the restriction stuck; it
does not guess that publication ended.

`MAP_SHARED` to a writable output or shared/remote/host volume creates a
`PersistentPublicationCapabilityV1` before mmap returns:

```text
PersistentPublicationCapabilityV1 {
  capability_id, authority_domain_id:Id128
  origin_task_cookie:u64
  origin_process_state_id:Id128
  mapping_attempt_identity:ExactRequestIdentityV1::MMAP_ATTEMPT
  reconciled_mm_snapshot_id?:Id128
  exact_sink_object_id_and_generation:ExactObjectGenerationV1
  requested_mapping {
    file_offset:u64, length:u64,
    prot_bits:READ | WRITE | EXEC,
    map_flags:SHARED | SHARED_VALIDATE,
    unknown_flag_bits:exactly 0
  }
  reservation_epoch:u64
  domain_reference_owned:bool
  transition_version:u64
  state:RESERVED | MAPPING_OBSERVED | RECONCILIATION_REQUIRED |
        RELEASED | RECLAIMABLE
}
```

It remains until a
held full-domain VMA/object/writeback reconciliation proves every mapping,
forked holder, fault, writeback, and async request is gone. `munmap`, `msync`,
exec, process exit, or origin-task death alone cannot clear it.

#### A.14.5 Persistent and cross-node volumes

Rename and hardlink preserve persistent file state. Overlay copy-up, reflink,
copy, snapshot, clone, backup, and restore must attach source authority to the
new object before it becomes visible or deny the operation. Unlink releases
only after link count is zero and no fd, VMA, async I/O, or writeback remains.

RWX storage needs a signed centrally committed
`PersistentVolumeAuthorityV1`: volume/storage generation, portable restriction,
participant set, access mode, and commit index. Every node denies covered file
effects through BPF until it fetches a non-rollback record, lowers it into a
fresh local set, installs it, and reads back the result. The mount may already
exist and the workload may already be running; Mithril neither holds nor
releases either one. When a qualified OCI/NRI/runtime start callback exists,
Mithril may delay returning from that callback until the same access state is
ready, but the callback remains a runtime-start gate rather than a mount gate.
Reactive node-local taint is insufficient because one node may crash before
another publishes.

```text
PersistentVolumeAuthorityV1 {
  persistent_volume_authority_id, cluster_uid:Id128
  csi_driver_canonical_name
  provider_or_csi_volume_handle_digest:DigestV1
  provisioned_volume_uid:Id128
  provisioned_storage_generation:u64
  access_mode:RWO | ROX | RWX | RWOP | UNKNOWN
  potential_sensitive_bits:u64
  semantic_restriction_artifact_digest:DigestV1
  permitted_execution_set_ids[]:Id128
  record_generation, control_commit_index:u64
  policy_artifact_digest:DigestV1
  state:PREPARING | ACTIVE | RETIRING | REVOKED | CORRUPT
  signer_key_id
  signature
}

VolumeAccessReadinessV1 {
  readiness_id, node_boot_id, execution_set_id,
    persistent_volume_authority_id:Id128
  exact_live_mount_identity
  observed_record_generation, observed_control_commit_index:u64
  installed_local_restriction_set_ref_id:u64
  installed_semantic_restriction_artifact_digest:DigestV1
  installed_domain_and_restriction_digest:DigestV1
  optional_runtime_start_callback_identity?:Id128
  state:PREPARING | READ_BACK | ACTIVE | DENIED
}
```

The central record carries portable restriction meaning, never a node-local
map handle. A node compiles that meaning to a fresh local set and reads it back
before marking covered volume access `ACTIVE`. Until then, the BPF access gate
denies covered effects. If a qualified runtime-start callback is waiting,
Mithril returns success only after `ACTIVE`; otherwise the task may run but its
covered accesses still deny. Stale commit index, rollback, unknown storage
generation, bad signature, or unavailable control leaves access denied. This
is intentionally volume-wide in Version 1: safe per-file cross-node identity
is unsupported until the storage backend proves stable non-reused identity and
every link/copy/snapshot/restore transition.

If a backend lacks stable non-reused object identity or qualified
link/copy-up/remount lifecycle, the honest options are a volume-wide common
domain, denial of the writable surface, or an unsupported per-file claim.

#### A.14.6 Failure and race tests

Mandatory tests pause or crash after every reservation, sensitive transition,
join pointer/ref write, completion, rename/link/unlink, overlay copy-up,
VMA/writeback transition, and volume commit. They cover blocked reader before
writer, mutable send buffer after admission, regular file, pipe, Unix stream
and datagram, shared memory, loopback/Pod IP, passed/duplicated fd, splice,
sendfile, copy-file-range, AIO, every relevant io_uring opcode, registered
files/buffers, SQPOLL, `MAP_SHARED`, multiple readers, sidecar restart, zero-
process gaps, node crash, and RWX cross-node publication.

The oracle is physical: no marker reaches the sink on denied branches; clean
declared data still succeeds; counters/refs never underflow; a crash never
restores broader authority; unsupported paths are named.

Mithril must never claim that process-local taint, object taint after transfer,
last-process exit, admission alone, `munmap`, path/inode identity, or a node-
local event makes shared publication safe.

### A.15 Exact Evidence, Graph, And Response Contract

Chapters 22-24 explain proof and response. This section defines the records
that make those explanations deterministic.

**Problem.** A local socket event, Kubernetes audit event, and AWS operation
may all occur close together. Time and a shared credential can suggest a path,
but they do not prove one Linux process caused the remote action. Likewise,
killing a process does not prove its controller, sockets, credentials, or
remote branches were contained.

#### A.15.1 Observation and coverage records

```text
EvidenceFieldV1 = FINDING_ID | REASON_CODE | DECISION | ERRNO |
  TASK_COOKIE | PROCESS_LINEAGE_ID | AUTHORITY_DOMAIN_ID |
  EXECUTION_SET_ID | EXACT_OBJECT_ID | OBJECT_CLASS_ID |
  DESTINATION_ID | PROVIDER_REQUEST_ID | PROVIDER_RESULT |
  COVERAGE_INTERVAL_IDS | POLICY_RULE_IDS | RESPONSE_RESULT

FindingGroupingFieldV1 = FINDING_ID | REASON_CODE | PROCESS_LINEAGE_ID |
  AUTHORITY_DOMAIN_ID | EXECUTION_SET_ID | EXACT_OBJECT_ID |
  PROVIDER_PRINCIPAL_ID | PROVIDER_RESOURCE_ID

ObservationEnvelopeV1 {
  schema_version: u32
  tenant_id: Id128
  observation_id: DigestV1
  source_id: Id128
  source_epoch, source_sequence: u64
  stable_provider_event_id?: bounded bytes
  node_boot_id?: Id128
  cpu_id?: u32
  hook_or_adapter_id: u32
  payload_schema_id: u32
  abi_or_api_version: u32
  profile_generation_ref_id?: u64
  boottime_ns?: u64
  projected_utc_ns?: i64
  time_uncertainty_ns: u64
  ingested_utc_ns: i64
  payload_fields[]: bounded typed EvidenceFieldV1
  proof_quality: ProofQualityV1
  coverage_interval_id: Id128
  transport_integrity_digest: DigestV1
  signature_or_batch_digest?: DigestV1
}

CoverageIntervalV1 {
  coverage_interval_id, source_id: Id128
  source_epoch: u64
  first_sequence, last_contiguous_sequence: u64
  start_boottime_ns, end_boottime_ns?: u64
  state: HEALTHY | GAPPED | UNKNOWN | CLOSED
  attempted, suppressed, requested, emitted, lost,
    classifier_miss_count: u64
  required_link_map_reader_digests[]: DigestV1
  gap_reason_code?: u32
  recovery_probe_artifact_id?: Id128
}
```

For kernel sources, `attempted = suppressed + requested` and
`requested = emitted + lost`. Suppression is intentional policy sampling;
loss is not. First loss, detach, reader failure, epoch change, counter
inconsistency, clock reset, or unknown map/link health closes the healthy
interval. Recovery opens a new interval; history is never rewritten.

The WAL truncates only through a durable contiguous acknowledgement. A restart
that cannot prove sequence continuity creates a new epoch and explicit gap.
Enforcement health, identity coverage, event coverage, semantic admission,
correlation feeds, and response verification remain separate axes.

#### A.15.2 Proof quality and findings

```text
ProofQualityV1 {
  source_authority: KERNEL_DECISION | SIGNED_COORDINATOR |
                    AUTHORITATIVE_PROVIDER | AUTHENTICATED_MEASUREMENT |
                    UNAUTHENTICATED
  local_subject_binding: EXACT_TASK | EXACT_PROCESS | EXACT_EXECUTION_SET |
                         CONTEXTUAL | NONE
  remote_subject_binding: EXACT_REQUEST | EXACT_SESSION | EXACT_OBJECT |
                          PRINCIPAL_ONLY | CONTEXTUAL | NONE
  operation_result_authority: PRE_EFFECT_DECISION |
                              AUTHORITATIVE_SUCCEEDED |
                              AUTHORITATIVE_DENIED | OBSERVED_ATTEMPT |
                              CONTEXTUAL | UNKNOWN
  temporal_coverage: COMPLETE | GAPPED | UNKNOWN
  integrity: SIGNED | AUTHENTICATED_CHANNEL | LOCAL_ATTESTED | UNVERIFIED
}

FindingV1 {
  finding_id: DigestV1
  package_id, package_version
  subject_id: DigestV1
  window_start_utc_ns, window_end_utc_ns: i64
  revision: u64
  state: PROVISIONAL | CONFIRMED | SUPERSEDED | RETRACTED |
         COVERAGE_INSUFFICIENT
  graph_version_id: DigestV1
  sorted_evidence_ids[], required_coverage_interval_ids[]: DigestV1
  superseded_revision?: u64
  closed_reason_code?: u32
}
```

Packages declare sources, coverage, maximum lateness, time uncertainty,
retention, exact/contextual join fields, and late-event behavior. Delivery
order and duplicate redelivery cannot change the terminal finding bytes. Time
never upgrades an edge to exact.

#### A.15.3 Multi-node graph

```text
GraphSubjectV1 {
  subject_id: DigestV1
  tenant_id: Id128
  subject_kind: TASK | PROCESS | EXECUTION_SET | SOCKET | REQUEST |
                CREDENTIAL_LEASE | KUBERNETES_OBJECT | PROVIDER_OBJECT |
                ARTIFACT | CI_RUN | CI_JOB | CI_STEP | EXTERNAL
  owning_authority_id: Id128
  immutable_identity_fields[]
  identity_state: EXACT | CONTEXTUAL | CONTRADICTED | SUPERSEDED
  first_seen_utc_ns, last_seen_utc_ns: i64
}

GraphEdgeV1 {
  edge_id: DigestV1
  from_subject_id, to_subject_id: DigestV1
  edge_type_id: u32
  package_id, package_version
  sorted_evidence_ids[], required_coverage_ids[]: DigestV1
  proof_quality: ProofQualityV1
  cause_strength: DIRECT | CONTEXTUAL | CONTRADICTED | SUPERSEDED
  valid_time_interval_and_uncertainty
  supersedes_edge_id?: DigestV1
}

GraphVersionV1 {
  graph_version_id: DigestV1
  parent_graph_version_id?: DigestV1
  input_source_watermarks[]
  package_versions[]
  sorted_subject_ids[], sorted_edge_ids[]: DigestV1
  canonical_graph_digest: DigestV1
}
```

`ProviderEdgeContractV1` registers the only fields that can make a particular
pair of endpoint kinds direct:

```text
GraphSubjectKindV1 = TASK | PROCESS | EXECUTION_SET | SOCKET | REQUEST |
  CREDENTIAL_LEASE | KUBERNETES_OBJECT | PROVIDER_OBJECT | ARTIFACT |
  CI_RUN | CI_JOB | CI_STEP | EXTERNAL

SourceKindV1 = RegistrySymbolV1
EvidenceFieldIdV1 = RegistrySymbolV1
FixtureIdV1 = ASCII matching ^[A-Z][A-Z0-9_-]{2,127}$

ProviderEdgeContractV1 {
  edge_type_id:u32
  from_subject_kind, to_subject_kind:GraphSubjectKindV1
  authoritative_source_kind:SourceKindV1
  direction:FROM_CAUSED_TO | TO_DERIVED_FROM
  required_equal_fields[1..32]:EvidenceFieldIdV1
  identifier_uniqueness_scope:bounded closed value
  required_request_fields[0..32]:EvidenceFieldIdV1
  required_result_fields[0..32]:EvidenceFieldIdV1
  required_coverage[1..16]:SourceKindV1
  minimum_proof_vector:ProofQualityV1
  time_rule:CAUSAL_ORDER_REQUIRED | PROVIDER_ORDER_REQUIRED |
            TIME_NOT_USED_FOR_EXACTNESS
  missing_field_result:CONTEXTUAL_EDGE | NO_EDGE | COVERAGE_UNKNOWN
  legitimate_shared_identity_negative_test_id:FixtureIdV1
}
```

The registry fixes source/target kinds, direction, equality fields,
uniqueness/cardinality scope, authoritative request/result fields, coverage,
proof predicate, time rule, missing-field result, and a concurrent
shared-identity negative fixture. Adapters cannot emit a generic direct edge
outside this registry.

Examples:

```text
local task -> Kubernetes request: direct only with carried request/lease proof
Kubernetes request -> object revision: API request/audit/object IDs and result
object revision -> controller -> Pod -> node-B root: UIDs, owner/scheduler,
  Pod UID, full container ID, and node admission
AWS lease -> operation: provider account/session/access-key fields and result;
  still not one Linux task when the lease was shared
artifact -> consumer: immutable provider version/digest plus one-use slot
connector -> provider request: connector invocation ID forwarded and confirmed
```

Remote tasks are never Linux children of local tasks. A missing carried proof
keeps the edge contextual even when account, IP, user agent, and time match.
Every branch independently records open, terminal verified, contextual only,
outside authority, or coverage unknown.

#### A.15.4 Response authorization and state

```text
ResponsePlanV1 {
  plan_id: Id128
  revision: u64
  frozen_graph_version: DigestV1
  frozen_branch_ids[]: DigestV1
  requested_actions[]: ResponseActionSpecV1
  authorization_id: Id128
  authorization_expires_utc_ns: i64
  node_deadline_boottime_ns?: u64
  idempotency_key_per_action[]: Id128
  state: PROPOSED | AUTHORIZED | REVALIDATING | APPLYING |
         VERIFYING | WATCHING | VERIFIED | PARTIAL | FAILED |
         UNKNOWN | EXPIRED | CANCELLED
  action_results[]
  required_watch_interval_ns: u64
  required_coverage_ids[]: Id128
}

EffectiveResponseSet {
  set_ref_id: nonzero u64
  response_restriction_ids[MAX_RESPONSE_REFS]: Id128
  combined_deny_effect_families: u64
  combined_socket_fence
  earliest_expiry_boottime_ns: u64
}
```

The policy types referenced by a response binding are closed. The authoritative
`ResponseActionSpecV1` definition is in Appendix A.11.5.1; the variants are
repeated here as a response-engine reading aid:

```text
response action variants =
  LOCAL { action:RESTRICT_LINEAGE | FENCE_SOCKETS | FREEZE_CGROUP }
  | KUBERNETES {
      action:REJECT_REPLACEMENT, admission_capability_id:PolicyLocalIdV1
    }
  | CREDENTIAL {
      action:REVOKE_CREDENTIAL, provider:ProviderV1, credential_kind,
      actuator_capability_id:PolicyLocalIdV1,
      typed_request_schema_digest:DigestV1
    }
  | MESH {
      action:DISABLE_MESH_DEVICE, provider:ProviderV1,
      actuator_capability_id:PolicyLocalIdV1,
      typed_request_schema_digest:DigestV1
    }
  | ARTIFACT {
      action:QUARANTINE_ARTIFACT, store_capability_id:PolicyLocalIdV1,
      typed_request_schema_digest:DigestV1
    }
  | SOURCE_CONTROL {
      action:SUSPEND_INSTALLATION, provider:ProviderV1,
      actuator_capability_id:PolicyLocalIdV1,
      typed_request_schema_digest:DigestV1
    }
  | PROVIDER_SPECIFIC {
      provider:ProviderV1, canonical_action_id:PolicyLocalIdV1,
      actuator_capability_id:PolicyLocalIdV1,
      typed_request_schema_digest:DigestV1
    }

BlastRadiusLimitV1 =
  LOCAL {
    permitted_target_selector_ids[1..64], process_count:u32,
    execution_set_count:u32, socket_count:u32, node_count:u32
  }
  | KUBERNETES {
      permitted_namespace_uids[1..64]:Id128,
      object_count:u32, controller_count:u32, node_count:u32
    }
  | CREDENTIAL {
      permitted_provider_account_ids[1..64], session_count:u32,
      principal_count:u32, role_count:u32, account_count:u32
    }
  | MESH {
      permitted_tailnet_or_tenant_ids[1..64], device_count:u32,
      route_count:u32, auth_key_count:u32
    }
  | SOURCE_CONTROL {
      permitted_organization_ids[1..64], installation_count:u32,
      repository_count:u32, ref_or_pr_count:u32
    }
  | ARTIFACT {
      permitted_store_ids[1..64], artifact_count:u32, consumer_count:u32
    }
  | PROVIDER_RESOURCES {
      permitted_provider_account_ids[1..64],
      permitted_resource_selector_ids[1..64], resource_count:u32,
      principal_count:u32
    }

TargetRevalidationV1 =
  PROCESS_PIDFD_TASK_COOKIE_STARTTIME_CGROUP_BINDING
  | LINEAGE_ROOT_AND_COMPLETE_EFFECTIVE_RESPONSE_SET
  | SOCKET_COOKIE_PROVENANCE_AND_LIVE_BINDING
  | CGROUP_FD_NONCE_AND_MEMBER_SET
  | KUBERNETES_UID_RESOURCE_VERSION
  | PROVIDER_STABLE_ID_REVISION_AND_AUTHORITY
  | ARTIFACT_IMMUTABLE_DIGEST_AND_STORE_REVISION

PhysicalPostconditionV1 =
  RESPONSE_SET_INSTALLED_AND_DESCENDANTS_RECONCILED
  | PROCESS_STOPPED_VIA_PIDFD
  | SOCKET_SET_FENCED_AND_EXISTING_FLOW_ORACLE_PASSED
  | CGROUP_FROZEN_AND_PACKET_FENCE_ACTIVE
  | REPLACEMENT_REJECTED_THROUGH_WATCH_WATERMARK
  | PROVIDER_CREDENTIAL_ACTION_READ_BACK
  | MESH_DEVICE_DISABLED_AND_HANDSHAKE_REJECTED
  | ARTIFACT_QUARANTINED_AND_CONSUMER_LOAD_REJECTED
  | PROVIDER_OPERATION_SPECIFIC_POSTCONDITION
```

The compiler accepts only compatible combinations. For example, a GitHub
audit fingerprint cannot select a revoke-secret action, and a process target
cannot use a Kubernetes-object postcondition. Zero in a blast-radius field
means no targets are authorized, not unlimited targets.

Provider adapters lower those generic actions to typed capabilities. The
initial required GitHub and AWS shapes are:

```text
ConnectorTokenMintObservation {
  broker_request_id, app_id, installation_id
  repositories[], permissions[], result
  credential_lease_id
  protected_token_handle?:ProtectedCredentialHandleV1
}

GithubDocumentedAuditObservation {
  documented_event_schema_id
  installation_id, actor_id
  repository_or_organization_id
  operation_id, request_or_delivery_id, authoritative_result
}

GithubRevokePossessedInstallationToken {
  credential_lease_id:Id128
  protected_token_handle:ProtectedCredentialHandleV1
}

GithubSuspendInstallation { installation_id:bounded bytes }
GithubRemoveRepositoryAccess {
  installation_id, repository_id:bounded bytes
}
WaitForExpiryAndWatch {
  token_fingerprint:bounded bytes
  expires_at_utc_ns:i64
}

AwsDenyAssumedRoleSession {
  principal_id, role_session_name, policy_change_target:bounded bytes
}

AwsRevokeRoleSessionsBefore {
  role_arn:bounded bytes
  cutoff_utc_ns:i64
}

AwsIdentityCenterRevokeUserSession {
  user_id, permission_set_or_application:bounded bytes
}
```

GitHub's revoke-installation-token API revokes the token used to authenticate
that revoke request. An audit hash, installation ID, or guessed token ID is
not the bearer secret. With no protected handle, the eligible choices are a
broader repository/installation action or expiry/watch, and the plan must show
that blast radius. Standard audit-only mode reports token mint detection as
unsupported unless the configured documented schema actually supplies that
event; downstream repository/workflow events remain usable.

AWS capabilities also have different physical scopes. Denying one named role
session, applying a role-wide “issued before” cutoff, and revoking an Identity
Center user session are not interchangeable. Each adapter records required IAM
authority, affected credential type and estimated session set, propagation
window, reversibility, and readback/canary procedure. If a cutoff disables two
sessions, Mithril must not label the result “exact session revoked.”

Every transition is a durable compare-and-swap recording actor, previous
revision, UTC, node time where relevant, reason, and idempotency key. A new
replacement or late branch creates a new plan revision; it cannot be ignored
because an older scope already verified.

Before actuation, response freezes the graph version and branches, checks
authorization and blast-radius limits, and re-resolves the target at its owning
authority:

```text
process: node boot + label epoch + task cookie + pidfd/start + cgroup binding
lineage: root plus complete inherited effective-response reconciliation
socket: cookie/generation/provenance/live binding
cgroup: opened fd + nonce + complete members
Kubernetes: UID + resourceVersion
provider: stable ID + revision + actuator authority
artifact: immutable digest + exact store revision
```

Future children inherit the effective response set at task creation in O(1).
Ancestor vectors help find existing descendants but are not the only future-
child control. Capacity overflow denies new protected effects/forks; Mithril
never drops the oldest response.

#### A.15.5 Physical response verification

| Action | Verification required in production |
| --- | --- |
| Process/lineage restriction | Exact response map/set readback; target points to it; every existing descendant reconciled or separately authorized broader fence; hooks/maps healthy |
| Existing socket/packet fence | Exact socket/cgroup keys, program generation and attachment readback; preexisting flows enumerated; tied drop/destroy counters |
| Cgroup freeze | Exact live cgroup reads `frozen=1` and task membership reconciles |
| Kill/signal | pidfd target revalidated and exact process exit confirmed; replacement branches stay open |
| Kubernetes action | exact UID/revision readback and replacement watch through healthy watermark |
| Credential/provider/mesh/source-control action | typed provider request/result plus authoritative postcondition readback; audit silence alone is insufficient |
| Artifact quarantine | exact store revision quarantined and every required consumer load/deploy path rejects |

Hostile probes run only in isolated qualification fixtures. Production
verification uses non-invasive readback and passive healthy watch. A real later
attempt may add errno or drop evidence, but absence of an attempt cannot make
installation unverified if readback is complete—and silence alone can never
substitute for readback.

`VERIFIED` means every action in that exact revision passed its postcondition
and all required sources remained healthy throughout the watch. `PARTIAL`
means a mixture of verified and failed/outside/unverifiable branches. `FAILED`
requires authoritative proof that none achieved the intended result.
`UNKNOWN` means proof is insufficient. `EXPIRED` and `CANCELLED` stop future
steps but never erase already applied actions.

Blast radius is part of approval. A common authority-domain restriction, shared
socket fence, cgroup freeze, or credential revocation must enumerate every
known participant and lost capability. If that scope is not authorized,
Mithril applies a separately proved narrower action or reports partial; it does
not silently widen response.

#### A.15.6 Determinism and failure tests

Tests deliver the same observations in every order, duplicate them, delay them
past watermarks, inject gaps, contradict a contextual edge, reuse a shared
credential concurrently, take a node offline, add a late Pod, overflow
response references, crash after every response transition, replay the same
idempotency key, fail every actuator/readback source, and keep one external
branch outside authority.

Expected graph/finding/plan bytes are deterministic after declared time/ID
normalization. Exact edges appear only for the client with unique carried
proof. A quiet but unverified actuator remains unknown. A verified old scope
plus an open new branch makes the incident partial/watching.

Mithril must never infer exact cause from time/IP/user-agent/shared credential,
equate graph identity with an actuator handle, inject attack probes into a
compromised production process, call process kill distributed containment, or
call missing events proof of success.

### A.16 Exact CI, Artifact, And Provider-Authority Contract

Chapter 26 explains CI with the same actor model as Kubernetes. This section
closes the records that distinguish job identity, step identity, executed
bytes, artifact trust, and credential authority.

**Problem.** GitHub says a job is running step `build`, but the runner may
materialize that step as a temporary shell script, a local action, a container,
or a JavaScript process that downloads more code. The coordinator's display
name or workflow digest does not prove which bytes a Linux child executed.

#### A.16.1 Provider job assignment and optional official step join

```text
CiProviderJobAssignmentEvidenceV1 {
  coordinator: CiCoordinatorV1
  tenant_id, repository_or_project_id: bounded bytes
  pipeline_run_id, pipeline_job_id: bounded bytes
  run_attempt: nonzero u32
  immutable_pipeline_definition_digest: DigestV1
  trigger_trust_class: CiTriggerTrustClassV1
  exact_runner_assignment_id: bounded bytes
  runner_group_or_pool_id?: bounded bytes
  assigned_node_or_runner_identity: bounded bytes
  issued_at_utc_ns, expires_at_utc_ns: i64
  provider_event_or_request_id: bounded bytes
  provider_signature_or_authenticated_record_digest: DigestV1
  proof_quality: ProofQualityV1
}

StepDefinitionIdentityV1 {
  coordinator: CiCoordinatorV1
  pipeline_run_id, pipeline_job_id, pipeline_step_id: bounded bytes
  step_definition_kind: RUN | ACTION | CONTAINER_ACTION | SERVICE |
                        REUSABLE_WORKFLOW | DEPLOY | POST | DEBUG
  immutable_workflow_revision_digest: DigestV1
  referenced_action_or_image_revision_digest?: DigestV1
  declared_inputs_digest: DigestV1
  declared_environment_reference_digest: DigestV1
  declared_working_directory_bytes: bounded bytes
}

MaterializedStepInvocationV1 {
  materialization_id: Id128
  step_definition_identity_digest?: DigestV1
  interpreter_or_image_digest: DigestV1
  observed_script_or_entrypoint_digest: DigestV1
  source_mutability_proof: SourceMutabilityProofV1
  canonical_argv_digest: DigestV1
  working_directory_bytes: bounded bytes
  public_environment_digest: DigestV1
  secret_reference_manifest_digest: DigestV1
  input_artifact_digests[]: DigestV1
  local_action_and_dependency_digests[]: DigestV1
  observed_task_or_container_binding_digest: DigestV1
  state: OBSERVED | IMMUTABLE_DURING_USE | MUTABLE_OR_RACY | FAILED
}

CiOfficialStepTaskJoinEvidenceV1 {
  evidence_id: Id128
  coordinator: CiCoordinatorV1
  official_interface_name_version: bounded bytes
  provider_assignment_evidence_digest: DigestV1
  pipeline_step_id: bounded bytes
  official_step_request_id: bounded bytes
  exact_task_or_container_binding_digest: DigestV1
  source_authentication_digest: DigestV1
  interface_ordering_capability_id: Id128
  proof_quality: ProofQualityV1
}

CiStepAdmissionJoinV1 {
  join_id: Id128
  provider_job_assignment_evidence_id: Id128
  official_step_task_join_evidence_id?: Id128
  exact_task_cookie_or_runtime_root_digest: DigestV1
  proof_quality: ProofQualityV1
  result: EXACT_STEP_AND_TASK | EXACT_JOB_ONLY |
          CONTEXTUAL_STEP_CANDIDATES | UNSUPPORTED
}
```

The coordinator can prove a job assignment. Exact named-step identity requires
an existing official interface that provides an authenticated unique join to
the actual task or container. Mithril does not patch the runner and does not
ask job code to call a trusted socket. A callback or copied environment value
from untrusted job code is not sufficient.

If the provider/runner exposes no such official join, the honest tier is exact
job identity plus exact Linux process lineage. Mithril may still protect the
whole job and track untrusted bytes, but it cannot claim one named YAML step
caused one action.

#### A.16.2 Job lifetime and cross-step state

```text
JobExecutionEpochV1 {
  job_execution_epoch_id: Id128
  coordinator: CiCoordinatorV1
  pipeline_run_id, pipeline_job_id: bounded bytes
  run_attempt: nonzero u32
  exact_runner_assignment_id: bounded bytes
  node_boot_id, execution_set_id: Id128
  workspace_generation, credential_generation: u64
  started_boottime_ns: u64
  ended_boottime_ns?: u64
  cleanup_tombstone_digest?: DigestV1
  state: PREPARING | ACTIVE | CLEANING | COMPLETE |
         RECONCILIATION_REQUIRED
}

CiStateArtifactV1 {
  state_artifact_id: Id128
  job_execution_epoch_id: Id128
  kind: GITHUB_ENV | GITHUB_PATH | STEP_OUTPUT | WORKSPACE_FILE |
        CACHE_ENTRY | ARTIFACT | UNIX_SOCKET | BACKGROUND_PROCESS |
        SHELL_STARTUP_FILE | OTHER_REGISTERED
  exact_producer_subject_id: DigestV1
  producer_trust_class: ProducerTrustClassV1
  exact_object_or_provider_version: bounded bytes
  immutable_digest?: DigestV1
  permitted_consumer_operations[]: ArtifactOperationV1
  consumer_scope
  created_boottime_ns: u64
  expires_or_cleanup_deadline_boottime_ns: u64
  state: ACTIVE | QUARANTINED | CLEANED | UNKNOWN
}
```

Step completion does not erase background processes, sockets, workspace files,
environment/path files, caches, or credentials. The next step consumes typed
state with producer trust. Runner reuse opens a new `JobExecutionEpochV1` only
after complete process/socket/mount/workspace/credential cleanup and readback.
Cleanup failure rejects privileged reuse or assigns a restricted unknown tier.

An untrusted PR may produce an artifact, but the artifact keeps
`UNTRUSTED_INPUT` provenance through cache, upload, download, image build, and
deployment. A later trusted workflow name does not upgrade the bytes. Load,
execute, and deploy each need their own consumer authorization and
attestation-policy match.

#### A.16.3 Credential issuance and use

```text
TokenIssuanceLedgerV1 {
  issuance_id: Id128
  authority_intent_id: Id128
  provider: ProviderV1
  provider_account_or_tenant: bounded bytes
  provider_principal: ProviderPrincipalV1
  public_credential_or_session_fingerprint: bounded bytes
  protected_credential_handle_id?: Id128
  permission_ids[]: u32
  resource_selectors[]: ResourceSelectorV1
  audience: bounded bytes
  issued_at_utc_ns, expires_at_utc_ns: i64
  provider_request_id, provider_result_id: bounded bytes
  state: ACTIVE | EXPIRED | REVOKE_REQUESTED | REVOKED | UNKNOWN
}

TokenConsumptionObservationV1 {
  consumption_id: DigestV1
  issuance_id_or_public_fingerprint?: bounded bytes
  local_or_ci_subject_id?: DigestV1
  provider: ProviderV1
  provider_principal: ProviderPrincipalV1
  operation_id: u32
  resources[]: ResourceSelectorV1
  provider_request_and_result
  proof_quality: ProofQualityV1
  coverage_interval_id: Id128
}
```

Credential delivery determines the earliest honest control:

| Delivery | Earliest control |
| --- | --- |
| Already in process environment/memory | No later file-read denial; control new lease, provider operation, destination, and response |
| Unopened projected/mounted file | Exact file-object open/use denial when qualified |
| Inherited or passed fd | Transfer/use/current-actor policy; open-only claim is insufficient |
| Existing provider-issued step lease | Use provider permissions/authorization before issuance; bind to exact step/task only when existing proof supplies the join |
| Provider read-only token | Provider prevents write even on the same TLS endpoint; readback effective permission |
| Shared write token on required same-TLS channel | Kernel cannot separate clone from push; use existing provider authorization/audit or deny the whole channel |

Mithril cannot derive a read token from an arbitrary installed write bearer
token unless the provider offers an exchange/delegation API and authorizes it.
When a GitHub App installation or equivalent existing provider API can mint a separately
scoped short-lived token, Mithril records the request/result and exposes only
that new capability to the approved subject.

##### A.16.3.1 Consumed authority and artifact objects

The signed body says what was approved. These durable objects say whether the
approval was claimed and whether a provider actually issued matching
authority.

```text
AuthorityLeaseIntentV1 {
  authority_intent_id, proof_id, claim_slot_id:Id128
  local_owner:exact process lineage or exact CI job/step subject
  provider:ProviderV1
  provider_account_or_project, issuer_subject, audience:bounded bytes
  requested_permission_set:u32[]
  requested_resource_scope:ResourceSelectorV1[]
  maximum_ttl_ns:u64
  provider_request_nonce:Id128
  state:PENDING | REQUESTING | ISSUED | DENIED | FAILED |
        EXPIRED | CANCELLED
}

CredentialLeaseV1 {
  credential_lease_id, authority_intent_id:Id128
  provider:ProviderV1
  provider_credential_type
  public_session_or_access_key_identifier:bounded bytes
  exact_provider_principal:ProviderPrincipalV1
  exact_resource_and_permission_scope_when_proven
  issued_at_utc_ns, expires_at_utc_ns:i64
  local_owner_binding_quality:ProofQualityV1
  provider_request_and_result_evidence_ids[]:DigestV1
  secret_material:exactly NEVER_STORED
  state:ACTIVE | EXPIRED | REVOKE_REQUESTED | REVOKED | UNKNOWN
}

ProtectedCredentialHandleV1 {
  handle_id, credential_lease_id:Id128
  encrypted_or_nonexportable_provider_secret_reference
  permitted_operations:[REVOKE_SELF]
  expires_at_utc_ns:i64
  never_serialized_to_evidence:exactly true
}
```

A provider result creates a lease only when provider, account, principal,
audience, nonce, permission/resource scope, and TTL are compatible with the
pending intent. If STS returns the wrong role, the intent becomes `FAILED`; the
response is evidence but no lease is invented. Secret bytes never enter
observations, graph, findings, or central WAL. An optional opaque protected
handle lives only at the provider-actuator boundary and authorizes its one typed
operation. A public token fingerprint is not such a handle.

Artifacts use immutable instances and independent consumer slots:

```text
ArtifactInstanceV1 {
  artifact_instance_id:Id128
  provider_artifact_id_and_version:bounded bytes
  producer_subject_id:DigestV1
  producer_trust_class:ProducerTrustClassV1
  immutable_digest:DigestV1
  byte_length:u64
  media_type:bounded bytes
  source_material_ids[], storage_observation_ids[],
    attestation_verification_ids[]:DigestV1
  state:PUBLISHED | QUARANTINED | EXPIRED
}

ArtifactConsumerSlotV1 {
  slot_id, artifact_instance_id:Id128
  exact_consumer_subject_id:DigestV1
  permitted_operation:READ_AS_DATA | VERIFY | LOAD | EXECUTE | DEPLOY
  deadline_utc_ns:i64
  state:PENDING | CLAIMED | COMPLETED | REJECTED | EXPIRED
}

AttestationVerificationV1 {
  attestation_digest:DigestV1
  predicate_type_and_version:bounded bytes
  signer_identity_and_trust_root:bounded bytes
  builder_identity:bounded bytes
  subject_digests[], material_digests[]:DigestV1
  source_repository_and_revision?:bounded bytes
  verifier_policy_digest:DigestV1
  result:VALID_AND_POLICY_MATCHED | VALID_BUT_POLICY_MISMATCH |
         INVALID | UNKNOWN
}
```

One artifact may fan out to many consumers, but each consumer claims its own
one-use slot. `READ_AS_DATA` does not authorize `LOAD`, `EXECUTE`, or `DEPLOY`.
A valid attestation signature proves that the signer made the statement; it
does not by itself make the builder, source, materials, policy, or bytes
trusted. From verification through use, Mithril holds the exact object/fd or
requires qualified immutable storage such as a sealed object, fs-verity, or
IMA. A cache key, artifact name, mutable tag, or digest checked before later
mutation is not byte continuity.

#### A.16.4 Physical CI shapes

Every adapter maps its real execution to one of these shapes:

```text
native shell/JavaScript child of a labeled runner
job container root
action/step container root
service or sidecar root
matrix/parallel job on another runner
reusable/remote workflow with a new coordinator boundary
deployment/provider operation with no local task
post/cleanup action after main failure
interactive debug/admin entry
Docker-in-Docker or nested runtime root
```

Native children use the ordinary fork/exec algorithm. Container/service/DinD
roots use initial/external root classification. Cross-runner work uses provider/artifact
edges, never native parenthood. Coordinator-only provider actions have no
dummy Linux task. Post/debug tasks get a distinct purpose only when an existing
official interface proves it; otherwise they remain native lineage or
restricted external roots.

#### A.16.5 CI failures, tests, and honest limits

Tests cover GitHub/GitLab/Tekton/Jenkins job/container/service shapes,
concurrent matrix jobs, local and remote actions, generated temporary scripts,
mutable local action, dependency download after workflow approval, untrusted
PR and `pull_request_target`-like privilege split, cache poisoning, artifact
mutation after verification, background process/socket, environment/path file,
runner reuse, cleanup crash, environment/file/fd/provider-issued/read-only credential
delivery, OIDC audience mismatch, same-TLS clone/push, deploy admission,
post-failure cleanup, debug entry, and DinD child containers.

The oracle checks job/task/container joins at their real proof quality,
observed executable bytes and mutability, process/domain restrictions,
credential scope, artifact trust, physical errno/provider result, cleanup
state, and coverage. A signed callback from job code, workflow hash, display
step, job token, boolean `attestation: verified`, or shared runner path cannot
substitute for an official unique join.

Named coordinator adapters and a source `CiPolicyV1` remain unallocated until
their phase approves the exact transport, trust root, records, and fixtures.
The generic architecture is complete, but the Version 1 parser must reject
unallocated `coordinators` or `ciRules` fields rather than silently accepting
design-level YAML.

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
| Every runtime root uses a `PENDING -> CLAIMED` ticket | Stock kubelet/CRI does not provide the required purpose or request-to-task token | Kernel creator + container binding classifies initial/native/external/unresolved; unknown external roots receive one restricted budget. The only deliberate exception is administrator-approved exec, where cluster policy and the administrator accept a short-lived next-exact-match race (§6-8). |
| `parent.thread_child_role` or separate thread-child role | Threads share a process, memory, often files; sibling role can launder authority | Threads share one process state; transitions are process-owned (§6) |
| Classify creator/exec actor by current cgroup before task label | A protected labeled task can be moved to host cgroup | Task storage first; cgroup verifies expected placement (§6, §13, §33) |
| Wake-path labeling without cross-cgroup failure proof | Child may run or land elsewhere before label; allocation may fail | Returning pre-effect creation hook or proved pre-wake finalizer plus fail-closed first effect (§6) |
| Userspace/asynchronous role assignment after exec | New image may act before update | Stage before point of no return; non-allocating commit before user mode (§6) |
| Every failed exec resumes old image | A failure after point of no return usually kills task; restoring authority is unsafe | Separate pre-PONR failure, post-PONR fatal/unknown, and success (§6) |
| Transparently hold and reconstruct every CRIU-restored task without runtime support | Stock restore interfaces may not expose a pre-run complete task/object barrier | Reject through an existing qualified hook, otherwise restrictive BPF treatment and honest `UNSUPPORTED` for complete restored history (§7) |
| Kubernetes metadata alone authenticates privileged exception | Metadata can be stale, reused, spoofed by another path, or lack human approval | Signed target-bound one-use exception plus node pre-setup enforcement (§7-9, §35.1) |
| Generic OCI pre-start hook proves a held task and exact setup | Hook timing and fields vary; an external hook is not automatically target-context execution or a hold | Qualify each stock hook's actual fields, ordering, and failure result; use BPF unresolved floor for missing identity (§5, §7, §29.4) |
| Insert a Mithril proxy or token into the runtime streaming protocol | This changes the runtime request path and still does not create a stock request-to-task field | Keep the ordinary Kubernetes/runtime path. The plugin and admission webhook may arm a BPF-map slot for the next complete matching external root, with explicit acceptance of the rare race; otherwise use the restricted external role (§7-8). |
| BPF hook performs synchronous disk I/O | BPF cannot write WAL and must remain bounded | Kernel decisions use prebuilt/pinned state; Rust persists and reconciles outside the hook (§8, §13) |
| Issuer chooses fail-open or emits reusable claims | Compromised issuer could widen local safety and replay authority | Local signed profile chooses failure; every claim is one-use (§8) |
| `Strong` is one scalar proof class | Signature, target, time, replay, task binding, and coverage can differ independently | Proof-quality vector (§8, §23) |
| Signed side-channel timing or Mithril-signed observation proves general kubelet intent | Another identical task can race, and stock CRI omits the reason | Keep probe/lifecycle/direct-runtime purpose `UNKNOWN`; apply the common external-root intersection unless an existing interface supplies a unique join. Administrator-approved exec may use the separately named, explicitly risk-accepted next-match exception (§7-8). |
| Google audit always contains original OIDC `jti` | Provider fields vary and may not preserve source claim | Explicit lease join fields; otherwise contextual edge (§8, §23) |
| Union of unequal candidate budgets is conservative | Union grants each candidate the other's authority | Exact proof, identical budget intersection, or reject (§6, §9) |
| Identical pending key proves an external root's purpose | Concurrent identical commands are indistinguishable and attacker-copyable | Never use a pending argv/cgroup claim for general purpose. The administrator-approved exception grants one bounded role to the first complete matching runtime external root and records that the association is raceable, not exact (§7-8). |

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
| Detect a task weakening its installed Seccomp floor | Installed Seccomp filters are monotonic; there is no removal syscall | For a qualified new-process start, prove Mithril installed the floor before target user code; otherwise make no Seccomp-floor claim (§21, §31) |

### B.4 Evidence, graph, response, and incident statements

| Rejected or corrected idea | Why it is wrong | Replacement |
| --- | --- | --- |
| Scalar `sourceQualityAtLeast` | Identity, time, result, coverage, and causal proof fail independently | `ProofQualityV1` vector and package predicates (§22-23) |
| Always connect a process directly to Kubernetes audit | Shared credential/time does not prove which process sent TLS request | Typed exact, shared-authority, temporal-context, or contradiction edges (§23) |
| Matching identifier creates any direct edge | IDs can be shared/reused and need provider-specific semantics | `ProviderEdgeContractV1` with join fields, direction, cardinality, time, and degradation (§23) |
| Bounded ancestor list alone controls future descendants | New child can appear after list is built | Response root/reference inherited at task creation plus reconciliation (§24) |
| Active hostile probes inside compromised production target | Probe may execute attacker-controlled code or change evidence | Readback and passive healthy watch; hostile probes run in isolated qualification fixtures (§24) |
| Publication success proves secret exfiltration | A write/send/provider object does not prove which bytes or source | Separate file-read, publication, packet, and provider results (§18, §25) |
| Bearer token identity inside TLS selects a kernel rule | Kernel sees destination/flow, not HTTP authorization token or verb | Whole-channel rule or existing provider permission/authorization; audit otherwise (§19, §25) |
| Provider audit is a prevention gate | Audit normally arrives after the provider decision | `POST_EFFECT` exact observation/alert plus optional response (§11, §25) |
| Connector catalog definitely reached through mesh | Published evidence may show separate or uncertain paths | Preserve alternate graph branches and proof quality (§23, §25) |
| Shared credential proves exact end-to-end cluster cause | Many actors can use the same credential | Shared-authority edge unless stronger request/session binding exists (§23, §25) |
| AWS access-key ID proves the Linux reader | Key IDs are shared and may be used elsewhere | Lease/session/request/source proof or contextual branch (§23, §25) |
| All AWS activity was external | Timeline can contain internal and external origins | Separate origin branches and do not merge without evidence (§25) |
| GitHub audit token identity is a revocation handle | Audit identity/hash may not be accepted by revocation API | Resolve exact installation/session through provider actuator or report no handle (§24-25) |
| Every memfd/anonymous execution has trusted digest | Writable backing may change or lack stable immutable bytes | Seal/hash/prove immutable backing or classify untrusted executable memory (§16, §25) |
| HF-020 definitely belongs to one protected lineage | Public timeline can leave attribution uncertain | Keep competing branches and claim only proven edge (§23, §25) |
| Configuration specificity plus restrictive action wins | It hides contradictory author intent and stages | Exact conflict and legal-stage compiler (§11-12) |
| Circular admission, reversed GitHub intent, generic AWS revocation | Admission cannot rely on an event emitted after release; GitHub read/write intent was reversed; AWS credentials need typed handle | Existing supported pre-effect authorization where available, local BPF effect control, corrected provider evidence, and exact actuator (§8-12, §24-26) |
| Retained “complete valid” YAML plus a combined key is the golden wire | Prose substitutions, stale standalone vectors, duplicate fields, and open keys are ambiguous | One checked canonical source and generated deterministic CBOR/signature vector in Phase 0 (§12) |
| Broad rollout selector or unstable metric denominator | Selector drift changes authority/health math | Immutable rollout snapshot and named numerator/denominator population (§11-12) |
| Erebor terminates Git/TLS | User explicitly rejects MITM and it expands trust/secrets | Provider-scoped token/gate, whole-channel deny, or honest audit (§19, §26) |
| Workflow digest proves the bytes executed | Generated temp script/local action/dependency can differ | Observe actual executable bytes and mutability; use full artifact provenance and state any integrity gap (§26) |
| Runner callback signature alone proves a step | Job code may call a socket or copy fields; stock runner may expose no unique task join | Exact job + Linux process evidence; exact step only through an existing official interface that supplies the unique join (§26) |
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
| Adapter and node owner both assign security meaning | Competing role decisions and invented fields appear | Adapter forwards documented source fields; `WorkloadBindingOwner` classifies roots and `AuthorizationProofOwner` validates only real authorizations (§34) |
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

The exact registry is:

```text
SupersessionRegistryV1 {
  architecture_revision_digest: DigestV1
  records[] {
    supersession_id
    retained_statement_ids[]
    controlling_statement_ids[]
    replacement_contract_ids[]
    affected_card_ids[]
    forbidden_contract_ids[]
    upstream_source_evidence_ids[]
  }
}

ImplementationCardV1 {
  card_id
  governing_statement_ids[]
  supersession_dependency_ids[]
  implementation_owner
  fixture_ids[]
}
```

Lint performs only checks a program can decide reliably:

```text
every statement/supersession marker has valid unique grammar
every referenced marker, contract, card, fixture, and source ID exists
every supersession has at least one retained statement, controlling statement,
  and replacement contract
every affected card declares the supersession dependency
no card declares a forbidden contract ID
the sorted document marker set equals the registry marker set
the registry and generated heading/statement set share the architecture digest
no explicit correction/abandoned marker is left unregistered
```

Lint does not pretend to solve natural-language equivalence. Human/security
review decides whether new prose repeats an old design and assigns it a
statement/contract ID. Precedence is: hard invariant first; then the exact
registered controlling contract for the named retained statement; then the
local rejected-design rule; then explanatory examples. Two controlling
records that require different physical results for the same exact key are a
document error, not an implementer choice.

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
the baseline solutions remain an existing provider permission/authorization
API, provider audit and response, or denial of the entire channel.

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
ADMIN-EXEC-APPROVAL-001
BOOT-ADMISSION-001
CFG-ROLLBACK-GOLDEN-002
CFG-V1-GOLDEN-002
CHECKPOINT-CREATE-001
CI-OFFICIAL-STEP-JOIN-001
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
AUTHORIZATION-REPLAY-004
ENTRY-CONTAINERS-001
ENTRY-EPHEMERAL-001
ENTRY-EXEC-001
ENTRY-EXEC-002
ENTRY-STOCK-HOOK-FAILURE-002
ENTRY-EXTERNAL-AMBIGUITY-001
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
ENTRY-BINDING-GAP-001
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

The old IDs `ENTRY-CLAIM-TRANSACTION-004`, `ENTRY-HOLD-ATTACK-002`,
`ENTRY-KUBELET-TICKET-001`, `ENTRY-ROOTFS-BARRIER-001`, and `CI-ATTEST-001`
may appear only inside rejected historical text. They are forbidden from the
active registry because they require a held/ticket-aware runtime or patched
runner contract.

### C.2 Exact criterion allocation

`ALWAYS` means core qualification. `WHEN_CLAIM_VECTOR_REFERENCES` activates
only when a release claims that surface. `WHEN_SURFACE_ALLOCATED_AND_ADVERTISED`
activates only after the optional surface has an approved phase and product
claim.

| Criterion | Condition | Exact fixture IDs |
| ---: | --- | --- |
| 1 | `ALWAYS` | `BOOT-ADMISSION-001` |
| 1 | `WHEN_CLAIM_VECTOR_REFERENCES` | `NODE-FLOOR-EXCEPTION-002`, `XNODE-PRIVILEGED-POD-001` |
| 2 | `ALWAYS` | `ENTRY-BINDING-GAP-001`, `ENTRY-CONTAINERS-001`, `ENTRY-EPHEMERAL-001`, `ENTRY-EXEC-001`, `ENTRY-EXEC-002`, `ENTRY-EXTERNAL-AMBIGUITY-001`, `ENTRY-LOSS-001`, `ENTRY-MIGRATE-001`, `ENTRY-NETPROBE-001`, `ENTRY-POSTSTART-001`, `ENTRY-POSTSTART-002`, `ENTRY-PRESTOP-001`, `ENTRY-PROBE-001`, `ENTRY-PROBE-002`, `ENTRY-PROBE-IMPERSONATION-003`, `ENTRY-RESTART-001`, `ENTRY-REUSE-001`, `ENTRY-SLEEP-001`, `ENTRY-START-001`, `ENTRY-STOCK-HOOK-FAILURE-002` |
| 2 | `WHEN_CLAIM_VECTOR_REFERENCES` | `ADMIN-EXEC-APPROVAL-001` |
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
| 10 | `ALWAYS` | `AUTHORIZATION-REPLAY-004`, `ENTRY-EXTERNAL-AMBIGUITY-001`, `ENTRY-PROBE-IMPERSONATION-003` |
| 10 | `WHEN_CLAIM_VECTOR_REFERENCES` | `HF-GRAN-AWS-DRYRUN-001`, `HF-GRAN-GITHUB-MINT-001`, `HF-GRAN-TOKEN-FORGE-001` |
| 11 | `WHEN_SURFACE_ALLOCATED_AND_ADVERTISED` | `CI-CACHE-001`, `CI-CONTAINER-001`, `CI-DEBUG-001`, `CI-DIND-001`, `CI-FANOUT-001`, `CI-GITHUB-TOKEN-001`, `CI-NATIVE-001`, `CI-OFFICIAL-STEP-JOIN-001`, `CI-OIDC-001`, `CI-OUTPUT-001`, `CI-POST-001`, `CI-PR-001`, `CI-RETRY-001`, `CI-RUNNER-REUSE-001`, `CI-STATE-001` |

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

#### D.1.1 Atomic checked-code claims

The crosswalk above is for navigation. The rows below are the atomic claims an
implementation card may cite. Each claim says what the pinned code actually
does and the precise lesson Mithril takes from it. A row is not a statement
about every upstream release or the maintainers' intent.

KubeArmor claims:

| ID | Pinned observation | Mithril consequence |
| --- | --- | --- |
| `KA-CODE-001` | `BPF/enforcer.bpf.c:10-68` returns allow on several missing container, scratch, or path lookups. | A required protected lookup miss denies; it cannot mean “not protected.” |
| `KA-CODE-002` | Main exec enforcement at `enforcer.bpf.c:346-412` keeps its decision when ring reservation fails. | Fix the physical result before best-effort evidence. |
| `KA-CODE-003` | `protectenv.bpf.c:78-81`, `filelessexec.bpf.c:91-95`, `anonmapexec.bpf.c:97-100`, `protectproc.bpf.c:86-89`, and `exec.bpf.c:117-120` allow when event allocation fails. | Every claimed deny path must survive event-allocation failure; these branches become hostile fixtures. |
| `KA-CODE-004` | `core/nriHandler.go:120-240` binds after start and removes enforcement during stop handling. | This callback alone cannot prove first-exec-through-last-task coverage. |
| `KA-CODE-005` | `system_monitor.c:1362-1376` attempts fork-time parent `exec_id` propagation; `processTree.go:133-428` remains PID/procfs assisted. | Learn early correlation, but do not call it synchronous per-task role authority. |
| `KA-CODE-006` | LSM network code at `enforcer.bpf.c:415-648` mainly matches socket type/protocol; CIDR/port rules and NFLOG attribution are separate userspace/nftables paths. | Mithril joins exact current role/domain to socket provenance and final destination itself. |
| `KA-CODE-007` | `shared.h:250-259`, `mapHelpers.go:47-73`, and `rulesHandling.go:414-638` use a per-container inner map mutated row by row. | Map indirection is useful, but immutable full generations and one active switch are Mithril-owned. |
| `KA-CODE-008` | `exec.bpf.c:22-53` uses namespace, TTY, and exec-map context and permits the non-TTY/missing branch. | TTY and inherited observation context are not authenticated probe/admin intent. |
| `KA-CODE-009` | `kubeUpdate.go:1405-1414` recognizes action words while `types.go:640-656` declares an unconstrained string. | Reuse readable allow/audit/block vocabulary only behind a closed validated enum and legal-stage compiler. |
| `KA-CODE-010` | Fork-map value is `u64` at `system_monitor.c:319-328`, but fork code uses `u32` at `:1368-1373`; consumers read `u64` in `shared.h:564-570` and `exec.bpf.c:50-53`. | Do not copy the width mismatch; test full-width propagation behavior. |
| `KA-CODE-011` | File/socket programs omit a trailing BPF-LSM `ret`; capable receives it but returns zero on several paths (`enforcer.bpf.c:650-808`). | Preserve an earlier denial per exact hook and branch; one exec result cannot qualify all programs. |
| `KA-CODE-012` | DNS LSM path at `enforcer.bpf.c:889-1075` is port-53/first-buffer/bounded and has allow-on-miss paths. | DNS parsing is optional context; literal IP, malformed/large traffic, TCP, non-53, DoT/DoH remain under destination/packet policy. |
| `KA-CODE-013` | `networkPolicyEnforcer.go:209-303` builds NFLOG userspace logs from Pod IP and records the first endpoint container; it is not the enforcement key. | Never describe that range as exact per-container or per-process enforcement attribution. |
| `KA-CODE-014` | `kubeUpdate.go:1405-1414` canonicalizes lowercase known values and empty only; unknown strings pass the switch. | Mithril rejects unknown action values rather than inheriting open strings. |
| `KA-CODE-015` | DNS code reads socket destination rather than per-message `msg_name`, only the first iovec, and assumes QNAME at byte 12 (`enforcer.bpf.c:1025-1075`, `shared.h:1221-1263`). | Qualify unconnected UDP, split iovecs, DNS-over-TCP framing, and every parser bound explicitly. |
| `KA-CODE-016` | `enforcer.bpf.c:672-690` enforces reads at `file_open`; `file_permission` returns unless write/append. | File-open coverage does not prove later inherited/passed-fd read-use denial. |
| `KA-CODE-017` | `nriHandler.go:181-214` removes policy in `StopContainer` before the runtime sends its termination signal. | Test shutdown retention separately; the code does not prove Kubernetes PreStop ordering. |
| `KA-CODE-018` | Presets cover selected memfd/shm paths, anonymous `mmap(PROT_EXEC)`, and procfs path opens, not all later `mprotect`, ptrace, process-vm, or perf effects. | Presets seed classifiers and fixtures; they are not complete effect families. |
| `KA-CODE-019` | `mapHelpers.go:59-73` and `rulesHandling.go:466-626` can mutate userspace state and log a failed BPF publish/delete. | Activation is build, exact readback, then publish-or-reject; log-and-continue never activates authority. |
| `KA-CODE-020` | Core attach failures error, while several path-program failures warn and continue (`enforcer.go:133-272`). | A full claim requires every declared link/program ID and behavior read back; reduced coverage is a named tier. |
| `KA-CODE-021` | `enforcer_path.bpf.c:7-73` has separate source/destination link/rename programs, omits trailing ret, and comments out chown. | Qualify each path program, paired order, stacking, and missing operation independently. |
| `KA-CODE-022` | DNS and preset LSM signatures omit trailing BPF-LSM ret. | Run stacking fixtures for main, DNS, path, and every enabled preset; a normal nonmatch may not erase an earlier deny. |
| `KA-CODE-023` | `systemMonitor.go:587-663` may continue after individual probe/reader failure. | Daemon liveness is not coverage truth; every source has an epoch, health state, and gap interval. |
| `KA-CODE-024` | `shared.h:315-395,809-922` bounds dentry walking, rule-key bytes, and prefix scans. | Bounded path text is evidence only; live mount/filesystem/object generation owns authority. |
| `KA-CODE-025` | `shared.h:1221-1263` does not check one user-read result, assumes simple framing, and emits a bounded name; caller does not use parser return. | Parser unknown/failure uses the destination floor or deny, never semantic allow. |
| `KA-CODE-026` | `kubearmor_exec_pids` is a 10,240-entry LRU map; exec preset allows on missing context (`system_monitor.c:261-328`, `exec.bpf.c:35-53`). | LRU is acceptable for hints, never authoritative task/process/role state. |
| `KA-CODE-027` | Outer and inner policy maps are fixed at 256 entries; host policy conditionally consumes an outer slot (`enforcer.go:81-98,283-285`, `mapHelpers.go:128-148`). | Preflight expanded map cardinality and test N/N+1; an over-capacity generation never becomes active. |
| `KA-CODE-028` | `systemMonitor.go:761-789` logs read errors/lost samples, exits on closed or nil reader; enforcement and preset reserve failures have different results. | Record per-source coverage and the actual physical result; never use one generic “sensor loss” statement. |

Tetragon claims:

| ID | Pinned observation | Mithril consequence |
| --- | --- | --- |
| `TG-CODE-001` | `bpf_fork.c:24-104` skips child state when parent state is absent. | Useful observation behavior; protected-child authorization instead needs preallocated fail-closed state or denial. |
| `TG-CODE-002` | Exec code/tests handle non-leader exec and de-threading; userspace deliberately does not cache TID identities (`bpf_execve_event.c`, `process.h`, `exit_test.go`, `process.go`). | Preserve the non-leader lesson while adding per-task synchronous authorization. |
| `TG-CODE-003` | `policy_filter.h:27-95` resolves cgroup membership; userspace can retain conflicting container/cgroup memberships (`state.go:126-153`). | Use cgroup selection as live placement context plus an authenticated binding nonce; reject/quarantine conflicts. |
| `TG-CODE-004` | OCI `createRuntime` can fail creation, while hook/map failures can log and continue (`oci-hook/main.go:443-459`, `rthooks.go:30-110`, `state.go`). | Qualify this exact stock hook's fields, ordering, error configuration, and physical result. Do not infer a held target or later exec purpose. |
| `TG-CODE-005` | `exec_id` and node/cache state are cluster/host derived and tolerate LRU, out-of-order, and GC behavior. | Add attested node-boot identity, typed provider edges, and explicit coverage intervals; do not call cache identity global authority. |
| `TG-CODE-006` | `fork_test.go:25-66` plus `exec_test.go:81-103` provides fork-without-exec coverage. | Adopt the fixture shape and add first-effect/label-order physical oracles. |
| `TG-CODE-007` | Generic LSM supports signal/Override; a separate enforcer and metrics also exist. | Tetragon is not observation-only. Qualify each mechanism separately and add durable causal/response state. |
| `TG-CODE-008` | Observer loss is counted, but event schema lacks Mithril source epoch/sequence/gap interval. | Add WAL-backed ordered coverage truth before negative conclusions. |
| `TG-CODE-009` | Runtime-hook API exposes initial `CreateContainer`, not one-use later-entry tickets. | Initial metadata does not authenticate probes, lifecycle hooks, streaming exec, or later admin entries. |
| `TG-CODE-010` | Generic LSM supports only argument indexes 0..4 and can return zero on output-state miss; a five-semantic-argument hook places chained ret outside that model. | Qualify hook signatures and prior-return behavior individually, including `path_rename`. |
| `TG-CODE-011` | Generic LSM override staging defaults to a one-entry map; insertion failure is ignored and missing state allows. | Saturate concurrency state and make authoritative insertion failure deny. |
| `TG-CODE-012` | One Tetragon binary owns many sensors and streams. | One node gatherer can own many BPF objects/readers; “one gatherer” does not mean one program. |
| `TG-CODE-013` | Generic calls separate monitor/enforce and expose Post/NoPost/Signal/Override actions. | Keep requested disposition separate from physical stage/result; add entry rejection and provider response. |
| `TG-CODE-014` | `bpf_execve_map_update.c` clears match-binary state; the actual cross-hook exec collection uses commit/event/process helpers. | Cite and test the real exec-staging path, not the similarly named cleanup program. |
| `TG-CODE-015` | The socket-block example is a kprobe policy, not a Generic-LSM `lsmHooks` example. | Do not infer Generic-LSM socket-hook coverage from that example. |
| `TG-CODE-016` | A fresh forward inner map is filled before outer publish; later forward/reverse membership changes are row-by-row. | Adopt fresh-map publication only; immutable full replacement and transactional reverse state remain Mithril work. |
| `TG-CODE-017` | Fork code propagates init-tree observation state and protobuf exposes it. | Treat init-tree/TTY/runtime context as evidence, not authenticated entry purpose. |
| `TG-CODE-018` | Fork/exec state is TGID-oriented and userspace omits TIDs. | Process observation is not an authoritative label for every task/thread. |
| `TG-CODE-019` | Generic-LSM actions and staged kprobe/fmod_ret enforcer are separate mechanisms. | Never combine their guarantees or qualification results into one path. |
| `TG-CODE-020` | `bpf_fork.c` is the implementation; `fork_test.go` is the executable fork-without-exec fixture. | Cite program placement and test proof separately. |
| `TG-CODE-021` | OCI `createContainer` case is a no-op; `createRuntime` sends the request, and configured `checkFail` may still allow after error. | Runtime hook is a conditional opportunity, not strict fail-closed admission by default. |
| `TG-CODE-022` | Fresh forward map publishes before reverse mappings, and a later failure does not roll the first publication back. | Do not inherit a claim of atomic bidirectional state. |
| `TG-CODE-023` | OCI hook transports metadata over an insecure gRPC channel or mode-0660 Unix socket and has no signer, nonce, expiry, slot, or held task. | This is useful local metadata plumbing. Authenticate the local source as installation requires, but never turn it into missing kubelet purpose or a held-task claim. |
| `TG-CODE-024` | Bounded exec state can miss insertion, yet a kill-policy test proves enforcement with process marked unknown. | Preserve generic enforcement on unknown observation, but never invent a protected role; use fail-closed preallocated identity or deny. |

`SOURCE-BOUNDARY-001` applies to every row: generic Linux LSM/socket/packet
evidence cannot distinguish Git clone from push or a Kubernetes/cloud verb in
same-destination encrypted TLS, and Linux cannot revoke an already issued
remote session. A separately qualified plaintext instrument may observe more,
but authenticated provider semantics and response still require their real
authority boundary.

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
- [Kubernetes admission webhooks](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/)
- [Kubernetes authentication webhooks and `UserInfo.extra`](https://kubernetes.io/docs/reference/access-authn-authz/authentication/)
- [Kubernetes `pods/exec` `CONNECT` admission example](https://kubernetes.io/blog/2021/12/21/admission-controllers-for-container-drift/)
- [Kubectl plugin contract and limitations](https://kubernetes.io/docs/tasks/extend-kubectl/kubectl-plugins/)
- [Kubelet Checkpoint API](https://kubernetes.io/docs/reference/node/kubelet-checkpoint-api/)
- [CRI runtime API](https://github.com/kubernetes/cri-api/blob/master/pkg/apis/runtime/v1/api.proto)
- [Containerd Runtime v2 exec IDs and lifecycle events](https://github.com/containerd/containerd/blob/main/docs/runtime-v2.md)
- [OAuth 2.0 Device Authorization Grant](https://www.rfc-editor.org/rfc/rfc8628.html)

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
| Durable identity objects and concrete field contract | Chapter 6; Appendix A.9.1-A.9.4 |
| Task/process/thread/entry/exec distinctions and state machines | Chapter 6; Appendix A.9.1-A.9.6 |
| Entry lifetimes and reference accounting | Chapters 6 and 9; Appendix A.9.4 |
| Creator parent versus changing kernel parent | Chapter 6 |
| Native fork/thread/vfork inheritance | Chapter 6 |
| Hook selection, PID finalization, clone-into-cgroup failures | Chapter 6 |
| Exec staging, interpreter/loader chain, non-leader exec, failed exec | Chapter 6 |
| Kubernetes external-entry facts and matrix | Chapters 6-7; §31.1 |
| Checkpoint creation/restore and the rejected full task-set hold | Current no-patch limit in Chapter 7 and §35.1; rejected history in Appendix A.9.9/B.2 |
| Attach and port-forward authority | Chapter 7; unallocated status §35.1 |
| Node-wide floor for attacker-created workloads and exceptions | Chapters 5 and 7; §35.1 |
| One-gatherer runtime integration and cold-boot circularity | Chapters 5 and 7 |
| Rejected runtime setup hold and rootfs-ready barrier | Rejection and active root-classification replacement in Chapter 7, Appendix A.9.7, and Appendix B.2 |
| Streaming exec two-stage fact and rejected stream proxy/ticket | Chapter 7; rejected history in Appendix A.9.7/B.2 |
| Real authorization signed wire, trust, replay, and failure posture | Chapter 8; Appendix A.10; explicitly not stock kubelet/runner intent |
| Authorization consumption variants and state machines | Chapter 8 and Appendix A.10.4; stock roots use classification rather than claims |
| Credential bytes versus protected actuator handle | Chapter 8 |
| Proof vector and use matrix | Chapters 8 and 23 |
| Stock kubelet purpose limitation and identical-command external-root design | Chapters 7-8; §30 Example B; rejected ticket history in Appendix A.9.7/B.2 |
| AWS and Google authority-lease proof, audit limitation | Chapter 8; Chapters 23, 25-26 |
| ExecSync external-root classification and rejected pending-claim algorithm | Chapters 7-8; Appendix A.9.7/B.2 |
| Restricted external/unresolved roots, shutdown, and containment | Chapters 7 and 9 |

### E.3 Original policy, compiled state, and local Linux effects

| Original topic | New location |
| --- | --- |
| Source policy and signed anti-rollback profile | Chapters 11-12; Appendix A.11 |
| Entry rules | Chapter 11 |
| Roles and one transition authority | Chapters 11-12 |
| Effect rules and authority-behavior rules | Chapter 11 |
| Compiler pipeline, conflicts, and precedence | Chapter 12; Appendix A.11.5-A.11.8 |
| Compiled map/decision ABI and lookup semantics | Chapters 12-13; Appendix A.12 |
| Generation activation, retention, retirement, rollback | Chapter 12; Appendices A.11.6-A.11.7 and A.12.1 |
| Cgroup binding identity/reuse and task placement | Chapters 5-7, 13; Appendix A.12.1-A.12.2 |
| Generic pre-effect order and stacked LSM semantics | Chapter 13; Appendix A.12.6 |
| Mount and network-namespace identity | Chapter 15 |
| Synchronous topology invalidation, CAS reconciliation, propagation/automount/referrals | Chapter 15 |
| Executable images, scripts, ELF loader, memfd/anonymous memory, `mprotect`, executable stack/personality | Chapter 16 |
| File and credential objects, namespace mutation, mmap/preexisting mapping, projected-token rotation | Chapter 17 |
| Open-fd provenance and delegated filesystem/local-proxy egress | Chapter 17 |
| Process-shared security state and exact current role | Chapter 18 |
| Threads/forks/cross-entry shared channels and bounded authority domains | Chapter 18 |
| Shared memory/files/IPC/local-inet/process control and persistent resources | Chapter 18; Appendix A.14 |
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
| Observation and coverage records | Chapter 22; Appendix A.15.1 |
| Proof quality vector | Chapters 22-23; Appendix A.15.2 |
| Package windows, watermarks, finding lifecycle | Chapter 22 |
| `HF-PROC-001`, `HF-DW-001`, `HF-XNODE-001` | Chapter 23 |
| Canonical multi-node graph and provider expansion contracts | Chapter 23; Appendix A.15.3 |
| Local lineage restriction and target re-resolution | Chapter 24; Appendix A.15.4 |
| Response application, physical verification, durable result vocabulary | Chapter 24; Appendix A.15.4-A.15.5 |
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
| CI identity, intent body, coordinator-to-task binding | Chapter 26; Appendices A.10.2 and A.16.1 |
| Native/container/service/matrix/reusable/artifact/OIDC/deploy/post/debug/DinD shapes | Chapter 26 |
| Untrusted PR, artifact/cache trust, indirect execution | Chapter 26 |
| Cross-step state and runner reuse | Chapter 26; Appendix A.16.2 |
| CI semantic lowering, credential-delivery boundaries, fixtures | Chapter 26; Appendix A.16; Appendix C |
| Detailed representative and granular Hugging Face action acceptance | Chapter 25; Appendix C; §25 exact action-card contract |

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
