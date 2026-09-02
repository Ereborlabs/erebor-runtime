# Mithril: Linux-Native Prevention, Evidence, And Verified Response

**Status: VALIDATED DESIGN AUTHORITY — 2026-08-08; CONTROL POLICY AND EVIDENCE
AMENDMENT — 2026-08-19; gRPC SERVICE AND IPC AMENDMENT — 2026-08-21;
CAPABILITY-GROUNDED KUBERNETES POLICY API AMENDMENT — 2026-08-23;
STOCK-RUNTIME BOOTSTRAP AMENDMENT — 2026-08-23; STATE-PRESERVING REINSTALL
AMENDMENT — 2026-08-31; KNOWN-PATH ROUTING AMENDMENT — 2026-08-31.** This is
the sole normative Mithril architecture for implementation planning.
Implementation still requires allocation and approval through the master plan
and one named phase. Historical architecture text may explain rejected
designs, but cannot override this file.

The 2026-08-19 amendment adds Control-plane source, rollout, and durable-intake
contracts. It does not change the frozen local BPF decision ABI. Historical
phase results remain bound to their recorded architecture digest. Phase 6.2
must update the affected exact-type closure and Control RPC and schema goldens,
prove compatibility with the completed Phase 6 node contract, and bind its
result and later results to this amended document.

The 2026-08-21 amendment replaces supported custom-framed IPC and the
multiplexed node-control stream with typed gRPC services. It removes generic
transport versions, message kinds, payload envelopes, and correlation fields.
It does not remove domain generations, cursors, digests, request IDs, boot
epochs, or replay rules. Local gRPC retains Unix peer-credential and cgroup
authorization. Remote node gRPC retains mTLS identity binding.

The 2026-08-23 amendment replaces the flattened Kubernetes policy document
with `WorkloadProtectionPolicy` and `WorkloadProtectionException`. The public
resources contain only qualified Kubernetes enforcement fields. Control keeps
one explicit lowering path from the base policy to the wider internal signed
policy document. An exception activates one precompiled grant without creating
another base generation.

The prepared-container amendment adds one internal, typed transition to the
node binding and BPF decision ABI. It treats the verified initial runtime entry
as trusted node infrastructure until the first signed-policy-approved
application exec. It does not add a public policy field, a generic runtime
exception, or a runtime-specific syscall list. Historical phase results keep
their recorded ABI. Phase 6.2 and later results bind the amended ABI and
architecture.

The 2026-08-31 amendment lets the retained runtime gate admit a
version-changed Mithril installer after an ordinary Helm deletion. The
installer replaces the binaries, runtime integration, and recovery manifest.
It does not replace durable Control or Node state. Each state owner performs
only a supported migration before it becomes ready, and the next policy
candidate continues the retained sequence and predecessor chain.

The known-path routing amendment makes a Node-installed route authoritative
for a known mount root. BPF uses the route before it considers mount age. If
no route exists on the source dentry ancestry, BPF selects the oldest unique
mount as the canonical fallback. Initial Kubernetes mounts are one baseline
snapshot. Their creation order does not select policy authority. A later bind
mount does not install a new route and therefore cannot rename its source for
policy evaluation.

The live-policy amendment applies a changed base policy to running processes.
Node builds and verifies one complete immutable generation before it publishes
that generation for a live binding. At a running process's next protected
effect, BPF compares the process generation with the published binding
generation. BPF migrates the process and its state vector under the existing
process transition guard, then evaluates the effect with the new generation.
Processes migrate independently. The system does not stop all tasks or perform
one workload-wide migration transaction. A task's birth generation and the
generation references of existing sockets and other long-lived objects remain
lifetime evidence until their owners release them.

Status: proposed architecture. This document does not authorize an
implementation phase. The
[master plan](./README.md) controls what may be built.

This is the standalone architecture and implementation contract. It uses a
product-first order: actor, permission, physical effect, and proof. Historical
designs may be consulted during review, but they are not normative and are not
required to implement this document.

The acceptance documents are:

- [Hugging Face adversarial acceptance](./hugging-face-adversarial-acceptance.md)
- [Live two-node lifecycle probe](./live-two-node-lifecycle-probe.md)

The incident facts come from:

- [Detailed incident analysis](../../research/hugging-face-agent-intrusion-analysis.md)
- [Normalized 21-event action stream](../../research/hugging-face-agent-intrusion-live-action-stream.md)

## How this document is organized

Parts I-II define the product, trust boundaries, actors, and runtime admission.
Parts III-IV define policy and Linux enforcement. Parts V-VI cover evidence,
response, the Hugging Face incident, and CI/CD. Parts VII-VIII cover checked
upstream lessons, qualification, ownership, and delivery. The appendices hold
exact contracts, rejected designs, fixtures, and sources.

An allocated contract must define every security term and active type. A name
alone is not a contract. Appendix A.8 requires an exact schema or alias before
Phase 0 freezes a type. Unresolved decisions and unallocated work stay explicit.

## Part I — Product, Gap, And Trust Boundaries

### 1. What Mithril Is

Mithril is a Linux-native system that prevents, proves, connects, and responds
to harmful actions made by workloads that an organization already chose to
run.

It handles the hard case: attacker code runs inside a legitimate process. It
has the same Pod, image, Unix user, cgroup, credentials, and network namespace
as legitimate code. No new shell, container, or suspicious binary need appear.

For every protected Linux effect, Mithril answers four questions:

```text
1. Who is acting?
   Exact task -> process -> execution -> independent container entry ->
   native authority state -> workload -> node.

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
response actuators. The control plane reconciles Kubernetes policy desired
state, compiles and distributes immutable signed candidates, durably accepts
normalized evidence, builds the cross-node and provider graph, authorizes
broader response, and tracks whether the physical result was verified.

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
an independent root and identifies its container. The root starts with the
restricted external role. Its next exec can install one declared entry role
only when the executable matches that entry's signed execution rule. A
configured, supported hook may add only the facts that its real interface
provides.

#### 2.3 The process that reads authority may not be the process that uses it

One process can read a token and place it in a shared file, shared memory,
inherited file descriptor, Unix socket, loopback service, or environment for
another process. The second process can then make the network request.

Mithril keeps the processes separate. For sockets, it checks the current
process, live channel, operation, and peer. A pipe has no exact peer for one
write, so the check uses the current process, pipe, and read/write operation.
Other observed pipe users are evidence only.

Shared files and memory use object rules, not invented process pairs. Mithril
checks the operations Linux exposes, such as open, read, write, map, permission
change, and attach. It does not inspect ordinary message bytes. Descriptor
passing may be recorded without tracking the represented object.

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
| Tetragon | Observes kernel process and syscall activity, tracks fork/exec state, filters by cgroup and workload, supports runtime-hook integration, and has real enforcement paths including Generic LSM override and a separate enforcer. | Its event/process model is not by itself Mithril's permission-bearing task, process, entry, and native-family state, and it does not alone provide the complete policy-generation, provider-correlation, and verified-response contract. Its runtime metadata is useful fact, but it does not prove an unexposed probe or lifecycle purpose. |
| Falco | Mature event ingestion, rule evaluation, enrichment, plugin model, and operational detection workflow. | Detection after an event is not synchronous prevention of every physical effect. Falco alone does not authenticate runtime entry roots, install per-task authority before first effect, or prove a response postcondition. |
| Cilium | Strong cgroup/workload network identity, eBPF datapath, service-aware policy, and Kubernetes networking. | A network identity does not distinguish two processes in one Pod, decide a local file or device operation, authenticate a runtime exec root, or prove which in-process code caused a provider action inside TLS. |
| Ordinary EDR | Broad telemetry, analytics, investigation, and response integrations; often valuable for detecting known behavior and fleet operations. | A product that observes after the syscall cannot claim the protected bytes were not read. Process reputation or behavioral scoring is not exact pre-effect authorization. Exact capabilities vary and must be measured rather than dismissed. |
| Seccomp, AppArmor, SELinux, or Landlock alone | Mature local isolation at their supported hooks and policy units. | No one mechanism supplies runtime intent, per-entry identity, object and socket provenance, provider edges, multi-node causality, or verified response. Mithril may compile part of a policy into them where they provide the best physical boundary. |
| Kubernetes admission or network policy alone | Rejects dangerous workload specifications or blocks workload-level flows. | It does not see hostile code already running inside a legitimate process, distinguish same-Pod actors, or govern local files, memory sharing, device ioctls, and inherited descriptors. |

Chapters 15 and 27-29 tie these boundaries to checked KubeArmor and Tetragon
source, the independent Jailer source where exact code exists, and Meta's
separately pinned presentation-level path-matching design.  Later upstream
changes require a new review.

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
  -> Kubernetes API destination is denied for that native process family
  -> a new or unknown process tree receives no application authority
  -> its first governed file/network/device/privilege effect is denied
  -> any completed remote action is joined with authority-owned IDs
  -> response re-resolves every live branch and verifies it stayed fenced
```

Any one of those barriers may stop this branch. The complete product keeps the
later barriers even when the earliest one is expected to succeed.

### 4. Mithril's Unique Contract

These guarantees form one product contract. Removing one weakens the claim.

1. **No workload or platform source changes.** Mithril installs its node and
   control components and may configure existing documented extension points.
   It does not patch platform binaries or change manifests, images, application
   code, process layout, credentials, traffic, TLS, or the agent harness.
2. **One node gatherer.** One Rust process owns all Mithril BPF programs,
   runtime admission, local evidence, and local response. Several BPF programs
   are implementation details of that one owner.
3. **Exact actor before effect.** Every protected task has immutable task
   identity that resolves to mutable process and native-lineage restriction
   state before it can perform a protected effect.
4. **Independent roots never inherit application authority.** A task created
   outside the application tree is an external root, even inside the same
   container. If stock Linux and CRI cannot prove its purpose, Mithril gives it
   the conservative external policy or denies it. Command text and timing do
   not create authority.
5. **One readable source policy.** One signed package defines entries, roles,
   transitions, effects, communication, decisions, responses, and exceptions.
   The compiler rejects ambiguity and creates bounded local records.
6. **Local decisions stay local.** A qualified BPF LSM or cgroup BPF hook
   denies the physical effect synchronously. Central services and existing
   runtime components never sit in a syscall path.
7. **Immutable activation.** Existing actors stay pinned to the generation
   they began under. Their fork/exec/privilege changes follow transitions
   already compiled into that signed policy generation. A partially written
   generation never becomes active.
8. **No invented byte meaning.** Mithril controls covered communication and may
   record descriptor passing. It does not interpret ordinary bytes or promise
   that an allowed peer will not misuse its own authority.
9. **Typed causality across boundaries.** There is no invented remote process
   parent. Kubernetes, mesh, connector, cloud, repository, and CI edges use
   the stable identifiers owned by those systems and carry proof quality.
10. **Coverage truth.** Enforcement, identity, observation, admission,
    correlation, and response health are separate time intervals.
11. **Narrowly authorized response.** The response engine finds the live target
    again, refuses stale or unclear identity, states the real blast radius, and
    checks the physical result.
12. **Claim by fixture, not intention.** Every advertised kernel, Kubernetes,
    and provider combination is backed by a named fixture and
    failure, bypass, event-loss, race, and performance evidence.

#### Claim boundary

Mithril must say where its authority ends:

- BPF cannot decide whether an in-memory Python expression is malicious. It
  decides the expression's later physical effects.
- Reading `os.environ` may use bytes already in memory and cause no new file
  hook. Mithril can still control a later file access, send, provider request,
  exec, device, or privilege effect.
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
  one WorkloadProtectionPolicy CRD, one bounded
    WorkloadProtectionException CRD, and least-privilege Control RBAC
  one Control-owned Kubernetes mutating and validating admission endpoint
  configuration of documented OCI, NRI, runtime, Kubernetes audit/API,
    CI provider, and verification extension points
  small stateless hook adapters that forward to mithril-node when the
    extension point requires a hook executable
  Mithril-owned read-only audit credentials and separately approved
    response credentials
  Mithril BPF programs, maps, links, local WAL, and control connection

not allowed in the no-change baseline:
  patches, forks, or rebuilt kubelet, containerd, runc, CRI, CNI, or CI runner
  replacement of those components with a Mithril-specific build
  changes to applications, developer-authored Pod intent, images, process
    layout, probes, lifecycle hooks, workload credentials, or the agent harness
  traffic redirection, DNS replacement, TLS interception, or a mandatory
  provider proxy
```

The Kubernetes API server can add Mithril-owned scheduling requirements to a
matching Pod through the registered admission endpoint. These requirements
restrict the scheduler to ready nodes derived from the live `mithril-node`
DaemonSet. They do not select the exact node or change application behavior.
The admitted object records the mutation.

The CRD is a Control input. It is not a node policy artifact, node activation
record, evidence store, or graph store. Only `mithril-control` watches the CRD.
It converts an accepted desired revision to the closed policy contract and
distributes an immutable signed candidate. Only `mithril-node` can stage,
read back, probe, and activate the corresponding local generation.

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
| Kubernetes/container runtime | Configure existing audit, mutating-admission, validating-admission, OCI, NRI, or runtime interfaces; read stock APIs; verify their fields, order, timeout, and failure result | Patched kubelet/containerd/runc, new CRI methods, changed application images or commands, or a ticket added to probes/hooks |
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
It must control the later file, network, provider, exec, device, or privilege
effect and state the remaining ambiguity.

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

#### Optional operator-owned L7 mediation

This is deliberately outside the no-change baseline and is
`UNALLOCATED_OPTIONAL`. If a threat requires synchronous semantic prevention
inside an encrypted channel--for example, allowing a source fetch but denying
a source push on the same TLS destination--an operator may explicitly deploy
and own a qualified mediation boundary.

Mithril must never silently inject a proxy, change DNS, install a CA, redirect
traffic, or make a workload trust a new TLS peer. The amendment instead names
the already operator-owned proxy or gateway, its authenticated client and
upstream identities, the exact plaintext semantic it can enforce, its failure
posture, and the physical result of a rejected request. Mithril may consume its
authenticated decision/result evidence and coordinate an authorized response;
the mediation owner remains the only synchronous L7 enforcement owner.

The baseline remains direct TLS, destination/channel control, provider-issued
least authority where available, and post-effect provider evidence. A product
claim may not describe optional mediation as if every workload were behind it.

GitHub does not generally turn an arbitrary existing write-capable bearer token
into a new read-only token. A GitHub App can request an installation token with
narrower permissions only within the installation's granted authority and the
provider's supported rules. That is a provider-issued capability, not token
derivation performed by Mithril.

#### Boot order and installation choices

A DaemonSet alone cannot promise protection before the first workload on a new
node. Kubelet must already run to start the DaemonSet. Mithril therefore uses
Kubernetes Node admission to add a `NoSchedule` quarantine taint to a new Node
that matches the live DaemonSet constraints. The DaemonSet tolerates that
taint. Control removes the taint only after the authenticated node session for
the current boot reports complete BPF and identity readiness.

The live DaemonSet Pod template is the only Mithril node-pool definition. The
operator does not copy its selector into Control policy. Pod admission combines
the DaemonSet selector and required affinity with the Pod's existing
constraints and requires the Control-owned ready label. The Kubernetes
scheduler still selects the exact node. Scheduler-binding admission rejects a
selected node whose authenticated ready session is absent or stale.

This quarantine controls new protected scheduling. Restoring a `NoSchedule`
taint does not evict an existing workload. The last valid local policy remains
active while Control reports the readiness loss.

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

A normal `kubectl exec` uses Kubernetes, kubelet, and the runtime. Its Linux
task starts as a restricted external root. Kubernetes audit records the API
request separately. A cluster may approve a stronger role through a short-lived,
one-use match. This is not an exact request-to-task join. The administrator
accepts the small risk that an identical runtime-created root wins the race.

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

`kubectl-mithril` waits for browser approval before it sends `pods/exec`.
The webhook never waits for a person. After approval, the plugin sends one
ordinary Kubernetes `CONNECT pods/exec` request and attaches the terminal.
Because plugins cannot replace built-in `kubectl exec`, the command is
`kubectl mithril exec`.

The browser uses the organization's identity provider. It shows the cluster,
Pod UID, container, argv, stream settings, requested role, expiry, and
approver. A workstation may use OIDC with PKCE. A headless client may use a
device code. The code finds the pending request; policy still decides whether
self-approval or a second person is required.

The requested operation is exact and one use. Its later Linux-task binding is
intentionally a bounded next-match association rather than an exact propagated
request ID:

```text
readable approved-administrative-exec view:
  approval_id
  authenticated_requester
  authenticated_approver
  cluster_id
  namespace
  pod_uid
  full_container_id
  container_generation
  approved_argv
  stdin_stdout_stderr_tty_flags
  approved_role_id
  policy_generation
  target_node_id
  issued_at
  expires_at
  one_use = true
  task_binding = NEXT_MATCHING_RUNTIME_EXTERNAL_ROOT
  requester_accepted_rare_binding_race = true
```

Mithril issues this authorization; kubelet does not. The plugin receives a
short-lived, memory-only exec credential. A stock Kubernetes authentication
integration validates it and puts the non-secret approval ID in
`AdmissionReview.userInfo.extra`. Its identity can use only the protected
`pods/exec` path, not the requester's general permissions. The validating
webhook rejects ordinary `kubectl exec`, curl, modified clients, and replay
without a live approval.

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

The webhook rejects if the node is offline, the container changed, slot
installation fails, or any value differs. Human approval already finished, so
only the short node round trip must fit the webhook deadline.

`mithril-node` remains the only node gatherer and BPF owner. Control sends the
approved request over the node's authenticated control stream. The node
verifies the Pod UID, full container ID, container generation, cgroup binding,
policy generation, and deadline before arming one short-lived slot.

Every runtime-created root is restricted before it can act. Only such a root
may inspect the slot. The approval preserves the exact argv that the
administrator entered, including a command such as `bash`. Before approval,
the node resolves that command in the target container's mount view, working
directory, and effective `PATH`; the browser displays the resolved path and
executable identity. Syscall-entry BPF records a bounded argv candidate from
mutable user memory. This candidate is not authority. At the exec-file open
that builds `linux_binprm`, BPF can provisionally allow only the same task when
the candidate, armed slot, exact executable, restricted external root, binding,
generation, and deadline all match. The slot stays `ARMED` and this preflight
grants no role, exception use, or file permission. At the deny-capable
`bprm_check_security` hook, BPF matches the same facts, then atomically changes
the slot from `ARMED` to `RESERVED`. If the compiled action selects a bounded
exception, this deny-capable path atomically consumes that exception under the
slot's `claim_slot_id`. The task stays in its restricted role. At
`security_bprm_committing_creds`, BPF compares the complete copied kernel-owned
argv with the reservation. At `sched_process_exec`, BPF compares the successful
process image argv again. Only an exact final match can consume the slot and
install the administrative role. The total argv limit is 4096 bytes. Missing,
truncated, changed, or over-limit input does not match. There is no argv or
executable-content hash.

A late mismatch or read failure occurs after the exec point of no return. BPF
cannot roll back that exec. It must leave the task without the approved role,
mark the task and reservation fail-closed, queue `SIGKILL` before user mode,
and emit a critical tamper observation. The node persists and reports the
observation. It does not decide whether the argv matches.

The exec caller can be any thread in a multithreaded process. Candidate state
is task-local. Competing threads can prepare candidates, but only the existing
process transition guard and the slot's atomic `ARMED` to `RESERVED` change can
select one winner. The match does not require `live_thread_refs == 1`.

The webhook checks TTY and stream flags, because stock Kubernetes does not
carry them into the Linux task. They are not BPF match fields. Therefore
another eligible root in the same container with the same executable object
and arguments can win the slot race even with different streams. The approving
administrator accepts this limit. Containerd exec IDs may improve later
evidence, but they are not required for the match.

```text
non-external or application task:
  keep existing lineage; never inspect the slot

restricted external root with exact live match:
  pass only its exact exec-file open; keep ARMED and grant no role
  ARMED -> RESERVED at the deny-capable bprm hook
  consume any selected bounded exception under the claim-slot receipt
  keep the restricted role while exec is pending
  check every script/interpreter/executable candidate
  verify copied argv at committing-creds
  verify process image argv at successful exec
  RESERVED -> CONSUMED and switch role only after the final match

early no match:
  keep the restricted role or deny the exec; do not reserve the slot

late mismatch or read failure:
  grant no role; close the reservation; queue SIGKILL; emit critical evidence
```

Descendants of the approved task inherit that bounded administrative lineage.
Every later exec, file, mapping, socket, device, process-control, and privilege
effect still passes the normal policy. Approval does not disable Mithril. A
typical diagnostic role may allow a shell, logs, and named internal health
endpoints while still denying ServiceAccount-token reads, runtime sockets,
mount, BPF, ptrace, host devices, persistence, and arbitrary Internet egress.

The accepted race is bounded as follows:

- Application descendants cannot consume the slot.
- The slot exists only after approval, for one container generation and a short
  deadline.
- One exact matching external root atomically reserves and consumes it.
- An identical probe, hook, runtime exec, or approved session may win first.
- Replacement, restart, expiry, map/sensor loss, or replay invalidates it.

The evidence chain is:

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
direct runtime caller, two identical approved sessions, different stream
shapes, replacement, restart, and expiry. It proves:

- admission checks stream flags, but BPF does not;
- application children never consume a slot;
- different, missing, truncated, or over-limit argv never matches;
- at most one identical external root wins the accepted race;
- failed exec consumes the slot without granting the role; and
- every non-winner stays restricted.

Without explicit cluster and administrator acceptance, the stronger role is
unavailable.

PostStart, PreStop, startup, readiness, and liveness probe entries use the same
transaction. Their syscall-entry argv is provisional. Their exact exec-file
preflight grants no role. Their deny-capable `bprm` step reserves one task-bound
entry attempt. The two late hooks verify copied and installed argv before the
probe role activates. A late mismatch uses the same fail-closed response and
critical evidence. A declared probe is reusable, so the successful transaction
consumes only its per-task attempt. It does not consume the reusable
declaration.

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
| `ProcessSecurityStateV1` | Current execution, role, policy generation, native authority state, response set, and exec state shared by all threads | This is the sole current process authority |
| `ProcessInstanceV1` | One exact live process interval | Used for live response after revalidation |
| `process_lineage_id` | Durable process identity through exec/reparent/PID coordinate changes | Used by the causal graph |
| `ImageProvenance` | Immutable executable, script/binfmt chain, ELF loaders, and source exec event | Several processes may share provenance after fork |
| `ProcessExecutionInstance` | One process using one image during one time interval | Fork creates a new process execution; exec creates another in the same lineage |
| `AuthorityDomainStateV1` | Restrictions shared only by one native process family | Threads and native fork descendants inherit it; IPC never joins independent roots into it |

The exact layouts appear in Appendix A. The hot-path read order is always:

```text
task label
  -> current process state
  -> native authority state named by current process state
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

`task_alloc` occurs before PID/TGID/start-time/pidfd coordinates exist. It
allocates opaque IDs and preallocated state only. A tested pre-wake point fills
the existing coordinate slots after PID assignment. It allocates nothing and
grants no permission. After visibility, Rust may append pidfd revalidation.

If coordinate finalization fails, the label points to
`FAIL_CLOSED_UNKNOWN`. The child cannot perform a protected effect.

`ID-TASK-COORD-FINALIZE-006` pauses before and after PID assignment and covers
leader-first exit, TID reuse, missing `PIDFD_THREAD`, and non-leader exec. It
proves that no PID-derived field exists before finalization and that no
incomplete record is reported as runnable. Phase 4
`LSM-DENY-SATURATION-001` owns physical map-saturation failure.

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

1. `mithril-control` watches Kubernetes and records the persisted Pod UID and
   scheduler-selected node. It delivers signed exact workload material only to
   that node. `mithril-node` verifies the material against the container
   runtime's supported read-only API and builds a binding from full container
   ID and cgroup lifetime to Pod UID, container name, image digest, and policy
   generation.
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
   later independent root first receives `RUNTIME_EXTERNAL_RESTRICTED`. During
   its exec, only such a restricted external root may atomically consume the
   complete approved-administrative-exec slot from Chapter 6 as the next exact
   executable-and-argv match. This exception carries the recorded
   administrator-accepted race. An unresolved protected task receives the local
   fail-closed floor.
6. Every file, exec, socket, device, privilege, and process-control hook reads
   the task result before making its decision. Event delivery is not on this
   decision path.
7. Userspace later enriches the evidence with Kubernetes audit or runtime
   events. Later enrichment may improve attribution, but it cannot rewrite a
   past allow or pretend that unknown purpose was known before the effect.

The cgroup binding and restrictive defaults must exist before Mithril claims
prevention for a container. If a process runs before the binding exists, the
honest result is either a denied protected effect or a recorded start gap. A
qualified synchronous OCI prestart hook can prove the ordering for its exact
runtime configuration. Snapshot CRI discovery cannot make that claim.

This prestart ordering applies to task identity. It does not make the held
task's final mount topology available on the qualified runc configuration.
Mithril therefore does not resolve an `EXACT` path selector from the OCI
prestart request. The current stock containerd path resolves `EXACT` selectors
when authenticated CRI inventory reports the container as `Running` and
supplies its final init PID. This path records a start gap. It does not claim
that exact-object authority existed before the container process started.

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

This architecture marks the full node floor
`PARTIAL_PHASE_6_2_INCIDENT_FLOOR`. Phase 6.2 owns the exact incident case:
admission rejects the hostile Pod specification, and retained BPF state denies
the hostile unmatched task's first covered host-secret, mount, device,
privilege, process-control, or network effect if admission is bypassed. Phase 8
owns signed exceptions and the complete typed field and runtime matrix. Phase
11 must test the combined result before a release claims complete prevention
of the privileged-Pod branch.

#### Administrative decommission

Deleting Kubernetes objects is not authorization to relax node enforcement.
An ordinary Helm uninstall removes the release objects. It leaves owned host
runtime hooks, the OCI base spec, the containerd default-runtime fragment, and
pinned BPF links, maps, and decisions in place. Containerd invokes the hook
without a retained NRI process and without a RuntimeClass. The absent node
admission socket makes a matching protected start fail closed. The retained
hook rejects the exact hostile unmatched OCI shape before its initial process.
It admits a version-changed Mithril installer only when the installer command,
owner, host paths, writable mounts, privileges, and socket match the retained
installation. The installer replaces the Mithril binaries, runtime
integration, and exact recovery manifest. It does not replace Control or Node
durable state. The new Control and Node reopen their existing state, run only
supported owner-controlled migrations, and continue the existing policy
sequence and predecessor chain. The hook then permits only the exact Control
and Node recovery commands and security-sensitive OCI shapes recorded by the
new manifest. The Control shape includes its non-root user and supplementary
group. It does not use an executable digest for those exceptions. A failed or
unsupported migration keeps admission closed and leaves the original
state intact. Kubernetes metadata is not installer or recovery authority.
Retained BPF state continues to govern existing bindings and denies the
incident's first covered effect after a direct non-CRI bypass.

Decommission uses an independent offline signing key. Kubernetes ServiceAccount
credentials, a CRD, a label, an annotation, a Helm release, Control status, or
`system:masters` authority cannot replace this signature. The signed payload
contains only:

```text
NodeDecommissionAuthorizationV1 {
  cluster_uid
  node_id
  node_boot_id
  expires_at_utc_ns
  nonce
}
```

The signature envelope adds the signer key ID, algorithm, canonical payload,
and signature. Control stores and relays the artifact unchanged over the
existing authenticated node session. Control cannot mint or edit it.

The node verifies the independent key, signature, exact cluster, node, current
boot, expiry, and unused nonce. It refuses decommission while a protected
runtime binding is live. It durably records the accepted nonce before it
changes physical state. Control then removes scheduling readiness and
quarantines the exact Node. The node closes admission and removes only its
marked containerd fragment, OCI base spec, recovery manifest, hook documents,
and hook binary. It restarts containerd and reads back that the default runtime
no longer invokes the hook. It then removes its pinned links and maps and reads
back absence. It durably records completion and acknowledges the exact
authorization. Control removes only its readiness label, identity annotations,
and quarantine taint after that acknowledgement. The operator can then remove
the Helm release.

If Helm is removed first, the retained host state stays active. The operator
must restore the same node owner or use the host decommission entry point with
the same valid artifact. Helm deletion itself never enters the decommission
state machine.

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
does. It also cannot send a reusable intent count. It sends explicit one-use
slots. The separate locally signed `ExceptionV1.maximum_uses` is enforced by
the generation-local BPF owner in Appendix A.11.5.1.

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

Reference ownership is explicit. Every task, process, entry, native authority state,
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
| `INV-EFFECT-001` | Rules are reduced to exact final decision keys. The bounded path graph in Chapter 15 may first produce a candidate selector, but exact mount/object revalidation produces the final key. Different physical results need a signed override or compilation fails. Missing required identity, generation, classifier, table, or response state denies. | An output path symlinked to a token resolves to the token object; conflicting allow/deny does not depend on “specificity” or file order. |
| `INV-EFFECT-002` | Telemetry, WAL, ring, rate-limit, or central-service pressure cannot turn a computed local denial into allow. | Fill the event ring while repeating token reads; every read still fails and loss counters increase. |
| `INV-POLICY-001` | Only a signed, validated, compiled, read-back generation can authorize. Learning never self-authorizes. | Observed malicious Kubernetes API use becomes a review candidate, not a new allow row. |
| `INV-POLICY-002` | Node publishes only a complete generation. BPF migrates each live process at its next protected effect. Old generations stay until every typed holder has ended. | Generation 42 is complete and reachable until Node publishes complete generation 43. Task T migrates to 43 at its next effect. Socket S keeps its declared generation-42 lifetime. Generation 42 is removed only after task, socket, object, and response references reach verified zero. |
| `INV-K8S-001` | Initial container roots, native descendants, separate init/sidecar/ephemeral containers, and later external roots stay distinct. Indistinguishable external purposes never receive invented roles. | An application child running `/app/healthcheck` keeps application lineage. Readiness and `kubectl exec` roots running the same bytes both receive the restricted external role unless an existing qualified interface proves more. |
| `INV-K8S-002` | Shutdown is not a bypass. | A contained `PreStop` cannot read a Secret or send to the public Internet. |
| `INV-IPC-001` | Independent roots remain separate. Their communication uses one bidirectional relationship or the configured unmatched result. Descriptor passing may be separate evidence, never exact represented-object provenance. | Converter and uploader may exchange bytes on their Unix socket, an unknown peer alerts, and an observed `SCM_RIGHTS` message records only that descriptor passing occurred. |
| `INV-GRAPH-001` | Native parent edges never cross a node. | A node-A API request and node-B Pod root join through Kubernetes/runtime IDs, not a false process-parent edge. |
| `INV-RESPONSE-001` | Response re-resolves the live physical target and verifies the postcondition. | PID reuse makes a queued PID-only kill fail safely; a pidfd/task-cookie/cgroup match is required. |
| `INV-COVERAGE-001` | Missing hooks, sequence gaps, start gaps, ambiguous entries, and unavailable provider feeds narrow the claim. | A GitHub feed outage yields an explicit unknown interval, never “no write occurred.” |

The original phrase “most specific deny wins” is an abandoned design. There is
no total order between, for example, a role-exact/object-wildcard allow and a
role-wildcard/token-exact deny. Both reduce to the same exact final decision
cell; without a signed override edge, the compiler rejects the profile. The
same rule applies to overlapping hierarchical path terminals in Chapter 15.

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

"First protected hook" is not "first instruction." CPU-only code may run before
a file, socket, exec, device, or privilege hook. Preventing process creation or
CPU use requires a qualified task-creation hook, a Seccomp floor *if the later
Seccomp surface is adopted and installed at process start*, a supported runtime
admission hook, `pids.max`, or a CPU controller. A file hook cannot claim that
result.

### 11. The Operator Uses A Capability-Grounded Kubernetes Policy

Production Kubernetes mode has one namespaced base-policy kind,
`WorkloadProtectionPolicy.mithril.erebor.dev`, and one namespaced bounded
exception kind, `WorkloadProtectionException.mithril.erebor.dev`. These
resources expose only the enforcement surface that Control, node lowering,
the BPF hooks, and the Kubernetes runtime path can use. They do not expose the
wider internal policy document.

The stored typed `.spec` is the desired-state source. Kubernetes object UID and
generation identify a source revision. Status, `resourceVersion`, labels, and
annotations do not grant policy authority. A restricted offline policy form
uses the same `WorkloadProtectionPolicy.spec` schema for review, import, and
qualification. It cannot activate production Kubernetes policy directly.

Control is the only CRD reader that can create signed node policy. It derives
cluster, namespace, controller, ServiceAccount, Pod UID, full container ID,
selected Node, node UID, boot, cgroup lifetime, and internal capability and
proof facts from authenticated platform state. None of those facts is a user
selector. The Kubernetes scheduler selects the exact Node from the constraints
that Mithril derives from the live `mithril-node` DaemonSet.

#### The base policy resource

```yaml
apiVersion: mithril.erebor.dev/v1alpha1
kind: WorkloadProtectionPolicy
metadata:
  name: conversion-worker
  namespace: datasets
spec:
  podSelector:
    matchLabels:
      app: conversion-worker

  mode: Protect

  containers:
    - names: [worker]
      kinds: [Application]
      images: [immutable-image-reference]

      applicationEntry:
        executionRule: application-entry
        role: worker

      additionalEntries:
        - name: initialize-cache
          kind: PostStart
          executionRule: initialize-cache-entry
          role: cache-initializer

      administrativeEntry:
        role: administrator

      externalRole: runtime-external

  roles:
    - name: worker

      files:
        - name: allow-worker-runtime
          path: /usr
          recursive: true
          operations: [OpenRead, Read, MmapRead]
          action: Allow

        - name: deny-service-account-files
          path: /var/run/secrets/kubernetes.io/serviceaccount
          recursive: true
          operations: [OpenRead, Read, MmapRead]
          action: Deny

      execution:
        - name: application-entry
          path: /usr/bin/conversion-worker
          recursive: false
          operations: [Execute]
          action: Allow

        - name: allow-worker-binaries
          path: /usr/bin
          recursive: true
          operations: [Execute, MmapExecute, Mprotect]
          action: Allow

      network:
        socketControls:
          - operations: [Create, Shutdown]
            action: Allow

        destinations:
          - name: result-service-addresses
            operations: [Connect, Send, Receive]
            protocols: [TCP]
            cidrs: [declared-address-prefix]
            ports:
              - first: 443
                last: 443
            action: Allow

      processControl:
        - name: signal-probe
          targetRole: worker
          operation: Signal
          signals: [0]
          action: Allow

      unixStreams:
        - name: worker-helper
          peerRoles: [helper]
          action: Allow

    - name: cache-initializer
      files:
        - name: deny-cache-secrets
          path: /var/run/secrets
          recursive: true
          operations: [OpenRead]
          action: Deny
      execution:
        - name: initialize-cache-entry
          path: /opt/worker/hooks/initialize-cache
          recursive: false
          operations: [Execute]
          action: Allow
      network:
        socketControls: []
        destinations: []
      processControl: []
      unixStreams: []

    - name: administrator
      files:
        - name: deny-administrator-sensitive-file
          path: /run/restricted
          recursive: true
          operations: [OpenRead]
          action: Deny
      execution: []
      network:
        socketControls: []
        destinations: []
      processControl: []
      unixStreams: []

    - name: runtime-external
      files: []
      execution: []
      network:
        socketControls: []
        destinations: []
      processControl: []
      unixStreams: []

  exceptionGrants:
    - name: temporary-file-access
      fileRules: [deny-service-account-files]
      maximumDuration: 5m
      maximumUses: 1
```

Every Pod container must match exactly one `containers` entry. An unmatched or
multiply matched container rejects admission. `images` contains digest-pinned
immutable image references, and admission preserves that match on updates.
Container kinds are `Init`, `Sidecar`, `Application`, and `Ephemeral`.

A role is a static authority label. The application entry references one exact
non-recursive `Execute` rule in its role. Each additional entry references one
such rule in its own role and declares one fixed lifecycle or exec-probe kind.
The kind documents and validates the Kubernetes use. BPF receives only the
validated entry table and does not distinguish Kubernetes lifecycle kinds. An
approved administrative entry uses the existing signed one-use admission
slot. A later root that does not match one admitted entry receives
`externalRole` and remains fail-closed. Each admitted entry installs only its
referenced role. Forked processes inherit that role. No entry inherits or
unions the application role. The CRD has no native role transition,
process-state bit, state transition, maximum native depth, or fork-role field
because the node does not lower those fields into active policy.

File rules and execution rules use canonical paths. Version 1 supports a
non-recursive allow or deny and a recursive deny. A recursive allow is accepted
only after its legitimate Kubernetes runtime control passes physical
qualification. Before that proof, Control rejects it as unsupported. The
example shows the intended recursive allow after that gate passes.

File operations are `OpenRead`, `OpenWrite`, `Read`, `Write`, `MmapRead`,
`MmapWrite`, `Create`, `SetAttributes`, `Unlink`, `Link`, and `Rename`.
Execution operations are `Execute`, `MmapExecute`, and `Mprotect`. A path may
deny the projected ServiceAccount mount, but the result is a path denial. It is
not semantic projected-token identity, rotation binding, named-volume identity,
immutable-artifact identity, or content identity.

Network destination rules contain IPv4 or IPv6 prefixes, `TCP` or `UDP`, port
ranges, and the applicable `Connect`, `Send`, `Receive`, or `Bind` operation.
Socket controls contain the qualified address-free `Create`, `Listen`,
`Accept`, `Shutdown`, or socket-option operation. Node enforcement retains
creator authority, intersects current-actor authority, and validates the final
address. The CRD has no Kubernetes Service reference, Pod destination
selector, DNS name or query rule, TLS or HTTP meaning, provider meaning, or CNI
or service-mesh guarantee.

A Unix-stream rule grants or denies one role-to-role relationship for connect,
send, and receive as one unit. Stale, unmatched, inherited, or passed endpoint
use is revalidated and denies when the relationship is not active. Pipes, Unix
datagrams, shared memory, SysV IPC, zero-copy channels, and generic
asynchronous IPC authority are not supported.

A process-control rule can match an exact signal number, including signal zero,
against an exact target role. Unmatched signals deny. Exact ptrace requests can
be denied. Positive general ptrace authority is not exposed.

`action` is `Allow` or `Deny`. Unlisted protected operations use the fixed
conservative denial that Control lowers into the internal policy. In `Protect`
mode, a policy denial returns the operation-specific safe result. In `Observe`
mode, that policy denial becomes would-deny evidence. Missing identity,
unsupported objects, and corrupt state remain fail-closed in both modes. The
operator cannot choose errno, capability IDs, proof predicates, or other
compiler inputs.

Overlapping rules with different actions reject. Rule order, object creation
time, name, and “deny wins” do not resolve a conflict. More than one matching
`WorkloadProtectionPolicy` also rejects the Pod. Control keeps the previous
valid non-conflicting generation for an existing target.

#### The bounded exception resource

The base policy can name a file-rule grant and its maximum duration and use
count. A separate resource requests one exact instance:

```yaml
apiVersion: mithril.erebor.dev/v1alpha1
kind: WorkloadProtectionException
metadata:
  name: conversion-worker-temporary-file-access
  namespace: datasets
spec:
  policyRef:
    name: conversion-worker
  grant: temporary-file-access
  target:
    pod:
      name: conversion-worker-7f8d4
      uid: exact-pod-uid
    containerName: worker
  requestedDuration: 2m
  requestedUses: 1
```

The exception spec is immutable. It can request only a same-namespace policy,
a named `exceptionGrants` entry, one exact Pod UID, one matching container, a
duration no greater than the grant maximum, and a use count no greater than the
grant maximum. Version 1 grants only the named denied file rules. It exposes no
network, IPC, device, privilege, or mount exception.

At base-policy compilation, each named grant produces conditional allow cells
for the referenced denied file rules and a generation-local exception handle.
The base generation installs no active runtime binding for that handle. A
missing, inactive, expired, exhausted, or mismatched binding therefore keeps
the base denial. This precompiled indirection lets a later exact exception
affect an existing task: the effect gate reads the live exception binding and
runtime state for every use, so no task or base-policy generation migrates.
This path uses the existing exception-handle binding, runtime-state, receipt,
and effect-decision ABI. Phase 6.2 does not change the frozen BPF ABI.

The exception object is a bounded request, not a compiled authority record.
The API server authenticates and authorizes the writer through separate
exception-writer RBAC. Control resolves the stored source, base policy, and
live Pod; resolves the role, named rules, precompiled decision cells, selected
Node, current boot, and active base-policy generation; and signs the bounded
exception candidate. The stored
object proves accepted desired state, but it does not prove which human wrote
it. The resource cannot supply approval proof, compiled keys, authority deltas,
policy or candidate digests, or a node target. The node consumes a use
atomically and reports a durable receipt. Expiry, exhaustion, deletion, or
revocation closes that runtime instance through a signed revocation without
resetting the consumption record or migrating the base policy generation.

#### Deliberately absent fields

| Field | Reason |
| --- | --- |
| States and native transitions | Control validates internal forms, but the node does not lower them. |
| Device rules | Exact local ioctl enforcement exists, but scheduled-Pod object measurement is not integrated into the runtime gate. |
| Capability or BPF permission rules | Only conservative denial is qualified; positive granular authority is not. |
| Mount permission rules | Mount invalidation and fail closure exist, but complete mount authority is not qualified. |
| ServiceAccount-token target | Rotation binding is not qualified. |
| Container-image target | Immutable executable and content proof is not qualified. `containers.images` is admission matching only. |
| Kubernetes Service destination | Current active network policy accepts address prefixes only. |
| Audit severity and finding routes | Phase 7 does not yet own the finding lifecycle. |
| Response actions | A later phase owns response. |
| Arbitrary policy errno | The compiler selects the fixed safe result for each operation. |
| User capability IDs or proof predicates | Control derives them. |
| User node selector | The DaemonSet and scheduler flow own node selection. |

The internal closed policy can retain fields needed by host mode and later
qualified phases. Their presence in `PolicyDocumentV1` does not make them part
of either Kubernetes CRD. Control owns one explicit lowering function from the
public base policy to that internal document. A bounded exception resolves a
grant that the bound base generation already compiled; it does not rewrite the
policy document.

### 12. Compiler, Signature, And Atomic Activation

An accepted base policy, or the offline restricted base-policy form, is lowered
into closed `PolicyDocumentV1` bytes. Named exception grants become inactive
conditional cells in that base policy. A `WorkloadProtectionException`
activates one exact runtime instance separately.
The signed profile uses deterministic CBOR
and Ed25519 with domain separator
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
stored base-policy revision or offline base-policy review source
  -> immutable KubernetesDesiredSourceRevisionV1 in production Kubernetes mode
  -> capability-grounded public-to-internal lowering
  -> closed canonical PolicyDocumentV1
  -> bounded schema, registry, capability, and source-revision validation
  -> selectors resolved to immutable workload snapshots
  -> container entries, static roles, and supported effects checked for reachability
  -> non-path selectors expanded to a finite exact decision universe;
     hierarchical path components compiled to the bounded resolver in Chapter 15
     and then reduced to an exact final object decision key
  -> conflicting public rules reject; exception grants compile inactive cells
  -> unsupported internal families remain fixed empty or conservative
  -> simulate against a recorded legitimate-workload baseline
  -> human approval
  -> assign issuer sequence and sign the immutable profile
  -> immutable signed per-node delivery candidate and target snapshot
  -> authenticated Control-to-node delivery
  -> node signature, validity, target, replay, and anti-rollback validation
  -> write a completely inactive generation
  -> read back every descriptor, row, default, membership, and digest
  -> run controlled allow and deny probes
  -> publish the active-generation handle for the live binding
  -> BPF migrates each running process at its next protected effect
  -> authenticated node activation acknowledgement and rollout inventory
```

The bounded exception path is separate:

```text
stored exception source revision
  -> resolve the active base-policy generation and named precompiled grant
  -> resolve exact Pod UID, container, selected Node, and current boot
  -> validate requested duration and uses against the base grant
  -> sign one target-bound exception activation or revocation candidate
  -> authenticated Control-to-node delivery
  -> verify source, base generation, grant, target, time, and replay state
  -> ExceptionAuthorityOwner activates or closes the runtime instance
  -> BPF effect gate atomically consumes each permitted use
  -> durable receipt and bounded exception status
```

The API server's accepted object under configured RBAC records desired state.
A watch event does not prove the human actor. Any separate human approval
required by the internal rollout remains required and binds the exact
base-policy source revision. Any separately required exception approval binds
the exact exception source, base generation, grant, and target.
The Control signing key proves candidate authenticity; it does not invent
approval. There is no cluster-wide atomic activation. Each node reports its
exact candidate and generation state. A partial rollout stays visible and
limits later findings and policy claims.

Base-policy deletion removes the policy from Control's complete desired-bundle
inventory. It does not create another policy candidate. The node keeps the
last valid generation while its runtime inventory still reports a matching
container lifetime or Control is unavailable. After runtime inventory proves
that lifetime is absent, the node removes each kernel binding owned by the
stored profile generation and node session. The mutable runtime binding alias
is not the cleanup key. Reference readback must permit generation removal.
Exception deletion, expiry,
exhaustion, or revocation still sends a signed close operation to the exact
runtime instance. A Kubernetes finalizer reports reconciliation progress only;
removal of the finalizer is not node authority.

This is the Mithril form of Tetragon's retain, rebuild, and replace lifecycle.
Tetragon keeps pinned enforcement across daemon loss, rebuilds current desired
policy, and removes replaced pinned state after successful reconstruction. Its
Pod cleanup uses stored Pod, container, and cgroup identities. Mithril uses the
stored profile, generation, node boot, and label epoch as its equivalent pinned
membership key. This key still matches when the runtime binding alias differs
from the scheduled authority alias. Mithril keeps its signed activation and
anti-rollback boundary for desired changes. Local stale-membership removal is
not a new policy. See
[persistent enforcement](https://tetragon.io/docs/concepts/enforcement/persistent-enforcement/),
[persistent gRPC policies](https://tetragon.io/docs/concepts/enforcement/persistent-grpc-policies/),
and [policy-filter state cleanup](https://github.com/cilium/tetragon/blob/main/pkg/policyfilter/state.go).

Compilation rejects ambiguous unequal-budget entries, escalation cycles,
unreachable roles, unsupported deny hooks, path-only objects marked immutable,
TLS verbs claimed from network-only evidence, response without a revalidation
key/postcondition, fail-open required classifiers, hard-invariant overrides,
and artifacts beyond verified BPF map/stack/instruction/depth/latency bounds.

Observation produces a candidate. It never writes active allow rows. Promotion
requires review, simulation, signature, probes, and rollout health.

#### Exact conflict rule

Rules are first separated by physical stage. Wildcards outside a hierarchical
path selector are expanded against the closed generation universe.
Hierarchical path components compile to the bounded resolver in Chapter 15;
its output must pass exact mount/object revalidation before it becomes a final
decision key. Identical physical decisions for one exact key may merge
compatible evidence and routing. Different physical results need a signed
`overrides` or exception edge naming the other rule and exact key delta.
Without that edge, compilation fails.

Priority controls display/notification order only. YAML order, wildcard count,
severity, “more specific,” and “deny is safer” never choose authority.

#### Generation activation and retirement

Generation handles are nonzero, monotonically allocated, and never reused
within `(node_boot_id, label_epoch)`. Every descriptor repeats that epoch.
Losing the allocator state while protected objects survive is fatal and holds
the workload fail-closed.

New external roots use the published binding generation. An existing process
migrates from its current generation to the published generation at its next
protected effect. Its tasks keep immutable birth-generation references for
exit accounting and evidence. Existing sockets, files/shared objects, native
authority states, VMAs, checkpoint state, pending entries/execs, derived
kernel capabilities, and response plans keep their typed lifetime generation
references.

```text
PREPARING: no holder may use or acquire
ACTIVE: existing holders may use; new holders may acquire with readback
RETIRING: existing proved holders may use; new references are denied
missing or unknown: deny and report corruption
```

Retirement requires all typed counters at zero, no owned reference tombstone
in complete iterator/WAL reconciliation, and the BPF grace period. Table rows
cannot disappear while a retained holder exists.

Node does not rewrite live task state. Node stages the semantic role and
process-state translation for each permitted old-to-new generation move. BPF
owns the live move. At the next protected effect, BPF acquires the process
transition guard, verifies the binding, target generation, translation, and
complete descriptors, updates the process state vector and active process
generation, releases the guard, and evaluates the effect with the new
generation. Another thread that encounters the guard denies its current effect
and can retry. A missing translation, concurrent exec transition, incomplete
generation, or failed validation denies without using a mixed state.

This migration is not atomic across a container. Each process moves on its own
next protected effect. The inactive generation can be built row by row because
no binding can reach it. Publication uses one exact pointer update after
readback and probes. Each process migration uses one local compare-and-swap on
its transition guard. These local atomic operations do not form a global task
migration transaction.

**Generation test.** Task T and socket S start on generation 42. Node publishes
complete generation 43. T's next file effect migrates T to 43 and uses the
generation-43 rule. S follows its declared generation-42 lifetime. A new root N
uses 43. Only after T exits, S closes, all typed references reconcile to zero,
and the grace period completes may 42 be removed.

`NATIVE-STATE-REF-LIFETIME-001` owns the Phase 2 task, process, entry, native
state, tombstone, and task-generation reference result. Socket, file, VMA,
device, IPC, and policy-effect lifetimes use their allocated Phase 3 and Phase
4 fixtures. Those later holders do not block the Phase 2 native-identity
result.

### 13. The One Local Pre-Effect Decision

Every protected Linux surface uses the same ordering. The surface-specific
hook supplies the effect, operation, object/channel identity, and arguments;
the identity and policy machinery is shared.

```text
1. Preserve any nonzero prior BPF-LSM result.
2. Read current task storage first.
3. If labeled, resolve that task's exact process, entry, native authority state,
   binding, placement, pinned generation, and reference state.
4. If unlabeled, completely resolve protected cgroup placement. Outside all
   protected roots uses explicit host policy. Protected or uncertain placement
   is classified as initial, restricted external, restored/unknown, or
   fail-closed unresolved; it never claims a command-based entry ticket.
5. Intersect active emergency/response restrictions and hard invariants.
6. Classify every required object axis and exact lifetime identity.
7. Read the exact base rule/default from the actor's pinned generation.
8. Intersect native-lineage restriction, process response, lineage response,
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
  native-lineage restriction,
  process response,
  native-lineage response,
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
map/helper lookup while holding the lock and never nests process/native-state/object
locks.

Version 1 permits one effect to change either process state or the shared
restriction state of its native process family, not both. This shared state
never crosses into an independent root because of IPC.

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

## Part IV — Physical Linux Enforcement And IPC

### 14. Why Mithril Uses Several Linux Mechanisms

No Linux mechanism covers the whole contract. Mithril compiles one source
policy into the mechanisms that own each physical boundary.

| Mechanism | Unique job | What it does not solve |
| --- | --- | --- |
| Existing mount namespace | The workload's existing namespace changes the filesystem view: host paths may be absent and mounts may already carry `ro`, `noexec`, `nosuid`, and `nodev`. Mithril measures that view and uses it when identifying objects. | Mithril does not change the Pod manifest or rebuild the mount view. Any object still visible needs another control. A mount namespace does not distinguish a native child from an external root or govern network/provider actions. |
| Landlock | When a supported start path lets Mithril install it in a new process, Landlock adds a monotonic restriction inherited by descendants. Available filesystem, network, Unix-socket, signal, and device-ioctl rights depend on the measured ABI. | Landlock is a start-time floor. It cannot be centrally loosened or dynamically rewritten, and it does not supply Kubernetes purpose, multi-node causality, or response orchestration. |
| Seccomp (deferred candidate) | A later stage may evaluate a qualified OCI Seccomp adjustment or target-context installer. Only if it meets the declared compatibility and performance budget may it install a filter before user code, removing whole syscall classes or scalar-argument shapes a role never needs. Installed filters are inherited and can only become stricter. | It is not a current Mithril enforcement dependency or product promise. If adopted, it remains a start-time floor and cannot safely resolve pathname pointers, file objects, target PIDs, Kubernetes roles, or TLS/provider semantics. |
| BPF LSM | Makes dynamic task-aware decisions at Linux security hooks for files, exec, sockets, process control, devices, capabilities, mount, BPF, perf, and other qualified operations. It can use Mithril's task, process, and native-family state before the effect. | It must be built and active as an LSM; helper/hook support varies by exact kernel. It cannot parse arbitrary TLS application intent or wait for a central service. GPL-compatible license is required for BPF LSM object programs that use the kernel's GPL-only interface. This does not automatically relicense the separate Rust program. |
| Cgroup BPF | Enforces workload/device floors, connect/send address policy, packet fences, and some socket operations at cgroup boundaries. | Cgroup membership alone is not per-process intent. Packet hooks may lack a meaningful current task. |
| TC/XDP/cgroup-skb | Drops actual packets, including established flows, after a response or final destination rewrite. | A packet does not reliably identify which of several sharing processes queued the bytes. Whole-socket/cgroup blast radius may be necessary. |
| Traditional SELinux/AppArmor | Adds mature distribution-owned mandatory policy and stacking defense. | Mithril cannot assume its hook observes every earlier denial; ordering and audit coverage are measured. |
| Supported runtime/admission extension | Lets Mithril prepare identity or reject a start at the exact point the stock interface documents. In the Kubernetes tier, Helm installs a marked OCI base spec on containerd's default CRI runtime. Containerd then invokes the retained hook directly. A later Seccomp evaluation may test whether a qualified NRI integration can adjust the OCI policy so the ordinary runtime installs it in the target. A separate target-context launcher integration may install Landlock. | The containerd base spec covers CRI starts, not direct non-CRI starts. Changing an OCI Seccomp field is not target-context execution and does not install Landlock. A callback cannot claim fields, ordering, or rejection behavior that its interface does not provide. It does not control hostile code already executing inside an admitted process. |

Where the existing mount view and supported start path permit it, a worker can
receive the three currently designed local layers without changing its
manifest, image, code, or command. A fourth Seccomp floor is a later evaluated
addition, not a baseline promise:

```text
existing mount namespace: host files absent; exact mounts and immutable flags
Landlock installed by Mithril at supported start: monotonic local floor
BPF LSM/cgroup: exact current task, runtime entry, object, domain state,
                dynamic response, device/network/privilege enforcement
later Seccomp candidate: unused syscall families removed only after a qualified
                         compatibility and performance decision
```

This is a capability combination, not a claim that current containerd NRI
provides all four. In the current scope, an unchanged Kubernetes worker can
receive its existing mount view and Mithril BPF enforcement. Landlock is
present only if another configured stock integration proves target-context
execution before user code. A later Seccomp decision may qualify an NRI policy
adjustment; until then `seccomp_capability_record_id` is absent and no
Seccomp-floor claim is made. Otherwise the support record says
`Landlock=ABSENT` and makes no Landlock-floor claim.

These layers intersect. None can turn another layer's denial into allow.
Seccomp is considered only in a later stage, after a qualified OCI adjustment
or target-context installer has passed its compatibility and performance gate.
Landlock is used only when a qualified integration runs the Landlock operation
in the new target's process context before user code. Otherwise Mithril relies
on BPF for the effects BPF can cover. Missing a required BPF LSM hook makes
that particular claim unsupported even when the namespace still hides many
objects.

#### Pairwise examples: what each combination could add

Use one unchanged conversion worker as the example. It needs
`/dataset/input`, `/work/output`, its Python runtime, DNS, and one result
service. It must not read the ServiceAccount token, inspect the host, create a
TUN device, or reach Kubernetes.

| Pair | Concrete result | What is still missing |
| --- | --- | --- |
| Mount namespace + Landlock | Host `/etc`, `/proc`, runtime sockets, and devices are not mounted into the worker; Landlock still denies undeclared opens under the visible dataset/work tree if a bind/symlink/layout mistake exposes them. | Both are installed before run and mostly monotonic. They do not know that a new probe root and the application root need different authority, or dynamically fence an already-running compromised lineage. |
| Mount namespace + future Seccomp | If the later Seccomp gate passes, host objects are structurally absent and `mount`, `ptrace`, `bpf`, `perf_event_open`, module, keyring, and unused namespace/syscall families can be removed. | A visible token and an allowed `connect` syscall still need object/destination/actor policy. Seccomp cannot follow a pathname or distinguish two roles that need the same syscall. |
| Mount namespace + BPF LSM | Namespace removes whole host regions; BPF LSM distinguishes the converter's native lineage from later external roots on every remaining exact file/exec/device/privilege object and can add a response restriction at runtime. | Stock CRI still does not distinguish probe, lifecycle, and admin purpose among identical external roots. Whole unused syscall classes remain outside the baseline scope unless the later Seccomp surface is adopted. |
| Landlock + future Seccomp | If the later Seccomp gate passes, Landlock limits visible filesystem/network/IPC rights inherited by descendants and Seccomp removes syscall families that should never be attempted. | It needs a trustworthy pre-run installer. It does not authenticate later runtime roots, express Mithril's changing process/native state, correlate multi-node actions, or centrally update response. The host view remains present even when access is denied. |
| Landlock + BPF LSM | Landlock supplies a monotonic least-authority floor that a later BPF policy bug cannot loosen; BPF LSM supplies exact task/entry/domain identity, dynamic object policy, and response. | The worker still sees every mounted pathname and may learn metadata through allowed operations. Host objects should still be removed by the namespace; a future Seccomp layer may remove unused syscall families. |
| Future Seccomp + BPF LSM | If the later Seccomp gate passes, Seccomp deletes broad attack surfaces while BPF LSM resolves the allowed syscall's real task, target object, and current restrictions. For example, Seccomp permits `openat` generally while BPF LSM denies the token object only for the converter. | The filesystem view remains broad without the mount namespace; there is no independent monotonic pathname/network floor without Landlock. |

If the future Seccomp gate passes, all four add another independent fact: the
host object first has to be visible, the syscall family has to exist, the
monotonic Landlock floor must permit it, and Mithril's current
task/object/domain decision must permit it. This is defense in depth, not four
copies of the same rule. Mithril still needs cgroup/packet controls for
established traffic and provider controls for TLS-hidden operations.

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

#### Synchronous topology decision

Watching a successful mount and updating policy later is too late. Node
publishes authenticated graph-prefix routes only from the held entry-time
container view. Node does not rebuild the mount topology after the task starts.

Before a namespace-visible mount mutation can take effect, the BPF hook
increments the global mutation epoch and pending count. The syscall return hook
clears the pending count. Each file or executable decision then performs these
steps in one BPF hook chain:

```text
snapshot the global mutation epoch and require pending count zero
read the live mount namespace root and namespace event
scan the live mount tree and build the oldest-mount cache
use an admitted graph-prefix route before the oldest-mount fallback
resolve and match the complete path
recheck the namespace event, mutation epoch, and pending count
```

A concurrent mutation, incomplete scan, missing route target, or unresolved
fallback denies under strict policy. Ring-buffer delivery is evidence only.
Daemon delay, restart, or event loss cannot authorize a file or executable
effect.

Shared propagation, automount, and network filesystem referrals can change a
namespace without the current task issuing the original syscall. The live
namespace event and mount-tree scan expose the resulting topology to the next
decision. If BPF cannot read a complete stable topology, the decision is
unresolved and denies.

**Race fixture.** A host task joins the worker mount namespace and mounts a
different object over an allowed path while the worker loops on open. A BPF
decision either completes against one stable live snapshot or denies because
the epoch, pending count, or namespace event changed. The fixture repeats with
two concurrent changes, a failed mount, propagation, overlay copy-up, and a
process exit during the scan.

#### Path selector resolution, path-tree floors, and exact object authority

Paths are signed policy inputs. A `PATH` selector is a live path expression.
It supports literal components, `*` for one component, and `**` for zero or
more components. It can supply an `ALLOW` or `DENY` decision without userspace
inode resolution. These examples have distinct meanings:

```text
x/y       live path with literal components
x/*/y     live path with one wildcard component
x/**/y    recursive live path pattern
EXACT x/y path-to-inode binding for one live container mount view
```

An `EXACT` selector is the separate inode-authority option. The node resolves
its signed canonical path in the authenticated CRI container mount view. It
then measures and reads back the live object. The selector grants no exact
authority when this binding is absent or stale. `WorkloadBindingOwner` uses
the existing CRI inventory and containerd event stream. A create notification
does not provide the final live init PID and mount view. When CRI reports the
container as `Running`, one reconciliation advances the workload binding and
supplies its authenticated PID for resolution. A later container, object, or
mount replacement starts the same resolution again. This stock notification
arrives after process start, so the current implementation records a start
gap for `EXACT` binding.

The node runs alone in a configured non-root effect-controller cgroup. It
verifies this ownership before it publishes the cgroup ID. BPF permits that
controller to perform read-mode protected-task inspection for current active
bindings. The exception does not permit ptrace attach, signal delivery, or an
external task in the controller cgroup. This narrow inspection permission lets
the node open the authenticated task mount namespace after the restrictive
effect profile is active.

This controller permission does not authorize container setup. The node
binding owner publishes `PreparedContainer` only after it verifies a held
runtime request, the CRI `Created` state, the scheduled Pod binding, and the
active signed policy. This state is not a policy selector, exception, or
runtime-supplied permission. It records that the exact initial entry is still
part of the trusted runtime boundary and is not yet an active workload.

```text
NRI CreateContainer
  -> inject two ordered Mithril createRuntime hooks
  -> the first hook stages immutable container, cgroup, image, and Pod facts
  -> no runtime authority is granted

Second OCI createRuntime hook with the exact initial task held
  -> send the container ID, PID, and cgroup to mithril-node
  -> verify CRI Created state and the staged immutable facts
  -> verify the scheduled Pod binding and active signed policy
  -> publish PreparedContainer for the exact binding and initial entry
  -> return allow only after map readback succeeds

Trusted runtime setup
  -> recognize the exact prepared binding and initial runtime entry
  -> permit runtime implementation details without a runc-specific operation list
  -> give runtime-created files, pipes, sockets, and handles no independent authority
  -> deny another binding, another entry, a later external root, or an expired state
  -> enforce one kernel monotonic-time deadline

First application exec
  -> resolve the container-visible executable path through the active signed
     policy
  -> require the exact container binding
  -> atomically change PreparedContainer from PREPARED to ACTIVE
  -> activate the normal workload execution identity
  -> evaluate explicit matching decisions before the application default
  -> block only an explicit matching DENY
  -> let an applicable exception authorize that denied action
  -> allow an action with no matching decision from the admitted entry lineage
```

`CreateContainer` prepares all authority for the container binding. The node
publishes the application entry, every additional-entry declaration and role,
the administrative role, the external role, and the active policy generation
before it releases the held initial task. These declarations remain fixed for
that binding and generation. The hook cannot create identities for later
entry processes because those processes do not exist yet.

BPF associates each later process with the prepared authority when the
runtime bootstrap relationship to the exact binding becomes visible. One
runtime exec can already be in progress when the task enters the container
cgroup. BPF lets only that exact task finish that in-flight bootstrap exec. It
does not install an entry role. The task remains restricted and prepared. Its
next exec must match one declared entry. A successful exec installs only that
entry's role. A failed or unmatched exec does not install workload authority.

The declared-entry match uses two facts from the same kernel exec request. At
exec syscall entry, BPF copies bounded `argv[0]` into task-local pending
request state before it checks cgroup membership. The state remains with the
task across an in-flight cgroup attachment and ends when that exec commits or
fails. It supplies the logical invocation path. The opened
`linux_binprm.file` supplies the executable backing object. BPF accepts only a
canonical absolute invocation path and walks only exact signed path
transitions for entry admission. The normal opened-file policy gate still runs
first. Thus, `/bin/sh` and `/bin/cp` can select different declared entries
when both resolve to BusyBox. The policy does not need to name
`/bin/busybox`. A relative, noncanonical, or unmatched invocation path does
not install a declared role. The application-start path keeps the
container-visible opened-file match because a runtime can use an internal
file-descriptor path for its held initial task.

An additional-entry declaration is reusable. Each invocation gets a new task
and process identity, a new prepared association, and a new exec transaction.
The static declaration remains installed. An administrative approval remains
one-use. Cgroup membership alone does not supply an admitted-entry identity.

After activation, the runtime can inspect and then signal the exact initial
task to stop the container. A permitted read-only inspection prepares one
runtime-controller lineage for the exact binding and initial entry. Only that
lineage can signal that exact task. This authority does not install a role,
permit an exec, or supply admitted-entry default allow. It ends with the
runtime-controller lineage and cannot move to another binding or entry.

The runtime is part of the node trusted computing base while the binding is
`PREPARED`. Mithril does not infer runtime identity from a `runc`, `crun`, or
`youki` syscall sequence. The exact binding and initial entry define the
boundary. Runtime implementation changes can add an anonymous file, pipe,
socket, namespace operation, or internal exec without changing the Mithril
policy model. This trust is intentionally broad inside that exact boundary.
It does not extend to another entry, another container, a later external root,
or a task after application activation.

The initial entry is a boot-scoped task entry identity. It is not an exact
executable file or inode identity.

The application-exec match follows Tetragon's binary-path boundary. BPF walks
the executable from the current task root and matches the signed path. The
match does not require an inode generation. Exact inode identity remains a
separate filesystem selector and administrative-exec control.

Runtime-created objects receive no durable bootstrap record. After activation,
the exact admitted entry lineage allows an action when no signed decision
matches. An explicit matching `DENY` blocks the action unless an applicable
exception authorizes it. The default does not apply to a task that only enters
the cgroup. That task must carry the exact admitted entry identity. A missing,
external, or different entry stays fail-closed.

A runtime-internal exec that does not satisfy the signed workload policy stays
`PREPARED`. The first exec that does satisfy the signed policy reserves
`EXEC_PENDING` across the multi-pass exec path. A pre-commit failure restores
`PREPARED`; a successful commit changes the state to `ACTIVE`. The kernel
transition, not a userspace event, opens workload authority and closes the
trusted-runtime boundary. Expiry closes an incomplete prepared state without
application activation. A node restart must read back the exact binding,
entry, deadline, and transition or keep admission readiness closed. An
`EXACT` path selector does not participate in the prepared state. After
activation, exact object resolution runs only for a selector that explicitly
requests `EXACT`.
Mithril resolves paths with a Node route first and Meta's bounded oldest-mount
algorithm as the fallback. Node records a graph prefix for each known mount
root in the authenticated container mount view. BPF uses that prefix when the
target dentry or one of its source ancestors has a current route. BPF selects
the oldest unique mount only when no route exists. A later bind-mount alias
cannot choose a new policy path. Mithril adds clean-topology, identity, and
exact-object conditions for a positive file decision. The public Meta
BpfJailer LPC 2025 presentation supplies the fallback mount-crossing traversal
and graph-matching approach. The presentation is design evidence, not public
implementation source; its slides 16-21 are bound here to the supplied PDF SHA-256
`81dca098d1ed96e19fd89b48b78be63c504f9f52f9f25b662e4a94c14a5209f6`.

Control compiles the component graph once into immutable generation rows.
When Node holds the initial container PID, it opens existing source dentries
through the held container root and publishes dynamic inode routes for that
binding. Each route references existing graph states. This stage does not add
graph states, change the generation digest, or activate another generation.
The provisional entry-measurement pass and the completed exact-object pass
remain two activation steps inside one policy generation.

Node does not rebuild these routes after the task starts. BPF reconstructs the
live topology for each file or executable decision. Its mount hooks update a
global mutation guard before a namespace-visible change. The decision path
reads the live namespace event and mount tree, uses an admitted route before
the oldest-mount fallback, and rechecks the guard before it returns. A
concurrent or unresolved topology denies. Ring-buffer delivery is evidence
only and is not part of authorization.

| Design part | Meta presentation contributes | Mithril retains or adds | Combined result |
| --- | --- | --- | --- |
| Canonical path reconstruction | Enumerate one root mount namespace, index `mount-root dentry -> mounts`, select the oldest (`lowest mnt_id_unique`) mount for an unresolved dentry, then cross through that selected mount's parent mountpoint | The admitted entry-time view supplies Node routes for known mount roots. A route is scoped to the binding, profile generation, mount namespace, filesystem device, and root inode. It stores existing graph-prefix states. | BPF scans the live topology synchronously. It uses a known route without mount-age selection. The oldest unique mount remains the fallback for an unknown route and prevents a later bind alias from selecting its target spelling. |
| Large rule matching | Bounded component graph/state machine with exact and wildcard transitions | Compile-time bounds, terminal-overlap rejection or signed exact override, no priority-by-specificity | Large hierarchical policies evaluate without linear rule scans or an unbounded string map. |
| Cache correctness | Cache or invalidate path work around rename and mount changes | The BPF cache key includes the live namespace event, namespace root, and root dentry. BPF checks the mutation epoch and pending count before and after resolution. | A cache cannot grant access through an old bind alias, reused inode, overlay copy-up, or remount. |
| Authorization result | A matched path rule | A signed `PATH` terminal can allow or deny from the live canonical path. A signed `EXACT` terminal also requires the current measured inode binding. | Live path policy and inode policy remain separate selector kinds. An unresolved `EXACT` selector cannot grant authority. |

Mithril's compiler and hot path therefore use this single bounded algorithm:

1. Compile the finite set of path patterns, wildcard components, and terminal
   dispositions into one bounded component-state graph. It is not a sequence
   of unbounded string comparisons or a whole-path hash table.
   Container creation cannot modify this graph or its generation digest.
2. From the target dentry, extract a bounded leaf-to-root vector of component
   byte views. The Meta design budgets up to 255 components of up to 255 bytes;
   Mithril's supported platform profile fixes and measures its own lower or
   equal bounds before a profile can activate. The vector is derived from
   kernel objects, never from a caller-supplied path string.
3. At each source dentry, look up an admitted Node route by binding, profile
   generation, mount namespace, filesystem device, and root inode. If the
   route exists, use its graph-prefix states and the collected child
   components. Do not select a mount by age for that routed path.
4. If no route exists on the source dentry ancestry, use the live BPF snapshot
   as Meta does. Look up every mount whose root is `D`, select the oldest mount
   by `mnt_id_unique`, and continue from that
   mount's parent and mountpoint. Do not continue through the mount by which
   the caller entered `D`. A missing candidate or an unreachable root is
   unresolved and denies under strict policy.
5. Reverse the resulting components and run them through the compiled graph.
   A transition can consume one exact component or the explicitly compiled
   wildcard component; only one non-conflicting terminal rule selects a
   candidate disposition. The compiler rejects overlapping terminal patterns
   with different physical results unless a signed override names the exact
   selector delta; YAML order, wildcard count, and “more specific” never
   choose authority.
6. If the terminal is a signed `PATH` selector, apply its compiled `ALLOW` or
   `DENY` decision from the live canonical path. Do not resolve an exact file
   object. A separate signed path-tree deny floor can also deny at this stage.
7. If the terminal is a signed `EXACT` selector, revalidate the task mount
   view, topology generation, selected canonical mount chain, measured file
   object, and retained policy generation before returning its physical
   decision. A selector match never authorizes a later inode generation,
   overlay object, or different selected root.

##### Signed path-tree deny floors

A signed `PathTreeDenyFloorV1` names one canonical path selector, whether the
selector is recursive, the covered file effects, and disposition `DENY`. The
compiler lowers the selector into the same bounded component graph as other
path selectors. It rejects `ALLOW`, an allow exception, or any other positive
disposition for this rule type. A recursive selector includes its named
directory and every descendant component.

For example, a recursive signed rule for `/tmp/secret-dir/**` denies each
covered effect on the directory and on every current or later child. The rule
does not contain a child inode number or inode generation. A file created after
policy activation, a replacement after unlink, and a file reached through a
represented alias are denied when their real canonical path is in this tree.

The BPF decision checks this floor after synchronous canonical path
reconstruction, but before exact-object lookup. For create, rename,
link, and similar name-changing operations, it checks each affected canonical
parent/name path before the object becomes visible. A missing path, an
ambiguous mount chain, a topology race, or an unqualified hook cannot bypass
the floor. Strict policy denies the operation until BPF has a stable result.

Node stores graph prefix states, not a deny bit. If a known mount root is
attached at `/home`, its route stores the state after `home`; `*` still
consumes one later component for `/home/*/secrets`. A route attached at `/srv`
keeps the `**` loop active for `/srv/**/secrets`. A container-root route starts
at graph state zero and provides the same result for paths that do not cross
another mount. One source can reference up to 16 deduplicated existing states.
BPF advances all of them and applies any role-specific denial. Node refuses
binding activation if it needs more than 16 states. It does not add a combined
state to the immutable graph. A future child uses its existing ancestor route.
Node also records a continuation at each initial Kubernetes submount that
crosses into another source tree.

Control compiles and signs the path graph once before container admission.
During the existing held-initial-PID inode stage, Node resolves each
represented source path to a state in that graph. Node publishes only the
dynamic route rows owned by the container binding. The provisional and exact
object passes keep the same generation handle and digest. They do not form a
new policy candidate or require a second generation. A policy replacement uses
a new generation only when its signed candidate changes.

This rule protects a location. It does not make pathname spelling a positive
identity. A separate exact-object rule is still required to allow a file, to
make a content claim, or to retain authority across a file instance. Existing,
passed, or inherited file descriptors remain subject to their
`FileInstanceProvenanceV1` and current-actor floors.

**Kubernetes submount example.** The initial container mount snapshot contains
these two mounts:

```text
source root         -> /home/secret
source root/models  -> /home/kubelet-attack
```

Node records that `source root/models` continues from
`/home/secret/models`. On access to `/home/kubelet-attack/secret`, BPF walks
from `secret` to the `models` dentry, finds the recorded route, and evaluates
`/home/secret/models/secret`. The decision does not depend on which
Kubernetes mount has the lower unique mount ID.

**Oldest-mount fallback example.** The first defense is before this resolver:
an untrusted worker is denied `mount --bind`, `move_mount`, `umount`,
`pivot_root`, namespace changes, directory rename, and hard-link changes that
could create or alter a protected alias. Therefore its attempted bind mount is
denied before a new mount exists. The following fixture explains the Meta
canonicalization rule against an already represented later alias; it is not an
allow path for that alias.

```text
M0: verified root mount in the selected MountSecurityViewV1

M5: original tracked secret mount
  mount root dentry = D
  attachment in M0 = /var/run/secrets/service
  mnt_id_unique = 41

M9: later bind mount of the same root dentry D
  attachment in M0 = /work/input/job-42
  mnt_id_unique = 92

opened file: config.json below D through M9
policy allow pattern: /work/input/*/config.json
```

The dentry walk first collects `config.json` and reaches mount-root dentry
`D`. No Node route exists for `D`, so the resolver performs the Meta fallback:

```text
D -> [ M5 (41), M9 (92) ]
select lowest mnt_id_unique -> M5
```

It does **not** cross `M9` at `/work/input/job-42`. It crosses the selected
older mount `M5` at its attachment, then walks its parent mount:

```text
config.json
-> D                         (root dentry shared by M5 and M9)
-> service                   (M5 mountpoint in M0)
-> secrets
-> run
-> /
```

Reversing the components yields:

```text
/var/run/secrets/service/config.json
```

The `/work/input/*/config.json` rule therefore does not match. If a mount-root
dentry has no older tracked mount, the Meta selection cannot invent one; the
pre-effect mount/topology fence is what prevents an untrusted task from
creating that first alias. A newly observed or ambiguous alias is unresolved
under strict policy unless BPF can reconstruct one complete stable topology.

#### eBPF implementation envelope

The Meta presentation makes clear that this is not a small `d_parent` loop.
Its implementation first extracts a vector of `d_name` string views and then
matches the vector; Meta reports roughly 2,000 lines of eBPF, substantial
verifier work, and pressure from BPF stack and instruction limits. The
component graph is specifically a hash-map/array-map representation, rather
than one whole-path hash, so a corpus of thousands of patterns remains bounded
in CPU and memory.

Mithril therefore treats path resolution as a separately qualified BPF hot
path. The target platform profile fixes the maximum component count, component
bytes, graph states/transitions, scratch-map memory, instructions, stack use,
and hook latency. It proves verifier acceptance and measures deny/allow
latency and I/O-heavy throughput at those bounds before activating a profile.
The extractor and matcher may be structured into verifier-safe bounded pieces,
but no implementation may silently truncate a name, depth, graph walk, or
mount traversal and then allow. Each such bound or verifier/map failure returns
the strict unresolved-object result.

The deck reports that Meta observed no measurable regression across its own
I/O-heavy workloads, while also describing path matching as materially slower
than other LSM operations. That is useful feasibility evidence, not a Mithril
performance claim: Mithril qualifies its own kernels, hardware, policies, and
workloads under the capability/performance contract in Appendix A.4.

The matcher may cache a resolved candidate only under the role, selector graph
generation, live namespace event, namespace root, and exact live object
identity. Bare inode caches are insufficient. Bind aliases, inode reuse,
overlay copy-up, remount, and different actor roots can change the answer. BPF
checks the mutation epoch and pending count around reconstruction. A cache
miss, truncation, topology race, ambiguity, or state-graph bound failure
follows the configured strict unresolved-object result. It never falls through
to allow.

This combined resolver does not copy the independent open-source `jailer`
matcher. That implementation is a useful task-storage example, but its bounded
dentry walk and global inode-cache invalidation do not implement the
presentation's mount-tree reconstruction or Mithril's actor-view/object
revalidation contract. Section 27 records the exact distinction.

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
must govern the next covered output, provider request, file access, exec,
device, or privilege effect and state that the memory access was unobserved.

#### Opened-file provenance follows the file

A host task can open a host credential and pass the fd into a container. Later
classification cannot use only the container's current mount view.

Each protected file instance retains exact `file->f_path` object/mount,
acquiring actor role, generation, and native-family state, open flags, response,
and live interval. Every later read/write/mmap uses the current actor's
permission intersected with that immutable file-instance floor. If a different
process later uses an inherited or received fd, the normal file hook supplies
the actual file and current process. Mithril does not need a detailed history
of how that descriptor reached the process.

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

### 18. Communication Between Independent Processes

Threads and native fork descendants share the restrictions described in
Chapter 6. A sidecar, init container, ephemeral container, `kubectl exec`, or
other runtime-created root remains independent, even when it shares the Pod's
network, files, or IPC namespace.

One relationship controls both directions of a Unix socket or local network
channel. A pipe has no exact peer for one write, so its decision uses the
current process, pipe, and read/write operation. Other observed pipe users are
evidence only. Unmatched communication uses the configured `unmatched` result.
Process control is separate and directional: controller, target, and operation.

Shared files and memory use object rules, not process pairs. Mithril governs
open, read, write, map, permission change, and attachment where Linux exposes a
hook. After a shared mapping is admitted, ordinary CPU loads and stores have no
per-access hook. Strict policy must deny the mapping or later freeze/terminate
its holders.

```yaml
ipc:
  unmatched: alert
  relationships:
    - id: converter-uploader
      endpoints:
        - {role: conversion-worker}
        - {role: result-uploader}
      channel:
        type: unix-stream
        listener: /run/uploader/upload.sock
      disposition: allow
```

The converter and uploader may use this socket. The containerd socket follows
another rule or `unmatched`. `alert` allows and records; `deny` returns an
error. Mithril may record descriptor passing without tracking the represented
object.

The rule does not interpret bytes. A converter may still ask a vulnerable
uploader to misuse its authority. Preventing that needs application or provider
authorization.

A shared output file uses ordinary object rules instead of the relationship
above. A converter may receive `WRITE` on the exact output object while an
uploader receives `READ`. A third process receives neither. If both processes
map the same writable object, admitting those mappings admits an ongoing shared
memory capability; there is no later pairwise read/write decision for each CPU
instruction.

Readable paths become live kernel identity before enforcement. Socket rules use
the current process, peer, namespace, channel generation, operation, and policy
generation. Unknown peers use `unmatched`. Pipe rules use the current process,
pipe generation, and operation. Shared objects use the current actor and object.

| Channel | What Mithril resolves |
| --- | --- |
| Unix socket | Live socket and endpoint processes |
| Pipe | Live pipe, current process, and read/write operation; observed other users are evidence, not an exact peer |
| Local IPv4/IPv6 | Network namespace, listener or peer set, socket generation, and final local route |
| Shared file | Exact live object and current actor at each covered file or mapping operation; there is no inferred peer |
| Shared memory | Exact object and current actor when mapping or attaching; ordinary later CPU loads/stores are outside hook coverage |
| Process control | Exact controller, target task, and operation |
| Descriptor passing | Communication edge and the fact that descriptor passing was attempted or occurred; not the represented object |

Wildcard listeners, `SO_REUSEPORT`, UDP, multicast, redirects, and hairpin
traffic use `unmatched` when the qualified hook cannot identify the peer.
`process_vm_readv/writev`, ptrace, `/proc/<pid>/mem`, `pidfd_getfd`, signals,
and ptrace control do not use the ordinary IPC relationship. They use a
directional process-control decision: this controller, this exact live target,
and this operation. Allowing process A to signal process B does not allow B to
signal A. PID alone is never enough.

A return hook cannot undo bytes already read or memory/registers already
changed. If the target cannot be pinned through the exact pre-effect operation,
strict policy denies or reports unsupported.

A signed `DEFENDER_READ_DECLASSIFICATION` names the target, case, read-only
operations, evidence sink, approver, expiry, and optional byte limit. The
verified Mithril inspector receives only the target fd and evidence fd. BPF LSM
checks target access. If the later Seccomp surface is adopted, its measured
inspector profile may additionally limit syscalls and fds. The inspector counts
successful bytes itself when configured; BPF LSM does not meter bytes. Writes,
ptrace control, signals, fd extraction, general sockets, and other output stay
forbidden.

#### Sensitive state and descriptor passing

If policy permits a sensitive access but restricts later actions, Mithril sets
`SENSITIVE_ACCESS_PERMITTED_OR_ATTEMPTED` on the actor's native family before
allowing the access. An independent receiver does not inherit it. The LSM allow
proves only that the attempt was allowed, not that a read returned bytes.

Secrets injected into environment or inherited memory may have no later read
hook. A profile that declares such an input starts the native family with
`POTENTIAL_SENSITIVE_IN_MEMORY` before its protected effects. Mithril does not
scan memory and pretend it discovered the secret. If the deployment cannot say
whether the input exists, policy either applies that conservative state or
reports the output-prevention claim unsupported.

Receiving bytes does not change a process role. A received descriptor also
does not transfer permission: later use is checked against the current process
at the normal file, device, socket, or other object hook.

Asynchronous and zero-copy operations are supported only when the qualified
hook controls the actual effect. Otherwise a strict profile denies the setup or
operation, and a permissive profile reports `UNSUPPORTED` for prevention.
Mithril does not try to cancel or drain arbitrary work already accepted by the
kernel.

#### Persistent files and volumes

A file may survive its creator through a name, hardlink, open fd, mapping, or
remount. Mithril retains its exact object and volume generation for access
control and response. A write does not automatically classify later bytes. The
later reader is checked against its own policy and the file's known
classification. End-to-end byte provenance is `UNSUPPORTED` unless the storage
system supplies a qualified immutable-artifact or provider record.

`PersistentVolumePolicyV1` and `VolumeAccessReadinessV1` carry volume identity,
policy generation, rollback protection, and access readiness. They do not
transfer inferred byte meaning between processes or nodes.

#### Abandoned live-merge design

Linux cannot atomically merge live process domains or drain every in-flight
operation. Mithril therefore governs each exposed operation and never claims
per-access control of an already admitted mapping.

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
current actor role/process/native-family state and actor netns
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

`socket_create` can check family, type, and protocol, but the socket does not
exist yet. A later qualified hook must label it before bind, connect, or send.
An accepted socket also needs a label before use; the pre-return accept hook is
not enough. A socket pair labels both ends. Missing identity denies first use.

Socket controls such as `SO_MARK`, `SO_BINDTODEVICE`, transparent/freebind,
attached BPF, reuseport, MPTCP, routing netlink, and ioctl are separate effects.
Do not authorize from a pointer into changeable userspace memory. A fixed value
needs a qualified hook after the kernel copies it; otherwise deny the option.

“No undeclared egress” means denying unused families and testing every allowed
path, including subflows, tunnels, redirects, io_uring, and SQPOLL. One TCP and
one UDP test do not prove it.

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

Preopened, inherited, duped, `SCM_RIGHTS`, and `pidfd_getfd` device fds remain
governed when they are used. The device hook sees the current process and
actual device object; Mithril need not reconstruct the descriptor's complete
transfer history. Read/write, mmap data/exec, poll, async submit,
io_uring/SQPOLL, and descriptor receipt are separate coverage rows. If poll
lacks a physical decision point, strict policy must deny fd acquisition or the
syscall via a launcher floor, or report use coverage unsupported.

Some ioctls return a new authority-bearing fd, such as a KVM VM, GPU context,
perf event, io_uring, or FUSE object. A qualified hook must label that object
before use. The label records its source, creator, operation, class, lifetime,
policy generation, and response state. Without that hook, Mithril can allow or
deny creation as a whole but cannot control the returned object separately.

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

Each row names all syscall/API/compat variants, a qualified pre-effect BPF hook
or capability/lockdown floor, and a physical oracle. A later Seccomp profile
may supply an additional floor only after its separate evaluation gate passes.
A new or unmapped variant is denied/unsupported, never assumed covered by a
similar older call.

The OCI runtime remains responsible for normal setup such as namespaces,
mounts, UID/GID, capabilities, securebits, and `no_new_privs`. Mithril does not
reimplement those operations. A configured stock admission hook may inspect
the requested security settings and reject them only if its documented timing
and return contract permit that result. BPF separately controls the later
covered operations performed by runtime helpers and workload tasks.

#### Deferred Seccomp evaluation contract

Seccomp is not a Version-1 enforcement dependency or release promise. A later
stage may add it only after one bounded profile has demonstrated: exact
installer/runtime compatibility, installation before target user code, correct
denial behavior, and no regression beyond the declared workload latency and
throughput budget. Until that decision, no Seccomp capability record is
installed, `SECCOMP-QUAL-001` is not a core release gate, and no Mithril
Seccomp-floor claim is made. The contracts below define what must be true if
that future surface is approved; they do not authorize building it now.

Ordinary installed seccomp cannot be weakened or detached by the task; the old
idea “detect a task weakening its filter” is factually wrong and abandoned. If
the later surface is approved, Mithril verifies its installation through a
supported start path and governs dangerous new user-notification or
ptrace/TRACE supervisor relationships.

`/proc/<pid>/status` shows mode/count, not arbitrary filter bytecode. Proof is:

```text
INSTALLER_ATTESTED: qualified Mithril start integration installed exact bytes
                    before target user code, either through target-context
                    setup or a qualified OCI Seccomp adjustment installed by
                    the runtime, then verified mode/count/TSYNC scope
KERNEL_OBSERVED: qualified kernel path proves exact installed identity/content
PRESENCE_ONLY: some filter exists; digest is not proved
ABSENT: no floor claimed
```

Correct and wrong filters can have the same mode/count. Only the first two may
prove exact rules. Partial TSYNC, wrong bytecode, install failure,
`NEW_LISTENER`, USER_NOTIF, and TRACE are fixtures. If Mithril can neither
supply a qualified OCI Seccomp adjustment that the runtime accepts nor perform
a qualified target-context install before user code, Seccomp is `ABSENT`. A
metadata-only OCI callback is not silently treated as an installer; the
containerd NRI `seccomp_policy` adjustment is a separately tested configuration
path, not mere metadata.

Seccomp cannot authorize `/proc/<target>/mem` by pathname: it cannot safely
dereference and authenticate the userspace pointer. The defender inspector uses
an owner-opened fd and BPF exact-target checks; a later approved Seccomp profile
may add fd/syscall confinement as described above.

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

Installation depends on what an existing launcher or runtime can do:

| Process situation | Future Seccomp result | Landlock result |
| --- | --- | --- |
| Mithril directly launches the process, such as an Erebor-governed agent/tool process | Candidate only: its child setup may install the compiled filter before the final program if the later gate qualifies it. | The same target-context child setup installs the ruleset before the final program. |
| Qualified containerd NRI adjustment is allowed by the exact runtime version and validator configuration | Candidate only: Mithril may supply `LinuxContainerAdjustment.seccomp_policy`; containerd would lower it into the OCI spec and the ordinary runtime would install it in the target. The later capability probe must reject versions or validator settings that refuse the adjustment. | Absent. NRI Seccomp-policy adjustment does not call `landlock_restrict_self()` in the target. |
| Existing supported launcher/runtime interface offers target-context pre-user-code execution | Candidate only: Mithril may install Seccomp there or use the runtime's normal OCI Seccomp installation if the later gate qualifies it. | Mithril installs Landlock there, records the measured ABI and exact syscall inputs/result, and qualifies the ordering with positive and negative probes. Landlock does not expose a general exact-policy readback for an arbitrary target. |
| Callback supplies metadata only and offers neither Seccomp-spec adjustment nor target-context execution | Absent. | Absent. |

Verify the real interface; the word “hook” proves nothing. NRI can supply a
Seccomp policy that the normal runtime installs, which is a candidate for the
later gate; it cannot install Landlock. Landlock must run in the target's own
setup path. If no supported interface offers that path, the Landlock layer is
absent.

The node daemon cannot attach either floor from outside to an arbitrary live
task. BPF LSM can still control that task's next covered action. None of these
paths changes a Kubernetes object, CI job, application, image, entrypoint, or
process model. Appendix A.13.6 defines thread coverage and installation proof.

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

`EvidenceIntakeOwner` in Control authenticates each bounded node batch and
appends accepted envelopes and coverage records by tenant, node, source,
epoch, and sequence. It advances the durable contiguous cursor only in the
same committed transaction as the accepted records. A duplicate with the same
identity and bytes is idempotent. A duplicate with different bytes rejects.
Out-of-order records remain pending inside a bounded window. Storage failure or
backpressure withholds acknowledgement, so the node keeps the WAL range.

Intake does not change node evidence, repair a coverage gap, or create a graph
edge. The graph owner reads only committed intake records and cursors. CRDs do
not store observation payloads, intake cursors, graph state, or findings. An
acknowledged record remains in Control until the graph owner has installed and
proved its declared retention, reference, and consumer-watermark rules.

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

A single `GraphAndFindingOwner` in `mithril-control` materializes local,
cross-node, and provider graph revisions. Nodes and CRD reconcilers emit or
retain source records; they never create graph edges. Phase 7 creates the
node-agnostic graph store and replay owner. Phases 8 and 10 extend that same
owner with qualified Kubernetes and provider edge contracts.

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
Fencing a shared TLS socket affects every process using it. A native-family
restriction affects that root and its native descendants. Freezing a cgroup or
Pod may affect unrelated roots and containers.

Before approval, Mithril re-resolves and enumerates all known affected
participants and exact lost effects. If an existing socket needs a separate
packet fence, it is a separate action. The result is named
`WIDENED_PHYSICAL_RESPONSE`, not process-only. If the operator does
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
| `HF-002` | Identity, environment, mount, cgroup, filesystem, and process reconnaissance | External branch remains context. On a managed task, deny undeclared diagnostic exec and exact proc/host/credential objects. | `ALG-LINEAGE` decides the helper; `ALG-FILE` resolves exact proc target/mount. Already resident environment has no new file effect; Mithril controls the next covered output. |
| `HF-003` | Bundled/fallback `curl`, `nc`, `ip`, or other tools | Deny executable objects absent from the role; an approved diagnostic tool remains destination- and effect-restricted. | Immutable executable identity, not `$PATH`, basename, copy, or rename. `ALG-NET` still governs the tool's socket. |
| `HF-004` | Publish environment/secrets to public capture endpoints | Managed unapproved destination: deny connect/send and prove no packet. Required/opaque channel: alert only what source/result proves. | `ALG-NET`; direct sensitive access may narrow that actor's later egress. An allowed TLS event without content oracle is `PAYLOAD_UNOBSERVABLE`, not confirmed secret exfiltration. |
| `HF-005` | Execute staged Python disguised as a source file | Deny only when exact object/content provenance already classifies the bytes as untrusted code, or deny its next prohibited effect. | Filename `.c` is no proof. `ALG-ARTIFACT` binds download/CAS/IMA/fs-verity/held-content identity; in-process Python interpretation has no exec hook. |
| `HF-006` | gzip/base64/chunk payloads in memory | Pure CPU computation proceeds; first prohibited file/code-map/exec/send/provider boundary is controlled. | No algorithm invents a packing syscall. Heuristic observation may raise finding priority but cannot claim prevention. |
| `HF-007` | Search public code/platform APIs for infrastructure names | External evidence is contextual/provider evidence. Managed undeclared destination is denied; documented service query may alert. | `ALG-NET` owns destination; `ALG-AUTHORITY` owns a real audited query. Similar text/time is not causal identity. |
| `HF-008` | Hostile HDF5 external-file reference reaches the conversion worker | Deny any target outside admitted dataset/runtime/scratch/output objects before bytes reach HDF5. Optional upload scanner may separately reject the artifact. | `ALG-FILE` on the existing Python task; actual mount/inode/proc object defeats `../`, symlink, bind, and `/proc/*/fd` aliases. No new process is required. |
| `HF-009` | Worker environment/secrets/source/context disclosed through result or network | Deny observable proc/token/source reads and undeclared file/socket/provider effects. In-memory environment read is unobservable; the next covered effect is decided. | Keep file, socket, packet, and provider results separate. Without a content oracle, normal and secret-shaped payloads over the same allowed TLS schema stay indistinguishable. |
| `HF-010` | Jinja expression executes Python in the existing worker | Do not claim “Jinja denied.” Deny the first prohibited exec/file/network/device/privilege effect of that already labeled process. | `ALG-LINEAGE` sees no new task. `ALG-FILE/NET/DEVICE` receive exact worker identity. Pure arithmetic is intentionally unclassified. |
| `HF-011` | Projected ServiceAccount token and namespace files opened/read | Conversion role gets `EACCES`; an exact controller role may read and receive its configured native-family restriction. Token bytes never enter evidence. | `ALG-FILE` uses rotating projected-volume semantic item. Open attempt, fd opened, positive bytes read, and provider credential used are separate results. A preloaded token shifts control to later effects. |
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

File access and later output are different actions:

| Result | Required oracle |
| --- | --- |
| `FILE_OPEN_PREVENTED` | Pre-effect deny plus matching syscall result/no fd |
| `FILE_ACCESS_ATTEMPT_ALLOWED` | Exact pre-effect allow; no claim that fd/bytes followed |
| `FILE_DESCRIPTOR_OPENED` | Same open attempt completed with nonnegative new fd and fd->object readback |
| `SENSITIVE_BYTES_READ` | Exact qualified positive-byte completion for that task/fd/path; mmap has its own path |
| `PROVIDER_CREDENTIAL_USED` | Authenticator/provider proves exact credential lease/fingerprint/request operation |
| `SEND_ATTEMPT_ALLOWED` | Exact local send admission; packet/result not implied |
| `PACKET_EMITTED` | Packet boundary proves transmission |
| `PROVIDER_WRITE_OBSERVED` | Authoritative repository or service proves a write |
| `SUSPECTED_SENSITIVE_OUTPUT` | A write or send follows an exact sensitive access; the bytes were not matched |
| `CONFIRMED_EXFIL` | Authorized content/provenance oracle matches protected and published bytes without storing secret |
| `PAYLOAD_UNOBSERVABLE` | Channel/result is known, but encrypted/in-memory content meaning is not |

`HF-011-READ-RESULT-001` covers zero-byte read, EOF, `EIO`, partial positive
read, mmap, inherited fd, io_uring, token already in memory, failed send,
emitted packet, and provider-confirmed write. No boundary borrows the
result word of another.

#### `HF-012` through `HF-018`: remote authority stays separate

Record four things for a remote action:

```text
local Linux action if one exists
provider/connector request and result
join proof between them
coverage for both sides
```

A socket deny can prevent a Kubernetes or IMDS request. An allowed TLS
connection does not reveal its verb. Provider audit may prove the verb but not
the local task. A direct join needs an ID or lease that both existing systems
expose. Otherwise the relation stays contextual.

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

unless evidence proves that route. Catalog exposure, credential validity,
credential use, and local cause are separate facts. Without a shared ID, the
cluster action is exact but its local cause is `CONTEXTUAL_SHARED_AUTHORITY`.

AWS replay from outside and AWS use by the worker are separate branches.
`DryRun=True` proves `ATTEMPTED_AUTHORIZATION_CHECK`, not a mutation. The final
AWS resource state proves whether a change occurred.

For GitHub, use existing issuance evidence when it exposes the App,
installation, repositories, permissions, result, lease, and protected token
handle. If normal audit does not record minting, that claim is unsupported. A
hash cannot revoke its token. A protected raw handle can. Suspending an entire
installation is wider and must be described that way.

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

Every card stores the syscall result, relevant before/after state, network
proof, provider result, resource state, coverage, generation, and graph digest.
An alert screenshot is not a test result. A missing hook or adapter must select
the card's degraded result and disable the claim.

#### End-to-end production branch

1. Mithril discovers the reviewed conversion image and binds the initial task
   as `conversion-worker`. A configured qualified stock start hook can prepare
   that binding early; otherwise protected effects deny until binding and the
   measured start gap remains explicit.
2. HDF5 resolves a hostile reference. A strict file rule denies it; an
   alert-only deployment permits the exact file action and a separate later
   output policy still applies.
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

The tables explain the incident. The records below give the test runner exact
fields, lookups, degraded results, and oracles:

```text
LookupStepV1 {
  sequence: u8                       // starts at 0; contiguous; maximum 31
  owner: NODE_TASK_STATE | NODE_OBJECT_STATE | NODE_DECISION_MAP |
         KUBERNETES_API_OR_AUDIT | PROVIDER_API_OR_AUDIT |
         GRAPH_REVISION | RESPONSE_READBACK
  operation_id: RegistrySymbolV1
  input_field_ids[1..32]: sorted unique RegistrySymbolV1
  required_capability_ids[0..16]: sorted unique Id128
  required_source_ids[0..16]: sorted unique Id128
  expected_output_field_ids[1..32]: sorted unique RegistrySymbolV1
  on_missing: DENY_LOCAL_EFFECT | REJECT_REMOTE_REQUEST |
              RETURN_UNSUPPORTED | MARK_CONTEXTUAL | FAIL_QUALIFICATION
}

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
| `HF-004` | External send; managed connect; allowed send result; provider-confirmed write |
| `HF-005` | External staged file; managed object with trusted provenance; ordinary source file |
| `HF-006` | Pure in-memory packing; later boundary-crossing effect |
| `HF-007` | External search; managed destination; documented service-semantic query |
| `HF-008` | Worker-local forbidden object; optional synchronous upload gate |
| `HF-009` | Protected read; resident environment; later output; same allowed TLS channel |
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
task/process/native-family state, current mount view, final resolved mount/filesystem/object
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

For `LOCAL_PRE_EFFECT`, the lookup plan uses Appendix A.12. Remote admission
names the authenticated gate and request. Provider evidence names the request,
result, resource revision, and coverage; it never claims a later audit event
rejected an earlier action. Outside-authority cases omit local task, cgroup,
and map fields instead of filling them with zero.

Each card stores its physical or provider result, required state and network
proof, coverage, generation, graph digest, and negative control. Screenshots,
command text, and a quiet period are not oracles.

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
| Container action/service | Independent container root and contextual/exact coordinator edge according to available IDs; shared workspace/network operations use configured IPC/object relationships without merging roots. |
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
5. The resulting native process family receives `ci-untrusted-build`: no repository
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
  but keep three entries/budgets; every shared operation uses its configured
  relationship or unmatched result.
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

Mithril does not run KubeArmor, Tetragon, the independent open-source Jailer,
Falco, or Cilium beside its own node agent. It also does not copy one of those
products and add a second policy engine. It studies the mechanisms that their
source proves, keeps the useful ideas, and builds one Mithril-owned
implementation around Mithril's identity, policy, evidence, and response
contracts.

The checked baselines are:

- KubeArmor commit `e46f112e8bd4d3c8c8a73c23bfe438ff40eeea1a`;
- Tetragon commit `dbb59576f9ce504c044f8d9a0cd7a0f91c71ae2c`; and
- independent Jailer commit `3ffc155512b8be4296842c2f0c2c47f8d3407694`.

The independent Jailer repository explicitly says it is not Meta's BpfJailer;
it is a separate implementation inspired by that work. Meta's supplied LPC
2025 PDF is a presentation, not a source repository. Its SHA-256 is
`81dca098d1ed96e19fd89b48b78be63c504f9f52f9f25b662e4a94c14a5209f6`.
It grounds the mount-aware traversal portion of the combined path resolver in
Chapter 15, but it cannot prove unpublished implementation details or enter a
code-line `SourceEvidenceClaimV1` until an exact public code snapshot exists.

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
presentation without a public code range remains a separately pinned
context-only review input. A display table is never the source of truth.

#### Code reuse and license gate

“Learn from” and “copy code” are different decisions.

- Both checked repositories have an Apache-2.0 top-level `LICENSE`.
- Independent Jailer also has an Apache-2.0 top-level `LICENSE`, but its
  `bpfjailer-bpf/src/main.bpf.c` has no SPDX header and declares a GPL kernel
  license section. Do not infer one file's redistribution terms from another
  project's top-level license or from a BPF `license` section.
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

KubeArmor compiles policy into compact maps. Its checked code changes entries
in live per-container maps (`KA-CODE-007` and `KA-CODE-019`;
`shared.h:250-259`, `mapHelpers.go:47-73`, `rulesHandling.go:414-638`). If one
update fails, the installed map can differ from the requested policy.

Mithril hardens this into a transaction:

1. compile every rule and negative set into fresh inactive maps;
2. verify counts, bounds, digests, and all expected lookups;
3. run allow, deny, map-miss, and capacity probes;
4. publish one generation pointer after the complete generation passes;
5. let BPF migrate each running process at its next protected effect;
6. keep old maps until every task, socket, domain, pending intent, and response
   generation reference is released.

**Example.** A profile has 400 file rules and rule 317 cannot be inserted. The
old generation remains active. No task sees rules 1 through 316 from the new
profile and rules 317 through 400 from the old one.

#### 28.4 Bind before first user effect, not after the container is already running

The checked NRI path adds policy after start and removes it at stop
(`KA-CODE-004` and `KA-CODE-017`, `core/nriHandler.go:120-240`). It is a useful
integration point. It does not prove control before first exec or the ordering
of every Kubernetes `PreStop` action.

Mithril prebuilds the container/cgroup binding when a stock hook runs early
enough. Unresolved protected tasks receive the fail-closed BPF floor. Mithril
claims start rejection only when a validating-admission or runtime hook really
provides it.

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

The checked KubeArmor BPF rules mainly decide socket type and protocol
(`KA-CODE-006` and `KA-CODE-013`, `enforcer.bpf.c:415-648`). Its NFLOG path
adds endpoint and container context in userspace
(`networkPolicyEnforcer.go:267-303,733-824`; `types.go:722-767`). That evidence
does not identify the current process role, preserve socket provenance, or
reveal a TLS verb.

**Example.** A broad uploader opens a TCP socket and passes it to a restricted
converter. Endpoint-only attribution could still call the flow “the Pod's
traffic.” Mithril intersects the socket creator's restrictions, the current
sender's native authority state, live response state, final route, and packet fence.
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

KubeArmor has useful presets for environment access, fileless exec, anonymous
executable mappings, and proc access (`KA-CODE-018`). Its exec context includes
namespace, TTY, and inherited context (`KA-CODE-008`,
`KubeArmor/BPF/exec.bpf.c:22-53`). Mithril uses these as test seeds, not full
policy families. A TTY is context, not administrative approval. Chapters 16,
17, and 21 define the full operations, bypasses, and physical checks.

#### 28.12 Measure every reader, map, and bound

The checked readers handle lost samples differently (`KA-CODE-023` and
`KA-CODE-028`). Paths and events are bounded (`KA-CODE-024`). Exec and policy
state use bounded or LRU maps (`KA-CODE-026` and `KA-CODE-027`). Mithril makes
these limits explicit:

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

Tetragon explicitly handles exec by a non-leader thread (`TG-CODE-002`,
`bpf_execve_event.c`, `process.h`, and `pkg/sensors/exec/exit_test.go`). Its
staging spans credential, map-update, and event programs (`TG-CODE-014`).
Mithril keeps this case as a permanent fixture and adds native-family authority
and policy-generation references.

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

#### 29.4 Use each stock runtime hook for what it really proves

Runtime hook stages have different contracts. The stock NRI hook injector can
inject OCI hooks but does not provide Mithril with a private runtime protocol.
Two ordered `createRuntime` entries provide the required stage-then-admit
sequence. The first reports immutable container, cgroup, image, and Pod facts.
The second reports the exact held PID and the same facts. The synchronous
second hook waits until Mithril verifies the CRI `Created` record, proves that
the cgroup contains only that PID, activates the signed generation, publishes
the binding as `PreparedContainer`, and reads it back. Only then does the hook
return and let the runtime continue.

The exact prepared entry remains trusted runtime infrastructure. Mithril does
not encode the setup operations of one runtime release. The first exec that
satisfies the signed workload policy changes the binding to `ACTIVE`. Every
later effect then uses normal workload policy. A runtime-internal exec stays
`PREPARED` and remains bounded by the same entry, binding, and deadline.

The ordered hooks commit task identity only. They do not expose the final
mount topology that an `EXACT` selector needs. Exact path-to-inode binding uses
the separate authenticated CRI `Running` inventory path. Stock containerd
supplies that state after process start, so this path records an initial
Exact-binding gap. Live `PATH` selectors remain kernel path-graph decisions
and do not use this userspace resolution.

**Example.** The second hook reports PID A and cgroup C. CRI readback must show
the same full container ID in `Created` state, and C must contain only A. If a
fact differs, Mithril does not publish `PreparedContainer`. If the facts match,
runtime setup can change across supported runtime versions without a new
Mithril operation list. Hook timeout, mismatch, and rejection remain separate
failure fixtures.

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

Tetragon is not observation-only. Generic LSM supports override and signal;
the staged `bpf_enforcer` is separate (`TG-CODE-007` and `TG-CODE-019`). Its
action vocabulary and mode split are useful (`TG-CODE-013`). Mithril likewise
keeps the physical hook result separate from event delivery and does not give
all actions the same assurance claim.

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

Tetragon shows one node binary owning many sensors (`TG-CODE-012`) and fresh
inner-map publication (`TG-CODE-016` and `TG-CODE-022`). Mithril uses both.
Reverse indexes and generation retention update in one recoverable transaction,
so half a relation cannot become active.

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
WorkloadProtectionPolicy
  -> Control lower/compile/sign/target -> node policy activation
WorkloadProtectionException
  -> Control resolves one precompiled grant -> node exception activation
  -> kernel task creation + runtime/Kubernetes inventory + optional stock hooks
  -> classify labeled native child, known initial root, external root, or unknown
  -> install or retain restrictive task/process identity before covered effects
  -> inherit identity on every fork/thread before child effects
  -> commit exec transitions around the real Linux exec hooks
  -> evaluate file/exec/network/device/privilege effects at pre-effect hooks
  -> evaluate IPC relationships and optional descriptor-passing evidence without merging actors
  -> fix the physical result
  -> emit bounded evidence with source sequence and coverage
  -> durably acknowledge accepted evidence in Control
  -> build typed local/multi-node/provider edges in Control
  -> authorize, apply, read back, and watch any response
```

KubeArmor most directly teaches compact pre-effect LSM policy. Tetragon most
directly teaches staged process observation, cgroup selection, one-process
sensor ownership, and runtime integration points. Mithril adds the missing
contract between those mechanisms: honest missing-purpose handling, task-first identity,
immutable activation, IPC relationship policy, cross-node graph proof, coverage
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
| `CARD-XNODE-PRIVILEGED-POD-001` | Worker's native family has Kubernetes credential-use evidence; node floor active on another node | Credential creates privileged Pod and runtime root remotely | Typed Kubernetes audit/object/binding edges connect nodes. Remote pre-admission or node floor rejects the root where supported; otherwise report exact observation and response, never local syscall prevention. Fixture: `XNODE-PRIVILEGED-POD-001`. |

### 31. Acceptance: What Must Work Before Mithril Makes A Claim

Passing unit tests for map lookups is not enough. Each advertised kernel,
runtime, and Kubernetes combination must pass real hostile workloads and
legitimate controls. The oracle is the physical syscall, packet, provider
object, or verified response result, not an alert string.

#### 31.1 Kubernetes and runtime entry matrix

Phase 2 owns the identity part of this matrix: root creation, native lineage,
execution sets, binding lifetimes, coordinates, and conservative missing-state
classification. Phase 3 owns observed relationship evidence. Phase 4 owns
permission, approved-role transitions, and physical effect results. A later
relationship or effect result does not block Phase 2.

| Fixture | Real setup | Required result |
| --- | --- | --- |
| `ENTRY-START-001` | Delay or drop runtime discovery/hook metadata for an initial root | The root receives conservative identity and the exact start gap is recorded. No first-instruction claim. Phase 4 owns effect denial. |
| `ENTRY-POSTSTART-001` | Race `PostStart` and entrypoint in both orders | Initial root and external root remain distinct; neither is fabricated as the other's child. |
| `ENTRY-POSTSTART-002` | Keep one real `PostStart` in flight across kubelet restart, then repeat the live Pod's exact hook command through CRI | Each observed external task gets a fresh task/lifetime identity and the same restricted budget; no stale identity is reused. Automatic kubelet resend is not required or claimed. |
| `ENTRY-PRESTOP-001` | Delete Pod while a restricted root is active | Termination does not change task identity or release required native references. Phase 4 owns containment-versus-cleanup policy. |
| `ENTRY-PROBE-001` | Concurrent startup/readiness/liveness exec probes | Stock path gives one restricted external class. Exact different purpose is claimed only for a qualified existing interface that actually carries it. |
| `ENTRY-PROBE-002` | Application child runs identical probe binary/argv/cadence | Native lineage remains; no probe role. |
| `ENTRY-NETPROBE-001` | HTTP, TCP, and gRPC probes | No fake in-container process root. Later network fixtures own host-flow and application-receive policy. |
| `ENTRY-SLEEP-001` | Lifecycle `sleep` action | Kubelet lifecycle evidence only; no invented task. |
| `ENTRY-EXEC-001` | `kubectl exec`, TTY/non-TTY, and `kubectl cp` | Restricted external roots plus separate Kubernetes audit facts. The configured approved path must also pass `ADMIN-EXEC-APPROVAL-001` before assigning a stronger task role. |
| `ENTRY-EXEC-002` | `crictl exec` runs same command as probe | Restricted external root, never a kubelet-probe role. |
| `ENTRY-EPHEMERAL-001` | Add ephemeral container sharing target PID namespace | Independent container execution set and profile; shared PID namespace does not merge trees. |
| `ENTRY-CONTAINERS-001` | Init, native sidecar, and app containers share Pod network/volume | Independent roots and execution sets. Later relationship fixtures own shared-resource edges. |
| `ENTRY-MIGRATE-001` | Move unlabeled task into protected cgroup or use `nsenter` | Namespace entry grants no identity. Cgroup entry creates a restricted external root. Phase 4 owns the protected-effect result. |
| `ENTRY-REUSE-001` | Reuse PID, namespace number, cgroup path/ID, Pod/container name | Full IDs and live intervals prevent old policy/response attachment. |
| `ENTRY-RESTART-001` | Restart kubelet, runtime, and node agent during discovery and binding | Live tasks are re-enumerated; no stale role is reused; incomplete history and coverage transition are explicit. |
| `ENTRY-LOSS-001` | Drop runtime/audit metadata and BPF entry evidence independently | The task stays a restricted unknown/external root and each coverage loss is explicit. Phase 4 owns the effect result. |

Every case records the exact runtime/CRI version; kernel/BTF/LSM order and
capabilities; Pod UID and resource version; full container/image/cgroup live
identity; entry classification and proof quality; task/process/exec cookies;
syscall or runtime outcome; and coverage/loss state.

#### 31.2 Physical effect and bypass matrix

| Family | Bypasses that must be tried | What the oracle proves |
| --- | --- | --- |
| Execution | `execveat`, `fexecve`, memfd, deleted file, script/interpreter, dynamic linker, rename/bind mount, overlay copy-up, non-leader exec, writable-to-executable `mprotect` | Forbidden image or executable memory never begins; allowed immutable image gets exact role. |
| File | symlink, hardlink, rename, bind mount, proc-fd alias, token rotation, inherited/passed fd, mmap, `io_uring`, writable `MAP_SHARED` visibility | Claimed operation returns denial before the named effect; already-open/in-memory gaps remain explicit. |
| Network | DNS and IP literal, IPv4/IPv6, TCP/UDP/raw/packet, passed socket, established TLS, sendfile/splice, TUN/AF_XDP/BPF redirect, destination rewrite, receive queue | Forbidden connect/send/packet is physically absent; established-flow and shared-socket blast radius are proved separately. |
| Device | `mknod`, aliases, open, TUN, GPU, FUSE, KVM, approved/unapproved ioctl, passed device fd | Device tuple, actor, operation, and derived object all match the exact rule. |
| Privilege | setuid/caps, credential changes, ptrace, process-vm, pidfd controls, `setns`/`unshare`, mount, BPF, perf, module, keyring, proc/sysctl, seccomp user notification | Chosen pre-effect hook denies; unsupported operation lowers the claim. |
| Identity | fork without exec, thread/`vfork`, non-leader exec, reparent, parent exit, task/cgroup/PID reuse, moved tasks, bootstrap | Stable identity or typed gap exists before effect; no userspace-labeling window. |
| Evidence | ring pressure, reader death, source gap, WAL full, generation switch, link/pin/map loss, control outage | Physical deny is independent from transport where mechanism is live; negative claims stop across gaps. |

The old phrase “seccomp weakening hook” is not a valid Linux test. Seccomp
filters are monotonic once installed. If the deferred Seccomp surface is later
approved, the real tests must prove that its floor existed before target user
code and could not be silently omitted. Mithril makes no Seccomp claim for a
process where it did not install that floor. Unapproved ptrace or Seccomp
user-notification supervisors are separate controls.

If the later Seccomp stage is allocated, `SECCOMP-QUAL-001` runs both candidate
installation forms separately. The direct-launch case proves target-context
installation. The containerd case uses NRI `seccomp_policy`, proves the exact
OCI policy digest reached the runtime, and exercises validator allow, validator
reject, missing NRI plugin, plugin timeout, runtime install failure, correct
forbidden-syscall denial, an allowed control, and the declared performance
budget. Passing the direct-launch case does not qualify NRI, and passing NRI
does not make a Landlock claim.

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
state, native-family restrictions, IPC channels, VMA snapshots, exec, file,
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
| Kubernetes policy watch closes, compacts, reorders, or loses API access | Relist from the durable object identity and report source delay | Keep every installed local generation; block an unproved new desired revision | No claim that CRD state converged until source and rollout readback recover |
| CRD is deleted or recreated while Control or a node is unavailable | Record the deletion, UID change, complete desired inventory, and unreachable nodes | Keep the last valid generation while the runtime lifetime exists or desired inventory is unavailable; remove stale membership after runtime absence | Object disappearance or finalizer removal never proves local runtime absence |
| Policy rollout is partial or an acknowledgement is stale | Report exact per-node candidate and generation state | Each node keeps its last valid complete generation; stale boot/target/candidate acknowledgement rejects | No cluster-wide active claim |
| WAL fills | Apply configured retention/backpressure before overwrite and expose gap | Local enforcement continues; evidence-dependent conclusions stop | No safe/contained claim across loss |
| Control evidence storage or intake acknowledgement fails | Retry the bounded batch and expose intake delay | Local enforcement and WAL retention continue | No WAL truncation or graph input beyond the durable contiguous acknowledgement |
| Kubernetes/provider audit is absent | Local evidence continues | Local controls continue | Provider verb and distributed edge are unknown/contextual |
| Runtime/kubelet restarts | Reconcile live tasks and external/initial classifications; open a gap where history is missing | Preserve pinned bindings; unknown new roots stay restricted | No stale purpose or lifecycle claim |
| Node reboots | Close old boot subjects and start new source epoch | Every workload is admitted again | Old response keys cannot target new tasks |
| Process/native-state map corrupt, mismatched, or full | Mark the exact task/native-family interval incomplete | Deny affected effects; an independently authorized freeze may hold | No role or native-state claim from missing data |
| IPC relationship or peer identity is missing/corrupt | Record the unmatched or unresolved channel | Apply the configured unmatched-IPC result | No claim that the peer or relationship was known |
| VMA snapshot is partial or task sharing changes during snapshot | Keep positive mappings, mark absence unproved | Never relax from partial snapshot; retain restrictions or reject exact action | `VMA_SNAPSHOT_INCOMPLETE` |

A missing enforcement mechanism cannot apply its own “safe state.” If the file
LSM link detaches, that link cannot freeze a cgroup or deny a file. A separate,
still-healthy configured stock runtime hook can reject new roots. A separate packet program can
fence egress. A separately qualified cgroup freezer can hold existing tasks.
Each action has its own authorization and readback.

**Recovery example.** Detach only the file-LSM link while TC remains attached.
Mithril marks file protection `UNKNOWN`. If policy authorizes it, TC fences the
affected workload/cgroup and verifies the fence. A token open during this interval is
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
8. Intersect it with native-family restrictions, response restrictions, object/socket
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
- task, process, native-family state, socket, response, topology, VMA, mm-cookie,
  IPC-channel, async-object, and pending-intent capacity, including the exact
  N+1 result;
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
enum PerformanceOperationV1 {
  Fork, Exec, Open, Connect, UdpSend, EstablishedTcpSend, PacketFence,
  EntryAdmission, IntentVerify,
  OtherRegistered { operation_registry_id: RegistrySymbolV1 },
}

enum PerformanceStateTransitionModeV1 {
  ReadOnly, MonotonicTransition, ContendedCas,
}

enum CapacityResourceKindV1 {
  BpfMap, Ring, Wal, PendingIntent, AuthorityDomain, IpcChannel, AsyncObject,
  OtherRegistered { resource_registry_id: RegistrySymbolV1 },
}

LatencyDistributionV1 {
  unit: NANOSECONDS
  sample_count: u64
  p50, p95, p99, maximum: u64
  histogram_artifact_digest: DigestV1
}

OperationPerformanceRecordV1 {
  operation_id: PerformanceOperationV1
  concurrency: nonzero u32
  evidence_mode_id: RegistrySymbolV1
  state_transition_mode: PerformanceStateTransitionModeV1
  warmup_iterations, measured_iterations: u64
  baseline, protected, added: LatencyDistributionV1
  cpu_time_ns, peak_resident_bytes: u64
  requested_events, emitted_events, lost_events: u64
  threshold_record_id: RegistrySymbolV1
}

CapacityPerformanceRecordV1 {
  resource_kind: CapacityResourceKindV1
  configured_capacity, largest_successful_cardinality,
    first_failed_cardinality, peak_bytes: u64
  expected_exhaustion_result: ResultCodeIdV1
  observed_exhaustion_result: ResultCodeIdV1
  health_transition_result: ResultCodeIdV1
}

PerformanceQualificationRecordV1 {
  qualification_record_id: QualificationRecordIdV1
  platform_support_manifest_digest, product_build_digest: DigestV1
  cpu_microcode_memory_numa_digest: DigestV1
  kernel_btf_boot_lsm_digest: DigestV1
  runtime_kubernetes_digest, bpf_object_set_digest: DigestV1
  workload_fixture_digest, policy_fixture_digest: DigestV1
  signed_threshold_set_digest, raw_sample_bundle_digest: DigestV1
  operation_records[1..128]: sorted unique OperationPerformanceRecordV1
  capacity_records[1..128]: sorted unique CapacityPerformanceRecordV1
}

PerformanceQualificationBundleV1 {
  bundle_version: exactly 1
  architecture_revision_digest, product_build_digest: DigestV1
  platform_support_manifest_digest: DigestV1
  records[1..256]: sorted unique PerformanceQualificationRecordV1
  canonical_payload_digest: ArtifactContentIdV1
  seal: SignedArtifactSealV1
}
```

Capability probes use `CapabilityRecordV1` and `CapabilityBundleV1` from
Appendix A. Both capability and performance bundles use deterministic CBOR,
SHA-256, and Ed25519 with distinct domain strings. Performance records contain
measurements and the signed threshold-set identity, not stored pass/fail
verdicts. Release qualification derives its gate result by requiring every
mandatory row, threshold, digest, build, platform, and minimum-sample rule to
agree. That derived release gate is not a functional-test or authorization
result.

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
| `NativeSecurityStateOwner` | `mithril-node` plus owned BPF transitions | Task/process/native-family/mm state, inherited restrictions, and local response refs | Build provider graph conclusions or merge independent IPC peers |
| `PolicyDesiredStateOwner` | Control | Accept policy and exception source revisions, reconcile list/watch state, lower the base policy, validate bounded exception requests, and project bounded CRD status | Sign or activate a candidate, select a node, expose internal-only fields, treat status as authority, or store evidence/graph data in a CRD |
| `PolicyCompiler` | Control | Validate/lower source policy and sign immutable artifact | Change a node's active pointer |
| `PolicyRolloutOwner` | Control | Freeze policy target snapshots; resolve exact exception generation, grant, workload, Node, and boot targets; deliver signed candidates; and maintain exact inventory | Write node BPF maps, change exception use state, claim cluster-wide atomic activation, or accept a stale acknowledgement |
| `PolicyActivationOwner` | `mithril-node` | Stage/read back/probe generation, read the expected pointer, publish the active pointer, count generation retention, and retire or roll back generations | Own native-family membership, pending intent, or response semantics |
| `ExceptionAuthorityOwner` | `mithril-node` plus the BPF effect gate | Durable bounded exception instances, receipts, restart recovery, and atomic pre-effect use consumption | Approve an exception, select a Kubernetes target, refund an unproved use, or widen the compiled grant |
| `KernelHostOwner` | `mithril-node` | One loader, link/map object lifecycle, ABI, capability state | Invent roles or semantic transitions |
| `ObjectAndSocketStateOwner` | `mithril-node` effect modules | Exact object/socket identity, lifetime, peer resolution, and IPC relationship result | Mutate native-family membership or infer byte provenance |
| `CoverageHealthOwner` | Node source plus merged control view | Source epochs, sequences, intervals, gaps, negative-claim eligibility | Change physical decisions |
| `LocalEvidenceOwner` | `mithril-node` | Canonical local observations, WAL, upload acknowledgement | Repair a deny after the fact |
| `EvidenceIntakeOwner` | Control | Authenticate and durably append node evidence, then advance the contiguous acknowledgement | Rewrite node evidence, repair gaps, or build graph edges |
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
native-family state. `PolicyActivationOwner` changes only the generation reference
those objects hold.

`PolicyDesiredStateOwner`, `PolicyCompiler`, `PolicyRolloutOwner`, and
`PolicyActivationOwner` form one ordered policy path, but each retains one
state transition. `EvidenceIntakeOwner` ends the transport transaction.
`GraphAndFindingOwner` starts a separate derived-state transaction from the
committed input. A module name, CRD controller, or shared database does not
permit one owner to perform another owner's transition.

The same gatherer may expose a cgroup-scoped, read-only observation stream to
Erebor Runtime. Runtime cannot load overlapping BPF programs/maps, assign a
Mithril role, mutate a response, or become another durable owner.

### 35. Delivery Phases

Architecture prose does not authorize implementation. The master plan and the
exact phase file must allocate the work, its tests, and its exit result.

Phase 0 has a required order. First, hostile prototypes prove the actual hook,
helper, field, ordering, and failure behavior for every surface allocated to
Version 1. Only after those probes pass may the corresponding Rust/BPF ABI,
schema, enum, fixture, and golden bytes freeze. “Freeze first and discover the
real hook in Phase 3” is forbidden. A surface that has not passed the prototype
gate remains `UNALLOCATED` or `UNSUPPORTED` and is absent from the frozen claim.

Supported userspace IPC uses typed gRPC methods. Each product boundary keeps
one versioned Protobuf API package and can declare multiple typed services.
Unary and streaming shapes follow the domain flow. A generic `Execute`,
message-kind dispatcher, or payload union cannot replace typed service
routing. Local services use Unix sockets and authorize the `SO_PEERCRED`
identity carried in request extensions. Node-control services use mTLS and
separate typed streams when Control must send work over a node-initiated
connection. A gRPC stream does not replace a durable cursor or anti-replay
generation.

| Phase | Product slice and required exit |
| --- | --- |
| 0 | Inventory every allocated surface and run hostile feasibility prototypes against its selected stock hooks and integrations first. Record real fields, helper availability, ordering, failure behavior, installation boundary, and unsupported paths. Then close every active type in `ExactTypeClosureRecordV1` and freeze only the proven Rust/BPF ABI, source and compiled schemas, capability/performance records, source-evidence registry, fixture registry, result words, and golden bytes. |
| 1 | Ship one Rust node process, one loader/pin lease, capability probes, base cgroup/runtime inventory, authenticated local transport, and boot readiness. A second loader cannot own the pin root. |
| 2 | Implement task/process/exec cookies, task-first fork/thread/vfork/non-leader-exec transitions, native-family state, bootstrap, initial/native/external/unresolved roots, and restart reconciliation. |
| 3 | Implement observation/classification for the exec/file/mm/socket/device/privilege/shared-channel paths already qualified in Phase 0; run candidate policy simulation and the complete bypass suite. If implementation discovers a missing hook, field, or object identity, the affected surface returns to the Phase 0 prototype/type-closure gate and its claim remains unsupported. No prevention claim comes from an unpaired hook. |
| 4 | Enforce signed immutable exec/file/device/privilege policy, entry miss behavior, exact decision precedence, IPC relationships, optional descriptor-passing evidence, and local deny/reject semantics. |
| 5 | Enforce role-aware socket lifecycle, local peer relationships, final destination, DNS/IP floor, packet and established-flow fence, and shared-socket blast radius. |
| 6 | Complete source sequences, WAL, coverage intervals, immutable generation recovery, link/map/pin health, restart/reuse truth, and sole-gatherer failure. |
| 6.1 | Replace supported custom-framed IPC with typed gRPC services, remove the ptrace protocol exception, split node-control operations by service family, and prove peer identity, bounds, cancellation, reconnect, and durable cursor behavior. |
| 6.2 | Add the production `WorkloadProtectionPolicy` and bounded `WorkloadProtectionException` CRDs, capability-grounded lowering, Control desired-state reconciliation, compile/sign/target/distribution, exact node rollout inventory, and durable Control evidence intake. Keep node activation and graph ownership separate. |
| 7 | Extend committed Phase 6.2 evidence and policy provenance into the one Control graph owner. Implement `HF-PROC-001`, `HF-DW-001`, authority behavior, deterministic package replay, notification routing, and provider-neutral leases. |
| 8 | Join Kubernetes audit/object/runtime evidence, build typed multi-node graph, and prove fan-out/reuse/contradiction behavior. |
| 9 | Implement response roots, cgroup/socket actions, explicit blast-radius approval, replacement-controller watch, readback, and verified postconditions. |
| 10 | Add separately qualified mesh, AWS, connector, artifact, GitHub evidence/lease/response packages. Each adapter proves identity limits and one typed actuator. |
| 11 | Qualify exact root classification and every configured stock OCI/NRI/runtime/Kubernetes integration for each advertised platform; package, upgrade, scale, performance, and full conformance; sign the limited release claim. |
| 12 | Optional upstream/EDR evidence adapters. They feed the same graph and do not add a second gatherer or authorize named CI adapters. |

#### Contract-to-code route

These are proposed monorepo module families, not final crate names. Phase 0 may
rename them, but it cannot split one durable owner across daemons or omit the
listed proof.

| Contract | First schema / physical phase | Proposed owner and code family | Concrete exit proof |
| --- | --- | --- | --- |
| Shared Rust/BPF ABI, exact-type closure, closed enums, map/link manifest, capability and source registries, golden bytes | 0 / 1 | `erebor-linux-sensor-abi`; generated C header + Rust types; `erebor-linux-sensor-host::KernelHostOwner`; Phase 0 schema checker | Every active `*V1` name is exact or an exact alias; Rust/C byte equality; second loader cannot acquire pin-root lease; failed attach is `UNSUPPORTED`. |
| Typed local and node-control gRPC services | 1 / 6.1 | `erebor-runtime-ipc` generated local services; `mithril-control` generated mTLS node services; existing Runtime, node, and Control domain owners | Descriptor closure; Unix peer and mTLS identity rejection; no custom frame, generic envelope, ptrace exception, fallback listener, false durable acknowledgement, or owner change. |
| Offline base-policy YAML, Kubernetes policy and exception desired state, internal signed compiled artifact, rollout, rollback, dispositions | 0 / 4 / 6.2 | `mithril-control::policy_schema`, `PolicyDesiredStateOwner`, `PolicyCompiler`, `PolicyRolloutOwner`; node `PolicyActivationOwner` and `ExceptionAuthorityOwner` | `CFG-V1-GOLDEN-002`, public-spec/offline equality, public-to-internal lowering, absent-field rejection, target-bound exception activation with guarded live-process migration, bounded consumption, relist/restart, stale acknowledgement, partial rollout, rollback/replay, inactive readback, allow/deny probes, expected-pointer readback, and active-pointer publication. |
| Fixture/family/claim/qualification schemas | 0 / 11 | `mithril-e2e::qualification_schema` and `QualificationOwner` | `FIXTURE-REGISTRY-COMPLETE-001`; digest splice, missing negative control, degraded-PASS, and wrong platform all reject. |
| Task/process/exec identity and native inheritance | 0 / 2 | `mithril-node::identity::NativeSecurityStateOwner`; owned `lifecycle.bpf.c`, `exec.bpf.c` | Fork-without-exec label before token open; moved-task/non-leader exec/PID reuse/ref cleanup pass. |
| Process/native-state/set/mm state | 0 / 2-4 | Same `NativeSecurityStateOwner`; kernel maps hold native-family restrictions, while `KernelHostOwner` only owns their lifecycle | Thread races cannot recover authority; map N+1 fails closed; Rust/BPF decision bytes agree; partial VMA snapshot never relaxes. |
| Runtime roots and cgroup binding | 0 / 1-4; platform claim 11 | `mithril-node::identity::WorkloadBindingOwner`; configured stock adapter only forwards documented facts | Identical application-child/probe/admin/direct-runtime commands: native child keeps lineage; indistinguishable external roots get the same restricted role. The approved administrative exception is stronger only through the configured short-lived one-use next-match slot, with the rare race explicitly accepted. Unresolved protected effects deny. No general command-based purpose. |
| File, descriptor, mapping, IPC, process-control and persistent object classification | 0 / observe 3, deny 4 | `mithril-node::effect`; direct actor transitions requested from `NativeSecurityStateOwner` | Symlink/bind/proc-fd/rotation/mmap/fd-pass/io_uring/persistent volume either allow, alert, deny, or return exact unsupported. |
| Socket identity, local peer relationship, destination, packet fence | 0 / observe 3, deny 5 | `mithril-node::effect::network` | Broad-created socket passed to a narrow actor cannot restore egress; loopback/Pod-IP/Unix communication uses the resolved peer relationship; established-flow oracle states blast radius. |
| Source sequence, coverage, WAL, restart reconstruction, durable Control intake | 0 / 6 / 6.1 / 6.2 | `mithril-node::evidence::{CoverageHealthOwner,LocalEvidenceOwner}`; `mithril-control::intake::EvidenceIntakeOwner` | Typed evidence RPC preserves the Phase 6 cursor; ring pressure preserves deny but gaps absence claim; restart changes epoch and reconciles live tasks/sockets/claims before admission; storage failure withholds contiguous acknowledgement and node WAL truncation. |
| Local and distributed detection graph | 0 / 7-8, provider 10 | `mithril-control::graph`, `mithril-control::detections` | Node-A process to node-B root uses audit/object/binding edges; shared credential plus time remains contextual. |
| Notification delivery | 0 / 7 | `mithril-control::notifications::NotificationRouter` | Secret fields reject; retry/dedupe do not duplicate finding or response; sink outage never relaxes enforcement. |
| Local/Kubernetes/provider response | 0 / 9-10 | `mithril-control::response::ResponseCoordinator`; authenticated node actuator; one provider actuator per capability | Stale PID/object UID denies; any wider cgroup/socket/workload effect requires explicit blast-radius approval; readback plus healthy watch is required for verified response. |
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
| Operator-owned L7 mediation | `UNALLOCATED_OPTIONAL` | Direct TLS remains the baseline; no semantic request prevention claim | Add a distinct mediation owner and deployment profile, authenticated client/upstream/result contracts, semantic failure posture, and fixtures. Mithril must not silently inject a proxy, redirect traffic, replace DNS, or install a workload CA. |
| Host daemons, developer machines, and non-Kubernetes agents | `UNALLOCATED_OPTIONAL` | Kubernetes/runtime bindings are the only allocated entry bindings; this is not needed for the current Kubernetes/Hugging Face scope and makes no host-daemon or developer-agent enrollment claim | Add exact existing system-manager/cgroup/executable-integrity source contracts, a pre-first-protected-effect installation proof, non-Kubernetes policy selectors, and PID-reuse/exec/fork fixtures. A userspace PID map populated after the task runs is never authority admission. |
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
| Production policy source | Stored typed `WorkloadProtectionPolicy` `.spec` plus applicable bounded `WorkloadProtectionException` objects; offline restricted base-policy YAML is review/import input | The public API cannot embed the internal policy document. Node-side watches, free-form YAML in a CRD string, and CRD status as authority are rejected. |
| CRD deletion | Remove the profile from complete desired node inventory; retain local protection until runtime inventory proves the matching lifetime is absent | Object disappearance, namespace deletion, finalizer removal, or Control outage cannot erase live protection. |
| Partial rollout | Report the exact candidate and active generation for each target; stop on signed rollout conditions | A Kubernetes `Available` condition or aggregate count cannot mean cluster-wide atomic activation. |
| Overlapping base policies | At most one policy can match one Pod; reject conflicts and keep the previous valid generation for existing targets | Name, namespace, creation time, priority, source order, and “deny wins” cannot compose policies. A bounded exception can change only a grant named by that one base policy. |
| Upstream code | Reuse ideas/code only after Phase 0 license/provenance review; keep Mithril Rust chassis | A fork must replace, not duplicate, the single owner. |
| Intent | Signed envelopes only for real Mithril/operator/provider authorization | Stock kubelet/runner events remain facts with their actual proof quality; signing a normalized observation does not create missing purpose. |
| `aws`/`gcloud`/`gsutil` | Normal native processes; login is separate authority lease | CLI-specific entry kinds are rejected. |
| Dispositions | Physical `allow`/`deny`/`reject` separate from alert/notification/response | Any unified enum must preserve stage legality and exact meanings. |
| CI | Model real job/step/native/container/service roots and artifact edges | One workflow/Pod tree loses remote jobs, service containers, and artifact causality. |

### 37. When The Architecture Is Actually Complete

Completion is not “the daemon stayed alive” and not “an alert was emitted.” It
requires these twelve results on every advertised platform:

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
12. Every production policy revision has an exact CRD source, signed candidate,
    target snapshot, node acknowledgement, and active-generation chain.
    Reconcile, deletion, partial rollout, restart, and Control/API outage cannot
    create stale authority, silent policy removal, or premature evidence
    acknowledgement.

The release is decided from a digest-bound artifact set, not from two loose
files: platform manifest, capability bundle, exact-type-closure bundle, fixture
registry, case-level result bundle, performance bundle, completion ledger,
qualification envelope, and exact signed release claims. Appendix A defines
those records. Appendix C defines the closed fixture set and criterion mapping.

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
| Digest | Closed algorithm enum plus fixed-length bytes; used only for immutable signed content, independently stored/transferred content, or content-addressed identity |
| Node time | Unsigned 64-bit monotonic boottime nanoseconds |
| Remote time | Signed UTC nanoseconds plus uncertainty and source clock information |
| Optional ID | Explicit presence plus value; all-zero bytes never mean absent |
| Enum | A named Rust enum or tagged union owns the logical variants. A fixed integer width and unknown-value rule are required only at a shared BPF ABI or explicitly allocated wire schema. |
| Collections | Declared maximum, unique/sorted when order is not semantic, rejected on duplicate/overflow |
| Serialization | Restricted duplicate-free source YAML; deterministic CBOR for signed or hashed records |
| Digest/signature | SHA-256 and Ed25519 in Version 1; each signed record family has a distinct ASCII domain separator |

### A.1.1 Exact foundation, not exhaustive modeling

This document deliberately closes the durable security foundation, not every
convenience, display, or in-memory helper type. A type must have an exact
schema before it can cross a security, persistence, or interoperability
boundary: a policy decision, BPF ABI, signed or hashed artifact, wire/disk
record, recovery state, release claim, or evidence field used for grouping,
deduplication, or authorization. A descriptive type may remain readable prose
until an implementation needs it, but it cannot silently cross one of those
boundaries. The catalog marks that distinction explicitly in A.8.

The shared foundation is deliberately small. These are Rust type families,
not a new numeric wire registry: an enclosing wire or BPF contract allocates a
representation only when it actually crosses that boundary.

```rust
type NodeIdentityV1 = Id128; // stable Node UID/enrollment identity, never node_boot_id
type ExceptionInstanceIdV1 = Id128;
type ExceptionNumericHandleV1 = NonZeroU32;
type ExceptionUseCountV1 = NonZeroU32;
type SigningKeyIdV1 = BoundedBytes<1, 128>;
type Ed25519SignatureV1 = [u8; 64];
type ArtifactContentIdV1 = DigestV1;

struct SignedArtifactSealV1 {
    signer_key_id: SigningKeyIdV1,
    signature: Ed25519SignatureV1,
}

enum ExceptionUseIdentityV1 {
    ClaimSlot { claim_slot_id: Id128 },
    KernelEffectAttempt { request_identity: ExactRequestIdentityV1 },
}

enum ExceptionBindingStateV1 { Preparing, Active, Retiring }
enum ExceptionStateV1 {
    Preparing, Active, Exhausted, Expired, Tombstoned, ReconciliationRequired,
}
enum ExceptionReceiptStateV1 {
    Claiming, Consumed, DeniedExhausted, DeniedExpired, DeniedCorrupt,
    ReconciliationRequired,
}
```

The remaining shared references are scalar aliases, not new record families:
`PolicyLocalIdV1` is the existing bounded policy-local name,
`RegistrySymbolV1` the existing bounded registry symbol, `CapabilityIdV1`,
`OracleValidatorIdV1`, and `OracleSchemaIdV1` are registry symbols,
`CapabilityRecordIdV1` and `QualificationRecordIdV1` are `Id128`, and
`FixtureIdV1`/`FixtureCaseIdV1` are the existing bounded logical fixture names.

`ArtifactContentIdV1` is SHA-256 of the deterministic canonical unsigned
record. It appears only when another record must refer to that artifact
independently. Every `SignedArtifactSealV1` is outside the unsigned record;
the enclosing record family owns its fixed ASCII domain separator, so using
the common seal never permits one family to verify as another.

Digest use is deliberately narrow. Ordinary in-memory records do not acquire a
digest merely because they are named types. Node-local runtime identities
normally use `Id128` or a non-reused epoch-scoped numeric handle. One signature
and digest over a complete immutable parent policy generation covers its
canonical child records; those children do not repeat their own digest. A child
has a digest only when it is independently stored, transferred, signed,
content-addressed, or must retain immutable identity outside its parent.

Phase 0 generates Rust and C layout assertions for every shared BPF ABI type:
size, alignment, field offset, integer width, byte order, enum value, maximum,
and golden bytes. Logical records in this document are not permission to
choose separate convenient layouts.

```text
ExactObjectKindV1: u8 =
  0 UNKNOWN | 1 REGULAR_FILE | 2 DIRECTORY | 3 SYMLINK | 4 PIPE |
  5 UNIX_SOCKET | 6 INET_SOCKET | 7 MEMFD | 8 SHARED_MEMORY |
  9 DEVICE | 10 PROC_OBJECT | 11 KERNEL_SECURITY_OBJECT |
  12 OTHER_QUALIFIED

PortableProfileGenerationV1 {
  profile_id: Id128
  owner_generation: nonzero u64
  compiled_artifact_digest: DigestV1
}

ExactObjectGenerationV1 {
  object_kind: ExactObjectKindV1
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
| Root classification, runtime/container facts, binding/topology snapshot, approved administrative-exec slot | Chapters 6-7 define the stock-system and risk-accepted administrative algorithms; Appendix A.9 fixes task/container identity and the exact BPF slot. Historical held-task records in A.9.7 are rejected, not implementation requirements. |
| `SignedIntentV1`, signed body union, administrative-exec approval, trust generation, replay records | Chapter 8 limits these records to real Mithril/operator/provider authorization; Appendix A.10 defines canonical CBOR, tags, bounds, trust, and replay. It never requires kubelet or a CI runner to sign. |
| `InvariantQualificationV1` | Chapter 10: one invariant, capability/source proof, stimulus, decision point, physical result, coverage, artifacts, status |
| `PolicyDocumentV1`, signed compiled profile, rollback authorization, `EffectDecisionKeyV1`, generation descriptors | Chapters 11-13 explain behavior; Appendices A.11-A.12 fix parser/signature/activation and Rust/BPF map semantics |
| Mount/file/VMA/socket/device/IPC/process-control records | Chapters 15-21 explain behavior; Appendices A.13-A.14 fix object, hook-family, lifetime, native-state, peer-relationship, and descriptor-passing contracts. Historical join/publication schemas are rejected. |
| `ObservationEnvelopeV1`, `CoverageIntervalV1`, `ProofQualityV1`, `FindingV1`, graph nodes/edges | Chapters 22-23 explain proof; Appendix A.15 fixes fields, intervals, direct-edge requirements, and determinism |
| Response plan/target/application/postcondition records | Chapter 24 explains response; Appendix A.15.4-A.15.6 fixes authorization, re-resolution, state, readback, and watch |
| CI run/job/process/artifact/lease/evidence records | Chapter 26 explains stock facts and limits; Appendix A.16 separates job/process evidence from optional official step joins and rejected patched-runner records |

All implementers must use this index. A field needed for a security decision
but absent from the closed record is a schema change, not an undocumented
side map or display annotation.

Documentation supersession is also machine-readable so rejected architecture
cannot become active because an implementer followed an older paragraph:

```text
SupersessionRegistryV1 {
  records[1..4096] {
    supersession_id: ASCII 1..128 bytes
    retained_statement_ids[1..64]: sorted unique ASCII 1..128 bytes
    controlling_statement_ids[1..64]: sorted unique ASCII 1..128 bytes
    replacement_contract_ids[1..64]: sorted unique ASCII 1..128 bytes
    affected_card_ids[0..256]: sorted unique registered card IDs
    forbidden_contract_ids[0..64]: sorted unique ASCII 1..128 bytes
    reason_code: RegistrySymbolV1
    proof_source_evidence_ids[0..64]: sorted unique Id128
  }
}

SupersessionHeadingSetV1 = sorted unique array[0..4096] of the
  retained/controlling statement IDs extracted from marked correction and
  rejected-design headings.
```

The registry and extracted set must agree. Neither needs a per-record digest;
the independently stored qualification/release parent binds the complete
canonical registry when it is used for a release.

### A.3 Source evidence

```text
EvidenceBoundaryNatureV1: u8 =
  0 UNKNOWN | 1 IMPLEMENTATION_CHOICE | 2 PLATFORM_CONTRACT |
  3 PROTOCOL_BOUNDARY | 4 CONFIGURATION_BOUNDARY

EvidenceAssertionModeV1: u8 =
  0 UNKNOWN | 1 SOURCE_PROVES | 2 SOURCE_SUPPORTS | 3 INFERENCE |
  4 HOSTILE_HYPOTHESIS

EvidenceRelationshipV1: u8 =
  0 UNKNOWN | 1 ADOPT | 2 HARDEN | 3 HOSTILE_TEST | 4 DO_NOT_INHERIT |
  5 CONTEXT_ONLY

SourceRangeV1 {
  repository_url: canonical HTTPS URL
  commit_or_version: bounded ASCII 1..128 bytes
  path: normalized repository-relative UTF-8 path, 1..4096 bytes, no `..`
  first_line, last_line: nonzero u32, last_line >= first_line
  blob_digest: DigestV1
}

SourceEvidenceClaimV1 {
  evidence_id: Id128
  atomic_claim_id: nonzero u16
  project: KUBEARMOR | TETRAGON | BPFJAILER | LINUX | OCI | KUBERNETES |
           PROVIDER
  ranges[1..16]: SourceRangeV1
  observation: bounded UTF-8 text with LF line endings
  boundary_nature: EvidenceBoundaryNatureV1
  assertion_mode: EvidenceAssertionModeV1
  relationship: EvidenceRelationshipV1
  dependent_fixture_ids[]: sorted unique registered fixture IDs
  reviewed_by: Id128
  reviewed_at_utc_ns: i64
  claim_digest: DigestV1
}
```

`boundary_nature` and `relationship` are separate. For example, a mutable map
update is an implementation choice and `HARDEN`; TLS payload opacity is a
protocol boundary and may be `CONTEXT_ONLY` plus a provider-gate requirement.
The display table cannot infer either field from a generic “kind.” One
`SourceEvidenceClaimV1` is atomic: a row that makes independently supportable
claims becomes multiple records rather than one prose digest over several
claims. Its digest is retained because source claims are independently stored
and referenced by fixtures and release evidence.

### A.4 Capability and performance bundles

```text
enum CapabilityStateV1 { Supported, Unsupported, Degraded, Unhealthy }

CapabilityRecordV1 {
  capability_record_id: CapabilityRecordIdV1
  capability_id: CapabilityIdV1
  capability_schema_version: nonzero u32
  platform_support_manifest_digest, product_build_digest: DigestV1
  node_or_fixture_platform_id: Id128
  probe_input_digest, observed_kernel_runtime_result_digest: DigestV1
  state: CapabilityStateV1
  reason_code: ReasonCodeIdV1
  measured_at_utc_ns: i64
}

CapabilityBundleV1 {
  bundle_version: exactly 1
  architecture_revision_digest, product_build_digest: DigestV1
  platform_support_manifest_digest: DigestV1
  capability_records[1..4096]: sorted unique by capability_record_id
  canonical_payload_digest: ArtifactContentIdV1
  seal: SignedArtifactSealV1
}
```

The closed performance records are in Chapter 33. Their unsigned bundle is
signed over:

```text
ASCII("MITHRIL-PERFORMANCE-BUNDLE-V1") || 0x00 ||
SHA-256(canonical_unsigned_bundle)
```

The capability bundle uses `MITHRIL-CAPABILITY-BUNDLE-V1`. The unsigned view
omits its `seal`; its content ID is recomputed from that canonical unsigned
view. The `OtherRegistered` enum variants carry their required registry ID;
unknown operation/resource IDs require a checked-in registry update.

### A.5 Closed platform assurance and exact claims

Every field below exists even when unsupported. An implementation cannot hide
a family by omitting it.

```text
enum AssuranceAxisV1 {
  BootAndAdmissionAvailability, InitialRuntimeEntry,
  LaterRuntimeEntryAndStreaming, CheckpointRestoreAndAttach,
  NativeTaskProcessExecIdentity, PolicyGenerationAndCgroupBinding,
  MountTopologyAndNamespace, FileObjectNamespaceAndIo,
  VmaAndExecutableMemory, ProcessAndAuthorityDomainState,
  IpcRelationshipAndDescriptorPassing, SocketNetworkAndDns,
  DeviceAndDerivedKernelObjects, PrivilegeKernelEscapeAndSelfProtection,
  SeccompFloor, LandlockFloor, LocalEvidenceAndCoverageTruth,
  MultiNodeAndProviderGraph, KubernetesAndProviderSemanticAuthority,
  ArtifactProvenanceAndTrust, LocalAndDistributedResponse,
  CiExecutionAndArtifactIdentity, PerformanceAndCapacity,
}

enum EvaluationStageV1 {
  EntryAdmission, NativeTransition, LocalPreEffect, RemotePreAdmission,
  PostEffect, Response,
}

AssuranceAxisRecordV1 {
  axis: AssuranceAxisV1
  capability_record_ids[0..256]: CapabilityRecordIdV1
  supported_stages[0..6]: sorted unique EvaluationStageV1
  claim_vector_ids[0..256]: Id128
  required_fixture_ids[0..256]: FixtureIdV1
  passed_result_ids[0..256]: Id128
  unsupported_or_degraded_paths[0..256]: UnsupportedPathV1
}

AssuranceAxesV1 = sorted unique array[1..23] of AssuranceAxisRecordV1 by axis

PlatformSupportManifestV1 {
  schema_version: exactly 1
  manifest_id: Id128
  architecture_revision_digest, product_build_digest: DigestV1
  architecture: X86_64 | AARCH64
  kernel_release_build_id_and_btf_digest: DigestV1
  boot_config_and_lsm_order_digest: DigestV1
  landlock_capability_record_id?: CapabilityRecordIdV1
  seccomp_capability_record_id?: CapabilityRecordIdV1
  container_runtime_name_version_config_digest: DigestV1
  kubernetes_version_and_streaming_shape_digest?: DigestV1
  bpf_program_link_map_manifest_digest, capability_bundle_digest: DigestV1
  assurance_axes: AssuranceAxesV1
  unsupported_paths[0..256]: sorted unique UnsupportedPathV1
  claim_vector_ids[0..1024]: sorted unique Id128
  performance_qualification_record_ids[0..256]: sorted unique QualificationRecordIdV1
  canonical_payload_digest: ArtifactContentIdV1
  seal: SignedArtifactSealV1
}

ClaimVectorV1 {
  claim_vector_id: Id128
  assurance_axis: AssuranceAxisV1
  object_family, operation, authority_boundary: RegistrySymbolV1
  evaluation_stage: EvaluationStageV1
  result: CONTEXTUAL_OBSERVATION | EXACT_OBSERVATION | PRE_EFFECT_DENIAL |
          SEMANTIC_REJECTION | VERIFIED_RESPONSE | UNSUPPORTED
  proof_quality: ProofQualityV1
  capability_record_ids[0..256]: CapabilityRecordIdV1
  required_fixture_ids[0..256]: FixtureIdV1
  passed_fixture_result_ids[0..256]: Id128
  required_coverage_predicates[0..64]: RegistrySymbolV1
  unsupported_path?: UnsupportedPathV1
  performance_qualification_id?: QualificationRecordIdV1
}

UnsupportedPathV1 {
  object_family, operation: RegistrySymbolV1
  stage: EvaluationStageV1
  missing_capability_or_evidence: ReasonCodeIdV1
  degraded_result: UNSUPPORTED | INSUFFICIENT_COVERAGE |
                   OBSERVATION_ONLY | NOT_APPLICABLE
  prohibited_product_statements[1..64]: bounded UTF-8 1..1024 bytes
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
FixtureIdV1 = ASCII matching ^[A-Z][A-Z0-9_-]{2,127}$
FixtureCaseIdV1 = lowercase ASCII 1..128 bytes

FixtureAllocationConditionV1: u8 =
  0 UNKNOWN | 1 ALWAYS | 2 WHEN_CLAIM_VECTOR_REFERENCES |
  3 WHEN_SURFACE_ALLOCATED_AND_ADVERTISED

enum FixtureDispositionV1 {
  Admit, AuditAdmit, RejectRequest, AllowEffect, AuditAllowEffect, DenyErrno,
  RecordOnly, Finding, ResponseProposal, VerifiedResponse, Unsupported,
}

enum QualificationResultV1 { Pass, Fail, Unsupported, InsufficientCoverage }

FixtureCaseV1 {
  case_id: FixtureCaseIdV1
  allocation_condition: FixtureAllocationConditionV1
  topology_digest, starting_state_digest, stimulus_digest: DigestV1
  expected_stage: EvaluationStageV1
  expected_disposition: FixtureDispositionV1
  expected_result: ResultCodeIdV1
  required_coverage_predicates[0..64]: RegistrySymbolV1
  oracle_schema: OracleSchemaIdV1
  oracle_validator_id: OracleValidatorIdV1
  oracle_artifact_expectation_digest: DigestV1
  negative_control_case_ids[0..64]: FixtureCaseIdV1
  degraded_result: UNSUPPORTED | INSUFFICIENT_COVERAGE |
                   OBSERVATION_ONLY | NOT_APPLICABLE
}

NormativeFixtureRegistryV1 {
  architecture_revision_digest: DigestV1
  fixtures[1..4096] {
    fixture_id: FixtureIdV1
    id_kind: FIXTURE | META_TEST
    source_section_id: ASCII 1..128 bytes
    owning_phase_and_crate: ASCII 1..256 bytes
    criterion_numbers[1..11]: sorted unique u8 in 1..11
    assurance_axes[1..23]: sorted unique AssuranceAxisV1
    prerequisite_capability_ids[0..256]: CapabilityIdV1
    upstream_source_evidence_ids[0..256]: Id128
    cases[1..256]: FixtureCaseV1
  }
}

FixtureCaseResultV1 {
  fixture_case_result_id: Id128
  fixture_id: FixtureIdV1
  case_id: FixtureCaseIdV1
  starting_state_digest, stimulus_digest: DigestV1
  observed_stage: EvaluationStageV1
  observed_disposition: FixtureDispositionV1
  observed_result: ResultCodeIdV1
  observed_coverage_interval_ids[0..64]: sorted unique Id128
  oracle_artifact_ids[0..16]: ArtifactContentIdV1
  canonical_oracle_digest: DigestV1
  negative_control_case_result_ids[0..64]: Id128
  result: QualificationResultV1
}

FixtureAggregateResultV1 {
  fixture_id: FixtureIdV1
  active_case_ids[0..256], dormant_case_ids[0..256]: FixtureCaseIdV1
  case_results[1..256]: sorted unique FixtureCaseResultV1 by case_id
  aggregate_result: QualificationResultV1
}

FixtureResultBundleV1 {
  result_bundle_id: Id128
  product_build_digest, platform_support_manifest_digest: DigestV1
  fixture_registry_digest: DigestV1
  fixture_results[1..4096]: sorted unique FixtureAggregateResultV1 by fixture_id
  canonical_payload_digest: ArtifactContentIdV1
  seal: SignedArtifactSealV1
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

```rust
type CanonicalFieldPathV1 = RegistrySymbolV1;
type FixtureLogicalSlotIdV1 = RegistrySymbolV1;

enum CanonicalAliasActualIdV1 {
    RuntimeId(Id128),
    ContentId(DigestV1),
}

struct FixtureAliasBindingV1 {
    actual_id: CanonicalAliasActualIdV1,
    logical_slot_id: FixtureLogicalSlotIdV1,
}

enum CanonicalFieldRuleV1 {
    Exact { field: CanonicalFieldPathV1 },
    IgnoreDisplay { field: CanonicalFieldPathV1 },
    TimeOffsetFromStimulus { field: CanonicalFieldPathV1 },
    OrderedList { field: CanonicalFieldPathV1 },
    KeySortedSet {
        field: CanonicalFieldPathV1,
        key_fields: BoundedVec<CanonicalFieldPathV1, 1, 16>,
    },
    CountedMultiset {
        field: CanonicalFieldPathV1,
        key_fields: BoundedVec<CanonicalFieldPathV1, 1, 16>,
    },
}

enum CanonicalIntervalPredicateV1 {
    TimeOffsetWithin {
        field: CanonicalFieldPathV1,
        earliest_offset_ns: i64,
        latest_offset_ns: i64,
    },
    IntegerWithin {
        field: CanonicalFieldPathV1,
        minimum: i64,
        maximum: i64,
    },
}

CanonicalOracleComparatorV1 {
  schema_version: exactly 1
  fixture_alias_bindings[0..256]: sorted unique FixtureAliasBindingV1 by actual_id
  field_rules[1..256]: sorted unique CanonicalFieldRuleV1 by field
  interval_predicates[0..64]: sorted unique CanonicalIntervalPredicateV1 by field
  expected_canonical_digest: DigestV1
}
```

The rules define the complete comparator projection. Every selected field has
exactly one field rule; an unknown selected field, duplicate rule, unresolved
alias, invalid collection key, or interval with `earliest > latest` fails the
fixture. `IgnoreDisplay` is allowed only for a field that cannot affect proof,
result, authorization, coverage, grouping, or a security decision. Time rules
replace absolute time with the signed offset from the fixture stimulus. The
expected digest is calculated over the resulting deterministic projection,
including explicit source-order gaps where an `OrderedList` selects them.

```text

CompletionLedgerV1 {
  ledger_id: Id128
  architecture_revision_digest, product_build_digest: DigestV1
  platform_support_manifest_digest, capability_bundle_digest: DigestV1
  exact_type_closure_bundle_digest: DigestV1
  fixture_registry_digest, fixture_result_bundle_digest: DigestV1
  performance_qualification_bundle_digest: DigestV1
  criteria[1..11]: sorted unique by criterion_number {
    criterion_number: 1..11
    claim_vector_ids[0..256]: Id128
    prerequisite_capability_ids[0..256]: CapabilityIdV1
    acceptance_fixture_ids[0..256]: FixtureIdV1
    accepted_result: exactly QualificationResultV1::Pass
    result_artifact_ids[0..256]: ArtifactContentIdV1
    status: QualificationResultV1
  }
}

QualificationEnvelopeV1 {
  qualification_id: Id128
  architecture_revision_digest, product_build_digest: DigestV1
  platform_support_manifest_digest, capability_bundle_digest: DigestV1
  exact_type_closure_bundle_digest: DigestV1
  fixture_registry_digest, fixture_result_bundle_digest: DigestV1
  completion_ledger_digest, performance_qualification_bundle_digest: DigestV1
  generated_at_utc_ns: i64
  release_qualifier_identity: Id128
  canonical_payload_digest: ArtifactContentIdV1
  seal: SignedArtifactSealV1
}

ReleaseClaimV1 {
  claim_id: Id128
  qualification_envelope_digest: DigestV1
  claim_vector_ids[1..256]: Id128
  human_statement: bounded UTF-8 1..4096 bytes
  valid_for_exact_platform_manifest_digest: DigestV1
  seal: SignedArtifactSealV1
}
```

The qualifier checks every signature and digest, exact fixture-set equality,
platform/build equality, coverage predicate, negative control, oracle, and
performance threshold. Data from another node, kernel, build, or registry
cannot be spliced in. A required non-`PASS` case makes every dependent claim
ineligible.

### A.8 Complete Version 1 type-ownership catalog

This catalog owns every Version 1 type that crosses the exact foundation and
retains only enough descriptive, rejected, or unallocated names to prevent
accidental promotion. It does not require one Rust struct per row. Closed enum
bodies and generated ABI views may share an implementation, but no required
information may disappear.

The catalog is not itself a field definition. Every name receives one of five
machine-checked states before any Version 1 freeze:

```text
ExactTypeClosureRecordV1 {
  type_name: ASCII matching ^[A-Z][A-Za-z0-9]{0,127}V1$
  status: EXACT_SCHEMA | EXACT_ALIAS | DESCRIPTIVE | UNALLOCATED | REJECTED
  controlling_section_id: ASCII 1..128 bytes
  alias_target_type_name?: ASCII 1..128 bytes
  used_by_rust: bool
  used_by_bpf: bool
  used_on_wire_or_disk: bool
}

ExactTypeClosureBundleV1 {
  architecture_revision_digest: DigestV1
  records[1..4096]: sorted unique by type_name
  active_type_name_set_digest: DigestV1
  canonical_payload_digest: ArtifactContentIdV1
  result: PASS | FAIL
}
```

`EXACT_SCHEMA` defines fields, bounds, enum values, encoding, transitions, and
failures. `EXACT_ALIAS` names one exact target and may only narrow it.
`DESCRIPTIVE` is allowed only in explanation or non-durable local display and
planning code; it cannot appear in a policy decision, BPF ABI, signed/hashed
or wire/disk record, recovery state, release claim, or grouping/deduplication
key. Promotion across any such boundary is a schema change.
`UNALLOCATED` cannot appear in accepted policy or release claims. `REJECTED`
cannot appear in production code or active fixtures.

The Phase 0 checker extracts every active `*V1` name. An `EXACT_SCHEMA` name
defined only in this catalog fails the build; a `DESCRIPTIVE` name fails if it
is used across an exact-foundation boundary. So do duplicate owners, missing
exact sections, alias cycles, BPF types without Rust/C layout checks, and
signed types without canonical bytes. This prevents names such as `LookupStepV1`,
`SetReferenceClassV1`, and `VmaIteratorSessionIdentityV1` from having a stated
job but no exact shape.

The remaining intentionally non-struct names have explicit status:

| Names | Closure status |
| --- | --- |
| `DigestV1` | `EXACT_ALIAS`: Appendix A.10.1 fixes algorithm tag `1` and exactly 32 SHA-256 bytes. |
| `NormativeFixtureSetV1` | `EXACT_ALIAS`: exactly the sorted unique fixture IDs in Appendix C.1. |
| `RuntimeEntryIntentV1`, `DeploymentAdmissionIntentV1`, `ArtifactHandoffIntentV1` | `REJECTED`: old wrapper names; the signed body union is controlling. |
| `CiPolicyV1` | `UNALLOCATED`: the source policy surface cannot be accepted until the CI adapter/schema phase gives it an exact definition. The generic coordinator, trust, and execution-shape enums remain active for evidence. |
| `BarrierEvidenceV1`, `RuntimeSetupBudgetV1`, `RestoreTargetBirthSlotV1` | `REJECTED`: depended on a held stock-runtime/rootfs/task barrier that Mithril does not own. |
| `CheckpointRestoreIntentV1` | `UNALLOCATED`: restore remains restricted/unknown without a qualified existing authorization and birth join. |
| `DomainSensitiveStateRuleV1`, `DomainSensitiveTransitionKeyV1`, `DomainSensitiveTransitionValueV1` | `REJECTED` old names: `NativeAuthorityStateRuleV1` and `NativeAuthorityTransition*V1` are controlling and never join independent domains. |
| `NetworkEffectKeyV1` | `REJECTED`: it required current actor and final rewritten destination at one hook; the two-stage actor/flow contracts in A.13.4 are controlling. |
| `PersistentVolumeAuthorityV1` | `REJECTED` old owner: `PersistentVolumePolicyV1` plus `VolumeAccessReadinessV1` are controlling. |

#### A.8.0 Shared scalar, enum, and artifact foundation

| Types | One job |
| --- | --- |
| `SigningKeyIdV1`, `Ed25519SignatureV1`, `SignedArtifactSealV1` | One reusable Rust signature shape; each enclosing family retains its own domain separator and wire representation. |
| `ArtifactContentIdV1` | Canonical unsigned content identity for an independently referenced artifact. |
| `NodeIdentityV1` | Stable node identity distinct from the node-boot epoch. |
| `CapabilityIdV1`, `OracleValidatorIdV1`, `OracleSchemaIdV1` | Typed registry-backed scalar IDs; unregistered values reject. |
| `CapabilityRecordIdV1`, `QualificationRecordIdV1`, `FixtureIdV1`, `FixtureCaseIdV1` | Opaque or bounded logical identifiers used in release and fixture joins. |
| `EvaluationStageV1`, `FixtureDispositionV1`, `QualificationResultV1`, `CapabilityStateV1` | Shared Rust enums where one concept is used by several records. |
| `PerformanceOperationV1`, `PerformanceStateTransitionModeV1`, `CapacityResourceKindV1` | Closed benchmark operation/resource/state vocabulary, with registered extensions only where declared. |
| `AssuranceAxisV1`, `AssuranceAxisRecordV1`, `AssuranceAxesV1` | One bounded platform-assurance axis and its exact capability/fixture/claim allocation. |
| `ExceptionInstanceIdV1`, `ExceptionNumericHandleV1`, `ExceptionUseCountV1` | Stable instance identity, generation-local handle, and bounded use-count scalar. |
| `ExceptionBindingStateV1`, `ExceptionStateV1`, `ExceptionReceiptStateV1`, `ExceptionUseIdentityV1` | One exception state machine and its typed, idempotent-use variants. |

#### A.8.1 Policy source, registries, and compilation

| Type | One job |
| --- | --- |
| `PolicyDocumentV1` | Closed source-policy root whose canonical bytes are signed and compiled |
| `KubernetesDesiredSourceRevisionV1` | Immutable tenant, cluster, CRD kind and identity, generation, canonical public spec, and deletion state for one policy or exception source |
| `PolicyExceptionCandidateV1` / `PolicyExceptionAcknowledgementV1` | One signed, exact-target activation or revocation for a precompiled base-policy file grant and its authenticated node result |
| `PolicyTargetV1` / `PolicyTargetSnapshotV1` | Exact immutable node/workload target set for one rollout revision |
| `PolicyDeliveryCandidateV1` | Signed target-bound activation or replacement candidate sent by Control to one node |
| `PolicyActivationAcknowledgementV1` | Authenticated node receipt that binds candidate, boot/label epoch, node-bound generation, readback, probe, and state |
| `PolicyRolloutStateV1` | Durable per-target Control projection of delivery and activation truth; never node authority |
| `PolicyLocalIdV1` | Bounded ID that is meaningful only inside one signed profile; never a global object identity |
| `RegistrySymbolV1` | Bounded symbolic atom resolved inside one signed registry generation; it is not a durable numeric identity |
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
| `NativeAuthorityStateRuleV1` | Monotonic rule that adds or checks restriction state shared by one native process family |
| `DetectionDispositionRuleV1` | Human allow/alert/deny/reject plus finding/notification/response bindings |
| `FallbackV1` | Explicit degraded result for a named missing capability/source; never issuer-selected fail-open |
| `BudgetSetV1` | Bounded counts, rates, lifetimes, concurrency, and depth |
| `ExceptionV1` | Signed, expiring, scoped authority delta with uses and approver |
| `FileExceptionGrantTemplateV1` | Signed base-policy template for one named set of denied file rules and its maximum duration and uses; it is not an active instance |
| `ExactExceptionSubjectSelectorV1` | Immutable exact workload/entry/role/key subject of an exception; no `*` |
| `PermittedAuthorityDeltaV1` | Machine-readable permission widening or narrowing that an exception requests |
| `ExceptionUseIdentityV1` | Exact claim-slot or kernel-effect-attempt identity that makes exception consumption idempotent across programs |
| `ExceptionHandleBindingKeyV1` / `ExceptionHandleBindingV1` | Generation-local numeric exception handle resolved to one stable exception instance on this node |
| `ExceptionRuntimeStateKeyV1` / `ExceptionRuntimeStateV1` | One pinned per-node BPF owner for a stable exception instance's maximum and consumed-use count across profile generations |
| `ExceptionUseReceiptKeyV1` / `ExceptionUseReceiptV1` | One durable per-logical-use claim preventing several rules or programs from charging the same exception twice |
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
| `GenerationLocalRoleHandleV1` | One profile-generation-scoped lowering from a reusable role name to a nonzero BPF role handle |
| `GenerationLocalDestinationPolicyHandleV1` | One profile-generation-scoped lowering from a reusable destination-policy name to a nonzero BPF destination handle |
| `GenerationLocalExceptionHandleV1` | One profile-generation-scoped lowering from a reusable exception name to a nonzero BPF exception handle |
| `GenerationLocalPolicyIdMapV1` | Immutable, read-back-verified role, destination, and exception handle tables for one node-local profile generation |
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
| `TaskLabelV1` | Immutable task-to-process/entry/binding birth identity; never cached final authority |
| `TaskInstanceV1` / `ProcessInstanceV1` | Live kernel coordinates and finalization state for one task/process instance |
| `ProcessSecurityStateV1` | Sole mutable current role, execution, profile, domain, response, and exec-guard owner for one process |
| `EntrySecurityStateV1` | Optional claim, admission outcome, root process, reference count, and lifetime for one entry |
| `AuthorityDomainStateV1` | Native-family monotonic restriction and response state; it never joins independent roots |
| `PendingExecV1` | One bounded script/binfmt/ELF-loader exec attempt through commit or failure |
| `ExternalRootClassificationV1` | Exact conservative result for an independent protected root and any qualified purpose evidence |
| `AdministrativeArgvV1` / `BoundedExecutionApprovalArgvV1` | Administrative-workflow and generic fixed BPF views of exact approved raw arguments |
| `PendingExecutionApprovalV1` | Task/exec-attempt-local proof that one execution approval slot was reserved, verified, and consumed |
| `SignedIntentV1` | Canonical signed authorization envelope for a capability-gated intent body |
| `EntryKindV1` | Closed root class: initial, native, external-unknown, restore-unknown, and qualified registered purpose. Probe/lifecycle/admin is legal only when an existing interface proves it. |
| `EntryClassificationV1` | Exact or conservative classification, candidate set, proof, and ambiguity result |
| `EntryRoleAssignmentV1` | Proven root classification -> initial process role and retained profile generation |
| `EntryAdmissionMatchV1` | Bound policy predicate for an initial, external, or unresolved root; never an argv ticket match |
| `PreparedExternalRootStateV1` | **Rejected no-patch design.** It described a held runtime root that stock interfaces do not provide. |
| `ExecutionSetBindingStateV1` | Container execution-set lifecycle and exact cgroup binding |
| `BindingLifecycleStateV1` | PREPARING/ACTIVE/DRAINING/TERMINATING/TOMBSTONED floor applied to task/object decisions |
| `WorkloadBindingActivationStateV1` | Node transaction from prepared binding through active/terminating/tombstoned |
| `WorkloadBindingArtifactV1` | Signed/hashed Pod-container-image-cgroup-profile binding proof |
| `NodeAdmissionRequestV1` | Bounded authenticated Kubernetes/runtime request presented to an allocated admission interface |
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
| `StateBitDefinitionV1` | Source-policy definition for one process or native-authority state bit and its legal transitions |
| `ProcessStateDefinitionV1` | Allowed state-vector shape and transitions for one profile |
| `RoleDefinitionV1` | Entry origins, base effects, budgets, transitions, and authority behavior for one role |
| `TransitionKindV1` | Closed owner of one atomic transition: none, process, or native authority |
| `NativeOperationV1` | Closed fork/thread/vfork/exec/credential native operation |
| `RuntimeOperationV1` | Closed operation name used only for facts or controls a qualified stock runtime integration actually exposes |
| `NativeRoleTransitionRuleV1` | Source role + native operation + target -> one target role/restriction |
| `NativeTransitionMatchV1` | Exact current state and operation selector |
| `TransitionDescriptorV1` | Compiled transition result, reference effects, and evidence rule |
| `ProcessTransitionKeyV1` / `ProcessTransitionValueV1` | Kernel exact-key and result for native transition |
| `TransitionIntentV1` | Optional signed Mithril authorization for a transition Mithril actually controls; never created from an ordinary kubelet event |
| `NativeTransitionBodyV1` | Closed signed-intent body for a native transition |
| `IntentKindV1` | Closed body union tag; CI is value `7` and Mithril-approved administrative exec is value `8` |
| `IntentBodyV1` / `IntentPayloadV1` | Canonical target-bound signed body union and common claims |
| `RuntimeEntryBodyV1` | Optional body for a qualified existing integration that supplies a real authorization and unique request/task identity; unused for ordinary stock roots |
| `AdministrativeExecBodyV1` / `ApprovedAdministrativeExecV1` | Exact Mithril-issued approval checked at Kubernetes admission; stream flags remain admission facts and are not a Linux-task match |
| `ResolvedAdministrativeExecutableV1` | User-approved command name plus the exact executable object resolved in the target container view |
| `ExecutionApprovalSlotKeyV1` / `ExecutionApprovalSlotV1` | Generic one-use node/BPF exec slot keyed by live cgroup binding; administrative approval is one issuer and the slot records the explicitly accepted next-match race |
| `KubeletExecutionRequestV1` | **Rejected no-patch design.** Stock kubelet/CRI supplies no such signed probe/lifecycle request. |
| `ExactRequestIdentityV1` | Stable request/attempt/issuer identity used for replay and graph joins |
| `KernelClaimTombstoneV1` | Pinned consumed/rejected fact only for a real Mithril-owned one-use authorization; not required for stock external-root classification |
| `TokenConsumptionObservationV1` | Exact claim/lease/token-handle consumption attempt and result, not secret bytes |
| `RuntimeEntryIntentV1` | **Abandoned name** replaced by `IntentPayloadV1(kind=RUNTIME_ENTRY)` plus `RuntimeEntryBodyV1` |

#### A.8.3 Compiled generation and decision ABI

| Type | One job |
| --- | --- |
| `PortableProfileGenerationV1` | Cross-node profile/generation identity for one immutable compiled artifact |
| `ProfileGenerationRefV1` | Non-reused node-local handle binding a portable generation to boot and label epoch |
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
| `PhysicalDecisionV1` | Allow, audit-allow, or exact errno with state transition and optional shared exception-consumption handle |
| `EffectDecisionKeyV1` | Role/effect/operation/composite object/process-domain-lifecycle exact key |
| `MonotonicSetTransitionKeyV1` / `MonotonicSetTransitionValueV1` | `REJECTED` collapsed names; Appendix A.12.5 separates process transitions from native-authority transitions because one BPF hook cannot atomically mutate both map values |
| `NativeAuthorityTransitionKeyV1` / `NativeAuthorityTransitionValueV1` | Atomic old native-family restriction state -> stricter state transition |

#### A.8.4 Mounts, files, memory, native authority, and IPC

| Type | One job |
| --- | --- |
| `ExactObjectGenerationV1` | Common non-reused live object generation used by file, socket, memory, device, and kernel-object contracts |
| `MountViewIdentityV1` / `LiveMountObjectV1` | Exact mount namespace/topology and live mount identity used during resolution |
| `NetworkNamespaceIdentityV1` | Exact netns cookie/live interval plus qualified capture mechanism |
| `MountNamespaceStateV1` | Admission-time mount namespace identity and retained ABI state. It does not authorize a post-start topology decision. |
| `MountSecurityViewV1` | Actor-visible mount/root/propagation/read-only/security view used for object resolution |
| `MountSourceClassRecordV1` | Exact declared/image/projected/host/device/remote mount source classification |
| `VolumeMountBarrierV1` | **Rejected design.** Mithril never owns, holds, or releases a mount or root filesystem. |
| `PersistentVolumePolicyV1` | Signed cross-node volume identity, access policy, participants, generation, and anti-rollback state. |
| `VolumeAccessReadinessV1` | Active per-node record proving that the current persistent-volume policy was installed and read back before BPF allows a covered file effect. This is an access gate, not a mount or task hold. |
| `FileObjectIdentityV1` | Mount namespace generation + mount/fs/inode/version/live identity and object kind |
| `FileInstanceProvenanceV1` | Open-time file identity, source object, opener, generation, and current file-policy floor; descriptor-transfer history is not required |
| `DelegatedIoEdgeV1` | Typed causal edge from a file/local-channel effect through the real kernel/process/service delegate to remote IO |
| `CreateKeyV1`, `SetattrKeyV1`, `RenameKeyV1`, `LinkKeyV1`, `UnlinkKeyV1` | Exact filesystem namespace mutation keys; no path-only authority |
| `SourceMutabilityProofV1` | Sealed-memfd, immutable content/image, or held-writer reconciliation proof for the interval in which source bytes were immutable |
| `KernelExecutableMappingClassV1` | File/anonymous/memfd/JIT mapping, write/execute history, loader purpose |
| `MmSnapshotIdentityV1` | Exact mm cookie, sharing generation, snapshot version, begin/end state |
| `VmaIteratorSessionIdentityV1` | Node/boot/mm/snapshot/session identity for one iterator run |
| `VmaIteratorSessionV1` | BEGIN/RECORD/END lifecycle, expected sharers, counters, gaps, outcome |
| `VmaIteratorFrameV1` | One exact VMA range, backing, permissions, provenance, and sequence |
| `VmaSnapshotV1` | Canonical complete or typed-partial set of frames and sharers |
| `CommunicationAuthorityDomainV1` | **Rejected.** Independent roots do not become one domain because they communicate. |
| `DomainSensitiveBitV1` | Monotonic restriction shared only by a native process family. |
| `SharedResourceStateV1` | **Rejected as byte-taint authority.** Exact objects still retain identity, policy floors, and response state. |
| `CrossEntryTransferControlV1` | `REJECTED`; replaced by `IpcRelationshipRuleV1` and the configured unmatched-IPC result. |
| `IpcEndpointSelectorV1` / `IpcChannelSelectorV1` | Readable endpoint pair and connection-oriented channel selector compiled to exact runtime identity; shared objects and directional process control are excluded. |
| `IpcRelationshipRuleV1` | One bidirectional communication disposition; it does not interpret bytes or descriptors. |
| `IpcChannelStateV1` | Exact live channel, resolved socket peers or observed pipe users, matched relationship, and applied disposition. |
| `IpcDescriptorPassingV1` | Communication edge plus descriptor-passing observation and communication result; it does not identify the represented object. |
| `IpcCapabilityTransferV1` | **Rejected.** Version 1 does not require exact object tracking for descriptor passing. |
| `SharedObjectAcquisitionV1` | Current actor, exact shared file/memory object, governed acquisition or file operation, result, and capability lifetime; never a per-CPU-access claim. |
| `AuthorityDomainJoinTransactionV1` | **Rejected.** There is no live-domain merge transaction. |
| `DomainJoinQuiescenceV1` | **Rejected.** Mithril does not claim global quiescence or async drain. |
| `DomainJoinRootProgressV1` | **Rejected historical live-merge state.** |
| `DomainJoinTargetProgressV1` | **Rejected historical live-merge state.** |
| `LocalInetChannelIdentityV1` | Netns/protocol/address/port/listener/socket generation and local peer set |
| `PublicationIdAllocatorV1`, `PublicationSlotV1`, `PublicationLeaseStateV1` | **Rejected historical byte-publication design.** |
| `PublicationDescriptorV1`, `PublicationDescriptorLifetimeV1`, `PublicationTransferPlanV1` | **Rejected historical byte-publication design.** |
| `PublicationPayloadSourceV1`, `UserBufferSegmentV1`, `PublicationInstanceV1` | **Rejected as byte-provenance authority.** Physical syscall/packet/provider results remain ordinary evidence. |
| `AuthorityDomainPublicationStateV1`, `PersistentPublicationCapabilityV1`, `PersistentFileSecurityStateV1` | **Rejected.** Mithril does not propagate inferred byte sensitivity or serialize global publication. |
| `RejectedSharedResourceTaintStateV1`, `RejectedPersistentFileTaintStateV1` | **Rejected retained schemas.** Present only to make byte-taint implementations fail closure review. |
| `ExactPublicationSinkV1` | **Rejected byte-publication name.** Exact destinations use the normal file/socket/provider records. |
| `LocalObjectSelectorV1` | Compiler-owned exact local object selection input; paths remain explanation |

#### A.8.5 Network, devices, and privilege

| Type | One job |
| --- | --- |
| `ActorSocketDecisionKeyV1` | Sender-stage current actor/domain + socket/netns + operation + requested peer key |
| `SocketFlowAuthorizationV1` | Actor-stage result installed on one socket/flow generation for later final-destination enforcement |
| `FinalFlowDecisionKeyV1` | Packet/flow-stage socket generation + final post-rewrite destination key; it never requires a fictional current task |
| `SocketProvenanceV1` | Immutable creator identity/domain/generation and later owner/pass/accept history |
| `ResolvedSocketOrChannelGenerationV1` | Exact socket/channel lifetime after bind/connect/accept/redirect resolution |
| `SocketControlEffectKeyV1` | `setsockopt`, bind/listen/accept/shutdown and other socket-control operation key |
| `DestinationPolicyRecordV1` | Versioned address/service/port/protocol class, final-route proof, packet requirement |
| `DeviceClassRecordV1` | Device type, major/minor, path-independent class, approved operation/ioctl registry |
| `DeviceFileEffectKeyV1` | Current actor + exact device fd/generation + open/read/write/ioctl/mmap key |
| `DerivedKernelCapabilityObjectV1` | TUN, io_uring, BPF link/map, perf, KVM/GPU context, keyring, pidfd, or similar authority-bearing object |
| `SecurityObjectRecordV1` | Exact process/kernel security target for ptrace, credentials, namespaces, module, BPF, perf, keyring, proc/sysctl |
| `ProcessControlEffectKeyV1` | Directional controller + exact live target task + exact ptrace/process-vm/proc/pidfd/signal operation key |
| `SeccompFloorProofV1` | **Deferred surface.** Future exact filter proof only after the Seccomp evaluation gate approves a qualified new-process start path; never a retroactive arbitrary-PID claim |
| `LandlockFloorProofV1` | Target-context installer proof: measured ABI, exact ruleset and flags, syscall result, thread scope, ordering, and qualification result; never an external arbitrary-PID attachment claim |

#### A.8.6 Evidence, graph, findings, and response

| Type | One job |
| --- | --- |
| `ObservationEnvelopeV1` | Source sequence, time, typed payload, proof vector, coverage interval, and transport integrity for one observation |
| `CoverageIntervalV1` | Healthy/gapped source interval and exact loss/suppression accounting under one source epoch |
| `EvidenceBatchV1` | Bounded one-source-epoch node upload with ordered envelopes, coverage records, and batch integrity |
| `EvidenceIntakeReceiptV1` | Durable Control commit and contiguous acknowledgement for one node/source epoch |
| `PolicyObservationProvenanceV1` | Exact or explicitly incomplete join from accepted node observations to source revision, candidate, target snapshot, and active node generation |
| `ProofQualityV1` | Orthogonal source, subject, result, temporal, and integrity proof axes |
| `FindingV1` | Deterministic revision over evidence, coverage, subject, package, and window |
| `GraphSubjectKindV1` / `SourceKindV1` / `EvidenceFieldIdV1` | Closed graph/provider-edge registry atoms |
| `ProviderEdgeContractV1` | Exact fields, coverage, proof, direction, and negative control required for one direct provider edge |
| `EvidenceBoundaryNatureV1` | Implementation, platform, protocol, or configuration boundary |
| `SourceEvidenceClaimV1` | One atomic pinned source claim, its ranges, proof mode, relationship, review, and dependent fixtures |
| `EvidenceAssertionModeV1` | Source proves/supports, inference, or hostile hypothesis |
| `EvidenceRelationshipV1` | Adopt, harden, hostile-test, do-not-inherit, or context-only |
| `SourceRangeV1` | Repository/commit/path/line/blob identity for one atomic source claim |
| `EvidenceFieldKeyV1` | Closed field selector used by notification and redaction policy |
| `EvidenceFieldV1` | Typed canonical observation field value with sensitivity, presence, provenance, and proof |
| `EvidencePayloadV1` | Bounded unique set of typed evidence fields carried by one observation |
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
| `ResponseActionRequestV1` / `ResponseActionResultV1` | One action identity, idempotency key, and typed terminal result inside a response plan |
| `ResponseBindingV1` | Finding/package/result -> allowed response spec and policy version |
| `ResponsePlanV1` | Authorized immutable set of actions, target revisions, ordering, rollback/expiry |
| `ResponseDecisionKeyV1` / `ResponseDecisionV1` | Exact local response restriction lookup and result |
| `TargetRevalidationV1` | Re-resolved live pidfd/cgroup/socket/object/provider target before actuation |
| `BlastRadiusLimitV1` | Maximum tasks/domains/workloads/sockets/resources that approval permits |
| `PhysicalPostconditionV1` | Exact readback and healthy watch predicate that makes response verified |

#### A.8.7 Provider, deployment, artifact, and CI intent

| Type | One job |
| --- | --- |
| `AuthorityLeaseIntentV1` | One capability-gated provider lease request bound to an exact local/job subject, scope, nonce, and deadline |
| `CredentialLeaseV1` | Authoritative issued provider credential/lease identity, scope, expiry, and revocation state without secret bytes |
| `ProtectedCredentialHandleV1` | Nonexportable provider-secret reference usable only by a narrowly authorized self-revocation operation |
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
| `CiOfficialStepTaskJoinEvidenceV1` | Authenticated evidence from an allocated official interface that carries one unique step-to-task join |
| `CiExecutionBindingV1` | Active step/job role, cgroup/root/native tree, policy, workspace, credential audiences |
| `JobExecutionEpochV1` | Nonreused run/job/attempt/runner reuse boundary and cleanup tombstone |
| `CiStateArtifactV1` | `GITHUB_ENV`, PATH, outputs, workspace, cache, socket, background process, or startup-file handoff with producer trust |
| `CiCoordinatorV1` | Closed generic coordinator vocabulary used by evidence; each named adapter transport and trust contract remains separately unallocated |
| `CiPolicyV1` | Closed future CI policy surface; parser rejects it until allocated |

#### A.8.8 Qualification-only and deprecated record names

| Type | Status and meaning |
| --- | --- |
| `KernelCapabilityRecordV1`, `CapabilityRecordV1`, `CapabilityBundleV1` | Exact measured kernel/platform capability result and signed bundle |
| `AssuranceAxesV1`, `AssuranceAxisRecordV1`, `ClaimVectorV1` | Closed support axes and exact claim-to-capability/fixture/coverage allocation |
| `PlatformSupportManifestV1`, `UnsupportedPathV1` | Exact supported platform identity and explicitly unsupported/degraded paths |
| `InvariantQualificationV1` | One invariant's capability, stimulus, boundary, physical result, evidence, oracle, and status |
| `FixtureIdV1`, `FixtureAllocationConditionV1`, `FixtureCaseV1` | Closed fixture identity, allocation condition, and one executable stimulus/oracle case |
| `NormativeFixtureRegistryV1` | Closed source-of-truth registry of fixture cases, criteria, capabilities, and owners |
| `FixtureCaseResultV1`, `FixtureAggregateResultV1`, `FixtureResultBundleV1` | Case, fixture, and signed bundle qualification results |
| `LatencyDistributionV1`, `OperationPerformanceRecordV1`, `CapacityPerformanceRecordV1` | Recorded operation latency/resource distributions and bounded-capacity outcomes |
| `PerformanceQualificationRecordV1`, `PerformanceQualificationBundleV1` | Platform/build-bound performance records and their signed release bundle |
| `CanonicalFieldPathV1`, `FixtureLogicalSlotIdV1`, `CanonicalAliasActualIdV1`, `FixtureAliasBindingV1`, `CanonicalFieldRuleV1`, `CanonicalIntervalPredicateV1`, `CanonicalOracleComparatorV1` | One complete typed normalization recipe and expected digest for a fixture oracle |
| `CompletionLedgerV1`, `QualificationEnvelopeV1`, `ReleaseClaimV1` | Criterion ledger, signed artifact envelope, and exact-platform release claim |
| `ImplementationCardV1` | Human implementation card that must map to a distinct executable fixture ID |
| `FixtureFamilyV1` | Explicit nonempty sorted fixture membership; wildcards forbidden |
| `NormativeFixtureSetV1` | Exact fixture-ID set printed in Appendix C.1 |
| `CriterionFixtureRequirementV1` | Criterion 1..11 + allocation condition + exact fixture IDs from Appendix C.2 |
| `ExactCompletionIdentityV1` | Exact architecture/build/platform/registry/result/performance digest tuple under qualification |
| `ExactTypeClosureRecordV1` | Exact-schema/alias/unallocated/rejected status and controlling section for every Version 1 name |
| `ExactTypeClosureBundleV1` | Complete sorted active-name set and closure result bound to the architecture revision |
| `PerformanceQualificationV1` | `REJECTED` untyped sketch replaced by the typed Chapter 33 records |

Types such as `LocalEffectMatchV1`, `DeviceFileEffectKeyV1`,
`SocketControlEffectKeyV1`, and `EntryAdmissionMatchV1` are compiler inputs to
one normalized decision cell. They do not create parallel policy engines.
Types such as `RuntimeEntryIntentV1`, `DeploymentAdmissionIntentV1`, and
`ArtifactHandoffIntentV1` remain only to document old names; the wire uses the
single signed intent envelope and a closed body union.

#### A.8.9 Qualification and documentation records

These records organize implementation and qualification. They do not enter a
kernel authorization lookup.

```text
ImplementationCardV1 {
  card_id: registered card ID
  real_world_stimulus: UTF-8 1..4096 bytes
  starting_task_entry_role_and_authority: UTF-8 1..4096 bytes
  authoritative_inputs[1..64]: UTF-8 1..4096 bytes
  exact_decision_boundary: UTF-8 1..4096 bytes
  ordered_map_and_state_reads[1..64]: UTF-8 1..4096 bytes
  compiled_policy_key: bstr(1..4096)
  physical_disposition: ResultCodeIdV1
  evidence_emitted[0..64]: EvidenceFieldKeyV1
  degraded_or_unsupported_result: ResultCodeIdV1
  legitimate_negative_control_fixture_ids[1..64]: sorted unique fixture IDs
  hostile_fixture_ids[1..64]: sorted unique fixture IDs
  physical_or_provider_oracle: UTF-8 1..4096 bytes
  upstream_source_evidence_ids[0..64]: sorted unique Id128
  governing_statement_ids[1..64]: sorted unique ASCII 1..128 bytes
  supersession_dependency_ids[0..64]: sorted unique ASCII 1..128 bytes
}

FixtureFamilyV1 {
  family_id: registered fixture-family ID
  member_fixture_ids[1..4096]: sorted unique registered fixture IDs
}

CriterionFixtureRequirementV1 {
  criterion_number: u8 in 1..11
  requirement_condition: ALWAYS | WHEN_CLAIM_VECTOR_REFERENCES |
                         WHEN_SURFACE_ALLOCATED_AND_ADVERTISED
  exact_fixture_ids[1..4096]: sorted unique registered fixture IDs
}

ExactCompletionIdentityV1 {
  architecture_revision_digest, product_build_digest: DigestV1
  platform_support_manifest_digest, capability_bundle_digest: DigestV1
  exact_type_closure_bundle_digest: DigestV1
  fixture_registry_digest, fixture_result_bundle_digest: DigestV1
  performance_qualification_bundle_digest: DigestV1
  completion_ledger_digest: DigestV1
}
```

`NormativeFixtureSetV1` is exactly the sorted unique fixture-ID set in Appendix
C.1. Qualification records use digests because their job is to bind separately
stored release artifacts; this is not a reason to add digests to their
ordinary child fields.

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
which native-family restriction and response state applies?
is it still in the cgroup binding to which it was admitted?
```

The answer comes from one immutable task label followed by mutable state owned
by the process, entry, binding, and native-family state. A task label is never a
cached final decision.

#### A.9.1 Exact identity records

```text
EntryClassificationV1: u8 =
  0 UNKNOWN | 1 EXACT_TARGET | 2 SAME_BUDGET_AMBIGUOUS | 3 AMBIGUOUS

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
  claim_slot_id?: Id128
  root_task_cookie: nonzero u64
  root_process_state_id: Id128
  committed_execution_id: Id128
  live_task_refs: u64
  admission_state: PENDING | CLAIMING | COMMITTED | TERMINAL
  terminal_reason?: REJECTED | EXPIRED | CANCELLED | CLAIM_FAILED
  lifetime_state: INACTIVE | ACTIVE | DRAINING | COMPLETE
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

An ordinary stock-runtime root has no claim slot. A qualified claim-backed or
approved administrative root retains `Some(claim_slot_id)` for evidence after
consumption. `terminal_reason` is present exactly when
`admission_state=TERMINAL`. A committed entry has no terminal reason. Zero is
never used as an absent claim ID.

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
  state: OWNED | RELEASED | RECONCILIATION_REQUIRED
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
  node_boot_id: Id128
  label_epoch: nonzero u64
  task_cookie: nonzero u64
  process_state_id, entry_instance_id: Id128
  execution_set_id, cgroup_binding_id, cgroup_lifetime_id: Id128
  full_container_id: bstr(32..128)
  pod_uid: bstr(1..64)
  container_name_utf8: bstr(1..253)
  creator_task_cookie?: nonzero u64
  root_class: u8, 1 INITIAL_CONTAINER_ROOT | 2 EXTERNAL_RUNTIME_ROOT |
                  3 RESTORED_OR_UNKNOWN_ROOT | 4 UNRESOLVED_PROTECTED
  purpose: u8, 0 UNKNOWN | 1 QUALIFIED_JOINED_PURPOSE |
               2 APPROVED_ADMINISTRATIVE_NEXT_MATCH
  purpose_source_id?: Id128
  purpose_to_task_join_proof?: DigestV1
  administrative_approval_proof_id?: Id128
  administrative_claim_slot_id?: Id128
  proof_quality: ProofQualityV1
  profile_generation_ref_id: nonzero u64
  installed_role_class: u8, 1 INITIAL_ROLE |
                              2 RUNTIME_EXTERNAL_RESTRICTED |
                              3 FAIL_CLOSED_UNKNOWN |
                              4 QUALIFIED_REGISTERED_ROLE |
                              5 APPROVED_ADMINISTRATIVE_ROLE
  installed_role_numeric_id: nonzero u32
  classified_boottime_ns: u64
}
```

`QUALIFIED_JOINED_PURPOSE` requires an existing interface that proves both
purpose and a unique request-to-task join. Stock CRI probe and hook exec uses
`purpose=UNKNOWN`. Command, arguments, timing, TTY, PodSpec similarity, and a
local observation cannot upgrade it. Approved administrative exec instead uses
`APPROVED_ADMINISTRATIVE_NEXT_MATCH`: a short-lived, one-use match with an
accepted race. It is not a unique join, so it has no
`purpose_to_task_join_proof`.

`UNKNOWN` forbids every optional purpose and approval field.
`QUALIFIED_JOINED_PURPOSE` requires its source and join proof and forbids the
administrative fields. `APPROVED_ADMINISTRATIVE_NEXT_MATCH` requires approval
and slot IDs and forbids a join proof. Every other combination is invalid.

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

For approved administrative exec, the external root is still labeled
`RUNTIME_EXTERNAL_RESTRICTED` first. Syscall entry records only a provisional
bounded argv candidate. At the deny-capable pre-point-of-no-return `bprm` hook,
BPF can reserve the one-use slot and mark the approved role as pending without
activating it. This reservation path consumes any selected bounded exception
under the claim-slot receipt. The committing-creds hook verifies the copied
kernel-owned argv. The successful-exec hook verifies the installed argv,
consumes the slot, and performs the in-place role switch. There is no unlabeled
interval and no application descendant may inspect the slot.

No active record requires a held task, a setup ticket, a rootfs-ready ticket,
a kubelet signature, a new CRI method, or a command-based pending claim.

##### A.9.7.1 Exact approved administrative-exec contract

Consider `kubectl mithril exec conversion-worker -- bash`. Admission sees
the Pod, container, argv, and stream flags. The later Linux task has neither
the admission ID nor the original stream flags. Rust checks those Kubernetes
facts and resolves `bash` in the target container before arming the node. The
approval UI displays `bash -> <resolved path>` and the exact executable object.
BPF later checks only the live task, its verified cgroup binding, the complete
kernel-owned exec argument image, and that resolved executable identity.

The node lowers every approved one-exec authorization into the same generic
execution approval slot. Administrative approval is the first issuer. A later
approved agent request for a tool such as Bash must use this slot and the same
BPF transaction. It must not introduce an agent-specific exec gate.

`ApprovedAdministrativeExecV1` is not a second wire format. Its exact alias is:

```text
ApprovedAdministrativeExecV1 = SignedIntentV1 where
  payload.kind = ADMINISTRATIVE_EXEC
  payload.body = AdministrativeExecBodyV1
  length(payload.claim_slot_ids) = 1
```

Appendix A.10 defines its signed bytes. The node lowers that approval into this
fixed BPF ABI:

```text
ExecutionApprovalSlotKeyV1 {
  node_boot_id: Id128
  cgroup_binding_id: Id128
}

ExecutionApprovalSlotV1 {
  proof_id: Id128
  claim_slot_id: Id128
  cgroup_binding_nonce: Id128
  container_generation: nonzero u64
  expected_argv: BoundedExecutionApprovalArgvV1
  resolved_executable_object_key_id: nonzero u64
  resolved_executable_object_generation: nonzero u64
  target_role_numeric_id: nonzero u32
  profile_generation_ref_id: nonzero u64
  exception_numeric_handle: 0 | ExceptionNumericHandleV1
    // zero means no ExceptionV1 consumption
  expected_root_class: u8, exactly EXTERNAL_RUNTIME_ROOT
  deadline_boottime_ns: u64
  state: atomic u32, 1 ARMED | 2 CONSUMED | 3 EXPIRED |
                     4 CANCELLED | 5 CORRUPT | 6 RESERVED | 7 TAMPERED
  transition_version: nonzero u64
}

ResolvedAdministrativeExecutableV1 {
  requested_name_bytes: bstr(1..4096), no embedded NUL
  resolution_mode: ABSOLUTE | CONTAINER_CWD_RELATIVE | CONTAINER_PATH_SEARCH
  resolved_display_path_bytes: bstr(1..4096), absolute, no embedded NUL
  container_working_directory_bytes: bstr(1..4096), absolute
  effective_path_entries[0..64]: bstr(1..4096), absolute,
    in resolution order with duplicates preserved
  target_mount_namespace_id: Id128
  target_mount_topology_generation: nonzero u64
  executable_object: FileObjectIdentityV1
}

PendingExecutionApprovalV1 {
  task_cookie: nonzero u64
  exec_attempt_sequence: nonzero u64
  proof_id: Id128
  claim_slot_id: Id128
  state: ARGUMENTS_MATCHED | SLOT_RESERVED | KERNEL_ARGV_VERIFIED |
         SLOT_CONSUMED | TAMPERED
}
```

One cgroup binding has at most one `ARMED` slot. The BPF value omits Pod and
container names, people, stream flags, tokens, signatures, and free text. It
keeps only bounded raw argv for comparison. Rust has bound the other facts to
the cgroup ID, nonce, and container generation. This argv is the expected
value. BPF reads the current task's binding and compares the fixed fields above
with the kernel-owned exec argument image.

An administrative-exec body deliberately does **not** carry an exception ID:
the body proves who approved this exact exec, while the signed profile owns
which exact compiled cell can widen authority. A nonzero slot handle is valid
only when one selected `CompiledActionPlanV1.consuming_exception_id` resolves
through that profile generation to one `ExceptionInstanceIdV1`. No matching
plan, more than one candidate, a mismatched subject, or a profile-generation
mismatch denies before the slot is armed. This leaves one exception owner and
does not create a second signed exception selector in the exec protocol.

The signed approval contains the raw arguments exactly as Kubernetes decoded
them. Rust lowers them into this fixed-size BPF value; it does not hash them:

```text
AdministrativeArgvV1 {
  arguments[1..256]: bstr(0..4096)
  total_argument_bytes: 1..4096
}

BoundedExecutionApprovalArgvV1 {
  argument_count: u16, 1..256
  argument_lengths[256]: u16
  argument_bytes[4096]: u8
  total_argument_bytes: u16, 1..4096
}
```

`argument_bytes` stores arguments in order; `argument_lengths` stores their
exact lengths. Unused space is zero. Syscall entry compares the mutable argv to
this bounded value only to create a provisional task candidate. At the
deny-capable `bprm` hook, BPF matches that candidate and the exact executable,
then reserves the slot. The committing-creds hook compares count, order,
length, and bytes from the copied kernel-owned exec argument image. The
successful-exec hook repeats the comparison against the installed process
image. BPF does not copy raw argv into evidence or a durable map.

The first argument is the exact nonempty command name entered by the requester;
it may be `bash`, a relative path, or an absolute path. Before approval, the
node resolves it using the declared mode in the target container view and
returns `ResolvedAdministrativeExecutableV1` for display and signature. Slot
installation repeats the resolution and requires the same exact live object.
At the `bprm` check, provisional `argv[0]` must equal the approved first
argument while the actual executable object must equal the resolved object
generation. Both late checks must then confirm that kernel-owned `argv[0]` and
all later arguments equal the approved values. The syscall filename and
`argv[0]` need not be equal. Normal executable policy still checks the live
file before slot consumption. Embedded NUL, ambiguous or changed resolution,
unsupported syscall, incomplete capture, or any count or size limit makes the
request unavailable. Prefix and truncated matches are forbidden.

Raw argv can contain secrets. Show it only to the approver and keep it only in
the short-lived authorization and BPF slot. Do not emit it as normal telemetry
or copy it into the WAL. Remove it after durable consumption, cancellation, or
expiry.

Create `PendingExecutionApprovalV1` from the provisional syscall-entry match.
Bind it to the current exec attempt. Only its `KERNEL_ARGV_VERIFIED` state can
reach final consumption. Failure, task exit, a changed attempt, a missing
record, or mismatch consumes or corrupts the reservation and never restores it
to `ARMED`.

The kernel-owned argument image is the only BPF argv authority. Syscall-entry
memory can select a candidate, but it cannot grant a role. The exact executable
and candidate reserve authority before the point of no return. Complete copied
argv and installed process argv verify that reservation at the two late hooks.
BPF must not fall back to an executable-only match or activate a role from the
provisional candidate.

The one-use execution approval transition is intentionally simple:

```text
webhook checks approval and PodExecOptions
  -> Rust verifies live Pod/container/cgroup binding
  -> node appends proof/slot IDs and slot intent to WAL, without raw argv
  -> node installs and reads back ARMED slot
  -> webhook returns allowed
  -> syscall entry records an untrusted bounded argv candidate
  -> exact exec-file preflight passes only the kernel open that builds bprm; slot stays ARMED
  -> a caller in a multithreaded process can prepare a task-local candidate
  -> at the deny-capable bprm hook, BPF matches binding + candidate + executable + generation + deadline
  -> atomic ARMED -> RESERVED; approved role stays pending and inactive
  -> consume any selected bounded exception under the claim-slot receipt
  -> full exec chain passes normal pending-exec policy
  -> committing-creds verifies the complete copied kernel-owned argv
  -> successful-exec verifies installed argv
  -> atomic RESERVED -> CONSUMED and task switches to the approved role
  -> every later effect still uses normal role policy
```

Declared PostStart, PreStop, startup, readiness, and liveness probes use this
same transaction. A reusable probe declaration authorizes the node to create a
fresh task-bound execution approval slot for each invocation. Successful exec
consumes that slot once but does not consume the declaration. The same slot
shape, exec-file preflight, argv checks, late tamper response, and role
activation apply.

If exec or the role switch fails, the task gets no approved role and the slot
stays consumed or corrupt. It never returns to `ARMED`. A late mismatch or read
failure also queues `SIGKILL` before user mode and emits critical evidence.
After restart, admission stays
closed until pinned slots match the WAL. An unexpired slot survives only on the
same boot, binding nonce, and WAL record. Any mismatch cancels it or preserves
consumption; it never creates another use.

The accepted limit is visible in the ABI: admission checks stream flags, but
the BPF slot does not contain them. Another external root in the same live
container can win only with the same executable object and arguments. Its stream
shape may differ. Cluster policy and the administrator accept this bounded
race.

**Rejected design summary.** The discarded design required held setup tasks,
root-filesystem barriers, ticket-aware kubelet/runtime changes, or a pending
claim for an unlabeled task. Stock interfaces do not provide those guarantees,
and requiring them would violate the no-patch rule. The active contract is
above; Appendix B.2 keeps the rejection and its reason.

#### A.9.8 Current root-classification failures and required tests

| Failure | Required physical result |
| --- | --- |
| Protected parent or root has no label | Resolve it as initial, restricted external, restored/unknown, or fail-closed unresolved; never inherit application authority |
| Task, process, or binding map is full | Deny the returning task/effect hook where supported and install/retain the fail-closed floor; never call an unlabeled actor protected |
| PID-coordinate finalization fails | Keep `FAIL_CLOSED_UNKNOWN`; no protected effect succeeds |
| Rootfs/mount/object binding is incomplete | Keep the binding unresolved and deny affected protected effects; claim start rejection only if the configured stock hook returned it |
| Runtime/hook source authentication fails | Discard its metadata; kernel placement remains restricted and source coverage becomes unhealthy |
| Concurrent exec loses the guard CAS | Deny that attempt before staging |
| Exec success observer cannot update | Retain the already installed pending deny floor |
| `task_free` update fails | Leak the restriction and require reconciliation; never decrement by guess |
| Daemon restarts with labeled or unresolved tasks | Preserve pinned restrictions; re-enumerate runtime/cgroups/tasks and reconcile labels, references, and WAL before opening a healthy interval |

Mandatory tests include leader-exits-first threads, failed fork rollback,
double cleanup, PID/TID reuse, moved labeled parent, moved exec task,
`CLONE_INTO_CGROUP`, concurrent exec, non-leader exec,
shebang, `binfmt_misc`, approved and substituted ELF loaders, pre/post-point-of-
no-return failure, direct `crictl` exec, identical probe/hook/admin commands,
runtime restart, discovery delay, missing hook fields, forged hook metadata,
and every supported stock hook failure/timeout result.

Physical map-saturation behavior is allocated to Phase 4
`LSM-DENY-SATURATION-001`; it is not a Phase 2 identity-closure gate.

#### A.9.9 Checkpoint, attach, port-forward, and node-floor limits

Checkpoint restore is not an active no-patch contract. Mithril may reject it
through an existing authorization hook or restrict later effects with BPF, but
it does not patch CRIU/runtime to hold restored tasks. Checkpoint export is a
sensitive memory/file/socket/device export and remains `UNSUPPORTED` until its
own phase proves complete target enumeration, state preservation, an encrypted
sink, and the physical result.

Attach creates no process. Port-forward is not process egress. Mithril records
the existing Kubernetes actor, request UID, target, channel or ports, result,
and proof quality. It does not insert a stream proxy.

A configured stock Kubernetes admission or runtime extension may apply this
node hard-floor decision:

```text
NodeAdmissionFieldKeyV1: u16 =
  0 UNKNOWN | 1 PRIVILEGED | 2 ALLOW_PRIVILEGE_ESCALATION |
  3 HOST_PID | 4 HOST_IPC | 5 HOST_NETWORK |
  6 ADDED_CAPABILITY | 7 DROPPED_CAPABILITY |
  8 SECCOMP_PROFILE_KIND_AND_DIGEST |
  9 APPARMOR_PROFILE_KIND_AND_DIGEST | 10 SELINUX_OPTIONS |
  11 HOST_PATH_SOURCE_AND_FLAGS |
  12 HOST_DEVICE_SOURCE_AND_PERMISSIONS |
  13 PROC_MOUNT_MASKS | 14 PROC_MOUNT_TYPE | 15 RUNTIME_CLASS |
  16 USER_NAMESPACE_MODE | 17 PID_IPC_NETWORK_NAMESPACE_TARGET |
  18 SYSCTL_NAME_AND_VALUE | 19 MOUNT_PROPAGATION |
  20 ROOTFS_READ_ONLY | 21 RUN_AS_UID_GID_GROUPS |
  22 NO_NEW_PRIVILEGES | 23 MASKED_PATH | 24 READONLY_PATH |
  25 SECUREBITS | 26 LINUX_PERSONALITY

NodeAdmissionFieldV1 {
  field_key: NodeAdmissionFieldKeyV1
  canonical_value:
    BOOL { value: bool }
    | SIGNED { value: i64 }
    | UNSIGNED { value: u64 }
    | BYTES { value: bstr(0..1024) }
    | DIGEST { value: DigestV1 }
    | SORTED_VALUES {
        values[1..64]:
          BOOL { value: bool } | SIGNED { value: i64 } |
          UNSIGNED { value: u64 } | BYTES { value: bstr(0..1024) } |
          DIGEST { value: DigestV1 }
      }
  source_path_id: nonzero u32
}

NodeAdmissionRequestV1 {
  request_id, node_boot_id, authenticated_peer_id: Id128
  interface_kind: KUBERNETES_VALIDATING_ADMISSION |
                  QUALIFIED_NRI_OR_RUNTIME_ADMISSION
  interface_capability_id: Id128
  runtime_or_apiserver_version_config_digest: DigestV1
  operation: CREATE_POD | RUN_POD_SANDBOX | CREATE_CONTAINER |
             START_CONTAINER | EXEC_SYNC | STREAMING_EXEC | RESTORE
  cluster_uid?: Id128
  pod_uid?: bstr(1..64)
  namespace_uid?: Id128
  service_account_uid?: Id128
  controller_uid?: Id128
  full_container_id?: bstr(32..128)
  image_digest: DigestV1
  effective_request_digest: DigestV1
  requested_field_entries[0..512]: NodeAdmissionFieldV1,
    sorted by (field_key, canonical_value), no duplicates
  selected_profile?: PortableProfileGenerationV1
  signed_exception_instance_id?: ExceptionInstanceIdV1
  one_use_exception_claim_slot_id?: Id128
  cgroup_binding_id_and_nonce?: { binding_id, binding_nonce: Id128 }
  deadline_boottime_ns: u64
}

NodeHardFloorDecisionV1 {
  request_id: Id128
  matched_baseline_or_exception_id?: Id128
  result: ALLOW_MATCHED | REJECT_UNMATCHED | REJECT_HARD_FLOOR |
          ADMIT_UNKNOWN_RESTRICTED_AND_ALERT
  exact_rejected_field_ids[]: sorted unique NodeAdmissionFieldKeyV1
  required_profile_generation_ref_id?: u64
  decision_interface_capability_id: Id128
  decision_digest: DigestV1
}
```

Unknown fields cannot be omitted from a full-floor request. A Kubernetes
admission request never claims that runtime
setup was prevented, and a runtime request never claims Kubernetes API
rejection; the selected interface kind controls the honest physical result.

`signed_exception_instance_id` identifies the same `ExceptionV1` instance
that later BPF consumers may charge. `one_use_exception_claim_slot_id` is a
separate signed-intent replay slot: it proves one admission request but never
creates, refunds, or substitutes for `ExceptionV1.maximum_uses`. A V1
admission decision records exception context only; it may claim a use only at
the separately qualified consumer that owns the applicable exception receipt.

Admission can reject an unmatched privileged, hostPID, host-root, or broad-
capability workload. A runtime extension may claim start rejection only when
its tested ordering proves it. Otherwise BPF controls later covered effects.
A privileged CSI or node agent needs a signed, expiring exception naming its
immutable image, controller, dangerous fields, scope, approver, and maximum
instances. Kubernetes labels alone are not authentication.

Chapter 7 states the active behavior. Chapter 35.1 keeps the unallocated work,
and Appendix B.2 records the rejected held-task and stream-proxy designs.

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
  1: SigningKeyIdV1,
  2: 1,                       // Ed25519
  3: bstr(1..32768),          // exact canonical IntentPayloadV1 bytes
  4: Ed25519SignatureV1
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

IntentKindV1: u8 =
  0 UNKNOWN | 1 RUNTIME_ENTRY | 2 NATIVE_TRANSITION | 3 AUTHORITY_LEASE |
  4 ARTIFACT_HANDOFF | 5 PROVIDER_OPERATION | 6 DEPLOYMENT_ADMISSION |
  7 CI_STEP | 8 ADMINISTRATIVE_EXEC
```

`RUNTIME_ENTRY` and `CI_STEP` are reserved capability-gated variants. The
decoder rejects them unless the platform manifest names a qualified existing
issuer and exact join contract. They are not enabled for stock kubelet/CRI or
an unmodified runner merely because the enum value exists.

`ADMINISTRATIVE_EXEC` is issued only by Mithril's
`AdministrativeApprovalOwner`. It requires exactly one claim slot and the
explicit `NEXT_MATCHING_RUNTIME_EXTERNAL_ROOT` risk acceptance. It is not a
`RUNTIME_ENTRY` proof and must not populate an exact request-to-task join.

The issuer does not choose mismatch, expiry, or fail-open behavior. Those
fields are absent. Local signed policy owns the result. Within `SignedIntentV1`,
multiplicity is the explicit slot array, never a reusable count. This does not
replace the separately compiled and BPF-consumed `ExceptionV1.maximum_uses`.

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

AdministrativeExecBodyV1 = {
  0: Id128 authenticated_requester_principal_id,
  1: Id128 authenticated_approver_principal_id,
  2: Id128 cluster_uid,
  3: bstr(1..253) namespace_utf8,
  4: bstr(1..64) pod_uid,
  5: bstr(1..253) container_name_utf8,
  6: bstr(32..128) full_container_id,
  7: nonzero u64 container_generation,
  8: [bstr(0..4096); 1..256] approved_argv,
  9: u8 stream_flags,
  10: PolicyLocalIdV1 approved_role_id,
  11: PortableProfileGenerationV1,
  12: NodeIdentityV1 target_node_id,
  13: 1,                         // NEXT_MATCHING_RUNTIME_EXTERNAL_ROOT
  14: true,                      // requester accepted the documented race
  15: ResolvedAdministrativeExecutableV1
}

stream_flags bits =
  bit 0 STDIN | bit 1 STDOUT | bit 2 STDERR | bit 3 TTY
  bits 4..7 must be zero
```

For `AdministrativeExecBodyV1`, the sum of the argument byte lengths is
`1..4096`, element 0 is a nonempty command name, and embedded NUL is forbidden.
The resolved executable's `requested_name_bytes` must equal element 0. Its
object, target mount view, resolution mode, working directory, and applicable
`PATH` entries are part of the signed parent body; the child does not need a
separate digest. These are signed parser rules, not display normalization.

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

IntentBodyV1 =
  {0: 1, 1: RuntimeEntryBodyV1}
  | {0: 2, 1: NativeTransitionBodyV1}
  | {0: 3, 1: AuthorityLeaseBodyV1}
  | {0: 4, 1: ArtifactHandoffBodyV1}
  | {0: 5, 1: ProviderOperationBodyV1}
  | {0: 6, 1: DeploymentAdmissionBodyV1}
  | {0: 7, 1: CiStepIntentBodyV1}
  | {0: 8, 1: AdministrativeExecBodyV1}
```

Shape `COORDINATOR_BUILTIN_NO_LOCAL_TASK` must use the coordinator-only
binding. A local shape may use a local binding only when the qualified official
interface provides it. Missing, extra, zero-filled, or wrong-shape fields are
parser errors. Mithril's own signature over separately observed job and task
records is not an official step-to-task join.

The closed base registries are:

```text
RuntimeOperationV1: u8 = 0 UNKNOWN | 1 CONTAINER_START | 2 EXEC_SYNC |
  3 STREAMING_EXEC | 4 LIFECYCLE_EXEC | 5 EPHEMERAL_CONTAINER |
  6 CHECKPOINT_RESTORE

NativeOperationV1: u8 =
  0 UNKNOWN | 1 FORK | 2 EXEC | 3 PRIVILEGE_TRANSITION

ArtifactOperationV1: u8 = 0 UNKNOWN | 1 READ_AS_DATA | 2 VERIFY | 3 LOAD |
  4 EXECUTE | 5 DEPLOY

CiCoordinatorV1: u8 =
  0 UNKNOWN | 1 GITHUB_ACTIONS | 2 GITLAB_CI | 3 JENKINS | 4 TEKTON

CiTriggerTrustClassV1: u8 =
  0 UNKNOWN | 1 TRUSTED_REF | 2 UNTRUSTED_CHANGE | 3 SCHEDULED |
  4 MANUAL_APPROVED | 5 POLICY_GENERATED

CiExecutionShapeV1: u8 =
  0 UNKNOWN | 1 NATIVE_TRANSITION | 2 RUNTIME_JOB_CONTAINER_ROOT |
  3 RUNTIME_ACTION_CONTAINER_ROOT | 4 SERVICE_ROOT |
  5 COORDINATOR_BUILTIN_NO_LOCAL_TASK

ProviderV1: u8 = 0 UNKNOWN | 1 KUBERNETES | 2 AWS | 3 GCP |
  4 GITHUB | 5 INTERNAL_CONNECTOR | 6 OCI_REGISTRY

EntryKindV1: u8 = 0 UNKNOWN | 1 CONTAINER_START | 2 QUALIFIED_EXEC_PROBE |
  3 QUALIFIED_LIFECYCLE_POSTSTART | 4 QUALIFIED_LIFECYCLE_PRESTOP |
  5 APPROVED_ADMINISTRATIVE_EXEC_NEXT_MATCH | 6 EPHEMERAL_CONTAINER |
  7 QUALIFIED_CI_CONTAINER_ACTION | 8 CHECKPOINT_RESTORE_UNKNOWN |
  9 UNKNOWN_EXTERNAL

ArtifactKindV1: u8 = 0 UNKNOWN | 1 FILE | 2 DIRECTORY_TREE | 3 OCI_IMAGE |
  4 CI_ARTIFACT | 5 CACHE_ENTRY | 6 QUEUE_MESSAGE |
  7 DEPLOYMENT_MANIFEST

ProducerTrustClassV1: u8 =
  0 UNKNOWN | 1 UNTRUSTED_INPUT | 2 PROTECTED_BUILD |
  3 APPROVED_RELEASE | 4 EXTERNAL_UNVERIFIED

ProviderResultBoundaryV1: u8 =
  0 UNKNOWN | 1 SYNCHRONOUS_GATE_RESULT |
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
fail-open, accept a reusable count inside a signed intent instead of slots,
infer a slot from time and
argv, store provider secrets as evidence, or call provider audit a synchronous
pre-effect intent proof. It must also never treat stock kubelet/CRI, runtime,
or runner observations as signed intent merely because Mithril normalized and
signed its own copy.

### A.11 Exact Policy, Parser, Signature, And Activation Contract

Chapters 11-12 describe one policy model. This section closes the places where
two implementations might otherwise make different choices.

**Problem.** An operator writes one rule denying the conversion worker access
to a canonical path. Rust, BPF, the policy-review UI, and the qualification
runner must all agree on the same actor, path, operation, failure result, and
bytes. This path rule does not become semantic projected-token identity. YAML
order or a library's permissive defaults cannot change the decision.

#### A.11.1 Source-file rules

Production Kubernetes mode serves two structural CRDs. The base policy uses
group `mithril.erebor.dev`, plural `workloadprotectionpolicies`, kind
`WorkloadProtectionPolicy`, namespaced scope, served version `v1alpha1`, and
one declared storage version. A bounded exception uses the same group, scope,
and versions, plural `workloadprotectionexceptions`, and kind
`WorkloadProtectionException`.

The API server's stored typed `.spec`, after the declared storage-version
conversion, is the desired-state source. Each CRD schema and the Control
decoder reject unknown fields, unknown enums, lossy conversions, and input
beyond declared size, depth, and count limits. The original submitted YAML
bytes, comments, map order, Kubernetes status, managed fields, and watch order
carry no authority.

The supported Kubernetes write path requires strict API field validation. An
unknown field cannot reach stored state or a candidate. A server/client mode
that silently prunes unknown input is unsupported for the exact-source claim;
the operator must not mistake a pruned request for the policy that Control
compiled.

Offline review, import, and qualification use the exact
`WorkloadProtectionPolicy.spec` shape in UTF-8 YAML 1.2 restricted to the JSON
data model. That decoder rejects duplicate keys, anchors, aliases, merge keys,
custom tags, non-string map keys, implicit timestamps, NaN or infinity,
integers outside the declared type, unknown fields, unknown enums, and input
beyond the declared size, depth, and count limits. Durations match
`^[0-9]+(ns|us|ms|s|m|h)$`; zero is legal only where the field says so. Offline
YAML cannot activate production Kubernetes policy without creating or updating
the CRD through the authenticated API.

The public shapes are:

```text
WorkloadProtectionPolicySpecV1 {
  pod_selector: KubernetesLabelSelectorV1
  mode: OBSERVE | PROTECT
  containers[1..256]: ContainerPolicyMatchV1
  roles[1..256]: KubernetesRolePolicyV1
  exception_grants[0..256]: FileExceptionGrantV1
}

ContainerPolicyMatchV1 {
  names[1..64]: Kubernetes container names
  kinds[1..4]: INIT | SIDECAR | APPLICATION | EPHEMERAL
  images[1..256]: digest-pinned immutable image references
  initial_role, external_role: PolicyLocalIdV1
}

KubernetesRolePolicyV1 {
  name: PolicyLocalIdV1
  files[0..1024]: PathRuleV1
  execution[0..1024]: PathRuleV1
  network: NetworkRulesV1
  process_control[0..1024]: ProcessControlRuleV1
  unix_streams[0..1024]: UnixStreamRelationshipV1
}

PathRuleV1 {
  name: PolicyLocalIdV1
  path: absolute canonical path
  recursive: bool
  operations[1..16]: closed operation enum for the containing family
  action: ALLOW | DENY
}

FileOperationV1 = OPEN_READ | OPEN_WRITE | READ | WRITE | MMAP_READ |
  MMAP_WRITE | CREATE | SET_ATTRIBUTES | UNLINK | LINK | RENAME
ExecutionOperationV1 = EXECUTE | MMAP_EXECUTE | MPROTECT

NetworkRulesV1 {
  socket_controls[0..256]: SocketControlRuleV1
  destinations[0..1024]: AddressDestinationRuleV1
}

SocketControlRuleV1 {
  operations[1..5]: CREATE | LISTEN | ACCEPT | SHUTDOWN | SET_SOCKET_OPTION
  action: ALLOW | DENY
}

AddressDestinationRuleV1 {
  name: PolicyLocalIdV1
  operations[1..4]: CONNECT | SEND | RECEIVE | BIND
  protocols[1..2]: TCP | UDP
  cidrs[1..256]: canonical IPv4 or IPv6 prefixes
  ports[1..256]: { first:u16, last:u16 }
  action: ALLOW | DENY
}

ProcessControlRuleV1 =
  SIGNAL {
    name: PolicyLocalIdV1
    target_role: PolicyLocalIdV1
    signals[1..64]: sorted unique u32
    action: ALLOW | DENY
  }
  | PTRACE {
      name: PolicyLocalIdV1
      target_role: PolicyLocalIdV1
      requests[1..64]: sorted unique u32
      action: exactly DENY
    }

UnixStreamRelationshipV1 {
  name: PolicyLocalIdV1
  peer_roles[1..256]: sorted unique PolicyLocalIdV1
  action: ALLOW | DENY
}

FileExceptionGrantV1 {
  name: PolicyLocalIdV1
  file_rules[1..256]: PolicyLocalIdV1
  maximum_duration: bounded nonzero duration
  maximum_uses: 1..65535
}

FileExceptionGrantTemplateV1 {
  grant_id: PolicyLocalIdV1
  denied_file_rule_ids[1..256]: sorted unique PolicyLocalIdV1
  maximum_duration_ns: nonzero u64
  maximum_uses: 1..65535
}

WorkloadProtectionExceptionSpecV1 {
  policy_ref: { name: Kubernetes object name }
  grant: PolicyLocalIdV1
  target {
    pod { name: Kubernetes Pod name, uid: Kubernetes UID }
    container_name: Kubernetes container name
  }
  requested_duration: bounded nonzero duration
  requested_uses: 1..65535
}

WorkloadProtectionPolicyStatusV1 {
  observed_generation: nonnegative i64
  rollout { desired:u32, active:u32, updating:u32, failed:u32 }
  conditions[0..8]: Kubernetes Condition
}

WorkloadProtectionExceptionStatusV1 {
  observed_generation: nonnegative i64
  state: PENDING | ACTIVE | CONSUMED | EXPIRED | REVOKED | FAILED
  conditions[0..8]: Kubernetes Condition
}
```

All names that form internal IDs are unique in their containing policy. Rule
operations are closed to the applicable sets in Chapter 11. The schema rejects
recursive allow until its Kubernetes runtime control is physically qualified.
It also rejects overlapping rules with different actions, more than one
container match, more than one policy match, a missing reference, an exception
outside its base grant, and every deliberately absent field listed in Chapter
11.

The public policy and the offline source lower through the same Control
function. A golden compares the derived internal `PolicyDocumentV1` bytes for
the same public spec. The public source never accepts `PolicyDocumentV1`
directly. Each public `exceptionGrants` entry becomes one closed
`FileExceptionGrantTemplateV1` in the internal policy. The internal static
`exceptions` list remains empty for this Kubernetes source; exact runtime
instances come only from `WorkloadProtectionException`. Version 1 has no
generic extension or metadata bag.

Control records every accepted source before it can create a candidate:

```text
KubernetesDesiredSourceRevisionV1 {
  schema_version: exactly 1
  source_kind: POLICY | EXCEPTION
  tenant_id, cluster_uid, namespace_uid, object_uid: Id128
  namespace_name, object_name: Kubernetes names
  api_version: exactly "mithril.erebor.dev/v1alpha1"
  object_generation: nonzero u64
  opaque_resource_version: bstr(1..1024)
  canonical_spec_digest: DigestV1
  policy_document_digest?: DigestV1, present only for POLICY
  state: ACCEPTED | DELETION_REQUESTED
  source_revision_id: DigestV1
}

PolicyExceptionCandidateV1 {
  schema_version: exactly 1
  exception_source_revision_id, policy_source_revision_id: DigestV1
  signed_profile_digest: DigestV1
  profile_generation_ref_id: nonzero u64
  grant_name: PolicyLocalIdV1
  compiled_cell_digests[1..256]: sorted unique DigestV1
  exception_instance_id: ExceptionInstanceIdV1
  tenant_id, cluster_uid, namespace_uid, pod_uid: Id128
  container_name: Kubernetes container name
  node_identity: NodeIdentityV1
  node_boot_id: Id128
  label_epoch: nonzero u64
  maximum_uses: 1..65535
  deadline_utc_ns: i64
  operation: ACTIVATE | REVOKE
  predecessor_candidate_content_id?: ArtifactContentIdV1
  distribution_sequence_epoch, distribution_sequence: nonzero u64
  candidate_content_id: ArtifactContentIdV1
  seal: SignedArtifactSealV1
}

PolicyExceptionAcknowledgementV1 {
  candidate_content_id: ArtifactContentIdV1
  exception_instance_id: ExceptionInstanceIdV1
  node_identity: NodeIdentityV1
  node_boot_id: Id128
  state: ACTIVE | REVOKED | CONSUMED | EXPIRED | REJECTED | STALE
  consumed_uses: u32
  latest_receipt_id?: ArtifactContentIdV1
  observed_utc_ns: i64
}
```

Control derives internal policy metadata, protected-universe IDs, workload and
entry IDs, capability and proof requirements, conservative failure posture,
fixed operation results, object registries, rollout fields, and signature
metadata. It assigns a monotonic internal policy version whenever the
base-policy source revision changes. It lowers native transitions, state bits,
authority behavior, correlation, findings, notifications, responses, and
coverage rules to the fixed empty or conservative values required by this
Kubernetes API.
Later phases cannot expose one of those fields without a new qualified public
contract.

`opaque_resource_version` supports watch resumption only. Control uses object
UID, generation, and canonical spec digest for source identity. It uses the
base-policy source revision, internal policy version, and issuer sequence for
policy anti-rollback. Exception candidates use their own source identity,
target-bound distribution sequence, predecessor, and non-refunding instance
state. A served-to-storage conversion must preserve the public semantic spec or
reject.

Control derives tenant, cluster, namespace UID, and object UID from its
authenticated cluster configuration and API-server records. A CRD field,
label, annotation, or status cannot select its own tenant. Control watches the
namespaced resources cluster-wide. The resource namespace scopes the policy;
there is no second configured protected-namespace selector. Cross-tenant
references reject before candidate creation.

List/watch delivery is at-least-once and may close, repeat, or compact. Control
persists accepted policy and exception source revisions, relists after
compaction, and produces the same base-policy and exception desired state after
restart. A watch event by itself cannot sign, target, distribute, retire, or
activate policy or exception authority.

#### A.11.2 Selectors classify candidates; bindings create authority

The types below are internal compiler and signed-artifact types. Their wider
fields do not appear in either Kubernetes CRD. The public lowering function
constructs only the capability-grounded subset described in A.11.1.

```text
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

ObjectClassifierSelectorV1 =
  PROJECTED_SERVICE_ACCOUNT_TOKEN {
    workload_selector_ids[1..32]: PolicyLocalIdV1
    service_account_uids[1..64]: Id128
    required_projected_source: KUBERNETES_SERVICEACCOUNT_TOKEN
    required_mount_read_only: bool
  }
  | FILESYSTEM_OBJECT {
      workload_selector_ids[1..32]: PolicyLocalIdV1
      mount_source_class_ids[1..64]: PolicyLocalIdV1
      relative_component_bytes[0..64]: bstr(1..255)
      filesystem_type_ids[0..64]: PolicyLocalIdV1
      required_object_type: REGULAR_FILE | DIRECTORY
    }
  | IMMUTABLE_ARTIFACT { artifact_digests[1..256]: DigestV1 }
  | DESTINATION { destination_policy_ids[1..256]: PolicyLocalIdV1 }
  | DEVICE { device_class_ids[1..256]: PolicyLocalIdV1 }
  | KERNEL_SECURITY_OBJECT { security_object_ids[1..256]: PolicyLocalIdV1 }

ObjectClassifierBindingV1 {
  classifier_binding_id: PolicyLocalIdV1
  object_class_id: ObjectClassIdV1
  selector: ObjectClassifierSelectorV1
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
  canonical_payload_digest: ArtifactContentIdV1
  seal: SignedArtifactSealV1
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
  canonical_payload_digest: ArtifactContentIdV1
}
```

Overlapping registry entries that assign different classes, a missing required
axis, stale endpoint generation, unknown filesystem/device/security type, or a
registry digest mismatch keeps the binding `PREPARING` and prevents activation.

#### A.11.3 Roles, entries, transitions, and effects

```text
StateBitDefinitionV1 {
  scope: PROCESS | NATIVE_AUTHORITY_DOMAIN
  bit_index: u8 in 0..63
  semantic_id: PolicyLocalIdV1
  monotonic: exactly true
}

ProcessStateBitV1 = u8 in 0..63 referring to exactly one
  StateBitDefinitionV1(scope=PROCESS)

DomainSensitiveBitV1 = u8 in 0..63 referring to exactly one
  StateBitDefinitionV1(scope=NATIVE_AUTHORITY_DOMAIN)

ProcessStateDefinitionV1 {
  process_state_id:PolicyLocalIdV1
  state_bits[0..64]:sorted unique closed ProcessStateBitV1
}

NativeAuthorityStateRuleV1 {
  state_rule_id:PolicyLocalIdV1
  triggering_object_class_ids[1..256]:ObjectClassIdV1
  triggering_operations[1..64]:RegistrySymbolV1
  set_sensitive_bits[1..64]:closed DomainSensitiveBitV1
  resulting_restriction_semantic_ids[1..64]:PolicyLocalIdV1
  monotonic:exactly true
}

PathSelectorV1 {
  schema_version: exactly 1
  path_selector_id: PolicyLocalIdV1
  selector_kind: PATH | EXACT
  PATH => path_pattern: absolute bounded live path expression with
    literal, `*`, or `**` components
  EXACT => canonical_path: absolute bounded path with literal components only
  object_class_id: ObjectClassIdV1
  device_class_id?: RegistrySymbolV1
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
  accepted_classifications[1..4]: EXACT_INITIAL |
    CONSERVATIVE_EXTERNAL_UNKNOWN | QUALIFIED_JOINED_PURPOSE |
    APPROVED_ADMINISTRATIVE_NEXT_MATCH
  required_purpose_source_capability_id?: Id128
  required_administrative_exec_approval: bool
  resulting_role_id: PolicyLocalIdV1
  on_missing_or_unequal_ambiguity: RESTRICT_EXTERNAL |
    DENY_PROTECTED_EFFECTS | REJECT_WHEN_STOCK_INTERFACE_SUPPORTS
  unknown_restricted_role_id?: PolicyLocalIdV1
}

NativeRoleTransitionRuleV1 {
  transition_rule_id: PolicyLocalIdV1
  source_role_ids[1..32]
  operation: FORK | THREAD_CREATE | EXEC | PRIVILEGE_TRANSITION
  executable_path_selector_ids[0..256]: PolicyLocalIdV1
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

Duplicate `(scope, bit_index)`, duplicate `(scope, semantic_id)`, an undefined
bit reference, or a non-monotonic definition rejects the policy. Rust and BPF
store only the fixed bit index; explanations recover the digest-bound semantic
ID from the signed profile.

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
  canonical_payload_digest: ArtifactContentIdV1
  seal: SignedArtifactSealV1
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
  root_classifications[1..5]: EXACT_INITIAL |
    CONSERVATIVE_EXTERNAL_UNKNOWN | QUALIFIED_JOINED_PURPOSE |
    APPROVED_ADMINISTRATIVE_NEXT_MATCH | UNRESOLVED_PROTECTED
  source_proof_qualities[0..8]: ProofQualityV1
  required_purpose_source_capability_ids[0..8]: Id128
  immutable_definition_digests[0..64]: DigestV1
}

NativeTransitionMatchV1 {
  kind: exactly NATIVE_TRANSITION
  subject: CommonSubjectMatchV1
  operations[1..4]: FORK | THREAD_CREATE | EXEC | PRIVILEGE_TRANSITION
  executable_path_selector_ids[0..256]: PolicyLocalIdV1
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
  PATH_SELECTORS { path_selector_ids[1..256]: PolicyLocalIdV1 }
  | OBJECT_CLASSES { object_class_ids[1..256]: ObjectClassIdV1 }
  | DESTINATIONS { destination_policy_ids[1..64]: PolicyLocalIdV1 }
  | DEVICES { device_class_ids[1..64]: PolicyLocalIdV1,
              ioctl_command_ids[0..256]: u32 }
  | SECURITY_OBJECTS { security_object_ids[1..64]: PolicyLocalIdV1,
                       target_selector_ids[0..64]: PolicyLocalIdV1 }

A `PATH_SELECTORS` rule signs the selector ID, tagged selector target, object
class, operations, and disposition. `PATH` matches the live canonical path.
`x/y`, `x/*/y`, and `x/**/y` mean literal, one-component wildcard, and
recursive live path matching. `PATH` does not require userspace inode
resolution. `EXACT x/y` is usable only after the node resolves it through an
authenticated `Running` CRI root and reads back the measured exact-object,
mount-view, and topology rows. The node derives the kernel handle from the
signed selector ID. Node configuration cannot supply this handle or an
exact-object authority row.

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

The compiler expands every wildcard except a hierarchical path component
against the finite signed universe. A hierarchical path component is compiled
into the bounded actor-view resolver in Chapter 15; its one terminal candidate
is revalidated to an exact mount/object decision key before physical authority
is selected. An omitted optional selector dimension means the whole finite
dimension. A present empty required selector is an error; it never means `*`.

```text
NormalizedDecisionCellV1 {
  cell_id: PolicyLocalIdV1
  exact_compiled_key
  physical_result
  complete_transition_descriptor?
  finding_specs[]
  response_binding_ids[]
  budget_semantics
  consuming_exception_id?: PolicyLocalIdV1
  source_rule_ids[]
}

CompiledActionPlanV1 {
  evaluation_stage: ENTRY_ADMISSION | NATIVE_TRANSITION |
                    LOCAL_PRE_EFFECT | REMOTE_PRE_ADMISSION | POST_EFFECT
  physical_result: ADMIT | AUDIT_ADMIT | REJECT_REQUEST |
                   ALLOW_EFFECT | AUDIT_ALLOW_EFFECT | DENY_ERRNO |
                   RECORD_COMPLETION | NOT_APPLICABLE
  errno?: EACCES | EPERM | EAGAIN | ECONNREFUSED
  post_effect_actions[1..3]: sorted unique
    RECORD | FINDING | RESPONSE_PROPOSAL
  expected_observed_result:
    ADMISSION_NOT_ATTEMPTED | ADMITTED | REJECTED_BY_MITHRIL |
    EFFECT_NOT_ATTEMPTED | ALLOWED_BY_MITHRIL | DENIED_BY_MITHRIL |
    PROVIDER_SUCCEEDED | PROVIDER_DENIED_BY_AUTHORITY |
    PROVIDER_FAILED | PROVIDER_RESULT_UNKNOWN
  finding_specs[0..16]: FindingSpecV1
  evidence_field_allowlist[0..64]: EvidenceFieldKeyV1
  notification_route_ids[0..64]: sorted unique PolicyLocalIdV1
  response_binding_ids[0..64]: sorted unique PolicyLocalIdV1
  required_proof: ProofQualityPredicateV1
  fallback_plan_by_failure_condition[0..16]: FallbackV1,
    sorted unique by condition
  consuming_exception_id?: PolicyLocalIdV1
  source_rule_ids[1..64]: sorted unique PolicyLocalIdV1
}
```

`errno` is present exactly for `DENY_ERRNO`. `consuming_exception_id` is
present exactly when this plan obtains authority from one `ExceptionV1` and
must consume that exception before returning the broadened result. `FINDING`
requires a nonempty
finding set; otherwise the finding set is empty. A notification or response
requires a finding. The compiled plan is a child of the immutable signed
profile generation, so it has no redundant child digest. An independently
exported explanation references the parent profile and cell ID instead.

Two cells merge only when the physical result, errno, complete transition,
findings, responses, and budget semantics are identical. Different results
need an explicit signed override or exception naming the exact replaced rule
and authority delta. The path-graph compiler applies the same condition to
overlapping terminal patterns before an object decision is emitted. Otherwise
compilation fails. Priority, YAML order, wildcard count, severity, “more
specific,” and “deny wins” never select authority.

Each operation becomes its own compiled key. `OPEN_READ` and later `READ` are
not one bit of authority. A file-open capability cannot satisfy a claim that
passed or inherited descriptors are controlled at use time.

##### A.11.5.1 Exceptions, notifications, responses, coverage, and rollout

An exception is a signed bounded authority change, not a free-form annotation:

```text
ExceptionV1 {
  exception_id: PolicyLocalIdV1
  exception_instance_id: ExceptionInstanceIdV1
  changed_rule_ids[1..64]: PolicyLocalIdV1
  exact_subject: ExactExceptionSubjectSelectorV1
  authority_delta: PermittedAuthorityDeltaV1
  approver_principal_id: Id128
  approval_proof_digest: DigestV1
  closed_reason_code: ReasonCodeIdV1
  valid_from_utc_ns, valid_until_utc_ns: i64
  consumption_scope: exactly PER_TARGET_NODE
  maximum_uses: ExceptionUseCountV1
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
  from_physical_result, to_physical_result: ResultCodeIdV1
  added_or_removed_operation_cells[0..256]: DigestV1
  added_or_removed_transition_cells[0..256]: DigestV1
  maximum_blast_radius: BlastRadiusLimitV1
}

ExceptionRuntimeStateKeyV1 {
  node_id: NodeIdentityV1
  exception_instance_id: ExceptionInstanceIdV1
}

ExceptionHandleBindingKeyV1 {
  profile_generation_ref_id: nonzero u64
  exception_numeric_handle: ExceptionNumericHandleV1
}

ExceptionHandleBindingV1 {
  runtime_state_key: ExceptionRuntimeStateKeyV1
  state: ExceptionBindingStateV1
}

ExceptionRuntimeStateV1 {
  exception_lock: bpf_spin_lock
  exception_id_for_readback: PolicyLocalIdV1
  exception_definition_digest: DigestV1
  maximum_uses: ExceptionUseCountV1
  consumed_uses: u32, 0..maximum_uses
  bound_profile_generation_refs: u32
  deadline_boottime_ns: u64
  transition_version: nonzero u64
  state: ExceptionStateV1
}

ExceptionUseReceiptKeyV1 {
  runtime_state_key: ExceptionRuntimeStateKeyV1
  use_identity: ExceptionUseIdentityV1
}

ExceptionUseReceiptV1 {
  consumed_ordinal?: ExceptionUseCountV1
  claimed_boottime_ns: u64
  transition_version: nonzero u64
  state: ExceptionReceiptStateV1
}
```

Wildcards, no expiry, missing approver, unlimited use, and hard-invariant
changes reject. The compiler shows the exact broadened/narrowed cells in the
activation explanation and claim exclusions.

One pinned `ExceptionRuntimeStateV1` entry owns the count for one
`exception_instance_id` on one target node. `maximum_uses` is therefore
per-target-node, as the signed `consumption_scope` states; Version 1 makes no
cluster-global count claim from node-local BPF state. Rule, transition, and
program maps carry only a generation-local numeric handle; they never keep
independent counters.

The state key uses the stable `NodeIdentityV1`, while `node_boot_id` remains a
separate reboot epoch. An administrative approval's `target_node_id` must
equal that stable identity before lowering; reboot restores the same node's
WAL-backed count and receipts rather than creating a new per-node budget.

Node lowering installs one `ExceptionHandleBindingV1` from that handle to the
stable runtime-state key. Carrying the same exception instance into a later
profile generation requires the same canonical exception-definition digest,
increments `bound_profile_generation_refs`, and preserves `consumed_uses`.
Changing any definition field under the same instance ID rejects. A later
exception may reuse the human `exception_id` only with a new non-reused
`exception_instance_id` and new approval. Before first activation on a node,
the owner either restores the instance's count and receipts from the WAL or
initializes and reads back `maximum_uses`, `consumed_uses=0`, and the monotonic
deadline.

Node lowering resolves `CompiledActionPlanV1.consuming_exception_id` through
`GenerationLocalPolicyIdMapV1` and writes that one handle into the applicable
`PhysicalDecisionV1`, `TransitionDescriptorV1`, or approved-exec slot.

Every possible consumer derives the same exact `ExceptionUseIdentityV1`.
Claim-backed administrative execution uses its existing `claim_slot_id`; a
kernel effect uses the `ExactRequestIdentityV1` already shared by every hook
for that attempt. The decisive BPF owner inserts one `CLAIMING` receipt with
`BPF_NOEXIST`. An existing `CONSUMED` receipt means another rule or program
already charged this same logical use, so the count is not charged again. An
existing `CLAIMING` or reconciliation receipt fails closed.

A receipt is idempotency state, not positive authority. Every participating
program still revalidates the same live actor, generation, compiled cell,
object, and floors. `consumed_ordinal` is present exactly for `CONSUMED`, equals
the post-increment `consumed_uses`, and is absent for every denial state.

The winning owner locks the one runtime-state value, rechecks the active handle
binding, deadline, and state, and increments `consumed_uses` only when it is below
`maximum_uses`. Reaching the maximum changes the state to `EXHAUSTED`. It then
marks the receipt `CONSUMED` before returning the exception-broadened result.
The count is consumed immediately before that result is returned, after all
other Mithril restriction and response floors have passed. A later kernel LSM
denial or failed physical operation does not refund it because safe rollback
cannot prove that no effect occurred.

For an approved administrative exec, only the winner of the existing
`ExecutionApprovalSlotV1` `ARMED -> RESERVED` transition may claim the exception
receipt. If the exception is then expired or exhausted, the exec remains
denied and the execution approval slot remains spent. Any map-capacity,
lookup, lock, receipt-finalization, or readback failure denies and sets
reconciliation-required state; it never grants an extra use. Pinned state and
receipts are authoritative across daemon restart. The WAL restores them before
activation after node restart. The owner retains them until the exception has
expired, every bound profile-generation reference is released, and receipt
retention/reconciliation is complete.

```text
NotificationRouteV1 {
  route_id: PolicyLocalIdV1
  sink: PAGER | CHAT | EMAIL | SIEM | WEBHOOK | TICKET
  sink_binding_id: PolicyLocalIdV1
  minimum_severity: INFO | LOW | MEDIUM | HIGH | CRITICAL
  grouping_fields[1..16]: FindingGroupingFieldV1
  dedupe_window: duration
  allowed_evidence_fields[1..64]: EvidenceFieldKeyV1
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
  canonical_payload_digest: ArtifactContentIdV1
  seal: SignedArtifactSealV1
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

enum ResponseActionSpecV1 {
  RestrictLineage,
  FenceSockets,
  FreezeCgroup,
  // Sends SIGKILL only after pidfd/task-cookie/start-time/cgroup revalidation.
  TerminateProcessPidfd,
  RejectKubernetesReplacement { admission_capability_id: PolicyLocalIdV1 },
  RevokeCredential {
    provider: ProviderV1,
    credential_kind: RegistrySymbolV1,
    actuator_capability_id: PolicyLocalIdV1,
    typed_request_schema_digest: DigestV1,
  },
  DisableMeshDevice {
    provider: ProviderV1,
    actuator_capability_id: PolicyLocalIdV1,
    typed_request_schema_digest: DigestV1,
  },
  QuarantineArtifact {
    store_capability_id: PolicyLocalIdV1,
    typed_request_schema_digest: DigestV1,
  },
  SuspendInstallation {
    provider: ProviderV1,
    actuator_capability_id: PolicyLocalIdV1,
    typed_request_schema_digest: DigestV1,
  },
  ProviderSpecific {
    provider: ProviderV1,
    canonical_action_id: PolicyLocalIdV1,
    actuator_capability_id: PolicyLocalIdV1,
    typed_request_schema_digest: DigestV1,
  },
}

struct ResponseActionRequestV1 {
  action_id: Id128,
  action: ResponseActionSpecV1,
  idempotency_key: Id128,
}

enum ResponseActionResultV1 {
  Verified { action_id: Id128, postcondition: PhysicalPostconditionV1 },
  AlreadySatisfied { action_id: Id128, postcondition: PhysicalPostconditionV1 },
  TargetNoLongerMatches { action_id: Id128 },
  ActuatorRejected { action_id: Id128, reason_code: ReasonCodeIdV1 },
  Failed { action_id: Id128, reason_code: ReasonCodeIdV1 },
  Expired { action_id: Id128 },
  Cancelled { action_id: Id128 },
}
```

The compiler uses a closed compatibility table between action, target
revalidation, postcondition, proof, and blast-radius variant. A GitHub audit
fingerprint cannot select a possessed-token revoke action; a process target
cannot use a Kubernetes-object postcondition. `TerminateProcessPidfd` is
compatible only with `PROCESS_PIDFD_TASK_COOKIE_STARTTIME_CGROUP_BINDING` and
`PROCESS_STOPPED_VIA_PIDFD`. The response owner sends `SIGKILL` through the
revalidated pidfd, then verifies the original process exit with `waitid` on
that pidfd. A target mismatch never signals; an `ESRCH` result succeeds only
when that same pidfd proves the target already exited.

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
  17: DigestV1 provider_vocabulary_registry_digest,
  18?: DigestV1 policy_source_revision_id
}

SignedWorkloadProtectionProfileV1 = {
  0: 1,
  1: SigningKeyIdV1,
  2: 1,                       // Ed25519
  3: bstr(1..4096) canonical header,
  4: bstr(1..1048576) canonical PolicyDocumentV1,
  5: Ed25519SignatureV1
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

SignedRollbackAuthorizationV1 = {
  0: 1,
  1: SigningKeyIdV1,
  2: 1,                       // Ed25519
  3: bstr(1..16384) canonical RollbackAuthorizationPayloadV1,
  4: Ed25519SignatureV1
}

rollback_signature_input =
  ASCII("MITHRIL-ROLLBACK-V1") || 0x00 ||
  SHA-256(canonical_rollback_payload)

RollbackAuthorizationV1 = verified SignedRollbackAuthorizationV1 where
  signature, issuer scope, exact current/target profile, platform, approver,
  time, sequence, and one-use replay state all pass and remain unconsumed.
```

Rollback uses this separate Ed25519 envelope and domain separator. It is
one-use and must name the exact current digest,
exact older target, platform, approver, and expiry. Re-signing an older version
is not rollback authority.

The activation owner durably records the greatest accepted issuer sequence and
profile version before publishing a generation. Lower signed values reject
unless the exact rollback authorization is valid and unused.

`policy_source_revision_id` is required for a profile produced from a
production Kubernetes base policy and absent for an offline qualification
profile. It binds the signed semantic policy to one accepted base-policy
revision without making Kubernetes metadata or status part of the policy
document.

`PolicyExceptionCandidateV1` uses domain separator
`MITHRIL-POLICY-EXCEPTION-CANDIDATE-V1`. Its signature binds the exception
source, active base-policy generation, grant, exact workload and node target,
deadline, use limit, operation, predecessor, and distribution sequence. It is
not a profile signature and cannot change policy cells.

#### A.11.7 Build, read back, probe, activate, and retire

```text
accept and persist the base-policy source revision,
  or load the offline base-policy review source
validate the closed public policy source and references
lower the public base policy and inactive exception grants into the internal policy
validate the internal policy, registries, and capabilities
resolve selectors into immutable workload/object snapshots
validate the role/transition graph and required capabilities
expand every exact decision cell and reject conflicts/capacity overflow
simulate against a recorded legitimate-workload baseline
obtain human approval
assign issuer sequence and sign the immutable profile and target candidate
deliver through the authenticated node channel
verify signature, target, validity, replay, and anti-rollback on the node
build a completely inactive generation
read back every descriptor, row, default, membership, and digest
run isolated allow and deny probes
publish one active-generation handle for the live binding
BPF migrates each running process at its next protected effect
return an authenticated activation acknowledgement to Control
```

An exception follows the separate path in Chapter 12. It resolves an inactive
grant in an already active generation and changes only
`ExceptionAuthorityOwner` runtime state. It does not build or publish another
base-policy generation.

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
  policy_id_map:GenerationLocalPolicyIdMapV1
  exact_protected_scope_ids[], exact_execution_set_ids[]:Id128
  exact_rollout_membership[]
  exact_compiled_kernel_cell_digests[]:DigestV1
  node_binding_digest:DigestV1
  state:PREPARING | READ_BACK | ACTIVE | REJECTED
}

GenerationLocalRoleHandleV1 {
  role_id: PolicyLocalIdV1
  numeric_handle: nonzero u32
}

GenerationProcessMigrationV1 {
  source_profile_generation_ref_id: nonzero u64
  target_profile_generation_ref_id: nonzero u64
  source_role_numeric_handle: nonzero u32
  source_process_state_numeric_handle: nonzero u32
  target_role_numeric_handle: nonzero u32
  target_process_state_numeric_handle: nonzero u32
}

GenerationLocalDestinationPolicyHandleV1 {
  destination_policy_id: PolicyLocalIdV1
  numeric_handle: nonzero u64
}

GenerationLocalExceptionHandleV1 {
  exception_id: PolicyLocalIdV1
  exception_instance_id: ExceptionInstanceIdV1
  numeric_handle: ExceptionNumericHandleV1
}

GenerationLocalPolicyIdMapV1 {
  profile_id: Id128
  profile_version: nonzero u64
  node_boot_id: Id128
  label_epoch: u64
  profile_generation_ref_id: nonzero u64
  role_handles[1..4096]: GenerationLocalRoleHandleV1,
    sorted unique by role_id and independently unique by numeric_handle
  destination_policy_handles[0..4096]:
    GenerationLocalDestinationPolicyHandleV1,
    sorted unique by destination_policy_id and independently unique by
    numeric_handle
  exception_handles[0..4096]: GenerationLocalExceptionHandleV1,
    sorted unique by exception_id and independently unique by numeric_handle
  state: PREPARING | READ_BACK | ACTIVE | TOMBSTONED
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

`PolicyLocalIdV1` names are reusable across profile generations. Lowering does
not assign a permanent global number. It assigns node-local handles inside one
immutable `GenerationLocalPolicyIdMapV1`; BPF role and destination-policy keys
and exception-use keys are interpreted only together with that map's
`profile_generation_ref_id`.
The same name may have different meaning in a later generation, but an active
generation never changes its mapping. Numeric handles remain non-reused within
the node boot and label epoch as required by Appendix A.12.1.
Activation reads back the complete tables before publishing the generation.
Evidence converts a handle back to the local name and portable profile
generation; a bare name or bare numeric handle is never durable identity.

Node compiles a migration row only when the source role and process state have
an exact semantic target in the new generation. BPF uses that row to migrate a
running process under its transition guard at the next protected effect. A
missing row denies the effect and leaves the process on its complete old
generation. Existing tasks keep their birth-generation references. Existing
sockets, files, mappings, domains, pending entries, and responses retain their
typed lifetime references. A retiring generation is deleted only after every
typed reference is zero, iterator/WAL reconciliation agrees, and the BPF grace
period passes.

Control freezes selection and delivery in these records:

```text
PolicyTargetV1 {
  tenant_id, cluster_uid: Id128
  node_identity: NodeIdentityV1
  workload_binding_generation_digests[0..4096]: DigestV1,
    sorted unique
}

PolicyTargetSnapshotV1 {
  policy_source_revision_id: DigestV1
  signed_profile_digest: DigestV1
  rollout_generation: nonzero u64
  targets[1..65536]: PolicyTargetV1, sorted unique,
    with at most 65536 aggregate workload-binding digests
  target_snapshot_digest: ArtifactContentIdV1
}

PolicyDeliveryCandidateV1 {
  schema_version: exactly 1
  tenant_id: Id128
  policy_source_revision_id: DigestV1
  signed_profile_digest: DigestV1
  target_snapshot_digest: DigestV1
  exact_target: PolicyTargetV1
  operation: ACTIVATE | REPLACE
  predecessor_candidate_content_id?: ArtifactContentIdV1
  distribution_sequence_epoch, distribution_sequence: nonzero u64
  issued_utc_ns, expires_utc_ns: i64
  candidate_content_id: ArtifactContentIdV1
  seal: SignedArtifactSealV1
}

PolicyActivationAcknowledgementV1 {
  acknowledgement_content_id: ArtifactContentIdV1
  tenant_id: Id128
  node_identity: NodeIdentityV1
  node_boot_id: Id128
  label_epoch: nonzero u64
  candidate_content_id: ArtifactContentIdV1
  policy_source_revision_id, target_snapshot_digest: DigestV1
  state: RECEIVED | STAGED | ACTIVE | REJECTED | STALE | UNKNOWN
  node_bound_generation_digest?: DigestV1
  profile_generation_ref_id?: nonzero u64
  readback_digest?: DigestV1
  probe_result_digest?: DigestV1
  reason_code?: ReasonCodeIdV1
  observed_utc_ns: i64
  authenticated_channel_receipt_digest: DigestV1
}

PolicyRolloutStateV1 {
  policy_source_revision_id, target_snapshot_digest: DigestV1
  target: PolicyTargetV1
  desired_candidate_content_id: ArtifactContentIdV1
  state: PENDING | DELIVERED | STAGED | ACTIVE | REJECTED | STALE | UNKNOWN
  latest_acknowledgement_content_id?: ArtifactContentIdV1
  transition_version: u64
  updated_utc_ns: i64
}
```

The candidate signature binds the exact target and operation. A node rejects
a candidate for another node, tenant, policy source revision, target snapshot,
or distribution sequence. The signed profile keeps its separate policy-issuer
sequence and rollback rules. The candidate sequence is keyed by distribution
signer and exact target and prevents an older target assignment from becoming
current. Idempotent redelivery requires the same candidate content ID. Control
accepts an acknowledgement only from the candidate's authenticated node
identity and current boot, label epoch, target snapshot, and candidate. The
channel receipt is a durable Control record of the mTLS peer and canonical
acknowledgement bytes; it is not a node policy signature.
`PolicyDeliveryCandidateV1` uses domain separator
`MITHRIL-POLICY-CANDIDATE-V1`; its content ID covers the deterministic
canonical unsigned record, and its seal stays outside that unsigned record.
An `ACTIVE` acknowledgement requires the node-bound generation,
profile-generation reference, complete readback, and passing probe digests. A
`REJECTED` acknowledgement requires a closed reason and cannot carry an active
claim. Other state-specific optional fields reject if they contradict the
named transition.
Delivery includes the referenced signed profile, registries, and static
compilation artifacts. Bounded content-addressed chunks may carry the bundle.
The node stages nothing until every referenced artifact is durable, complete,
and digest-verified. A reference to an artifact already on the node is valid
only after exact durable readback of that digest.

Selection is immutable per snapshot. A changed Pod, workload binding, or node
inventory creates a new target snapshot and rollout
transition. Control does not edit an old snapshot to make rollout health look
complete. Policy status projects `observedGeneration`, standard conditions,
and bounded `desired`, `active`, `updating`, and `failed` counts. Exception
status projects `observedGeneration`, standard conditions, and one bounded
state. Source and candidate digests, signatures, receipts, counters, and
per-target inventory stay in the Control store. Status cannot authorize any
transition.

Base-policy deletion creates `DELETION_REQUESTED` source state and removes its
bundles from complete desired node inventory. It creates no policy candidate.
Exception deletion, expiry, exhaustion, or revocation creates a signed
`REVOKE` operation for the exact exception instance and keeps the consumption
record. A node never removes a generation merely because a CRD, namespace, or
finalizer disappeared. It waits for runtime inventory to prove that the
matching container lifetime is absent. If Control is unavailable, the last
valid base generation remains available according to its signed validity and
local failure posture.

#### A.11.8 Required goldens and stable failures

`CFG-V1-GOLDEN-002` must be generated from one complete checked-in source after
the final schema exists. It includes restricted YAML, deterministic policy
CBOR, every registry payload/digest, header, signature, envelope, compiler
cells, and round trip. Prose substitutions and the retained stale
`CFG-V1-GOLDEN-001` bytes are not conformance data.

The Phase 6.2 source golden adds the stored policy spec, policy and exception
source revisions, policy target snapshot and delivery candidate, exception
activation and revocation candidates, and both acknowledgement families. It
proves that the stored policy
spec and offline policy form produce the same internal `PolicyDocumentV1`
bytes. It also covers every absent public field, unknown fields, lossy version
conversion, invalid references, bounded exception consumption, duplicate watch
delivery, stale UID or generation, overlapping workload selection, watch
compaction and relist, delete and recreate, wrong target, stale boot, partial
rollout, and status mutation. These are phase-owned tests; they do not add an
Appendix C fixture ID.

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
exist before the finding, claim rollback from a signature alone, let a node
watch policy CRDs, use CRD status as authority, or erase a local generation
because a Kubernetes object disappeared.

### A.12 Exact Kernel Decision ABI And Lookup

Chapter 13 explains the one local decision. This section fixes the map keys,
value meanings, lookup order, and failure behavior.

**Example.** Python opens the projected token. The role's base table denies it.
Even if the base table allowed it, a native-family restriction, active
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

SetKindV1: u8 =
  0 UNKNOWN | 1 RESTRICTION | 2 RESPONSE | 3 RETAINED_GENERATION

SetReferenceClassV1: u8 =
  0 UNKNOWN | 1 TASK | 2 PROCESS | 3 NATIVE_AUTHORITY_DOMAIN | 4 SOCKET |
  5 FILE_OR_SHARED_OBJECT | 6 PENDING_CLAIM | 7 RESPONSE_PLAN |
  8 RECONCILIATION | 9 WAL_RETENTION

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

SetReferenceTombstoneV1 {
  reference_owner_id: Id128
  reference_owner_generation: nonzero u64
  set_ref_id: nonzero u64
  reference_class: SetReferenceClassV1
  owned: bool
  acquisition_transition_version: nonzero u64
  release_transition_version?: nonzero u64
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
    vma_and_async_object_refs, checkpoint_restore_refs: u64
    pending_entry_and_exec_refs, response_plan_refs: u64
    state: ACTIVE | RETIRING
  }
}

GenerationReferenceClassV1: u8 =
  0 UNKNOWN | 1 TASK | 2 SOCKET | 3 FILE_OR_SHARED_OBJECT |
  4 AUTHORITY_DOMAIN | 5 DERIVED_KERNEL_CAPABILITY |
  6 VMA_OR_ASYNC_OBJECT | 7 CHECKPOINT_RESTORE |
  8 PENDING_ENTRY_OR_EXEC | 9 RESPONSE_PLAN

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

An owner acquires its typed reference before activation or use and releases
it once through `owned=true -> false`. Retirement requires every class counter
to be zero, no owned tombstone in the complete iterator/WAL reconciliation,
and the grace period. Existing processes do not migrate in Version 1: a new
root takes the active generation; an old root, its forks and execs keep the
generation they already own.

#### A.12.2 Binding and composite object identity

```text
BindingLifecycleStateV1: u8 =
  0 UNKNOWN | 1 PREPARING | 2 ACTIVE | 3 DRAINING |
  4 TERMINATING | 5 TOMBSTONED

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
  lifecycle_state: BindingLifecycleStateV1
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
  binding_lifecycle_state: BindingLifecycleStateV1
}

EffectDefaultKeyV1 {
  profile_generation_ref_id: u64
  active_role_id: u32
  entry_kind: u16
  effect_family: u16
  operation: u16
  composite_atom_id: u64
  process_state_vector_id: u32
  binding_lifecycle_state: BindingLifecycleStateV1
}

PhysicalDecisionV1 {
  decision: ALLOW | AUDIT_ALLOW | DENY
  errno: i16
  evidence_class_id: u32
  transition_id: u32              // zero means no state change
  exception_numeric_handle: 0 | ExceptionNumericHandleV1
    // zero means no ExceptionV1 consumption
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
  binding_lifecycle_state: BindingLifecycleStateV1
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
  lifecycle_state: BindingLifecycleStateV1
  effect_family, operation: u16
}
```

Creation/acquisition installs and reads back a dynamic floor before the object
or channel becomes usable. First use before `ACTIVE`, capacity N+1, object
reuse, missing provenance, or an unclassified received fd denies.

#### A.12.5 Atomic transitions

```text
TransitionKindV1: u8 =
  0 UNKNOWN | 1 NONE | 2 PROCESS_ONLY | 3 NATIVE_AUTHORITY_ONLY

TransitionDescriptorV1 {
  transition_id: u32
  node_boot_id: Id128
  label_epoch: u64
  transition_kind: TransitionKindV1
  profile_generation_ref_id: u64
  exception_numeric_handle: 0 | ExceptionNumericHandleV1
    // zero means no ExceptionV1 consumption
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

NativeAuthorityTransitionKeyV1 {
  profile_generation_ref_id: u64
  transition_id: u32
  current_potential_sensitive_bits, current_observed_sensitive_bits: u64
  current_restriction_set_ref_id, current_domain_response_set_ref_id: u64
}

NativeAuthorityTransitionValueV1 {
  next_potential_sensitive_bits, next_observed_sensitive_bits: u64
  next_restriction_set_ref_id, next_domain_response_set_ref_id: u64
}
```

BPF resolves the descriptor and prospective row before locking the owning
state. Under the one lock it rechecks the complete old tuple/version and writes
the complete next tuple. Version 1 rejects a rule that requires one syscall to
atomically mutate both process and domain map values. A direct sensitive access
uses the native-domain transition as its authority.

#### A.12.6 Canonical lookup order

```text
1. If an earlier stacked LSM result is nonzero, preserve it and return it.
2. Read TaskLabelV1. If absent, completely resolve protected placement:
   proved outside -> explicit host policy;
   protected or unknown -> deny missing protected identity.
3. Validate expected live cgroup object, binding ID, nonce, live interval,
   descendant rule, lifecycle generation, and current placement.
4. Copy process, native-family state, entry, and binding tuples under their own
   locks. Never nest locks. Revalidate each version; retry one complete snapshot
   once, then deny on continuing contention.
5. Require committed/active entry, active process, compatible epochs, exact
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
  root_mount_id: u64
  admitted_route_digest: DigestV1
  state: ADMISSION_ACTIVE | FAIL_CLOSED_UNKNOWN | TOMBSTONED
  live_interval_id: Id128
  transition_version: u64
}

MountSecurityViewV1 {
  mount_namespace_id: Id128
  admission_generation: u64
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
  object_kind: ExactObjectKindV1
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
  dynamic_floor_state_id: Id128
  state: PREPARING | ACTIVE | TOMBSTONED | RECONCILIATION_REQUIRED
}
```

Paths are display and policy-authoring inputs. A signed path-tree `DENY` floor
is the limited exception: it can deny a covered effect when the real canonical
path is in the protected tree, without an exact child object or inode
generation. The final positive decision uses the resolved mount, filesystem,
object, and generation. Rename and bind aliases do not change positive object
authority. Inode-number reuse creates a new generation.

The BPF mount hooks update the mutation epoch and pending count before a
namespace-visible change. Each file or executable decision reads the live
namespace event and mount tree. BPF resolves the complete path and rechecks the
guard in the same hook chain. A concurrent or incomplete topology denies. Rust
does not build or publish a post-start topology snapshot.

#### A.13.2 File-operation coverage

| Operation family | Exact object that must be known before allow | Required decision/result distinction |
| --- | --- | --- |
| Open/read acquisition | Final resolved object after namespace lookup | attempted open, returned fd, later positive bytes, mmap, and provider use are different results |
| Existing/passed/inherited fd use | `FileInstanceProvenanceV1` plus current actor | current actor policy intersects the file's floor; a separate descriptor-passing record may exist, but transfer history is not required |
| Create/mkdir/mknod/symlink | parent directory object, new name bytes, mount generation, proposed object kind | reserve/classify before visibility; attach new-object floor before first use |
| Rename/link | exact source object plus old/new parent objects and names | both sides must be checked; paired hooks cannot lose an earlier LSM denial |
| Unlink/rmdir | exact object and parent/name relation | namespace removal does not erase open/VMA/persistent state |
| chmod/chown/truncate/setattr | exact object, requested attributes, current file provenance | mutation uses a dedicated key; open permission is insufficient |
| read/write/splice/sendfile/copy-file-range | current actor, exact source and sink, offsets/lengths, async request identity | admission and positive completed bytes are recorded separately |
| mmap/mprotect/pkey_mprotect | exact mm, VMA range, backing object, old/new permissions and write/execute history | executable or writable-shared capability exists for VMA lifetime, not syscall lifetime |
| io_uring/AIO | submitting actor/native state, ring generation, registered files/buffers, opcode, later executor/completion | SQPOLL never borrows the kernel thread's role; unsupported opcode/setup denies full claim |

Filesystem namespace mutation uses operation-specific keys rather than one
underspecified file key:

```text
CreateKeyV1 = {
  actor_process_state_id, actor_authority_domain_id: Id128
  mount_view: MountSecurityViewV1
  parent_directory: FileObjectIdentityV1
  name_bytes: bstr(1..255)
  object_kind: ExactObjectKindV1
  mode, create_and_resolve_flags: u64
}

LinkKeyV1 = {
  actor_process_state_id, actor_authority_domain_id: Id128
  source_object: FileObjectIdentityV1
  destination_parent: FileObjectIdentityV1
  destination_name_bytes: bstr(1..255)
  flags: u64
}

RenameKeyV1 = {
  actor_process_state_id, actor_authority_domain_id: Id128
  source_parent, source_object, destination_parent: FileObjectIdentityV1
  destination_existing_object?: FileObjectIdentityV1
  destination_name_bytes: bstr(1..255)
  operation: ORDINARY | NOREPLACE | EXCHANGE | WHITEOUT
}

UnlinkKeyV1 = {
  actor_process_state_id, actor_authority_domain_id: Id128
  parent_directory, victim_object: FileObjectIdentityV1
  victim_kind: FILE | DIRECTORY
}

SetattrKeyV1 = {
  actor_process_state_id, actor_authority_domain_id: Id128
  object: FileObjectIdentityV1
  operation: TRUNCATE | MODE | UID | GID | XATTR | FILE_CAPABILITY
  bounded_new_value_class: RegistrySymbolV1
}

ExactRequestIdentityV1: u8 =
  0 UNKNOWN
  | 1 SYNC_SYSCALL {
    task_cookie: nonzero u64, process_state_id: Id128,
    syscall_entry_sequence, effect_attempt_sequence: nonzero u64,
    effect_family, operation: u16
  }
  | 2 AIO_REQUEST {
      aio_context_id, request_id: Id128, submission_sequence: nonzero u64
    }
  | 3 IO_URING_REQUEST {
      ring_id: Id128, ring_generation, submission_sequence: nonzero u64,
      sqe_index: u32, user_data: u64, opcode: u16
    }
  | 4 MMAP_ATTEMPT {
      task_cookie: nonzero u64, process_state_id, authority_domain_id: Id128,
      attempt_sequence: nonzero u64
    }

MAX_NESTED_EFFECT_ATTEMPTS = 4

TaskEffectAttemptStateV1 {
  task_cookie: nonzero u64
  syscall_entry_sequence, next_effect_attempt_sequence: nonzero u64
  frames[MAX_NESTED_EFFECT_ATTEMPTS] {
    effect_attempt_sequence: nonzero u64
    effect_family, operation, hook_discriminator: u16
    repeated_lsm_pass_count: u16
    request_identity: ExactRequestIdentityV1
    state: PREPARING | DECIDED | RETURNED | CANCELLED
  }
  depth: u16 in 0..MAX_NESTED_EFFECT_ATTEMPTS
  state: ACTIVE | OVERFLOW_FAIL_CLOSED | TASK_EXITED
}

DelegatedIoEdgeV1 {
  edge_id: DigestV1
  initiating_effect_observation_id: DigestV1
  worker_task_cookie: nonzero u64
  worker_process_state_id: Id128
  initiating_object: ExactObjectGenerationV1
  delegate_kind: KERNEL_FS | FUSE_DAEMON | CSI_SIDECAR |
                 LOCAL_PROXY | OTHER_QUALIFIED
  backing_mount_or_service_identity: Id128
  delegate_process_or_socket_subject_id?: DigestV1
  backing_remote_flow_or_provider_subject_id?: DigestV1
  proof_quality: ProofQualityV1
}
```

The request identity prevents a completion or repeated LSM pass from being
joined to a different syscall, ring, or mapping attempt. Frame overflow denies
the effect and opens an identity/coverage failure; it never overwrites an outer
attempt. A delegated edge is evidence about the real IO chain, not authority to
attribute the delegate's packet directly to the worker.

Projected ServiceAccount token rotation must install the new exact object
binding before AtomicWriter makes the new revision visible. An asynchronous
userspace inode update after visibility is too late. If the platform cannot
delay visibility, the strict role denies the projected mount or reports that
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
SourceMutabilityProofV1 {
  proof_id: Id128
  proof_generation: nonzero u64
  covered_source: ExactObjectGenerationV1
  proof:
    SEALED_MEMFD {
      required_seals: F_SEAL_WRITE | F_SEAL_SEAL
      no_preexisting_writable_mapping_proof_id: Id128
    }
    | IMMUTABLE_CAS_OR_IMAGE_OBJECT {
        content_digest: DigestV1
        read_only_backing_proof_id: Id128
      }
    | HELD_WRITER_RECONCILIATION {
        reconciliation_id: Id128
        writer_and_vma_snapshot_id: Id128
      }
  valid_from_transition_version: nonzero u64
  state: ACTIVE | INVALIDATED | TOMBSTONED
}

KernelExecutableMappingClassV1 {
  mapping_class: FILE_BACKED | MEMFD | ANONYMOUS_JIT |
                 ANONYMOUS_OTHER | SPECIAL_KERNEL_MAPPING
  backing_object?: ExactObjectGenerationV1
  source_mutability_proof_id?: Id128
  initial_permissions, requested_permissions: READ | WRITE | EXEC
  write_history: NEVER_WRITABLE | WRITABLE_BEFORE_EXEC |
                 WRITABLE_AND_EXECUTABLE | UNKNOWN
  loader_purpose: PROCESS_IMAGE | ELF_INTERPRETER | BINFMT_INTERPRETER |
                  JIT_CODE | SHARED_LIBRARY | OTHER_QUALIFIED
  state: PREPARING | ACTIVE | INVALIDATED | TOMBSTONED
}

MmSnapshotIdentityV1 {
  node_boot_id: Id128
  label_epoch: u64
  mm_cookie: nonzero u64
  mm_generation: u64
  snapshot_version: u64
  expected_sharer_count: u32
}

VmaIteratorSessionIdentityV1 {
  node_boot_id: Id128
  label_epoch: u64
  iterator_session_id: Id128
  mm_cookie: nonzero u64
  mm_generation: u64
  snapshot_version: u64
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

VmaIteratorFrameV1 =
  BEGIN {
    wire_version: exactly 1
    session_identity: VmaIteratorSessionIdentityV1
    expected_mm_snapshot: MmSnapshotIdentityV1
    expected_sharer_count: u32
    first_sequence: exactly 1
  }
  | RECORD {
      sequence: nonzero u64
      session_identity: VmaIteratorSessionIdentityV1
      task_cookie: nonzero u64
      process_state_id: Id128
      range_start, range_end: u64, range_end > range_start
      vm_flags: u64
      effective_permissions: READ | WRITE | EXEC
      mapping_class: KernelExecutableMappingClassV1
      backing_identity_quality: EXACT_LIVE_FILE_OBJECT |
                                ANONYMOUS_CLASSIFIED |
                                REDUCED_INODE_ONLY | UNKNOWN
      backing_file_object?: FileObjectIdentityV1
    }
  | END {
      final_sequence, record_count, sharer_count: u64
      status: COMPLETE | ITERATOR_ERROR
    }

VmaSnapshotV1 {
  snapshot_id: Id128
  identity: MmSnapshotIdentityV1
  iterator_session: VmaIteratorSessionIdentityV1
  sharer_task_cookies[1..4096]: sorted unique nonzero u64
  records[0..1048576]: VmaIteratorFrameV1::RECORD,
    sorted by (range_start, range_end)
  completeness: COMPLETE | PARTIAL_GAP | PARTIAL_UNKNOWN_CLASS |
                REVALIDATION_FAILED
  committed_boottime_ns?: u64
}
```

An `mm_struct *` pointer is not durable identity. BPF/Rust use a non-reused mm
cookie, generation, live interval, expected sharers, and begin/record/end
iterator protocol. An incomplete snapshot is typed partial and cannot prove
that no executable or writable-shared mapping exists.

The source mutability proof intentionally has no same-domain or domain-join
variant: communication and shared ancestry do not make bytes immutable. A VMA
snapshot is `COMPLETE` only after one BEGIN, contiguous RECORD frames, one
successful END, EOF, and unchanged sharer/mm revalidation. The END frame does
not require BPF to compute a cryptographic stream digest; the committed
snapshot digest is a userspace content identity only when another signed or
stored artifact references the completed snapshot.

In-process Python/Jinja interpretation may create no exec or executable-memory
transition. Mithril controls its next file, socket, device, privilege, write,
send, or provider effect and must not report “Python execution denied” when
only a later effect was denied.

#### A.13.4 Network and socket lifetime

```text
ActorSocketDecisionKeyV1 {
  current_process_state_id, current_authority_domain_id: Id128
  current_profile_generation_ref_id: u64
  operation: SOCKET_CREATE | BIND | LISTEN | ACCEPT | CONNECT |
             SEND | RECEIVE | SHUTDOWN | SETSOCKOPT | GETSOCKOPT
  socket_key_id?, socket_generation?: u64
  current_actor_network_namespace_generation_id: Id128
  socket_network_namespace_generation_id?: Id128
  protocol: u16
  requested_peer?: {
    address_family: IPV4 | IPV6 | UNIX | OTHER_QUALIFIED
    address_bytes: bstr(0..108)
    port: u16
  }
  dynamic_response_floor_id: Id128
}

SocketControlEffectKeyV1 = ActorSocketDecisionKeyV1 where operation is one of
  SOCKET_CREATE | BIND | LISTEN | ACCEPT | SHUTDOWN | SETSOCKOPT | GETSOCKOPT

SocketFlowAuthorizationV1 {
  flow_authorization_id: Id128
  socket_key_id, socket_generation, flow_generation: nonzero u64
  authorizing_process_state_id, authorizing_authority_domain_id: Id128
  authorizing_profile_generation_ref_id: nonzero u64
  socket_network_namespace_generation_id: Id128
  protocol: u16
  requested_peer?: {
    address_family: IPV4 | IPV6 | UNIX | OTHER_QUALIFIED
    address_bytes: bstr(0..108)
    port: u16
  }
  allowed_final_destination_policy_ids[1..64]: nonzero u64
  dynamic_floor_state_id: Id128
  state: PREPARING | ACTIVE | FENCED | TOMBSTONED |
         RECONCILIATION_REQUIRED
  transition_version: nonzero u64
}

FinalFlowDecisionKeyV1 {
  flow_authorization_id: Id128
  socket_key_id, socket_generation, flow_generation: nonzero u64
  socket_network_namespace_generation_id: Id128
  protocol: u16
  final_destination_policy_id: nonzero u64
  final_address_bytes: bstr(4..16)
  final_port: u16
  rewrite_chain_generation: nonzero u64
  dynamic_response_floor_id: Id128
}

ResolvedSocketOrChannelGenerationV1 {
  exact_socket_or_channel_key_id: nonzero u64
  exact_socket_or_channel_generation: nonzero u64
  backing_identity: ExactObjectGenerationV1
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
  active_flow_authorization_id?: Id128
  dynamic_floor_state_id: Id128
  state: PREPARING | ACTIVE | SHUTTING_DOWN | TOMBSTONED |
         RECONCILIATION_REQUIRED
}
```

The sender-stage decision and the final-flow decision are deliberately
separate. At `connect`, `send`, or `sendmsg`, the first key has a meaningful
current actor and can deny the syscall before the requested operation. An
allow installs or selects `SocketFlowAuthorizationV1`. A later ordered
cgroup/TC/packet boundary uses `FinalFlowDecisionKeyV1` after routing, NAT,
mesh, or socket rewrite. That boundary relies on the socket/flow authorization
and does not pretend that packet-hook `current` identifies the sender.

The socket identity is absent exactly for `SOCKET_CREATE`, before the socket
exists, and required for every later operation. `requested_peer` is required
when the operation exposes one and absent when Linux supplies none. A final
flow key is valid only for qualified IP packet paths: IPv4 uses exactly four
address bytes and IPv6 exactly sixteen. Unix/local channels remain under the
sender/channel relationship contract rather than fabricating a packet
destination.

If the sender stage allows but the final stage drops a rewritten packet,
evidence reports `PACKET_DROPPED_AFTER_REWRITE`; it does not report
`SEND_SYSCALL_DENIED`. Retransmissions and already queued bytes remain attached
to the socket/flow floor, not retroactively to one process. Each new shared-
socket use still checks its actual current actor at the sender stage. When
different actors cannot share one safe final flow floor, policy denies the use
or fences the whole socket and reports that blast radius.

Every use intersects current actor/domain policy with immutable socket
provenance and the exact live socket floor. A passed, inherited, accepted, or
preexisting socket does not transfer its creator's positive allow. Shared use
does not merge actors. Each use checks the current actor and configured peer
relationship. A separately authorized whole-socket fence reports its actual
blast radius.

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
ProcessControlEffectKeyV1 {
  controller_process_state_id, controller_authority_domain_id: Id128
  controller_profile_generation_ref_id: nonzero u64
  operation: PTRACE_ATTACH | PTRACE_READ | PTRACE_WRITE |
             PROCESS_VM_READ | PROCESS_VM_WRITE |
             PROC_MEM_OPEN_READ | PROC_MEM_OPEN_WRITE |
             PROC_FD_OPEN | PROC_NS_OPEN |
             PIDFD_OPEN | PIDFD_GETFD | PIDFD_SIGNAL | SIGNAL
  target_node_boot_id: Id128
  target_label_epoch: u64
  target_task_cookie: nonzero u64
  target_process_instance_id, target_process_state_id: Id128
}

SeccompFloorProofV1 {
  proof_id: Id128
  task_or_process_state_id: Id128
  source: MITHRIL_DIRECT_TARGET_INSTALL |
          QUALIFIED_OCI_SECCOMP_ADJUSTMENT |
          PREEXISTING_PRESENCE_ONLY
  installer_or_runtime_capability_id?: Id128
  exact_runtime_version_and_config_digest?: DigestV1
  requested_oci_seccomp_policy_digest?: DigestV1
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

LandlockFloorProofV1 {
  proof_id: Id128
  task_or_process_state_id: Id128
  source: MITHRIL_DIRECT_TARGET_INSTALL |
          QUALIFIED_TARGET_CONTEXT_INSTALL
  installer_capability_id: Id128
  kernel_version_config_and_lsm_digest: DigestV1
  measured_landlock_abi: nonzero u32
  ruleset_digest: DigestV1
  handled_access_fs_mask: u64
  handled_access_net_mask: u64
  scoped_mask: u64
  restrict_self_flags: u32
  restrict_self_result: SUCCESS | ERROR
  errno_if_error?: nonzero u16
  thread_scope: CALLER_AND_FUTURE_CHILDREN |
                THREAD_GROUP_AND_FUTURE_CHILDREN
  single_threaded_before_install: PROVED | NOT_PROVED | NOT_REQUIRED
  installed_before_untrusted_phase: PROVED | NOT_PROVED
  qualification_fixture_result: PASS | FAIL | NOT_RUN
  state: VERIFIED | PARTIAL | FAILED | UNKNOWN
}
```

`SeccompFloorProofV1` is reserved for the deferred Seccomp surface. It is not
emitted, required, or used to support a Version-1 enforcement claim. A later
approved stage may activate it only with the evaluation contract in Chapter 21
and the conditional `SECCOMP-QUAL-001` fixture.

This key is directional. The current task supplies the controller fields. The
kernel target task must resolve to the listed task cookie, process instance,
and process state in the current node boot and label epoch. A numeric PID is
only a way to find a candidate; it is never part of the authorization key.
An exact allow is unavailable for an unlabelled target. Policy then uses its
configured unknown-target result, normally deny for a protected controller.

Each operation is qualified separately at a hook that runs before that
operation can change or disclose target state. If the hook cannot distinguish,
for example, `PROC_FD_OPEN` from an ordinary proc-file open, Mithril reports
that operation unsupported instead of treating a nearby event as prevention.
`PIDFD_GETFD` is itself a process-control operation and can be denied before it
returns a new fd. If it is allowed, later use of that fd is governed by the
normal file, device, socket, or other object hook for the current process;
Mithril does not require a detailed transfer history. The readable policy may
group operations, but the compiled key and evidence keep the exact operation
above.

`MITHRIL_DIRECT_TARGET_INSTALL` and `QUALIFIED_OCI_SECCOMP_ADJUSTMENT` require
`installer_or_runtime_capability_id` and the exact requested filter digest.
The OCI variant also requires the exact runtime/configuration digest.
`PREEXISTING_PRESENCE_ONLY` forbids those claims and cannot produce
`state=VERIFIED` for exact filter content.

For `LandlockFloorProofV1`, `SUCCESS` forbids `errno_if_error`; `ERROR`
requires it. `THREAD_GROUP_AND_FUTURE_CHILDREN` requires measured ABI 8 or
newer, the registered numeric `LANDLOCK_RESTRICT_SELF_TSYNC` bit in
`restrict_self_flags`, and a successful syscall. Without that combination,
full-process `VERIFIED` requires
`thread_scope=CALLER_AND_FUTURE_CHILDREN` and
`single_threaded_before_install=PROVED`. `VERIFIED` also requires
`installed_before_untrusted_phase=PROVED` and
`qualification_fixture_result=PASS`. Mithril records the installer-owned
ruleset bytes and syscall result; it does not claim that Linux later returned
the exact ruleset from an arbitrary target.

If the deferred Seccomp surface is later approved, filters only become
stricter; there is no syscall that removes an installed filter. For a new
process on a qualified start path, Mithril must prove that it installed the
required floor before that target's user code and that all required threads
received it. A Mithril-owned launcher may install the floor later but before it
runs untrusted code; that is still a qualified target path, not external
retrofit. A user-notification listener cannot widen authority, and
ptrace/supervisor relationships need separate control. Seccomp can match
syscall numbers and scalar arguments. It cannot authenticate the pathname
behind a userspace pointer, so it cannot by itself authorize
`/proc/<target>/mem`.

Landlock is an additional target-installed floor. Its available rights depend
on the running ABI and may include filesystem, network-port, Unix-socket,
signal, and device-ioctl controls. Mithril installs it only through a qualified
target-context path before the target enters untrusted execution. The target
must either still be single-threaded or successfully use the measured ABI's
thread-group synchronization. If Mithril did not install it there, Mithril does
not make a Landlock-floor claim. Landlock does not replace dynamic BPF policy,
task identity, IPC relationship checks, devices and privilege outside its ABI,
provider semantics, or response.

For a defender's approved memory read, the trusted owner opens the exact target
while held, passes only that read-only target fd and one evidence-sink fd to a
short-lived measured inspector, and checks the exact inspector, case, target,
deadline, and allowed access in BPF LSM. A later approved Seccomp profile may
add an fd/syscall floor. If the authorization includes a byte limit, the
Mithril-owned inspector enforces it by counting its successful reads and
stopping at the approved maximum. BPF LSM does not expose a reliable byte
counter for this purpose. Memory write, ptrace control, fd extraction, signal,
and general network remain forbidden.

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

### A.14 Exact Native Authority And IPC Contract

Chapter 18 keeps native inheritance and IPC separate. Threads and native fork
descendants share restrictive state. Independent roots never join because of a
socket, pipe, file, shared memory area, loopback connection, or descriptor
passing.

#### A.14.1 Native authority state

```text
AuthorityDomainStateV1 {
  authority_domain_id, node_boot_id: Id128
  label_epoch, domain_epoch: u64
  domain_lock: bpf_spin_lock
  live_process_refs: u64
  response_plan_refs: u64
  reconciliation_hold_refs: u64
  potential_sensitive_bits, observed_sensitive_bits: u64
  effective_restriction_set_ref_id: u64
  effective_response_set_ref_id: u64
  retained_generation_set_ref_id: u64
  transition_version: u64
  state: PREPARING | ACTIVE | RECLAIMABLE |
         FAIL_CLOSED_OVERFLOW | CORRUPT
}

RejectedSharedResourceTaintStateV1 {
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

RejectedPersistentFileTaintStateV1 {
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
explicit `CLONE_VM|CLONE_FILES|CLONE_FS`. Independent roots never join this
domain.

The domain carries only the native family's negative restrictions, sensitive
bits, response floors, and retained generations. A converter does not inherit
an uploader's Mithril role, permission set, or restriction bits through IPC.
If their byte channel is allowed, the converter may still ask a vulnerable
uploader to misuse the uploader's own authority; Linux cannot interpret or
prevent that confused-deputy request.

A domain is reclaimed after its process, response, reconciliation, retained
generation, WAL, and grace-period references reach zero. The two rejected
taint records above remain named only so old implementations are not revived;
they are not active Version 1 schemas.

#### A.14.2 Connection-oriented IPC relationship

One relationship covers ordinary communication in both directions for sockets,
pipes, and local network channels. Descriptor passing may produce a separate
observation, but it has no Version 1 object-tracking or permission model. If no
relationship matches, `PolicyDocumentV1.unmatched_ipc_disposition` supplies the
result.

```text
IpcRelationshipRuleV1 {
  relationship_id: Id128
  endpoint_a: IpcEndpointSelectorV1
  endpoint_b: IpcEndpointSelectorV1
  channel: IpcChannelSelectorV1
  communication_disposition: ALLOW | ALERT | DENY
  profile_generation_ref_id: u64
}

IpcEndpointSelectorV1 {
  role_id?: u32
  execution_set_id?: Id128
  protected_host_service_id?: Id128
}

IpcChannelSelectorV1 {
  kind: UNIX_STREAM | UNIX_DATAGRAM | PIPE | LOCAL_INET
  readable_selector_digest: DigestV1
}

IpcChannelStateV1 {
  channel_state_id: Id128
  exact_live_channel_or_object_identity: ExactObjectGenerationV1
  participants:
    SOCKET_ENDPOINTS {
      endpoint_a_process_state_id: Id128
      endpoint_b_process_state_id: Id128
    }
    | PIPE_OBSERVED_USERS {
        process_state_ids[0..MAX_PIPE_OBSERVED_USERS]: Id128
      }
  participant_resolution: EXACT_SOCKET_ENDPOINTS |
                          PIPE_PEER_NOT_AVAILABLE | EVIDENCE_OVERFLOW
  matched_relationship_id?: Id128
  applied_disposition: ALLOW | ALERT | DENY
  profile_generation_ref_id: u64
  state: PREPARING | ACTIVE | TOMBSTONED | CORRUPT
}

IpcDescriptorPassingV1 {
  observation_id: Id128
  channel_state_id: Id128
  sender_process_state_id: Id128
  receiver_process_state_id?: Id128
  observation: SEND_WITH_DESCRIPTORS | RECEIVE_WITH_DESCRIPTORS
  communication_result: ALLOWED | DENIED | UNKNOWN
  descriptor_count?: u16
  profile_generation_ref_id: nonzero u64
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
  endpoint_process_state_ids[]:Id128
  topology_version:u64
}
```

For a pipe read or write, the current process must match either endpoint
selector and the exact live pipe must match the channel selector. The decision
does not depend on the observed-user list, so evidence overflow cannot broaden
permission. When two processes are observed using the pipe, evidence may link
both to it, but never says that one consumed bytes from a particular write. A
policy that requires an exact peer cannot use a pipe relationship; it follows
`unmatched` or uses a socket whose peer can be resolved.

Shared files and shared memory do not use `IpcRelationshipRuleV1`. They compile
through the normal exact local-effect decision and are recorded at the
operation Linux can actually govern:

```text
SharedObjectAcquisitionV1 {
  acquisition_id: Id128
  task_cookie: u64
  process_state_id, authority_domain_id: Id128
  exact_object: ExactObjectGenerationV1
  operation: FILE_OPEN_READ | FILE_OPEN_WRITE | FILE_READ | FILE_WRITE |
             MMAP_READ | MMAP_WRITE | MMAP_EXEC | MPROTECT |
             SHMAT_READ | SHMAT_WRITE
  profile_generation_ref_id: nonzero u64
  physical_result: ALLOWED | DENIED | UNSUPPORTED
  capability_lifetime: OPERATION_ONLY | OPEN_FILE_LIFETIME |
                       MAPPING_OR_ATTACHMENT_LIFETIME
  decided_boottime_ns: u64
}
```

For `FILE_READ` and `FILE_WRITE`, a qualified hook may make another decision on
each covered operation. For `MMAP_*` and `SHMAT_*`, the decision governs
creation or permission of the mapping/attachment. If it succeeds, later CPU
loads and stores are not new `SharedObjectAcquisitionV1` records. Mithril may
freeze or terminate holders during response, but it cannot claim that policy
was rechecked for each memory access.

“Local” is resolved in the exact live network namespace. It includes loopback,
Pod IP, wildcard listeners, local redirection, and qualified hairpin delivery;
it is not determined by the spelling of an address. `UNKNOWN` cannot establish
a known peer and follows the configured unmatched-IPC disposition. Local
IPv4/IPv6 and Unix sockets use resolved endpoints. Pipes use the current actor,
live pipe, and operation; observed users are evidence only. Descriptor passing
may produce the minimal observation above. It does not require identifying the
object represented by the descriptor.
Regular files, `emptyDir`, memfd mappings, and shared memory instead use the
exact object-acquisition contract above. Process control uses the directional
controller-target key in Appendix A.13.6.

#### A.14.3 Rejected live merge and byte tracking

Mithril does not merge independent process domains after IPC. Linux cannot
atomically stop every task, drain every asynchronous operation, rewrite all
references, and resume them as one domain.

Mithril also does not reserve every byte publication or infer which input bytes
caused an output. It governs the current actor's socket, pipe, file, mapping,
and provider effects. Descriptor passing may be separate evidence, but no
represented-object or byte-provenance graph becomes authority. Appendix B.3
keeps the rejected designs and their replacements.

#### A.14.4 Persistent and cross-node volumes

Rename and hardlink preserve object identity. Overlay copy-up, reflink, copy,
snapshot, clone, backup, and restore create a new object identity. Policy must
classify that new object or deny its covered use. Mithril does not infer that
copied bytes carry the source process's security state.

RWX storage needs a signed centrally committed
`PersistentVolumePolicyV1`: volume/storage generation, access policy,
participant set, access mode, and commit index. Every node denies covered file
effects through BPF until it fetches a non-rollback record, lowers it into a
fresh local set, installs it, and reads back the result. The mount may already
exist and the workload may already be running; Mithril neither holds nor
releases either one. When a qualified OCI/NRI/runtime start callback exists,
Mithril may delay returning from that callback until the same access state is
ready, but the callback remains a runtime-start gate rather than a mount gate.

```text
PersistentVolumePolicyV1 {
  persistent_volume_policy_id, cluster_uid:Id128
  csi_driver_canonical_name
  provider_or_csi_volume_handle_digest:DigestV1
  provisioned_volume_uid:Id128
  provisioned_storage_generation:u64
  access_mode:RWO | ROX | RWX | RWOP | UNKNOWN
  permitted_execution_set_ids[]:Id128
  volume_access_policy_digest:DigestV1
  record_generation, control_commit_index:u64
  policy_artifact_digest:DigestV1
  state:PREPARING | ACTIVE | RETIRING | REVOKED | CORRUPT
  seal: SignedArtifactSealV1
}

VolumeAccessReadinessV1 {
  readiness_id, node_boot_id, execution_set_id,
    persistent_volume_policy_id:Id128
  exact_live_mount_identity
  observed_record_generation, observed_control_commit_index:u64
  installed_local_access_policy_ref_id:u64
  installed_volume_access_policy_digest:DigestV1
  optional_runtime_start_callback_identity?:Id128
  state:PREPARING | READ_BACK | ACTIVE | DENIED
}
```

The central record carries portable access policy, never a node-local map
handle. A node compiles that policy to a fresh local set and reads it back
before marking covered volume access `ACTIVE`. Until then, the BPF access gate
denies covered effects. If a qualified runtime-start callback is waiting,
Mithril returns success only after `ACTIVE`; otherwise the task may run but its
covered accesses still deny. Stale commit index, rollback, unknown storage
generation, bad signature, or unavailable control leaves access denied. This
is intentionally volume-wide in Version 1: safe per-file cross-node identity
is unsupported until the storage backend proves stable non-reused identity.

If a backend lacks stable non-reused object identity or qualified
link/copy-up/remount lifecycle, the honest options are a volume-wide common
access policy, denial of the writable surface, or an unsupported per-file
claim. None propagates inferred byte sensitivity.

#### A.14.5 Failure and race tests

Tests cover allowed and unmatched Unix stream/datagram, pipe, loopback, Pod-IP,
across containers, Pods, and host services. Separate process-control tests cover
each controller-to-target operation and prove that allowing A to control B does
not allow B to control A. Separate object tests cover shared-file
open/read/write/mmap and shared-memory mapping/attachment. They replace a
pathname socket, reuse an abstract name, restart either endpoint, race peer
exit, replace an object, keep an old mapping, and pass files, sockets, pidfds,
memfds, and device fds.

For sockets and local network channels, the relationship oracle checks the
physical operation and exact peer identity. For a pipe, it checks the current
process, live pipe, and read/write operation. It proves that observed pipe users
are evidence only and that Mithril never reports one as the exact reader of a
write. Both ordinary communication directions follow the one relationship
result. Optional descriptor-passing evidence requires only the communication
edge, observation, communication result, and optional descriptor count, never
the represented object. Later use of a received file or device fd is tested
through the normal file or device hook for the receiving process. The
process-control oracle checks the exact controller, target task identity, and
operation before the effect. The shared-object oracle checks the exact actor,
object, operation, and capability lifetime. It proves that a denied mapping or
attachment was not created. If a mapping was allowed, the test records later
loads/stores as outside per-access enforcement and uses freeze/termination to
test containment. Unsupported AIO, io_uring, zero-copy, mutable shared-memory,
exact-peer-required pipe, or ambiguous socket-peer paths return the configured
deny or `UNSUPPORTED`; they never trigger a domain merge or global drain.

Mithril must never claim that an allowed byte stream carries inferred security
state, that a graph edge proves byte provenance, or that two communicating
processes became one authority domain.

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
EvidenceFieldKeyV1: u16 =
  0 UNKNOWN | 1 FINDING_ID | 2 REASON_CODE | 3 DECISION | 4 ERRNO |
  5 TASK_COOKIE | 6 PROCESS_LINEAGE_ID | 7 AUTHORITY_DOMAIN_ID |
  8 EXECUTION_SET_ID | 9 EXACT_OBJECT_ID | 10 OBJECT_CLASS_ID |
  11 DESTINATION_ID | 12 PROVIDER_REQUEST_ID | 13 PROVIDER_RESULT |
  14 COVERAGE_INTERVAL_IDS | 15 POLICY_RULE_IDS | 16 RESPONSE_RESULT |
  17 PROVIDER_PRINCIPAL_ID | 18 PROVIDER_RESOURCE_ID

EvidenceFieldV1 =
  FINDING_ID { value: DigestV1, sensitivity, provenance_observation_ids[], proof_quality }
  | REASON_CODE { value: ReasonCodeIdV1, sensitivity, provenance_observation_ids[], proof_quality }
  | DECISION { value: ResultCodeIdV1, sensitivity, provenance_observation_ids[], proof_quality }
  | ERRNO { value: i16, sensitivity, provenance_observation_ids[], proof_quality }
  | TASK_COOKIE { value: nonzero u64, sensitivity, provenance_observation_ids[], proof_quality }
  | PROCESS_LINEAGE_ID { value: Id128, sensitivity, provenance_observation_ids[], proof_quality }
  | AUTHORITY_DOMAIN_ID { value: Id128, sensitivity, provenance_observation_ids[], proof_quality }
  | EXECUTION_SET_ID { value: Id128, sensitivity, provenance_observation_ids[], proof_quality }
  | EXACT_OBJECT_ID { value: Id128, sensitivity, provenance_observation_ids[], proof_quality }
  | OBJECT_CLASS_ID { value: ObjectClassIdV1, sensitivity, provenance_observation_ids[], proof_quality }
  | DESTINATION_ID { value: nonzero u64, sensitivity, provenance_observation_ids[], proof_quality }
  | PROVIDER_REQUEST_ID { value: Id128, sensitivity, provenance_observation_ids[], proof_quality }
  | PROVIDER_RESULT { value: ProviderResultBoundaryV1, sensitivity, provenance_observation_ids[], proof_quality }
  | PROVIDER_PRINCIPAL_ID { value: ProviderPrincipalV1, sensitivity, provenance_observation_ids[], proof_quality }
  | PROVIDER_RESOURCE_ID { value: ResourceSelectorV1, sensitivity, provenance_observation_ids[], proof_quality }
  | COVERAGE_INTERVAL_IDS { value[1..64]: Id128, sensitivity, provenance_observation_ids[], proof_quality }
  | POLICY_RULE_IDS { value[1..64]: PolicyLocalIdV1, sensitivity, provenance_observation_ids[], proof_quality }
  | RESPONSE_RESULT { value: ResultCodeIdV1, sensitivity, provenance_observation_ids[], proof_quality }
  | REDACTED { key: EvidenceFieldKeyV1, sensitivity, provenance_observation_ids[], proof_quality }
  | UNKNOWN { key: EvidenceFieldKeyV1, sensitivity, provenance_observation_ids[], proof_quality }

where sensitivity = PUBLIC | INTERNAL | SENSITIVE_IDENTIFIER
and provenance_observation_ids[0..16] are sorted unique DigestV1 values
and proof_quality is ProofQualityV1. Every array-valued field is sorted unique.

EvidencePayloadV1 {
  fields[1..64]: EvidenceFieldV1, sorted unique by EvidenceFieldKeyV1
}

FindingGroupingFieldV1: u8 =
  0 UNKNOWN | 1 FINDING_ID | 2 REASON_CODE | 3 PROCESS_LINEAGE_ID |
  4 AUTHORITY_DOMAIN_ID | 5 EXECUTION_SET_ID | 6 EXACT_OBJECT_ID |
  7 PROVIDER_PRINCIPAL_ID | 8 PROVIDER_RESOURCE_ID

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
  payload: EvidencePayloadV1
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

EvidenceBatchV1 {
  schema_version: exactly 1
  tenant_id: Id128
  node_identity: NodeIdentityV1
  node_boot_id, source_id: Id128
  label_epoch: nonzero u64
  source_epoch: u64
  first_sequence, last_sequence: u64
  prior_durable_contiguous_acknowledgement: u64
  observations[1..1024]: ObservationEnvelopeV1,
    sorted unique by source_sequence
  coverage_intervals[0..64]: CoverageIntervalV1,
    sorted unique by coverage_interval_id
  batch_content_id: ArtifactContentIdV1
}

EvidenceIntakeReceiptV1 {
  schema_version: exactly 1
  tenant_id: Id128
  node_identity: NodeIdentityV1
  node_boot_id, source_id: Id128
  label_epoch: nonzero u64
  source_epoch: u64
  batch_content_id: ArtifactContentIdV1
  durable_contiguous_sequence: u64
  accepted_record_set_digest: DigestV1
  control_commit_index: nonzero u64
  committed_utc_ns: i64
  authenticated_channel_receipt_digest: DigestV1
}
```

The field variant determines its key and value type; a decoder rejects a
duplicate key or a value encoded under the wrong variant. `REDACTED` means the
source proved the field existed but policy removed its value. `UNKNOWN` means
the source could not establish the value. Raw source observations normally
have no provenance observation IDs; derived observations list only their
direct inputs. The envelope's proof vector is the overall source result while
a field may carry a weaker field-specific vector. Coverage interval IDs are
opaque `Id128` values everywhere; evidence integrity comes from the containing
observation/batch rather than from turning the interval identifier into a
digest.

For kernel sources, `attempted = suppressed + requested` and
`requested = emitted + lost`. Suppression is intentional policy sampling;
loss is not. First loss, detach, reader failure, epoch change, counter
inconsistency, clock reset, or unknown map/link health closes the healthy
interval. Recovery opens a new interval; history is never rewritten.

The WAL truncates only through a durable contiguous acknowledgement. A restart
that cannot prove sequence continuity creates a new epoch and explicit gap.
Enforcement health, identity coverage, event coverage, semantic admission,
correlation feeds, and response verification remain separate axes.

One batch contains one node source epoch. It can contain a bounded
out-of-order set, but every envelope must repeat the same tenant, node, source,
and epoch coordinates. One source epoch cannot cross a label-epoch change; the
node opens a new source epoch first. Control verifies each observation ID and
batch content ID over the canonical batch content before transport. The mTLS
peer identity and canonical batch bytes produce the separate durable channel
receipt. An
existing `(tenant, node, source, epoch, sequence)` with different bytes
rejects the batch. The receipt is created only after the records and source
cursor share one durable commit. The node validates the authenticated Control
peer and receipt coordinates, persists the new cursor, and truncates only the
covered contiguous WAL range. A graph package cannot read an uncommitted batch
or use a transport receipt as an observation.

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
  sorted_evidence_ids[]: DigestV1
  required_coverage_interval_ids[]: Id128
  policy_provenance_ids[0..64]: DigestV1, sorted unique
  superseded_revision?: u64
  closed_reason_code?: u32
}

PolicyObservationProvenanceV1 {
  provenance_content_id: ArtifactContentIdV1
  tenant_id: Id128
  node_identity: NodeIdentityV1
  node_boot_id: Id128
  label_epoch, profile_generation_ref_id: nonzero u64
  source_id: Id128
  source_epoch: u64
  observation_ids[1..4096]: DigestV1, sorted unique
  policy_source_revision_id?: DigestV1
  candidate_content_id?: ArtifactContentIdV1
  target_snapshot_digest?: DigestV1
  node_bound_generation_digest?: DigestV1
  activation_acknowledgement_content_id?: ArtifactContentIdV1
  state: EXACT | MISSING | CONTRADICTED
}
```

A route may group on a field only when that exact field is present in the
payload and admitted by its evidence allowlist. Provider principal and resource
values retain their typed canonical forms for equality; a sink receives them
only after the normal sensitivity and route allowlist checks.

Packages declare sources, coverage, maximum lateness, time uncertainty,
retention, exact/contextual join fields, and late-event behavior. Delivery
order and duplicate redelivery cannot change the terminal finding bytes. Time
never upgrades an edge to exact.

The intake source registration and evidence batch bind node identity, boot,
label epoch, source, and source epoch. The activation acknowledgement binds
that coordinate and the node-local profile-generation reference to the derived
policy revision, candidate, target snapshot, and node-bound generation. Phase 7
creates `PolicyObservationProvenanceV1` from those exact records. Time, CRD
status, and aggregate rollout counts cannot fill a missing join. A finding that
depends on policy state lists the exact provenance ID or reports it missing or
contradicted.

#### A.15.3 Multi-node graph

```text
GraphSubjectV1 {
  subject_id: DigestV1
  tenant_id: Id128
  subject_kind: GraphSubjectKindV1
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
  sorted_evidence_ids[]: DigestV1
  required_coverage_ids[]: Id128
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
  sorted_policy_provenance_ids[]: DigestV1
  sorted_subject_ids[], sorted_edge_ids[]: DigestV1
  canonical_graph_digest: DigestV1
}
```

`ProviderEdgeContractV1` registers the only fields that can make a particular
pair of endpoint kinds direct:

```text
GraphSubjectKindV1: u8 =
  0 UNKNOWN | 1 TASK | 2 PROCESS | 3 EXECUTION_SET | 4 SOCKET |
  5 REQUEST | 6 CREDENTIAL_LEASE | 7 KUBERNETES_OBJECT |
  8 PROVIDER_OBJECT | 9 ARTIFACT | 10 CI_RUN | 11 CI_JOB |
  12 CI_STEP | 13 EXTERNAL

SourceKindV1 = RegistrySymbolV1
EvidenceFieldIdV1 = RegistrySymbolV1

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
  frozen_branch_ids[1..256]: DigestV1
  actions[1..64]: sorted unique ResponseActionRequestV1 by action_id
  authorization_id: Id128
  authorization_expires_utc_ns: i64
  node_deadline_boottime_ns?: u64
  state: PROPOSED | AUTHORIZED | REVALIDATING | APPLYING |
         VERIFYING | WATCHING | VERIFIED | PARTIAL | FAILED |
         UNKNOWN | EXPIRED | CANCELLED
  action_results[0..64]: sorted unique ResponseActionResultV1 by action_id
  required_watch_interval_ns: u64
  required_coverage_ids[0..64]: Id128
}

EffectiveResponseSet {
  set_ref_id: nonzero u64
  response_restriction_ids[MAX_RESPONSE_REFS]: Id128
  combined_deny_effect_families: u64
  combined_socket_fence
  earliest_expiry_boottime_ns: u64
}
```

The policy types referenced by a response binding are closed. The
authoritative Rust enum for `ResponseActionSpecV1` and the action request/result
types are in Appendix A.11.5.1. This section defines only the response-engine
types that compose with it:

```text
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

TargetRevalidationV1: u8 =
  0 UNKNOWN
  | 1 PROCESS_PIDFD_TASK_COOKIE_STARTTIME_CGROUP_BINDING
  | 2 LINEAGE_ROOT_AND_COMPLETE_EFFECTIVE_RESPONSE_SET
  | 3 SOCKET_COOKIE_PROVENANCE_AND_LIVE_BINDING
  | 4 CGROUP_FD_NONCE_AND_MEMBER_SET
  | 5 KUBERNETES_UID_RESOURCE_VERSION
  | 6 PROVIDER_STABLE_ID_REVISION_AND_AUTHORITY
  | 7 ARTIFACT_IMMUTABLE_DIGEST_AND_STORE_REVISION

PhysicalPostconditionV1: u8 =
  0 UNKNOWN
  | 1 RESPONSE_SET_INSTALLED_AND_DESCENDANTS_RECONCILED
  | 2 PROCESS_STOPPED_VIA_PIDFD
  | 3 SOCKET_SET_FENCED_AND_EXISTING_FLOW_ORACLE_PASSED
  | 4 CGROUP_FROZEN_AND_PACKET_FENCE_ACTIVE
  | 5 REPLACEMENT_REJECTED_THROUGH_WATCH_WATERMARK
  | 6 PROVIDER_CREDENTIAL_ACTION_READ_BACK
  | 7 MESH_DEVICE_DISABLED_AND_HANDSHAKE_REJECTED
  | 8 ARTIFACT_QUARANTINED_AND_CONSUMER_LOAD_REJECTED
  | 9 PROVIDER_OPERATION_SPECIFIC_POSTCONDITION
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

Blast radius is part of approval. A native-family restriction, shared
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
  source_mutability_proof_id: Id128
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
| Inherited or passed fd | Use/current-actor policy; descriptor passing may be recorded separately, and open-only policy is insufficient |
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

Rejected designs remain visible in one index so a later edit does not
accidentally revive them. They are history, not a second normative contract.

### B.1 Product, evidence, and upstream lessons

| Rejected or corrected idea | Why it is wrong | Replacement in this document |
| --- | --- | --- |
| Put every local decision in BPF | Policy compilation, signatures, provider meaning, graph correlation, and approval do not belong in a bounded hook | Rust/control prepares authority; BPF makes only bounded local pre-effect decisions (Chapters 5, 12-13) |
| Exact attribution implies narrow actuation | A precise task may share a socket/domain/cgroup with others | Response reports and verifies actual blast radius (Chapters 18-19, 24) |
| Infer machine evidence behavior from a display `Kind` | Boundary nature and Mithril relationship are independent fields | `SourceEvidenceClaimV1` stores both (Appendix A.3) |
| One network key requires both current actor and final post-rewrite destination | Sender hooks know the actor; final packet hooks may know the rewritten destination but have no meaningful current task | `ActorSocketDecisionKeyV1` installs `SocketFlowAuthorizationV1`; `FinalFlowDecisionKeyV1` enforces the final destination (Appendix A.13.4) |
| KubeArmor map-of-maps already equals immutable policy generations | Checked updates mutate rows over time and may partially diverge | Build, read back, and probe a fresh generation. Read the expected pointer, then publish the active pointer (Chapter 12, §28.3) |
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

### B.3 Policy, identity lookup, objects, and IPC

| Rejected or corrected idea | Why it is wrong | Replacement |
| --- | --- | --- |
| Version 1 generic metadata extensions | Unknown signed fields create divergent interpretations | Closed schema; unknown/duplicate key rejects (§12) |
| Flatten the internal policy document into a CRD or put YAML in one string | The API would expose unqualified capabilities, and schema, conversion, field ownership, and typed rejection could not preserve the public boundary | Structural `WorkloadProtectionPolicy` and bounded `WorkloadProtectionException` resources lower through one Control owner into internal `PolicyDocumentV1` (Ch. 11-12, Appendix A.11) |
| Every node watches policy CRDs | It creates many policy-source owners and bypasses Control compilation, signing, targeting, and rollout truth | Control alone reconciles CRDs and sends signed target-bound candidates; node alone activates them (Ch. 5, §12, §34) |
| CRD status or finalizer grants node authority | Status is mutable reporting state and finalizers can be removed | Authenticated signed candidate plus node readback/probe/CAS; status is a bounded projection only (§12, Appendix A.11.7) |
| CRD deletion erases active node policy | API or Control outage could remove protection without runtime-lifetime proof | Publish complete desired inventory, retain live local protection, and remove stored membership only after runtime inventory proves the lifetime is absent (§12, §32) |
| Compose overlapping base-policy CRDs by priority, creation order, or “deny wins” | The result depends on mutable metadata or an incomplete conflict rule and can create two policy owners for one workload | Version 1 rejects more than one policy match for one Pod. A bounded exception can change only a named file grant in that one base policy. A later composition model must define one closed exact-cell compiler (§11-12). |
| Two independent transition authorities | Role shorthand and explicit transition could disagree | Compiler lowers both to one table and rejects conflicts (§11-12) |
| Cgroup lookup before existing task label | Moving a task can escape policy | Task-first lookup everywhere (§13) |
| Prose specificity, YAML order, priority, or “deny wins” resolves source conflict | These rules are ambiguous before exact lowering | Expand exact cell; identical physical results merge; differing results need explicit signed override (§12) |
| Owner-local generation number, digest-only defaults, or cached final allow | Generation `42` can collide across profiles; digest/default without owner and state is incomplete; response can change | Portable generation plus node ref; every cell has explicit default; label never stores final allow (§12, Appendix A.1) |
| Rewrite one active generation in place or use “current socket owner” shorthand | Partial policy and passed/shared sockets break authority | Build a complete immutable generation, publish its binding pointer, and keep creator, current actor, peer relationship, and socket floor identity (§12, §19) |
| Migrate every live process in one workload-wide transaction | Cross-thread, socket, native-state, and reference coordination adds a global stop point | BPF migrates each process under its local transition guard at its next protected effect (§12) |
| Label birth generation must equal the published generation | Birth evidence and existing protected objects intentionally retain older valid generation references | Migrate the active process generation and validate each retained lifetime reference independently (§12) |
| Ad-hoc state/default lookup in generic hook | Missing cells can accidentally inherit allow | Exact decision key plus explicit default and required dynamic floors (§13) |
| Reusable inode or undefined mount generation grants a file effect | Inode is reused and namespace/mount topology changes object meaning | Use mount namespace generation + mount/fs/inode/version/live identity for positive file authority. A signed canonical path-tree `DENY` floor needs none of these child-object fields (§15, §17). |
| Projected-token rotation can wait for asynchronous userspace update | New object may be readable before classifier catches up | Classify synchronously before access, or deny until the exact object is bound (§17) |
| Process-local sensitive bit proves which bytes were published | The kernel does not know which input bytes caused a later output | Use the bit only to restrict that actor/native family; govern each IPC/output operation and make no byte-provenance claim (§18) |
| Old process-shared ABI sketch or task-label role cache is authoritative | Duplicated mutable authority diverges | One `ProcessSecurityStateV1` and one native authority state; label stores a reference only (§6, §18) |
| Load native authority state directly from task label | Process may move to a stricter/current state; label is immutable | Label -> current process -> current native state (§6, §13) |
| IPC dynamically adds members to a native authority domain | Independent roots retain distinct identities and permissions | Native creation shares native state; IPC uses a relationship rule and never changes membership (§18) |
| Join only on explicit `CLONE_VM/FILES/FS` | IPC and descriptor passing are not process creation | Do not join. Check the current actor and channel; use exact peers for sockets, but never invent one for pipes (§18) |
| “No authority laundering” across an allowed ordinary-byte channel | Linux sees the channel and bytes, not whether an application request asks a broader peer to act as a confused deputy | Guarantee only the declared communication; descriptor passing may be separate evidence, and application/provider authorization is required for request meaning (§4, §18) |
| Object taint proves arbitrary byte flow | Another task may read or write concurrently, and the kernel does not know message meaning | Keep object identity and direct effect evidence; deny the shared-object acquisition or connection-oriented relationship, or report byte provenance unsupported (§18) |
| Pre-resolve every listener before application code | Dynamic bind/reuse/redirect makes startup inventory incomplete | Resolve listener/recipient at connect/accept/delivery; deny unknown strict channel (§18-19) |
| Returning hook can undo process-memory effects | `process_vm_writev`, ptrace, or kernel copy may have occurred before a late return point | Use proven pre-copy hook or deny earlier actuator acquisition; otherwise observation only (§18, §21) |
| Seccomp authorizes `/proc/<target>/mem` by pathname | Seccomp does not resolve filesystem target identity | BPF/traditional LSM exact file/target; a future approved Seccomp syscall floor may add confinement (§17, §21) |
| Reuse a native authority domain for cross-entry IPC | It would silently merge unrelated processes and overstate what Linux can enforce | Keep domains separate; use `IpcRelationshipRuleV1` and exact channel state (§18) |
| Reclaim a socket/file merely because its creator exited | Kernel objects may survive through other references | Keep exact object/socket lifetime state independently of the native domain (§18-19) |
| Freeze, drain, and redirect live domains before IPC | Linux has no general atomic drain/merge transaction | This design is abandoned; apply the relationship decision at the actual operation (§18, Appendix A.14.3) |
| Merge positive or negative policy across IPC peers | Communication does not make two actors one security principal | Keep each actor's role and native restrictions; evaluate both endpoint identities through one relationship (§18) |
| `OBJECT_TAINT` after writing prevents `emptyDir` laundering | Inode state does not prove which bytes a reader consumed | Govern file access and communication; record descriptor passing separately without claiming byte or represented-object provenance (§18) |
| An allowed send proves bytes were delivered or identifies their origin | Admission, completion, packet delivery, and provider result are different facts | Record each physical result separately without a byte-provenance claim (§18, §25) |
| Detect a task weakening its installed Seccomp floor | Installed Seccomp filters are monotonic; there is no removal syscall | If the future surface is approved, prove installation before target user code; otherwise make no Seccomp-floor claim (§21, §31) |

### B.4 Evidence, graph, response, and incident statements

| Rejected or corrected idea | Why it is wrong | Replacement |
| --- | --- | --- |
| Scalar `sourceQualityAtLeast` | Identity, time, result, coverage, and causal proof fail independently | `ProofQualityV1` vector and package predicates (§22-23) |
| Store evidence, intake cursors, graph edges, or findings in policy CRDs | CRD update semantics and status bounds do not provide the immutable evidence/graph lifecycle, and policy RBAC would cross the trust boundary | Durable Control intake and graph stores with CRDs limited to policy desired state and bounded status (§22-23, §34) |
| Always connect a process directly to Kubernetes audit | Shared credential/time does not prove which process sent TLS request | Typed exact, shared-principal, temporal-context, or contradiction edges (§23) |
| Matching identifier creates any direct edge | IDs can be shared/reused and need provider-specific semantics | `ProviderEdgeContractV1` with join fields, direction, cardinality, time, and degradation (§23) |
| Bounded ancestor list alone controls future descendants | New child can appear after list is built | Response root/reference inherited at task creation plus reconciliation (§24) |
| Active hostile probes inside compromised production target | Probe may execute attacker-controlled code or change evidence | Readback and passive healthy watch; hostile probes run in isolated qualification fixtures (§24) |
| A successful write/send proves secret exfiltration | The operation does not prove which bytes or source it contained | Separate sensitive access, write/send completion, packet, and provider results (§18, §25) |
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
| A file read proves a later write/send, or is unrelated to it | Read and output are separate effects that may have a causal edge | Report both results and the strength of the edge (§17-18, §25) |

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

### B.6 Supersession and source boundaries

When a teaching example conflicts with a later correction, the correction must
name the retained statement, controlling contract, affected implementation
cards, fixtures, and forbidden contract IDs. Phase 0 lint checks that every
reference exists, every card declares its dependency, and no two controlling
records require different results for the same key. Human review decides when
two prose statements mean the same thing.

`CFG-V1-GOLDEN-002` replaces stale vector `CFG-V1-GOLDEN-001` and is generated
from one checked source. `SOURCE-BOUNDARY-001` remains the shared limit: Linux
cannot distinguish Git clone from push or provider verbs inside encrypted
same-destination TLS, and cannot revoke an already issued remote IAM session.
Use provider authorization/audit/response or deny the whole channel.

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
IPC-RELATIONSHIP-LOSS-002
NATIVE-STATE-REF-LIFETIME-001
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
HF-RESP-BLAST-RADIUS-003
ID-CGROUP-ESCAPE-001
ID-CLONE-CGROUP-002
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
IPC-RELATIONSHIP-ALLOW-003
IPC-RELATIONSHIP-UNMATCHED-005
IPC-PEER-RACE-004
IPC-ENDPOINT-RESTART-006
STATE-FORK-IPC-002
IPC-LOCAL-INET-008
FILE-MMAP-SHARED-011
STATE-PERSISTENT-FILE-LIFETIME-007
IPC-PROCESS-CHANNEL-009
IPC-ASYNC-UNSUPPORTED-010
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
claim. `WHEN_SECCOMP_SURFACE_ALLOCATED_AND_ADVERTISED` additionally requires
the deferred Seccomp compatibility and performance gate in Chapter 21 to pass;
it is false for Version 1.

| Criterion | Condition | Exact fixture IDs |
| ---: | --- | --- |
| 1 | `ALWAYS` | `BOOT-ADMISSION-001` |
| 1 | `WHEN_CLAIM_VECTOR_REFERENCES` | `NODE-FLOOR-EXCEPTION-002`, `XNODE-PRIVILEGED-POD-001` |
| 2 | `ALWAYS` | `ENTRY-BINDING-GAP-001`, `ENTRY-CONTAINERS-001`, `ENTRY-EPHEMERAL-001`, `ENTRY-EXEC-001`, `ENTRY-EXEC-002`, `ENTRY-EXTERNAL-AMBIGUITY-001`, `ENTRY-LOSS-001`, `ENTRY-MIGRATE-001`, `ENTRY-NETPROBE-001`, `ENTRY-POSTSTART-001`, `ENTRY-POSTSTART-002`, `ENTRY-PRESTOP-001`, `ENTRY-PROBE-001`, `ENTRY-PROBE-002`, `ENTRY-PROBE-IMPERSONATION-003`, `ENTRY-RESTART-001`, `ENTRY-REUSE-001`, `ENTRY-SLEEP-001`, `ENTRY-START-001`, `ENTRY-STOCK-HOOK-FAILURE-002` |
| 2 | `WHEN_CLAIM_VECTOR_REFERENCES` | `ADMIN-EXEC-APPROVAL-001` |
| 2 | `WHEN_SURFACE_ALLOCATED_AND_ADVERTISED` | `CHECKPOINT-CREATE-001`, `ENTRY-RESTORE-001`, `ENTRY-STREAM-001` |
| 3 | `ALWAYS` | `EXEC-COMMIT-STATE-001`, `ID-CGROUP-ESCAPE-001`, `ID-CLONE-CGROUP-002`, `ID-CREATOR-PARENT-007`, `ID-MOVED-PARENT-FORK-004`, `ID-MOVED-TASK-EXEC-005`, `ID-TASK-COORD-FINALIZE-006`, `IPC-ENDPOINT-RESTART-006`, `IPC-PEER-RACE-004`, `IPC-RELATIONSHIP-ALLOW-003`, `IPC-RELATIONSHIP-LOSS-002`, `IPC-RELATIONSHIP-UNMATCHED-005`, `NATIVE-STATE-REF-LIFETIME-001` |
| 4 | `ALWAYS` | `DEVICE-DERIVED-001`, `EXEC-CONCURRENT-002`, `FILE-CONTENT-RACE-002`, `FILE-IDENTITY-001`, `FILE-MMAP-001`, `FILE-MMAP-SHARED-011`, `FILE-NAMESPACE-001`, `FILE-SA-TOKEN-OPEN-001`, `FILE-VMA-SNAPSHOT-001`, `HF-LOCAL-001`, `HF-NET-001`, `IPC-ASYNC-UNSUPPORTED-010`, `IPC-LOCAL-INET-008`, `IPC-PROCESS-CHANNEL-009`, `MEM-EXEC-001`, `MEM-KERNEL-MAP-002`, `MOUNT-ATTR-001`, `MOUNT-CAS-002`, `MOUNT-PROPAGATION-003`, `MOUNT-SNAPSHOT-004`, `NET-ACCEPT-PASS-001`, `NET-DNS-EXFIL-001`, `NET-NS-PASS-001`, `NET-RECV-001`, `NET-REWRITE-001`, `NET-SOCKCTL-001`, `NET-SOCKET-LIFE-001`, `STATE-FORK-IPC-002`, `STATE-PERSISTENT-FILE-LIFETIME-007`, `STATE-THREAD-RACE-001` |
| 4 | `WHEN_SECCOMP_SURFACE_ALLOCATED_AND_ADVERTISED` | `SECCOMP-QUAL-001` |
| 4 | `WHEN_CLAIM_VECTOR_REFERENCES` | `HF-GRAN-CONNECTOR-DIRECT-001`, `HF-GRAN-DEAD-DROP-001`, `HF-GRAN-HOSTPATH-001`, `HF-GRAN-MESH-ROOT-001` |
| 5 | `ALWAYS` | `FILE-DELEGATED-EGRESS-001`, `FILE-FD-PASS-001`, `HF-004-RESULT-001`, `HF-011-READ-RESULT-001`, `NET-SHARED-RESPONSE-002` |
| 5 | `WHEN_CLAIM_VECTOR_REFERENCES` | `HF-GRAN-CI-BUILDRS-001`, `HF-GRAN-HOST-LOC-001`, `HF-GRAN-OUTSIDE-001` |
| 6 | `ALWAYS` | `EDGE-ARTIFACT-CONSUMER-005`, `EDGE-AWS-SHARED-001`, `EDGE-CONNECTOR-FORWARD-004`, `EDGE-GITHUB-SHARED-003`, `EDGE-K8S-SHARED-002`, `EDGE-MESSAGE-CONSUMER-006` |
| 6 | `WHEN_CLAIM_VECTOR_REFERENCES` | `HF-GRAN-AWS-SPLIT-001`, `HF-GRAN-CLUSTER-SHARED-001`, `HF-GRAN-GITHUB-TREE-PR-001`, `HF-GRAN-MESH-SOCKS-001` |
| 7 | `ALWAYS` | `HF-RESP-002`, `HF-RESP-BLAST-RADIUS-003` |
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

Independent Jailer (not Meta BpfJailer):

- [top-level license](../../../jailer/LICENSE)
- [task-local storage, pending enrollment, and task allocation](../../../jailer/bpfjailer-bpf/src/main.bpf.c)
- [dentry path-state matcher and cache invalidation](../../../jailer/bpfjailer-bpf/src/main.bpf.c)

Meta BpfJailer presentation only:

- [LPC 2025 deck](../../../BpfJailer%20LPC%202025.pdf) -- slides 16-21 are
  design evidence for the mount-aware component matcher in Chapter 15. This is
  not public source code and therefore is not a `SourceEvidenceClaimV1` range.

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
| Independent Jailer task storage, delayed PID enrollment, and task-allocation inheritance: `bpfjailer-bpf/src/main.bpf.c` | `BJ-CODE-001`, `002` |

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
| `KA-CODE-006` | LSM network code at `enforcer.bpf.c:415-648` mainly matches socket type/protocol; CIDR/port rules and NFLOG attribution are separate userspace/nftables paths. | Mithril evaluates exact current role/native state, socket provenance, peer relationship, and final destination itself. |
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

Independent Jailer claims:

| ID | Pinned observation | Mithril consequence |
| --- | --- | --- |
| `BJ-CODE-001` | `bpfjailer-bpf/src/main.bpf.c:23-31` declares `BPF_MAP_TYPE_TASK_STORAGE`; `:486-510` allocates child storage at `task_alloc` and copies the parent's process information. In the checked KubeArmor snapshot, no task-storage use occurs. In the checked Tetragon snapshot, the name occurs only in generated BTF, reader, or vendored ABI material--not in a live enforcement-program map declaration or task-storage helper call. This comparison is limited to these pinned snapshots. | Adopt task-local storage as the early task identity anchor. Mithril's label still requires its own `TaskLabelV1` lifecycle, identity, and fail-closed contracts; do not claim that no KubeArmor or Tetragon version can use task storage. |
| `BJ-CODE-002` | `main.bpf.c:58-64,466-483,515-526` accepts a userspace pending-enrollment record keyed by PID, then migrates it only when a later governed file hook executes. `task_alloc` returns allow when storage allocation fails (`:486-490`). | Do not use PID-delayed enrollment. A protected Mithril task receives its opaque task state at the early lifecycle boundary, and any protected-identity state failure follows the configured deny/unknown-floor contract. |

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
- [Tetragon process-exec argument observation](https://tetragon.io/docs/use-cases/process-lifecycle/process-execution/)
- [Tetragon in-kernel argument selectors](https://tetragon.io/docs/concepts/tracing-policy/selectors/)
- [Falco process-argument fields and truncation](https://falco.org/docs/reference/rules/supported-fields/)
- [OCI runtime lifecycle](https://specs.opencontainers.org/runtime-spec/runtime/)
- [OCI hook ordering](https://specs.opencontainers.org/runtime-spec/config/)
- [Containerd NRI integration and Seccomp-adjustment controls](https://containerd.io/docs/2.2/nri/)
- [Locally checked NRI `SetLinuxSeccompPolicy`](../../../tetragon/contrib/tetragon-rthooks/vendor/github.com/containerd/nri/pkg/api/adjustment.go)
- [Locally checked NRI `LinuxContainerAdjustment.seccomp_policy`](../../../tetragon/contrib/tetragon-rthooks/vendor/github.com/containerd/nri/pkg/api/api.proto)
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
