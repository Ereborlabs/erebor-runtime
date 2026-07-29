# Erebor Defender: Linux Enforcement, Correlation, and Response Engineering

Status: living product and technical research. This document approves no
implementation, deployment, dependency, or fork.

Related reading:

- [Earlier combined Runtime and Defender research](erebor-runtime-and-defender-learning.md)
- [Hugging Face Agent Intrusion: Published Live Action Stream](hugging-face-agent-intrusion-live-action-stream.md)
- [Hugging Face Agent Intrusion: Erebor Defender Implementation Analysis](hugging-face-agent-intrusion-analysis.md)

## Product boundary and terminology

Erebor Defender and Erebor Runtime are separate products:

- **Erebor Defender** owns the node security agent, Linux workload sensor and
  enforcer, evidence intake, coverage model, identity and causal graph,
  detections, investigation service, response authorization, and defensive
  connectors described in this document.
- **Erebor Runtime** governs agent/tool actions through execution Sessions and
  governed action surfaces. Defender does not require Runtime, does not create
  or own Runtime Sessions, and does not use Runtime policy objects as its
  Linux workload policy.
- **Container runtime** means infrastructure such as the OCI/CRI implementation
  that creates a container process. A Defender integration with containerd,
  CRI-O, `runc`, or an equivalent implementation is not an Erebor Runtime
  integration.

If Erebor Runtime is separately deployed on an asset, Defender may ingest its
evidence or request one of its typed defensive actions through an optional
adapter. That relationship is the same kind of product-to-product integration
as an EDR, SIEM, Kubernetes, or cloud connector. A Runtime Session ID never
replaces Defender's native task, process, cgroup, container, workload, or
provider identity.

## Deployment preservation is non-negotiable

Defender must protect the deployment that exists. Installing Defender may add
Defender-owned node/runtime integration, collectors, correlation services, and
approved enforcement programs. Baseline protection cannot require changes to
the protected application's code, harness, job/Pod/process topology,
controller manifests, mounted credentials, ServiceAccounts, RBAC, IAM, network
routes, or provider principals.

Defender distinguishes:

- **D — deployment-preserving capability:** observe, attribute, detect, or
  enforce an effect on existing processes, credentials, sockets, API requests,
  and provider identities;
- **H — operator hardening:** optional manifest, RBAC, IAM, admission, CNI,
  launch-template, or secret-distribution change; and
- **R — redesign:** optional parser/scanner, broker, split credential,
  per-operation principal, sidecar, supervisor, or scheduling change.

H/R work can be recommended, simulated, and verified after an operator adopts
it. It is never silently converted into a Defender prerequisite or credited as
an action Defender performed.

This is especially important for Kubernetes controllers. Their mounted
ServiceAccount token and API access can be legitimate and necessary. Defender
must allow the signed controller role's existing behavior, deny or flag access
by an unexpected child/process role, compare actual API verbs/resources/scopes
with authoritative audit, and state the same-process limit. If injected code
uses the controller's existing process, client, TLS connection, and token,
Linux cannot distinguish it from legitimate controller code; the API audit
event is the first semantic fact. A file denial also cannot revoke token bytes
already read into memory or inherited across a permitted fork.

## The conclusion

Tetragon and Falco are useful implementations to study and optional sources to
integrate. They are not Erebor Defender's architectural boundary.

Defender must own the guarantees described here. For Linux workloads that
means the Defender node plane builds the real fork/exec task graph, inherits
policy state before a child runs, and—only in an approved enforce profile—
synchronously denies exec/file/socket/device/privilege effects absent from the
existing role while exposing exact response actuators. It can implement that
plane with CO-RE eBPF tracepoints, BPF task/socket storage, BPF LSM, cgroup BPF,
container-runtime hooks, authoritative Kubernetes/provider audit and response
connectors, plus optional H-class seccomp, mount-namespace, and Landlock
hardening.

Tetragon may populate compatible observations or actuate a supported hook.
Falco may supply independent rule detections and plugin events. A gap in
either product is not a Defender limitation when Linux or another authoritative
control point can implement the requirement.

```text
Defender node planes: independent local task/exec graphs + Linux enforcement
Optional sources:   Tetragon / Falco / CNI / existing EDR and audit systems
Authoritative APIs: Kubernetes / cloud / identity / mesh / source control
                                  │
                                  ▼
Erebor Defender: evidence integrity + typed multi-node causal graph
                 + scoped investigation tools + approval-gated action
```

The fundamental limits are narrower: Linux cannot attribute two concurrent
logical jobs inside one interpreter without some work-item identity, and
packet metadata cannot distinguish two operations inside the same opaque TLS
channel. Defender states those limits and controls the next available
file/socket/credential/provider boundary; it does not redesign the workload or
pretend a product gap is fundamental.

## Technology-first implementation map

The design starts from the physical effect that must be observed or denied,
then selects the authoritative decision point. It does not start from a
vendor's current rule language or event schema.

| Required guarantee | Primary technology | What Defender builds |
| --- | --- | --- |
| identify the exact executing subject | `task_alloc`, scheduler fork/exec/exit tracepoints, task-local BPF storage, cgroup and namespace identity | Defender-native task/thread, process, execution-image, and bounded ancestor-lineage graph |
| preserve causal lineage across nodes, clusters, and providers | authenticated node/cluster identities; Kubernetes audit IDs, object UIDs, owner references, bindings, and CRI identity; credential leases; connector/request/message IDs; immutable artifact digests | immutable typed causal edges and versioned distributed-lineage views over independently proven node-local trees |
| deny an unexpected executable before it runs | BPF LSM `bprm_check_security`, immutable mount/inode/content identity, mount namespace | signed source-role → executable → resulting-role rules returning `-EACCES` |
| deny an in-process file, code-loading, or credential effect that the existing process role does not need | BPF LSM file/inode/mmap hooks; optional mount namespace and Landlock floors | role/object/access rules that allow existing controller credential use, deny unexpected process roles, and do not rely on a new process appearing |
| deny prohibited egress without decrypting TLS | BPF LSM socket hooks, cgroup `connect4/6` and UDP `sendmsg4/6`, socket storage, cgroup-skb or TC | per-process-role destination policy and packet fences; required existing API/IMDS access remains allowed and operation semantics come from server/provider audit |
| deny device and kernel escape surfaces | cgroup-device BPF and ioctl/file/security LSM hooks; optional H-class `/dev` and seccomp floors | role-specific device, privilege-transition, ptrace, BPF, perf, mount, and module profiles over the existing workload |
| stop a compromised process lineage | in-kernel response-root map checked at protected hooks, socket-cookie fence, pidfd, cgroup v2 egress/freeze | scoped progression from process lineage to socket set to cgroup, with explicit blast radius and postcondition checks |
| prove what was and was not observed | ring buffers, loss counters, boot/source sequence, append-only local spool, capability probes | raw evidence, coverage intervals, gap detection, policy-generation provenance, and replayable findings |
| correlate local compromise with remote effects | Kubernetes audit, cloud/IdP/mesh/VCS audit, credential lease IDs, provider request/resource IDs | deterministic typed joins with visible join strength, fan-out, gaps, uncertainty, tenant/resource binding, and late-evidence versioning |
| perform remote containment safely | narrow node/Kubernetes/cloud/IdP/VCS connector credentials, typed action APIs, approvals, idempotency, expiry | coordinated but independently authorized physical responses per exact lineage member, including controller reconciliation and watch-window verification |

The engineering rule is:

1. if an imported tool lacks a hook, field, rule, or actuator that the
   underlying Linux or provider decision point can supply, Defender implements
   it or integrates the authoritative API;
2. if the running kernel lacks the required decision point, Defender requires a
   supported kernel, a proved built-in LSM equivalent, or reports a reduced
   enforcement tier; and
3. only missing information at every available authoritative boundary is a
   fundamental limit.

This preserves the deployed application architecture. Required integration
belongs in Defender's node image, OCI/CRI path, evidence collectors, and
provider connectors—not in the worker, agent harness, credentials, or
logical-job model. Kubernetes admission, RBAC/IAM changes, CNI policy, and
launch-time mount/Landlock/seccomp hardening are separately classified H work
when they alter the protected deployment's effective behavior.

## Non-normative implementation studies

The following records the major technologies used by the checked-out projects
so Defender can reuse code or compare behavior intelligently. It is not the
Defender architecture. Exact versions and support matrices change, so an
integration must collect the deployed component's capability report rather
than rely on this document alone.

### Tetragon: Go control plane around Linux eBPF sensors

| Layer | Technologies and role | Defender implication |
| --- | --- | --- |
| Agent and policy runtime | A Go daemon and `tetra` CLI; the local source uses the `cilium/ebpf` Go library to inspect features and load/attach BPF programs, links, maps, and BTF. | The Defender adapter can use Tetragon's typed gRPC API, but must separately record which kernel features actually admitted each policy. |
| Kernel programs | Linux eBPF programs, built with Clang for target architectures. Tetragon policies cover kprobes, tracepoints, uprobes, LSM hooks, USDTs, and fentry-style hooks where supported. | It can observe or act close to a kernel object, which is stronger evidence than parsing a user-space log, but hook coverage is never universal. |
| Kernel state and event path | BPF maps hold policy/filter state; kernel-to-user event delivery uses bounded kernel buffers. Tetragon detects BTF, helper, attachment, and event-buffer capability differences. | Evidence ingestion must include buffer/drop/health state. A received event is useful; an absent event is not a blanket negative assertion. |
| Policy language | YAML `TracingPolicy`/`TracingPolicyNamespaced` resources contain hook specifications, selectors, actions, workload scope, and options. The policy is lowered to kernel sensors and maps. | Do not let a model submit raw YAML. Defender should own a smaller, typed detection/containment package and compile or approve the exact Tetragon policy. |
| Kubernetes integration | Custom resources and a Go controller-runtime operator distribute policies. The operator also maintains `PodInfo` identity data that helps associate network activity with Kubernetes workloads. | The operator and its Kubernetes API permission are high-value control-plane assets. Defender should treat policy changes as privileged evidence and guard against tenant/namespace confusion. |
| Remote API | Protocol Buffers and gRPC serve events, health, version/info, policy lifecycle, sensor operations, and configuration. The API can use a Unix-domain socket for local IPC or optional TCP protected by TLS/mTLS. | A Defender gRPC collector is feasible, but event streaming and policy mutation must use different credentials and authorization paths. Collecting events must not imply permission to add a policy. |
| Durability and recovery | BPF programs can be pinned in bpffs; persistent gRPC policy support keeps desired state and can retain prior enforcement while replacement programs load. | Persisted local enforcement can outlive an agent outage, but observation can still be missing. Defender must model that interval as `enforcing-no-observation`. |
| Operations | Helm/DaemonSet deployment, Prometheus health/event metrics, and a Kubernetes operator. | Metrics and policy inventory are inputs to Defender coverage, not just SRE dashboards. |

#### Tetragon's kernel technologies in plain terms

- **eBPF** is verified code loaded into the Linux kernel. It can inspect
  selected kernel events with less user/kernel crossing than a user-space
  tracer. The verifier and feature availability constrain what may load.
- **BTF** is kernel type metadata. It helps an eBPF loader understand the
  running kernel's data structures and test whether a program can attach.
- **Kprobes, tracepoints, and fentry** observe kernel execution at different
  attachment points. They are powerful but kernel/version dependent.
- **Uprobes and USDTs** attach to user-space program functions or statically
  defined user-space probes. They can enrich an investigation, but should not
  be treated as a universal process-enforcement boundary.
- **LSM hooks** are Linux security decision points. When the required hook and
  BPF action are supported, they are a better fit for a local security decision
  than observing a syscall after the fact.
- **BPF maps and bpffs pinning** let the agent share policy state with kernel
  programs and preserve selected objects across process restart. They are not a
  durable Defender evidence database.

Tetragon's local source also shows explicit feature probes and tests around
signal and override helpers. This is the correct operational stance: the
Defender UI must never advertise an enforcement mechanism on an asset where the
kernel cannot provide it.

### Falco: C++ detection engine with pluggable event acquisition

| Layer | Technologies and role | Defender implication |
| --- | --- | --- |
| Detection engine | A C++ `falco_engine` built around the `libsinsp`/`libscap` ecosystem. The local source parses rules, builds filter abstract syntax trees, expands macros/lists, and indexes rules by event type/source. | Falco is an efficient source-specific rule evaluator. Treat its alert as a versioned derived fact, retaining the raw alert and rule/content provenance. |
| Kernel event source | The current default is Falco's modern eBPF driver: an embedded CO-RE eBPF probe using modern BPF features such as the BPF ring buffer. A kernel-module path remains a compatibility option for environments that cannot run the modern probe. | Driver choice, kernel support, privileges, verifier failures, and drop counters change coverage. Defender needs them in the asset capability and coverage model. |
| Rule content | YAML rules use conditions, output templates, priority, tags, macros, lists, exceptions, and source-specific fields. Engine and plugin compatibility can be declared in the rule file. | Borrow the package/version/test discipline, but do not make alert priority an action authorization or make the Falco DSL Defender's universal language. |
| Plugin framework | Dynamically loaded shared libraries (`.so` on Unix) use a C ABI. They can source events, extract fields, parse event payloads, or inject asynchronous events. The official plugin architecture supports implementations in any language that exposes the required C functions. | Plugins can bring Kubernetes audit, cloud, identity, or other evidence. They are executable code in the sensor trust boundary: load only reviewed, version-pinned plugins and record their provenance. |
| Event processing | Each event source has an isolated processing thread and its own rules. Falco does not correlate events across sources. | Preserve source-specific fidelity at intake, then perform cross-source correlation only in Defender's evidence graph. |
| Alert delivery | Falco formats alerts as structured output and supports channels including stdout, files, syslog, HTTP, and program output; it also has queue, buffering, timeout, and drop configuration. | The Defender adapter needs authenticated intake, source/boot identity, replay protection where available, delivery-health telemetry, and raw-envelope retention. |
| Operations | Falco supports packages, containers, and Helm deployment, plus web/metrics configuration and external alert routers such as Falcosidekick. | It can coexist with existing SOC pipelines. Defender should integrate as a consumer first, not become an unbounded alert-routing replacement. |

#### Falco's kernel-driver choice matters

Falco's two current practical kernel collection paths have different tradeoffs:

- **Modern eBPF / CO-RE:** the probe is bundled with Falco and uses a compiled
  eBPF object designed to adapt to compatible kernels through type/relocation
  metadata. It avoids building or downloading a per-kernel module, but still
  needs the right kernel features, privileges, BPF syscall access, memory-lock
  allowance, and verifier acceptance.
- **Kernel module:** provides wider compatibility for some older or unusual
  environments, but it is a kernel module with a heavier installation, signing,
  privilege, and upgrade burden.

Neither choice is “just a log source.” It can see sensitive process and system
behavior, so Defender's deployment review must consider kernel lockdown,
container privileges, host mounts, driver provenance, and the blast radius of a
compromised sensor.

### Shared technology lessons

| Concern | Tetragon | Falco | Defender decision |
| --- | --- | --- | --- |
| Kernel privilege | Loads eBPF programs and may change local behavior. | Loads an eBPF probe or kernel module for syscall collection. | Treat each node agent as privileged security infrastructure; isolate its credentials and upgrade path. |
| Content supply chain | YAML policy can change observation/enforcement behavior. | Rules and dynamic plugins can change detection behavior. | Sign/version detection packages, verify compatibility, and retain content hashes with findings. |
| Event transport | gRPC, JSON/log export, bounded kernel buffers. | Multiple output channels and bounded queues/buffers. | Track source health and loss explicitly; do not use alert absence as proof. |
| Kubernetes control | Operator/CRDs and workload identity mapping. | Helm plus plugins/metadata integrations. | Do not give a generic Defender client cluster-admin or policy-writing permission. Separate read, deploy, and response roles. |
| Evidence semantics | Can observe and sometimes enforce locally. | Detects and reports. | A source event, a local denial, an alert, and a remote action result remain different evidence types. |

### What Defender may reuse and what it must own

Reuse is an implementation decision after the contract is defined:

- Tetragon can be an endpoint event/policy-health adapter where its current
  hooks and identity fields satisfy a package.
- Falco can be an existing detection/plugin adapter where an organization
  already operates it.
- CNI, Prometheus, cloud audit, and other mature sources can contribute native
  facts and health.
- Defender implements a missing sensor or actuator when the underlying kernel or
  authoritative API can supply the required decision.

Defender owns:

- a tenant-safe identity graph spanning native task/thread, process, exec,
  workload, cloud principal, artifact, and provider audit resource;
- the Linux task/exec/effect and pre-effect enforcement contract for protected
  workloads, even when third-party software implements some hooks;
- immutable raw evidence, normalized observations, coverage intervals, and
  reproducible findings;
- cross-source correlation and the separation of fact from hypothesis;
- action authorization, approvals, idempotency, expiry, rollback, and
  postcondition verification; and
- a model-facing tool boundary that cannot turn attacker-controlled evidence
  into direct kernel/sensor, Kubernetes, cloud, or identity authority.

## Defender's product boundary

Erebor Defender is a separate future project. It is not an agent execution
harness and does not create an interactive execution environment for the
defender. It is a service used by humans, GLM, SIEM, and other defensive tools
to investigate and request a narrow action on infrastructure the defender
organization owns.

The Defender service authenticates the caller, checks tenant/resource scope and
approval policy, invokes a defender-owned connector, and records the result.
The client model never becomes the enforcement or authority boundary.

```text
Defender node + optional sensors + cloud/identity/control-plane audit
                              │ raw evidence and coverage
                              ▼
                      Erebor Defender service
   intake → actual/expected graph → correlation → authorization
                              │
                              ▼
 process/cgroup + Kubernetes + cloud/IdP/VCS defensive connectors
                              │
                              ▼
               verified result and immutable response record
```

The source deployment is part of the defender's estate. A Defender deployment
on Hugging Face assets has no authority over an unrelated OpenAI evaluation
workload.

## Kernel decision-point and sensor engineering

[Tetragon](https://tetragon.io/) lets policies choose kernel hook points and
filter on process, file, socket, namespace, capability, and Kubernetes
workload facts. A matching policy can emit an event or perform a configured
action. Policies can be managed through Kubernetes resources, gRPC, or startup
configuration.

| Tetragon role | Defender use | Required caution |
| --- | --- | --- |
| Endpoint sensor | Stream process, file, socket, namespace, and capability observations with workload identity. | Keep the exact policy, sensor version, source health, and capability report with the evidence. |
| High-confidence tripwire | Detect an exploit primitive, such as unexpected namespace creation, credential access, sensitive mutation, or prohibited connection. | Filter intentionally. Missing events may mean a gap, not that behavior did not occur. |
| Containment actuator | Apply an approved, temporary restriction to a selected local workload. | Record the exact mechanism, scope, expiry, and postcondition. |

### In-kernel filtering is a data-quality feature

Tetragon's in-kernel filtering reduces event volume before it reaches a fleet
collector. For Defender this is also an evidence-design lesson: collect the
facts that answer a defender question, not every syscall.

For a remote-code dataset worker, a detection package may request process
lineage; execution; selected credential and process-control file access; namespace and
capability changes; and connections to metadata, cluster-control, or unexpected
private destinations. Defender must retain the policy ID and configuration that
made an observation possible. Otherwise, an absence cannot be interpreted.

### A killed process is not necessarily a prevented effect

Tetragon distinguishes two enforcement meanings:

- A signal such as `SIGKILL` terminates the process, but an operation already
  in progress, such as a write, can still complete.
- An override return value prevents a supported call from executing and returns
  an error instead. This is the relevant mechanism if the claim is that the
  operation itself was denied.

Defender's action vocabulary must preserve this distinction.

```text
response: fence workload after sensitive write attempt

process killed      → process stopped; write result is unknown
call overridden     → supported operation returned denial; effect was denied
credential revoked  → new use should fail; existing connections need checking
```

Every result needs a postcondition probe. If the physical outcome cannot be
proved, Defender records `unknown`, not `contained`.

### Monitor-first rollout is a reusable idea

Tetragon supports monitoring and enforcement policy modes. That suggests the
following Defender content lifecycle:

```text
signed package → monitor deployment → evidence replay and review
       │                                      │
       └──────────────── no ──────────────────┘
                                              ▼
                  narrow approval → time-bounded containment → verify → expire
```

Defender should adapt this lifecycle rather than expose raw Tetragon policy as a
general user-facing language. A Defender package additionally needs tenant and
resource authorization, response class, expiry, rollback, evidence expectations,
and a verified postcondition.

### Prevention continuity and evidence continuity are different

Tetragon can pin an enforcement policy so it continues while the Tetragon agent
is down. Its documentation also says no events are received during that outage.
This gives Defender a vital rule: it needs a first-class coverage state.

| Coverage state | Meaning | Permitted claim |
| --- | --- | --- |
| `observing` | Sensor and evidence pipeline are healthy for the policy scope. | The expected stream was available, within documented limits. |
| `enforcing-no-observation` | Local rule continued, but observations could not arrive. | The rule persisted; no complete history can be claimed. |
| `degraded` | Drops, backlog, source error, or identity-resolution failure occurred. | Findings carry reduced confidence. |
| `uncovered` | The sensor/policy was absent or untrusted. | No negative conclusion is permitted. |

### Capability variance must be visible

Tetragon's source and tests expose feature variance: hook availability, signals,
override helpers, and modified-return behavior vary by kernel and deployment.
Defender should maintain an asset capability inventory:

```text
asset class → kernel/build → Tetragon version → usable hook/action matrix
            → installed policy version → coverage health → allowed actuators
```

The response tool can then say, “this node can only terminate the process, so
the write result is unknown,” rather than presenting a false universal control.

## Detection-engine and event-pipeline engineering

[Falco](https://falco.org/) evaluates event streams against rules and emits
structured alerts. Its native syscall source can be extended by plugins, such
as Kubernetes Audit, AWS CloudTrail, and Okta sources. Rules are associated
with one source; Falco does not correlate across sources.

| Falco capability | Defender use | Defender responsibility |
| --- | --- | --- |
| Rules, macros, lists, exceptions, tags, priorities, and output fields. | Ingest mature detection content while retaining rule provenance. | A rule match is a signal, not a full attack story or proof an effect was prevented. |
| Plugins and typed source fields. | Use existing local, cloud, and identity telemetry without changing the protected workload or Defender node plane. | Track source schema, plugin version, source trust, and delivery health. |
| JSON, HTTP, program, file, syslog, and other outputs. | Deliver alert envelopes to Defender intake. | An alert output is not a durable ledger and no alert is not a negative result. |
| First/all rule matching configuration. | Tune operational signal and noise. | Preserve supporting/conflicting predicate matches rather than hiding context. |

### Detection packages, not scattered alert queries

Falco suggests a good content discipline. A Defender detection package
could include:

- source adapter and supported schema/plugin versions;
- predicates that create named facts or findings;
- technique, asset, owner, confidence, and response-class tags;
- a raw-event replay corpus and expected derived findings;
- required sensor capabilities and an explicit unsupported state;
- advisory severity, never a direct authorization decision; and
- proposed response intents with evidence and approval requirements.

Do not make Falco's language Defender's public detection-policy language.
Defender needs cross-source joins, causal evidence, capability checks, response
authorization, and lifecycle semantics beyond an individual rule match.

### Cross-source correlation is Defender's responsibility

A serious incident crosses sources:

```text
untrusted artifact → Tetragon process execution
        │
credential-file access → Tetragon/Falco syscall evidence
        │
cloud role use → CloudTrail evidence
        │
privileged workload/policy change → Kubernetes audit evidence
```

Defender can correlate these through stable resource identity, time windows,
parent process/workload identity, credential lease IDs, network-flow identity,
and provider audit IDs. It must retain uncertainty: events that are merely
close in time are a hypothesis, not proof of causality.

### Alert delivery health must become evidence health

Falco has output queues, buffering, channels, and drop/timeout configuration.
Direct Falco HTTP output does not by itself give Defender a durable,
gap-detectable event stream. The reference adapter therefore runs a local
collector beside Falco. Falco posts structured JSON to the collector's
loopback-only HTTP endpoint; the collector appends each accepted body to a
disk-backed write-ahead log before returning success, assigns a monotonic
sequence within one collector boot, and forwards batches to Defender over mTLS.

The corresponding Falco settings in the checked-out configuration surface are:

```yaml
json_output: true
json_include_output_fields_property: true
json_include_tags_property: true
buffered_outputs: false
http_output:
  enabled: true
  url: "http://127.0.0.1:2802/v1/falco"
  keep_alive: true
```

The localhost handoff is not a complete delivery guarantee. Falco can still
drop or fail an alert before the collector commits it. Falco output-queue,
timeout, and drop health therefore remains part of coverage.

The forwarded record is:

```text
FalcoIntakeRecord {
  tenant_id: UUID
  asset_id: UUID
  collector_instance_id: UUID
  collector_boot_id: UUID
  collector_sequence: u64
  falco_hostname: String
  falco_version: SemVer
  event_time: Timestamp
  received_from_falco_at: Timestamp
  rule: String
  priority: String
  source: String
  tags: [String]
  output_fields: Map<String, JSONScalar>
  ruleset_artifact_digest: SHA256
  plugin_versions: Map<String, SemVer>
  raw_json: Bytes
}
```

The intake API accepts a batch only when the client certificate is bound to the
record's tenant and asset. Its unique key is:

```text
(tenant_id, collector_instance_id, collector_boot_id, collector_sequence)
```

On retry it returns the prior acknowledgement. A sequence gap immediately
closes the source's healthy `CoverageInterval`; it is not repaired by receiving
a later event. The collector retains its local write-ahead segment until
Defender acknowledges the highest contiguous sequence.

Falco itself may not supply a stable source-event ID. Defender must not invent
exactly-once semantics by hashing only the formatted alert: two legitimate
matches can have identical JSON. The collector sequence is the delivery
identity; the immutable raw JSON and ruleset digest establish alert provenance.

Falco metrics, rule-load status, plugin-open status, output drops, collector
queue depth, last acknowledged sequence, and clock error become coverage
inputs. If the collector restarts without its prior write-ahead state, the next
interval begins `degraded` with reason `collector_sequence_discontinuity`.

## Defender-owned Linux mechanism

Protected workloads do not need an SDK, one job per Pod, or a harness change.
In explicitly approved enforce-from-start mode, the node/container-runtime
path applies a signed profile before the existing container process executes:

```text
CRI/OCI implementation owns namespace, mount, cgroup, and init-task creation
  → runtime holds the container in OCI created state; user program has not run
  → runtime/shim gives authenticated Pod/container/cgroup/init identity
    to the Defender binder
  → Defender installs and verifies the cgroup/profile generation and root label
  → runtime accepts the transaction-bound acknowledgement, completes the
    deployment's configured child setup, and executes the unchanged worker
```

This is a cross-component admission handoff, not Defender reimplementing
container construction. The runtime owns the container lifecycle and the
Defender binder owns only identity resolution, policy binding, root labeling,
and verification. A standard `startContainer` hook can provide a pre-exec
failure gate, but a runtime/shim integration is still needed when the contract
requires authenticated CRI identity. Applying a new Landlock/seccomp floor to
the actual container-init process is separately approved H work, not part of
the baseline handoff.

Observe mode emits this identity handoff without making Defender availability a
start dependency. Missing acknowledgement opens a coverage gap and may require
`bootstrapped` root identity. Only approved enforce mode blocks runtime start.

For already-running workloads, rollout starts observe-only and reconstructs
live tasks from a BPF task iterator plus `/proc` as explicitly `bootstrapped`
labels. It never claims to have observed creation edges that predate
attachment. A transition that freezes the cgroup to establish a race-bounded
enforcement baseline is a simulated, operator-approved disruptive action; it
is not silently performed during Defender installation.

An ordinary external OCI hook can install node/cgroup state before the
user-specified process, but it cannot impose Landlock on another process.
If adopted, Landlock requires a container-runtime child setup step before exec
and cannot be retrofit to an arbitrary live worker. BPF LSM remains the
deployment-preserving dynamic per-task enforcement mechanism.

The in-kernel mechanism is:

| Requirement | Linux technology | Defender contract |
| --- | --- | --- |
| complete task lineage | BPF LSM `task_alloc`, `sched_process_fork`, `sched_process_exec`, `sched_process_exit` | task identity is a kernel-assigned cookie scoped by node boot and label epoch; TID/TGID/start-time are revalidation coordinates; fork-without-exec, exec-without-fork, and non-leader-thread exec remain distinct |
| policy before child runs | `BPF_MAP_TYPE_TASK_STORAGE` created/inherited at `task_alloc` | child inherits workload, role, ancestry vector, policy generation, and response state before user code |
| expected command/process graph | BPF LSM `bprm_check_security` plus immutable executable identity | absent source-role → executable → resulting-role edge returns `-EACCES` before the image runs |
| file effects | BPF LSM file/inode/path/mmap/descriptor hooks; optional H-class mount/Landlock floors | role controls kernel object classes, aliases, mappings, and passed descriptors; path string alone is not authority |
| network effects | BPF LSM socket hooks, cgroup `connect4/6` and UDP `sendmsg4/6`, socket storage, cgroup-skb/TC | process-context decisions for new operations; socket/cgroup packet decisions for established flows |
| devices | cgroup-device BPF and file/ioctl LSM; optional H-class `/dev`/seccomp floors | type/major/minor and approved ioctl/use class are independently enforced |
| privilege and escape | capability/credential/ptrace/mount/namespace/BPF/perf/module LSM hooks; existing seccomp/admission are evidence and changing them is H | effects absent from the signed existing role are denied; existing API authority remains server-side context |
| exact subtree restriction | every task label carries a bounded ancestor-lineage vector; protected hooks check an in-kernel response-root map | one root-map insertion restricts existing and future descendants on their next protected effect |
| broad emergency stop | socket-cookie packet fence, then cgroup egress/freeze | scope widens explicitly from task → socket set → container/Pod cgroup |

The expected graph is a signed `WorkloadProcessProfile` bound to immutable
image digest. OCI entrypoint, SBOM/file identity, reviewed configuration, and
monitor-mode observations generate a candidate; observations never
self-authorize. Each role has allowed thread/process creation rules, exec
edges, and file, network, device, privilege, namespace, and control-plane
effects. A forked child that never execs receives an inherited execution image
and restrictive child role, so its effects are still attributable and
enforceable.

This is why process lineage alone is insufficient. A Jinja payload can run
inside the approved Python process without a Linux exec. The next prohibited
file/socket/device/control-plane action is denied by that role's effect policy.
Conversely, `python → sh → curl` is stopped at the exec edge before the shell
or curl image runs.

External products may implement or corroborate a hook, but the table above is
the Defender contract. The detailed schemas, algorithms, failure states, and
target-kernel tests are in [Hugging Face Agent Intrusion: Erebor Defender
Implementation Analysis](hugging-face-agent-intrusion-analysis.md).

## An architecture to evaluate for Erebor Defender

This product shape separates raw telemetry, conclusions, and physical response.

```text
                    mechanism and provider plane
 ┌──────────────────────┬────────────────┬────────────────────┐
 │ Defender node plane  │ optional       │ cloud / IdP / K8s │
 │ task/LSM/cgroup      │ sensors / CNI  │ / mesh / VCS      │
 └──────────┬───────────┴───────┬────────┴──────────┬─────────┘
            └───────────────────┴──────┬────────────┘
                              ▼
                    evidence intake and coverage
                              │ verifies sender, preserves raw
                              ▼
             native identity + distributed causal-lineage graph
                              │ facts, typed joins, gaps, provenance
                              ▼
                   findings, cases, and attack hypotheses
                              │ no direct authority
                              ▼
                typed response request and approval evaluation
                              │ scope + expiry + postcondition
                              ▼
       Linux task/socket/cgroup / K8s / cloud / IdP / VCS actuators
                              │
                              ▼
                    verified outcome and immutable audit
```

### Minimum buildable service slice

The smallest implementation that can prove this architecture consists of:

| Component | Input | Durable output | Required failure behavior |
| --- | --- | --- | --- |
| Node capability and container binder | kernel config/BTF/helper probes, authenticated OCI/CRI created-state handoff, cgroup/container-runtime inventory, signed workload profile | node capability record, root task/process label, and exact cgroup/Pod/image/profile binding | observe mode records a coverage gap and does not block start; approved enforce-from-start mode withholds acknowledgement when identity, hook, label, or probe fails |
| Defender task/effect sensor-enforcer | `task_alloc`, fork/exec/exit, BPF LSM, cgroup/socket/device hooks, policy maps and link health | native task/exec graph events, synchronous decisions, map/link generations, loss counters | fail closed at protected hooks when task state is missing; distinguish enforcement continuity from event loss |
| Node evidence collector | ring-buffer records, monotonic clock anchors, policy/link health | local WAL, raw kernel envelopes, normalized task/effect observations | expose per-CPU gaps and WAL gaps; never call dropped evidence benign |
| Optional sensor collector | Tetragon/Falco/CNI/EDR native stream plus product health | source-native envelope and derived observation | source gaps degrade only dependent claims; optional source never owns the canonical graph |
| Kubernetes-audit collector | raw `audit.k8s.io/v1` events | immutable audit envelope and normalized API observation | never log Secret or TokenRequest response bodies; preserve audit ID |
| Kubernetes object-history collector | scoped list/watch over protected workload kinds | object UID/resource-version intervals, owner-reference edges, controller state, Pod bindings, and watch coverage | never collect Secret/ConfigMap bodies for lineage; relist after watch loss is bootstrapped and cannot fabricate missed transitions |
| Container-root binder | ordered OCI/CRI lifecycle plus authenticated node identity | Pod UID/sandbox/full-container/cgroup/image → node boot/label epoch/root task and process binding | sequence loss or reconstructed live state is an explicit gap; only enforce-from-start mode requires acknowledgement while the exact init task remains in OCI created state |
| Flow collector | Defender datapath, CNI, or equivalent flows, endpoint inventory, IP leases | flow envelope, socket/cgroup/Pod/IP history, verdict observation | refuse exact process attribution when only workload/IP evidence exists |
| Provider collector | AWS, mesh, connector, GitHub audit feeds | provider envelope with provider event/resource IDs | retain provider delivery delay and cursor gaps |
| Correlator | typed observations plus coverage intervals | immutable typed causal edges, versioned distributed-lineage views, and findings | deterministic replay; no cross-node process-parent edges; no response when required coverage or identity is ambiguous |
| Response controller | authorized typed request or distributed response plan | immutable per-target execution attempts and postcondition checks | each node/provider target is re-resolved and authorized; distributed result is verified only when every required branch verifies |

A practical reference persistence layout is:

```text
object store
  raw/<tenant>/<source>/<date>/<envelope-id>
      exact source bytes; write-once retention policy

transactional database
  source_envelopes       primary key envelope_id
  observations           index (tenant_id, package_state_key, occurred_at)
  causal_edges           immutable typed edge, proof class, source observations
  lineage_views          versioned members, branches, gaps, and coverage refs
  coverage_intervals     non-overlapping per asset/source/policy
  finding_versions       unique (finding_id, version)
  deployment_risk_findings
                          existing authority/topology evidence and residual risk
  hardening_proposals    H/R proposal, owner, compatibility risk, state,
                          simulation, and verification evidence
  response_requests      unique idempotency_key
  response_executions    append-only attempts and verification results
```

The database transaction that inserts a normalized observation also records
the raw object URI and hash. An observation whose raw object is missing is
invalid and cannot enter correlation. The correlator writes a finding and its
observation references in one transaction. The response worker reads only
authorized `ResponseRequest` rows; it cannot consume a model-generated string
or Falco priority as an instruction.

The concrete dataset-worker package, source mappings, actuator requests, and
acceptance suite are specified in [Hugging Face Agent Intrusion: Erebor
Defender Implementation Analysis](hugging-face-agent-intrusion-analysis.md).

### Do not collapse these evidence objects

| Object | Meaning | Authority and lifecycle |
| --- | --- | --- |
| `SourceEnvelope` | Exact source payload plus sender and receipt metadata. | Immutable after intake; no conclusion implied. |
| `Observation` | Normalized source-attributed statement, such as process X opened file Y. | References raw data and schema version. |
| `CoverageInterval` | What a source/policy could see for an asset and its health. | Prevents false negative claims. |
| `CausalEdge` | One typed transition between exact subjects, with join fields, evidence, proof class, gaps, and coverage. | Immutable; a remote execution is never encoded as a process-parent edge. |
| `DistributedLineageView` | Versioned traversal of node-local trees and resource/provider subjects from one root. | Derived and recomputable; late evidence creates a new version and cannot authorize a kernel action by itself. |
| `Finding` | Versioned detection result over observations. | Recomputable; carries predicate/content version and confidence. |
| `DeploymentRiskFinding` | Evidence that existing credentials, RBAC/IAM, routes, admission, or topology enable an attack path. | Reports the deployed truth; does not claim Defender changed it. |
| `HardeningProposal` | Typed H/R recommendation with owner, affected assets, compatibility risk, simulation, and verification. | `proposed` is not `executed`; only authoritative later evidence can mark it observed applied. |
| `Case` | Investigation view linking findings, assets, hypotheses, and decisions. | Mutable workflow; cannot rewrite evidence. |
| `ResponseRequest` | Proposed state change with actor, target, reason, expiry, and postcondition. | Authorization-checked. |
| `ResponseExecution` | Connector request/result, verification, rollback, and final known/unknown state. | Immutable audit; only this claims action occurred. |

This permits a GLM to investigate and summarize without allowing a
model-generated sentence to mutate evidence or create authority.

## Correlation: turn source signals into attributable causal evidence

Correlation is a Defender-owned service, not a sensor rule. The Defender node
sensor/enforcer, optional third-party sensors, Kubernetes, cloud, identity,
DNS, and flow systems each report partial facts. Defender preserves those
facts and joins them into a reviewable explanation of **which task did what,
through which identity, to which resource, and what happened next**.

It should not claim that two events are causally related merely because they
are close in time. A causal path needs named join keys, an explicit time
relationship, provenance, and a confidence explanation. When those are absent,
the product should show an investigation hypothesis rather than a fact.

```text
Defender node / optional sensors / K8s + cloud audit / DNS + flow
                              │
                              ▼
                   source envelope and coverage intake
                   │ authenticates sender; retains raw payload
                   ▼
              normalized observations with stable identities
                   │ process, workload, credential, resource, time
                   ▼
                     identity and causality graph
                   │ joins, paths, confidence, uncertainty
                   ▼
                  versioned findings and investigation cases
                   │ no direct authority
                   ▼
               typed response request and approval evaluation
```

### The identity graph is the hard part

An observation such as “`curl` ran” has almost no operational meaning alone.
Defender resolves it, while the workload exists, into both a native task tree
and an execution/effect graph:

```text
node boot ID + label epoch + kernel-assigned task cookie
  → exact TaskInstance/thread
  → kernel-assigned process-lineage ID
  → ProcessInstance and parent ProcessInstance
  → ExecInstance and source-role → resulting-role edge
  → inherited process profile and role
  → file/socket/device/security effects
  → cgroup and namespace membership at effect time
  → container ID and immutable image digest
  → pod UID, namespace, workload, and cluster
  → Kubernetes service account and workload identity
  → cloud role / credential lease
```

The same approach applies to resources:

```text
socket tuple / network namespace
  → DNS query and resolved destination, if observed
  → IP, service, private endpoint, or metadata endpoint
  → cloud API or SaaS resource, when provider audit can prove it
```

The stable task/thread key is `(node_boot_id, label_epoch, task_cookie)`. The
containing process/thread-group key is `(node_boot_id, label_epoch,
process_lineage_id)`. The node allocates the cookies in `task_alloc`, stores
them in task-local storage, and retains the process-lineage ID across exec.
Host TID/TGID/start-boottime remain time-bounded native coordinates used to
find and revalidate the live kernel object, not durable graph identity. This
survives Linux de-threading when a non-leader thread execs and assumes the
TGID. `CLONE_THREAD` creates a task inside the same `ProcessInstance`;
fork-without-exec creates a child process; exec-without-fork creates a new
execution on the same process. The graph also uses container and Pod UIDs
rather than names, immutable image/artifact digests rather than tags,
credential lease or provider audit IDs, and connector-specific resource IDs.

“Does not belong to the process tree” is represented precisely:

- an actual child edge absent from the signed expected profile is
  `UnexpectedExecEdge`;
- an approved process performing an unapproved file, socket, device, privilege,
  or control-plane action is `Unexpected*Effect`; and
- an effect that cannot be joined to a live actual task is `OrphanEffect` or
  `LineageCoverageGap`, not automatic proof of compromise.

This graph does not require one job per Pod or an application job event. When
many logical jobs run inside the same interpreter, Linux can deny that
process's prohibited effect but cannot identify which logical job caused it.
Optional authenticated platform audit may add that context; Defender never
invents it.

The mapping is a derived, versioned fact. For example, a cloud audit event may
arrive after the Pod that used the role has gone away. Defender should retain
the identity evidence and state whether the link was direct (for example, a
credential lease ID) or inferred (for example, unique workload identity plus
time window).

### Native lineage is local; distributed lineage is causal

The native task/process graph never crosses a node. Its parent edges come only
from observed Linux fork/clone semantics under one authenticated node boot and
label epoch. When activity on one node causes work on another, Defender joins
the two independently proven native trees through explicit non-process
subjects:

```text
native ProcessInstance A on node 1
  → API request / credential use / connector call / message / artifact
  → authoritative resource or controller transition
  → Pod binding, remote request, message consumption, or artifact load
  → native ProcessInstance B on node 2
```

The durable edge records a typed source and target, event-time interval, proof
class (`direct`, `derived`, `contextual`, or `contradicted`), exact joining
fields, source observation IDs, coverage intervals, and missing proof. A
versioned `DistributedLineageView` records its root, members, causal edge IDs,
fan-out branches, gaps, contradictions, outside-authority subjects, and the
prior version it supersedes. Raw observations and edges remain immutable.

For Kubernetes, the complete path is:

```text
process/socket
  → auditID and authenticated API request
  → exact object UID
  → controller reconciliation + ownerReferences[].uid
  → exact Pod UID
  → scheduler binding / node assignment
  → OCI/CRI full container ID
  → node-local root task/process
```

Each arrow needs its own evidence. Names, labels, selectors, service-account
names, IPs, and timestamps are context, not durable joins. This matters because
object names can be reused, a ReplicaSet can acquire a matching Pod,
controllers can fan out and retry, Pod deletion can trigger replacement on
another node, and source IP can be shared or translated.

Other supported bridges follow the same rule:

- exact credential lease/access-key ID for credential use;
- authenticated source and destination request IDs for connector forwarding;
- broker message ID or stable partition/offset for queue delivery;
- immutable digest/revision for artifact production and loading; and
- receiver-side request/execution identity for a remote command.

A network flow proves communication, not that the receiver executed a command.
A mutable tag or filename proves neither artifact identity nor causation.
Missing audit, ownership, binding, container-start, receiver, or provider
evidence creates a named open branch. It is never skipped to make the graph
look complete.

The distributed lineage ID is a correlation handle, not an enforcement token.
To contain a remote Linux member, the response controller must ask that
member's authenticated node to re-resolve its cluster, node boot, label epoch,
Pod/container/cgroup binding, task/process identity, and pidfd coordinates.
This prevents a late or mistaken graph join from becoming ambient fleet-wide
kernel authority.

### Preserve raw facts; derive one common observation shape

Adapters should not overwrite a source's meaning. They retain a
`SourceEnvelope`, then emit an `Observation` with enough information for
cross-source joins:

```text
Observation {
  occurred_at,             // source event time, if supplied
  received_at,             // Defender receipt time
  source, source_instance, source_sequence,
  tenant_and_asset_binding,
  subject:
      process | workload | principal | API_request | controller
    | connector_invocation | queue_message | artifact_version,
  subject_identity_refs,
  resource:
      file | socket | DNS | credential | API | Kubernetes_object
    | container | provider_resource | queue_message | artifact | policy,
  causal_keys:
      audit/request/object/owner/binding/container IDs
    | credential lease/access-key ID
    | connector source/destination request IDs
    | broker message ID or partition/offset
    | immutable artifact digest/revision,
  action, result,
  raw_evidence_ref,
  coverage_interval_ref,
}
```

`occurred_at` and `received_at` must remain separate. Kernel events can carry
high-resolution local time; cloud audits can arrive late or in batches; agents
and nodes can have clock skew. The correlator therefore needs bounded
out-of-order handling, source sequence/cursor tracking where available, and
the ability to recompute a *new version* of a finding when late evidence
arrives. It never edits the original evidence or silently changes the prior
conclusion.

Every observation also references a `CoverageInterval`. An absent cloud audit
event or missing kernel event is only evidence of absence when Defender knows
that the relevant source, policy, transport, and asset binding were healthy at
that instant. Otherwise the conclusion is `unknown`, not “benign.”

### Build paths with ordered joins, not a giant unbounded graph query

The first implementation should use deterministic, bounded correlation
packages. Each package declares its required sources, stable join keys, time
windows, predicates, confidence conditions, and the possible response class.
The packages are replayed against raw event fixtures before rollout.

Join strength should be made visible, in roughly this order:

1. Direct native task/effect binding: same `TaskInstance`, exact socket/file
   object, or observed parent/child task edge.
2. Direct execution binding: approved or denied exec transition on that task.
3. Direct workload binding: matching cgroup, container ID, Pod UID, or
   immutable workload-controller instance; this is broader than a process
   edge.
4. Direct control-plane transition: audit/request ID → object UID →
   owner-reference/controller event → Pod UID → binding → CRI/container root.
   Each arrow remains separately reviewable.
5. Direct authority bridge: an exact credential lease, access-key/provider
   request ID, connector source/destination request pair, queue message ID, or
   immutable artifact digest.
6. Direct network binding: a socket cookie, connection tuple, or
   connection-tracking identity
   observed at both ends. This proves communication; receiver evidence is
   still required to claim remote execution.
7. Supporting context only: matching image tag, DNS name, IP range, object or
   principal name, label selector, or a narrow time window.

The last category can raise priority but should not by itself authorise
containment. A package should state whether it has an observed path, a strongly
supported inference, or a weak hypothesis.

For example, the package-cache compromise pattern is not “a proxy used the
network.” It is a multi-step path:

```text
untrusted package request
  → cache-proxy process
  → unexpected child shell / interpreter / client process
  → credential-file, metadata, or control-plane access attempt
  → cloud credential or API use attributable to that workload
```

The Defender node plane provides the required task lineage and selected
file/socket/device/security facts. Third-party sensors may add independent
detections. DNS/flow telemetry can establish a network path. Kubernetes and
cloud audit establish authoritative resource and credential effects. No single
source is assumed to prove the whole chain.

The resulting finding should be understandable without reading a rule engine:

```text
Finding: cache-proxy child process attempted credential escalation
Confidence: high
Observed path:
  proxy workload image sha256:…
  → native task T spawned /usr/bin/python3 (exec LSM + fork/exec evidence)
  → task T connected to metadata address (socket hook; denied)
  → role R was used by the workload identity (cloud audit)
Coverage:
  kernel sensor healthy; flow sensor healthy; cloud audit delivered 42 s late
Uncertainty:
  no direct proof that the metadata request returned a credential
```

This explains both why the finding is serious and what has *not* been proven.
It is materially safer than converting an alert severity into a broad response.

### Correlation produces an authorized request, not an imperative

The correlator may propose a narrow response only after it creates a finding.
It cannot issue a shell command, a Kubernetes request, a cloud API call, or a
kernel policy by itself. The response plane independently checks tenant,
target, actor, policy, approval, expiry, connector scope, and postcondition.

```text
high-confidence workload path
        │
        ├── Linux: restrict this exact process lineage and descendants
        ├── cgroup: freeze/fence this broader container boundary
        ├── Kubernetes: isolate this Pod or workload instance
        ├── identity provider: revoke this exact lease or binding
        ├── network: deny this workload's new egress path
        └── forensics: preserve process, connection, and audit evidence
```

Responses must distinguish a local, reversible containment from a shared,
high-blast-radius action. Fencing one compromised workload may be pre-approved
for a particular asset; rotating a shared production credential requires human
approval. Each execution records the requested scope, the connector result,
verification result, and any race it cannot close, such as existing network
connections.

### A GLM can assist investigation but cannot become the correlator

A GLM can turn a finding into a readable timeline, propose read-only graph
queries, group similar evidence, and draft a response request. It must receive
attacker-controlled logs, package metadata, and command lines as untrusted
content. It cannot convert text into an observation, alter a causal path,
create a response authorization, or obtain connector credentials.

That division is essential for a Defender used by humans and other agents:
the service retains the evidence, correlation rules, authorization checks, and
physical-response authority; its clients receive only scoped read and response
tools.

### Technical incident profile: untrusted Kubernetes worker

The July 2026 Hugging Face technical timeline is a concrete test of this
architecture. An untrusted dataset first disclosed local worker data and then
executed code inside a production Pod. The expansion came from credential
access, metadata/control-plane access, privileged workload creation, broad
secrets, mesh enrollment, a shared cluster connector, and source-control token
minting. The exact kernel mechanisms, graph schema, package state machines,
actuator requests, action mapping, and 68-test acceptance suite are in
[Hugging Face Agent Intrusion: Erebor Defender Implementation
Analysis](hugging-face-agent-intrusion-analysis.md).

That implementation does not require one conversion per Pod or an application
job claim. The unchanged worker may run many jobs in one Python process.
Defender builds:

```text
actual task tree:
  task/thread key = node boot + label epoch + task cookie
  process key = node boot + label epoch + process-lineage ID
  TID/TGID/start-time = current lookup and response revalidation coordinates
  CLONE_THREAD, fork/clone, and fork-without-exec represented separately

execution graph:
  each image installed by exec, including exec-without-fork
  expected source-role → executable identity → resulting-role comparison

effect graph:
  file, mmap, socket, device, capability, namespace, mount, ptrace, BPF,
  perf, module, Kubernetes, cloud, mesh, connector, and source-control effects

distributed causal graph:
  independent native trees connected only through typed API/object/controller/
  binding/container/credential/connector/message/artifact transitions
  fan-out, missing transitions, outside-authority subjects, and late versions
  remain explicit
```

The node plane is a Defender-owned CO-RE eBPF sensor/enforcer. `task_alloc`
inherits the approved profile/role before a child runs;
`bprm_check_security` denies unexpected executable edges before image
installation; BPF LSM file/socket/security hooks deny prohibited effects from
an otherwise approved Python process; cgroup BPF owns network and device
boundaries. Existing mount/seccomp state, Kubernetes audit/RBAC, and provider
IAM remain evidence and policy context. Changing mounts, Landlock, seccomp,
admission, RBAC, IAM, credentials, or workload identity is optional H work,
not a condition for Defender's baseline.

Two packages have different responsibilities:

```text
HF-PROC-001:
  one unexpected exec/file/socket/device/security effect
  → synchronous kernel denial
  → exact native task evidence and containing ProcessInstance finding

HF-DW-001:
  credential access, authority channel, and API/provider use
  → first evaluate each against the signed behavior of the existing role
  → expected controller token/API use is context, not a finding
  → an unexpected process role, destination, verb/resource/scope, or provider
    operation creates the finding
  → prefer native/request/credential joins; same-Pod timing stays contextual
```

This handles both common paths:

```text
Python → sh → curl
  unexpected exec edges; deny before shell/client image runs

Python directly reads token and opens HTTPS socket
  no process edge
  if absent from that existing role: deny file/socket effect
  if normal for that controller role: API/provider audit supplies semantics
```

The default response target is the native `ProcessInstance`, not one thread,
job, or revision. Threads share memory, file tables, credentials, and process
role:

1. every thread task label contains its process-lineage ID plus a bounded
   inherited process-ancestor vector;
2. insert the exact process lineage into the preloaded response-root map;
3. every existing and future descendant process synchronously matches that
   root at its next protected exec, file, socket, device, or privilege hook;
4. fence attributable socket cookies at the packet path;
5. revalidate exact process leaders with native start time and pidfds, then
   optionally `SIGSTOP` them;
6. when incomplete lineage/socket evidence or atomic computation stop requires
   a broader boundary, attach a cgroup-skb fence and use cgroup v2 freeze;
7. verify response-root lookup, denial probes, socket-cookie drops, pidfd
   targets, BPF links, cgroup identity, and any frozen membership.

Linux has no atomic primitive for “freeze this arbitrary process subtree but
not other processes in the same cgroup.” The response-root scheme closes the
protected-effect race for a complete, depth-bounded tree; signal delivery still
cannot atomically stop arbitrary descendants. The cgroup is the stronger but
broader computation/packet boundary and can interrupt every job in a shared
worker.

Revision quarantine is a separate optional response. It is eligible only when
existing authenticated application/platform evidence identifies the immutable
revision or digest. Kernel ancestry, Pod UID, and timing never manufacture that
identity.

The incident controls are classified by whether Defender can provide them
against the current deployment:

| Incident effect | D — works with existing deployment | Optional H/R |
| --- | --- | --- |
| HDF5 local-file disclosure | detect/deny the resulting file effect when absent from the existing role; otherwise control later effects | scanner/parser rejection is R |
| in-process Python execution | no fabricated exec edge; deny or detect subsequent disallowed effects | strict schema/removing Jinja is R |
| projected token/environment access | allow expected controller role; deny unexpected child/process role; audit same-process authority use | token/secret removal or broker is H/R |
| metadata/control-plane access | per-role destination policy; preserve required access; use Kubernetes/cloud audit for verb/resource/operation | CNI deny or identity migration is H |
| unexpected commands | BPF LSM exec policy over approved source role, executable identity, and resulting role | none required |
| devices and escape surfaces | BPF LSM/cgroup-device policy can deny effects absent from the current role | `/dev`, seccomp, capability, or manifest hardening is H |
| privileged host-mounted Pod | audit attempt/result and contain created distributed lineage | admission/RBAC denial is H |
| broad Secret authority | inventory effective permission, detect actual read from audit, contain source; never claim admission blocked a read | RBAC reduction is H |
| AWS, mesh, connector, or GitHub effect | provider audit/behavior deviation plus exact or honestly broad response | scoped/split roles, one-use keys, or separate principals are H/R |

The real information limits remain explicit: a kernel cannot name one logical
job among concurrent work inside the same interpreter; cannot read an encrypted
HTTP verb without TLS termination; and cannot undo an effect that already
completed. A sensor product's missing fork event or selector is not such a
limit—Defender implements the missing kernel mechanism.

## Concrete Defender capabilities to explore

### Existing-authority protection and hardening proposals

Defender first models the authority already present instead of demanding a
cleaner deployment. For each workload and process role, it records non-secret
credential objects, API/metadata destinations, effective Kubernetes RBAC and
provider IAM, authoritative operation history, and the coverage that supports
the model. Legitimate controller token reads and signed API behavior remain
allowed.

The deployment-preserving path has three distinct outcomes:

1. an unexpected child or process role opening the existing credential object
   can be denied or flagged at the BPF LSM file boundary;
2. a role with no existing API/IMDS need can be denied at the socket boundary;
   and
3. when injected code acts inside the legitimate controller process, the
   kernel connection is not falsely labeled malicious. Kubernetes or provider
   audit is compared with the signed verb/resource/scope/operation profile,
   and Defender contains the narrowest proven process, socket set, cgroup, or
   identity boundary.

Defender emits a `DeploymentRiskFinding` when the existing ServiceAccount,
RBAC/IAM grant, route, or shared identity enables a dangerous path. It may pair
that finding with one or more `HardeningProposal` objects—for example a
narrower RBAC grant, workload identity, admission policy, CNI rule, secret
distribution change, or broker redesign. Each proposal names its external
owner, compatibility risk, affected workloads/principals, simulation, and
verification. It remains `proposed` until authoritative evidence shows that
the operator adopted it; the unchanged deployment remains the baseline
Defender must protect.

### Fleet coverage map

Give responders a view of what every cluster, node group, workload class, and
provider account can currently observe and contain. Combine Defender kernel
hook, BPF link/map/profile generation, task-label, ring-buffer,
seccomp/Landlock, cgroup, evidence-collector, connector, and optional-sensor
health. A distributed path carries the coverage interval for every transition
and node, so one offline destination collector or missing API audit interval is
shown as an open branch and blocks a fleet-wide `verified` claim. This is
better than a generic “sensor installed” badge.

### Evidence-first attack reconstruction

The main experience should be a causal timeline, not an alert inbox. Starting
from a native task, artifact digest, cloud principal, or imported alert,
Defender can show related task/exec lineage, credentials, sockets, provider
effects, cross-node/controller fan-out, open branches, gaps, and similar
activity elsewhere. Clearly distinguish node-local ancestry, observed causal
transitions, context, and hypotheses.

A GLM is useful here for proposing read-only queries and explaining the graph.
It remains a client of the Defender service.

### Response cards, not a remote shell

Every response card serializes the same outer request:

```text
ResponseRequest {
  response_request_id: UUID
  type: versioned response-class ID
  tenant_id: UUID
  finding_id: UUID
  target: typed native subject, workload, or provider resource reference
  requested_effects: [Enum]
  requested_by: authenticated principal
  approval_ids: [UUID]
  expires_at: Timestamp
  idempotency_key: SHA256
  expected_preconditions: Map
}
```

The authorization service resolves the target again and checks tenant, asset,
response class, approvals, expiry, connector scope, and expected current state.
The connector receives the typed target and effects, never an arbitrary command
or URL.

Response cards are incident actions, not baseline deployment requirements.
Deleting a Pod, changing an identity, suspending a provider installation, or
freezing a cgroup deliberately changes production and therefore requires the
card's explicit scope, approval, blast-radius, and postcondition contract.

| Response class | Physical connector call | Required postcondition | Known race or blast radius |
| --- | --- | --- | --- |
| `defender.contain-distributed-lineage.v1` | coordinator freezes one lineage-view version, immediately fences the seed, revokes proven propagation capabilities, invokes exact node/provider actions for each authorized member, and contains the owning reconciler; late branches receive new plan versions | every required branch's physical postcondition verifies, no controller replacement appears, no branch stays open, and required coverage remains healthy through the watch interval | orchestration is not a global kernel primitive; offline, uncovered, outside-authority, unresolved, or unapproved branches force `partial` or `unknown` |
| `linux.restrict-process-tree.v1` | node agent revalidates native process key and inserts its process-lineage ID into the preloaded response-root map; pidfd `SIGSTOP` is optional | protected-effect probes are denied for every thread in the root and each process whose pre-existing/inherited ancestry contains it; iterator proves live coverage | exact effect restriction requires complete ancestry within profile depth; signals do not atomically freeze arbitrary descendants |
| `linux.fence-socket-set.v1` | node agent fences attributable socket cookies in the packet-path map | map/readback and controlled packet-drop probe match every requested live socket | a passed/shared socket affects all its users; incomplete cookie history requires cgroup scope |
| `linux.fence-cgroup-egress.v1` | node agent holds target cgroup FD and attaches/activates a preloaded `cgroup_skb/egress` drop program | cgroup inode/ID, BPF link/program, membership, TTL, and controlled packet-drop probe match | affects the actual cgroup subtree; may include many jobs or multiple containers |
| `linux.freeze-cgroup.v1` | write `1` to cgroup v2 `cgroup.freeze` through the held target FD | `cgroup.events` reports frozen and every enumerated member is stopped | whole cgroup subtree, not one logical job |
| `defender.deploy-node-profile.v1` | activate signed process/effect map generation for an immutable image/profile on allowlisted node classes | BPF links/maps, profile digest/mode, task-label probe, and expected allow/deny probes all match | unsupported hooks or partial probes make enforcement incomplete; `SIGKILL` is not pre-effect denial |
| `kubernetes.revoke-bound-pod-token.v1` | delete exact bound Pod after fencing, then safe TokenReview when possible | bound token no longer authenticates and Pod UID is absent | unbound or shared service-account tokens need wider RBAC/identity response |
| `aws.revoke-role-sessions-before.v1` | install time-cutoff deny on one allowlisted role | deny policy readback and controlled old-session failure | affects every role session issued before cutoff; high-blast-radius approval |
| `tailscale.revoke-key-and-devices.v1` | delete auth-key ID, then delete approved device IDs | key and devices absent; later network/config audit checked | key revocation alone does not remove enrolled devices |
| `github.revoke-installation-token.v1` | exact known token calls `DELETE /installation/token` | token authentication fails | impossible by fingerprint alone; suspending installation is wider |
| `artifact.quarantine-revision.v1` | only after exact platform evidence, product API changes that immutable revision/digest to quarantined | exact revision and declared identical-digest cases cannot enter scheduler | ineligible from kernel/Pod timing alone; already running copies need separate containment |

Execution is append-only:

```text
proposed → authorized → executing → verifying
                                  → verified | partial | failed | unknown
```

An HTTP success, `kubectl apply`, or connector acknowledgement leaves the
execution in `verifying`. Only the postcondition moves it to `verified`.

Distributed containment is a plan over those narrow cards, not a wider
actuator. Every node target is re-resolved against its own native identity,
every provider target retains its connector-specific authorization, and every
new branch discovered during the containment watch is separately simulated and
authorized. Killing one Pod is not sufficient when its controller can
reconcile a replacement on another node. The coordinator must constrain the
exact owning object with UID and resource-version preconditions, using a
kind-specific suspend, scale, admission block, or approved deletion action.

### Tool surface for humans and defensive agents

Defender exposes typed investigation and response methods, not an interactive
execution environment or remote shell:

| Method | Input | Authority |
| --- | --- | --- |
| `GetFinding` | tenant-bound finding ID and requested evidence depth | read raw references, normalized facts, coverage, edges, and response eligibility |
| `SearchEvidence` | typed time, asset, subject, object, action, and source filters with bounded page size | read only; no arbitrary SQL or provider query |
| `SimulateResponse` | finding ID, response class, typed target, requested effects | resolves preconditions, expected connector calls, approvals, races, and blast radius without executing |
| `RequestResponse` | simulation ID, approval IDs, expiry, idempotency key | creates an authorization-checked request; does not expose connector credentials |
| `GetResponseExecution` | response request/execution ID | reads attempts, provider request IDs, verification checks, and final known/unknown state |

The caller credential contains tenant, role, and allowed method scopes. It
contains no node-enforcer, optional-sensor, Kubernetes, AWS, mesh, connector,
GitHub, or other provider credential. Those remain in separately deployed
connector identities.

Attacker-controlled evidence is returned as data fields. It never becomes a
tool name, URL, shell fragment, target ID, or policy expression without typed
parsing and resource resolution. A GLM may call `SimulateResponse` and
`RequestResponse`; authorization and required human approvals remain server
decisions.

### Detection-package replay and response simulation

Before a detection package is deployed or a response becomes pre-approved,
replay it against Defender node fork/exec/effect/health envelopes, optional sensor
events, application/platform audit records, provider audit records, benign
lookalikes, duplicates, reordered events, and deliberate coverage gaps. Assert
expected findings, edge strength, action availability, and postcondition
behavior.

Before changing production, a responder should be able to simulate the target
set, authorization, dependencies, connector calls, and expected blast radius.
Simulation must remain clearly distinct from a physical effect.

### Conservative automatic containment

Some cross-source combinations justify opt-in, narrowly scoped automatic
containment:

```text
unexpected native task/exec edge or in-process prohibited effect
  + credential access by an unexpected process role
  + destination or API/provider behavior outside the signed existing profile
  + healthy relevant hooks and evidence
       │
       ▼
restrict exact process tree; use cgroup fence only when its broader target is
approved
       │
       ▼
open a case; require human approval for shared credential rotation
```

A lone high-severity alert should not automatically change a cluster or revoke
a shared production credential. Ordinary controller token reads and API calls
must not satisfy this combination. It needs reviewed deviation evidence, an
asset-specific policy, expiry, and a human escalation path.

## Implementation and reuse choices

| Capability | Default owner | Reuse rule | Required proof |
| --- | --- | --- | --- |
| native task/exec/effect enforcement | Defender node plane | reuse an upstream component only for hooks where it satisfies the exact contract; implement missing fork, task-label, role, or actuator behavior | pre-effect return, task inheritance, PID-reuse safety, loss state, policy generation, and target-kernel tests |
| optional endpoint detections | adapter to Tetragon, Falco, or another source | ingest structured raw/native events without making their rule engine authoritative | source provenance, native IDs, version, coverage, and no invented joins |
| network datapath | cgroup BPF/TC plus compatible CNI integration | reuse CNI identity and verdicts where present; keep process socket policy independent | new and established flow behavior, IPv4/IPv6, secondary interface, socket sharing, and exact cgroup scope |
| distributed causal lineage | Defender correlator over native, Kubernetes, connector, queue, artifact, and provider observations | reuse authoritative source schemas and IDs; own edge proof rules, immutable edge storage, lineage-view versioning, and gap semantics | cross-node rejection for process-parent edges, UID/name reuse, controller fan-out/retry, late/contradictory evidence, and missing-transition fixtures |
| profile/content lifecycle | Defender | compile signed process/effect profiles and optional sensor content | monitor/enforce distinction, image binding, atomic generation switch, rollback, and probes |
| physical response | narrow Defender node/control-plane/provider connectors plus distributed coordinator | reuse provider APIs; never hand general credentials to a sensor or model; orchestration never becomes ambient authority | per-member authorization, native target re-resolution, controller replacement watch, authority boundary, idempotency, blast radius, coverage, and postcondition |

The first evaluation is the native kernel vertical slice: unchanged multi-job
worker, exact task/process graph, unexpected exec denial, in-process
file/socket denial for effects absent from the signed existing role, expected
credential/API behavior without false findings, and verified
process-tree-versus-cgroup containment.
Existing sensor ingestion can run in parallel, but it cannot replace that
proof or postpone it indefinitely.

## Non-negotiable lessons

- Do not treat `SIGKILL` or `SIGSTOP` as proof that an earlier physical effect
  was prevented.
- Do not promote any sensor severity or priority into action authorization.
- Do not hide hook detachment, task-label failure, sensor downtime, output
  backlog, drops, or absent plugins.
- Do not expose raw kernel/sensor policy, shells, Kubernetes, cloud, or identity
  credentials to a model client.
- Do not define baseline protection by removing or replacing the protected
  deployment's credentials, ServiceAccounts, RBAC, IAM, routes, controller
  manifests, application code, or topology.
- Do not turn a scanner, broker, split identity, admission policy, CNI rule, or
  other H/R recommendation into a Defender capability or prerequisite.
- Do not call an expected controller token read or API connection malicious;
  require a process-role, destination, or authoritative API/provider behavior
  deviation.
- Do not claim Kubernetes admission prevented `get`, `list`, or `watch`; those
  reads bypass admission.
- Do not require job-per-Pod/process or application job claims to make Linux
  attribution convenient.
- Do not call Pod-level timing a process edge or revision identity.
- Do not create a process-parent edge across nodes. Join native trees through
  typed authoritative causal transitions and expose every missing transition.
- Do not call network communication remote execution without receiver-side
  request/execution evidence.
- Do not call distributed containment verified while a required branch is
  offline, uncovered, outside authority, unapproved, unresolved, or able to be
  recreated by its controller.
- Do not create a universal rule language before evidence, response, and
  lifecycle contracts are proven for initial integrations.
- Do not infer Defender authority over an asset from evidence that originated
  outside the defender organization's authenticated asset inventory.

## Questions a future Defender phase must answer

1. Who owns each kernel hook, policy/profile version, map/link, key, and
   lifecycle?
2. Which effects can each hook synchronously deny, which can it only observe,
   and how are detachments, drops, and downtime represented?
3. How does intake prevent alteration, replay, tenant confusion, and schema
   ambiguity?
4. How are native task/exec, optional sensor, Kubernetes audit/object/
   controller/binding/container, application work-item, socket/flow,
   credential, connector, message, artifact, and provider identities joined
   across nodes and clusters without inventing process ancestry?
5. Which findings are facts, which are inference, and which content version
   produced them?
6. Which mechanisms deny an effect, which only stop a task, which act on a
   socket set or whole cgroup, and which require complete bounded ancestry?
7. Who may request, approve, execute, reverse, and verify each response card?
8. What happens if Defender, a sensor, transport, or connector restarts during
   containment?
9. How are packages replayed against hostile, benign, incomplete, and
   out-of-order evidence?
10. How is a model prevented from converting attacker-controlled text into
    unreviewed authority?
11. Which distributed branches are inside response authority, how are late
    branches admitted to a new response-plan version, and what exact
    watch-window and coverage proof permits `verified`?
12. Does every proposed control work against the original credentials,
    identities, routes, manifests, and topology; if not, is it visibly
    classified H or R and excluded from baseline acceptance?

## Primary sources consulted

- [Tetragon overview](https://tetragon.io/docs/overview/)
- [Tetragon tracing-policy reference](https://tetragon.io/docs/reference/tracing-policy/)
- [Tetragon enforcement semantics](https://tetragon.io/docs/concepts/enforcement/)
- [Tetragon enforcement modes](https://tetragon.io/docs/concepts/tracing-policy/mode/)
- [Tetragon persistent enforcement](https://tetragon.io/docs/concepts/enforcement/persistent-enforcement/)
- [Tetragon gRPC transport security](https://tetragon.io/docs/installation/grpc-tls/)
- [Tetragon metrics](https://tetragon.io/docs/installation/metrics/)
- [Tetragon threat model](https://tetragon.io/docs/threat-model/)
- [Falco event sources](https://falco.org/docs/concepts/event-sources/)
- [Falco kernel event drivers](https://falco.org/docs/concepts/event-sources/kernel/)
- [Falco plugins](https://falco.org/docs/concepts/plugins/)
- [Falco plugin architecture](https://falco.org/docs/concepts/plugins/architecture/)
- [Falco plugin event sources](https://falco.org/docs/concepts/event-sources/plugins/)
- [Falco rule fields](https://falco.org/docs/reference/rules/supported-fields/)
- [Falco rule format versioning](https://falco.org/docs/concepts/rules/versioning/)
- [Hugging Face technical incident timeline](https://huggingface.co/blog/agent-intrusion-technical-timeline)
- [Linux kernel: LSM BPF programs](https://docs.kernel.org/bpf/prog_lsm.html)
- [Linux kernel: LSM hook development reference](https://docs.kernel.org/security/lsm-development.html)
- [Linux kernel source: current LSM hook definitions](https://github.com/torvalds/linux/blob/master/include/linux/lsm_hook_defs.h)
- [Linux kernel: BPF program and attach types](https://docs.kernel.org/bpf/libbpf/program_types.html)
- [Linux kernel: cgroup v2 and BPF device control](https://docs.kernel.org/admin-guide/cgroup-v2.html)
- [Linux kernel: socket-local BPF storage](https://docs.kernel.org/bpf/map_sk_storage.html)
- [Linux kernel source: task-local BPF storage implementation](https://github.com/torvalds/linux/blob/master/kernel/bpf/bpf_task_storage.c)
- [Linux kernel source: exec de-threading and task identity transition](https://github.com/torvalds/linux/blob/master/fs/exec.c)
- [Linux kernel: Landlock](https://docs.kernel.org/userspace-api/landlock.html)
- [Linux kernel: seccomp filter](https://docs.kernel.org/userspace-api/seccomp_filter.html)
- [OCI runtime spec: create/start lifecycle and container states](https://specs.opencontainers.org/runtime-spec/runtime/)
- [OCI runtime spec: pre-exec hook ordering](https://specs.opencontainers.org/runtime-spec/config/)
- [Kubernetes auditing and audit stages](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
- [Kubernetes audit event schema](https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/)
- [Kubernetes owners and dependents](https://kubernetes.io/docs/concepts/overview/working-with-objects/owners-dependents/)
- [Kubernetes OwnerReference schema](https://kubernetes.io/docs/reference/kubernetes-api/definitions/owner-reference-v1-meta/)
- [Kubernetes ReplicaSet ownership and selector behavior](https://kubernetes.io/docs/concepts/workloads/controllers/replicaset/)
- [Kubernetes controller reconciliation](https://kubernetes.io/docs/concepts/architecture/controller/)
- [Kubernetes scheduling framework and Bind phase](https://kubernetes.io/docs/concepts/scheduling-eviction/scheduling-framework/#bind)
- [Kubernetes: ValidatingAdmissionPolicy](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
- [Kubernetes: admission-controller boundary, including reads bypassing admission](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/)
- [Kubernetes: ServiceAccounts and projected tokens](https://kubernetes.io/docs/concepts/security/service-accounts/)
- [Kubernetes: RBAC good practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/)
- [Kubernetes: `hostPath` volume risks](https://kubernetes.io/docs/concepts/storage/volumes/#hostpath)
- [Cilium: Hubble network observability](https://docs.cilium.io/en/stable/observability/hubble/)

The local `tetragon/` and `falco/` clones were also inspected for policy,
enforcement, test, source, rule-loading, output, and queue behavior. Revisit
this guide when a future Defender phase names a concrete asset type and
response contract.
