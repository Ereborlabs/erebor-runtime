# Defender Learning Guide: Tetragon, Falco, and Erebor's Opportunity

Status: living product and technical research. This document approves no
implementation, deployment, dependency, or fork.

Related reading:

- [Runtime and Defender learning guide](erebor-runtime-and-defender-learning.md)
- [Linux Kernel-Native Effect Enforcement Master Plan](../plans/linux-kernel-native-enforcement/README.md)

## The conclusion

Tetragon and Falco are principally useful to a future Erebor Defender.
Tetragon is a Linux eBPF runtime-security system with both high-fidelity
endpoint observations and selected inline enforcement. Falco is a broad,
source-specific detection engine that evaluates streams of events against
rules and delivers alerts. Both can be used in a product; Erebor does not need
to recreate their kernel sensors or rule engines merely to learn from them.

Neither product is a complete Defender. Tetragon's policy boundary is local to
a host/workload. Falco's documentation explicitly says it does not correlate
events across different sources. Neither supplies the proposed Erebor Defender
authority boundary: a model, human, or SIEM client must not directly possess
the credentials that can isolate a workload, revoke a role, or alter a cluster.

```text
Tetragon: kernel facts + selected local enforcement
Falco:    source-specific detection facts + alert delivery
                         │
                         ▼
Erebor Defender: evidence integrity + cross-source attack story
                 + scoped investigation tools + approval-gated action
```

## Technology anatomy

The following describes the major technologies actually used by the checked-out
projects and the operational consequences for Defender. Exact versions and
support matrices change, so a future integration must collect the deployed
component's capability report rather than rely on this document alone.

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

| Concern | Tetragon | Falco | Erebor Defender decision |
| --- | --- | --- | --- |
| Kernel privilege | Loads eBPF programs and may change local behavior. | Loads an eBPF probe or kernel module for syscall collection. | Treat each node agent as privileged security infrastructure; isolate its credentials and upgrade path. |
| Content supply chain | YAML policy can change observation/enforcement behavior. | Rules and dynamic plugins can change detection behavior. | Sign/version detection packages, verify compatibility, and retain content hashes with findings. |
| Event transport | gRPC, JSON/log export, bounded kernel buffers. | Multiple output channels and bounded queues/buffers. | Track source health and loss explicitly; do not use alert absence as proof. |
| Kubernetes control | Operator/CRDs and workload identity mapping. | Helm plus plugins/metadata integrations. | Do not give a generic Defender client cluster-admin or policy-writing permission. Separate read, deploy, and response roles. |
| Evidence semantics | Can observe and sometimes enforce locally. | Detects and reports. | A source event, a local denial, an alert, and a remote action result remain different evidence types. |

### What Defender can reuse and what it must own

Use upstream capabilities where they fit:

- Tetragon as an endpoint event and policy/health source, and later as one
  carefully constrained local containment adapter.
- Falco as an existing detection and alert source, including its reviewed
  plugin ecosystem where the organization already operates it.
- Prometheus and the native health/metric surfaces as inputs to Defender
  coverage calculations, rather than inventing a second node-health protocol.
- Tetragon's gRPC/protobuf types and Falco's structured JSON output as adapter
  boundaries, avoiding an unnecessary fork of either engine.

Erebor must still own the product-specific pieces:

- a tenant-safe identity graph spanning workload, process, Runtime Session,
  cloud principal, artifact, and provider audit resource;
- immutable raw evidence, normalized observations, coverage intervals, and
  reproducible findings;
- cross-source correlation and the separation of fact from hypothesis;
- action authorization, approvals, idempotency, expiry, rollback, and
  postcondition verification; and
- a model-facing tool boundary that cannot turn attacker-controlled evidence
  into direct Tetragon, Kubernetes, cloud, or identity authority.

## Defender's product boundary

Erebor Defender is a separate future project. It is not an agent and does not
own a Runtime Session. It is a service used by humans, GLM, SIEM, and other
defensive tools to investigate and request a narrow action on infrastructure
the defender organization owns.

The Defender service authenticates the caller, checks tenant/resource scope and
approval policy, invokes a defender-owned connector, and records the result.
The client model never becomes the enforcement or authority boundary.

```text
Tetragon / Falco / Runtime / cloud / identity sensors
                         │ raw evidence
                         ▼
                 Erebor Defender service
 intake → evidence/coverage → correlation → case → response authorization
                         │
                         ▼
 Runtime fence / Tetragon policy / Kubernetes / cloud / IdP / VCS connector
                         │
                         ▼
              verified result and immutable response record
```

The source deployment is part of the defender's estate. A Defender deployment
on Hugging Face assets does not give it a Session or authority over an unrelated
OpenAI evaluation workload.

## What Tetragon teaches

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
lineage; execution; selected credential/runtime file access; namespace and
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

Erebor should adapt this lifecycle rather than expose raw Tetragon policy as a
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

## What Falco teaches

[Falco](https://falco.org/) evaluates event streams against rules and emits
structured alerts. Its native syscall source can be extended by plugins, such
as Kubernetes Audit, AWS CloudTrail, and Okta sources. Rules are associated
with one source; Falco does not correlate across sources.

| Falco capability | Defender use | Erebor responsibility |
| --- | --- | --- |
| Rules, macros, lists, exceptions, tags, priorities, and output fields. | Ingest mature detection content while retaining rule provenance. | A rule match is a signal, not a full attack story or proof an effect was prevented. |
| Plugins and typed source fields. | Use existing local, cloud, and identity telemetry without changing Runtime. | Track source schema, plugin version, source trust, and delivery health. |
| JSON, HTTP, program, file, syslog, and other outputs. | Deliver alert envelopes to Defender intake. | An alert output is not a durable ledger and no alert is not a negative result. |
| First/all rule matching configuration. | Tune operational signal and noise. | Preserve supporting/conflicting predicate matches rather than hiding context. |

### Detection packages, not scattered alert queries

Falco suggests a good content discipline. An Erebor Defender detection package
could include:

- source adapter and supported schema/plugin versions;
- predicates that create named facts or findings;
- technique, asset, owner, confidence, and response-class tags;
- a raw-event replay corpus and expected derived findings;
- required sensor capabilities and an explicit unsupported state;
- advisory severity, never a direct authorization decision; and
- proposed response intents with evidence and approval requirements.

Do not make Falco's language the initial Erebor public policy language.
Defender needs cross-source joins, causal evidence, capability checks, response
authorization, and lifecycle semantics beyond an individual rule match.

### Falco's cross-source limit is Defender's opening

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
The Defender adapter must represent their consequences rather than silently
draw a green dashboard. On intake it needs:

- authenticated sender and tenant/asset binding;
- source instance/boot identity, cursor or sequence when available, event time,
  and receipt time as separate facts;
- immutable raw-envelope retention plus parsed normalized observations;
- explicit queue/drop/health telemetry and coverage intervals; and
- a durable retry/acknowledgement contract appropriate to the source.

## An architecture to evaluate for Erebor Defender

This product shape separates raw telemetry, conclusions, and physical response.

```text
                         sensor/provider plane
 ┌────────────┬───────────────┬───────────┬────────────┐
 │ Tetragon   │ Falco         │ Runtime   │ cloud / IdP│
 │ kernel     │ rules/plugins │ Sessions  │ / K8s / VCS│
 └─────┬──────┴──────┬────────┴─────┬─────┴─────┬──────┘
       └──────────────┴──────┬───────┴───────────┘
                              ▼
                    evidence intake and coverage
                              │ verifies sender, preserves raw
                              ▼
                  normalized observations and identity graph
                              │ facts, joins, provenance, confidence
                              ▼
                   findings, cases, and attack hypotheses
                              │ no direct authority
                              ▼
                typed response request and approval evaluation
                              │ scope + expiry + postcondition
                              ▼
        Runtime / Tetragon / Kubernetes / cloud / IdP / VCS actuators
                              │
                              ▼
                    verified outcome and immutable audit
```

### Do not collapse these evidence objects

| Object | Meaning | Authority and lifecycle |
| --- | --- | --- |
| `SourceEnvelope` | Exact source payload plus sender and receipt metadata. | Immutable after intake; no conclusion implied. |
| `Observation` | Normalized source-attributed statement, such as process X opened file Y. | References raw data and schema version. |
| `CoverageInterval` | What a source/policy could see for an asset and its health. | Prevents false negative claims. |
| `Finding` | Versioned detection result over observations. | Recomputable; carries predicate/content version and confidence. |
| `Case` | Investigation view linking findings, assets, hypotheses, and decisions. | Mutable workflow; cannot rewrite evidence. |
| `ResponseRequest` | Proposed state change with actor, target, reason, expiry, and postcondition. | Authorization-checked. |
| `ResponseExecution` | Connector request/result, verification, rollback, and final known/unknown state. | Immutable audit; only this claims action occurred. |

This permits a GLM to investigate and summarize without allowing a
model-generated sentence to mutate evidence or create authority.

## Concrete Defender capabilities to explore

### Fleet coverage map

Give responders a view of what every cluster, node group, Runtime tier, and
provider account can currently observe and contain. Combine Tetragon capability
reports, Falco sources/plugins/rule sets, Runtime evidence health, and connector
scope. This is better than a generic “sensor installed” badge.

### Evidence-first attack reconstruction

The main experience should be a causal timeline, not an alert inbox. Starting
from a process, artifact digest, cloud principal, or Falco alert, Defender can
show related process lineage, credentials, sockets, provider effects, gaps, and
similar activity elsewhere. Clearly distinguish observed facts from hypotheses.

A GLM is useful here for proposing read-only queries and explaining the graph.
It remains a client of the Defender service.

### Response cards, not a remote shell

Offer a small set of typed, provider-specific actions instead of arbitrary
commands.

| Response card | Preconditions | Verified result |
| --- | --- | --- |
| Fence Runtime workload | Session exists and policy authorizes containment. | No new governed effects; Session seals or reports incomplete evidence. |
| Add temporary Tetragon containment | Asset supports exact mechanism; approved policy, target, and expiry exist. | Correct policy mode/domain is loaded and a probe verifies its stated boundary. |
| Isolate Kubernetes workload | Ownership and connector permission are established. | Workload reaches declared isolation; existing connections are reported separately. |
| Revoke lease or identity binding | Exact token/key/role is known and in tenant scope. | Provider confirms revocation; dependent impact is recorded. |
| Block immutable artifact digest | Artifact system supports that control. | Future acquisition is denied; existing copies are located separately. |

“Block” must not hide differing races and blast radii. A signal, token
revocation, and firewall change are materially different response mechanisms.

### Detection-package replay and response simulation

Before a detection package is deployed or a response becomes pre-approved,
replay it against Tetragon envelopes, Falco alerts from each expected source,
Runtime events, provider audit records, benign lookalikes, duplicates,
reordered events, and deliberate coverage gaps. Assert expected findings,
confidence, action availability, and postcondition behavior.

Before changing production, a responder should be able to simulate the target
set, authorization, dependencies, connector calls, and expected blast radius.
Simulation must remain clearly distinct from a physical effect.

### Conservative automatic containment

Some cross-source combinations justify opt-in, narrowly scoped automatic
containment:

```text
untrusted-loader lineage
  + sensitive credential access
  + metadata/control-plane connection
  + healthy relevant sensors
       │
       ▼
fence only that workload and revoke only its Session lease
       │
       ▼
open a case; require human approval for shared credential rotation
```

A lone high-severity alert should not automatically change a cluster or revoke
a shared production credential. The combination must have reviewed evidence,
an asset-specific policy, expiry, and a human escalation path.

## Integration choices

| Choice | What Erebor does | Benefits | Required proof |
| --- | --- | --- | --- |
| **Ingest existing deployments first** | Consume Tetragon events/policy/health and Falco alerts/health through adapters. | Lowest coupling; preserves existing investment. | Intake provenance, tenant binding, source coverage, and evidence correctness. |
| **Manage content next** | Compile approved Defender packages to monitor-first Tetragon/Falco deployment. | Consistent testing, expiry, rollout, and audit. | Preserve upstream ownership, compatibility, and rollback semantics. |
| **Control response later** | Invoke narrowly scoped Runtime, Tetragon, Kubernetes, cloud, or IdP connectors. | Converts detection into verified containment. | Authorization, idempotency, approval, and postcondition proof. |
| **Embed or fork an engine** | Maintain modified upstream implementation. | Maximum control. | High security/upgrade burden; require proof that adapters cannot meet the contract. |

The recommended first evaluation is ingestion. Do not begin by embedding an
engine or giving a Tetragon/Falco deployment unrestricted response credentials.

## Non-negotiable lessons

- Do not treat Tetragon `SIGKILL` as proof that a physical effect was prevented.
- Do not promote Falco severity or priority into action authorization.
- Do not hide sensor downtime, output backlog, drops, or absent plugins.
- Do not expose raw Tetragon policy, shells, Kubernetes, cloud, or identity
  credentials to a model client.
- Do not create a universal rule language before evidence, response, and
  lifecycle contracts are proven for initial integrations.
- Do not conflate a Defender deployment on one organization's assets with an
  unrelated attacker's Runtime Session.

## Questions a future Defender phase must answer

1. Who owns source deployment, policy/rule version, keys, and lifecycle?
2. Which exact events can it observe, and how are drops/downtime represented?
3. How does intake prevent alteration, replay, tenant confusion, and schema
   ambiguity?
4. How are Tetragon process, Falco alert, Runtime Session, Kubernetes workload,
   and cloud audit event identities joined?
5. Which findings are facts, which are inference, and which content version
   produced them?
6. Which mechanisms deny an effect, which only terminate a process, and which
   have an unknown race?
7. Who may request, approve, execute, reverse, and verify each response card?
8. What happens if Defender, a sensor, transport, or connector restarts during
   containment?
9. How are packages replayed against hostile, benign, incomplete, and
   out-of-order evidence?
10. How is a model prevented from converting attacker-controlled text into
    unreviewed authority?

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

The local `tetragon/` and `falco/` clones were also inspected for policy,
enforcement, test, source, rule-loading, output, and queue behavior. Revisit
this guide when a future Defender phase names a concrete asset type and
response contract.
