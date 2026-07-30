# Mithril Single-Gatherer Architecture and Upstream Adoption Plan

Status: architecture direction recorded; implementation has not started. This
document approves the design decisions listed below for future planning, but it
does not by itself authorize a dependency, fork, deployment, privilege, or
automatic response.

Product name: **Mithril** is the product called **Erebor Warden** and
**Erebor Defender** in earlier research. Those names remain historical aliases,
not separate products. This filename is retained for link stability.

Repository direction: the current repository remains `erebor-runtime` until a
separately approved repository migration. The target is one repository named
`erebor` containing both Erebor Runtime and Mithril, plus explicitly shared
kernel-observation code. A monorepo does not merge their product authority:
Mithril remains the defender and enforcement product, while Runtime governs
agent execution through Runtime-owned surfaces.

Mithril does not use Runtime Sessions as its native Linux identity or
enforcement model. Runtime may bind observations from the shared Linux sensor
to a Runtime Session, but that binding is a Runtime enrichment layered over
native task, process, execution, cgroup, socket, and node identity.

## Related documents

This plan preserves and specializes the following research:

- [Erebor Defender: Linux Enforcement, Correlation, and Response Engineering](erebor-defender-learning-from-tetragon-and-falco.md)
- [Hugging Face Agent Intrusion: Erebor Defender Implementation Analysis](hugging-face-agent-intrusion-analysis.md)
- [Hugging Face Agent Intrusion: Published Live Action Stream](hugging-face-agent-intrusion-live-action-stream.md)
- [Learning Guide: Erebor Runtime and the Future Erebor Defender](erebor-runtime-and-defender-learning.md)
- [Linux Kernel-Native Effect Enforcement Master Plan](../plans/linux-kernel-native-enforcement/README.md)

The first document defines Mithril's Linux enforcement, evidence, correlation,
coverage, and response responsibilities. The Hugging Face analysis provides a
concrete multi-node attack and acceptance workload. The Runtime and Defender
learning guide explains the product boundary and the fundamental limits of
opaque TLS, shared credentials, and same-process compromise. The Linux
kernel-native enforcement plan is Runtime work; it is related technology, not
Mithril's implementation plan. Together these documents are design inputs:
Mithril must be implemented from their combined threat, identity, effect,
coverage, correlation, and response requirements rather than by reproducing
one upstream product's existing architecture.

## Goal

Build a production Mithril that:

1. requires only one privileged Mithril gatherer type per protected Linux node;
2. observes and enforces against unchanged applications, Pods, controllers,
   credentials, process topology, and agent harnesses;
3. creates exact node-local task, process, execution, socket, and effect
   identity;
4. correlates independently proven node-local trees across Kubernetes, cloud,
   identity, mesh, source-control, connector, message, and artifact boundaries;
5. synchronously denies supported local effects before they occur;
6. exposes narrowly scoped, approval-gated, physically verified response;
7. distinguishes healthy observation from degraded or absent coverage; and
8. is installed and operated as one product rather than a bundle of KubeArmor,
   Falco, Tetragon, Cilium, and their relays or exporters;
9. owns its loader, node userspace, control-plane userspace, schemas, and
   security state in Rust; and
10. shares one Rust Linux sensor implementation with Erebor Runtime, where
    Runtime uses it only to observe agent actions.

## Decision summary

The following decisions are recorded.

| Area | Decision |
| --- | --- |
| product name | Mithril; Warden and Defender are historical names |
| repository | one future monorepo named `erebor`, containing Runtime, Mithril, and shared components |
| implementation language | Mithril-owned loader and userspace are Rust; BPF programs remain C/headers compiled as CO-RE objects |
| BPF loading stack | use upstream libbpf through `libbpf-rs`/`libbpf-cargo` as the default design, subject to Phase 0 version and kernel-matrix proof |
| shared sensor | one Rust-owned Linux sensor implementation and raw kernel-event ABI serve both products |
| Runtime mode | Runtime scopes the shared sensor to agent work and receives observations only; it receives no Mithril denial, profile-map, or response authority |
| co-resident ownership | when Runtime and Mithril share a host, exactly one active kernel-program owner loads overlapping programs and Runtime subscribes to its scoped observation stream |
| node deployment | one `mithril-node` binary and one DaemonSet Pod per protected Linux node |
| cluster-wide service | Mithril Control is Erebor-hosted SaaS or one self-hosted service; it is not another privileged node sensor |
| initial node substrate | implement a Rust-owned loader and node agent informed by the combined research; do not fork an upstream product as the product chassis |
| public contract | Mithril owns its event, identity, policy, coverage, evidence, and response schemas; no upstream API is the permanent contract |
| local enforcement | Mithril owns task-role-aware BPF LSM, cgroup BPF, socket storage, and packet-fence programs |
| Tetragon use | study and selectively adapt appropriately licensed BPF techniques, tests, and behavior; do not retain its Go daemon as Mithril's userspace |
| KubeArmor use | learn from and selectively reimplement its LSM hook coverage and policy compilation; do not deploy or embed the complete KubeArmor product |
| Falco use | import or translate selected Falco detection content; do not deploy Falco or its kernel driver as part of Mithril |
| Cilium use | optional Hubble/Cilium evidence and response adapter when already installed; never a Mithril prerequisite |
| network baseline | Mithril owns minimal process-aware connect, bind, sendmsg, socket, and containment coverage without becoming a CNI |
| application semantics | no TLS interception; use kernel-visible destination facts and authoritative server/provider audit |
| hot-path authority | local signed policy maps decide kernel enforcement; no central network round trip is allowed in an LSM or cgroup decision |
| evidence | one node event pipeline, append-only local spool, explicit sequence/loss evidence, and one outbound mTLS stream |
| installation | one Helm release; no required Mithril operator, admission webhook, relay, exporter, sidecar, or per-source collector |
| rollout | observe first, simulate and review, then enable signed enforcement profiles |
| fallback | unsupported kernels receive an explicit reduced tier; missing enforcement is never represented as full protection |

## Non-negotiables

### Preserve the protected deployment

Baseline Mithril protection must not require changes to:

- application or agent code;
- tool protocols or harnesses;
- one job per Pod or one job per process;
- existing controller, Pod, or process topology;
- mounted ServiceAccount tokens or other credentials;
- RBAC, IAM, provider identities, or network routes;
- the customer's CNI; or
- application-level events that do not already exist.

Mithril may install its own node agent, kernel programs, runtime hook, central
service, and evidence/provider connectors. Changes to the protected deployment
remain separately proposed hardening or redesign work.

### One gatherer means one node sensor owner

BPF programs attach to a local kernel. A process on one node cannot attach BPF
programs to another node's kernel. A multi-node cluster therefore requires one
local Mithril instance per protected node.

The product contract is:

> One privileged Mithril agent type per node, containing all Mithril Linux
> gathering and local enforcement. Mithril does not require another privileged
> Falco, KubeArmor, Tetragon, Cilium, Tracee, audit, or exporter agent beside
> it.

One node agent may load several BPF programs at different kernel hooks. Multiple
programs inside the same owner do not violate the single-gatherer contract.
Trying to use one BPF program for unrelated LSM, scheduler, cgroup, socket, and
packet hooks would weaken portability and clarity without reducing operational
components.

### Prevention and observation are separate claims

- An LSM or supported override returning a denial can prove that the selected
  operation was denied before effect.
- Sending `SIGKILL` proves that a process was signalled. It does not prove that
  an in-progress write or other effect did not complete.
- Pinned enforcement may remain active while the userspace agent is down, but
  that interval is not observed.
- An alert is evidence of a detection, not proof of containment.
- A successful API response is not enough; each response needs a physical
  postcondition.

### Mithril owns its guarantees

An upstream implementation may supply code, an observation, or an actuator.
It does not define Mithril's correctness boundary. Mithril must implement or
integrate every required guarantee that Linux or an authoritative provider
control point can supply.

### Rust owns the product boundary

Mithril's production loader and userspace are Rust-owned. This includes:

- BPF object selection, CO-RE loading, attachment, pinning, upgrade, rollback,
  feature probing, verifier reporting, and map lifecycle;
- node identity, event decoding, policy compilation, evidence, coverage,
  response, and local APIs;
- Mithril Control, correlation, connectors, investigation, authorization, and
  response coordination unless a later approved plan establishes a narrower
  language boundary; and
- the local arbitration that prevents Runtime and Mithril from loading
  duplicate overlapping program sets.

C remains acceptable for the kernel BPF programs and their headers. Rust
ownership does not mean translating verifier-sensitive BPF C into Rust merely
for language uniformity. Go or C++ upstream code may be research evidence,
test-oracle material, or an optional isolated compatibility component, but it
is not the Mithril product chassis.

### Shared sensor code does not merge product authority

The monorepo contains one shared Linux sensor implementation with at least two
explicit capability modes:

| Mode | Scope | Permitted authority |
| --- | --- | --- |
| `mithril-observe` | selected or node-wide workloads | observe, enrich, spool, and report; no denial |
| `mithril-protect` | selected or node-wide workloads | observe plus signed Mithril enforcement and typed response |
| `runtime-observe` | Runtime-owned agent cgroups/processes | observe agent actions and return evidence to Runtime; no Mithril policy installation, denial, containment, or response |

`runtime-observe` is not a configuration flag that an agent can upgrade into
protection or response authority. Its Rust type/API surface, loaded object set,
map file descriptors, Unix API permissions, and tests must make that authority
unavailable. Runtime continues to enforce agent actions through its own
governed execution paths; the shared Linux sensor supplies corroborating
observation and coverage.

## Research baseline

The local source inspection used these revisions:

| Project | Local revision | Primary areas inspected |
| --- | --- | --- |
| KubeArmor | `e46f112e8bd4d3c8c8a73c23bfe438ff40eeea1a` | `KubeArmor/BPF`, `KubeArmor/enforcer/bpflsm`, `KubeArmor/monitor`, policy specifications and deployment model |
| Falco | `2656c5a34b1f14a09516c00f10c1820240029821` with `falcosecurity/libs` pinned at `6fbc055dd53eff5ce3ad79e96cb5b21252ad0090` | userspace event/rule pipeline, modern BPF driver and `libpman`, plugin proposals, drop handling and deployment documentation |
| Tetragon | `dbb59576f9ce504c044f8d9a0cd7a0f91c71ae2c` | `bpf/process`, `pkg/sensors`, `pkg/process`, cgroup/container identity, events, TracingPolicy and enforcement |
| Cilium/Hubble | no local clone used | official current component, datapath, policy, identity, L7, and Hubble documentation |

These revisions are research evidence, not dependency pins. Phase 0 must repeat
the inspection against the exact revisions selected for implementation.

The measured kernel-source baseline uses physical lines, including comments
and blanks, and excludes generated architecture `vmlinux.h` files:

| Project area | Files | Physical lines | Interpretation |
| --- | ---: | ---: | --- |
| Tetragon-owned production BPF C/headers | 97 | 15,071 | 29 production C files contain 3,132 lines; most implementation is in tightly coupled headers |
| Tetragon `bpf/lib` internal headers | 17 | 2,643 | private Tetragon BPF support headers, not a linkable library |
| Tetragon copied `bpf/libbpf` headers | 2 | 1,111 | only `bpf_core_read.h` and `bpf_tracing.h`, not the libbpf userspace library |
| KubeArmor BPF C/headers | 20 | about 6,290 | small enough to reimplement mechanisms, but production parity also requires lifecycle and kernel-matrix work |
| Falco modern BPF C/headers | 195 | 20,083 | 176 syscall/event BPF programs plus 19 non-generated headers |
| Falco `libpman` C/headers | 18 | 4,856 | a real reusable userspace library boundary, but not selected as Mithril's loader |

The source size does not estimate the whole implementation. Tetragon's
selected sensor, process, observer, BPF, selector, and policy-filter Go
packages add roughly 44,400 physical lines. Falco also depends on its shared
driver event schema and libscap/libsinsp behavior. The difficult production
work is kernel compatibility, verifier-safe behavior, exact ABI ownership,
loss handling, policy replacement, recovery, tests, and operational proof.

The recorded license reading is:

- Tetragon userspace is Apache-2.0. Its `bpf/` directory is generally
  `GPL-2.0-only OR BSD-2-Clause`, but specific included headers are GPL-only.
  `bpf/lib` is not GPL-only, yet any reused dependency closure requires a
  per-file audit.
- Tetragon's `bpf/libbpf` directory is only a copied header subset. Actual
  upstream libbpf is dual BSD-2-Clause/LGPL-2.1; Mithril selects the
  BSD-2-Clause option for the loader dependency when available and approved.
- KubeArmor userspace is Apache-2.0, while important BPF sources identify as
  GPL-2.0 and several headers require provenance review.
- Falco userspace is Apache-2.0. `falcosecurity/libs/driver` is dual
  `GPL-2.0-only OR MIT`; `libpman` and the libscap adapter are Apache-2.0.
- BPF LSM programs must be GPL-compatible. Mithril-owned BPF should therefore
  use an approved GPL-compatible dual license such as
  `GPL-2.0-only OR BSD-2-Clause`, while Rust userspace remains under the
  separately selected Erebor distribution license.

The ELF `license` section controls kernel GPL-compatibility checks; it does not
replace the source file's copyright license. A GPL-compatible BPF object and a
separately licensed userspace loader can coexist, but distribution obligations
for every copied or modified BPF source remain explicit Phase 0 work.

Primary external references:

- [KubeArmor documentation](https://docs.kubearmor.io/kubearmor)
- [KubeArmor v0.5 BPF-LSM release notes](https://docs.kubearmor.io/kubearmor/release-notes/releases/v0.5)
- [KubeArmor v0.11 deployment components](https://docs.kubearmor.io/kubearmor/release-notes/releases/v0.11)
- [Falco architecture and capabilities](https://falco.org/docs/)
- [Falco event sources and cross-source limitation](https://falco.org/docs/concepts/event-sources/)
- [Falco dropped-event handling](https://falco.org/docs/concepts/event-sources/kernel/dropped-events/)
- [Tetragon events](https://tetragon.io/docs/concepts/events/)
- [Tetragon TracingPolicy reference](https://tetragon.io/docs/reference/tracing-policy/)
- [Tetragon enforcement semantics](https://tetragon.io/docs/concepts/enforcement/)
- [Tetragon persistent enforcement](https://tetragon.io/docs/concepts/enforcement/persistent-enforcement/)
- [Tetragon BPF directory licensing](https://github.com/cilium/tetragon/blob/main/bpf/COPYING)
- [Falco libraries subcomponent notices](https://github.com/falcosecurity/libs/blob/master/NOTICES)
- [Linux kernel BPF licensing](https://docs.kernel.org/bpf/bpf_licensing.html)
- [Upstream libbpf](https://github.com/libbpf/libbpf)
- [Rust libbpf bindings and Cargo skeleton tooling](https://github.com/libbpf/libbpf-rs)
- [Cilium component overview](https://docs.cilium.io/en/stable/overview/component-overview/)
- [Cilium eBPF network datapath](https://docs.cilium.io/en/stable/network/ebpf/intro/)
- [Cilium Layer 7 policy and proxy behavior](https://docs.cilium.io/en/stable/security/policy/layer7/)
- [Hubble internals](https://docs.cilium.io/en/stable/internals/hubble/)

## Product findings

### KubeArmor

KubeArmor is strongest as local workload mandatory access control. Its policy
selects Kubernetes workloads and describes process execution, file access,
network protocols and DNS, capabilities, and audit-only syscall conditions.
It can compile supported rules into BPF LSM, AppArmor, or SELinux enforcement.

Its current BPF source includes LSM hooks for:

- executable loading;
- file open and permission;
- path mutation;
- capability checks;
- socket creation, connect, accept, and DNS sendmsg; and
- selected protection presets.

Its BPF-LSM container-policy key is based on PID and mount namespace identity,
with rule keys containing target and source paths. Its userspace monitor also
maintains a container/host-PID process map for event enrichment.

This is useful code and design evidence, but it is not Mithril's identity model.
A path-oriented `fromSource` rule cannot distinguish two identical Python,
shell, or curl branches in the same Pod when their security role is determined
by ancestry rather than executable path.

KubeArmor's normal Kubernetes installation also contains more operational
owners than Mithril wants: operator, snitch, controller, per-node daemon, and
relay. Mithril must not reproduce that deployment merely to reuse its LSM work.

### Falco

Falco is strongest as a rule and detection ecosystem:

- syscall fields and stateful enrichment;
- rules, macros, lists, exceptions, tags, and priorities;
- a large body of community detection content;
- plugins for non-syscall sources;
- output integrations; and
- explicit syscall-drop metrics and actions.

Falco Core is not a pre-effect enforcement engine. Its own model is monitor,
evaluate, and alert, with a separate downstream response component when
desired. Falco also assigns each rule to one event source and explicitly does
not correlate across event sources.

Mithril therefore should reuse detection knowledge and compatibility semantics,
not Falco's privileged collector. Running Falco beside Mithril would duplicate
syscall/process gathering and still leave Mithril responsible for cross-source
causality and response.

### Tetragon

Tetragon is the strongest implementation reference for Mithril's initial node
plane because it already supplies:

- CO-RE BPF loading and sensor lifecycle;
- process clone, exec, and exit events;
- stable process execution IDs and parent execution IDs;
- cgroup, container, Pod, node, and Kubernetes enrichment;
- generic kprobe, fentry, tracepoint, uprobe, USDT, and LSM hook policies;
- in-kernel selectors and event filtering;
- gRPC and JSON event APIs;
- metrics, bug diagnostics, and kernel-version test machinery; and
- operation override, signal, and pinned enforcement mechanisms.

Its process cache intentionally tracks thread groups rather than every task
thread. Mithril needs task-specific effect attribution, task-local inherited
roles, exact subtree response, and explicit PID-reuse proof. Those are
Mithril-owned requirements that prevent Tetragon's Go daemon and event model
from becoming the product chassis.

Tetragon's public TracingPolicy is intentionally generic and kernel-oriented.
Mithril must not make customers author raw kernel hook specifications for normal
protection. Mithril profiles compile through a Rust-owned policy compiler into
Mithril-owned maps and program configuration.

### Cilium and Hubble

Cilium is the strongest network datapath in this comparison:

- workload security identities;
- L3/L4 network policy;
- DNS/FQDN policy;
- cgroup/socket and TC BPF enforcement;
- service and routing integration;
- packet and flow verdicts; and
- optional L7 policy and visibility through Envoy.

That capability comes with ownership of cluster networking and CNI behavior.
Mithril cannot silently install or replace a customer's CNI to obtain network
evidence. Mithril also cannot require Envoy or TLS termination.

Mithril must implement a small, security-specific process/socket plane that
works with any CNI. When Cilium and Hubble already exist, an optional adapter
may provide higher-quality packet, identity, DNS, and policy-verdict evidence.

## Why Mithril owns the Rust loader and userspace

No inspected upstream product has Mithril's complete correctness boundary.
Forking one would save its existing userspace implementation while forcing
Mithril's identity, evidence, coverage, correlation, and response contracts
through an architecture designed for a different product.

| Requirement | KubeArmor | Tetragon | Falco | Mithril decision |
| --- | --- | --- | --- | --- |
| local LSM policy | strongest existing fit | generic LSM and override machinery | not a pre-effect enforcement engine | reimplement the required hooks and policy maps |
| process lifecycle | useful but path/PID-oriented | strongest implementation reference | broad syscall state | implement exact task/process/execution identity in Rust plus owned BPF |
| BPF loading | Go with `cilium/ebpf` | Go with `cilium/ebpf` | C `libpman` with libbpf | Rust `libbpf-rs`/`libbpf-cargo` over upstream libbpf |
| Kubernetes enrichment | present | strong and process-coupled | enrichment through libsinsp/plugins | implement only the identity resolution Mithril requires |
| detection content | policy examples | tracing policies | strongest rule ecosystem | translate selected content into Mithril-native rules |
| distributed graph and response | absent | absent | absent | Rust-owned Mithril Control |
| Runtime reuse | not designed for it | not designed for it | not designed for it | one shared Rust sensor with a watch-only Runtime mode |

Tetragon remains the primary behavioral and test reference for lifecycle,
sensor loading, cgroup attribution, kernel compatibility, persistent
enforcement, and diagnostics. KubeArmor remains the primary reference for
BPF-LSM hook coverage and policy-map compilation. Falco remains the primary
reference for syscall extraction, drop handling, event schemas, and detection
content.

Mithril reimplements the product boundary instead of performing a clean-room
rewrite that ignores known solutions. Appropriately licensed, independently
useful BPF helpers may be adapted with provenance. Behavioral fixtures and
failure cases should be reproduced as Mithril tests. Upstream code is not
copied merely to reduce initial line count.

This removes the durable upstream daemon, event contract, process cache,
policy API, and release model from Mithril. The remaining Rust owner must prove
the same kernel portability, verifier behavior, link/map lifecycle, loss
accounting, recovery, and performance properties before the simplification is
accepted.

## Target deployment

```text
Each protected Linux node
┌─────────────────────────────────────────────────────────────┐
│ mithril-node: one privileged Rust binary / one DaemonSet Pod │
│                                                             │
│ Rust/libbpf BPF lifecycle owner                             │
│ task/process/effect graph                                   │
│ CRI/cgroup/Kubernetes identity resolver                     │
│ signed profile compiler and local policy-map writer         │
│ event merge, local spool, coverage, and response actuator   │
│                                                             │
│                    one outbound mTLS stream                 │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│ Mithril Control: Erebor SaaS or one self-hosted service      │
│                                                             │
│ fleet/configuration      immutable evidence                 │
│ identity/causal graph    detection and replay               │
│ investigation API       response authorization/coordinator  │
│ Kubernetes, cloud, IdP, mesh, VCS and connector adapters    │
└─────────────────────────────────────────────────────────────┘
```

For SaaS, the customer installs only `mithril-node` and the Kubernetes
configuration needed to authenticate it. For self-hosting, the same Helm
release may also install Mithril Control. Mithril Control is not a privileged
kernel gatherer.

## Target `erebor` monorepo and shared sensor ownership

The eventual repository rename is:

```text
erebor/
├── crates/
│   ├── erebor-runtime-*/          Runtime product crates
│   ├── erebor-linux-sensor-*/     shared Rust loader, raw ABI and host owner
│   ├── mithril-node-*/            defender node identity, policy and response
│   └── mithril-control-*/         fleet, graph, connector and authorization
├── bpf/
│   └── erebor-linux-sensor/       owned C CO-RE programs and headers
├── examples/
├── integrations/
└── docs/
```

Exact crate splits remain implementation work, but the durable ownership does
not:

- shared crates own only kernel program lifecycle, native identity primitives,
  raw event decoding, sequence/loss truth, and scoped subscription;
- Runtime crates own Runtime Session binding, agent-action interpretation, and
  Runtime audit integration;
- Mithril node crates own node-wide enrichment, profile enforcement, coverage,
  evidence spooling, and local response;
- Mithril Control crates own distributed causality, provider connectors,
  investigation, authorization, and coordinated response; and
- BPF sources expose one versioned raw ABI that neither Runtime nor Mithril
  exposes directly as its public product API.

The repository move is not part of this documentation edit. It requires an
approved migration plan that preserves Git history, package names, releases,
CI, documentation links, and downstream consumers.

### One active host owner

The same source code must not become two competing loaders on a host:

1. If Mithril is installed, `mithril-node` owns the BPF links, maps, pin root,
   sequence space, and raw event stream. Runtime uses an authenticated local
   subscription scoped to its agent cgroups and receives observation only.
2. If Mithril is absent, Runtime may instantiate the shared Rust sensor in
   `runtime-observe` mode for Runtime-owned agent cgroups.
3. Host ownership is acquired through a versioned pin-root lease and startup
   reconciliation. A second owner refuses overlapping attachment rather than
   silently duplicating events.
4. A handoff proves compatible ABI and map generations before transferring
   ownership. Unsupported handoff reports a coverage gap and performs an
   explicit restart; it never pretends continuity.
5. Runtime cannot request node-wide data, enforcement-map writes, socket
   fencing, task termination, or Mithril response through the subscription.

This is one gatherer implementation and, on a co-resident host, one active
gatherer instance. It is not a hidden Runtime collector beside Mithril.

## `mithril-node` ownership

`mithril-node` is one process with the following internal owners.

### Kernel program manager

Owns:

- CO-RE object selection and loading;
- upstream libbpf ownership through Rust `libbpf-rs`/`libbpf-cargo`;
- BPF links and pinned maps under one Mithril pin root;
- program and map generation;
- feature probes;
- atomic policy-generation activation;
- old-generation rollback;
- startup reconciliation;
- task-iterator bootstrap and readback; and
- link, map, verifier, and helper health.

No other Mithril component may independently attach overlapping node programs.
The shared sensor host owner exposes a narrow Rust API; it does not expose raw
libbpf handles or writable enforcement maps to Runtime or an agent workload.

### Native identity owner

Builds and retains:

- task/thread identity;
- thread-group/process identity;
- execution-image history;
- parent task and parent process;
- bounded ancestry;
- cgroup, PID namespace, mount namespace, and network namespace identity;
- container and workload binding; and
- lineage completeness state.

The native identity owner must not use PID alone as durable identity.

### Effect owner

Normalizes kernel observations into:

- executable effects;
- filesystem effects;
- credential-file reads;
- memory/code-loading effects;
- socket and packet effects;
- device and ioctl effects;
- capability and credential transitions;
- ptrace and process-control effects;
- namespace and mount effects; and
- kernel attack-surface effects such as BPF, perf, keyring, and module access.

### Policy owner

Receives a signed Mithril profile generation, validates it, compiles it into
local maps, activates it atomically, and proves the installed generation.
Policy failure must not silently remove a previously active enforcement
generation.

### Evidence and coverage owner

Owns:

- one normalized userspace event pipeline;
- raw kernel sequence and loss evidence;
- identity-resolution failure evidence;
- an append-only local spool after userspace receipt;
- retry and backpressure;
- one outbound mTLS stream;
- acknowledgement checkpoints; and
- coverage intervals.

### Local response owner

Executes only typed, authorized actions:

- deny protected effects for one task or process lineage;
- fence known sockets and future sockets for a lineage;
- terminate an exact task or process through pidfd where supported;
- freeze or fence a cgroup with an explicit wider blast radius;
- preserve process, file, socket, and policy evidence; and
- verify a named postcondition.

It does not execute arbitrary shell commands supplied by Mithril Control or a
defensive agent.

## Kernel program set

One gatherer loads multiple purpose-specific programs.

| Program family | Candidate attachment | Required result |
| --- | --- | --- |
| task birth | BPF LSM `task_alloc` and a proved fork fallback | child receives an inherited task/role label before it can perform protected work |
| process lifecycle | scheduler fork, exec, and exit tracepoints or stable fentry equivalents | exact process and execution history with explicit gaps |
| executable denial | BPF LSM `bprm_check_security` and code-loading hooks | unsupported image or role transition is denied before execution |
| filesystem denial | BPF LSM file, inode, path, mmap, and related hooks | protected read/mutation/code-loading effect is denied before completion |
| privilege/process control | BPF LSM capable, ptrace, credential, namespace, mount, BPF, perf, and related hooks | role-specific escape and privilege effects are observed or denied |
| device control | cgroup-device BPF plus selected file/ioctl/security hooks | device access is attributed and denied at the narrowest supported boundary |
| socket decision | BPF LSM socket hooks and cgroup connect/bind/sendmsg hooks | connection attempt is attributed to the exact task/process role and decided locally |
| socket continuity | BPF socket storage | socket retains its originating lineage after the creating task changes or exits |
| packet containment | cgroup-skb or TC attachment selected by capability probe | existing and future prohibited traffic is fenced with a visible scope |
| health | per-CPU sequence/loss and generation maps | observation gaps and installed enforcement generation are externally provable |

The exact hook set is a Phase 0/3 deliverable because hook availability and
arguments vary across kernel families. The guarantee, not one hard-coded hook,
is the stable requirement.

### Runtime observation use of the program set

Runtime reuses only the observation portions needed to watch agent actions:

- process and execution lifecycle;
- relevant filesystem and credential access;
- namespace, mount, privilege, process-control, device, and kernel-surface
  attempts;
- socket creation, connect, bind, sendmsg, DNS, and socket continuity; and
- sequence, loss, capability, and coverage evidence.

In `runtime-observe` mode:

- programs are filtered to Runtime-owned agent cgroups as early as the
  supported hook permits;
- LSM observation programs return the prior/allow result and cannot consult
  Mithril deny generations;
- pre-effect denial, emergency lineage deny, packet fence, kill, freeze, and
  response programs are not attached or are inaccessible through the
  mode-specific loader API;
- no Mithril profile signing key, control credential, response credential, or
  writable protection map is present;
- Runtime receives immutable native identity coordinates and adds its own
  Session/action correlation in Runtime-owned code; and
- coverage states exactly which effect classes and intervals were watched.

Tests must attempt to cross the mode boundary from a compromised Runtime agent,
the Runtime daemon's unprivileged interfaces, stale pinned maps, and a forged
local subscriber. Watch-only is a physical authority reduction, not a policy
convention.

## Mithril-owned identity model

The minimum identity schema is:

```text
NodeIdentity {
  tenant_id
  cluster_uid
  node_uid
  node_boot_id
  sensor_instance_id
}

TaskIdentity {
  node_identity
  task_cookie
  native_tid
  start_boottime
  process_lineage_id
  parent_task_cookie
  role_id
  profile_generation
}

ProcessIdentity {
  node_identity
  process_lineage_id
  native_tgid
  leader_task_cookie
  parent_process_lineage_id
  cgroup_id
  container_id
  pod_uid
  lineage_state
}

ExecutionIdentity {
  process_lineage_id
  exec_generation
  mount_id
  device
  inode
  image_digest_or_measurement
  path_for_presentation
}
```

`lineage_state` is at least:

```text
complete | bootstrapped | missing_parent | source_gap
```

Required semantics:

- a new thread receives a task identity but shares its process identity;
- a new thread group receives a new process lineage identity;
- exec changes execution identity but does not pretend the process was forked;
- a child inherits its role/profile before it performs protected effects;
- PID and TID reuse never join unrelated subjects;
- orphaning and reparenting do not rewrite historical parentage;
- bootstrap of already-running tasks is visible as bootstrap, not complete
  birth-time observation; and
- response lookup uses stable identity plus boot and policy generation, not a
  stale numeric PID.

## Policy and enforcement model

The customer-facing profile describes workload roles and physical effects. It
does not expose raw kprobe names or vendor event fields.

Conceptual shape:

```text
WorkloadProcessProfile {
  profile_id
  profile_version
  target_workload_identity
  image_and_mount_constraints
  root_role
  role_transitions[]
  executable_effects[]
  filesystem_effects[]
  socket_effects[]
  device_and_privilege_effects[]
  observation_requirements
  enforcement_mode
  expiry
  signature
}
```

The policy compiler produces numeric decision keys where possible:

```text
role + mount/object identity + operation
role + executable identity + resulting role
role + destination address/port/protocol + socket identity
role + device/privilege class + operation
```

Paths are policy authoring and presentation inputs. Path strings alone are not
strong executable or file identity because rename, bind mounts, aliases,
overlay filesystems, and mutation can change their meaning.

Modes:

```text
observe
simulate
enforce
emergency_containment
```

Only a signed, compatible, non-expired generation may enter `enforce`.
`simulate` computes the decision and evidence without applying denial.

## Network design

Mithril's built-in network plane is deliberately smaller than Cilium.

It must provide without a CNI dependency:

- task/process attribution for socket creation and connection attempts;
- TCP and UDP destination address, port, protocol, cgroup, and network
  namespace;
- bind/listen and accepted-socket evidence where supported;
- DNS query evidence and bounded FQDN policy where the resolver path is
  observable;
- socket-local lineage storage;
- immediate denial of new prohibited connections;
- a packet or socket fence for already-created channels during containment;
- explicit loss and coverage; and
- coexistence tests for common CNIs.

It does not provide:

- Pod networking;
- service load balancing;
- routing or encapsulation;
- a service mesh;
- universal L7 parsing; or
- TLS termination.

### Optional Cilium/Hubble integration

When already installed, Mithril may consume:

- workload and security identity;
- packet flow and drop verdicts;
- DNS/FQDN history;
- service identity;
- existing Cilium policy state; and
- Hubble node/source health.

This is corroborating or higher-fidelity network evidence. Mithril's guaranteed
local process/socket enforcement cannot depend on it.

### Opaque TLS limit

Kernel and packet evidence cannot distinguish two application operations
inside the same encrypted connection. Mithril must not claim that it can
distinguish `git clone` from `git push`, or one provider API verb from another,
from destination metadata alone.

Available controls are:

1. allow or deny the entire destination/channel at the kernel boundary;
2. use a distinct provider capability or credential when the provider supports
   it;
3. correlate with authoritative server/provider audit;
4. invoke a provider-side preventive or response API; or
5. offer TLS termination or an application-aware intermediary only as an
   explicit optional redesign, never as Mithril's baseline.

## Evidence, correlation, and Mithril Control

Node-local parentage remains local kernel fact. Cross-node causality is formed
from typed, independently proven edges:

```text
node process
  → credential read/use
  → socket/request
  → Kubernetes or provider audit event
  → resource UID/request ID
  → controller owner reference or scheduler binding
  → remote container/cgroup
  → remote node-local process
```

Mithril Control owns:

- authenticated node and source registry;
- raw immutable evidence intake;
- normalized observations;
- source sequence and deduplication;
- coverage intervals;
- node-local graph materialization;
- distributed typed causal edges;
- versioned distributed lineage views;
- deterministic detection and replay;
- investigation queries;
- response authorization;
- distributed response coordination; and
- postcondition results.

External connectors are modules or workers inside Mithril Control's operational
boundary, not additional privileged node gatherers. If a provider supplies
events through an existing queue, audit sink, or API, Mithril consumes that
source without installing a second Linux sensor.

Kubernetes audit requires an actual audit source. A normal Kubernetes watch is
not an audit stream. Supported deployment paths must be explicit:

- managed-cluster audit pulled from the provider's logging service;
- API-server audit webhook sent directly to Mithril Control; or
- self-managed audit files read by the same `mithril-node` on the relevant
  control-plane node.

Missing audit is a coverage gap. It must not be silently replaced with inferred
API semantics.

## Coverage model

Every finding and response is evaluated against source coverage.

```text
CoverageInterval {
  source_id
  node_or_authority_scope
  start
  end
  state
  capability_generation
  policy_generation
  first_sequence
  last_sequence
  dropped_or_missing_count
  reason
}
```

States:

| State | Meaning | Permitted claim |
| --- | --- | --- |
| `observing` | required programs, identities, queues, and stream are healthy | expected evidence was available within documented limits |
| `enforcing_without_observation` | local rule remains pinned but events cannot be consumed or delivered | enforcement remained installed; complete history cannot be claimed |
| `degraded` | event loss, backlog, identity failure, source delay, or partial capability | findings carry reduced confidence and negative conclusions are restricted |
| `uncovered` | required source or policy is absent or untrusted | no negative conclusion is allowed |

Ring-buffer reservation failure, perf-buffer loss, userspace channel overflow,
spool exhaustion, sequence discontinuity, policy-map failure, and connector
delay all create evidence. They are not debug-only log messages.

## Response model

Responses are typed physical operations, not arbitrary remote commands.

```text
ResponseCommand {
  response_id
  tenant_id
  authorized_subject
  target_identity
  target_generation
  action_type
  expected_scope
  expiry
  approval
  idempotency_key
  required_postconditions[]
}
```

Local progression:

```text
exact task
  → exact process lineage
  → known and future lineage sockets
  → containing cgroup
  → workload/controller
```

Each wider step states the additional blast radius. A cgroup freeze is not
represented as an exact-process response.

Distributed response coordinates independently authorized actions. It does
not treat a remote process as a Linux child. A result is:

```text
verified | partial | failed | unknown
```

`verified` requires every required local and provider postcondition to succeed
under healthy required coverage through the response watch interval.

## Upstream adoption boundaries

### Tetragon: research, test oracle, and selective BPF adaptation

Study continuously:

- `bpf/process`: lifecycle, generic event machinery, selectors, path and
  argument extraction, task/process helpers, and enforcement techniques;
- `pkg/sensors`: BPF object, map, link, policy-generation, and recovery
  lifecycle;
- `pkg/process`: process cache behavior, ordering, retries, and missing-parent
  handling;
- `pkg/cgidmap` and cgroup packages: container/cgroup identity;
- Kubernetes watchers and workload enrichment;
- ring-buffer observer, metrics, diagnostics, capability probes, and kernel
  test harness; and
- persistent enforcement and upgrade behavior.

Do not fork or retain as Mithril's product chassis:

- the Tetragon Go daemon;
- Go sensor, observer, process-cache, or Kubernetes packages;
- raw TracingPolicy as the public or internal Mithril policy model;
- Tetragon event protobuf as the Mithril evidence contract;
- Tetragon process cache identity as response identity; or
- Tetragon's signal action as proof of prevented effect.

`tetragon/bpf/lib` is a private header collection, not libbpf. Most inspected
files are dual GPL-2.0/BSD-2-Clause, but their dependency closure contains
exceptions. Mithril may adapt a small independently useful header only when:

- its SPDX, copyright, upstream revision, and transitive include licenses are
  recorded;
- it does not import Tetragon's map names or event ABI by accident;
- a Mithril-owned Rust loader and decoder test it across the supported kernel
  matrix; and
- the resulting source is easier to maintain than a small Mithril-owned
  equivalent.

Behavioral parity matters more than textual reuse. Every selected mechanism
needs a Mithril fixture for success, verifier rejection, feature absence, event
loss, restart, and upgrade.

### KubeArmor: study and selectively reimplement

Study:

- BPF LSM hook selection;
- path and object extraction;
- container namespace to policy-map binding;
- map-of-maps policy updates;
- process/file/network/capability policy compilation;
- DNS enforcement;
- AppArmor and SELinux fallback behavior; and
- platform capability detection.

Do not copy the complete architecture:

- operator;
- snitch;
- controller;
- relay;
- feeder;
- KubeArmor CRDs as Mithril's public policy; or
- PID/mount-namespace plus path/source rule identity as Mithril's final model.

The Mithril implementation uses task-role and immutable object identity.
KubeArmor's approximately 6,300 lines of BPF C/header code are small enough
that the default is to reimplement required mechanisms against Mithril-owned
maps and ABI. Direct source reuse is exceptional and requires per-file license
review plus proof that it preserves Mithril's stronger identity and evidence
contracts.

### Falco: content compatibility, not collection

Implement an importer for a documented subset of:

- rules;
- macros;
- lists;
- exceptions;
- priorities;
- tags; and
- output field references.

Every imported rule records:

- original artifact and version;
- source event type;
- field mapping;
- unsupported or weakened predicates;
- Mithril-native equivalent;
- required coverage; and
- replay tests.

Do not deploy or embed:

- Falco's kernel module or eBPF driver;
- `libpman` or libscap as Mithril's primary loader/event pipeline;
- a second syscall stream;
- Falcosidekick;
- Falco Talon; or
- Falco's single-source correlation boundary.

Falco's `libpman` is a real reusable C library and its modern BPF driver is
permissively available under the MIT side of its dual license. It is still not
selected because it would replace the Rust loader boundary, impose Falco's
syscall event ABI, and duplicate Tetragon-derived observation mechanisms that
Mithril must already implement for enforcement identity. Embedding Falco's
C++ rule engine likewise adds an FFI lifecycle while Mithril still must build
cross-source temporal and causal evaluation. Either choice may be revisited
only as an optional compatibility component with a measured benefit and no
second privileged gathering plane.

### Cilium/Hubble: optional adapter

Do not fork Cilium or take over the CNI. Use stable APIs when Cilium is already
present. The adapter must:

- discover availability;
- authenticate to the existing Hubble or Cilium endpoint;
- preserve Cilium node, identity, flow, verdict, and time fields;
- report independent source coverage;
- avoid double-counting a Mithril socket event and a Hubble flow as two effects;
- survive absence or removal without weakening Mithril's baseline network
  enforcement; and
- never enable Envoy or L7 interception without explicit operator adoption.

## License and provenance gate

Repository-level license labels are insufficient. Phase 0 must inventory:

- every copied source file and its SPDX identifier;
- the complete transitive include closure for every reused BPF header;
- generated BPF object provenance;
- vendored dependencies and notices;
- patent and trademark obligations;
- required source redistribution;
- compatibility with Mithril's intended distribution; and
- the upstream security-update process.

The inspected KubeArmor userspace is Apache-2.0, while important BPF files are
marked GPL-2.0. Inspected Tetragon userspace is Apache-2.0; its BPF directory is
generally dual BSD/GPL with file-level exceptions. Falco userspace is
Apache-2.0 and its driver is dual MIT/GPL. Upstream libbpf is dual
BSD-2-Clause/LGPL-2.1. No code is copied and no compiled BPF object is
distributed until counsel or the project's approved license process accepts
the exact source and dependency closure.

The default owned-code license boundary is:

| Boundary | Intended treatment |
| --- | --- |
| Mithril and shared Rust userspace | Erebor-selected userspace license, independent of copied GPL BPF code |
| Mithril-owned BPF LSM and related C | approved GPL-compatible dual license, expected `GPL-2.0-only OR BSD-2-Clause` |
| upstream libbpf | consume under approved BSD-2-Clause option |
| adapted upstream source | preserve original notices and selected license; record modifications and revision |
| generated BPF objects | reproducibly map every object to its exact source and toolchain |

This plan is technical guidance, not a legal conclusion.

## KubeArmor's “first Kubernetes BPF-LSM engine” claim

KubeArmor's public wording is “First K8s Security Engine to Leverage BPF-LSM.”
The technical basis is:

1. BPF LSM was new in the upstream Linux 5.7 era.
2. KubeArmor v0.5 added BPF-LSM enforcement to an existing Kubernetes workload
   policy.
3. The same Kubernetes policy surface could select Pods and compile into
   BPF-LSM or another LSM backend.
4. KubeArmor joined Kubernetes selectors, container-runtime identity, dynamic
   policy updates, enforcement, and telemetry.

“Kubernetes-native” describes its CRDs, label selectors, workload lifecycle,
and reconciliation. It is not a Kubernetes-specific BPF-LSM kernel mode.

The source confirms KubeArmor's claim and its historical basis. This plan does
not independently assert that no earlier project performed any similar
integration. Historical priority also does not make BPF-LSM exclusive to
KubeArmor.

## What Mithril adds beyond KubeArmor

Mithril is not differentiated by having another file or process deny rule.

Consider one Pod with a long-running controller and many concurrent jobs:

```text
controller
  ├─ job A → python → shell → curl
  └─ job B → python → shell → curl
```

Both branches may have identical executable paths. KubeArmor can select the
Pod and use source executable paths, but path identity does not express that
these are different inherited process roles.

Mithril assigns and propagates:

```text
lineage A: role=dataset-conversion
lineage B: role=controller-maintenance
```

Mithril can then:

1. attribute a mounted credential read to lineage A;
2. attach lineage A to the resulting socket;
3. join the socket with a Kubernetes audit request;
4. join the request to a created object UID and owner reference;
5. follow the controller/binding/container transition onto another node;
6. join the remote container to its independently observed process root;
7. show one versioned distributed causal view;
8. fence lineage A and its sockets without claiming that lineage B was
   isolated;
9. verify the local and remote postconditions; and
10. report `partial` or `unknown` if a node, source, or branch is unresolved.

Mithril-specific product capabilities are:

- task-local inherited enforcement roles;
- explicit process and execution identity across PID reuse;
- thread-aware effect attribution;
- multi-node, multi-source causal correlation;
- raw durable evidence and replay;
- coverage truth;
- exact and progressively wider response scopes;
- response simulation, approval, expiry, idempotency, and postconditions; and
- narrow agent-native investigation and response tools for defenders.

KubeArmor remains ahead of a new Mithril implementation in mature AppArmor and
SELinux fallback, platform coverage, established CRDs, policy examples, and
operator experience. Those are adoption risks to close, not features to deny.

## Kernel and platform support tiers

BPF LSM support is not determined by the displayed kernel version alone. Full
support requires the configured and active LSM, BTF/CO-RE viability, required
BPF program and map types, helper availability, cgroup mode, and usable hook
arguments. Distribution backports can move capabilities across nominal kernel
versions.

Mithril reports one of these tiers per node:

| Tier | Requirements | Permitted claim |
| --- | --- | --- |
| `full` | required lifecycle hooks, BPF LSM, task/socket storage or proved equivalent, cgroup BPF, packet fence, BTF, and healthy evidence path | complete documented Mithril observation and selected pre-effect enforcement |
| `enforce-reduced` | some pre-effect backends available, but one or more required effect classes are missing | only named effect classes are enforced; missing classes are explicit |
| `observe` | lifecycle and selected trace sources available without required denial hooks | detection and evidence only; no prevention claim |
| `unsupported` | stable identity or required trusted observation cannot be provided | node is not represented as protected |

AppArmor or SELinux compatibility may later improve `enforce-reduced` coverage.
It cannot be declared equivalent until object identity, policy generation,
telemetry, and denial tests prove the same guarantee.

## First-process race and container-runtime integration

Observing a cgroup or CRI event after a container has started is not enough to
claim that its first user process was protected.

Strict-from-first-exec mode requires a Mithril-owned OCI, CRI, or NRI integration
that:

1. lets the OCI/container runtime create the container namespaces and cgroup;
2. resolves the created container and cgroup identity;
3. binds the signed Mithril profile;
4. verifies the installed map generation and required BPF links; and
5. permits the runtime to execute the user process only after that proof.

This integration is served by the same `mithril-node` binary over a local Unix
socket or runtime hook. It is not another gatherer and does not change the
protected application.

The shared sensor's `runtime-observe` mode does not use this gate to authorize
or deny execution. Runtime may use its own session startup ordering to begin
observation before an agent task runs, but loss of that observation is reported
as Runtime coverage degradation rather than a Mithril enforcement result.

Without strict runtime coordination, Mithril may protect already-running
workloads and observe startup, but it must report the unprotected startup
interval.

## Performance design

Mithril must not gather every syscall or perform central decisions for normal
allowed operations.

Required practices:

- attach at semantic decision points rather than ptrace entry/exit stops;
- use in-kernel selectors to discard irrelevant events;
- use numeric task, object, socket, and policy keys;
- avoid full path reconstruction for every ordinary read;
- emit lifecycle changes, protected effects, violations, policy changes, and
  intentionally selected allowed observations;
- rate-limit only after preserving loss/coverage truth;
- keep enforcement local during control-plane outage;
- separate bounded hot-path maps from durable userspace evidence; and
- benchmark both allowed and denied paths.

Initial performance acceptance targets are set in Phase 0. They must cover:

- process fork/exec rate;
- file-open/read/write hot paths;
- TCP and UDP connection rate;
- DNS rate;
- ring-buffer saturation;
- control-plane disconnection;
- policy generation swap; and
- coexistence with common CNIs and workload runtimes;
- scoped `runtime-observe` overhead on an interactive agent workload; and
- Runtime and Mithril co-residency through one active sensor owner.

No target is accepted solely because it is faster than ptrace. The node agent
must meet an explicit CPU, memory, latency, drop, and recovery budget.

## Installation and operations target

The target UX below is a design target, not a claim that these commands exist:

```text
helm upgrade --install mithril erebor/mithril \
  --namespace erebor-mithril \
  --create-namespace \
  --set control.endpoint=...

mithril status
mithril capabilities
mithril coverage
mithril profiles simulate ...
mithril findings replay ...
mithril responses inspect ...
```

The Helm release installs:

- one `mithril-node` DaemonSet;
- one ServiceAccount and the minimum required RBAC;
- configuration and trust material;
- an optional Mithril Control Deployment for self-hosting; and
- optional CRDs only if GitOps policy authoring is adopted later.

It does not require:

- a separate operator;
- an admission webhook;
- a relay or exporter;
- an event sidecar;
- an application sidecar;
- Cilium;
- Falco;
- KubeArmor; or
- Tetragon as a separately visible product.

The future `erebor` monorepo may produce both Runtime and Mithril release
artifacts. That does not require installing both products. A Runtime-only host
installs only the shared observation capability needed by Runtime; a
Mithril-protected host installs only one active node sensor and offers Runtime
the scoped local subscription when Runtime is also present.

Operational requirements:

- startup performs automatic capability probing;
- status shows the real per-node support tier;
- default mode is observe;
- enforcement activation is signed and auditable;
- upgrades use atomic program/map generations;
- rollback restores a previously verified generation;
- control-plane outage does not silently unload enforcement;
- evidence outage changes coverage state;
- diagnostics package node capabilities, links, maps, generations, loss, queue,
  and spool health without exposing secrets; and
- uninstall removes Mithril links, maps, hooks, and credentials predictably.

## Implementation phases

Every phase is a stop point. Future implementation requires explicit approval
for one phase at a time. Each phase must update this document with exact source
state, verification, and `Done`, `Not done`, or `Blocked`.

### Phase 0: upstream, license, kernel, and performance baseline

State: Not started.

Purpose: prove that a Rust-owned loader and userspace can preserve the required
upstream-derived kernel guarantees without adopting an upstream daemon as the
product chassis.

Scope:

- repeat source and per-file license inventory;
- select and pin candidate Rust, `libbpf-rs`, `libbpf-cargo`, libbpf, Clang,
  LLVM, and bpftool versions;
- inventory the exact Tetragon, KubeArmor, Falco, Linux selftest, and libbpf
  source and behavior references;
- decide each candidate BPF helper as adapt, reimplement, or reject, with
  transitive-license disposition;
- build a Rust vertical spike that loads owned C CO-RE lifecycle, LSM,
  cgroup/socket, and ring-buffer programs;
- enumerate Mithril-required hooks on the supported kernel matrix;
- probe BPF LSM, BTF, task/socket storage, cgroup v2/BPF, TC, and runtime hooks;
- prove `mithril-observe`, `mithril-protect`, and `runtime-observe` attachment
  and authority boundaries;
- prove one-owner detection and Runtime/Mithril co-resident subscription;
- define support tiers;
- establish allowed/denied operation baselines; and
- define CPU, memory, latency, event-loss, and recovery budgets.

Acceptance:

- every reused file has provenance and license disposition;
- every required guarantee maps to a tested hook or named missing capability;
- the Rust loader reports verifier and capability failures without an upstream
  Go or C daemon;
- `runtime-observe` cannot load or update denial/response state;
- a second overlapping loader refuses ownership and creates truthful coverage
  evidence;
- selected kernels have reproducible capability reports;
- baseline load and loss results are recorded;
- upstream research/update ownership is assigned; and
- no product capability is credited to an unverified upstream assumption.

Checkpoint: approve or reject the Rust/libbpf substrate and exact adapted source
set before creating production product code.

### Phase 1: one-binary node chassis

State: Not started.

Purpose: create one Rust Mithril node process and the shared sensor boundary
without yet introducing Mithril enforcement identity.

Scope:

- create the shared Rust loader/raw-ABI/host-owner crates and owned BPF source
  tree in the current monorepo;
- create Rust Mithril node, configuration, transport, metrics, and diagnostics
  crates;
- produce one `mithril-node` binary and image with no Tetragon, KubeArmor, or
  Falco daemon embedded;
- implement process exec/exit loading, decoding, cgroup/CRI/Kubernetes
  enrichment, sequence/loss evidence, and capability reporting;
- implement the authenticated scoped local observation subscription;
- implement `runtime-observe` as a mode-specific Rust authority surface;
- add one outbound mTLS transport boundary; and
- create a minimal one-DaemonSet Helm deployment.

Acceptance:

- one DaemonSet Pod per node observes process exec/exit;
- no second privileged collector is installed;
- all loader and node userspace production code in scope is Rust;
- owned BPF objects build reproducibly from recorded C/header sources;
- container, Pod UID, node, cgroup, and image enrichment works;
- one mTLS stream reconnects without duplicate accepted sequence;
- disabling the central connection does not crash the sensor;
- a Runtime-only fixture observes only its agent cgroup without any denial
  authority;
- a co-resident fixture uses `mithril-node` as the sole active loader and gives
  Runtime a scoped observation stream; and
- upstream-derived behavior fixtures and Mithril packaging tests pass.

Checkpoint: the Rust node chassis and shared watch-only boundary work before
Mithril identity is introduced.

### Phase 2: exact task and process identity

State: Not started.

Purpose: replace process-cache identity as Mithril's attribution and response
authority.

Scope:

- task birth/fork label inheritance;
- task and process lineage IDs;
- execution generations;
- task storage and proved fallback;
- thread, fork, exec, exit, orphan, bootstrap, and PID-reuse handling;
- task iterator/readback;
- Mithril identity protobuf/schema; and
- node-local graph and lineage completeness.

Acceptance:

- child role exists before the child executes protected code;
- threads share process identity but retain task identity;
- exec does not create false fork lineage;
- PID/TID reuse cannot target old identity;
- bootstrap and missing parents remain visible;
- loss creates `source_gap`;
- restart reconstructs or explicitly gaps live identity; and
- exact-task and exact-process lookup reject stale boot/generation coordinates.

Checkpoint: no enforcement until identity invariants pass hostile tests.

### Phase 3: effect observation and profile simulation

State: Not started.

Purpose: observe the physical effects Mithril will later deny, without changing
workload behavior.

Scope:

- executable, filesystem, credential, code-loading, privilege, process-control,
  namespace, mount, device, ioctl, socket, and kernel-surface observations;
- immutable object and executable identity;
- Mithril effect schema;
- profile compiler in observe/simulate mode;
- in-kernel filtering; and
- current-deployment learning and expected-role diff.

Acceptance:

- every effect is joined to exact task, process, execution, cgroup, container,
  Pod, node, profile, and coverage identity;
- two identical executable branches in one Pod remain distinguishable by
  lineage role;
- allowed-event volume stays within the Phase 0 budget;
- simulation records the decision and matched rule without denial;
- unsupported effect classes are explicit; and
- the unchanged Hugging Face reference worker completes legitimate work.

Checkpoint: review learned profiles and false positives before denial exists.

### Phase 4: signed pre-effect enforcement

State: Not started.

Purpose: turn reviewed profiles into local synchronous decisions.

Scope:

- signed profile validation;
- atomic compiled-map generation;
- BPF LSM and supported override denial;
- role transition;
- emergency lineage-root deny map;
- enforcement persistence and rollback; and
- denial evidence and postcondition.

Acceptance:

- prohibited executable never runs;
- prohibited file mutation leaves object content and metadata unchanged;
- prohibited credential read fails before bytes are returned for covered hooks;
- prohibited privilege/device operation fails;
- an allowed unchanged workload remains functional;
- stale, unsigned, expired, or incompatible profile is rejected;
- agent restart does not silently remove pinned enforcement;
- observation loss changes coverage state; and
- signal-only actions are never reported as prevented effects.

Checkpoint: enable only reviewed effect classes on selected canary nodes.

### Phase 5: process-aware network plane

State: Not started.

Purpose: provide CNI-independent socket policy and containment.

Scope:

- connect, bind, listen, accept, and UDP sendmsg coverage;
- task/process to socket storage;
- DNS observation and bounded domain policy;
- new-connection denial;
- existing-socket/packet fence;
- CNI coexistence; and
- explicit TLS semantic limit in findings.

Acceptance:

- prohibited new connection is denied before establishment;
- UDP send paths cannot bypass covered destination rules;
- socket lineage survives creator exit;
- emergency lineage fence stops covered existing and future traffic;
- Mithril works without Cilium;
- Mithril coexists with Cilium, Calico, and a baseline Kubernetes CNI;
- DNS loss or alternate resolver path changes coverage; and
- no finding claims clone, push, email, or API-verb semantics from opaque TLS.

Checkpoint: network enforcement remains a security plane, not a CNI.

### Phase 6: durable evidence, coverage, and recovery

State: Not started.

Purpose: make observation quality and recovery part of the security contract.

Scope:

- kernel sequence and loss counters;
- one userspace event merge;
- append-only local spool;
- acknowledgement and replay;
- coverage intervals;
- spool/backpressure policy;
- pinned generation recovery;
- diagnostics bundle; and
- corruption and disk-pressure behavior.

Acceptance:

- forced ring-buffer loss creates a bounded degraded interval;
- forced userspace queue loss is visible;
- central outage is replayed without duplicate durable observations;
- spool exhaustion follows a declared fail-open/fail-closed policy;
- enforcement-without-observation is distinguishable;
- corrupt local records are detected and isolated;
- restart reconciles links/maps/profiles and live tasks; and
- negative detections are suppressed when required coverage is absent.

Checkpoint: no multi-node correlation until source truth is reliable.

### Phase 7: Mithril Control and node-local graph ingestion

State: Not started.

Purpose: create the central evidence, fleet, investigation, and authorization
owner.

Scope:

- node/source authentication;
- immutable raw intake;
- normalized observation store;
- deduplication and ordering;
- coverage storage;
- node-local task/process/effect graph;
- signed profile distribution;
- investigation API; and
- read-only defensive-agent tools.

Acceptance:

- raw evidence can deterministically rebuild normalized records;
- duplicate delivery does not duplicate effects;
- tenant, cluster, node boot, and profile generation cannot cross-bind;
- node-local graph matches hostile fork/exec/thread fixtures;
- queries return evidence and coverage, not unsupported conclusions;
- profile distribution is signed and acknowledged; and
- a defensive agent receives no shell or implicit response authority.

Checkpoint: approve storage and authorization before external connectors.

### Phase 8: authoritative connectors and distributed causality

State: Not started.

Purpose: connect local compromise to Kubernetes and provider effects across
nodes.

Scope:

- Kubernetes audit and object history;
- cloud, identity, mesh, connector, message, artifact, and source-control
  adapters added one at a time;
- typed edge schemas;
- join strength and ambiguity;
- fan-out, late evidence, contradiction, and graph versioning; and
- Hugging Face `HF-008` through `HF-021` replay.

Acceptance:

- no remote process is represented as a kernel child;
- each cross-boundary edge names authoritative identifiers;
- weak time-only joins remain weak and visible;
- fan-out and late branches create new graph versions;
- missing audit/source coverage creates a gap;
- the Hugging Face chain is reconstructed only where published/available
  evidence supports it; and
- unrelated OpenAI and Hugging Face authority domains never merge.

Checkpoint: approve each connector's read and response authority separately.

### Phase 9: local and distributed response

State: Not started.

Purpose: provide narrow physical containment with honest result states.

Scope:

- exact task/process lineage denial;
- socket set and future-socket fence;
- pidfd termination;
- cgroup fence/freeze;
- Kubernetes/controller actions;
- provider actions;
- simulation, approval, idempotency, expiry, rollback, and watch windows; and
- distributed coordination over one graph version.

Acceptance:

- stale PID, boot, lineage, target generation, or graph version is rejected;
- exact-process response does not silently become whole-Pod response;
- wider actions show affected workloads and principals before approval;
- every actuator has a physical postcondition;
- controller replacement and late branches are watched;
- offline or outside-authority targets produce `partial` or `unknown`;
- repeated command is idempotent; and
- arbitrary shell execution is impossible through the response API.

Checkpoint: automatic response remains disabled until individually approved.

### Phase 10: optional compatibility and content

State: Not started.

Purpose: gain ecosystem value without changing Mithril's architecture.

Scope:

- Falco content importer and replay suite;
- optional Hubble adapter;
- optional Tetragon event compatibility input;
- optional existing-EDR corroboration;
- AppArmor/SELinux reduced-tier investigation; and
- provenance and duplicate-effect handling.

Acceptance:

- removing every optional adapter leaves baseline Mithril guarantees intact;
- imported Falco rules declare unsupported predicates;
- Hubble evidence has independent coverage and deduplication;
- no optional product becomes a required deployment;
- no optional adapter replaces the Rust loader, raw ABI, native identity, or
  single-owner boundary;
- fallback enforcement is not called equivalent without proof; and
- adapter compromise cannot install Mithril kernel policy or execute response.

Checkpoint: each optional integration receives separate product approval.

### Phase 11: production installation and fleet hardening

State: Not started.

Purpose: prove simple installation, upgrades, scale, and sensor self-protection.

Scope:

- prepare or execute the approved `erebor-runtime` to `erebor` repository
  migration without losing history or release ownership;
- build independent Runtime and Mithril artifacts from the monorepo;
- one Helm release and optional host package;
- strict runtime hook installation;
- signed images/SBOM/provenance;
- least-privilege RBAC and host mounts;
- certificate rotation;
- atomic upgrades and rollback;
- multi-architecture images;
- scale, resource, and failure testing;
- uninstall and evidence retention; and
- operational runbooks.

Acceptance:

- repository and package migration preserves supported downstream builds,
  documentation links, release provenance, and Git history;
- Runtime can be installed without Mithril and Mithril without Runtime;
- a co-resident Runtime/Mithril host has one active sensor owner and no
  duplicate overlapping event stream;
- a new supported cluster reaches truthful observe coverage through one install;
- strict-from-first-exec mode proves the runtime gate;
- upgrade never leaves an unreported enforcement gap;
- failed upgrade rolls back or reports uncovered state;
- one node agent remains the only Mithril privileged gatherer;
- fleet status exposes mixed capabilities and generations;
- compromised workloads cannot modify Mithril maps, socket, credentials, or
  binary through their existing namespaces/cgroups; and
- uninstall removes active enforcement only through an authorized, audited
  workflow.

Checkpoint: production launch requires the full conformance matrix.

## Cross-phase verification matrix

Every implementation phase selects applicable rows and records exact commands,
fixtures, kernels, and results.

| Test family | Required proof |
| --- | --- |
| BPF verifier | every object loads or fails with a classified capability result on every supported kernel |
| identity | threads, fork-without-exec, exec-without-fork, double fork, orphan, PID reuse, bootstrap, loss, and restart |
| filesystem | overlayfs, bind mount, rename, hard link, deleted-open file, symlink, mount namespace, read/write/create/delete/mmap |
| network | TCP, UDP, DNS, existing sockets, alternate resolvers, network namespace, CNI coexistence, packet fence |
| device/privilege | cgroup devices, ioctl classes, ptrace, capability, BPF, perf, mount, namespace and module paths |
| container lifecycle | containerd, CRI-O, OCI/NRI hook ordering, first-process gate, Pod replacement and node reboot |
| evidence | ring loss, queue loss, central outage, spool full/corrupt, duplicate/reordered delivery and clock skew |
| correlation | Kubernetes audit/object/controller/binding, provider request/resource IDs, fan-out, contradiction and late evidence |
| response | stale targets, exact versus cgroup blast radius, idempotency, expiry, rollback, offline node and postconditions |
| security | unprivileged and privileged workload attacks on maps, bpffs, sockets, credentials, Unix APIs and update path |
| performance | allowed and denied latency, CPU, memory, event rate, loss threshold, policy swap and recovery |
| product boundary | no Mithril dependency on Runtime Sessions, no application changes, no extra privileged collector and no TLS interception |
| language and ownership | Rust owns loader/userspace; owned C BPF is reproducible; no upstream daemon is the hidden product chassis |
| shared sensor | Runtime-only, Mithril-only, and co-resident modes; one active loader; scoped observations; watch-only authority cannot escalate |
| monorepo | independent Runtime/Mithril builds, dependency-direction checks, license inventory, release isolation, and history-preserving migration |

The Hugging Face reference acceptance remains:

1. run the existing unchanged multi-job worker;
2. distinguish native process branches where Linux supplies distinct task
   ancestry;
3. state same-interpreter work-item ambiguity where Linux cannot distinguish
   jobs;
4. observe or deny credential, file, socket, device, and privilege effects
   according to the reviewed role;
5. join authoritative Kubernetes/provider effects across nodes;
6. contain the smallest proven scope;
7. verify every physical result; and
8. preserve gaps and uncertainty.

## Explicitly excluded architecture

This plan does not select:

- four separately deployed KubeArmor, Falco, Tetragon, and Cilium collectors;
- a Tetragon Go daemon fork as Mithril's node chassis;
- Falco `libpman`, libscap, or KubeArmor as Mithril's primary loader;
- two overlapping Runtime and Mithril BPF loaders on one host;
- Mithril denial or response authority exposed through `runtime-observe`;
- a Mithril sidecar in every protected Pod;
- one Pod or process per application job;
- required application instrumentation;
- a model-operated root shell;
- central synchronous authorization for every kernel operation;
- TLS interception as the default network control;
- Cilium as a required CNI;
- path-only durable execution identity;
- PID-only response identity;
- signal delivery as proof of prevented effect;
- alert absence as proof of safety; or
- automatic high-blast-radius response.

## Open implementation decisions

The following choices are intentionally not made by this document:

- the exact history-preserving sequence and release transition for renaming
  `erebor-runtime` to the `erebor` monorepo;
- exact shared Rust crate/module names and whether the active host owner is
  linked into each product binary or hosted behind one separately packaged
  local executable when only one process can safely own the host;
- exact `libbpf-rs`, `libbpf-cargo`, libbpf, Clang/LLVM, and bpftool versions;
- the durable raw and normalized storage engines;
- the exact public policy serialization and optional CRD design;
- the initial supported distribution/kernel matrix;
- exact performance budgets;
- whether AppArmor/SELinux fallback enters the first commercial release;
- the first provider connectors after Kubernetes audit; and
- which response actions, if any, become eligible for automatic approval.

Each choice requires an implementation proposal with trade-offs and acceptance
proof. None may weaken the recorded single-gatherer, identity, coverage,
deployment-preservation, or response guarantees.

## Final success condition

The architecture succeeds when:

1. one `erebor` monorepo produces independently installable Runtime and Mithril
   products from Rust-owned userspace and owned C BPF sources;
2. a customer can install one Mithril node agent type, leave the protected
   deployment unchanged, and see truthful per-node coverage;
3. Mithril attributes a physical effect to the correct native process lineage,
   follows authoritative effects across nodes and providers, denies supported
   prohibited effects before completion, and executes the smallest authorized
   response with a verified physical result;
4. Runtime reuses the same Linux sensor implementation to watch agent actions
   without acquiring Mithril enforcement or response authority; and
5. a host running both products has one active gatherer owner and no duplicate
   overlapping kernel collection.

It fails if simplicity is achieved by hiding a second collector, weakening
identity, dropping coverage truth, requiring application redesign, treating
opaque TLS as plaintext, claiming containment without a postcondition, hiding
an upstream daemon behind Mithril branding, or treating watch-only Runtime
observation as an enforcement boundary.
