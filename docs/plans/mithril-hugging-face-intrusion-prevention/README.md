# Mithril Hugging Face Intrusion Prevention Master Plan

Status: Proposed. No implementation phase is authorized until the user
approves that phase by name.

Parent plan: none. This is a new product implementation master plan.

Design authorities:

- [Policy And Protection Algorithm Architecture](./policy-and-protection-algorithm-architecture.md)
- [Mithril Single-Gatherer Architecture and Upstream Adoption Plan](../../research/erebor-warden-single-gatherer-architecture-plan.md)
- [Erebor Defender: Linux Enforcement, Correlation, and Response Engineering](../../research/erebor-defender-learning-from-tetragon-and-falco.md)
- [Hugging Face Agent Intrusion: Erebor Defender Implementation Analysis](../../research/hugging-face-agent-intrusion-analysis.md)
- [Hugging Face Agent Intrusion: Published Live Action Stream](../../research/hugging-face-agent-intrusion-live-action-stream.md)
- [Linux Kernel-Native Effect Enforcement Master Plan](../linux-kernel-native-enforcement/README.md)

The older filenames and the words Defender/Warden remain in research links for
history. The product name in this implementation plan is **Mithril**.

## Goal

Build a production Mithril product that can protect an unchanged Linux and
Kubernetes deployment from the Hugging Face-side chain represented by
`HF-008` through `HF-021`.

On a fully supported node, Mithril must synchronously deny the first
out-of-profile physical effect after hostile input obtains in-process execution:
an executable transition, protected file or credential access, socket effect,
device effect, privilege transition, or kernel escape operation. It must then
attribute the attempt to the exact native process lineage, retain durable
evidence and coverage, follow any authoritative causal expansion across nodes
and providers, and execute the smallest authorized containment action with a
verified physical postcondition.

The target is not “detect a command resembling the published incident.” The
target is:

```text
hostile input reaches an unchanged worker
  → first distinguishable prohibited effect is denied before completion
  → exact task/process/effect evidence is durable
  → any already-completed or deliberately allowed branch is correlated
  → every proven local and remote branch is narrowly contained
  → physical postconditions and remaining uncertainty are reported
```

## Meaning Of “Prevent The Hugging Face Intrusion”

The release claim is conditional and mechanically testable:

1. `HF-001` through `HF-007` occurred in an external evaluation environment
   outside the Hugging Face-owned boundary. Mithril deployed on the protected
   estate must not claim authority over those events.
2. Mithril does not claim that it rejects the hostile HDF5 structure at
   `HF-008` or prevents the in-process Jinja evaluation at `HF-010` without an
   optional application-owned remediation. The deployment-preserving product
   assumes hostile code can already run inside the existing interpreter.
3. If the signed worker role does not need the attempted effect, Mithril must
   deny the first covered effect from `HF-009` onward before it completes.
   Representative gates are environment/credential object access, an
   unapproved `python → sh/curl/tailscale` edge, API/IMDS egress, executable
   memory/code loading, device use, or privilege/namespace escape.
4. If malicious code uses the same legitimate process, credential, destination,
   and existing TLS connection as ordinary controller behavior, Linux cannot
   distinguish intent. Mithril must preserve the allowed operation, detect the
   first semantic deviation from Kubernetes or provider audit, fence the exact
   proven source, and report whether the semantic effect had already completed.
5. Provider-side prevention such as Kubernetes admission, RBAC/IAM narrowing,
   or operation-specific capabilities is optional operator hardening. It may
   strengthen the result after separate approval, but it is not silently made a
   prerequisite for the baseline product.
6. A run passes the incident prevention gate only if the protected fixture
   proves that no prohibited branch reaches a later incident stage after the
   expected denial or containment point. An alert, signal, map write, HTTP
   success, or process exit is not sufficient proof.

This definition prevents a marketing claim from outrunning the available
kernel or provider information.

## Non-Negotiables

- Protect the deployment that exists. Baseline installation cannot require
  changes to application code, agent harness, controller/Pod/process/job
  topology, mounted credentials, ServiceAccounts, RBAC, IAM, routes, CNI, or
  provider principal design.
- One `mithril-node` DaemonSet Pod runs one container containing one privileged
  Rust `mithril-node` process per protected Linux node. This is one component,
  not a Pod plus a second daemon.
- One active host owner owns overlapping BPF links, maps, pin root, sequence
  space, and raw event stream. A co-resident Erebor Runtime subscribes to
  scoped observation and cannot load enforcement or invoke response.
- Rust owns the loader and all product userspace. Owned C CO-RE programs are
  the kernel payload. No Tetragon, KubeArmor, Falco, Cilium, or upstream daemon
  becomes the hidden product chassis.
- Upstream behavior may be studied or selectively adapted only after the Phase
  0 per-file and transitive-license gate. No research checkout is a build
  dependency by accident.
- Native task/process lineage never crosses a node. Cross-node propagation is
  represented only by typed causal edges backed by authoritative identifiers.
- A task cookie, label epoch, process-lineage ID, node boot ID, full container
  ID, Pod UID, cgroup identity, and live revalidation replace PID-only
  attribution and response.
- Allowed controller credential and API use must continue to work. An
  unexpected child role and an unexpected same-process server operation are
  different cases with different decision points.
- Direct TLS is not intercepted. Kernel/network evidence must not claim it can
  distinguish clone, push, email, token minting, or API verbs inside the same
  encrypted channel.
- Observation, prevention, detection, containment, and verified recovery are
  separate result types. Killing a process after an effect is not prevention.
- Source health, drops, sequence gaps, policy generations, connector delay, and
  unsupported hooks are evidence. Negative conclusions are forbidden when
  required coverage is absent.
- Response APIs are typed, scoped, expiring, idempotent, approval-aware
  physical operations. They never expose an arbitrary shell to a human or
  defensive agent.
- Every phase adds code-backed tests. The standing incident fixture grows with
  the product; it is not postponed until the last phase.
- Implement one approved phase at a time. Stop after its checkpoint and wait
  for approval before starting the next phase.

## Existing Repository Baseline

At plan creation:

- the current Cargo workspace contains eighteen `erebor-runtime-*` crates;
- no `mithril-*` crate exists;
- no shared `erebor-linux-sensor-*` Rust crate exists;
- no owned `bpf/erebor-linux-sensor/` source tree exists;
- no `mithril-node` image, DaemonSet, Helm release, or Mithril Control service
  exists;
- the existing Runtime Linux process guard is ptrace-based and belongs to
  Runtime, not to Mithril;
- the research trees for Tetragon, KubeArmor, Falco, and other products are
  reference material only; and
- the future repository rename from `erebor-runtime` to `erebor` has not
  occurred.

No phase may claim a Mithril capability merely because a checked-out upstream
project contains similar code.

## Current-Code Boundary And Existing Runtime Plan

The current Runtime implementation remains grounded in:

- `Cargo.toml` for workspace membership;
- `crates/erebor-runtime-core/src/config/session/interception.rs` for the
  current interception backend selection;
- `crates/erebor-runtime-session/src/os/linux/process_guard.rs` and its
  `process_guard/` module family for the ptrace-based Runtime owner; and
- `crates/erebor-runtime-e2e/` for current cross-crate Runtime acceptance.

Those files do not implement Mithril and are not silently repurposed by the
early phases. The existing
[Linux Kernel-Native Effect Enforcement Master Plan](../linux-kernel-native-enforcement/README.md)
is Runtime Session-oriented, while this plan introduces the node-wide shared
sensor and Mithril authority.

Phase 0 must record one explicit overlap decision before either plan implements
a BPF loader:

- the shared ABI/host owner in this plan becomes the only common loader and the
  Runtime plan retains only Runtime-specific Session admission, lowering, and
  evidence work; or
- a different single-owner boundary is approved with equivalent one-loader,
  watch-only Runtime, identity, recovery, and coverage proof.

Two independently implemented overlapping loaders are not an acceptable
resolution. The current ptrace path remains honestly available until a
separately approved Runtime integration phase changes it.

## Proposed Current-Repository Target

Phase 0 must approve or replace these exact names before Phase 1. Until then
they are the plan's proposed current-repository paths:

```text
bpf/
└── erebor-linux-sensor/
    ├── include/
    ├── lifecycle.bpf.c
    ├── exec.bpf.c
    ├── file.bpf.c
    ├── socket.bpf.c
    ├── device.bpf.c
    ├── security.bpf.c
    └── response.bpf.c

crates/
├── erebor-linux-sensor-abi/       versioned raw kernel/userspace ABI
├── erebor-linux-sensor-host/      Rust/libbpf loader and one-owner boundary
├── mithril-node/                  one node binary and local owners
├── mithril-control/               central intake, graph, detection, connectors
└── mithril-e2e/                   cross-crate and live incident fixtures

packaging/
└── mithril/
    ├── image/
    └── helm/mithril/
```

The first implementation keeps ownership cohesive. A crate is split only when
Phase 0 or a later approved phase proves a real dependency/lifecycle boundary;
line count alone is not permission to fragment an owner.

## Target Deployment And Authority

```text
protected Linux node
┌─────────────────────────────────────────────────────────────────┐
│ one DaemonSet Pod                                               │
│   one container                                                 │
│     one mithril-node Rust process                               │
│       ├─ shared Rust/libbpf host owner + owned C CO-RE programs │
│       ├─ native identity and effect owners                      │
│       ├─ signed local policy + response owners                  │
│       └─ local spool, coverage, mTLS, optional Runtime watcher  │
└──────────────────────────────┬──────────────────────────────────┘
                               │ one authenticated outbound stream
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│ Mithril Control                                                 │
│ raw intake → coverage → node graph → distributed causal graph  │
│            → findings → authorization → typed connectors       │
└─────────────────────────────────────────────────────────────────┘
```

Mithril Control may be SaaS or self-hosted. It is not a second privileged node
gatherer. Kubernetes, cloud, mesh, connector, and source-control adapters live
at the control/service boundary or consume existing audit sources.

## Durable Owners

| Contract | Owner | Forbidden substitute |
| --- | --- | --- |
| BPF objects, links, maps, verifier/capability probes, pin-root lease, raw sequence | `erebor-linux-sensor-host` inside the active `mithril-node` process | a second Tetragon/Falco/KubeArmor/Runtime loader |
| task/thread, process, execution, role inheritance, bootstrap and PID-reuse truth | `mithril-node` native identity owner | userspace PID cache or Pod name |
| exec/file/socket/device/security effect normalization and decision evidence | `mithril-node` effect owner | syscall text or alert strings |
| signed profile compile, map generation, atomic activation and rollback | `mithril-node` policy owner | raw model-authored BPF maps or third-party YAML |
| local WAL, loss, acknowledgement and coverage intervals | `mithril-node` evidence owner | logs without sequence/gap semantics |
| immutable source envelopes, normalized observations and deterministic replay | `mithril-control` intake/evidence owners | mutable case notes |
| node-local graph and typed distributed causal edges | `mithril-control` graph owner | cross-node process-parent edges or time-only joins |
| finding packages `HF-PROC-001`, `HF-DW-001`, `HF-XNODE-001` | `mithril-control` detection owner | a model conclusion or Falco severity |
| response authorization, simulation, per-target execution and postconditions | `mithril-control` response owner plus authenticated node/provider actuator | arbitrary remote shell |
| Runtime agent observation | Runtime consumer over a cgroup-scoped read-only subscription | Mithril policy/session identity or a second raw sensor |

## Standing Hugging Face Test Contract

[Hugging Face Adversarial Acceptance](./hugging-face-adversarial-acceptance.md)
is normative for every phase. It defines:

- the unchanged multi-job worker and legitimate-controller controls;
- the non-weaponized post-compromise behavior driver;
- exact local, cross-node, provider, failure, bypass, and response scenarios;
- the expected decision point and physical postcondition for every incident
  stage;
- the coverage prerequisites for every conclusion; and
- the release claim allowed at each completed phase.

[Live Two-Node Lifecycle Probe](./live-two-node-lifecycle-probe.md) is required
for phases that touch kernel loading, native identity, pre-effect enforcement,
container admission, Kubernetes correlation, distributed response, packaging,
or upgrade/recovery. Unit tests and replay fixtures do not replace it.

## Phase Baseline Summary

The plan uses the architecture research's twelve build stages and adds a
dedicated provider/recovery stage. The attack fixture is introduced in Phase 0,
not after implementation:

| Phase | Product increment | Incident proof added |
| ---: | --- | --- |
| 0 | kernel, license, ABI, path, testbed, and performance contract | safe fixture and exact stage/postcondition matrix compile and run |
| 1 | one Rust node binary and shared watch-only substrate | unchanged worker lifecycle is observed by one gatherer |
| 2 | exact native task/process/execution identity | hostile and benign branches cannot merge across PID reuse or concurrency |
| 3 | physical effect observation and signed profile simulation | `HF-009`–`HF-012` effects are attributed without changing behavior |
| 4 | signed local pre-effect enforcement | first prohibited exec/file/code/device/privilege effect returns denial |
| 5 | process-aware network decision and packet fence | API/IMDS/C2 egress is denied or honestly classified as ambiguous |
| 6 | durable evidence, coverage, and recovery | loss/outage cannot become false “safe” or false “prevented” claims |
| 7 | Mithril Control and deterministic detection packages | local credential/authority pivot replays to stable findings |
| 8 | Kubernetes audit/object/CRI correlation | exact multi-node causal path and controller fan-out are reconstructed |
| 9 | local and distributed physical response | seed, sockets, remote branches, and reconciler are contained and verified |
| 10 | AWS, mesh, connector, artifact, and GitHub adapters | `HF-013`–`HF-019` provider expansion is correlated and narrowly recovered |
| 11 | production installation, upgrades, scale, security, and final conformance | complete `HF-008`–`HF-021` prevention/containment matrix passes |
| 12 | optional ecosystem compatibility | Falco/Tetragon/Hubble/EDR inputs add evidence without changing guarantees |

## Phase Index

- [Phase 0: Substrate, License, ABI, And Incident Baseline](./phase-0-substrate-license-abi-and-incident-baseline.md)
- [Phase 1: One-Binary Node Chassis](./phase-1-one-binary-node-chassis.md)
- [Phase 2: Exact Native Identity](./phase-2-exact-native-identity.md)
- [Phase 3: Effect Observation And Profile Simulation](./phase-3-effect-observation-and-profile-simulation.md)
- [Phase 4: Signed Local Pre-Effect Enforcement](./phase-4-signed-local-pre-effect-enforcement.md)
- [Phase 5: Process-Aware Network Plane](./phase-5-process-aware-network-plane.md)
- [Phase 6: Durable Evidence, Coverage, And Recovery](./phase-6-durable-evidence-coverage-and-recovery.md)
- [Phase 7: Mithril Control And Detection Packages](./phase-7-mithril-control-and-detection-packages.md)
- [Phase 8: Kubernetes Distributed Causality](./phase-8-kubernetes-distributed-causality.md)
- [Phase 9: Local And Distributed Response](./phase-9-local-and-distributed-response.md)
- [Phase 10: Provider Connectors And Recovery](./phase-10-provider-connectors-and-recovery.md)
- [Phase 11: Production Installation And Final Conformance](./phase-11-production-installation-and-final-conformance.md)
- [Phase 12: Optional Ecosystem Compatibility](./phase-12-optional-ecosystem-compatibility.md)

## Approval And Stop Workflow

1. The user approves one phase by name.
2. The implementation follows only that phase's scope.
3. The implementer updates that phase's `Phase Result` with exact files,
   commands, kernels/runtimes, fixture IDs, results, gaps, and a
   `Done`/`Not done`/`Blocked` state.
4. Every code phase runs the repository Rust CI procedure after the final
   relevant edit and the phase-specific BPF/kernel/cluster tests.
5. Applicable phases run the live two-node lifecycle probe.
6. The implementer stops and waits for explicit approval of the next phase.

Phase completion never authorizes the next phase automatically.

## Common Verification Gates

Commands are future implementation requirements and are not claimed as run by
this documentation change:

```sh
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
bash .github/scripts/verify-rust-ci.sh
git diff --check
```

Phase 0 defines reproducible commands for:

- C CO-RE compilation and skeleton generation;
- per-kernel verifier/capability probes;
- BPF unit and kernel selftests;
- containerd and CRI-O root-admission tests;
- the isolated two-node Kubernetes testbed;
- packet, provider, restart, loss, and upgrade fault injection; and
- performance comparison against the approved baseline.

## Final Product Gate

Mithril is not ready merely because all phase files contain code. Phase 11 must
prove, on every advertised full-support platform:

1. one installation produces exactly one active node gatherer per node;
2. the unchanged legitimate multi-job worker and controller remain functional;
3. the safe incident driver reaches in-process execution but its first
   prohibited physical effect is denied synchronously;
4. no denied branch reaches the next incident stage;
5. the same-process ambiguity case is detected from authoritative audit without
   false TLS/kernel semantics and is contained within its declared bound;
6. native and distributed identities remain exact across node, restart, PID,
   object-name, IP, and cgroup reuse;
7. cross-node fan-out, controller replacement, provider use, and late branches
   remain visible and independently targetable;
8. every response reports `verified`, `partial`, `failed`, or `unknown` from
   physical postconditions and healthy required coverage;
9. Runtime-only, Mithril-only, and co-resident modes preserve the one-owner and
   watch-only authority boundaries; and
10. mixed or unsupported kernels receive truthful reduced/observe/unsupported
    status rather than an equivalent prevention claim.

Phase 12 is optional and cannot be used to satisfy this gate.
