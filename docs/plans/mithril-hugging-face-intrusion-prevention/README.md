# Mithril Hugging Face Intrusion Prevention Master Plan

Status: Rewritten from the validated architecture on 2026-08-08. Proposed;
this document does not authorize implementation until the user approves one
phase by name.

Design authority:

- [Validated readable architecture](./policy-and-protection-algorithm-architecture-readable.md)
- [Hugging Face adversarial acceptance](./hugging-face-adversarial-acceptance.md)
- [Live two-node lifecycle probe](./live-two-node-lifecycle-probe.md)

The [previous architecture](./policy-and-protection-algorithm-architecture.md)
is a superseded historical record. It may explain rejected ideas but cannot
define implementation behavior.

## Goal And Release Boundary

Build Mithril as an owned Linux/Kubernetes prevention, evidence, causality,
and verified-response product for the Hugging Face incident chain. On a
qualified platform it must deny the first distinguishable prohibited physical
effect, attribute it to an exact actor and object, preserve loss-aware evidence,
follow proven cross-node/provider branches, and execute only authorized typed
response operations whose physical postconditions are checked.

The baseline protects unchanged workloads. It does not claim to understand
arbitrary in-process intent, encrypted application verbs, or incident stages
outside its deployed authority. Every release claim uses the exact result and
proof vocabulary in architecture Chapters 4, 22-25, 31, and 37.

## Implementation Rules

- One approved phase at a time. Completing one phase does not authorize the
  next.
- Every phase has named deliverables, design-section bindings, real code-backed
  tests, exact fixtures, and a `Done`, `Not done`, or `Blocked` result.
- A phase cannot weaken or silently reinterpret the validated architecture. A
  conflict stops implementation and requires an architecture amendment.
- The protected application, image, command, Pod/process topology, credentials,
  RBAC/IAM, CNI, and provider principals remain unchanged for the baseline.
- Rust owns product userspace. Owned C CO-RE programs are the kernel payload.
- Tetragon, KubeArmor, Meta BpfJailer, and the independent Jailer are pinned
  learning/source inputs, not hidden product daemons or automatic dependencies.
- Direct TLS remains direct. Optional L7 mediation is separately allocated.
- Seccomp is not a Version-1 dependency. It is evaluated only in Phase 12 and
  is added only after its compatibility and performance gate passes.
- Every unsupported hook, identity, source gap, overflow, or unverified result
  mechanically narrows the advertised claim.

## Current Repository Baseline

At this rewrite the workspace has eighteen `erebor-runtime-*` crates and no
Mithril, BPF interceptor, or Mithril Control crate. Existing reusable work is:

- `crates/erebor-runtime-core/src/interception.rs` and its module family:
  portable process/file/socket request and decision concepts;
- `crates/erebor-runtime-session/src/runtime_interception_broker.rs` and its
  module family: the Session-owned broker/client/handler implementation;
- `crates/erebor-runtime-session/src/interception_backend.rs`: the current
  Linux ptrace backend owner; and
- `crates/erebor-runtime-e2e/`: existing cross-crate Runtime acceptance.

Those types are useful inputs, not the Mithril kernel ABI. Phase 0 must decide
which portable concepts move into the shared Interceptor family, which remain
Session-specific, and how compatibility is migrated without two policy owners.
The existing
[Linux kernel-native enforcement plan](../linux-kernel-native-enforcement/README.md)
must consume the same Interceptor owner before either plan implements an
overlapping loader.

## Target Components And Ownership

Phase 0 may refine names, but these ownership boundaries are fixed:

```text
bpf/erebor-interceptor/          owned CO-RE lifecycle/effect programs

crates/erebor-interceptor-abi/   portable surface + exact Rust/C ABI contracts
crates/erebor-interceptor/       one loader/link/map/pin owner and local clients
crates/mithril-node/             identity, policy activation, effects, WAL,
                                 local response; embeds Interceptor owner
crates/mithril-control/          policy compile/sign, secure node control,
                                 graph, findings, approvals, connectors
crates/mithril-e2e/              fixture, qualification, and release proofs
packaging/mithril/               image, Helm, and platform manifests
```

The shared **Interceptor** is a component family, not another daemon:

- `erebor-interceptor-abi` owns portable requests/results and exact BPF map/event
  layouts shared by Runtime adapters, Mithril, fixtures, and generated C.
- `erebor-interceptor` owns Linux preflight, BPF load/attach, links, maps,
  pin-root lease, capability readback, and scoped local subscriptions.
- In Mithril mode, `mithril-node` embeds and owns that component. A co-resident
  Runtime uses an authenticated, cgroup-scoped client and cannot assign Mithril
  roles, activate policy, or invoke response.
- In a later Runtime-only deployment, the Runtime daemon may embed the same
  component only after acquiring the same exclusive pin-root lease. There is
  never a Runtime loader and Mithril loader at the same time.
- Mithril-specific actor state, signed policy generations, evidence semantics,
  detection, and response do not move into the generic Interceptor.

`mithril-control` is required, not postponed to the detection phase. Phase 1
creates its service chassis and mutually authenticated gRPC node channel.
Later phases add only the messages needed for policy delivery, evidence,
findings, and response. This plan does not require a public API contract yet.

## Phase Dependency And Deliverable Summary

| Phase | Required deliverable | Validated design coverage |
| ---: | --- | --- |
| 0 | Feasibility/source dossier, shared-Interceptor ownership decision, proven hook prototypes, closed ABI/schema/goldens, fixture/performance baseline | Ch. 1-5, 10-13, 27-30, 33-36; A.1-A.13; B-D |
| 1 | One shared Interceptor owner, one `mithril-node`, one `mithril-control`, secure gRPC, capability/readiness, Runtime coexistence proof | Ch. 5, 14, 27-30, 32, 34; A.3-A.7, A.12-A.13 |
| 2 | Exact task/process/exec/native-family and runtime-root identity with restart/reuse truth | Ch. 6-9; A.8-A.10, A.12, A.14 |
| 3 | Policy compiler/signature/atomic candidate generation plus observe-only coverage for every allocated local effect and canonical path matcher | Ch. 10-21, 28-30; A.11-A.14 |
| 4 | Signed pre-effect exec/file/memory/IPC/device/privilege enforcement and bounded exceptions | Ch. 10-18, 20-21; A.11-A.14 |
| 5 | Process-aware socket/network/DNS/final-flow enforcement and packet response floor | Ch. 18-19; A.13.4, A.14 |
| 6 | Durable evidence, coverage intervals, WAL, generation/restart recovery, loss and owner-health truth | Ch. 9, 22, 31-33; A.3-A.7, A.15.1-A.15.2 |
| 7 | Mithril Control evidence intake, deterministic graph/finding packages, notifications, and provider-neutral authority leases | Ch. 8, 22-25, 30, 34; A.10, A.15 |
| 8 | Kubernetes/runtime/audit multi-node causality and conservative purpose classification | Ch. 7-8, 23, 25, 30-31; A.9-A.10, A.15.3 |
| 9 | Authorized local and distributed response with blast-radius disclosure and verified postconditions | Ch. 24-25, 32, 34; A.15.4-A.15.6 |
| 10 | Qualified AWS/Google/GitHub/mesh/connector/artifact evidence, leases, and typed provider actuators | Ch. 23-26; A.10, A.15-A.16 |
| 11 | Packaging, upgrade, platform qualification, performance, complete HF conformance, and signed release claims | Ch. 25, 30-33, 37; A.4-A.7; C |
| 12 | Independent decisions/prototypes for deferred surfaces and optional upstream evidence adapters | Ch. 5, 7, 14, 21, 26, 35.1; A.13.6, A.16 |

Phase order is strict through Phase 11. Phase 12 is independent after Phase 0
and cannot satisfy a Phase 11 core gate.

## Complete Design-To-Phase Coverage Ledger

This ledger is the master completeness check. A design row is covered only when
the named phase file contains a matching deliverable and proof.

| Architecture section or feature | Implementing phase(s) | Completion evidence |
| --- | --- | --- |
| Ch. 1-4 product, gap, claim/result vocabulary | 0, 11 | checked claim registry; release claims limited to proven boundaries |
| Ch. 5 node/trust architecture, one owner, unchanged workloads, secure control | 0, 1, 11 | exclusive pin lease; unchanged fixture; mTLS gRPC; root-compromise limits |
| Ch. 6 actor/task/process/thread/exec/native identity | 2 | fork/thread/vfork/non-leader-exec/PID-reuse fixtures |
| Ch. 7 runtime-created roots, probes, lifecycle, admin exec, unmatched workloads | 2, 4, 8, 11 | stock-runtime matrix; restricted external role; one-use admin exception |
| Ch. 8 authorization proof, intent, trust/time/replay | 0, 2, 7, 10 | signed-envelope goldens; replay/mismatch/restart tests |
| Ch. 9 exit, shutdown, reference retention | 2, 6 | exact cleanup/tombstone/reconciliation tests |
| Ch. 10 invariants | 0 and every phase | invariant-to-test ledger cannot lose a row |
| Ch. 11 readable policy, roles, effects, dispositions, exceptions | 0, 3, 4 | parser/compiler goldens; bounded-use exception consumption |
| Ch. 12 compiler, signatures, activation, rollback | 0, 3, 4, 6 | deterministic bytes; inactive readback; one CAS; retirement recovery |
| Ch. 13 one local decision and atomic state | 0, 2-5 | Rust/BPF lookup golden; task-first and contention tests |
| Ch. 14 mechanism boundaries and deferred Seccomp | 0, 1, 3-5, 12 | hook/capability matrix; Seccomp remains absent unless Phase 12 gate passes |
| Ch. 15 mounts, canonical oldest-mount path, exact objects | 0, 3, 4 | Meta bind-alias fixture; DIRTY topology races; object revalidation |
| Ch. 16 exec images and executable memory | 0, 3, 4 | exec chain, loader, memfd, mmap/mprotect, immutable-image fixtures |
| Ch. 17 files, credentials, delegated I/O | 0, 3, 4, 5 | token rotation, proc-fd, fd pass, remote delegate fixtures |
| Ch. 18 IPC, native authority, persistent objects | 2-5 | directional relationship, shared mapping, async unsupported tests |
| Ch. 19 network/DNS/TLS limits | 3, 5, 7, 10 | socket lifetime, rewrite, DNS exfiltration, same-TLS honest-result tests |
| Ch. 20 devices and derived authority | 0, 3, 4 | device/ioctl/derived-fd fixtures |
| Ch. 21 privilege, self-protection, Landlock, deferred Seccomp | 0, 3, 4, 11, 12 | escape matrix; self-protection oracle; optional-layer records |
| Ch. 22 evidence, coverage, proof quality, findings | 0, 6, 7 | source epoch/gap tests and deterministic replay |
| Ch. 23 cross-node/provider causality | 7, 8, 10 | registered edge contracts; fan-out/contradiction/shared-principal tests |
| Ch. 24 response transaction and blast radius | 9, 10 | authorization, simulation, exact re-resolution, physical readback |
| Ch. 25 complete HF proof package | 0, 3-11 | standing incident fixture grows in every phase; complete Phase 11 matrix |
| Ch. 26 CI/CD model and honest tiers | 10, 12 | provider/artifact foundations in 10; named CI adapters remain Phase 12 allocations |
| Ch. 27-29 Jailer/Meta/KubeArmor/Tetragon lessons | 0, 1-6 | pinned source dossier plus adopted-code provenance/test IDs |
| Ch. 30 combined pipeline | 1-10 | end-to-end native and identical-probe examples |
| Ch. 31 acceptance | every phase, final 11 | exact fixture cases and physical oracles |
| Ch. 32 failure/recovery | 1, 2, 6, 9, 11 | daemon/reader/control/link/map/restart fault matrix |
| Ch. 33 boundedness/performance | 0, 1-6, 11 | per-hook distributions, N/N+1 maps, evidence-preserving benchmarks |
| Ch. 34 durable owners | 0, 1, 7, 9, 10 | one writer per state family; no duplicate daemon/loader |
| Ch. 35 delivery/unallocated surfaces | this master, 12 | coverage linter and deferred-surface ledger |
| Ch. 36 approval defaults | 0, owning phase | recorded decisions before ABI/policy changes |
| Ch. 37 completion | 11 | digest-bound qualification bundle and signed limited claim |
| A.1-A.7 foundations/qualification records | 0, 6, 11 | closure, bundles, result records, release envelope |
| A.8-A.12 identity/policy/kernel ABI | 0, 2-4 | generated types, goldens, lifecycle and lookup fixtures |
| A.13 Linux effects | 0, 3-5, 11, optional 12 | hook matrix and per-effect physical oracle |
| A.14 native authority/IPC | 2-4 | exact state and relationship fixtures |
| A.15 evidence/graph/response | 6-10 | deterministic artifacts and physical response results |
| A.16 CI/artifact/provider authority | 10, optional 12 | provider/artifact contracts; separately allocated CI adapters |
| Appendix B rejected designs | 0 and review in every phase | forbidden-contract lint and no historical authority |
| Appendix C fixtures/completion | every phase, final 11 | exact registry equality and criterion mapping |
| Appendix D sources | 0 | pinned digest/license/provenance/source-evidence registry |

## Upstream Learning And Selective Adoption Gate

Phase 0 produces an `UPSTREAM-ADOPTION-V1` dossier before product code is
copied or derived. It must separately cover:

| Source | Required lesson/prototype | Explicit rejection or limit |
| --- | --- | --- |
| Meta BpfJailer deck | component state graph, wildcard matching, mount-root map, lowest `mnt_id_unique` canonicalization, mount/rename/link protection, verifier/code-size budget | presentation is design evidence, not source-code provenance |
| Independent Jailer | task-storage declaration, parent-to-child copy in `task_alloc`, bounded BPF map/state patterns | never use pending-PID delayed enrollment; its dentry-only walk/inode cache is not the path authority |
| KubeArmor | BPF LSM pre-effect patterns, policy lowering, map publication, DNS/parser bounds, reader/loss behavior, mount traversal | missing identity cannot allow; action words/events do not prove physical results; no KubeArmor daemon |
| Tetragon | early fork identity, non-leader exec, cgroup resolution, NRI facts, loss accounting, fresh maps, generic LSM lessons | process cache is not Mithril authority; runtime metadata does not invent purpose; no Tetragon daemon |

Each adopted unit receives source path/commit/digest, license decision, local
owner, changed behavior, hostile fixture, and a `copied`, `derived`, or
`reimplemented` classification. Later implementation phases must cite the
approved dossier entry; “inspired by upstream” is not enough.

## Fixture Allocation

The exact registry is architecture Appendix C. Phase ownership is:

| Fixture family | Owning phase |
| --- | --- |
| schema, config, closure, source-evidence, hook feasibility | 0 |
| boot, loader ownership, capability/readiness | 1 |
| `ENTRY-*`, `ID-*`, task/process/exec/native-state lifecycle | 2 |
| observe-side effect attribution and policy simulation | 3 |
| `FILE-*`, `MEM-*`, `MOUNT-*`, `DEVICE-*`, local `IPC-*`, privilege denials | 4 |
| `NET-*`, DNS, rewrite, socket lifetime and flow fence | 5 |
| loss, coverage, WAL, restart, map/link/reader health | 6 |
| `HF-LOCAL-*`, local findings, notification and authority-neutral replay | 7 |
| `EDGE-K8S-*`, `XNODE-*`, Kubernetes fan-out and contradiction | 8 |
| `HF-RESP-*`, local/distributed response and blast radius | 9 |
| AWS/GitHub/connector/artifact/provider-granularity fixtures | 10 |
| complete registry, criterion mapping, performance and release envelope | 11 |
| `SECCOMP-QUAL-001`, checkpoint/stream/CI/L7/host-agent and optional-source fixtures only when separately allocated | 12 |

No phase may rename, add, or remove a fixture without updating Appendix C,
the registry artifact, criterion mapping, and owning phase in one review.

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

## Required Shape Of Every Phase Result

Each phase ends with this checked-in block:

```text
State: Done | Not done | Blocked
Validated architecture revision/digest:
Completed deliverable IDs:
Files and durable owners changed:
Upstream-adoption dossier IDs used:
Fixture cases and exact physical results:
Commands and exact source state covered:
Platform/kernel/runtime manifests:
Performance/capacity results:
Unsupported/degraded paths:
Remaining work in this phase:
Next phase not authorized:
```

The result must be backed by committed Rust tests. Shell/live probes are
additional evidence. After final Rust edits the repository CI procedure must
pass; applicable phases also run the live two-node lifecycle probe.

## Approval And Stop Points

Stop after every phase. Also stop immediately before:

- changing the validated architecture, signed policy/wire, or a durable owner;
- adding a second node process or BPF loader;
- weakening a deny, identity, evidence, coverage, or response invariant;
- terminating workload TLS or inserting a proxy;
- implementing any Phase 12 surface beyond its approved evaluation scope; or
- widening a typed response actuator.

Only the user can approve those changes and the next phase.
