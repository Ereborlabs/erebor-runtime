# Mithril Hugging Face Intrusion Prevention Master Plan

Status: Rewritten from the validated architecture on 2026-08-08, amended for
Control policy and evidence convergence on 2026-08-19, and amended for gRPC
service and IPC convergence on 2026-08-21. The capability-grounded Kubernetes
policy API amendment was approved on 2026-08-23. Proposed; this document does
not authorize implementation until the user approves one phase by name. The
stock-runtime bootstrap amendment was approved for Phase 6.2 on 2026-08-23.
The known-path route with oldest-mount fallback was approved on 2026-08-31.

Design authority:

- [Validated readable architecture](./policy-and-protection-algorithm-architecture-readable.md)
- [Hugging Face adversarial acceptance](./hugging-face-adversarial-acceptance.md)
- [Live two-node lifecycle probe](./live-two-node-lifecycle-probe.md)
- [Manual acceptance index](./manual-testing/README.md)
- [Shared manual-test environment setup](./manual-testing/environment-setup.md)
- [Implemented outcome review guide](./implemented-phase-review.md)

The [previous architecture](./policy-and-protection-algorithm-architecture.md)
is a superseded historical record. It may explain rejected ideas but cannot
define implementation behavior.

The 2026-08-19 architecture amendment is additive to completed local phases.
Do not rewrite a historical phase result or change the frozen BPF ABI because
of this plan. Phase 6.2 updates the affected exact-type closure and Control
RPC and schema goldens, proves compatibility with the final Phase 6 node
contract, and records the amended architecture digest for Phase 6.2 and later
work.

The 2026-08-21 amendment inserts Phase 6.1 before that work. Phase 6.1 removes
the obsolete ptrace IPC constraint, replaces supported custom-framed IPC with
typed gRPC services, and splits node-control operations by service family.
It removes redundant transport versions and envelopes. It keeps domain
generations, cursors, digests, and replay rules that gRPC does not replace.

The 2026-08-23 amendment replaces the flattened public policy CRD with a
capability-grounded `WorkloadProtectionPolicy` and a separate bounded
`WorkloadProtectionException`. Control lowers the base policy into the wider
internal signed policy. An exception activates one precompiled grant without
migrating the base generation. The amendment does not expose unqualified
internal fields or change the frozen BPF ABI.

The approved stock-runtime amendment adds one internal `RuntimeBootstrap`
transition to the node binding and BPF decision ABI. The node can arm it only
for the exact held initial task after it verifies the scheduled binding and
active signed policy. BPF restricts it to a fixed qualified operation set,
one entry lineage, owned anonymous objects, one deadline, and one application
handoff. It is not a CRD field, a policy rule, or a runtime-selected bypass.

The known-path routing amendment separates Kubernetes baseline mounts from
later bind mounts. Node records the compiled path prefix for a known mount
root in the authenticated initial container mount snapshot. BPF uses that
route without mount-age selection. If no route exists on the source dentry
ancestry, BPF uses the oldest unique mount as the canonical fallback. A dirty,
missing, or unresolved route and fallback cannot allow an effect.

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

## What Already Exists And Is Reused

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

No existing crate, imported source tree, or upstream daemon is treated as an
already-complete Mithril enforcement boundary. Reuse is accepted only through
the Phase 0 ownership, license, semantic-difference, and hostile-fixture gate.

## Target Components And Ownership

Phase 0 may refine names, but these ownership boundaries are fixed:

```text
bpf/erebor-interceptor/          owned CO-RE lifecycle/effect programs

crates/erebor-interceptor-abi/   portable surface + exact Rust/C ABI contracts
crates/erebor-interceptor/       one loader/link/map/pin owner and local clients
crates/mithril-node/             identity, policy activation, effects, WAL,
                                 local response; embeds Interceptor owner
crates/mithril-control/          CRD reconciliation, policy compile/sign,
                                 secure node control, durable evidence intake,
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
Phase 6.1 splits that channel into typed operation-specific services. Later
phases extend the owning service needed for policy delivery, evidence,
findings, and response. This plan does not require a public API contract yet.

The target policy and evidence data flow is:

```text
WorkloadProtectionPolicy CRD
  -> mithril-control validate, lower, compile, sign, target, and distribute
  -> mithril-node stage, read back, probe, and activate
  -> mithril-control exact per-node rollout inventory

WorkloadProtectionException CRD
  -> mithril-control resolve one precompiled base-policy file grant
  -> signed exact-target activation or revocation on the selected node
  -> ExceptionAuthorityOwner state and BPF atomic use consumption

protected effect
  -> owned Interceptor hook/map decision
  -> mithril-node identity + policy + physical result
  -> local WAL and coverage record
  -> mTLS gRPC upload and durable mithril-control acknowledgement
  -> deterministic Control graph/finding/authorization
  -> mTLS gRPC typed response request
  -> mithril-node or typed provider actuator
  -> authoritative physical readback
```

An installed local generation decides without a Control round trip. A Control
outage blocks only work that needs unavailable or expired Control-owned trust,
policy, approval, graph, or response state; it cannot convert an already
computable local deny into allow.

### Durable Owner Allocation

| Validated durable owner | First/full owning phase(s) |
| --- | --- |
| `TrustBundleOwner` | 1 bootstrap; 6.2 rotation/revocation/distribution |
| `AdministrativeApprovalOwner` | 4 approved administrative-exec transaction |
| `AuthorizationProofOwner` | 2 foundations; 4, 7, and 10 owning authorization families |
| `WorkloadBindingOwner` | 2 runtime roots; 6.2 protected Pod scheduling and runtime gate; 8 privileged/unmatched node floor |
| `NativeSecurityStateOwner` | 2 identity; 4 enforcement; 9 response references |
| `PolicyDesiredStateOwner` | 6.2 policy and bounded-exception CRD source reconciliation, base-policy lowering, and exception-grant resolution |
| `PolicyCompiler` | 3 compile/sign; 6.2 Control operation |
| `PolicyRolloutOwner` | 6.2 policy target snapshots, exact exception targets, distribution, and inventory |
| `PolicyActivationOwner` | 3 candidate/readback; 4 activation; 6 recovery/retirement |
| `ExceptionAuthorityOwner` | 4 bounded use/receipts/recovery; 6.2 Kubernetes exception instances |
| `KernelHostOwner` | 1 load/link/map/pin lease; 6 integrity/recovery |
| `ObjectAndSocketStateOwner` | 3 models; 4-5 physical decisions; 6 recovery |
| `CoverageHealthOwner` | 6 local source; 7-10 merged source views |
| `LocalEvidenceOwner` | 6 canonical observation/WAL/upload |
| `EvidenceIntakeOwner` | 6 durable append and acknowledgement; 6.2 production Control transaction and source cursor |
| `GraphAndFindingOwner` | 7 local; 8 Kubernetes; 10 provider/artifact branches |
| `NotificationRouter` | 7 |
| `ResponseCoordinator` | 9 local/Kubernetes; 10 provider plans |
| `ProviderResponseActuator[provider, capability]` | 10, one typed owner per approved capability |
| `AuthorityLeaseOwner` | 7 provider-neutral records; 10 exact provider bindings |
| `CheckpointAuthorityOwner` | Phase 12 evaluation only; a new approved phase must own implementation |
| `StreamEvidenceOwner` | Phase 12 evaluation only; a new approved phase must own implementation |
| `QualificationOwner` | 0 schemas/registry; 11 release decision and envelope |

The phase result must name any owner it changes. A phase cannot create another
writer under a different type or process name.

## Not In Scope For The Core Release

- Patching or rebuilding the OCI runtime, kubelet, kernel, CI runner, or
  protected workload.
- A second privileged node daemon, BPF loader, raw event reader, or policy
  authority.
- Node-side CRD watches, CRD-backed evidence or graph storage, and CRD status
  as activation authority.
- TLS interception, automatic proxy/CA/DNS injection, or invented L7 results.
- Byte-level taint/provenance through arbitrary memory, pipes, shared memory,
  encrypted payloads, or confused-deputy application protocols.
- PID-, pathname-, command-, timing-, TTY-, or display-name-only authority.
- Seccomp, checkpoint/stream authority, host/developer agents, named CI
  adapters, or optional upstream evidence sources as Phase 11 dependencies.
- Generic shell response or generic provider API execution.

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
| 6.1 | Typed gRPC services for all supported IPC, removal of the ptrace protocol exception, and node-control service separation | Ch. 5, 22, 30, 32-35; A.3-A.7, A.15.1 |
| 6.2 | Kubernetes policy desired state, Control reconciliation/signing/rollout, secure node delivery, and durable Control evidence intake | Ch. 5, 11-12, 22, 30, 32, 34-37; A.8.1, A.11, A.15.1 |
| 6.3 | Product-neutral shared telemetry and structured Mithril operational logs with component-specific verbosity | Ch. 32-35 operational visibility; no authority or evidence change |
| 7 | Accepted-evidence indexes, deterministic graph/finding packages, policy provenance, notifications, and provider-neutral authority leases | Ch. 8, 22-25, 30, 32, 34-35; A.10, A.15 |
| 8 | Kubernetes/runtime/audit multi-node causality and conservative purpose classification | Ch. 7-8, 23, 25, 30-31; A.9-A.10, A.15.3 |
| 9 | Authorized local and distributed response with blast-radius disclosure and verified postconditions | Ch. 24-25, 32, 34; A.15.4-A.15.6 |
| 10 | Qualified AWS/Google/GitHub/mesh/connector/artifact evidence, leases, and typed provider actuators | Ch. 23-26; A.10, A.15-A.16 |
| 11 | Packaging, upgrade, platform qualification, performance, complete HF conformance, and signed release claims | Ch. 25, 30-33, 37; A.4-A.7; C |
| 12 | Independent decisions/prototypes for deferred surfaces and optional upstream evidence adapters | Ch. 5, 7, 14, 21, 26, 35.1; A.13.6, A.16 |

Phase order is strict through Phase 11, including Phases 6.1, 6.2, and 6.3
between Phases 6 and 7. Phase 12 allocation decisions may begin after Phase 0, but a
physical evaluation must wait for the owning prerequisite named in Phase 12.
Phase 12 cannot satisfy a Phase 11 core gate.

Phase 6 owns the node WAL, upload client, replay behavior, and protocol-facing
acknowledgement cursor. Phase 6.1 moves that behavior to typed gRPC services
without changing its durable meaning. Phase 6.2 owns the production Control
transaction that makes an acknowledgement durable and the source cursor that
Phase 7 may read. This boundary lets Phase 6 close without assigning graph or
Control-store ownership to the node.

## Complete Design-To-Phase Coverage Ledger

This ledger is the master completeness check. A design row is covered only when
the named phase file contains a matching deliverable and proof.

| Architecture section or feature | Implementing phase(s) | Completion evidence |
| --- | --- | --- |
| Ch. 1-4 product, gap, claim/result vocabulary | 0, 11 | checked claim registry; release claims limited to proven boundaries |
| Ch. 5 node/trust architecture, one owner, unchanged workloads, secure control | 0, 1, 6.1, 6.2, 11 | exclusive pin lease; unchanged fixture; typed mTLS gRPC services; CRD/RBAC boundary; root-compromise limits |
| Ch. 6 actor/task/process/thread/exec/native identity | 2 | fork/thread/vfork/non-leader-exec/PID-reuse fixtures |
| Ch. 7 runtime-created roots, probes, lifecycle, admin exec, unmatched workloads | 2, 4, 8, 11 | stock-runtime matrix; restricted external role; one-use admin exception |
| Ch. 8 authorization proof, intent, trust/time/replay | 0, 2, 6.1, 6.2, 7, 10 | typed-service peer binding; signed-envelope goldens; replay/mismatch/restart tests |
| Ch. 9 exit, shutdown, reference retention | 2, 6 | exact cleanup/tombstone/reconciliation tests |
| Ch. 10 invariants | 0 and every phase | invariant-to-test ledger cannot lose a row |
| Ch. 11 readable policy, roles, effects, dispositions, exceptions | 0, 3, 4, 6.2 | capability-grounded policy CRD/offline-source equality; separate exception CRD; parser/compiler goldens; bounded-use exception consumption |
| Ch. 12 compiler, signatures, activation, rollback | 0, 3, 4, 6, 6.2 | deterministic bytes; source provenance; inactive readback; one CAS; retirement recovery |
| Ch. 13 one local decision and atomic state | 0, 2-5 | Rust/BPF lookup golden; task-first and contention tests |
| Ch. 14 mechanism boundaries and deferred Seccomp | 0, 1, 3-5, 12 | hook/capability matrix; Seccomp remains absent unless Phase 12 gate passes |
| Ch. 15 mounts, known-root path routes, oldest-mount fallback, exact objects | 0, 3, 4, 6.2 | Kubernetes baseline-submount order fixture; later bind-alias fixture; DIRTY topology races; object revalidation |
| Ch. 16 exec images and executable memory | 0, 3, 4 | exec chain, loader, memfd, mmap/mprotect, immutable-image fixtures |
| Ch. 17 files, credentials, delegated I/O | 0, 3, 4, 5 | token rotation, proc-fd, fd pass, remote delegate fixtures |
| Ch. 18 IPC, native authority, persistent objects | 2-5 | directional relationship, shared mapping, async unsupported tests |
| Ch. 19 network/DNS/TLS limits | 3, 5, 7, 10 | socket lifetime, rewrite, DNS exfiltration, same-TLS honest-result tests |
| Ch. 20 devices and derived authority | 0, 3, 4 | device/ioctl/derived-fd fixtures |
| Ch. 21 privilege, self-protection, Landlock, deferred Seccomp | 0, 3, 4, 11, 12 | escape matrix; self-protection oracle; optional-layer records |
| Ch. 22 evidence, coverage, proof quality, findings | 0, 6, 6.1, 6.2, 7 | typed evidence service; source epoch/gap tests; durable intake acknowledgement; deterministic replay |
| Ch. 23 cross-node/provider causality | 7, 8, 10 | one Control graph owner; registered edge contracts; fan-out/contradiction/shared-principal tests |
| Ch. 24 response transaction and blast radius | 9, 10 | authorization, simulation, exact re-resolution, physical readback |
| Ch. 25 complete HF proof package | 0, 3-11 | standing incident fixture grows in every phase; complete Phase 11 matrix |
| Ch. 26 CI/CD model and honest tiers | 10, 12 | provider/artifact foundations in 10; named CI adapters remain Phase 12 allocations |
| Ch. 27-29 Jailer/Meta/KubeArmor/Tetragon lessons | 0, 1-6 | pinned source dossier plus adopted-code provenance/test IDs |
| Ch. 30 combined pipeline | 1-10, including 6.1 and 6.2 | typed node services; base-policy lowering; target-bound exception activation; node delivery and node-to-Control evidence flow; end-to-end native and identical-probe examples |
| Ch. 31 acceptance | every phase, final 11 | exact fixture cases and physical oracles |
| Ch. 32 failure/recovery | 1, 2, 6, 6.1, 6.2, 9, 11 | transport/daemon/reader/control/API-watch/intake/link/map/restart fault matrix |
| Ch. 33 boundedness/performance | 0, 1-6, 6.1, 11 | per-hook distributions, gRPC flow-control bounds, N/N+1 maps, evidence-preserving benchmarks |
| Ch. 34 durable owners | 0, 1, 6.2, 7, 9, 10 | one writer per source, rollout, intake, graph, and actuator state family; no duplicate daemon/loader |
| Ch. 35 delivery/unallocated surfaces | this master, 6.1, 6.2, 7, 12 | typed service boundary, Control boundary, coverage linter, and deferred-surface ledger |
| Ch. 36 approval defaults | 0, 6.2, owning phase | recorded source, deletion, rollout, and security decisions before ABI/policy changes |
| Ch. 37 completion | 6.2, 11 | policy convergence proof and digest-bound qualification bundle with signed limited claim |
| A.1-A.7 foundations/qualification records | 0, 6, 11 | closure, bundles, result records, release envelope |
| A.8-A.12 identity/policy/kernel ABI | 0, 2-4, 6.2 | generated types, CRD source revisions, rollout records, goldens, lifecycle and lookup fixtures |
| A.13 Linux effects | 0, 3-5, 11, optional 12 | hook matrix and per-effect physical oracle |
| A.14 native authority/IPC | 2-4 | exact state and relationship fixtures |
| A.15 evidence/graph/response | 6, 6.1, 6.2, 7-10 | typed evidence service, durable intake, deterministic artifacts, and physical response results |
| A.16 CI/artifact/provider authority | 10, optional 12 | provider/artifact contracts; separately allocated CI adapters |
| Appendix B rejected designs | 0 and review in every phase | forbidden-contract lint and no historical authority |
| Appendix C fixtures/completion | every phase, final 11 | exact registry equality and criterion mapping |
| Appendix D sources | 0 | pinned digest/license/provenance/source-evidence registry |

Phase 6.2 owns the exact hostile privileged-Pod admission, the retained
containerd default-runtime gate for that OCI shape, exact measured Mithril
recovery, and the retained BPF incident floor for non-CRI bypasses. Helm is the
installer, but containerd owns hook invocation after installation. The design
does not retain an NRI service and does not require a RuntimeClass. Phase 8
owns signed privileged exceptions and the complete typed runtime matrix. Phase
11 must rerun both before it can make the complete Hugging Face prevention
claim. All other unallocated surfaces remain evaluation-only in Phase 12 and
require a new approved implementation phase before they can ship.

The retained gate admits a version-changed Mithril installer only when its
installer command, owner, host paths, writable mounts, privileges, and socket
match the retained installation. The installer replaces the host integration
and exact recovery manifest. It does not replace Control or Node durable
state. A normal reinstall reopens the same Control PVC and Node state paths.
Each state owner performs only an explicitly supported migration, and Control
continues the existing policy candidate and sequence chain. An unsupported
migration fails closed. A fresh Control combined with retained Node policy
state is not an upgrade and must fail anti-replay. Phase 11 qualifies the full
upgrade, rollback, and migration matrix.

### Hugging Face Card Allocation

| Incident cards | Owning implementation phases | Required integration result |
| --- | --- | --- |
| `HF-001` | 7, 10, 11 | external branch is `OUTSIDE_AUTHORITY`; a separately protected replay uses normal entry/effect controls |
| `HF-002`-`HF-003` | 3-5, 7 | managed exec/proc/file/network effects are exact; resident or external facts keep their honest limit |
| `HF-004` | 5, 7, 10 | connect/send/packet/provider-write results remain distinct |
| `HF-005`-`HF-006` | 3-5, 7, 10 | exact artifact/code/effect boundary or pure in-memory allowed result; no filename/packing fiction |
| `HF-007` | 5, 7, 10 | local destination and provider semantic result remain separate |
| `HF-008` | 3-4, 7 | earliest complete local block: exact forbidden file object denied before fd/bytes |
| `HF-009`-`HF-011` | 3-5, 7, 10 | file/read/output/result words and in-memory/same-TLS limits stay separate |
| `HF-012` | 5, 7-8, 10 | API/IMDS destination result plus separately proven Kubernetes/AWS operation |
| `HF-013`-`HF-020` | 8-10 | repository, mesh, connector, cluster, cloud, GitHub, external respawn, and host-location branches |
| `HF-021` | 9-10 | typed response, replacement/late branch watch, and exact partial/unknown recovery result |

Phase 11 reruns every card and granular branch under the candidate platform and
claim vector. No phase may mark a card complete by proving only one of the
required local, provider, outside-authority, or honest-limit branches.

### Explicit-Default Allocation

| Chapter 36 decision family | Decision/proof phase(s) |
| --- | --- |
| multiple roots, initial start, later exec, stock exec purpose | 0 feasibility; 2 identity; 8/11 platform qualification |
| approved administrative exec | 2 identity; 4 complete approval/admission/slot/exec transaction |
| `PreStop` under containment and missing identity | 2, 4-5, 9 |
| immutable executable identity | 0, 3-4 |
| same TLS endpoint | 5 local result; 10 provider result |
| several logical jobs in one process | 2 exact process limit; 7/9 finding and blast-radius disclosure |
| learning is review-only | 3 candidate generation; 7 finding workflow |
| production policy sources and deletion | 6.2 policy and exception CRD reconciliation, signed retirement, and last-valid-generation retention |
| partial policy rollout | 6.2 exact per-node inventory; 7 finding and claim limits; 11 scale/failover qualification |
| upstream code reuse/license | 0 dossier; each consuming phase cites it |
| real signed intent only | 0 schema; 2, 4, 7, and 10 owning issuers/consumers |
| disposition/stage separation | 0 schema; 3 simulation; 4-5 local; 10 provider |
| CI physical shape | 10 foundation; 12 named-adapter evaluation |

## Upstream Learning And Selective Adoption Gate

Phase 0 produces an `UPSTREAM-ADOPTION-V1` dossier before product code is
copied or derived. It must separately cover:

| Source | Required lesson/prototype | Explicit rejection or limit |
| --- | --- | --- |
| Meta BpfJailer deck | component state graph, wildcard matching, mount-root map, lowest `mnt_id_unique` fallback canonicalization, mount/rename/link protection, verifier/code-size budget | Node uses a known-root route first; the presentation is design evidence, not source-code provenance |
| Independent Jailer | task-storage declaration, parent-to-child copy in `task_alloc`, bounded BPF map/state patterns | never use pending-PID delayed enrollment; its dentry-only walk/inode cache is not the path authority |
| KubeArmor | BPF LSM pre-effect patterns, policy lowering, map publication, DNS/parser bounds, reader/loss behavior, mount traversal | missing identity cannot allow; action words/events do not prove physical results; no KubeArmor daemon |
| Tetragon | early fork identity, non-leader exec, cgroup resolution, NRI facts, loss accounting, fresh maps, generic LSM lessons | process cache is not Mithril authority; runtime metadata does not invent purpose; no Tetragon daemon |

Each adopted unit receives source path/commit/digest, license decision, local
owner, changed behavior, hostile fixture, and a `copied`, `derived`, or
`reimplemented` classification. Later implementation phases must cite the
approved dossier entry; “inspired by upstream” is not enough.

## Exact Fixture Allocation

The following is the first-completion owner for every one of the 133 IDs in
architecture Appendix C. Phase 3 reruns the Phase 4/5 physical-effect cases in
observe/simulation mode; Phases 7-10 rerun inputs needed by their graph and
response boundaries; Phase 11 reruns every active criterion. Those repetitions
do not change first ownership.

### Phase 0

```text
CFG-ROLLBACK-GOLDEN-002
CFG-V1-GOLDEN-002
DECISION-SET-GOLDEN-001
FIXTURE-REGISTRY-COMPLETE-001
SOURCE-KA-BOUNDS-004
SOURCE-KA-CAPACITY-005
SOURCE-KA-PARTIAL-ATTACH-001
SOURCE-KA-READER-LOSS-003
SOURCE-KA-STACK-PER-HOOK-002
SOURCE-TG-EXEC-MAP-007
SOURCE-TG-PATH-RENAME-008
SOURCE-TG-RUNTIME-JOIN-006
```

### Phase 1

```text
BOOT-ADMISSION-001
```

### Phase 2

```text
AUTHORIZATION-REPLAY-004
ENTRY-BINDING-GAP-001
ENTRY-CONTAINERS-001
ENTRY-EPHEMERAL-001
ENTRY-EXEC-001
ENTRY-EXEC-002
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
ENTRY-REUSE-001
ENTRY-SLEEP-001
ENTRY-START-001
ENTRY-STOCK-HOOK-FAILURE-002
EXEC-COMMIT-STATE-001
ID-CGROUP-ESCAPE-001
ID-CLONE-CGROUP-002
ID-CREATOR-PARENT-007
ID-MOVED-PARENT-FORK-004
ID-MOVED-TASK-EXEC-005
ID-TASK-COORD-FINALIZE-006
NATIVE-STATE-REF-LIFETIME-001
```

### Phase 4

```text
ADMIN-EXEC-APPROVAL-001
DEVICE-DERIVED-001
EXEC-CONCURRENT-002
FILE-CONTENT-RACE-002
FILE-FD-PASS-001
FILE-IDENTITY-001
FILE-MMAP-001
FILE-MMAP-SHARED-011
FILE-NAMESPACE-001
FILE-SA-TOKEN-OPEN-001
FILE-VMA-SNAPSHOT-001
HF-LOCAL-001
IPC-ASYNC-UNSUPPORTED-010
IPC-PEER-RACE-004
IPC-PROCESS-CHANNEL-009
IPC-RELATIONSHIP-ALLOW-003
IPC-RELATIONSHIP-UNMATCHED-005
LSM-DENY-SATURATION-001
MEM-EXEC-001
MEM-KERNEL-MAP-002
MOUNT-ATTR-001
MOUNT-CAS-002
MOUNT-PROPAGATION-003
MOUNT-SNAPSHOT-004
SELF-PROTECT-001
STATE-FORK-IPC-002
STATE-PERSISTENT-FILE-LIFETIME-007
STATE-THREAD-RACE-001
```

### Phase 5

```text
FILE-DELEGATED-EGRESS-001
HF-004-RESULT-001
HF-011-READ-RESULT-001
HF-NET-001
IPC-LOCAL-INET-008
NET-ACCEPT-PASS-001
NET-DNS-EXFIL-001
NET-NS-PASS-001
NET-RECV-001
NET-REWRITE-001
NET-SHARED-RESPONSE-002
NET-SOCKCTL-001
NET-SOCKET-LIFE-001
```

### Phase 6

```text
IPC-ENDPOINT-RESTART-006
IPC-RELATIONSHIP-LOSS-002
```

### Phase 8

```text
EDGE-K8S-SHARED-002
HF-GRAN-CLUSTER-SHARED-001
HF-GRAN-HOSTPATH-001
NODE-FLOOR-EXCEPTION-002
XNODE-PRIVILEGED-POD-001
```

### Phase 9

```text
HF-GRAN-CAPTURE-001
HF-GRAN-RESPAWN-001
HF-RESP-002
HF-RESP-BLAST-RADIUS-003
```

### Phase 10

```text
EDGE-ARTIFACT-CONSUMER-005
EDGE-AWS-SHARED-001
EDGE-CONNECTOR-FORWARD-004
EDGE-GITHUB-SHARED-003
EDGE-MESSAGE-CONSUMER-006
HF-GRAN-AWS-DRYRUN-001
HF-GRAN-AWS-SPLIT-001
HF-GRAN-CONNECTOR-DIRECT-001
HF-GRAN-DEAD-DROP-001
HF-GRAN-GITHUB-MINT-001
HF-GRAN-GITHUB-REARM-001
HF-GRAN-GITHUB-REVOKE-001
HF-GRAN-GITHUB-TREE-PR-001
HF-GRAN-HOST-LOC-001
HF-GRAN-MESH-ENUM-001
HF-GRAN-MESH-ROOT-001
HF-GRAN-MESH-SOCKS-001
HF-GRAN-OUTSIDE-001
HF-GRAN-TOKEN-FORGE-001
```

### Phase 12, Conditional Only

```text
CHECKPOINT-CREATE-001
CI-CACHE-001
CI-CONTAINER-001
CI-DEBUG-001
CI-DIND-001
CI-FANOUT-001
CI-GITHUB-TOKEN-001
CI-NATIVE-001
CI-OFFICIAL-STEP-JOIN-001
CI-OIDC-001
CI-OUTPUT-001
CI-POST-001
CI-PR-001
CI-RETRY-001
CI-RUNNER-REUSE-001
CI-STATE-001
ENTRY-RESTORE-001
ENTRY-STREAM-001
HF-GRAN-CI-BUILDRS-001
SECCOMP-QUAL-001
```

Phases 3, 6.1, 6.2, 6.3, 7, and 11 have no new first-owned Appendix C IDs. Phase 3
must prove the observation/simulation form of the exact Phase 4/5 IDs. Phase
6.1 must prove its named gRPC service and cutover cases. Phase 6.2 must
prove its named reconciliation, rollout, and intake cases. Phase 6.3 must
prove structured service output without treating logs as evidence. Phase 7 must prove
the named detection packages using already-owned inputs. Phase 11 must prove
registry equality and every criterion active in the signed claim. A
phase-owned test that is not an Appendix C fixture remains required by its
phase but cannot silently expand the closed registry.

No phase may rename, add, or remove a fixture without updating Appendix C,
the registry artifact, criterion mapping, and this allocation in one review.

## Cross-Cutting Failure Ownership

| Failure boundary | First implementation owner | Required result |
| --- | --- | --- |
| hook/helper/BTF/LSM absent or partial attach | 0-1 | unsupported capability; no readiness or equivalent claim |
| missing task/parent/coordinate or ambiguous external purpose | 2 | restrictive unknown/intersection; no invented role |
| policy compile/readback/probe/CAS failure | 3-4 | old complete generation remains; no partial activation |
| mount/path/object ambiguity or bound overflow | 3-4 | strict unresolved result; never cached/fallback allow |
| socket peer/rewrite/final-flow ambiguity | 5 | configured unmatched/deny result and exact claim limit |
| ring/reader/WAL/map/link/pin/restart failure | 6 | physical decision preserved where live; coverage gap/claim closure |
| gRPC peer, method, stream, bound, cancellation, or cutover failure | 6.1 | no fallback dispatch or authorization change; durable state advances only through its domain rule |
| CRD watch, compile, rollout, Control intake, or acknowledgement failure | 6.2 | last valid local generation remains; mixed state and missing durable acknowledgement stay explicit |
| operational log initialization or rendering failure | 6.3 | invalid configuration prevents readiness; later output loss cannot change enforcement, evidence, policy, or recovery state |
| Control, audit, notification, or provider source outage | 6-10 | local generation remains authoritative; remote conclusion/action becomes unavailable or weaker |
| stale/reused/wider response target | 9-10 | no actuation until exact re-resolution and blast-radius approval |
| unsupported platform, upgrade, or performance/capacity failure | 11 | signed claim omitted or narrowed for that exact manifest |
| optional-surface failure | 12 | `DEFER`/`REJECT`; no change to the core release |

## Phase Index

- [Phase 0: Substrate, License, ABI, And Incident Baseline](./phase-0-substrate-license-abi-and-incident-baseline.md)
- [Phase 1: One-Binary Node Chassis](./phase-1-one-binary-node-chassis.md)
- [Phase 2: Exact Native Identity](./phase-2-exact-native-identity.md)
- [Phase 3: Effect Observation And Profile Simulation](./phase-3-effect-observation-and-profile-simulation.md)
- [Phase 4: Signed Local Pre-Effect Enforcement](./phase-4-signed-local-pre-effect-enforcement.md)
- [Phase 5: Process-Aware Network Plane](./phase-5-process-aware-network-plane.md)
- [Phase 6: Durable Evidence, Coverage, And Recovery](./phase-6-durable-evidence-coverage-and-recovery.md)
- [Phase 6.1: gRPC Service And IPC Convergence](./phase-6-1-grpc-service-and-ipc-convergence.md)
- [Phase 6.2: Control Policy And Evidence Convergence](./phase-6-2-control-policy-and-evidence-convergence.md)
- [Phase 6.3: Shared Telemetry And Operational Logging](./phase-6-3-shared-telemetry-and-operational-logging.md)
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
