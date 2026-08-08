# Phase 0: Substrate, License, ABI, And Incident Baseline

Status: Proposed. This phase is not authorized until approved by name.

Master: [Mithril Hugging Face Intrusion Prevention](./README.md)  
Design authority: [Validated readable architecture](./policy-and-protection-algorithm-architecture-readable.md)

## Purpose

Prove the selected stock kernel/runtime mechanisms before freezing contracts.
Close the Version-1 types, shared Interceptor boundary, source provenance,
fixtures, and performance budgets needed by all later phases.

## Scope And Design Coverage

- Chapters 1-5: product/claim/trust boundaries.
- Chapters 10-14: invariants, policy, decision and mechanism feasibility.
- Chapters 15-21: prototype every allocated Linux effect family.
- Chapters 27-30 and Appendix D: upstream learning and checked evidence.
- Chapters 31, 33-36 and Appendices A.1-A.13, B, C: qualification,
  ownership, exact types, rejected contracts, fixtures, and delivery gates.

## Deliverables

### D0.1 — Architecture closure and traceability

Produce a machine-checked ledger containing every Chapter 1-37 section,
Appendix A.1-A.16 contract family, invariant, fixture ID, durable owner, and
owning phase. Reject unknown references, duplicate fixture IDs, active rejected
contract names, and a phase without a physical oracle.

### D0.2 — Shared Interceptor ownership decision

Approve the exact crate/module names for the shared Interceptor family. The
decision must:

- inventory `erebor-runtime-core::interception`, the Session interception
  broker/backend, and the Linux kernel-native enforcement plan;
- identify portable concepts to move, Session-only concepts to retain, and
  compatibility adapters to test;
- assign one exclusive loader/link/map/pin-root owner in Runtime-only,
  Mithril-only, and co-resident modes; and
- prohibit an independent Runtime BPF loader after the shared owner exists.

The expected boundary is `erebor-interceptor-abi` plus
`erebor-interceptor`, embedded by `mithril-node`; Phase 0 may rename it without
changing the one-owner result.

### D0.3 — Pinned upstream adoption dossier

Create one record per copied, derived, or reimplemented unit from:

- Meta BpfJailer: mount-root index, lowest-`mnt_id_unique`
  canonicalization, state-graph wildcard matching, mutation protection, and
  verifier/code-size limits;
- independent Jailer: task storage and parent-to-child `task_alloc` copying;
- KubeArmor: BPF LSM decisions, policy lowering/publication, path/mount/DNS
  mechanics, prior denial, bounds, readers, and loss; and
- Tetragon: early fork context, non-leader exec, cgroup/runtime joins, fresh
  maps, generic LSM behavior, concurrency, and loss.

Every record includes repository/commit/file/lines or PDF digest/slides,
license, transitive dependencies, local owner, semantic differences, and
hostile fixture. Explicitly reject Jailer's pending-PID enrollment and
dentry-only inode-cache authority, and reject upstream daemons as product
chassis.

### D0.4 — Hostile feasibility prototypes before ABI freeze

On each candidate platform, compile, load, and physically probe:

1. BPF LSM activation/order, BTF/CO-RE, helpers, task storage, cgroup hooks,
   attach/link/map limits, prior-result behavior, and failure results;
2. `task_alloc`, fork/thread/vfork, non-leader exec, success/failure/PONR, and
   first-protected-effect identity availability;
3. Meta's bounded component graph plus mount-root-to-oldest-mount traversal,
   including the `/var/run/secrets/service` to `/work/input/job-42` bind-alias
   fixture and an ordinary-subdirectory limitation;
4. pre-effect DIRTY ordering for mount/move/unmount/pivot/namespace/rename/link
   mutations and complete snapshot reconciliation;
5. file, exec, mmap/mprotect, IPC, socket, final-flow, DNS, device/ioctl,
   process-control, privilege, and self-protection decision points; and
6. verifier, stack, instruction, map, component-depth, latency, throughput,
   saturation, N/N+1, and evidence-loss behavior.

A failing surface remains unsupported and is absent from the frozen claim.

### D0.5 — Authority-bearing types, schemas, ABI, and goldens

Only after D0.4 passes, implement the Appendix A foundation and type-closure
records, generated Rust/C layouts, closed enums/unions, source policy schema,
compiled generation/signature/rollback schema, kernel decision ABI, evidence
envelope, capability/performance/result bundles, fixture registry, and golden
bytes. Close every authority-bearing type that crosses the Rust/C ABI or is
independently persisted, transferred, signed, compared, or released. Ordinary
internal in-memory helpers need not be cataloged, wire-closed, or individually
digested. Child records already covered by canonical signed parent bytes do
not receive redundant digests. Rust and C consume generated ABI definitions
from one authority.

### D0.6 — Reproducible testbed and incident baseline

Create the safe Hugging Face fixture skeleton, exact stage/postcondition map,
two-node platform manifests, deterministic replay inputs, capability probe
runner, benchmark runner, and fixture-registry equality test. Record the
unchanged workload digest before any enforcement.

### D0.7 — Mithril Control/node security bootstrap decision

Specify only what Phase 1 needs: node identity issuance, trust roots, mutual
TLS, outbound gRPC connection, version negotiation, replay/sequence handling,
and failure posture. Do not freeze a public API or provider connector surface.

### D0.8 — Phase result and implementation authorization boundary

Publish all supported/unsupported prototype results, approved upstream dossier
IDs, closed-contract digest, platform budgets, and the exact Phase 1 scope.

## Checkpoint

One digest-bound feasibility/closure bundle proves every Version-1 surface or
marks it unsupported, accounts for every design/owner/fixture row, and records
the only contracts Phase 1 may implement. No product daemon is the checkpoint.

## Required Tests And Fixtures

- `CFG-V1-GOLDEN-002`, `CFG-ROLLBACK-GOLDEN-002`,
  `DECISION-SET-GOLDEN-001`, `FIXTURE-REGISTRY-COMPLETE-001`.
- `SOURCE-KA-PARTIAL-ATTACH-001`, `SOURCE-KA-STACK-PER-HOOK-002`,
  `SOURCE-KA-READER-LOSS-003`, `SOURCE-KA-BOUNDS-004`,
  `SOURCE-KA-CAPACITY-005`, `SOURCE-TG-RUNTIME-JOIN-006`,
  `SOURCE-TG-EXEC-MAP-007`, `SOURCE-TG-PATH-RENAME-008`.
- Feasibility instances of the owning later-phase fixtures; these prove hooks
  and bounds but do not complete the later product capability.

## Acceptance

- Every allocated surface has a passing physical prototype and exact bound, or
  is explicitly unsupported.
- No ABI/type was frozen before its mechanism proof.
- One shared Interceptor owner is approved across both master plans.
- Every adopted upstream unit has a license/provenance record and hostile test.
- The fixture/coverage ledger accounts for the entire validated architecture.

## Excluded

No product daemon, production policy enforcement, provider connector,
response actuator, or optional Phase 12 surface ships here.

## Phase Result

```text
State: Not done.
Validated architecture revision/digest: not recorded.
Completed deliverable IDs: none.
Files and durable owners changed: none.
Upstream-adoption dossier IDs used: none.
Fixture cases and exact physical results: not run.
Commands and exact source state covered: none; this is a plan-only rewrite.
Platform/kernel/runtime manifests: none.
Performance/capacity results: none.
Unsupported/degraded paths: not yet measured.
Remaining work in this phase: all deliverables.
Next phase not authorized: yes.
```
