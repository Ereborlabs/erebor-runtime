# Phase 0: Substrate, License, ABI, And Incident Baseline

Status: Proposed. This phase is not authorized until approved by name.

Master: [Mithril Hugging Face Intrusion Prevention](./README.md)  
Design authority: [Validated readable architecture](./policy-and-protection-algorithm-architecture-readable.md)
Manual acceptance: [Phase 0 runbook](./manual-testing/phase-0-manual-acceptance.md)  
Environment setup: [shared setup guide](./manual-testing/environment-setup.md)

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
State: Blocked.
Validated architecture revision/digest: policy-and-protection-algorithm-architecture-readable.md at SHA-256 4a445b4015c4868a87af4893398068c5f362452c316d0cb8d06c038d41ffc0d8.
Completed deliverable IDs: D0.1, D0.2, D0.3, D0.6, D0.7. D0.4 has compile-time and hostile-model evidence only. D0.5 remains deferred and deliberately has no Rust/C candidate ABI or decision golden until D0.4 passes. D0.8 records this blocked boundary.
Files and durable owners changed: erebor-interceptor-abi owns portable interception types only; erebor-runtime-core::interception is its compatibility re-export; mithril-e2e owns Phase 0 closure, provenance, source-regression, fixture, capability, benchmark, and direct libbpf-rs qualification loaders; bpf/erebor-interceptor/include owns the checked-in x86, arm64, arm, and riscv kernel headers using the Tetragon wrapper pattern; bpf/erebor-interceptor/phase0 owns the disposable feasibility object with direct libbpf map declarations; spec/qualification/v1 and spec/provenance/v1 own the checked registries; phase-0-artifacts/interceptor-ownership.md and security-bootstrap-decision.md record the two decisions. No product loader or daemon was added.
Dependency decision: mithril-e2e pins libbpf-rs 0.27.0 with its `vendored` feature. Cargo.lock checksums lock libbpf-rs and libbpf-sys; that feature builds the bundled libbpf, libelf, and zlib rather than linking host copies. libbpf-rs is dual licensed LGPL-2.1-only OR BSD-2-Clause; Phase 0 adopts the BSD-2-Clause option. No upstream source was copied into this repository.
Upstream-adoption dossier IDs used: UPSTREAM-ADOPTION-V1 with META-MOUNT-ROOT-001, META-OLDEST-MOUNT-002, META-COMPONENT-GRAPH-003, META-MUTATION-DIRTY-004, META-VERIFIER-BUDGET-005, BJ-TASK-STORAGE-001, BJ-REJECTED-ENROLLMENT-002, KA-LSM-DECISION-001, KA-POLICY-PUBLICATION-002, KA-PATH-MOUNT-003, KA-DNS-BOUNDS-004, KA-READER-CAPACITY-005, TG-FORK-EXEC-001, TG-RUNTIME-CGROUP-JOIN-002, TG-GENERIC-LSM-003, TG-VMLINUX-HEADER-006, TG-VMLINUX-ARM64-007, AS-VMLINUX-ARM-001, AS-VMLINUX-RISCV-002, TG-FRESH-MAPS-004, and TG-CONCURRENCY-LOSS-005. All pinned repository, commit, license, and primary-source digests pass source-check.
Fixture cases and exact physical results: FIXTURE-REGISTRY-COMPLETE-001 and the eight SOURCE-* hostile models pass. The owned object compiles twice to identical bytes against the checked-in host x86 kernel header and compiles once against each checked-in x86, arm64, arm, and riscv header; tests prove no `vmlinux.h` or ABI header is generated into their output directories. The direct libbpf-rs loader test opens and validates the generated object without privilege. BPF LSM is active on x86, but its unprivileged physical probe fails with libbpf `EPERM` while loading; the privileged rerun is blocked because `sudo -n` reports "a password is required". No privileged load, attach, or physical effect result has been recorded. DECISION-SET-GOLDEN-001, CFG-V1-GOLDEN-002, and CFG-ROLLBACK-GOLDEN-002 remain intentionally unimplemented until D0.4 passes.
Commands and exact source state covered: cargo fmt --all --check and git diff --check pass after the fully vendored selection. cargo test -p mithril-e2e --all-targets --all-features passed before that selection; its enabled build is currently blocked because libbpf-sys requires GNU `gawk`, which is absent and cannot be installed without sudo. cargo run -p mithril-e2e --bin mithril-phase0 -- --repo-root . physical-probe --output-directory /tmp/erebor-phase0-libbpf-probe reached the libbpf load call and correctly failed with `EPERM`; sudo -n target/debug/mithril-phase0 --repo-root . physical-probe --output-directory /tmp/erebor-phase0-libbpf-probe was blocked because sudo requires a password. Full repository CI must be rerun after the final source edit. These results cover the dirty working tree, not a commit.
Platform/kernel/runtime manifests: current node is x86_64 Linux 6.8.0-137-generic; BTF SHA-256 6da9f6b4ebcae9b07e6a717b517884abf7f6b524e46340e40fb164eed4a49a7c; checked headers are local generated x86 (SHA-256 fdf27f9576476716322614877427f24c2632a96183d981152ac37e45ff2c9d8d), Tetragon generated arm64, and AgentSight generated arm and riscv; cgroup v2 present; BPF LSM active on the current x86 host; deterministic candidate BPF object SHA-256 aa2469419bdd396a00552d9b8a2f094db501bf60771919ddf6079604172bcb21. Arm64, arm, and riscv are compile-only until separately measured. The checked two-node manifests remain MEASURE_AT_RUNTIME templates until the live lab run.
Performance/capacity results: the benchmark smoke runner retained 1,000 raw open samples after 100 warmups at concurrency 1 and 32; this is runner validation, not the required qualification distribution. AuthoritativeMap N/N+1 denies without corrupting N, AtomicGeneration rejects partial publication, TaskStorage fails closed at capacity/missing parent, and reader loss preserves installed denial in code-backed hostile tests. The required 100,000-warmup/1,000,000-sample baseline/protected trials and live kernel map/verifier limits have not run.
Candidate bundle digests: closure/provenance/fixture candidate contract 27911af9a1557185e49689737ba82205c509d085e2b0c845514bb51563837311; unchanged protected fixture 741a9fd0857e360a8b3096924f52dd59695d9f6440aa6610370e4e092b23b1dc.
Unsupported/degraded paths: every physical BPF hook/helper/map/link, prior-result, saturation, evidence-loss, and effect-family claim remains unsupported pending a privileged active-BPF-LSM load/attach run. No unsupported surface is represented as frozen or released.
Remaining work in this phase: obtain sudo authority and run privileged verifier/load/attach and physical allow/deny/failure probes; record exact bounds and two platform manifests; run full baseline/protected distributions; then and only then implement/freeze the complete source-policy, compiled profile/signature/rollback, evidence, capability/performance/result schemas and CFG goldens; rerun the repository CI procedure after the final edit.
Next phase not authorized: yes.
```
