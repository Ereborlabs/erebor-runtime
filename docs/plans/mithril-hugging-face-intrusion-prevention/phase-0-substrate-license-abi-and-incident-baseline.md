# Phase 0: Substrate, License, ABI, And Incident Baseline

Status: Done for the physically qualified x86_64 capability claim. The
corrected benchmark distributions now have a current physical record. The
remaining 16 allocated capabilities are explicit unsupported records.

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

## Historical Phase Result (superseded)

```text
State: Blocked.
Validated architecture revision/digest: policy-and-protection-algorithm-architecture-readable.md at SHA-256 4a445b4015c4868a87af4893398068c5f362452c316d0cb8d06c038d41ffc0d8.
Completed deliverable IDs: D0.1, D0.2, D0.3, D0.6, D0.7. D0.4 has compile-time and hostile-model evidence plus one live x86 BPF-LSM file-open attach/effect probe; it is not complete. D0.5 remains deferred and deliberately has no Rust/C candidate ABI or decision golden until D0.4 passes. D0.8 records this blocked boundary.
Files and durable owners changed: erebor-interceptor-abi owns portable interception types only; erebor-runtime-core::interception is its compatibility re-export; mithril-e2e owns kernel qualification, provenance, source-regression, fixture, capability, benchmark, and direct libbpf-rs qualification loaders; bpf/erebor-interceptor/include owns the checked-in x86, arm64, arm, and riscv kernel headers using the Tetragon wrapper pattern; bpf/erebor-interceptor/qualification owns the disposable feasibility object with direct libbpf map declarations; spec/qualification/v1 and spec/provenance/v1 own the checked registries; phase-0-artifacts/interceptor-ownership.md and security-bootstrap-decision.md record the two decisions. No product loader or daemon was added.
Dependency decision: mithril-e2e pins libbpf-rs 0.27.0 with its `vendored` feature. Cargo.lock checksums lock libbpf-rs and libbpf-sys; that feature builds the bundled libbpf, libelf, and zlib rather than linking host copies. libbpf-rs is dual licensed LGPL-2.1-only OR BSD-2-Clause; Phase 0 adopts the BSD-2-Clause option. No upstream source was copied into this repository.
Upstream-adoption dossier IDs used: UPSTREAM-ADOPTION-V1 with META-MOUNT-ROOT-001, META-OLDEST-MOUNT-002, META-COMPONENT-GRAPH-003, META-MUTATION-DIRTY-004, META-VERIFIER-BUDGET-005, BJ-TASK-STORAGE-001, BJ-REJECTED-ENROLLMENT-002, KA-LSM-DECISION-001, KA-POLICY-PUBLICATION-002, KA-PATH-MOUNT-003, KA-DNS-BOUNDS-004, KA-READER-CAPACITY-005, TG-FORK-EXEC-001, TG-RUNTIME-CGROUP-JOIN-002, TG-GENERIC-LSM-003, TG-VMLINUX-HEADER-006, TG-VMLINUX-ARM64-007, AS-VMLINUX-ARM-001, AS-VMLINUX-RISCV-002, TG-FRESH-MAPS-004, and TG-CONCURRENCY-LOSS-005. All pinned repository, commit, license, and primary-source digests pass source-check.
Fixture cases and exact physical results: FIXTURE-REGISTRY-COMPLETE-001 and the eight SOURCE-* hostile models pass. The owned object compiles twice to identical bytes against the checked-in host x86 kernel header and compiles once against each checked-in x86, arm64, arm, and riscv header; tests prove no `vmlinux.h` or ABI header is generated into their output directories. The fully vendored direct libbpf-rs loader test opens and validates the generated object without privilege. The privileged x86 run loaded the object, created its task-storage, array, and ring-buffer maps, and attached all 21 LSM programs. Its ephemeral link IDs were 2 through 22 and program IDs 73 through 93. It physically proved file-open allow -> map readback and `EACCES` deny -> map clear and allow for inode 18091956. Each other LSM hook has load/attach evidence only; the non-LSM `qualification_final_flow` program was loaded but deliberately not attached by this LSM-only qualifier. There is therefore no physical claim yet for cgroup/final-flow or for any effect other than file open. DECISION-SET-GOLDEN-001, CFG-V1-GOLDEN-002, and CFG-ROLLBACK-GOLDEN-002 remain intentionally unimplemented until D0.4 passes.
Commands and exact source state covered: cargo fmt --all --check, git diff --check, cargo test -p mithril-e2e --all-targets --all-features, and bash .github/scripts/verify-rust-ci.sh pass after the fully vendored selection. The vendored build used an offline temporary Cargo home containing a writable copy of the locked libbpf-sys crate because the host Cargo registry is read-only; this does not alter Cargo.lock or the dependency graph. The unprivileged physical probe reached the libbpf load call and correctly failed with `EPERM`. The interactive privileged command, target/debug/mithril-kernel-qualification --repo-root . physical-probe --output-directory /tmp/mithril-kernel-qualification/physical, succeeded and produced physical-file-open-probe.json with the results above. These results cover the dirty working tree, not a commit.
Platform/kernel/runtime manifests: current node is x86_64 Linux 6.8.0-137-generic; BTF SHA-256 6da9f6b4ebcae9b07e6a717b517884abf7f6b524e46340e40fb164eed4a49a7c; checked headers are local generated x86 (SHA-256 fdf27f9576476716322614877427f24c2632a96183d981152ac37e45ff2c9d8d), Tetragon generated arm64, and AgentSight generated arm and riscv; cgroup v2 present; BPF LSM active on the current x86 host; deterministic candidate BPF object SHA-256 aa2469419bdd396a00552d9b8a2f094db501bf60771919ddf6079604172bcb21. Arm64, arm, and riscv are compile-only until separately measured. The checked two-node manifests remain MEASURE_AT_RUNTIME templates until the live lab run.
Performance/capacity results: the benchmark smoke runner retained 1,000 raw open samples after 100 warmups at concurrency 1 and 32; this is runner validation, not the required qualification distribution. AuthoritativeMap N/N+1 denies without corrupting N, AtomicGeneration rejects partial publication, TaskStorage fails closed at capacity/missing parent, and reader loss preserves installed denial in code-backed hostile tests. The required 100,000-warmup/1,000,000-sample baseline/protected trials and live kernel map/verifier limits have not run.
Candidate bundle digests: closure/provenance/fixture candidate contract 27911af9a1557185e49689737ba82205c509d085e2b0c845514bb51563837311; unchanged protected fixture 741a9fd0857e360a8b3096924f52dd59695d9f6440aa6610370e4e092b23b1dc.
Unsupported/degraded paths: file-open is physically supported only for this single x86 qualifier case. All other effect-family, cgroup/final-flow, helper, prior-result, saturation, evidence-loss, and per-hook behavior claims remain unsupported until their own physical probes and exact bounds pass. No unsupported surface is represented as frozen or released.
Remaining work in this phase: run privileged per-effect allow/deny/failure probes and cgroup/final-flow attachment; record verifier, helper, map, link, task-storage, prior-result, saturation, and evidence-loss bounds plus two platform manifests; run full baseline/protected distributions; then and only then implement/freeze the complete source-policy, compiled profile/signature/rollback, evidence, capability/performance/result schemas and CFG goldens; rerun the repository CI procedure after the final Rust edit.
Next phase not authorized: yes.
```

## Phase Result

```text
State: Done for capability closure and the corrected physical performance record.
Validated architecture revision/digest: policy-and-protection-algorithm-architecture-readable.md at SHA-256 4a445b4015c4868a87af4893398068c5f362452c316d0cb8d06c038d41ffc0d8.
Completed deliverable IDs: D0.1-D0.8. Version 1 freezes only the physically proven x86_64 BPF-LSM attach/readback and file-open pre-effect denial slice. The remaining 16 allocated capabilities are explicit Unsupported records and cannot be advertised.
Files and durable owners changed: erebor-interceptor-abi owns the closed Rust authority types and cbindgen-checked C header; erebor-interceptor owns the only libbpf-rs loader/link/map/pin-root lease; mithril-e2e owns qualification, capability closure, benchmarks, goldens, provenance, and checked results; bpf/erebor-interceptor owns checked multi-architecture vmlinux headers and the Phase 0 C CO-RE object; spec/qualification/v1 and spec/provenance/v1 own digest-bound evidence. Runtime can only use the shared read-only client and cannot create a second kernel owner.
Dependency decision: libbpf-rs 0.27.0 is pinned with its fully vendored libbpf/libelf/zlib feature for runtime object, program, map, link, pin, and readback ownership. Pinned cbindgen 0.29.4 is build-time ABI glue only: it renders the C header from Rust repr(C) authority into OUT_DIR and rejects any byte drift from the checked header. No custom ABI parser or generator remains.
Upstream-adoption dossier IDs used: UPSTREAM-ADOPTION-V1 and its META-*, BJ-*, KA-*, TG-*, and AS-* records. The selected practices are source-pinned and license checked; no upstream daemon was copied into the product chassis.
Fixture cases and exact physical results: CFG-V1-GOLDEN-002, CFG-ROLLBACK-GOLDEN-002, DECISION-SET-GOLDEN-001, FIXTURE-REGISTRY-COMPLETE-001, and the eight SOURCE-* hostile models pass. The current privileged x86_64 probe loaded three maps, attached and read back 35 LSM programs, and recorded file_open_allow_deny_allow=true. The probe artifact SHA-256 is 701e3051ba8a9139a4561e935b679b3d900fa9bde542da6dbb24ed484756e0eb. The physical file-open evidence SHA-256 is c435ef585e9697fb91262ce75f0853eae033c8f5f81e19c19bc8637d883ac840. The qualification record SHA-256 is 5fa38103d830543b544be83d75968870d3ff4ab9aa13f20f8576cae7405b8f9f.
Commands and exact source state covered: the disposable VM record under /tmp/mithril-vm-source18-final covers BPF source SHA-256 9a4259269a545f32f72398a62357b0798c5008311f866d4695ee549fec1ea8d1 and BPF object SHA-256 71f681542da5188ab5acfd3f81f56cee789b904e7952c767bd1f73162e2fc118. Repository CI results are recorded separately after the final repository edit. The superseded Browser-CDP process-mediation E2E stays ignored with a TODO to implement it on the shared Interceptor.
Platform/kernel/runtime manifest: x86_64 Linux 6.8.0-136-generic; LSM order lockdown,capability,landlock,yama,apparmor,bpf; runtime BTF SHA-256 9aa9eb9e8108bff44e685830315fb7a442bafd99778314cdd6de0fb72868829f; ABI header SHA-256 f42baa4dd9b7c744c9611c3560c8198b4c899940677822452c48cbf28570b931. The supported capability IDs are BPF_LSM_ATTACH_READBACK, FILE_OPEN_PRE_EFFECT_DENIAL, and X86_64_PHYSICAL_QUALIFICATION. The other 16 capability records are unsupported. Arm64, arm, and riscv have checked compile headers but no physical qualification.
Performance/capacity results: every distribution completed 100,000 warmup operations and 1,000,000 measured operations. At concurrency 1, BASELINE recorded elapsed_ns=4996974543, operations_per_second=200121.0915514564, p50_ns=4336, p95_ns=4415, p99_ns=5798, maximum_ns=812662, and raw_samples_sha256=a95680d66a4f236ae3792c2669de4e46cfd5e595dd2575462ea7365db0a03dbb. At concurrency 32, BASELINE recorded elapsed_ns=2584003144, operations_per_second=386996.4331591386, p50_ns=4415, p95_ns=4942, p99_ns=9696, maximum_ns=45029839, and raw_samples_sha256=795f921413e783f4083dc9cef4bab447998b0390213374fccc5752397f7b7717. At concurrency 1, PROTECTED recorded elapsed_ns=5114964515, operations_per_second=195504.7776123233, p50_ns=4445, p95_ns=4505, p99_ns=6255, maximum_ns=1548407, and raw_samples_sha256=53a70f61a3747aa82509aa7b1569b137723b33480dec9623372a9173f666e44c. At concurrency 32, PROTECTED recorded elapsed_ns=2657156010, operations_per_second=376342.2231275009, p50_ns=4535, p95_ns=5589, p99_ns=12788, maximum_ns=58021750, and raw_samples_sha256=c4aa53e24ffc6279b26f066abd56208f0d786c8a7385e990bb4f56c90ff8824b. The baseline artifact SHA-256 is fc4ad21e7641039ec780cb101311906c460b55be2f30c4a1ceed1211100d5208. The protected artifact SHA-256 is c1f1185f4b3f60066cf680f44e189bd1ad2740f4eba48b73486302d342749143.
Closed-contract digest: 8a4c4b0662c5382b91c3353b52593bf8a3fe81e9363d28062e7d7d3792161bbf. Unchanged protected fixture: 741a9fd0857e360a8b3096924f52dd59695d9f6440aa6610370e4e092b23b1dc.
Unsupported/degraded paths: task/fork/exec identity, mount component graph, mutation DIRTY/reconciliation, non-file effect families, final-flow/DNS/network enforcement, evidence-loss guarantees, and non-x86 physical claims are unsupported. The loaded non-LSM final-flow prototype is not attached or claimed.
Remaining work in this phase: none for the closed x86_64 claim. New capability work belongs to a later authorized outcome.
Next authorization boundary: each later phase has its own result.
```
