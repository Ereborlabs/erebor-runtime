# Phase 3: Effect Observation And Profile Simulation

Status: Blocked pending the real Docker/CRI operator cases. The implemented
self-cleaning privileged Phase 3 effect probe passed on 2026-08-10; no
prevention claim is made.

Master: [Mithril Hugging Face Intrusion Prevention](./README.md)
Design: [Validated readable architecture](./policy-and-protection-algorithm-architecture-readable.md)
Manual acceptance: [Phase 3 runbook](./manual-testing/phase-3-manual-acceptance.md)  
Environment setup: [shared setup guide](./manual-testing/environment-setup.md)

## Purpose

Implement the complete source-policy compiler and observe-only local effect
model. Prove that every future deny is paired with the real actor, object,
hook, state, and physical result before enabling policy enforcement.

## Scope And Design Coverage

Chapters 10-21 and 28-31; Appendices A.11-A.14.

## Deliverables

### D3.1 — Source policy and compiler in Mithril Control

Implement the closed parser, registries, selectors, roles, entries,
transitions, effects, bounded exceptions, dispositions, exact conflicts,
canonical bytes, signatures, anti-rollback, and deterministic lowering.
Unknown/duplicate/open fields reject. Policy names may be reused; generations
and signed content remain exact.

### D3.2 — Candidate generation and simulation

Build complete inactive map generations, read them back, run deterministic
simulation, and generate explanations without activating physical denial.
Non-path selectors expand to finite exact keys; hierarchical paths compile to
the bounded component graph and exact-object candidate stage.

### D3.3 — Meta canonical path and mount-view implementation

Implement the approved bounded `d_name` vector, state graph/wildcards,
mount-root index, lowest-`mnt_id_unique` selection, selected parent/mountpoint
walk, actor `MountSecurityViewV1`, topology snapshot, DIRTY state, and strict
unresolved result. The bind-alias fixture must resolve the original tracked
`/var/run/secrets/service/config.json`, not the later
`/work/input/job-42/config.json` target. Version 1 does not cache final
decisions. It also leaves resolved path-candidate caching disabled unless a
separate hostile alias-equivalence proof shows that every cache key preserves
the exact component/mount-chain match; a bare exact-file-object cache is not
sufficient for pre-existing hard-link aliases.

### D3.4 — Observe-only effect families

Using the shared Interceptor, attribute the Phase 0-qualified exec, executable
memory, file/create/mutate, credentials, delegated I/O, IPC/process-control,
socket/network, device/ioctl/derived-object, privilege, mount, and
self-protection paths. Each event carries exact actor/object/operation/stage and
whether the physical effect completed.

### D3.5 — Exact object and dynamic-state models

Implement mount/file/socket/channel/device/derived-capability generations,
opened-file provenance, immutable executable classification, mm/VMA snapshot
identity, persistent object state, relationship candidates, and dynamic floors
without claiming byte provenance.

### D3.6 — Honest observe semantics

`OBSERVE` may allow only a simulatable policy denial and emit `WOULD_DENY` or
`WOULD_REJECT`. Missing identity, corrupt generation, prior LSM denial,
emergency restriction, ambiguous topology, and unsupported physical boundary
retain their hard-safety result.

### D3.7 — Standing incident observe increment

Run the unchanged HF worker and legitimate controls. Produce stable simulated
decisions for the managed/local branches of `HF-002` through `HF-012`, with
special focus on the earliest complete `HF-008` file-object block, without
changing application behavior or claiming prevention. Pure in-memory and
outside-authority branches retain their honest non-prevention result.

## Checkpoint

One deterministic signed candidate generation simulates every Phase 4/5
fixture with exact actor/object/stage/result, and the bounded canonical path
matcher passes its hostile corpus. Policy denial remains physically disabled.

## Required Tests And Fixtures

- Policy/config/generation goldens and exact-conflict/exception tests.
- Observe/simulate the exact Phase 4 first-owned IDs:
  `ADMIN-EXEC-APPROVAL-001`, `DEVICE-DERIVED-001`,
  `FILE-CONTENT-RACE-002`, `FILE-FD-PASS-001`, `FILE-IDENTITY-001`,
  `FILE-MMAP-001`, `FILE-MMAP-SHARED-011`, `FILE-NAMESPACE-001`,
  `FILE-SA-TOKEN-OPEN-001`, `FILE-VMA-SNAPSHOT-001`, `HF-LOCAL-001`,
  `IPC-ASYNC-UNSUPPORTED-010`, `IPC-PEER-RACE-004`,
  `IPC-PROCESS-CHANNEL-009`, `IPC-RELATIONSHIP-ALLOW-003`,
  `IPC-RELATIONSHIP-UNMATCHED-005`, `LSM-DENY-SATURATION-001`,
  `MEM-EXEC-001`,
  `MEM-KERNEL-MAP-002`, `MOUNT-ATTR-001`, `MOUNT-CAS-002`,
  `MOUNT-PROPAGATION-003`, `MOUNT-SNAPSHOT-004`, `SELF-PROTECT-001`, and
  `STATE-PERSISTENT-FILE-LIFETIME-007`.
- Observe/simulate the exact Phase 5 first-owned IDs:
  `FILE-DELEGATED-EGRESS-001`, `HF-004-RESULT-001`,
  `HF-011-READ-RESULT-001`, `HF-NET-001`, `IPC-LOCAL-INET-008`,
  `NET-ACCEPT-PASS-001`, `NET-DNS-EXFIL-001`, `NET-NS-PASS-001`,
  `NET-RECV-001`, `NET-REWRITE-001`, `NET-SHARED-RESPONSE-002`,
  `NET-SOCKCTL-001`, and `NET-SOCKET-LIFE-001`.
- Path bind/rename/link/mount ambiguity, pre-existing hard-link alias cache
  equivalence, ordinary-subdirectory limits, and oldest-mount controls must
  accompany `MOUNT-SNAPSHOT-004`, `FILE-IDENTITY-001`, and
  `MOUNT-PROPAGATION-003`.
- Upstream-dossier regression tests for every adopted path/task/map pattern.

## Acceptance

- Every allocated local effect has exact actor/object attribution or an exact
  unsupported/unresolved result.
- The canonical path graph is verifier-qualified at declared bounds and passes
  the oldest-mount example.
- Compiler output is deterministic and cannot activate a partial generation.
- Observe mode never converts broken identity/state into allow.
- No product prevention claim is exposed.

## Excluded

Active local policy denial, final packet fencing, durable remote evidence,
distributed graphing, and response.

## Phase Result

```text
State: Blocked.
Validated architecture revision/digest: policy-and-protection-algorithm-architecture-readable.md at SHA-256 4a445b4015c4868a87af4893398068c5f362452c316d0cb8d06c038d41ffc0d8.
Completed deliverable IDs: D3.1-D3.4, D3.6, and D3.7 are code-backed. D3.5 is implemented for the qualified exact-file and mount-view state and, per Acceptance, every other allocated object mechanism has an exact hard-safe unsupported result instead of a fabricated partial model. The self-cleaning production-path physical probe passed. The phase remains Blocked only until the real Docker/CRI operator integrations are run; it is not represented as Done.
Files and durable owners changed: mithril-control::policy owns the closed restricted YAML parser, reference/bound validation, deterministic CBOR, Ed25519 candidate/rollback envelopes, full-action exact conflicts, finite local cells/defaults, bounded component graph, honest simulation, and the 50-case Phase 3 oracle. mithril-node::NodePolicyGenerationOwner verifies candidates, enforces anti-rollback, derives local handles, installs and reads back immutable candidate rows, resolves live exact files, snapshots mount views, selects the oldest unique mount, and proposes exact DIRTY-to-CLEAN reconciliation. erebor-interceptor remains the only libbpf-rs loader and one native RingBuffer reader. The production identity object owns the bounded component walk, graph lookup, namespace-global mount mutation epoch/pending transaction, reconciliation CAS, dynamic exact-file binding, observe decisions, hard-safety results, and per-CPU loss health. mithril-e2e::EffectTestRunner owns the assertion-bearing self-cleaning privileged host oracle. examples/mithril-phase3-manual retains separate real Docker, CRI, raw nsenter, hard-link, bind-alias, mount-attack, saturation, latency, and unsupported-network operator cases.
Correctness and simplicity result: one C/CO-RE object and one libbpf-rs owner serve every container. The BPF decision is fixed before best-effort ring reservation, prior LSM errno is returned unchanged, multi-operation wrappers stop after the first nonzero result, ring loss cannot change the result, and ioctl stays hard unsupported without a qualified command axis. A file candidate requires a CLEAN mount-namespace view, stable epoch/snapshot before and after the bounded component graph, exact live mount/device/inode/generation identity, and a retained read-back profile. Mount topology state is keyed by mount namespace rather than the mutating task's cgroup, so an external privileged task entering a protected namespace marks it DIRTY too. Reconciliation refuses to clean the view when the configured exact mount/device/inode/generation changed. Covered mount hooks retain the mutation in task storage until syscall exit and accept only an exact userspace epoch/version proposal. The LSM paths alone use the namespace-view spin lock; the tracing exit path uses BPF atomic version/pending updates and decrements pending last because Linux rejects spin-lock maps for tracing programs. A configured creation errno is explicitly sign-extended and verifier-bounded to `[-MAX_ERRNO, -1]`, with `-EACCES` as the invalid-value fallback. Task storage receives only a verifier-trusted typed hook task or `bpf_get_current_task_btf()` result. Real-parent topology uses exact CO-RE-read coordinates; an ordinary fork attaches the already proven creator cookie, while `CLONE_PARENT`, `CLONE_THREAD`, reparenting, and independent roots retain the architecture's coordinate-only representation instead of inventing a cookie or passing a scalar probe-read pointer to task storage. No final decision cache or second path engine was added. An identical recovered generation is verified in place and is never downgraded to PREPARING. Reader exit is a node failure. Both the Rust probe and manual cases own bounded cleanup.
Upstream-adoption dossier IDs used: KA-LSM-DECISION-001 and KA-READER-CAPACITY-005 for decision-before-telemetry and ring-loss behavior; TG-GENERIC-LSM-003, TG-VMLINUX-HEADER-006, TG-VMLINUX-ARM64-007, TG-CONCURRENCY-LOSS-005, AS-VMLINUX-ARM-001, and AS-VMLINUX-RISCV-002 for explicit CO-RE programs, generated multi-architecture headers, per-CPU scratch, and concurrency/loss practices; META-MOUNT-ROOT-001, META-OLDEST-MOUNT-002, and META-COMPONENT-GRAPH-003 for the bounded mount-root traversal and component graph. The local implementation adds actor-view snapshot validation, DIRTY ordering, exact proposal CAS, and final object/profile revalidation required by the Mithril architecture.
Fixture cases and exact physical results: the closed parser, deterministic compiler, full-action exact conflict, default expansion, signatures, one-use rollback, immutable install recovery, bounded graph, oldest-mount nested-alias walk, hard-link non-transfer, namespace-global DIRTY/CAS model, exact-object reconciliation rejection, ring liveness/loss, ABI layout, production-object layout, and checked multi-architecture compilation are automated. `mithril-effect-test physical-probe` additionally implements exact open, hard-link, later bind alias, concurrent protected mount denial, external mount replacement, recovery, saturation, network hard safety, latency, and cleanup assertions. The machine-readable simulation oracle covers the exact 25 Phase 4 and 13 Phase 5 fixture IDs required here plus 12 managed/pure-memory/outside-authority HF cases. On 2026-08-10 the operator reported that both the corrected self-cleaning production-object/native-task probe and the complete Phase 3 effect probe passed. Earlier effect-probe runs exposed three real harness/identity defects: unrelated inaccessible mounts were eagerly opened, the protected pipe protocol was hard-denied, and namespace/device fields were read with the wrong widths/encoding. The resolver now follows only the relevant bind/parent closure, the child uses a file-backed mailbox mapped before cgroup placement, and exact kernel coordinates use their native Linux widths and `new_encode_dev` encoding. The concurrent mount workers are created before protected cgroup placement and remain parked until observation activation; this removes allocator-dependent thread-stack failures without moving the actual mount attempts outside protection. Real Docker/CRI cases are not yet claimed.
Commands and exact source state covered: `bash .github/scripts/verify-rust-ci.sh` passes on the final Rust, Cargo, and BPF source state, including formatting, `cargo check --workspace`, all-target/all-feature clippy with warnings denied, and the full workspace test suite. The checked x86, arm64, arm, and riscv production-object compilation also passes. The privileged `mithril-effect-test physical-probe` result remains pending operator execution.
Platform/kernel/runtime manifests: the current x86_64 Linux 6.8 BTF hook prototypes match the explicit program arguments and expose mnt_id_unique. That verifier rejects any tracing program which references a map whose value contains bpf_spin_lock, so the syscall-exit path references only the unlocked view/task-storage maps and uses atomic counters; the spin-lock map is LSM-only. It also requires an LSM program's `R0` to remain in `[-MAX_ERRNO, 0]`; the production deny helper sign-extends its configured `i32`, accepts only `[-MAX_ERRNO, -1]`, and otherwise returns `-EACCES`. Its task-storage helper requires a trusted/BTF/RCU task pointer, so pointers copied through `bpf_probe_read_kernel`/`BPF_CORE_READ_INTO` are used for field reads only. The complete production translation unit compiles with -Wall -Werror against checked x86, arm64, arm, and riscv vmlinux headers. Only the existing Phase 0 x86 file-open qualifier is physical evidence; compilation is not a non-x86 physical claim. Current Linux adds a bpf-hook parameter on newer kernels, so an incompatible target must fail load/readiness until separately qualified rather than guessing an ABI.
Performance/capacity results: the observation ring is bounded at 4 MiB, recent userspace history at 1,024 records, compiled exact cells at 65,536, and path model at 4,096 states/64 components. Both the Rust effect probe and manual examples contain reader-paused saturation and same-workload baseline/observe open-latency assertions, but no new physical measurement is recorded yet. Active-denial saturation belongs to Phase 4, durable reader/WAL/recovery saturation to Phase 6, and final map N/N+1 plus platform capacity/latency qualification to Phase 11.
Unsupported/degraded paths: LOCAL_EFFECT_OBSERVATION remains DEGRADED and LOCAL_EFFECT_PREVENTION remains unsupported. Signed candidate DENY is physically allowed and reported as WOULD_DENY. A protected unqualified mount, network, IPC, device/ioctl, privilege, socket/channel, derived-capability, complete mm/VMA, persistent-provenance, or self-protection object hard-denies as UNSUPPORTED_OBJECT; those families do not inherit file authority. In particular, Phase 3 has no qualified anonymous-memory model, so post-placement anonymous mappings such as newly allocated thread stacks remain hard unsupported; the mount-race fixture prepares its threads before placement and performs only the mount syscalls after activation. Propagation, automount/referral, and cross-namespace fan-out ordering are not claimed until physically qualified. Exact-file configuration still needs a live resolver plus a nonzero operator/filesystem inode generation and is not yet a rotation-aware runtime binding. Runtime observation is bounded, non-durable, and its current peer cgroup proof retains the limitation recorded in the review guide. A pre-existing represented bind alias canonicalizes correctly but its signed denial remains observe-only; a new protected mount attempt is physically hard-denied because its mount object is unqualified.
Remaining work in this phase: run and record the real Docker and CRI operator integrations. The automated probe has passed its raw namespace attachment, live file/alias decisions, protected and external mount attacks, saturation, latency, and cleanup assertions. Cross-namespace mount propagation/fan-out retains the explicit unsupported result in Phase 3; Phase 4 owns its physical enforcement qualification. Change State to Done only if every Phase 3 oracle passes. New classified socket/channel/device/VMA models belong behind their own Phase 0 physical/type gate rather than speculative placeholder maps.
Next phase not authorized: yes.
```
