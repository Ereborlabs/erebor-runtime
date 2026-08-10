# Phase 4: Signed Local Pre-Effect Enforcement

Status: Not done. The signed exact-file prevention increment and explicit
hard-close floor for the currently unqualified local hooks are implemented;
the complete policy-aware Phase 4 surface and privileged qualification are not
complete.

Master: [Mithril Hugging Face Intrusion Prevention](./README.md)
Design: [Validated readable architecture](./policy-and-protection-algorithm-architecture-readable.md)
Manual acceptance: [Phase 4 runbook](./manual-testing/phase-4-manual-acceptance.md)  
Environment setup: [shared setup guide](./manual-testing/environment-setup.md)

## Purpose

Activate signed immutable policy for every qualified non-network local effect
and prove the forbidden physical effect does not occur.

## Scope And Design Coverage

Chapters 10-18 and 20-21; Appendices A.11-A.14.

## Deliverables

### D4.1 — Atomic policy activation and lookup

Stage a complete generation, validate signature/rollback, read back every set
and bound, run allow/deny probes, and switch one active pointer with CAS.
Implement the Appendix A.12 task-first lookup: base authority intersected with
restriction, response, lifetime, and exact-object floors. Missing required
state denies; cached explanations never authorize.

### D4.2 — Exec and executable-memory enforcement

Deny forbidden `execve`, `execveat`, `fexecve`, script/interpreter,
`binfmt_misc`, loader, memfd/deleted-file, non-leader exec, executable mmap,
and mprotect/pkey transitions. Authorization binds immutable image/object and
current exec/native state, not a command string or path alone.

### D4.3 — File, credential, and mount enforcement

Enforce exact open/read/write/create/setattr/rename/link/unlink/mmap decisions,
projected-token rotation, proc aliases, inherited/passed fds, overlay copy-up,
persistent objects, and delegated-I/O acquisition. Mount/topology mutations
are denied where undeclared; any allowed change enters DIRTY before effect and
blocks strict file/exec decisions until complete reconciliation. Canonical path
matching remains only an exact-object candidate.

### D4.4 — IPC and process-control enforcement

Enforce directional Unix/local-channel relationships and process-control
operations using current actor, exact peer/target, channel/object generation,
and operation. Independent roots never join native authority. Pipes and shared
memory retain their honest peer/per-access limits; unsupported async paths are
denied or explicitly unsupported.

### D4.5 — Devices, derived authority, privilege, and self-protection

Enforce device access/ioctls/derived fds, credential/capability changes,
namespace/mount/pivot, ptrace/process-vm/pidfd, BPF/perf/module/keyring,
proc/sysctl, io_uring, and protection of Mithril links/maps/config/binary. Each
advertised operation has a qualified pre-effect hook and physical oracle.

### D4.6 — Bounded exceptions and administrative exec

Implement exact, signed, expiring exceptions with `maximum_uses`. Consumption
is atomic in the matching BPF rule/map entry; a nonmatching rule/program cannot
consume or reuse it. Implement the approved one-use administrative exec path,
including resolved executable object, full argv match, deadline, slot
consumption, normal exec-chain policy, and accepted next-match race disclosure.
`claim_slot_id` remains optional outside that path. Mithril Control's
`AdministrativeApprovalOwner` owns authenticated human approval, the explicit
next-matching-root risk acceptance, Kubernetes admission credential, and
signed node authorization; it cannot assign a Linux role or assert an exact
request-to-task join.

### D4.7 — Optional qualified Landlock floor

If the Phase 0 platform/start path qualified Landlock target-context install,
install and prove the monotonic floor before untrusted code. Otherwise record
Landlock absent. Local BPF enforcement and this phase's release result cannot
depend on an unavailable Landlock path.

### D4.8 — HF local prevention increment

For each managed/local non-network branch of `HF-002` through `HF-012`,
identify and deny the first distinguishable forbidden effect, prove it did not
complete, and prove the legitimate same-deployment control still succeeds.
`HF-008` is the mandatory earliest complete block: the hostile HDF5 reference
must receive no forbidden fd or bytes. Pure in-memory and outside-authority
branches retain their honest result rather than a fabricated denial.

## Checkpoint

Every qualified non-network local effect has a signed task-first decision and
physical positive/negative oracle, including bounded exception consumption and
the complete `HF-008` block. Network destinations and distributed conclusions
remain outside the checkpoint.

## Required Tests And Fixtures

- `ADMIN-EXEC-APPROVAL-001`, `DEVICE-DERIVED-001`,
  `FILE-CONTENT-RACE-002`, `FILE-FD-PASS-001`, `FILE-IDENTITY-001`,
  `FILE-MMAP-001`, `FILE-MMAP-SHARED-011`, `FILE-NAMESPACE-001`,
  `FILE-SA-TOKEN-OPEN-001`, and `FILE-VMA-SNAPSHOT-001`.
- `MEM-EXEC-001`, `MEM-KERNEL-MAP-002`, `MOUNT-ATTR-001`,
  `MOUNT-CAS-002`, `MOUNT-PROPAGATION-003`, and `MOUNT-SNAPSHOT-004`.
- `IPC-ASYNC-UNSUPPORTED-010`, `IPC-PEER-RACE-004`,
  `IPC-PROCESS-CHANNEL-009`, `IPC-RELATIONSHIP-ALLOW-003`,
  `IPC-RELATIONSHIP-UNMATCHED-005`, and
  `STATE-PERSISTENT-FILE-LIFETIME-007`.
- `HF-LOCAL-001`, `LSM-DENY-SATURATION-001`, `SELF-PROTECT-001`, and exact
  policy/decision goldens from Phase 0. `NODE-FLOOR-EXCEPTION-002` is not owned
  here; Phase 8 owns its Kubernetes admission/node-floor result.

## Acceptance

- Every advertised denial returns before the named effect and has a physical
  negative oracle.
- Signed generation/rollback/conflict/default behavior is deterministic and
  atomically active.
- Mount, alias, identity, fd, mmap, async, and object-reuse bypasses do not
  widen authority.
- Exceptions cannot exceed `maximum_uses` or be consumed by unrelated entries.
- Normal worker, controller, probes, lifecycle, and approved admin controls
  remain functional.

## Excluded

Destination-aware network enforcement, durable distributed evidence, graph
correlation, and response coordination.

## Phase Result

```text
State: Not done.
Validated architecture revision/digest: policy-and-protection-algorithm-architecture-readable.md sha256 4a445b4015c4868a87af4893398068c5f362452c316d0cb8d06c038d41ffc0d8.
Completed deliverable IDs: partial D4.1; the hard-close subset of D4.2, D4.4, and D4.5; the exact-file and file-mutation hard-close subset of D4.3; partial D4.6; and the exact-file portion of D4.8.
Files and durable owners changed: mithril-control owns PROTECT compilation and exact exception binding; NodePolicyGenerationOwner owns PREPARING -> READ_BACK -> ACTIVE installation, anti-rollback, exact rows, and exception state; the production BPF effect gate owns pre-effect deny and atomic exception consumption; mithril-e2e owns the disposable physical oracle; examples/mithril-phase4-manual owns operator cases.
Upstream-adoption dossier IDs used: existing Phase 0 libbpf-rs/libbpf-cargo and checked vmlinux-header decisions; no new runtime or BPF framework.
Fixture cases and exact physical results: unprivileged compiler/ABI/interceptor/node/effect suites pass. The self-cleaning privileged PROTECT probe is implemented for exact open, inherited-fd read, file-backed mmap, a same-container exact benign read, concurrent exact N/N+1 exception consumption, monotonic expiry, exhausted-state loader restart, hard-link/bind aliases, denied protected mount races, external mount DIRTY/reconciliation races, unqualified exec and anonymous executable memory, create/chmod/truncate/unlink/link/rename, SysV IPC, ptrace, signal, namespace privilege, device ioctl, BPF map creation, pinned-link removal, saturation, latency, and cleanup. Each hard-close result also requires the expected effect family and operation in the kernel observation. The probe has not been run on the final source state.
Commands and exact source state covered: `cargo check --workspace` and `bash .github/scripts/verify-rust-ci.sh` pass on the final implementation state, including all-target/all-feature clippy with warnings denied and loopback integration tests; production identity.bpf.c compiles with -Wall -Werror for x86_64, arm64, arm, and riscv checked-in vmlinux headers. Privileged BPF-LSM execution remains to be recorded.
Platform/kernel/runtime manifests: no new Phase 4 physical result artifact recorded yet.
Performance/capacity results: exception-state capacity is compiler-checked at 4,096; the physical saturation and latency result awaits the privileged probe.
Unsupported/degraded paths: receipt-idempotent stable exception instances, policy-aware IPC, device/ioctl, credential, process-control, complete executable-memory/provenance, policy-aware self-protection, Landlock, mount propagation/fan-out, and the complete HF-002..HF-012 local matrix remain unqualified. Exceptions are therefore restricted to one exact file-open cell rather than being broadened unsafely across hooks. Typed unqualified hooks fail protected tasks closed where present and have physical-oracle coverage in the pending privileged probe; this is not a policy-aware support claim. Network remains Phase 5.
Remaining work in this phase: qualify or implement D4.2-D4.5 and D4.7, implement stable receipt/WAL exception ownership, finish administrative approval-to-profile exception resolution and physical admin-exec proof, run the full required fixture matrix and legitimate controls, and record the final privileged result. Earlier Phase 2/3 Docker/CRI cases also remain unrecorded.
Next phase not authorized: yes.
```
