# Phase 2: Exact Native Identity

Status: Implementation complete; privileged physical acceptance blocked on an operator sudo run.

Master: [Mithril Hugging Face Intrusion Prevention](./README.md)
Design: [Validated readable architecture](./policy-and-protection-algorithm-architecture-readable.md)
Manual acceptance: [Phase 2 runbook](./manual-testing/phase-2-manual-acceptance.md)  
Environment setup: [shared setup guide](./manual-testing/environment-setup.md)

## Purpose

Establish exact task, process, execution, native-family, entry, container, and
runtime-root identity before any later phase uses identity for authority.

## Scope And Design Coverage

Chapters 6-9 and 13; Appendices A.8-A.10, A.12, and A.14.

## Deliverables

### D2.1 — Identity/state ABI and owners

Implement task storage labels, `TaskCoordinateV1`, process/execution/native
state, entry security state, generation references, lifetimes, tombstones, and
atomic transition maps under `NativeSecurityStateOwner` and
`WorkloadBindingOwner`. `KernelHostOwner` owns map lifecycle, not semantics.
Before adding these first production BPF programs, make upstream
`libbpf-cargo` the single CI/build owner for C-to-BPF artifacts. It consumes
the checked multi-architecture vmlinux headers and publishes the digest-pinned
object used by packaging; remove the duplicated direct-Clang product build
paths. `mithril-node` loads that prebuilt object through fully vendored
`libbpf-rs` and never invokes a compiler at runtime.

### D2.2 — Native creation before first effect

Using the approved Jailer/Tetragon-derived dossier entries, label fork, clone,
thread, and vfork children before they can perform a protected effect. Copy
task-local state from the real parent, create new task/process/execution IDs as
defined, and fail first effect closed on allocation/finalization uncertainty.
Never use delayed PID enrollment.

### D2.3 — Exact exec transaction

Implement staged exec identity, immutable image candidate, pre-/post-PONR
failure handling, success commit, non-leader exec, scripts/interpreters,
`execveat`/`fexecve`, and concurrent-exec serialization. A failed/unknown exec
never restores broader authority.

### D2.4 — Runtime and container-root classification

Bind cgroup/container execution sets and classify initial, native, external,
and unresolved roots. Probes, lifecycle hooks, `kubectl exec`, `crictl exec`,
init/sidecars, ephemeral containers, moved tasks, and unmatched workloads keep
their validated distinctions. Identical argv/timing/TTY never creates purpose.

### D2.5 — Authorization proof and administrative slot identity

Implement signed-envelope verification, trust/time/replay foundations and the
identity side of the approved one-use administrative exec slot. This phase may
bind and consume identity state in fixtures, but Phase 4 owns permission and
physical exec denial.

### D2.6 — Restart, reuse, and reference reconciliation

Reconcile live tasks/cgroups/containers after daemon/runtime/kubelet restart;
prove PID/TID, cgroup, namespace, Pod/container name, and object reuse do not
inherit authority. Lost cleanup leaks restriction and requires reconciliation.

## Checkpoint

Every protected task in the entry/identity matrix has exact or conservative
kernel state before its first protected effect, and restart/reuse cannot
recover authority. No effect permission table is active.

## Required Tests And Fixtures

- Entry: `ENTRY-BINDING-GAP-001`, `ENTRY-CONTAINERS-001`,
  `ENTRY-EPHEMERAL-001`, `ENTRY-EXEC-001`, `ENTRY-EXEC-002`,
  `ENTRY-EXTERNAL-AMBIGUITY-001`, `ENTRY-LOSS-001`, `ENTRY-MIGRATE-001`,
  `ENTRY-NETPROBE-001`, `ENTRY-POSTSTART-001`, `ENTRY-POSTSTART-002`,
  `ENTRY-PRESTOP-001`, `ENTRY-PROBE-001`, `ENTRY-PROBE-002`,
  `ENTRY-PROBE-IMPERSONATION-003`, `ENTRY-RESTART-001`, `ENTRY-REUSE-001`,
  `ENTRY-SLEEP-001`, `ENTRY-START-001`, and
  `ENTRY-STOCK-HOOK-FAILURE-002`.
- Native identity: `EXEC-COMMIT-STATE-001`, `EXEC-CONCURRENT-002`,
  `ID-CGROUP-ESCAPE-001`, `ID-CLONE-CGROUP-002`,
  `ID-CLONE-CGROUP-FAIL-003`, `ID-CREATOR-PARENT-007`,
  `ID-MOVED-PARENT-FORK-004`, `ID-MOVED-TASK-EXEC-005`,
  `ID-TASK-COORD-FINALIZE-006`, `NATIVE-STATE-REF-LIFETIME-001`,
  `STATE-FORK-IPC-002`, and `STATE-THREAD-RACE-001`.
- Authorization: `AUTHORIZATION-REPLAY-004`; the identity half of
  `ADMIN-EXEC-APPROVAL-001` is exercised here and the complete physical result
  is owned by Phase 4.
- Identical native-child/probe/admin commands and non-leader exec are required
  controls, not additional role-classification signals.

## Acceptance

- Every protected effect lookup begins with exact task identity, never cgroup.
- Native inheritance is installed before the child can use protected
  authority; missing task storage cannot allow.
- Runtime-created roots receive exact or conservative classification with no
  command-based purpose.
- All state/reference transitions are atomic, bounded, restart-safe, and
  generation-retaining.
- No file/network/device permission is granted in this phase.

## Excluded

Policy matching, effect allow/deny tables, graph conclusions, and response.

## Phase Result

```text
State: Blocked.
Validated architecture revision/digest: policy-and-protection-algorithm-architecture-readable.md at SHA-256 4a445b4015c4868a87af4893398068c5f362452c316d0cb8d06c038d41ffc0d8.
Completed deliverable IDs: D2.1-D2.6 are implemented and code-backed; the phase cannot be marked Done until the privileged physical probe and applicable runtime/Kubernetes fixture matrix pass.
Files and durable owners changed: erebor-interceptor-abi owns the generated snake_case Rust/C task, process, entry, authority, fork-edge, exec, binding, reference, and health layouts; bpf/erebor-interceptor/programs owns the production CO-RE identity program and direct libbpf maps; erebor-interceptor owns the fully vendored libbpf-rs load/attach/pin/reuse/readback lifecycle and embeds the single libbpf-cargo-built production object; mithril-node owns binding publication, boot/label epochs, task reconciliation, signed-intent verification, trust/time/replay state, and one-use authorization identity; mithril-e2e owns only the bounded acceptance runner.
Build and simplicity result: libbpf-cargo 0.27.0 is the only production C-to-BPF build path. The resulting object is embedded in the node binary and opened from memory through fully vendored libbpf-rs 0.27.0; the former second configured object path/checksum and Docker build-directory copy were removed. cbindgen remains only the Rust-to-C ABI renderer and drift check. Standard Linux names CLONE_THREAD and EACCES are used through the minimal syscall-note UAPI header because the full kernel UAPI headers are not CO-RE translation-unit safe. Product-owned state constants are generated once from the shared ABI.
Upstream-adoption dossier IDs used: BJ-TASK-STORAGE-001 and BJ-REJECTED-ENROLLMENT-002 for task-first allocation and rejection of delayed PID enrollment; KA-LSM-DECISION-001 and KA-PATH-MOUNT-003 for prior-result/fail-closed LSM behavior and live mount identity; TG-FORK-EXEC-001, TG-RUNTIME-CGROUP-JOIN-002, TG-FRESH-MAPS-004, TG-VMLINUX-HEADER-006, and TG-VMLINUX-ARM64-007 for fork/exec, cgroup binding, recoverable publication, and CO-RE headers; AS-VMLINUX-ARM-001 and AS-VMLINUX-RISCV-002 for checked compile headers. No upstream daemon, policy engine, loader, or delayed-enrollment model was copied.
Fixture cases and exact physical results: AUTHORIZATION-REPLAY-004 has code-backed signature, exact-target, bounded deterministic-CBOR, trust/key/epoch, 4,096-bit replay, durable proof/slot, restart, and one-use consumption tests. Unit tests cover exact ABI layout, closed enum/state values, binding identity and initial-root admission, epoch recovery, reference parsing, object embedding, required program/map sets, packaging, and all 33 Phase 2 fixture allocations. The unprivileged identity verifier passed with production object SHA-256 949f89744abd628a3bf4d359bcadff34f9a74935b95e4f7d5078c4e8a29d7004 and report SHA-256 99991bd4adbfabf4059ebe0cb8c33f1a33f2eae62b2d5dcf5fd33bbc5ce2cca6. No privileged Phase 2 physical result is recorded yet.
Commands and exact source state covered: targeted cargo tests passed 53 tests across erebor-interceptor-abi, erebor-interceptor, mithril-node, and mithril-e2e; focused all-target/all-feature clippy passed with -D warnings; mithril-identity-test verify passed and wrote /tmp/mithril-identity-final/identity-verification.json. The final `bash .github/scripts/verify-rust-ci.sh` passed after the final Rust, Cargo, and BPF source changes, covering formatting, `cargo check --workspace`, workspace all-target/all-feature clippy with warnings denied, and the complete workspace test suite. The physical probe was not run: BPF LSM is active, but sudo could not create the dedicated cgroup because this noninteractive session cannot provide the operator password.
Platform/kernel/runtime manifests: current host reports x86_64 with BPF in the active LSM order and runtime BTF present. The production program compiles through the checked x86, arm64, arm, and riscv vmlinux dispatch; only a successful privileged probe may establish physical support on a platform.
Performance/capacity results: all authoritative maps are bounded and fail closed on missing/capacity state; no Phase 2 production latency or saturation claim is recorded until the privileged suite runs. Phase 0's feasibility benchmark is historical qualification evidence, not a Phase 2 production result.
Unsupported/degraded paths: complete administrative-exec permission and physical denial remain Phase 4; policy/effect tables remain absent. Kubernetes/container-runtime-specific entry cases, non-leader/concurrent/failure-injected exec, map saturation, identifier reuse, and non-x86 platforms remain physically unqualified. A cleanup loss deliberately leaks restriction and raises reconciliation rather than recovering authority.
Remaining work in this phase: run the documented privileged identity probe on a fresh dedicated cgroup/pin root, retain its JSON, then run the applicable runtime/Kubernetes and failure-injection matrix. Do not change the implementation result to Done without those physical artifacts.
Next phase not authorized: yes.
```
