# Phase 2: Exact Native Identity

Status: Code-backed implementation complete; phase acceptance blocked on the privileged physical and runtime/container/Kubernetes matrix.

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
Files and durable owners changed: erebor-interceptor-abi owns the generated snake_case Rust/C task, process, entry, authority, fork-edge, exec, binding, reference, and health layouts; bpf/erebor-interceptor/programs owns the production CO-RE identity object through one translation-unit front, one map owner, shared task/root helpers, and lifecycle/exec/effect/exit hook families; erebor-interceptor owns the fully vendored libbpf-rs load/attach/pin/reuse/readback lifecycle and its narrow read-only pinned-map reader, and embeds the single libbpf-cargo-built production object; mithril-node owns binding publication, exact CRI inventory reconciliation, boot/label epochs, task reconciliation, signed-intent verification, trust/time/replay state, one-use authorization identity, and the read-only live-task inspector used by operators and e2e; mithril-e2e owns only the bounded acceptance runner.
Build and simplicity result: libbpf-cargo 0.27.0 is the only production C-to-BPF build path, and the production C is compiled with -Wall -Werror. The resulting object is embedded in the node binary and opened from memory through fully vendored libbpf-rs 0.27.0; the former second configured object path/checksum and Docker build-directory copy were removed. The BPF source follows the checked-source hook-family shape without adding another object, loader, map owner, or link step: the small `identity.bpf.c` front includes the map/task/root owners and cohesive lifecycle, exec-transaction, effect-gate, and exit families into the same object. cbindgen remains only the Rust-to-C ABI renderer and drift check. Standard Linux names CLONE_PARENT, CLONE_THREAD, AT_EXECVE_CHECK, and EACCES are used through the minimal syscall-note UAPI header because those macros are absent from vmlinux BTF and full host UAPI headers would make the CO-RE translation unit host-architecture-dependent. Product-owned state constants are generated once from the shared ABI.
Correctness-preserving simplifications: execution_set_bindings is the single cgroup-placement authority. Configured non-CRI bindings still use one exact cgroup path and periodically revalidate its live handle, device, and inode. The 2026-08-09 pass rejects the cgroup root as a workload, opens the cgroup handle before publication, compares the handle and live path identity before each publish, and rejects root/traversal CRI paths. When CRI is configured, `WorkloadBindingOwner` takes one standard full `ListContainers` snapshot per interval, ignores unconfigured containers, validates the configured full container ID, Pod UID, sandbox, container name, image reference, creation generation, and live Created/Running state, and resolves `runtimeSpec.linux.cgroupsPath` locally before publishing. A newly observed Created container may retain configured initial-root arming only while its cgroup is empty; a container first observed Running is conservatively external and is never retroactively promoted. A missing/stopped exact lifetime is transitioned to Terminating, and a changed/reused identity fails closed. The periodic inventory is recovery truth after event loss or restart; adding a separate CRI-event state machine would not prove pre-start ordering. Raw Docker exec, direct CRI exec, and a host task moved after `nsenter` use the same BPF classification path rather than separate runtime-specific identity engines. The BPF program performs a bounded 64-level walk of the live kernel cgroup ancestry, using the upstream-compatible cgroup ancestors layout with the self.parent fallback; an unreadable or over-depth chain denies and increments health rather than treating the task as unprotected. Missing exit tombstones now also increment reconciliation health while retaining restrictions. This replaces both the userspace descendant scan and the capacity-sensitive descendant map. AT_EXECVE_CHECK ownership is an atomic task-cookie marker in ProcessSecurityStateV1, so a check-only exec cannot stage an exec, consume an administrative slot, or depend on insertion into another bounded map. Binding nonces are random UUID-v4 values on first publication and are recovered byte-exactly from pinned state on restart. Nested configured protected roots are rejected instead of introducing precedence rules. Exact desired assignments remain bootstrap inputs in Phase 2; policy compilation/effect permission is Phase 3-4 and authenticated fleet distribution remains Phase 7-8.
Upstream-adoption dossier IDs used: BJ-TASK-STORAGE-001 and BJ-REJECTED-ENROLLMENT-002 for task-first allocation and rejection of delayed PID enrollment; KA-LSM-DECISION-001 and KA-PATH-MOUNT-003 for prior-result/fail-closed LSM behavior and live mount identity; TG-FORK-EXEC-001, TG-RUNTIME-CGROUP-JOIN-002, TG-FRESH-MAPS-004, TG-VMLINUX-HEADER-006, and TG-VMLINUX-ARM64-007 for fork/exec, cgroup binding, recoverable publication, and CO-RE headers; AS-VMLINUX-ARM-001 and AS-VMLINUX-RISCV-002 for checked compile headers. No upstream daemon, policy engine, loader, or delayed-enrollment model was copied.
Fixture cases and exact physical results: AUTHORIZATION-REPLAY-004 has code-backed signature, exact-target, bounded deterministic-CBOR, trust/key/epoch, 4,096-bit replay, durable proof/slot, restart, idempotent close recovery, and one-use consumption tests. Unit tests cover exact ABI layout, closed enum/state values, binding identity and initial-root admission, configured static/CRI binding validation, Created-versus-Running initial-root treatment, exact runtime-lifetime reconciliation, cgroup path-reuse and cgroup-root rejection, distinct/recovered nonce behavior, epoch recovery, CRI cgroup parsing, reference parsing, object embedding, exact required program/map sets, packaging, and exact allocation of all 33 Phase 2 fixture IDs. The complete operator case catalog lives under examples/mithril-phase2-manual. Separate small shells run the real mithril-node for raw Docker exec, direct CRI exec, Kubernetes exec, native-child provenance, namespace-only and cgroup-moved `nsenter`, and exact restart recovery; each owns and removes its tasks, pins, lease, state, config, and logs. The CRI/Kubernetes shells remove the configured cgroup path from their temporary node config so local CRI resolution is required. They do not claim physical execution of every catalog row. The automated physical probe creates and removes its own dedicated cgroup and BPF pin tree before reporting success. The unprivileged identity verifier passed with 32 programs, 20 maps, production object SHA-256 a0aaaf9aa9ba64c6cf27ad733e0fa4af2d5890fd623ef1f11cb02802bd3d4fdc, and report SHA-256 c6cbb392482a163995c99a71c01707471ed8ac55ae1fc7af1d3a7a1aea3ca318. Fixture allocation is not represented as physical fixture execution. No privileged Phase 2 physical or manual result is recorded yet.
Commands and exact source state covered: targeted cargo tests passed 68 tests across erebor-interceptor-abi, erebor-interceptor, mithril-node, and mithril-e2e; focused all-target/all-feature clippy passed with `-D warnings`; every Phase 2 shell passed `bash -n` (ShellCheck is not installed on this host); and `mithril-identity-test verify` passed after the BPF exit-health and cgroup-binding corrections. The final `bash .github/scripts/verify-rust-ci.sh` passed after the final Rust, Cargo, BPF, example, and phase-result changes, covering formatting, the exact `cargo check --workspace` CI gate, workspace all-target/all-feature clippy with warnings denied, and the complete workspace test suite. The privileged physical and manual examples were not run because they require operator-owned sudo invocations and live test containers/cgroups.
Platform/kernel/runtime manifests: current host reports x86_64 with BPF in the active LSM order and runtime BTF present. The production program compiles through the checked x86, arm64, arm, and riscv vmlinux dispatch; only a successful privileged probe may establish physical support on a platform.
Performance/capacity results: all authoritative maps are bounded and fail closed on missing/capacity state; no Phase 2 production latency or saturation claim is recorded until the privileged suite runs. Phase 0's feasibility benchmark is historical qualification evidence, not a Phase 2 production result.
Unsupported/degraded paths: complete administrative-exec permission and physical denial remain Phase 4; policy/effect tables remain absent. The Phase 2 administrative identity foundation uses the trusted node lowering boundary to install an exact live executable tuple; the Phase 4 resolver and expiry/cancellation owner remain required for the complete portable transaction. A configured static Docker binding validates live cgroup identity but does not continuously validate Docker-daemon metadata; a replacement container therefore requires a new configured generation and otherwise loses authority. CRI-backed bindings continuously validate exact runtime metadata and local cgroup placement, but snapshot discovery alone cannot prove that a binding preceded the first user instruction; only a qualified Created/empty-cgroup observation or later supported start hook can make that claim. Kubernetes/container-runtime-specific entry cases, non-leader/concurrent/failure-injected exec, map saturation, identifier reuse, and non-x86 platforms remain physically unqualified. A cleanup loss deliberately leaks restriction and raises reconciliation rather than recovering authority.
Remaining work in this phase: run the documented privileged identity probe on a fresh dedicated cgroup/pin root, run the applicable Docker/CRI/Kubernetes/`nsenter` case shells, retain operator-selected external evidence, then run the remaining failure-injection matrix. Do not change the implementation result to Done without those physical artifacts.
Next phase not authorized: yes.
```
