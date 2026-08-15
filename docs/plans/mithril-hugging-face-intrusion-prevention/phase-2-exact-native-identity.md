# Phase 2: Exact Native Identity

Status: Blocked. The current source passed the disposable privileged VM
identity probe. The complete failure-injection and entry-case matrix is not
recorded.

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
Completed deliverable IDs: D2.1-D2.6 are implemented and code-backed. The current source passed the disposable privileged VM identity probe. The phase cannot be marked Done until the remaining failure-injection and entry-case matrix passes.
Files and durable owners changed: erebor-interceptor-abi owns the generated snake_case Rust/C task, process, entry, authority, fork-edge, exec, binding, reference, and health layouts; bpf/erebor-interceptor/programs owns the production CO-RE identity object through one translation-unit front, one map owner, shared task/root helpers, and lifecycle/exec/effect/exit hook families; erebor-interceptor owns the fully vendored libbpf-rs load/attach/pin/reuse/readback lifecycle and its narrow read-only pinned-map reader, and embeds the single libbpf-cargo-built production object; mithril-node owns binding publication, exact CRI inventory reconciliation, boot/label epochs, task reconciliation, signed-intent verification, trust/time/replay state, one-use authorization identity, and the read-only live-task inspector used by operators and e2e; mithril-e2e owns the bounded acceptance runners and disposable VM harness; examples/mithril-identity-manual owns the operator-driven cases.
Build and simplicity result: libbpf-cargo 0.27.0 is the only production C-to-BPF build path, and the production C is compiled with -Wall -Werror. The resulting object is embedded in the node binary and opened from memory through fully vendored libbpf-rs 0.27.0; the former second configured object path/checksum and Docker build-directory copy were removed. The BPF source follows the checked-source hook-family shape without adding another object, loader, map owner, or link step: the small `identity.bpf.c` front includes the map/task/root owners and cohesive lifecycle, exec-transaction, effect-gate, and exit families into the same object. cbindgen remains only the Rust-to-C ABI renderer and drift check. Standard Linux names CLONE_PARENT, CLONE_THREAD, AT_EXECVE_CHECK, and EACCES are used through the minimal syscall-note UAPI header because those macros are absent from vmlinux BTF and full host UAPI headers would make the CO-RE translation unit host-architecture-dependent. Product-owned state constants are generated once from the shared ABI.
Correctness-preserving simplifications: execution_set_bindings is the single cgroup-placement authority. Configured non-CRI bindings still use one exact cgroup path and periodically revalidate its live handle, device, and inode. The 2026-08-09 pass rejects the cgroup root as a workload, opens the cgroup handle before publication, compares the handle and live path identity before each publish, and rejects root/traversal CRI paths. When CRI is configured, `WorkloadBindingOwner` takes one standard full `ListContainers` snapshot per interval, ignores unconfigured containers, validates the configured full container ID, Pod UID, sandbox, container name, image reference, creation generation, and live Created/Running state, and resolves `runtimeSpec.linux.cgroupsPath` locally before publishing. A newly observed Created container may retain configured initial-root arming only while its cgroup is empty; a container first observed Running is conservatively external and is never retroactively promoted. A missing/stopped exact lifetime is transitioned to Terminating, and a changed/reused identity fails closed. The periodic inventory is recovery truth after event loss or restart; adding a separate CRI-event state machine would not prove pre-start ordering. Raw Docker exec, direct CRI exec, and a host task moved after `nsenter` use the same BPF classification path rather than separate runtime-specific identity engines. The BPF program performs a bounded 64-level walk of the live kernel cgroup ancestry, using the upstream-compatible cgroup ancestors layout with the self.parent fallback; an unreadable or over-depth chain denies and increments health rather than treating the task as unprotected. Missing exit tombstones now also increment reconciliation health while retaining restrictions. This replaces both the userspace descendant scan and the capacity-sensitive descendant map. AT_EXECVE_CHECK ownership is an atomic task-cookie marker in ProcessSecurityStateV1, so a check-only exec cannot stage an exec, consume an administrative slot, or depend on insertion into another bounded map. Binding nonces are random UUID-v4 values on first publication and are recovered byte-exactly from pinned state on restart. Nested configured protected roots are rejected instead of introducing precedence rules. Exact desired assignments remain bootstrap inputs in Phase 2; policy compilation/effect permission is Phase 3-4 and authenticated fleet distribution remains Phase 7-8.
Upstream-adoption dossier IDs used: BJ-TASK-STORAGE-001 and BJ-REJECTED-ENROLLMENT-002 for task-first allocation and rejection of delayed PID enrollment; KA-LSM-DECISION-001 and KA-PATH-MOUNT-003 for prior-result/fail-closed LSM behavior and live mount identity; TG-FORK-EXEC-001, TG-RUNTIME-CGROUP-JOIN-002, TG-FRESH-MAPS-004, TG-VMLINUX-HEADER-006, and TG-VMLINUX-ARM64-007 for fork/exec, cgroup binding, recoverable publication, and CO-RE headers; AS-VMLINUX-ARM-001 and AS-VMLINUX-RISCV-002 for checked compile headers. No upstream daemon, policy engine, loader, or delayed-enrollment model was copied.
Fixture cases and exact physical results: AUTHORIZATION-REPLAY-004 has code-backed signature, exact-target, bounded deterministic-CBOR, trust/key/epoch, 4,096-bit replay, durable proof/slot, restart, idempotent close recovery, and one-use consumption tests. Unit tests cover exact ABI layout, closed enum/state values, binding identity and initial-root admission, configured static/CRI binding validation, Created-versus-Running initial-root treatment, exact runtime-lifetime reconciliation, cgroup path-reuse and cgroup-root rejection, distinct/recovered nonce behavior, epoch recovery, CRI cgroup parsing, reference parsing, object embedding, exact required program/map sets, packaging, and exact allocation of all 33 identity fixture IDs. The complete operator case catalog lives under examples/mithril-identity-manual. Separate small shells run the real mithril-node for raw Docker exec, direct CRI exec, Kubernetes exec, native-child provenance, namespace-only and cgroup-moved `nsenter`, and exact restart recovery; each owns and removes its tasks, pins, lease, state, config, and logs. The current VM record has object_sha256=c9a73d3f640443c0968ee86f76d5a456b369e75564bdae925aecb06cda2dbbf1. First start and recovered start each report ready=true, 45 maps, and 48 links. map_ids_stable_across_restart=true and profile_task_refs_after_exit=0. The external root and the direct `clone3(CLONE_INTO_CGROUP)` root have root_class=external_runtime_root and installed_role_class=runtime_external_restricted. The direct native child has creator_task_cookie=5 and real_parent_task_cookie=5. The later native child keeps task_cookie=21 and creator_task_cookie=18 across exec, while active_execution_id changes from 00000000000000010000000000000016 to 0000000000000001000000000000001c. pin_root_removed=true, lease_removed=true, and cgroup_removed=true. The identity evidence SHA-256 is f392274c5643120b035cf84937529a39d805931ddeba37bbbaf148c66c58bc0e. On 2026-08-15, the K3s lane added by `d806aa3` also ran a direct `crictl exec` in the exact bound container. The direct CRI task had no creator task cookie, `external_runtime_root` as its root class, and `runtime_external_restricted` as its installed role. The same lane passed its OBSERVE and PROTECT file-effect checks and removed its namespace, fixture, pin root, and lane state. This is one physical `ENTRY-EXEC-002` result. Fixture allocation is not physical execution of every fixture.
Commands and exact source state covered: the disposable VM record under /tmp/mithril-vm-source18-final covers the current object digest above. The optional k3s record under /tmp/mithril-k3s-source20-final uses the same object digest. Repository CI results are recorded separately after the final repository edit.
Platform/kernel/runtime manifests: the physical identity probe ran on x86_64 Ubuntu kernel 6.8.0-136-generic with LSM order lockdown,capability,landlock,yama,apparmor,bpf, runtime BTF SHA-256 9aa9eb9e8108bff44e685830315fb7a442bafd99778314cdd6de0fb72868829f, cgroup v2, and unique mount IDs. The optional k3s lane recorded k3s v1.35.5+k3s1, node ubuntu, CRI endpoint unix:///run/k3s/containerd/containerd.sock, overlay storage, and a projected token available through exec and the workload root. Its k3s record SHA-256 is 905a3ad84106e975cc1cde8b68cb24c861079f8baf3b616c597ec14e234f2503. This is runtime-substrate evidence only. It does not configure or prove a Mithril CRI binding. The production program compiles through the checked x86, arm64, arm, and riscv vmlinux dispatch. Compilation is not a non-x86 physical result.
Performance/capacity results: all authoritative maps are bounded and fail closed on missing or full state. No identity-specific production latency or saturation result is recorded. The feasibility benchmark is historical platform evidence, not an identity result.
Unsupported/degraded paths: complete administrative-exec approval, permission, and physical denial remain outside this identity result. Policy and effect tables now exist in the current source, but they do not expand this result. The administrative identity foundation uses the trusted node lowering boundary to install an exact live executable tuple; the approval ingress and complete portable transaction remain required. A configured static Docker binding validates live cgroup identity but does not continuously validate Docker-daemon metadata; a replacement container therefore requires a new configured generation and otherwise loses authority. CRI-backed bindings continuously validate exact runtime metadata and local cgroup placement, but snapshot discovery alone cannot prove that a binding preceded the first user instruction; only a qualified Created/empty-cgroup observation or later supported start hook can make that claim. The complete ephemeral-container, non-leader/concurrent/failure-injected exec, map saturation, identifier reuse, and non-x86 cases remain physically unqualified. A cleanup loss deliberately leaks restriction and raises reconciliation rather than recovering authority.
Remaining work in this phase: run and record the remaining Phase 2 operator rows and failure-injection matrix. Do not change the implementation result to Done without those physical artifacts.
Next phase not authorized: yes.
```

## Maintenance update — 2026-08-09

`KernelHostOwner::start` now validates the program/map layout from the same
opened libbpf object that it subsequently loads fresh or reuses for identity
recovery. This removes the duplicate open/parse path while retaining the two
separate checks: every required program must be present before load, and every
non-iterator required program must attach after load. Focused
`cargo test -p erebor-interceptor`, `cargo check --workspace`, and
`bash .github/scripts/verify-rust-ci.sh` passed.

## Qualification update — 2026-08-12

The repository owns the disposable privileged harness at
[`crates/mithril-e2e/harness/vm`](../../../crates/mithril-e2e/harness/vm/README.md).
The current identity VM run passed on x86_64 Ubuntu kernel 6.8.0-136-generic.
It used object SHA-256
`c9a73d3f640443c0968ee86f76d5a456b369e75564bdae925aecb06cda2dbbf1`.
The evidence file SHA-256 is
`f392274c5643120b035cf84937529a39d805931ddeba37bbbaf148c66c58bc0e`.
The probe recorded these results:

- A task created directly with `clone3(CLONE_INTO_CGROUP)` had an external,
  restricted root identity before the probe released the task.
- The first native child had the external root as its creator and real parent.
- First start and recovered start each reported `ready=true`, 45 maps, and 48
  links.
- `map_ids_stable_across_restart=true` and
  `profile_task_refs_after_exit=0`.
- The native child kept its task and creator identity across exec and changed
  its active execution identity.
- `pin_root_removed=true`, `lease_removed=true`, and
  `cgroup_removed=true`.

The optional k3s lane also passed. It recorded Pod readiness, CRI discovery,
the workload root, overlay storage, and a projected token. Its record SHA-256
is `905a3ad84106e975cc1cde8b68cb24c861079f8baf3b616c597ec14e234f2503`.
This lane proves the k3s substrate only. It does not configure or prove a
Mithril CRI binding.

The phase stays **Blocked** because the complete entry-case and
failure-injection matrix is not recorded. The full ephemeral-container,
non-leader and concurrent exec, cgroup and PID reuse, saturation, and non-x86
physical cases remain unqualified.

## Qualification update — 2026-08-15

At source commit `d4fd67f`, the production identity probe passed on x86_64
Linux `6.8.0-137-generic`. It used production object SHA-256
`69ee79417f875f7c7a7065d18e08918e9d9bc32359711b57013eba77879fbcbe` and
runtime BTF SHA-256
`6da9f6b4ebcae9b07e6a717b517884abf7f6b524e46340e40fb164eed4a49a7c`.
The evidence file SHA-256 is
`dbf7bc49e4aedb22f38d261f0d51720e9bc71e79b9803d12cc74bdb39df4a7ff`.

The probe recorded `cgroup_escape_placement_mismatch_detected=true`,
`distinct_pin_root_owner_rejected=true`,
`map_ids_stable_across_restart=true`, and
`profile_task_refs_after_exit=0`. Its pin root, lease, and cgroup cleanup
fields are true. The second-owner result uses a distinct pin root and instance
lease. It verifies the active host-owner guard rather than a same-path lock.
After the first owner shut down while its pins remained, a second pin root was
rejected before it attached a link. The original pin root then recovered its
links and maps.

The checked qualification registry now contains the digest-bound 134 Appendix
C fixture IDs, required families, and canonical golden inputs. The readable
architecture, master allocation, and parser validate it. These commands pass:

```sh
cargo test -p mithril-e2e --lib closure::tests::fixture_registry_matches_architecture_master_and_criteria --all-features
cargo test -p mithril-e2e --lib golden::tests --all-features
cargo test -p mithril-e2e --lib identity::tests --all-features
cargo test -p mithril-control --test profile_simulation --all-features
```

The phase remains **Blocked**. This probe does not execute the complete entry
and failure-injection matrix. The full ephemeral-container, non-leader and
concurrent exec, cgroup and PID reuse, saturation, and non-x86 physical cases
remain unqualified.

## Double-Fork Qualification Update — 2026-08-15

An isolated physical probe ran at source commit
`2f3dad0081377651a8d2b52ca9479439ac7176b0`. The identity, BPF, and inspector
paths were unchanged from
`6190ca75641cb73d585712e2900afb520576db26`, which added the double-fork
fixture. It ran on x86-64 Linux `6.8.0-137-generic` with BPF object SHA-256
`69ee79417f875f7c7a7065d18e08918e9d9bc32359711b57013eba77879fbcbe`. The
result JSON SHA-256 is
`e69b94754c479ceeddaf55d847b4d89d870793cf30d5a0139eead12fc28c4f64`.

The outer restricted runtime root had task cookie `57`. Its intermediate
native child had task cookie `60` and creator and real-parent cookie `57`.
The stopped grandchild had task cookie `66`, creator and real-parent cookie
`60`, and real-parent interval `1`. After the intermediate exited and the
grandchild executed `sleep`, it kept task cookie `66` and creator cookie `60`.
Its real-parent cookie changed to `0`, its real-parent interval changed to
`2`, and its active execution changed. The probe reported
`pin_root_removed=true`, `lease_removed=true`, `cgroup_removed=true`, and
`profile_task_refs_after_exit=0`.

This is physical evidence for the double-fork subcase of
`ID-CREATOR-PARENT-007` only. It does not qualify subreaper, namespace-init,
ptrace-reparenting, or PID-reuse cases. The phase remains **Blocked**.

## Moved-Parent Fork Source Update — 2026-08-15

Source commit `8dbd9f5910cceeb9155a2701f47bbdfe25f58d25` adds a source-backed
ordinary-fork check for `ID-MOVED-PARENT-FORK-004`. The identity probe moves
its labeled `CloneIntoCgroupFixture` root to the parent cgroup. It requires
the `fail_closed_unknown` state before it resumes the root and requires its
ordinary `fork` call to fail with `EACCES`. The fixture also rejects a visible
child and the runner requires one more placement-mismatch count. The output
sets `moved_parent_fork_denied=true` only after those checks pass.

The Linux Security Module task-allocation hook rejects a labeled creator when
its active cgroup binding does not match the label placement. The node
configures that denial as `EACCES`. The focused fixture test and
`bash .github/scripts/verify-rust-ci.sh` passed for this source change.

No privileged VM ran this slice. The existing manual catalog keeps the row,
but its operator scripts do not create this controlled fixture. The phase
remains **Blocked**.
