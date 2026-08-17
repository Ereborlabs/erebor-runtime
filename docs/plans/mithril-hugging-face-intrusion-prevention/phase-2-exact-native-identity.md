# Phase 2: Exact Native Identity

Status: Blocked. The current source passed the disposable privileged VM
identity probe. The complete failure-injection and entry-case matrix is not
recorded.

Master: [Mithril Hugging Face Intrusion Prevention](./README.md)
Design: [Validated readable architecture](./policy-and-protection-algorithm-architecture-readable.md)
Manual acceptance: [Phase 2 runbook](./manual-testing/phase-2-manual-acceptance.md)  
Closure matrix: [checked fixture evidence](./phase-2-closure-matrix.md)
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
Fixture cases and exact physical results: AUTHORIZATION-REPLAY-004 has code-backed signature, exact-target, bounded deterministic-CBOR, trust/key/epoch, 4,096-bit replay, durable proof/slot, restart, idempotent close recovery, and one-use consumption tests. Unit tests cover exact ABI layout, closed enum/state values, binding identity and initial-root admission, configured static/CRI binding validation, Created-versus-Running initial-root treatment, exact runtime-lifetime reconciliation, cgroup path-reuse and cgroup-root rejection, distinct/recovered nonce behavior, epoch recovery, CRI cgroup parsing, reference parsing, object embedding, exact required program/map sets, packaging, and exact allocation of all 33 identity fixture IDs. The complete operator case catalog lives under examples/mithril-identity-manual. Separate small shells run the real mithril-node for raw Docker exec, direct CRI exec, Kubernetes exec, native-child provenance, namespace-only and cgroup-moved `nsenter`, and exact restart recovery; each owns and removes its tasks, pins, lease, state, config, and logs. An earlier VM record has object_sha256=c9a73d3f640443c0968ee86f76d5a456b369e75564bdae925aecb06cda2dbbf1. First start and recovered start each report ready=true, 45 maps, and 48 links. map_ids_stable_across_restart=true and profile_task_refs_after_exit=0. The external root and the direct `clone3(CLONE_INTO_CGROUP)` root have root_class=external_runtime_root and installed_role_class=runtime_external_restricted. The direct native child has creator_task_cookie=5 and real_parent_task_cookie=5. The later native child keeps task_cookie=21 and creator_task_cookie=18 across exec, while active_execution_id changes from 00000000000000010000000000000016 to 0000000000000001000000000000001c. pin_root_removed=true, lease_removed=true, and cgroup_removed=true. The identity evidence SHA-256 is f392274c5643120b035cf84937529a39d805931ddeba37bbbaf148c66c58bc0e. On 2026-08-15, the K3s lane added by `d806aa3` also ran a direct `crictl exec` in the exact bound container. The direct CRI task had no creator task cookie, `external_runtime_root` as its root class, and `runtime_external_restricted` as its installed role. The same lane passed its OBSERVE and PROTECT file-effect checks and removed its namespace, fixture, pin root, and lane state. This is one physical `ENTRY-EXEC-002` result. Fixture allocation is not physical execution of every fixture.
Commands and exact source state covered: the disposable VM record under /tmp/mithril-vm-source18-final covers the current object digest above. The optional k3s record under /tmp/mithril-k3s-source20-final uses the same object digest. Repository CI results are recorded separately after the final repository edit.
Platform/kernel/runtime manifests: the physical identity probe ran on x86_64 Ubuntu kernel 6.8.0-136-generic with LSM order lockdown,capability,landlock,yama,apparmor,bpf, runtime BTF SHA-256 9aa9eb9e8108bff44e685830315fb7a442bafd99778314cdd6de0fb72868829f, cgroup v2, and unique mount IDs. The optional k3s lane recorded k3s v1.35.5+k3s1, node ubuntu, CRI endpoint unix:///run/k3s/containerd/containerd.sock, overlay storage, and a projected token available through exec and the workload root. Its k3s record SHA-256 is 905a3ad84106e975cc1cde8b68cb24c861079f8baf3b616c597ec14e234f2503. This is runtime-substrate evidence only. It does not configure or prove a Mithril CRI binding. The production program compiles through the checked x86, arm64, arm, and riscv vmlinux dispatch. Compilation is not a non-x86 physical result.
Performance/capacity results: all authoritative maps are bounded and fail closed on missing or full state. No identity-specific production latency or saturation result is recorded. The feasibility benchmark is historical platform evidence, not an identity result.
Unsupported/degraded paths: complete administrative-exec approval, permission, and physical denial remain outside this identity result. Policy and effect tables now exist in the current source, but they do not expand this result. The administrative identity foundation uses the trusted node lowering boundary to install an exact live executable tuple; the approval ingress and complete portable transaction remain required. A configured static Docker binding validates live cgroup identity but does not continuously validate Docker-daemon metadata; a replacement container therefore requires a new configured generation and otherwise loses authority. CRI-backed bindings continuously validate exact runtime metadata and local cgroup placement, but snapshot discovery alone cannot prove that a binding preceded the first user instruction; only a qualified Created/empty-cgroup observation or later supported start hook can make that claim. Serial and two-worker normal concurrent exec passed in the manual VM. Exec versus fork, vfork, and thread creation, complete ephemeral-container, map saturation, identifier reuse, and non-x86 cases remain physically unqualified. A cleanup loss deliberately leaks restriction and raises reconciliation rather than recovering authority.
Remaining work in this phase: run and record the remaining Phase 2 operator rows and failure-injection matrix. Do not change the implementation result to Done without those physical artifacts.
Next phase not authorized: yes.
```

## Concurrent Exec Result — 2026-08-17

The retained x86_64 Ubuntu 24.04 VM, kernel `6.8.0-137-generic`, ran the
production `mithril-identity-test physical-probe` with unique paths. The JSON
record was `/tmp/mithril-phase2-concurrent-final.9XkJqd/identity-physical-probe.json`.
Its SHA-256 was
`6438be6817109b6592fb60bd39fd50e061528fcc8615f5403037c4bcc5a0ee08`.
The BPF object SHA-256 was
`69ee79417f875f7c7a7065d18e08918e9d9bc32359711b57013eba77879fbcbe`.

The source fixture SHA-256 was
`a168927ad6a9f37da535f7c05be1cb9eeab8a72303555025946c410e3c85c3f9`.
It created two sibling Python threads, held both before `exec`, and released
both through one barrier. The fixture required exactly four identity-ID
allocations: two task identities and two clone-attempt identities. It required
two distinct live `task_coordinates` records with the root process state. The
surviving Linux exec had one worker task cookie, the root creator cookie, the
same restricted role, changed execution and image IDs, and no exec guard.
The JSON recorded `concurrent_thread_exec_committed=true` and removal of the
pin root, lease, and cgroup.

The same retained VM ran
[`native-child.sh --concurrent-thread-exec`](../../../examples/mithril-identity-manual/native-child.sh)
as root. Its source SHA-256 was
`adc11a45efb571fe4e73e4d8aaa27a4de3d9ede69a6244117b53ee446ac9644d`.
It created and removed its K3s Pod, CRI binding, fixture directory, node,
pin, lease, and cgroup. No case namespace, fixture, pin, node process, lease,
or cgroup remained.

This result qualifies the normal two-worker exec subcase of
`EXEC-CONCURRENT-002`. It does not qualify exec versus fork, vfork, or thread
creation. The phase remains **Blocked**.

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

## Moved-Parent Fork Physical Qualification Update — 2026-08-15

The isolated identity probe passed at source commit
`bd48b5a474273510c92611fa90285632883d13cb`. The copied
`mithril-identity-test` binary SHA-256 was
`5bf7300dc74ff6792727210a3d4907dfb50cf1fe32ca855ab40f2db815c288d1`.
The result JSON is
`/tmp/mithril-phase2-moved-parent-bd48b5a47427/identity-physical-probe.json`.
Its SHA-256 is
`82a525950ccf1a78d8be29307f2cf479eb28901a016d48e9404bdece982f3216`.

The normal native child had task cookie `28`. Its active execution changed
from `0000000000000001000000000000001d` to
`00000000000000010000000000000023`. Its image provenance changed from
`0000000000000001000000000000001b` to
`00000000000000010000000000000024`. Both snapshots were active. The final
snapshot had no exec guard.

The moved labeled parent became fail-closed before it resumed. Its ordinary
`fork` exited with `EACCES` and created no visible child. The runner required a
second placement-mismatch increment after the earlier cgroup-move mismatch.
The JSON records `moved_parent_fork_denied=true` and
`cgroup_escape_placement_mismatch_detected=true`.

The JSON also records `map_ids_stable_across_restart=true`,
`profile_task_refs_after_exit=0`, and
`live_manifest_mismatch_detected=true`. It records
`pin_root_removed=true`, `lease_removed=true`, and `cgroup_removed=true`.
Postflight found the dedicated pin root, lease, and cgroup absent. Only the
unrelated tracing BPF link remained.

This qualifies `ID-MOVED-PARENT-FORK-004` only. A readable manual script was
not added. It cannot reproduce the fixture-controlled cgroup move without
creating a separate runtime. The phase remains **Blocked** because the full
entry and failure-injection matrix is not qualified.

## Moved-Native-Task Exec Physical Qualification Update — 2026-08-15

The isolated identity probe passed at source commit
`0c25e8c84a94d4a632e1f44efd50befbbe37f420`. The copied
`mithril-identity-test` binary SHA-256 was
`ab212876b1cca4a38255a64a09b0c56c0831bef513b11ce6dc12a19b83c56404`.
The preserved result JSON is
`/tmp/mithril-phase2-moved-task-0c25e8c84a94-39721.identity-physical-probe.json`.
Its SHA-256 is
`dc116ae01389e131232f8d3c0d850b23f716cfed9309c338edaea5077cb0a854`.

The JSON records schema version `4` and `moved_task_exec_denied=true`. The
normal native child kept its task cookie across exec. Its active execution ID
and image provenance ID changed. Its final coordinate state was `Runnable`,
and its exec guard state was `None`.

The runner moved only the stopped labeled child to the parent cgroup. It
required `FailClosedUnknown` before release. After release, it required a
second placement-mismatch increase and a failing outer shell within five
seconds. A successful `sleep` exec cannot satisfy that oracle. This proves the
denied moved-task exec without a later `sleep` effect.

The JSON records `pin_root_removed=true`, `lease_removed=true`, and
`cgroup_removed=true`. Postflight found the primary, alternate, and retired
pin roots, the cgroup, the lease, and the lane root absent. Only the unrelated
tracing BPF link remained.

This qualifies `ID-MOVED-TASK-EXEC-005` only. The complete entry and
failure-injection matrix remains unqualified. The phase remains **Blocked**.

## Entry-Migration Identity Subcase — 2026-08-15

The moved-native-task JSON above also proves one narrow
`ENTRY-MIGRATE-001` subcase. The probe ran at source commit
`0c25e8c84a94d4a632e1f44efd50befbbe37f420`, which contains
`5d5518e95350b364bc6bb5da58d3e0c13ea561d5`. It starts a host shell outside
the configured cgroup, then moves that PID into the configured cgroup. The
runner requires `creator_task_cookie=null`, `external_runtime_root`,
`runtime_external_restricted`, the configured external role, and `Runnable`.
The JSON records those values in `external_root`.

This is physical identity evidence for host-task cgroup entry only. It does
not run `nsenter`, restore, or a protected effect. It does not qualify the
complete `ENTRY-MIGRATE-001` row. The phase remains **Blocked**.

## Non-TTY Kubernetes Exec Identity Subcase — 2026-08-15

The retained K3s CRI lane ran at source commit
`e38a117b1d2a3bb2f3e1947483c1f4f61f7fd43e`. Its staged guest script SHA-256
was `380fd7c73d33aefc320ff7919160db38c29be7d06b59f6dc51dd5b715fcf4018`.
The lane invoked `kubectl exec ... -- sh -c ...` without `-i`, `-t`, or
`--tty`. Before it accepted the task, the staged script required
`creator_task_cookie=null`, `external_runtime_root`, and
`runtime_external_restricted` for that `kubectl exec` root.

The `OBSERVE` record is
`/tmp/mithril-phase3-direct-cri-evidence.eWjKKw/observe-clean.txt`, SHA-256
`c6cdd686dde59b84fa362b1c3e4e3d8e839bac44339081b8611cfc985057b994`. It
records task cookie `80` for the `kubectl exec` exact read. The `PROTECT`
record is
`/tmp/mithril-phase3-direct-cri-evidence.eWjKKw/protect-clean.txt`, SHA-256
`a3a5a16e8abc67e0d919b4650c62e0a1ce75c0df206c96028d93c8790351f8ab`. It
also records task cookie `80` for the exact read. The Phase 3 record reports
clean lane postflight. This reuses that physical evidence; it is not a new VM
run.

This is one non-TTY `kubectl exec` identity subcase of `ENTRY-EXEC-001`.
It does not test TTY execution, copy-shaped execution, or a native application
child with the identical command. It does not complete `ENTRY-EXEC-001`. The
phase remains **Blocked**.

## Pre-PONR Failed-Exec Physical Qualification — 2026-08-15

The isolated identity probe passed at source commit
`af685cd6a8dd73f22bd44234b3346298dd04dcd1`. The copied
`mithril-identity-test` binary SHA-256 was
`b23d8be165d9b88532dcd15db1905233134a86a2be8f7f40042e508a302c49a0`.
The result JSON is
`/tmp/mithril-phase2-preponr-af685cd.9897yN/identity-physical-probe.json`.
It has schema version `5` and SHA-256
`8a57d0a43b7fe505da68f0644237720e8419145a942ae9173ab643b1c8c6cf45`.

The runner stopped the native Bash child before it took its baseline snapshot.
It required no `pending_execs` entry. It then forced an ELF loader failure
after exec preparation and before the point of no return.
`pre_ponr_failed_exec_restored=true`. The before and post-failure snapshots
both had task cookie `44`, creator and real-parent cookie `41`, process state
`00000000000000010000000000000030`, active execution
`00000000000000010000000000000033`, image provenance
`00000000000000010000000000000034`, and active role `11`. Their process
execution and process-state vector were active, and their exec guard was none.

A later normal exec kept task cookie `44`, creator and real-parent cookie
`41`, process state `00000000000000010000000000000030`, and active role
`11`. It changed active execution to
`00000000000000010000000000000039` and image provenance to
`0000000000000001000000000000003a`. Its process execution and process-state
vector were active, and its exec guard was none.

The JSON records `pin_root_removed=true`, `lease_removed=true`,
`cgroup_removed=true`, and `profile_task_refs_after_exit=0`. Postflight found
the run staging root absent. Only the unrelated tracing BPF link remained.

Use [`native-child.sh --failed-exec`](../../../../examples/mithril-identity-manual/native-child.sh)
for the readable companion procedure. It requires `/bin/bash`, `python3`, and
a dynamically linked `/bin/true` in the selected workload.

This is physical evidence for the pre-PONR recovery subcase of
`EXEC-COMMIT-STATE-001` only. It does not qualify post-PONR fatal or unknown
handling, concurrent or non-leader exec, or the full fixture. The phase remains
**Blocked**.

## Entry-Migration Manual VM Qualification — 2026-08-17

At source commit `e6352f8`, the retained x86_64 Ubuntu 24.04 VM ran the exact
root-shell command:

```sh
examples/mithril-identity-manual/nsenter-move.sh
```

The shell SHA-256 was
`871f3dc975a31cf423a97296462581a16a224d16650270ca59f962ffdbb5adec`.
The shell used `identity_prepare_k3s_case` to create and remove its Pod, CRI
binding, fixture directory, node process, pins, lease, state, and cgroup. It
started a namespace-only `sleep 300` child, confirmed no Mithril task identity
before movement, and moved that child into the configured cgroup. The final
task had no creator task cookie, `external_runtime_root`,
`runtime_external_restricted`, active role `2`, and `Runnable` coordinate
state `3`. The shell printed `PASS`.

The same VM ran `mithril-identity-test physical-probe` with unique paths. The
result JSON was
`/tmp/mithril-phase2-entry-auto.KoZvGP/identity-physical-probe.json`. Its
SHA-256 was
`91990138176e69b729f043b3f9e349fffa259f6bf36e9edbfdfd53405722ac2b`.
The JSON records restricted external roots for both the host-entry control and
the `CloneIntoCgroupFixture` root. It records
`pin_root_removed=true`, `lease_removed=true`,
`cgroup_removed=true`, and `profile_task_refs_after_exit=0`.

Postflight found no case namespace, fixture directory, Mithril pin, node
process, lease, or cgroup. This is a qualified namespace-entry and cgroup-move
subcase of `ENTRY-MIGRATE-001`. It does not test a protected effect, movement
of an already labeled task through a namespace boundary, restore, or the full
fixture. The phase remains **Blocked**.

## Labeled Native Mount-Namespace Entry — 2026-08-17

At source commit `da4e1996c8e3ec4450d5b9e0ca5da7d6bacd6f89`, the retained
x86_64 Ubuntu 24.04 VM, kernel `6.8.0-137-generic`, ran the production
identity probe with these unique paths:

```sh
/mnt/mithril-source/target/debug/mithril-identity-test \
  --repo-root /mnt/mithril-source \
  --output-directory /tmp/mithril-phase2-labelled-ns-20260817-1450 \
  physical-probe \
  --pin-root /sys/fs/bpf/erebor-mithril-phase2-labelled-ns-20260817-1450 \
  --lease-path /tmp/mithril-phase2-labelled-ns-20260817-1450.lock \
  --cgroup-path /sys/fs/cgroup/erebor-mithril-phase2-labelled-ns-20260817-1450
```

The source SHA-256 values were
`identity.rs=30d1d88ba42b35f9fe1e7c6e42c938fd1b44cad87722c89f0e427c10437636e1`
and
`clone3.rs=aa80e796f0553792e5d4cca54f023acfc02d08da085275fa9524cb5112db992b`.
The BPF object SHA-256 was
`69ee79417f875f7c7a7065d18e08918e9d9bc32359711b57013eba77879fbcbe`.
The schema-8 JSON was
`/tmp/mithril-phase2-labelled-ns-20260817-1450/identity-physical-probe.json`.
Its SHA-256 was
`a079d291aa17bf7a19d8ef281b37ce773f325e2a014014072e75d6761d34c161`.

The existing `CloneIntoCgroupFixture` stopped its native child before entry.
It released the child into a distinct mount namespace through `nsenter`. The
JSON records the same task cookie `15`, creator and real-parent cookie `12`,
process state `00000000000000010000000000000013`, and active role `11`
before and after entry. The active execution changed from
`00000000000000010000000000000010` to
`00000000000000010000000000000019`. The image provenance changed from
`0000000000000001000000000000000e` to
`0000000000000001000000000000001a`. The final task was `Runnable`, both
process records were active, and the exec guard was none. The JSON records
pin, lease, and cgroup removal.

At source commit `af1e1c3eae202354b413beda085032930776fee3`, the same VM ran
this root-shell command:

```sh
examples/mithril-identity-manual/nsenter-move.sh --labeled-task
```

The shell SHA-256 was
`6cda64a4e3c62e61ee24f05f301e6ff627e722d9f4525d601434ea4c0f12cbcd`.
The shell uses `identity_prepare_k3s_case`. It creates its Pod and fixture
directory, obtains the live CRI binding and cgroup, and owns node, pin, lease,
state, and cleanup setup. It moves a staging Bash into the configured cgroup,
executes Bash in that cgroup, and requires the restricted external-root record.
That root creates one stopped native child. The child enters only the Pod mount
namespace and executes `sleep 300`.

The manual records kept one task cookie, creator cookie, real-parent cookie,
process state, and restricted role. They recorded changed execution and image
provenance IDs, `Runnable`, active process execution and state-vector records,
and no exec guard. The shell printed `PASS`. Postflight found no case namespace,
fixture directory, Mithril pin, node process, lease, or cgroup.

This qualifies the labeled native mount-namespace subcase of
`ENTRY-MIGRATE-001`. It does not test a protected effect or restore. The phase
remains **Blocked**.

## Current Moved-Native Rows — 2026-08-17

At source commit `c1b15be02553ae6cd18210d23f9e2bb2447a9511`, the retained
x86_64 Ubuntu 24.04 VM ran this root-shell command with unique paths:

```sh
/mnt/mithril-source/target/debug/mithril-identity-test \
  --repo-root /mnt/mithril-source \
  --output-directory /tmp/mithril-phase2-native-current.WXbFLa \
  physical-probe \
  --cgroup-path /sys/fs/cgroup/erebor-mithril-native-current-WXbFLa \
  --pin-root /sys/fs/bpf/erebor-mithril-native-current-WXbFLa \
  --lease-path /tmp/mithril-phase2-native-current.WXbFLa/owner.lock
```

The binary SHA-256 was
`ad9365eb1e89236b50f70284cdaa0688b2895e15259fd25293f5596e873a0566`.
The `identity.rs` SHA-256 was
`55a41850493db34587f6ccb513bcad33e016ce3b0a23e5bcca23f67a26643ec2`.
The `clone3.rs` SHA-256 was
`8bebbc088420f8280e9e3fa80717f2901ff48c530aca2e1c7e6fedd97d444e78`.
The JSON SHA-256 was
`25fde400976256d45d6b5a30f2c6854355af88dd910e99d97ef6c91c2de544da`.

The result recorded `moved_parent_fork_denied=true` and
`moved_task_exec_denied=true`. It recorded
`pin_root_removed=true`, `lease_removed=true`, `cgroup_removed=true`, and
`profile_task_refs_after_exit=0`. Postflight found no probe pin, lease,
cgroup, node, or fixture process.

This current result qualifies `ID-MOVED-PARENT-FORK-004` and
`ID-MOVED-TASK-EXEC-005`. The first case has no valid operator shell because
the controlled `CloneIntoCgroupFixture` owns its process synchronization. The
second case has the readable
[`native-child.sh --moved-exec`](../../../../examples/mithril-identity-manual/native-child.sh)
procedure. The other matrix rows remain unqualified. The phase remains
**Blocked**.

## Subreaper Reparenting Qualification — 2026-08-17

The qualifying source commit is `7f742772b5f6bf51a9eee9e48cc63197c08480a1`.
The retained x86_64 Ubuntu 24.04 VM ran kernel `6.8.0-137-generic`.
It ran `IdentityTestRunner::physical_probe` with unique output, pin, lease,
and cgroup paths. The schema-9 JSON is
`/tmp/mithril-phase2-subreaper-20260817-1642/identity-physical-probe.json`.
Its SHA-256 is
`a448889bbed4a157af9146ef7f504cac25fefc0682b2f030fc120a6e2fe6882e`.
The BPF object SHA-256 is
`69ee79417f875f7c7a7065d18e08918e9d9bc32359711b57013eba77879fbcbe`.

The fixture created restricted external root task `124`, native intermediate
task `127`, and stopped native child task `133`. Before the intermediate exit,
the child creator and real-parent cookie were `127`. After the exit and child
`sleep` exec, the child kept task cookie `133`, creator cookie `127`, process
state, and restricted role `11`. Its real-parent cookie was `0`, its
real-parent coordinates were the live root TID and TGID `6997`, and its
real-parent interval changed from `1` to `2`. Its execution and image IDs
changed. Its coordinate and both process records remained active, and its exec
guard was none.

The same VM ran this root-shell command:

```sh
examples/mithril-identity-manual/native-child.sh --subreaper
```

The shell created its K3s Pod and live CRI binding through
`identity_prepare_k3s_case`. It printed `PASS`. It checked the same immutable
creator, real-parent coordinate, execution, image, role, and active-state
limits. Postflight found no case namespace, fixture directory, Mithril pin,
node process, lease, or cgroup. The JSON records
`pin_root_removed=true`, `lease_removed=true`, `cgroup_removed=true`, and
`profile_task_refs_after_exit=0`.

This qualifies the subreaper reparenting subcase of
`ID-CREATOR-PARENT-007` only. Namespace-init, ptrace reparenting, and PID reuse
remain required. The phase remains **Blocked**.
