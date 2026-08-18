# Phase 2: Exact Native Identity

Status: Blocked. The current source passed the privileged VM native identity
probe and its Kubernetes entry extension. The extension includes direct CRI
exec, non-TTY and TTY `kubectl exec`, `kubectl cp`, and an identical native
child. It also includes lifecycle sleep and HTTP, TCP, and gRPC readiness
probes, plus separate init, native-sidecar, and application identity. The VM
used Kubernetes through the K3s distribution. A targeted ephemeral container
also kept a separate identity tree while it shared the application PID
namespace. Concurrent exec probes and probe-identical native, `kubectl exec`,
and direct CRI entries also kept their required identity classes. The complete
failure-injection and entry-case matrix is not recorded. A qualified OCI
prestart path now binds the held container init task before its first exec and
keeps real PostStart hooks distinct in both application-start orders.
The native probe also records post-PONR fatal exec state, leader-first exit,
exact native reference release, and namespace PID/TID reuse without stale
identity.

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
- Native identity: `EXEC-COMMIT-STATE-001`, `ID-CGROUP-ESCAPE-001`,
  `ID-CLONE-CGROUP-002`,
  `ID-CREATOR-PARENT-007`,
  `ID-MOVED-PARENT-FORK-004`, `ID-MOVED-TASK-EXEC-005`,
  `ID-TASK-COORD-FINALIZE-006`, and `NATIVE-STATE-REF-LIFETIME-001`.
- Authorization: `AUTHORIZATION-REPLAY-004`; the identity half of
  `ADMIN-EXEC-APPROVAL-001` is exercised here and the complete physical result
  is owned by Phase 4.
- `STATE-FORK-IPC-002` begins in Phase 3 observation and Phase 4 enforcement.
  Its required public-send result is an effect-policy decision, not a Phase 2
  identity result.
- `EXEC-CONCURRENT-002` and `STATE-THREAD-RACE-001` begin in Phase 4. Their
  required target-role transition and raced effect decision need Phase 4
  policy authority. The current normal Linux exec control remains source and
  manual evidence for that later work.
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
Validated architecture revision/digest: policy-and-protection-algorithm-architecture-readable.md at SHA-256 22678b9c0379ff915fe595059f3da2789c3e32cdf54d61656c7257175263d14a.
Completed deliverable IDs: D2.1-D2.6 are implemented and code-backed. The current source passed the disposable privileged VM identity probe. The phase cannot be marked Done until the remaining failure-injection and entry-case matrix passes.
Files and durable owners changed: erebor-interceptor-abi owns the generated snake_case Rust/C task, process, entry, authority, fork-edge, exec, binding, reference, and health layouts; bpf/erebor-interceptor/programs owns the production CO-RE identity object through one translation-unit front, one map owner, shared task/root helpers, and lifecycle/exec/effect/exit hook families; erebor-interceptor owns the fully vendored libbpf-rs load/attach/pin/reuse/readback lifecycle and its narrow read-only pinned-map reader, and embeds the single libbpf-cargo-built production object; mithril-node owns binding publication, exact CRI inventory reconciliation, boot/label epochs, task reconciliation, signed-intent verification, trust/time/replay state, one-use authorization identity, and the read-only live-task inspector used by operators and e2e; mithril-e2e owns the bounded acceptance runners and disposable VM harness; examples/mithril-identity-manual owns the operator-driven cases.
Build and simplicity result: libbpf-cargo 0.27.0 is the only production C-to-BPF build path, and the production C is compiled with -Wall -Werror. The resulting object is embedded in the node binary and opened from memory through fully vendored libbpf-rs 0.27.0; the former second configured object path/checksum and Docker build-directory copy were removed. The BPF source follows the checked-source hook-family shape without adding another object, loader, map owner, or link step: the small `identity.bpf.c` front includes the map/task/root owners and cohesive lifecycle, exec-transaction, effect-gate, and exit families into the same object. cbindgen remains only the Rust-to-C ABI renderer and drift check. Standard Linux names CLONE_PARENT, CLONE_THREAD, AT_EXECVE_CHECK, and EACCES are used through the minimal syscall-note UAPI header because those macros are absent from vmlinux BTF and full host UAPI headers would make the CO-RE translation unit host-architecture-dependent. Product-owned state constants are generated once from the shared ABI.
Correctness-preserving simplifications: execution_set_bindings is the single cgroup-placement authority. Configured non-CRI bindings still use one exact cgroup path and periodically revalidate its live handle, device, and inode. The 2026-08-09 pass rejects the cgroup root as a workload, opens the cgroup handle before publication, compares the handle and live path identity before each publish, and rejects root/traversal CRI paths. When CRI is configured, `WorkloadBindingOwner` takes one standard full `ListContainers` snapshot per interval, ignores unconfigured containers, validates the configured full container ID, Pod UID, sandbox, container name, image reference, creation generation, and live Created/Running state, and resolves `runtimeSpec.linux.cgroupsPath` locally before publishing. A newly observed Created container may retain configured initial-root arming only while its cgroup is empty; a container first observed Running is conservatively external and is never retroactively promoted. A missing/stopped exact lifetime is transitioned to Terminating, and a changed/reused identity fails closed. The periodic inventory is recovery truth after event loss or restart; adding a separate CRI-event state machine would not prove pre-start ordering. Raw Docker exec, direct CRI exec, and a host task moved after `nsenter` use the same BPF classification path rather than separate runtime-specific identity engines. The BPF program performs a bounded 64-level walk of the live kernel cgroup ancestry, using the upstream-compatible cgroup ancestors layout with the self.parent fallback; an unreadable or over-depth chain denies and increments health rather than treating the task as unprotected. Missing exit tombstones now also increment reconciliation health while retaining restrictions. This replaces both the userspace descendant scan and the capacity-sensitive descendant map. AT_EXECVE_CHECK ownership is an atomic task-cookie marker in ProcessSecurityStateV1, so a check-only exec cannot stage an exec, consume an administrative slot, or depend on insertion into another bounded map. Binding nonces are random UUID-v4 values on first publication and are recovered byte-exactly from pinned state on restart. Nested configured protected roots are rejected instead of introducing precedence rules. Exact desired assignments remain bootstrap inputs in Phase 2; policy compilation/effect permission is Phase 3-4 and authenticated fleet distribution remains Phase 7-8.
Upstream-adoption dossier IDs used: BJ-TASK-STORAGE-001 and BJ-REJECTED-ENROLLMENT-002 for task-first allocation and rejection of delayed PID enrollment; KA-LSM-DECISION-001 and KA-PATH-MOUNT-003 for prior-result/fail-closed LSM behavior and live mount identity; TG-FORK-EXEC-001, TG-RUNTIME-CGROUP-JOIN-002, TG-FRESH-MAPS-004, TG-VMLINUX-HEADER-006, and TG-VMLINUX-ARM64-007 for fork/exec, cgroup binding, recoverable publication, and CO-RE headers; AS-VMLINUX-ARM-001 and AS-VMLINUX-RISCV-002 for checked compile headers. No upstream daemon, policy engine, loader, or delayed-enrollment model was copied.
Fixture cases and exact physical results: the source allocates exactly 29 Phase 2 fixture IDs. Unit tests cover authorization-envelope identity, ABI layout, binding identity, runtime reconciliation, reference parsing, object embedding, required program/map sets, packaging, and fixture allocation. The native physical probe covers initial and external roots, direct `clone3(CLONE_INTO_CGROUP)`, native inheritance, exec continuity, reparenting, movement, restart, and cleanup. The Kubernetes extension covers the pre-existing conservative root, direct CRI exec, non-TTY and TTY `kubectl exec`, `kubectl cp`, an identical native child, the native lifecycle `sleep` action, HTTP, TCP, and gRPC readiness probes, distinct regular-init, native-sidecar, and application roots, a targeted ephemeral root in a shared PID namespace, concurrent exec-probe impersonation controls, and termination-time PreStop identity. The schema-15 entry JSON SHA-256 is ef749b5a6d2521c6bd865317ce3843bf685610d009500f6d37569c9bd26a57cc. The schema-16 lifecycle-sleep JSON SHA-256 is a62e82352a3153c65895d69265e4e0265d78ec6a76679e50a7d1f0bbcc2804fb. The schema-17 network-probe JSON SHA-256 is cbc024f56ce366a84aa2b0ffdbb7efaab58599b282d1f24295f30c08702fac07. The schema-18 container-identity JSON SHA-256 is dfb7b407b8a945c474a210fb769abbc09b03599ecb271f4c27cb9d195da92ada. The schema-19 ephemeral-identity JSON SHA-256 is ee12bc57c8431ac801ae6e06e2e55dbf75ec50692b3a594785fc0d27fabf0efc. The schema-20 probe-identity JSON SHA-256 is abead9ce84882d9ecc69853a417ef39ccd629f0df7de97e4ac0e5eebfd9190a6. The schema-21 PreStop JSON SHA-256 is 4d14142beb3671342c7c6d2c8ed8e5c9d85da730f60ef556f7783f7cd231fcee. The independent runtime entries are restricted external roots with no fabricated purpose. The identical children have native parent lineage and the parent's restricted role. Each lifecycle-sleep and network-probe cgroup contained only its container init PID. The regular init, native sidecar, application, and ephemeral container have separate conservative roots and execution sets as applicable. Fixture allocation and unit coverage are not physical execution of every fixture. The closure matrix states each remaining exact limit.
Commands and exact source state covered: source commit 098f167c88755f88acabf7f387da5095d568869d freezes the accepted PreStop runner, manifest, runtime helper, and manual shell. The accepted schema-21 JSON is /tmp/mithril-phase2-kubernetes-prestop-20260818-044/identity-physical-probe.json. The retained VM ran examples/mithril-identity-manual/kubernetes-prestop.sh as root; it passed from the same source bytes. Source commit 4ca2d26bd90ad6a9cd85b7fe5e9e615a6ea4fa14 and schema-20 JSON cover probe identity. Source commit 76d0145c2ecd7991ab7160773faf452c383df6a9 and schema-19 JSON cover ephemeral identity. Source commit 6e23a23e327f70b3462faf932b0845f7e52ec67f and schema-18 JSON cover container identity. Source commit f9b7c8bc2be84f2a39f3db7b43dae3ab1914c0d0 and schema-17 JSON cover network probes. Source commit 828fdec76c5753790c526d87e6757fde6134002e and schema-16 JSON cover lifecycle sleep. Source commit 53fbd287aad8b6012eb4f80dcd4fe83e34ed5470 and schema-15 JSON cover the Kubernetes entry forms. The manual and automated owners removed their Namespace, fixture, pin, lease, cgroup, node process, and loaded Erebor Interceptor programs. The manual harness destroyed each retained VM.
PostStart qualification update: source commit a056f00fd7d110cc0582b6e8a476de1d1e233a59 and schema-22 JSON cover prestart-bound initial roots, both real PostStart orders, and one repeated exact hook delivery after K3s restart. The accepted JSON is /tmp/mithril-phase2-kubernetes-poststart-20260818-049/identity-physical-probe.json. Its SHA-256 is f7b1c44d26ad5c3b36b401d5f80e87156594dd790daf965fc65c58760e4e0dcb. The retained VM ran examples/mithril-identity-manual/kubernetes-poststart.sh as root from the same source bytes. Automated and manual cleanup removed the case Namespace, RuntimeClass, fixture, prestart request, pin, lease, cgroup, node process, and loaded programs. The VM remains retained for the next operator case.
Native terminal-state qualification update: source commit e63488e and schema-23 JSON close EXEC-COMMIT-STATE-001, ID-CREATOR-PARENT-007, ID-TASK-COORD-FINALIZE-006, and NATIVE-STATE-REF-LIFETIME-001. The accepted JSON is /tmp/mithril-phase2-native-terminal-20260818-8/identity-physical-probe.json. Its SHA-256 is f659a8983f7002f8558d88862b2f3500b2e138563c083f308f56ac309f1be8cb. The same retained VM ran examples/mithril-identity-manual/native-pid-reuse.sh as root from the same source bytes. Automated and manual cleanup removed their fixture, pin, lease, cgroup, node process, Namespace, Pod, state, and manual work directory. The exact result is post-PONR fatal and outcome-unknown exec state; creator continuity across namespace PID reuse; task-coordinate continuity across missing PIDFD_THREAD, leader-first exit, and namespace TID reuse; and process, entry, profile-reference, and tombstone release at final thread exit. It does not qualify runtime-binding loss, restart reconciliation, full Kubernetes lifetime reuse, stock hook rejection, or authorization replay.
Platform/kernel/runtime manifests: the current physical result ran on x86_64 Ubuntu 24.04, kernel 6.8.0-137-generic, with cgroup v2 and the required BPF/LSM support. Kubernetes v1.35.5 ran through the K3s v1.35.5+k3s1 distribution, containerd v2.2.3-k3s1, the live CRI endpoint, and the configured io.containerd.runc.v2 handler. The OCI prestart hook held each init task until Mithril verified its Created container and sole cgroup PID, published its static binding, and activated identity. The BPF object SHA-256 is 02408c371aafaeeb044cbf11195a25dca35013bcdea44e37aa0756ebd2f2f3e6. The production program compiles through the checked x86, arm64, arm, and riscv vmlinux dispatch. Compilation is not a non-x86 physical result.
Performance/capacity results: all authoritative maps are bounded and fail closed on missing or full state. No identity-specific production latency or saturation result is recorded. The feasibility benchmark is historical platform evidence, not an identity result.
Unsupported/degraded paths: approved administrative roles, permission tables, raced policy transitions, protected effects, IPC policy, shared-resource policy, and response remain outside this identity result. A configured static Docker binding validates live cgroup identity but does not continuously validate Docker-daemon metadata. CRI-backed bindings validate exact runtime metadata and local cgroup placement, but snapshot discovery alone cannot prove that a binding preceded the first user instruction. Only a qualified Created/empty-cgroup observation or supported start interface can make that claim. The closure matrix lists the remaining Phase 2 identity, entry, coordinate, native-reference, and failure-injection results. A cleanup loss retains restriction and raises reconciliation instead of recovering authority.
PostStart limit: K3s did not automatically resend the in-flight hook. The fixture supplied the second exact CRI delivery after restart and does not claim automatic kubelet replay. Hook timeout, mismatch, and missing-field rejection remain open.
Remaining work in this phase: `AUTHORIZATION-REPLAY-004`, `ENTRY-LOSS-001`, `ENTRY-RESTART-001`, `ENTRY-REUSE-001`, and `ENTRY-STOCK-HOOK-FAILURE-002`. Do not change the implementation result to Done without their physical artifacts.
Next phase not authorized: yes.
```

## Kubernetes Entry Result — 2026-08-17

Source commit `da01f77d2deb83482788f16081307b01a6dc6556` passed the full
disposable VM harness on x86_64 Ubuntu 24.04, kernel
`6.8.0-137-generic`. Kubernetes `v1.35.5` ran through the K3s
`v1.35.5+k3s1` distribution. The schema-14 identity JSON is
`/tmp/mithril-kubernetes-entry-20260817-021/identity-physical-probe.json`.
Its SHA-256 is
`aa70c2c398c6d07d138b81293103f3cbfc4be91d2c8999387b893ff7cac92910`.
The BPF object SHA-256 is
`3269516fcd2714ab7fbe29df26386c40f0c912b6284007b641d8bbf68842b876`.

The pre-existing Pod root had no creator, `restored_or_unknown_root`, and
`fail_closed_unknown`. Direct CRI exec and non-TTY `kubectl exec` each had no
creator, `external_runtime_root`, `runtime_external_restricted`, and active
role `11`. Their task cookies differed. The runner removed its Kubernetes
Namespace, fixture directory, pin, lease, and cgroup. The outer harness removed
Kubernetes and destroyed the VM.

The retained manual VM ran `cri-exec.sh` and `kubernetes-exec.sh`
consecutively as root. Both printed `PASS`. Postflight found no case Namespace,
fixture, Mithril process, pin, lease, cgroup, or loaded Erebor Interceptor
program. The manual harness destroyed the VM, and `virsh list --all --name`
was empty.

This completes `ENTRY-EXEC-002`. It completes only the non-TTY subcase of
`ENTRY-EXEC-001`; TTY exec, `kubectl cp`, and the identical native-child
control remain open. Phase 4 owns the approved administrative role. Phase 2
remains **Blocked**.

## Kubernetes Exec Closure Result — 2026-08-18

Source commit `53fbd287aad8b6012eb4f80dcd4fe83e34ed5470` uses the
existing `IdentityTestRunner` and bundle. The automated physical extension
passed in the retained x86_64 Ubuntu 24.04 VM on kernel
`6.8.0-137-generic`. Kubernetes `v1.35.5` used the K3s
`v1.35.5+k3s1` distribution.

The schema-15 JSON is
`/tmp/mithril-phase2-kubernetes-entry-exec-20260818-025/identity-physical-probe.json`.
Its SHA-256 is
`ef749b5a6d2521c6bd865317ce3843bf685610d009500f6d37569c9bd26a57cc`.
It records distinct restricted external roots for non-TTY and TTY
`kubectl exec` and `kubectl cp`. It records an external parent and its native
child with exact creator, real-parent, and inherited-role identity. The copy
fixture also required exact destination bytes.

The same retained VM ran `kubernetes-exec-tty.sh`, `kubernetes-copy.sh`, and
`kubernetes-native-child.sh` consecutively as root. All three printed `PASS`.
Postflight found no case Namespace, fixture, Mithril process, pin, lease,
cgroup, or loaded Erebor Interceptor program. The manual harness destroyed the
VM, and `virsh list --all --name` was empty. The final full Rust CI script
passed with exit status `0`.

This completes `ENTRY-EXEC-001` and `ENTRY-START-001`. The pre-existing Pod
root records the exact late-discovery gap and conservative identity. It does
not prove first-instruction observation. It also does not prove approved
administrative exec; Phase 4 owns that result. Other open rows keep Phase 2
**Blocked**.

## Kubernetes Lifecycle Sleep Result — 2026-08-18

Source commit `828fdec76c5753790c526d87e6757fde6134002e` keeps the
Kubernetes lifecycle case in `IdentityTestRunner`. The schema-16 physical JSON
is
`/tmp/mithril-phase2-kubernetes-sleep-20260818-029/identity-physical-probe.json`.
Its SHA-256 is
`a62e82352a3153c65895d69265e4e0265d78ec6a76679e50a7d1f0bbcc2804fb`.
It records `kubernetes_lifecycle_sleep_no_task=true` and
`kubernetes_fixture_removed=true`.

The fixture used Kubernetes `v1.35.5` through the K3s `v1.35.5+k3s1`
distribution on x86_64 Ubuntu 24.04, kernel `6.8.0-137-generic`. It created a
real Pod with a 30-second native lifecycle `sleep` action. While the Pod was
not Ready, the live container cgroup contained only its init PID. The action
therefore created no in-container task.

The retained VM ran `kubernetes-lifecycle-sleep.sh` as root from the committed
source. The shell printed one init PID, the same single cgroup task, and
`PASS`. Postflight found no case Namespace, fixture, pin, lease, cgroup, node
process, or loaded Erebor Interceptor program. The manual harness destroyed
the VM, and `virsh list --all` was empty. The required focused tests, VM shell
checks, Clippy, and full Rust CI passed.

This completes `ENTRY-SLEEP-001`. The result proves only that the native
Kubernetes lifecycle `sleep` action creates no extra in-container task. It
does not qualify exec probes, network probes, identity purpose, role, or
policy. Other open rows keep Phase 2 **Blocked**.

## Kubernetes Network-Probe Result — 2026-08-18

Source commit `f9b7c8bc2be84f2a39f3db7b43dae3ab1914c0d0` keeps the
Kubernetes network-probe case in `IdentityTestRunner`. The schema-17 physical
JSON is
`/tmp/mithril-phase2-kubernetes-network-20260818-033/identity-physical-probe.json`.
Its SHA-256 is
`cbc024f56ce366a84aa2b0ffdbb7efaab58599b282d1f24295f30c08702fac07`.
It records true results for HTTP, TCP, and gRPC probe task absence and for
Kubernetes fixture removal.

The fixture used Kubernetes `v1.35.5` through the K3s `v1.35.5+k3s1`
distribution on the retained x86_64 Ubuntu 24.04 VM. Each readiness probe made
its container Ready without a restart. The runner resolved each live container
through CRI and sampled its cgroup every 10 ms for four seconds. Every sample
contained only the CRI-reported init PID.

The retained VM ran
`examples/mithril-identity-manual/kubernetes-network-probes.sh` as root from
the same committed source. It sampled each cgroup 400 times, printed the same
single init task for each container, and printed `PASS`. Postflight found no
case Namespace, fixture, pin, lease, cgroup, node process, or loaded Erebor
Interceptor program. The manual harness destroyed the VM, and
`virsh list --all` was empty. Focused tests, VM shell checks, Clippy, and full
Rust CI passed.

This completes `ENTRY-NETPROBE-001`. The result proves only that native HTTP,
TCP, and gRPC readiness probes create no extra in-container task. It does not
qualify network flow, application receipt, purpose, role, or policy. Other
open rows keep Phase 2 **Blocked**.

## Kubernetes Container-Identity Result — 2026-08-18

Source commit `6e23a23e327f70b3462faf932b0845f7e52ec67f` keeps the
container case in `IdentityTestRunner`. The schema-18 physical JSON is
`/tmp/mithril-phase2-kubernetes-containers-20260818-034/identity-physical-probe.json`.
Its SHA-256 is
`dfb7b407b8a945c474a210fb769abbc09b03599ecb271f4c27cb9d195da92ada`.
It records three task roots, three execution-set IDs, their distinctness, and
fixture removal.

The fixture used Kubernetes `v1.35.5` through the K3s `v1.35.5+k3s1`
distribution on the retained x86_64 Ubuntu 24.04 VM. One regular init, one
restartable init used as a native sidecar, and one application ran in the same
Pod sandbox and mounted the same host-backed volume. The roots had task cookies
`12`, `5`, and `19`, separate process states, and execution-set IDs ending in
`01`, `02`, and `03`. Late discovery correctly assigned
`restored_or_unknown_root` and `fail_closed_unknown` to each root.

The retained VM ran
`examples/mithril-identity-manual/kubernetes-containers.sh` as root from the
same committed source. It printed the same three task cookies and execution-
set IDs, then printed `PASS`. Postflight found no case Namespace, fixture, pin,
lease, cgroup, node process, or loaded Erebor Interceptor program. The manual
harness destroyed the VM, and `virsh list --all` was empty. Focused tests, VM
shell checks, Clippy, and the final full Rust CI run passed.

This completes `ENTRY-CONTAINERS-001`. The result proves only separate root and
execution-set identity for the three container kinds in one Pod. It does not
qualify their shared-network or shared-volume relationships or policy. Other
open rows keep Phase 2 **Blocked**.

## Kubernetes Ephemeral-Identity Result — 2026-08-18

Source commit `76d0145c2ecd7991ab7160773faf452c383df6a9` keeps the
ephemeral-container case in `IdentityTestRunner`. The schema-19 physical JSON
is
`/tmp/mithril-phase2-kubernetes-ephemeral-20260818-035/identity-physical-probe.json`.
Its SHA-256 is
`ee12bc57c8431ac801ae6e06e2e55dbf75ec50692b3a594785fc0d27fabf0efc`.
It records the target and ephemeral task roots, one shared PID-namespace
result, distinct execution-set and profile results, and fixture removal.

The fixture used Kubernetes `v1.35.5` through the K3s `v1.35.5+k3s1`
distribution on the retained x86_64 Ubuntu 24.04 VM. It patched the real Pod
`ephemeralcontainers` subresource and retained the exact
`targetContainerName: application` field. The application and debugger used
the same Pod sandbox and PID-namespace inode. They used separate container
cgroups, task cookies `5` and `12`, process states, execution-set IDs ending in
`01` and `02`, and profile generation references `7` and `8`. Late discovery
correctly assigned `restored_or_unknown_root` and `fail_closed_unknown` to
both roots.

The retained VM ran
`examples/mithril-identity-manual/kubernetes-ephemeral.sh` as root from the
same source bytes. It printed both task, execution-set, and profile identities,
the shared PID-namespace inode `4026532733`, and `PASS`. Postflight found only
the four baseline Kubernetes Namespaces. It found no case fixture, manual work
directory, pin, lease, cgroup, node process, or loaded Erebor Interceptor
program. The manual harness destroyed the VM, and `virsh list --all` was empty.
Focused tests, VM shell checks, Clippy, and the final full Rust CI run passed.

This completes `ENTRY-EPHEMERAL-001`. The exact limit is independent root,
process, execution-set, and profile identity for a targeted ephemeral
container that shares the application PID namespace. It does not qualify
shared-namespace relationships or policy. Other open rows keep Phase 2
**Blocked**.

## Kubernetes Exec-Probe Identity Result — 2026-08-18

Source commit `4ca2d26bd90ad6a9cd85b7fe5e9e615a6ea4fa14` keeps the
combined case in `IdentityTestRunner`. The schema-20 physical JSON is
`/tmp/mithril-phase2-kubernetes-probes-20260818-042/identity-physical-probe.json`.
Its SHA-256 is
`abead9ce84882d9ecc69853a417ef39ccd629f0df7de97e4ac0e5eebfd9190a6`.

One Kubernetes Pod used separate containers so startup, readiness, and
liveness exec probes could be live at the same time. Kubernetes does not run
readiness or liveness probes in one container until its startup probe succeeds.
Each stock probe, ordinary `kubectl exec`, and direct CRI exec ran identical
`/bin/sh -c` command bytes and became a distinct `external_runtime_root` with
`runtime_external_restricted` and role `11`. The application child ran the
same command during that interval. It kept creator and real-parent task cookie
`26`, the application execution set, inherited role `11`, and no root or
installed-role class. All seven recorded task and process identities were
distinct.

The retained VM ran
`examples/mithril-identity-manual/kubernetes-probe-impersonation.sh` as root.
It printed `PASS`. Postflight found only the four baseline Kubernetes
Namespaces. It found no case fixture, manual work directory, pin, lease,
cgroup, node process, or loaded Erebor Interceptor program. The manual harness
destroyed the VM, and `virsh list --all --name` was empty. Focused tests, shell
checks, Clippy, and `bash .github/scripts/verify-rust-ci.sh` passed.

This completes `ENTRY-PROBE-001`, `ENTRY-PROBE-002`, and
`ENTRY-PROBE-IMPERSONATION-003`. The exact limit is one held invocation of
each entry source in one concurrent interval. Stock Kubernetes supplied no
purpose, so no probe role is claimed. Approved-role transition belongs to
Phase 4. Other open rows keep Phase 2 **Blocked**.

## Kubernetes PreStop Identity Result — 2026-08-18

Source commit `098f167c88755f88acabf7f387da5095d568869d` keeps the
real PreStop case in `IdentityTestRunner`. The schema-21 physical JSON is
`/tmp/mithril-phase2-kubernetes-prestop-20260818-044/identity-physical-probe.json`.
Its SHA-256 is
`4d14142beb3671342c7c6d2c8ed8e5c9d85da730f60ef556f7783f7cd231fcee`.

The runner deleted a real Kubernetes Pod while its exec PreStop hook was held
in a FIFO. The application snapshot was unchanged before and during the hook:
task cookie `5`, process state ending in `03`, execution set ending in `01`,
and role `11`. The PreStop task had cookie `19`, a distinct process state,
`external_runtime_root`, `runtime_external_restricted`, and role `11`. The
profile had exactly two task references while both tasks were live and zero
after Pod deletion.

The retained VM ran `examples/mithril-identity-manual/kubernetes-prestop.sh`
as root. It printed both task identities and `PASS`. Postflight found only the
four baseline Kubernetes Namespaces. It found no case fixture, manual work
directory, pin, lease, cgroup, node process, or loaded Erebor Interceptor
program. The manual harness destroyed the VM, and `virsh list --all --name`
was empty. Focused tests, shell checks, Clippy, and the final full Rust CI run
passed.

This completes `ENTRY-PRESTOP-001`. The exact limit is task identity and
profile-reference retention during a real PreStop exec. Phase 4 owns
containment and effect policy. Other open rows keep Phase 2 **Blocked**.

## Kubernetes Prestart And PostStart Result — 2026-08-18

Source commit `a056f00fd7d110cc0582b6e8a476de1d1e233a59` uses the
existing runtime-binding and identity owners. A synchronous OCI prestart hook
holds each real init task. Mithril verifies the full container ID, Created
state, cgroup, sole PID, Pod UID, sandbox, container name, image digest, and
container generation before it publishes and activates the initial root.

The retained VM ran a fresh native base and the full Kubernetes extension with
object SHA-256
`02408c371aafaeeb044cbf11195a25dca35013bcdea44e37aa0756ebd2f2f3e6`.
The schema-22 physical JSON is
`/tmp/mithril-phase2-kubernetes-poststart-20260818-049/identity-physical-probe.json`.
Its SHA-256 is
`f7b1c44d26ad5c3b36b401d5f80e87156594dd790daf965fc65c58760e4e0dcb`.

Real Kubernetes PostStart hooks ran before and after the application
entrypoint. The two applications had task cookies `5` and `59`, initial-root
class, and initial role `10`. Their hooks had task cookies `150` and `218`,
restricted-external class, and role `11`. Every task and process identity was
distinct.

The restart application kept task cookie `108` and an identical snapshot.
The first real hook had task cookie `269`. The repeated exact CRI delivery had
task cookie `381`. Their process identities differed, and both used the same
restricted external role.

The retained VM ran
`examples/mithril-identity-manual/kubernetes-poststart.sh` as root. It printed
both observed orders, the two repeated-hook cookies, and `PASS`. Postflight
found no case Namespace, RuntimeClass, fixture, prestart request, pin, lease,
cgroup, node process, or loaded program. Full Rust CI passed.

This completes `ENTRY-POSTSTART-001` and the Mithril identity oracle in
`ENTRY-POSTSTART-002`. K3s did not automatically resend the in-flight hook.
Kubernetes permits duplicate delivery but does not guarantee deterministic
resend after this restart. The fixture repeats the live Pod's exact hook
command through CRI and makes no automatic kubelet replay claim. Hook failure
injection remains open. Other open rows keep Phase 2 **Blocked**.

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

The historical optional Kubernetes lane through the K3s distribution passed.
It recorded Pod readiness, CRI discovery,
the workload root, overlay storage, and a projected token. Its record SHA-256
is `905a3ad84106e975cc1cde8b68cb24c861079f8baf3b616c597ec14e234f2503`.
This historical lane proves the Kubernetes substrate only. It does not
configure or prove a Mithril CRI binding.

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

The checked qualification registry now contains the digest-bound 133 Appendix
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
process, lease, or cgroup. This historical result qualified the namespace-entry
and cgroup-move subcase of `ENTRY-MIGRATE-001`. It did not cover movement of an
already labeled task. The current recheck below completes the Phase 2 identity
scope.

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
`ENTRY-MIGRATE-001`. The current recheck below combines this result with the
namespace-only and cgroup-move result.

## Current Entry-Migration VM Recheck — 2026-08-17

At source commit `ff129206ca610689c68b1de475b982f6e86ea97e`, a retained
x86_64 Ubuntu 24.04 VM, kernel `6.8.0-137-generic`, ran these root-shell
commands:

```sh
examples/mithril-identity-manual/nsenter-move.sh
examples/mithril-identity-manual/nsenter-move.sh --labeled-task
```

The current shell SHA-256 was
`6cda64a4e3c62e61ee24f05f301e6ff627e722d9f4525d601434ea4c0f12cbcd`.
The first command printed `PASS` after it proved that namespace entry gave the
`sleep 300` child no task identity and cgroup movement gave it the restricted
external-root identity. The final record had task cookie `12`, no creator,
active role `2`, and coordinate state `3` (`Runnable`).

The labeled command printed `PASS`. Its child kept task cookie `18`, creator
and real-parent task cookie `12`, process state
`00000000000000010000000000000016`, and active role `2`. Its execution ID
changed from `00000000000000010000000000000013` to
`0000000000000001000000000000001c`. Its image ID changed from
`00000000000000010000000000000011` to
`0000000000000001000000000000001d`. The final child was runnable, both
process records were active, and its exec guard was none.

The disposable automated VM probe used the same source state before this
commit. Its schema-13 JSON was
`/tmp/mithril-phase2-registry-refresh-20260817-2130/identity-physical-probe.json`,
SHA-256 `54f7a3a61d3831fabefbf1ccce14f4f72704684b454f9e90423a5a77f95a0911`.
`CloneIntoCgroupFixture` recorded restricted external root task cookie `33` and
native-child task cookie `36`. The child kept its task, creator, parent, and
process IDs across mount-namespace entry. It changed execution and image IDs.
The JSON records `pin_root_removed=true`, `lease_removed=true`,
`cgroup_removed=true`, and `profile_task_refs_after_exit=0`.

Manual postflight found no case namespace, fixture directory, Mithril pin,
node process, lease or work directory, or identifiable manual cgroup. The
harness then removed the retained VM and `virsh list --all` was empty. These
results complete the Phase 2 identity scope of `ENTRY-MIGRATE-001`. Phase 4
owns protected effects. Phase 12 owns checkpoint restore through
`ENTRY-RESTORE-001`. Neither later result is a Phase 2 closure gate.

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

The shell created its Kubernetes Pod and live CRI binding through
`identity_prepare_k3s_case`. The VM used the K3s distribution. The shell
printed `PASS`. It checked the same immutable
creator, real-parent coordinate, execution, image, role, and active-state
limits. Postflight found no case namespace, fixture directory, Mithril pin,
node process, lease, or cgroup. The JSON records
`pin_root_removed=true`, `lease_removed=true`, `cgroup_removed=true`, and
`profile_task_refs_after_exit=0`.

This qualifies the subreaper reparenting subcase of
`ID-CREATOR-PARENT-007` only. Namespace-init, ptrace reparenting, and PID reuse
remain required. The phase remains **Blocked**.

## PID-Namespace-Init Reparenting Qualification — 2026-08-17

Source commit `6b1cf72` adds this subcase to the existing
`NativeProcessFixture` and `IdentityTestRunner`. It adds no runner, role, or
durable map. The retained x86_64 Ubuntu 24.04 VM ran kernel
`6.8.0-137-generic` and this command with unique paths:

```sh
"$MITHRIL_BIN_DIRECTORY/mithril-identity-test" \
  --repo-root "$MITHRIL_MANUAL_SOURCE" \
  --output-directory /tmp/mithril-phase2-namespace-init-20260817-1630 \
  physical-probe \
  --pin-root /sys/fs/bpf/erebor-mithril-phase2-namespace-init-20260817-1630 \
  --lease-path /tmp/mithril-phase2-namespace-init-20260817-1630/owner.lock \
  --cgroup-path /sys/fs/cgroup/erebor-mithril-phase2-namespace-init-20260817-1630
```

The schema-9 JSON is
`/tmp/mithril-phase2-namespace-init-20260817-1630/identity-physical-probe.json`.
Its SHA-256 is
`c4fac47027dd4d2e46b50ecb8fcd8fd2716d798db1347cc73b6317ef1b06a624`.
The test binary SHA-256 is
`eb8e7e591b3a5dc379bc9e4428904f6edff65d316096852ebf16e7b7d6ff348d`.
The `identity.rs` source SHA-256 is
`604be2b2f62c1ca5687dfccc0c4f1999939cfa69be93fe57a27f3e1e09ede993`.
The BPF object SHA-256 is
`69ee79417f875f7c7a7065d18e08918e9d9bc32359711b57013eba77879fbcbe`.

The fixture created and stopped a user and PID namespace before it entered the
configured cgroup. The moved namespace init had host TID and TGID `3488`, task
cookie `146`, and namespace PID `1`. It was an `external_runtime_root` with
`runtime_external_restricted` and active role `11`. Its native intermediate
had task cookie `149`, creator and real-parent cookie `146`, and parent TID and
TGID `3488`. The stopped native child had task cookie `155`, creator and
real-parent cookie `149`, parent TID and TGID `3489`, and parent interval `1`.

After the runner terminated the intermediate, the child had the same task
cookie `155`, creator cookie `149`, process state
`0000000000000001000000000000009f`, and active role `11`. Its real-parent
cookie was `0`. Its real-parent TID and TGID were `3488`. Its parent interval
was `2`. Its execution changed from
`0000000000000001000000000000009c` to
`000000000000000100000000000000a2`. Its image changed from
`00000000000000010000000000000094` to
`000000000000000100000000000000a3`. Its coordinate was `Runnable`; both
process records were active; and its exec guard was none.

The same VM ran this readable root-shell command:

```sh
examples/mithril-identity-manual/native-child.sh --namespace-init
```

The shell calls `identity_prepare_k3s_case`. It creates the Pod and CRI
binding. It starts and stops the namespace outside the Pod cgroup. It moves
only PID 1 into that cgroup before it creates its native children. The shell
printed `PASS`. Postflight found no case namespace, fixture directory, Mithril
pin, node process, lease, cgroup, or manual work directory.

`cargo test -p mithril-e2e native_process_fixture --all-features -- --nocapture`
passed all nine native fixture tests. `bash -n` passed for the manual shell.
The required `bash .github/scripts/verify-rust-ci.sh` ran twice. The second run
passed the unrelated browser-CDP test that first reported a resource error. It
then reached the Mithril e2e suite and stopped with 58 tests passed and four
tests failed. Each failure reports the pre-existing mismatch between the
current readable-architecture digest and the digest in
`spec/qualification/v1/fixtures.yaml`. This source record does not change that
user-owned registry.
This qualifies the PID-namespace-init reparenting subcase of
`ID-CREATOR-PARENT-007`. Ptrace reparenting and PID reuse remain required. The
phase remains **Blocked**.

## Live-Binding-Gap Qualification — 2026-08-17

Source commit `e3962e8` adds a bounded live-task reconciliation path. It uses
the existing `task_labels` task-local map. `WorkloadBindingOwner` reads the
target cgroup's live process leaders, opens a pidfd for each leader, and
inserts a zero label with `BPF_NOEXIST` while the binding is preparing. The
iterator recognizes only a fully zero label as uninitialized. It then creates
the existing `restored_or_unknown_root` with the existing
`fail_closed_unknown` role. A task that acts before the iterator completes has
an invalid label and does not receive authority.

The retained x86_64 Ubuntu 24.04 VM ran Linux `6.8.0-137-generic` and this
command with unique paths:

```sh
"$MITHRIL_BIN_DIRECTORY/mithril-identity-test" \
  --repo-root "$MITHRIL_MANUAL_SOURCE" \
  --output-directory /var/tmp/mithril-phase2-binding-1786986448 \
  physical-probe \
  --pin-root /sys/fs/bpf/mithril-phase2-binding-1786986448 \
  --lease-path /run/mithril-phase2-binding-1786986448.lock \
  --cgroup-path /sys/fs/cgroup/mithril-phase2-binding-1786986448
```

The schema-10 JSON SHA-256 is
`aec5e501424d0347c2b2c38d236ddd35a754051d20a1f8283fc2d8af1d744fdf`.
The test binary SHA-256 is
`f10a021dc4f597ca408e6627fe840928cef172c86b64b52917e683648592e123`.
The BPF object SHA-256 is
`3269516fcd2714ab7fbe29df26386c40f0c912b6284007b641d8bbf68842b876`.
The pre-binding root had task cookie `5`, no creator task cookie,
`restored_or_unknown_root`, `fail_closed_unknown`, role `11`, and coordinate
state `3`. Its reconciliation report had zero allocation, coordinate, and
reconciliation failures. The later cgroup-entry control remained the normal
restricted external root. The JSON records that the dedicated pin root, lease,
and cgroup were removed.

The same retained VM ran
[`binding-gap.sh`](../../../../examples/mithril-identity-manual/binding-gap.sh).
It printed `PASS` and verified that its exact Pod cgroup was removed. The
postflight found no case namespace, fixture directory, Mithril pin, node
process, lease work directory, or manual work directory.

This qualifies `ENTRY-BINDING-GAP-001` only. The remaining required fixtures
are open. The phase remains **Blocked**.

## External-Root-Ambiguity Qualification — 2026-08-17

Source commit `e0e2af9` extends `IdentityTestRunner` and the existing physical
bundle. It starts two independent `NativeProcessFixture` roots, moves both
into one active binding, and requires different task cookies and process-state
IDs. Both roots must have no creator, `external_runtime_root`,
`runtime_external_restricted`, the configured external role, and `Runnable`
coordinates. It adds no map, role, runner, or durable type.

The retained x86_64 Ubuntu 24.04 VM ran Linux `6.8.0-137-generic` and this
command with unique paths:

```sh
"$MITHRIL_BIN_DIRECTORY/mithril-identity-test" \
  --repo-root "$MITHRIL_MANUAL_SOURCE" \
  --output-directory /var/tmp/mithril-phase2-ambiguity-1786987689 \
  physical-probe \
  --pin-root /sys/fs/bpf/mithril-phase2-ambiguity-1786987689 \
  --lease-path /run/mithril-phase2-ambiguity-1786987689.lock \
  --cgroup-path /sys/fs/cgroup/mithril-phase2-ambiguity-1786987689
```

The schema-11 JSON SHA-256 is
`e259bb5f298d2ebcd0a0179176781e88925fef382ddb0f5a153410cb343167cf`.
The test binary SHA-256 is
`678b8e0ff7c70c50e46e36cc5d795dc8df4b4d55632de3a143520868f206f15c`.
The BPF object SHA-256 is
`3269516fcd2714ab7fbe29df26386c40f0c912b6284007b641d8bbf68842b876`.
The first root had task cookie `12`, process state
`0000000000000001000000000000000a`, and role `11`. The second had task cookie
`19`, process state `00000000000000010000000000000011`, and role `11`. Both
had no creator, `external_runtime_root`, `runtime_external_restricted`, and
coordinate state `3`. The JSON records equal restricted roles and removed pin,
lease, and cgroup paths.

The same retained VM ran
[`external-ambiguity.sh`](../../../../examples/mithril-identity-manual/external-ambiguity.sh)
as root. It printed `PASS` and verified that its exact Pod cgroup was removed.
Postflight found no case namespace, fixture directory, Mithril pin, node
process, lease work directory, or manual work directory.

This qualifies `ENTRY-EXTERNAL-AMBIGUITY-001` only. The remaining required
fixtures are open. The phase remains **Blocked**.

## Cgroup-Escape Qualification — 2026-08-17

Source commit `c5b2147b537fa411978f7a9c9533de5eab1f7a4f` extends the existing
`CloneIntoCgroupFixture` and physical bundle. The fixture stops a root before
its direct `open(2)` of a sentinel. It first requires an unmoved restricted
external root to open the sentinel. It then moves a second root to the
unprotected cgroup, requires its fail-closed coordinate, and requires the
same direct open to exit with `EACCES`. It adds no map, role, runner, or
durable type.

The retained x86_64 Ubuntu 24.04 VM ran Linux `6.8.0-137-generic` with these
unique paths:

```sh
"$MITHRIL_BIN_DIRECTORY/mithril-identity-test" \
  --repo-root "$MITHRIL_MANUAL_SOURCE" \
  --output-directory /var/tmp/mithril-phase2-cgroup-escape-20260817-1450 \
  physical-probe \
  --pin-root /sys/fs/bpf/mithril-phase2-cgroup-escape-20260817-1450 \
  --lease-path /run/mithril-phase2-cgroup-escape-20260817-1450.lock \
  --cgroup-path /sys/fs/cgroup/mithril-phase2-cgroup-escape-20260817-1450
```

The schema-12 JSON SHA-256 is
`c0605bf353ec6c67c906ae3f34fc872254c509e08ab16daebe6cfeceac50c460`.
The test binary SHA-256 is
`6d2fb16531e072255d720339ca650f0f3bb3847aac6edeaadc60a18b59c4a0be`.
The BPF object SHA-256 is
`3269516fcd2714ab7fbe29df26386c40f0c912b6284007b641d8bbf68842b876`.
The unmoved control had task cookie `214`, process state
`000000000000000100000000000000d4`, role `11`, and coordinate state `3`.
The moved root had task cookie `221`, process state
`000000000000000100000000000000db`, role `11`, and coordinate state `6`.
Both had no creator, `external_runtime_root`, and
`runtime_external_restricted`. The JSON records an allowed unmoved first
effect, a placement mismatch, a denied moved first effect, removed pin, lease,
and cgroup paths, and `profile_task_refs_after_exit=0`.

The same retained VM ran
[`cgroup-escape.sh`](../../../../examples/mithril-identity-manual/cgroup-escape.sh)
as root. The shell used `identity_prepare_k3s_case`, checked the configured
external role and runnable coordinate before the move, then checked the same
task cookie, process state, role, and fail-closed coordinate after the move.
It printed `PASS` only when the unmoved open succeeded and the moved open
returned `EACCES`. Postflight found no case namespace, fixture directory,
Mithril pin, node process, lease work directory, manual work directory, or
case cgroup.

This qualifies `ID-CGROUP-ESCAPE-001` only. The remaining required fixtures
are open. The phase remains **Blocked**.

## Clone-Into-Cgroup Native-Child First-Effect Qualification — 2026-08-17

Source commit `bae628d` extends the existing `CloneIntoCgroupFixture`. It
stops the native child after `fork`, before the child has an effect. The
existing `IdentityTestRunner` inspects the clone root and stopped child, then
releases the child by pidfd. The child makes one direct sentinel `open(2)` and
writes its one-byte result to the fixture-owned status pipe. Source commit
`4b4d669` adds bounded stderr to an existing stopped-child failure report. It
does not change identity, permission, or fixture ownership.

The retained x86_64 Ubuntu 24.04 VM ran Linux `6.8.0-137-generic` and this
root command with unique paths:

```sh
/mnt/mithril-source/target/debug/mithril-identity-test \
  --repo-root /mnt/mithril-source \
  --output-directory /var/tmp/mithril-phase2-clone-first-effect-20260817-1706 \
  physical-probe \
  --pin-root /sys/fs/bpf/mithril-phase2-clone-first-effect-20260817-1706 \
  --lease-path /run/mithril-phase2-clone-first-effect-20260817-1706.lock \
  --cgroup-path /sys/fs/cgroup/mithril-phase2-clone-first-effect-20260817-1706
```

The copied schema-13 JSON is
`/tmp/mithril-phase2-clone-first-effect-20260817-1706.json`. Its SHA-256 is
`d690be264034dad636dd64e97e4830ae24b0a11f0ed5077dc525da303069fd44`.
The test binary SHA-256 is
`fdf84da58ad0f1ad150dfc184015b2b5ab1415cee1b00c601db3a77900a8adf6`.
The BPF object SHA-256 is
`3269516fcd2714ab7fbe29df26386c40f0c912b6284007b641d8bbf68842b876`.

The stopped clone root had task cookie `228`, process state
`000000000000000100000000000000e2`, no creator, role `11`,
`external_runtime_root`, `runtime_external_restricted`, and coordinate `3`.
The stopped native child had task cookie `231`, process state
`000000000000000100000000000000eb`, creator and real-parent cookie `228`,
role `11`, no root or installed-role class, coordinate `3`, and active process
records. `clone_into_cgroup_native_child_first_effect_allowed=true` records
the child sentinel open. The JSON also records
`profile_task_refs_after_exit=0`, `pin_root_removed=true`,
`lease_removed=true`, and `cgroup_removed=true`. Postflight found no case
namespace, fixture, Mithril pin, node process, lease, or cgroup.

No manual shell is valid for this case. The fixture alone owns the exact
`CLONE_INTO_CGROUP` file descriptor, stopped root and child, pidfd release,
and status pipe. A second shell or runner could not reproduce that controlled
first-effect boundary without violating fixture ownership.

This qualifies `ID-CLONE-CGROUP-002` only. The required repository check ran
after the source changes: 58 tests passed and four registry tests failed only
because the user-owned `spec/qualification/v1/fixtures.yaml` architecture
revision digest does not match its validated document. The remaining required
fixtures are open. The phase remains **Blocked**.
