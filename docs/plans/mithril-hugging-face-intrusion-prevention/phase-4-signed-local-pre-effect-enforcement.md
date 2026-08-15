# Phase 4: Signed Local Pre-Effect Enforcement

Status: Not done. The source has signed exact-file, exec, device-ioctl,
denial-only process-control, unmatched Unix-stream, bounded-exception, and
hard-close slices. The current source passed the disposable privileged VM
enforcement probe. The complete policy-aware local surface remains incomplete.

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
Completed deliverable IDs: D4.1 is partial: generation staging, readback, active selection, and per-binding expected-value recheck exist, but controlled activation probes, one all-binding atomic switch, and complete retirement do not. D4.2 is partial for exact exec variants and qualified file-backed executable mappings; immutable provenance, script and binfmt chains, loader state, pkey transitions, and complete VMA state remain incomplete. D4.3 is partial for exact files, represented aliases, mutations, and DIRTY mount handling; rotation, overlay copy-up, persistent objects, delegated I/O, and propagation remain incomplete. D4.4 is partial for denial-only process-control and unmatched Unix-stream decisions; positive exact relationships remain rejected. D4.5 is partial for exact device ioctl and hard-close floors; derived devices, complete privilege authority, and self-protection remain incomplete. D4.6 has stable exception-instance, receipt, and WAL ownership, but the administrative ingress and end-to-end administrative-exec proof remain incomplete. D4.7 is complete as `ABSENT`: the node reports `LANDLOCK_TARGET_CONTEXT_FLOOR=ABSENT` with reason `NO_QUALIFIED_TARGET_CONTEXT_INSTALL`. D4.8 is partial. The current physical record covers 24 HF local branches: 6 PREVENTED, 1 HARD_CLOSED_UNQUALIFIED, 5 NO_COVERED_EFFECT, 4 OUTSIDE_AUTHORITY, 4 DEFERRED_NETWORK, and 4 UNSUPPORTED. The complete HF local prevention matrix is not qualified.
Files and durable owners changed: mithril-control owns PROTECT compilation and exact exception binding. NodePolicyGenerationOwner owns generation staging, readback, anti-rollback, active state, and typed rule installation. ExceptionAuthorityOwner owns stable exception instances, successful-use receipts, WAL recovery, restart restoration, and reboot separation. The production BPF effect gate owns pre-effect decisions and atomic exception consumption. mithril-e2e owns the disposable physical oracle. examples/mithril-local-enforcement-manual owns operator cases.
Upstream-adoption dossier IDs used: existing Phase 0 libbpf-rs/libbpf-cargo and checked vmlinux-header decisions; no new runtime or BPF framework.
Fixture cases and exact physical results: compiler, ABI, interceptor, node, and effect suites contain source-level cases for the implemented slices. The current PROTECT record has exact_open_denied_before_effect=true, inherited_fd_read_denied=true, file_mmap_denied=true, writable_shared_mmap_denied=true, executable_mmap_denied=true, file_mprotect_exec_denied=true, and benign_read_allowed=true. execve_denied=true, execveat_denied=true, fexecve_denied=true, script_exec_denied=true, deleted_exec_denied=true, non_leader_exec_denied=true, approved_exec_allowed=true, and memfd_exec_failed_closed=true. device_ioctl_exact_allowed=true, device_ioctl_unmatched_denied=true, process_ptrace_exact_denied=true, process_signal_exact_denied=true, and unix_stream_unmatched_denied=true. bounded_exception_maximum_uses=2, bounded_exception_n_allows=true, bounded_exception_n_plus_one_denied=true, bounded_exception_expiry_denied=true, and bounded_exception_restart_preserved=true. hard_link_alias_denied=true, symlink_alias_denied=true, proc_fd_alias_denied=true, passed_fd_read_denied=true, passed_benign_fd_read_allowed=true, and bind_alias_canonicalized=true. protected_mount_race_denied=true, external_mount_replacement_failed_closed=true, and exact_object_restored_after_reconciliation=true. The hard-close fields for anonymous exec, file creation and mutation, IPC, ptrace, signal, namespace privilege, device ioctl, BPF, and self-protection are true. saturation_preserved_network_denial=true and saturation_preserved_benign_allow=true after saturation_opens=50000. pin_root_removed=true, lease_removed=true, cgroup_removed=true, and fixture_root_removed=true. The local-enforcement evidence SHA-256 is fe708e493601ab3716e724417ee26509466efb03a6bfa0d37d187b6b9f3cb72e.
Commands and exact source state covered: the disposable VM record under /tmp/mithril-vm-source18-final covers the current typed-effect and durable-exception implementation. Repository CI results are recorded separately after the final repository edit. The production BPF translation unit compiles with `-Wall -Werror` for checked x86, arm64, arm, and riscv vmlinux headers. This is compile evidence, not non-x86 physical evidence.
Platform/kernel/runtime manifests: the current probe ran on x86_64 Ubuntu kernel 6.8.0-136-generic with LSM order lockdown,capability,landlock,yama,apparmor,bpf, runtime BTF SHA-256 9aa9eb9e8108bff44e685830315fb7a442bafd99778314cdd6de0fb72868829f, cgroup v2, and unique mount IDs. The optional k3s lane recorded k3s v1.35.5+k3s1, Pod readiness, CRI endpoint unix:///run/k3s/containerd/containerd.sock, workload-root discovery, overlay storage, and projected-token discovery. Its record SHA-256 is 905a3ad84106e975cc1cde8b68cb24c861079f8baf3b616c597ec14e234f2503. This is substrate evidence only. It does not run a Mithril CRI binding or local effect decision.
Performance/capacity results: exception-definition capacity is compiler-checked at 4,096, and the successful-use receipt map is bounded at 65,536 entries. The VM record has measured_opens=10000 and saturation_opens=50000. Its BASELINE distribution has sample_count=10000, p50=6832 ns, p95=6941 ns, p99=75565 ns, maximum=480479 ns, and raw_samples_sha256=16f5b7fc870feb31bdef7fafbc0487b78da77a4c8e813ca33c93b16bcb222eec. Its PROTECT distribution has sample_count=10000, p50=6215 ns, p95=6623 ns, p99=82638 ns, maximum=568239 ns, and raw_samples_sha256=0f341d456eae547df2f6a540536c4759cf81588714f4bc12c6c8e45ceed92768. The recorded averages are baseline_average_open_ns=7990 and observed_average_open_ns=7525.
Unsupported/degraded paths: exact file, qualified exec, exact device-ioctl, denial-only process-control, unmatched Unix-stream, stable exception receipt and WAL, and explicit hard-close slices exist. Positive process-control and positive exact Unix-stream relationships remain rejected. Immutable exec provenance and complete script, binfmt, loader, pkey, and VMA handling remain incomplete. Token rotation, overlay copy-up, persistent objects, delegated I/O, propagation, derived-device authority, complete privilege authority, and self-protection remain incomplete. Landlock is an advertised `ABSENT` capability, not an unqualified implementation gap. Administrative ingress and the complete HF local matrix remain incomplete. Network remains outside this outcome.
Remaining work in this phase: complete controlled activation probes, all-binding atomic activation, and retirement; complete the remaining exec, file, IPC, process, device, derived-authority, privilege, and self-protection surfaces; finish administrative approval-to-profile resolution and physical administrative-exec proof; and run the full fixture matrix with legitimate controls. Native identity and effect observation retain their own unresolved acceptance work.
Next phase not authorized: yes.
```

## Qualification update — 2026-08-12

The current disposable VM harness completed the production-object
local-enforcement probe in `PROTECT` mode. The evidence file SHA-256 is
`fe708e493601ab3716e724417ee26509466efb03a6bfa0d37d187b6b9f3cb72e`.
The probe recorded these physical results:

- The exact open, inherited file-descriptor read, and file-backed mapping were
  denied before the named effect returned authority.
- The benign exact-file control remained allowed.
- The hard-link and bind-alias cases retained the expected object and path
  results.
- Protected and external mount-replacement races failed closed. Exact
  reconciliation restored the original object.
- A bounded exception allowed exactly two concurrent uses. Use N+1 failed.
  Expiry failed. Loader restart retained the exhausted state.
- Exact exec variants, one approved image, exact device ioctl, exact ptrace
  and signal targets, and the unmatched Unix-stream rule produced their
  recorded decisions.
- The unqualified anonymous and memfd exec, file mutation, IPC, namespace
  privilege, BPF, and link-removal probes took their explicit hard-close
  paths. These are safety floors. They are not policy-aware support claims.
- A paused reader and 50,000 opens did not change deny or benign results.
- The 10,000-sample BASELINE distribution recorded p50=6832 ns, p95=6941 ns,
  p99=75565 ns, and maximum=480479 ns.
- The 10,000-sample PROTECT distribution recorded p50=6215 ns, p95=6623 ns,
  p99=82638 ns, and maximum=568239 ns.
- The cleanup fields for the fixture root, pin root, lease file, and cgroup are
  true.

An earlier real Docker exact-file manual case also passed. The protected process
received `EACCES` before it obtained the secret file descriptor or bytes. The
shell removed all Mithril-owned artifacts.

The optional k3s lane passed Pod readiness, CRI discovery, workload-root
discovery, overlay storage, and projected-token discovery. Its record SHA-256
is `905a3ad84106e975cc1cde8b68cb24c861079f8baf3b616c597ec14e234f2503`.
It proves the runtime substrate only. It does not prove a Mithril CRI binding
or local effect decision.

The state stays **Not done**. Controlled activation and retirement, complete
exec provenance, rotation and persistence, positive relationship models,
derived authority, privilege and self-protection, administrative ingress, and
the complete HF local matrix remain incomplete. Landlock is complete as an
explicit `ABSENT` capability.

## Qualification update — 2026-08-15

At source commit `e9b380a`, the production effect probe passed in `PROTECT`
mode on x86_64 Linux `6.8.0-137-generic`. The evidence file SHA-256 is
`74dec05c7984076a908db509733b078492407a145298fee684e20ed1ef9cc8c6`.
It recorded `exact_open_denied_before_effect=true`,
`inherited_fd_read_denied=true`, `passed_fd_read_denied=true`, and
`io_uring_secret_read_denied_before_effect=true`. It also recorded successful
mount propagation and mount-attribute reconciliation, failed-closed external
replacement, exact-object recovery, and complete fixture cleanup.

The retained Kubernetes administrative-exec lane has a separate blocker. Its
Control draft, admission, and slot-arm steps complete. Stock runc `1.4.2`
then fails closed before the target exec. The retained observation records
`EXECUTE` and `FILE WRITE` `UNSUPPORTED_OBJECT` results with `EACCES`, and the
approved slot remains armed. runc uses a sealed self-clone and inherited
bootstrap channels that the exact-object and typed-channel models do not
authorize. A broad runc or pipe exception would expand authority. Supporting
this runtime requires this short-lived, signed lease:

```text
approved exec for container C and command X
  -> runc bootstrap lease for C, short expiry
  -> runc may complete normal setup inside C
  -> exact handover to X
  -> lease ends; X gets the approved role
```

The lease cannot start another container or a later exec. If runc does not
start X before it ends, no task gets the approved role. This design trusts runc
only for this short setup period. The current implementation does not support
this path.

The phase remains **Not done**. The passed probe qualifies the implemented
local slice only. It does not complete the administrative runtime protocol or
the remaining policy-aware local matrix.

## Qualification update — 2026-08-15 — K3s CRI paired control

At source commit `bf0e606`, a fresh disposable x86_64 Linux
`6.8.0-137-generic` VM ran the production K3s CRI lane against one bound
container. The lane used a real `crictl exec` root and a real `kubectl exec`
root. Both roots were `external_runtime_root` with the
`runtime_external_restricted` role.

The lane used two exact read-only hostPath files in the same `kubectl exec`
task. In `OBSERVE` mode, secret object key 7 completed its open and recorded
`WOULD_DENY` with `UNKNOWN_AFTER_PRE_EFFECT`. Benign object key 8 completed
its open and recorded `EXACT_POLICY_ALLOW` with
`UNKNOWN_AFTER_PRE_EFFECT`. The observe evidence SHA-256 is
`16d72808d4dbaec218522a8432c18f50ae495cb655784223b537f0f08c5a695b`.

In `PROTECT` mode, secret object key 7 recorded `EXACT_POLICY_DENY`,
`DENIED_BEFORE_EFFECT`, and kernel result `-13`. The same task opened benign
object key 8 and recorded `EXACT_POLICY_ALLOW` with kernel result `0`. The
protect evidence SHA-256 is
`12195030548676e93f71ce836d3ebf12999bc267195be6aebd8cb5cb6748ee94`.

The combined VM command later failed in the separate native-identity probe.
It did not invalidate the completed CRI artifacts. This is one K3s
policy-aware deny and legitimate-control result. It does not qualify rotating
projected tokens, the administrative runc bootstrap path, or the remaining
Phase 4 matrix. The phase remains **Not done**.
