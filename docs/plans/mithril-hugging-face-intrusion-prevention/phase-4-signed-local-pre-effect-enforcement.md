# Phase 4: Signed Local Pre-Effect Enforcement

Status: Done for the limited x86_64 local-enforcement claim. The protected
result has 14 Appendix C `PASS` results, 14 exact `UNSUPPORTED` results, and
one additional `PASS` result for the plan-owned path-tree fixture. An
unsupported surface is not part of the advertised claim.

Master: [Mithril Hugging Face Intrusion Prevention](./README.md)
Design: [Validated readable architecture](./policy-and-protection-algorithm-architecture-readable.md)
Manual acceptance: [Phase 4 runbook](./manual-testing/phase-4-manual-acceptance.md)  
Closure matrix: [Phase 4 closure matrix](./phase-4-closure-matrix.md)  
Environment setup: [shared setup guide](./manual-testing/environment-setup.md)
Implementation review: [local pre-effect enforcement](./phase-4-implementation-review.md)

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
matching remains an exact-object candidate for a positive decision.

Add signed recursive path-tree `DENY` floors. A rule can protect a canonical
path such as `/tmp/secret-dir/**` and deny its covered effects for every
current, new, or replaced child. The terminal decision uses the clean canonical
path and mount view. It does not require the child inode or inode generation.
Apply it before exact-object lookup. Check every affected parent/name path for
create, rename, link, and other name-changing operations before visibility.
Reject a path-tree `ALLOW`, allow exception, or another positive disposition.
Exact object identity remains required for positive file authority and for
file-instance provenance.

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
the capability as unsupported because the target-context path is absent.
Local BPF enforcement and this phase's release result cannot depend on an
unavailable Landlock path.

### D4.8 — HF local prevention increment

For each managed/local non-network branch of `HF-002` through `HF-012`,
identify and deny the first distinguishable forbidden effect, prove it did not
complete, and prove the legitimate same-deployment control still succeeds.
Use the safe in-process post-compromise driver from the normative acceptance
contract. It does not need to weaponize HDF5 or Jinja. Pure in-memory and
outside-authority branches retain their honest result rather than a fabricated
denial.

## Checkpoint

Every qualified non-network local effect has a signed task-first decision and
physical positive/negative oracle, including bounded exception consumption and
the complete `HF-008` block. Network destinations and distributed conclusions
remain outside the checkpoint.

## Required Tests And Fixtures

- `ADMIN-EXEC-APPROVAL-001`, `DEVICE-DERIVED-001`,
  `FILE-CONTENT-RACE-002`, `FILE-FD-PASS-001`, `FILE-IDENTITY-001`,
  `FILE-MMAP-001`, `FILE-MMAP-SHARED-011`, `FILE-NAMESPACE-001`,
  `FILE-PATH-TREE-DENY-001`, `FILE-SA-TOKEN-OPEN-001`, and
  `FILE-VMA-SNAPSHOT-001`.
- `MEM-EXEC-001`, `MEM-KERNEL-MAP-002`, `MOUNT-ATTR-001`,
  `MOUNT-CAS-002`, `MOUNT-PROPAGATION-003`, and `MOUNT-SNAPSHOT-004`.
- `EXEC-CONCURRENT-002`, `IPC-ASYNC-UNSUPPORTED-010`, `IPC-PEER-RACE-004`,
  `IPC-PROCESS-CHANNEL-009`, `IPC-RELATIONSHIP-ALLOW-003`,
  `IPC-RELATIONSHIP-UNMATCHED-005`, `STATE-FORK-IPC-002`, and
  `STATE-PERSISTENT-FILE-LIFETIME-007`, and `STATE-THREAD-RACE-001`.
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
- A signed path-tree denial protects each covered current, new, or replaced
  file under the canonical tree without a child inode binding. A path-only
  rule cannot allow a file effect.
- Exceptions cannot exceed `maximum_uses` or be consumed by unrelated entries.
- Each advertised worker, controller, probe, lifecycle, or administrative
  control remains functional.

## Excluded

Destination-aware network enforcement, durable distributed evidence, graph
correlation, and response coordination.

## Phase Result

```text
State: Done for the limited x86_64 local-enforcement claim.
Last implementation-validated architecture revision/digest: policy-and-protection-algorithm-architecture-readable.md sha256 22678b9c0379ff915fe595059f3da2789c3e32cdf54d61656c7257175263d14a.
Completed deliverable IDs: D4.1 through D4.8 close as capability results. Fifteen qualified fixture outcomes have physical `PASS` results. Fourteen unqualified fixture outcomes have exact `UNSUPPORTED` results and are not advertised.
Files and durable owners changed: mithril-control owns PROTECT compilation and exact exception binding. NodePolicyGenerationOwner owns generation staging, readback, anti-rollback, publication, and retirement. ExceptionAuthorityOwner owns stable exception instances, receipts, WAL recovery, restart restoration, and reboot separation. The production BPF effect gate owns pre-effect decisions and atomic exception consumption. mithril-e2e owns the physical oracle and typed fixture results.
Upstream-adoption dossier IDs used: existing Phase 0 libbpf-rs, libbpf-cargo, and checked vmlinux-header decisions. No new runtime or BPF framework was added.
Fixture cases and exact physical results: the protected result has 15 `PASS`, 14 `UNSUPPORTED`, zero `FAIL`, and zero `DEGRADED` fixture results. The 15 passes include the 14 allocated Appendix C fixtures and `FILE-PATH-TREE-DENY-001`. The exact table and reason codes are in phase-4-closure-matrix.md.
Commands and exact source state covered: bash .github/scripts/verify-rust-ci.sh passed at implementation commit e0438d920d5071295ab733db0d7df0eb03a95b8c. The explicitly rebuilt mithril-effect-test binary SHA-256 is eee25b63425be5ec7ba8d7b9f8510cabea8c1b1af6aa832c90e1181373245fd0. The physical result is /tmp/mithril-phase4-e0438d9-final/local-enforcement-physical-probe.json with SHA-256 8fc1f4ad4536d00afd29754255410fed4b1290c3a138687f51c70edac079c793.
Platform/kernel/runtime manifests: x86_64 Linux 6.8.0-137-generic, cgroup v2, BPF LSM, active LSM order lockdown,capability,landlock,yama,apparmor,bpf, and runtime BTF SHA-256 6da9f6b4ebcae9b07e6a717b517884abf7f6b524e46340e40fb164eed4a49a7c. No non-x86 physical claim is made.
Performance/capacity results: the physical result has 10,000 measured opens and 50,000 saturation opens. It lost 39,081 observation records under saturation while the protected denial and benign allow remained correct. All four cleanup fields are true.
Unsupported/degraded paths: administrative exec, immutable executable and file-content proof, complete mm/VMA state, overlay copy-up provenance, projected-token rotation and controller binding, complete mount variants and propagation, persistent file-instance lifetime, protected exec and role races, and complete local self-protection remain unsupported. Landlock target-context installation is unsupported with reason NO_QUALIFIED_TARGET_CONTEXT_INSTALL. Network and distributed results remain outside this outcome.
Remaining work in this phase: none inside the limited claim. A missing hook, field, identity, or authority model must return to the prototype and type-closure gate before a later authorized plan can advertise it. The stock-runc administrative bootstrap also needs an architecture decision.
Next phase not authorized: yes.
```

## Path-tree protection design update — 2026-08-17

State: Not done. This is a design requirement. It is not implementation or
physical-test evidence.

Architecture source digest after this design update:
`f62e7e0075bbbfae142034fe421bf9fe4dbfd950b265acfc0536d786d2dcfca4`.

Mithril must support a signed canonical path-tree `DENY` rule. The rule must
deny each covered effect under the selected tree, including a file created or
replaced after policy activation. It must decide from the clean canonical path
and mount view before exact-object lookup. It must not require the child inode
or inode generation.

`FILE-PATH-TREE-DENY-001` must prove that a rule for `/tmp/secret-dir/**`
denies a pre-existing child, a child created after activation, and a replacement
child before a descriptor or bytes are returned. It must prove that a legitimate
file outside the tree still follows its normal policy. It must also prove that
a path-tree `ALLOW` fails policy compilation, and that an ambiguous or dirty
mount view fails closed.

This rule is a restriction only. Positive file authority and retained file
instance authority still require exact-object and provenance checks.

## Path-tree implementation result — 2026-08-17

State: **Done** for the bounded `FILE-PATH-TREE-DENY-001` slice. The phase
remains **Not done**.

The signed source accepts only recursive `DENY` floors for `FILE` operations.
It rejects `ALLOW`, exceptions, noncanonical paths, empty operation sets, and
unsupported effect families. The node determinizes the floor with exact path
patterns and installs one operation mask on each matching terminal.

The node compiles only the static generation-scoped graph. It does not resolve
a live mount path for a path-tree floor. BPF reads the task's live mount
namespace, scans its mount tree, selects the lowest `mnt_id_unique` for each
root dentry, and walks from the leaf across mount parents to the namespace
root. It reverses the components and traverses only the task's bound profile
generation from state zero. The floor runs before exact-object lookup. It
therefore covers a negative dentry for `CREATE`, children that appear or
change after activation, and a task whose mount namespace appears after
policy activation.

Exact implementation commit `d38248f` passed the repository VM kernel,
identity, observation, and protection probes on x86_64 Linux
`6.8.0-137-generic`. The production BPF object SHA-256 is
`edf9d9941e8bd3bbc8ec0a04f32e5fec1adc1571b8b1b508b8c4ab8a994d6943`.
The local-enforcement artifact SHA-256 is
`fa91e8f1a3ee179285ec0d6ad7f592cc5a612d1d030d3f70ffefd9cec6898a3b`.
It records a denial at the 255-component limit, future-namespace denial,
pre-existing, later, and replacement child denials, an allowed outside
control, failed-closed mount replacement, propagation invalidation,
`mount_setattr` reconciliation, and complete fixture cleanup.

The BPF mount enumeration limit is 4,096. The mount scan stack and path vector
each accept 255 entries. Each component accepts at most 255 bytes. The
combined live mount and dentry walk accepts 4,351 callbacks. The source has no
separate 64-entry mount-depth limit.

The disposable VM artifact and manual operator result are recorded in the
[manual acceptance document](./manual-testing/phase-4-manual-acceptance.md#signed-path-tree-denial--2026-08-17).

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

## Qualification update — 2026-08-15 — retained VM mount slice

At source commit `5b1abfa984d0`, the retained x86_64 VM ran
`mithril-effect-test physical-probe --protect` with unique pin-root, lease,
cgroup, fixture, and output paths. The JSON artifact is
`/tmp/mithril-phase234-codex-retained-1/phase4-meta-mount-5b1abfa984d0-20260815T144741Z/effect-physical-probe.json`,
SHA-256 `9cfda0507593f4b2b2ca040d58f2bb03d922bbf2cc0f93d182ec746859157dca`.
The binary SHA-256 is
`8426f68d285187e74e39bfadadeb57c3595a944a200001df639a685116bbfd1b`.
The embedded BPF object SHA-256 is
`69ee79417f875f7c7a7065d18e08918e9d9bc32359711b57013eba77879fbcbe`.
The run reused the retained checked test-signing fixture only after its
SHA-256 matched `69cb65712b6e3b31d67de53e7eefa898027dc63e19f4f67ae0ae3e698a8fa0f8`.
It did not copy the signing key.

The JSON records `bind_alias_canonicalized=true`,
`protected_mount_race_denied=true`,
`mount_stale_proposal_failed_closed=true`,
`external_mount_replacement_failed_closed=true`, and
`exact_object_restored_after_reconciliation=true`. It also records
`mount_propagation_reached_peer=true`,
`mount_propagation_all_views_failed_closed=true`,
`mount_propagation_reconciled=true`,
`mount_setattr_global_invalidation=true`, and
`mount_setattr_reconciled=true`. The cleanup fields
`pin_root_removed=true`, `lease_removed=true`, `cgroup_removed=true`, and
`fixture_root_removed=true`. Postflight found no unique pin, lease, cgroup,
fixture root, or Mithril/Erebor process. Only the unrelated
`hid_tail_call` BPF link remained.

This retained-VM record qualifies the implemented alias and mount-CAS slice.
It does not replace a fresh full-harness qualification record. The phase
remains **Not done**. The administrative runc bootstrap sequence remains
unsupported. Do not add a broad runc, pipe, or socket exception.

## Qualification update — 2026-08-16 — readable CRI alias and mount cases

A fresh manual K3s VM ran
[`nsenter-bind-alias-deny.sh`](../../../examples/mithril-local-enforcement-manual/nsenter-bind-alias-deny.sh)
and
[`mount-attack-deny.sh`](../../../examples/mithril-local-enforcement-manual/mount-attack-deny.sh)
against one bound Python 3.12 container. The working tree was based at
`78f12f568b2e8fb8de89d2fbc667aef3824eddfb`. The script SHA-256 values were
`8ffca2db77acd95d87b669374a5cf1246829e2e5221f401bac468c891b83b74d` and
`51a14ad266eb02c3d8c2af22cabab1bc3ffecc7470b50dec0814b665bca336df`.

The alias case created two file bind aliases before activation. Its Python
probe required two exact key-7 denials. The mount case issued eight Python
`mount(2)` calls after activation. Each call returned `EACCES` or `EPERM`.
The protected-file retries also denied. Both scripts exited 0. Their output
SHA-256 values were
`09e3b76ee1a37afd563eb0c4b6171dbcfa86a25510f4c14b1d9854665eae35e7` and
`3f2e2a62c5281b2a1750f4c6d12f19649e8a8f1e9a3a0797886e2c3c9655c73c`.

The scripts removed their Mithril state. The outer runner removed each Pod,
namespace, and fixture. Final inspection found no Mithril pin or process.
Only unrelated BPF link 1 remained. This proves two manual CRI slices. It does
not qualify propagation, idmapped mounts, token rotation, or administrative
exec. The phase remains **Not done**.

## Qualification update — 2026-08-18 — inherited IPC and identity lifecycle

Implementation commit `5dd695e` adds a physical inherited Unix-stream case.
A fork child inherits its parent's connected endpoint but does not inherit the
parent's exact relationship authority. The protected operation denies. The
declared parent-to-peer control still succeeds.

The same source serializes external-root label publication against task exit.
It rejects a label claim after `PF_EXITING`, publishes the task cookie last,
and lets the exit hook cancel an incomplete claim. The identity fixtures use
explicit barriers for PID-namespace and `CLONE_INTO_CGROUP` transitions. Six
consecutive identity probes passed in one retained guest.

A fresh disposable VM then passed the kernel, identity, observation, and
protected-effect lanes. The local-enforcement JSON is
`/tmp/mithril-phase4-full-after-fixes/local-enforcement-physical-probe.json`.
Its SHA-256 is
`04b1fdb9f5b86c884612a880d79fe272d45e79eaade69a1fc238808376eab465`.
It records `inherited_unix_stream_send_denied=true`,
`unix_stream_relationship_allowed=true`, 10,000 measured opens, 50,000
saturation opens, preserved policy decisions under loss, and complete cleanup.
The identity JSON SHA-256 is
`fff4e3f494751c01b8e75c83e1515bbb16ce143ea4c93ac7e2e79c7c4dc66c99`.

`STATE-FORK-IPC-002` is **Done**. The phase remains **Not done** with 16
implementation-open Appendix C rows. The
[closure matrix](./phase-4-closure-matrix.md) states each remaining owner and
separates later-phase work.
