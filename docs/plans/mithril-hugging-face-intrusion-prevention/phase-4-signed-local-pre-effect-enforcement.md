# Phase 4: Signed Local Pre-Effect Enforcement

Status: **Not done** for the complete phase. The signed path-tree denial claim
is **Done** for the tested ordinary bind, recursive-bind, and `move_mount`
forms. The Kubernetes baseline-submount route correction is **Done**. The
remaining unsupported capabilities and the unfinished administrative
reservation and late argv verification keep the phase open. The approved
initial-exec and mount-epoch architecture is documentation only. Its
implementation is not approved.

- Master: [Mithril Hugging Face Intrusion Prevention](./README.md)
- Design: [Validated readable architecture](./policy-and-protection-algorithm-architecture-readable.md)
- Manual acceptance: [Phase 4 runbook](./manual-testing/phase-4-manual-acceptance.md)
- Closure matrix: [Phase 4 closure matrix](./phase-4-closure-matrix.md)
- Environment setup: [shared setup guide](./manual-testing/environment-setup.md)
- Implementation review: [local pre-effect enforcement](./phase-4-implementation-review.md)

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
are denied where undeclared. For an allowed topology change, BPF updates its
synchronous mutation guard before effect. Each later file or executable
decision rebuilds and verifies the live topology before it can allow.
Canonical path matching remains an exact-object candidate for a positive
decision.

Add signed recursive path-tree `DENY` floors. A rule can protect a canonical
path such as `/tmp/secret-dir/**` and deny its covered effects for every
current, new, or replaced child. The terminal decision uses the clean canonical
path and mount view. It does not require the child inode or inode generation.
Apply it before exact-object lookup. Check every affected parent/name path for
create, rename, link, and other name-changing operations before visibility.
Reject a path-tree `ALLOW`, allow exception, or another positive disposition.
Exact object identity remains required for positive file authority and for
file-instance provenance.

Use a current Node route before mount-age selection when Node knows the mount
root path. The route identifies the mount root by its container binding,
profile generation, topology generation, mount namespace, filesystem device,
and root inode. It stores the compiled path-graph prefix. If no route exists on
the source dentry ancestry, use the oldest unique mount as the canonical
fallback. Treat all mounts in the initial Kubernetes container snapshot as one
baseline. Their creation order does not select policy authority.

Compile the path graph once as immutable generation content. The held-initial-
PID inode stage publishes route rows as dynamic binding state in that same
generation. Route publication must not add graph states, change the generation
digest, or allocate a second generation. Completion of provisional entry and
exact-object measurement also stays in the same generation.

At the held `createRuntime` stage, the task still has its pre-container root.
Node opens the configured root from the OCI bundle through the held mount
namespace. It rebases bundle mountpoints to container paths and publishes the
provisional entry-time routes. It must not derive a route from
`/proc/<pid>/root` at this stage. At the approved initial-exec boundary, Node
replaces the provisional dynamic rows from the final container mount view
before it publishes application-entry authority. This lifecycle does not
change the graph or allocate another generation.

BPF owns the pre-effect mount guard. Keep mount activity evidence separate
from the security-view epoch. Record every observed mount API operation. An
operation advances the affected namespace security epoch only when it can
change that namespace's visible topology or security attributes. An operation
with unknown attribution or possible propagation advances the global
fail-closed epoch. A concurrent, dirty, or unresolved security view denies.
Node reconciles a dirty represented view from a complete verified snapshot.

Key every BPF mount-cache state and mount-selection row with the captured
security-view epoch and namespace identity. Build all rows for one epoch before
the cache state becomes ready. Do not reuse a row from an earlier epoch when
the namespace event, namespace address, task-root pointers, or mount-root
identity stay the same. Use the cache only after BPF rechecks the same
security-view epoch and confirms that no relevant mount mutation is pending.
The approved classification and fallback rules are in the dated architecture
correction below.

For a bind mount, BPF evaluates the canonical path below the current task root
and each admitted source route that represents the resolved object. A path-tree
denial from either path wins. An admitted source route can supply positive exact
object authority only after the task-root path has no applicable denial. Thus,
binding an allowed object over a denied path cannot convert the denied path to
an allow.

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

### D4.6 — Bounded exceptions and execution approval slots

Implement exact, signed, expiring exceptions with `maximum_uses`. Consumption
is atomic in the matching BPF rule/map entry; a nonmatching rule/program cannot
consume or reuse it. An execution approval slot is the generic kernel primitive
for one approved exec attempt. It binds the resolved executable object, the
complete immutable argv snapshot, live binding, generation, deadline, target role, and
optional exception claim. Administrative approval is the first workflow that
creates one. A later approved agent request for a tool such as Bash must create
the same slot and must not add another BPF admission mechanism.

Node serializes the signed raw argv as each argument followed by its NUL byte.
It divides that complete stream into ordered chunks of at most 4096 bytes. Node
allocates a fresh snapshot ID, inserts each expected chunk once with
`BPF_NOEXIST`, reads back the complete snapshot, and then publishes the slot
descriptor. The descriptor contains the snapshot ID, argument count, total
span, and chunk count. Node must not modify a published chunk. A publication
failure creates no armed slot and removes the rows that the failed publication
created.

At syscall entry, BPF must capture the complete kernel-valid argv from mutable
user memory before any cgroup, binding, role, policy, or slot lookup. BPF writes
ordered chunks once under a fresh task-local capture ID and marks the capture
complete only after it reads the terminating NULL argv pointer. The provisional
capture is not authority. Do not use a Mithril buffer limit as an exec limit.
An executable-only entry can continue if capture is unavailable because argv is
not an authorization fact for that entry. BPF must emit explicit
incomplete-capture evidence. An entry with an exact-argv condition cannot
reserve its slot unless the complete capture exists and matches the expected
snapshot byte for byte, including argument boundaries.

At the deny-capable `bprm_check_security` hook, BPF must compare the complete
candidate capture with the expected immutable snapshot when the entry requires
it. It must also match the resolved executable, live binding, generation,
deadline, and restricted external root before it atomically changes the slot
from `ARMED` to `RESERVED`. Reservation grants no role. If the selected compiled
action consumes a bounded exception, BPF also consumes that exception under the
slot's `claim_slot_id` in this deny-capable reservation path. An exception-
consumption failure corrupts the reservation and denies the exec. At
`security_bprm_committing_creds`, BPF reads the complete copied kernel-owned
argv into ordered chunks and compares each chunk with the same immutable
snapshot. At `sched_process_exec`, BPF repeats that comparison against the
successful process image argv.
Only an exact final match can change `RESERVED` to `CONSUMED` and install the
slot's target role. A mismatch, read failure, incomplete input, or failed exec
consumes or corrupts the already-spent reservation, grants no role, keeps the
task fail-closed, queues `SIGKILL` before user-mode execution, and emits a
critical tamper observation. The node persists and reports that observation.
It does not make the match decision.

BPF removes provisional chunks when the exec commits, fails, or loses its exact
task binding. Node removes expected chunks only after the slot is terminal and
no pending reservation refers to it. Both maps have configured capacity. A
capacity failure makes an exact-argv request unavailable; it does not deny an
entry whose signed rule has no argv condition.

The exec caller can be any thread in a multithreaded process. Candidate state
is task-local. Competing threads can prepare candidates, but only the existing
process transition guard and the slot's atomic `ARMED` to `RESERVED` change can
select one winner. The match must not require `live_thread_refs == 1`.

Declared PostStart, PreStop, startup, readiness, and liveness probe entries must
use the same provisional chunk capture, pre-PONR reservation, kernel-owned argv
verification, successful-exec confirmation, fail-closed response, and tamper
evidence. A declared probe remains reusable, but each probe invocation creates
a new task-bound execution approval slot from that declaration. The slot is
consumed once; the probe declaration is not consumed.
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

## Approved OCI Hook Lifecycle Correction — 2026-09-03

State: **Superseded** by the approved initial-exec and mount-epoch architecture
below. Do not implement this `startContainer` helper or its communication
bridge. This section remains as historical analysis.

Yes—my recommended incremental design is to keep `createContainer` and add `startContainer`, with different responsibilities. More precisely, the full sequence uses three stages:

1. `createRuntime`: establish the host-side admission and hold.
2. `createContainer`: prepare provisional identity and the trusted bridge.
3. `startContainer`: reconcile the final mount view and release execution.

`createContainer` must stop meaning “mount state is final.”

## What happens now

1. Containerd asks runc to create the container.

2. runc creates the init process and installs the OCI specification mounts.

3. runc runs Mithril’s `createRuntime` hook.

4. The node loads the BPF policy maps and places the runc-init task in the prepared/held state.

5. runc runs Mithril’s `createContainer` hook.

6. Mithril reads the PID, bundle, cgroup, namespaces, and mount routes.

7. Mithril currently reconciles the mount epoch and treats that view as final.

8. Mithril releases `createContainer`.

9. runc then performs `pivot_root` cleanup:

```text
mount("", ".", MS_SLAVE | MS_REC)
umount(".", MNT_DETACH)
```

10. BPF observes those operations:

```text
clean_epoch   = 1
current_epoch = 3
```

11. No owner performs another reconciliation.

12. runc executes the application.

13. The application’s first marker write encounters the stale mount view and gets `UNRESOLVED_OBJECT`.

That is the lightweight r95–r97 failure.

## What both hooks would do

1. `createRuntime` establishes the signed admission and holds the task.

2. `createContainer` receives the OCI state while the host filesystem is still reachable.

3. `createContainer` performs only provisional work:

   - verify container ID, PID, cgroup, bundle, and annotations;
   - create the prepared identity;
   - install non-final policy data;
   - prepare or verify the trusted helper and node communication path that will remain available after pivot-root;
   - keep the application admission held.

4. `createContainer` returns.

5. runc performs its remaining mount operations.

6. BPF increments the mount epoch and leaves the mount view dirty.

7. This is safe because the application is still held and has not executed.

8. After root finalization, runc invokes `startContainer`.

9. The `startContainer` helper sends the same OCI identity to the node.

10. The node independently verifies the live PID, cgroup, namespace, and prior admission.

11. The node reads the now-final `/proc/<pid>/mountinfo`.

12. The node compares the mount routes with the BPF views.

13. The node applies the reconciliation proposal.

14. The node verifies:

```text
pending_mounts == 0
clean_epoch == current_epoch
all required mount-route digests match
task remains in the prepared state
```

15. The node atomically changes the task from prepared to active.

16. `startContainer` returns success.

17. The local runc source shows that runc then closes file descriptors and calls `execve`; it performs no further rootfs mount setup. [final hook and exec](/home/navid/go/src/github.com/Ereborlabs/erebor-runtime/runc/libcontainer/standard_init_linux.go:282)

18. The application’s first effect therefore uses the final, clean mount view.

## What this solves

It solves the startup mutation specifically:

```text
createContainer reconciliation
        ↓
runc changes mounts
        ↓
stale BPF view
```

becomes:

```text
createContainer preparation
        ↓
runc changes mounts
        ↓
startContainer final reconciliation
        ↓
application exec
```

The runc mount and unmount are no longer a race. They occur before the final reconciliation by construction.

## What it does not solve alone

Containerd can perform later mount preparation for `crictl exec` after the application is running. `startContainer` does not run for each ordinary runc exec.

That case still requires the persistent mount-mutation mechanism:

1. Containerd/runc starts an exec preparation.

2. BPF increments the global mount epoch.

3. The clean epoch no longer matches.

4. BPF refuses stale path authorization.

5. Reads during this dirty state fail closed with guard evidence.

6. The node reads the changed mount topology and reconciles it.

7. The clean epoch catches up.

8. Later protected reads return normal `PATH_TREE_POLICY_DENY`.

Thus `startContainer` fixes initial bootstrap, while the epoch/reconciliation mechanism protects later runtime mutations.

## What we have tested so far

1. Focused Rust unit tests and static harness tests passed.

2. Earlier lightweight runs reached the concurrent-exec test, but the old guard existed only during the extremely short pending syscall interval.

3. Lightweight r86 completed 16,384 reads before the mount epoch changed from `22` to `220`. No read overlapped the pending interval, so the intended guard oracle failed.

4. Kubernetes r13 successfully started the pod:

   - pod Ready;
   - zero restarts;
   - mounts succeeded;
   - protected paths denied;
   - control path allowed;
   - 566 normal policy denials;
   - zero unresolved events.

   It then stopped because it did not observe the required mutation collision.

5. Replacing the subshell read with `command : <path` removed one fork and exit per read.

6. The new FIFO and 32-exec driver were added but have not yet been qualified in Kubernetes.

7. The strict dirty-epoch latch made the later-mutation test deterministic in principle, but exposed the missing startup boundary first.

8. r95–r97 failed at the first application marker, before the application’s own mount commands or concurrent reads ran.

9. The actor trace showed runc-init issuing `mount` and `umount` after the `createContainer` release.

10. The local runc source confirmed that those operations are part of post-hook pivot-root cleanup.

No latest-shape Kubernetes run has happened yet.

## Proposed deliverables

If you approve this lifecycle structure, I will proceed in this order:

1. Add `startContainer` support while preserving `createRuntime`, `createContainer`, and every existing trace.

2. Change `createContainer` to provisional preparation only.

3. Implement the trusted post-pivot helper/IPC bridge.

4. Make `startContainer` perform final reconciliation and activation.

5. Add unit tests for:

   - lifecycle ordering;
   - no activation at `createContainer`;
   - dirty epoch after post-create mounts;
   - final reconciliation at `startContainer`;
   - failure when another mount occurs before activation;
   - failure when the helper or peer identity is incorrect.

6. Run the focused Rust and harness tests, then commit that deliverable.

7. Run the lightweight physical test and require:

   - runc post-create mount mutation observed;
   - start reconciliation succeeds;
   - first application marker succeeds;
   - all protected reads denied;
   - control read allowed;
   - no stable-state unresolved events;
   - every concurrent exec denied;
   - deliberate dirty-state reads fail closed;
   - post-reconciliation reads return normal policy denial.

8. Commit the completed lightweight deliverable.

9. Run Kubernetes only after lightweight passes the same state transitions and oracles.

10. If Kubernetes exposes a condition missing from lightweight, stop the Kubernetes cycle, add that exact condition to lightweight, and make lightweight pass first.

11. Commit Kubernetes harness/evidence and documentation separately.

This is an architecture/lifecycle change, so I need your approval before implementing it.

## Approved Initial-Exec And Mount-Epoch Architecture — 2026-09-03

State: **Architecture approved. Implementation is not approved.** Stop after
this documentation commit. Wait for explicit implementation approval.

This correction uses stock runc. It does not add a runc wrapper, runc patch,
container helper, container-mounted socket, or `startContainer` hook. Keep all
current execution and mount diagnostics.

### Initial PID completion boundary

1. Containerd asks stock runc to create the container.

2. runc creates the initial `runc init` process.

3. runc creates the namespaces and performs the early rootfs mounts.

4. runc runs the two ordered Mithril `createRuntime` hook entries.

5. The first entry stages immutable container, cgroup, image, and Pod facts.
   The second entry sends the exact held initial PID and OCI state to the node
   through the existing host path.

6. The node verifies the exact PID, PID lifetime, cgroup, container identity,
   signed policy candidate, and provisional namespace state. The node creates
   a `PREPARED` binding. It does not publish application-entry authority for
   this binding.

7. runc runs `createContainer`. The node validates the declared entries and
   stages candidate data. It keeps the binding-specific application-entry row
   absent. `createContainer` returns without declaring the mount view final.

8. runc performs its remaining rootfs work. This work includes `pivot_root`,
   final read-only remounts, and masked-path mounts.

9. runc installs the OCI seccomp filter that contains the `execve` and
   `execveat` user-notification rule.

10. The runc host parent sends the seccomp listener FD and OCI process state to
    the node through the OCI `listenerPath`. The socket is host-only. It is not
    mounted in the container.

11. runc completes create. The initial process waits on runc's start FIFO.

12. Containerd starts the container. runc opens the start FIFO.

13. The exact initial PID calls `execve` or `execveat` for the application.

14. The kernel blocks that syscall and sends one seccomp notification to the
    node. No application instruction has run.

15. The node validates the live notification ID, PID lifetime, cgroup, mount
    namespace, executable request, container identity, and `PREPARED` binding.
    The node reads the final mount topology and rejects any mismatch or pending
    mutation.

16. On success, the node rebuilds the final exact executable, exact-object,
    mount-view, and mount-route dependencies. It installs and reads back those
    dependencies. It writes the binding-specific application-entry rule last
    and reads it back. That final row is the application-authority publication
    point. The node then replies `CONTINUE` to the seccomp notification.

17. BPF evaluates the real exec request. BPF verifies the opened executable,
    invocation path, argv requirements, binding, generation, and entry rule.
    A successful transaction changes `PREPARED` to `EXEC_PENDING`.

18. The first syscall from the new application image proves that the image
    reached user space. BPF changes `EXEC_PENDING` to `ACTIVE` at this point.

The checked local stock-runc source fixes this order. `createContainer` returns
before `pivot_root` and the final rootfs operations
([rootfs order](../../../runc/libcontainer/rootfs_linux.go#L226)). The host
parent forwards the seccomp listener FD and OCI process state through
`listenerPath`
([listener transfer](../../../runc/libcontainer/process_linux.go#L940)). The
init process installs seccomp, waits on the existing exec FIFO, closes its
internal file descriptors, and then calls exec
([initial exec order](../../../runc/libcontainer/standard_init_linux.go#L234)).

A failure at stages 14 through 16 denies the syscall and publishes no
application role. A pre-point-of-no-return BPF failure at stage 17 denies the
exec. A later BPF mismatch grants no role and prevents a user-mode effect with
the existing fail-closed exec response. If the node fails after row publication
but before its `CONTINUE` response, the initial process remains blocked in the
kernel. Recovery must revalidate the complete transaction or revoke the
binding-specific row before it resolves the notification.

### Delayed binding publication

A policy generation can already be active for another container. The node
must not deactivate that shared generation. The delay applies to the new
container's binding-specific authority.

The binding-specific entry key contains the profile generation, binding ID,
entry atom, and source role. BPF has no application admission when that row is
absent. Stages 6 and 7 can verify signed immutable policy content and prepare
candidate rows, but they must not publish the new binding's usable
application-entry row. Stage 16 installs all dependencies first and writes the
binding-specific entry row last.

### Why earlier lightweight cases passed

Before implementation commit `27e7763`, the global mount snapshot rejected a
path decision only while a mount syscall was pending. It did not require the
clean epoch to equal the current epoch. A runc mount syscall could finish,
clear the pending counter, and let BPF rebuild from live kernel state without
a final node reconciliation.

Commit `27e7763` added the persistent `clean_epoch == current_epoch` guard.
The complete direct-runc lifecycle then exposed the missing boundary:

```text
createContainer reconciles epoch 1
  -> createContainer returns
  -> runc performs post-hook mount work
  -> current epoch becomes 3
  -> clean epoch remains 1
  -> the first application path effect returns UNRESOLVED_OBJECT
```

Focused Rust tests exercised state and map transitions. They did not execute
the complete stock-runc rootfs lifecycle. Lightweight r84 passed its
regression oracle because it reproduced `UNRESOLVED_OBJECT`; it did not prove
successful application startup. The earlier Kubernetes r13 reader ran after
the Pod was Running and Ready and did not guard the initial application exec
under the persistent clean-epoch rule.

The retained VM is `mithril-runtime-qualification-960031`. Retained directories
`/var/tmp/mithril-r96` through `/var/tmp/mithril-r102` remain on that VM. The
r97 failure is in `/var/tmp/mithril-r97/run.log`. The r98 through r100 mount
actor logs record the runc lifecycle. The r100 lifecycle log gives the clearest
post-`createContainer` mount sequence.

### Later runc exec correction

An ordinary later `runc exec` does not repeat initial rootfs setup. The local
runc setns-init path joins the existing namespaces and calls exec. The measured
`open_tree`, `fsconfig`, and `fsmount` calls came from runc executable sealing.
That code creates a detached overlayfs mount FD. It does not attach the mount
to the running container's mount namespace.

The observed global epoch change from 22 to 220 proves mount API activity. It
does not prove a change to the target container's mount topology. The prior
concurrent-exec oracle tested false global coupling. Do not add an initial-
mount reconciliation transaction to later exec on this evidence.

An application descendant inherits the initial seccomp filter. A stock-runc
later exec does not depend on that lineage. Its setns init installs the
configured filter for the new process
([setns filter](../../../runc/libcontainer/setns_init_linux.go#L94)). Its host
parent forwards the new listener FD
([setns listener](../../../runc/libcontainer/process_linux.go#L532)). Only the
exact initial PID in `PREPARED` uses stages 15 and 16. A later notification must
not publish initial-entry authority or start an initial-mount reconciliation.
The node validates the notification and container lifetime, then lets the
normal BPF entry transaction make the authorization decision. Loss of the
listener remains fail-closed.

### Mount activity and security-view epochs

Keep two logical facts separate:

1. The mount-activity evidence sequence records every observed `fsconfig`,
   `fsmount`, `open_tree`, `mount_setattr`, `mount`, `umount`, `pivot_root`, and
   `move_mount` operation. These records remain available for diagnostics and
   future features.

2. The security-view epoch advances only when an operation can change a
   represented namespace's visible topology or security attributes. Unknown
   attribution and possible mount propagation use the global fail-closed
   fallback.

Use this classification:

| Operation | Evidence record | Security-view invalidation |
| --- | --- | --- |
| `fsconfig` `SET_*` on a new context | Yes | No |
| `fsconfig` `CMD_CREATE` for a detached mount | Yes | No |
| `fsmount` that returns a detached mount FD | Yes | No |
| `open_tree` with `OPEN_TREE_CLONE` | Yes | No |
| `move_mount` that attaches or moves a mount | Yes | Affected namespace |
| `fsconfig` `CMD_RECONFIGURE` | Yes | Affected filesystem, or global fallback |
| `mount_setattr` on an attached mount | Yes | Affected namespace |
| `mount`, `umount`, or `pivot_root` | Yes | Affected namespace |
| Unknown target or possible propagation | Yes | Global fail-closed fallback |

This is not a syscall-name exemption. The implementation must distinguish a
new detached filesystem context from reconfiguration of an existing mounted
filesystem. Access through an unattached mount FD must remain fail-closed
unless separate exact authority exists. `move_mount` must invalidate the
destination security view before an attached mount becomes usable.

### Required qualification order

1. Unit tests must prove delayed binding publication, notification validation,
   entry-row-last publication, failure cleanup, and the first-syscall `ACTIVE`
   transition.

2. The lightweight direct-runc test must prove the post-`createContainer`
   mount sequence, the blocked initial exec, final reconciliation, first marker
   success, protected denials, and the allowed control.

3. The lightweight later-exec test must compare the target mount namespace
   inode, namespace event, and `mountinfo` digest before and after concurrent
   exec preparation. Detached runc sealing must remain visible as evidence and
   must not dirty the target security view.

4. A separate lightweight case must attach a detached mount with `move_mount`.
   It must prove that the target view becomes dirty before protected access can
   continue. It must also cover `FSCONFIG_CMD_RECONFIGURE`, attached
   `mount_setattr`, access through an unattached mount FD, and shared-mount
   propagation.

5. Kubernetes runs only after all paired lightweight cases pass. If Kubernetes
   exposes a condition that lightweight missed, stop the Kubernetes cycle. Add
   that exact condition to lightweight and make lightweight pass before the
   next Kubernetes run.

6. Preserve every temporary diagnostic stage until the approved implementation
   and qualification work determines its permanent evidence owner. Do not
   remove a trace as part of this correction.

No implementation, lightweight rerun, or Kubernetes rerun is authorized by
this documentation decision. Wait for explicit implementation approval.

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
- The initial application image cannot execute until the node validates the
  final mount view and publishes the binding-specific application entry. The
  BPF exec transaction changes the binding from `PREPARED` to `EXEC_PENDING`.
  The first application syscall changes it to `ACTIVE`.
- Detached mount construction emits mount activity evidence but does not
  invalidate an unrelated mount-namespace security view. An attachment,
  reconfiguration, attached mount-attribute change, or propagation event
  advances the affected security-view epoch. Unknown scope uses the global
  fail-closed fallback.
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
State: Not done for the complete phase. The signed path-tree denial claim is Done for the tested mount forms.
Last implementation-validated architecture: policy-and-protection-algorithm-architecture-readable.md.
Completed deliverable IDs: The earlier record contains completed capability results for D4.1 through D4.8. The current probe closes the D4.3 successful child-bind path reconstruction gap. Fourteen Appendix C fixture outcomes have physical `PASS` results. Fourteen unqualified fixture outcomes have exact `UNSUPPORTED` results and are not advertised.
Files and durable owners changed: mithril-control owns PROTECT compilation and exact exception binding. NodePolicyGenerationOwner owns generation staging, readback, anti-rollback, publication, and retirement. ExceptionAuthorityOwner owns stable exception instances, receipts, WAL recovery, restart restoration, and reboot separation. The production BPF effect gate owns pre-effect decisions and atomic exception consumption. mithril-e2e owns the physical oracle and typed fixture results.
Upstream-adoption dossier IDs used: existing Phase 0 libbpf-rs, libbpf-cargo, and checked vmlinux-header decisions. No new runtime or BPF framework was added.
Fixture cases and exact physical results: the current protected probe records 15 `PASS`, 14 `UNSUPPORTED`, zero `FAIL`, and zero `DEGRADED` results. Fourteen passes are allocated Appendix C fixtures. `FILE-PATH-TREE-DENY-001` is Done for the tested mount forms. The probe denies preactivation and postactivation child binds, a recursive bind, and an `open_tree` plus `move_mount` alias. The matching allowed aliases and outside-tree file remain readable. The exact table and reason codes are in phase-4-closure-matrix.md.
Commands and exact source state covered: the repository formatting, workspace check, warnings-as-errors Clippy, and full workspace test gates passed. The full workspace test command passed 972 tests. The rebuilt `mithril-effect-test` protected probe passed in the retained qualification VM. No generated artifact or digest is part of this delivery.
Platform/kernel/runtime manifests: x86_64 Linux 6.8.0-137-generic, cgroup v2, BPF LSM, active LSM order lockdown,capability,landlock,yama,apparmor,bpf, and runtime BTF SHA-256 6da9f6b4ebcae9b07e6a717b517884abf7f6b524e46340e40fb164eed4a49a7c. No non-x86 physical claim is made.
Performance/capacity results: the physical result has 10,000 measured opens and 50,000 saturation opens. It lost 39,081 observation records under saturation while the protected denial and benign allow remained correct. All four cleanup fields are true.
Unsupported/degraded paths: administrative exec, immutable executable and file-content proof, complete mm/VMA state, overlay copy-up provenance, projected-token rotation and controller binding, complete mount variants and propagation, persistent file-instance lifetime, protected exec and role races, and complete local self-protection remain unsupported. Landlock target-context installation is unsupported with reason NO_QUALIFIED_TARGET_CONTEXT_INSTALL. Network and distributed results remain outside this outcome.
Remaining work in this phase: qualify the capabilities that remain `UNSUPPORTED`. A missing hook, field, identity, or authority model must return to the prototype and type-closure gate before a later authorized plan can advertise it. Implement and qualify the approved administrative reservation transaction. Apply the same verification transaction to each declared probe entry before the probe-entry claim closes.
Next phase not authorized: yes.
```

The dated records below describe earlier source states. Their status sentences
do not override the current Phase Result.

## Administrative exec copied-argv feasibility — 2026-09-02

State: **Historical measurement**. This result does not advertise
administrative exec. The approved transaction below supersedes the requirement
that one hook both reads copied argv and denies the exec.

A disposable BPF probe ran in retained VM
`mithril-runtime-qualification-3504827` on x86_64 Linux
`6.8.0-138-generic`. The probe selected one exec with two arguments and
measured the copied argument address at both sides of the exec address-space
transition.

At sleepable `lsm/bprm_check_security`, the hook was deny-capable and
`point_of_no_return=0`. The current task used `mm=0xffff8a0bc7181600`.
The copied argument image used `bprm->mm=0xffff8a0bc7186e00` and
`bprm->p=0x7fffffffefc4`. `bpf_probe_read_user` and
`bpf_copy_from_user_task` both returned `-EFAULT`. A kernel read returned
`-ERANGE`. No argument byte was available.

At `fentry/security_bprm_committing_creds`, the current task used the prior
`bprm->mm`, `bprm->mm` was null, and `point_of_no_return=1`. A user read from
the same `0x7fffffffefc4` address succeeded and returned
`/bin/echo\0mithril-kernel-owned-a` as the first 32 bytes. This hook cannot
deny or roll back the exec.

The measured interface has no point where standard BPF can both
read the complete kernel-owned argument image and deny before the point of no
return. The approved design uses the deny-capable hook to reserve authority,
then verifies kernel-owned argv at the two available late hooks. A late mismatch
cannot roll back exec. It must prevent user-mode execution with `SIGKILL`, leave
the task without the approved role, and emit critical tamper evidence. The
checked product source still has the old syscall-entry-only comparison. It does
not meet the approved contract and provides no administrative-exec claim. The
probe links, pin directories, launcher, and remote objects were removed. The VM
remains retained and running.

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

State: Superseded by the 2026-08-21 correction below. The earlier evidence
proves a narrower path-tree slice but does not close
`FILE-PATH-TREE-DENY-001`.

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

## Successful child-bind correction — 2026-08-21

State: **Done** for the tested mount forms.

The mount cache selects the oldest mount for each exact root dentry. The live
walker probes that cache at each dentry. It records a non-self root name and
follows source `d_parent`. It crosses a selected mount attachment only at a
self-parent filesystem root.

Mount policy remains a separate owner. The physical probe lets each tested
mount complete. That source state reconciled postactivation topology before
access. The protected aliases return `PATH_TREE_POLICY_DENY`. Matching allowed
aliases and the outside-tree file remain readable. The synchronous correction
below replaces the earlier reconciliation ownership. The readable algorithm is in the
[path-tree implementation review](./path-tree-denial-implementation-review.md#successful-child-bind-source-walk).

## Kubernetes baseline-submount route correction — 2026-08-31

State: **Done** for the paired lightweight and Kubernetes route case at its
recorded source. The global-epoch flow below records that source. The approved
initial-exec and mount-epoch architecture above supersedes that epoch ownership
for future implementation.

```text
Node holds the authenticated initial container mount snapshot
  -> Control has already compiled and signed the complete immutable path graph
  -> Node measures existing source dentries through the held container root
  -> Node resolves each represented source path to an existing graph state
  -> Node publishes only dynamic inode routes for the container binding
  -> the provisional and completed binding keep the same generation handle
  -> the active graph and its digest do not change
  -> a Kubernetes submount inherits the known source path
  -> Kubernetes mount creation order does not select the route

BPF reaches a mount-root dentry during a path walk
  -> BPF uses the current Node route when one exists
  -> BPF appends the collected child components and continues graph matching
  -> BPF does not compare unique mount IDs for this routed path

BPF finds no Node route on the source dentry ancestry
  -> BPF selects the oldest represented mount by unique mount ID
  -> BPF continues through that mount's parent path
  -> a missing or unresolved fallback denies under strict policy

At the recorded source, a represented namespace changes after activation
  -> the BPF mount hook updates the global epoch and pending count before effect
  -> the BPF return hook clears the pending count after the syscall
  -> the next BPF decision snapshots the guard and live namespace event
  -> BPF selects or builds only cache rows keyed by that global epoch
  -> BPF scans the live mount tree and resolves the path in the same hook chain
  -> BPF rechecks the guard before it applies the policy decision
  -> a race or unresolved path denies without a Node round trip

Node restarts or remeasures a live binding
  -> Node acquires and verifies the retained container mount view
  -> Node rebuilds the complete dynamic exact-object and mount-route rows
  -> Node republishes each canonical route from the current mount snapshot
  -> a changed snapshot digest can replace the prior dynamic route value
  -> the signed path graph, generation descriptor, and graph state IDs do not change
  -> an incomplete or unverifiable live view does not publish replacement rows
```

The route stores graph state IDs, not an inode denial bit. A mount-root route at
`/home` keeps `*` active for `/home/*/secrets`. A mount-root route at `/srv`
keeps `**` active for `/srv/**/secrets`. The container-root route supplies the
same result when the path does not cross another mount. A future child uses
the route on its known ancestor. If more than one known path applies to one
source root, Node stores the deduplicated existing states. BPF advances all of
them, combines their role-specific denial masks, and applies any denial. One
route can contain 16 states. Node refuses binding activation if it needs more.
Node does not create a combined graph state.

This route publication is part of the existing held-initial-PID inode stage.
It is not policy compilation and does not require a second generation. A later
signed policy replacement can use a new generation. Container creation cannot
replace a generation to publish inode routes. The route row is dynamic binding
authority. Node can replace its snapshot digest and measured route data after
it verifies a complete current view. The signed graph rows in that generation
remain immutable.

The paired lightweight and Kubernetes tests must use both Kubernetes mount
orders. They must also complete a later in-container bind mount. Both source
and target paths are inside the container. The alias read must return
`EACCES`, while an unrelated control path remains readable.

The paired tests passed on 2026-09-01 with the current BPF object. The
lightweight case denied both Kubernetes mount orders, the later in-container
bind, `/home/*/secrets`, and `/srv/**/secrets`. Its unrelated control path
remained readable. The case also passed owner restart and pinned-program
upgrade. The Kubernetes protected-start case then produced the same five
denials and `CONTROL_ALLOWED`. It ran with
`--protected-start-only --reuse-environment` and wrote its result to
`/tmp/mithril-route-synchronous-parser-fixed-20260901`.

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

At that source state, the retained Kubernetes administrative-exec lane had a
separate blocker. Its
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

This dated lease proposal was not approved and is not the current architecture.
The approved transaction uses BPF slot reservation and late kernel-owned argv
verification. It does not grant runc a bootstrap lease.

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
