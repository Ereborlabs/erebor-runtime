# Native Identity Manual Cases

These are operator-driven checks against the real `mithril-node`. They are not
commands for manually invoking the automated e2e runner.

## Manual Testing In A VM

Use the [manual VM](../../crates/mithril-e2e/harness/vm/README.md#manual-testing-in-a-vm).
In the guest, run `sudo -i`, source `/var/tmp/mithril-manual.env`, and change
to `$MITHRIL_MANUAL_SOURCE`. The manual VM supports CRI, Kubernetes, and
raw-namespace cases. Docker cases require Docker.

Run this self-contained K3s case from that root shell:

```sh
examples/mithril-identity-manual/native-child.sh --thread-exec
```

The command creates one Python Pod and live CRI binding. It starts a Python
root with one non-leader thread. That thread executes `sleep`. The command
removes its Pod and fixture directory at exit.

Run this concurrent-exec case from the same root shell:

```sh
examples/mithril-identity-manual/native-child.sh --concurrent-thread-exec
```

The command creates one Python Pod and live CRI binding. Two sibling worker
threads wait at one barrier, then both call `exec`. Linux leaves one `sleep`
process. The command checks that its Mithril process state and restricted role
remain correct. It removes its Pod and fixture directory at exit.

Run this subreaper reparenting case from the same root shell:

```sh
examples/mithril-identity-manual/native-child.sh --subreaper
```

The command creates one Python Pod and live CRI binding. A restricted external
Python root sets itself as a Linux child subreaper. Its native middle child
exits after it creates one stopped grandchild. The grandchild becomes a child
of the subreaper, then executes `sleep`. The command checks immutable creator
identity, changed real parent, and the inherited restricted role. It removes
its Pod and fixture directory at exit.

Run this PID-namespace-init reparenting case from the same root shell:

```sh
examples/mithril-identity-manual/native-child.sh --namespace-init
```

The command creates one Python Pod and live CRI binding. It starts and stops a
user and PID namespace outside the Pod cgroup. It moves the namespace init,
which has PID `1`, into the Pod cgroup. The init creates a middle child and one
stopped grandchild. The middle child exits. The namespace init adopts the
grandchild, which then executes `sleep`. The command checks the immutable
creator, the adopted real-parent coordinates, and the inherited restricted
role. It removes the host processes, Pod, and fixture directory at exit.

Run this live-binding-gap case from the same root shell:

```sh
examples/mithril-identity-manual/binding-gap.sh
```

The command creates one Pod and moves one waiting host process into its cgroup
before it starts Mithril. It requires
`restored_or_unknown_root`, `fail_closed_unknown`, the configured external
role, and `Runnable`. It then moves a later waiting host process into the same
cgroup and requires the normal restricted external-root identity. The command
removes both processes, the Pod, node process, pin root, lease, state, and
fixture directory at exit.

Run this concurrent external-root case from the same root shell:

```sh
examples/mithril-identity-manual/external-ambiguity.sh
```

The command starts Mithril, then moves two waiting host processes with the
same command into one Pod cgroup. It requires separate task and process
identities, no creator, and the same configured restricted external role. The
command removes both processes, the Pod, node process, pin root, lease, state,
and fixture directory at exit.

Run this self-contained namespace-entry case from the same root shell:

```sh
examples/mithril-identity-manual/nsenter-move.sh
```

The command creates one Pod and live CRI binding. It starts and verifies one
namespace-only `sleep 300` child. It moves that child into the configured
cgroup and requires the restricted external-root identity. The command removes
the child, Pod, node process, pin root, lease, state, and fixture directory at
exit.

Run this labeled native-child namespace-entry case from the same root shell:

```sh
examples/mithril-identity-manual/nsenter-move.sh --labeled-task
```

The command creates one restricted external root in the Pod cgroup. Its stopped
native child enters only the Pod mount namespace, then executes `sleep`. The
child must keep its task, creator, parent, process, and role identities. Its
execution and image identities must change. The command removes the child,
Pod, node process, pin root, lease, state, and fixture directory at exit.

## Operator Cases

Outside the manual VM, build the real node and inspector once:

```bash
cargo build -p mithril-node --bins
```

Then run only the case being checked:

| Case | Command |
| --- | --- |
| Raw Docker exec | `sudo examples/mithril-identity-manual/docker-exec.sh NODE_CONFIG CONTAINER` |
| Direct CRI exec | `sudo examples/mithril-identity-manual/cri-exec.sh NODE_CONFIG FULL_CONTAINER_ID` |
| Kubernetes exec | `sudo examples/mithril-identity-manual/kubernetes-exec.sh NODE_CONFIG FULL_CONTAINER_ID NAMESPACE POD CONTAINER` |
| Native child | `sudo examples/mithril-identity-manual/native-child.sh NODE_CONFIG CONTAINER_OR_FULL_CRI_ID` |
| Orphaned native child | `sudo examples/mithril-identity-manual/native-child.sh NODE_CONFIG CONTAINER_OR_FULL_CRI_ID --orphan` |
| Double-fork native child | `sudo examples/mithril-identity-manual/native-child.sh NODE_CONFIG CONTAINER_OR_FULL_CRI_ID --double-fork` |
| Moved native-child exec | `sudo examples/mithril-identity-manual/native-child.sh NODE_CONFIG CONTAINER_OR_FULL_CRI_ID --moved-exec` |
| Pre-PONR failed native exec | `sudo examples/mithril-identity-manual/native-child.sh NODE_CONFIG CONTAINER_OR_FULL_CRI_ID --failed-exec` |
| Non-leader Python thread exec | `sudo examples/mithril-identity-manual/native-child.sh --thread-exec` in the manual VM; otherwise `sudo examples/mithril-identity-manual/native-child.sh NODE_CONFIG CONTAINER_OR_FULL_CRI_ID --thread-exec` |
| Concurrent Python thread exec | `sudo examples/mithril-identity-manual/native-child.sh --concurrent-thread-exec` in the manual VM |
| Subreaper native reparenting | `sudo examples/mithril-identity-manual/native-child.sh --subreaper` in the manual VM |
| PID-namespace-init reparenting | `sudo examples/mithril-identity-manual/native-child.sh --namespace-init` in the manual VM |
| Live binding gap | `sudo examples/mithril-identity-manual/binding-gap.sh` in the manual VM |
| Concurrent external roots | `sudo examples/mithril-identity-manual/external-ambiguity.sh` in the manual VM |
| `nsenter` and cgroup movement | `sudo examples/mithril-identity-manual/nsenter-move.sh` in the manual VM |
| Labeled native-child mount entry | `sudo examples/mithril-identity-manual/nsenter-move.sh --labeled-task` in the manual VM |
| Node restart | `sudo examples/mithril-identity-manual/restart.sh NODE_CONFIG CONTAINER_OR_FULL_CRI_ID` |

Kubernetes is optional, not excluded: only `kubernetes-exec.sh` requires it.
The Docker case derives a trusted test-only configured cgroup binding from
`docker inspect`. CRI and Kubernetes cases require the full live container ID
and its exact test profile assignment in `workload_bindings`; the temporary
config deliberately removes `root_cgroup_path` so `mithril-node` must resolve,
validate, and reconcile the live cgroup through CRI.

## Direct CRI Exec Check

Use this check only when all of these prerequisites are true:

- Run it as root on the node that owns the live CRI container.
- Build `mithril-node` and `mithril-inspect` with `cargo build -p mithril-node --bins`.
- Install `crictl` and `jq`.
- Put exactly one binding for the full live container ID in `NODE_CONFIG`.
  The binding must specify the CRI socket and the exact test profile.

Start the check:

```bash
sudo examples/mithril-identity-manual/cri-exec.sh \
  NODE_CONFIG FULL_CRI_CONTAINER_ID
```

The script prints a `crictl --runtime-endpoint ... exec` command. Run that
command in another root terminal. It starts a sleeping process and asks for its
host PID from the container cgroup.

The oracle is the printed task record. The process must have no creator task
cookie, `external_runtime_root` as its root class, and
`runtime_external_restricted` as its installed role. Command bytes, arguments,
and cgroup placement do not create a probe or application role.

This check proves one direct CRI exec root after the node starts. It does not
prove a kubelet probe join, first-instruction binding, or the complete entry
and failure-injection matrix.

## Namespace Entry And Cgroup Movement Check

Use this check in the retained manual VM as root:

```bash
sudo examples/mithril-identity-manual/nsenter-move.sh
```

The script creates one Python Pod and a live CRI binding. It starts the
`nsenter` helper and finds its only direct child. The script accepts the child
only when it is live, has command `sleep 300`, and has the target container's
mount, UTS, IPC, network, and PID namespaces. It also requires the child to be
outside the configured cgroup and to have no Mithril task identity. The script
then moves only that verified child into the configured cgroup.

The moved child must have no creator task cookie, `external_runtime_root`,
`runtime_external_restricted`, the configured external role, and `Runnable`.
This is one namespace-entry and cgroup-move identity subcase. It does not test
a protected effect, movement of an already labeled task, restore, or the full
entry-migration matrix.

## Labeled Native-Child Mount-Namespace Entry Check

Use this check in the retained manual VM as root:

```bash
sudo examples/mithril-identity-manual/nsenter-move.sh --labeled-task
```

The script creates one Python Pod and a live CRI binding. It moves one waiting
host Bash root into the configured cgroup and requires the restricted external
root identity. The root creates one stopped native child. The child enters only
the Pod mount namespace and executes `sleep 300`.

Before entry, the child must name the root as creator and current real parent.
After entry, it must keep its task cookie, creator cookie, real-parent cookie,
process state, and restricted role. Its active execution and image provenance
identities must change. It must stay `Runnable` with active process execution
and state-vector records. The script removes the child, Pod, node process, pin
root, lease, state, and fixture directory at exit.

This is one labeled namespace-entry subcase. It does not test a protected
effect, restore, or the full entry-migration matrix.

## Creator-Exit Native Child Check

Run this check when a container runtime can start one shell and its stopped
native child:

```bash
sudo examples/mithril-identity-manual/native-child.sh \
  NODE_CONFIG CONTAINER_OR_FULL_CRI_ID --orphan
```

The script prints one runtime-exec command. Run it in another root terminal.
Enter the host PID of its shell and stopped child. The script checks their
creator edge. Kill only the printed shell PID, then press Enter. The script
resumes the child and checks its next exec record.

The child must keep its original creator task cookie. Its real-parent interval
sequence must increase, and its current real parent must not be the exited
creator. The child remains a native task with the inherited restricted role.

This check covers the creator-exit branch of `ID-CREATOR-PARENT-007`. It does
not cover double forks, subreapers, namespace-init reparenting, ptrace
reparenting, or PID reuse.

## Double-Fork Native Child Check

Run this check when a container runtime can start an outer shell, one native
intermediate child, and one stopped native grandchild:

```bash
sudo examples/mithril-identity-manual/native-child.sh \
  NODE_CONFIG CONTAINER_OR_FULL_CRI_ID --double-fork
```

The script prints one runtime-exec command. Run it in another root terminal.
Enter the host PID of the outer shell, its intermediate child, and the stopped
grandchild. The script checks both creator edges and their current real-parent
records. Kill only the printed intermediate PID, then press Enter. The outer
task changes to `sleep` and stays live. The script resumes the grandchild and
checks its next exec record.

The grandchild must keep its original task cookie and creator task cookie. Its
creator is the exited intermediate task, not the outer root. Its current
real-parent record must change, its real-parent interval sequence must
increase, and it must remain a native task with the inherited restricted role.

This procedure covers the double-fork branch of `ID-CREATOR-PARENT-007`. It
does not cover subreapers, namespace-init reparenting, ptrace reparenting, or
PID reuse. It is an operator procedure, not a qualified VM result.

## Moved Native-Child Exec Check

Run this check when the host can move one stopped native child to the parent of
the configured container cgroup:

```bash
sudo examples/mithril-identity-manual/native-child.sh \
  NODE_CONFIG CONTAINER_OR_FULL_CRI_ID --moved-exec
```

The script prints one runtime-exec command. Run it in another root terminal.
Enter the host PID of its shell and stopped child. The script records their
native identity, moves only the child PID to the parent cgroup, and waits for
`coordinate_state=6` (`FailClosedUnknown`). It then resumes the child.

The child must keep its task and creator cookies. It must not become `sleep`.
It must exit within five seconds because its exec is denied. This shows that a
labeled task that leaves its expected placement does not use host exec policy.

This procedure is an operator check for `ID-MOVED-TASK-EXEC-005`. It is not a
qualified VM result.

## Pre-PONR Failed Native-Exec Check

Run this check only when the selected workload has `/bin/bash`, `python3`, and
a dynamically linked `/bin/true`:

```bash
sudo examples/mithril-identity-manual/native-child.sh \
  NODE_CONFIG CONTAINER_OR_FULL_CRI_ID --failed-exec
```

The script prints a root Bash command and one paste block. The block copies
`/bin/true`, changes one byte in its ELF loader path to an equal-length invalid
path, and starts a stopped native Bash child. This causes an ELF loader failure
after exec preparation and before exec commit. It does not use a missing
pathname or a shell script failure.

Enter the host PID of the printed root Bash session and its stopped child. The
script records their task identities. Resume the child once. Wait for
`MITHRIL_EXECFAIL_RECOVERED`, then let the script inspect it again. The task,
creator, execution ID, image ID, and role must remain unchanged. The exec guard
must be `0`.

Resume the child a second time. It must become `sleep`. The task, creator, and
role must remain unchanged. The execution ID and image ID must change. End the
child when the script asks. The remote Bash session removes its exact temporary
`execfail` file and prints `MITHRIL_EXECFAIL_CLEANED`.

This procedure covers one pre-PONR failure followed by one normal exec commit
for `EXEC-COMMIT-STATE-001`. It does not cover post-PONR fatal handling,
concurrent exec, map saturation, or a qualified VM result.

## Non-Leader Python Thread Exec Check

Run this check only when the selected workload has `python3` and `/bin/sleep`:

```bash
sudo examples/mithril-identity-manual/native-child.sh \
  NODE_CONFIG CONTAINER_OR_FULL_CRI_ID --thread-exec
```

The script prints a command for a second root terminal and a short Python
block. The block creates one non-leader thread and waits for `SIGUSR1`.
When it prints `MITHRIL_NONLEADER_READY`, find the Python host PID in the
configured cgroup and enter it. The script requires exactly one non-leader
thread, then sends `SIGUSR1`.

The non-leader thread must become `sleep`. Its final task must name the
Python root as creator, keep the same process state and role, change execution
and image IDs, have no external-root class, and report the original PID as
both host TID and TGID. This is one non-leader de-threading subcase. It does
not race execs or cover concurrent fork, vfork, or thread creation.

## Concurrent Python Thread Exec Check

Run this case in the manual VM as root:

```bash
sudo examples/mithril-identity-manual/native-child.sh --concurrent-thread-exec
```

The script creates its own K3s Pod and live CRI binding. It starts two sibling
Python workers and releases both through one barrier. Linux leaves one `sleep`
process. The survivor must keep the root creator, process state, and restricted
role. Its execution and image IDs must change. The script removes its Pod,
fixture, node, pin, lease, state, config, and logs. This is the normal
two-worker subcase. It does not test exec versus fork, vfork, or thread
creation.

Every executable starts the real `mithril-node`, performs one operator-driven
case, and removes its test tasks, BPF pins, lease, temporary config, state, and
logs on success or failure. `identity-runtime.sh` contains only that shared
lifecycle and cleanup. No script removes a supplied container, Pod, or CRI
sandbox because it did not create them.

For automated privileged identity and local-effect evidence, use the separate
[VM e2e harness](../../crates/mithril-e2e/harness/vm/README.md).

The complete identity catalog is split only to keep the tables readable:

- [entry and container-runtime cases](./container-entry-catalog.md)
- [native identity and authorization cases](./native-identity-catalog.md)

These scripts do not pretend to cover every catalog row. Race injection,
saturation, reuse, lifecycle hooks, and the remaining Kubernetes behavior still
require their applicable qualification setup.
