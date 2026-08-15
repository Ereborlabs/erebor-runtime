# Native Identity Manual Cases

These are operator-driven checks against the real `mithril-node`. They are not
commands for manually invoking the automated e2e runner.

Build the real node and inspector once:

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
| `nsenter` and cgroup movement | `sudo examples/mithril-identity-manual/nsenter-move.sh NODE_CONFIG CONTAINER_OR_FULL_CRI_ID` |
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
