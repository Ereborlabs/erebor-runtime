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
| `nsenter` and cgroup movement | `sudo examples/mithril-identity-manual/nsenter-move.sh NODE_CONFIG CONTAINER_OR_FULL_CRI_ID` |
| Node restart | `sudo examples/mithril-identity-manual/restart.sh NODE_CONFIG CONTAINER_OR_FULL_CRI_ID` |

Kubernetes is optional, not excluded: only `kubernetes-exec.sh` requires it.
The Docker case derives a trusted test-only configured cgroup binding from
`docker inspect`. CRI and Kubernetes cases require the full live container ID
and its exact test profile assignment in `workload_bindings`; the temporary
config deliberately removes `root_cgroup_path` so `mithril-node` must resolve,
validate, and reconcile the live cgroup through CRI.

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
