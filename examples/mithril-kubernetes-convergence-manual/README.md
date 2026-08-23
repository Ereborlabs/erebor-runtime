# Kubernetes Policy Convergence Manual Case

Status: The case is implemented. The current source has not passed this manual
case.

This case uses the production Kubernetes API, admission webhooks, scheduler,
Control service, node DaemonSet, OCI prestart hook, policy compiler, and node
policy inspector. It does not call an automated test.

The case creates one namespace, one policy, two RuntimeClasses, and two
protected Pods. It verifies the Control and node RBAC boundaries, server-side
Pod mutation, direct-node bypass rejection, scheduler-selected placement,
selected-node-only policy delivery, a held protected start, fail-closed hook
failure, and a new binding for a restarted container.

## Start The Environment

From the repository worktree on the host, run:

```bash
crates/mithril-e2e/harness/vm/manual.sh start-convergence
crates/mithril-e2e/harness/vm/manual.sh ssh-convergence
```

The first command creates two retained K3s VMs and installs the production
Mithril chart. The second command opens a shell in the first VM. The repository
is mounted read-only at `/mnt/mithril-source`.

## Prepare The Guest

In the guest, run:

```bash
sudo -i
. /var/tmp/mithril-convergence-manual.env
cd "$MITHRIL_MANUAL_SOURCE"

command -v kubectl jq sed
test -x "$MITHRIL_BIN_DIRECTORY/mithril-policy"
kubectl get --raw=/readyz
kubectl get nodes -o wide
kubectl -n mithril-system get pods -o wide
```

The API readiness command must succeed. At least two Mithril node Pods and the
Control Pod must be Ready.

## Run The Case

From the same root guest shell, run this exact command:

```bash
examples/mithril-kubernetes-convergence-manual/run.sh
```

The command must print one JSON object with `"result": "PASS"`. The object
names the scheduler-selected Node and two different container lifetime IDs.
The command returns nonzero if admission sets `spec.nodeName`, accepts the
direct-node bypass, delivers policy to another Node, releases a container
without its exact binding, permits start without the runtime gate, or reuses
the first container lifetime.

The EXIT trap removes the namespace, both RuntimeClasses, Pod marker files, and
the private temporary directory on success, failure, or interruption. After a
pass, these commands must report no resources:

```bash
kubectl get namespace mithril-convergence-manual
kubectl get runtimeclass mithril-convergence-manual
kubectl get runtimeclass mithril-convergence-manual-fail
```

Each command must return `NotFound`.

## Remove The Environment

Leave the guest. From the same worktree on the host, run:

```bash
crates/mithril-e2e/harness/vm/manual.sh destroy-convergence
```

The harness checks both ownership records before it removes the VMs and their
local work directories.

This case proves the documented two-node K3s and containerd path. It does not
qualify another Kubernetes distribution, CRI implementation, OCI runtime,
architecture, CNI, or admission-hook manager.
