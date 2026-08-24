# Kubernetes Policy Convergence Manual Case

Status: The case is implemented. The current source has not passed this manual
case.

The last physical attempt used the old API and stopped after stock `runc` used
anonymous-file and IPC bootstrap operations that have no typed authority. Do
not treat this result as test noise. Do not add a broad runtime exception.

This case uses the production Kubernetes API, admission webhooks, scheduler,
Control service, node DaemonSet, OCI prestart hook, policy compiler, exception
authority, and node policy inspector. It does not call an automated test.

The case creates one namespace, one `WorkloadProtectionPolicy`, one
`WorkloadProtectionException`, two RuntimeClasses, and two protected Pods. It
uses separate policy-writer and exception-writer identities. It verifies the
Control and node RBAC boundaries, server-side Pod mutation, direct-node bypass
rejection, scheduler-selected placement, selected-node-only policy delivery,
base-policy denial, exact-node exception activation, one-use consumption,
exception revocation, unused-exception retirement after Pod disappearance, a
held protected start, fail-closed hook failure, and a new binding for a
restarted container. It then closes the terminal policy chain, restarts
Control and the selected node process, proves that the old root does not
replay, and proves that a recreated policy starts from a new root activation.

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
names the scheduler-selected Nodes and two different container lifetime IDs.
It also records the custom resource, writer separation, exact-target,
exception, terminal-cleanup, restart, and fresh-root oracles. The command
returns nonzero if admission sets `spec.nodeName`, accepts the direct-node
bypass, delivers authority to another Node, fails to enforce the base denial,
permits more than one exception use, refunds an unused exception after target
disappearance, releases a container without its exact binding, permits start
without the runtime gate, reuses the first runtime binding, replays a closed
root, or gives a recreated policy a predecessor-bound candidate.

The EXIT trap removes the namespace, both RuntimeClasses, all case marker
files, and the private temporary directory on success, failure, or
interruption. The namespace owns both CRDs, the service accounts, the role
bindings, and the Pods. After a pass, these commands must report no resources:

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
