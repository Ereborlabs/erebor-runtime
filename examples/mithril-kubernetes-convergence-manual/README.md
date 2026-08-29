# Kubernetes Policy Convergence Manual Case

Status: Pass. On 2026-08-29, the current source passed this case on two K3s
nodes with Kubernetes v1.35.5+k3s1 and containerd v2.2.3-k3s1. The case used
the stock runtime and the `PreparedContainer` boundary.

This case uses the production Kubernetes API, admission webhooks, scheduler,
Control service, node DaemonSet, two ordered OCI `createRuntime` hooks, policy
compiler, exception authority, and node policy inspector. It does not call an
automated test.

The case creates one namespace, one `WorkloadProtectionPolicy`, one
`WorkloadProtectionException`, two RuntimeClasses, and two protected Pods. It
uses separate policy-writer and exception-writer identities. It verifies the
Control and node RBAC boundaries, server-side Pod mutation, direct-node bypass
rejection, scheduler-selected placement, selected-node-only policy delivery,
base-policy denial, exact-node exception activation, one-use consumption,
exception revocation, unused-exception retirement after Pod disappearance, a
held protected start, fail-closed hook failure, and a new binding for a
restarted container. It then removes the Pod, waits for runtime absence and
desired-inventory cleanup, restarts Control and the selected node process,
proves that stale policy does not replay, and proves that a recreated policy
starts from a new root activation.

## Start The Environment

From the repository worktree on the host, run:

```bash
crates/mithril-e2e/harness/vm/manual.sh start-convergence
crates/mithril-e2e/harness/vm/manual.sh ssh-convergence
```

The first command creates two retained K3s VMs and installs the production
Mithril chart. The second command opens a shell in the first VM. The repository
is mounted read-only at `/mnt/mithril-source`.

To reset VMs from a completed automated run, use its retained-environment
record:

```bash
crates/mithril-e2e/harness/vm/two-node-convergence.sh \
  --reuse-environment <result-directory>/retained-environment.json \
  --manual-environment --output-directory <new-result-directory>
```

This command removes the previous release and state before it installs the
current release. It stages the manual example under
`/var/tmp/mithril-convergence-manual-source` in node A. It does not require a
source mount and does not create another VM.

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
entry-role, exception, desired-inventory cleanup, restart, and fresh-root
oracles. The command
returns nonzero if admission sets `spec.nodeName`, accepts the direct-node
bypass, delivers authority to another Node, fails to enforce the base denial,
permits more than one exception use, refunds an unused exception after target
disappearance, releases a container without its exact prepared binding,
permits start without the runtime gate, reuses the first runtime binding,
replays stale policy after runtime absence, carries prepared-runtime IPC into
the application, or gives a recreated policy a predecessor-bound candidate.

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
