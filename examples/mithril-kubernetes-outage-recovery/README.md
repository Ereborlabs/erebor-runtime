# Kubernetes Control Outage Recovery Example

This example uses the installed Mithril release through normal Kubernetes
operations. It creates two protected Pods, one on each Ready Node. The example
then stops the Control Deployment and proves these behaviors:

- Both existing Pods keep the last valid local denial.
- Kubernetes rejects a new protected Pod while Control is unavailable.
- Both existing Pods keep the same identity after Control recovers.
- The Control PVC keeps every unconsumed evidence segment across the restart.

The example does not create, select, or remove VMs. It also does not replace
the installed Mithril release.

Run the lightweight outage tests from the repository host first:

```bash
rtk cargo test -p mithril-node --lib kubernetes_outage
rtk cargo test -p mithril-control --lib kubernetes_outage
rtk cargo test -p mithril-control --test control_policy_reconciliation kubernetes_outage
rtk cargo test -p mithril-e2e --lib kubernetes_outage
```

Create the manual two-node environment on the host:

```bash
crates/mithril-e2e/harness/vm/manual.sh start-convergence
crates/mithril-e2e/harness/vm/manual.sh ssh-convergence
```

Run the example in the first guest:

```bash
sudo -i
. /var/tmp/mithril-convergence-manual.env
cd "$MITHRIL_MANUAL_SOURCE"
examples/mithril-kubernetes-outage-recovery/run.sh
```

The exit path restores the Control replica count and removes the namespace,
RuntimeClass, and Node labels that the example owns.

The example records the SHA-256 manifest before the outage. After recovery,
it requires every old segment to remain. New node uploads can add segments.

After the example completes, remove the two manual VMs from the host:

```bash
crates/mithril-e2e/harness/vm/manual.sh destroy-convergence
```

The automated `mithril-e2e` qualification also covers a selected-worker
network partition, a mixed policy rollout, and a Kubernetes API outage. Those
provider-level cases are not part of this operator example.
