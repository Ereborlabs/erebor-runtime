# Phase 6.2 Closure Matrix

- Phase: [Control Policy And Evidence Convergence](./phase-6-2-control-policy-and-evidence-convergence.md)
- Architecture: [validated readable architecture](./policy-and-protection-algorithm-architecture-readable.md)
- Manual acceptance: [Phase 6.2 runbook](./manual-testing/phase-6-2-manual-acceptance.md)
- Implementation review: [Phase 6.2 review guide](./phase-6-2-implementation-review.md)

## Closure Decision

Phase 6.2 is **In progress**. Deliverables D6.2.1-D6.2.8 keep their recorded
automated result. Deliverables D6.2.9-D6.2.12 reopen the phase for Kubernetes
node eligibility, workload admission, scheduler binding, exact-node policy
delivery, and runtime-start ordering.

The amendment is not closed by CRD reconciliation alone. A result is complete
only when a matching Pod can be scheduled by the Kubernetes scheduler onto a
node derived from the live `mithril-node` DaemonSet, and the exact initial
container process remains held until that node activates the Pod's exact
policy and cgroup binding.

## Authority Corrections

| Decision | Authority | Non-authority |
| --- | --- | --- |
| Which nodes can host protected Pods | The live `mithril-node` DaemonSet Pod template defines node selector and required node affinity. Control derives and verifies them. | A second Mithril node-pool selector, a static node list, or a profile field. |
| Which exact node receives a Pod | The Kubernetes scheduler chooses one node from the combined Pod and Mithril constraints. | Mithril admission, Control rollout, or `mithril-node`. |
| Which Pods are protected | One `WorkloadProtectionProfile` in the Pod's namespace matches the Pod and container facts. | A separate protected-tenant or protected-namespace scope setting. Configured tenant and cluster IDs bind provenance only. |
| Whether a node can receive a new protected Pod | Control verifies the authenticated node session, current boot, BPF and identity readiness, and DaemonSet eligibility. It projects the result as a ready label and quarantine-taint removal. | A self-applied node label, DaemonSet Pod readiness alone, or stale Node status. |
| Which node receives policy | The persisted Pod UID and scheduler-selected `spec.nodeName` create one immutable rollout target. | Cluster-wide broadcast, all DaemonSet nodes, or admission-time prediction. |
| Whether the initial process can start | The selected `mithril-node` verifies the exact OCI prestart request, active policy generation, and cgroup binding before it releases the held process. | Pod admission success, scheduler binding success, Control status, or policy download alone. |

## Deliverable Closure

| Deliverable | Current result | Evidence required to close |
| --- | --- | --- |
| `D6.2.1` | Closed by the prior source result. | Keep the CRD schema, canonical source, and strict validation tests green. |
| `D6.2.2` | Closed by the prior source result. | Keep desired-state, compilation, signer, restart, and invalid-update tests green. The namespace configuration must no longer select protected Pods. |
| `D6.2.3` | Closed for static registered inventory. Reopened for scheduler-bound inventory. | Prove that a new or removed bound Pod changes the immutable target snapshot without a policy-source change. Prove exact-node selection and stale-target rejection. |
| `D6.2.4` | Closed for signed node transfer and activation. Reopened for dynamic Kubernetes binding material. | Prove that the candidate carries exact scheduled workload material and that another node, boot, Pod, or container cannot consume it. |
| `D6.2.5` | Closed by the prior source result. | Keep durable evidence transaction and acknowledgement tests green. |
| `D6.2.6` | Closed for prior rollout and intake recovery. Reopened for node and workload lifecycle recovery. | Prove Control restart, node reconnect, boot change, Pod deletion, container restart, and profile retirement without authority reuse. |
| `D6.2.7` | Closed for prior status and limits. Reopened for admission, node readiness, and cluster-wide profile discovery. | Prove bounded admission requests, least-privilege RBAC, session expiry, secret filtering, and status-is-not-authority. |
| `D6.2.8` | Closed for the deterministic prior Control proof. Reopened for the complete scheduling-to-runtime transaction. | Prove the two-node scheduler choice, exact-node delivery, held initial process, active binding readback, and fail-closed timeout. |
| `D6.2.9` | Not done. | Implement DaemonSet-derived eligibility, Node quarantine admission, authenticated node-name binding, readiness projection, loss handling, and tests. |
| `D6.2.10` | Not done. | Implement matching-profile Pod admission, additive scheduling constraints, bypass rejection, scheduler-binding validation, persisted Pod observation, and tests. |
| `D6.2.11` | Not done. | Implement immutable bound-workload targets, signed binding material, exact-node node configuration, OCI prestart admission, cgroup publication, runtime release, and tests. |
| `D6.2.12` | Not done. | Package webhooks, TLS, RBAC, taint toleration, node identity, hook adapter, health, automated acceptance, and the physical runbook result. |

## Automated Proof Matrix

| Seam | Positive proof | Negative oracle |
| --- | --- | --- |
| DaemonSet derivation | Selector and required affinity accept the same labeled nodes as the supported DaemonSet template. | Unsupported or changed constraints do not leave a stale ready projection. |
| Node quarantine | A matching node stays tainted until its authenticated current-boot session reports complete readiness. | A missing, stale, wrong-name, wrong-boot, or unhealthy session cannot remove the taint. |
| Pod match | One same-namespace profile match produces a protected admission result. | Zero matches do not mutate the Pod. Multiple matches reject it. |
| Pod scheduling constraints | Existing Pod constraints and derived Mithril constraints are combined, and the scheduler can choose either of two eligible ready nodes. | `nodeName`, quarantine toleration, conflicting mutation input, and stale ready state reject. |
| Scheduler binding | A binding to an eligible ready node with the current session succeeds. | A binding to another node, UID, boot, or stale session rejects. |
| Workload target | Persisted Pod UID, selected node, controller, ServiceAccount, container, and digest create one immutable exact target. | Pod deletion, UID reuse, node change, or container change retires the old target. |
| Policy delivery | Only the selected node can inventory, fetch, verify, and acknowledge the target-bound candidate. | Every other node and boot rejects the candidate even when it has the same profile artifact. |
| Runtime gate | The held OCI initial PID is released after policy activation and exact cgroup binding readback. | Missing candidate, wrong annotations, PID or cgroup mismatch, timeout, disconnect, and restart reject without release. |
| Retirement | A signed restrictive successor replaces the exact active target. | CRD deletion, API loss, or Control loss cannot erase the last valid local generation. |

## Physical Proof Matrix

The physical result must use the current stock Kubernetes and OCI runtime
extension points. It must record their versions and exact configuration.

| Scenario | Required observation |
| --- | --- |
| New eligible node | The Node receives the quarantine taint before protected scheduling. The DaemonSet starts, registers, proves readiness, and Control removes the taint. |
| Two eligible nodes | The scheduler, not Mithril, selects either ready node. Only that node inventories and activates the candidate. |
| Unready node | A matching node without a ready `mithril-node` session remains quarantined and receives no protected Pod. |
| Protected start | The OCI prestart hook holds the initial PID. No application instruction runs before exact policy and binding activation. |
| Gate failure | A stopped node service or unavailable candidate causes the stock runtime to report start failure after the bounded timeout. |
| Lifecycle | Container restart creates a new exact binding. Pod deletion and UID reuse cannot reuse the old binding. |
| Selector change | A DaemonSet constraint change updates node eligibility without a second selector configuration. |

No physical result is recorded yet.

## Verification State

The planning amendment and this matrix have passed `git diff --check`. No code,
automated test, cluster test, or physical runtime-gate result is claimed by
this matrix. Each implementation commit must record its focused command. The
final source state must pass:

```sh
rtk bash .github/scripts/verify-rust-ci.sh
```

## Unadvertised Work

This phase does not add the Phase 8 privileged or unmatched-workload floor. A
Pod with no matching profile stays outside this protected scheduling flow.
This phase also does not claim Kubernetes audit causality, graph edges,
findings, response actuation, an eviction guarantee for running Pods after a
`NoSchedule` taint, or boot protection before Node admission can run.
