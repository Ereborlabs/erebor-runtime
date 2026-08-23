# Phase 6.2 Closure Matrix

- Phase: [Control Policy And Evidence Convergence](./phase-6-2-control-policy-and-evidence-convergence.md)
- Architecture: [validated readable architecture](./policy-and-protection-algorithm-architecture-readable.md)
- Manual acceptance: [Phase 6.2 runbook](./manual-testing/phase-6-2-manual-acceptance.md)
- Implementation review: [Phase 6.2 review guide](./phase-6-2-implementation-review.md)

## Closure Decision

Phase 6.2 is **Blocked**. Source implementation and automated acceptance for
D6.2.1-D6.2.12 passed. Physical Kubernetes acceptance reached scheduler
binding, selected-node delivery, policy activation, runtime binding, and
durable evidence intake. Stock `runc` container start failed because its
bootstrap uses an anonymous file write and IPC access that have no typed
authority. The validated architecture requires an approved runtime-bootstrap
authority and forbids a broad runtime exception.

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
| `D6.2.1` | Source and automated proof: **Done**. | No new physical result is required for the closed API schema. |
| `D6.2.2` | Source and automated proof: **Done**. | No new physical result is required for deterministic desired-state reconciliation. |
| `D6.2.3` | Scheduler-bound source inventory and physical exact-node proof: **Done**. | No additional proof is required for scheduler-bound inventory. |
| `D6.2.4` | Dynamic signed binding material and physical selected-node delivery: **Done**. | No additional proof is required for exact-node delivery. |
| `D6.2.5` | Source, automated proof, and physical durable evidence intake: **Done**. | Run the failure and replay variants after the runtime-bootstrap decision. |
| `D6.2.6` | Node and workload lifecycle recovery source and automated proof: **Done**. | Run the physical restart, reconnect, boot-change, deletion, and retirement cases. |
| `D6.2.7` | Admission, readiness, cluster-wide discovery, and RBAC source proof: **Done**. | Run the live API-server, session-expiry, RBAC-denial, and secret-filtering cases. |
| `D6.2.8` | Automated transaction and physical convergence through runtime binding: **Blocked**. | Approve runtime-bootstrap authority, then prove protected process start and lifecycle with stock `runc`. |
| `D6.2.9` | Source, automated proof, and physical node readiness: **Done**. | Run readiness-loss and DaemonSet-selector variants after the runtime-bootstrap decision. |
| `D6.2.10` | Source, automated proof, and physical Pod admission and scheduler binding: **Done**. | No additional proof is required for admission and initial scheduler binding. |
| `D6.2.11` | Source proof, exact-node delivery, activation, and runtime binding: **Blocked**. | Approve runtime-bootstrap authority, then prove process release, restart, and timeout behavior. |
| `D6.2.12` | Packaging, automated proof, and physical chart installation: **Blocked**. | Complete protected start and the remaining manual cases after the runtime-bootstrap decision. |

## Automated Proof Matrix

| Seam | Positive proof | Negative oracle |
| --- | --- | --- |
| DaemonSet derivation | Selector and required affinity accept the same labeled nodes as the supported DaemonSet template. | Unsupported or changed constraints do not leave a stale ready projection. |
| Node quarantine | A matching node stays tainted until its authenticated current-boot session reports complete readiness. | A missing, stale, wrong-name, wrong-UID, wrong-boot, or unhealthy session cannot remove the taint. A replacement Node cannot inherit readiness by name. |
| Pod match | One same-namespace profile match produces a protected admission result. | Zero matches do not mutate the Pod. Multiple matches and caller-supplied Mithril annotations reject. |
| Pod scheduling constraints | Existing Pod constraints and derived Mithril constraints are combined, and the scheduler can choose either of two eligible ready nodes. | `nodeName`, quarantine toleration, conflicting mutation input, excessive affinity expansion, and stale ready state reject. |
| Pod update | A protected Pod keeps its admitted policy identity and digest-pinned matching containers. | An unprotected scheduled Pod cannot enter a profile through an update. A protected Pod cannot change its profile identity through a Pod or ephemeral-container update. |
| Scheduler binding | A binding to an eligible ready node with the current session succeeds. | A binding to another node, UID, boot, or stale session rejects. |
| Workload target | Persisted Pod UID, selected node, controller, ServiceAccount, container, and digest create one immutable exact target. | Pod deletion, UID reuse, node change, or container change retires the old target. |
| Policy delivery | Only the selected node can inventory, fetch, verify, and acknowledge the target-bound candidate. | Every other node and boot rejects the candidate even when it has the same profile artifact. |
| Runtime gate | The held OCI initial PID is released after policy activation and exact cgroup binding readback. | Missing candidate, wrong policy annotations, PID or cgroup mismatch, timeout, disconnect, active socket-owner replacement, and restart reject without release. |
| Retirement | A signed restrictive successor replaces the exact active target. A complete relist retires a durable source that disappeared. | A partial relist, historical event, CRD deletion, API loss, or Control loss cannot erase the last valid local generation. |

## Physical Proof Matrix

The physical result must use the current stock Kubernetes and OCI runtime
extension points. It must record their versions and exact configuration.

| Scenario | Result | Observation |
| --- | --- | --- |
| New eligible node | **Pass** | Each matching Node started quarantined. Its DaemonSet Pod registered and proved readiness before Control removed the taint. |
| Two eligible nodes | **Pass** | Kubernetes selected the worker. Only that node received and activated the exact candidate. |
| Unready node | **Not run** | The run did not remove one node session after initial readiness. |
| Protected start | **Fail** | Policy activation and runtime binding completed. Stock `runc` then used an anonymous file write and IPC access with no typed authority. The runtime reported start failure, and the application did not run. |
| Gate failure | **Not run** | The protected-start failure stopped the procedure before this case. |
| Lifecycle | **Not run** | The protected-start failure stopped the procedure before restart and UID-reuse cases. |
| Selector change | **Not run** | The protected-start failure stopped the procedure before this case. |

The procedure cleanup removed the test namespace and runtime classes. Control
accepted the denial evidence before the node truncated the related WAL data.

## Verification State

The following checks passed:

```sh
bash .github/scripts/verify-rust-ci.sh
# Passed the repository format, check, clippy, and full workspace test gate.

bash packaging/mithril/helm/tests/verify.sh
# Passed chart lint and the rendered packaging contract.

cargo test -p mithril-control --test kubernetes_policy_api
# 5 passed.

cargo test -p mithril-e2e --lib
# 70 passed in the final repository gate.

cargo test -p mithril-node --lib
# 129 passed in the final repository gate.

cargo test -p mithril-node --bin mithril-oci-hook
# 2 passed in the final repository gate.
```

The first review gate exposed test-only strict-Clippy failures. The test was
corrected, and the complete gate passed. The final Control unit-test count was
63. An earlier complete gate had one transient browser discovery failure with
`WouldBlock`; the isolated test and the next complete gate passed.

The live cluster case passed through runtime binding and durable evidence
intake. The stock-runtime protected-start case failed. Automated tests do not
change the remaining physical cases from `Not run` to `Pass`.

## Unadvertised Work

This phase does not add the Phase 8 privileged or unmatched-workload floor. A
Pod with no matching profile stays outside this protected scheduling flow.
This phase also does not claim Kubernetes audit causality, graph edges,
findings, response actuation, an eviction guarantee for running Pods after a
`NoSchedule` taint, or boot protection before Node admission can run.
