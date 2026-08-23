# Phase 6.2 Closure Matrix

- Phase: [Control Policy And Evidence Convergence](./phase-6-2-control-policy-and-evidence-convergence.md)
- Architecture: [validated readable architecture](./policy-and-protection-algorithm-architecture-readable.md)
- Manual acceptance: [Phase 6.2 runbook](./manual-testing/phase-6-2-manual-acceptance.md)
- Implementation review: [Phase 6.2 review guide](./phase-6-2-implementation-review.md)

## Closure Decision

Phase 6.2 is **Not done**. The approved API correction replaces the flattened
`WorkloadProtectionProfile` with a capability-grounded
`WorkloadProtectionPolicy` and a separate bounded
`WorkloadProtectionException`. The branch does not implement those resources,
their lowering, or their complete fixtures. The previous API proof does not
close the corrected design.

The earlier physical Kubernetes run remains partial evidence. It reached
scheduler binding, selected-node delivery, policy activation, runtime binding,
and durable evidence intake. Stock `runc` container start then failed because
its bootstrap uses an anonymous file write and IPC access that have no typed
authority. The architecture still requires an approved runtime-bootstrap
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
| Which Pods are protected | One `WorkloadProtectionPolicy` in the Pod's namespace matches the Pod, and every Pod container matches exactly one policy container entry. | A separate protected-tenant or protected-namespace setting, an unmatched container, or overlapping base policies. Configured tenant and cluster IDs bind provenance only. |
| Which exception can widen policy | One `WorkloadProtectionException` names a base-policy file grant, exact Pod UID, matching container, bounded duration, and bounded uses. Control resolves the precompiled cells and exact active generation. | A user approval proof, compiled key, policy digest, node target, network or IPC rule, or an exception outside the base grant. |
| Whether a node can receive a new protected Pod | Control verifies the authenticated node session, current boot, BPF and identity readiness, and DaemonSet eligibility. It projects the result as a ready label and quarantine-taint removal. | A self-applied node label, DaemonSet Pod readiness alone, or stale Node status. |
| Which node receives policy | The persisted Pod UID and scheduler-selected `spec.nodeName` create one immutable rollout target. | Cluster-wide broadcast, all DaemonSet nodes, or admission-time prediction. |
| Whether the initial process can start | The selected `mithril-node` verifies the exact OCI prestart request, active policy generation, and cgroup binding before it releases the held process. | Pod admission success, scheduler binding success, Control status, or policy download alone. |

## Deliverable Closure

| Deliverable | Current result | Evidence required to close |
| --- | --- | --- |
| `D6.2.1` | Corrected API design: **Not done**. | Implement both structural CRDs, strict public schemas, bounded status, offline policy form, and public-to-internal golden. Prove that internal-only fields reject. |
| `D6.2.2` | Corrected desired-state owner: **Not done**. | Reconcile both source kinds, lower base-policy grants, enforce separate exception-writer RBAC, and prove deterministic restart and relist behavior. |
| `D6.2.3` | Prior scheduler-bound inventory proof is reusable; corrected provenance: **Not done**. | Bind the base-policy source to one exact target snapshot and bind each exception source to the active base-policy generation, grant, Pod, container, Node, and boot. |
| `D6.2.4` | Prior selected-node delivery proof is reusable; corrected candidate contract: **Not done**. | Deliver and acknowledge base-policy candidates and separate bounded exception activation or revocation candidates. |
| `D6.2.5` | Durable intake happy path is proven; required failure variants: **Not done**. | Run physical failure, replay, reordering, backpressure, restart, and WAL-truncation variants. |
| `D6.2.6` | Existing policy lifecycle proof is reusable; exception lifecycle: **Not done**. | Prove policy retirement plus exception consumption, expiry, revocation, deletion, replay rejection, restart, reconnect, and boot change. |
| `D6.2.7` | Existing readiness and RBAC proof is reusable; corrected status and RBAC: **Not done**. | Prove standard bounded status for both resources, no digest or receipt exposure, separate operator rights, Control status-only writes, and live RBAC denials. |
| `D6.2.8` | Corrected end-to-end transaction: **Not done**. | Prove policy and exception convergence, then resolve runtime bootstrap and prove protected process start and lifecycle with stock `runc`. |
| `D6.2.9` | Initial node readiness is proven; required lifecycle variants: **Not done**. | Run readiness loss, stale session, boot change, Node UID replacement, restart, and DaemonSet-selector variants. |
| `D6.2.10` | Prior Pod admission and scheduler binding proof is reusable; corrected policy matching: **Not done**. | Prove one policy match, exactly one container-entry match for every container, image pinning, absent-field rejection, and unchanged scheduler choice. |
| `D6.2.11` | Prior exact-node delivery, activation, and runtime binding proof is reusable: **Not done**. | Prove corrected policy delivery and exception activation without base-generation migration, then resolve runtime bootstrap and prove process release, restart, and timeout behavior. |
| `D6.2.12` | Prior chart installation proof is obsolete for the API package: **Not done**. | Package and physically test both CRDs, corrected RBAC, manual examples, protected start, lifecycle, and cleanup. |

## Automated Proof Matrix

| Seam | Positive proof | Negative oracle |
| --- | --- | --- |
| Public policy schema | The stored `WorkloadProtectionPolicy.spec` and offline form lower to the same internal policy. | Unknown, internal-only, unqualified, oversized, or conflicting fields reject before a candidate exists. |
| Static roles and effects | Exactly matched containers receive initial or conservative external roles, and supported path, address, Unix-stream, signal, and ptrace rules lower to exact cells. | Native transitions, semantic token or image targets, service destinations, device, privilege, mount, finding, response, proof, errno, or node-selector fields reject. Recursive allow rejects until physical qualification. |
| Bounded exception | An API-server-authorized request activates one precompiled file grant for the exact Pod and container without migrating the base generation, within the duration and use limits. | Wrong writer, policy generation, grant, Pod UID, container, Node, boot, duration, uses, rule family, stale object, overlap, replay, or user-supplied authority material rejects. |
| DaemonSet derivation | Selector and required affinity accept the same labeled nodes as the supported DaemonSet template. | Unsupported or changed constraints do not leave a stale ready projection. |
| Node quarantine | A matching node stays tainted until its authenticated current-boot session reports complete readiness. | A missing, stale, wrong-name, wrong-UID, wrong-boot, or unhealthy session cannot remove the taint. A replacement Node cannot inherit readiness by name. |
| Pod match | One same-namespace policy match and exactly one container-entry match for every container produce a protected admission result. | Zero policy matches do not mutate the Pod. Multiple policies, unmatched or multiply matched containers, mutable image matches, and caller-supplied Mithril annotations reject. |
| Pod scheduling constraints | Existing Pod constraints and derived Mithril constraints are combined, and the scheduler can choose either of two eligible ready nodes. | `nodeName`, quarantine toleration, conflicting mutation input, excessive affinity expansion, and stale ready state reject. |
| Pod update | A protected Pod keeps its admitted policy identity and digest-pinned matching containers. | An unprotected scheduled Pod cannot enter a policy through an update. A protected Pod cannot change its policy identity through a Pod or ephemeral-container update. |
| Scheduler binding | A binding to an eligible ready node with the current session succeeds. | A binding to another node, UID, boot, or stale session rejects. |
| Workload target | Persisted Pod UID, selected node, controller, ServiceAccount, container, and digest create one immutable exact target. | Pod deletion, UID reuse, node change, or container change retires the old target. |
| Policy delivery | Only the selected node can inventory, fetch, verify, and acknowledge the target-bound candidate. | Every other node and boot rejects the candidate even when it has the same signed policy artifact. |
| Runtime gate | The held OCI initial PID is released after policy activation and exact cgroup binding readback. | Missing candidate, wrong policy annotations, PID or cgroup mismatch, timeout, disconnect, active socket-owner replacement, and restart reject without release. |
| Retirement | A signed restrictive successor replaces the exact active base target. A complete relist retires a durable base source. A signed exception revocation closes only its runtime instance. | A partial relist, historical event, API loss, Control loss, or recreated exception cannot erase the last valid base generation or restore consumed authority. |

## Physical Proof Matrix

The physical result must use the current stock Kubernetes and OCI runtime
extension points. It must record their versions and exact configuration.
The observations below used the superseded flattened CRD. They remain evidence
for the node, scheduler, delivery, runtime-gate, and intake seams, but they do
not prove either corrected CRD.

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

## Previous Verification State

The following checks passed before the API correction:

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

These commands do not prove the corrected public schemas, lowering, exception
resource, status, RBAC, package, or examples. They must run again after the
implementation changes. The previous live cluster case passed through runtime
binding and durable evidence intake. The stock-runtime protected-start case
failed. Automated tests do not change the remaining physical cases from `Not
run` to `Pass`.

## Unadvertised Work

This phase does not add the Phase 8 privileged or unmatched-workload floor. A
Pod with no matching policy stays outside this protected scheduling flow.
This phase also does not claim Kubernetes audit causality, graph edges,
findings, response actuation, an eviction guarantee for running Pods after a
`NoSchedule` taint, or boot protection before Node admission can run.

The Kubernetes policy API does not expose native transitions or states,
devices, capability or BPF grants, mount grants, semantic token or image
targets, Kubernetes Service or DNS destinations, non-Unix-stream IPC, positive
general ptrace, audit or finding configuration, response actions, arbitrary
errno, user capability or proof IDs, node selectors, or exceptions outside a
named base-policy file grant.
