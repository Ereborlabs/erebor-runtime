# Phase 6.2 Closure Matrix

- Phase: [Control Policy And Evidence Convergence](./phase-6-2-control-policy-and-evidence-convergence.md)
- Architecture: [validated readable architecture](./policy-and-protection-algorithm-architecture-readable.md)
- Manual acceptance: [Phase 6.2 runbook](./manual-testing/phase-6-2-manual-acceptance.md)
- Implementation review: [Phase 6.2 review guide](./phase-6-2-implementation-review.md)

## Closure Decision

Phase 6.2 is **Not done**. The approved API correction replaces the flattened
`WorkloadProtectionProfile` with a capability-grounded
`WorkloadProtectionPolicy` and a separate bounded
`WorkloadProtectionException`. The branch now implements both resources,
their lowering, their durable Control and node lifecycles, and current
automated and manual fixture flows. The current source has not passed the
physical procedure.

The earlier physical Kubernetes run remains partial evidence. It reached
scheduler binding, selected-node delivery, policy activation, runtime binding,
and durable evidence intake. Stock `runc` container start then failed because
its bootstrap uses an anonymous file write and IPC access that have no typed
authority. The approved `RuntimeBootstrap` design is now part of the
architecture and phase plan. It is not implemented or physically proved yet.

The amendment is not closed by custom resource reconciliation alone. A result
is complete only when a matching Pod can be scheduled by the Kubernetes
scheduler onto a node derived from the live `mithril-node` DaemonSet, and the
exact initial container process remains held until that node activates the
Pod's exact policy and cgroup binding. The complete current physical flow must
also pass retirement, restart, Node UID replacement, host epoch, cleanup, and
fresh-root checks.

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
| Which bootstrap effects can occur | BPF grants the internal `RuntimeBootstrap` identity only to the exact held initial entry, fixed operation classes, and anonymous objects created by that entry before the deadline. | A CRD field, path-backed file, network destination, another entry or container, later external root, or post-handoff process. |

## Deliverable Closure

| Deliverable | Current result | Evidence required to close |
| --- | --- | --- |
| `D6.2.1` | **Implemented and automated.** | The two generated structural CRDs, strict schemas, bounded status, offline policy form, lowering golden, and internal-field rejection tests pass. Physical API installation remains unverified. |
| `D6.2.2` | **Implemented and automated.** | One desired-state owner reconciles both source kinds. The store proves atomic source and artifact acceptance, restart, complete relist retirement, partial relist safety, and separate exception retirement. |
| `D6.2.3` | **Implemented and automated.** | API-only workload inventory binds exact scheduler, Pod, container, Node, Node UID, boot, and label facts. Node claims cannot create a Kubernetes target. |
| `D6.2.4` | **Implemented and automated.** | Policy and exception candidates use bounded chain-ordered delivery, resumable transfer, exact acknowledgements, rejection recovery, and terminal cleanup authorization. |
| `D6.2.5` | **Partial.** | Automated intake failure, duplicate, gap, reorder, replay, storage, restart, and WAL migration tests pass. The required physical evidence variants remain `Not run`. |
| `D6.2.6` | **Implemented and automated; physical result not done.** | Tests cover policy target shrink, restrictive retirement, terminal closure, exception use, expiry, revocation, target disappearance, restart, reconnect, and physical-session settlement. Run the current physical lifecycle. |
| `D6.2.7` | **Implemented and automated; physical result not done.** | Both statuses are bounded and contain no authority material. Separate writer roles and Control status-only permissions are rendered and exercised by typed authorization reviews. Run them against the current installed CRDs. |
| `D6.2.8` | **Blocked at physical protected start.** | Implement the approved stock-runtime bootstrap authority. Then run the complete current policy and exception transaction through application start and cleanup. |
| `D6.2.9` | **Implemented and scripted; physical result not done.** | Automated tests cover session expiry, reconnect, Node UID rebind, boot and label reset, and startup absence proof. The physical fixture scripts quarantine, UID replacement, selector re-entry, process restart, and host reboot. Run the fixture. |
| `D6.2.10` | **Implemented and automated; physical result not done.** | Policy and container matching, immutable image pins, Pod mutation, update validation, binding validation, and scheduler choice tests pass. Run the current physical admission flow. |
| `D6.2.11` | **Implemented and automated; physical result blocked.** | Exact selected-node delivery, activation, cgroup binding, cancellation rollback, runtime lifetime replacement, terminal cleanup, and timeout tests pass. Stock-runtime process release still needs the approved bootstrap authority and a physical pass. |
| `D6.2.12` | **Implemented and rendered; physical result not done.** | The chart packages both CRDs, RBAC, admission, node and Control workloads, atomic hook ownership and cleanup, automated fixture, and independent manual example. Run install, full scenario, uninstall, and host-path cleanup physically. |
| `D6.2.13` | **Approved; not implemented.** | Implement createContainer staging, exact prestart activation, the bounded BPF transition and object ownership, one-use application handoff, recovery, automated behavior, and current stock-runtime physical proof. |

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
| Runtime bootstrap | The exact initial entry creates and uses only owned anonymous bootstrap objects, then one policy-approved application exec consumes the authority. | Authority before prestart, a path-backed or network object, another entry or binding, an unsealed self-exec, expiry, replay, or any post-handoff use rejects. |
| Retirement | A signed restrictive successor replaces the exact active base target. A complete relist retires a durable base source. A signed exception revocation closes only its runtime instance. | A partial relist, historical event, API loss, Control loss, or recreated exception cannot erase the last valid base generation or restore consumed authority. |

## Physical Proof Matrix

The physical result must use the current stock Kubernetes and OCI runtime
extension points. It must record their versions and exact configuration. The
current source has not run this matrix. The observations marked `Prior pass`
or `Prior fail` used the superseded flattened resource. They do not prove the
current CRDs or fixture.

| Scenario | Result | Observation |
| --- | --- | --- |
| New eligible node | **Prior pass; current not run** | The old run observed initial quarantine and ready projection. The current fixture also requires same-name UID replacement and host epoch advance. |
| Two eligible nodes | **Prior pass; current not run** | The old run observed one scheduler-selected node and selected-node delivery. The current fixture compares the complete typed target with live Node and Pod facts. |
| Protected start | **Prior fail; current not run** | The old run activated policy and binding. Stock `runc` then used anonymous-file and IPC operations with no typed authority. The application did not run. |
| Runtime and policy lifecycle | **Not run** | The current fixture contains task replacement, exception target retirement, terminal cleanup, restart, no-root replay, and fresh-root checks. |
| Node lifecycle | **Not run** | The current fixture contains session loss, quarantine, same-name Node UID replacement, DaemonSet exclusion and re-entry, node process restart, and host reboot checks. |
| Evidence failure variants | **Not run** | Automated tests pass. Physical duplicate, gap, reorder, storage failure, restart, and WAL truncation remain required. |
| Watch and outage variants | **Not run** | Physical complete and partial relist, Control outage, API outage, and mixed rollout remain required. |
| Installation cleanup | **Not run** | Rendered Helm tests pass. The physical fixture now checks exact hook paths and owned uninstall cleanup on both hosts. |

The procedure cleanup removed the test namespace and runtime classes. Control
accepted the denial evidence before the node truncated the related WAL data.

## Current Automated Verification

The repository Rust CI script passed format, workspace check, strict Clippy,
and the full workspace test gate. The final gate included 89 Mithril Control
library tests, 28 reconciliation tests, 6 Kubernetes policy API tests, 150
Mithril node library tests, 2 OCI adapter tests, and 5 node mutual Transport
Layer Security integration tests.

The Helm verification passed hook ownership behavior, chart lint, and the
render contract. The VM harness behavior suite passed. The independent manual
example behavior suite passed. `git diff --check` passed.

These automated results prove the current API and source behavior. They do not
change an unrun physical case to `Pass`. The previous live cluster case used
the old API, passed through runtime binding and durable evidence intake, and
then failed stock-runtime protected start.

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
