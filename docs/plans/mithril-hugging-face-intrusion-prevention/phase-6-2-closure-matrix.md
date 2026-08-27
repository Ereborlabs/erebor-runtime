# Phase 6.2 Closure Matrix

- Phase: [Control Policy And Evidence Convergence](./phase-6-2-control-policy-and-evidence-convergence.md)
- Architecture: [validated readable architecture](./policy-and-protection-algorithm-architecture-readable.md)
- Manual acceptance: [Phase 6.2 runbook](./manual-testing/phase-6-2-manual-acceptance.md)
- Implementation review: [Phase 6.2 review guide](./phase-6-2-implementation-review.md)
- Policy example: [independent entry roles](./phase-6-2-entry-policy-example.yaml)

## Closure Decision

Phase 6.2 is **Not done**. The approved API correction replaces the flattened
`WorkloadProtectionProfile` with a capability-grounded
`WorkloadProtectionPolicy` and a separate bounded
`WorkloadProtectionException`. The branch now implements both resources,
their lowering, their durable Control and node lifecycles, and current
automated and manual fixture flows. The current source has not passed the
physical procedure. The approved policy amendment replaces `initialRole` with
an explicit application entry, adds declared additional entries and one
approved administrative entry, and retains `externalRole`. The amendment is
implemented and covered by automated and non-Kubernetes VM tests. The current
Kubernetes fixture and manual example do not yet use the amended schema.

The direct stock-`runc` application-start lane now passes. It proves the
`PREPARED` to `ACTIVE` transition and dependency access with libc and the ELF
loader absent from policy. The earlier physical Kubernetes run remains partial evidence. It reached
scheduler binding, selected-node delivery, policy activation, runtime binding,
and durable evidence intake. Stock `runc` container start then failed under the
superseded runtime-bootstrap model. The current source implements the approved
`PreparedContainer` boundary. The focused current protected-start transaction
passed. The complete protected Kubernetes procedure is not proved yet.

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
| Whether the initial process can start | The selected `mithril-node` matches two ordered `createRuntime` calls, verifies CRI `Created` state, active policy, the exact held TGID, and the cgroup binding, then reads back `PreparedContainer`. | Pod admission success, scheduler binding success, Control status, policy download, or the first runtime-fact hook alone. |
| Which runtime setup can occur | BPF trusts the exact prepared binding and initial runtime entry until one deadline. It does not use a runtime-specific operation list. Runtime-created objects receive no independent authority. | A CRD field, another binding, another entry, a later external root, or an expired state. |
| Which independent root becomes an admitted entry | The application entry references one named execution rule. Each declared additional entry references one named execution rule in its own role. The approved administrative entry requires the existing signed one-use slot. | Runtime creation, cgroup membership, command timing, a declared kind alone, or an ordinary `kubectl exec` or direct `crictl exec` that has no exact declared-entry match. |
| Which policy an admitted entry uses | Each committed entry installs only its referenced role. A native descendant keeps its creator entry's role. | The application role as fallback, implicit role inheritance, permission union, or the external role. |
| Which unmatched entry policy applies | `externalRole` is the restricted pre-admission and unmatched-entry role. | An admitted-entry default or an automatic transition to another role. |
| Which active entry action is allowed | The exact admitted entry lineage checks explicit signed decisions for its installed role first. A matching Deny blocks unless an applicable exception authorizes it. A missing decision allows. | Cgroup membership alone, an unlabeled task, an unmatched external entry, another entry's role, or a prepared-runtime object grant. |

## Deliverable Closure

| Deliverable | Current result | Evidence required to close |
| --- | --- | --- |
| `D6.2.1` | **Implemented and automated; physical result not done.** | Structural schema, reference validation, independent-role lowering, offline-policy golden equality, and internal-field rejection tests pass. Install and exercise the current CRD physically. |
| `D6.2.2` | **Implemented and automated.** | One desired-state owner reconciles both source kinds. The store proves atomic source and artifact acceptance, restart, complete relist retirement, partial relist safety, and separate exception retirement. |
| `D6.2.3` | **Implemented and automated.** | API-only workload inventory binds exact scheduler, Pod, container, Node, Node UID, boot, and label facts. Node claims cannot create a Kubernetes target. |
| `D6.2.4` | **Implemented and automated.** | Policy inventory returns the complete authenticated desired bundle set and skips superseded candidates. Policy transfer is resumable. Activation acknowledgements are exact. Exception candidates keep their bounded activation and revocation order. |
| `D6.2.5` | **Partial.** | Automated intake failure, duplicate, gap, reorder, replay, storage, restart, and WAL migration tests pass. The required physical evidence variants remain `Not run`. |
| `D6.2.6` | **Implemented and automated; physical result not done.** | Tests cover target withdrawal, complete desired inventory, owner-matched stale binding and generation removal across a runtime alias change, live-runtime retention, exception use, expiry, revocation, restart, reconnect, and physical-session settlement. Run the current physical lifecycle. |
| `D6.2.7` | **Implemented and automated; physical result not done.** | Both statuses are bounded and contain no authority material. Separate writer roles and Control status-only permissions are rendered and exercised by typed authorization reviews. Run them against the current installed CRDs. |
| `D6.2.8` | **Implemented and automated; physical result not done.** The non-Kubernetes VM procedure proves independent and reusable additional-entry roles. | Run the complete Kubernetes policy, entry, and exception transaction through application start, PostStart, PreStop, exec probes, approved administrative exec, external-entry denial, and cleanup. |
| `D6.2.9` | **Implemented and scripted; physical result not done.** | Automated tests cover session expiry, reconnect, Node UID rebind, boot and label reset, and startup absence proof. The physical fixture scripts quarantine, UID replacement, selector re-entry, process restart, and host reboot. Run the fixture. |
| `D6.2.10` | **Implemented and automated; physical result not done.** | Policy and container matching, immutable image pins, Pod mutation, update validation, binding validation, and scheduler choice tests pass. Run the current physical admission flow. |
| `D6.2.11` | **Implemented and automated; physical result not done.** | Exact selected-node delivery, activation, staged runtime fact equality, cgroup binding, cancellation rollback, runtime lifetime replacement, desired-inventory cleanup, and timeout tests pass. Run the stock-runtime process-release path physically. |
| `D6.2.12` | **Partial.** The current chart and manual case are implemented. The approved policy example is present, but the production CRD and runnable examples do not accept it. | Implement and package the amended CRD. Update the automated fixture and independent manual case. Run install, full scenario, uninstall, and host-path cleanup physically. |
| `D6.2.13` | **Implemented and automated; physical Kubernetes result not done.** PreparedContainer, application activation, independent entry-role installation, reusable declarations, and external denial pass automated and non-Kubernetes VM tests. | Prove every declared entry, the approved administrative entry, unmatched external denial, and no role inheritance through the protected Kubernetes transaction. |

## Automated Proof Matrix

| Seam | Positive proof | Negative oracle |
| --- | --- | --- |
| Public policy schema | The stored `WorkloadProtectionPolicy.spec` and offline form lower to the same internal policy. | Unknown, internal-only, unqualified, oversized, or conflicting fields reject before a candidate exists. |
| Entry references and roles | The application entry and every declared additional entry resolve one named `Allow Execute` rule in their own role. The administrative entry resolves one role, and `externalRole` stays restricted. | A missing or cross-role rule, duplicate reference, unsupported kind, non-Execute rule, recursive entry rule, ambiguous match, implicit role inheritance, or permission union rejects. |
| Static roles and effects | Every admitted entry receives only its referenced role, and supported path, address, Unix-stream, signal, and ptrace rules lower to exact cells. | Native transitions, semantic token or image targets, service destinations, device, privilege, mount, finding, response, proof, errno, or node-selector fields reject. Recursive allow rejects until physical qualification. |
| Bounded exception | An API-server-authorized request activates one precompiled file grant for the exact Pod and container without migrating the base generation, within the duration and use limits. | Wrong writer, policy generation, grant, Pod UID, container, Node, boot, duration, uses, rule family, stale object, overlap, replay, or user-supplied authority material rejects. |
| DaemonSet derivation | Selector and required affinity accept the same labeled nodes as the supported DaemonSet template. | Unsupported or changed constraints do not leave a stale ready projection. |
| Node quarantine | A matching node stays tainted until its authenticated current-boot session reports complete readiness. | A missing, stale, wrong-name, wrong-UID, wrong-boot, or unhealthy session cannot remove the taint. A replacement Node cannot inherit readiness by name. |
| Pod match | One same-namespace policy match and exactly one container-entry match for every container produce a protected admission result. | Zero policy matches do not mutate the Pod. Multiple policies, unmatched or multiply matched containers, mutable image matches, and caller-supplied Mithril annotations reject. |
| Pod scheduling constraints | Existing Pod constraints and derived Mithril constraints are combined, and the scheduler can choose either of two eligible ready nodes. | `nodeName`, quarantine toleration, conflicting mutation input, excessive affinity expansion, and stale ready state reject. |
| Pod update | A protected Pod keeps its admitted policy identity and digest-pinned matching containers. | An unprotected scheduled Pod cannot enter a policy through an update. A protected Pod cannot change its policy identity through a Pod or ephemeral-container update. |
| Scheduler binding | A binding to an eligible ready node with the current session succeeds. | A binding to another node, UID, boot, or stale session rejects. |
| Workload target | Persisted Pod UID, selected node, controller, ServiceAccount, container, and digest create one immutable exact target. | Pod deletion, UID reuse, node change, or container change retires the old target. |
| Policy delivery | Only the selected node can inventory, fetch, verify, and acknowledge the target-bound candidate. | Every other node and boot rejects the candidate even when it has the same signed policy artifact. |
| Runtime gate | The first `createRuntime` call stages facts only. The second call stays held until the node publishes and reads back the exact cgroup, TGID, binding, policy generation, and `PreparedContainer` state. | Missing candidate, changed stage, wrong policy annotations, TGID or cgroup mismatch, timeout, disconnect, active socket-owner replacement, and restart reject without release. |
| Prepared container and entries | The exact prepared binding permits runtime setup. The application entry activates the binding. A declared PostStart can commit before or after activation. Later declared entries and an approved administrative entry install only their own roles. | Another binding, unmatched external root, ordinary administrative exec, failed or ambiguous entry match, expired state, or cgroup-only entry rejects. Explicit matching Deny remains effective, and runtime-created objects carry no separate grant. |
| Retirement | A complete relist or target snapshot removes stale bundles from complete desired node inventory. The node retains live runtime protection and removes known local membership after runtime absence. A signed exception revocation closes only its runtime instance. | A partial relist, historical event, API loss, Control loss, or recreated exception cannot erase live base protection or restore consumed authority. |

## Physical Proof Matrix

The physical result must use the current stock Kubernetes and OCI runtime
extension points. It must record their versions and exact configuration. The
current source has not run this matrix. The observations marked `Prior pass`
or `Prior fail` used the superseded flattened resource. They do not prove the
current CRDs or fixture.

| Scenario | Result | Observation |
| --- | --- | --- |
| Direct stock-runc application start | **Pass** | Stock runc 1.3.4 changed the exact binding from `PREPARED` to `ACTIVE`. The application exited successfully. The evidence recorded libc and the ELF loader as present in the root filesystem and absent from policy. |
| New eligible node | **Prior pass; current not run** | The old run observed initial quarantine and ready projection. The current fixture also requires same-name UID replacement and host epoch advance. |
| Two eligible nodes | **Prior pass; current not run** | The old run observed one scheduler-selected node and selected-node delivery. The current fixture compares the complete typed target with live Node and Pod facts. |
| Focused protected start | **Pass** | Kubernetes v1.35.5+k3s1 and containerd 2.2.3-k3s1 activated the `/bin/sh` application entry, allowed later BusyBox applet execs through the admitted lineage, enforced the explicit file Deny, and denied a direct CRI external entry. This does not prove the approved additional or administrative entries. |
| Independent entry roles | **VM pass; Kubernetes not run** | The stock-runc VM procedure proved five independent additional-entry roles, one repeated PostStart declaration, role isolation, and unmatched external denial. The Kubernetes result must also cover PostStart before and after application activation, PreStop, all three exec-probe kinds, approved administrative exec, role isolation, and unmatched external denial. |
| Runtime and policy lifecycle | **Not run** | The current fixture contains task replacement, exception target retirement, desired-inventory cleanup, restart, no-root inspection, and fresh-root checks. |
| Node lifecycle | **Not run** | The current fixture contains session loss, quarantine, same-name Node UID replacement, DaemonSet exclusion and re-entry, node process restart, and host reboot checks. |
| Evidence failure variants | **Not run** | Automated tests pass. Physical duplicate, gap, reorder, storage failure, restart, and WAL truncation remain required. |
| Watch and outage variants | **Not run** | Physical complete and partial relist, Control outage, API outage, and mixed rollout remain required. |
| Installation cleanup | **Not run** | Rendered Helm tests pass. The physical fixture now checks exact hook paths and owned uninstall cleanup on both hosts. |

The procedure cleanup removed the test namespace and runtime classes. Control
accepted the denial evidence before the node truncated the related WAL data.

## Current Automated Verification

The repository Rust CI script passed format, workspace check, strict Clippy,
and the full workspace test gate on the current source. The exact command was
`rtk bash .github/scripts/verify-rust-ci.sh`.

The Helm verification passed hook ownership behavior, chart lint, and the
render contract. The VM harness behavior suite passed. The independent manual
example behavior suite passed. `git diff --check` passed.

These automated results prove the application, additional, administrative,
and external entry schema and runtime transitions. They also prove complete
desired-inventory validation, live-runtime retention, and crash-safe stale
profile cleanup. They do not change an unrun physical Kubernetes case to
`Pass`.

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

The declared lifecycle or probe kind is policy intent. Stock CRI does not
prove the request purpose or provide a unique purpose-to-task join. A later
ordinary exec with the same observable entry match remains an explicit
no-patch ambiguity. The phase does not convert that match into stronger
purpose evidence.
