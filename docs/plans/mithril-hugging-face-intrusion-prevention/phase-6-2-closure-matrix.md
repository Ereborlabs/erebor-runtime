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
automated and manual fixture flows. The complete automated two-node physical
fixture passed on the current source. The approved policy amendment replaces
`initialRole` with an explicit application entry, adds declared additional
entries and one approved administrative entry, and retains `externalRole`.
The Kubernetes fixture uses this schema and proved its declared entries. The
independent manual case and the physical evidence-failure, watch-compaction,
network-partition, storage-outage, and final-uninstall cases remain `Not run`.

The direct stock-`runc` application-start lane proves the `PREPARED` to
`ACTIVE` transition and dependency access with libc and the ELF loader absent
from policy. The automated Kubernetes fixture proves the same boundary through
stock containerd. It also proves policy replacement, bounded exception use,
target retirement, restart recovery, Node UID replacement, host epoch change,
desired-inventory cleanup, and a fresh root activation.

The amendment is not closed by custom resource reconciliation alone. The
current automated physical result proves scheduler placement on a node derived
from the live `mithril-node` DaemonSet. It also proves that the exact initial
container process stays held until that node activates the Pod's exact policy
and cgroup binding.

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
| `D6.2.1` | **Implemented, automated, and physically exercised.** | Structural schema, reference validation, independent-role lowering, offline-policy golden equality, and internal-field rejection tests pass. The complete Kubernetes fixture installed and exercised the current CRDs. |
| `D6.2.2` | **Implemented and automated.** | One desired-state owner reconciles both source kinds. The store proves atomic source and artifact acceptance, restart, complete relist retirement, partial relist safety, and separate exception retirement. |
| `D6.2.3` | **Implemented and automated.** | API-only workload inventory binds exact scheduler, Pod, container, Node, Node UID, boot, and label facts. Node claims cannot create a Kubernetes target. |
| `D6.2.4` | **Implemented, automated, and physically exercised.** | Policy inventory returns the complete authenticated desired bundle set and skips superseded candidates. Policy transfer is resumable. Activation acknowledgements are exact. Exception candidates keep their bounded activation and revocation order. The selected-node transaction passed physically. |
| `D6.2.5` | **Partial.** | Automated intake failure, duplicate, gap, reorder, replay, storage, restart, WAL migration, and capacity tests pass. The healthy physical stream passed with no lost events, queue drops, WAL rewrite, or repeated Control connection. The physical failure variants remain `Not run`. |
| `D6.2.6` | **Implemented, automated, and physically exercised.** | The current fixture passed target withdrawal, complete desired inventory, live-runtime retention, exception use, expiry, revocation, target retirement, restart, reconnect, and physical-session settlement. |
| `D6.2.7` | **Implemented, automated, and physically exercised.** | Both statuses are bounded and contain no authority material. Separate writer roles and Control status-only permissions passed typed authorization reviews against the installed CRDs. |
| `D6.2.8` | **Implemented, automated, and physically exercised.** | The non-Kubernetes VM and complete Kubernetes fixtures proved independent and reusable entry roles, application start, PostStart, PreStop, exec probes, approved administrative exec, external-entry denial, and scenario cleanup. |
| `D6.2.9` | **Implemented, automated, and physically exercised.** | The fixture passed quarantine, same-name Node UID replacement, selector re-entry, node process restart, and host reboot with a new boot and label epoch. |
| `D6.2.10` | **Implemented, automated, and physically exercised.** | Policy and container matching, immutable image pins, Pod mutation, update validation, binding validation, and scheduler choice passed through the current physical admission flow. |
| `D6.2.11` | **Implemented, automated, and physically exercised.** | Exact selected-node delivery, activation, staged runtime fact equality, cgroup binding, runtime lifetime replacement, desired-inventory cleanup, and stock-runtime process release passed physically. |
| `D6.2.12` | **Partial.** | The current chart, automated fixture, and manual case are implemented. The retained-cluster fixture installed the package and passed the full scenario. The independent manual run and final uninstall cleanup remain `Not run`. |
| `D6.2.13` | **Implemented, automated, and physically exercised.** | The Kubernetes transaction proved every declared entry, the approved administrative entry, unmatched external denial, and no role inheritance. |

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

The physical result uses the current stock Kubernetes and OCI runtime
extension points. The complete automated fixture passed with Kubernetes
v1.35.5+k3s1 and containerd v2.2.3-k3s1. The result is
`/tmp/mithril-phase-6-2-full-convergence-reuse49-20260828`.

| Scenario | Result | Observation |
| --- | --- | --- |
| Direct-runc entry roles | **Pass** | Runc 1.3.4 changed the exact binding from `PREPARED` to `ACTIVE`. The procedure proved six independent declared roles, repeated entry invocation, role isolation, and external-entry denial. The evidence also recorded libc and the ELF loader as present in the root filesystem and absent from policy. |
| New eligible node | **Pass** | The run observed initial quarantine, ready projection, same-name UID replacement, and host epoch advance. |
| Two eligible nodes | **Pass** | The scheduler selected `ubuntu-d6fecdb3`. The fixture compared the complete typed target with live Node and Pod facts. |
| Focused protected start | **Pass** | Kubernetes v1.35.5+k3s1 and containerd 2.2.3-k3s1 activated the `/bin/sh` application entry, allowed later BusyBox applet execs through the admitted lineage, enforced the explicit file Deny, and denied a direct CRI external entry. This does not prove the approved additional or administrative entries. |
| Independent entry roles | **Pass** | The direct-runc VM and Kubernetes procedures proved five independent additional-entry roles, repeated PostStart, PreStop, all three exec-probe kinds, approved administrative exec, role isolation, and unmatched external denial. |
| Runtime and policy lifecycle | **Pass** | The run proved task replacement, exception target retirement, desired-inventory cleanup, restart, no-root inspection, and fresh-root activation. |
| Node lifecycle | **Pass** | The run proved session loss, quarantine, same-name Node UID replacement, DaemonSet exclusion and re-entry, node process restart, and host reboot. |
| Evidence failure variants | **Not run** | Automated tests pass. Physical duplicate, gap, reorder, storage failure, restart, and WAL truncation remain required. |
| Watch and outage variants | **Not run** | Physical complete and partial relist, Control outage, API outage, and mixed rollout remain required. |
| Installation cleanup | **Partial** | The retained run removed the prior release and checked hook cleanup on both hosts before installation. It retained the final release and VMs, so final uninstall cleanup remains `Not run`. |

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
profile cleanup.

The retained physical command passed:

```text
rtk proxy crates/mithril-e2e/harness/vm/two-node-convergence.sh --output-directory /tmp/mithril-phase-6-2-full-convergence-reuse49-20260828 --keep-vms --reuse-environment /tmp/mithril-phase-6-2-full-convergence-reuse48-20260828/retained-environment.json
```

The scenario removed its workload namespace, policy, exception, Pods, and
marker state. Its final fresh Node Pods were ready with zero container restarts
and one Control connection each. It retained the two owned VMs, K3s cluster,
and installed Mithril release for the next failure-variant run.

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
