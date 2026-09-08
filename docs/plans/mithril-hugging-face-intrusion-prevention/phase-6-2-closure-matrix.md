# Phase 6.2 Closure Matrix

- Phase: [Control Policy And Evidence Convergence](./phase-6-2-control-policy-and-evidence-convergence.md)
- Architecture: [validated readable architecture](./policy-and-protection-algorithm-architecture-readable.md)
- Manual acceptance: [Phase 6.2 runbook](./manual-testing/phase-6-2-manual-acceptance.md)
- Implementation review: [Phase 6.2 review guide](./phase-6-2-implementation-review.md)
- Held-OCI design: [held OCI route publication](./phase-6-2-held-oci-route-publication-design.md)
- Recovered-entry design: [recovered container entry activation](./phase-6-2-recovered-container-entry-activation-design.md)
- Policy example: [independent entry roles](./phase-6-2-entry-policy-example.yaml)

## Closure Decision

Phase 6.2 is **Not done**. The approved API correction replaces the flattened
`WorkloadProtectionProfile` with a capability-grounded
`WorkloadProtectionPolicy` and a separate bounded
`WorkloadProtectionException`. The branch now implements both resources,
their lowering, their durable Control and node lifecycles, and current
automated and manual fixture flows. The complete current-source automated
two-node physical fixture passes. It includes the evidence-health and final
node-projection stress checks. The independent manual case passed on its
recorded source. The
approved policy amendment replaces `initialRole` with an explicit application
entry, adds declared additional entries and one approved administrative entry,
and retains `externalRole`. The Kubernetes fixture uses this schema and proved
its declared entries under the earlier contract. It does not prove the approved
administrative entry or the new probe argv-verification requirement. The
approved recovered-container design defines a measured
`RECOVERING -> ACTIVE_RECOVERED` cutover in `lifecycle_state`. Mithril Node
installs all signed policy rows before it publishes the binding directly as
`RECOVERING`. Node supplies authenticated CRI coordinates. BPF measures PID 1,
its executable, applicable arguments, root view, and complete process tree
after this publication. BPF assigns the
verified current init tree to the application entry, assigns other existing
trees to the restricted external role, and publishes `ACTIVE_RECOVERED` after
complete validation. Future entries use the normal per-exec admission path.
This recovery design is not complete or qualified. The lightweight test must
call the same production Node reconciliation operation as Kubernetes. It must
reproduce each Kubernetes-only failure before an implementation fix or another
Kubernetes run. The
historical complete fixture also proves guarded migration of one running
process to a replacement base-policy generation. The current physical outage
fixture passed evidence-stream interruption and recovery, storage failure,
network partition, API outage, an expired Kubernetes watch cursor, and Control
relist. Version-changed Kubernetes recovery and authorized final decommission
remain `Not run`.

The recovery changes under test on 2026-09-07 do not have a Kubernetes pass.
The lightweight test reaches `RECOVERING`, but BPF rejects the initial
application candidate. Its signed `/bin/sh` path resolves to `/bin/busybox`;
the current recovery path matcher is not equivalent to the normal exec-path
matcher. See the recovered-entry design for the exact test and bpftrace
evidence. Earlier physical passes do not qualify these source changes.

The recovery check on 2026-09-08 is also **Not done**. The recovered-entry
lightweight case passed, including a repeated identity-reconciliation cycle
and the probe's own file-policy denial. Kubernetes failed before Node
published `RECOVERING`: policy-delivery restoration changed the recovered
binding's `arm_initial_root` from false to true. The lightweight case bypassed
that restoration step. Its shared production operation must include that
step before the implementation fix and the next Kubernetes run. The broader
lightweight administrative-recovery case also fails policy activation. See
the recovered-entry design for the exact evidence and remaining checks.

The later shared-cycle correction reproduced that Node failure in lightweight
before removing the display flag from authority decisions. Lightweight run 28
passed through durable save and restore. Kubernetes then completed recovery
and admitted a later probe, but its denial target file was absent. Lightweight
run 29 reproduced that fixture failure before the paired fixture correction.
Lightweight run 30 passed. The next Kubernetes capture excluded the actual
`EXACT_POLICY_DENY` event. Lightweight run 31 reproduced this filter error
through the production observation server and CLI. Both captures now have no
reason filter; lightweight run 32 passed. The next Kubernetes check selected
the readiness task instead of the startup task. Lightweight run 34 reproduced
this event-order error. Both cases now inspect the exact held startup task.
Lightweight run 35 and the paired focused Kubernetes case passed. Their
results are in `target/mithril-recovery-qualification/20260908-resumed/`, in
`recovered-run35.json` and
`kubernetes-exact-probe/recovered-container-kubernetes-entry.json`.
The broader lightweight case passed in `entry-role-run15.json` in the same
directory. It includes recovered administrative entry, argument-mismatch and
replay denial, one-use approval, slot cleanup, ordinary entry roles, and cache
retirement. The Kubernetes administrative-approval transaction remains
unqualified. The paired fresh Kubernetes protected-start check failed:
Node treated the held binding's verified CRI `Created` identity as recovered
`Running` identity and stopped during publication. The lightweight held-start
setup omitted that CRI identity. A shared-operation reproduction is required
before the fix or another Kubernetes run. See the recovered-entry design for
the saved Node error and exact branch.
The later lightweight run 16 reproduces the held-start publication error
through the shared `publish_held_activated_root` operation. The current source
selects recovery validation from `lifecycle_state`, not CRI identity presence.
The held-start unit regression and lightweight runtime run 19 pass. The focused
lightweight recovery run 37 also passes. The paired Kubernetes check passes in
`kubernetes-held-created-green/protected-start-result.json` in the same evidence
directory. The held-start correction is **Done**. See the implementation review
for the scheduled-policy fixture correction and saved failing evidence.
The full repository gate still fails the draft lifecycle ABI numbering check.
Recovery remains **Not done**.

The later forward-lifecycle change uses the existing `ACTIVE_RECOVERED` to
`ACTIVE` normalization without changing stored state or evidence. Lightweight
recovery run 39 and normal-start run 20 pass. Their results are under
`target/mithril-recovery-qualification/20260908-forward-lifecycle/`. The BPF
source compiles against all four checked-in architecture headers. No current
Kubernetes pass covers this change. The latest Kubernetes VM is paused on an
I/O error and its configured backing-disk path is absent. The broader lifecycle
predicate cleanup, stable ABI values, and recovery race checks remain open.
Result: **Not done**.

The later binding-identity cleanup removes BPF lifecycle ranges from the
identity predicate and retains denials in effect and transition owners.
Recovery publication takes the binding guard, but complete task-change race
safety remains open. Lightweight run 43 and the paired Kubernetes result in
`20260908-forward-lifecycle/kubernetes-external-pid/` prove two application
tasks, two restricted external tasks, runtime bootstrap, signed probe
admission, and the expected denials. Lightweight run 42 first reproduced the
Kubernetes parent-and-child command-line ambiguity. Normal lightweight run 22
also passes after the fixture sorts its signed target inputs. The paired
Kubernetes normal-start check also passes; its result is
`20260908-forward-lifecycle/kubernetes-normal-start/protected-start-result.json`.
The repository gate still fails the stable lifecycle ABI assertion.
See the implementation review for
the object digest, exact evidence paths, and remaining recovery matrix.
Result: **Not done**.

The direct stock-`runc` application-start lane proves the `PREPARED` to
`ACTIVE` transition and dependency access with libc and the ELF loader absent
from policy. The current complete Kubernetes fixture proves the same start
boundary through stock containerd. It also proves policy replacement, bounded
exception use, target retirement, restart recovery, Node UID replacement, host
epoch change, desired-inventory cleanup, and a fresh root activation.

The amendment is not closed by custom resource reconciliation alone. The
current automated physical result proves scheduler placement on a node derived
from the live `mithril-node` DaemonSet. It also proves that the exact initial
container process stays held until that node activates the Pod's exact policy
and cgroup binding. The current result also proves that `createRuntime`
publishes no process-derived path authority. The matching `createContainer`
hook publishes the authoritative OCI path rows before application release.

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
| Which view can publish initial path authority | A matching `createContainer` request supplies the OCI bundle and root handle after the binding is prepared. The node measures and publishes the first exact objects and canonical mount routes through that view. | The held process view during `createRuntime`, periodic reconciliation before `createContainer`, a signed logical entry row, or a later unrelated process. |
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
| `D6.2.5` | **Implemented, automated, and physically exercised.** | Automated intake failure, duplicate, gap, reorder, replay, storage, restart, binary WAL migration, capacity policy, and connection-reuse tests pass. The physical outage fixture retained unacknowledged records across Control and Node restart, withheld acknowledgement while Control storage was read-only, replayed the records after recovery, preserved existing Control and Node WAL prefixes, and truncated Node WAL data only after durable acknowledgement. |
| `D6.2.6` | **Implemented, automated, and physically exercised.** | The current fixture passed target withdrawal, complete desired inventory, live-runtime retention, exception use, expiry, revocation, target retirement, restart, reconnect, and physical-session settlement. |
| `D6.2.7` | **Implemented, automated, and physically exercised.** | Both statuses are bounded and contain no authority material. Separate writer roles and Control status-only permissions passed typed authorization reviews against the installed CRDs. |
| `D6.2.8` | **Partial.** | The non-Kubernetes VM and complete Kubernetes fixtures proved independent and reusable declared entry roles, application start, PostStart, PreStop, exec probes, external-entry denial, and scenario cleanup under the earlier contract. The administrative reservation and late kernel-owned argv checks are not qualified. Recovered-container activation and its later-entry path are not implemented or qualified. Declared probe entries must use the same per-exec checks before this result closes. |
| `D6.2.9` | **Implemented, automated, and physically exercised.** | The fixture passed quarantine, same-name Node UID replacement, selector re-entry, node process restart, and host reboot with a new boot and label epoch. |
| `D6.2.10` | **Implemented, automated, and physically exercised.** | Policy and container matching, immutable image pins, Pod mutation, update validation, binding validation, and scheduler choice passed through the current physical admission flow. |
| `D6.2.11` | **Partial.** | Exact selected-node delivery, activation, guarded live-process migration, staged runtime fact equality, cgroup binding, runtime lifetime replacement, desired-inventory cleanup, and stock-runtime process release pass physically. The current lightweight and Kubernetes cases prove held-OCI path deferral, authoritative `createContainer` path publication, stale-cache repair, and retirement of older cache generations. The retained containerd default-runtime gate and exact socket-free Control and Node recovery pass for the current image shapes. Version-changed Kubernetes recovery and direct non-CRI BPF fallback remain unproved. |
| `D6.2.12` | **Partial.** | The current chart installs and reads back the retained containerd fragment, OCI base spec, hook, and recovery manifest. Ordinary uninstall retained that integration, and the current Control and Node shapes recovered through it. The direct-runc probe permits version-changed binaries for exact shapes and rejects changed shapes. The version-changed Kubernetes recovery and authorized final decommission remain `Not run`. |
| `D6.2.13` | **Partial.** | The Kubernetes transaction proved every declared entry, unmatched external denial, and no role inheritance under the earlier contract. It does not prove the approved administrative transaction or late argv verification for declared probe entries. |

## Automated Proof Matrix

| Seam | Positive proof | Negative oracle |
| --- | --- | --- |
| Public policy schema | The stored `WorkloadProtectionPolicy.spec` and offline form lower to the same internal policy. | Unknown, internal-only, unqualified, oversized, or conflicting fields reject before a candidate exists. |
| Entry references and roles | The application entry and every declared additional entry resolve one named `Allow Execute` rule in their own role. The administrative entry resolves one role, and `externalRole` stays restricted. | A missing or cross-role rule, duplicate reference, unsupported kind, non-Execute rule, recursive entry rule, ambiguous match, implicit role inheritance, or permission union rejects. |
| Static roles and effects | Every admitted entry receives only its referenced role, and supported path, address, Unix-stream, signal, and ptrace rules lower to exact cells. | Native transitions, semantic token or image targets, service destinations, device, privilege, mount, finding, response, proof, errno, or node-selector fields reject. Recursive allow rejects until physical qualification. |
| Bounded exception | An API-server-authorized request activates one precompiled file grant for the exact Pod and container without creating another base generation, within the duration and use limits. A running process uses the grant after BPF migrates that process to the active base generation at its next protected effect. | Wrong writer, policy generation, grant, Pod UID, container, Node, boot, duration, uses, rule family, stale object, overlap, replay, missing process migration, or user-supplied authority material rejects. |
| Running policy update | Node builds and proves one unreachable immutable generation, publishes it for the live binding, and BPF migrates each running process under its transition guard at that process's next protected effect. | A partial generation is never published. A missing semantic role or process-state translation, concurrent transition, or incomplete target denies the effect. There is no workload-wide migration transaction. |
| DaemonSet derivation | Selector and required affinity accept the same labeled nodes as the supported DaemonSet template. | Unsupported or changed constraints do not leave a stale ready projection. |
| Node quarantine | A matching node stays tainted until its authenticated current-boot session reports complete readiness. | A missing, stale, wrong-name, wrong-UID, wrong-boot, or unhealthy session cannot remove the taint. A replacement Node cannot inherit readiness by name. |
| Pod match | One same-namespace policy match and exactly one container-entry match for every container produce a protected admission result. | Zero policy matches do not mutate the Pod. Multiple policies, unmatched or multiply matched containers, mutable image matches, and caller-supplied Mithril annotations reject. |
| Pod scheduling constraints | Existing Pod constraints and derived Mithril constraints are combined, and the scheduler can choose either of two eligible ready nodes. | `nodeName`, quarantine toleration, conflicting mutation input, excessive affinity expansion, and stale ready state reject. |
| Pod update | A protected Pod keeps its admitted policy identity and digest-pinned matching containers. | An unprotected scheduled Pod cannot enter a policy through an update. A protected Pod cannot change its policy identity through a Pod or ephemeral-container update. |
| Scheduler binding | A binding to an eligible ready node with the current session succeeds. | A binding to another node, UID, boot, or stale session rejects. |
| Workload target | Persisted Pod UID, selected node, controller, ServiceAccount, container, and digest create one immutable exact target. | Pod deletion, UID reuse, node change, or container change retires the old target. |
| Policy delivery | Only the selected node can inventory, fetch, verify, and acknowledge the target-bound candidate. | Every other node and boot rejects the candidate even when it has the same signed policy artifact. |
| Runtime gate | The first `createRuntime` call stages facts only. The second call stays held until the node publishes and reads back the exact cgroup, TGID, binding, policy generation, and `PreparedContainer` state. The signed entry rows stay staged, but the process path view publishes no measured path row. The matching `createContainer` call supplies the OCI root handle and publishes the first measured path rows. | Missing candidate, changed stage, wrong policy annotations, TGID or cgroup mismatch, premature process-derived path authority, timeout, disconnect, active socket-owner replacement, and restart reject without application release. |
| Retained default-runtime gate | Containerd's default CRI runtime invokes the retained hook without NRI or a RuntimeClass. The exact hostile OCI shape rejects before its process runs. Exact OCI-shape-bound Mithril recovery succeeds when the node socket is absent. | Ordinary Helm deletion leaves the integration active. A changed recovery command or security-sensitive OCI field rejects. A direct non-CRI bypass reaches the retained BPF incident floor. |
| Prepared container and entries | The exact prepared binding permits runtime setup. The application entry activates the binding. A declared PostStart can commit before or after activation. Later declared entries install only their own roles. | Another binding, unmatched external root, ordinary administrative exec, failed or ambiguous entry match, expired state, or cgroup-only entry rejects. The approved administrative entry remains unavailable until BPF can match complete kernel-owned argv before the exec point of no return. Explicit matching Deny remains effective, and runtime-created objects carry no separate grant. |
| Retirement | A complete relist or target snapshot removes stale bundles from complete desired node inventory. The node retains live runtime protection and removes known local membership after runtime absence. A signed exception revocation closes only its runtime instance. | A partial relist, historical event, API loss, Control loss, or recreated exception cannot erase live base protection or restore consumed authority. |

## Physical Proof Matrix

The current complete physical results use stock Kubernetes and Open Container
Initiative (OCI) runtime extension points. They passed with Kubernetes
v1.35.5+k3s1 and containerd v2.2.3-k3s1. The convergence evidence is
`/tmp/mithril-phase62-projected-epoch-full-kubernetes-20260906-g`. The outage
evidence is `/tmp/mithril-phase62-outage-recovery-20260906-j`. Both harnesses
removed their scenario resources and retained the two healthy VMs and K3s
cluster.

| Scenario | Result | Observation |
| --- | --- | --- |
| Direct-runc entry roles | **Pass** | K3s-bundled runc 1.4.2 changed the exact binding from `PREPARED` to `ACTIVE`. The current procedure retained the seven signed entry rows and published no process-derived path route before `createContainer`. It then proved OCI path publication, six independent declared roles, repeated entry invocation, role isolation, external-entry denial, cache repair, and owned-resource cleanup. |
| New eligible node | **Pass** | The run observed initial quarantine, ready projection, same-name UID replacement, and host epoch advance. |
| Two eligible nodes | **Pass** | The scheduler selected `ubuntu-0437f198`. The fixture compared the complete typed target with live Node and Pod facts. |
| Focused protected start | **Pass** | Kubernetes v1.35.5+k3s1 and containerd 2.2.3-k3s1 enforced held-OCI path deferral, activated the `/bin/sh` application entry, allowed later BusyBox applet execs through the admitted lineage, enforced the explicit file Deny, and denied a direct CRI external entry. This result does not prove the approved additional or administrative entries. |
| Held OCI path publication | **Pass** | The production `createRuntime` path does not call exact-binding reconciliation. The lightweight case then ran production background reconciliation before `createContainer`. It preserved the exact signed entry-row keys and values and found no canonical mount route. The paired Kubernetes start enforced the OCI-derived path denial. |
| Independent entry roles | **Partial** | The prior direct-runc VM and Kubernetes procedures proved five independent additional-entry roles, repeated PostStart, PreStop, all three exec-probe kinds, role isolation, and unmatched external denial. The expanded direct-runc fixture reaches an execution approval slot created by the administrative workflow, then the target exec remains restricted. It does not prove approved administrative exec. |
| Independent manual case | **Pass** | The case selected `ubuntu-5775b0d0`, proved exact target and prepared-container activation, failed closed when runtime admission was unavailable, replaced the container lifetime and runtime binding, refused stale-root replay, and created a fresh root activation. Its trap removed the namespace and both RuntimeClasses. |
| Mount-cache retirement | **Pass** | The lightweight and Kubernetes fixtures forced a READY mount-count mismatch. BPF advanced the cache generation and rebuilt the same live topology. Routine Node reconciliation removed every row with an older security-view epoch or cache generation. The current READY rows and path denial remained active. |
| Runtime and policy lifecycle | **Pass** | The complete current-source run proved task replacement, exception target retirement, desired-inventory cleanup, restart, no-root inspection, and fresh-root activation. |
| Running policy update | **Pass** | The complete current-source run published one replacement generation for the live binding. The same running application migrated at its next protected effect. A later child exec used the replacement generation. |
| Node lifecycle | **Pass** | The complete current-source run proved session loss, quarantine, same-name Node UID replacement, DaemonSet exclusion and re-entry, node process restart, and host reboot. |
| Evidence failure variants | **Pass** | During a Control outage, both Nodes retained unacknowledged records and one Node retained them across restart. A read-only Control evidence volume withheld acknowledgement. After storage recovery, Control accepted the retained records without changing stored segment prefixes, and both Nodes truncated acknowledged WAL data. |
| Watch and outage variants | **Pass** | K3s returned `410 Expired` for resource version 1. Control then recovered after its policy watch missed a deletion and creation. The same run kept local denial during Control and API outages, blocked new protected work while Control was absent, retained the predecessor on one partitioned Node, reported a mixed rollout, and converged after reconnection. |
| Retained runtime integration | **Partial** | The current run removed the Helm release, retained and read back the host integration, and recovered the exact current Control and Node shapes. Its direct-runc probe allowed version-changed binaries for exact shapes and rejected changed recovery shapes. A Kubernetes run with version-changed images and the authorized final-decommission case remain required. |

The procedure cleanup removed the test namespace and runtime classes. Control
accepted the denial evidence before the node truncated the related WAL data.

## Current Automated Verification

The repository Rust CI script passed format, workspace check, and strict
Clippy. Its parallel workspace-test stage reproduced three existing timing
races. Each affected test passed alone. The Interceptor and Mithril end-to-end
library suites passed serially with 112 passed tests and two ignored tests.

The VM harness behavior suite passed. `git diff --check` passed. The recorded
Helm and independent manual-example results apply to their source checkpoints.

The lightweight suites execute Rust owners and fixture commands. They do not
read source text as a capability oracle. The paired Kubernetes fixture remains
the physical acceptance owner.

The current lightweight mount-cache command passed:

```text
rtk bash crates/mithril-e2e/harness/vm/run.sh --with-k3s --entry-role-runtime-only --output-directory /tmp/mithril-phase62-mount-cache-gc-lightweight-20260905
```

The result is
`/tmp/mithril-phase62-mount-cache-gc-lightweight-20260905/runc-entry-role-runtime-probe.json`.
Its SHA-256 is
`0433090c5d82a86116e6d283af905e5759b4a750d8692d19dd88cc93253959fe`.
It records held-OCI path deferral, unchanged signed entry rows, OCI path
publication, path-tree denial, cache repair, retirement of unreachable route
and state rows, and owned-resource cleanup.

The paired focused Kubernetes command passed after the lightweight command:

```text
rtk bash crates/mithril-e2e/harness/vm/two-node-convergence.sh --protected-start-only --reuse-environment /tmp/mithril-phase62-complete-green-20260905-j/retained-environment.json --output-directory /tmp/mithril-phase62-mount-cache-gc-kubernetes-20260905-a
```

The result is
`/tmp/mithril-phase62-mount-cache-gc-kubernetes-20260905-a/protected-start-result.json`.
Its SHA-256 is
`fcf84b7a16adf41d759ad635a3ed49d48f6438d7b081b83ece0872411c45ea10`.
It records held-OCI path deferral, active application admission, explicit path
denial, external-cgroup denial, six independent entry roles, cache generation
advance, and zero unreachable cache rows.

The complete current-source Kubernetes command then passed:

```text
rtk env MITHRIL_VM_REUSE_IMAGES=true bash crates/mithril-e2e/harness/vm/two-node-convergence.sh --reuse-environment /tmp/mithril-phase62-complete-green-20260905-j/retained-environment.json --output-directory /tmp/mithril-phase62-mount-cache-gc-full-kubernetes-20260905-b
```

The complete result is
`/tmp/mithril-phase62-mount-cache-gc-full-kubernetes-20260905-b/two-node-convergence.json`.
Its SHA-256 is
`d43d2bd7bb58e0ef858677e0e21094854ac55f9462c71fa03223ba3de5283f2c`.

The focused and repository commands passed:

```text
rtk bash crates/mithril-e2e/harness/vm/test.sh
rtk cargo test -p mithril-node --lib
rtk cargo test -p erebor-interceptor -p mithril-e2e --lib --tests -- --test-threads=1
rtk git diff --check
```

The historical complete Kubernetes result is
`target/mithril-generation-migration-kubernetes-20260902-d/two-node-convergence.json`.
The historical focused replacement-exception result is
`target/mithril-replacement-generation-lightweight-20260902-r12/replacement-generation-exception-probe.json`.

## Remaining Closure Work

Version-changed Kubernetes recovery and authorized final decommission remain
`Not run`. The approved administrative-entry transaction and late kernel-owned
argument checks for administrative and probe entries remain unqualified. The
physical direct non-CRI BPF fallback also remains unproved.

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
