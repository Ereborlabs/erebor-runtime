# Phase 6.2 Recovered Container Entry Activation Design Proposal

Status: Approved design on 2026-09-07. Implementation and qualification are
not complete.

Parent: [Phase 6.2 Control Policy And Evidence Convergence](./phase-6-2-control-policy-and-evidence-convergence.md)

Closure: [Phase 6.2 closure matrix](./phase-6-2-closure-matrix.md)

Related design: [Held OCI route publication](./phase-6-2-held-oci-route-publication-design.md)

This proposal lets Mithril establish forward entry authority for a protected
container that was already running when Mithril recovered it. Recovery creates
one measured cutover. BPF assigns the application entry to the current
container-init tree, keeps every other existing process tree on the restricted
external role, and admits only new later entries through the normal executable
and argument checks. Mithril Node cannot assign a role or rule ID to a task.

The recovery result does not claim that Mithril governed the original
container start or any action before the cutover.

## Intended End State

An exact running container uses this recovery handoff:

```text
Node local preparation -- Node publish --> RECOVERING -- BPF commit --> ACTIVE_RECOVERED
```

`UNARMED` is not a Node recovery-delivery phase. It can already exist as the
restricted result of an earlier generic task or binding observation. In that
case, Node can replace it with one guarded `RECOVERING` publication. Node must
not publish a new recovery binding as `UNARMED` and depend on a later
reconciliation cycle to install `RECOVERING`.

Before the publication, Node resolves and validates the CRI lifetime, init
task, cgroup, signed policy generation, normal `ContainerStart` rule,
executable, applicable arguments, and canonical root routes. Node installs
supporting rows that remain unreachable without the binding. The
`RECOVERING` binding publication is the handoff commit. A successful Node
recovery operation therefore returns only after readback proves that BPF
received `RECOVERING` or already advanced it.

While the binding is `RECOVERING`, BPF denies covered effects and does not
create runtime-bootstrap authority. Mithril Node installs the signed policy,
binding facts, initial `RECOVERING` state, and bounded recovery request. It
invokes the BPF recovery iterator but does not change identity state after that
publication. BPF measures one stable task set, creates one recovered
application entry for the exact container-init process, assigns its current
in-container process tree to that entry, and assigns all other existing process
trees to `externalRole` with `admitted_entry_rule_id = 0`.

After complete BPF validation, BPF publishes `ACTIVE_RECOVERED` and releases
the recovery barrier. Mithril Node reads back that result. A later runtime
controller can then prepare an exact runtime-bootstrap lineage against the
recovered application anchor. A new probe, lifecycle hook, tool entry, or
approved administrative entry starts with `externalRole` and rule ID `0`. Its
own executable and arguments select and commit its declared entry.

Evidence identifies the recovery cutover and the earlier coverage gap. It does
not report the recovered application tree as an originally held and admitted
tree.

## Current Defect

A later entry in a container that Mithril governed from creation uses the
admitted initial application entry as its runtime-bootstrap anchor. The
runtime controller receives a task-local marker when it performs an exact
permitted control operation against that anchor. Its child carries the marker
through runc infrastructure until the final entry executable reaches BPF.

A recovered container has no such anchor. Its binding has an unarmed prepared
state, its existing root has no admitted entry rule, and the runtime controller
cannot receive the marker. BPF then treats runc's internal current-image exec
as a possible declared entry instead of runtime infrastructure. The runc image
does not match the declared probe or administrative entry, so BPF denies the
exec before runc executes the requested command.

The final entry lookup is not defective. The runtime cannot reach that lookup.

## Exact Later-Entry Dependency

The governed and recovered paths differ at `lsm/ptrace_access_check`. They do
not differ at the final probe-rule lookup.

### Container governed from creation

The runtime controller inspects the admitted initial container task
  -> `identity_process_control_gate` calls
  `runtime_entry_may_control_initial_target`
  -> BPF requires prepared-container state `ACTIVE`
  -> BPF requires `prepared_container_entry_instance_id` to equal the target
  task's entry ID
  -> BPF requires the target entry to have a nonzero
  `admitted_entry_rule_id`
  -> BPF calls `mark_runtime_entry_bootstrap` for the exact controller thread
  group

The runtime controller creates runc
  -> `task_alloc` copies the task-local bootstrap state to the exact child
  lineage
  -> BPF creates runc's `external_runtime_root` after cgroup attachment
  -> the runc process starts with `externalRole`, entry rule ID `0`, and
  `runtime_entry_bootstrap_prepared = 1`

runc executes its internal current image
  -> `lsm/bprm_check_security` calls
  `runtime_entry_bootstrap_actor_is_exact`
  -> the predicate accepts the exact active binding and bootstrap lineage
  -> `image_contains_candidate` confirms that the executable candidate belongs
  to runc's current image
  -> BPF sets `pending.prepared_runtime_exec` to
  `PREPARED_RUNTIME_EXEC_ENTRY_V1`
  -> BPF keeps `pending.admitted_entry_rule_id = 0`
  -> the exec is runtime infrastructure and does not become an admitted entry

runc executes the requested probe
  -> the next `lsm/bprm_check_security` resolves the requested executable and
  complete arguments
  -> BPF selects the signed probe rule
  -> successful exec commits only the probe's role and rule ID

### Container recovered while running

The runtime controller inspects the unarmed container task
  -> BPF sees prepared-container state `UNARMED`
  -> `prepared_container_entry_instance_id` is zero
  -> the target entry has `admitted_entry_rule_id = 0`
  -> `runtime_entry_may_control_initial_target` returns false
  -> BPF does not call `mark_runtime_entry_bootstrap`

runc reaches its internal current-image exec without the marker
  -> `runtime_entry_bootstrap_prepared = 0`
  -> `runtime_entry_bootstrap_actor_is_exact` returns false
  -> BPF cannot classify the exec as runtime infrastructure
  -> no declared probe or administrative rule matches the runc image
  -> BPF denies the internal exec
  -> runc never executes the requested probe
  -> BPF never reaches the final probe-rule selection

### Required recovered behavior

After BPF publishes `ACTIVE_RECOVERED`, the recovered application entry must be
a valid initial anchor for the same later-entry bootstrap path:

```text
BPF-admitted recovered application anchor
    -> ptrace control creates the exact bootstrap marker
    -> the runc child inherits the marker
    -> runc's matching current-image exec passes with rule ID 0
    -> the requested probe exec reaches BPRM
    -> BPF selects and commits the signed probe rule
```

Recovery does not create a second probe admission path. It supplies the
missing initial anchor and makes `ACTIVE_RECOVERED` valid wherever the normal
later-entry bootstrap requires an active admitted initial anchor.

### Active-anchor predicate scope

The implementation must use one BPF helper for the state part of an active
admitted-anchor check:

```text
prepared-container state is ACTIVE or ACTIVE_RECOVERED
```

`runtime_entry_may_control_initial_target` uses this helper for the inspected
application target. `runtime_entry_bootstrap_actor_is_exact` uses it for the
external runtime actor. Both predicates retain all existing binding, entry,
role, classification, task, boot, and policy-generation checks.

This equivalence applies only to forward later-entry bootstrap. It does not
make `ACTIVE_RECOVERED` proof of the original application exec. It does not
change `PREPARED`, `EXEC_PENDING`, `UNARMED`, or `RECOVERING` behavior. The
implementation must review every direct comparison with `ACTIVE`; it must not
replace comparisons whose purpose is original-start admission or evidence.

The temporary diagnostic only traced the existing predicate inputs and result.
It did not change `runtime_entry_may_control_initial_target`,
`runtime_entry_bootstrap_actor_is_exact`, or an authorization decision. The
diagnostic is not part of this design and is not evidence of a fix.

## Existing Normal-Start Ownership

The current held-container flow uses this owner split:

Mithril Node prepares the held container
  -> `PublishedBinding::prepare_container` writes the initial `PREPARED` state
  and exact held init TGID
  -> Node publishes the binding and invokes BPF reconciliation

BPF creates the initial identity
  -> the BPF task iterator claims the exact held task
  -> `label_external_root` allocates the task, process, execution, and entry
  identities
  -> BPF assigns the initial role and stores its allocated entry in
  `prepared_container_entry_instance_id`
  -> Node reads back the BPF-created identity

BPF observes the application exec
  -> `prepared_container_reserve_activation` changes `PREPARED` to
  `EXEC_PENDING`
  -> BPF verifies and commits the application entry rule
  -> `activate_prepared_container_for_application` changes `EXEC_PENDING` to
  `ACTIVE` after the first syscall proves that the new image reached user mode

Mithril Node does not allocate the identity, assign the role or rule, store the
application anchor, or publish `ACTIVE`. The recovered-container flow keeps
this same ownership rule. Node supplies the initial prepared state. BPF owns
the identity and the active-state commit.

## Shared Initial-Entry Machinery

Normal start and recovery must use the same policy selection and identity
assignment functions. Recovery is another way to establish the normal signed
initial application entry. It is not another authorization path.

On the Node side, one initial-root preparation function must:

- resolve the active generation's normal signed `ContainerStart` rule;
- validate the concrete binding, cgroup, init task, executable, applicable
  arguments, and canonical routes;
- install the supporting policy and route rows; and
- publish the prepared-container value last.

The caller selects only the initial state and evidence inputs. A held new
container publishes `PREPARED`. A recovered running container publishes
`RECOVERING`. Recovery-specific Node code must not repeat rule lookup, route
installation, or binding publication.

On the BPF side, one normal initial-entry authority function must return the
signed rule ID, application role, executable requirements, and applicable
argument requirements. The held-init exec path and the recovered-init
validation path must both use that result. The recovery path adds only the
stable-tree cutover, new entry allocation, provisional-identity replacement,
and recovery provenance. It must not contain a second rule table or a copied
normal-entry matcher.

This consolidation is an implementation constraint. The final change must
remove the duplicate recovery policy path and reduce the recovery-specific BPF
code. A larger recovery-specific authorization implementation does not satisfy
this design.

## Authority Decision

Recovery creates a new authority boundary. It does not reconstruct the
original birth boundary.

| Fact | Authority after recovery | Non-authority |
| --- | --- | --- |
| Container identity | Authenticated CRI container ID and generation, exact cgroup, init PID identity, node boot, and active signed binding | Container name, Pod name, cached PID, or cgroup path text alone |
| Recovered application | BPF selects the stable current init task after the bounded request, kernel task identity, current executable and arguments, signed application entry, and binding all match | A Node-written role or rule ID, PID 1 alone, image name alone, current executable alone, or an incomplete task snapshot |
| Application descendants | BPF selects a current in-container process only when its complete in-cgroup parent chain reaches the verified init task in the stable recovery snapshot | A Node-provided task class, a process outside the exact cgroup, an unresolved parent edge, or a task that appears after the snapshot |
| Other existing tasks | BPF assigns a restricted external identity with rule ID `0` | A Node-assigned rule or a guessed probe, lifecycle, administrative, or application entry |
| Future later entry | Fresh external root followed by exact executable and argument admission | Runtime name, command timing, cgroup membership, or recovery state alone |
| Coverage claim | Effects after the successful recovery cutover | Original exec, earlier ancestry, and effects before the cutover |

The existing `prepared_container_entry_instance_id` remains the binding's
application anchor. In `ACTIVE_RECOVERED`, it names the recovered application
entry instead of an entry created by the held OCI start path. The binding state
and evidence provenance distinguish the two origins.

## Assignment Ownership Invariant

BPF is the only owner that assigns process identity and policy authority. Only
BPF can:

- allocate an `entry_instance_id`, process identity, task cookie, or execution
  identity;
- write a task's nonzero task label;
- write its process state, entry state, and root classification;
- assign its installed role and `admitted_entry_rule_id`; and
- store the recovered application entry in
  `prepared_container_entry_instance_id`.

Mithril Node can install only the signed policy, immutable binding facts, the
initial `RECOVERING` state, and the bounded recovery request. It can invoke the
BPF recovery iterator and read the BPF result. After it publishes
`RECOVERING`, it cannot write task storage, task coordinates, process states,
entry states, classifications, the application anchor, or another
prepared-container lifecycle state.

The recovery request contains the binding identity, transition version,
recovery attempt identity, exact cgroup identity, and exact init task identity.
It does not contain an `entry_instance_id`, installed role ID, or admitted rule
ID. BPF reads the application role and entry rule from the active signed policy
generation that the binding names. BPF rejects a request if the binding,
generation, cgroup, init task, or transition version changes.

## State Contract

| State | BPF behavior | Node behavior |
| --- | --- | --- |
| `UNARMED` | Existing tasks use the restricted floor. No runtime controller can use the application-anchor bootstrap. This state is not a completed recovery handoff. | Node can replace an existing unarmed observation with one exact `RECOVERING` publication. Node must not publish a new recovery binding in this state. |
| `RECOVERING` | Covered effects deny. BPF claims tasks, assigns identities, tracks task-set changes, and validates the complete task set. New task placement cannot create an admitted entry or runtime-bootstrap marker. | Node can invoke the BPF recovery iterator and read its progress. It cannot change the state. |
| `ACTIVE_RECOVERED` | The BPF-assigned recovered application entry and its descendants use the application role. Other old roots remain external. New later roots use normal entry admission. | Node retains the recovery record and reconciles the exact container lifetime. |
| `ACTIVE` | Existing held-OCI behavior remains unchanged. | Node reads back the original prepared-container activation. |
| `CORRUPT` | All affected covered effects deny. | Node reports the failure and does not retry in place. |

`ACTIVE` and `ACTIVE_RECOVERED` have the same forward later-entry behavior.
They have different evidence meaning and different activation proofs. Mithril
Node owns only the initial `RECOVERING` publication, including a guarded
replacement of an older `UNARMED` observation. BPF owns every transition out
of `RECOVERING`. Mithril Node cannot publish
`ACTIVE_RECOVERED`, roll the binding back, or mark it `CORRUPT`.

## Recovery Flow

Mithril Node discovers one running protected container with no retained active
entry identity
  -> `WorkloadBindingOwner` resolves one authenticated CRI container ID and
  generation
  -> `WorkloadBindingOwner` resolves the exact live cgroup and init task
  -> `WorkloadBindingOwner` validates the node boot, label epoch, execution
  set, profile, and active signed policy generation
  -> the shared initial-root preparation resolves the normal signed
  `ContainerStart` rule and validates the executable and applicable arguments
  -> the shared initial-root preparation installs the supporting policy and
  canonical route rows while they remain unreachable
  -> `WorkloadBindingOwner` verifies that no active binding conflicts with the
  request; an existing `UNARMED` observation must have zero BPF-owned recovery
  output fields
  -> `WorkloadBindingOwner` publishes one `RECOVERING` binding value with the
  exact recovery attempt, cgroup, container lifetime, and init task inputs
  -> the installation contains no task label, entry ID, installed role, or
  admitted rule ID
  -> Node reads back the exact `RECOVERING` installation

Mithril Node invokes the BPF recovery iterator
  -> BPF reads the installed `RECOVERING` binding and active signed policy
  -> BPF verifies the node boot, label epoch, binding identity, transition
  version, cgroup identity, container lifetime, and init task identity
  -> BPF resolves the application entry, role, and execution rule from the
  active signed policy generation
  -> BPF rejects any mismatch before it assigns identity or authority
  -> Mithril Node makes no further lifecycle transition

BPF accepts the exact `RECOVERING` installation
  -> BPF claims the recovery transaction under the binding transition guard
  -> BPF initializes its task-set generation and completion counters
  -> BPF denies covered effects for the exact binding
  -> BPF refuses entry admission and runtime-bootstrap creation for the exact
  binding
  -> BPF task create, cgroup attach, reparent, exec, and exit hooks advance the
  task-set generation while recovery is in progress

BPF scans the live task set
  -> the BPF iterator selects only tasks in the exact bound cgroup lifetime
  -> BPF claims each task's local storage and allocates its kernel identity
  -> BPF selects the exact verified init task as the recovered application
  root
  -> BPF allocates one fresh application `entry_instance_id`
  -> BPF reads the application role and `admitted_entry_rule_id` from the
  signed application entry
  -> BPF assigns that entry, role, rule, and process-state vector to the init
  task
  -> BPF assigns the same application entry and role to each current process
  whose complete in-cgroup parent chain reaches the init task
  -> BPF creates a restricted external entry for every other existing process
  tree
  -> every external entry has `externalRole`, purpose `unknown`, and
  `admitted_entry_rule_id = 0`
  -> BPF records recovered provenance and the recovery attempt identity on all
  candidate rows

A task appears, exits, attaches, reparents, or starts exec during the scan
  -> its BPF lifecycle hook advances the task-set generation
  -> the current scan cannot commit
  -> BPF keeps the binding `RECOVERING` and keeps covered effects denied
  -> a later iterator pass restarts from the new task-set generation

BPF validates the recovery candidate
  -> candidate rows remain unreachable while the binding is `RECOVERING`
  -> BPF checks every task label, process state, entry state, classification,
  role, rule ID, binding ID, policy generation, and recovery attempt identity
  -> BPF requires the same task-set generation and the same complete live task
  count at the start and end of validation
  -> BPF requires one exact recovered application root and no unlabeled task,
  unresolved parent, duplicate root, or task from another cgroup lifetime

The BPF validation is complete
  -> BPF acquires the binding transition guard
  -> BPF checks the request, policy generation, task-set generation, task
  count, application entry, and candidate-row counts again
  -> BPF stores its allocated application entry as the binding's application
  anchor
  -> BPF advances the binding transition version
  -> BPF changes `RECOVERING` to `ACTIVE_RECOVERED`
  -> BPF releases the transition guard
  -> effects after this BPF cutover use the recovered identities

Mithril Node reads the BPF result
  -> it reports `ACTIVE_RECOVERED`, the BPF-assigned counts, and the coverage
  cutover
  -> it does not rewrite the application anchor, task identities, roles, rule
  IDs, or lifecycle state

BPF detects a non-retryable contradiction
  -> BPF changes `RECOVERING` to `CORRUPT` under the transition guard
  -> BPF does not publish the candidate as active
  -> covered effects remain fail-closed

Mithril Node stops or restarts during recovery
  -> installed policy and BPF internal state remain unchanged
  -> BPF does not infer success from the Node process lifetime
  -> a later Node instance can invoke the same BPF recovery and readback path

## Existing Task Behavior

The verified init process performs its next covered effect after the cutover
  -> BPF verifies `ACTIVE_RECOVERED`, the recovered application entry, current
  binding, current policy generation, and task identity
  -> BPF applies the application role to the effect
  -> evidence marks the actor and binding as recovered at the cutover

A selected current application descendant performs its next covered effect
  -> BPF verifies the descendant's recovered process identity and shared
  application entry
  -> BPF applies the application role
  -> BPF does not claim an observed kernel birth edge for the pre-cutover task

An existing probe, hook, runtime helper, or ambiguous process performs a
covered effect
  -> BPF applies `externalRole`
  -> `admitted_entry_rule_id` remains `0`
  -> BPF does not infer the old entry kind from its executable, arguments,
  name, parent, or timing
  -> the task can exit, but it cannot obtain an admitted role through recovery

An existing external task exits
  -> the normal task-exit owner retires its recovered external identity
  -> the exit does not change the application anchor or authorize a later task

## Future Later-Entry Flow

Kubelet requests a new exec probe after `ACTIVE_RECOVERED`
  -> containerd sends the request to the exact live container shim
  -> a runtime controller performs the qualified read-only ptrace operation
  against the recovered application anchor
  -> at `lsm/ptrace_access_check`, BPF verifies the active recovered binding,
  exact anchor entry, nonzero anchor rule, current node boot, and current policy
  generation
  -> `runtime_entry_may_control_initial_target` accepts
  `ACTIVE_RECOVERED` as an active admitted initial anchor
  -> BPF creates one task-local runtime-bootstrap marker on the observed
  controller thread group

The marked runtime controller creates a child
  -> `task_alloc` copies the marker to the exact child lineage
  -> cgroup attachment creates one fresh `external_runtime_root`
  -> the new root starts with `externalRole`, purpose `unknown`, and rule ID
  `0`
  -> no runtime name, binary path, process name, or lifecycle kind becomes
  authority

runc performs an internal executable transition
  -> at `lsm/bprm_check_security`,
  `runtime_entry_bootstrap_actor_is_exact` verifies the marker, external runc
  root, active recovered binding, and current policy generation
  -> `image_contains_candidate` verifies that the candidate belongs to runc's
  current image
  -> BPF sets `pending.prepared_runtime_exec` to
  `PREPARED_RUNTIME_EXEC_ENTRY_V1`
  -> BPF keeps the external role and `pending.admitted_entry_rule_id = 0`
  -> successful internal exec retains the marker for the same task lineage and
  binding

runc executes the requested probe command
  -> the exec syscall hook captures the logical invocation path and complete
  arguments
  -> `bprm_check_security` checks the opened executable through the normal
  policy gate
  -> BPF looks up the declared entry by policy generation, binding, logical
  path atom, and `externalRole`
  -> BPF verifies the declared executable, required arguments, target role,
  and process-state vector
  -> BPF reserves the declared rule ID under the process transition guard
  -> the credential and successful-exec hooks verify the same request
  -> successful exec commits only the declared probe role and rule ID
  -> BPF clears the runtime-bootstrap marker

The requested command does not match one declared entry
  -> BPF does not commit a rule ID or target role
  -> the task remains an external root
  -> BPF denies the exec before the requested program reaches user mode

## Approved Administrative Entry

Control approves one administrative command for an `ACTIVE_RECOVERED` binding
  -> Mithril Node verifies and publishes the existing signed one-use slot
  -> the slot remains bound to the node boot, binding ID and nonce, container
  generation, policy generation, exact executable, complete arguments, role,
  and deadline

The runtime prepares the approved command
  -> the recovered application anchor supplies only the runtime-bootstrap
  relationship
  -> the runtime-bootstrap marker does not reserve or consume the approval
  slot
  -> runc remains an external runtime root through its internal execs

runc executes the approved command
  -> the normal BPRM transaction matches the exact executable and complete
  kernel-captured arguments
  -> one task reserves and consumes the approval slot
  -> successful exec installs only the administrative role and rule ID
  -> another command, task, binding, generation, or replay remains denied

## Recovery Evidence

The recovery transaction emits one bounded record that contains:

- node ID, node boot ID, and label epoch;
- Pod UID, container ID, container generation, and binding ID;
- policy generation and application rule ID;
- recovery attempt ID and cutover boot-time timestamp;
- init task cookie and recovered application entry ID;
- application-tree and external-tree task counts;
- executable and argument verification results;
- BPF task-set generation and validation result;
- previous and final binding states; and
- success, retryable failure, or corrupt result.

The record states that coverage before the cutover is unknown. Control and Node
status must not convert that interval into a protected result.

## Implementation Owners

| Owner | Required change |
| --- | --- |
| Interceptor ABI | Add `RECOVERING` and `ACTIVE_RECOVERED` prepared-container states. Add only the recovery identity needed for guarded publication and evidence. |
| `WorkloadBindingOwner` | Use the same initial-root preparation and publication function as held-init arming. Resolve the exact CRI lifetime and init task. Publish the binding directly as `RECOVERING` after its supporting rows are ready. Do not assign task authority or publish a later state. |
| `NativeSecurityStateOwner` | Invoke the BPF recovery and validation iterators. Read health and completion output. Do not write identity rows or lifecycle transitions. |
| BPF recovery owner | Claim tasks, allocate identities, select the init tree, assign roles and rule IDs, validate the complete task set, store the application anchor, and publish `ACTIVE_RECOVERED` or `CORRUPT`. |
| BPF task lifecycle | Deny during `RECOVERING`, advance the recovery task-set generation for every task change, accept only complete recovered rows at `ACTIVE_RECOVERED`, and classify every new root after the cutover. |
| BPF runtime-bootstrap owner | Make `ACTIVE_RECOVERED` a valid admitted initial anchor in `runtime_entry_may_control_initial_target` and `runtime_entry_bootstrap_actor_is_exact`. Keep marker inheritance task-local. Permit only the same current-image runtime-internal transition that the normal active path permits, without assigning an entry role. |
| BPF exec owner | Keep the new root external until its own executable and arguments reserve and commit one declared or approved entry. |
| Node evidence owner | Record the recovery gap, task partition, cutover, and failure state without claiming original-start coverage. |
| Lightweight qualification | Start a fresh container and shim before Mithril binds them. Prove recovery and later-entry behavior with the K3s runtime versions. |
| Kubernetes qualification | Run the same state transitions, role results, rule results, denials, and evidence fields on the physical K3s path. |

## Acceptance

1. A state-machine test proves that Node's recovery handoff publishes
   `RECOVERING` directly. An older `UNARMED` observation can be replaced in the
   same guarded publication, but a new recovery binding is never delivered as
   `UNARMED`. The test proves that only BPF can publish a later recovery state,
   including `ACTIVE_RECOVERED`, retry rollback, and fail-closed corruption
   transitions. Retirement after activation keeps its existing owner.
2. A recovery test verifies the exact CRI container lifetime, init task,
   executable, arguments, root view, and policy generation.
3. A BPF recovery test proves that BPF assigns the recovered application rule
   and role to the init tree and assigns every other existing tree to
   `externalRole` with rule ID `0`. Node writes none of these values.
4. A race test creates, exits, and reparents tasks around recovery. No task can
   act without one read-back identity, and an unstable snapshot cannot become
   active.
5. A failure test covers an unstable task-set generation, PID reuse, container
   replacement, executable mismatch, argument mismatch, policy replacement,
   partial BPF publication, failed readback, and node restart during
   `RECOVERING`.
6. Existing external tasks cannot acquire a declared role after recovery. They
   remain restricted until exit.
7. A future PostStart, PreStop, startup probe, readiness probe, and liveness
   probe starts as an external root and commits only its declared rule and
   role.
8. A future runtime controller receives the bootstrap marker from the exact
   recovered application anchor. Its child inherits the marker. The matching
   current-image runc internal exec sets `prepared_runtime_exec` to `ENTRY`,
   keeps admitted rule ID `0`, and grants no entry role. The next BPRM check
   selects and commits the signed probe rule.
9. An unmatched `kubectl exec`, direct `crictl exec`, cgroup-entering task,
   wrong executable, wrong arguments, wrong binding, and replay remain denied.
10. One approved administrative exec consumes its exact one-use slot and
    installs only the administrative role. An ordinary administrative exec
    remains external and denied.
11. The lightweight test starts the container and shim before Mithril, records
    the BPF-produced recovered task partition, and then proves the later-entry
    results.
12. The paired Kubernetes test uses the same K3s containerd, shim, and runc
    versions and requires the same state transitions, result fields, roles,
    rule IDs, and decisions.
13. The lightweight test passes before the Kubernetes test runs.
14. Evidence reports the pre-cutover gap and never reports the original exec
    as Mithril-governed.
15. The complete repository Rust gate passes after the final source edit.
16. Held-init arming and recovered-init preparation call the same Node
    initial-root preparation functions and the same BPF normal-entry authority
    functions. Recovery-specific code contains only cutover and provenance
    behavior, and the recovery implementation is net-negative after duplicate
    authority logic is removed.

## Exclusions

This proposal does not reconstruct pre-cutover birth lineage, entry purpose,
open-file ownership, socket ownership, memory provenance, or completed effects.
It does not authorize checkpoint restore, an unmatched workload, a container
without authenticated CRI identity, or a task outside the exact cgroup.

This proposal does not identify runc, containerd, a shim, or another runtime by
name, executable path, arguments, or a fixed syscall sequence. It does not
give application authority to an existing independent or ambiguous process
tree.

Version-changed Kubernetes recovery, direct non-CRI fallback, authorized final
decommission, and complete Phase 6.2 closure remain separate work.

## Result

Not done. The design is approved. No implementation or qualification result is
claimed by this proposal.
