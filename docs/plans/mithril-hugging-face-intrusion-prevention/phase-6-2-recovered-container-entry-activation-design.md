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

## Qualification Check On 2026-09-07

Result: **Not done**. The current lightweight production-cycle test fails
before BPF publishes an application entry. Kubernetes has not run against
this source change.

The first lightweight failure found a Node policy publication defect. The
path-reconciliation early return omitted normal entry rows for a new binding
when the measured path sets did not change. The current source removes that
early return. The next run reached BPF recovery.

The fixture also used `/bin/busybox sleep 300` with a signed `/bin/sh`
application entry. The fixture now starts `/bin/sh -c 'sleep 300 & wait'`.
This uses the signed entry path and keeps a child in the application tree.
The corrected test still fails. bpftrace readback shows one scanned task,
zero accepted candidates, one invalid task, and a zero application entry ID.
The signed `/bin/sh` path is a symlink to `/bin/busybox`. Normal admission
matches the captured exec pathname. The current recovery code matches the
resolved path of `mm->exe_file`. These are different inputs. The current
recovery matcher does not prove equivalent admission for this case.

Trace evidence is in
`/tmp/mithril-recovery-lifecycle-lightweight-20260907-astra2/signed-entry-bpftrace.log`.
The retained VM is `mithril-runtime-qualification-836598`. The trace did not
change an admission decision. Do not count the trace process exit code as a
test pass.

The repository gate passed formatting, workspace check, and strict Clippy.
It then failed `decision_abi_layout_and_values_are_closed`: the draft changed
the `Tombstoned` value from 5 to 10. The full workspace test suite did not
complete. No implementation deliverable is qualified by this run.

## Qualification Check On 2026-09-08

Result: **Not done**. The recovered-entry lightweight case passed on the
retained kernel VM. The paired Kubernetes case failed before Node published
`RECOVERING`. No implementation deliverable is qualified by these results.

The lightweight result is
`/tmp/mithril-recovery-argv-20260908-run24.json`. BPF assigned application
role 2 and normal entry rule 8 to two application tasks. A later runtime
inspection created the bootstrap marker. The internal runtime exec kept rule
ID 0. The probe received role 8 and rule 5. Its permitted output passed, its
own file-policy denial passed, and an unmatched exec was denied. A second
production identity-reconciliation call preserved the recovered task
snapshot. This case had no existing external task tree.

The Kubernetes evidence is in
`/tmp/mithril-recovered-k8s-20260908-current`. Node reported
`running container recovery has invalid initial state`. Runtime reconciliation
sets `arm_initial_root = false` for the running container. Policy delivery
saves that binding. `materialize_scheduled_bindings` then restores its runtime
coordinates but does not preserve `arm_initial_root`. The reconstructed
configuration has `arm_initial_root = true`. Recovery installation rejects
that configuration before the BPF handoff. An added policy-delivery regression
check reproduces this field loss and fails. The defect is not fixed.

The lightweight case did not include this complete production path. It
assigned the resolved runtime binding directly to its configuration. The
shared operation must also cover production policy-delivery restoration
before this case can qualify Kubernetes recovery. Do not add another manual
test sequence or rerun Kubernetes before that lightweight reproduction fails.

The broader lightweight case also remains incomplete. Its static
administrative-recovery fixture fails policy activation because that path
requires a live binding before policy publication. Do not publish an
intermediate `UNARMED` recovery binding to bypass this failure. The ABI value
failure recorded above and the remaining lifecycle-predicate review are also
open. These results do not close the full process-tree, argument-mismatch,
race, administrative-entry, or complete repository checks.

### Shared-Cycle Correction On 2026-09-08

The Node and lightweight paths now call `NodeBindingReconciliation::reconcile`.
This operation includes CRI selection, durable binding save and restore,
policy installation, and BPF readback. Lightweight supplies a signed Control
bundle through `deliver_policy`. It no longer assigns the resolved binding
directly to Node configuration. Run 27 reproduced the exact Kubernetes
`running container recovery has invalid initial state` failure before the fix.

The fix removes `arm_initial_root` from authorization decisions. Node retains
every matching non-`UNKNOWN` BPF state without clearing exec cookies or
replacing a pending state. The shared-cycle lightweight run 28 passed. Its
result is `/tmp/mithril-recovery-argv-20260908-run28.json`.

The next Kubernetes run is in
`/tmp/mithril-recovered-k8s-20260908-shared-cycle`. BPF completed recovery and
admitted a later probe. The denial check failed because the target file did
not exist. `cat` returned `ENOENT`, not a policy denial. Lightweight run 29
reproduced that condition and failed its denial-evidence check before the
fixture correction. The revised cases check missing-file failure separately
from signed denial of an existing file. Lightweight run 30 passed.

The next Kubernetes run, `shared-cycle-fixed`, reached the actual signed file
denial. Its unfiltered diagnostic contains `EXACT_POLICY_DENY`, probe rule 5,
role 7, and `kernel_result=-13`. The test capture omitted that event because
`start_entry_effect_capture` selected other reasons but not
`EXACT_POLICY_DENY`. Lightweight run 31 used the production observation server
and `mithril-inspect` with those same filters. It failed with
`the public observation capture omitted the signed file denial`.

The correction removes the reason filters from both captures. Lightweight
run 32 passed through the production observation server and CLI. Its result
is `/tmp/mithril-recovery-argv-20260908-run32.json`. The paired Kubernetes run
was interrupted. The host restart removed its temporary evidence.
Neither fixture correction changes BPF authorization.

The resumed Kubernetes run captured the denial but selected the wrong probe.
Readiness `/bin/grep` ran before startup `/bin/cat`. The harness selected the
first non-application event, then searched for the denial under the readiness
rule. Lightweight run 34 reproduced this error with a real readiness exec
before the startup exec. Both cases now hold the startup task on a FIFO and
read its exact identity through the production inspection API. The first
event no longer selects the expected role or rule. Lightweight run 35 passed.

The paired focused Kubernetes case then passed. It records the recovered
anchor, runtime bootstrap marker, internal runtime exec with rule zero,
signed probe admission, signed file denial, unmatched-exec denial, and a
ready startup probe. Evidence is under
`target/mithril-recovery-qualification/20260908-resumed/`:

- `recovered-run35.json`: lightweight recovery result before Kubernetes.
- `recovered-run36.json`: lightweight pass after the final shared fixture edits.
- `kubernetes-exact-probe/recovered-container-kubernetes-entry.json`: physical result.
- `kubernetes-exact-probe/recovered-entry-probe.json`: exact startup task.
- `kubernetes-exact-probe/recovered-entry-effects.txt`: signed denial evidence.
- `kubernetes-exact-probe/recovered-entry-bpftrace.txt`: runtime hook trace.

The host disk filled during Kubernetes setup and paused the test VMs. Removal
of the disposable Rust incremental cache restored space. The current test VMs
resumed before the recovery checks. No VM disk or test evidence was removed.

The broader lightweight administrative-entry case also passed. Its first
shared-cycle delivery omitted the first active container from the signed
target list. Production rejected that activation. The fixture now includes
both targets and uses the production binding-ID derivation. The two targets
have distinct container and execution-set IDs. The base configuration no
longer includes the old static candidate in addition to the Control-delivered
candidate. Run 13 reached recovery and unapproved-exec denial, then failed
because the requested administrative file existed only in the first
container. The fixture now requests `/bin/busybox` in the recovered container.
Run 14 admitted the approved command with administrator role 1 and rule 7,
but its assertion expected the old generation 2 instead of the delivered
generation 3. The assertion now uses the delivered generation. Run 15 passed,
including argument-mismatch denial, one-use approval, administrator role
assignment, replay denial, slot cleanup, ordinary entry roles, and cache
retirement. Its result is `entry-role-run15.json` under the evidence directory
above. Logs for runs 10 through 14 are saved there as `entry-role-runN.log`.
The paired Kubernetes protected-start check failed in
`kubernetes-protected-fresh`. An attempted reuse of the recovery-only fixture
was rejected before admission: only its first node has a Mithril runtime
manifest. The protected-start reuse check requires both nodes. No production
check was changed to bypass that rejection.

The fresh normal-start case found a Node validation defect. The first OCI
hook stages runtime facts. The second hook verifies CRI `Created`, then
publishes the held binding and attaches that verified runtime identity.
`validate_initial_root_preparation` treats every nonempty `runtime_identity`
as recovery. It requires no held PID and CRI `Running`. The valid held
`Created` binding fails that check. Node exits with
`recovered initial-root preparation changed before publication`; later hook
attempts cannot connect to its admission socket. The Node log is
`kubernetes-protected-fresh/node-admission-previous.log`.

The lightweight held-start setup has no CRI identity at that validation point.
It therefore takes the other branch and passes. This normal-start condition
must be added through a shared production operation before the implementation
fix or another Kubernetes run. Do not assign private runtime state in the
fixture. The recovery passes above do not qualify normal protected start or
the Kubernetes administrative-approval transaction.

All 243 Node unit tests passed with Unix-socket access. The repository gate
passed formatting, workspace check, and strict Clippy. It failed the existing
ABI assertion that requires `Tombstoned = 5`; the current draft uses 10.
The draft also keeps numeric lifecycle predicates and uses the recovery-row
transition guard for final publication. The approved design requires simple
identity predicates and the binding transition guard. These source gaps and
complete tree, executable-mismatch, and race qualification remain open.
Result: **Not done**. No new implementation commit is qualified yet.

### Held-Start Validation Correction On 2026-09-08

The lightweight runtime case now calls the same
`WorkloadBindingOwner::publish_held_activated_root` operation as Node. It
supplies the scheduled policy before the held binding and supplies a CRI
`Created` observation with runtime PID zero. The held process PID remains a
separate OCI input. This is a normal initial start, not recovery.

Run 16 failed with the exact Kubernetes error before the validator fix:
`recovered initial-root preparation changed before publication`. The saved
log is
`target/mithril-recovery-qualification/20260908-resumed/held-created-red-run16.log`.
The validator now selects recovery checks from `lifecycle_state = RECOVERING`,
not from CRI identity presence. The shared operation verifies CRI identity
through the existing production validator. Node no longer stores a pending
runtime identity between verification and publication. The runtime request
keeps its cancellation checks and rollback behavior.

Lightweight runtime run 19 and focused recovery run 37 pass. Their results
are `entry-role-run19.json` and `recovered-run37.json` in the same evidence
directory. The paired Kubernetes protected-start run passes in
`kubernetes-held-created-green/protected-start-result.json`. It proves normal
start, independent declared entries, incomplete-argument denial, path
deferral, cache retirement, and external-entry denial. Result for the
held-start correction: **Done**. The broader source gaps listed above remain
open. Result for this recovery design: **Not done**.

## Intended End State

Node reads the exact retained BPF binding before it starts recovery. A binding
that matches the current boot, label epoch, and container lifetime keeps every
non-`UNKNOWN` lifecycle state. This includes pending and terminal states. Node
does not convert a retained state to `RECOVERING`. A retained state does not
authorize an effect; BPF applies that state's existing effect checks.

`arm_initial_root` can remain as a display field. It does not select recovery,
assign authority, or override BPF state. Durable policy delivery keeps the
signed policy and container association. The Node loop and lightweight case
call the same production reconciliation operation, including durable save,
restore, policy installation, and BPF readback.

An exact running container uses this recovery handoff:

```text
Node local preparation -- Node publish --> RECOVERING -- BPF commit --> ACTIVE_RECOVERED
```

Recovery uses only `lifecycle_state`. Remove the separate
`prepared_container_state` field. Node publishes no intermediate `UNARMED`
recovery binding.

Before the publication, Node authenticates the CRI container lifetime, cgroup,
and init task coordinates. Node installs all signed policy rows. Node does not
measure the process executable, arguments, root view, or process tree. The
`RECOVERING` binding publication is the handoff commit. A successful Node
recovery operation therefore returns only after readback proves that BPF
received `RECOVERING` or already advanced it.

While the binding is `RECOVERING`, BPF denies covered effects and does not
create runtime-bootstrap authority. Mithril Node installs the signed policy,
binding facts, initial `RECOVERING` state, and bounded recovery request. It
invokes the BPF recovery iterator but does not change identity state after that
publication. After `RECOVERING` is visible, BPF measures the exact PID 1,
executable, applicable arguments, root view, and complete process tree. BPF
measures one stable task set, creates one recovered
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
  -> BPF requires `lifecycle_state = ACTIVE`
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

The normal and recovered flows use the same committed application entry as
the runtime anchor. Keep lifecycle transitions at their owner. Do not add
lists of lifecycle states to identity checks, or hide such lists in helpers,
variables, or numeric ranges. Preserve the recovery barrier and terminal
denial checks.

`runtime_entry_may_control_initial_target` verifies the inspected application
target. `runtime_entry_bootstrap_actor_is_exact` verifies the external runtime
actor. Both retain the binding, entry, role, classification, task, boot, and
policy-generation checks.

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

- authenticate the concrete CRI binding, cgroup, and init task coordinates;
- install the normal signed policy rows; and
- publish the binding with its initial `lifecycle_state` last.

The caller selects only the initial state and evidence inputs. A held new
container publishes `PREPARED`. A recovered running container publishes
`RECOVERING`. Recovery-specific Node code must not repeat rule lookup or
binding publication. BPF measures the recovered process and root view after
this publication.

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
entry states, classifications, the application anchor, or another recovery
lifecycle state.

The recovery request contains the binding identity, transition version,
recovery attempt identity, exact cgroup identity, and exact init task identity.
It does not contain an `entry_instance_id`, installed role ID, or admitted rule
ID. BPF reads the application role and entry rule from the active signed policy
generation that the binding names. BPF rejects a request if the binding,
generation, cgroup, init task, or transition version changes.

## State Contract

| State | BPF behavior | Node behavior |
| --- | --- | --- |
| `RECOVERING` | Covered effects deny. BPF claims tasks, assigns identities, tracks task-set changes, and validates the complete task set. New task placement cannot create an admitted entry or runtime-bootstrap marker. | Node can invoke the BPF recovery iterator and read its progress. It cannot change the state. |
| `ACTIVE_RECOVERED` | The BPF-assigned recovered application entry and its descendants use the application role. Other old roots remain external. New later roots use normal entry admission. | Node retains the recovery record and reconciles the exact container lifetime. |
| `ACTIVE` | Existing held-OCI behavior remains unchanged. | Node reads back the original prepared-container activation. |
| `CORRUPT` | All affected covered effects deny. | Node reports the failure and does not retry in place. |

`ACTIVE` and `ACTIVE_RECOVERED` have the same forward later-entry behavior.
They have different evidence meaning and different activation proofs. Mithril
Node owns only the initial `RECOVERING` publication. BPF owns every transition out
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
  -> the shared initial-root preparation installs all normal signed policy
  rows while they remain unreachable
  -> `WorkloadBindingOwner` verifies that no active binding conflicts with the
  request
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
  -> BPF measures PID 1, its executable, applicable arguments, root view, and
  complete process tree against that normal signed rule
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
| Interceptor ABI | Keep recovery state only in `lifecycle_state`. Remove `prepared_container_state`. Add only the recovery identity needed for guarded publication and evidence. |
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
   `lifecycle_state = RECOVERING` directly after all signed policy rows exist.
   No recovery binding is delivered as `UNARMED`. The test proves that only
   BPF can publish a later recovery state,
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
11. The lightweight test starts the container and shim before Mithril and
    supplies external CRI and signed policy inputs to the supported Node
    reconciliation API. The real Node loop calls that same production
    operation. The test inspects the BPF task partition and later-entry
    results. It does not repeat Node's internal publication sequence. Each
    Kubernetes-only failure must first fail in this lightweight operation.
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
