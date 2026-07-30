# Phase 9: Local And Distributed Response

Status: Not started.

Master plan: [Mithril Hugging Face Intrusion Prevention](./README.md)

## Purpose

Turn exact evidence and one immutable distributed-lineage version into narrow,
authorized physical containment with explicit widening and verified
postconditions.

## Depends On

Phase 8 must be `Done`. The user must separately approve each response class,
its credential, automatic/manual approval policy, expiry, rollback, blast
radius, and required postconditions.

## Phase Scope

### Typed Response Contract

Implement:

```text
ResponseRequest
  → simulation
  → authorization
  → immutable target plan
  → per-target execution
  → physical verification
  → verified | partial | failed | unknown
```

Every command contains:

- tenant and authorized subject;
- finding and exact graph/lineage version;
- target identity and generation;
- requested and optional broader effects;
- expected scope and enumerated impacted subjects;
- approval and authorization policy;
- expiry and idempotency key;
- dependencies and watch interval; and
- required physical postconditions.

No free-form command, model sentence, alert severity, or Falco/Tetragon action
can become an actuator request.

### Local Actuators

Implement cohesive owners under:

```text
crates/mithril-node/src/response/
  mod.rs
  target.rs
  restrict.rs
  pidfd.rs
  socket_fence.rs
  cgroup.rs
  evidence.rs
  verify.rs
```

Support separately authorized scopes:

1. **Exact process lineage restriction.** Insert one
   `(label_epoch, process_lineage_id, generation)` response root checked at
   every protected hook. Existing/future descendants match the bounded
   ancestor vector.
2. **Exact process stop.** Revalidate the current leader/task through pidfd,
   task cookie, start time, Pod/container/cgroup, and generation; deliver
   `SIGSTOP`. Treat `SIGKILL` as a distinct irreversible action.
3. **Known socket fence.** Fence the exact observed/shared socket-cookie set
   and all future sockets/effects for the restricted lineage.
4. **Cgroup egress/freeze.** Hold an open cgroup FD, enumerate actual members,
   activate the cgroup packet fence and optionally `cgroup.freeze=1`, and state
   the wider container/Pod blast radius.
5. **Bounded evidence capture.** Preserve declared process/file/socket/cgroup/
   namespace/policy metadata before irreversible actions, without delaying an
   urgent network fence.

The response controller may widen from process → sockets → cgroup only through
an explicit planned/authorized target.

### Node-Side Revalidation

Before actuation, reject:

- wrong tenant/cluster/node;
- stale node boot;
- stale label epoch/task cookie/process-lineage ID;
- PID/TID/start-time mismatch;
- changed Pod UID/full container ID/cgroup identity;
- incompatible profile/target generation;
- expired command;
- unavailable required program/map/postcondition path; or
- scope outside the authenticated node.

The central graph is evidence, not ambient kernel authority.

### Kubernetes And Controller Actuators

Implement narrow Mithril Control connector actions using object UID and
resourceVersion preconditions:

- suspend a supported Job/custom workload;
- scale a scalable exact controller when approved;
- install a narrow run-scoped admission block for the exact object lineage;
- foreground-delete an approved object after evidence capture; and
- verify that no replacement descendant appears through `watch_until`.

Deleting one Pod is not complete when a controller can recreate it.

Secret reads and already-completed API operations are not rolled back by
admission.

### Distributed Coordinator

Create:

```text
crates/mithril-control/src/response/
  model.rs
  simulation.rs
  authorization.rs
  coordinator.rs
  node.rs
  kubernetes.rs
  execution.rs
  verification.rs
  watch.rs
```

Freeze one exact `DistributedLineageView` version into a
`DistributedResponsePlan`. Then:

1. open the containment watch;
2. fence the seed locally without waiting for complete remote expansion;
3. invoke an exact propagation-capability action if this phase has an approved
   Kubernetes credential target;
4. independently re-resolve and contain each response-eligible remote Linux
   member;
5. constrain the owning reconciler;
6. create a new simulated/authorized plan version for late branches; and
7. verify every branch and source through `watch_until`.

An offline or outside-authority target remains evidence and forces
`partial`/`unknown`; it is never silently dropped.

### Agent-Native Response Boundary

Defensive agents may:

- request simulation;
- inspect target eligibility and blast radius;
- submit an exact typed request within their principal's scope; and
- inspect immutable execution/postcondition results.

They cannot manufacture target identity, bypass approval, expand the plan,
change BPF maps directly, call Kubernetes with Mithril credentials, or execute
shell commands.

## Hugging Face Test Increment

Implement:

- `HF-RESP-001` exact local restriction, stop, socket fence, and cgroup
  widening;
- `HF-RESP-002` two-node seed/remote/controller containment;
- the safe privileged-workload branch with controller replacement during the
  watch;
- shared-interpreter simulation showing every affected job is unknown/wider;
- stale target, incomplete ancestry/socket history, offline node,
  outside-authority, missing coverage, and late branch states; and
- optional exact input revision quarantine only when authenticated immutable
  revision evidence exists.

## Code-Backed Tests

- authorization tenant/resource/action/approval/expiry matrix;
- idempotent request/execution retry and crash recovery;
- task/lineage restriction across every thread, existing descendant, and new
  descendant;
- depth overflow, bootstrapped ancestry, and missing label ineligibility;
- pidfd stop verification and separate irreversible kill authorization;
- shared socket and complete/incomplete socket-history fences;
- cgroup FD/ID reuse, membership enumeration, packet fence, and freeze;
- process-versus-cgroup blast-radius simulation;
- Kubernetes UID/resourceVersion stale precondition and reconciler
  replacement;
- distributed dependency order, concurrent targets, partial failure, offline
  node, outside authority, and late graph version;
- watch-window source loss and final-state classification;
- agent/tool prompt injection and authority escalation attempts; and
- `HF-RESP-001`/`002` live tests and response latency budgets.

## Live Probe

Run Probe E in full, including late controller replacement, one offline-node
variant, one incomplete-source variant, and one repeated idempotency key.

## Checkpoint

Run the common repository gates, local actuator and stale-target matrices,
authorization/idempotency/watch tests, all physical postcondition probes, and
live Probe E. Preserve simulation, approval, immutable execution, verification,
coverage, and final-state records.

## Acceptance

- stale or forged native/provider targets are rejected;
- exact restriction immediately denies protected effects for all proven
  existing/future descendants;
- pidfd stop, LSM denial, socket fence, and cgroup freeze are distinct results;
- socket/cgroup postconditions prove packet and computation state;
- wider scopes list actual affected processes/workloads before approval;
- the distributed coordinator never sends a remote PID or lineage ID as
  unverified kernel authority;
- the owning controller cannot silently replace a contained Pod;
- late branches require a new plan version and authorization;
- every action is idempotent and expiry-aware;
- final state matches physical postconditions and coverage;
- agent-native tools cannot bypass response authorization; and
- the two-node incident fixture is contained at the smallest proven scopes.

## Explicit Stop Point

Stop after local/Kubernetes response passes. Do not add AWS, mesh, shared
connector, source-control, or other provider credentials/actions until each
Phase 10 adapter receives independent approval.

## Phase Result

State: Not started.

Record response schemas/classes, authorization rules, actuator credentials,
blast-radius/postcondition tests, live plans/results, latency, gaps, and final
state.
